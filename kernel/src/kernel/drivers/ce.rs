// SPDX-License-Identifier: BSD-3-Clause-Clear
// SRNG register/descriptor setup references Linux v6.8 ath12k hal.c/ce.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Polled Qualcomm Copy Engine rings. Register access, DMA, and pipe layout
//! are injected; this transport does not interpret HTC, WMI, or Ethernet.
use super::mhi::{Error, Memory, Registers, Result};
use super::srng::Ring;
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Clone, Copy)]
pub struct Pipe {
    pub tx: usize,
    pub rx: usize,
    pub buffer_bytes: usize,
}
#[derive(Clone, Copy)]
pub struct Config {
    pub base: u32,
    pub stride: u32,
    pub pipes: &'static [Pipe],
    /// WLANFW target pipe records: number, direction, entries, buffer size, flags.
    pub target: &'static [[u32; 5]],
    /// WLANFW service records: service ID, direction, pipe number.
    pub services: &'static [[u32; 3]],
    pub control_receive: &'static [u8],
}

struct Tx {
    ring: Ring,
    buffers: usize,
    sensitive: Vec<bool>,
    reaped: usize,
}
struct Rx {
    post: Ring,
    status: Ring,
    buffers: usize,
    read: usize,
    outstanding: usize,
}
struct Queue {
    pipe: u8,
    bytes: usize,
    tx: Option<Tx>,
    rx: Option<Rx>,
}
pub struct Engine<M> {
    memory: M,
    bytes: usize,
    config: Config,
    queues: Vec<Queue>,
    incoming: VecDeque<(u8, Vec<u8>)>,
    started: bool,
}
fn span(cursor: &mut usize, bytes: usize, align: usize) -> Result<usize> {
    let start = cursor.checked_add(align - 1).ok_or(Error::Allocation)? & !(align - 1);
    *cursor = start.checked_add(bytes).ok_or(Error::Allocation)?;
    Ok(start)
}
fn plan(config: Config) -> Result<(usize, Vec<Queue>)> {
    let end = (config.pipes.len() as u32)
        .checked_mul(config.stride)
        .and_then(|value| value.checked_add(0x1410))
        .and_then(|value| config.base.checked_add(value));
    if config.pipes.is_empty()
        || config.pipes.len() > 9
        || config.stride < 0x2000
        || !config.base.is_multiple_of(4096)
        || !config.stride.is_multiple_of(4096)
        || end.is_none_or(|end| end > 0x0200_0000)
    {
        return Err(Error::Registers);
    }
    let mut cursor = 4096usize; // hardware pointer writebacks, separate from rings
    let mut shadow = 0usize;
    let mut queues = Vec::new();
    for (pipe, cfg) in config.pipes.iter().enumerate() {
        if cfg.tx == 0 && cfg.rx == 0 {
            continue;
        }
        if cfg.buffer_bytes == 0 || cfg.buffer_bytes > 8192 || !cfg.buffer_bytes.is_multiple_of(4) {
            return Err(Error::Registers);
        }
        for count in [cfg.tx, cfg.rx] {
            if count != 0 && (!count.is_power_of_two() || !(4..=4096).contains(&count)) {
                return Err(Error::Registers);
            }
        }
        let mut ring = |entries, words, status, group: u32, pointer, id| -> Result<Ring> {
            let offset = span(&mut cursor, entries * words * 4, 128)?;
            let r0 = config.base + pipe as u32 * config.stride + group;
            let ring = Ring {
                offset,
                shadow,
                entries,
                words,
                r0,
                r2: config.base + pipe as u32 * config.stride + pointer,
                id,
                position: 0,
                status,
                idle: false,
            };
            shadow += 4;
            Ok(ring)
        };
        let tx_ring = if cfg.tx != 0 {
            Some(ring(cfg.tx, 4, false, 0, 0x400, 64 + pipe as u32)?)
        } else {
            None
        };
        let rx_rings = if cfg.rx != 0 {
            Some((
                ring(cfg.rx, 2, false, 0x1000, 0x1400, 81 + pipe as u32)?,
                ring(cfg.rx, 4, true, 0x1058, 0x1408, 100 + pipe as u32)?,
            ))
        } else {
            None
        };
        let tx = tx_ring
            .map(|ring| -> Result<Tx> {
                Ok(Tx {
                    sensitive: alloc::vec![false;ring.entries],
                    reaped: 0,
                    ring,
                    buffers: span(&mut cursor, cfg.tx * cfg.buffer_bytes, 4096)?,
                })
            })
            .transpose()?;
        let rx = rx_rings
            .map(|(post, status)| -> Result<Rx> {
                Ok(Rx {
                    post,
                    status,
                    buffers: span(&mut cursor, cfg.rx * cfg.buffer_bytes, 4096)?,
                    read: 0,
                    outstanding: 0,
                })
            })
            .transpose()?;
        queues.push(Queue {
            pipe: pipe as u8,
            bytes: cfg.buffer_bytes,
            tx,
            rx,
        });
    }
    Ok((cursor, queues))
}
impl<M: Memory> Engine<M> {
    pub fn required_bytes(config: Config) -> Result<usize> {
        Ok(plan(config)?.0)
    }
    /// Memory must back at least `bytes` bytes and remain owned for the device lifetime.
    pub fn new(config: Config, memory: M, bytes: usize) -> Result<Self> {
        let (needed, queues) = plan(config)?;
        if bytes < needed
            || !memory.physical().is_multiple_of(128)
            || memory
                .physical()
                .checked_add(needed as u64)
                .is_none_or(|end| end > 1u64 << 32)
        {
            return Err(Error::Pointer);
        }
        Ok(Self {
            memory,
            bytes: needed,
            config,
            queues,
            incoming: VecDeque::new(),
            started: false,
        })
    }
    pub fn start(&mut self, io: &mut impl Registers) -> Result<()> {
        if self.started {
            return Err(Error::State);
        }
        for queue in &mut self.queues {
            if let Some(tx) = &queue.tx {
                tx.ring.initialize(io, &mut self.memory)?;
            }
            if let Some(rx) = &mut queue.rx {
                rx.post.initialize(io, &mut self.memory)?;
                rx.status.initialize(io, &mut self.memory)?;
                let control =
                    self.config.base + u32::from(queue.pipe) * self.config.stride + 0x10b0;
                let value = (io.read(control)? & !0xffff) | queue.bytes as u32;
                io.write(control, value)?;
                for _ in 0..rx.post.entries - 2 {
                    post_receive(&mut self.memory, io, rx, queue.bytes)?;
                }
            }
        }
        self.started = true;
        Ok(())
    }
    pub fn send(&mut self, io: &mut impl Registers, pipe: u8, bytes: &[u8]) -> Result<()> {
        self.send_inner(io, pipe, bytes, false)
    }
    pub fn send_sensitive(
        &mut self,
        io: &mut impl Registers,
        pipe: u8,
        bytes: &[u8],
    ) -> Result<()> {
        self.send_inner(io, pipe, bytes, true)
    }
    fn send_inner(
        &mut self,
        io: &mut impl Registers,
        pipe: u8,
        bytes: &[u8],
        sensitive: bool,
    ) -> Result<()> {
        if !self.started {
            return Err(Error::State);
        }
        let queue = self
            .queues
            .iter_mut()
            .find(|queue| queue.pipe == pipe)
            .ok_or(Error::Registers)?;
        let tx = queue.tx.as_mut().ok_or(Error::Registers)?;
        if bytes.is_empty() || bytes.len() > queue.bytes {
            return Err(Error::Packet);
        }
        let done = tx.ring.hardware(&self.memory)?;
        while tx.reaped != done {
            if tx.sensitive[tx.reaped] {
                for at in (tx.buffers + tx.reaped * queue.bytes
                    ..tx.buffers + (tx.reaped + 1) * queue.bytes)
                    .step_by(4)
                {
                    self.memory.write32(at, 0);
                }
                tx.sensitive[tx.reaped] = false;
            }
            tx.reaped = (tx.reaped + 1) % tx.ring.entries;
        }
        let next = (tx.ring.position + 1) % tx.ring.entries;
        if next == tx.ring.hardware(&self.memory)? {
            return Err(Error::Full);
        }
        let buffer = tx.buffers + tx.ring.position * queue.bytes;
        self.memory.copy_in(buffer, bytes);
        tx.sensitive[tx.ring.position] = sensitive;
        let desc = tx.ring.offset + tx.ring.position * 16;
        self.memory
            .write32(desc, (self.memory.physical() + buffer as u64) as u32);
        self.memory.write32(desc + 4, (bytes.len() as u32) << 16);
        self.memory.write32(desc + 8, tx.ring.position as u32);
        self.memory.write32(desc + 12, 0);
        tx.ring.position = next;
        tx.ring.publish(io)
    }
    pub fn poll(&mut self, io: &mut impl Registers) -> Result<()> {
        if !self.started {
            return Err(Error::State);
        }
        let mut budget = 64;
        for queue in &mut self.queues {
            if let Some(tx) = &mut queue.tx {
                let done = tx.ring.hardware(&self.memory)?;
                while tx.reaped != done {
                    if tx.sensitive[tx.reaped] {
                        let at = tx.buffers + tx.reaped * queue.bytes;
                        for offset in (at..at + queue.bytes).step_by(4) {
                            self.memory.write32(offset, 0);
                        }
                        tx.sensitive[tx.reaped] = false;
                    }
                    tx.reaped = (tx.reaped + 1) % tx.ring.entries;
                }
            }
            let Some(rx) = &mut queue.rx else { continue };
            let hardware = rx.status.hardware(&self.memory)?;
            let mut pipe_budget = 16;
            while rx.status.position != hardware
                && budget != 0
                && pipe_budget != 0
                && self.incoming.len() < 64
            {
                if rx.outstanding == 0 {
                    return Err(Error::Completion);
                }
                let offset = rx.status.offset + rx.status.position * 16;
                let flags = self.memory.read32(offset);
                let length = (flags >> 16) as usize;
                if length == 0 || length > queue.bytes || flags & (1 << 11) != 0 {
                    return Err(Error::Packet);
                }
                let bytes = self
                    .memory
                    .copy_out(rx.buffers + rx.read * queue.bytes, length);
                self.incoming.push_back((queue.pipe, bytes));
                self.memory.write32(offset, 0);
                rx.read = (rx.read + 1) % rx.post.entries;
                rx.outstanding -= 1;
                rx.status.position = (rx.status.position + 1) % rx.status.entries;
                rx.status.publish(io)?;
                post_receive(&mut self.memory, io, rx, queue.bytes)?;
                budget -= 1;
                pipe_budget -= 1;
            }
        }
        Ok(())
    }
    pub fn receive(&mut self) -> Option<(u8, Vec<u8>)> {
        self.incoming.pop_front()
    }
    /// Read host DMA storage after firmware has entered crash-dump mode.
    /// This does not access device registers or reconfigure any queue.
    pub fn snapshot(&self) -> (u64, Vec<u8>) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let mut bytes = self.memory.copy_out(0, self.bytes);
        for queue in &self.queues {
            if let Some(tx) = &queue.tx {
                for (slot, sensitive) in tx.sensitive.iter().enumerate() {
                    if *sensitive {
                        let at = tx.buffers + slot * queue.bytes;
                        bytes[at..at + queue.bytes].fill(0);
                    }
                }
            }
        }
        (self.memory.physical(), bytes)
    }
    pub fn log_state(&mut self, io: &mut impl Registers) {
        for queue in &self.queues {
            let rings = [
                queue.tx.as_ref().map(|tx| &tx.ring),
                queue.rx.as_ref().map(|rx| &rx.post),
                queue.rx.as_ref().map(|rx| &rx.status),
            ];
            for ring in rings.into_iter().flatten() {
                crate::compact_println!(
                    "CE: pipe={} status={} base={:016x} r0={:08x} misc={:08x} hp={} tp={} shadow={}",
                    queue.pipe,
                    ring.status,
                    self.memory.physical() + ring.offset as u64,
                    ring.r0,
                    io.read(ring.r0 + 0x10).unwrap_or(u32::MAX),
                    io.read(ring.r2).unwrap_or(u32::MAX),
                    io.read(ring.r2 + 4).unwrap_or(u32::MAX),
                    self.memory.read32(ring.shadow)
                );
            }
        }
    }
}
fn post_receive(
    memory: &mut impl Memory,
    io: &mut impl Registers,
    rx: &mut Rx,
    bytes: usize,
) -> Result<()> {
    let next = (rx.post.position + 1) % rx.post.entries;
    if next == rx.post.hardware(memory)? {
        return Err(Error::Full);
    }
    let address = memory.physical() + (rx.buffers + rx.post.position * bytes) as u64;
    let offset = rx.post.offset + rx.post.position * 8;
    memory.write64(offset, address);
    rx.post.position = next;
    rx.outstanding += 1;
    rx.post.publish(io)
}

#[cfg(test)]
mod tests;
