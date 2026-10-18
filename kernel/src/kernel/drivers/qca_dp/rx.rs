// SPDX-License-Identifier: BSD-3-Clause-Clear
// Firmware ring/pool setup references Linux v7.0 ath12k dp_rx.c and hal.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
//! Firmware-owned receive rings and a bounded boot-lifetime buffer pool.
//!
//! Consumed buffers remain reserved. Recycling requires validated packet
//! completions, which is a later data-path step; firmware consuming a refill
//! descriptor is not proof that it has finished DMA to the packet buffer.
use super::{Error, Memory, Result};
use crate::kernel::htt;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Refill,
    Mac,
    Exception,
    Monitor,
}
#[derive(Clone, Copy)]
pub struct RingConfig {
    pub id: u8,
    pub pdev: u8,
    pub direction: u8,
    pub role: Role,
    pub entries: usize,
    pub words: usize,
}
#[derive(Clone, Copy)]
pub struct Config {
    pub rings: &'static [RingConfig],
    pub buffers: usize,
    pub buffer_bytes: usize,
    pub return_manager: u8,
}
struct Remote {
    config: RingConfig,
    base: usize,
    head: usize,
    tail: usize,
}
impl Remote {
    fn wire(&self, physical: u64) -> htt::Ring {
        htt::Ring {
            id: self.config.id,
            pdev: self.config.pdev,
            direction: self.config.direction,
            entries: self.config.entries,
            words: self.config.words,
            base: physical + self.base as u64,
            head: physical + self.head as u64,
            tail: physical + self.tail as u64,
        }
    }
    fn pointers(&self, memory: &impl Memory) -> Result<(usize, usize)> {
        let head = memory.read32(self.head) as usize;
        let tail = memory.read32(self.tail) as usize;
        fence(Ordering::Acquire);
        if [head, tail].iter().any(|v| {
            *v >= self.config.entries * self.config.words || !v.is_multiple_of(self.config.words)
        }) {
            return Err(Error::Pointer);
        }
        Ok((head / self.config.words, tail / self.config.words))
    }
}
struct Plan {
    rings: Vec<Remote>,
    pool: usize,
    bytes: usize,
    refill: usize,
}
fn plan(config: Config) -> Result<Plan> {
    if config.rings.is_empty()
        || config.rings.len() > 16
        || !(4..=16384).contains(&config.buffers)
        || !(512..=4096).contains(&config.buffer_bytes)
        || !config.buffer_bytes.is_multiple_of(128)
        || config.return_manager > 15
    {
        return Err(Error::Registers);
    }
    let mut cursor = 4096usize;
    let mut rings = Vec::new();
    let mut refill = None;
    for (index, spec) in config.rings.iter().enumerate() {
        if (spec.role == Role::Exception) != (spec.direction == 0) {
            return Err(Error::Registers);
        }
        if spec.role == Role::Refill && (refill.replace(index).is_some() || spec.words != 2) {
            return Err(Error::Registers);
        }
        if config.rings[..index]
            .iter()
            .any(|old| old.id == spec.id && old.pdev == spec.pdev)
        {
            return Err(Error::Registers);
        }
        let ring = Remote {
            config: *spec,
            base: cursor,
            head: index * 128,
            tail: index * 128 + 64,
        };
        htt::setup(ring.wire(0x100000))?; // validate sizes and wire representation
        cursor = cursor
            .checked_add(spec.entries * spec.words * 4)
            .ok_or(Error::Pointer)?;
        cursor = (cursor + 127) & !127;
        rings.push(ring);
    }
    let refill = refill.ok_or(Error::Registers)?;
    if config.buffers < rings[refill].config.entries - 1 {
        return Err(Error::Registers);
    }
    let pool = cursor;
    let bytes = pool
        .checked_add(config.buffers * config.buffer_bytes)
        .ok_or(Error::Pointer)?;
    Ok(Plan {
        rings,
        pool,
        bytes,
        refill,
    })
}
pub struct Receive<M> {
    memory: M,
    config: Config,
    rings: Vec<Remote>,
    pool: usize,
    refill: usize,
    cookie_base: u32,
    next_buffer: usize,
    producer: usize,
    active: bool,
    live: Vec<bool>,
    recycled: alloc::collections::VecDeque<usize>,
}
impl<M: Memory> Receive<M> {
    pub fn required_bytes(config: Config) -> Result<usize> {
        Ok(plan(config)?.bytes)
    }
    pub fn new(
        config: Config,
        memory: M,
        capacity: usize,
        cookies: core::ops::Range<u32>,
    ) -> Result<Self> {
        let p = plan(config)?;
        if capacity < p.bytes
            || !memory.physical().is_multiple_of(128)
            || memory
                .physical()
                .checked_add(p.bytes as u64)
                .is_none_or(|end| end > 1u64 << 32)
            || cookies.end > 1 << 20
            || cookies.start >= cookies.end
            || cookies.end - cookies.start < config.buffers as u32
        {
            return Err(Error::Pointer);
        }
        Ok(Self {
            memory,
            config,
            rings: p.rings,
            pool: p.pool,
            refill: p.refill,
            cookie_base: cookies.start,
            next_buffer: 0,
            producer: 0,
            active: false,
            live: alloc::vec![false;config.buffers],
            recycled: alloc::collections::VecDeque::new(),
        })
    }
    pub fn start(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::State);
        }
        for ring in &self.rings {
            self.memory.write32(ring.head, 0);
            self.memory.write32(ring.tail, 0);
        }
        self.active = true;
        self.poll()?;
        self.log_state();
        Ok(())
    }
    pub fn commands(&self) -> Result<Vec<Vec<u8>>> {
        if !self.active {
            return Err(Error::State);
        }
        self.rings
            .iter()
            .map(|r| htt::setup(r.wire(self.memory.physical())))
            .collect()
    }
    pub fn poll(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        for ring in &self.rings {
            ring.pointers(&self.memory)?;
        }
        let ring = &self.rings[self.refill];
        let (head, tail) = ring.pointers(&self.memory)?;
        if head != self.producer {
            return Err(Error::Pointer);
        }
        while self.next_buffer < self.config.buffers || !self.recycled.is_empty() {
            let next = (self.producer + 1) % ring.config.entries;
            if next == tail {
                break;
            }
            let slot = if let Some(slot) = self.recycled.pop_front() {
                slot
            } else {
                let slot = self.next_buffer;
                self.next_buffer += 1;
                slot
            };
            if self.live[slot] {
                return Err(Error::Pointer);
            }
            self.live[slot] = true;
            let start = self.pool + slot * self.config.buffer_bytes;
            for at in (start..start + self.config.buffer_bytes).step_by(4) {
                self.memory.write32(at, 0);
            }
            let address = self.memory.physical() + start as u64;
            let cookie = self.cookie_base + slot as u32;
            let at = ring.base + self.producer * 8;
            self.memory.write32(at, address as u32);
            self.memory.write32(
                at + 4,
                ((address >> 32) as u32 & 255)
                    | (u32::from(self.config.return_manager) << 8)
                    | (cookie << 12),
            );
            self.producer = next;
        }
        fence(Ordering::Release);
        self.memory
            .write32(ring.head, (self.producer * ring.config.words) as u32);
        Ok(())
    }
    /// A validated host destination-ring completion transfers buffer ownership.
    /// The returned descriptor and packet are CPU copies; recycling happens on poll.
    pub fn complete(&mut self, cookie: u32) -> Result<Vec<u8>> {
        let slot = cookie.checked_sub(self.cookie_base).ok_or(Error::Pointer)? as usize;
        if slot >= self.live.len() || !self.live[slot] {
            return Err(Error::Completion);
        }
        let bytes = self.memory.copy_out(
            self.pool + slot * self.config.buffer_bytes,
            self.config.buffer_bytes,
        );
        self.live[slot] = false;
        self.recycled.push_back(slot);
        Ok(bytes)
    }
    pub fn log_state(&self) {
        if !self.active {
            return;
        }
        crate::compact_println!(
            "WiFi: RX buffers posted={} reserve={} bytes={}",
            self.next_buffer,
            self.config.buffers - self.next_buffer,
            self.config.buffer_bytes
        );
        for ring in &self.rings {
            crate::compact_println!(
                "WiFi: RX ring={} pdev={} head={} tail={}",
                u32::from(ring.config.id),
                u32::from(ring.config.pdev),
                self.memory.read32(ring.head),
                self.memory.read32(ring.tail)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::drivers::qca_dp::tests::Ram;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;
    const CONFIG: Config = Config {
        rings: &[
            RingConfig {
                id: 5,
                pdev: 0,
                direction: 2,
                role: Role::Refill,
                entries: 4,
                words: 2,
            },
            RingConfig {
                id: 0,
                pdev: 1,
                direction: 1,
                role: Role::Mac,
                entries: 4,
                words: 2,
            },
        ],
        buffers: 8,
        buffer_bytes: 2048,
        return_manager: 6,
    };
    #[test]
    fn firmware_consumption_replenishes_with_fresh_buffers_and_never_reuses_live_dma() {
        let bytes = Receive::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        let mut rx = Receive::new(CONFIG, memory.clone(), bytes, 0x20000..0x21000).unwrap();
        assert!(rx.commands().is_err());
        rx.start().unwrap();
        assert_eq!(rx.next_buffer, 3);
        let first = memory.read32(rx.rings[0].base);
        assert_eq!(memory.read32(rx.rings[0].base + 4), 0x20000600);
        assert_eq!(rx.commands().unwrap().len(), 2);
        memory.clone().write32(rx.rings[0].tail, 6);
        rx.poll().unwrap();
        assert_eq!(rx.next_buffer, 6);
        assert_ne!(memory.read32(rx.rings[0].base), first);
        memory.clone().write32(rx.rings[0].tail, 4);
        rx.poll().unwrap();
        assert_eq!(rx.next_buffer, 8);
        let pointer = memory.read32(rx.rings[0].head);
        memory.clone().write32(rx.rings[0].tail, pointer);
        rx.poll().unwrap();
        assert_eq!(rx.next_buffer, 8); // no unsafe buffer recycling after pool exhaustion
    }
    #[test]
    fn bad_dma_pointers_or_cookie_ranges_cannot_produce_descriptors() {
        let bytes = Receive::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        assert!(Receive::new(CONFIG, memory.clone(), bytes, 0..7).is_err());
        let mut rx = Receive::new(CONFIG, memory.clone(), bytes, 0..8).unwrap();
        rx.start().unwrap();
        memory.clone().write32(rx.rings[0].tail, 1);
        assert_eq!(rx.poll(), Err(Error::Pointer));
        memory.clone().write32(rx.rings[0].tail, 8);
        assert_eq!(rx.poll(), Err(Error::Pointer));
    }
}
#[cfg(test)]
mod completion_tests {
    use super::*;
    use crate::kernel::drivers::qca_dp::tests::Ram;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;
    #[test]
    fn only_a_posted_buffer_can_complete_and_recycling_waits_for_refill_space() {
        const CFG: Config = Config {
            rings: &[RingConfig {
                id: 5,
                pdev: 0,
                direction: 2,
                role: Role::Refill,
                entries: 4,
                words: 2,
            }],
            buffers: 4,
            buffer_bytes: 2048,
            return_manager: 6,
        };
        let n = Receive::<Ram>::required_bytes(CFG).unwrap();
        let mut ram = Ram(Rc::new(RefCell::new(vec![0; n])));
        let mut rx = Receive::new(CFG, ram.clone(), n, 100..104).unwrap();
        rx.start().unwrap();
        assert!(rx.complete(99).is_err());
        assert!(rx.complete(103).is_err());
        ram.copy_in(rx.pool, b"packet");
        assert_eq!(&rx.complete(100).unwrap()[..6], b"packet");
        assert!(rx.complete(100).is_err());
        rx.poll().unwrap();
        assert!(!rx.live[0]);
        ram.write32(rx.rings[0].tail, 2);
        rx.poll().unwrap();
        assert!(rx.live[0]);
        assert_eq!(ram.read32(rx.pool), 0);
    }
}
