//! MHI boot and paired packet channels. Register access and DMA storage are injected
//! so protocol/state-machine tests exercise the same code as the PCI driver.
//! Register/protocol reference: Linux v6.8 MHI and ath12k; no Linux runtime.
pub mod dma;
pub mod dump;
use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{Ordering, fence};

pub const CONTEXT_BYTES: usize = 0x9000;
pub const PACKET_BYTES: usize = 8192;
pub const PACKET_STORAGE: usize = PACKET_BYTES * 128;
pub const SEGMENT: usize = 512 * 1024;
const CHANNEL_CONTEXT: usize = 44;
const EVENT_CONTEXT: usize = 0x2000;
// Match the page separation provided by Linux coherent allocations on x86.
// Keep each context array and ring on its own page even for sub-page rings.
const COMMAND_CONTEXT: usize = 0x3000;
const COMMAND_RING: usize = 0x4000;
const EVENTS: [usize; 2] = [0x5000, 0x6000];
const EVENT_COUNTS: [usize; 2] = [32, 256];
const TRANSFERS: [usize; 2] = [0x7000, 0x8000];
const DEPTH: usize = 64;
const CTRL: u32 = 0x38;
const STATUS: u32 = 0x48;
const TIMEOUT: u64 = 5_000_000_000;
const MAX_SPINS: usize = 5_000_000;

/// One host-to-device and one device-to-host channel, independent of the
/// protocol carried on them. Channel 127 is reserved for the wake doorbell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channels([u8; 2]);
impl Channels {
    pub const fn new(transmit: u8, receive: u8) -> Option<Self> {
        if transmit >= 127 || receive >= 127 || transmit == receive {
            None
        } else {
            Some(Self([transmit, receive]))
        }
    }
}

/// DMA addresses for BHI's first stage and BHIE's full-image vector table.
pub struct Firmware {
    pub first_stage: u64,
    pub first_bytes: usize,
    pub vectors: u64,
    pub vector_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Registers,
    Link,
    Timeout,
    Firmware,
    State,
    Pointer,
    Completion,
    Allocation,
    Full,
    Packet,
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::Registers => "invalid register layout",
            Self::Link => "PCIe link lost",
            Self::Timeout => "device timeout",
            Self::Firmware => "firmware transfer failed",
            Self::State => "device state error",
            Self::Pointer => "invalid DMA completion pointer",
            Self::Completion => "unexpected DMA completion",
            Self::Allocation => "DMA memory or device mapping allocation failed",
            Self::Full => "transport queue full",
            Self::Packet => "invalid control packet",
        }
    }
}
pub type Result<T> = core::result::Result<T, Error>;

pub trait Registers {
    fn read(&mut self, offset: u32) -> Result<u32>;
    fn write(&mut self, offset: u32, value: u32) -> Result<()>;
    fn now(&mut self) -> u64;
}

pub trait Memory {
    fn physical(&self) -> u64;
    fn read32(&self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn copy_in(&mut self, offset: usize, bytes: &[u8]);
    fn copy_out(&self, offset: usize, count: usize) -> Vec<u8>;
    fn write64(&mut self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
    fn read64(&self, offset: usize) -> u64 {
        u64::from(self.read32(offset)) | (u64::from(self.read32(offset + 4)) << 32)
    }
}

fn doorbell(io: &mut impl Registers, offset: u32, value: u64) -> Result<()> {
    fence(Ordering::Release);
    io.write(offset + 4, (value >> 32) as u32)?;
    io.write(offset, value as u32)
}

fn wait(
    io: &mut impl Registers,
    mut condition: impl FnMut(&mut dyn Registers) -> Result<bool>,
) -> Result<()> {
    let deadline = io.now().saturating_add(TIMEOUT);
    for _ in 0..MAX_SPINS {
        if condition(io)? {
            return Ok(());
        }
        if io.now() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    Err(Error::Timeout)
}

#[derive(Clone, Copy)]
pub struct Layout {
    pub bhi: u32,
    pub bhie: u32,
    pub channel_db: u32,
    pub event_db: u32,
}
impl Layout {
    pub fn read(io: &mut impl Registers, register_bytes: u32) -> Result<Self> {
        let this = Self {
            bhi: io.read(0x28)?,
            bhie: io.read(0x2c)?,
            channel_db: io.read(0x18)?,
            event_db: io.read(0x20)?,
        };
        for (offset, bytes) in [
            (this.bhi, 0xc8),
            (this.bhie, 0x80),
            (this.channel_db, 128 * 8),
            (this.event_db, 2 * 8),
        ] {
            if offset < 0x100
                || !offset.is_multiple_of(4)
                || offset
                    .checked_add(bytes)
                    .is_none_or(|end| end > register_bytes)
            {
                return Err(Error::Registers);
            }
        }
        Ok(this)
    }
}

fn context(memory: &mut impl Memory, offset: usize, base: usize, bytes: usize) {
    let pointer = memory.physical() + base as u64;
    memory.write64(offset + 12, pointer);
    memory.write64(offset + 20, bytes as u64);
    memory.write64(offset + 28, pointer);
    memory.write64(offset + 36, pointer);
}

pub fn initialize_contexts(memory: &mut impl Memory, channels: Channels) -> Result<()> {
    let limit = memory
        .physical()
        .checked_add(CONTEXT_BYTES as u64)
        .ok_or(Error::Pointer)?;
    if !memory.physical().is_multiple_of(4096) || limit > 1u64 << 32 {
        return Err(Error::Pointer);
    }
    // MHI rings must be aligned to their full length, not merely to a TRE.
    // Check before writing contexts or publishing their addresses to hardware.
    for (offset, count) in [
        (COMMAND_RING, 128),
        (EVENTS[0], EVENT_COUNTS[0]),
        (EVENTS[1], EVENT_COUNTS[1]),
        (TRANSFERS[0], DEPTH),
        (TRANSFERS[1], DEPTH),
    ] {
        let bytes = (count * 16) as u64;
        let base = memory
            .physical()
            .checked_add(offset as u64)
            .ok_or(Error::Pointer)?;
        if !base.is_multiple_of(bytes) || base.checked_add(bytes).is_none_or(|end| end > limit) {
            return Err(Error::Pointer);
        }
    }
    for channel in 0..128 {
        memory.write32(channel * CHANNEL_CONTEXT, 2 << 8);
    }
    for index in 0..2 {
        let ch = usize::from(channels.0[index]) * CHANNEL_CONTEXT;
        memory.write32(ch + 4, (index + 1) as u32);
        memory.write32(ch + 8, 1);
        context(memory, ch, TRANSFERS[index], DEPTH * 16);
        let er = EVENT_CONTEXT + index * CHANNEL_CONTEXT;
        memory.write32(er, (index as u32) << 16);
        memory.write32(er + 4, 1); // valid software event ring
        memory.write32(er + 8, 0); // shared single MSI vector
        context(memory, er, EVENTS[index], EVENT_COUNTS[index] * 16);
        memory.write64(
            er + 36,
            memory.physical() + (EVENTS[index] + (EVENT_COUNTS[index] - 1) * 16) as u64,
        );
    }
    context(memory, COMMAND_CONTEXT, COMMAND_RING, 128 * 16);
    Ok(())
}

/// Transfer the signed first-stage image, publish DMA contexts, then transfer
/// the full image's vector list. Sequence IDs are protocol cookies, not secrets.
pub fn boot(
    io: &mut impl Registers,
    memory: &mut impl Memory,
    layout: Layout,
    channels: Channels,
    firmware: Firmware,
) -> Result<()> {
    let Firmware {
        first_stage,
        first_bytes,
        vectors,
        vector_bytes,
    } = firmware;
    if first_bytes == 0
        || first_bytes > SEGMENT
        || vector_bytes == 0
        || !vector_bytes.is_multiple_of(16)
    {
        return Err(Error::Firmware);
    }
    wait(io, |io| Ok(io.read(CTRL)? & 2 == 0))?;
    io.write(layout.bhi + 0x20, 0)?;
    let ee = io.read(layout.bhi + 0x28)?;
    if ee == 0 {
        io.write(layout.bhi + 0x2c, 0)?;
        io.write(layout.bhi + 0x0c, (first_stage >> 32) as u32)?;
        io.write(layout.bhi + 0x08, first_stage as u32)?;
        io.write(layout.bhi + 0x10, first_bytes as u32)?;
        fence(Ordering::Release);
        io.write(layout.bhi + 0x18, 1)?;
        wait(io, |io| match io.read(layout.bhi + 0x2c)? >> 30 {
            0 => Ok(false),
            2 => Ok(true),
            _ => Err(Error::Firmware),
        })?;
    } else if !matches!(ee, 1 | 2 | 4) {
        return Err(Error::State);
    }
    wait(io, |io| {
        let value = io.read(STATUS)?;
        if value & 4 != 0 {
            return Err(Error::State);
        }
        Ok(value & 1 != 0 && io.read(CTRL)? & 2 == 0)
    })?;
    initialize_contexts(memory, channels)?;
    for (offset, address) in [
        (0x58, memory.physical()),
        (0x60, memory.physical() + EVENT_CONTEXT as u64),
        (0x68, memory.physical() + COMMAND_CONTEXT as u64),
        (0x80, 0),
        (0x88, 0xffff_ffff),
        (0x98, 0),
        (0xa0, 0xffff_ffff),
    ] {
        doorbell(io, offset, address)?;
    }
    let config = (io.read(0x10)? & 0x0000_ffff) | (2 << 16);
    io.write(0x10, config)?;
    for index in 0..2 {
        doorbell(
            io,
            layout.event_db + index as u32 * 8,
            memory.read64(EVENT_CONTEXT + index * CHANNEL_CONTEXT + 36),
        )?;
    }
    let ctrl = (io.read(CTRL)? & !(0xff << 8)) | (2 << 8);
    io.write(CTRL, ctrl)?;
    wait(io, |io| {
        let status = io.read(STATUS)?;
        if status & 4 != 0 {
            return Err(Error::State);
        }
        Ok((status >> 8) & 0xff == 2)
    })?;
    doorbell(io, layout.channel_db + 127 * 8, 1)?;
    wait(io, |io| match io.read(layout.bhi + 0x28)? {
        1 | 2 | 4 => Ok(true),
        0 => Ok(false),
        _ => Err(Error::State),
    })?;
    if io.read(layout.bhi + 0x28)? == 1 {
        io.write(layout.bhie + 0x30, (vectors >> 32) as u32)?;
        io.write(layout.bhie + 0x2c, vectors as u32)?;
        io.write(layout.bhie + 0x34, vector_bytes as u32)?;
        fence(Ordering::Release);
        io.write(layout.bhie + 0x3c, 2)?;
        wait(io, |io| match io.read(layout.bhie + 0x44)? >> 30 {
            0 => Ok(false),
            2 => Ok(true),
            _ => Err(Error::Firmware),
        })?;
    }
    wait(io, |io| match io.read(layout.bhi + 0x28)? {
        2 | 4 => Ok(true),
        1 => Ok(false),
        _ => Err(Error::State),
    })
}

fn ring_index(pointer: u64, base: u64, count: usize) -> Result<usize> {
    let offset = pointer.checked_sub(base).ok_or(Error::Pointer)?;
    if offset >= (count * 16) as u64 || !offset.is_multiple_of(16) {
        return Err(Error::Pointer);
    }
    Ok(offset as usize / 16)
}

pub struct Transport<R, M> {
    pub io: R,
    pub contexts: M,
    pub packets: M,
    layout: Layout,
    channels: Channels,
    event_read: [usize; 2],
    command_write: usize,
    pending_command: Option<(u64, u8)>,
    command_done: bool,
    reprime: bool,
    tx_read: usize,
    tx_write: usize,
    rx_read: usize,
    rx_write: usize,
    incoming: VecDeque<Vec<u8>>,
}
impl<R: Registers, M: Memory> Transport<R, M> {
    pub fn new(io: R, contexts: M, packets: M, layout: Layout, channels: Channels) -> Self {
        Self {
            io,
            contexts,
            packets,
            layout,
            channels,
            event_read: [0; 2],
            command_write: 0,
            pending_command: None,
            command_done: false,
            reprime: false,
            tx_read: 0,
            tx_write: 0,
            rx_read: 0,
            rx_write: 0,
            incoming: VecDeque::new(),
        }
    }
    pub fn start(&mut self) -> Result<()> {
        // AMSS may have replaced the bootloader that saw the first doorbells.
        // Bring mission firmware to M0 and republish ring credits before commands.
        self.activate()?;
        // A readable mission EE register can precede consumption of the
        // corresponding M0/EE events. Acknowledge those before the first command.
        self.poll()?;
        for channel in self.channels.0 {
            self.contexts
                .write32(usize::from(channel) * CHANNEL_CONTEXT, (2 << 8) | 1);
            let offset = COMMAND_RING + self.command_write * 16;
            self.contexts.write64(offset, 0);
            self.contexts.write32(offset + 8, 0);
            self.contexts
                .write32(offset + 12, (u32::from(channel) << 24) | (0x12 << 16));
            self.pending_command = Some((self.contexts.physical() + offset as u64, channel));
            self.command_done = false;
            self.command_write = (self.command_write + 1) % 128;
            let pointer =
                self.contexts.physical() + (COMMAND_RING + self.command_write * 16) as u64;
            self.contexts.write64(COMMAND_CONTEXT + 36, pointer);
            doorbell(&mut self.io, 0x70, pointer)?;
            let started = self.io.now();
            let deadline = started.saturating_add(TIMEOUT);
            let mut completed = false;
            for _ in 0..MAX_SPINS {
                self.poll()?;
                if self.command_done {
                    completed = true;
                    break;
                }
                if self.io.now() >= deadline {
                    break;
                }
            }
            if !completed {
                crate::compact_println!(
                    "MHI: START channel={} timed out after {} ms",
                    channel,
                    self.io.now().saturating_sub(started) / 1_000_000
                );
                return Err(Error::Timeout);
            }
        }
        for _ in 0..DEPTH - 1 {
            self.post_receive()?;
        }
        Ok(())
    }
    fn activate(&mut self) -> Result<()> {
        doorbell(&mut self.io, self.layout.channel_db + 127 * 8, 1)?;
        let status = self.io.read(STATUS)?;
        if status & 4 != 0 {
            return Err(Error::State);
        }
        if (status >> 8) & 0xff != 2 {
            let control = (self.io.read(CTRL)? & !(0xff << 8)) | (2 << 8);
            self.io.write(CTRL, control)?;
            wait(&mut self.io, |io| {
                let value = io.read(STATUS)?;
                if value & 4 != 0 {
                    return Err(Error::State);
                }
                Ok((value >> 8) & 0xff == 2)
            })?;
        }
        for er in 0..2 {
            doorbell(
                &mut self.io,
                self.layout.event_db + er as u32 * 8,
                self.contexts
                    .read64(EVENT_CONTEXT + er * CHANNEL_CONTEXT + 36),
            )?;
        }
        if self.pending_command.is_some() {
            doorbell(
                &mut self.io,
                0x70,
                self.contexts.read64(COMMAND_CONTEXT + 36),
            )?;
        }
        if self.tx_read != self.tx_write {
            self.publish_channel(0, self.tx_write)?;
        }
        if self.rx_read != self.rx_write {
            self.publish_channel(1, self.rx_write)?;
        }
        Ok(())
    }
    pub fn log_state(&mut self) {
        crate::compact_println!(
            "MHI: control={:08x} status={:08x} EE={:08x} pending_channel={}",
            self.io.read(CTRL).unwrap_or(u32::MAX),
            self.io.read(STATUS).unwrap_or(u32::MAX),
            self.io.read(self.layout.bhi + 0x28).unwrap_or(u32::MAX),
            self.pending_command
                .map(|(_, ch)| u32::from(ch))
                .unwrap_or(u32::MAX)
        );
        for (name, offset) in [
            ("CCABAP", 0x58),
            ("ECABAP", 0x60),
            ("CRCBAP", 0x68),
            ("CRDB", 0x70),
        ] {
            crate::compact_println!(
                "MHI: {} register={:08x}:{:08x}",
                name,
                self.io.read(offset + 4).unwrap_or(u32::MAX),
                self.io.read(offset).unwrap_or(u32::MAX)
            );
        }
        crate::compact_println!(
            "MHI: config={:08x} CHDB={:08x} ERDB={:08x} context_dma={:016x}",
            self.io.read(0x10).unwrap_or(u32::MAX),
            self.io.read(0x18).unwrap_or(u32::MAX),
            self.io.read(0x20).unwrap_or(u32::MAX),
            self.contexts.physical()
        );
        if let Some((pointer, _)) = self.pending_command
            && let Ok(index) =
                ring_index(pointer, self.contexts.physical() + COMMAND_RING as u64, 128)
        {
            let offset = COMMAND_RING + index * 16;
            crate::compact_println!(
                "MHI: pending TRE={:016x} {:08x} {:08x}",
                self.contexts.read64(offset),
                self.contexts.read32(offset + 8),
                self.contexts.read32(offset + 12)
            );
        }
        for (name, offset) in [
            ("command", COMMAND_CONTEXT),
            ("event0", EVENT_CONTEXT),
            ("event1", EVENT_CONTEXT + CHANNEL_CONTEXT),
        ] {
            crate::compact_println!(
                "MHI: {} base={:016x} len={:x} rp={:016x} wp={:016x}",
                name,
                self.contexts.read64(offset + 12),
                self.contexts.read64(offset + 20),
                self.contexts.read64(offset + 28),
                self.contexts.read64(offset + 36)
            );
        }
        for channel in self.channels.0 {
            let offset = usize::from(channel) * CHANNEL_CONTEXT;
            crate::compact_println!(
                "MHI: channel={} config={:08x} rp={:016x} wp={:016x}",
                channel,
                self.contexts.read32(offset),
                self.contexts.read64(offset + 28),
                self.contexts.read64(offset + 36)
            );
        }
    }
    fn post_receive(&mut self) -> Result<()> {
        let index = self.rx_write;
        let offset = TRANSFERS[1] + index * 16;
        let address = self.packets.physical() + ((DEPTH + index) * PACKET_BYTES) as u64;
        self.contexts.write64(offset, address);
        self.contexts.write32(offset + 8, PACKET_BYTES as u32);
        self.contexts.write32(offset + 12, (2 << 16) | (1 << 9));
        self.rx_write = (index + 1) % DEPTH;
        self.publish_channel(1, self.rx_write)
    }
    fn publish_channel(&mut self, index: usize, position: usize) -> Result<()> {
        let pointer = self.contexts.physical() + (TRANSFERS[index] + position * 16) as u64;
        self.contexts.write64(
            usize::from(self.channels.0[index]) * CHANNEL_CONTEXT + 36,
            pointer,
        );
        doorbell(
            &mut self.io,
            self.layout.channel_db + u32::from(self.channels.0[index]) * 8,
            pointer,
        )
    }
    pub fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > PACKET_BYTES {
            return Err(Error::Packet);
        }
        let next = (self.tx_write + 1) % DEPTH;
        if next == self.tx_read {
            return Err(Error::Full);
        }
        self.packets.copy_in(self.tx_write * PACKET_BYTES, bytes);
        let offset = TRANSFERS[0] + self.tx_write * 16;
        self.contexts.write64(
            offset,
            self.packets.physical() + (self.tx_write * PACKET_BYTES) as u64,
        );
        self.contexts.write32(offset + 8, bytes.len() as u32);
        self.contexts.write32(offset + 12, (2 << 16) | (1 << 9));
        self.tx_write = next;
        self.publish_channel(0, next)
    }
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }
    pub fn reset(&mut self) {
        let _ = self.io.write(CTRL, 2);
    }
    pub fn poll(&mut self) -> Result<()> {
        let status = self.io.read(STATUS)?;
        if status & 4 != 0 {
            return Err(Error::State);
        }
        // Hold the wake doorbell asserted; this bring-up path has no runtime PM.
        if (status >> 8) & 0xff == 3 || (status >> 8) & 0xff == 4 {
            self.activate()?;
        }
        for er in 0..2 {
            let context = EVENT_CONTEXT + er * CHANNEL_CONTEXT;
            let base = self.contexts.physical() + EVENTS[er] as u64;
            let count = EVENT_COUNTS[er];
            let produced = ring_index(self.contexts.read64(context + 28), base, count)?;
            fence(Ordering::Acquire);
            let mut budget = count;
            while self.event_read[er] != produced && budget != 0 {
                let offset = EVENTS[er] + self.event_read[er] * 16;
                let pointer = self.contexts.read64(offset);
                let data = self.contexts.read32(offset + 8);
                let kind = self.contexts.read32(offset + 12);
                self.event(pointer, data, kind)?;
                self.event_read[er] = (self.event_read[er] + 1) % count;
                let write = (self.event_read[er] + count - 1) % count;
                let pointer = base + (write * 16) as u64;
                self.contexts.write64(context + 36, pointer);
                doorbell(&mut self.io, self.layout.event_db + er as u32 * 8, pointer)?;
                budget -= 1;
            }
        }
        // Ring again after acknowledging M0/mission events, even when the
        // status register already said M0 before this poll. Replaying a write
        // pointer preserves ring ownership and does not enqueue another command.
        if self.reprime {
            self.reprime = false;
            self.activate()?;
        }
        Ok(())
    }
    fn event(&mut self, pointer: u64, data: u32, kind: u32) -> Result<()> {
        match (kind >> 16) & 0xff {
            0x20 => {
                crate::compact_println!("MHI: state event={}", data >> 24);
                if data >> 24 == 0xff {
                    return Err(Error::State);
                }
                self.reprime |= data >> 24 == 2;
            }
            0x40 => {
                crate::compact_println!("MHI: execution environment event={}", data >> 24);
                if matches!(data >> 24, 3 | 6) {
                    return Err(Error::Firmware);
                }
                self.reprime |= matches!(data >> 24, 2 | 4);
            }
            0x21 => {
                let Some((expected, _)) = self.pending_command else {
                    return Err(Error::Completion);
                };
                if pointer != expected || data >> 24 != 1 {
                    return Err(Error::Completion);
                }
                self.pending_command = None;
                self.command_done = true;
            }
            0x22 => {
                let channel = kind >> 24;
                if !matches!(data >> 24, 2 | 4) {
                    return Err(Error::Completion);
                }
                let index = self
                    .channels
                    .0
                    .iter()
                    .position(|configured| u32::from(*configured) == channel)
                    .ok_or(Error::Completion)?;
                let position = ring_index(
                    pointer,
                    self.contexts.physical() + TRANSFERS[index] as u64,
                    DEPTH,
                )?;
                if index == 0 {
                    if position != self.tx_read || self.tx_read == self.tx_write {
                        return Err(Error::Completion);
                    }
                    self.tx_read = (self.tx_read + 1) % DEPTH;
                } else {
                    if position != self.rx_read || self.rx_read == self.rx_write {
                        return Err(Error::Completion);
                    }
                    let length = (data & 0xffff) as usize;
                    if length == 0 || length > PACKET_BYTES || self.incoming.len() >= 32 {
                        return Err(Error::Packet);
                    }
                    self.incoming.push_back(
                        self.packets
                            .copy_out((DEPTH + position) * PACKET_BYTES, length),
                    );
                    self.rx_read = (self.rx_read + 1) % DEPTH;
                    self.post_receive()?;
                }
            }
            _ => return Err(Error::Completion),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
