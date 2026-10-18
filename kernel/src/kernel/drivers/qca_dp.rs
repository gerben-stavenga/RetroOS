// SPDX-License-Identifier: BSD-3-Clause-Clear
// Descriptor/ring definitions reference Linux v6.8/v6.17 ath12k hal.c/dp.c
// and hal_rx.c/hal_desc.h for common-ring and REO global setup.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! Qualcomm packet-engine startup storage. This supplies hardware link
//! descriptors, common control/data rings and REO destinations. Packet
//! processing follows later. Cookie conversion uses driver-owned slot tokens.
use super::{
    mhi::{Error, Memory, Registers, Result},
    srng::Ring,
};
use alloc::vec::Vec;
pub mod cookie;
pub mod frames;
pub mod rx;

#[derive(Clone, Copy)]
pub struct RingConfig {
    pub r0: u32,
    pub r2: u32,
    pub id: u32,
    pub entries: usize,
    pub words: usize,
    pub destination: bool,
    pub command_numbers: bool,
}
#[derive(Clone, Copy)]
pub struct ReoConfig {
    pub base: u32,
    pub misc: u32,
    pub aging: u32,
}
#[derive(Clone, Copy)]
pub struct DataConfig {
    pub tx: u32,
    pub tx_completion: u32,
    pub rx_error: u32,
    pub bank: u32,
    pub return_manager: u8,
    pub pdev: u8,
}
pub struct Packets {
    pub frames: Vec<Vec<u8>>,
    pub transmitted: Vec<(u64, bool)>,
}
#[derive(Clone, Copy)]
pub struct Config {
    pub data: Option<DataConfig>,
    pub idle_r0: u32,
    pub idle_r2: u32,
    pub reo_r0: u32,
    pub reo_r2: u32,
    pub link_entries: usize,
    pub reo_entries: usize,
    pub reo_count: usize,
    pub common: &'static [RingConfig],
    pub reo_setup: Option<ReoConfig>,
}
pub struct Bootstrap<M> {
    memory: M,
    idle: Ring,
    reo: Vec<Ring>,
    common: Vec<Ring>,
    cookies: Option<cookie::Table<M>>,
    config: Config,
    pool: usize,
    started: bool,
    receive_started: bool,
    tx_pool: usize,
    tx_pending: [Option<(u32, Option<u64>)>; 32],
    tx_sequence: u32,
}
struct Plan {
    bytes: usize,
    pool: usize,
    tx_pool: usize,
    idle: Ring,
    reo: Vec<Ring>,
    common: Vec<Ring>,
}
/// Firmware completions overlay HTT status on the same bits as the TQM
/// release reason. Both TQM ACKED (source 0) and HTT OK (source 3) mean ACK.
/// Other producers and every nonzero status are not delivery confirmation.
fn tx_acked(info: u32) -> bool {
    matches!(info & 7, 0 | 3) && (info >> 13) & 15 == 0
}
fn plan(config: Config) -> Result<Plan> {
    if !(4..=32768).contains(&config.link_entries)
        || !config.link_entries.is_power_of_two()
        || !(4..=2048).contains(&config.reo_entries)
        || !config.reo_entries.is_power_of_two()
        || !(1..=8).contains(&config.reo_count)
        || config.common.len() > 32
        || [config.idle_r0, config.idle_r2, config.reo_r0, config.reo_r2]
            .iter()
            .any(|offset| !offset.is_multiple_of(4) || !(0x100..0x1fff000).contains(offset))
    {
        return Err(Error::Registers);
    }
    if let Some(reo) = config.reo_setup {
        for offset in [reo.base, reo.misc, reo.aging] {
            if !offset.is_multiple_of(4) || !(0x100..0x1fff000).contains(&offset) {
                return Err(Error::Registers);
            }
        }
    }
    if let Some(data) = config.data {
        if !data.bank.is_multiple_of(4)
            || !(0x100..0x1fff000).contains(&data.bank)
            || data.return_manager > 15
            || data.pdev > 3
        {
            return Err(Error::Registers);
        }
        for (id, destination) in [
            (data.tx, false),
            (data.tx_completion, true),
            (data.rx_error, true),
        ] {
            if !config
                .common
                .iter()
                .any(|r| r.id == id && r.destination == destination && r.words == 8)
            {
                return Err(Error::Registers);
            }
        }
    }
    let idle = Ring {
        offset: 4096,
        shadow: 0,
        entries: config.link_entries,
        words: 2,
        r0: config.idle_r0,
        r2: config.idle_r2,
        id: 120,
        position: 0,
        status: false,
        idle: true,
    };
    let pool = (idle.offset + config.link_entries * 8 + 127) & !127;
    let mut cursor = pool + config.link_entries * 128;
    let mut reo = Vec::new();
    for index in 0..config.reo_count {
        reo.push(Ring {
            offset: cursor,
            shadow: 4 + index * 4,
            entries: config.reo_entries,
            words: 8,
            r0: config.reo_r0 + index as u32 * 0x78,
            r2: config.reo_r2 + index as u32 * 8,
            id: 1 + index as u32,
            position: 0,
            status: true,
            idle: false,
        });
        cursor += config.reo_entries * 32;
    }
    let mut common = Vec::new();
    for (index, spec) in config.common.iter().enumerate() {
        if !(4..=32768).contains(&spec.entries)
            || !spec.entries.is_power_of_two()
            || !(2..=64).contains(&spec.words)
            || spec.entries * spec.words >= 1 << 20
            || spec.id > 255
            || (spec.command_numbers && (spec.destination || spec.words < 3))
            || [spec.r0, spec.r2]
                .iter()
                .any(|offset| !offset.is_multiple_of(4) || !(0x100..0x1fff000).contains(offset))
        {
            return Err(Error::Registers);
        }
        cursor = (cursor + 127) & !127;
        common.push(Ring {
            offset: cursor,
            shadow: 4 + (config.reo_count + index) * 4,
            entries: spec.entries,
            words: spec.words,
            r0: spec.r0,
            r2: spec.r2,
            id: spec.id,
            position: 0,
            status: spec.destination,
            idle: false,
        });
        cursor += spec.entries * spec.words * 4;
    }
    Ok(Plan {
        bytes: cursor + 32 * 2048,
        tx_pool: cursor,
        pool,
        idle,
        reo,
        common,
    })
}
impl<M: Memory> Bootstrap<M> {
    pub fn required_bytes(config: Config) -> Result<usize> {
        Ok(plan(config)?.bytes)
    }
    /// Memory is zero-initialized DMA storage retained for the device lifetime.
    pub fn new(config: Config, memory: M, capacity: usize) -> Result<Self> {
        let Plan {
            bytes: needed,
            pool,
            tx_pool,
            idle,
            reo,
            common,
        } = plan(config)?;
        if capacity < needed
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
            idle,
            reo,
            common,
            cookies: None,
            config,
            pool,
            started: false,
            receive_started: false,
            tx_pool,
            tx_pending: [None; 32],
            tx_sequence: 0,
        })
    }
    pub fn start(&mut self, io: &mut impl Registers) -> Result<()> {
        if self.started {
            return Err(Error::State);
        }
        // One contiguous descriptor bank; cookie low three bits identify bank
        // zero. Leave one ring slot empty, as for the reference SRNG producer.
        for index in 0..self.idle.entries - 1 {
            let address = self.memory.physical() + (self.pool + index * 128) as u64;
            let cookie = (self.idle.entries - index + 0x4000) << 3;
            self.memory
                .write32(self.idle.offset + index * 8, address as u32);
            self.memory.write32(
                self.idle.offset + index * 8 + 4,
                1 << 8 | (cookie as u32) << 12,
            );
        }
        self.idle.initialize(io, &mut self.memory)?;
        self.idle.position = self.idle.entries - 1;
        self.idle.publish(io)?;
        for (ring, spec) in self.common.iter().zip(self.config.common) {
            if spec.command_numbers {
                // REO commands carry a persistent sequence number after the
                // 64-bit TLV header, even while the source ring is empty.
                for index in 0..ring.entries {
                    self.memory
                        .write32(ring.offset + index * ring.words * 4 + 8, index as u32 + 1);
                }
            }
            ring.initialize(io, &mut self.memory)?;
        }
        if let Some(reo) = self.config.reo_setup {
            let enable = io.read(reo.base)?;
            io.write(reo.base, enable | 0xc)?; // aging list and flush
            let misc = io.read(reo.misc)?;
            // Fragment and BAR frames go to the initialized exception ring 0.
            io.write(reo.misc, misc & !(0xff << 17))?;
            for (index, timeout) in [100000, 100000, 100000, 40000].iter().enumerate() {
                io.write(reo.aging + index as u32 * 4, *timeout)?;
            }
            // Hash routing to SW1..SW4, repeated across all 32 buckets.
            io.write(reo.base + 0xc, 0x43214321)?;
            io.write(reo.base + 0x10, 0x43214321)?;
        }
        self.started = true;
        crate::compact_println!("WiFi: packet engine links={}", self.idle.position);
        crate::compact_println!("WiFi: packet engine common rings={}", self.common.len());
        Ok(())
    }
    /// Firmware's service-ready precedes REO destination setup and WMI INIT.
    pub fn start_receive(&mut self, io: &mut impl Registers) -> Result<()> {
        if !self.started || self.receive_started {
            return Err(Error::State);
        }
        if let Some(cookies) = &mut self.cookies {
            cookies.enable(io)?;
        }
        for ring in &self.reo {
            ring.initialize(io, &mut self.memory)?;
        }
        self.receive_started = true;
        crate::compact_println!("WiFi: packet engine REO rings={}", self.reo.len());
        // Read while the hardware is healthy: post-crash clock-gated reads
        // return all ones and cannot establish whether setup took effect.
        self.log_state(io);
        Ok(())
    }
    pub fn install_cookies(
        &mut self,
        io: &mut impl Registers,
        mut table: cookie::Table<M>,
    ) -> Result<()> {
        if !self.started || self.receive_started || self.cookies.is_some() {
            return Err(Error::State);
        }
        table.install(io)?;
        self.cookies = Some(table);
        Ok(())
    }
    pub fn transmit_idle(&self) -> bool {
        self.tx_pending.iter().all(Option::is_none)
    }
    /// Native-WiFi encapsulation uses the peer's hardware key selection. The
    /// protected bit is clear for EAPOL and set for authorized data traffic.
    pub fn transmit(
        &mut self,
        io: &mut impl Registers,
        frame: &[u8],
        completion: Option<u64>,
        ast: (u16, u16),
    ) -> Result<()> {
        if !self.receive_started || frame.len() < 24 || frame.len() > 2048 {
            return Err(Error::State);
        }
        let data = self.config.data.ok_or(Error::State)?;
        let slot = self
            .tx_pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let ring = self
            .common
            .iter_mut()
            .find(|r| r.id == data.tx)
            .ok_or(Error::Registers)?;
        let next = (ring.position + 1) % ring.entries;
        if next == ring.hardware(&self.memory)? {
            return Err(Error::Full);
        }
        // Address lookup by DA/SA for native-WiFi; peer map supplies AST identity.
        io.write(data.bank, 2 | (1 << 9) | (1 << 11) | (1 << 14))?;
        self.tx_sequence = self.tx_sequence.wrapping_add(1) & 0xfff;
        let cookie = (self.tx_sequence << 5) | slot as u32;
        let at = self.tx_pool + slot * 2048;
        self.memory.copy_in(at, frame);
        let address = self.memory.physical() + at as u64;
        let fields = [
            address as u32,
            ((address >> 32) as u32 & 255) | (u32::from(data.return_manager) << 8) | (cookie << 12),
            0,
            (1 | (u32::from(data.pdev) << 11)) << 16,
            frame.len() as u32,
            1 | (16 << 4),
            u32::from(ast.0) | (u32::from(ast.1 & 15) << 20),
            0,
        ];
        let desc = ring.offset + ring.position * 32;
        for (n, word) in fields.into_iter().enumerate() {
            self.memory.write32(desc + n * 4, word);
        }
        self.tx_pending[slot] = Some((cookie, completion));
        ring.position = next;
        ring.publish(io)
    }
    pub fn packets(
        &mut self,
        io: &mut impl Registers,
        receive: &mut rx::Receive<M>,
    ) -> Result<Packets> {
        let mut packets = Packets {
            frames: Vec::new(),
            transmitted: Vec::new(),
        };
        let Some(data) = self.config.data else {
            return Ok(packets);
        };
        let cookies = self.cookies.as_ref().ok_or(Error::State)?;
        for ring in &mut self.reo {
            let head = ring.hardware(&self.memory)?;
            for _ in 0..64 {
                if ring.position == head {
                    break;
                }
                let at = ring.offset + ring.position * 32;
                let cookie = self.memory.read32(at + 4) >> 12;
                let token = self.memory.read64(at + 20);
                cookies.resolve(cookie, token)?;
                let info = self.memory.read32(at + 28);
                let msdu = self.memory.read32(at + 16);
                let frame = receive.complete(cookie)?;
                // Single-buffer MSDUs only; errors/fragments never reach IP or authentication.
                if matches!(info & 255, 0 | 2) && msdu & 7 == 3 && msdu & (1 << 17) == 0 {
                    packets.frames.push(frame);
                }
                ring.position = (ring.position + 1) % ring.entries;
            }
            ring.publish(io)?;
        }
        // Missing per-TID REO queues are a documented receive path. Keep
        // only DESC_ADDR_ZERO; MIC/PN/decrypt failures are always discarded.
        if let Some(ring) = self.common.iter_mut().find(|r| r.id == data.rx_error) {
            let head = ring.hardware(&self.memory)?;
            for _ in 0..64 {
                if ring.position == head {
                    break;
                }
                let at = ring.offset + ring.position * 32;
                let info = self.memory.read32(at + 8);
                if (info >> 6) & 7 != 0 || !matches!(info & 7, 1 | 2) || info & (1 << 31) != 0 {
                    return Err(Error::Completion);
                }
                let converted = info & (1 << 16) != 0;
                let cookie = if converted {
                    (self.memory.read32(at + 28) >> 8) & 0xfffff
                } else {
                    self.memory.read32(at + 4) >> 12
                };
                if converted {
                    cookies.resolve(cookie, self.memory.read64(at))?;
                }
                let msdu = self.memory.read32(at + 20);
                let frame = receive.complete(cookie)?;
                if info & 7 == 2 && (info >> 24) & 0x7f == 0 && msdu & 7 == 3 {
                    packets.frames.push(frame);
                }
                ring.position = (ring.position + 1) % ring.entries;
            }
            ring.publish(io)?;
        }
        // WBM ring 0 is the completion destination for TCL ring 0 (RBM SW0=5).
        if let Some(ring) = self.common.iter_mut().find(|r| r.id == data.tx_completion) {
            let head = ring.hardware(&self.memory)?;
            for _ in 0..64 {
                if ring.position == head {
                    break;
                }
                let at = ring.offset + ring.position * 32;
                let info = self.memory.read32(at + 8);
                let info3 = self.memory.read32(at + 28);
                let cookie = ((info >> 18) & 0xfff) | (((info3 >> 20) & 255) << 12);
                let token = self.memory.read64(at);
                if info & (1 << 30) == 0 || info & (1 << 31) != 0 {
                    return Err(Error::Completion);
                }
                cookies.resolve(cookie, token)?;
                let slot = (cookie & 31) as usize;
                let Some((expected, completion)) = self.tx_pending[slot] else {
                    return Err(Error::Completion);
                };
                if cookie != expected {
                    return Err(Error::Completion);
                }
                self.tx_pending[slot] = None;
                for word in
                    (self.tx_pool + slot * 2048..self.tx_pool + (slot + 1) * 2048).step_by(4)
                {
                    self.memory.write32(word, 0);
                }
                if let Some(id) = completion {
                    crate::compact_println!(
                        "WiFi: EAPOL completion source={} status={}",
                        info & 7,
                        (info >> 13) & 15
                    );
                    packets.transmitted.push((id, tx_acked(info)));
                }
                ring.position = (ring.position + 1) % ring.entries;
            }
            ring.publish(io)?;
        }
        receive.poll()?;
        Ok(packets)
    }
    pub fn log_state(&self, io: &mut impl Registers) {
        for ring in core::iter::once(&self.idle)
            .chain(&self.common)
            .chain(&self.reo)
        {
            let size = io.read(ring.r0 + 4).unwrap_or(u32::MAX);
            crate::compact_println!(
                "DP: ring={} base={:02x}:{:08x} words={} misc={:08x} hp={} tp={}",
                ring.id,
                size & 255,
                io.read(ring.r0).unwrap_or(u32::MAX),
                size >> 8,
                io.read(ring.r0 + 0x10).unwrap_or(u32::MAX),
                io.read(ring.r2).unwrap_or(u32::MAX),
                io.read(ring.r2 + 4).unwrap_or(u32::MAX)
            );
        }
    }
}

#[cfg(test)]
mod tests;
