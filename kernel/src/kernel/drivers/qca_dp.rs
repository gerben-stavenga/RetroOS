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
pub struct Config {
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
}
struct Plan {
    bytes: usize,
    pool: usize,
    idle: Ring,
    reo: Vec<Ring>,
    common: Vec<Ring>,
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
        bytes: cursor,
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
