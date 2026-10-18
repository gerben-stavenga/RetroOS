// SPDX-License-Identifier: BSD-3-Clause-Clear
// Two-level cookie conversion references Linux v6.17 ath12k dp.c/dp.h/hal.h;
// PCI window aliases follow pci.c's address bits 24..19 and low 19 bits.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! Hardware cookies resolve to bounded driver-owned descriptor tokens. Tokens
//! are physical slot identities, never unchecked CPU pointers.
use super::*;
const PAGE: usize = 4096;
const ENTRIES: usize = 512;
const SLOT: usize = 32;

#[derive(Clone, Copy)]
pub struct Config {
    pub reo: u32,
    pub wbm: u32,
    pub wbm_rings: u32,
    pub tx_pages: usize,
    pub rx_pages: usize,
}
impl Config {
    pub fn rx_range(self) -> Result<core::ops::Range<u32>> {
        let (pages, _) = layout(self)?;
        Ok((self.tx_pages * ENTRIES) as u32..(pages * ENTRIES) as u32)
    }
}
pub struct Table<M> {
    memory: M,
    config: Config,
    cmem: u32,
    cmem_mmio: u32,
    pages: usize,
    slots: usize,
    installed: bool,
    enabled: bool,
}
fn layout(config: Config) -> Result<(usize, usize)> {
    let pages = config
        .tx_pages
        .checked_add(config.rx_pages)
        .ok_or(Error::Pointer)?;
    if config.tx_pages == 0
        || config.rx_pages == 0
        || pages > 1024
        || [config.reo, config.wbm]
            .iter()
            .any(|base| !base.is_multiple_of(4) || !(0x100..0x1fff000).contains(base))
        || config.wbm_rings == 0
        || config.wbm_rings & !0xfe != 0
    {
        return Err(Error::Registers);
    }
    Ok((pages, pages * PAGE + pages * ENTRIES * SLOT))
}
impl<M: Memory> Table<M> {
    pub fn required_bytes(config: Config) -> Result<usize> {
        Ok(layout(config)?.1)
    }
    pub fn new(config: Config, memory: M, capacity: usize, cmem: (u64, u64)) -> Result<Self> {
        let (pages, needed) = layout(config)?;
        let low = cmem.0 as u32;
        let mmio = low & 0x01ff_ffff;
        // QMI reports an on-chip region, not host RAM. ath12k programs its
        // low address with internal CMEM high byte 0x10. Reject other spaces
        // and any interval outside this PCI driver's mapped SoC window.
        // Keep the full base for hardware, but use its 25-bit PCI window
        // alias for MMIO (including the 0x10000000 target-bus prefix).
        if capacity < needed
            || !memory.physical().is_multiple_of(PAGE as u64)
            || memory
                .physical()
                .checked_add(needed as u64)
                .is_none_or(|end| end > 1 << 32)
            || !matches!(cmem.0 >> 32, 0 | 0x10)
            || !matches!(low & 0xfe00_0000, 0 | 0x1000_0000)
            || !mmio.is_multiple_of(PAGE as u32)
            || mmio < PAGE as u32
            || mmio
                .checked_add(PAGE as u32)
                .is_none_or(|end| end > 0x2000000)
            || cmem.1 < PAGE as u64
            || cmem.0.checked_add(cmem.1).is_none()
        {
            return Err(Error::Pointer);
        }
        Ok(Self {
            memory,
            config,
            cmem: low,
            cmem_mmio: mmio,
            pages,
            slots: pages * PAGE,
            installed: false,
            enabled: false,
        })
    }
    pub fn install(&mut self, io: &mut impl Registers) -> Result<()> {
        if self.installed {
            return Err(Error::State);
        }
        // Conversion stays disabled while the complete table is populated.
        let reo = io.read(self.config.reo + 4)?;
        io.write(self.config.reo + 4, reo & !(3 << 19))?;
        let wbm = io.read(self.config.wbm + 0x54)?;
        io.write(self.config.wbm + 0x54, wbm & !(1 << 8))?;
        for index in 0..self.pages * ENTRIES {
            self.memory.write64(
                index * 8,
                self.memory.physical() + (self.slots + index * SLOT) as u64,
            );
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        for page in 0..1024 {
            let address = if page < self.pages {
                ((self.memory.physical() + (page * PAGE) as u64) >> 12) as u32
            } else {
                0
            };
            io.write(self.cmem_mmio + page as u32 * 4, address)?;
            if io.read(self.cmem_mmio + page as u32 * 4)? != address {
                return Err(Error::Pointer);
            }
        }
        crate::compact_println!(
            "WiFi: cookie table DMA={:016x} pages={} CMEM verified",
            self.memory.physical(),
            self.pages
        );
        self.installed = true;
        Ok(())
    }
    pub fn enable(&mut self, io: &mut impl Registers) -> Result<()> {
        if !self.installed || self.enabled {
            return Err(Error::State);
        }
        // Cookie bits 0..8 select an 8-byte entry in a 4K secondary page;
        // bits 9..19 select the primary entry in CMEM. DMA remains 32-bit.
        let format = 0x10 | (19 << 8) | (8 << 13) | (1 << 18);
        io.write(self.config.reo, self.cmem)?;
        io.write(self.config.reo + 4, format | (3 << 19))?;
        io.write(self.config.wbm, self.cmem)?;
        io.write(self.config.wbm + 4, format)?;
        let indication = io.read(self.config.wbm + 0x50)?;
        io.write(self.config.wbm + 0x50, indication | 0xb)?;
        let rings = io.read(self.config.wbm + 0x54)?;
        io.write(
            self.config.wbm + 0x54,
            rings | (1 << 8) | self.config.wbm_rings,
        )?;
        self.enabled = true;
        crate::compact_println!(
            "WiFi: cookie conversion CMEM={:08x} TX pages={} RX pages={}",
            self.cmem,
            self.config.tx_pages,
            self.config.rx_pages
        );
        Ok(())
    }
    /// Validate a hardware cookie and converted token before using its slot.
    pub fn resolve(&self, cookie: u32, token: u64) -> Result<usize> {
        let index = cookie as usize;
        if !self.enabled
            || index >= self.pages * ENTRIES
            || token != self.memory.physical() + (self.slots + index * SLOT) as u64
        {
            return Err(Error::Pointer);
        }
        Ok(self.slots + index * SLOT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::drivers::qca_dp::tests::{Io, Ram};
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;
    const CONFIG: Config = Config {
        reo: 0xa38050,
        wbm: 0xa34040,
        wbm_rings: 0x3a,
        tx_pages: 4,
        rx_pages: 1,
    };
    #[test]
    fn tables_resolve_cookies_and_preserve_conversion_order() {
        let bytes = Table::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        let mut table =
            Table::new(CONFIG, memory.clone(), bytes, (0x1000b00000, PAGE as u64)).unwrap();
        let mut io = Io::default();
        assert_eq!(table.enable(&mut io), Err(Error::State));
        table.install(&mut io).unwrap();
        assert_eq!(io.0[&(CONFIG.reo + 4)] & (3 << 19), 0);
        assert_eq!(io.0[&(CONFIG.wbm + 0x54)] & (1 << 8), 0);
        for page in 0..1024 {
            assert_eq!(
                io.0[&(0xb00000 + page * 4)],
                if page < 5 { 0x100 + page } else { 0 }
            );
        }
        table.enable(&mut io).unwrap();
        assert_eq!(io.0[&CONFIG.reo], 0xb00000);
        assert_eq!(io.0[&(CONFIG.reo + 4)], 0x1d1310);
        assert_eq!(io.0[&(CONFIG.wbm + 4)], 0x51310);
        assert_eq!(io.0[&(CONFIG.wbm + 0x50)], 0xb);
        assert_eq!(io.0[&(CONFIG.wbm + 0x54)], 0x13a);
        for index in 0..2560 {
            let token = memory.read64(index * 8);
            assert_eq!(
                table.resolve(index as u32, token).unwrap(),
                5 * PAGE + index * SLOT
            );
            assert!(table.resolve(index as u32, token + 1).is_err());
        }
        assert!(table.resolve(2560, 0).is_err());
        assert!(table.resolve(u32::MAX, 0).is_err());
        assert_eq!(table.install(&mut io), Err(Error::State));
        assert_eq!(table.enable(&mut io), Err(Error::State));
    }
    #[test]
    fn pci_window_alias_does_not_truncate_the_hardware_cmem_base() {
        let bytes = Table::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        let mut table = Table::new(CONFIG, memory, bytes, (0x10b00000, 4096)).unwrap();
        let mut io = Io::default();
        table.install(&mut io).unwrap();
        table.enable(&mut io).unwrap();
        assert_eq!(io.0[&0xb00000], 0x100);
        assert!(!io.0.contains_key(&0x10b00000));
        assert_eq!(io.0[&CONFIG.reo], 0x10b00000);
        assert_eq!(io.0[&CONFIG.wbm], 0x10b00000);
    }
    #[test]
    fn failed_cmem_readback_cannot_enable_conversion() {
        struct Corrupt(Io);
        impl Registers for Corrupt {
            fn read(&mut self, at: u32) -> Result<u32> {
                Ok(self.0.read(at)? ^ if at == 0xb00004 { 1 } else { 0 })
            }
            fn write(&mut self, at: u32, value: u32) -> Result<()> {
                self.0.write(at, value)
            }
            fn now(&mut self) -> u64 {
                0
            }
        }
        let bytes = Table::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        let mut table = Table::new(CONFIG, memory, bytes, (0xb00000, 4096)).unwrap();
        let mut io = Corrupt(Io::default());
        assert_eq!(table.install(&mut io), Err(Error::Pointer));
        assert_eq!(table.enable(&mut io), Err(Error::State));
        assert_eq!(io.0.0[&(CONFIG.reo + 4)] & (3 << 19), 0);
        assert_eq!(io.0.0[&(CONFIG.wbm + 0x54)] & (1 << 8), 0);
    }
    #[test]
    fn invalid_cmem_and_dma_are_rejected_before_mmio() {
        let bytes = Table::<Ram>::required_bytes(CONFIG).unwrap();
        let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
        for region in [
            (0, 4096),
            (0xb00001, 4096),
            (0xb00000, 4095),
            (0x2000000, 4096),
            (0x1100b00000, 4096),
        ] {
            assert!(Table::new(CONFIG, memory.clone(), bytes, region).is_err());
        }
        assert!(Table::new(CONFIG, memory.clone(), bytes - 1, (0xb00000, 4096)).is_err());
        assert!(
            Table::<Ram>::required_bytes(Config {
                tx_pages: usize::MAX,
                ..CONFIG
            })
            .is_err()
        );
        assert!(
            Table::<Ram>::required_bytes(Config {
                rx_pages: 1024,
                ..CONFIG
            })
            .is_err()
        );
        assert!(Table::new(CONFIG, memory, bytes, (0x1fff000, 4096 * 2)).is_ok());
    }
}
