// SPDX-License-Identifier: BSD-3-Clause-Clear
// SRNG register/descriptor setup references Linux v6.8 ath12k hal.c/ce.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Shared Qualcomm SRNG descriptor-ring registers and DMA pointer handling.
use super::mhi::{Error, Memory, Registers, Result};
use core::sync::atomic::{Ordering, fence};

/// Firmware maps these ordered target doorbells onto consecutive BAR aliases.
/// Reads still use the original target register; only producer writes redirect.
#[derive(Clone, Copy)]
pub(crate) struct ShadowMap {
    base: u32,
    targets: &'static [u32],
}
impl ShadowMap {
    pub(crate) fn new(base: u32, targets: &'static [u32], aperture: usize) -> Result<Self> {
        if targets.is_empty()
            || targets.len() > 60
            || !base.is_multiple_of(4)
            || (base as usize)
                .checked_add(targets.len() * 4)
                .is_none_or(|end| end > aperture)
            || targets.iter().enumerate().any(|(index, target)| {
                !target.is_multiple_of(4)
                    || !(0x100..=0x01ff_fffc).contains(target)
                    || targets[..index].contains(target)
            })
        {
            return Err(Error::Registers);
        }
        Ok(Self { base, targets })
    }
    pub(crate) fn write_alias(&self, target: u32) -> Option<usize> {
        self.targets
            .iter()
            .position(|value| *value == target)
            .map(|index| self.base as usize + index * 4)
    }
}

#[cfg(test)]
mod shadow_tests {
    use super::*;
    #[test]
    fn aliases_follow_firmware_order_and_leave_other_registers_direct() {
        let map = ShadowMap::new(0x8fc, &[0xa3b04c, 0xa46000, 0x1b80400], 0x80000).unwrap();
        assert_eq!(map.write_alias(0xa3b04c), Some(0x8fc));
        assert_eq!(map.write_alias(0x1b80400), Some(0x904));
        assert_eq!(map.write_alias(0xa3b048), None); // hardware-owned head pointer
        assert_eq!(map.write_alias(0xa38000), None); // ordinary configuration
    }
    #[test]
    fn invalid_maps_cannot_escape_the_bar_aperture_or_alias_twice() {
        for (base, targets, aperture) in [
            (0x8fc, &[][..], 0x80000),
            (0x8fd, &[0xa3b04c][..], 0x80000),
            (0x8fc, &[0xa3b04d][..], 0x80000),
            (0x8fc, &[0xa3b04c, 0xa3b04c][..], 0x80000),
            (0x8fc, &[0xa3b04c][..], 0x8ff),
            (0x8fc, &[0x2000000][..], 0x80000),
        ] {
            assert!(ShadowMap::new(base, targets, aperture).is_err());
        }
    }
}

pub(crate) struct Ring {
    pub(crate) offset: usize,
    pub(crate) shadow: usize,
    pub(crate) entries: usize,
    pub(crate) words: usize,
    pub(crate) r0: u32,
    pub(crate) r2: u32,
    pub(crate) id: u32,
    pub(crate) position: usize,
    pub(crate) status: bool,
    pub(crate) idle: bool,
}
impl Ring {
    pub(crate) fn hardware(&self, memory: &impl Memory) -> Result<usize> {
        let value = memory.read32(self.shadow) as usize;
        fence(Ordering::Acquire);
        if value >= self.entries * self.words || !value.is_multiple_of(self.words) {
            return Err(Error::Pointer);
        }
        Ok(value / self.words)
    }
    pub(crate) fn initialize(
        &self,
        io: &mut impl Registers,
        memory: &mut impl Memory,
    ) -> Result<()> {
        let base = memory.physical() + self.offset as u64;
        let shadow = memory.physical() + self.shadow as u64;
        io.write(self.r0 + 0x10, 0)?;
        io.write(self.r0, base as u32)?;
        io.write(
            self.r0 + 4,
            ((base >> 32) as u32 & 255) | ((self.entries * self.words) as u32) << 8,
        )?;
        io.write(
            self.r0 + 8,
            self.words as u32 | if self.status { self.id << 8 } else { 0 },
        )?;
        let pointer = if self.status { 0x14 } else { 0x1c };
        if !self.idle {
            io.write(self.r0 + pointer, shadow as u32)?;
            io.write(self.r0 + pointer + 4, (shadow >> 32) as u32)?;
        }
        // Poll DMA pointer writebacks; no CE MSI or interrupt moderation needed.
        io.write(self.r0 + 0x4c, 0)?;
        io.write(self.r0 + 0x48, 0)?;
        io.write(self.r0 + 0x50, 0)?;
        if self.status {
            io.write(self.r0 + 0x24, 0)?;
        } else {
            io.write(self.r0 + 0x30, 0)?;
            io.write(self.r0 + 0x34, 0)?;
        }
        memory.write32(self.shadow, 0);
        io.write(self.r2, 0)?;
        io.write(self.r2 + 4, 0)?;
        fence(Ordering::Release);
        io.write(
            self.r0 + 0x10,
            if self.status {
                0x40
            } else if self.idle {
                0x43
            } else {
                0x42
            },
        )?;
        io.read(self.r0 + 0x10)?;
        Ok(())
    }
    pub(crate) fn publish(&self, io: &mut impl Registers) -> Result<()> {
        fence(Ordering::Release);
        io.write(
            self.r2 + if self.status { 4 } else { 0 },
            (self.position * self.words) as u32,
        )
    }
}
