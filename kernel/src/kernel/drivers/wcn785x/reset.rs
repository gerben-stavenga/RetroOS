// SPDX-License-Identifier: BSD-3-Clause-Clear
// Register sequencing adapted from ath12k.
// Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Bounded WCN7850 PCIe and MHI reset, with injected register access.
use super::mhi::{Error, Registers, Result};

pub(super) fn delay<R: Registers>(registers: &mut R, milliseconds: u64) -> Result<()> {
    let end = registers.now().saturating_add(milliseconds * 1_000_000);
    for _ in 0..5_000_000 {
        if registers.now() >= end {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Error::Timeout)
}

pub(super) fn run<R: Registers>(
    registers: &mut R,
    stage: &mut &'static str,
    hot_reset: u32,
) -> Result<()> {
    *stage = "PCIe LTSSM recovery";
    let mut value = registers.read(0x01e0_81b0);
    crate::compact_println!(
        "WiFi: reset LTSSM initial={:08x}",
        value.unwrap_or(u32::MAX)
    );
    for _ in 0..5 {
        match value {
            Ok(0x111) => break,
            // The recovery write must still happen after an all-ones read.
            // Merely waiting and reading again leaves this state unchanged.
            Err(Error::Link) => delay(registers, 5)?,
            Err(error) => return Err(error),
            _ => {}
        }
        registers.write(0x01e0_81b0, 0x111)?;
        value = registers.read(0x01e0_81b0);
    }
    crate::compact_println!("WiFi: reset LTSSM final={:08x}", value.unwrap_or(u32::MAX));
    if value? != 0x111 {
        return Err(Error::Link);
    }
    *stage = "PCIe hot-reset configuration";
    let value = registers.read(hot_reset)? | 0x10;
    registers.write(hot_reset, value)?;
    registers.read(hot_reset)?;
    delay(registers, 5)?;
    *stage = "PCIe interrupt clear";
    registers.write(0x01e0_8228, u32::MAX)?;
    *stage = "WLAON power control";
    let value = registers.read(0x01f8_031c)? & !4;
    registers.write(0x01f8_031c, value)?;
    *stage = "MHI vector clear";
    for offset in [0x360, 0x368, 0x394, 0x39c] {
        registers.write(offset, 0)?;
    }
    *stage = "WLAON warm-boot clear";
    registers.write(0x01f8_0504, 0)?;
    delay(registers, 10)?;
    *stage = "WLAON reset-cause clear";
    registers.read(0x01f8_060c)?;
    *stage = "SoC global reset";
    let value = registers.read(0x3008)?;
    registers.write(0x3008, value | 1)?;
    // Complete each posted PCIe write before timing that edge. The value
    // during reset is not a health check; still deassert reset if it is all ones.
    let _ = registers.read(0x3008);
    delay(registers, 10)?;
    registers.write(0x3008, value & !1)?;
    let _ = registers.read(0x3008);
    delay(registers, 10)?;
    registers.read(0x3008)?;
    *stage = "MHI reset";
    registers.write(0x38, 2)?;
    delay(registers, 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};

    struct Radio {
        values: BTreeMap<u32, u32>,
        writes: Vec<(u32, u32)>,
        unavailable: Option<u32>,
        recoverable: bool,
        reset_reads_invalid: bool,
        time: u64,
    }
    impl Radio {
        fn new() -> Self {
            Self {
                values: [
                    (0x01e0_81b0, 0x111),
                    (0x01e4_0304, 0x80),
                    (0x01f8_031c, 0x17),
                    (0x3008, 0x20),
                ]
                .into(),
                writes: Vec::new(),
                unavailable: None,
                recoverable: false,
                reset_reads_invalid: false,
                time: 0,
            }
        }
    }
    impl Registers for Radio {
        fn read(&mut self, offset: u32) -> Result<u32> {
            // Model the invalid register that failed on the physical WCN7850.
            if offset == 0x01e3_8338 {
                return Err(Error::Link);
            }
            if self.reset_reads_invalid
                && offset == 0x3008
                && self.values.get(&offset).is_some_and(|value| value & 1 != 0)
            {
                return Err(Error::Link);
            }
            if self.unavailable == Some(offset) {
                return Err(Error::Link);
            }
            Ok(*self.values.get(&offset).unwrap_or(&0))
        }
        fn write(&mut self, offset: u32, value: u32) -> Result<()> {
            self.writes.push((offset, value));
            self.values.insert(offset, value);
            if self.recoverable && offset == 0x01e0_81b0 && value == 0x111 {
                self.unavailable = None;
            }
            Ok(())
        }
        fn now(&mut self) -> u64 {
            self.time += 1_000_000;
            self.time
        }
    }

    #[test]
    fn all_ones_ltssm_requires_a_recovery_write() {
        let mut radio = Radio::new();
        radio.unavailable = Some(0x01e0_81b0);
        radio.recoverable = true;
        let mut stage = "";
        assert_eq!(
            run(
                &mut radio,
                &mut stage,
                super::super::hardware::SUPPORTED[0].hot_reset
            ),
            Ok(())
        );
        assert_eq!(radio.writes[0], (0x01e0_81b0, 0x111));
        assert_eq!(radio.values[&0x01e4_0304], 0x90);
        assert_eq!(radio.values[&0x01f8_031c], 0x13);
        assert_eq!(radio.values[&0x3008], 0x20);
        assert_eq!(radio.writes.last(), Some(&(0x38, 2)));
    }

    #[test]
    fn wcn7850_hot_reset_avoids_the_qcn9274_register() {
        let mut radio = Radio::new();
        let mut stage = "";
        assert_eq!(
            run(
                &mut radio,
                &mut stage,
                super::super::hardware::SUPPORTED[0].hot_reset
            ),
            Ok(())
        );
        assert!(radio.writes.contains(&(0x01e4_0304, 0x90)));
        assert!(
            !radio
                .writes
                .iter()
                .any(|(offset, _)| *offset == 0x01e3_8338)
        );
    }

    #[test]
    fn transient_all_ones_during_reset_still_deasserts_it() {
        let mut radio = Radio::new();
        radio.reset_reads_invalid = true;
        let mut stage = "";
        assert_eq!(
            run(
                &mut radio,
                &mut stage,
                super::super::hardware::SUPPORTED[0].hot_reset
            ),
            Ok(())
        );
        assert_eq!(radio.values[&0x3008], 0x20);
        assert_eq!(stage, "MHI reset");
    }

    #[test]
    fn failed_recovery_is_bounded_and_does_not_reset_mhi() {
        let mut radio = Radio::new();
        radio.unavailable = Some(0x01e0_81b0);
        let mut stage = "";
        assert_eq!(
            run(
                &mut radio,
                &mut stage,
                super::super::hardware::SUPPORTED[0].hot_reset
            ),
            Err(Error::Link)
        );
        assert_eq!(radio.writes, [(0x01e0_81b0, 0x111); 5]);
        assert_eq!(stage, "PCIe LTSSM recovery");
    }

    #[test]
    fn later_link_failure_identifies_the_stage_and_stops() {
        let mut radio = Radio::new();
        radio.unavailable = Some(0x01f8_031c);
        let mut stage = "";
        assert_eq!(
            run(
                &mut radio,
                &mut stage,
                super::super::hardware::SUPPORTED[0].hot_reset
            ),
            Err(Error::Link)
        );
        assert_eq!(stage, "WLAON power control");
        assert!(
            !radio
                .writes
                .iter()
                .any(|(offset, _)| *offset == 0x3008 || *offset == 0x38)
        );
    }
}
