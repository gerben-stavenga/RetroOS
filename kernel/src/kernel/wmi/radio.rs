// SPDX-License-Identifier: BSD-3-Clause-Clear
// Basic radio setup references Linux v7.0 ath12k mac.c and wmi.c/wmi.h.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
use super::{Error, Result, tlv};
use alloc::vec::Vec;

#[derive(Clone, Copy)]
pub struct RfKill {
    pub pin: u8,
    pub function: u8,
    pub on_high: bool,
}
#[derive(Clone, Copy)]
pub struct Config {
    pub tx_mask: u32,
    pub rx_mask: u32,
    pub rfkill: Option<RfKill>,
}
fn parameter(pdev: u32, id: u32, value: u32) -> Result<Vec<u8>> {
    let mut bytes = 0x4003u32.to_le_bytes().to_vec();
    let body = [pdev, id, value]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<_>>();
    tlv(&mut bytes, 82, &body)?;
    Ok(bytes)
}
pub fn commands(
    pdev: u32,
    config: Config,
    chains: u32,
    rfkill_supported: bool,
) -> Result<Vec<Vec<u8>>> {
    if [config.tx_mask, config.rx_mask]
        .iter()
        .any(|mask| *mask == 0 || *mask > 255 || mask.count_ones() > chains)
    {
        return Err(Error::Packet);
    }
    let mut out = alloc::vec![
        parameter(pdev, 0x22, 1)?, // PMF QoS
        parameter(pdev, 0xa, 1)?,  // dynamic bandwidth
        parameter(pdev, 0x23, 0)?, // ARP access-category override disabled
        parameter(pdev, 0x8f, 1)?, // mesh multicast delivery, matching mac_start
        parameter(pdev, 1, config.tx_mask)?,
        parameter(pdev, 2, config.rx_mask)?,
    ];
    if rfkill_supported && let Some(rf) = config.rfkill {
        if rf.pin == 0 || rf.pin > 63 || rf.function > 15 {
            return Err(Error::Packet);
        }
        let value =
            u32::from(rf.pin) | (u32::from(rf.on_high) << 6) | (u32::from(rf.function) << 7);
        out.push(parameter(pdev, 0x31, value)?);
        out.push(parameter(pdev, 0x2e, 0)?); // radio on; physical GPIO kill still applies
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::super::{tlvs, word};
    use super::*;
    #[test]
    fn radio_parameters_use_profile_masks_and_advertised_rfkill_support() {
        let config = Config {
            tx_mask: 3,
            rx_mask: 3,
            rfkill: Some(RfKill {
                pin: 48,
                function: 0,
                on_high: true,
            }),
        };
        assert_eq!(commands(0, config, 2, false).unwrap().len(), 6);
        let packets = commands(0, config, 2, true).unwrap();
        assert_eq!(packets.len(), 8);
        let fields = tlvs(&packets[6][4..]).unwrap();
        assert_eq!(fields[0].0, 82);
        assert_eq!(word(fields[0].1, 4).unwrap(), 0x31);
        assert_eq!(word(fields[0].1, 8).unwrap(), 112);
        assert!(commands(0, config, 1, true).is_err());
    }
}
