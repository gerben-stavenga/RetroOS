// SPDX-License-Identifier: BSD-3-Clause-Clear
// Wire layouts reference Linux v7.0 ath12k wmi.h/wmi.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! WMI station creation and passive discovery, independent of PCI hardware.
use super::{Error, Result, regulatory::Report, required, tlv, word};
use crate::kernel::wifi::scan::Network;
use alloc::vec::Vec;

pub const REQUEST_ID: u32 = 1;
pub const MAX_SCAN_MS: u32 = 20_000;

#[derive(Clone, Copy)]
pub struct RadioConfig {
    pub pdev: u32,
    pub regulatory_phy: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    pub frequency: u32,
    pub max_power: u8,
    pub antenna_gain: u8,
    pub radar: bool,
}
/// Initially discover 20-MHz 2.4/5-GHz channels only. No country override,
/// active probes, 6-GHz power-class assumption or transmit permission.
pub fn channels(report: &Report) -> Vec<Channel> {
    let mut candidates: Vec<u32> = (1..=13).map(|n| 2407 + n * 5).collect();
    candidates.extend((36..=64).step_by(4).map(|n| 5000 + n * 5));
    candidates.extend((100..=144).step_by(4).map(|n| 5000 + n * 5));
    candidates.extend((149..=177).step_by(4).map(|n| 5000 + n * 5));
    let mut channels = Vec::new();
    for frequency in candidates {
        let rules = if frequency < 3000 {
            &report.rules[..report.counts[0]]
        } else {
            &report.rules[report.counts[0]..report.counts[0] + report.counts[1]]
        };
        let covering: Vec<_> = rules
            .iter()
            .filter(|r| {
                (r[0] & 0xffff) <= frequency - 10
                    && (r[0] >> 16) >= frequency + 10
                    && (r[1] & 0xffff) >= 20
            })
            .collect();
        if covering.is_empty()
            || covering
                .iter()
                .any(|r| r[2] & (1 | (1 << 6) | (1 << 11)) != 0)
        {
            continue;
        }
        channels.push(Channel {
            frequency,
            max_power: covering.iter().map(|r| (r[1] >> 16) as u8).min().unwrap(),
            antenna_gain: covering.iter().map(|r| (r[1] >> 24) as u8).min().unwrap(),
            radar: covering.iter().any(|r| r[2] & (1 << 3) != 0),
        });
    }
    channels
}
fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn command(id: u32, tag: u16, fields: &[u32]) -> Result<Vec<u8>> {
    let mut bytes = id.to_le_bytes().to_vec();
    tlv(&mut bytes, tag, &words(fields))?;
    Ok(bytes)
}
pub fn create_station(
    config: RadioConfig,
    vdev: u32,
    mac: [u8; 6],
    chains: u32,
) -> Result<Vec<u8>> {
    if mac == [0; 6] || mac[0] & 1 != 0 || !(1..=8).contains(&chains) {
        return Err(Error::Packet);
    }
    let mut address = [0; 8];
    address[..6].copy_from_slice(&mac);
    let mut bytes = command(
        0x5001,
        86,
        &[
            vdev,
            2,
            0,
            word(&address, 0)?,
            word(&address, 4)?,
            2,
            config.pdev,
            1,
            0,
            0,
            255,
        ],
    )?;
    let mut streams = Vec::new();
    for band in 0..2 {
        tlv(&mut streams, 411, &words(&[band, chains, chains]))?;
    }
    tlv(&mut bytes, 18, &streams)?;
    Ok(bytes)
}
pub fn channel_list(config: RadioConfig, channels: &[Channel]) -> Result<Vec<u8>> {
    if channels.is_empty() || channels.len() > 64 {
        return Err(Error::Packet);
    }
    let mut bytes = command(0x3003, 79, &[channels.len() as u32, 0, config.pdev])?;
    let mut array = Vec::new();
    for chan in channels {
        let mode = u32::from(chan.frequency < 3000); // MODE_11G / MODE_11A
        let info = mode | (1 << 7) | if chan.radar { 1 << 10 } else { 0 };
        // Regulatory rules use dBm/dBi; channel-list fields use half units.
        let power = u32::from(chan.max_power.saturating_mul(2));
        tlv(
            &mut array,
            80,
            &words(&[
                chan.frequency,
                chan.frequency,
                0,
                info,
                (power << 8) | (power << 16),
                u32::from(chan.antenna_gain.saturating_mul(2)) | (power << 8),
            ]),
        )?;
    }
    tlv(&mut bytes, 18, &array)?;
    Ok(bytes)
}
/// Match the station's basic NSS/wake configuration before discovery. Keep
/// these separate from CREATE so a retry never creates a duplicate vdev.
pub fn station_awake(vdev: u32, chains: u32) -> Result<Vec<Vec<u8>>> {
    if !(1..=8).contains(&chains) {
        return Err(Error::Packet);
    }
    Ok(alloc::vec![
        command(0x5008, 95, &[vdev, 34, chains])?, // WMI_VDEV_PARAM_NSS
        command(0x9002, 109, &[vdev, 0, 0])?,      // RX wake policy: wake
        command(0x9002, 109, &[vdev, 1, 1])?,      // TX threshold: always
        command(0x9002, 109, &[vdev, 2, 0])?,      // no maximum PS-poll count
        command(0x9001, 108, &[vdev, 0])?,         // power saving disabled
    ])
}
pub fn start(vdev: u32, scan_id: u32, channels: &[Channel]) -> Result<Vec<u8>> {
    if !(0xa000..=0xafff).contains(&scan_id) || channels.is_empty() || channels.len() > 64 {
        return Err(Error::Packet);
    }
    let mut fields = [0u32; 39];
    fields[..21].copy_from_slice(&[
        scan_id,
        REQUEST_ID,
        vdev,
        1,
        1 | 2 | 8 | 16 | 32 | 64,
        50,
        150,
        50,
        500,
        0,
        0,
        0,
        MAX_SCAN_MS,
        5,
        1 | 0x10000,
        0,
        channels.len() as u32,
        1,
        0,
        0,
        0,
    ]);
    fields[36] = 70;
    fields[37] = 70;
    let mut bytes = command(0x3001, 77, &fields)?;
    tlv(
        &mut bytes,
        16,
        &words(&channels.iter().map(|c| c.frequency).collect::<Vec<_>>()),
    )?;
    tlv(&mut bytes, 19, &[])?; // SSIDs: none, passive only
    tlv(&mut bytes, 19, &[255, 255, 255, 255, 255, 255, 0, 0])?;
    tlv(&mut bytes, 17, &[])?;
    Ok(bytes)
}
pub fn stop(config: RadioConfig, vdev: u32, scan_id: u32) -> Result<Vec<u8>> {
    command(0x3002, 78, &[REQUEST_ID, scan_id, 0, vdev, config.pdev])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanEvent {
    pub kind: u32,
    pub reason: u32,
    pub frequency: u32,
    pub request: u32,
    pub scan: u32,
    pub vdev: u32,
}
pub struct Session {
    pub id: u32,
    pub vdev: u32,
    pub deadline: u64,
}
impl Session {
    /// Firmware events may arrive late after cancellation. All three identity
    /// fields must match before they can change the current scan's state.
    pub fn phase(&self, event: ScanEvent) -> Option<crate::kernel::wifi::scan::Phase> {
        use crate::kernel::wifi::scan::Phase;
        if event.scan != self.id || event.request != REQUEST_ID || event.vdev != self.vdev {
            return None;
        }
        if event.kind & (2 | 16 | 32 | 64) != 0 {
            Some(if event.kind & 2 != 0 && event.reason == 0 {
                Phase::Complete
            } else {
                Phase::Failed(if event.reason != 0 { event.reason } else { 4 })
            })
        } else if event.kind & 1 != 0 {
            Some(Phase::Running)
        } else {
            None
        }
    }
}
impl ScanEvent {
    pub(super) fn parse(values: &[(u16, &[u8])]) -> Result<Self> {
        let bytes = required(values, 36)?;
        if bytes.len() < 28 {
            return Err(Error::Packet);
        }
        Ok(Self {
            kind: word(bytes, 0)?,
            reason: word(bytes, 4)?,
            frequency: word(bytes, 8)?,
            request: word(bytes, 12)?,
            scan: word(bytes, 16)?,
            vdev: word(bytes, 20)?,
        })
    }
}
pub(super) fn management(values: &[(u16, &[u8])]) -> Result<Option<Network>> {
    let Some((frame, frequency, signal)) = management_frame(values)? else {
        return Ok(None);
    };
    if !matches!(frame.first(), Some(0x80 | 0x50)) {
        return Ok(None); // other management subtypes are not discovery results
    }
    Network::from_management(frame, frequency, signal)
        .map(Some)
        .ok_or(Error::Packet)
}

pub(super) fn management_frame<'a>(
    values: &[(u16, &'a [u8])],
) -> Result<Option<(&'a [u8], u32, i32)>> {
    let header = required(values, 44)?;
    // ath12k_wmi_mgmt_rx_params has four rssi_ctl words: 17 words
    // total, with chan_freq at word 16. Accept additive trailing fields.
    if header.len() < 68 {
        return Err(Error::Packet);
    }
    if word(header, 20)? & 0x39 != 0 {
        return Ok(None);
    } // CRC, decrypt, MIC, missing key
    let len = word(header, 16)? as usize;
    if len > 4096 {
        return Err(Error::Packet);
    }
    let frame = required(values, 17)?.get(..len).ok_or(Error::Packet)?;
    let mut frequency = word(header, 64)?;
    if frequency == 0 {
        let channel = word(header, 0)?;
        frequency = match channel {
            1..=13 => 2407 + channel * 5,
            14 => 2484,
            36..=177 => 5000 + channel * 5,
            _ => return Ok(None),
        };
    }
    // Linux uses the firmware SNR plus the default -95 dBm noise floor.
    let signal = i32::try_from(word(header, 4)?)
        .unwrap_or(0)
        .saturating_sub(95);
    Ok(Some((frame, frequency, signal)))
}

pub enum Event {
    Scan(ScanEvent),
    Network(Network),
    Station(super::station::Event),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    const CONFIG: RadioConfig = RadioConfig {
        pdev: 0,
        regulatory_phy: 0,
    };
    fn channel() -> Channel {
        Channel {
            frequency: 2412,
            max_power: 20,
            antenna_gain: 0,
            radar: false,
        }
    }
    #[test]
    fn scan_wire_layout_is_passive_and_arrays_match_counts() {
        let bytes = start(0, 0xa001, &[channel()]).unwrap();
        let values = super::super::tlvs(&bytes[4..]).unwrap();
        assert_eq!(
            values
                .iter()
                .map(|(t, b)| (*t, b.len()))
                .collect::<Vec<_>>(),
            [(77, 156), (16, 4), (19, 0), (19, 8), (17, 0)]
        );
        assert_eq!(word(values[0].1, 14 * 4).unwrap(), 0x10001);
        assert_eq!(word(values[0].1, 20 * 4).unwrap(), 0);
        assert_eq!(word(values[0].1, 16 * 4).unwrap(), 1);
        let create = create_station(CONFIG, 0, [2, 3, 4, 5, 6, 7], 2).unwrap();
        let v = super::super::tlvs(&create[4..]).unwrap();
        assert_eq!(v[0].1.len(), 44);
        assert_eq!(word(v[0].1, 6 * 4).unwrap(), 0);
        assert_eq!(super::super::tlvs(v[1].1).unwrap().len(), 2);
        let list = channel_list(CONFIG, &[channel()]).unwrap();
        let v = super::super::tlvs(&list[4..]).unwrap();
        let c = super::super::tlvs(v[1].1).unwrap();
        assert_eq!(word(c[0].1, 12).unwrap(), 0x81);
        assert_eq!(word(c[0].1, 16).unwrap(), (40 << 8) | (40 << 16));
        let awake = station_awake(3, 2).unwrap();
        assert_eq!(awake.len(), 5);
        assert_eq!(
            awake[0],
            [0x5008u32, (95 << 16) | 12, 3, 34, 2]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            awake[4],
            [0x9001u32, (108 << 16) | 8, 3, 0]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        );
        assert!(start(0, 1, &[channel()]).is_err());
        assert!(channel_list(CONFIG, &[]).is_err());
    }
    #[test]
    fn management_frames_are_bounded_and_rx_errors_are_discarded() {
        let mut hdr = vec![0u8; 68];
        hdr[16..20].copy_from_slice(&38u32.to_le_bytes());
        hdr[4..8].copy_from_slice(&40u32.to_le_bytes());
        hdr[64..68].copy_from_slice(&2412u32.to_le_bytes());
        let mut frame = vec![0u8; 38];
        frame[0] = 0x80;
        frame[16] = 2;
        let n = management(&[(44, &hdr), (17, &frame)]).unwrap().unwrap();
        assert_eq!(n.signal_dbm, -55);
        assert!(n.ssid.is_empty());
        assert!(management(&[(44, &hdr), (17, &frame[..37])]).is_err());
        hdr[20] = 1;
        assert!(management(&[(44, &hdr), (17, &frame)]).unwrap().is_none());
    }
    #[test]
    fn linux_management_header_uses_four_antenna_words_and_allows_extensions() {
        // Field order from Linux v7.0's ath12k_wmi_mgmt_rx_params, without
        // its outer TLV. Deliberately distinguish TSF/pdev/frequency fields.
        let fields = [
            1,
            40,
            6000,
            1,
            38,
            0, // channel, SNR, rate, mode, length, status
            41,
            42,
            43,
            44, // rssi_ctl[ATH_MAX_ANTENNA = 4]
            0,
            (-55i32) as u32,
            100,
            200,
            300,
            0,
            2412,
        ];
        let mut header = words(&fields);
        assert_eq!(header.len(), 68);
        let mut frame = vec![0u8; 38];
        frame[0] = 0x80;
        frame[16] = 2;
        let n = management(&[(44, &header), (17, &frame)]).unwrap().unwrap();
        assert_eq!(n.frequency, 2412);
        assert_eq!(n.signal_dbm, -55);
        header.extend_from_slice(&words(&[0xdeadbeef, 0xbad0cafe]));
        assert_eq!(
            management(&[(44, &header), (17, &frame)])
                .unwrap()
                .unwrap()
                .frequency,
            2412
        );
        assert!(management(&[(44, &header[..67]), (17, &frame)]).is_err());
    }
    #[test]
    fn scan_events_require_the_current_request_vdev_and_scan_id() {
        use crate::kernel::wifi::scan::Phase;
        let session = Session {
            id: 0xa001,
            vdev: 3,
            deadline: 123,
        };
        let event = ScanEvent {
            kind: 1,
            reason: 0,
            frequency: 0,
            request: REQUEST_ID,
            scan: session.id,
            vdev: 3,
        };
        assert_eq!(session.phase(event), Some(Phase::Running));
        assert_eq!(
            session.phase(ScanEvent {
                scan: 0xa000,
                ..event
            }),
            None
        );
        assert_eq!(
            session.phase(ScanEvent {
                request: 99,
                ..event
            }),
            None
        );
        assert_eq!(session.phase(ScanEvent { vdev: 0, ..event }), None);
        assert_eq!(session.phase(ScanEvent { kind: 8, ..event }), None);
        assert_eq!(
            session.phase(ScanEvent { kind: 2, ..event }),
            Some(Phase::Complete)
        );
        assert_eq!(
            session.phase(ScanEvent {
                kind: 2,
                reason: 3,
                ..event
            }),
            Some(Phase::Failed(3))
        );
        assert_eq!(
            session.phase(ScanEvent { kind: 64, ..event }),
            Some(Phase::Failed(4))
        );
    }
    #[test]
    fn passive_channels_require_full_regulatory_coverage_and_keep_restrictions() {
        let mut report = Report {
            phy: 0,
            country: *b"00",
            fixed: Vec::new(),
            counts: [0; 11],
            rules: vec![
                [2402 | (2472 << 16), 40 | (20 << 16), 2, 0],
                [5170 | (5250 << 16), 80 | (17 << 16), 2 | (1 << 3), 0],
            ],
            raw_rules: Vec::new(),
            extensions: Vec::new(),
        };
        report.counts[0] = 1;
        report.counts[1] = 1;
        let plan = channels(&report);
        assert_eq!(plan.iter().filter(|c| c.frequency < 3000).count(), 11);
        assert!(
            plan.iter()
                .all(|c| c.frequency <= 2462 || (5180..=5240).contains(&c.frequency))
        );
        assert!(
            plan.iter()
                .filter(|c| c.frequency >= 3000)
                .all(|c| c.radar && c.max_power == 17)
        );
        report.rules[0][2] |= 1;
        report.rules[1][2] |= 1 << 11;
        assert!(channels(&report).is_empty());
    }
}
