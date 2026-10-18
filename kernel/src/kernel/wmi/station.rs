// SPDX-License-Identifier: BSD-3-Clause-Clear
// Wire layouts reference Linux v7.0 ath12k wmi.c/wmi.h.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! Single-link station commands. Authentication policy lives in wifi::link.
use super::{Error, Result, scan::Channel, tlv};
use crate::kernel::wifi::{auth::Key, link::legacy_rates, scan::Network};
use alloc::{vec, vec::Vec};
use zeroize::Zeroizing;
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn command(id: u32, tag: u16, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = id.to_le_bytes().to_vec();
    tlv(&mut out, tag, body)?;
    Ok(out)
}
pub fn peer(vdev: u32, mac: [u8; 6], create: bool) -> Result<Vec<u8>> {
    let mut body = vec![0; if create { 16 } else { 12 }];
    put(&mut body, 0, vdev);
    body[4..10].copy_from_slice(&mac);
    let mut out = command(
        if create { 0x6001 } else { 0x6002 },
        if create { 97 } else { 98 },
        &body,
    )?;
    if create {
        let mut ml = Vec::new();
        tlv(&mut ml, 981, &[0; 4])?;
        tlv(&mut out, 18, &ml)?;
    }
    Ok(out)
}
pub fn start(vdev: u32, network: &Network, channel: &Channel) -> Result<Vec<u8>> {
    if network.ssid.len() > 32 || network.frequency != channel.frequency {
        return Err(Error::Packet);
    }
    let mut body = [0; 112];
    put(&mut body, 0, vdev);
    // Linux leaves requestor_id zero; firmware need not echo host sequence IDs.
    put(&mut body, 8, u32::from(network.beacon_interval));
    let mut dtim = 1;
    let mut ies = network.ies.as_slice();
    while ies.len() >= 2 {
        let n = usize::from(ies[1]);
        let val = ies.get(2..2 + n).ok_or(Error::Packet)?;
        if ies[0] == 5 && val.len() >= 2 {
            dtim = u32::from(val[1]).max(1);
        }
        ies = &ies[2 + n..];
    }
    put(&mut body, 12, dtim);
    put(&mut body, 16, 8); // LDPC RX, legacy 20MHz association
    put(&mut body, 20, network.ssid.len() as u32);
    body[24..24 + network.ssid.len()].copy_from_slice(&network.ssid);
    put(&mut body, 72, 1);
    put(&mut body, 76, 1);
    put(&mut body, 96, 1); // non-MBSSID
    let mut out = command(0x5003, 88, &body)?;
    let power = u32::from(channel.max_power.saturating_mul(2));
    let fields = [
        channel.frequency,
        channel.frequency,
        0,
        u32::from(channel.frequency < 3000) | if channel.radar { 1 << 10 } else { 0 },
        (power << 8) | (power << 16),
        u32::from(channel.antenna_gain.saturating_mul(2)) | (power << 8),
    ];
    let value: Vec<_> = fields.into_iter().flat_map(u32::to_le_bytes).collect();
    tlv(&mut out, 80, &value)?;
    tlv(&mut out, 18, &[])?;
    Ok(out)
}
pub fn associate(vdev: u32, network: &Network, aid: u16) -> Result<Vec<u8>> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Packet);
    }
    let mut rates = legacy_rates(network).map_err(|_| Error::Packet)?;
    let count = rates.len();
    for rate in &mut rates {
        *rate &= 0x7f;
    }
    rates.resize((count + 3) & !3, 0);
    let mut body = [0; 244];
    body[..6].copy_from_slice(&network.bssid);
    put(&mut body, 8, vdev);
    put(&mut body, 12, 1);
    put(&mut body, 16, u32::from(aid));
    put(&mut body, 20, 4); // NEED_PTK_4_WAY; AUTH remains clear until handshake completes
    put(&mut body, 24, u32::from(network.capability));
    put(&mut body, 28, 10);
    put(&mut body, 48, 1);
    put(&mut body, 56, u32::from(network.frequency < 3000));
    put(&mut body, 68, count as u32);
    let mut out = command(0x6005, 101, &body)?;
    tlv(&mut out, 17, &rates)?;
    tlv(&mut out, 17, &[])?;
    tlv(&mut out, 102, &[0; 16])?;
    for _ in 0..4 {
        tlv(&mut out, 18, &[])?;
    }
    Ok(out)
}
pub fn up(vdev: u32, mac: [u8; 6], aid: u16) -> Result<Vec<u8>> {
    let mut body = [0; 32];
    put(&mut body, 0, vdev);
    put(&mut body, 4, u32::from(aid));
    body[8..14].copy_from_slice(&mac);
    command(0x5005, 92, &body)
}
pub fn authorize(vdev: u32, mac: [u8; 6], authorized: bool) -> Result<Vec<u8>> {
    let mut body = [0; 20];
    put(&mut body, 0, vdev);
    body[4..10].copy_from_slice(&mac);
    put(&mut body, 12, 3);
    put(&mut body, 16, u32::from(authorized));
    command(0x6004, 100, &body)
}
pub fn stop(vdev: u32) -> Result<Vec<u8>> {
    command(0x5006, 93, &vdev.to_le_bytes())
}
pub fn down(vdev: u32) -> Result<Vec<u8>> {
    command(0x5007, 94, &vdev.to_le_bytes())
}
pub fn key(vdev: u32, key: &Key) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new([0; 100]);
    put(&mut body[..], 0, vdev);
    body[4..10].copy_from_slice(&key.peer);
    put(&mut body[..], 12, u32::from(key.id.index));
    put(&mut body[..], 16, u32::from(!key.id.pairwise));
    put(&mut body[..], 20, 4);
    body[24..30].copy_from_slice(&key.receive_counter);
    put(&mut body[..], 80, 16);
    let mut out = Zeroizing::new(command(0x5009, 96, &body[..])?);
    tlv(&mut out, 17, &key.bytes[..])?;
    Ok(out)
}
pub fn management(vdev: u32, id: u32, address: u64, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 24 || frame.len() > 2048 || address == 0 || address >= 1 << 40 {
        return Err(Error::Packet);
    }
    let n = frame.len().min(64);
    let mut prefix = frame[..n].to_vec();
    prefix.resize((n + 3) & !3, 0);
    let fields = [
        vdev,
        id,
        0,
        address as u32,
        (address >> 32) as u32,
        frame.len() as u32,
        n as u32,
        0,
    ];
    let body: Vec<_> = fields.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut out = command(0x7008, 422, &body)?;
    tlv(&mut out, 17, &prefix)?;
    Ok(out)
}

pub enum Event {
    Management(Vec<u8>),
    Started {
        request: u32,
        status: u32,
    },
    Associated {
        peer: [u8; 6],
    },
    Key {
        peer: [u8; 6],
        index: u32,
        flags: u32,
        status: u32,
    },
    ManagementSent {
        id: u32,
        status: u32,
    },
    Stopped,
    PeerDeleted {
        peer: [u8; 6],
    },
}
pub(super) fn event(id: u32, values: &[(u16, &[u8])]) -> Result<Option<Event>> {
    use super::{required, word};
    let mac = |b: &[u8], n: usize| -> Result<[u8; 6]> {
        Ok(b.get(n..n + 6).ok_or(Error::Packet)?.try_into().unwrap())
    };
    Ok(Some(match id {
        0x5001 => {
            let b = required(values, 40)?;
            if word(b, 0)? != 0 {
                return Ok(None);
            }
            Event::Started {
                request: word(b, 4)?,
                status: word(b, 12)?,
            }
        }
        0x5002 => {
            let b = required(values, 41)?;
            if word(b, 0)? != 0 {
                return Ok(None);
            }
            Event::Stopped
        }
        0x5003 => {
            let b = required(values, 42)?;
            if word(b, 0)? != 0 {
                return Ok(None);
            }
            Event::Key {
                peer: mac(b, 4)?,
                index: word(b, 12)?,
                flags: word(b, 16)?,
                status: word(b, 20)?,
            }
        }
        0x6006 => {
            let b = required(values, 434)?;
            if word(b, 0)? != 0 {
                return Ok(None);
            }
            Event::Associated { peer: mac(b, 4)? }
        }
        0x6007 => {
            let b = required(values, 451)?;
            if word(b, 0)? != 0 {
                return Ok(None);
            }
            Event::PeerDeleted { peer: mac(b, 4)? }
        }
        0x7006 => {
            let b = required(values, 423)?;
            Event::ManagementSent {
                id: word(b, 0)?,
                status: word(b, 4)?,
            }
        }
        _ => return Ok(None),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::wifi::auth::{Cipher, KeyId};
    #[test]
    fn station_start_matches_linux_zero_requestor_and_accepts_its_reply() {
        let network = Network {
            bssid: [2, 0, 0, 0, 0, 2],
            ssid: b"test".to_vec(),
            frequency: 5200,
            signal_dbm: -34,
            privacy: true,
            rsn: Vec::new(),
            wpa: Vec::new(),
            ies: vec![5, 4, 0, 2, 0, 0],
            capability: 0x411,
            beacon_interval: 100,
        };
        let channel = Channel {
            frequency: 5200,
            max_power: 17,
            antenna_gain: 0,
            radar: false,
        };
        let command = start(0, &network, &channel).unwrap();
        let values = super::super::tlvs(&command[4..]).unwrap();
        assert_eq!(
            values
                .iter()
                .map(|(tag, value)| (*tag, value.len()))
                .collect::<Vec<_>>(),
            [(88, 112), (80, 24), (18, 0)]
        );
        assert_eq!(super::super::word(values[0].1, 4).unwrap(), 0);
        assert_eq!(super::super::word(values[0].1, 12).unwrap(), 2);
        let mut reply = [0; 40];
        put(&mut reply, 16, 3);
        assert!(matches!(
            event(0x5001, &[(40, &reply)]).unwrap(),
            Some(Event::Started {
                request: 0,
                status: 0
            })
        ));
        put(&mut reply, 12, 4);
        assert!(matches!(
            event(0x5001, &[(40, &reply)]).unwrap(),
            Some(Event::Started {
                request: 0,
                status: 4
            })
        ));
        put(&mut reply, 0, 1);
        assert!(event(0x5001, &[(40, &reply)]).unwrap().is_none());
    }
    #[test]
    fn key_and_management_wire_boundaries_match_firmware_structs() {
        let key = Key {
            id: KeyId {
                pairwise: false,
                index: 2,
            },
            peer: [2, 3, 4, 5, 6, 7],
            cipher: Cipher::Ccmp128,
            receive_counter: [1, 2, 3, 4, 5, 6],
            bytes: Zeroizing::new([0x55; 16]),
        };
        let cmd = super::key(0, &key).unwrap();
        let tlvs = super::super::tlvs(&cmd[4..]).unwrap();
        assert_eq!(tlvs[0].0, 96);
        assert_eq!(tlvs[0].1.len(), 100);
        assert_eq!(&tlvs[0].1[24..32], &[1, 2, 3, 4, 5, 6, 0, 0]);
        assert_eq!(super::super::word(tlvs[0].1, 20).unwrap(), 4);
        assert_eq!(tlvs[1], (17, &[0x55; 16][..]));
        let mut frame = vec![0; 101];
        frame[0] = 0xb0;
        let cmd = management(0, 9, 0x123400, &frame).unwrap();
        let tlvs = super::super::tlvs(&cmd[4..]).unwrap();
        assert_eq!(tlvs[0].1.len(), 32);
        assert_eq!(tlvs[1].1.len(), 64);
        assert_eq!(super::super::word(tlvs[0].1, 20).unwrap(), 101);
        assert_eq!(super::super::word(tlvs[0].1, 24).unwrap(), 64);
    }
}
