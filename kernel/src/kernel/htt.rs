// SPDX-License-Identifier: BSD-3-Clause-Clear
// HTT wire definitions reference Linux v7.0 ath12k dp_htt.c/dp_htt.h.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
//! Shared Qualcomm host/target transport: negotiation and firmware-owned rings.
use crate::kernel::drivers::mhi::{Error, Result};
use alloc::vec::Vec;

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}
pub fn version_request() -> Vec<u8> {
    words(&[0, 5 | (4 << 8) | (2 << 16)]) // TCL metadata v2, as Linux mission mode
}
#[derive(Default)]
pub struct State {
    pub version: Option<(u8, u8)>,
    pub peer: Option<([u8; 6], u16, u16)>,
}
impl State {
    pub fn receive(&mut self, bytes: &[u8]) -> Result<()> {
        let info = u32::from_le_bytes(bytes.get(..4).ok_or(Error::Packet)?.try_into().unwrap());
        let kind = info as u8;
        crate::compact_println!("WiFi: HTT event={:02x} bytes={}", kind, bytes.len());
        if kind == 0 {
            let version = ((info >> 16) as u8, (info >> 8) as u8);
            crate::compact_println!("WiFi: HTT version={}.{}", version.0, version.1);
            if version.0 != 3 || self.version.is_some_and(|old| old != version) {
                return Err(Error::State);
            }
            self.version = Some(version);
        }
        if matches!(kind, 3 | 0x1e | 0x2b) && (info >> 8) & 255 == 0 {
            if bytes.len() < 16 {
                return Err(Error::Packet);
            }
            let lo = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            let hi = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
            let mut mac = [0; 6];
            mac[..4].copy_from_slice(&bytes[4..8]);
            mac[4..].copy_from_slice(&bytes[8..10]);
            let (index, hash) = if kind == 0x2b {
                (hi as u16, (hi >> 16) as u16)
            } else {
                ((lo >> 16) as u16, hi as u16)
            };
            self.peer = Some((mac, index, hash));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Ring {
    /// HTT ring identifiers, not host HAL ring indices or MMIO addresses.
    pub id: u8,
    pub pdev: u8,
    /// 0: hardware to host; 1: host to hardware; 2: host to firmware.
    pub direction: u8,
    pub entries: usize,
    pub words: usize,
    pub base: u64,
    pub head: u64,
    pub tail: u64,
}
pub fn setup(ring: Ring) -> Result<Vec<u8>> {
    if ring.direction > 2
        || !(4..=8192).contains(&ring.entries)
        || !ring.entries.is_power_of_two()
        || !(2..=64).contains(&ring.words)
        || ring
            .entries
            .checked_mul(ring.words)
            .is_none_or(|n| n > 65535)
        || !ring.base.is_multiple_of(128)
        || !ring.head.is_multiple_of(4)
        || !ring.tail.is_multiple_of(4)
        || ring.head == ring.tail
        || ring.base == 0
        || ring.head == 0
        || ring.tail == 0
    {
        return Err(Error::Pointer);
    }
    Ok(words(&[
        0xb | (u32::from(ring.pdev) << 8)
            | (u32::from(ring.id) << 16)
            | (u32::from(ring.direction) << 24),
        ring.base as u32,
        (ring.base >> 32) as u32,
        (ring.entries * ring.words) as u32
            | ((ring.words as u32) << 16)
            | if ring.direction == 1 { 1 << 25 } else { 0 },
        ring.head as u32,
        (ring.head >> 32) as u32,
        ring.tail as u32,
        (ring.tail >> 32) as u32,
        0,
        0,
        0,
        0,
        0, // polled, no MSI, moderation or low-threshold interrupt
    ]))
}
#[derive(Clone, Copy)]
pub struct RxLayout {
    pub packet: u16,
    pub mpdu: u16,
    pub msdu: u16,
    pub header: u16,
}
pub fn rx_filter(pdev: u8, buffer_bytes: usize, layout: RxLayout) -> Result<Vec<u8>> {
    if pdev == 0
        || buffer_bytes > 65535
        || usize::from(layout.packet) >= buffer_bytes
        || [layout.mpdu, layout.msdu, layout.header]
            .iter()
            .any(|o| o % 4 != 0 || *o >= layout.packet)
    {
        return Err(Error::Packet);
    }
    // Linux's WCN7850 selection: MPDU_START, RX_PACKET, MSDU_END; BAR,
    // multicast, unicast and null-data. Essential management frames use WMI.
    Ok(words(&[
        0xc | (u32::from(pdev) << 8) | (1 << 26) | (1 << 28),
        buffer_bytes as u32,
        0,
        0,
        1 << 24,
        (1 << 18) | (1 << 21) | (1 << 24),
        0xd,
        u32::from(layout.packet) | (u32::from(layout.header) << 16),
        u32::from(layout.mpdu) << 16,
        u32::from(layout.msdu),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]))
}
pub fn disable_monitor(pdev: u8, buffer_bytes: usize) -> Result<Vec<u8>> {
    if pdev == 0 || buffer_bytes == 0 || buffer_bytes > 65535 {
        return Err(Error::Packet);
    }
    let mut fields = [0u32; 17];
    fields[0] = 0xc | (u32::from(pdev) << 8) | (1 << 16);
    fields[1] = buffer_bytes as u32;
    Ok(words(&fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn read(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
    }
    #[test]
    fn version_negotiates_metadata_and_rejects_unsupported_firmware() {
        assert_eq!(version_request(), [0, 0, 0, 0, 5, 4, 2, 0]);
        let mut state = State::default();
        for n in 0..4 {
            assert!(state.receive(&[0; 4][..n]).is_err());
        }
        assert!(state.receive(&0x20000u32.to_le_bytes()).is_err());
        assert!(state.version.is_none());
        state.receive(&0x30700u32.to_le_bytes()).unwrap();
        assert_eq!(state.version, Some((3, 7)));
    }
    #[test]
    fn ring_setup_preserves_both_dma_pointers_and_direction() {
        let ring = Ring {
            id: 5,
            pdev: 0,
            direction: 2,
            entries: 4096,
            words: 2,
            base: 0x100000,
            head: 0x200000,
            tail: 0x200040,
        };
        let packet = setup(ring).unwrap();
        assert_eq!(packet.len(), 52);
        assert_eq!(read(&packet, 0), 0x0205000b);
        assert_eq!(read(&packet, 3), 0x22000);
        assert_eq!(read(&packet, 4), 0x200000);
        assert_eq!(read(&packet, 6), 0x200040);
        let packet = setup(Ring {
            id: 0,
            pdev: 2,
            direction: 1,
            ..ring
        })
        .unwrap();
        assert_eq!(read(&packet, 0), 0x0100020b);
        assert_eq!(read(&packet, 3), 0x2022000);
        assert!(
            setup(Ring {
                tail: ring.head,
                ..ring
            })
            .is_err()
        );
        assert!(setup(Ring { words: 64, ..ring }).is_err());
    }
    #[test]
    fn receive_filter_encodes_profile_offsets_without_guessing_layouts() {
        let layout = RxLayout {
            packet: 400,
            mpdu: 144,
            msdu: 0,
            header: 272,
        };
        let packet = rx_filter(1, 2048, layout).unwrap();
        assert_eq!(packet.len(), 68);
        assert_eq!(read(&packet, 0), 0x1400010c);
        assert_eq!(read(&packet, 6), 0xd);
        assert_eq!(read(&packet, 7), 400 | (272 << 16));
        assert_eq!(read(&packet, 8), 144 << 16);
        assert!(rx_filter(1, 128, layout).is_err());
    }
}
