// SPDX-License-Identifier: BSD-3-Clause-Clear
// RX descriptor offsets reference Linux v7.0 ath12k wifi7/hal_rx_desc.h.
//! WCN7850 receive metadata and native-WiFi packet boundaries.
use alloc::vec::Vec;
pub(super) struct Packet {
    pub ethernet: Vec<u8>,
    pub protected: bool,
    pub key: u8,
    pub pn: u64,
}
fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
pub(super) fn decode(bytes: &[u8], station: [u8; 6], peer: [u8; 6]) -> Option<Packet> {
    // msdu_end tag + 128-byte descriptor, MPDU tag at 144, payload at 400.
    let errors = word(bytes, 128)?;
    let done = word(bytes, 132)?;
    if done & (1 << 31) == 0 || errors & 0xf803_9000 != 0 {
        return None;
    }
    let flags = word(bytes, 196)?; // MPDU info4 = 144 + tag8 + offset44
    if flags & 0x1d != 0x1d
        || flags & 0x7c00 != 0
        || flags & (1 << 16) == 0
        || flags & (1 << 17) != 0
    {
        return None;
    }
    let key = word(bytes, 200)? as u8;
    let mpdu_info = word(bytes, 204)?;
    // Association currently advertises no WMM/aggregation support.
    if mpdu_info & ((1 << 25) | (1 << 26) | (1 << 30)) != 0 {
        return None;
    }
    let info5 = u16::from_le_bytes(bytes.get(50..52)?.try_into().ok()?);
    if info5 & 0x3000 != 0x3000 {
        return None;
    }
    let length = (word(bytes, 80)? & 0x3fff) as usize;
    let pad = ((info5 >> 10) & 3) as usize;
    if (word(bytes, 84)? >> 8) & 3 != 1 {
        return None;
    }
    let frame = bytes.get(400 + pad..400 + pad + length)?;
    if frame.len() < 32
        || frame[0] != 8
        || frame[1] & 0x87 != 2
        || frame[10..16] != peer
        || frame[22] & 15 != 0
    {
        return None;
    }
    if frame[4..10] != station && frame[4] & 1 == 0 {
        return None;
    }
    if frame[24..30] != [0xaa, 0xaa, 3, 0, 0, 0] {
        return None;
    }
    let protected = flags & (1 << 18) != 0;
    if protected && (flags & (1 << 9) == 0 || (done >> 10) & 7 != 0 || key > 3) {
        return None;
    }
    let pn = u64::from(word(bytes, 164)?) | (u64::from(word(bytes, 168)? & 0xffff) << 32);
    let mut ethernet = frame[4..10].to_vec();
    ethernet.extend_from_slice(&frame[16..22]);
    ethernet.extend_from_slice(&frame[30..]);
    Some(Packet {
        ethernet,
        protected,
        key,
        pn,
    })
}
pub(super) fn encapsulate(
    ethernet: &[u8],
    station: [u8; 6],
    peer: [u8; 6],
    sequence: u16,
    protected: bool,
) -> Option<Vec<u8>> {
    if ethernet.len() < 14 || ethernet.len() > 1514 || ethernet[6..12] != station {
        return None;
    }
    let mut frame = alloc::vec![0;24];
    frame[0] = 8;
    frame[1] = 1 | if protected { 0x40 } else { 0 };
    frame[4..10].copy_from_slice(&peer);
    frame[10..16].copy_from_slice(&station);
    frame[16..22].copy_from_slice(&ethernet[..6]);
    frame[22..24].copy_from_slice(&((sequence & 0xfff) << 4).to_le_bytes());
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&ethernet[12..]);
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn received() -> Vec<u8> {
        let station = [2, 0, 0, 0, 0, 1];
        let peer = [2, 0, 0, 0, 0, 2];
        let mut bytes = alloc::vec![0;2048];
        put(&mut bytes, 132, 1 << 31);
        put(&mut bytes, 196, 0x1d | (1 << 16) | (1 << 18) | (1 << 9));
        put(&mut bytes, 84, 1 << 8);
        put(&mut bytes, 164, 7);
        bytes[50..52].copy_from_slice(&0x3000u16.to_le_bytes());
        let mut eth = station.to_vec();
        eth.extend_from_slice(&peer);
        eth.extend_from_slice(&[0x88, 0x8e, 1, 2, 3]);
        let mut frame = encapsulate(&eth, peer, station, 1, false).unwrap();
        frame[1] = 2;
        frame[10..16].copy_from_slice(&peer);
        frame[16..22].copy_from_slice(&peer);
        put(&mut bytes, 80, frame.len() as u32);
        bytes[400..400 + frame.len()].copy_from_slice(&frame);
        bytes
    }
    #[test]
    fn rx_metadata_bounds_and_errors_protect_authentication_and_ip() {
        let mut bytes = received();
        let sta = [2, 0, 0, 0, 0, 1];
        let ap = [2, 0, 0, 0, 0, 2];
        let frame = decode(&bytes, sta, ap).unwrap();
        assert_eq!(frame.ethernet[12..], [0x88, 0x8e, 1, 2, 3]);
        assert!(frame.protected);
        assert_eq!(frame.pn, 7);
        assert!(decode(&bytes[..420], sta, ap).is_none());
        put(&mut bytes, 128, 1 << 29);
        assert!(decode(&bytes, sta, ap).is_none());
        put(&mut bytes, 128, 0);
        put(&mut bytes, 132, 0);
        assert!(decode(&bytes, sta, ap).is_none());
        put(&mut bytes, 132, (1 << 31) | (1 << 10));
        assert!(decode(&bytes, sta, ap).is_none());
    }
    #[test]
    fn tx_header_uses_ap_as_receiver_and_controls_protection() {
        let sta = [2, 0, 0, 0, 0, 1];
        let ap = [2, 0, 0, 0, 0, 2];
        let mut eth = alloc::vec![0xff;6];
        eth.extend_from_slice(&sta);
        eth.extend_from_slice(&[8, 0, 1, 2]);
        let frame = encapsulate(&eth, sta, ap, 0x123, true).unwrap();
        assert_eq!(frame[1], 0x41);
        assert_eq!(frame[4..10], ap);
        assert_eq!(frame[16..22], [0xff; 6]);
        assert_eq!(frame[22..24], [0x30, 0x12]);
        assert_eq!(encapsulate(&eth, sta, ap, 0, false).unwrap()[1], 1);
    }
}
