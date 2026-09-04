//! Transport-neutral HostFS framing.
//!
//! This module knows nothing about UARTs, sockets, filesystem state, or session
//! policy. Callers provide byte-level send and receive closures.

pub(crate) const FLAG: u8 = 0x7e;
pub(crate) const ESC: u8 = 0x7d;
pub(crate) const ESC_FLAG: u8 = 0x5e;
pub(crate) const ESC_ESC: u8 = 0x5d;
pub(crate) const MAX_BODY: usize = 4096; // type + payload + CRC16
pub(crate) const MAX_FRAME_PAYLOAD: usize = MAX_BODY - 3;

fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub(crate) fn crc16(data: &[u8]) -> u16 {
    crc16_update(0xffff, data)
}

fn crc16_parts(first: &[u8], second: &[u8]) -> u16 {
    crc16_update(crc16_update(0xffff, first), second)
}

/// Encode one complete frame through a raw-byte sink.
pub(crate) fn send_frame<F>(frame_type: u8, payload: &[u8], mut send_raw: F) -> bool
where
    F: FnMut(u8) -> bool,
{
    if payload.len() > MAX_FRAME_PAYLOAD || !send_raw(FLAG) {
        return false;
    }

    let mut send_escaped = |byte: u8| match byte {
        FLAG => send_raw(ESC) && send_raw(ESC_FLAG),
        ESC => send_raw(ESC) && send_raw(ESC_ESC),
        _ => send_raw(byte),
    };

    if !send_escaped(frame_type) {
        return false;
    }
    for &byte in payload {
        if !send_escaped(byte) {
            return false;
        }
    }
    for &byte in &crc16_parts(&[frame_type], payload).to_le_bytes() {
        if !send_escaped(byte) {
            return false;
        }
    }
    send_raw(FLAG)
}

/// Receive one valid frame, discarding malformed frames until the next flag.
/// Every unescaped FLAG abandons the current candidate and starts a boundary.
pub(crate) fn recv_frame<F>(read_raw: &mut F, body: &mut [u8; MAX_BODY]) -> Option<(u8, usize)>
where
    F: FnMut() -> Option<u8>,
{
    let mut in_frame = false;
    let mut escaped = false;
    let mut len = 0usize;
    loop {
        let byte = read_raw()?;
        if byte == FLAG {
            if in_frame && !escaped && (3..=MAX_BODY).contains(&len) {
                let received = u16::from_le_bytes([body[len - 2], body[len - 1]]);
                if crc16(&body[..len - 2]) == received {
                    return Some((body[0], len - 3));
                }
            }
            in_frame = true;
            escaped = false;
            len = 0;
            continue;
        }
        if !in_frame {
            continue;
        }
        let byte = if escaped {
            escaped = false;
            match byte {
                ESC_FLAG => FLAG,
                ESC_ESC => ESC,
                _ => {
                    in_frame = false;
                    len = 0;
                    continue;
                }
            }
        } else if byte == ESC {
            escaped = true;
            continue;
        } else {
            byte
        };
        if len < body.len() {
            body[len] = byte;
            len += 1;
        } else {
            in_frame = false;
            len = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BODY, crc16, recv_frame, send_frame};
    use alloc::{vec, vec::Vec};

    #[test]
    fn round_trip_escapes_control_bytes() {
        let payload = [0x7e, 0x7d, 0x00, 0xff];
        let mut encoded = Vec::new();
        assert!(send_frame(0x42, &payload, |byte| {
            encoded.push(byte);
            true
        }));

        let mut index = 0;
        let mut body = [0u8; MAX_BODY];
        let frame = recv_frame(
            &mut || {
                let byte = encoded.get(index).copied();
                index += 1;
                byte
            },
            &mut body,
        );
        assert_eq!(frame, Some((0x42, payload.len())));
        assert_eq!(&body[1..1 + payload.len()], &payload);
    }

    #[test]
    fn crc_matches_known_empty_body_value() {
        assert_eq!(crc16(&[]), 0xffff);
    }

    #[test]
    fn invalid_crc_is_discarded_before_a_valid_frame() {
        let mut bad = Vec::new();
        assert!(send_frame(0x41, b"bad", |byte| {
            bad.push(byte);
            true
        }));
        let last = bad.len() - 2;
        bad[last] ^= 1;

        let mut good = Vec::new();
        assert!(send_frame(0x42, b"good", |byte| {
            good.push(byte);
            true
        }));
        bad.extend_from_slice(&good);

        let mut index = 0;
        let mut body = [0u8; MAX_BODY];
        let frame = recv_frame(
            &mut || {
                let byte = bad.get(index).copied();
                index += 1;
                byte
            },
            &mut body,
        );
        assert_eq!(frame, Some((0x42, 4)));
    }

    #[test]
    fn malformed_escape_is_resynchronized_at_next_flag() {
        let mut encoded = vec![super::FLAG, 0x41, super::ESC, 0x00, super::FLAG];
        send_frame(0x43, b"ok", |byte| {
            encoded.push(byte);
            true
        });

        let mut index = 0;
        let mut body = [0u8; MAX_BODY];
        let frame = recv_frame(
            &mut || {
                let byte = encoded.get(index).copied();
                index += 1;
                byte
            },
            &mut body,
        );
        assert_eq!(frame, Some((0x43, 2)));
    }

    #[test]
    fn multiple_frames_can_be_read_from_one_stream() {
        let mut encoded = Vec::new();
        for (kind, payload) in [(0x51, b"one".as_slice()), (0x52, b"two".as_slice())] {
            send_frame(kind, payload, |byte| {
                encoded.push(byte);
                true
            });
        }

        let mut index = 0;
        let mut next = || {
            let byte = encoded.get(index).copied();
            index += 1;
            byte
        };
        let mut body = [0u8; MAX_BODY];
        assert_eq!(recv_frame(&mut next, &mut body), Some((0x51, 3)));
        assert_eq!(recv_frame(&mut next, &mut body), Some((0x52, 3)));
    }

    #[test]
    fn oversized_frame_is_discarded_before_a_valid_frame() {
        let mut encoded = vec![super::FLAG];
        encoded.extend(core::iter::repeat(0x11).take(MAX_BODY + 1));
        encoded.push(super::FLAG);
        send_frame(0x61, b"ok", |byte| {
            encoded.push(byte);
            true
        });

        let mut index = 0;
        let mut body = [0u8; MAX_BODY];
        let frame = recv_frame(
            &mut || {
                let byte = encoded.get(index).copied();
                index += 1;
                byte
            },
            &mut body,
        );
        assert_eq!(frame, Some((0x61, 2)));
    }

    #[test]
    fn truncated_frame_is_abandoned_at_next_flag() {
        let mut encoded = vec![super::FLAG, 0x40, 0x01, super::FLAG];
        send_frame(0x62, b"ok", |byte| {
            encoded.push(byte);
            true
        });

        let mut index = 0;
        let mut body = [0u8; MAX_BODY];
        let frame = recv_frame(
            &mut || {
                let byte = encoded.get(index).copied();
                index += 1;
                byte
            },
            &mut body,
        );
        assert_eq!(frame, Some((0x62, 2)));
    }
}
