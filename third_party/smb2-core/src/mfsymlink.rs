//! Minshall–French SMB symlinks, compatible with Linux CIFS `mfsymlinks`.
//! Wire layout documented by Linux fs/smb/client/link.c: fixed-size regular
//! file, decimal byte length, lowercase MD5 of the target, then target bytes.
use alloc::{vec, vec::Vec};
use digest::Digest;
use md5::Md5;

pub const FILE_SIZE: usize = 1067;
pub const MAX_TARGET: usize = 1024;
const TARGET_OFFSET: usize = 43;
const HEX: &[u8; 16] = b"0123456789abcdef";

fn checksum(target: &[u8]) -> [u8; 32] {
    let digest = Md5::digest(target);
    let mut text = [0; 32];
    for (i, byte) in digest.iter().enumerate() {
        text[2 * i] = HEX[(byte >> 4) as usize];
        text[2 * i + 1] = HEX[(byte & 15) as usize];
    }
    text
}

pub fn encode(target: &[u8]) -> Option<Vec<u8>> {
    if target.is_empty() || target.len() > MAX_TARGET || target.contains(&0) {
        return None;
    }
    let mut bytes = vec![b' '; FILE_SIZE];
    bytes[..5].copy_from_slice(b"XSym\n");
    let mut length = target.len();
    for digit in (5..9).rev() {
        bytes[digit] = b'0' + (length % 10) as u8;
        length /= 10;
    }
    bytes[9] = b'\n';
    bytes[10..42].copy_from_slice(&checksum(target));
    bytes[42] = b'\n';
    bytes[TARGET_OFFSET..TARGET_OFFSET + target.len()].copy_from_slice(target);
    if TARGET_OFFSET + target.len() < FILE_SIZE {
        bytes[TARGET_OFFSET + target.len()] = b'\n';
    }
    Some(bytes)
}

/// Malformed candidates remain ordinary files. Validate the entire checksum
/// so an unrelated 1067-byte file never becomes a link merely by its size.
pub fn decode(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() != FILE_SIZE || &bytes[..5] != b"XSym\n"
        || bytes[9] != b'\n' || bytes[42] != b'\n' {
        return None;
    }
    let mut length = 0;
    for &digit in &bytes[5..9] {
        if !digit.is_ascii_digit() { return None; }
        length = length * 10 + usize::from(digit - b'0');
    }
    if length == 0 || length > MAX_TARGET { return None; }
    let target = &bytes[TARGET_OFFSET..TARGET_OFFSET + length];
    if target.contains(&0) || bytes[10..42] != checksum(target) { return None; }
    Some(target)
}
