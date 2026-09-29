//! Filesystem choices from the boot command line. This is kernel policy;
//! `arch-abi::BootConfig` only transports the parsed values across the boot boundary.

use crate::BootConfig;
use arch_abi::{VolumeUuid, cmdline};

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid filesystem UUID"),
    }
}

fn uuid16(value: &[u8]) -> [u8; 16] {
    assert_eq!(value.len(), 36, "ext4 UUID must have 36 characters");
    let mut result = [0; 16];
    let mut digit = 0;
    for (i, &byte) in value.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-', "invalid ext4 UUID");
        } else {
            result[digit / 2] = (result[digit / 2] << 4) | hex(byte);
            digit += 1;
        }
    }
    result
}

fn c_uuid(value: &[u8]) -> VolumeUuid {
    if value.len() == 36 { return VolumeUuid::Ext4(uuid16(value)); }
    assert_eq!(value.len(), 9, "C: UUID must be FAT or ext4 format");
    assert_eq!(value[4], b'-', "invalid FAT UUID");
    let mut result = [0; 4];
    for (position, &byte) in value.iter().enumerate() {
        if position == 4 { continue; }
        let digit = if position < 4 { position } else { position - 1 };
        result[digit / 2] = (result[digit / 2] << 4) | hex(byte);
    }
    VolumeUuid::Fat(result)
}

fn validate_mount_path(path: &[u8]) {
    assert!(path.first() == Some(&b'/') && path.len() < 128, "invalid filesystem path");
    if path == b"/" { return; }
    assert!(path[1..].split(|&c| c == b'/').all(|part|
        !part.is_empty() && part != b"." && part != b".." &&
        part.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))),
        "filesystem path must be canonical");
}

/// Invalid explicit settings fail closed instead of selecting another writable disk.
pub fn apply(config: &mut BootConfig, command: &[u8]) {
    cmdline::for_each_key_value(command, |key, value| {
        if cmdline::key_eq(key, b"retroos.root") {
            config.root_uuid = Some(uuid16(value));
        } else if cmdline::key_eq(key, b"retroos.c-uuid") {
            config.c_uuid = Some(c_uuid(value));
        } else if cmdline::key_eq(key, b"retroos.c-root") {
            validate_mount_path(value);
            config.set_c_root(value);
        } else if cmdline::key_eq(key, b"retroos.runtime") {
            validate_mount_path(value);
            assert!(value.len() > 1, "runtime must be a subdirectory");
            config.set_runtime_path(&value[1..]);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_root_runtime_and_c_volume() {
        let mut config = BootConfig::empty();
        apply(&mut config, b"retroos.root=ea8c19a0-a2e3-4d14-9fd2-6955c176122c retroos.c-root=/home/retroos retroos.runtime=/boot/release/RETROOS retroos.c-uuid=ABCD-1234");
        assert_eq!(config.root_uuid, Some([0xea,0x8c,0x19,0xa0,0xa2,0xe3,0x4d,0x14,0x9f,0xd2,0x69,0x55,0xc1,0x76,0x12,0x2c]));
        assert_eq!(config.c_uuid, Some(VolumeUuid::Fat([0xab, 0xcd, 0x12, 0x34])));
        assert_eq!(config.c_root(), b"home/retroos/");
        assert_eq!(config.runtime(), Some(&b"boot/release/RETROOS/"[..]));
    }

    #[test]
    #[should_panic]
    fn malformed_c_uuid_fails_closed() {
        apply(&mut BootConfig::empty(), b"retroos.c-uuid=ABCD-X234");
    }

    #[test]
    #[should_panic]
    fn invalid_runtime_path_fails_closed() {
        apply(&mut BootConfig::empty(), b"retroos.runtime=/boot/../home");
    }
}
