//! Bounded firmware loading through the ordinary shared VFS.
//! Firmware is installed separately; drivers do not embed host-specific blobs.
use super::vfs;
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidName,
    Missing,
    Size,
    Read,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 192
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !name
            .bytes()
            .any(|b| b == 0 || b == b'\\' || b == b':' || b.is_ascii_control())
}

/// Look in /lib/firmware, then C:\RETROOS\FIRMWARE. Compressed firmware must
/// be unpacked by the installer; a partial read is never passed to a device.
pub fn request(name: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    if !valid_name(name) {
        return Err(Error::InvalidName);
    }
    let paths = [
        [b"lib/firmware/".as_slice(), name.as_bytes()].concat(),
        [super::dos::c_root(), b"RETROOS/FIRMWARE/", name.as_bytes()].concat(),
    ];
    for path in paths {
        let fd = vfs::open_to_handle(&path);
        if fd < 0 {
            continue;
        }
        let result = (|| {
            let size = vfs::file_size_by_handle(fd) as usize;
            if size == 0 || size > maximum {
                return Err(Error::Size);
            }
            let mut bytes = vec![0; size];
            let mut offset = 0;
            while offset < size {
                let count = vfs::read_by_handle(fd, &mut bytes[offset..]);
                if count <= 0 || count as usize > size - offset {
                    return Err(Error::Read);
                }
                offset += count as usize;
            }
            Ok(bytes)
        })();
        vfs::close_vfs_handle(fd);
        return result;
    }
    Err(Error::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firmware_names_cannot_escape_search_roots() {
        assert!(valid_name("ath12k/WCN7850/hw2.0/amss.bin"));
        for name in [
            "",
            "/etc/passwd",
            "../x",
            "a/../x",
            "a//b",
            "a/",
            "C:x",
            "a\\b",
            "a\0b",
        ] {
            assert!(!valid_name(name), "{name:?}");
        }
    }
}
