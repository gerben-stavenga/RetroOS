//! USTAR TAR filesystem reader

/// USTAR header (512 bytes)
#[repr(C)]
pub struct TarHeader {
    pub filename: [u8; 100],
    pub filemode: [u8; 8],
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    pub filesize: [u8; 12],
    pub mtime: [u8; 12],
    pub checksum: [u8; 8],
    pub typeflag: u8,
    pub link_target: [u8; 100],
    pub magic: [u8; 6],
    pub version: [u8; 2],
    pub username: [u8; 32],
    pub groupname: [u8; 32],
    pub devmajor: [u8; 8],
    pub devminor: [u8; 8],
    pub prefix: [u8; 155],
    pub pad: [u8; 12],
}

const _: () = assert!(core::mem::size_of::<TarHeader>() == 512);

/// Parse octal number from TAR header field
pub fn parse_octal(buf: &[u8]) -> u64 {
    let mut result = 0u64;
    for &c in buf {
        if c < b'0' || c > b'7' {
            break;
        }
        result = result * 8 + (c - b'0') as u64;
    }
    result
}

/// Get length of null-terminated string in buffer
fn strlen(buf: &[u8]) -> usize {
    for (i, &c) in buf.iter().enumerate() {
        if c == 0 {
            return i;
        }
    }
    buf.len()
}

impl TarHeader {
    /// Check if this is end of archive (all zeros)
    pub fn is_end(&self) -> bool {
        self.filename[0] == 0
    }

    /// Get filename as byte slice
    pub fn filename(&self) -> &[u8] {
        &self.filename[..strlen(&self.filename)]
    }

    /// Get file size from header
    pub fn filesize(&self) -> usize {
        parse_octal(&self.filesize) as usize
    }

    /// Number of 512-byte blocks for file data
    pub fn data_blocks(&self) -> u32 {
        ((self.filesize() + 511) / 512) as u32
    }
}
