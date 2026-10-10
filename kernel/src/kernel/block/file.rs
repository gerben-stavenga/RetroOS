//! A disk backed by an existing file, with positional I/O and no image copy.
//! Calls occur under the VFS serialization lock at runtime; startup is single
//! threaded. Going directly to the resolved backing filesystem avoids taking
//! the VFS lock recursively while accessing a filesystem inside the image.

use super::{Disk, FlushError};
use crate::kernel::vfs::BackingFile;
use alloc::string::String;

pub struct FileDisk {
    file: BackingFile,
    name: String,
    writable: bool,
}
impl FileDisk {
    pub fn new(file: BackingFile, name: String, writable: bool) -> Result<Self, &'static str> {
        if file.size() == 0 || !file.size().is_multiple_of(512) {
            file.close();
            return Err("disk image must contain whole 512-byte sectors");
        }
        if writable && !file.writable() {
            file.close();
            return Err("image backing file is not writable");
        }
        Ok(Self {
            file,
            name,
            writable,
        })
    }
    fn offset(&self, lba: u64) -> Option<u32> {
        u32::try_from(lba.checked_mul(512)?).ok()
    }
}
impl Disk for FileDisk {
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        let Some(offset) = self.offset(lba) else {
            return 0;
        };
        let count = buf
            .len()
            .min(self.file.size().saturating_sub(offset) as usize);
        let n = self.file.read_at(offset, &mut buf[..count]);
        if n < 0 {
            0
        } else {
            if n as usize == count {
                count.div_ceil(512) as u32
            } else {
                n as u32 / 512
            }
        }
    }
    fn write(&self, lba: u64, buf: &[u8]) -> u32 {
        if !self.writable {
            return 0;
        }
        let Some(offset) = self.offset(lba) else {
            return 0;
        };
        if u64::from(offset) + buf.len() as u64 > u64::from(self.file.size()) {
            return 0;
        }
        let n = self.file.write_at(offset, buf);
        if n < 0 {
            0
        } else {
            if n as usize == buf.len() {
                buf.len().div_ceil(512) as u32
            } else {
                n as u32 / 512
            }
        }
    }
    fn flush(&self) -> Result<(), FlushError> {
        if !self.writable || self.file.flush() == 0 {
            Ok(())
        } else {
            Err(FlushError)
        }
    }
    fn sectors(&self) -> u64 {
        u64::from(self.file.size()) / 512
    }
    fn name(&self) -> &str {
        &self.name
    }
}
impl Drop for FileDisk {
    fn drop(&mut self) {
        self.file.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};
    use alloc::{boxed::Box, vec::Vec};
    use core::cell::RefCell;
    struct Bytes(RefCell<Vec<u8>>);
    impl Filesystem for Bytes {
        fn open(&self, _: &[u8]) -> Option<Vnode> {
            Some(Vnode {
                handle: 1,
                size: self.0.borrow().len() as u32,
                mode: 0o666,
            })
        }
        fn read(&self, _: u64, offset: u32, buf: &mut [u8], _: u32) -> i32 {
            let bytes = self.0.borrow();
            let n = buf.len().min(bytes.len().saturating_sub(offset as usize));
            buf[..n].copy_from_slice(&bytes[offset as usize..offset as usize + n]);
            n as i32
        }
        fn write(&self, _: u64, offset: u32, data: &[u8]) -> i32 {
            self.0.borrow_mut()[offset as usize..offset as usize + data.len()]
                .copy_from_slice(data);
            data.len() as i32
        }
        fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> {
            None
        }
        fn dir_exists(&self, _: &[u8]) -> bool {
            false
        }
    }
    #[test]
    fn positional_io_is_bounded_and_ram_writes_do_not_touch_the_file() {
        let fs = Box::leak(Box::new(Bytes(RefCell::new(alloc::vec![7; 1024]))));
        let backing = BackingFile::test_file(fs, fs.open(b"image").unwrap(), true);
        let disk = Box::leak(Box::new(
            FileDisk::new(backing, "image".into(), true).unwrap(),
        ));
        assert_eq!(disk.write(1, &[8; 512]), 1);
        assert_eq!(fs.0.borrow()[512], 8);
        assert_eq!(disk.write(2, &[9; 512]), 0);
        let overlay = crate::kernel::block::overlay::RamOverlay::wrap(disk);
        assert_eq!(overlay.write(1, &[9; 512]), 1);
        let mut out = [0; 512];
        assert_eq!(overlay.read(1, &mut out), 1);
        assert_eq!(out[0], 9);
        assert_eq!(fs.0.borrow()[512], 8);
        let ro = BackingFile::test_file(fs, fs.open(b"image").unwrap(), false);
        assert!(FileDisk::new(ro, "denied".into(), true).is_err());
        let ro = BackingFile::test_file(fs, fs.open(b"image").unwrap(), false);
        let ro = FileDisk::new(ro, "readonly".into(), false).unwrap();
        assert_eq!(ro.write(0, &[0; 512]), 0);
    }
}
