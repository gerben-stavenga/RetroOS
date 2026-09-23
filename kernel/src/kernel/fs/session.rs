//! Volatile storage for TEMP and editable copies of boot CONFIG defaults.
//! A sparse RAM disk reuses the FAT backend's complete filesystem semantics.
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::cell::RefCell;
use super::fat::{FatFs, VolumeIo};
use crate::kernel::{block::{Disk, Volume}, vfs::Filesystem};

const SECTORS: u64 = 65536; // 32 MiB capacity, allocated only as written.
struct SessionDisk(RefCell<BTreeMap<u64, Box<[u8; 512]>>>);
impl Disk for SessionDisk {
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        let n = SECTORS.saturating_sub(lba).min(buf.len().div_ceil(512) as u64);
        buf.fill(0);
        let pages = self.0.borrow();
        for (i, chunk) in buf.chunks_mut(512).take(n as usize).enumerate() {
            if let Some(page) = pages.get(&(lba + i as u64)) {
                chunk.copy_from_slice(&page[..chunk.len()]);
            }
        }
        n as u32
    }
    fn write(&self, lba: u64, buf: &[u8]) -> u32 {
        let n = SECTORS.saturating_sub(lba).min(buf.len().div_ceil(512) as u64);
        let mut pages = self.0.borrow_mut();
        for (i, chunk) in buf.chunks(512).take(n as usize).enumerate() {
            let sector = lba + i as u64;
            if chunk.len() == 512 && chunk.iter().all(|b| *b == 0) {
                pages.remove(&sector);
            } else {
                let page = pages.entry(sector).or_insert_with(|| Box::new([0; 512]));
                page[..chunk.len()].copy_from_slice(chunk);
            }
        }
        n as u32
    }
    fn sectors(&self) -> u64 { SECTORS }
    fn name(&self) -> &str { "session-ram" }
}

pub fn new() -> Box<dyn Filesystem> {
    let disk = Box::leak(Box::new(SessionDisk(RefCell::new(BTreeMap::new()))));
    let volume = Volume::whole(disk);
    fatfs::format_volume(&mut VolumeIo::new(volume, true), fatfs::FormatVolumeOptions::new())
        .expect("session RAM format failed");
    Box::new(FatFs::new(VolumeIo::new(volume, true)).expect("session RAM mount failed"))
}

/// Copy boot defaults into writable session memory. Never mutate the boot source.
/// Boot trees contain ordinary files/directories; symlinks are not followed.
pub fn copy_defaults(source: &dyn Filesystem, from: &[u8], target: &dyn Filesystem, to: &[u8]) -> bool {
    fn copy(source: &dyn Filesystem, from: &[u8], target: &dyn Filesystem, to: &[u8], depth: u8) -> bool {
        if !source.dir_exists(from) { return true; }
        if depth == 0 { return false; }
        if !target.dir_exists(to) && target.mkdir(to) != 0 { return false; }
        let mut entries = Vec::new();
        source.readdir(from, 0, &mut entries, usize::MAX);
        for entry in entries {
            let name = &entry.name[..entry.name_len];
            if name == b"." || name == b".." || entry.is_symlink { continue; }
            let src = [from, b"/", name].concat();
            let dst = [to, b"/", name].concat();
            if entry.is_dir {
                if !copy(source, &src, target, &dst, depth - 1) { return false; }
            } else {
                let Some(input) = source.open(&src) else { return false };
                let Some(output) = target.create(&dst) else {
                    source.clunk(input.handle);
                    return false;
                };
                let mut buf = [0; 4096];
                let mut offset = 0;
                while offset < input.size {
                    let n = source.read(input.handle, offset, &mut buf, input.size);
                    if n <= 0 { break; }
                    if target.write(output.handle, offset, &buf[..n as usize]) != n { break; }
                    offset += n as u32;
                }
                target.clunk(output.handle);
                source.clunk(input.handle);
                if offset != input.size { return false; }
            }
        }
        true
    }
    copy(source, from, target, to, 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_disk_preserves_partial_sectors_and_bounds() {
        let disk = SessionDisk(RefCell::new(BTreeMap::new()));
        assert_eq!(disk.write(SECTORS - 1, &[7; 1024]), 1);
        assert_eq!(disk.write(SECTORS - 1, &[9; 3]), 1);
        let mut output = [0; 1024];
        assert_eq!(disk.read(SECTORS - 1, &mut output), 1);
        assert_eq!(&output[..4], &[9, 9, 9, 7]);
        assert!(output[512..].iter().all(|b| *b == 0));
        assert_eq!(disk.write(u64::MAX, &[1; 512]), 0);
        assert_eq!(disk.0.borrow().len(), 1);
        disk.write(SECTORS - 1, &[0; 512]);
        assert!(disk.0.borrow().is_empty());
    }

    #[test]
    fn session_defaults_are_independent_and_temp_starts_empty() {
        let source = new();
        assert_eq!(source.mkdir(b"CONFIG"), 0);
        assert_eq!(source.mkdir(b"CONFIG/NESTED"), 0);
        let node = source.create(b"CONFIG/NESTED/DEFAULT.TXT").unwrap();
        source.write(node.handle, 0, &[42; 8193]);
        source.clunk(node.handle);
        let session = new();
        assert!(copy_defaults(source.as_ref(), b"CONFIG", session.as_ref(), b"CONFIG"));
        let copy = session.open(b"CONFIG/NESTED/DEFAULT.TXT").unwrap();
        let mut output = [0; 8193];
        assert_eq!(session.read(copy.handle, 0, &mut output, copy.size), 8193);
        assert_eq!(output, [42; 8193]);
        assert_eq!(session.write(copy.handle, 0, b"X"), 1);
        session.clunk(copy.handle);
        let original = source.open(b"CONFIG/NESTED/DEFAULT.TXT").unwrap();
        source.read(original.handle, 0, &mut output[..1], original.size);
        assert_eq!(output[0], 42);
        source.clunk(original.handle);
        assert_eq!(session.mkdir(b"TEMP"), 0);
        assert!(session.open(b"TEMP/OLD.TXT").is_none());
    }
}
