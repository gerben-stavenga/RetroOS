//! Ext4 filesystem — implements the Filesystem trait via ext4-view crate.
//!
//! ext4-view is path-oriented, while our VFS trait is handle-oriented.
//! Bridge: on open(), read the file into a kernel buffer keyed by handle.
//! On read(), serve from that buffer. This works well for the expected
//! use case (loading DOS games and small files from a Linux partition).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::error::Error;

use ext4_view::{Ext4, Ext4Read};
use crate::kernel::{hdd, vfs::{Filesystem, Vnode, DirEntry}};


/// Reader that implements Ext4Read by reading from an ATA partition.
struct DiskReader {
    partition_start: u32,
}

impl Ext4Read for DiskReader {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        if dst.is_empty() {
            return Ok(());
        }
        let first_sector = (start_byte / 512) as u32;
        let byte_offset = (start_byte % 512) as usize;
        let total_bytes = byte_offset + dst.len();
        let sector_count = total_bytes.div_ceil(512);

        let mut buf = vec![0u8; sector_count * 512];
        hdd::read_sectors(self.partition_start + first_sector, &mut buf);
        dst.copy_from_slice(&buf[byte_offset..byte_offset + dst.len()]);
        Ok(())
    }
}

/// Ext4 filesystem wrapper implementing the VFS Filesystem trait.
pub struct Ext4Fs {
    fs: Ext4,
    /// Cached file contents, keyed by handle (monotonic counter).
    cache: RefCell<BTreeMap<u64, Vec<u8>>>,
    /// Next handle to assign.
    next_handle: RefCell<u64>,
}

impl Ext4Fs {
    /// Mount an ext4 partition starting at the given LBA sector.
    pub fn new(partition_start: u32) -> Result<Self, &'static str> {
        let reader = DiskReader { partition_start };
        let fs = Ext4::load(Box::new(reader)).map_err(|_| "failed to load ext4")?;
        Ok(Self {
            fs,
            cache: RefCell::new(BTreeMap::new()),
            next_handle: RefCell::new(1),
        })
    }
}

/// Build an absolute path from a VFS relative path: prepend '/'.
fn make_absolute<'a>(path: &[u8], buf: &'a mut [u8; 256]) -> Option<&'a str> {
    buf[0] = b'/';
    let len = path.len().min(255);
    buf[1..1 + len].copy_from_slice(&path[..len]);
    let mut total = 1 + len;
    // Remove trailing slash (ext4-view doesn't want it for files)
    if total > 1 && buf[total - 1] == b'/' {
        total -= 1;
    }
    core::str::from_utf8(&buf[..total]).ok()
}


impl Filesystem for Ext4Fs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        // POSIX: case-sensitive only. DOS callers go through DFS's CI cache.
        let mut buf = [0u8; 256];
        let abs = make_absolute(path, &mut buf)?;
        let data = self.fs.read(abs).ok()?;
        let size = data.len() as u32;

        let mut handle_ref = self.next_handle.borrow_mut();
        let handle = *handle_ref;
        *handle_ref = handle.wrapping_add(1);

        self.cache.borrow_mut().insert(handle, data);

        // ext4-view's read API doesn't surface mode bits — default to a
        // generic file mode. Worth replacing with a stat-based lookup if
        // we need accurate POSIX bits from the ext4 partition.
        Some(Vnode { handle, size, mode: 0o644 })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        let cache = self.cache.borrow();
        let data = match cache.get(&handle) {
            Some(d) => d,
            None => return 0,
        };

        let off = offset as usize;
        let file_size = (size as usize).min(data.len());
        if off >= file_size {
            return 0;
        }
        let avail = file_size - off;
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&data[off..off + n]);
        n as i32
    }

    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry> {
        let mut path_buf = [0u8; 256];
        let abs = if dir.is_empty() {
            "/"
        } else {
            make_absolute(dir, &mut path_buf)?
        };

        let read_dir = self.fs.read_dir(abs).ok()?;

        let mut i = 0usize;
        for entry_result in read_dir {
            let entry = entry_result.ok()?;
            let name_path = entry.path();
            let name_bytes: &[u8] = name_path.as_ref();

            // Get basename (after last '/')
            let basename = match name_bytes.iter().rposition(|&b| b == b'/') {
                Some(pos) => &name_bytes[pos + 1..],
                None => name_bytes,
            };

            if basename == b"." || basename == b".." || basename.is_empty() {
                continue;
            }

            if i == index {
                let is_dir = entry.file_type().ok().map_or(false, |ft| ft.is_dir());
                let size = if is_dir {
                    0
                } else {
                    entry.metadata()
                        .map(|m| m.len() as u32)
                        .unwrap_or(0)
                };
                let name_len = basename.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len,
                    size,
                    is_dir,
                    mode: if is_dir { 0o755 } else { 0o644 },
                };
                de.name[..name_len].copy_from_slice(&basename[..name_len]);
                return Some(de);
            }
            i += 1;
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        if path.is_empty() {
            return true;
        }
        let mut buf = [0u8; 256];
        let abs = match make_absolute(path, &mut buf) {
            Some(s) => s,
            None => return false,
        };
        self.fs.exists(abs).unwrap_or(false)
    }
}
