//! Ext4 filesystem — implements the Filesystem trait via ext4-view crate.
//!
//! ext4-view is path-oriented, while our VFS trait is handle-oriented.
//! Bridge: on open() keep a seekable `File` cursor keyed by handle; on read()
//! seek to the requested offset and pull only that range off disk. Memory is
//! bounded regardless of file size — unlike slurping whole files into a
//! per-handle buffer, which exhausted the kernel heap on large CD assets
//! (Indy IV's multi-MB MONSTER.SOU OOM'd `demand_page_kernel`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use core::cell::RefCell;
use core::error::Error;

use ext4_view::{Ext4, Ext4Read, File};
use crate::kernel::vfs::{Filesystem, Vnode, DirEntry};


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
        crate::kernel::block::read_sectors(self.partition_start + first_sector, &mut buf);
        dst.copy_from_slice(&buf[byte_offset..byte_offset + dst.len()]);
        Ok(())
    }
}

/// Ext4 filesystem wrapper implementing the VFS Filesystem trait.
pub struct Ext4Fs {
    fs: Ext4,
    /// Per-handle seekable file cursors (handle = monotonic counter). A `File`
    /// is just an inode + extent iterator + offset (a few hundred bytes), NOT
    /// the file's contents — so this stays small no matter how large the files
    /// are. Lifetime matches the VFS path-cache: handles are not dropped on
    /// close (the path-cache shares a handle across opens and is never
    /// evicted), exactly as the old cached byte buffers lived.
    open_files: RefCell<BTreeMap<u64, File>>,
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
            open_files: RefCell::new(BTreeMap::new()),
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
        let file = self.fs.open(abs).ok()?;
        // Pull size + real permission bits before File is moved into the handle
        // map. The execute bits matter: the old hardcoded 0o644 made every ext4
        // binary look non-executable, so busybox refused to run anything
        // ("ls: Permission denied"). open() follows symlinks, so this is the
        // resolved target's mode.
        let (size, mode) = {
            let md = file.metadata();
            (md.len() as u32, md.mode())
        };

        let mut handle_ref = self.next_handle.borrow_mut();
        let handle = *handle_ref;
        *handle_ref = handle.wrapping_add(1);

        self.open_files.borrow_mut().insert(handle, file);

        Some(Vnode { handle, size, mode })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let mut files = self.open_files.borrow_mut();
        let file = match files.get_mut(&handle) {
            Some(f) => f,
            None => return 0,
        };
        // Only seek when not already positioned there. Sequential reads (the
        // common case) leave `position` at `offset` after the previous read;
        // `seek_to` re-walks the extent iterator from the start, so seeking
        // every chunk would turn a sequential read into O(n²).
        if file.position() != offset as u64 {
            if file.seek_to(offset as u64).is_err() {
                return 0;
            }
        }
        // `read_bytes` yields block-sized partials and Ok(0) at EOF; loop to
        // fill the caller's buffer (naturally bounded by end-of-file).
        let mut total = 0usize;
        while total < buf.len() {
            match file.read_bytes(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        total as i32
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
                let ft = entry.file_type().ok();
                // Resolve symlinks so a symlinked directory lists AS a directory
                // (DN descends into it, the DFS walk traverses it) and a
                // symlinked file reports its target's size/mode. Real entries
                // keep the cheap inode-local metadata(); only symlinks pay the
                // extra path resolution (Ext4::metadata follows FollowSymlinks::All).
                // This is what lets `ln -s …/apps/games /home/retroos/GAMES`
                // surface under C:\GAMES instead of looking like a file.
                let md = if ft.map_or(false, |t| t.is_symlink()) {
                    core::str::from_utf8(name_bytes).ok().and_then(|p| self.fs.metadata(p).ok())
                } else {
                    entry.metadata().ok()
                };
                let is_dir = match &md {
                    Some(m) => m.is_dir(),
                    None => ft.map_or(false, |t| t.is_dir()),
                };
                let size = if is_dir { 0 } else { md.as_ref().map(|m| m.len() as u32).unwrap_or(0) };
                let mode = md.as_ref().map(|m| m.mode()).unwrap_or(if is_dir { 0o755 } else { 0o644 });
                let name_len = basename.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len,
                    size,
                    is_dir,
                    mode,
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
        // A directory exists iff read_dir succeeds — it fails for regular files
        // (so stat() no longer reports e.g. /bin/ls as a directory, which made
        // busybox reject it). read_dir follows symlinks (FollowSymlinks::All),
        // so a symlink TO a directory correctly counts as one.
        self.fs.read_dir(abs).is_ok()
    }
}
