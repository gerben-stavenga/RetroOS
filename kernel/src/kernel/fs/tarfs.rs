//! TAR filesystem — implements the Filesystem trait for TAR archives, either
//! on disk (the boot partition) or in RAM (the kernel's embedded bootfs).

use crate::kernel::vfs::{Filesystem, Vnode, DirEntry};
use lib::tar::TarHeader;
use alloc::vec::Vec;

const BLOCK_SIZE: usize = 512;

/// Where the TAR bytes live: RAM only. A disk-backed variant existed but was
/// never constructed — startup's placeholder was always replaced by the
/// embedded bootfs before mount, so the only thing it could ever have done was
/// read sector 0 with an unbuilt index.
enum Source {
    /// TAR bytes in RAM (`kernel::bootfs()`, linked into the kernel image).
    Ram(&'static [u8]),
}

/// In-memory index entry. The TAR is a singly-linked list on disk, so
/// `open()` would otherwise have to PIO-read the chain block-by-block on
/// every call — `D21 3D open` becoming a linear ATA scan of the whole
/// archive. We pay the scan cost once at mount time and answer opens
/// from RAM after that.
struct IndexEntry {
    name: [u8; 100],
    name_len: u16,
    data_block: u32,
    size: u32,
    is_symlink: bool,
    link: [u8; 100],
    link_len: u16,
    /// POSIX mode bits from USTAR header (filemode field, parsed octal).
    mode: u16,
    /// Unix epoch seconds from the USTAR mtime field; 0 = unknown.
    mtime: u32,
}

pub struct TarFs {
    source: Source,
    /// Entries sorted by name (POSIX-strict). DOS callers go through DFS,
    /// which keeps a separate per-dir 8.3-alias cache and translates DOS
    /// names to canonical VFS names before reaching here.
    index: Vec<IndexEntry>,
}

impl TarFs {
    /// A TAR held in RAM (the embedded bootfs).
    pub const fn new_ram(bytes: &'static [u8]) -> Self {
        Self { source: Source::Ram(bytes), index: Vec::new() }
    }

    /// The one source-specific primitive: fetch TAR block `block` into `buf`.
    /// RAM reads past the end yield zeros — TAR end-of-archive, so a
    /// truncated blob still terminates the index walk.
    fn read_block(&self, block: u32, buf: &mut [u8; BLOCK_SIZE]) {
        match self.source {
            Source::Ram(bytes) => {
                let off = block as usize * BLOCK_SIZE;
                buf.fill(0);
                if off < bytes.len() {
                    let n = (bytes.len() - off).min(BLOCK_SIZE);
                    buf[..n].copy_from_slice(&bytes[off..off + n]);
                }
            }
        }
    }

    /// Walk the on-disk TAR header chain once and cache entries in RAM.
    /// Entries sorted by name allow O(log N) `open()` lookups.
    pub fn build_index(&mut self) {
        let mut block: u32 = 0;
        while let Some(entry) = self.read_header(block) {
            self.index.push(IndexEntry {
                name: entry.name,
                name_len: entry.name_len as u16,
                data_block: entry.data_block,
                size: entry.size,
                is_symlink: entry.is_symlink,
                link: entry.link,
                link_len: entry.link_len as u16,
                mode: entry.mode,
                mtime: entry.mtime,
            });
            block = entry.next_block;
        }
        self.index.sort_by(|a, b| {
            a.name[..a.name_len as usize].cmp(&b.name[..b.name_len as usize])
        });
        let Source::Ram(bytes) = self.source;
        crate::println!(
            "TAR: indexed {} entries from embedded bootfs ({} KB)",
            self.index.len(), bytes.len() / 1024);
    }

    /// O(log N) case-sensitive lookup.
    fn find_cs(&self, path: &[u8]) -> Option<&IndexEntry> {
        self.index.binary_search_by(|e| {
            e.name[..e.name_len as usize].cmp(path)
        }).ok().map(|i| &self.index[i])
    }

    fn read_header(&self, block: u32) -> Option<TarEntry> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(block, &mut buf);
        let header = unsafe { &*(buf.as_ptr() as *const TarHeader) };
        if header.is_end() { return None; }
        let size = header.filesize() as u32;
        let data_blocks = header.data_blocks();
        let name_bytes = header.filename();
        let mut name = [0u8; 100];
        let name_len = name_bytes.len().min(100);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);
        let mut link = [0u8; 100];
        let mut link_len = 0;
        if header.is_symlink() {
            let lt = header.link_target();
            link_len = lt.len().min(100);
            link[..link_len].copy_from_slice(&lt[..link_len]);
        }
        Some(TarEntry {
            name, name_len, size,
            data_block: block + 1,
            next_block: block + 1 + data_blocks,
            is_symlink: header.is_symlink(),
            link, link_len,
            mode: header.filemode(),
            mtime: header.filemtime(),
        })
    }
}

struct TarEntry {
    name: [u8; 100],
    name_len: usize,
    size: u32,
    data_block: u32,
    next_block: u32,
    is_symlink: bool,
    /// Symlink target (relative or absolute). Only valid when `is_symlink`.
    link: [u8; 100],
    link_len: usize,
    mode: u16,
    mtime: u32,
}

/// Check if a TAR entry name is in the given directory.
/// Returns the basename (part after the directory prefix) if it matches.
fn entry_in_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if entry_name.len() <= dir.len() {
        return None;
    }
    if !dir.is_empty() && &entry_name[..dir.len()] != dir { return None; }
    let rest = &entry_name[dir.len()..];
    if rest.contains(&b'/') {
        return None;
    }
    Some(rest)
}

impl Filesystem for TarFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let mut current: [u8; 164] = [0u8; 164];
        let mut current_len = path.len().min(current.len());
        current[..current_len].copy_from_slice(&path[..current_len]);

        for _ in 0..8 {
            let entry = self.find_cs(&current[..current_len])?;
            if !entry.is_symlink {
                return Some(Vnode {
                    handle: entry.data_block as u64,
                    size: entry.size,
                    mode: entry.mode,
                });
            }
            let dir_end = current[..current_len]
                .iter()
                .rposition(|&b| b == b'/')
                .map(|i| i + 1)
                .unwrap_or(0);
            let link = &entry.link[..entry.link_len as usize];
            if !link.is_empty() && link[0] == b'/' {
                let lstart = link.iter().position(|&b| b != b'/').unwrap_or(link.len());
                let n = (link.len() - lstart).min(current.len());
                current[..n].copy_from_slice(&link[lstart..lstart + n]);
                current_len = n;
            } else {
                let n = (dir_end + link.len()).min(current.len());
                let copy_n = (n - dir_end).min(link.len());
                current[dir_end..dir_end + copy_n].copy_from_slice(&link[..copy_n]);
                current_len = dir_end + copy_n;
            }
        }
        None
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        if offset >= size {
            return 0;
        }
        let remaining = (size - offset) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return 0;
        }

        let data_block = handle as u32;
        let mut done = 0usize;
        let mut file_off = offset as usize;
        let mut sector_buf = [0u8; 512];

        while done < to_read {
            let block_index = file_off / 512;
            let block_offset = file_off % 512;
            let chunk = (512 - block_offset).min(to_read - done);

            self.read_block(data_block + block_index as u32, &mut sector_buf);
            buf[done..done + chunk].copy_from_slice(&sector_buf[block_offset..block_offset + chunk]);

            done += chunk;
            file_off += chunk;
        }
        done as i32
    }

    /// The whole archive index is in RAM, so one pass over it yields the
    /// entire directory — subdirectories first, then files, matching the
    /// order the old index-based version produced. `max` is honoured, but a
    /// tar directory is small enough that the first batch normally finishes
    /// it; the cookie is a logical entry index into that fixed sequence.
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        let mut seen = 0u64; // entries passed over to reach the cookie
        let start = cookie;

        // Phase 1: unique subdirectory names. Linear scan of RAM, no ATA reads.
        let mut dirs: Vec<&[u8]> = Vec::new();
        for entry in &self.index {
            let name = &entry.name[..entry.name_len as usize];
            if name.len() > dir.len() {
                let matches = if dir.is_empty() { true } else { &name[..dir.len()] == dir };
                if matches {
                    let rest = &name[dir.len()..];
                    if let Some(slash) = rest.iter().position(|&b| b == b'/') {
                        let dir_name = &rest[..slash];
                        if !dirs.contains(&dir_name) {
                            dirs.push(dir_name);
                        }
                    }
                }
            }
        }
        for dir_name in dirs {
            if seen >= start {
                if out.len() >= max {
                    return Some(seen);
                }
                let len = dir_name.len().min(100);
                let mut de =
                    DirEntry { name: [0; 100], name_len: len, size: 0, is_dir: true,
                        mode: 0o755, mtime: 0 };
                de.name[..len].copy_from_slice(&dir_name[..len]);
                out.push(de);
            }
            seen += 1;
        }

        // Phase 2: files directly in this directory.
        for entry in &self.index {
            let name = &entry.name[..entry.name_len as usize];
            if let Some(basename) = entry_in_dir(name, dir) {
                if seen >= start {
                    if out.len() >= max {
                        return Some(seen);
                    }
                    let len = basename.len().min(100);
                    let mut de = DirEntry {
                        name: [0; 100],
                        name_len: len,
                        size: entry.size,
                        is_dir: false,
                        mode: entry.mode,
                        mtime: entry.mtime,
                    };
                    de.name[..len].copy_from_slice(&basename[..len]);
                    out.push(de);
                }
                seen += 1;
            }
        }

        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        // A directory exists when *some* entry has it as a strict prefix —
        // i.e. the next byte is '/'. The previous version's prefix-only
        // check matched the file itself ("bin/busybox" satisfies the
        // prefix of "bin/busybox"), making files masquerade as dirs and
        // breaking access(X_OK) on executable lookups.
        if path.is_empty() { return true; }
        let pat_with_slash = path.last().copied() == Some(b'/');
        let mut block: u32 = 0;
        loop {
            match self.read_header(block) {
                Some(entry) => {
                    let name = &entry.name[..entry.name_len];
                    if name.len() > path.len()
                        && &name[..path.len()] == path
                        && (pat_with_slash || name[path.len()] == b'/')
                    {
                        return true;
                    }
                    block = entry.next_block;
                }
                None => return false,
            }
        }
    }
}
