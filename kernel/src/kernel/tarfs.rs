//! TAR filesystem — implements the Filesystem trait for TAR archives on disk.

use crate::kernel::{hdd, vfs::{Filesystem, Vnode, DirEntry}};
use lib::tar::TarHeader;
use alloc::vec::Vec;

const BLOCK_SIZE: usize = 512;

/// In-memory index entry. The TAR is a singly-linked list on disk, so
/// `open()` would otherwise have to PIO-read the chain block-by-block on
/// every call — `D21 3D open` becoming a linear ATA scan of the whole
/// archive. We pay the scan cost once at mount time and answer opens
/// from RAM after that.
struct IndexEntry {
    name: [u8; 100],
    /// Same bytes as `name` with ASCII letters uppercased. Lets the
    /// case-insensitive open path be a memcmp against pre-normalized
    /// keys instead of a per-byte to-upper loop on every comparison.
    name_upper: [u8; 100],
    name_len: u16,
    data_block: u32,
    size: u32,
    is_symlink: bool,
    link: [u8; 100],
    link_len: u16,
}

pub struct TarFs {
    start_sector: u32,
    /// Entries sorted by original (case-sensitive) name — POSIX lookup.
    index: Vec<IndexEntry>,
    /// Permutation of `index` sorted by `name_upper` — DOS lookup.
    index_ci: Vec<u32>,
}

impl TarFs {
    pub const fn new(start_sector: u32) -> Self {
        Self { start_sector, index: Vec::new(), index_ci: Vec::new() }
    }

    /// Walk the on-disk TAR header chain once and cache entries in RAM.
    /// Entry name is kept in its original case; we also store an
    /// uppercase variant so DOS-side case-insensitive lookups can use a
    /// pre-normalized memcmp against `name_upper` instead of running a
    /// per-byte to-upper loop on every comparison. Both views are sorted
    /// to allow O(log N) lookups: `index` by original name (POSIX,
    /// `open`), `index_ci` as indices into `index` sorted by
    /// `name_upper` (DOS, `open_ci`).
    pub fn build_index(&mut self) {
        let mut block: u32 = 0;
        loop {
            let entry = match self.read_header(block) {
                Some(e) => e,
                None => break,
            };
            let mut name_upper = entry.name;
            for b in &mut name_upper[..entry.name_len] {
                b.make_ascii_uppercase();
            }
            self.index.push(IndexEntry {
                name: entry.name,
                name_upper,
                name_len: entry.name_len as u16,
                data_block: entry.data_block,
                size: entry.size,
                is_symlink: entry.is_symlink,
                link: entry.link,
                link_len: entry.link_len as u16,
            });
            block = entry.next_block;
        }
        self.index.sort_by(|a, b| {
            a.name[..a.name_len as usize].cmp(&b.name[..b.name_len as usize])
        });
        // Build the case-insensitive view as a permutation of the main
        // index sorted by uppercase name.
        self.index_ci = (0..self.index.len() as u32).collect();
        let idx_ref = &self.index;
        self.index_ci.sort_by(|&a, &b| {
            let ea = &idx_ref[a as usize];
            let eb = &idx_ref[b as usize];
            ea.name_upper[..ea.name_len as usize].cmp(&eb.name_upper[..eb.name_len as usize])
        });
        crate::println!("TAR: indexed {} entries from sector {:#x}",
            self.index.len(), self.start_sector);
    }

    /// O(log N) case-sensitive lookup. POSIX-faithful for Linux callers.
    fn find_cs(&self, path: &[u8]) -> Option<&IndexEntry> {
        self.index.binary_search_by(|e| {
            e.name[..e.name_len as usize].cmp(path)
        }).ok().map(|i| &self.index[i])
    }

    /// O(log N) case-insensitive lookup. Uppercases the query into a
    /// stack buffer, binary-searches `index_ci` against `name_upper`.
    fn find_ci(&self, path: &[u8]) -> Option<&IndexEntry> {
        let mut buf = [0u8; 200];
        let n = path.len().min(buf.len());
        for i in 0..n {
            buf[i] = path[i].to_ascii_uppercase();
        }
        let needle = &buf[..n];
        let idx_ref = &self.index;
        self.index_ci.binary_search_by(|&i| {
            let e = &idx_ref[i as usize];
            e.name_upper[..e.name_len as usize].cmp(needle)
        }).ok().map(|pos| &self.index[self.index_ci[pos] as usize])
    }

    fn read_header(&self, block: u32) -> Option<TarEntry> {
        let mut buf = [0u8; BLOCK_SIZE];
        hdd::read_sectors(self.start_sector + block, &mut buf);
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
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

/// Check if a TAR entry name is in the given directory.
/// Returns the basename (part after the directory prefix) if it matches.
fn entry_in_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if entry_name.len() <= dir.len() {
        return None;
    }
    if !dir.is_empty() {
        let prefix = &entry_name[..dir.len()];
        if !eq_ignore_case(prefix, dir) { return None; }
    }
    let rest = &entry_name[dir.len()..];
    if rest.iter().any(|&b| b == b'/') {
        return None;
    }
    Some(rest)
}

impl TarFs {
    /// Symlink-chasing open core. The lookup function is parameterised so
    /// case-sensitive (POSIX `open`) and case-insensitive (DOS `open_ci`)
    /// variants share the symlink resolution loop.
    fn open_with<F>(&self, path: &[u8], lookup: F) -> Option<Vnode>
    where F: for<'a> Fn(&'a Self, &[u8]) -> Option<&'a IndexEntry>,
    {
        let mut current: [u8; 164] = [0u8; 164];
        let mut current_len = path.len().min(current.len());
        current[..current_len].copy_from_slice(&path[..current_len]);

        for _ in 0..8 {
            let entry = lookup(self, &current[..current_len])?;
            if !entry.is_symlink {
                return Some(Vnode { handle: entry.data_block as u64, size: entry.size });
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
}

impl Filesystem for TarFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        self.open_with(path, |fs, p| fs.find_cs(p))
    }

    fn open_ci(&self, path: &[u8]) -> Option<Vnode> {
        self.open_with(path, |fs, p| fs.find_ci(p))
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

            hdd::read_sectors(self.start_sector + data_block + block_index as u32, &mut sector_buf);
            buf[done..done + chunk].copy_from_slice(&sector_buf[block_offset..block_offset + chunk]);

            done += chunk;
            file_off += chunk;
        }
        done as i32
    }

    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry> {
        // Phase 1: collect unique subdirectory names from the in-memory
        // index. Linear scan of RAM, no ATA reads.
        let mut dirs: [[u8; 64]; 32] = [[0; 64]; 32];
        let mut dir_lens: [usize; 32] = [0; 32];
        let mut dir_count = 0usize;
        for entry in &self.index {
            let name = &entry.name[..entry.name_len as usize];
            if name.len() > dir.len() {
                let prefix = &name[..dir.len()];
                if dir.is_empty() || eq_ignore_case(prefix, dir) {
                    let rest = &name[dir.len()..];
                    if let Some(slash) = rest.iter().position(|&b| b == b'/') {
                        let dir_name = &rest[..slash];
                        let mut dup = false;
                        for j in 0..dir_count {
                            if dir_lens[j] == dir_name.len() && eq_ignore_case(&dirs[j][..dir_lens[j]], dir_name) {
                                dup = true;
                                break;
                            }
                        }
                        if !dup && dir_count < 32 {
                            let len = dir_name.len().min(64);
                            dirs[dir_count][..len].copy_from_slice(&dir_name[..len]);
                            dir_lens[dir_count] = len;
                            dir_count += 1;
                        }
                    }
                }
            }
        }

        // Return directory entry if index falls in directory range
        if index < dir_count {
            let len = dir_lens[index];
            let mut de = DirEntry { name: [0; 100], name_len: len, size: 0, is_dir: true };
            de.name[..len].copy_from_slice(&dirs[index][..len]);
            return Some(de);
        }

        // Phase 2: enumerate files in directory (also from index).
        let file_idx = index - dir_count;
        let mut i = 0usize;
        for entry in &self.index {
            let name = &entry.name[..entry.name_len as usize];
            if let Some(basename) = entry_in_dir(name, dir) {
                if i == file_idx {
                    let mut de = DirEntry { name: [0; 100], name_len: basename.len(), size: entry.size, is_dir: false };
                    de.name[..basename.len()].copy_from_slice(basename);
                    return Some(de);
                }
                i += 1;
            }
        }

        None
    }

    fn list_dir(&self, dir: &[u8], buf: &mut [DirEntry]) -> usize {
        let mut count = 0usize;

        // Phase 1: collect unique subdirectory names
        let mut dirs: [[u8; 64]; 32] = [[0; 64]; 32];
        let mut dir_lens: [usize; 32] = [0; 32];
        let mut dir_count = 0usize;
        let mut block: u32 = 0;
        loop {
            let entry = match self.read_header(block) {
                Some(e) => e,
                None => break,
            };
            let name = &entry.name[..entry.name_len];
            if name.len() > dir.len() {
                let prefix = &name[..dir.len()];
                if dir.is_empty() || eq_ignore_case(prefix, dir) {
                    let rest = &name[dir.len()..];
                    if let Some(slash) = rest.iter().position(|&b| b == b'/') {
                        let dir_name = &rest[..slash];
                        let mut dup = false;
                        for j in 0..dir_count {
                            if dir_lens[j] == dir_name.len() && eq_ignore_case(&dirs[j][..dir_lens[j]], dir_name) {
                                dup = true;
                                break;
                            }
                        }
                        if !dup && dir_count < 32 {
                            let len = dir_name.len().min(64);
                            dirs[dir_count][..len].copy_from_slice(&dir_name[..len]);
                            dir_lens[dir_count] = len;
                            dir_count += 1;
                        }
                    }
                }
            }
            block = entry.next_block;
        }

        // Emit directory entries
        for i in 0..dir_count {
            if count >= buf.len() { return count; }
            let len = dir_lens[i];
            buf[count] = DirEntry { name: [0; 100], name_len: len, size: 0, is_dir: true };
            buf[count].name[..len].copy_from_slice(&dirs[i][..len]);
            count += 1;
        }

        // Phase 2: emit files in one pass
        block = 0;
        loop {
            match self.read_header(block) {
                Some(entry) => {
                    if count >= buf.len() { return count; }
                    let name = &entry.name[..entry.name_len];
                    if let Some(basename) = entry_in_dir(name, dir) {
                        let blen = basename.len();
                        buf[count] = DirEntry { name: [0; 100], name_len: blen, size: entry.size, is_dir: false };
                        buf[count].name[..blen].copy_from_slice(basename);
                        count += 1;
                    }
                    block = entry.next_block;
                }
                None => break,
            }
        }
        count
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
                        && eq_ignore_case(&name[..path.len()], path)
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
