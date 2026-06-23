//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.
//!
//! Writable overlay: a BTreeMap<Vec<u8>, Vec<u8>> holds RAM-backed files
//! created by DOS programs. create() inserts, open() checks overlay
//! before the backing filesystem, read()/write()/seek() dispatch on the backing type.
//!
//! All VFS state — the mount table, the open-file table, the RAM overlay, and
//! the path/dir caches — is a single kernel-wide singleton (`Vfs`) behind a
//! `spin::Mutex`, so access is borrow-checked and correct under multiple cores.
//! The lock is taken only from kernel/event-loop context (ISRs merely queue), so
//! a plain spinlock suffices. To stay deadlock-free, the *state* lives in `&mut
//! self` methods on `Vfs` (which call each other via `self`, never re-locking);
//! the public free functions are thin wrappers that lock once, and the
//! orchestrators (`open`/`read`/…, which only juggle the caller's fd array and
//! call other public wrappers) never hold the lock across a call. The backing
//! filesystems never call back into `vfs`, so holding the lock across `fs.read`/
//! `fs.open` is safe.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::kernel::thread::FdKind;

/// Maximum simultaneous open files system-wide
const MAX_OPEN_FILES: usize = 64;

/// Maximum file descriptors per thread (must match thread::MAX_FDS)
const MAX_FDS: usize = 32;

/// First usable file descriptor (0=stdin, 1=stdout, 2=stderr)
const FIRST_FD: usize = 3;

/// Sentinel: handle value meaning "RAM-backed file"
const RAM_SENTINEL: u64 = u64::MAX;

/// Maximum length of a normalized path key
const PATH_KEY_MAX: usize = 164;

/// Filesystem trait — implemented by TarFs, Ext4Fs, etc. POSIX-strict; the
/// DOS personality wraps this layer with its own case-folding cache (DFS).
pub trait Filesystem {
    /// Look up a file by normalized path, case-sensitively (POSIX).
    fn open(&self, path: &[u8]) -> Option<Vnode>;

    /// Read from a file identified by handle at given byte offset.
    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32;

    /// Enumerate directory entries at index. Returns None at end.
    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry>;

    /// Check if a directory path exists.
    fn dir_exists(&self, path: &[u8]) -> bool;

    /// Create (or truncate) a file. Returns vnode on success. Default = R/O.
    fn create(&self, _path: &[u8]) -> Option<Vnode> { None }

    /// Write to a file identified by handle at given byte offset. Returns
    /// bytes written, or negative errno. Default = R/O (silently accept).
    fn write(&self, _handle: u64, _offset: u32, data: &[u8]) -> i32 {
        data.len() as i32
    }
}

/// Identifies a file on a filesystem
#[derive(Clone, Copy)]
pub struct Vnode {
    pub handle: u64,  // filesystem-specific opaque handle (RAM_SENTINEL for overlay)
    pub size: u32,
    /// POSIX permission bits (lower 12 — perms + setuid/setgid/sticky).
    /// Carried through from the backing filesystem (TAR's USTAR mode field,
    /// ext4's stat, etc.). Linux personality returns these in stat64.
    pub mode: u16,
}

/// Directory entry returned by readdir
pub struct DirEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
    pub is_dir: bool,
    /// POSIX permission bits (same convention as `Vnode::mode`).
    pub mode: u16,
}

/// Stable inode from a path (FNV-1a, forced nonzero). Same path → same ino,
/// distinct paths → distinct ino (modulo hash collisions) — enough for the
/// dynamic linker's object dedup.
fn path_ino(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in path { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h | 1
}

/// An open file in the global file table
pub struct FileEntry {
    pub vnode: Vnode,
    pub offset: u32,
    pub refcount: u16,
    /// Stable per-file inode (FNV hash of the path). fstat reports it so the
    /// dynamic linker's (st_dev, st_ino) dedup distinguishes libraries — without
    /// it every file shares ino 0 and ld.so thinks libc == the main binary.
    pub ino: u64,
    /// Index into the mount table (which filesystem owns this file)
    pub mount_idx: u8,
    /// For RAM-backed files: normalized path key into the RAM overlay
    pub ram_key: [u8; PATH_KEY_MAX],
    pub ram_key_len: u8,
}

/// Mount table entry
#[derive(Clone, Copy)]
struct Mount {
    prefix: &'static [u8],  // e.g. b"" for root, b"boot/" for sub-mount
    fs: &'static dyn Filesystem,
}

const MAX_MOUNTS: usize = 6;

/// Single-directory readdir cache (avoids O(n²) re-scanning for sequential
/// readdir). One directory cached at a time, growable so a flat dir with
/// hundreds of entries doesn't get truncated.
struct DirCache {
    dir: [u8; 96],
    dir_len: usize,
    entries: Vec<DirEntry>,
    valid: bool,
}

impl DirCache {
    const fn new() -> Self {
        DirCache { dir: [0; 96], dir_len: 0, entries: Vec::new(), valid: false }
    }
}

/// Fallback filesystem for "nothing mounted": every lookup misses.
struct EmptyFs;
impl Filesystem for EmptyFs {
    fn open(&self, _path: &[u8]) -> Option<Vnode> { None }
    fn read(&self, _h: u64, _o: u32, _b: &mut [u8], _s: u32) -> i32 { -2 }
    fn readdir(&self, _dir: &[u8], _index: usize) -> Option<DirEntry> { None }
    fn dir_exists(&self, _path: &[u8]) -> bool { false }
}
static EMPTY_FS: EmptyFs = EmptyFs;

// ============================================================================
// The VFS singleton
// ============================================================================

/// All VFS state, behind one lock. See the module docs for the locking model.
struct Vfs {
    mounts: [Option<Mount>; MAX_MOUNTS],
    mount_count: usize,
    /// Writable file overlay — persists across open/close cycles.
    ram_files: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Path-keyed vnode cache in front of `fs.open()` (skips the FS walk on
    /// repeated opens — matters most for ext4). RAM overlay shadows it.
    path_cache: BTreeMap<Vec<u8>, (u8, Vnode)>,
    /// Global file table — slot is free when refcount == 0.
    file_table: [FileEntry; MAX_OPEN_FILES],
    dir_cache: DirCache,
}

impl Vfs {
    const fn new() -> Self {
        const EMPTY: FileEntry = FileEntry {
            vnode: Vnode { handle: 0, size: 0, mode: 0 },
            ino: 0,
            offset: 0,
            refcount: 0,
            mount_idx: 0,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
        Vfs {
            mounts: [None; MAX_MOUNTS],
            mount_count: 0,
            ram_files: BTreeMap::new(),
            path_cache: BTreeMap::new(),
            file_table: [EMPTY; MAX_OPEN_FILES],
            dir_cache: DirCache::new(),
        }
    }

    // ── mount table ──────────────────────────────────────────────────────

    /// Find the mount whose prefix matches `path`: (mount_index, fs, path-after-
    /// prefix). Longest prefix wins; a path equal to a prefix sans trailing `/`
    /// resolves to that mount's root.
    fn resolve_mount<'a>(&self, path: &'a [u8]) -> (u8, &'static dyn Filesystem, &'a [u8]) {
        let mut best_idx = 0u8;
        let mut best_len = 0usize;
        let mut found = false;
        for i in 0..self.mount_count {
            if let Some(ref m) = self.mounts[i] {
                let plen = m.prefix.len();
                let matches = m.prefix.is_empty()
                    || (path.len() >= plen && eq_ignore_case(&path[..plen], m.prefix))
                    || (plen > 0 && m.prefix.last() == Some(&b'/')
                        && path.len() == plen - 1
                        && eq_ignore_case(path, &m.prefix[..plen-1]));
                if matches && (!found || plen > best_len) {
                    best_idx = i as u8;
                    best_len = plen.min(path.len());
                    found = true;
                }
            }
        }
        if !found {
            // Nothing mounted (e.g. the hosted bare-ELF Linux path, before a root
            // fs exists). Resolve to the empty filesystem so opens miss with
            // -ENOENT instead of panicking.
            return (0, &EMPTY_FS, path);
        }
        let m = self.mounts[best_idx as usize].as_ref().unwrap();
        (best_idx, m.fs, &path[best_len..])
    }

    /// If `parent/<name>` (case-insensitive) is itself a mount point, return the
    /// mount's directory component (e.g. parent=`home/retroos`, name=`BOOT` →
    /// `b"boot"`). DFS uses this so a VFS mount point is a traversable directory
    /// even though the parent's *backing* fs has no such readdir entry.
    fn mount_child(&self, parent: &[u8], name: &[u8]) -> Option<&'static [u8]> {
        let mut par = parent;
        while par.first() == Some(&b'/') { par = &par[1..]; }
        while par.last() == Some(&b'/') { par = &par[..par.len() - 1]; }
        for i in 0..self.mount_count {
            if let Some(ref m) = self.mounts[i] {
                let prefix: &'static [u8] = m.prefix;
                // Drop the trailing slash mount prefixes carry.
                let p: &'static [u8] = if prefix.last() == Some(&b'/') {
                    &prefix[..prefix.len() - 1]
                } else { prefix };
                if p.is_empty() { continue; } // root mount: no child name
                let (dir, last): (&[u8], &'static [u8]) = match p.iter().rposition(|&b| b == b'/') {
                    Some(idx) => (&p[..idx], &p[idx + 1..]),
                    None => (&b""[..], p),
                };
                if eq_ignore_case(dir, par) && eq_ignore_case(last, name) {
                    return Some(last);
                }
            }
        }
        None
    }

    fn mount_fs(&self, idx: u8) -> &'static dyn Filesystem {
        self.mounts[idx as usize].as_ref().expect("VFS: invalid mount index").fs
    }

    fn mount(&mut self, prefix: &'static [u8], fs: &'static dyn Filesystem) {
        assert!(self.mount_count < MAX_MOUNTS, "VFS: mount table full");
        self.mounts[self.mount_count] = Some(Mount { prefix, fs });
        self.mount_count += 1;
    }

    // ── file table ───────────────────────────────────────────────────────

    fn alloc_file_entry(&self) -> Option<usize> {
        (0..MAX_OPEN_FILES).find(|&i| self.file_table[i].refcount == 0)
    }

    fn close_handle(&mut self, idx: i32) {
        if idx >= 0 && (idx as usize) < MAX_OPEN_FILES {
            let entry = &mut self.file_table[idx as usize];
            if entry.refcount > 0 {
                entry.refcount -= 1;
            }
        }
    }

    fn add_ref(&mut self, idx: i32) {
        if idx >= 0 && (idx as usize) < MAX_OPEN_FILES {
            self.file_table[idx as usize].refcount += 1;
        }
    }

    // ── dir cache ────────────────────────────────────────────────────────

    fn invalidate_dir_cache(&mut self) {
        self.dir_cache.valid = false;
    }

    /// Populate the directory cache for `dir` (single pass).
    fn populate_dir_cache(&mut self, dir: &[u8]) {
        let dlen = dir.len().min(self.dir_cache.dir.len());
        self.dir_cache.dir[..dlen].copy_from_slice(&dir[..dlen]);
        self.dir_cache.dir_len = dlen;
        self.dir_cache.entries.clear();

        let (_midx, fs, subpath) = self.resolve_mount(dir);
        let mut idx = 0usize;
        while let Some(e) = fs.readdir(subpath, idx) {
            self.dir_cache.entries.push(e);
            idx += 1;
        }

        // Synthesize mount-point directories.
        for i in 0..self.mount_count {
            if let Some(ref m) = self.mounts[i] {
                if let Some(name) = mount_child_in_dir(m.prefix, dir) {
                    let name_len = name.len().min(100);
                    let mut de = DirEntry {
                        name: [0; 100], name_len, size: 0, is_dir: true, mode: 0o755,
                    };
                    de.name[..name_len].copy_from_slice(&name[..name_len]);
                    self.dir_cache.entries.push(de);
                }
            }
        }

        // RAM overlay files.
        for (key, data) in self.ram_files.iter() {
            if let Some(basename) = entry_in_ram_dir(key, dir) {
                let len = basename.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100], name_len: len, size: data.len() as u32,
                    is_dir: false, mode: 0o644,
                };
                de.name[..len].copy_from_slice(&basename[..len]);
                self.dir_cache.entries.push(de);
            }
        }

        self.dir_cache.valid = true;
    }

    fn readdir(&mut self, dir: &[u8], index: usize) -> Option<DirEntry> {
        let stale = !self.dir_cache.valid
            || self.dir_cache.dir_len != dir.len()
            || self.dir_cache.dir[..self.dir_cache.dir_len] != *dir;
        if stale {
            self.populate_dir_cache(dir);
        }
        self.dir_cache.entries.get(index).map(clone_dir_entry)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        let (_midx, fs, subpath) = self.resolve_mount(path);
        fs.dir_exists(subpath)
    }

    // ── open / create / read / write / seek ──────────────────────────────

    fn open_to_handle(&mut self, path: &[u8]) -> i32 {
        // Check RAM overlay first.
        if let Some(data) = self.ram_files.get(path) {
            let size = data.len() as u32;
            let table_idx = match self.alloc_file_entry() {
                Some(i) => i,
                None => return -24,
            };
            let key_len = path.len().min(PATH_KEY_MAX) as u8;
            let mut ram_key = [0u8; PATH_KEY_MAX];
            ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
            self.file_table[table_idx] = FileEntry {
                vnode: Vnode { handle: RAM_SENTINEL, size, mode: 0o644 },
                ino: path_ino(path),
                offset: 0,
                refcount: 1,
                mount_idx: 0,
                ram_key,
                ram_key_len: key_len,
            };
            return table_idx as i32;
        }

        // Path cache: skip fs.open if we've already resolved this path. The
        // cached vnode's FS-internal handle is shared across file-table entries;
        // each entry still has its own offset.
        if let Some(&(midx, vnode)) = self.path_cache.get(path) {
            let table_idx = match self.alloc_file_entry() {
                Some(i) => i,
                None => return -24,
            };
            self.file_table[table_idx] = FileEntry {
                vnode, ino: path_ino(path), offset: 0, refcount: 1, mount_idx: midx,
                ram_key: [0; PATH_KEY_MAX], ram_key_len: 0,
            };
            return table_idx as i32;
        }

        let (midx, fs, subpath) = self.resolve_mount(path);
        let vnode = match fs.open(subpath) {
            Some(v) => v,
            None => return -2,
        };

        self.path_cache.insert(path.to_vec(), (midx, vnode));

        let table_idx = match self.alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        self.file_table[table_idx] = FileEntry {
            vnode,
            ino: path_ino(path),
            offset: 0,
            refcount: 1,
            mount_idx: midx,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
        table_idx as i32
    }

    fn create_to_handle(&mut self, path: &[u8]) -> i32 {
        let (midx, fs, subpath) = self.resolve_mount(path);
        if let Some(vnode) = fs.create(subpath) {
            let table_idx = match self.alloc_file_entry() {
                Some(i) => i,
                None => return -24,
            };
            self.file_table[table_idx] = FileEntry {
                vnode,
                ino: path_ino(path),
                offset: 0,
                refcount: 1,
                mount_idx: midx,
                ram_key: [0; PATH_KEY_MAX],
                ram_key_len: 0,
            };
            self.invalidate_dir_cache();
            return table_idx as i32;
        }

        let key_len = path.len().min(PATH_KEY_MAX) as u8;
        self.ram_files.insert(path.to_vec(), Vec::new());
        self.invalidate_dir_cache();

        let table_idx = match self.alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        let mut ram_key = [0u8; PATH_KEY_MAX];
        ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
        self.file_table[table_idx] = FileEntry {
            vnode: Vnode { handle: RAM_SENTINEL, size: 0, mode: 0o644 },
            ino: path_ino(path),
            offset: 0,
            refcount: 1,
            mount_idx: 0,
            ram_key,
            ram_key_len: key_len,
        };
        table_idx as i32
    }

    fn delete(&mut self, path: &[u8]) -> i32 {
        if self.ram_files.remove(path).is_some() {
            self.invalidate_dir_cache();
            0
        } else { -2 }
    }

    fn read_by_handle(&mut self, handle: i32, buf: &mut [u8]) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let off = self.file_table[h].offset as usize;
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            if let Some(data) = self.ram_files.get(&key) {
                if off >= data.len() { return 0; }
                let avail = data.len() - off;
                let n = buf.len().min(avail);
                buf[..n].copy_from_slice(&data[off..off + n]);
                self.file_table[h].offset += n as u32;
                return n as i32;
            }
            return 0;
        }

        let (mount_idx, fs_handle, offset, size) = {
            let e = &self.file_table[h];
            (e.mount_idx, e.vnode.handle, e.offset, e.vnode.size)
        };
        let n = self.mount_fs(mount_idx).read(fs_handle, offset, buf, size);
        if n > 0 { self.file_table[h].offset += n as u32; }
        n
    }

    fn write_by_handle(&mut self, handle: i32, data: &[u8]) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let off = self.file_table[h].offset as usize;
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            if let Some(file_data) = self.ram_files.get_mut(&key) {
                let end = off + data.len();
                if end > file_data.len() { file_data.resize(end, 0); }
                file_data[off..end].copy_from_slice(data);
                let new_size = file_data.len() as u32;
                self.file_table[h].offset = end as u32;
                self.file_table[h].vnode.size = new_size;
                return data.len() as i32;
            }
            return -9;
        }

        let (mount_idx, fs_handle, offset) = {
            let e = &self.file_table[h];
            (e.mount_idx, e.vnode.handle, e.offset)
        };
        let n = self.mount_fs(mount_idx).write(fs_handle, offset, data);
        if n > 0 {
            let e = &mut self.file_table[h];
            e.offset += n as u32;
            if e.offset > e.vnode.size { e.vnode.size = e.offset; }
        }
        n
    }

    fn seek_by_handle(&mut self, handle: i32, offset: i32, whence: i32) -> i32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return -9; }
        let h = handle as usize;
        if self.file_table[h].refcount == 0 { return -9; }

        let size = if self.file_table[h].vnode.handle == RAM_SENTINEL {
            let klen = self.file_table[h].ram_key_len as usize;
            let key = self.file_table[h].ram_key[..klen].to_vec();
            self.ram_files.get(&key).map(|d| d.len() as u32).unwrap_or(0)
        } else {
            self.file_table[h].vnode.size
        };

        let cur = self.file_table[h].offset;
        let new_offset = match whence {
            0 => offset as i64,
            1 => cur as i64 + offset as i64,
            2 => size as i64 + offset as i64,
            _ => return -22,
        };
        if new_offset < 0 { return -22; }
        self.file_table[h].offset = new_offset as u32;
        self.file_table[h].offset as i32
    }

    fn file_size_by_handle(&self, handle: i32) -> u32 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        if e.vnode.handle == RAM_SENTINEL {
            let key = &e.ram_key[..e.ram_key_len as usize];
            return self.ram_files.get(key).map(|d| d.len() as u32).unwrap_or(0);
        }
        e.vnode.size
    }

    fn file_ino_by_handle(&self, handle: i32) -> u64 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.ino
    }

    fn file_mode_by_handle(&self, handle: i32) -> u16 {
        if handle < 0 || (handle as usize) >= MAX_OPEN_FILES { return 0; }
        let e = &self.file_table[handle as usize];
        if e.refcount == 0 { return 0; }
        e.vnode.mode
    }
}

// `Vfs` holds `&'static dyn Filesystem`, and some backends are not thread-safe
// in isolation (the ext4 wrapper uses `Rc`/`RefCell` because `ext4_view` is
// single-threaded). This `Send` is nonetheless sound — and SMP-correct, not a
// single-core assumption — because *every* filesystem access goes through
// `&mut self` while the VFS `spin::Mutex` is held, so no filesystem (and no
// `Rc` refcount) is ever touched by two cores at once. The lock serializes all
// FS use; this is the one `unsafe` the locking model earns, in place of the 22
// scattered `static mut` accesses it replaced.
unsafe impl Send for Vfs {}

static VFS: Mutex<Vfs> = Mutex::new(Vfs::new());

// ============================================================================
// Pure helpers (no VFS state)
// ============================================================================

/// Case-insensitive comparison of two byte slices
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

fn alloc_fd(fds: &[FdKind; MAX_FDS]) -> Option<usize> {
    (FIRST_FD..MAX_FDS).find(|&fd| fds[fd].is_none())
}

/// Extract VFS handle from an FdKind, or return -9 (EBADF).
fn vfs_handle(fds: &[FdKind; MAX_FDS], fd: i32) -> Result<i32, i32> {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 { return Err(-9); }
    match fds[fd as usize] {
        FdKind::Vfs(idx) => Ok(idx),
        _ => Err(-9),
    }
}

fn clone_dir_entry(e: &DirEntry) -> DirEntry {
    DirEntry {
        name: e.name,
        name_len: e.name_len,
        size: e.size,
        is_dir: e.is_dir,
        mode: e.mode,
    }
}

/// If a mount prefix is a direct child of `dir`, return the child name.
/// e.g. mount "boot/" in dir "" → Some("boot"), mount "a/b/" in dir "a/" → Some("b").
fn mount_child_in_dir<'a>(prefix: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if prefix.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&prefix[..dir.len()], dir) { return None; }
    let rest = &prefix[dir.len()..];
    let name = rest.strip_suffix(b"/")?;
    if name.is_empty() || name.contains(&b'/') { return None; }
    Some(name)
}

fn entry_in_ram_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if entry_name.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&entry_name[..dir.len()], dir) { return None; }
    let rest = &entry_name[dir.len()..];
    if rest.iter().any(|&b| b == b'/') { return None; }
    Some(rest)
}

// ============================================================================
// Public API — thin locking wrappers + lock-free orchestrators.
// Called by syscalls.rs and vm86.rs.
// ============================================================================

/// Mount a filesystem at a prefix. Empty prefix = root.
pub fn mount(prefix: &'static [u8], fs: &'static dyn Filesystem) {
    VFS.lock().mount(prefix, fs);
}

/// Invalidate the directory cache (call after file create/delete).
pub fn invalidate_dir_cache() {
    VFS.lock().invalidate_dir_cache();
}

/// Open a file by absolute VFS path. Returns fd (>= 3) or negative error.
/// POSIX-strict case-sensitive lookup. (Orchestrator: no lock held across the
/// `open_to_handle` / `close_vfs_handle` wrapper calls.)
pub fn open(path: &[u8], fds: &mut [FdKind; MAX_FDS]) -> i32 {
    let handle = open_to_handle(path);
    if handle < 0 { return handle; }
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => { close_vfs_handle(handle); return -24; }
    };
    fds[fd] = FdKind::Vfs(handle);
    fd as i32
}

/// Read from an open file descriptor. Returns bytes read or negative error.
pub fn read(fd: i32, buf: &mut [u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => read_by_handle(handle, buf),
        Err(e) => e,
    }
}

/// Read entire file contents via fd into a kernel buffer (ignores current offset).
pub fn read_raw(fd: i32, buf: &mut [u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => read_by_handle(handle, buf),
        Err(e) => e,
    }
}

/// Close a file descriptor.
pub fn close(fd: i32, fds: &mut [FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => {
            fds[fd as usize] = FdKind::None;
            close_vfs_handle(handle);
            0
        }
        Err(e) => e,
    }
}

/// Create (or truncate) a writable RAM-backed file by absolute VFS path.
pub fn create(path: &[u8], fds: &mut [FdKind; MAX_FDS]) -> i32 {
    let handle = create_to_handle(path);
    if handle < 0 { return handle; }
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => { close_vfs_handle(handle); return -24; }
    };
    fds[fd] = FdKind::Vfs(handle);
    fd as i32
}

/// Create (or truncate) a file. If the path's mount FS supports `create`,
/// it owns the file; otherwise we fall back to the RAM overlay.
pub fn create_to_handle(path: &[u8]) -> i32 {
    VFS.lock().create_to_handle(path)
}

/// Write to an open file descriptor.
pub fn write(fd: i32, data: &[u8], fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => write_by_handle(handle, data),
        Err(e) => e,
    }
}

/// Delete a RAM-backed file by absolute VFS path.
pub fn delete(path: &[u8]) -> i32 {
    VFS.lock().delete(path)
}

/// Get the size of an open file descriptor.
pub fn file_size(fd: i32, fds: &[FdKind; MAX_FDS]) -> u32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => file_size_by_handle(handle),
        Err(_) => 0,
    }
}

/// Seek on an open file descriptor. whence: 0=SET, 1=CUR, 2=END
pub fn seek(fd: i32, offset: i32, whence: i32, fds: &[FdKind; MAX_FDS]) -> i32 {
    match vfs_handle(fds, fd) {
        Ok(handle) => seek_by_handle(handle, offset, whence),
        Err(e) => e,
    }
}

/// Enumerate directory entries at index. Uses a single-pass cache.
pub fn readdir(dir: &[u8], index: usize) -> Option<DirEntry> {
    VFS.lock().readdir(dir, index)
}

/// Check if a directory exists on a mounted filesystem.
pub fn dir_exists(path: &[u8]) -> bool {
    VFS.lock().dir_exists(path)
}

/// If `parent/<name>` (case-insensitive) is a mount point, return its directory
/// component (so a VFS mount is traversable by DFS's component walk).
pub fn mount_child(parent: &[u8], name: &[u8]) -> Option<&'static [u8]> {
    VFS.lock().mount_child(parent, name)
}

/// Decrement refcount for a VFS file table entry (Linux FdKind::Vfs close).
pub fn close_vfs_handle(idx: i32) {
    VFS.lock().close_handle(idx);
}

/// Increment refcount for a VFS file table entry (Linux fork/dup).
pub fn add_vfs_ref(idx: i32) {
    VFS.lock().add_ref(idx);
}

/// Open a file and return the VFS file table index (not an fd slot).
/// Used by Linux syscalls that manage their own FdKind table.
pub fn open_to_handle(path: &[u8]) -> i32 {
    VFS.lock().open_to_handle(path)
}

/// Read from a VFS file table entry by handle index.
pub fn read_by_handle(handle: i32, buf: &mut [u8]) -> i32 {
    VFS.lock().read_by_handle(handle, buf)
}

/// Write to a VFS file table entry by handle index.
pub fn write_by_handle(handle: i32, data: &[u8]) -> i32 {
    VFS.lock().write_by_handle(handle, data)
}

/// Seek on a VFS handle directly.
pub fn seek_by_handle(handle: i32, offset: i32, whence: i32) -> i32 {
    VFS.lock().seek_by_handle(handle, offset, whence)
}

/// Get file size by VFS handle.
pub fn file_size_by_handle(handle: i32) -> u32 {
    VFS.lock().file_size_by_handle(handle)
}

/// Stable inode for an open handle — fstat's st_ino (dynamic-linker dedup).
pub fn file_ino_by_handle(handle: i32) -> u64 {
    VFS.lock().file_ino_by_handle(handle)
}

/// Get POSIX mode bits by VFS handle. Returns 0 for an invalid handle.
pub fn file_mode_by_handle(handle: i32) -> u16 {
    VFS.lock().file_mode_by_handle(handle)
}
