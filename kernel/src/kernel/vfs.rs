//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.
//!
//! Writable overlay: a BTreeMap<Vec<u8>, Vec<u8>> holds RAM-backed files
//! created by DOS programs. create() inserts, open() checks overlay
//! before the backing filesystem, read()/write()/seek() dispatch on the backing type.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Maximum simultaneous open files system-wide
const MAX_OPEN_FILES: usize = 64;

/// Maximum file descriptors per thread (must match thread::MAX_FDS)
const MAX_FDS: usize = 16;

/// First usable file descriptor (0=stdin, 1=stdout, 2=stderr)
const FIRST_FD: usize = 3;

/// Sentinel: handle value meaning "RAM-backed file"
const RAM_SENTINEL: u64 = u64::MAX;

/// Maximum length of a normalized path key
const PATH_KEY_MAX: usize = 164;

/// Filesystem trait — implemented by TarFs, Ext4Fs, etc.
pub trait Filesystem {
    /// Look up a file by normalized path. Returns vnode on match.
    fn open(&self, path: &[u8]) -> Option<Vnode>;

    /// Read from a file identified by handle at given byte offset.
    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32;

    /// Enumerate directory entries at index. Returns None at end.
    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry>;

    /// Check if a directory path exists.
    fn dir_exists(&self, path: &[u8]) -> bool;
}

/// Identifies a file on a filesystem
#[derive(Clone, Copy)]
pub struct Vnode {
    pub handle: u64,  // filesystem-specific opaque handle (RAM_SENTINEL for overlay)
    pub size: u32,
}

/// Directory entry returned by readdir
pub struct DirEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
    pub is_dir: bool,
}

/// An open file in the global file table
pub struct FileEntry {
    pub vnode: Vnode,
    pub offset: u32,
    pub refcount: u16,
    /// Index into MOUNTS table (which filesystem owns this file)
    pub mount_idx: u8,
    /// For RAM-backed files: normalized path key into RAM_FILES
    pub ram_key: [u8; PATH_KEY_MAX],
    pub ram_key_len: u8,
}

/// Mount table entry
struct Mount {
    prefix: &'static [u8],  // e.g. b"" for root, b"tar/" for sub-mount
    fs: &'static dyn Filesystem,
}

/// Mount table — up to 4 mounts, checked longest-prefix-first
const MAX_MOUNTS: usize = 4;
static mut MOUNTS: [Option<Mount>; MAX_MOUNTS] = [None, None, None, None];
static mut MOUNT_COUNT: usize = 0;

/// Writable file overlay — persists across open/close cycles
static mut RAM_FILES: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;

#[allow(static_mut_refs)]
fn ram_files() -> &'static mut BTreeMap<Vec<u8>, Vec<u8>> {
    unsafe { RAM_FILES.get_or_insert_with(BTreeMap::new) }
}

/// Find the mount whose prefix matches `path`, returning (mount_index, fs, path-after-prefix).
/// Longest prefix wins.
fn resolve_mount(path: &[u8]) -> (u8, &'static dyn Filesystem, &[u8]) {
    let mut best_idx = 0u8;
    let mut best_len = 0usize;
    let mut found = false;
    unsafe {
        for i in 0..MOUNT_COUNT {
            if let Some(ref m) = MOUNTS[i] {
                let plen = m.prefix.len();
                if m.prefix.is_empty() || (path.len() >= plen
                    && eq_ignore_case(&path[..plen], m.prefix))
                {
                    if !found || plen > best_len {
                        best_idx = i as u8;
                        best_len = plen;
                        found = true;
                    }
                }
            }
        }
    }
    if !found { panic!("VFS: no filesystem mounted"); }
    let m = unsafe { MOUNTS[best_idx as usize].as_ref().unwrap() };
    (best_idx, m.fs, &path[best_len..])
}

/// Get a filesystem by mount index.
fn mount_fs(idx: u8) -> &'static dyn Filesystem {
    unsafe { MOUNTS[idx as usize].as_ref().expect("VFS: invalid mount index").fs }
}

/// Mount a filesystem at a prefix. Empty prefix = root.
pub fn mount(prefix: &'static [u8], fs: &'static dyn Filesystem) {
    unsafe {
        assert!(MOUNT_COUNT < MAX_MOUNTS, "VFS: mount table full");
        MOUNTS[MOUNT_COUNT] = Some(Mount { prefix, fs });
        MOUNT_COUNT += 1;
    }
}

/// Global file table — slot is free when refcount == 0
static mut FILE_TABLE: [FileEntry; MAX_OPEN_FILES] = {
    const EMPTY: FileEntry = FileEntry {
        vnode: Vnode { handle: 0, size: 0 },
        offset: 0,
        refcount: 0,
        mount_idx: 0,
        ram_key: [0; PATH_KEY_MAX],
        ram_key_len: 0,
    };
    [EMPTY; MAX_OPEN_FILES]
};

/// Case-insensitive comparison of two byte slices
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

// ============================================================================
// Global file table helpers
// ============================================================================

fn alloc_file_entry() -> Option<usize> {
    unsafe {
        for i in 0..MAX_OPEN_FILES {
            if FILE_TABLE[i].refcount == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn alloc_fd(fds: &mut [i32; MAX_FDS]) -> Option<usize> {
    for fd in FIRST_FD..MAX_FDS {
        if fds[fd] == -1 {
            return Some(fd);
        }
    }
    None
}

// ============================================================================
// Public API — called by syscalls.rs and vm86.rs
// ============================================================================

/// Open a file by absolute VFS path. Returns fd (>= 3) or negative error.
pub fn open(path: &[u8], fds: &mut [i32; MAX_FDS]) -> i32 {
    // Check RAM overlay first
    let ram = ram_files();
    if let Some(data) = ram.get(path) {
        let size = data.len() as u32;
        let table_idx = match alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        let fd = match alloc_fd(fds) {
            Some(f) => f,
            None => return -24,
        };
        let key_len = path.len().min(PATH_KEY_MAX) as u8;
        let mut ram_key = [0u8; PATH_KEY_MAX];
        ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
        unsafe {
            FILE_TABLE[table_idx] = FileEntry {
                vnode: Vnode { handle: RAM_SENTINEL, size },
                offset: 0,
                refcount: 1,
                mount_idx: 0,
                ram_key,
                ram_key_len: key_len,
            };
        }
        fds[fd] = table_idx as i32;
        return fd as i32;
    }

    // Fall back to mounted filesystem
    let (midx, fs, subpath) = resolve_mount(path);
    let vnode = match fs.open(subpath) {
        Some(v) => v,
        None => return -2, // ENOENT
    };

    let table_idx = match alloc_file_entry() {
        Some(i) => i,
        None => return -24,
    };

    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => return -24,
    };

    unsafe {
        FILE_TABLE[table_idx] = FileEntry {
            vnode,
            offset: 0,
            refcount: 1,
            mount_idx: midx,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
    }
    fds[fd] = table_idx as i32;

    fd as i32
}

/// Read from an open file descriptor. Returns bytes read or negative error.
pub fn read(fd: i32, buf: &mut [u8], fds: &[i32; MAX_FDS]) -> i32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9;
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9;
    }

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9;
    }

    if entry.vnode.handle == RAM_SENTINEL {
        let key = &entry.ram_key[..entry.ram_key_len as usize];
        let ram = ram_files();
        if let Some(data) = ram.get(key) {
            let off = entry.offset as usize;
            if off >= data.len() { return 0; }
            let avail = data.len() - off;
            let n = buf.len().min(avail);
            buf[..n].copy_from_slice(&data[off..off + n]);
            entry.offset += n as u32;
            return n as i32;
        }
        return 0;
    }

    let n = mount_fs(entry.mount_idx).read(entry.vnode.handle, entry.offset, buf, entry.vnode.size);
    if n > 0 {
        entry.offset += n as u32;
    }
    n
}

/// Read entire file contents via fd into a kernel buffer (ignores current offset).
pub fn read_raw(fd: i32, buf: &mut [u8], fds: &[i32; MAX_FDS]) -> i32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9;
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9;
    }
    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9;
    }
    mount_fs(entry.mount_idx).read(entry.vnode.handle, entry.offset, buf, entry.vnode.size)
}

/// Close a file descriptor.
pub fn close(fd: i32, fds: &mut [i32; MAX_FDS]) -> i32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9;
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9;
    }

    fds[fd as usize] = -1;

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount > 0 {
        entry.refcount -= 1;
    }
    0
}

/// Create (or truncate) a writable RAM-backed file by absolute VFS path.
pub fn create(path: &[u8], fds: &mut [i32; MAX_FDS]) -> i32 {
    let key_len = path.len().min(PATH_KEY_MAX) as u8;

    ram_files().insert(path.to_vec(), Vec::new());

    let table_idx = match alloc_file_entry() {
        Some(i) => i,
        None => return -24,
    };
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => return -24,
    };

    let mut ram_key = [0u8; PATH_KEY_MAX];
    ram_key[..key_len as usize].copy_from_slice(&path[..key_len as usize]);
    unsafe {
        FILE_TABLE[table_idx] = FileEntry {
            vnode: Vnode { handle: RAM_SENTINEL, size: 0 },
            offset: 0,
            refcount: 1,
            mount_idx: 0,
            ram_key,
            ram_key_len: key_len,
        };
    }
    fds[fd] = table_idx as i32;
    fd as i32
}

/// Write to an open file descriptor.
pub fn write(fd: i32, data: &[u8], fds: &[i32; MAX_FDS]) -> i32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9;
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9;
    }

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9;
    }
    if entry.vnode.handle != RAM_SENTINEL {
        return data.len() as i32; // read-only FS; silently accept
    }

    let key = &entry.ram_key[..entry.ram_key_len as usize];
    let ram = ram_files();
    if let Some(file_data) = ram.get_mut(key) {
        let off = entry.offset as usize;
        let end = off + data.len();
        if end > file_data.len() {
            file_data.resize(end, 0);
        }
        file_data[off..end].copy_from_slice(data);
        entry.offset = end as u32;
        entry.vnode.size = file_data.len() as u32;
        return data.len() as i32;
    }
    -9
}

/// Delete a RAM-backed file by absolute VFS path.
pub fn delete(path: &[u8]) -> i32 {
    if ram_files().remove(path).is_some() { 0 } else { -2 }
}

/// Get the size of an open file descriptor.
pub fn file_size(fd: i32, fds: &[i32; MAX_FDS]) -> u32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 { return 0; }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 { return 0; }
    let entry = unsafe { &FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 { return 0; }
    if entry.vnode.handle == RAM_SENTINEL {
        let key = &entry.ram_key[..entry.ram_key_len as usize];
        return ram_files().get(key).map(|d| d.len() as u32).unwrap_or(0);
    }
    entry.vnode.size
}

/// Seek on an open file descriptor. whence: 0=SET, 1=CUR, 2=END
pub fn seek(fd: i32, offset: i32, whence: i32, fds: &[i32; MAX_FDS]) -> i32 {
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9;
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9;
    }

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9;
    }

    let size = if entry.vnode.handle == RAM_SENTINEL {
        let key = &entry.ram_key[..entry.ram_key_len as usize];
        ram_files().get(key).map(|d| d.len() as u32).unwrap_or(0)
    } else {
        entry.vnode.size
    };

    let new_offset = match whence {
        0 => offset as i64,
        1 => entry.offset as i64 + offset as i64,
        2 => size as i64 + offset as i64,
        _ => return -22,
    };

    if new_offset < 0 {
        return -22;
    }

    entry.offset = new_offset as u32;
    entry.offset as i32
}

/// Enumerate directory entries at index. Combines filesystem + mount points + RAM overlay.
pub fn readdir(dir: &[u8], index: usize) -> Option<DirEntry> {
    let (_midx, fs, subpath) = resolve_mount(dir);
    let mut remaining = index;

    // Filesystem entries first
    if let Some(de) = fs.readdir(subpath, remaining) {
        return Some(de);
    }
    let mut fs_count = 0;
    while fs.readdir(subpath, fs_count).is_some() { fs_count += 1; }
    remaining -= fs_count;

    // Synthesize mount point directories visible in this dir
    unsafe {
        for i in 0..MOUNT_COUNT {
            if let Some(ref m) = MOUNTS[i] {
                if let Some(name) = mount_child_in_dir(m.prefix, dir) {
                    if remaining == 0 {
                        let name_len = name.len().min(100);
                        let mut de = DirEntry {
                            name: [0; 100],
                            name_len,
                            size: 0,
                            is_dir: true,
                        };
                        de.name[..name_len].copy_from_slice(&name[..name_len]);
                        return Some(de);
                    }
                    remaining -= 1;
                }
            }
        }
    }

    // RAM overlay files
    let mut j = 0usize;
    for (key, data) in ram_files().iter() {
        if let Some(basename) = entry_in_ram_dir(key, dir) {
            if j == remaining {
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len: basename.len(),
                    size: data.len() as u32,
                    is_dir: false,
                };
                let len = basename.len().min(100);
                de.name[..len].copy_from_slice(&basename[..len]);
                return Some(de);
            }
            j += 1;
        }
    }
    None
}

/// If a mount prefix is a direct child of `dir`, return the child name.
/// e.g. mount "tar/" in dir "" → Some("tar"), mount "a/b/" in dir "a/" → Some("b").
fn mount_child_in_dir<'a>(prefix: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    // Mount prefix must start with dir
    if prefix.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&prefix[..dir.len()], dir) { return None; }
    let rest = &prefix[dir.len()..];
    // rest should be "name/" — one component with trailing slash
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

/// Check if a directory exists on a mounted filesystem.
pub fn dir_exists(path: &[u8]) -> bool {
    let (_midx, fs, subpath) = resolve_mount(path);
    fs.dir_exists(subpath)
}

/// Duplicate all FDs from src into dst (for fork).
pub fn dup_fds(src: &[i32; MAX_FDS], dst: &mut [i32; MAX_FDS]) {
    *dst = *src;
    unsafe {
        for &idx in dst.iter() {
            if idx >= 0 && (idx as usize) < MAX_OPEN_FILES {
                FILE_TABLE[idx as usize].refcount += 1;
            }
        }
    }
}

/// Close all FDs in the given array.
pub fn close_all_fds(fds: &mut [i32; MAX_FDS]) {
    unsafe {
        for fd in fds.iter_mut() {
            if *fd >= 0 && (*fd as usize) < MAX_OPEN_FILES {
                let entry = &mut FILE_TABLE[*fd as usize];
                if entry.refcount > 0 {
                    entry.refcount -= 1;
                }
            }
            *fd = -1;
        }
    }
}
