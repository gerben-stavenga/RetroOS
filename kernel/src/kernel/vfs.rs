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
    /// For RAM-backed files: normalized path key into RAM_FILES
    pub ram_key: [u8; PATH_KEY_MAX],
    pub ram_key_len: u8,
}

/// The backing filesystem (set once at startup)
static mut ROOT_FS: Option<&'static dyn Filesystem> = None;

/// Writable file overlay — persists across open/close cycles
static mut RAM_FILES: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;

#[allow(static_mut_refs)]
fn ram_files() -> &'static mut BTreeMap<Vec<u8>, Vec<u8>> {
    unsafe { RAM_FILES.get_or_insert_with(BTreeMap::new) }
}

#[allow(static_mut_refs)]
fn root_fs() -> &'static dyn Filesystem {
    unsafe { ROOT_FS.expect("VFS: no filesystem mounted") }
}

/// Mount a filesystem as the root. Must be called once at startup.
pub fn mount_root(fs: &'static dyn Filesystem) {
    unsafe { ROOT_FS = Some(fs); }
}

/// Global file table — slot is free when refcount == 0
static mut FILE_TABLE: [FileEntry; MAX_OPEN_FILES] = {
    const EMPTY: FileEntry = FileEntry {
        vnode: Vnode { handle: 0, size: 0 },
        offset: 0,
        refcount: 0,
        ram_key: [0; PATH_KEY_MAX],
        ram_key_len: 0,
    };
    [EMPTY; MAX_OPEN_FILES]
};

// ============================================================================
// Path resolution (VFS-level, filesystem-agnostic)
// ============================================================================

/// Strip DOS path prefix (e.g. `C:\`, `.\`, `\`) from a path.
fn strip_dos_prefix(path: &[u8]) -> &[u8] {
    let mut start = 0;
    if path.len() >= 2 && path[1] == b':' && path[0].is_ascii_alphabetic() {
        start = 2;
    }
    while start < path.len() && (path[start] == b'\\' || path[start] == b'/') {
        start += 1;
    }
    &path[start..]
}

/// Case-insensitive comparison of two byte slices
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

/// Resolve a path relative to the current working directory.
fn resolve_path<'a>(path: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    let has_drive = path.len() >= 2 && path[1] == b':' && path[0].is_ascii_alphabetic();
    let stripped = strip_dos_prefix(path);

    let len = if stripped.is_empty() {
        0
    } else {
        let mut pos = 0;
        if !has_drive {
            let cwd = crate::kernel::thread::current().cwd_str();
            for &b in cwd {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        }
        for &b in stripped {
            if pos < buf.len() {
                buf[pos] = if b == b'\\' { b'/' } else { b };
                pos += 1;
            }
        }
        pos
    };
    &buf[..len]
}

/// Resolve a path relative to cwd (public, for use by exec).
pub fn resolve<'a>(path: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    resolve_path(path, buf)
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

/// Open a file by path. Returns fd (>= 3) or negative error.
pub fn open(path: &[u8]) -> i32 {
    let mut buf = [0u8; PATH_KEY_MAX];
    let key = resolve_path(path, &mut buf);

    // Check RAM overlay first
    let ram = ram_files();
    if let Some(data) = ram.get(key) {
        let size = data.len() as u32;
        let table_idx = match alloc_file_entry() {
            Some(i) => i,
            None => return -24,
        };
        let fds = &mut crate::kernel::thread::current().fds;
        let fd = match alloc_fd(fds) {
            Some(f) => f,
            None => return -24,
        };
        let key_len = key.len().min(PATH_KEY_MAX) as u8;
        let mut ram_key = [0u8; PATH_KEY_MAX];
        ram_key[..key_len as usize].copy_from_slice(&key[..key_len as usize]);
        unsafe {
            FILE_TABLE[table_idx] = FileEntry {
                vnode: Vnode { handle: RAM_SENTINEL, size },
                offset: 0,
                refcount: 1,
                ram_key,
                ram_key_len: key_len,
            };
        }
        fds[fd] = table_idx as i32;
        return fd as i32;
    }

    // Fall back to mounted filesystem
    let vnode = match root_fs().open(key) {
        Some(v) => v,
        None => return -2, // ENOENT
    };

    let table_idx = match alloc_file_entry() {
        Some(i) => i,
        None => return -24,
    };

    let fds = &mut crate::kernel::thread::current().fds;
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => return -24,
    };

    unsafe {
        FILE_TABLE[table_idx] = FileEntry {
            vnode,
            offset: 0,
            refcount: 1,
            ram_key: [0; PATH_KEY_MAX],
            ram_key_len: 0,
        };
    }
    fds[fd] = table_idx as i32;

    fd as i32
}

/// Read from an open file descriptor. Returns bytes read or negative error.
pub fn read(fd: i32, buf: &mut [u8]) -> i32 {
    let fds = &crate::kernel::thread::current().fds;
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

    let n = root_fs().read(entry.vnode.handle, entry.offset, buf, entry.vnode.size);
    if n > 0 {
        entry.offset += n as u32;
    }
    n
}

/// Read entire file contents via fd into a kernel buffer (ignores current offset).
pub fn read_raw(fd: i32, buf: &mut [u8]) -> i32 {
    let fds = &crate::kernel::thread::current().fds;
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
    root_fs().read(entry.vnode.handle, entry.offset, buf, entry.vnode.size)
}

/// Close a file descriptor.
pub fn close(fd: i32) -> i32 {
    let fds = &mut crate::kernel::thread::current().fds;
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

/// Create (or truncate) a writable RAM-backed file.
pub fn create(path: &[u8]) -> i32 {
    let mut buf = [0u8; PATH_KEY_MAX];
    let key = resolve_path(path, &mut buf);
    let key_len = key.len().min(PATH_KEY_MAX) as u8;

    ram_files().insert(key.to_vec(), Vec::new());

    let table_idx = match alloc_file_entry() {
        Some(i) => i,
        None => return -24,
    };
    let fds = &mut crate::kernel::thread::current().fds;
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => return -24,
    };

    let mut ram_key = [0u8; PATH_KEY_MAX];
    ram_key[..key_len as usize].copy_from_slice(&key[..key_len as usize]);
    unsafe {
        FILE_TABLE[table_idx] = FileEntry {
            vnode: Vnode { handle: RAM_SENTINEL, size: 0 },
            offset: 0,
            refcount: 1,
            ram_key,
            ram_key_len: key_len,
        };
    }
    fds[fd] = table_idx as i32;
    fd as i32
}

/// Write to an open file descriptor.
pub fn write(fd: i32, data: &[u8]) -> i32 {
    let fds = &crate::kernel::thread::current().fds;
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

/// Delete a RAM-backed file by path.
pub fn delete(path: &[u8]) -> i32 {
    let mut buf = [0u8; PATH_KEY_MAX];
    let key = resolve_path(path, &mut buf);
    if ram_files().remove(key).is_some() { 0 } else { -2 }
}

/// Get the size of an open file descriptor.
pub fn file_size(fd: i32) -> u32 {
    let fds = &crate::kernel::thread::current().fds;
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
pub fn seek(fd: i32, offset: i32, whence: i32) -> i32 {
    let fds = &crate::kernel::thread::current().fds;
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

/// Enumerate directory entries at index. Combines filesystem + RAM overlay.
pub fn readdir(index: usize) -> Option<DirEntry> {
    let cwd = crate::kernel::thread::current().cwd_str();

    // Try filesystem first
    if let Some(de) = root_fs().readdir(cwd, index) {
        return Some(de);
    }

    // Count filesystem entries to compute RAM overlay offset
    let mut fs_count = 0;
    while root_fs().readdir(cwd, fs_count).is_some() {
        fs_count += 1;
    }

    // RAM overlay files in cwd
    let ram_idx = index - fs_count;
    let mut j = 0usize;
    for (key, data) in ram_files().iter() {
        if let Some(basename) = entry_in_ram_dir(key, cwd) {
            if j == ram_idx {
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

fn entry_in_ram_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if entry_name.len() <= dir.len() { return None; }
    if !dir.is_empty() && !eq_ignore_case(&entry_name[..dir.len()], dir) { return None; }
    let rest = &entry_name[dir.len()..];
    if rest.iter().any(|&b| b == b'/') { return None; }
    Some(rest)
}

/// Change current directory.
pub fn chdir(path: &[u8]) -> i32 {
    let stripped = strip_dos_prefix(path);

    if stripped == b".." {
        let t = crate::kernel::thread::current();
        let cwd = t.cwd_str();
        if cwd.is_empty() { return 0; }
        let without_slash = &cwd[..cwd.len().saturating_sub(1)];
        let new_len = match without_slash.iter().rposition(|&b| b == b'/') {
            Some(pos) => pos + 1,
            None => 0,
        };
        t.cwd_len = new_len;
        return 0;
    }

    if stripped.is_empty() || stripped == b"/" || stripped == b"\\" {
        let t = crate::kernel::thread::current();
        t.cwd_len = 0;
        return 0;
    }

    let mut new_cwd = [0u8; 64];
    let mut pos = 0;

    let t = crate::kernel::thread::current();
    let cwd = t.cwd_str();
    for &b in cwd {
        if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
    }
    for &b in stripped {
        if pos < new_cwd.len() {
            new_cwd[pos] = if b == b'\\' { b'/' } else { b };
            pos += 1;
        }
    }
    if pos > 0 && new_cwd[pos - 1] != b'/' {
        if pos < new_cwd.len() { new_cwd[pos] = b'/'; pos += 1; }
    }

    let prefix = &new_cwd[..pos];
    if !root_fs().dir_exists(prefix) {
        return -2;
    }

    t.set_cwd(prefix);
    0
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
