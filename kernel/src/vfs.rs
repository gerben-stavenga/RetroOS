//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.

use crate::startup;

/// Maximum simultaneous open files system-wide
const MAX_OPEN_FILES: usize = 64;

/// Maximum file descriptors per thread (must match thread::MAX_FDS)
const MAX_FDS: usize = 16;

/// First usable file descriptor (0=stdin, 1=stdout, 2=stderr)
const FIRST_FD: usize = 3;

/// Identifies a file on a filesystem
#[derive(Clone, Copy)]
pub struct Vnode {
    pub data_block: u32, // TarFS: starting data block (sector after header)
    pub size: u32,
}

/// An open file in the global file table
pub struct FileEntry {
    pub vnode: Vnode,
    pub offset: u32,
    pub refcount: u16,
}

/// Directory entry returned by readdir
pub struct DirEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
}

/// Global file table — slot is free when refcount == 0
static mut FILE_TABLE: [FileEntry; MAX_OPEN_FILES] = {
    const EMPTY: FileEntry = FileEntry {
        vnode: Vnode { data_block: 0, size: 0 },
        offset: 0,
        refcount: 0,
    };
    [EMPTY; MAX_OPEN_FILES]
};

// ============================================================================
// TarFS operations
// ============================================================================

/// Strip DOS path prefix (e.g. `C:\`, `.\`, `\`) from a path.
fn strip_dos_prefix(path: &[u8]) -> &[u8] {
    let mut start = 0;
    // Skip drive letter + colon (e.g. "C:")
    if path.len() >= 2 && path[1] == b':' && path[0].is_ascii_alphabetic() {
        start = 2;
    }
    // Skip leading backslashes/slashes
    while start < path.len() && (path[start] == b'\\' || path[start] == b'/') {
        start += 1;
    }
    &path[start..]
}

/// Case-insensitive comparison of two byte slices
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

/// Walk the TAR archive looking for `path`. Returns a Vnode on match.
/// Strips DOS path prefixes and matches case-insensitively.
fn tar_open(path: &[u8]) -> Option<Vnode> {
    let basename = strip_dos_prefix(path);
    let mut block: u32 = 0;
    loop {
        let entry = startup::tar_entry_at_block(block)?;
        let name = &entry.name[..entry.name_len];
        if eq_ignore_case(name, basename) {
            return Some(Vnode {
                data_block: entry.data_block,
                size: entry.size,
            });
        }
        block = entry.next_block;
    }
}

/// Read from a TarFS vnode at the given byte offset into `buf`.
/// Returns number of bytes read.
fn tar_read(vnode: &Vnode, offset: u32, buf: &mut [u8]) -> i32 {
    if offset >= vnode.size {
        return 0;
    }
    let remaining = (vnode.size - offset) as usize;
    let to_read = buf.len().min(remaining);
    if to_read == 0 {
        return 0;
    }

    let mut done = 0usize;
    let mut file_off = offset as usize;

    // Sector-aligned buffer for disk reads
    let mut sector_buf = [0u8; 512];

    while done < to_read {
        let block_index = file_off / 512;
        let block_offset = file_off % 512;
        let chunk = (512 - block_offset).min(to_read - done);

        startup::read_data_at_block(vnode.data_block + block_index as u32, &mut sector_buf);
        buf[done..done + chunk].copy_from_slice(&sector_buf[block_offset..block_offset + chunk]);

        done += chunk;
        file_off += chunk;
    }

    done as i32
}

/// Enumerate root directory by index. Returns None at end.
pub fn readdir(index: usize) -> Option<DirEntry> {
    let mut block: u32 = 0;
    let mut i = 0usize;
    loop {
        let entry = startup::tar_entry_at_block(block)?;
        if i == index {
            return Some(DirEntry {
                name: entry.name,
                name_len: entry.name_len,
                size: entry.size,
            });
        }
        i += 1;
        block = entry.next_block;
    }
}

// ============================================================================
// Global file table helpers
// ============================================================================

/// Allocate a slot in the global file table. Returns index or None.
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

/// Allocate a file descriptor in the thread's FD array.
/// Returns the fd number (>= FIRST_FD) or None.
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
    let vnode = match tar_open(path) {
        Some(v) => v,
        None => return -2, // ENOENT
    };

    let table_idx = match alloc_file_entry() {
        Some(i) => i,
        None => return -24, // EMFILE
    };

    let fds = &mut crate::thread::current().fds;
    let fd = match alloc_fd(fds) {
        Some(f) => f,
        None => return -24, // EMFILE
    };

    unsafe {
        FILE_TABLE[table_idx] = FileEntry {
            vnode,
            offset: 0,
            refcount: 1,
        };
    }
    fds[fd] = table_idx as i32;

    fd as i32
}

/// Read from an open file descriptor. Returns bytes read or negative error.
pub fn read(fd: i32, buf: &mut [u8]) -> i32 {
    let fds = &crate::thread::current().fds;
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9; // EBADF
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9; // EBADF
    }

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9; // EBADF
    }

    let n = tar_read(&entry.vnode, entry.offset, buf);
    if n > 0 {
        entry.offset += n as u32;
    }
    n
}

/// Read entire file contents via fd into a kernel buffer (ignores current offset).
/// Used by EXEC to load program files.
pub fn read_raw(fd: i32, buf: &mut [u8]) -> i32 {
    let fds = &crate::thread::current().fds;
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
    tar_read(&entry.vnode, entry.offset, buf)
}

/// Close a file descriptor. Returns 0 or negative error.
pub fn close(fd: i32) -> i32 {
    let fds = &mut crate::thread::current().fds;
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9; // EBADF
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9; // EBADF
    }

    fds[fd as usize] = -1;

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount > 0 {
        entry.refcount -= 1;
    }
    0
}

/// Seek on an open file descriptor.
/// whence: 0=SET, 1=CUR, 2=END
/// Returns new offset or negative error.
pub fn seek(fd: i32, offset: i32, whence: i32) -> i32 {
    let fds = &crate::thread::current().fds;
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 {
        return -9; // EBADF
    }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 {
        return -9; // EBADF
    }

    let entry = unsafe { &mut FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 {
        return -9; // EBADF
    }

    let new_offset = match whence {
        0 => offset as i64,                                  // SEEK_SET
        1 => entry.offset as i64 + offset as i64,           // SEEK_CUR
        2 => entry.vnode.size as i64 + offset as i64,       // SEEK_END
        _ => return -22, // EINVAL
    };

    if new_offset < 0 {
        return -22; // EINVAL
    }

    entry.offset = new_offset as u32;
    entry.offset as i32
}

/// Duplicate all FDs from src into dst (for fork). Bumps refcounts.
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

/// Close all FDs in the given array. Decrements refcounts.
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
