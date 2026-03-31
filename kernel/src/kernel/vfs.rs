//! Virtual Filesystem layer
//!
//! Provides file open/read/close/seek via a global file table.
//! Thread FD arrays index into this table. FDs 0/1/2 are reserved
//! for stdin/stdout/stderr and handled directly in syscall handlers.

use crate::kernel::startup;

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
    pub is_dir: bool,
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

/// Resolve a path relative to the current working directory.
/// Strips DOS prefix, normalizes slashes, prepends cwd for relative paths.
/// Paths that had a drive prefix (C:\...) are treated as absolute (no cwd prepend).
/// Returns the full TAR path in `buf`.
fn resolve_path<'a>(path: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    // Detect if path has a drive letter (absolute DOS path)
    let has_drive = path.len() >= 2 && path[1] == b':' && path[0].is_ascii_alphabetic();
    let stripped = strip_dos_prefix(path);

    let len = if stripped.is_empty() {
        0
    } else {
        let mut pos = 0;
        // Only prepend cwd for relative paths (no drive prefix)
        if !has_drive {
            let cwd = crate::kernel::thread::current().cwd_str();
            for &b in cwd {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
        }
        // Copy the path, normalizing backslashes
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
/// Strips DOS prefix, normalizes backslashes, prepends cwd.
pub fn resolve<'a>(path: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    resolve_path(path, buf)
}

/// Walk the TAR archive looking for `path`. Returns a Vnode on match.
/// Resolves relative to cwd, strips DOS path prefixes, case-insensitive.
fn tar_open(path: &[u8]) -> Option<Vnode> {
    let mut buf = [0u8; 164];
    let full_path = resolve_path(path, &mut buf);
    let mut block: u32 = 0;
    loop {
        let entry = startup::tar_entry_at_block(block)?;
        let name = &entry.name[..entry.name_len];
        if eq_ignore_case(name, full_path) {
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

/// Check if a TAR entry name is in the given directory.
/// Returns the basename (part after the directory prefix) if it matches,
/// or None if it's not in this directory or is in a deeper subdirectory.
fn entry_in_dir<'a>(entry_name: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    // dir is "" for root or "WOLF3D/" for a subdirectory
    if entry_name.len() <= dir.len() {
        return None;
    }
    // Check prefix matches (case-insensitive)
    if !dir.is_empty() {
        if entry_name.len() < dir.len() { return None; }
        let prefix = &entry_name[..dir.len()];
        if !eq_ignore_case(prefix, dir) { return None; }
    }
    let rest = &entry_name[dir.len()..];
    // Skip if it's in a deeper subdirectory (contains '/')
    if rest.iter().any(|&b| b == b'/') {
        return None;
    }
    Some(rest)
}

/// Enumerate current directory by index. Returns directories first, then files.
/// Returns None at end.
pub fn readdir(index: usize) -> Option<DirEntry> {
    let cwd = crate::kernel::thread::current().cwd_str();

    // Phase 1: collect unique subdirectory names
    let mut dirs: [[u8; 64]; 32] = [[0; 64]; 32];
    let mut dir_lens: [usize; 32] = [0; 32];
    let mut dir_count = 0usize;
    let mut block: u32 = 0;
    loop {
        let entry = match startup::tar_entry_at_block(block) {
            Some(e) => e,
            None => break,
        };
        let name = &entry.name[..entry.name_len];
        if name.len() > cwd.len() {
            let prefix = &name[..cwd.len()];
            if cwd.is_empty() || eq_ignore_case(prefix, cwd) {
                let rest = &name[cwd.len()..];
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

    // Return directory entry if index falls in directory range
    if index < dir_count {
        let len = dir_lens[index];
        let mut de = DirEntry {
            name: [0; 100],
            name_len: len,
            size: 0,
            is_dir: true,
        };
        de.name[..len].copy_from_slice(&dirs[index][..len]);
        return Some(de);
    }

    // Phase 2: enumerate files (index offset by dir_count)
    let file_idx = index - dir_count;
    block = 0;
    let mut i = 0usize;
    loop {
        let entry = startup::tar_entry_at_block(block)?;
        let name = &entry.name[..entry.name_len];
        if let Some(basename) = entry_in_dir(name, cwd) {
            if i == file_idx {
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len: basename.len(),
                    size: entry.size,
                    is_dir: false,
                };
                de.name[..basename.len()].copy_from_slice(basename);
                return Some(de);
            }
            i += 1;
        }
        block = entry.next_block;
    }
}

/// Change current directory. Path can be relative or absolute.
/// Returns 0 on success, negative error on failure.
pub fn chdir(path: &[u8]) -> i32 {
    let stripped = strip_dos_prefix(path);

    // Handle ".." — go up one level
    if stripped == b".." {
        let t = crate::kernel::thread::current();
        let cwd = t.cwd_str();
        if cwd.is_empty() { return 0; } // already at root
        // Remove trailing slash, then find the previous slash
        let without_slash = &cwd[..cwd.len().saturating_sub(1)];
        let new_len = match without_slash.iter().rposition(|&b| b == b'/') {
            Some(pos) => pos + 1, // keep the slash
            None => 0,            // back to root
        };
        t.cwd_len = new_len;
        return 0;
    }

    // Handle "\" or "/" — go to root
    if stripped.is_empty() || stripped == b"/" || stripped == b"\\" {
        let t = crate::kernel::thread::current();
        t.cwd_len = 0;
        return 0;
    }

    // Build the new directory path and verify it exists in the TAR
    let mut new_cwd = [0u8; 64];
    let mut pos = 0;

    // Start from cwd for relative paths
    let t = crate::kernel::thread::current();
    let cwd = t.cwd_str();
    for &b in cwd {
        if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
    }
    // Append the new directory name, normalizing backslashes
    for &b in stripped {
        if pos < new_cwd.len() {
            new_cwd[pos] = if b == b'\\' { b'/' } else { b };
            pos += 1;
        }
    }
    // Ensure trailing slash
    if pos > 0 && new_cwd[pos - 1] != b'/' {
        if pos < new_cwd.len() { new_cwd[pos] = b'/'; pos += 1; }
    }

    // Verify the directory exists: check if any TAR entry starts with this prefix
    let prefix = &new_cwd[..pos];
    let mut block: u32 = 0;
    let found = loop {
        match startup::tar_entry_at_block(block) {
            Some(entry) => {
                let name = &entry.name[..entry.name_len];
                if name.len() >= prefix.len() && eq_ignore_case(&name[..prefix.len()], prefix) {
                    break true;
                }
                block = entry.next_block;
            }
            None => break false,
        }
    };

    if !found {
        return -2; // ENOENT
    }

    t.set_cwd(&new_cwd[..pos]);
    0
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

    let fds = &mut crate::kernel::thread::current().fds;
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
    let fds = &crate::kernel::thread::current().fds;
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
    tar_read(&entry.vnode, entry.offset, buf)
}

/// Close a file descriptor. Returns 0 or negative error.
pub fn close(fd: i32) -> i32 {
    let fds = &mut crate::kernel::thread::current().fds;
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

/// Get the size of an open file descriptor. Returns 0 on error.
pub fn file_size(fd: i32) -> u32 {
    let fds = &crate::kernel::thread::current().fds;
    if fd < FIRST_FD as i32 || fd >= MAX_FDS as i32 { return 0; }
    let table_idx = fds[fd as usize];
    if table_idx < 0 || table_idx >= MAX_OPEN_FILES as i32 { return 0; }
    let entry = unsafe { &FILE_TABLE[table_idx as usize] };
    if entry.refcount == 0 { return 0; }
    entry.vnode.size
}

/// Seek on an open file descriptor.
/// whence: 0=SET, 1=CUR, 2=END
/// Returns new offset or negative error.
pub fn seek(fd: i32, offset: i32, whence: i32) -> i32 {
    let fds = &crate::kernel::thread::current().fds;
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
