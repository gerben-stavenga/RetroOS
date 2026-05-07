//! Shared exec primitives — file loading, format detection, thread init dispatch.
//!
//! This is the kernel's single exec entry point. Personality-specific
//! initialization (Linux user stack, DOS IVT/COM loading) lives in the
//! respective personality modules, called from here via fan-out.

extern crate alloc;

use alloc::vec::Vec;
use crate::kernel::vfs;

// ── File loading ────────────────────────────────────────────────────────

/// Load a file by path (resolved against cwd) into a heap buffer.
pub fn load_file(path: &[u8], cwd: &[u8]) -> Result<Vec<u8>, i32> {
    let mut path_buf = [0u8; 164];
    let resolved = resolve_path(path, cwd, &mut path_buf);
    load_file_resolved(resolved)
}

/// Load a file by already-resolved path into a heap buffer. Path is
/// expected to be canonical-case (Linux's `resolve_path` or DFS's
/// `to_vfs_open` produce one); the VFS itself is POSIX-strict.
pub fn load_file_resolved(path: &[u8]) -> Result<Vec<u8>, i32> {
    let handle = vfs::open_to_handle(path);
    if handle < 0 { return Err(2); } // ENOENT
    let size = vfs::file_size_by_handle(handle) as usize;
    if size == 0 { vfs::close_vfs_handle(handle); return Err(2); }
    let mut buf = alloc::vec![0u8; size];
    vfs::read_by_handle(handle, &mut buf);
    vfs::close_vfs_handle(handle);
    Ok(buf)
}

// ── Format detection ────────────────────────────────────────────────────

/// Binary format detected from magic bytes and file extension.
pub enum BinaryFormat {
    Elf,
    MzExe,
    Com,
}

/// Detect binary format from magic bytes and path extension.
pub fn detect_format(data: &[u8], path: &[u8]) -> BinaryFormat {
    if data.len() >= 4 && data[0..4] == [0x7F, b'E', b'L', b'F'] {
        return BinaryFormat::Elf;
    }
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return BinaryFormat::MzExe;
    }
    if has_ext(path, b"EXE") {
        return BinaryFormat::MzExe;
    }
    BinaryFormat::Com
}

fn has_ext(path: &[u8], ext: &[u8; 3]) -> bool {
    path.len() >= 4 && path[path.len() - 4] == b'.'
        && path[path.len() - 3].to_ascii_uppercase() == ext[0]
        && path[path.len() - 2].to_ascii_uppercase() == ext[1]
        && path[path.len() - 1].to_ascii_uppercase() == ext[2]
}

// ── Thread init fan-out ─────────────────────────────────────────────────

/// Initialize a thread from a loaded binary. Detects format and fans out
/// to the right personality for thread setup.
///
/// - **ELF**: caller must have already cleaned the address space.
/// - **DOS**: address space setup (clean + low mem + IVT) is handled internally.
/// - `args` is used for ELF argv; ignored for DOS.
/// - `parent_env_data` is the parent DOS env snapshot (DOS-only path); pass
///   None for initial loads or non-DOS execs.
/// - `parent_cwd` is the parent's cwd in VFS form; used to seed DFS for DOS
///   (ignored by ELF, which preserves the caller's LinuxState in-place).
pub fn init_thread(tid: usize, data: &[u8], path: &[u8], args: &[Vec<u8>], cmdtail: &[u8], parent_env_data: Option<&[u8]>, parent_cwd: &[u8]) -> Result<(), i32> {
    match detect_format(data, path) {
        BinaryFormat::Elf => {
            crate::kernel::linux::exec_elf_into(tid, data, args)
        }
        fmt => {
            let is_exe = matches!(fmt, BinaryFormat::MzExe);
            crate::kernel::dos::exec_dos_into(tid, data, is_exe, path, cmdtail, parent_env_data, parent_cwd);
            Ok(())
        }
    }
}

// ── Path utilities ──────────────────────────────────────────────────────

/// Resolve a path against a working directory. Absolute paths ignore cwd.
/// Normalizes `.`/`./` and `..`/`../` segments. Returns a slice of `buf`
/// holding the resolved path with no leading slash.
pub fn resolve_path<'a>(path: &[u8], cwd: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    // Build the raw concatenation first (cwd + path for relatives).
    let mut tmp = [0u8; 164];
    let mut tlen = 0;
    let raw: &[u8] = if !path.is_empty() && path[0] == b'/' {
        // Absolute — strip leading slashes.
        &path[path.iter().position(|&b| b != b'/').unwrap_or(path.len())..]
    } else {
        for &b in cwd {
            if tlen < tmp.len() { tmp[tlen] = b; tlen += 1; }
        }
        if tlen > 0 && tmp[tlen - 1] != b'/' && tlen < tmp.len() {
            tmp[tlen] = b'/'; tlen += 1;
        }
        for &b in path {
            if tlen < tmp.len() { tmp[tlen] = b; tlen += 1; }
        }
        &tmp[..tlen]
    };

    // Walk segments, skipping "." and applying ".." by popping.
    let mut pos = 0;
    let mut start = 0;
    while start < raw.len() {
        let end = raw[start..]
            .iter()
            .position(|&b| b == b'/')
            .map(|p| start + p)
            .unwrap_or(raw.len());
        let seg = &raw[start..end];
        if seg.is_empty() || seg == b"." {
            // skip
        } else if seg == b".." {
            // pop one component (find last '/' before pos-1)
            if pos > 0 {
                pos -= 1; // step over implicit trailing slash if any
                while pos > 0 && buf[pos - 1] != b'/' { pos -= 1; }
            }
        } else {
            for &b in seg {
                if pos < buf.len() { buf[pos] = b; pos += 1; }
            }
            if end < raw.len() && pos < buf.len() {
                buf[pos] = b'/'; pos += 1;
            }
        }
        start = end + 1;
    }
    // If the original path had a trailing slash, keep it; otherwise strip.
    let trailing = !raw.is_empty() && raw.last() == Some(&b'/');
    if !trailing && pos > 0 && buf[pos - 1] == b'/' {
        pos -= 1;
    }
    &buf[..pos]
}
