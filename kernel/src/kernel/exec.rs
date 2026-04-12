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

/// Load a file by already-resolved path into a heap buffer.
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
pub fn init_thread(tid: usize, data: &[u8], path: &[u8], args: &[Vec<u8>]) -> Result<(), i32> {
    match detect_format(data, path) {
        BinaryFormat::Elf => {
            crate::kernel::linux::exec_elf_into(tid, data, args)
        }
        fmt => {
            let is_exe = matches!(fmt, BinaryFormat::MzExe);
            crate::kernel::dos::exec_dos_into(tid, data, is_exe, path);
            Ok(())
        }
    }
}

// ── Path utilities ──────────────────────────────────────────────────────

/// Resolve a path against a working directory. Absolute paths ignore cwd.
pub fn resolve_path<'a>(path: &[u8], cwd: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    let mut pos = 0;
    if !path.is_empty() && path[0] == b'/' {
        let trimmed = &path[path.iter().position(|&b| b != b'/').unwrap_or(path.len())..];
        for &b in trimmed {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    } else {
        for &b in cwd {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
        for &b in path {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    }
    &buf[..pos]
}
