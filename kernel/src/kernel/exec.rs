//! Shared exec primitives — file loading, format detection, thread init dispatch.
//!
//! This is the kernel's single exec entry point. Personality-specific
//! initialization (Linux user stack, DOS IVT/COM loading) lives in the
//! respective personality modules, called from here via fan-out.

extern crate alloc;

use alloc::vec::Vec;

/// Device ownership supplied by the process-creation path. Binary detection
/// and device construction are deliberately separate: DOS fork hands in its
/// cloned VGA, while a non-DOS image must not carry one at all.
pub enum ExecVga {
    None,
    Dos(crate::kernel::bios_display::DosVideo),
}
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryFormat {
    Elf,
    Lx,
    Ne,
    Pe,
    MzExe,
    Com,
}

/// Detect binary format from magic bytes and path extension.
pub fn detect_format(data: &[u8], path: &[u8]) -> BinaryFormat {
    if data.len() >= 4 && data[0..4] == [0x7F, b'E', b'L', b'F'] {
        return BinaryFormat::Elf;
    }
    if is_lx(data) {
        return BinaryFormat::Lx;
    }
    if crate::kernel::windows::ne::is_windows_ne(data) {
        return BinaryFormat::Ne;
    }
    if is_pe(data) {
        return BinaryFormat::Pe;
    }
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return BinaryFormat::MzExe;
    }
    if has_ext(path, b"EXE") {
        return BinaryFormat::MzExe;
    }
    BinaryFormat::Com
}

/// Select the half of a dual DOS/Windows executable that DOS would run.
///
/// Some executables contain a complete MZ program followed by an aligned PE
/// image.  COMANCHE.EXE is one: its DOS half launches C1.EXE, while its PE half
/// is a Windows launcher.  A conventional PE stub overlaps the PE headers in
/// the file extent declared by its MZ header; a genuine dual-mode executable's
/// declared MZ image ends before the secondary header begins.
pub fn detect_format_for_dos(data: &[u8], path: &[u8]) -> BinaryFormat {
    let format = detect_format(data, path);
    if format == BinaryFormat::Pe && has_complete_mz_image(data) {
        BinaryFormat::MzExe
    } else {
        format
    }
}

fn has_complete_mz_image(data: &[u8]) -> bool {
    if data.get(..2) != Some(b"MZ") || data.len() < 0x40 {
        return false;
    }
    let word = |at| u16::from_le_bytes([data[at], data[at + 1]]) as usize;
    let last_page = word(2);
    let pages = word(4);
    let header_bytes = word(8) * 16;
    let secondary = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let Some(image_bytes) = pages.checked_sub(1)
        .and_then(|whole| whole.checked_mul(512))
        .and_then(|whole| whole.checked_add(if last_page == 0 { 512 } else { last_page }))
    else {
        return false;
    };
    header_bytes < image_bytes && image_bytes <= secondary && image_bytes <= data.len()
}

fn is_lx(data: &[u8]) -> bool {
    if data.get(0..2) == Some(b"LX") { return true; }
    if data.get(0..2) != Some(b"MZ") || data.len() < 0x40 { return false; }
    let at = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(at..at.saturating_add(2)) == Some(b"LX")
}

fn is_pe(data: &[u8]) -> bool {
    crate::kernel::windows::pe::Image::parse(data)
        .is_ok_and(|image| image.is_windows_application())
}

#[cfg(test)]
mod tests {
    use super::{BinaryFormat, detect_format, detect_format_for_dos};
    use alloc::vec;

    fn mz_pe(subsystem: u16) -> alloc::vec::Vec<u8> {
        let mut data = vec![0; 256];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(&0x14cu16.to_le_bytes());
        data[84..86].copy_from_slice(&96u16.to_le_bytes());
        let optional = 88;
        data[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        data[optional + 28..optional + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        data[optional + 32..optional + 36].copy_from_slice(&4096u32.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&4096u32.to_le_bytes());
        data[optional + 60..optional + 64].copy_from_slice(&256u32.to_le_bytes());
        data[optional + 68..optional + 70].copy_from_slice(&subsystem.to_le_bytes());
        data
    }

    #[test]
    fn only_windows_subsystems_select_the_native_pe_loader() {
        assert_eq!(detect_format(&mz_pe(2), b"WINDOWS.EXE"), BinaryFormat::Pe);
        assert_eq!(detect_format(&mz_pe(3), b"CONSOLE.EXE"), BinaryFormat::Pe);
        assert_eq!(
            detect_format(&mz_pe(0), b"DOSGAME.EXE"),
            BinaryFormat::MzExe
        );
    }

    #[test]
    fn dos_launch_uses_complete_mz_half_of_dual_mode_pe() {
        let mut data = vec![0; 512];
        data[..2].copy_from_slice(b"MZ");
        data[2..4].copy_from_slice(&96u16.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[8..10].copy_from_slice(&4u16.to_le_bytes());
        data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        data[148..150].copy_from_slice(&96u16.to_le_bytes());
        let optional = 152;
        data[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        data[optional + 28..optional + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        data[optional + 32..optional + 36].copy_from_slice(&4096u32.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&4096u32.to_le_bytes());
        data[optional + 60..optional + 64].copy_from_slice(&256u32.to_le_bytes());
        data[optional + 68..optional + 70].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(detect_format(&data, b"DUAL.EXE"), BinaryFormat::Pe);
        assert_eq!(detect_format_for_dos(&data, b"DUAL.EXE"), BinaryFormat::MzExe);
    }
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
/// **Ownership note**: every byte-buffer parameter is taken by value
/// (`Vec<u8>`), not by reference. Internally we tear down and rebuild the
/// caller's address space, so a `&[u8]` borrowing user memory would dangle.
/// Owning Vecs makes that bug impossible to express -- the caller must hand
/// us kernel-heap data.
///
/// - **ELF**: caller must have already cleaned the address space.
/// - **DOS**: address space setup (clean + low mem + IVT) is handled internally.
/// - `path` is the load path, used only for format detection (the .EXE
///   extension fallback). It is kept separate from `args` because POSIX lets
///   `argv[0]` differ from the executable path — busybox/toybox are launched
///   as `/bin/busybox` with `argv[0]` = the applet name (`sh`, `ls`, …) and
///   dispatch on it. Forcing `args[0] = path` here used to break that.
/// - `args` is the full argv; `args[0]` is argv[0]. Subsequent entries are
///   extra argv for ELF; ignored for DOS.
/// - `parent_env_data` is the parent DOS env snapshot (DOS-only path);
///   pass `Vec::new()` for non-DOS execs or initial loads with no parent.
/// - `parent_cwd` is the parent's cwd in VFS form; used to seed DFS for DOS
///   (ignored by ELF, which preserves the caller's LinuxState in-place).
#[allow(clippy::too_many_arguments)]
pub fn init_thread<A: crate::Arch>(machine: &mut A, threads: &mut [crate::kernel::thread::Thread<A>], tid: usize, data: Vec<u8>, path: &[u8], args: Vec<Vec<u8>>, cmdtail: Vec<u8>, parent_env_data: Vec<u8>, parent_cwd: Vec<u8>, personality_name: Option<crate::kernel::thread::PersonalityName>, viopl: u8, exec_vga: ExecVga) -> Result<(), i32> {
    // Name the thread for the F12 switch picker — the one path every launch
    // (boot init and fork-exec) flows through, so every task is named.
    threads[tid].kernel.set_comm(path);
    let format = if personality_name == Some(crate::kernel::thread::PersonalityName::Dos) {
        detect_format_for_dos(&data, path)
    } else {
        detect_format(&data, path)
    };
    match format {
        BinaryFormat::Elf if matches!(exec_vga, ExecVga::None) => {
            crate::kernel::linux::exec_elf_into(machine, threads, tid, &data, path, &args)
        }
        BinaryFormat::Elf => Err(-8),
        BinaryFormat::Lx if matches!(exec_vga, ExecVga::None) => {
            crate::kernel::os2::exec_lx_into(
                machine, threads, tid, data, path, &parent_cwd, personality_name)
        }
        BinaryFormat::Lx => Err(-8),
        BinaryFormat::Ne if matches!(exec_vga, ExecVga::None) => {
            crate::kernel::windows::exec_ne_into(
                machine, threads, tid, data, path, &parent_cwd, personality_name)
        }
        BinaryFormat::Ne => Err(-8),
        BinaryFormat::Pe if matches!(exec_vga, ExecVga::None) => {
            crate::kernel::windows::exec_pe_into(
                machine, threads, tid, data, path, &parent_cwd, personality_name)
        }
        BinaryFormat::Pe => Err(-8),
        fmt => {
            let ExecVga::Dos(vga) = exec_vga else { return Err(-8) };
            let is_exe = matches!(fmt, BinaryFormat::MzExe);
            // `args[0]` is already a DOS path when the launcher was DOS
            // (personality_name == Some(Dos)); otherwise it's VFS and exec_dos_into
            // dosifies it (the cross-personality / boot fallback).
            let args0_is_dos = personality_name == Some(crate::kernel::thread::PersonalityName::Dos);
            crate::kernel::dos::exec_dos_into(machine, threads, tid, data, is_exe, args, cmdtail, parent_env_data, parent_cwd, args0_is_dos, viopl, vga);
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
