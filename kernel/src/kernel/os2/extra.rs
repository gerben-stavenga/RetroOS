//! OS/2 filesystem and mixed 16/32-bit console services.
use super::*;
use crate::kernel::vfs;

pub(super) struct Find {
    pub handle: u32,
    pub entries: Vec<vfs::DirEntry>,
    pub next: usize,
    pub level: u32,
}
pub(super) struct Video {
    pub cols: u16,
    pub rows: u16,
    pub cells: Vec<u8>,
    pub x: u16,
    pub y: u16,
    pub cursor: [u16; 4],
    pub buffer: u32,
    pub selector: u16,
    pub hwnd: u32,
}
impl Video {
    pub fn new() -> Self {
        Self {
            cols: 80,
            rows: 25,
            cells: vec![0; 4000],
            x: 0,
            y: 0,
            cursor: [14, 15, 1, 0],
            buffer: 0,
            selector: 0,
            hwnd: 0,
        }
    }
}
pub(super) fn shift_state() -> u16 {
    use crate::kernel::keyboard::key_down;
    u16::from(key_down(0x36))
        | (u16::from(key_down(0x2a)) << 1)
        | (u16::from(key_down(0x1d)) << 2)
        | (u16::from(key_down(0x38)) << 3)
        | (((crate::kernel::keyboard::control_state() >> 6) as u16 & 1) << 4)
        | (((crate::kernel::keyboard::control_state() >> 5) as u16 & 1) << 5)
        | (((crate::kernel::keyboard::control_state() >> 7) as u16 & 1) << 6)
}
fn word<A: crate::Arch>(m: &A, s: &Os2State, r: &Regs, off: usize) -> u16 {
    m.read::<u16>(stack_linear(s, r) + 4 + off)
}
fn pointer<A: crate::Arch>(m: &A, s: &Os2State, r: &Regs, off: usize) -> usize {
    selector_base(s, word(m, s, r, off + 2))
        .unwrap_or(0)
        .wrapping_add(word(m, s, r, off) as u32) as usize
}
pub(super) fn kbd<A: crate::Arch>(m: &mut A, s: &mut Os2State, r: &Regs, ordinal: u16) -> u32 {
    let out = pointer(m, s, r, if ordinal == 4 { 4 } else { 2 });
    match ordinal {
        10 => {
            m.write::<u16>(out, 10);
            m.write::<u16>(out + 2, s.kbd_mask);
            m.write::<u16>(out + 4, 13);
            m.write::<u16>(out + 6, 0);
            m.write::<u16>(out + 8, shift_state());
        }
        11 => {
            s.kbd_mask = m.read::<u16>(out + 2);
        }
        4 | 22 => {
            if ordinal == 4 && s.keys.is_empty() && word(m, s, r, 2) == 0 {
                s.wait_key = true;
                return u32::MAX;
            }
            s.wait_key = false;
            m.zero(out, 10);
            if let Some(&(ascii, scan, shift, milliseconds)) = s.keys.first() {
                m.write::<u8>(out, ascii);
                m.write::<u8>(out + 1, scan);
                // OS/2 requires both the extended-code status bit and a
                // 00/E0 character for scan-code keys (including Alt chords).
                m.write::<u8>(out + 2, 0x40 | if ascii == 0 || ascii == 0xe0 { 2 } else { 0 });
                m.write::<u16>(out + 4, shift);
                m.write::<u32>(out + 6, milliseconds);
                if ordinal == 4 {
                    s.keys.remove(0);
                }
            } else {
                m.write::<u16>(out + 4, shift_state());
            }
        }
        _ => return ERROR_INVALID_FUNCTION,
    }
    NO_ERROR
}
fn paint(s: &mut Os2State) {
    let width = s.video.cols as u32 * 8;
    let height = s.video.rows as u32 * 16;
    if s.video.hwnd == 0 {
        s.video.hwnd = create_pm_window(s, b"", 0, width, height, true);
    }
    let window = s
        .pm_windows
        .iter_mut()
        .find(|w| w.hwnd == s.video.hwnd)
        .unwrap();
    window.width = width;
    window.height = height;
    window
        .pixels
        .resize(width as usize * height as usize * 4, 0);
    const COLORS: [u32; 16] = [
        0, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555,
        0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
    ];
    let page = lib::codepage::current_codepage();
    for y in 0..s.video.rows as usize {
        for x in 0..s.video.cols as usize {
            let at = (y * s.video.cols as usize + x) * 2;
            let character = page.decode_glyph(s.video.cells[at]);
            let attr = s.video.cells[at + 1];
            let glyph = crate::kernel::text::glyph16(character);
            for (row, &bits) in glyph.iter().enumerate() {
                for col in 0..8 {
                    let color = COLORS[if bits & (0x80 >> col) != 0 {
                        (attr & 15) as usize
                    } else {
                        (attr >> 4) as usize
                    }];
                    let pixel = ((y * 16 + row) * width as usize + x * 8 + col) * 4;
                    window.pixels[pixel..pixel + 4].copy_from_slice(&color.to_le_bytes());
                }
            }
        }
    }
    s.pm_dirty = true;
    crate::term::term().blit_cells(
        s.video.cols as usize,
        s.video.rows as usize,
        &s.video.cells,
        s.video.x as usize,
        s.video.y as usize,
    );
    crate::kernel::term::mark_dirty();
}
fn video<A: crate::Arch>(m: &mut A, s: &mut Os2State, r: &Regs, ordinal: u16) -> u32 {
    let out = pointer(m, s, r, 2);
    match ordinal {
        1 => {}
        9 => {
            m.write::<u16>(out, s.video.x);
            let row = pointer(m, s, r, 6);
            m.write::<u16>(row, s.video.y);
        }
        15 => {
            s.video.x = word(m, s, r, 2);
            s.video.y = word(m, s, r, 4);
            paint(s);
        }
        21 => {
            let cb = m.read::<u16>(out) as usize;
            let mut bytes = [0u8; 34];
            bytes[..2].copy_from_slice(&34u16.to_le_bytes());
            bytes[2] = 1;
            bytes[3] = 4;
            bytes[4..6].copy_from_slice(&s.video.cols.to_le_bytes());
            bytes[6..8].copy_from_slice(&s.video.rows.to_le_bytes());
            bytes[8..10].copy_from_slice(&(s.video.cols * 8).to_le_bytes());
            bytes[10..12].copy_from_slice(&(s.video.rows * 16).to_le_bytes());
            bytes[13] = 1;
            bytes[18..22].copy_from_slice(&(s.video.cells.len() as u32).to_le_bytes());
            m.copy_to(out, &bytes[..cb.min(bytes.len())]);
        }
        22 => {
            let cols = m.read::<u16>(out + 4);
            let rows = m.read::<u16>(out + 6);
            if !(1..=160).contains(&cols) || !(1..=100).contains(&rows) {
                return ERROR_INVALID_PARAMETER;
            }
            s.video.cols = cols;
            s.video.rows = rows;
            s.video.cells.resize(cols as usize * rows as usize * 2, 0);
            paint(s);
        }
        27 => {
            for (i, &value) in s.video.cursor.iter().enumerate() {
                m.write::<u16>(out + i * 2, value);
            }
        }
        32 => {
            for i in 0..4 {
                s.video.cursor[i] = m.read::<u16>(out + i * 2);
            }
        }
        31 => {
            if s.video.buffer == 0 {
                let base = s.heap_next;
                s.heap_next += 0x10000;
                m.zero(base as usize, 0x10000);
                m.set_page_flags(base as usize / 4096, 16, true, false);
                s.video.buffer = base;
                s.video.selector = push_descriptor(&mut s.ldt, base, 65536, false, false);
                s.on_resume(m);
            }
            let address = pointer(m, s, r, 6);
            m.write::<u32>(address, (s.video.selector as u32) << 16);
            m.write::<u16>(out, s.video.cells.len() as u16);
        }
        43 => {
            let off = word(m, s, r, 4) as usize;
            let length = word(m, s, r, 2) as usize;
            if off + length > s.video.cells.len() {
                return ERROR_INVALID_PARAMETER;
            }
            m.copy_from(
                s.video.buffer as usize + off,
                &mut s.video.cells[off..off + length],
            );
            paint(s);
        }
        46 => {
            let out = pointer(m, s, r, 2);
            let cb = m.read::<u16>(out) as usize;
            let mut data = [0u8; 32];
            data[..2].copy_from_slice(&32u16.to_le_bytes());
            data[2..4].copy_from_slice(&3u16.to_le_bytes());
            data[4..6].copy_from_slice(&3u16.to_le_bytes());
            data[6..10].copy_from_slice(&262144u32.to_le_bytes());
            m.copy_to(out, &data[..cb.min(32)]);
        }
        11 => {
            let status = pointer(m, s, r, 2);
            m.write::<u16>(status, 0);
        }
        19 => {
            let n = word(m, s, r, 2) as usize;
            let text = pointer(m, s, r, 4);
            let mut bytes = vec![0; n];
            m.copy_from(text, &mut bytes);
            for b in bytes {
                crate::term::putchar(b);
            }
            crate::kernel::term::mark_dirty();
        }
        49 | 51 => return ERROR_INVALID_FUNCTION,
        26 => {
            let col = word(m, s, r, 2) as usize;
            let row = word(m, s, r, 4) as usize;
            let count = word(m, s, r, 6) as usize;
            let attribute = m.read::<u8>(pointer(m, s, r, 8));
            let start = row * s.video.cols as usize + col;
            let end = (start + count).min(s.video.cells.len() / 2);
            if start > end {
                return 87;
            }
            for cell in start..end {
                s.video.cells[cell * 2 + 1] = attribute;
            }
            if s.video.buffer != 0 {
                m.copy_to(s.video.buffer as usize, &s.video.cells);
            }
            paint(s);
        }
        7 => {
            let fill = pointer(m, s, r, 2);
            let cell = m.read::<u16>(fill).to_le_bytes();
            let count = word(m, s, r, 6) as usize;
            let right = word(m, s, r, 8).min(s.video.cols - 1) as usize;
            let bottom = word(m, s, r, 10).min(s.video.rows - 1) as usize;
            let left = word(m, s, r, 12) as usize;
            let top = word(m, s, r, 14) as usize;
            if left > right || top > bottom {
                return 87;
            }
            let cols = s.video.cols as usize;
            for row in top..=bottom {
                for col in left..=right {
                    let dest = (row * cols + col) * 2;
                    if row + count <= bottom {
                        let source = ((row + count) * cols + col) * 2;
                        s.video.cells.copy_within(source..source + 2, dest);
                    } else {
                        s.video.cells[dest..dest + 2].copy_from_slice(&cell);
                    }
                }
            }
            if s.video.buffer != 0 {
                m.copy_to(s.video.buffer as usize, &s.video.cells);
            }
            paint(s);
        }
        _ => return ERROR_INVALID_FUNCTION,
    }
    NO_ERROR
}
pub(super) fn alloc_shared<A: crate::Arch>(m: &mut A, s: &mut Os2State, r: &Regs) -> u32 {
    let name = arg32(m, r, 1);
    let result = alloc_os2_memory(m, s, arg32(m, r, 0) as usize, arg32(m, r, 2));
    if result == 0 && name != 0 && let Ok(mut name) = c_string(m, name) {
        name.make_ascii_uppercase();
        s.shared
            .push((name, m.read::<u32>(arg32(m, r, 0) as usize)));
    }
    result
}
pub(super) fn get_shared<A: crate::Arch>(m: &mut A, s: &Os2State, r: &Regs) -> u32 {
    let Ok(mut name) = c_string(m, arg32(m, r, 1)) else {
        return ERROR_INVALID_PARAMETER;
    };
    name.make_ascii_uppercase();
    let Some((_, address)) = s.shared.iter().find(|(n, _)| *n == name) else {
        return ERROR_FILE_NOT_FOUND;
    };
    m.write::<u32>(arg32(m, r, 0) as usize, *address);
    NO_ERROR
}
fn copy_string<A: crate::Arch>(m: &mut A, out: usize, cap: usize, bytes: &[u8]) -> u32 {
    let bytes = crate::kernel::text::Encoding::oem().encode(&alloc::string::String::from_utf8_lossy(bytes), b'?').0;
    if cap <= bytes.len() { return 111; }
    m.copy_to(out, &bytes);
    m.write::<u8>(out + bytes.len(), 0);
    NO_ERROR
}
/// Convert a VFS path to a path relative to C:. C_ROOT has a trailing slash,
/// while canonical directory paths omit it, including at the drive root.
fn drive_relative(path: &[u8], root: &[u8]) -> Vec<u8> {
    let root_dir = root.strip_suffix(b"/").unwrap_or(root);
    let relative = if path == root_dir {
        &b""[..]
    } else {
        path.strip_prefix(root_dir)
            .filter(|rest| root_dir.is_empty() || rest.starts_with(b"/"))
            .unwrap_or(path)
    };
    relative.iter().copied().skip_while(|&b| b == b'/')
        .map(|b| if b == b'/' { b'\\' } else { b }).collect()
}

pub(super) fn current_dos(s: &Os2State) -> Vec<u8> {
    drive_relative(s.cwd_str(), crate::kernel::dos::c_root())
}

#[cfg(test)]
mod path_tests {
    use super::drive_relative;

    #[test]
    fn drive_root_does_not_expose_its_vfs_mount_prefix() {
        assert_eq!(drive_relative(b"home/retroos", b"home/retroos/"), b"");
        assert_eq!(drive_relative(b"home/retroos/", b"home/retroos/"), b"");
        assert_eq!(drive_relative(b"home/retroos/NDN-OS32", b"home/retroos/"), br"NDN-OS32");
        assert_eq!(drive_relative(b"home/retroos/NDN-OS32/plugins", b"home/retroos/"), br"NDN-OS32\plugins");
        assert_eq!(drive_relative(b"home/retroos-other", b"home/retroos/"), br"home\retroos-other");
        assert_eq!(drive_relative(b"OS2/APPS", b""), br"OS2\APPS");
    }
}

fn file_info<A: crate::Arch>(
    m: &mut A,
    out: usize,
    cap: usize,
    level: u32,
    size: u32,
    attr: u32,
) -> u32 {
    let need = match level {
        1 => 24,
        2 => 28,
        11 => 32,
        12 => 36,
        _ => return 124,
    };
    if cap < need {
        return 111;
    }
    m.zero(out, need);
    let wide = level >= 11;
    let attr_offset = if wide { 28 } else { 20 };
    let allocated = u64::from(size).next_multiple_of(4096);
    if wide {
        m.write::<u64>(out + 12, u64::from(size));
        m.write::<u64>(out + 20, allocated);
    } else {
        m.write::<u32>(out + 12, size);
        m.write::<u32>(out + 16, allocated.min(u64::from(u32::MAX)) as u32);
    }
    m.write::<u32>(out + attr_offset, attr);
    if matches!(level, 2 | 12) {
        m.write::<u32>(out + attr_offset + 4, 4);
    }
    NO_ERROR
}
fn find_output<A: crate::Arch>(
    m: &mut A,
    find: &mut Find,
    out: usize,
    cap: usize,
    count: usize,
    actual: usize,
) -> u32 {
    let wide = find.level >= 11;
    let ea = matches!(find.level, 2 | 12);
    let attr_offset = if wide { 32 } else { 24 };
    let header = attr_offset + 5 + if ea { 4 } else { 0 };
    let mut used = 0;
    let mut written = 0;
    let mut previous = None;
    while written < count && find.next < find.entries.len() {
        let entry = &find.entries[find.next];
        let encoded = crate::kernel::text::Encoding::oem().encode(&alloc::string::String::from_utf8_lossy(&entry.name), b'?').0;
        let name = &encoded[..encoded.len().min(255)];
        let len = (header + name.len() + 1).next_multiple_of(4);
        if used + len > cap {
            break;
        }
        let dest = out + used;
        m.zero(dest, len);
        if let Some(previous) = previous {
            m.write::<u32>(previous, (dest - previous) as u32);
        }
        let allocated = u64::from(entry.size).next_multiple_of(4096);
        if wide {
            m.write::<u64>(dest + 16, u64::from(entry.size));
            m.write::<u64>(dest + 24, allocated);
        } else {
            m.write::<u32>(dest + 16, entry.size);
            m.write::<u32>(dest + 20, allocated.min(u64::from(u32::MAX)) as u32);
        }
        m.write::<u32>(
            dest + attr_offset,
            entry
                .dos_attributes
                .unwrap_or(if entry.is_dir { 16 } else { 32 }) as u32,
        );
        if ea {
            m.write::<u32>(dest + attr_offset + 4, 4);
        }
        m.write::<u8>(dest + header - 1, name.len() as u8);
        m.copy_to(dest + header, name);
        previous = Some(dest);
        used += len;
        written += 1;
        find.next += 1;
    }
    m.write::<u32>(actual, written as u32);
    if written != 0 {
        NO_ERROR
    } else if find.next >= find.entries.len() {
        18
    } else {
        111
    }
}
fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    crate::kernel::text::wildcard(pattern, name)
}
/// DosExecPgm uses two NUL-terminated argument strings (argv[0], then tail).
/// The shared launcher owns the address-space transition; no DOS stub is run
/// for a native PE/LX child.
pub(super) fn exec_program<A: crate::Arch>(m: &mut A, s: &mut Os2State, r: &Regs)
    -> Result<thread::KernelAction, u32> {
    let flags = arg32(m, r, 2);
    // Debug and asynchronous-result modes need DosWaitChild/trace support.
    if flags > 1 { return Err(ERROR_INVALID_FUNCTION); }
    let result_out = arg32(m, r, 5) as usize;
    if result_out == 0 { return Err(ERROR_INVALID_PARAMETER); }
    let name = c_string(m, arg32(m, r, 6))?;
    let path = os2_path(s, &name, false).or_else(|error| {
        if name.iter().any(|&b| matches!(b, b':' | b'/' | b'\\')) { return Err(error); }
        let path_value = s.environment.split(|&b| b == 0).find_map(|entry| {
            let eq = entry.iter().position(|&b| b == b'=')?;
            entry[..eq].eq_ignore_ascii_case(b"PATH").then_some(&entry[eq + 1..])
        }).unwrap_or(b"");
        for dir in path_value.split(|&b| b == b';').filter(|dir| !dir.is_empty()) {
            let mut candidate = dir.to_vec(); candidate.push(b'\\'); candidate.extend_from_slice(&name);
            if let Ok(path) = os2_path(s, &candidate, false) { return Ok(path); }
        }
        Err(error)
    }).inspect_err(|_error| {
        let out = arg32(m, r, 0) as usize;
        if out != 0 { let _ = copy_string(m, out, arg32(m, r, 1) as usize, &name); }
    })?;
    let args = arg32(m, r, 3);
    let tail = if args == 0 { Vec::new() } else {
        let first = raw_string(m, args)?;
        c_string(m, args.checked_add(first.len() as u32 + 1).ok_or(ERROR_INVALID_PARAMETER)?)?
    };
    let env_ptr = arg32(m, r, 4);
    let environment = if env_ptr == 0 { None } else {
        let mut env = Vec::new();
        for i in 0..4096 {
            let byte = m.read::<u8>(env_ptr as usize + i);
            env.push(byte);
            if env.len() >= 2 && env[env.len() - 2..] == [0, 0] { break; }
        }
        if !env.ends_with(&[0, 0]) { return Err(ERROR_INVALID_PARAMETER); }
        Some(crate::kernel::text::Encoding::oem().decode(&env, false).unwrap().into_bytes())
    };
    if path.len() > 164 || tail.len() > 127 { return Err(ERROR_INVALID_PARAMETER); }
    let mut path_buf = [0; 164]; path_buf[..path.len()].copy_from_slice(&path);
    let mut tail_buf = [0; 128]; tail_buf[..tail.len()].copy_from_slice(&tail);
    s.exec_process = Some(super::ExecProcess { result_out, synchronous: flags == 0, pid: 0, exit_code: None });
    s.exec_environment = environment;
    let out = arg32(m, r, 0) as usize;
    if out != 0 && arg32(m, r, 1) != 0 { m.write::<u8>(out, 0); }
    Ok(thread::KernelAction::ForkExec {
        path: path_buf, path_len: path.len(), cmdtail: tail_buf, cmdtail_len: tail.len(),
        cwd: [0; 164], cwd_len: 0, personality_name: None,
        policy: crate::kernel::dos::LaunchPolicy::default(),
        on_error: exec_error, on_success: exec_success,
    })
}

fn exec_error(regs: &mut Regs, error: i32) { regs.rax = error.unsigned_abs() as u64; }
fn exec_success(regs: &mut Regs, _tid: i32) { regs.rax = 0; }

fn search_path<A: crate::Arch>(m: &mut A, s: &Os2State, r: &Regs) -> u32 {
    let flags = arg32(m, r, 0);
    if flags & !7 != 0 { return ERROR_INVALID_PARAMETER; }
    let Ok(path) = c_string(m, arg32(m, r, 1)) else { return ERROR_INVALID_PARAMETER; };
    let Ok(file) = c_string(m, arg32(m, r, 2)) else { return ERROR_INVALID_PARAMETER; };
    let out = arg32(m, r, 3) as usize;
    let cap = arg32(m, r, 4) as usize;
    if out == 0 || cap == 0 { return ERROR_INVALID_PARAMETER; }
    let path = if flags & 2 != 0 {
        let value = s.environment.split(|&b| b == 0).find_map(|entry| {
            let equal = entry.iter().position(|&b| b == b'=')?;
            entry[..equal].eq_ignore_ascii_case(&path).then_some(&entry[equal + 1..])
        });
        let Some(value) = value else { return 203; }; // ERROR_ENVVAR_NOT_FOUND
        value
    } else { path.as_slice() };
    let cwd = current_dos(s);
    let paths = (flags & 1 != 0).then_some(&b""[..]).into_iter()
        .chain(path.split(|&b| b == b';'));
    for directory in paths {
        let mut candidate = directory.to_vec();
        if !candidate.is_empty() && !candidate.ends_with(b"\\") && !candidate.ends_with(b"/") {
            candidate.push(b'\\');
        }
        candidate.extend_from_slice(&file);
        let absolute = os2_absolute_path(&cwd, &candidate);
        if crate::kernel::dos::windows_abs_to_vfs(&absolute, false)
            .is_some_and(|path| vfs::stat(&path, true).is_some()) {
            return copy_string(m, out, cap, &absolute);
        }
    }
    ERROR_FILE_NOT_FOUND
}

pub(super) fn dispatch<A: crate::Arch>(
    m: &mut A,
    kt: &mut thread::KernelThread<A>,
    s: &mut Os2State,
    r: &mut Regs,
    api: Api,
) -> u32 {
    let a = |n| arg32(m, r, n);
    match api {
        Api::Base(127) => {
            let out = pointer(m, s, r, 0);
            m.write::<u32>(out, (m.free_page_count() * 4096).min(u32::MAX as usize) as u32);
            NO_ERROR
        }
        // Thread exports are present so clients can handle an unsupported
        // operation. Never report a fabricated TID or a successful kill.
        Api::Base(311) => 50, // ERROR_NOT_SUPPORTED
        Api::Base(111) => 309, // ERROR_INVALID_THREADID
        Api::Base(228) => search_path(m, s, r),
        Api::Base(272 | 989) => {
            let fd = a(0) as usize;
            if fd >= thread::MAX_FDS { return ERROR_INVALID_HANDLE; }
            let thread::FdKind::Vfs(handle) = kt.fds[fd] else { return ERROR_INVALID_HANDLE; };
            if api == Api::Base(989) && a(2) != 0 { return ERROR_INVALID_PARAMETER; }
            let result = vfs::resize_by_handle(handle, a(1));
            if result < 0 { os2_error(result) } else { NO_ERROR }
        }
        Api::Base(219) => {
            let attr_offset = match a(1) { 1 => 20, 11 => 28, _ => return 124 };
            if (a(3) as usize) < attr_offset + 4 { return 111; } // ERROR_BUFFER_OVERFLOW
            if a(4) & !0x10 != 0 { return ERROR_INVALID_PARAMETER; }
            let info = a(2) as usize;
            if info == 0 { return ERROR_INVALID_PARAMETER; }
            let Ok(raw) = c_string(m, a(0)) else { return ERROR_INVALID_PARAMETER; };
            let Ok(path) = os2_path(s, &raw, false) else { return ERROR_FILE_NOT_FOUND; };
            // VFS currently stores modification time, but cannot persist
            // creation/access times. Zero fields mean leave them unchanged.
            if m.read::<u32>(info) != 0 || m.read::<u32>(info + 4) != 0 { return 50; }
            let date = m.read::<u16>(info + 8);
            let time = m.read::<u16>(info + 10);
            let stamp = if date != 0 || time != 0 {
                let Some(stamp) = crate::kernel::dos::dos_to_unix_datetime(time, date) else {
                    return ERROR_INVALID_PARAMETER;
                };
                Some(stamp)
            } else { None };
            let attributes = m.read::<u32>(info + attr_offset);
            if attributes & !0x37 != 0 { return ERROR_INVALID_PARAMETER; }
            if let Some(stamp) = stamp {
                let handle = vfs::open_to_handle(&path);
                if handle < 0 { return os2_error(handle); }
                let mut fds = [thread::FdKind::None; thread::MAX_FDS];
                fds[0] = thread::FdKind::Vfs(handle);
                let result = vfs::set_handle_mtime(0, stamp, &fds);
                vfs::close_vfs_handle(handle);
                if result < 0 { return os2_error(result); }
            }
            let result = vfs::set_dos_attributes(&path, attributes as u8);
            if result < 0 { os2_error(result) } else { NO_ERROR }
        }
        Api::Kbd(n) => kbd(m, s, r, n),
        Api::Vio(n) => video(m, s, r, n),
        Api::Mou(17) => {
            let out = pointer(m, s, r, 0);
            m.write::<u16>(out, 1);
            NO_ERROR
        }
        Api::Mou(9 | 16 | 18 | 21 | 26) => NO_ERROR,
        Api::Mou(8 | 13 | 15 | 19) => {
            let out = pointer(m, s, r, 2);
            m.write::<u16>(out, if api == Api::Mou(8) { 2 } else { 0 });
            if matches!(api, Api::Mou(13 | 19)) {
                m.write::<u16>(out + 2, 0);
            }
            NO_ERROR
        }
        Api::Mou(20) => {
            let out = pointer(m, s, r, 6);
            m.zero(out, 10);
            232
        }
        Api::Base(318) => {
            let err = a(0) as usize;
            let cap = a(1) as usize;
            let name = a(2);
            let out = a(3) as usize;
            let Ok(name) = c_string(m, name) else {
                return 87;
            };
            match load_module(m, s, &name) {
                Ok(h) => {
                    m.write::<u32>(out, h);
                    NO_ERROR
                }
                Err(e) => {
                    let _ = copy_string(m, err, cap, &name);
                    if crate::kernel::startup::trace_enabled() {
                        crate::compact_println!(
                            "[os2-load] failed {} error={}",
                            core::str::from_utf8(&name).unwrap_or("?"),
                            e
                        );
                    }
                    e
                }
            }
        }
        Api::Base(322) => {
            if a(0) > 0 && a(0) as usize <= s.modules.len() {
                NO_ERROR
            } else {
                6
            }
        }
        Api::Base(284) => ERROR_INVALID_FUNCTION,
        Api::Base(212) => NO_ERROR,
        Api::Base(220) => {
            if a(0) == 3 {
                NO_ERROR
            } else {
                15
            }
        }
        Api::Base(275) => {
            let disk = a(0) as usize;
            let map = a(1) as usize;
            m.write::<u32>(disk, 3);
            m.write::<u32>(map, 4);
            NO_ERROR
        }
        Api::Base(274) => {
            let out = a(1) as usize;
            let len = a(2) as usize;
            let cap = m.read::<u32>(len) as usize;
            let path = current_dos(s);
            if crate::kernel::startup::trace_enabled() {
                crate::compact_println!("[os2-cwd] {}", core::str::from_utf8(&path).unwrap_or("?"));
            }
            let result = copy_string(m, out, cap, &path);
            let encoded_len = crate::kernel::text::Encoding::oem().encode(&alloc::string::String::from_utf8_lossy(&path), b'?').0.len();
            m.write::<u32>(len, encoded_len as u32 + 1);
            result
        }
        Api::Base(263) => {
            let h = a(0);
            let Some(i) = s.find.iter().position(|f| f.handle == h) else {
                return 6;
            };
            s.find.remove(i);
            NO_ERROR
        }
        Api::Base(264) => {
            let Ok(raw) = c_string(m, a(0)) else {
                return 87;
            };
            let handle = a(1) as usize;
            let attr = a(2);
            let out = a(3) as usize;
            let cap = a(4) as usize;
            let actual = a(5) as usize;
            let count = m.read::<u32>(actual) as usize;
            let level = a(6);
            if crate::kernel::startup::trace_enabled() {
                crate::compact_println!("[os2-find] {} attr={:#x} level={} cap={} count={}",
                    core::str::from_utf8(&raw).unwrap_or("?"), attr, level, cap, count);
            }
            if !matches!(level, 1 | 2 | 11 | 12) {
                return 124;
            }
            if count == 0 {
                return 87;
            }
            let split = raw.iter().rposition(|&b| b == b'\\' || b == b'/');
            let (dir, pattern) = match split {
                Some(i) => (
                    &raw[..if i == 2 && raw[1] == b':' { 3 } else { i }],
                    &raw[i + 1..],
                ),
                None => (&b""[..], raw.as_slice()),
            };
            let Ok(dir) = os2_path(s, dir, false) else {
                return 3;
            };
            if !vfs::dir_exists(&dir) {
                return 3;
            }
            let mut entries = Vec::new();
            let mut index = 0;
            while let Some(entry) = vfs::readdir(&dir, index) {
                index += 1;
                let attributes = entry
                    .dos_attributes
                    .unwrap_or(if entry.is_dir { 16 } else { 32 });
                if wildcard(pattern, &entry.name) && attributes as u32 & 0x16 & !attr == 0 {
                    entries.push(entry);
                }
            }
            let h = s.next_pm_handle;
            s.next_pm_handle += 1;
            let mut find = Find {
                handle: h,
                entries,
                next: 0,
                level,
            };
            let result = find_output(m, &mut find, out, cap, count, actual);
            if result == 0 {
                m.write::<u32>(handle, h);
                s.find.push(find);
            }
            result
        }
        Api::Base(265) => {
            let h = a(0);
            let out = a(1) as usize;
            let cap = a(2) as usize;
            let actual = a(3) as usize;
            let count = m.read::<u32>(actual) as usize;
            let Some(find) = s.find.iter_mut().find(|f| f.handle == h) else {
                return 6;
            };
            find_output(m, find, out, cap, count, actual)
        }
        Api::Base(278) => {
            let level = a(1);
            let out = a(2) as usize;
            let cap = a(3) as usize;
            match level {
                1 => {
                    if cap < 18 {
                        return 111;
                    }
                    m.zero(out, 18);
                    m.write::<u32>(out + 4, 8);
                    m.write::<u32>(out + 8, 32768);
                    m.write::<u32>(out + 12, 24576);
                    m.write::<u16>(out + 16, 512);
                    NO_ERROR
                }
                2 => {
                    if cap < 17 {
                        return 111;
                    }
                    m.zero(out, 17);
                    m.write::<u8>(out + 4, 7);
                    m.copy_to(out + 5, b"RETROOS");
                    NO_ERROR
                }
                _ => 124,
            }
        }
        Api::Base(277) => {
            let out = a(3) as usize;
            let length = a(4) as usize;
            let cap = m.read::<u32>(length) as usize;
            let bytes = b"\x03\0\x02\0\x03\0\0\0C:\0FAT\0";
            m.write::<u32>(length, bytes.len() as u32);
            if cap < bytes.len() {
                111
            } else {
                m.copy_to(out, bytes);
                NO_ERROR
            }
        }
        Api::Base(270 | 226 | 259 | 271) => {
            let ordinal = if let Api::Base(n) = api { n } else { 0 };
            let Ok(path) = c_string(m, a(0)).and_then(|p| os2_path(s, &p, ordinal == 270)) else {
                return 2;
            };
            let result = match ordinal {
                270 => vfs::mkdir(&path),
                226 => vfs::rmdir(&path),
                259 => vfs::delete(&path),
                _ => {
                    let Ok(new) = c_string(m, a(1)).and_then(|p| os2_path(s, &p, true)) else {
                        return 3;
                    };
                    vfs::rename(&path, &new)
                }
            };
            if result < 0 {
                os2_error(result)
            } else {
                NO_ERROR
            }
        }
        Api::Base(323) => {
            let Ok(path) = c_string(m, a(0)).and_then(|p| os2_path(s, &p, false)) else {
                return 2;
            };
            let out = a(1) as usize;
            let Ok(data) = crate::kernel::exec::load_file_resolved(&path) else {
                return 2;
            };
            let flags = match crate::kernel::exec::detect_format(&data, &path) {
                crate::kernel::exec::BinaryFormat::Lx => 2,
                _ => 0x20,
            };
            m.write::<u32>(out, flags);
            NO_ERROR
        }
        Api::Base(255) => {
            let Ok(path) = c_string(m, a(0)).and_then(|p| os2_path(s, &p, false)) else {
                return 3;
            };
            if !vfs::dir_exists(&path) {
                return 3;
            }
            if path.len() > s.cwd.len() {
                return 111;
            }
            s.cwd[..path.len()].copy_from_slice(&path);
            s.cwd_len = path.len();
            NO_ERROR
        }
        Api::Base(229) => {
            let millis = a(0);
            if millis == 0 {
                return NO_ERROR;
            }
            if s.sleep_ready {
                s.sleep_ready = false;
                s.sleep_deadline = None;
                return NO_ERROR;
            }
            if s.sleep_deadline.is_none() {
                s.sleep_deadline = Some(m.now().saturating_add(millis as u64 * 1_000_000));
            }
            u32::MAX
        }
        Api::Base(306) => {
            let address = a(0);
            let length = a(1) as usize;
            let flags = a(2) as usize;
            let Some(&(base, size)) = s
                .allocations
                .iter()
                .find(|&&(base, size)| address >= base && address < base + size)
            else {
                return 487;
            };
            let cap = m.read::<u32>(length);
            m.write::<u32>(length, cap.min(base + size - address));
            m.write::<u32>(flags, 0x13);
            NO_ERROR
        }
        Api::Pm(0, 813) => 1,
        Api::Pm(0, 817) => 0,
        Api::Pm(0, 707 | 733 | 793) => 1,
        Api::Pm(_, _) => 0,
        Api::Base(305) => {
            let address = a(0);
            let size = a(1);
            let flags = a(2);
            if crate::kernel::startup::trace_enabled() {
                crate::compact_println!("[os2-mem] address={:#x} size={:#x} flags={:#x}", address, size, flags);
            }
            let Some(end) = address.checked_add(size) else {
                return 87;
            };
            let allocated = s
                .allocations
                .iter()
                .any(|&(base, len)| address >= base && end <= base + len);
            let mapped = s.modules.iter().any(|module| {
                lx::Image::parse(&module.data)
                    .ok()
                    .and_then(|image| image.objects().ok())
                    .is_some_and(|objects| {
                        objects.iter().any(|o| {
                            let base = module.bias.saturating_add(o.address) & !4095;
                            let top = module
                                .bias
                                .saturating_add(o.address)
                                .saturating_add(o.size)
                                .saturating_add(4095)
                                & !4095;
                            address >= base && end <= top
                        })
                    })
            });
            if !allocated && !mapped {
                return 487;
            }
            // Module pages are committed by the loader. Changing protection
            // or recommitting an existing allocation preserves its contents.
            m.set_page_flags(
                address as usize / 4096,
                (address as usize % 4096 + size as usize).div_ceil(4096),
                flags & 2 != 0,
                flags & 4 != 0,
            );
            NO_ERROR
        }
        Api::Base(320) => {
            let h = a(0) as usize;
            let cap = a(1) as usize;
            let out = a(2) as usize;
            let Some(module) = s.modules.get(h.wrapping_sub(1)) else {
                return 6;
            };
            let mut p = b"C:\\".to_vec();
            let root = crate::kernel::dos::c_root();
            let relative = module.path.strip_prefix(root).unwrap_or(&module.path);
            p.extend(
                relative
                    .iter()
                    .copied()
                    .skip_while(|b| *b == b'/')
                    .map(|b| if b == b'/' { b'\\' } else { b }),
            );
            copy_string(m, out, cap, &p)
        }
        Api::Base(352) => {
            let handle = a(0) as usize;
            let kind = a(1) as u16;
            let id = a(2) as u16;
            let out = a(3) as usize;
            let Some(module) = s.modules.get(handle.wrapping_sub(1)) else {
                return 6;
            };
            let Ok(image) = lx::Image::parse(&module.data) else {
                return 8;
            };
            let Some(resource) = image
                .resources()
                .ok()
                .and_then(|v| v.into_iter().find(|r| r.kind == kind && r.id == id))
            else {
                return 1814;
            };
            let Ok(address) = object_address(&image, module.bias, resource.object, resource.offset)
            else {
                return 8;
            };
            m.write::<u32>(out, address);
            NO_ERROR
        }
        Api::Base(353) => NO_ERROR,
        Api::Base(354 | 355) => {
            let record = a(0);
            if record == 0 || record >= USER_LIMIT.saturating_sub(8) {
                return ERROR_INVALID_PARAMETER;
            }
            let mut link = PROCESS_DATA;
            for _ in 0..1024 {
                let current = m.read::<u32>(link as usize);
                if current == record {
                    if api == Api::Base(354) { return ERROR_INVALID_PARAMETER; }
                    m.write::<u32>(link as usize, m.read::<u32>(record as usize));
                    return NO_ERROR;
                }
                if current == 0xffff_ffff {
                    if api == Api::Base(355) { return ERROR_INVALID_PARAMETER; }
                    m.write::<u32>(record as usize, m.read::<u32>(PROCESS_DATA as usize));
                    m.write::<u32>(PROCESS_DATA as usize, record);
                    return NO_ERROR;
                }
                if current == 0 || current >= USER_LIMIT.saturating_sub(8) {
                    return ERROR_INVALID_PARAMETER;
                }
                link = current;
            }
            ERROR_INVALID_PARAMETER
        }
        Api::Base(378) => {
            let out = a(1) as usize;
            if out != 0 {
                m.write::<u32>(out, 0);
            }
            NO_ERROR
        }
        Api::Base(223) => {
            let Ok(path) = c_string(m, a(0)).and_then(|p| os2_path(s, &p, false)) else {
                return 2;
            };
            let level = a(1);
            let out = a(2) as usize;
            let cap = a(3) as usize;
            if level == 5 {
                let mut p = b"C:\\".to_vec();
                p.extend(drive_relative(&path, crate::kernel::dos::c_root()));
                return copy_string(m, out, cap, &p);
            }
            let Some(stat) = vfs::stat(&path, true) else {
                return 2;
            };
            file_info(
                m,
                out,
                cap,
                level,
                stat.size,
                vfs::dos_attributes(&path).unwrap_or(if stat.is_dir { 16 } else { 32 }) as u32,
            )
        }
        Api::Base(279) => {
            let fd = a(0) as usize;
            let level = a(1);
            let out = a(2) as usize;
            let cap = a(3) as usize;
            if fd >= thread::MAX_FDS {
                return 6;
            }
            let Some((stat, _)) = vfs::fd_info(fd as i32, &kt.fds) else {
                return 6;
            };
            file_info(
                m,
                out,
                cap,
                level,
                stat.size,
                if stat.is_dir { 16 } else { 32 },
            )
        }
        Api::Msg(_) => 317,
        _ => {
            let name = alloc::format!("{:?}", api);
            crate::compact_println!(
                "OS/2: unsupported {} args={:#x},{:#x},{:#x},{:#x}",
                name.as_str(),
                a(0),
                a(1),
                a(2),
                a(3)
            );
            ERROR_INVALID_FUNCTION
        }
    }
}

pub(super) fn begin_dll_init<A: crate::Arch>(m: &mut A, s: &mut Os2State, r: &mut Regs) {
    if s.dll_saved.is_some() {
        return;
    }
    let Some((entry, handle)) = s.dll_init.pop() else {
        return;
    };
    s.dll_saved = Some(*r);
    let stack = (r.sp() as u32).wrapping_sub(12);
    m.write::<u32>(stack as usize, PROCESS_DATA + 0x300);
    m.write::<u32>(stack as usize + 4, handle);
    m.write::<u32>(stack as usize + 8, 0);
    r.frame.rsp = stack as u64;
    r.frame.rip = entry as u64;
}
fn load_module<A: crate::Arch>(m: &mut A, s: &mut Os2State, path: &[u8]) -> Result<u32, u32> {
    let name = module_name(
        path.rsplit(|&b| b == b'/' || b == b'\\')
            .next()
            .unwrap_or(path),
    );
    if let Some(index) = find_module(&s.modules, &name) {
        return Ok(index as u32 + 1);
    }
    let (resolved, data) = if path.contains(&b'/') || path.contains(&b'\\') || path.contains(&b':')
    {
        let resolved = os2_path(s, path, false)?;
        let data = crate::kernel::exec::load_file_resolved(&resolved).map_err(|_| 2u32)?;
        (resolved, data)
    } else {
        load_dependency(&name, s.exec_path_str()).map_err(|e| e as u32)?
    };
    let first = s.modules.len();
    let ldt_len = s.ldt.len();
    let result = (|| {
        let mut pending = vec![(name, resolved, data)];
        while let Some((name, path, data)) = pending.pop() {
            if find_module(&s.modules, &name).is_some() {
                continue;
            }
            if s.modules.len() >= MAX_MODULES {
                return Err(8);
            }
            let image = lx::Image::parse(&data).map_err(|_| 193u32)?;
            if !image.is_dll() {
                return Err(193);
            }
            let bias = DLL_BIAS_FIRST + (s.modules.len() as u32 - 1) * DLL_BIAS_STRIDE;
            let mut selectors = Vec::new();
            for o in image.objects().map_err(|_| 8u32)? {
                selectors.push(push_descriptor(
                    &mut s.ldt,
                    bias.checked_add(o.address).ok_or(8u32)?,
                    o.size,
                    o.flags & lx::OBJ_EXECUTABLE != 0,
                    o.flags & lx::OBJ_BIG != 0,
                ));
            }
            let imports = image.import_modules().map_err(|_| 8u32)?;
            s.modules.push(Module {
                name,
                path: path.clone(),
                data,
                bias,
                selectors,
            });
            for import in imports {
                if find_module(&s.modules, &import).is_none() {
                    let (p, d) = load_dependency(&import, &path).map_err(|e| e as u32)?;
                    pending.push((module_name(&import), p, d));
                }
            }
        }
        for module in &s.modules[first..] {
            map_module(m, module).map_err(|e| e as u32)?;
        }
        for i in first..s.modules.len() {
            apply_fixups(m, &s.modules, i).map_err(|e| e as u32)?;
        }
        for module in &s.modules[first..] {
            protect_module(m, module).map_err(|e| e as u32)?;
        }
        Ok(first as u32 + 1)
    })();
    if result.is_err() {
        s.modules.truncate(first);
        s.ldt.truncate(ldt_len);
        return result;
    }
    let modules = core::mem::take(&mut s.modules);
    register_gates(s, &modules);
    s.modules = modules;
    s.on_resume(m);
    for i in first..s.modules.len() {
        let module = &s.modules[i];
        let image = lx::Image::parse(&module.data).map_err(|_| 8u32)?;
        if image.header.start_object != 0 {
            let entry = object_address(
                &image,
                module.bias,
                image.header.start_object as u16,
                image.header.eip,
            )
            .map_err(|e| e as u32)?;
            s.dll_init.push((entry, i as u32 + 1));
        }
    }
    result
}
