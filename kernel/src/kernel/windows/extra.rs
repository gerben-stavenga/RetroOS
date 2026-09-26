//! Imports Midnight Commander and its CRT need beyond the small replacement
//! DLLs. Missing exports become `int 0x83` trampolines; these calls implement
//! them. The text console is a character buffer painted into a Win32 window.

use super::{
    arg, c_string, copy_ascii, fail, full_windows_path, guest_windows_path, w_string, windows_path, Window,
    WindowsState, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    INVALID_HANDLE_VALUE,
};
use crate::Regs;
use crate::kernel::thread;
use alloc::{vec, vec::Vec};

pub(super) struct Spec {
    pub module: &'static [u8],
    pub name: &'static [u8],
    pub arg_bytes: u32,
}

pub(super) struct Bound {
    pub name: &'static [u8],
    pub address: u32,
    pub arg_bytes: u32,
}

pub(super) struct Block {
    addr: u32,
    size: u32,
    used: bool,
}

pub(super) struct Find {
    handle: u32,
    entries: Vec<Entry>,
    index: usize,
}

struct Entry {
    name: Vec<u8>,
    short: Vec<u8>,
    size: u32,
    dir: bool,
}

struct Key {
    down: bool,
    ascii: u8,
    scan: u16,
    vk: u16,
}

pub(super) struct Console {
    pub cols: u16,
    pub rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    attr: u16,
    cells: Vec<u8>,
    input: Vec<Key>,
    pub hwnd: u32,
    /// `ReadConsoleInput` found no key. The call stays at the `int 0x83` so
    /// the next entry sees a real event instead of an empty record.
    hold: bool,
}

impl Console {
    pub(super) fn new() -> Self {
        let mut console = Self {
            cols: 80,
            rows: 25,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07,
            cells: Vec::new(),
            input: Vec::new(),
            hwnd: 0,
            hold: false,
        };
        console.blank();
        console
    }

    fn blank(&mut self) {
        self.cells.clear();
        self.cells
            .resize(self.cols as usize * self.rows as usize * 2, 0);
        for cell in self.cells.chunks_exact_mut(2) {
            cell[0] = b' ';
            cell[1] = self.attr as u8;
        }
    }

}

const SPECS: &[Spec] = &[
    spec(b"ADVAPI32", b"AllocateAndInitializeSid", 44),
    spec(b"ADVAPI32", b"EqualSid", 8),
    spec(b"ADVAPI32", b"FreeSid", 4),
    spec(b"ADVAPI32", b"GetTokenInformation", 20),
    spec(b"ADVAPI32", b"OpenProcessToken", 12),
    spec(b"KERNEL32", b"Beep", 8),
    spec(b"KERNEL32", b"CompareStringA", 24),
    spec(b"KERNEL32", b"CompareStringW", 24),
    spec(b"KERNEL32", b"CreateConsoleScreenBuffer", 20),
    spec(b"KERNEL32", b"CreateDirectoryA", 8),
    spec(b"KERNEL32", b"CreateDirectoryW", 8),
    spec(b"KERNEL32", b"CreateFileW", 28),
    spec(b"KERNEL32", b"CreateMutexA", 12),
    spec(b"KERNEL32", b"CreatePipe", 16),
    spec(b"KERNEL32", b"CreateProcessA", 40),
    spec(b"KERNEL32", b"CreateProcessW", 40),
    spec(b"KERNEL32", b"CreateThread", 24),
    spec(b"KERNEL32", b"DeleteCriticalSection", 4),
    spec(b"KERNEL32", b"DeleteFileA", 4),
    spec(b"KERNEL32", b"DeleteFileW", 4),
    spec(b"KERNEL32", b"DuplicateHandle", 28),
    spec(b"KERNEL32", b"EnterCriticalSection", 4),
    spec(b"KERNEL32", b"ExitThread", 4),
    spec(b"KERNEL32", b"FileTimeToLocalFileTime", 8),
    spec(b"KERNEL32", b"FileTimeToSystemTime", 8),
    spec(b"KERNEL32", b"FillConsoleOutputAttribute", 20),
    spec(b"KERNEL32", b"FillConsoleOutputCharacterA", 20),
    spec(b"KERNEL32", b"FindClose", 4),
    spec(b"KERNEL32", b"FindFirstFileA", 8),
    spec(b"KERNEL32", b"FindFirstFileW", 8),
    spec(b"KERNEL32", b"FindNextFileA", 8),
    spec(b"KERNEL32", b"FindNextFileW", 8),
    spec(b"KERNEL32", b"FreeEnvironmentStringsA", 4),
    spec(b"KERNEL32", b"FreeEnvironmentStringsW", 4),
    spec(b"KERNEL32", b"FreeLibrary", 4),
    spec(b"KERNEL32", b"GetConsoleScreenBufferInfo", 8),
    spec(b"KERNEL32", b"GetCurrentDirectoryA", 8),
    spec(b"KERNEL32", b"GetCurrentDirectoryW", 8),
    spec(b"KERNEL32", b"GetCurrentProcess", 0),
    spec(b"KERNEL32", b"GetCurrentProcessId", 0),
    spec(b"KERNEL32", b"GetCurrentThread", 0),
    spec(b"KERNEL32", b"GetDiskFreeSpaceA", 20),
    spec(b"KERNEL32", b"GetDriveTypeA", 4),
    spec(b"KERNEL32", b"GetDriveTypeW", 4),
    spec(b"KERNEL32", b"GetEnvironmentStrings", 0),
    spec(b"KERNEL32", b"GetEnvironmentStringsW", 0),
    spec(b"KERNEL32", b"GetExitCodeProcess", 8),
    spec(b"KERNEL32", b"GetFileAttributesA", 4),
    spec(b"KERNEL32", b"GetFileAttributesW", 4),
    spec(b"KERNEL32", b"GetFileInformationByHandle", 8),
    spec(b"KERNEL32", b"GetFullPathNameA", 16),
    spec(b"KERNEL32", b"GetFullPathNameW", 16),
    spec(b"KERNEL32", b"GetLocalTime", 4),
    spec(b"KERNEL32", b"GetLocaleInfoA", 16),
    spec(b"KERNEL32", b"GetLocaleInfoW", 16),
    spec(b"KERNEL32", b"GetLogicalDriveStringsA", 8),
    spec(b"KERNEL32", b"GetLogicalDrives", 0),
    spec(b"KERNEL32", b"GetNumberOfConsoleInputEvents", 8),
    spec(b"KERNEL32", b"GetStringTypeA", 20),
    spec(b"KERNEL32", b"GetStringTypeW", 16),
    spec(b"KERNEL32", b"GetSystemTime", 4),
    spec(b"KERNEL32", b"GetTempPathA", 8),
    spec(b"KERNEL32", b"GetTickCount", 0),
    spec(b"KERNEL32", b"GetTimeZoneInformation", 4),
    spec(b"KERNEL32", b"GetUserDefaultLCID", 0),
    spec(b"KERNEL32", b"GetVersionExA", 4),
    spec(b"KERNEL32", b"GetVolumeInformationA", 32),
    spec(b"KERNEL32", b"HeapAlloc", 12),
    spec(b"KERNEL32", b"HeapCompact", 8),
    spec(b"KERNEL32", b"HeapCreate", 12),
    spec(b"KERNEL32", b"HeapDestroy", 4),
    spec(b"KERNEL32", b"HeapFree", 12),
    spec(b"KERNEL32", b"HeapReAlloc", 16),
    spec(b"KERNEL32", b"HeapSize", 12),
    spec(b"KERNEL32", b"HeapValidate", 12),
    spec(b"KERNEL32", b"HeapWalk", 8),
    spec(b"KERNEL32", b"InitializeCriticalSection", 4),
    spec(b"KERNEL32", b"InterlockedDecrement", 4),
    spec(b"KERNEL32", b"InterlockedIncrement", 4),
    spec(b"KERNEL32", b"IsBadCodePtr", 4),
    spec(b"KERNEL32", b"IsBadReadPtr", 8),
    spec(b"KERNEL32", b"IsBadWritePtr", 8),
    spec(b"KERNEL32", b"IsValidCodePage", 4),
    spec(b"KERNEL32", b"IsValidLocale", 8),
    spec(b"KERNEL32", b"LCMapStringA", 24),
    spec(b"KERNEL32", b"LCMapStringW", 24),
    spec(b"KERNEL32", b"LeaveCriticalSection", 4),
    spec(b"KERNEL32", b"LocalFileTimeToFileTime", 8),
    spec(b"KERNEL32", b"LockFile", 20),
    spec(b"KERNEL32", b"MoveFileA", 8),
    spec(b"KERNEL32", b"MoveFileW", 8),
    spec(b"KERNEL32", b"PeekConsoleInputA", 16),
    spec(b"KERNEL32", b"PeekNamedPipe", 24),
    spec(b"KERNEL32", b"RaiseException", 16),
    spec(b"KERNEL32", b"ReadConsoleA", 20),
    spec(b"KERNEL32", b"ReadConsoleOutputA", 20),
    spec(b"KERNEL32", b"ReleaseMutex", 4),
    spec(b"KERNEL32", b"RemoveDirectoryA", 4),
    spec(b"KERNEL32", b"RemoveDirectoryW", 4),
    spec(b"KERNEL32", b"ResumeThread", 4),
    spec(b"KERNEL32", b"RtlUnwind", 16),
    spec(b"KERNEL32", b"SetConsoleActiveScreenBuffer", 4),
    spec(b"KERNEL32", b"SetConsoleCursorPosition", 8),
    spec(b"KERNEL32", b"SetConsoleScreenBufferSize", 8),
    spec(b"KERNEL32", b"SetConsoleTitleA", 4),
    spec(b"KERNEL32", b"SetConsoleWindowInfo", 12),
    spec(b"KERNEL32", b"SetCurrentDirectoryA", 4),
    spec(b"KERNEL32", b"SetCurrentDirectoryW", 4),
    spec(b"KERNEL32", b"SetEndOfFile", 4),
    spec(b"KERNEL32", b"SetEnvironmentVariableW", 8),
    spec(b"KERNEL32", b"SetErrorMode", 4),
    spec(b"KERNEL32", b"SetFileAttributesA", 8),
    spec(b"KERNEL32", b"SetFileAttributesW", 8),
    spec(b"KERNEL32", b"SetFileTime", 16),
    spec(b"KERNEL32", b"SetHandleCount", 4),
    spec(b"KERNEL32", b"SetLastError", 4),
    spec(b"KERNEL32", b"SetLocalTime", 4),
    spec(b"KERNEL32", b"Sleep", 4),
    spec(b"KERNEL32", b"SystemTimeToFileTime", 8),
    spec(b"KERNEL32", b"TerminateProcess", 8),
    spec(b"KERNEL32", b"TlsAlloc", 0),
    spec(b"KERNEL32", b"TlsFree", 4),
    spec(b"KERNEL32", b"TlsGetValue", 4),
    spec(b"KERNEL32", b"TlsSetValue", 8),
    spec(b"KERNEL32", b"UnlockFile", 20),
    spec(b"KERNEL32", b"WaitForSingleObject", 8),
    spec(b"KERNEL32", b"WriteConsoleOutputA", 20),
    spec(b"KERNEL32", b"WriteConsoleOutputAttribute", 20),
    spec(b"KERNEL32", b"WriteConsoleOutputCharacterA", 20),
];

const fn spec(module: &'static [u8], name: &'static [u8], arg_bytes: u32) -> Spec {
    Spec { module, name, arg_bytes }
}

pub(super) fn lookup(module: &[u8], name: &[u8]) -> Option<&'static Spec> {
    let module = module_stem(module);
    SPECS.iter().find(|spec| {
        spec.module.eq_ignore_ascii_case(module) && spec.name.eq_ignore_ascii_case(name)
    })
}

fn module_stem(name: &[u8]) -> &[u8] {
    let end = name
        .iter()
        .rposition(|&b| b == b'.')
        .filter(|&at| name[at..].eq_ignore_ascii_case(b".DLL"))
        .unwrap_or(name.len());
    &name[..end]
}

pub(super) fn take_hold(console: &mut Console) -> bool {
    let held = console.hold;
    console.hold = false;
    held
}

pub(super) fn push_key(console: &mut Console, scancode: u8) {
    if scancode == 0xe0 || console.input.len() >= 64 {
        return;
    }
    let down = scancode & 0x80 == 0;
    let scan = u16::from(scancode & 0x7f);
    let mut ascii = if down {
        crate::kernel::keyboard::scancode_to_ascii(scancode)
    } else {
        0
    };
    if scan == 0x1c {
        ascii = if down { b'\r' } else { 0 };
    }
    console.input.push(Key {
        down,
        ascii,
        scan,
        vk: virtual_key(scan, ascii),
    });
}

/// CreateProcess from the Win32 personality feeds the shared fork/exec
/// mechanism. MSVCRT's system() passes COMSPEC plus "/c command"; unwrap that
/// shell request so native Windows binaries start directly as child processes.
pub(super) fn create_process<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &Regs,
    wide: bool,
) -> Result<thread::KernelAction, u32> {
    let read_string = |address| {
        if wide { w_string(machine, address) } else { c_string(machine, address) }
    };
    let app = if arg(machine, regs, 0) == 0 {
        Vec::new()
    } else {
        read_string(arg(machine, regs, 0))?
    };
    let command = if arg(machine, regs, 1) == 0 {
        app.clone()
    } else {
        read_string(arg(machine, regs, 1))?
    };
    let (program, cmdtail) = command_program(&command, &app);
    if program.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let path = windows_path(state, &program, false)?;
    if !crate::kernel::vfs::path_exists(&path) {
        return Err(ERROR_FILE_NOT_FOUND);
    }
    let cwd = if arg(machine, regs, 7) == 0 {
        Vec::new()
    } else {
        windows_path(state, &read_string(arg(machine, regs, 7))?, false)?
    };
    if path.len() > 164 || cwd.len() > 164 || cmdtail.len() > 127 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut path_buf = [0; 164];
    path_buf[..path.len()].copy_from_slice(&path);
    let mut cwd_buf = [0; 164];
    cwd_buf[..cwd.len()].copy_from_slice(&cwd);
    let mut tail_buf = [0; 128];
    tail_buf[..cmdtail.len()].copy_from_slice(&cmdtail);

    let info = arg(machine, regs, 9) as usize;
    state.prepare_process(info);
    state.last_error = ERROR_FILE_NOT_FOUND;
    Ok(thread::KernelAction::ForkExec {
        path: path_buf,
        path_len: path.len(),
        cmdtail: tail_buf,
        cmdtail_len: cmdtail.len(),
        cwd: cwd_buf,
        cwd_len: cwd.len(),
        personality_name: None,
        policy: crate::kernel::dos::LaunchPolicy::default(),
        on_error: create_process_error,
        on_success: create_process_success,
    })
}

fn create_process_error(regs: &mut Regs, _error: i32) {
    regs.rax = 0;
}

fn create_process_success(regs: &mut Regs, _child_tid: i32) {
    regs.rax = 1;
}

fn command_program(command: &[u8], app: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let shell = app.rsplit(|&b| b == b'\\' || b == b'/').next()
        .is_some_and(|name| name.eq_ignore_ascii_case(b"COMMAND.COM") || name.eq_ignore_ascii_case(b"CMD.EXE"));
    let mut text = command;
    if !app.is_empty() {
        if let Some((first, rest)) = take_word(text) {
            let same_app = first.eq_ignore_ascii_case(app)
                || first.rsplit(|&b| b == b'\\' || b == b'/').next()
                    .is_some_and(|name| app.rsplit(|&b| b == b'\\' || b == b'/')
                        .next().is_some_and(|app_name| name.eq_ignore_ascii_case(app_name)));
            if same_app {
                text = rest.trim_ascii_start();
            }
        }
        if !shell {
            return (app.to_vec(), text.trim_ascii_start().to_vec());
        }
    }
    if shell && text.len() >= 2 && text[..2].eq_ignore_ascii_case(b"/c") {
        text = text[2..].trim_ascii_start();
    }
    take_word(text).map_or((Vec::new(), Vec::new()), |(program, tail)| {
        (program.to_vec(), tail.trim_ascii_start().to_vec())
    })
}

fn take_word(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let text = text.trim_ascii_start();
    if text.is_empty() { return None; }
    if text[0] == b'"' {
        let end = text[1..].iter().position(|&b| b == b'"')? + 1;
        Some((&text[1..end], &text[end + 1..]))
    } else {
        let end = text.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(text.len());
        Some((&text[..end], &text[end..]))
    }
}

fn virtual_key(scan: u16, ascii: u8) -> u16 {
    match scan {
        0x1c => 0x0d,
        0x48 => 0x26,
        0x50 => 0x28,
        0x4b => 0x25,
        0x4d => 0x27,
        0x47 => 0x24,
        0x4f => 0x23,
        0x49 => 0x21,
        0x51 => 0x22,
        0x53 => 0x2e,
        0x52 => 0x2d,
        0x3b..=0x44 => 0x70 + (scan - 0x3b),
        _ if ascii.is_ascii_alphabetic() => u16::from(ascii.to_ascii_uppercase()),
        _ if ascii != 0 => u16::from(ascii),
        _ => 0,
    }
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &Regs,
    name: &[u8],
) -> u32 {
    if name.eq_ignore_ascii_case(b"GetTickCount") {
        return (machine.now() / 1_000_000) as u32;
    }
    if name.eq_ignore_ascii_case(b"GetCurrentProcess")
        || name.eq_ignore_ascii_case(b"GetCurrentThread")
    {
        return 0xffff_ffff;
    }
    if name.eq_ignore_ascii_case(b"GetCurrentProcessId") {
        return (kt.tid + 1) as u32;
    }
    if name.eq_ignore_ascii_case(b"GetUserDefaultLCID") {
        return 0x0409;
    }
    if name.eq_ignore_ascii_case(b"GetLogicalDrives") {
        return 1 << 2;
    }
    if name.eq_ignore_ascii_case(b"SetLastError") {
        state.last_error = arg(machine, regs, 0);
        return 0;
    }
    if name.eq_ignore_ascii_case(b"HeapCreate") {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"HeapAlloc") {
        return heap_alloc(machine, state, arg(machine, regs, 1), arg(machine, regs, 2));
    }
    if name.eq_ignore_ascii_case(b"HeapFree") {
        heap_free(state, arg(machine, regs, 2));
        return 1;
    }
    if name.eq_ignore_ascii_case(b"HeapReAlloc") {
        return heap_realloc(
            machine,
            state,
            arg(machine, regs, 1),
            arg(machine, regs, 2),
            arg(machine, regs, 3),
        );
    }
    if name.eq_ignore_ascii_case(b"HeapSize") {
        let addr = arg(machine, regs, 2);
        return state
            .blocks
            .iter()
            .find(|block| block.addr == addr && block.used)
            .map_or(0xffff_ffff, |block| block.size);
    }
    if name.eq_ignore_ascii_case(b"HeapDestroy")
        || name.eq_ignore_ascii_case(b"HeapValidate")
        || name.eq_ignore_ascii_case(b"InitializeCriticalSection")
        || name.eq_ignore_ascii_case(b"EnterCriticalSection")
        || name.eq_ignore_ascii_case(b"LeaveCriticalSection")
        || name.eq_ignore_ascii_case(b"DeleteCriticalSection")
        || name.eq_ignore_ascii_case(b"FreeLibrary")
        || name.eq_ignore_ascii_case(b"ReleaseMutex")
        || name.eq_ignore_ascii_case(b"SetEndOfFile")
        || name.eq_ignore_ascii_case(b"LockFile")
        || name.eq_ignore_ascii_case(b"UnlockFile")
        || name.eq_ignore_ascii_case(b"SetFileTime")
        || name.eq_ignore_ascii_case(b"SetFileAttributesA")
        || name.eq_ignore_ascii_case(b"SetFileAttributesW")
        || name.eq_ignore_ascii_case(b"SetErrorMode")
        || name.eq_ignore_ascii_case(b"SetConsoleTitleA")
        || name.eq_ignore_ascii_case(b"SetConsoleActiveScreenBuffer")
        || name.eq_ignore_ascii_case(b"Sleep")
        || name.eq_ignore_ascii_case(b"Beep")
        || name.eq_ignore_ascii_case(b"ResumeThread")
        || name.eq_ignore_ascii_case(b"FileTimeToLocalFileTime")
        || name.eq_ignore_ascii_case(b"FileTimeToSystemTime")
        || name.eq_ignore_ascii_case(b"LocalFileTimeToFileTime")
        || name.eq_ignore_ascii_case(b"SystemTimeToFileTime")
        || name.eq_ignore_ascii_case(b"FreeEnvironmentStringsA")
        || name.eq_ignore_ascii_case(b"FreeEnvironmentStringsW")
    {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"HeapCompact") || name.eq_ignore_ascii_case(b"HeapWalk") {
        return 0;
    }
    if name.eq_ignore_ascii_case(b"TlsAlloc") {
        let slot = tls_alloc(state);
        if slot == 0xffff_ffff {
            return fail(state, ERROR_INVALID_PARAMETER, slot);
        }
        state.last_error = 0;
        return slot;
    }
    if name.eq_ignore_ascii_case(b"TlsFree") {
        let slot = arg(machine, regs, 0);
        if slot < 64 {
            state.tls_mask &= !(1 << slot);
            state.last_error = 0;
            return 1;
        }
        return fail(state, ERROR_INVALID_PARAMETER, 0);
    }
    if name.eq_ignore_ascii_case(b"TlsGetValue") {
        let slot = arg(machine, regs, 0) as usize;
        if slot >= 64 {
            return fail(state, ERROR_INVALID_PARAMETER, 0);
        }
        state.last_error = 0;
        return state.tls[slot];
    }
    if name.eq_ignore_ascii_case(b"TlsSetValue") {
        let slot = arg(machine, regs, 0) as usize;
        if slot >= 64 {
            return fail(state, ERROR_INVALID_PARAMETER, 0);
        }
        state.tls[slot] = arg(machine, regs, 1);
        state.last_error = 0;
        return 1;
    }
    if name.eq_ignore_ascii_case(b"InterlockedIncrement")
        || name.eq_ignore_ascii_case(b"InterlockedDecrement")
    {
        let at = arg(machine, regs, 0) as usize;
        let delta = if name.eq_ignore_ascii_case(b"InterlockedIncrement") {
            1i32
        } else {
            -1
        };
        let value = (machine.read::<u32>(at) as i32).wrapping_add(delta) as u32;
        machine.write::<u32>(at, value);
        return value;
    }
    if name.eq_ignore_ascii_case(b"IsBadReadPtr")
        || name.eq_ignore_ascii_case(b"IsBadWritePtr")
        || name.eq_ignore_ascii_case(b"IsBadCodePtr")
    {
        return u32::from(arg(machine, regs, 0) == 0);
    }
    if name.eq_ignore_ascii_case(b"IsValidCodePage") || name.eq_ignore_ascii_case(b"IsValidLocale")
    {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetHandleCount") {
        return arg(machine, regs, 0).max(3);
    }
    if name.eq_ignore_ascii_case(b"DuplicateHandle") {
        let out = arg(machine, regs, 3) as usize;
        machine.write::<u32>(out, arg(machine, regs, 1));
        return 1;
    }
    if name.eq_ignore_ascii_case(b"WaitForSingleObject") {
        return 0;
    }
    if name.eq_ignore_ascii_case(b"CreateMutexA") {
        let handle = state.next_object;
        state.next_object += 1;
        return handle;
    }
    if name.eq_ignore_ascii_case(b"CreateConsoleScreenBuffer") {
        ensure_window(state);
        return 0x0004_0001;
    }
    if name.eq_ignore_ascii_case(b"GetConsoleScreenBufferInfo") {
        return screen_info(machine, state, arg(machine, regs, 1) as usize);
    }
    if name.eq_ignore_ascii_case(b"SetConsoleCursorPosition") {
        let coord = arg(machine, regs, 1);
        state.console.cursor_x = (coord & 0xffff) as u16;
        state.console.cursor_y = (coord >> 16) as u16;
        paint(state);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetConsoleScreenBufferSize") {
        // The text screen is fixed at 80x25. Honouring a larger size makes
        // Midnight Commander lay the panels out past the visible rows, so the
        // bottom of each panel never appears. Report success and keep 80x25.
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetConsoleWindowInfo") {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetNumberOfConsoleInputEvents") {
        machine.write::<u32>(arg(machine, regs, 1) as usize, state.console.input.len() as u32);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"PeekConsoleInputA") || name.eq_ignore_ascii_case(b"ReadConsoleInputA")
    {
        let consume = name.eq_ignore_ascii_case(b"ReadConsoleInputA");
        return read_input(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3) as usize, consume);
    }
    if name.eq_ignore_ascii_case(b"ReadConsoleA") {
        return read_console_text(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3) as usize);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputCharacterA") {
        return write_chars(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputAttribute") {
        return write_chars(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"FillConsoleOutputCharacterA") {
        return fill_cells(machine, state, arg(machine, regs, 1) as u8, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"FillConsoleOutputAttribute") {
        return fill_cells(machine, state, arg(machine, regs, 1) as u8, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputA") {
        return console_block(machine, state, regs, false);
    }
    if name.eq_ignore_ascii_case(b"ReadConsoleOutputA") {
        return console_block(machine, state, regs, true);
    }
    if name.eq_ignore_ascii_case(b"GetCurrentDirectoryA") {
        return copy_dir(machine, state, arg(machine, regs, 0) as usize, arg(machine, regs, 1) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"GetCurrentDirectoryW") {
        return copy_dir(machine, state, arg(machine, regs, 0) as usize, arg(machine, regs, 1) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"SetCurrentDirectoryA") || name.eq_ignore_ascii_case(b"SetCurrentDirectoryW")
    {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, 0),
        };
        return set_directory(state, &raw);
    }
    if name.eq_ignore_ascii_case(b"GetFileAttributesA") || name.eq_ignore_ascii_case(b"GetFileAttributesW")
    {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, 0xffff_ffff),
        };
        return attributes(state, &raw);
    }
    if name.eq_ignore_ascii_case(b"FindFirstFileA") || name.eq_ignore_ascii_case(b"FindFirstFileW") {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
        };
        return find_first(machine, state, &raw, arg(machine, regs, 1) as usize);
    }
    if name.eq_ignore_ascii_case(b"FindNextFileA") || name.eq_ignore_ascii_case(b"FindNextFileW") {
        return find_next(machine, state, arg(machine, regs, 0), arg(machine, regs, 1) as usize);
    }
    if name.eq_ignore_ascii_case(b"FindClose") {
        let handle = arg(machine, regs, 0);
        state.finds.retain(|find| find.handle != handle);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"DeleteFileA") || name.eq_ignore_ascii_case(b"DeleteFileW")
        || name.eq_ignore_ascii_case(b"RemoveDirectoryA") || name.eq_ignore_ascii_case(b"RemoveDirectoryW")
        || name.eq_ignore_ascii_case(b"CreateDirectoryA") || name.eq_ignore_ascii_case(b"CreateDirectoryW")
    {
        return mutate_path(machine, state, regs, name);
    }
    if name.eq_ignore_ascii_case(b"MoveFileA") || name.eq_ignore_ascii_case(b"MoveFileW") {
        let wide = name.ends_with(b"W");
        let read = |n| if wide { w_string(machine, arg(machine, regs, n)) } else { c_string(machine, arg(machine, regs, n)) };
        let from = match read(0) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let to = match read(1) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let from = match windows_path(state, &from, false) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let to = match windows_path(state, &to, true) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        return if crate::kernel::vfs::rename(&from, &to) < 0 { fail(state, ERROR_FILE_NOT_FOUND, 0) } else { 1 };
    }
    if name.eq_ignore_ascii_case(b"GetFullPathNameA") || name.eq_ignore_ascii_case(b"GetFullPathNameW") {
        return full_path(machine, state, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetLogicalDriveStringsA") {
        let text = b"C:\\\0";
        return copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 0) as usize, text) + 1;
    }
    if name.eq_ignore_ascii_case(b"GetDriveTypeA") || name.eq_ignore_ascii_case(b"GetDriveTypeW") {
        return 3;
    }
    if name.eq_ignore_ascii_case(b"GetTempPathA") {
        return copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 0) as usize, b"C:\\TEMP\\");
    }
    if name.eq_ignore_ascii_case(b"GetDiskFreeSpaceA") {
        for n in 1..5 {
            let ptr = arg(machine, regs, n) as usize;
            if ptr != 0 {
                machine.write::<u32>(ptr, if n == 1 || n == 2 { 512 } else { 1024 * 1024 });
            }
        }
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetVolumeInformationA") {
        copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize, b"RETROOS");
        if arg(machine, regs, 4) != 0 {
            machine.write::<u32>(arg(machine, regs, 4) as usize, 255);
        }
        copy_ascii(machine, arg(machine, regs, 6) as usize, arg(machine, regs, 7) as usize, b"FAT");
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetEnvironmentStrings") {
        return env_block(machine, false);
    }
    if name.eq_ignore_ascii_case(b"GetEnvironmentStringsW") {
        return env_block(machine, true);
    }
    if name.eq_ignore_ascii_case(b"GetVersionExA") {
        return version(machine, arg(machine, regs, 0) as usize);
    }
    if name.eq_ignore_ascii_case(b"GetLocalTime") || name.eq_ignore_ascii_case(b"GetSystemTime")
        || name.eq_ignore_ascii_case(b"SetLocalTime")
    {
        if !name.starts_with(b"Set") {
            machine.zero(arg(machine, regs, 0) as usize, 16);
        }
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetTimeZoneInformation") {
        machine.zero(arg(machine, regs, 0) as usize, 172);
        return 0;
    }
    if name.eq_ignore_ascii_case(b"CompareStringA") || name.eq_ignore_ascii_case(b"CompareStringW") {
        return compare(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"LCMapStringA") || name.eq_ignore_ascii_case(b"LCMapStringW") {
        return map_string(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetLocaleInfoA") || name.eq_ignore_ascii_case(b"GetLocaleInfoW") {
        return locale_info(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetStringTypeA") || name.eq_ignore_ascii_case(b"GetStringTypeW") {
        return string_type(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetFileInformationByHandle") {
        machine.zero(arg(machine, regs, 1) as usize, 52);
        machine.write::<u32>(arg(machine, regs, 1) as usize, 0x20);
        machine.write::<u32>(arg(machine, regs, 1) as usize + 44, 1);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetExitCodeProcess") {
        let handle = arg(machine, regs, 0);
        machine.write::<u32>(
            arg(machine, regs, 1) as usize,
            state.process_exit_code(handle).unwrap_or(259),
        );
        return 1;
    }
    if name.eq_ignore_ascii_case(b"CreateFileW") {
        let raw = match w_string(machine, arg(machine, regs, 0)) {
            Ok(v) => v,
            Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
        };
        return super::create_file(machine, kt, state, &raw, arg(machine, regs, 4));
    }
    if name.eq_ignore_ascii_case(b"CreateThread")
        || name.eq_ignore_ascii_case(b"CreatePipe")
        || name.eq_ignore_ascii_case(b"PeekNamedPipe")
        || name.eq_ignore_ascii_case(b"TerminateProcess")
        || name.eq_ignore_ascii_case(b"OpenProcessToken")
        || name.eq_ignore_ascii_case(b"GetTokenInformation")
        || name.eq_ignore_ascii_case(b"AllocateAndInitializeSid")
        || name.eq_ignore_ascii_case(b"EqualSid")
        || name.eq_ignore_ascii_case(b"FreeSid")
    {
        return fail(state, 120, 0);
    }
    if name.eq_ignore_ascii_case(b"ExitThread") || name.eq_ignore_ascii_case(b"RaiseException")
        || name.eq_ignore_ascii_case(b"RtlUnwind")
    {
        return 0;
    }
    crate::compact_println!(
        "Windows: unhandled {}",
        core::str::from_utf8(name).unwrap_or("api")
    );
    0
}

fn tls_alloc(state: &mut WindowsState) -> u32 {
    for slot in 0..64 {
        if state.tls_mask & (1 << slot) == 0 {
            state.tls_mask |= 1 << slot;
            state.tls[slot] = 0;
            return slot as u32;
        }
    }
    0xffff_ffff
}

fn heap_alloc<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, flags: u32, bytes: u32) -> u32 {
    let size = bytes.max(1).next_multiple_of(8);
    if let Some(block) = state.blocks.iter_mut().find(|block| !block.used && block.size >= size) {
        block.used = true;
        if flags & 8 != 0 {
            machine.zero(block.addr as usize, block.size as usize);
        }
        return block.addr;
    }
    let addr = state.heap_next;
    let Some(end) = addr.checked_add(size) else {
        return 0;
    };
    if end >= super::USER_LIMIT {
        return 0;
    }
    state.heap_next = end;
    machine.zero(addr as usize, size as usize);
    machine.set_page_flags(addr as usize / 4096, size.div_ceil(4096) as usize, true, false);
    state.blocks.push(Block { addr, size, used: true });
    addr
}

fn heap_free(state: &mut WindowsState, addr: u32) {
    if let Some(block) = state.blocks.iter_mut().find(|block| block.addr == addr) {
        block.used = false;
    }
}

fn heap_realloc<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    flags: u32,
    addr: u32,
    bytes: u32,
) -> u32 {
    let old = state
        .blocks
        .iter()
        .find(|block| block.addr == addr && block.used)
        .map(|block| block.size)
        .unwrap_or(0);
    let next = heap_alloc(machine, state, flags, bytes);
    if next == 0 || addr == 0 {
        return next;
    }
    let n = old.min(bytes) as usize;
    for i in 0..n {
        let byte = machine.read::<u8>(addr as usize + i);
        machine.write::<u8>(next as usize + i, byte);
    }
    heap_free(state, addr);
    next
}

pub(super) fn open_console(state: &mut WindowsState) {
    ensure_window(state);
}

fn ensure_window(state: &mut WindowsState) {
    if state.console.hwnd != 0 {
        return;
    }
    let hwnd = state.next_object;
    state.next_object += 1;
    state.console.hwnd = hwnd;
    let width = state.console.cols as u32 * 8;
    let height = state.console.rows as u32 * 16;
    state.windows.push(Window {
        hwnd,
        parent: 0,
        wndproc: 0,
        x: 0,
        y: 0,
        width,
        height,
        visible: true,
        pixels: vec![0; width as usize * height as usize * 4],
    });
    paint(state);
}

fn paint(state: &mut WindowsState) {
    ensure_window(state);
    let hwnd = state.console.hwnd;
    let cols = state.console.cols as usize;
    let rows = state.console.rows as usize;
    let cells = state.console.cells.clone();
    let cursor = (state.console.cursor_x as usize, state.console.cursor_y as usize);
    let Some(window) = state.windows.iter_mut().find(|window| window.hwnd == hwnd) else {
        return;
    };
    for y in 0..rows {
        for x in 0..cols {
            let at = (y * cols + x) * 2;
            let ch = cells[at] as usize;
            let attr = cells[at + 1];
            let (fg, bg) = if cursor == (x, y) {
                (color(attr >> 4), color(attr))
            } else {
                (color(attr), color(attr >> 4))
            };
            let glyph = &lib::vga_fonts::FONT_8X16[ch.min(255) * 16..ch.min(255) * 16 + 16];
            for row in 0..16 {
                let bits = glyph[row];
                for col in 0..8 {
                    let pixel = if bits & (0x80 >> col) != 0 { fg } else { bg };
                    let px = (y * 16 + row) * window.width as usize + x * 8 + col;
                    let dest = px * 4;
                    if dest + 4 <= window.pixels.len() {
                        window.pixels[dest..dest + 4].copy_from_slice(&pixel.to_le_bytes());
                    }
                }
            }
        }
    }
    state.dirty = true;
    crate::term::term().blit_cells(
        cols,
        rows,
        &cells,
        cursor.0,
        cursor.1,
    );
}

fn color(index: u8) -> u32 {
    const PALETTE: [u32; 16] = [
        0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555,
        0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
    ];
    PALETTE[(index & 0x0f) as usize]
}

fn screen_info<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, out: usize) -> u32 {
    ensure_window(state);
    let console = &state.console;
    machine.write::<u16>(out, console.cols);
    machine.write::<u16>(out + 2, console.rows);
    machine.write::<u16>(out + 4, console.cursor_x);
    machine.write::<u16>(out + 6, console.cursor_y);
    machine.write::<u16>(out + 8, console.attr);
    machine.write::<u16>(out + 10, 0);
    machine.write::<u16>(out + 12, 0);
    machine.write::<u16>(out + 14, console.cols.saturating_sub(1));
    machine.write::<u16>(out + 16, console.rows.saturating_sub(1));
    machine.write::<u16>(out + 18, console.cols);
    machine.write::<u16>(out + 20, console.rows);
    1
}

/// `WriteConsoleOutputA` / `ReadConsoleOutputA`. Midnight Commander paints each
/// panel as one `CHAR_INFO` rectangle; ignoring that buffer left only the
/// stray text (the hotlist notice) that was written a character at a time.
fn console_block<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &Regs,
    read: bool,
) -> u32 {
    let buffer = arg(machine, regs, 1) as usize;
    let size = arg(machine, regs, 2);
    let origin = arg(machine, regs, 3);
    let region = arg(machine, regs, 4) as usize;
    let buf_w = (size & 0xffff) as i32;
    let buf_h = (size >> 16) as i32;
    let origin_x = (origin & 0xffff) as i32;
    let origin_y = (origin >> 16) as i32;
    if region == 0 || buf_w <= 0 || buf_h <= 0 {
        return 0;
    }
    ensure_window(state);
    let cols = i32::from(state.console.cols);
    let rows = i32::from(state.console.rows);
    let left = i32::from(machine.read::<i16>(region));
    let top = i32::from(machine.read::<i16>(region + 2));
    let right = i32::from(machine.read::<i16>(region + 4));
    let bottom = i32::from(machine.read::<i16>(region + 6));
    if right < left || bottom < top {
        return 0;
    }
    let src_x0 = origin_x;
    let src_y0 = origin_y;
    let clip_left = left.clamp(0, cols);
    let clip_top = top.clamp(0, rows);
    let clip_right = right.clamp(-1, cols - 1);
    let clip_bottom = bottom.clamp(-1, rows - 1);
    if clip_right >= clip_left && clip_bottom >= clip_top {
        for row in clip_top..=clip_bottom {
            for col in clip_left..=clip_right {
                let sx = src_x0 + (col - left);
                let sy = src_y0 + (row - top);
                if sx < 0 || sy < 0 || sx >= buf_w || sy >= buf_h {
                    continue;
                }
                let guest = buffer + (sy as usize * buf_w as usize + sx as usize) * 4;
                let screen = (row as usize * cols as usize + col as usize) * 2;
                if read {
                    machine.write::<u16>(guest, u16::from(state.console.cells[screen]));
                    machine.write::<u16>(guest + 2, u16::from(state.console.cells[screen + 1]));
                } else {
                    state.console.cells[screen] = machine.read::<u16>(guest) as u8;
                    state.console.cells[screen + 1] = machine.read::<u16>(guest + 2) as u8;
                }
            }
        }
    }
    machine.write::<i16>(region, clip_left as i16);
    machine.write::<i16>(region + 2, clip_top as i16);
    machine.write::<i16>(region + 4, clip_right as i16);
    machine.write::<i16>(region + 6, clip_bottom as i16);
    if !read {
        paint(state);
    }
    1
}

pub(super) fn write_console_text<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    src: usize,
    len: usize,
) {
    ensure_window(state);
    for i in 0..len {
        let byte = machine.read::<u8>(src + i);
        match byte {
            b'\r' => state.console.cursor_x = 0,
            b'\n' => {
                state.console.cursor_x = 0;
                if state.console.cursor_y + 1 < state.console.rows {
                    state.console.cursor_y += 1;
                }
            }
            ch => {
                let x = state.console.cursor_x;
                let y = state.console.cursor_y;
                let cols = state.console.cols;
                let at = (y as usize * cols as usize + x as usize) * 2;
                if at + 1 < state.console.cells.len() {
                    state.console.cells[at] = ch;
                    state.console.cells[at + 1] = state.console.attr as u8;
                }
                if x + 1 < cols {
                    state.console.cursor_x = x + 1;
                } else {
                    state.console.cursor_x = 0;
                    if y + 1 < state.console.rows {
                        state.console.cursor_y = y + 1;
                    }
                }
            }
        }
    }
    paint(state);
}

fn write_chars<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    src: usize,
    len: u32,
    coord: u32,
    written: usize,
    attrs: bool,
) -> u32 {
    ensure_window(state);
    let x = (coord & 0xffff) as u16;
    let y = (coord >> 16) as u16;
    let start = y as usize * state.console.cols as usize + x as usize;
    let room = state.console.cols as usize * state.console.rows as usize;
    let n = (len as usize).min(room.saturating_sub(start));
    for i in 0..n {
        let at = (start + i) * 2;
        if attrs {
            state.console.cells[at + 1] = machine.read::<u16>(src + i * 2) as u8;
        } else {
            state.console.cells[at] = machine.read::<u8>(src + i);
        }
    }
    if written != 0 {
        machine.write::<u32>(written, n as u32);
    }
    paint(state);
    1
}

fn fill_cells<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    value: u8,
    len: u32,
    coord: u32,
    written: usize,
    attrs: bool,
) -> u32 {
    ensure_window(state);
    let x = (coord & 0xffff) as u16;
    let y = (coord >> 16) as u16;
    let start = y as usize * state.console.cols as usize + x as usize;
    let room = state.console.cols as usize * state.console.rows as usize;
    let n = (len as usize).min(room.saturating_sub(start));
    for i in 0..n {
        let at = (start + i) * 2;
        if attrs {
            state.console.cells[at + 1] = value;
        } else {
            state.console.cells[at] = value;
        }
    }
    if written != 0 {
        machine.write::<u32>(written, n as u32);
    }
    paint(state);
    1
}

pub(super) fn read_input<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    buf: usize,
    count: u32,
    read: usize,
    consume: bool,
) -> u32 {
    if consume && state.console.input.is_empty() {
        state.console.hold = true;
        return 0;
    }
    let n = (count as usize).min(state.console.input.len()).min(16);
    for i in 0..n {
        let key = &state.console.input[i];
        let at = buf + i * 20;
        machine.write::<u16>(at, 1);
        machine.write::<u32>(at + 4, u32::from(key.down));
        machine.write::<u16>(at + 8, 1);
        machine.write::<u16>(at + 10, key.vk);
        machine.write::<u16>(at + 12, key.scan);
        machine.write::<u16>(at + 14, u16::from(key.ascii));
        machine.write::<u32>(at + 16, 0);
    }
    if consume {
        state.console.input.drain(..n);
    }
    if read != 0 {
        machine.write::<u32>(read, n as u32);
    }
    1
}

fn read_console_text<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    buf: usize,
    cap: u32,
    read: usize,
) -> u32 {
    let mut n = 0;
    while n < cap as usize {
        let Some(pos) = state.console.input.iter().position(|key| key.down && key.ascii != 0) else {
            break;
        };
        let ascii = state.console.input[pos].ascii;
        state.console.input.remove(pos);
        machine.write::<u8>(buf + n, ascii);
        n += 1;
        if ascii == b'\r' || ascii == b'\n' {
            break;
        }
    }
    if read != 0 {
        machine.write::<u32>(read, n as u32);
    }
    1
}

fn current_dos(state: &WindowsState) -> Vec<u8> {
    if state.cwd_len == 0 {
        return b"C:\\".to_vec();
    }
    guest_windows_path(state.cwd_str())
}

fn copy_dir<A: crate::Arch>(machine: &mut A, state: &WindowsState, cap: usize, out: usize, wide: bool) -> u32 {
    let text = current_dos(state);
    if wide {
        if out == 0 {
            return (text.len() + 1) as u32;
        }
        let n = text.len().min(cap.saturating_sub(1));
        for (i, &byte) in text[..n].iter().enumerate() {
            machine.write::<u16>(out + i * 2, u16::from(byte));
        }
        machine.write::<u16>(out + n * 2, 0);
        n as u32
    } else if out == 0 {
        (text.len() + 1) as u32
    } else {
        copy_ascii(machine, out, cap, &text)
    }
}

fn set_directory(state: &mut WindowsState, raw: &[u8]) -> u32 {
    let path = match windows_path(state, raw, false) {
        Ok(path) => path,
        Err(error) => return fail(state, error, 0),
    };
    if !crate::kernel::vfs::dir_exists(&path) && !crate::kernel::vfs::path_exists(&path) {
        return fail(state, ERROR_FILE_NOT_FOUND, 0);
    }
    let n = path.len().min(state.cwd.len());
    state.cwd[..n].copy_from_slice(&path[..n]);
    state.cwd_len = n;
    1
}

fn attributes(state: &mut WindowsState, raw: &[u8]) -> u32 {
    let mut text = raw.to_vec();
    while text.last().is_some_and(|b| *b == b'\\' || *b == b'/') {
        text.pop();
    }
    let path = match windows_path(state, &text, false) {
        Ok(path) => path,
        Err(_) => return fail(state, ERROR_FILE_NOT_FOUND, 0xffff_ffff),
    };
    if crate::kernel::vfs::dir_exists(&path) {
        return 0x10;
    }
    match crate::kernel::vfs::stat(&path, true) {
        Some(stat) if stat.is_dir => 0x10,
        Some(_) => 0x20,
        None => fail(state, ERROR_FILE_NOT_FOUND, 0xffff_ffff),
    }
}

fn split_pattern(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let Some(split) = raw.iter().rposition(|&b| b == b'\\' || b == b'/') else {
        return (Vec::new(), raw.to_vec());
    };
    let dir_end = if split == 2 && raw.get(1) == Some(&b':') { 3 } else { split };
    let dir = raw[..dir_end].to_vec();
    let name = if split + 1 == raw.len() { b"*".to_vec() } else { raw[split + 1..].to_vec() };
    (dir, name)
}

fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    if pattern == b"*" || pattern == b"*.*" {
        return true;
    }
    let mut pi = 0;
    let mut ni = 0;
    let mut star = None;
    let mut mark = 0;
    let pat = pattern;
    while ni < name.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi].eq_ignore_ascii_case(&name[ni])) {
            pi += 1;
            ni += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ni;
        } else if let Some(at) = star {
            pi = at + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn find_first<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, raw: &[u8], out: usize) -> u32 {
    let (dir, pattern) = split_pattern(raw);
    let path = match windows_path(state, &dir, false) {
        Ok(path) => path,
        Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
    };
    let mut entries = Vec::new();
    let dot = pattern == b".";
    let dotdot = pattern == b"..";
    if dot || pattern == b"*" || pattern == b"*.*" {
        entries.push(Entry { name: b".".to_vec(), short: b".".to_vec(), size: 0, dir: true });
    }
    if dotdot || pattern == b"*" || pattern == b"*.*" {
        entries.push(Entry { name: b"..".to_vec(), short: b"..".to_vec(), size: 0, dir: true });
    }
    if !dot && !dotdot {
        let mut index = 0;
        while let Some(item) = crate::kernel::vfs::readdir(&path, index) {
            index += 1;
            if item.name == b"." || item.name == b".." || !glob_match(&pattern, &item.name) {
                continue;
            }
            entries.push(Entry {
                name: item.name,
                short: item.short_name.map(|s| s.as_bytes().to_vec()).unwrap_or_default(),
                size: item.size,
                dir: item.is_dir,
            });
        }
    }
    if entries.is_empty() {
        return fail(state, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
    }
    write_find(machine, out, &entries[0]);
    let handle = state.next_find;
    state.next_find += 1;
    state.finds.push(Find { handle, entries, index: 1 });
    handle
}

fn find_next<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, handle: u32, out: usize) -> u32 {
    let Some(find) = state.finds.iter_mut().find(|find| find.handle == handle) else {
        return fail(state, ERROR_INVALID_HANDLE, 0);
    };
    if find.index >= find.entries.len() {
        return fail(state, 18, 0);
    }
    write_find(machine, out, &find.entries[find.index]);
    find.index += 1;
    1
}

fn write_find<A: crate::Arch>(machine: &mut A, out: usize, entry: &Entry) {
    machine.zero(out, 318);
    machine.write::<u32>(out, if entry.dir { 0x10 } else { 0x20 });
    machine.write::<u32>(out + 32, entry.size);
    let n = entry.name.len().min(259);
    machine.copy_to(out + 44, &entry.name[..n]);
    let s = entry.short.len().min(13);
    if s != 0 {
        machine.copy_to(out + 304, &entry.short[..s]);
    }
}

fn mutate_path<A: crate::Arch>(
    machine: &A,
    state: &mut WindowsState,
    regs: &Regs,
    name: &[u8],
) -> u32 {
    let wide = name.ends_with(b"W");
    let raw = if wide {
        w_string(machine, arg(machine, regs, 0))
    } else {
        c_string(machine, arg(machine, regs, 0))
    };
    let raw = match raw {
        Ok(v) => v,
        Err(error) => return fail(state, error, 0),
    };
    let create = name.starts_with(b"Create");
    let path = match windows_path(state, &raw, create) {
        Ok(path) => path,
        Err(error) => return fail(state, error, 0),
    };
    let rc = if name.starts_with(b"Delete") {
        crate::kernel::vfs::delete(&path)
    } else if name.starts_with(b"Remove") {
        crate::kernel::vfs::rmdir(&path)
    } else {
        crate::kernel::vfs::mkdir(&path)
    };
    if rc < 0 { 0 } else { 1 }
}

fn full_path<A: crate::Arch>(machine: &mut A, state: &WindowsState, regs: &Regs, wide: bool) -> u32 {
    let raw = if wide {
        w_string(machine, arg(machine, regs, 0))
    } else {
        c_string(machine, arg(machine, regs, 0))
    };
    let raw = match raw {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let absolute = full_windows_path(state, &raw);
    let cap = arg(machine, regs, 1) as usize;
    let buf = arg(machine, regs, 2) as usize;
    let part = arg(machine, regs, 3) as usize;
    let file = absolute.iter().rposition(|&b| b == b'\\').map(|n| n + 1).unwrap_or(0);
    if part != 0 && buf != 0 {
        let width = if wide { 2 } else { 1 };
        machine.write::<u32>(part, buf as u32 + (file * width) as u32);
    }
    if wide {
        copy_dir_bytes(machine, buf, cap, &absolute)
    } else {
        copy_ascii(machine, buf, cap, &absolute)
    }
}

fn copy_dir_bytes<A: crate::Arch>(machine: &mut A, out: usize, cap: usize, text: &[u8]) -> u32 {
    if cap == 0 || out == 0 {
        return (text.len() + 1) as u32;
    }
    let n = text.len().min(cap - 1);
    for (i, &byte) in text[..n].iter().enumerate() {
        machine.write::<u16>(out + i * 2, u16::from(byte));
    }
    machine.write::<u16>(out + n * 2, 0);
    n as u32
}

fn env_block<A: crate::Arch>(machine: &mut A, wide: bool) -> u32 {
    const ENV: usize = 0x7ff1_0000;
    let text = b"COMSPEC=C:\\RETROOS\\COMMAND.COM\0PATH=C:\\RETROOS;C:\\\0TEMP=C:\\TEMP\0\0";
    if !wide {
        machine.zero(ENV, 4096);
        machine.copy_to(ENV, text);
        machine.set_page_flags(ENV / 4096, 1, true, false);
        return ENV as u32;
    }
    for (i, &byte) in text.iter().enumerate() {
        machine.write::<u16>(ENV + 2048 + i * 2, u16::from(byte));
    }
    ENV as u32 + 2048
}

fn version<A: crate::Arch>(machine: &mut A, out: usize) -> u32 {
    let size = machine.read::<u32>(out);
    machine.zero(out, size.min(156) as usize);
    machine.write::<u32>(out, size);
    machine.write::<u32>(out + 4, 4);
    machine.write::<u32>(out + 8, 0);
    machine.write::<u32>(out + 12, 1381);
    machine.write::<u32>(out + 16, 2);
    1
}

fn taken<A: crate::Arch>(machine: &A, ptr: u32, count: i32, wide: bool) -> Vec<u8> {
    if count < 0 {
        return if wide { w_string(machine, ptr).unwrap_or_default() } else { c_string(machine, ptr).unwrap_or_default() };
    }
    let n = count as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let byte = if wide { machine.read::<u16>(ptr as usize + i * 2) as u8 } else { machine.read::<u8>(ptr as usize + i) };
        out.push(byte);
    }
    out
}

fn compare<A: crate::Arch>(machine: &A, regs: &Regs, wide: bool) -> u32 {
    let flags = arg(machine, regs, 1);
    let mut left = taken(machine, arg(machine, regs, 2), arg(machine, regs, 3) as i32, wide);
    let mut right = taken(machine, arg(machine, regs, 4), arg(machine, regs, 5) as i32, wide);
    if flags & 1 != 0 {
        for byte in left.iter_mut().chain(right.iter_mut()) {
            *byte = byte.to_ascii_uppercase();
        }
    }
    match left.cmp(&right) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Equal => 2,
        core::cmp::Ordering::Greater => 3,
    }
}

fn map_string<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let flags = arg(machine, regs, 1);
    let mut text = taken(machine, arg(machine, regs, 2), arg(machine, regs, 3) as i32, wide);
    if flags & 0x200 != 0 {
        for byte in &mut text { *byte = byte.to_ascii_uppercase(); }
    } else if flags & 0x100 != 0 {
        for byte in &mut text { *byte = byte.to_ascii_lowercase(); }
    }
    let dest = arg(machine, regs, 4) as usize;
    let cap = arg(machine, regs, 5) as usize;
    if dest == 0 || cap == 0 {
        return (text.len() + 1) as u32;
    }
    let n = text.len().min(cap);
    for (i, &byte) in text[..n].iter().enumerate() {
        if wide { machine.write::<u16>(dest + i * 2, u16::from(byte)); }
        else { machine.write::<u8>(dest + i, byte); }
    }
    n as u32
}

fn locale_info<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let kind = arg(machine, regs, 1) & 0xffff;
    let text: &[u8] = match kind {
        0x1004 => b"1252",
        0x1001 | 0x0001 => b"English",
        _ => b"",
    };
    if text.is_empty() {
        return 0;
    }
    let dest = arg(machine, regs, 2) as usize;
    let cap = arg(machine, regs, 3) as usize;
    if dest == 0 || cap == 0 {
        return (text.len() + 1) as u32;
    }
    if wide { copy_dir_bytes(machine, dest, cap, text) } else { copy_ascii(machine, dest, cap, text) + 0 }
}

fn string_type<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let (src, count, dest) = if wide {
        (arg(machine, regs, 1), arg(machine, regs, 2) as i32, arg(machine, regs, 3) as usize)
    } else {
        (arg(machine, regs, 2), arg(machine, regs, 3) as i32, arg(machine, regs, 4) as usize)
    };
    let text = taken(machine, src, count, wide);
    for (i, &byte) in text.iter().enumerate() {
        let mut kind = 0u16;
        if byte.is_ascii_uppercase() { kind |= 0x0001 | 0x0100; }
        if byte.is_ascii_lowercase() { kind |= 0x0002 | 0x0100; }
        if byte.is_ascii_digit() { kind |= 0x0004 | 0x0200; }
        if byte.is_ascii_whitespace() { kind |= 0x0008 | 0x0800; }
        if byte.is_ascii_punctuation() { kind |= 0x0010 | 0x0400; }
        if byte.is_ascii_control() { kind |= 0x0020; }
        machine.write::<u16>(dest + i * 2, kind);
    }
    1
}
