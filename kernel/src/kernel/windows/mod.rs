//! Native 32-bit Windows console personality.
//!
//! PE imports resolve against ordinary replacement DLLs. Their exported
//! functions are consecutive `INT 83h` gates; the personality implements the
//! Win32 calls and completes their stdcall returns.

extern crate alloc;

pub mod pe;

use alloc::{vec, vec::Vec};
use crate::Regs;
use crate::kernel::thread;

const GATE_VECTOR: u8 = 0x83;
const DLL_BASE_FIRST: u32 = 0x1000_0000;
const DLL_BASE_STRIDE: u32 = 0x0100_0000;
const STACK_TOP: u32 = 0xbff0_0000;
const USER_LIMIT: u32 = 0xc000_0000;
const TEB_BASE: u32 = 0x7ffd_e000;
const PEB_BASE: u32 = 0x7ffd_f000;
const PROCESS_DATA: u32 = 0x7ffd_c000;
const HEAP_BASE: u32 = 0x5000_0000;

const INVALID_HANDLE_VALUE: u32 = 0xffff_ffff;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_INVALID_PARAMETER: u32 = 87;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    CloseHandle, CreateEventA, CreateFileA, ExitProcess, FlushFileBuffers,
    GetACP, GetCPInfo, GetCommandLineA, GetCommandLineW, GetConsoleMode,
    GetCurrentThreadId, GetFileType, GetLastError, GetModuleFileNameA,
    GetModuleFileNameW, GetModuleHandleA, GetOEMCP, GetProcAddress,
    GetStdHandle, GetVersion, LoadLibraryA, MultiByteToWideChar,
    ReadConsoleInputA, ReadFile, SetConsoleCtrlHandler, SetConsoleMode,
    SetEnvironmentVariableA, SetFilePointer, SetStdHandle,
    SetUnhandledExceptionFilter, UnhandledExceptionFilter, VirtualAlloc,
    VirtualFree, VirtualQuery, WideCharToMultiByte, WriteConsoleA, WriteFile,
    CharUpperA,
}

#[derive(Clone, Copy)]
struct Gate { return_ip: u32, api: Api, arg_bytes: u32 }

struct Module { name: Vec<u8>, path: Vec<u8>, data: Vec<u8>, base: u32 }

pub struct WindowsState {
    gates: Vec<Gate>,
    ldt: Vec<u64>,
    modules: Vec<Module>,
    allocations: Vec<(u32, u32)>,
    heap_next: u32,
    last_error: u32,
    pub cwd: [u8; 128],
    pub cwd_len: usize,
    exec_path: [u8; 164],
    exec_path_len: usize,
    command_line_a: u32,
    command_line_w: u32,
    next_object: u32,
    stack_base: u32,
    stack_size: u32,
}

impl WindowsState {
    fn new() -> Self {
        Self {
            gates: Vec::new(), ldt: vec![0], modules: Vec::new(), allocations: Vec::new(),
            heap_next: HEAP_BASE, last_error: 0, cwd: [0; 128], cwd_len: 0,
            exec_path: [0; 164], exec_path_len: 0, command_line_a: 0,
            command_line_w: 0, next_object: 0x10000,
            stack_base: 0, stack_size: 0,
        }
    }
    pub fn cwd_str(&self) -> &[u8] { &self.cwd[..self.cwd_len] }
    pub fn exec_path_str(&self) -> &[u8] { &self.exec_path[..self.exec_path_len] }
    pub fn on_resume<A: crate::Arch>(&mut self, machine: &mut A) { machine.load_ldt(&self.ldt); }
    pub fn process_key(&self, fds: &[thread::FdKind; thread::MAX_FDS], scancode: u8) {
        if !crate::kernel::keyboard::update_key_state(scancode) { return; }
        let c = crate::kernel::keyboard::scancode_to_ascii(scancode);
        if c != 0 { if let thread::FdKind::PipeRead(p) = fds[0] { crate::kernel::kpipe::write(p, &[c]); } }
    }
}

fn descriptor(base: u32, limit: u32) -> u64 {
    let mut d = (limit & 0xffff) as u64;
    d |= ((base & 0xffff) as u64) << 16;
    d |= (((base >> 16) & 0xff) as u64) << 32;
    d |= 0xf2u64 << 40;
    d |= ((((limit >> 16) & 0x0f) as u64) | 0x40) << 48;
    d | (((base >> 24) & 0xff) as u64) << 56
}

fn module_name(name: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    out.make_ascii_uppercase();
    if !out.ends_with(b".DLL") { out.extend_from_slice(b".DLL"); }
    out
}

fn dirname(path: &[u8]) -> &[u8] {
    path.iter().rposition(|&b| b == b'/').map_or(b"", |n| &path[..n])
}

fn join(dir: &[u8], file: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + 1 + file.len());
    out.extend_from_slice(dir);
    if !dir.is_empty() && dir.last() != Some(&b'/') { out.push(b'/'); }
    out.extend_from_slice(file);
    out
}

fn find_module(modules: &[Module], name: &[u8]) -> Option<usize> {
    let name = module_name(name);
    modules.iter().position(|m| m.name.eq_ignore_ascii_case(&name))
}

fn load_dependency(name: &[u8], importer: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let file = module_name(name);
    let system = join(crate::kernel::dos::c_root(), b"WINDOWS/SYSTEM32");
    for path in [join(dirname(importer), &file), join(&system, &file)] {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&path) { return Ok((path, data)); }
    }
    Err(2)
}

fn map_module<A: crate::Arch>(machine: &mut A, module: &Module) -> Result<(), i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    let end = module.base.checked_add(image.header.size_image).ok_or(8)?;
    if end >= USER_LIMIT { return Err(8); }
    machine.zero(module.base as usize, image.header.size_image as usize);
    let headers = (image.header.size_headers as usize).min(module.data.len());
    machine.copy_to(module.base as usize, &module.data[..headers]);
    for section in image.sections().map_err(|_| 8)? {
        let size = (section.raw_size as usize).min(section.virtual_size.max(section.raw_size) as usize);
        if size != 0 {
            let raw = section.raw_offset as usize;
            let bytes = module.data.get(raw..raw + size).ok_or(8)?;
            machine.copy_to((module.base + section.rva) as usize, bytes);
        }
    }
    let delta = module.base.wrapping_sub(image.header.image_base);
    if delta != 0 {
        for (page, entries) in image.reloc_blocks().map_err(|_| 8)? {
            for entry in entries {
                match entry >> 12 {
                    0 => {}
                    3 => {
                        let at = module.base.checked_add(page).and_then(|v| v.checked_add((entry & 0xfff) as u32)).ok_or(8)? as usize;
                        machine.write::<u32>(at, machine.read::<u32>(at).wrapping_add(delta));
                    }
                    _ => return Err(8),
                }
            }
        }
    }
    Ok(())
}

fn protect_module<A: crate::Arch>(machine: &mut A, module: &Module) -> Result<(), i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    for section in image.sections().map_err(|_| 8)? {
        let size = section.virtual_size.max(section.raw_size) as usize;
        if size == 0 { continue; }
        let base = (module.base + section.rva) as usize;
        let pages = (base % 4096 + size).div_ceil(4096);
        machine.set_page_flags(base / 4096, pages,
            section.characteristics & 0x8000_0000 != 0,
            section.characteristics & 0x2000_0000 != 0);
    }
    Ok(())
}

fn resolve_export(module: &Module, symbol: &pe::ImportSymbol) -> Result<u32, i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    let export = image.exports().map_err(|_| 8)?.into_iter().find(|e| match symbol {
        pe::ImportSymbol::Name(n) => e.name.eq_ignore_ascii_case(n),
        pe::ImportSymbol::Ordinal(n) => e.ordinal == *n,
    }).ok_or(127)?;
    // Forwarded exports are deliberately outside the initial replacement-DLL surface.
    if export.rva >= image.header.export.rva
        && export.rva < image.header.export.rva.saturating_add(image.header.export.size) { return Err(127); }
    module.base.checked_add(export.rva).ok_or(8)
}

fn apply_imports<A: crate::Arch>(machine: &mut A, modules: &[Module], index: usize) -> Result<(), i32> {
    let image = pe::Image::parse(&modules[index].data).map_err(|_| 8)?;
    for import in image.imports().map_err(|_| 8)? {
        let target_index = find_module(modules, &import.module).ok_or(2)?;
        let address = resolve_export(&modules[target_index], &import.symbol)?;
        machine.write::<u32>((modules[index].base + import.iat_rva) as usize, address);
    }
    Ok(())
}

fn export_address(modules: &[Module], module: &[u8], name: &[u8]) -> Result<u32, i32> {
    let i = find_module(modules, module).ok_or(2)?;
    resolve_export(&modules[i], &pe::ImportSymbol::Name(name.to_vec()))
}

fn windows_path(state: &WindowsState, path: &[u8], create: bool) -> Result<Vec<u8>, u32> {
    if path.len() >= 2 && path[1] == b':' {
        let mut dos = path.to_vec();
        for b in &mut dos { if *b == b'/' { *b = b'\\'; } }
        let path = if create { crate::kernel::dos::dos_abs_to_vfs_create(&dos) }
            else { crate::kernel::dos::dos_abs_to_vfs(&dos) };
        return path.ok_or(ERROR_FILE_NOT_FOUND);
    }
    let mut p = path.to_vec();
    for b in &mut p { if *b == b'\\' { *b = b'/'; } }
    Ok(join(state.cwd_str(), &p))
}

fn guest_windows_path(path: &[u8]) -> Vec<u8> {
    let root = crate::kernel::dos::c_root();
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut out = b"C:\\".to_vec();
    out.extend(relative.iter().map(|&b| if b == b'/' { b'\\' } else { b }));
    out
}

pub fn exec_pe_into<A: crate::Arch>(
    machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize,
    data: Vec<u8>, path: &[u8], parent_cwd: &[u8], launcher: Option<thread::PersonalityName>,
) -> Result<(), i32> {
    let parsed_main = pe::Image::parse(&data).map_err(|_| 8)?;
    if parsed_main.is_dll() { return Err(8); }
    let main_header = parsed_main.header;
    let main_path = if launcher == Some(thread::PersonalityName::Dos) {
        crate::kernel::dos::dos_abs_to_vfs(path).unwrap_or_else(|| path.to_vec())
    } else { let mut b = [0u8; 164]; crate::kernel::exec::resolve_path(path, parent_cwd, &mut b).to_vec() };
    let mut modules = vec![Module { name: b"MAIN.EXE".to_vec(), path: main_path.clone(), data, base: main_header.image_base }];
    let mut i = 0;
    while i < modules.len() {
        let imports = pe::Image::parse(&modules[i].data).map_err(|_| 8)?.imports().map_err(|_| 8)?;
        for import in imports {
            if find_module(&modules, &import.module).is_some() { continue; }
            let (dll_path, dll_data) = load_dependency(&import.module, &modules[i].path)?;
            let image = pe::Image::parse(&dll_data).map_err(|_| 8)?;
            if !image.is_dll() { return Err(8); }
            let slot = modules.len() as u32;
            modules.push(Module { name: module_name(&import.module), path: dll_path, data: dll_data,
                base: DLL_BASE_FIRST.checked_add((slot - 1) * DLL_BASE_STRIDE).ok_or(8)? });
        }
        i += 1;
    }
    for module in &modules { map_module(machine, module)?; }
    for n in 0..modules.len() { apply_imports(machine, &modules, n)?; }

    let stack_size = main_header.stack_reserve.max(64 * 1024).next_multiple_of(4096);
    let stack_base = STACK_TOP.checked_sub(stack_size).ok_or(8)?;
    machine.zero(stack_base as usize, stack_size as usize);
    machine.set_page_flags(stack_base as usize / 4096, stack_size as usize / 4096, true, false);
    machine.zero(PROCESS_DATA as usize, 4096);
    machine.zero(TEB_BASE as usize, 4096);
    machine.zero(PEB_BASE as usize, 4096);
    machine.set_page_flags(PROCESS_DATA as usize / 4096, 1, true, false);
    machine.set_page_flags(TEB_BASE as usize / 4096, 1, true, false);
    machine.set_page_flags(PEB_BASE as usize / 4096, 1, true, false);

    machine.write::<u32>(TEB_BASE as usize, 0xffff_ffff); // SEH end marker
    machine.write::<u32>((TEB_BASE + 4) as usize, STACK_TOP);
    machine.write::<u32>((TEB_BASE + 8) as usize, stack_base);
    machine.write::<u32>((TEB_BASE + 0x18) as usize, TEB_BASE);
    machine.write::<u32>((TEB_BASE + 0x20) as usize, 1);
    machine.write::<u32>((TEB_BASE + 0x24) as usize, tid as u32 + 1);
    machine.write::<u32>((TEB_BASE + 0x30) as usize, PEB_BASE);
    machine.write::<u32>((PEB_BASE + 8) as usize, modules[0].base);
    machine.write::<u32>((PEB_BASE + 0x10) as usize, PROCESS_DATA);

    let win_path = guest_windows_path(&main_path);
    let cmd_a = PROCESS_DATA + 0x200;
    machine.copy_to(cmd_a as usize, &win_path);
    machine.write::<u8>((cmd_a + win_path.len() as u32) as usize, 0);
    let cmd_w = PROCESS_DATA + 0x400;
    for (n, &b) in win_path.iter().enumerate() { machine.write::<u16>(cmd_w as usize + n * 2, b as u16); }
    machine.write::<u16>(cmd_w as usize + win_path.len() * 2, 0);

    for module in &modules { protect_module(machine, module)?; }
    let stack = STACK_TOP - 4;
    machine.write::<u32>(stack as usize, 0);
    let entry = modules[0].base.checked_add(main_header.entry_rva).ok_or(8)?;
    let current = thread::get_thread(threads, tid).ok_or(8)?;
    thread::init_process_thread(current, entry, stack);

    let mut state = WindowsState::new();
    state.ldt.push(descriptor(TEB_BASE, 4095));
    current.kernel.vcpu.regs.fs = 0x0f;
    state.command_line_a = cmd_a; state.command_line_w = cmd_w;
    state.stack_base = stack_base; state.stack_size = stack_size;
    state.exec_path_len = main_path.len().min(state.exec_path.len());
    state.exec_path[..state.exec_path_len].copy_from_slice(&main_path[..state.exec_path_len]);
    let cwd = dirname(&main_path); state.cwd_len = cwd.len().min(state.cwd.len());
    state.cwd[..state.cwd_len].copy_from_slice(&cwd[..state.cwd_len]);

    let specs: &[(&[u8], &[u8], Api, u32)] = &[
        (b"KERNEL32", b"CloseHandle", Api::CloseHandle, 4),
        (b"KERNEL32", b"CreateEventA", Api::CreateEventA, 16),
        (b"KERNEL32", b"CreateFileA", Api::CreateFileA, 28),
        (b"KERNEL32", b"ExitProcess", Api::ExitProcess, 4),
        (b"KERNEL32", b"FlushFileBuffers", Api::FlushFileBuffers, 4),
        (b"KERNEL32", b"GetACP", Api::GetACP, 0),
        (b"KERNEL32", b"GetCPInfo", Api::GetCPInfo, 8),
        (b"KERNEL32", b"GetCommandLineA", Api::GetCommandLineA, 0),
        (b"KERNEL32", b"GetCommandLineW", Api::GetCommandLineW, 0),
        (b"KERNEL32", b"GetConsoleMode", Api::GetConsoleMode, 8),
        (b"KERNEL32", b"GetCurrentThreadId", Api::GetCurrentThreadId, 0),
        (b"KERNEL32", b"GetFileType", Api::GetFileType, 4),
        (b"KERNEL32", b"GetLastError", Api::GetLastError, 0),
        (b"KERNEL32", b"GetModuleFileNameA", Api::GetModuleFileNameA, 12),
        (b"KERNEL32", b"GetModuleFileNameW", Api::GetModuleFileNameW, 12),
        (b"KERNEL32", b"GetModuleHandleA", Api::GetModuleHandleA, 4),
        (b"KERNEL32", b"GetOEMCP", Api::GetOEMCP, 0),
        (b"KERNEL32", b"GetProcAddress", Api::GetProcAddress, 8),
        (b"KERNEL32", b"GetStdHandle", Api::GetStdHandle, 4),
        (b"KERNEL32", b"GetVersion", Api::GetVersion, 0),
        (b"KERNEL32", b"LoadLibraryA", Api::LoadLibraryA, 4),
        (b"KERNEL32", b"MultiByteToWideChar", Api::MultiByteToWideChar, 24),
        (b"KERNEL32", b"ReadConsoleInputA", Api::ReadConsoleInputA, 16),
        (b"KERNEL32", b"ReadFile", Api::ReadFile, 20),
        (b"KERNEL32", b"SetConsoleCtrlHandler", Api::SetConsoleCtrlHandler, 8),
        (b"KERNEL32", b"SetConsoleMode", Api::SetConsoleMode, 8),
        (b"KERNEL32", b"SetEnvironmentVariableA", Api::SetEnvironmentVariableA, 8),
        (b"KERNEL32", b"SetFilePointer", Api::SetFilePointer, 16),
        (b"KERNEL32", b"SetStdHandle", Api::SetStdHandle, 8),
        (b"KERNEL32", b"SetUnhandledExceptionFilter", Api::SetUnhandledExceptionFilter, 4),
        (b"KERNEL32", b"UnhandledExceptionFilter", Api::UnhandledExceptionFilter, 4),
        (b"KERNEL32", b"VirtualAlloc", Api::VirtualAlloc, 16),
        (b"KERNEL32", b"VirtualFree", Api::VirtualFree, 12),
        (b"KERNEL32", b"VirtualQuery", Api::VirtualQuery, 12),
        (b"KERNEL32", b"WideCharToMultiByte", Api::WideCharToMultiByte, 32),
        (b"KERNEL32", b"WriteConsoleA", Api::WriteConsoleA, 20),
        (b"KERNEL32", b"WriteFile", Api::WriteFile, 20),
        (b"USER32", b"CharUpperA", Api::CharUpperA, 4),
    ];
    for &(module, name, api, arg_bytes) in specs {
        let Some(_) = find_module(&modules, module) else { continue; };
        let address = export_address(&modules, module, name)?;
        state.gates.push(Gate { return_ip: address + 2, api, arg_bytes });
    }
    state.modules = modules;
    state.on_resume(machine);
    current.personality = thread::Personality::Windows(state);
    Ok(())
}

fn arg<A: crate::Arch>(machine: &A, regs: &Regs, n: usize) -> u32 {
    machine.read::<u32>(regs.sp() as usize + 4 + n * 4)
}

fn c_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    if address == 0 { return Err(ERROR_INVALID_PARAMETER); }
    let mut out = Vec::new();
    for i in 0..32768 { let b = machine.read::<u8>(address as usize + i); if b == 0 { return Ok(out); } out.push(b); }
    Err(ERROR_INVALID_PARAMETER)
}

fn finish<A: crate::Arch>(machine: &A, regs: &mut Regs, gate: Gate, result: u32) {
    let ret = machine.read::<u32>(regs.sp() as usize);
    regs.rax = result as u64;
    regs.frame.rip = ret as u64;
    regs.frame.rsp += 4 + gate.arg_bytes as u64;
}

fn fail(state: &mut WindowsState, error: u32, result: u32) -> u32 { state.last_error = error; result }

fn io_write<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, handle: usize, ptr: usize, len: usize, actual: usize) -> u32 {
    if handle >= thread::MAX_FDS { return 0; }
    let mut data = vec![0; len]; machine.copy_from(ptr, &mut data);
    let n = match kt.fds[handle] {
        thread::FdKind::ConsoleOut => { for &b in &data { crate::term::putchar(b); } crate::kernel::term::mark_dirty(); len as i32 }
        thread::FdKind::PipeWrite(p) => crate::kernel::kpipe::write(p, &data),
        thread::FdKind::Vfs(h) => crate::kernel::vfs::write_by_handle(machine, h, &data),
        _ => -1,
    };
    if n < 0 { return 0; }
    if actual != 0 { machine.write::<u32>(actual, n as u32); }
    1
}

fn io_read<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, handle: usize, ptr: usize, len: usize, actual: usize) -> u32 {
    if handle >= thread::MAX_FDS { return 0; }
    let mut data = vec![0; len];
    let n = match kt.fds[handle] {
        thread::FdKind::Vfs(h) => crate::kernel::vfs::read_by_handle(h, &mut data),
        thread::FdKind::PipeRead(p) => crate::kernel::kpipe::read(p, &mut data) as i32,
        _ => -1,
    };
    if n < 0 { return 0; }
    machine.copy_to(ptr, &data[..n as usize]);
    if actual != 0 { machine.write::<u32>(actual, n as u32); }
    1
}

fn copy_ascii<A: crate::Arch>(machine: &mut A, out: usize, cap: usize, text: &[u8]) -> u32 {
    if cap == 0 { return 0; }
    let n = text.len().min(cap - 1); machine.copy_to(out, &text[..n]); machine.write::<u8>(out + n, 0); n as u32
}

fn dispatch<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, state: &mut WindowsState, regs: &mut Regs, api: Api) -> u32 {
    match api {
        Api::GetLastError => state.last_error,
        Api::GetACP => 1252,
        Api::GetOEMCP => 437,
        Api::GetVersion => 0x0000_0004,
        Api::GetCurrentThreadId => (kt.tid + 1) as u32,
        Api::GetCommandLineA => state.command_line_a,
        Api::GetCommandLineW => state.command_line_w,
        Api::GetStdHandle => match arg(machine, regs, 0) as i32 { -10 => 0, -11 => 1, -12 => 2, _ => INVALID_HANDLE_VALUE },
        Api::SetStdHandle => {
            let slot = match arg(machine, regs, 0) as i32 { -10 => 0, -11 => 1, -12 => 2, _ => return fail(state, ERROR_INVALID_PARAMETER, 0) };
            let source = arg(machine, regs, 1) as usize;
            if source >= thread::MAX_FDS { fail(state, ERROR_INVALID_HANDLE, 0) } else { kt.fds[slot] = kt.fds[source]; 1 }
        }
        Api::GetFileType => {
            let h = arg(machine, regs, 0) as usize;
            if h >= thread::MAX_FDS { return fail(state, ERROR_INVALID_HANDLE, 0); }
            match kt.fds[h] { thread::FdKind::Vfs(_) => 1, thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => 3, thread::FdKind::ConsoleOut => 2, _ => 0 }
        }
        Api::WriteFile | Api::WriteConsoleA => io_write(machine, kt, arg(machine, regs, 0) as usize,
            arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize, arg(machine, regs, 3) as usize),
        Api::ReadFile => io_read(machine, kt, arg(machine, regs, 0) as usize,
            arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize, arg(machine, regs, 3) as usize),
        Api::CreateFileA => {
            let disposition = arg(machine, regs, 4);
            let create = matches!(disposition, 1 | 2 | 4 | 5);
            let raw = match c_string(machine, arg(machine, regs, 0)) { Ok(v) => v, Err(e) => return fail(state, e, INVALID_HANDLE_VALUE) };
            let path = match windows_path(state, &raw, create) { Ok(v) => v, Err(e) => return fail(state, e, INVALID_HANDLE_VALUE) };
            let existed = crate::kernel::vfs::path_exists(&path);
            let vh = match disposition {
                1 if existed => return fail(state, 80, INVALID_HANDLE_VALUE),
                1 | 2 => crate::kernel::vfs::create_to_handle(&path),
                3 if existed => crate::kernel::vfs::open_to_handle(&path),
                4 if existed => crate::kernel::vfs::open_to_handle(&path),
                4 => crate::kernel::vfs::create_to_handle(&path),
                5 if existed => crate::kernel::vfs::create_to_handle(&path),
                _ => return fail(state, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE),
            };
            if vh < 0 { return fail(state, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE); }
            let Some(fd) = kt.alloc_fd(3) else { crate::kernel::vfs::close_vfs_handle(vh); return fail(state, 4, INVALID_HANDLE_VALUE); };
            kt.fds[fd] = thread::FdKind::Vfs(vh); state.last_error = if existed { 183 } else { 0 }; fd as u32
        }
        Api::CloseHandle => {
            let h = arg(machine, regs, 0);
            if h >= 0x10000 { return 1; }
            let h = h as usize;
            if h >= thread::MAX_FDS || kt.fds[h].is_none() { fail(state, ERROR_INVALID_HANDLE, 0) } else { kt.close_fd(h); 1 }
        }
        Api::FlushFileBuffers => 1,
        Api::SetFilePointer => {
            let h = arg(machine, regs, 0) as usize;
            if h >= thread::MAX_FDS { return fail(state, ERROR_INVALID_HANDLE, INVALID_HANDLE_VALUE); }
            let thread::FdKind::Vfs(vh) = kt.fds[h] else { return fail(state, ERROR_INVALID_HANDLE, INVALID_HANDLE_VALUE); };
            let high_ptr = arg(machine, regs, 2) as usize;
            if high_ptr != 0 && machine.read::<u32>(high_ptr) != 0 { return fail(state, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE); }
            let pos = crate::kernel::vfs::seek_by_handle(vh, arg(machine, regs, 1) as i32, arg(machine, regs, 3) as i32);
            if pos < 0 { fail(state, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE) } else { if high_ptr != 0 { machine.write::<u32>(high_ptr, 0); } pos as u32 }
        }
        Api::VirtualAlloc => {
            let requested = arg(machine, regs, 0);
            let size = arg(machine, regs, 1).max(1).next_multiple_of(4096);
            let base = if requested != 0 { requested & !4095 } else { state.heap_next };
            let Some(end) = base.checked_add(size) else { return fail(state, ERROR_NOT_ENOUGH_MEMORY, 0); };
            if end >= USER_LIMIT { return fail(state, ERROR_NOT_ENOUGH_MEMORY, 0); }
            if requested == 0 { state.heap_next = end; }
            machine.zero(base as usize, size as usize); machine.set_page_flags(base as usize / 4096, size as usize / 4096, true, false);
            state.allocations.push((base, size)); base
        }
        Api::VirtualFree => { let base = arg(machine, regs, 0); if let Some(n) = state.allocations.iter().position(|&(a, _)| a == base) { state.allocations.swap_remove(n); 1 } else { fail(state, ERROR_INVALID_PARAMETER, 0) } }
        Api::VirtualQuery => {
            let address = arg(machine, regs, 0); let out = arg(machine, regs, 1) as usize; let len = arg(machine, regs, 2);
            if len < 28 { return 0; }
            let (base, size) = if address >= state.stack_base && address < state.stack_base + state.stack_size {
                (state.stack_base, state.stack_size)
            } else if let Some(&(base, size)) = state.allocations.iter().find(|&&(base, size)| address >= base && address < base + size) {
                (base, size)
            } else {
                (address & !4095, 4096)
            };
            machine.write::<u32>(out, base); machine.write::<u32>(out + 4, base);
            machine.write::<u32>(out + 8, 0x04); machine.write::<u32>(out + 12, size);
            machine.write::<u32>(out + 16, 0x1000); machine.write::<u32>(out + 20, 0x04); machine.write::<u32>(out + 24, 0x20000); 28
        }
        Api::GetModuleHandleA | Api::LoadLibraryA => {
            let p = arg(machine, regs, 0);
            if p == 0 { state.modules[0].base } else {
                let name = match c_string(machine, p) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
                if let Some(n) = find_module(&state.modules, &name) {
                    state.modules[n].base
                } else {
                    fail(state, 126, 0)
                }
            }
        }
        Api::GetProcAddress => {
            let base = arg(machine, regs, 0); let p = arg(machine, regs, 1);
            let Some(module) = state.modules.iter().find(|m| m.base == base) else { return fail(state, 126, 0); };
            let symbol = if p <= 0xffff { pe::ImportSymbol::Ordinal(p as u16) } else { match c_string(machine, p) { Ok(n) => pe::ImportSymbol::Name(n), Err(e) => return fail(state, e, 0) } };
            resolve_export(module, &symbol).unwrap_or_else(|_| fail(state, 127, 0))
        }
        Api::GetModuleFileNameA => {
            let module = arg(machine, regs, 0); let path = if module == 0 { &state.modules[0].path } else { match state.modules.iter().find(|m| m.base == module) { Some(m) => &m.path, None => return fail(state, 126, 0) } };
            copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize, &guest_windows_path(path))
        }
        Api::GetModuleFileNameW => {
            let module = arg(machine, regs, 0); let path = if module == 0 { &state.modules[0].path } else { match state.modules.iter().find(|m| m.base == module) { Some(m) => &m.path, None => return fail(state, 126, 0) } };
            let text = guest_windows_path(path); let out = arg(machine, regs, 1) as usize; let cap = arg(machine, regs, 2) as usize;
            if cap == 0 { return 0; } let n = text.len().min(cap - 1); for (i, &b) in text[..n].iter().enumerate() { machine.write::<u16>(out + i * 2, b as u16); } machine.write::<u16>(out + n * 2, 0); n as u32
        }
        Api::GetCPInfo => { let out = arg(machine, regs, 1) as usize; machine.zero(out, 20); machine.write::<u32>(out, 1); machine.write::<u8>(out + 4, b'?'); 1 }
        Api::MultiByteToWideChar => {
            let input = arg(machine, regs, 2) as usize; let count = arg(machine, regs, 3) as i32; let out = arg(machine, regs, 4) as usize; let cap = arg(machine, regs, 5) as usize;
            let n = if count < 0 { c_string(machine, input as u32).map_or(0, |v| v.len() + 1) } else { count as usize };
            if out == 0 { return n as u32; } let written = n.min(cap); for i in 0..written { machine.write::<u16>(out + i * 2, machine.read::<u8>(input + i) as u16); } written as u32
        }
        Api::WideCharToMultiByte => {
            let input = arg(machine, regs, 2) as usize; let count = arg(machine, regs, 3) as i32; let out = arg(machine, regs, 4) as usize; let cap = arg(machine, regs, 5) as usize;
            let n = if count < 0 { let mut n = 0; while n < 32768 && machine.read::<u16>(input + n * 2) != 0 { n += 1; } n + 1 } else { count as usize };
            if out == 0 { return n as u32; } let written = n.min(cap); for i in 0..written { machine.write::<u8>(out + i, machine.read::<u16>(input + i * 2) as u8); } written as u32
        }
        Api::GetConsoleMode => { machine.write::<u32>(arg(machine, regs, 1) as usize, 3); 1 }
        Api::SetConsoleMode | Api::SetConsoleCtrlHandler | Api::SetEnvironmentVariableA => 1,
        Api::SetUnhandledExceptionFilter => 0,
        Api::UnhandledExceptionFilter => 1,
        Api::CreateEventA => { let h = state.next_object; state.next_object += 1; h }
        Api::ReadConsoleInputA => fail(state, ERROR_INVALID_HANDLE, 0),
        Api::CharUpperA => {
            let p = arg(machine, regs, 0);
            if p <= 0xffff { (p as u8).to_ascii_uppercase() as u32 } else { let mut at = p as usize; loop { let b = machine.read::<u8>(at); if b == 0 { break; } machine.write::<u8>(at, b.to_ascii_uppercase()); at += 1; } p }
        }
        Api::ExitProcess => unreachable!(),
    }
}

pub fn handle_event<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, state: &mut WindowsState, regs: &mut Regs, event: crate::KernelEvent) -> thread::KernelAction {
    match event {
        crate::KernelEvent::Irq => thread::KernelAction::Done,
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let Some(gate) = state.gates.iter().copied().find(|g| g.return_ip == regs.ip32()) else {
                crate::println!("Windows: invalid API gate at {:#x}", regs.ip32()); return thread::KernelAction::Exit(-1);
            };
            if gate.api == Api::ExitProcess { return thread::KernelAction::Exit(arg(machine, regs, 0) as i32); }
            let result = dispatch(machine, kt, state, regs, gate.api);
            finish(machine, regs, gate, result); thread::KernelAction::Done
        }
        crate::KernelEvent::PageFault { .. } => unreachable!("page faults are handled by the event loop"),
        _ => { crate::println!("Windows: unhandled event {:?} at {:#x}", event, regs.ip32()); thread::KernelAction::Exit(-1) }
    }
}
