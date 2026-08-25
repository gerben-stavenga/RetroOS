//! Native 32-bit Windows console personality.
//!
//! PE imports resolve against ordinary replacement DLLs. Their exported
//! functions are consecutive `INT 83h` gates; the personality implements the
//! Win32 calls and completes their stdcall returns.

extern crate alloc;

pub mod pe;
pub mod ne;
mod win16;

use crate::Regs;
use crate::kernel::thread;
use alloc::{vec, vec::Vec};

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
    CloseHandle,
    CreateEventA,
    CreateFileA,
    ExitProcess,
    FlushFileBuffers,
    GetACP,
    GetCPInfo,
    GetCommandLineA,
    GetCommandLineW,
    GetConsoleMode,
    GetCurrentThreadId,
    GetFileType,
    GetLastError,
    GetModuleFileNameA,
    GetModuleFileNameW,
    GetModuleHandleA,
    GetOEMCP,
    GetProcAddress,
    GetModuleHandleW,
    GetStartupInfoA,
    GetTickCount64,
    GetStdHandle,
    GetVersion,
    LoadLibraryA,
    MultiByteToWideChar,
    ReadConsoleInputA,
    ReadFile,
    SetConsoleCtrlHandler,
    SetConsoleMode,
    SetEnvironmentVariableA,
    SetFilePointer,
    SetStdHandle,
    SetUnhandledExceptionFilter,
    UnhandledExceptionFilter,
    VirtualAlloc,
    VirtualFree,
    VirtualQuery,
    WideCharToMultiByte,
    WriteConsoleA,
    WriteFile,
    CharUpperA,
    LstrcpyW,
    LstrlenW,
    RegisterClassW,
    CreateWindowExW,
    ShowWindow,
    UpdateWindow,
    InvalidateRect,
    GetMessageW,
    PeekMessageW,
    TranslateMessage,
    DispatchMessageW,
    PostMessageW,
    PostQuitMessage,
    DefWindowProcW,
    RetroWndProcReturn,
    GetClientRect,
    BeginPaint,
    EndPaint,
    GetDC,
    ReleaseDC,
    FillRect,
    DrawEdge,
    GetSysColorBrush,
    GetSystemMetrics,
    SetRect,
    InflateRect,
    OffsetRect,
    PtInRect,
    MoveWindow,
    CreateCompatibleDC,
    CreateCompatibleBitmap,
    SelectObject,
    BitBlt,
    CreateSolidBrush,
    CreatePen,
    DeleteObject,
    DeleteDC,
    GetStockObject,
    MoveToEx,
    LineTo,
    Ellipse,
    Polygon,
    SetBkColor,
    SetTextColor,
    TextOutW,
    GetTextExtentPoint32W,
    Stub(u32),
}

#[derive(Clone, Copy)]
struct Gate {
    return_ip: u32,
    api: Api,
    arg_bytes: u32,
    name: &'static [u8],
}

struct Module {
    name: Vec<u8>,
    path: Vec<u8>,
    data: Vec<u8>,
    base: u32,
}

#[derive(Clone)]
struct WindowClass {
    name: Vec<u8>,
    wndproc: u32,
    background: u32,
}

#[derive(Clone, Copy)]
struct Message {
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
}

struct Window {
    hwnd: u32,
    parent: u32,
    wndproc: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    visible: bool,
    pixels: Vec<u8>,
}

enum GdiObject {
    Bitmap {
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    },
    Brush(u32),
    Pen(u32),
    Font,
}

struct DeviceContext {
    handle: u32,
    bitmap: Option<u32>,
    x: i32,
    y: i32,
    pen: u32,
    brush: u32,
    font: u32,
    bk: u32,
    text: u32,
}

#[derive(Clone, Copy)]
struct Callback {
    gate: Gate,
}

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
    classes: Vec<WindowClass>,
    windows: Vec<Window>,
    messages: Vec<Message>,
    callback: Option<Callback>,
    callback_return: u32,
    quit: bool,
    paint_dc: u32,
    dirty: bool,
    cursor_dirty: bool,
    paint_hwnd: u32,
    focus_hwnd: u32,
    gdi_objects: Vec<(u32, GdiObject)>,
    dcs: Vec<DeviceContext>,
    mouse_x: i32,
    mouse_y: i32,
    mouse_buttons: u8,
    win16: Option<win16::State>,
}

impl WindowsState {
    fn new() -> Self {
        Self {
            gates: Vec::new(),
            ldt: vec![0],
            modules: Vec::new(),
            allocations: Vec::new(),
            heap_next: HEAP_BASE,
            last_error: 0,
            cwd: [0; 128],
            cwd_len: 0,
            exec_path: [0; 164],
            exec_path_len: 0,
            command_line_a: 0,
            command_line_w: 0,
            next_object: 0x10000,
            stack_base: 0,
            stack_size: 0,
            classes: Vec::new(),
            windows: Vec::new(),
            messages: Vec::new(),
            callback: None,
            callback_return: 0,
            quit: false,
            paint_dc: 0x20000,
            dirty: true,
            cursor_dirty: true,
            paint_hwnd: 0,
            focus_hwnd: 0,
            gdi_objects: Vec::new(),
            dcs: Vec::new(),
            mouse_x: 0,
            mouse_y: 0,
            mouse_buttons: 0,
            win16: None,
        }
    }
    pub fn cwd_str(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }
    pub fn exec_path_str(&self) -> &[u8] {
        &self.exec_path[..self.exec_path_len]
    }
    pub fn on_resume<A: crate::Arch>(&mut self, machine: &mut A) {
        machine.load_ldt(&self.ldt);
    }
    pub fn repaint_osd(&mut self) {
        self.cursor_dirty = true;
    }
    pub fn process_key(&mut self, fds: &[thread::FdKind; thread::MAX_FDS], scancode: u8) {
        let pressed = crate::kernel::keyboard::update_key_state(scancode);
        let hwnd = self
            .windows
            .iter()
            .rfind(|w| w.visible && w.parent == 0)
            .map_or(0, |w| w.hwnd);
        self.messages.push(Message {
            hwnd,
            message: if scancode & 0x80 == 0 { 0x0100 } else { 0x0101 },
            wparam: u32::from(scancode & 0x7f),
            lparam: 0,
        });
        if !pressed {
            return;
        }
        let c = crate::kernel::keyboard::scancode_to_ascii(scancode);
        if c != 0
            && let thread::FdKind::PipeRead(p) = fds[0]
        {
            crate::kernel::kpipe::write(p, &[c]);
        }
    }

    pub fn process_mouse(&mut self, dx: i16, dy: i16, buttons: u8) {
        let Some(window) = self.windows.iter().rfind(|w| w.visible && w.parent == 0) else {
            return;
        };
        let hwnd = window.hwnd;
        self.mouse_x =
            (self.mouse_x + i32::from(dx)).clamp(0, window.width.saturating_sub(1) as i32);
        self.mouse_y =
            (self.mouse_y + i32::from(dy)).clamp(0, window.height.saturating_sub(1) as i32);
        let lparam = (self.mouse_x as u32 & 0xffff) | ((self.mouse_y as u32 & 0xffff) << 16);
        self.messages.push(Message {
            hwnd,
            message: 0x0200,
            wparam: buttons as u32,
            lparam,
        });
        if buttons & 1 != 0 && self.mouse_buttons & 1 == 0 {
            self.messages.push(Message {
                hwnd,
                message: 0x0201,
                wparam: 1,
                lparam,
            });
        } else if buttons & 1 == 0 && self.mouse_buttons & 1 != 0 {
            self.messages.push(Message {
                hwnd,
                message: 0x0202,
                wparam: 0,
                lparam,
            });
        }
        if buttons & 2 != 0 && self.mouse_buttons & 2 == 0 {
            self.messages.push(Message {
                hwnd,
                message: 0x0204,
                wparam: 2,
                lparam,
            });
        } else if buttons & 2 == 0 && self.mouse_buttons & 2 != 0 {
            self.messages.push(Message {
                hwnd,
                message: 0x0205,
                wparam: 0,
                lparam,
            });
        }
        self.mouse_buttons = buttons;
        self.cursor_dirty = true;
    }
}

pub fn exec_ne_into<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
) -> Result<(), i32> {
    win16::exec(machine, threads, tid, data, path, parent_cwd, launcher)
}

/// Publish the foremost native Win32 top-level window into the shared desktop.
pub fn render<A: crate::Arch>(
    _machine: &mut A,
    _bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    state: &mut WindowsState,
    _display: &mut crate::kernel::display::Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    const WINDOW_SURFACE: crate::kernel::gui::SurfaceKey = crate::kernel::gui::SurfaceKey(1);
    const WINDOW_PRESENTATION: crate::kernel::gui::PresentationKey =
        crate::kernel::gui::PresentationKey(1);
    let focus_changed = desktop.focus(endpoint);
    let Some(index) = state.windows.iter()
        .rposition(|window| window.visible && window.parent == 0) else {
        return;
    };
    let (width, height) = (
        state.windows[index].width as usize,
        state.windows[index].height as usize,
    );
    let surface = desktop
        .ensure_surface(endpoint, WINDOW_SURFACE)
        .expect("create Win32 surface");
    let node = desktop
        .ensure_node(
            endpoint,
            WINDOW_PRESENTATION,
            crate::kernel::gui::Rect::new(0, 0, width as u32, height as u32),
        )
        .expect("create Win32 presentation node");
    let placement = desktop
        .geometry(node)
        .expect("live Win32 presentation node");
    let pointer_changed = desktop.set_pointer(crate::kernel::gui::Point {
        x: placement.x + state.mouse_x,
        y: placement.y + state.mouse_y,
    });
    if !state.dirty && !state.cursor_dirty && !focus_changed && !pointer_changed {
        return;
    }
    let mut transaction = crate::kernel::gui::Transaction::new(endpoint);
    transaction
        .set_geometry(
            node,
            crate::kernel::gui::Rect::new(placement.x, placement.y, width as u32, height as u32),
        )
        .attach(node, Some(surface))
        .set_visible(node, true);
    desktop
        .commit(transaction)
        .expect("commit Win32 presentation node");

    state.dirty = false;
    state.cursor_dirty = false;
}

pub fn surface_buffer<'a>(
    state: &'a WindowsState,
) -> Option<crate::kernel::gui::PixelBuffer<'a>> {
    let window = state.windows.iter().rfind(|window| window.visible && window.parent == 0)?;
    crate::kernel::gui::PixelBuffer::new(
        window.width as usize,
        window.height as usize,
        window.width as usize * 4,
        vga::PixelFormat::NATIVE,
        &window.pixels,
    ).ok()
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
    if !out.ends_with(b".DLL") {
        out.extend_from_slice(b".DLL");
    }
    out
}

fn dirname(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|&b| b == b'/')
        .map_or(b"", |n| &path[..n])
}

fn join(dir: &[u8], file: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + 1 + file.len());
    out.extend_from_slice(dir);
    if !dir.is_empty() && dir.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(file);
    out
}

fn find_module(modules: &[Module], name: &[u8]) -> Option<usize> {
    let name = module_name(name);
    modules
        .iter()
        .position(|m| m.name.eq_ignore_ascii_case(&name))
}

fn load_dependency(name: &[u8], importer: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let file = module_name(name);
    let system = join(crate::kernel::dos::c_root(), b"WINDOWS/SYSTEM32");
    for path in [join(dirname(importer), &file), join(&system, &file)] {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&path) {
            return Ok((path, data));
        }
    }
    Err(2)
}

fn map_module<A: crate::Arch>(machine: &mut A, module: &Module) -> Result<(), i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    let end = module.base.checked_add(image.header.size_image).ok_or(8)?;
    if end >= USER_LIMIT {
        return Err(8);
    }
    machine.zero(module.base as usize, image.header.size_image as usize);
    let headers = (image.header.size_headers as usize).min(module.data.len());
    machine.copy_to(module.base as usize, &module.data[..headers]);
    for section in image.sections().map_err(|_| 8)? {
        let size =
            (section.raw_size as usize).min(section.virtual_size.max(section.raw_size) as usize);
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
                        let at = module
                            .base
                            .checked_add(page)
                            .and_then(|v| v.checked_add((entry & 0xfff) as u32))
                            .ok_or(8)? as usize;
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
        if size == 0 {
            continue;
        }
        let base = (module.base + section.rva) as usize;
        let pages = (base % 4096 + size).div_ceil(4096);
        machine.set_page_flags(
            base / 4096,
            pages,
            section.characteristics & 0x8000_0000 != 0,
            section.characteristics & 0x2000_0000 != 0,
        );
    }
    Ok(())
}

fn resolve_export(module: &Module, symbol: &pe::ImportSymbol) -> Result<u32, i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    let export = image
        .exports()
        .map_err(|_| 8)?
        .into_iter()
        .find(|e| match symbol {
            pe::ImportSymbol::Name(n) => e.name.eq_ignore_ascii_case(n),
            pe::ImportSymbol::Ordinal(n) => e.ordinal == *n,
        })
        .ok_or(127)?;
    // Forwarded exports are deliberately outside the initial replacement-DLL surface.
    if export.rva >= image.header.export.rva
        && export.rva
            < image
                .header
                .export
                .rva
                .saturating_add(image.header.export.size)
    {
        return Err(127);
    }
    module.base.checked_add(export.rva).ok_or(8)
}

fn apply_imports<A: crate::Arch>(
    machine: &mut A,
    modules: &[Module],
    index: usize,
) -> Result<(), i32> {
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
        for b in &mut dos {
            if *b == b'/' {
                *b = b'\\';
            }
        }
        let path = if create {
            crate::kernel::dos::dos_abs_to_vfs_create(&dos)
        } else {
            crate::kernel::dos::dos_abs_to_vfs(&dos)
        };
        return path.ok_or(ERROR_FILE_NOT_FOUND);
    }
    let mut p = path.to_vec();
    for b in &mut p {
        if *b == b'\\' {
            *b = b'/';
        }
    }
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
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
) -> Result<(), i32> {
    let parsed_main = pe::Image::parse(&data).map_err(|_| 8)?;
    if parsed_main.is_dll() {
        return Err(8);
    }
    let main_header = parsed_main.header;
    let main_path = if launcher == Some(thread::PersonalityName::Dos) {
        crate::kernel::dos::dos_abs_to_vfs(path).unwrap_or_else(|| path.to_vec())
    } else {
        let mut b = [0u8; 164];
        crate::kernel::exec::resolve_path(path, parent_cwd, &mut b).to_vec()
    };
    let mut modules = vec![Module {
        name: b"MAIN.EXE".to_vec(),
        path: main_path.clone(),
        data,
        base: main_header.image_base,
    }];
    let mut i = 0;
    while i < modules.len() {
        let imports = pe::Image::parse(&modules[i].data)
            .map_err(|_| 8)?
            .imports()
            .map_err(|_| 8)?;
        for import in imports {
            if find_module(&modules, &import.module).is_some() {
                continue;
            }
            let (dll_path, dll_data) = load_dependency(&import.module, &modules[i].path)?;
            let image = pe::Image::parse(&dll_data).map_err(|_| 8)?;
            if !image.is_dll() {
                return Err(8);
            }
            let slot = modules.len() as u32;
            modules.push(Module {
                name: module_name(&import.module),
                path: dll_path,
                data: dll_data,
                base: DLL_BASE_FIRST
                    .checked_add((slot - 1) * DLL_BASE_STRIDE)
                    .ok_or(8)?,
            });
        }
        i += 1;
    }
    for module in &modules {
        map_module(machine, module)?;
    }
    for n in 0..modules.len() {
        apply_imports(machine, &modules, n)?;
    }

    let stack_size = main_header
        .stack_reserve
        .max(64 * 1024)
        .next_multiple_of(4096);
    let stack_base = STACK_TOP.checked_sub(stack_size).ok_or(8)?;
    machine.zero(stack_base as usize, stack_size as usize);
    machine.set_page_flags(
        stack_base as usize / 4096,
        stack_size as usize / 4096,
        true,
        false,
    );
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
    for (n, &b) in win_path.iter().enumerate() {
        machine.write::<u16>(cmd_w as usize + n * 2, b as u16);
    }
    machine.write::<u16>(cmd_w as usize + win_path.len() * 2, 0);

    for module in &modules {
        protect_module(machine, module)?;
    }
    let stack = STACK_TOP - 4;
    machine.write::<u32>(stack as usize, 0);
    let entry = modules[0]
        .base
        .checked_add(main_header.entry_rva)
        .ok_or(8)?;
    let current = thread::get_thread(threads, tid).ok_or(8)?;
    thread::init_process_thread(current, entry, stack);

    let mut state = WindowsState::new();
    state.ldt.push(descriptor(TEB_BASE, 4095));
    current.kernel.vcpu.regs.fs = 0x0f;
    state.command_line_a = cmd_a;
    state.command_line_w = cmd_w;
    state.stack_base = stack_base;
    state.stack_size = stack_size;
    state.exec_path_len = main_path.len().min(state.exec_path.len());
    state.exec_path[..state.exec_path_len].copy_from_slice(&main_path[..state.exec_path_len]);
    let cwd = dirname(&main_path);
    state.cwd_len = cwd.len().min(state.cwd.len());
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
        (
            b"KERNEL32",
            b"GetCurrentThreadId",
            Api::GetCurrentThreadId,
            0,
        ),
        (b"KERNEL32", b"GetFileType", Api::GetFileType, 4),
        (b"KERNEL32", b"GetLastError", Api::GetLastError, 0),
        (
            b"KERNEL32",
            b"GetModuleFileNameA",
            Api::GetModuleFileNameA,
            12,
        ),
        (
            b"KERNEL32",
            b"GetModuleFileNameW",
            Api::GetModuleFileNameW,
            12,
        ),
        (b"KERNEL32", b"GetModuleHandleA", Api::GetModuleHandleA, 4),
        (b"KERNEL32", b"GetModuleHandleW", Api::GetModuleHandleW, 4),
        (b"KERNEL32", b"GetOEMCP", Api::GetOEMCP, 0),
        (b"KERNEL32", b"GetProcAddress", Api::GetProcAddress, 8),
        (b"KERNEL32", b"GetStdHandle", Api::GetStdHandle, 4),
        (b"KERNEL32", b"GetStartupInfoA", Api::GetStartupInfoA, 4),
        (b"KERNEL32", b"GetTickCount64", Api::GetTickCount64, 0),
        (b"KERNEL32", b"GetVersion", Api::GetVersion, 0),
        (b"KERNEL32", b"LoadLibraryA", Api::LoadLibraryA, 4),
        (
            b"KERNEL32",
            b"MultiByteToWideChar",
            Api::MultiByteToWideChar,
            24,
        ),
        (
            b"KERNEL32",
            b"ReadConsoleInputA",
            Api::ReadConsoleInputA,
            16,
        ),
        (b"KERNEL32", b"ReadFile", Api::ReadFile, 20),
        (
            b"KERNEL32",
            b"SetConsoleCtrlHandler",
            Api::SetConsoleCtrlHandler,
            8,
        ),
        (b"KERNEL32", b"SetConsoleMode", Api::SetConsoleMode, 8),
        (
            b"KERNEL32",
            b"SetEnvironmentVariableA",
            Api::SetEnvironmentVariableA,
            8,
        ),
        (b"KERNEL32", b"SetFilePointer", Api::SetFilePointer, 16),
        (b"KERNEL32", b"SetStdHandle", Api::SetStdHandle, 8),
        (
            b"KERNEL32",
            b"SetUnhandledExceptionFilter",
            Api::SetUnhandledExceptionFilter,
            4,
        ),
        (
            b"KERNEL32",
            b"UnhandledExceptionFilter",
            Api::UnhandledExceptionFilter,
            4,
        ),
        (b"KERNEL32", b"VirtualAlloc", Api::VirtualAlloc, 16),
        (b"KERNEL32", b"VirtualFree", Api::VirtualFree, 12),
        (b"KERNEL32", b"VirtualQuery", Api::VirtualQuery, 12),
        (
            b"KERNEL32",
            b"WideCharToMultiByte",
            Api::WideCharToMultiByte,
            32,
        ),
        (b"KERNEL32", b"WriteConsoleA", Api::WriteConsoleA, 20),
        (b"KERNEL32", b"WriteFile", Api::WriteFile, 20),
        (b"KERNEL32", b"lstrcpyW", Api::LstrcpyW, 8),
        (b"KERNEL32", b"lstrlenW", Api::LstrlenW, 4),
        (b"USER32", b"CharUpperA", Api::CharUpperA, 4),
        (b"USER32", b"AdjustWindowRect", Api::Stub(1), 12),
        (b"USER32", b"BeginPaint", Api::BeginPaint, 8),
        (b"USER32", b"CheckMenuItem", Api::Stub(0), 12),
        (b"USER32", b"CreateWindowExW", Api::CreateWindowExW, 48),
        (b"USER32", b"DefWindowProcW", Api::DefWindowProcW, 16),
        (b"USER32", b"DestroyIcon", Api::Stub(1), 4),
        (b"USER32", b"DialogBoxParamW", Api::Stub(0), 20),
        (b"USER32", b"DispatchMessageW", Api::DispatchMessageW, 4),
        (b"USER32", b"DrawEdge", Api::DrawEdge, 16),
        (b"USER32", b"EndDialog", Api::Stub(1), 8),
        (b"USER32", b"EndPaint", Api::EndPaint, 8),
        (b"USER32", b"FillRect", Api::FillRect, 12),
        (b"USER32", b"GetClientRect", Api::GetClientRect, 8),
        (b"USER32", b"GetDC", Api::GetDC, 4),
        (b"USER32", b"GetDlgItem", Api::Stub(0), 8),
        (b"USER32", b"GetDlgItemInt", Api::Stub(0), 16),
        (b"USER32", b"GetDlgItemTextW", Api::Stub(0), 16),
        (b"USER32", b"GetMenuItemRect", Api::Stub(0), 16),
        (b"USER32", b"GetMessageW", Api::GetMessageW, 16),
        (b"USER32", b"GetSysColorBrush", Api::GetSysColorBrush, 4),
        (b"USER32", b"GetSystemMetrics", Api::GetSystemMetrics, 4),
        (b"USER32", b"InflateRect", Api::InflateRect, 12),
        (b"USER32", b"InvalidateRect", Api::InvalidateRect, 12),
        (b"USER32", b"KillTimer", Api::Stub(1), 8),
        (b"USER32", b"LoadAcceleratorsW", Api::Stub(0), 8),
        (b"USER32", b"LoadCursorW", Api::Stub(1), 8),
        (b"USER32", b"LoadIconW", Api::Stub(1), 8),
        (b"USER32", b"LoadMenuW", Api::Stub(0), 8),
        (b"USER32", b"LoadStringW", Api::Stub(0), 16),
        (b"USER32", b"MapWindowPoints", Api::Stub(0), 16),
        (b"USER32", b"MessageBoxW", Api::Stub(1), 16),
        (b"USER32", b"MoveWindow", Api::MoveWindow, 24),
        (b"USER32", b"OffsetRect", Api::OffsetRect, 12),
        (b"USER32", b"PeekMessageW", Api::PeekMessageW, 20),
        (b"USER32", b"PostMessageW", Api::PostMessageW, 16),
        (b"USER32", b"PostQuitMessage", Api::PostQuitMessage, 4),
        (b"USER32", b"PtInRect", Api::PtInRect, 12),
        (b"USER32", b"RegisterClassW", Api::RegisterClassW, 4),
        (b"USER32", b"RetroWndProcReturn", Api::RetroWndProcReturn, 0),
        (b"USER32", b"ReleaseCapture", Api::Stub(1), 0),
        (b"USER32", b"ReleaseDC", Api::ReleaseDC, 8),
        (b"USER32", b"SendMessageW", Api::Stub(0), 16),
        (b"USER32", b"SetCapture", Api::Stub(1), 4),
        (b"USER32", b"SetDlgItemInt", Api::Stub(1), 16),
        (b"USER32", b"SetDlgItemTextW", Api::Stub(1), 12),
        (b"USER32", b"SetMenu", Api::Stub(1), 8),
        (b"USER32", b"SetRect", Api::SetRect, 20),
        (b"USER32", b"SetTimer", Api::Stub(1), 16),
        (b"USER32", b"ShowWindow", Api::ShowWindow, 8),
        (b"USER32", b"TranslateAcceleratorW", Api::Stub(0), 12),
        (b"USER32", b"TranslateMessage", Api::TranslateMessage, 4),
        (b"USER32", b"UpdateWindow", Api::UpdateWindow, 4),
        (b"GDI32", b"Arc", Api::Stub(1), 36),
        (b"GDI32", b"BitBlt", Api::BitBlt, 36),
        (
            b"GDI32",
            b"CreateCompatibleBitmap",
            Api::CreateCompatibleBitmap,
            12,
        ),
        (b"GDI32", b"CreateCompatibleDC", Api::CreateCompatibleDC, 4),
        (b"GDI32", b"CreateFontW", Api::Stub(1), 56),
        (b"GDI32", b"CreatePen", Api::CreatePen, 12),
        (b"GDI32", b"CreateSolidBrush", Api::CreateSolidBrush, 4),
        (b"GDI32", b"DeleteDC", Api::DeleteDC, 4),
        (b"GDI32", b"DeleteObject", Api::DeleteObject, 4),
        (b"GDI32", b"Ellipse", Api::Ellipse, 20),
        (b"GDI32", b"GetLayout", Api::Stub(0), 4),
        (b"GDI32", b"GetStockObject", Api::GetStockObject, 4),
        (
            b"GDI32",
            b"GetTextExtentPoint32W",
            Api::GetTextExtentPoint32W,
            16,
        ),
        (b"GDI32", b"LineTo", Api::LineTo, 12),
        (b"GDI32", b"MoveToEx", Api::MoveToEx, 16),
        (b"GDI32", b"Polygon", Api::Polygon, 12),
        (b"GDI32", b"SelectObject", Api::SelectObject, 8),
        (b"GDI32", b"SetBkColor", Api::SetBkColor, 8),
        (b"GDI32", b"SetBkMode", Api::Stub(1), 8),
        (b"GDI32", b"SetLayout", Api::Stub(0), 8),
        (b"GDI32", b"SetTextColor", Api::SetTextColor, 8),
        (b"GDI32", b"TextOutW", Api::TextOutW, 20),
        (b"ADVAPI32", b"RegCloseKey", Api::Stub(0), 4),
        (b"ADVAPI32", b"RegCreateKeyExW", Api::Stub(1), 36),
        (b"ADVAPI32", b"RegQueryValueExW", Api::Stub(2), 24),
        (b"ADVAPI32", b"RegSetValueExW", Api::Stub(0), 24),
        (b"COMCTL32", b"InitCommonControlsEx", Api::Stub(1), 4),
        (b"DWMAPI", b"DwmSetWindowAttribute", Api::Stub(0), 16),
        (b"SHELL32", b"ExtractIconA", Api::Stub(0), 12),
        (b"SHELL32", b"ShellAboutW", Api::Stub(1), 16),
        (b"WINMM", b"PlaySoundW", Api::Stub(1), 12),
    ];
    for &(module, name, api, arg_bytes) in specs {
        let Some(_) = find_module(&modules, module) else {
            continue;
        };
        let address = export_address(&modules, module, name)?;
        state.gates.push(Gate {
            return_ip: address + 2,
            api,
            arg_bytes,
            name,
        });
    }
    state.callback_return = export_address(&modules, b"USER32", b"RetroWndProcReturn")?;
    state.modules = modules;
    state.on_resume(machine);
    current.personality = thread::Personality::Windows(state);
    Ok(())
}

fn arg<A: crate::Arch>(machine: &A, regs: &Regs, n: usize) -> u32 {
    machine.read::<u32>(regs.sp() as usize + 4 + n * 4)
}

fn c_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    if address == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut out = Vec::new();
    for i in 0..32768 {
        let b = machine.read::<u8>(address as usize + i);
        if b == 0 {
            return Ok(out);
        }
        out.push(b);
    }
    Err(ERROR_INVALID_PARAMETER)
}

fn w_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    if address == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut out = Vec::new();
    for i in 0..32768 {
        let c = machine.read::<u16>(address as usize + i * 2);
        if c == 0 {
            return Ok(out);
        }
        if c > 0x7f {
            return Err(ERROR_INVALID_PARAMETER);
        }
        out.push(c as u8);
    }
    Err(ERROR_INVALID_PARAMETER)
}

fn finish<A: crate::Arch>(machine: &A, regs: &mut Regs, gate: Gate, result: u32) {
    let ret = machine.read::<u32>(regs.sp() as usize);
    regs.rax = result as u64;
    regs.frame.rip = ret as u64;
    regs.frame.rsp += 4 + gate.arg_bytes as u64;
}

fn fail(state: &mut WindowsState, error: u32, result: u32) -> u32 {
    state.last_error = error;
    result
}

fn io_write<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    handle: usize,
    ptr: usize,
    len: usize,
    actual: usize,
) -> u32 {
    if handle >= thread::MAX_FDS {
        return 0;
    }
    let mut data = vec![0; len];
    machine.copy_from(ptr, &mut data);
    let n = match kt.fds[handle] {
        thread::FdKind::ConsoleOut => {
            for &b in &data {
                crate::term::putchar(b);
            }
            crate::kernel::term::mark_dirty();
            len as i32
        }
        thread::FdKind::PipeWrite(p) => crate::kernel::kpipe::write(p, &data),
        thread::FdKind::Vfs(h) => crate::kernel::vfs::write_by_handle(machine, h, &data),
        _ => -1,
    };
    if n < 0 {
        return 0;
    }
    if actual != 0 {
        machine.write::<u32>(actual, n as u32);
    }
    1
}

fn io_read<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    handle: usize,
    ptr: usize,
    len: usize,
    actual: usize,
) -> u32 {
    if handle >= thread::MAX_FDS {
        return 0;
    }
    let mut data = vec![0; len];
    let n = match kt.fds[handle] {
        thread::FdKind::Vfs(h) => crate::kernel::vfs::read_by_handle(h, &mut data),
        thread::FdKind::PipeRead(p) => crate::kernel::kpipe::read(p, &mut data) as i32,
        _ => -1,
    };
    if n < 0 {
        return 0;
    }
    machine.copy_to(ptr, &data[..n as usize]);
    if actual != 0 {
        machine.write::<u32>(actual, n as u32);
    }
    1
}

fn copy_ascii<A: crate::Arch>(machine: &mut A, out: usize, cap: usize, text: &[u8]) -> u32 {
    if cap == 0 {
        return 0;
    }
    let n = text.len().min(cap - 1);
    machine.copy_to(out, &text[..n]);
    machine.write::<u8>(out + n, 0);
    n as u32
}

fn write_message<A: crate::Arch>(machine: &mut A, out: usize, message: Message) {
    machine.write::<u32>(out, message.hwnd);
    machine.write::<u32>(out + 4, message.message);
    machine.write::<u32>(out + 8, message.wparam);
    machine.write::<u32>(out + 12, message.lparam);
    machine.write::<u32>(out + 16, (machine.now() / 1_000_000) as u32);
    machine.write::<u32>(out + 20, 0);
    machine.write::<u32>(out + 24, 0);
}

fn queue_paint(state: &mut WindowsState, hwnd: u32) {
    if !state.windows.iter().any(|window| window.hwnd == hwnd && window.visible) {
        return;
    }
    if !state
        .messages
        .iter()
        .any(|m| m.hwnd == hwnd && m.message == 0x000f)
    {
        state.messages.push(Message {
            hwnd,
            message: 0x000f,
            wparam: 0,
            lparam: 0,
        });
    }
    state.dirty = true;
}

fn begin_wndproc<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    state: &mut WindowsState,
    gate: Gate,
    message: Message,
) -> bool {
    let Some(window) = state.windows.iter().find(|w| w.hwnd == message.hwnd) else {
        return false;
    };
    if window.wndproc == 0 || state.callback.is_some() {
        return false;
    }
    let sp = regs.sp().wrapping_sub(20);
    machine.write::<u32>(sp as usize, state.callback_return);
    machine.write::<u32>(sp as usize + 4, message.hwnd);
    machine.write::<u32>(sp as usize + 8, message.message);
    machine.write::<u32>(sp as usize + 12, message.wparam);
    machine.write::<u32>(sp as usize + 16, message.lparam);
    state.callback = Some(Callback { gate });
    regs.frame.rsp = sp;
    regs.frame.rip = window.wndproc as u64;
    true
}

fn system_color(index: u32) -> u32 {
    match index {
        0 | 4 | 5 | 15 => 0x00c0_c0c0,
        6 | 8 | 9 => 0x0000_0000,
        13 => 0x0080_0000,
        14 => 0x00ff_ffff,
        16 => 0x0080_8080,
        20 => 0x00ff_ffff,
        _ => 0x00c0_c0c0,
    }
}

fn object_color(state: &WindowsState, handle: u32, default: u32) -> u32 {
    if (0x30000..0x30100).contains(&handle) {
        return system_color(handle - 0x30000);
    }
    match state
        .gdi_objects
        .iter()
        .find(|(h, _)| *h == handle)
        .map(|(_, o)| o)
    {
        Some(GdiObject::Brush(color)) | Some(GdiObject::Pen(color)) => *color,
        _ => default,
    }
}

fn dc_bitmap(state: &WindowsState, dc: u32) -> Option<u32> {
    state
        .dcs
        .iter()
        .find(|item| item.handle == dc)
        .and_then(|item| item.bitmap)
}

struct RenderTarget<'a> {
    width: u32,
    height: u32,
    origin_x: i32,
    origin_y: i32,
    clip_width: u32,
    clip_height: u32,
    pixels: &'a mut Vec<u8>,
}

fn target_mut(
    state: &mut WindowsState,
    dc: u32,
) -> Option<RenderTarget<'_>> {
    if dc == state.paint_dc {
        let hwnd = state.paint_hwnd;
        let window = state.windows.iter().find(|window| window.hwnd == hwnd)?;
        let (clip_width, clip_height) = (window.width, window.height);
        let (mut x, mut y, mut parent) = (window.x, window.y, window.parent);
        let mut root = hwnd;
        while parent != 0 {
            let window = state.windows.iter().find(|window| window.hwnd == parent)?;
            root = window.hwnd;
            if window.parent != 0 {
                x = x.saturating_add(window.x);
                y = y.saturating_add(window.y);
            }
            parent = window.parent;
        }
        if root == hwnd { x = 0; y = 0; }
        return state.windows.iter_mut().find(|window| window.hwnd == root).map(|window| {
            let need = window.width as usize * window.height as usize * 4;
            if window.pixels.len() != need {
                window.pixels.resize(need, 0xc0);
            }
            RenderTarget {
                width: window.width,
                height: window.height,
                origin_x: x,
                origin_y: y,
                clip_width,
                clip_height,
                pixels: &mut window.pixels,
            }
        });
    }
    let bitmap = dc_bitmap(state, dc)?;
    state.gdi_objects.iter_mut().find_map(|(handle, object)| {
        if *handle != bitmap {
            return None;
        }
        match object {
            GdiObject::Bitmap {
                width,
                height,
                pixels,
            } => Some(RenderTarget {
                width: *width,
                height: *height,
                origin_x: 0,
                origin_y: 0,
                clip_width: *width,
                clip_height: *height,
                pixels,
            }),
            _ => None,
        }
    })
}

fn put_pixel(state: &mut WindowsState, dc: u32, x: i32, y: i32, color: u32) {
    let Some(target) = target_mut(state, dc) else {
        return;
    };
    if x < 0 || y < 0 || x >= target.clip_width as i32 || y >= target.clip_height as i32 {
        return;
    }
    let x = x.saturating_add(target.origin_x);
    let y = y.saturating_add(target.origin_y);
    if x < 0 || y < 0 || x >= target.width as i32 || y >= target.height as i32 { return; }
    let at = (y as usize * target.width as usize + x as usize) * 4;
    if at + 4 <= target.pixels.len() {
        target.pixels[at..at + 4].copy_from_slice(&color.to_le_bytes());
    }
}

fn fill_pixels(
    state: &mut WindowsState,
    dc: u32,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
) {
    let Some(target) = target_mut(state, dc) else {
        return;
    };
    let left = left.clamp(0, target.clip_width as i32).saturating_add(target.origin_x)
        .clamp(0, target.width as i32) as usize;
    let right = right.clamp(0, target.clip_width as i32).saturating_add(target.origin_x)
        .clamp(0, target.width as i32) as usize;
    let top = top.clamp(0, target.clip_height as i32).saturating_add(target.origin_y)
        .clamp(0, target.height as i32) as usize;
    let bottom = bottom.clamp(0, target.clip_height as i32).saturating_add(target.origin_y)
        .clamp(0, target.height as i32) as usize;
    let bytes = color.to_le_bytes();
    for y in top..bottom {
        for x in left..right {
            let at = (y * target.width as usize + x) * 4;
            target.pixels[at..at + 4].copy_from_slice(&bytes);
        }
    }
}

fn line(state: &mut WindowsState, dc: u32, mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: u32) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        put_pixel(state, dc, x0, y0, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let twice = error * 2;
        if twice >= dy {
            error += dy;
            x0 += sx;
        }
        if twice <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

fn rect_from_guest<A: crate::Arch>(machine: &A, address: usize) -> (i32, i32, i32, i32) {
    (
        machine.read::<u32>(address) as i32,
        machine.read::<u32>(address + 4) as i32,
        machine.read::<u32>(address + 8) as i32,
        machine.read::<u32>(address + 12) as i32,
    )
}

fn dispatch<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &mut Regs,
    api: Api,
) -> u32 {
    match api {
        Api::GetLastError => state.last_error,
        Api::GetACP => 1252,
        Api::GetOEMCP => 437,
        Api::GetVersion => 0x0000_0004,
        Api::GetCurrentThreadId => (kt.tid + 1) as u32,
        Api::GetCommandLineA => state.command_line_a,
        Api::GetCommandLineW => state.command_line_w,
        Api::GetStdHandle => match arg(machine, regs, 0) as i32 {
            -10 => 0,
            -11 => 1,
            -12 => 2,
            _ => INVALID_HANDLE_VALUE,
        },
        Api::SetStdHandle => {
            let slot = match arg(machine, regs, 0) as i32 {
                -10 => 0,
                -11 => 1,
                -12 => 2,
                _ => return fail(state, ERROR_INVALID_PARAMETER, 0),
            };
            let source = arg(machine, regs, 1) as usize;
            if source >= thread::MAX_FDS {
                fail(state, ERROR_INVALID_HANDLE, 0)
            } else {
                kt.fds[slot] = kt.fds[source];
                1
            }
        }
        Api::GetFileType => {
            let h = arg(machine, regs, 0) as usize;
            if h >= thread::MAX_FDS {
                return fail(state, ERROR_INVALID_HANDLE, 0);
            }
            match kt.fds[h] {
                thread::FdKind::Vfs(_) => 1,
                thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => 3,
                thread::FdKind::ConsoleOut => 2,
                _ => 0,
            }
        }
        Api::WriteFile | Api::WriteConsoleA => io_write(
            machine,
            kt,
            arg(machine, regs, 0) as usize,
            arg(machine, regs, 1) as usize,
            arg(machine, regs, 2) as usize,
            arg(machine, regs, 3) as usize,
        ),
        Api::ReadFile => io_read(
            machine,
            kt,
            arg(machine, regs, 0) as usize,
            arg(machine, regs, 1) as usize,
            arg(machine, regs, 2) as usize,
            arg(machine, regs, 3) as usize,
        ),
        Api::CreateFileA => {
            let disposition = arg(machine, regs, 4);
            let create = matches!(disposition, 1 | 2 | 4 | 5);
            let raw = match c_string(machine, arg(machine, regs, 0)) {
                Ok(v) => v,
                Err(e) => return fail(state, e, INVALID_HANDLE_VALUE),
            };
            let path = match windows_path(state, &raw, create) {
                Ok(v) => v,
                Err(e) => return fail(state, e, INVALID_HANDLE_VALUE),
            };
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
            if vh < 0 {
                return fail(state, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
            }
            let Some(fd) = kt.alloc_fd(3) else {
                crate::kernel::vfs::close_vfs_handle(vh);
                return fail(state, 4, INVALID_HANDLE_VALUE);
            };
            kt.fds[fd] = thread::FdKind::Vfs(vh);
            state.last_error = if existed { 183 } else { 0 };
            fd as u32
        }
        Api::CloseHandle => {
            let h = arg(machine, regs, 0);
            if h >= 0x10000 {
                return 1;
            }
            let h = h as usize;
            if h >= thread::MAX_FDS || kt.fds[h].is_none() {
                fail(state, ERROR_INVALID_HANDLE, 0)
            } else {
                kt.close_fd(h);
                1
            }
        }
        Api::FlushFileBuffers => 1,
        Api::SetFilePointer => {
            let h = arg(machine, regs, 0) as usize;
            if h >= thread::MAX_FDS {
                return fail(state, ERROR_INVALID_HANDLE, INVALID_HANDLE_VALUE);
            }
            let thread::FdKind::Vfs(vh) = kt.fds[h] else {
                return fail(state, ERROR_INVALID_HANDLE, INVALID_HANDLE_VALUE);
            };
            let high_ptr = arg(machine, regs, 2) as usize;
            if high_ptr != 0 && machine.read::<u32>(high_ptr) != 0 {
                return fail(state, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE);
            }
            let pos = crate::kernel::vfs::seek_by_handle(
                vh,
                arg(machine, regs, 1) as i32,
                arg(machine, regs, 3) as i32,
            );
            if pos < 0 {
                fail(state, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE)
            } else {
                if high_ptr != 0 {
                    machine.write::<u32>(high_ptr, 0);
                }
                pos as u32
            }
        }
        Api::VirtualAlloc => {
            let requested = arg(machine, regs, 0);
            let size = arg(machine, regs, 1).max(1).next_multiple_of(4096);
            let base = if requested != 0 {
                requested & !4095
            } else {
                state.heap_next
            };
            let Some(end) = base.checked_add(size) else {
                return fail(state, ERROR_NOT_ENOUGH_MEMORY, 0);
            };
            if end >= USER_LIMIT {
                return fail(state, ERROR_NOT_ENOUGH_MEMORY, 0);
            }
            if requested == 0 {
                state.heap_next = end;
            }
            machine.zero(base as usize, size as usize);
            machine.set_page_flags(base as usize / 4096, size as usize / 4096, true, false);
            state.allocations.push((base, size));
            base
        }
        Api::VirtualFree => {
            let base = arg(machine, regs, 0);
            if let Some(n) = state.allocations.iter().position(|&(a, _)| a == base) {
                state.allocations.swap_remove(n);
                1
            } else {
                fail(state, ERROR_INVALID_PARAMETER, 0)
            }
        }
        Api::VirtualQuery => {
            let address = arg(machine, regs, 0);
            let out = arg(machine, regs, 1) as usize;
            let len = arg(machine, regs, 2);
            if len < 28 {
                return 0;
            }
            let (base, size) =
                if address >= state.stack_base && address < state.stack_base + state.stack_size {
                    (state.stack_base, state.stack_size)
                } else if let Some(&(base, size)) = state
                    .allocations
                    .iter()
                    .find(|&&(base, size)| address >= base && address < base + size)
                {
                    (base, size)
                } else {
                    (address & !4095, 4096)
                };
            machine.write::<u32>(out, base);
            machine.write::<u32>(out + 4, base);
            machine.write::<u32>(out + 8, 0x04);
            machine.write::<u32>(out + 12, size);
            machine.write::<u32>(out + 16, 0x1000);
            machine.write::<u32>(out + 20, 0x04);
            machine.write::<u32>(out + 24, 0x20000);
            28
        }
        Api::GetModuleHandleA | Api::LoadLibraryA | Api::GetModuleHandleW => {
            let p = arg(machine, regs, 0);
            if p == 0 {
                state.modules[0].base
            } else {
                let name = match api {
                    Api::GetModuleHandleW => w_string(machine, p),
                    _ => c_string(machine, p),
                };
                let name = match name {
                    Ok(v) => v,
                    Err(e) => return fail(state, e, 0),
                };
                if let Some(n) = find_module(&state.modules, &name) {
                    state.modules[n].base
                } else {
                    fail(state, 126, 0)
                }
            }
        }
        Api::GetProcAddress => {
            let base = arg(machine, regs, 0);
            let p = arg(machine, regs, 1);
            let Some(module) = state.modules.iter().find(|m| m.base == base) else {
                return fail(state, 126, 0);
            };
            let symbol = if p <= 0xffff {
                pe::ImportSymbol::Ordinal(p as u16)
            } else {
                match c_string(machine, p) {
                    Ok(n) => pe::ImportSymbol::Name(n),
                    Err(e) => return fail(state, e, 0),
                }
            };
            resolve_export(module, &symbol).unwrap_or_else(|_| fail(state, 127, 0))
        }
        Api::GetModuleFileNameA => {
            let module = arg(machine, regs, 0);
            let path = if module == 0 {
                &state.modules[0].path
            } else {
                match state.modules.iter().find(|m| m.base == module) {
                    Some(m) => &m.path,
                    None => return fail(state, 126, 0),
                }
            };
            copy_ascii(
                machine,
                arg(machine, regs, 1) as usize,
                arg(machine, regs, 2) as usize,
                &guest_windows_path(path),
            )
        }
        Api::GetModuleFileNameW => {
            let module = arg(machine, regs, 0);
            let path = if module == 0 {
                &state.modules[0].path
            } else {
                match state.modules.iter().find(|m| m.base == module) {
                    Some(m) => &m.path,
                    None => return fail(state, 126, 0),
                }
            };
            let text = guest_windows_path(path);
            let out = arg(machine, regs, 1) as usize;
            let cap = arg(machine, regs, 2) as usize;
            if cap == 0 {
                return 0;
            }
            let n = text.len().min(cap - 1);
            for (i, &b) in text[..n].iter().enumerate() {
                machine.write::<u16>(out + i * 2, b as u16);
            }
            machine.write::<u16>(out + n * 2, 0);
            n as u32
        }
        Api::GetCPInfo => {
            let out = arg(machine, regs, 1) as usize;
            machine.zero(out, 20);
            machine.write::<u32>(out, 1);
            machine.write::<u8>(out + 4, b'?');
            1
        }
        Api::MultiByteToWideChar => {
            let input = arg(machine, regs, 2) as usize;
            let count = arg(machine, regs, 3) as i32;
            let out = arg(machine, regs, 4) as usize;
            let cap = arg(machine, regs, 5) as usize;
            let n = if count < 0 {
                c_string(machine, input as u32).map_or(0, |v| v.len() + 1)
            } else {
                count as usize
            };
            if out == 0 {
                return n as u32;
            }
            let written = n.min(cap);
            for i in 0..written {
                machine.write::<u16>(out + i * 2, machine.read::<u8>(input + i) as u16);
            }
            written as u32
        }
        Api::WideCharToMultiByte => {
            let input = arg(machine, regs, 2) as usize;
            let count = arg(machine, regs, 3) as i32;
            let out = arg(machine, regs, 4) as usize;
            let cap = arg(machine, regs, 5) as usize;
            let n = if count < 0 {
                let mut n = 0;
                while n < 32768 && machine.read::<u16>(input + n * 2) != 0 {
                    n += 1;
                }
                n + 1
            } else {
                count as usize
            };
            if out == 0 {
                return n as u32;
            }
            let written = n.min(cap);
            for i in 0..written {
                machine.write::<u8>(out + i, machine.read::<u16>(input + i * 2) as u8);
            }
            written as u32
        }
        Api::GetConsoleMode => {
            machine.write::<u32>(arg(machine, regs, 1) as usize, 3);
            1
        }
        Api::SetConsoleMode | Api::SetConsoleCtrlHandler | Api::SetEnvironmentVariableA => 1,
        Api::SetUnhandledExceptionFilter => 0,
        Api::UnhandledExceptionFilter => 1,
        Api::CreateEventA => {
            let h = state.next_object;
            state.next_object += 1;
            h
        }
        Api::ReadConsoleInputA => fail(state, ERROR_INVALID_HANDLE, 0),
        Api::CharUpperA => {
            let p = arg(machine, regs, 0);
            if p <= 0xffff {
                (p as u8).to_ascii_uppercase() as u32
            } else {
                let mut at = p as usize;
                loop {
                    let b = machine.read::<u8>(at);
                    if b == 0 {
                        break;
                    }
                    machine.write::<u8>(at, b.to_ascii_uppercase());
                    at += 1;
                }
                p
            }
        }
        Api::GetStartupInfoA => {
            let out = arg(machine, regs, 0) as usize;
            machine.zero(out, 68);
            machine.write::<u32>(out, 68);
            0
        }
        Api::GetTickCount64 => {
            let ticks = machine.now() / 1_000_000;
            regs.rdx = ticks >> 32;
            ticks as u32
        }
        Api::LstrlenW => w_string(machine, arg(machine, regs, 0)).map_or(0, |s| s.len() as u32),
        Api::LstrcpyW => {
            let dst = arg(machine, regs, 0) as usize;
            let src = arg(machine, regs, 1) as usize;
            let mut n = 0;
            loop {
                let c = machine.read::<u16>(src + n * 2);
                machine.write::<u16>(dst + n * 2, c);
                n += 1;
                if c == 0 || n == 32768 {
                    break;
                }
            }
            dst as u32
        }
        Api::RegisterClassW => {
            let wc = arg(machine, regs, 0) as usize;
            let wndproc = machine.read::<u32>(wc + 4);
            let background = machine.read::<u32>(wc + 28);
            let name_ptr = machine.read::<u32>(wc + 36);
            let name = match w_string(machine, name_ptr) {
                Ok(name) => name,
                Err(e) => return fail(state, e, 0),
            };
            if let Some(class) = state
                .classes
                .iter_mut()
                .find(|c| c.name.eq_ignore_ascii_case(&name))
            {
                class.wndproc = wndproc;
                class.background = background;
            } else {
                state.classes.push(WindowClass {
                    name,
                    wndproc,
                    background,
                });
            }
            state.classes.len() as u32
        }
        Api::CreateWindowExW => {
            let class_ptr = arg(machine, regs, 1);
            let class = if class_ptr <= 0xffff {
                state.classes.first()
            } else {
                let name = match w_string(machine, class_ptr) {
                    Ok(v) => v,
                    Err(_) => return 0,
                };
                state
                    .classes
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(&name))
            };
            let Some(class) = class else {
                return fail(state, 1411, 0);
            };
            let width = arg(machine, regs, 6).clamp(1, 2048);
            let height = arg(machine, regs, 7).clamp(1, 2048);
            let hwnd = state.next_object;
            state.next_object = state.next_object.wrapping_add(1);
            let pixels = vec![0xc0; width as usize * height as usize * 4];
            state.windows.push(Window {
                hwnd,
                parent: arg(machine, regs, 8),
                wndproc: class.wndproc,
                x: arg(machine, regs, 4) as i32,
                y: arg(machine, regs, 5) as i32,
                width,
                height,
                visible: false,
                pixels,
            });
            state.messages.push(Message {
                hwnd,
                message: 0x0001,
                wparam: 0,
                lparam: arg(machine, regs, 11),
            });
            hwnd
        }
        Api::ShowWindow => {
            let hwnd = arg(machine, regs, 0);
            if let Some(window) = state.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                let was = window.visible;
                window.visible = arg(machine, regs, 1) != 0;
                if window.visible {
                    queue_paint(state, hwnd);
                }
                was as u32
            } else {
                0
            }
        }
        Api::UpdateWindow | Api::InvalidateRect => {
            let hwnd = arg(machine, regs, 0);
            if state.windows.iter().any(|w| w.hwnd == hwnd) {
                queue_paint(state, hwnd);
                1
            } else {
                0
            }
        }
        Api::GetMessageW | Api::PeekMessageW => {
            let out = arg(machine, regs, 0) as usize;
            if state.quit {
                return 0;
            }
            if state.messages.is_empty() {
                if let Some(window) = state.windows.iter().find(|w| w.visible) {
                    state.messages.push(Message {
                        hwnd: window.hwnd,
                        message: 0x0113,
                        wparam: 1,
                        lparam: 0,
                    });
                } else {
                    return 0;
                }
            }
            let message = state.messages[0];
            write_message(machine, out, message);
            let remove = api == Api::GetMessageW || arg(machine, regs, 4) & 1 != 0;
            if remove {
                state.messages.remove(0);
            }
            1
        }
        Api::TranslateMessage => 1,
        Api::DispatchMessageW | Api::RetroWndProcReturn => 0,
        Api::PostMessageW => {
            state.messages.push(Message {
                hwnd: arg(machine, regs, 0),
                message: arg(machine, regs, 1),
                wparam: arg(machine, regs, 2),
                lparam: arg(machine, regs, 3),
            });
            1
        }
        Api::PostQuitMessage => {
            state.quit = true;
            0
        }
        Api::DefWindowProcW => 0,
        Api::GetClientRect => {
            let hwnd = arg(machine, regs, 0);
            let out = arg(machine, regs, 1) as usize;
            let Some(window) = state.windows.iter().find(|w| w.hwnd == hwnd) else {
                return 0;
            };
            machine.write::<u32>(out, 0);
            machine.write::<u32>(out + 4, 0);
            machine.write::<u32>(out + 8, window.width);
            machine.write::<u32>(out + 12, window.height);
            1
        }
        Api::GetSystemMetrics => match arg(machine, regs, 0) {
            0 => 1024,
            1 => 768,
            2 | 3 => 16,
            4 => 20,
            5 | 6 => 1,
            7 | 8 => 3,
            15 => 19,
            32 | 33 => 4,
            _ => 0,
        },
        Api::SetRect => {
            let out = arg(machine, regs, 0) as usize;
            for n in 0..4 { machine.write::<u32>(out + n * 4, arg(machine, regs, n + 1)); }
            1
        }
        Api::InflateRect => {
            let out = arg(machine, regs, 0) as usize;
            let dx = arg(machine, regs, 1); let dy = arg(machine, regs, 2);
            machine.write::<u32>(out, machine.read::<u32>(out).wrapping_sub(dx));
            machine.write::<u32>(out + 4, machine.read::<u32>(out + 4).wrapping_sub(dy));
            machine.write::<u32>(out + 8, machine.read::<u32>(out + 8).wrapping_add(dx));
            machine.write::<u32>(out + 12, machine.read::<u32>(out + 12).wrapping_add(dy));
            1
        }
        Api::OffsetRect => {
            let out = arg(machine, regs, 0) as usize;
            let dx = arg(machine, regs, 1); let dy = arg(machine, regs, 2);
            machine.write::<u32>(out, machine.read::<u32>(out).wrapping_add(dx));
            machine.write::<u32>(out + 4, machine.read::<u32>(out + 4).wrapping_add(dy));
            machine.write::<u32>(out + 8, machine.read::<u32>(out + 8).wrapping_add(dx));
            machine.write::<u32>(out + 12, machine.read::<u32>(out + 12).wrapping_add(dy));
            1
        }
        Api::PtInRect => {
            let (l, t, r, b) = rect_from_guest(machine, arg(machine, regs, 0) as usize);
            let x = arg(machine, regs, 1) as i32; let y = arg(machine, regs, 2) as i32;
            (x >= l && x < r && y >= t && y < b) as u32
        }
        Api::MoveWindow => {
            let hwnd = arg(machine, regs, 0);
            let width = arg(machine, regs, 3).clamp(1, 2048);
            let height = arg(machine, regs, 4).clamp(1, 2048);
            if let Some(window) = state.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                window.width = width; window.height = height;
                window.pixels.resize(width as usize * height as usize * 4, 0xc0);
                if arg(machine, regs, 5) != 0 { queue_paint(state, hwnd); }
                1
            } else { 0 }
        }
        Api::BeginPaint => {
            let hwnd = arg(machine, regs, 0);
            let out = arg(machine, regs, 1) as usize;
            let Some(window) = state.windows.iter().find(|w| w.hwnd == hwnd) else {
                return 0;
            };
            machine.zero(out, 64);
            machine.write::<u32>(out, state.paint_dc);
            machine.write::<u32>(out + 8, 0);
            machine.write::<u32>(out + 12, 0);
            machine.write::<u32>(out + 16, window.width);
            machine.write::<u32>(out + 20, window.height);
            state.paint_hwnd = hwnd;
            state.paint_dc
        }
        Api::EndPaint => {
            state.dirty = true;
            1
        }
        Api::GetDC => {
            state.paint_hwnd = arg(machine, regs, 0);
            state.paint_dc
        }
        Api::ReleaseDC => 1,
        Api::GetSysColorBrush => 0x30000 + arg(machine, regs, 0),
        Api::CreateSolidBrush => {
            let handle = state.next_object;
            state.next_object += 1;
            state
                .gdi_objects
                .push((handle, GdiObject::Brush(arg(machine, regs, 0))));
            handle
        }
        Api::CreatePen => {
            let handle = state.next_object;
            state.next_object += 1;
            state
                .gdi_objects
                .push((handle, GdiObject::Pen(arg(machine, regs, 2))));
            handle
        }
        Api::CreateCompatibleBitmap => {
            let width = arg(machine, regs, 1).clamp(1, 2048);
            let height = arg(machine, regs, 2).clamp(1, 2048);
            let handle = state.next_object;
            state.next_object += 1;
            state.gdi_objects.push((
                handle,
                GdiObject::Bitmap {
                    width,
                    height,
                    pixels: vec![0; width as usize * height as usize * 4],
                },
            ));
            handle
        }
        Api::CreateCompatibleDC => {
            let handle = state.next_object;
            state.next_object += 1;
            state.dcs.push(DeviceContext {
                handle,
                bitmap: None,
                x: 0,
                y: 0,
                pen: 0x30008,
                brush: 0x30005,
                font: 1,
                bk: 0x00ff_ffff,
                text: 0,
            });
            handle
        }
        Api::SelectObject => {
            let dc = arg(machine, regs, 0);
            let object = arg(machine, regs, 1);
            let kind = state
                .gdi_objects
                .iter()
                .find(|(h, _)| *h == object)
                .map(|(_, o)| match o {
                    GdiObject::Bitmap { .. } => 0,
                    GdiObject::Brush(_) => 1,
                    GdiObject::Pen(_) => 2,
                    GdiObject::Font => 3,
                });
            let Some(context) = state.dcs.iter_mut().find(|d| d.handle == dc) else {
                return 0;
            };
            match kind {
                Some(0) => context.bitmap.replace(object).unwrap_or(1),
                Some(1) => {
                    let old = context.brush;
                    context.brush = object;
                    old
                }
                Some(2) => {
                    let old = context.pen;
                    context.pen = object;
                    old
                }
                Some(3) => {
                    let old = context.font;
                    context.font = object;
                    old
                }
                _ => 1,
            }
        }
        Api::DeleteObject => {
            let object = arg(machine, regs, 0);
            if let Some(index) = state.gdi_objects.iter().position(|(h, _)| *h == object) {
                state.gdi_objects.swap_remove(index);
                1
            } else {
                1
            }
        }
        Api::DeleteDC => {
            let dc = arg(machine, regs, 0);
            if let Some(index) = state.dcs.iter().position(|d| d.handle == dc) {
                state.dcs.swap_remove(index);
                1
            } else {
                0
            }
        }
        Api::GetStockObject => {
            0x30000
                + match arg(machine, regs, 0) {
                    4 => 8,
                    5 => 5,
                    _ => 5,
                }
        }
        Api::FillRect => {
            let dc = arg(machine, regs, 0);
            let rect = arg(machine, regs, 1) as usize;
            let color = object_color(state, arg(machine, regs, 2), 0x00c0_c0c0);
            let (l, t, r, b) = rect_from_guest(machine, rect);
            fill_pixels(state, dc, l, t, r, b, color);
            1
        }
        Api::DrawEdge => {
            let dc = arg(machine, regs, 0);
            let rect = arg(machine, regs, 1) as usize;
            let (l, t, r, b) = rect_from_guest(machine, rect);
            line(state, dc, l, t, r - 1, t, 0x00ff_ffff);
            line(state, dc, l, t, l, b - 1, 0x00ff_ffff);
            line(state, dc, l, b - 1, r - 1, b - 1, 0x0080_8080);
            line(state, dc, r - 1, t, r - 1, b - 1, 0x0080_8080);
            1
        }
        Api::MoveToEx => {
            let dc = arg(machine, regs, 0);
            let x = arg(machine, regs, 1) as i32;
            let y = arg(machine, regs, 2) as i32;
            let Some(context) = state.dcs.iter_mut().find(|d| d.handle == dc) else {
                return 0;
            };
            let old = arg(machine, regs, 3) as usize;
            if old != 0 {
                machine.write::<u32>(old, context.x as u32);
                machine.write::<u32>(old + 4, context.y as u32);
            }
            context.x = x;
            context.y = y;
            1
        }
        Api::LineTo => {
            let dc = arg(machine, regs, 0);
            let x = arg(machine, regs, 1) as i32;
            let y = arg(machine, regs, 2) as i32;
            let Some((x0, y0, pen)) = state
                .dcs
                .iter()
                .find(|d| d.handle == dc)
                .map(|d| (d.x, d.y, d.pen))
            else {
                return 0;
            };
            let color = object_color(state, pen, 0);
            line(state, dc, x0, y0, x, y, color);
            if let Some(context) = state.dcs.iter_mut().find(|d| d.handle == dc) {
                context.x = x;
                context.y = y;
            }
            1
        }
        Api::Ellipse => {
            let dc = arg(machine, regs, 0);
            let l = arg(machine, regs, 1) as i32;
            let t = arg(machine, regs, 2) as i32;
            let r = arg(machine, regs, 3) as i32;
            let b = arg(machine, regs, 4) as i32;
            let brush = state
                .dcs
                .iter()
                .find(|d| d.handle == dc)
                .map_or(0x30005, |d| d.brush);
            let color = object_color(state, brush, 0);
            let cx = (l + r) / 2;
            let cy = (t + b) / 2;
            let rx = ((r - l) / 2).max(1);
            let ry = ((b - t) / 2).max(1);
            for y in t..b {
                for x in l..r {
                    let dx = x - cx;
                    let dy = y - cy;
                    if dx * dx * ry * ry + dy * dy * rx * rx <= rx * rx * ry * ry {
                        put_pixel(state, dc, x, y, color);
                    }
                }
            }
            1
        }
        Api::Polygon => {
            let dc = arg(machine, regs, 0);
            let points = arg(machine, regs, 1) as usize;
            let count = arg(machine, regs, 2) as usize;
            let pen = state
                .dcs
                .iter()
                .find(|d| d.handle == dc)
                .map_or(0x30008, |d| d.pen);
            let color = object_color(state, pen, 0);
            if count > 1 && count < 1024 {
                for i in 0..count {
                    let j = (i + 1) % count;
                    let x0 = machine.read::<u32>(points + i * 8) as i32;
                    let y0 = machine.read::<u32>(points + i * 8 + 4) as i32;
                    let x1 = machine.read::<u32>(points + j * 8) as i32;
                    let y1 = machine.read::<u32>(points + j * 8 + 4) as i32;
                    line(state, dc, x0, y0, x1, y1, color);
                }
            }
            1
        }
        Api::SetBkColor | Api::SetTextColor => {
            let dc = arg(machine, regs, 0);
            let color = arg(machine, regs, 1);
            let Some(context) = state.dcs.iter_mut().find(|d| d.handle == dc) else {
                return 0xffff_ffff;
            };
            if api == Api::SetBkColor {
                let old = context.bk;
                context.bk = color;
                old
            } else {
                let old = context.text;
                context.text = color;
                old
            }
        }
        Api::GetTextExtentPoint32W => {
            let count = arg(machine, regs, 2);
            let out = arg(machine, regs, 3) as usize;
            machine.write::<u32>(out, count * 8);
            machine.write::<u32>(out + 4, 16);
            1
        }
        Api::TextOutW => {
            let dc = arg(machine, regs, 0);
            let x = arg(machine, regs, 1) as i32;
            let y = arg(machine, regs, 2) as i32;
            let text = arg(machine, regs, 3) as usize;
            let count = (arg(machine, regs, 4) as usize).min(4096);
            let color = state
                .dcs
                .iter()
                .find(|d| d.handle == dc)
                .map_or(0, |d| d.text);
            for n in 0..count {
                let ch = machine.read::<u16>(text + n * 2) as usize;
                if ch >= 256 {
                    continue;
                }
                let glyph = &lib::vga_fonts::FONT_8X16[ch * 16..ch * 16 + 16];
                for (gy, &bits) in glyph.iter().enumerate() {
                    for gx in 0..8 {
                        if bits & (0x80 >> gx) != 0 {
                            put_pixel(state, dc, x + (n * 8 + gx) as i32, y + gy as i32, color);
                        }
                    }
                }
            }
            1
        }
        Api::BitBlt => {
            let dst = arg(machine, regs, 0);
            let dx = arg(machine, regs, 1) as i32;
            let dy = arg(machine, regs, 2) as i32;
            let width = arg(machine, regs, 3) as usize;
            let height = arg(machine, regs, 4) as usize;
            let src = arg(machine, regs, 5);
            let sx = arg(machine, regs, 6) as i32;
            let sy = arg(machine, regs, 7) as i32;
            let Some(source_bitmap) = dc_bitmap(state, src) else {
                return 0;
            };
            let Some((sw, sh, source)) = state.gdi_objects.iter().find_map(|(h, o)| match o {
                GdiObject::Bitmap {
                    width,
                    height,
                    pixels,
                } if *h == source_bitmap => Some((*width, *height, pixels.clone())),
                _ => None,
            }) else {
                return 0;
            };
            for y in 0..height {
                for x in 0..width {
                    let px = sx + x as i32;
                    let py = sy + y as i32;
                    if px >= 0 && py >= 0 && px < sw as i32 && py < sh as i32 {
                        let at = (py as usize * sw as usize + px as usize) * 4;
                        let color = u32::from_le_bytes([
                            source[at],
                            source[at + 1],
                            source[at + 2],
                            source[at + 3],
                        ]);
                        put_pixel(state, dst, dx + x as i32, dy + y as i32, color);
                    }
                }
            }
            state.dirty = true;
            1
        }
        Api::Stub(result) => result,
        Api::ExitProcess => unreachable!(),
    }
}

pub fn handle_event<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &mut Regs,
    event: crate::KernelEvent,
) -> thread::KernelAction {
    if let Some(mut win16) = state.win16.take() {
        let action = win16::handle_event(machine, kt, state, &mut win16, regs, event);
        state.win16 = Some(win16);
        return action;
    }
    match event {
        crate::KernelEvent::Irq => thread::KernelAction::Done,
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let Some(gate) = state
                .gates
                .iter()
                .copied()
                .find(|g| g.return_ip == regs.ip32())
            else {
                crate::println!("Windows: invalid API gate at {:#x}", regs.ip32());
                return thread::KernelAction::Exit(-1);
            };
            if gate.api == Api::ExitProcess {
                return thread::KernelAction::Exit(arg(machine, regs, 0) as i32);
            }
            if crate::kernel::startup::trace_enabled() {
                crate::dbg_println!("[win32] {}", core::str::from_utf8(gate.name).unwrap_or("?"));
            }
            if gate.api == Api::RetroWndProcReturn {
                let Some(callback) = state.callback.take() else {
                    crate::dbg_println!("Windows: stray WNDPROC return");
                    return thread::KernelAction::Exit(-1);
                };
                let result = regs.rax as u32;
                finish(machine, regs, callback.gate, result);
                return thread::KernelAction::Done;
            }
            if gate.api == Api::DispatchMessageW {
                let msg = arg(machine, regs, 0) as usize;
                let message = Message {
                    hwnd: machine.read::<u32>(msg),
                    message: machine.read::<u32>(msg + 4),
                    wparam: machine.read::<u32>(msg + 8),
                    lparam: machine.read::<u32>(msg + 12),
                };
                if begin_wndproc(machine, regs, state, gate, message) {
                    return thread::KernelAction::Done;
                }
            }
            let result = dispatch(machine, kt, state, regs, gate.api);
            finish(machine, regs, gate, result);
            thread::KernelAction::Done
        }
        crate::KernelEvent::PageFault { .. } => {
            unreachable!("page faults are handled by the event loop")
        }
        _ => {
            crate::println!("Windows: unhandled event {:?} at {:#x}", event, regs.ip32());
            thread::KernelAction::Exit(-1)
        }
    }
}
