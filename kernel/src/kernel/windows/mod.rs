//! Native Windows personality.
//!
//! PE imports resolve against Wine and RetroOS backend DLLs. Only explicit
//! private INT 83h exports enter kernel services. Windows API behavior belongs
//! in userspace; missing exports never synthesize kernel implementations.

extern crate alloc;

pub mod pe;
pub mod ne;
mod atoms;
mod memory;
mod registry;
mod native_file;
mod session;
mod sections;
mod user_objects;
mod user_queue;
mod graphics;
mod classes;
mod extra;
mod encoding;
mod threads;
mod exceptions;
mod wine_startup;
mod win16;

use crate::Regs;
use crate::kernel::thread;
use alloc::{vec, vec::Vec};

const GATE_VECTOR: u8 = 0x83;
const DLL_BASE_FIRST: u32 = 0x1000_0000;
const DLL_BASE_STRIDE: u32 = 0x0100_0000;
const STACK_TOP: u32 = 0xbff0_0000;
pub(super) const USER_LIMIT: u32 = 0xc000_0000;
// Wine places 0x800 bytes of per-thread debug storage after the TEB.
const TEB_BASE: u32 = 0x7ffd_d000;
const TEB_SIZE: usize = 8192;
// TEB scratch string used by Wine's ANSI-to-Unicode filename conversion.
const TEB_STATIC_STRING: u32 = 0xbf8;
const TEB_STATIC_BUFFER: u32 = 0xc00;
fn initialize_teb_string<A: crate::Arch>(machine: &mut A) {
    machine.write::<u16>((TEB_BASE + TEB_STATIC_STRING) as usize, 0);
    machine.write::<u16>((TEB_BASE + TEB_STATIC_STRING + 2) as usize, 522);
    machine.write::<u32>((TEB_BASE + TEB_STATIC_STRING + 4) as usize, TEB_BASE + TEB_STATIC_BUFFER);
}
// Wine stores debug-channel options on the page following the PEB.
const PEB_BASE: u32 = 0x7ffd_9000;
const PEB_SIZE: usize = 8192;
const PROCESS_DATA: u32 = 0x7ffd_c000;
const HEAP_BASE: u32 = 0x5000_0000;

const RECENT_APIS: usize = 12;
#[derive(Clone, Copy)]
struct RecentApi {
    name: [u8; 40],
    len: u8,
}
static mut RECENT: [RecentApi; RECENT_APIS] = [RecentApi { name: [0; 40], len: 0 }; RECENT_APIS];
static mut RECENT_AT: usize = 0;

fn note_api(name: &[u8]) {
    let mut slot = RecentApi { name: [0; 40], len: 0 };
    let n = name.len().min(slot.name.len());
    slot.name[..n].copy_from_slice(&name[..n]);
    slot.len = n as u8;
    unsafe {
        let at = core::ptr::read_volatile(&raw const RECENT_AT);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(RECENT).cast::<RecentApi>().add(at % RECENT_APIS),
            slot,
        );
        core::ptr::write_volatile(&raw mut RECENT_AT, at.wrapping_add(1));
    }
}

/// The last Win32 gates entered, oldest first. Printed from the page-fault
/// path so a jump to a null pointer still names the calls that led there.
pub fn print_recent_apis() {
    unsafe {
        let n = core::ptr::read_volatile(&raw const RECENT_AT);
        if n == 0 {
            return;
        }
        let start = n.saturating_sub(RECENT_APIS);
        for i in start..n {
            let slot = core::ptr::read_volatile(
                core::ptr::addr_of!(RECENT).cast::<RecentApi>().add(i % RECENT_APIS),
            );
            if slot.len == 0 {
                continue;
            }
            crate::compact_println!(
                "  api {}",
                core::str::from_utf8(&slot.name[..slot.len as usize]).unwrap_or("?")
            );
        }
    }
}

const INVALID_HANDLE_VALUE: u32 = 0xffff_ffff;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    BitBlt,
    DeleteDC,
    DeleteObject,
    EndPaint,
    ExitProcess,
    Extension,
    FillRect,
    InvalidateRect,
    RetroWndProcReturn,
    SelectObject,
    TextOutW,
    WriteFile,
    Yield,
    Unsupported,
    MapFile,
    LocaleId,
    Registry,
    Clock,
    SetSelectors,
    MemoryProtect,
    SystemInfo,
    ClearTls,
    FileKind,
    NativeFile,
    Session,
    Section,
    MemoryQuery,
    Wait,
    NativeThread,
    RestoreContext,
    UserObject,
    WindowObject,
    WindowTree,
    Cursor,
    Graphics,
    UniqueId,
    Class,
    Atom,
    DosMemory,
    Event,
    Sync,
    UserQueue,
    MemoryReserve,
    MemoryCommit,
    MemoryDecommit,
    MemoryRelease,

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

#[derive(Clone, Copy)]
struct Message {
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
}

pub(super) struct Window {
    hwnd: u32,
    parent: u32,
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
    Font,
}

struct DeviceContext {
    viewport: Option<(i32, i32, u32, u32)>,
    handle: u32,
    window: Option<u32>,
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
    module_result: Option<u32>,
}

/// Windows API state plus optional protected-mode DOS services for NE programs.
pub struct WindowsProcess<A: crate::Arch> {
    state: WindowsState,
    dos: Option<alloc::boxed::Box<crate::kernel::dos::DosState<A>>>,
}
impl<A: crate::Arch> WindowsProcess<A> {
    pub fn on_resume(&mut self, machine: &mut A) {
        self.state.on_resume(machine);
        if let Some(dos) = &mut self.dos {
            dos.ldt[..self.state.ldt.len()].copy_from_slice(&self.state.ldt);
        }
    }
    pub fn on_exit(&mut self, machine: &mut A, regs: &mut Regs) {
        if let Some(dos) = &mut self.dos { dos.on_exit(machine, regs, false); }
    }
}
impl<A: crate::Arch> From<WindowsState> for WindowsProcess<A> {
    fn from(state: WindowsState) -> Self { Self { state, dos: None } }
}
impl<A: crate::Arch> core::ops::Deref for WindowsProcess<A> {
    type Target = WindowsState;
    fn deref(&self) -> &WindowsState { &self.state }
}
impl<A: crate::Arch> core::ops::DerefMut for WindowsProcess<A> {
    fn deref_mut(&mut self) -> &mut WindowsState { &mut self.state }
}

type GdiClipRect = (i32, i32, i32, i32);

pub struct WindowsState {
    pub(crate) environment: Vec<u8>,
    file_oem: bool,
    gates: Vec<Gate>,
    threads: threads::State,
    exceptions: exceptions::State,
    registry: registry::Handles,
    ldt: Vec<u64>,
    modules: Vec<Module>,
    allocations: Vec<(u32, u32)>,
    memory: Vec<memory::Region>,
    session: session::State,
    sections: sections::State,
    user_objects: user_objects::State,
    user_queues: user_queue::State,
    classes: classes::State,
    protections: Vec<(u32, u32)>,
    heap_next: u32,
    blocks: Vec<extra::Block>,
    mappings: Vec<extra::Mapping>,
    tls: [u32; 64],
    tls_mask: u64,
    finds: Vec<extra::Find>,
    next_find: u32,
    console: extra::Console,
    /// Last `SetConsoleMode` value for the three standard handles. S-Lang
    /// refuses to start the screen if the input handle still has processed
    /// mode (bit 0) set, which is what a constant mode of 3 reported.
    last_error: u32,
    error_mode: u32,
    pub cwd: [u8; 128],
    pub cwd_len: usize,
    exec_path: [u8; 164],
    exec_path_len: usize,
    command_line_a: u32,
    command_line_w: u32,
    next_object: u32,
    process_info_out: usize,
    process_handle: u32,
    process_tid: u32,
    process_exit_code: Option<u32>,
    teb_base: u32,
    stack_base: u32,
    stack_size: u32,
    windows: Vec<Window>,
    presentations: Vec<(u32, crate::kernel::gui::NodeId)>,
    messages: Vec<Message>,
    user_events: Vec<u32>,
    registered_messages: Vec<(Vec<u8>,u32)>,
    // DLL initialization only; USER32 window callbacks use ordinary guest calls.
    callback: Option<Callback>,
    callback_stack: Vec<Callback>,
    callback_return: u32,
    paint_dc: u32,
    dirty: bool,
    cursor_dirty: bool,
    cursor_visible: bool,
    paint_hwnd: u32,
    focus_hwnd: u32,
    gdi_objects: Vec<(u32, GdiObject)>,
    dcs: Vec<DeviceContext>,
    gdi_rops: Vec<(u32,i32)>,
    gdi_clips: Vec<(u32, Vec<GdiClipRect>)>,
    mouse_x: i32,
    mouse_y: i32,
    mouse_buttons: u8,
    win16: Option<win16::State>,
}

impl WindowsState {
    fn new() -> Self {
        Self {
            environment: extra::windows_environment(&[]),
            file_oem: false,
            gates: Vec::new(),
            threads: threads::State::default(),
            exceptions: exceptions::State::default(),
            registry: registry::Handles::default(),
            ldt: vec![0],
            modules: Vec::new(),
            allocations: Vec::new(),
            memory: Vec::new(),
            session: session::State::default(),
            sections: sections::State::default(),
            user_objects: user_objects::State::default(),
            user_queues: user_queue::State::default(),
            classes: classes::State::default(),
            protections: Vec::new(),
            heap_next: HEAP_BASE,
            blocks: Vec::new(),
            mappings: Vec::new(),
            tls: [0; 64],
            tls_mask: 0,
            finds: Vec::new(),
            next_find: 0x30000,
            console: extra::Console::new(),
            last_error: 0,
            error_mode: 0,
            cwd: [0; 128],
            cwd_len: 0,
            exec_path: [0; 164],
            exec_path_len: 0,
            command_line_a: 0,
            command_line_w: 0,
            next_object: 0x10000,
            process_info_out: 0,
            process_handle: 0,
            process_tid: 0,
            process_exit_code: None,
            teb_base: TEB_BASE,
            stack_base: 0,
            stack_size: 0,
            windows: Vec::new(),
            presentations: Vec::new(),
            messages: Vec::new(),
            user_events: Vec::new(),
            registered_messages: Vec::new(),
            callback: None,
            callback_stack: Vec::new(),
            callback_return: 0,
            paint_dc: 0x20000,
            dirty: true,
            cursor_dirty: true,
            cursor_visible: true,
            paint_hwnd: 0,
            focus_hwnd: 0,
            gdi_objects: Vec::new(),
            dcs: Vec::new(),
            gdi_rops: Vec::new(),
            gdi_clips: Vec::new(),
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
        if self.process_info_out != 0 && self.process_tid != 0 {
            let out = self.process_info_out;
            machine.write::<u32>(out, self.process_handle);
            machine.write::<u32>(out + 4, 0);
            machine.write::<u32>(out + 8, self.process_tid);
            machine.write::<u32>(out + 12, self.process_tid);
            self.process_info_out = 0;
        }
    }
    pub(crate) fn prepare_process(&mut self, process_info_out: usize) -> u32 {
        let handle = self.next_object;
        self.next_object = self.next_object.wrapping_add(4);
        self.process_info_out = process_info_out;
        self.process_handle = handle;
        self.process_tid = 0;
        self.process_exit_code = None;
        handle
    }
    pub(crate) fn process_started(&mut self, tid: u32) {
        self.process_tid = tid;
    }
    pub(crate) fn process_exited(&mut self, tid: u32, code: u32) {
        if self.process_tid == tid {
            self.process_exit_code = Some(code);
        }
    }
    pub(crate) fn process_exit_code(&self, handle: u32) -> Option<u32> {
        (handle == self.process_handle).then_some(self.process_exit_code).flatten()
    }
    pub fn repaint_osd(&mut self) {
        self.cursor_dirty = true;
    }
    fn wake_user(&mut self) {
        for &event in &self.user_events {
            threads::signal(&mut self.threads, event);
        }
    }
    pub fn process_key(&mut self, fds: &[thread::FdKind; thread::MAX_FDS], scancode: u8, now: u64) {
        let pressed = crate::kernel::keyboard::update_console(&mut self.console.keyboard,scancode);
        if crate::kernel::keyboard::event().scan == 0 { return; }
        user_queue::keyboard_event(self, crate::kernel::keyboard::event(), crate::kernel::keyboard::control_state(), now);
        self.wake_user();
        extra::push_key(&mut self.console, scancode, crate::kernel::keyboard::event(), crate::kernel::keyboard::control_state());
        if !pressed {
            return;
        }
        if let thread::FdKind::PipeRead(p) = fds[0] {
            let event = crate::kernel::keyboard::event();
            for &character in event.characters() {
                let mut bytes = [0;4];
                let text = character.encode_utf8(&mut bytes);
                let bytes = encoding::page(self.console.input_cp).unwrap().encode(text,b'?').0;
                crate::kernel::kpipe::write(p,&bytes);
            }
        }
    }

    pub fn process_mouse(&mut self, dx: i16, dy: i16, buttons: u8) {
        let Some(window) = self.windows.iter().rfind(|w| w.visible && w.parent == 0) else {
            return;
        };
        let hwnd = window.hwnd;
        let (width, height) = self.windows.iter().filter(|w| w.visible && w.parent == 0)
            .fold((640, 480), |(width, height), w| (
                width.max(w.x.saturating_add(w.width as i32)),
                height.max(w.y.saturating_add(w.height as i32))));
        self.mouse_x = self.mouse_x.saturating_add(i32::from(dx)).clamp(0, width - 1);
        self.mouse_y = self.mouse_y.saturating_add(i32::from(dy)).clamp(0, height - 1);
        // USER32 routes this desktop position, including capture and hit tests.
        let x = self.mouse_x - window.x;
        let y = self.mouse_y - window.y;
        let lparam = (x as u32 & 0xffff) | ((y as u32 & 0xffff) << 16);
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
        self.wake_user();
        self.mouse_buttons = buttons;
        self.cursor_dirty = true;
    }
}

#[allow(clippy::too_many_arguments)] // Shared executable launch context.
pub fn exec_ne_into<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
    cmdtail: &[u8],
    parent_env: &[u8],
) -> Result<(), i32> {
    win16::exec(machine, threads, tid, data, path, parent_cwd, launcher, cmdtail, parent_env)
}

/// Publish guest-owned top-level surfaces. USER32 owns placement and window
/// policy; the desktop composes every surface rather than discarding all but
/// the last one (for example, a game's floating status/tool window).
pub fn render<A: crate::Arch>(
    _machine: &mut A,
    _bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    state: &mut WindowsState,
    _display: &mut crate::kernel::display::Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    publish_surfaces(state, desktop, endpoint);
}

fn publish_surfaces(
    state: &mut WindowsState,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    use crate::kernel::gui::{Point, PresentationKey, Rect, SurfaceKey, Transaction};
    let focus_changed = desktop.focus(endpoint);
    let pointer_changed = if state.cursor_visible {
        desktop.set_pointer(Point { x: state.mouse_x, y: state.mouse_y })
    } else { desktop.clear_pointer() };
    if !state.dirty && !state.cursor_dirty && !focus_changed && !pointer_changed {
        return;
    }
    let mut transaction = Transaction::new(endpoint);
    let mut structural = false;
    let order_changed = state.presentations.iter().map(|&(hwnd, _)| hwnd)
        .ne(state.windows.iter().filter(|w| w.parent == 0).map(|w| w.hwnd));
    state.presentations.retain(|&(hwnd, node)| {
        if state.windows.iter().any(|w| w.hwnd == hwnd && w.parent == 0) {
            true
        } else {
            transaction.destroy(node);
            structural = true;
            false
        }
    });
    for window in state.windows.iter().filter(|w| w.parent == 0) {
        let key = SurfaceKey(u64::from(window.hwnd));
        let surface = desktop.ensure_surface(endpoint, key).expect("create Windows surface");
        let geometry = Rect::new(window.x, window.y, window.width, window.height);
        let node = desktop.ensure_node(endpoint, PresentationKey(key.0), geometry)
            .expect("create Windows presentation");
        if !state.presentations.iter().any(|&(hwnd, _)| hwnd == window.hwnd) {
            state.presentations.push((window.hwnd, node));
        }
        if desktop.node_state(node).is_none_or(|current| {
            current.geometry != geometry || current.content != Some(surface)
                || current.visible != window.visible
        }) {
            transaction.set_geometry(node, geometry).attach(node, Some(surface))
                .set_visible(node, window.visible);
            structural = true;
        }
        if state.dirty {
            desktop.damage_surface(endpoint, key);
        }
        if order_changed {
            // Native surface order is supplied by guest USER32, back to front.
            transaction.raise(node);
            structural = true;
        }
    }
    if structural { desktop.commit(transaction).expect("commit Windows presentations"); }
    if order_changed {
        for (i, window) in state.windows.iter().filter(|w| w.parent == 0).enumerate() {
            if let Some(j) = state.presentations.iter().position(|&(hwnd, _)| hwnd == window.hwnd) {
                state.presentations.swap(i, j);
            }
        }
    }
    state.dirty = false;
    state.cursor_dirty = false;
}

pub fn surface_buffer(
    state: &WindowsState,
    key: crate::kernel::gui::SurfaceKey,
) -> Option<crate::kernel::gui::PixelBuffer<'_>> {
    let window = state.windows.iter().find(|w| u64::from(w.hwnd) == key.0 && w.parent == 0)?;
    crate::kernel::gui::PixelBuffer::new(
        window.width as usize,
        window.height as usize,
        window.width as usize * 4,
        if window.hwnd == state.console.hwnd { vga::PixelFormat::NATIVE }
        else { vga::PixelFormat { red_pos: 0, blue_pos: 16, ..vga::PixelFormat::NATIVE } },
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
    if !out.contains(&b'.') {
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
    let system = join(crate::kernel::dos::c_root(), b"RETROOS/WINDOWS/SYSTEM32");
    for path in [join(dirname(importer), &file), join(&system, &file)] {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&path) {
            return Ok((path, data));
        }
    }
    crate::compact_println!(
        "Windows: missing {}",
        core::str::from_utf8(&file).unwrap_or("dll")
    );
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

/// Track explicit protection changes and otherwise use the PE section flags.
fn memory_protection(state: &WindowsState, address: u32) -> Option<u32> {
    let page = address & !4095;
    if let Some(&(_, protection)) = state.protections.iter().find(|&&(p, _)| p == page) {
        return Some(protection);
    }
    if let Some(flags) = memory::permissions(state, address) {
        return Some(match flags { 0 => 2, 1 => 4, 2 => 0x20, _ => 0x40 });
    }
    for module in &state.modules {
        let Ok(image) = pe::Image::parse(&module.data) else { continue; };
        if address >= module.base && address < module.base.checked_add(image.header.size_image)? {
            for section in image.sections().ok()? {
                let start = module.base.checked_add(section.rva)?;
                let end = start.checked_add(section.virtual_size.max(section.raw_size))?;
                if address >= (start & !4095) && address < end.next_multiple_of(4096) {
                    let write = section.characteristics & 0x80000000 != 0;
                    let execute = section.characteristics & 0x20000000 != 0;
                    return Some(match (write, execute) {
                        (false, false) => 2, (true, false) => 4,
                        (false, true) => 0x20, (true, true) => 0x40,
                    });
                }
            }
            return Some(2);
        }
    }
    if (address >= state.stack_base && address < state.stack_base + state.stack_size)
        || (address >= HEAP_BASE && address < state.heap_next)
        || state.allocations.iter().any(|&(base,size)| address >= base && address < base + size)
    { Some(4) } else { None }
}

fn protection_flags(protection: u32) -> Option<(bool, bool)> {
    match protection {
        2 => Some((false, false)),
        4 | 8 => Some((true, false)),
        0x10 | 0x20 => Some((false, true)),
        0x40 | 0x80 => Some((true, true)),
        _ => None,
    }
}

fn change_protection<A: crate::Arch>(machine: &mut A, state: &mut WindowsState,
                                   address: u32, size: u32, protection: u32) -> Result<u32,u32> {
    let (write,execute) = protection_flags(protection).ok_or(ERROR_INVALID_PARAMETER)?;
    let end = address.checked_add(size).filter(|&end| size != 0 && end < USER_LIMIT)
        .ok_or(ERROR_INVALID_PARAMETER)?;
    let start = address & !4095;
    let limit = end.next_multiple_of(4096);
    let old = memory_protection(state,address).ok_or(487u32)?;
    for page in (start..limit).step_by(4096) {
        if memory_protection(state,page).is_none() { return Err(487); }
        if !memory::can_protect(state, page, write, execute) { return Err(5); }
    }
    machine.set_page_flags(start as usize / 4096, ((limit-start)/4096) as usize, write,execute);
    for page in (start..limit).step_by(4096) {
        if let Some(entry) = state.protections.iter_mut().find(|entry| entry.0 == page) {
            entry.1 = protection;
        } else { state.protections.push((page,protection)); }
    }
    Ok(old)
}

// Both startup imports and dynamic loads follow only requested forwarders.
// Loading every export's target would pull optional DLLs into every process.
fn ensure_dependency(modules: &mut Vec<Module>, name: &[u8], importer: usize) -> Result<usize, i32> {
    if let Some(index) = find_module(modules, name) { return Ok(index); }
    let (path, data) = load_dependency(name, &modules[importer].path)?;
    let image = pe::Image::parse(&data).map_err(|_| 8)?;
    if !image.is_dll() { return Err(8); }
    let index = modules.len();
    let base = DLL_BASE_FIRST.checked_add((index as u32 - 1).checked_mul(DLL_BASE_STRIDE).ok_or(8)?).ok_or(8)?;
    if image.header.size_image > DLL_BASE_STRIDE || base.checked_add(image.header.size_image).is_none_or(|end| end > HEAP_BASE) {
        return Err(8);
    }
    modules.push(Module { name: module_name(name), path, data, base });
    Ok(index)
}

fn load_import_dependencies(modules: &mut Vec<Module>, start: usize) -> Result<(), i32> {
    let mut index = start;
    while index < modules.len() {
        let imports = pe::Image::parse(&modules[index].data).map_err(|_| 8)?.imports().map_err(|_| 8)?;
        for import in imports {
            let mut target = ensure_dependency(modules, &import.module, index)?;
            let mut symbol = import.symbol;
            let mut visited = Vec::new();
            loop {
                if visited.contains(&(target, symbol.clone())) { return Err(127); }
                visited.push((target, symbol.clone()));
                let image = pe::Image::parse(&modules[target].data).map_err(|_| 8)?;
                // apply_imports emits the diagnostic for absent exports.
                let Some(rva) = image.export_rva(&symbol).map_err(|_| 8)? else { break; };
                let Some((name, next)) = image.forwarder(rva).map_err(|_| 8)? else { break; };
                target = ensure_dependency(modules, &name, target)?;
                symbol = next;
            }
        }
        index += 1;
    }
    Ok(())
}

fn resolve_export(modules: &[Module], mut index: usize, symbol: &pe::ImportSymbol) -> Result<u32, i32> {
    let mut symbol = symbol.clone();
    let mut visited = Vec::new();
    loop {
        if visited.contains(&(index, symbol.clone())) { return Err(127); }
        visited.push((index, symbol.clone()));
        let module = &modules[index];
        let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
        let rva = image.export_rva(&symbol).map_err(|_| 8)?.ok_or(127)?;
        if let Some((name, next)) = image.forwarder(rva).map_err(|_| 8)? {
            index = find_module(modules, &name).ok_or(2)?;
            symbol = next;
        } else { return module.base.checked_add(rva).ok_or(8); }
    }
}

fn apply_imports<A: crate::Arch>(machine: &mut A, modules: &[Module], index: usize) -> Result<(), i32> {
    let image = pe::Image::parse(&modules[index].data).map_err(|_| 8)?;
    for import in image.imports().map_err(|_| 8)? {
        let target_index = find_module(modules, &import.module).ok_or(2)?;
        let address = resolve_export(modules, target_index, &import.symbol).map_err(|error| {
            let name = match &import.symbol {
                pe::ImportSymbol::Name(name) => name.clone(),
                pe::ImportSymbol::Ordinal(n) => alloc::format!("#{n}").into_bytes(),
            };
            crate::compact_println!("Windows: unresolved {}!{}",
                core::str::from_utf8(&import.module).unwrap_or("dll"),
                core::str::from_utf8(&name).unwrap_or("symbol"));
            error
        })?;
        machine.write::<u32>((modules[index].base + import.iat_rva) as usize, address);
    }
    Ok(())
}

fn dll_initializers(modules: &[Module], start: usize) -> Result<Vec<(u32, u32)>, i32> {
    fn visit(modules: &[Module], index: usize, start: usize, seen: &mut [bool], output: &mut Vec<(u32,u32)>) -> Result<(),i32> {
        if index < start || seen[index] { return Ok(()); }
        seen[index] = true; // Circular DLL dependencies are permitted.
        let image = pe::Image::parse(&modules[index].data).map_err(|_| 8)?;
        for import in image.imports().map_err(|_| 8)? {
            let dependency = find_module(modules, &import.module).ok_or(2)?;
            visit(modules, dependency, start, seen, output)?;
            let address = resolve_export(modules, dependency, &import.symbol)?;
            if let Some(target) = modules.iter().position(|m| address >= m.base && address - m.base < DLL_BASE_STRIDE) {
                visit(modules, target, start, seen, output)?;
            }
        }
        if image.header.entry_rva != 0 {
            output.push((modules[index].base, modules[index].base.checked_add(image.header.entry_rva).ok_or(8)?));
        }
        Ok(())
    }
    let mut seen = vec![false; modules.len()];
    let mut output = Vec::new();
    for index in start..modules.len() { visit(modules, index, start, &mut seen, &mut output)?; }
    Ok(output)
}

fn rollback_modules<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, start: usize) {
    for module in &state.modules[start..] {
        if let Ok(image) = pe::Image::parse(&module.data) {
            machine.unmap_range(module.base as usize / 4096, (image.header.size_image as usize).div_ceil(4096));
        }
    }
    state.gates.retain(|gate| !state.modules[start..].iter().any(|module|
        gate.return_ip >= module.base && gate.return_ip - module.base < DLL_BASE_STRIDE));
    state.modules.truncate(start);
}

/// Map a DLL requested after startup, retaining the process's import gates.
fn load_library<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, name: &[u8]) -> Result<(u32,Vec<(u32,u32)>),u32> {
    let file=name.rsplit(|&b|b==b'/' || b==b'\\').next().unwrap_or(name);
    if let Some(index)=find_module(&state.modules,file) {return Ok((state.modules[index].base,Vec::new()));}
    let raw=if file.contains(&b'.') {name.to_vec()} else {let mut path=name.to_vec();path.extend_from_slice(b".DLL");path};
    // A bare DLL name may exist only in SYSTEM32. Resolve the prospective
    // local path first, then let the dependency search handle a missing file.
    let path=windows_path(state,&raw,true)?;
    let (path,data)=match crate::kernel::exec::load_file_resolved(&path) {
        Ok(data)=>(path,data),
        Err(_)=>load_dependency(file,&state.modules[0].path).map_err(|_|126u32)?,
    };
    let image=pe::Image::parse(&data).map_err(|_|193u32)?;
    if !image.is_dll() {return Err(193);}
    let start=state.modules.len();
    let base=DLL_BASE_FIRST.checked_add((start as u32-1).checked_mul(DLL_BASE_STRIDE).ok_or(8u32)?).ok_or(8u32)?;
    if image.header.size_image > DLL_BASE_STRIDE || base.checked_add(image.header.size_image).is_none_or(|end| end > HEAP_BASE) { return Err(8); }
    if crate::kernel::startup::trace_enabled() {
        crate::compact_dbg_println!("[win32-load] {} base={:08x}",core::str::from_utf8(&path).unwrap_or("?"),base);
    }
    state.modules.push(Module{name:module_name(file),path,data,base});
    let result=(|| {
        load_import_dependencies(&mut state.modules, start).map_err(|e| e as u32)?;
        for module in &state.modules[start..] {map_module(machine,module).map_err(|_|8u32)?;}
        for index in start..state.modules.len() {apply_imports(machine,&state.modules,index).map_err(|_|127u32)?;}
        for module in &state.modules[start..] {
            protect_module(machine,module).map_err(|_|8u32)?;
            register_module_gates(machine, module, &mut state.gates).map_err(|e| e as u32)?;
        }
        let dlls = dll_initializers(&state.modules, start).map_err(|e| e as u32)?;
        Ok((base,dlls))
    })();
    if result.is_err() {
        rollback_modules(machine, state, start);
    }
    result
}

/// Guest code that calls each real DLL entry with DLL_PROCESS_ATTACH, then
/// jumps to the executable. Each DllMain is stdcall and removes its own
/// arguments, so the stack the executable sees is unchanged.
fn dll_startup_stub<A: crate::Arch>(
    machine: &mut A,
    dlls: &[(u32, u32)],
    exe_entry: u32,
    abort: u32,
) -> Result<u32, i32> {
    dll_startup_stub_at(machine, dlls, exe_entry, 0x7ff2_0000, abort)
}

fn dll_startup_stub_at<A: crate::Arch>(machine: &mut A, dlls: &[(u32,u32)], exe_entry: u32, stub: u32, abort: u32) -> Result<u32,i32> {
    let mut code = Vec::new();
    for &(base, entry) in dlls {
        code.extend_from_slice(&[0x68, 0, 0, 0, 0]);
        code.extend_from_slice(&[0x68, 1, 0, 0, 0]);
        code.push(0x68);
        code.extend_from_slice(&base.to_le_bytes());
        code.push(0xb8);
        code.extend_from_slice(&entry.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]);
        // A failed attach must not fall through into the application's entry.
        code.extend_from_slice(&[0x85, 0xc0, 0x75, 14, 0x68]);
        code.extend_from_slice(&0xc0000142u32.to_le_bytes());
        code.push(0xb8);
        code.extend_from_slice(&abort.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0, 0x0f, 0x0b]);
    }
    code.push(0x68);
    code.extend_from_slice(&exe_entry.to_le_bytes());
    code.push(0xc3);
    if code.len() > 4096 {
        return Err(8);
    }
    machine.zero(stub as usize, 4096);
    machine.copy_to(stub as usize, &code);
    machine.set_page_flags(stub as usize / 4096, 1, false, true);
    Ok(stub)
}

const API_SPECS: &[(&[u8], &[u8], Api, u32)] = &[
    (b"RETROOS", b"RetroProcessExit", Api::ExitProcess, 4),
    (b"RETROOS", b"RetroWriteFile", Api::WriteFile, 20),
    (b"RETROOS", b"RetroYield", Api::Yield, 0),
    (b"RETROOS", b"RetroMapFile", Api::MapFile, 12),
    (b"RETROOS", b"RetroLocaleId", Api::LocaleId, 0),
    (b"RETROOS", b"RetroRegistry", Api::Registry, 28),
    (b"RETROOS", b"RetroClock", Api::Clock, 4),
    (b"RETROOS", b"RetroMemoryProtect", Api::MemoryProtect, 12),
    (b"RETROOS", b"RetroSystemInfo", Api::SystemInfo, 4),
    (b"RETROOS", b"RetroClearTls", Api::ClearTls, 4),
    (b"RETROOS", b"RetroFileKind", Api::FileKind, 4),
    (b"RETROOS", b"RetroFile", Api::NativeFile, 28),
    (b"RETROOS", b"RetroSession", Api::Session, 24),
    (b"RETROOS", b"RetroSection", Api::Section, 24),
    (b"RETROOS", b"RetroMemoryQuery", Api::MemoryQuery, 8),
    (b"RETROOS", b"RetroWait", Api::Wait, 20),
    (b"RETROOS", b"RetroThread", Api::NativeThread, 12),
    (b"RETROOS", b"RetroRestoreContext", Api::RestoreContext, 4),
    (b"RETROOS", b"RetroUserObject", Api::UserObject, 24),
    (b"RETROOS", b"RetroWindow", Api::WindowObject, 24),
    (b"RETROOS", b"RetroWindowTree", Api::WindowTree, 12),
    (b"RETROOS", b"RetroCursor", Api::Cursor, 8),
    (b"RETROOS", b"RetroGraphics", Api::Graphics, 12),
    (b"RETROOS", b"RetroUniqueId", Api::UniqueId, 4),
    (b"RETROOS", b"RetroClass", Api::Class, 20),
    (b"RETROOS", b"RetroAtom", Api::Atom, 20),
    (b"RETROOS", b"RetroDosMemory", Api::DosMemory, 16),
    (b"RETROOS", b"RetroEvent", Api::Event, 16),
    (b"RETROOS", b"RetroSync", Api::Sync, 24),
    (b"RETROOS", b"RetroQueue", Api::UserQueue, 12),
    (b"RETROOS", b"RetroSetSelectors", Api::SetSelectors, 24),
    (b"RETROOS", b"RetroMemoryReserve", Api::MemoryReserve, 8),
    (b"RETROOS", b"RetroMemoryCommit", Api::MemoryCommit, 12),
    (b"RETROOS", b"RetroMemoryDecommit", Api::MemoryDecommit, 8),
    (b"RETROOS", b"RetroMemoryRelease", Api::MemoryRelease, 4),
    (b"RETROOS", b"RetroUnsupported", Api::Unsupported, 4),
];

/// Real DLL functions execute as guest code. Only explicit INT 83h exports
/// register kernel gates, identically for startup imports and LoadLibrary.
fn register_module_gates<A: crate::Arch>(machine: &A, module: &Module, gates: &mut Vec<Gate>) -> Result<(), i32> {
    let image = pe::Image::parse(&module.data).map_err(|_| 8)?;
    let dll_name = module.name.strip_suffix(b".DLL").unwrap_or(&module.name);
    for export in image.exports().map_err(|_| 8)? {
        let address = module.base + export.rva;
        if machine.read::<u16>(address as usize) != 0x83cd { continue; }
        let core = API_SPECS.iter().find(|(dll, name, _, _)|
            dll_name.eq_ignore_ascii_case(dll) && export.name == *name);
        let spec = core.map(|(_, name, api, bytes)| (*name, *api, *bytes));
        if let Some((name, api, arg_bytes)) = spec {
            gates.push(Gate { return_ip: address + 2, api, arg_bytes, name });
        }
    }
    Ok(())
}

fn export_address(modules: &[Module], module: &[u8], name: &[u8]) -> Result<u32, i32> {
    let i = find_module(modules, module).ok_or(2)?;
    resolve_export(modules, i, &pe::ImportSymbol::Name(name.to_vec()))
}

pub(super) fn windows_path(state: &WindowsState, path: &[u8], create: bool) -> Result<Vec<u8>, u32> {
    let dos = full_windows_path(state, path);
    crate::kernel::dos::windows_abs_to_vfs(&dos, create).ok_or(ERROR_FILE_NOT_FOUND)
}

/// Resolve absolute, root-relative, drive-relative, and plain relative paths.
pub(super) fn full_windows_path(state: &WindowsState, path: &[u8]) -> Vec<u8> {
    let mut raw = path.to_vec();
    for b in &mut raw {
        if *b == b'/' { *b = b'\\'; }
    }
    let cwd = if state.cwd_len == 0 { b"C:\\".to_vec() } else { guest_windows_path(state.cwd_str()) };
    let drive = cwd.first().copied().unwrap_or(b'C');
    let (prefix, rest) = if raw.len() >= 2 && raw[1] == b':' {
        if raw.get(2) == Some(&b'\\') {
            return canonical_windows_path(&raw);
        }
        let base = if raw[0].eq_ignore_ascii_case(&drive) { cwd } else { vec![raw[0], b':', b'\\'] };
        (base, &raw[2..])
    } else if raw.first() == Some(&b'\\') {
        (vec![drive, b':', b'\\'], &raw[1..])
    } else {
        (cwd, raw.as_slice())
    };
    let mut out = prefix;
    if !rest.is_empty() {
        if out.last() != Some(&b'\\') { out.push(b'\\'); }
        out.extend_from_slice(rest);
    }
    canonical_windows_path(&out)
}

fn canonical_windows_path(path: &[u8]) -> Vec<u8> {
    if path.len() < 3 || path[1] != b':' || path[2] != b'\\' {
        return path.to_vec();
    }
    let mut components: Vec<&[u8]> = Vec::new();
    for component in path[3..].split(|&b| b == b'\\') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            components.pop();
        } else {
            components.push(component);
        }
    }
    let mut out = path[..3].to_vec();
    for component in components {
        if out.len() > 3 { out.push(b'\\'); }
        out.extend_from_slice(component);
    }
    out
}

pub(super) fn guest_windows_path(path: &[u8]) -> Vec<u8> {
    let root = crate::kernel::dos::c_root();
    let root_dir = root.strip_suffix(b"/").unwrap_or(root);
    let drives: &[(u8, &[u8])] = &[
        (b'C', root_dir), (b'D', b"cdrom"), (b'H', b"host"),
        (b'A', b"floppya"), (b'B', b"floppyb"),
        (b'E', b"disk1"), (b'F', b"disk2"), (b'G', b"disk3"),
        (b'I', b"disk4"), (b'J', b"disk5"), (b'K', b"disk6"),
        (b'L', b"disk7"),
    ];
    let configured = (b'E'..=b'L').filter_map(|drive| {
        crate::kernel::dos::extra_drive_prefix(drive)
            .map(|prefix| (drive, prefix.strip_suffix(b"/").unwrap_or(prefix)))
    });
    let Some((drive, prefix)) = configured.chain(drives.iter().copied()).find(|(_, prefix)| {
        path == *prefix || path.strip_prefix(*prefix).is_some_and(|rest| rest.starts_with(b"/"))
    }) else {
        let mut out = b"C:\\".to_vec();
        out.extend(path.iter().map(|&b| if b == b'/' { b'\\' } else { b }));
        return out;
    };
    let suffix = path.strip_prefix(prefix).unwrap_or(b"");
    let relative = suffix.strip_prefix(b"/").unwrap_or(suffix);
    let mut out = vec![drive, b':', b'\\'];
    out.extend(relative.iter().map(|&b| if b == b'/' { b'\\' } else { b }));
    out
}

#[allow(clippy::too_many_arguments)]
pub fn exec_pe_into<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    _parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
    parent_env: &[u8],
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
        // The launch boundary already resolved the VFS image name. Cwd
        // belongs to the child process, not to DLL/image path resolution.
        crate::kernel::exec::resolve_path(path, b"", &mut b).to_vec()
    };
    let mut modules = vec![Module {
        name: b"MAIN.EXE".to_vec(),
        path: main_path.clone(),
        data,
        base: main_header.image_base,
    }];
    load_import_dependencies(&mut modules, 0)?;
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
    machine.zero(TEB_BASE as usize, TEB_SIZE);
    machine.zero(PEB_BASE as usize, PEB_SIZE);
    machine.set_page_flags(PROCESS_DATA as usize / 4096, 1, true, false);
    machine.set_page_flags(TEB_BASE as usize / 4096, TEB_SIZE / 4096, true, false);
    machine.set_page_flags(PEB_BASE as usize / 4096, PEB_SIZE / 4096, true, false);

    machine.write::<u32>(TEB_BASE as usize, 0xffff_ffff); // SEH end marker
    machine.write::<u32>((TEB_BASE + 4) as usize, STACK_TOP);
    machine.write::<u32>((TEB_BASE + 8) as usize, stack_base);
    machine.write::<u32>((TEB_BASE + 0x18) as usize, TEB_BASE);
    machine.write::<u32>((TEB_BASE + 0x20) as usize, 1);
    machine.write::<u32>((TEB_BASE + 0x24) as usize, tid as u32 + 1);
    machine.write::<u32>((TEB_BASE + 0x30) as usize, PEB_BASE);
    initialize_teb_string(machine);
    machine.write::<u8>((PEB_BASE + 4096) as usize, 7);
    machine.write::<u32>((PEB_BASE + 0x64) as usize, 1);
    machine.write::<u32>((PEB_BASE + 8) as usize, modules[0].base);
    machine.write::<u32>((PEB_BASE + 0x10) as usize, PROCESS_DATA);

    let win_path = guest_windows_path(&main_path);
    let cmd_a = PROCESS_DATA + 0x200;
    encoding::copy(machine, cmd_a as usize, 512, &win_path, false);
    let cmd_w = PROCESS_DATA + 0x400;
    encoding::copy(machine, cmd_w as usize, 512, &win_path, true);

    for module in &modules {
        protect_module(machine, module)?;
    }
    let stack = STACK_TOP - 4;
    machine.write::<u32>(stack as usize, 0);
    let entry = modules[0]
        .base
        .checked_add(main_header.entry_rva)
        .ok_or(8)?;
    let dlls = dll_initializers(&modules, 1)?;
    let entry = if dlls.is_empty() {
        entry
    } else {
        let abort = export_address(&modules, b"RETROOS", b"RetroProcessExit")?;
        if let Ok(attach_module) = export_address(&modules, b"NTDLL", b"RetroWineAttachModule") {
            let initializers: Vec<_> = dlls.iter().map(|&(base, _)| (base, attach_module)).collect();
            let attach = dll_startup_stub(machine, &initializers, entry, abort)?;
            wine_startup::bootstrap(machine, &modules, 0, attach, abort, Vec::new())?
        } else {
            dll_startup_stub(machine, &dlls, entry, abort)?
        }
    };
    let current = thread::get_thread(threads, tid).ok_or(8)?;
    thread::init_process_thread(current, entry, stack);

    let mut state = WindowsState::new();
    state.environment = extra::windows_environment(parent_env);
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

    for module in &modules {
        register_module_gates(machine, module, &mut state.gates)?;
    }
    state.callback_return = export_address(&modules, b"USER32", b"RetroWndProcReturn").unwrap_or(0);
    if state.callback_return == 0 {
        state.callback_return=0x7ff6_0000;
        machine.zero(state.callback_return as usize,4096);
        machine.copy_to(state.callback_return as usize,&[0xcd,0x83]);
        machine.set_page_flags(state.callback_return as usize/4096,1,false,true);
        state.gates.push(Gate{return_ip:state.callback_return+2,api:Api::RetroWndProcReturn,arg_bytes:0,name:b"RetroWndProcReturn"});
    }
    if main_header.subsystem == 3 {
        extra::open_console(&mut state);
    }
    state.modules = modules;
    initialize_process_strings(machine,&mut state)?;
    initialize_environment(machine,&mut state)?;
    state.on_resume(machine);
    current.personality = thread::Personality::Windows(state.into());
    Ok(())
}

pub(super) fn arg<A: crate::Arch>(machine: &A, regs: &Regs, n: usize) -> u32 {
    machine.read::<u32>(regs.sp() as usize + 4 + n * 4)
}

pub(super) fn c_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    Ok(encoding::ansi().decode(&raw_string(machine, address)?, false).unwrap().into_bytes())
}

pub(super) fn raw_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
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

pub(super) fn w_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    if address == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut units = encoding::units(machine, address, -1)?;
    units.pop();
    crate::kernel::text::from_utf16(&units, true).map(|s| s.into_bytes()).map_err(|_| 1113)
}

fn finish<A: crate::Arch>(machine: &A, regs: &mut Regs, gate: Gate, result: u32) {
    let sp = regs.sp() as usize;
    let ret = machine.read::<u32>(sp);
    if ret < 0x1000 {
        let mut below = [0u32; 4];
        let mut top = [0u32; 8];
        for (i, word) in below.iter_mut().enumerate() {
            *word = machine.read::<u32>(sp.wrapping_sub(16) + i * 4);
        }
        for (i, word) in top.iter_mut().enumerate() {
            *word = machine.read::<u32>(sp + i * 4);
        }
        crate::compact_println!(
            "Windows: {} returns to {:#x} esp={:#x} eip={:#x} args={}",
            core::str::from_utf8(gate.name).unwrap_or("?"),
            ret,
            sp,
            regs.ip32(),
            gate.arg_bytes
        );
        crate::compact_println!(
            "  below {:08x} {:08x} {:08x} {:08x}",
            below[0], below[1], below[2], below[3]
        );
        crate::compact_println!(
            "  stack {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
            top[0], top[1], top[2], top[3], top[4], top[5], top[6], top[7]
        );
        crate::compact_println!(
            "  iat peek={:#x} readin={:#x} readfile_slot={:#x}",
            machine.read::<u32>(0x46d3b8),
            machine.read::<u32>(0x46d3bc),
            machine.read::<u32>(0x46d3c0)
        );
    }
    regs.rax = result as u64;
    regs.frame.rip = ret as u64;
    regs.frame.rsp += 4 + gate.arg_bytes as u64;
}

pub(super) fn create_file<A: crate::Arch>(
    _machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    raw: &[u8],
    disposition: u32,
) -> u32 {
    let create = matches!(disposition, 1 | 2 | 4 | 5);
    let path = match windows_path(state, raw, create) {
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
    output_cp: u32,
) -> u32 {
    if handle >= thread::MAX_FDS {
        return 0;
    }
    let mut data = vec![0; len];
    machine.copy_from(ptr, &mut data);
    let n = match kt.fds[handle] {
        thread::FdKind::ConsoleOut => {
            let text = encoding::page(output_cp).unwrap().decode(&data, false).unwrap();
            for &b in text.as_bytes() { crate::term::putchar(b); }
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

pub(super) fn copy_ascii<A: crate::Arch>(machine: &mut A, out: usize, cap: usize, text: &[u8]) -> u32 {
    if cap == 0 {
        return 0;
    }
    let encoded = encoding::ansi().encode(&alloc::string::String::from_utf8_lossy(text), b'?').0;
    let n = encoded.len().min(cap - 1);
    machine.copy_to(out, &encoded[..n]);
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
    state.wake_user();
    state.dirty = true;
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

fn object_color(_state: &WindowsState, handle: u32, default: u32) -> u32 {
    if (0x40000..=0x40008).contains(&handle) {
        return match handle - 0x40000 {
            0 | 6 => 0x00ff_ffff, 1 => 0x00c0_c0c0, 2 => 0x0080_8080,
            3 => 0x0040_4040, 4 | 7 => 0, _ => default,
        };
    }
    if (0x30000..0x30100).contains(&handle) {
        return system_color(handle - 0x30000);
    }
    default
}

fn dc_bitmap(state: &WindowsState, dc: u32) -> Option<u32> {
    state
        .dcs
        .iter()
        .find(|item| item.handle == dc)
        .and_then(|item| item.bitmap)
}

struct RenderTarget<'a> {
    dirty: Option<&'a mut bool>,
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
    let viewport = state.dcs.iter().find(|d| d.handle == dc).and_then(|d| d.viewport);
    let window = if dc == state.paint_dc { Some(state.paint_hwnd) } else { state.dcs.iter().find(|d| d.handle == dc).and_then(|d| d.window) };
    if let Some(hwnd) = window {
        let window = state.windows.iter().find(|window| window.hwnd == hwnd)?;
        let (vx, vy, clip_width, clip_height) = viewport.unwrap_or((0, 0, window.width, window.height));
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
        let dirty = &mut state.dirty;
        return state.windows.iter_mut().find(|window| window.hwnd == root).map(|window| {
            let need = window.width as usize * window.height as usize * 4;
            if window.pixels.len() != need {
                window.pixels.resize(need, 0xc0);
            }
            RenderTarget {
                dirty: Some(dirty),
                width: window.width,
                height: window.height,
                origin_x: x.saturating_add(vx),
                origin_y: y.saturating_add(vy),
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
                dirty: None,
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
    let rop = state.gdi_rops.iter().find(|(h,_)|*h==dc).map_or(13,|(_,r)|*r) - 1;
    if state.gdi_clips.iter().find(|(h,_)| *h==dc).is_some_and(|(_,r)| !r.iter().any(|&(l,t,r,b)| l<=x && x<r && t<=y && y<b)) { return; }

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
        let old = u32::from_le_bytes(target.pixels[at..at+4].try_into().unwrap());
        let mut mixed = 0;
        if rop&1!=0 {mixed |= !color & !old;}
        if rop&2!=0 {mixed |= !color & old;}
        if rop&4!=0 {mixed |= color & !old;}
        if rop&8!=0 {mixed |= color & old;}
        target.pixels[at..at + 4].copy_from_slice(&(mixed & 0x00ff_ffff).to_le_bytes());
        if let Some(dirty) = target.dirty { *dirty = true; }
    }
}

fn fill_pixels(state: &mut WindowsState, dc: u32, left: i32, top: i32, right: i32, bottom: i32, color: u32) {
    if let Some((_,rects)) = state.gdi_clips.iter().find(|(h,_)| *h==dc) {
        let rects = rects.clone();
        for (l,t,r,b) in rects { fill_pixels_unclipped(state,dc,left.max(l),top.max(t),right.min(r),bottom.min(b),color); }
    } else { fill_pixels_unclipped(state,dc,left,top,right,bottom,color); }
}

fn fill_pixels_unclipped(
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
    if left >= right || top >= bottom { return; }
    if let Some(dirty) = target.dirty { *dirty = true; }
    let bytes = color.to_le_bytes();
    for y in top..bottom {
        for x in left..right {
            let at = (y * target.width as usize + x) * 4;
            target.pixels[at..at + 4].copy_from_slice(&bytes);
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
        Api::Yield => 0,
        Api::UserQueue => user_queue::call(machine,state,core::array::from_fn(|i|arg(machine,regs,i))),
        Api::Sync => threads::sync(machine, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::Event => threads::event(machine, state, arg(machine, regs, 0), arg(machine, regs, 1), arg(machine, regs, 2), arg(machine, regs, 3)),
        Api::Atom => atoms::call(machine,core::array::from_fn(|i| arg(machine,regs,i))),
        Api::Class => classes::call(machine,state,core::array::from_fn(|i| arg(machine,regs,i))),
        Api::UniqueId => { let out=arg(machine,regs,0); machine.write::<u64>(out as usize,user_objects::next_id()); 0 },
        Api::Graphics => graphics::call(machine,state,core::array::from_fn(|i|arg(machine,regs,i))),
        Api::Cursor => user_objects::cursor_call(machine,state,core::array::from_fn(|i|arg(machine,regs,i))),
        Api::WindowTree => user_objects::tree_call(machine,state,core::array::from_fn(|i|arg(machine,regs,i))),
        Api::WindowObject => user_objects::window_call(machine, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::UserObject => user_objects::call(machine, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::MemoryQuery => {
            let Some(info)=memory::query(state,arg(machine,regs,0)) else {return 0xc000000d;};
            let out=arg(machine,regs,1) as usize;
            for (i,value) in info.into_iter().enumerate() {machine.write::<u32>(out+i*4,value);}
            0
        },
        Api::Section => sections::call(machine, kt, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::Session => session::call(machine, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::NativeFile => native_file::call(machine, kt, state, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::FileKind => match kt.fds.get(arg(machine, regs, 0) as usize) {
            Some(thread::FdKind::Vfs(_) | thread::FdKind::Dir { .. }) => 1,
            Some(thread::FdKind::ConsoleOut) => 2,
            Some(thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_)) => 3,
            _ => 0,
        },
        Api::ClearTls => threads::clear_tls(machine, &mut state.threads, arg(machine, regs, 0)),
        Api::SystemInfo => {
            let out = arg(machine, regs, 0) as usize;
            machine.write::<u32>(out, machine.total_page_count().unwrap_or(machine.free_page_count()) as u32);
            machine.write::<u32>(out + 4, machine.free_page_count() as u32);
            0
        },
        Api::MemoryProtect => change_protection(machine, state, arg(machine, regs, 0),
            arg(machine, regs, 1), arg(machine, regs, 2)).unwrap_or(0),
        Api::SetSelectors => {
            let entries: [(u32, u64); 2] = core::array::from_fn(|i| (
                arg(machine, regs, i * 3), u64::from(arg(machine, regs, i * 3 + 1))
                    | (u64::from(arg(machine, regs, i * 3 + 2)) << 32)));
            for &(selector, descriptor) in &entries {
                if selector == 0 { continue; }
                if selector > 65535 || selector & 7 != 7 || selector >> 3 < 32
                    || (descriptor != 0 && (descriptor >> 44 & 7 != 7)) { return 0xc000000d; }
            }
            for (selector, descriptor) in entries {
                if selector == 0 { continue; }
                let index = (selector >> 3) as usize;
                if state.ldt.len() <= index { state.ldt.resize(index + 1, 0); }
                state.ldt[index] = descriptor;
            }
            machine.load_ldt(&state.ldt);
            0
        },
        Api::Clock => {
            let out = arg(machine, regs, 0) as usize;
            let Some(unix) = crate::kernel::clock::rtc_unix_timestamp() else { return 0xc0000001; };
            machine.write::<u64>(out, (u64::from(unix) + 11_644_473_600) * 10_000_000);
            machine.write::<u64>(out + 8, machine.now() / 100);
            machine.write::<i32>(out + 16, -crate::kernel::clock::utc_offset_minutes());
            0
        },
        Api::Registry => registry::call(machine, &mut state.registry, core::array::from_fn(|i| arg(machine, regs, i))),
        Api::LocaleId => lib::locale::current().lcid,
        Api::MapFile => {
            let name = arg(machine, regs, 0);
            let base_out = arg(machine, regs, 1);
            let size_out = arg(machine, regs, 2);
            if base_out == 0 || size_out == 0 { return 0xc0000005; }
            let Ok(name) = raw_string(machine, name) else { return 0xc000000d; };
            let Ok(path) = windows_path(state, &name, false) else { return 0xc0000034; };
            let Ok(data) = crate::kernel::exec::load_file_resolved(&path) else { return 0xc0000034; };
            let Some(size) = u32::try_from(data.len()).ok().and_then(|n| n.checked_add(4095)).map(|n| n & !4095) else { return 0xc0000017; };
            if size == 0 { return 0xc000011e; }
            let base = memory::call(machine, state, Api::MemoryReserve, 0, size, 0);
            if base == 0 { return 0xc0000017; }
            if memory::call(machine, state, Api::MemoryCommit, base, size, 1) == 0 {
                memory::call(machine, state, Api::MemoryRelease, base, 0, 0);
                return 0xc0000017;
            }
            machine.copy_to(base as usize, &data);
            machine.set_page_flags(base as usize / 4096, size as usize / 4096, false, false);
            machine.write::<u32>(base_out as usize, base);
            machine.write::<u32>(size_out as usize, data.len() as u32);
            0
        },
        Api::MemoryReserve | Api::MemoryCommit | Api::MemoryDecommit | Api::MemoryRelease => {
            let base = arg(machine, regs, 0);
            let size = if api == Api::MemoryRelease { 0 } else { arg(machine, regs, 1) };
            let flags = if api == Api::MemoryCommit { arg(machine, regs, 2) } else { 0 };
            memory::call(machine, state, api, base, size, flags)
        },
        Api::WriteFile => io_write(
            machine, kt, arg(machine, regs, 0) as usize,
            arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize,
            arg(machine, regs, 3) as usize, state.console.output_cp,
        ),
        Api::InvalidateRect => {
            let hwnd = arg(machine, regs, 0);
            if state.windows.iter().any(|w| w.hwnd == hwnd) {
                queue_paint(state, hwnd);
                1
            } else {
                0
            }
        }
        Api::RetroWndProcReturn => 0,
        Api::EndPaint => {
            state.dirty = true;
            1
        }
        Api::SelectObject => {
            let dc = arg(machine, regs, 0);
            let object = arg(machine, regs, 1);
            let kind = if (0x40006..=0x40008).contains(&object) { Some(2) }
            else if (0x40000..=0x40005).contains(&object) || (0x30000..0x30100).contains(&object) { Some(1) } else { state
                .gdi_objects
                .iter()
                .find(|(h, _)| *h == object)
                .map(|(_, o)| match o {
                    GdiObject::Bitmap { .. } => 0,
                    GdiObject::Font => 3,
                }) };
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
            state.gdi_clips.retain(|(h,_)| *h!=dc);
            state.gdi_rops.retain(|(h,_)| *h!=dc);
            if let Some(index) = state.dcs.iter().position(|d| d.handle == dc) {
                state.dcs.swap_remove(index);
                1
            } else {
                0
            }
        }
        Api::FillRect => {
            let dc = arg(machine, regs, 0);
            let rect = arg(machine, regs, 1) as usize;
            let brush = arg(machine, regs, 2);
            let brush = if brush == 0 { state.dcs.iter().find(|d| d.handle == dc).map_or(0, |d| d.brush) } else { brush };
            if brush == 0x40005 { return 1; }
            let color = object_color(state, brush, 0x00c0_c0c0);
            let (l, t, r, b) = rect_from_guest(machine, rect);
            fill_pixels(state, dc, l, t, r, b, color);
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
            let units: Vec<u16> = (0..count).map(|n| machine.read::<u16>(text + n * 2)).collect();
            let text = crate::kernel::text::from_utf16(&units, false).unwrap();
            for (n, ch) in text.chars().enumerate() {
                let glyph = crate::kernel::text::glyph16(ch);
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
            if width == 0 || height == 0 || width > i32::MAX as usize || height > i32::MAX as usize { return 0; }
            let src = arg(machine, regs, 5);
            let sx = arg(machine, regs, 6) as i32;
            let sy = arg(machine, regs, 7) as i32;
            // Snapshot the requested source view, including window DCs, so
            // overlapping scroll/copy operations do not consume changed pixels.
            let Some(source) = target_mut(state, src) else { return 0; };
            let left = i64::from(sx).max(0).max(-i64::from(source.origin_x));
            let top = i64::from(sy).max(0).max(-i64::from(source.origin_y));
            let right = (i64::from(sx)+width as i64).min(i64::from(source.clip_width)).min(i64::from(source.width)-i64::from(source.origin_x));
            let bottom = (i64::from(sy)+height as i64).min(i64::from(source.clip_height)).min(i64::from(source.height)-i64::from(source.origin_y));
            if right <= left || bottom <= top { return 1; }
            let (copy_width,copy_height)=((right-left) as usize,(bottom-top) as usize);
            let mut pixels=Vec::with_capacity(copy_width*copy_height*4);
            for y in top..bottom {
                let start=((y+i64::from(source.origin_y)) as usize*source.width as usize+(left+i64::from(source.origin_x)) as usize)*4;
                pixels.extend_from_slice(&source.pixels[start..start+copy_width*4]);
            }
            let (left,top,source)=(left as i32,top as i32,pixels);
            let dx = dx.saturating_add(left.saturating_sub(sx));
            let dy = dy.saturating_add(top.saturating_sub(sy));
            {
                // BitBlt uses the ternary raster operation, never the pen ROP2.
                let rop = (arg(machine, regs, 8) >> 16) as u8;
                let brush = state.dcs.iter().find(|d| d.handle == dst).map_or(0, |d| d.brush);
                let pattern = object_color(state, brush, 0xffffff);
                // Resolve destination and clip once; SRCCOPY still copies rows.
                let clips = state.gdi_clips.iter().find(|(h,_)| *h == dst).map(|(_,r)| r.clone());
                let Some(target) = target_mut(state, dst) else { return 0; };
                let bounds = [(0, 0, target.clip_width as i32, target.clip_height as i32)];
                let mut changed = false;
                for &(cl, ct, cr, cb) in clips.as_deref().unwrap_or(&bounds) {
                    let l = i64::from(dx).max(i64::from(cl)).max(0).max(-i64::from(target.origin_x));
                    let t = i64::from(dy).max(i64::from(ct)).max(0).max(-i64::from(target.origin_y));
                    let r = (i64::from(dx) + copy_width as i64).min(i64::from(cr))
                        .min(i64::from(target.clip_width)).min(i64::from(target.width) - i64::from(target.origin_x));
                    let b = (i64::from(dy) + copy_height as i64).min(i64::from(cb))
                        .min(i64::from(target.clip_height)).min(i64::from(target.height) - i64::from(target.origin_y));
                    if l >= r || t >= b { continue; }
                    let count = (r-l) as usize * 4;
                    for y in t..b {
                        let from = ((y - i64::from(dy)) as usize * copy_width + (l - i64::from(dx)) as usize) * 4;
                        let to = ((y + i64::from(target.origin_y)) as usize * target.width as usize
                            + (l + i64::from(target.origin_x)) as usize) * 4;
                        if rop == 0xcc {
                            target.pixels[to..to+count].copy_from_slice(&source[from..from+count]);
                        } else {
                            for x in (0..count).step_by(4) {
                                let src = u32::from_le_bytes(source[from+x..from+x+4].try_into().unwrap());
                                let dst = u32::from_le_bytes(target.pixels[to+x..to+x+4].try_into().unwrap());
                                let mut color = 0;
                                for term in 0..8 {
                                    if rop & (1 << term) != 0 {
                                        color |= (if term & 4 != 0 { pattern } else { !pattern })
                                            & (if term & 2 != 0 { src } else { !src })
                                            & (if term & 1 != 0 { dst } else { !dst });
                                    }
                                }
                                target.pixels[to+x..to+x+4].copy_from_slice(&(color & 0xffffff).to_le_bytes());
                            }
                        }
                    }
                    changed = true;
                }
                if changed && let Some(dirty) = target.dirty { *dirty = true; }
            }
            1
        }
        Api::Extension => 0,
        Api::ExitProcess | Api::Unsupported | Api::DosMemory | Api::Wait | Api::NativeThread | Api::RestoreContext => unreachable!(),
    }
}

// Keep Windows-only call frames off the shared DOS/Linux event dispatcher.
#[inline(never)]
pub fn handle_event<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    process: &mut WindowsProcess<A>,
    regs: &mut Regs,
    event: crate::KernelEvent,
) -> thread::KernelAction {
    let state = &mut process.state;
    if !A::seg_is_32(regs.code_seg()) && let Some(mut win16) = state.win16.take() {
        let action = win16::handle_event(machine, bios, kt, state, &mut win16, process.dos.as_mut().expect("NE DOS services"), regs, event);
        state.win16 = Some(win16);
        if matches!(event, crate::KernelEvent::Irq) { if !threads::schedule(machine,state,regs) {kt.state=thread::ThreadState::Blocked;} }
        return action;
    }
    match event {
        crate::KernelEvent::Irq => {
            if !threads::schedule(machine,state,regs) {kt.state=thread::ThreadState::Blocked;} thread::KernelAction::Done },
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let Some(gate) = state
                .gates
                .iter()
                .copied()
                .find(|g| g.return_ip == regs.ip32())
            else {
                crate::compact_println!("Windows: invalid API gate at {:#x}", regs.ip32());
                return thread::KernelAction::Exit(-1);
            };
            if let Some(action) = threads::call(machine,state,kt,regs,gate) { return action; }
            if gate.api == Api::Unsupported {
                let name = raw_string(machine, arg(machine, regs, 0)).unwrap_or_default();
                crate::compact_println!("Wine backend not implemented: {}", core::str::from_utf8(&name).unwrap_or("?"));
                let lock = machine.read::<u32>((PEB_BASE + 0x1c) as usize);
                crate::compact_println!("Wine PEB lock={:#x} thread={} fs={:#x}", lock,
                    machine.read::<u32>((state.teb_base + 0x24) as usize), regs.fs);
                if memory_protection(state, lock).is_some() {
                    crate::compact_println!("Wine PEB lock count={} recursion={} owner={:#x}",
                        machine.read::<i32>(lock as usize + 4), machine.read::<u32>(lock as usize + 8),
                        machine.read::<u32>(lock as usize + 12));
                }
                let caller = machine.read::<u32>(regs.sp32() as usize + 8);
                for module in &state.modules {
                    if caller >= module.base && caller - module.base < DLL_BASE_STRIDE {
                        crate::compact_println!("Wine backend caller: {}+{:#x}", core::str::from_utf8(&module.name).unwrap_or("?"), caller - module.base);
                    }
                }
                let mut frame = regs.rbp as u32;
                for _ in 0..8 {
                    if frame < state.stack_base || frame.checked_add(8).is_none_or(|end| end > state.stack_base + state.stack_size) { break; }
                    let caller = machine.read::<u32>(frame as usize + 4);
                    for module in &state.modules {
                        if caller >= module.base && caller - module.base < DLL_BASE_STRIDE {
                            crate::compact_println!("Wine backend frame: {}+{:#x}", core::str::from_utf8(&module.name).unwrap_or("?"), caller - module.base);
                        }
                    }
                    let next = machine.read::<u32>(frame as usize);
                    if next <= frame { break; }
                    frame = next;
                }
                return thread::KernelAction::Exit(-38);
            }
            if gate.api == Api::ExitProcess {
                return thread::KernelAction::Exit(arg(machine, regs, 0) as i32);
            }
            note_api(gate.name);
            if crate::kernel::startup::trace_enabled() {
                crate::compact_dbg_println!("[win32] {}", core::str::from_utf8(gate.name).unwrap_or("?"));
            }
            if gate.api == Api::RetroWndProcReturn {
                let Some(callback) = state.callback.take() else {
                    crate::compact_dbg_println!("Windows: stray WNDPROC return");
                    return thread::KernelAction::Exit(-1);
                };
                let result = callback.module_result.map_or(regs.rax as u32, |base| {
                    if regs.rax == 0 { fail(state,1114,0) } else { base }
                });
                state.callback=state.callback_stack.pop();
                finish(machine, regs, callback.gate, result);
                return thread::KernelAction::Done;
            }
            let result = if gate.api == Api::DosMemory {
                if let Some(dos) = &mut process.dos {
                    crate::kernel::dos::win16_memory(machine, dos, arg(machine, regs, 0),
                        arg(machine, regs, 1), arg(machine, regs, 2), arg(machine, regs, 3) != 0)
                } else { 0 }
            } else {
                dispatch(machine, kt, state, regs, gate.api)
            };
            if crate::kernel::startup::trace_enabled() && matches!(gate.name,
                b"CreateFileA" | b"FindFirstFileA" | b"LoadStringA" | b"CreateThread" | b"GetLastError" | b"SetFilePointer") {
                crate::compact_dbg_println!("[win32-result] {} arg0={:08x} arg1={:08x} result={:08x} error={}",
                    core::str::from_utf8(gate.name).unwrap_or("?"), arg(machine,regs,0),arg(machine,regs,1),result,state.last_error);
                if matches!(gate.name,b"CreateFileA" | b"FindFirstFileA") && let Ok(path)=c_string(machine,arg(machine,regs,0)) {
                    crate::compact_dbg_println!("[win32-path] {}",core::str::from_utf8(&path).unwrap_or("?"));
                }
            }
            if extra::take_hold(&mut state.console) {
                // INT advances EIP past its two-byte gate before the handler
                // runs. Retry the same call once input becomes available.
                regs.frame.rip -= 2;
                if !threads::schedule(machine,state,regs) {kt.state=thread::ThreadState::Blocked;}
                return thread::KernelAction::Done;
            }
            if gate.api == Api::SetSelectors && result == 0 {
                if let Some(dos) = &mut process.dos {
                    dos.ldt[..state.ldt.len()].copy_from_slice(&state.ldt);
                }
            }
            finish(machine, regs, gate, result);
            if !threads::schedule(machine,state,regs) {kt.state=thread::ThreadState::Blocked;}
            thread::KernelAction::Done
        }
        crate::KernelEvent::Exception(13) if exceptions::deliver(machine,state,regs,0xc0000005) => thread::KernelAction::Done,
        crate::KernelEvent::PageFault { .. } => {
            unreachable!("page faults are handled by the event loop")
        }
        _ => {
            crate::compact_println!("Windows: unhandled event {:?} at {:#x}", event, regs.ip32());
            crate::compact_println!("Windows fault: cs={:#x} ss={:#x} fs={:#x} ds={:#x} es={:#x} sp={:#x} ax={:#x} bx={:#x} cx={:#x} dx={:#x}",regs.frame.cs,regs.frame.ss,regs.fs,regs.ds,regs.es,regs.sp32(),regs.rax,regs.rbx,regs.rcx,regs.rdx);
            for module in &state.modules {
                if regs.ip32()>=module.base && regs.ip32()-module.base<DLL_BASE_STRIDE {
                    crate::compact_println!("Windows fault in {}+{:#x}",core::str::from_utf8(&module.name).unwrap_or("?"),regs.ip32()-module.base);
                }
            }

            thread::KernelAction::Exit(-1)
        }
    }
}

#[cfg(test)]
mod forwarder_tests {
    use super::*;

    fn module(name: &[u8], base: u32, forward: Option<&[u8]>) -> Module {
        Module { name: name.to_vec(), path: name.to_vec(), base, data: pe::export_test_image(forward) }
    }

    #[test]
    fn follows_name_then_ordinal_forwarder_and_rejects_cycles() {
        let mut modules = vec![
            module(b"FIRST.DLL", 0x10000000, Some(b"second.Entry")),
            module(b"SECOND.DLL", 0x11000000, Some(b"THIRD.#7")),
            module(b"THIRD.DLL", 0x12000000, None),
        ];
        let symbol = pe::ImportSymbol::Name(b"Entry".to_vec());
        assert_eq!(resolve_export(&modules, 0, &symbol), Ok(0x12000300));
        modules[2] = module(b"THIRD.DLL", 0x12000000, Some(b"FIRST.Entry"));
        assert_eq!(resolve_export(&modules, 0, &symbol), Err(127));
        modules.pop();
        assert_eq!(resolve_export(&modules, 0, &symbol), Err(2));
    }
}

#[cfg(test)]
mod path_tests {
    use super::{full_windows_path, guest_windows_path, WindowsState};

    #[test]
    fn resolves_drive_relative_paths() {
        let mut state = WindowsState::new();
        assert_eq!(full_windows_path(&state, b"C:MC"), b"C:\\MC");
        assert_eq!(full_windows_path(&state, b"\\MC"), b"C:\\MC");
        assert_eq!(full_windows_path(&state, b"MC"), b"C:\\MC");
        assert_eq!(full_windows_path(&state, b"C:\\MC"), b"C:\\MC");
        let cwd = [crate::kernel::dos::c_root(), b"MC"].concat();
        state.cwd[..cwd.len()].copy_from_slice(&cwd);
        state.cwd_len = cwd.len();
        assert_eq!(full_windows_path(&state, b"C:FILE"), b"C:\\MC\\FILE");
        assert_eq!(full_windows_path(&state, b"\\FILE"), b"C:\\FILE");
        assert_eq!(full_windows_path(&state, b"."), b"C:\\MC");
        assert_eq!(full_windows_path(&state, b".\\*"), b"C:\\MC\\*");
        assert_eq!(full_windows_path(&state, b"..\\FILE"), b"C:\\FILE");
    }

    #[test]
    fn maps_drive_roots_to_windows_paths() {
        assert_eq!(guest_windows_path(b"cdrom"), b"D:\\");
        assert_eq!(guest_windows_path(b"cdrom/GAMES"), b"D:\\GAMES");
        assert_eq!(guest_windows_path(b"host"), b"H:\\");
        assert_eq!(guest_windows_path(b"disk1/TOOLS"), b"E:\\TOOLS");
    }
}

#[cfg(test)]
mod damage_tests {
    use super::*;

    #[test]
    fn independent_windows_keep_surfaces_geometry_and_z_order() {
        use crate::kernel::gui::{Content, Desktop, EndpointId, SurfaceKey};
        let mut state = WindowsState::new();
        state.cursor_visible = false;
        for (hwnd, x, width, color) in [(10, 0, 4, 0x0000ffu32), (11, 2, 2, 0xff0000)] {
            state.windows.push(Window { hwnd, parent: 0, x, y: 0, width, height: 1,
                visible: true, pixels: color.to_le_bytes().repeat(width as usize) });
        }
        let mut desktop = Desktop::new();
        let endpoint = EndpointId(1);
        let mut compose = |state: &mut WindowsState| {
            state.dirty = true;
            publish_surfaces(state, &mut desktop, endpoint);
            let content: Vec<_> = state.windows.iter().map(|w| {
                let key = SurfaceKey(u64::from(w.hwnd));
                Content { id: desktop.ensure_surface(endpoint, key).unwrap(),
                    buffer: surface_buffer(state, key).unwrap() }
            }).collect();
            let mut output = Vec::new();
            desktop.compose_surfaces(&content, 4, 1, vga::PixelFormat::NATIVE, &mut output).unwrap();
            output.chunks_exact(4).map(|p| u32::from_le_bytes(p.try_into().unwrap())).collect::<Vec<_>>()
        };
        assert_eq!(compose(&mut state), vec![0xff0000, 0xff0000, 0xff, 0xff]);
        state.windows.swap(0, 1);
        assert_eq!(compose(&mut state), vec![0xff0000; 4]);
        state.windows[1].visible = false;
        let output = compose(&mut state);
        assert_eq!(&output[2..], &[0xff, 0xff]);
        state.windows.remove(0);
        compose(&mut state);
        assert_eq!(state.presentations.len(), 1);
        assert!(surface_buffer(&state, SurfaceKey(11)).is_none());
    }

    #[test]
    fn window_writes_damage_scanout_but_offscreen_work_and_reads_do_not() {
        let mut state = WindowsState::new();
        state.windows.push(Window {
            hwnd: 7,
            parent: 0,
            x: 0,
            y: 0,
            width: 8,
            height: 8,
            visible: true,
            pixels: vec![0; 8 * 8 * 4],
        });
        state.paint_hwnd = 7;
        let dc = state.paint_dc;
        state.dirty = false;
        assert!(target_mut(&mut state, dc).is_some());
        assert!(!state.dirty, "querying a target must not damage it");
        fill_pixels(&mut state, dc, 0, 0, 4, 4, 0xff);
        assert!(
            state.dirty,
            "GetDC fills must present without EndPaint/input"
        );
        state.dirty = false;
        put_pixel(&mut state, dc, 5, 5, 0xff00);
        assert!(
            state.dirty,
            "text/line/pixel writes must damage their surface"
        );
        state.dirty = false;
        put_pixel(&mut state, dc, 99, 99, 0);
        fill_pixels(&mut state, dc, 99, 99, 100, 100, 0);
        assert!(!state.dirty, "clipped writes must not damage a surface");
        state.gdi_objects.push((
            9,
            GdiObject::Bitmap {
                width: 8,
                height: 8,
                pixels: vec![0; 8 * 8 * 4],
            },
        ));
        state.dcs.push(DeviceContext {
            viewport: None,
            handle: 8,
            window: None,
            bitmap: Some(9),
            x: 0,
            y: 0,
            pen: 0,
            brush: 0,
            font: 0,
            bk: 0,
            text: 0,
        });
        fill_pixels(&mut state, 8, 0, 0, 8, 8, 0xff);
        put_pixel(&mut state, 8, 0, 0, 0xff00);
        assert!(
            !state.dirty,
            "offscreen menu composition must stay invisible"
        );
    }
}

pub(crate) fn poll_threads<A: crate::Arch>(machine:&mut A,kt:&mut thread::KernelThread<A>,process:&mut WindowsProcess<A>,regs:&mut Regs) {
    user_queue::poll(machine,&mut process.state);
    threads::poll(machine,kt,&mut process.state,regs);
}

fn initialize_environment<A: crate::Arch>(machine:&mut A,state:&mut WindowsState)->Result<(),i32> {
    let text=alloc::string::String::from_utf8_lossy(&state.environment);
    let units:Vec<u16>=text.encode_utf16().collect();
    let size=((units.len()*2+4095)&!4095) as u32;
    let base=memory::call(machine,state,Api::MemoryReserve,0,size,0);
    if base==0 {return Err(-12);}
    if memory::call(machine,state,Api::MemoryCommit,base,size,1)==0 {
        memory::call(machine,state,Api::MemoryRelease,base,0,0);
        return Err(-12);
    }
    for (i,unit) in units.iter().enumerate() {machine.write::<u16>(base as usize+i*2,*unit);}
    machine.write::<u32>((PROCESS_DATA+0x48) as usize,base);
    machine.write::<u32>((PROCESS_DATA+0x290) as usize,(units.len()*2) as u32);
    machine.write::<u32>((PROCESS_DATA+0x294) as usize,1);
    Ok(())
}

fn process_cwd(path:&[u8])->Vec<u8> {
    let mut path=guest_windows_path(path);
    if path.last()!=Some(&b'\\'){path.push(b'\\');}
    path
}
fn initialize_process_strings<A:crate::Arch>(machine:&mut A,state:&mut WindowsState)->Result<(),i32>{
    machine.write::<u32>(PROCESS_DATA as usize,4096);
    machine.write::<u32>((PROCESS_DATA+4) as usize,0x298);
    machine.write::<u32>((PROCESS_DATA+8) as usize,1);
    let image=guest_windows_path(state.exec_path_str());
    let cwd=process_cwd(state.cwd_str());
    for (field,buffer,value) in [(0x24u32,0x400u32,cwd.as_slice()),
        (0x30,0x600,b"C:\\RETROOS\\WINDOWS\\SYSTEM32;C:\\RETROOS\\WINDOWS\\SYSTEM".as_slice()),
        (0x38,0x800,image.as_slice()),(0x40,0xa00,image.as_slice())] {
        let units=encoding::encode(value,true);
        if units.len()>=256{return Err(-8);}
        encoding::copy(machine,(PROCESS_DATA+buffer) as usize,256,value,true);
        machine.write::<u16>((PROCESS_DATA+field) as usize,(units.len()*2) as u16);
        machine.write::<u16>((PROCESS_DATA+field+2) as usize,512);
        machine.write::<u32>((PROCESS_DATA+field+4) as usize,PROCESS_DATA+buffer);
    }
    state.command_line_w=PROCESS_DATA+0xa00;
    Ok(())
}
