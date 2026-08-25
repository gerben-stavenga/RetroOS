//! Native 32-bit OS/2 application personality.
//!
//! Applications and compatibility DLLs are ordinary LX modules. DOSCALLS and
//! the PM/GPI facade DLLs expose two-byte `INT 82h` gates; all service
//! implementation lives here in Rust.

extern crate alloc;

pub mod lx;

use alloc::{vec, vec::Vec};
use crate::Regs;
use crate::kernel::thread;

const GATE_VECTOR: u8 = 0x82;
const DLL_BIAS_FIRST: u32 = 0x1000_0000;
const DLL_BIAS_STRIDE: u32 = 0x0100_0000;
const STACK_TOP: u32 = 0xbff0_0000;
const USER_LIMIT: u32 = 0xc000_0000;
const MAX_MODULES: usize = 64;
const PROCESS_DATA: u32 = 0x0800_0000;
const HEAP_BASE: u32 = 0x4000_0000;

const NO_ERROR: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_INVALID_PARAMETER: u32 = 87;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    DosQueryHType, DosExit, DosResetBuffer, DosSetFilePtr, DosClose,
    DosOpen, DosRead, DosWrite, DosQueryCp, DosAllocMem, DosFreeMem,
    DosQueryModuleHandle, DosQueryProcAddr, DosQuerySysInfo, DosSetRelMaxFH,
    DosFlatToSel, DosSelToFlat, DosOpenL, DosSetFileLocksL, DosSetFilePtrL,
    DosGetDateTime, DosAllocSharedMem, DosGetNamedSharedMem, DosGetInfoBlocks,
    DosQueryDBCSEnv, KbdCharIn, VioGetConfig,
    WinInitialize, WinCreateMsgQueue, WinCreateWindow, WinShowWindow,
    WinGetPS, WinReleasePS, WinFillRect, WinPostQueueMsg, WinGetMsg,
    WinDispatchMsg, WinDestroyWindow, WinDestroyMsgQueue, WinTerminate,
    WinBeginPaint, WinDismissDlg, WinDrawBitmap, WinDrawBorder, WinEndPaint,
    WinInvalidateRect, WinLoadString, WinMessageBox, WinPtInRect,
    WinQueryDlgItemText, WinQuerySysValue, WinQueryWindow, WinQueryWindowPos,
    WinQueryWindowRect, WinSetDlgItemText, WinSetWindowPos, WinStartTimer,
    WinStopTimer, WinWindowFromId, WinSendDlgItemMsg, WinCreateStdWindow,
    WinDefDlgProc, WinDefWindowProc, WinSendMsg, WinDlgBox, WinRegisterClass,
    RetroWndProcReturn, GpiBox, GpiDeleteBitmap, GpiLoadBitmap, GpiMove,
    PrfOpenProfile, PrfCloseProfile, PrfQueryProfileData, PrfWriteProfileData,
    WinCreateHelpInstance, WinDestroyHelpInstance, WinAssociateHelpInstance,
}

#[derive(Clone, Copy)]
struct Gate {
    cs: u16,
    return_ip: u32,
    api: Api,
    far16_args: u16,
}

#[derive(Clone, Copy)]
struct PmMessage {
    hwnd: u32,
    message: u32,
    mp1: u32,
    mp2: u32,
}

struct PmWindow {
    hwnd: u32,
    wndproc: u32,
    id: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    visible: bool,
    pixels: Vec<u8>,
}

struct PmClass {
    name: Vec<u8>,
    wndproc: u32,
}

struct PmBitmap {
    handle: u32,
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Callback { dispatch_sp: u32 }

/// OS/2-specific process state. The first implementation intentionally keeps
/// process state small; TIB/PIB, threads and asynchronous operations grow here
/// rather than leaking into the generic LX loader.
pub struct Os2State {
    gates: Vec<Gate>,
    ldt: Vec<u64>,
    modules: Vec<Module>,
    allocations: Vec<(u32, u32)>,
    heap_next: u32,
    pub cwd: [u8; 64],
    pub cwd_len: usize,
    exec_path: [u8; 128],
    exec_path_len: usize,
    next_pm_handle: u32,
    pm_classes: Vec<PmClass>,
    pm_bitmaps: Vec<PmBitmap>,
    pm_windows: Vec<PmWindow>,
    pm_messages: Vec<PmMessage>,
    callback: Option<Callback>,
    callback_return: u32,
    timer_hwnd: u32,
    timer_id: u32,
    timer_interval_ns: u64,
    timer_deadline_ns: u64,
    mouse_x: i32,
    mouse_y: i32,
    mouse_buttons: u8,
    cursor_dirty: bool,
    pm_dirty: bool,
}

impl Os2State {
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            ldt: vec![0],
            modules: Vec::new(),
            allocations: Vec::new(),
            heap_next: HEAP_BASE,
            cwd: [0; 64],
            cwd_len: 0,
            exec_path: [0; 128],
            exec_path_len: 0,
            next_pm_handle: 0x10000,
            pm_classes: Vec::new(),
            pm_bitmaps: Vec::new(),
            pm_windows: Vec::new(),
            pm_messages: Vec::new(),
            callback: None,
            callback_return: 0,
            timer_hwnd: 0,
            timer_id: 0,
            timer_interval_ns: 0,
            timer_deadline_ns: 0,
            mouse_x: 0,
            mouse_y: 0,
            mouse_buttons: 0,
            cursor_dirty: true,
            pm_dirty: false,
        }
    }

    pub fn cwd_str(&self) -> &[u8] { &self.cwd[..self.cwd_len] }
    pub fn exec_path_str(&self) -> &[u8] { &self.exec_path[..self.exec_path_len] }

    pub fn on_resume<A: crate::Arch>(&mut self, machine: &mut A) {
        machine.load_ldt(&self.ldt);
    }

    fn set_exec_path(&mut self, path: &[u8]) {
        let n = path.len().min(self.exec_path.len());
        self.exec_path[..n].copy_from_slice(&path[..n]);
        self.exec_path_len = n;
    }

    pub fn process_key(&self, fds: &[thread::FdKind; thread::MAX_FDS], scancode: u8) {
        if !crate::kernel::keyboard::update_key_state(scancode) { return; }
        let c = crate::kernel::keyboard::scancode_to_ascii(scancode);
        if c == 0 { return; }
        if let thread::FdKind::PipeRead(idx) = fds[0] {
            crate::kernel::kpipe::write(idx, &[c]);
        }
    }

    pub fn process_mouse(&mut self, dx: i16, dy: i16, buttons: u8) {
        let Some(window) = self.pm_windows.iter().rfind(|window| window.visible) else { return; };
        let hwnd = window.hwnd;
        self.mouse_x = (self.mouse_x + i32::from(dx)).clamp(0, window.width as i32 - 1);
        self.mouse_y = (self.mouse_y + i32::from(dy)).clamp(0, window.height as i32 - 1);
        let pm_y = window.height as i32 - 1 - self.mouse_y;
        let mp1 = (self.mouse_x as u32 & 0xffff) | ((pm_y as u32 & 0xffff) << 16);
        self.pm_messages.push(PmMessage { hwnd, message: 0x0070, mp1, mp2: buttons as u32 });
        for (mask, down, up) in [(1, 0x0071, 0x0072), (2, 0x0074, 0x0075)] {
            if buttons & mask != 0 && self.mouse_buttons & mask == 0 {
                self.pm_messages.push(PmMessage { hwnd, message: down, mp1, mp2: 0 });
            } else if buttons & mask == 0 && self.mouse_buttons & mask != 0 {
                self.pm_messages.push(PmMessage { hwnd, message: up, mp1, mp2: 0 });
            }
        }
        self.mouse_buttons = buttons;
        self.cursor_dirty = true;
    }

    pub fn advance_timers(&mut self, now: u64) {
        if self.timer_hwnd == 0
            || now < self.timer_deadline_ns
            || self.pm_messages.iter().any(|message| {
                message.hwnd == self.timer_hwnd
                    && message.message == 0x0024
                    && message.mp1 == self.timer_id
            })
        {
            return;
        }
        self.pm_messages.push(PmMessage {
            hwnd: self.timer_hwnd,
            message: 0x0024,
            mp1: self.timer_id,
            mp2: 0,
        });
        // PM timers are notifications, not a count of elapsed periods.
        self.timer_deadline_ns = now.saturating_add(self.timer_interval_ns);
    }

    pub fn has_pending_message(&self) -> bool {
        !self.pm_messages.is_empty()
    }

    pub fn repaint_osd(&mut self) {
        self.pm_dirty = true;
    }
}

/// Publish the foremost native Presentation Manager window into the shared
/// desktop. PM owns its pixels; the compositor owns placement and visibility.
pub fn render<A: crate::Arch>(
    _machine: &mut A,
    _bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    state: &mut Os2State,
    _display: &mut crate::kernel::display::Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    const PM_SURFACE: crate::kernel::gui::SurfaceKey = crate::kernel::gui::SurfaceKey(1);
    const PM_PRESENTATION: crate::kernel::gui::PresentationKey =
        crate::kernel::gui::PresentationKey(1);
    let focus_changed = desktop.focus(endpoint);
    let Some(index) = state.pm_windows.iter().rposition(|window| window.visible) else {
        return;
    };
    let (width, height) = (
        state.pm_windows[index].width as usize,
        state.pm_windows[index].height as usize,
    );
    let surface = desktop.ensure_surface(endpoint, PM_SURFACE).expect("create PM surface");
    let node = desktop
        .ensure_node(
            endpoint,
            PM_PRESENTATION,
            crate::kernel::gui::Rect::new(0, 0, width as u32, height as u32),
        )
        .expect("create PM presentation node");
    let placement = desktop.geometry(node).expect("live PM presentation node");
    let pointer_changed = desktop.set_pointer(crate::kernel::gui::Point {
        x: placement.x + state.mouse_x,
        y: placement.y + state.mouse_y,
    });
    if !state.pm_dirty && !state.cursor_dirty && !focus_changed && !pointer_changed {
        return;
    }
    let mut transaction = crate::kernel::gui::Transaction::new(endpoint);
    transaction
        .set_geometry(node, crate::kernel::gui::Rect::new(
            placement.x, placement.y, width as u32, height as u32,
        ))
        .attach(node, Some(surface))
        .set_visible(node, true);
    desktop.commit(transaction).expect("commit PM presentation node");

    state.pm_dirty = false;
    state.cursor_dirty = false;
}

pub fn surface_buffer<'a>(
    state: &'a Os2State,
) -> Option<crate::kernel::gui::PixelBuffer<'a>> {
    let window = state.pm_windows.iter().rfind(|window| window.visible)?;
    crate::kernel::gui::PixelBuffer::new(
        window.width as usize,
        window.height as usize,
        window.width as usize * 4,
        vga::PixelFormat::NATIVE,
        &window.pixels,
    ).ok()
}

impl Default for Os2State {
    fn default() -> Self { Self::new() }
}

struct Module {
    name: Vec<u8>,
    path: Vec<u8>,
    data: Vec<u8>,
    bias: u32,
    selectors: Vec<u16>,
}

fn build_descriptor(base: u32, limit: u32, access: u64, flags: u64) -> u64 {
    let mut desc = (limit & 0xffff) as u64;
    desc |= ((base & 0xffff) as u64) << 16;
    desc |= (((base >> 16) & 0xff) as u64) << 32;
    desc |= (access & 0xff) << 40;
    desc |= ((((limit >> 16) & 0x0f) as u64) | (flags & 0xf0)) << 48;
    desc | (((base >> 24) & 0xff) as u64) << 56
}

fn push_descriptor(ldt: &mut Vec<u64>, base: u32, size: u32, code: bool, big: bool) -> u16 {
    let selector = ((ldt.len() as u16) << 3) | 7;
    let access = if code { 0xfa } else { 0xf2 };
    ldt.push(build_descriptor(base, size.saturating_sub(1), access, if big { 0x40 } else { 0 }));
    selector
}

fn eq_name(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn module_name(name: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    if out.len() >= 4 && out[out.len() - 4..].eq_ignore_ascii_case(b".DLL") {
        out.truncate(out.len() - 4);
    }
    out.make_ascii_uppercase();
    if out == b"DOSCALL1" { return b"DOSCALLS".to_vec(); }
    out
}

fn dirname(path: &[u8]) -> &[u8] {
    path.iter().rposition(|&b| b == b'/').map_or(b"", |n| &path[..n])
}

fn join(dir: &[u8], file: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + usize::from(!dir.is_empty()) + file.len());
    out.extend_from_slice(dir);
    if !dir.is_empty() && dir.last() != Some(&b'/') { out.push(b'/'); }
    out.extend_from_slice(file);
    out
}

fn dll_filename(name: &[u8]) -> Vec<u8> {
    let mut out = module_name(name);
    out.extend_from_slice(b".DLL");
    out
}

fn load_dependency(name: &[u8], importer_path: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let file = dll_filename(name);
    let system_dll_dir = join(crate::kernel::dos::c_root(), b"OS2/DLL");
    let candidates = [
        join(dirname(importer_path), &file),
        join(&system_dll_dir, &file),
    ];
    for path in candidates {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&path) {
            return Ok((path, data));
        }
    }
    Err(2)
}

fn object_address(image: &lx::Image<'_>, bias: u32, object: u16, offset: u32) -> Result<u32, i32> {
    let obj = image.object(object as u32).map_err(|_| 8)?;
    if offset > obj.size { return Err(8); }
    bias.checked_add(obj.address).and_then(|v| v.checked_add(offset)).ok_or(8)
}

fn find_module(modules: &[Module], name: &[u8]) -> Option<usize> {
    let name = module_name(name);
    modules.iter().position(|m| eq_name(&m.name, &name))
}

#[derive(Clone, Copy)]
struct ResolvedTarget { linear: u32, selector: u16, offset: u32 }

fn resolve_export(modules: &[Module], module_index: usize, ordinal: Option<u16>, name: Option<&[u8]>) -> Result<ResolvedTarget, i32> {
    let module = modules.get(module_index).ok_or(8)?;
    let image = lx::Image::parse(&module.data).map_err(|_| 8)?;
    let export = image.exports().map_err(|_| 8)?.into_iter().find(|e| {
        ordinal.is_some_and(|n| e.ordinal == n)
            || name.is_some_and(|n| eq_name(&e.name, n))
    });
    let Some(export) = export else {
        return Err(127); // ERROR_PROC_NOT_FOUND
    };
    Ok(ResolvedTarget {
        linear: object_address(&image, module.bias, export.object, export.offset)?,
        selector: *module.selectors.get(export.object as usize - 1).ok_or(8)?,
        offset: export.offset,
    })
}

fn map_module<A: crate::Arch>(machine: &mut A, module: &Module) -> Result<(), i32> {
    let image = lx::Image::parse(&module.data).map_err(|_| 8)?;
    for object_number in 1..=image.header.object_count {
        let object = image.object(object_number).map_err(|_| 8)?;
        let base32 = module.bias.checked_add(object.address).ok_or(8)?;
        let end32 = base32.checked_add(object.size).ok_or(8)?;
        if end32 > USER_LIMIT { return Err(8); }
        let base = base32 as usize;
        machine.zero(base, object.size as usize);
        for n in 0..object.map_count {
            let page = image.page(object.map_index + n).map_err(|_| 8)?;
            let within = n.checked_mul(image.header.page_size).ok_or(8)?;
            match page.flags {
                lx::PAGE_VALID => {
                    let bytes = image.page_data(page).map_err(|_| 8)?;
                    // LX page records are page-sized storage units. The last
                    // page of an object may contain linker padding beyond the
                    // object's declared virtual size; map only its live prefix.
                    let remaining = object.size.saturating_sub(within) as usize;
                    machine.copy_to(base + within as usize, &bytes[..bytes.len().min(remaining)]);
                }
                lx::PAGE_ZEROED | lx::PAGE_INVALID => {}
                lx::PAGE_ITERATED => return Err(8),
                _ => return Err(8),
            }
        }
    }
    Ok(())
}

fn apply_fixups<A: crate::Arch>(machine: &mut A, modules: &[Module], module_index: usize) -> Result<(), i32> {
    let module = modules.get(module_index).ok_or(8)?;
    let image = lx::Image::parse(&module.data).map_err(|_| 8)?;
    let imports = image.import_modules().map_err(|_| 8)?;
    for fixup in image.fixups().map_err(|_| 8)? {
        let (source_object, page_offset) = image.page_location(fixup.page).map_err(|_| 8)?;
        let source_base = object_address(&image, module.bias, source_object as u16, page_offset)?;
        let source_signed = source_base as i64 + fixup.source_offset as i64;
        if !(0..USER_LIMIT as i64).contains(&source_signed) { return Err(8); }
        let source = source_signed as u32;
        let target = match fixup.target {
            lx::Target::Internal { object, offset } => {
                ResolvedTarget {
                    linear: object_address(&image, module.bias, object, offset)?,
                    selector: *module.selectors.get(object as usize - 1).ok_or(8)?,
                    offset,
                }
            }
            lx::Target::ImportOrdinal { module: import_ordinal, ordinal } => {
                let imported_name = imports.get(import_ordinal as usize - 1).ok_or(8)?;
                let imported = find_module(modules, imported_name).ok_or(8)?;
                resolve_export(modules, imported, Some(ordinal), None)?
            }
            lx::Target::ImportName { module: import_ordinal, name_offset } => {
                let imported_name = imports.get(import_ordinal as usize - 1).ok_or(8)?;
                let imported = find_module(modules, imported_name).ok_or(8)?;
                let procedure = image.import_name(name_offset).map_err(|_| 8)?;
                resolve_export(modules, imported, None, Some(&procedure))?
            }
        };
        let linear = target.linear.wrapping_add(fixup.additive);
        let offset = target.offset.wrapping_add(fixup.additive);
        match fixup.source_type {
            0 => machine.write::<u8>(source as usize, linear as u8),
            3 => {
                machine.write::<u16>(source as usize, offset as u16);
                machine.write::<u16>(source as usize + 2, target.selector);
            }
            5 => machine.write::<u16>(source as usize, offset as u16),
            6 => machine.write::<u16>(source as usize, target.selector),
            7 => machine.write::<u32>(source as usize, linear),
            8 => machine.write::<u32>(source as usize, linear.wrapping_sub(source.wrapping_add(4))),
            _ => return Err(8),
        }
    }
    Ok(())
}

fn protect_module<A: crate::Arch>(machine: &mut A, module: &Module) -> Result<(), i32> {
    let image = lx::Image::parse(&module.data).map_err(|_| 8)?;
    for object in image.objects().map_err(|_| 8)? {
        let base = module.bias.checked_add(object.address).ok_or(8)? as usize;
        let first = base / 4096;
        let pages = (base % 4096 + object.size as usize).div_ceil(4096);
        if pages != 0 {
            machine.set_page_flags(
                first,
                pages,
                object.flags & lx::OBJ_WRITABLE != 0,
                object.flags & lx::OBJ_EXECUTABLE != 0,
            );
        }
    }
    Ok(())
}

fn vfs_image_path(path: &[u8], personality: Option<thread::PersonalityName>, cwd: &[u8]) -> Vec<u8> {
    if personality == Some(thread::PersonalityName::Dos) {
        crate::kernel::dos::dos_abs_to_vfs(path).unwrap_or_else(|| path.to_vec())
    } else {
        let mut buf = [0u8; 164];
        crate::kernel::exec::resolve_path(path, cwd, &mut buf).to_vec()
    }
}

/// Load an LX program and all of its DLL imports into the active address
/// space, relocate them, and initialize `tid` as an OS/2 process.
pub fn exec_lx_into<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
) -> Result<(), i32> {
    let main_image = lx::Image::parse(&data).map_err(|_| 8)?;
    if main_image.is_dll() { return Err(8); }
    let main_path = vfs_image_path(path, launcher, parent_cwd);
    let mut modules = vec![Module {
        name: module_name(main_path.rsplit(|&b| b == b'/').next().unwrap_or(&main_path)),
        path: main_path.clone(),
        data,
        bias: 0,
        selectors: Vec::new(),
    }];

    // Breadth-first dependency closure. A module is loaded once by its OS/2
    // logical module name, regardless of which importer reaches it first.
    let mut i = 0;
    while i < modules.len() {
        let imports = lx::Image::parse(&modules[i].data).map_err(|_| 8)?
            .import_modules().map_err(|_| 8)?;
        for imported in imports {
            if find_module(&modules, &imported).is_some() { continue; }
            if modules.len() >= MAX_MODULES { return Err(8); }
            let (dll_path, dll_data) = load_dependency(&imported, &modules[i].path)?;
            let image = lx::Image::parse(&dll_data).map_err(|_| 8)?;
            if !image.is_dll() { return Err(8); }
            let slot = modules.len() as u32;
            modules.push(Module {
                name: module_name(&imported),
                path: dll_path,
                data: dll_data,
                bias: DLL_BIAS_FIRST.checked_add((slot - 1) * DLL_BIAS_STRIDE).ok_or(8)?,
                selectors: Vec::new(),
            });
        }
        i += 1;
    }

    let mut ldt = vec![0];
    for module in &mut modules {
        let image = lx::Image::parse(&module.data).map_err(|_| 8)?;
        for object in image.objects().map_err(|_| 8)? {
            module.selectors.push(push_descriptor(
                &mut ldt,
                module.bias.checked_add(object.address).ok_or(8)?,
                object.size,
                object.flags & lx::OBJ_EXECUTABLE != 0,
                object.flags & lx::OBJ_BIG != 0,
            ));
        }
    }

    for module in &modules {
        if let Err(error) = map_module(machine, module) {
            crate::println!("OS/2: cannot map module {}", core::str::from_utf8(&module.name).unwrap_or("?"));
            return Err(error);
        }
    }
    for index in 0..modules.len() {
        if let Err(error) = apply_fixups(machine, &modules, index) {
            crate::println!("OS/2: cannot fix up module {}", core::str::from_utf8(&modules[index].name).unwrap_or("?"));
            return Err(error);
        }
    }

    let main = lx::Image::parse(&modules[0].data).map_err(|_| 8)?;
    let entry = object_address(&main, 0, main.header.start_object as u16, main.header.eip)?;
    let mut stack = if main.header.stack_object != 0 {
        object_address(&main, 0, main.header.stack_object as u16, main.header.esp)?
    } else {
        let size = main.header.stack_size.max(64 * 1024) as usize;
        if size >= STACK_TOP as usize { return Err(8); }
        let base = STACK_TOP as usize - size;
        machine.zero(base, size);
        machine.set_page_flags(base / 4096, size.div_ceil(4096), true, false);
        STACK_TOP
    };

    // OS/2 loader process data: a TIB selected by FS, followed by TIB2, PIB,
    // environment and the two-string command block expected by Open Watcom.
    machine.zero(PROCESS_DATA as usize, 4096);
    machine.set_page_flags(PROCESS_DATA as usize / 4096, 1, true, false);
    let tib = PROCESS_DATA;
    let tib2 = tib + 0x40;
    let pib = tib + 0x80;
    let env = tib + 0x100;
    let cmd = tib + 0x200;
    let tib_sel = push_descriptor(&mut ldt, tib, 4096, false, true);
    machine.write::<u32>((tib + 4) as usize, stack.saturating_sub(main.header.stack_size));
    machine.write::<u32>((tib + 8) as usize, stack);
    machine.write::<u32>((tib + 12) as usize, tib2);
    machine.write::<u32>(tib2 as usize, tid as u32 + 1);
    machine.write::<u32>(pib as usize, tid as u32 + 1);
    machine.write::<u32>((pib + 8) as usize, 1);
    machine.write::<u32>((pib + 12) as usize, cmd);
    machine.write::<u32>((pib + 16) as usize, env);
    machine.copy_to(env as usize, b"PATH=C:\\OS2\\APPS;C:\\OS2\\DLL\0COMSPEC=C:\\BOOT\\COMMAND.COM\0\0");
    let mut os2_name = Vec::with_capacity(main_path.len() + 4);
    os2_name.extend_from_slice(b"C:\\");
    let croot = crate::kernel::dos::c_root();
    let relative = main_path.strip_prefix(croot).unwrap_or(&main_path);
    os2_name.extend(relative.iter().map(|&b| if b == b'/' { b'\\' } else { b }));
    machine.copy_to(cmd as usize, &os2_name);
    machine.write::<u8>(cmd as usize + os2_name.len(), 0);
    machine.write::<u8>(cmd as usize + os2_name.len() + 1, 0);

    // The CRT entry sees an OS/2 loader frame, not a C CALL frame.
    stack = stack.checked_sub(20).ok_or(8)?;
    machine.write::<u32>(stack as usize, 0);
    machine.write::<u32>(stack as usize + 4, 1); // main module handle
    machine.write::<u32>(stack as usize + 8, pib);
    machine.write::<u32>(stack as usize + 12, env);
    machine.write::<u32>(stack as usize + 16, cmd);

    for module in &modules { protect_module(machine, module)?; }

    let current = thread::get_thread(threads, tid).ok_or(8)?;
    thread::init_process_thread(current, entry, stack);
    current.kernel.vcpu.regs.fs = tib_sel as u64;
    let mut state = Os2State::new();
    state.ldt = ldt;
    let gate_specs: &[(&[u8], &[u8], Api, u16)] = &[
        (b"DOSCALLS", b"DosQueryHType", Api::DosQueryHType, 0),
        (b"DOSCALLS", b"DosExit", Api::DosExit, 0),
        (b"DOSCALLS", b"DosResetBuffer", Api::DosResetBuffer, 0),
        (b"DOSCALLS", b"DosSetFilePtr", Api::DosSetFilePtr, 0),
        (b"DOSCALLS", b"DosClose", Api::DosClose, 0),
        (b"DOSCALLS", b"DosOpen", Api::DosOpen, 0),
        (b"DOSCALLS", b"DosRead", Api::DosRead, 0),
        (b"DOSCALLS", b"DosWrite", Api::DosWrite, 0),
        (b"DOSCALLS", b"DosQueryCp", Api::DosQueryCp, 0),
        (b"DOSCALLS", b"DosAllocMem", Api::DosAllocMem, 0),
        (b"DOSCALLS", b"DosFreeMem", Api::DosFreeMem, 0),
        (b"DOSCALLS", b"DosQueryModuleHandle", Api::DosQueryModuleHandle, 0),
        (b"DOSCALLS", b"DosQueryProcAddr", Api::DosQueryProcAddr, 0),
        (b"DOSCALLS", b"DosQuerySysInfo", Api::DosQuerySysInfo, 0),
        (b"DOSCALLS", b"DosSetRelMaxFH", Api::DosSetRelMaxFH, 0),
        (b"DOSCALLS", b"DosFlatToSel", Api::DosFlatToSel, 0),
        (b"DOSCALLS", b"DosSelToFlat", Api::DosSelToFlat, 0),
        (b"DOSCALLS", b"DosOpenL", Api::DosOpenL, 0),
        (b"DOSCALLS", b"DosSetFileLocksL", Api::DosSetFileLocksL, 0),
        (b"DOSCALLS", b"DosSetFilePtrL", Api::DosSetFilePtrL, 0),
        (b"DOSCALLS", b"DosGetDateTime", Api::DosGetDateTime, 0),
        (b"DOSCALLS", b"DosAllocSharedMem", Api::DosAllocSharedMem, 0),
        (b"DOSCALLS", b"DosGetNamedSharedMem", Api::DosGetNamedSharedMem, 0),
        (b"DOSCALLS", b"DosGetInfoBlocks", Api::DosGetInfoBlocks, 0),
        (b"NLS", b"DosQueryDBCSEnv", Api::DosQueryDBCSEnv, 0),
        (b"KBDCALLS", b"KbdCharIn", Api::KbdCharIn, 6),
        (b"VIOCALLS", b"VioGetConfig", Api::VioGetConfig, 6),
        (b"PMWIN", b"WinInitialize", Api::WinInitialize, 0),
        (b"PMWIN", b"WinCreateMsgQueue", Api::WinCreateMsgQueue, 0),
        (b"PMWIN", b"WinCreateWindow", Api::WinCreateWindow, 0),
        (b"PMWIN", b"WinShowWindow", Api::WinShowWindow, 0),
        (b"PMWIN", b"WinGetPS", Api::WinGetPS, 0),
        (b"PMWIN", b"WinReleasePS", Api::WinReleasePS, 0),
        (b"PMWIN", b"WinFillRect", Api::WinFillRect, 0),
        (b"PMWIN", b"WinPostQueueMsg", Api::WinPostQueueMsg, 0),
        (b"PMWIN", b"WinGetMsg", Api::WinGetMsg, 0),
        (b"PMWIN", b"WinDispatchMsg", Api::WinDispatchMsg, 0),
        (b"PMWIN", b"WinDestroyWindow", Api::WinDestroyWindow, 0),
        (b"PMWIN", b"WinDestroyMsgQueue", Api::WinDestroyMsgQueue, 0),
        (b"PMWIN", b"WinTerminate", Api::WinTerminate, 0),
        (b"PMWIN", b"WinBeginPaint", Api::WinBeginPaint, 0),
        (b"PMWIN", b"WinDismissDlg", Api::WinDismissDlg, 0),
        (b"PMWIN", b"WinDrawBitmap", Api::WinDrawBitmap, 0),
        (b"PMWIN", b"WinDrawBorder", Api::WinDrawBorder, 0),
        (b"PMWIN", b"WinEndPaint", Api::WinEndPaint, 0),
        (b"PMWIN", b"WinInvalidateRect", Api::WinInvalidateRect, 0),
        (b"PMWIN", b"WinLoadString", Api::WinLoadString, 0),
        (b"PMWIN", b"WinMessageBox", Api::WinMessageBox, 0),
        (b"PMWIN", b"WinPtInRect", Api::WinPtInRect, 0),
        (b"PMWIN", b"WinQueryDlgItemText", Api::WinQueryDlgItemText, 0),
        (b"PMWIN", b"WinQuerySysValue", Api::WinQuerySysValue, 0),
        (b"PMWIN", b"WinQueryWindow", Api::WinQueryWindow, 0),
        (b"PMWIN", b"WinQueryWindowPos", Api::WinQueryWindowPos, 0),
        (b"PMWIN", b"WinQueryWindowRect", Api::WinQueryWindowRect, 0),
        (b"PMWIN", b"WinSetDlgItemText", Api::WinSetDlgItemText, 0),
        (b"PMWIN", b"WinSetWindowPos", Api::WinSetWindowPos, 0),
        (b"PMWIN", b"WinStartTimer", Api::WinStartTimer, 0),
        (b"PMWIN", b"WinStopTimer", Api::WinStopTimer, 0),
        (b"PMWIN", b"WinWindowFromID", Api::WinWindowFromId, 0),
        (b"PMWIN", b"WinSendDlgItemMsg", Api::WinSendDlgItemMsg, 0),
        (b"PMWIN", b"WinCreateStdWindow", Api::WinCreateStdWindow, 0),
        (b"PMWIN", b"WinDefDlgProc", Api::WinDefDlgProc, 0),
        (b"PMWIN", b"WinDefWindowProc", Api::WinDefWindowProc, 0),
        (b"PMWIN", b"WinSendMsg", Api::WinSendMsg, 0),
        (b"PMWIN", b"WinDlgBox", Api::WinDlgBox, 0),
        (b"PMWIN", b"WinRegisterClass", Api::WinRegisterClass, 0),
        (b"PMWIN", b"RetroWndProcReturn", Api::RetroWndProcReturn, 0),
        (b"PMGPI", b"GpiBox", Api::GpiBox, 0),
        (b"PMGPI", b"GpiDeleteBitmap", Api::GpiDeleteBitmap, 0),
        (b"PMGPI", b"GpiLoadBitmap", Api::GpiLoadBitmap, 0),
        (b"PMGPI", b"GpiMove", Api::GpiMove, 0),
        (b"PMSHAPI", b"PrfOpenProfile", Api::PrfOpenProfile, 0),
        (b"PMSHAPI", b"PrfCloseProfile", Api::PrfCloseProfile, 0),
        (b"PMSHAPI", b"PrfQueryProfileData", Api::PrfQueryProfileData, 0),
        (b"PMSHAPI", b"PrfWriteProfileData", Api::PrfWriteProfileData, 0),
        (b"HELPMGR", b"WinCreateHelpInstance", Api::WinCreateHelpInstance, 0),
        (b"HELPMGR", b"WinDestroyHelpInstance", Api::WinDestroyHelpInstance, 0),
        (b"HELPMGR", b"WinAssociateHelpInstance", Api::WinAssociateHelpInstance, 0),
    ];
    for &(module_name, export_name, api, far16_args) in gate_specs {
        // A process only needs gates for DLLs in its own import closure. For
        // example, a small stdio program imports DOSCALLS but no KBD/VIO/NLS
        // module; those absent optional modules are not a load failure.
        let Some(mi) = find_module(&modules, module_name) else { continue; };
        let Ok(target) = resolve_export(&modules, mi, None, Some(export_name)) else { continue; };
        state.gates.push(Gate {
            cs: if far16_args == 0 { arch_abi::USER_CS } else { target.selector },
            return_ip: if far16_args == 0 { target.linear + 2 } else { target.offset + 2 },
            api,
            far16_args,
        });
    }
    state.set_exec_path(&main_path);
    let cwd = dirname(&main_path);
    let n = cwd.len().min(state.cwd.len());
    state.cwd[..n].copy_from_slice(&cwd[..n]);
    state.cwd_len = n;
    state.modules = modules;
    state.callback_return = state.gates.iter()
        .find(|gate| gate.api == Api::RetroWndProcReturn)
        .map(|gate| gate.return_ip - 2)
        .unwrap_or(0);
    state.on_resume(machine);
    current.personality = thread::Personality::Os2(state);
    Ok(())
}

fn gate_from_event(state: &Os2State, cs: u16, ip: u32) -> Option<Gate> {
    state.gates.iter().copied().find(|g| g.cs == cs && g.return_ip == ip)
}

fn finish_call<A: crate::Arch>(machine: &A, regs: &mut Regs, result: u32) {
    let sp = regs.sp() as usize;
    let return_eip = machine.read::<u32>(sp);
    regs.rax = result as u64;
    regs.frame.rip = return_eip as u64;
    // _System is caller-clean: consume only CALL's return address. The caller
    // resumes at its generated `add esp, argument_bytes`.
    regs.frame.rsp = regs.frame.rsp.wrapping_add(4);
}

fn finish_gate<A: crate::Arch>(machine: &A, regs: &mut Regs, gate: Gate, result: u32) {
    if gate.far16_args == 0 {
        finish_call(machine, regs, result);
    } else {
        let sp = regs.sp() as usize;
        regs.rax = (regs.rax & !0xffff) | result as u16 as u64;
        regs.frame.rip = machine.read::<u16>(sp) as u64;
        regs.frame.cs = machine.read::<u16>(sp + 2) as u64;
        regs.frame.rsp = regs.frame.rsp.wrapping_add(4 + gate.far16_args as u64);
    }
}

fn arg32<A: crate::Arch>(machine: &A, regs: &Regs, n: usize) -> u32 {
    machine.read::<u32>(regs.sp() as usize + 4 + n * 4)
}

fn c_string<A: crate::Arch>(machine: &A, address: u32) -> Result<Vec<u8>, u32> {
    if address == 0 { return Err(ERROR_INVALID_PARAMETER); }
    let mut out = Vec::new();
    for i in 0..1024 {
        let b = machine.read::<u8>(address as usize + i);
        if b == 0 { return Ok(out); }
        out.push(b);
    }
    Err(ERROR_INVALID_PARAMETER)
}

fn os2_path(state: &Os2State, path: &[u8], create: bool) -> Result<Vec<u8>, u32> {
    if path.len() >= 2 && path[1] == b':' {
        let mut dos = path.to_vec();
        for b in &mut dos { if *b == b'/' { *b = b'\\'; } }
        let resolved = if create {
            crate::kernel::dos::dos_abs_to_vfs_create(&dos)
        } else {
            crate::kernel::dos::dos_abs_to_vfs(&dos)
        };
        return resolved.ok_or(ERROR_FILE_NOT_FOUND);
    }
    let mut normalized = path.to_vec();
    for b in &mut normalized { if *b == b'\\' { *b = b'/'; } }
    Ok(join(state.cwd_str(), &normalized))
}

fn os2_error(error: i32) -> u32 {
    match -error {
        2 => 2, 9 => ERROR_INVALID_HANDLE, 12 => ERROR_NOT_ENOUGH_MEMORY,
        13 => 5, 17 => 80, 22 => ERROR_INVALID_PARAMETER, 24 => 4,
        _ => ERROR_INVALID_FUNCTION,
    }
}

fn dos_open<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, state: &Os2State, regs: &Regs) -> u32 {
    let phandle = arg32(machine, regs, 1) as usize;
    let paction = arg32(machine, regs, 2) as usize;
    let actions = arg32(machine, regs, 5);
    let path = match c_string(machine, arg32(machine, regs, 0))
        .and_then(|p| os2_path(state, &p, actions & 0x10 != 0)) { Ok(p) => p, Err(e) => return e };
    let existed = crate::kernel::vfs::path_exists(&path);
    let handle = if existed {
        match actions & 3 {
            1 => crate::kernel::vfs::open_to_handle(&path),
            2 => crate::kernel::vfs::create_to_handle(&path),
            _ => return 80,
        }
    } else if actions & 0x10 != 0 {
        crate::kernel::vfs::create_to_handle(&path)
    } else {
        return ERROR_FILE_NOT_FOUND;
    };
    if handle < 0 { return os2_error(handle); }
    let Some(fd) = kt.alloc_fd(3) else {
        crate::kernel::vfs::close_vfs_handle(handle);
        return 4;
    };
    kt.fds[fd] = thread::FdKind::Vfs(handle);
    machine.write::<u32>(phandle, fd as u32);
    if paction != 0 { machine.write::<u32>(paction, if existed { if actions & 3 == 2 { 3 } else { 1 } } else { 2 }); }
    NO_ERROR
}

fn dos_open_l<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, state: &Os2State, regs: &Regs) -> u32 {
    // LONGLONG cbFile occupies argument slots 3 and 4; the remaining Open
    // parameters are therefore shifted by one compared with DosOpen.
    let phandle = arg32(machine, regs, 1) as usize;
    let paction = arg32(machine, regs, 2) as usize;
    let actions = arg32(machine, regs, 6);
    let path = match c_string(machine, arg32(machine, regs, 0))
        .and_then(|p| os2_path(state, &p, actions & 0x10 != 0)) { Ok(p) => p, Err(e) => return e };
    let existed = crate::kernel::vfs::path_exists(&path);
    let handle = if existed {
        match actions & 3 {
            1 => crate::kernel::vfs::open_to_handle(&path),
            2 => crate::kernel::vfs::create_to_handle(&path),
            _ => return 80,
        }
    } else if actions & 0x10 != 0 {
        crate::kernel::vfs::create_to_handle(&path)
    } else { return ERROR_FILE_NOT_FOUND; };
    if handle < 0 { return os2_error(handle); }
    let Some(fd) = kt.alloc_fd(3) else { crate::kernel::vfs::close_vfs_handle(handle); return 4; };
    kt.fds[fd] = thread::FdKind::Vfs(handle);
    machine.write::<u32>(phandle, fd as u32);
    if paction != 0 { machine.write::<u32>(paction, if existed { if actions & 3 == 2 { 3 } else { 1 } } else { 2 }); }
    NO_ERROR
}

fn dos_read<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, regs: &Regs) -> u32 {
    let fd = arg32(machine, regs, 0) as usize;
    let address = arg32(machine, regs, 1) as usize;
    let length = arg32(machine, regs, 2) as usize;
    let actual = arg32(machine, regs, 3) as usize;
    if fd >= thread::MAX_FDS { return ERROR_INVALID_HANDLE; }
    let mut bytes = vec![0; length];
    let n = match kt.fds[fd] {
        thread::FdKind::Vfs(h) => crate::kernel::vfs::read_by_handle(h, &mut bytes),
        thread::FdKind::PipeRead(p) => crate::kernel::kpipe::read(p, &mut bytes) as i32,
        _ => return ERROR_INVALID_HANDLE,
    };
    if n < 0 { return os2_error(n); }
    machine.copy_to(address, &bytes[..n as usize]);
    if actual != 0 { machine.write::<u32>(actual, n as u32); }
    NO_ERROR
}

fn dos_write<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, regs: &mut Regs) -> u32 {
    let handle = arg32(machine, regs, 0) as usize;
    let buffer = arg32(machine, regs, 1) as usize;
    let length = arg32(machine, regs, 2) as usize;
    let actual = arg32(machine, regs, 3) as usize;
    if handle >= thread::MAX_FDS { return ERROR_INVALID_HANDLE; }
    let mut bytes = vec![0u8; length];
    machine.copy_from(buffer, &mut bytes);
    let written = match kt.fds[handle] {
        thread::FdKind::ConsoleOut => {
            for &b in &bytes { crate::term::putchar(b); }
            crate::kernel::term::mark_dirty();
            length as i32
        }
        thread::FdKind::PipeWrite(pipe) => crate::kernel::kpipe::write(pipe, &bytes),
        thread::FdKind::Vfs(file) => crate::kernel::vfs::write_by_handle(machine, file, &bytes),
        _ => return ERROR_INVALID_HANDLE,
    };
    if written < 0 { return ERROR_INVALID_HANDLE; }
    if actual != 0 { machine.write::<u32>(actual, written as u32); }
    NO_ERROR
}

fn selector_base(state: &Os2State, selector: u16) -> Option<u32> {
    let desc = *state.ldt.get((selector >> 3) as usize)?;
    Some((((desc >> 16) & 0xffff) | (((desc >> 32) & 0xff) << 16) | (((desc >> 56) & 0xff) << 24)) as u32)
}

fn write_pm_message<A: crate::Arch>(machine: &mut A, address: usize, message: PmMessage) {
    machine.write::<u32>(address, message.hwnd);
    machine.write::<u32>(address + 4, message.message);
    machine.write::<u32>(address + 8, message.mp1);
    machine.write::<u32>(address + 12, message.mp2);
    machine.write::<u32>(address + 16, machine.get_ticks() as u32);
    machine.write::<u32>(address + 20, 0);
    machine.write::<u32>(address + 24, 0);
}

fn fill_pm_rect<A: crate::Arch>(machine: &A, state: &mut Os2State, regs: &Regs) -> u32 {
    let hps = arg32(machine, regs, 0);
    let rect = arg32(machine, regs, 1) as usize;
    let color = arg32(machine, regs, 2).to_le_bytes();
    let Some(window) = state.pm_windows.iter_mut().find(|window| window.hwnd == hps) else {
        return 0;
    };
    let left = machine.read::<i32>(rect).clamp(0, window.width as i32);
    let bottom = machine.read::<i32>(rect + 4).clamp(0, window.height as i32);
    let right = machine.read::<i32>(rect + 8).clamp(left, window.width as i32);
    let top = machine.read::<i32>(rect + 12).clamp(bottom, window.height as i32);
    for pm_y in bottom..top {
        let y = window.height as i32 - 1 - pm_y;
        for x in left..right {
            let at = (y as usize * window.width as usize + x as usize) * 4;
            window.pixels[at..at + 4].copy_from_slice(&color);
        }
    }
    state.pm_dirty = true;
    1
}

fn queue_pm_message(state: &mut Os2State, message: PmMessage) {
    if !state.pm_messages.iter().any(|queued| {
        queued.hwnd == message.hwnd && queued.message == message.message
    }) {
        state.pm_messages.push(message);
    }
}

fn create_pm_window(state: &mut Os2State, class: &[u8], id: u32, width: u32, height: u32, visible: bool) -> u32 {
    let hwnd = state.next_pm_handle;
    state.next_pm_handle = state.next_pm_handle.wrapping_add(1);
    let wndproc = state.pm_classes.iter()
        .find(|registered| eq_name(&registered.name, class))
        .map_or(0, |registered| registered.wndproc);
    state.pm_windows.push(PmWindow {
        hwnd,
        wndproc,
        id,
        x: 0,
        y: 0,
        width: width.clamp(1, 2048),
        height: height.clamp(1, 2048),
        visible,
        pixels: vec![0x00; width.clamp(1, 2048) as usize * height.clamp(1, 2048) as usize * 4],
    });
    queue_pm_message(state, PmMessage { hwnd, message: 0x0001, mp1: 0, mp2: 0 });
    queue_pm_message(state, PmMessage { hwnd, message: 0x0023, mp1: 0, mp2: 0 });
    state.pm_dirty = true;
    hwnd
}

fn begin_wndproc<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    state: &mut Os2State,
    _gate: Gate,
    message: PmMessage,
) -> bool {
    let Some(window) = state.pm_windows.iter().find(|window| window.hwnd == message.hwnd) else {
        return false;
    };
    if window.wndproc == 0 || state.callback.is_some() { return false; }
    let sp = regs.sp().wrapping_sub(20);
    machine.write::<u32>(sp as usize, state.callback_return);
    machine.write::<u32>(sp as usize + 4, message.hwnd);
    machine.write::<u32>(sp as usize + 8, message.message);
    machine.write::<u32>(sp as usize + 12, message.mp1);
    machine.write::<u32>(sp as usize + 16, message.mp2);
    state.callback = Some(Callback { dispatch_sp: regs.sp() as u32 });
    regs.frame.rsp = sp;
    regs.frame.rip = window.wndproc as u64;
    true
}

fn alloc_os2_memory<A: crate::Arch>(machine: &mut A, state: &mut Os2State, out: usize, requested: u32) -> u32 {
    let size = requested.max(1).next_multiple_of(4096);
    let Some(end) = state.heap_next.checked_add(size) else { return ERROR_NOT_ENOUGH_MEMORY; };
    if end >= USER_LIMIT { return ERROR_NOT_ENOUGH_MEMORY; }
    let base = state.heap_next;
    state.heap_next = end;
    machine.zero(base as usize, size as usize);
    machine.set_page_flags(base as usize / 4096, size as usize / 4096, true, false);
    state.allocations.push((base, size));
    machine.write::<u32>(out, base);
    NO_ERROR
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_os2_bitmap(data: &[u8], handle: u32) -> Option<PmBitmap> {
    let file = if data.get(0..2) == Some(b"BA") { 14 } else { 0 };
    if data.get(file..file + 2) != Some(b"BM") { return None; }
    let bits = le_u32(data, file + 10)? as usize;
    let info = file + 14;
    let header_size = le_u32(data, info)? as usize;
    let (width, height, planes, bit_count, palette_stride) = if header_size == 12 {
        (
            le_u16(data, info + 4)? as u32,
            le_u16(data, info + 6)? as u32,
            le_u16(data, info + 8)?,
            le_u16(data, info + 10)?,
            3,
        )
    } else if header_size >= 16 {
        (
            le_u32(data, info + 4)?,
            le_u32(data, info + 8)?,
            le_u16(data, info + 12)?,
            le_u16(data, info + 14)?,
            4,
        )
    } else { return None; };
    if width == 0 || height == 0 || planes != 1 || !matches!(bit_count, 1 | 4 | 8) {
        return None;
    }
    let palette_at = info.checked_add(header_size)?;
    let colors = 1usize << bit_count;
    data.get(palette_at..palette_at.checked_add(colors * palette_stride)?)?;
    let row_bytes = (width as usize * bit_count as usize).div_ceil(32) * 4;
    data.get(bits..bits.checked_add(row_bytes * height as usize)?)?;
    let mut pixels = vec![0; width as usize * height as usize * 4];
    for y in 0..height as usize {
        let source_y = height as usize - 1 - y;
        let row = bits + source_y * row_bytes;
        for x in 0..width as usize {
            let index = match bit_count {
                1 => (data[row + x / 8] >> (7 - x % 8)) & 1,
                4 => {
                    let byte = data[row + x / 2];
                    if x & 1 == 0 { byte >> 4 } else { byte & 0x0f }
                }
                8 => data[row + x],
                _ => unreachable!(),
            } as usize;
            let color = palette_at + index * palette_stride;
            let target = (y * width as usize + x) * 4;
            pixels[target] = data[color];
            pixels[target + 1] = data[color + 1];
            pixels[target + 2] = data[color + 2];
        }
    }
    Some(PmBitmap { handle, width, height, pixels })
}

fn load_pm_bitmap(state: &mut Os2State, id: u16) -> u32 {
    let handle = 0x20000 + u32::from(id);
    if state.pm_bitmaps.iter().any(|bitmap| bitmap.handle == handle) { return handle; }
    let Some(module) = state.modules.first() else { return 0; };
    let Ok(image) = lx::Image::parse(&module.data) else { return 0; };
    let Ok(resources) = image.resources() else { return 0; };
    let Some(resource) = resources.into_iter().find(|resource| resource.kind == 2 && resource.id == id) else {
        return 0;
    };
    let Ok(data) = image.resource_data(resource) else { return 0; };
    let Some(bitmap) = decode_os2_bitmap(&data, handle) else { return 0; };
    state.pm_bitmaps.push(bitmap);
    handle
}

fn draw_pm_bitmap<A: crate::Arch>(machine: &A, state: &mut Os2State, regs: &Regs) -> u32 {
    let hps = arg32(machine, regs, 0);
    let handle = arg32(machine, regs, 1);
    let destination = arg32(machine, regs, 3) as usize;
    let Some(bitmap) = state.pm_bitmaps.iter().find(|bitmap| bitmap.handle == handle) else { return 0; };
    let Some(window) = state.pm_windows.iter_mut().find(|window| window.hwnd == hps) else { return 0; };
    let left = machine.read::<i32>(destination);
    let bottom = machine.read::<i32>(destination + 4);
    for source_y in 0..bitmap.height as i32 {
        let target_y = window.height as i32 - 1 - (bottom + bitmap.height as i32 - 1 - source_y);
        if !(0..window.height as i32).contains(&target_y) { continue; }
        for source_x in 0..bitmap.width as i32 {
            let target_x = left + source_x;
            if !(0..window.width as i32).contains(&target_x) { continue; }
            let source = (source_y as usize * bitmap.width as usize + source_x as usize) * 4;
            let target = (target_y as usize * window.width as usize + target_x as usize) * 4;
            window.pixels[target..target + 4].copy_from_slice(&bitmap.pixels[source..source + 4]);
        }
    }
    state.pm_dirty = true;
    1
}

fn dispatch_api<A: crate::Arch>(
    machine: &mut A, kt: &mut thread::KernelThread<A>, state: &mut Os2State,
    regs: &mut Regs, api: Api,
) -> u32 {
    match api {
        Api::DosOpen => dos_open(machine, kt, state, regs),
        Api::DosOpenL => dos_open_l(machine, kt, state, regs),
        Api::DosSetFileLocksL => NO_ERROR,
        Api::DosSetFilePtrL => {
            let fd = arg32(machine, regs, 0) as usize;
            let offset = arg32(machine, regs, 1) as i32;
            let high = arg32(machine, regs, 2) as i32;
            let whence = arg32(machine, regs, 3) as i32;
            let actual = arg32(machine, regs, 4) as usize;
            if high != 0 && high != -1 { return ERROR_INVALID_PARAMETER; }
            if fd >= thread::MAX_FDS { return ERROR_INVALID_HANDLE; }
            let thread::FdKind::Vfs(handle) = kt.fds[fd] else { return ERROR_INVALID_HANDLE; };
            let pos = crate::kernel::vfs::seek_by_handle(handle, offset, whence);
            if pos < 0 { os2_error(pos) } else {
                if actual != 0 {
                    machine.write::<u32>(actual, pos as u32);
                    machine.write::<u32>(actual + 4, 0);
                }
                NO_ERROR
            }
        }
        Api::DosRead => dos_read(machine, kt, regs),
        Api::DosWrite => dos_write(machine, kt, regs),
        Api::DosClose => {
            let fd = arg32(machine, regs, 0) as usize;
            if fd >= thread::MAX_FDS || kt.fds[fd].is_none() { ERROR_INVALID_HANDLE }
            else { kt.close_fd(fd); NO_ERROR }
        }
        Api::DosSetFilePtr => {
            let fd = arg32(machine, regs, 0) as usize;
            let offset = arg32(machine, regs, 1) as i32;
            let whence = arg32(machine, regs, 2) as i32;
            let actual = arg32(machine, regs, 3) as usize;
            if fd >= thread::MAX_FDS { return ERROR_INVALID_HANDLE; }
            let thread::FdKind::Vfs(handle) = kt.fds[fd] else { return ERROR_INVALID_HANDLE; };
            let pos = crate::kernel::vfs::seek_by_handle(handle, offset, whence);
            if pos < 0 { os2_error(pos) } else {
                if actual != 0 { machine.write::<u32>(actual, pos as u32); }
                NO_ERROR
            }
        }
        Api::DosResetBuffer => NO_ERROR,
        Api::DosQueryHType => {
            let fd = arg32(machine, regs, 0) as usize;
            if fd >= thread::MAX_FDS || kt.fds[fd].is_none() { return ERROR_INVALID_HANDLE; }
            let kind = match kt.fds[fd] {
                thread::FdKind::Vfs(_) => 0,
                thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => 2,
                _ => 1,
            };
            machine.write::<u32>(arg32(machine, regs, 1) as usize, kind);
            machine.write::<u32>(arg32(machine, regs, 2) as usize, 0);
            NO_ERROR
        }
        Api::DosQueryCp => {
            let cb = arg32(machine, regs, 0);
            let list = arg32(machine, regs, 1) as usize;
            let actual = arg32(machine, regs, 2) as usize;
            if cb < 4 { ERROR_INVALID_PARAMETER } else {
                machine.write::<u32>(list, 437);
                machine.write::<u32>(actual, 4);
                NO_ERROR
            }
        }
        Api::DosAllocMem | Api::DosAllocSharedMem => alloc_os2_memory(
            machine, state, arg32(machine, regs, 0) as usize, arg32(machine, regs, 1),
        ),
        Api::DosFreeMem => {
            let address = arg32(machine, regs, 0);
            if let Some(i) = state.allocations.iter().position(|&(a, _)| a == address) {
                state.allocations.swap_remove(i);
                NO_ERROR
            } else { ERROR_INVALID_PARAMETER }
        }
        Api::DosQueryModuleHandle => {
            let name = match c_string(machine, arg32(machine, regs, 0)) { Ok(n) => n, Err(e) => return e };
            if let Some(index) = find_module(&state.modules, &name) {
                machine.write::<u32>(arg32(machine, regs, 1) as usize, index as u32 + 1);
                NO_ERROR
            } else { 126 }
        }
        Api::DosQueryProcAddr => {
            let handle = arg32(machine, regs, 0) as usize;
            if handle == 0 || handle > state.modules.len() { return 126; }
            let ordinal = arg32(machine, regs, 1);
            let name_ptr = arg32(machine, regs, 2);
            let target = if ordinal != 0 {
                resolve_export(&state.modules, handle - 1, Some(ordinal as u16), None)
            } else {
                let name = match c_string(machine, name_ptr) { Ok(n) => n, Err(e) => return e };
                resolve_export(&state.modules, handle - 1, None, Some(&name))
            };
            match target {
                Ok(t) => { machine.write::<u32>(arg32(machine, regs, 3) as usize, t.linear); NO_ERROR }
                Err(e) => e as u32,
            }
        }
        Api::DosQuerySysInfo => {
            let first = arg32(machine, regs, 0);
            let last = arg32(machine, regs, 1);
            let out = arg32(machine, regs, 2) as usize;
            let size = arg32(machine, regs, 3) as usize;
            let count = last.checked_sub(first).map_or(usize::MAX, |n| n as usize + 1);
            if count.checked_mul(4).is_none_or(|n| n > size) { return ERROR_INVALID_PARAMETER; }
            for i in 0..count {
                let index = first + i as u32;
                let value = match index {
                    1 => 260, 5 => 3, 10 => 4096, 11 => 20, 12 => 45,
                    13 => 0, 14 => machine.get_ticks() as u32, 17 | 19 | 20 => 256 * 1024 * 1024,
                    26 => 1, _ => 0,
                };
                machine.write::<u32>(out + i * 4, value);
            }
            NO_ERROR
        }
        Api::DosSetRelMaxFH => {
            let max = arg32(machine, regs, 1) as usize;
            if max != 0 { machine.write::<u32>(max, thread::MAX_FDS as u32); }
            NO_ERROR
        }
        Api::DosGetDateTime => {
            let out = arg32(machine, regs, 0) as usize;
            machine.zero(out, 12);
            machine.write::<u8>(out, 12);
            machine.write::<u8>(out + 1, 0);
            machine.write::<u8>(out + 4, 1);
            machine.write::<u8>(out + 5, 1);
            machine.write::<u16>(out + 6, 1996);
            NO_ERROR
        }
        Api::DosGetNamedSharedMem => ERROR_FILE_NOT_FOUND,
        Api::DosGetInfoBlocks => {
            machine.write::<u32>(arg32(machine, regs, 0) as usize, PROCESS_DATA);
            machine.write::<u32>(arg32(machine, regs, 1) as usize, PROCESS_DATA + 0x80);
            NO_ERROR
        }
        Api::DosQueryDBCSEnv => {
            let cb = arg32(machine, regs, 0) as usize;
            let out = arg32(machine, regs, 2) as usize;
            if cb != 0 { machine.zero(out, cb); }
            NO_ERROR
        }
        Api::DosFlatToSel => {
            // In RetroOS all 32-bit user objects are flat; return a canonical
            // data selector while preserving the flat offset in EAX.
            arch_abi::USER_DS as u32
        }
        Api::DosSelToFlat => arg32(machine, regs, 0),
        Api::KbdCharIn => NO_ERROR,
        Api::VioGetConfig => {
            // 16-bit Pascal args: id, far pointer, hvio. Fill the common
            // leading length/adapter/display fields conservatively.
            let sp = regs.sp() as usize;
            let offset = machine.read::<u16>(sp + 6) as u32;
            let selector = machine.read::<u16>(sp + 8);
            if let Some(base) = selector_base(state, selector) {
                machine.write::<u16>((base + offset) as usize, 10);
            }
            NO_ERROR
        }
        Api::WinInitialize => 1,
        Api::WinCreateMsgQueue => 2,
        Api::WinCreateWindow => {
            let class = c_string(machine, arg32(machine, regs, 1)).unwrap_or_default();
            let width = arg32(machine, regs, 6).clamp(1, 2048);
            let height = arg32(machine, regs, 7).clamp(1, 2048);
            create_pm_window(
                state, &class, arg32(machine, regs, 10), width, height,
                arg32(machine, regs, 3) & 0x8000_0000 != 0,
            )
        }
        Api::WinShowWindow => {
            let hwnd = arg32(machine, regs, 0);
            let Some(window) = state.pm_windows.iter_mut().find(|window| window.hwnd == hwnd) else {
                return 0;
            };
            window.visible = arg32(machine, regs, 1) != 0;
            state.pm_dirty = true;
            1
        }
        Api::WinGetPS => {
            let hwnd = arg32(machine, regs, 0);
            if state.pm_windows.iter().any(|window| window.hwnd == hwnd) { hwnd } else { 0 }
        }
        Api::WinReleasePS => 1,
        Api::WinFillRect => fill_pm_rect(machine, state, regs),
        Api::WinPostQueueMsg => {
            state.pm_messages.push(PmMessage {
                hwnd: 0,
                message: arg32(machine, regs, 1),
                mp1: arg32(machine, regs, 2),
                mp2: arg32(machine, regs, 3),
            });
            1
        }
        Api::WinGetMsg => {
            let out = arg32(machine, regs, 1) as usize;
            state.advance_timers(machine.now());
            let Some(message) = (!state.pm_messages.is_empty())
                .then(|| state.pm_messages.remove(0))
            else {
                // Keep the call frame intact.  PMWIN's WinGetMsg tail executes
                // HLT and retries this gate when the event loop next runs it.
                return u32::MAX;
            };
            write_pm_message(machine, out, message);
            (message.message != 0x002a) as u32
        }
        Api::WinDispatchMsg | Api::RetroWndProcReturn => 0,
        Api::WinDestroyWindow => {
            let hwnd = arg32(machine, regs, 0);
            if let Some(index) = state.pm_windows.iter().position(|window| window.hwnd == hwnd) {
                state.pm_windows.swap_remove(index);
                state.pm_dirty = true;
                1
            } else { 0 }
        }
        Api::WinDestroyMsgQueue | Api::WinTerminate => 1,
        Api::WinRegisterClass => {
            let name = match c_string(machine, arg32(machine, regs, 1)) {
                Ok(name) => name,
                Err(_) => return 0,
            };
            let wndproc = arg32(machine, regs, 2);
            if let Some(class) = state.pm_classes.iter_mut().find(|class| eq_name(&class.name, &name)) {
                class.wndproc = wndproc;
            } else {
                state.pm_classes.push(PmClass { name, wndproc });
            }
            1
        }
        Api::WinCreateStdWindow => {
            let class = c_string(machine, arg32(machine, regs, 3)).unwrap_or_default();
            let client = create_pm_window(state, &class, 0x8008, 640, 480, true);
            let out = arg32(machine, regs, 8) as usize;
            if out != 0 { machine.write::<u32>(out, client); }
            client
        }
        Api::WinBeginPaint => {
            let hwnd = arg32(machine, regs, 0);
            let rect = arg32(machine, regs, 2) as usize;
            if let Some(window) = state.pm_windows.iter().find(|window| window.hwnd == hwnd) {
                if rect != 0 {
                    machine.write::<i32>(rect, 0);
                    machine.write::<i32>(rect + 4, 0);
                    machine.write::<i32>(rect + 8, window.width as i32);
                    machine.write::<i32>(rect + 12, window.height as i32);
                }
                hwnd
            } else { 0 }
        }
        Api::WinEndPaint | Api::WinDismissDlg | Api::WinDrawBorder
        | Api::WinSetDlgItemText
        | Api::WinDestroyHelpInstance | Api::WinAssociateHelpInstance
        | Api::PrfCloseProfile | Api::PrfWriteProfileData
        | Api::GpiDeleteBitmap => 1,
        Api::WinInvalidateRect => {
            let hwnd = arg32(machine, regs, 0);
            queue_pm_message(state, PmMessage { hwnd, message: 0x0023, mp1: 0, mp2: 0 });
            1
        }
        Api::WinQuerySysValue => match arg32(machine, regs, 1) {
            20 => 1024,
            21 => 768,
            _ => 16,
        },
        Api::WinQueryWindowRect => {
            let hwnd = arg32(machine, regs, 0);
            let out = arg32(machine, regs, 1) as usize;
            let Some(window) = state.pm_windows.iter().find(|window| window.hwnd == hwnd) else { return 0; };
            machine.write::<i32>(out, 0);
            machine.write::<i32>(out + 4, 0);
            machine.write::<i32>(out + 8, window.width as i32);
            machine.write::<i32>(out + 12, window.height as i32);
            1
        }
        Api::WinQueryWindowPos => {
            let hwnd = arg32(machine, regs, 0);
            let out = arg32(machine, regs, 1) as usize;
            let Some(window) = state.pm_windows.iter().find(|window| window.hwnd == hwnd) else { return 0; };
            machine.zero(out, 36);
            machine.write::<i32>(out + 4, window.height as i32);
            machine.write::<i32>(out + 8, window.width as i32);
            machine.write::<i32>(out + 12, window.y);
            machine.write::<i32>(out + 16, window.x);
            machine.write::<u32>(out + 24, hwnd);
            1
        }
        Api::WinSetWindowPos => {
            let hwnd = arg32(machine, regs, 0);
            let Some(window) = state.pm_windows.iter_mut().find(|window| window.hwnd == hwnd) else { return 0; };
            let flags = arg32(machine, regs, 6);
            if flags & 0x0001 != 0 {
                window.width = arg32(machine, regs, 4).clamp(1, 2048);
                window.height = arg32(machine, regs, 5).clamp(1, 2048);
                window.pixels.resize(window.width as usize * window.height as usize * 4, 0);
            }
            if flags & 0x0002 != 0 {
                window.x = arg32(machine, regs, 2) as i32;
                window.y = arg32(machine, regs, 3) as i32;
            }
            if flags & 0x0004 != 0 { window.visible = true; }
            state.pm_dirty = true;
            1
        }
        Api::WinStartTimer => {
            state.timer_hwnd = arg32(machine, regs, 1);
            let requested_id = arg32(machine, regs, 2);
            state.timer_id = if requested_id == 0 { 1 } else { requested_id };
            let interval_ms = arg32(machine, regs, 3).max(1);
            state.timer_interval_ns = u64::from(interval_ms).saturating_mul(1_000_000);
            state.timer_deadline_ns = machine.now().saturating_add(state.timer_interval_ns);
            state.timer_id
        }
        Api::WinStopTimer => {
            let hwnd = arg32(machine, regs, 1);
            let timer_id = arg32(machine, regs, 2);
            if state.timer_hwnd != hwnd || state.timer_id != timer_id {
                return 0;
            }
            state.timer_hwnd = 0;
            state.timer_id = 0;
            state.timer_interval_ns = 0;
            state.timer_deadline_ns = 0;
            1
        }
        Api::WinWindowFromId => {
            let parent = arg32(machine, regs, 0);
            let id = arg32(machine, regs, 1);
            state.pm_windows.iter().find(|window| window.id == id)
                .map_or(parent, |window| window.hwnd)
        }
        Api::WinQueryWindow => arg32(machine, regs, 0),
        Api::WinPtInRect => {
            let rect = arg32(machine, regs, 1) as usize;
            let point = arg32(machine, regs, 2) as usize;
            let x = machine.read::<i32>(point);
            let y = machine.read::<i32>(point + 4);
            (x >= machine.read::<i32>(rect) && x < machine.read::<i32>(rect + 8)
                && y >= machine.read::<i32>(rect + 4) && y < machine.read::<i32>(rect + 12)) as u32
        }
        Api::WinLoadString | Api::WinQueryDlgItemText => {
            let (length_arg, out_arg) = if api == Api::WinLoadString { (3, 4) } else { (2, 3) };
            let length = arg32(machine, regs, length_arg) as usize;
            let out = arg32(machine, regs, out_arg) as usize;
            if length != 0 { machine.write::<u8>(out, 0); }
            0
        }
        Api::WinMessageBox => 1,
        Api::WinSendDlgItemMsg | Api::WinSendMsg | Api::WinDefDlgProc | Api::WinDefWindowProc => 0,
        Api::WinDlgBox => 1,
        Api::WinDrawBitmap => draw_pm_bitmap(machine, state, regs),
        Api::GpiLoadBitmap => {
            load_pm_bitmap(state, arg32(machine, regs, 2) as u16)
        }
        Api::GpiMove | Api::GpiBox => 1,
        Api::PrfOpenProfile => 1,
        Api::PrfQueryProfileData => 0,
        Api::WinCreateHelpInstance => 1,
        Api::DosExit => unreachable!(),
    }
}

pub fn handle_event<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut Os2State,
    regs: &mut Regs,
    event: crate::KernelEvent,
) -> thread::KernelAction {
    match event {
        crate::KernelEvent::Irq => thread::KernelAction::Done,
        // PMWIN parks an empty WinGetMsg on HLT.  This is an input wait, not a
        // task-selection request: keep the PM window focused and wake it when
        // input or a timer message arrives.
        crate::KernelEvent::Hlt => {
            kt.state = thread::ThreadState::Blocked;
            thread::KernelAction::Done
        }
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let Some(gate) = gate_from_event(state, regs.frame.cs as u16, regs.ip32()) else {
                crate::println!("OS/2: invalid API gate at {:#x}", regs.ip32());
                return thread::KernelAction::Exit(-1);
            };
            match gate.api {
                Api::DosExit => {
                    let result = machine.read::<u32>(regs.sp() as usize + 8);
                    thread::KernelAction::Exit(result as i32)
                }
                Api::RetroWndProcReturn => {
                    let Some(callback) = state.callback.take() else {
                        crate::println!("OS/2: stray window-procedure return");
                        return thread::KernelAction::Exit(-1);
                    };
                    let result = regs.rax as u32;
                    regs.rax = result as u64;
                    regs.frame.rip = machine.read::<u32>(callback.dispatch_sp as usize) as u64;
                    regs.frame.rsp = callback.dispatch_sp.wrapping_add(4) as u64;
                    thread::KernelAction::Done
                }
                Api::WinDispatchMsg => {
                    let msg = arg32(machine, regs, 1) as usize;
                    let message = PmMessage {
                        hwnd: machine.read::<u32>(msg),
                        message: machine.read::<u32>(msg + 4),
                        mp1: machine.read::<u32>(msg + 8),
                        mp2: machine.read::<u32>(msg + 12),
                    };
                    if begin_wndproc(machine, regs, state, gate, message) {
                        thread::KernelAction::Done
                    } else {
                        finish_gate(machine, regs, gate, 0);
                        thread::KernelAction::Done
                    }
                }
                api => {
                    let result = dispatch_api(machine, kt, state, regs, api);
                    if api != Api::WinGetMsg || result != u32::MAX {
                        finish_gate(machine, regs, gate, result);
                    }
                    thread::KernelAction::Done
                }
            }
        }
        crate::KernelEvent::PageFault { .. } => unreachable!("page faults are handled by the event loop"),
        _ => {
            crate::println!("OS/2: unhandled event {:?} at {:#x}", event, regs.ip32());
            let mut code = [0u8; 16];
            machine.copy_from(regs.ip32() as usize, &mut code);
            let mut stack = [0u32; 8];
            for (i, word) in stack.iter_mut().enumerate() {
                *word = machine.read::<u32>(regs.sp() as usize + i * 4);
            }
            crate::println!("OS/2: code={:02x?} sp={:#x} stack={:08x?}", code, regs.sp(), stack);
            let _ = ERROR_INVALID_FUNCTION;
            thread::KernelAction::Exit(-1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pm_timer_wakes_an_idle_queue_without_bursting() {
        let mut state = Os2State::new();
        state.timer_hwnd = 7;
        state.timer_id = 3;
        state.timer_interval_ns = 10;
        state.timer_deadline_ns = 100;

        state.advance_timers(99);
        assert!(!state.has_pending_message());
        state.advance_timers(100);
        assert_eq!(state.pm_messages.len(), 1);
        assert_eq!(state.timer_deadline_ns, 110);
        state.advance_timers(200);
        assert_eq!(state.pm_messages.len(), 1);

        state.pm_messages.clear();
        state.advance_timers(200);
        assert_eq!(state.pm_messages.len(), 1);
        assert_eq!(state.timer_deadline_ns, 210);
    }

    #[test]
    fn gate_is_identified_by_selector_and_return_ip() {
        let mut state = Os2State::new();
        state.gates.push(Gate { cs: arch_abi::USER_CS, return_ip: 0x1002, api: Api::DosExit, far16_args: 0 });
        assert_eq!(gate_from_event(&state, arch_abi::USER_CS, 0x1002).map(|g| g.api), Some(Api::DosExit));
        assert!(gate_from_event(&state, arch_abi::USER_DS, 0x1002).is_none());
        assert!(gate_from_event(&state, arch_abi::USER_CS, 0x1003).is_none());
    }
}
