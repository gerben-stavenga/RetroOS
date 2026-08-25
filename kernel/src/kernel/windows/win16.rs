//! Built-in Win16 ABI hosted by the native Windows personality.
//!
//! Imported NE entry points are rebound to two-byte `INT 83h` stubs in a
//! synthetic 16-bit code segment.  This mirrors the replacement-PE DLL path,
//! while keeping the historical segmented ABI out of the compositor.

extern crate alloc;

use alloc::{vec, vec::Vec};

use crate::Regs;
use crate::kernel::thread;

use super::{ne, WindowsState, GATE_VECTOR};

const SEGMENT_BASE: u32 = 0x0100_0000;
const SEGMENT_STRIDE: u32 = 0x0001_0000;
const MODULE_BASE: u32 = 0x0200_0000;
const MODULE_STRIDE: u32 = 0x0010_0000;
const PSP_BASE: u32 = 0x0300_0000;
const ENV_BASE: u32 = 0x0301_0000;
const RESOURCE_BASE: u32 = 0x0302_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Module {
    Kernel,
    Gdi,
    User,
    Sound,
    Shell,
    Keyboard,
}

#[derive(Clone, Copy)]
struct Gate {
    module: Module,
    ordinal: u16,
    selector: u16,
    offset: u16,
    arg_bytes: u16,
    long_result: bool,
    name: &'static str,
}

#[derive(Clone, Copy)]
struct Callback {
    dispatch_gate: Gate,
    result: CallbackResult,
}

#[derive(Clone, Copy)]
enum CallbackResult {
    WndProc,
    CreateWindow { hwnd: u32 },
    DialogInit { hwnd: u32, auto_ok: bool },
    DialogCommand { hwnd: u32 },
}

struct Resource {
    handle: u16,
    offset: u16,
}

pub(super) struct State {
    image: Vec<u8>,
    gates: Vec<Gate>,
    callbacks: Vec<Callback>,
    callback_gate: Gate,
    instance: u16,
    auto_data: u16,
    local_next: u16,
    local_end: u16,
    local_allocations: Vec<(u16, u16)>,
    psp_selector: u16,
    env_selector: u16,
    timer: u16,
    resource_selector: u16,
    resource_next: u16,
    resources: Vec<Resource>,
}

fn module(name: &[u8]) -> Option<Module> {
    if name.eq_ignore_ascii_case(b"KERNEL") { Some(Module::Kernel) }
    else if name.eq_ignore_ascii_case(b"GDI") { Some(Module::Gdi) }
    else if name.eq_ignore_ascii_case(b"USER") { Some(Module::User) }
    else if name.eq_ignore_ascii_case(b"SOUND") { Some(Module::Sound) }
    else if name.eq_ignore_ascii_case(b"SHELL") { Some(Module::Shell) }
    else if name.eq_ignore_ascii_case(b"KEYBOARD") { Some(Module::Keyboard) }
    else { None }
}

/// `(stack bytes, returns DX:AX, diagnostic name)` for the imports used by
/// Windows 3.1 WINMINE.  Pascal callees remove their arguments; register and
/// varargs entries have no fixed stack cleanup.
fn spec(module: Module, ordinal: u16) -> Option<(u16, bool, &'static str)> {
    let s = match (module, ordinal) {
        (Module::Kernel, 1) => (2, false, "FatalExit"),
        (Module::Kernel, 3) => (0, true, "GetVersion"),
        (Module::Kernel, 4) => (6, false, "LocalInit"),
        (Module::Kernel, 5) => (4, false, "LocalAlloc"),
        (Module::Kernel, 6) => (6, false, "LocalReAlloc"),
        (Module::Kernel, 7) => (2, false, "LocalFree"),
        (Module::Kernel, 8) => (2, true, "LocalLock"),
        (Module::Kernel, 9) => (2, false, "LocalUnlock"),
        (Module::Kernel, 10) => (2, false, "LocalSize"),
        (Module::Kernel, 15) => (6, false, "GlobalAlloc"),
        (Module::Kernel, 16) => (8, false, "GlobalReAlloc"),
        (Module::Kernel, 17) => (2, false, "GlobalFree"),
        (Module::Kernel, 18) => (2, true, "GlobalLock"),
        (Module::Kernel, 19) => (2, false, "GlobalUnlock"),
        (Module::Kernel, 20) => (2, true, "GlobalSize"),
        (Module::Kernel, 23) => (2, false, "LockSegment"),
        (Module::Kernel, 24) => (2, false, "UnlockSegment"),
        (Module::Kernel, 25) => (4, true, "GlobalCompact"),
        (Module::Kernel, 30) => (2, false, "WaitEvent"),
        (Module::Kernel, 47) => (4, true, "GetModuleHandle"),
        (Module::Kernel, 48) => (2, false, "GetModuleUsage"),
        (Module::Kernel, 49) => (8, false, "GetModuleFileName"),
        (Module::Kernel, 50) => (6, true, "GetProcAddress"),
        (Module::Kernel, 51) => (6, true, "MakeProcInstance"),
        (Module::Kernel, 52) => (4, false, "FreeProcInstance"),
        (Module::Kernel, 58) => (18, false, "GetProfileString"),
        (Module::Kernel, 60) => (10, false, "FindResource"),
        (Module::Kernel, 61) => (4, false, "LoadResource"),
        (Module::Kernel, 62) => (2, true, "LockResource"),
        (Module::Kernel, 63) => (2, false, "FreeResource"),
        (Module::Kernel, 74) => (10, false, "OpenFile"),
        (Module::Kernel, 81) => (2, false, "_lclose"),
        (Module::Kernel, 88) => (8, true, "lstrcpy"),
        (Module::Kernel, 89) => (8, true, "lstrcat"),
        (Module::Kernel, 90) => (4, false, "lstrlen"),
        (Module::Kernel, 91) => (0, false, "InitTask"),
        (Module::Kernel, 95) => (4, false, "LoadLibrary"),
        (Module::Kernel, 96) => (2, false, "FreeLibrary"),
        (Module::Kernel, 97) => (12, false, "GetTempFileName"),
        (Module::Kernel, 102) => (0, false, "DOS3Call"),
        (Module::Kernel, 107) => (2, false, "SetErrorMode"),
        (Module::Kernel, 115) => (4, false, "OutputDebugString"),
        (Module::Kernel, 121) => (4, false, "LocalShrink"),
        (Module::Kernel, 127) => (14, false, "GetPrivateProfileInt"),
        (Module::Kernel, 128) => (22, false, "GetPrivateProfileString"),
        (Module::Kernel, 129) => (16, false, "WritePrivateProfileString"),
        (Module::Kernel, 131) => (0, true, "GetDOSEnvironment"),
        (Module::Kernel, 132) => (0, true, "GetWinFlags"),
        (Module::Kernel, 135) => (6, false, "GetSystemDirectory"),
        (Module::Kernel, 136) => (2, false, "GetDriveType"),
        (Module::Kernel, 137) => (6, false, "FatalAppExit"),
        (Module::Kernel, 207) => (2, false, "IsDBCSLeadByte"),

        (Module::Gdi, 1) => (6, true, "SetBkColor"),
        (Module::Gdi, 2) => (4, false, "SetBkMode"),
        (Module::Gdi, 3) => (4, false, "SetMapMode"),
        (Module::Gdi, 4) => (4, false, "SetROP2"),
        (Module::Gdi, 7) => (4, false, "SetStretchBltMode"),
        (Module::Gdi, 9) => (6, true, "SetTextColor"),
        (Module::Gdi, 11) => (6, true, "SetWindowOrg"),
        (Module::Gdi, 12) => (6, true, "SetWindowExt"),
        (Module::Gdi, 13) => (6, true, "SetViewportOrg"),
        (Module::Gdi, 14) => (6, true, "SetViewportExt"),
        (Module::Gdi, 19) => (6, false, "LineTo"),
        (Module::Gdi, 20) => (6, true, "MoveTo"),
        (Module::Gdi, 23) => (18, false, "Arc"),
        (Module::Gdi, 27) => (10, false, "Rectangle"),
        (Module::Gdi, 29) => (14, false, "PatBlt"),
        (Module::Gdi, 31) => (10, true, "SetPixel"),
        (Module::Gdi, 33) => (12, false, "TextOut"),
        (Module::Gdi, 34) => (20, false, "BitBlt"),
        (Module::Gdi, 35) => (24, false, "StretchBlt"),
        (Module::Gdi, 36) => (8, false, "Polygon"),
        (Module::Gdi, 38) => (14, true, "Escape"),
        (Module::Gdi, 44) => (4, false, "SelectClipRgn"),
        (Module::Gdi, 45) => (4, false, "SelectObject"),
        (Module::Gdi, 51) => (6, false, "CreateCompatibleBitmap"),
        (Module::Gdi, 52) => (2, false, "CreateCompatibleDC"),
        (Module::Gdi, 53) => (16, false, "CreateDC"),
        (Module::Gdi, 54) => (8, false, "CreateEllipticRgn"),
        (Module::Gdi, 57) => (4, false, "CreateFontIndirect"),
        (Module::Gdi, 60) => (2, false, "CreatePatternBrush"),
        (Module::Gdi, 61) => (8, false, "CreatePen"),
        (Module::Gdi, 66) => (4, false, "CreateSolidBrush"),
        (Module::Gdi, 67) => (8, false, "DPtoLP"),
        (Module::Gdi, 68) => (2, false, "DeleteDC"),
        (Module::Gdi, 69) => (2, false, "DeleteObject"),
        (Module::Gdi, 74) => (10, true, "GetBitmapBits"),
        (Module::Gdi, 80) => (4, false, "GetDeviceCaps"),
        (Module::Gdi, 81) => (2, false, "GetMapMode"),
        (Module::Gdi, 82) => (8, false, "GetObject"),
        (Module::Gdi, 83) => (6, true, "GetPixel"),
        (Module::Gdi, 87) => (2, false, "GetStockObject"),
        (Module::Gdi, 91) => (8, true, "GetTextExtent"),
        (Module::Gdi, 93) => (6, false, "GetTextMetrics"),
        (Module::Gdi, 94) => (2, true, "GetViewportExt"),
        (Module::Gdi, 96) => (2, true, "GetWindowExt"),
        (Module::Gdi, 99) => (8, false, "LPtoDP"),
        (Module::Gdi, 123) => (4, false, "PlayMetaFile"),
        (Module::Gdi, 127) => (2, false, "DeleteMetaFile"),
        (Module::Gdi, 128) => (6, false, "MulDiv"),
        (Module::Gdi, 148) => (6, true, "SetBrushOrg"),
        (Module::Gdi, 150) => (2, false, "UnrealizeObject"),
        (Module::Gdi, 153) => (16, false, "CreateIC"),
        (Module::Gdi, 154) => (6, true, "GetNearestColor"),
        (Module::Gdi, 156) => (6, false, "CreateDiscardableBitmap"),
        (Module::Gdi, 160) => (2, false, "SetMetaFileBits"),
        (Module::Gdi, 351) => (22, false, "ExtTextOut"),
        (Module::Gdi, 360) => (4, false, "CreatePalette"),
        (Module::Gdi, 367) => (10, false, "AnimatePalette"),
        (Module::Gdi, 442) => (20, false, "CreateDIBitmap"),
        (Module::Gdi, 443) => (30, false, "SetDIBitsToDevice"),

        (Module::User, 1) => (12, false, "MessageBox"),
        (Module::User, 5) => (2, false, "InitApp"),
        (Module::User, 6) => (2, false, "PostQuitMessage"),
        (Module::User, 10) => (10, false, "SetTimer"),
        (Module::User, 12) => (4, false, "KillTimer"),
        (Module::User, 15) => (0, true, "GetCurrentTime"),
        (Module::User, 18) => (2, false, "SetCapture"),
        (Module::User, 19) => (0, false, "ReleaseCapture"),
        (Module::User, 28) => (6, false, "ClientToScreen"),
        (Module::User, 31) => (2, false, "IsIconic"),
        (Module::User, 39) => (6, false, "BeginPaint"),
        (Module::User, 40) => (6, false, "EndPaint"),
        (Module::User, 41) => (30, false, "CreateWindow"),
        (Module::User, 42) => (4, false, "ShowWindow"),
        (Module::User, 45) => (2, false, "BringWindowToTop"),
        (Module::User, 50) => (8, false, "FindWindow"),
        (Module::User, 53) => (2, false, "DestroyWindow"),
        (Module::User, 56) => (12, false, "MoveWindow"),
        (Module::User, 57) => (4, false, "RegisterClass"),
        (Module::User, 66) => (2, false, "GetDC"),
        (Module::User, 68) => (4, false, "ReleaseDC"),
        (Module::User, 72) => (12, false, "SetRect"),
        (Module::User, 76) => (8, false, "PtInRect"),
        (Module::User, 87) => (12, false, "DialogBox"),
        (Module::User, 88) => (4, false, "EndDialog"),
        (Module::User, 92) => (8, false, "SetDlgItemText"),
        (Module::User, 93) => (10, false, "GetDlgItemText"),
        (Module::User, 94) => (8, false, "SetDlgItemInt"),
        (Module::User, 95) => (10, false, "GetDlgItemInt"),
        (Module::User, 107) => (10, true, "DefWindowProc"),
        (Module::User, 108) => (10, false, "GetMessage"),
        (Module::User, 109) => (12, false, "PeekMessage"),
        (Module::User, 110) => (10, false, "PostMessage"),
        (Module::User, 111) => (10, true, "SendMessage"),
        (Module::User, 113) => (4, false, "TranslateMessage"),
        (Module::User, 114) => (4, true, "DispatchMessage"),
        (Module::User, 124) => (2, false, "UpdateWindow"),
        (Module::User, 125) => (8, false, "InvalidateRect"),
        (Module::User, 150) => (6, false, "LoadMenu"),
        (Module::User, 154) => (6, false, "CheckMenuItem"),
        (Module::User, 155) => (6, false, "EnableMenuItem"),
        (Module::User, 158) => (4, false, "SetMenu"),
        (Module::User, 171) => (12, false, "WinHelp"),
        (Module::User, 173) => (6, false, "LoadCursor"),
        (Module::User, 174) => (6, false, "LoadIcon"),
        (Module::User, 176) => (10, false, "LoadString"),
        (Module::User, 177) => (6, false, "LoadAccelerators"),
        (Module::User, 178) => (8, false, "TranslateAccelerator"),
        (Module::User, 179) => (2, false, "GetSystemMetrics"),
        (Module::User, 286) => (0, false, "GetDesktopWindow"),
        (Module::User, 287) => (2, false, "GetLastActivePopup"),
        (Module::User, 420) => (0, false, "wsprintf"),

        (Module::User, 16) => (4, false, "ClipCursor"),
        (Module::User, 17) => (4, false, "GetCursorPos"),
        (Module::User, 22) => (2, false, "SetFocus"),
        (Module::User, 23) => (0, false, "GetFocus"),
        (Module::User, 24) => (6, false, "RemoveProp"),
        (Module::User, 25) => (6, false, "GetProp"),
        (Module::User, 26) => (8, false, "SetProp"),
        (Module::User, 29) => (6, false, "ScreenToClient"),
        (Module::User, 32) => (6, false, "GetWindowRect"),
        (Module::User, 33) => (6, false, "GetClientRect"),
        (Module::User, 34) => (4, false, "EnableWindow"),
        (Module::User, 35) => (2, false, "IsWindowEnabled"),
        (Module::User, 36) => (8, false, "GetWindowText"),
        (Module::User, 37) => (6, false, "SetWindowText"),
        (Module::User, 46) => (2, false, "GetParent"),
        (Module::User, 47) => (2, false, "IsWindow"),
        (Module::User, 60) => (0, false, "GetActiveWindow"),
        (Module::User, 61) => (14, false, "ScrollWindow"),
        (Module::User, 62) => (8, false, "SetScrollPos"),
        (Module::User, 64) => (10, false, "SetScrollRange"),
        (Module::User, 69) => (2, false, "SetCursor"),
        (Module::User, 70) => (4, false, "SetCursorPos"),
        (Module::User, 71) => (2, false, "ShowCursor"),
        (Module::User, 74) => (8, false, "CopyRect"),
        (Module::User, 77) => (8, false, "OffsetRect"),
        (Module::User, 78) => (8, false, "InflateRect"),
        (Module::User, 79) => (12, false, "IntersectRect"),
        (Module::User, 81) => (8, false, "FillRect"),
        (Module::User, 83) => (8, false, "FrameRect"),
        (Module::User, 84) => (8, false, "DrawIcon"),
        (Module::User, 85) => (14, false, "DrawText"),
        (Module::User, 91) => (4, false, "GetDlgItem"),
        (Module::User, 96) => (8, false, "CheckRadioButton"),
        (Module::User, 97) => (6, false, "CheckDlgButton"),
        (Module::User, 98) => (4, false, "IsDlgButtonChecked"),
        (Module::User, 100) => (12, false, "DlgDirList"),
        (Module::User, 101) => (12, true, "SendDlgItemMessage"),
        (Module::User, 104) => (2, false, "MessageBeep"),
        (Module::User, 106) => (2, false, "GetKeyState"),
        (Module::User, 118) => (4, false, "RegisterWindowMessage"),
        (Module::User, 122) => (14, true, "CallWindowProc"),
        (Module::User, 127) => (6, false, "ValidateRect"),
        (Module::User, 131) => (4, true, "GetClassLong"),
        (Module::User, 133) => (4, false, "GetWindowWord"),
        (Module::User, 134) => (6, false, "SetWindowWord"),
        (Module::User, 135) => (4, true, "GetWindowLong"),
        (Module::User, 136) => (8, true, "SetWindowLong"),
        (Module::User, 151) => (0, false, "CreateMenu"),
        (Module::User, 152) => (2, false, "DestroyMenu"),
        (Module::User, 153) => (12, false, "ChangeMenu"),
        (Module::User, 156) => (4, false, "GetSystemMenu"),
        (Module::User, 157) => (2, false, "GetMenu"),
        (Module::User, 159) => (4, false, "GetSubMenu"),
        (Module::User, 160) => (2, false, "DrawMenuBar"),
        (Module::User, 175) => (6, false, "LoadBitmap"),
        (Module::User, 180) => (2, true, "GetSysColor"),
        (Module::User, 185) => (22, false, "GrayString"),
        (Module::User, 189) => (0, false, "GetSysModalWindow"),
        (Module::User, 191) => (6, false, "ChildWindowFromPoint"),
        (Module::User, 196) => (20, true, "TabbedTextOut"),
        (Module::User, 229) => (2, false, "GetTopWindow"),
        (Module::User, 232) => (14, false, "SetWindowPos"),
        (Module::User, 236) => (0, false, "GetCapture"),
        (Module::User, 240) => (14, false, "DialogBoxIndirectParam"),
        (Module::User, 242) => (16, false, "CreateDialogIndirectParam"),
        (Module::User, 244) => (8, false, "EqualRect"),
        (Module::User, 249) => (2, false, "GetAsyncKeyState"),
        (Module::User, 277) => (2, false, "GetDlgCtrlID"),
        (Module::User, 282) => (6, false, "SelectPalette"),
        (Module::User, 283) => (2, false, "RealizePalette"),
        (Module::User, 407) => (18, false, "CreateIcon"),
        (Module::User, 410) => (12, false, "InsertMenu"),
        (Module::User, 411) => (10, false, "AppendMenu"),
        (Module::User, 412) => (6, false, "RemoveMenu"),
        (Module::User, 413) => (6, false, "DeleteMenu"),
        (Module::User, 414) => (12, false, "ModifyMenu"),
        (Module::User, 430) => (8, false, "lstrcmp"),
        (Module::User, 431) => (4, true, "AnsiUpper"),
        (Module::User, 432) => (4, true, "AnsiLower"),
        (Module::User, 457) => (2, false, "DestroyIcon"),
        (Module::User, 466) => (6, false, "DrawFocusRect"),
        (Module::User, 471) => (8, false, "lstrcmpi"),
        (Module::User, 472) => (4, true, "AnsiNext"),
        (Module::User, 512) => (12, false, "WNetGetConnection"),

        (Module::Sound, 1) => (0, false, "OpenSound"),
        (Module::Sound, 2) => (0, false, "CloseSound"),
        (Module::Sound, 4) => (8, false, "SetVoiceNote"),
        (Module::Sound, 5) => (10, false, "SetVoiceAccent"),
        (Module::Sound, 9) => (0, false, "StartSound"),
        (Module::Sound, 10) => (0, false, "StopSound"),
        (Module::Shell, 22) => (12, false, "ShellAbout"),
        (Module::Keyboard, 5) => (8, false, "AnsiToOem"),
        (Module::Keyboard, 6) => (8, false, "OemToAnsi"),
        _ => return None,
    };
    Some(s)
}

fn descriptor(base: u32, limit: u32, code: bool) -> u64 {
    let mut d = (limit & 0xffff) as u64;
    d |= ((base & 0xffff) as u64) << 16;
    d |= (((base >> 16) & 0xff) as u64) << 32;
    d |= (if code { 0xfau64 } else { 0xf2u64 }) << 40;
    d |= (((limit >> 16) & 0x0f) as u64) << 48;
    d | (((base >> 24) & 0xff) as u64) << 56
}

fn selector(ldt: &mut Vec<u64>, base: u32, size: usize, code: bool) -> Result<u16, i32> {
    if size == 0 || size > 0x10000 || ldt.len() >= 8192 { return Err(-8); }
    let sel = ((ldt.len() as u16) << 3) | 7;
    ldt.push(descriptor(base, size as u32 - 1, code));
    Ok(sel)
}

fn selector_base_from_ldt(ldt: &[u64], selector: u16) -> Option<u32> {
    let desc = *ldt.get((selector >> 3) as usize)?;
    Some((((desc >> 16) & 0xffff)
        | (((desc >> 32) & 0xff) << 16)
        | (((desc >> 56) & 0xff) << 24)) as u32)
}

fn segment_base(number: u16) -> Result<u32, i32> {
    if number == 0 { return Err(-8); }
    SEGMENT_BASE.checked_add((u32::from(number) - 1) * SEGMENT_STRIDE).ok_or(-8)
}

fn register_gate(
    gates: &mut Vec<Gate>,
    module: Module,
    ordinal: u16,
    selector: u16,
    offset: u16,
) -> Result<Gate, i32> {
    if let Some(gate) = gates.iter().find(|g| g.module == module && g.ordinal == ordinal) {
        return Ok(*gate);
    }
    let (arg_bytes, long_result, name) = spec(module, ordinal).ok_or_else(|| {
        crate::dbg_println!("[win16] unsupported import {:?}.{}", module, ordinal);
        -8
    })?;
    let gate = Gate { module, ordinal, selector, offset, arg_bytes, long_result, name };
    gates.push(gate);
    Ok(gate)
}

struct LoadedModule {
    name: Vec<u8>,
    kind: Option<Module>,
    data: Vec<u8>,
    selectors: Vec<u16>,
}

fn module_file(name: &[u8]) -> Vec<u8> {
    let mut file = name.to_vec();
    file.make_ascii_uppercase();
    if !file.ends_with(b".DLL") { file.extend_from_slice(b".DLL"); }
    file
}

fn join(dir: &[u8], file: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(dir.len() + file.len() + 1);
    path.extend_from_slice(dir);
    if !dir.is_empty() && dir.last() != Some(&b'/') { path.push(b'/'); }
    path.extend_from_slice(file);
    path
}

fn dirname(path: &[u8]) -> &[u8] {
    path.iter().rposition(|&b| b == b'/').map_or(b"", |at| &path[..at])
}

fn canonical_module_name(name: &[u8]) -> Vec<u8> {
    let mut canonical = name.to_vec();
    canonical.make_ascii_uppercase();
    if canonical.ends_with(b".DLL") { canonical.truncate(canonical.len() - 4); }
    canonical
}

fn load_module_file(name: &[u8], importer: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let file = module_file(name);
    let system = join(crate::kernel::dos::c_root(), b"WINDOWS/SYSTEM");
    for path in [join(dirname(importer), &file), join(&system, &file)] {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&path) {
            return Ok((path, data));
        }
        let rooted = [crate::kernel::dos::c_root(), path.as_slice()].concat();
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&rooted) {
            return Ok((rooted, data));
        }
    }
    Err(-2)
}

fn module_segment_base(module_index: usize, segment: u16) -> Result<u32, i32> {
    if segment == 0 { return Err(-8); }
    MODULE_BASE
        .checked_add(u32::try_from(module_index).map_err(|_| -8)? * MODULE_STRIDE)
        .and_then(|base| base.checked_add((u32::from(segment) - 1) * SEGMENT_STRIDE))
        .ok_or(-8)
}

fn patch_chain<A: crate::Arch>(
    machine: &mut A,
    base: u32,
    alloc_size: usize,
    relocation: &ne::Relocation,
    offset: u16,
    selector: u16,
) -> Result<(), i32> {
    let mut source = relocation.source_offset;
    let mut remaining = alloc_size / 2 + 1;
    loop {
        let at = base.checked_add(u32::from(source)).ok_or(-8)? as usize;
        if usize::from(source) >= alloc_size || remaining == 0 { return Err(-8); }
        remaining -= 1;
        let next = machine.read::<u16>(at);
        match relocation.source_type & 0x0f {
            2 => machine.write::<u16>(at, selector),
            3 => {
                if usize::from(source) + 4 > alloc_size { return Err(-8); }
                machine.write::<u16>(at, offset);
                machine.write::<u16>(at + 2, selector);
            }
            5 => machine.write::<u16>(at, offset),
            kind => {
                crate::dbg_println!("[win16] unsupported NE source relocation {}", kind);
                return Err(-8);
            }
        }
        if relocation.flags & 4 != 0 || next == 0xffff { break; }
        source = next;
    }
    Ok(())
}

fn imported_target<A: crate::Arch>(
    machine: &A,
    ldt: &[u64],
    modules: &[LoadedModule],
    gates: &mut Vec<Gate>,
    name: &[u8],
    ordinal: Option<u16>,
    symbol: Option<&[u8]>,
) -> Result<(u16, u16), i32> {
    let canonical = canonical_module_name(name);
    let kind = module(&canonical);
    if kind == Some(Module::Kernel) {
        match ordinal {
            Some(114) => return Ok((8, 0)),
            Some(178) => return Ok((0x0413, 0)),
            _ => {}
        }
    }
    let Some(loaded) = modules.iter().find(|loaded| loaded.name == canonical) else {
        crate::dbg_println!("[win16] module {} not loaded",
            core::str::from_utf8(&canonical).unwrap_or("?"));
        return Err(-2);
    };
    let image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
    let entry = match (ordinal, symbol) {
        (Some(ordinal), None) => image.entry(ordinal),
        (None, Some(symbol)) => image.entry_by_name(symbol),
        _ => return Err(-8),
    };
    let (segment, offset) = entry.map_err(|_| {
        let module = core::str::from_utf8(&canonical).unwrap_or("?");
        if let Some(ordinal) = ordinal {
            crate::dbg_println!("[win16] export {}.{} not found", module, ordinal);
        } else {
            crate::dbg_println!("[win16] export {}!{} not found", module,
                core::str::from_utf8(symbol.unwrap_or(b"?")).unwrap_or("?"));
        }
        -127
    })?;
    let selector = *loaded.selectors.get(segment.wrapping_sub(1) as usize).ok_or(-8)?;
    if let (Some(kind), Some(ordinal)) = (kind, ordinal) {
        let base = selector_base_from_ldt(ldt, selector).ok_or(-8)?;
        if machine.read::<u8>((base + u32::from(offset)) as usize) != 0xcd
            || machine.read::<u8>((base + u32::from(offset) + 1) as usize) != GATE_VECTOR
        {
            return Err(-8);
        }
        let gate = register_gate(gates, kind, ordinal, selector, offset)?;
        return Ok((gate.offset, gate.selector));
    }
    Ok((offset, selector))
}

fn relocate_image<A: crate::Arch>(
    machine: &mut A,
    image: &ne::Image<'_>,
    selectors: &[u16],
    modules: &[LoadedModule],
    ldt: &[u64],
    gates: &mut Vec<Gate>,
    mut segment_base: impl FnMut(u16) -> Result<u32, i32>,
) -> Result<(), i32> {
    for number in 1..=image.header.segment_count {
        let segment = image.segment(number).map_err(|_| -8)?;
        let base = segment_base(number)?;
        for relocation in image.relocations(segment).map_err(|_| -8)? {
            let (offset, target_selector) = match &relocation.target {
                ne::Target::Internal { segment, offset } => {
                    let selector = *selectors.get(segment.wrapping_sub(1) as usize).ok_or(-8)?;
                    (*offset, selector)
                }
                ne::Target::ImportOrdinal { module, ordinal } => imported_target(
                    machine, ldt, modules, gates, module, Some(*ordinal), None,
                )?,
                ne::Target::ImportName { module, name } => imported_target(
                    machine, ldt, modules, gates, module, None, Some(name),
                )?,
            };
            patch_chain(machine, base, segment.alloc_size, &relocation, offset, target_selector)?;
        }
    }
    Ok(())
}

pub(super) fn exec<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
) -> Result<(), i32> {
    let image = ne::Image::parse(&data).map_err(|_| -8)?;
    let header = image.header;
    let mut ldt = vec![0];
    let mut selectors = Vec::with_capacity(header.segment_count as usize);

    for number in 1..=header.segment_count {
        let segment = image.segment(number).map_err(|_| -8)?;
        let extra = if number == header.auto_data {
            usize::from(header.heap_size).saturating_add(usize::from(header.stack_size))
        } else { 0 };
        let size = segment.alloc_size.checked_add(extra).ok_or(-8)?.min(0x10000);
        if size < segment.alloc_size { return Err(-8); }
        let base = segment_base(number)?;
        machine.zero(base as usize, size);
        machine.copy_to(base as usize, image.segment_bytes(segment).map_err(|_| -8)?);
        selectors.push(selector(&mut ldt, base, size, segment.is_code())?);
    }

    let main_path = if launcher == Some(thread::PersonalityName::Dos) {
        crate::kernel::dos::dos_abs_to_vfs(path).unwrap_or_else(|| path.to_vec())
    } else {
        let mut b = [0u8; 164];
        crate::kernel::exec::resolve_path(path, parent_cwd, &mut b).to_vec()
    };
    // Build the complete dependency closure before applying any fixups. Real
    // Win16 libraries (for example an application's COMMDLG.DLL) contain code
    // and imports of their own; replacement system DLLs are merely leaves in
    // this same graph.
    let mut pending: Vec<(Vec<u8>, Vec<u8>)> = image.modules().map_err(|_| -8)?
        .into_iter().map(|name| (name, main_path.clone())).collect();
    let mut modules = Vec::new();
    let mut next = 0;
    while next < pending.len() {
        let (name, importer) = pending[next].clone();
        next += 1;
        let canonical = canonical_module_name(&name);
        if modules.iter().any(|loaded: &LoadedModule| loaded.name == canonical) { continue; }
        let (module_path, module_data) = load_module_file(&canonical, &importer)?;
        let module_image = ne::Image::parse(&module_data).map_err(|_| -8)?;
        let mut module_selectors = Vec::with_capacity(module_image.header.segment_count as usize);
        let module_index = modules.len();
        for number in 1..=module_image.header.segment_count {
            let segment = module_image.segment(number).map_err(|_| -8)?;
            let base = module_segment_base(module_index, number)?;
            machine.zero(base as usize, segment.alloc_size);
            machine.copy_to(base as usize,
                module_image.segment_bytes(segment).map_err(|_| -8)?);
            module_selectors.push(selector(
                &mut ldt, base, segment.alloc_size, segment.is_code())?);
        }
        let dependencies = module_image.modules().map_err(|_| -8)?;
        modules.push(LoadedModule {
            name: canonical.clone(),
            kind: module(&canonical),
            data: module_data,
            selectors: module_selectors,
        });
        pending.extend(dependencies.into_iter().map(|dependency| {
            (dependency, module_path.clone())
        }));
    }

    machine.zero(PSP_BASE as usize, 4096);
    machine.zero(ENV_BASE as usize, 4096);
    let psp_selector = selector(&mut ldt, PSP_BASE, 256, false)?;
    let env_selector = selector(&mut ldt, ENV_BASE, 4096, false)?;
    let resource_selector = selector(&mut ldt, RESOURCE_BASE, 0x10000, false)?;
    machine.write::<u16>((PSP_BASE + 0x2c) as usize, env_selector);
    machine.zero(RESOURCE_BASE as usize, 0x10000);
    let mut gates = Vec::new();

    relocate_image(
        machine, &image, &selectors, &modules, &ldt, &mut gates, segment_base,
    )?;
    for (module_index, loaded) in modules.iter().enumerate() {
        let module_image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
        relocate_image(
            machine, &module_image, &loaded.selectors, &modules, &ldt, &mut gates,
            |number| module_segment_base(module_index, number),
        )?;
    }
    let user = modules.iter().find(|loaded| loaded.kind == Some(Module::User)).ok_or(-2)?;
    let user_image = ne::Image::parse(&user.data).map_err(|_| -8)?;
    let (callback_segment, callback_offset) = user_image.entry(421).map_err(|_| -127)?;
    let callback_selector = *user.selectors
        .get(callback_segment.wrapping_sub(1) as usize).ok_or(-8)?;
    let callback_gate = Gate {
        module: Module::User,
        ordinal: 0xffff,
        selector: callback_selector,
        offset: callback_offset,
        arg_bytes: 0,
        long_result: true,
        name: "WndProcReturn",
    };
    gates.push(callback_gate);

    for number in 1..=header.segment_count {
        let segment = image.segment(number).map_err(|_| -8)?;
        let extra = if number == header.auto_data {
            usize::from(header.heap_size).saturating_add(usize::from(header.stack_size))
        } else { 0 };
        let size = segment.alloc_size.saturating_add(extra).min(0x10000);
        machine.set_page_flags(
            segment_base(number)? as usize / 4096,
            size.div_ceil(4096),
            !segment.is_code(),
            segment.is_code(),
        );
    }
    for (module_index, loaded) in modules.iter().enumerate() {
        let module_image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
        for number in 1..=module_image.header.segment_count {
            let segment = module_image.segment(number).map_err(|_| -8)?;
            machine.set_page_flags(
                module_segment_base(module_index, number)? as usize / 4096,
                segment.alloc_size.div_ceil(4096),
                !segment.is_code(),
                segment.is_code(),
            );
        }
    }
    machine.set_page_flags(PSP_BASE as usize / 4096, 1, true, false);
    machine.set_page_flags(ENV_BASE as usize / 4096, 1, true, false);
    machine.set_page_flags(RESOURCE_BASE as usize / 4096, 16, true, false);

    let current = thread::get_thread(threads, tid).ok_or(-8)?;
    let mut windows = WindowsState::new();
    windows.next_object = 0x0100;
    windows.paint_dc = 0x0200;
    windows.dcs.push(super::DeviceContext {
        handle: windows.paint_dc,
        bitmap: None,
        x: 0,
        y: 0,
        pen: 0,
        brush: 0,
        font: 1,
        bk: 0x00ff_ffff,
        text: 0,
    });
    windows.ldt = ldt;
    windows.exec_path_len = main_path.len().min(windows.exec_path.len());
    windows.exec_path[..windows.exec_path_len]
        .copy_from_slice(&main_path[..windows.exec_path_len]);
    let cwd = super::dirname(&main_path);
    windows.cwd_len = cwd.len().min(windows.cwd.len());
    windows.cwd[..windows.cwd_len].copy_from_slice(&cwd[..windows.cwd_len]);

    let auto_segment = image.segment(header.auto_data).map_err(|_| -8)?;
    let local_next = u16::try_from(auto_segment.alloc_size).map_err(|_| -8)?;
    let local_end = usize::from(local_next)
        .checked_add(usize::from(header.heap_size)).ok_or(-8)?.min(0xffff) as u16;
    let stack_selector = *selectors.get(header.stack_segment.wrapping_sub(1) as usize).ok_or(-8)?;
    let stack_segment = image.segment(header.stack_segment).map_err(|_| -8)?;
    let default_sp = stack_segment.alloc_size
        .checked_add(if header.stack_segment == header.auto_data {
            usize::from(header.heap_size).saturating_add(usize::from(header.stack_size))
        } else { usize::from(header.stack_size) }).ok_or(-8)?.min(0xfffe) as u16;
    let sp = if header.stack_offset == 0 { default_sp } else { header.stack_offset };
    let data_selector = *selectors.get(header.auto_data.wrapping_sub(1) as usize).ok_or(-8)?;
    let code_selector = *selectors.get(header.entry_segment.wrapping_sub(1) as usize).ok_or(-8)?;

    current.kernel.vcpu.regs.init_user_process(0, 0);
    let regs = &mut current.kernel.vcpu.regs;
    regs.frame.rip = u64::from(header.entry_offset);
    regs.frame.cs = u64::from(code_selector);
    regs.frame.rsp = u64::from(sp);
    regs.frame.ss = u64::from(stack_selector);
    regs.ds = u64::from(data_selector);
    regs.es = u64::from(data_selector);
    regs.fs = 0;
    regs.gs = 0;
    // Win16 startup contract: AX=zero, BX=stack size, CX=heap size,
    // DI=instance handle, SI=previous instance (zero for first instance).
    regs.rax = 0;
    regs.rbx = u64::from(header.stack_size);
    regs.rcx = u64::from(header.heap_size);
    regs.rdi = u64::from(data_selector);
    regs.rsi = 0;

    windows.win16 = Some(State {
        image: data,
        gates,
        callbacks: Vec::new(),
        callback_gate,
        instance: data_selector,
        auto_data: data_selector,
        local_next,
        local_end,
        local_allocations: Vec::new(),
        psp_selector,
        env_selector,
        timer: 0,
        resource_selector,
        resource_next: 0,
        resources: Vec::new(),
    });
    windows.on_resume(machine);
    current.personality = thread::Personality::Windows(windows);
    Ok(())
}

fn selector_base(state: &WindowsState, selector: u16) -> Option<u32> {
    selector_base_from_ldt(&state.ldt, selector)
}

fn linear(state: &WindowsState, selector: u16, offset: u16) -> Option<usize> {
    selector_base(state, selector)?.checked_add(u32::from(offset)).map(|v| v as usize)
}

fn stack_at(state: &WindowsState, regs: &Regs, displacement: u16) -> Option<usize> {
    linear(state, regs.stack_seg(), (regs.sp32() as u16).wrapping_add(displacement))
}

fn stack_u16<A: crate::Arch>(
    machine: &A, state: &WindowsState, regs: &Regs, displacement: u16,
) -> Option<u16> {
    Some(machine.read::<u16>(stack_at(state, regs, displacement)?))
}

fn stack_u32<A: crate::Arch>(
    machine: &A, state: &WindowsState, regs: &Regs, displacement: u16,
) -> Option<u32> {
    Some(machine.read::<u32>(stack_at(state, regs, displacement)?))
}

fn far_linear(state: &WindowsState, pointer: u32) -> Option<usize> {
    let offset = pointer as u16;
    let selector = (pointer >> 16) as u16;
    if selector == 0 { None } else { linear(state, selector, offset) }
}

fn far_string<A: crate::Arch>(
    machine: &A, state: &WindowsState, pointer: u32,
) -> Option<Vec<u8>> {
    if pointer >> 16 == 0 { return None; }
    let address = far_linear(state, pointer)?;
    let mut out = Vec::new();
    for n in 0..0x10000usize.saturating_sub(pointer as u16 as usize) {
        let byte = machine.read::<u8>(address + n);
        if byte == 0 { return Some(out); }
        out.push(byte);
    }
    None
}

fn dos_path(path: &[u8]) -> Vec<u8> {
    let root = crate::kernel::dos::c_root();
    let relative = path.strip_prefix(root).unwrap_or(path);
    let relative = relative.strip_prefix(b"/").unwrap_or(relative);
    let mut result = Vec::with_capacity(relative.len() + 3);
    result.extend_from_slice(b"C:\\");
    result.extend(relative.iter().map(|&byte| if byte == b'/' { b'\\' } else { byte }));
    result
}

fn write_message16<A: crate::Arch>(machine: &mut A, out: usize, message: super::Message) {
    machine.write::<u16>(out, message.hwnd as u16);
    machine.write::<u16>(out + 2, message.message as u16);
    machine.write::<u16>(out + 4, message.wparam as u16);
    machine.write::<u32>(out + 6, message.lparam);
    machine.write::<u32>(out + 10, (machine.now() / 1_000_000) as u32);
    machine.write::<u16>(out + 14, 0);
    machine.write::<u16>(out + 16, 0);
}

fn message16<A: crate::Arch>(machine: &A, at: usize) -> super::Message {
    super::Message {
        hwnd: u32::from(machine.read::<u16>(at)),
        message: u32::from(machine.read::<u16>(at + 2)),
        wparam: u32::from(machine.read::<u16>(at + 4)),
        lparam: machine.read::<u32>(at + 6),
    }
}

fn begin_wndproc<A: crate::Arch>(
    machine: &mut A,
    windows: &WindowsState,
    state: &mut State,
    regs: &mut Regs,
    dispatch_gate: Gate,
    callback_result: CallbackResult,
    message: super::Message,
) -> bool {
    let Some(window) = windows.windows.iter().find(|window| window.hwnd == message.hwnd) else {
        return false;
    };
    if window.wndproc == 0 { return false; }
    let new_sp = (regs.sp32() as u16).wrapping_sub(14);
    let Some(stack) = linear(windows, regs.stack_seg(), new_sp) else { return false; };
    machine.write::<u16>(stack, state.callback_gate.offset);
    machine.write::<u16>(stack + 2, state.callback_gate.selector);
    machine.write::<u32>(stack + 4, message.lparam);
    machine.write::<u16>(stack + 8, message.wparam as u16);
    machine.write::<u16>(stack + 10, message.message as u16);
    machine.write::<u16>(stack + 12, message.hwnd as u16);
    state.callbacks.push(Callback { dispatch_gate, result: callback_result });
    regs.frame.rsp = u64::from(new_sp);
    regs.frame.rip = u64::from(window.wndproc as u16);
    regs.frame.cs = u64::from((window.wndproc >> 16) as u16);
    true
}

fn dib_header<A: crate::Arch>(machine: &A, header: usize) -> Option<(usize, usize, u16, usize)> {
    match machine.read::<u32>(header) {
        12 => {
            let width = machine.read::<u16>(header + 4) as usize;
            let height = machine.read::<u16>(header + 6) as usize;
            let bpp = machine.read::<u16>(header + 10);
            (width != 0 && height != 0).then_some((width, height, bpp, header + 12))
        }
        size if (40..=4096).contains(&size) => {
            let width = machine.read::<i32>(header + 4).unsigned_abs() as usize;
            let height = machine.read::<i32>(header + 8).unsigned_abs() as usize;
            let bpp = machine.read::<u16>(header + 14);
            (width != 0 && height != 0 && width <= 2048 && height <= 2048)
                .then_some((width, height, bpp, header + size as usize))
        }
        _ => None,
    }
}

fn decode_dib<A: crate::Arch>(
    machine: &A,
    bits: usize,
    palette: usize,
    width: usize,
    height: usize,
    bpp: u16,
    output: &mut [u8],
) {
    let row_bytes = (width.saturating_mul(bpp as usize).saturating_add(31) / 32) * 4;
    let core_palette = machine.read::<u32>(palette.saturating_sub(12)) == 12;
    let palette_stride = if core_palette { 3 } else { 4 };
    for y in 0..height {
        let source_row = bits + (height - 1 - y) * row_bytes;
        for x in 0..width {
            let color = match bpp {
                1 => {
                    let byte = machine.read::<u8>(source_row + x / 8);
                    let index = usize::from((byte >> (7 - x % 8)) & 1);
                    palette_color(machine, palette, palette_stride, index)
                }
                4 => {
                    let byte = machine.read::<u8>(source_row + x / 2);
                    let index = usize::from(if x & 1 == 0 { byte >> 4 } else { byte & 15 });
                    palette_color(machine, palette, palette_stride, index)
                }
                8 => {
                    let index = machine.read::<u8>(source_row + x) as usize;
                    palette_color(machine, palette, palette_stride, index)
                }
                24 => {
                    let at = source_row + x * 3;
                    let b = machine.read::<u8>(at) as u32;
                    let g = machine.read::<u8>(at + 1) as u32;
                    let r = machine.read::<u8>(at + 2) as u32;
                    b | (g << 8) | (r << 16)
                }
                32 => machine.read::<u32>(source_row + x * 4) & 0x00ff_ffff,
                _ => 0,
            };
            let at = (y * width + x) * 4;
            if let Some(pixel) = output.get_mut(at..at + 4) {
                pixel.copy_from_slice(&color.to_le_bytes());
            }
        }
    }
}

fn palette_color<A: crate::Arch>(
    machine: &A, palette: usize, stride: usize, index: usize,
) -> u32 {
    let at = palette + index * stride;
    let b = machine.read::<u8>(at) as u32;
    let g = machine.read::<u8>(at + 1) as u32;
    let r = machine.read::<u8>(at + 2) as u32;
    b | (g << 8) | (r << 16)
}

fn menu_word(data: &[u8], at: &mut usize) -> Option<u16> {
    let value = u16::from_le_bytes(data.get(*at..*at + 2)?.try_into().ok()?);
    *at += 2;
    Some(value)
}

fn menu_text(data: &[u8], at: &mut usize) -> Option<Vec<u8>> {
    let start = *at;
    let end = data.get(start..)?.iter().position(|&byte| byte == 0)? + start;
    *at = end + 1;
    Some(data[start..end].to_vec())
}

fn menu_items(data: &[u8], at: &mut usize) -> Option<Vec<super::MenuItem>> {
    let mut items = Vec::new();
    loop {
        let flags = menu_word(data, at)?;
        let popup = flags & 0x0010 != 0;
        let command = if popup { 0 } else { menu_word(data, at)? };
        let text = menu_text(data, at)?;
        let children = if popup { menu_items(data, at)? } else { Vec::new() };
        items.push(super::MenuItem { text, command, children });
        if flags & 0x0080 != 0 { return Some(items); }
    }
}

fn install_menu(windows: &mut WindowsState, handle: u32, data: &[u8]) {
    if handle == 0 || windows.menus.iter().any(|menu| menu.handle == handle) { return; }
    if data.len() < 4 { return; }
    let header = u16::from_le_bytes([data[2], data[3]]) as usize;
    let mut at = 4usize.saturating_add(header);
    if let Some(items) = menu_items(data, &mut at) {
        windows.menus.push(super::Menu { handle, items });
    }
}

fn ensure_menu(windows: &mut WindowsState, state: &State, handle: u32) {
    let Ok(image) = ne::Image::parse(&state.image) else { return };
    let Ok(data) = image.resource(4, handle as u16) else { return };
    install_menu(windows, handle, data);
}

fn dialog_byte(data: &[u8], at: &mut usize) -> Option<u8> {
    let value = *data.get(*at)?;
    *at += 1;
    Some(value)
}

fn dialog_i16(data: &[u8], at: &mut usize) -> Option<i16> {
    let value = i16::from_le_bytes(data.get(*at..*at + 2)?.try_into().ok()?);
    *at += 2;
    Some(value)
}

fn dialog_u32(data: &[u8], at: &mut usize) -> Option<u32> {
    let value = u32::from_le_bytes(data.get(*at..*at + 4)?.try_into().ok()?);
    *at += 4;
    Some(value)
}

fn dialog_string(data: &[u8], at: &mut usize) -> Option<Vec<u8>> {
    let first = dialog_byte(data, at)?;
    if first == 0 { return Some(Vec::new()); }
    if first & 0x80 != 0 { return Some(vec![first]); }
    let mut text = vec![first];
    loop {
        let byte = dialog_byte(data, at)?;
        if byte == 0 { return Some(text); }
        text.push(byte);
    }
}

fn create_dialog(
    windows: &mut WindowsState, state: &State, template: u16, proc: u32,
) -> Option<(u32, bool)> {
    let image = ne::Image::parse(&state.image).ok()?;
    let data = image.resource(5, template).ok()?;
    let mut at = 0;
    let _style = dialog_u32(data, &mut at)?;
    let count = dialog_byte(data, &mut at)?;
    let _x = dialog_i16(data, &mut at)?;
    let _y = dialog_i16(data, &mut at)?;
    let width = u32::from(dialog_i16(data, &mut at)?.max(80) as u16) * 2;
    let height = u32::from(dialog_i16(data, &mut at)?.max(40) as u16) * 2 + 20;
    let _menu = dialog_string(data, &mut at)?;
    let _class = dialog_string(data, &mut at)?;
    let title = dialog_string(data, &mut at)?;
    let hwnd = windows.next_object;
    windows.next_object = windows.next_object.wrapping_add(1);
    windows.windows.push(super::Window {
        hwnd, parent: 0, wndproc: proc, menu: 0, control_class: 0, text: title.clone(), x: 0, y: 0,
        width, height, visible: true,
        pixels: vec![0xc0; width as usize * height as usize * 4],
    });
    let root = windows.windows.len() - 1;
    super::menu_fill(&mut windows.windows[root], 0, 0, width as i32, 20, 0x0080_80c0);
    super::menu_text(&mut windows.windows[root], 6, 2, &title);
    let mut interactive = false;
    for _ in 0..count {
        let x = i32::from(dialog_i16(data, &mut at)?) * 2;
        let y = i32::from(dialog_i16(data, &mut at)?) * 2 + 20;
        let control_width = u32::from(dialog_i16(data, &mut at)?.max(1) as u16) * 2;
        let control_height = u32::from(dialog_i16(data, &mut at)?.max(1) as u16) * 2;
        let id = u32::from(dialog_i16(data, &mut at)? as u16);
        let _style = dialog_u32(data, &mut at)?;
        let class = dialog_string(data, &mut at)?;
        let text = dialog_string(data, &mut at)?;
        let extra = dialog_byte(data, &mut at)? as usize;
        at = at.checked_add(extra)?;
        let class_id = class.first().copied().unwrap_or(0);
        if matches!(class_id, 0x81 | 0x84) || (class_id == 0x80 && id != 1) {
            interactive = true;
        }
        if class_id == 0x80 || class_id == 0x81 {
            super::menu_fill(&mut windows.windows[root], x, y,
                x + control_width as i32, y + control_height as i32, 0x00ff_ffff);
        }
        if class_id == 0x84 {
            super::menu_fill(&mut windows.windows[root], x, y,
                x + control_width as i32, y + control_height as i32, 0x00ff_ffff);
            super::menu_text(&mut windows.windows[root], x + 1, y + 1, b"^");
            super::menu_text(&mut windows.windows[root], x + 1,
                y + control_height as i32 - 17, b"v");
        }
        let shown = if class_id == 0x81 && id == 151 { b"Player".as_slice() } else { &text };
        if !shown.is_empty() && shown.first() != Some(&b'#') {
            super::menu_text(&mut windows.windows[root], x + 3, y + 1, shown);
        }
        windows.windows.push(super::Window {
            hwnd: windows.next_object, parent: hwnd, wndproc: 0, menu: id,
            control_class: class_id, text: shown.to_vec(),
            x, y, width: control_width, height: control_height, visible: true,
            pixels: Vec::new(),
        });
        windows.next_object = windows.next_object.wrapping_add(1);
    }
    windows.dirty = true;
    Some((hwnd, !interactive))
}

fn finish<A: crate::Arch>(
    machine: &A,
    windows: &WindowsState,
    regs: &mut Regs,
    gate: Gate,
    result: u32,
) -> Result<(), ()> {
    let stack = stack_at(windows, regs, 0).ok_or(())?;
    let ip = machine.read::<u16>(stack);
    let cs = machine.read::<u16>(stack + 2);
    regs.rax = (regs.rax & !0xffff) | u64::from(result as u16);
    if gate.long_result {
        regs.rdx = (regs.rdx & !0xffff) | u64::from((result >> 16) as u16);
    }
    regs.frame.rip = u64::from(ip);
    regs.frame.cs = u64::from(cs);
    regs.frame.rsp = u64::from((regs.sp32() as u16).wrapping_add(4 + gate.arg_bytes));
    Ok(())
}

fn dispatch<A: crate::Arch>(
    machine: &mut A,
    _kt: &mut thread::KernelThread<A>,
    windows: &mut WindowsState,
    state: &mut State,
    regs: &mut Regs,
    gate: Gate,
) -> u32 {
    match (gate.module, gate.ordinal) {
        (Module::Kernel, 3) => 0x0000_0a03, // Windows 3.10
        (Module::Kernel, 4) => 1,
        (Module::Kernel, 91) => {
            // The Microsoft C startup consumes these register results before
            // it calls WinMain.
            regs.rax = u64::from(state.instance);
            regs.rbx = u64::from(state.local_end.wrapping_sub(state.local_next));
            regs.rcx = 0;
            regs.rdx = 1; // SW_SHOWNORMAL, passed by the C runtime to WinMain.
            regs.rsi = 0;
            regs.rdi = u64::from(state.instance);
            regs.ds = u64::from(state.auto_data);
            regs.es = u64::from(state.psp_selector);
            1
        }
        (Module::Kernel, 102) => {
            match (regs.rax as u16 >> 8) as u8 {
                0x25 => 0, // Set interrupt vector; Win16 owns the virtual vector.
                0x30 => {
                    regs.rax = (regs.rax & !0xffff) | 0x0005;
                    5
                }
                0x35 => {
                    regs.es = u64::from(state.psp_selector);
                    regs.rbx &= !0xffff;
                    regs.rax as u32
                }
                ah => {
                    crate::dbg_println!("[win16] DOS3Call AH={:02x} stub", ah);
                    regs.rax as u32
                }
            }
        }
        (Module::Kernel, 5) => {
            let size = stack_at(windows, regs, 4)
                .map(|p| machine.read::<u16>(p) as usize).unwrap_or(0);
            let aligned = (size.max(2) + 1) & !1;
            let next = usize::from(state.local_next).saturating_add(aligned);
            if next > usize::from(state.local_end) {
                crate::dbg_println!("[win16] LocalAlloc {} failed ({:04x}..{:04x})",
                    size, state.local_next, state.local_end);
                0
            } else {
                let handle = state.local_next;
                state.local_next = next as u16;
                state.local_allocations.push((handle, aligned as u16));
                u32::from(handle)
            }
        }
        (Module::Kernel, 6) => {
            let handle = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            let size = stack_u16(machine, windows, regs, 6).unwrap_or(0) as usize;
            let Some((_, old_size)) = state.local_allocations.iter()
                .find(|(allocated, _)| *allocated == handle).copied() else { return 0 };
            if size <= old_size as usize { return u32::from(handle); }
            let aligned = (size.max(2) + 1) & !1;
            let next = usize::from(state.local_next).saturating_add(aligned);
            if next > usize::from(state.local_end) { return 0; }
            let new_handle = state.local_next;
            let Some(source) = linear(windows, state.auto_data, handle) else { return 0 };
            let Some(destination) = linear(windows, state.auto_data, new_handle) else { return 0 };
            let mut bytes = vec![0; old_size as usize];
            machine.copy_from(source, &mut bytes);
            machine.copy_to(destination, &bytes);
            state.local_next = next as u16;
            state.local_allocations.push((new_handle, aligned as u16));
            u32::from(new_handle)
        }
        (Module::Kernel, 7) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            state.local_allocations.retain(|(allocated, _)| *allocated != handle);
            0
        }
        (Module::Kernel, 8) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            if handle == 0 { 0 } else {
                u32::from(handle) | (u32::from(state.auto_data) << 16)
            }
        }
        (Module::Kernel, 9) => 0,
        (Module::Kernel, 10) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            state.local_allocations.iter().find(|(allocated, _)| *allocated == handle)
                .map_or(0, |(_, size)| u32::from(*size))
        }
        (Module::Kernel, 25) => 0x000f_0000,
        (Module::Kernel, 23 | 24 | 30 | 52) => 1,
        (Module::Kernel, 47) => u32::from(state.instance),
        (Module::Kernel, 49) => {
            let capacity = stack_u16(machine, windows, regs, 4).unwrap_or(0) as usize;
            let Some(out) = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            if capacity == 0 { return 0; }
            let path = dos_path(windows.exec_path_str());
            let len = path.len().min(capacity - 1);
            machine.copy_to(out, &path[..len]);
            machine.write::<u8>(out + len, 0);
            len as u32
        }
        (Module::Kernel, 51) => {
            // MakeProcInstance is unnecessary in protected mode: preserve the
            // application's far procedure value.
            let Some(p) = stack_at(windows, regs, 6) else { return 0 };
            machine.read::<u32>(p)
        }
        (Module::Kernel, 88) => {
            let source_pointer = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let destination_pointer = stack_u32(machine, windows, regs, 8).unwrap_or(0);
            let Some(source) = far_string(machine, windows, source_pointer) else { return 0 };
            let Some(destination) = far_linear(windows, destination_pointer) else { return 0 };
            machine.copy_to(destination, &source);
            machine.write::<u8>(destination + source.len(), 0);
            destination_pointer
        }
        (Module::Kernel, 60) => {
            let kind_pointer = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let name_pointer = stack_u32(machine, windows, regs, 8).unwrap_or(0);
            let kind = if kind_pointer >> 16 == 0 { kind_pointer as u16 } else {
                crate::dbg_println!("[win16] named resource type unsupported");
                return 0;
            };
            let id = if name_pointer >> 16 == 0 { name_pointer as u16 } else {
                crate::dbg_println!("[win16] named resource unsupported");
                return 0;
            };
            let Ok(image) = ne::Image::parse(&state.image) else { return 0 };
            let Ok(bytes) = image.resource(kind, id) else {
                crate::dbg_println!("[win16] resource type={} id={} not found", kind, id);
                return 0;
            };
            let offset = (usize::from(state.resource_next) + 1) & !1;
            let Some(end) = offset.checked_add(bytes.len()) else { return 0 };
            if end >= 0x10000 { return 0; }
            machine.copy_to(RESOURCE_BASE as usize + offset, bytes);
            let handle = windows.next_object as u16;
            windows.next_object = windows.next_object.wrapping_add(1);
            state.resources.push(Resource { handle, offset: offset as u16 });
            state.resource_next = end as u16;
            u32::from(handle)
        }
        (Module::Kernel, 61) => {
            u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0))
        }
        (Module::Kernel, 62) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            state.resources.iter().find(|resource| resource.handle == handle)
                .map(|resource| u32::from(resource.offset)
                    | (u32::from(state.resource_selector) << 16))
                .unwrap_or(0)
        }
        (Module::Kernel, 115) => 0,
        (Module::Kernel, 127) => {
            u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0))
        }
        (Module::Kernel, 128) => {
            let capacity = stack_u16(machine, windows, regs, 8).unwrap_or(0) as usize;
            let Some(out) = stack_u32(machine, windows, regs, 10)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            let default_pointer = stack_u32(machine, windows, regs, 14).unwrap_or(0);
            let default = far_string(machine, windows, default_pointer).unwrap_or_default();
            if capacity == 0 { return 0; }
            let len = default.len().min(capacity - 1);
            machine.copy_to(out, &default[..len]);
            machine.write::<u8>(out + len, 0);
            len as u32
        }
        (Module::Kernel, 129) => 1,
        (Module::Kernel, 131) => u32::from(state.env_selector) << 16,
        (Module::Kernel, 132) => 0x0025, // protected mode, 386, enhanced mode
        (Module::User, 1) => {
            let style = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let text = stack_u32(machine, windows, regs, 10).unwrap_or(0);
            let caption = stack_u32(machine, windows, regs, 6).unwrap_or(0);
            let text = far_string(machine, windows, text).unwrap_or_default();
            let caption = far_string(machine, windows, caption).unwrap_or_default();
            crate::dbg_println!("[win16] MessageBox '{}': '{}'",
                core::str::from_utf8(&caption).unwrap_or("?"),
                core::str::from_utf8(&text).unwrap_or("?"));
            if matches!(style & 0x000f, 3 | 4) { 6 } else { 1 } // IDYES or IDOK
        }
        (Module::User, 5) => 1,
        (Module::User, 6) => {
            windows.quit = true;
            0
        }
        (Module::User, 10) => {
            let requested = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            state.timer = if requested == 0 { 1 } else { requested };
            u32::from(state.timer)
        }
        (Module::User, 12) => {
            state.timer = 0;
            1
        }
        (Module::User, 15) => (machine.now() / 1_000_000) as u32,
        (Module::User, 18) => stack_u16(machine, windows, regs, 4).unwrap_or(0) as u32,
        (Module::User, 19) => 1,
        (Module::User, 22) => {
            let hwnd = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let previous = windows.focus_hwnd;
            if hwnd == 0 || windows.windows.iter().any(|window| window.hwnd == hwnd) {
                windows.focus_hwnd = hwnd;
            }
            previous
        }
        (Module::User, 23) => windows.focus_hwnd,
        (Module::User, 32) => {
            let Some(rect) = stack_u32(machine, windows, regs, 4)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let hwnd = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let (x, y, width, height) = if hwnd == 0 {
                (0, 0, 640, 480)
            } else if let Some(window) = windows.windows.iter().find(|window| window.hwnd == hwnd) {
                (window.x, window.y, window.width as i32, window.height as i32)
            } else { return 0 };
            machine.write::<i16>(rect, x as i16);
            machine.write::<i16>(rect + 2, y as i16);
            machine.write::<i16>(rect + 4, x.saturating_add(width) as i16);
            machine.write::<i16>(rect + 6, y.saturating_add(height) as i16);
            1
        }
        (Module::User, 33) => {
            let Some(rect) = stack_u32(machine, windows, regs, 4)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let hwnd = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let Some(window) = windows.windows.iter().find(|window| window.hwnd == hwnd) else {
                return 0;
            };
            machine.write::<i16>(rect, 0);
            machine.write::<i16>(rect + 2, 0);
            machine.write::<i16>(rect + 4, window.width as i16);
            machine.write::<i16>(rect + 6, window.height as i16);
            1
        }
        (Module::User, 36) => {
            let capacity = stack_u16(machine, windows, regs, 4).unwrap_or(0) as usize;
            let Some(out) = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let hwnd = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let text = windows.windows.iter().find(|window| window.hwnd == hwnd)
                .map_or(b"".as_slice(), |window| window.text.as_slice());
            if capacity == 0 { return 0; }
            let len = text.len().min(capacity - 1);
            machine.copy_to(out, &text[..len]);
            machine.write::<u8>(out + len, 0);
            len as u32
        }
        (Module::User, 37) => {
            let pointer = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let hwnd = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let Some(text) = far_string(machine, windows, pointer) else { return 0 };
            if let Some(window) = windows.windows.iter_mut().find(|window| window.hwnd == hwnd) {
                window.text = text;
                windows.dirty = true;
                1
            } else { 0 }
        }
        (Module::User, 39) => {
            let Some(out) = stack_u32(machine, windows, regs, 4)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            let hwnd = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let Some(window) = windows.windows.iter().find(|window| window.hwnd == hwnd) else {
                return 0;
            };
            machine.zero(out, 30);
            machine.write::<u16>(out, windows.paint_dc as u16);
            machine.write::<u16>(out + 2, 1);
            machine.write::<i16>(out + 4, 0);
            machine.write::<i16>(out + 6, 0);
            machine.write::<i16>(out + 8, window.width as i16);
            machine.write::<i16>(out + 10, window.height as i16);
            windows.paint_hwnd = hwnd;
            windows.paint_dc
        }
        (Module::User, 40) => {
            windows.dirty = true;
            1
        }
        (Module::User, 57) => {
            let Some(wc) = stack_u32(machine, windows, regs, 4)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            let wndproc = machine.read::<u32>(wc + 2);
            let background = u32::from(machine.read::<u16>(wc + 16));
            let menu_pointer = machine.read::<u32>(wc + 18);
            let menu = if menu_pointer >> 16 == 0 { menu_pointer } else { 0 };
            let name_pointer = machine.read::<u32>(wc + 22);
            let Some(name) = far_string(machine, windows, name_pointer) else { return 0 };
            if let Some(class) = windows.classes.iter_mut()
                .find(|class| class.name.eq_ignore_ascii_case(&name)) {
                class.wndproc = wndproc;
                class.background = background;
                class.menu = menu;
            } else {
                windows.classes.push(super::WindowClass { name, wndproc, background, menu });
            }
            windows.classes.len() as u32
        }
        (Module::User, 41) => {
            let class_pointer = stack_u32(machine, windows, regs, 30).unwrap_or(0);
            let class = if class_pointer >> 16 == 0 {
                windows.classes.first().map(|class| {
                    (class.wndproc, class.background, class.menu)
                })
            } else {
                let Some(name) = far_string(machine, windows, class_pointer) else {
                    crate::dbg_println!("[win16] invalid window class pointer {:08x}", class_pointer);
                    return 0;
                };
                windows.classes.iter().find(|class| class.name.eq_ignore_ascii_case(&name))
                    .map(|class| (class.wndproc, class.background, class.menu))
                    .or_else(|| [b"BUTTON".as_slice(), b"EDIT", b"STATIC", b"LISTBOX",
                        b"SCROLLBAR", b"COMBOBOX", b"MDICLIENT"]
                        .iter().any(|class| name.eq_ignore_ascii_case(class))
                        .then_some((0, 0x30005, 0)))
                    .or_else(|| {
                        crate::dbg_println!("[win16] window class '{}' not found",
                            core::str::from_utf8(&name).unwrap_or("?"));
                        None
                    })
            };
            let Some((wndproc, _background, class_menu)) = class else { return 0 };
            let parent = u32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0));
            let requested_menu = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let menu = if parent == 0 && requested_menu == 0 { class_menu } else { requested_menu };
            ensure_menu(windows, state, menu);
            let raw_width = stack_u16(machine, windows, regs, 16).unwrap_or(1);
            let raw_height = stack_u16(machine, windows, regs, 14).unwrap_or(1);
            let raw_x = stack_u16(machine, windows, regs, 20).unwrap_or(0);
            let raw_y = stack_u16(machine, windows, regs, 18).unwrap_or(0);
            let (width, height) = if parent == 0 && raw_width == 0x8000 {
                // CW_USEDEFAULT on a top-level window delegates both dimensions
                // to the window manager; the supplied height is ignored.
                (640, 480)
            } else {
                (u32::from(raw_width).clamp(1, 2048),
                    u32::from(raw_height).clamp(1, 2048))
            };
            let hwnd = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.windows.push(super::Window {
                hwnd,
                parent,
                wndproc,
                menu,
                control_class: 0,
                text: Vec::new(),
                x: if parent == 0 && raw_x == 0x8000 { 0 } else { i32::from(raw_x as i16) },
                y: if parent == 0 && raw_x == 0x8000 { 0 } else { i32::from(raw_y as i16) },
                width,
                height,
                visible: false,
                pixels: vec![0xc0; width as usize * height as usize * 4],
            });
            hwnd
        }
        (Module::User, 42) => {
            let show = stack_u16(machine, windows, regs, 4).unwrap_or(0) != 0;
            let hwnd = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            if let Some(window) = windows.windows.iter_mut().find(|window| window.hwnd == hwnd) {
                let was = window.visible;
                window.visible = show;
                let top_level = window.parent == 0;
                let size = window.width | (window.height << 16);
                if show && top_level {
                    windows.messages.push(super::Message {
                        hwnd,
                        message: 0x0005,
                        wparam: 0,
                        lparam: size,
                    });
                }
                if show { super::queue_paint(windows, hwnd); }
                was as u32
            } else { 0 }
        }
        (Module::User, 53) => {
            let hwnd = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            if let Some(index) = windows.windows.iter().position(|window| window.hwnd == hwnd) {
                windows.windows.remove(index);
                1
            } else { 0 }
        }
        (Module::User, 56) => {
            let repaint = stack_u16(machine, windows, regs, 4).unwrap_or(0) != 0;
            let height = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(1)).clamp(1, 2048);
            let width = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(1)).clamp(1, 2048);
            let y = i32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0) as i16);
            let x = i32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0) as i16);
            let hwnd = u32::from(stack_u16(machine, windows, regs, 14).unwrap_or(0));
            if let Some(window) = windows.windows.iter_mut().find(|window| window.hwnd == hwnd) {
                window.x = x;
                window.y = y;
                window.width = width;
                window.height = height;
                window.pixels.resize(width as usize * height as usize * 4, 0xc0);
                if repaint { super::queue_paint(windows, hwnd); }
                1
            } else { 0 }
        }
        (Module::User, 66) => {
            windows.paint_hwnd = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            windows.paint_dc
        }
        (Module::User, 68) => 1,
        (Module::User, 72) => {
            let Some(rect) = stack_u32(machine, windows, regs, 12)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            machine.write::<i16>(rect, stack_u16(machine, windows, regs, 10).unwrap_or(0) as i16);
            machine.write::<i16>(rect + 2, stack_u16(machine, windows, regs, 8).unwrap_or(0) as i16);
            machine.write::<i16>(rect + 4, stack_u16(machine, windows, regs, 6).unwrap_or(0) as i16);
            machine.write::<i16>(rect + 6, stack_u16(machine, windows, regs, 4).unwrap_or(0) as i16);
            1
        }
        (Module::User, 76) => {
            let point = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let Some(rect) = stack_u32(machine, windows, regs, 8)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            let x = point as u16 as i16;
            let y = (point >> 16) as u16 as i16;
            let left = machine.read::<i16>(rect);
            let top = machine.read::<i16>(rect + 2);
            let right = machine.read::<i16>(rect + 4);
            let bottom = machine.read::<i16>(rect + 6);
            (x >= left && x < right && y >= top && y < bottom) as u32
        }
        (Module::User, 81) => {
            let brush = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let Some(rect) = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let dc = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let left = i32::from(machine.read::<i16>(rect));
            let top = i32::from(machine.read::<i16>(rect + 2));
            let right = i32::from(machine.read::<i16>(rect + 4));
            let bottom = i32::from(machine.read::<i16>(rect + 6));
            let color = super::object_color(windows, brush, 0x00c0_c0c0);
            super::fill_pixels(windows, dc, left, top, right, bottom, color);
            windows.dirty = true;
            1
        }
        (Module::User, 88) => {
            let hwnd = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            windows.windows.retain(|window| window.hwnd != hwnd && window.parent != hwnd);
            windows.dirty = true;
            1
        }
        (Module::User, 91) => {
            let id = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let dialog = stack_u16(machine, windows, regs, 6).unwrap_or(0);
            windows.windows.iter().find(|window| {
                window.parent == u32::from(dialog) && window.menu == u32::from(id)
            }).map_or(0, |window| window.hwnd)
        }
        (Module::User, 92) => {
            let pointer = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let id = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let dialog = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let Some(text) = far_string(machine, windows, pointer) else { return 0 };
            if let Some(window) = windows.windows.iter_mut()
                .find(|window| window.parent == dialog && window.menu == id)
            {
                window.text = text;
                windows.dirty = true;
                1
            } else { 0 }
        }
        (Module::User, 93) => {
            let capacity = stack_u16(machine, windows, regs, 4).unwrap_or(0) as usize;
            let Some(out) = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let id = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let dialog = u32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0));
            let text = windows.windows.iter()
                .find(|window| window.parent == dialog && window.menu == id)
                .map_or(b"".as_slice(), |window| window.text.as_slice());
            if capacity == 0 { return 0; }
            let len = text.len().min(capacity - 1);
            machine.copy_to(out, &text[..len]);
            machine.write::<u8>(out + len, 0);
            len as u32
        }
        (Module::User, 101) => {
            let lparam = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let wparam = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            let message = stack_u16(machine, windows, regs, 10).unwrap_or(0);
            let id = stack_u16(machine, windows, regs, 12).unwrap_or(0);
            let _ = (id, message, wparam, lparam);
            0
        }
        (Module::User, 108 | 109) => {
            if windows.quit { return 0; }
            if windows.messages.is_empty() {
                if state.timer != 0
                    && let Some(window) = windows.windows.iter().find(|window| window.visible)
                {
                    windows.messages.push(super::Message {
                        hwnd: window.hwnd, message: 0x0113,
                        wparam: u32::from(state.timer), lparam: 0,
                    });
                }
                if windows.messages.is_empty() { return 0; }
            }
            let message = windows.messages[0];
            let Some(out) = stack_u32(machine, windows, regs,
                    if gate.ordinal == 108 { 10 } else { 12 })
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            write_message16(machine, out, message);
            let remove = gate.ordinal == 108
                || stack_u16(machine, windows, regs, 4).unwrap_or(0) & 1 != 0;
            if remove { windows.messages.remove(0); }
            1
        }
        (Module::User, 110) => {
            windows.messages.push(super::Message {
                hwnd: u32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0)),
                message: u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0)),
                wparam: u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0)),
                lparam: stack_u32(machine, windows, regs, 4).unwrap_or(0),
            });
            1
        }
        (Module::User, 107 | 111 | 113 | 114) => 0,
        (Module::User, 124 | 125) => {
            let hwnd_displacement = if gate.ordinal == 124 { 4 } else { 10 };
            let hwnd = u32::from(stack_u16(machine, windows, regs, hwnd_displacement).unwrap_or(0));
            if windows.windows.iter().any(|window| window.hwnd == hwnd) {
                super::queue_paint(windows, hwnd);
                1
            } else { 0 }
        }
        (Module::User, 150) => {
            let resource = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            if resource >> 16 == 0 {
                ensure_menu(windows, state, resource);
                resource
            } else {
                let handle = windows.next_object;
                windows.next_object = windows.next_object.wrapping_add(1);
                if let Some(name) = far_string(machine, windows, resource)
                    && let Ok(image) = ne::Image::parse(&state.image)
                    && let Ok(data) = image.named_resource(4, &name)
                {
                    install_menu(windows, handle, data);
                }
                handle
            }
        }
        (Module::User, 151) => {
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            handle
        }
        (Module::User, 152) => 1,
        (Module::User, 157) => {
            let hwnd = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            windows.windows.iter().find(|window| window.hwnd == hwnd)
                .map_or(0, |window| window.menu)
        }
        (Module::User, 158) => {
            let menu = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let hwnd = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            if let Some(window) = windows.windows.iter_mut().find(|window| window.hwnd == hwnd) {
                window.menu = menu;
                windows.dirty = true;
                1
            } else {
                0
            }
        }
        (Module::User, 159) => u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0)),
        (Module::User, 160) => {
            windows.dirty = true;
            1
        }
        (Module::User, 173 | 174 | 177) => 1,
        (Module::User, 154 | 155 | 171) => 1,
        (Module::User, 175) => {
            let name = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            if name >> 16 != 0 {
                crate::dbg_println!("[win16] named bitmap resources unsupported");
                return 0;
            }
            let Ok(image) = ne::Image::parse(&state.image) else { return 0 };
            let Ok(bytes) = image.resource(2, name as u16) else {
                crate::dbg_println!("[win16] bitmap resource {} not found", name as u16);
                return 0;
            };
            let offset = (usize::from(state.resource_next) + 3) & !3;
            let Some(end) = offset.checked_add(bytes.len()) else { return 0 };
            if end >= 0x10000 { return 0; }
            let header = RESOURCE_BASE as usize + offset;
            machine.copy_to(header, bytes);
            let Some((width, height, bpp, palette)) = dib_header(machine, header) else {
                return 0;
            };
            let header_size = machine.read::<u32>(header) as usize;
            let palette_entries = match bpp {
                1..=8 if header_size >= 40 => {
                    let used = machine.read::<u32>(header + 32) as usize;
                    if used == 0 { 1usize << bpp } else { used }
                }
                1..=8 => 1usize << bpp,
                _ => 0,
            };
            let palette_stride = if header_size == 12 { 3 } else { 4 };
            let bits = palette.saturating_add(palette_entries.saturating_mul(palette_stride));
            let Some(pixel_bytes) = width.checked_mul(height).and_then(|n| n.checked_mul(4)) else {
                return 0;
            };
            let mut pixels = vec![0u8; pixel_bytes];
            decode_dib(machine, bits, palette, width, height, bpp, &mut pixels);
            state.resource_next = end as u16;
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Bitmap {
                width: width as u32,
                height: height as u32,
                pixels,
            }));
            handle
        }
        (Module::User, 178) => 0,
        (Module::User, 176) => {
            let capacity = stack_u16(machine, windows, regs, 4).unwrap_or(0) as usize;
            let Some(out) = stack_u32(machine, windows, regs, 6)
                .and_then(|p| far_linear(windows, p)) else { return 0 };
            let id = stack_u16(machine, windows, regs, 10).unwrap_or(0);
            let Ok(image) = ne::Image::parse(&state.image) else { return 0 };
            let Ok(text) = image.string_resource(id) else { return 0 };
            if capacity == 0 { return 0; }
            let len = text.len().min(capacity - 1);
            machine.copy_to(out, &text[..len]);
            machine.write::<u8>(out + len, 0);
            len as u32
        }
        (Module::User, 179) => {
            let metric = stack_at(windows, regs, 4).map(|p| machine.read::<u16>(p)).unwrap_or(0);
            match metric { 0 => 640, 1 => 480, 2 | 3 => 16, 4 => 16, 15 => 16, _ => 0 }
        }
        (Module::User, 180) => {
            match stack_u16(machine, windows, regs, 4).unwrap_or(0) {
                0 | 4 | 15 => 0x00c0_c0c0,
                1 | 3 => 0x0080_8080,
                2 => 0x0080_0000,
                5 | 9 | 14 => 0x00ff_ffff,
                6 | 7 | 8 | 10 | 18 => 0,
                13 => 0x0000_0080,
                _ => 0x00c0_c0c0,
            }
        }
        (Module::User, 286) => 1,
        (Module::User, 287) => stack_u16(machine, windows, regs, 4).unwrap_or(0) as u32,

        (Module::Gdi, 4) => 1,
        (Module::Gdi, 19) => {
            let y = stack_u16(machine, windows, regs, 4).unwrap_or(0) as i16 as i32;
            let x = stack_u16(machine, windows, regs, 6).unwrap_or(0) as i16 as i32;
            let dc = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let (old_x, old_y, pen) = windows.dcs.iter().find(|item| item.handle == dc)
                .map(|item| (item.x, item.y, item.pen)).unwrap_or((0, 0, 0));
            let color = super::object_color(windows, pen, 0);
            super::line(windows, dc, old_x, old_y, x, y, color);
            if let Some(item) = windows.dcs.iter_mut().find(|item| item.handle == dc) {
                item.x = x; item.y = y;
            }
            1
        }
        (Module::Gdi, 20) => {
            let y = stack_u16(machine, windows, regs, 4).unwrap_or(0) as i16 as i32;
            let x = stack_u16(machine, windows, regs, 6).unwrap_or(0) as i16 as i32;
            let dc = u32::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let mut old = 0;
            if let Some(item) = windows.dcs.iter_mut().find(|item| item.handle == dc) {
                old = (item.x as u16 as u32) | ((item.y as u16 as u32) << 16);
                item.x = x; item.y = y;
            }
            old
        }
        (Module::Gdi, 31) => {
            let color = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let y = stack_u16(machine, windows, regs, 8).unwrap_or(0) as i16 as i32;
            let x = stack_u16(machine, windows, regs, 10).unwrap_or(0) as i16 as i32;
            let dc = u32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0));
            super::put_pixel(windows, dc, x, y, color);
            color
        }
        (Module::Gdi, 33) => {
            let count = usize::from(stack_u16(machine, windows, regs, 4).unwrap_or(0)).min(4096);
            let Some(text) = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let y = i32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0) as i16);
            let x = i32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0) as i16);
            let dc = u32::from(stack_u16(machine, windows, regs, 14).unwrap_or(0));
            let color = windows.dcs.iter().find(|context| context.handle == dc)
                .map_or(0, |context| context.text);
            for n in 0..count {
                let ch = usize::from(machine.read::<u8>(text + n));
                let glyph = &lib::vga_fonts::FONT_8X16[ch * 16..ch * 16 + 16];
                for (gy, &bits) in glyph.iter().enumerate() {
                    for gx in 0..8 {
                        if bits & (0x80 >> gx) != 0 {
                            super::put_pixel(windows, dc,
                                x + (n * 8 + gx) as i32, y + gy as i32, color);
                        }
                    }
                }
            }
            windows.dirty = true;
            1
        }
        (Module::Gdi, 34) => {
            let sy = stack_u16(machine, windows, regs, 8).unwrap_or(0) as i16 as i32;
            let sx = stack_u16(machine, windows, regs, 10).unwrap_or(0) as i16 as i32;
            let src = u32::from(stack_u16(machine, windows, regs, 12).unwrap_or(0));
            let height = stack_u16(machine, windows, regs, 14).unwrap_or(0) as usize;
            let width = stack_u16(machine, windows, regs, 16).unwrap_or(0) as usize;
            let dy = stack_u16(machine, windows, regs, 18).unwrap_or(0) as i16 as i32;
            let dx = stack_u16(machine, windows, regs, 20).unwrap_or(0) as i16 as i32;
            let dst = u32::from(stack_u16(machine, windows, regs, 22).unwrap_or(0));
            let Some(source_bitmap) = super::dc_bitmap(windows, src) else { return 0 };
            let Some((sw, sh, source)) = windows.gdi_objects.iter().find_map(|(handle, object)| {
                match object {
                    super::GdiObject::Bitmap { width, height, pixels }
                        if *handle == source_bitmap => Some((*width, *height, pixels.clone())),
                    _ => None,
                }
            }) else { return 0 };
            for y in 0..height {
                for x in 0..width {
                    let px = sx + x as i32;
                    let py = sy + y as i32;
                    if px < 0 || py < 0 || px >= sw as i32 || py >= sh as i32 { continue; }
                    let at = (py as usize * sw as usize + px as usize) * 4;
                    let color = u32::from_le_bytes(source[at..at + 4].try_into().unwrap());
                    super::put_pixel(windows, dst, dx + x as i32, dy + y as i32, color);
                }
            }
            windows.dirty = true;
            1
        }
        (Module::Gdi, 45) => {
            let object = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let dc = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            if let Some(item) = windows.dcs.iter_mut().find(|item| item.handle == dc) {
                if windows.gdi_objects.iter().any(|(h, o)| *h == object
                    && matches!(o, super::GdiObject::Bitmap { .. })) {
                    item.bitmap.replace(object).unwrap_or(0)
                } else if windows.gdi_objects.iter().any(|(h, o)| *h == object
                    && matches!(o, super::GdiObject::Pen(_))) {
                    core::mem::replace(&mut item.pen, object)
                } else if windows.gdi_objects.iter().any(|(h, o)| *h == object
                    && matches!(o, super::GdiObject::Font)) {
                    core::mem::replace(&mut item.font, object)
                } else {
                    core::mem::replace(&mut item.brush, object)
                }
            } else { 0 }
        }
        (Module::Gdi, 51) => {
            let height = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let width = u32::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            let Some(size) = usize::try_from(width).ok()
                .and_then(|width| usize::try_from(height).ok()
                    .and_then(|height| width.checked_mul(height)))
                .and_then(|pixels| pixels.checked_mul(4)) else { return 0 };
            if width == 0 || height == 0 || width > 2048 || height > 2048 { return 0; }
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Bitmap {
                width,
                height,
                pixels: vec![0; size],
            }));
            handle
        }
        (Module::Gdi, 52) => {
            // A memory DC always owns a default 1x1 monochrome bitmap.  The
            // first SelectObject must return that non-null previous object.
            let bitmap = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((bitmap, super::GdiObject::Bitmap {
                width: 1,
                height: 1,
                pixels: vec![0; 4],
            }));
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.dcs.push(super::DeviceContext {
                handle, bitmap: Some(bitmap), x: 0, y: 0, pen: 0, brush: 0, font: 1,
                bk: 0x00ff_ffff, text: 0,
            });
            handle
        }
        (Module::Gdi, 57) => {
            if stack_u32(machine, windows, regs, 4)
                .and_then(|pointer| far_linear(windows, pointer)).is_none()
            {
                return 0;
            }
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Font));
            handle
        }
        (Module::Gdi, 60) => {
            let bitmap = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let Some(color) = windows.gdi_objects.iter().find_map(|(handle, object)| {
                match object {
                    super::GdiObject::Bitmap { pixels, .. } if *handle == bitmap => pixels
                        .get(..4).map(|pixel| u32::from_le_bytes(pixel.try_into().unwrap())),
                    _ => None,
                }
            }) else { return 0 };
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Brush(color)));
            handle
        }
        (Module::Gdi, 61) => {
            let color = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Pen(color)));
            handle
        }
        (Module::Gdi, 66) => {
            let color = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            windows.gdi_objects.push((handle, super::GdiObject::Brush(color)));
            handle
        }
        (Module::Gdi, 68) => {
            let handle = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            if let Some(index) = windows.dcs.iter().position(|item| item.handle == handle) {
                windows.dcs.remove(index); 1
            } else { 0 }
        }
        (Module::Gdi, 69) => {
            let handle = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            if let Some(index) = windows.gdi_objects.iter().position(|(h, _)| *h == handle) {
                windows.gdi_objects.remove(index); 1
            } else { 0 }
        }
        (Module::Gdi, 80) => {
            let index = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            match index {
                // WinMine's 16-bit signed comparison treats the modern
                // high-colour sentinel (-1) as monochrome.  Advertise the
                // classic 16-colour Windows display that this personality
                // emulates instead.
                8 => 640, 10 => 480, 12 => 4, 14 => 1, 24 => 16,
                _ => 0,
            }
        }
        (Module::Gdi, 82) => {
            let Some(out) = stack_u32(machine, windows, regs, 4)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            let capacity = usize::from(stack_u16(machine, windows, regs, 8).unwrap_or(0));
            let handle = u32::from(stack_u16(machine, windows, regs, 10).unwrap_or(0));
            let Some(object) = windows.gdi_objects.iter()
                .find(|(object_handle, _)| *object_handle == handle)
                .map(|(_, object)| object) else { return 0 };
            match object {
                super::GdiObject::Bitmap { width, height, .. } if capacity >= 14 => {
                    machine.zero(out, 14);
                    machine.write::<i16>(out + 2, *width as i16);
                    machine.write::<i16>(out + 4, *height as i16);
                    machine.write::<i16>(out + 6, width.saturating_add(7).div_ceil(8) as i16);
                    machine.write::<u8>(out + 8, 1);
                    machine.write::<u8>(out + 9, 1);
                    14
                }
                _ => {
                    machine.zero(out, capacity);
                    capacity as u32
                }
            }
        }
        (Module::Gdi, 87) => {
            let index = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let color = match index { 0 | 6 => 0x00ff_ffff, 1 => 0x00c0_c0c0,
                2 => 0x0080_8080, 3 => 0x0040_4040, _ => 0 };
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            let object = if matches!(index, 6..=8) {
                super::GdiObject::Pen(color)
            } else { super::GdiObject::Brush(color) };
            windows.gdi_objects.push((handle, object));
            handle
        }
        (Module::Gdi, 91) => {
            let count = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            count.saturating_mul(8) | (16 << 16)
        }
        (Module::Gdi, 93) => {
            let Some(out) = stack_u32(machine, windows, regs, 4)
                .and_then(|pointer| far_linear(windows, pointer)) else { return 0 };
            machine.zero(out, 30);
            machine.write::<i16>(out, 16);      // tmHeight
            machine.write::<i16>(out + 2, 13);  // tmAscent
            machine.write::<i16>(out + 4, 3);   // tmDescent
            machine.write::<i16>(out + 10, 8);  // tmAveCharWidth
            machine.write::<i16>(out + 12, 8);  // tmMaxCharWidth
            machine.write::<i16>(out + 14, 400); // tmWeight
            machine.write::<i16>(out + 18, 96); // tmDigitizedAspectX
            machine.write::<i16>(out + 20, 96); // tmDigitizedAspectY
            machine.write::<u8>(out + 22, 0x20); // tmFirstChar
            machine.write::<u8>(out + 23, 0xff); // tmLastChar
            machine.write::<u8>(out + 24, b'?'); // tmDefaultChar
            machine.write::<u8>(out + 25, b' '); // tmBreakChar
            1
        }
        (Module::Gdi, 442) => {
            let bits_pointer = stack_u32(machine, windows, regs, 10).unwrap_or(0);
            let header_pointer = stack_u32(machine, windows, regs, 18).unwrap_or(0);
            let Some(header) = far_linear(windows, header_pointer) else { return 0 };
            let Some((width, height, bpp, palette_at)) = dib_header(machine, header) else {
                return 0;
            };
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            let mut pixels = vec![0u8; width * height * 4];
            if let Some(bits) = far_linear(windows, bits_pointer) {
                decode_dib(machine, bits, palette_at, width, height, bpp, &mut pixels);
            }
            windows.gdi_objects.push((handle, super::GdiObject::Bitmap {
                width: width as u32,
                height: height as u32,
                pixels,
            }));
            handle
        }
        (Module::Gdi, 443) => {
            let bmi_pointer = stack_u32(machine, windows, regs, 6).unwrap_or(0);
            let bits_pointer = stack_u32(machine, windows, regs, 10).unwrap_or(0);
            let Some(header) = far_linear(windows, bmi_pointer) else { return 0 };
            let Some(bits) = far_linear(windows, bits_pointer) else { return 0 };
            let Some((source_width, source_height, bpp, palette_at)) = dib_header(machine, header)
                else { return 0 };
            if crate::kernel::startup::trace_enabled() {
                crate::dbg_println!("[win16] SetDIBitsToDevice source={}x{}x{}", source_width, source_height, bpp);
            }
            let lines = usize::from(stack_u16(machine, windows, regs, 14).unwrap_or(0));
            // Win16 callers may point `bits` at just the requested scan-line
            // run (WinMine does this for each digit in a vertical sprite
            // strip).  Decode that run, not the full height declared by BMI.
            let decoded_height = lines.min(source_height);
            let mut pixels = vec![0u8; source_width * decoded_height * 4];
            decode_dib(machine, bits, palette_at, source_width, decoded_height, bpp, &mut pixels);
            let source_y = i32::from(stack_u16(machine, windows, regs, 18).unwrap_or(0) as i16);
            let source_x = i32::from(stack_u16(machine, windows, regs, 20).unwrap_or(0) as i16);
            let height = usize::from(stack_u16(machine, windows, regs, 22).unwrap_or(0)).min(lines.max(1));
            let width = usize::from(stack_u16(machine, windows, regs, 24).unwrap_or(0));
            let dest_y = i32::from(stack_u16(machine, windows, regs, 26).unwrap_or(0) as i16);
            let dest_x = i32::from(stack_u16(machine, windows, regs, 28).unwrap_or(0) as i16);
            let dc = u32::from(stack_u16(machine, windows, regs, 30).unwrap_or(0));
            for y in 0..height {
                for x in 0..width {
                    let sx = source_x + x as i32;
                    let sy = source_y + y as i32;
                    if sx < 0 || sy < 0 || sx >= source_width as i32 || sy >= decoded_height as i32 {
                        continue;
                    }
                    let at = (sy as usize * source_width + sx as usize) * 4;
                    let color = u32::from_le_bytes(pixels[at..at + 4].try_into().unwrap());
                    super::put_pixel(windows, dc, dest_x + x as i32, dest_y + y as i32, color);
                }
            }
            windows.dirty = true;
            lines as u32
        }
        (Module::Sound, _) => 1,
        (Module::Keyboard, 5 | 6) => 1,
        _ => {
            crate::dbg_println!("[win16] stub {}", gate.name);
            0
        }
    }
}

pub(super) fn handle_event<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    windows: &mut WindowsState,
    state: &mut State,
    regs: &mut Regs,
    event: crate::KernelEvent,
) -> thread::KernelAction {
    match event {
        crate::KernelEvent::Irq => thread::KernelAction::Done,
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let ip = regs.ip32() as u16;
            let Some(gate) = state.gates.iter().copied()
                .find(|gate| gate.selector == regs.code_seg()
                    && gate.offset.wrapping_add(2) == ip) else {
                crate::dbg_println!("[win16] invalid DLL gate {:04x}:{:04x}", regs.code_seg(), ip);
                return thread::KernelAction::Exit(-1);
            };
            if gate.ordinal == 0xffff {
                let Some(callback) = state.callbacks.pop() else {
                    return thread::KernelAction::Exit(-1);
                };
                let wndproc_result = (regs.rax as u16 as u32) | ((regs.rdx as u16 as u32) << 16);
                let result = match callback.result {
                    CallbackResult::WndProc => wndproc_result,
                    CallbackResult::CreateWindow { hwnd } => {
                        if wndproc_result as u16 == 0xffff {
                            if let Some(index) = windows.windows.iter()
                                .position(|window| window.hwnd == hwnd)
                            {
                                windows.windows.remove(index);
                            }
                            0
                        } else {
                            hwnd
                        }
                    }
                    CallbackResult::DialogInit { hwnd, auto_ok } => {
                        if auto_ok && begin_wndproc(machine, windows, state, regs,
                            callback.dispatch_gate, CallbackResult::DialogCommand { hwnd },
                            super::Message { hwnd, message: 0x0111, wparam: 1, lparam: 0 })
                        {
                            return thread::KernelAction::Done;
                        }
                        0
                    }
                    CallbackResult::DialogCommand { hwnd } => {
                        windows.windows.retain(|window| window.hwnd != hwnd && window.parent != hwnd);
                        windows.dirty = true;
                        1
                    }
                };
                if finish(machine, windows, regs, callback.dispatch_gate, result).is_err() {
                    return thread::KernelAction::Exit(-1);
                }
                return thread::KernelAction::Done;
            }
            if crate::kernel::startup::trace_enabled() {
                crate::dbg_println!("[win16] {:?}.{} {}", gate.module, gate.ordinal, gate.name);
            }
            if gate.module == Module::User && gate.ordinal == 114 {
                let Some(message_at) = stack_u32(machine, windows, regs, 4)
                    .and_then(|p| far_linear(windows, p)) else {
                    return thread::KernelAction::Exit(-1);
                };
                let message = message16(machine, message_at);
                if begin_wndproc(machine, windows, state, regs, gate,
                    CallbackResult::WndProc, message) {
                    return thread::KernelAction::Done;
                }
            }
            if gate.module == Module::User && gate.ordinal == 87 {
                let proc = stack_u32(machine, windows, regs, 4).unwrap_or(0);
                let template = stack_u32(machine, windows, regs, 10).unwrap_or(0);
                if let Some((hwnd, auto_ok)) = create_dialog(windows, state, template as u16, proc)
                    && begin_wndproc(machine, windows, state, regs, gate,
                    CallbackResult::DialogInit { hwnd, auto_ok },
                    super::Message { hwnd, message: 0x0110, wparam: 0, lparam: 0 })
                {
                    return thread::KernelAction::Done;
                }
            }
            if gate.module == Module::User && gate.ordinal == 108
                && !windows.quit && windows.messages.is_empty() && state.timer == 0
            {
                // GetMessage blocks until input or another producer queues a
                // message.  Re-enter the INT gate when this thread is next
                // scheduled instead of returning the WM_QUIT value zero.
                regs.frame.rip = u64::from(gate.offset);
                return thread::KernelAction::Yield;
            }
            let result = dispatch(machine, kt, windows, state, regs, gate);
            if gate.module == Module::User && gate.ordinal == 41 && result != 0 {
                let message = super::Message {
                    hwnd: result,
                    message: 1,
                    wparam: 0,
                    lparam: stack_u32(machine, windows, regs, 4).unwrap_or(0),
                };
                if begin_wndproc(machine, windows, state, regs, gate,
                    CallbackResult::CreateWindow { hwnd: result }, message) {
                    return thread::KernelAction::Done;
                }
            }
            if finish(machine, windows, regs, gate, result).is_err() {
                return thread::KernelAction::Exit(-1);
            }
            thread::KernelAction::Done
        }
        crate::KernelEvent::PageFault { .. } => unreachable!("page faults handled by event loop"),
        _ => {
            crate::dbg_println!("[win16] unhandled {:?} at {:04x}:{:04x}",
                event, regs.code_seg(), regs.ip32() as u16);
            thread::KernelAction::Exit(-1)
        }
    }
}
