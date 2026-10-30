//! NE loading and the remaining native Win16 services.
//!
//! USER and core GDI exports run in guest DLLs through a segmented ABI adapter
//! to the shared Rust implementation. Only remaining INT 83h exports enter here;
//! application callbacks and their continuations stay on guest stacks.

extern crate alloc;

use alloc::{vec, vec::Vec};

use crate::Regs;
use crate::kernel::thread;

use super::{ne, WindowsState, GATE_VECTOR};

const SEGMENT_BASE: u32 = 0x0100_0000;
const SEGMENT_STRIDE: u32 = 0x0001_0000;
const MODULE_BASE: u32 = 0x0200_0000;
const PSP_BASE: u32 = 0x0008_0000;
const ENV_BASE: u32 = 0x0008_1000;
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

impl compact_fmt::Format for Module {
    fn format(&self, out: &mut dyn compact_fmt::Write, _: compact_fmt::FormatSpec) -> compact_fmt::Result {
        out.write_str(match self {
            Self::Kernel => "Kernel",
            Self::Gdi => "Gdi",
            Self::User => "User",
            Self::Sound => "Sound",
            Self::Shell => "Shell",
            Self::Keyboard => "Keyboard",
        })
    }
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

struct Resource {
    handle: u16,
    offset: u16,
}

struct LocalBlock {
    start: u16,
    data: u16,
    handle: u16,
    size: u16,
    movable: bool,
    locks: u8,
}

struct GlobalBlock { handle: u16, selector: u16, count: usize, address: u32, size: u32, flags: u16, locks: u16 }

pub(super) struct State {
    image: Vec<u8>,
    modules: Vec<LoadedModule>,
    bridge_cs: u16,
    gates: Vec<Gate>,
    instance: u16,
    auto_data: u16,
    local_next: u16,
    local_start: u16,
    local_blocks: Vec<LocalBlock>,
    global_blocks: Vec<GlobalBlock>,
    selector_floor: usize,
    selector_reservations: Vec<u16>,
    local_end: u16,
    psp_selector: u16,
    env_selector: u16,
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
        (Module::Kernel, 21) => (2, true, "GlobalHandle"),
        (Module::Kernel, 159) => (2, true, "GlobalHandleNoRIP"),
        (Module::Kernel, 138) => (2, true, "GetHeapSpaces"),
        (Module::Kernel, 169) => (2, true, "GetFreeSpace"),
        (Module::Kernel, 170) => (2, false, "AllocCStoDSAlias"),
        (Module::Kernel, 175) => (2, false, "AllocSelector"),
        (Module::Kernel, 176) => (2, false, "FreeSelector"),
        (Module::Kernel, 177) => (4, false, "PrestoChangoSelector"),
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
        (Module::Kernel, 60) => (10, false, "FindResource"),
        (Module::Kernel, 61) => (4, false, "LoadResource"),
        (Module::Kernel, 62) => (2, true, "LockResource"),
        (Module::Kernel, 63) => (2, false, "FreeResource"),
        (Module::Kernel, 74) => (10, false, "OpenFile"),
        (Module::Kernel, 88) => (8, true, "lstrcpy"),
        (Module::Kernel, 89) => (8, true, "lstrcat"),
        (Module::Kernel, 90) => (4, false, "lstrlen"),
        (Module::Kernel, 91) => (0, false, "InitTask"),
        (Module::Kernel, 426) => (4, false, "RetroLoadLibrary"),
        (Module::Kernel, 427) => (10, false, "RetroNextInitializer"),
        (Module::Kernel, 96) => (2, false, "FreeLibrary"),
        (Module::Kernel, 102) => (0, false, "DOS3Call"),
        (Module::Kernel, 107) => (2, false, "SetErrorMode"),
        (Module::Kernel, 115) => (4, false, "OutputDebugString"),
        (Module::Kernel, 121) => (4, false, "LocalShrink"),
        (Module::Kernel, 129) => (16, false, "WritePrivateProfileString"),
        (Module::Kernel, 131) => (0, true, "GetDOSEnvironment"),
        (Module::Kernel, 132) => (0, true, "GetWinFlags"),
        (Module::Kernel, 136) => (2, false, "GetDriveType"),
        (Module::Kernel, 137) => (6, false, "FatalAppExit"),
        (Module::Kernel, 207) => (2, false, "IsDBCSLeadByte"),

        (Module::Gdi, 7) => (4, false, "SetStretchBltMode"),
        (Module::Gdi, 11) => (6, true, "SetWindowOrg"),
        (Module::Gdi, 12) => (6, true, "SetWindowExt"),
        (Module::Gdi, 13) => (6, true, "SetViewportOrg"),
        (Module::Gdi, 14) => (6, true, "SetViewportExt"),
        (Module::Gdi, 23) => (18, false, "Arc"),
        (Module::Gdi, 35) => (24, false, "StretchBlt"),
        (Module::Gdi, 38) => (14, true, "Escape"),
        (Module::Gdi, 53) => (16, false, "CreateDC"),
        (Module::Gdi, 54) => (8, false, "CreateEllipticRgn"),
        (Module::Gdi, 57) => (4, false, "CreateFontIndirect"),
        (Module::Gdi, 67) => (8, false, "DPtoLP"),
        (Module::Gdi, 93) => (6, false, "GetTextMetrics"),
        (Module::Gdi, 94) => (2, true, "GetViewportExt"),
        (Module::Gdi, 96) => (2, true, "GetWindowExt"),
        (Module::Gdi, 99) => (8, false, "LPtoDP"),
        (Module::Gdi, 123) => (4, false, "PlayMetaFile"),
        (Module::Gdi, 127) => (2, false, "DeleteMetaFile"),
        (Module::Gdi, 153) => (16, false, "CreateIC"),
        (Module::Gdi, 154) => (6, true, "GetNearestColor"),
        (Module::Gdi, 156) => (6, false, "CreateDiscardableBitmap"),
        (Module::Gdi, 160) => (2, false, "SetMetaFileBits"),
        (Module::Gdi, 360) => (4, false, "CreatePalette"),
        (Module::Gdi, 367) => (10, false, "AnimatePalette"),
        (Module::Gdi, 442) => (20, false, "CreateDIBitmap"),
        (Module::Gdi, 443) => (30, false, "SetDIBitsToDevice"),

        (Module::User, 45) => (2, false, "BringWindowToTop"),
        (Module::User, 50) => (8, false, "FindWindow"),
        (Module::User, 171) => (12, false, "WinHelp"),
        (Module::User, 176) => (10, false, "LoadString"),
        (Module::User, 177) => (6, false, "LoadAccelerators"),
        (Module::User, 178) => (8, false, "TranslateAccelerator"),
        (Module::User, 287) => (2, false, "GetLastActivePopup"),
        (Module::User, 420) => (0, false, "wsprintf"),

        (Module::User, 16) => (4, false, "ClipCursor"),
        (Module::User, 100) => (12, false, "DlgDirList"),
        (Module::User, 104) => (2, false, "MessageBeep"),
        (Module::User, 118) => (4, false, "RegisterWindowMessage"),
        (Module::User, 131) => (4, true, "GetClassLong"),
        (Module::User, 180) => (2, true, "GetSysColor"),
        (Module::User, 185) => (22, false, "GrayString"),
        (Module::User, 189) => (0, false, "GetSysModalWindow"),
        (Module::User, 191) => (6, false, "ChildWindowFromPoint"),
        (Module::User, 229) => (2, false, "GetTopWindow"),
        (Module::User, 240) => (14, false, "DialogBoxIndirectParam"),
        (Module::User, 249) => (2, false, "GetAsyncKeyState"),
        (Module::User, 282) => (6, false, "SelectPalette"),
        (Module::User, 283) => (2, false, "RealizePalette"),
        (Module::User, 407) => (18, false, "CreateIcon"),
        (Module::User, 430) => (8, false, "lstrcmp"),
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
    // NE segments use Win16 global-heap storage, rounded to 32 bytes. The
    // loader backs these ranges with whole pages; expose the allocation's
    // padding too, while keeping the declared DGROUP/heap layout unchanged.
    let allocated = size.div_ceil(32) * 32;
    let sel = ((ldt.len() as u16) << 3) | 7;
    ldt.push(descriptor(base, allocated as u32 - 1, code));
    Ok(sel)
}

fn selector_slots(windows: &mut WindowsState, state: &State, count: usize) -> Option<usize> {
    if count==0 || count>8192 {return None;}
    for start in state.selector_floor..=8192-count {
        if (start..start+count).all(|i| windows.ldt.get(i).copied().unwrap_or(0)==0
            && !state.selector_reservations.contains(&(i as u16*8+7))) {
            if windows.ldt.len()<start+count {windows.ldt.resize(start+count,0);}
            return Some(start);
        }
    }
    None
}
fn global_alloc<A: crate::Arch>(machine: &mut A, windows: &mut WindowsState, state: &mut State, size: u32, flags: u16) -> u32 {
    let count = size.max(1).div_ceil(65536) as usize;
    let Some(index) = selector_slots(windows,state,count) else { return 0 };
    let address = super::extra::heap_alloc(machine,windows,if flags & 0x40 != 0 {8} else {0},size);
    if address == 0 { return 0; }
    let first = index as u16 * 8 + 7;
    for i in 0..count {
        let left = size.max(1).saturating_sub(i as u32 * 65536);
        windows.ldt[index+i]=descriptor(address+i as u32*65536,left.min(65536)-1,false);
    }
    let handle = if flags & 2 != 0 { first - 1 } else { first };
    state.global_blocks.push(GlobalBlock {handle,selector:first,count,address,size,flags,locks:0});
    u32::from(handle)
}
fn global_free(windows: &mut WindowsState, state: &mut State, index: usize) {
    let block = state.global_blocks.remove(index);
    for i in 0..block.count { windows.ldt[usize::from(block.selector>>3)+i] = 0; }
    super::extra::heap_free(windows,block.address);
}
fn sync_selectors<A: crate::Arch>(machine: &mut A, windows: &WindowsState, old_len: usize) {
    const TABLE: usize = 0x7ff8_0000;
    let pages = (windows.ldt.len()*8).div_ceil(4096);
    let old_pages = (old_len*8).div_ceil(4096);
    if pages > old_pages { machine.zero(TABLE+old_pages*4096,(pages-old_pages)*4096); }
    machine.set_page_flags(TABLE/4096,pages,true,false);
    for (i,&desc) in windows.ldt.iter().enumerate() {
        let base = selector_base_from_ldt(&windows.ldt,i as u16*8+7).unwrap_or(0);
        let limit = ((desc&0xffff)|((desc>>32)&0xf0000)) as u32;
        machine.write::<u32>(TABLE+i*8,base);
        machine.write::<u32>(TABLE+i*8+4,limit);
    }
    machine.set_page_flags(TABLE/4096,pages,false,false);
    if let Ok(config) = super::export_address(&windows.modules,b"USER32",b"Retro16Config") {
        machine.write::<u32>(config as usize+24,windows.ldt.len() as u32);
    }
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
        crate::compact_dbg_println!("[win16] unsupported import {:?}.{}", module, ordinal);
        -8
    })?;
    let gate = Gate { module, ordinal, selector, offset, arg_bytes, long_result, name };
    gates.push(gate);
    Ok(gate)
}

struct LoadedModule {
    // 0: pending, 1: running (recursive loads must not reenter), 2: ready, 3: failed.
    initialized: u8,
    base: u32,
    name: Vec<u8>,
    kind: Option<Module>,
    data: Vec<u8>,
    selectors: Vec<u16>,
    references: u16,
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
    let system = join(crate::kernel::dos::c_root(), b"RETROOS/WINDOWS/SYSTEM");
    // Core facades form a private ABI with the kernel and shared PE DLLs.
    // Load them exclusively from the matched runtime, never from an app.
    // Ordinary application dependencies (e.g. COMMDLG) keep local precedence.
    let local = join(dirname(importer), &file);
    let runtime = join(&system, &file);
    let candidates = [local, runtime];
    let paths = if module(name).is_some() { &candidates[1..] } else { &candidates[..] };
    for path in paths {
        if let Ok(data) = crate::kernel::exec::load_file_resolved(path) {
            return Ok((path.clone(), data));
        }
        let rooted = [crate::kernel::dos::c_root(), path.as_slice()].concat();
        if let Ok(data) = crate::kernel::exec::load_file_resolved(&rooted) {
            return Ok((rooted, data));
        }
    }
    crate::compact_println!("Windows: missing Win16 {}", core::str::from_utf8(&file).unwrap_or("dll"));
    Err(-2)
}

fn module_segment_base(base: u32, segment: u16) -> Result<u32, i32> {
    if segment == 0 { return Err(-8); }
    base.checked_add((u32::from(segment) - 1) * SEGMENT_STRIDE).ok_or(-8)
}

fn module_allocation(modules: &[LoadedModule], segments: u16) -> Result<u32, i32> {
    let base = modules.last().map_or(MODULE_BASE, |m| m.base + m.selectors.len() as u32 * SEGMENT_STRIDE);
    let end = base.checked_add(u32::from(segments) * SEGMENT_STRIDE).ok_or(-8)?;
    if segments == 0 || end > RESOURCE_BASE { return Err(-8); }
    Ok(base)
}

fn module_segment_size(image: &ne::Image<'_>, number: u16) -> Result<usize, i32> {
    let segment = image.segment(number).map_err(|_| -8)?;
    let heap = if number == image.header.auto_data { usize::from(image.header.heap_size) } else { 0 };
    Ok(segment.alloc_size.saturating_add(heap).min(0x10000))
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
                crate::compact_dbg_println!("[win16] unsupported NE source relocation {}", kind);
                return Err(-8);
            }
        }
        if relocation.flags & 4 != 0 || next == 0xffff { break; }
        source = next;
    }
    Ok(())
}

const LOW_EXPORTS: &[(u16,&[u8],u32)] = &[
    (183,b"__0000H",0),(193,b"__0040H",0x400),
    (174,b"__A000H",0xa0000),(181,b"__B000H",0xb0000),(182,b"__B800H",0xb8000),
    (195,b"__C000H",0xc0000),(179,b"__D000H",0xd0000),
    (190,b"__E000H",0xe0000),(194,b"__F000H",0xf0000),
];
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
        if let Some((_,_,base))=LOW_EXPORTS.iter().find(|(o,n,_)|ordinal==Some(*o) || symbol.is_some_and(|s|s.eq_ignore_ascii_case(n))) {
            let index=ldt.iter().enumerate().find(|(i,desc)| **desc & (1<<47)!=0 && **desc & (1<<43)==0
                && selector_base_from_ldt(ldt,*i as u16*8+7)==Some(*base)).map(|(i,_)|i).ok_or(-8)?;
            return Ok((index as u16*8+7,0));
        }
        if symbol.is_some_and(|s|s.eq_ignore_ascii_case(b"__AHSHIFT")) {return Ok((3,0));}
        if symbol.is_some_and(|s|s.eq_ignore_ascii_case(b"__AHINCR")) {return Ok((8,0));}
        match ordinal {
            Some(113) => return Ok((3, 0)),
            Some(114) => return Ok((8, 0)),
            Some(178) => return Ok((0x0413, 0)),
            _ => {}
        }
    }
    let Some(loaded) = modules.iter().find(|loaded| loaded.name == canonical) else {
        crate::compact_dbg_println!("[win16] module {} not loaded",
            core::str::from_utf8(&canonical).unwrap_or("?"));
        return Err(-2);
    };
    let image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
    let ordinal = ordinal.or_else(|| symbol.and_then(|name| image.ordinal_by_name(name).ok()));
    let entry = match (ordinal, symbol) {
        (Some(ordinal), _) => image.entry(ordinal),
        (None, Some(symbol)) => image.entry_by_name(symbol),
        _ => return Err(-8),
    };
    let (segment, offset) = entry.map_err(|_| {
        let module = core::str::from_utf8(&canonical).unwrap_or("?");
        if let Some(ordinal) = ordinal {
            crate::compact_dbg_println!("[win16] export {}.{} not found", module, ordinal);
        } else {
            crate::compact_dbg_println!("[win16] export {}!{} not found", module,
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
            // Guest implementations (including mixed-bitness thunks) execute
            // normally. Only actual INT exports belong in the native gate map.
            return Ok((offset, selector));
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
    image_base: u32,
) -> Result<(), i32> {
    for number in 1..=image.header.segment_count {
        let segment = image.segment(number).map_err(|_| -8)?;
        let base = module_segment_base(image_base, number)?;
        for relocation in image.relocations(segment).map_err(|_| -8)? {
            let (offset, target_selector) = match &relocation.target {
                ne::Target::FpuFixup => continue,
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

#[allow(clippy::too_many_arguments)] // Shared executable launch context.
pub(super) fn exec<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    tid: usize,
    data: Vec<u8>,
    path: &[u8],
    parent_cwd: &[u8],
    launcher: Option<thread::PersonalityName>,
    cmdtail: &[u8],
) -> Result<(), i32> {
    let image = ne::Image::parse(&data).map_err(|_| -8)?;
    let header = image.header;
    let mut dos = crate::kernel::dos::new_win16(machine, (PSP_BASE >> 4) as u16);
    let mut ldt = dos.ldt[..32].to_vec();
    for &(_,_,base) in LOW_EXPORTS { selector(&mut ldt,base,65536,false)?; }
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
        // The launch boundary already resolved the VFS image name. Cwd
        // belongs to the child process, not to DLL/image path resolution.
        crate::kernel::exec::resolve_path(path, b"", &mut b).to_vec()
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
        let module_base = module_allocation(&modules, module_image.header.segment_count)?;
        for number in 1..=module_image.header.segment_count {
            let segment = module_image.segment(number).map_err(|_| -8)?;
            let base = module_segment_base(module_base, number)?;
            let size = module_segment_size(&module_image, number)?;
            machine.zero(base as usize, size);
            machine.copy_to(base as usize, module_image.segment_bytes(segment).map_err(|_| -8)?);
            module_selectors.push(selector(&mut ldt, base, size, segment.is_code())?);
        }
        let dependencies = module_image.modules().map_err(|_| -8)?;
        modules.push(LoadedModule {
            initialized: if module_image.header.entry_segment == 0 { 2 } else { 0 },
            base: module_base,
            name: canonical.clone(),
            kind: module(&canonical),
            data: module_data,
            selectors: module_selectors,
            references: 1,
        });
        pending.extend(dependencies.into_iter().map(|dependency| {
            (dependency, module_path.clone())
        }));
    }

    // Preserve the launcher's command tail in the shared PMDOS PSP.
    let tail = &cmdtail[..cmdtail.len().min(126)];
    machine.write::<u8>((PSP_BASE + 0x80) as usize, tail.len() as u8);
    machine.copy_to((PSP_BASE + 0x81) as usize, tail);
    machine.write::<u8>((PSP_BASE + 0x81) as usize + tail.len(), 0);
    // PMDOS initialized the shared PSP/JFT before NE image loading.
    machine.zero(ENV_BASE as usize, 4096);
    let psp_selector = selector(&mut ldt, PSP_BASE, 256, false)?;
    let env_selector = selector(&mut ldt, ENV_BASE, 4096, false)?;
    let resource_selector = selector(&mut ldt, RESOURCE_BASE, 0x10000, false)?;
    machine.write::<u16>((PSP_BASE + 0x2c) as usize, env_selector);
    machine.zero(RESOURCE_BASE as usize, 0x10000);
    let mut gates = Vec::new();
    // These private gates are called inside KERNEL.DLL, not through an NE
    // import relocation, so register them explicitly in the matched runtime.
    for ordinal in [426, 427] {
        imported_target(machine, &ldt, &modules, &mut gates, b"KERNEL", Some(ordinal), None)?;
    }

    relocate_image(
        machine, &image, &selectors, &modules, &ldt, &mut gates, SEGMENT_BASE,
    )?;
    for loaded in &modules {
        let module_image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
        relocate_image(
            machine, &module_image, &loaded.selectors, &modules, &ldt, &mut gates,
            loaded.base,
        )?;
    }
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
    for loaded in &modules {
        let module_image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
        for number in 1..=module_image.header.segment_count {
            let segment = module_image.segment(number).map_err(|_| -8)?;
            machine.set_page_flags(
                module_segment_base(loaded.base, number)? as usize / 4096,
                module_segment_size(&module_image, number)?.div_ceil(4096),
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
    // Window DCs now belong to guest USER. Do not reserve a numeric DC that
    // could collide with a subsequently allocated real bitmap/window context.
    windows.paint_dc = 0;
    windows.ldt = ldt;
    windows.exec_path_len = main_path.len().min(windows.exec_path.len());
    windows.exec_path[..windows.exec_path_len]
        .copy_from_slice(&main_path[..windows.exec_path_len]);
    let cwd = if parent_cwd.is_empty() {
        super::dirname(&main_path).to_vec()
    } else if parent_cwd.get(1) == Some(&b':') {
        crate::kernel::dos::dos_abs_to_vfs(&crate::kernel::exec::absolute_dos_cwd(parent_cwd)).ok_or(-2)?
    } else {
        parent_cwd.to_vec()
    };
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
    init_bridge(machine, &mut windows, &modules, &current.kernel.vcpu.regs, tid, &data, data_selector)?;
    let bridge_cs = current.kernel.vcpu.regs.code_seg();
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
        modules,
        bridge_cs,
        gates,
        instance: data_selector,
        auto_data: data_selector,
        local_next,
        local_start: local_next,
        local_blocks: Vec::new(),
        global_blocks: Vec::new(),
        selector_floor: windows.ldt.len(),
        selector_reservations: Vec::new(),
        local_end,
        psp_selector,
        env_selector,
        resource_selector,
        resource_next: 0,
        resources: Vec::new(),
    });
    // Initializers run as ordinary far calls in KERNEL.DLL on the guest stack.
    // The same runner is used by LoadLibrary; no kernel callback continuation.
    if windows.win16.as_ref().is_some_and(|s| s.modules.iter().any(|m| m.initialized == 0)) {
        let state = windows.win16.as_ref().ok_or(-8)?;
        let kernel = state.modules.iter().find(|m| m.kind == Some(Module::Kernel)).ok_or(-8)?;
        let entry = ne::Image::parse(&kernel.data).map_err(|_| -8)?.entry(428).map_err(|_| -8)?;
        let regs = &mut current.kernel.vcpu.regs;
        let stack = selector_base(&windows, regs.frame.ss as u16).ok_or(-8)? as usize;
        let sp = (regs.sp32() as u16).checked_sub(4).ok_or(-8)?;
        machine.write::<u16>(stack + sp as usize, regs.ip32() as u16);
        machine.write::<u16>(stack + sp as usize + 2, regs.code_seg());
        regs.frame.rsp = u64::from(sp);
        regs.frame.cs = u64::from(kernel.selectors[entry.0 as usize-1]);
        regs.frame.rip = u64::from(entry.1);
    }
    windows.on_resume(machine);
    dos.ldt[..windows.ldt.len()].copy_from_slice(&windows.ldt);
    for i in 0..windows.ldt.len() { dos.ldt_alloc[i / 32] |= 1 << (i % 32); }
    dos.dfs.init_from_vfs(&super::guest_windows_path(windows.cwd_str()));
    current.personality = thread::Personality::Windows(super::WindowsProcess { state: windows, dos: Some(dos) });
    Ok(())
}

/// Bind guest thunk entry points. There is no per-call kernel continuation.
fn init_bridge<A: crate::Arch>(
    machine: &mut A,
    windows: &mut WindowsState,
    modules: &[LoadedModule],
    flat: &Regs,
    tid: usize,
    image_data: &[u8],
    instance: u16,
) -> Result<(), i32> {
    let user = modules
        .iter()
        .find(|m| m.kind == Some(Module::User))
        .ok_or(-2)?;
    let image = ne::Image::parse(&user.data).map_err(|_| -8)?;
    let _binding = match image.entry(423) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    let (ret_segment, ret_offset) = image.entry(424).map_err(|_| -8)?;
    let return16 =
        (u32::from(user.selectors[ret_segment as usize - 1]) << 16) | u32::from(ret_offset);
    let (native_segment, native_offset) = image.entry(425).map_err(|_| -8)?;
    let native16 = (u32::from(user.selectors[native_segment as usize - 1]) << 16) | u32::from(native_offset);
    // The first module represents the NE executable for filename/instance
    // lookup; PE dependency mapping starts at the ordinary first DLL slot.
    windows.modules.push(super::Module {
        name: super::module_name(windows.exec_path_str()),
        path: windows.exec_path_str().to_vec(),
        data: Vec::new(),
        base: SEGMENT_BASE,
    });
    let (_, initializers) = super::load_library(machine, windows, b"USER32.DLL").map_err(|_| -8)?;
    // Our replacement DLLs have no DllMain. Do not silently skip a real DLL's.
    if !initializers.is_empty() {
        return Err(-8);
    }
    let entry = super::export_address(&windows.modules, b"USER32", b"Retro16Enter")?;
    let back = super::export_address(&windows.modules, b"USER32", b"Retro16Return")?;
    let config = super::export_address(&windows.modules, b"USER32", b"Retro16Config")?;
    let teb = super::TEB_BASE;
    machine.zero(teb as usize, 4096);
    machine.write::<u32>((teb + 0x18) as usize, teb);
    machine.write::<u32>((teb + 0x24) as usize, tid as u32 + 1);
    machine.set_page_flags(teb as usize / 4096, 1, true, false);
    let teb_selector = selector(&mut windows.ldt, teb, 4096, false)?;
    const TABLE: u32 = 0x7ff8_0000;
    let table_size = (windows.ldt.len() * 8).next_multiple_of(4096);
    machine.zero(TABLE as usize, table_size);
    for (i, &desc) in windows.ldt.iter().enumerate().skip(1) {
        let selector = (i as u16) * 8 + 7;
        let base = selector_base(windows, selector).ok_or(-8)?;
        let limit = ((desc & 0xffff) | ((desc >> 32) & 0xf0000)) as u32;
        machine.write::<u32>(TABLE as usize + i * 8, base);
        machine.write::<u32>(TABLE as usize + i * 8 + 4, limit);
    }
    machine.set_page_flags(TABLE as usize / 4096, table_size / 4096, false, false);
    windows.stack_size = 256 * 1024;
    windows.stack_base = super::STACK_TOP - windows.stack_size;
    // A read-only guard catches downward stack writes beyond the guest reserve.
    let guard = windows.stack_base as usize - 4096;
    machine.zero(guard, 4096);
    machine.set_page_flags(guard / 4096, 1, false, false);
    machine.zero(windows.stack_base as usize, windows.stack_size as usize);
    machine.set_page_flags(
        windows.stack_base as usize / 4096,
        windows.stack_size as usize / 4096,
        true,
        false,
    );
    const RESOURCE_IMAGE: u32 = 0x7000_0000;
    let image_pages = image_data.len().div_ceil(4096);
    machine.zero(RESOURCE_IMAGE as usize, image_pages * 4096);
    machine.copy_to(RESOURCE_IMAGE as usize, image_data);
    machine.set_page_flags(RESOURCE_IMAGE as usize / 4096, image_pages, false, false);
    for (i, value) in [
        flat.ds as u32,
        u32::from(teb_selector),
        super::STACK_TOP,
        0,
        TABLE,
        return16,
        windows.ldt.len() as u32,
        windows.stack_base,
        RESOURCE_IMAGE,
        image_data.len() as u32,
        u32::from(instance),
        native16,
    ]
    .into_iter()
    .enumerate()
    {
        machine.write::<u32>(config as usize + i * 4, value);
    }
    for loaded in modules {
        let image = ne::Image::parse(&loaded.data).map_err(|_| -8)?;
        let Ok((segment, offset)) = image.entry_by_name(b"RetroBridgeConfig") else {
            continue;
        };
        let code_selector = loaded.selectors[segment as usize - 1];
        let base = selector_base(windows, code_selector).ok_or(-8)?;
        let pages = image
            .segment(u16::from(segment))
            .map_err(|_| -8)?
            .alloc_size
            .div_ceil(4096);
        machine.set_page_flags(base as usize / 4096, pages, true, false);
        machine.write::<u32>((base + u32::from(offset)) as usize, entry);
        machine.write::<u16>((base + u32::from(offset) + 4) as usize, flat.code_seg());
        machine.write::<u32>((base + u32::from(offset) + 6) as usize, back);
        machine.write::<u16>((base + u32::from(offset) + 10) as usize, flat.code_seg());
        machine.set_page_flags(base as usize / 4096, pages, false, true);
    }
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
                    r | (g << 8) | (b << 16)
                }
                32 => {
                    let v = machine.read::<u32>(source_row + x * 4);
                    ((v & 0xff) << 16) | (v & 0xff00) | ((v >> 16) & 0xff)
                },
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
    r | (g << 8) | (b << 16)
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

fn local_alloc<A: crate::Arch>(machine: &mut A, windows: &WindowsState, state: &mut State, size: usize, flags: u16) -> u32 {
    let aligned = (size.max(1) + 3) & !3;
    let movable = flags & 2 != 0;
    let overhead = if movable { 4 } else { 0 };
    let mut at = (usize::from(state.local_start).max(4) + 3) & !3;
    let mut slot = 0;
    for block in &state.local_blocks {
        if at + overhead + aligned <= usize::from(block.start) { break; }
        at = usize::from(block.data) + usize::from(block.size);
        slot += 1;
    }
    if at + overhead + aligned > usize::from(state.local_end) { return 0; }
    // Movable HLOCAL values identify a handle cell (low bits 10),
    // whose word points to the four-byte-aligned data in DGROUP.
    let data = (at + overhead) as u16;
    let handle = (at + if movable { 2 } else { 0 }) as u16;
    let Some(pointer) = far_linear(windows, (u32::from(state.auto_data) << 16) | u32::from(data)) else { return 0 };
    if movable { machine.write::<u16>(pointer - 2, data); }
    if flags & 0x40 != 0 { machine.zero(pointer, aligned); }
    state.local_blocks.insert(slot, LocalBlock { start: at as u16, data, handle, size: aligned as u16, movable, locks: 0 });
    state.local_next = state.local_next.max((at + overhead + aligned) as u16);
    u32::from(handle)
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
        (Module::Kernel, 115) => {
            if let Some(text) = stack_u32(machine, windows, regs, 4)
                .and_then(|p| far_string(machine, windows, p)) {
                crate::compact_println!("{}", core::str::from_utf8(&text).unwrap_or("?"));
            }
            0
        }
        (Module::Kernel, 107) => {
            let mode = u32::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            core::mem::replace(&mut windows.error_mode, mode)
        }
        (Module::Kernel, 3) => 0x0000_0a03, // Windows 3.10
        (Module::Kernel, 4) => 1,
        (Module::Kernel, 91) => {
            // The Microsoft C startup consumes these register results before
            // it calls WinMain.
            regs.rax = u64::from(state.instance);
            // InitTask returns ES:BX pointing into the PSP command tail.
            // Returning heap capacity here makes C runtimes dereference past
            // the 256-byte PSP selector limit.
            let length = machine.read::<u8>((PSP_BASE + 0x80) as usize).min(126) as u32;
            let mut offset = if length == 0 { 0x80 } else { 0x81 };
            while offset < 0x81 + length && matches!(machine.read::<u8>((PSP_BASE + offset) as usize), b' ' | b'\t') { offset += 1; }
            machine.write::<u8>((PSP_BASE + 0x81 + length.min(126)) as usize, 0);
            regs.rbx = u64::from(offset);
            regs.rcx = 0;
            regs.rdx = 1; // SW_SHOWNORMAL, passed by the C runtime to WinMain.
            regs.rsi = 0;
            regs.rdi = u64::from(state.instance);
            regs.ds = u64::from(state.auto_data);
            regs.es = u64::from(state.psp_selector);
            1
        }
        (Module::Kernel, 5) => {
            let size = usize::from(stack_u16(machine, windows, regs, 4).unwrap_or(0));
            let flags = stack_u16(machine, windows, regs, 6).unwrap_or(0);
            local_alloc(machine, windows, state, size, flags)
        }
        (Module::Kernel, 6) => {
            let handle = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            let size = usize::from(stack_u16(machine, windows, regs, 6).unwrap_or(0));
            let flags = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let Some(index) = state.local_blocks.iter().position(|b| b.handle == handle) else { return 0 };
            if flags & 0x80 != 0 { return u32::from(handle); }
            let aligned = (size.max(1) + 3) & !3;
            let block = &state.local_blocks[index];
            let data = block.data;
            let old_size = usize::from(block.size);
            let movable = block.movable;
            let limit = state.local_blocks.get(index + 1).map_or(state.local_end, |b| b.start);
            let Some(pointer) = far_linear(windows, (u32::from(state.auto_data) << 16) | u32::from(data)) else { return 0 };
            if usize::from(data) + aligned <= usize::from(limit) {
                if flags & 0x40 != 0 && aligned > old_size { machine.zero(pointer + old_size, aligned - old_size); }
                state.local_blocks[index].size = aligned as u16;
                state.local_next = state.local_blocks.last().map_or(state.local_start, |b| b.data + b.size);
                return u32::from(handle);
            }
            if block.locks != 0 || flags & 2 == 0 { return 0; }
            let mut bytes = vec![0; old_size.min(size)];
            for (i, byte) in bytes.iter_mut().enumerate() { *byte = machine.read::<u8>(pointer + i); }
            let replacement = local_alloc(machine, windows, state, size, (flags & !2) | if movable { 2 } else { 0 });
            if replacement == 0 { return 0; }
            let new = state.local_blocks.iter().find(|b| u32::from(b.handle) == replacement).unwrap();
            let dest = far_linear(windows, (u32::from(state.auto_data) << 16) | u32::from(new.data)).unwrap();
            machine.copy_to(dest, &bytes);
            state.local_blocks.retain(|b| b.handle != handle);
            replacement
        }
        (Module::Kernel, 7) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            if handle == 0 { return 0; }
            let Some(index) = state.local_blocks.iter().position(|b| b.handle == handle) else { return u32::from(handle) };
            if state.local_blocks[index].locks != 0 { return u32::from(handle); }
            state.local_blocks.remove(index);
            state.local_next = state.local_blocks.last().map_or(state.local_start, |b| b.data + b.size);
            0
        }
        (Module::Kernel, 8) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let Some(block) = state.local_blocks.iter_mut().find(|b| b.handle == handle) else { return 0 };
            if block.movable { block.locks = block.locks.saturating_add(1); }
            (u32::from(state.auto_data) << 16) | u32::from(block.data)
        }
        (Module::Kernel, 9) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            let Some(block) = state.local_blocks.iter_mut().find(|b| b.handle == handle) else { return 0 };
            block.locks = block.locks.saturating_sub(1);
            u32::from(block.locks != 0)
        }
        (Module::Kernel, 10) => {
            let handle = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            state.local_blocks.iter().find(|b| b.handle == handle).map_or(0, |b| u32::from(b.size))
        }
        (Module::Kernel, 138) => {
            let total=u32::from(state.local_end-state.local_start);
            let used=state.local_blocks.iter().map(|b|u32::from(b.size)+if b.movable {4}else{0}).sum::<u32>();
            (total<<16)|total.saturating_sub(used)
        }
        (Module::Kernel, 15) => {
            let size = stack_u32(machine,windows,regs,4).unwrap_or(0);
            let flags = stack_u16(machine,windows,regs,8).unwrap_or(0);
            global_alloc(machine,windows,state,size,flags)
        }
        (Module::Kernel, 16) => {
            let flags = stack_u16(machine,windows,regs,4).unwrap_or(0);
            let size = stack_u32(machine,windows,regs,6).unwrap_or(0);
            let handle = stack_u16(machine,windows,regs,10).unwrap_or(0);
            let Some(index) = state.global_blocks.iter().position(|b| b.handle == handle) else { return 0 };
            if flags & 0x80 != 0 { state.global_blocks[index].flags = flags; return u32::from(handle); }
            let old = &state.global_blocks[index];
            if size <= old.size { state.global_blocks[index].size = size; return u32::from(handle); }
            if old.locks != 0 || old.flags & 2 == 0 { return 0; }
            let (address, length, original_flags) = (old.address, old.size, old.flags);
            let next = global_alloc(machine,windows,state,size,original_flags | (flags & 0x40));
            if next == 0 { return 0; }
            let new_address = state.global_blocks.last().unwrap().address;
            for i in 0..length as usize {
                let byte = machine.read::<u8>(address as usize+i);
                machine.write::<u8>(new_address as usize+i,byte);
            }
            global_free(windows,state,index);
            next
        }
        (Module::Kernel, 17..=21 | 159) => {
            let handle = stack_u16(machine,windows,regs,4).unwrap_or(0);
            let Some(index) = state.global_blocks.iter().position(|b| b.handle == handle || b.selector == handle) else {
                return 0;
            };
            let block = &mut state.global_blocks[index];
            match gate.ordinal {
                // GlobalFree releases a Win16 block even while it is locked.
                17 => { global_free(windows,state,index); 0 }
                18 => {
                    if block.flags & 2 != 0 { block.locks = block.locks.saturating_add(1); }
                    // Win16 also returns the selector in CX.
                    regs.rcx = (regs.rcx & !0xffff) | u64::from(block.selector);
                    u32::from(block.selector)<<16
                }
                19 => { block.locks = block.locks.saturating_sub(1); u32::from(block.locks != 0) }
                20 => block.size,
                _ => (u32::from(block.selector)<<16)|u32::from(block.handle),
            }
        }
        (Module::Kernel, 170 | 175 | 176 | 177) => {
            let src = stack_u16(machine,windows,regs,if gate.ordinal == 177 {6} else {4}).unwrap_or(0);
            let index = usize::from(src >> 3);
            if src != 0 && (src & 7 != 7 || index >= windows.ldt.len()) { return 0; }
            let mut desc = if src == 0 { 0 } else { windows.ldt[index] };
            match gate.ordinal {
                176 => { if src == 0 || index < state.selector_floor { return u32::from(src); } windows.ldt[index] = 0; state.selector_reservations.retain(|&s|s!=src); 0 }
                177 => {
                    let dest = stack_u16(machine,windows,regs,4).unwrap_or(0);
                    if src == 0 || dest & 7 != 7 || usize::from(dest>>3) >= windows.ldt.len() { return 0; }
                    desc ^= 1 << 43;
                    windows.ldt[usize::from(dest>>3)] = desc;
                    if desc & (1 << 43) != 0 {
                        // Executable aliases can point at generated code in
                        // global memory. Keep its data alias writable too.
                        let base = selector_base(windows, dest).unwrap() as usize;
                        let limit = ((desc & 0xffff) | ((desc >> 32) & 0xf0000)) as usize;
                        machine.set_page_flags(base / 4096, ((base % 4096) + limit + 1).div_ceil(4096), true, true);
                    }
                    u32::from(dest)
                }
                _ => {
                    if gate.ordinal == 170 { desc &= !(1 << 43); }
                    let Some(index)=selector_slots(windows,state,1) else{return 0;};
                    let sel=index as u16*8+7;
                    windows.ldt[index]=desc;
                    state.selector_reservations.push(sel);
                    u32::from(sel)
                }
            }
        }
        (Module::Kernel, 136) => {
            let drive=stack_u16(machine,windows,regs,4).unwrap_or(u16::MAX);
            if drive>=26 || !crate::kernel::dos::drive_available(b'A'+drive as u8) {0}
            else {match drive {0|1=>2,3|8=>4,_=>3}}
        }
        (Module::Kernel, 25 | 169) => machine.free_page_count().saturating_mul(4096).min(u32::MAX as usize) as u32,
        (Module::Kernel, 23 | 24 | 30 | 52) => 1,
        (Module::Kernel, 47) => {
            let p = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            if p == 0 { u32::from(state.instance) } else {
                far_string(machine, windows, p).and_then(|name| {
                    let name = canonical_module_name(&name);
                    state.modules.iter().find(|m| m.name == name).map(|m| u32::from(m.selectors[0]))
                }).unwrap_or(0)
            }
        }
        (Module::Kernel, 48) => {
            let h = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            if h == state.instance { 1 } else {
                state.modules.iter().find(|m| m.selectors.first() == Some(&h)).map_or(0, |m| u32::from(m.references))
            }
        }
        (Module::Kernel, 50) => {
            let p = stack_u32(machine, windows, regs, 4).unwrap_or(0);
            let h = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            let name = if p >> 16 == 0 { None } else { far_string(machine, windows, p) };
            let ordinal = if p >> 16 == 0 { Some(p as u16) } else { None };
            if h == state.instance {
                let Ok(image) = ne::Image::parse(&state.image) else { return 0 };
                let target = ordinal.map_or_else(|| image.entry_by_name(name.as_deref().unwrap_or(b"")), |o| image.entry(o));
                return target.ok().and_then(|(segment, offset)| {
                    let base = segment_base(u16::from(segment)).ok()?;
                    let index = (1..windows.ldt.len()).find(|&i|
                        selector_base_from_ldt(&windows.ldt, i as u16 * 8 + 7) == Some(base))?;
                    Some((((index as u32)*8+7)<<16) | u32::from(offset))
                }).unwrap_or(0);
            }
            let Some(module) = state.modules.iter().find(|m| m.selectors.first() == Some(&h)) else { return 0 };
            let module_name = module.name.clone();
            imported_target(machine, &windows.ldt, &state.modules, &mut state.gates, &module_name, ordinal, name.as_deref())
                .map_or(0, |(offset, selector)| (u32::from(selector)<<16)|u32::from(offset))
        }
        (Module::Kernel, 426) => {
            let Some(name) = stack_u32(machine, windows, regs, 4).and_then(|p| far_string(machine, windows, p)) else { return 2 };
            load_dynamic(machine, windows, state, &name).map_or_else(|e| if e == -2 {2} else {11}, u32::from)
        }
        (Module::Kernel, 427) => {
            let Some(pointer) = stack_u32(machine, windows, regs, 4) else { return 11; };
            let Some(&descriptor) = windows.ldt.get((pointer >> 19) as usize) else { return 11; };
            let limit = (descriptor & 0xffff) | ((descriptor >> 32) & 0xf0000);
            if u64::from(pointer as u16) + 11 > limit { return 11; }
            let Some(out) = far_linear(windows, pointer) else { return 11; };
            let success = stack_u16(machine, windows, regs, 8).unwrap_or(0);
            let previous = stack_u16(machine, windows, regs, 10).unwrap_or(0);
            let root = stack_u16(machine, windows, regs, 12).unwrap_or(0);
            if previous != 0 {
                let Some(m) = state.modules.iter_mut().find(|m| m.selectors.first() == Some(&previous)) else { return 11; };
                if m.initialized != 1 { return 11; }
                m.initialized = if success != 0 { 2 } else { 3 };
                if success == 0 { return 11; }
            }
            match next_initializer(state, root) {
                Ok(Some(index)) => {
                    let m = &mut state.modules[index];
                    let Ok(image) = ne::Image::parse(&m.data) else { return 11; };
                    let Some(&cs) = m.selectors.get(image.header.entry_segment.wrapping_sub(1) as usize) else { return 11; };
                    let ds = m.selectors.get(image.header.auto_data.wrapping_sub(1) as usize).copied().unwrap_or(0);
                    let instance = if ds != 0 { ds } else { m.selectors[0] };
                    let words = [image.header.entry_offset, cs, ds, image.header.heap_size, instance, m.selectors[0]];
                    for (i, word) in words.into_iter().enumerate() { machine.write::<u16>(out + i*2, word); }
                    m.initialized = 1;
                    0xffff
                }
                Ok(None) => 0,
                Err(_) => 11,
            }
        }
        (Module::Kernel, 96) => {
            let h = stack_u16(machine, windows, regs, 4).unwrap_or(0);
            if let Some(m) = state.modules.iter_mut().find(|m| m.selectors.first() == Some(&h)) {
                m.references = m.references.saturating_sub(1);
            }
            0
        }
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
                crate::compact_dbg_println!("[win16] named resource type unsupported");
                return 0;
            };
            let id = if name_pointer >> 16 == 0 { name_pointer as u16 } else {
                crate::compact_dbg_println!("[win16] named resource unsupported");
                return 0;
            };
            let Ok(image) = ne::Image::parse(&state.image) else { return 0 };
            let Ok(bytes) = image.resource(kind, id) else {
                crate::compact_dbg_println!("[win16] resource type={} id={} not found", kind, id);
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
        (Module::Kernel, 129) => 1,
        (Module::Kernel, 131) => u32::from(state.env_selector) << 16,
        (Module::Kernel, 132) => 0x0025, // protected mode, 386, enhanced mode
        (Module::User, 177) => 1,
        (Module::User, 171) => 1,
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
            let Some((width, height, bpp, _)) = dib_header(machine, header) else {
                return 0;
            };
            // The dimensions header and initialization BITMAPINFO are separate
            // arguments; the colour table belongs to the latter.
            let info = stack_u32(machine, windows, regs, 6)
                .and_then(|pointer| far_linear(windows, pointer));
            let init = stack_u32(machine, windows, regs, 14).unwrap_or(0) & 4 != 0; // CBM_INIT
            let handle = windows.next_object;
            windows.next_object = windows.next_object.wrapping_add(1);
            let mut pixels = vec![0u8; width * height * 4];
            if init {
                let Some(bits) = far_linear(windows, bits_pointer) else { return 0 };
                let Some((iw, ih, ibpp, palette_at)) = info.and_then(|p| dib_header(machine, p)) else { return 0 };
                if (iw, ih, ibpp) != (width, height, bpp) { return 0; }
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
                crate::compact_dbg_println!("[win16] SetDIBitsToDevice source={}x{}x{}", source_width, source_height, bpp);
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
            crate::compact_dbg_println!("[win16] stub {}", gate.name);
            0
        }
    }
}

#[allow(clippy::too_many_arguments)] // Shared personality dispatch context.
pub(super) fn handle_event<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    windows: &mut WindowsState,
    state: &mut State,
    dos: &mut crate::kernel::dos::DosState<A>,
    regs: &mut Regs,
    event: crate::KernelEvent,
) -> thread::KernelAction {
    match event {
        crate::KernelEvent::Irq => thread::KernelAction::Done,
        crate::KernelEvent::Hlt => crate::kernel::dos::win16_resume(machine, kt, dos, regs)
            .unwrap_or(thread::KernelAction::Done),
        crate::KernelEvent::SoftInt(0x1a) => {
            crate::kernel::dos::win16_int1a(machine, dos, regs);
            thread::KernelAction::Done
        }
        crate::KernelEvent::SoftInt(0x2f) => crate::kernel::dos::win16_multiplex(machine, dos, regs),
        crate::KernelEvent::SoftInt(0x21) => dos_call(machine, bios, kt, windows, dos, regs),
        crate::KernelEvent::SoftInt(GATE_VECTOR) => {
            let ip = regs.ip32() as u16;
            let Some(gate) = state.gates.iter().copied()
                .find(|gate| gate.selector == regs.code_seg()
                    && gate.offset.wrapping_add(2) == ip) else {
                crate::compact_dbg_println!("[win16] invalid DLL gate {:04x}:{:04x}", regs.code_seg(), ip);
                return thread::KernelAction::Exit(-1);
            };
            if gate.module == Module::Kernel && gate.ordinal == 102 {
                // Complete the FAR CALL first. PMDOS can now return or suspend
                // using the same continuation as a direct software interrupt.
                let ax = regs.rax as u32;
                if finish(machine, windows, regs, gate, ax).is_err() {
                    return thread::KernelAction::Exit(-1);
                }
                return dos_call(machine, bios, kt, windows, dos, regs);
            }
            if gate.module == Module::Kernel && gate.ordinal == 1 {
                return thread::KernelAction::Exit(stack_u16(machine, windows, regs, 4).unwrap_or(1) as i32);
            }
            if crate::kernel::startup::trace_enabled() {
                crate::compact_dbg_println!("[win16] {:?}.{} {}", gate.module, gate.ordinal, gate.name);
            }
            let old_ldt = windows.ldt.len();
            let result = dispatch(machine, kt, windows, state, regs, gate);
            if gate.module == Module::Kernel && matches!(gate.ordinal,15..=17|426|170|175..=177) {
                // Lock/unlock/size/handle queries (18..=21) only touch block
                // metadata. Rebuilding the descriptor mirror and reloading the
                // LDT for each query makes resource-heavy Win16 startup crawl.
                // Like DPMI descriptor release, clear saved data segments
                // whose selector was freed. The metal return stub reloads
                // them before IRET; reloading a deleted descriptor faults in
                // ring 0 even when the guest never uses that segment again.
                for segment in [&mut regs.ds, &mut regs.es, &mut regs.fs, &mut regs.gs] {
                    let selector = *segment as u16;
                    if selector & 4 != 0
                        && windows.ldt.get(usize::from(selector >> 3)) == Some(&0)
                    {
                        *segment = 0;
                    }
                }
                sync_selectors(machine,windows,old_ldt);
                dos.ldt[..windows.ldt.len()].copy_from_slice(&windows.ldt);
                for i in 0..windows.ldt.len() { dos.ldt_alloc[i / 32] |= 1 << (i % 32); }
                machine.load_ldt(&dos.ldt[..]);
            }
            if finish(machine, windows, regs, gate, result).is_err() {
                return thread::KernelAction::Exit(-1);
            }
            thread::KernelAction::Done
        }
        crate::KernelEvent::PageFault { .. } => unreachable!("page faults handled by event loop"),
        _ => {
            crate::compact_dbg_println!("[win16] unhandled {:?} at {:04x}:{:04x}",
                event, regs.code_seg(), regs.ip32() as u16);
            crate::compact_dbg_println!("[win16] ax={:04x} bx={:04x} cx={:04x} dx={:04x} ds={:04x} es={:04x} di={:04x}", regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.ds, regs.es, regs.rdi);
            thread::KernelAction::Exit(-1)
        }
    }
}

fn dos_call<A: crate::Arch>(
    machine: &mut A, bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>, windows: &mut WindowsState,
    dos: &mut crate::kernel::dos::DosState<A>, regs: &mut Regs,
) -> thread::KernelAction {
    let previous_cwd = super::guest_windows_path(windows.cwd_str());
    dos.dfs.init_from_vfs(&previous_cwd);
    let action = crate::kernel::dos::win16_int21(machine, bios, kt, dos, regs);
    machine.load_ldt(&dos.ldt[..]);
    let mut path = alloc::vec![b'A' + dos.dfs.current_drive_number(), b':', b'\\'];
    path.extend_from_slice(dos.dfs.get_cwd());
    if !path.eq_ignore_ascii_case(&previous_cwd)
        && let Some(cwd) = crate::kernel::dos::windows_abs_to_vfs(&path, false)
    {
        windows.cwd_len = cwd.len().min(windows.cwd.len());
        windows.cwd[..windows.cwd_len].copy_from_slice(&cwd[..windows.cwd_len]);
    }
    action
}

fn load_dynamic<A: crate::Arch>(machine: &mut A, windows: &mut WindowsState, state: &mut State, name: &[u8]) -> Result<u16, i32> {
    let name = canonical_module_name(name);
    if let Some(m) = state.modules.iter_mut().find(|m| m.name == name) {
        if m.initialized == 3 { return Err(-8); }
        m.references = m.references.saturating_add(1);
        return Ok(m.selectors[0]);
    }
    let start = state.modules.len();
    let old_ldt = windows.ldt.len();
    let old_gates = state.gates.len();
    let mut mapped = Vec::new();
    let result = (|| {
        let mut pending = vec![(name.clone(), windows.exec_path_str().to_vec())];
        let mut next = 0;
        while next < pending.len() {
            let (name, importer) = pending[next].clone(); next += 1;
            let name = canonical_module_name(&name);
            if state.modules.iter().any(|m| m.name == name) { continue; }
            let (path, data) = load_module_file(&name, &importer)?;
            let image = ne::Image::parse(&data).map_err(|_| -8)?;
            let mut selectors = Vec::new();
            let module_base = module_allocation(&state.modules, image.header.segment_count)?;
            for n in 1..=image.header.segment_count {
                let segment = image.segment(n).map_err(|_| -8)?;
                let base = module_segment_base(module_base, n)?;
                let size = module_segment_size(&image, n)?;
                mapped.push((base as usize / 4096, size.div_ceil(4096)));
                machine.set_page_flags(base as usize/4096, size.div_ceil(4096), true, false);
                machine.zero(base as usize, size);
                machine.copy_to(base as usize, image.segment_bytes(segment).map_err(|_| -8)?);
                selectors.push(selector(&mut windows.ldt, base, size, segment.is_code())?);
            }
            let dependencies = image.modules().map_err(|_| -8)?;
            state.modules.push(LoadedModule { initialized: if image.header.entry_segment == 0 { 2 } else { 0 }, base: module_base, kind: module(&name), name, data, selectors, references: 1 });
            pending.extend(dependencies.into_iter().map(|dep| (dep, path.clone())));
        }
        let entry = super::export_address(&windows.modules, b"USER32", b"Retro16Enter")?;
        let back = super::export_address(&windows.modules, b"USER32", b"Retro16Return")?;
        for index in start..state.modules.len() {
            let m = &state.modules[index];
            let image = ne::Image::parse(&m.data).map_err(|_| -8)?;
            relocate_image(machine, &image, &m.selectors, &state.modules, &windows.ldt, &mut state.gates, m.base)?;
            if let Ok((segment, offset)) = image.entry_by_name(b"RetroBridgeConfig") {
                let base = selector_base(windows, m.selectors[segment as usize-1]).ok_or(-8)?;
                machine.write::<u32>((base+u32::from(offset)) as usize, entry);
                machine.write::<u16>((base+u32::from(offset)+4) as usize, state.bridge_cs);
                machine.write::<u32>((base+u32::from(offset)+6) as usize, back);
                machine.write::<u16>((base+u32::from(offset)+10) as usize, state.bridge_cs);
            }
            for n in 1..=image.header.segment_count {
                let seg = image.segment(n).map_err(|_| -8)?;
                machine.set_page_flags(module_segment_base(m.base,n)? as usize/4096, module_segment_size(&image, n)?.div_ceil(4096), !seg.is_code(), seg.is_code());
            }
        }
        // Extend the guest selector translation table without reinitializing USER state.
        const TABLE: usize = 0x7ff8_0000;
        let pages = (windows.ldt.len()*8).div_ceil(4096);
        let old_pages = (old_ldt*8).div_ceil(4096);
        if pages > old_pages { machine.zero(TABLE+old_pages*4096, (pages-old_pages)*4096); }
        machine.set_page_flags(TABLE/4096, pages, true, false);
        for i in old_ldt..windows.ldt.len() {
            let desc = windows.ldt[i];
            let base = selector_base(windows, i as u16*8+7).ok_or(-8)?;
            machine.write::<u32>(TABLE+i*8, base);
            machine.write::<u32>(TABLE+i*8+4, ((desc&0xffff)|((desc>>32)&0xf0000)) as u32);
        }
        machine.set_page_flags(TABLE/4096, pages, false, false);
        let config = super::export_address(&windows.modules, b"USER32", b"Retro16Config")?;
        machine.write::<u32>(config as usize+24, windows.ldt.len() as u32);
        Ok(state.modules[start].selectors[0])
    })();
    if result.is_err() {
        for (base, count) in mapped { machine.unmap_range(base, count); }
        state.modules.truncate(start);
        state.gates.truncate(old_gates);
        windows.ldt.truncate(old_ldt);
    }
    result
}

/// Dependency-first initialization. A running module breaks a dependency cycle
/// and permits a DLL to call LoadLibrary recursively from its own LibMain.
fn next_initializer(state: &State, root: u16) -> Result<Option<usize>, i32> {
    fn visit(state: &State, index: usize, seen: &mut Vec<usize>) -> Result<Option<usize>, i32> {
        let m = &state.modules[index];
        if m.initialized == 3 { return Err(-8); }
        if m.initialized == 1 || seen.contains(&index) { return Ok(None); }
        seen.push(index);
        let image = ne::Image::parse(&m.data).map_err(|_| -8)?;
        for name in image.modules().map_err(|_| -8)? {
            let name = canonical_module_name(&name);
            let dependency = state.modules.iter().position(|m| m.name == name).ok_or(-2)?;
            if let Some(next) = visit(state, dependency, seen)? { return Ok(Some(next)); }
        }
        Ok((m.initialized == 0).then_some(index))
    }
    let mut seen = Vec::new();
    if root == 0 {
        for index in 0..state.modules.len() {
            if let Some(next) = visit(state, index, &mut seen)? { return Ok(Some(next)); }
        }
        Ok(None)
    } else {
        let index = state.modules.iter().position(|m| m.selectors.first() == Some(&root)).ok_or(-2)?;
        visit(state, index, &mut seen)
    }
}
