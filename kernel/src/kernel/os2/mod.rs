//! Native 32-bit OS/2 application personality.
//!
//! Applications and compatibility DLLs are ordinary LX modules. DOSCALLS is
//! a tiny replacement DLL whose exports are consecutive two-byte `INT 82h`
//! gates; all service implementation lives here in Rust.

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
    DosQueryDBCSEnv, KbdCharIn, VioGetConfig,
}

#[derive(Clone, Copy)]
struct Gate {
    cs: u16,
    return_ip: u32,
    api: Api,
    far16_args: u16,
}

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
                    if within.checked_add(bytes.len() as u32).ok_or(8)? > object.size {
                        return Err(8);
                    }
                    machine.copy_to(base + within as usize, bytes);
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

    for module in &modules { map_module(machine, module)?; }
    for index in 0..modules.len() { apply_fixups(machine, &modules, index)?; }

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
        (b"NLS", b"DosQueryDBCSEnv", Api::DosQueryDBCSEnv, 0),
        (b"KBDCALLS", b"KbdCharIn", Api::KbdCharIn, 6),
        (b"VIOCALLS", b"VioGetConfig", Api::VioGetConfig, 6),
    ];
    for &(module_name, export_name, api, far16_args) in gate_specs {
        // A process only needs gates for DLLs in its own import closure. For
        // example, a small stdio program imports DOSCALLS but no KBD/VIO/NLS
        // module; those absent optional modules are not a load failure.
        let Some(mi) = find_module(&modules, module_name) else { continue; };
        let target = resolve_export(&modules, mi, None, Some(export_name))?;
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
        Api::DosAllocMem => {
            let out = arg32(machine, regs, 0) as usize;
            let size = arg32(machine, regs, 1).max(1).next_multiple_of(4096);
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
            if count.checked_mul(4).map_or(true, |n| n > size) { return ERROR_INVALID_PARAMETER; }
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
                api => {
                    let result = dispatch_api(machine, kt, state, regs, api);
                    finish_gate(machine, regs, gate, result);
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
    fn gate_is_identified_by_selector_and_return_ip() {
        let mut state = Os2State::new();
        state.gates.push(Gate { cs: arch_abi::USER_CS, return_ip: 0x1002, api: Api::DosExit, far16_args: 0 });
        assert_eq!(gate_from_event(&state, arch_abi::USER_CS, 0x1002).map(|g| g.api), Some(Api::DosExit));
        assert!(gate_from_event(&state, arch_abi::USER_DS, 0x1002).is_none());
        assert!(gate_from_event(&state, arch_abi::USER_CS, 0x1003).is_none());
    }
}
