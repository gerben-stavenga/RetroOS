//! DOS/DPMI personality — MS-DOS compatible execution environment with a
//! DPMI 0.9 host layered on top.
//!
//! Built on top of the `machine` layer which owns the virtual 8259/8253/8042
//! and VGA register set, and `arch::monitor` which decodes #GP-faulting
//! sensitive instructions. This module provides the public surface; the
//! INT-handler implementation lives in `dos.rs`, the DPMI extender in
//! `dpmi.rs`, the VFS bridge in `dfs.rs`, the virtual PC machine in
//! `machine.rs`, and XMS/EMS/UMA in their own files.
//!
//! The BIOS ROM at 0xF0000-0xFFFFF and the BIOS IVT at 0x0000-0x03FF are
//! preserved from the original hardware state (via COW page 0). BIOS handlers
//! work transparently because their I/O instructions trap through the TSS IOPB
//! to our virtual devices in the `machine` module.

extern crate alloc;

/// Trace DOS/DPMI calls when enabled.
/// Compile-time master kill switch; constant-fold removes all trace calls
/// when false.
const DOS_TRACE: bool = false;
const DOS_TRACE_HW_IRG: bool = false;

/// Runtime trace gate, toggled by INT 31h synth AH=02 (on) / AH=03 (off).
/// Lets COMMAND.COM bracket a single exec so the log only captures that
/// child program, not surrounding shell/launcher noise. Default OFF so
/// boot/init/DN startup are silent until something explicitly enables it.
static DOS_TRACE_RT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Independent gate for hardware-IRQ-vector trace lines (timer 0x08, key 0x09,
/// etc). Default OFF so a noisy timer tick doesn't drown the per-call DPMI
/// trace. Toggled by INT 31h synth AH=04 (on) / AH=05 (off). Both gates
/// (general + HW) must be ON for an HW-vector trace to fire.
pub(crate) static DOS_TRACE_HW_RT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Single-step tracing budget. Armed by specific DPMI handlers to watch the
/// client's code path right after a suspicious return. Decremented on each
/// PM `#DB`; at zero, tracing stops and TF is cleared.
pub(crate) static PM_STEP_BUDGET: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Log one PM step: CS:EIP + key regs, plus the first few opcode bytes.
pub(crate) fn pm_step_log(regs: &crate::Regs) {
    let is_vm86 = regs.frame.rflags & (1u64 << 17) != 0;
    let (cs_base, mode) = if is_vm86 {
        ((regs.code_seg() as u32) << 4, "RM")
    } else {
        let cs = regs.code_seg();
        let m = if crate::arch::monitor::seg_is_32(cs) { "PM32" } else { "PM16" };
        (crate::arch::monitor::seg_base(cs), m)
    };
    let ip = if mode == "PM32" { regs.ip32() } else { regs.ip32() & 0xFFFF };
    let lin = cs_base.wrapping_add(ip);
    let mut b = [0u8; 8];
    for i in 0..8 {
        b[i] = unsafe { core::ptr::read_volatile((lin + i as u32) as *const u8) };
    }
    crate::dbg_println!(
        "[STEP {}] {:04X}:{:08X} op={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} EAX={:08X} EBX={:08X} ECX={:08X} EDX={:08X} ESI={:08X} EDI={:08X} EBP={:08X} SS:SP={:04X}:{:08X} DS={:04X} ES={:04X}",
        mode, regs.code_seg(), ip,
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
        regs.rsi as u32, regs.rdi as u32, regs.rbp as u32,
        regs.frame.ss as u16, regs.sp32(),
        regs.ds as u16, regs.es as u16,
    );
}

/// Returns true if a trace line should fire. Folds away to `false` when the
/// compile-time `DOS_TRACE` master switch is off, so disabled traces cost
/// nothing in the binary.
#[inline]
fn should_trace() -> bool {
    DOS_TRACE && DOS_TRACE_RT.load(core::sync::atomic::Ordering::Relaxed)
}

macro_rules! dos_trace {
    (force $($arg:tt)*) => {
        if crate::kernel::dos::DOS_TRACE_HW_RT.load(core::sync::atomic::Ordering::Relaxed) {
            $crate::dbg_println!($($arg)*);
        }
    };
    ($($arg:tt)*) => {
        if crate::kernel::dos::should_trace() {
            $crate::dbg_println!($($arg)*);
        }
    };
}
pub(crate) use dos_trace;

mod dpmi;
mod dfs;
mod machine;
mod xms;
mod ems;
mod dos;

// Stub array / slot table / IRQ-stack constants live in `dos.rs` (alongside
// the INT handlers that own them); the `dpmi` sibling module also reads them
// when wiring PM↔RM control flow. Re-import here so both can write
// `crate::kernel::dos::STUB_BASE` (etc.) regardless of which submodule
// physically defines the constant.
#[allow(unused_imports)]
use dos::{
    STUB_BASE, STUB_SEG,
    SLOT_RM_IRET_REFLECT, SLOT_RM_IRET_CALL, SLOT_RAW_REAL_TO_PM,
    SLOT_CB_ENTRY_BASE, SLOT_CB_ENTRY_END,
    SLOT_SAVE_RESTORE, SLOT_EXCEPTION_RET, SLOT_PM_TO_REAL,
    SLOT_PM_IRET,
    slot_offset,
    host_stack_base, host_stack_size,
};

use crate::kernel::thread;
use crate::vga;
use crate::Regs;

/// DOS-specific thread state: virtual hardware machine + DOS personality + optional DPMI.
///
/// Split into three logical groups:
///   - `pc`: PC machine virtualization (policy-free peripherals — vpic/vpit/vkbd/vga,
///     A20 gate, HMA pages, skip_irq latch, e0 scancode-prefix latch). Shared by
///     both the DOS personality and DPMI.
///   - DOS personality fields (flattened): PSP tracking, DTA, heap/free segment,
///     XMS/EMS state, FindFirst/FindNext state, exec-parent chain.
///   - `dpmi`: optional DPMI protected-mode state (LDT, memory blocks, callbacks).
pub struct DosState {
    /// Policy-free PC machine state: virtual 8259 PIC, 8253 PIT, PS/2 keyboard,
    /// VGA register set, A20 gate, HMA page tracking.
    pub pc: machine::PcMachine,

    pub dta: u32,
    pub heap_seg: u16,
    pub heap_base_seg: u16,
    pub alloc_strategy: u16,
    pub umb_link_state: u16,
    /// Current PSP segment as seen by INT 21h/AH=50h (set), 51h (get), 62h (get).
    pub current_psp: u16,
    pub dos_pending_char: Option<u8>,
    /// Last child termination status (INT 21h/AH=4Dh): AL = code, AH = type.
    pub last_child_exit_status: u16,
    pub exec_parent: Option<ExecParent>,
    pub xms: Option<alloc::boxed::Box<xms::XmsState>>,
    pub ems: Option<alloc::boxed::Box<ems::EmsState>>,
    /// FindFirst/FindNext search state (per-thread, one active enumeration).
    pub find_path: [u8; 96],
    pub find_path_len: u8,
    pub find_idx: u16,

    /// DOS File System wrapper — sole DOS↔VFS translator.
    /// Tracks cwd in DOS form (uppercase, backslashes, no drive/root).
    pub dfs: dfs::DfsState,
    pub dos_blocks: alloc::vec::Vec<DosMemBlock>,

    /// PMDOS infrastructure — always present, independent of whether a DPMI
    /// client has entered. Hosts the LDT (with kernel-owned slots populated
    /// at thread init) and the PM interrupt-vector table (default-filled with
    /// vector-stub entries). A DPMI client layers its CLIENT_CS/DS/SS plus
    /// dynamic allocations on top; `dos.dpmi.is_some()` marks that layering.
    pub ldt: alloc::boxed::Box<[u64; dpmi::LDT_ENTRIES]>,
    pub ldt_alloc: [u32; dpmi::LDT_ENTRIES / 32],
    pub pm_vectors: [(u16, u32); 256],

    pub dpmi: Option<alloc::boxed::Box<dpmi::DpmiState>>,
}

#[derive(Clone, Copy)]
pub struct DosMemBlock {
    pub seg: u16,
    pub paras: u16,
}

/// Allocate a zero-filled LDT on the heap. 64KB; we use a `vec![0; N]` route
/// because `Box::new([0u64; N])` materializes the array on the stack first
/// and overflows the kernel stack, whereas `vec!` uses the `alloc_zeroed`
/// specialization for primitives and never touches the stack.
pub(crate) fn fresh_ldt() -> alloc::boxed::Box<[u64; dpmi::LDT_ENTRIES]> {
    alloc::vec![0u64; dpmi::LDT_ENTRIES]
        .into_boxed_slice()
        .try_into()
        .ok()
        .expect("LDT size mismatch")
}

impl DosState {
    pub fn new() -> Self {
        let ldt = fresh_ldt();
        let mut dos = DosState {
            pc: machine::PcMachine::new(),
            dta: 0,
            heap_seg: 0xA000,
            heap_base_seg: 0xA000,
            alloc_strategy: 0,
            umb_link_state: 0,
            current_psp: dos::heap_start() + 0x10,
            dos_pending_char: None,
            last_child_exit_status: 0,
            exec_parent: None,
            xms: None,
            ems: None,
            find_path: [0; 96],
            find_path_len: 0,
            find_idx: 0,
            dfs: dfs::DfsState::new(),
            dos_blocks: alloc::vec::Vec::new(),
            ldt,
            ldt_alloc: [0u32; dpmi::LDT_ENTRIES / 32],
            pm_vectors: [(0, 0); 256],
            dpmi: None,
        };
        dpmi::install_kernel_ldt_slots(&mut dos);
        dos
    }

    /// Process a raw PS/2 scancode — queue as virtual keyboard IRQ.
    pub fn process_key(&mut self, scancode: u8) {
        machine::queue_irq(&mut self.pc, crate::arch::Irq::Key(scancode));
    }

    /// Per-thread cleanup at exit: persist VGA, free EMS-backed pages, drop
    /// XMS/EMS state, restore A20. Called from `thread::exit_thread`.
    pub fn on_exit(&mut self) {
        self.pc.vga.save_from_hardware();
        if let Some(ref mut ems) = self.ems {
            ems.free_all_pages();
        }
        self.ems = None;
        self.xms = None;
        self.pc.set_a20(true);
    }

    /// Called by the context-switch code when this thread becomes the running
    /// DOS thread. Encapsulates any per-resume side effects (right now: point
    /// LDTR at this thread's LDT). Keeps the LDT layout private to the dos
    /// module — external code never touches `self.ldt`.
    pub fn on_resume(&self) {
        let ldt_ptr = self.ldt.as_ptr() as u32;
        let ldt_limit = (dpmi::LDT_ENTRIES * 8 - 1) as u32;
        crate::kernel::startup::arch_load_ldt(ldt_ptr, ldt_limit);
    }
}

/// Saved parent state for returning from EXEC'd child.
/// Chained via `prev` so nested exec works (e.g. DN.COM→DN.PRG→gfx.com).
pub struct ExecParent {
    pub ss: u16,
    pub sp: u16,
    pub ds: u16,
    pub es: u16,
    pub heap_seg: u16,
    pub heap_base_seg: u16,
    pub psp: u16,
    pub dos_blocks: alloc::vec::Vec<DosMemBlock>,
    /// Parent's DPMI state, suspended during child execution. Per DPMI 0.9:
    /// each DPMI client has independent state (LDT, pm_vectors, etc.); a
    /// DPMI parent's state must not be observable to a (non-DPMI) child.
    /// Restored on `exec_return`. A child that itself enters DPMI allocates
    /// its own DpmiState (independent of parent's, dropped on child exit).
    pub dpmi: Option<alloc::boxed::Box<dpmi::DpmiState>>,
    /// Parent's PM interrupt-vector table, suspended alongside dpmi so the
    /// child sees the default (reflect-to-RM) stubs for every vector. The
    /// child may install its own hooks (e.g. it enters DPMI itself) and those
    /// get dropped here on return; parent's hooks are reinstated by
    /// `exec_return`.
    pub pm_vectors: [(u16, u32); 256],
    /// Parent's LDT + alloc bitmap. Swapped out on EXEC so the child starts
    /// with a clean (kernel-slots-only) LDT and can't observe or clobber
    /// parent's dynamic selector allocations. Swapping the box is cheap; only
    /// the fresh child-LDT allocation happens in the EXEC fast path.
    pub ldt: alloc::boxed::Box<[u64; dpmi::LDT_ENTRIES]>,
    pub ldt_alloc: [u32; dpmi::LDT_ENTRIES / 32],
    pub prev: Option<alloc::boxed::Box<ExecParent>>,
}

/// Translate a `seg:off` client pointer to a flat linear address.
///
/// All callers run inside our DOS handlers (`int_21h` etc.), reached via
/// the V86 dispatch — both real V86 callers (DOS .COM/.EXE) and PM
/// callers reflected through `reflect_int_to_real_mode`. By the time we
/// reach a handler the regs are VM86, so `seg` is a paragraph.
///
/// Per `feedback_dpmi_host_no_seg_xlate`, the DPMI host doesn't translate
/// PM selectors during reflection — that's the extender/client's
/// responsibility. We don't second-guess `seg` based on saved PM state.
#[inline]
fn linear(_dos: &thread::DosState, _regs: &Regs, seg: u16, off: u32) -> u32 {
    ((seg as u32) << 4).wrapping_add(off & 0xFFFF)
}

/// INT 31h is the kernel's unified syscall trap. Every kernel-owned exit
/// trampoline ends in `CD 31`, and PM clients also raise `INT 31h` directly
/// to call the DPMI services API. Mode + CS is the discriminator:
///
/// | Mode | CS                | Routes to                     | Slot space                          |
/// |------|-------------------|-------------------------------|-------------------------------------|
/// | VM86 | `STUB_SEG`        | `dos::rm_stub_dispatch`       | RM IVT redirects + far-call entries |
/// | VM86 | else              | `dos::synth_dispatch`         | Synth INT 31h (AH-dispatched)       |
/// | PM   | `VECTOR_STUB`     | `dpmi::vector_stub_reflect`   | Per-vector default reflection       |
/// | PM   | `SPECIAL_STUB`    | `dpmi::pm_stub_dispatch`      | PM host-stub return trampolines     |
/// | PM   | client selector   | `dpmi::dpmi_api`              | DPMI services (by AX)               |
///
/// Lives at the personality root because INT 31h spans both submodules
/// (RM-side stubs in `dos.rs`, PM-side stubs + DPMI API in `dpmi.rs`).
pub fn syscall(
    kt: &mut thread::KernelThread,
    dos: &mut thread::DosState,
    regs: &mut Regs,
) -> thread::KernelAction {
    use crate::UserMode;
    let mode = regs.mode();
    let cs = if mode == UserMode::VM86 { machine::vm86_cs(regs) } else { regs.code_seg() };
    match (mode, cs) {
        (UserMode::VM86, dos::STUB_SEG)         => dos::rm_stub_dispatch(kt, dos, regs),
        (UserMode::VM86, _)                     => dos::rm_native_syscall(kt, dos, regs),
        (_, dpmi::VECTOR_STUB_SEL)              => dpmi::vector_stub_reflect(dos, regs),
        (_, dpmi::SPECIAL_STUB_SEL)             => dpmi::pm_stub_dispatch(dos, regs),
        _                                       => dpmi::dpmi_api(dos, regs),
    }
}

/// Single entry point the event loop calls for the DOS personality.
/// All DOS/DPMI-specific knowledge (VM86 INT routing, DPMI INT 31, soft INT
/// reflection, In/Out/Ins/Outs port virtualization, exception → DPMI exception
/// handler, GP-fault classification) lives here, not in `startup.rs`.
///
/// `PageFault` is excluded — the loop handles it inline because it needs
/// access to the full `Thread` (for `signal_thread`).
pub fn handle_event(
    kt: &mut thread::KernelThread,
    dos: &mut thread::DosState,
    regs: &mut Regs,
    kevent: crate::arch::monitor::KernelEvent,
) -> thread::KernelAction {
    use crate::arch::monitor::KernelEvent as KE;

    let is_vm86 = regs.mode() == crate::UserMode::VM86;
    match kevent {
        KE::Irq => thread::KernelAction::Done,
        KE::Hlt => thread::KernelAction::Yield,
        KE::SoftInt(n) => {
            if n == 0x31 {
                // Kernel syscall — `syscall` branches on mode + CS to reach
                // the right RM/PM dispatcher. Runs even on non-DPMI threads
                // (HW-IRQ default reflection lands here too).
                syscall(kt, dos, regs)
            } else {
                // Invariants: VM86 only ever traps INT 31h (only entry in
                // the TSS bitmap), and the only path into PM is DPMI. So a
                // non-31 SoftInt here is necessarily a PM client soft INT
                // delivered through an active DPMI session.
                assert!(!is_vm86,
                    "VM86 SoftInt({:#x}) bubbled to dos — only INT 31h should trap", n);
                assert!(dos.dpmi.is_some(),
                    "PM SoftInt({:#x}) without an active DPMI session", n);
                dpmi::dpmi_soft_int(kt, dos, regs, n)
            }
        }
        KE::In { port, size } => {
            machine::handle_in_event(&mut dos.pc, regs, port, size.bytes());
            thread::KernelAction::Done
        }
        KE::Out { port, size } => {
            machine::handle_out_event(&mut dos.pc, regs, port, size.bytes());
            thread::KernelAction::Done
        }
        KE::Ins { size } => {
            machine::handle_ins_event(&mut dos.pc, regs, size.bytes());
            thread::KernelAction::Done
        }
        KE::Outs { size } => {
            machine::handle_outs_event(&mut dos.pc, regs, size.bytes());
            thread::KernelAction::Done
        }
        KE::Exception(n) => {
            if dos.dpmi.is_some() {
                dpmi::dispatch_dpmi_exception(dos, regs, n as u32)
            } else {
                crate::println!("DOS: CPU exception {} in non-DPMI thread at CS:EIP={:#x}:{:#x}",
                    n, regs.code_seg(), regs.ip32());
                thread::KernelAction::Exit(-11)
            }
        }
        KE::Fault => {
            if is_vm86 {
                let lin = (regs.code_seg() as u32) * 16 + regs.ip32() as u16 as u32;
                let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
                panic!("VM86: unhandled opcode at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                    regs.code_seg(), regs.ip32() as u16, lin,
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]);
            } else if dos.dpmi.is_some() {
                dpmi::dispatch_dpmi_exception(dos, regs, 13)
            } else {
                thread::KernelAction::Exit(-11)
            }
        }
        KE::PageFault { .. } => unreachable!("PageFault handled in event loop"),
    }
}

/// Initialize a thread for VM86 mode (.COM/.EXE execution).
/// `cwd` is the parent's cwd in VFS form (lowercase, forward-slash); used to
/// seed `DfsState`. Pass `&[]` for an initial load with no parent.
/// cs/ip/ss/sp are real-mode segment:offset values.
fn init_process_thread_vm86(thread: &mut thread::Thread, psp_seg: u16, cs: u16, ip: u16, ss: u16, sp: u16, cwd: &[u8]) {
    use machine::{VM_FLAG, IF_FLAG, VIF_FLAG};
    let mut dos_state = DosState::new();
    dos_state.dfs.init_from_vfs(cwd);
    thread.personality = thread::Personality::Dos(dos_state);

    let state = &mut thread.kernel.cpu_state;
    *state = Regs::empty();

    state.ds = psp_seg as u64;
    state.es = psp_seg as u64;
    state.fs = 0;
    state.gs = 0;

    state.frame = crate::Frame64 {
        rip: ip as u64,
        cs: cs as u64,
        rflags: (VM_FLAG | IF_FLAG | VIF_FLAG | 0x1000) as u64,
        rsp: sp as u64,
        ss: ss as u64,
    };
}

/// Load a DOS binary (.COM or .EXE) and initialize the thread for VM86 mode.
/// Handles full address space setup: clean + low mem + IVT + binary load + thread init.
/// Called from kernel exec fan-out. `parent_env_data` is the parent's env block
/// snapshot (taken before the address space was torn down), or None for an
/// initial load with no parent (synthesizes default COMSPEC/PATH).
pub fn exec_dos_into(tid: usize, data: &[u8], is_exe: bool, prog_name: &[u8], cmdtail: &[u8], parent_env_data: Option<&[u8]>, parent_cwd: &[u8]) {
    use crate::kernel::startup;

    startup::arch_user_clean();
    startup::arch_map_low_mem();
    dos::setup_ivt();

    // prog_name is VFS-form (from exec fan-out); convert to drive-qualified
    // DOS form for the PSP environment suffix. DOS extenders parse that
    // field back, so it must look like "C:\BIN\PROG.EXE".
    let mut dos_name = [0u8; dfs::DFS_PATH_MAX];
    let dos_len = dfs::vfs_to_dos(prog_name, &mut dos_name);
    let dos_name = &dos_name[..dos_len];

    // Parent: either an env snapshot (with sys's PSP as the segment, since
    // the actual parent is not in this address space) or just sys.
    let parent = match parent_env_data {
        Some(env) => dos::ParentRef { psp_seg: dos::sys_psp_seg(), env },
        None => dos::sys_program().as_parent(),
    };
    let loaded = if is_exe && dos::is_mz_exe(data) {
        dos::load_exe(dos::heap_start(), &parent, data, dos_name).unwrap_or_else(|| {
            panic!("Invalid MZ EXE");
        })
    } else {
        dos::load_com(dos::heap_start(), &parent, data, dos_name)
    };
    loaded.program.set_cmdline(cmdtail);

    let psp_seg = loaded.program.psp_seg();
    let end_seg = loaded.end_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    let current = thread::get_thread(tid).unwrap();
    init_process_thread_vm86(current, psp_seg, cs, ip, ss, sp, parent_cwd);
    let dos_state = current.dos_mut();
    dos_reset_blocks(dos_state, end_seg);
    dos_state.dta = (psp_seg as u32) * 16 + 0x80;
    current.kernel.symbols = None;
}

/// Set up the initial DOS thread for a fresh program load (no parent).
/// Used by the boot/init path; fork+exec uses `exec_dos_into` instead.
/// Returns the new tid; caller drives the event loop.
pub fn run_init_program(buf: &[u8], path: &[u8], cmdline_tail: &[u8], cwd: &[u8]) -> usize {
    use crate::kernel::startup;

    let t = thread::create_thread(None, crate::RootPageTable::empty(), true)
        .expect("Failed to create DOS thread");
    let tid = t.kernel.tid as usize;

    startup::arch_map_low_mem();
    dos::setup_ivt();

    let mut dos_name = [0u8; dfs::DFS_PATH_MAX];
    let dos_len = dfs::vfs_to_dos(path, &mut dos_name);
    let dos_name = &dos_name[..dos_len];

    let parent = dos::sys_program().as_parent();
    let loaded = if dos::is_mz_exe(buf) {
        dos::load_exe(dos::heap_start(), &parent, buf, dos_name).expect("load_exe failed")
    } else {
        dos::load_com(dos::heap_start(), &parent, buf, dos_name)
    };

    let psp_seg = loaded.program.psp_seg();
    let end_seg = loaded.end_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    init_process_thread_vm86(t, psp_seg, cs, ip, ss, sp, cwd);
    let dos_state = t.dos_mut();
    dos_state.heap_seg = end_seg;
    dos_state.dta = (psp_seg as u32) * 16 + 0x80;

    loaded.program.set_cmdline(cmdline_tail);

    let (col, row) = vga::vga().cursor_pos();
    unsafe {
        core::ptr::write_volatile(0x450 as *mut u8, col as u8);
        core::ptr::write_volatile(0x451 as *mut u8, row as u8);
    }
    unsafe { *(&raw mut crate::arch::REGS) = t.kernel.cpu_state; }
    // Initial thread never goes through a context switch, so load LDTR
    // directly here. Subsequent threads pick this up via `on_resume` in the
    // event-loop switch path.
    t.dos_mut().on_resume();
    tid
}

/// Snapshot a DOS env block (variable strings up to and including the
/// `00 00` terminator) into a heap Vec. Used so the parent's env survives
/// the COW fork's address-space teardown that happens before `map_psp` runs
/// in the child.
fn snapshot_env(env_seg: u16) -> alloc::vec::Vec<u8> {
    let src = ((env_seg as usize) << 4) as *const u8;
    let mut out = alloc::vec::Vec::new();
    let mut prev_was_nul = false;
    let mut i = 0usize;
    while i < 32768 {
        let b = unsafe { *src.add(i) };
        out.push(b);
        i += 1;
        if b == 0 && prev_was_nul { break; }
        prev_was_nul = b == 0;
    }
    out
}

/// Snapshot the parent's DOS environment block for fork+exec inheritance.
/// In PM, `current_psp == PSP_SEL` and the env paragraph lives in `dpmi.saved_rm_env`
/// (PSP[0x2C] may have been patched with an env selector). In RM, PSP[0x2C] is
/// authoritative.
pub fn snapshot_parent_env(dos: &thread::DosState) -> alloc::vec::Vec<u8> {
    let psp_seg = dos.current_psp;
    let env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if psp_seg == dpmi::PSP_SEL => dpmi.saved_rm_env,
        _ => dos::program_at(psp_seg).psp.env_seg,
    };
    snapshot_env(env_seg)
}

/// F12 / panic dump: print DPMI LDT entries and PM stack/code bytes.
/// No-op when the thread isn't a DPMI client.
pub fn dump_dpmi_state(dos: &thread::DosState, regs: &Regs) {
    if dos.dpmi.is_none() { return; }
    for (name, sel) in [
        ("CS", regs.code_seg()), ("SS", regs.stack_seg()),
        ("DS", regs.ds as u16), ("ES", regs.es as u16),
        ("FS", regs.fs as u16), ("GS", regs.gs as u16),
    ] {
        if sel == 0 { continue; }
        if sel & 4 == 0 { continue; }
        let idx = (sel >> 3) as usize;
        if idx >= dos.ldt.len() { continue; }
        let raw = dos.ldt[idx];
        let base = dpmi::DpmiState::desc_base(raw);
        let limit = dpmi::DpmiState::desc_limit(raw);
        crate::dbg_println!("[DBG] LDT {}={:04X} idx={} base={:08X} limit={:08X} raw={:016X}",
            name, sel, idx, base, limit, raw);
    }
    let cs_base = dpmi::seg_base(&dos.ldt[..], regs.code_seg());
    let ss_base = dpmi::seg_base(&dos.ldt[..], regs.stack_seg());
    let cs_32 = dpmi::seg_is_32(&dos.ldt[..], regs.code_seg());
    let ip_lin = cs_base.wrapping_add(if cs_32 { regs.ip32() } else { regs.ip32() & 0xFFFF });
    let sp_lin = ss_base.wrapping_add(regs.sp32());
    let pre = ip_lin.wrapping_sub(16);
    let cp = unsafe { core::slice::from_raw_parts(pre as *const u8, 32) };
    crate::dbg_println!("[DBG] code @{:08x} (-16..+16):", pre);
    crate::dbg_println!("[DBG]   {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} | {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7],
        cp[8], cp[9], cp[10], cp[11], cp[12], cp[13], cp[14], cp[15],
        cp[16], cp[17], cp[18], cp[19], cp[20], cp[21], cp[22], cp[23],
        cp[24], cp[25], cp[26], cp[27], cp[28], cp[29], cp[30], cp[31]);
    let sw = unsafe { core::slice::from_raw_parts(sp_lin as *const u32, 8) };
    crate::dbg_println!("[DBG] stack @{:08x}: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
        sp_lin, sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]);
}

/// Queue an arch IRQ into this thread's virtual PIC.
pub fn queue_irq(dos: &mut thread::DosState, irq: crate::arch::Irq) {
    machine::queue_irq(&mut dos.pc, irq);
}

/// Try to deliver one pending interrupt from the virtual PIC. IRQ delivery
/// is uniform regardless of the client's current mode: `deliver_pm_irq`
/// snapshots the client state on a kernel IRQ stack and switches to the
/// handler at `pm_vectors[vec].sel:off`. When the handler IRETs it lands at
/// `SLOT_PM_RET_{16,32}` → `cross_mode_restore` → back to the client's
/// original state (VM86 or PM). If `pm_vectors[vec]` is the default stub
/// (no PM handler installed), `vector_stub_reflect` runs `cross_mode_restore`
/// and then reflects the IRQ to BIOS — via `machine::reflect_interrupt`
/// when the restored state is VM86, via `reflect_int_to_real_mode` when
/// it's PM.
pub fn raise_pending(dos: &mut thread::DosState, regs: &mut Regs) {
    let Some(vec) = machine::pick_pending_vec(&mut dos.pc, regs) else { return };
    DOS_TRACE_HW_RT.store(false, core::sync::atomic::Ordering::Relaxed);
    dpmi::deliver_pm_irq(dos, regs, vec);
}

// ── Block-allocator helpers used by INT 21h handlers in `dos.rs` ────────

fn next_dos_block_limit(dos: &DosState, seg: u16, skip_seg: Option<u16>) -> u16 {
    let mut limit = 0xA000u16;
    for block in &dos.dos_blocks {
        if Some(block.seg) == skip_seg || block.seg < seg {
            continue;
        }
        if block.seg < limit {
            limit = block.seg;
        }
    }
    limit
}

fn sync_heap_seg(dos: &mut DosState) {
    let mut first_free = dos.heap_base_seg;
    loop {
        let mut advanced = false;
        for block in &dos.dos_blocks {
            if block.seg == first_free {
                first_free = block.seg.saturating_add(block.paras);
                advanced = true;
                break;
            }
        }
        if !advanced {
            break;
        }
    }
    dos.heap_seg = first_free.min(0xA000);
}

fn largest_dos_block(dos: &DosState) -> u16 {
    let mut largest = 0u16;
    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);
    for block in blocks {
        if block.seg > cur {
            largest = largest.max(block.seg - cur);
        }
        let end = block.seg.saturating_add(block.paras);
        if end > cur {
            cur = end;
        }
    }
    largest.max(0xA000u16.saturating_sub(cur))
}

fn dos_reset_blocks(dos: &mut DosState, base_seg: u16) {
    dos.heap_base_seg = base_seg;
    dos.heap_seg = base_seg;
    dos.dos_blocks.clear();
}

fn dos_alloc_block(dos: &mut DosState, need: u16) -> Result<u16, u16> {
    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);

    for block in blocks {
        if block.seg > cur {
            let gap = block.seg - cur;
            if need <= gap {
                if need != 0 {
                    dos.dos_blocks.push(DosMemBlock { seg: cur, paras: need });
                }
                sync_heap_seg(dos);
                return Ok(cur);
            }
        }
        let end = block.seg.saturating_add(block.paras);
        if end > cur {
            cur = end;
        }
    }

    let avail = 0xA000u16.saturating_sub(cur);
    if need <= avail {
        if need != 0 {
            dos.dos_blocks.push(DosMemBlock { seg: cur, paras: need });
        }
        sync_heap_seg(dos);
        Ok(cur)
    } else {
        Err(largest_dos_block(dos))
    }
}

fn dos_free_block(dos: &mut DosState, seg: u16) -> Result<(), u16> {
    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        dos.dos_blocks.remove(idx);
        sync_heap_seg(dos);
        Ok(())
    } else {
        Err(9)
    }
}

fn dos_resize_block(dos: &mut DosState, seg: u16, paras: u16) -> Result<(), (u16, u16)> {
    if seg == dos.current_psp {
        let max = next_dos_block_limit(dos, seg, None).saturating_sub(seg);
        if paras <= max {
            dos.heap_base_seg = seg.saturating_add(paras);
            sync_heap_seg(dos);
            return Ok(());
        }
        return Err((8, max));
    }

    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        let max = next_dos_block_limit(dos, seg, Some(seg)).saturating_sub(seg);
        if paras <= max {
            dos.dos_blocks[idx].paras = paras;
            sync_heap_seg(dos);
            Ok(())
        } else {
            Err((8, max))
        }
    } else {
        Err((9, 0))
    }
}
