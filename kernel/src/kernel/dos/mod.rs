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

/// Runtime trace gate, toggled by INT 31h synth AH=02 (on) / AH=03 (off).
/// Lets COMMAND.COM bracket a single exec so the log only captures that
/// child program, not surrounding shell/launcher noise. Default OFF so
/// boot/init/DN startup are silent until something explicitly enables it.
static DOS_TRACE_RT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Track whether we're currently running in a hardware IRQ context.
pub(crate) static IN_HW_IRQ_CONTEXT: core::sync::atomic::AtomicBool =
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
    DOS_TRACE_RT.load(core::sync::atomic::Ordering::Relaxed) && !IN_HW_IRQ_CONTEXT.load(core::sync::atomic::Ordering::Relaxed)
}

macro_rules! dos_trace {
    (force $($arg:tt)*) => {
        $crate::dbg_println!($($arg)*);
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
mod mode_transitions;

// VgaState is hardware-shaped (4 planes + register snapshot), not DOS policy.
// Re-export so the Linux personality can hold its own console snapshot — DOS
// machine emulation stays private otherwise.
pub use machine::VgaState;

// Stub array / slot table / IRQ-stack constants live in `dos.rs` (alongside
// the INT handlers that own them); the `dpmi` sibling module also reads them
// when wiring PM↔RM control flow. Re-import here so both can write
// `crate::kernel::dos::STUB_BASE` (etc.) regardless of which submodule
// physically defines the constant.
#[allow(unused_imports)]
use dos::{
    STUB_BASE, STUB_SEG,
    SLOT_RM_IRET, SLOT_RM_IRET_CALL,
    SLOT_RAW_REAL_TO_PM,
    SLOT_CB_ENTRY_BASE, SLOT_CB_ENTRY_END,
    SLOT_SAVE_RESTORE, SLOT_EXCEPTION_RET, SLOT_PM_TO_REAL,
    SLOT_PMDOS_INT21,
    SLOT_PM_IRET,
    slot_offset,
    host_stack_base, host_stack_size, host_stack_empty_sp,
    rm_stack_base, rm_stack_size, rm_stack_seg, rm_stack_align_offset,
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

    /// PMDOS short-circuit for INT 21 from PM. When set, `pm_vectors[0x21]`
    /// targets `SLOT_PMDOS_INT21` instead of the generic vector stub —
    /// the kernel services INT 21 with PM regs intact, so DS:DX with a
    /// high-base PM-block selector resolves correctly via LDT lookup
    /// instead of being silently truncated by an RM-paragraph translation.
    /// Default-on for 16-bit DPMI clients (Borland's `dpmiload` etc.);
    /// 32-bit clients (DJGPP via CWSDPMI) marshal explicitly via INT 31
    /// 0300 and don't need this — leaving it off for them keeps spec-strict
    /// reflect-to-RM behaviour for INT 21 hooks installed in the IVT.
    pub pm_dos: bool,
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
            pm_dos: false,
        };
        dpmi::install_kernel_ldt_slots(&mut dos);
        dos
    }

    /// Process a raw PS/2 scancode — queue as virtual keyboard IRQ.
    pub fn process_key(&mut self, scancode: u8) {
        machine::queue_irq(&mut self.pc, crate::arch::Irq::Key(scancode));
    }

    /// Per-thread cleanup at exit: free EMS-backed pages, drop XMS/EMS
    /// state, restore A20. The screen snapshot is handled by `suspend`,
    /// which `exit_thread` calls separately before `arch_user_clean`
    /// unmaps the 0xA0000 framebuffer. Called from `thread::exit_thread`.
    pub fn on_exit(&mut self) {
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

    /// Called when the thread loses focus. Snapshots the VGA framebuffer
    /// + register set so the screen can be repainted on materialize.
    pub fn suspend(&mut self) {
        self.pc.vga.save_from_hardware();
    }

    /// Called when the thread regains focus. Repaints the VGA framebuffer
    /// from the suspend snapshot. CPU-binding side effects live in
    /// `on_resume` and happen on every swap-in regardless of focus.
    pub fn materialize(&mut self) {
        self.pc.vga.restore_to_hardware();
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
    /// Parent's PMDOS routing flag, suspended alongside dpmi/pm_vectors so
    /// the child runs with the default reflect-to-RM INT 21 path.
    pub pm_dos: bool,
    /// Parent was running in PM at EXEC time. The child is always VM86;
    /// `exec_return` uses this to flip `VM_FLAG` back so the dispatch tail
    /// runs the PM iret-frame pop instead of the VM86 one.
    pub pm_mode: bool,
    pub prev: Option<alloc::boxed::Box<ExecParent>>,
}

/// Translate a `seg:off` client pointer to a flat linear address.
///
/// All callers run inside our DOS handlers (`int_21h` etc.), reached via
/// the V86 dispatch — both real V86 callers (DOS .COM/.EXE) and PM
/// callers reflected through `reflect_int_to_real_mode`. By the time we
/// reach a handler the regs are VM86, so `seg` is a paragraph.
///
/// Resolve a (seg, off) buffer address to a linear address. Mode-aware:
/// in PM, `seg` is an LDT/GDT selector — look up the descriptor base.
/// In VM86 it's an RM paragraph — shift by 4. The two paths only diverge
/// for the 16-bit-DPMI PMDOS short-circuit (`pmdos_int21_handler`), where
/// the DOS handler runs with PM regs and high-base PM selectors as buffer
/// pointers; the regular reflect-to-RM path always reaches the handler in
/// VM86 with RM-paragraph regs.
#[inline]
fn linear(dos: &thread::DosState, regs: &Regs, seg: u16, off: u32) -> u32 {
    if regs.mode() == crate::UserMode::VM86 {
        ((seg as u32) << 4).wrapping_add(off & 0xFFFF)
    } else {
        mode_transitions::seg_base(&dos.ldt[..], seg).wrapping_add(off)
    }
}

/// INT 31h is the kernel's unified syscall trap. Every kernel-owned exit
/// trampoline ends in `CD 31`, and PM clients also raise `INT 31h` directly
/// to call the DPMI services API. Mode + CS is the discriminator:
///
/// | Mode | CS                | Routes to                     | Slot space                          |
/// |------|-------------------|-------------------------------|-------------------------------------|
/// | VM86 | `STUB_SEG`        | `dos::rm_stub_dispatch`       | RM IVT redirects + far-call entries |
/// | VM86 | else              | `dos::synth_dispatch`         | Synth INT 31h (AH-dispatched)       |
/// | PM   | `VECTOR_STUB`     | `mode_transitions::vector_stub_reflect`   | Per-vector default reflection       |
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
        (_, mode_transitions::VECTOR_STUB_SEL)  => mode_transitions::vector_stub_reflect(dos, regs),
        (_, mode_transitions::SPECIAL_STUB_SEL) => dpmi::pm_stub_dispatch(kt, dos, regs),
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
        // Cooperative focus: HLT means "park me until an IRQ arrives". It
        // must NOT yield/schedule — that would hand focus to the next Ready
        // thread on the very first idle cycle, defeating F11. The Phase 1
        // drain re-runs raise_pending each iteration, so any pending IRQ
        // gets injected on the next round.
        KE::Hlt => thread::KernelAction::Done,
        KE::SoftInt(n) => {
            if n == 0x31 {
                // Kernel syscall — `syscall` branches on mode + CS to reach
                // the right RM/PM dispatcher. Runs even on non-DPMI threads
                // (HW-IRQ default reflection lands here too).
                syscall(kt, dos, regs)
            } else {
                // Invariants: VM86 only ever traps INT 31h (only entry in
                // the TSS bitmap), and the only path into PM is DPMI. So a
                // PM clients deliver via DPMI's soft-INT path. VM86
                // software INTs go through the IDT-redirect bitmap to
                // RM IVT[n] without trapping; the only VM86 soft-INTs
                // that *do* land here are the DPL=3 IDT vectors (3 and
                // 4 — `int3` debugger, `into` overflow). DOS's default
                // IVT[3]/[4] entry is a bare `IRET`, and the CPU already
                // saved IP-after-the-instruction in regs.eip during the
                // ring-3→ring-0 trap, so a no-op return is equivalent
                // to executing that default IRET in user mode. Compilers
                // that emit `INTO` for unchecked overflow detection
                // (Borland TP/TC) rely on exactly that behaviour when
                // no debugger has hooked the vector.
                if is_vm86 {
                    debug_assert!(matches!(n, 3 | 4),
                        "VM86 SoftInt({:#x}) bubbled to dos — only INT 3/4 should trap from VM86", n);
                    thread::KernelAction::Done
                } else {
                    debug_assert!(dos.dpmi.is_some(),
                        "PM SoftInt({:#x}) without an active DPMI session", n);
                    mode_transitions::deliver_pm_int(dos, regs, n)
                }
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
            // DPMI exception delivery is for PM clients. A DPMI session
            // can outlive its initial entry (TSR'd PM hosts like dpmiload
            // keep `dos.dpmi` Some while running RM-side code), so
            // `dpmi.is_some()` is not the right gate — `regs.mode()` is.
            // Otherwise a #UD in VM86 code lands in dispatch_dpmi_exception
            // which tries to load PM-shaped saved regs and #GPs the kernel.
            if !is_vm86 && dos.dpmi.is_some() {
                dpmi::dispatch_dpmi_exception(dos, regs, n as u32)
            } else {
                let lin = if is_vm86 {
                    ((regs.code_seg() as u32) << 4).wrapping_add(regs.ip32())
                } else {
                    crate::arch::monitor::seg_base(regs.code_seg()).wrapping_add(regs.ip32())
                };
                let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
                let liq = unsafe { mode_transitions::LAST_IRQ };
                crate::println!("DOS: CPU exception {} at CS:EIP={:04x}:{:#x} ss:sp={:04x}:{:08x} (vm86={}) bytes={:02x?} last_irq=vec{:02x} target={:04x}:{:08x} from cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x}",
                    n, regs.code_seg(), regs.ip32(),
                    regs.stack_seg(), regs.sp32(),
                    is_vm86, bytes,
                    liq.0, liq.1, liq.2, liq.3, liq.4, liq.5, liq.6);
                // DOS termination type 02h (critical error) | low byte = vector.
                // exit_thread copies this verbatim into parent's
                // last_child_exit_status, where AH=4Dh exposes it.
                thread::KernelAction::Exit(0x0200 | (n as i32 & 0xFF))
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
                thread::KernelAction::Exit(0x0200 | 13) // #GP
            }
        }
        KE::PageFault { .. } => unreachable!("PageFault handled in event loop"),
        // DOS personality has no syscall ABI — segfault the thread.
        KE::Syscall => thread::KernelAction::Exit(0x0200),
    }
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

    let current = thread::get_thread(tid).unwrap();

    // Initialize a fresh DosState and seed the heap chain at heap_start so
    // the upcoming dos_alloc_block calls (env, then program block) carve
    // env_seg = heap_start + 1, psp_seg = env_seg + 0x10 = heap_start + 17.
    let mut new_state = DosState::new();
    new_state.dfs.init_from_vfs(parent_cwd);
    current.personality = thread::Personality::Dos(new_state);
    let dos_state = current.dos_mut();
    dos_reset_blocks(dos_state, dos::heap_start());

    // Parent: either an env snapshot (with sys's PSP as the segment, since
    // the actual parent is not in this address space) or just sys.
    let parent = match parent_env_data {
        Some(env) => dos::ParentRef { psp_seg: dos::boot_psp_seg(), env },
        None => dos::boot_parent(),
    };
    let loaded = if is_exe && dos::is_mz_exe(data) {
        dos::load_exe(dos_state, &parent, data, dos_name).expect("Invalid MZ EXE")
    } else {
        dos::load_com(dos_state, &parent, data, dos_name)
    };
    crate::dbg_println!("exec_dos_into tid={} psp_seg={:04X} cmdtail.len={} cmdtail={:?}",
        tid, loaded.psp_seg, cmdtail.len(),
        core::str::from_utf8(cmdtail).unwrap_or("<non-utf8>"));
    dos::Psp::at(loaded.psp_seg).set_cmdline(cmdtail);

    let psp_seg = loaded.psp_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    init_process_thread_vm86_state(current, psp_seg, cs, ip, ss, sp);
    let dos_state = current.dos_mut();
    dos_state.dta = (psp_seg as u32) * 16 + 0x80;
    current.kernel.symbols = None;
}

/// Helper: write CPU state for a freshly loaded VM86 program. Caller has
/// already populated `current.personality` and run the loader.
fn init_process_thread_vm86_state(thread: &mut thread::Thread, psp_seg: u16, cs: u16, ip: u16, ss: u16, sp: u16) {
    use machine::{VM_FLAG, IF_FLAG, IOPL_VM86};
    let state = &mut thread.kernel.cpu_state;
    *state = Regs::empty();
    state.ds = psp_seg as u64;
    state.es = psp_seg as u64;
    state.fs = 0;
    state.gs = 0;
    state.frame = crate::Frame64 {
        rip: ip as u64,
        cs: cs as u64,
        rflags: (VM_FLAG | IF_FLAG | IOPL_VM86) as u64,
        rsp: sp as u64,
        ss: ss as u64,
    };
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

    let mut new_state = DosState::new();
    new_state.dfs.init_from_vfs(cwd);
    t.personality = thread::Personality::Dos(new_state);
    let dos_state = t.dos_mut();
    dos_reset_blocks(dos_state, dos::heap_start());

    let parent = dos::boot_parent();
    let loaded = if dos::is_mz_exe(buf) {
        dos::load_exe(dos_state, &parent, buf, dos_name).expect("load_exe failed")
    } else {
        dos::load_com(dos_state, &parent, buf, dos_name)
    };

    let psp_seg = loaded.psp_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    init_process_thread_vm86_state(t, psp_seg, cs, ip, ss, sp);
    let dos_state = t.dos_mut();
    dos_state.dta = (psp_seg as u32) * 16 + 0x80;

    dos::Psp::at(loaded.psp_seg).set_cmdline(cmdline_tail);

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
        _ => dos::Psp::at(psp_seg).env_seg,
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
    let cs_base = mode_transitions::seg_base(&dos.ldt[..], regs.code_seg());
    let ss_base = mode_transitions::seg_base(&dos.ldt[..], regs.stack_seg());
    let cs_32 = mode_transitions::seg_is_32(&dos.ldt[..], regs.code_seg());
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
/// and then reflects the IRQ to BIOS via `reflect_int_to_real_mode` —
/// uniformly for VM86 and PM clients. BIOS executes on a kernel-owned RM
/// frame allocated from host_stack, never on the client's own stack.
pub fn raise_pending(dos: &mut thread::DosState, regs: &mut Regs) {
    let Some(vec) = machine::pick_pending_vec(&mut dos.pc, regs) else { return };
    IN_HW_IRQ_CONTEXT.store(true, core::sync::atomic::Ordering::Relaxed);
    mode_transitions::deliver_pm_irq(dos, regs, vec);
}

// ── Block-allocator helpers used by INT 21h handlers in `dos.rs` ────────
//
// Convention (matches real DOS):
//   - Each block in `dos.dos_blocks` records its data segment and data
//     paragraph count. A 1-paragraph MCB header lives at `block.seg - 1`.
//   - Total conventional consumption per allocation is `paras + 1`.
//   - `heap_base_seg` is the seg of the *first MCB* in the chain (i.e.,
//     the first paragraph available for the chain — everything below is
//     occupied by the program block, env, system structures).
//   - The chain extends from `heap_base_seg` up to 0xA000, walkable by
//     reading [mcb_seg]: sig + owner + paras, then advancing to
//     `mcb_seg + 1 + paras` for the next MCB.
//
// `dos_blocks` is the source of truth. Guest writes to MCB memory are
// ignored; every alloc/free/resize/reset re-emits the chain via
// `sync_mcb_chain`. This keeps the kernel safe from buggy or hostile
// guests that scribble on MCB memory while still presenting a
// consistent chain to programs that walk it (extender stubs, MEM-style
// utilities, TSR detectors).

/// Mirror `dos.dos_blocks` out as a real DOS Memory Control Block chain
/// in VM86 memory. Free MCBs are synthesized in the gaps so the chain
/// walks contiguously from `heap_base_seg` up to 0xA000.
fn sync_mcb_chain(dos: &DosState) {
    let owner = dos.current_psp;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);

    // Update the LOL-1 first-MCB pointer. AH=52h returns ES:BX = LOL, and
    // programs (DOS/4G stubs, MEM utilities) read [LOL - 2] = first MCB
    // segment to walk the chain head.
    dos::set_first_mcb_seg(dos.heap_base_seg);

    let mut entries: alloc::vec::Vec<(u16, u16, u16)> = alloc::vec::Vec::new();

    let mut walk = dos.heap_base_seg;
    for block in &blocks {
        let block_mcb = block.seg.saturating_sub(1);
        if block_mcb > walk {
            // Free MCB at walk; data [walk+1, block_mcb), paras=block_mcb-walk-1.
            let paras = block_mcb - walk - 1;
            entries.push((walk, 0, paras));
        }
        // Owned MCB at block_mcb (= block.seg - 1).
        entries.push((block_mcb, owner, block.paras));
        walk = block.seg.saturating_add(block.paras);
    }
    if walk < 0xA000 {
        let paras = 0xA000u16 - walk - 1;
        entries.push((walk, 0, paras));
    }

    let last_idx = entries.len();
    for (i, &(mcb_seg, ow, paras)) in entries.iter().enumerate() {
        let sig = if i + 1 == last_idx { b'Z' } else { b'M' };
        let addr = (mcb_seg as u32) << 4;
        unsafe {
            let p = addr as *mut u8;
            *p = sig;
            ((addr + 1) as *mut u16).write_unaligned(ow);
            ((addr + 3) as *mut u16).write_unaligned(paras);
            for off in 5..16 {
                *((addr + off) as *mut u8) = 0;
            }
        }
    }
}

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

/// `heap_seg` = first paragraph past the contiguous run of allocated blocks
/// starting at `heap_base_seg`. Used for the in-process EXEC fan-out as the
/// "where does the child's arena start" hint.
fn sync_heap_seg(dos: &mut DosState) {
    let mut first_free = dos.heap_base_seg;
    loop {
        let mut advanced = false;
        for block in &dos.dos_blocks {
            // Block's MCB sits at first_free; data at first_free+1.
            if block.seg == first_free.saturating_add(1) {
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

/// Largest free *data* paragraphs across all gaps + trailing region.
/// Each gap loses 1 paragraph to MCB overhead.
fn largest_dos_block(dos: &DosState) -> u16 {
    let mut largest_data = 0u16;
    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);
    for block in blocks {
        let block_mcb = block.seg.saturating_sub(1);
        if block_mcb > cur {
            let region = block_mcb - cur;
            largest_data = largest_data.max(region.saturating_sub(1));
        }
        let end = block.seg.saturating_add(block.paras);
        if end > cur {
            cur = end;
        }
    }
    if cur < 0xA000 {
        let region = 0xA000 - cur;
        largest_data = largest_data.max(region.saturating_sub(1));
    }
    largest_data
}

fn dos_reset_blocks(dos: &mut DosState, base_seg: u16) {
    dos.heap_base_seg = base_seg;
    dos.heap_seg = base_seg;
    dos.dos_blocks.clear();
    sync_mcb_chain(dos);
}

fn dos_alloc_block(dos: &mut DosState, need: u16) -> Result<u16, u16> {
    // Each alloc consumes 1 MCB paragraph + `need` data paragraphs. Quirk
    // preserved from pre-MCB code: AH=48 BX=0 silently succeeds without
    // recording a block (returns the would-be data segment).
    let total = if need == 0 { 1u16 } else { need.saturating_add(1) };
    if need != 0 && total < need {
        return Err(0);
    }

    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);
    let mut max_data = 0u16;

    for block in &blocks {
        let block_mcb = block.seg.saturating_sub(1);
        if block_mcb > cur {
            let region = block_mcb - cur;
            if region >= total {
                let data_seg = cur.saturating_add(1);
                if need != 0 {
                    dos.dos_blocks.push(DosMemBlock { seg: data_seg, paras: need });
                }
                sync_heap_seg(dos);
                sync_mcb_chain(dos);
                return Ok(data_seg);
            }
            max_data = max_data.max(region.saturating_sub(1));
        }
        cur = block.seg.saturating_add(block.paras);
    }

    if cur < 0xA000 {
        let region = 0xA000 - cur;
        if region >= total {
            let data_seg = cur.saturating_add(1);
            if need != 0 {
                dos.dos_blocks.push(DosMemBlock { seg: data_seg, paras: need });
            }
            sync_heap_seg(dos);
            sync_mcb_chain(dos);
            return Ok(data_seg);
        }
        max_data = max_data.max(region.saturating_sub(1));
    }

    Err(max_data)
}

fn dos_free_block(dos: &mut DosState, seg: u16) -> Result<(), u16> {
    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        dos.dos_blocks.remove(idx);
        sync_heap_seg(dos);
        sync_mcb_chain(dos);
        Ok(())
    } else {
        Err(9)
    }
}

fn dos_resize_block(dos: &mut DosState, seg: u16, paras: u16) -> Result<(), (u16, u16)> {
    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        // Block resize: data must end before next block's MCB (or at 0xA000
        // if no next block).
        let next_limit = next_dos_block_limit(dos, seg, Some(seg));
        let max = if next_limit < 0xA000 {
            next_limit.saturating_sub(seg).saturating_sub(1)
        } else {
            next_limit.saturating_sub(seg)
        };
        if paras <= max {
            dos.dos_blocks[idx].paras = paras;
            sync_heap_seg(dos);
            sync_mcb_chain(dos);
            Ok(())
        } else {
            Err((8, max))
        }
    } else {
        Err((9, 0))
    }
}
