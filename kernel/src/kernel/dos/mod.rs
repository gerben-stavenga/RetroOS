//! DOS/DPMI personality — MS-DOS compatible execution environment with a
//! DPMI 0.9 host layered on top.
//!
//! Built on top of the `machine` layer which owns the virtual 8259/8253/8042
//! and VGA register set, and `arch::monitor` which decodes #GP-faulting
//! sensitive instructions. This module provides the public surface; the
//! INT-handler implementation lives in `dos.rs`, the DPMI extender in
//! `dpmi`, the VFS bridge in `dfs.rs`, the virtual PC machine in
//! `machine.rs`, and XMS/EMS/UMA in their own files.
//!
//! DOS always boots from a COW template containing the Rust substitute BIOS.
//! Native video firmware is not part of a DOS address space; a native `FullscreenVga`
//! delegates only physical display operations to the kernel-owned
//! `BiosDisplayWorkspace`.

extern crate alloc;
use alloc::vec::Vec;

/// Track whether we're currently running in a hardware IRQ context.
pub(crate) static IN_HW_IRQ_CONTEXT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Returns true if a DOS/DPMI trace line should fire: the shared runtime trace
/// gate is on ([`crate::kernel::startup::trace_enabled`] — toggled by the F12
/// monitor or bracketed by COMMAND.COM via INT 31h AH=02/03) and we are not
/// inside a hardware IRQ.
#[inline]
fn should_trace() -> bool {
    crate::kernel::startup::trace_enabled()
        && !IN_HW_IRQ_CONTEXT.load(core::sync::atomic::Ordering::Relaxed)
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

mod bios;
pub(crate) use bios::Bda;
mod dpmi;
mod dfs;
mod machine;
mod present;
mod xms;
mod ems;
// The DOS ABI core (INT 21h/33h services). Named `dosabi` rather than `dos` so
// it does not shadow its parent module; `dos` stays a local alias for the many
// in-file references.
#[path = "dos.rs"]
mod dosabi;
use self::dosabi as dos;
mod mode_transitions;

pub use machine::vsb::SbDevice;
pub use machine::vga::physical_vga_present;
pub(crate) use machine::vga::release_fullscreen;
use crate::kernel::bios_display::{DosVideo, EmulatedVga};
pub use dos::parse_config_env;
/// FS-layout policy: DOS C: → this VFS subtree. Set once at boot from
/// BootConfig.c_root; read by the DN/CONFIG launch paths.
pub use dfs::{c_root, set_c_root, set_hostfs_enabled};

/// Look up `KEY` in a DOS environment block (the parsed CONFIG.SYS master
/// env). Startup reads boot policy out of it — `SB_AUDIO=` — before any
/// guest exists.
pub fn config_var<'a>(env: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    machine::env_var(env, key)
}


// Stub array / slot table / IRQ-stack constants live in `dos.rs` (alongside
// the INT handlers that own them); the `dpmi` sibling module also reads them
// when wiring PM↔RM control flow. Re-import here so both can write
// `crate::kernel::dos::STUB_BASE` (etc.) regardless of which submodule
// physically defines the constant.
#[allow(unused_imports)]
use dos::{
    STUB_BASE, STUB_SEG, CTRL_STUB_SEG,
    SLOT_RESUME_CONTINUATION,
    SLOT_RAW_REAL_TO_PM,
    SLOT_CB_ENTRY_BASE, SLOT_CB_ENTRY_END,
    SLOT_SAVE_RESTORE, SLOT_EXCEPTION_RET, SLOT_EXCEPTION_RET_V10, SLOT_PM_TO_REAL,
    SLOT_PMDOS_INT10, SLOT_PMDOS_INT21, SLOT_PMDOS_INT33, SLOT_MOUSE_CB_RET,
    slot_offset, ctrl_slot_off,
    host_stack_base, host_stack_size, host_stack_empty_sp,
    EXC_STACK_TOP, EXC_STACK_SLOT,
    rm_stack_base, rm_stack_size, rm_stack_seg, rm_stack_align_offset,
};

use crate::kernel::thread;
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
pub struct DosState<A: crate::Arch> {
    /// Policy-free PC machine state: virtual 8259 PIC, 8253 PIT, PS/2 keyboard,
    /// VGA register set, A20 gate, HMA page tracking.
    ///
    /// Boxed: `PcMachine` is tens of KB of device state (VGA, GUS, the Voodoo)
    /// and `DosState` is built by value on the 64 KB kernel stack every time a
    /// program is exec'd. Inline, construction alone hits the guard page.
    pub pc: alloc::boxed::Box<machine::PcMachine>,

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
    /// FCB-FindFirst (AH=11h/12h) search state. Still a single enumeration:
    /// the FCB surface has nowhere better to keep a cursor, and no DOS program
    /// we run interleaves FCB searches. The handle-based AH=4Eh/4Fh path uses
    /// `searches` below instead.
    pub find_path: [u8; 96],
    pub find_path_len: u8,
    pub find_idx: u16,
    /// Active AH=4Eh enumerations. See `DosSearch`.
    pub searches: [DosSearch; DOS_SEARCH_SLOTS],
    /// Round-robin allocation cursor for `searches`.
    pub search_next: u8,
    /// FCB-FindFirst (AH=11h) state remembered across to FindNext (AH=12h):
    /// the drive number to report in the DTA result FCB and whether the
    /// caller used an extended FCB (0xFF prefix in their input FCB) so the
    /// DTA write reproduces the same prefix layout.
    pub fcb_search_drive: u8,
    pub fcb_search_ext: bool,

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
    /// Monotonic DPMI linear-memory high-water mark shared across nested
    /// clients. EXEC suspends the parent's DPMI state, but the child's
    /// allocations still live in the same linear address space and must not
    /// overlap the parent's protected-mode stack or heap blocks.
    pub dpmi_mem_next: u32,
    /// Downward-growing allocator for DPMI 0800h physical mappings. Shared
    /// across nested EXEC clients because their mappings coexist in this
    /// address space while the parent's DPMI state is suspended.
    pub dpmi_phys_next: u32,
    /// Exact RM IVT values most recently returned through PM INT 21h/AH=35h.
    /// PM callers receive LOW_MEM_SEL:linear for addressability, but AH=25h
    /// must round-trip that value back to the original real seg:off where
    /// possible because interrupt handlers can depend on their CS:IP shape.
    pub pm_rm_vector_shadow: [(u16, u16, u16); 256],

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

    /// LIFO stack of suspended DOS continuations. A syscall that cannot finish
    /// synchronously moves its original return frame here with its callback,
    /// then returns its active interrupt frame normally to `SLOT_RESUME`.
    /// Nested IRQs therefore see a balanced guest stack and may suspend in the
    /// same way; while nonempty, the active continuation waits at the stub.
    /// The closure returns `Some(next)` to stay parked with a new model,
    /// or `None` to signal completion (SLOT_RESUME then enters the stored
    /// return computation). The return-based contract makes
    /// the "still waiting vs done" decision explicit at every call site
    /// instead of leaning on unrelated process state.
    pub suspended_calls: alloc::vec::Vec<SuspendedCall<A>>,
}

/// The boxed retry closure inside a [`ResumeCallback`].
type ResumeFn<A> = dyn FnOnce(
    &mut A,
    &mut thread::KernelThread<A>,
    &mut DosState<A>,
    &mut Regs,
) -> Option<ResumeCallback<A>>;

/// Block-and-retry closure stored in a [`SuspendedCall`]. Wrapped in a newtype
/// so the FnOnce can return another `ResumeCallback` (recursive type).
pub struct ResumeCallback<A: crate::Arch>(pub alloc::boxed::Box<ResumeFn<A>>);

/// The guest computation following a suspended interrupt. The original frame
/// has already returned to the mode-appropriate `SLOT_RESUME`; completion
/// restores this target directly instead of reaching into the guest stack.
#[derive(Clone, Copy)]
pub enum DosReturnFrame {
    Vm86 { ip: u16, cs: u16, flags: u16 },
    Protected { eip: u32, cs: u16, eflags: u32 },
}

/// One delimited DOS continuation: delayed work plus the computation to enter
/// when that work completes. Nested suspensions naturally form a LIFO stack.
pub struct SuspendedCall<A: crate::Arch> {
    pub callback: ResumeCallback<A>,
    pub return_frame: DosReturnFrame,
}

#[derive(Clone, Copy)]
pub struct DosMemBlock {
    pub seg: u16,
    pub paras: u16,
    pub owner: u16,
}

/// Allocate a zero-filled LDT on the heap. 64KB; we use a `vec![0; N]` route
/// because `Box::new([0u64; N])` materializes the array on the stack first
/// and overflows the kernel stack, whereas `vec!` uses the `alloc_zeroed`
/// specialization for primitives and never touches the stack.
pub(crate) fn fresh_ldt() -> alloc::boxed::Box<[u64; dpmi::LDT_ENTRIES]> {
    alloc::vec![0u64; dpmi::LDT_ENTRIES]
        .into_boxed_slice()
        .try_into()
        .expect("LDT size mismatch")
}

impl<A: crate::Arch> DosState<A> {
    pub fn new_boxed(machine: &mut A, vga: DosVideo) -> alloc::boxed::Box<Self> {
        let ldt = fresh_ldt();
        // Allocate first and initialize fields at their final addresses. A
        // conventional `Box::new(DosState { .. })` makes rustc materialize
        // the complete 10 KiB value on the 64 KiB kernel stack before copying
        // it to the heap. EXEC reaches this constructor through an already
        // deep call chain, so that hidden temporary can hit the guard page.
        let mut state = alloc::boxed::Box::<Self>::new_uninit();
        let p = state.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*p).pc).write(machine::PcMachine::new_boxed(machine, vga));
            core::ptr::addr_of_mut!((*p).dta).write(0);
            core::ptr::addr_of_mut!((*p).heap_seg).write(0xA000);
            core::ptr::addr_of_mut!((*p).heap_base_seg).write(0xA000);
            core::ptr::addr_of_mut!((*p).alloc_strategy).write(0);
            core::ptr::addr_of_mut!((*p).umb_link_state).write(0);
            core::ptr::addr_of_mut!((*p).current_psp).write(dos::heap_start() + 0x10);
            core::ptr::addr_of_mut!((*p).dos_pending_char).write(None);
            core::ptr::addr_of_mut!((*p).last_child_exit_status).write(0);
            core::ptr::addr_of_mut!((*p).exec_parent).write(None);
            core::ptr::addr_of_mut!((*p).xms).write(None);
            core::ptr::addr_of_mut!((*p).ems).write(None);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).find_path), 0, 1);
            core::ptr::addr_of_mut!((*p).find_path_len).write(0);
            core::ptr::addr_of_mut!((*p).find_idx).write(0);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).searches), 0, 1);
            core::ptr::addr_of_mut!((*p).search_next).write(0);
            core::ptr::addr_of_mut!((*p).fcb_search_drive).write(0);
            core::ptr::addr_of_mut!((*p).fcb_search_ext).write(false);
            core::ptr::addr_of_mut!((*p).dfs).write(dfs::DfsState::new_with_hostfs(dfs::hostfs_enabled()));
            core::ptr::addr_of_mut!((*p).dos_blocks).write(alloc::vec::Vec::new());
            core::ptr::addr_of_mut!((*p).ldt).write(ldt);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).ldt_alloc), 0, 1);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).pm_vectors), 0, 1);
            core::ptr::addr_of_mut!((*p).dpmi_mem_next).write(dpmi::MEM_BASE);
            core::ptr::addr_of_mut!((*p).dpmi_phys_next).write(dpmi::PHYS_MAP_TOP);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).pm_rm_vector_shadow), 0, 1);
            core::ptr::addr_of_mut!((*p).dpmi).write(None);
            core::ptr::addr_of_mut!((*p).pm_dos).write(false);
            core::ptr::addr_of_mut!((*p).suspended_calls).write(alloc::vec::Vec::new());
            state.assume_init()
        }
    }

    /// Process a raw PS/2 scancode — queue as virtual keyboard IRQ.
    pub fn process_key(&mut self, machine: &mut A, regs: &mut Regs, scancode: u8) {
        machine::queue_irq(machine, &mut self.pc, regs, crate::Irq::Key(scancode));
    }

    /// Per-thread cleanup at exit: free EMS-backed pages, drop XMS/EMS
    /// state. The screen snapshot is handled by `suspend`, which `exit_thread`
    /// calls separately before `arch_user_clean` unmaps the 0xA0000
    /// framebuffer. Called from `thread::exit_thread`.
    pub fn on_exit(&mut self, machine: &mut A, regs: &mut Regs, capture_vga: bool) {
        if capture_vga {
            // The live aperture belongs to this address space. Complete the
            // detached snapshot before the address space disappears. Normal
            // DOS return has already moved NativeVga directly and deliberately
            // skips this readback path.
            self.pc.vga.capture_address_space_vram(machine);
        }
        if let Some(ref mut dpmi) = self.dpmi {
            dpmi.unmap_all_physical(machine);
        }
        if let Some(ref mut ems) = self.ems {
            ems.free_all_pages();
        }
        self.ems = None;
        self.xms = None;
        // Hand the single global ISA-DMA pool back; a dying thread that
        // armed SB DMA must not poison it for the next program.
        self.pc.sb.release_dma_pool(machine, regs);
        let pc = &mut self.pc;
        pc.gus.reset(machine, &mut pc.vpic);
        pc.mpu.reset();
        pc.spk.reset();
    }

    /// Called by the context-switch code when this thread becomes the running
    /// DOS thread. Encapsulates any per-resume side effects (right now: point
    /// LDTR at this thread's LDT). Keeps the LDT layout private to the dos
    /// module — external code never touches `self.ldt`.
    pub fn on_resume(&mut self, machine: &mut A) {
        machine.load_ldt(&self.ldt[..]);
    }

    /// Called when the thread loses focus. Snapshots the VGA framebuffer +
    /// register set so the screen can be repainted on materialize. With no
    /// card there is nothing to do: the per-thread register file already IS
    /// the live state (the emulated port model), and VRAM lives in guest RAM.
    pub(super) fn release_display(
        &mut self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> crate::kernel::display::DisplayHandoff {
        machine::vga::release_fullscreen(&mut self.pc.vga, machine, bios_workspace)
    }

    /// Called when the thread regains focus. Repaints the VGA framebuffer
    /// from the suspend snapshot. CPU-binding side effects live in
    /// `on_resume` and happen on every swap-in regardless of focus.
    pub(super) fn acquire_display_restore(
        &mut self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::display::DisplayHandoff,
    ) {
        machine::vga::acquire_fullscreen(
            &mut self.pc.vga, machine, bios_workspace, display);
    }

    /// Acquire a handoff while preserving the adapter's current state. Unlike
    /// `materialize`, this deliberately discards the receiver's recovery
    /// image and performs no mode set or framebuffer restore.
    pub(super) fn acquire_display_replace(
        &mut self,
        machine: &mut A,
        display: crate::kernel::display::DisplayHandoff,
    ) {
        machine::vga::acquire_fullscreen_replace(&mut self.pc.vga, machine, display);
    }

}

/// How many AH=4Eh enumerations may be live at once.
pub const DOS_SEARCH_SLOTS: usize = 8;

/// One active FindFirst/FindNext enumeration.
///
/// Real DOS keeps the resume cursor in the caller's own DTA, which is what
/// lets a program run several searches at once by swapping DTAs between
/// calls — file managers do exactly that, walking a directory while stat-ing
/// entries through a second DTA. Holding a single cursor in `DosState`
/// instead makes the two searches silently consume each other's entries.
///
/// The search path (up to 96 bytes) will not fit in the DTA's 21-byte
/// reserved area, so it stays here and the DTA carries a slot id, a
/// generation and the cursor — enough to identify *which* search a given DTA
/// belongs to and where it had got to.
#[derive(Clone, Copy)]
pub struct DosSearch {
    pub path: [u8; 96],
    pub path_len: u8,
    /// Bumped every time the slot is reused, so a DTA left over from a
    /// finished search cannot resume whatever now occupies its slot.
    pub generation: u8,
    pub in_use: bool,
}

impl DosSearch {
    pub const fn new() -> Self {
        DosSearch { path: [0; 96], path_len: 0, generation: 0, in_use: false }
    }
}

impl Default for DosSearch {
    fn default() -> Self {
        Self::new()
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
    pub dta: u32,
    pub dos_blocks: alloc::vec::Vec<DosMemBlock>,
    /// Real-mode IVT entries owned by kernel services. PM parents may have
    /// installed transient hooks into their own address space; the child runs
    /// with clean kernel stubs and normal exits restore the parent view.
    pub ivt_vectors: [(u8, u16, u16); 12],
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
    pub pm_rm_vector_shadow: [(u16, u16, u16); 256],
    /// Parent's PMDOS routing flag, suspended alongside dpmi/pm_vectors so
    /// the child runs with the default reflect-to-RM INT 21 path.
    pub pm_dos: bool,
    /// Parent's locked-stack chain cursor (`pc.locked_stack.other_stack`),
    /// suspended so the child starts a fresh continuation chain. The cursor
    /// is a LIFO position into the parent's host/PM stack tied to the
    /// parent's LDT selectors; leaving it visible to the child makes the
    /// child's first PM IRQ plant its resume continuation on the *parent's*
    /// stack selector — which is null in the child's fresh LDT, so the exit
    /// IRET to the resume park #GPs in ring 0 (the OMF-launcher relaunch
    /// crash). Restored on `exec_return` alongside dpmi/ldt.
    pub locked_stack_other: Option<(u16, u32)>,
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
/// THE one place a guest (segment-or-selector : offset) pair becomes a flat
/// linear address. VM86 uses `seg<<4` with the A20 fold; PM walks the LDT for
/// base+limit. Downstream the linear is used with the flat `regs.read/write/
/// slice` memory API.
#[inline]
fn linear<A: crate::Arch>(_machine: &mut A, dos: &thread::DosState<A>, regs: &Regs, seg: u16, off: u32) -> u32 {
    if regs.mode() == crate::UserMode::VM86 {
        let lin = ((seg as u32) << 4).wrapping_add(off & 0xFFFF);
        // A20 is permanently wrapped (force line 20 low): the HMA
        // (FFFF:0010..FFFF:FFFF) folds back over the first 64 KiB, the faithful
        // A20-off default. A VM86 guest can't use a real HMA (we report none)
        // nor unreal mode, so there is nothing to gate on — see machine::new.
        lin & !(1 << 20)
    } else {
        // PM client: resolve the buffer selector through its LDT base. This is
        // why PMDOS services 16-bit DPMI INT 21 in PM rather than reflecting to
        // RM: Borland issues buffered calls bare from PM with selector pointers
        // (confirmed: INT 21 AH=3Dh open, DS:DX=008F:149B = the filename). A
        // reflect would hand RM-DOS the selector *value* as a segment (DPMI
        // §host must not translate selectors — feedback_dpmi_host_no_seg_xlate),
        // dereferencing garbage. Servicing in PM lets `seg_base` find the buffer.
        let limit = mode_transitions::seg_limit(&dos.ldt[..], seg);
        if off > limit {
            // Offset past the segment limit — a #GP on real silicon. Surface it
            // (hard #GP delivery is a follow-up; today the access proceeds and
            // an unmapped linear still faults via #PF).
            dos_trace!("[DOS] sel {:04X}:{:X} past limit {:X}", seg, off, limit);
        }
        mode_transitions::seg_base(&dos.ldt[..], seg).wrapping_add(off)
    }
}

/// INT 31h is the kernel's unified syscall trap. Every kernel-owned exit
/// trampoline ends in `CD 31`, and PM clients also raise `INT 31h` directly
/// to call the DPMI services API. Mode + CS is the discriminator:
///
/// | Mode | CS                | Routes to                     | Slot space                          |
/// |------|-------------------|-------------------------------|-------------------------------------|
/// | VM86 | `STUB_SEG`        | `dos::rm_vector_dispatch`     | Vector view: slot == INT vector     |
/// | VM86 | `CTRL_STUB_SEG`   | `dos::rm_ctrl_dispatch`       | Control view: far-call entries      |
/// | VM86 | else              | `dos::synth_dispatch`         | Synth INT 31h (AH-dispatched)       |
/// | PM   | `VECTOR_STUB`     | `mode_transitions::vector_stub_reflect`   | Per-vector default reflection       |
/// | PM   | `SPECIAL_STUB`    | `dpmi::pm_stub_dispatch`      | PM host-stub return trampolines     |
/// | PM   | client selector   | `dpmi::dpmi_api`              | DPMI services (by AX)               |
///
/// Lives at the personality root because INT 31h spans both submodules
/// (RM-side stubs in `dos.rs`, PM-side stubs + DPMI API in `dpmi`).
pub fn syscall<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    use crate::UserMode;
    let mode = regs.mode();
    let cs = if mode == UserMode::VM86 { machine::vm86_cs(regs) } else { regs.code_seg() };
    match (mode, cs) {
        (UserMode::VM86, dos::STUB_SEG)         => dos::rm_vector_dispatch(machine, bios_display, kt, dos, regs),
        (UserMode::VM86, dos::CTRL_STUB_SEG)    => dos::rm_ctrl_dispatch(machine, bios_display, kt, dos, regs),
        (UserMode::VM86, _)                     => dos::rm_native_syscall(machine, kt, dos, regs),
        (_, mode_transitions::VECTOR_STUB_SEL)  => mode_transitions::vector_stub_reflect(machine, dos, regs),
        (_, mode_transitions::SPECIAL_STUB_SEL) => dpmi::pm_stub_dispatch(machine, bios_display, kt, dos, regs),
        _                                       => dpmi::dpmi_api(machine, dos, regs),
    }
}

/// Page-fault hook for the planar VGA trap: when a guest unchained-graphics
/// access to the A0000 window faults (the window is left unmapped so the planar
/// write/read logic runs), decode the faulting store/load and emulate it. Pure
/// kernel + lib, no arch — both backends deliver the same PageFault. Returns
/// true if handled (resume), false → real SEGV.
pub fn try_vga_fault<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, addr: u32) -> bool {
    // The Voodoo's aperture is trapped the same way, through the same decoder
    // — a different window and a different device behind it, nothing else.
    if let Some(off) = dos.pc.voodoo.as_ref()
        .and_then(|voodoo| voodoo.aperture_offset(addr))
    {
        let (cs_base, def32, ds_base, es_base) = fault_segment_bases(dos, regs);
        let voodoo = dos.pc.voodoo.as_mut().unwrap();
        let mut target = machine::mmio::MmioTarget::Voodoo(voodoo);
        return machine::mmio::handle_mmio_fault(
            machine, regs, &mut target, cs_base, def32, ds_base, es_base, off,
        );
    }
    // The emulated register file is the sole aperture authority. A native
    // owner has no software trap: its adapter performs plane routing itself.
    // Resolved before the device is borrowed, so the decode below needs only
    // one match: the bases come from the register frame, not from the VGA.
    let (cs_base, def32, ds_base, es_base) = fault_segment_bases(dos, regs);
    let Some(dev) = dos.pc.vga.emulated_mut() else {
        return false;
    };
    let Some(pages) = machine::vga::trapped_aperture(&dev.state) else {
        return false;
    };
    let base = u32::from(pages.start) << 12;
    let len = u32::from(pages.end - pages.start) << 12;
    if !(base..base + len).contains(&addr) {
        return false;
    }
    let off = addr - base;
    let mut target = machine::mmio::MmioTarget::Planar { vga: &mut dev.state, base, len };
    machine::mmio::handle_mmio_fault(machine, regs, &mut target, cs_base, def32, ds_base, es_base, off)
}

/// Resolve CS (instruction fetch) plus the DS/ES bases a `movs` needs: source
/// is DS:(E)SI, destination ES:(E)DI. VM86 segs are shift-by-4; PM segs index
/// the LDT. Plumbing both is what lets the 32-bit-PM `rep movsd` blit (Doom's
/// Mode-Y plane copy under CWSDPMI) decode instead of SEGV.
fn fault_segment_bases<A: crate::Arch>(
    dos: &thread::DosState<A>,
    regs: &Regs,
) -> (u32, bool, u32, u32) {
    if regs.mode() == crate::UserMode::VM86 {
        ((regs.code_seg() as u32) << 4, false, (regs.ds as u32) << 4, (regs.es as u32) << 4)
    } else {
        let cs = regs.code_seg();
        let ldt = &dos.ldt[..];
        (
            mode_transitions::seg_base(ldt, cs),
            mode_transitions::seg_is_32(ldt, cs),
            mode_transitions::seg_base(ldt, regs.ds as u16),
            mode_transitions::seg_base(ldt, regs.es as u16),
        )
    }
}

/// Single entry point the event loop calls for the DOS personality.
/// All DOS/DPMI-specific knowledge (VM86 INT routing, DPMI INT 31, soft INT
/// reflection, In/Out/Ins/Outs port virtualization, exception → DPMI exception
/// handler, GP-fault classification) lives here, not in `startup.rs`.
///
/// `PageFault` is excluded — the loop handles it inline because it needs
/// access to the full `Thread` (for `signal_thread`).
pub fn handle_event<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    kevent: crate::KernelEvent,
) -> thread::KernelAction {
    use crate::KernelEvent as KE;

    let is_vm86 = regs.mode() == crate::UserMode::VM86;
    match kevent {
        KE::Irq => thread::KernelAction::Done,
        // Virtual IF: arch reflected a PM CLI/STI (window toggle) or a #DB
        // inside a window; the policy + per-space map live here (dpmi::vif).
        KE::VifWindow { entry_ip, vif_was_on } => {
            if let Some(dpmi) = dos.dpmi.as_mut() {
                let vif_now = regs.flags32() & (1 << 19) != 0;
                if vif_was_on && !vif_now {
                    dpmi.vif.on_cli(machine, regs, entry_ip);
                } else if !vif_was_on && vif_now {
                    dpmi.vif.on_sti(regs);
                }
            }
            thread::KernelAction::Done
        }
        KE::VifStep => {
            match dos.dpmi.as_mut().map(|d| d.vif.on_db(machine, regs)) {
                Some(dpmi::DbResult::Event(ev)) => handle_event(machine, &mut *bios_display, kt, dos, regs, ev),
                _ => thread::KernelAction::Done,
            }
        }
        // Cooperative focus: HLT means "park me until an IRQ arrives". It
        // must NOT yield/schedule — that would hand focus to the next Ready
        // thread on the very first idle cycle, defeating task switching. The Phase 1
        // drain re-runs raise_pending each iteration, so any pending IRQ
        // gets injected on the next round.
        KE::Hlt => {
            let resume_ip = if is_vm86 {
                dos::ctrl_slot_off(dos::SLOT_RESUME) as u32 + 1
            } else {
                dos::STUB_BASE + dos::slot_offset(dos::SLOT_RESUME) as u32 + 1
            };
            let resume_cs = if is_vm86 {
                dos::CTRL_STUB_SEG
            } else {
                mode_transitions::SPECIAL_STUB_SEL
            };
            let at_resume_hlt = !dos.suspended_calls.is_empty()
                && regs.code_seg() == resume_cs
                && regs.ip32() == resume_ip;
            if at_resume_hlt {
                dos::poll_suspended_call(machine, kt, dos, regs)
            } else {
                thread::KernelAction::Done
            }
        }
        KE::SoftInt(n) => {
            if n == 0x31 {
                // Kernel syscall — `syscall` branches on mode + CS to reach
                // the right RM/PM dispatcher. Runs even on non-DPMI threads
                // (HW-IRQ default reflection lands here too).
                syscall(machine, bios_display, kt, dos, regs)
            } else {
                // Invariants: VM86 only ever traps INT 31h (only entry in
                // the TSS bitmap), and the only path into PM is DPMI. So a
                // PM clients deliver via DPMI's soft-INT path. VM86
                // software INTs go through the IDT-redirect bitmap to
                // RM IVT[n] without trapping; the only VM86 soft-INTs
                // that *do* land here are the DPL=3 IDT vectors (3 and
                // 4 — `int3` debugger, `into` overflow). DOS's default
                // IVT[3]/[4] entry is normally our bare `IRET`, and the CPU
                // already reports IP-after-the-instruction, so a no-op is
                // equivalent to executing that default handler. A guest may
                // hook either vector, though: Future Crew's ST3 packer uses
                // an INT 3 handler as part of its self-decryption. Reflect
                // hooked vectors with the already-advanced IP on the frame.
                if is_vm86 {
                    debug_assert!(matches!(n, 3 | 4),
                        "VM86 SoftInt({:#x}) bubbled to dos — only INT 3/4 should trap from VM86", n);
                    let ivt_seg = machine.read::<u16>((n as usize) * 4 + 2);
                    if ivt_seg != dos::STUB_SEG {
                        arch_abi::monitor::sw_reflect_vm86_int(regs, machine, n);
                    }
                    thread::KernelAction::Done
                } else {
                    debug_assert!(dos.dpmi.is_some(),
                        "PM SoftInt({:#x}) without an active DPMI session", n);
                    mode_transitions::deliver_pm_int(machine, dos, regs, n)
                }
            }
        }
        KE::In { port, size } => {
            machine::handle_in_event(machine, &mut dos.pc, regs, port, size.bytes());
            thread::KernelAction::Done
        }
        KE::Out { port, size } => {
            machine::handle_out_event(machine, &mut dos.pc, regs, port, size.bytes());
            thread::KernelAction::Done
        }
        KE::Ins { size, rep, addr32 } => {
            machine::handle_ins_event(machine, &mut dos.pc, regs, size.bytes(), rep, addr32);
            thread::KernelAction::Done
        }
        KE::Outs { size, rep, addr32 } => {
            machine::handle_outs_event(machine, &mut dos.pc, regs, size.bytes(), rep, addr32);
            thread::KernelAction::Done
        }
        KE::Exception(n) => {
            // CLI/STI never arrive here: a CPL-3 CLI/STI #GP is a sensitive
            // instruction the ARCH emulates against the virtual IF below the
            // boundary (metal: the #GP monitor; interp: the exception path in
            // cpu.rs) — the kernel sees identical events from both backends.
            //
            // A DPMI virtual-IF learning window can cross onto the client's
            // VM86 side. Its TF-generated #DB still belongs to `vif`, not to
            // the client's protected-mode exception table. Conversely, a
            // bare VM86 program may deliberately hook INT 1 and single-step
            // itself (ST3's packer). Ownership state, rather than CPU mode,
            // separates those cases.
            if n == 1 && is_vm86 {
                let vif_owns_db = dos.dpmi.as_ref().is_some_and(|d| d.vif.owns_db());
                if vif_owns_db {
                    return match dos.dpmi.as_mut().map(|d| d.vif.on_db(machine, regs)) {
                        Some(dpmi::DbResult::Event(ev)) =>
                            handle_event(machine, bios_display, kt, dos, regs, ev),
                        _ => thread::KernelAction::Done,
                    };
                }
                if machine.read::<u16>(4 + 2) != dos::STUB_SEG {
                    arch_abi::monitor::sw_reflect_vm86_int(regs, machine, 1);
                } else {
                    // No guest handler owns this trace. Avoid restoring TF and
                    // trapping forever on the next VM86 instruction.
                    regs.clear_flag32(1 << 8);
                }
                return thread::KernelAction::Done;
            }

            // DPMI session active: route to client's exception handler
            // regardless of current mode. push_continuation_and_switch_to_pm_side handles the
            // VM86→PM toggle if needed; save.restore puts us back in
            // VM86 on the unwind.
            if dos.dpmi.is_some() {
                // A #GP reflected to a PM client is almost always a segment
                // limit the client thinks is wider than it is — the Glide
                // tests fault on an aperture read whose linear address lies
                // outside DS. The client's own handler prints registers but
                // reads the descriptors AFTER it has restored them, so dump
                // the live LDT view here, where it is still the fault's.
                if n == 13 {
                    log_pm_gp(dos, regs);
                }
                dpmi::dispatch_dpmi_exception(machine, dos, regs, n as u32)
            } else if is_vm86 && matches!(n, 0..=7 | 16 | 17 | 19)
                && machine.read::<u16>((n as usize) * 4 + 2) != dos::STUB_SEG
            {
                // Bare VM86 (no DPMI): reflect the CPU exceptions that a
                // real-mode program can handle through the same-numbered IVT
                // vector. This includes #UD: DOS programs may deliberately
                // execute invalid encodings during CPU detection and
                // repair/advance the saved IP in their INT 6 handler. Only
                // guest-hooked vectors are reflected: returning
                // through the substitute BIOS's default IRET stub would retry
                // same fault forever. #GP and #PF remain monitor/paging events,
                // while protected-mode-only selector faults cannot originate
                // from ordinary VM86 instructions.
                arch_abi::monitor::sw_reflect_vm86_int(regs, machine, n);
                thread::KernelAction::Done
            } else {
                let lin = if is_vm86 {
                    ((regs.code_seg() as u32) << 4).wrapping_add(regs.ip32())
                } else {
                    A::seg_base(regs.code_seg()).wrapping_add(regs.ip32())
                };
                let mut bytes = [0u8; 8];
                machine.copy_from(lin as usize, &mut bytes);
                let ss_lin = if is_vm86 {
                    ((regs.stack_seg() as u32) << 4).wrapping_add(regs.sp32() & 0xFFFF)
                } else {
                    A::seg_base(regs.stack_seg()).wrapping_add(regs.sp32())
                };
                let s0 = machine.read::<u16>((ss_lin) as usize);
                let s1 = machine.read::<u16>((ss_lin.wrapping_add(2)) as usize);
                let s2 = machine.read::<u16>((ss_lin.wrapping_add(4)) as usize);
                let s3 = machine.read::<u16>((ss_lin.wrapping_add(6)) as usize);
                let s4 = machine.read::<u16>((ss_lin.wrapping_add(8)) as usize);
                let s5 = machine.read::<u16>((ss_lin.wrapping_add(10)) as usize);
                let liq = unsafe { mode_transitions::LAST_IRQ };
                crate::println!("DOS: CPU exception {} at CS:EIP={:04x}:{:#x} ss:sp={:04x}:{:08x} psp={:04x} (vm86={}) bytes={:02x?} stack={:04x} {:04x} {:04x} {:04x} {:04x} {:04x} last_irq=vec{:02x} target={:04x}:{:08x} from cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x}",
                    n, regs.code_seg(), regs.ip32(),
                    regs.stack_seg(), regs.sp32(),
                    dos.current_psp,
                    is_vm86, bytes,
                    s0, s1, s2, s3, s4, s5,
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
                let mut bytes = [0u8; 8];
                machine.copy_from(lin as usize, &mut bytes);
                // Dump the surrounding state before panicking: a plain
                // `push ds` etc. can't #GP in genuine VM86, so SS:SP/flags
                // and the last IRQ we reflected (vector + the CS:IP/SS:SP it
                // was delivered against) tell us how the guest got here.
                let liq = unsafe { mode_transitions::LAST_IRQ };
                crate::println!("VM86 #GP state: ss:sp={:04x}:{:08x} flags={:#x} vm={} last_irq=vec{:02x} handler={:04x}:{:04x} delivered_at cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x}",
                    regs.stack_seg(), regs.sp32(), regs.flags32(),
                    regs.mode() == crate::UserMode::VM86,
                    liq.0, liq.1, liq.2 as u16, liq.3, liq.4, liq.5, liq.6);
                panic!("VM86: unhandled opcode at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                    regs.code_seg(), regs.ip32() as u16, lin,
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]);
            } else if dos.dpmi.is_some() {
                log_pm_gp(dos, regs);
                dpmi::dispatch_dpmi_exception(machine, dos, regs, 13)
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
/// Back the legacy VGA memory window (0xA0000-0xBFFFF) with fresh RAM when the
/// display is the GOP framebuffer rather than a real VGA card.
///
/// `map_low_mem` identity-maps that window to the physical legacy aperture,
/// which a real card backs (and DOS writes there drive the screen). But on a
/// UEFI machine with no legacy-VGA-backed RAM, the GPU decodes the window yet
/// stores nothing — reads return 0xFF — so the emulated VGA's text buffer
/// (0xB8000) and mode-13h/graphics buffer (0xA0000) never retain what the guest
/// writes, and `display_tick` renders 0xFF (a white screen). Fresh RAM makes the
/// emulated VGA's memory actually hold data; the kernel renders it to the GOP
/// framebuffer itself. The planar trap re-maps 0xA0000 as it arms/disarms.
fn back_vga_window_if_emulated<A: crate::Arch>(machine: &mut A) {
    // Every new DOS VGA starts detached, even on a machine that has a card.
    // Focus attachment later materializes this RAM-backed device on hardware.
    machine.map_fresh_range(0xA0000 >> 12, 0x18000 >> 12);
    machine.map_vga_text_aperture();
}

/// COW source for top-level DOS worlds. It contains only the Rust substitute
/// BIOS and DOS-owned low memory; native video firmware has a separate
/// kernel-only workspace in `bios_display`.
pub struct DosTemplate<A: crate::Arch> {
    vcpu: crate::Vcpu<A>,
    fx: A::Fx,
}

impl<A: crate::Arch> DosTemplate<A> {
    pub fn new(machine: &mut A) -> Self {
        let mut regs = crate::Regs::empty();
        initialize_dos_template(machine, &mut regs);
        let mut space = A::PageTable::default();
        machine.user_fork(&mut space);
        machine.free_user_pages();
        Self {
            vcpu: crate::Vcpu::new(regs, space),
            fx: machine.clean_fx_template(),
        }
    }

    fn activate_clone(&mut self, machine: &mut A) {
        let previous = machine.activate(
            core::mem::take(&mut self.vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );
        let mut child = A::PageTable::default();
        machine.user_fork(&mut child);
        self.vcpu.space = machine.activate(child, &mut self.fx, core::ptr::null_mut());
        let mut previous = previous;
        machine.destroy_space(&mut previous);
    }
}

/// Construct the kernel's pristine real-mode BIOS/DOS-low-memory template.
/// This is called exactly once; top-level DOS worlds COW-clone the result.
pub(crate) fn initialize_dos_template<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    machine.map_low_mem();
    back_vga_window_if_emulated(machine);
    dos::setup_ivt(machine, regs);
}

/// Point a cleared register set at a two-instruction kernel video-BIOS thunk:
/// `INT 10h; INT 31h`. The native workspace predates the substitute stub
/// array, so both instructions are written explicitly into its private driver
/// address space.
pub(crate) fn prepare_bios_int10<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    const THUNK_SLOT: u8 = 0xFE;
    let thunk = (usize::from(dos::STUB_SEG) << 4) + usize::from(dos::slot_offset(THUNK_SLOT));
    machine.write::<[u8; 4]>(thunk, [0xCD, 0x10, 0xCD, 0x31]);
    *regs = Regs::empty();
    regs.frame = crate::Frame64 {
        rip: dos::slot_offset(THUNK_SLOT) as u64,
        cs: dos::STUB_SEG as u64,
        rflags: machine::vm86_entry_flags(machine::IOPL_DEFAULT) as u64,
        rsp: (dos::rm_stack_align_offset() as u32 + dos::rm_stack_size()) as u64,
        ss: dos::rm_stack_seg() as u64,
    };
}

/// Replace the ordinary INT 10h thunk with the VBE ModeInfoBlock.WinFuncPtr
/// far call. VBE defines this entry precisely so repeated bank changes avoid
/// the firmware interrupt dispatcher while retaining Function 05h's register
/// convention and status result.
pub(crate) fn prepare_bios_window_call<A: crate::Arch>(
    machine: &mut A,
    regs: &mut Regs,
    target: u32,
) -> u32 {
    const THUNK_SLOT: u8 = 0xFE;
    prepare_bios_int10(machine, regs);
    let offset = target as u16;
    let segment = (target >> 16) as u16;
    let thunk_offset = dos::slot_offset(THUNK_SLOT);
    let thunk = (usize::from(dos::STUB_SEG) << 4) + usize::from(thunk_offset);
    machine.write::<[u8; 7]>(thunk, [
        0x9A,
        offset as u8, (offset >> 8) as u8,
        segment as u8, (segment >> 8) as u8,
        0xCD, 0x31,
    ]);
    u32::from(thunk_offset) + 7
}

pub(crate) fn bios_thunk_returned(
    regs: &Regs,
    event: &crate::KernelEvent,
    return_ip: u32,
) -> bool {
    matches!(event, crate::KernelEvent::SoftInt(0x31))
        && regs.code_seg() == dos::STUB_SEG
        && regs.ip32() == return_ip
}

pub(crate) fn bios_int10_returned(regs: &Regs, event: &crate::KernelEvent) -> bool {
    bios_thunk_returned(regs, event, bios_int10_return_ip())
}

pub(crate) const fn bios_int10_return_ip() -> u32 {
    dos::slot_offset(0xFF) as u32 + 2
}

/// Handles full address space setup: clean + low mem + IVT + binary load + thread init.
/// Called from kernel exec fan-out. `parent_env_data` is the parent's env block
/// snapshot (taken before the address space was torn down), or None for an
/// initial load with no parent (synthesizes default COMSPEC/PATH).
#[allow(clippy::too_many_arguments)]
pub fn exec_dos_into<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize, data: Vec<u8>, is_exe: bool, args: Vec<Vec<u8>>, cmdtail: Vec<u8>, parent_env_data: Vec<u8>, parent_cwd: Vec<u8>, args0_is_dos: bool, viopl: u8, vga: DosVideo) {
    let current = thread::get_thread(threads, tid).unwrap();
    machine.free_user_pages();
    machine.map_low_mem();
    // The virtual-IF exit map (dpmi::vif) is owned by the DPMI client and made
    // fresh at each `dpmi_enter`, so a new address space starts with an empty
    // one — no global clear needed.
    back_vga_window_if_emulated(machine);
    dos::setup_ivt(machine, &mut current.kernel.vcpu);

    // The PSP environment program-name suffix — drive-qualified DOS form
    // ("C:\BIN\PROG.EXE"), which DOS extenders parse back to reopen their own EXE.
    let prog_name = args.first().expect("exec_dos_into: args[0] must be the program path");
    let mut dos_name = [0u8; dfs::DFS_PATH_MAX];
    let dos_name: &[u8] = if args0_is_dos {
        // Launcher was DOS: args[0] is already the canonical DOS path it used
        // (the real 8.3 names) — use it verbatim so it round-trips when reopened.
        // No VFS→DOS reconstruction (which mangled long non-8.3 names).
        let n = prog_name.len().min(dos_name.len());
        dos_name[..n].copy_from_slice(&prog_name[..n]);
        &dos_name[..n]
    } else {
        // Cross-personality / boot: args[0] is VFS — dosify it.
        let dos_len = dfs::vfs_to_dos(prog_name, &mut dos_name);
        &dos_name[..dos_len]
    };

    // Initialize a fresh DosState and seed the heap chain at heap_start so
    // the upcoming dos_alloc_block calls (env, then program block) carve
    // env_seg = heap_start + 1, psp_seg = env_seg + 0x10 = heap_start + 17.
    // In-place exec replaces (drops) the old DosState — release its SB
    // DMA pool binding first, else the global pool stays held forever.
    if let thread::Personality::Dos(old) = &mut current.personality {
        old.pc.sb.release_dma_pool(machine, &mut current.kernel.vcpu);
        let pc = &mut old.pc;
        pc.gus.reset(machine, &mut pc.vpic);
        pc.mpu.reset();
        pc.spk.reset();
    }
    // Construct directly in the personality's final storage. Keeping a
    // `new_state: DosState` local makes rustc reserve another ~16 KiB copy on
    // the kernel stack for the whole duration of this already-deep EXEC path;
    // a child launched by DN can then cross the 64 KiB stack guard. Do the
    // small post-construction DFS initialization after installation instead.
    current.personality = thread::Personality::Dos(DosState::new_boxed(machine, vga));
    // `regs` (the thread's vcpu) and `dos_state` (its DOS personality) are
    // disjoint fields of `current`, so borrow them directly rather than via
    // `dos_mut()` — the loaders need both at once.
    let regs = &mut current.kernel.vcpu;
    let dos_state = match &mut current.personality {
        thread::Personality::Dos(d) => d,
        _ => unreachable!("just set Dos personality"),
    };
    dos_state.pc.vga.initialize_active_address_space(machine);
    dpmi::install_kernel_ldt_slots(dos_state);
    dos_state.dfs.init_from_vfs(&parent_cwd);
    dos_reset_blocks(machine, dos_state, regs, dos::heap_start());

    // Parent: env snapshot with sys's PSP as the segment, since the actual
    // parent is not in this address space (or doesn't exist, e.g. boot).
    let parent = dos::boot_parent_with_env(&parent_env_data);
    let loaded = if is_exe && dos::is_mz_exe(&data) {
        dos::load_exe(machine, regs, dos_state, &parent, &data, dos_name).expect("Invalid MZ EXE")
    } else {
        dos::load_com(machine, regs, dos_state, &parent, &data, dos_name)
    };
    crate::dbg_println!("exec_dos_into tid={} psp_seg={:04X} cmdtail.len={} cmdtail={:?}",
        tid, loaded.psp_seg, cmdtail.len(),
        core::str::from_utf8(&cmdtail).unwrap_or("<non-utf8>"));
    dos::Psp::set_cmdline(machine, loaded.psp_seg, &cmdtail);

    let psp_seg = loaded.psp_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    init_process_thread_vm86_state(machine, current, psp_seg, cs, ip, ss, sp);
    // Virtual IOPL passed in by the exec caller: COMMAND.COM reads the `iopl3`
    // flag from LOADFIX.CFG and passes 3 via SYNTH_FORK_EXEC; every other caller
    // passes 1 (spec-conforming). The kernel never reads LOADFIX.CFG itself.
    // The real run IOPL is pinned to 1 at the arch exit; this is the virtual
    // level the PM gate reads. (Literal mask: `machine` is the arch param here.)
    let f = &mut current.kernel.vcpu.regs.frame.rflags;
    *f = (*f & !(3u64 << 12)) | ((viopl as u64) << 12);
    let dos_state = current.dos_mut();
    dos_state.dta = (psp_seg as u32) * 16 + 0x80;
    current.kernel.symbols = None;
    // Bind this thread's DOS CPU state (LDT/TLS/IOPB) into the hardware now.
    // An in-place execve has no context switch, so `on_resume` — which the boot
    // path's `run_init_program` calls — wouldn't otherwise fire, leaving the
    // CPU's LDTR on the *parent's* LDT. When the parent was a Linux process its
    // LDT[7] is a TLS data segment, not the DOS PM-stub code selector, so the
    // first DOS protected-mode transition (cs=0x3f) #GPs. (Repro: stress.elf —
    // a Linux process forks then execve's a DOS .COM.)
    current.dos_mut().on_resume(machine);
}

/// Executor for `KernelAction::DosSynthChild`: the cross-thread half of the
/// INT-31 synth ops (reap / waitpid probe), run after the
/// caller's `dos`/`kt` borrow releases. Writes the AX/BX/CF result into the
/// live frame and stays on the caller (`None`).
pub(crate) fn handle_synth_child<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    regs: &mut Regs,
    tid: usize,
    pid: i32,
    op: thread::DosChildOp,
) -> Option<usize> {
    use thread::DosChildOp as Op;
    match op {
        Op::Reap => {
            thread::reap(threads, machine, pid);
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
        }
        Op::Waitpid => {
            let (ctid, _code) = thread::peek_zombie_child(threads, tid, pid);
            if ctid >= 0 {
                regs.rax &= !0xFFFF;                                    // AX=0 exited
                regs.rbx = (regs.rbx & !0xFFFF) | (ctid as u16) as u64; // BX=child_pid
                regs.clear_flag32(1);
            } else if ctid == -11 {
                regs.rax = (regs.rax & !0xFFFF) | 1;                    // AX=1 still running
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | (-ctid) as u64;
                regs.set_flag32(1);
            }
        }
    }
    None
}

/// Helper: write CPU state for a freshly loaded VM86 program. Caller has
/// already populated `current.personality` and run the loader.
fn init_process_thread_vm86_state<A: crate::Arch>(_machine: &mut A, thread: &mut thread::Thread<A>, psp_seg: u16, cs: u16, ip: u16, ss: u16, sp: u16) {
    use machine::IOPL_DEFAULT;
    let state = &mut thread.kernel.vcpu.regs;
    *state = Regs::empty();
    state.ds = psp_seg as u64;
    state.es = psp_seg as u64;
    state.fs = 0;
    state.gs = 0;
    state.frame = crate::Frame64 {
        rip: ip as u64,
        cs: cs as u64,
        // Seed the virtual IOPL here at process start; the real run IOPL is
        // pinned to 1 at the arch exit. VM + virtual-IF on + canonical IF
        // pinned to 1, all via the single construction helper.
        rflags: machine::vm86_entry_flags(IOPL_DEFAULT) as u64,
        rsp: sp as u64,
        ss: ss as u64,
    };
}

/// Set up the initial DOS thread for a fresh program load (no parent).
/// Used by the boot/init path; fork+exec uses `exec_dos_into` instead.
/// Returns the new tid; caller drives the event loop.
#[allow(clippy::too_many_arguments)]
pub fn run_init_program<A: crate::Arch>(machine: &mut A, dos_template: &mut DosTemplate<A>, threads: &mut [thread::Thread<A>], buf: Vec<u8>, args: Vec<Vec<u8>>, cmdline_tail: Vec<u8>, cwd: Vec<u8>, env: Vec<u8>) -> usize {

    dos_template.activate_clone(machine);

    let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
        .expect("Failed to create DOS thread");
    let tid = t.kernel.tid as usize;

    let mut dos_name = [0u8; dfs::DFS_PATH_MAX];
    let path = args.first().expect("run_init_program: args[0] must be the program path");
    let dos_len = dfs::vfs_to_dos(path, &mut dos_name);
    let dos_name = &dos_name[..dos_len];

    if let thread::Personality::Dos(old) = &mut t.personality {
        old.pc.sb.release_dma_pool(machine, &mut t.kernel.vcpu);
        let pc = &mut old.pc;
        pc.gus.reset(machine, &mut pc.vpic);
        pc.mpu.reset();
        pc.spk.reset();
    }
    let vga = DosVideo::Vga(EmulatedVga::initial_mode3());
    t.personality = thread::Personality::Dos(DosState::new_boxed(machine, vga));
    let loaded = {
        // `regs` and `dos_state` are disjoint fields of `t`; borrow directly.
        let regs = &mut t.kernel.vcpu;
        let dos_state = match &mut t.personality {
            thread::Personality::Dos(d) => d,
            _ => unreachable!("just set Dos personality"),
        };
        dos_state.pc.vga.initialize_active_address_space(machine);
        dpmi::install_kernel_ldt_slots(dos_state);
        dos_state.dfs.init_from_vfs(&cwd);
        dos_reset_blocks(machine, dos_state, regs, dos::heap_start());

        let parent = dos::boot_parent_with_env(&env);
        if dos::is_mz_exe(&buf) {
            dos::load_exe(machine, regs, dos_state, &parent, &buf, dos_name).expect("load_exe failed")
        } else {
            dos::load_com(machine, regs, dos_state, &parent, &buf, dos_name)
        }
    };

    let psp_seg = loaded.psp_seg;
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;

    init_process_thread_vm86_state(machine, t, psp_seg, cs, ip, ss, sp);
    // Direct launches (--cmd, boot init) bypass COMMAND.COM, so no LOADFIX.CFG
    // policy applies — seed `IfMode::Repair` (vIOPL=2) rather than the strict
    // conforming default. The launcher cannot know whether the program is a
    // non-conforming DPMI client (DOOM re-enables IF via POPF and HANGS at
    // vIOPL=1), and Repair honors it for the price of a few #DB per second.
    // Programs launched through the shell get the per-program LOADFIX policy,
    // which can name `iopl3` to fall back to the always-correct stepping path.
    {
        let f = &mut t.kernel.vcpu.regs.frame.rflags;
        *f = (*f & !(machine::IOPL_MASK as u64)) | (2u64 << 12);
    }
    t.dos_mut().dta = (psp_seg as u32) * 16 + 0x80;

    let (col, row) = lib::term::term().cursor_pos();
    {
        let _regs = &mut t.kernel.vcpu;
        dos::Psp::set_cmdline(machine, loaded.psp_seg, &cmdline_tail);
        Bda::set_page0_cursor(machine, col as u8, row as u8);
    }
    // (The event loop seeds its live vcpu from this thread's saved state, so no
    // separate "set current vcpu" is needed here.)
    // Initial thread never goes through a context switch, so load LDTR
    // directly here. Subsequent threads pick this up via `on_resume` in the
    // event-loop switch path.
    t.dos_mut().on_resume(machine);
    tid
}

/// Map an absolute DOS path (output of `DfsState::resolve`, e.g. the program
/// name carried in a `Some(Dos)` ForkExec) to its VFS form for reading. The
/// DOS-layer's single VFS translator; the generic exec layer calls this rather
/// than reaching into `dfs`. `None` if the path doesn't resolve.
pub fn dos_abs_to_vfs(dos_abs: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    dfs::DfsState::to_vfs_open(dos_abs, &mut out)
        .ok()
        .map(|n| out[..n].to_vec())
}

/// Map an absolute DOS path to its VFS form while permitting the final path
/// component not to exist yet. File-creation APIs use this variant; parent
/// directories must still resolve normally.
pub fn dos_abs_to_vfs_create(dos_abs: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    dfs::DfsState::to_vfs_create(dos_abs, &mut out)
        .ok()
        .map(|n| out[..n].to_vec())
}

/// Snapshot a DOS env block (variable strings up to and including the
/// `00 00` terminator) into a heap Vec. Used so the parent's env survives
/// the COW fork's address-space teardown that happens before `map_psp` runs
/// in the child.
fn snapshot_env<A: crate::Arch>(machine: &mut A, env_seg: u16) -> alloc::vec::Vec<u8> {
    let base = (env_seg as usize) << 4;
    let mut out = alloc::vec::Vec::new();
    let mut prev_was_nul = false;
    let mut i = 0usize;
    while i < 32768 {
        let b = machine.read::<u8>(base + i);
        out.push(b);
        i += 1;
        if b == 0 && prev_was_nul { break; }
        prev_was_nul = b == 0;
    }
    out
}

/// Snapshot the parent's DOS environment block for fork+exec inheritance.
/// `dos.current_psp` is always a segment; PSP[0x2C] may have been
/// converted to a selector at DPMI entry, so use `saved_rm_env` when the
/// active PSP matches the one whose env we patched.
pub fn snapshot_parent_env<A: crate::Arch>(machine: &mut A, _regs: &mut Regs, dos: &thread::DosState<A>) -> alloc::vec::Vec<u8> {
    let psp_seg = dos.current_psp;
    let env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if dpmi.env_ldt_idx != 0 && dpmi.saved_rm_psp == psp_seg => {
            dpmi.saved_rm_env
        }
        _ => dos::Psp::env_seg(machine, psp_seg),
    };
    snapshot_env(machine, env_seg)
}

/// F12 / panic dump: print DPMI LDT entries and PM stack/code bytes.
/// No-op when the thread isn't a DPMI client.
/// Dump the zero-perturbation virtual-IF chain ring (F12 state key).
pub fn dump_if_ring() {
    mode_transitions::dump_if_ring();
}

/// Dump the zero-perturbation GUS port-access ring (F12 state key). Pairs with
/// `dump_if_ring` to diagnose a wedged/storming GUS ISR: shows the exact
/// register cycle the handler loops on, tagged with `irq=1` for ISR-context.
pub fn dump_gus_ring() {
    machine::vgus::dump_gus_ring();
}

pub fn dump_dpmi_state<A: crate::Arch>(machine: &mut A, dos: &thread::DosState<A>, regs: &Regs) {
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
        let base = dpmi::desc_base(raw);
        let limit = dpmi::desc_limit(raw);
        crate::dbg_println!("[DBG] LDT {}={:04X} idx={} base={:08X} limit={:08X} raw={:016X}",
            name, sel, idx, base, limit, raw);
    }
    let cs_base = mode_transitions::seg_base(&dos.ldt[..], regs.code_seg());
    let ss_base = mode_transitions::seg_base(&dos.ldt[..], regs.stack_seg());
    let cs_32 = mode_transitions::seg_is_32(&dos.ldt[..], regs.code_seg());
    let ip_lin = cs_base.wrapping_add(if cs_32 { regs.ip32() } else { regs.ip32() & 0xFFFF });
    let sp_lin = ss_base.wrapping_add(regs.sp32());
    let _ = machine;
    crate::dbg_println!("[DBG] code @{:08x} stack @{:08x}", ip_lin, sp_lin);
}

/// Queue an arch IRQ into this thread's virtual PIC.
pub fn queue_irq<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, irq: crate::Irq) {
    machine::queue_irq(machine, &mut dos.pc, regs, irq);
}

/// Advance the virtual PIT/RTC to `now_ns` and raise IRQ0/IRQ8 when periods
/// elapsed. The physical IRQ0 wakeup supplies cadence, not elapsed units.
pub fn advance_timers<A: crate::Arch>(dos: &mut thread::DosState<A>, now_ns: u64) {
    machine::advance_timers(&mut dos.pc, now_ns);
}

/// Pump a fullscreen DOS video device. Native VGA scans itself out; an
/// emulated fullscreen VGA actively renders into the display it owns.
pub fn pump_fullscreen<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut thread::DosState<A>,
    regs: &Regs,
    now_ns: u64,
) {
    debug_assert!(dos.pc.vga.is_fullscreen());
    present::display_tick(machine, bios, &mut dos.pc, regs, now_ns, None, None);
}

/// Render state-only DOS VGA through the event loop's compositor display.
pub fn render<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut thread::DosState<A>,
    regs: &Regs,
    now_ns: u64,
    display: &mut crate::kernel::display::Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    debug_assert!(!dos.pc.vga.is_fullscreen());
    present::display_tick(
        machine,
        bios,
        &mut dos.pc,
        regs,
        now_ns,
        Some(display),
        Some((desktop, endpoint)),
    );
}

/// Advance emulated audio playback and its guest-visible device events.
pub fn audio_tick<A: crate::Arch>(
    machine: &mut A,
    dos: &mut thread::DosState<A>,
    now_ns: u64,
    span: crate::kernel::sound::AudioSpan<'_>,
) {
    machine::audio_tick(machine, &mut dos.pc, now_ns, span);
}

/// Per-slice audio device service (trigger IRQs, DMA-probe completions, GF1
/// timers and MPU drain) without running the PCM mixer.
pub fn audio_service<A: crate::Arch>(
    machine: &mut A,
    dos: &mut thread::DosState<A>,
    now_ns: u64,
    dt_ns: u64,
    pushed: u64,
) {
    machine::audio_service(machine, &mut dos.pc, now_ns, dt_ns, pushed);
}

/// Try to deliver one pending interrupt from the virtual PIC. IRQ delivery
/// is uniform regardless of the client's current mode: `deliver_pm_irq`
/// snapshots the client state on a kernel IRQ stack and switches to the
/// handler at `pm_vectors[vec].sel:off`. When the handler IRETs it lands at
/// `SLOT_RESUME_CONTINUATION`, which restores the client's original state
/// (VM86 or PM). If `pm_vectors[vec]` is the default stub (no PM handler
/// installed), `vector_stub_reflect` reflects the IRQ to BIOS via
/// `reflect_int_to_real_mode` first, then returns through the same continuation
/// resume path. BIOS executes on a kernel-owned RM frame allocated from
/// host_stack, never on the client's own stack.
pub fn raise_pending<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    // Never inject while the guest sits on the resume-continuation park —
    // the one-instruction window where a handler's IRET has landed on the
    // stub but its CD 31 hasn't yet trapped back for the unwind. A real DPMI
    // host runs its unwind machinery with interrupts disabled, so an IRQ can
    // never land there; our park is guest-visible code, so without this
    // guard a timer tick delivered exactly there re-nests a fresh excursion
    // at every unwind step. Where ticks outpace the unwind (the interpreted
    // backend), the depth only ever grows — Duke3D's demo loop died with
    // DOS/4GW error 2002 "transfer stack overflow on interrupt 08h at
    // 3F:0504" (= SPECIAL_STUB_SEL:SLOT_RESUME_CONTINUATION) exactly this
    // way. Only this slot is deferred: every other stub trap is a legitimate
    // delivery point, and deferring them all starves delivery outright on
    // the interp (post-execute boundaries during INT-21h-heavy phases are
    // always at some stub). The vPIC keeps the line latched; delivery
    // happens at the next boundary, once the unwind has resumed real code.
    let resume_park_ip = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION) as u32;
    let at_resume_park = if regs.mode() == crate::UserMode::VM86 {
        regs.code_seg() == dos::CTRL_STUB_SEG && regs.ip32() == resume_park_ip
    } else {
        regs.code_seg() == mode_transitions::SPECIAL_STUB_SEL
            && regs.ip32() == resume_park_ip
    };
    if at_resume_park {
        // Drop the INTR line for this instant instead of leaving it asserted:
        // the interp stops at a block boundary BEFORE the park's CD 31
        // executes whenever the line is up and the guest is interruptible, so
        // deferral + an asserted line re-stops at the same PC with zero
        // progress, forever (Jazz Jackrabbit hung this way the moment a
        // keystroke landed mid-chain: guest parked at 0000:0504, keyboard IRQ
        // pending, block hook re-firing). The vpic still latches the request;
        // the CD 31 traps within one instruction and the next raise_pending —
        // guest no longer at the park — re-asserts the line and delivers.
        machine.set_irq_line(false);
        return;
    }
    // Mouse-callback dispatch (INT 33h AX=000Ch / Function 12), not a
    // hardware IRQ12/INT 74h delivery. Microsoft documents Function 12 as a
    // FAR subroutine callback and says the mouse driver protects it from
    // reentry: the subroutine is not called again until it terminates.
    //
    // We therefore deliver only from an interruptible guest point (IF=1),
    // but keep IF as-is for the callback itself; `cb_in_flight` provides the
    // specified mouse-driver reentrancy guard. `deliver_mouse_callback` clears
    // `pending_cond` for this invocation and sets `cb_in_flight`.
    let mouse = &dos.pc.mouse;
    let mouse_ready = regs.frame.rflags & (machine::VIF_FLAG as u64) != 0
        && !mouse.cb_in_flight
        && mouse.cb_mask & mouse.pending_cond != 0;
    if mouse_ready {
        dos::deliver_mouse_callback(machine, dos, regs);
    } else if let Some(vec) = machine::pick_pending_vec(&mut dos.pc, regs) {
        IN_HW_IRQ_CONTEXT.store(true, core::sync::atomic::Ordering::Relaxed);
        mode_transitions::deliver_pm_irq(machine, dos, regs, vec);
    }
    // Keep the interpreter's CPU INTR line coherent with what's still pending so
    // its per-block interrupt check keeps firing until everything is delivered
    // (no-op on metal, where the real 8259 drives INTR).
    machine.set_irq_line(dos.pc.intr_pending());
}

// ── Block-allocator helpers used by INT 21h handlers in `dos.rs` ────────
//
// Convention (matches real DOS):
//   - Each block in `dos.dos_blocks` records its data segment, data
//     paragraph count, and owning PSP. A 1-paragraph MCB header lives at
//     `block.seg - 1`.
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
fn sync_mcb_chain<A: crate::Arch>(machine: &mut A, dos: &DosState<A>, _regs: &mut Regs) {
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);

    // Update the LOL-1 first-MCB pointer. AH=52h returns ES:BX = LOL, and
    // programs (DOS/4G stubs, MEM utilities) read [LOL - 2] = first MCB
    // segment to walk the chain head.
    dos::set_first_mcb_seg(machine, dos.heap_base_seg);

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
        entries.push((block_mcb, block.owner, block.paras));
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
        machine.write::<u8>(addr as usize, sig);
        machine.write::<u16>(addr as usize + 1, ow);
        machine.write::<u16>(addr as usize + 3, paras);
        // Bytes 5..15 are not structural chain fields. In particular, do not
        // clear them while splitting a block: a caller may have its INT 21h
        // return frame in the paragraph that becomes the new free MCB. DOS
        // updates the MCB header in place; callers may rely on the remainder
        // of that paragraph surviving AH=4Ah.
    }
}

fn next_dos_block_limit<A: crate::Arch>(dos: &DosState<A>, seg: u16, skip_seg: Option<u16>) -> u16 {
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
fn sync_heap_seg<A: crate::Arch>(dos: &mut DosState<A>) {
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
/// Each gap loses 1 paragraph to MCB overhead. Used by `load_exe` to size a
/// max-alloc child against the live (non-reset) MCB chain.
fn largest_dos_block<A: crate::Arch>(dos: &DosState<A>) -> u16 {
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

fn dos_reset_blocks<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, base_seg: u16) {
    dos.heap_base_seg = base_seg;
    dos.heap_seg = base_seg;
    dos.dos_blocks.clear();
    sync_mcb_chain(machine, dos, regs);
}

fn current_mcb_owner<A: crate::Arch>(dos: &DosState<A>) -> u16 {
    dos.current_psp
}

fn dos_alloc_block<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, need: u16) -> Result<u16, u16> {
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
    let owner = current_mcb_owner(dos);

    for block in &blocks {
        let block_mcb = block.seg.saturating_sub(1);
        if block_mcb > cur {
            let region = block_mcb - cur;
            if region >= total {
                let data_seg = cur.saturating_add(1);
                if need != 0 {
                    dos.dos_blocks.push(DosMemBlock { seg: data_seg, paras: need, owner });
                }
                sync_heap_seg(dos);
                sync_mcb_chain(machine, dos, regs);
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
                dos.dos_blocks.push(DosMemBlock { seg: data_seg, paras: need, owner });
            }
            sync_heap_seg(dos);
            sync_mcb_chain(machine, dos, regs);
            return Ok(data_seg);
        }
        max_data = max_data.max(region.saturating_sub(1));
    }

    Err(max_data)
}

fn dos_free_block<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, seg: u16) -> Result<(), u16> {
    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        dos.dos_blocks.remove(idx);
        sync_heap_seg(dos);
        sync_mcb_chain(machine, dos, regs);
        Ok(())
    } else {
        Err(9)
    }
}

fn dos_set_program_block_owner<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, env_seg: u16, psp_seg: u16, owner: u16) {
    for block in &mut dos.dos_blocks {
        if block.seg == env_seg || block.seg == psp_seg {
            block.owner = owner;
        }
    }
    sync_mcb_chain(machine, dos, regs);
}

fn dos_keep_resident_block<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, seg: u16, paras: u16, owner: u16) {
    let paras = paras.min(0xA000u16.saturating_sub(seg));
    if paras == 0 {
        sync_mcb_chain(machine, dos, regs);
        return;
    }

    dos.dos_blocks.push(DosMemBlock { seg, paras, owner });
    sync_heap_seg(dos);
    sync_mcb_chain(machine, dos, regs);
}

fn dos_resize_block<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs, seg: u16, paras: u16) -> Result<(), (u16, u16)> {
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
            sync_mcb_chain(machine, dos, regs);
            Ok(())
        } else {
            Err((8, max))
        }
    } else {
        Err((9, 0))
    }
}

/// The real-mode segment holding the IVT stub array — every unhooked INT
/// lands here. Exposed so the profiler can decode which service a trap was
/// for: the stub slot index IS the original vector.
pub fn stub_seg() -> u16 {
    dos::STUB_SEG
}

/// Descriptor state at a client #GP: which selectors were loaded, what they
/// actually covered, and where the Voodoo aperture sits — enough to say
/// whether the faulting address was simply past a limit. First few only: a
/// client that GPs repeatedly must not flood the log.
fn log_pm_gp<A: crate::Arch>(dos: &thread::DosState<A>, regs: &Regs) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static SEEN: AtomicU32 = AtomicU32::new(0);
    if SEEN.fetch_add(1, Ordering::Relaxed) >= 8 {
        return;
    }
    let seg = |sel: u16| -> (u32, u32) {
        match dpmi::valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
            Some(idx) => {
                let d = dos.ldt[idx];
                (dpmi::desc_base(d), dpmi::desc_limit(d))
            }
            None => (0, 0),
        }
    };
    let (cs_b, cs_l) = seg(regs.code_seg());
    let (ds_b, ds_l) = seg(regs.ds as u16);
    let (es_b, es_l) = seg(regs.es as u16);
    let (ss_b, ss_l) = seg(regs.stack_seg());
    crate::println!(
        "[#GP] cs={:04x}:{:#x} err={:#x} eax={:#x} ebx={:#x} esi={:#x}",
        regs.code_seg(), regs.ip32(), regs.err_code, regs.rax as u32,
        regs.rbx as u32, regs.rsi as u32
    );
    crate::println!(
        "[#GP] cs={:04x} base={:#x} limit={:#x} | ds={:04x} base={:#x} limit={:#x}",
        regs.code_seg(), cs_b, cs_l, regs.ds as u16, ds_b, ds_l
    );
    crate::println!(
        "[#GP] es={:04x} base={:#x} limit={:#x} | ss={:04x} base={:#x} limit={:#x} | voodoo aperture={:x?}",
        regs.es as u16, es_b, es_l, regs.stack_seg(), ss_b, ss_l,
        dos.pc.voodoo.as_ref().and_then(|voodoo| voodoo.linear_base)
    );
}
