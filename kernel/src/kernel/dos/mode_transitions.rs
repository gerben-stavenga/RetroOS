//! DPMI protected-mode DOS crossing mechanics.
//!
//! Owns the per-thread **locked PM stack** (DPMI 0.9 §3.1.2 "locked
//! protected mode stack") and the dedicated real-mode stack used when
//! protected-mode DOS clients reflect interrupts, invoke real-mode
//! procedures, receive callbacks, or run protected-mode IRQ/exception
//! handlers. This is not a generic mode-switch layer: it is the stack
//! bridge for DPMI/PMDOS execution.
//!
//! ### User execution states
//!
//! Four logical states matter to the bridge:
//!
//! - `ClientPm`     — PM running on the client's own PM stack.
//! - `ClientRm`     — RM/VM86 running on the client's own RM stack.
//! - `PmInLocked`   — PM running on the DPMI locked PM stack. PM IRQ
//!   handlers, exception handlers, RM callbacks, and
//!   post-soft-INT-reflect PM continuations all run
//!   here. The handler may switch SS to its own
//!   "locked" stack mid-execution (DPMI 0.9 §3.1.2):
//!   that switched-to stack also counts as the locked
//!   stack until the handler switches back.
//! - `RmInLocked`   — RM running on the dedicated RM stack (a separate
//!   per-thread buffer in low memory). RM-INT reflection
//!   from PM, DPMI 0300/0301/0302 calls, etc.
//!
//! ### State tracking
//!
//! Per-thread tracking lives in [`LockedStackState::other_stack`]:
//! `Option<(SS, SP)>`. `None` ⇒ user is in client mode (not on either
//! dedicated stack). `Some((ss, sp))` ⇒ kernel cross-mode entry has
//! put the user on a dedicated stack and we remember the cursor of
//! the *other* dedicated stack we'd ping-pong to.
//! `regs.SS:SP` is authoritative for whichever stack the user is
//! currently on; `other_stack` tracks the cursor of the not-current
//! one. HostContinuation captures and restores `other_stack` symmetrically.
//!
//! ### Frame layout
//!
//! Cross-mode entries push a `HostContinuation` on the PM-side stack. Some
//! recipes place an IRET frame above it for PM IRQ delivery or callback
//! return. Explicit DPMI RM calls store their register-structure address
//! in the continuation so one return path can write results back, restore
//! GP regs, and restore `other_stack`.

use arch_abi::GuestBytes;
use super::dosabi as dos;
use crate::Vcpu;
use super::machine;
use super::thread;

/// Per-thread tracking for kernel-mediated DPMI/PMDOS crossings.
///
/// `other_stack` is the central state: `None` when the user is in
/// client mode (not on either dedicated stack), `Some((ss, sp))` when
/// kernel cross-mode entry has put the user on a dedicated stack and
/// remembers the cursor of the *other* dedicated stack we'd ping-pong
/// to. `regs.SS:SP` is authoritative for whichever stack the user is
/// currently on; `other_stack` tracks the cursor of the not-current
/// one.
///
/// Maintained automatically via `HostContinuation`'s capture/restore: every
/// `push_continuation` records the current value, and
/// `resume_continuation` restores it. Bracket boundaries (`deliver_pm_irq`
/// first-entry, etc.) update it explicitly when transitioning state.
pub struct LockedStackState {
    pub other_stack: Option<(u16, u32)>,
}

impl LockedStackState {
    pub fn new() -> Self {
        Self { other_stack: None }
    }
}

/// Snapshot of CPU state captured across a kernel-orchestrated mode
/// switch. Pushed onto the locked stack by recipes that need to
/// remember "where to go back to". GP regs are deliberately not part
/// of this struct; explicit DPMI RM-call recipes save them in the
/// caller-visible RmCallStruct while the RM side runs, then exchange that
/// structure with the live result regs during `resume_continuation`.
///
/// ### Hardware-stack-compat layout
///
/// The first five `u32` fields are ordered `eip, cs, eflags, esp, ss`
/// to mirror what a 32-bit CPU pushes on a fault/interrupt with stack
/// switch (`ESP` → low: EIP, CS, EFLAGS, ESP, SS). This lets recipes
/// expose a spec-mandated frame to the client by writing only a small
/// prefix above the HostContinuation instead of duplicating the faulting
/// state:
///
///   - **DPMI 0.9 §6 PM exception frame** (32-bit): a 3-dword prefix
///     `[ret_eip, ret_cs, err_code]` above HostContinuation gives the handler
///     the exact 8-field spec layout — faulting `EIP/CS/EFLAGS/ESP/SS`
///     at offsets `+12/+16/+20/+24/+28` from the handler's ESP coincide
///     with HostContinuation's first five u32 fields. Handler modifications
///     to those fields land in HostContinuation directly, and `save.restore`
///     picks them up on unwind without a copy step.
///   - **HW IRQ entry**: the iret-frame `[eip, cs, eflags]` pushed
///     above HostContinuation (with control values, not faulting state)
///     follows the same field order, so a hardware IRET pops it and
///     leaves `regs.SS:SP` aligned at the start of HostContinuation for the
///     trap-back stub to find.
///
/// 16-bit clients don't get the overlap (their spec frame uses u16
/// fields, not u32) — those recipes write a separate compact frame
/// and pay the small redundancy.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct HostContinuation {
    // Hardware-stack-compat layout: matches CPU iret-frame field order
    // (eip, cs, eflags) so the spec exception frame's faulting portion
    // can overlap with HostContinuation's first 5 u32 fields for 32-bit clients.
    pub eip:    u32,
    pub cs:     u32,
    pub eflags: u32,
    pub esp:    u32,
    pub ss:     u32,
    pub ds:     u16,
    pub es:     u16,
    pub fs:     u16,
    pub gs:     u16,
    /// `dos.pc.locked_stack.other_stack` value at push time. Sentinel
    /// `(0, 0)` means `None` (selector 0 is never a valid stack
    /// selector, so the encoding is unambiguous). `resume_continuation`
    /// restores `dos.pc.locked_stack.other_stack` from these fields.
    pub other_ss: u16,
    pub other_sp: u32,
    pub rm_call_struct_addr: u32,
}

pub(super) const HOST_CONTINUATION_SIZE: u32 = core::mem::size_of::<HostContinuation>() as u32;

impl HostContinuation {
    pub fn capture<A: crate::Arch>(regs: &Vcpu<A>, other_stack: Option<(u16, u32)>, rm_call_struct_addr: Option<u32>) -> Self {
        let (other_ss, other_sp) = other_stack.unwrap_or((0, 0));
        Self {
            eip:    regs.ip32(),
            cs:     regs.code_seg() as u32,
            eflags: regs.flags32(),
            esp:    regs.sp32(),
            ss:     regs.stack_seg() as u32,
            ds:     regs.ds as u16,
            es:     regs.es as u16,
            fs:     regs.fs as u16,
            gs:     regs.gs as u16,
            other_ss,
            other_sp,
            rm_call_struct_addr: rm_call_struct_addr.unwrap_or(0),
        }
    }

    pub fn restore<A: crate::Arch>(&self, regs: &mut Vcpu<A>) {
        regs.frame.cs  = self.cs as u64;
        regs.frame.rip = self.eip as u64;
        regs.set_flags32(self.eflags);
        regs.frame.ss  = self.ss as u64;
        regs.frame.rsp = self.esp as u64;
        regs.ds        = self.ds as u64;
        regs.es        = self.es as u64;
        regs.fs        = self.fs as u64;
        regs.gs        = self.gs as u64;
    }

    /// Decode the optional DPMI register-block pointer.
    pub fn rm_call_struct_addr(&self) -> Option<u32> {
        if self.rm_call_struct_addr == 0 { None } else { Some(self.rm_call_struct_addr) }
    }

    /// Decode the captured `other_stack` value. `(0, 0)` ⇒ None.
    pub fn other_stack(&self) -> Option<(u16, u32)> {
        let ss = self.other_ss;
        let sp = self.other_sp;
        if ss == 0 { None } else { Some((ss, sp)) }
    }
}

/// DPMI real-mode call structure used by INT 31h/0300-0302 and callbacks.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct RmCallStruct {
    pub edi: u32, pub esi: u32, pub ebp: u32, pub _reserved: u32,
    pub ebx: u32, pub edx: u32, pub ecx: u32, pub eax: u32,
    pub flags: u16, pub es: u16, pub ds: u16, pub fs: u16, pub gs: u16,
    pub ip: u16, pub cs: u16, pub sp: u16, pub ss: u16,
}

impl RmCallStruct {
    pub fn capture<A: crate::Arch>(regs: &Vcpu<A>) -> Self {
        Self {
            edi: regs.rdi as u32, esi: regs.rsi as u32, ebp: regs.rbp as u32, _reserved: 0,
            ebx: regs.rbx as u32, edx: regs.rdx as u32, ecx: regs.rcx as u32, eax: regs.rax as u32,
            flags: machine::guest_flags(regs) as u16, es: regs.es as u16, ds: regs.ds as u16,
            fs: regs.fs as u16, gs: regs.gs as u16, ip: regs.ip32() as u16,
            cs: regs.code_seg(), sp: regs.sp32() as u16, ss: regs.stack_seg(),
        }
    }

    pub fn restore_gp<A: crate::Arch>(&self, regs: &mut Vcpu<A>) {
        regs.rax = (regs.rax & !0xFFFFFFFF) | self.eax as u64;
        regs.rbx = (regs.rbx & !0xFFFFFFFF) | self.ebx as u64;
        regs.rcx = (regs.rcx & !0xFFFFFFFF) | self.ecx as u64;
        regs.rdx = (regs.rdx & !0xFFFFFFFF) | self.edx as u64;
        regs.rsi = (regs.rsi & !0xFFFFFFFF) | self.esi as u64;
        regs.rdi = (regs.rdi & !0xFFFFFFFF) | self.edi as u64;
        regs.rbp = (regs.rbp & !0xFFFFFFFF) | self.ebp as u64;
    }
}

// ─── Foundation primitives ────────────────────────────────────────────
//
// The pm-side cursor is tracked as a full (SS, SP) pair — never just
// an SP — so that handlers which switch SS off the kernel-shared
// host_stack onto their own locked stack (DPMI 0.9 §3.1.2) round-trip
// correctly. When user is on the pm side, the cursor is `regs.SS:SP`
// (whatever stack they're on right now). When user is on the rm side,
// it's been stashed in `other_stack` at toggle time, capturing both
// segment and offset of wherever pm last was.

/// Pick the pm-side stack selector for a fresh first-entry. 32-bit
/// clients get the PM32 alias (D=1), 16-bit clients PM16. Both alias
/// the same physical buffer at `host_stack_base()`.
pub(super) fn host_stack_pm_seg<A: crate::Arch>(dos: &thread::DosState<A>) -> u16 {
    if dos.dpmi.as_ref().is_some_and(|d| d.client_use32) {
        HOST_STACK_PM32_SEL
    } else {
        HOST_STACK_PM16_SEL
    }
}

/// Provides the pm-side stack `(SS, SP)` for the next push or pop —
/// "give me the stack to use for the pm side".
///
///   - chain empty (`other_stack=None`): a fresh host_stack at empty
///     TOS. First-entry will switch the user onto it.
///   - in chain, user on pm side (`mode != VM86`): the user's current
///     `regs.SS:SP`. Works whether SS is HOST_STACK_PM* or a
///     handler-owned locked stack; we just track wherever pm
///     currently is.
///   - in chain, user on rm side (`mode == VM86`): pm side's
///     `(SS, SP)` was stashed in `other_stack` at the toggle that put
///     us on rm. Read it back.
#[inline]
pub(super) fn pm_get_stack<A: crate::Arch>(dos: &thread::DosState<A>, regs: &Vcpu<A>) -> (u16, u32) {
    match dos.pc.locked_stack.other_stack {
        None => (host_stack_pm_seg(dos), dos::host_stack_empty_sp()),
        Some(p) if regs.mode() == crate::UserMode::VM86 => p,
        Some(_) => (regs.stack_seg(), regs.sp32()),
    }
}

/// Resolve a (SS, SP) pair to a linear address, using the LDT for SS
/// base. Used by continuation and IRET-frame helpers for explicit
/// pm-side cursors.
fn pm_addr(ldt: &[u64], cursor: (u16, u32)) -> u32 {
    seg_base(ldt, cursor.0).wrapping_add(cursor.1)
}

fn fresh_rm_stack() -> (u16, u32) {
    (dos::rm_stack_seg(), rm_stack_top() as u32)
}

/// rm-side stack provider: live rm cursor if tracked in other_stack
/// (chain in flight), else rm_dedicated:rm_TOS (first-entry default).
/// Used by `push_continuation_and_switch_to_rm_side` callers when the recipe does not have a
/// user-supplied rm SS:SP.
pub(super) fn rm_get_stack<A: crate::Arch>(dos: &thread::DosState<A>) -> (u16, u32) {
    dos.pc.locked_stack.other_stack.unwrap_or_else(fresh_rm_stack)
}

fn rm_cursor_for_pm_entry<A: crate::Arch>(dos: &thread::DosState<A>, regs: &Vcpu<A>) -> (u16, u32) {
    match dos.pc.locked_stack.other_stack {
        None => fresh_rm_stack(),
        Some(cursor) if regs.mode() != crate::UserMode::VM86 => cursor,
        Some(_) => (regs.stack_seg(), regs.sp32()),
    }
}

/// Capture current regs as a HostContinuation and write it at
/// `(pm_get_stack.SS, pm_get_stack.SP − HOST_CONTINUATION_SIZE)`. Returns the
/// post-push (SS, SP). Private — recipes go through `push_continuation_and_switch_to_pm_side`
/// or `push_continuation_and_switch_to_rm_side`, the only entry points to the locked-stack
/// chain.
fn push_continuation<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, rm_call_struct_addr: Option<u32>) -> (u16, u32) {
    push_continuation_at_cursor(dos, regs, rm_call_struct_addr, None)
}

/// `push_continuation` with an optional explicit pm-side (SS, SP) target
/// instead of `pm_get_stack`'s chain cursor. Used by exception dispatch,
/// which must place its frames in the host stack's exception region — the
/// chain cursor may point at the client's own stack, where the client's
/// exception handler is entitled to scribble (see `dos::EXC_STACK_TOP`).
fn push_continuation_at_cursor<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, rm_call_struct_addr: Option<u32>, cursor: Option<(u16, u32)>) -> (u16, u32) {
    let save = HostContinuation::capture(regs, dos.pc.locked_stack.other_stack, rm_call_struct_addr);
    let (ss, sp) = cursor.unwrap_or_else(|| pm_get_stack(dos, regs));
    let new_sp = sp - HOST_CONTINUATION_SIZE;
    let addr = pm_addr(&dos.ldt[..], (ss, new_sp));
    regs.write::<HostContinuation>((addr) as usize, save);
    {
        let (c, e, s2, p, r) = (save.cs, save.eip, save.ss, save.esp, save.rm_call_struct_addr);
        dos_trace!("[HC push] @{:04x}:{:#x} (lin={:#x}) save cs:eip={:04x}:{:#x} ss:esp={:04x}:{:#x} other={:?} rmcs={:#x}",
            ss, new_sp, addr, c, e, s2, p, save.other_stack(), r);
    }
    (ss, new_sp)
}

/// Read the topmost HostContinuation on the pm side. The caller follows
/// with `resume_continuation`, which restores SS:SP and `other_stack`, so
/// the post-pop cursor does not need to live anywhere.
pub(super) fn pop_continuation<A: crate::Arch>(dos: &thread::DosState<A>, regs: &Vcpu<A>) -> HostContinuation {
    pop_continuation_at(regs, &dos.ldt[..], pm_get_stack(dos, regs))
}

/// Read a HostContinuation at an explicit (SS, SP). Used by recipes that
/// know the pm-side cursor directly.
pub(super) fn pop_continuation_at<A: crate::Arch>(regs: &Vcpu<A>, ldt: &[u64], cursor: (u16, u32)) -> HostContinuation {
    let addr = pm_addr(ldt, cursor);
    let save = regs.read::<HostContinuation>((addr) as usize);
    {
        let (c, e, s2, p, r) = (save.cs, save.eip, save.ss, save.esp, save.rm_call_struct_addr);
        dos_trace!("[HC pop ] @{:04x}:{:#x} (lin={:#x}) save cs:eip={:04x}:{:#x} ss:esp={:04x}:{:#x} other={:?} rmcs={:#x}",
            cursor.0, cursor.1, addr, c, e, s2, p, save.other_stack(), r);
    }
    save
}

pub(super) fn resume_continuation<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, save: HostContinuation) {
    let saved_regs = save.rm_call_struct_addr().map(|addr| {
        let current = RmCallStruct::capture(regs);
        let saved = regs.read::<RmCallStruct>((addr) as usize);
        regs.write::<RmCallStruct>((addr) as usize, current);
        saved
    });

    save.restore(regs);
    dos.pc.locked_stack.other_stack = save.other_stack();

    if let Some(saved) = saved_regs {
        saved.restore_gp(regs);
        if regs.mode() == crate::UserMode::VM86 {
            let ret_ip = machine::vm86_pop(regs);
            let ret_cs = machine::vm86_pop(regs);
            machine::set_vm86_ip(regs, ret_ip);
            machine::set_vm86_cs(regs, ret_cs);
        }
    }
}

// ─── DPMI side-switch primitives ─────────────────────────────────────
//
// These are the only entry points that both push a HostContinuation and move
// execution between the DPMI PM side and the RM side. Their contract is
// deliberately narrow:
//
//   1. Push exactly one HostContinuation on the PM side before changing mode bits.
//   2. Set regs.SS:SP to the destination side's cursor.
//   3. Set other_stack to the cursor for the side that is no longer current.
//   4. Do not choose the destination CS:EIP or add recipe-specific frames.
//
// Callers own target CS:EIP, interrupt/call frames, register marshalling,
// and any later adjustment of other_stack after adding records above the
// HostContinuation.

/// Push a HostContinuation and make the PM side current.
///
/// Postconditions:
///   - `regs.mode()` is protected mode (`VM_FLAG` clear).
///   - `regs.SS:SP` points at the newly-pushed HostContinuation on the PM side.
///   - `other_stack` holds the RM resume cursor. For first entry this is
///     the dedicated RM stack top, not the caller's VM86 stack.
///
/// The caller must then choose PM `CS:EIP` and may add recipe-specific
/// frames above the HostContinuation before finalizing `regs.SP`.
pub(super) fn push_continuation_and_switch_to_pm_side<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, rm_call_struct_addr: Option<u32>) -> (u16, u32) {
    push_continuation_and_switch_to_pm_side_at(dos, regs, rm_call_struct_addr, None)
}

/// `push_continuation_and_switch_to_pm_side` with an optional explicit
/// pm-side cursor for the HostContinuation (see `push_continuation_at_cursor`).
pub(super) fn push_continuation_and_switch_to_pm_side_at<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, rm_call_struct_addr: Option<u32>, cursor: Option<(u16, u32)>) -> (u16, u32) {
    if_record(IF_SWITCH_PM, regs, if_bit(regs), if_bit(regs),
        dos.pc.locked_stack.other_stack);
    // Track where the RM side should resume if this PM entry reflects
    // back to real mode. First entry must use the dedicated RM stack;
    // a VM86 caller's own stack may be too small for BIOS/DOS handlers.
    // HostContinuation still captures the interrupted SS:SP for final restore.
    let next_rm_cursor = rm_cursor_for_pm_entry(dos, regs);
    let pm_save_at = push_continuation_at_cursor(dos, regs, rm_call_struct_addr, cursor);
    regs.frame.ss  = pm_save_at.0 as u64;
    regs.frame.rsp = pm_save_at.1 as u64;
    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    dos.pc.locked_stack.other_stack = Some(next_rm_cursor);
    pm_save_at
}

/// Push a HostContinuation and make the RM side current.
///
/// Postconditions:
///   - `regs.mode()` is VM86 (`VM_FLAG` set).
///   - `regs.SS:SP` is `rm_dest`.
///   - `other_stack` holds the PM cursor where the HostContinuation was pushed.
///
/// The caller must then choose RM `CS:EIP` and may add recipe-specific
/// PM-side frames above the HostContinuation. If it does, it must update
/// `other_stack` to the new topmost PM cursor before returning to user code.
pub(super) fn push_continuation_and_switch_to_rm_side<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>,
                                rm_dest: (u16, u32), rm_call_struct_addr: Option<u32>) -> (u16, u32) {
    let pm_save_at = push_continuation(dos, regs, rm_call_struct_addr);
    regs.frame.ss  = rm_dest.0 as u64;
    regs.frame.rsp = rm_dest.1 as u64;
    regs.frame.rflags |= machine::VM_FLAG as u64;
    dos.pc.locked_stack.other_stack = Some(pm_save_at);
    pm_save_at
}

// ─── Dedicated RM stack ───────────────────────────────────────────────
//
// The dedicated RM stack is a per-thread paragraph-aligned buffer in
// low memory (`dos::rm_stack_base()` / `dos::rm_stack_size()`). All
// kernel-orchestrated RM execution — RM-INT reflection from PM, DPMI
// 0300/0301/0302 calls, RM-side of callbacks — runs on it. Each
// excursion starts at `rm_stack_top()` and grows down; the contents
// between excursions are dead bytes (not preserved across nesting).

/// Top-of-stack offset for a fresh RM excursion: SP starts here and
/// pushes go below. The (base & 0xF) prefix accounts for the buffer's
/// possible sub-paragraph alignment within LowMem — `rm_stack_seg()`
/// floors to the paragraph, so SP needs to be offset back up to land
/// inside the buffer. Subtract two on top of that to leave a 16-bit
/// guard word so a 32-bit `pushd` near the top doesn't roll past the
/// buffer end.
pub(super) fn rm_stack_top() -> u16 {
    dos::rm_stack_align_offset() + (dos::rm_stack_size() as u16) - 2
}

// =============================================================================
// Stub-segment LDT layout
// =============================================================================
//
// The stub bytes themselves live at `dos::host_stack_base() ... STUB_BASE`
// (a fixed CD-31 array set up by `dos::setup_ivt`); these LDT slots are the
// PM views onto that memory. `dpmi::install_kernel_ldt_slots` allocates and
// programs them at thread init.

/// LDT index of the vector-default stub segment. Base=0, limit=0x0FFF, 16-bit.
/// Every entry in `pm_vectors` that the client has not installed points into
/// this segment at STUB_BASE + vec*2 (a `CD 31` that traps back to the host).
/// When dpmi_int31 sees CS == this selector, the trap is a default-vector
/// reflection: route to `vector_stub_reflect` which dispatches the vector to
/// the real-mode IVT.
///
/// Placed at LDT[200] — well above the CWSDPMI [1..127] range.
pub const VECTOR_STUB_LDT_IDX: usize = 4;

/// LDT index of the host "special stub" segment. Base=0, limit=0x0FFF, 16-bit.
/// Addresses handed back to the client for host services (0305h PM save/restore,
/// 0306h PM-to-real switch) and the `SLOT_EXCEPTION_RET` return trampoline
/// live in this segment. When dpmi_int31 sees CS == this selector,
/// pm_stub_dispatch routes by slot. Keeping this separate from
/// VECTOR_STUB_LDT_IDX prevents the ambiguity between default-vector stubs
/// 0xFB-0xFF and the special slots at the same offsets.
pub const SPECIAL_STUB_LDT_IDX: usize = 7;

/// Selector value (TI=1, RPL=3) for the kernel-owned VECTOR_STUB segment
/// that holds the per-vector default INT-reflection stubs.
pub(super) const VECTOR_STUB_SEL: u16 = ((VECTOR_STUB_LDT_IDX as u16) << 3) | 4 | 3;

/// Selector value (TI=1, RPL=3) for the kernel-owned SPECIAL_STUB segment
/// that holds the host's PM return trampolines (HW-IRQ unwind, exception
/// return, raw mode switch, save/restore).
pub(super) const SPECIAL_STUB_SEL: u16 = ((SPECIAL_STUB_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT indices for the kernel-shared host stack — three aliasing
/// selectors at the same base (`dos::host_stack_base()`), one with B=0
/// for 16-bit clients and one with B=1 for 32-bit clients. The bitness
/// difference only controls whether push/pop uses SP or ESP; the
/// physical buffer is the same. Host-internal — not handed to the client.
pub const HOST_STACK_PM16_LDT_IDX: usize = 8;
pub const HOST_STACK_PM32_LDT_IDX: usize = 9;
pub const HOST_STACK_PM16_SEL: u16 = ((HOST_STACK_PM16_LDT_IDX as u16) << 3) | 4 | 3;
pub const HOST_STACK_PM32_SEL: u16 = ((HOST_STACK_PM32_LDT_IDX as u16) << 3) | 4 | 3;

/// Sentinel for "synthetic IRET" continuations. Reserves `SPECIAL_STUB_SEL:0`
/// (which would dispatch via slot 0 = SLOT_XMS — RM-only, never used by
/// pm_stub_dispatch). Don't add a PM slot 0 handler without picking a
/// different sentinel.
const SYNTHETIC_HOST_IRET_EIP: u32 = 0;

fn synthetic_host_iret_target() -> (u16, u32) {
    (SPECIAL_STUB_SEL, SYNTHETIC_HOST_IRET_EIP)
}

// ─── PM interrupt delivery ─────────────────────────────────────────────
//
// PM IRQ delivery uses the same cross-mode chain as RM reflection:
// `regs.SS:SP` is the live stack cursor, and `other_stack` holds the
// cursor for the side not currently executing. First-entry/toggle cases
// push a `HostContinuation` plus an IRET frame targeting
// `SLOT_RESUME_CONTINUATION`; nested PM-side IRQs only need a normal IRET
// frame on the current PM stack.

/// Deliver a PM soft INT to the installed handler.
///
/// Per DPMI 0.9 §3.1.2: software interrupts do **not** switch stacks —
/// the handler runs on the client's own PM stack. Standard hardware-INT
/// semantics done in software:
///
///   - Push an IRET frame on `regs.ss:regs.sp` (the client's stack) with
///     return CS:EIP:EFLAGS pointing back at the interrupted client.
///     Frame width follows the DPMI client type. Some 32-bit clients install
///     handlers in 16-bit-looking segments but return with IRETD.
///   - Set CS:EIP to the installed handler. Clear TF so we don't
///     single-step into the handler. IF/IOPL/etc. follow the caller's
///     EFLAGS unchanged (spec leaves soft-INT handler IF state alone).
///   - Run. The handler's eventual IRET pops the frame and resumes the
///     client directly — no kernel involvement, no snapshot, no stack
///     switch.
pub(super) fn deliver_pm_int<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, vector: u8) -> thread::KernelAction {
    let (sel, off) = dos.pm_vectors[vector as usize];
    let frame_use32 = match dos.dpmi.as_ref() {
        Some(dpmi) => dpmi.client_use32,
        None => return thread::KernelAction::Done,
    };
    push_iret_frame(&dos.ldt[..], regs, frame_use32,
        regs.ip32(), regs.code_seg(), machine::guest_flags(regs));
    if sel == VECTOR_STUB_SEL && off == dos::STUB_BASE + (vector as u32) * 2 {
        let (stub_sel, stub_off) = synthetic_host_iret_target();
        regs.set_cs32(stub_sel as u32);
        regs.set_ip32(stub_off);
        return reflect_int_to_real_mode(dos, regs, vector);
    }
    regs.set_cs32(sel as u32);
    regs.set_ip32(off);
    regs.clear_flag32(1 << 8);
    // Skip per-call trace for noisy INT 21 character-output AHs so the
    // exception-handler dump and CRT printf output stay readable.
    let ah = (regs.rax >> 8) as u8;
    let chatty = vector == 0x21 && matches!(ah, 0x02 | 0x06 | 0x09);
    if !chatty {
        dos_trace!("[DPMI] PM_INT vec={:02X} -> {:04x}:{:#x} on client SS:ESP={:04x}:{:#x}",
            vector, sel, off, regs.frame.ss as u16, regs.sp32());
    }
    thread::KernelAction::Done
}

/// Deliver a HW IRQ to a PM handler. Per DPMI 0.9 §3.1.2 the host
/// switches to the locked PM stack on the *first* entry from a non-
/// handler context (the client's PM stack or VM86); nested entries
/// already inside a handler context reuse the existing stack chain.
///
///   - **First entry or RM-side toggle**: push a `HostContinuation`, switch to
///     the PM locked-stack alias, and push an IRET frame targeting
///     `SLOT_RESUME_CONTINUATION`. The handler IRETs to that stub, and
///     the unified continuation resume restores the interrupted
///     state, including SS:ESP.
///
///   - **Nested while already on the PM side of a chain**: push only an
///     IRET frame at `regs.ESP - frame_size` targeting the outer CS:EIP.
///     No `HostContinuation` is needed because the current PM stack already is
///     the live cursor and same-privilege IRET can unwind it directly.
///
/// Works for non-DPMI threads too: `install_kernel_ldt_slots` makes the
/// LDT + kernel-owned selectors (VECTOR_STUB, SPECIAL_STUB, HOST_STACK_PM*)
/// available at thread init. When `pm_vectors[vec]` is the default stub,
/// the round-trip lands in `vector_stub_reflect` which discriminates the
/// first-entry case by the IRET target == `SLOT_RESUME_CONTINUATION`.
/// Diagnostic: last HW-IRQ delivery info, printed by the exception
/// dispatcher when a non-DPMI VM86 thread faults — lets us see whether
/// a HW IRQ was just delivered (and where) right before the crash.
/// Layout: (vec, target_sel, target_off, src_cs, src_ip, src_ss, src_sp).
pub(super) static mut LAST_IRQ: (u8, u16, u32, u16, u32, u16, u32) = (0xFF, 0, 0, 0, 0, 0, 0);

// ── Zero-perturbation virtual-IF trace ring ──────────────────────────────
// One entry per PM-IRQ-chain event, written inline (pure stores, no I/O,
// no formatting) so it doesn't change instruction timing — the Sokoban
// stuck-IF=0 hang is a Heisenbug that print-tracing hides. Dumped only on
// the F12 state key via `dump_if_ring()`.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(super) struct IfEvt {
    pub tag: u8,        // IF_* tag below
    pub vm86: bool,     // true = guest in VM86 at this point
    pub cs: u16,
    pub ip: u32,
    pub if_in: bool,    // virtual IF before this event
    pub if_out: bool,   // virtual IF after this event
    pub other: (u16, u32), // locked_stack.other_stack at this point
}
pub(super) const IF_SWITCH_PM: u8 = 1; // push_continuation_and_switch_to_pm_side (first/toggle entry)
pub(super) const IF_REFLECT_RM: u8 = 2; // reflect_int_to_real_mode (clears IF)
pub(super) const IF_RESUME_CONTINUATION: u8 = 3;    // resume_continuation_from_stub (pops HostContinuation)
pub(super) const IF_PM_IRQ_NESTED_DEF: u8 = 4; // deliver_pm_irq nested, default vector (inline reflect)
pub(super) const IF_PM_IRQ_NESTED: u8 = 5;     // deliver_pm_irq nested, hooked vector (stub return)
pub(super) const IF_PM_IRQ_FIRST: u8 = 6;      // deliver_pm_irq first-entry/toggle

const IF_RING_LEN: usize = 128;
pub(super) static mut IF_RING: [IfEvt; IF_RING_LEN] = [IfEvt {
    tag: 0, vm86: false, cs: 0, ip: 0, if_in: false, if_out: false, other: (0, 0),
}; IF_RING_LEN];
pub(super) static mut IF_RING_POS: usize = 0;

#[inline]
pub(super) fn if_record<A: crate::Arch>(tag: u8, regs: &Vcpu<A>, if_in: bool, if_out: bool,
                        other: Option<(u16, u32)>) {
    unsafe {
        let i = IF_RING_POS % IF_RING_LEN;
        IF_RING[i] = IfEvt {
            tag,
            vm86: regs.mode() == crate::UserMode::VM86,
            cs: regs.code_seg(),
            ip: regs.ip32(),
            if_in,
            if_out,
            other: other.unwrap_or((0, 0)),
        };
        IF_RING_POS = IF_RING_POS.wrapping_add(1);
    }
}

/// The guest's virtual interrupt flag (VIF/bit 19) — the kernel's single store.
#[inline]
fn if_bit<A: crate::Arch>(regs: &Vcpu<A>) -> bool {
    regs.frame.rflags & (machine::VIF_FLAG as u64) != 0
}

/// F12 hook for virtual-IF diagnostics. Prints the most recent ring entries
/// (oldest first): tag, guest mode, CS:IP at record time, virtual-IF
/// before→after, and the other_stack cursor.
pub(super) fn dump_if_ring() {
    unsafe {
        let pos = IF_RING_POS;
        let n = pos.min(IF_RING_LEN);
        crate::dbg_println!("[IFRING] {} events total, showing last {} in_hw_irq={}",
            pos, n,
            super::IN_HW_IRQ_CONTEXT.load(core::sync::atomic::Ordering::Relaxed));
        for k in 0..n {
            let i = (pos - n + k) % IF_RING_LEN;
            let e = IF_RING[i];
            crate::dbg_println!(
                "[IFRING] #{:03} tag={} vm86={} {:04X}:{:08X} if {}→{} other={:04X}:{:08X}",
                pos - n + k, e.tag, e.vm86 as u8, e.cs, e.ip,
                e.if_in as u8, e.if_out as u8, e.other.0, e.other.1);
        }
    }
}

pub(super) fn deliver_pm_irq<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, vector: u8) {
    let (sel, off) = dos.pm_vectors[vector as usize];
    unsafe {
        LAST_IRQ = (vector, sel, off, regs.code_seg(), regs.ip32(),
                    regs.stack_seg(), regs.sp32());
    }
    let default_vector = sel == VECTOR_STUB_SEL && off == dos::STUB_BASE + (vector as u32) * 2;
    let handler_use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);

    // Discriminate via (regs.mode, other_stack):
    //   (PM,   Some) → nested on pm side; plant iret-frame at
    //                   regs.SP − frame_size on whatever stack the
    //                   handler is currently using. Hardware same-priv
    //                   IRET unwinds inline; no kernel save needed
    //                   because regs.SS:SP IS the cursor and we can
    //                   trust hardware to put it back.
    //   (VM86, Some) → toggle from rm side: push save on pm side
    //                   (whose cursor is in other_stack), switch to
    //                   pm side at the post-push position, leave the
    //                   prior rm SS:SP captured in the save for unwind.
    //   (_,    None) → first-entry from client: pm side is empty, so
    //                   pm_get_stack defaults to host_stack:empty_sp.
    //                   Same path as toggle, plus the empty default.
    let in_pm = regs.mode() != crate::UserMode::VM86;
    let nested_on_pm = in_pm && dos.pc.locked_stack.other_stack.is_some();
    let pre_vif = if_bit(regs);
    let delivery_tag = if nested_on_pm && default_vector { IF_PM_IRQ_NESTED_DEF }
                       else if nested_on_pm { IF_PM_IRQ_NESTED }
                       else { IF_PM_IRQ_FIRST };
    // Track where push_continuation actually placed the HostContinuation, so
    // the default-vector reflect below pops the SAME (possibly nested) slot
    // instead of the fixed top-of-stack. A HW IRQ taken *inside* an active
    // cross-mode excursion (e.g. the timer firing during a DPMI sim-INT 10h
    // VESA call) pushes its HC one slot deeper; reading the fixed top slot
    // grabbed the outer excursion's HC and leaked a VM86-context segment into
    // the PM frame → #GP on the exit's `pop gs` (Quake/Doom under Bochs, where
    // timing lands the tick mid-excursion).
    let pushed_hc_at = if nested_on_pm && default_vector {
        // Nested IRQ on an UNHOOKED vector → default stub reflects to RM below;
        // the RM/VM86 handler's IRET restores VIF in hardware (VME), so no stub
        // round-trip is needed. Plant the iret-frame inline at regs.SS:[SP-frame]
        // (push_iret_frame uses regs.frame.ss for the segment base, so this
        // writes whatever stack the handler is currently on — DPMI 0.9 §3.1.2
        // permits handler SS != HOST_STACK_PM*).
        push_iret_frame(&dos.ldt[..], regs, handler_use32,
            regs.ip32(), regs.code_seg(), machine::guest_flags(regs));
        None
    } else if nested_on_pm {
        // Nested IRQ into the client's OWN PM handler. We're already on the PM
        // side so we don't switch, but we MUST still push a HostContinuation
        // (on the handler's current stack — pm_get_stack returns regs.SS:SP for
        // the nested case) and return the handler through SLOT_RESUME_CONTINUATION.
        // This is load-bearing for the virtual-IF: deliver clears VIF below
        // (handlers run with interrupts off), and the CPU CANNOT re-enable it on
        // the handler's IRET — POPF/IRET preserve EFLAGS bits 19/20. Only
        // resume_continuation, replaying the captured pre-IRQ eflags, puts VIF
        // back. Without this the nested path left VIF=0 forever: the client's
        // timer firing inside a DPMI excursion → mainline spins on a tick now
        // permanently held (VIP=1) — the Doom/Duke3D startup hang in the wild.
        let at = push_continuation(dos, regs, None);
        regs.frame.ss = at.0 as u64;
        regs.frame.rsp = at.1 as u64;
        let stub_eip = dos::STUB_BASE + dos::slot_offset(dos::SLOT_RESUME_CONTINUATION) as u32;
        push_iret_frame(&dos.ldt[..], regs, handler_use32,
            stub_eip, SPECIAL_STUB_SEL, machine::guest_flags(regs));
        Some(at)
    } else {
        // First-entry from client OR toggle from rm: push_continuation_and_switch_to_pm_side
        // pushes HostContinuation, lands user on top of the save, captures pre-
        // toggle rm SS:SP into other_stack (rm_TOS for first-entry from
        // PM client). Recipe layers an iret-to-SLOT_RESUME_CONTINUATION frame above
        // the save so the eventual handler IRET round-trips through
        // the kernel for unwind.
        let at = push_continuation_and_switch_to_pm_side(dos, regs, None);
        let stub_eip = dos::STUB_BASE + dos::slot_offset(dos::SLOT_RESUME_CONTINUATION) as u32;
        push_iret_frame(&dos.ldt[..], regs, handler_use32,
            stub_eip, SPECIAL_STUB_SEL, machine::guest_flags(regs));

        // Zero DS/ES/FS/GS:
        //   - PM-handler entry: spec wants undefined segs; null is the safe
        //     choice and matches what real DPMI hosts do.
        //   - The unwind via SLOT_RESUME_CONTINUATION's synthetic-IRET branch
        //     restores DS/ES from HC2, then exits to PM at SPECIAL_STUB_SEL
        //     for the next CD 31 trap. The exit asm's `pop ds` loads DS as a
        //     PM selector before the final IRET — a paragraph-sized VM86 seg
        //     here would #GP. Capturing zeros into HC2 keeps that pop safe.
        // HC1 still holds the original client segs for the outer unwind.
        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;
        Some(at)
    };

    if default_vector {
        // PoP timer ISR at 0F11:B110 — `inc word [DS:0x2C]` against its own
        // DGROUP — assumes DS=interrupted-program's data segment, matching
        // real-mode CPU semantics. Reflect to RM with client's pre-IRQ segs
        // restored from HC1 so the ISR finds the expected paragraph instead
        // of phys 0x2C in the BIOS IVT.
        let (stub_sel, stub_off) = synthetic_host_iret_target();
        regs.frame.cs = stub_sel as u64;
        regs.frame.rip = stub_off as u64;
        let r = reflect_int_to_real_mode(dos, regs, vector);
        // Use the actual pushed HC slot (nested-aware); fall back to the fixed
        // top slot only on the nested_on_pm path, which pushes no continuation.
        let pm_save_at = pushed_hc_at.unwrap_or((host_stack_pm_seg(dos),
                          dos::host_stack_empty_sp() - HOST_CONTINUATION_SIZE));
        let hc1 = pop_continuation_at(regs, &dos.ldt[..], pm_save_at);
        regs.ds = hc1.ds as u64;
        regs.es = hc1.es as u64;
        regs.fs = hc1.fs as u64;
        regs.gs = hc1.gs as u64;
        let _ = r;
        if_record(delivery_tag, regs, pre_vif, if_bit(regs), Some((vector as u16, 0)));
        return;
    }

    // PM HW-IRQ handler entry: clear VM, the guest's virtual IF (VIF — handlers
    // enter with interrupts disabled, textbook INT semantics), and TF. The real
    // IF (bit 9) is the host's, forced =1 at the arch exit. IOPL is pinned to 1
    // there too, so it needs no touch here.
    regs.frame.rflags &= !((machine::VM_FLAG | machine::VIF_FLAG | (1u32 << 8)) as u64);
    regs.frame.cs  = sel as u64;
    regs.frame.rip = off as u64;
    if_record(delivery_tag, regs, pre_vif, if_bit(regs), Some((vector as u16, 0)));
}

/// Push an IRET frame on the stack addressed by `regs.ss:regs.sp`, updating
/// regs.sp. Frame width matches the *handler's* bitness — 12 bytes for a
/// 32-bit handler (D=1), 6 bytes for 16-bit (D=0). This is the width the
/// handler's `IRET` will use on its way back, so push and matching pop must
/// agree on handler bitness, regardless of the client's overall size.
pub(super) fn push_iret_frame<A: crate::Arch>(ldt: &[u64], regs: &mut Vcpu<A>, handler_is_32: bool,
                   eip: u32, cs: u16, flags: u32) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 12 } else { 6 };
    // Frame width follows handler.D — what handler's IRET will pop.
    // SP semantics follow SS.B — full ESP wraps within seg-limit on a
    // 32-bit stack; SP wraps within 0x10000 with upper-ESP preserved on
    // a 16-bit stack. The two bits are independent (see Intel SDM 6.12).
    let sp_in = regs.sp32();
    let sp = if stack_is_32 {
        sp_in.wrapping_sub(frame_size)
    } else {
        let new_sp16 = (sp_in as u16).wrapping_sub(frame_size as u16);
        (sp_in & !0xFFFF) | new_sp16 as u32
    };
    let eff_sp = if stack_is_32 { sp } else { sp & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    let a = addr as usize;
    if handler_is_32 {
        regs.write::<u32>(a, eip);
        regs.write::<u32>(a + 4, cs as u32);
        regs.write::<u32>(a + 8, flags);
    } else {
        regs.write::<u16>(a, eip as u16);
        regs.write::<u16>(a + 2, cs);
        regs.write::<u16>(a + 4, flags as u16);
    }
    regs.set_sp32(sp);
}

/// Push a FAR-return frame (`CS:(E)IP`, no flags) on the stack addressed by
/// `regs.ss:regs.sp`, updating regs.sp. Width follows the *handler's* bitness
/// — 8 bytes for a 32-bit handler, 4 bytes for 16-bit — because the handler's
/// `RETF` is what pops it. Used for MS-Mouse INT 33h AX=0Ch PM callbacks,
/// which the driver enters with a FAR CALL and the handler ends with FAR RET
/// (unlike HW IRQ / DPMI callbacks, which IRET — see `push_iret_frame`).
pub(super) fn push_farret_frame<A: crate::Arch>(ldt: &[u64], regs: &mut Vcpu<A>, handler_is_32: bool,
                   eip: u32, cs: u16) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 8 } else { 4 };
    let sp_in = regs.sp32();
    let sp = if stack_is_32 {
        sp_in.wrapping_sub(frame_size)
    } else {
        let new_sp16 = (sp_in as u16).wrapping_sub(frame_size as u16);
        (sp_in & !0xFFFF) | new_sp16 as u32
    };
    let eff_sp = if stack_is_32 { sp } else { sp & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    let a = addr as usize;
    if handler_is_32 {
        regs.write::<u32>(a, eip);
        regs.write::<u32>(a + 4, cs as u32);
    } else {
        regs.write::<u16>(a, eip as u16);
        regs.write::<u16>(a + 2, cs);
    }
    regs.set_sp32(sp);
}

/// Pop an IRET frame off `regs.ss:regs.sp`, advancing regs.sp.
/// `handler_is_32` must match the width used at push time. Frame width
/// follows handler.D; SP semantics follow SS.B (see `push_iret_frame`).
pub(super) fn pop_iret_frame<A: crate::Arch>(ldt: &[u64], regs: &mut Vcpu<A>, handler_is_32: bool) -> (u32, u16, u32) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 12 } else { 6 };
    let sp_in = regs.sp32();
    let eff_sp = if stack_is_32 { sp_in } else { sp_in & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    let a = addr as usize;
    let frame = if handler_is_32 {
        (regs.read::<u32>(a), regs.read::<u32>(a + 4) as u16, regs.read::<u32>(a + 8))
    } else {
        (regs.read::<u16>(a) as u32, regs.read::<u16>(a + 2), regs.read::<u16>(a + 4) as u32)
    };
    let new_sp = if stack_is_32 {
        sp_in.wrapping_add(frame_size)
    } else {
        let new_sp16 = (sp_in as u16).wrapping_add(frame_size as u16);
        (sp_in & !0xFFFF) | new_sp16 as u32
    };
    regs.set_sp32(new_sp);
    frame
}

/// Per-vector default stub trap. Mimics, in kernel space, the canonical
/// PM stub a DOS extender would install:
///
///   push_regs              ← `push_continuation`   (in `reflect_int_to_real_mode`)
///   call simulate_rm_int   ← RM-INT round-trip       (in `reflect_int_to_real_mode`)
///   pop_regs               ← `resume_continuation` (in `resume_continuation_from_stub`)
///   iret                   ← synthetic host IRET
///
/// Uniform — no discrimination by iret-target. The planted iret-frame
/// (deliver_pm_irq or deliver_pm_int wrote it) is consumed by the
/// synthetic host IRET after `resume_continuation_from_stub` restores the continuation:
///   - `SLOT_RESUME_CONTINUATION` for cross-mode HW-IRQ first-entry.
///   - The outer caller's CS:EIP for soft-INT and nested-HW-IRQ.
pub(super) fn vector_stub_reflect<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>) -> thread::KernelAction {
    let eip = regs.ip32();
    let vector = ((eip.wrapping_sub(dos::STUB_BASE + 2)) / 2) as u8;
    if vector >= 0x10 {
        dos_trace!("[DPMI] VECSTUB vec={:#04x} SS:ESP={:04x}:{:#x} CS:EIP={:04x}:{:#x} DS={:04X} ES={:04X} DX={:04X} DI={:04X}",
            vector, regs.stack_seg(), regs.sp32(), regs.code_seg(), eip,
            regs.ds as u16, regs.es as u16, regs.rdx as u16, regs.rdi as u16);
    }
    // INT 31h's host default handler is the DPMI services API — NOT a real-
    // mode IVT reflection. A client that hooks INT 31h and tail-chains to the
    // previously-installed (host) vector — which we report as this default
    // stub (`AX=0204` returns VECTOR_STUB_SEL:STUB_BASE+0x62) — reaches here.
    // Reflecting it to RM silently drops the DPMI call (Borland RTM's loader
    // chains set-descriptor-base/limit on its PSP-alias selector this way; the
    // lost calls leave the selector unset → `Loader error (0010)`, blocking
    // Borland Pascal and Jazz Jackrabbit). Service it as DPMI instead. The
    // CD 31 in the stub pushed its own IRET frame on top of the original
    // caller's; pop it so dpmi_api's results return to that caller.
    if vector == 0x31 {
        let use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
        let (eip, cs, flags) = pop_iret_frame(&dos.ldt[..], regs, use32);
        regs.set_ip32(eip);
        regs.set_cs32(cs as u32);
        // The popped image is guest-view (the client's IF intent in the IF
        // slot, bit 19 absent) — raw set_flags32 would clear the canonical
        // VIF. `apply_guest_flags` maps the image's IF slot back to VIF.
        machine::apply_guest_flags(regs, flags);
        return super::dpmi::dpmi_api(machine, dos, regs);
    }

    let (stub_sel, stub_off) = synthetic_host_iret_target();
    regs.set_cs32(stub_sel as u32);
    regs.set_ip32(stub_off);
    reflect_int_to_real_mode(dos, regs, vector)
}


/// Reflect an INT to real mode via the IVT. Whether the IVT entry points
/// at BIOS, DOS, or a user-installed hook is irrelevant — it's just
/// "execute INT N in RM, come back when it's done". Used by the
/// per-vector default stub (`vector_stub_reflect`) and by the unhandled-
/// exception fallback (`dispatch_dpmi_exception`).
///
/// On the way out: push `HostContinuation`, switch to the RM-side cursor, and
/// set up regs to enter the IVT handler in VM86 with the trampoline
/// IRET frame pointing back at SLOT_RESUME_CONTINUATION. Per DPMI 0.9 §2.4 / §3.2:
/// EAX/EBX/ECX/EDX/ESI/EDI/EBP and flags are passed unaltered; segment
/// registers are undefined in real mode.
///
/// On the way back: RM IRET pops the trampoline frame and lands at
/// SLOT_RESUME_CONTINUATION. If the saved continuation target is the synthetic
/// host IRET marker, `resume_continuation_from_stub` restores the PM state and
/// immediately pops the frame the caller planted on the user stack.
pub(super) fn reflect_int_to_real_mode<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>, vector: u8) -> thread::KernelAction {
    // Run the RM handler on the dedicated RM stack — never the
    // client's own VM86 stack — so a HW IRQ landing during a sensitive
    // moment in the client (e.g. just after exec_return) can't trample
    // saved registers / return address. Works for VM86 and PM clients
    // alike, no DPMI session required.
    //
    // Capture the client's flags before push_continuation_and_switch_to_rm_side mutates them
    // (it sets VM_FLAG) — these go on the rm iret-frame so RM IRET
    // restores them unmodified per CPU's own INT-n semantics. Pushing
    // 0 or current handler flags would corrupt status bits across the
    // round-trip.
    let ret_flags = machine::guest_flags(regs) as u16;

    // rm_get_stack: live rm cursor if a chain is in flight (e.g., we're
    // a nested reflect inside an outer 0300 BIOS call), else rm_TOS.
    // The toggle pushes its iret-frame *below* this cursor, sharing
    // rm_dedicated LIFO-style without a snapshot copy.
    //
    // Per DPMI 0.9 §2.4 / §3.2 segment registers are "undefined" in real
    // mode after PM→RM int reflection. We pass the PM selector values
    // through unchanged — RM-side BIOS/DOS code that would dereference
    // them gets nonsense paragraphs (the spec's "undefined"), which is
    // fine since none does. Our own DOS handlers route buffer addressing
    // through `linear()` which is PM-aware, or via the dedicated
    // pmdos_int21_handler short-circuit for 16-bit clients (`pm_dos`).
    let rm_dest = rm_get_stack(dos);
    let _save_at = push_continuation_and_switch_to_rm_side(dos, regs, rm_dest, None);

    let ivt_off = machine::read_u16(regs, 0, (vector as u32) * 4);
    let ivt_seg = machine::read_u16(regs, 0, (vector as u32) * 4 + 2);

    // Push trampoline IRET frame on the RM slab, mirroring what the CPU's
    // own INT n in real mode would push: FLAGS / CS / IP.
    let ret_off: u16 = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION);
    let ret_seg: u16 = dos::CTRL_STUB_SEG;
    machine::vm86_push(regs, ret_flags);
    machine::vm86_push(regs, ret_seg);
    machine::vm86_push(regs, ret_off);

    // Enter the RM handler with the guest's virtual IF (VIF) cleared (matches
    // CPU's INT-n: clears IF, preserves status flags) and IOPL=1. The real IF
    // (bit 9) is the host's, untouched here and forced =1 at the arch exit.
    // VM_FLAG already set by push_continuation_and_switch_to_rm_side and
    // preserved by the read-modify-write.
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    let if_was = if_bit(regs);
    // vIOPL rides the flags unchanged (no IOPL force): the real IOPL is pinned
    // to 1 at the arch exit, so the RM-handler entry only needs VIF cleared.
    let new_flags = regs.flags32() & !machine::VIF_FLAG;
    regs.frame.rflags = new_flags as u64;
    if_record(IF_REFLECT_RM, regs, if_was, if_bit(regs),
        dos.pc.locked_stack.other_stack);

    // Per DPMI, the host must not translate PM selectors into RM paragraphs
    // when reflecting a software interrupt. The extender/client is responsible
    // for any DOS-call marshaling that requires real-mode segment values.

    dos_trace!("[DPMI] reflect INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X} DS={:04X} ES={:04X}",
        vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32(), regs.rax as u16,
        regs.ds as u16, regs.es as u16);

    thread::KernelAction::Done
}

/// SLOT_RESUME_CONTINUATION dispatch - the single continuation return.
///
/// Explicit DPMI RM calls and callbacks carry an `RmCallStruct` address in
/// the continuation; `resume_continuation` exchanges that register block and
/// restores the suspended side. A synthetic host IRET target asks this function
/// to consume a planted interrupt frame after restoring the continuation.
pub(super) fn resume_continuation_from_stub<A: crate::Arch>(dos: &mut thread::DosState<A>, regs: &mut Vcpu<A>) {
    const STATUS_MASK: u32 = 0x08D5;
    let resume_if_in = if_bit(regs);
    let resume_other = dos.pc.locked_stack.other_stack;
    let current_status = regs.flags32() & STATUS_MASK;

    let save = pop_continuation(dos, regs);
    let resumes_to_host_iret = save.cs as u16 == SPECIAL_STUB_SEL
        && save.eip == SYNTHETIC_HOST_IRET_EIP;
    let was_outermost = save.other_stack().is_none();
    resume_continuation(dos, regs, save);
    if resumes_to_host_iret {
        let use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
        let (ret_eip, ret_cs, ret_flags) = pop_iret_frame(&dos.ldt[..], regs, use32);
        regs.set_ip32(ret_eip);
        regs.set_cs32(ret_cs as u32);
        // ret_flags is guest-observable; `apply_guest_flags` maps its IF slot
        // to VIF. Then force VIF on: this frame closes a HW-IRQ/soft-INT
        // excursion, and the client resumes interruptible regardless of the
        // image (handlers enter with the image's IF slot cleared).
        machine::apply_guest_flags(regs, (ret_flags & !STATUS_MASK) | current_status);
        let vif_on = regs.flags32() | machine::VIF_FLAG;
        regs.set_flags32(vif_on);
    }
    // IRQ chain complete when we just popped an outermost HC (HC.other_stack=None
    // ⇒ first-entry from client). Nested HCs (Some) keep the flag so trace
    // gating stays correct inside a soft-INT-from-IRQ-handler reflect.
    if was_outermost {
        super::IN_HW_IRQ_CONTEXT.store(false, core::sync::atomic::Ordering::Relaxed);
    }
    if_record(IF_RESUME_CONTINUATION, regs, resume_if_in, if_bit(regs), resume_other);

    dos_trace!("[DPMI] RESUME_CONTINUATION_STUB -> {:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
}



// =============================================================================
// LDT descriptor decode helpers
// =============================================================================
//
// Used by the iret-frame primitives, the stub dispatchers, and the `dpmi` module's own
// LDT management. Bare descriptor decode — no DPMI session knowledge.

/// Get the base address for any selector. GDT selectors (TI=0) are flat.
pub(super) fn seg_base(ldt: &[u64], sel: u16) -> u32 {
    if sel & 4 == 0 { return 0; }
    let idx = (sel >> 3) as usize;
    if idx >= ldt.len() { return 0; }
    let d = ldt[idx];
    let b0 = ((d >> 16) & 0xFFFF) as u32;
    let b1 = ((d >> 32) & 0xFF) as u32;
    let b2 = ((d >> 56) & 0xFF) as u32;
    b0 | (b1 << 16) | (b2 << 24)
}

/// Get the byte limit for any selector. GDT selectors (TI=0) are treated as
/// flat (full 4 GiB). LDT descriptors honour the G (granularity) bit via
/// `desc_limit`.
pub(super) fn seg_limit(ldt: &[u64], sel: u16) -> u32 {
    if sel & 4 == 0 { return 0xFFFF_FFFF; }
    let idx = (sel >> 3) as usize;
    if idx >= ldt.len() { return 0; }
    super::dpmi::desc_limit(ldt[idx])
}

/// Get the D/B (default operand size) bit. GDT selectors are treated as 32-bit.
pub(super) fn seg_is_32(ldt: &[u64], sel: u16) -> bool {
    if sel & 4 == 0 { return true; }
    let idx = (sel >> 3) as usize;
    if idx >= ldt.len() { return true; }
    ldt[idx] & (1u64 << 54) != 0
}
