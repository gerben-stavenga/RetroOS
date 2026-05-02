//! PM/RM transition mechanics for our DOS personality.
//!
//! Owns the per-thread **locked PM stack** (DPMI 0.9 §3.1.2 "locked
//! protected mode stack") and tracks user execution state across mode
//! switches. The locked stack is a buffer in low memory, aliased by
//! two LDT selectors (PM16 with B=0, PM32 with B=1, both base=0) so
//! user PM handlers see SS_base matching client flat DS_base.
//!
//! ### User execution states
//!
//! Four logical states distinguished by (mode, stack):
//!
//! - `ClientPm`     — PM running on the client's own PM stack.
//! - `ClientRm`     — RM/VM86 running on the client's own RM stack.
//! - `PmInLocked`   — PM running on the locked PM stack. PM IRQ
//!                    handlers, exception handlers, RM callbacks, and
//!                    post-soft-INT-reflect PM continuations all run
//!                    here. The handler may switch SS to its own
//!                    "locked" stack mid-execution (DPMI 0.9 §3.1.2):
//!                    that switched-to stack also counts as the locked
//!                    stack until the handler switches back.
//! - `RmInLocked`   — RM running on the dedicated RM stack (a separate
//!                    per-thread buffer in low memory). BIOS reflection
//!                    from PM, DPMI 0300/0301/0302 calls, etc.
//!
//! ### State tracking
//!
//! Per-thread tracking lives in [`LockedStackState`]:
//!
//! - `depth`: nesting count of *handler-context* entries. 0 means we
//!   are in `ClientPm` or `ClientRm`. >0 means a handler is active —
//!   could be `PmInLocked` or `RmInLocked` (or further nesting).
//!   `enter_locked_pm` increments; `leave_locked_pm` decrements. Used
//!   to discriminate first-entry vs nested HW IRQ delivery without
//!   relying on `regs.SS`, which can be the user's switched-to stack.
//!
//! - `tos: (sel, esp)`: only meaningful while in `RmInLocked`. Records
//!   the SS:ESP that was current immediately before we transitioned
//!   into RM-in-locked, so that on return (or on a nested PM excursion
//!   from RM) we know where on the locked stack the snapshot/save
//!   chain lives. While the user is on the locked stack
//!   (`PmInLocked`), `regs.SS:ESP` is authoritative — the field is
//!   ignored.
//!
//! ### Frame kinds on the locked stack
//!
//! At any instant the locked stack holds zero or more LIFO frames:
//!
//! - `Save` — captured CPU state ([`ModeSave`]) for restoring on
//!   unwind. Pushed by recipes that cross from a non-handler context
//!   into a handler, or that nest a fresh handler-context save (PM
//!   excursion from RM-in-locked).
//! - `RmSnapshot` — a bytewise copy of the dedicated RM stack at the
//!   moment we entered RM-in-locked. On exit from RM-in-locked, this
//!   gets copied back so the outer RM-in-locked excursion (if any)
//!   resumes with its stack contents intact.
//!
//! The recipes (added in subsequent commits) compose push/pop of these
//! frames with regs manipulation; the dispatcher routes each kernel-
//! trapping return-stub (CD 31 at well-known addresses) to the matching
//! recipe.

use super::dos;
use super::dos_trace;
use super::machine;
use super::thread;
use crate::Regs;

/// Per-thread state tracking for the locked stack and the dedicated
/// RM stack. Lives on `dos.pc` alongside the existing PC machine
/// fields.
pub(super) struct LockedStackState {
    /// Handler-context nesting count.
    /// - 0 = client context (`ClientPm` / `ClientRm`).
    /// - >0 = handler context (`PmInLocked` / `RmInLocked` /
    ///   further-nested PM excursions during RM-in-locked).
    /// Updated only at recipe boundaries (`enter_locked_pm` /
    /// `leave_locked_pm` and the RM/PM excursion variants).
    pub depth: u8,

    /// SS:ESP captured at the moment we transitioned into
    /// `RmInLocked`. Tells the kernel where on the locked stack the
    /// chain (RmSnapshot + any saves) lives, since `regs.SS:ESP`
    /// while in `RmInLocked` is on the dedicated RM stack, not the
    /// locked stack. Inert when not in `RmInLocked`.
    ///
    /// Selector is part of the pair because the outer's `SS` may be
    /// our `LOCKED_STACK_PM*_SEL` *or* a selector the handler
    /// switched to (DPMI 0.9 §3.1.2 "If the client switches off this
    /// stack, the new stack must also be locked and will become the
    /// protected mode stack until it switches back").
    pub tos: LockedStackTos,
}

/// SS:ESP pair recording where on the locked stack the kernel-managed
/// chain lives at the moment of an RM-in-locked transition.
#[derive(Clone, Copy, Default)]
pub(super) struct LockedStackTos {
    pub sel: u16,
    pub esp: u32,
}

impl LockedStackState {
    pub fn new() -> Self {
        Self {
            depth: 0,
            tos: LockedStackTos::default(),
        }
    }

    /// True while a handler context is active anywhere up the chain.
    /// Equivalent to "user is in `PmInLocked` or `RmInLocked` (or
    /// further nesting)". Replaces the old `SS == LOCKED_STACK_PM*_SEL`
    /// heuristic used for nest-vs-first-entry decisions, since that
    /// heuristic breaks when a handler switches stacks mid-execution.
    pub fn in_handler(&self) -> bool {
        self.depth > 0
    }
}

/// Snapshot of CPU state captured across a kernel-orchestrated mode
/// switch. Pushed onto the locked stack by recipes that need to
/// remember "where to go back to". GP regs are deliberately not part
/// of this struct — DPMI 0.9 §2.4 round-trips them through the
/// handler / RM code, and recipes that need to preserve them across
/// an explicit call (DPMI 0300-02) lay their own typed frame above
/// the ModeSave.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct ModeSave {
    pub cs:     u32,
    pub eip:    u32,
    pub eflags: u32,
    pub ss:     u32,
    pub esp:    u32,
    pub ds:     u16,
    pub es:     u16,
    pub fs:     u16,
    pub gs:     u16,
}

pub(super) const MODE_SAVE_SIZE: u32 = core::mem::size_of::<ModeSave>() as u32;

impl ModeSave {
    pub fn capture(regs: &Regs) -> Self {
        Self {
            cs:     regs.code_seg() as u32,
            eip:    regs.ip32(),
            eflags: regs.flags32(),
            ss:     regs.stack_seg() as u32,
            esp:    regs.sp32(),
            ds:     regs.ds as u16,
            es:     regs.es as u16,
            fs:     regs.fs as u16,
            gs:     regs.gs as u16,
        }
    }

    pub fn restore(&self, regs: &mut Regs) {
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
}

// ─── Foundation primitives ────────────────────────────────────────────
//
// All save primitives operate at `dos.pc.host_stack_sp` (the
// kernel-tracked top of the locked-stack chain). No cursor parameters
// at the call site. Cursor-driven callers (where the user's
// post-iret SS:ESP lands on the save and host_stack_sp hasn't been
// synced) resync `host_stack_sp = regs.sp32()` themselves before
// invoking these — the resync is the cursor-driven step, not part of
// the primitive.

/// Capture current regs as a ModeSave and push it onto the locked
/// stack at `host_stack_sp - MODE_SAVE_SIZE`. Decrements
/// `host_stack_sp`, increments `depth`.
pub(super) fn push_save(dos: &mut thread::DosState, regs: &Regs) {
    let save = ModeSave::capture(regs);
    let cursor = dos.pc.host_stack_sp - MODE_SAVE_SIZE;
    let addr = dos::host_stack_base() + cursor;
    unsafe { core::ptr::write_unaligned(addr as *mut ModeSave, save); }
    dos.pc.host_stack_sp = cursor;
    dos.pc.locked_stack.depth = dos.pc.locked_stack.depth.saturating_add(1);
}

/// Pop the topmost ModeSave off the locked stack. Reads at
/// `host_stack_sp`, advances `host_stack_sp` past the save,
/// decrements `depth`. Does NOT touch regs — the caller calls
/// `save.restore(regs)` when ready (which may be immediately, or
/// after computing things from current regs first as `rm_iret_call`
/// does for its RmCallStruct writeback).
pub(super) fn pop_save(dos: &mut thread::DosState) -> ModeSave {
    let addr = dos::host_stack_base() + dos.pc.host_stack_sp;
    let save = unsafe { core::ptr::read_unaligned(addr as *const ModeSave) };
    dos.pc.host_stack_sp += MODE_SAVE_SIZE;
    dos.pc.locked_stack.depth = dos.pc.locked_stack.depth.saturating_sub(1);
    save
}

// ─── Dedicated RM stack ───────────────────────────────────────────────
//
// The dedicated RM stack is a per-thread paragraph-aligned buffer in
// low memory (`dos::rm_stack_base()` / `dos::rm_stack_size()`). All
// kernel-orchestrated RM execution — BIOS reflection from PM, DPMI
// 0300/0301/0302 calls, RM-side of callbacks — runs on it.
//
// Reentrance for nested kernel-orchestrated RM use is achieved by
// `push_rm_snapshot` (copies the buffer's current contents onto the
// locked stack) before the new excursion starts. `pop_rm_snapshot`
// copies them back on the way out. A nested excursion thus starts on
// a "fresh" RM stack from `rm_stack_top()`, and the outer excursion
// resumes with its bytes intact.

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

/// Snapshot the entire dedicated RM stack onto the locked stack.
/// Decrements `host_stack_sp` by the buffer size; the contents at
/// `host_stack_sp..host_stack_sp + size` mirror `rm_stack` byte for
/// byte. Caller is responsible for tracking that an `RmSnapshot`
/// frame now sits atop the locked stack so the matching
/// `pop_rm_snapshot` runs on the unwind path.
pub(super) fn push_rm_snapshot(dos: &mut thread::DosState) {
    let size = dos::rm_stack_size();
    let cursor = dos.pc.host_stack_sp - size;
    unsafe {
        core::ptr::copy_nonoverlapping(
            dos::rm_stack_base() as *const u8,
            (dos::host_stack_base() + cursor) as *mut u8,
            size as usize,
        );
    }
    dos.pc.host_stack_sp = cursor;
}

/// Restore the dedicated RM stack contents from the topmost
/// `RmSnapshot` frame on the locked stack. Advances `host_stack_sp`
/// past the snapshot.
pub(super) fn pop_rm_snapshot(dos: &mut thread::DosState) {
    let size = dos::rm_stack_size();
    unsafe {
        core::ptr::copy_nonoverlapping(
            (dos::host_stack_base() + dos.pc.host_stack_sp) as *const u8,
            dos::rm_stack_base() as *mut u8,
            size as usize,
        );
    }
    dos.pc.host_stack_sp += size;
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
/// physical buffer is the same. The third alias is a VM86 paragraph
/// (`dos::host_stack_vm86_paragraph()`) consumed when ring-0 transiently
/// runs VM86 code (e.g. nested 0x0302 RM excursion). Host-internal —
/// not handed to the client.
pub const HOST_STACK_PM16_LDT_IDX: usize = 8;
pub const HOST_STACK_PM32_LDT_IDX: usize = 9;
pub const HOST_STACK_PM16_SEL: u16 = ((HOST_STACK_PM16_LDT_IDX as u16) << 3) | 4 | 3;
pub const HOST_STACK_PM32_SEL: u16 = ((HOST_STACK_PM32_LDT_IDX as u16) << 3) | 4 | 3;

// ─── Cross-mode save lane on host_stack ─────────────────────────────────
//
// Every PM-handler entry from a non-host-stack mode (HW IRQ outermost or
// BIOS-mid-handler) pushes a `ModeSave` capturing the interrupted regs
// onto host_stack at `pc.host_stack_sp`, then an iret_frame above it
// targeting `SLOT_PM_IRET`. The handler's IRET pops the iret_frame
// (hardware), traps to the kernel via the stub, kernel pops the ModeSave
// and restores. Pure nested-on-host-stack entries (handler-mid-execution
// IRQ where regs.SS is already HOST_STACK_PM) skip the ModeSave — the
// outer handler's CS:EIP and stack already hold the chain, so a plain
// hardware IRET back to outer is sufficient.

// CPU state snapshots and the primitives that read/write them
// (`push_save` / `pop_save` / `pop_save_at` / `peek_save_at` /
// `consume_save_at`) live in [`super::mode_transitions`]. This module
// composes them with DPMI policy.

/// Stub-frame for `SLOT_RM_IRET_CALL` — pushed above the `ModeSave` by
/// every explicit PM→RM-call entry (`0300/01/02` and `callback_entry`).
/// On unwind, `rm_iret_call` writes the post-RM regs into the
/// RmCallStruct at `rm_struct_addr`, then restores the saved GP regs
/// (PM caller's for `0300/01/02`; RM caller's for `callback_entry`).
/// Other slots (`SLOT_PM_IRET`, `SLOT_RM_IRET_REFLECT`) don't need this
/// — handler preservation / spec round-trip handle their GP regs.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct CallStubFrame {
    rm_struct_addr: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    /// 1 if the recipe pushed an `RmSnapshot` (because BIOS will run
    /// on our dedicated RM stack); 0 if the user supplied their own
    /// SS:SP via the RmCallStruct (BIOS runs there, our dedicated
    /// stack is untouched, no snapshot needed). On unwind the
    /// SLOT_RM_IRET_CALL handler conditionally pops the snapshot.
    used_dedicated_rm: u32,
}

const CALL_STUB_SIZE: u32 = core::mem::size_of::<CallStubFrame>() as u32;

impl CallStubFrame {
    pub(super) fn capture(regs: &Regs, rm_struct_addr: u32, used_dedicated_rm: bool) -> Self {
        Self {
            rm_struct_addr,
            eax: regs.rax as u32,
            ebx: regs.rbx as u32,
            ecx: regs.rcx as u32,
            edx: regs.rdx as u32,
            esi: regs.rsi as u32,
            edi: regs.rdi as u32,
            ebp: regs.rbp as u32,
            used_dedicated_rm: used_dedicated_rm as u32,
        }
    }

    pub(super) fn restore_gp(&self, regs: &mut Regs) {
        regs.rax = (regs.rax & !0xFFFFFFFF) | self.eax as u64;
        regs.rbx = (regs.rbx & !0xFFFFFFFF) | self.ebx as u64;
        regs.rcx = (regs.rcx & !0xFFFFFFFF) | self.ecx as u64;
        regs.rdx = (regs.rdx & !0xFFFFFFFF) | self.edx as u64;
        regs.rsi = (regs.rsi & !0xFFFFFFFF) | self.esi as u64;
        regs.rdi = (regs.rdi & !0xFFFFFFFF) | self.edi as u64;
        regs.rbp = (regs.rbp & !0xFFFFFFFF) | self.ebp as u64;
    }
}

/// Write a `CallStubFrame` at the cursor. Returns the new (lower) cursor.
pub(super) fn host_stack_write_call_args(cursor: u32, frame: CallStubFrame) -> u32 {
    let new_cursor = cursor - CALL_STUB_SIZE;
    let addr = dos::host_stack_base() + new_cursor;
    unsafe { core::ptr::write_unaligned(addr as *mut CallStubFrame, frame); }
    new_cursor
}

/// Read a `CallStubFrame` at the cursor.
fn host_stack_read_call_args(cursor: u32) -> CallStubFrame {
    let addr = dos::host_stack_base() + cursor;
    unsafe { core::ptr::read_unaligned(addr as *const CallStubFrame) }
}

/// Push an IRET frame for a PM handler entry at the given cursor. Returns
/// the new cursor. Width follows client bitness per DPMI 0.9 §10.6.
fn host_stack_write_iret(cursor: u32, client_use32: bool,
                         ret_eip: u32, ret_cs: u16, ret_flags: u32) -> u32 {
    let frame_size: u32 = if client_use32 { 12 } else { 6 };
    let new_cursor = cursor - frame_size;
    let addr = dos::host_stack_base() + new_cursor;
    unsafe {
        if client_use32 {
            let p = addr as *mut u32;
            core::ptr::write_unaligned(p,        ret_eip);
            core::ptr::write_unaligned(p.add(1), ret_cs as u32);
            core::ptr::write_unaligned(p.add(2), ret_flags);
        } else {
            let p = addr as *mut u16;
            core::ptr::write_unaligned(p,        ret_eip as u16);
            core::ptr::write_unaligned(p.add(1), ret_cs);
            core::ptr::write_unaligned(p.add(2), ret_flags as u16);
        }
    }
    new_cursor
}

/// Deliver a PM soft INT to the installed handler.
///
/// Per DPMI 0.9 §3.1.2: software interrupts do **not** switch stacks —
/// the handler runs on the client's own PM stack. Standard hardware-INT
/// semantics done in software:
///
///   - Push an IRET frame on `regs.ss:regs.sp` (the client's stack) with
///     return CS:EIP:EFLAGS pointing back at the interrupted client.
///     Frame width follows `dpmi.client_use32` per §10.6 (32-bit client →
///     12-byte IRETD frame; 16-bit → 6-byte IRET frame). The handler
///     owns matching its IRET width to the client's.
///   - Set CS:EIP to the installed handler. Clear TF so we don't
///     single-step into the handler. IF/IOPL/etc. follow the caller's
///     EFLAGS unchanged (spec leaves soft-INT handler IF state alone).
///   - Run. The handler's eventual IRET pops the frame and resumes the
///     client directly — no kernel involvement, no snapshot, no stack
///     switch.
pub(super) fn deliver_pm_int(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    let (sel, off) = dos.pm_vectors[vector as usize];
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => return thread::KernelAction::Done,
    };
    let client_use32 = dpmi.client_use32;
    let handler_flags = regs.flags32() & !(1u32 << 8);
    push_iret_frame(&dos.ldt[..], regs, client_use32,
        regs.ip32(), regs.code_seg(), handler_flags);
    regs.set_cs32(sel as u32);
    regs.set_ip32(off);
    regs.clear_flag32(1 << 8);
    dos_trace!("[DPMI] PM_INT vec={:02X} -> {:04x}:{:#x} on client SS:ESP={:04x}:{:#x}",
        vector, sel, off, regs.frame.ss as u16, regs.sp32());
    thread::KernelAction::Done
}

/// Deliver a HW IRQ to a PM handler. Per DPMI 0.9 §3.1.2 the host
/// switches to the locked PM stack on the *first* entry from a non-
/// handler context (the client's PM stack or VM86); nested entries
/// already inside a handler context reuse the existing stack chain.
///
///   - **First entry** (handler depth == 0): push a `ModeSave`
///     capturing the interrupted regs onto `host_stack` at
///     `pc.host_stack_sp`, push an iret frame above it targeting
///     `SLOT_PM_IRET`. Switch SS:ESP to the `HOST_STACK_PM*` alias. The
///     handler's IRET pops the iret frame and traps to the kernel via
///     the stub, which pops the ModeSave (via `cross_mode_restore`) and
///     restores the interrupted state — including SS:ESP, which a
///     same-priv hardware IRET could not have done.
///
///   - **Nested in a handler context** (handler depth > 0): push only
///     the iret frame at `regs.ESP - frame_size` targeting the outer's
///     CS:EIP. No ModeSave; hardware same-priv IRET handles the unwind
///     directly. We must NOT use a `regs.SS == HOST_STACK_PM*` check
///     to detect nesting — DPMI 0.9 §3.1.2 lets the handler switch SS
///     to its own locked stack mid-execution, so the nested case can
///     run with `SS != HOST_STACK_PM*`. The `depth` counter on
///     `LockedStackState` is incremented on every handler entry and
///     decremented on every unwind, so it tracks "are we inside a
///     handler" reliably regardless of stack switching.
///
/// Works for non-DPMI threads too: `install_kernel_ldt_slots` makes the
/// LDT + kernel-owned selectors (VECTOR_STUB, SPECIAL_STUB, HOST_STACK_PM*)
/// available at thread init. When `pm_vectors[vec]` is the default stub,
/// the round-trip lands in `vector_stub_reflect` which discriminates the
/// first-entry case by the IRET target == `SLOT_PM_IRET`.
pub(super) fn deliver_pm_irq(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) {
    let (sel, off) = dos.pm_vectors[vector as usize];
    // DPMI 0.9 §10.6: frame width follows the *client*'s bitness, not the
    // handler segment's D bit. A 32-bit client routinely installs a
    // 16-bit-segment handler that issues `66 CF` (32-bit IRETD) — clients
    // own that contract end-to-end. Non-DPMI threads default to 16-bit
    // (the host default-stub path is 16-bit).
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);

    // Handler starts with IF=TF=0; other flag bits follow the current EFLAGS.
    let handler_flags = regs.flags32() & !(machine::IF_FLAG | (1u32 << 8) | machine::VM_FLAG);

    if dos.pc.locked_stack.in_handler() {
        // Nested in an already-active handler context: just push iret_frame
        // targeting outer's CS:EIP at current ESP - frame_size. Hardware
        // same-priv IRET unwinds inline, no kernel involvement.
        let new_esp = host_stack_write_iret(
            regs.sp32(), client_use32,
            regs.ip32(), regs.code_seg(), handler_flags);
        regs.frame.rsp = new_esp as u64;
        // Stack-cursor discipline: if the iret-frame landed on host_stack,
        // advance the kernel-tracked cursor so subsequent push_save calls
        // don't overlap. If the handler had switched off host_stack to its
        // own locked stack (per DPMI 0.9 §3.1.2), the iret-frame is on that
        // other stack and host_stack_sp is unaffected.
        if regs.stack_seg() == HOST_STACK_PM16_SEL || regs.stack_seg() == HOST_STACK_PM32_SEL {
            dos.pc.host_stack_sp = new_esp;
        }
    } else {
        // First entry: push a ModeSave (kernel-side save area) + plant
        // an iret-to-SLOT_PM_IRET frame so the eventual handler IRET
        // round-trips through the kernel for unwinding.
        push_save(dos, regs);
        let stub_eip = dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_IRET) as u32;
        let cursor2 = host_stack_write_iret(
            dos.pc.host_stack_sp, client_use32,
            stub_eip, SPECIAL_STUB_SEL, handler_flags);
        dos.pc.host_stack_sp = cursor2;

        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;

        let stk_sel = if client_use32 { HOST_STACK_PM32_SEL } else { HOST_STACK_PM16_SEL };
        regs.frame.ss  = stk_sel as u64;
        regs.frame.rsp = cursor2 as u64;
    }

    regs.frame.rflags &= !((machine::VM_FLAG | machine::IF_FLAG | (1u32 << 8)) as u64);
    regs.frame.cs  = sel as u64;
    regs.frame.rip = off as u64;
}

/// Pop the ModeSave pushed by the outermost-relative PM-handler entry
/// (`deliver_pm_irq` taking the cross-mode branch). Called from
/// `pm_stub_dispatch` when SLOT_PM_IRET fires (client handler IRETed
/// through our stub) and from `vector_stub_reflect` when the default
/// stub catches an IRQ that has no PM handler installed.
///
/// At entry: hardware IRET advanced regs.ESP past the iret_frame, so
/// regs.ESP now points at the ModeSave on host_stack. After restoring,
/// `host_stack_sp` is bumped back up past both records.
pub(super) fn cross_mode_restore(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    debug_assert!(regs.stack_seg() == HOST_STACK_PM16_SEL ||
                  regs.stack_seg() == HOST_STACK_PM32_SEL,
                  "cross_mode_restore: SS not host_stack");

    // Resync host_stack_sp from the user's post-iret cursor: hardware
    // IRET advanced ESP past the iret frame onto the save's start.
    dos.pc.host_stack_sp = regs.sp32();
    let save = pop_save(dos);
    save.restore(regs);

    let (cs, eip, ss, esp, vm) =
        (save.cs as u16, save.eip, save.ss as u16, save.esp,
         save.eflags & machine::VM_FLAG != 0);
    dos_trace!("[DPMI] IRQ RESTORE -> {:04X}:{:#x} SS:ESP={:04X}:{:#x} VM={}",
        cs, eip, ss, esp, vm);

    thread::KernelAction::Done
}

/// Push an IRET frame on the stack addressed by `regs.ss:regs.sp`, updating
/// regs.sp. Frame width matches the *handler's* bitness — 12 bytes for a
/// 32-bit handler (D=1), 6 bytes for 16-bit (D=0). This is the width the
/// handler's `IRET` will use on its way back, so push and matching pop must
/// agree on handler bitness, regardless of the client's overall size.
fn push_iret_frame(ldt: &[u64], regs: &mut Regs, handler_is_32: bool,
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
    if handler_is_32 {
        unsafe {
            let p = addr as *mut u32;
            core::ptr::write_unaligned(p, eip);
            core::ptr::write_unaligned(p.add(1), cs as u32);
            core::ptr::write_unaligned(p.add(2), flags);
        }
    } else {
        unsafe {
            let p = addr as *mut u16;
            core::ptr::write_unaligned(p, eip as u16);
            core::ptr::write_unaligned(p.add(1), cs);
            core::ptr::write_unaligned(p.add(2), flags as u16);
        }
    }
    regs.set_sp32(sp);
}

/// Pop an IRET frame off `regs.ss:regs.sp`, advancing regs.sp.
/// `handler_is_32` must match the width used at push time. Frame width
/// follows handler.D; SP semantics follow SS.B (see `push_iret_frame`).
fn pop_iret_frame(ldt: &[u64], regs: &mut Regs, handler_is_32: bool) -> (u32, u16, u32) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 12 } else { 6 };
    let sp_in = regs.sp32();
    let eff_sp = if stack_is_32 { sp_in } else { sp_in & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    let frame = if handler_is_32 {
        unsafe {
            let p = addr as *const u32;
            let eip = core::ptr::read_unaligned(p);
            let cs = core::ptr::read_unaligned(p.add(1)) as u16;
            let flags = core::ptr::read_unaligned(p.add(2));
            (eip, cs, flags)
        }
    } else {
        unsafe {
            let p = addr as *const u16;
            let ip = core::ptr::read_unaligned(p) as u32;
            let cs = core::ptr::read_unaligned(p.add(1));
            let flags = core::ptr::read_unaligned(p.add(2)) as u32;
            (ip, cs, flags)
        }
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
///   push_regs              ← `push_save`           (in `reflect_int_to_bios`)
///   call simulate_rm_int   ← BIOS round-trip       (in `reflect_int_to_bios`)
///   pop_regs               ← `pop_save`            (in `rm_iret_stub`)
///   sti                                             (in `rm_iret_stub`)
///   iret                   ← synthetic iret-pop    (in `rm_iret_stub`)
///
/// Uniform — no discrimination by iret-target. The planted iret-frame
/// (deliver_pm_irq or deliver_pm_int wrote it) is consumed at the
/// synthetic-iret tail in `rm_iret_stub`, landing regs at whatever
/// target the planter chose:
///   - `SLOT_PM_IRET` for cross-mode HW-IRQ first-entry → next CD 31
///     traps `cross_mode_restore` to pop the outer save.
///   - The outer caller's CS:EIP for soft-INT and nested-HW-IRQ.
pub(super) fn vector_stub_reflect(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let eip = regs.ip32();
    let vector = ((eip.wrapping_sub(dos::STUB_BASE + 2)) / 2) as u8;
    if vector >= 0x10 {
        dos_trace!("[DPMI] VECSTUB vec={:#04x} SS:ESP={:04x}:{:#x} CS:EIP={:04x}:{:#x} DS={:04X} ES={:04X} DX={:04X} DI={:04X}",
            vector, regs.stack_seg(), regs.sp32(), regs.code_seg(), eip,
            regs.ds as u16, regs.es as u16, regs.rdx as u16, regs.rdi as u16);
    }
    reflect_int_to_bios(dos, regs, vector, dos::SLOT_RM_IRET_STUB)
}


/// Reflect a software INT from protected mode to real mode via the IVT.
/// Used when a DPMI client executes `INT xx` and no PM handler is installed.
/// Per DPMI 0.9 §2.4 / §3.2: EAX/EBX/ECX/EDX/ESI/EDI/EBP and flags are
/// passed unaltered; segment registers are undefined in real mode. Any API
/// that passes pointers via segments is the DOS extender's responsibility
/// to translate via its own INT 21h hook — not the host's.
pub(super) fn reflect_int_to_real_mode(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    reflect_int_to_bios(dos, regs, vector, dos::SLOT_RM_IRET_REFLECT)
}

/// Like `reflect_int_to_real_mode` but parameterized by the RM-side
/// return slot the BIOS handler IRETs through. Direct callers pick the
/// slot whose unwind handler matches what they want to happen on the
/// way back: `SLOT_RM_IRET_REFLECT` for plain "restore captured state",
/// `SLOT_RM_IRET_STUB` for "stub-style: restore + sti + synth-iret of
/// the iret-frame the planter left on the user's stack".
pub(super) fn reflect_int_to_bios(dos: &mut thread::DosState, regs: &mut Regs, vector: u8, return_slot: u8) -> thread::KernelAction {
    // Save client state, snapshot the dedicated RM stack onto the
    // locked stack, then run BIOS on a fresh dedicated RM stack. BIOS
    // runs on a kernel-owned RM stack — never on the client's own VM86
    // stack — so a HW IRQ landing during a sensitive moment in the
    // client (e.g. just after exec_return) can't trample the client's
    // saved registers / return address. The snapshot+restore pair on
    // the locked stack provides reentrance for nested kernel-orchestrated
    // RM excursions. Works for VM86 and PM clients alike — no DPMI
    // session required.
    push_save(dos, regs);
    push_rm_snapshot(dos);

    // Get IVT entry
    let ivt_off = machine::read_u16(0, (vector as u32) * 4);
    let ivt_seg = machine::read_u16(0, (vector as u32) * 4 + 2);

    regs.frame.ss = dos::rm_stack_seg() as u64;
    regs.frame.rsp = rm_stack_top() as u64;

    // Push trampoline IRET frame on the RM slab, mirroring what the CPU's
    // own INT n in real mode would push: FLAGS / CS / IP. FLAGS is the
    // client's flags *unmodified* — that's what real-mode INT writes,
    // and it's what BIOS IRET pops back. The handler runs with IF=0
    // because we set it on `regs.frame.rflags` below, not by mutating
    // the on-stack frame. Pushing 0 (or modifying flags here) would let
    // the unwind handler's status-flag passthrough (CF/ZF/DF/...) snapshot
    // wrong values and silently corrupt the client across the IRQ.
    let ret_flags = regs.flags32() as u16;
    let ret_off: u16 = dos::slot_offset(return_slot);
    let ret_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, ret_flags);
    machine::vm86_push(regs, ret_seg);
    machine::vm86_push(regs, ret_off);

    // Enter the BIOS handler in VM86 with IF cleared — matches what the
    // CPU's own INT n does in real mode (preserves status flags, just
    // clears IF). VIF is owned by the arch layer (VME virtualization),
    // not us. IOPL=1 keeps cli/sti virtualized.
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    let flags = (regs.flags32() & !(machine::IF_FLAG | machine::IOPL_MASK))
        | machine::VM_FLAG
        | machine::IOPL_VM86;
    regs.frame.rflags = flags as u64;

    // Per DPMI, the host must not translate PM selectors into RM paragraphs
    // when reflecting a software interrupt. The extender/client is responsible
    // for any DOS-call marshaling that requires real-mode segment values.

    dos_trace!("[DPMI] reflect INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X} DS={:04X} ES={:04X}",
        vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32(), regs.rax as u16,
        regs.ds as u16, regs.es as u16);

    thread::KernelAction::Done
}

/// SLOT_RM_IRET_REFLECT dispatch — implicit IVT-reflection unwind.
/// Called when VM86 IRETs from a BIOS handler we entered via
/// `reflect_int_to_real_mode`. Pops the `ModeSave` and restores
/// CS/EIP/SS/ESP/EFLAGS/segregs. GP regs are *not* in `ModeSave` — per
/// DPMI 0.9 §2.4 they round-trip through real mode (BIOS modifies them,
/// PM caller sees the modified values). Then ORs IF=1 into EFLAGS per
/// the spec's "default IRQ stub must STI before IRET" rule
/// (`feedback_dpmi_default_stub_sti`).
pub(super) fn rm_iret_reflect(dos: &mut thread::DosState, regs: &mut Regs) {
    // Snapshot RM arithmetic flags before restore overwrites EFLAGS.
    // VM/IOPL/IF/TF/RF/NT must come from the saved PM state — copying
    // RM EFLAGS verbatim would set VM=1 and drop us back into VM86.
    const STATUS_MASK: u32 = 0x0CD5; // CF,PF,AF,ZF,SF,OF,DF
    let rm_arith = regs.flags32() & STATUS_MASK;

    // Restore the dedicated RM stack from its snapshot on the locked
    // stack, then pop the save and restore regs to the original PM
    // (or VM86) caller state.
    pop_rm_snapshot(dos);
    pop_save(dos).restore(regs);

    regs.set_flags32((regs.flags32() & !STATUS_MASK) | rm_arith);
    regs.frame.rflags |= machine::IF_FLAG as u64;

    dos_trace!("[DPMI] RM_IRET_REFLECT -> CS:EIP={:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
}

/// SLOT_RM_IRET_STUB dispatch — `vector_stub_reflect`'s stub-emulation
/// tail. Mirrors `pop_regs / sti / iret` of the canonical default-stub:
///
///   - Pop the rm_snapshot and the ModeSave the entry-side push_save'd.
///   - OR IF=1 into the captured EFLAGS (default-stub STI rule).
///   - Synthetic IRET: pop the iret-frame the planter (`deliver_pm_irq`
///     or `deliver_pm_int`) wrote on the user's stack, install
///     CS:EIP/EFLAGS from it, advance regs.SP, and — if the user is on
///     host_stack — advance `host_stack_sp` in lockstep so subsequent
///     pushes don't overlap the now-consumed iret-frame area.
pub(super) fn rm_iret_stub(dos: &mut thread::DosState, regs: &mut Regs) {
    const STATUS_MASK: u32 = 0x0CD5;
    let rm_arith = regs.flags32() & STATUS_MASK;

    pop_rm_snapshot(dos);
    pop_save(dos).restore(regs);
    regs.set_flags32((regs.flags32() & !STATUS_MASK) | rm_arith);
    regs.frame.rflags |= machine::IF_FLAG as u64;

    // Planted iret-frame width follows client bitness (DPMI 0.9 §10.6),
    // matching what host_stack_write_iret used on the entry side.
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);
    let frame_size: u32 = if client_use32 { 12 } else { 6 };
    let on_host_stack = regs.stack_seg() == HOST_STACK_PM16_SEL
        || regs.stack_seg() == HOST_STACK_PM32_SEL;
    let (ret_eip, ret_cs, ret_flags) = pop_iret_frame(&dos.ldt[..], regs, client_use32);
    if on_host_stack {
        dos.pc.host_stack_sp += frame_size;
    }
    regs.set_ip32(ret_eip);
    regs.set_cs32(ret_cs as u32);
    regs.set_flags32(ret_flags | machine::IF_FLAG);

    dos_trace!("[DPMI] RM_IRET_STUB -> {:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        ret_cs, ret_eip, regs.stack_seg(), regs.sp32());
}

/// SLOT_RM_IRET_CALL dispatch — explicit PM→RM call unwind (0x0300/01/02
/// and `callback_entry`). Pops the `CallStubFrame`, writes current RM regs
/// (the post-call values) into the RmCallStruct at `rm_struct_addr`, then
/// restores the saved GP regs and pops the `ModeSave`. Restoration order
/// is critical: writeback uses *current* (post-RM) regs, so it must run
/// before `restore_gp` overwrites them.
pub(super) fn rm_iret_call(dos: &mut thread::DosState, regs: &mut Regs) {
    let stub = host_stack_read_call_args(dos.pc.host_stack_sp);
    dos.pc.host_stack_sp += CALL_STUB_SIZE;
    // Restore the dedicated RM stack iff this excursion ran on it
    // (the recipe recorded the choice on push). User-supplied SS:SP
    // means BIOS pushed onto the user's stack; our dedicated buffer
    // was never touched, no snapshot to restore.
    if stub.used_dedicated_rm != 0 {
        pop_rm_snapshot(dos);
    }
    let save = pop_save(dos);

    // Writeback current RM regs into RmCallStruct so the PM caller sees
    // results. Must happen *before* GP-restore overwrites regs.
    let rm_struct_addr = { let f = stub; f.rm_struct_addr };
    let rm_struct = RmCallStruct {
        edi: regs.rdi as u32,
        esi: regs.rsi as u32,
        ebp: regs.rbp as u32,
        _reserved: 0,
        ebx: regs.rbx as u32,
        edx: regs.rdx as u32,
        ecx: regs.rcx as u32,
        eax: regs.rax as u32,
        flags: regs.flags32() as u16,
        es: regs.es as u16,
        ds: regs.ds as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
        ip: regs.ip32() as u16,
        cs: regs.code_seg(),
        sp: regs.sp32() as u16,
        ss: regs.stack_seg(),
    };
    unsafe { *(rm_struct_addr as *mut RmCallStruct) = rm_struct; }

    stub.restore_gp(regs);
    save.restore(regs);

    dos_trace!("[INT31 RET] AX={:04x} CF={:x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        regs.rax as u16, regs.flags32() & 1,
        regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);

}


// =============================================================================
// LDT descriptor decode helpers
// =============================================================================
//
// Used by the iret-frame primitives, the stub dispatchers, and dpmi.rs's own
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

/// Get the D/B (default operand size) bit. GDT selectors are treated as 32-bit.
pub(super) fn seg_is_32(ldt: &[u64], sel: u16) -> bool {
    if sel & 4 == 0 { return true; }
    let idx = (sel >> 3) as usize;
    if idx >= ldt.len() { return true; }
    ldt[idx] & (1u64 << 54) != 0
}

/// DPMI real-mode call structure (50 bytes at ES:EDI). Filled by the client
/// before a 0300/0301/0302 INT 31h call; written back by `rm_iret_call` with
/// the post-RM register state. Kept here because the writeback is part of
/// the unwind machinery — the API parsing in `dpmi::call_real_mode_proc` etc.
/// hands us the buffer address at entry.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct RmCallStruct {
    pub edi: u32, pub esi: u32, pub ebp: u32, pub _reserved: u32,
    pub ebx: u32, pub edx: u32, pub ecx: u32, pub eax: u32,
    pub flags: u16, pub es: u16, pub ds: u16, pub fs: u16, pub gs: u16,
    pub ip: u16, pub cs: u16, pub sp: u16, pub ss: u16,
}
