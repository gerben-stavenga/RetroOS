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
//!                    per-thread buffer in low memory). RM-INT reflection
//!                    from PM, DPMI 0300/0301/0302 calls, etc.
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
//! one. ModeSave captures and restores `other_stack` symmetrically.
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

/// Per-thread tracking for kernel-mediated PM/RM crossings.
///
/// `other_stack` is the central state: `None` when the user is in
/// client mode (not on either dedicated stack), `Some((ss, sp))` when
/// kernel cross-mode entry has put the user on a dedicated stack and
/// remembers the cursor of the *other* dedicated stack we'd ping-pong
/// to. `regs.SS:SP` is authoritative for whichever stack the user is
/// currently on; `other_stack` tracks the cursor of the not-current
/// one.
///
/// Maintained automatically via `ModeSave`'s capture/restore: every
/// `push_save` records the current value, every matching `pop_save`'s
/// caller restores it. Bracket boundaries (`deliver_pm_irq`
/// first-entry, etc.) update it explicitly when transitioning state.
pub(super) struct LockedStackState {
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
    /// `dos.pc.locked_stack.other_stack` value at push time. Sentinel
    /// `(0, 0)` means `None` (selector 0 is never a valid stack
    /// selector, so the encoding is unambiguous). pop_save's caller
    /// restores `dos.pc.locked_stack.other_stack` from these fields.
    pub other_ss: u16,
    pub other_sp: u32,
}

pub(super) const MODE_SAVE_SIZE: u32 = core::mem::size_of::<ModeSave>() as u32;

impl ModeSave {
    pub fn capture(regs: &Regs, other_stack: Option<(u16, u32)>) -> Self {
        let (other_ss, other_sp) = other_stack.unwrap_or((0, 0));
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
            other_ss,
            other_sp,
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

    /// Decode the captured `other_stack` value. `(0, 0)` ⇒ None.
    pub fn other_stack(&self) -> Option<(u16, u32)> {
        let ss = self.other_ss;
        let sp = self.other_sp;
        if ss == 0 { None } else { Some((ss, sp)) }
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
pub(super) fn host_stack_pm_seg(dos: &thread::DosState) -> u16 {
    if dos.dpmi.as_ref().map_or(false, |d| d.client_use32) {
        HOST_STACK_PM32_SEL
    } else {
        HOST_STACK_PM16_SEL
    }
}

/// The pm-side cursor as a (SS, SP) pair.
///
///   - chain empty (`other_stack=None`): default to host_stack at empty
///     TOS — what first-entry will switch onto.
///   - in chain, user on pm side (`mode != VM86`): regs.SS:SP itself.
///     Works whether SS is HOST_STACK_PM* or some handler-owned locked
///     stack; we just track wherever pm currently is.
///   - in chain, user on rm side (`mode == VM86`): pm side's
///     (SS, SP) was stashed in other_stack at the toggle that put us
///     on rm. Read it back.
#[inline]
pub(super) fn pm_cursor(dos: &thread::DosState, regs: &Regs) -> (u16, u32) {
    match dos.pc.locked_stack.other_stack {
        None => (host_stack_pm_seg(dos), dos::host_stack_empty_sp()),
        Some(p) if regs.mode() == crate::UserMode::VM86 => p,
        Some(_) => (regs.stack_seg(), regs.sp32()),
    }
}

/// Resolve a (SS, SP) pair to a linear address, using the LDT for SS
/// base. Used by push_save / pop_save to read/write a save at an
/// arbitrary pm-side cursor.
fn pm_addr(ldt: &[u64], cursor: (u16, u32)) -> u32 {
    seg_base(ldt, cursor.0).wrapping_add(cursor.1)
}

/// Capture current regs as a ModeSave and write it at
/// `pm_cursor.SP − MODE_SAVE_SIZE` on `pm_cursor.SS`. Returns the
/// post-push (SS, SP) — caller is responsible for stashing it
/// (via regs.SS:SP if landing the user on pm side, or `other_stack`
/// if landing on rm side).
pub(super) fn push_save(dos: &mut thread::DosState, regs: &Regs) -> (u16, u32) {
    let save = ModeSave::capture(regs, dos.pc.locked_stack.other_stack);
    let (ss, sp) = pm_cursor(dos, regs);
    let new_sp = sp - MODE_SAVE_SIZE;
    let addr = pm_addr(&dos.ldt[..], (ss, new_sp));
    unsafe { core::ptr::write_unaligned(addr as *mut ModeSave, save); }
    (ss, new_sp)
}

/// Read the topmost ModeSave at `pm_cursor`. Doesn't write back — the
/// caller follows with `save.restore(regs)` which clobbers SS:SP and
/// other_stack, so the post-pop cursor doesn't need to live anywhere.
pub(super) fn pop_save(dos: &thread::DosState, regs: &Regs) -> ModeSave {
    pop_save_at(&dos.ldt[..], pm_cursor(dos, regs))
}

/// Read a ModeSave at an explicit (SS, SP). Used by `rm_iret_call`
/// which has to skip past a CallStubFrame first.
pub(super) fn pop_save_at(ldt: &[u64], cursor: (u16, u32)) -> ModeSave {
    let addr = pm_addr(ldt, cursor);
    unsafe { core::ptr::read_unaligned(addr as *const ModeSave) }
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
// RM-INT-mid-handler) pushes a `ModeSave` capturing the interrupted regs
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
    //                   pm_cursor defaults to host_stack:empty_sp.
    //                   Same path as toggle, plus the empty default.
    let in_pm = regs.mode() != crate::UserMode::VM86;
    let nested_on_pm = in_pm && dos.pc.locked_stack.other_stack.is_some();
    if nested_on_pm {
        let new_esp = host_stack_write_iret(
            regs.sp32(), client_use32,
            regs.ip32(), regs.code_seg(), handler_flags);
        regs.frame.rsp = new_esp as u64;
    } else {
        // Capture pre-toggle rm side for other_stack. In the toggle
        // case (VM86, Some) regs.SS:SP IS the rm cursor — recording
        // it lets a nested reflect_int_to_real_mode push its iret
        // frame *below* this position instead of clobbering at
        // rm_stack_top. In the first-entry case (None) rm is empty,
        // so default to rm_TOS.
        let rm_cursor = if regs.mode() == crate::UserMode::VM86 {
            (regs.stack_seg(), regs.sp32())
        } else {
            (dos::rm_stack_seg(),
             (dos::rm_stack_align_offset() as u32) + dos::rm_stack_size())
        };

        // Push save on pm side. push_save returns the post-push
        // (SS, SP) — that's where the iret-frame will go above the
        // save, and where regs.SS:SP will land for the handler.
        let cursor1 = push_save(dos, regs);
        let stub_eip = dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_IRET) as u32;
        let new_sp = host_stack_write_iret(
            cursor1.1, client_use32,
            stub_eip, SPECIAL_STUB_SEL, handler_flags);

        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;

        regs.frame.ss  = cursor1.0 as u64;
        regs.frame.rsp = new_sp as u64;

        // other_stack tracks rm side's live cursor (so a nested
        // reflect_int_to_real_mode resumes below it instead of at
        // rm_TOS, sharing the dedicated buffer LIFO-style without
        // a snapshot copy).
        dos.pc.locked_stack.other_stack = Some(rm_cursor);
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
/// regs.SS:SP now points at the ModeSave on whichever pm stack the
/// handler used (host_stack or its own locked stack). pm_cursor reads
/// it directly off (regs.SS, regs.SP); save.restore then clobbers SS:SP
/// with the pre-toggle values.
pub(super) fn cross_mode_restore(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let save = pop_save(dos, regs);
    save.restore(regs);
    // Restore the other_stack that was current at push time (None at
    // outermost-from-client entry, Some at nested entries).
    dos.pc.locked_stack.other_stack = save.other_stack();

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
pub(super) fn push_iret_frame(ldt: &[u64], regs: &mut Regs, handler_is_32: bool,
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
///   push_regs              ← `push_save`           (in `reflect_int_to_real_mode`)
///   call simulate_rm_int   ← RM-INT round-trip       (in `reflect_int_to_real_mode`)
///   pop_regs               ← `pop_save`            (in `rm_iret`)
///   sti                                             (in `rm_iret`)
///   iret                   ← synthetic iret-pop    (in `rm_iret`)
///
/// Uniform — no discrimination by iret-target. The planted iret-frame
/// (deliver_pm_irq or deliver_pm_int wrote it) is consumed at the
/// synthetic-iret tail in `rm_iret`, landing regs at whatever
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
    reflect_int_to_real_mode(dos, regs, vector)
}


/// Reflect an INT to real mode via the IVT. Whether the IVT entry points
/// at BIOS, DOS, or a user-installed hook is irrelevant — it's just
/// "execute INT N in RM, come back when it's done". Used by the
/// per-vector default stub (`vector_stub_reflect`) and by the unhandled-
/// exception fallback (`dispatch_dpmi_exception`).
///
/// On the way out: push_save, push_rm_snapshot, set up regs to enter
/// the IVT handler in VM86 with the trampoline iret-frame on rm_stack
/// pointing back at SLOT_RM_IRET. Per DPMI 0.9 §2.4 / §3.2:
/// EAX/EBX/ECX/EDX/ESI/EDI/EBP and flags are passed unaltered; segment
/// registers are undefined in real mode.
///
/// On the way back: RM IRET pops the trampoline frame, lands at
/// SLOT_RM_IRET, kernel runs `rm_iret` — pop_rm_snapshot, pop_save,
/// sti, synth-iret of the iret-frame the caller planted on the user's
/// stack (CS:EIP they want resumed at).
pub(super) fn reflect_int_to_real_mode(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    // Save client state, then run the RM handler on the dedicated RM
    // stack. The handler runs on a kernel-owned RM stack — never on
    // the client's own VM86 stack — so a HW IRQ landing during a
    // sensitive moment in the client (e.g. just after exec_return)
    // can't trample the client's saved registers / return address.
    // Works for VM86 and PM clients alike — no DPMI session required.
    //
    // Read rm side's live cursor *before* push_save so a nested
    // excursion (e.g. HW IRQ during a 0300 BIOS call → default-stub
    // reflect → here again) lands its iret-frame *below* the outer
    // excursion's data, sharing rm_dedicated LIFO-style. The outer
    // entry (deliver_pm_irq toggle, or simulate_real_mode_int) wrote
    // the live rm SS:SP into other_stack at toggle time. None means
    // first-entry from client — rm is empty, default to rm_TOS.
    let rm_cursor = match dos.pc.locked_stack.other_stack {
        Some(p) => p,
        None => (dos::rm_stack_seg(), rm_stack_top() as u32),
    };
    let pm_after_push = push_save(dos, regs);

    // Get IVT entry
    let ivt_off = machine::read_u16(0, (vector as u32) * 4);
    let ivt_seg = machine::read_u16(0, (vector as u32) * 4 + 2);

    regs.frame.ss  = rm_cursor.0 as u64;
    regs.frame.rsp = rm_cursor.1 as u64;

    // Push trampoline IRET frame on the RM slab, mirroring what the CPU's
    // own INT n in real mode would push: FLAGS / CS / IP. FLAGS is the
    // client's flags *unmodified* — that's what real-mode INT writes,
    // and it's what RM IRET pops back. The handler runs with IF=0
    // because we set it on `regs.frame.rflags` below, not by mutating
    // the on-stack frame. Pushing 0 (or modifying flags here) would let
    // the unwind handler's status-flag passthrough (CF/ZF/DF/...) snapshot
    // wrong values and silently corrupt the client across the IRQ.
    let ret_flags = regs.flags32() as u16;
    let ret_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET);
    let ret_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, ret_flags);
    machine::vm86_push(regs, ret_seg);
    machine::vm86_push(regs, ret_off);

    // Enter the RM handler in VM86 with IF cleared — matches what the
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

    // User now on rm side; stash the post-push pm (SS, SP) in
    // other_stack so the unwind path can locate the save.
    dos.pc.locked_stack.other_stack = Some(pm_after_push);

    dos_trace!("[DPMI] reflect INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X} DS={:04X} ES={:04X}",
        vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32(), regs.rax as u16,
        regs.ds as u16, regs.es as u16);

    thread::KernelAction::Done
}

/// SLOT_RM_IRET dispatch — RM-INT-return unwind.
/// Mirrors the canonical PM default-stub's tail in kernel space:
///
///   - Pop the rm_snapshot and the ModeSave that `reflect_int_to_real_mode`
///     pushed on entry.
///   - OR IF=1 into EFLAGS (default-stub STI rule per DPMI 0.9).
///   - Synthetic IRET: pop the iret-frame the caller planted on the
///     user's stack (whatever CS:EIP they want resumed at), install
///     CS:EIP/EFLAGS from it, advance regs.SP, and — if the user is on
///     host_stack — advance `host_stack_sp` in lockstep so subsequent
///     pushes don't overlap the now-consumed iret-frame area.
pub(super) fn rm_iret(dos: &mut thread::DosState, regs: &mut Regs) {
    const STATUS_MASK: u32 = 0x0CD5;
    let rm_arith = regs.flags32() & STATUS_MASK;

    // pm_cursor reads from other_stack here (we're in VM86 with
    // other_stack=Some); pop_save fetches the save from wherever pm
    // last was.
    let save = pop_save(dos, regs);
    save.restore(regs);
    dos.pc.locked_stack.other_stack = save.other_stack();
    regs.set_flags32((regs.flags32() & !STATUS_MASK) | rm_arith);
    regs.frame.rflags |= machine::IF_FLAG as u64;

    // Planted iret-frame width follows client bitness (DPMI 0.9 §10.6),
    // matching what host_stack_write_iret used on the entry side.
    // pop_iret_frame advances regs.SP — which IS the pm cursor while
    // user is on pm side, so the frame's bytes are released
    // automatically.
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);
    let (ret_eip, ret_cs, ret_flags) = pop_iret_frame(&dos.ldt[..], regs, client_use32);
    regs.set_ip32(ret_eip);
    regs.set_cs32(ret_cs as u32);
    regs.set_flags32(ret_flags | machine::IF_FLAG);

    dos_trace!("[DPMI] RM_IRET_STUB -> {:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        ret_cs, ret_eip, regs.stack_seg(), regs.sp32());
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

