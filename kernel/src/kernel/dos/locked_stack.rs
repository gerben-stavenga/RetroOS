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

/// Capture current regs as a ModeSave and push it onto the locked
/// stack. Increments the handler-context `depth`. While the legacy
/// `host_stack_sp` cursor is still in use elsewhere, this primitive
/// keeps it in sync (writes at `host_stack_sp - MODE_SAVE_SIZE` and
/// decrements). Once all recipes migrate, the field goes away and
/// this writes via `regs.SS:ESP` / `tos` per the documented model.
pub(super) fn push_save(dos: &mut thread::DosState, regs: &Regs) {
    let save = ModeSave::capture(regs);
    let cursor = dos.pc.host_stack_sp - MODE_SAVE_SIZE;
    let addr = dos::host_stack_base() + cursor;
    unsafe { core::ptr::write_unaligned(addr as *mut ModeSave, save); }
    dos.pc.host_stack_sp = cursor;
    dos.pc.locked_stack.depth = dos.pc.locked_stack.depth.saturating_add(1);
}

/// Pop the topmost ModeSave off the locked stack and restore regs.
/// The save is at `regs.sp32()` because the user just IRETed across
/// the iret frame the recipe planted, advancing ESP onto the save's
/// position. Resyncs `host_stack_sp` past the popped save and
/// decrements `depth`. Returns the popped save for callers that
/// want to inspect it (typically for tracing).
pub(super) fn pop_save(dos: &mut thread::DosState, regs: &mut Regs) -> ModeSave {
    let cursor = regs.sp32();
    let addr = dos::host_stack_base() + cursor;
    let save = unsafe { core::ptr::read_unaligned(addr as *const ModeSave) };
    save.restore(regs);
    dos.pc.host_stack_sp = cursor + MODE_SAVE_SIZE;
    dos.pc.locked_stack.depth = dos.pc.locked_stack.depth.saturating_sub(1);
    save
}
