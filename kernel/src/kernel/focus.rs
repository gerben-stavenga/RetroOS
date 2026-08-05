//! Console focus: which thread owns the display, keyboard, mouse — and the
//! machine's Sound Blaster when a guest is driving it directly.
//!
//! Focus is orthogonal to scheduling — F11 moves FOCUS (a console-ownership
//! transfer: snapshot the old owner's screen state, repaint the new
//! owner's, swap the I/O bitmap so the real card follows the owner); the
//! scheduler decides who RUNS. Today the event loop runs the focused
//! thread, so every focus transfer is accompanied by an execution switch —
//! when background execution arrives, focus stays put while threads
//! multiplex, and everything keyed off [`focused`] keeps working.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::thread::Personality;

static FOCUS: AtomicUsize = AtomicUsize::new(0);

/// The thread that owns the console (display + keyboard + mouse).
pub fn focused() -> usize {
    FOCUS.load(Ordering::Relaxed)
}

/// Adopt the console without a previous owner (the initial program of a
/// boot or cmdline run). No hooks: a fresh thread has nothing to repaint.
pub fn adopt(tid: usize) {
    FOCUS.store(tid, Ordering::Relaxed);
}

/// First half of a console handoff: snapshot the outgoing owner's screen
/// state. Runs while the old thread's context is still the live one. `old`
/// is None when the previous owner is already gone (zombie — `exit_thread`
/// snapshotted its farewell screen before teardown).
/// The Sound Blaster comes back with the display: one machine, one card, and
/// the owner is whoever the machine is currently showing.
pub fn release<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: Option<&mut crate::kernel::bios_display::BiosDisplayWorkspace<A>>,
    old: &mut Personality<A>,
) -> (crate::kernel::platform::DisplayToken, Option<crate::kernel::drivers::sb16::SbCard>) {
    let card = old.release_sb(machine);
    (old.suspend(machine, bios_workspace), card)
}

/// Second half: repaint the incoming owner's screen state and record it as
/// the console owner. Runs after the execution switch, with the new
/// thread's context live — materialize ordering matches the pre-focus-API
/// behaviour exactly.
/// Returns the card the incoming owner did NOT take (a Linux thread, or any
/// thread on a machine whose card the kernel mixer owns), so it stays in the
/// caller's handoff rather than being dropped.
pub fn acquire<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: Option<&mut crate::kernel::bios_display::BiosDisplayWorkspace<A>>,
    new_tid: usize,
    new: &mut Personality<A>,
    display: crate::kernel::platform::DisplayToken,
    card: Option<crate::kernel::drivers::sb16::SbCard>,
) -> Option<crate::kernel::drivers::sb16::SbCard> {
    new.materialize(machine, bios_workspace, display);
    FOCUS.store(new_tid, Ordering::Relaxed);
    new.adopt_sb(machine, card)
}
