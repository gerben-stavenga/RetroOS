//! Console focus: which thread owns the display, keyboard, mouse — and the
//! machine's Sound Blaster when a guest is driving it directly.
//!
//! Focus is orthogonal to scheduling — the F12 task picker moves FOCUS (a
//! console-ownership transfer: snapshot the old owner's screen state, repaint the new
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

/// Detach the outgoing display while its guest address space is active.
pub fn release<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    old: &mut Personality<A>,
) -> (crate::kernel::display::DisplayHandoff, Option<crate::kernel::drivers::sb16::SbCard>) {
    let card = old.release_sb(machine);
    (old.suspend(machine, bios_workspace), card)
}

/// Attach the incoming display after its guest address space is active.
pub fn acquire<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    new_tid: usize,
    new: &mut Personality<A>,
    display: crate::kernel::display::DisplayHandoff,
    card: Option<crate::kernel::drivers::sb16::SbCard>,
) -> Option<crate::kernel::drivers::sb16::SbCard> {
    new.materialize(machine, bios_workspace, display);
    FOCUS.store(new_tid, Ordering::Relaxed);
    new.adopt_sb(machine, card)
}
