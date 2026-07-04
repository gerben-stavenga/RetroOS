//! Console focus: which thread owns the display, keyboard, and mouse.
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
pub fn release<A: crate::Arch>(old: Option<&mut Personality<A>>) {
    if let Some(old) = old {
        old.suspend();
    }
}

/// Second half: repaint the incoming owner's screen state and record it as
/// the console owner. Runs after the execution switch, with the new
/// thread's context live — materialize ordering matches the pre-focus-API
/// behaviour exactly.
pub fn acquire<A: crate::Arch>(new_tid: usize, new: &mut Personality<A>) {
    new.materialize();
    FOCUS.store(new_tid, Ordering::Relaxed);
}
