//! Scheduling policy — who runs next.
//!
//! Today's policy, stated in one place instead of inline in the event loop:
//! the FOCUSED thread runs. Execution leaves it only when an action says so
//! (exit → the waiting parent or whatever `schedule` finds; an explicit
//! Switch; a Yield target) or when the F12 task picker moves focus (and
//! execution follows, because focus implies execution for now). When background execution
//! arrives, this module is the only thing that should need to change — the
//! test of whether the factorization around it is right.

use crate::Regs;
use crate::kernel::thread;

/// The scheduler's answer for this iteration.
pub enum Verdict {
    /// Keep running the current thread.
    Stay,
    /// Switch to this thread (focus follows, for now).
    Switch(usize),
    /// The current address space was retained and relabelled as this child;
    /// only the event-loop's ownership label changes.
    ContinueAs(usize),
    /// No runnable threads remain — the event loop is done.
    AllDead,
}

/// Decide what runs next, given what the personality asked for and any
/// pending task-picker request. It is honored only when the action itself
/// didn't already pick a successor.
#[allow(clippy::too_many_arguments)]
pub fn verdict<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    regs: &mut Regs,
    tid: usize,
    action: thread::KernelAction,
    exiting_display: &mut Option<crate::kernel::display::ExitDisplay>,
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::SbCard>,
    display: &mut Option<crate::kernel::display::Display>,
) -> Verdict {
    // Explicit match (not `.or_else(closure)`) so the `next_after` mutable
    // borrow of `threads` ends cleanly before `focus_request` reborrows it.
    let next = match next_after(machine, bios_workspace, threads, regs, tid, action, exiting_display, sb_handoff, display) {
        Some(Verdict::Switch(0)) => return Verdict::AllDead,
        Some(n) => return n,
        None => focus_request(threads, tid),
    };
    match next {
        None => Verdict::Stay,
        Some(0) => Verdict::AllDead, // thread 0 = idle: nothing real to run
        Some(next) => Verdict::Switch(next),
    }
}

/// Map a personality action to the next thread to run. `None` = stay on
/// the current thread.
#[allow(clippy::too_many_arguments)]
fn next_after<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    regs: &mut Regs,
    tid: usize,
    action: thread::KernelAction,
    exiting_display: &mut Option<crate::kernel::display::ExitDisplay>,
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::SbCard>,
    display: &mut Option<crate::kernel::display::Display>,
) -> Option<Verdict> {
    match action {
        thread::KernelAction::Done => None,
        thread::KernelAction::Yield => thread::yield_thread(threads, tid, regs).map(Verdict::Switch),
        thread::KernelAction::Exit(code) => Some(Verdict::Switch(thread::exit_thread(
            threads, machine, bios_workspace, tid, code, exiting_display, sb_handoff, display,
        ))),
        thread::KernelAction::Switch(next) => Some(Verdict::Switch(next)),
        thread::KernelAction::ForkExec { path, path_len, cmdtail, cmdtail_len, personality_name, viopl, on_error, on_success } => {
            crate::kernel::startup::handle_fork_exec(
                machine, bios_workspace, threads, regs, tid,
                &path[..path_len], &cmdtail[..cmdtail_len], personality_name, viopl,
                on_error, on_success, sb_handoff, display,
            ).map(Verdict::ContinueAs)
        }
        thread::KernelAction::Fork { on_done, child_stack } => {
            crate::kernel::linux::handle_fork(machine, threads, regs, tid, child_stack, on_done)
                .map(Verdict::Switch)
        }
        thread::KernelAction::Exec { buffer, path, args, cwd } => {
            crate::kernel::linux::handle_exec(
                machine, bios_workspace, threads, regs, tid, buffer, path, args, cwd,
                exiting_display, sb_handoff, display,
            ).map(Verdict::Switch)
        }
        thread::KernelAction::Wait { pid, status_ptr } => {
            crate::kernel::linux::handle_wait(machine, threads, regs, tid, pid, status_ptr)
                .map(Verdict::Switch)
        }
        thread::KernelAction::DosSynthChild { pid, op } => {
            crate::kernel::dos::handle_synth_child(machine, threads, regs, tid, pid, op)
                .map(Verdict::Switch)
        }
    }
}

/// Honor the F12 task picker's explicit target. This is a pure focus shift:
/// it does not wake a blocked thread or break waitpid.
pub(crate) fn focus_request<A: crate::Arch>(threads: &[thread::Thread<A>], tid: usize) -> Option<usize> {
    // Ignore a stale target that is the current owner, out of range, or no
    // longer active.
    if let Some(target) = thread::take_switch_target() {
        // `target == tid` is still meaningful when the CONSOLE is elsewhere:
        // the picker chose the thread that happens to be running while
        // another thread owns the display (a `/C` parent polls its wait, so
        // it is scheduled round-robin and may consume the request meant to
        // focus itself). That case is a focus-only handoff downstream.
        if (target != tid || crate::kernel::focus::focused() != target)
            && target < threads.len()
            && matches!(
                threads[target].kernel.state,
                thread::ThreadState::Ready | thread::ThreadState::Running | thread::ThreadState::Blocked
            )
        {
            return Some(target);
        }
        return None;
    }
    None
}
