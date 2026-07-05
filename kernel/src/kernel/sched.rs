//! Scheduling policy — who runs next.
//!
//! Today's policy, stated in one place instead of inline in the event loop:
//! the FOCUSED thread runs. Execution leaves it only when an action says so
//! (exit → the waiting parent or whatever `schedule` finds; an explicit
//! Switch; a Yield target) or when F11 moves focus (and execution follows,
//! because focus implies execution for now). When background execution
//! arrives, this module is the only thing that should need to change — the
//! test of whether the factorization around it is right.

use crate::Regs;
use crate::Vcpu;
use crate::kernel::thread;

/// The scheduler's answer for this iteration.
pub enum Verdict {
    /// Keep running the current thread.
    Stay,
    /// Switch to this thread (focus follows, for now).
    Switch(usize),
    /// No runnable threads remain — the event loop is done.
    AllDead,
}

/// Decide what runs next, given what the personality asked for and any
/// pending F11. F11 is honored only when the action itself didn't already
/// pick a successor.
pub fn verdict<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    regs: &mut Regs,
    tid: usize,
    action: thread::KernelAction,
) -> Verdict {
    // Explicit match (not `.or_else(closure)`) so the `next_after` mutable
    // borrow of `threads` ends cleanly before `focus_request` reborrows it.
    let next = match next_after(machine, threads, regs, tid, action) {
        Some(n) => Some(n),
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
fn next_after<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    regs: &mut Regs,
    tid: usize,
    action: thread::KernelAction,
) -> Option<usize> {
    match action {
        thread::KernelAction::Done => None,
        thread::KernelAction::Yield => thread::yield_thread(threads, tid, regs),
        thread::KernelAction::Exit(code) => Some(thread::exit_thread(threads, machine, tid, code)),
        thread::KernelAction::Switch(next) => Some(next),
        thread::KernelAction::ForkExec { path, path_len, cmdtail, cmdtail_len, personality_name, viopl, on_error, on_success } => {
            crate::kernel::startup::handle_fork_exec(machine, threads, regs, tid,
                &path[..path_len], &cmdtail[..cmdtail_len], personality_name, viopl,
                on_error, on_success,
            )
        }
        thread::KernelAction::Fork { on_done, child_stack } => {
            crate::kernel::linux::handle_fork(machine, threads, regs, tid, child_stack, on_done)
        }
        thread::KernelAction::Exec { buffer, path, args, cwd } => {
            crate::kernel::linux::handle_exec(machine, threads, regs, tid, buffer, path, args, cwd)
        }
        thread::KernelAction::Wait { pid, status_ptr } => {
            crate::kernel::linux::handle_wait(machine, threads, regs, tid, pid, status_ptr)
        }
        thread::KernelAction::DosSynthChild { pid, op } => {
            crate::kernel::dos::handle_synth_child(machine, threads, regs, tid, pid, op)
        }
    }
}

/// Honor a pending F11 request: focus cycles to the next thread — and with
/// it, execution. Pure focus shift — does not wake any blocked thread or
/// break any waitpid; the shell decides backgrounding semantics by polling
/// SYNTH_WAITPID + reading kbd.
pub(crate) fn focus_request<A: crate::Arch>(threads: &[thread::Thread<A>], tid: usize) -> Option<usize> {
    if thread::take_switch_request() {
        thread::cycle_next(threads, tid)
    } else {
        None
    }
}
