//! Scheduling policy — who runs next.
//!
//! Today's policy, stated in one place instead of inline in the event loop:
//! the FOCUSED thread runs. Execution leaves it only when an action says so
//! (exit → the waiting parent or whatever `schedule` finds; an explicit
//! Switch; a Yield target) or when F11 moves focus (and execution follows,
//! because focus implies execution for now). When background execution
//! arrives, this module is the only thing that should need to change — the
//! test of whether the factorization around it is right.

use crate::kernel::thread;

/// Map a personality action to the next thread to run. `None` = stay on
/// the current thread. A returned `Some(0)` means "no runnable threads
/// left" (the idle thread) — the event loop's exit condition.
pub fn next_after(
    machine: &mut crate::TheArch,
    regs: &mut crate::arch::Vcpu,
    tid: usize,
    action: thread::KernelAction,
) -> Option<usize> {
    match action {
        thread::KernelAction::Done => None,
        thread::KernelAction::Yield => thread::yield_thread(tid, regs),
        thread::KernelAction::Exit(code) => Some(thread::exit_thread(machine, tid, code)),
        thread::KernelAction::Switch(next) => Some(next),
        thread::KernelAction::ForkExec { path, path_len, cmdtail, cmdtail_len, on_error, on_success } => {
            crate::kernel::startup::handle_fork_exec(
                machine, regs, tid,
                &path[..path_len], &cmdtail[..cmdtail_len],
                on_error, on_success,
            )
        }
        thread::KernelAction::Fork(_) => {
            // TODO: implement Fork in event loop
            None
        }
        thread::KernelAction::Exec { path: _, path_len: _, args: _ } => {
            // TODO: implement Exec in event loop
            None
        }
    }
}

/// Honor a pending F11 request: focus cycles to the next thread — and with
/// it, execution. Pure focus shift — does not wake any blocked thread or
/// break any waitpid; the shell decides backgrounding semantics by polling
/// SYNTH_WAITPID + reading kbd.
pub fn focus_request(tid: usize) -> Option<usize> {
    if thread::take_switch_request() {
        thread::cycle_next(tid)
    } else {
        None
    }
}
