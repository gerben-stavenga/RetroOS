//! PR_[GS]ET_PDEATHSIG and notification from the creating task's exit.
use super::*;
use alloc::collections::BTreeMap;

#[derive(Default)]
pub(super) struct State {
    owner: i32,
    settings: BTreeMap<i32, u8>,
    pending: u64,
    senders: BTreeMap<u8, i32>,
    child_exit_code: Option<i32>,
    stopped: bool,
}
impl State {
    pub fn retire(&mut self, caller: i32) { self.settings.remove(&caller); }
    pub fn exec(&self, caller: i32, process: i32) -> Self {
        let mut state = Self { owner: process, pending: self.pending, senders: self.senders.clone(), child_exit_code: self.child_exit_code, ..Self::default() };
        if let Some(&signal) = self.settings.get(&caller) { state.settings.insert(process, signal); }
        state
    }
}

pub(super) fn prctl<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let caller = async_io::current_id(&linux.async_io, kt.tid);
    match a.a0 {
        1 => {
            if a.a1 > 64 { return SyscallResult::val(-EINVAL); }
            linux.parent_death.owner = kt.tid;
            linux.parent_death.settings.insert(caller, a.a1 as u8);
        }
        2 => {
            let signal = u32::from(*linux.parent_death.settings.get(&caller).unwrap_or(&0));
            if !high_memory::copy_to(machine, a.a1, &signal.to_ne_bytes()) { return SyscallResult::val(-EFAULT); }
        }
        _ => return SyscallResult::val(-EINVAL),
    }
    SyscallResult::val(0)
}

fn target(linux: &LinuxState, signal: usize) -> Option<i32> {
    async_io::signal_target(&linux.async_io, linux.parent_death.owner,
        |id| signals::disposition(linux, id, signal).is_some())
}
pub(super) fn stopped(linux: &LinuxState) -> bool { linux.parent_death.stopped }
pub(super) fn due(linux: &LinuxState) -> bool {
    if linux.parent_death.pending == 0 { return false; }
    (1..=64).any(|signal| linux.parent_death.pending & (1 << (signal - 1)) != 0
        && (!linux.parent_death.stopped || signal == 9 || signal == 18)
        && target(linux, signal).is_some())
}

fn queue<A: crate::Arch>(task: &mut thread::Thread<A>, signal: u8, sender: i32) {
    let thread::Personality::Linux(linux) = &mut task.personality else { return; };
    linux.parent_death.owner = task.kernel.tid;
    let signal = signal as usize;
    // A continue cancels pending stops even when it is blocked/ignored;
    // conversely a newly generated stop cancels a pending continue.
    if signal == 18 { linux.parent_death.pending &= !((1 << 18) | (1 << 19) | (1 << 20) | (1 << 21)); }
    if matches!(signal, 19..=22) { linux.parent_death.pending &= !(1 << 17); }
    if signal == 17 { linux.parent_death.child_exit_code = None; }
    let handler = signals::handler(linux, signal);
    if signal == 18 && linux.parent_death.stopped {
        linux.parent_death.stopped = false;
        async_io::wake_signal(&mut task.kernel, &mut linux.async_io, linux.parent_death.owner);
    }
    if handler == 1 || handler == 0 && matches!(signal, 17 | 18 | 23 | 28) { thread::refresh_cpu_hash(task); return; }
    linux.parent_death.pending |= 1 << (signal - 1);
    linux.parent_death.senders.insert(signal as u8, sender);
    if (!linux.parent_death.stopped || signal == 9) && let Some(id) = target(linux, signal) {
        async_io::wake_signal(&mut task.kernel, &mut linux.async_io, id);
    }
    thread::refresh_cpu_hash(task);
}

/// Process-directed kill, including signal zero liveness probes. All Linux
/// processes currently have the fixed session credentials and a private
/// process group (the same model exposed by getpgrp/setpgid).
pub(crate) fn kill<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>],
    caller: usize, regs: &mut Regs, pid: i32, signal: u8) -> Option<thread::KernelAction>
{
    let mut found = false;
    for (index, task) in threads.iter_mut().enumerate() {
        let id = index as i32;
        let selected = match pid {
            0 => index == caller,
            -1 => index != caller && index != 1,
            n if n < -1 => n.checked_neg() == Some(id),
            n => n == id,
        };
        if !selected || task.kernel.state == thread::ThreadState::Unused
            || !matches!(task.personality, thread::Personality::Linux(_)) { continue; }
        // Zombies still exist until wait reaps them. A signal has no effect.
        found = true;
        if signal != 0 && task.kernel.state != thread::ThreadState::Zombie {
            queue(task, signal, caller as i32);
        }
    }
    regs.rax = if found { 0 } else { (-3i64) as u64 };
    let task = &mut threads[caller];
    if let thread::Personality::Linux(linux) = &mut task.personality {
        poll(machine, &mut task.kernel, linux, regs)
    } else { None }
}

/// Async waiters use SIGCHLD to retry waitpid(WNOHANG), even when they are
/// currently parked in epoll rather than a blocking wait4. Queue only after
/// publishing the zombie, so the handler can observe the completed child.
pub(crate) fn child_exited<A: crate::Arch>(parent: &mut thread::Thread<A>, child: i32, code: i32) {
    if !matches!(parent.kernel.state, thread::ThreadState::Ready | thread::ThreadState::Running | thread::ThreadState::Blocked) {
        return;
    }
    queue(parent, 17, child);
    if let thread::Personality::Linux(linux) = &mut parent.personality
        && linux.parent_death.pending & (1 << 16) != 0 {
        linux.parent_death.child_exit_code = Some(code);
    }
}

/// Called with the task table, without activating any child's address space.
/// `creator=None` means all threads in the parent process are terminating.
pub(crate) fn parent_exited<A: crate::Arch>(threads: &mut [thread::Thread<A>], process: usize, creator: Option<i32>) {
    let live_linux = |task: &thread::Thread<A>| matches!(task.personality, thread::Personality::Linux(_))
        && matches!(task.kernel.state, thread::ThreadState::Ready | thread::ThreadState::Running | thread::ThreadState::Blocked);
    // PID 1 may be DN, not a Linux init. Adopting a daemon into DN makes
    // its eventual exit schedule DN and take the live Linux console away.
    // Prefer Linux init when present; otherwise use the surviving Linux
    // ancestor at this terminal's root, never an orphan itself or a DOS task.
    let mut adopt = -1;
    if process != 1 && threads.get(1).is_some_and(live_linux) {
        adopt = 1;
    } else if let thread::Personality::Linux(owner) = &threads[process].personality {
        let mut parent = threads[process].kernel.parent_tid;
        for _ in 0..threads.len() {
            let Some(task) = usize::try_from(parent).ok().and_then(|id| threads.get(id)) else { break; };
            if parent == process as i32 || !live_linux(task) { break; }
            let thread::Personality::Linux(linux) = &task.personality else { break; };
            if !owner.shares_terminal(linux) { break; }
            adopt = parent;
            parent = task.kernel.parent_tid;
        }
    }
    for task in threads.iter_mut() {
        if task.kernel.parent_tid != process as i32 || matches!(task.kernel.state, thread::ThreadState::Unused | thread::ThreadState::Zombie) { continue; }
        if let thread::Personality::Linux(linux) = &mut task.personality {
            let matches = linux.parent_creator.is_some() && (creator.is_none() || linux.parent_creator == creator);
            if matches {
                let signals: alloc::vec::Vec<_> = linux.parent_death.settings.values().copied().filter(|&signal| signal != 0).collect();
                for signal in signals { queue(task, signal, process as i32); }
                if let thread::Personality::Linux(linux) = &mut task.personality { linux.parent_creator = None; }
            }
            if creator.is_none() {
                task.kernel.parent_tid = adopt;
                if let thread::Personality::Linux(linux) = &mut task.personality { linux.parent_creator = (adopt >= 0).then_some(adopt); }
            }
        }
    }
}

pub(crate) fn notify_thread_exits<A: crate::Arch>(threads: &mut [thread::Thread<A>], process: usize) {
    let exited = match &mut threads[process].personality {
        thread::Personality::Linux(linux) => async_io::take_exited(&mut linux.async_io),
        _ => return,
    };
    for id in exited { parent_exited(threads, process, Some(id)); }
}

pub(super) fn poll<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, regs: &mut Regs) -> Option<thread::KernelAction> {
    if linux.parent_death.pending == 0 && !linux.parent_death.stopped { return None; }
    let caller = async_io::current_id(&linux.async_io, kt.tid);
    let signal = (1..=64).find(|&signal| linux.parent_death.pending & (1 << (signal - 1)) != 0
        && (!linux.parent_death.stopped || signal == 9 || signal == 18)
        && signals::disposition(linux, caller, signal).is_some());
    let Some(signal) = signal else {
        if linux.parent_death.stopped { kt.state = thread::ThreadState::Blocked; return Some(thread::KernelAction::Done); }
        return None;
    };
    linux.parent_death.pending &= !(1 << (signal - 1));
    let sender = linux.parent_death.senders.remove(&(signal as u8)).unwrap_or(0);
    let child_exit_code = if signal == 17 { linux.parent_death.child_exit_code.take() } else { None };
    let handler = signals::handler(linux, signal);
    if handler == 1 || handler == 0 && matches!(signal, 17 | 18 | 23 | 28) { return Some(thread::KernelAction::Done); }
    if signal == 19 || handler == 0 && matches!(signal, 20..=22) {
        linux.parent_death.stopped = true;
        kt.state = thread::ThreadState::Blocked;
        return Some(thread::KernelAction::Done);
    }
    let interrupted = kt.state == thread::ThreadState::Blocked || linux.has_blocked_work();
    async_io::interrupt(kt, &mut linux.async_io, regs);
    if interrupted {
        linux.pending_read = None; linux.pending_poll = None; linux.pending_socket = None;
        linux.pending_select = None; linux.pending_random = None; linux.pending_flock = None;
        linux.pending_record_lock = None; linux.pending_readv = None;
        linux.wait_status_ptr = 0; linux.waiting_child = None;
        regs.rax = (-4i64) as u64;
    }
    let delivered = if signal == 9 { false }
        else if let Some(code) = child_exit_code { signals::deliver_child_exit(machine, linux, kt.tid, regs, sender, code) }
        else { signals::deliver(machine, linux, kt.tid, regs, signal, 0, sender as u64) };
    if !delivered {
        return Some(thread::KernelAction::Exit(-(signal as i32)));
    }
    Some(thread::KernelAction::Done)
}
