//! Wall-clock interval timers. Fork clears them; exec preserves them.
use super::{Args, LinuxState, SyscallResult, async_io, signals, thread};
use crate::Regs;

#[derive(Clone, Copy, Default)]
pub(super) struct Timer {
    deadline: Option<u64>,
    interval: u64,
    pending: bool,
}
impl Timer {
    fn expire(&mut self, now: u64) {
        if let Some(deadline) = self.deadline.filter(|&deadline| now >= deadline) {
            self.pending = true;
            self.deadline = (now - deadline)
                .checked_div(self.interval)
                .and_then(|missed| missed.checked_add(1))
                .and_then(|count| count.checked_mul(self.interval))
                .and_then(|advance| deadline.checked_add(advance));
        }
    }
}
fn valid(pointer: u64) -> bool {
    pointer != 0 && pointer.checked_add(32).is_some_and(|end| end <= 0xc0000000)
}
fn duration(seconds: i64, micros: i64) -> Option<u64> {
    if seconds < 0 || !(0..1_000_000).contains(&micros) {
        return None;
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(micros as u64 * 1000)
}
fn store<A: crate::Arch>(machine: &mut A, pointer: u64, timer: Timer, now: u64) {
    for (offset, nanos) in [
        (0, timer.interval),
        (16, timer.deadline.map_or(0, |end| end.saturating_sub(now))),
    ] {
        let micros = nanos.div_ceil(1000);
        machine.write::<u64>(pointer as usize + offset, micros / 1_000_000);
        machine.write::<u64>(pointer as usize + offset + 8, micros % 1_000_000);
    }
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    linux: &mut LinuxState,
    set: bool,
    a: &Args,
) -> SyscallResult {
    if a.a0 > 2 {
        return SyscallResult::val(-22);
    }
    // CPU-accounting timers need execution accounting rather than wall time.
    if a.a0 != 0 {
        return SyscallResult::val(-38);
    }
    let output = if set { a.a2 } else { a.a1 };
    if (!set || output != 0) && !valid(output) || set && a.a1 != 0 && !valid(a.a1) {
        return SyscallResult::val(-14);
    }
    let now = machine.now();
    let new = if set {
        let (interval, value) = if a.a1 == 0 {
            (0, 0)
        } else {
            let read = |machine: &mut A, offset| {
                duration(
                    machine.read(a.a1 as usize + offset),
                    machine.read(a.a1 as usize + offset + 8),
                )
            };
            let (Some(interval), Some(value)) = (read(machine, 0), read(machine, 16)) else {
                return SyscallResult::val(-22);
            };
            (interval, value)
        };
        let deadline = if value == 0 {
            None
        } else {
            let Some(end) = now.checked_add(value) else {
                return SyscallResult::val(-22);
            };
            Some(end)
        };
        Some((interval, deadline))
    } else {
        None
    };
    linux.alarm.expire(now);
    if output != 0 {
        store(machine, output, linux.alarm, now);
    }
    if let Some((interval, deadline)) = new {
        linux.alarm.interval = interval;
        linux.alarm.deadline = deadline;
    }
    SyscallResult::val(0)
}

pub(super) fn poll<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
) -> Option<thread::KernelAction> {
    linux.alarm.expire(machine.now());
    if !linux.alarm.pending {
        return None;
    }
    let tid = async_io::current_id(&linux.async_io, kt.tid);
    let ignored = signals::disposition(linux, tid, 14)?;
    if ignored {
        linux.alarm.pending = false;
        return None;
    }
    let was_blocked = kt.state == thread::ThreadState::Blocked;
    async_io::interrupt(kt, &mut linux.async_io, regs);
    if was_blocked {
        linux.pending_read = None;
        linux.pending_poll = None;
        linux.pending_socket = None;
        linux.pending_select = None;
        linux.pending_random = None;
        linux.pending_flock = None;
        linux.pending_record_lock = None;
        linux.wait_status_ptr = 0;
        linux.waiting_child = None;
        regs.rax = (-4i64) as u64;
    }
    if !signals::deliver(machine, linux, kt.tid, regs, 14, 128, 0) {
        return Some(thread::KernelAction::Exit(-14));
    }
    linux.alarm.pending = false;
    Some(thread::KernelAction::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_timevals_and_skips_missed_intervals() {
        assert_eq!(duration(1, 999999), Some(1_999_999_000));
        assert_eq!(duration(-1, 0), None);
        assert_eq!(duration(0, 1000000), None);
        assert_eq!(duration(i64::MAX, 0), None);
        let mut timer = Timer {
            deadline: Some(10),
            interval: 5,
            pending: false,
        };
        timer.expire(27);
        assert!(timer.pending);
        assert_eq!(timer.deadline, Some(30));
        timer.interval = 0;
        timer.expire(30);
        assert_eq!(timer.deadline, None);
    }
}
