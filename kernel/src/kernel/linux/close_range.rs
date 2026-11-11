//! close_range operates on both ordinary and emulated async descriptors.
use super::{Args, EINVAL, LinuxState, SyscallResult, async_io, thread};

pub(super) fn call<A: crate::Arch>(kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, args: &Args) -> SyscallResult {
    let (first, last, flags) = (args.a0 as u32, args.a1 as u32, args.a2 as u32);
    if first > last || flags & !6 != 0 { return SyscallResult::val(-EINVAL); }
    // Fork already owns a private descriptor table. Splitting the table of
    // one CLONE_FILES user thread from its siblings is not implemented.
    if flags & 2 != 0 && async_io::live_task_count(&linux.async_io) > 1 {
        return SyscallResult::val(-95);
    }
    let cloexec = flags & 4 != 0;
    for fd in (first as usize).min(thread::MAX_FDS)..(u64::from(last) + 1).min(thread::MAX_FDS as u64) as usize {
        if kt.fds[fd].is_none() { continue; }
        if cloexec { kt.cloexec.set(fd, true); } else { kt.close_fd(fd); }
    }
    async_io::close_range(&mut linux.async_io, first, last, cloexec);
    SyscallResult::val(0)
}
