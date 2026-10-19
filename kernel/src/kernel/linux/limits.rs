//! Queries for the limits this personality currently exposes. Updating a
//! limit is unsupported unless it is an identical no-op; never report that
//! a requested policy was installed without enforcing it.
use super::{Args, EFAULT, EINVAL, SyscallResult, thread};

fn values(resource: u64) -> Option<(u64, u64)> {
    let limit = match resource {
        4 => 0,                      // RLIMIT_CORE: no core-dump writer.
        7 => thread::MAX_FDS as u64, // Ordinary process file-descriptor table.
        0..=15 => u64::MAX,          // No additional CPU, stack, data or address-space policy.
        _ => return None,
    };
    Some((limit, limit))
}
fn range(pointer: u64, size: u64) -> bool {
    pointer != 0
        && pointer
            .checked_add(size)
            .is_some_and(|end| end <= 0xc0000000)
}

pub(super) fn prlimit<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    args: &Args,
) -> SyscallResult {
    if args.a0 != 0 && args.a0 != kt.tid as u64 {
        return SyscallResult::val(-3);
    }
    let Some((soft, hard)) = values(args.a1) else {
        return SyscallResult::val(-EINVAL);
    };
    if (args.a2 != 0 && !range(args.a2, 16)) || (args.a3 != 0 && !range(args.a3, 16)) {
        return SyscallResult::val(-EFAULT);
    }
    if args.a2 != 0 {
        let proposed_soft = machine.read::<u64>(args.a2 as usize);
        let proposed_hard = machine.read::<u64>(args.a2 as usize + 8);
        if proposed_soft > proposed_hard {
            return SyscallResult::val(-EINVAL);
        }
        if (proposed_soft, proposed_hard) != (soft, hard) {
            return SyscallResult::val(-95);
        }
    }
    if args.a3 != 0 {
        machine.write::<u64>(args.a3 as usize, soft);
        machine.write::<u64>(args.a3 as usize + 8, hard);
    }
    SyscallResult::val(0)
}

pub(super) fn getrlimit<A: crate::Arch>(machine: &mut A, args: &Args, wide: bool) -> SyscallResult {
    let Some((soft, hard)) = values(args.a0) else {
        return SyscallResult::val(-EINVAL);
    };
    if !range(args.a1, if wide { 16 } else { 8 }) {
        return SyscallResult::val(-EFAULT);
    }
    if wide {
        machine.write::<u64>(args.a1 as usize, soft);
        machine.write::<u64>(args.a1 as usize + 8, hard);
    } else {
        machine.write::<u32>(args.a1 as usize, soft.min(u32::MAX as u64) as u32);
        machine.write::<u32>(args.a1 as usize + 4, hard.min(u32::MAX as u64) as u32);
    }
    SyscallResult::val(0)
}
