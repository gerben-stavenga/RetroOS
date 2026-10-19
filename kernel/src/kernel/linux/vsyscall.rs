//! Linux x86-64 fixed-address calls, emulated at instruction-fetch faults.
//! Keep these addresses unmapped: data accesses and non-entry instruction
//! addresses must still fault. Services are shared with normal syscalls.
use super::{Args, EFAULT, SyscallResult, time};
use crate::{Regs, UserMode};

const USER_END: u64 = 0xc0000000;

fn output_ok(pointer: u64, bytes: u64) -> bool {
    pointer == 0
        || pointer
            .checked_add(bytes)
            .is_some_and(|end| end <= USER_END)
}

/// RetroOS currently runs guests on one logical CPU and one NUMA node.
/// Return the guest's placement, independently of host CPU numbering.
pub(super) fn getcpu<A: crate::Arch>(machine: &mut A, args: &Args) -> SyscallResult {
    if !output_ok(args.a0, 4) || !output_ok(args.a1, 4) {
        return SyscallResult::val(-EFAULT);
    }
    if args.a0 != 0 {
        machine.write::<u32>(args.a0 as usize, 0);
    }
    if args.a1 != 0 {
        machine.write::<u32>(args.a1 as usize, 0);
    }
    SyscallResult::val(0)
}

fn entry(regs: &Regs, address: u32) -> Option<u32> {
    // User instruction fetch, not a data access, write or kernel fault.
    if regs.mode() != UserMode::Mode64
        || regs.err_code & 0x16 != 0x14
        || regs.frame.rip as u32 != address
    {
        return None;
    }
    match regs.frame.rip {
        0xffff_ffff_ff60_0000 => Some(0),
        0xffff_ffff_ff60_0400 => Some(1),
        0xffff_ffff_ff60_0800 => Some(2),
        _ => None,
    }
}

pub(super) fn emulate<A: crate::Arch>(machine: &mut A, regs: &mut Regs, address: u32) -> bool {
    let Some(number) = entry(regs, address) else {
        return false;
    };
    let stack = regs.frame.rsp;
    if stack == 0 || !output_ok(stack, 8) {
        return false;
    }
    let (first_size, second_size) = match number {
        0 => (16, 8),
        1 => (8, 0),
        _ => (4, 4),
    };
    if !output_ok(regs.rdi, first_size) || (second_size != 0 && !output_ok(regs.rsi, second_size)) {
        return false;
    }
    let caller = machine.read::<u64>(stack as usize);
    if caller >= USER_END {
        return false;
    }
    let args = Args {
        a0: regs.rdi,
        a1: regs.rsi,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };
    let result = match number {
        0 => time::gettimeofday(machine, &args, true),
        1 => time::time(machine, &args, true),
        _ => getcpu(machine, &args),
    };
    regs.rax = result.retval as u64;
    // The fault happened at the callee entry, after CALL pushed its return IP.
    regs.frame.rip = caller;
    regs.frame.rsp = stack + 8;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_user_instruction_entries_are_emulated() {
        let mut regs = Regs::empty();
        regs.frame.cs = 0x33;
        regs.frame.rip = 0xffff_ffff_ff60_0800;
        regs.err_code = 0x14;
        assert_eq!(entry(&regs, 0xff600800), Some(2));
        for error in [0, 4, 0x10, 0x16] {
            regs.err_code = error;
            assert_eq!(entry(&regs, 0xff600800), None);
        }
        regs.err_code = 0x14;
        for rip in [0xffff_ffff_ff60_0801, 0xffff_ffff_ff60_0c00, 0xff60_0800] {
            regs.frame.rip = rip;
            assert_eq!(entry(&regs, rip as u32), None);
        }
        assert!(output_ok(0, 16));
        assert!(output_ok(USER_END - 4, 4));
        assert!(!output_ok(USER_END - 3, 4));
        assert!(!output_ok(u64::MAX, 8));
    }
}
