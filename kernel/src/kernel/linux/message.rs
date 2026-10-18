//! Linux scatter/gather datagram sends, with explicit 32/64-bit ABI layouts.
use super::{Args, EFAULT, EINVAL, SyscallResult, net, read_sockaddr, sock_handle, thread};
use alloc::vec::Vec;
fn word<A: crate::Arch>(machine: &mut A, at: usize, wide: bool) -> usize {
    if wide {
        machine.read::<u64>(at) as usize
    } else {
        machine.read::<u32>(at) as usize
    }
}
fn send<A: crate::Arch>(machine: &mut A, h: i32, header: usize, flags: i32, wide: bool) -> i32 {
    if header == 0 {
        return -EFAULT;
    }
    let unit = if wide { 8 } else { 4 };
    let name = word(machine, header, wide);
    let namelen = machine.read::<u32>(header + unit) as usize;
    let iov_at = header + if wide { 16 } else { 8 };
    let iov = word(machine, iov_at, wide);
    let count = word(machine, iov_at + unit, wide);
    let control_len = word(machine, iov_at + 3 * unit, wide);
    if control_len != 0 {
        return -95;
    } // Ancillary sends need their own typed API.
    if count > 1024 {
        return -EINVAL;
    }
    if count != 0 && iov == 0 {
        return -EFAULT;
    }
    let mut data = Vec::new();
    for i in 0..count {
        let Some(at) = i.checked_mul(unit * 2).and_then(|n| iov.checked_add(n)) else {
            return -EFAULT;
        };
        let base = word(machine, at, wide);
        let n = word(machine, at + unit, wide);
        if n > 65536 - data.len() {
            return -90;
        }
        if n != 0 && base == 0 {
            return -EFAULT;
        }
        let start = data.len();
        data.resize(start + n, 0);
        machine.copy_from(base, &mut data[start..]);
    }
    if name != 0 && namelen < 16 {
        return -EINVAL;
    }
    let (address, n) = read_sockaddr(machine, name, namelen);
    // One send per message: iovecs form a single UDP datagram.
    net::sendto(h, &data, flags, &address[..n])
}
pub(super) fn sendmsg<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    args: &Args,
    wide: bool,
) -> SyscallResult {
    let h = match sock_handle(kt, args.a0) {
        Ok(h) => h,
        Err(e) => return SyscallResult::val(e),
    };
    SyscallResult::val(send(machine, h, args.a1 as usize, args.a2 as i32, wide))
}
pub(super) fn sendmmsg<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    args: &Args,
    wide: bool,
) -> SyscallResult {
    let h = match sock_handle(kt, args.a0) {
        Ok(h) => h,
        Err(e) => return SyscallResult::val(e),
    };
    let (header, stride) = if wide { (56, 64) } else { (28, 32) };
    for index in 0..args.a2.min(1024) as usize {
        let Some(at) = index
            .checked_mul(stride)
            .and_then(|n| (args.a1 as usize).checked_add(n))
        else {
            return SyscallResult::val(if index == 0 { -EFAULT } else { index as i32 });
        };
        let n = send(machine, h, at, args.a3 as i32, wide);
        if n < 0 {
            return SyscallResult::val(if index == 0 { n } else { index as i32 });
        }
        machine.write::<u32>(at + header, n as u32);
    }
    SyscallResult::val(args.a2.min(1024) as i32)
}
