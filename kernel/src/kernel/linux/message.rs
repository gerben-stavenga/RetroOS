//! Linux scatter/gather socket messages, with explicit 32/64-bit ABI layouts.
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

/// Receive one message, scattering bytes without turning UDP iovecs into
/// separate receives. Ancillary data is absent in the current network stack.
pub(super) fn recvmsg<A: crate::Arch>(
    machine: &mut A, kt: &thread::KernelThread<A>, args: &Args, wide: bool,
) -> SyscallResult {
    SyscallResult::val(receive(machine, kt, args, wide))
}
fn receive<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, args: &Args, wide: bool) -> i32 {
    let h = match sock_handle(kt, args.a0) { Ok(h) => h, Err(e) => return e };
    let flags = args.a2 as u32;
    if flags & !(2 | 0x20 | 0x40) != 0 { return -95; }
    let header = args.a1 as usize;
    if header == 0 { return -EFAULT; }
    let unit = if wide { 8 } else { 4 };
    let name = word(machine, header, wide);
    let namelen = machine.read::<u32>(header + unit) as usize;
    let iov_at = header + if wide { 16 } else { 8 };
    let iov = word(machine, iov_at, wide);
    let count = word(machine, iov_at + unit, wide);
    if count > 1024 { return -EINVAL; }
    if count != 0 && iov == 0 { return -EFAULT; }
    let mut vectors = Vec::new();
    let mut capacity = 0usize;
    for index in 0..count {
        let Some(at) = index.checked_mul(unit * 2).and_then(|n| iov.checked_add(n)) else { return -EFAULT };
        let base = word(machine, at, wide);
        let len = word(machine, at + unit, wide);
        if len != 0 && (base == 0 || base.checked_add(len).is_none_or(|end| end > 0xc000_0000)) { return -EFAULT; }
        let Some(total) = capacity.checked_add(len) else { return -EINVAL };
        capacity = total;
        vectors.push((base, len));
    }
    let datagram = match crate::kernel::net::socket_kind(h) {
        Ok(kind) => kind == crate::kernel::net::SocketKind::Udp,
        Err(e) => return -net::errno(e),
    };
    if !datagram && flags & 0x20 != 0 { return -95; }
    // UDP must consume the entire packet even when the caller's vectors are
    // short. A stream must consume only the bytes the caller can receive.
    let mut bytes = alloc::vec![0; if datagram { 65536 } else { capacity.min(65536) }];
    let mut address = [0; 16];
    let n = net::recvfrom(h, &mut bytes, (flags & !0x20) as i32, &mut address);
    if n < 0 { return n; }
    let copied = (n as usize).min(capacity);
    let mut offset = 0;
    for (base, len) in vectors {
        let len = len.min(copied - offset);
        if len != 0 { machine.copy_to(base, &bytes[offset..offset + len]); }
        offset += len;
    }
    if name != 0 {
        machine.copy_to(name, &address[..namelen.min(address.len())]);
        machine.write::<u32>(header + unit, address.len() as u32);
    } else { machine.write::<u32>(header + unit, 0); }
    // msg_controllen and msg_flags are output fields (padding differs by ABI).
    if wide { machine.write::<u64>(iov_at + 3 * unit, 0); }
    else { machine.write::<u32>(iov_at + 3 * unit, 0); }
    machine.write::<u32>(iov_at + 4 * unit, if n as usize > copied { 0x20 } else { 0 });
    if datagram && flags & 0x20 != 0 { n } else { copied as i32 }
}

/// Gather socket writes before sending so a UDP writev remains one datagram.
pub(super) fn gather<A: crate::Arch>(machine: &mut A, iov: usize, count: usize, wide: bool) -> Result<Vec<u8>, i32> {
    if count > 1024 { return Err(-EINVAL); }
    if count != 0 && iov == 0 { return Err(-EFAULT); }
    let unit = if wide { 8 } else { 4 };
    let mut bytes = Vec::new();
    for i in 0..count {
        let at = i.checked_mul(unit * 2).and_then(|n| iov.checked_add(n)).ok_or(-EFAULT)?;
        let base = word(machine, at, wide);
        let len = word(machine, at + unit, wide);
        if len > 65536 - bytes.len() { return Err(-90); }
        if len != 0 && (base == 0 || base.checked_add(len).is_none_or(|end| end > 0xc000_0000)) { return Err(-EFAULT); }
        let offset = bytes.len();
        bytes.resize(offset + len, 0);
        machine.copy_from(base, &mut bytes[offset..]);
    }
    Ok(bytes)
}
pub(super) fn writev<A: crate::Arch>(machine: &mut A, handle: i32, args: &Args, wide: bool) -> SyscallResult {
    SyscallResult::val(match gather(machine, args.a1 as usize, args.a2 as usize, wide) {
        Ok(data) => if data.is_empty() { 0 } else { net::sendto(handle, &data, 0, &[]) },
        Err(e) => e,
    })
}
