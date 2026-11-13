//! Long-mode reservations above the compatibility kernel's PML4 slot.
use super::*;
pub(super) const START: u64 = 1 << 39;
const END: u64 = 1 << 47;

#[derive(Clone)]
pub(super) struct State {
    cursor: u64,
    ranges: alloc::vec::Vec<(u64, u64)>,
}
impl Default for State {
    fn default() -> Self { Self::new() }
}
impl State {
    pub fn new() -> Self { Self { cursor: 1 << 46, ranges: alloc::vec::Vec::new() } }
    fn remove(&mut self, start: u64, end: u64) {
        let mut index = 0;
        while index < self.ranges.len() {
            let (lo, hi) = self.ranges[index];
            if hi <= start || lo >= end { index += 1; continue; }
            if lo < start && hi > end {
                self.ranges[index] = (lo, start);
                self.ranges.insert(index + 1, (end, hi));
                break;
            } else if lo < start { self.ranges[index].1 = start; index += 1; }
            else if hi > end { self.ranges[index].0 = end; break; }
            else { self.ranges.remove(index); }
        }
    }
    fn reserve(&mut self, start: u64, end: u64) {
        self.remove(start, end);
        self.ranges.push((start, end));
    }
    fn allocate(&self, size: u64) -> Option<u64> {
        let mut end = self.cursor;
        loop {
            let base = end.checked_sub(size).filter(|base| *base >= START)?;
            match self.ranges.iter().filter(|(lo, hi)| base < *hi && end > *lo).max_by_key(|(lo, _)| *lo) {
                Some((lo, _)) => end = *lo,
                None => return Some(base),
            }
        }
    }
}

pub fn range(address: u64, length: u64) -> bool {
    address.checked_add(length).is_some_and(|end|
        (address != 0 || length == 0) && (end <= 0xc0000000 || address >= START && end <= END))
}
pub fn copy_to<A: crate::Arch>(machine: &mut A, address: u64, bytes: &[u8]) -> bool {
    if !range(address, bytes.len() as u64) { return false; }
    if address < START { machine.copy_to(address as usize, bytes); true }
    else {
        // Keep the Arch interface mutable-buffer-only without exposing a guest reference.
        let mut buffer = bytes.to_vec();
        crate::kernel::memory::high_copy(machine, address, &mut buffer, true)
    }
}
pub fn copy_from<A: crate::Arch>(machine: &mut A, address: u64, bytes: &mut [u8]) -> bool {
    if !range(address, bytes.len() as u64) { return false; }
    if address < START { machine.copy_from(address as usize, bytes); true }
    else { crate::kernel::memory::high_copy(machine, address, bytes, false) }
}

/// Read a guest string without truncating high thread-stack pointers. Stop at
/// page boundaries so a terminating NUL never requires the following page.
pub(super) fn copy_cstr<A: crate::Arch>(machine: &mut A, address: u64, bytes: &mut [u8]) -> Result<usize, i32> {
    if address < START {
        if !range(address, 1) { return Err(-EFAULT); }
        let count = bytes.len().min((0xc0000000 - address) as usize);
        let length = machine.copy_cstr(address as usize, &mut bytes[..count]);
        return if length == count && count < bytes.len() { Err(-EFAULT) } else { Ok(length) };
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let pointer = address.checked_add(offset as u64).ok_or(-EFAULT)?;
        let count = (4096 - (pointer & 4095) as usize).min(bytes.len() - offset);
        if !copy_from(machine, pointer, &mut bytes[offset..offset + count]) { return Err(-EFAULT); }
        if let Some(end) = bytes[offset..offset + count].iter().position(|&byte| byte == 0) { return Ok(offset + end); }
        offset += count;
    }
    Ok(offset)
}

pub fn mmap<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    if a.a0 < START && a.a1 <= 0xc0000000 && a.a0 <= u32::MAX as u64 {
        let low = sys_mmap2(machine, kt, linux, a, a.a5 as usize);
        // Additional V8 isolates can exhaust the low window with reservations
        // smaller than 3 GiB. Fixed mappings and MAP_32BIT must stay low.
        if low.retval != -(ENOMEM as i64) || a.a3 & (0x10 | 0x40 | 0x100000) != 0
            || a.a3 & 0x20 == 0 || a.a3 & 3 != 2 { return low; }
    }
    if a.a1 == 0 { return SyscallResult::val(-EINVAL); }
    linux_trace!("[LINUX-HIGH] mmap addr={:#x} len={:#x} prot={:#x} flags={:#x}", a.a0, a.a1, a.a2, a.a3);
    let Some(size) = a.a1.checked_add(4095).map(|n| n & !4095).filter(|n| *n != 0 && *n <= END - START)
        else { return SyscallResult::val(-ENOMEM); };
    if a.a3 & 0x20 == 0 || a.a3 & 3 != 2 { return SyscallResult::val(-19); }
    if a.a2 & !7 != 0 { return SyscallResult::val(-EINVAL); }
    let fixed = a.a3 & (0x10 | 0x100000) != 0;
    if fixed && a.a0 & 4095 != 0 { return SyscallResult::val(-EINVAL); }
    if fixed && a.a0 < START { return SyscallResult::val(-ENOMEM); }
    let hint = a.a0 & !4095;
    if hint >= START && hint.checked_add(size).is_some_and(|end| end <= END) {
        let operation = if a.a3 & 0x10 != 0 { 0 } else { 4 };
        let result = crate::kernel::memory::high_mapping(machine, hint, size, operation, a.a2 as u32);
        if result == 0 { linux.high_mappings.reserve(hint, hint + size); return SyscallResult::val64(hint as i64); }
        linux_trace!("[LINUX-HIGH] hint failed {}", result);
        if fixed { return SyscallResult::val(result); }
    } else if fixed { return SyscallResult::val(-ENOMEM); }
    // Leave low-address allocations where the existing ELF loaders expect them.
    // The sparse high arena is used for large reservations and explicit hints.
    let Some(base) = linux.high_mappings.allocate(size)
        else { return SyscallResult::val(-ENOMEM); };
    let result = crate::kernel::memory::high_mapping(machine, base, size, 4, a.a2 as u32);
    if result == 0 {
        linux.high_mappings.cursor = base;
        linux.high_mappings.reserve(base, base + size);
        SyscallResult::val64(base as i64)
    } else { linux_trace!("[LINUX-HIGH] allocation failed {}", result); SyscallResult::val(result) }
}

pub fn change<A: crate::Arch>(machine: &mut A, a: &Args, operation: u32) -> SyscallResult {
    if a.a0 & 4095 != 0 { return SyscallResult::val(-EINVAL); }
    let Some(length) = a.a1.checked_add(4095).map(|n| n & !4095)
        else { return SyscallResult::val(-EINVAL); };
    if !range(a.a0, length) || a.a0 < START { return SyscallResult::val(-EINVAL); }
    if length == 0 { return SyscallResult::val(if operation == 2 { -EINVAL } else { 0 }); }
    SyscallResult::val(crate::kernel::memory::high_mapping(machine, a.a0, length, operation, if operation == 1 { a.a2 as u32 } else { 0 }))
}

pub fn unmap<A: crate::Arch>(machine: &mut A, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let result = change(machine, a, 2);
    if result.retval == 0 {
        let end = a.a0 + ((a.a1 + 4095) & !4095);
        linux.high_mappings.remove(a.a0, end);
        if a.a0 == linux.high_mappings.cursor { linux.high_mappings.cursor = end; }
    }
    result
}
