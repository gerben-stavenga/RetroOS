//! DPMI 0500h-0503h presentation over the DOS personality's common committed
//! extended-memory manager. Descriptor and mode-switch state remains DPMI-owned;
//! allocation, quota, range selection and page lifetime do not.

use super::state::DpmiState;
use super::super::memory::{self, Backing, DosMemory, Error};

const PAGE: u32 = 4096;
const MAX_MEM_BLOCKS: usize = 256;
const NO_LINEAR: u16 = 0x8012;
const NO_PHYSICAL: u16 = 0x8013;
const NO_HANDLE: u16 = 0x8016;
const BAD_SIZE: u16 = 0x8021;
const BAD_HANDLE: u16 = 0x8023;

fn code(error: Error) -> u16 {
    match error {
        Error::BadSize => BAD_SIZE,
        Error::NoLinear => NO_LINEAR,
        Error::NoPhysical => NO_PHYSICAL,
        Error::NoSlots => NO_HANDLE,
        Error::BadHandle => BAD_HANDLE,
    }
}

pub(super) fn info<A: Backing>(machine: &A, memory: &DosMemory, dpmi: &DpmiState) -> [u32; 12] {
    let free = memory.available_pages(machine).min(u32::MAX as usize) as u32;
    let max = if memory.owner_blocks(dpmi.memory_owner) < MAX_MEM_BLOCKS {
        memory.largest_bytes(machine, dpmi.mem_start, memory::general_limit(), PAGE) / PAGE
    } else { 0 };
    // DPMI 0.9 defines this as pages managed by the DPMI host, not installed
    // machine RAM. Kernel pages, another DOS task's suspended address space,
    // and reserved video backing can never be returned by 0501h and therefore
    // must not be counted. Existing blocks of this client remain managed but
    // are no longer free.
    let managed = memory.owner_pages(dpmi.memory_owner)
        .saturating_add(free as usize).min(u32::MAX as usize) as u32;
    let mut info = [u32::MAX; 12];
    info[0] = max * PAGE;
    info[1] = max;
    info[2] = max;
    info[4] = managed;
    info[5] = free;
    info[6] = managed;
    info[8] = 0;
    info
}

pub(super) fn allocate<A: Backing>(
    machine: &mut A,
    memory: &mut DosMemory,
    dpmi: &DpmiState,
    size: u32,
) -> Result<u32, u16> {
    if memory.owner_blocks(dpmi.memory_owner) >= MAX_MEM_BLOCKS { return Err(NO_HANDLE); }
    memory.allocate(
        machine, dpmi.memory_owner, size, PAGE, dpmi.mem_start, memory::general_limit(),
    ).map(|block| block.base).map_err(code)
}

pub(super) fn free<A: Backing>(
    machine: &mut A,
    memory: &mut DosMemory,
    dpmi: &DpmiState,
    handle: u32,
) -> Result<(), u16> {
    memory.free(machine, dpmi.memory_owner, handle).map_err(code)
}

pub(super) fn resize<A: Backing>(
    machine: &mut A,
    memory: &mut DosMemory,
    dpmi: &DpmiState,
    handle: u32,
    size: u32,
) -> Result<u32, u16> {
    memory.resize(
        machine, dpmi.memory_owner, handle, size, PAGE, dpmi.mem_start,
        memory::general_limit(),
    ).map(|block| block.base).map_err(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pool { free: usize }

    impl Backing for Pool {
        fn free_page_count(&self) -> usize { self.free }
        fn map_fresh_range(&mut self, _base: usize, count: usize) { self.free -= count; }
        fn unmap_range(&mut self, _base: usize, count: usize) { self.free += count; }
        fn swap_page_entries(&mut self, _from: usize, _to: usize, _count: usize) {}
    }

    #[test]
    fn memory_info_counts_only_pages_managed_for_this_client() {
        let mut pool = Pool { free: 4096 };
        let mut memory = DosMemory::new();
        let (owner, start) = memory.new_dpmi_owner();
        let dpmi = DpmiState::new(owner, start);

        let before = info(&pool, &memory, &dpmi);
        assert_eq!(before[4], before[5]);
        assert_eq!(before[5], before[6]);

        allocate(&mut pool, &mut memory, &dpmi, 3 * PAGE).unwrap();
        let after = info(&pool, &memory, &dpmi);
        assert_eq!(after[4], after[5] + 3);
        assert_eq!(after[6], after[5] + 3);
        assert_eq!(after[6], before[6]);
    }
}
