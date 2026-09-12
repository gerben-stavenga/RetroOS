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
    let max = if memory.owner_blocks(dpmi.memory_owner) < MAX_MEM_BLOCKS {
        memory.largest_bytes(machine, dpmi.mem_start, memory::general_limit(), PAGE) / PAGE
    } else { 0 };
    let mut info = [u32::MAX; 12];
    info[0] = max * PAGE;
    info[1] = max;
    info[2] = max;
    info[4] = max;
    info[5] = max;
    info[6] = memory.total_page_count(machine)
        .map_or(u32::MAX, |n| n.min(u32::MAX as usize) as u32);
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
