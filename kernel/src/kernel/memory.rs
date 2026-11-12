//! Kernel-owned physical page supply and explicit inputs to arch operations.
use crate::Arch;
use super::phys_mm;
use arch_abi::page_supply::{PageInput, PageSupply, SUPPLY_CAPACITY};
#[thread_local]
static mut SPARES: PageInput = PageInput::new();
#[thread_local]
static mut CURRENT: *mut PageSupply = core::ptr::null_mut();
fn spares_ptr() -> *mut PageInput { &raw mut SPARES }
static IO: spin::Once<arch_abi::PhysicalFrameIo> = spin::Once::new();

pub fn install_supply(supply: *mut PageSupply) { unsafe { CURRENT = supply; } }

pub fn install_io(io: arch_abi::PhysicalFrameIo) { IO.call_once(|| io); }

/// # Safety
/// Supply belongs to this core. Metadata and its refill stack are resident.
pub unsafe fn replenish(supply: *mut PageSupply) {
    // Drain pages returned by arch before requesting new backing from the pool.
    while unsafe { (*supply).returned_head } != 0 {
        let io = IO.get().expect("returned frames before physical I/O initialization");
        let page = unsafe { (*supply).returned_head };
        let mut next = [0; 8];
        (io.read)(page, 0, &mut next);
        unsafe { (*supply).returned_head = u64::from_ne_bytes(next); (*supply).returned_count -= 1; }
        phys_mm::free_phys_page(page);
    }
    unsafe { phys_mm::replenish_supply(supply); }
}
pub fn service<A: Arch>(machine: &mut A) {
    if let Some(supply) = machine.page_supply() {
        install_supply(supply);
        unsafe { replenish(supply); }
    }
}

/// Mapping operations receive owned pages as data, never allocator callbacks.
pub fn with_pages<A: Arch, R>(machine: &mut A, count: usize, operation: impl FnOnce(&mut A) -> R) -> R {
    if machine.page_supply().is_none() { return operation(machine); }
    assert!(count <= SUPPLY_CAPACITY);
    service(machine);
    let mut input = PageInput::new();
    for _ in 0..count {
        let spare = unsafe { (*spares_ptr()).take() };
        let page = spare.or_else(phys_mm::alloc_phys_page)
            .expect("out of physical memory preparing arch input");
        input.pages[input.count] = page;
        input.count += 1;
    }
    let previous = machine.set_page_input(&mut input);
    let result = operation(machine);
    machine.set_page_input(previous);
    while let Some(page) = input.take() {
        unsafe {
            let spares = &mut *spares_ptr();
            assert!(spares.count < SUPPLY_CAPACITY);
            spares.pages[spares.count] = page;
            spares.count += 1;
        }
    }
    result
}
pub fn fork<A: Arch>(machine: &mut A, child: &mut A::PageTable) {
    with_pages(machine, 3, |machine| machine.user_fork(child));
}
pub fn map_low_mem<A: Arch>(machine: &mut A) {
    with_pages(machine, 16, |machine| machine.map_low_mem());
}
pub fn high_copy<A: Arch>(machine: &mut A, mut address: u64, mut bytes: &mut [u8], to_user: bool) -> bool {
    while !bytes.is_empty() {
        let n = bytes.len().min(4096 - (address as usize & 4095));
        let (part, rest) = bytes.split_at_mut(n);
        if !with_pages(machine, 5, |machine| machine.high_copy(address, part, to_user)) { return false; }
        address += n as u64;
        bytes = rest;
    }
    true
}
pub fn high_mapping<A: Arch>(machine: &mut A, address: u64, length: u64, operation: u32, protection: u32) -> i32 {
    loop {
        let result = with_pages(machine, 5, |machine|
            machine.high_mapping(address, length, operation, protection));
        if result != -11 || machine.page_supply().is_none() { return result; }
    }
}
pub fn alloc_contig<A: Arch>(machine: &mut A, pages: usize) -> u64 {
    if machine.page_supply().is_some() { service(machine); phys_mm::alloc_contig(pages).unwrap_or(0) }
    else { machine.alloc_phys_contig(pages) }
}
pub fn free_contig<A: Arch>(machine: &mut A, page: u64, pages: usize) {
    if machine.page_supply().is_some() { phys_mm::free_phys_contig(page, pages); }
    else { machine.free_phys_contig(page, pages); }
}
pub fn dma_channel<A: Arch>(machine: &A, channel: usize) -> u64 {
    if machine.page_supply().is_some() { phys_mm::dma_channel_buf(channel) }
    else { machine.dma_channel_buf(channel) }
}
pub fn cache_access(io: arch_abi::PhysicalFrameIo) -> arch_abi::FrameAccess {
    install_io(io);
    arch_abi::FrameAccess {
        allocate: allocate_frame, release: phys_mm::free_phys_page,
        read: io.read, write: io.write, free: phys_mm::free_page_count,
        total: phys_mm::total_page_count,
        references: |page| usize::from(phys_mm::get_ref_count(page)),
        set_reclaim: phys_mm::set_reclaim,
    }
}

fn allocate_frame() -> Option<u64> {
    let supply = unsafe { CURRENT };
    if !supply.is_null() {
        // A large unmap may have returned many frames since the last event-loop
        // boundary. Reclaim them before treating the RAM pool as exhausted.
        unsafe {
            while (*supply).returned_head != 0 {
                let io = IO.get().expect("physical I/O not installed");
                let page = (*supply).returned_head;
                let mut next = [0; 8];
                (io.read)(page, 0, &mut next);
                (*supply).returned_head = u64::from_ne_bytes(next);
                (*supply).returned_count -= 1;
                phys_mm::free_phys_page(page);
            }
        }
    }
    phys_mm::alloc_phys_page()
}
