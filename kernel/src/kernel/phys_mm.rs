//! Physical RAM allocator for exclusively owned frames.
#![no_std]
extern crate alloc;
use arch_abi::PAGE_SIZE;
use core::sync::atomic::{AtomicUsize, Ordering};

use arch_abi::page_supply::FrameLayout;

#[path = "phys_mm/isa_dma.rs"]
mod isa_dma;
pub use isa_dma::{LowDmaMemory, install_low_dma_memory, dma_channel_buf};
use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
#[path = "phys_mm/pool.rs"]
mod pool;
use pool::Pool;

// One bootstrap page covers 128 MiB of usable RAM; address holes and boot
// modules are excluded before allocation. Full metadata is sized to real RAM.
const BOOTSTRAP_BYTES: usize = PAGE_SIZE;
static POOL: spin::Mutex<Option<Pool<'static>>> = spin::Mutex::new(None);

fn with_pool<R>(operation: impl FnOnce(&mut Pool<'static>) -> R) -> R {
    // The critical section touches only resident metadata.
    let mut pool = POOL.lock();
    operation(pool.as_mut().expect("physical allocator not initialized"))
}

/// Install the finalized RAM layout and mark the occupied boot frames.
pub fn bootstrap<'a>(layout: &'static FrameLayout, occupied: &'a [core::ops::Range<u64>]) -> Bootstrap<'a> {
    let mut pool = Pool::new(layout, BOOTSTRAP_BYTES);
    for range in occupied { pool.mark(range.start, range.end); }
    let previous = POOL.lock().replace(pool);
    drop(previous);
    Bootstrap { occupied }
}

#[must_use]
pub struct Bootstrap<'a> {
    occupied: &'a [core::ops::Range<u64>],
}

impl Bootstrap<'_> {
    /// Back the full bitmap through the kernel heap, which can draw frames from
    /// the bootstrap bitmap while this allocation is in progress.
    pub fn finish(self) {
        let pages = with_pool(|pool| pool.frame_count());
        assert!(pages != 0, "firmware supplied no usable RAM");
        let states = alloc::vec![0; pages.div_ceil(8)];
        with_pool(|pool| {
            pool.expand(states);
            // Some boot reservations may lie beyond the bootstrap bitmap.
            for range in self.occupied { pool.mark(range.start, range.end); }
        });
    }
}

// The kernel may donate an exclusively owned cached frame on exhaustion.
// No pool borrow survives the callback; it may release cache metadata.
static RECLAIM: spin::Mutex<Option<fn() -> Option<u64>>> = spin::Mutex::new(None);
pub fn set_reclaim(callback: fn() -> Option<u64>) { *RECLAIM.lock() = Some(callback); }
/// Heap growth cannot reclaim objects through the heap it is extending.
pub fn alloc_resident_page() -> Option<u64> {
    with_pool(|pool| pool.allocate())
}

pub fn alloc_phys_page() -> Option<u64> {
    if let Some(page) = with_pool(|pool| pool.allocate()) { return Some(page); }
    let reclaim = (*RECLAIM.lock())?;
    reclaim()
}

/// Return an exclusively owned frame to the allocator.
pub fn free_phys_page(page: u64) {
    with_pool(|pool| pool.release(page));
}

/// Allocate physically contiguous DMA memory from the general pool.
///
/// Release with `free_phys_contig`. Pages are not zeroed.
pub fn alloc_phys_contig(num_pages: usize) -> Option<u64> {
    alloc_contig(num_pages)
}

/// Return a contiguous allocation to RAM.
pub fn free_phys_contig(start_page: u64, num_pages: usize) {
    with_pool(|pool| pool.free_contiguous(start_page, num_pages));
}

/// PCI allocations remain below 4 GiB for devices with 32-bit DMA addresses.
/// This constraint does not apply to the general physical page allocator.
pub fn alloc_contig(num_pages: usize) -> Option<u64> {
    with_pool(|pool| pool.allocate_contiguous(num_pages, (1u64 << 32) / PAGE_SIZE as u64))
}
pub fn free_page_count() -> usize { with_pool(|pool| pool.free_pages()) }
pub fn total_page_count() -> usize { with_pool(|pool| pool.managed_pages()) }

#[cfg(test)]
#[path = "phys_mm/tests.rs"]
mod tests;

/// Allocate a bounded batch. A short batch means the RAM pool is exhausted.
pub fn page_batch(count: usize) -> arch_abi::page_supply::PageInput {
    assert!(count <= arch_abi::page_supply::SUPPLY_CAPACITY);
    let mut pages = arch_abi::page_supply::PageInput::new();
    for _ in 0..count {
        let Some(page) = alloc_phys_page() else { break; };
        pages.push(page);
    }
    pages
}
/// Permanent host mapping of the RAM supplied at platform setup. Zero means
/// physical RAM has no direct view and shared buffers use the kernel heap.
static DIRECT_BASE: AtomicUsize = AtomicUsize::new(0);
static DIRECT_BYTES: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// The page-aligned mapping must remain writable for the lifetime of the kernel.
/// Call once, before any architecture or kernel memory allocation.
pub unsafe fn install_direct_ram(base: *mut u8, bytes: usize) {
    assert!(!base.is_null() && (base as usize).is_multiple_of(PAGE_SIZE));
    assert!(bytes.is_multiple_of(PAGE_SIZE));
    DIRECT_BASE.store(base as usize, Ordering::Release);
    DIRECT_BYTES.store(bytes, Ordering::Release);
}

/// Allocate and zero frames from directly mapped RAM.
fn alloc_direct_pages(count: usize) -> u64 {
    assert!(DIRECT_BASE.load(Ordering::Acquire) != 0 && count != 0, "direct RAM not initialized");
    let page = if count == 1 { alloc_phys_page() } else { alloc_contig(count) }
        .expect("physical RAM exhausted");
    unsafe { core::ptr::write_bytes(direct_pointer(page), 0, count.checked_mul(PAGE_SIZE).unwrap()); }
    page
}

pub fn direct_pointer(page: u64) -> *mut u8 {
    let offset = usize::try_from(page).unwrap().checked_mul(PAGE_SIZE).unwrap();
    assert!(offset < DIRECT_BYTES.load(Ordering::Acquire));
    (DIRECT_BASE.load(Ordering::Acquire) + offset) as *mut u8
}

/// Translate a pointer within the caller's permanent hosted RAM view.
pub fn direct_frame(base: core::ptr::NonNull<u8>) -> u64 {
    let start = DIRECT_BASE.load(Ordering::Acquire);
    assert_ne!(start, 0, "direct RAM not initialized");
    let offset = (base.as_ptr() as usize).checked_sub(start).expect("pointer outside direct RAM");
    assert!(offset.is_multiple_of(PAGE_SIZE));
    assert!(offset.checked_add(PAGE_SIZE).is_some_and(|end| end <= DIRECT_BYTES.load(Ordering::Acquire)));
    (offset / PAGE_SIZE) as u64
}

pub fn alloc_shared_pages(count: usize) -> core::ptr::NonNull<u8> {
    assert!(count != 0);
    if DIRECT_BASE.load(Ordering::Acquire) != 0 {
        return core::ptr::NonNull::new(direct_pointer(alloc_direct_pages(count))).unwrap();
    }
    let layout = Layout::from_size_align(count.checked_mul(PAGE_SIZE).unwrap(), PAGE_SIZE).unwrap();
    core::ptr::NonNull::new(unsafe { alloc_zeroed(layout) })
        .unwrap_or_else(|| alloc::alloc::handle_alloc_error(layout))
}

/// # Safety
/// All aliases must be removed, and base/count must match a live allocation.
pub unsafe fn free_shared_pages(base: core::ptr::NonNull<u8>, count: usize) {
    let direct = DIRECT_BASE.load(Ordering::Acquire);
    if direct != 0 {
        let offset = (base.as_ptr() as usize).checked_sub(direct).unwrap();
        assert!(offset.is_multiple_of(PAGE_SIZE));
        assert!(offset.checked_add(count.checked_mul(PAGE_SIZE).unwrap()).unwrap() <= DIRECT_BYTES.load(Ordering::Acquire));
        for i in 0..count { free_phys_page((offset / PAGE_SIZE + i) as u64); }
    } else {
        unsafe { dealloc(base.as_ptr(), Layout::from_size_align(count.checked_mul(PAGE_SIZE).unwrap(), PAGE_SIZE).unwrap()); }
    }
}
