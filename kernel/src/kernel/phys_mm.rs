//! Physical RAM allocator: an allocation bitmap separate from resident frame references.
#![no_std]
extern crate alloc;
use arch_abi::PAGE_SIZE;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Platform-supplied physical byte range. Reserved ranges override usable RAM.
#[derive(Clone, Copy)]
pub struct MemoryRegion { pub base: u64, pub length: u64, pub usable: bool }

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
static mut BOOTSTRAP_STATES: [u8; BOOTSTRAP_BYTES] = [0; BOOTSTRAP_BYTES];
static mut POOL: Pool = Pool::new();
static mut KERNEL_RANGE: (u64, u64) = (0, 0);
fn pool_ptr() -> *mut Pool { &raw mut POOL }
static POOL_LOCK: AtomicBool = AtomicBool::new(false);
// Arch reads immutable layout data, never fields covered by a mutable Pool borrow.
static mut VIEW_REGIONS: [arch_abi::page_supply::FrameRegion; 256] =
    [arch_abi::page_supply::FrameRegion { first: 0, end: 0, offset: 0 }; 256];
static mut VIEW_READY: bool = false;
struct PoolGuard;
impl Drop for PoolGuard { fn drop(&mut self) { POOL_LOCK.store(false, Ordering::Release); } }
fn with_pool<R>(operation: impl FnOnce(&mut Pool) -> R) -> R {
    while POOL_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    let _guard = PoolGuard;
    // The critical section only touches resident metadata; never allocate,
    // reclaim, free heap storage or enter arch while this borrow is live.
    let pool = unsafe { &mut *pool_ptr() };
    let result = operation(pool);
    result
}


// Written during single-CPU initialization, then immutable.
static mut ZERO_PAGE: u64 = u64::MAX;
pub fn is_zero_page(page: u64) -> bool { page == unsafe { ZERO_PAGE } }

/// Track whole usable pages; overlapping firmware reservations take precedence.
pub fn init_phys_mm(
    entries: impl Iterator<Item = MemoryRegion> + Clone,
    limit: u64,
    kernel_low: u64,
    kernel_high: u64,
    zero_page: u64,
) {
    unsafe { ZERO_PAGE = zero_page; VIEW_READY = false; }
    unsafe {
        let pool = &mut *pool_ptr();
        *pool = Pool::new();
        KERNEL_RANGE = (kernel_low, kernel_high);
        for entry in entries.clone() {
            if !entry.usable { continue; }
            let first = entry.base.div_ceil(PAGE_SIZE as u64).min(limit);
            let end = (entry.base.saturating_add(entry.length) / PAGE_SIZE as u64).min(limit);
            pool.include(first, end);
        }
        for entry in entries {
            if entry.usable { continue; }
            let first = (entry.base / PAGE_SIZE as u64).min(limit);
            let end = entry.base.saturating_add(entry.length).div_ceil(PAGE_SIZE as u64).min(limit);
            pool.exclude(first, end);
        }
        pool.exclude(0, 0x100000 / PAGE_SIZE as u64);
        reset_bootstrap(pool);
    }
}

unsafe fn reset_bootstrap(pool: &mut Pool) {
    unsafe {
        pool.bootstrap((&raw mut BOOTSTRAP_STATES).cast(), BOOTSTRAP_BYTES);
        let (first, end) = KERNEL_RANGE;
        pool.mark(first, end);
    }
}

/// Allocate full metadata after the heap is enabled. No mutable pool borrow
/// survives an allocation: backing metadata pages recursively calls this pool.
pub fn complete_initialization() {
    let pages = unsafe { (*pool_ptr()).pages };
    assert!(pages != 0, "firmware supplied no usable RAM");
    let state_layout = Layout::array::<u8>(pages.div_ceil(8)).expect("page state size overflow");
    unsafe {
        let states = alloc_zeroed(state_layout);
        assert!(!states.is_null(), "cannot allocate physical page states");
        (*pool_ptr()).expand(states, core::ptr::null_mut());
    }
}

/// Before allocation, omit boot reservations from metadata altogether.
pub fn mark_reserved(low_page: u64, high_page: u64) {
    unsafe {
        let pool = &mut *pool_ptr();
        if !pool.started {
            VIEW_READY = false;
            pool.exclude(low_page, high_page);
            reset_bootstrap(pool);
        } else { panic!("boot reservation after physical allocation started"); }
    }
}

#[allow(dead_code)]
pub fn mark_used(low_page: u64, high_page: u64) {
    unsafe { (*pool_ptr()).mark(low_page, high_page); }
}

// The kernel may donate an exclusively owned cached frame on exhaustion.
// No pool borrow survives the callback; it may release cache metadata.
static RECLAIM: AtomicUsize = AtomicUsize::new(0);
pub fn set_reclaim(callback: fn() -> Option<u64>) { RECLAIM.store(callback as usize, Ordering::Release); }
/// Heap growth cannot reclaim objects through the heap it is extending.
pub fn alloc_resident_page() -> Option<u64> {
    with_pool(|pool| pool.allocate())
}

pub fn alloc_phys_page() -> Option<u64> {
    if let Some(page) = with_pool(|pool| pool.allocate()) { return Some(page); }
    let callback = RECLAIM.load(Ordering::Acquire);
    if callback == 0 { return None; }
    let reclaim: fn() -> Option<u64> = unsafe { core::mem::transmute(callback) };
    reclaim()
}

pub fn free_phys_page(page: u64) {
    if is_zero_page(page) { return; }
    with_pool(|pool| pool.release(page));
}

pub fn inc_shared_count(page: u64) -> bool {
    if is_zero_page(page) { return true; }
    with_pool(|pool| pool.retain(page))
}

/// Publish resident ownership data, never allocator functions, to arch.
pub fn ownership() -> arch_abi::page_supply::FrameOwnership {
    with_pool(|pool| {
        let mut view = pool.ownership(unsafe { ZERO_PAGE });
        unsafe {
            if !VIEW_READY {
                core::ptr::copy_nonoverlapping(view.regions, (&raw mut VIEW_REGIONS).cast(), view.regions_len);
                VIEW_READY = true;
            }
        }
        view.regions = (&raw const VIEW_REGIONS).cast();
        view
    })
}

/// Provision the page-aligned reference arena before guest execution. Allocation and first
/// touches happen in kernel context; fault handlers only access resident bytes.
pub fn prepare_fault_metadata() {
    let pages = unsafe { (*pool_ptr()).pages };
    let bytes = pages.next_multiple_of(PAGE_SIZE);
    let arena = unsafe { alloc_zeroed(Layout::from_size_align(bytes, PAGE_SIZE).unwrap()) };
    assert!(!arena.is_null(), "cannot allocate resident frame references");
    unsafe { (*pool_ptr()).install_counts(arena); }
}

pub fn get_ref_count(page: u64) -> u8 {
    if is_zero_page(page) { return 255; }
    with_pool(|pool| pool.refs(page))
}

#[allow(dead_code)]
pub fn is_shared(page: u64) -> bool { matches!(get_ref_count(page), 2..=254) }

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
pub fn bootstrap_supply() -> arch_abi::page_supply::PageBootstrap {
    let mut pages = [0; arch_abi::page_supply::FAULT_PAGES];
    for page in &mut pages { *page = alloc_phys_page().expect("out of AP fault reserve pages"); }
    arch_abi::page_supply::PageBootstrap { ownership: ownership(), pages }
}

/// Permanent host mapping of the RAM supplied at platform setup. Zero means
/// physical RAM has no direct view and shared buffers use the kernel heap.
static DIRECT_BASE: AtomicUsize = AtomicUsize::new(0);
static DIRECT_BYTES: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// The page-aligned mapping must remain writable for the lifetime of the kernel.
/// Call once, before any architecture or kernel memory allocation.
pub unsafe fn init_direct_ram(base: *mut u8, bytes: usize) {
    assert!(!base.is_null() && (base as usize).is_multiple_of(PAGE_SIZE));
    assert!(bytes.is_multiple_of(PAGE_SIZE));
    DIRECT_BASE.store(base as usize, Ordering::Release);
    DIRECT_BYTES.store(bytes, Ordering::Release);
    init_phys_mm(core::iter::once(MemoryRegion { base: 0, length: bytes as u64, usable: true }),
        (bytes / PAGE_SIZE) as u64, 0, 0, u64::MAX);
    complete_initialization();
    prepare_fault_metadata();
}

/// Allocate zeroed frames from directly mapped RAM. Allocation, reference
/// counting and reuse use exactly the same pool as native physical memory.
pub fn alloc_backed_pages(count: usize) -> u64 {
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
        return core::ptr::NonNull::new(direct_pointer(alloc_backed_pages(count))).unwrap();
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
