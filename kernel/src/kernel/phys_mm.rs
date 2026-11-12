//! Physical RAM allocator: a one-bit RAM bitmap and sparse shared refcounts.
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
use pool::{Pool, REF_BLOCK_PAGES};

// One bootstrap page covers 128 MiB of usable RAM; address holes and boot
// modules are excluded before allocation. Full metadata is sized to real RAM.
const BOOTSTRAP_BYTES: usize = PAGE_SIZE;
static mut BOOTSTRAP_STATES: [u8; BOOTSTRAP_BYTES] = [0; BOOTSTRAP_BYTES];
static mut POOL: Pool = Pool::new();
static mut KERNEL_RANGE: (u64, u64) = (0, 0);
fn pool_ptr() -> *mut Pool { &raw mut POOL }
static POOL_LOCK: AtomicBool = AtomicBool::new(false);
static PUBLISHED_FREE: AtomicUsize = AtomicUsize::new(0);
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
    PUBLISHED_FREE.store(pool.free_pages(), Ordering::Release);
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
    let block_layout = Layout::array::<*mut u8>(pages.div_ceil(REF_BLOCK_PAGES))
        .expect("refcount directory size overflow");
    unsafe {
        let states = alloc_zeroed(state_layout);
        assert!(!states.is_null(), "cannot allocate physical page states");
        let blocks = alloc_zeroed(block_layout).cast::<*mut u8>();
        assert!(!blocks.is_null(), "cannot allocate physical refcount directory");
        (*pool_ptr()).expand(states, blocks);
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
pub fn alloc_phys_page() -> Option<u64> {
    if let Some(page) = with_pool(|pool| pool.allocate()) { return Some(page); }
    let callback = RECLAIM.load(Ordering::Acquire);
    if callback == 0 { return None; }
    let reclaim: fn() -> Option<u64> = unsafe { core::mem::transmute(callback) };
    reclaim()
}

pub fn free_phys_page(page: u64) {
    if is_zero_page(page) { return; }
    let unused = with_pool(|pool| pool.release(page));
    if let Some(data) = unused {
        unsafe { dealloc(data, Layout::array::<u8>(REF_BLOCK_PAGES).unwrap()); }
    }
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
        view.free = &PUBLISHED_FREE;
        view
    })
}

/// Populate all refcount blocks before guest execution. Allocation and first
/// touches happen in kernel context; fault handlers only access resident bytes.
pub fn prepare_fault_metadata() {
    let pages = unsafe { (*pool_ptr()).pages };
    let blocks = pages.div_ceil(REF_BLOCK_PAGES);
    let bytes = blocks.checked_mul(REF_BLOCK_PAGES).expect("reference metadata overflow");
    let arena = unsafe { alloc_zeroed(Layout::array::<u8>(bytes).unwrap()) };
    assert!(!arena.is_null(), "cannot allocate resident frame references");
    for block in 0..blocks {
        assert!(unsafe { (*pool_ptr()).install_ref_block(block, arena.add(block * REF_BLOCK_PAGES)) });
    }
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

/// # Safety
/// Supply is resident and belongs to the calling CPU. No mutable supply borrow
/// survives allocation, so nested first-touch faults can use the existing reserve.
pub unsafe fn replenish_supply(supply: *mut arch_abi::page_supply::PageSupply) {
    if unsafe { (*supply).count } < arch_abi::page_supply::SUPPLY_CAPACITY {
        unsafe { (*supply).refills += 1; }
    }
    while unsafe { (*supply).count } < arch_abi::page_supply::SUPPLY_CAPACITY {
        let Some(page) = alloc_phys_page() else {
            assert!(unsafe { (*supply).count } >= arch_abi::page_supply::FAULT_PAGES,
                "physical memory exhausted refilling fault reserve");
            break;
        };
        // Reclaim may have released kernel mappings into this same reserve.
        if unsafe { (*supply).count } == arch_abi::page_supply::SUPPLY_CAPACITY {
            free_phys_page(page);
            break;
        }
        unsafe { (*supply).donate(page); }
    }
}
pub fn bootstrap_supply(refill_ip: usize) -> arch_abi::page_supply::PageBootstrap {
    let mut pages = [0; arch_abi::page_supply::FAULT_PAGES];
    for page in &mut pages { *page = alloc_phys_page().expect("out of AP fault reserve pages"); }
    arch_abi::page_supply::PageBootstrap { ownership: ownership(), pages, refill_ip }
}
