//! Physical RAM allocator: a one-bit RAM bitmap and sparse shared refcounts.
use crate::paging2::PAGE_SIZE;
use crate::MultibootMmapEntry;
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

pub fn is_zero_page(page: u64) -> bool {
    page == crate::paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize)
}

fn physical_page_limit() -> u64 {
    if crate::paging2::cpu_mode() == crate::paging2::CpuMode::Legacy {
        return (1u64 << 32) / PAGE_SIZE as u64;
    }
    let (max, _, _, _) = crate::x86::cpuid(0x8000_0000);
    let bits = if max >= 0x8000_0008 {
        crate::x86::cpuid(0x8000_0008).0 & 255
    } else { 36 };
    (1u64 << bits.clamp(32, 52)) / PAGE_SIZE as u64
}

/// Track whole usable pages; overlapping firmware reservations take precedence.
pub fn init_phys_mm(mmap_entries: &[MultibootMmapEntry], mmap_count: usize, kernel_low: u64, kernel_high: u64) {
    let limit = physical_page_limit();
    let entries = &mmap_entries[..mmap_count.min(mmap_entries.len())];
    unsafe {
        let pool = &mut *pool_ptr();
        *pool = Pool::new();
        KERNEL_RANGE = (kernel_low, kernel_high);
        for entry in entries {
            if entry.typ != 1 { continue; }
            let first = entry.base.div_ceil(PAGE_SIZE as u64).min(limit);
            let end = (entry.base.saturating_add(entry.length) / PAGE_SIZE as u64).min(limit);
            pool.include(first, end);
        }
        for entry in entries {
            if entry.typ == 1 { continue; }
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
            pool.exclude(low_page, high_page);
            reset_bootstrap(pool);
        } else { panic!("boot reservation after physical allocation started"); }
    }
}

#[allow(dead_code)]
pub fn mark_used(low_page: u64, high_page: u64) {
    unsafe { (*pool_ptr()).mark(low_page, high_page); }
}

pub fn alloc_phys_page() -> Option<u64> { unsafe { (*pool_ptr()).allocate() } }

pub fn free_phys_page(page: u64) {
    if is_zero_page(page) { return; }
    let unused = unsafe { (*pool_ptr()).release(page) };
    if let Some(data) = unused {
        unsafe { dealloc(data, Layout::array::<u8>(REF_BLOCK_PAGES).unwrap()); }
    }
}

pub fn inc_shared_count(page: u64) -> bool {
    if is_zero_page(page) { return true; }
    let missing = unsafe { (*pool_ptr()).missing_ref_block(page) };
    if let Some(block) = missing {
        let data = unsafe { alloc_zeroed(Layout::array::<u8>(REF_BLOCK_PAGES).unwrap()) };
        assert!(!data.is_null(), "cannot allocate shared physical refcounts");
        // Allocation can reenter the pool. A nested retain may have installed
        // this block in the meantime; keep its counts and discard ours.
        if !unsafe { (*pool_ptr()).install_ref_block(block, data) } {
            unsafe { dealloc(data, Layout::array::<u8>(REF_BLOCK_PAGES).unwrap()); }
        }
    }
    unsafe { (*pool_ptr()).retain(page) }
}

pub fn get_ref_count(page: u64) -> u8 {
    if is_zero_page(page) { return 255; }
    unsafe { (*pool_ptr()).refs(page) }
}

#[allow(dead_code)]
pub fn is_shared(page: u64) -> bool { matches!(get_ref_count(page), 2..=254) }

fn unmap_dma_storage(va: usize, pages: usize) {
    for page in 0..pages {
        crate::paging2::unmap_kernel_page(va + page * PAGE_SIZE);
    }
}

fn kernel_dma_page(va: usize, pages: usize, alignment_pages: usize) -> usize {
    let Some(phys) = va.checked_sub(crate::paging2::KERNEL_BASE)
        .and_then(|offset| offset.checked_add(crate::paging2::KERNEL_PHYS)) else {
            return 0;
        };
    let page = phys / PAGE_SIZE;
    if phys % PAGE_SIZE != 0
        || !page.is_multiple_of(alignment_pages)
        || page + pages > DMA_MAX_PAGE
    {
        return 0;
    }
    page
}

/// Largest physical page usable for ISA DMA (addresses are 24-bit, < 16 MB).
const DMA_MAX_PAGE: usize = 0x100_0000 / PAGE_SIZE;
// Physical pages of lazily allocated channel buffers. usize::MAX serializes
// first allocation; trap entry has IRQs disabled, so a same-CPU interrupt
// cannot reenter while its slot is being initialized.
use core::sync::atomic::{AtomicUsize, Ordering};
static DMA_CHANNELS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

/// Physical page of a channel's permanent low-memory buffer (0 if unavailable).
/// AP stack/TLS reservations must be finished first. Allocate only channels
/// actually requested; the entire shared pool remains loader-reserved.
pub fn dma_channel_buf(ch: usize) -> u64 {
    let Some(slot) = DMA_CHANNELS.get(ch) else { return 0; };
    loop {
        let page = slot.load(Ordering::Acquire);
        if page == usize::MAX { core::hint::spin_loop(); continue; }
        if page != 0 { return page as u64; }
        if slot.compare_exchange(0, usize::MAX, Ordering::Acquire, Ordering::Relaxed).is_ok() { break; }
    }
    let bytes = if ch >= 4 { 128 * 1024 } else { 64 * 1024 };
    let Ok(storage) = crate::boot_mem::allocate_permanent(Layout::from_size_align(bytes, bytes).unwrap()) else {
        slot.store(0, Ordering::Release);
        return 0;
    };
    let page = kernel_dma_page(storage as usize, bytes / PAGE_SIZE, bytes / PAGE_SIZE);
    assert_ne!(page, 0, "boot pool violates ISA DMA address constraints");
    // The driver maps these frames uncached. Remove the ordinary cached alias;
    // physical ownership stays with the pool, already reserved as kernel BSS.
    unmap_dma_storage(storage as usize, bytes / PAGE_SIZE);
    debug_assert!((page..page + bytes / PAGE_SIZE).all(|p| get_ref_count(p as u64) == 1));
    slot.store(page, Ordering::Release);
    page as u64
}

/// Allocate physically contiguous DMA memory from the general pool.
///
/// Release with `free_phys_contig`. Pages are not zeroed.
pub fn alloc_phys_contig(num_pages: usize) -> Option<u64> {
    alloc_contig(num_pages)
}

/// Return a contiguous allocation to RAM.
pub fn free_phys_contig(start_page: u64, num_pages: usize) {
    unsafe { (*pool_ptr()).free_contiguous(start_page, num_pages); }
}

/// PCI allocations remain below 4 GiB for devices with 32-bit DMA addresses.
/// This constraint does not apply to the general physical page allocator.
pub fn alloc_contig(num_pages: usize) -> Option<u64> {
    unsafe { (*pool_ptr()).allocate_contiguous(num_pages, (1u64 << 32) / PAGE_SIZE as u64) }
}
pub fn free_page_count() -> usize { unsafe { (*pool_ptr()).free_pages() } }
pub fn total_page_count() -> usize { unsafe { (*pool_ptr()).managed_pages() } }
