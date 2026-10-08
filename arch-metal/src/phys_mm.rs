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

/// Locate the kernel-owned ISA DMA buffers after the physical memory map is
/// initialized. Their storage is part of the kernel image at 1 MB, so GRUB
/// cannot fill the remaining low 16 MB with modules and starve Sound Blaster
/// DMA. Kernel pages were marked used by `init_phys_mm` already.
pub fn reserve_dma_regions() {
    unsafe {
        let bufs_va = core::ptr::addr_of!(DMA_BUFS_STORAGE) as usize;
        DMA_BUFS_BASE = kernel_dma_page(
            bufs_va,
            DMA_BUFS_PAGES,
            DMA_BUF_16BIT_PAGES,
        );
        // The normal kernel BSS mapping is write-back. The guest aliases
        // these physical pages uncached for coherent ISA DMA; remove the
        // unused BSS virtual mapping so the CPU never sees conflicting cache
        // types. The physical pages remain owned by the kernel image.
        if DMA_BUFS_BASE != 0 {
            unmap_dma_storage(bufs_va, DMA_BUFS_PAGES);
            debug_assert!((DMA_BUFS_BASE..DMA_BUFS_BASE + DMA_BUFS_PAGES)
                .all(|page| get_ref_count(page as u64) == 1));
        }
    }
}

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
/// Per-channel permanent ISA-DMA buffers. The 128 KB-aligned kernel BSS owns
/// them before Multiboot modules are loaded. Layout: four 128 KB buffers for
/// 16-bit channels, then four 64 KB buffers for 8-bit channels.
const DMA_BUF_8BIT_PAGES: usize = 0x1_0000 / PAGE_SIZE;   // 64 KB
const DMA_BUF_16BIT_PAGES: usize = 0x2_0000 / PAGE_SIZE;  // 128 KB
const DMA_BUFS_PAGES: usize = 4 * DMA_BUF_16BIT_PAGES + 4 * DMA_BUF_8BIT_PAGES;
#[repr(align(131072))]
#[allow(dead_code)] // Guest mappings and the 8237 access these bytes by physical address.
struct AlignedDmaBuffers([u8; DMA_BUFS_PAGES * PAGE_SIZE]);
static mut DMA_BUFS_STORAGE: AlignedDmaBuffers = AlignedDmaBuffers([0; DMA_BUFS_PAGES * PAGE_SIZE]);
/// First physical page of the per-channel buffer block (0 = unavailable).
static mut DMA_BUFS_BASE: usize = 0;

/// Physical page number of DMA channel `ch`'s permanent buffer (0 = none).
/// 16-bit channels (4-7) occupy the front of the block, 8-bit (0-3) after.
pub fn dma_channel_buf(ch: usize) -> u64 {
    let base = unsafe { DMA_BUFS_BASE };
    if base == 0 || ch >= 8 { return 0; }
    let off = if ch >= 4 {
        (ch - 4) * DMA_BUF_16BIT_PAGES
    } else {
        4 * DMA_BUF_16BIT_PAGES + ch * DMA_BUF_8BIT_PAGES
    };
    (base + off) as u64
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
