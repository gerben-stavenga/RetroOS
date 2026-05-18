//! Physical memory allocator
//!
//! Tracks physical page usage with reference counts.
//! - 0 = free
//! - 255 = reserved (never allocatable)
//! - 1-254 = reference count (for copy-on-write sharing)

use crate::arch::paging2::PAGE_SIZE;
use crate::MultibootMmapEntry;

/// Check if a page is the zero page (always shared, never freed)
pub fn is_zero_page(page: u64) -> bool {
    page == crate::arch::paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize)
}

/// Maximum number of physical pages we track (64K pages = 256MB)
/// Limited to keep kernel under 1MB for now
const MAX_PAGES: usize = 64 * 1024;

/// Reserved page marker (never allocatable)
const RESERVED: u8 = 255;

/// Reference counts for each physical page
static mut PAGE_REFS: [u8; MAX_PAGES] = [0; MAX_PAGES];

/// Next page to check when allocating (simple optimization)
static mut NEXT_FREE: usize = 0;

/// Initialize physical memory allocator from memory map
///
/// # Safety
/// Must be called once during kernel init with valid memory map.
pub fn init_phys_mm(mmap_entries: &[MultibootMmapEntry], mmap_count: usize, kernel_low: u64, kernel_high: u64) {
    unsafe {
        // Mark all pages as reserved initially
        for i in 0..MAX_PAGES {
            PAGE_REFS[i] = RESERVED;
        }

        // Mark available regions from memory map
        for i in 0..mmap_count {
            if i >= mmap_entries.len() {
                break;
            }
            let entry = &mmap_entries[i];

            // Type 1 = available memory
            if entry.typ != 1 {
                continue;
            }

            let start_page = (entry.base as u64 + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
            let end_page = ((entry.base + entry.length) as u64) / PAGE_SIZE as u64;

            for page in start_page..end_page {
                if (page as usize) < MAX_PAGES {
                    PAGE_REFS[page as usize] = 0; // Free
                }
            }
        }

        // Mark first 1MB as reserved (BIOS, video memory, etc)
        for i in 0..256 {
            PAGE_REFS[i] = RESERVED;
        }

        // Mark kernel pages as used
        for page in kernel_low..kernel_high {
            if (page as usize) < MAX_PAGES {
                PAGE_REFS[page as usize] = 1;
            }
        }

        // Start searching after kernel
        NEXT_FREE = kernel_high as usize;

        // Reserve a low-memory ISA-DMA pool. ISA DMA needs a physically
        // contiguous, < 16 MB, boundary-non-crossing buffer; the general
        // allocator walks upward and fragments the whole < 16 MB region
        // before a game ever plays sound. Carve a fixed 64 KB-aligned,
        // 64 KB pool now and mark it RESERVED so `alloc_phys_page` skips
        // it. 64 KB-aligned + ≤ 64 KB ⇒ no 8-bit (64 KB) or 16-bit
        // (128 KB) DMA-boundary crossing by construction. One SB DMA
        // buffer is live at a time (foreground thread owns the card).
        let mut p = 256usize;
        while p + DMA_POOL_PAGES <= DMA_MAX_PAGE.min(MAX_PAGES) {
            if p % DMA_POOL_PAGES != 0 { p += 1; continue; } // 64 KB align
            if (p..p + DMA_POOL_PAGES).all(|i| PAGE_REFS[i] == 0) {
                for i in p..p + DMA_POOL_PAGES { PAGE_REFS[i] = RESERVED; }
                DMA_POOL_START = p;
                break;
            }
            p += DMA_POOL_PAGES;
        }
    }
}

/// Largest physical page usable for ISA DMA (addresses are 24-bit, < 16 MB).
const DMA_MAX_PAGE: usize = 0x100_0000 / PAGE_SIZE;
/// Reserved ISA-DMA pool size: 64 KB = 16 pages, 64 KB-aligned.
const DMA_POOL_PAGES: usize = 0x1_0000 / PAGE_SIZE;
/// First page of the reserved DMA pool (0 = not reserved / unavailable).
static mut DMA_POOL_START: usize = 0;
/// True while the pool is handed out (single live SB DMA buffer).
static mut DMA_POOL_BUSY: bool = false;

/// Mark a range of pages as reserved
#[allow(dead_code)]
pub fn mark_reserved(low_page: u64, high_page: u64) {
    for page in low_page..high_page {
        if (page as usize) < MAX_PAGES {
            unsafe { PAGE_REFS[page as usize] = RESERVED; }
        }
    }
}

/// Mark a range of pages as used (reference count = 1)
#[allow(dead_code)]
pub fn mark_used(low_page: u64, high_page: u64) {
    for page in low_page..high_page {
        if (page as usize) < MAX_PAGES {
            unsafe { PAGE_REFS[page as usize] = 1; }
        }
    }
}

/// Allocate a physical page
/// Returns page number or None if out of memory
pub fn alloc_phys_page() -> Option<u64> {
    unsafe {
        let start = NEXT_FREE;
        let mut page = start;

        loop {
            if page >= MAX_PAGES {
                page = 256; // Skip first 1MB
            }

            if PAGE_REFS[page] == 0 {
                PAGE_REFS[page] = 1;
                NEXT_FREE = page + 1;
                return Some(page as u64);
            }

            page += 1;
            if page == start {
                // Wrapped around, no free pages
                return None;
            }
        }
    }
}

/// Free a physical page (decrement reference count)
/// Returns true if the page is now free
pub fn free_phys_page(page: u64) {
    assert!((page as usize) < MAX_PAGES , "invalid page to free: {:#x}", page);

    if is_zero_page(page) { return; }
    unsafe {
        let count = PAGE_REFS[page as usize];
        assert!(count > 0, "double free or invalid page: {:#x}", page);
        if count == RESERVED {
            return;
        }
        let count = count - 1;
        PAGE_REFS[page as usize] = count;
    }
}

/// Increment shared count for a page (for copy-on-write sharing)
/// Returns true if successful
pub fn inc_shared_count(page: u64) -> bool {
    if is_zero_page(page) { return true; }
    if page as usize >= MAX_PAGES {
        return false;
    }

    unsafe {
        let count = PAGE_REFS[page as usize];
        if count == 0 || count == RESERVED {
            return false;
        }
        if count + 1 >= RESERVED {
            panic!("refcount overflow: page {:#x} count {}", page, count);
        }

        PAGE_REFS[page as usize] = count + 1;
        true
    }
}

/// Get the reference count for a page
pub fn get_ref_count(page: u64) -> u8 {
    if is_zero_page(page) { return RESERVED; }
    if page as usize >= MAX_PAGES {
        return RESERVED;
    }
    unsafe { PAGE_REFS[page as usize] }
}

/// Check if a page is shared (ref count > 1)
#[allow(dead_code)]
pub fn is_shared(page: u64) -> bool {
    if page as usize >= MAX_PAGES {
        return false;
    }
    unsafe {
        let count = PAGE_REFS[page as usize];
        count > 1 && count != RESERVED
    }
}

/// Hand out the reserved ISA-DMA pool for a buffer of `num_pages`
/// (≤ `DMA_POOL_PAGES`). Returns the pool's start page, or None if the
/// pool is unavailable, busy, or the buffer is too large. `boundary_log2`
/// is satisfied by construction: the pool is 64 KB-aligned and ≤ 64 KB,
/// so no 8-bit (64 KB) or 16-bit (128 KB) boundary is ever crossed.
///
/// Release with `free_phys_contig`. Pages are NOT zeroed — the DMA-remap
/// path copies the guest buffer in.
pub fn alloc_phys_contig(num_pages: usize, _boundary_log2: u32) -> Option<u64> {
    unsafe {
        if DMA_POOL_START == 0 || DMA_POOL_BUSY
            || num_pages == 0 || num_pages > DMA_POOL_PAGES {
            return None;
        }
        DMA_POOL_BUSY = true;
        Some(DMA_POOL_START as u64)
    }
}

/// Release the DMA pool (back to available, not to the general allocator —
/// the pool pages stay RESERVED for the next SB buffer).
pub fn free_phys_contig(start_page: u64, _num_pages: usize) {
    unsafe {
        if start_page as usize == DMA_POOL_START {
            DMA_POOL_BUSY = false;
        }
    }
}

/// Get free page count (for debugging)
pub fn free_page_count() -> usize {
    let mut count = 0;
    unsafe {
        for i in 0..MAX_PAGES {
            if PAGE_REFS[i] == 0 {
                count += 1;
            }
        }
    }
    count
}


