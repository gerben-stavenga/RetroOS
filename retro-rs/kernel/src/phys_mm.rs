//! Physical memory allocator
//!
//! Tracks physical page usage with reference counts.
//! - 0 = free
//! - 255 = reserved (never allocatable)
//! - 1-254 = reference count (for copy-on-write sharing)

use crate::paging2::PAGE_SIZE;
use crate::MMapEntry;

/// Check if a page is the zero page (always shared, never freed)
pub fn is_zero_page(page: u64) -> bool {
    page == crate::paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize)
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

/// Diagnostic counters for tracking leaks
static mut TOTAL_ALLOCS: u64 = 0;
static mut TOTAL_FREES: u64 = 0;  // ref reached 0
static mut TOTAL_DECREFS: u64 = 0;  // ref decremented but > 0

/// Initialize physical memory allocator from memory map
///
/// # Safety
/// Must be called once during kernel init with valid memory map.
pub fn init_phys_mm(mmap_entries: &[MMapEntry], mmap_count: usize, kernel_low: u64, kernel_high: u64) {
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
    }
}

/// Mark a range of pages as reserved
pub fn mark_reserved(low_page: u64, high_page: u64) {
    for page in low_page..high_page {
        if (page as usize) < MAX_PAGES {
            unsafe { PAGE_REFS[page as usize] = RESERVED; }
        }
    }
}

/// Mark a range of pages as used (reference count = 1)
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
                TOTAL_ALLOCS += 1;
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
pub fn free_phys_page(page: u64) -> bool {
    if is_zero_page(page) { return false; }
    if page as usize >= MAX_PAGES {
        return false;
    }

    unsafe {
        let count = PAGE_REFS[page as usize];
        if count == 0 || count == RESERVED {
            // Already free or reserved, bug
            return false;
        }

        PAGE_REFS[page as usize] = count - 1;
        if count - 1 == 0 {
            TOTAL_FREES += 1;
            true
        } else {
            TOTAL_DECREFS += 1;
            false
        }
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
pub fn is_shared(page: u64) -> bool {
    if page as usize >= MAX_PAGES {
        return false;
    }
    unsafe {
        let count = PAGE_REFS[page as usize];
        count > 1 && count != RESERVED
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

/// Print diagnostic counters and page ref distribution
pub fn dump_stats() {
    unsafe {
        let mut free = 0u32;
        let mut used1 = 0u32;
        let mut used2 = 0u32;
        let mut used3plus = 0u32;
        let mut reserved = 0u32;
        for i in 0..MAX_PAGES {
            match PAGE_REFS[i] {
                0 => free += 1,
                RESERVED => reserved += 1,
                1 => used1 += 1,
                2 => used2 += 1,
                _ => used3plus += 1,
            }
        }
        let ta = core::ptr::read_volatile(&raw const TOTAL_ALLOCS);
        let tf = core::ptr::read_volatile(&raw const TOTAL_FREES);
        let td = core::ptr::read_volatile(&raw const TOTAL_DECREFS);
        let hp = crate::heap::heap_pages();
        let (la, lf, lr) = crate::heap::large_stats();
        crate::println!("PHYS: alloc={} free={} decref={} | free={} r1={} r2={} r3+={} rsv={} heap={} lg={}/{}/{}",
            ta, tf, td,
            free, used1, used2, used3plus, reserved, hp, la, lf, lr);
    }
}
