//! Physical memory allocator
//!
//! Tracks physical page usage with reference counts.
//! - 0 = free
//! - 255 = reserved (never allocatable)
//! - 1-254 = reference count (for copy-on-write sharing)

use crate::paging2::PAGE_SIZE;
use crate::MMapEntry;

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
pub fn init_phys_mm(mmap_entries: &[MMapEntry], mmap_count: usize, kernel_low: usize, kernel_high: usize) {
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

            let start_page = (entry.base as usize + PAGE_SIZE - 1) / PAGE_SIZE;
            let end_page = ((entry.base + entry.length) as usize) / PAGE_SIZE;

            for page in start_page..end_page {
                if page < MAX_PAGES {
                    PAGE_REFS[page] = 0; // Free
                }
            }
        }

        // Mark first 1MB as reserved (BIOS, video memory, etc)
        for i in 0..256 {
            PAGE_REFS[i] = RESERVED;
        }

        // Mark kernel pages as used
        for page in kernel_low..kernel_high {
            if page < MAX_PAGES {
                PAGE_REFS[page] = 1;
            }
        }

        // Start searching after kernel
        NEXT_FREE = kernel_high;
    }
}

/// Mark a range of pages as reserved
pub fn mark_reserved(low_page: usize, high_page: usize) {
    for page in low_page..high_page {
        if page < MAX_PAGES {
            unsafe { PAGE_REFS[page] = RESERVED; }
        }
    }
}

/// Mark a range of pages as used (reference count = 1)
pub fn mark_used(low_page: usize, high_page: usize) {
    for page in low_page..high_page {
        if page < MAX_PAGES {
            unsafe { PAGE_REFS[page] = 1; }
        }
    }
}

/// Allocate a physical page
/// Returns page number or None if out of memory
pub fn alloc_phys_page() -> Option<usize> {
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
                return Some(page);
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
pub fn free_phys_page(page: usize) -> bool {
    if page >= MAX_PAGES {
        return false;
    }

    unsafe {
        let count = PAGE_REFS[page];
        if count == 0 || count == RESERVED {
            // Already free or reserved, bug
            return false;
        }

        PAGE_REFS[page] = count - 1;
        count - 1 == 0
    }
}

/// Increment shared count for a page (for copy-on-write sharing)
/// Returns true if successful
pub fn inc_shared_count(page: usize) -> bool {
    if page >= MAX_PAGES {
        return false;
    }

    unsafe {
        let count = PAGE_REFS[page];
        if count == 0 || count >= RESERVED - 1 {
            // Free, reserved, or at max count
            return false;
        }

        PAGE_REFS[page] = count + 1;
        true
    }
}

/// Get the reference count for a page
pub fn get_ref_count(page: usize) -> u8 {
    if page >= MAX_PAGES {
        return RESERVED;
    }
    unsafe { PAGE_REFS[page] }
}

/// Check if a page is shared (ref count > 1)
pub fn is_shared(page: usize) -> bool {
    if page >= MAX_PAGES {
        return false;
    }
    unsafe {
        let count = PAGE_REFS[page];
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
