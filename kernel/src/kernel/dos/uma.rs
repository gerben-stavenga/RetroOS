//! Upper Memory Area (UMA) page scan and Upper Memory Block (UMB) allocator.
//!
//! Pages 0xC0..0xEF (192KB) sit between conventional memory and ROM. After
//! `scan_uma()` we know which are free; the EMS submodule claims a 64KB run
//! for the page frame, the rest are available for UMB allocation by XMS.

use crate::dbg_println;

/// UMA covers pages 0xC0-0xEF (192KB). Pages 0xF0-0xFF are always BIOS ROM.
const UMA_BASE: usize = 0xC0;
const UMA_END: usize = 0xF0;
const UMA_PAGES: usize = UMA_END - UMA_BASE; // 48

/// Bitmap of free pages in UMA (bit i = page UMA_BASE+i). 1=free, 0=ROM/reserved.
/// Set by scan_uma(), then EMS claims 16 pages, rest available for UMB.
static mut UMA_FREE: u64 = 0;

/// Bitmap of UMB-allocated pages (subset of UMA_FREE). 1=allocated by UMB, 0=free.
static mut UMB_ALLOC: u64 = 0;

/// Bitmap of pages reserved for EMS (16 pages for 64KB page frame).
#[allow(dead_code)]
static mut EMS_PAGES: u64 = 0;

/// EMS page frame base page (set by scan_uma); read by `ems` submodule.
pub(super) static mut EMS_BASE_PAGE: usize = 0xD0;

/// Scan UMA to find free pages. A page is "free" if all bytes are 0x00 or 0xFF.
pub(super) fn scan_uma() {
    let mut free: u64 = 0;
    for i in 0..UMA_PAGES {
        let base = ((UMA_BASE + i) * 0x1000) as *const u8;
        let first = unsafe { *base };
        let mut uniform = true;
        for j in 1..0x1000 {
            if unsafe { *base.add(j) } != first { uniform = false; break; }
        }
        if uniform && (first == 0x00 || first == 0xFF) {
            free |= 1 << i;
        }
    }
    unsafe { UMA_FREE = free; }

    // Find 16 contiguous free pages for the EMS page frame (64KB).
    // Prefer 0xD000 (standard EMS frame address).
    if let Some(off) = find_contiguous_run(free, 16, 0xD0 - UMA_BASE) {
        unsafe { EMS_BASE_PAGE = UMA_BASE + off; }
        // Reserve EMS frame pages from UMB allocation
        let mask = ((1u64 << 16) - 1) << off;
        unsafe { UMA_FREE &= !mask; }
    }

    // Log results
    let umb_free = unsafe { UMA_FREE };
    let ems_base = unsafe { EMS_BASE_PAGE };
    let mut umb_count = 0u32;
    let mut t = umb_free;
    while t != 0 { umb_count += 1; t &= t - 1; }
    dbg_println!("UMA: EMS frame at {:05X}, UMB {}KB free", ems_base * 0x1000, umb_count * 4);
}

/// Find `count` contiguous set bits in `bitmap`, preferring `hint` offset.
fn find_contiguous_run(bitmap: u64, count: usize, hint: usize) -> Option<usize> {
    // Try starting at hint first
    if hint + count <= UMA_PAGES {
        let mask = ((1u64 << count) - 1) << hint;
        if bitmap & mask == mask { return Some(hint); }
    }
    // Scan from start
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if bitmap & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= count { return Some(run_start); }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Get UMB-available bitmap (free pages minus EMS minus already allocated)
fn umb_avail() -> u64 {
    unsafe { UMA_FREE & !UMB_ALLOC }
}

/// Allocate a UMB of at least `paragraphs` size (1 paragraph = 16 bytes).
/// Returns (segment, paragraphs_allocated) or None.
pub(super) fn umb_alloc(paragraphs: u16) -> Option<(u16, u16)> {
    let pages_needed = ((paragraphs as usize) * 16 + 0xFFF) / 0x1000;
    if pages_needed == 0 { return None; }

    let avail = umb_avail();
    // First-fit contiguous run
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= pages_needed {
                let mut alloc_mask = 0u64;
                for j in run_start..run_start + pages_needed {
                    alloc_mask |= 1 << j;
                }
                unsafe { UMB_ALLOC |= alloc_mask; }
                let base_page = UMA_BASE + run_start;
                crate::kernel::startup::arch_unmap_range(base_page, pages_needed);
                let seg = (base_page as u16) * 0x100; // page to segment
                let paras = (pages_needed as u16) * 0x100;
                return Some((seg, paras));
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Free a UMB by segment address.
pub(super) fn umb_free(segment: u16) -> bool {
    let page = (segment / 0x100) as usize;
    if page < UMA_BASE || page >= UMA_END { return false; }
    let offset = page - UMA_BASE;

    let alloc = unsafe { UMB_ALLOC };
    if alloc & (1 << offset) == 0 { return false; }

    // Free contiguous run starting at offset
    let mut mask = 0u64;
    let mut i = offset;
    while i < UMA_PAGES && alloc & (1 << i) != 0 {
        mask |= 1 << i;
        i += 1;
    }
    let count = (i - offset) as usize;
    unsafe { UMB_ALLOC &= !mask; }
    crate::kernel::startup::arch_free_range(page, count);
    true
}

/// Largest free UMB in paragraphs.
pub(super) fn umb_largest() -> u16 {
    let avail = umb_avail();
    let mut largest = 0usize;
    let mut run = 0usize;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            run += 1;
            if run > largest { largest = run; }
        } else {
            run = 0;
        }
    }
    (largest as u16) * 0x100
}
