//! Address-space adapter for the interpreter backend.
//!
//! Historically this module *was* the memory model: each guest space was its own
//! `mmap`-reserved host arena, demand-committed a page at a time, with unicorn
//! running PG=0 (guest linear = physical). That made a guest VA a contiguous
//! host pointer, but mapped one unicorn region per 4 KiB page — O(n²) flatview
//! churn for large working sets (Doom).
//!
//! The model now lives in `paging`: one guest-physical region (the `phys`
//! memfd), real x86 page tables in that RAM, and unicorn running CR0.PG=1 so its
//! softmmu walks the tables. This module is a thin adapter keeping the call
//! names the kernel-facing `calls.rs` and `cpu.rs` already use, each forwarding
//! to the corresponding `paging::space_*` operation on the active space.

use crate::paging;

/// Create the boot address space (id 0) and make it active.
pub fn init() {
    paging::space_init();
}

/// Create a fresh empty address space; returns its id.
pub fn new_space() -> u32 {
    paging::space_new()
}

/// Destroy a space entirely (reaped thread). id 0 (boot) is permanent.
pub fn destroy_space(id: u32) {
    paging::space_destroy(id);
}

/// Make `id` the active space.
pub fn switch_to(id: u32) {
    paging::space_switch(id);
}

/// Id of the active space.
pub fn active_id() -> u32 {
    paging::active_id()
}

/// Replace `count` pages at `vpage` with fresh zeroed RW frames.
pub fn map_fresh(vpage: usize, count: usize) {
    paging::space_map_fresh(vpage, count);
}

/// Set writability over a range of present pages.
pub fn set_flags(vpage: usize, count: usize, writable: bool) {
    paging::space_set_writable(vpage, count, writable);
}

/// Clear entries to absent (next access demand-faults).
pub fn unmap(vpage: usize, count: usize) {
    paging::space_unmap(vpage, count);
}

/// Free `count` pages (drop PTEs and release the frames).
pub fn free(vpage: usize, count: usize) {
    paging::space_free(vpage, count);
}

/// Copy page-table entries src→dst (fresh-frame content copy).
pub fn copy_entries(src: usize, dst: usize, count: usize) {
    paging::space_copy_entries(src, dst, count);
}

/// Swap page-table entries a↔b (PTE swap).
pub fn swap_entries(a: usize, b: usize, count: usize) {
    paging::space_swap_entries(a, b, count);
}

/// Alias `count` guest pages at `vpage` onto physical frames at `ppage`.
pub fn map_phys(vpage: usize, count: usize, ppage: u64) {
    paging::space_map_phys(vpage, count, ppage, true);
}

/// Map the first 1 MB user-accessible (VM86/DOS low memory).
pub fn map_low_mem() {
    paging::space_map_low_mem();
}

/// Free every user page in the active space (arch CLEAN).
pub fn clean() {
    paging::space_clean();
}

/// Fork the active-from `src` space into a fresh one; returns the new id.
pub fn fork_copy(src: u32) -> u32 {
    paging::space_fork(src)
}
