//! The kernel-facing arch call surface — the calls the kernel makes *into* the
//! arch layer. On metal each is an `int 0x80` stub; here they are direct
//! functions over the software MMU / address spaces. Signatures match
//! `kernel/src/arch/calls.rs` exactly so the kernel is backend-blind.
//!
//! Milestone 1: the execution and memory-management calls are `unimplemented!()`
//! stubs (filled in M2–M4). The call-number constants are kept for surface
//! parity with the metal backend.
#![allow(unused_variables)]

use crate::space::RootPageTable;

/// Arch call numbers — kept identical to the metal backend (`traps::arch_call`)
/// for surface parity. The interpreter dispatches by calling the functions
/// below directly, so these are not used as a wire protocol here.
pub mod arch_call {
    pub const EXECUTE: u64 = 0x100;
    pub const ACTIVATE: u64 = 0x101;
    pub const FORK: u64 = 0x105;
    pub const CLEAN: u64 = 0x106;
    pub const LOAD_LDT: u64 = 0x115;
    pub const MAP_KERNEL_PHYSICAL: u64 = 0x116;
    pub const SET_TLS_ENTRY: u64 = 0x117;
    #[allow(dead_code)]
    pub const HASH_PHYS_PAGE: u64 = 0x118;
    pub const SET_DEBUG_WATCH: u64 = 0x119;
    pub const ALLOC_PHYS_CONTIG: u64 = 0x11A;
    pub const FREE_PHYS_CONTIG: u64 = 0x11B;
    pub const ISA_UNMASK_IRQ: u64 = 0x11C;
    pub const DMA_CHANNEL_BUF: u64 = 0x11D;
}

/// Fork the current address space into `child_root`. M4 will make this COW;
/// for now it is a full copy (correct, just not lazy).
pub fn arch_user_fork(child_root: &mut RootPageTable) {
    let parent = crate::mmu::active_id();
    *child_root = RootPageTable(crate::mmu::fork_copy(parent));
}

/// Free all user pages in the current address space.
pub fn arch_user_clean() {
    crate::mmu::clean();
    crate::engine::flush();
}

/// Free user pages in the current address space (arch CLEAN).
pub fn arch_free_user_pages() {
    arch_user_clean();
}

/// Install a privileged physical driver window.
pub fn arch_map_kernel_physical(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
    crate::paging::map_kernel_physical(vpage_start, num_pages, ppage_start, flags);
}

/// Load the LDT base+limit (the active descriptor table for PM selector
/// resolution). Stored for `monitor::seg_base`; only consulted once a guest
/// enters protected mode (DPMI). Real-mode DOS never reads it.
pub fn arch_load_ldt(ldt: &[u64]) {
    crate::desc::load_ldt(ldt);
}

/// Set a per-thread TLS GDT entry; returns the GDT index. Stored for PM segment
/// resolution; `index < 0` auto-allocates the first free TLS slot.
pub fn arch_set_tls_entry(index: i32, base: u32, limit: u32, _limit_in_pages: bool) -> i32 {
    crate::desc::set_tls_entry(index, base, limit)
}

/// Allocate physically contiguous DMA pages; returns start page or 0.
pub fn arch_alloc_phys_contig(num_pages: usize) -> u64 {
    // The phys backing is a sparse memfd with a bump allocator.
    crate::phys::alloc_frames(num_pages)
}

/// Free a contiguous run from `arch_alloc_phys_contig`.
pub fn arch_free_phys_contig(start_page: u64, num_pages: usize) {
    crate::phys::free_frames(start_page, num_pages);
}

/// Physical page of DMA channel `ch`'s permanent ISA-DMA buffer (0 = none).
pub fn arch_dma_channel_buf(_ch: usize) -> u64 {
    // Hosted execution has no physical ISA DMA pool. Return the Arch
    // contract's "unavailable" value; inline mixing reads active guest RAM.
    0
}

/// Re-arm a deferred-ack IRQ line. (M2 virtual device layer)
pub fn arch_isa_unmask_irq(line: u8) {
    unimplemented!("M2: virtual IRQ rearm")
}
