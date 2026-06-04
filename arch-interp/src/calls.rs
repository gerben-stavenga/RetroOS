//! The kernel-facing arch call surface — the calls the kernel makes *into* the
//! arch layer. On metal each is an `int 0x80` stub; here they are direct
//! functions over the software MMU / address spaces. Signatures match
//! `kernel/src/arch/calls.rs` exactly so the kernel is backend-blind.
//!
//! Milestone 1: the execution and memory-management calls are `unimplemented!()`
//! stubs (filled in M2–M4). The call-number constants are kept for surface
//! parity with the metal backend.
#![allow(unused_variables)]

use crate::machine::FxState;
use crate::space::RootPageTable;
use crate::vcpu::Vcpu;
use arch_abi::KernelEvent;

/// Arch call numbers — kept identical to the metal backend (`traps::arch_call`)
/// for surface parity. The interpreter dispatches by calling the functions
/// below directly, so these are not used as a wire protocol here.
pub mod arch_call {
    pub const EXECUTE: u64 = 0x100;
    pub const SWITCH_TO: u64 = 0x101;
    pub const FORK: u64 = 0x105;
    pub const CLEAN: u64 = 0x106;
    pub const SET_PAGE_FLAGS: u64 = 0x108;
    pub const MAP_LOW_MEM: u64 = 0x109;
    pub const COPY_PAGE_ENTRIES: u64 = 0x10C;
    pub const SWAP_PAGE_ENTRIES: u64 = 0x10E;
    pub const UNMAP_RANGE: u64 = 0x10F;
    pub const FREE_RANGE: u64 = 0x110;
    pub const LOAD_LDT: u64 = 0x115;
    pub const MAP_PHYS_RANGE: u64 = 0x116;
    pub const SET_TLS_ENTRY: u64 = 0x117;
    #[allow(dead_code)]
    pub const HASH_PHYS_PAGE: u64 = 0x118;
    pub const SET_DEBUG_WATCH: u64 = 0x119;
    pub const ALLOC_PHYS_CONTIG: u64 = 0x11A;
    pub const FREE_PHYS_CONTIG: u64 = 0x11B;
    pub const REARM_IRQ: u64 = 0x11C;
    pub const DMA_CHANNEL_BUF: u64 = 0x11D;
    pub const MAP_FRESH_RANGE: u64 = 0x11E;
}

/// Resume the current Vcpu on the software core and return the next event.
/// Runs `emu_start` in instruction-counted slices; hooks surface the event.
pub fn do_arch_execute() -> KernelEvent {
    crate::cpu::execute()
}

/// Switch threads: swap live state with the pointed-to state. (M2/M3)
pub fn arch_switch_to(vcpu: &mut Vcpu, hash_ptr: *mut u64, fx_ptr: *mut FxState) {
    unimplemented!("M3: address-space + register swap")
}

/// COW-fork the current address space, filling `child_root`. (M4)
pub fn arch_user_fork(child_root: &mut RootPageTable) {
    unimplemented!("M4: COW fork over the software MMU")
}

/// Free all user pages in the current address space. (M3)
pub fn arch_user_clean() {
    unimplemented!("M3: free user pages")
}

/// Free user pages in the current address space (arch CLEAN). (M3)
pub fn arch_free_user_pages() {
    unimplemented!("M3: free user pages")
}

/// Set page permissions (bit0=W, bit1=X) over a range. (M3)
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, executable: bool) {
    unimplemented!("M3: software MMU page flags")
}

/// Map the first 1MB user-accessible for VM86. (M3)
pub fn arch_map_low_mem() {
    unimplemented!("M3: low-memory mapping")
}

/// Copy page-table entries src→dst. (M3)
pub fn arch_copy_page_entries(src_vpage: usize, dst_vpage: usize, count: usize) {
    unimplemented!("M3: software MMU copy entries")
}

/// Swap page-table entries a↔b. (M3)
pub fn arch_swap_page_entries(a_vpage: usize, b_vpage: usize, count: usize) {
    unimplemented!("M3: software MMU swap entries")
}

/// Clear entries to absent (enables demand paging on next access). (M3)
pub fn arch_unmap_range(base_page: usize, count: usize) {
    unimplemented!("M3: software MMU unmap range")
}

/// Free physical pages and restore identity-mapped read-only entries. (M3)
pub fn arch_free_range(base_page: usize, count: usize) {
    unimplemented!("M3: software MMU free range")
}

/// Replace `count` user pages with fresh anonymous RW frames. (M3)
pub fn arch_map_fresh_range(vpage: usize, count: usize) {
    unimplemented!("M3: software MMU fresh range")
}

/// Map a range of physical pages into user virtual space. (M3)
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
    unimplemented!("M3: software MMU phys mapping")
}

/// Load LDT base+limit. (M4)
pub fn arch_load_ldt(base: u32, limit: u32) {
    unimplemented!("M4: software LDT")
}

/// Set a per-thread TLS GDT entry; returns the GDT index or -1. (M4)
pub fn arch_set_tls_entry(index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
    unimplemented!("M4: software TLS entry")
}

/// Allocate ISA-DMA-safe physically-contiguous pages; returns start page or 0.
pub fn arch_alloc_phys_contig(num_pages: usize, boundary_log2: u32) -> u64 {
    unimplemented!("interp DMA-contiguous allocation (not needed for flat-PM ELF)")
}

/// Free a contiguous run from `arch_alloc_phys_contig`.
pub fn arch_free_phys_contig(start_page: u64, num_pages: usize) {
    unimplemented!("interp DMA-contiguous free")
}

/// Physical page of DMA channel `ch`'s permanent ISA-DMA buffer (0 = none).
pub fn arch_dma_channel_buf(ch: usize) -> u64 {
    unimplemented!("interp DMA channel buffer")
}

/// Re-arm a deferred-ack IRQ line. (M2 virtual device layer)
pub fn arch_rearm_irq(line: u8) {
    unimplemented!("M2: virtual IRQ rearm")
}
