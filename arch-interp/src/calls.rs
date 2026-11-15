//! Direct hosted implementations of the shared architecture operations.
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
    pub const SET_TLS_ENTRY: u64 = 0x117;
    #[allow(dead_code)]
    pub const HASH_PHYS_PAGE: u64 = 0x118;
    pub const SET_DEBUG_WATCH: u64 = 0x119;
    pub const ISA_UNMASK_IRQ: u64 = 0x11C;
}

/// Share the current user page tables into the caller-owned child root.
pub fn arch_user_fork(child_root: &mut RootPageTable) {
    crate::paging::space_fork(child_root);
}

/// Free all user pages in the current address space.
pub fn arch_user_clean() {
    crate::paging::space_clean();
    crate::engine::flush();
}

/// Free user pages in the current address space (arch CLEAN).
pub fn arch_free_user_pages() {
    arch_user_clean();
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

/// Re-arm a deferred-ack IRQ line. (M2 virtual device layer)
pub fn arch_isa_unmask_irq(line: u8) {
    unimplemented!("M2: virtual IRQ rearm")
}
