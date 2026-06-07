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

/// Switch threads: swap live state (`REGS`) with the pointed-to state, and make
/// the incoming address space active. On entry `vcpu` holds the incoming state;
/// on exit it holds the saved outgoing state (matching the metal contract).
pub fn arch_switch_to(vcpu: &mut Vcpu, _hash_ptr: *mut u64, _fx_ptr: *mut FxState) {
    let live = unsafe { &mut *(&raw mut crate::vcpu::REGS) };
    core::mem::swap(&mut live.regs, &mut vcpu.regs);
    core::mem::swap(&mut live.space, &mut vcpu.space);
    // `live` now holds the incoming context — activate its address space and
    // drop the outgoing space's lazy Unicorn mappings.
    crate::cpu::flush_uc();
    crate::mmu::switch_to(live.space.0);
    // FPU state is the software core's; cross-switch FPU preservation is M4.
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
    crate::cpu::flush_uc();
}

/// Free user pages in the current address space (arch CLEAN).
pub fn arch_free_user_pages() {
    arch_user_clean();
}

/// Set page permissions (bit0=W, bit1=X) over a range.
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, _executable: bool) {
    crate::mmu::set_flags(start_vpage, count, writable);
    crate::cpu::invalidate_uc(start_vpage, count);
}

/// Map the first 1MB user-accessible.
pub fn arch_map_low_mem() {
    crate::mmu::map_low_mem();
    install_bios_stubs();
    crate::cpu::invalidate_uc(0, 0x100);
}

/// BIOS firmware the interpreter must supply. On real hardware (and metal) the
/// PC BIOS ROM owns these IVT vectors; the interpreter has no ROM, so without a
/// handler a guest `int 11h` (or a reflected IRQ0 `int 8`) lands on a null IVT
/// entry and the guest then executes the zeroed IVT as code, scrambling itself.
///
/// The substantive handlers (INT 08/10/11/16/1A + the BDA) are written in 16-bit
/// C (`bios/bios.c`, built by our own Turbo C) and loaded by `crate::bios`. Here
/// we add only a generic `iret` for the handful of BIOS vectors we don't model.
fn install_bios_stubs() {
    let m = crate::vcpu::mem();
    const SEG: u16 = 0xF000;
    // Generic `iret` at F000:0010 — for BIOS vectors we don't model, so a guest
    // call returns harmlessly instead of executing the null IVT.
    m.write::<u8>(0xF0010, 0xCF);
    for v in [0x12u8, 0x14, 0x15, 0x17, 0x1B, 0x1C] {
        m.write::<u16>(v as usize * 4, 0x0010);
        m.write::<u16>(v as usize * 4 + 2, SEG);
    }
    // The real handlers (in C) + the BDA seed.
    crate::bios::install();
}

/// Copy page-table entries src→dst.
pub fn arch_copy_page_entries(src_vpage: usize, dst_vpage: usize, count: usize) {
    crate::mmu::copy_entries(src_vpage, dst_vpage, count);
    crate::cpu::invalidate_uc(dst_vpage, count);
}

/// Swap page-table entries a↔b.
pub fn arch_swap_page_entries(a_vpage: usize, b_vpage: usize, count: usize) {
    crate::mmu::swap_entries(a_vpage, b_vpage, count);
    crate::cpu::invalidate_uc(a_vpage, count);
    crate::cpu::invalidate_uc(b_vpage, count);
}

/// Clear entries to absent (enables demand paging on next access).
pub fn arch_unmap_range(base_page: usize, count: usize) {
    crate::mmu::unmap(base_page, count);
    crate::cpu::invalidate_uc(base_page, count);
}

/// Free physical pages over a range.
pub fn arch_free_range(base_page: usize, count: usize) {
    crate::mmu::free(base_page, count);
    crate::cpu::invalidate_uc(base_page, count);
}

/// Replace `count` user pages with fresh anonymous RW frames.
pub fn arch_map_fresh_range(vpage: usize, count: usize) {
    crate::mmu::map_fresh(vpage, count);
    crate::cpu::invalidate_uc(vpage, count);
}

/// Map a range of physical pages into user virtual space.
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, _ppage_start: u64, _flags: u64) {
    crate::mmu::map_phys(vpage_start, num_pages);
    crate::cpu::invalidate_uc(vpage_start, num_pages);
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
