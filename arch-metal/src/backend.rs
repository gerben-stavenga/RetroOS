//! `Metal` — the bare-metal `arch_abi::Arch` implementor.
//!
//! Mirror of `arch-interp`'s `Interp`: every method delegates to the existing
//! ring-0 surface (the `int 0x80` call wrappers in `calls.rs`, the `x86`
//! primitives, the timer/IRQ queue in `irq.rs`, the descriptor/monitor helpers).
//! Threading `&mut Metal` through the kernel — and folding the `REGS`/timer
//! statics into it — is the later stage; defining the impl now keeps the two
//! backends symmetric against the shared `trait Arch`.

use super::paging2::RootPageTable;
use super::x86::FxState;
use arch_abi::{Arch, Irq, KernelEvent, Vcpu};

/// The bare-metal backend handle. Zero-sized today (state lives in module
/// statics — `traps::REGS`, the timer/IRQ queue); it gains fields as those
/// globals migrate into it.
pub struct Metal;

impl Arch for Metal {
    type PageTable = RootPageTable;
    type Fx = FxState;

    // ── Port I/O ──
    fn inb(&mut self, port: u16) -> u8 { super::x86::inb(port) }
    fn inw(&mut self, port: u16) -> u16 { super::x86::inw(port) }
    fn inl(&mut self, port: u16) -> u32 { super::x86::inl(port) }
    fn outb(&mut self, port: u16, val: u8) { super::x86::outb(port, val) }
    fn outw(&mut self, port: u16, val: u16) { super::x86::outw(port, val) }
    fn outl(&mut self, port: u16, val: u32) { super::x86::outl(port, val) }
    fn allow_io_ports(&mut self, port: u16, count: usize) {
        super::descriptors::allow_io_ports(port, count)
    }
    fn reset_io_bitmap(&mut self) {
        super::descriptors::reset_io_bitmap()
    }

    // ── Execution & scheduling ──
    //
    // Metal keeps the live frame in `traps::REGS` (the int-0x80 trap save area).
    // Bridge the loop-owned `Vcpu` to it around each call; the bridge copy is the
    // register file only (~200 B) — the address space / CR3 is touched only at
    // switch. (The internal frame goes away when the globals migrate into `Metal`.)
    fn execute(&mut self, vcpu: &mut Vcpu<Self>) -> KernelEvent {
        // `Vcpu` is move-only: SWAP ownership into the internal live frame for
        // the duration of the run, then swap it back (no copy).
        let live = unsafe { &mut *(&raw mut super::traps::REGS) };
        core::mem::swap(live, vcpu);
        let ev = super::calls::do_arch_execute();
        core::mem::swap(live, vcpu);
        ev
    }
    fn switch_to(
        &mut self,
        live: &mut Vcpu<Self>,
        swap: &mut Vcpu<Self>,
        hash_ptr: *mut u64,
        fx_ptr: *mut FxState,
    ) {
        let regs = unsafe { &mut *(&raw mut super::traps::REGS) };
        core::mem::swap(regs, live);
        super::calls::arch_switch_to(swap, hash_ptr, fx_ptr);
        core::mem::swap(regs, live);
    }

    // ── Timer ──
    fn get_ticks(&self) -> u64 { super::irq::get_ticks() }
    fn take_pending_ticks(&mut self) -> u32 { super::irq::take_pending_ticks() }
    fn drain(&mut self, f: &mut dyn FnMut(Irq)) { super::irq::drain(f) }
    fn rdtsc(&self) -> u64 { super::x86::rdtsc() }

    // ── IRQ lines ──
    fn set_irq_line(&mut self, _asserted: bool) {} // real 8259 drives INTR
    fn rearm_irq(&mut self, line: u8) { super::calls::arch_rearm_irq(line) }
    fn set_debug_watch(&mut self, addrs: Option<(u32, u32)>) { super::calls::arch_set_debug_watch(addrs) }

    // ── Arch calls: paging / fork / LDT / DMA ──
    fn user_fork(&mut self, child: &mut RootPageTable) { super::calls::arch_user_fork(child) }
    fn free_user_pages(&mut self) { super::calls::arch_free_user_pages() }
    // The metal "space" is the saved-entries buffer inside the Thread (the
    // live tables use the constant root); page frames were already freed by
    // free_user_pages at exit, so there is no arch-side object to release.
    fn destroy_space(&mut self, _root: &mut RootPageTable) {}
    fn set_page_flags(&mut self, start_vpage: usize, count: usize, writable: bool, executable: bool) {
        super::calls::arch_set_page_flags(start_vpage, count, writable, executable)
    }
    fn map_low_mem(&mut self) { super::calls::arch_map_low_mem() }
    fn map_vga_text_aperture(&mut self) { super::calls::arch_map_vga_text_aperture() }
    fn copy_page_entries(&mut self, src_vpage: usize, dst_vpage: usize, count: usize) {
        super::calls::arch_copy_page_entries(src_vpage, dst_vpage, count)
    }
    fn swap_page_entries(&mut self, a_vpage: usize, b_vpage: usize, count: usize) {
        super::calls::arch_swap_page_entries(a_vpage, b_vpage, count)
    }
    fn unmap_range(&mut self, base_page: usize, count: usize) { super::calls::arch_unmap_range(base_page, count) }
    fn map_fresh_range(&mut self, vpage: usize, count: usize) { super::calls::arch_map_fresh_range(vpage, count) }
    fn load_ldt(&mut self, ldt: &[u64]) { super::calls::arch_load_ldt(ldt) }
    fn map_phys_range(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
        super::calls::arch_map_phys_range(vpage_start, num_pages, ppage_start, flags)
    }
    fn alloc_phys_contig(&mut self, num_pages: usize, boundary_log2: u32) -> u64 {
        super::calls::arch_alloc_phys_contig(num_pages, boundary_log2)
    }
    fn free_phys_contig(&mut self, start_page: u64, num_pages: usize) {
        super::calls::arch_free_phys_contig(start_page, num_pages)
    }
    fn dma_channel_buf(&self, ch: usize) -> u64 { super::calls::arch_dma_channel_buf(ch) }
    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
        super::calls::arch_set_tls_entry(index, base, limit, limit_in_pages)
    }

    // ── FPU/SSE state ──
    fn clean_fx_template(&self) -> FxState { super::x86::clean_fx_template() }

    // ── Diagnostics & power ──
    fn free_page_count(&self) -> usize { super::phys_mm::free_page_count() }
    fn shutdown(&mut self) -> ! { super::x86::shutdown() }
    fn halt_forever(&mut self) -> ! { super::halt_forever() }

    // ── x86 descriptor resolution (associated fns — ambient GDT/LDT) ──
    fn seg_base(sel: u16) -> u32 { super::descriptors::seg_base(sel) }
    fn seg_is_32(sel: u16) -> bool { super::descriptors::seg_is_32(sel) }
    fn int_intercepted(vector: u8) -> bool { super::descriptors::int_intercepted(vector) }
}
