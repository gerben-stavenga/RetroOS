//! `Interp` — the interpreter's `arch_abi::Arch` implementor.
//!
//! For now every method delegates to the existing free functions / statics (the
//! surface the hosted kernel still calls directly). Threading `&mut Interp`
//! through the kernel (and moving the statics into this struct to drop their
//! `unsafe`) is the later stage; defining the impl now validates the trait
//! against this backend and is the value the kernel will be injected with.

use crate::space::RootPageTable;
use crate::vcpu::{self, Vcpu};
use arch_abi::{Arch, GuestBytes, GuestOverlay, Irq, KernelEvent, Regs};

/// The interpreter backend handle. Zero-sized today (state lives in module
/// statics); it gains fields as the globals migrate into it.
pub struct Interp;

impl GuestBytes for Interp {
    fn read<T: Copy>(&self, addr: usize) -> T { vcpu::mem().read(addr) }
    fn write<T: Copy>(&mut self, addr: usize, val: T) { vcpu::mem().write(addr, val) }
    fn slice(&self, addr: usize, len: usize) -> &[u8] { vcpu::mem().slice(addr, len) }
    fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8] { vcpu::mem().slice_mut(addr, len) }
    fn c_str(&self, addr: usize, max: usize) -> &[u8] { vcpu::mem().c_str(addr, max) }
    fn zero(&mut self, addr: usize, len: usize) { vcpu::mem().zero(addr, len) }
    fn write_bytes(&mut self, addr: usize, src: &[u8]) { vcpu::mem().write_bytes(addr, src) }
}

impl GuestOverlay for Interp {
    fn at<T>(&mut self, addr: usize) -> &mut T {
        // Tie the placed ref's lifetime to `&mut self` (not `'static`).
        let p = vcpu::mem().slice_mut(addr, core::mem::size_of::<T>()).as_mut_ptr() as *mut T;
        unsafe { &mut *p }
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) { vcpu::mem().copy_within(src, dst, len) }
}

impl Arch for Interp {
    type PageTable = RootPageTable;
    type Fx = crate::machine::FxState;

    // ── Port I/O ──
    fn inb(&mut self, port: u16) -> u8 { crate::machine::inb(port) }
    fn inw(&mut self, port: u16) -> u16 { crate::machine::inw(port) }
    fn outb(&mut self, port: u16, val: u8) { crate::machine::outb(port, val) }
    fn outw(&mut self, port: u16, val: u16) { crate::machine::outw(port, val) }

    // ── Execution & scheduling ──
    //
    // The interp still keeps an internal live frame (`vcpu::REGS`) that its CPU
    // core syncs against; bridge the loop-owned `Vcpu` to it around each call.
    // (The internal frame goes away when the globals migrate into `Interp`.)
    fn execute(&mut self, vcpu: &mut Vcpu) -> KernelEvent {
        unsafe { *(&raw mut vcpu::REGS) = *vcpu; }
        let ev = crate::cpu::execute();
        *vcpu = unsafe { *(&raw const vcpu::REGS) };
        ev
    }
    fn switch_to(&mut self, live: &mut Vcpu, swap: &mut Vcpu, hash_ptr: *mut u64, fx_ptr: *mut Self::Fx) {
        // `arch_switch_to` swaps the internal live frame with `swap`; stage the
        // loop's `live` into it first, then read the incoming state back out.
        unsafe { *(&raw mut vcpu::REGS) = *live; }
        crate::calls::arch_switch_to(swap, hash_ptr, fx_ptr);
        *live = unsafe { *(&raw const vcpu::REGS) };
    }

    // ── Timer ──
    fn get_ticks(&self) -> u64 { crate::machine::get_ticks() }
    fn take_pending_ticks(&mut self) -> u32 { crate::machine::take_pending_ticks() }
    fn drain(&mut self, f: &mut dyn FnMut(Irq)) { crate::machine::drain(|e| f(e)) }
    fn rdtsc(&self) -> u64 { crate::machine::rdtsc() }

    // ── IRQ lines ──
    fn set_irq_line(&mut self, asserted: bool) { crate::machine::set_irq_line(asserted) }
    fn rearm_irq(&mut self, line: u8) { crate::calls::arch_rearm_irq(line) }
    fn set_debug_watch(&mut self, _addrs: Option<(u32, u32)>) {} // no debug-register feature

    // ── Arch calls: paging / fork / LDT / DMA ──
    fn user_fork(&mut self, child: &mut RootPageTable) { crate::calls::arch_user_fork(child) }
    fn free_user_pages(&mut self) { crate::calls::arch_free_user_pages() }
    fn set_page_flags(&mut self, start_vpage: usize, count: usize, writable: bool, executable: bool) {
        crate::calls::arch_set_page_flags(start_vpage, count, writable, executable)
    }
    fn map_low_mem(&mut self) { crate::calls::arch_map_low_mem() }
    fn copy_page_entries(&mut self, src_vpage: usize, dst_vpage: usize, count: usize) {
        crate::calls::arch_copy_page_entries(src_vpage, dst_vpage, count)
    }
    fn swap_page_entries(&mut self, a_vpage: usize, b_vpage: usize, count: usize) {
        crate::calls::arch_swap_page_entries(a_vpage, b_vpage, count)
    }
    fn unmap_range(&mut self, base_page: usize, count: usize) { crate::calls::arch_unmap_range(base_page, count) }
    fn free_range(&mut self, base_page: usize, count: usize) { crate::calls::arch_free_range(base_page, count) }
    fn map_fresh_range(&mut self, vpage: usize, count: usize) { crate::calls::arch_map_fresh_range(vpage, count) }
    fn load_ldt(&mut self, ldt: &[u64]) { crate::calls::arch_load_ldt(ldt) }
    fn map_phys_range(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
        crate::calls::arch_map_phys_range(vpage_start, num_pages, ppage_start, flags)
    }
    fn alloc_phys_contig(&mut self, num_pages: usize, boundary_log2: u32) -> u64 {
        crate::calls::arch_alloc_phys_contig(num_pages, boundary_log2)
    }
    fn free_phys_contig(&mut self, start_page: u64, num_pages: usize) {
        crate::calls::arch_free_phys_contig(start_page, num_pages)
    }
    fn dma_channel_buf(&self, ch: usize) -> u64 { crate::calls::arch_dma_channel_buf(ch) }
    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
        crate::calls::arch_set_tls_entry(index, base, limit, limit_in_pages)
    }

    // ── FPU/SSE state ──
    fn clean_fx_template(&self) -> Self::Fx { crate::machine::clean_fx_template() }

    // ── Diagnostics & power ──
    fn free_page_count(&self) -> usize { crate::machine::free_page_count() }
    fn shutdown(&mut self) -> ! { crate::machine::shutdown() }
    fn halt_forever(&mut self) -> ! { crate::machine::halt_forever() }

    // ── x86 segment helpers ──
    fn seg_base(&self, sel: u16) -> u32 { crate::monitor::seg_base(sel) }
    fn seg_is_32(&self, sel: u16) -> bool { crate::monitor::seg_is_32(sel) }
    fn sw_reflect_vm86_int(&mut self, regs: &mut Regs, vector: u8) {
        unsafe { crate::monitor::sw_reflect_vm86_int(regs, vector) }
    }
}
