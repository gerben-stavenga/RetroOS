//! `Interp` — the interpreter's `arch_abi::Arch` implementor.
//!
//! For now every method delegates to the existing free functions / statics (the
//! surface the hosted kernel still calls directly). Threading `&mut Interp`
//! through the kernel (and moving the statics into this struct to drop their
//! `unsafe`) is the later stage; defining the impl now validates the trait
//! against this backend and is the value the kernel will be injected with.

use crate::space::RootPageTable;
use crate::vcpu::{self};
use arch_abi::{Arch, Irq, KernelEvent, Regs};

/// The interpreter backend handle. Zero-sized today (state lives in module
/// statics); it gains fields as the globals migrate into it.
pub struct Interp;

impl Arch for Interp {
    type PageTable = RootPageTable;
    type Fx = crate::machine::FxState;

    // ── Port I/O ──
    fn inb(&mut self, port: u16) -> u8 { crate::machine::inb(port) }
    fn inw(&mut self, port: u16) -> u16 { crate::machine::inw(port) }
    fn inl(&mut self, port: u16) -> u32 { crate::machine::inl(port) }
    fn outb(&mut self, port: u16, val: u8) { crate::machine::outb(port, val) }
    fn outw(&mut self, port: u16, val: u16) { crate::machine::outw(port, val) }
    fn outl(&mut self, port: u16, val: u32) { crate::machine::outl(port, val) }
    fn allow_io_ports(&mut self, port: u16, count: usize) { crate::engine::allow_io_ports(port, count) }
    fn reset_io_bitmap(&mut self) { crate::engine::reset_io_bitmap() }

    // ── Execution & scheduling ──
    //
    // The interp still keeps an internal live frame (`vcpu::REGS`) that its CPU
    // core syncs against; bridge the loop-owned `Vcpu` to it around each call.
    // (The internal frame goes away when the globals migrate into `Interp`.)
    // `&mut *(&raw mut REGS)` is the `&raw`-first form that avoids a
    // `static_mut_refs` reference; clippy's `deref_addrof` rewrite would
    // reintroduce it.
    #[allow(clippy::deref_addrof)]
    fn execute(&mut self, regs: &mut Regs) -> KernelEvent {
        // Bridge the loop-owned registers to the backend's live frame for the
        // run (the active SPACE already lives in `REGS.space`), then read them
        // back. Swap, not copy — `Regs` is Copy but swap keeps a single source.
        let live = unsafe { &mut *(&raw mut vcpu::REGS) };
        core::mem::swap(&mut live.regs, regs);
        let ev = crate::engine::execute();
        core::mem::swap(&mut live.regs, regs);
        ev
    }
    // deref_addrof: same `&raw`-first REGS idiom as `execute`.
    // not_unsafe_ptr_arg_deref: the `*mut Fx`/`*mut u64` args are the trait's
    // fixed signature; the deref is guarded by the `is_null` check above.
    #[allow(clippy::deref_addrof, clippy::not_unsafe_ptr_arg_deref)]
    fn activate(&mut self, incoming: RootPageTable, fx_ptr: *mut Self::Fx, _hash_ptr: *mut u64) -> RootPageTable {
        // Swap the live FPU with the thread's save area (null ⇒ transient
        // kernel-only swap, skip). KVM: state is the vcpu's XSAVE; TCG: no-op.
        if !fx_ptr.is_null() {
            crate::engine::fx_switch(unsafe { &mut *fx_ptr });
        }
        // Move `incoming` into the single active-space slot and return the
        // displaced one. Then make the new active space live (drop the outgoing
        // space's lazy Unicorn mappings).
        let live = unsafe { &mut *(&raw mut vcpu::REGS) };
        let old = core::mem::replace(&mut live.space, incoming);
        crate::engine::flush();
        crate::mmu::switch_to(live.space.0);
        old
    }

    // ── Timer ──
    fn get_ticks(&self) -> u64 { crate::machine::get_ticks() }
    fn take_pending_ticks(&mut self) -> u32 { crate::machine::take_pending_ticks() }
    fn drain(&mut self, f: &mut dyn FnMut(Irq)) { crate::machine::drain(f) }
    fn rdtsc(&self) -> u64 { crate::machine::rdtsc() }

    // ── IRQ lines ──
    fn set_irq_line(&mut self, asserted: bool) { crate::machine::set_irq_line(asserted) }
    fn rearm_irq(&mut self, line: u8) { crate::calls::arch_rearm_irq(line) }
    fn set_debug_watch(&mut self, _addrs: Option<(u32, u32)>) {} // no debug-register feature

    // ── Arch calls: paging / fork / LDT / DMA ──
    fn user_fork(&mut self, child: &mut RootPageTable) { crate::calls::arch_user_fork(child) }
    fn free_user_pages(&mut self) { crate::calls::arch_free_user_pages() }
    fn destroy_space(&mut self, root: &mut Self::PageTable) {
        crate::mmu::destroy_space(root.0);
        crate::engine::flush();
    }
    fn set_page_flags(&mut self, start_vpage: usize, count: usize, writable: bool, executable: bool) {
        crate::calls::arch_set_page_flags(start_vpage, count, writable, executable)
    }
    fn map_low_mem(&mut self) { crate::calls::arch_map_low_mem() }
    fn map_vga_text_aperture(&mut self) { crate::calls::arch_map_vga_text_aperture() }
    fn copy_page_entries(&mut self, src_vpage: usize, dst_vpage: usize, count: usize) {
        crate::calls::arch_copy_page_entries(src_vpage, dst_vpage, count)
    }
    fn swap_page_entries(&mut self, a_vpage: usize, b_vpage: usize, count: usize) {
        crate::calls::arch_swap_page_entries(a_vpage, b_vpage, count)
    }
    fn unmap_range(&mut self, base_page: usize, count: usize) { crate::calls::arch_unmap_range(base_page, count) }
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

    // ── x86 descriptor resolution (associated fns — ambient `desc` state) ──
    fn seg_base(sel: u16) -> u32 { crate::desc::seg_base(sel) }
    fn seg_is_32(sel: u16) -> bool { crate::desc::seg_is_32(sel) }
    fn int_intercepted(vector: u8) -> bool { crate::desc::int_intercepted(vector) }
}
