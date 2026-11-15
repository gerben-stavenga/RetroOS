//! `Interp` — the interpreter's `arch_abi::Arch` implementor.
//!
//! For now every method delegates to the existing free functions / statics (the
//! surface the hosted kernel still calls directly). Threading `&mut Interp`
//! through the kernel (and moving the statics into this struct to drop their
//! `unsafe`) is the later stage; defining the impl now validates the trait
//! against this backend and is the value the kernel will be injected with.

use crate::space::RootPageTable;
use crate::vcpu::{self};
use arch_abi::{X86, Memory, Arch, Diagnostics, KernelEvent, Regs};

/// The interpreter backend handle. Zero-sized today (state lives in module
/// statics); it gains fields as the globals migrate into it.
pub struct Interp;


impl X86 for Interp {
    fn isa_unmask_irq(&mut self, line: u8) { crate::calls::arch_isa_unmask_irq(line) }

    type Fx = crate::machine::FxState;

    fn fx_state_bytes(fx: &Self::Fx) -> Option<&[u8; 512]> { Some(&fx.0) }

    fn fx_state_bytes_mut(fx: &mut Self::Fx) -> Option<&mut [u8; 512]> { Some(&mut fx.0) }

    fn inb(&mut self, port: u16) -> u8 { crate::machine::inb(port) }

    fn inw(&mut self, port: u16) -> u16 { crate::machine::inw(port) }

    fn inl(&mut self, port: u16) -> u32 { crate::machine::inl(port) }

    fn outb(&mut self, port: u16, val: u8) { crate::machine::outb(port, val) }

    fn outw(&mut self, port: u16, val: u16) { crate::machine::outw(port, val) }

    fn outl(&mut self, port: u16, val: u32) { crate::machine::outl(port, val) }

    fn user_64_supported(&self) -> bool {
        // The KVM engine runs Mode64 slices in real long mode (4-level twin
        // CR3 + 64-bit shim). The TCG engine still executes Mode64 flat-32
        // ("smoke paths only") — it flips when the Unicorn core goes MODE_64.
        cfg!(feature = "kvm")
    }

    fn switch_fx(&mut self, fx: &mut Self::Fx) {
        crate::engine::fx_switch(fx);
    }

    fn on_ldt_changed(&mut self) {
        crate::desc::mark_ldt_dirty();
    }

    fn set_debug_watch(&mut self, _addrs: Option<(u32, u32)>) {}

    fn load_ldt(&mut self, ldt: &[u64]) { crate::calls::arch_load_ldt(ldt) }

    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
        crate::calls::arch_set_tls_entry(index, base, limit, limit_in_pages)
    }

    fn clean_fx_template(&self) -> Self::Fx { crate::machine::clean_fx_template() }

    fn fpu_st0(&self) -> [u8; 10] { crate::engine::fpu_st0() }

    fn fpu_pop(&mut self) { crate::engine::fpu_pop() }

    fn seg_base(sel: u16) -> u32 { crate::desc::seg_base(sel) }

    fn seg_is_32(sel: u16) -> bool { crate::desc::seg_is_32(sel) }

    fn int_intercepted(vector: u8) -> bool { crate::desc::int_intercepted(vector) }
}

impl Memory for Interp {
    fn page_format(&self) -> arch_abi::page_entry::X86PteFormat { arch_abi::page_entry::X86PteFormat::Legacy32 }

    fn read_mapping(&mut self, page: arch_abi::UserPage) -> Result<arch_abi::page_entry::PageEntry, arch_abi::MappingError> {
        crate::paging::read_mapping(page)
    }

    unsafe fn replace_mapping(&mut self, page: arch_abi::UserPage, entry: arch_abi::page_entry::PageEntry) -> Result<(), arch_abi::MappingError> {
        crate::paging::replace_user_mapping(page, entry)
    }

    type PageTable = RootPageTable;

    #[allow(clippy::deref_addrof)]
    fn activate(&mut self, mut incoming: RootPageTable) -> RootPageTable {
        if incoming.0 == u32::MAX { incoming = RootPageTable(crate::mmu::new_space()); }
        // Move `incoming` into the single active-space slot and return the
        // displaced one. Then make the new active space live (drop the outgoing
        // space's lazy Unicorn mappings).
        let live = unsafe { &mut *(&raw mut vcpu::REGS) };
        let old = core::mem::replace(&mut live.space, incoming);
        crate::engine::flush();
        crate::mmu::switch_to(live.space.0);
        // A swap changes the active thread ⇒ its descriptor tables must be
        // re-materialized before the next entry (catch-all for DOS and Linux).
        crate::desc::mark_ldt_dirty();
        old
    }

    fn user_fork(&mut self, child: &mut RootPageTable) { crate::calls::arch_user_fork(child) }

    fn free_user_pages(&mut self) { crate::calls::arch_free_user_pages() }

    fn destroy_space(&mut self, root: &mut Self::PageTable) {
        crate::mmu::destroy_space(root.0);
        crate::engine::flush();
    }

    fn frame_access(&self) -> Option<arch_abi::FrameAccess> { Some(crate::phys::frame_access()) }

    fn alloc_shared_pages(&mut self, count: usize) -> core::ptr::NonNull<u8> {
        assert!(count != 0);
        let base = crate::phys::frame_ptr(crate::phys::alloc_frames(count));
        core::ptr::NonNull::new(base).unwrap()
    }

    unsafe fn free_shared_pages(&mut self, base: core::ptr::NonNull<u8>, count: usize) {
        crate::phys::free_frames(crate::phys::kernel_frame(base, count), count);
    }

    unsafe fn shared_page(&mut self, base: core::ptr::NonNull<u8>) -> arch_abi::page_entry::PhysicalFrame {
        arch_abi::page_entry::PhysicalFrame::new(crate::phys::kernel_frame(base, 1)).unwrap()
    }

    fn map_kernel_physical(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
        assert!(vpage_start >= 0xc0000000 / 4096);
        crate::calls::arch_map_kernel_physical(vpage_start, num_pages, ppage_start, flags)
    }

    fn alloc_phys_contig(&mut self, num_pages: usize) -> u64 {
        crate::calls::arch_alloc_phys_contig(num_pages)
    }

    fn free_phys_contig(&mut self, start_page: u64, num_pages: usize) {
        crate::calls::arch_free_phys_contig(start_page, num_pages)
    }

    fn dma_channel_buf(&self, ch: usize) -> u64 { crate::calls::arch_dma_channel_buf(ch) }

    fn free_page_count(&self) -> usize { crate::machine::free_page_count() }

    fn total_page_count(&self) -> Option<usize> { Some(crate::phys::PHYS_SIZE / 4096 - 1) }
}

impl Arch for Interp {
    #[allow(clippy::deref_addrof)]
    fn execute(&mut self, regs: &mut Regs, io: &arch_abi::IoPolicy, max_time: core::time::Duration) -> KernelEvent {
        crate::suite_control::gate();
        crate::engine::install_io_policy(io);
        // Bridge the loop-owned registers to the backend's live frame for the
        // run (the active SPACE already lives in `REGS.space`), then read them
        // back. Swap, not copy — `Regs` is Copy but swap keeps a single source.
        let live = unsafe { &mut *(&raw mut vcpu::REGS) };
        core::mem::swap(&mut live.regs, regs);
        let ev = crate::engine::execute(max_time);
        core::mem::swap(&mut live.regs, regs);
        ev
    }

    fn now(&self) -> u64 { crate::machine::now() }

    fn idle(&mut self, max_time: core::time::Duration) -> KernelEvent { crate::machine::idle(max_time); KernelEvent::Irq }

    fn shutdown(&mut self) -> ! { crate::machine::shutdown() }

    fn halt_forever(&mut self) -> ! { crate::machine::halt_forever() }
}

impl Diagnostics for Interp {

}

/// Run inside each engine's existing single-CPU proof, not a parallel test.
#[cfg(test)]
pub(crate) fn check_virtual_irq_frame(machine: &mut Interp) {
    use arch_abi::GuestBytes;
    const VIP: u32 = 1 << 20;
    const VIF: u32 = 1 << 19;
    const CODE: usize = 0x7f00;
    let io = arch_abi::IoPolicy::deny_all();
    let limit = core::time::Duration::from_millis(100);
    for opcode in [0xfb, 0x9d, 0xcf] { // STI, POPF, IRET
        machine.copy_to(CODE, &[opcode, 0xcd, 0x31]);
        let mut pending = Regs::empty();
        pending.set_cs32(0);
        pending.set_ss32(0);
        pending.set_sp32(0x7000);
        pending.set_ip32(CODE as u32);
        pending.set_flags32((1 << 17) | (1 << 12) | VIP | 2);
        if opcode == 0xcf {
            machine.write::<u16>(0x7000, (CODE + 1) as u16);
            machine.write::<u16>(0x7002, 0);
            machine.write::<u16>(0x7004, 0x202);
        } else {
            machine.write::<u16>(0x7000, 0x202);
        }
        assert!(matches!(machine.execute(&mut pending, &io, limit), KernelEvent::Irq),
            "opcode {opcode:x} must return when VIP becomes deliverable");
        assert_eq!(pending.ip32(), (CODE + 1) as u32);
        assert_eq!(pending.flags32() & (VIF | VIP), VIF | VIP);

        // A different context has no pending indication and must run normally.
        let mut other = pending;
        other.clear_flag32(VIP);
        assert!(matches!(machine.execute(&mut other, &io, limit), KernelEvent::SoftInt(0x31)));
        assert_eq!(pending.ip32(), (CODE + 1) as u32);

        // Pending alone must not interrupt execution while guest IF is off.
        pending.clear_flag32(VIF);
        assert!(matches!(machine.execute(&mut pending, &io, limit), KernelEvent::SoftInt(0x31)));
        assert_ne!(pending.flags32() & VIP, 0);
    }
}
