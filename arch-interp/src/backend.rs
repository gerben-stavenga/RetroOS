//! Hosted implementation of the shared arch-abi traits.

#[cfg(feature = "tcg")]
use crate::space::RootPageTable;
use crate::vcpu::{self};
#[cfg(feature = "tcg")]
use arch_abi::{X86, Memory};
use arch_abi::{Arch, Diagnostics, KernelEvent, Regs};

/// The interpreter backend handle. Zero-sized today (state lives in module
/// statics); it gains fields as the globals migrate into it.
pub struct Interp;


#[cfg(feature = "tcg")]
impl X86 for Interp {
    unsafe fn bind_planar(&mut self, _: Option<planar::Binding>) {}
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

#[cfg(feature = "tcg")]
impl Memory for Interp {
    fn alias_mappings(&mut self, a: arch_abi::UserPage, b: arch_abi::UserPage, count: usize,
        pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingError>, arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || crate::paging::rearrange_mappings(a, b, count, false))
    }

    fn swap_mappings(&mut self, a: arch_abi::UserPage, b: arch_abi::UserPage, count: usize,
        pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingError>, arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || crate::paging::rearrange_mappings(a, b, count, true))
    }

    fn read_mappings(&mut self, start: arch_abi::UserPage, entries: &mut [arch_abi::page_entry::PageEntry]) -> Result<(), arch_abi::MappingFailure> {
        crate::paging::mapping_batch(start, entries.len(), |page, index| {
            entries[index] = crate::paging::read_mapping(page)?;
            Ok(())
        })
    }

    fn read_mapping_run(&mut self, start: arch_abi::UserPage, maximum: usize) -> Result<(arch_abi::page_entry::PageEntry, usize), arch_abi::MappingError> {
        crate::paging::read_mapping_run(start, maximum)
    }

    unsafe fn replace_mappings(&mut self, start: arch_abi::UserPage, entries: &[arch_abi::page_entry::PageEntry], pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingFailure>, arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || {
            crate::paging::mapping_batch(start, entries.len(), |page, index| crate::paging::replace_user_mapping(page, entries[index]))
        })
    }

    unsafe fn fill_mappings(&mut self, start: arch_abi::UserPage, count: usize, entry: arch_abi::page_entry::PageEntry, pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingFailure>, arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || {
            crate::paging::mapping_batch(start, count, |page, _| crate::paging::replace_user_mapping(page, entry))
        })
    }

    type PageTable = RootPageTable;

    fn activate(&mut self, incoming: RootPageTable) -> RootPageTable {
        let old = crate::paging::activate(incoming);
        crate::engine::flush();
        crate::desc::mark_ldt_dirty();
        old
    }

    fn supply_pages(&self, pages: arch_abi::page_supply::PageInput) -> (usize, arch_abi::page_supply::PageInput) {
        crate::phys::supply_pages(pages)
    }
    fn user_fork(&mut self, child: &mut RootPageTable, pages: arch_abi::page_supply::PageInput) -> ((), arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || {
            crate::calls::arch_user_fork(child)
        })
    }

    fn free_user_pages(&mut self) { crate::calls::arch_free_user_pages() }

    fn destroy_space(&mut self, root: &mut Self::PageTable) {
        crate::paging::destroy(root);
        crate::engine::flush();
    }



}

impl Arch for Interp {
    #[allow(clippy::deref_addrof)]
    fn execute(&mut self, regs: &mut Regs, _io: &arch_abi::IoPolicy, max_time: core::time::Duration) -> KernelEvent {
        crate::suite_control::gate();
        // Bridge the loop-owned registers to the backend's live frame for the
        // run, then read them
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
    use arch_abi::eflags;
    const CODE: usize = 0x7f00;
    let io = arch_abi::IoPolicy::deny_all();
    let limit = core::time::Duration::from_millis(100);
    for opcode in [0xfb, 0x9d, 0xcf] { // STI, POPF, IRET
        machine.copy_to((CODE) as u64, &[opcode, 0xcd, 0x31], crate::test_memory::input(5));
        #[cfg(feature = "kvm")]
        crate::mmu_tests::executable(CODE as u64);
        let mut pending = Regs::empty();
        pending.set_cs32(0);
        pending.set_ss32(0);
        pending.set_sp32(0x7000);
        pending.set_ip32(CODE as u32);
        pending.set_flags32(eflags::VM_FLAG | (1 << eflags::IOPL_SHIFT) | eflags::VIP_FLAG | 2);
        if opcode == 0xcf {
            machine.write::<u16>(0x7000, (CODE + 1) as u16);
            machine.write::<u16>(0x7002, 0);
            machine.write::<u16>(0x7004, 0x202);
        } else {
            machine.write::<u16>(0x7000, 0x202);
        }
        let event = machine.execute(&mut pending, &io, limit);
        assert!(matches!(event, KernelEvent::Irq),
            "opcode {opcode:x} must return when VIP becomes deliverable: {event:?}, regs={pending:?}");
        assert_eq!(pending.ip32(), (CODE + 1) as u32);
        assert_eq!(pending.flags32() & (eflags::VIF_FLAG | eflags::VIP_FLAG), eflags::VIF_FLAG | eflags::VIP_FLAG);

        // A different context has no pending indication and must run normally.
        let mut other = pending;
        other.clear_flag32(eflags::VIP_FLAG);
        assert!(matches!(machine.execute(&mut other, &io, limit), KernelEvent::SoftInt(0x31)));
        assert_eq!(pending.ip32(), (CODE + 1) as u32);

        // Pending alone must not interrupt execution while guest IF is off.
        pending.clear_flag32(eflags::VIF_FLAG);
        assert!(matches!(machine.execute(&mut pending, &io, limit), KernelEvent::SoftInt(0x31)));
        assert_ne!(pending.flags32() & eflags::VIP_FLAG, 0);
    }
}
