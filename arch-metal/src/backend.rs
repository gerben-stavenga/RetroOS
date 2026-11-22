//! `Metal` — the bare-metal `arch_abi::Core` implementor.
//!
//! Mirror of `arch-interp`'s `Interp`: every method delegates to the existing
//! ring-0 surface (the `int 0x80` call wrappers in `calls.rs`, the `x86`
//! primitives, the timer/IRQ controllers in `irq.rs`, the descriptor/monitor helpers).
//! CPU execution state lives in arch-owned Rust TLS. The handle addresses the
//! current CPU; it does not own or synchronize the remaining shared devices.

use crate::mapping::{Read, Replace, Fill, ReadRun, invoke};
use arch_abi::{MappingError, MappingFailure, UserPage};
use arch_abi::page_entry::PageEntry;
use super::paging2::AddressSpace;
use super::x86::FxState;
use arch_abi::{X86, Memory, Diagnostics, ExecutionProfile, ExecutionProfileStage};

#[cfg(not(feature = "kvm"))]
use arch_abi::{Core, KernelEvent, Regs};

/// Zero-sized handle to the current CPU. Trap state lives in CPU-local TLS;
/// machine-wide resources remain shared.
pub struct Metal {
    _local: core::marker::PhantomData<*mut ()>,
}

impl Metal {
    /// Bind the handle to the current processor.
    ///
    /// # Safety
    /// The caller must have exclusive access to this core for the entire
    /// lifetime of the handle. A trap may borrow access while execution is
    /// suspended and must return it before resuming.
    pub const unsafe fn bind_current() -> Self {
        Self { _local: core::marker::PhantomData }
    }
}

impl X86 for Metal {
    unsafe fn install_trap_hook(&mut self, mut hook: Option<arch_abi::entry::TrapHook>) {
        unsafe { invoke(crate::arch_call::INSTALL_TRAP_HOOK, &mut hook); }
    }
    fn isa_unmask_irq(&mut self, line: u8) {
        #[cfg(not(feature = "kvm"))]
        super::calls::arch_isa_unmask_irq(line);
        #[cfg(feature = "kvm")]
        panic!("no physical ISA controller in KVM (line {line})");
    }

    fn isa_enable_irq(&mut self, line: u8) {
        #[cfg(not(feature = "kvm"))]
        super::irq::isa_enable_irq(line);
        #[cfg(feature = "kvm")]
        panic!("no physical ISA controller in KVM (line {line})");
    }

    type Fx = FxState;

    fn fx_state_bytes(fx: &Self::Fx) -> Option<&[u8; 512]> { Some(&fx.0) }

    fn fx_state_bytes_mut(fx: &mut Self::Fx) -> Option<&mut [u8; 512]> { Some(&mut fx.0) }

    fn inb(&mut self, port: u16) -> u8 { super::x86::inb(port) }

    fn inw(&mut self, port: u16) -> u16 { super::x86::inw(port) }

    fn inl(&mut self, port: u16) -> u32 { super::x86::inl(port) }

    fn outb(&mut self, port: u16, val: u8) { super::x86::outb(port, val) }

    fn outw(&mut self, port: u16, val: u16) { super::x86::outw(port, val) }

    fn outl(&mut self, port: u16, val: u32) { super::x86::outl(port, val) }

    fn user_64_supported(&self) -> bool {
        // Long mode is toggled per-thread on demand (traps::toggle_mode_if_needed),
        // so CPU support is the whole capability.
        super::paging2::cpu_supports_long_mode()
    }

    fn switch_fx(&mut self, fx: &mut Self::Fx) {
        super::calls::arch_switch_fx(fx);
    }

    fn set_debug_watch(&mut self, addrs: Option<(u32, u32)>) { super::calls::arch_set_debug_watch(addrs) }

    fn load_ldt(&mut self, ldt: &[u64]) { super::calls::arch_load_ldt(ldt) }

    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
        super::calls::arch_set_tls_entry(index, base, limit, limit_in_pages)
    }

    fn clean_fx_template(&self) -> FxState { super::x86::clean_fx_template() }

    fn fpu_st0(&self) -> [u8; 10] { super::x86::fpu_st0() }

    fn fpu_pop(&mut self) { super::x86::fpu_pop() }

    fn seg_base(sel: u16) -> u32 { super::descriptors::seg_base(sel) }

    fn seg_is_32(sel: u16) -> bool { super::descriptors::seg_is_32(sel) }

    fn int_intercepted(vector: u8) -> bool { super::descriptors::int_intercepted(vector) }
}

impl Memory for Metal {
    fn alias_mappings(&mut self, a: arch_abi::UserPage, b: arch_abi::UserPage, count: usize,
        pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingError>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            let mut args = crate::mapping::Rearrange { a, b, count, swap: false, result: Ok(()) };
            unsafe { invoke(crate::arch_call::REARRANGE_MAPPINGS, &mut args); }
            args.result
        })
    }

    fn swap_mappings(&mut self, a: arch_abi::UserPage, b: arch_abi::UserPage, count: usize,
        pages: arch_abi::page_supply::PageInput) -> (Result<(), arch_abi::MappingError>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            let mut args = crate::mapping::Rearrange { a, b, count, swap: true, result: Ok(()) };
            unsafe { invoke(crate::arch_call::REARRANGE_MAPPINGS, &mut args); }
            args.result
        })
    }

    fn read_mappings(&mut self, page: UserPage, entries: &mut [PageEntry]) -> Result<(), MappingFailure> {
        let mut arguments = Read { page, entries, result: Ok(()) };
        unsafe { invoke(crate::arch_call::READ_MAPPINGS, &mut arguments); }
        arguments.result
    }

    unsafe fn replace_mappings(&mut self, page: UserPage, entries: &[PageEntry], pages: arch_abi::page_supply::PageInput) -> (Result<(), MappingFailure>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            let mut arguments = Replace { page, entries, result: Ok(()) };
            unsafe { invoke(crate::arch_call::REPLACE_MAPPINGS, &mut arguments); }
            arguments.result
        })
    }

    fn read_mapping_run(&mut self, page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        let mut arguments = ReadRun { page, maximum, result: Err(MappingError::InvalidAddress) };
        unsafe { invoke(crate::arch_call::READ_MAPPING_RUN, &mut arguments); }
        arguments.result
    }

    unsafe fn fill_mappings(&mut self, page: UserPage, count: usize, entry: PageEntry, pages: arch_abi::page_supply::PageInput) -> (Result<(), MappingFailure>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            let mut arguments = Fill { page, count, entry, result: Ok(()) };
            unsafe { invoke(crate::arch_call::FILL_MAPPINGS, &mut arguments); }
            arguments.result
        })
    }

    type AddressSpace = AddressSpace;

    fn activate(&mut self, mut incoming: AddressSpace) -> AddressSpace {
        super::calls::arch_activate(&mut incoming);
        incoming
    }

    fn user_fork(&mut self, child: &mut AddressSpace, pages: arch_abi::page_supply::PageInput) -> ((), arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            super::calls::arch_user_fork(child)
        })
    }

    fn free_user_pages(&mut self) { super::calls::arch_free_user_pages() }

    fn destroy_space(&mut self, _root: &mut AddressSpace) {}


    fn supply_pages(&self, pages: arch_abi::page_supply::PageInput) -> (usize, arch_abi::page_supply::PageInput) {
        crate::memory::supply_pages(pages)
    }
}

#[cfg(not(feature = "kvm"))]
impl Core for Metal {
    fn interrupt_processor(&mut self, processor: u32) {
        unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::INTERRUPT_PROCESSOR as u32, in("edx") processor); }
    }

    #[allow(clippy::deref_addrof)]
    fn execute(&mut self, regs: &mut Regs, io: &arch_abi::IoPolicy, max_time: core::time::Duration) -> (KernelEvent, arch_abi::page_supply::SupplyStatus) {
        super::descriptors::install_io_policy(io);
        super::exec_profile::time(ExecutionProfileStage::PolicyInstall);
        // The ring transitions exchange their physical frames directly with
        // this loop-owned register object.  Its borrow remains live until the
        // matching INT 80 returns, so no intermediate register copy is needed.
        super::traps::set_execute_regs(regs);
        super::exec_profile::time(ExecutionProfileStage::BridgeIn);
        let (event, extra) = super::calls::do_arch_execute_raw(max_time.as_nanos().min(u64::MAX as u128) as u64);
        super::traps::set_execute_regs(core::ptr::null_mut());
        super::exec_profile::time(ExecutionProfileStage::BridgeOut);
        let ev = KernelEvent::decode(event, extra);
        super::exec_profile::time(ExecutionProfileStage::Decode);
        (ev, super::memory::supply_status())
    }

    fn now(&self) -> u64 { super::irq::now(false) }

    fn idle(&mut self, max_time: core::time::Duration) -> KernelEvent { super::calls::arch_idle(max_time.as_nanos().min(u64::MAX as u128) as u64); KernelEvent::Irq }

    fn shutdown(&mut self) -> ! { super::x86::shutdown() }

    fn halt_forever(&mut self) -> ! { super::halt_forever() }
}

impl Diagnostics for Metal {
    fn check_address_space(&mut self, expected: u64) -> u64 {
        super::calls::arch_check_address_space(expected)
    }

    fn execution_profile_set(&mut self, enabled: bool) { super::exec_profile::set(enabled) }

    fn execution_profile_reset(&mut self) { super::exec_profile::reset() }

    fn execution_profile_begin(&mut self) { super::exec_profile::begin() }

    fn execution_profile_time(&mut self, stage: ExecutionProfileStage) { super::exec_profile::time(stage) }

    fn execution_profile(&self) -> ExecutionProfile { super::exec_profile::snapshot() }
}
