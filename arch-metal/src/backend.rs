//! `Metal` — the bare-metal `arch_abi::Arch` implementor.
//!
//! Mirror of `arch-interp`'s `Interp`: every method delegates to the existing
//! ring-0 surface (the `int 0x80` call wrappers in `calls.rs`, the `x86`
//! primitives, the timer/IRQ controllers in `irq.rs`, the descriptor/monitor helpers).
//! CPU execution state lives in arch-owned Rust TLS. The handle addresses the
//! current CPU; it does not own or synchronize the remaining shared devices.

use crate::mapping::{Read, Replace, Fill, ReadRun, invoke};
use arch_abi::{MappingError, MappingFailure, UserPage};
use arch_abi::page_entry::{PageEntry, X86PteFormat};
use super::paging2::RootPageTable;
use super::x86::FxState;
use arch_abi::{X86, Memory, Arch, Diagnostics, ExecutionProfile, ExecutionProfileStage, KernelEvent, Regs};

/// Zero-sized handle to the current CPU. Trap state lives in CPU-local TLS;
/// machine-wide resources remain shared.
pub struct Metal;

impl X86 for Metal {
    fn isa_unmask_irq(&mut self, line: u8) { super::calls::arch_isa_unmask_irq(line) }

    fn isa_enable_irq(&mut self, line: u8) { super::irq::isa_enable_irq(line) }

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

    unsafe fn replace_interrupt_handlers(&mut self, vector: u8, handlers: arch_abi::InterruptHandlers) -> arch_abi::InterruptHandlers {
        super::calls::arch_replace_interrupt_handlers(vector, handlers)
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
    fn page_format(&self) -> X86PteFormat { crate::mapping::format() }

    fn read_mapping(&mut self, page: UserPage) -> Result<PageEntry, MappingError> {
        let mut entry = PageEntry::Absent;
        self.read_mappings(page, core::slice::from_mut(&mut entry)).map_err(|failure| failure.error)?;
        Ok(entry)
    }

    unsafe fn replace_mapping(&mut self, page: UserPage, entry: PageEntry) -> Result<(), MappingError> {
        unsafe { self.replace_mappings(page, core::slice::from_ref(&entry)) }.map_err(|failure| failure.error)
    }

    fn read_mappings(&mut self, page: UserPage, entries: &mut [PageEntry]) -> Result<(), MappingFailure> {
        let mut arguments = Read { page, entries, result: Ok(()) };
        unsafe { invoke(crate::arch_call::READ_MAPPINGS, &mut arguments); }
        arguments.result
    }

    unsafe fn replace_mappings(&mut self, page: UserPage, entries: &[PageEntry]) -> Result<(), MappingFailure> {
        let mut arguments = Replace { page, entries, result: Ok(()) };
        unsafe { invoke(crate::arch_call::REPLACE_MAPPINGS, &mut arguments); }
        arguments.result
    }

    fn read_mapping_run(&mut self, page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        let mut arguments = ReadRun { page, maximum, result: Err(MappingError::InvalidAddress) };
        unsafe { invoke(crate::arch_call::READ_MAPPING_RUN, &mut arguments); }
        arguments.result
    }

    unsafe fn fill_mappings(&mut self, page: UserPage, count: usize, entry: PageEntry) -> Result<(), MappingFailure> {
        let mut arguments = Fill { page, count, entry, result: Ok(()) };
        unsafe { invoke(crate::arch_call::FILL_MAPPINGS, &mut arguments); }
        arguments.result
    }

    type PageTable = RootPageTable;

    fn high_copy(&mut self, address: u64, buffer: &mut [u8], to_user: bool) -> bool {
        super::high_paging::invoke(super::high_paging::Request {
            address, length: buffer.len() as u64, to_user, buffer: buffer.as_mut_ptr() as usize, result: 0,
        }) == 0
    }

    fn activate(&mut self, mut incoming: RootPageTable) -> RootPageTable {
        super::calls::arch_activate(&mut incoming);
        incoming
    }

    fn private_page_tables(&mut self) -> i32 {
        let result: u32;
        unsafe { core::arch::asm!("int 0x80", inlateout("eax") crate::arch_call::PRIVATE_TABLES as u32 => result); }
        result as i32
    }

    fn refresh_kernel_mappings(&mut self) {
        unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::REFRESH_KERNEL as u32); }
    }

    fn user_fork(&mut self, child: &mut RootPageTable) { super::calls::arch_user_fork(child) }

    fn free_user_pages(&mut self) { super::calls::arch_free_user_pages() }

    fn destroy_space(&mut self, _root: &mut RootPageTable) {}

    fn physical_frame_io(&self) -> Option<arch_abi::PhysicalFrameIo> { Some(crate::frames::io()) }

    fn page_supply(&self) -> Option<*mut arch_abi::page_supply::PageSupply> { Some(crate::memory::supply()) }

    fn set_page_input(&mut self, input: *mut arch_abi::page_supply::PageInput) -> *mut arch_abi::page_supply::PageInput {
        crate::memory::set_input(input)
    }

    fn alloc_shared_pages(&mut self, count: usize) -> core::ptr::NonNull<u8> {
        assert!(count != 0);
        let layout = alloc::alloc::Layout::from_size_align(count.checked_mul(4096).unwrap(), 4096).unwrap();
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) };
        core::ptr::NonNull::new(base).unwrap_or_else(|| alloc::alloc::handle_alloc_error(layout))
    }

    unsafe fn free_shared_pages(&mut self, base: core::ptr::NonNull<u8>, count: usize) {
        let layout = alloc::alloc::Layout::from_size_align(count.checked_mul(4096).unwrap(), 4096).unwrap();
        unsafe { alloc::alloc::dealloc(base.as_ptr(), layout); }
    }

    unsafe fn shared_page(&mut self, base: core::ptr::NonNull<u8>) -> arch_abi::page_entry::PhysicalFrame {
        arch_abi::page_entry::PhysicalFrame::new(crate::frames::physical(base.as_ptr() as usize)).unwrap()
    }

    fn map_kernel_physical(&mut self, vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
        assert!(vpage_start >= 0xc0000000 / 4096);
        super::calls::arch_map_kernel_physical(vpage_start, num_pages, ppage_start, flags)
    }

    fn framebuffer_map_policy(&self) -> arch_abi::FramebufferMapPolicy {
        super::paging2::framebuffer_map_policy()
    }

    fn alloc_phys_contig(&mut self, num_pages: usize) -> u64 {
        panic!("kernel must supply contiguous backing ({num_pages} pages)")
    }

    fn free_phys_contig(&mut self, start_page: u64, num_pages: usize) {
        panic!("kernel must release contiguous backing ({start_page}, {num_pages})")
    }

    fn dma_channel_buf(&self, ch: usize) -> u64 { panic!("kernel must supply ISA channel {ch}") }

    fn free_page_count(&self) -> usize { super::memory::free_page_count() }

    fn total_page_count(&self) -> Option<usize> { Some(super::memory::total_page_count()) }
}

impl Arch for Metal {
    fn interrupt_processor(&mut self, processor: u32) {
        unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::INTERRUPT_PROCESSOR as u32, in("edx") processor); }
    }

    #[allow(clippy::deref_addrof)]
    fn execute(&mut self, regs: &mut Regs, io: &arch_abi::IoPolicy, max_time: core::time::Duration) -> KernelEvent {
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
        ev
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
