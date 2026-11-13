//! CPU-local donated pages, with no allocator dependency or allocation callbacks.
use arch_abi::page_supply::{FrameOwnership, PageBootstrap, PageInput, PageSupply, FAULT_PAGES};
use crate::paging2;
#[thread_local]
static mut SUPPLY: PageSupply = PageSupply::new();
#[thread_local]
static mut INPUT: *mut PageInput = core::ptr::null_mut();

pub fn supply() -> *mut PageSupply { &raw mut SUPPLY }
/// Kernel supplies resident metadata and its fault-resume entry, never an allocator.
pub fn configure(ownership: FrameOwnership, refill_ip: usize) {
    unsafe { (*supply()).ownership = ownership; (*supply()).refill_ip = refill_ip; }
}
pub fn bootstrap(boot: PageBootstrap) {
    configure(boot.ownership, boot.refill_ip);
    for page in boot.pages { unsafe { (*supply()).donate(page); } }
}
pub fn set_input(input: *mut PageInput) -> *mut PageInput {
    unsafe { let old = INPUT; INPUT = input; old }
}
pub fn can_fault() -> bool {
    unsafe { (*supply()).fault_depth != 0 || (*supply()).count >= FAULT_PAGES }
}
pub fn defer_fault(ip: &mut u64) {
    unsafe {
        let state = &mut *supply();
        assert!(state.refill_ip != 0 && state.resume_ip == 0, "recursive frame replenishment");
        state.resume_ip = *ip as usize;
        *ip = state.refill_ip as u64;
    }
}
pub struct FaultGuard;
impl FaultGuard {
    pub fn enter() -> Self {
        unsafe {
            if (*supply()).fault_depth == 0 { (*supply()).fault_pages_current = 0; }
            (*supply()).fault_depth += 1;
        }
        Self
    }
}
impl Drop for FaultGuard {
    fn drop(&mut self) {
        unsafe {
            let state = &mut *supply();
            state.fault_depth -= 1;
            if state.fault_depth == 0 {
                state.fault_pages_peak = state.fault_pages_peak.max(state.fault_pages_current);
                assert!(state.fault_pages_current <= FAULT_PAGES, "fault exceeded donated-page bound");
            }
        }
    }
}
/// Consume a donated page. Faults use their guaranteed per-core reserve;
/// ordinary operations must receive a PageInput from their kernel caller.
pub fn take_page() -> Option<u64> {
    unsafe {
        if (*supply()).fault_depth != 0 {
            let page = (*supply()).take();
            if page.is_some() { (*supply()).fault_pages_current += 1; (*supply()).fault_pages_used += 1; }
            page
        }
        else if INPUT.is_null() { None } else { (*INPUT).take() }
    }
}
pub fn get_ref_count(page: u64) -> u8 {
    unsafe { (*supply()).ownership.references(page) }
}
pub fn inc_shared_count(page: u64) -> bool {
    unsafe { (*supply()).ownership.retain(page) }
}
pub fn release_page(page: u64) {
    if !unsafe { (*supply()).ownership.release_shared(page) } { return; }
    unsafe {
        let state = &mut *supply();
        if state.count < state.pages.len() { state.donate(page); return; }
        // The last reference becomes a returned-page list link. Preserve the
        // temporary window even when a COW operation already owns its mapping.
        let saved = paging2::temp_swap(page);
        (&raw mut paging2::TEMP_PAGE).cast::<u64>().write(state.returned_head);
        let _ = paging2::temp_swap(saved);
        state.returned_head = page;
        state.returned_count += 1;
    }
}
pub fn free_page_count() -> usize { unsafe { (*supply()).ownership.free_pages() } }
pub fn total_page_count() -> usize { unsafe { (*supply()).ownership.active } }

/// Physical page-number ceiling imposed by the active x86 paging mode/CPU.
pub fn physical_page_limit() -> u64 {
    use crate::paging2::{self, CpuMode, PAGE_SIZE};
    if paging2::cpu_mode() == CpuMode::Legacy { return (1u64 << 32) / PAGE_SIZE as u64; }
    let (max, _, _, _) = crate::x86::cpuid(0x8000_0000);
    let bits = if max >= 0x8000_0008 { crate::x86::cpuid(0x8000_0008).0 & 255 } else { 36 };
    (1u64 << bits.clamp(32, 52)) / PAGE_SIZE as u64
}

#[repr(C)]
pub(crate) struct Returns { output: *mut u64, capacity: usize, count: usize }
pub fn collect_returns(output: &mut [u64]) -> usize {
    let mut request = Returns { output: output.as_mut_ptr(), capacity: output.len(), count: 0 };
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)); }
    if cs & 3 == 0 { handle_returns(&mut request); }
    else { unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::RETURNED_FRAMES as u32,
        in("edx") &mut request as *mut Returns as usize); } }
    request.count
}
pub(crate) fn handle_returns(request: &mut Returns) {
    unsafe {
        let state = &mut *supply();
        while state.returned_head != 0 && request.count < request.capacity {
            let page = state.returned_head;
            let saved = paging2::temp_swap(page);
            state.returned_head = (&raw const paging2::TEMP_PAGE).cast::<u64>().read();
            let _ = paging2::temp_swap(saved);
            state.returned_count -= 1;
            request.output.add(request.count).write(page);
            request.count += 1;
        }
    }
}

pub(crate) fn input_available() -> bool {
    unsafe { !INPUT.is_null() && (*INPUT).count != 0 }
}
