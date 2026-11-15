//! CPU-local donated pages, with no allocator dependency or allocation callbacks.
use arch_abi::page_supply::{FrameOwnership, PageBootstrap, PageInput, PageSupply, FAULT_PAGES};
use crate::paging2;
#[thread_local]
static mut SUPPLY: PageSupply = PageSupply::new();
#[thread_local]
static mut INPUT: PageInput = PageInput::new();

fn supply() -> *mut PageSupply { &raw mut SUPPLY }
/// Kernel supplies resident ownership metadata, never executable callbacks.
pub fn configure(ownership: FrameOwnership) {
    unsafe { (*supply()).ownership = ownership; }
}
pub fn bootstrap(boot: PageBootstrap) {
    configure(boot.ownership);
    for page in boot.pages { unsafe { (*supply()).donate(page); } }
}
/// Only owned page numbers enter the operation; no caller storage is retained.
pub(crate) fn with_input<R>(pages: PageInput, operation: impl FnOnce() -> R) -> (R, PageInput) {
    struct Restore(PageInput);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { *(&raw mut INPUT) = core::mem::take(&mut self.0); } }
    }
    let _restore = Restore(unsafe { core::mem::replace(&mut *(&raw mut INPUT), pages) });
    let result = operation();
    let unused = unsafe { core::mem::take(&mut *(&raw mut INPUT)) };
    (result, unused)
}
pub fn supply_pages(mut pages: PageInput) -> (usize, PageInput) {
    let state = unsafe { &mut *supply() };
    assert!(state.fault_depth == 0);
    while state.count < state.pages.len() {
        let Some(page) = pages.take() else { break; };
        state.donate(page);
    }
    while pages.count < pages.pages.len() && state.returned_head != 0 {
        let page = state.returned_head;
        let mut next = [0; 8];
        crate::frames::read(page, 0, &mut next);
        state.returned_head = u64::from_ne_bytes(next);
        state.returned_count -= 1;
        pages.push(page);
    }
    (state.pages.len() - state.count, pages)
}
pub fn fault_pages_used() -> usize { unsafe { (*supply()).fault_pages_used } }
pub fn can_fault() -> bool {
    unsafe { (*supply()).fault_depth != 0 || (*supply()).count >= FAULT_PAGES }
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
        else { (*(&raw mut INPUT)).take() }
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

/// Physical page-number ceiling imposed by the active x86 paging mode/CPU.
pub fn physical_page_limit() -> u64 {
    use crate::paging2::{self, CpuMode, PAGE_SIZE};
    if paging2::cpu_mode() == CpuMode::Legacy { return (1u64 << 32) / PAGE_SIZE as u64; }
    let (max, _, _, _) = crate::x86::cpuid(0x8000_0000);
    let bits = if max >= 0x8000_0008 { crate::x86::cpuid(0x8000_0008).0 & 255 } else { 36 };
    (1u64 << bits.clamp(32, 52)) / PAGE_SIZE as u64
}

pub(crate) fn input_available() -> bool {
    unsafe { (*(&raw const INPUT)).count != 0 }
}
