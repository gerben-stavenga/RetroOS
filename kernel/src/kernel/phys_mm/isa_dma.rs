//! ISA DMA channel buffers: kernel-owned lifetime and low-memory constraints.
use arch_abi::PAGE_SIZE;
use core::alloc::Layout;

/// Platform access to permanent, physically contiguous boot storage.
pub struct LowDmaMemory {
    /// Return (virtual byte address, physical page number), aligned to layout.
    pub reserve: fn(Layout) -> Option<(usize, u64)>,
    /// Remove the ordinary cached alias before the driver maps it uncached.
    pub unmap: fn(usize),
}
static MEMORY: AtomicPtr<LowDmaMemory> = AtomicPtr::new(core::ptr::null_mut());
pub fn install_low_dma_memory(memory: &'static LowDmaMemory) {
    assert!(MEMORY.compare_exchange(core::ptr::null_mut(),
        core::ptr::from_ref(memory).cast_mut(), Ordering::Release, Ordering::Relaxed).is_ok(),
        "ISA DMA memory already installed");
}
fn memory() -> &'static LowDmaMemory {
    let pointer = MEMORY.load(Ordering::Acquire);
    assert!(!pointer.is_null(), "ISA DMA memory not installed");
    // Installation accepts only immutable, permanent callback tables.
    unsafe { &*pointer }
}

/// Largest physical page usable for ISA DMA (addresses are 24-bit, < 16 MB).
const DMA_MAX_PAGE: usize = 0x100_0000 / PAGE_SIZE;
// Physical pages of lazily allocated channel buffers. usize::MAX serializes
// first allocation; trap entry has IRQs disabled, so a same-CPU interrupt
// cannot reenter while its slot is being initialized.
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
static DMA_CHANNELS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

/// Physical page of a channel's permanent low-memory buffer (0 if unavailable).
/// Early boot reservations must be closed first. Allocate only channels
/// actually requested; the entire shared pool remains loader-reserved.
pub fn dma_channel_buf(ch: usize) -> u64 {
    let Some(slot) = DMA_CHANNELS.get(ch) else { return 0; };
    loop {
        let page = slot.load(Ordering::Acquire);
        if page == usize::MAX { core::hint::spin_loop(); continue; }
        if page != 0 { return page as u64; }
        if slot.compare_exchange(0, usize::MAX, Ordering::Acquire, Ordering::Relaxed).is_ok() { break; }
    }
    let bytes = if ch >= 4 { 128 * 1024 } else { 64 * 1024 };
    let Some((storage, page)) = (memory().reserve)(Layout::from_size_align(bytes, bytes).unwrap()) else {
        slot.store(0, Ordering::Release);
        return 0;
    };
    assert!(page != 0 && page.is_multiple_of((bytes / PAGE_SIZE) as u64)
        && page.checked_add((bytes / PAGE_SIZE) as u64).is_some_and(|end| end <= DMA_MAX_PAGE as u64),
        "boot pool violates ISA DMA address constraints");
    // The driver maps these frames uncached. Remove the ordinary cached alias;
    // physical ownership stays with the pool, already reserved as kernel BSS.
    for offset in (0..bytes).step_by(PAGE_SIZE) { (memory().unmap)(storage + offset); }
    debug_assert!((page..page + (bytes / PAGE_SIZE) as u64).all(|p| super::get_ref_count(p) == 1));
    slot.store(page as usize, Ordering::Release);
    page
}
