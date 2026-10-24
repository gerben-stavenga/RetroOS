//! A loader-reserved, physically contiguous pool placed last in kernel BSS.
//! Minimal BSP setup reserves the shared kernel tables. Then allocate every
//! AP stack/TLS before other consumers. Finishing
//! that phase opens the remaining pool to permanent low-memory allocations.
use core::alloc::Layout;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

// Reservation capacity is independent of the pre-paging allocation ceiling.
// The tail can serve ISA DMA after flat segments/paging are established.
pub const CAPACITY: usize = 2 * 1024 * 1024;
pub const BOOT_MARGIN: usize = 128 * 1024;
pub fn boot_limit() -> usize {
    (crate::paging2::KERNEL_BASE + crate::paging2::BOOT_IDENTITY_END
        - crate::paging2::KERNEL_PHYS
        - BOOT_MARGIN)
        .min(pool_end())
}
#[repr(align(4096))]
struct Pool([u8; CAPACITY]);
#[used]
#[unsafe(link_section = ".boot_pool")]
static mut POOL: Pool = Pool([0; CAPACITY]);
// 0: unclaimed, 1: AP allocations, 2: permanent allocations (including DMA).
static PHASE: AtomicU8 = AtomicU8::new(0);
static NEXT: AtomicUsize = AtomicUsize::new(0);

pub fn pool_start() -> usize {
    unsafe { (&raw mut POOL.0) as usize }
}
pub fn pool_end() -> usize {
    pool_start() + CAPACITY
}

/// End of the entire loader-reserved image, including unused pool capacity.
pub fn end() -> usize {
    unsafe extern "C" {
        static _end: u8;
    }
    (&raw const _end) as usize
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutOfBootMemory;

fn allocation(
    next: usize,
    limit: usize,
    layout: Layout,
) -> Result<(usize, usize), OutOfBootMemory> {
    let at = next
        .checked_add(layout.align() - 1)
        .ok_or(OutOfBootMemory)?
        & !(layout.align() - 1);
    let end = at.checked_add(layout.size()).ok_or(OutOfBootMemory)?;
    if end > limit {
        return Err(OutOfBootMemory);
    }
    Ok((at, end))
}

/// Reserve the shared boot page tables before paging exists.
///
/// # Safety
/// BSP only, before claiming BootMemory or starting any AP. Returned addresses
/// are linked addresses, usable with the boot offset segments as well as paging.
pub(crate) unsafe fn allocate_bootstrap(layout: Layout) -> Result<*mut u8, OutOfBootMemory> {
    assert_eq!(PHASE.load(Ordering::Relaxed), 0);
    let next = NEXT.load(Ordering::Relaxed).max(pool_start());
    let (at, end) = allocation(next, boot_limit(), layout)?;
    NEXT.store(end, Ordering::Relaxed);
    Ok(at as *mut u8)
}

pub struct BootMemory {
    next: usize,
}
impl BootMemory {
    /// Claim the AP-allocation phase after minimal BSP arch initialization.
    /// The ELF loader has already reserved the entire pool as part of BSS.
    ///
    /// # Safety
    /// Call once on the BSP, before starting APs or allocating DMA buffers.
    pub unsafe fn new() -> Self {
        assert!(
            PHASE
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok(),
            "boot pool already claimed"
        );
        Self {
            next: NEXT.load(Ordering::Relaxed).max(pool_start()),
        }
    }
    pub fn allocate(&mut self, layout: Layout) -> Result<*mut u8, OutOfBootMemory> {
        let (at, next) = allocation(self.next, boot_limit(), layout)?;
        self.next = next;
        Ok(at as *mut u8)
    }
    /// Preview a sequence including alignment, without consuming any storage.
    pub fn can_allocate(&self, layouts: &[Layout]) -> bool {
        let mut next = self.next;
        for &layout in layouts {
            let Ok((_, end)) = allocation(next, boot_limit(), layout) else {
                return false;
            };
            next = end;
        }
        true
    }
    /// Close AP allocation before starting CPUs. Remaining pool space can now
    /// supply DMA buffers and other permanent, contiguous low-memory storage.
    pub fn finish(self) {
        NEXT.store(self.next, Ordering::Relaxed);
        PHASE.store(2, Ordering::Release);
    }
}

/// Permanent allocation after all AP stacks/TLS have been reserved. This never
/// uses the ordinary heap or the frame allocator. Exhaustion leaves the cursor
/// unchanged. The caller initializes the returned bytes before publishing them.
pub fn allocate_permanent(layout: Layout) -> Result<*mut u8, OutOfBootMemory> {
    if PHASE.load(Ordering::Acquire) != 2 {
        return Err(OutOfBootMemory);
    }
    let mut old = NEXT.load(Ordering::Relaxed);
    loop {
        let (at, next) = allocation(old, pool_end(), layout)?;
        match NEXT.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(at as *mut u8),
            Err(now) => old = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ap_allocations_precede_permanent_allocations() {
        let dma = Layout::from_size_align(131072, 131072).unwrap();
        assert_eq!(allocate_permanent(dma), Err(OutOfBootMemory));
        let tables = unsafe { allocate_bootstrap(Layout::from_size_align(16384, 4096).unwrap()) }
            .unwrap() as usize;
        assert_eq!(tables, pool_start());
        let mut boot = unsafe { BootMemory::new() };
        let ap = boot
            .allocate(Layout::from_size_align(65536, 4096).unwrap())
            .unwrap() as usize;
        assert!(ap >= tables + 16384);
        assert_eq!(allocate_permanent(dma), Err(OutOfBootMemory));
        boot.finish();
        let channel = allocate_permanent(dma).unwrap() as usize;
        assert!(channel >= ap + 65536);
        assert_eq!(channel % 131072, 0);
        let next = NEXT.load(Ordering::Relaxed);
        assert_eq!(
            allocate_permanent(Layout::from_size_align(CAPACITY, 1).unwrap()),
            Err(OutOfBootMemory)
        );
        assert_eq!(NEXT.load(Ordering::Relaxed), next);
    }
    #[test]
    fn preview_accounts_for_alignment_without_consuming() {
        let memory = BootMemory {
            next: (boot_limit() & !131071) - 131072,
        };
        let dma = Layout::from_size_align(131072, 131072).unwrap();
        assert!(memory.can_allocate(&[dma]));
        assert!(!memory.can_allocate(&[Layout::new::<u8>(), dma]));
        assert_eq!(memory.next, (boot_limit() & !131071) - 131072);
    }
    #[test]
    fn alignment_and_exact_exhaustion() {
        let (_, next) = allocation(0x300000, 0x320000, Layout::new::<u8>()).unwrap();
        assert_eq!(
            allocation(
                next,
                0x320000,
                Layout::from_size_align(65536, 65536).unwrap()
            ),
            Ok((0x310000, 0x320000))
        );
        assert_eq!(
            allocation(0x320000, 0x320000, Layout::new::<u8>()),
            Err(OutOfBootMemory)
        );
    }
    #[test]
    fn dma_alignment_and_overflow() {
        assert_eq!(
            allocation(
                0x310001,
                0x340000,
                Layout::from_size_align(131072, 131072).unwrap()
            ),
            Ok((0x320000, 0x340000))
        );
        assert_eq!(
            allocation(
                usize::MAX - 1,
                usize::MAX,
                Layout::from_size_align(4, 4).unwrap()
            ),
            Err(OutOfBootMemory)
        );
    }
}
