//! A loader-reserved, physically contiguous pool placed last in kernel BSS.
//! After minimal BSP arch setup, allocate every AP stack/TLS first. Finishing
//! that phase opens the remaining pool to permanent low-memory allocations.
use core::alloc::Layout;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

// Six 128 KiB units leave a 128 KiB safety margin below physical 4 MiB.
// kernel.ld checks the non-pool footprint and the complete physical extent.
pub const CAPACITY: usize = 768 * 1024;
#[repr(align(131072))]
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
        Self { next: pool_start() }
    }
    pub fn allocate(&mut self, layout: Layout) -> Result<*mut u8, OutOfBootMemory> {
        let (at, next) = allocation(self.next, pool_end(), layout)?;
        self.next = next;
        Ok(at as *mut u8)
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
        let mut boot = unsafe { BootMemory::new() };
        let ap = boot
            .allocate(Layout::from_size_align(65536, 4096).unwrap())
            .unwrap() as usize;
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
