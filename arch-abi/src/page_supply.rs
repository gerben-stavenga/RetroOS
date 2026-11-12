//! Resident frame ownership metadata and explicitly donated per-CPU pages.
//! No allocator or reclaim operation crosses this boundary.
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const FAULT_PAGES: usize = 5; // data + up to four x86 page-table levels
pub const SUPPLY_CAPACITY: usize = 64;
pub const REF_BLOCK_PAGES: usize = 64;

#[derive(Clone, Copy)]
pub struct FrameRegion { pub first: u64, pub end: u64, pub offset: usize }

/// Non-owning access to resident, kernel-owned ownership metadata.
/// Regions and metadata storage remain resident and alive while installed.
#[derive(Clone, Copy)]
pub struct FrameOwnership {
    pub regions: *const FrameRegion,
    pub regions_len: usize,
    pub bitmap: *const u8,
    pub blocks: *const *mut u8,
    pub active: usize,
    pub free: *const AtomicUsize,
    pub zero_page: u64,
}
impl FrameOwnership {
    pub const EMPTY: Self = Self { regions: core::ptr::null(), regions_len: 0,
        bitmap: core::ptr::null(), blocks: core::ptr::null(), active: 0,
        free: core::ptr::null(), zero_page: u64::MAX };
    unsafe fn index(&self, page: u64) -> Option<usize> {
        if self.regions_len == 0 { return None; }
        let regions = unsafe { core::slice::from_raw_parts(self.regions, self.regions_len) };
        let at = regions.partition_point(|r| r.end <= page);
        let r = regions.get(at)?;
        if page < r.first { return None; }
        let index = r.offset + usize::try_from(page - r.first).ok()?;
        (index < self.active).then_some(index)
    }
    unsafe fn count(&self, index: usize) -> Option<&AtomicU8> {
        if self.blocks.is_null() { return None; }
        let block = unsafe { *self.blocks.add(index / REF_BLOCK_PAGES) };
        if block.is_null() { return None; }
        Some(unsafe { &*block.add(index % REF_BLOCK_PAGES).cast::<AtomicU8>() })
    }
    /// # Safety
    /// This descriptor and all referenced storage must be resident and valid.
    pub unsafe fn references(&self, page: u64) -> u8 {
        if page == self.zero_page { return 255; }
        let Some(index) = (unsafe { self.index(page) }) else { return 255; };
        if unsafe { ((&*self.bitmap.add(index / 8).cast::<AtomicU8>()).load(Ordering::Acquire) >> (index % 8)) & 1 } == 0 { return 0; }
        let n = unsafe { self.count(index) }.map_or(0, |c| c.load(Ordering::Acquire));
        if n == 0 { 1 } else { n }
    }
    /// # Safety
    /// Metadata is resident; the caller owns a live reference to this page.
    pub unsafe fn retain(&self, page: u64) -> bool {
        if page == self.zero_page { return true; }
        let Some(index) = (unsafe { self.index(page) }) else { return false; };
        if unsafe { ((&*self.bitmap.add(index / 8).cast::<AtomicU8>()).load(Ordering::Acquire) >> (index % 8)) & 1 } == 0 { return false; }
        let Some(count) = (unsafe { self.count(index) }) else { return false; };
        count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            assert!(old < 254, "physical page refcount overflow");
            Some(if old == 0 { 2 } else { old + 1 })
        }).unwrap();
        true
    }
    /// Drop a shared reference, or transfer the last reference to the caller.
    /// An exclusive page retains count one until its new owner releases it.
    /// # Safety
    /// Metadata is resident; the caller owns the reference being transferred.
    pub unsafe fn release_shared(&self, page: u64) -> bool {
        if page == self.zero_page { return false; }
        let Some(index) = (unsafe { self.index(page) }) else { return false; };
        assert_ne!(unsafe { ((&*self.bitmap.add(index / 8).cast::<AtomicU8>()).load(Ordering::Acquire) >> (index % 8)) & 1 }, 0,
            "double release of physical page");
        let Some(count) = (unsafe { self.count(index) }) else { return true; };
        let result = count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            if old < 2 { None } else { Some(if old == 2 { 0 } else { old - 1 }) }
        });
        result.is_err()
    }
    /// # Safety
    /// The descriptor's free counter must be resident and valid if non-null.
    pub unsafe fn free_pages(&self) -> usize {
        if self.free.is_null() { 0 } else { unsafe { &*self.free }.load(Ordering::Relaxed) }
    }
}

/// Owner-core-only exchange state. Kernel supplies owned pages; arch consumes
/// them without allocating. Retired pages remain owned until returned to kernel.
pub struct PageSupply {
    pub pages: [u64; SUPPLY_CAPACITY],
    pub count: usize,
    pub returned_head: u64,
    pub returned_count: usize,
    pub resume_ip: usize,
    pub refill_ip: usize,
    pub fault_depth: usize,
    pub fault_pages_used: usize,
    pub fault_pages_current: usize,
    pub fault_pages_peak: usize,
    pub refills: usize,
    pub ownership: FrameOwnership,
}
impl PageSupply {
    pub const fn new() -> Self { Self { pages: [0; SUPPLY_CAPACITY], count: 0,
        returned_head: 0, returned_count: 0, resume_ip: 0, refill_ip: 0,
        fault_depth: 0, fault_pages_used: 0, fault_pages_current: 0,
        fault_pages_peak: 0, refills: 0, ownership: FrameOwnership::EMPTY } }
    pub fn take(&mut self) -> Option<u64> {
        if self.count == 0 { return None; }
        self.count -= 1;
        Some(self.pages[self.count])
    }
    pub fn donate(&mut self, page: u64) {
        assert!(page != 0 && self.count < SUPPLY_CAPACITY, "invalid frame donation");
        self.pages[self.count] = page;
        self.count += 1;
    }
}
impl Default for PageSupply { fn default() -> Self { Self::new() } }

/// Initial AP donation, prepared by the BSP before the AP can fault.
#[derive(Clone, Copy)]
pub struct PageBootstrap {
    pub ownership: FrameOwnership,
    pub pages: [u64; FAULT_PAGES],
    pub refill_ip: usize,
}

/// Explicitly owned backing pages for one kernel-to-arch mapping operation.
pub struct PageInput { pub pages: [u64; SUPPLY_CAPACITY], pub count: usize }
impl PageInput {
    pub const fn new() -> Self { Self { pages: [0; SUPPLY_CAPACITY], count: 0 } }
    pub fn take(&mut self) -> Option<u64> {
        if self.count == 0 { None } else { self.count -= 1; Some(self.pages[self.count]) }
    }
}
impl Default for PageInput { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn concurrent_sharing_preserves_the_exclusive_owner() {
        let counts: [AtomicU8; REF_BLOCK_PAGES] = core::array::from_fn(|_| AtomicU8::new(0));
        let region = [FrameRegion { first: 256, end: 320, offset: 0 }];
        let bitmap = [255u8; 8];
        let free = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let blocks = [counts.as_ptr().cast_mut().cast::<u8>()];
                    let refs = FrameOwnership { regions: region.as_ptr(), regions_len: 1,
                        bitmap: bitmap.as_ptr(), blocks: blocks.as_ptr(), active: 64,
                        free: &free, zero_page: 0 };
                    for _ in 0..1000 {
                        assert!(unsafe { refs.retain(256) });
                        assert!(!unsafe { refs.release_shared(256) });
                    }
                    assert_eq!(unsafe { refs.references(0) }, 255);
                    assert_eq!(unsafe { refs.references(255) }, 255);
                });
            }
        });
        assert_eq!(counts[0].load(Ordering::Acquire), 0, "one implicit owner remains");
    }
}
