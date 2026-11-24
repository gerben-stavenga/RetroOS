//! Resident frame reference counts and explicitly donated per-CPU pages.
//! No allocator or reclaim operation crosses this boundary.
use core::sync::atomic::{AtomicU8, Ordering};

pub const FAULT_PAGES: usize = 5; // data + up to four x86 page-table levels
pub const SUPPLY_CAPACITY: usize = 64;

/// Owner-core reserve status on return from execution. Retired pages remain
/// owned by arch until transferred through `Memory::supply_pages`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyStatus {
    pub needed: usize,
    pub returned: usize,
}

#[derive(Clone, Copy)]
pub struct FrameRegion { pub first: u64, pub end: u64, pub offset: usize }

impl FrameRegion {
    fn index(regions: &[Self], page: u64) -> Option<usize> {
        let at = regions.partition_point(|r| r.end <= page);
        let region = regions.get(at)?;
        if page < region.first { return None; }
        Some(region.offset + usize::try_from(page - region.first).ok()?)
    }
}

/// Platform-supplied physical byte range. Reservations override usable RAM.
#[derive(Clone, Copy)]
pub struct MemoryRegion { pub base: u64, pub length: u64, pub usable: bool }

const MAX_REGIONS: usize = 256;

/// Boot-time layout of the managed RAM frames and their packed metadata indexes.
pub struct FrameLayout {
    regions: [FrameRegion; MAX_REGIONS],
    count: usize,
    pages: usize,
}

impl FrameLayout {
    pub const fn empty() -> Self {
        Self {
            regions: [FrameRegion { first: 0, end: 0, offset: 0 }; MAX_REGIONS],
            count: 0,
            pages: 0,
        }
    }

    pub fn from_memory_map(entries: impl Iterator<Item = MemoryRegion> + Clone, limit: u64) -> Self {
        let mut layout = Self::empty();
        let size = crate::PAGE_SIZE as u64;
        for entry in entries.clone().filter(|entry| entry.usable) {
            let first = entry.base.div_ceil(size).min(limit);
            let end = (entry.base.saturating_add(entry.length) / size).min(limit);
            layout.include(first, end);
        }
        for entry in entries.filter(|entry| !entry.usable) {
            let first = (entry.base / size).min(limit);
            let end = entry.base.saturating_add(entry.length).div_ceil(size).min(limit);
            layout.exclude(first, end);
        }
        layout
    }

    pub fn regions(&self) -> &[FrameRegion] {
        &self.regions[..self.count]
    }

    pub fn frame_count(&self) -> usize {
        self.pages
    }

    fn insert(&mut self, at: usize, region: FrameRegion) {
        assert!(self.count < MAX_REGIONS, "too many physical RAM regions");
        self.regions.copy_within(at..self.count, at + 1);
        self.regions[at] = region;
        self.count += 1;
    }

    fn remove(&mut self, at: usize) {
        self.regions.copy_within(at + 1..self.count, at);
        self.count -= 1;
    }

    fn include(&mut self, first: u64, end: u64) {
        if first >= end { return; }
        let at = self.regions[..self.count].partition_point(|r| r.first < first);
        self.insert(at, FrameRegion { first, end, offset: 0 });
        let mut i = 0;
        while i + 1 < self.count {
            if self.regions[i].end >= self.regions[i + 1].first {
                self.regions[i].end = self.regions[i].end.max(self.regions[i + 1].end);
                self.remove(i + 1);
            } else { i += 1; }
        }
        self.offsets();
    }

    /// Exclude a reserved physical frame range before publishing the layout.
    pub fn exclude(&mut self, first: u64, end: u64) {
        if first >= end { return; }
        let mut i = 0;
        while i < self.count {
            let region = self.regions[i];
            if first >= region.end || end <= region.first { i += 1; continue; }
            if first <= region.first && end >= region.end { self.remove(i); continue; }
            if first > region.first && end < region.end {
                self.regions[i].end = first;
                self.insert(i + 1, FrameRegion { first: end, ..region });
                i += 2;
            } else {
                self.regions[i].first = region.first.max(end);
                if first > region.first {
                    self.regions[i].first = region.first;
                    self.regions[i].end = first;
                }
                i += 1;
            }
        }
        self.offsets();
    }

    fn offsets(&mut self) {
        let mut offset = 0usize;
        for region in &mut self.regions[..self.count] {
            region.offset = offset;
            let length = usize::try_from(region.end - region.first)
                .expect("RAM metadata exceeds kernel address space");
            offset = offset.checked_add(length).expect("RAM metadata size overflow");
        }
        self.pages = offset;
    }

    pub fn index(&self, page: u64) -> Option<usize> {
        FrameRegion::index(self.regions(), page)
    }

    pub fn frame(&self, index: usize) -> u64 {
        assert!(index < self.pages);
        let at = self.regions().partition_point(|r| r.offset <= index) - 1;
        let region = self.regions[at];
        region.first + (index - region.offset) as u64
    }
}

/// Resident reference-count arena. Allocator bitmaps are separate.
/// Setup supplies the arena and region index; both remain resident while installed.
/// Callers must own the frame: zero here denotes one exclusive reference, not free RAM.
#[derive(Clone, Copy)]
pub struct FrameOwnership {
    pub regions: *const FrameRegion,
    pub regions_len: usize,
    pub counts: *mut u8,
    pub active: usize,
    pub zero_page: u64,
}
// Copies only carry addresses. Access requires the caller to uphold the
// resident-storage contract, and shared counters are accessed atomically.
unsafe impl Send for FrameOwnership {}
unsafe impl Sync for FrameOwnership {}

impl FrameOwnership {
    /// Pair the frozen RAM layout with the caller's resident counters.
    ///
    /// # Safety
    /// Counters must be zero-initialized storage of `storage_layout` size and
    /// alignment and remain resident while copies of this descriptor are in use.
    pub unsafe fn from_layout(layout: &'static FrameLayout, counts: *mut u8, zero_page: u64) -> Self {
        let regions = layout.regions();
        Self {
            regions: regions.as_ptr(),
            regions_len: regions.len(),
            counts,
            active: layout.frame_count(),
            zero_page,
        }
    }

    /// Layout of the zero-initialized counter storage supplied at setup.
    pub fn storage_layout(frames: usize) -> core::alloc::Layout {
        let bytes = frames.checked_next_multiple_of(crate::PAGE_SIZE)
            .expect("frame counter storage size overflow");
        core::alloc::Layout::from_size_align(bytes, crate::PAGE_SIZE).unwrap()
    }

    pub const EMPTY: Self = Self { regions: core::ptr::null(), regions_len: 0,
        counts: core::ptr::null_mut(), active: 0,
        zero_page: u64::MAX };
    unsafe fn index(&self, page: u64) -> Option<usize> {
        if self.regions_len == 0 { return None; }
        let regions = unsafe { core::slice::from_raw_parts(self.regions, self.regions_len) };
        let index = FrameRegion::index(regions, page)?;
        (index < self.active).then_some(index)
    }
    unsafe fn count(&self, index: usize) -> Option<&AtomicU8> {
        if self.counts.is_null() { return None; }
        Some(unsafe { &*self.counts.add(index).cast::<AtomicU8>() })
    }
    /// # Safety
    /// This descriptor and all referenced storage must be resident and valid.
    pub unsafe fn references(&self, page: u64) -> u8 {
        if page == self.zero_page { return 255; }
        let Some(index) = (unsafe { self.index(page) }) else { return 255; };
        let n = unsafe { self.count(index) }.map_or(0, |c| c.load(Ordering::Acquire));
        if n == 0 { 1 } else { n }
    }
    /// # Safety
    /// Metadata is resident; the caller owns a live reference to this page.
    pub unsafe fn retain(&self, page: u64) -> bool {
        if page == self.zero_page { return true; }
        let Some(index) = (unsafe { self.index(page) }) else { return false; };
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
        let Some(count) = (unsafe { self.count(index) }) else { return true; };
        let result = count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            if old < 2 { None } else { Some(if old == 2 { 0 } else { old - 1 }) }
        });
        result.is_err()
    }

}

/// One transferable reference to a physical page. The frame number is
/// public information; creating another owner requires proving ownership.
#[must_use = "transfer or release the owned page"]
#[repr(transparent)]
#[derive(Debug)]
pub struct OwnedPage(core::num::NonZeroU64);

impl OwnedPage {
    /// # Safety
    /// The caller transfers ownership of one live page reference. No other
    /// token may represent that same reference.
    pub unsafe fn from_number(number: u64) -> Self {
        Self(core::num::NonZeroU64::new(number).expect("owned page zero"))
    }

    pub const fn number(&self) -> u64 { self.0.get() }

    /// Transfer the reference through a frame-number interface.
    pub const fn into_number(self) -> u64 { self.number() }
}

/// Fixed-width donated-page stack shared by the hosted arch and its supervisor.
/// Access is exclusive to the owning CPU while it is stopped in the host.
#[repr(C, align(8))]
pub struct PageReserve {
    pages: [u64; SUPPLY_CAPACITY],
    count: u64,
}
impl Default for PageReserve {
    fn default() -> Self { Self::new() }
}

impl PageReserve {
    pub const fn new() -> Self { Self { pages: [0; SUPPLY_CAPACITY], count: 0 } }
    pub fn len(&self) -> usize { self.count as usize }
    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn take(&mut self) -> Option<OwnedPage> {
        if self.count == 0 { return None; }
        self.count -= 1;
        // Only donate() puts an owned reference in a live slot.
        Some(unsafe { OwnedPage::from_number(self.pages[self.count as usize]) })
    }
    pub fn donate(&mut self, page: OwnedPage) {
        assert!(self.len() < SUPPLY_CAPACITY, "page reserve is full");
        self.pages[self.count as usize] = page.into_number();
        self.count += 1;
    }
}

/// Owner-core-only exchange state. Kernel supplies owned pages; arch consumes
/// them without allocating. Retired pages remain owned until returned to kernel.
pub struct PageSupply {
    pub reserve: PageReserve,
    pub returned_head: u64,
    pub returned_count: usize,
    pub fault_depth: usize,
    pub fault_pages_used: usize,
    pub fault_pages_current: usize,
    pub fault_pages_peak: usize,
    pub ownership: FrameOwnership,
}
impl PageSupply {
    pub fn status(&self) -> SupplyStatus {
        SupplyStatus { needed: SUPPLY_CAPACITY - self.reserve.len(), returned: self.returned_count }
    }
    pub const fn new() -> Self { Self { reserve: PageReserve::new(),
        returned_head: 0, returned_count: 0,
        fault_depth: 0, fault_pages_used: 0, fault_pages_current: 0,
        fault_pages_peak: 0, ownership: FrameOwnership::EMPTY } }
    pub fn take(&mut self) -> Option<OwnedPage> { self.reserve.take() }
    pub fn donate(&mut self, page: OwnedPage) { self.reserve.donate(page); }
}
impl Default for PageSupply { fn default() -> Self { Self::new() } }

/// Initial AP donation, prepared by the BSP before the AP can fault.
pub struct PageBootstrap {
    pub ownership: FrameOwnership,
    pages: Option<[OwnedPage; FAULT_PAGES]>,
}

impl PageBootstrap {
    pub fn new(ownership: FrameOwnership, pages: [OwnedPage; FAULT_PAGES]) -> Self {
        Self { ownership, pages: Some(pages) }
    }

    pub fn take_pages(&mut self) -> [OwnedPage; FAULT_PAGES] {
        self.pages.take().expect("AP reserve already donated")
    }
}

/// Explicitly owned backing pages for one kernel-to-arch mapping operation.
pub struct PageInput { pages: [u64; SUPPLY_CAPACITY], count: usize }
impl PageInput {
    pub fn push(&mut self, page: OwnedPage) {
        assert!(self.count < SUPPLY_CAPACITY, "page batch is full");
        self.pages[self.count] = page.into_number();
        self.count += 1;
    }
    pub const fn new() -> Self { Self { pages: [0; SUPPLY_CAPACITY], count: 0 } }
    pub fn take(&mut self) -> Option<OwnedPage> {
        if self.count == 0 { return None; }
        self.count -= 1;
        // push() or the wire handoff transferred this reference into the batch.
        Some(unsafe { OwnedPage::from_number(self.pages[self.count]) })
    }
    pub const fn len(&self) -> usize { self.count }
    pub const fn is_empty(&self) -> bool { self.count == 0 }
    pub fn numbers(&self) -> &[u64] { &self.pages[..self.count] }

    pub(crate) fn into_raw_parts(self) -> ([u64; SUPPLY_CAPACITY], usize) {
        (self.pages, self.count)
    }

    /// # Safety
    /// The first `count` entries must each transfer one owned reference.
    pub(crate) unsafe fn from_raw_parts(pages: [u64; SUPPLY_CAPACITY], count: usize) -> Self {
        assert!(count <= SUPPLY_CAPACITY);
        Self { pages, count }
    }
}
impl Default for PageInput { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn frame_ownership_uses_the_frozen_layout_across_gaps() {
        let size = crate::PAGE_SIZE as u64;
        let high = 1 << 20;
        let map = [
            MemoryRegion { base: 256 * size, length: 6 * size, usable: true },
            MemoryRegion { base: 258 * size, length: size, usable: false },
            MemoryRegion { base: high * size, length: 2 * size, usable: true },
        ];
        let mut layout = FrameLayout::from_memory_map(map.into_iter(), u64::MAX);
        layout.exclude(260, 261);
        let layout = std::boxed::Box::leak(std::boxed::Box::new(layout));
        let expected = [256, 257, 259, 261, high, high + 1];
        assert_eq!(layout.frame_count(), expected.len());
        for (index, frame) in expected.into_iter().enumerate() {
            assert_eq!(layout.frame(index), frame);
            assert_eq!(layout.index(frame), Some(index));
        }
        assert_eq!(layout.index(258), None);
        assert_eq!(layout.index(260), None);

        #[repr(align(4096))]
        struct Counters([u8; crate::PAGE_SIZE]);
        let mut counters = Counters([0; crate::PAGE_SIZE]);
        let ownership = unsafe { FrameOwnership::from_layout(layout, counters.0.as_mut_ptr(), 0) };
        assert_eq!(ownership.regions, layout.regions().as_ptr());
        assert!(!unsafe { ownership.retain(260) });
        assert!(unsafe { ownership.retain(high + 1) });
        assert_eq!(&counters.0[..expected.len()], &[0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn concurrent_sharing_preserves_the_exclusive_owner() {
        let counts: [AtomicU8; 64] = core::array::from_fn(|_| AtomicU8::new(0));
        let region = [FrameRegion { first: 256, end: 320, offset: 0 }];
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let refs = FrameOwnership { regions: region.as_ptr(), regions_len: 1,
                        counts: counts.as_ptr().cast_mut().cast::<u8>(), active: 64,
                        zero_page: 0 };
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
