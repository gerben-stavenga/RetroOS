//! Compact metadata for usable RAM only. No allocation inside page operations;
//! the caller supplies the bitmap, directory, and individual shared-ref blocks.

pub(super) const REF_BLOCK_PAGES: usize = 64;
const MAX_REGIONS: usize = 256;
const FREE: u8 = 0;
const OWNED: u8 = 1;

#[derive(Clone, Copy)]
struct Region { first: u64, end: u64, offset: usize }
const EMPTY: Region = Region { first: 0, end: 0, offset: 0 };

pub(super) struct Pool {
    regions: [Region; MAX_REGIONS],
    count: usize,
    pub(super) pages: usize,
    states: *mut u8,
    active: usize,
    blocks: *mut *mut u8,
    free: usize,
    next: usize,
    pub(super) started: bool,
}

impl Pool {
    pub(super) const fn new() -> Self {
        Self { regions: [EMPTY; MAX_REGIONS], count: 0, pages: 0,
            states: core::ptr::null_mut(), active: 0, blocks: core::ptr::null_mut(),
            free: 0, next: 0, started: false }
    }

    fn insert(&mut self, at: usize, region: Region) {
        assert!(self.count < MAX_REGIONS, "too many physical RAM regions");
        self.regions.copy_within(at..self.count, at + 1);
        self.regions[at] = region;
        self.count += 1;
    }

    fn remove(&mut self, at: usize) {
        self.regions.copy_within(at + 1..self.count, at);
        self.count -= 1;
    }

    pub(super) fn include(&mut self, first: u64, end: u64) {
        if first >= end { return; }
        let at = self.regions[..self.count].partition_point(|r| r.first < first);
        self.insert(at, Region { first, end, offset: 0 });
        let mut i = 0;
        while i + 1 < self.count {
            if self.regions[i].end >= self.regions[i + 1].first {
                self.regions[i].end = self.regions[i].end.max(self.regions[i + 1].end);
                self.remove(i + 1);
            } else { i += 1; }
        }
        self.offsets();
    }

    /// Before the first allocation, reservations can be omitted altogether.
    /// This also lets the bootstrap bitmap cover free RAM after large modules.
    pub(super) fn exclude(&mut self, first: u64, end: u64) {
        if first >= end { return; }
        assert!(!self.started, "cannot move live physical page metadata");
        let mut i = 0;
        while i < self.count {
            let region = self.regions[i];
            if first >= region.end || end <= region.first { i += 1; continue; }
            if first <= region.first && end >= region.end { self.remove(i); continue; }
            if first > region.first && end < region.end {
                self.regions[i].end = first;
                self.insert(i + 1, Region { first: end, ..region });
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

    fn index(&self, page: u64) -> Option<usize> {
        let at = self.regions[..self.count].partition_point(|r| r.end <= page);
        let region = self.regions.get(at).filter(|_| at < self.count)?;
        (page >= region.first).then(|| region.offset + (page - region.first) as usize)
    }

    fn page(&self, index: usize) -> u64 {
        let at = self.regions[..self.count].partition_point(|r| r.offset <= index) - 1;
        let region = self.regions[at];
        region.first + (index - region.offset) as u64
    }

    pub(super) unsafe fn bootstrap(&mut self, states: *mut u8, bytes: usize) {
        self.states = states;
        self.active = self.pages.min(bytes * 8);
        unsafe { core::ptr::write_bytes(states, 0, bytes); }
        self.free = self.active;
        self.next = 0;
    }

    /// Buffers are zeroed and remain live for the life of the pool. Copy after
    /// both allocations: backing their pages has changed bootstrap ownership.
    pub(super) unsafe fn expand(&mut self, states: *mut u8, blocks: *mut *mut u8) {
        assert!(self.blocks.is_null(), "physical metadata already expanded");
        unsafe { core::ptr::copy_nonoverlapping(self.states, states, self.active.div_ceil(8)); }
        // Padding bits from the last bootstrap byte must describe free RAM.
        if !self.active.is_multiple_of(8) {
            unsafe { *states.add(self.active / 8) &= (1 << (self.active % 8)) - 1; }
        }
        self.free += self.pages - self.active;
        self.active = self.pages;
        self.states = states;
        self.blocks = blocks;
    }

    fn state(&self, index: usize) -> u8 {
        if index >= self.active { return OWNED; }
        unsafe { (*self.states.add(index / 8) >> (index % 8)) & 1 }
    }

    fn set(&mut self, index: usize, state: u8) {
        let old = self.state(index);
        assert!(index < self.active);
        if old == FREE { self.free -= 1; }
        if state == FREE { self.free += 1; }
        unsafe {
            let byte = self.states.add(index / 8);
            let shift = index % 8;
            *byte = (*byte & !(1 << shift)) | (state << shift);
        }
    }

    pub(super) fn mark(&mut self, first: u64, end: u64) {
        for i in 0..self.count {
            let r = self.regions[i];
            let lo = first.max(r.first);
            let hi = end.min(r.end);
            if lo >= hi { continue; }
            let start = r.offset + (lo - r.first) as usize;
            let stop = (r.offset + (hi - r.first) as usize).min(self.active);
            for index in start..stop {
                self.set(index, OWNED);
            }
        }
    }

    fn find_free(&self, mut start: usize, end: usize) -> Option<usize> {
        while start < end {
            if start.is_multiple_of(32) && end - start >= 32 {
                let bits = unsafe { self.states.add(start / 8).cast::<u32>().read_unaligned() };
                let available = !bits;
                if available != 0 { return Some(start + available.trailing_zeros() as usize); }
                start += 32;
            } else {
                if self.state(start) == FREE { return Some(start); }
                start += 1;
            }
        }
        None
    }

    pub(super) fn allocate(&mut self) -> Option<u64> {
        self.started = true;
        if self.free == 0 { return None; }
        let next = self.next.min(self.active);
        let index = self.find_free(next, self.active).or_else(|| self.find_free(0, next))?;
        self.set(index, OWNED);
        self.next = index + 1;
        Some(self.page(index))
    }

    pub(super) fn allocate_contiguous(&mut self, count: usize, limit: u64) -> Option<u64> {
        self.started = true;
        if count == 0 || count > self.free { return None; }
        for i in 0..self.count {
            let region = self.regions[i];
            let end = region.end.min(limit);
            if end <= region.first { continue; }
            let stop = (region.offset + (end - region.first) as usize).min(self.active);
            let mut at = region.offset;
            while count <= stop.saturating_sub(at) {
                let Some(free) = self.find_free(at, stop) else { break; };
                at = free;
                if count > stop - at { break; }
                let mut length = 1;
                while length < count && self.state(at + length) == FREE { length += 1; }
                if length == count {
                    for index in at..at + count { self.set(index, OWNED); }
                    return Some(region.first + (at - region.offset) as u64);
                }
                at += length + 1;
            }
        }
        None
    }

    pub(super) fn free_contiguous(&mut self, first: u64, count: usize) {
        let end = first.checked_add(count as u64).expect("DMA range overflow");
        for page in first..end {
            let index = self.index(page).expect("DMA allocation outside RAM");
            assert_eq!(self.refs(page), 1, "invalid DMA allocation");
            self.set(index, FREE);
        }
    }

    pub(super) fn refs(&self, page: u64) -> u8 {
        let Some(index) = self.index(page) else { return 255; };
        if index >= self.active { return 255; }
        if self.state(index) == FREE { return 0; }
        if self.blocks.is_null() { return 1; }
        unsafe {
            let block = *self.blocks.add(index / REF_BLOCK_PAGES);
            if block.is_null() { return 1; }
            let count = *block.add(index % REF_BLOCK_PAGES);
            if count == 0 { 1 } else { count }
        }
    }

    /// Request one zeroed block outside the mutable pool borrow: its heap
    /// backing can recursively call allocate() during a kernel page fault.
    pub(super) fn missing_ref_block(&self, page: u64) -> Option<usize> {
        let index = self.index(page)?;
        if self.state(index) != OWNED || self.blocks.is_null() { return None; }
        let block = index / REF_BLOCK_PAGES;
        unsafe { (*self.blocks.add(block)).is_null().then_some(block) }
    }

    pub(super) unsafe fn install_ref_block(&mut self, block: usize, data: *mut u8) -> bool {
        unsafe {
            let slot = self.blocks.add(block);
            if !(*slot).is_null() { return false; }
            *slot = data;
            true
        }
    }

    pub(super) fn retain(&mut self, page: u64) -> bool {
        let Some(index) = self.index(page) else { return false; };
        if self.state(index) != OWNED || self.blocks.is_null() { return false; }
        unsafe {
            let block = *self.blocks.add(index / REF_BLOCK_PAGES);
            if block.is_null() { return false; }
            let count = block.add(index % REF_BLOCK_PAGES);
            let old = if *count == 0 { 1 } else { *count };
            assert!(old < 254, "physical page refcount overflow");
            *count = old + 1;
        }
        true
    }

    /// Return an unused refcount block for deallocation outside the pool borrow.
    pub(super) fn release(&mut self, page: u64) -> Option<*mut u8> {
        let index = self.index(page)?;
        assert!(index < self.active && self.state(index) == OWNED, "double free of physical page");
        if self.refs(page) == 1 {
            self.set(index, FREE);
            return None;
        }
        unsafe {
            let slot = self.blocks.add(index / REF_BLOCK_PAGES);
            let data = *slot;
            let count = data.add(index % REF_BLOCK_PAGES);
            assert!(*count >= 2, "invalid shared physical page");
            *count -= 1;
            if *count == 1 {
                *count = 0;
                if (0..REF_BLOCK_PAGES).all(|i| *data.add(i) == 0) {
                    *slot = core::ptr::null_mut();
                    return Some(data);
                }
            }
        }
        None
    }

    pub(super) fn free_pages(&self) -> usize { self.free }
    pub(super) fn managed_pages(&self) -> usize { self.active }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};

    struct Fixture {
        pool: Pool,
        _bootstrap: Vec<u8>,
        _bitmap: Vec<u8>,
        _directory: Vec<*mut u8>,
        blocks: Vec<Box<[u8; REF_BLOCK_PAGES]>>,
    }
    impl Fixture {
        fn new(ranges: &[(u64, u64)], holes: &[(u64, u64)]) -> Self {
            let mut pool = Pool::new();
            for &(first, end) in ranges { pool.include(first, end); }
            for &(first, end) in holes { pool.exclude(first, end); }
            let mut bootstrap = vec![0; pool.pages.div_ceil(8).min(4096)];
            unsafe { pool.bootstrap(bootstrap.as_mut_ptr(), bootstrap.len()); }
            let mut bitmap = vec![0; pool.pages.div_ceil(8)];
            let mut directory = vec![core::ptr::null_mut(); pool.pages.div_ceil(REF_BLOCK_PAGES)];
            unsafe { pool.expand(bitmap.as_mut_ptr(), directory.as_mut_ptr()); }
            Self { pool, _bootstrap: bootstrap, _bitmap: bitmap, _directory: directory, blocks: vec![] }
        }
        fn retain(&mut self, page: u64) -> bool {
            if let Some(index) = self.pool.missing_ref_block(page) {
                let mut block = Box::new([0; REF_BLOCK_PAGES]);
                assert!(unsafe { self.pool.install_ref_block(index, block.as_mut_ptr()) });
                self.blocks.push(block);
            }
            self.pool.retain(page)
        }
    }

    #[test]
    fn bitmap_crosses_words_and_excludes_address_holes() {
        let mut f = Fixture::new(&[(300, 340), (0x100000, 0x100048)], &[(320, 327)]);
        let expected: Vec<_> = (300..320).chain(327..340).chain(0x100000..0x100048).collect();
        assert_eq!(f.pool.free_pages(), expected.len());
        for page in &expected { assert_eq!(f.pool.allocate(), Some(*page)); }
        assert_eq!(f.pool.allocate(), None);
        assert_eq!(f.pool.free_pages(), 0);
        assert_eq!(f.pool.refs(321), 255);
        for page in &expected { assert_eq!(f.pool.release(*page), None); }
        assert_eq!(f.pool.free_pages(), expected.len());
        assert_eq!(f.pool.allocate(), Some(300));
    }

    #[test]
    fn contiguous_runs_never_cross_physical_holes_or_dma_limit() {
        let mut f = Fixture::new(&[(256, 258), (300, 320), (0x100000, 0x100010)], &[]);
        f.pool.mark(256, 258);
        assert_eq!(f.pool.allocate_contiguous(10, 0x100000), Some(300));
        f.pool.free_contiguous(300, 10);
        assert_eq!(f.pool.allocate_contiguous(21, u64::MAX), None);
        f.pool.mark(300, 320);
        assert_eq!(f.pool.allocate_contiguous(1, 0x100000), None);
        assert_eq!(f.pool.allocate(), Some(0x100000));
        assert_eq!(f.pool.refs(0x100000), 1);
    }

    #[test]
    fn shared_counts_disappear_at_one_and_last_release_frees_page() {
        let mut f = Fixture::new(&[(0x100000000, 0x100000100)], &[]);
        let a = f.pool.allocate().unwrap();
        let b = f.pool.allocate().unwrap();
        assert!(a > u32::MAX as u64);
        assert_eq!(f.pool.refs(a), 1);
        assert!(f.retain(a) && f.retain(b) && f.retain(a));
        assert_eq!(f.blocks.len(), 1);
        assert_eq!(f.pool.refs(a), 3);
        assert_eq!(f.pool.release(a), None);
        assert_eq!(f.pool.release(a), None);
        assert_eq!(f.pool.refs(a), 1);
        assert_eq!(f.pool.release(b), Some(f.blocks[0].as_mut_ptr()));
        assert_eq!(f.pool.missing_ref_block(a), Some(0));
        assert_eq!(f.pool.refs(a), 1);
        assert_eq!(f.pool.release(a), None);
        assert_eq!(f.pool.refs(a), 0);
        assert_eq!(f.pool.free_pages(), f.pool.pages - 1);
        assert!(!f.retain(a));
    }

    #[test]
    fn bootstrap_can_start_after_large_boot_modules() {
        let mut pool = Pool::new();
        pool.include(256, 0x20000);
        pool.exclude(512, 0x18000);
        pool.exclude(512, 512); // empty reservation changes nothing
        let mut bits = [0u8; 8];
        unsafe { pool.bootstrap(bits.as_mut_ptr(), bits.len()); }
        pool.mark(256, 512);
        assert_eq!(pool.allocate(), None); // bitmap covers kernel pages first
        // Rebuild with a full bootstrap page: it reaches RAM after the module
        // by compact index, instead of stopping at a physical-address ceiling.
        let mut bits = [0u8; 4096];
        unsafe { pool.bootstrap(bits.as_mut_ptr(), bits.len()); }
        pool.mark(256, 512);
        assert_eq!(pool.allocate(), Some(0x18000));
    }
}
