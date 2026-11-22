//! Compact metadata for usable RAM only. No allocation inside page operations;
//! the caller supplies the allocation bitmap.

#![forbid(unsafe_code)]

use arch_abi::page_supply::FrameLayout;
use alloc::vec::Vec;

const BOOTSTRAP_BYTES: usize = arch_abi::PAGE_SIZE;

const FREE: u8 = 0;
const OWNED: u8 = 1;

enum Bitmap {
    Bootstrap([u8; BOOTSTRAP_BYTES]),
    Full(Vec<u8>),
}

pub(super) struct Pool<'a> {
    layout: &'a FrameLayout,
    states: Bitmap,
    active: usize,
    free: usize,
    next: usize,
}

impl<'a> Pool<'a> {
    pub(super) fn new(layout: &'a FrameLayout, bootstrap_bytes: usize) -> Self {
        assert!(bootstrap_bytes <= BOOTSTRAP_BYTES);
        let active = layout.frame_count().min(bootstrap_bytes * 8);
        Self {
            layout,
            states: Bitmap::Bootstrap([0; BOOTSTRAP_BYTES]),
            active,
            free: active,
            next: 0,
        }
    }

    /// Copy the bootstrap state after allocating the new bitmap, since that
    /// allocation itself consumes bootstrap frames.
    pub(super) fn expand(&mut self, mut states: Vec<u8>) {
        assert!(matches!(self.states, Bitmap::Bootstrap(_)));
        assert_eq!(states.len(), self.layout.frame_count().div_ceil(8));
        let used_bytes = self.active.div_ceil(8);
        states[..used_bytes].copy_from_slice(&self.states()[..used_bytes]);
        // Padding bits from the last bootstrap byte must describe free RAM.
        if !self.active.is_multiple_of(8) {
            states[self.active / 8] &= (1 << (self.active % 8)) - 1;
        }
        self.free += self.layout.frame_count() - self.active;
        self.active = self.layout.frame_count();
        self.states = Bitmap::Full(states);
    }

    fn states(&self) -> &[u8] {
        match &self.states {
            Bitmap::Bootstrap(bytes) => bytes,
            Bitmap::Full(bytes) => bytes,
        }
    }

    fn state(&self, index: usize) -> u8 {
        if index >= self.active { return OWNED; }
        (self.states()[index / 8] >> (index % 8)) & 1
    }

    fn set(&mut self, index: usize, state: u8) {
        assert!(index < self.active);
        let bytes: &mut [u8] = match &mut self.states {
            Bitmap::Bootstrap(bytes) => bytes,
            Bitmap::Full(bytes) => bytes,
        };
        let byte = &mut bytes[index / 8];
        let shift = index % 8;
        if (*byte >> shift) & 1 == FREE { self.free -= 1; }
        if state == FREE { self.free += 1; }
        *byte = (*byte & !(1 << shift)) | (state << shift);
    }

    pub(super) fn mark(&mut self, first: u64, end: u64) {
        for &r in self.layout.regions() {
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
                let byte = start / 8;
                let bits = u32::from_le_bytes(self.states()[byte..byte + 4].try_into().unwrap());
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
        if self.free == 0 { return None; }
        let next = self.next.min(self.active);
        let index = self.find_free(next, self.active).or_else(|| self.find_free(0, next))?;
        self.set(index, OWNED);
        self.next = index + 1;
        Some(self.layout.frame(index))
    }

    pub(super) fn allocate_contiguous(&mut self, count: usize, limit: u64) -> Option<u64> {
        if count == 0 || count > self.free { return None; }
        for &region in self.layout.regions() {
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
            let index = self.layout.index(page).expect("DMA allocation outside RAM");
            self.release_index(index);
        }
    }

    pub(super) fn release(&mut self, page: u64) {
        let index = self.layout.index(page).expect("release outside managed RAM");
        self.release_index(index);
    }

    fn release_index(&mut self, index: usize) {
        assert_eq!(self.state(index), OWNED, "double release of physical page");
        self.set(index, FREE);
    }

    pub(super) fn frame_count(&self) -> usize { self.layout.frame_count() }
    pub(super) fn free_pages(&self) -> usize { self.free }
    pub(super) fn managed_pages(&self) -> usize { self.active }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use arch_abi::page_supply::MemoryRegion;

    fn full_pool(layout: &FrameLayout) -> Pool<'_> {
        let mut pool = Pool::new(layout, BOOTSTRAP_BYTES);
        pool.expand(vec![0; layout.frame_count().div_ceil(8)]);
        pool
    }

    fn layout(ranges: &[(u64, u64)], holes: &[(u64, u64)]) -> FrameLayout {
        let size = arch_abi::PAGE_SIZE as u64;
        let entries = ranges.iter().map(|&(first, end)| MemoryRegion {
            base: first * size, length: (end - first) * size, usable: true,
        });
        let mut layout = FrameLayout::from_memory_map(entries, u64::MAX);
        for &(first, end) in holes { layout.exclude(first, end); }
        layout
    }

    #[test]
    fn bitmap_crosses_words_and_excludes_address_holes() {
        let layout = layout(&[(300, 340), (0x100000, 0x100048)], &[(320, 327)]);
        let mut pool = full_pool(&layout);
        let expected: Vec<_> = (300..320).chain(327..340).chain(0x100000..0x100048).collect();
        assert_eq!(pool.free_pages(), expected.len());
        for page in &expected { assert_eq!(pool.allocate(), Some(*page)); }
        assert_eq!(pool.allocate(), None);
        assert_eq!(pool.free_pages(), 0);
        assert_eq!(pool.layout.index(321), None);
        for page in &expected { pool.release(*page); }
        assert_eq!(pool.free_pages(), expected.len());
        assert_eq!(pool.allocate(), Some(300));
    }

    #[test]
    fn contiguous_runs_never_cross_physical_holes_or_dma_limit() {
        let layout = layout(&[(256, 258), (300, 320), (0x100000, 0x100010)], &[]);
        let mut pool = full_pool(&layout);
        pool.mark(256, 258);
        assert_eq!(pool.allocate_contiguous(10, 0x100000), Some(300));
        pool.free_contiguous(300, 10);
        assert_eq!(pool.allocate_contiguous(21, u64::MAX), None);
        pool.mark(300, 320);
        assert_eq!(pool.allocate_contiguous(1, 0x100000), None);
        assert_eq!(pool.allocate(), Some(0x100000));
    }

    #[test]
    fn exclusive_release_recycles_high_frames() {
        let layout = layout(&[(0x100000000, 0x100000002)], &[]);
        let mut pool = full_pool(&layout);
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        assert!(a > u32::MAX as u64 && b > a);
        assert_eq!(pool.allocate(), None);
        pool.release(a);
        assert_eq!(pool.free_pages(), 1);
        assert_eq!(pool.allocate(), Some(a));
    }

    #[test]
    fn bootstrap_can_start_after_large_boot_modules() {
        let mut layout = layout(&[(256, 0x20000)], &[(512, 0x18000)]);
        layout.exclude(512, 512); // empty reservation changes nothing
        let mut pool = Pool::new(&layout, 8);
        pool.mark(256, 512);
        assert_eq!(pool.allocate(), None); // bitmap covers kernel pages first
        // Rebuild with a full bootstrap page: it reaches RAM after the module
        // by compact index, instead of stopping at a physical-address ceiling.
        let mut pool = Pool::new(&layout, BOOTSTRAP_BYTES);
        pool.mark(256, 512);
        assert_eq!(pool.allocate(), Some(0x18000));
    }
}
