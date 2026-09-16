//! Generic read-through cache for block devices.
//!
//! Filesystems see the same [`Disk`] contract whether the device underneath is
//! ATA, NVMe, a Multiboot image, or a volatile write overlay.  The cache is
//! composed once above those devices, so filesystem adapters contain no cache
//! policy and writes remain coherent at the block boundary.

use super::{Disk, Volume};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::cell::{Cell, RefCell};

const PAGE_SIZE: usize = 4096;
const PAGE_SECTORS: u64 = (PAGE_SIZE / 512) as u64;
/// Match the old lwext4 configuration: 512 filesystem-sized buffers. Pages
/// are allocated lazily, so an unused volume costs only its map header.
const PAGE_LIMIT: usize = 512;

// hits, misses, pages loaded, inner bytes. The block layer is serialized by
// the VFS on current kernels, so the profiler follows the cache's existing
// single-owner model.
static mut PROFILE: [u64; 4] = [0; 4];

fn profile_add(index: usize, value: u64) {
    if !crate::kernel::startup::profile_enabled() {
        return;
    }
    unsafe {
        let profile = &mut *core::ptr::addr_of_mut!(PROFILE);
        profile[index] = profile[index].wrapping_add(value);
    }
}

pub(crate) fn profile_reset() {
    unsafe { PROFILE = [0; 4]; }
}

pub(crate) fn profile() -> [u64; 4] {
    unsafe { *core::ptr::addr_of!(PROFILE) }
}

struct Page {
    data: Box<[u8]>,
    used: u64,
}

/// A 2 MiB LRU, write-through-invalidated cache over one disk.
pub struct CachedDisk {
    inner: &'static dyn Disk,
    pages: RefCell<BTreeMap<u64, Page>>,
    clock: Cell<u64>,
}

struct VolumeDisk {
    volume: Volume,
}

impl Disk for VolumeDisk {
    fn read(&self, lba: u64, buffer: &mut [u8]) -> u32 {
        self.volume.read(lba, buffer)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> u32 {
        self.volume.write(lba, buffer)
    }

    fn sectors(&self) -> u64 {
        self.volume.sectors
    }

    fn flush(&self) {
        self.volume.flush();
    }

    fn name(&self) -> &str {
        self.volume.disk().name()
    }
}

/// Give one already-bounded volume its own cache. Partition discovery stays
/// on the raw disk, and cache fills can never cross the volume boundary.
pub fn volume(volume: Volume) -> Volume {
    let inner: &'static dyn Disk = Box::leak(Box::new(VolumeDisk { volume }));
    let cached: &'static dyn Disk = Box::leak(Box::new(CachedDisk::wrap(inner)));
    Volume::whole(cached)
}

impl CachedDisk {
    pub fn wrap(inner: &'static dyn Disk) -> Self {
        Self {
            inner,
            pages: RefCell::new(BTreeMap::new()),
            clock: Cell::new(0),
        }
    }

    fn load_page(&self, page: u64) -> bool {
        let now = self.clock.get().wrapping_add(1);
        self.clock.set(now);
        let mut pages = self.pages.borrow_mut();
        if let Some(cached) = pages.get_mut(&page) {
            profile_add(0, 1);
            cached.used = now;
            return true;
        }
        drop(pages);

        profile_add(1, 1);

        let offset = page.saturating_mul(PAGE_SIZE as u64);
        let available = self
            .inner
            .sectors()
            .saturating_mul(512)
            .saturating_sub(offset)
            .min(PAGE_SIZE as u64) as usize;
        if available == 0 {
            return false;
        }
        let mut data = alloc::vec![0u8; PAGE_SIZE].into_boxed_slice();
        if self.inner.read(page.saturating_mul(PAGE_SECTORS), &mut data[..available])
            as usize
            != available.div_ceil(512)
        {
            return false;
        }
        profile_add(2, 1);
        profile_add(3, available as u64);

        let mut pages = self.pages.borrow_mut();
        if pages.len() == PAGE_LIMIT
            && let Some(oldest) = pages
                .iter()
                .min_by_key(|(_, cached)| cached.used)
                .map(|(&page, _)| page)
        {
            pages.remove(&oldest);
        }
        pages.insert(page, Page { data, used: now });
        true
    }

    fn invalidate(&self, lba: u64, len: usize) {
        if len == 0 {
            return;
        }
        let first = lba / PAGE_SECTORS;
        let last_sector = lba.saturating_add(len.div_ceil(512) as u64).saturating_sub(1);
        let last = last_sector / PAGE_SECTORS;
        let mut pages = self.pages.borrow_mut();
        for page in first..=last {
            pages.remove(&page);
        }
    }
}

impl Disk for CachedDisk {
    fn read(&self, lba: u64, buffer: &mut [u8]) -> u32 {
        let start = lba.saturating_mul(512);
        let valid = self
            .inner
            .sectors()
            .saturating_mul(512)
            .saturating_sub(start)
            .min(buffer.len() as u64) as usize;
        buffer[valid..].fill(0);
        let mut position = start;
        let mut copied = 0;
        while copied < valid {
            let page = position / PAGE_SIZE as u64;
            if !self.load_page(page) {
                return copied.div_ceil(512) as u32;
            }
            let within = (position % PAGE_SIZE as u64) as usize;
            let amount = (valid - copied).min(PAGE_SIZE - within);
            let pages = self.pages.borrow();
            let Some(cached) = pages.get(&page) else {
                return copied.div_ceil(512) as u32;
            };
            buffer[copied..copied + amount]
                .copy_from_slice(&cached.data[within..within + amount]);
            copied += amount;
            position += amount as u64;
        }
        valid.div_ceil(512) as u32
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> u32 {
        // Invalidate first: a short/failed write may still change a prefix.
        self.invalidate(lba, buffer.len());
        self.inner.write(lba, buffer)
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{CachedDisk, Disk, PAGE_LIMIT, PAGE_SECTORS, PAGE_SIZE};
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};

    struct MemoryDisk {
        bytes: RefCell<Vec<u8>>,
        reads: Cell<u32>,
        flushes: Cell<u32>,
    }

    impl Disk for MemoryDisk {
        fn read(&self, lba: u64, buffer: &mut [u8]) -> u32 {
            self.reads.set(self.reads.get() + 1);
            let start = lba as usize * 512;
            let bytes = self.bytes.borrow();
            let Some(source) = bytes.get(start..start + buffer.len()) else { return 0 };
            buffer.copy_from_slice(source);
            buffer.len().div_ceil(512) as u32
        }

        fn write(&self, lba: u64, buffer: &[u8]) -> u32 {
            let start = lba as usize * 512;
            let mut bytes = self.bytes.borrow_mut();
            let Some(destination) = bytes.get_mut(start..start + buffer.len()) else { return 0 };
            destination.copy_from_slice(buffer);
            buffer.len().div_ceil(512) as u32
        }

        fn flush(&self) { self.flushes.set(self.flushes.get() + 1); }

        fn sectors(&self) -> u64 { self.bytes.borrow().len().div_ceil(512) as u64 }
        fn name(&self) -> &str { "cache-test" }
    }

    #[test]
    fn reuses_pages_and_invalidates_overlapping_writes() {
        let inner = Box::leak(Box::new(MemoryDisk {
            bytes: RefCell::new((0..8192).map(|offset| offset as u8).collect()),
            reads: Cell::new(0),
            flushes: Cell::new(0),
        }));
        let cache = CachedDisk::wrap(inner);

        let mut first = [0; 32];
        assert_eq!(cache.read(0, &mut first), 1);
        assert_eq!(inner.reads.get(), 1);
        let mut same_page = [0; 512];
        assert_eq!(cache.read(4, &mut same_page), 1);
        assert_eq!(inner.reads.get(), 1);
        let mut next_page = [0; 512];
        assert_eq!(cache.read(8, &mut next_page), 1);
        assert_eq!(inner.reads.get(), 2);

        assert_eq!(cache.write(0, &vec![0xaa; 512]), 1);
        let mut changed = [0; 512];
        assert_eq!(cache.read(0, &mut changed), 1);
        assert_eq!(changed, [0xaa; 512]);
        assert_eq!(inner.reads.get(), 3);
        cache.flush();
        assert_eq!(inner.flushes.get(), 1);
    }

    #[test]
    fn large_read_is_cached_page_by_page() {
        let inner = Box::leak(Box::new(MemoryDisk {
            bytes: RefCell::new(vec![0x5a; 2 * PAGE_SIZE]),
            reads: Cell::new(0),
            flushes: Cell::new(0),
        }));
        let cache = CachedDisk::wrap(inner);
        let mut output = vec![0; 2 * PAGE_SIZE];

        assert_eq!(cache.read(0, &mut output), (2 * PAGE_SECTORS) as u32);
        assert_eq!(inner.reads.get(), 2);
        assert_eq!(output, vec![0x5a; 2 * PAGE_SIZE]);
        assert_eq!(cache.pages.borrow().len(), 2);
    }

    #[test]
    fn unaligned_large_read_caches_each_touched_page() {
        let inner = Box::leak(Box::new(MemoryDisk {
            bytes: RefCell::new(vec![0x5a; 3 * PAGE_SIZE]),
            reads: Cell::new(0),
            flushes: Cell::new(0),
        }));
        let cache = CachedDisk::wrap(inner);
        let mut output = vec![0; 2 * PAGE_SIZE];

        assert_eq!(cache.read(1, &mut output), (2 * PAGE_SECTORS) as u32);
        assert_eq!(inner.reads.get(), 3);
        assert_eq!(output, vec![0x5a; 2 * PAGE_SIZE]);
        assert_eq!(cache.pages.borrow().len(), 3);
    }

    #[test]
    fn evicts_the_least_recently_used_page() {
        let inner = Box::leak(Box::new(MemoryDisk {
            bytes: RefCell::new(vec![0; (PAGE_LIMIT + 1) * PAGE_SIZE]),
            reads: Cell::new(0),
            flushes: Cell::new(0),
        }));
        let cache = CachedDisk::wrap(inner);
        let mut sector = [0; 512];

        for page in 0..PAGE_LIMIT {
            assert_eq!(cache.read(page as u64 * PAGE_SECTORS, &mut sector), 1);
        }
        assert_eq!(cache.read(0, &mut sector), 1);
        assert_eq!(cache.read(PAGE_LIMIT as u64 * PAGE_SECTORS, &mut sector), 1);
        assert!(cache.pages.borrow().contains_key(&0));
        assert!(!cache.pages.borrow().contains_key(&1));

        let reads = inner.reads.get();
        assert_eq!(cache.read(0, &mut sector), 1);
        assert_eq!(inner.reads.get(), reads);
        assert_eq!(cache.read(PAGE_SECTORS, &mut sector), 1);
        assert_eq!(inner.reads.get(), reads + 1);
    }
}
