//! Demand-paged heap allocator with an indexed free-space tree (freestanding).
//!
//! A generic `GlobalAlloc` that carves allocations out of a fixed virtual
//! address window `[base, end)`. It is *demand-paged*: `extend_heap` only claims
//! virtual address space (bumps a cursor toward `end`) and never maps a page
//! itself — it assumes that touching an address in the window gets backed by the
//! platform (a `#PF` handler on bare metal). An optional embedder callback
//! returns whole free pages to that platform on deallocation. The allocator
//! otherwise knows only the two window bounds supplied via [`DemandHeap::init`].
//! Free-space indexing and page reclamation live here with `lib`'s other
//! freestanding primitives. Allocations round to a header-sized power of two
//! (32 bytes on the kernel target), keeping splits representable without
//! hidden headers on live allocations.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::{Acquire, Release, Relaxed}};

const PAGE_SIZE: usize = 4096;
const RETAINED_RANGES: usize = 64;

#[derive(Clone, Copy)]
struct Retained { start: usize, end: usize }
const EMPTY_RETAINED: Retained = Retained { start: 0, end: 0 };

/// Large-allocation instrumentation (≥ 100 KB), for diagnostic logging.
static LARGE_ALLOCS: AtomicU32 = AtomicU32::new(0);
static LARGE_FREES: AtomicU32 = AtomicU32::new(0);
static LARGE_REUSE: AtomicU32 = AtomicU32::new(0); // satisfied from free list (no extend)
static ALLOCATIONS: AtomicU32 = AtomicU32::new(0);
static DEALLOCATIONS: AtomicU32 = AtomicU32::new(0);

/// Successful heap allocation and deallocation calls since boot.
///
/// Reading these counters performs no allocation, so they are safe to include
/// in the profiler output. `allocations - deallocations` is the number of live
/// allocations modulo counter wrap.
pub fn allocation_counts() -> (u32, u32) {
    (
        ALLOCATIONS.load(Relaxed),
        DEALLOCATIONS.load(Relaxed),
    )
}

/// Opt-in allocator timings, in timestamp-counter ticks. The kernel switches
/// this alongside its event profiler; recording never allocates.
static PROFILE_ENABLED: AtomicBool = AtomicBool::new(false);
struct ProfileCounters { lock: AtomicBool, values: UnsafeCell<[u64; 6]> }
unsafe impl Sync for ProfileCounters {}
static PROFILE: ProfileCounters = ProfileCounters { lock: AtomicBool::new(false), values: UnsafeCell::new([0; 6]) };
impl ProfileCounters {
    fn with<T>(&self, f: impl FnOnce(&mut [u64; 6]) -> T) -> T {
        while self.lock.swap(true, Acquire) { core::hint::spin_loop(); }
        let result = f(unsafe { &mut *self.values.get() });
        self.lock.store(false, Release);
        result
    }
}

pub fn profile_enable(enabled: bool) { PROFILE_ENABLED.store(enabled, Relaxed); }
pub fn profile_reset() { PROFILE.with(|counters| *counters = [0; 6]); }
/// Allocation calls/ticks/max, followed by deallocation calls/ticks/max.
pub fn profile() -> [u64; 6] { PROFILE.with(|counters| *counters) }

fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    return unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(target_arch = "x86")]
    return unsafe { core::arch::x86::_rdtsc() };
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    0
}

struct ProfileSample { start: Option<u64>, offset: usize }
impl ProfileSample {
    fn start(offset: usize) -> Self {
        Self { start: PROFILE_ENABLED.load(Relaxed).then(ticks), offset }
    }
}
impl Drop for ProfileSample {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            let elapsed = ticks().wrapping_sub(start);
            PROFILE.with(|counters| {
                counters[self.offset] += 1;
                counters[self.offset + 1] += elapsed;
                counters[self.offset + 2] = counters[self.offset + 2].max(elapsed);
            });
        }
    }
}

#[path = "heap/tree.rs"]
mod tree;
use tree::{FreeBlock, FreeTree};

/// Keep every split representable as an intrusive free node. A power-of-two
/// quantum divides pages and every larger requested alignment, so no tiny
/// remainder is lost when an allocation is freed and coalesced again.
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>().next_power_of_two();
const SMALL_STEP: usize = core::mem::align_of::<FreeBlock>();
const SMALL_CLASSES: usize = 256 / SMALL_STEP + 1;
const SMALL_LIMIT: u8 = 16;

// Exact rounded sizes; allocations retain the caller's alignment contract.
// Include the page-sized scratch buffers used when expanding mount aliases.
fn small_class(size: usize, align: usize) -> Option<usize> {
    if align > SMALL_STEP { return None; }
    if size == PAGE_SIZE { Some(SMALL_CLASSES - 1) }
    else if size <= 256 { Some(size / SMALL_STEP - 1) }
    else { None }
}

const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

struct Inner {
    free: FreeTree,
    small_enabled: bool,
    small: [Option<NonNull<FreeBlock>>; SMALL_CLASSES],
    small_count: [u8; SMALL_CLASSES],
    /// Top of the virtual range claimed so far (grows toward `heap_end`).
    mapped_end: usize,
    /// Ceiling of the heap window (set in `init`).
    heap_end: usize,
    /// Return whole, unused pages to the platform's demand-paging pool.
    release: Option<fn(usize, usize)>,
    retained: [Retained; RETAINED_RANGES],
    retained_count: usize,
    retained_bytes: usize,
    retain_limit: usize,
}

/// Demand-paged heap over a `[base, end)` virtual window. Install as the
/// `#[global_allocator]` and call [`DemandHeap::init`] once after paging is up.
pub struct DemandHeap {
    inner: UnsafeCell<Inner>,
    locked: AtomicBool,
}
struct HeapGuard<'a>(&'a AtomicBool);
impl Drop for HeapGuard<'_> { fn drop(&mut self) { self.0.store(false, Release); } }

// All mutable allocator state is protected by locked. Fault replenishment
// uses resident physical metadata and must not reclaim through this heap
// while the lock is held.
unsafe impl Send for DemandHeap {}
unsafe impl Sync for DemandHeap {}

impl DemandHeap {
    fn lock(&self) -> HeapGuard<'_> {
        while self.locked.compare_exchange(false, true, Acquire, Relaxed).is_err() { core::hint::spin_loop(); }
        HeapGuard(&self.locked)
    }
    /// Refill policy must avoid recursive heap reclaim while an allocation owns it.
    pub fn is_locked(&self) -> bool { self.locked.load(Relaxed) }
    pub const fn new() -> Self {
        DemandHeap {
            locked: AtomicBool::new(false),
            inner: UnsafeCell::new(Inner { free: FreeTree::new(), small_enabled: false, small: [None; SMALL_CLASSES], small_count: [0; SMALL_CLASSES], mapped_end: 0, heap_end: 0, release: None,
                retained: [EMPTY_RETAINED; RETAINED_RANGES], retained_count: 0, retained_bytes: 0, retain_limit: 0 }),
        }
    }

    /// Retain a bounded set of rounded-size scratch allocations. Call during
    /// initialization, before this heap is shared. Cached blocks remain backed
    /// and are returned to the coalescing allocator if its window is exhausted.
    pub fn enable_small_cache(&self) {
        let _guard = self.lock();
        unsafe { (*self.inner.get()).small_enabled = true; }
    }

    /// Initialize the allocator over `[base, end)`. Call once, after the
    /// platform can back accesses in that window.
    pub fn init(&self, base: usize, end: usize) {
        self.init_with_release(base, end, None);
    }

    /// As `init`, with an optional callback receiving a page-aligned address
    /// and byte length on deallocation. It must not allocate or reenter this
    /// heap, and accesses to released pages must be demand-backed again.
    pub fn init_with_release(&self, base: usize, end: usize, release: Option<fn(usize, usize)>) {
        self.init_with_cached_release(base, end, release, 0);
    }

    /// Retain at most `cache_bytes` of free backing for reuse. Old ranges and
    /// excess bytes are released normally. Allocations remove their pages from
    /// this cache before any later free can evict them. No bookkeeping allocates.
    pub fn init_with_cached_release(&self, base: usize, end: usize, release: Option<fn(usize, usize)>, cache_bytes: usize) {
        let _guard = self.lock();
        let inner = unsafe { &mut *self.inner.get() };
        inner.free = FreeTree::new();
        inner.small_enabled = false;
        inner.small = [None; SMALL_CLASSES];
        inner.small_count = [0; SMALL_CLASSES];
        inner.heap_end = end & !(MIN_BLOCK_SIZE - 1);
        inner.mapped_end = align_up(base, MIN_BLOCK_SIZE).min(inner.heap_end);
        inner.release = release;
        inner.retained_count = 0;
        inner.retained_bytes = 0;
        inner.retain_limit = cache_bytes & !(PAGE_SIZE - 1);
    }
}

impl Default for DemandHeap {
    fn default() -> Self { Self::new() }
}

impl Inner {
    fn take_small(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        if !self.small_enabled { return None; }
        let class = small_class(size, align)?;
        let block = self.small[class]?;
        self.small[class] = unsafe { (*block.as_ptr()).next };
        self.small_count[class] -= 1;
        Some(block.as_ptr().cast())
    }

    fn put_small(&mut self, ptr: *mut u8, size: usize, align: usize) -> bool {
        if !self.small_enabled { return false; }
        let Some(class) = small_class(size, align) else { return false; };
        if self.small_count[class] == SMALL_LIMIT { return false; }
        let block = ptr.cast::<FreeBlock>();
        unsafe { block.write(FreeBlock::new(size, self.small[class])); }
        self.small[class] = NonNull::new(block);
        self.small_count[class] += 1;
        true
    }

    fn drain_small(&mut self) {
        for class in 0..SMALL_CLASSES {
            while let Some(block) = self.small[class] {
                let (size, next) = unsafe { ((*block.as_ptr()).size, (*block.as_ptr()).next) };
                self.small[class] = next;
                self.small_count[class] -= 1;
                self.free_region(block.as_ptr() as usize, size);
            }
        }
    }

    fn free_region(&mut self, addr: usize, size: usize) {
        let (merged, length) = self.add_free_region(addr, size);
        if self.release.is_some() {
            // Keep live boundaries and the surviving free-list header backed.
            let start = align_up(merged + MIN_BLOCK_SIZE, PAGE_SIZE).max(addr & !(PAGE_SIZE - 1));
            let end = ((merged + length) & !(PAGE_SIZE - 1))
                .min(align_up(addr + size + MIN_BLOCK_SIZE, PAGE_SIZE));
            if start < end { self.cache_or_release(start, end); }
        }
    }

    fn remove_retained(&mut self, index: usize) -> Retained {
        let range = self.retained[index];
        self.retained_bytes -= range.end - range.start;
        self.retained.copy_within(index + 1..self.retained_count, index);
        self.retained_count -= 1;
        range
    }

    fn release_range(&self, start: usize, end: usize) {
        if start < end && let Some(release) = self.release { release(start, end - start); }
    }

    fn append_retained(&mut self, start: usize, end: usize) {
        if start == end { return; }
        if self.retained_count == RETAINED_RANGES {
            self.release_range(start, end);
        } else {
            self.retained[self.retained_count] = Retained { start, end };
            self.retained_count += 1;
            self.retained_bytes += end - start;
        }
    }

    /// Remove allocated pages AND the new remainder's free-list header page.
    /// Only the untouched free fragments may subsequently be evicted.
    fn forget_retained(&mut self, start: usize, end: usize) {
        let mut i = 0;
        while i < self.retained_count {
            let range = self.retained[i];
            if start >= range.end || end <= range.start { i += 1; continue; }
            self.remove_retained(i);
            if range.start < start { self.append_retained(range.start, start); }
            if range.end > end { self.append_retained(end, range.end); }
        }
    }

    fn cache_or_release(&mut self, start: usize, end: usize) {
        if self.release.is_none() { return; }
        let keep = (end - start).min(self.retain_limit);
        if keep == 0 { self.release_range(start, end); return; }
        while self.retained_bytes + keep > self.retain_limit || self.retained_count == RETAINED_RANGES {
            let old = self.remove_retained(0);
            self.release_range(old.start, old.end);
        }
        self.append_retained(start, start + keep);
        self.release_range(start + keep, end);
    }

    /// Claim virtual address space (physical pages are demand-backed on access).
    fn extend_heap(&mut self, min_size: usize) -> bool {
        let pages_needed = min_size.div_ceil(PAGE_SIZE).max(4);
        let wanted = pages_needed.saturating_mul(PAGE_SIZE);
        let region_start = self.mapped_end;
        self.mapped_end = self.mapped_end.saturating_add(wanted).min(self.heap_end);
        let bytes = self.mapped_end - region_start;
        if bytes > 0 {
            self.add_free_region(region_start, bytes);
        }
        bytes >= wanted
    }

    /// Insert and coalesce in address order without scanning free blocks.
    fn add_free_region(&mut self, addr: usize, size: usize) -> (usize, usize) {
        self.free.insert_coalescing(addr, size)
    }

    fn alloc_from_tree(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let address = self.free.allocate(size, align.max(MIN_BLOCK_SIZE))?;
        self.forget_retained(address & !(PAGE_SIZE - 1), align_up(address + size + MIN_BLOCK_SIZE, PAGE_SIZE));
        Some(address as *mut u8)
    }

}

unsafe impl GlobalAlloc for DemandHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _sample = ProfileSample::start(0);
        let _guard = self.lock();
        let inner = unsafe { &mut *self.inner.get() };

        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), MIN_BLOCK_SIZE);
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        if let Some(ptr) = inner.take_small(size, align).or_else(|| inner.alloc_from_tree(size, align)) {
            if size >= 100_000 { LARGE_REUSE.fetch_add(1, Relaxed); }
            ALLOCATIONS.fetch_add(1, Relaxed);
            return ptr;
        }

        if size >= 100_000 { LARGE_ALLOCS.fetch_add(1, Relaxed); }
        if !inner.extend_heap(size + align) {
            inner.drain_small();
        }

        let ptr = inner.alloc_from_tree(size, align).unwrap_or(core::ptr::null_mut());
        if !ptr.is_null() {
            ALLOCATIONS.fetch_add(1, Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _sample = ProfileSample::start(3);
        let _guard = self.lock();
        let inner = unsafe { &mut *self.inner.get() };

        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), MIN_BLOCK_SIZE);
        if size >= 100_000 { LARGE_FREES.fetch_add(1, Relaxed); }
        DEALLOCATIONS.fetch_add(1, Relaxed);
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());
        if !inner.put_small(ptr, size, align) {
            inner.free_region(ptr as usize, size);
        }
    }
}
