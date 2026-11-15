//! Allocator over explicitly supplied resident memory.
//! The owner maps storage before donating it with `Heap::add_region`.
//! Allocation never extends virtual memory or invokes a backing callback.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::{Acquire, Release, Relaxed}};

const PAGE_SIZE: usize = 4096;
/// Large-allocation instrumentation (≥ 100 KB), for diagnostic logging.
static LARGE_ALLOCS: AtomicU32 = AtomicU32::new(0);
static LARGE_FREES: AtomicU32 = AtomicU32::new(0);
static LARGE_REUSE: AtomicU32 = AtomicU32::new(0); // satisfied without draining small caches
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
}

/// An allocator whose free regions are already resident.
pub struct Heap {
    inner: UnsafeCell<Inner>,
    locked: AtomicBool,
}
struct HeapGuard<'a>(&'a AtomicBool);
impl Drop for HeapGuard<'_> { fn drop(&mut self) { self.0.store(false, Release); } }

// All mutable allocator state is protected by locked.
unsafe impl Send for Heap {}
unsafe impl Sync for Heap {}

impl Heap {
    fn lock(&self) -> HeapGuard<'_> {
        while self.locked.compare_exchange(false, true, Acquire, Relaxed).is_err() { core::hint::spin_loop(); }
        HeapGuard(&self.locked)
    }
    pub const fn new() -> Self {
        Heap {
            locked: AtomicBool::new(false),
            inner: UnsafeCell::new(Inner { free: FreeTree::new(), small_enabled: false, small: [None; SMALL_CLASSES], small_count: [0; SMALL_CLASSES] }),
        }
    }

    /// Retain a bounded set of rounded-size scratch allocations. Call during
    /// initialization, before this heap is shared. Cached blocks remain backed
    /// and are returned to the coalescing allocator on allocation pressure.
    pub fn enable_small_cache(&self) {
        let _guard = self.lock();
        unsafe { (*self.inner.get()).small_enabled = true; }
    }

    /// Donate resident writable storage. Regions must be disjoint from all
    /// previous donations and remain valid for this heap's lifetime.
    ///
    /// # Safety
    /// The caller exclusively owns the entire region and guarantees residency.
    pub unsafe fn add_region(&self, base: usize, end: usize) {
        let start = align_up(base, MIN_BLOCK_SIZE);
        let end = end & !(MIN_BLOCK_SIZE - 1);
        if end <= start { return; }
        let _guard = self.lock();
        unsafe { (*self.inner.get()).add_free_region(start, end - start); }
    }

}

impl Default for Heap {
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
        self.add_free_region(addr, size);
    }

    /// Insert and coalesce in address order without scanning free blocks.
    fn add_free_region(&mut self, addr: usize, size: usize) -> (usize, usize) {
        self.free.insert_coalescing(addr, size)
    }

    fn alloc_from_tree(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let address = self.free.allocate(size, align.max(MIN_BLOCK_SIZE))?;
        Some(address as *mut u8)
    }

}

unsafe impl GlobalAlloc for Heap {
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
        inner.drain_small();

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
