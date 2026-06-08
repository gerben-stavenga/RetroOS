//! Demand-paged linked-list heap allocator (freestanding).
//!
//! A generic `GlobalAlloc` that carves allocations out of a fixed virtual
//! address window `[base, end)`. It is *demand-paged*: `extend_heap` only claims
//! virtual address space (bumps a cursor toward `end`) and never maps a page
//! itself — it assumes that touching an address in the window gets backed by the
//! platform (a `#PF` handler on bare metal). So the allocator holds no platform
//! knowledge beyond the two window bounds, which the embedder supplies via
//! [`DemandHeap::init`]. The raw free-list pointer-juggling lives here, off the
//! kernel, with `lib`'s other freestanding primitives.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

const PAGE_SIZE: usize = 4096;

/// Large-allocation instrumentation (≥ 100 KB), for diagnostic logging.
static LARGE_ALLOCS: AtomicU32 = AtomicU32::new(0);
static LARGE_FREES: AtomicU32 = AtomicU32::new(0);
static LARGE_REUSE: AtomicU32 = AtomicU32::new(0); // satisfied from free list (no extend)

/// Free block header stored at the start of each free region.
struct FreeBlock {
    size: usize,
    next: Option<NonNull<FreeBlock>>,
}

/// Minimum allocation size (must fit a `FreeBlock` for when it's freed).
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

struct Inner {
    head: Option<NonNull<FreeBlock>>,
    /// Top of the virtual range claimed so far (grows toward `heap_end`).
    mapped_end: usize,
    /// Ceiling of the heap window (set in `init`).
    heap_end: usize,
}

/// Demand-paged heap over a `[base, end)` virtual window. Install as the
/// `#[global_allocator]` and call [`DemandHeap::init`] once after paging is up.
pub struct DemandHeap {
    inner: UnsafeCell<Inner>,
}

// Single-threaded kernel: access is serialized by the global allocator lock
// semantics (one CPU). The `UnsafeCell` is the one raw cell.
unsafe impl Send for DemandHeap {}
unsafe impl Sync for DemandHeap {}

impl DemandHeap {
    pub const fn new() -> Self {
        DemandHeap {
            inner: UnsafeCell::new(Inner { head: None, mapped_end: 0, heap_end: 0 }),
        }
    }

    /// Initialize the allocator over `[base, end)`. Call once, after the
    /// platform can back accesses in that window.
    pub fn init(&self, base: usize, end: usize) {
        let inner = unsafe { &mut *self.inner.get() };
        inner.head = None;
        inner.mapped_end = base;
        inner.heap_end = end;
    }
}

impl Default for DemandHeap {
    fn default() -> Self { Self::new() }
}

impl Inner {
    /// Claim virtual address space (physical pages are demand-backed on access).
    fn extend_heap(&mut self, min_size: usize) -> bool {
        let pages_needed = ((min_size + PAGE_SIZE - 1) / PAGE_SIZE).max(4);

        let region_start = self.mapped_end;
        let mut region_pages = 0;

        while region_pages < pages_needed {
            if self.mapped_end >= self.heap_end {
                break;
            }
            self.mapped_end += PAGE_SIZE;
            region_pages += 1;
        }

        if region_pages > 0 {
            self.add_free_region(region_start, region_pages * PAGE_SIZE);
        }

        region_pages >= pages_needed
    }

    /// Add a region to the free list (sorted by address, coalesces).
    fn add_free_region(&mut self, addr: usize, size: usize) {
        if size < MIN_BLOCK_SIZE {
            return; // Too small to track
        }

        let block_ptr = addr as *mut FreeBlock;
        unsafe {
            (*block_ptr).size = size;
            (*block_ptr).next = None;
        }
        let new_block = unsafe { NonNull::new_unchecked(block_ptr) };

        // Find insertion point (sorted by address).
        let mut current = &mut self.head;
        while let Some(block) = *current {
            if block.as_ptr() as usize > addr {
                break;
            }
            current = unsafe { &mut (*block.as_ptr()).next };
        }

        // Insert.
        unsafe {
            (*new_block.as_ptr()).next = *current;
            *current = Some(new_block);
        }

        // Coalesce with next block if adjacent.
        unsafe {
            let block = new_block.as_ptr();
            if let Some(next) = (*block).next {
                let block_end = addr + (*block).size;
                if block_end == next.as_ptr() as usize {
                    (*block).size += (*next.as_ptr()).size;
                    (*block).next = (*next.as_ptr()).next;
                }
            }
        }

        // Coalesce with previous block if adjacent (re-traverse to find prev).
        let mut prev: Option<NonNull<FreeBlock>> = None;
        let mut current = self.head;
        while let Some(block) = current {
            if block.as_ptr() as usize == addr {
                if let Some(mut prev_block) = prev {
                    let prev_ptr = unsafe { prev_block.as_mut() };
                    let prev_end = prev_block.as_ptr() as usize + prev_ptr.size;
                    if prev_end == addr {
                        prev_ptr.size += unsafe { (*block.as_ptr()).size };
                        prev_ptr.next = unsafe { (*block.as_ptr()).next };
                    }
                }
                break;
            }
            prev = current;
            current = unsafe { (*block.as_ptr()).next };
        }
    }

    /// Allocate from the free list.
    fn alloc_from_list(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let mut current = &mut self.head;

        while let Some(block) = *current {
            let block_ptr = block.as_ptr();
            let block_addr = block_ptr as usize;
            let block_size = unsafe { (*block_ptr).size };

            let aligned_addr = align_up(block_addr, align);
            let padding = aligned_addr - block_addr;
            let total_needed = padding + size;

            if block_size >= total_needed {
                let alloc_addr = aligned_addr;

                if padding >= MIN_BLOCK_SIZE {
                    unsafe {
                        (*block_ptr).size = padding;
                    }

                    let remainder_addr = alloc_addr + size;
                    let remainder_size = block_size - total_needed;

                    if remainder_size >= MIN_BLOCK_SIZE {
                        let remainder_ptr = remainder_addr as *mut FreeBlock;
                        unsafe {
                            (*remainder_ptr).size = remainder_size;
                            (*remainder_ptr).next = (*block_ptr).next;
                            (*block_ptr).next = Some(NonNull::new_unchecked(remainder_ptr));
                        }
                    }
                } else if padding > 0 {
                    let alloc_addr = block_addr;
                    let actual_size = size + padding;
                    let remainder_size = block_size - actual_size;

                    if remainder_size >= MIN_BLOCK_SIZE {
                        let remainder_ptr = (alloc_addr + actual_size) as *mut FreeBlock;
                        unsafe {
                            (*remainder_ptr).size = remainder_size;
                            (*remainder_ptr).next = (*block_ptr).next;
                            *current = Some(NonNull::new_unchecked(remainder_ptr));
                        }
                    } else {
                        unsafe {
                            *current = (*block_ptr).next;
                        }
                    }
                    return Some(alloc_addr as *mut u8);
                } else {
                    let remainder_addr = alloc_addr + size;
                    let remainder_size = block_size - size;

                    if remainder_size >= MIN_BLOCK_SIZE {
                        let remainder_ptr = remainder_addr as *mut FreeBlock;
                        unsafe {
                            (*remainder_ptr).size = remainder_size;
                            (*remainder_ptr).next = (*block_ptr).next;
                            *current = Some(NonNull::new_unchecked(remainder_ptr));
                        }
                    } else {
                        unsafe {
                            *current = (*block_ptr).next;
                        }
                    }
                }

                return Some(alloc_addr as *mut u8);
            }

            current = unsafe { &mut (*block_ptr).next };
        }

        None
    }
}

unsafe impl GlobalAlloc for DemandHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = unsafe { &mut *self.inner.get() };

        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), core::mem::align_of::<FreeBlock>());
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        if let Some(ptr) = inner.alloc_from_list(size, align) {
            if size >= 100_000 { LARGE_REUSE.fetch_add(1, Relaxed); }
            return ptr;
        }

        if size >= 100_000 { LARGE_ALLOCS.fetch_add(1, Relaxed); }
        if !inner.extend_heap(size + align) {
            return core::ptr::null_mut();
        }

        inner.alloc_from_list(size, align).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = unsafe { &mut *self.inner.get() };

        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), core::mem::align_of::<FreeBlock>());
        if size >= 100_000 { LARGE_FREES.fetch_add(1, Relaxed); }
        inner.add_free_region(ptr as usize, size);
    }
}
