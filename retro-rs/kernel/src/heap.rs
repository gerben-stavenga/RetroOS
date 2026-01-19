//! Kernel heap allocator
//!
//! Linked-list allocator that requests pages on demand from the physical
//! memory manager and maps them into the kernel address space.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::NonNull;

use crate::paging2::{self, Entry, Entry32, Entry64, Entries, PAGE_SIZE};
use crate::phys_mm;

/// Heap ends before the top of address space
pub const HEAP_END: usize = 0xFFF0_0000;

/// Get heap base (first page after kernel _end)
fn heap_base() -> usize {
    unsafe extern "C" {
        static _end: u8;
    }
    let end = (&raw const _end) as usize;
    // Align up to next page
    (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Free block header stored at the start of each free region
struct FreeBlock {
    size: usize,
    next: Option<NonNull<FreeBlock>>,
}

/// Minimum allocation size (must fit a FreeBlock for when it's freed)
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

/// Align value up to alignment
const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

/// Inner allocator state
struct AllocatorInner {
    head: Option<NonNull<FreeBlock>>,
    mapped_end: usize,
}

/// Kernel heap allocator with interior mutability
pub struct KernelAllocator {
    inner: UnsafeCell<AllocatorInner>,
}

unsafe impl Send for KernelAllocator {}
unsafe impl Sync for KernelAllocator {}

impl KernelAllocator {
    /// Create a new uninitialized allocator
    pub const fn new() -> Self {
        KernelAllocator {
            inner: UnsafeCell::new(AllocatorInner {
                head: None,
                mapped_end: 0,  // Set properly in init()
            }),
        }
    }

    /// Initialize the allocator (call once after paging is set up)
    pub fn init(&self) {
        let inner = unsafe { &mut *self.inner.get() };
        inner.head = None;
        inner.mapped_end = heap_base();
        crate::println!("Heap base: {:#x}", inner.mapped_end);
    }
}

impl AllocatorInner {
    /// Extend the heap by mapping more pages
    fn extend_heap(&mut self, min_size: usize) -> bool {
        let pages_needed = (min_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let pages_needed = pages_needed.max(4); // Allocate at least 4 pages at a time

        for _ in 0..pages_needed {
            if self.mapped_end >= HEAP_END {
                return false;
            }

            // Allocate physical page
            let phys_page = match phys_mm::alloc_phys_page() {
                Some(p) => p,
                None => return false,
            };

            // Map it into kernel space (user=false, readonly=false)
            let virt_page_idx = self.mapped_end / PAGE_SIZE;
            match paging2::entries() {
                Entries::Legacy(e) => e[virt_page_idx] = Entry32::new(phys_page, true, false),
                Entries::Pae(e) => e[virt_page_idx] = Entry64::new(phys_page, true, false),
            }

            self.mapped_end += PAGE_SIZE;
        }

        paging2::flush_tlb();

        // Add the new region to the free list
        let new_region_start = self.mapped_end - pages_needed * PAGE_SIZE;
        let new_region_size = pages_needed * PAGE_SIZE;
        self.add_free_region(new_region_start, new_region_size);

        true
    }

    /// Add a region to the free list (sorted by address, coalesces)
    fn add_free_region(&mut self, addr: usize, size: usize) {
        if size < MIN_BLOCK_SIZE {
            return; // Too small to track
        }

        // Create the free block
        let block_ptr = addr as *mut FreeBlock;
        unsafe {
            (*block_ptr).size = size;
            (*block_ptr).next = None;
        }
        let new_block = unsafe { NonNull::new_unchecked(block_ptr) };

        // Find insertion point (sorted by address)
        let mut current = &mut self.head;

        while let Some(block) = *current {
            if block.as_ptr() as usize > addr {
                break;
            }
            current = unsafe { &mut (*block.as_ptr()).next };
        }

        // Insert the new block
        unsafe {
            (*new_block.as_ptr()).next = *current;
            *current = Some(new_block);
        }

        // Coalesce with next block if adjacent
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

        // Coalesce with previous block if adjacent
        // (need to re-traverse to find previous)
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

    /// Allocate memory from the free list
    fn alloc_from_list(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let mut current = &mut self.head;

        while let Some(block) = *current {
            let block_ptr = block.as_ptr();
            let block_addr = block_ptr as usize;
            let block_size = unsafe { (*block_ptr).size };

            // Calculate aligned start within this block
            let aligned_addr = align_up(block_addr, align);
            let padding = aligned_addr - block_addr;

            // Check if this block can satisfy the allocation
            let total_needed = padding + size;

            if block_size >= total_needed {
                // Can use this block
                let alloc_addr = aligned_addr;

                // Handle padding at start (if any, leave as free block)
                if padding >= MIN_BLOCK_SIZE {
                    // Keep the padding as a free block
                    unsafe {
                        (*block_ptr).size = padding;
                    }

                    // Handle remainder after allocation
                    let remainder_addr = alloc_addr + size;
                    let remainder_size = block_size - total_needed;

                    if remainder_size >= MIN_BLOCK_SIZE {
                        // Create a new free block for the remainder
                        let remainder_ptr = remainder_addr as *mut FreeBlock;
                        unsafe {
                            (*remainder_ptr).size = remainder_size;
                            (*remainder_ptr).next = (*block_ptr).next;
                            (*block_ptr).next = Some(NonNull::new_unchecked(remainder_ptr));
                        }
                    }
                } else if padding > 0 {
                    // Padding too small to keep, include it in allocation
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
                        // Use entire block
                        unsafe {
                            *current = (*block_ptr).next;
                        }
                    }
                    return Some(alloc_addr as *mut u8);
                } else {
                    // No padding needed
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
                        // Use entire block
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

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = unsafe { &mut *self.inner.get() };

        let size = layout.size().max(MIN_BLOCK_SIZE);
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        // Try to allocate from existing free list
        if let Some(ptr) = inner.alloc_from_list(size, align) {
            return ptr;
        }

        // Need more memory
        if !inner.extend_heap(size + align) {
            return core::ptr::null_mut();
        }

        // Try again
        inner.alloc_from_list(size, align).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = unsafe { &mut *self.inner.get() };

        let size = layout.size().max(MIN_BLOCK_SIZE);
        inner.add_free_region(ptr as usize, size);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator::new();

/// Initialize the kernel heap allocator
pub fn init() {
    ALLOCATOR.init();
}
