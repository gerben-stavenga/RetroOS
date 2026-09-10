use lib::heap::DemandHeap;
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

const PAGE: usize = 4096;
static RELEASED: AtomicUsize = AtomicUsize::new(0);

fn release(addr: usize, bytes: usize) {
    assert_eq!(addr % PAGE, 0);
    assert_eq!(bytes % PAGE, 0);
    // Destroy released contents to catch stale free-list headers on reuse.
    unsafe { std::ptr::write_bytes(addr as *mut u8, 0xdd, bytes); }
    RELEASED.fetch_add(bytes, Relaxed);
}

#[test]
fn releases_whole_free_pages_preserves_neighbors_and_reuses_metadata() {
    unsafe {
        let arena = Layout::from_size_align(32 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = DemandHeap::new();
        heap.init_with_release(memory as usize, memory as usize + arena.size(), Some(release));
        let small = Layout::from_size_align(128, 16).unwrap();
        let large = Layout::from_size_align(3 * PAGE, 16).unwrap();
        let left = heap.alloc(small);
        let middle = heap.alloc(large);
        let right = heap.alloc(small);
        assert!(!left.is_null() && !middle.is_null() && !right.is_null());
        std::ptr::write_bytes(left, 0x11, small.size());
        std::ptr::write_bytes(right, 0x22, small.size());
        heap.dealloc(middle, large);
        assert_eq!(RELEASED.load(Relaxed), 2 * PAGE);
        assert!(std::slice::from_raw_parts(left, small.size()).iter().all(|&b| b == 0x11));
        assert!(std::slice::from_raw_parts(right, small.size()).iter().all(|&b| b == 0x22));
        let reused = heap.alloc(large);
        assert_eq!(reused, middle);
        std::ptr::write_bytes(reused, 0x33, large.size());
        heap.dealloc(left, small);
        heap.dealloc(right, small);
        heap.dealloc(reused, large); // coalesces on both sides
        let whole = Layout::from_size_align(4 * PAGE, PAGE).unwrap();
        let next = heap.alloc(whole);
        assert_eq!(next, memory);
        std::ptr::write_bytes(next, 0x44, whole.size());
        heap.dealloc(next, whole);
        assert!(RELEASED.load(Relaxed) >= 5 * PAGE);
        // When an aligned successor merges, its former header page is now
        // free too, even though it lies just beyond the allocation freed.
        let page = Layout::from_size_align(PAGE, PAGE).unwrap();
        let a = heap.alloc(page);
        let b = heap.alloc(page);
        let c = heap.alloc(page);
        heap.dealloc(b, page);
        let before = RELEASED.load(Relaxed);
        heap.dealloc(a, page);
        assert_eq!(RELEASED.load(Relaxed) - before, PAGE);
        assert_eq!(heap.alloc(page), a); // header of the merged block survived
        heap.dealloc(a, page);
        heap.dealloc(c, page);
        std::alloc::dealloc(memory, arena);
    }
}
