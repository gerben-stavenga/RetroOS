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

#[test]
fn page_alignment_survives_a_prefix_smaller_than_a_free_header() {
    unsafe {
        let arena = Layout::from_size_align(8 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = DemandHeap::new();
        heap.init(memory as usize, memory as usize + arena.size());
        // Seed a large free extent, then leave its start just before a page
        // boundary. One pointer-sized alignment gap cannot hold a FreeBlock.
        let large = Layout::from_size_align(4 * PAGE, PAGE).unwrap();
        let seed = heap.alloc(large);
        assert!(!seed.is_null());
        heap.dealloc(seed, large);
        let prefix_layout = Layout::from_size_align(PAGE - std::mem::size_of::<usize>(), std::mem::align_of::<usize>()).unwrap();
        let prefix = heap.alloc(prefix_layout);
        assert_eq!(prefix, memory);
        std::ptr::write_bytes(prefix, 0x5a, prefix_layout.size());
        let page_layout = Layout::from_size_align(PAGE, PAGE).unwrap();
        let page = heap.alloc(page_layout);
        assert!(!page.is_null());
        assert_eq!(page as usize % PAGE, 0);
        std::ptr::write_bytes(page, 0xa5, PAGE);
        assert!(std::slice::from_raw_parts(prefix, prefix_layout.size()).iter().all(|&byte| byte == 0x5a));
        heap.dealloc(page, page_layout);
        heap.dealloc(prefix, prefix_layout);
        let reused = heap.alloc(large);
        assert_eq!(reused, memory);
        heap.dealloc(reused, large);
        std::alloc::dealloc(memory, arena);
    }
}

thread_local! {
    static CACHE_RELEASES: std::cell::RefCell<Vec<(usize, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn cache_release(addr: usize, bytes: usize) {
    assert_eq!(addr % PAGE, 0);
    assert_eq!(bytes % PAGE, 0);
    unsafe { std::ptr::write_bytes(addr as *mut u8, 0xdd, bytes); }
    CACHE_RELEASES.with(|events| events.borrow_mut().push((addr, bytes)));
}

#[test]
fn hot_buffers_reuse_backing_but_large_frees_still_release_excess() {
    unsafe {
        CACHE_RELEASES.with(|events| events.borrow_mut().clear());
        let arena = Layout::from_size_align(128 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = DemandHeap::new();
        heap.init_with_cached_release(memory as usize, memory as usize + arena.size(), Some(cache_release), 16 * PAGE);
        let buffer = Layout::from_size_align(8 * PAGE, 16).unwrap();
        for _ in 0..1000 {
            let p = heap.alloc(buffer);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0x5a, buffer.size());
            heap.dealloc(p, buffer);
        }
        CACHE_RELEASES.with(|events| assert!(events.borrow().is_empty()));
        let large = Layout::from_size_align(64 * PAGE, PAGE).unwrap();
        let p = heap.alloc(large);
        assert!(!p.is_null());
        std::ptr::write_bytes(p, 0x44, large.size());
        heap.dealloc(p, large);
        CACHE_RELEASES.with(|events| {
            let bytes: usize = events.borrow().iter().map(|event| event.1).sum();
            assert!(bytes >= 47 * PAGE, "retained beyond the 16-page budget: {bytes}");
        });
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn cached_page_eviction_never_releases_live_allocations_or_free_headers() {
    unsafe {
        CACHE_RELEASES.with(|events| events.borrow_mut().clear());
        let arena = Layout::from_size_align(1024 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = DemandHeap::new();
        heap.init_with_cached_release(memory as usize, memory as usize + arena.size(), Some(cache_release), 8 * PAGE);
        heap.enable_small_cache();
        let mut live: Vec<(*mut u8, Layout, u8)> = Vec::new();
        let mut random = 17u32;
        for step in 0..5000 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            if live.len() >= 24 || !live.is_empty() && random & 3 == 0 {
                let index = random as usize % live.len();
                let (p, layout, _) = live.swap_remove(index);
                heap.dealloc(p, layout);
            } else {
                let size = if random & 8 == 0 { 16 + random as usize % 241 }
                    else if random & 16 == 0 { PAGE }
                    else { 32 + random as usize % (6 * PAGE) };
                let align = if random & 4 == 0 { PAGE } else { std::mem::align_of::<usize>() };
                let layout = Layout::from_size_align(size, align).unwrap();
                let p = heap.alloc(layout);
                assert!(!p.is_null());
                assert_eq!(p as usize % layout.align(), 0);
                let byte = (step % 127) as u8;
                std::ptr::write_bytes(p, byte, layout.size());
                live.push((p, layout, byte));
            }
            for &(p, layout, byte) in &live {
                assert!(std::slice::from_raw_parts(p, layout.size()).iter().all(|&b| b == byte), "evicted live bytes at step {step}");
            }
        }
        for (p, layout, _) in live { heap.dealloc(p, layout); }
        // A coalesced extent must retain a usable free-list header.
        let whole = Layout::from_size_align(128 * PAGE, PAGE).unwrap();
        let p = heap.alloc(whole);
        assert!(!p.is_null());
        std::ptr::write_bytes(p, 0xaa, whole.size());
        heap.dealloc(p, whole);
        CACHE_RELEASES.with(|events| assert!(!events.borrow().is_empty()));
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn small_cache_drains_on_exhaustion_and_coalesces_the_whole_arena() {
    unsafe {
        let arena = Layout::from_size_align(4 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = DemandHeap::new();
        heap.init(memory as usize, memory as usize + arena.size());
        heap.enable_small_cache();
        let layout = Layout::from_size_align(128, std::mem::align_of::<usize>()).unwrap();
        let blocks: Vec<_> = (0..arena.size() / 128).map(|_| heap.alloc(layout)).collect();
        assert!(blocks.iter().all(|p| !p.is_null()));
        // Interleave cached blocks, ordinary free regions, and live neighbors.
        for &p in blocks.iter().step_by(2) { heap.dealloc(p, layout); }
        for &p in blocks.iter().skip(1).step_by(2) {
            std::ptr::write_bytes(p, 0xa5, 128);
            heap.dealloc(p, layout);
        }
        let whole = heap.alloc(arena);
        assert_eq!(whole, memory, "cached blocks must not create false OOM");
        std::ptr::write_bytes(whole, 0x5a, arena.size());
        heap.dealloc(whole, arena);
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn small_cache_reuses_exact_sizes_without_violating_stronger_alignment() {
    unsafe {
        let arena = Layout::from_size_align(8 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = DemandHeap::new();
        heap.init_with_cached_release(memory as usize, memory as usize + arena.size(), Some(cache_release), 2 * PAGE);
        heap.enable_small_cache();
        let layout = Layout::from_size_align(24, std::mem::align_of::<usize>()).unwrap();
        let first = heap.alloc(layout);
        let second = heap.alloc(layout);
        assert_ne!(second as usize % 256, 0);
        heap.dealloc(second, layout);
        let aligned_layout = Layout::from_size_align(24, 256).unwrap();
        let aligned = heap.alloc(aligned_layout);
        assert_eq!(aligned as usize % 256, 0);
        let recycled = heap.alloc(layout);
        assert_eq!(recycled, second);
        std::ptr::write_bytes(first, 0x11, 24);
        std::ptr::write_bytes(aligned, 0x22, 24);
        std::ptr::write_bytes(recycled, 0x33, 24);
        heap.dealloc(first, layout);
        heap.dealloc(aligned, aligned_layout);
        heap.dealloc(recycled, layout);
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn fragmented_extents_preserve_live_blocks_and_recover_the_whole_arena() {
    unsafe {
        let arena = Layout::from_size_align(32 * 1024 * 1024, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = DemandHeap::new();
        heap.init_with_cached_release(memory as usize, memory as usize + arena.size(), Some(cache_release), 16 * PAGE);
        heap.enable_small_cache();
        let small = Layout::from_size_align(512, 8).unwrap();
        let larger = Layout::from_size_align(544, 8).unwrap();
        let mut blocks = Vec::new();
        for _ in 0..8000 {
            let p = heap.alloc(small);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0x71, small.size());
            blocks.push(p);
        }
        // Thousands of separated holes; none can satisfy the larger request.
        // Insert in reverse order to exercise balancing in both directions.
        for &p in blocks.iter().step_by(2).rev() { heap.dealloc(p, small); }
        let mut extra = Vec::new();
        for _ in 0..3000 {
            let p = heap.alloc(larger);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0x39, larger.size());
            extra.push(p);
        }
        for &p in blocks.iter().skip(1).step_by(2) {
            assert!(std::slice::from_raw_parts(p, small.size()).iter().all(|&b| b == 0x71));
        }
        for &p in &extra {
            assert!(std::slice::from_raw_parts(p, larger.size()).iter().all(|&b| b == 0x39));
        }
        // Mix predecessor, successor and two-sided coalescing at many depths.
        for &p in blocks.iter().skip(1).step_by(2) { heap.dealloc(p, small); }
        for &p in extra.iter().step_by(2) { heap.dealloc(p, larger); }
        for &p in extra.iter().skip(1).step_by(2).rev() { heap.dealloc(p, larger); }
        let whole = heap.alloc(arena);
        assert_eq!(whole, memory, "splits must not lose unrepresentable tails");
        std::ptr::write_bytes(whole, 0x55, arena.size());
        heap.dealloc(whole, arena);
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn unaligned_window_edges_never_allocate_or_write_beyond_the_window() {
    unsafe {
        let arena = Layout::from_size_align(4 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc(arena);
        std::ptr::write_bytes(memory, 0x77, arena.size());
        let start = memory as usize + 8;
        let end = memory as usize + 3 * PAGE - 8;
        let heap = DemandHeap::new();
        heap.init(start, end);
        let tiny = Layout::from_size_align(1, 1).unwrap();
        let mut live = Vec::new();
        loop {
            let p = heap.alloc(tiny);
            if p.is_null() { break; }
            assert!(p as usize >= start && (p as usize) < end);
            p.write(0x39);
            live.push(p);
        }
        assert!(live.len() > 100);
        for p in live { heap.dealloc(p, tiny); }
        let page = Layout::from_size_align(PAGE, PAGE).unwrap();
        let p = heap.alloc(page);
        assert!(!p.is_null() && p as usize % PAGE == 0);
        std::ptr::write_bytes(p, 0x11, PAGE);
        heap.dealloc(p, page);
        assert!(std::slice::from_raw_parts(memory, 8).iter().all(|&b| b == 0x77));
        assert!(std::slice::from_raw_parts(end as *const u8, arena.size() - (end - memory as usize)).iter().all(|&b| b == 0x77));
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn concurrent_allocations_keep_live_buffers_disjoint_and_coalesce() {
    unsafe {
        let arena = Layout::from_size_align(2 * 1024 * 1024, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = DemandHeap::new();
        heap.init(memory as usize, memory as usize + arena.size());
        heap.enable_small_cache();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let heap = &heap;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let mut live = Vec::new();
                    for step in 0..2000 {
                        let size = 16 + (step * 173 + worker * 97) % 8192;
                        let layout = Layout::from_size_align(size, 16).unwrap();
                        let p = heap.alloc(layout);
                        assert!(!p.is_null());
                        let byte = (worker * 29 + step) as u8;
                        std::ptr::write_bytes(p, byte, size);
                        live.push((p, layout, byte));
                        if live.len() >= 8 {
                            let (p, layout, byte) = live.remove(0);
                            assert!(std::slice::from_raw_parts(p, layout.size()).iter().all(|&b| b == byte));
                            heap.dealloc(p, layout);
                        }
                    }
                    for (p, layout, byte) in live {
                        assert!(std::slice::from_raw_parts(p, layout.size()).iter().all(|&b| b == byte));
                        heap.dealloc(p, layout);
                    }
                });
            }
        });
        let whole = heap.alloc(arena);
        assert_eq!(whole, memory);
        heap.dealloc(whole, arena);
        std::alloc::dealloc(memory, arena);
    }
}
