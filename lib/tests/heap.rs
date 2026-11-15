use lib::heap::Heap;
use std::alloc::{GlobalAlloc, Layout};

const PAGE: usize = 4096;
#[test]
fn page_alignment_survives_a_prefix_smaller_than_a_free_header() {
    unsafe {
        let arena = Layout::from_size_align(8 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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

#[test]
fn mixed_allocations_preserve_live_bytes_and_free_headers() {
    unsafe {
        let arena = Layout::from_size_align(1024 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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
        std::alloc::dealloc(memory, arena);
    }
}

#[test]
fn small_cache_drains_on_exhaustion_and_coalesces_the_whole_arena() {
    unsafe {
        let arena = Layout::from_size_align(4 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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
        let heap = Heap::new();
        heap.add_region(start, end);
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
        let heap = Heap::new();
        heap.add_region(memory as usize, memory as usize + arena.size());
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

#[test]
fn exhaustion_waits_for_explicit_resident_storage() {
    unsafe {
        let arena = Layout::from_size_align(3 * PAGE, PAGE).unwrap();
        let memory = std::alloc::alloc_zeroed(arena);
        assert!(!memory.is_null());
        let heap = Heap::new();
        let page = Layout::from_size_align(PAGE, PAGE).unwrap();
        assert!(heap.alloc(page).is_null());
        heap.add_region(memory as usize, memory as usize + PAGE);
        assert_eq!(heap.alloc(page), memory);
        // The adjacent bytes exist, but have not been donated to this heap.
        std::ptr::write_bytes(memory.add(PAGE), 0x77, 2 * PAGE);
        assert!(heap.alloc(page).is_null());
        assert!(std::slice::from_raw_parts(memory.add(PAGE), 2 * PAGE)
            .iter().all(|&byte| byte == 0x77));
        heap.add_region(memory as usize + 2 * PAGE, memory as usize + 3 * PAGE);
        assert_eq!(heap.alloc(page), memory.add(2 * PAGE));
        assert!(heap.alloc(page).is_null());
        heap.dealloc(memory, page);
        heap.dealloc(memory.add(2 * PAGE), page);
        assert!(heap.alloc(arena).is_null(), "undonated hole must stay inaccessible");
        heap.add_region(memory as usize + PAGE, memory as usize + 2 * PAGE);
        assert_eq!(heap.alloc(arena), memory);
        heap.dealloc(memory, arena);
        std::alloc::dealloc(memory, arena);
    }
}
