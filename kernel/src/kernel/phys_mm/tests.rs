use super::*;
use alloc::boxed::Box;
use arch_abi::page_supply::MemoryRegion;
extern crate std;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn layout(entries: impl Iterator<Item = MemoryRegion> + Clone, limit: u64) -> &'static FrameLayout {
    let mut layout = FrameLayout::from_memory_map(entries, limit);
    layout.exclude(0, 0x100000 / PAGE_SIZE as u64);
    Box::leak(Box::new(layout))
}

#[test]
fn firmware_holes_high_ram_and_exhaustion() {
    let _guard = TEST_LOCK.lock().unwrap();
    let map = [
        MemoryRegion { base: 0, length: 0x100000, usable: true },
        // Integrated graphics/firmware has reserved the first 256 MiB.
        MemoryRegion { base: 0x100000, length: 0xff00000, usable: false },
        MemoryRegion { base: 0x10000000, length: 3 * 4096, usable: true },
        MemoryRegion { base: 0x1_0000_0000, length: 4096, usable: true },
    ];
    let occupied = [256..258];
    bootstrap(layout(map.into_iter(), 1 << 24), &occupied).finish();
    assert_eq!(free_page_count(), 4);
    assert_eq!(alloc_phys_page(), Some(0x10000));
    assert_eq!(alloc_phys_page(), Some(0x10001));
    assert_eq!(alloc_phys_page(), Some(0x10002));
    assert_eq!(alloc_phys_page(), Some(0x100000));
    assert_eq!(alloc_phys_page(), None);
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_page(), Some(0x10001));
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_contig(1), Some(0x10001));
    free_phys_contig(0x10001, 1);
    assert_eq!(free_page_count(), 1);
    assert_eq!(alloc_phys_contig(usize::MAX), None);

    // A small, fully allocated machine must terminate after wrapping even
    // when the last successful allocation ended at the tracked RAM limit.
    let small = [MemoryRegion { base: 0, length: 259 * 4096, usable: true }];
    bootstrap(layout(small.into_iter(), 1 << 24), &occupied).finish();
    assert_eq!(alloc_phys_page(), Some(258));
    assert_eq!(alloc_phys_page(), None);
    assert_eq!(free_page_count(), 0);
    static DONATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(258);
    fn donate() -> Option<u64> {
        match DONATION.swap(0, core::sync::atomic::Ordering::Relaxed) { 0 => None, page => Some(page) }
    }
    set_reclaim(donate);
    assert_eq!(alloc_phys_page(), Some(258), "reclaim transfers existing ownership");
    assert_eq!(alloc_phys_page(), None);
    free_phys_page(258);
    assert_eq!(free_page_count(), 1);
    // Owned batches stop at exhaustion and leave transfer/rejection to arch.
    let mut pages = page_batch(64);
    assert_eq!(pages.count, 1);
    assert_eq!(pages.take(), Some(258));
    assert_eq!(page_batch(1).count, 0);
    free_phys_page(258);

}

#[test]
fn enabling_all_frames_preserves_reservations_beyond_the_bootstrap_bitmap() {
    let _guard = TEST_LOCK.lock().unwrap();
    let first = 0x100;
    let bootstrap_pages = (BOOTSTRAP_BYTES * 8) as u64;
    let reserved = first + bootstrap_pages;
    let bytes = (reserved + 2) * PAGE_SIZE as u64;
    let layout = layout(core::iter::once(MemoryRegion { base: 0, length: bytes, usable: true }), reserved + 2);
    let occupied = [reserved..reserved + 1];

    let allocator = bootstrap(layout, &occupied);
    assert_eq!(free_page_count(), bootstrap_pages as usize);
    allocator.finish();
    assert_eq!(free_page_count(), bootstrap_pages as usize + 1);
    assert_eq!(alloc_contig(bootstrap_pages as usize), Some(first));
    assert_eq!(alloc_phys_page(), Some(reserved + 1));
    assert_eq!(alloc_phys_page(), None);
}

#[test]
fn direct_ram_reuses_contiguous_pages() {
    let _guard = TEST_LOCK.lock().unwrap();
    let bytes = 0x100000 + 16 * PAGE_SIZE;
    let storage = Layout::from_size_align(bytes, PAGE_SIZE).unwrap();
    let ram = unsafe { alloc_zeroed(storage) };
    let end = (bytes / PAGE_SIZE) as u64;
    let layout = layout(core::iter::once(MemoryRegion {
        base: 0, length: bytes as u64, usable: true,
    }), end);
    unsafe { install_direct_ram(ram, bytes); }
    bootstrap(layout, &[]).finish();
    assert_eq!(total_page_count(), 16);
    let memory = alloc_shared_pages(16);
    let first = ((memory.as_ptr() as usize - ram as usize) / PAGE_SIZE) as u64;
    assert_eq!(free_page_count(), 0);
    unsafe { core::ptr::write_bytes(memory.as_ptr(), 0xa5, 16 * PAGE_SIZE); }
    unsafe { free_shared_pages(memory, 16); }
    assert_eq!(free_page_count(), 16);
    let reused = alloc_direct_pages(16);
    assert_eq!(reused, first);
    assert!(unsafe { core::slice::from_raw_parts(direct_pointer(reused), 16 * PAGE_SIZE) }.iter().all(|&b| b == 0));
    free_phys_contig(reused, 16);
    assert_eq!(free_page_count(), 16);
}
