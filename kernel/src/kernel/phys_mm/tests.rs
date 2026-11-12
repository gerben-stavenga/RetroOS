#[test]
fn firmware_holes_high_ram_and_exhaustion() {
    use super::*;
    let map = [
        MemoryRegion { base: 0, length: 0x100000, usable: true },
        // Integrated graphics/firmware has reserved the first 256 MiB.
        MemoryRegion { base: 0x100000, length: 0xff00000, usable: false },
        MemoryRegion { base: 0x10000000, length: 3 * 4096, usable: true },
        MemoryRegion { base: 0x1_0000_0000, length: 4096, usable: true },
    ];
    init_phys_mm(map.into_iter(), 1 << 24, 256, 258, 0);
    complete_initialization();
    prepare_fault_metadata();
    assert_eq!(free_page_count(), 4);
    assert_eq!(alloc_phys_page(), Some(0x10000));
    assert_eq!(alloc_phys_page(), Some(0x10001));
    assert_eq!(alloc_phys_page(), Some(0x10002));
    assert_eq!(alloc_phys_page(), Some(0x100000));
    assert_eq!(alloc_phys_page(), None);
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_page(), Some(0x10001));
    assert!(inc_shared_count(0x10001));
    free_phys_page(0x10001);
    assert_eq!(get_ref_count(0x10001), 1);
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_contig(1), Some(0x10001));
    free_phys_contig(0x10001, 1);
    assert_eq!(free_page_count(), 1);
    assert_eq!(alloc_phys_contig(usize::MAX), None);

    // A small, fully allocated machine must terminate after wrapping even
    // when the last successful allocation ended at the tracked RAM limit.
    let small = [MemoryRegion { base: 0, length: 259 * 4096, usable: true }];
    init_phys_mm(small.into_iter(), 1 << 24, 256, 258, 0);
    complete_initialization();
    prepare_fault_metadata();
    assert_eq!(alloc_phys_page(), Some(258));
    assert_eq!(alloc_phys_page(), None);
    assert_eq!(free_page_count(), 0);
    static DONATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(258);
    fn donate() -> Option<u64> {
        match DONATION.swap(0, core::sync::atomic::Ordering::Relaxed) { 0 => None, page => Some(page) }
    }
    set_reclaim(donate);
    assert_eq!(alloc_phys_page(), Some(258), "reclaim transfers existing ownership");
    assert_eq!(get_ref_count(258), 1);
    assert_eq!(alloc_phys_page(), None);
    free_phys_page(258);
    assert_eq!(free_page_count(), 1);
    // Reclaim can return a page through the cache and independently fill the
    // fault reserve by releasing kernel mappings. Do not overfill or lose either.
    let small = [MemoryRegion { base: 0, length: 260 * 4096, usable: true }];
    init_phys_mm(small.into_iter(), 1 << 24, 256, 258, 0);
    complete_initialization();
    prepare_fault_metadata();
    assert_eq!(alloc_phys_page(), Some(258));
    assert_eq!(alloc_phys_page(), Some(259));
    let mut reserve = arch_abi::page_supply::PageSupply::new();
    for page in 1000..1063 { reserve.donate(page); }
    static REFILL: core::sync::atomic::AtomicPtr<arch_abi::page_supply::PageSupply> =
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
    fn return_during_reclaim() -> Option<u64> {
        let pointer = REFILL.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
        if pointer.is_null() { return None; }
        unsafe { (*pointer).donate(259); }
        Some(258)
    }
    REFILL.store(&mut reserve, core::sync::atomic::Ordering::Relaxed);
    set_reclaim(return_during_reclaim);
    unsafe { replenish_supply(&mut reserve); }
    assert_eq!(reserve.count, arch_abi::page_supply::SUPPLY_CAPACITY);
    assert_eq!(get_ref_count(258), 0, "surplus donation returned to allocator");
    assert_eq!(get_ref_count(259), 1, "reserve keeps ownership of returned frame");

}
