//! Software-MMU tests driven through the public arch surface: demand paging at
//! a high (sparse) guest address, per-space isolation across an address-space
//! switch (`Arch::activate`, the same primitive the kernel uses), and unmap →
//! demand-zero.

use retroos_arch_interp as arch;
use arch_abi::{Memory as _, UserPage};
use arch_abi::page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame};

const HI: usize = 0x4000_0000; // sparse high VA (a flat reservation would never fit)

/// Make space `id` the active one exactly as the kernel does — `Arch::activate`
/// moves it into the active slot and returns the displaced (previous) space.
fn switch(root: arch::RootPageTable) -> arch::RootPageTable {
    arch::Interp.activate(root)
}

#[test]
fn demand_isolation_and_unmap() {
    init();

    // Demand-commit at a sparse high address (proves the reserved-VA model).
    arch::mem().write::<u32>(HI, 0xCAFE_BABE);
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE);

    // A second space is isolated; the first space's contents survive a round
    // trip through it.
    let other = arch::RootPageTable::default();
    let saved = switch(other);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "new space must be zero-isolated");
    arch::mem().write::<u32>(HI, 0x1234_5678);

    switch(saved); // back to the original space
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE, "space 0 preserved");

    // Unmap drops the page; the next access demand-zeroes it.
    let mut machine = arch::Interp;
    let zero = arch_abi::mapping::read_mapping(&mut machine, UserPage::new(0x7000_0000).unwrap()).unwrap();
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, UserPage::new(HI as u64).unwrap(), zero, test_memory::input(5)).0.unwrap(); }
    assert_eq!(arch::mem().read::<u32>(HI), 0, "unmapped page reads back zero");
}

#[test]
fn kernel_owned_shared_pages_are_coherent_across_guest_fork() {
    init();
    let mut machine = arch::Interp;
    let memory = test_memory::alloc_shared_pages(3);
    assert_eq!(memory.as_ptr() as usize % 4096, 0);
    unsafe {
        assert!(core::slice::from_raw_parts(memory.as_ptr(), 3 * 4096).iter().all(|&b| b == 0));
        let start = UserPage::new(HI as u64).unwrap();
        for i in 0..3 {
            let pointer = core::ptr::NonNull::new_unchecked(memory.as_ptr().add(i * 4096));
            let frame = PhysicalFrame::new(test_memory::direct_frame(pointer)).unwrap();
            arch_abi::mapping::replace_mapping(&mut machine, start.offset(i).unwrap(), PageEntry::Writable(Mapping {
                backing: Backing::Borrowed(frame), attributes: Attributes::EXECUTABLE,
            }), test_memory::input(5)).0.unwrap();
        }
        *memory.as_ptr().add(8197) = 0xC3;
    }
    assert_eq!(arch::mem().read::<u8>(HI + 8197), 0xC3);
    let mut child = arch::RootPageTable::default();
    machine.user_fork(&mut child, test_memory::input(5)).0;
    let parent = machine.activate(child);
    arch::mem().write::<u8>(HI + 8197, 0x79);
    assert_eq!(unsafe { *memory.as_ptr().add(8197) }, 0x79);
    machine.free_user_pages();
    let mut child = machine.activate(parent);
    assert_eq!(arch::mem().read::<u8>(HI + 8197), 0x79);
    machine.free_user_pages();
    machine.destroy_space(&mut child);
    assert_eq!(unsafe { *memory.as_ptr().add(8197) }, 0x79);
    unsafe { test_memory::free_shared_pages(memory, 3); }
}

#[test]
fn default_space_does_not_alias_a_suspended_vfork_parent() {
    init();
    let mut machine = arch::Interp;
    arch::mem().write::<u32>(HI, 0xCAFE_BABE);
    // vfork parks the shared image while child exit/exec cleans a fresh space.
    let parent = machine.activate(arch::RootPageTable::default());
    assert_eq!(arch::mem().read::<u32>(HI), 0);
    arch::mem().write::<u32>(HI, 0x1234_5678);
    machine.free_user_pages();
    let mut empty = machine.activate(parent);
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE);
    machine.destroy_space(&mut empty);
}

#[test]
fn typed_mapping_ownership_and_protection() {
    init();
    let mut machine = arch::Interp;
    let page = UserPage::new(HI as u64).unwrap();
    let frame = PhysicalFrame::new(test_memory::alloc_phys_page().unwrap()).unwrap();
    let mapping = Mapping { backing: Backing::Owned(frame), attributes: Attributes::EXECUTABLE };
    unsafe { arch::physical_ram().0.add(frame.number() as usize * 4096).write(0x42); }
    unsafe {
        arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::Writable(mapping), test_memory::input(5)).0.unwrap();
        // Transfer lifetime to the mapping by dropping the allocation reference.
        test_memory::free_phys_page(frame.number());
        arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::NoAccess(mapping), test_memory::input(5)).0.unwrap();
    }
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, page).unwrap(), PageEntry::NoAccess(mapping));
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::ReadOnly(mapping), test_memory::input(5)).0.unwrap(); }
    assert_eq!(arch::mem().read::<u8>(HI), 0x42);
    // Self replacement must retain before releasing the last mapping reference.
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::ReadOnly(mapping), test_memory::input(5)).0.unwrap(); }
    assert_eq!(arch::mem().read::<u8>(HI), 0x42);
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::Absent, test_memory::input(5)).0.unwrap(); }
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, page).unwrap(), PageEntry::Absent);
}

#[test]
fn borrowed_cow_copies_and_batch_failure_reports_progress() {
    init();
    let mut machine = arch::Interp;
    let start = UserPage::new(HI as u64).unwrap();
    let memory = test_memory::alloc_shared_pages(1);
    let frame = PhysicalFrame::new(test_memory::direct_frame(memory)).unwrap();
    let mapping = Mapping { backing: Backing::Borrowed(frame), attributes: Attributes::EXECUTABLE };
    unsafe {
        *memory.as_ptr() = 0x42;
        arch_abi::mapping::replace_mapping(&mut machine, start, PageEntry::CopyOnWrite(mapping), test_memory::input(5)).0.unwrap();
    }
    arch::mem().write::<u8>(HI, 0x79);
    assert_eq!(unsafe { *memory.as_ptr() }, 0x42);
    assert_eq!(arch::mem().read::<u8>(HI), 0x79);
    assert!(matches!(arch_abi::mapping::read_mapping(&mut machine, start).unwrap(),
        PageEntry::Writable(Mapping { backing: Backing::Owned(_), .. })));
    let invalid = Mapping { backing: Backing::Borrowed(PhysicalFrame::new(1 << 20).unwrap()), ..mapping };
    let result = unsafe { machine.replace_mappings(start, &[
        PageEntry::Intercepted, PageEntry::ReadOnly(invalid), PageEntry::Absent,
    ], test_memory::input(5)).0 }.unwrap_err();
    assert_eq!(result.completed, 1);
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, start).unwrap(), PageEntry::Intercepted);
    let end = UserPage::new(0xbfff_f000).unwrap();
    let before = arch_abi::mapping::read_mapping(&mut machine, end).unwrap();
    let result = unsafe { machine.replace_mappings(end, &[PageEntry::Absent; 2], test_memory::input(5)).0 }.unwrap_err();
    assert_eq!(result.completed, 0);
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, end).unwrap(), before);
    unsafe { test_memory::free_shared_pages(memory, 1); }
}

#[test]
fn fill_and_range_validation_through_arch() {
    init();
    let mut machine = arch::Interp;
    let start = UserPage::new(HI as u64).unwrap();
    unsafe { machine.fill_mappings(start, 3, PageEntry::Intercepted, test_memory::input(5)).0.unwrap(); }
    let mut entries = [PageEntry::Absent; 3];
    machine.read_mappings(start, &mut entries).unwrap();
    assert_eq!(entries, [PageEntry::Intercepted; 3]);
    assert_eq!(machine.read_mapping_run(start, 3), Ok((PageEntry::Intercepted, 3)));
    assert_eq!(machine.read_mapping_run(start, 0), Err(arch_abi::MappingError::InvalidAddress));
    assert_eq!(machine.read_mapping_run(start, 2), Ok((PageEntry::Intercepted, 2)));
    assert_eq!(machine.read_mapping_run(start, 4), Ok((PageEntry::Intercepted, 3)));
    // Missing tables describe repeated zero backing without consuming input.
    let sparse = UserPage::new(0x6800_0000).unwrap();
    let zero = arch_abi::mapping::read_mapping(&mut machine, sparse).unwrap();
    assert_eq!(machine.read_mapping_run(sparse, 1024), Ok((zero, 1024)));
    // Adjacent RAM frames are different entries, even with equal permissions.
    arch::mem().write::<u8>(HI + 0x10000, 1);
    arch::mem().write::<u8>(HI + 0x11000, 2);
    let ram = UserPage::new((HI + 0x10000) as u64).unwrap();
    assert_eq!(machine.read_mapping_run(ram, 2).unwrap().1, 1);

    let end = UserPage::new(0xbfff_f000).unwrap();
    let before = arch_abi::mapping::read_mapping(&mut machine, end).unwrap();
    let failure = unsafe { machine.fill_mappings(end, 2, PageEntry::Absent, test_memory::input(5)).0 }.unwrap_err();
    assert_eq!(failure, arch_abi::MappingFailure { completed: 0, error: arch_abi::MappingError::InvalidAddress });
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, end).unwrap(), before);
    unsafe { machine.fill_mappings(start, 0, PageEntry::Absent, test_memory::input(5)).0.unwrap(); }
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, start).unwrap(), PageEntry::Intercepted);
}

#[test]
fn supplied_input_exhaustion_preserves_the_uncompleted_suffix() {
    init();
    let mut machine = arch::Interp;
    let mut input = arch_abi::page_supply::PageInput::new();
    input.pages[0] = test_memory::alloc_backed_pages(1);
    input.count = 1;
    // The two entries require different page tables.
    let start = UserPage::new(0x403f_f000).unwrap();
    let untouched = arch_abi::mapping::read_mapping(&mut machine, start.offset(1).unwrap()).unwrap();
    let (result, input) = unsafe { machine.replace_mappings(start, &[PageEntry::Intercepted; 2], input) };
    let failure = result.unwrap_err();
    assert_eq!(failure, arch_abi::MappingFailure { completed: 1, error: arch_abi::MappingError::NeedPages });
    assert_eq!(input.count, 0);
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, start).unwrap(), PageEntry::Intercepted);
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, start.offset(1).unwrap()).unwrap(), untouched);
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, start.offset(1).unwrap(), PageEntry::Intercepted, test_memory::input(5)).0.unwrap(); }
}

#[test]
fn fork_needs_no_allocation_and_detachment_waits_for_input() {
    init();
    let mut machine = arch::Interp;
    let at = UserPage::new(HI as u64).unwrap();
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, at, PageEntry::Intercepted, test_memory::input(5)).0.unwrap(); }
    let input = arch_abi::page_supply::PageInput::new();
    let mut child = arch::RootPageTable::default();
    let ((), input) = machine.user_fork(&mut child, input);
    let parent = machine.activate(child);
    let (result, input) = unsafe { arch_abi::mapping::replace_mapping(&mut machine, at, PageEntry::Absent, input) };
    assert_eq!(result, Err(arch_abi::MappingError::NeedPages));
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, at).unwrap(), PageEntry::Intercepted);
    assert_eq!(input.count, 0);
    unsafe { arch_abi::mapping::replace_mapping(&mut machine, at, PageEntry::Absent, test_memory::input(5)).0.unwrap(); }
    let mut child = machine.activate(parent);
    assert_eq!(arch_abi::mapping::read_mapping(&mut machine, at).unwrap(), PageEntry::Intercepted);
    machine.destroy_space(&mut child);
}

#[test]
fn page_batches_return_rejected_and_unused_ownership() {
    init();
    let mut machine = arch::Interp;
    let pages = test_memory::input(2);
    let numbers = [pages.pages[0], pages.pages[1]];
    let (needed, pages) = machine.supply_pages(pages);
    assert_eq!(needed, 0);
    assert_eq!(&pages.pages[..pages.count], &numbers);
    let at = UserPage::new(HI as u64).unwrap();
    let (result, pages) = unsafe { arch_abi::mapping::replace_mapping(&mut machine, at, PageEntry::Intercepted, pages) };
    result.unwrap();
    assert_eq!(pages.count, 1, "only the new table consumes backing");
    let (result, mut pages) = unsafe { arch_abi::mapping::replace_mapping(&mut machine, at, PageEntry::Absent, pages) };
    result.unwrap();
    assert_eq!(pages.count, 1, "reusing a table returns all unused backing");
    while let Some(page) = pages.take() { test_memory::free_phys_page(page); }
    machine.free_user_pages();
    // Released table backing is returned as data, not through caller storage.
    let (_, mut retired) = machine.supply_pages(Default::default());
    assert!(retired.count > 0);
    while let Some(page) = retired.take() { test_memory::free_phys_page(page); }
}

#[test]
fn retired_pages_are_drained_in_bounded_batches() {
    init();
    let mut machine = arch::Interp;
    let mut expected = std::collections::BTreeSet::new();
    for index in 1..=70 {
        let pages = test_memory::input(1);
        expected.insert(pages.pages[0]);
        let page = UserPage::new(index * 0x40_0000).unwrap();
        let (result, unused) = unsafe { arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::Intercepted, pages) };
        result.unwrap();
        assert_eq!(unused.count, 0);
    }
    machine.free_user_pages();
    for count in [64, 6, 0] {
        let (needed, mut pages) = machine.supply_pages(Default::default());
        assert_eq!(needed, 0);
        assert_eq!(pages.count, count);
        while let Some(page) = pages.take() {
            assert!(expected.remove(&page), "retired backing returned exactly once");
            test_memory::free_phys_page(page);
        }
    }
    assert!(expected.is_empty());
}

#[test]
fn concurrent_forks_detach_replace_and_destroy_shared_tables() {
    init();
    let mut machine = arch::Interp;
    const STRIDE: usize = 4 * 1024 * 1024;
    for index in 0..4 {
        arch::mem().write::<u8>(HI + index * STRIDE, 17);
        arch::mem().write::<u8>(HI + index * STRIDE + 4096, 29);
    }
    let mut roots = Vec::new();
    for _ in 0..4 {
        let mut root = arch::RootPageTable::default();
        machine.user_fork(&mut root, test_memory::input(5));
        roots.push(root);
    }
    let barrier = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        for (worker, root) in roots.into_iter().enumerate() {
            let barrier = &barrier;
            scope.spawn(move || {
                init();
                let mut machine = arch::Interp;
                machine.activate(root);
                for round in 0..16 {
                    test_memory::refill(&machine);
                    let mut child = arch::RootPageTable::default();
                    machine.user_fork(&mut child, test_memory::input(5));
                    let parent = machine.activate(child);
                    barrier.wait();
                    for index in 0..4 {
                        let address = HI + index * STRIDE;
                        assert_eq!(arch::mem().read::<u8>(address), 17);
                        let source = UserPage::new(address as u64).unwrap();
                        let alias = source.offset(2).unwrap();
                        machine.alias_mappings(source, alias, 1, test_memory::input(5)).0.unwrap();
                        machine.swap_mappings(source.offset(1).unwrap(), alias, 1, test_memory::input(5)).0.unwrap();
                        assert_eq!(arch::mem().read::<u8>(address + 8192), 29);
                        arch::mem().write::<u8>(address, (worker * 16 + round + 32) as u8);
                        assert_eq!(arch::mem().read::<u8>(address + 4096), (worker * 16 + round + 32) as u8);
                        let page = UserPage::new((address + 4096) as u64).unwrap();
                        let (result, _) = unsafe { arch_abi::mapping::replace_mapping(&mut machine, page, PageEntry::Absent, test_memory::input(5)) };
                        result.unwrap();
                        assert_eq!(arch_abi::mapping::read_mapping(&mut machine, page).unwrap(), PageEntry::Absent);
                    }
                    // One CPU may release the last old table while another
                    // CPU is retaining its leaves for a private replacement.
                    machine.free_user_pages();
                    let mut empty = machine.activate(parent);
                    machine.destroy_space(&mut empty);
                    for index in 0..4 {
                        assert_eq!(arch::mem().read::<u8>(HI + index * STRIDE), 17);
                        assert_eq!(arch::mem().read::<u8>(HI + index * STRIDE + 4096), 29);
                    }
                }
                machine.free_user_pages();
                test_memory::refill(&machine);
            });
        }
    });
    for index in 0..4 {
        let address = HI + index * STRIDE;
        assert_eq!(arch::mem().read::<u8>(address), 17);
        let entry = arch_abi::mapping::read_mapping(&mut machine, UserPage::new(address as u64).unwrap()).unwrap();
        let mapping = match entry {
            PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => m,
            _ => panic!("expected RAM"),
        };
        assert_eq!(unsafe { test_memory::ownership().references(mapping.backing.frame().number()) }, 1);
    }
    machine.free_user_pages();
}

fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| { let (base, bytes) = arch::physical_ram();
        unsafe { test_memory::init_direct_ram(base, bytes); }
    });
    unsafe { arch::init_guest_ram(test_memory::alloc_backed_pages(arch::PAGING_PAGES), test_memory::ownership()); }
    test_memory::refill(&arch::Interp);
}

/// A deliberately simple test caller. Arch receives ownership metadata and
/// donated frames; it has no dependency on any kernel allocator.
pub mod test_memory {
    use arch_abi::page_supply::{FrameOwnership, FrameRegion, PageInput, REF_BLOCK_PAGES};
    use std::sync::{OnceLock, atomic::{AtomicU64, Ordering}};
    struct Pool { view: FrameOwnership, base: usize, bytes: usize, next: AtomicU64 }
    unsafe impl Send for Pool {}
    unsafe impl Sync for Pool {}
    static POOL: OnceLock<Pool> = OnceLock::new();
    pub unsafe fn init_direct_ram(base: *mut u8, bytes: usize) {
        POOL.get_or_init(|| {
            let pages = bytes / 4096;
            let regions = Box::leak(Box::new([FrameRegion { first: 0, end: pages as u64, offset: 0 }]));
            let bitmap = Box::leak(vec![255u8; pages.div_ceil(8)].into_boxed_slice());
            let refs = Box::leak(vec![0u8; pages].into_boxed_slice());
            let blocks = Box::leak((0..pages.div_ceil(REF_BLOCK_PAGES))
                .map(|i| unsafe { refs.as_mut_ptr().add(i * REF_BLOCK_PAGES) })
                .collect::<Vec<_>>().into_boxed_slice());
            Pool { base: base as usize, bytes, next: AtomicU64::new(256),
                view: FrameOwnership { regions: regions.as_ptr(), regions_len: 1,
                    bitmap: bitmap.as_ptr(), blocks: blocks.as_ptr(), active: pages, zero_page: u64::MAX } }
        });
    }
    fn pool() -> &'static Pool { POOL.get().unwrap() }
    pub fn ownership() -> FrameOwnership { pool().view }
    pub fn alloc_backed_pages(count: usize) -> u64 {
        let p = pool();
        let frame = p.next.fetch_add(count as u64, Ordering::Relaxed);
        assert!((frame as usize + count) * 4096 <= p.bytes);
        unsafe { std::ptr::write_bytes((p.base + frame as usize * 4096) as *mut u8, 0, count * 4096); }
        frame
    }
    pub fn alloc_phys_page() -> Option<u64> { Some(alloc_backed_pages(1)) }
    pub fn is_shared(frame: u64) -> bool { unsafe { ownership().references(frame) > 1 } }
    pub fn free_phys_page(frame: u64) { unsafe { ownership().release_shared(frame); } }
    pub fn free_phys_contig(frame: u64, count: usize) {
        for page in frame..frame + count as u64 { free_phys_page(page); }
    }
    pub fn input(count: usize) -> PageInput {
        let mut pages = PageInput::new();
        for _ in 0..count { pages.push(alloc_backed_pages(1)); }
        pages
    }
    pub fn refill(machine: &impl arch_abi::Memory) {
        let (needed, mut returned) = machine.supply_pages(PageInput::new());
        while let Some(page) = returned.take() { free_phys_page(page); }
        assert_eq!(machine.supply_pages(input(needed)).1.count, 0);
    }
    pub fn direct_frame(base: std::ptr::NonNull<u8>) -> u64 {
        ((base.as_ptr() as usize - pool().base) / 4096) as u64
    }
    pub fn alloc_shared_pages(count: usize) -> std::ptr::NonNull<u8> {
        let frame = alloc_backed_pages(count);
        std::ptr::NonNull::new((pool().base + frame as usize * 4096) as *mut u8).unwrap()
    }
    pub unsafe fn free_shared_pages(base: std::ptr::NonNull<u8>, count: usize) {
        free_phys_contig(((base.as_ptr() as usize - pool().base) / 4096) as u64, count);
    }
}

#[test]
fn arch_alias_swap_overlap_cow_and_retry() {
    init();
    let mut machine = arch::Interp;
    let a = UserPage::new(0x2000000).unwrap();
    let b = UserPage::new(0x3000000).unwrap();
    for i in 0..4 { arch::mem().write::<u32>(a.address() as usize + i * 4096, 10 + i as u32); }
    // A fork shares both tables and leaves. Aliasing must detach the source
    // before making it writable, and must not alter the child's snapshot.
    let mut child = arch::RootPageTable::default();
    machine.user_fork(&mut child, test_memory::input(5));
    assert_eq!(machine.alias_mappings(a, b, 4, Default::default()).0, Err(arch_abi::MappingError::NeedPages));
    for i in 0..4 { assert_eq!(arch::mem().read::<u32>(a.address() as usize + i * 4096), 10 + i as u32); }
    // Small batches force preparation to span several calls. No destination
    // aliases may be installed until preparation is complete.
    for attempt in 0..20 {
        match machine.alias_mappings(a, b, 4, test_memory::input(1)).0 {
            Ok(()) => break,
            Err(arch_abi::MappingError::NeedPages) => {
                assert!(attempt < 19, "preparation failed to make progress");
                assert!(matches!(arch_abi::mapping::read_mapping(&mut machine, b).unwrap(), PageEntry::CopyOnWrite(_)));
            }
            result => panic!("alias failed: {result:?}"),
        }
    }
    arch::mem().write::<u32>(b.address() as usize, 99);
    assert_eq!(arch::mem().read::<u32>(a.address() as usize), 99);
    let parent = machine.activate(child);
    assert_eq!(arch::mem().read::<u32>(a.address() as usize), 10);
    let mut child = machine.activate(parent);
    machine.destroy_space(&mut child);

    // Right-overlapping aliases must use the original snapshot, not repeatedly
    // copy the first frame. Then test the opposite overlap direction.
    machine.alias_mappings(a, a.offset(1).unwrap(), 3, test_memory::input(5)).0.unwrap();
    let values = |base: UserPage| core::array::from_fn::<_, 4, _>(|i| arch::mem().read::<u32>(base.address() as usize + i * 4096));
    assert_eq!(values(a), [99, 99, 11, 12]);
    machine.alias_mappings(a.offset(1).unwrap(), a, 3, test_memory::input(5)).0.unwrap();
    assert_eq!(values(a), [99, 11, 12, 12]);
    machine.swap_mappings(a, a.offset(1).unwrap(), 3, test_memory::input(5)).0.unwrap();
    assert_eq!(values(a), [11, 12, 12, 99]);

    // Invalid ranges are rejected before any preparation or replacement.
    let before = values(a);
    let end = UserPage::new(0xbffff000).unwrap();
    assert_eq!(machine.alias_mappings(a, end, 2, test_memory::input(5)).0, Err(arch_abi::MappingError::InvalidAddress));
    assert_eq!(values(a), before);
}
