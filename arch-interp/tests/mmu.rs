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
    let zero = machine.read_mapping(UserPage::new(0x7000_0000).unwrap()).unwrap();
    unsafe { machine.replace_mapping(UserPage::new(HI as u64).unwrap(), zero).unwrap(); }
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
            machine.replace_mapping(start.offset(i).unwrap(), PageEntry::Writable(Mapping {
                backing: Backing::Borrowed(frame), attributes: Attributes::EXECUTABLE,
            })).unwrap();
        }
        *memory.as_ptr().add(8197) = 0xC3;
    }
    assert_eq!(arch::mem().read::<u8>(HI + 8197), 0xC3);
    let mut child = arch::RootPageTable::default();
    machine.user_fork(&mut child);
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
        machine.replace_mapping(page, PageEntry::Writable(mapping)).unwrap();
        // Transfer lifetime to the mapping by dropping the allocation reference.
        test_memory::free_phys_page(frame.number());
        machine.replace_mapping(page, PageEntry::NoAccess(mapping)).unwrap();
    }
    assert_eq!(machine.read_mapping(page).unwrap(), PageEntry::NoAccess(mapping));
    unsafe { machine.replace_mapping(page, PageEntry::ReadOnly(mapping)).unwrap(); }
    assert_eq!(arch::mem().read::<u8>(HI), 0x42);
    // Self replacement must retain before releasing the last mapping reference.
    unsafe { machine.replace_mapping(page, PageEntry::ReadOnly(mapping)).unwrap(); }
    assert_eq!(arch::mem().read::<u8>(HI), 0x42);
    unsafe { machine.replace_mapping(page, PageEntry::Absent).unwrap(); }
    assert_eq!(machine.read_mapping(page).unwrap(), PageEntry::Absent);
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
        machine.replace_mapping(start, PageEntry::CopyOnWrite(mapping)).unwrap();
    }
    arch::mem().write::<u8>(HI, 0x79);
    assert_eq!(unsafe { *memory.as_ptr() }, 0x42);
    assert_eq!(arch::mem().read::<u8>(HI), 0x79);
    assert!(matches!(machine.read_mapping(start).unwrap(),
        PageEntry::Writable(Mapping { backing: Backing::Owned(_), .. })));
    let invalid = Mapping { backing: Backing::Borrowed(PhysicalFrame::new(1 << 20).unwrap()), ..mapping };
    let result = unsafe { machine.replace_mappings(start, &[
        PageEntry::Intercepted, PageEntry::ReadOnly(invalid), PageEntry::Absent,
    ]) }.unwrap_err();
    assert_eq!(result.completed, 1);
    assert_eq!(machine.read_mapping(start).unwrap(), PageEntry::Intercepted);
    let end = UserPage::new(0xbfff_f000).unwrap();
    let before = machine.read_mapping(end).unwrap();
    let result = unsafe { machine.replace_mappings(end, &[PageEntry::Absent; 2]) }.unwrap_err();
    assert_eq!(result.completed, 0);
    assert_eq!(machine.read_mapping(end).unwrap(), before);
    unsafe { test_memory::free_shared_pages(memory, 1); }
}

#[test]
fn fill_and_range_validation_through_arch() {
    init();
    let mut machine = arch::Interp;
    let start = UserPage::new(HI as u64).unwrap();
    unsafe { machine.fill_mappings(start, 3, PageEntry::Intercepted).unwrap(); }
    let mut entries = [PageEntry::Absent; 3];
    machine.read_mappings(start, &mut entries).unwrap();
    assert_eq!(entries, [PageEntry::Intercepted; 3]);
    assert_eq!(machine.read_mapping_run(start, 3), Ok((PageEntry::Intercepted, 1)));
    assert_eq!(machine.read_mapping_run(start, 0), Err(arch_abi::MappingError::InvalidAddress));
    let end = UserPage::new(0xbfff_f000).unwrap();
    let before = machine.read_mapping(end).unwrap();
    let failure = unsafe { machine.fill_mappings(end, 2, PageEntry::Absent) }.unwrap_err();
    assert_eq!(failure, arch_abi::MappingFailure { completed: 0, error: arch_abi::MappingError::InvalidAddress });
    assert_eq!(machine.read_mapping(end).unwrap(), before);
    unsafe { machine.fill_mappings(start, 0, PageEntry::Absent).unwrap(); }
    assert_eq!(machine.read_mapping(start).unwrap(), PageEntry::Intercepted);
}

#[test]
fn supplied_input_exhaustion_preserves_the_uncompleted_suffix() {
    init();
    let mut machine = arch::Interp;
    let mut input = arch_abi::page_supply::PageInput::new();
    input.pages[0] = test_memory::alloc_backed_pages(1);
    input.count = 1;
    let previous = machine.set_page_input(&mut input);
    // The two entries require different page tables.
    let start = UserPage::new(0x403f_f000).unwrap();
    let untouched = machine.read_mapping(start.offset(1).unwrap()).unwrap();
    let failure = unsafe { machine.replace_mappings(start, &[PageEntry::Intercepted; 2]) }.unwrap_err();
    assert_eq!(failure, arch_abi::MappingFailure { completed: 1, error: arch_abi::MappingError::NeedPages });
    assert_eq!(input.count, 0);
    assert_eq!(machine.read_mapping(start).unwrap(), PageEntry::Intercepted);
    assert_eq!(machine.read_mapping(start.offset(1).unwrap()).unwrap(), untouched);
    machine.set_page_input(previous);
    unsafe { machine.replace_mapping(start.offset(1).unwrap(), PageEntry::Intercepted).unwrap(); }
}

#[test]
fn fork_needs_no_allocation_and_detachment_waits_for_input() {
    init();
    let mut machine = arch::Interp;
    let at = UserPage::new(HI as u64).unwrap();
    unsafe { machine.replace_mapping(at, PageEntry::Intercepted).unwrap(); }
    let mut input = arch_abi::page_supply::PageInput::new();
    let previous = machine.set_page_input(&mut input);
    let mut child = arch::RootPageTable::default();
    machine.user_fork(&mut child);
    let parent = machine.activate(child);
    assert_eq!(unsafe { machine.replace_mapping(at, PageEntry::Absent) }, Err(arch_abi::MappingError::NeedPages));
    assert_eq!(machine.read_mapping(at).unwrap(), PageEntry::Intercepted);
    assert_eq!(input.count, 0);
    machine.set_page_input(previous);
    unsafe { machine.replace_mapping(at, PageEntry::Absent).unwrap(); }
    let mut child = machine.activate(parent);
    assert_eq!(machine.read_mapping(at).unwrap(), PageEntry::Intercepted);
    machine.destroy_space(&mut child);
}

fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| { let (base, bytes) = arch::physical_ram();
        unsafe { test_memory::init_direct_ram(base, bytes); }
    });
    unsafe { arch::init_guest_ram(test_memory::alloc_backed_pages(arch::PAGING_PAGES)); }
    unsafe {
        let supply = arch::Interp.page_supply().unwrap();
        (*supply).ownership = test_memory::ownership();
        test_memory::replenish_supply(supply);
    }
    let mut input = Box::new(arch_abi::page_supply::PageInput::new());
    for _ in 0..64 {
        input.pages[input.count] = test_memory::alloc_backed_pages(1);
        input.count += 1;
    }
    arch::Interp.set_page_input(Box::into_raw(input));
}

/// A deliberately simple test caller. Arch receives ownership metadata and
/// donated frames; it has no dependency on any kernel allocator.
pub mod test_memory {
    use arch_abi::page_supply::{FrameOwnership, FrameRegion, PageSupply, REF_BLOCK_PAGES};
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
    pub unsafe fn replenish_supply(supply: *mut PageSupply) {
        unsafe {
            while (*supply).count < (*supply).pages.len() {
                (*supply).donate(alloc_backed_pages(1));
            }
        }
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
