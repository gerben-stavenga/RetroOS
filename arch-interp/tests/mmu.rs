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
fn switch(id: u32) -> arch::RootPageTable {
    arch::Interp.activate(arch::RootPageTable(id))
}

#[test]
fn demand_isolation_and_unmap() {
    arch::init_guest_ram(0);

    // Demand-commit at a sparse high address (proves the reserved-VA model).
    arch::mem().write::<u32>(HI, 0xCAFE_BABE);
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE);

    // A second space is isolated; the first space's contents survive a round
    // trip through it.
    let other = arch::new_space();
    let saved = switch(other);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "new space must be zero-isolated");
    arch::mem().write::<u32>(HI, 0x1234_5678);

    switch(saved.0); // back to the original space
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE, "space 0 preserved");

    // Unmap drops the page; the next access demand-zeroes it.
    let mut machine = arch::Interp;
    let zero = machine.read_mapping(UserPage::new(0x7000_0000).unwrap()).unwrap();
    unsafe { machine.replace_mapping(UserPage::new(HI as u64).unwrap(), zero).unwrap(); }
    assert_eq!(arch::mem().read::<u32>(HI), 0, "unmapped page reads back zero");
}

#[test]
fn kernel_owned_shared_pages_are_coherent_across_guest_fork() {
    arch::init_guest_ram(0);
    let mut machine = arch::Interp;
    let memory = machine.alloc_shared_pages(3);
    assert_eq!(memory.as_ptr() as usize % 4096, 0);
    unsafe {
        assert!(core::slice::from_raw_parts(memory.as_ptr(), 3 * 4096).iter().all(|&b| b == 0));
        let start = UserPage::new(HI as u64).unwrap();
        for i in 0..3 {
            let pointer = core::ptr::NonNull::new_unchecked(memory.as_ptr().add(i * 4096));
            let frame = machine.shared_page(pointer);
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
    unsafe { machine.free_shared_pages(memory, 3); }
}

#[test]
fn default_space_does_not_alias_a_suspended_vfork_parent() {
    arch::init_guest_ram(0);
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
    arch::init_guest_ram(0);
    let mut machine = arch::Interp;
    let page = UserPage::new(HI as u64).unwrap();
    let frames = machine.frame_access().unwrap();
    let frame = PhysicalFrame::new((frames.allocate)().unwrap()).unwrap();
    let mapping = Mapping { backing: Backing::Owned(frame), attributes: Attributes::EXECUTABLE };
    (frames.write)(frame.number(), 0, &[0x42]);
    unsafe {
        machine.replace_mapping(page, PageEntry::Writable(mapping)).unwrap();
        // Transfer lifetime to the mapping by dropping the allocation reference.
        (frames.release)(frame.number());
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
    arch::init_guest_ram(0);
    let mut machine = arch::Interp;
    let start = UserPage::new(HI as u64).unwrap();
    let memory = machine.alloc_shared_pages(1);
    let frame = unsafe { machine.shared_page(memory) };
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
    unsafe { machine.free_shared_pages(memory, 1); }
}

#[test]
fn fill_and_range_validation_through_arch() {
    arch::init_guest_ram(0);
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
