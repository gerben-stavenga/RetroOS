//! Kernel-owned physical pages supplied to arch as owned batches.
#![forbid(unsafe_code)]
use crate::Core;
use bytemuck::Pod;
use super::phys_mm;
use arch_abi::page_supply::{OwnedPage, PageInput, SupplyStatus, SUPPLY_CAPACITY, FAULT_PAGES};
#[thread_local]
static SPARES: core::cell::RefCell<PageInput> = const { core::cell::RefCell::new(PageInput::new()) };

fn release(mut pages: PageInput) {
    while let Some(page) = pages.take() { phys_mm::free_phys_page(page); }
}

/// Drain retired frames before asking the allocator for more backing.
fn collect<A: arch_abi::Memory>(machine: &A) -> usize {
    loop {
        let (needed, returned) = machine.supply_pages(PageInput::new());
        let empty = returned.is_empty();
        release(returned);
        if empty { return needed; }
    }
}

pub fn service<A: arch_abi::Memory>(machine: &A) {
    let needed = collect(machine);
    replenish(machine, SupplyStatus { needed, returned: 0 });
}

/// Execution already reports the reserve; only enter arch to transfer pages.
pub fn replenish<A: arch_abi::Memory>(machine: &A, status: SupplyStatus) {
    let SupplyStatus { mut needed, mut returned } = status;
    while returned != 0 {
        let (remaining, pages) = machine.supply_pages(PageInput::new());
        assert!(!pages.is_empty() && pages.len() <= returned, "invalid retired-page count");
        returned -= pages.len();
        needed = remaining;
        release(pages);
    }
    if needed == 0 { return; }
    let pages = phys_mm::page_batch(needed);
    assert!(SUPPLY_CAPACITY - needed + pages.len() >= FAULT_PAGES,
        "physical memory exhausted refilling fault reserve");
    let (_, returned) = machine.supply_pages(pages);
    release(returned);
}

/// Each operation owns its input batch and returns the unused frames.
pub fn with_pages<A: Core, R>(machine: &mut A, count: usize,
    operation: impl FnOnce(&mut A, PageInput) -> (R, PageInput)) -> R
{
    let (result, unused) = operation(machine, input_pages(count));
    keep_input(unused);
    collect(machine);
    result
}

fn input_pages(count: usize) -> PageInput {
    assert!(count <= SUPPLY_CAPACITY);
    let mut input = PageInput::new();
    for _ in 0..count {
        let spare = SPARES.borrow_mut().take();
        input.push(spare.or_else(phys_mm::alloc_phys_page)
            .expect("out of physical memory preparing arch input"));
    }
    input
}
fn keep_input(mut unused: PageInput) {
    let mut spares = SPARES.borrow_mut();
    while let Some(page) = unused.take() {
        spares.push(page);
    }
}
pub fn fork<A: Core>(machine: &mut A, child: &mut A::AddressSpace) {
    with_pages(machine, 3, |machine, pages| machine.user_fork(child, pages));
}

/// Install a batch, resuming after the committed prefix if table backing runs out.
pub(crate) fn install<A: Core>(machine: &mut A, mut page: UserPage,
    mut entries: &[Install<'_>],
) -> Result<(), arch_abi::MappingError> {
    while !entries.is_empty() {
        match with_pages(machine, 5, |machine, pages| machine.replace_mappings(page, entries, pages)) {
            Ok(()) => return Ok(()),
            Err(failure) if failure.error == arch_abi::MappingError::NeedPages => {
                page = page.offset(failure.completed)?;
                entries = &entries[failure.completed..];
            }
            Err(failure) => return Err(failure.error),
        }
    }
    Ok(())
}

/// The cache holds a live reference until arch acquires its own.
pub(crate) fn map_cached_private<A: Core>(machine: &mut A, vpage: usize, frame: &OwnedPage,
    writable: bool, executable: bool,
) -> Result<(), arch_abi::MappingError> {
    let access = if writable { Access::CopyOnWrite } else { Access::ReadOnly };
    install(machine, page(vpage), &[Install::owned(frame, access,
        Attributes::default().with_executable(executable))])
}

pub(crate) use super::platform::ResidentSharedPages;

/// Map a platform-owned physical view or an intercepted guest aperture.
pub(crate) fn map_physical<A: Core>(machine: &mut A, vpage: usize, count: usize, physical: u64, flags: u64) {
    if count == 0 { return; }
    let start = page(vpage);
    start.offset(count - 1).expect("invalid device mapping range");
    if flags & arch_abi::MAP_MMIO != 0 {
        fill_with(machine, start, count, |machine, start, count, pages|
            machine.fill_mappings(start, count, Install::INTERCEPTED, pages))
            .expect("cannot install intercepted aperture");
        return;
    }
    let region = super::platform::PhysicalView::new(physical, count)
        .expect("physical view overlaps allocator RAM or exceeds address limits");
    let mut attributes = Attributes::EXECUTABLE;
    for (bit, attr) in [(1 << 3, Attributes::WRITE_THROUGH), (1 << 4, Attributes::CACHE_DISABLE), (1 << 7, Attributes::PAT)] {
        if flags & bit != 0 { attributes = attributes | attr; }
    }
    // Bounded batches keep bank switching to one trap/TLB flush per chunk.
    let mut entries = [Install::ABSENT; 64];
    for base in (0..count).step_by(entries.len()) {
        let length = (count - base).min(entries.len());
        for (offset, entry) in entries[..length].iter_mut().enumerate() {
            *entry = region.mapping(base + offset, attributes);
        }
        install(machine, start.offset(base).unwrap(), &entries[..length]).expect("cannot map physical backing");
    }
}

use arch_abi::{UserPage, mapping::{Access, Edit, Install, Missing, Protection}, page_entry::Attributes};

fn page(vpage: usize) -> UserPage { UserPage::new((vpage as u64).checked_mul(4096).unwrap()).unwrap() }
/// Provide backing and resume an architecture edit after its committed prefix.
pub(crate) fn edit<A: Core>(machine: &mut A, start: UserPage, count: usize, operation: Edit)
    -> Result<(), arch_abi::MappingError>
{
    fill_with(machine, start, count, |machine, start, count, pages|
        machine.edit_mappings(start, count, operation, pages))
}

/// Discard contents and allow subsequent anonymous writes.
pub fn reset<A: Core>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    edit(machine, page(vpage), count, Edit::ReserveZero {
        access: Protection::ReadWrite, executable: true, only_if_vacant: false,
    }).expect("reset mappings");
}

pub(crate) fn unmap<A: Core>(machine: &mut A, start: UserPage, count: usize)
    -> Result<(), arch_abi::MappingError>
{
    fill_with(machine, start, count, |machine, start, count, pages|
        machine.fill_mappings(start, count, Install::ABSENT, pages))
}

/// Commit distinct zeroed RAM for the given range.
pub fn fresh<A: Core>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    edit(machine, page(vpage), count, Edit::CommitZero).expect("commit anonymous RAM");
}

/// Change the permissions of backed pages in the range.
pub fn protect<A: Core>(machine: &mut A, vpage: usize, count: usize, writable: bool, executable: bool) {
    if count == 0 { return; }
    let access = if writable { Protection::ReadWrite } else { Protection::ReadOnly };
    edit(machine, page(vpage), count, Edit::Protect { access, executable, missing: Missing::Skip })
        .expect("set protection");
}

/// Request aliases; arch owns overlap handling, COW, and frame references.
pub fn alias<A: Core>(machine: &mut A, source: usize, destination: usize, count: usize) {
    if count == 0 || source == destination { return; }
    loop {
        match with_pages(machine, 5, |machine, pages| machine.alias_mappings(page(source), page(destination), count, pages)) {
            Err(arch_abi::MappingError::NeedPages) => continue,
            result => { result.expect("install aliases"); return; }
        }
    }
}

/// Request pairwise swaps; arch preserves both references across replacement.
pub fn swap<A: Core>(machine: &mut A, a: usize, b: usize, count: usize) {
    if count == 0 || a == b { return; }
    loop {
        match with_pages(machine, 5, |machine, pages| machine.swap_mappings(page(a), page(b), count, pages)) {
            Err(arch_abi::MappingError::NeedPages) => continue,
            result => { result.expect("swap mappings"); return; }
        }
    }
}

fn fill_with<A: Core>(machine: &mut A, mut start: UserPage, mut count: usize,
    mut operation: impl FnMut(&mut A, UserPage, usize, PageInput) ->
        (Result<(), arch_abi::MappingFailure>, PageInput),
) -> Result<(), arch_abi::MappingError> {
    if count == 0 { return Ok(()); }
    start.offset(count - 1)?;
    loop {
        match with_pages(machine, 5, |machine, pages| operation(machine, start, count, pages)) {
            Ok(()) => return Ok(()),
            Err(failure) if failure.error == arch_abi::MappingError::NeedPages => {
                count -= failure.completed;
                if count == 0 { return Ok(()); }
                start = start.offset(failure.completed)?;
            }
            Err(failure) => return Err(failure.error),
        }
    }
}

/// Construct the DOS personality's memory, independently of host firmware.
/// A/B are the video aperture; C/E are UMB RAM, D is the EMS frame, and F
/// contains the substitute BIOS ROM. BIOS installation populates its fonts.
pub fn map_dos_memory<A: Core>(machine: &mut A) {
    reset(machine, 0, 0xa0);
    fresh(machine, 0, 16);
    fresh(machine, 0xa0, 0x60);
    protect(machine, 0xf0, 0x10, false, true);
}

pub fn map_text_screen<A: Core>(machine: &mut A) {
    if let Some(frame) = super::platform::text_frame() { map_physical(machine, 0xb8, 8, frame, 0); }
    else { fresh(machine, 0xb8, 8); }
}

/// Replace image pages with explicit private RAM before a workspace patches them.
pub fn private_copy<A: Core>(machine: &mut A, first: usize, count: usize) {
    if count == 0 { return; }
    edit(machine, page(first), count, Edit::MakePrivate).expect("make image private");
}

/// Kernel transfers supply explicit backing for page-bounded user accesses.
/// They never use or replenish the execution fault reserve.
pub trait GuestBytes {
    /// Copy a high user buffer without narrowing its address. False means EFAULT.
    fn high_copy(&mut self, address: u64, bytes: &mut [u8], to_user: bool) -> bool;
    fn copy_from(&self, address: u64, bytes: &mut [u8]);
    fn copy_to(&mut self, address: u64, bytes: &[u8]);
    fn read<T: Pod>(&self, address: u64) -> T {
        let mut value = T::zeroed();
        self.copy_from(address, bytemuck::bytes_of_mut(&mut value));
        value
    }
    fn write<T: bytemuck::NoUninit>(&mut self, address: u64, value: T) {
        self.copy_to(address, bytemuck::bytes_of(&value));
    }
    fn copy_cstr(&self, address: u64, bytes: &mut [u8]) -> usize {
        for (i, byte) in bytes.iter_mut().enumerate() {
            let value = self.read::<u8>(address + i as u64);
            if value == 0 { return i; }
            *byte = value;
        }
        bytes.len()
    }
    fn zero(&mut self, mut address: u64, mut length: usize) {
        let zeros = [0; 4096];
        while length != 0 {
            let n = length.min(4096);
            self.copy_to(address, &zeros[..n]);
            address += n as u64;
            length -= n;
        }
    }
    fn copy_within(&mut self, src: u64, dst: u64, len: usize) {
        let mut buffer = [0; 4096];
        let mut remaining = len;
        while remaining != 0 {
            let n = remaining.min(buffer.len());
            let offset = if dst > src { remaining - n } else { len - remaining };
            self.copy_from(src + offset as u64, &mut buffer[..n]);
            self.copy_to(dst + offset as u64, &buffer[..n]);
            remaining -= n;
        }
    }
}
impl<A: arch_abi::Core + arch_abi::GuestBytes> GuestBytes for A {
    fn high_copy(&mut self, mut address: u64, mut bytes: &mut [u8], to_user: bool) -> bool {
        while !bytes.is_empty() {
            let n = bytes.len().min(4096 - (address as usize & 4095));
            let (part, rest) = bytes.split_at_mut(n);
            let pages = input_pages(5);
            let (result, unused) = if to_user {
                arch_abi::GuestBytes::copy_to(self, address, part, pages)
            } else { arch_abi::GuestBytes::copy_from(self, address, part, pages) };
            keep_input(unused);
            if result.is_none() { return false; }
            address += n as u64;
            bytes = rest;
        }
        true
    }
    fn copy_from(&self, mut address: u64, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let n = bytes.len().min(4096 - (address as usize & 4095));
            let (part, rest) = bytes.split_at_mut(n);
            let (result, unused) = arch_abi::GuestBytes::copy_from(self, address, part, input_pages(5));
            keep_input(unused);
            result.expect("inaccessible guest read");
            address += n as u64;
            bytes = rest;
        }
    }
    fn copy_to(&mut self, mut address: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = bytes.len().min(4096 - (address as usize & 4095));
            let (result, unused) = arch_abi::GuestBytes::copy_to(self, address, &bytes[..n], input_pages(5));
            keep_input(unused);
            result.expect("inaccessible guest write");
            address += n as u64;
            bytes = &bytes[n..];
        }
    }
}
