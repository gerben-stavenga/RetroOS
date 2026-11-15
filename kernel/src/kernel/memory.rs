//! Kernel-owned physical pages supplied to arch as owned batches.
use crate::Arch;
use super::phys_mm;
use arch_abi::page_supply::{PageInput, SUPPLY_CAPACITY, FAULT_PAGES};
#[thread_local]
static mut SPARES: PageInput = PageInput::new();

fn release(mut pages: PageInput) {
    while let Some(page) = pages.take() { phys_mm::free_phys_page(page); }
}

/// Drain retired frames before asking the allocator for more backing.
fn collect<A: arch_abi::Memory>(machine: &A) -> usize {
    loop {
        let (needed, returned) = machine.supply_pages(PageInput::new());
        let empty = returned.count == 0;
        release(returned);
        if empty { return needed; }
    }
}

pub fn service<A: arch_abi::Memory>(machine: &A) {
    let needed = collect(machine);
    let pages = phys_mm::page_batch(needed);
    assert!(SUPPLY_CAPACITY - needed + pages.count >= FAULT_PAGES,
        "physical memory exhausted refilling fault reserve");
    let (_, returned) = machine.supply_pages(pages);
    release(returned);
}

/// Each operation owns its input batch and returns the unused frames.
pub fn with_pages<A: Arch, R>(machine: &mut A, count: usize,
    operation: impl FnOnce(&mut A, PageInput) -> (R, PageInput)) -> R
{
    assert!(count <= SUPPLY_CAPACITY);
    service(machine);
    let mut input = PageInput::new();
    for _ in 0..count {
        let spare = unsafe { (*(&raw mut SPARES)).take() };
        input.push(spare.or_else(phys_mm::alloc_phys_page)
            .expect("out of physical memory preparing arch input"));
    }
    let (result, mut unused) = operation(machine, input);
    while let Some(page) = unused.take() {
        unsafe { (*(&raw mut SPARES)).push(page); }
    }
    collect(machine);
    result
}
pub fn fork<A: Arch>(machine: &mut A, child: &mut A::PageTable) {
    with_pages(machine, 3, |machine, pages| machine.user_fork(child, pages));
}

pub(crate) fn allocate_frame<A: arch_abi::Memory>(machine: &A) -> Option<u64> {
    collect(machine);
    phys_mm::alloc_phys_page()
}

pub fn private_tables<A: Arch>(machine: &mut A) {
    loop {
        let result = with_pages(machine, SUPPLY_CAPACITY, |machine, pages| machine.private_page_tables(pages));
        if result == 0 { break; }
        assert_eq!(result, -11, "cannot detach process page tables");
    }
}

/// Install one mapping with explicit table backing and retry only uncompleted work.
/// # Safety
/// The entry's backing must satisfy Arch::replace_mapping's requirements.
pub unsafe fn replace<A: Arch>(machine: &mut A, page: arch_abi::UserPage,
    entry: arch_abi::page_entry::PageEntry) -> Result<(), arch_abi::MappingError>
{
    loop {
        let result = with_pages(machine, 5, |machine, pages| unsafe { machine.replace_mapping(page, entry, pages) });
        if result != Err(arch_abi::MappingError::NeedPages) { return result; }
    }
}

/// Install a batch, resuming after the committed prefix if table backing runs out.
/// # Safety
/// Every entry must satisfy Arch::replace_mapping's requirements.
pub unsafe fn replace_batch<A: Arch>(machine: &mut A, mut page: arch_abi::UserPage,
    mut entries: &[arch_abi::page_entry::PageEntry]) -> Result<(), arch_abi::MappingError>
{
    while !entries.is_empty() {
        match with_pages(machine, 5, |machine, pages| unsafe { machine.replace_mappings(page, entries, pages) }) {
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

/// File-cache mapping composition: the cache keeps shared backing alive, while
/// a private mapping retains a reference and starts writable views as COW.
pub fn map_cached_frame<A: Arch>(machine: &mut A, vpage: usize, frame: u64,
    shared: bool, writable: bool, executable: bool) -> bool
{
    use arch_abi::{UserPage, page_entry::{Backing, Mapping, PageEntry, PhysicalFrame}};
    let Some(address) = (vpage as u64).checked_mul(4096) else { return false; };
    let Ok(page) = UserPage::new(address) else { return false; };
    let Ok(frame) = PhysicalFrame::new(frame) else { return false; };
    let mapping = Mapping { backing: if shared { Backing::Borrowed(frame) } else { Backing::Owned(frame) },
        attributes: Attributes::default().with_executable(executable) };
    let entry = if !writable { PageEntry::ReadOnly(mapping) }
        else if shared { PageEntry::Writable(mapping) } else { PageEntry::CopyOnWrite(mapping) };
    unsafe { replace(machine, page, entry) }.is_ok()
}

/// Borrow shared allocation pages into a user view. Ownership remains with the
/// allocation; allocation and mapping are separate architecture mechanisms.
/// # Safety
/// The allocation must outlive all aliases; synchronize access with user code.
pub unsafe fn map_shared_pages<A: Arch>(machine: &mut A, vpage: usize,
    base: core::ptr::NonNull<u8>, count: usize)
{
    use arch_abi::{UserPage, page_entry::{Attributes, Backing, Mapping, PageEntry}};
    let start = UserPage::new((vpage as u64).checked_mul(4096).expect("mapping address overflow")).unwrap();
    if count != 0 { start.offset(count - 1).unwrap(); }
    for index in 0..count {
        let pointer = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(index * 4096)) };
        let frame = unsafe { super::platform::physical_frame(pointer) };
        let entry = PageEntry::Writable(Mapping { backing: Backing::Borrowed(frame), attributes: Attributes::EXECUTABLE });
        unsafe { replace(machine, start.offset(index).unwrap(), entry) }.expect("cannot map shared backing");
    }
}

/// Borrow physical backing into user mappings.
pub fn map_physical<A: Arch>(machine: &mut A, vpage: usize, count: usize, physical: u64, flags: u64) {
    use arch_abi::{UserPage, page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame}};
    let start = UserPage::new((vpage as u64).checked_mul(4096).expect("mapping address overflow")).unwrap();
    if count != 0 { start.offset(count - 1).unwrap(); }
    let mut attributes = Attributes::EXECUTABLE;
    for (bit, attr) in [(1 << 3, Attributes::WRITE_THROUGH), (1 << 4, Attributes::CACHE_DISABLE), (1 << 7, Attributes::PAT)] {
        if flags & bit != 0 { attributes = attributes | attr; }
    }
    // Bounded batches keep bank switching to one trap/TLB flush per chunk.
    let mut entries = [PageEntry::Absent; 64];
    for base in (0..count).step_by(entries.len()) {
        let length = (count - base).min(entries.len());
        for (offset, entry) in entries[..length].iter_mut().enumerate() {
            *entry = if flags & arch_abi::MAP_MMIO != 0 { PageEntry::Intercepted } else {
                let frame = PhysicalFrame::new(physical.checked_add((base + offset) as u64).expect("physical range overflow")).unwrap();
                PageEntry::Writable(Mapping { backing: Backing::Borrowed(frame), attributes })
            };
        }
        unsafe { replace_batch(machine, start.offset(base).unwrap(), &entries[..length]) }.expect("cannot map physical backing");
    }
}

use arch_abi::{UserPage, page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame}};

fn page(vpage: usize) -> UserPage { UserPage::new((vpage as u64).checked_mul(4096).unwrap()).unwrap() }
fn backing(entry: PageEntry) -> Option<Mapping> {
    match entry {
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => Some(m),
        _ => None,
    }
}
fn pin(entry: PageEntry) {
    if let Some(Mapping { backing: Backing::Owned(frame), .. }) = backing(entry) {
        assert!(phys_mm::inc_shared_count(frame.number()), "invalid mapping reference");
    }
}
fn unpin(entry: PageEntry) {
    if let Some(Mapping { backing: Backing::Owned(frame), .. }) = backing(entry) { phys_mm::free_phys_page(frame.number()); }
}

static ZERO_FRAME: spin::Once<PhysicalFrame> = spin::Once::new();
pub fn zero_mapping<A: Arch>(machine: &A, executable: bool) -> Mapping {
    let frame = *ZERO_FRAME.call_once(|| {
        let frame = allocate_frame(machine).expect("zero frame allocation");
        super::platform::write_physical_frame(frame, 0, &[0; 4096]);
        PhysicalFrame::new(frame).unwrap()
    });
    Mapping { backing: Backing::Borrowed(frame), attributes: Attributes::default().with_executable(executable) }
}

/// Personality policy: discard contents and allow subsequent anonymous writes.
pub fn reset<A: Arch>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    let entry = PageEntry::CopyOnWrite(zero_mapping(machine, true));
    unsafe { fill(machine, page(vpage), count, entry) }.expect("reset mappings");
}

/// Allocate distinct RAM before creating aliases (EMS/A20/device shadows).
pub fn fresh<A: Arch>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    let start = page(vpage); start.offset(count - 1).unwrap();
    for index in 0..count {
        service(machine);
        let frame = allocate_frame(machine).expect("anonymous frame allocation");
        super::platform::write_physical_frame(frame, 0, &[0; 4096]);
        let entry = PageEntry::Writable(Mapping { backing: Backing::Owned(PhysicalFrame::new(frame).unwrap()),
            attributes: Attributes::EXECUTABLE });
        let result = unsafe { replace(machine, start.offset(index).unwrap(), entry) };
        phys_mm::free_phys_page(frame);
        result.expect("map anonymous RAM");
    }
}

/// Change access while keeping contents and cache attributes. Owned storage is
/// made COW when write access is granted; externally owned storage stays shared.
pub fn protect<A: Arch>(machine: &mut A, vpage: usize, count: usize, writable: bool, executable: bool) {
    for index in 0..count {
        let page = page(vpage + index);
        let old = machine.read_mapping(page).expect("read protection");
        let Some(mut mapping) = backing(old) else { continue; };
        let mut temporary = None;
        if !writable && matches!(old, PageEntry::CopyOnWrite(Mapping { backing: Backing::Borrowed(_), .. }))
            && !ZERO_FRAME.get().is_some_and(|f| *f == mapping.backing.frame()) {
            // ReadOnly has no hidden future-write policy. A borrowed private
            // snapshot becomes normal owned RAM before losing its COW state.
            let frame = allocate_frame(machine).expect("private protection backing");
            let mut bytes = [0; 4096];
            super::platform::read_physical_frame(mapping.backing.frame().number(), 0, &mut bytes);
            super::platform::write_physical_frame(frame, 0, &bytes);
            mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
            temporary = Some(frame);
        }
        mapping.attributes = mapping.attributes.with_executable(executable);
        let entry = if !writable { PageEntry::ReadOnly(mapping) }
            else if matches!(old, PageEntry::CopyOnWrite(_)) || matches!(mapping.backing, Backing::Owned(_)) || ZERO_FRAME.get().is_some_and(|f| *f == mapping.backing.frame()) {
                PageEntry::CopyOnWrite(mapping)
            } else { PageEntry::Writable(mapping) };
        let result = unsafe { replace(machine, page, entry) };
        if let Some(frame) = temporary { phys_mm::free_phys_page(frame); }
        result.expect("set protection");
    }
}

/// Snapshot and pin all source references before replacing overlapping ranges.
/// COW sources become private RAM before another writable alias is installed.
pub fn alias<A: Arch>(machine: &mut A, source: usize, destination: usize, count: usize) {
    if count == 0 || source == destination { return; }
    let mut entries = alloc::vec::Vec::with_capacity(count);
    for index in 0..count {
        let at = page(source + index);
        let mut entry = machine.read_mapping(at).expect("read alias source");
        if let PageEntry::CopyOnWrite(mut mapping) = entry {
            service(machine);
            let frame = allocate_frame(machine).expect("alias backing allocation");
            let mut bytes = [0; 4096];
            super::platform::read_physical_frame(mapping.backing.frame().number(), 0, &mut bytes);
            super::platform::write_physical_frame(frame, 0, &bytes);
            mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
            entry = PageEntry::Writable(mapping);
            let result = unsafe { replace(machine, at, entry) };
            phys_mm::free_phys_page(frame);
            result.expect("materialize alias source");
        }
        pin(entry); entries.push(entry);
    }
    let result = unsafe { replace_batch(machine, page(destination), &entries) };
    for entry in entries { unpin(entry); }
    result.expect("install aliases");
}

/// Swap each pair while holding both references across replacement.
pub fn swap<A: Arch>(machine: &mut A, a: usize, b: usize, count: usize) {
    for index in 0..count {
        let a = page(a + index); let b = page(b + index);
        let left = machine.read_mapping(a).unwrap(); let right = machine.read_mapping(b).unwrap();
        pin(left); pin(right);
        unsafe { replace(machine, a, right).unwrap(); replace(machine, b, left).unwrap(); }
        unpin(left); unpin(right);
    }
}

/// # Safety
/// Same backing lifetime requirements as Arch::fill_mappings.
pub unsafe fn fill<A: Arch>(machine: &mut A, mut start: UserPage, mut count: usize, entry: PageEntry) -> Result<(), arch_abi::MappingError> {
    while count != 0 {
        match with_pages(machine, 5, |machine, pages| unsafe { machine.fill_mappings(start, count, entry, pages) }) {
            Ok(()) => return Ok(()),
            Err(failure) if failure.error == arch_abi::MappingError::NeedPages => {
                start = start.offset(failure.completed)?; count -= failure.completed;
            }
            Err(failure) => return Err(failure.error),
        }
    }
    Ok(())
}

/// Construct the DOS personality's memory, independently of host firmware.
/// A/B are the video aperture; C/E are UMB RAM, D is the EMS frame, and F
/// contains the substitute BIOS ROM. BIOS installation populates its fonts.
pub fn map_dos_memory<A: Arch>(machine: &mut A) {
    reset(machine, 0, 0xa0);
    fresh(machine, 0, 16);
    fresh(machine, 0xa0, 0x60);
    protect(machine, 0xf0, 0x10, false, true);
}

static TEXT_FRAME: spin::Once<u64> = spin::Once::new();
pub fn set_text_frame(frame: u64) { TEXT_FRAME.call_once(|| frame); }
pub fn text_frame() -> u64 { *TEXT_FRAME.get().expect("text screen backing") }
pub fn map_text_screen<A: Arch>(machine: &mut A) {
    if let Some(&frame) = TEXT_FRAME.get() { map_physical(machine, 0xb8, 8, frame, 0); }
    else { fresh(machine, 0xb8, 8); }
}

/// Replace image pages with explicit private RAM before a workspace patches them.
pub fn private_copy<A: Arch>(machine: &mut A, first: usize, count: usize) {
    for index in 0..count {
        let at = page(first + index);
        let mut mapping = backing(machine.read_mapping(at).expect("read image mapping")).expect("image backing");
        service(machine);
        let frame = allocate_frame(machine).expect("private image allocation");
        let mut bytes = [0; 4096];
        super::platform::read_physical_frame(mapping.backing.frame().number(), 0, &mut bytes);
        super::platform::write_physical_frame(frame, 0, &bytes);
        mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
        let result = unsafe { replace(machine, at, PageEntry::Writable(mapping)) };
        phys_mm::free_phys_page(frame);
        result.expect("install private image");
    }
}

/// Kernel transfers replenish user backing between page-bounded arch accesses.
pub trait GuestBytes {
    /// Copy a high user buffer without narrowing its address. False means EFAULT.
    fn high_copy(&mut self, address: u64, bytes: &mut [u8], to_user: bool) -> bool;
    fn copy_from(&self, address: usize, bytes: &mut [u8]);
    fn copy_to(&mut self, address: usize, bytes: &[u8]);
    fn read<T: Copy>(&self, address: usize) -> T {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        unsafe {
            self.copy_from(address, core::slice::from_raw_parts_mut(
                value.as_mut_ptr().cast(), core::mem::size_of::<T>()));
            value.assume_init()
        }
    }
    fn write<T: Copy>(&mut self, address: usize, value: T) {
        unsafe { self.copy_to(address, core::slice::from_raw_parts(
            (&value as *const T).cast(), core::mem::size_of::<T>())); }
    }
    fn copy_cstr(&self, address: usize, bytes: &mut [u8]) -> usize {
        for (i, byte) in bytes.iter_mut().enumerate() {
            let value = self.read::<u8>(address + i);
            if value == 0 { return i; }
            *byte = value;
        }
        bytes.len()
    }
    fn zero(&mut self, mut address: usize, mut length: usize) {
        let zeros = [0; 4096];
        while length != 0 {
            let n = length.min(4096);
            self.copy_to(address, &zeros[..n]);
            address += n;
            length -= n;
        }
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        let mut buffer = [0; 4096];
        let mut remaining = len;
        while remaining != 0 {
            let n = remaining.min(buffer.len());
            let offset = if dst > src { remaining - n } else { len - remaining };
            self.copy_from(src + offset, &mut buffer[..n]);
            self.copy_to(dst + offset, &buffer[..n]);
            remaining -= n;
        }
    }
}
impl<A: arch_abi::Arch + arch_abi::GuestBytes> GuestBytes for A {
    fn high_copy(&mut self, mut address: u64, mut bytes: &mut [u8], to_user: bool) -> bool {
        while !bytes.is_empty() {
            let n = bytes.len().min(4096 - (address as usize & 4095));
            let (part, rest) = bytes.split_at_mut(n);
            if !with_pages(self, 5, |machine, pages| arch_abi::GuestBytes::high_copy(machine, address, part, to_user, pages)) {
                return false;
            }
            address += n as u64;
            bytes = rest;
        }
        true
    }
    fn copy_from(&self, mut address: usize, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            service(self);
            let n = bytes.len().min(4096 - (address & 4095));
            let (part, rest) = bytes.split_at_mut(n);
            arch_abi::GuestBytes::copy_from(self, address, part);
            address += n;
            bytes = rest;
        }
    }
    fn copy_to(&mut self, mut address: usize, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            service(self);
            let n = bytes.len().min(4096 - (address & 4095));
            arch_abi::GuestBytes::copy_to(self, address, &bytes[..n]);
            address += n;
            bytes = &bytes[n..];
        }
    }
}
