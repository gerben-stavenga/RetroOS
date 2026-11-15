//! Kernel-owned physical page supply and explicit inputs to arch operations.
use crate::Arch;
use super::phys_mm;
use arch_abi::page_supply::{PageInput, PageSupply, SUPPLY_CAPACITY};
#[thread_local]
static mut SPARES: PageInput = PageInput::new();
#[thread_local]
static mut CURRENT: *mut PageSupply = core::ptr::null_mut();
fn spares_ptr() -> *mut PageInput { &raw mut SPARES }
static IO: spin::Once<arch_abi::PhysicalFrameIo> = spin::Once::new();

pub fn install_supply(supply: *mut PageSupply) { unsafe { CURRENT = supply; } }

pub fn install_io(io: arch_abi::PhysicalFrameIo) { IO.call_once(|| io); }

/// # Safety
/// Supply belongs to this core. Metadata and its refill stack are resident.
pub unsafe fn replenish(supply: *mut PageSupply) {
    // Drain pages returned by arch before requesting new backing from the pool.
    while unsafe { (*supply).returned_head } != 0 {
        let io = IO.get().expect("returned frames before physical I/O initialization");
        let page = unsafe { (*supply).returned_head };
        let mut next = [0; 8];
        (io.read)(page, 0, &mut next);
        unsafe { (*supply).returned_head = u64::from_ne_bytes(next); (*supply).returned_count -= 1; }
        phys_mm::free_phys_page(page);
    }
    unsafe { phys_mm::replenish_supply(supply); }
}
pub fn service<A: Arch>(machine: &mut A) {
    if let Some(supply) = machine.page_supply() {
        install_supply(supply);
        unsafe { replenish(supply); }
    }
}

/// Mapping operations receive owned pages as data, never allocator callbacks.
pub fn with_pages<A: Arch, R>(machine: &mut A, count: usize, operation: impl FnOnce(&mut A) -> R) -> R {
    if machine.page_supply().is_none() { return operation(machine); }
    assert!(count <= SUPPLY_CAPACITY);
    service(machine);
    let mut input = PageInput::new();
    for _ in 0..count {
        let spare = unsafe { (*spares_ptr()).take() };
        let page = spare.or_else(phys_mm::alloc_phys_page)
            .expect("out of physical memory preparing arch input");
        input.pages[input.count] = page;
        input.count += 1;
    }
    let previous = machine.set_page_input(&mut input);
    let result = operation(machine);
    machine.set_page_input(previous);
    while let Some(page) = input.take() {
        unsafe {
            let spares = &mut *spares_ptr();
            assert!(spares.count < SUPPLY_CAPACITY);
            spares.pages[spares.count] = page;
            spares.count += 1;
        }
    }
    result
}
pub fn fork<A: Arch>(machine: &mut A, child: &mut A::PageTable) {
    with_pages(machine, 3, |machine| machine.user_fork(child));
}
pub fn high_copy<A: Arch>(machine: &mut A, mut address: u64, mut bytes: &mut [u8], to_user: bool) -> bool {
    while !bytes.is_empty() {
        let n = bytes.len().min(4096 - (address as usize & 4095));
        let (part, rest) = bytes.split_at_mut(n);
        if !with_pages(machine, 5, |machine| machine.high_copy(address, part, to_user)) { return false; }
        address += n as u64;
        bytes = rest;
    }
    true
}
pub fn alloc_contig<A: Arch>(machine: &mut A, pages: usize) -> u64 {
    if machine.page_supply().is_some() { service(machine); phys_mm::alloc_contig(pages).unwrap_or(0) }
    else { machine.alloc_phys_contig(pages) }
}
pub fn free_contig<A: Arch>(machine: &mut A, page: u64, pages: usize) {
    if machine.page_supply().is_some() { phys_mm::free_phys_contig(page, pages); }
    else { machine.free_phys_contig(page, pages); }
}
pub fn dma_channel<A: Arch>(machine: &A, channel: usize) -> u64 {
    if machine.page_supply().is_some() { phys_mm::dma_channel_buf(channel) }
    else { machine.dma_channel_buf(channel) }
}
pub fn cache_access(io: arch_abi::PhysicalFrameIo) -> arch_abi::FrameAccess {
    install_io(io);
    arch_abi::FrameAccess {
        retain: phys_mm::inc_shared_count,
        allocate: allocate_frame, release: phys_mm::free_phys_page,
        read: io.read, write: io.write, free: phys_mm::free_page_count,
        total: phys_mm::total_page_count,
        references: |page| usize::from(phys_mm::get_ref_count(page)),
        set_reclaim: phys_mm::set_reclaim,
    }
}

fn allocate_frame() -> Option<u64> {
    let supply = unsafe { CURRENT };
    if !supply.is_null() {
        // A large unmap may have returned many frames since the last event-loop
        // boundary. Reclaim them before treating the RAM pool as exhausted.
        unsafe {
            while (*supply).returned_head != 0 {
                let io = IO.get().expect("physical I/O not installed");
                let page = (*supply).returned_head;
                let mut next = [0; 8];
                (io.read)(page, 0, &mut next);
                (*supply).returned_head = u64::from_ne_bytes(next);
                (*supply).returned_count -= 1;
                phys_mm::free_phys_page(page);
            }
        }
    }
    phys_mm::alloc_phys_page()
}

pub fn private_tables<A: Arch>(machine: &mut A) {
    loop {
        let result = with_pages(machine, SUPPLY_CAPACITY, |machine| machine.private_page_tables());
        if result == 0 { break; }
        assert_eq!(result, -11, "cannot detach process page tables");
    }
}

/// Construct supported x86 permissions. Legacy paging cannot enforce NX.
pub fn mapping_attributes<A: Arch>(machine: &A, executable: bool) -> arch_abi::page_entry::Attributes {
    use arch_abi::page_entry::{Attributes, X86PteFormat};
    if executable || !matches!(machine.page_format(), X86PteFormat::Wide { nx: true, .. }) {
        Attributes::EXECUTABLE
    } else { Attributes::default() }
}

/// Install one mapping with explicit table backing and retry only uncompleted work.
/// # Safety
/// The entry's backing must satisfy Arch::replace_mapping's requirements.
pub unsafe fn replace<A: Arch>(machine: &mut A, page: arch_abi::UserPage,
    entry: arch_abi::page_entry::PageEntry) -> Result<(), arch_abi::MappingError>
{
    loop {
        let result = with_pages(machine, 5, |machine| unsafe { machine.replace_mapping(page, entry) });
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
        match with_pages(machine, 5, |machine| unsafe { machine.replace_mappings(page, entries) }) {
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
        attributes: mapping_attributes(machine, executable) };
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
        let frame = unsafe { machine.shared_page(pointer) };
        let entry = PageEntry::Writable(Mapping { backing: Backing::Borrowed(frame), attributes: Attributes::EXECUTABLE });
        unsafe { replace(machine, start.offset(index).unwrap(), entry) }.expect("cannot map shared backing");
    }
}

/// Compatibility composition for existing physical-window callers. User
/// entries borrow physical storage; privileged driver windows remain separate.
pub fn map_physical<A: Arch>(machine: &mut A, vpage: usize, count: usize, physical: u64, flags: u64) {
    use arch_abi::{UserPage, page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame}};
    if vpage >= 0xc0000000 / 4096 {
        machine.map_kernel_physical(vpage, count, physical, flags);
        return;
    }
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

fn frames<A: Arch>(machine: &A) -> arch_abi::FrameAccess {
    machine.frame_access().unwrap_or_else(|| cache_access(machine.physical_frame_io().expect("physical frame access")))
}
fn page(vpage: usize) -> UserPage { UserPage::new((vpage as u64).checked_mul(4096).unwrap()).unwrap() }
fn backing(entry: PageEntry) -> Option<Mapping> {
    match entry {
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => Some(m),
        _ => None,
    }
}
fn pin(access: arch_abi::FrameAccess, entry: PageEntry) {
    if let Some(Mapping { backing: Backing::Owned(frame), .. }) = backing(entry) {
        assert!((access.retain)(frame.number()), "invalid mapping reference");
    }
}
fn unpin(access: arch_abi::FrameAccess, entry: PageEntry) {
    if let Some(Mapping { backing: Backing::Owned(frame), .. }) = backing(entry) { (access.release)(frame.number()); }
}

static ZERO_FRAME: spin::Once<PhysicalFrame> = spin::Once::new();
pub fn zero_mapping<A: Arch>(machine: &A, executable: bool) -> Mapping {
    let frame = *ZERO_FRAME.call_once(|| {
        let access = frames(machine);
        let frame = (access.allocate)().expect("zero frame allocation");
        (access.write)(frame, 0, &[0; 4096]);
        PhysicalFrame::new(frame).unwrap()
    });
    Mapping { backing: Backing::Borrowed(frame), attributes: mapping_attributes(machine, executable) }
}

/// Personality policy: discard contents and allow subsequent anonymous writes.
/// Device windows in the privileged region are invalidated, not turned into RAM.
pub fn reset<A: Arch>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    if vpage >= 0xc0000000 / 4096 {
        machine.map_kernel_physical(vpage, count, 0, arch_abi::MAP_MMIO);
        return;
    }
    let entry = PageEntry::CopyOnWrite(zero_mapping(machine, true));
    unsafe { fill(machine, page(vpage), count, entry) }.expect("reset mappings");
}

/// Allocate distinct RAM before creating aliases (EMS/A20/device shadows).
pub fn fresh<A: Arch>(machine: &mut A, vpage: usize, count: usize) {
    if count == 0 { return; }
    let start = page(vpage); start.offset(count - 1).unwrap();
    let access = frames(machine);
    for index in 0..count {
        service(machine);
        let frame = (access.allocate)().expect("anonymous frame allocation");
        (access.write)(frame, 0, &[0; 4096]);
        let entry = PageEntry::Writable(Mapping { backing: Backing::Owned(PhysicalFrame::new(frame).unwrap()),
            attributes: mapping_attributes(machine, true) });
        let result = unsafe { replace(machine, start.offset(index).unwrap(), entry) };
        (access.release)(frame);
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
            let access = frames(machine);
            let frame = (access.allocate)().expect("private protection backing");
            let mut bytes = [0; 4096];
            (access.read)(mapping.backing.frame().number(), 0, &mut bytes);
            (access.write)(frame, 0, &bytes);
            mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
            temporary = Some((access, frame));
        }
        mapping.attributes = mapping.attributes.with_executable(mapping_attributes(machine, executable).contains(Attributes::EXECUTABLE));
        let entry = if !writable { PageEntry::ReadOnly(mapping) }
            else if matches!(old, PageEntry::CopyOnWrite(_)) || matches!(mapping.backing, Backing::Owned(_)) || ZERO_FRAME.get().is_some_and(|f| *f == mapping.backing.frame()) {
                PageEntry::CopyOnWrite(mapping)
            } else { PageEntry::Writable(mapping) };
        let result = unsafe { replace(machine, page, entry) };
        if let Some((access, frame)) = temporary { (access.release)(frame); }
        result.expect("set protection");
    }
}

/// Snapshot and pin all source references before replacing overlapping ranges.
/// COW sources become private RAM before another writable alias is installed.
pub fn alias<A: Arch>(machine: &mut A, source: usize, destination: usize, count: usize) {
    if count == 0 || source == destination { return; }
    let access = frames(machine);
    let mut entries = alloc::vec::Vec::with_capacity(count);
    for index in 0..count {
        let at = page(source + index);
        let mut entry = machine.read_mapping(at).expect("read alias source");
        if let PageEntry::CopyOnWrite(mut mapping) = entry {
            service(machine);
            let frame = (access.allocate)().expect("alias backing allocation");
            let mut bytes = [0; 4096];
            (access.read)(mapping.backing.frame().number(), 0, &mut bytes);
            (access.write)(frame, 0, &bytes);
            mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
            entry = PageEntry::Writable(mapping);
            let result = unsafe { replace(machine, at, entry) };
            (access.release)(frame);
            result.expect("materialize alias source");
        }
        pin(access, entry); entries.push(entry);
    }
    let result = unsafe { replace_batch(machine, page(destination), &entries) };
    for entry in entries { unpin(access, entry); }
    result.expect("install aliases");
}

/// Swap each pair while holding both references across replacement.
pub fn swap<A: Arch>(machine: &mut A, a: usize, b: usize, count: usize) {
    let access = frames(machine);
    for index in 0..count {
        let a = page(a + index); let b = page(b + index);
        let left = machine.read_mapping(a).unwrap(); let right = machine.read_mapping(b).unwrap();
        pin(access, left); pin(access, right);
        unsafe { replace(machine, a, right).unwrap(); replace(machine, b, left).unwrap(); }
        unpin(access, left); unpin(access, right);
    }
}

/// # Safety
/// Same backing lifetime requirements as Arch::fill_mappings.
pub unsafe fn fill<A: Arch>(machine: &mut A, mut start: UserPage, mut count: usize, entry: PageEntry) -> Result<(), arch_abi::MappingError> {
    while count != 0 {
        match with_pages(machine, 5, |machine| unsafe { machine.fill_mappings(start, count, entry) }) {
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
    let access = frames(machine);
    for index in 0..count {
        let at = page(first + index);
        let mut mapping = backing(machine.read_mapping(at).expect("read image mapping")).expect("image backing");
        service(machine);
        let frame = (access.allocate)().expect("private image allocation");
        let mut bytes = [0; 4096];
        (access.read)(mapping.backing.frame().number(), 0, &mut bytes);
        (access.write)(frame, 0, &bytes);
        mapping.backing = Backing::Owned(PhysicalFrame::new(frame).unwrap());
        let result = unsafe { replace(machine, at, PageEntry::Writable(mapping)) };
        (access.release)(frame);
        result.expect("install private image");
    }
}
