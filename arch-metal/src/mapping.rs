//! Typed user mapping operations over the live recursive tables.
use arch_abi::{MappingError, MappingFailure, UserPage};
use arch_abi::page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame, X86PteFormat};
use crate::paging2::{self, Entry, Entries};
use crate::paging2::flags::*;

// Each arch call borrows its own typed arguments until the trap returns.
pub(crate) struct Read<'a> {
    pub(crate) page: UserPage,
    pub(crate) entries: &'a mut [PageEntry],
    pub(crate) result: Result<(), MappingFailure>,
}
pub(crate) struct Replace<'a> {
    pub(crate) page: UserPage,
    pub(crate) entries: &'a [PageEntry],
    pub(crate) result: Result<(), MappingFailure>,
}
pub(crate) struct Fill {
    pub(crate) page: UserPage,
    pub(crate) entry: PageEntry,
    pub(crate) count: usize,
    pub(crate) result: Result<(), MappingFailure>,
}
pub(crate) struct ReadRun {
    pub(crate) page: UserPage,
    pub(crate) maximum: usize,
    pub(crate) result: Result<(PageEntry, usize), MappingError>,
}

// Safety: the call number must name the handler for T.
pub(crate) unsafe fn invoke<T>(call: u64, arguments: &mut T) {
    unsafe { core::arch::asm!("int 0x80", in("eax") call as u32,
        in("edx") arguments as *mut T as usize); }
}

fn read_run(page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
    if page.address() >= crate::high_paging::START { return crate::high_paging::read_run(page, maximum); }
    fn scan<E: Entry>(entries: &[E], page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        let entry = read(entries, page)?;
        let per_table = 4096 / core::mem::size_of::<E>();
        let limit = maximum.min(per_table - (page.address() as usize / 4096) % per_table);
        let mut count = 1;
        while count < limit && read(entries, page.offset(count)?)? == entry { count += 1; }
        Ok((entry, count))
    }
    match paging2::entries() {
        Entries::E32(e) => scan(e, page, maximum),
        Entries::E64(e) => scan(e, page, maximum),
    }
}
fn replace_page(page: UserPage, incoming: PageEntry) -> Result<(), MappingError> {
    if page.address() >= crate::high_paging::START {
        return crate::high_paging::fill(page, 1, incoming).map_err(|failure| failure.error);
    }
    match paging2::entries() {
        Entries::E32(e) => replace(e, page, incoming),
        Entries::E64(e) => replace(e, page, incoming),
    }
}

fn validate_range(page: UserPage, count: usize) -> Result<(), MappingFailure> {
    if count != 0 { page.offset(count - 1).map_err(|error| MappingFailure { completed: 0, error })?; }
    Ok(())
}
fn batch(page: UserPage, count: usize, mut apply: impl FnMut(UserPage, usize) -> Result<(), MappingError>)
    -> Result<(), MappingFailure>
{
    validate_range(page, count)?;
    for completed in 0..count {
        apply(page.offset(completed).unwrap(), completed).map_err(|error| MappingFailure { completed, error })?;
    }
    Ok(())
}
pub(crate) fn read_mappings(arguments: &mut Read<'_>) {
    let _paging = paging2::PagingGuard::lock();
    arguments.result = batch(arguments.page, arguments.entries.len(), |page, index| {
        arguments.entries[index] = read_run(page, 1)?.0;
        Ok(())
    });
}
pub(crate) fn replace_mappings(arguments: &mut Replace<'_>) {
    let _paging = paging2::PagingGuard::lock();
    arguments.result = batch(arguments.page, arguments.entries.len(), |page, index| {
        replace_page(page, arguments.entries[index])
    });
    // Invalidate successful prefixes even when a later replacement failed.
    paging2::flush_tlb();
}
pub(crate) fn fill_mappings(arguments: &mut Fill) {
    let _paging = paging2::PagingGuard::lock();
    let Fill { page, count, entry, result } = arguments;
    *result = validate_range(*page, *count).and_then(|()| {
        if *count == 0 { return Ok(()); }
        if page.address() >= crate::high_paging::START {
            crate::high_paging::fill(*page, *count, *entry)
        } else { batch(*page, *count, |page, _| replace_page(page, *entry)) }
    });
    paging2::flush_tlb();
}
pub(crate) fn read_mapping_run(arguments: &mut ReadRun) {
    let _paging = paging2::PagingGuard::lock();
    arguments.result = if arguments.maximum == 0 { Err(MappingError::InvalidAddress) }
        else {
            arguments.page.offset(arguments.maximum - 1)
                .and_then(|_| read_run(arguments.page, arguments.maximum))
        };
}

pub(crate) fn format() -> X86PteFormat {
    if !paging2::is_pae() { X86PteFormat::Legacy32 }
    else { X86PteFormat::Wide { physical_address_bits: 52, nx: paging2::nx_enabled() } }
}

/// Legacy low empty entries still denote implicit demand-zero until their
/// callers migrate. Explicit Absent uses SOFT_RO without PRESENT; it faults.
pub(crate) fn zero_mapping() -> Mapping {
    Mapping {
        backing: Backing::Borrowed(PhysicalFrame::new(paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize)).unwrap()),
        attributes: Attributes::EXECUTABLE,
    }
}

pub(crate) fn decode<E: Entry>(entry: E, inherited_cow: bool) -> Result<PageEntry, MappingError> {
    if entry.raw() == 0 { return Ok(PageEntry::CopyOnWrite(zero_mapping())); }
    if !entry.present() && entry.raw() & NO_ACCESS == 0 {
        return Ok(if entry.raw() & SOFT_RO != 0 { PageEntry::Absent } else { PageEntry::Intercepted });
    }
    let frame = PhysicalFrame::new(entry.page())?;
    let backing = if entry.raw() & FOREIGN != 0 { Backing::Borrowed(frame) } else { Backing::Owned(frame) };
    let mut attributes = Attributes::default();
    for (yes, flag) in [
        (entry.raw() & NO_EXECUTE == 0, Attributes::EXECUTABLE),
        (entry.raw() & WRITE_THROUGH != 0, Attributes::WRITE_THROUGH),
        (entry.raw() & CACHE_DISABLE != 0, Attributes::CACHE_DISABLE),
        (entry.raw() & WRITE_COMBINE != 0, Attributes::PAT),
    ] { if yes { attributes = attributes | flag; } }
    let mapping = Mapping { backing, attributes };
    Ok(if !entry.present() { PageEntry::NoAccess(mapping) }
        else if !entry.writable() { PageEntry::ReadOnly(mapping) }
        else if !entry.hw_writable() || inherited_cow && entry.raw() & FOREIGN == 0 { PageEntry::CopyOnWrite(mapping) }
        else { PageEntry::Writable(mapping) })
}

pub(crate) fn encode<E: Entry>(page: UserPage, entry: PageEntry) -> Result<E, MappingError> {
    // Check permissions/frame width before translating into the existing tables.
    entry.encode(format(), page.address())?;
    let mapping = match entry {
        PageEntry::Absent => { let mut e = E::default(); e.set_raw(SOFT_RO); return Ok(e); }
        PageEntry::Intercepted => { let mut e = E::default(); e.set_raw(CACHE_DISABLE); return Ok(e); }
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => m,
    };
    if mapping.backing.frame().number() >= crate::memory::physical_page_limit() { return Err(MappingError::InvalidFrame); }
    let mut e = E::new(mapping.backing.frame().number(), matches!(entry, PageEntry::Writable(_)), true);
    e.set_writable(matches!(entry, PageEntry::Writable(_) | PageEntry::CopyOnWrite(_)));
    e.set_no_execute(!mapping.attributes.contains(Attributes::EXECUTABLE));
    e.set_flag(FOREIGN, matches!(mapping.backing, Backing::Borrowed(_)));
    e.set_flag(WRITE_THROUGH, mapping.attributes.contains(Attributes::WRITE_THROUGH));
    e.set_flag(CACHE_DISABLE, mapping.attributes.contains(Attributes::CACHE_DISABLE));
    e.set_flag(WRITE_COMBINE, mapping.attributes.contains(Attributes::PAT));
    if matches!(entry, PageEntry::NoAccess(_)) { e.set_present(false); e.set_flag(NO_ACCESS, true); }
    Ok(e)
}

fn read<E: Entry>(entries: &[E], page: UserPage) -> Result<PageEntry, MappingError> {
    let index = page.address() as usize / 4096;
    let mut chain = [0; 4];
    let mut count = 0;
    let mut parent = paging2::parent_index::<E>(index);
    loop {
        chain[count] = parent; count += 1;
        let next = paging2::parent_index::<E>(parent);
        if next == parent { break; }
        parent = next;
    }
    let mut cow = false;
    for &parent in chain[..count].iter().rev() {
        if !entries[parent].present() { return Ok(PageEntry::CopyOnWrite(zero_mapping())); }
        cow |= !entries[parent].hw_writable();
    }
    decode(entries[index], cow)
}

/// Make every table above `index` present and privately writable, top-down,
/// exactly as a write fault would: a missing table starts as the shared zero
/// table, then copy-on-write gives it a page. Outside a fault those pages
/// come from the caller's batch, never the per-CPU fault reserve; an empty
/// batch is `NeedPages`, and the kernel refills it and resumes after the
/// committed prefix. Filling a large fresh range therefore costs batch pages,
/// not reserve pages (the reserve only covers one fault's worth).
fn prepare_tables<E: Entry>(entries: &mut [E], index: usize) -> Result<(), MappingError> {
    let mut chain = [0; 4];
    let mut count = 0;
    let mut parent = paging2::parent_index::<E>(index);
    loop {
        chain[count] = parent; count += 1;
        let next = paging2::parent_index::<E>(parent);
        if next == parent { break; }
        parent = next;
    }
    for &parent in chain[..count].iter().rev() {
        // The recursive self-map and the kernel's fixed levels are not user tables.
        if parent >= paging2::recursive_idx() { continue; }
        if !entries[parent].present() {
            let zero = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
            paging2::replace_mapping(&mut entries[parent], E::new(zero, false, true));
            paging2::flush_tlb();
        }
        if !entries[parent].hw_writable() {
            if !crate::memory::input_available() { return Err(MappingError::NeedPages); }
            paging2::cow_entry(entries, parent);
        }
    }
    Ok(())
}

fn replace<E: Entry>(entries: &mut [E], page: UserPage, entry: PageEntry) -> Result<(), MappingError> {
    let incoming = encode::<E>(page, entry)?;
    // Before taking a frame reference, so NeedPages leaves no leak behind.
    prepare_tables(entries, page.address() as usize / 4096)?;
    if let PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) = entry {
        if let Backing::Owned(frame) = m.backing {
            if !crate::memory::inc_shared_count(frame.number()) { return Err(MappingError::InvalidFrame); }
        }
    }
    paging2::replace_mapping(&mut entries[page.address() as usize / 4096], incoming);
    Ok(())
}
