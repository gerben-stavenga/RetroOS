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
pub(crate) struct Edit {
    pub(crate) page: UserPage,
    pub(crate) count: usize,
    pub(crate) operation: arch_abi::mapping::Edit,
    pub(crate) result: Result<(), MappingFailure>,
}

pub(crate) struct ReadRun {
    pub(crate) page: UserPage,
    pub(crate) maximum: usize,
    pub(crate) result: Result<(PageEntry, usize), MappingError>,
}

// Safety: the call number must name the handler for T.
pub(crate) unsafe fn invoke<T>(call: u64, arguments: &mut T) {
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs); }
    if cs & 3 == 0 {
        let mut request = arch_abi::entry::KernelCall { rax: call,
            rdx: arguments as *mut T as u64, rbx: 0, rcx: 0, rsi: 0, rdi: 0 };
        assert!(matches!(crate::traps::arch_dispatch(&mut request), arch_abi::entry::CallOutcome::Complete));
        return;
    }
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
fn fill(page: UserPage, count: usize, entry: PageEntry) -> Result<(), MappingFailure> {
    validate_range(page, count)?;
    if count == 0 { return Ok(()); }
    if page.address() >= crate::high_paging::START {
        crate::high_paging::fill(page, count, entry)
    } else {
        batch(page, count, |page, _| replace_page(page, entry))
    }
}

pub(crate) fn fill_mappings(arguments: &mut Fill) {
    let _paging = paging2::PagingGuard::lock();
    arguments.result = fill(arguments.page, arguments.count, arguments.entry);
    paging2::flush_tlb();
}

pub(crate) fn edit_mappings(arguments: &mut Edit) {
    let _paging = paging2::PagingGuard::lock();
    arguments.result = arch_abi::mapping::edit_range(&mut Mappings,
        arguments.page, arguments.count, arguments.operation, zero_mapping().backing.frame());
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
pub(crate) fn prepare_tables<E: Entry>(entries: &mut [E], index: usize) -> Result<(), MappingError> {
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
            if !crate::memory::page_available() { return Err(MappingError::NeedPages); }
            paging2::cow_entry(entries, parent);
        }
    }
    Ok(())
}

/// Preflight a direct supervisor access to resident, owned user RAM. Unlike
/// resolving a kernel copy, this never materializes tables or COW backing.
/// Callers keep the paging guard across the check and the memory access.
pub(crate) fn resident(address: u32, len: u32, write: bool) -> bool {
    let Some(end) = address.checked_add(len) else { return false };
    if end > 0xc0000000 { return false; }
    fn check<E: Entry>(entries: &[E], index: usize, write: bool) -> bool {
        let parent = paging2::parent_index::<E>(index);
        // Parents must be present before their children can even be read
        // through the recursive mapping. Writes must not cross a COW parent.
        if parent != index && !check(entries, parent, write) { return false; }
        let entry = entries[index];
        entry.present() && (!write || entry.hw_writable())
    }
    fn range<E: Entry>(entries: &[E], address: u32, end: u32, write: bool) -> bool {
        for index in address as usize / 4096..(end as usize).div_ceil(4096) {
            if !check(entries, index, write) || entries[index].raw() & FOREIGN != 0
                || write && !entries[index].writable() { return false; }
        }
        true
    }
    match paging2::entries() {
        Entries::E32(e) => range(e, address, end, write),
        Entries::E64(e) => range(e, address, end, write),
    }
}

/// Resolve a user buffer without touching its virtual address. Reads need no
/// materialized tables; writes explicitly privatize tables and COW backing.
pub(crate) fn resolve(address: u64, write: bool) -> Option<u64> {
    let page = UserPage::new(address & !4095).ok()?;
    fn access<E: Entry>(entries: &mut [E], page: UserPage, write: bool) -> Option<u64> {
        let entry = read(entries, page).ok()?;
        let mapping = match entry {
            PageEntry::ReadOnly(m) if !write => m,
            PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => m,
            _ => return None,
        };
        if !write { return Some(mapping.backing.frame().number()); }
        let index = page.address() as usize / 4096;
        prepare_tables(entries, index).expect("guest copy has insufficient supplied table pages");
        if entries[index].raw() == 0 {
            let incoming = encode::<E>(page, PageEntry::CopyOnWrite(mapping)).unwrap();
            paging2::replace_mapping(&mut entries[index], incoming);
        }
        if !entries[index].hw_writable() { paging2::cow_entry(entries, index); }
        Some(entries[index].page())
    }
    match paging2::entries() {
        Entries::E32(e) => access(e, page, write),
        Entries::E64(e) => access(e, page, write),
    }
}

fn replace<E: Entry>(entries: &mut [E], page: UserPage, entry: PageEntry) -> Result<(), MappingError> {
    let incoming = encode::<E>(page, entry)?;
    // Before taking a frame reference, so NeedPages leaves no leak behind.
    prepare_tables(entries, page.address() as usize / 4096)?;
    if let PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) = entry
        && let Backing::Owned(frame) = m.backing && !crate::memory::inc_shared_count(frame.number())
    {
        return Err(MappingError::InvalidFrame);
    }
    paging2::replace_mapping(&mut entries[page.address() as usize / 4096], incoming);
    Ok(())
}

#[inline(never)]
fn copy_frame(source: PhysicalFrame) -> Result<PhysicalFrame, MappingError> {
    let frame = PhysicalFrame::new(crate::memory::take_page().ok_or(MappingError::NeedPages)?).unwrap();
    let mut bytes = [0; 4096];
    // The paging lock protects the temporary window; this runs at ring 0.
    let saved = paging2::temp_swap(source.number());
    unsafe { core::ptr::copy_nonoverlapping((&raw const paging2::TEMP_PAGE).cast::<u8>(), bytes.as_mut_ptr(), 4096); }
    let _ = paging2::temp_swap(frame.number());
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), (&raw mut paging2::TEMP_PAGE).cast::<u8>(), 4096); }
    let _ = paging2::temp_swap(saved);
    Ok(frame)
}

struct Mappings;
impl arch_abi::mapping::EditMappings for Mappings {
    fn read_run(&mut self, start: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        read_run(start, maximum)
    }
    fn fill(&mut self, start: UserPage, count: usize, entry: PageEntry) -> Result<(), MappingFailure> {
        fill(start, count, entry)
    }
    fn copy(&mut self, source: PhysicalFrame) -> Result<PhysicalFrame, MappingError> {
        copy_frame(source)
    }
    fn release(&mut self, frame: PhysicalFrame) { crate::memory::release_page(frame.number()); }
}
impl arch_abi::mapping::Rearrange for Mappings {
    fn read(&mut self, page: UserPage) -> Result<PageEntry, MappingError> { read_run(page, 1).map(|(entry, _)| entry) }
    fn prepare(&mut self, page: UserPage) -> Result<(), MappingError> {
        let entry = self.read(page)?;
        self.replace(page, entry)
    }
    #[inline(never)]
    fn private_alias(&mut self, page: UserPage) -> Result<(), MappingError> {
        let PageEntry::CopyOnWrite(mut mapping) = self.read(page)? else { return Ok(()); };
        let frame = copy_frame(mapping.backing.frame())?;
        mapping.backing = Backing::Owned(frame);
        let entry = PageEntry::Writable(mapping);
        let result = self.replace(page, entry);
        // replace retained the mapping; release our temporary owned reference.
        self.release(entry);
        result
    }
    fn replace(&mut self, page: UserPage, entry: PageEntry) -> Result<(), MappingError> { replace_page(page, entry) }
    fn retain(&mut self, entry: PageEntry) {
        if let Some(frame) = owned_backing(entry) { assert!(crate::memory::inc_shared_count(frame.number())); }
    }
    fn release(&mut self, entry: PageEntry) {
        if let Some(frame) = owned_backing(entry) { crate::memory::release_page(frame.number()); }
    }
}
fn owned_backing(entry: PageEntry) -> Option<PhysicalFrame> {
    match entry {
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => {
            match m.backing { Backing::Owned(frame) => Some(frame), Backing::Borrowed(_) => None }
        }
        _ => None,
    }
}

pub(crate) struct Rearrange {
    pub a: UserPage,
    pub b: UserPage,
    pub count: usize,
    pub swap: bool,
    pub result: Result<(), MappingError>,
}
pub(crate) fn rearrange_mappings(args: &mut Rearrange) {
    let _paging = paging2::PagingGuard::lock();
    args.result = arch_abi::mapping::rearrange(&mut Mappings, args.a, args.b, args.count, args.swap);
    paging2::flush_tlb();
}
