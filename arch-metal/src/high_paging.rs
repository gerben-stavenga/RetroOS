//! Sparse long-mode user mappings outside the compatibility kernel's PML4 slot.
//! Rust remains 32-bit: table and data access uses a temporary physical window.
//! Nonpresent reservation entries describe a uniform subtree without allocating
//! its lower tables. Fork shares tables; mutations and write faults deshare them.
use crate::paging2::{self, Entry, Entry64, AddressSpace};
use crate::paging2::flags::*;

pub const START: u64 = 1 << 39;
pub const END: u64 = 1 << 47;
const RESERVED: u64 = 1 << 10;
const BLOCKED: u64 = 1 << 8; // software: uniform NoAccess mapping

#[repr(C)]
pub(crate) struct Request {
    pub address: u64,
    pub length: u64,
    pub to_user: bool,
    pub buffer: usize,
    pub result: i32,
}

pub(crate) fn invoke(request: Request) -> i32 {
    #[cfg(feature = "kvm")]
    { self::request(&request) }
    #[cfg(not(feature = "kvm"))]
    {
        let cs: u16;
        unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs); }
        if cs & 3 == 0 { return self::request(&request); }
        let mut request = request;
        unsafe { core::arch::asm!("int 0x80",
            in("eax") crate::arch_call::HIGH_MEMORY as u32,
            in("edx") &mut request as *mut Request as usize,
        ); }
        request.result
    }
}

fn supported() -> bool { paging2::cpu_mode() == paging2::CpuMode::Compat }
fn root(index: usize) -> Entry64 {
    unsafe { (&raw const paging2::PML4).cast::<Entry64>().add(index).read_volatile() }
}
fn set_root(index: usize, entry: Entry64) {
    unsafe { (&raw mut paging2::PML4).cast::<Entry64>().add(index).write_volatile(entry); }
}

// The save area still fits in the union's legacy 768-dword storage.
const _: () = assert!(core::mem::size_of::<AddressSpace>() == 768 * 4);
pub fn swap(space: &mut AddressSpace) {
    let _paging = paging2::PagingGuard::lock();
    if !paging2::is_pae() { return; }
    for index in 1..256 {
        let old = root(index);
        set_root(index, unsafe { space.e64[index + 3] });
        unsafe { space.e64[index + 3] = old; }
    }
}
pub fn fork(space: &mut AddressSpace) {
    let _paging = paging2::PagingGuard::lock();
    if !paging2::is_pae() { return; }
    for index in 1..256 {
        let mut entry = root(index);
        if entry.present() {
            entry.set_hw_writable(false);
            crate::memory::inc_shared_count(entry.page());
            set_root(index, entry);
        }
        unsafe { space.e64[index + 3] = entry; }
    }
}

fn with_frame<T>(page: u64, f: impl FnOnce(*mut u8) -> T) -> T {
    let saved = paging2::temp_swap(page);
    let result = f((&raw mut paging2::TEMP_PAGE).cast::<u8>());
    let _ = paging2::temp_swap(saved);
    result
}
fn read(page: u64, index: usize) -> Entry64 {
    with_frame(page, |p| unsafe { p.cast::<Entry64>().add(index).read_volatile() })
}
fn write(page: u64, index: usize, entry: Entry64) {
    with_frame(page, |p| unsafe { p.cast::<Entry64>().add(index).write_volatile(entry); });
}
fn allocate(fill: Entry64) -> Result<u64, i32> {
    let page = crate::memory::take_page().ok_or(-11)?;
    with_frame(page, |p| {
        for index in 0..512 { unsafe { p.cast::<Entry64>().add(index).write(fill); } }
    });
    Ok(page)
}
fn release(entry: Entry64, level: u32) {
    if !entry.present() && !(level == 0 && entry.raw() & RESERVED != 0) { return; }
    if level == 0 && entry.raw() & FOREIGN != 0 { return; }
    if level > 0 && crate::memory::get_ref_count(entry.page()) == 1 {
        for index in 0..512 { release(read(entry.page(), index), level - 1); }
    }
    crate::memory::release_page(entry.page());
}
pub fn clean() {
    let _paging = paging2::PagingGuard::lock();
    if !paging2::is_pae() { return; }
    for index in 1..256 {
        let entry = root(index);
        set_root(index, Entry64(0));
        release(entry, 3);
    }
}

// Return a private child table. A reserved parent expands into 512 identical
// reservation markers. A shared table retains its children before being copied.
fn table(entry: &mut Entry64) -> Result<u64, i32> {
    if !entry.present() {
        *entry = Entry64::new(allocate(*entry)?, true, true);
    } else if crate::memory::get_ref_count(entry.page()) > 1 {
        let page = allocate(Entry64(0))?;
        for index in 0..512 {
            let mut child = read(entry.page(), index);
            if (child.present() || child.raw() & RESERVED != 0) && child.raw() & FOREIGN == 0 {
                child.set_hw_writable(false);
                crate::memory::inc_shared_count(child.page());
                write(entry.page(), index, child);
            }
            write(page, index, child);
        }
        crate::memory::release_page(entry.page());
        *entry = Entry64::new(page, true, true);
    } else { entry.set_hw_writable(true); }
    Ok(entry.page())
}



fn resolve(address: u64, write_access: bool, execute: bool) -> Option<u64> {
    if !(START..END).contains(&address) { return None; }
    fn walk(entry: &mut Entry64, level: u32, address: u64, write_access: bool, execute: bool) -> Option<u64> {
        if entry.raw() == 0 { return None; }
        if level == 0 {
            if !entry.present() {
                if entry.raw() & RESERVED == 0 || entry.raw() & BLOCKED != 0 { return None; }
                entry.0 = (entry.0 & !RESERVED) | PRESENT;
            }
            if !entry.user() || write_access && !entry.writable()
                || execute && entry.raw() & NO_EXECUTE != 0 { return None; }
            if write_access && !entry.hw_writable() {
                if entry.raw() & FOREIGN != 0 || crate::memory::get_ref_count(entry.page()) > 1 {
                    let page = allocate(Entry64(0)).expect("user access has no supplied data page");
                    let scratch = (&raw mut crate::SCRATCH).cast::<u8>();
                    with_frame(entry.page(), |p| unsafe { core::ptr::copy_nonoverlapping(p, scratch, 4096); });
                    with_frame(page, |p| unsafe { core::ptr::copy_nonoverlapping(scratch, p, 4096); });
                    if entry.raw() & FOREIGN == 0 { crate::memory::release_page(entry.page()); }
                    entry.0 = (entry.0 & !Entry64::ADDR_MASK & !FOREIGN) | (page << 12);
                }
                entry.set_hw_writable(true);
            }
            return Some(entry.page());
        }
        let page = table(entry).expect("user access has no supplied table page");
        let index = ((address >> (12 + 9 * (level - 1))) & 511) as usize;
        let mut child = read(page, index);
        let result = walk(&mut child, level - 1, address, write_access, execute);
        write(page, index, child);
        result
    }
    let index = (address >> 39) as usize;
    let mut entry = root(index);
    let result = walk(&mut entry, 3, address, write_access, execute);
    set_root(index, entry);
    result
}
pub fn fault(address: u64, error: u64) -> bool {
    let _paging = paging2::PagingGuard::lock();
    if !supported() || error & 8 != 0 { return false; }
    let result = resolve(address, error & 2 != 0, error & 16 != 0).is_some();
    paging2::flush_tlb();
    result
}
/// Byte access is independent of mapping policy.
pub fn request(request: &Request) -> i32 {
    let _paging = paging2::PagingGuard::lock();
    let result = copy_request(request);
    // A failed copy can still have privatized and written its initial pages.
    if request.to_user { paging2::flush_tlb(); }
    result
}
fn copy_request(request: &Request) -> i32 {
    let Some(end) = request.address.checked_add(request.length) else { return -22; };
    let low = end <= 0xc0000000;
    if !low && (request.address < START || end > END || !supported()) { return -22; }
    let mut offset = 0;
    while offset < request.length {
        let address = request.address + offset;
        let page = if low { crate::mapping::resolve(address, request.to_user) }
        else if request.to_user { resolve(address, true, false) }
        else {
            let page = UserPage::new(address & !4095).unwrap();
            match read_run(page, 1).ok().map(|(entry, _)| entry) {
                Some(PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m)) => Some(m.backing.frame().number()),
                _ => None,
            }
        };
        let Some(page) = page else { return -14; };
        let at = (address & 4095) as usize;
        let count = (request.length - offset).min((4096 - at) as u64) as usize;
        with_frame(page, |p| unsafe {
            let buffer = (request.buffer as *mut u8).add(offset as usize);
            if request.to_user { core::ptr::copy_nonoverlapping(buffer, p.add(at), count); }
            else { core::ptr::copy_nonoverlapping(p.add(at), buffer, count); }
        });
        offset += count as u64;
    }
    0
}

use arch_abi::{MappingError, MappingFailure, UserPage, page_entry::{Backing, PageEntry}};
fn decode_uniform(entry: Entry64) -> Result<PageEntry, MappingError> {
    if entry.raw() == 0 { return Ok(PageEntry::Absent); }
    if entry.raw() & RESERVED == 0 { return Ok(PageEntry::Intercepted); }
    let decoded = crate::mapping::decode(Entry64((entry.raw() & !RESERVED & !BLOCKED) | PRESENT), false)?;
    if entry.raw() & BLOCKED != 0 {
        match decoded {
            PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => Ok(PageEntry::NoAccess(m)),
            _ => Err(MappingError::InvalidFrame),
        }
    } else { Ok(decoded) }
}
fn encode_uniform(page: UserPage, entry: PageEntry) -> Result<Entry64, MappingError> {
    let mut encoded = crate::mapping::encode::<Entry64>(page, entry)?;
    match entry {
        PageEntry::Absent => encoded.0 = 0,
        PageEntry::Intercepted => (),
        _ => {
            encoded.set_present(false); encoded.set_flag(RESERVED, true);
            encoded.set_flag(BLOCKED, matches!(entry, PageEntry::NoAccess(_)));
        }
    }
    Ok(encoded)
}

pub(crate) fn read_run(page: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
    let _paging = paging2::PagingGuard::lock();
    if !supported() { return Err(MappingError::Unsupported); }
    let address = page.address();
    let mut entry = root((address >> 39) as usize);
    let mut inherited_cow = false;
    for level in (0..=3).rev() {
        if !entry.present() {
            let span = 1u64 << (12 + 9 * level);
            let remaining = ((span - (address & (span - 1))) / 4096).min(maximum as u64) as usize;
            let mut decoded = decode_uniform(entry)?;
            if inherited_cow {
                if let PageEntry::Writable(m) = decoded {
                    if matches!(m.backing, Backing::Owned(_)) { decoded = PageEntry::CopyOnWrite(m); }
                }
            }
            return Ok((decoded, remaining));
        }
        if level == 0 { return Ok((crate::mapping::decode(entry, inherited_cow)?, 1)); }
        inherited_cow |= !entry.hw_writable();
        let index = ((address >> (12 + 9 * (level - 1))) & 511) as usize;
        entry = read(entry.page(), index);
    }
    unreachable!()
}

/// Repeated borrowed leaves can be represented by a nonpresent uniform subtree.
/// Owned leaves retain one reference per occurrence, so they expand to leaves.
/// The mapping trap invalidates translations after the entire operation,
/// including any committed prefix on failure.
pub(crate) fn fill(page: UserPage, count: usize, incoming: PageEntry) -> Result<(), MappingFailure> {
    let _paging = paging2::PagingGuard::lock();
    let fail = |error| MappingFailure { completed: 0, error };
    if !supported() { return Err(fail(MappingError::Unsupported)); }
    let encoded = encode_uniform(page, incoming).map_err(fail)?;
    let owned = match incoming {
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) =>
            if let Backing::Owned(frame) = m.backing { Some(frame.number()) } else { None },
        _ => None,
    };
    fn update(entry: &mut Entry64, level: u32, base: u64, start: u64, end: u64,
        encoded: Entry64, owned: Option<u64>, completed: &mut usize) -> Result<(), MappingError>
    {
        let span = 1u64 << (12 + 9 * level);
        if level == 0 || owned.is_none() && start <= base && end >= base + span {
            if let Some(frame) = owned {
                if !crate::memory::inc_shared_count(frame) { return Err(MappingError::InvalidFrame); }
            }
            let old = *entry; *entry = encoded; release(old, level);
            *completed = ((end.min(base + span) - start) / 4096) as usize;
            return Ok(());
        }
        let table_page = table(entry).map_err(|_| MappingError::NeedPages)?;
        let child_span = span / 512;
        let first = ((start.max(base) - base) / child_span) as usize;
        let last = ((end.min(base + span) - base).div_ceil(child_span)) as usize;
        for index in first..last {
            let mut child = read(table_page, index);
            let result = update(&mut child, level - 1, base + index as u64 * child_span,
                start, end, encoded, owned, completed);
            write(table_page, index, child); result?;
        }
        Ok(())
    }
    let start = page.address(); let end = start + count as u64 * 4096;
    let mut completed = 0;
    for index in (start >> 39) as usize..end.div_ceil(1 << 39) as usize {
        let mut entry = root(index);
        let result = update(&mut entry, 3, (index as u64) << 39, start, end, encoded, owned, &mut completed);
        set_root(index, entry);
        result.map_err(|error| MappingFailure { completed, error })?;
    }
    Ok(())
}
