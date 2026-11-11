//! Sparse long-mode user mappings outside the compatibility kernel's PML4 slot.
//! Rust remains 32-bit: table and data access uses a temporary physical window.
//! Nonpresent reservation entries describe a uniform subtree without allocating
//! its lower tables. Fork shares tables; mutations and write faults deshare them.
use crate::paging2::{self, Entry, Entry64, RootPageTable};
use crate::paging2::flags::*;

pub const START: u64 = 1 << 39;
pub const END: u64 = 1 << 47;
const RESERVED: u64 = 1 << 10;
const ACCESS: u64 = 1 << 11;

#[repr(C)]
pub(crate) struct Request {
    pub address: u64,
    pub length: u64,
    pub operation: u32,
    pub protection: u32,
    pub buffer: usize,
    pub result: i32,
}

pub(crate) fn invoke(mut request: Request) -> i32 {
    unsafe { core::arch::asm!("int 0x80",
        in("eax") crate::arch_call::HIGH_MEMORY as u32,
        in("edx") &mut request as *mut Request as usize,
    ); }
    request.result
}

fn supported() -> bool { paging2::cpu_mode() == paging2::CpuMode::Compat }
fn root(index: usize) -> Entry64 {
    unsafe { (&raw const paging2::PML4).cast::<Entry64>().add(index).read_volatile() }
}
fn set_root(index: usize, entry: Entry64) {
    unsafe { (&raw mut paging2::PML4).cast::<Entry64>().add(index).write_volatile(entry); }
}

// The save area still fits in the union's legacy 768-dword storage.
const _: () = assert!(core::mem::size_of::<RootPageTable>() == 768 * 4);
pub fn save(space: &mut RootPageTable) {
    if !paging2::is_pae() { return; }
    for index in 1..256 { unsafe { space.e64[index + 3] = root(index); } }
}
pub fn load(space: &RootPageTable) {
    if !paging2::is_pae() { return; }
    for index in 1..256 { set_root(index, unsafe { space.e64[index + 3] }); }
}
pub fn swap(space: &mut RootPageTable) {
    if !paging2::is_pae() { return; }
    for index in 1..256 {
        let old = root(index);
        set_root(index, unsafe { space.e64[index + 3] });
        unsafe { space.e64[index + 3] = old; }
    }
}
pub fn fork(space: &mut RootPageTable) {
    if !paging2::is_pae() { return; }
    for index in 1..256 {
        let mut entry = root(index);
        if entry.present() {
            entry.set_hw_writable(false);
            crate::phys_mm::inc_shared_count(entry.page());
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
    let page = crate::phys_mm::alloc_phys_page().ok_or(-12)?;
    with_frame(page, |p| {
        for index in 0..512 { unsafe { p.cast::<Entry64>().add(index).write(fill); } }
    });
    Ok(page)
}
fn release(entry: Entry64, level: u32) {
    if !entry.present() { return; }
    if level > 0 && crate::phys_mm::get_ref_count(entry.page()) == 1 {
        for index in 0..512 { release(read(entry.page(), index), level - 1); }
    }
    crate::phys_mm::free_phys_page(entry.page());
}
pub fn clean() {
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
    } else if crate::phys_mm::get_ref_count(entry.page()) > 1 {
        let page = allocate(Entry64(0))?;
        for index in 0..512 {
            let mut child = read(entry.page(), index);
            if child.present() {
                child.set_hw_writable(false);
                crate::phys_mm::inc_shared_count(child.page());
                write(entry.page(), index, child);
            }
            write(page, index, child);
        }
        crate::phys_mm::free_phys_page(entry.page());
        *entry = Entry64::new(page, true, true);
    } else { entry.set_hw_writable(true); }
    Ok(entry.page())
}
fn marker(protection: u32) -> Entry64 {
    Entry64(RESERVED | if protection & 7 != 0 { ACCESS } else { 0 }
        | if protection & 2 != 0 { READ_WRITE } else { SOFT_RO }
        | if protection & 4 == 0 && paging2::nx_enabled() { NO_EXECUTE } else { 0 })
}
fn occupied(entry: Entry64, level: u32, base: u64, start: u64, end: u64) -> bool {
    if entry.raw() == 0 { return false; }
    if !entry.present() || level == 0 { return true; }
    let span = 1u64 << (12 + 9 * (level - 1));
    let first = ((start.max(base) - base) / span) as usize;
    let last = ((end.min(base + span * 512) - base).div_ceil(span)) as usize;
    (first..last).any(|i| occupied(read(entry.page(), i), level - 1, base + i as u64 * span, start, end))
}

fn update(entry: &mut Entry64, level: u32, base: u64, start: u64, end: u64, op: u32, prot: u32) -> Result<(), i32> {
    let span = 1u64 << (12 + 9 * level);
    let full = start <= base && end >= base + span;
    if (full || level == 0) && matches!(op, 0 | 2 | 4) {
        let old = *entry;
        *entry = if op == 2 { Entry64(0) } else { marker(prot) };
        release(old, level);
        return Ok(());
    }
    if entry.raw() == 0 && matches!(op, 1 | 3) { return Err(-12); }
    if !entry.present() && full && op == 1 { *entry = marker(prot); return Ok(()); }
    if !entry.present() && op == 3 { return Ok(()); }
    if level == 0 {
        if op == 3 {
            let old = *entry;
            let prot = if !old.user() { 0 } else {
                (if old.writable() { 3 } else { 1 }) | if old.raw() & NO_EXECUTE == 0 { 4 } else { 0 }
            };
            *entry = marker(prot);
            release(old, 0);
        } else {
            // Keep committed data through PROT_NONE. USER controls visibility;
            // semantic permissions survive fork independently of hardware COW.
            entry.set_user(prot & 7 != 0);
            entry.set_writable(prot & 2 != 0);
            entry.set_hw_writable(prot & 2 != 0 && crate::phys_mm::get_ref_count(entry.page()) == 1);
            entry.set_no_execute(prot & 4 == 0);
        }
        return Ok(());
    }
    if op == 2 && entry.raw() == 0 { return Ok(()); }
    let page = table(entry)?;
    let child_span = span / 512;
    let first = ((start.max(base) - base) / child_span) as usize;
    let last = ((end.min(base + span) - base).div_ceil(child_span)) as usize;
    for index in first..last {
        let mut child = read(page, index);
        let result = update(&mut child, level - 1, base + index as u64 * child_span, start, end, op, prot);
        write(page, index, child);
        result?;
    }
    Ok(())
}

pub fn request(request: &Request) -> i32 {
    if !supported() { return -12; }
    let start = request.address;
    let Some(end) = start.checked_add(request.length).filter(|end| start >= START && *end <= END) else { return -22; };
    if request.operation >= 5 {
        if request.operation > 6 { return -22; }
        let mut offset = 0;
        while offset < request.length {
            let address = start + offset;
            let Some(page) = resolve(address, request.operation == 6, false) else { return -14; };
            let at = (address & 4095) as usize;
            let count = (request.length - offset).min((4096 - at) as u64) as usize;
            with_frame(page, |p| unsafe {
                let buffer = (request.buffer as *mut u8).add(offset as usize);
                if request.operation == 6 { core::ptr::copy_nonoverlapping(buffer, p.add(at), count); }
                else { core::ptr::copy_nonoverlapping(p.add(at), buffer, count); }
            });
            offset += count as u64;
        }
        paging2::flush_tlb();
        return 0;
    }
    if start & 4095 != 0 || end & 4095 != 0 || start == end || request.protection & !7 != 0 { return -22; }
    if request.operation == 4 {
        for index in (start >> 39) as usize..end.div_ceil(1 << 39) as usize {
            if occupied(root(index), 3, (index as u64) << 39, start, end) { return -17; }
        }
    }
    let mut result = Ok(());
    for index in (start >> 39) as usize..end.div_ceil(1 << 39) as usize {
        let mut entry = root(index);
        result = update(&mut entry, 3, (index as u64) << 39, start, end, request.operation, request.protection);
        set_root(index, entry);
        if result.is_err() { break; }
    }
    paging2::flush_tlb();
    result.err().unwrap_or(0)
}

fn resolve(address: u64, write_access: bool, execute: bool) -> Option<u64> {
    if !(START..END).contains(&address) { return None; }
    fn walk(entry: &mut Entry64, level: u32, address: u64, write_access: bool, execute: bool) -> Option<u64> {
        if entry.raw() == 0 { return None; }
        if !entry.present() && (entry.raw() & ACCESS == 0 || write_access && !entry.hw_writable()
            || execute && entry.raw() & NO_EXECUTE != 0) { return None; }
        if level == 0 {
            if entry.present() && (!entry.user() || write_access && !entry.writable()
                || execute && entry.raw() & NO_EXECUTE != 0) { return None; }
            if !entry.present() {
                let old = *entry;
                let page = allocate(Entry64(0)).ok()?;
                *entry = Entry64::new(page, old.hw_writable(), true);
                entry.set_writable(old.hw_writable());
                entry.set_no_execute(old.raw() & NO_EXECUTE != 0);
            } else if write_access {
                if crate::phys_mm::get_ref_count(entry.page()) > 1 {
                    let page = allocate(Entry64(0)).ok()?;
                    let scratch = (&raw mut crate::SCRATCH).cast::<u8>();
                    with_frame(entry.page(), |p| unsafe { core::ptr::copy_nonoverlapping(p, scratch, 4096); });
                    with_frame(page, |p| unsafe { core::ptr::copy_nonoverlapping(scratch, p, 4096); });
                    crate::phys_mm::free_phys_page(entry.page());
                    entry.0 = (entry.0 & !Entry64::ADDR_MASK) | (page << 12);
                }
                entry.set_hw_writable(true);
            }
            return Some(entry.page());
        }
        let page = table(entry).ok()?;
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
    if !supported() || error & 8 != 0 { return false; }
    let result = resolve(address, error & 2 != 0, error & 16 != 0).is_some();
    paging2::flush_tlb();
    result
}
