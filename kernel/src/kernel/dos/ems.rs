//! EMS 4.0 (Expanded Memory Specification) emulation via INT 67h.
//!
//! 64KB page-frame in upper memory (set up by `scan_uma`), 256 logical pages
//! of 16KB each (4MB total) allocated from the DOS personality's common
//! committed extended-memory pool.

use crate::Regs;
use super::xms::EMS_BASE_PAGE;
use crate::kernel::thread;

pub(crate) const EMS_ENABLED: bool = true;

// LIM handle zero belongs to the operating system. Application handles are
// slots 1..=16.
const MAX_EMS_HANDLES: usize = 17;
/// Total EMS pages available (256 × 16KB = 4MB)
const EMS_TOTAL_PAGES: u16 = 256;

const EMS_PAGE_BYTES: u32 = 16 * 1024;

/// Dummy file handle returned for device "EMMXXXX0" (EMS detection)
pub(crate) const EMS_DEVICE_HANDLE: u16 = 0xFE;

/// EMS page frame segment — set dynamically by `scan_uma()`.
pub fn ems_frame_seg() -> u16 {
    (EMS_BASE_PAGE.load(core::sync::atomic::Ordering::Relaxed) as u16) * 0x100
}

fn ems_base_page() -> usize {
    EMS_BASE_PAGE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Alias a window onto its backing pages. The backing mapping stays live:
/// multiple physical windows may name the same logical EMS page.
fn map_ems_window<A: crate::Arch>(machine: &mut A, window: usize, backing: Option<usize>) {
    let frame = ems_base_page() + window * 4;
    if let Some(backing) = backing {
        machine.copy_page_entries(backing, frame, 4);
    } else {
        machine.unmap_range(frame, 4);
    }
}

type PageMap = [Option<(u8, u16)>; 4];

/// Per-thread EMS driver state
pub struct EmsState {
    handles: [Option<EmsHandle>; MAX_EMS_HANDLES],
    /// Current mapping: frame[window] = (handle, logical_page) or None
    frame: PageMap,
}

#[derive(Clone, Copy)]
struct EmsHandle {
    /// One allocation in the common manager. A legal zero-page EMS handle has
    /// no backing range until it is enlarged.
    base: Option<u32>,
    pages: u16,
    saved_map: Option<PageMap>,
}

impl EmsState {
    fn new() -> Self {
        const NONE_H: Option<EmsHandle> = None;
        Self { handles: [NONE_H; MAX_EMS_HANDLES], frame: [None; 4] }
    }

    fn alloc_pages(&self) -> u16 {
        let mut used: u16 = 0;
        for h in self.handles.iter().flatten() {
            used += h.pages;
        }
        EMS_TOTAL_PAGES.saturating_sub(used)
    }

    /// Remove window aliases before releasing the owning allocations.
    pub fn free_all_pages<A: crate::Arch>(&mut self, machine: &mut A) {
        for window in 0..self.frame.len() {
            if self.frame[window].is_some() {
                map_ems_window(machine, window, None);
            }
        }
        self.handles = core::array::from_fn(|_| None);
        self.frame = [None; 4];
    }

    fn map<A: crate::Arch>(&mut self, machine: &mut A, window: usize,
                          handle: u16, logical: u16) -> Result<(), u8> {
        if window >= 4 { return Err(0x8B); }
        let mapping = if logical == 0xFFFF { None } else {
            let h = self.handles.get(handle as usize).and_then(Option::as_ref).ok_or(0x83)?;
            let page = backing_vpage(h, logical).ok_or(0x8A)?;
            Some((page, (handle as u8, logical)))
        };
        map_ems_window(machine, window, mapping.map(|m| m.0));
        self.frame[window] = mapping.map(|m| m.1);
        Ok(())
    }

    fn restore<A: crate::Arch>(&mut self, machine: &mut A, map: PageMap) -> Result<(), u8> {
        // Validate the entire saved context before changing any window.
        for (handle, logical) in map.iter().flatten() {
            let h = self.handles.get(*handle as usize).and_then(Option::as_ref).ok_or(0x83)?;
            backing_vpage(h, *logical).ok_or(0x8A)?;
        }
        for (window, entry) in map.into_iter().enumerate() {
            let (handle, logical) = entry.unwrap_or((0, 0xFFFF));
            self.map(machine, window, u16::from(handle), logical)?;
        }
        Ok(())
    }

}

/// Ensure EMS state exists for current thread
fn ems_state<A: crate::Arch>(dos: &mut thread::DosState<A>) -> &mut EmsState {
    if dos.ems.is_none() {
        dos.ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    dos.ems.as_deref_mut().unwrap()
}

fn ems_parts<A: crate::Arch>(dos: &mut thread::DosState<A>)
    -> (&mut EmsState, &mut super::memory::DosMemory)
{
    if dos.ems.is_none() {
        dos.ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    (dos.ems.as_deref_mut().unwrap(), &mut dos.memory)
}

fn backing_vpage(handle: &EmsHandle, logical_page: u16) -> Option<usize> {
    if logical_page >= handle.pages { return None; }
    handle.base.map(|base| (base / 4096) as usize + usize::from(logical_page) * 4)
}

pub(crate) fn int_67h<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    dos_trace!("EMS: AH={:02X} AX={:04X} BX={:04X} CX={:04X} DX={:04X}",
        ah, regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16);
    // Hide EMS from DPMI clients. The page-frame segment we'd report
    // (e.g. 0xD000) is a real-mode segment, not a PM selector. Borland
    // C++ 3.1 writes it into overlay tables and later dereferences it in
    // protected mode. PM clients should use DPMI memory services instead.
    if dos.dpmi.is_some() {
        regs.rax = (regs.rax & !0xFF00) | 0x80_00; // AH=80: not present
        dos_trace!("EMS: -> AX={:04X} (DPMI active, hidden from PM client)",
            regs.rax as u16);
        return thread::KernelAction::Done;
    }
    let result = int_67h_inner(machine, dos, regs, ah);
    dos_trace!("EMS: -> AX={:04X} BX={:04X} CX={:04X} DX={:04X}",
        regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16);
    result
}

fn int_67h_inner<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, ah: u8) -> thread::KernelAction {
    match ah {
        // AH=40h — Get status
        0x40 => {
            regs.rax &= !0xFF00; // AH=0: OK
        }
        // AH=41h — Get page frame segment
        0x41 => {
            regs.rbx = (regs.rbx & !0xFFFF) | ems_frame_seg() as u64;
            regs.rax &= !0xFF00; // AH=0
        }
        // AH=42h — Get unallocated page count
        0x42 => {
            let (ems, memory) = ems_parts(dos);
            let free = ems.alloc_pages().min(
                memory.available_pages(machine).saturating_div(4).min(u16::MAX as usize) as u16,
            );
            regs.rbx = (regs.rbx & !0xFFFF) | free as u64;     // BX = free pages
            regs.rdx = (regs.rdx & !0xFFFF) | EMS_TOTAL_PAGES as u64; // DX = total pages
            regs.rax &= !0xFF00; // AH=0
        }
        // AH=43h — Allocate handle (BX=pages needed, returns DX=handle)
        0x43 => {
            let pages_needed = regs.rbx as u16;
            let (ems, memory) = ems_parts(dos);
            // Find free handle
            let mut handle = None;
            for i in 1..MAX_EMS_HANDLES {
                if ems.handles[i].is_none() {
                    handle = Some(i);
                    break;
                }
            }
            match handle {
                Some(i) => {
                    if pages_needed > ems.alloc_pages() {
                        regs.rax = (regs.rax & !0xFF00) | (0x88 << 8); // not enough pages
                    } else {
                        let allocated = if pages_needed == 0 { Ok(None) } else {
                            memory.allocate(
                                machine, super::memory::EMS_OWNER,
                                u32::from(pages_needed) * EMS_PAGE_BYTES, EMS_PAGE_BYTES,
                                0x0050_0000, super::memory::general_limit(),
                            ).map(Some)
                        };
                        match allocated {
                            Ok(block) => {
                                ems.handles[i] = Some(EmsHandle {
                                    base: block.map(|b| b.base), pages: pages_needed, saved_map: None,
                                });
                                regs.rdx = (regs.rdx & !0xFFFF) | i as u64;
                                regs.rax &= !0xFF00;
                            }
                            Err(_) => regs.rax = (regs.rax & !0xFF00) | (0x88 << 8),
                        }
                    }
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x85 << 8); // no more handles
                }
            }
        }
        // AH=44h — Map page (AL=physical page 0-3, BX=logical page, DX=handle)
        0x44 => {
            let result = ems_state(dos).map(machine, regs.rax as u8 as usize,
                                          regs.rdx as u16, regs.rbx as u16);
            regs.rax = (regs.rax & !0xFF00) | (u64::from(result.err().unwrap_or(0)) << 8);
        }
        // AH=45h — Release handle (DX=handle)
        0x45 => {
            let handle = regs.rdx as u16;
            let (ems, memory) = ems_parts(dos);
            if handle != 0 && (handle as usize) < MAX_EMS_HANDLES && ems.handles[handle as usize].is_some() {
                // Unmap any windows using this handle
                for w in 0..4 {
                    if let Some((h, _)) = ems.frame[w]
                        && h == handle as u8 {
                            map_ems_window(machine, w, None);
                            ems.frame[w] = None;
                        }
                }
                let released = ems.handles[handle as usize].take().unwrap();
                if let Some(base) = released.base {
                    let _ = memory.free(machine, super::memory::EMS_OWNER, base);
                }
                regs.rax &= !0xFF00; // AH=0
            } else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
            }
        }
        // AH=46h — Get version
        0x46 => {
            regs.rax &= !0xFF00; // AH=0
            regs.rax = (regs.rax & !0xFF) | 0x40; // AL=40h = version 4.0
        }
        // AH=47h/48h — Save/restore the complete page map in a handle.
        0x47 | 0x48 => {
            let ems = ems_state(dos);
            let handle = regs.rdx as u16 as usize;
            let result = match ems.handles.get(handle).copied().flatten() {
                None => Err(0x83u8),
                Some(h) if ah == 0x47 => {
                    if h.saved_map.is_some() { Err(0x8D) } else {
                        ems.handles[handle].as_mut().unwrap().saved_map = Some(ems.frame);
                        Ok(())
                    }
                }
                Some(h) => match h.saved_map {
                    None => Err(0x8E),
                    Some(map) => {
                        let result = ems.restore(machine, map);
                        if result.is_ok() {
                            ems.handles[handle].as_mut().unwrap().saved_map = None;
                        }
                        result
                    }
                },
            };
            regs.rax = (regs.rax & !0xFF00) | (u64::from(result.err().unwrap_or(0)) << 8);
        }
        // AH=4Bh — Get number of open handles
        0x4B => {
            let ems = ems_state(dos);
            let count = ems.handles.iter().filter(|h| h.is_some()).count() as u16;
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax &= !0xFF00;
        }
        // AH=4Ch — Get pages allocated to handle (DX=handle)
        0x4C => {
            let handle = regs.rdx as u16;
            let ems = ems_state(dos);
            if handle != 0 && (handle as usize) < MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[handle as usize] {
                    regs.rbx = (regs.rbx & !0xFFFF) | h.pages as u64;
                    regs.rax &= !0xFF00;
                } else {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                }
            } else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
            }
        }
        // AH=4Dh — Get pages for all handles (ES:DI = buffer)
        0x4D => {
            let ems = ems_state(dos);
            let es = regs.es as u32;
            let di = regs.rdi as u32;
            let mut addr = (es << 4) + di;
            let mut count = 0u16;
            for i in 1..MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[i] {
                    machine.write::<u16>(addr as usize, i as u16);
                    machine.write::<u16>(addr as usize + 2, h.pages);
                    addr += 4;
                    count += 1;
                }
            }
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax &= !0xFF00;
        }
        // AH=50h — Map multiple pages (AL=0: phys page mode, AL=1: segment mode)
        // CX=count, DX=handle, DS:SI=mapping array
        0x50 => {
            let sub = regs.rax as u8;
            let count = regs.rcx as u16;
            let handle = regs.rdx as u16;
            let address = ((regs.ds as u16 as usize) << 4) + regs.rsi as u16 as usize;
            let ems = ems_state(dos);
            let result = (|| -> Result<(), u8> {
                if sub > 1 { return Err(0x8F); }
                for i in 0..usize::from(count) {
                    let logical = machine.read::<u16>(address + i * 4);
                    let physical = machine.read::<u16>(address + i * 4 + 2);
                    let window = if sub == 0 { usize::from(physical) } else {
                        let offset = physical.checked_sub(ems_frame_seg()).ok_or(0x8B)?;
                        if !offset.is_multiple_of(0x400) { return Err(0x8B); }
                        usize::from(offset / 0x400)
                    };
                    ems.map(machine, window, handle, logical)?;
                }
                Ok(())
            })();
            regs.rax = (regs.rax & !0xFF00) | (u64::from(result.err().unwrap_or(0)) << 8);
        }
        // AH=51h — Reallocate pages for handle (DX=handle, BX=new count)
        0x51 => {
            let handle = regs.rdx as u16;
            let new_count = regs.rbx as u16;
            let (ems, memory) = ems_parts(dos);
            if handle == 0 || (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }
            let Some(old) = ems.handles[handle as usize] else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            };
            let old_base = old.base;
            let old_count = old.pages;
            if new_count > old_count.saturating_add(ems.alloc_pages()) {
                regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                return thread::KernelAction::Done;
            }

            // Detach aliases before resizing the owning allocation, then map
            // surviving windows onto its possibly relocated backing.
            let mut mapped = [None; 4];
            for (window, slot) in mapped.iter_mut().enumerate() {
                if let Some((mapped_handle, logical)) = ems.frame[window]
                    && mapped_handle == handle as u8
                {
                    map_ems_window(machine, window, None);
                    ems.frame[window] = None;
                    *slot = Some(logical);
                }
            }
            let changed = match (old_base, new_count) {
                (None, 0) => Ok(None),
                (None, _) => memory.allocate(
                    machine, super::memory::EMS_OWNER,
                    u32::from(new_count) * EMS_PAGE_BYTES, EMS_PAGE_BYTES,
                    0x0050_0000, super::memory::general_limit(),
                ).map(|block| Some(block.base)),
                (Some(base), 0) => memory.free(machine, super::memory::EMS_OWNER, base).map(|()| None),
                (Some(base), _) => memory.resize(
                    machine, super::memory::EMS_OWNER, base,
                    u32::from(new_count) * EMS_PAGE_BYTES, EMS_PAGE_BYTES,
                    0x0050_0000, super::memory::general_limit(),
                ).map(|block| Some(block.base)),
            };
            match changed {
                Ok(base) => {
                    ems.handles[handle as usize] = Some(EmsHandle { base, pages: new_count, saved_map: old.saved_map });
                    let resized = ems.handles[handle as usize].as_ref().unwrap();
                    for (window, logical) in mapped.into_iter().enumerate() {
                        if let Some(logical) = logical
                            && let Some(vpage) = backing_vpage(resized, logical)
                        {
                            map_ems_window(machine, window, Some(vpage));
                            ems.frame[window] = Some((handle as u8, logical));
                        }
                    }
                    regs.rax &= !0xFF00;
                    regs.rbx = (regs.rbx & !0xFFFF) | new_count as u64;
                }
                Err(_) => {
                    // The old allocation is intact on failure; restore its windows.
                    for (window, logical) in mapped.into_iter().enumerate() {
                        if let Some(logical) = logical {
                            map_ems_window(machine, window, backing_vpage(&old, logical));
                            ems.frame[window] = Some((handle as u8, logical));
                        }
                    }
                    regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                }
            }
        }
        // AH=57h — Move/exchange conventional or expanded memory regions.
        0x57 => {
            let result = move_region(machine, ems_state(dos), regs);
            regs.rax = (regs.rax & !0xFF00) | (u64::from(result.err().unwrap_or(0)) << 8);
        }
        // AH=58h — Get mappable physical page array
        0x58 => {
            let al = regs.rax as u8;
            if al == 0 {
                // Sub 0: fill array at ES:DI with (segment, physical_page) pairs
                let es = regs.es as u32;
                let di = regs.rdi as u32;
                let base = (es << 4) + di;
                for i in 0..4u32 {
                    let seg = ems_frame_seg() + (i as u16) * 0x0400;
                    machine.write::<u16>((base + i * 4) as usize, seg);
                    machine.write::<u16>((base + i * 4 + 2) as usize, i as u16);
                }
                regs.rcx = (regs.rcx & !0xFFFF) | 4; // 4 mappable pages
                regs.rax &= !0xFF00;
            } else {
                regs.rcx = (regs.rcx & !0xFFFF) | 4;
                regs.rax &= !0xFF00;
            }
        }
        _ => {
            dos_trace!("EMS: UNHANDLED AH={:02X}", ah);
            regs.rax = (regs.rax & !0xFF00) | (0x84 << 8); // AH=84: function not supported
        }
    }
    thread::KernelAction::Done
}

/// Resolve one packed AH=57h endpoint. Expanded offsets can cross logical
/// pages, but the initial offset must lie within its first 16 KiB page.
fn region_address<A: crate::Arch>(machine: &A, ems: &EmsState, descriptor: usize,
                                  length: usize) -> Result<usize, u8> {
    let kind = machine.read::<u8>(descriptor);
    let handle = machine.read::<u16>(descriptor + 1);
    let offset = usize::from(machine.read::<u16>(descriptor + 3));
    let page = usize::from(machine.read::<u16>(descriptor + 5));
    match kind {
        0 => {
            let address = (page << 4) + offset;
            if address + length > 0x10_0000 { return Err(0xA2); }
            Ok(address)
        }
        1 => {
            let h = ems.handles.get(usize::from(handle)).and_then(Option::as_ref).ok_or(0x83)?;
            if offset >= EMS_PAGE_BYTES as usize { return Err(0x95); }
            if page >= usize::from(h.pages) { return Err(0x8A); }
            let start = page * EMS_PAGE_BYTES as usize + offset;
            if start + length > usize::from(h.pages) * EMS_PAGE_BYTES as usize { return Err(0x93); }
            Ok(h.base.ok_or(0x8A)? as usize + start)
        }
        _ => Err(0x98),
    }
}

/// Split an address range at window boundaries and translate aliases back to
/// the owning allocation. This also detects overlap when one endpoint uses a
/// conventional segment inside the EMS page frame.
fn region_spans(ems: &EmsState, mut address: usize, mut length: usize)
    -> alloc::vec::Vec<(usize, usize)>
{
    let mut spans = alloc::vec::Vec::new();
    let frame = ems_base_page() * 4096;
    while length != 0 {
        let (canonical, run) = if address < frame {
            (address, length.min(frame - address))
        } else if address < frame + 4 * EMS_PAGE_BYTES as usize {
            let window = (address - frame) / EMS_PAGE_BYTES as usize;
            let offset = (address - frame) % EMS_PAGE_BYTES as usize;
            let canonical = ems.frame[window].and_then(|(handle, logical)| {
                backing_vpage(ems.handles[usize::from(handle)].as_ref()?, logical)
            }).map_or(address, |page| page * 4096 + offset);
            (canonical, length.min(EMS_PAGE_BYTES as usize - offset))
        } else {
            (address, length)
        };
        spans.push((canonical, run));
        address += run;
        length -= run;
    }
    spans
}

fn move_region<A: crate::Arch>(machine: &mut A, ems: &EmsState, regs: &Regs) -> Result<(), u8> {
    let sub = regs.rax as u8;
    if sub > 1 { return Err(0x8F); }
    let descriptor = ((regs.ds as u16 as usize) << 4) + regs.rsi as u16 as usize;
    let length = machine.read::<u32>(descriptor) as usize;
    if length > 0x10_0000 { return Err(0x96); }
    let src = region_address(machine, ems, descriptor + 4, length)?;
    let dst = region_address(machine, ems, descriptor + 11, length)?;
    let sources = region_spans(ems, src, length);
    let destinations = region_spans(ems, dst, length);
    let overlap = sources.iter().any(|&(s, sn)| destinations.iter()
        .any(|&(d, dn)| s < d + dn && d < s + sn));
    let overlap_status = if machine.read::<u8>(descriptor + 4)
        != machine.read::<u8>(descriptor + 11) { 0x94 } else if sub == 1 { 0x97 } else { 0x92 };
    if overlap && sub == 1 { return Err(overlap_status); }
    if sub == 0 && !overlap {
        machine.copy_within(src, dst, length);
        return Ok(());
    }
    // Snapshot before writing: linear addresses alone cannot reveal physical
    // overlap through two different page-frame windows. The spec limits this
    // temporary buffer to 1 MiB, and no guest page mappings need to change.
    let mut source = alloc::vec![0u8; length];
    machine.copy_from(src, &mut source);
    if sub == 1 {
        machine.copy_within(dst, src, length);
    }
    machine.copy_to(dst, &source);
    if overlap { Err(overlap_status) } else { Ok(()) }
}
