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

/// Swap an EMS window with a backing region.
fn swap_ems_window<A: crate::Arch>(machine: &mut A, window: usize, backing_vpage: usize) {
    let frame = ems_base_page() + window * 4;
    machine.swap_page_entries(backing_vpage, frame, 4);
}

/// Per-thread EMS driver state
pub struct EmsState {
    handles: [Option<EmsHandle>; MAX_EMS_HANDLES],
    /// Current mapping: frame[window] = (handle, logical_page) or None
    frame: [Option<(u8, u16)>; 4],
}

#[derive(Clone, Copy)]
struct EmsHandle {
    /// One allocation in the common manager. A legal zero-page EMS handle has
    /// no backing range until it is enlarged.
    base: Option<u32>,
    pages: u16,
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

    /// Put mapped pages back in their backing ranges before the common memory
    /// manager releases those ranges. This keeps EMS teardown correct even
    /// when it happens before the entire address space is destroyed.
    pub fn free_all_pages<A: crate::Arch>(&mut self, machine: &mut A) {
        for window in 0..self.frame.len() {
            if let Some((handle, logical)) = self.frame[window]
                && let Some(allocation) = self.handles[handle as usize]
                && let Some(vpage) = backing_vpage(&allocation, logical)
            {
                swap_ems_window(machine, window, vpage);
            }
        }
        self.handles = core::array::from_fn(|_| None);
        self.frame = [None; 4];
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
                                    base: block.map(|b| b.base), pages: pages_needed,
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
            let phys_page = regs.rax as u8; // AL
            let log_page = regs.rbx as u16;
            let handle = regs.rdx as u16;

            if phys_page > 3 {
                regs.rax = (regs.rax & !0xFF00) | (0x8B << 8); // invalid physical page
                return thread::KernelAction::Done;
            }

            let ems = ems_state(dos);

            // BX=FFFFh means unmap
            if log_page == 0xFFFF {
                // Save current frame content back to its backing
                if let Some((old_h, old_lp)) = ems.frame[phys_page as usize]
                    && let Some(ref h) = ems.handles[old_h as usize] {
                        swap_ems_window(machine, phys_page as usize, backing_vpage(h, old_lp).unwrap());
                    }
                ems.frame[phys_page as usize] = None;
                regs.rax &= !0xFF00; // AH=0
                return thread::KernelAction::Done;
            }

            if handle == 0 || (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                return thread::KernelAction::Done;
            }

            match &ems.handles[handle as usize] {
                Some(h) if log_page < h.pages => {
                    let new_vpage = backing_vpage(h, log_page).unwrap();
                    // Save current frame content back to old backing
                    if let Some((old_h, old_lp)) = ems.frame[phys_page as usize]
                        && let Some(ref oh) = ems.handles[old_h as usize] {
                            swap_ems_window(machine, phys_page as usize, backing_vpage(oh, old_lp).unwrap());
                        }
                    // Load new backing into frame
                    swap_ems_window(machine, phys_page as usize, new_vpage);
                    ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                    regs.rax &= !0xFF00; // AH=0
                }
                Some(_) => {
                    regs.rax = (regs.rax & !0xFF00) | (0x8A << 8); // logical page out of range
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                }
            }
        }
        // AH=45h — Release handle (DX=handle)
        0x45 => {
            let handle = regs.rdx as u16;
            let (ems, memory) = ems_parts(dos);
            if handle != 0 && (handle as usize) < MAX_EMS_HANDLES && ems.handles[handle as usize].is_some() {
                // Unmap any windows using this handle
                for w in 0..4 {
                    if let Some((h, lp)) = ems.frame[w]
                        && h == handle as u8 {
                            if let Some(ref hnd) = ems.handles[h as usize] {
                                swap_ems_window(machine, w, backing_vpage(hnd, lp).unwrap());
                            }
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
            let al = regs.rax as u8;
            let count = regs.rcx as u16;
            let handle = regs.rdx as u16;
            let ds = regs.ds as u16 as u32;
            let si = regs.rsi as u16 as u32;
            let base_addr = (ds << 4) + si;

            let ems = ems_state(dos);
            if handle == 0 || (handle as usize) >= MAX_EMS_HANDLES || ems.handles[handle as usize].is_none() {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }

            for i in 0..count as u32 {
                let log_page = machine.read::<u16>((base_addr + i * 4) as usize);
                let phys_raw = machine.read::<u16>((base_addr + i * 4 + 2) as usize);

                let phys_page = if al == 0 {
                    phys_raw as u8
                } else {
                    // Segment mode: convert segment to physical page index
                    let seg_offset = phys_raw.wrapping_sub(ems_frame_seg());
                    (seg_offset / 0x0400) as u8 // each window is 0x400 paragraphs (16KB)
                };

                if phys_page > 3 {
                    regs.rax = (regs.rax & !0xFF00) | (0x8B << 8);
                    return thread::KernelAction::Done;
                }

                // Save current frame content back to old backing
                if let Some((old_h, old_lp)) = ems.frame[phys_page as usize]
                    && let Some(ref oh) = ems.handles[old_h as usize] {
                        swap_ems_window(machine, phys_page as usize, backing_vpage(oh, old_lp).unwrap());
                    }

                if log_page == 0xFFFF {
                    ems.frame[phys_page as usize] = None;
                } else {
                    match &ems.handles[handle as usize] {
                        Some(h) if log_page < h.pages => {
                            let new_vpage = backing_vpage(h, log_page).unwrap();
                            swap_ems_window(machine, phys_page as usize, new_vpage);
                            ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                        }
                        _ => {
                            regs.rax = (regs.rax & !0xFF00) | (0x8A << 8);
                            return thread::KernelAction::Done;
                        }
                    }
                }
            }
            regs.rax &= !0xFF00; // AH=0
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

            // Restore every window before the common allocation moves or
            // releases backing PTEs. Reapply surviving mappings afterward.
            let mut mapped = [None; 4];
            for (window, slot) in mapped.iter_mut().enumerate() {
                if let Some((mapped_handle, logical)) = ems.frame[window]
                    && mapped_handle == handle as u8
                {
                    swap_ems_window(machine, window, backing_vpage(&old, logical).unwrap());
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
                    ems.handles[handle as usize] = Some(EmsHandle { base, pages: new_count });
                    let resized = ems.handles[handle as usize].as_ref().unwrap();
                    for (window, logical) in mapped.into_iter().enumerate() {
                        if let Some(logical) = logical
                            && let Some(vpage) = backing_vpage(resized, logical)
                        {
                            swap_ems_window(machine, window, vpage);
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
                            swap_ems_window(machine, window, backing_vpage(&old, logical).unwrap());
                            ems.frame[window] = Some((handle as u8, logical));
                        }
                    }
                    regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                }
            }
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
