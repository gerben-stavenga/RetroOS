//! EMS 4.0 (Expanded Memory Specification) emulation via INT 67h.
//!
//! 64KB page-frame in upper memory (set up by `scan_uma`), 256 logical pages
//! of 16KB each (4MB total) backed by the kernel's demand paging.

use crate::dbg_println;
use super::uma::EMS_BASE_PAGE;
use crate::kernel::startup;
use crate::kernel::thread;
use crate::Regs;

pub(crate) const EMS_ENABLED: bool = true;

const MAX_EMS_HANDLES: usize = 16;
/// Total EMS pages available (256 × 16KB = 4MB)
const EMS_TOTAL_PAGES: u16 = 256;

/// EMS backing region: virtual address space for EMS logical pages.
/// Each EMS page = 16KB = 4 virtual pages. Demand paging provides backing.
const EMS_BACKING_BASE: u32 = 0x500000;
/// Virtual page number for EMS logical page N = EMS_BACKING_VPAGE + N * 4
const EMS_BACKING_VPAGE: usize = (EMS_BACKING_BASE / 0x1000) as usize;

/// Dummy file handle returned for device "EMMXXXX0" (EMS detection)
pub(crate) const EMS_DEVICE_HANDLE: u16 = 0xFE;

/// EMS page frame segment — set dynamically by `scan_uma()`.
pub fn ems_frame_seg() -> u16 {
    (unsafe { EMS_BASE_PAGE } as u16) * 0x100
}

fn ems_base_page() -> usize {
    unsafe { EMS_BASE_PAGE }
}

/// Swap an EMS window with a backing region.
fn swap_ems_window(window: usize, backing_vpage: usize) {
    let frame = ems_base_page() + window * 4;
    startup::arch_swap_page_entries(backing_vpage, frame, 4);
}

/// Per-thread EMS driver state
pub struct EmsState {
    handles: [Option<EmsHandle>; MAX_EMS_HANDLES],
    /// Current mapping: frame[window] = (handle, logical_page) or None
    frame: [Option<(u8, u16)>; 4],
    /// Next EMS backing page index to allocate (bump allocator)
    next_page: u16,
}

struct EmsHandle {
    /// Backing virtual page for each logical page (each = 4 contiguous vpages).
    /// Demand paging provides physical backing on first access.
    pages: alloc::vec::Vec<usize>,
}

impl EmsState {
    fn new() -> Self {
        const NONE_H: Option<EmsHandle> = None;
        Self { handles: [NONE_H; MAX_EMS_HANDLES], frame: [None; 4], next_page: 0 }
    }

    fn alloc_pages(&self) -> u16 {
        let mut used: u16 = 0;
        for h in &self.handles {
            if let Some(h) = h {
                used += h.pages.len() as u16;
            }
        }
        EMS_TOTAL_PAGES.saturating_sub(used)
    }

    /// Clean up: backing pages are freed when the address space is torn down.
    pub fn free_all_pages(&mut self) {
        self.handles = core::array::from_fn(|_| None);
        self.frame = [None; 4];
    }
}

/// Ensure EMS state exists for current thread
fn ems_state(dos: &mut thread::DosState) -> &mut EmsState {
    if dos.ems.is_none() {
        dos.ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    dos.ems.as_deref_mut().unwrap()
}

pub(crate) fn int_67h(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    dbg_println!("EMS: AH={:02X} AX={:04X} BX={:04X} CX={:04X} DX={:04X}",
        ah, regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16);
    let result = int_67h_inner(dos, regs, ah);
    dbg_println!("EMS: -> AX={:04X} BX={:04X} CX={:04X} DX={:04X}",
        regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16);
    result
}

fn int_67h_inner(dos: &mut thread::DosState, regs: &mut Regs, ah: u8) -> thread::KernelAction {
    match ah {
        // AH=40h — Get status
        0x40 => {
            regs.rax = regs.rax & !0xFF00; // AH=0: OK
        }
        // AH=41h — Get page frame segment
        0x41 => {
            regs.rbx = (regs.rbx & !0xFFFF) | ems_frame_seg() as u64;
            regs.rax = regs.rax & !0xFF00; // AH=0
        }
        // AH=42h — Get unallocated page count
        0x42 => {
            let ems = ems_state(dos);
            let free = ems.alloc_pages();
            regs.rbx = (regs.rbx & !0xFFFF) | free as u64;     // BX = free pages
            regs.rdx = (regs.rdx & !0xFFFF) | EMS_TOTAL_PAGES as u64; // DX = total pages
            regs.rax = regs.rax & !0xFF00; // AH=0
        }
        // AH=43h — Allocate handle (BX=pages needed, returns DX=handle)
        0x43 => {
            let pages_needed = regs.rbx as u16;
            let ems = ems_state(dos);
            // Find free handle
            let mut handle = None;
            for i in 0..MAX_EMS_HANDLES {
                if ems.handles[i].is_none() {
                    handle = Some(i);
                    break;
                }
            }
            match handle {
                Some(i) => {
                    if ems.next_page + pages_needed > EMS_TOTAL_PAGES {
                        regs.rax = (regs.rax & !0xFF00) | (0x88 << 8); // not enough pages
                    } else {
                        // Allocate backing vpages from the EMS region (demand-paged)
                        let mut pages = alloc::vec::Vec::with_capacity(pages_needed as usize);
                        for _ in 0..pages_needed {
                            let vpage = EMS_BACKING_VPAGE + ems.next_page as usize * 4;
                            ems.next_page += 1;
                            pages.push(vpage);
                        }
                        ems.handles[i] = Some(EmsHandle { pages });
                        regs.rdx = (regs.rdx & !0xFFFF) | i as u64;
                        regs.rax = regs.rax & !0xFF00; // AH=0
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
                if let Some((old_h, old_lp)) = ems.frame[phys_page as usize] {
                    if let Some(ref h) = ems.handles[old_h as usize] {
                        swap_ems_window(phys_page as usize, h.pages[old_lp as usize]);
                    }
                }
                ems.frame[phys_page as usize] = None;
                regs.rax = regs.rax & !0xFF00; // AH=0
                return thread::KernelAction::Done;
            }

            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                return thread::KernelAction::Done;
            }

            match &ems.handles[handle as usize] {
                Some(h) if (log_page as usize) < h.pages.len() => {
                    let backing_vpage = h.pages[log_page as usize];
                    // Save current frame content back to old backing
                    if let Some((old_h, old_lp)) = ems.frame[phys_page as usize] {
                        if let Some(ref oh) = ems.handles[old_h as usize] {
                            swap_ems_window(phys_page as usize, oh.pages[old_lp as usize]);
                        }
                    }
                    // Load new backing into frame
                    swap_ems_window(phys_page as usize, backing_vpage);
                    ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                    regs.rax = regs.rax & !0xFF00; // AH=0
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
            let ems = ems_state(dos);
            if (handle as usize) < MAX_EMS_HANDLES && ems.handles[handle as usize].is_some() {
                // Unmap any windows using this handle
                for w in 0..4 {
                    if let Some((h, lp)) = ems.frame[w] {
                        if h == handle as u8 {
                            if let Some(ref hnd) = ems.handles[h as usize] {
                                swap_ems_window(w, hnd.pages[lp as usize]);
                            }
                            ems.frame[w] = None;
                        }
                    }
                }
                // Release handle (backing pages freed with address space)
                ems.handles[handle as usize] = None;
                regs.rax = regs.rax & !0xFF00; // AH=0
            } else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
            }
        }
        // AH=46h — Get version
        0x46 => {
            regs.rax = (regs.rax & !0xFF00) | (0x00 << 8); // AH=0
            regs.rax = (regs.rax & !0xFF) | 0x40; // AL=40h = version 4.0
        }
        // AH=4Bh — Get number of open handles
        0x4B => {
            let ems = ems_state(dos);
            let count = ems.handles.iter().filter(|h| h.is_some()).count() as u16;
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax = regs.rax & !0xFF00;
        }
        // AH=4Ch — Get pages allocated to handle (DX=handle)
        0x4C => {
            let handle = regs.rdx as u16;
            let ems = ems_state(dos);
            if (handle as usize) < MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[handle as usize] {
                    regs.rbx = (regs.rbx & !0xFFFF) | h.pages.len() as u64;
                    regs.rax = regs.rax & !0xFF00;
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
            for i in 0..MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[i] {
                    unsafe {
                        (addr as *mut u16).write_unaligned(i as u16);
                        ((addr + 2) as *mut u16).write_unaligned(h.pages.len() as u16);
                    }
                    addr += 4;
                    count += 1;
                }
            }
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax = regs.rax & !0xFF00;
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
            if (handle as usize) >= MAX_EMS_HANDLES || ems.handles[handle as usize].is_none() {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }

            for i in 0..count as u32 {
                let log_page = unsafe { ((base_addr + i * 4) as *const u16).read_unaligned() };
                let phys_raw = unsafe { ((base_addr + i * 4 + 2) as *const u16).read_unaligned() };

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
                if let Some((old_h, old_lp)) = ems.frame[phys_page as usize] {
                    if let Some(ref oh) = ems.handles[old_h as usize] {
                        swap_ems_window(phys_page as usize, oh.pages[old_lp as usize]);
                    }
                }

                if log_page == 0xFFFF {
                    ems.frame[phys_page as usize] = None;
                } else {
                    match &ems.handles[handle as usize] {
                        Some(h) if (log_page as usize) < h.pages.len() => {
                            let backing_vpage = h.pages[log_page as usize];
                            swap_ems_window(phys_page as usize, backing_vpage);
                            ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                        }
                        _ => {
                            regs.rax = (regs.rax & !0xFF00) | (0x8A << 8);
                            return thread::KernelAction::Done;
                        }
                    }
                }
            }
            regs.rax = regs.rax & !0xFF00; // AH=0
        }
        // AH=51h — Reallocate pages for handle (DX=handle, BX=new count)
        0x51 => {
            let handle = regs.rdx as u16;
            let new_count = regs.rbx as u16;
            let ems = ems_state(dos);
            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }
            match &mut ems.handles[handle as usize] {
                Some(h) => {
                    let old_count = h.pages.len();
                    if (new_count as usize) > old_count {
                        if ems.next_page + (new_count - old_count as u16) > EMS_TOTAL_PAGES {
                            regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                            return thread::KernelAction::Done;
                        }
                        for _ in old_count..(new_count as usize) {
                            let vpage = EMS_BACKING_VPAGE + ems.next_page as usize * 4;
                            ems.next_page += 1;
                            h.pages.push(vpage);
                        }
                    } else if (new_count as usize) < old_count {
                        h.pages.truncate(new_count as usize);
                    }
                    regs.rax = regs.rax & !0xFF00;
                    regs.rbx = (regs.rbx & !0xFFFF) | new_count as u64;
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
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
                    unsafe {
                        ((base + i * 4) as *mut u16).write_unaligned(seg);
                        ((base + i * 4 + 2) as *mut u16).write_unaligned(i as u16);
                    }
                }
                regs.rcx = (regs.rcx & !0xFFFF) | 4; // 4 mappable pages
                regs.rax = regs.rax & !0xFF00;
            } else {
                // Sub 1: just return count
                regs.rcx = (regs.rcx & !0xFFFF) | 4;
                regs.rax = regs.rax & !0xFF00;
            }
        }
        _ => {
            dbg_println!("EMS: UNHANDLED AH={:02X}", ah);
            regs.rax = (regs.rax & !0xFF00) | (0x84 << 8); // AH=84: function not supported
        }
    }
    thread::KernelAction::Done
}
