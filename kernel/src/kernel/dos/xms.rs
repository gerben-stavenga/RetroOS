//! XMS 3.0 (Extended Memory Specification) emulation.
//!
//! Pure bookkeeping over the VM86 linear address space above the HMA + A20
//! shadow region. Physical backing comes from the kernel's demand paging.

use crate::kernel::dos::dos_trace;
use crate::kernel::dos::linear;
use super::uma::{umb_alloc, umb_free, umb_largest};
use crate::kernel::thread;
use crate::Regs;

const MAX_XMS_HANDLES: usize = 16;
/// XMS address space: linear 0x120000 (after HMA + shadow region) to ~0x500000.
/// Pages 0x100-0x10F = HMA, 0x110-0x11F = A20 shadow. XMS starts after both.
const XMS_BASE: u32 = 0x120000; // after HMA + shadow (1MB + 128KB)
const XMS_END: u32 = 0x500000;  // 5MB — plenty for DOS games
const XMS_TOTAL_KB: u16 = ((XMS_END - XMS_BASE) / 1024) as u16;

/// A single XMS handle — contiguous range in VM86 linear address space.
struct XmsHandle {
    base: u32,    // linear address
    size_kb: u16,
    locked: bool,
}

/// Per-thread XMS driver state.
pub struct XmsState {
    handles: [Option<XmsHandle>; MAX_XMS_HANDLES],
    a20_local: u16,
    a20_global: u16,
}

impl XmsState {
    fn new() -> Self {
        const NONE: Option<XmsHandle> = None;
        Self { handles: [NONE; MAX_XMS_HANDLES], a20_local: 0, a20_global: 0 }
    }

    /// Find a contiguous free region of `size` bytes. Returns linear address or None.
    fn find_free(&self, size: u32) -> Option<u32> {
        if size == 0 { return Some(XMS_BASE); }

        // Collect allocated ranges, sorted by base
        let mut ranges: [(u32, u32); MAX_XMS_HANDLES] = [(0, 0); MAX_XMS_HANDLES];
        let mut count = 0;
        for h in &self.handles {
            if let Some(h) = h {
                ranges[count] = (h.base, h.size_kb as u32 * 1024);
                count += 1;
            }
        }
        for i in 1..count {
            let mut j = i;
            while j > 0 && ranges[j].0 < ranges[j - 1].0 {
                ranges.swap(j, j - 1);
                j -= 1;
            }
        }

        let mut start = XMS_BASE;
        for i in 0..count {
            let gap = ranges[i].0.saturating_sub(start);
            if gap >= size { return Some(start); }
            start = ranges[i].0 + ranges[i].1;
        }
        if XMS_END.saturating_sub(start) >= size { return Some(start); }
        None
    }

    fn free_kb(&self) -> u16 {
        let mut used: u32 = 0;
        for h in &self.handles {
            if let Some(h) = h {
                used += h.size_kb as u32;
            }
        }
        XMS_TOTAL_KB.saturating_sub(used as u16)
    }

    fn largest_free_kb(&self) -> u16 {
        let mut ranges: [(u32, u32); MAX_XMS_HANDLES] = [(0, 0); MAX_XMS_HANDLES];
        let mut count = 0;
        for h in &self.handles {
            if let Some(h) = h {
                ranges[count] = (h.base, h.size_kb as u32 * 1024);
                count += 1;
            }
        }
        for i in 1..count {
            let mut j = i;
            while j > 0 && ranges[j].0 < ranges[j - 1].0 {
                ranges.swap(j, j - 1);
                j -= 1;
            }
        }
        let mut largest = 0u32;
        let mut start = XMS_BASE;
        for i in 0..count {
            let gap = ranges[i].0.saturating_sub(start);
            if gap > largest { largest = gap; }
            start = ranges[i].0 + ranges[i].1;
        }
        let gap = XMS_END.saturating_sub(start);
        if gap > largest { largest = gap; }
        (largest / 1024) as u16
    }
}

fn xms_state(dos: &mut thread::DosState) -> &mut XmsState {
    if dos.xms.is_none() {
        dos.xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    dos.xms.as_deref_mut().unwrap()
}

pub(crate) fn xms_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — Get XMS version
        0x00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0300; // XMS 3.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // driver internal revision
            regs.rdx = (regs.rdx & !0xFFFF) | 0x0001; // HMA exists
        }
        // AH=03h — Global enable A20
        0x03 => {
            let xms = xms_state(dos);
            xms.a20_global += 1;
            dos.pc.set_a20(true);
            regs.rax = (regs.rax & !0xFFFF) | 1; // success
            regs.rbx = regs.rbx & !0xFFFF; // BL=0 no error
        }
        // AH=04h — Global disable A20
        0x04 => {
            let xms = xms_state(dos);
            xms.a20_global = xms.a20_global.saturating_sub(1);
            if xms.a20_global == 0 && xms.a20_local == 0 {
                dos.pc.set_a20(false);
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = regs.rbx & !0xFFFF;
        }
        // AH=05h — Local enable A20
        0x05 => {
            let xms = xms_state(dos);
            xms.a20_local += 1;
            dos.pc.set_a20(true);
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = regs.rbx & !0xFFFF;
        }
        // AH=06h — Local disable A20
        0x06 => {
            let xms = xms_state(dos);
            xms.a20_local = xms.a20_local.saturating_sub(1);
            if xms.a20_local == 0 && xms.a20_global == 0 {
                dos.pc.set_a20(false);
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = regs.rbx & !0xFFFF;
        }
        // AH=07h — Query A20 state
        0x07 => {
            let enabled = dos.pc.a20_enabled;
            regs.rax = (regs.rax & !0xFFFF) | if enabled { 1 } else { 0 };
            regs.rbx = regs.rbx & !0xFFFF;
        }
        // AH=08h — Query free extended memory
        0x08 => {
            let xms = xms_state(dos);
            let largest = xms.largest_free_kb();
            let total = xms.free_kb();
            regs.rax = (regs.rax & !0xFFFF) | largest as u64; // largest free block (KB)
            regs.rdx = (regs.rdx & !0xFFFF) | total as u64;   // total free (KB)
        }
        // AH=09h — Allocate extended memory block (DX=size in KB)
        0x09 => {
            let size_kb = regs.rdx as u16;
            let xms = xms_state(dos);
            let mut handle = None;
            for i in 0..MAX_XMS_HANDLES {
                if xms.handles[i].is_none() {
                    handle = Some(i);
                    break;
                }
            }
            match handle {
                Some(i) => {
                    let size_bytes = size_kb as u32 * 1024;
                    match xms.find_free(size_bytes) {
                        Some(base) => {
                            xms.handles[i] = Some(XmsHandle {
                                base,
                                size_kb,
                                locked: false,
                            });
                            regs.rax = (regs.rax & !0xFFFF) | 1;
                            regs.rdx = (regs.rdx & !0xFFFF) | (i + 1) as u64;
                        }
                        None => {
                            regs.rax = regs.rax & !0xFFFF;
                            regs.rbx = (regs.rbx & !0xFF) | 0xA0;
                        }
                    }
                }
                None => {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA1;
                }
            }
        }
        // AH=0Ah — Free extended memory block (DX=handle)
        0x0A => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if xms.handles[handle as usize - 1].take().is_some() {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Bh — Move extended memory block (DS:SI = move struct)
        0x0B => {
            xms_move(dos, regs);
        }
        // AH=0Ch — Lock extended memory block (DX=handle)
        0x0C => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref mut h) = xms.handles[handle as usize - 1] {
                    h.locked = true;
                    let addr = h.base;
                    regs.rdx = (regs.rdx & !0xFFFF) | (addr >> 16) as u64;
                    regs.rbx = (regs.rbx & !0xFFFF) | (addr & 0xFFFF) as u64;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Dh — Unlock extended memory block (DX=handle)
        0x0D => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref mut h) = xms.handles[handle as usize - 1] {
                    h.locked = false;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Eh — Get EMB handle information (DX=handle)
        0x0E => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref h) = xms.handles[handle as usize - 1] {
                    let lock_count = if h.locked { 1u8 } else { 0 };
                    let free_handles = xms.handles.iter().filter(|h| h.is_none()).count() as u8;
                    // BH=lock count, BL=free handles
                    regs.rbx = (regs.rbx & !0xFFFF) | (lock_count as u64) << 8 | free_handles as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | h.size_kb as u64;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Fh — Reallocate extended memory block (DX=handle, BX=new size KB)
        // Simple: free old, alloc new (no data preservation — rare in practice)
        0x0F => {
            let handle = regs.rdx as u16;
            let new_kb = regs.rbx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if xms.handles[handle as usize - 1].is_some() {
                    let old = xms.handles[handle as usize - 1].take().unwrap();
                    let new_bytes = new_kb as u32 * 1024;
                    match xms.find_free(new_bytes) {
                        Some(base) => {
                            xms.handles[handle as usize - 1] = Some(XmsHandle {
                                base,
                                size_kb: new_kb,
                                locked: old.locked,
                            });
                            regs.rax = (regs.rax & !0xFFFF) | 1;
                        }
                        None => {
                            // Restore old handle
                            xms.handles[handle as usize - 1] = Some(old);
                            regs.rax = regs.rax & !0xFFFF;
                            regs.rbx = (regs.rbx & !0xFF) | 0xA0;
                        }
                    }
                } else {
                    regs.rax = regs.rax & !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=88h — Query free extended memory (32-bit, XMS 3.0)
        0x88 => {
            let xms = xms_state(dos);
            let free = xms.free_kb() as u32;
            regs.rax = (regs.rax & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFFFFFF) | (XMS_END - 1) as u64;
            regs.rbx = regs.rbx & !0xFFFF;
        }
        // AH=10h — Request Upper Memory Block (DX=size in paragraphs)
        0x10 => {
            let size = regs.rdx as u16;
            match umb_alloc(size) {
                Some((seg, paras)) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1; // success
                    regs.rbx = (regs.rbx & !0xFFFF) | seg as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | paras as u64;
                }
                None => {
                    let largest = umb_largest();
                    regs.rax = regs.rax & !0xFFFF; // failure
                    regs.rbx = (regs.rbx & !0xFF) | if largest > 0 { 0xB0 } else { 0xB1 };
                    regs.rdx = (regs.rdx & !0xFFFF) | largest as u64;
                }
            }
        }
        // AH=11h — Release Upper Memory Block (DX=segment)
        0x11 => {
            let seg = regs.rdx as u16;
            if umb_free(seg) {
                regs.rax = (regs.rax & !0xFFFF) | 1; // success
            } else {
                regs.rax = regs.rax & !0xFFFF; // failure
                regs.rbx = (regs.rbx & !0xFF) | 0xB2; // invalid UMB segment
            }
        }
        _ => {
            dos_trace!("XMS: UNHANDLED AH={:02X}", ah);
            regs.rax = regs.rax & !0xFFFF; // failure
            regs.rbx = (regs.rbx & !0xFF) | 0x80; // not implemented
        }
    }
    thread::KernelAction::Done
}

/// XMS function 0Bh: Move extended memory block.
/// DS:SI points to a move structure:
///   +00: u32 length (bytes)
///   +04: u16 source handle (0=conventional)
///   +06: u32 source offset (or seg:off if handle=0)
///   +0A: u16 dest handle (0=conventional)
///   +0C: u32 dest offset (or seg:off if handle=0)
fn xms_move(dos: &mut thread::DosState, regs: &mut Regs) {
    let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);

    let length = unsafe { (addr as *const u32).read_unaligned() } as usize;
    let src_handle = unsafe { ((addr + 4) as *const u16).read_unaligned() };
    let src_offset = unsafe { ((addr + 6) as *const u32).read_unaligned() };
    let dst_handle = unsafe { ((addr + 10) as *const u16).read_unaligned() };
    let dst_offset = unsafe { ((addr + 12) as *const u32).read_unaligned() };

    if length == 0 {
        regs.rax = (regs.rax & !0xFFFF) | 1;
        regs.rbx = regs.rbx & !0xFFFF;
        return;
    }

    // Resolve source to linear address
    let xms = xms_state(dos);
    let src = if src_handle == 0 {
        // Conventional memory: offset is seg:off packed as off(16):seg(16)
        let seg = (src_offset >> 16) as u32;
        let off = (src_offset & 0xFFFF) as u32;
        (seg << 4) + off
    } else {
        let idx = src_handle as usize - 1;
        match xms.handles.get(idx).and_then(|h| h.as_ref()) {
            Some(h) if (src_offset as usize) + length <= h.size_kb as usize * 1024 => {
                h.base + src_offset
            }
            _ => {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA3;
                return;
            }
        }
    };

    // Resolve dest to linear address
    let dst = if dst_handle == 0 {
        let seg = (dst_offset >> 16) as u32;
        let off = (dst_offset & 0xFFFF) as u32;
        (seg << 4) + off
    } else {
        let idx = dst_handle as usize - 1;
        match xms.handles.get(idx).and_then(|h| h.as_ref()) {
            Some(h) if (dst_offset as usize) + length <= h.size_kb as usize * 1024 => {
                h.base + dst_offset
            }
            _ => {
                regs.rax = regs.rax & !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA5;
                return;
            }
        }
    };

    unsafe {
        core::ptr::copy(src as *const u8, dst as *mut u8, length);
    }
    regs.rax = (regs.rax & !0xFFFF) | 1;
    regs.rbx = regs.rbx & !0xFFFF;
}
