//! XMS 3.0 (Extended Memory Specification) emulation.
//!
//! Pure bookkeeping over the VM86 linear address space above the HMA.
//! Physical backing comes from the kernel's demand paging.

use arch_abi::Arch;
use arch_abi::GuestBytes;
use crate::kernel::dos::linear;
use crate::arch::Vcpu;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed};
use crate::dbg_println;
use crate::kernel::thread;
use crate::Regs;

const MAX_XMS_HANDLES: usize = 16;
/// XMS address space: linear 0x120000 to about 0x500000. Pages 0x100-0x10F are
/// the HMA (permanently wrapped over page 0); 0x110-0x11F is a reserved gap left
/// from the former A20 shadow region.
const XMS_BASE: u32 = 0x120000;
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
}

impl XmsState {
    fn new() -> Self {
        const NONE: Option<XmsHandle> = None;
        Self { handles: [NONE; MAX_XMS_HANDLES] }
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

pub(crate) fn xms_dispatch(machine: &mut crate::TheArch, dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — Get XMS version
        0x00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0300; // XMS 3.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // driver internal revision
            regs.rdx = regs.rdx & !0xFFFF;            // no HMA (A20 always wrapped)
        }
        // AH=03h–06h — A20 enable/disable (global + local). The gate is
        // permanently wrapped (see machine::new): a VM86 guest has no usable HMA
        // and can't reach >1 MB directly, so these are no-op successes — callers
        // that bracket XMS access with enable/disable just proceed.
        0x03 | 0x04 | 0x05 | 0x06 => {
            regs.rax = (regs.rax & !0xFFFF) | 1; // success
            regs.rbx = regs.rbx & !0xFFFF;       // BL=0 no error
        }
        // AH=07h — Query A20 state. Report "enabled" so an enable-then-verify
        // caller is satisfied; the physical wrap is invisible to XMS-API users.
        0x07 => {
            regs.rax = (regs.rax & !0xFFFF) | 1;
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
        // This implementation allocates a fresh block and does not preserve contents.
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
                            // Preserve the original handle when the new allocation fails.
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
            match umb_alloc(machine, size) {
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
            if umb_free(machine, seg) {
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
fn xms_move(dos: &mut thread::DosState, regs: &mut Vcpu) {
    let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);

    let length = regs.read::<u32>((addr) as usize) as usize;
    let src_handle = regs.read::<u16>(((addr + 4)) as usize);
    let src_offset = regs.read::<u32>(((addr + 6)) as usize);
    let dst_handle = regs.read::<u16>(((addr + 10)) as usize);
    let dst_offset = regs.read::<u32>(((addr + 12)) as usize);

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

    regs.copy_within(src as usize, dst as usize, length);
    regs.rax = (regs.rax & !0xFFFF) | 1;
    regs.rbx = regs.rbx & !0xFFFF;
}

// ── Upper Memory Area: page scan + UMB allocator ───────────────────────
// XMS 3.0 owns UMB allocation per the spec (AH=10/11/12). UMA is the
// physical address range (0xC0000-0xEFFFF) we parcel out from; the EMS
// submodule reads `EMS_BASE_PAGE` to know where its 64KB page frame sits.

/// UMA covers pages 0xC0-0xEF (192KB). Pages 0xF0-0xFF are always BIOS ROM.
const UMA_BASE: usize = 0xC0;
const UMA_END: usize = 0xF0;
const UMA_PAGES: usize = UMA_END - UMA_BASE; // 48

/// Bitmap of free pages in UMA (bit i = page UMA_BASE+i). 1=free, 0=ROM/reserved.
/// Set by `scan_uma()`, then EMS claims 16 pages, rest available for UMB.
// 48-bit page bitmaps. The bare-metal i686 target has no AtomicU64, so each
// is split across two AtomicU32 halves; the kernel is single-core, so the two
// halves are always updated together (see the load64/store64/and64/or64 pair
// helpers). 1=free (UMA_FREE) / 1=allocated (UMB_ALLOC).
static UMA_FREE_LO: AtomicU32 = AtomicU32::new(0);
static UMA_FREE_HI: AtomicU32 = AtomicU32::new(0);
static UMB_ALLOC_LO: AtomicU32 = AtomicU32::new(0);
static UMB_ALLOC_HI: AtomicU32 = AtomicU32::new(0);

fn load64(lo: &AtomicU32, hi: &AtomicU32) -> u64 {
    (hi.load(Relaxed) as u64) << 32 | lo.load(Relaxed) as u64
}
fn store64(lo: &AtomicU32, hi: &AtomicU32, v: u64) {
    lo.store(v as u32, Relaxed); hi.store((v >> 32) as u32, Relaxed);
}
fn and64(lo: &AtomicU32, hi: &AtomicU32, m: u64) {
    lo.fetch_and(m as u32, Relaxed); hi.fetch_and((m >> 32) as u32, Relaxed);
}
fn or64(lo: &AtomicU32, hi: &AtomicU32, m: u64) {
    lo.fetch_or(m as u32, Relaxed); hi.fetch_or((m >> 32) as u32, Relaxed);
}

/// EMS page frame base page (set by `scan_uma`); read by `ems` submodule.
pub(super) static EMS_BASE_PAGE: AtomicUsize = AtomicUsize::new(0xD0);

/// Scan UMA to find free pages. A page is "free" if all bytes are 0x00 or 0xFF.
pub(super) fn scan_uma(regs: &Vcpu) {
    let mut free: u64 = 0;
    for i in 0..UMA_PAGES {
        let base = (UMA_BASE + i) * 0x1000;
        let first = regs.read::<u8>(base);
        let mut uniform = true;
        for j in 1..0x1000 {
            if regs.read::<u8>(base + j) != first { uniform = false; break; }
        }
        if uniform && (first == 0x00 || first == 0xFF) {
            free |= 1 << i;
        }
    }
    store64(&UMA_FREE_LO, &UMA_FREE_HI, free);

    // Find 16 contiguous free pages for the EMS page frame (64KB).
    // Prefer 0xD000 (standard EMS frame address).
    if let Some(off) = find_contiguous_run(free, 16, 0xD0 - UMA_BASE) {
        EMS_BASE_PAGE.store(UMA_BASE + off, Relaxed);
        let mask = ((1u64 << 16) - 1) << off;
        and64(&UMA_FREE_LO, &UMA_FREE_HI, !mask);
    }

    let umb_free = load64(&UMA_FREE_LO, &UMA_FREE_HI);
    let ems_base = EMS_BASE_PAGE.load(Relaxed);
    let mut umb_count = 0u32;
    let mut t = umb_free;
    while t != 0 { umb_count += 1; t &= t - 1; }
    dbg_println!("UMA: EMS frame at {:05X}, UMB {}KB free", ems_base * 0x1000, umb_count * 4);
}

/// Find `count` contiguous set bits in `bitmap`, preferring `hint` offset.
fn find_contiguous_run(bitmap: u64, count: usize, hint: usize) -> Option<usize> {
    if hint + count <= UMA_PAGES {
        let mask = ((1u64 << count) - 1) << hint;
        if bitmap & mask == mask { return Some(hint); }
    }
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if bitmap & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= count { return Some(run_start); }
        } else {
            run_len = 0;
        }
    }
    None
}

fn umb_avail() -> u64 {
    load64(&UMA_FREE_LO, &UMA_FREE_HI) & !load64(&UMB_ALLOC_LO, &UMB_ALLOC_HI)
}

/// Allocate a UMB of at least `paragraphs` size (1 paragraph = 16 bytes).
/// Returns (segment, paragraphs_allocated) or None.
fn umb_alloc(machine: &mut crate::TheArch, paragraphs: u16) -> Option<(u16, u16)> {
    let pages_needed = ((paragraphs as usize) * 16 + 0xFFF) / 0x1000;
    if pages_needed == 0 { return None; }

    let avail = umb_avail();
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= pages_needed {
                let mut alloc_mask = 0u64;
                for j in run_start..run_start + pages_needed {
                    alloc_mask |= 1 << j;
                }
                or64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, alloc_mask);
                let base_page = UMA_BASE + run_start;
                machine.unmap_range(base_page, pages_needed);
                let seg = (base_page as u16) * 0x100;
                let paras = (pages_needed as u16) * 0x100;
                return Some((seg, paras));
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Free a UMB by segment address.
fn umb_free(machine: &mut crate::TheArch, segment: u16) -> bool {
    let page = (segment / 0x100) as usize;
    if page < UMA_BASE || page >= UMA_END { return false; }
    let offset = page - UMA_BASE;

    let alloc = load64(&UMB_ALLOC_LO, &UMB_ALLOC_HI);
    if alloc & (1 << offset) == 0 { return false; }

    let mut mask = 0u64;
    let mut i = offset;
    while i < UMA_PAGES && alloc & (1 << i) != 0 {
        mask |= 1 << i;
        i += 1;
    }
    let count = (i - offset) as usize;
    and64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, !mask);
    machine.free_range(page, count);
    true
}

/// Largest free UMB in paragraphs.
fn umb_largest() -> u16 {
    let avail = umb_avail();
    let mut largest = 0usize;
    let mut run = 0usize;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            run += 1;
            if run > largest { largest = run; }
        } else {
            run = 0;
        }
    }
    (largest as u16) * 0x100
}
