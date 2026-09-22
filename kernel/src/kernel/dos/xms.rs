//! XMS 3.0 (Extended Memory Specification) emulation.
//!
//! Pure bookkeeping over the VM86 linear address space above the HMA.
//! Physical backing comes from the DOS personality's common committed
//! extended-memory pool.

use crate::Regs;
use crate::kernel::dos::linear;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering::Relaxed};
use crate::compact_dbg_println;
use crate::kernel::thread;

const MAX_XMS_HANDLES: usize = 16;
/// XMS address space begins at 0x120000. Pages 0x100-0x10F are
/// the HMA (permanently wrapped over page 0); 0x110-0x11F is a reserved gap left
/// from the former A20 shadow region. The common manager supplies the upper
/// bound and shared 32 MiB capacity.
const XMS_BASE: u32 = 0x120000;
/// Highest exclusive address representable by an ordinary real-mode far
/// pointer (FFFF:FFFF plus one).
const DIRECT_LIMIT: u32 = 0x10FFF0;

/// A single XMS handle — contiguous range in VM86 linear address space.
#[derive(Clone, Copy)]
struct XmsHandle {
    /// Zero-length handles deliberately own no common-manager range.
    base: Option<u32>,
    size_kb: u32,
    lock_count: u8,
}

fn handle_index(handle: u16) -> Option<usize> {
    handle.checked_sub(1).map(usize::from).filter(|&i| i < MAX_XMS_HANDLES)
}

fn free_handle_count(xms: &XmsState) -> usize {
    xms.handles.iter().filter(|h| h.is_none()).count()
}

fn allocate_emb<A: crate::Arch>(
    machine: &mut A,
    xms: &mut XmsState,
    memory: &mut super::memory::DosMemory,
    size_kb: u32,
) -> Result<u16, u8> {
    let slot = xms.handles.iter().position(Option::is_none).ok_or(0xA1)?;
    let base = if size_kb == 0 {
        None
    } else {
        let bytes = size_kb.checked_mul(1024).ok_or(0xA0)?;
        Some(memory.allocate(
            machine, super::memory::XMS_OWNER, bytes, 4096, XMS_BASE,
            super::memory::general_limit(),
        ).map_err(|_| 0xA0)?.base)
    };
    xms.handles[slot] = Some(XmsHandle { base, size_kb, lock_count: 0 });
    Ok((slot + 1) as u16)
}

fn resize_emb<A: crate::Arch>(
    machine: &mut A,
    xms: &mut XmsState,
    memory: &mut super::memory::DosMemory,
    handle: u16,
    size_kb: u32,
) -> Result<(), u8> {
    let slot = handle_index(handle).ok_or(0xA2)?;
    let old = xms.handles[slot].ok_or(0xA2)?;
    if old.lock_count != 0 { return Err(0xAB); }
    let base = match (old.base, size_kb) {
        (None, 0) => None,
        (None, _) => {
            let bytes = size_kb.checked_mul(1024).ok_or(0xA0)?;
            Some(memory.allocate(
                machine, super::memory::XMS_OWNER, bytes, 4096, XMS_BASE,
                super::memory::general_limit(),
            ).map_err(|_| 0xA0)?.base)
        }
        (Some(base), 0) => {
            memory.free(machine, super::memory::XMS_OWNER, base).map_err(|_| 0xA2)?;
            None
        }
        (Some(base), _) => {
            let bytes = size_kb.checked_mul(1024).ok_or(0xA0)?;
            Some(memory.resize(
                machine, super::memory::XMS_OWNER, base, bytes, 4096, XMS_BASE,
                super::memory::general_limit(),
            ).map_err(|_| 0xA0)?.base)
        }
    };
    xms.handles[slot] = Some(XmsHandle { base, size_kb, lock_count: 0 });
    Ok(())
}

/// Per-thread XMS driver state.
pub struct XmsState {
    report_limit_kb: u16,
    handles: [Option<XmsHandle>; MAX_XMS_HANDLES],
}

impl XmsState {
    fn new() -> Self {
        const NONE: Option<XmsHandle> = None;
        Self { report_limit_kb: u16::MAX, handles: [NONE; MAX_XMS_HANDLES] }
    }

}

fn xms_state<A: crate::Arch>(dos: &mut thread::DosState<A>) -> &mut XmsState {
    if dos.xms.is_none() {
        dos.xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    dos.xms.as_deref_mut().unwrap()
}

/// Aladdin compares AH=08 sizes as signed words; keep this opt-in per launch.
pub(super) fn set_report_limit<A: crate::Arch>(dos: &mut thread::DosState<A>, enabled: bool) {
    xms_state(dos).report_limit_kb = if enabled { i16::MAX as u16 } else { u16::MAX };
}

fn xms_parts<A: crate::Arch>(dos: &mut thread::DosState<A>)
    -> (&mut XmsState, &mut super::memory::DosMemory)
{
    if dos.xms.is_none() {
        dos.xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    (dos.xms.as_deref_mut().unwrap(), &mut dos.memory)
}

pub(crate) fn xms_dispatch<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — Get XMS version
        0x00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0300; // XMS 3.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // driver internal revision
            regs.rdx &= !0xFFFF;            // no HMA (A20 always wrapped)
        }
        // AH=01h/02h — Request/release HMA. RetroOS deliberately has no HMA:
        // its VM86 1MB boundary remains wrapped onto low memory.
        0x01 | 0x02 => {
            regs.rax &= !0xFFFF;
            regs.rbx = (regs.rbx & !0xFF) | 0x90; // HMA does not exist
        }
        // AH=03h/05h — Global/local Enable A20. The virtual gate cannot be
        // enabled, so report the specified A20 error instead of claiming a
        // state change while leaving the HMA alias in place.
        0x03 | 0x05 => {
            regs.rax &= !0xFFFF;
            regs.rbx = (regs.rbx & !0xFF) | 0x82;
        }
        // AH=04h/06h — Global/local Disable A20. It is already disabled.
        0x04 | 0x06 => {
            regs.rax = (regs.rax & !0xFFFF) | 1;
        }
        // AH=07h — Query A20 state: disabled, with no query error.
        0x07 => {
            regs.rax &= !0xFFFF;
        }
        // AH=08h — Query free extended memory
        0x08 => {
            let (xms, memory) = xms_parts(dos);
            let physical = memory.available_pages(machine).saturating_mul(4)
                .min(usize::from(xms.report_limit_kb)) as u16;
            let largest = (memory.largest_bytes(machine, XMS_BASE, super::memory::general_limit(), 4096) / 1024)
                .min(u32::from(physical)) as u16;
            let total = physical;
            regs.rax = (regs.rax & !0xFFFF) | largest as u64; // largest free block (KB)
            regs.rdx = (regs.rdx & !0xFFFF) | total as u64;   // total free (KB)
            if total == 0 { regs.rbx = (regs.rbx & !0xFF) | 0xA0; }
        }
        // AH=09h — Allocate extended memory block (DX=size in KB)
        0x09 => {
            let size_kb = regs.rdx as u16;
            let (xms, memory) = xms_parts(dos);
            match allocate_emb(machine, xms, memory, u32::from(size_kb)) {
                Ok(handle) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.rdx = (regs.rdx & !0xFFFF) | u64::from(handle);
                }
                Err(error) => {
                    regs.rax &= !0xFFFF;
                    regs.rdx &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
                }
            }
        }
        // AH=0Ah — Free extended memory block (DX=handle)
        0x0A => {
            let handle = regs.rdx as u16;
            let (xms, memory) = xms_parts(dos);
            let Some(slot) = handle_index(handle) else {
                regs.rax &= !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                return thread::KernelAction::Done;
            };
            match xms.handles[slot] {
                Some(block) if block.lock_count != 0 => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xAB;
                }
                Some(block) => {
                    if let Some(base) = block.base {
                        let _ = memory.free(machine, super::memory::XMS_OWNER, base);
                    }
                    xms.handles[slot] = None;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                }
                None => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            }
        }
        // AH=0Bh — Move extended memory block (DS:SI = move struct)
        0x0B => {
            xms_move(machine, dos, regs);
        }
        // AH=0Ch — Lock extended memory block (DX=handle)
        0x0C => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if let Some(slot) = handle_index(handle) {
                if let Some(ref mut h) = xms.handles[slot] {
                    if h.lock_count == u8::MAX {
                        regs.rax &= !0xFFFF;
                        regs.rbx = (regs.rbx & !0xFF) | 0xAC;
                        return thread::KernelAction::Done;
                    }
                    h.lock_count += 1;
                    let addr = h.base.unwrap_or(0);
                    regs.rdx = (regs.rdx & !0xFFFF) | (addr >> 16) as u64;
                    regs.rbx = (regs.rbx & !0xFFFF) | (addr & 0xFFFF) as u64;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax &= !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Dh — Unlock extended memory block (DX=handle)
        0x0D => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if let Some(slot) = handle_index(handle) {
                if let Some(ref mut h) = xms.handles[slot] {
                    if h.lock_count == 0 {
                        regs.rax &= !0xFFFF;
                        regs.rbx = (regs.rbx & !0xFF) | 0xAA;
                    } else {
                        h.lock_count -= 1;
                        regs.rax = (regs.rax & !0xFFFF) | 1;
                    }
                } else {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax &= !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Eh — Get EMB handle information (DX=handle)
        0x0E => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if let Some(slot) = handle_index(handle) {
                if let Some(ref h) = xms.handles[slot] {
                    let free_handles = free_handle_count(xms) as u8;
                    // BH=lock count, BL=free handles
                    regs.rbx = (regs.rbx & !0xFFFF) | (h.lock_count as u64) << 8 | free_handles as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | u64::from(h.size_kb as u16);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax &= !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Fh — Reallocate extended memory block (DX=handle, BX=new size KB).
        // The common manager preserves the old pages if relocation is needed.
        0x0F => {
            let handle = regs.rdx as u16;
            let new_kb = regs.rbx as u16;
            let (xms, memory) = xms_parts(dos);
            match resize_emb(machine, xms, memory, handle, u32::from(new_kb)) {
                Ok(()) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                }
                Err(error) => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
                }
            }
        }
        // AH=88h — Query free extended memory (32-bit, XMS 3.0)
        0x88 => {
            let (_xms, memory) = xms_parts(dos);
            let free = memory.available_pages(machine).saturating_mul(4)
                .min(u32::MAX as usize) as u32;
            let largest = (memory.largest_bytes(
                machine, XMS_BASE, super::memory::general_limit(), 4096,
            ) / 1024).min(free);
            regs.rax = (regs.rax & !0xFFFF_FFFF) | u64::from(largest);
            regs.rdx = (regs.rdx & !0xFFFF_FFFF) | u64::from(free);
            regs.rcx = (regs.rcx & !0xFFFF_FFFF)
                | u64::from(XMS_BASE + super::memory::client_bytes() - 1);
            regs.rbx = (regs.rbx & !0xFF) | if free == 0 { 0xA0 } else { 0 };
        }
        // AH=89h — Allocate Any Extended Memory (32-bit size in EDX).
        0x89 => {
            let size_kb = regs.rdx as u32;
            let (xms, memory) = xms_parts(dos);
            match allocate_emb(machine, xms, memory, size_kb) {
                Ok(handle) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.rdx = (regs.rdx & !0xFFFF) | u64::from(handle);
                }
                Err(error) => {
                    regs.rax &= !0xFFFF;
                    regs.rdx &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
                }
            }
        }
        // AH=8Eh — Get Extended EMB Handle Information.
        0x8E => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if let Some(h) = handle_index(handle).and_then(|slot| xms.handles[slot]) {
                regs.rax = (regs.rax & !0xFFFF) | 1;
                regs.rbx = (regs.rbx & !0xFFFF) | (u64::from(h.lock_count) << 8);
                regs.rcx = (regs.rcx & !0xFFFF) | free_handle_count(xms) as u64;
                regs.rdx = (regs.rdx & !0xFFFF_FFFF) | u64::from(h.size_kb);
            } else {
                regs.rax &= !0xFFFF;
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=8Fh — Reallocate Any Extended Memory (32-bit size in EBX).
        0x8F => {
            let handle = regs.rdx as u16;
            let size_kb = regs.rbx as u32;
            let (xms, memory) = xms_parts(dos);
            match resize_emb(machine, xms, memory, handle, size_kb) {
                Ok(()) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                }
                Err(error) => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
                }
            }
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
                    regs.rax &= !0xFFFF; // failure
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
                regs.rax &= !0xFFFF; // failure
                regs.rbx = (regs.rbx & !0xFF) | 0xB2; // invalid UMB segment
            }
        }
        // AH=12h — Reallocate Upper Memory Block.
        0x12 => {
            let segment = regs.rdx as u16;
            let paragraphs = regs.rbx as u16;
            match umb_resize(machine, segment, paragraphs) {
                Ok(_) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                }
                Err(0xB0) => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | 0xB0;
                    regs.rdx = (regs.rdx & !0xFFFF) | u64::from(umb_largest());
                }
                Err(error) => {
                    regs.rax &= !0xFFFF;
                    regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
                }
            }
        }
        _ => {
            dos_trace!("XMS: UNHANDLED AH={:02X}", ah);
            regs.rax &= !0xFFFF; // failure
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
fn xms_move<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    let addr = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32);

    let length = machine.read::<u32>((addr) as usize) as usize;
    let src_handle = machine.read::<u16>((addr + 4) as usize);
    let src_offset = machine.read::<u32>((addr + 6) as usize);
    let dst_handle = machine.read::<u16>((addr + 10) as usize);
    let dst_offset = machine.read::<u32>((addr + 12) as usize);

    if length & 1 != 0 {
        regs.rax &= !0xFFFF;
        regs.rbx = (regs.rbx & !0xFF) | 0xA7;
        return;
    }
    let length32 = match u32::try_from(length) {
        Ok(length) => length,
        Err(_) => {
            regs.rax &= !0xFFFF;
            regs.rbx = (regs.rbx & !0xFF) | 0xA7;
            return;
        }
    };

    let xms = xms_state(dos);
    let resolve = |handle: u16, offset: u32, bad_handle: u8, bad_offset: u8|
        -> Result<u32, u8>
    {
        if handle == 0 {
            // Intel DWORD notation: low word is offset, high word is segment.
            let segment = offset >> 16;
            let displacement = offset & 0xFFFF;
            let address = (segment << 4).checked_add(displacement).ok_or(bad_offset)?;
            let end = address.checked_add(length32).ok_or(bad_offset)?;
            if end > DIRECT_LIMIT { return Err(bad_offset); }
            return Ok(address);
        }
        let slot = handle_index(handle).ok_or(bad_handle)?;
        let block = xms.handles[slot].ok_or(bad_handle)?;
        let end = offset.checked_add(length32).ok_or(bad_offset)?;
        let bytes = block.size_kb.checked_mul(1024).ok_or(bad_offset)?;
        if end > bytes { return Err(bad_offset); }
        match block.base {
            Some(base) => base.checked_add(offset).ok_or(bad_offset),
            None if end == 0 => Ok(0),
            None => Err(bad_offset),
        }
    };
    let src = match resolve(src_handle, src_offset, 0xA3, 0xA4) {
        Ok(address) => address,
        Err(error) => {
            regs.rax &= !0xFFFF;
            regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
            return;
        }
    };
    let dst = match resolve(dst_handle, dst_offset, 0xA5, 0xA6) {
        Ok(address) => address,
        Err(error) => {
            regs.rax &= !0xFFFF;
            regs.rbx = (regs.rbx & !0xFF) | u64::from(error);
            return;
        }
    };

    let overlaps = src < dst.saturating_add(length32) && dst < src.saturating_add(length32);
    if overlaps && src >= dst {
        regs.rax &= !0xFFFF;
        regs.rbx = (regs.rbx & !0xFF) | 0xA8;
        return;
    }

    machine.copy_within(src as usize, dst as usize, length);
    regs.rax = (regs.rax & !0xFFFF) | 1;
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
/// Allocation length in 4 KiB pages, present only at each block's first page.
/// This prevents releasing one UMB from consuming a separately allocated
/// adjacent run in the bitmap.
static UMB_LEN: [AtomicU8; UMA_PAGES] = [const { AtomicU8::new(0) }; UMA_PAGES];

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
pub(super) fn scan_uma<A: crate::Arch>(machine: &mut A) {
    let mut free: u64 = 0;
    for i in 0..UMA_PAGES {
        let base = (UMA_BASE + i) * 0x1000;
        let first = machine.read::<u8>(base);
        let mut uniform = true;
        for j in 1..0x1000 {
            if machine.read::<u8>(base + j) != first { uniform = false; break; }
        }
        if uniform && (first == 0x00 || first == 0xFF) {
            free |= 1 << i;
        }
    }
    store64(&UMA_FREE_LO, &UMA_FREE_HI, free);
    store64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, 0);
    for length in &UMB_LEN { length.store(0, Relaxed); }

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
    compact_dbg_println!("UMA: EMS frame at {:05X}, UMB {}KB free", ems_base * 0x1000, umb_count * 4);
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
fn umb_alloc<A: crate::Arch>(machine: &mut A, paragraphs: u16) -> Option<(u16, u16)> {
    let pages_needed = ((paragraphs as usize) * 16).div_ceil(0x1000);
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
                UMB_LEN[run_start].store(pages_needed as u8, Relaxed);
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
fn umb_free<A: crate::Arch>(machine: &mut A, segment: u16) -> bool {
    let page = (segment / 0x100) as usize;
    if !(UMA_BASE..UMA_END).contains(&page) || segment as usize != page * 0x100 {
        return false;
    }
    let offset = page - UMA_BASE;
    let count = UMB_LEN[offset].swap(0, Relaxed) as usize;
    if count == 0 { return false; }
    let mask = ((1u64 << count) - 1) << offset;
    and64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, !mask);
    machine.unmap_range(page, count);
    true
}

/// Resize a UMB without moving its segment. The implementation may return a
/// page-rounded block; XMS explicitly returns the actual paragraph count.
fn umb_resize<A: crate::Arch>(machine: &mut A, segment: u16, paragraphs: u16)
    -> Result<u16, u8>
{
    let page = (segment / 0x100) as usize;
    if !(UMA_BASE..UMA_END).contains(&page) || segment as usize != page * 0x100 {
        return Err(0xB2);
    }
    let offset = page - UMA_BASE;
    let old_pages = UMB_LEN[offset].load(Relaxed) as usize;
    if old_pages == 0 { return Err(0xB2); }
    let new_pages = (usize::from(paragraphs) * 16).div_ceil(0x1000);
    if new_pages == 0 { return Err(0xB0); }
    if new_pages == old_pages { return Ok((new_pages as u16) * 0x100); }

    if new_pages < old_pages {
        let released = old_pages - new_pages;
        let released_offset = offset + new_pages;
        let mask = ((1u64 << released) - 1) << released_offset;
        and64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, !mask);
        UMB_LEN[offset].store(new_pages as u8, Relaxed);
        machine.unmap_range(UMA_BASE + released_offset, released);
        return Ok((new_pages as u16) * 0x100);
    }

    let growth = new_pages - old_pages;
    let growth_offset = offset + old_pages;
    if growth_offset + growth > UMA_PAGES { return Err(0xB0); }
    let mask = ((1u64 << growth) - 1) << growth_offset;
    if umb_avail() & mask != mask { return Err(0xB0); }
    or64(&UMB_ALLOC_LO, &UMB_ALLOC_HI, mask);
    UMB_LEN[offset].store(new_pages as u8, Relaxed);
    machine.unmap_range(UMA_BASE + growth_offset, growth);
    Ok((new_pages as u16) * 0x100)
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
