//! DOS/DPMI personality — MS-DOS compatible execution environment with a
//! DPMI 0.9 host layered on top.
//!
//! Built on top of the `machine` layer which owns the virtual 8259/8253/8042
//! and VGA register set, and `arch::monitor` which decodes #GP-faulting
//! sensitive instructions. This module provides the DOS half of the
//! personality directly:
//! - `handle_vm86_int` — called from the event loop on a VM86 `SoftInt`
//! - INT 21h (DOS services), INT 10h/13h/16h/1Ah (BIOS), INT 2Fh (multiplex)
//! - XMS 3.0 / EMS 4.0 / UMB memory services
//! - .COM and MZ .EXE program loaders, EXEC chain (fork/exec parent tracking)
//! - PSP, SFT, CDS, LOL real-mode structures; FindFirst/FindNext state
//!
//! The DPMI extender (submodule `dpmi`) owns the PM half: LDT/descriptor
//! management, PM GP-fault decode, INT 31h, exception/soft-INT reflection,
//! real-mode callbacks, and locked memory handles. PM→RM INT translation in
//! `dpmi::dpmi_soft_int` reflects down into the DOS handlers here.
//!
//! The BIOS ROM at 0xF0000-0xFFFFF and the BIOS IVT at 0x0000-0x03FF are
//! preserved from the original hardware state (via COW page 0). BIOS handlers
//! work transparently because their I/O instructions trap through the TSS IOPB
//! to our virtual devices in the `machine` module.

extern crate alloc;

/// Trace DOS/DPMI calls when enabled.
/// Compile-time master kill switch; constant-fold removes all trace calls
/// when false.
pub(crate) const DOS_TRACE: bool = true;
pub(crate) const DOS_TRACE_HW_IRG: bool = false;

/// Runtime trace gate, toggled by INT 31h synth AH=02 (on) / AH=03 (off).
/// Lets COMMAND.COM bracket a single exec so the log only captures that
/// child program, not surrounding shell/launcher noise. Default OFF so
/// boot/init/DN startup are silent until something explicitly enables it.
pub(crate) static DOS_TRACE_RT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Independent gate for hardware-IRQ-vector trace lines (timer 0x08, key 0x09,
/// etc). Default OFF so a noisy timer tick doesn't drown the per-call DPMI
/// trace. Toggled by INT 31h synth AH=04 (on) / AH=05 (off). Both gates
/// (general + HW) must be ON for an HW-vector trace to fire.
pub(crate) static DOS_TRACE_HW_RT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Single-step tracing budget. Armed by specific DPMI handlers to watch the
/// client's code path right after a suspicious return. Decremented on each
/// PM `#DB`; at zero, tracing stops and TF is cleared.
pub(crate) static PM_STEP_BUDGET: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Log one PM step: CS:EIP + key regs, plus the first few opcode bytes.
pub(crate) fn pm_step_log(regs: &crate::Regs) {
    let cs_base = crate::arch::monitor::seg_base(regs.code_seg());
    let lin = cs_base.wrapping_add(regs.ip32());
    let mut b = [0u8; 8];
    for i in 0..8 {
        b[i] = unsafe { core::ptr::read_volatile((lin + i as u32) as *const u8) };
    }
    crate::dbg_println!(
        "[STEP] {:04X}:{:08X} op={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} EAX={:08X} EBX={:08X} ECX={:08X} EDX={:08X} ESI={:08X} EDI={:08X} EBP={:08X} SS:SP={:04X}:{:08X} DS={:04X} ES={:04X}",
        regs.code_seg(), regs.ip32(),
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
        regs.rsi as u32, regs.rdi as u32, regs.rbp as u32,
        regs.frame.ss as u16, regs.sp32(),
        regs.ds as u16, regs.es as u16,
    );
}

/// Returns true if a trace line tied to interrupt vector `vec` should fire.
/// Combines the general gate with the HW-vector gate so an HW-IRQ-noisy site
/// can wrap its `dos_trace!` in a single check.
#[inline]
pub(crate) fn should_trace() -> bool {
    // TEMP: silenced to keep the DPMI log compact for diffing against CWSDPMI.
    // Use `dos_trace!(force ...)` to bypass this gate.
    true
}

macro_rules! dos_trace {
    (force $($arg:tt)*) => {
        if crate::kernel::dos::DOS_TRACE_HW_RT.load(core::sync::atomic::Ordering::Relaxed) {
            $crate::dbg_println!($($arg)*);
        }
    };
    ($($arg:tt)*) => {
        if crate::kernel::dos::should_trace() {
            $crate::dbg_println!($($arg)*);
        }
    };
}
pub(crate) use dos_trace;

pub mod dpmi;
pub mod dfs;

use crate::kernel::thread;
use crate::kernel::machine::{
    self,
    IF_FLAG,
    read_u16, write_u16,
    vm86_cs, vm86_ip, vm86_ss, vm86_sp, vm86_flags,
    set_vm86_cs, set_vm86_ip,
    vm86_push, vm86_pop,
    reflect_interrupt, clear_bios_keyboard_buffer, pop_bios_keyboard_word,
};
use crate::vga;
use crate::dbg_println;
use crate::Regs;

const EMS_ENABLED: bool = true;

/// Dummy file handle returned for /dev/null semantics.
const NULL_FILE_HANDLE: u16 = 99;

/// DOS-specific thread state: virtual hardware machine + DOS personality + optional DPMI.
///
/// Split into three logical groups:
///   - `pc`: PC machine virtualization (policy-free peripherals — vpic/vpit/vkbd/vga,
///     A20 gate, HMA pages, skip_irq latch, e0 scancode-prefix latch). Shared by
///     both the DOS personality and DPMI.
///   - DOS personality fields (flattened): PSP tracking, DTA, heap/free segment,
///     XMS/EMS state, FindFirst/FindNext state, exec-parent chain.
///   - `dpmi`: optional DPMI protected-mode state (LDT, memory blocks, callbacks).
pub struct DosState {
    /// Policy-free PC machine state: virtual 8259 PIC, 8253 PIT, PS/2 keyboard,
    /// VGA register set, A20 gate, HMA page tracking.
    pub pc: crate::kernel::machine::PcMachine,

    // ── DOS personality fields ────────────────────────────────────────
    pub dta: u32,
    pub heap_seg: u16,
    pub heap_base_seg: u16,
    pub alloc_strategy: u16,
    pub umb_link_state: u16,
    /// Current PSP segment as seen by INT 21h/AH=50h (set), 51h (get), 62h (get).
    pub current_psp: u16,
    pub dos_pending_char: Option<u8>,
    /// Last child termination status (INT 21h/AH=4Dh): AL = code, AH = type.
    pub last_child_exit_status: u16,
    pub exec_parent: Option<crate::kernel::dos::ExecParent>,
    pub xms: Option<alloc::boxed::Box<crate::kernel::dos::XmsState>>,
    pub ems: Option<alloc::boxed::Box<crate::kernel::dos::EmsState>>,
    /// FindFirst/FindNext search state (per-thread, one active enumeration).
    pub find_path: [u8; 96],
    pub find_path_len: u8,
    pub find_idx: u16,

    /// DOS File System wrapper — sole DOS↔VFS translator.
    /// Tracks cwd in DOS form (uppercase, backslashes, no drive/root).
    pub dfs: dfs::DfsState,
    pub dos_blocks: alloc::vec::Vec<DosMemBlock>,

    pub dpmi: Option<alloc::boxed::Box<crate::kernel::dos::dpmi::DpmiState>>,
}

#[derive(Clone, Copy)]
pub struct DosMemBlock {
    pub seg: u16,
    pub paras: u16,
}

impl DosState {
    pub fn new() -> Self {
        DosState {
            pc: crate::kernel::machine::PcMachine::new(),
            dta: 0,
            heap_seg: 0xA000,
            heap_base_seg: 0xA000,
            alloc_strategy: 0,
            umb_link_state: 0,
            current_psp: crate::kernel::dos::PSP_SEGMENT,
            dos_pending_char: None,
            last_child_exit_status: 0,
            exec_parent: None,
            xms: None,
            ems: None,
            find_path: [0; 96],
            find_path_len: 0,
            find_idx: 0,
            dfs: dfs::DfsState::new(),
            dos_blocks: alloc::vec::Vec::new(),
            dpmi: None,
        }
    }

    /// Process a raw PS/2 scancode — queue as virtual keyboard IRQ.
    pub fn process_key(&mut self, scancode: u8) {
        crate::kernel::machine::queue_irq(&mut self.pc, crate::arch::Irq::Key(scancode));
    }
}

fn next_dos_block_limit(dos: &DosState, seg: u16, skip_seg: Option<u16>) -> u16 {
    let mut limit = 0xA000u16;
    for block in &dos.dos_blocks {
        if Some(block.seg) == skip_seg || block.seg < seg {
            continue;
        }
        if block.seg < limit {
            limit = block.seg;
        }
    }
    limit
}

fn sync_heap_seg(dos: &mut DosState) {
    let mut first_free = dos.heap_base_seg;
    loop {
        let mut advanced = false;
        for block in &dos.dos_blocks {
            if block.seg == first_free {
                first_free = block.seg.saturating_add(block.paras);
                advanced = true;
                break;
            }
        }
        if !advanced {
            break;
        }
    }
    dos.heap_seg = first_free.min(0xA000);
}

fn largest_dos_block(dos: &DosState) -> u16 {
    let mut largest = 0u16;
    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);
    for block in blocks {
        if block.seg > cur {
            largest = largest.max(block.seg - cur);
        }
        let end = block.seg.saturating_add(block.paras);
        if end > cur {
            cur = end;
        }
    }
    largest.max(0xA000u16.saturating_sub(cur))
}

pub(crate) fn dos_reset_blocks(dos: &mut DosState, base_seg: u16) {
    dos.heap_base_seg = base_seg;
    dos.heap_seg = base_seg;
    dos.dos_blocks.clear();
}

pub(crate) fn dos_alloc_block(dos: &mut DosState, need: u16) -> Result<u16, u16> {
    let mut cur = dos.heap_base_seg;
    let mut blocks = dos.dos_blocks.clone();
    blocks.sort_by_key(|b| b.seg);

    for block in blocks {
        if block.seg > cur {
            let gap = block.seg - cur;
            if need <= gap {
                if need != 0 {
                    dos.dos_blocks.push(DosMemBlock { seg: cur, paras: need });
                }
                sync_heap_seg(dos);
                return Ok(cur);
            }
        }
        let end = block.seg.saturating_add(block.paras);
        if end > cur {
            cur = end;
        }
    }

    let avail = 0xA000u16.saturating_sub(cur);
    if need <= avail {
        if need != 0 {
            dos.dos_blocks.push(DosMemBlock { seg: cur, paras: need });
        }
        sync_heap_seg(dos);
        Ok(cur)
    } else {
        Err(largest_dos_block(dos))
    }
}

pub(crate) fn dos_free_block(dos: &mut DosState, seg: u16) -> Result<(), u16> {
    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        dos.dos_blocks.remove(idx);
        sync_heap_seg(dos);
        Ok(())
    } else {
        Err(9)
    }
}

pub(crate) fn dos_resize_block(dos: &mut DosState, seg: u16, paras: u16) -> Result<(), (u16, u16)> {
    if seg == dos.current_psp {
        let max = next_dos_block_limit(dos, seg, None).saturating_sub(seg);
        if paras <= max {
            dos.heap_base_seg = seg.saturating_add(paras);
            sync_heap_seg(dos);
            return Ok(());
        }
        return Err((8, max));
    }

    if let Some(idx) = dos.dos_blocks.iter().position(|b| b.seg == seg) {
        let max = next_dos_block_limit(dos, seg, Some(seg)).saturating_sub(seg);
        if paras <= max {
            dos.dos_blocks[idx].paras = paras;
            sync_heap_seg(dos);
            Ok(())
        } else {
            Err((8, max))
        }
    } else {
        Err((9, 0))
    }
}

/// Translate a `seg:off` client pointer to a flat linear address.
///
/// In V86 mode `seg` is a real-mode paragraph and `off` is masked to 16 bits.
/// In protected mode `seg` is an LDT/GDT selector and we resolve the descriptor
/// base via the DPMI state. Offset width follows the client CS D/B bit.
#[inline]
fn linear(dos: &thread::DosState, regs: &Regs, seg: u16, off: u32) -> u32 {
    if regs.frame.rflags as u32 & machine::VM_FLAG != 0 {
        ((seg as u32) << 4).wrapping_add(off & 0xFFFF)
    } else if let Some(dpmi) = dos.dpmi.as_ref() {
        let cs_32 = dpmi::seg_is_32(dpmi, regs.frame.cs as u16);
        let off = if cs_32 { off } else { off & 0xFFFF };
        dpmi::seg_base(dpmi, seg).wrapping_add(off)
    } else {
        ((seg as u32) << 4).wrapping_add(off & 0xFFFF)
    }
}

/// PSP segment for the initial DOS program — derived from low-memory layout
/// end so the environment block at `PSP_SEGMENT-0x10` (256 bytes) never
/// overlaps kernel structures. The .COM/.EXE load module begins at
/// `PSP_SEGMENT+0x10` (256 bytes past the PSP). For .COM programs DOS sets
/// CS=DS=ES=SS=PSP_SEGMENT, IP=0x100.
pub const PSP_SEGMENT: u16 = (((IRQ_STACK_ADDR + IRQ_STACK_SIZE) + 0xF) >> 4) as u16 + 0x10;
/// .COM entry IP (relative to its PSP segment). Equivalent to `(psp+0x10):0000`.
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer for .COM (top of PSP's 64KB segment)
const COM_SP: u16 = 0xFFFE;

fn poll_dos_console_char(dos: &mut thread::DosState) -> Option<u8> {
    if let Some(ch) = dos.dos_pending_char.take() {
        return Some(ch);
    }

    let word = pop_bios_keyboard_word()?;
    let ascii = word as u8;
    let scan = (word >> 8) as u8;
    if ascii == 0 && scan != 0 {
        dos.dos_pending_char = Some(scan);
    }
    Some(ascii)
}

// ============================================================================
// XMS (Extended Memory Specification) state
// ============================================================================

const MAX_XMS_HANDLES: usize = 16;
/// XMS address space: linear 0x120000 (after HMA + shadow region) to ~0x500000.
/// Pages 0x100-0x10F = HMA, 0x110-0x11F = A20 shadow. XMS starts after both.
const XMS_BASE: u32 = 0x120000; // after HMA + shadow (1MB + 128KB)
const XMS_END: u32 = 0x500000;  // 5MB — plenty for DOS games

/// EMS backing region: virtual address space for EMS logical pages.
/// Each EMS page = 16KB = 4 virtual pages. Demand paging provides backing.
const EMS_BACKING_BASE: u32 = 0x500000;
/// Virtual page number for EMS logical page N = EMS_BACKING_VPAGE + N * 4
const EMS_BACKING_VPAGE: usize = (EMS_BACKING_BASE / 0x1000) as usize;
const XMS_TOTAL_KB: u16 = ((XMS_END - XMS_BASE) / 1024) as u16;

/// A single XMS handle — contiguous range in VM86 linear address space
struct XmsHandle {
    base: u32,    // linear address
    size_kb: u16,
    locked: bool,
}

/// Per-thread XMS driver state.
/// Pure bookkeeping over the VM86 linear address space above HMA.
/// Physical backing is provided by the kernel's demand paging.
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

// ============================================================================
// UMA (Upper Memory Area) scan and UMB allocation
// ============================================================================

/// UMA covers pages 0xC0-0xEF (192KB). Pages 0xF0-0xFF are always BIOS ROM.
const UMA_BASE: usize = 0xC0;
const UMA_END: usize = 0xF0;
const UMA_PAGES: usize = UMA_END - UMA_BASE; // 48

/// Bitmap of free pages in UMA (bit i = page UMA_BASE+i). 1=free, 0=ROM/reserved.
/// Set by scan_uma(), then EMS claims 16 pages, rest available for UMB.
static mut UMA_FREE: u64 = 0;

/// Bitmap of UMB-allocated pages (subset of UMA_FREE). 1=allocated by UMB, 0=free.
static mut UMB_ALLOC: u64 = 0;

/// Bitmap of pages reserved for EMS (16 pages for 64KB page frame).
#[allow(dead_code)]
static mut EMS_PAGES: u64 = 0;

/// EMS page frame base page (set by scan_uma)
static mut EMS_BASE_PAGE: usize = 0xD0;

/// Scan UMA to find free pages. A page is "free" if all bytes are 0x00 or 0xFF.
pub fn scan_uma() {
    let mut free: u64 = 0;
    for i in 0..UMA_PAGES {
        let base = ((UMA_BASE + i) * 0x1000) as *const u8;
        let first = unsafe { *base };
        let mut uniform = true;
        for j in 1..0x1000 {
            if unsafe { *base.add(j) } != first { uniform = false; break; }
        }
        if uniform && (first == 0x00 || first == 0xFF) {
            free |= 1 << i;
        }
    }
    unsafe { UMA_FREE = free; }

    // Find 16 contiguous free pages for the EMS page frame (64KB).
    // Prefer 0xD000 (standard EMS frame address).
    if let Some(off) = find_contiguous_run(free, 16, 0xD0 - UMA_BASE) {
        unsafe { EMS_BASE_PAGE = UMA_BASE + off; }
        // Reserve EMS frame pages from UMB allocation
        let mask = ((1u64 << 16) - 1) << off;
        unsafe { UMA_FREE &= !mask; }
    }

    // Log results
    let umb_free = unsafe { UMA_FREE };
    let ems_base = unsafe { EMS_BASE_PAGE };
    let mut umb_count = 0u32;
    let mut t = umb_free;
    while t != 0 { umb_count += 1; t &= t - 1; }
    dbg_println!("UMA: EMS frame at {:05X}, UMB {}KB free", ems_base * 0x1000, umb_count * 4);
}

/// Find `count` contiguous set bits in `bitmap`, preferring `hint` offset.
fn find_contiguous_run(bitmap: u64, count: usize, hint: usize) -> Option<usize> {
    // Try starting at hint first
    if hint + count <= UMA_PAGES {
        let mask = ((1u64 << count) - 1) << hint;
        if bitmap & mask == mask { return Some(hint); }
    }
    // Scan from start
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

/// Get UMB-available bitmap (free pages minus EMS minus already allocated)
fn umb_avail() -> u64 {
    unsafe { UMA_FREE & !UMB_ALLOC }
}

/// Allocate a UMB of at least `paragraphs` size (1 paragraph = 16 bytes).
/// Returns (segment, paragraphs_allocated) or None.
fn umb_alloc(paragraphs: u16) -> Option<(u16, u16)> {
    let pages_needed = ((paragraphs as usize) * 16 + 0xFFF) / 0x1000;
    if pages_needed == 0 { return None; }

    let avail = umb_avail();
    // First-fit contiguous run
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
                unsafe { UMB_ALLOC |= alloc_mask; }
                let base_page = UMA_BASE + run_start;
                crate::kernel::startup::arch_unmap_range(base_page, pages_needed);
                let seg = (base_page as u16) * 0x100; // page to segment
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
fn umb_free(segment: u16) -> bool {
    let page = (segment / 0x100) as usize;
    if page < UMA_BASE || page >= UMA_END { return false; }
    let offset = page - UMA_BASE;

    let alloc = unsafe { UMB_ALLOC };
    if alloc & (1 << offset) == 0 { return false; }

    // Free contiguous run starting at offset
    let mut mask = 0u64;
    let mut i = offset;
    while i < UMA_PAGES && alloc & (1 << i) != 0 {
        mask |= 1 << i;
        i += 1;
    }
    let count = (i - offset) as usize;
    unsafe { UMB_ALLOC &= !mask; }
    crate::kernel::startup::arch_free_range(page, count);
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

// ============================================================================
// EMS (Expanded Memory Specification) state
// ============================================================================

const MAX_EMS_HANDLES: usize = 16;
/// Total EMS pages available (256 × 16KB = 4MB)
const EMS_TOTAL_PAGES: u16 = 256;
/// EMS page frame segment — set dynamically by scan_uma()
pub fn ems_frame_seg() -> u16 {
    (unsafe { EMS_BASE_PAGE } as u16) * 0x100
}

fn ems_base_page() -> usize {
    unsafe { EMS_BASE_PAGE }
}

/// Swap an EMS window with a backing region.
fn swap_ems_window(window: usize, backing_vpage: usize) {
    let frame = ems_base_page() + window * 4;
    crate::kernel::startup::arch_swap_page_entries(backing_vpage, frame, 4);
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



// ============================================================================
// INT dispatch — intercept DOS/BIOS calls, reflect others via IVT
// ============================================================================

/// Handle INT n from VM86 mode.
/// With VME, only INTs whose bit is SET in the redirection bitmap trap here.
/// Without VME, all INTs trap — unintercepted ones are reflected through IVT.
pub fn handle_vm86_int(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs, int_num: u8) -> thread::KernelAction {
    if !crate::arch::int_intercepted(int_num) {
        reflect_interrupt(regs, int_num);
        return thread::KernelAction::Done;
    }
    match int_num {
        STUB_INT => stub_dispatch(kt, dos, regs),
        _ => {
            panic!("VM86: INT {:02X} intercepted in bitmap but has no handler", int_num);
        }
    }
}

// ============================================================================
// Stub dispatch — routes INT 31h from unified CD 31 array by slot number
// ============================================================================

/// Dispatch a kernel-owned DOS/BIOS vector directly (no V86 detour).
///
/// Used by both the V86 stub dispatcher and the DPMI PM soft-int fast path.
/// The caller is responsible for any mode-specific frame housekeeping after
/// the call (V86 stack pop, PM return-frame restore, etc.).
pub(crate) fn dispatch_kernel_syscall(
    kt: &mut thread::KernelThread,
    dos: &mut thread::DosState,
    regs: &mut Regs,
    vector: u8,
) -> thread::KernelAction {
    match vector {
        0x08 => thread::KernelAction::Done, // timer — handled via VM86 IRQ reflect path
        0x13 => int_13h(regs),
        0x20 => {
            if let Some(parent) = dos.exec_parent.take() {
                dos.last_child_exit_status = 0x0000;
                return exec_return(dos, regs, parent);
            }
            thread::KernelAction::Exit(0)
        }
        0x21 => int_21h(kt, dos, regs),
        // INT 25h/26h — Absolute Disk Read/Write — return error
        0x25 | 0x26 => {
            regs.rax = (regs.rax & !0xFF00) | (0x02 << 8); // AH=02 address mark not found
            regs.set_flag32(1); // CF=1 error
            thread::KernelAction::Done
        }
        0x28 => thread::KernelAction::Done, // INT 28h — DOS idle
        0x2E => int_2eh(kt, dos, regs),
        0x2F => int_2fh(dos, regs),
        0x67 => int_67h(dos, regs),
        _ => {
            dos_trace!("dispatch_kernel_syscall: unhandled vector {:#04x}", vector);
            thread::KernelAction::Done
        }
    }
}

/// Dispatch INT 31h from the unified stub array. Slot = (IP - 2) / 2.
/// IVT-redirect stubs have a FLAGS/CS/IP frame on the VM86 stack from the
/// original INT; far-call stubs have a CS/IP frame from CALL FAR.
/// The kernel pops these frames directly — no RETF/RETF 2 in the stub.
fn stub_dispatch(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    let cs = vm86_cs(regs);

    // INT 31h from user code (outside the stub segment) = synth syscall.
    // AH selects the subfunction. Unknown subfunctions fall through to IVT reflect.
    if cs != STUB_SEG {
        return synth_dispatch(kt, dos, regs);
    }

    let slot = ((ip.wrapping_sub(2)) / 2) as u8;
    let is_far_call = matches!(slot,
        SLOT_XMS | SLOT_DPMI_ENTRY | SLOT_CALLBACK_RET | SLOT_RM_INT_RET
        | SLOT_RAW_REAL_TO_PM | SLOT_SAVE_RESTORE)
        || (slot >= SLOT_CB_ENTRY_BASE && slot < SLOT_CB_ENTRY_END);

    let action = match slot {
        SLOT_XMS => xms_dispatch(dos, regs),
        SLOT_DPMI_ENTRY => {
            dpmi::dpmi_enter(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CALLBACK_RET => {
            dpmi::callback_return(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RM_INT_RET => {
            // Implicit INT reflection (no PM handler installed). Same
            // unwind as a callback, then synthesize the STI that DPMI
            // requires IRQ handlers to perform before IRET — our default
            // stub is the nominal handler here.
            dpmi::callback_return(dos, regs);
            regs.frame.rflags |= crate::kernel::machine::IF_FLAG as u64;
            DOS_TRACE_HW_RT.store(true, core::sync::atomic::Ordering::Relaxed);
            thread::KernelAction::Done
        }
        SLOT_RAW_REAL_TO_PM => {
            dpmi::raw_switch_real_to_pm(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CB_ENTRY_BASE..SLOT_CB_ENTRY_END => {
            let cb_idx = (slot - SLOT_CB_ENTRY_BASE) as usize;
            dpmi::callback_entry(dos, regs, cb_idx);
            thread::KernelAction::Done
        }
        SLOT_HW_IRQ_BASE..SLOT_HW_IRQ_END => {
            // Hardware IRQ N: chain to BIOS handler on private stack.
            // Reflect frame (FLAGS/CS/IP) stays on current stack — BIOS IRET pops it.
            hw_irq_reflect(dos, regs, slot - SLOT_HW_IRQ_BASE);
            return thread::KernelAction::Done;
        }
        0x13 | 0x20 | 0x21 | 0x25 | 0x26 | 0x28 | 0x2E | 0x2F | 0x67 => {
            // Restore caller FLAGS into regs so handlers may mutate them
            // (CF/ZF returns); then write back so normal IRET-style pop
            // restores the handler's result to the caller.
            let caller_flags = read_u16(vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4));
            crate::kernel::machine::set_vm86_flags(regs, caller_flags as u32);
            let action = dispatch_kernel_syscall(kt, dos, regs, slot);
            // exec_return / Exit replace thread state — skip the VM86 frame pop below.
            if !matches!(action, thread::KernelAction::Done) {
                return action;
            }
            write_u16(vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4),
                      crate::kernel::machine::vm86_flags(regs) as u16);
            action
        }
        SLOT_HW_IRQ_RET => {
            // BIOS handler IRET'd to trampoline. Restore original SS:SP;
            // the common pop below IRETs the reflect frame back to the
            // interrupted code (including its flags).
            let (ss, sp) = dos.pc.irq_saved_sssp.take().expect("HW_IRQ_RET without saved SS:SP");
            crate::kernel::machine::set_vm86_ss(regs, ss);
            crate::kernel::machine::set_vm86_sp(regs, sp);
            thread::KernelAction::Done
        }
        SLOT_SAVE_RESTORE => {
            dpmi::save_restore_protected_mode_state(dos, regs);
            thread::KernelAction::Done
        }
        _ => {
            panic!("VM86: INT 31h unknown stub slot {:#04x} CS:IP={:04x}:{:#06x}", slot, cs, ip);
        }
    };

    // Pop the VM86 stack frame left by the caller before returning.
    // IVT-redirect: original INT pushed FLAGS/CS/IP (6 bytes) — pop and return to caller.
    // Far-call (XMS): CALL FAR pushed CS/IP (4 bytes) — pop and return to caller.
    // Mode-switching stubs (DPMI entry, raw switch, callbacks) replace all regs — skip.
    if !is_far_call {
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        let ret_flags = vm86_pop(regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
        crate::kernel::machine::set_vm86_flags(regs, ret_flags as u32);
    } else if matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE) {
        // Returns to caller — pop far-call return address
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
    }
    // Other far-call stubs (DPMI entry, raw switch, callbacks) switch modes entirely

    action
}

// ============================================================================
// Synth syscalls — invoked by user-code INT 31h (outside STUB_SEG).
// Modeled as a tiny set of primitives that COMMAND.COM (or any program)
// can call to coordinate processes + VGA across threads.
// ============================================================================

/// INT 31h from user code. AH selects subfunction.
/// On success: AX=0, CF=0. On error: AX=errno (unsigned), CF=1.
/// Unknown AH reflects through IVT (legacy DPMI int-31 path).
fn synth_dispatch(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — SYNTH_VGA_TAKE: adopt target thread's screen.
        // Input:  BX = target pid
        // Output: AX = 0 on success, errno on failure; CF reflects error.
        0x00 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            let rv = thread::vga_take(&mut dos.pc.vga, pid);
            regs.rax = (regs.rax & !0xFFFF) | ((rv as i16 as u16) as u64);
            if rv < 0 { regs.set_flag32(1); } else { regs.clear_flag32(1); }
            thread::KernelAction::Done
        }
        // AH=01h — SYNTH_FORK_EXEC_WAIT: fork+exec program and wait for it.
        // Reads the caller's own PSP cmdline at DS:0080h (byte-count + text),
        // strips leading whitespace and an optional "/C", takes the first
        // whitespace-delimited token as the program name.
        // Output on success (CF=0):
        //          BX = child pid (valid in both exit and decoupled cases)
        //          AX = 0 on normal exit (exit code via INT 21h/4Dh)
        //          AX = 1 on decoupled (F11 broke wait)
        // Output on error (CF=1):
        //          AX = errno
        0x01 => {
            let psp = linear(dos, regs, regs.ds as u16, 0);
            let tail_len = unsafe { *((psp + 0x80) as *const u8) } as usize;
            let read = |i: usize| -> u8 {
                unsafe { *((psp + 0x81 + i as u32) as *const u8) }
            };
            let mut i = 0;
            while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            if i + 1 < tail_len && read(i) == b'/' && (read(i + 1) & 0xDF) == b'C' {
                i += 2;
                while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            }
            let mut filename = [0u8; 128];
            let mut flen = 0;
            while i < tail_len && flen < 127 {
                let c = read(i);
                if matches!(c, b' ' | b'\t' | b'\r' | 0) { break; }
                filename[flen] = c;
                flen += 1;
                i += 1;
            }
            if flen == 0 {
                regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
            // If the name is a .BAT, expand to its first executable command.
            let flen = expand_bat(dos, &mut filename, flen, kt);
            fork_exec(dos, &filename[..flen], kt)
        }
        // AH=02h — TRACE_ON: enable runtime DOS/DPMI trace gate.
        // AH=03h — TRACE_OFF: disable it.
        // No DPMI 0.9 collision (RM-only path; PM DPMI is dispatched separately).
        0x02 | 0x03 => {
            DOS_TRACE_RT.store(ah == 0x02, core::sync::atomic::Ordering::Relaxed);
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // Unknown AH: reflect through IVT for legacy/DPMI compatibility.
        _ => {
            reflect_interrupt(regs, 0x31);
            thread::KernelAction::Done
        }
    }
}

// ============================================================================
// BIOS INT 13h — Disk services
// ============================================================================

/// INT 08h — Timer tick (IRQ0).
/// Replaces the BIOS handler: increment BDA tick counter, call INT 1Ch.
/// Handled in kernel to avoid BIOS handler's stack usage on the program's
/// stack (which can corrupt tiny .COM stubs like LZEXE decompressors).
/// Saved BIOS IRQ handlers (before we hook the IVT). Indexed by IRQ number
/// 0..15 (not interrupt vector). IRQ 0..7 = INT 0x08..0x0F, IRQ 8..15 =
/// INT 0x70..0x77.
static mut BIOS_HW_IRQ: [(u16, u16); 16] = [(0, 0); 16];

/// Convert IRQ number (0..15) to its real-mode interrupt vector.
fn irq_to_vector(irq: u8) -> u8 {
    if irq < 8 { 0x08 + irq } else { 0x70 + (irq - 8) }
}

/// INT 08h — Timer tick (IRQ0).
/// Switch to private IRQ stack, then chain to BIOS handler.
/// When the BIOS handler IRETs, it returns to SLOT_HW_IRQ_RET which
/// traps back to kernel to restore the original SS:SP.
/// Hardware IRQ reflect with private stack.
/// The reflect frame (FLAGS/CS/IP) stays on the original VM86 stack.
/// We switch to a private stack, push a trampoline, and jump to the
/// saved BIOS handler.  BIOS IRETs to trampoline → SLOT_HW_IRQ_RET
/// restores SS:SP → post-match pops the reflect frame → done.
fn hw_irq_reflect(dos: &mut thread::DosState, regs: &mut Regs, irq: u8) {
    if dos.pc.irq_saved_sssp.is_none() {
        // First hardware IRQ: switch to private stack, push trampoline.
        dos.pc.irq_saved_sssp = Some((vm86_ss(regs), vm86_sp(regs)));
        crate::kernel::machine::set_vm86_ss(regs, IRQ_STACK_SEG);
        crate::kernel::machine::set_vm86_sp(regs, IRQ_STACK_TOP);

        vm86_push(regs, vm86_flags(regs) as u16);
        vm86_push(regs, STUB_SEG);
        vm86_push(regs, slot_offset(SLOT_HW_IRQ_RET));
    }
    // Reflect frame (FLAGS/CS/IP) is on the current stack (original or IRQ).
    let (bios_cs, bios_ip) = unsafe { BIOS_HW_IRQ[irq as usize] };
    set_vm86_ip(regs, bios_ip);
    set_vm86_cs(regs, bios_cs);
    regs.clear_flag32(IF_FLAG);
}

fn int_13h(regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let dl = regs.rdx as u8; // drive number
    // For floppy drives (DL < 0x80), return "drive not ready" error.
    // Hard drives (DL >= 0x80) are also unsupported — return error.
    match ah {
        // AH=00h Reset Disk — just succeed
        0x00 => {
            regs.rax = regs.rax & !0xFF00; // AH=0 success
            regs.clear_flag32(1);
        }
        // AH=08h Get Drive Parameters
        0x08 => {
            if dl < 0x80 {
                // No floppy drives
                regs.rax = (regs.rax & !0xFF00) | (0x07 << 8); // AH=07 drive parameter activity failed
                regs.set_flag32(1);
            } else {
                // Report a minimal hard drive geometry
                regs.rax = regs.rax & !0xFF00; // AH=0 success
                regs.rbx = (regs.rbx & !0xFF) | 0; // BL=drive type (0 for HD)
                regs.rcx = (regs.rcx & !0xFFFF) | ((32 << 8) | 63); // CH=max cyl low, CL=max sect
                regs.rdx = (regs.rdx & !0xFFFF) | ((1 << 8) | 1); // DH=max head, DL=number of drives
                regs.clear_flag32(1);
            }
        }
        // AH=15h Get Disk Type
        0x15 => {
            if dl < 0x80 {
                // No floppy: AH=0 means "no such drive"
                regs.rax = regs.rax & !0xFF00;
                regs.set_flag32(1);
            } else {
                // Hard disk present
                regs.rax = (regs.rax & !0xFF00) | (0x03 << 8); // AH=03 = hard disk
                regs.clear_flag32(1);
            }
        }
        _ => {
            // All other functions: return error (drive not ready)
            regs.rax = (regs.rax & !0xFF00) | (0x80 << 8); // AH=80h timeout/not ready
            regs.set_flag32(1);
        }
    }
    thread::KernelAction::Done
}

/// DOS character output — writes via VGA putchar and syncs the BDA cursor
/// position at 0040:0050 so BIOS and programs (like DN) that read the BDA
/// cursor see the correct position.
fn dos_putchar(c: u8) {
    use crate::arch::outb;
    unsafe {
        let col = core::ptr::read_volatile(0x450 as *const u8) as usize;
        let row = core::ptr::read_volatile(0x451 as *const u8) as usize;
        let v = vga::vga();
        v.set_cursor_pos(col, row);
        v.putchar(c);
        let (col, row) = v.cursor_pos();
        core::ptr::write_volatile(0x450 as *mut u8, col as u8);
        core::ptr::write_volatile(0x451 as *mut u8, row as u8);
        // Update CRTC hardware cursor so save_from_hardware captures it
        let offset = (row * 80 + col) as u16;
        outb(0x3D4, 0x0E); outb(0x3D5, (offset >> 8) as u8);
        outb(0x3D4, 0x0F); outb(0x3D5, offset as u8);
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    if ah != 0x2C && ah != 0x2A && regs.mode() == crate::UserMode::VM86 {
        dos_trace!(force "[INT21] AX={:04x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
            regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
            regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    }
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            dos_putchar(regs.rdx as u8);
            thread::KernelAction::Done
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40); // clear ZF = char available
                } else {
                    regs.set_flag32(0x40); // set ZF = no char available
                }
            } else {
                dos_putchar(dl);
            }
            thread::KernelAction::Done
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let start = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut addr = start;
            loop {
                let ch = unsafe { *(addr as *const u8) };
                if ch == b'$' { break; }
                dos_putchar(ch);
                addr = addr.wrapping_add(1);
                // Safety limit: cap at 64 KiB from start
                if addr.wrapping_sub(start) > 0xFFFF { break; }
            }
            thread::KernelAction::Done
        }
        // AH=0x0B: Check Standard Input Status — AL=0 no char, 0xFF char ready
        0x0B => {
            regs.rax = (regs.rax & !0xFF) | 0x00; // no character available
            thread::KernelAction::Done
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            let off = regs.rdx as u16;
            let seg = regs.ds as u16;
            write_u16(0, (int_num as u32) * 4, off);
            write_u16(0, (int_num as u32) * 4 + 2, seg);
            thread::KernelAction::Done
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => { regs.rdx = regs.rdx & !0xFF; } // DL=0: break checking off
                0x01 => {} // set break — ignore
                _ => {
                    dos_trace!("D21 33 unsupported AL={:02X}", al);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x34: Get INDOS Flag pointer — returns ES:BX → byte that is
        // nonzero while DOS is executing. We're never "in DOS" from the
        // guest's perspective (kernel services calls synchronously), so
        // point at a permanently-zero byte inside SYSPSP.
        0x34 => {
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (SYSPSP_ADDR + INDOS_FLAG_OFFSET as u32) as u64;
            } else {
                regs.es = SYSPSP_SEG as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | INDOS_FLAG_OFFSET as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=64-byte buffer)
        // Returns ASCIIZ path without drive letter or leading backslash
        // DL: 0=default, 1=A, 2=B, 3=C
        0x47 => {
            let dl = regs.rdx as u8;
            let drive = if dl == 0 { 3 } else { dl };
            if drive != 3 {
                // Invalid drive (A:/B:)
                regs.rax = (regs.rax & !0xFFFF) | 0x0F;
                regs.set_flag32(1);
            } else {
                let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
                let cwd = dos.dfs.get_cwd();
                unsafe {
                    for (i, &b) in cwd.iter().enumerate() {
                        *((addr + i as u32) as *mut u8) = b;
                    }
                    *((addr + cwd.len() as u32) as *mut u8) = 0;
                }
                dos_trace!("D21 47 DL={:02X} out=\"{}\"",
                    dl, core::str::from_utf8(cwd).unwrap_or("?"));
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | 2; // C:
            thread::KernelAction::Done
        }
        // AH=0x0C: Flush input buffer then execute function in AL
        0x0C => {
            clear_bios_keyboard_buffer();
            dos.dos_pending_char = None;
            // Just execute the sub-function in AL
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40);
                } else {
                    regs.set_flag32(0x40); // ZF=1
                }
            }
            // Other sub-functions: just return
            thread::KernelAction::Done
        }
        // AH=0x0D: Disk Reset (flush buffers) — no-op on RAM-backed FS
        0x0D => {
            thread::KernelAction::Done
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            dos.dta = dta;
            thread::KernelAction::Done
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = dos.dta;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | dta as u64;
            } else {
                regs.es = (dta >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (dta & 0x0F) as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 5.00 (DOS/32A and other extenders require >= 4.0)
            regs.rax = (regs.rax & !0xFFFF) | 0x0005; // AL=5 (major), AH=0 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            thread::KernelAction::Done
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            let off = read_u16(0, (int_num as u32) * 4);
            let seg = read_u16(0, (int_num as u32) * 4 + 2);
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                // PM client: return LOW_MEM_SEL:linear so the selector is valid.
                let linear = ((seg as u32) << 4).wrapping_add(off as u32);
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (linear & 0xFFFF) as u64;
            } else {
                // V86 / real mode: return the raw IVT seg:off pair.
                regs.es = seg as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | off as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x38: Get country information — return minimal stub
        //
        // DOS 2.x uses a 32-byte buffer; DOS 3.0+ extended it to 34 bytes.
        // Many programs (including NC 2.0) allocate only 32 bytes, so write
        // field-by-field rather than blindly zeroing 34 bytes.
        0x38 => {
            let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            unsafe {
                let p = addr as *mut u8;
                core::ptr::write_bytes(p, 0, 24); // zero first 24 bytes (through case-map)
                // +00: date format (0 = USA: mm/dd/yy)
                // +02: currency symbol '$\0\0\0\0'
                *p.add(2) = b'$';
                // +07: thousands separator ',\0'
                *p.add(7) = b',';
                // +09: decimal separator '.\0'
                *p.add(9) = b'.';
                // +0B: date separator '/\0'
                *p.add(0x0B) = b'/';
                // +0D: time separator ':\0'
                *p.add(0x0D) = b':';
            }
            regs.rbx = (regs.rbx & !0xFFFF) | 1; // country code = 1 (USA)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut path = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *((addr + i as u32) as *const u8) };
                if ch == 0 { break; }
                path[i] = ch;
                i += 1;
            }
            let err = dos.dfs.chdir(&path[..i]);
            if err != 0 {
                regs.set_flag32(1);
                regs.rax = (regs.rax & !0xFFFF) | err as u64;
            } else {
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x3D: Open file (DS:DX=ASCIIZ filename, AL=access mode)
        0x3D => {
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            // Check for device names (before normalization)
            if EMS_ENABLED && name[..i].eq_ignore_ascii_case(b"EMMXXXX0") {
                regs.rax = (regs.rax & !0xFFFF) | EMS_DEVICE_HANDLE as u64;
                regs.clear_flag32(1);
            } else {
                let raw_name_str = core::str::from_utf8(&name[..i]).unwrap_or("?");
                dos_trace!("D21 3D raw=\"{}\" cwd=\"{}\"", raw_name_str,
                    core::str::from_utf8(dos.dfs.get_cwd()).unwrap_or("?"));
                let fd = match dfs_open_existing(dos, &name[..i]) {
                    Ok(buf) => {
                        let (ref path, len) = buf;
                        dos_trace!("D21 3D open \"{}\"", core::str::from_utf8(&path[..len]).unwrap_or("?"));
                        crate::kernel::vfs::open(&path[..len], &mut kt.fds)
                    }
                    Err(e) => -e,
                };
                if fd >= 0 {
                    // Populate SFT entry and PSP JFT for this handle
                    let size = crate::kernel::vfs::file_size(fd, &kt.fds);
                    sft_set_file(fd as u16, size);
                    unsafe {
                        let psp = ((dos.current_psp as u32) * 16) as *mut u8;
                        if (fd as usize) < 20 { *psp.add(0x34 + fd as usize) = fd as u8; }
                    }
                    regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                    regs.clear_flag32(1); // clear carry
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                    regs.set_flag32(1); // set carry
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            let handle = regs.rbx as u16;
            if handle != NULL_FILE_HANDLE && (!EMS_ENABLED || handle != EMS_DEVICE_HANDLE) {
                crate::kernel::vfs::close(handle as i32, &mut kt.fds);
                sft_clear(handle);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as u16 as i32;
            let count = regs.rcx as u16 as usize;
            let buf_addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            if handle == 0 {
                // stdin — read from virtual keyboard
                // Return 0 for now (no line-buffered stdin in VM86)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == 1 || handle == 2 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — return 0 bytes (EOF)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if count == 0 || buf_addr == 0 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, count) };
                crate::dbg_println!("D21 3F enter h={} req={:#X} buf={:08X}", handle, count, buf_addr);
                let n = crate::kernel::vfs::read(handle, buf, &kt.fds);
                crate::dbg_println!("D21 3F exit  h={} req={:#X} got={:#X}", handle, count, n);
                if n >= 0 {
                    if (n as usize) < count { dos_trace!("D21 3F SHORT h={} req={} got={}", handle, count, n); }
                    regs.rax = (regs.rax & !0xFFFF) | n as u64;
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => {
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut raw = [0u8; 80];
            let mut raw_len = 0;
            while raw_len < 79 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                raw[raw_len] = ch;
                addr += 1;
                raw_len += 1;
            }
            // Resolve DOS path (last component may be a wildcard pattern).
            // Walk the directory components via DFS; append the pattern verbatim.
            let mut abs = [0u8; dfs::DFS_PATH_MAX];
            let alen = match dos.dfs.resolve(&raw[..raw_len], &mut abs) {
                Ok(n) => n,
                Err(_) => {
                    regs.rax = (regs.rax & !0xFFFF) | 3;
                    regs.set_flag32(1);
                    return thread::KernelAction::Done;
                }
            };
            // Split at last '\' to separate dir from pattern.
            let split = abs[..alen].iter().rposition(|&b| b == b'\\').unwrap_or(0);
            let dir_dos = &abs[..split + 1]; // includes trailing '\'
            let pat = &abs[split + 1..alen];
            // Strip trailing '\' for walk (keep "X:\" if dir_dos is exactly that).
            let dir_for_walk = if dir_dos.len() > 3 { &dir_dos[..dir_dos.len() - 1] } else { dir_dos };
            let mut vfs_dir = [0u8; dfs::DFS_PATH_MAX];
            let vlen = match dfs::DfsState::to_vfs_open(dir_for_walk, &mut vfs_dir) {
                Ok(n) => n,
                Err(e) => {
                    regs.rax = (regs.rax & !0xFFFF) | e as u64;
                    regs.set_flag32(1);
                    return thread::KernelAction::Done;
                }
            };
            // Compose "vfs_dir/pat" in dos.find_path.
            let mut pos = 0;
            for &b in &vfs_dir[..vlen] {
                if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
            }
            if vlen > 0 && pos < dos.find_path.len() {
                dos.find_path[pos] = b'/'; pos += 1;
            }
            for &b in pat {
                if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
            }
            dos.find_path_len = pos as u8;
            dos.find_idx = 0;
            find_matching_file(dos, regs)
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            find_matching_file(dos, regs)
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            // If we're in an EXEC'd child, return to parent
            if let Some(parent) = dos.exec_parent.take() {
                // Termination type 00h (normal) | return code in AL.
                dos.last_child_exit_status = (regs.rax as u8) as u16;
                return exec_return(dos, regs, parent);
            }
            let code = regs.rax as u8;
            thread::KernelAction::Exit(code as i32)
        }
        // AH=0x31: Terminate and Stay Resident (TSR)
        // AL = return code, DX = paragraphs to keep (from child's PSP)
        // Like AH=4Ch but the child's memory stays committed: heap_seg
        // remains above the resident block so subsequent parent allocations
        // don't overlap. INT vector hooks the child installed in the IVT
        // remain valid because the IVT is part of the address space and the
        // child's code at heap_seg+offset is still mapped.
        0x31 => {
            if let Some(parent) = dos.exec_parent.take() {
                let keep = regs.rdx as u16;
                let child_psp_seg = parent.heap_seg;
                let resident_top = child_psp_seg.saturating_add(keep);
                // Termination type 03h (TSR) | return code in AL.
                dos.last_child_exit_status = 0x0300 | (regs.rax as u8) as u16;
                let action = exec_return(dos, regs, parent);
                if resident_top > dos.heap_seg {
                    dos_reset_blocks(dos, resident_top);
                }
                return action;
            }
            let code = regs.rax as u8;
            thread::KernelAction::Exit(code as i32)
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            match dos_alloc_block(dos, need) {
                Ok(seg) => {
                    regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                    regs.clear_flag32(1);
                }
                Err(avail) => {
                    regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                    regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            match dos_free_block(dos, regs.es as u16) {
                Ok(()) => regs.clear_flag32(1),
                Err(err) => {
                    regs.rax = (regs.rax & !0xFFFF) | err as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            match dos_resize_block(dos, regs.es as u16, regs.rbx as u16) {
                Ok(()) => regs.clear_flag32(1),
                Err((err, max)) => {
                    regs.rax = (regs.rax & !0xFFFF) | err as u64;
                    regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x44: IOCTL (various subfunctions)
        0x44 => {
            let al = regs.rax as u8;
            match al {
                // AL=0x00: Get Device Information (BX=handle, returns DX=info word)
                0x00 => {
                    let handle = regs.rbx as u16;
                    if handle <= 2 {
                        // stdin/stdout/stderr: bit 7=1 (device), bit 0=1 (stdin), bit 1=1 (stdout)
                        let info: u16 = 0x80 | match handle {
                            0 => 0x01, // stdin
                            _ => 0x02, // stdout/stderr
                        };
                        regs.rdx = (regs.rdx & !0xFFFF) | info as u64;
                        regs.clear_flag32(1);
                    } else if EMS_ENABLED && handle == EMS_DEVICE_HANDLE {
                        // EMMXXXX0 device: bit 7=1 (device)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x80;
                        regs.clear_flag32(1);
                    } else {
                        // File handle: bit 7=0 (file), bits 5-0=drive (2=C:)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0002;
                        regs.clear_flag32(1);
                    }
                }
                // AL=0x07: Check device output status (BX=handle)
                0x07 => {
                    // AL=FFh = ready
                    regs.rax = (regs.rax & !0xFF) | 0xFF;
                    regs.clear_flag32(1);
                }
                // AL=0x08: Check if block device is removable (BL=drive, 0=default,1=A,3=C)
                0x08 => {
                    // AX=0 = removable, AX=1 = fixed
                    regs.rax = (regs.rax & !0xFFFF) | 1; // fixed disk
                    regs.clear_flag32(1); // clear CF
                }
                // AL=0x09: Check if block device is remote (BL=drive)
                0x09 => {
                    regs.rdx = (regs.rdx & !0xFFFF) | 0x0000; // bit 12=0 = local
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 44 (IOCTL) unsupported AL={:02X} BX={:04X} CX={:04X}",
                        al, regs.rbx as u16, regs.rcx as u16);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C)
        0x0E => {
            regs.rax = (regs.rax & !0xFF) | 3; // AL = number of logical drives
            thread::KernelAction::Done
        }
        // AH=0x3C: Create file (CX=attr, DS:DX=filename) — RAM-backed via VFS overlay
        0x3C => {
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let fd = match dfs_create_path(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 4; // too many open files
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            // Handle 1=stdout, 2=stderr
            if handle == 1 || handle == 2 {
                let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
                for i in 0..count as u32 {
                    let ch = unsafe { *((addr + i) as *const u8) };
                    dos_putchar(ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else if handle == NULL_FILE_HANDLE {
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else {
                let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
                let data = unsafe { core::slice::from_raw_parts(addr as *const u8, count as usize) };
                let n = crate::kernel::vfs::write(handle as i32, data, &kt.fds);
                regs.rax = (regs.rax & !0xFFFF) | if n >= 0 { n as u64 } else { count as u64 };
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as u16 as i32;
            if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — always at position 0
                regs.rdx = regs.rdx & !0xFFFF;
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let offset = ((regs.rcx as u16 as u32) << 16 | regs.rdx as u16 as u32) as i32;
                let whence = regs.rax as u8 as i32; // AL = origin
                let result = crate::kernel::vfs::seek(handle, offset, whence, &kt.fds);
                dos_trace!("D21 42 h={} whence={} off={:#X} -> {:#X}", handle, whence, offset as u32, result);
                if result >= 0 {
                    // Return new position in DX:AX
                    regs.rdx = (regs.rdx & !0xFFFF) | ((result as u32 >> 16) as u64);
                    regs.rax = (regs.rax & !0xFFFF) | (result as u16 as u64);
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x43: Get/Set File Attributes (AL=0: get, AL=1: set)
        // DS:DX = ASCIIZ filename, CX = attributes (for set)
        0x43 => {
            let al = regs.rax as u8;
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            { let p = addr as *const u8; let mut hex = [0u8; 32];
              for j in 0..16usize { let b = unsafe { *p.add(j) }; hex[j*2] = b"0123456789ABCDEF"[(b>>4) as usize]; hex[j*2+1] = b"0123456789ABCDEF"[(b&0xF) as usize]; }
              dos_trace!("D21 43 addr={:08X} hex={}", addr, core::str::from_utf8(&hex).unwrap()); }
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                crate::kernel::vfs::close(fd, &mut kt.fds);
                if al == 0 {
                    // Get attributes: return 0x20 (archive) in CX
                    regs.rcx = (regs.rcx & !0xFFFF) | 0x20;
                }
                // Set attributes: just succeed (read-only FS)
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x29: Parse filename into FCB (DS:SI=string, ES:DI=FCB)
        // AL bits: 0=skip leading separators, 1=set drive only if specified,
        //          2=set filename only if specified, 3=set extension only if specified
        0x29 => {
            let ds_base = linear(dos, regs, regs.ds as u16, 0);
            let mut si = regs.rsi as u16;
            let fcb = linear(dos, regs, regs.es as u16, regs.rdi as u32);

            // Skip leading whitespace/separators if bit 0 set
            let flags = regs.rax as u8;
            if flags & 1 != 0 {
                loop {
                    let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                    if ch == b' ' || ch == b'\t' || ch == b';' || ch == b',' {
                        si += 1;
                    } else {
                        break;
                    }
                }
            }

            // Zero-fill the 11-byte name field in FCB (drive byte at +0, name at +1..+12)
            unsafe { core::ptr::write_bytes((fcb + 1) as *mut u8, b' ', 11); }

            // Check for drive letter (e.g., "C:")
            let ch0 = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
            let ch1 = unsafe { *(ds_base.wrapping_add(si as u32 + 1) as *const u8) };
            if ch1 == b':' && ch0.is_ascii_alphabetic() {
                unsafe { *(fcb as *mut u8) = ch0.to_ascii_uppercase() - b'A' + 1; }
                si += 2;
            } else {
                unsafe { *(fcb as *mut u8) = 0; } // default drive
            }

            // Parse filename (up to 8 chars) into FCB+1
            let mut pos = 0u32;
            loop {
                let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                if ch == b'.' || ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                if ch == b'*' {
                    while pos < 8 { unsafe { *((fcb + 1 + pos) as *mut u8) = b'?'; } pos += 1; }
                    si += 1;
                    break;
                }
                if pos < 8 {
                    unsafe { *((fcb + 1 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                    pos += 1;
                }
                si += 1;
            }

            // Parse extension (up to 3 chars) into FCB+9
            let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
            if ch == b'.' {
                si += 1;
                pos = 0;
                loop {
                    let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                    if ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                    if ch == b'*' {
                        while pos < 3 { unsafe { *((fcb + 9 + pos) as *mut u8) = b'?'; } pos += 1; }
                        si += 1;
                        break;
                    }
                    if pos < 3 {
                        unsafe { *((fcb + 9 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                        pos += 1;
                    }
                    si += 1;
                }
            }

            // Update SI to point past parsed name
            regs.rsi = (regs.rsi & !0xFFFF) | si as u64;
            // AL=0: no wildcards, AL=1: wildcards present, AL=0xFF: drive invalid
            let has_wildcards = unsafe {
                let name_area = core::slice::from_raw_parts((fcb + 1) as *const u8, 11);
                name_area.iter().any(|&b| b == b'?')
            };
            regs.rax = (regs.rax & !0xFF) | if has_wildcards { 1 } else { 0 };
            thread::KernelAction::Done
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            exec_program(kt, dos, regs)
        }
        // AH=2Ah — Get System Date
        0x2A => {
            // Return a fixed date: 2026-03-22 (Saturday)
            regs.rcx = (regs.rcx & !0xFFFF) | 2026; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | (3 << 8) | 22; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | 6; // AL = day of week (0=Sun, 6=Sat)
            thread::KernelAction::Done
        }
        // AH=2Ch — Get System Time
        0x2C => {
            // Derive from BIOS tick count at 0040:006C (18.2 ticks/sec)
            let ticks = unsafe { *((0x46C) as *const u32) };
            let total_secs = ticks / 18;
            let hours = (total_secs / 3600) % 24;
            let mins = (total_secs / 60) % 60;
            let secs = total_secs % 60;
            let centisecs = ((ticks % 18) * 100) / 18;
            regs.rcx = (regs.rcx & !0xFFFF) | (hours << 8) as u64 | mins as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (secs << 8) as u64 | centisecs as u64;
            thread::KernelAction::Done
        }
        // AH=0x57: Get/Set File Date and Time (AL=0: get, AL=1: set, BX=handle)
        0x57 => {
            let al = regs.rax as u8;
            if al == 0 {
                // Get: return a fixed date/time (2026-03-22 12:00:00)
                // DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2
                // DOS date: bits 15-9=year-1980, 8-5=month, 4-0=day
                let time: u16 = (12 << 11) | (0 << 5) | 0; // 12:00:00
                let date: u16 = (46 << 9) | (3 << 5) | 22; // 2026-03-22
                regs.rcx = (regs.rcx & !0xFFFF) | time as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | date as u64;
                regs.clear_flag32(1);
            } else {
                // Set: succeed silently (read-only FS)
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x60: Canonicalize path (DS:SI=input, ES:DI=output buffer)
        0x60 => {
            let src = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
            let dst = linear(dos, regs, regs.es as u16, regs.rdi as u32);
            // Read input path
            let mut name = [0u8; 128];
            let mut len = 0;
            while len < 127 {
                let ch = unsafe { *((src + len as u32) as *const u8) };
                if ch == 0 { break; }
                name[len] = ch;
                len += 1;
            }
            {
                let cs = regs.frame.cs as u16;
                let ip = regs.frame.rip as u32;
                dos_trace!("D21 60 in=\"{}\" cs:ip={:04X}:{:08X}",
                    core::str::from_utf8(&name[..len]).unwrap_or("?"), cs, ip);
            }
            // Build canonical path: if no drive letter, prepend "C:\"
            let mut out = [0u8; 128];
            let mut pos;
            if len >= 2 && name[1] == b':' {
                // Already has drive letter — uppercase it
                out[0] = name[0].to_ascii_uppercase();
                out[1] = b':';
                out[2] = b'\\';
                pos = 3;
                let skip = if len > 2 && (name[2] == b'/' || name[2] == b'\\') { 3 } else { 2 };
                for i in skip..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
                    pos += 1;
                }
            } else {
                // Relative — prepend C:\ + CWD (DFS already in DOS form).
                out[0] = b'C'; out[1] = b':'; out[2] = b'\\';
                pos = 3;
                let cwds = dos.dfs.get_cwd();
                for &ch in cwds {
                    if pos >= 127 { break; }
                    out[pos] = ch;
                    pos += 1;
                }
                if pos > 3 && out[pos - 1] != b'\\' { out[pos] = b'\\'; pos += 1; }
                for i in 0..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
                    pos += 1;
                }
            }
            out[pos] = 0;
            // Write to ES:DI
            unsafe {
                core::ptr::copy_nonoverlapping(out.as_ptr(), dst as *mut u8, pos + 1);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x52: Get List of Lists (returns ES:BX → DOS internal structure)
        0x52 => {
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | LOL_ADDR as u64;
            } else {
                regs.es = LOL_SEG as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | 0u64;
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x36: Get Disk Free Space (DL=drive, 0=default,1=A,2=B,3=C...)
        // Returns: AX=sectors/cluster, BX=free clusters, CX=bytes/sector, DX=total clusters
        // On error: AX=0xFFFF
        0x36 => {
            let dl = regs.rdx as u8;
            // Map drive: 0=default(C), 1=A, 2=B, 3=C
            let drive = if dl == 0 { 3 } else { dl };
            if drive == 3 {
                // C: drive — report fake 16MB disk, 8MB free
                // 512 bytes/sector, 8 sectors/cluster (4KB), 4096 total clusters = 16MB
                regs.rax = (regs.rax & !0xFFFF) | 8;    // AX = sectors per cluster
                regs.rbx = (regs.rbx & !0xFFFF) | 2048; // BX = free clusters
                regs.rcx = (regs.rcx & !0xFFFF) | 512;  // CX = bytes per sector
                regs.rdx = (regs.rdx & !0xFFFF) | 4096; // DX = total clusters
            } else {
                // A:/B: or unknown — invalid drive
                regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
            }
            thread::KernelAction::Done
        }
        // AH=0x67: Set Handle Count — stub success
        0x67 => {
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x41: Delete file (DS:DX=filename)
        0x41 => {
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            if let Ok((path, len)) = dfs_open_existing(dos, &name[..i]) {
                crate::kernel::vfs::delete(&path[..len]);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x59: Get Extended Error Information
        0x59 => {
            // Return "file not found" as default extended error
            regs.rax = (regs.rax & !0xFFFF) | 2; // AX = error code (file not found)
            regs.rbx = (regs.rbx & !0xFFFF) | ((1 << 8) | 2); // BH=1 (class: out of resource), BL=2 (action: abort)
            regs.rcx = regs.rcx & !0xFFFF; // CH=0 (locus: unknown)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x58: DOS 5+ allocation strategy / UMB link state
        0x58 => {
            let al = regs.rax as u8;
            match al {
                0x00 => {
                    regs.rax = (regs.rax & !0xFFFF) | dos.alloc_strategy as u64;
                    regs.clear_flag32(1);
                }
                0x01 => {
                    dos.alloc_strategy = regs.rbx as u16;
                    regs.clear_flag32(1);
                }
                0x02 => {
                    regs.rax = (regs.rax & !0xFFFF) | dos.umb_link_state as u64;
                    regs.clear_flag32(1);
                }
                0x03 => {
                    dos.umb_link_state = regs.rbx as u16;
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 58 unsupported AL={:02X}", al);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4D: Get Return Code of Subprocess
        // Returns AL = code passed to AH=4Ch/AH=31h, AH = termination type
        // (00h normal, 01h Ctrl-Break, 02h critical error, 03h TSR).
        0x4D => {
            let status = dos.last_child_exit_status;
            regs.rax = (regs.rax & !0xFFFF) | status as u64;
            thread::KernelAction::Done
        }
        // AH=0x50: Set Current Process ID (BX = new PSP segment)
        // Undocumented in DOS 1-3, documented in 5+. Same backing field as
        // AH=51h/62h. No return value other than the side effect.
        0x50 => {
            dos.current_psp = regs.rbx as u16;
            thread::KernelAction::Done
        }
        // AH=0x51: Get Current Process ID (returns BX = current PSP segment)
        // Undocumented sibling of AH=62h.
        0x51 => {
            regs.rbx = (regs.rbx & !0xFFFF) | dos.current_psp as u64;
            let cs = regs.frame.cs as u16;
            let ip = regs.frame.rip as u32;
            dos_trace!("D21 51 -> BX={:04X} cs:ip={:04X}:{:08X}",
                dos.current_psp, cs, ip);
            thread::KernelAction::Done
        }
        // AH=0x62: Get PSP segment (returns BX=PSP segment)
        0x62 => {
            regs.rbx = (regs.rbx & !0xFFFF) | dos.current_psp as u64;
            regs.clear_flag32(1);
            let cs = regs.frame.cs as u16;
            let ip = regs.frame.rip as u32;
            dos_trace!("D21 62 -> BX={:04X} cs:ip={:04X}:{:08X}",
                dos.current_psp, cs, ip);
            thread::KernelAction::Done
        }
        // AH=0x6C: Extended Open/Create (DOS 4.0+)
        // BX=mode, CX=attributes, DX=action, DS:SI=ASCIIZ filename
        // Action: bit0=open-if-exists, bit4=create-if-not-exists
        0x6C => {
            let action = regs.rdx as u16;
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let open_exists = action & 0x01 != 0;
            let create_not = action & 0x10 != 0;

            // Try open first
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 && open_exists {
                let size = crate::kernel::vfs::file_size(fd, &kt.fds);
                sft_set_file(fd as u16, size);
                unsafe {
                    let psp = ((dos.current_psp as u32) * 16) as *mut u8;
                    if (fd as usize) < 20 { *psp.add(0x34 + fd as usize) = fd as u8; }
                }
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.rcx = (regs.rcx & !0xFFFF) | 1; // CX=1: file opened
                regs.clear_flag32(1);
            } else if create_not {
                // File doesn't exist — create RAM-backed file via VFS overlay
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut kt.fds); }
                let new_fd = match dfs_create_path(dos, &name[..i]) {
                    Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                    Err(e) => -e,
                };
                if new_fd >= 0 {
                    regs.rax = (regs.rax & !0xFFFF) | new_fd as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | 2; // CX=2: file created
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 4;
                    regs.set_flag32(1);
                }
            } else {
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut kt.fds); }
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x5D: Server function — subfunction in AL
        0x5D => {
            let al = regs.rax as u8;
            match al {
                // AL=06: Get DOS Swappable Data Area address
                //   Returns DS:SI→ swap area, CX=total size, DX=size that must
                //   always be swapped. Point at SYSPSP (zeroed) with a nominal
                //   size; DPMILOAD just needs a plausible pointer.
                0x06 => {
                    if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                        regs.ds = dpmi::LOW_MEM_SEL as u64;
                        regs.rsi = (regs.rsi & !0xFFFF) | SYSPSP_ADDR as u64;
                    } else {
                        regs.ds = SYSPSP_SEG as u64;
                        regs.rsi = (regs.rsi & !0xFFFF) | 0u64;
                    }
                    regs.rcx = (regs.rcx & !0xFFFF) | SYSPSP_SIZE as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | SYSPSP_SIZE as u64;
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 5D unsupported AL={:02X}", al);
                    regs.rax = (regs.rax & !0xFFFF) | 1; // invalid function
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        0x71 => {
            // LFN (Long File Name) API — not supported.
            // Return AX=7100h so DJGPP/libc knows to fall back to short-name DOS calls.
            regs.rax = (regs.rax & !0xFFFF) | 0x7100;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
        0xFF => {
            dos_trace!("VM86: INT 21h AX={:04X} BX={:04X}", regs.rax as u16, regs.rbx as u16);
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
        _ => {
            dos_trace!("VM86: unhandled INT 21h AH={:#04x} AX={:04X}", ah, regs.rax as u16);
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
    }
}

/// DOS INT 21h/4B — Load and Execute Program
///
/// Try to open a program file via VFS. If the name has no extension (no dot),
/// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Eh — COMMAND.COM internal execute
// ============================================================================

fn int_2eh(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
    // Treat as COMMAND.COM /C — fork-exec the program in a fresh address space.
    let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
    let len = unsafe { *(addr as *const u8) } as usize;
    let mut cmd = [0u8; 128];
    let copy = len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((addr + 1) as *const u8, cmd.as_mut_ptr(), copy);
    }
    let mut start = 0;
    while start < copy && cmd[start] == b' ' { start += 1; }
    let mut end = start;
    while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
    if end <= start { return thread::KernelAction::Done; }

    // Shift the program name to the start of the buffer.
    let plen = end - start;
    cmd.copy_within(start..end, 0);
    fork_exec(dos, &cmd[..plen], kt)
}

// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS + DPMI detection)
// ============================================================================

/// Fill regs with DPMI 0.90 installation-check reply (shared by INT 2F/1687h
/// and DOS/32A's INT 21h AX=FF87h probe).
fn dpmi_install_check(regs: &mut Regs) {
    regs.rax = regs.rax & !0xFFFF; // AX=0: DPMI available
    regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // BX bit0 = 32-bit supported
    regs.rcx = (regs.rcx & !0xFF) | 0x03; // CL = 386
    regs.rdx = (regs.rdx & !0xFFFF) | 0x005A; // DX = DPMI 0.90
    regs.rsi = regs.rsi & !0xFFFF; // SI = 0 paragraphs needed
    regs.es = STUB_SEG as u64;
    regs.rdi = (regs.rdi & !0xFFFF) | slot_offset(SLOT_DPMI_ENTRY) as u64;
}

fn int_2fh(_dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
    dos_trace!("D2F {:04X} BX={:04X} CX={:04X} DX={:04X} cs:ip={:04X}:{:04X}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.code_seg(), regs.ip32() as u16);
    match ax {
        // AX=1687h — DPMI installation check
        0x1687 => {
            dpmi_install_check(regs);
            thread::KernelAction::Done
        }
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            thread::KernelAction::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | slot_offset(SLOT_XMS) as u64;
            thread::KernelAction::Done
        }
        _ => {
            // Unhandled — return "not installed" (AL unchanged). Multiplex
            // probes use this as the protocol, so it's not always a bug —
            // log so a missing-real-TSR bug doesn't hide as "silent miss".
            dos_trace!("D2F unsupported AX={:04X} (returning not-installed)", ax);
            thread::KernelAction::Done
        }
    }
}

// ============================================================================
// XMS dispatch (called via stub slot SLOT_XMS)
// ============================================================================

/// Ensure XMS state exists for current thread, return mutable reference
fn xms_state(dos: &mut thread::DosState) -> &mut XmsState {
    if dos.xms.is_none() {
        dos.xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    dos.xms.as_deref_mut().unwrap()
}

fn xms_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
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

/// XMS function 0Bh: Move extended memory block
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

// ============================================================================
// INT 67h — EMS driver
// ============================================================================

/// Ensure EMS state exists for current thread
fn ems_state(dos: &mut thread::DosState) -> &mut EmsState {
    if dos.ems.is_none() {
        dos.ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    dos.ems.as_deref_mut().unwrap()
}

fn int_67h(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
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

fn dos_open_program(kt: &mut thread::KernelThread, dos: &mut thread::DosState, name: &[u8]) -> i32 {
    let try_open = |dos: &thread::DosState, kt: &mut thread::KernelThread, n: &[u8]| -> i32 {
        match dfs_open_existing(dos, n) {
            Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
            Err(_) => -2,
        }
    };

    let fd = try_open(dos, kt, name);
    if fd >= 0 { return fd; }
    // If the name already has a dot, don't try extensions
    if name.iter().any(|&c| c == b'.') { return fd; }
    // Try .COM / .EXE / .ELF in turn
    let mut buf = [0u8; 132];
    let nlen = name.len();
    if nlen + 4 > buf.len() { return -2; }
    buf[..nlen].copy_from_slice(name);
    for ext in [b".COM", b".EXE", b".ELF"] {
        buf[nlen..nlen + 4].copy_from_slice(ext);
        let fd = try_open(dos, kt, &buf[..nlen + 4]);
        if fd >= 0 { return fd; }
    }
    -2 // ENOENT
}

/// Expand a .BAT file to its first executable command.
///
/// If `filename[..flen]` names a .BAT file, open it, find the first line
/// that isn't blank / REM / `@echo off` / `:label`, strip a leading `@`,
/// and copy the first whitespace-delimited token back into `filename`.
/// Returns the new length. For non-.BAT names, returns `flen` unchanged.
///
/// Only the first command is executed — multi-line BAT semantics (loops,
/// conditionals, state) are out of scope for this basic handler.
fn expand_bat(dos: &mut thread::DosState, filename: &mut [u8; 128], flen: usize, kt: &mut thread::KernelThread) -> usize {
    // Case-insensitive suffix check for ".BAT"
    if flen < 4 { return flen; }
    let tail = &filename[flen - 4..flen];
    if !(tail[0] == b'.'
        && (tail[1] & 0xDF) == b'B'
        && (tail[2] & 0xDF) == b'A'
        && (tail[3] & 0xDF) == b'T') { return flen; }

    let (vfs_path, vfs_len) = match dfs_open_existing(dos, &filename[..flen]) {
        Ok(v) => v,
        Err(_) => return flen,
    };
    let fd = crate::kernel::vfs::open(&vfs_path[..vfs_len], &mut kt.fds);
    if fd < 0 { return flen; }

    let mut buf = [0u8; 512];
    let n = crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);
    if n <= 0 { return flen; }
    let n = n as usize;

    // Walk lines, find the first real command.
    let mut p = 0usize;
    while p < n {
        // Skip leading whitespace
        while p < n && matches!(buf[p], b' ' | b'\t') { p += 1; }
        // Blank line?
        if p >= n || matches!(buf[p], b'\r' | b'\n') {
            while p < n && matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Optional leading '@' (suppress echo) — strip it
        let mut q = p;
        if buf[q] == b'@' { q += 1; }
        // REM / ECHO OFF / label — skip whole line
        let lower = |i: usize| -> u8 { if i < n { buf[i] & 0xDF } else { 0 } };
        let end_of_word = |i: usize| -> bool {
            i >= n || matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n')
        };
        let is_rem = lower(q) == b'R' && lower(q+1) == b'E' && lower(q+2) == b'M' && end_of_word(q+3);
        let is_echo = lower(q) == b'E' && lower(q+1) == b'C' && lower(q+2) == b'H' && lower(q+3) == b'O' && end_of_word(q+4);
        let is_label = buf[q] == b':';
        if is_rem || is_echo || is_label {
            while p < n && !matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Real command — extract first whitespace-delimited token
        let start = q;
        let mut end = q;
        while end < n && !matches!(buf[end], b' ' | b'\t' | b'\r' | b'\n') { end += 1; }
        let tok_len = (end - start).min(127);
        // Zero the buffer first so leftover bytes don't leak
        for b in filename.iter_mut() { *b = 0; }
        filename[..tok_len].copy_from_slice(&buf[start..start + tok_len]);
        return tok_len;
    }
    flen
}

/// Resolve path and return ForkExec action for the event loop to execute.
/// Synth ABI: on success BX=child_tid, CF=0. On error AX=errno, CF=1.
fn fork_exec(dos: &mut thread::DosState, prog_name: &[u8], _kt: &mut thread::KernelThread) -> thread::KernelAction {
    // Resolve raw DOS name → VFS path via DFS.
    let mut path = [0u8; 164];
    let path_len = match dfs_open_existing(dos, prog_name) {
        Ok((p, len)) => {
            path[..len].copy_from_slice(&p[..len]);
            len
        }
        Err(_) => {
            // Let the event loop handle ENOENT by reporting failure.
            return thread::KernelAction::Done;
        }
    };

    fn on_error(regs: &mut Regs, err: i32) {
        regs.rax = (regs.rax & !0xFFFF) | err as u64;
        regs.set_flag32(1);
    }

    fn on_success(regs: &mut Regs, child_tid: i32) {
        regs.rbx = (regs.rbx & !0xFFFF) | ((child_tid as u16) as u64);
        regs.clear_flag32(1);
    }

    thread::KernelAction::ForkExec {
        path,
        path_len,
        on_error,
        on_success,
    }
}

/// DOS INT 4Bh EXEC — load and execute a DOS program in-process.
/// Loads a .COM or MZ .EXE into a fresh child segment above `heap_seg`,
/// shares the address space with the parent, and transfers control.
/// Parent resumes via exec_return on child INT 20h / 4C00.
/// Non-DOS formats (ELF, BAT) should be routed through COMMAND.COM /C
/// which uses synth INT 31h AH=01h to fork+exec+wait a separate thread.
fn exec_program(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let al = regs.rax as u8;
    match al {
        0x00 => {}                                  // load & execute — fall through
        0x03 => return exec_load_overlay(kt, dos, regs),
        // AL=01 (load only) and AL=02 (reserved) not implemented. Borland BC
        // and Watcom tools use 00/03 exclusively; surface others so we notice.
        _ => {
            dos_trace!("D21 4B unsupported AL={:02X}", al);
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
    }

    // Read ASCIIZ filename from DS:DX
    let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = unsafe { *(addr as *const u8) };
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }

    // Read parameter block at ES:BX
    let pb = linear(dos, regs, regs.es as u16, regs.rbx as u32);
    let cmdtail_off = unsafe { ((pb + 2) as *const u16).read_unaligned() } as u32;
    let cmdtail_seg = unsafe { ((pb + 4) as *const u16).read_unaligned() } as u32;
    let cmdtail_addr = (cmdtail_seg << 4) + cmdtail_off;
    let tail_len = unsafe { *(cmdtail_addr as *const u8) } as usize;
    let mut tail = [0u8; 128];
    let copy_len = tail_len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((cmdtail_addr + 1) as *const u8, tail.as_mut_ptr(), copy_len);
    }

    let prog_name: &[u8] = &filename[..flen];

    // TRACE: log cmdtail and filename BC passes to EXEC
    {
        let mut tail_vis = [0u8; 80];
        let vis_len = copy_len.min(80);
        for i in 0..vis_len {
            let b = tail[i];
            tail_vis[i] = if b < 32 || b >= 127 { b'?' } else { b };
        }
        dos_trace!("EXEC prog={:?} cmdtail_len={} tail={:?}",
            core::str::from_utf8(prog_name).unwrap_or("?"),
            copy_len,
            core::str::from_utf8(&tail_vis[..vis_len]).unwrap_or("?"));
    }

    // --- DOS program: in-process exec (shared address space) ---
    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    // ELF binaries need a separate address space — route through fork_exec.
    let is_elf = buf.len() >= 4 && buf[0..4] == [0x7F, b'E', b'L', b'F'];
    crate::dbg_println!("  exec_program: {:?} size={} elf={}", core::str::from_utf8(prog_name), size, is_elf);
    if is_elf {
        return fork_exec(dos, prog_name, kt);
    }

    let is_exe = is_mz_exe(&buf);
    // Layout the child's two arenas above the parent's heap end: env block
    // first (0x10 paragraphs), then PSP+code/BSS. `map_psp` places env at
    // `psp_seg - 0x10`, so `child_seg = heap_seg + 0x10` keeps the env safely
    // inside the child's own allocation and never inside parent memory.
    let child_seg = dos.heap_seg + 0x10;
    crate::dbg_println!("  exec_program: {:?} size={} exe={} child_seg={:04X} parent_psp={:04X}",
        core::str::from_utf8(prog_name), size, is_exe, child_seg, dos.current_psp);

    // Resolve the DOS-form absolute path for the env program-path suffix.
    // Must be drive-qualified uppercase (e.g. "C:\BIN\PROG.EXE") — DOS
    // extenders derive their cwd estimate from this field.
    let mut abs_dos = [0u8; dfs::DFS_PATH_MAX];
    let abs_len = dos.dfs.resolve(prog_name, &mut abs_dos).unwrap_or(0);

    // Snapshot parent's env block. In PM the parent's PSP[0x2C] may hold a
    // selector (32-bit client) and dos.current_psp is PSP_SEL — read the
    // captured RM env paragraph from DpmiState. In RM PSP[0x2C] is the RM
    // segment. Same address space here, but read into a Vec so map_psp's
    // signature matches the cross-address-space fork+exec path.
    let parent_psp = dos.current_psp;
    let parent_env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if parent_psp == dpmi::PSP_SEL => dpmi.saved_rm_env,
        _ => unsafe { (((parent_psp as u32) * 16 + 0x2C) as *const u16).read_unaligned() },
    };
    let parent_env_vec = snapshot_env(parent_env_seg);
    let (cs, ip, ss, sp, end_seg) = if is_exe {
        match load_exe_at(child_seg, parent_psp, Some(&parent_env_vec), &buf, &abs_dos[..abs_len]) {
            Some(t) => t,
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 11;
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    } else {
        load_com_at(child_seg, parent_psp, Some(&parent_env_vec), &buf, &abs_dos[..abs_len])
    };

    // Copy command tail to child's PSP at child_seg:0080
    let child_psp = (child_seg as u32) << 4;
    unsafe {
        let tail_dst = (child_psp + 0x80) as *mut u8;
        *tail_dst = copy_len as u8;
        core::ptr::copy_nonoverlapping(tail.as_ptr(), tail_dst.add(1), copy_len);
        *tail_dst.add(1 + copy_len) = 0x0D;
    }

    // Save parent state. Parent's INT frame (IP/CS/FLAGS) is on the VM86
    // stack at current SS:SP. exec_return restores SS:SP so stub_dispatch
    // pops the frame and resumes the parent.
    let prev = dos.exec_parent.take();
    let parent_heap = dos.heap_seg;
    let parent_heap_base = dos.heap_base_seg;
    let parent_blocks = dos.dos_blocks.clone();
    dos.heap_seg = end_seg.max(dos.heap_seg);
    dos.heap_base_seg = dos.heap_seg;
    dos.dos_blocks.clear();
    dos.dta = (child_seg as u32) * 16 + 0x80;
    dos.current_psp = child_seg;
    dos.exec_parent = Some(ExecParent {
        ss: vm86_ss(regs),
        sp: vm86_sp(regs),
        ds: regs.ds as u16,
        es: regs.es as u16,
        heap_seg: parent_heap,
        heap_base_seg: parent_heap_base,
        psp: parent_psp,
        dos_blocks: parent_blocks,
        prev: prev.map(alloc::boxed::Box::new),
    });

    // Set child entry. Push child's CS:IP + FLAGS onto the child's stack
    // so that stub_dispatch's pop restores them correctly.
    regs.set_ss32(ss as u32);
    regs.set_sp32(sp as u32);
    let flags = vm86_flags(regs) as u16;
    vm86_push(regs, flags);
    vm86_push(regs, cs);
    vm86_push(regs, ip);
    regs.ds = child_seg as u64;
    regs.es = child_seg as u64;
    regs.clear_flag32(1);
    crate::dbg_println!("  exec_program loaded: cs:ip={:04X}:{:04X} ss:sp={:04X}:{:04X} end_seg={:04X} heap_seg={:04X}",
        cs, ip, ss, sp, end_seg, dos.heap_seg);
    thread::KernelAction::Done
}

/// DOS INT 21h/4B AL=03 — Load Overlay.
/// Loads a program into caller-chosen memory. No PSP, no control transfer,
/// no address-space changes. Parameter block at ES:BX:
///   WORD 0: load_segment  — where the file image goes
///   WORD 2: reloc_factor  — value added to each relocated word for MZ EXE
/// For .COM / flat binaries the file is copied verbatim at load_seg:0.
/// For MZ .EXE the load module is copied at load_seg:0 and each relocation
/// entry gets `reloc_factor` added (NOT load_seg — the spec leaves it to
/// the caller, e.g. Borland C passes the segment of the overlay frame).
fn exec_load_overlay(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // ASCIIZ filename at DS:DX
    let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = unsafe { *(addr as *const u8) };
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }
    let prog_name: &[u8] = &filename[..flen];

    // Parameter block at ES:BX — two WORDs.
    let pb = linear(dos, regs, regs.es as u16, regs.rbx as u32);
    let load_seg = unsafe { (pb as *const u16).read_unaligned() };
    let reloc_factor = unsafe { ((pb + 2) as *const u16).read_unaligned() };
    dos_trace!("D21 4B03 LOAD_OVERLAY prog={:?} load_seg={:04X} reloc_factor={:04X}",
        core::str::from_utf8(prog_name).unwrap_or("?"), load_seg, reloc_factor);

    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        dos_trace!("D21 4B03 open failed: {:?}", core::str::from_utf8(prog_name).unwrap_or("?"));
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    let load_base = (load_seg as u32) << 4;
    if is_mz_exe(&buf) {
        let data = &buf[..];
        let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
        let last_page_bytes = w(0x02) as u32;
        let total_pages = w(0x04) as u32;
        let reloc_count = w(0x06) as usize;
        let header_paragraphs = w(0x08) as u32;
        let reloc_offset = w(0x18) as usize;

        let file_size = if last_page_bytes == 0 {
            total_pages * 512
        } else {
            (total_pages - 1) * 512 + last_page_bytes
        };
        let header_size = header_paragraphs * 16;
        let load_size = file_size.saturating_sub(header_size) as usize;
        let reloc_end = reloc_offset + reloc_count * 4;

        if header_size as usize > data.len()
            || load_size > data.len() - header_size as usize
            || reloc_end > data.len()
        {
            dos_trace!("D21 4B03 bad MZ header");
            regs.rax = (regs.rax & !0xFFFF) | 11;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }

        let img = &data[header_size as usize..header_size as usize + load_size];
        unsafe {
            core::ptr::copy_nonoverlapping(img.as_ptr(), load_base as *mut u8, load_size);
        }
        // Apply relocations using caller's reloc_factor (not load_seg).
        for i in 0..reloc_count {
            let entry = reloc_offset + i * 4;
            let off = w(entry) as u32;
            let seg = w(entry + 2) as u32;
            let a = load_base + (seg << 4) + off;
            unsafe {
                let p = a as *mut u16;
                let v = p.read_unaligned();
                p.write_unaligned(v.wrapping_add(reloc_factor));
            }
        }
        dos_trace!("D21 4B03 MZ loaded: load_size={} relocs={}", load_size, reloc_count);
    } else {
        // Raw / .COM: copy file verbatim at load_seg:0.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), load_base as *mut u8, buf.len());
        }
        dos_trace!("D21 4B03 raw loaded: size={}", buf.len());
    }

    regs.clear_flag32(1);
    thread::KernelAction::Done
}

/// Return from an EXEC'd child to the parent.
/// Restores the parent's CS:IP, SS:SP, DS, ES and clears carry (success).
fn exec_return(dos: &mut thread::DosState, regs: &mut Regs, parent: ExecParent) -> thread::KernelAction {
    crate::dbg_println!("  exec_return: restoring heap={:04X}->{:04X} psp={:04X}->{:04X} ss:sp={:04X}:{:04X}",
        dos.heap_seg, parent.heap_seg,
        dos.current_psp, parent.psp,
        parent.ss, parent.sp);
    regs.set_ss32(parent.ss as u32);
    regs.set_sp32(parent.sp as u32);
    regs.clear_flag32(1);
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    dos.heap_seg = parent.heap_seg;
    dos.heap_base_seg = parent.heap_base_seg;
    dos.current_psp = parent.psp;
    dos.dos_blocks = parent.dos_blocks;
    dos.exec_parent = parent.prev.map(|b| *b);
    thread::KernelAction::Done
}

/// Saved parent state for returning from EXEC'd child.
/// Chained via `prev` so nested exec works (e.g. DN.COM→DN.PRG→gfx.com).
pub struct ExecParent {
    pub ss: u16,
    pub sp: u16,
    pub ds: u16,
    pub es: u16,
    pub heap_seg: u16,
    pub heap_base_seg: u16,
    pub psp: u16,
    pub dos_blocks: alloc::vec::Vec<DosMemBlock>,
    pub prev: Option<alloc::boxed::Box<ExecParent>>,
}

/// Match a filename against a DOS wildcard pattern (e.g. "*.*", "*.EXE").
/// Case-insensitive. Supports '*' and '?' wildcards.
fn dos_wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    // Convert both pattern and name to 11-byte FCB format (8.3, space-padded)
    // then compare. In FCB format, '?' matches any char including space (padding).
    let to_fcb = |s: &[u8]| -> [u8; 11] {
        let mut fcb = [b' '; 11];
        let mut i = 0;
        let mut pos = 0;
        // Base name (up to 8 chars)
        while i < s.len() && s[i] != b'.' && pos < 8 {
            if s[i] == b'*' {
                while pos < 8 { fcb[pos] = b'?'; pos += 1; }
                i += 1;
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        // Skip to dot
        while i < s.len() && s[i] != b'.' { i += 1; }
        if i < s.len() && s[i] == b'.' { i += 1; }
        // Extension (up to 3 chars)
        pos = 8;
        while i < s.len() && pos < 11 {
            if s[i] == b'*' {
                while pos < 11 { fcb[pos] = b'?'; pos += 1; }
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        fcb
    };

    let pat_fcb = to_fcb(pattern);
    let name_fcb = to_fcb(name);

    for i in 0..11 {
        if pat_fcb[i] != b'?' && pat_fcb[i] != name_fcb[i] {
            return false;
        }
    }
    true
}

/// Resolve a raw DOS path to a VFS path for OPEN (all components must exist).
/// Returns `([u8; DFS_PATH_MAX], len)` on success, DOS error code on failure
/// (2 = file not found, 3 = path not found, 15 = invalid drive).
pub(crate) fn dfs_open_existing(dos: &thread::DosState, dos_in: &[u8])
    -> Result<([u8; dfs::DFS_PATH_MAX], usize), i32>
{
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    let vlen = dfs::DfsState::to_vfs_open(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// Resolve a raw DOS path to a VFS path for CREATE (final component may not
/// exist yet). Intermediate dirs must exist.
pub(crate) fn dfs_create_path(dos: &thread::DosState, dos_in: &[u8])
    -> Result<([u8; dfs::DFS_PATH_MAX], usize), i32>
{
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    let vlen = dfs::DfsState::to_vfs_create(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// FindFirst/FindNext helper: resume search from dos.find_idx,
/// updating it in place. Directory and pattern come from find_path.
fn find_matching_file(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // Split find_path into directory and pattern components.
    // find_path is an absolute VFS path like "DN/DN*.SWP" or "*.*".
    // The directory part includes any trailing slash; the pattern is
    // the basename (filespec with wildcards).
    let path_len = dos.find_path_len as usize;
    let full = &dos.find_path[..path_len];
    let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let dir_buf = {
        let mut b = [0u8; 96];
        b[..split].copy_from_slice(&full[..split]);
        (b, split)
    };
    let pat_buf = {
        let mut b = [0u8; 32];
        let plen = (path_len - split).min(b.len());
        b[..plen].copy_from_slice(&full[split..split + plen]);
        (b, plen)
    };
    let dir = &dir_buf.0[..dir_buf.1];
    let pat = &pat_buf.0[..pat_buf.1];

    let mut idx = dos.find_idx as usize;

    loop {
        match crate::kernel::vfs::readdir(dir, idx) {
            Some(entry) => {
                idx += 1;
                let name = &entry.name[..entry.name_len];
                if dos_wildcard_match(pat, name) {
                    dos.find_idx = idx as u16;
                    // Fill DTA at dos.dta
                    let dta = dos.dta;
                    // DTA layout (43 bytes):
                    //   0x00-0x14: reserved (unused by us — state lives in DosState)
                    //   0x15: attribute of matched file
                    //   0x16: file time (2 bytes)
                    //   0x18: file date (2 bytes)
                    //   0x1A: file size (4 bytes, little-endian)
                    //   0x1E: filename (13 bytes, null-terminated, 8.3 format)
                    unsafe {
                        let p = dta as *mut u8;
                        core::ptr::write_bytes(p, 0, 43);
                        *p.add(0x15) = if entry.is_dir { 0x10 } else { 0x20 };
                        (p.add(0x1A) as *mut u32).write_unaligned(entry.size);
                        let name_len = entry.name_len.min(12);
                        core::ptr::copy_nonoverlapping(
                            entry.name.as_ptr(),
                            p.add(0x1E),
                            name_len,
                        );
                        *p.add(0x1E + name_len) = 0;
                    }
                    regs.clear_flag32(1);
                    return thread::KernelAction::Done;
                }
            }
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 18; // no more files
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    }
}

/// Prepare the VM86 IVT for a new process.
///
/// The BIOS IVT at 0x0000-0x03FF is preserved from the COW copy of page 0,
/// so BIOS handlers in ROM (0xF0000-0xFFFFF) are accessible. When a BIOS
/// handler does I/O (IN/OUT), it traps through the IOPB to our virtual
/// PIC/keyboard, so BIOS code works transparently.
///
/// Stub area base in conventional memory (segment 0x0050, offset 0x0000)
pub(crate) const STUB_BASE: u32 = 0x0500;
pub(crate) const STUB_SEG: u16 = 0x0050;

/// Trap vector for all stubs (only one in TSS bitmap)
const STUB_INT: u8 = 0x31;

// Slot assignments in the unified CD 31 array (256 entries, 2 bytes each).
// Slot N at offset N*2 from segment base. After CD 31, IP = N*2+2, slot = (IP-2)/2.
const SLOT_XMS: u8 = 0x00;
const SLOT_DPMI_ENTRY: u8 = 0x01;
pub(crate) const SLOT_CALLBACK_RET: u8 = 0x02;
pub(crate) const SLOT_RAW_REAL_TO_PM: u8 = 0x03;
pub(crate) const SLOT_CB_ENTRY_BASE: u8 = 0x04;
pub(crate) const SLOT_CB_ENTRY_END: u8 = 0x14; // exclusive (16 callbacks)
/// Slots SLOT_HW_IRQ_BASE + N are entered from a stub-hooked IVT for hardware
/// IRQ N (0..15). INT 08h..0Fh and INT 70h..77h all funnel through here so
/// their BIOS handlers run on a private IRQ stack, not the user's stack.
pub(crate) const SLOT_HW_IRQ_BASE: u8 = 0xE0;
pub(crate) const SLOT_HW_IRQ_END: u8 = 0xF0; // exclusive (16 IRQs)
/// VM86-only: RM IRET target for implicit INT reflection (no PM handler
/// installed, default stub reflected to RM). `rm_int_return` restores PM
/// state and synthesizes the STI that DPMI spec requires IRQ handlers to
/// perform before IRET — our default stub is the nominal handler here.
pub(crate) const SLOT_RM_INT_RET: u8 = 0xFA;
/// VM86-only: BIOS HW IRQ handler IRET trampoline (restores pre-reflect SS:SP).
pub(crate) const SLOT_HW_IRQ_RET: u8 = 0xFC;
pub(crate) const SLOT_SAVE_RESTORE: u8 = 0xFD;
pub(crate) const SLOT_EXCEPTION_RET: u8 = 0xFE;
pub(crate) const SLOT_PM_TO_REAL: u8 = 0xFF;

/// Offset within STUB_SEG for a given slot number.
pub(crate) const fn slot_offset(slot: u8) -> u16 { (slot as u16) * 2 }

/// Dummy file handle returned for device "EMMXXXX0" (EMS detection)
const EMS_DEVICE_HANDLE: u16 = 0xFE;

pub fn setup_ivt() {
    // Unified stub array: 256 entries × 2 bytes (CD 31) at 0x0500-0x06FF.
    // Slot N at offset N*2. VM86 traps via TSS bitmap bit 31h; PM fires INT 31h (DPL=3).
    unsafe {
        let b = STUB_BASE as *mut u8;
        for i in 0..256u32 {
            *b.add((i * 2) as usize) = 0xCD;
            *b.add((i * 2 + 1) as usize) = STUB_INT;
        }
    }

    // Patch IVT entries to point to our stubs (IVT lives at linear 0x0000).
    // Save original BIOS HW IRQ vectors before we hook them — all 16 IRQs are
    // routed through private-stack slots so their BIOS handlers never run on
    // the user's (possibly tiny) stack.
    for irq in 0u8..16 {
        let vec = irq_to_vector(irq);
        let ip = read_u16(0, (vec as u32) * 4);
        let cs = read_u16(0, (vec as u32) * 4 + 2);
        unsafe { BIOS_HW_IRQ[irq as usize] = (cs, ip); }
        write_u16(0, (vec as u32) * 4, slot_offset(SLOT_HW_IRQ_BASE + irq));
        write_u16(0, (vec as u32) * 4 + 2, STUB_SEG);
    }
    for &int_num in &[0x13u8, 0x20, 0x21, 0x25, 0x26, 0x28, 0x2E, 0x2F, 0x67] {
        write_u16(0, (int_num as u32) * 4, slot_offset(int_num));
        write_u16(0, (int_num as u32) * 4 + 2, STUB_SEG);
    }

    // Set up fake DOS internal structures (List of Lists + System File Table)
    // so that DJGPP's fstat (which uses INT 21h/52h → SFT) can find file info.
    setup_lol_sft();

    // Scan upper memory to find free pages for UMB/EMS
    scan_uma();
}

// ── Low-memory layout (sequential from STUB_BASE) ──────────────────
// Stubs:     256 × 2 bytes       0x0500–0x06FF
// SYSPSP:    256 bytes           0x0700–0x07FF   (seg 0x70)
// LoL:       0x40 bytes          0x0800–0x083F   (seg 0x80)
// SFT:       6 + 20×59 = 1186   0x0840–0x0CE1
// CDS:       8 × 81 = 648       0x0CE2–0x0DD4
// IRQ stack: 256 bytes           0x0DE0–0x0EDF   (seg 0xDE)
// Env block: (COM_SEG-0x10)      0x0EE0–0x0EFF   (seg 0xEE)
// COM/EXE:   load area           0x0FE0–...      (seg 0xFE)
//
// SYSPSP is a minimal "system" PSP whose parent-PSP field points to itself,
// matching real DOS: COMMAND.COM's PSP[0x16] points to a distinct SYSPSP
// segment, and SYSPSP[0x16] self-references (terminating the chain).
// DPMILOAD checks grandparent != parent and refuses to run if they match,
// so we must never make the initial program self-parenting.
const SYSPSP_ADDR: u32 = STUB_BASE + 256 * 2;                     // 0x0700
const SYSPSP_SIZE: u32 = 256;
const SYSPSP_SEG: u16 = (SYSPSP_ADDR >> 4) as u16;                // 0x70
/// Offset within SYSPSP of the INDOS flag byte (permanently zero).
/// Placed in the "command tail" area since the system PSP never runs.
const INDOS_FLAG_OFFSET: u16 = 0xFE;
const LOL_ADDR: u32 = SYSPSP_ADDR + SYSPSP_SIZE;                  // 0x0800
const LOL_SIZE: u32 = 0x40;
const SFT_ADDR: u32 = LOL_ADDR + LOL_SIZE;                        // 0x0840
const SFT_ENTRIES: u16 = 20;
const SFT_ENTRY_SIZE: u32 = 59;
const SFT_SIZE: u32 = 6 + SFT_ENTRIES as u32 * SFT_ENTRY_SIZE;    // 1186
const CDS_ADDR: u32 = SFT_ADDR + SFT_SIZE;                        // 0x0CE2
const CDS_ENTRY_SIZE: u32 = 81;
const NUM_DRIVES: u8 = 8; // A..H (H: = hostfs)
const CDS_SIZE: u32 = NUM_DRIVES as u32 * CDS_ENTRY_SIZE;         // 243
const DOS_AREA_END: u32 = CDS_ADDR + CDS_SIZE;                    // 0x0DD5
/// Private stack for hardware IRQ reflection (avoids using program's stack).
/// 256 bytes, paragraph-aligned. Stack grows down, so SP starts at top.
const IRQ_STACK_ADDR: u32 = (DOS_AREA_END + 15) & !15;            // 0x0DE0
const IRQ_STACK_SIZE: u32 = 256;
pub(crate) const IRQ_STACK_SEG: u16 = (IRQ_STACK_ADDR >> 4) as u16;
pub(crate) const IRQ_STACK_TOP: u16 = IRQ_STACK_SIZE as u16;      // SP starts here
const LOL_SEG: u16 = (LOL_ADDR >> 4) as u16;

/// Write a little-endian u16 to an arbitrary (possibly unaligned) address.
unsafe fn write_le16(addr: *mut u8, val: u16) {
    unsafe {
        *addr = val as u8;
        *addr.add(1) = (val >> 8) as u8;
    }
}

/// Write a little-endian u32 to an arbitrary (possibly unaligned) address.
unsafe fn write_le32(addr: *mut u8, val: u32) {
    unsafe {
        *addr = val as u8;
        *addr.add(1) = (val >> 8) as u8;
        *addr.add(2) = (val >> 16) as u8;
        *addr.add(3) = (val >> 24) as u8;
    }
}

fn setup_lol_sft() {
    unsafe {
        // Zero the whole DOS area (SYSPSP + LoL + SFT + CDS)
        let total = (DOS_AREA_END - SYSPSP_ADDR) as usize;
        core::ptr::write_bytes(SYSPSP_ADDR as *mut u8, 0, total);

        // SYSPSP: a stand-in for COMMAND.COM's PSP. Its parent-PSP field
        // points to itself, terminating the PSP parent chain. Real DOS
        // does the same for COMMAND.COM. This is what the initial program's
        // PSP[0x16] points to, so DPMILOAD's grandparent check succeeds
        // (grandparent = SYSPSP_SEG != parent = PSP_SEGMENT).
        let syspsp = SYSPSP_ADDR as *mut u8;
        *syspsp.add(0) = 0xCD;                // INT 20h
        *syspsp.add(1) = 0x20;
        *syspsp.add(2) = 0x00;                // top of memory = 0xA000
        *syspsp.add(3) = 0xA0;
        write_le16(syspsp.add(0x16), SYSPSP_SEG); // self-reference

        let lol = LOL_ADDR as *mut u8;
        // LoL+04h: far pointer to SFT
        write_le16(lol.add(4), (SFT_ADDR & 0xF) as u16);
        write_le16(lol.add(6), (SFT_ADDR >> 4) as u16);
        // LoL+16h: far pointer to CDS array
        write_le16(lol.add(0x16), (CDS_ADDR & 0xF) as u16);
        write_le16(lol.add(0x18), (CDS_ADDR >> 4) as u16);
        // LoL+20h: number of block devices
        *lol.add(0x20) = 1; // one block device (C:)
        // LoL+21h: LASTDRIVE
        *lol.add(0x21) = NUM_DRIVES;

        // SFT header: next pointer = FFFF:FFFF (end of chain), count = SFT_ENTRIES
        let sft = SFT_ADDR as *mut u8;
        write_le32(sft, 0xFFFFFFFF);
        write_le16(sft.add(4), SFT_ENTRIES);

        // Pre-populate entries 0-2 as character devices (stdin/stdout/stderr)
        for i in 0..3u32 {
            let entry = sft.add(6 + (i * SFT_ENTRY_SIZE) as usize);
            write_le16(entry, 1); // refcount = 1
            write_le16(entry.add(5), 0x80 | if i == 0 { 1 } else { 2 }); // device info
        }

        // CDS entries: A: and B: invalid (flags=0), C: valid
        let cds = CDS_ADDR as *mut u8;
        // C: entry (index 2)
        let c_entry = cds.add(2 * CDS_ENTRY_SIZE as usize);
        // Path: "C:\" (67-byte ASCIIZ field)
        *c_entry.add(0) = b'C';
        *c_entry.add(1) = b':';
        *c_entry.add(2) = b'\\';
        // +43h: flags — 0x4000 = valid physical drive
        write_le16(c_entry.add(0x43), 0x4000);
        // +4Fh: backslash offset (points to the '\' in "C:\")
        write_le16(c_entry.add(0x4F), 2);

        // H: entry (index 7) — hostfs
        let h_entry = cds.add(7 * CDS_ENTRY_SIZE as usize);
        *h_entry.add(0) = b'H';
        *h_entry.add(1) = b':';
        *h_entry.add(2) = b'\\';
        write_le16(h_entry.add(0x43), 0x4000);
        write_le16(h_entry.add(0x4F), 2);
    }
}

/// Populate SFT entry for a newly opened file handle.
fn sft_set_file(handle: u16, size: u32) {
    if handle as u32 >= SFT_ENTRIES as u32 { return; }
    unsafe {
        let entry = (SFT_ADDR as *mut u8).add(6 + handle as usize * SFT_ENTRY_SIZE as usize);
        write_le16(entry.add(0x00), 1);       // refcount
        write_le16(entry.add(0x02), 0);       // open mode (read)
        *entry.add(0x04) = 0x20;              // attribute = archive
        write_le16(entry.add(0x05), 0x0000);  // device info = file
        write_le16(entry.add(0x0D), 0x6000);  // time: 12:00:00
        write_le16(entry.add(0x0F), 0x5C76);  // date: 2026-03-22
        write_le32(entry.add(0x11), size);    // file size
        write_le32(entry.add(0x15), 0);       // position = 0
    }
}

/// Clear SFT entry when a file handle is closed.
fn sft_clear(handle: u16) {
    if handle as u32 >= SFT_ENTRIES as u32 { return; }
    unsafe {
        let entry = (SFT_ADDR as *mut u8).add(6 + handle as usize * SFT_ENTRY_SIZE as usize);
        write_le16(entry, 0); // refcount = 0
    }
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Map the PSP and environment for a DOS program.
///
/// - PSP (256 bytes) at `psp_seg:0000`.
/// - Environment block 256 bytes before PSP (at `(psp_seg - 0x10):0000`).
///
/// Per DOS EXEC (AH=4B) semantics the child always gets a FRESH env arena:
///   - If `parent_env_data` is `Some`, copy its variable strings (up to `00 00`).
///     The slice is the raw env block (kernel-side snapshot — must survive the
///     parent's address space being torn down across fork+exec).
///   - Otherwise write default COMSPEC/PATH.
///   - Always append the DOS 3+ suffix `01 00 <prog_name> 00` — child's own
///     path, not the parent's.
///
/// Pages are written via demand paging (ring-1 writes trigger page faults
/// that allocate fresh pages at ring 0).
fn map_psp(psp_seg: u16, parent_psp: u16, parent_env_data: Option<&[u8]>, prog_name: &[u8]) {
    let psp_addr = (psp_seg as usize) << 4;

    // Always allocate a fresh env arena for the child at psp_seg - 0x10.
    // Env arena is 0x10 paragraphs = 256 bytes. Reserve space for the DOS 3+
    // suffix (2 + prog_name + 1 NUL); cap the inherited-variable copy so it
    // always fits.
    const ENV_SIZE: usize = 256;
    let suffix_need = 2 + prog_name.len() + 1;
    let vars_cap = ENV_SIZE.saturating_sub(suffix_need);
    let env_seg: u16 = psp_seg - 0x10;
    let env_ptr = ((env_seg as usize) << 4) as *mut u8;
    unsafe { core::ptr::write_bytes(env_ptr, 0, ENV_SIZE); }
    let mut off = 0usize;
    if let Some(src) = parent_env_data {
        // Copy parent's variable strings up to and including the `00 00` terminator.
        let mut i = 0usize;
        let mut prev_was_nul = false;
        while off < vars_cap && i < src.len() {
            let b = src[i];
            unsafe { *env_ptr.add(off) = b; }
            i += 1; off += 1;
            if b == 0 && prev_was_nul { break; }
            prev_was_nul = b == 0;
        }
    } else {
        // Initial program — synthesize default env.
        for src in [&b"COMSPEC=C:\\COMMAND.COM\0"[..], &b"PATH=C:\\\0"[..]] {
            if off + src.len() > vars_cap { break; }
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), env_ptr.add(off), src.len()); }
            off += src.len();
        }
        unsafe { *env_ptr.add(off) = 0; }   // double-NUL terminator
        off += 1;
    }
    // DOS 3+ suffix: word 01 00, then child's own program pathname, then NUL.
    // Drive-qualified uppercase DOS form (e.g. "C:\BIN\PROG.EXE"). DOS
    // extenders (BC, dos4gw, dos16m) parse this field back to derive a
    // cwd estimate — it must be in real DOS form, not VFS-form.
    unsafe {
        *env_ptr.add(off) = 0x01; *env_ptr.add(off + 1) = 0x00;
    }
    off += 2;
    for &b in prog_name {
        if off + 1 >= ENV_SIZE { break; }
        unsafe { *env_ptr.add(off) = b; }
        off += 1;
    }
    unsafe { *env_ptr.add(off) = 0; }

    // Parent-PSP segment for PSP[0x16]. For initial load (no real parent),
    // point at SYSPSP — matches real DOS, where COMMAND.COM's parent is the
    // system PSP (not itself). DPMILOAD relies on grandparent != parent.
    let parent_field = if psp_seg == parent_psp { SYSPSP_SEG } else { parent_psp };

    let psp_ptr = psp_addr as *mut u8;
    unsafe {
        core::ptr::write_bytes(psp_ptr, 0, 256);
        *psp_ptr.add(0) = 0xCD; // INT 20h
        *psp_ptr.add(1) = 0x20;
        *psp_ptr.add(2) = 0x00; // top of memory = 0xA000
        *psp_ptr.add(3) = 0xA0;
        // Parent PSP segment
        *psp_ptr.add(0x16) = parent_field as u8;
        *psp_ptr.add(0x17) = (parent_field >> 8) as u8;
        *psp_ptr.add(0x2C) = env_seg as u8;
        *psp_ptr.add(0x2D) = (env_seg >> 8) as u8;
        // JFT: pointer at PSP+0x18 → inline JFT at PSP+0x34
        *(psp_ptr.add(0x18) as *mut u16) = 0x0034; // offset
        *(psp_ptr.add(0x1A) as *mut u16) = psp_seg; // segment
        *(psp_ptr.add(0x32) as *mut u16) = 20; // max open files
        // Inline JFT (20 bytes at PSP+0x34): 0/1/2 = stdin/stdout/stderr, rest = 0xFF
        *psp_ptr.add(0x34) = 0; // stdin → SFT 0
        *psp_ptr.add(0x35) = 1; // stdout → SFT 1
        *psp_ptr.add(0x36) = 2; // stderr → SFT 2
        for i in 3..20usize {
            *psp_ptr.add(0x34 + i) = 0xFF; // closed
        }
        *psp_ptr.add(0x80) = 0; // command tail length
        *psp_ptr.add(0x81) = 0x0D; // CR
    }

    // TRACE: dump env block (first 160 bytes after suffix marker) and prog_name
    unsafe {
        let env_base = (env_seg as u32) * 16;
        let p = env_base as *const u8;
        let mut dump = [0u8; 80];
        for i in 0..80usize {
            let b = *p.add(i);
            dump[i] = if b == 0 { b'.' } else if b < 32 || b >= 127 { b'?' } else { b };
        }
        dos_trace!("map_psp psp={:04X} env={:04X} parent_psp={:04X} prog={:?} env[0..80]={:?}",
            psp_seg, env_seg, parent_psp,
            core::str::from_utf8(prog_name).unwrap_or("?"),
            core::str::from_utf8(&dump).unwrap_or("?"));
    }
}

/// Snapshot a DOS env block (variable strings up to and including the
/// `00 00` terminator) into a heap Vec. Used so the parent's env survives
/// the COW fork's address-space teardown that happens before `map_psp` runs
/// in the child.
pub fn snapshot_env(env_seg: u16) -> alloc::vec::Vec<u8> {
    let src = ((env_seg as usize) << 4) as *const u8;
    let mut out = alloc::vec::Vec::new();
    let mut prev_was_nul = false;
    let mut i = 0usize;
    // Cap at one paragraph-aligned env arena (256 bytes) to bound work
    // even if the terminator is absent.
    while i < 32768 {
        let b = unsafe { *src.add(i) };
        out.push(b);
        i += 1;
        if b == 0 && prev_was_nul { break; }
        prev_was_nul = b == 0;
    }
    out
}

/// Load a DOS binary (.COM or .EXE) and initialize the thread for VM86 mode.
/// Handles full address space setup: clean + low mem + IVT + binary load + thread init.
/// Called from kernel exec fan-out. `parent_env_data` is the parent's env block
/// snapshot (taken before the address space was torn down), or None for an
/// initial load with no parent (synthesizes default COMSPEC/PATH).
pub fn exec_dos_into(tid: usize, data: &[u8], is_exe: bool, prog_name: &[u8], parent_env_data: Option<&[u8]>, parent_cwd: &[u8]) {
    use crate::kernel::{startup, thread};

    startup::arch_user_clean();
    startup::arch_map_low_mem();
    setup_ivt();

    // prog_name is VFS-form (from exec fan-out); convert to drive-qualified
    // DOS form for the PSP environment suffix. DOS extenders parse that
    // field back, so it must look like "C:\BIN\PROG.EXE".
    let mut dos_name = [0u8; dfs::DFS_PATH_MAX];
    let dos_len = dfs::vfs_to_dos(prog_name, &mut dos_name);
    let dos_name = &dos_name[..dos_len];

    let (cs, ip, ss, sp, end_seg) = if is_exe && is_mz_exe(data) {
        load_exe(data, dos_name, parent_env_data).unwrap_or_else(|| {
            crate::println!("Invalid MZ EXE");
            (0, 0, 0, 0, 0)
        })
    } else {
        load_com(data, dos_name, parent_env_data)
    };

    let current = thread::get_thread(tid).unwrap();
    thread::init_process_thread_vm86(current, PSP_SEGMENT, cs, ip, ss, sp, parent_cwd);
    let dos_state = current.dos_mut();
    dos_reset_blocks(dos_state, end_seg);
    dos_state.dta = (PSP_SEGMENT as u32) * 16 + 0x80;
    current.kernel.symbols = None;
}

/// Check if data starts with the MZ signature.
pub fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Load a .COM binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// Layout:
///   Segment PSP_SEGMENT:
///     0x0000-0x00FF: PSP (Program Segment Prefix)
///     0x0100-...:    .COM binary code (= segment (PSP_SEGMENT+0x10):0000)
///   Stack at PSP_SEGMENT:COM_SP (top of segment)
pub fn load_com(data: &[u8], prog_name: &[u8], parent_env_data: Option<&[u8]>) -> (u16, u16, u16, u16, u16) {
    load_com_at(PSP_SEGMENT, PSP_SEGMENT, parent_env_data, data, prog_name)
}

/// Returns (cs, ip, ss, sp, end_seg) — caller sets heap_seg = end_seg.
fn load_com_at(psp_seg: u16, parent_psp: u16, parent_env_data: Option<&[u8]>, data: &[u8], prog_name: &[u8]) -> (u16, u16, u16, u16, u16) {
    map_psp(psp_seg, parent_psp, parent_env_data, prog_name);
    let end_seg = psp_seg.wrapping_add(0x1000);

    // Load .COM code at psp_seg:0x100 (= (psp_seg+0x10):0).
    let load_addr = ((psp_seg as u32) << 4) + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            data.len(),
        );
    }

    (psp_seg, COM_OFFSET, psp_seg, COM_SP, end_seg)
}

/// Load an MZ .EXE binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// MZ header layout (first 28 bytes):
///   0x00: 'MZ' signature
///   0x02: bytes on last page (0 = full 512-byte page)
///   0x04: total pages (512 bytes each, includes header)
///   0x06: relocation count
///   0x08: header size in paragraphs (16 bytes each)
///   0x0E: initial SS (relative to load segment)
///   0x10: initial SP
///   0x14: initial IP
///   0x16: initial CS (relative to load segment)
///   0x18: relocation table offset
pub fn load_exe(data: &[u8], prog_name: &[u8], parent_env_data: Option<&[u8]>) -> Option<(u16, u16, u16, u16, u16)> {
    load_exe_at(PSP_SEGMENT, PSP_SEGMENT, parent_env_data, data, prog_name)
}

/// Returns (cs, ip, ss, sp, end_seg) — caller sets heap_seg = end_seg.
fn load_exe_at(psp_seg: u16, parent_psp: u16, parent_env_data: Option<&[u8]>, data: &[u8], prog_name: &[u8]) -> Option<(u16, u16, u16, u16, u16)> {
    if data.len() < 28 {
        return None;
    }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
    let min_extra = w(0x0A) as u32;
    let init_ss = w(0x0E);
    let init_sp = w(0x10);
    let init_ip = w(0x14);
    let init_cs = w(0x16);
    let reloc_offset = w(0x18) as usize;

    // Calculate file size and load module offset/size
    let file_size = if last_page_bytes == 0 {
        total_pages * 512
    } else {
        (total_pages - 1) * 512 + last_page_bytes
    };
    let header_size = header_paragraphs * 16;
    let load_size = file_size.saturating_sub(header_size) as usize;

    if header_size as usize > data.len() || load_size > data.len() - header_size as usize {
        return None;
    }

    // Load module starts 0x10 paragraphs (256 bytes) after the PSP.
    let load_segment = psp_seg + 0x10;

    map_psp(psp_seg, parent_psp, parent_env_data, prog_name);

    // Set initial heap past the loaded program (PSP + load image + min extra/BSS)
    let load_paras = ((load_size as u32 + 15) / 16) as u16;
    let end_seg = load_segment.wrapping_add(load_paras).wrapping_add(min_extra as u16);

    // Copy load module
    let load_base = (load_segment as u32) << 4;
    let load_data = &data[header_size as usize..header_size as usize + load_size];
    unsafe {
        core::ptr::copy_nonoverlapping(
            load_data.as_ptr(),
            load_base as *mut u8,
            load_size,
        );
    }

    // Zero BSS from end of load module up to end_seg. DOS itself does not
    // do this — the MZ loader just copies the image and allocates extra
    // paragraphs uninitialized; real CRTs (Borland c0, Watcom cstart, ...)
    // zero BSS from linker-emitted symbols. We zero here to be defensive
    // on re-exec, where the backing pages may retain prior-run data.
    let bss_start = load_base + load_size as u32;
    let bss_end = (end_seg as u32) << 4;
    if bss_end > bss_start {
        unsafe {
            core::ptr::write_bytes(bss_start as *mut u8, 0, (bss_end - bss_start) as usize);
        }
    }

    // Apply relocations: each entry is (offset, segment) within the load module.
    // Add load_segment to the 16-bit word at that address.
    let reloc_end = reloc_offset + reloc_count * 4;
    if reloc_end > data.len() {
        return None;
    }
    for i in 0..reloc_count {
        let entry = reloc_offset + i * 4;
        let off = w(entry) as u32;
        let seg = w(entry + 2) as u32;
        let addr = load_base + (seg << 4) + off;
        unsafe {
            let p = addr as *mut u16;
            let val = p.read_unaligned();
            p.write_unaligned(val.wrapping_add(load_segment));
        }
    }

    let cs = init_cs.wrapping_add(load_segment);
    let ss = init_ss.wrapping_add(load_segment);

    Some((cs, init_ip, ss, init_sp, end_seg))
}
