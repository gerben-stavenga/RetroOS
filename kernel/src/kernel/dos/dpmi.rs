//! DPMI (DOS Protected Mode Interface) 0.9 emulation
//!
//! Minimal DPMI server for DOS4GW/DOOM: mode switch, LDT descriptors,
//! linear memory allocation, real-mode interrupt simulation, and I/O
//! virtualization from 32-bit protected mode.
//!
//! A DOS thread starts in VM86 (real mode), detects DPMI via INT 2F/1687h,
//! then calls the entry point to switch to 32-bit protected mode. INT 31h
//! services are dispatched directly from the event loop (IDT DPL=3 for
//! vectors 0x30-0xFF). GP faults from protected mode (#13 with Mode32)
//! handle sensitive instructions: I/O, CLI/STI, PUSHF/POPF, HLT, IRET.

extern crate alloc;

use alloc::boxed::Box;
use crate::kernel::thread;
use crate::kernel::dos;
use super::machine;
use crate::kernel::startup;
use crate::Regs;

use super::dos_trace;

/// Number of LDT entries
pub(super) const LDT_ENTRIES: usize = 8192;

/// LDT index of the "low memory" selector. Base=0, limit=1MB, 16-bit.
/// DOS handlers that need to return a pointer to a fixed low-memory byte
/// (INDOS flag, LOL, IVT vectors) use this as ES; BX is the linear address.
///
/// Internal-host slots are placed at LDT[200+] (well outside the LDT[1..127]
/// range that CWSDPMI uses) so DOS/4GW's `lar`-probe of low slots sees the
/// CWSDPMI-shaped empty range and we don't collide with client allocations.
pub const LOW_MEM_LDT_IDX: usize = 5;

/// Selector value for LOW_MEM_LDT_IDX (TI=1, RPL=3).
pub const LOW_MEM_SEL: u16 = ((LOW_MEM_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT index of the PSP selector (ES on return from dpmi_enter).
/// Matches CWSDPMI's l_apsp = 18.
/// Matches CWSDPMI's `l_apsp = 18` so DOS/4GW's first dynamic alloc lands at
/// LDT[20] (sel 0xA7) — same as CWSDPMI.
pub const PSP_LDT_IDX: usize = 18;

/// Selector value for PSP_LDT_IDX (TI=1, RPL=3).
pub const PSP_SEL: u16 = ((PSP_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT index of the vector-default stub segment. Base=0, limit=0x0FFF, 16-bit.
/// Every entry in `pm_vectors` that the client has not installed points into
/// this segment at STUB_BASE + vec*2 (a `CD 31` that traps back to the host).
/// When dpmi_int31 sees CS == this selector, the trap is a default-vector
/// reflection: route to `vector_stub_reflect` which dispatches the vector to
/// the real-mode IVT.
///
/// Placed at LDT[200] — well above the CWSDPMI [1..127] range.
pub const VECTOR_STUB_LDT_IDX: usize = 4;

/// LDT index of the host "special stub" segment. Base=0, limit=0x0FFF, 16-bit.
/// Addresses handed back to the client for host services (0305h PM save/restore,
/// 0306h PM-to-real switch) and the `SLOT_EXCEPTION_RET` return trampoline
/// live in this segment. When dpmi_int31 sees CS == this selector,
/// pm_stub_dispatch routes by slot. Keeping this separate from
/// VECTOR_STUB_LDT_IDX prevents the ambiguity between default-vector stubs
/// 0xFB-0xFF and the special slots at the same offsets.
pub const SPECIAL_STUB_LDT_IDX: usize = 7;

/// Selector value (TI=1, RPL=3) for the kernel-owned VECTOR_STUB segment
/// that holds the per-vector default INT-reflection stubs.
pub(super) const VECTOR_STUB_SEL: u16 = ((VECTOR_STUB_LDT_IDX as u16) << 3) | 4 | 3;

/// Selector value (TI=1, RPL=3) for the kernel-owned SPECIAL_STUB segment
/// that holds the host's PM return trampolines (HW-IRQ unwind, exception
/// return, raw mode switch, save/restore).
pub(super) const SPECIAL_STUB_SEL: u16 = ((SPECIAL_STUB_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT indices for the client's initial CS/DS/SS. Matches CWSDPMI's
/// l_acode=16, l_adata=17, l_apsp=18 layout. SS lives at l_aenv=19 (CWSDPMI
/// uses that slot for the env pointer; RetroOS doesn't separately allocate
/// env so we reuse 19 for SS). LDT[1..15] stays null so DOS/4GW's "lar
/// probe" sees the CWSDPMI-shaped empty range.
pub const CLIENT_CS_LDT_IDX: usize = 16;
pub const CLIENT_DS_LDT_IDX: usize = 17;
pub const CLIENT_SS_LDT_IDX: usize = 19;

/// LDT indices for the kernel-shared host stack — three aliasing
/// selectors at the same base (`dos::host_stack_base()`), one with B=0
/// for 16-bit clients and one with B=1 for 32-bit clients. The bitness
/// difference only controls whether push/pop uses SP or ESP; the
/// physical buffer is the same. The third alias is a VM86 paragraph
/// (`dos::host_stack_vm86_paragraph()`) consumed when ring-0 transiently
/// runs VM86 code (e.g. nested 0x0302 RM excursion). Host-internal —
/// not handed to the client.
pub const HOST_STACK_PM16_LDT_IDX: usize = 8;
pub const HOST_STACK_PM32_LDT_IDX: usize = 9;
pub const HOST_STACK_PM16_SEL: u16 = ((HOST_STACK_PM16_LDT_IDX as u16) << 3) | 4 | 3;
pub const HOST_STACK_PM32_SEL: u16 = ((HOST_STACK_PM32_LDT_IDX as u16) << 3) | 4 | 3;

// ─── Cross-mode save lane on host_stack ─────────────────────────────────
//
// Every PM-handler entry from a non-host-stack mode (HW IRQ outermost or
// BIOS-mid-handler) pushes a `ModeSave` capturing the interrupted regs
// onto host_stack at `pc.host_stack_sp`, then an iret_frame above it
// targeting `SLOT_PM_IRET`. The handler's IRET pops the iret_frame
// (hardware), traps to the kernel via the stub, kernel pops the ModeSave
// and restores. Pure nested-on-host-stack entries (handler-mid-execution
// IRQ where regs.SS is already HOST_STACK_PM) skip the ModeSave — the
// outer handler's CS:EIP and stack already hold the chain, so a plain
// hardware IRET back to outer is sufficient.

// CPU state snapshots and the primitives that read/write them
// (`push_save` / `pop_save` / `pop_save_at` / `peek_save_at` /
// `consume_save_at`) live in [`super::mode_transitions`]. This module
// composes them with DPMI policy.

/// Stub-frame for `SLOT_RM_IRET_CALL` — pushed above the `ModeSave` by
/// every explicit PM→RM-call entry (`0300/01/02` and `callback_entry`).
/// On unwind, `rm_iret_call` writes the post-RM regs into the
/// RmCallStruct at `rm_struct_addr`, then restores the saved GP regs
/// (PM caller's for `0300/01/02`; RM caller's for `callback_entry`).
/// Other slots (`SLOT_PM_IRET`, `SLOT_RM_IRET_REFLECT`) don't need this
/// — handler preservation / spec round-trip handle their GP regs.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CallStubFrame {
    rm_struct_addr: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    /// 1 if the recipe pushed an `RmSnapshot` (because BIOS will run
    /// on our dedicated RM stack); 0 if the user supplied their own
    /// SS:SP via the RmCallStruct (BIOS runs there, our dedicated
    /// stack is untouched, no snapshot needed). On unwind the
    /// SLOT_RM_IRET_CALL handler conditionally pops the snapshot.
    used_dedicated_rm: u32,
}

const CALL_STUB_SIZE: u32 = core::mem::size_of::<CallStubFrame>() as u32;

impl CallStubFrame {
    fn capture(regs: &Regs, rm_struct_addr: u32, used_dedicated_rm: bool) -> Self {
        Self {
            rm_struct_addr,
            eax: regs.rax as u32,
            ebx: regs.rbx as u32,
            ecx: regs.rcx as u32,
            edx: regs.rdx as u32,
            esi: regs.rsi as u32,
            edi: regs.rdi as u32,
            ebp: regs.rbp as u32,
            used_dedicated_rm: used_dedicated_rm as u32,
        }
    }

    fn restore_gp(&self, regs: &mut Regs) {
        regs.rax = (regs.rax & !0xFFFFFFFF) | self.eax as u64;
        regs.rbx = (regs.rbx & !0xFFFFFFFF) | self.ebx as u64;
        regs.rcx = (regs.rcx & !0xFFFFFFFF) | self.ecx as u64;
        regs.rdx = (regs.rdx & !0xFFFFFFFF) | self.edx as u64;
        regs.rsi = (regs.rsi & !0xFFFFFFFF) | self.esi as u64;
        regs.rdi = (regs.rdi & !0xFFFFFFFF) | self.edi as u64;
        regs.rbp = (regs.rbp & !0xFFFFFFFF) | self.ebp as u64;
    }
}

/// Write a `CallStubFrame` at the cursor. Returns the new (lower) cursor.
fn host_stack_write_call_args(cursor: u32, frame: CallStubFrame) -> u32 {
    let new_cursor = cursor - CALL_STUB_SIZE;
    let addr = dos::host_stack_base() + new_cursor;
    unsafe { core::ptr::write_unaligned(addr as *mut CallStubFrame, frame); }
    new_cursor
}

/// Read a `CallStubFrame` at the cursor.
fn host_stack_read_call_args(cursor: u32) -> CallStubFrame {
    let addr = dos::host_stack_base() + cursor;
    unsafe { core::ptr::read_unaligned(addr as *const CallStubFrame) }
}

/// Push an IRET frame for a PM handler entry at the given cursor. Returns
/// the new cursor. Width follows client bitness per DPMI 0.9 §10.6.
fn host_stack_write_iret(cursor: u32, client_use32: bool,
                         ret_eip: u32, ret_cs: u16, ret_flags: u32) -> u32 {
    let frame_size: u32 = if client_use32 { 12 } else { 6 };
    let new_cursor = cursor - frame_size;
    let addr = dos::host_stack_base() + new_cursor;
    unsafe {
        if client_use32 {
            let p = addr as *mut u32;
            core::ptr::write_unaligned(p,        ret_eip);
            core::ptr::write_unaligned(p.add(1), ret_cs as u32);
            core::ptr::write_unaligned(p.add(2), ret_flags);
        } else {
            let p = addr as *mut u16;
            core::ptr::write_unaligned(p,        ret_eip as u16);
            core::ptr::write_unaligned(p.add(1), ret_cs);
            core::ptr::write_unaligned(p.add(2), ret_flags as u16);
        }
    }
    new_cursor
}

/// Maximum DPMI memory blocks
const MAX_MEM_BLOCKS: usize = 256;
/// Base address for DPMI linear memory allocations
const MEM_BASE: u32 = 0x0050_0000;

/// Maximum number of real-mode callbacks (INT 31h/0303h)
const MAX_CALLBACKS: usize = 16;

/// Per-thread DPMI state (heap-allocated, attached to Thread.dpmi).
/// The LDT and `pm_vectors` live on `DosState` — always allocated at thread
/// init — so DPMI entry/exit doesn't have to (re)allocate them. See
/// `feedback_ldt_in_dpmi.md`.
pub struct DpmiState {
    /// Linear memory blocks allocated via INT 31h/0501h
    pub mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub mem_next: u32,
    /// Hidden real-mode state for raw mode switches (INT 31h/0305h/0306h).
    pub raw_rm_state: RawModeState,
    /// Hidden protected-mode state for raw mode switches (INT 31h/0305h/0306h).
    pub raw_pm_state: RawModeState,
    /// Exception handler vectors (set via INT 31h/0203h)
    /// (selector, offset) for exceptions 0x00-0x1F
    pub exc_vectors: [(u16, u32); 32],
    /// Real-mode callbacks (INT 31h/0303h)
    /// Each entry: Some((pm_cs, pm_eip, rm_struct_sel, rm_struct_off))
    pub callbacks: [Option<(u16, u32, u16, u32)>; MAX_CALLBACKS],
    /// Client mode bit-width as declared at INT 2F/1687h → entry point.
    /// Determines the operand size used for FAR CALL/INT frames the client
    /// places on its own stack (4 vs 8 bytes for CALL FAR, 6 vs 12 bytes for
    /// INT). The stub LDT segment itself is 16-bit, so we can't infer this
    /// from the trapped CS — we must remember what the client declared.
    pub client_use32: bool,
    /// RM PSP segment captured on the most recent RM→PM transition (initial
    /// `dpmi_enter` or `raw_switch_real_to_pm`). The matching PM→RM transition
    /// uses this to restore `dos.current_psp`. While in PM, `dos.current_psp`
    /// is fixed at `PSP_SEL` and this field names the RM PSP that PSP_SEL's
    /// LDT[4] descriptor points at.
    pub saved_rm_psp: u16,
    /// Original PSP[0x2C] value (RM env paragraph) captured on the most
    /// recent RM→PM transition. For 32-bit clients we patch PSP[0x2C] with
    /// an env selector during PM execution; PM→RM restores from this field.
    /// For 16-bit clients PSP[0x2C] is left untouched but we still capture
    /// it so callers that want the RM env segment have a single source.
    pub saved_rm_env: u16,
    /// LDT slot of the env selector allocated for 32-bit clients on RM→PM,
    /// or 0 if none is currently allocated (16-bit client, null env, or
    /// PM→RM has run since the last RM→PM). Non-zero implies PSP[0x2C] of
    /// `saved_rm_psp` is currently patched with `idx_to_sel(env_ldt_idx)`.
    pub env_ldt_idx: usize,
}

/// A DPMI linear memory block
#[derive(Clone, Copy)]
struct MemBlock {
    base: u32,
    size: u32,
}

/// Host-private alternate-mode state saved/restored by INT 31h/0305h.
///
/// The DPMI spec leaves the buffer format host-defined; clients only know the
/// size returned by AX=0305h and pass the buffer back to the save/restore
/// routine. We keep the hidden CS:IP, SS:SP, flags, and segment registers for
/// the non-current mode here so raw mode switches can be nested safely.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawModeState {
    flags: u32,
    cs: u16,
    ip: u32,
    ss: u16,
    sp: u32,
    ds: u16,
    es: u16,
    fs: u16,
    gs: u16,
}

impl DpmiState {
    pub fn new() -> Self {
        Self {
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            raw_rm_state: RawModeState::default(),
            raw_pm_state: RawModeState::default(),
            exc_vectors: [(0, 0); 32],
            callbacks: [None; MAX_CALLBACKS],
            client_use32: false,
            saved_rm_psp: 0,
            saved_rm_env: 0,
            env_ldt_idx: 0,
        }
    }

    /// Convert LDT index to selector (TI=1, RPL=3)
    fn idx_to_sel(idx: usize) -> u16 {
        ((idx as u16) << 3) | 4 | 3
    }

    /// Convert selector to LDT index
    fn sel_to_idx(sel: u16) -> usize {
        (sel >> 3) as usize
    }

    /// Build a data descriptor (present, DPL=3, writable)
    /// `db` = D/B bit: false = 16-bit, true = 32-bit
    fn make_data_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xF2; // Present | DPL=3 | S=1 | Data | Writable
        let flags: u64 = (g << 7) | ((db as u64) << 6);
        build_descriptor(base, limit_val, access, flags)
    }

    /// Build a 32-bit data descriptor (present, DPL=3, writable)
    fn make_data_desc(base: u32, limit: u32) -> u64 {
        Self::make_data_desc_ex(base, limit, true)
    }

    /// Build a code descriptor (present, DPL=3, readable)
    /// `db` = D bit: false = 16-bit, true = 32-bit
    fn make_code_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xFA; // Present | DPL=3 | S=1 | Code | Readable
        let flags: u64 = (g << 7) | ((db as u64) << 6);
        build_descriptor(base, limit_val, access, flags)
    }

    /// Build a 32-bit code descriptor (present, DPL=3, readable)
    #[allow(dead_code)]
    fn make_code_desc(base: u32, limit: u32) -> u64 {
        Self::make_code_desc_ex(base, limit, true)
    }

    /// Get the base address from an LDT descriptor
    pub fn desc_base(desc: u64) -> u32 {
        let b0 = ((desc >> 16) & 0xFFFF) as u32;
        let b1 = ((desc >> 32) & 0xFF) as u32;
        let b2 = ((desc >> 56) & 0xFF) as u32;
        b0 | (b1 << 16) | (b2 << 24)
    }

    /// Get the limit from an LDT descriptor (taking G bit into account)
    pub fn desc_limit(desc: u64) -> u32 {
        let l0 = (desc & 0xFFFF) as u32;
        let l1 = ((desc >> 48) & 0x0F) as u32;
        let raw = l0 | (l1 << 16);
        if desc & (1 << 55) != 0 { // G bit
            (raw << 12) | 0xFFF
        } else {
            raw
        }
    }

    /// Set base address in a descriptor
    fn set_desc_base(desc: &mut u64, base: u32) {
        *desc &= !0xFF00_00FF_FFFF_0000;
        *desc |= ((base & 0xFFFF) as u64) << 16;
        *desc |= (((base >> 16) & 0xFF) as u64) << 32;
        *desc |= (((base >> 24) & 0xFF) as u64) << 56;
    }

    /// Check if a descriptor has the D/B (default operation size) bit set (32-bit)
    fn desc_is_32(desc: u64) -> bool {
        desc & (1u64 << 54) != 0
    }

    /// Match CWSDPMI's "segment to descriptor" reuse heuristic:
    /// 64 KiB byte-granularity descriptor with base == seg << 4.
    fn desc_is_seg_alias(desc: u64, base: u32) -> bool {
        let lim0 = (desc & 0xFFFF) as u16;
        let lim1 = ((desc >> 48) & 0xFF) as u8;
        let base0 = ((desc >> 16) & 0xFFFF) as u16;
        let base1 = ((desc >> 32) & 0xFF) as u8;
        let base2 = ((desc >> 56) & 0xFF) as u8;

        lim0 == 0xFFFF
            && lim1 == 0
            && base2 == 0
            && base0 == (base as u16)
            && base1 == ((base >> 16) as u8)
    }

    /// Set limit in a descriptor (adjusts G bit)
    fn set_desc_limit(desc: &mut u64, limit: u32) {
        let (lim, g) = if limit > 0xFFFFF {
            (limit >> 12, true)
        } else {
            (limit, false)
        };
        // Clear old limit bits and G bit
        *desc &= !0x000F_0000_0000_FFFF;
        *desc &= !(1u64 << 55); // clear G
        *desc |= (lim & 0xFFFF) as u64;
        *desc |= (((lim >> 16) & 0x0F) as u64) << 48;
        if g { *desc |= 1u64 << 55; }
    }
}

/// Build an x86 segment descriptor from components.
/// flags: high nibble of byte 6 — bit 7 = G, bit 6 = D/B, bit 5 = L, bit 4 = AVL.
fn build_descriptor(base: u32, limit: u32, access: u64, flags: u64) -> u64 {
    let mut desc: u64 = 0;
    desc |= (limit & 0xFFFF) as u64;                          // bits  0-15: Limit[15:0]
    desc |= ((base & 0xFFFF) as u64) << 16;                   // bits 16-31: Base[15:0]
    desc |= (((base >> 16) & 0xFF) as u64) << 32;             // bits 32-39: Base[23:16]
    desc |= (access & 0xFF) << 40;                             // bits 40-47: Access byte
    let byte6 = (((limit >> 16) & 0x0F) as u64) | (flags & 0xF0); // Limit[19:16] | G:D/B:L:AVL
    desc |= byte6 << 48;                                       // bits 48-55
    desc |= (((base >> 24) & 0xFF) as u64) << 56;             // bits 56-63: Base[31:24]
    desc
}

/// Populate the kernel-owned LDT slots and default pm_vectors. Called from
/// `DosState::new()` so the PMDOS infrastructure is always live — HW IRQ
/// routing can use it even before any DPMI client has called dpmi_enter.
pub(super) fn install_kernel_ldt_slots(dos: &mut thread::DosState) {
    // Reserve + install each kernel slot.
    let mark = |dos: &mut thread::DosState, idx: usize, desc: u64| {
        dos.ldt[idx] = desc;
        dos.ldt_alloc[idx / 32] |= 1 << (idx % 32);
    };
    mark(dos, VECTOR_STUB_LDT_IDX,  DpmiState::make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, SPECIAL_STUB_LDT_IDX, DpmiState::make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, LOW_MEM_LDT_IDX,      DpmiState::make_data_desc_ex(0, 0xFFFFF, false));
    // Both PM aliases at the same base — SP value is offset-portable across
    // the three views (PM16/PM32/VM86 paragraph) of the same physical buffer.
    let host_base = dos::host_stack_base();
    let host_limit = dos::host_stack_size() - 1;
    mark(dos, HOST_STACK_PM16_LDT_IDX, DpmiState::make_data_desc_ex(host_base, host_limit, false));
    mark(dos, HOST_STACK_PM32_LDT_IDX, DpmiState::make_data_desc_ex(host_base, host_limit, true));
    // PSP_LDT_IDX is written per RM→PM by `enter_pm_psp_view`; just reserve.
    dos.ldt_alloc[PSP_LDT_IDX / 32] |= 1 << (PSP_LDT_IDX % 32);

    reset_pm_vectors(dos);
}

/// Fill `dos.pm_vectors` with the default `vector_stub` entries. Each vector
/// traps to its own CD 31 slot in the vector-stub segment; `vector_stub_reflect`
/// then reflects the interrupt to the real-mode IVT. Called from thread init
/// and from the EXEC path so a child never inherits a DPMI parent's hooks.
pub(super) fn reset_pm_vectors(dos: &mut thread::DosState) {
    for i in 0..256 {
        dos.pm_vectors[i] = (VECTOR_STUB_SEL, dos::STUB_BASE + (i as u32) * 2);
    }
}

// ── LDT bitmap helpers — operate on the thread-wide `dos.ldt`/`ldt_alloc` ──
//
// Descriptor *layout* helpers (make_*_desc_ex, set_desc_base, desc_base, …)
// stay as associated fns on DpmiState since they're pure; the bitmap-mutating
// allocators live here because they own the placement policy (l_free == 16)
// and the free/alloc state is part of DosState now.

/// Allocate an LDT selector. Returns index (16..LDT_ENTRIES) or None.
/// Starts at 16 to match CWSDPMI's `l_free`, leaving LDT[1..15] null so
/// DOS/4GW's `lar`-probe of low slots sees an empty range like CWSDPMI does.
///
/// Takes `ldt_alloc` as `&mut [u32]` (not `&mut DosState`) so call sites that
/// already hold `&mut dos.dpmi` can still invoke via disjoint field borrow:
/// `alloc_ldt(&mut dos.ldt_alloc)`.
pub(super) fn alloc_ldt(ldt_alloc: &mut [u32]) -> Option<usize> {
    for idx in 16..LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        if ldt_alloc[word] & (1 << bit) == 0 {
            ldt_alloc[word] |= 1 << bit;
            dos_trace!("[DPMI] alloc_ldt -> idx={} sel={:04X}", idx, DpmiState::idx_to_sel(idx));
            return Some(idx);
        }
    }
    dos_trace!("[DPMI] alloc_ldt FAILED (LDT full)");
    None
}

/// Allocate a contiguous run of LDT selectors. Returns the first index.
pub(super) fn alloc_ldt_range(ldt_alloc: &mut [u32], count: usize) -> Option<usize> {
    if count == 0 || count >= LDT_ENTRIES {
        return None;
    }
    'outer: for first in 16..=(LDT_ENTRIES - count) {
        for idx in first..(first + count) {
            let word = idx / 32;
            let bit = idx % 32;
            if ldt_alloc[word] & (1 << bit) != 0 {
                continue 'outer;
            }
        }
        for idx in first..(first + count) {
            let word = idx / 32;
            let bit = idx % 32;
            ldt_alloc[word] |= 1 << bit;
        }
        dos_trace!("[DPMI] alloc_ldt_range({}) -> idx={}..{} sel={:04X}..{:04X}",
            count, first, first + count - 1,
            DpmiState::idx_to_sel(first), DpmiState::idx_to_sel(first + count - 1));
        return Some(first);
    }
    dos_trace!("[DPMI] alloc_ldt_range({}) FAILED", count);
    None
}

/// Free an LDT selector by index (clears the descriptor and its alloc bit).
pub(super) fn free_ldt(ldt: &mut [u64], ldt_alloc: &mut [u32], idx: usize) {
    if idx > 0 && idx < LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        ldt_alloc[word] &= !(1 << bit);
        ldt[idx] = 0;
    }
}

pub(super) fn ldt_is_allocated(ldt_alloc: &[u32], idx: usize) -> bool {
    if idx >= LDT_ENTRIES {
        return false;
    }
    let word = idx / 32;
    let bit = idx % 32;
    ldt_alloc[word] & (1 << bit) != 0
}

// ============================================================================
// DPMI entry — mode switch from Dos/VM86 to Dos/DPMI (protected mode)
// ============================================================================

/// Switch from VM86 to 32-bit protected mode.
/// Called from rm_int31_dispatch when the DPMI entry stub executes.
pub fn dpmi_enter(dos: &mut thread::DosState, regs: &mut Regs) {
    let client_type = regs.rax as u16; // AX: 0=16-bit, 1=32-bit
    // Save VM86 register state for the FAR CALL return address
    // The FAR CALL pushed CS:IP on the real-mode stack.
    // Pop the return address so we know where to resume in PM.
    let ret_ip = machine::vm86_pop(regs);
    let ret_cs = machine::vm86_pop(regs);
    dos_trace!("[DPMI] ENTER AX={} ({}bit client) caller={:04X}:{:04X} psp={:04X}",
        client_type, if client_type != 0 { 32 } else { 16 },
        ret_cs, ret_ip, dos.current_psp);

    let real_ss = regs.stack_seg();
    let real_sp = regs.sp32() as u16;
    let entry_rm_state = capture_real_mode_state(regs, ret_cs, ret_ip, real_ss, real_sp);

    // Allocate DPMI state
    let mut dpmi = DpmiState::new();
    dpmi.client_use32 = client_type != 0;
    dpmi.raw_rm_state = entry_rm_state;

    // Set up initial LDT entries.
    // Kernel slots (VECTOR_STUB, SPECIAL_STUB, LOW_MEM, IRQ_PM16/32_STACK) plus
    // PSP_LDT_IDX reservation are already installed on `dos.ldt` by
    // install_kernel_ldt_slots at thread init. Here we only write the three
    // per-DPMI-client selectors: CS/DS/SS based on the caller's RM state.
    //
    // CS stays 16-bit: the return from mode switch is still 16-bit stub code.
    // SS must be 32-bit for 32-bit clients so interrupts save/restore full ESP.
    // DS/ES stay 16-bit (data segments don't affect stack width).
    let use32 = client_type != 0;

    // CS — code, base = ret_cs * 16 (caller's CS, not stub segment).
    // Placed at LDT[16] (CWSDPMI's l_acode) — see CLIENT_CS_LDT_IDX docs.
    let cs_base = (ret_cs as u32) * 16;
    dos.ldt[CLIENT_CS_LDT_IDX] = DpmiState::make_code_desc_ex(cs_base, 0xFFFF, false);
    dos.ldt_alloc[CLIENT_CS_LDT_IDX / 32] |= 1 << (CLIENT_CS_LDT_IDX % 32);

    // DS — data, base = real-mode DS * 16, limit = 64K.
    // Placed at LDT[17] (CWSDPMI's l_adata).
    let ds_base = (regs.ds as u32) * 16;
    dos.ldt[CLIENT_DS_LDT_IDX] = DpmiState::make_data_desc_ex(ds_base, 0xFFFF, false);
    dos.ldt_alloc[CLIENT_DS_LDT_IDX / 32] |= 1 << (CLIENT_DS_LDT_IDX % 32);

    // SS — stack, base = real_ss * 16, limit = 64K.
    // 32-bit clients need B=1 so the CPU uses full ESP during interrupts.
    // Placed at LDT[19] (CWSDPMI's l_aenv slot, repurposed — RetroOS doesn't
    // separately allocate an env selector).
    let ss_base = (real_ss as u32) * 16;
    dos.ldt[CLIENT_SS_LDT_IDX] = DpmiState::make_data_desc_ex(ss_base, 0xFFFF, use32);
    dos.ldt_alloc[CLIENT_SS_LDT_IDX / 32] |= 1 << (CLIENT_SS_LDT_IDX % 32);

    let cs_sel = DpmiState::idx_to_sel(CLIENT_CS_LDT_IDX);
    let ds_sel = DpmiState::idx_to_sel(CLIENT_DS_LDT_IDX);
    let ss_sel = DpmiState::idx_to_sel(CLIENT_SS_LDT_IDX);

    // The DPMI 0.9 §3.1.3 real-mode stack lives in `LowMem.rm_stack`
    // (kernel-managed, paragraph-aligned, 0x200 bytes — the spec
    // minimum). Shared by all kernel-orchestrated RM excursions; nested
    // use is reentrant via the snapshot-on-locked-stack discipline. No
    // DOS-heap allocation needed.

    // Round client allocation pool up to a 1 MB boundary. DOS/4GW appears to
    // treat the first 0501 base as a slab origin and takes a private code path
    // when it is not MB-aligned (matches CWSDPMI's VADDR_START=0x400000).
    dpmi.mem_next = (dpmi.mem_next + 0xFFFFF) & !0xFFFFF;

    // pm_vectors stays zero-initialized: sel=0 means "no client handler",
    // which signals reflect-to-real-mode in dpmi_soft_int. INT 31h/0204h
    // synthesizes the stub address on demand for clients that chain to the
    // default handler.

    // Attach DPMI state to thread, then build the per-RM→PM PSP view: this
    // builds LDT[4] (PSP_SEL) for the active RM PSP, captures saved_rm_psp /
    // saved_rm_env, and (for 32-bit clients) allocates an env selector and
    // patches PSP[0x2C] per DPMI 0.9 §4.1. Sets `dos.current_psp = PSP_SEL`.
    dos.dpmi = Some(Box::new(dpmi));
    enter_pm_psp_view(dos);

    // No arch_load_ldt here: `dos.ldt` is a fixed per-thread buffer allocated
    // at thread init, and the context switch into this thread already pointed
    // LDTR at it. Mutations to `dos.ldt[CLIENT_CS/DS/SS]` are visible to the
    // CPU without reloading.

    // One-time LDT dump for DPMI client init (debugging RM-segment alias logic
    // in protected-mode loaders like DOS/4GW that compute paragraph segments
    // from PM descriptor bases).
    for i in 1..8 {
        let d = dos.ldt[i];
        if d != 0 {
            dos_trace!("[DPMI] INIT_LDT idx={} sel={:04X} base={:08X} raw={:016X}",
                i, DpmiState::idx_to_sel(i), DpmiState::desc_base(d), d);
        }
    }

    // Switch regs from VM86 to protected mode:
    // Clear VM flag, set PM selectors, set EIP to return offset
    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::IF_FLAG as u64;
    regs.frame.cs = cs_sel as u64;
    regs.frame.rip = ret_ip as u64;
    regs.frame.ss = ss_sel as u64;
    regs.frame.rsp = real_sp as u64;
    regs.ds = ds_sel as u64;
    regs.es = PSP_SEL as u64;
    regs.fs = 0;
    regs.gs = 0;
}

// PM #GP monitor lives in `arch/monitor.rs`. The arch decoder handles
// CLI/STI/PUSHF/POPF/IRET directly (fast-path iret to user) and bubbles
// INT/HLT/IN/OUT/INS/OUTS up as `KernelEvent`s. PM software-INT dispatch
// for installed DPMI client vectors is handled by `dpmi_soft_int` below.

// ============================================================================
// DPMI software INT dispatch (vectors 0x30-0xFF, DPL=3 in IDT)
// ============================================================================

/// Deliver a PM soft INT to the installed handler.
///
/// Per DPMI 0.9 §3.1.2: software interrupts do **not** switch stacks —
/// the handler runs on the client's own PM stack. Standard hardware-INT
/// semantics done in software:
///
///   - Push an IRET frame on `regs.ss:regs.sp` (the client's stack) with
///     return CS:EIP:EFLAGS pointing back at the interrupted client.
///     Frame width follows `dpmi.client_use32` per §10.6 (32-bit client →
///     12-byte IRETD frame; 16-bit → 6-byte IRET frame). The handler
///     owns matching its IRET width to the client's.
///   - Set CS:EIP to the installed handler. Clear TF so we don't
///     single-step into the handler. IF/IOPL/etc. follow the caller's
///     EFLAGS unchanged (spec leaves soft-INT handler IF state alone).
///   - Run. The handler's eventual IRET pops the frame and resumes the
///     client directly — no kernel involvement, no snapshot, no stack
///     switch.
pub fn deliver_pm_int(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) {
    let (sel, off) = dos.pm_vectors[vector as usize];
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => return,
    };
    let client_use32 = dpmi.client_use32;
    let handler_flags = regs.flags32() & !(1u32 << 8);
    push_iret_frame(&dos.ldt[..], regs, client_use32,
        regs.ip32(), regs.code_seg(), handler_flags);
    regs.set_cs32(sel as u32);
    regs.set_ip32(off);
    regs.clear_flag32(1 << 8);
    dos_trace!("[DPMI] PM_INT vec={:02X} -> {:04x}:{:#x} on client SS:ESP={:04x}:{:#x}",
        vector, sel, off, regs.frame.ss as u16, regs.sp32());
}

/// Thin wrapper preserving the old event-loop entry signature.
pub fn dpmi_soft_int(_kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    dos_trace!("[DPMI] SOFTINT {:02X} AX={:04X} CS:EIP={:04x}:{:#x} DS={:04X} ES={:04X} EDX={:08X} EDI={:08X}",
        vector, regs.rax as u16, regs.code_seg(), regs.ip32(),
        regs.ds as u16, regs.es as u16, regs.rdx as u32, regs.rdi as u32);
    let arm_step = false; // disabled while debugging non-traced behavior
    let _ = vector == 0x21 && (regs.rax as u16) == 0x4300;
    if arm_step {
        if dos.dpmi.is_some() {
            let base = seg_base(&dos.ldt[..], regs.ds as u16);
            let addr = base.wrapping_add(regs.rdx as u32);
            let mut hex = [0u8; 32];
            for j in 0..16usize {
                let b = unsafe { *((addr as *const u8).add(j)) };
                hex[j*2] = b"0123456789ABCDEF"[(b >> 4) as usize];
                hex[j*2+1] = b"0123456789ABCDEF"[(b & 0xF) as usize];
            }
            dos_trace!("[DPMI] PM DS:EDX={:04X}:{:08X} -> linear={:08X} hex={}",
                regs.ds as u16, regs.rdx as u32, addr,
                core::str::from_utf8(&hex).unwrap());
        }
    }
    deliver_pm_int(dos, regs, vector);
    if arm_step {
        use core::sync::atomic::Ordering;
        if dos::PM_STEP_BUDGET.load(Ordering::Relaxed) == 0 {
            dos::PM_STEP_BUDGET.store(65000, Ordering::Relaxed);
            regs.set_flag32(1 << 8); // TF on entry to hook
            dos_trace!("[STEP] armed 65000 steps at INT 21 AX=4300 hook entry");
        }
    }
    thread::KernelAction::Done
}

/// Deliver a HW IRQ to a PM handler. Per DPMI 0.9 §3.1.2 the host
/// switches to the locked PM stack (`host_stack`) on the *first* entry
/// from the client's stack OR from VM86; nested entries already on the
/// locked stack reuse it without switching.
///
///   - **First entry** (regs.SS is not the locked PM stack): push a
///     `ModeSave` capturing the interrupted regs onto `host_stack` at
///     `pc.host_stack_sp`, push an iret frame above it targeting
///     `SLOT_PM_IRET`. Switch SS:ESP to the `HOST_STACK_PM*` alias. The
///     handler's IRET pops the iret frame and traps to the kernel via
///     the stub, which pops the ModeSave (via `cross_mode_restore`) and
///     restores the interrupted state — including SS:ESP, which a
///     same-priv hardware IRET could not have done.
///
///   - **Nested on the locked PM stack** (regs in PM and SS is a
///     `HOST_STACK_PM*` alias): push only the iret frame at
///     `regs.ESP - frame_size` targeting the outer's CS:EIP. No
///     ModeSave; hardware same-priv IRET handles the unwind directly.
///
/// The two cases collapse to: "is the CPU currently on the locked PM
/// stack in PM mode?". In VM86 the SS register is a paragraph and
/// numerically comparing it to a PM selector value would be a category
/// error, so the mode check has to come first.
///
/// Works for non-DPMI threads too: `install_kernel_ldt_slots` makes the
/// LDT + kernel-owned selectors (VECTOR_STUB, SPECIAL_STUB, HOST_STACK_PM*)
/// available at thread init. When `pm_vectors[vec]` is the default stub,
/// the round-trip lands in `vector_stub_reflect` which discriminates the
/// first-entry case by the IRET target == `SLOT_PM_IRET`.
pub fn deliver_pm_irq(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) {
    let (sel, off) = dos.pm_vectors[vector as usize];
    // DPMI 0.9 §10.6: frame width follows the *client*'s bitness, not the
    // handler segment's D bit. A 32-bit client routinely installs a
    // 16-bit-segment handler that issues `66 CF` (32-bit IRETD) — clients
    // own that contract end-to-end. Non-DPMI threads default to 16-bit
    // (the host default-stub path is 16-bit).
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);

    // Handler starts with IF=TF=0; other flag bits follow the current EFLAGS.
    let handler_flags = regs.flags32() & !(machine::IF_FLAG | (1u32 << 8) | machine::VM_FLAG);

    let in_pm = regs.mode() != crate::UserMode::VM86;
    let cur_ss = regs.stack_seg();
    let nested_on_host_stack = in_pm
        && (cur_ss == HOST_STACK_PM16_SEL || cur_ss == HOST_STACK_PM32_SEL);

    if nested_on_host_stack {
        // Nested on the locked PM stack: just push iret_frame targeting
        // outer's CS:EIP at current ESP - frame_size. Hardware same-priv
        // IRET unwinds inline, no kernel involvement.
        let new_esp = host_stack_write_iret(
            regs.sp32(), client_use32,
            regs.ip32(), regs.code_seg(), handler_flags);
        regs.frame.rsp = new_esp as u64;
    } else {
        // First entry: push a ModeSave (kernel-side save area) + plant
        // an iret-to-SLOT_PM_IRET frame so the eventual handler IRET
        // round-trips through the kernel for unwinding.
        super::mode_transitions::push_save(dos, regs);
        let stub_eip = dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_IRET) as u32;
        let cursor2 = host_stack_write_iret(
            dos.pc.host_stack_sp, client_use32,
            stub_eip, SPECIAL_STUB_SEL, handler_flags);
        dos.pc.host_stack_sp = cursor2;

        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;

        let stk_sel = if client_use32 { HOST_STACK_PM32_SEL } else { HOST_STACK_PM16_SEL };
        regs.frame.ss  = stk_sel as u64;
        regs.frame.rsp = cursor2 as u64;
    }

    regs.frame.rflags &= !((machine::VM_FLAG | machine::IF_FLAG | (1u32 << 8)) as u64);
    regs.frame.cs  = sel as u64;
    regs.frame.rip = off as u64;
}

/// Pop the ModeSave pushed by the outermost-relative PM-handler entry
/// (`deliver_pm_irq` taking the cross-mode branch). Called from
/// `pm_stub_dispatch` when SLOT_PM_IRET fires (client handler IRETed
/// through our stub) and from `vector_stub_reflect` when the default
/// stub catches an IRQ that has no PM handler installed.
///
/// At entry: hardware IRET advanced regs.ESP past the iret_frame, so
/// regs.ESP now points at the ModeSave on host_stack. After restoring,
/// `host_stack_sp` is bumped back up past both records.
fn cross_mode_restore(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    debug_assert!(regs.stack_seg() == HOST_STACK_PM16_SEL ||
                  regs.stack_seg() == HOST_STACK_PM32_SEL,
                  "cross_mode_restore: SS not host_stack");

    // Resync host_stack_sp from the user's post-iret cursor: hardware
    // IRET advanced ESP past the iret frame onto the save's start.
    dos.pc.host_stack_sp = regs.sp32();
    let save = super::mode_transitions::pop_save(dos);
    save.restore(regs);

    let (cs, eip, ss, esp, vm) =
        (save.cs as u16, save.eip, save.ss as u16, save.esp,
         save.eflags & machine::VM_FLAG != 0);
    dos_trace!("[DPMI] IRQ RESTORE -> {:04X}:{:#x} SS:ESP={:04X}:{:#x} VM={}",
        cs, eip, ss, esp, vm);

    thread::KernelAction::Done
}

/// Push an IRET frame on the stack addressed by `regs.ss:regs.sp`, updating
/// regs.sp. Frame width matches the *handler's* bitness — 12 bytes for a
/// 32-bit handler (D=1), 6 bytes for 16-bit (D=0). This is the width the
/// handler's `IRET` will use on its way back, so push and matching pop must
/// agree on handler bitness, regardless of the client's overall size.
fn push_iret_frame(ldt: &[u64], regs: &mut Regs, handler_is_32: bool,
                   eip: u32, cs: u16, flags: u32) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 12 } else { 6 };
    // Frame width follows handler.D — what handler's IRET will pop.
    // SP semantics follow SS.B — full ESP wraps within seg-limit on a
    // 32-bit stack; SP wraps within 0x10000 with upper-ESP preserved on
    // a 16-bit stack. The two bits are independent (see Intel SDM 6.12).
    let sp_in = regs.sp32();
    let sp = if stack_is_32 {
        sp_in.wrapping_sub(frame_size)
    } else {
        let new_sp16 = (sp_in as u16).wrapping_sub(frame_size as u16);
        (sp_in & !0xFFFF) | new_sp16 as u32
    };
    let eff_sp = if stack_is_32 { sp } else { sp & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    if handler_is_32 {
        unsafe {
            let p = addr as *mut u32;
            core::ptr::write_unaligned(p, eip);
            core::ptr::write_unaligned(p.add(1), cs as u32);
            core::ptr::write_unaligned(p.add(2), flags);
        }
    } else {
        unsafe {
            let p = addr as *mut u16;
            core::ptr::write_unaligned(p, eip as u16);
            core::ptr::write_unaligned(p.add(1), cs);
            core::ptr::write_unaligned(p.add(2), flags as u16);
        }
    }
    regs.set_sp32(sp);
}

/// Pop an IRET frame off `regs.ss:regs.sp`, advancing regs.sp.
/// `handler_is_32` must match the width used at push time. Frame width
/// follows handler.D; SP semantics follow SS.B (see `push_iret_frame`).
fn pop_iret_frame(ldt: &[u64], regs: &mut Regs, handler_is_32: bool) -> (u32, u16, u32) {
    let ss = regs.frame.ss as u16;
    let base = seg_base(ldt, ss);
    let stack_is_32 = seg_is_32(ldt, ss);
    let frame_size: u32 = if handler_is_32 { 12 } else { 6 };
    let sp_in = regs.sp32();
    let eff_sp = if stack_is_32 { sp_in } else { sp_in & 0xFFFF };
    let addr = base.wrapping_add(eff_sp);
    let frame = if handler_is_32 {
        unsafe {
            let p = addr as *const u32;
            let eip = core::ptr::read_unaligned(p);
            let cs = core::ptr::read_unaligned(p.add(1)) as u16;
            let flags = core::ptr::read_unaligned(p.add(2));
            (eip, cs, flags)
        }
    } else {
        unsafe {
            let p = addr as *const u16;
            let ip = core::ptr::read_unaligned(p) as u32;
            let cs = core::ptr::read_unaligned(p.add(1));
            let flags = core::ptr::read_unaligned(p.add(2)) as u32;
            (ip, cs, flags)
        }
    };
    let new_sp = if stack_is_32 {
        sp_in.wrapping_add(frame_size)
    } else {
        let new_sp16 = (sp_in as u16).wrapping_add(frame_size as u16);
        (sp_in & !0xFFFF) | new_sp16 as u32
    };
    regs.set_sp32(new_sp);
    frame
}

/// Synthetic trap for an uninstalled PM vector. The CD 31 at
/// `VECTOR_STUB:STUB_BASE+vec*2` traps here; we pop the IRET frame the
/// delivery path pushed and decide what to do by inspecting its target:
///
///   - Target is our `SLOT_PM_RET_{16,32}` stub → this was the outermost
///     host-snapshotted PM delivery (HW IRQ via `deliver_pm_irq` or PM
///     soft INT via `deliver_pm_int`). Pop the snapshot via
///     `cross_mode_restore`, which puts us back in the client's original
///     mode, then reflect the INT to BIOS via `reflect_int_to_real_mode`
///     uniformly (VM86 and PM clients alike — BIOS always runs on a
///     kernel-owned RM frame allocated from host_stack).
///
///   - Target is anything else → the pushed frame carries an outer
///     handler's CS:EIP, i.e. we're nested inside a still-live handler.
///     Install the popped state in regs and reflect via the DPMI PM→RM
///     path.
pub(super) fn vector_stub_reflect(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let eip = regs.ip32();
    let vector = ((eip.wrapping_sub(dos::STUB_BASE + 2)) / 2) as u8;
    // HW IRQ vectors (timer 0x08, keyboard 0x09, etc.) fire on every tick —
    // log only the soft-INT reflections (vec >= 0x10) by default.
    if vector >= 0x10 {
        dos_trace!("[DPMI] VECSTUB vec={:#04x} SS:ESP={:04x}:{:#x} CS:EIP={:04x}:{:#x} DS={:04X} ES={:04X} DX={:04X} DI={:04X}",
            vector, regs.stack_seg(), regs.sp32(), regs.code_seg(), eip,
            regs.ds as u16, regs.es as u16, regs.rdx as u16, regs.rdi as u16);
    }

    // The frame width matches what `deliver_pm_irq`/`deliver_pm_int` pushed,
    // which follows the client's bitness per DPMI 0.9 §10.6 (32-bit clients
    // get 12-byte IRETD frames, 16-bit clients get 6-byte IRET frames).
    // Non-DPMI threads default to 16-bit (host default-stub semantics).
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);
    let (ret_eip, ret_cs, ret_flags) = pop_iret_frame(&dos.ldt[..], regs, client_use32);

    let pm_iret_off = dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_IRET) as u32;
    let is_outermost = ret_cs == SPECIAL_STUB_SEL && ret_eip == pm_iret_off;

    if is_outermost {
        let _ = (ret_eip, ret_cs, ret_flags);
        // HW IRQ default-stub bridge: tail-replace into RM at the BIOS
        // handler. The OUTER ModeSave from `deliver_pm_irq` stays on
        // the locked stack untouched. We snapshot the dedicated RM
        // stack, set up RM execution, and plant an iret frame that
        // returns through SLOT_RM_IRET_FORWARD instead of
        // SLOT_RM_IRET_REFLECT — the FORWARD handler synthesizes
        // PM-at-SLOT_PM_IRET so the existing outer-save unwind path
        // (cross_mode_restore) fires next. Net result: a single
        // ModeSave through the entire HW IRQ flow.
        super::mode_transitions::push_rm_snapshot(dos);

        let ivt_off = machine::read_u16(0, (vector as u32) * 4);
        let ivt_seg = machine::read_u16(0, (vector as u32) * 4 + 2);

        regs.frame.ss = dos::rm_stack_seg() as u64;
        regs.frame.rsp = super::mode_transitions::rm_stack_top() as u64;

        let ret_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_FORWARD);
        let ret_seg: u16 = dos::STUB_SEG;
        let ret_flags = regs.flags32() as u16;
        machine::vm86_push(regs, ret_flags);
        machine::vm86_push(regs, ret_seg);
        machine::vm86_push(regs, ret_off);

        regs.frame.cs = ivt_seg as u64;
        regs.frame.rip = ivt_off as u64;
        let flags = (regs.flags32() & !(machine::IF_FLAG | machine::IOPL_MASK))
            | machine::VM_FLAG
            | machine::IOPL_VM86;
        regs.frame.rflags = flags as u64;

        dos_trace!("[DPMI] BRIDGE INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X}",
            vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32());

        return thread::KernelAction::Done;
    }

    regs.set_ip32(ret_eip);
    regs.set_cs32(ret_cs as u32);
    regs.set_flags32(ret_flags);
    reflect_int_to_real_mode(dos, regs, vector)
}

// ============================================================================
// PM stub dispatch — INT 31h from the unified CD 31 array
// ============================================================================

/// Dispatch INT 31h that came from the special-stub segment. Only host-
/// initiated return trampolines and entry points live here, so the slot is
/// always one of SLOT_EXCEPTION_RET / SLOT_PM_TO_REAL / SLOT_SAVE_RESTORE.
/// Slot = (EIP - STUB_BASE - 2) / 2.
pub(super) fn pm_stub_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let eip = regs.ip32();
    let stub_base = dos::STUB_BASE;
    let slot = ((eip.wrapping_sub(stub_base + 2)) / 2) as u8;
    dos_trace!("[DPMI] STUB slot={:#04x} EIP={:#x}", slot, eip);

    match slot {
        dos::SLOT_EXCEPTION_RET => {
            return exception_return(dos, regs);
        }
        dos::SLOT_PM_TO_REAL => {
            return raw_switch_pm_to_real(dos, regs);
        }
        dos::SLOT_PM_IRET => {
            let r = cross_mode_restore(dos, regs);
            // PM-handler path for HW IRQ: client handler ran, IRETed
            // through our stub, cross_mode_restore put us back at the
            // interrupted client state. IRQ context is over.
            super::IN_HW_IRQ_CONTEXT.store(false, core::sync::atomic::Ordering::Relaxed);
            return r;
        }
        dos::SLOT_SAVE_RESTORE => {
            save_restore_real_mode_state(dos, regs);

            // Pop the far-call return address and resume caller. Frame size
            // depends on the client's operand size: 16-bit CALL FAR pushed
            // IP+CS as 4 bytes; 32-bit CALL FAR pushed EIP+CS as 8 bytes.
            let dpmi = dos.dpmi.as_ref().unwrap();
            let use32 = dpmi.client_use32;
            let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
            let ss_32 = seg_is_32(&dos.ldt[..], regs.stack_seg());
            let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
            let (ret_eip, ret_cs, frame_size) = if use32 {
                let eip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u32) };
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u32) };
                (eip, cs, 8u32)
            } else {
                let ip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u16) } as u32;
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 2)) as *const u16) } as u32;
                (ip, cs, 4u32)
            };
            let new_sp = sp.wrapping_add(frame_size);
            if ss_32 { regs.set_sp32(new_sp); }
            else { regs.set_sp32((regs.sp32() & !0xFFFF) | (new_sp & 0xFFFF)); }
            regs.set_ip32(ret_eip);
            regs.set_cs32(ret_cs);
            thread::KernelAction::Done
        }
        _ => panic!("pm_stub_dispatch: unhandled slot {:#04x}", slot),
    }
}

// ============================================================================
// INT 31h — DPMI services API
// ============================================================================

/// PM client-initiated INT 31h — the DPMI service API, dispatched by AX.
/// Caller (`dos::syscall`) has already classified the trap as client-side
/// (CS not in the kernel's stub LDT slots).
pub(super) fn dpmi_api(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: INT 31h from client but no DPMI state!");
            set_carry(regs);
            return thread::KernelAction::Done;
        }
    };

    let ax = regs.rax as u16;
    dos_trace!("[INT31] AX={:04x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);

    // PM TF single-step arming (disabled — flip the `if false` to re-enable).
    #[allow(dead_code)]
    if false {
        use core::sync::atomic::Ordering;
        if dos::PM_STEP_BUDGET.load(Ordering::Relaxed) == 0 {
            static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !ONCE.swap(true, Ordering::Relaxed) {
                dos::PM_STEP_BUDGET.store(200_000, Ordering::Relaxed);
                regs.set_flag32(1 << 8); // TF on return to client
                dos_trace!("[STEP] armed 200000 steps at first INT 31 (PM init)");
            }
        }
    }

    match ax {
        // AX=0000h — Allocate LDT Descriptors
        // CX = number of descriptors
        // Returns: AX = base selector
        0x0000 => {
            let count = (regs.rcx & 0xFFFF) as usize;
            if count == 0 { set_carry(regs); return thread::KernelAction::Done; }
            // DPMI requires the returned descriptors to be a contiguous run.
            match alloc_ldt_range(&mut dos.ldt_alloc, count) {
                Some(idx) => {
                    for extra in idx..(idx + count) {
                        dos.ldt[extra] = DpmiState::make_data_desc(0, 0);
                    }
                    let sel = DpmiState::idx_to_sel(idx);
                    regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                    clear_carry(regs);
                }
                None => set_carry(regs),
            }
        }
        // AX=0001h — Free LDT Descriptor
        // BX = selector
        0x0001 => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            dos_trace!("[DPMI] 0001 free sel={:04X} idx={}", sel, idx);
            free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
            // Null out any segment register still holding the freed selector,
            // otherwise IRET back to user mode will GP fault.
            if regs.ds as u16 == sel { regs.ds = 0; }
            if regs.es as u16 == sel { regs.es = 0; }
            if regs.fs as u16 == sel { regs.fs = 0; }
            if regs.gs as u16 == sel { regs.gs = 0; }
            clear_carry(regs);
        }
        // AX=0002h — Segment to Descriptor
        // BX = real-mode segment. Returns: AX = selector (maps 64KB at seg<<4)
        0x0002 => {
            let seg = regs.rbx as u16;
            let base = (seg as u32) << 4;
            for idx in 1..LDT_ENTRIES {
                if ldt_is_allocated(&dos.ldt_alloc, idx) && DpmiState::desc_is_seg_alias(dos.ldt[idx], base) {
                    let sel = DpmiState::idx_to_sel(idx);
                    regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                    dos_trace!("[DPMI] 0002 seg={:04X} -> reuse sel={:04X} base={:08X}", seg, sel, base);
                    clear_carry(regs);
                    return thread::KernelAction::Done;
                }
            }
            if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
                dos.ldt[idx] = DpmiState::make_data_desc_ex(base, 0xFFFF, false);
                let sel = DpmiState::idx_to_sel(idx);
                regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                dos_trace!("[DPMI] 0002 seg={:04X} -> sel={:04X} base={:08X}", seg, sel, base);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0003h — Get Selector Increment Value
        // Returns: AX = 8
        0x0003 => {
            regs.rax = (regs.rax & !0xFFFF) | 8;
            clear_carry(regs);
        }
        // AX=0006h — Get Segment Base Address
        // BX = selector. Returns: CX:DX = base
        0x0006 => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let base = DpmiState::desc_base(dos.ldt[idx]);
                dos_trace!("[DPMI] 0006 sel={:04X} -> base={:08X}", sel, base);
                regs.rcx = (regs.rcx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | (base & 0xFFFF) as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0007h — Set Segment Base Address
        // BX = selector, CX:DX = base
        0x0007 => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let base = ((regs.rcx as u32 & 0xFFFF) << 16) | (regs.rdx as u32 & 0xFFFF);
                DpmiState::set_desc_base(&mut dos.ldt[idx], base);
                dos_trace!("[DPMI] 0007 sel={:04X} base={:08X}", sel, base);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0008h — Set Segment Limit
        // BX = selector, CX:DX = limit
        0x0008 => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let limit = ((regs.rcx as u32 & 0xFFFF) << 16) | (regs.rdx as u32 & 0xFFFF);
                DpmiState::set_desc_limit(&mut dos.ldt[idx], limit);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0009h — Set Descriptor Access Rights
        // BX = selector, CL = access rights byte, CH = extended type
        0x0009 => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let cl = regs.rcx as u8;
                let ch = (regs.rcx >> 8) as u8;
                // Match CWSDPMI: force the descriptor to stay code/data (S=1)
                // and only accept G/D/B/AVL in the high nibble.
                dos.ldt[idx] &= !0x00F0_FF00_0000_0000;
                dos.ldt[idx] |= ((0x10 | cl) as u64) << 40;
                dos.ldt[idx] |= ((ch & 0xD0) as u64) << 48;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=000Ah — Create Alias Descriptor (data alias of code segment)
        // BX = selector. Returns: AX = new data selector
        0x000A => {
            let sel = regs.rbx as u16;
            let src_idx = DpmiState::sel_to_idx(sel);
            if src_idx < LDT_ENTRIES {
                if let Some(new_idx) = alloc_ldt(&mut dos.ldt_alloc) {
                    let mut desc = dos.ldt[src_idx];
                    // Change type from code to data (clear bit 3 of type nibble = execute bit)
                    // Access byte bit 43 = execute. Clear it, set writable (bit 41)
                    desc &= !(1u64 << 43); // clear execute
                    desc |= 1u64 << 41;    // set writable
                    dos.ldt[new_idx] = desc;
                    let new_sel = DpmiState::idx_to_sel(new_idx);
                    regs.rax = (regs.rax & !0xFFFF) | new_sel as u64;
                    dos_trace!("[DPMI] 000A alias src_sel={:04X} -> new_sel={:04X} base={:08X}",
                        sel, new_sel, DpmiState::desc_base(desc));
                    clear_carry(regs);
                } else {
                    set_carry(regs);
                }
            } else {
                set_carry(regs);
            }
        }
        // AX=000Bh — Get Descriptor
        // BX = selector, ES:EDI = buffer (8 bytes)
        0x000B => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let dest = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
                let desc = dos.ldt[idx];
                unsafe { core::ptr::write_unaligned(dest as *mut u64, desc); }
                dos_trace!("[DPMI] 000B sel={:04X} -> base={:08X} raw={:016X}", sel,
                    DpmiState::desc_base(desc), desc);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=000Ch — Set Descriptor
        // BX = selector, ES:EDI = descriptor (8 bytes)
        0x000C => {
            let sel = regs.rbx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if idx < LDT_ENTRIES {
                let src = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
                let mut new_desc = unsafe { core::ptr::read_unaligned(src as *const u64) };
                // Match CWSDPMI: force the descriptor to stay non-system.
                new_desc |= 1u64 << 44;
                dos.ldt[idx] = new_desc;
                dos_trace!("[DPMI] 000C sel={:04X} base={:08X} raw={:016X}", sel,
                    DpmiState::desc_base(new_desc), new_desc);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0100h — Allocate DOS Memory Block
        // BX = paragraphs. Returns: AX = real-mode segment, DX = selector
        0x0100 => {
            let paragraphs = regs.rbx as u16;
            match dos::dos_alloc_block(dos, paragraphs) {
                Ok(seg) => {
                    if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
                        let base = (seg as u32) * 16;
                        let limit = (paragraphs as u32).saturating_mul(16).saturating_sub(1);
                        dos.ldt[idx] = DpmiState::make_data_desc(base, limit);
                        let sel = DpmiState::idx_to_sel(idx);
                        regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                        regs.rdx = (regs.rdx & !0xFFFF) | sel as u64;
                        dos_trace!("[DPMI] 0100 alloc paragraphs={:04X} -> seg={:04X} sel={:04X} base={:08X}",
                            paragraphs, seg, sel, base);
                        clear_carry(regs);
                    } else {
                        let _ = dos::dos_free_block(dos, seg);
                        regs.rax = (regs.rax & !0xFFFF) | 8;
                        set_carry(regs);
                    }
                }
                Err(max) => {
                    regs.rax = (regs.rax & !0xFFFF) | 8;
                    regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                    set_carry(regs);
                }
            }
        }
        // AX=0101h — Free DOS Memory Block
        // DX = selector
        0x0101 => {
            let sel = regs.rdx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if !ldt_is_allocated(&dos.ldt_alloc, idx) {
                regs.rax = (regs.rax & !0xFFFF) | 9;
                set_carry(regs);
            } else {
                let base = DpmiState::desc_base(dos.ldt[idx]);
                let seg = (base >> 4) as u16;
                match dos::dos_free_block(dos, seg) {
                    Ok(()) => {
                        free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
                        clear_carry(regs);
                    }
                    Err(err) => {
                        regs.rax = (regs.rax & !0xFFFF) | err as u64;
                        set_carry(regs);
                    }
                }
            }
        }
        // AX=0102h — Resize DOS Memory Block
        // BX = new paragraphs, DX = selector
        0x0102 => {
            let paragraphs = regs.rbx as u16;
            let sel = regs.rdx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            if !ldt_is_allocated(&dos.ldt_alloc, idx) {
                regs.rax = (regs.rax & !0xFFFF) | 9;
                set_carry(regs);
            } else {
                let base = DpmiState::desc_base(dos.ldt[idx]);
                let seg = (base >> 4) as u16;
                match dos::dos_resize_block(dos, seg, paragraphs) {
                    Ok(()) => {
                        let limit = (paragraphs as u32).saturating_mul(16).saturating_sub(1);
                        dos.ldt[idx] = DpmiState::make_data_desc(base, limit);
                        clear_carry(regs);
                    }
                    Err((err, max)) => {
                        regs.rax = (regs.rax & !0xFFFF) | err as u64;
                        regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                        set_carry(regs);
                    }
                }
            }
        }
        // AX=0200h — Get Real Mode Interrupt Vector
        // BL = interrupt number. Returns: CX:DX = seg:off
        0x0200 => {
            let int_num = regs.rbx as u8;
            let off = machine::read_u16(0, (int_num as u32) * 4);
            let seg = machine::read_u16(0, (int_num as u32) * 4 + 2);
            regs.rcx = (regs.rcx & !0xFFFF) | seg as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0201h — Set Real Mode Interrupt Vector
        // BL = interrupt number, CX:DX = seg:off
        0x0201 => {
            let int_num = regs.rbx as u8;
            let seg = regs.rcx as u16;
            let off = regs.rdx as u16;
            dos_trace!("[DPMI] 0201 set RM vec {:02X} = {:04X}:{:04X}", int_num, seg, off);
            machine::write_u16(0, (int_num as u32) * 4, off);
            machine::write_u16(0, (int_num as u32) * 4 + 2, seg);
            clear_carry(regs);
        }
        // AX=0202h — Get Processor Exception Handler Vector
        // BL = exception number. DPMI 0.9 only defines 0..14 (CPU exceptions);
        // higher indices return CF=1 to match CWSDPMI.
        0x0202 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 15 {
                let (sel, off) = dpmi.exc_vectors[exc as usize];
                regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
                regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0203h — Set Processor Exception Handler Vector
        // BL = exception number, CX:EDX = selector:offset. Same 0..14 range.
        0x0203 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 15 {
                dpmi.exc_vectors[exc as usize] = (regs.rcx as u16, regs.rdx as u32);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0204h — Get Protected Mode Interrupt Vector
        // BL = interrupt number. Returns: CX:EDX = selector:offset
        // If no client handler is installed, synthesize the address of the
        // default CD 31 stub slot — clients store this as a chain-to handler.
        0x0204 => {
            let int_num = regs.rbx as u8;
            let (sel, off) = dos.pm_vectors[int_num as usize];
            regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
            regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0205h — Set Protected Mode Interrupt Vector
        // BL = interrupt number, CX:EDX = selector:offset
        0x0205 => {
            let int_num = regs.rbx as u8;
            let sel = regs.rcx as u16;
            let off = regs.rdx as u32;
            dos_trace!("[DPMI] 0205 set vec {:02X} = {:04X}:{:#X}", int_num, sel, off);
            dos.pm_vectors[int_num as usize] = (sel, off);
            clear_carry(regs);
        }
        // AX=0300h — Simulate Real Mode Interrupt
        // BL = interrupt number, ES:EDI = real-mode call structure (50 bytes)
        0x0300 => {
            return simulate_real_mode_int(dos, regs);
        }
        // AX=0301h — Call Real Mode Far Procedure
        // ES:EDI = real-mode call structure
        0x0301 => {
            return call_real_mode_proc(dos, regs);
        }
        // AX=0302h — Call Real Mode Procedure with IRET Frame
        // ES:EDI = real-mode call structure (procedure returns via IRET)
        0x0302 => {
            return call_real_mode_proc_iret(dos, regs);
        }
        // AX=0303h — Allocate Real Mode Callback Address
        // DS:SI = PM callback handler, ES:DI = real-mode register structure
        // Returns: CX:DX = real-mode callback address (segment:offset)
        0x0303 => {
            let dpmi = dos.dpmi.as_mut().unwrap();
            // Find a free callback slot
            let slot = dpmi.callbacks.iter().position(|c| c.is_none());
            match slot {
                Some(i) => {
                    dpmi.callbacks[i] = Some((
                        regs.ds as u16,
                        regs.rsi as u32,
                        regs.es as u16,
                        regs.rdi as u32,
                    ));
                    // Return real-mode address: STUB_SEG:slot_offset(SLOT_CB_ENTRY_BASE + i)
                    let rm_off = dos::slot_offset(dos::SLOT_CB_ENTRY_BASE + i as u8);
                    regs.rcx = (regs.rcx & !0xFFFF) | dos::STUB_SEG as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | rm_off as u64;
                    clear_carry(regs);
                }
                None => set_carry(regs),
            }
        }
        // AX=0304h — Free Real Mode Callback Address
        // CX:DX = real-mode callback address to free
        0x0304 => {
            let dpmi = dos.dpmi.as_mut().unwrap();
            let off = regs.rdx as u16;
            let cb_base = dos::slot_offset(dos::SLOT_CB_ENTRY_BASE);
            let cb_end = dos::slot_offset(dos::SLOT_CB_ENTRY_END);
            if off >= cb_base && off < cb_end {
                let idx = ((off - cb_base) / 2) as usize;
                dpmi.callbacks[idx] = None;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0400h — Get DPMI Version
        // Returns: AH=major, AL=minor, BX=flags, CL=processor, DH=master PIC, DL=slave PIC
        0x0400 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x005A; // version 0.90
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0005; // 32-bit, no virtual memory
            regs.rcx = (regs.rcx & !0xFF) | 0x03;     // 386 processor
            // DH = master PIC base vector, DL = slave PIC base vector
            // Report 0x08/0x70 (matching real-mode BIOS mapping) so DJGPP hooks
            // IRQ 1 as INT 9 (keyboard), IRQ 0 as INT 8 (timer), etc.
            regs.rdx = (regs.rdx & !0xFFFF) | ((0x08 << 8) | 0x70) as u64;
            clear_carry(regs);
        }
        // AX=0500h — Get Free Memory Information
        // ES:EDI = 48-byte buffer. Mirror CWSDPMI: fields that aren't applicable
        // stay as 0xFFFFFFFF ("unknown / no limit"). DOS/4GW branches on [3]/[7]
        // (linear space) — concrete small values trigger a conservative path.
        0x0500 => {
            let dest = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
            let physical_pages: u32 = 4096;
            let free_pages: u32 = 4096;
            let swap_pages: u32 = 0x4000; // pretend 64 MB of paging file (CWSDPMI default w/ swap)
            let mut info = [0xFFFF_FFFFu32; 12];
            info[4] = physical_pages;            // total unlocked
            info[6] = physical_pages;            // total physical
            info[2] = free_pages;                // max locked alloc
            info[5] = free_pages;                // total free
            info[8] = swap_pages;                // paging file pages
            info[1] = swap_pages + physical_pages; // max unlocked alloc (pages)
            info[0] = info[1] << 12;             // largest block (bytes)
            unsafe {
                for (i, value) in info.into_iter().enumerate() {
                    core::ptr::write_unaligned((dest as *mut u32).add(i), value);
                }
            }
            clear_carry(regs);
        }
        // AX=0501h — Allocate Memory Block
        // BX:CX = size in bytes. Returns: BX:CX = linear address, SI:DI = handle
        0x0501 => {
            let size = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            if size == 0 { set_carry(regs); return thread::KernelAction::Done; }
            // Align to page boundary
            let aligned = (size + 0xFFF) & !0xFFF;
            let base = dpmi.mem_next;
            dpmi.mem_next = dpmi.mem_next.wrapping_add(aligned);
            // Record the block
            let mut stored = false;
            for slot in dpmi.mem_blocks.iter_mut() {
                if slot.is_none() {
                    *slot = Some(MemBlock { base, size: aligned });
                    stored = true;
                    break;
                }
            }
            if !stored { set_carry(regs); return thread::KernelAction::Done; }
            // Return linear address in BX:CX
            dos_trace!("[DPMI] 0501 alloc size={:#x} -> base={:#x}", size, base);
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (base & 0xFFFF) as u64;
            // Return handle in SI:DI (use base address as handle)
            regs.rsi = (regs.rsi & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (base & 0xFFFF) as u64;
            clear_carry(regs);
        }
        // AX=0502h — Free Memory Block
        // SI:DI = handle
        0x0502 => {
            let handle = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            for slot in dpmi.mem_blocks.iter_mut() {
                if let Some(blk) = slot {
                    if blk.base == handle {
                        *slot = None;
                        break;
                    }
                }
            }
            clear_carry(regs);
        }
        // AX=0503h — Resize Memory Block
        // BX:CX = new size, SI:DI = handle
        // Returns: BX:CX = new linear address, SI:DI = new handle
        0x0503 => {
            let new_size = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            let handle = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            let aligned = (new_size + 0xFFF) & !0xFFF;
            // Grow in place — all memory is demand-paged so we just update the size.
            // This preserves existing data (pages already faulted in stay mapped).
            let mut base = handle;
            for slot in dpmi.mem_blocks.iter_mut() {
                if let Some(blk) = slot {
                    if blk.base == handle {
                        // Ensure mem_next covers the grown region
                        let end = blk.base.wrapping_add(aligned);
                        if end > dpmi.mem_next {
                            dpmi.mem_next = end;
                        }
                        blk.size = aligned;
                        base = blk.base;
                        break;
                    }
                }
            }
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (base & 0xFFFF) as u64;
            regs.rsi = (regs.rsi & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (base & 0xFFFF) as u64;
            clear_carry(regs);
        }
        // AX=0600h-0601h — Lock/Unlock Linear Region (no-op, all memory is locked)
        0x0600 | 0x0601 => {
            clear_carry(regs);
        }
        // AX=0702h — Mark Page as Demand Paging Candidate
        // AX=0703h — Discard Page Contents
        // This host does not implement demand-paged VM, so these are advisory no-ops.
        0x0702 | 0x0703 => {
            clear_carry(regs);
        }
        // AX=0900h — Get and Disable Virtual Interrupt State
        // Returns: AL = previous state (1=enabled, 0=disabled)
        0x0900 => {
            let prev = if regs.frame.rflags & (1 << 9) != 0 { 1u64 } else { 0u64 };
            regs.frame.rflags &= !(1 << 9);
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0901h — Get and Enable Virtual Interrupt State
        0x0901 => {
            let prev = if regs.frame.rflags & (1 << 9) != 0 { 1u64 } else { 0u64 };
            regs.frame.rflags |= 1 << 9;
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0902h — Get Virtual Interrupt State
        0x0902 => {
            regs.rax = (regs.rax & !0xFF) | if regs.frame.rflags & (1 << 9) != 0 { 1 } else { 0 };
            clear_carry(regs);
        }
        // AX=0A00h — Get Vendor-Specific API Entry Point (not supported)
        0x0A00 => {
            set_carry(regs);
        }
        // AX=0305h — Get State Save/Restore Addresses
        // AX=0 means "no client buffer needed"; host keeps state internally.
        // Matches CWSDPMI (exphdlr.c:1145). A non-zero size is a semantic
        // signal to clients that changes their setup path even if they never
        // call the routine.
        0x0305 => {
            regs.rax = regs.rax & !0xFFFF;
            // Real-mode save/restore: stub slot SLOT_SAVE_RESTORE
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u64;
            // Protected-mode save/restore entry in the special-stub segment.
            regs.rsi = (regs.rsi & !0xFFFF) | SPECIAL_STUB_SEL as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (dos::STUB_BASE + dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u32) as u64;
            clear_carry(regs);
        }
        // AX=0306h — Get Raw Mode Switch Addresses
        // Returns real-to-PM and PM-to-real switch entry points
        0x0306 => {
            // BX:CX = real-to-PM entry point (real-mode segment:offset)
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_RAW_REAL_TO_PM) as u64;
            // SI:(E)DI = PM-to-real entry in the special-stub segment.
            regs.rsi = (regs.rsi & !0xFFFF) | SPECIAL_STUB_SEL as u64;
            regs.rdi = (regs.rdi & !0xFFFFFFFF) | (dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_TO_REAL) as u32) as u64;
            clear_carry(regs);
        }
        // AX=0507h — Set Page Attributes (DPMI 1.0)
        // All our memory is committed, so this is a no-op.
        0x0507 => {
            clear_carry(regs);
        }
        // AX=0E00h — Get Coprocessor Status
        // AX=0E01h — Set Coprocessor Emulation
        // FPU is always available and not emulated.
        0x0E00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0E00;
            // BX: bit 0 = MPv (FPU exists), bits 4-7 = FPU type (4=487SX+)
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0041;
            clear_carry(regs);
        }
        0x0E01 => {
            clear_carry(regs);
        }
        // AX=0800h — Physical Address Mapping
        // BX:CX = physical address, SI:DI = size
        // Returns BX:CX = linear address
        0x0800 => {
            let phys = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            let size = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            let aligned = (size + 0xFFF) & !0xFFF;
            // Allocate virtual range from DPMI linear memory pool
            let base = dpmi.mem_next;
            dpmi.mem_next = dpmi.mem_next.wrapping_add(aligned);
            // Map physical pages at the allocated virtual address via ring-0 arch call
            let num_pages = aligned as usize / 4096;
            let vpage_start = base as usize / 4096;
            let ppage_start = phys as u64 / 4096;
            // PWT (bit 3) + PCD (bit 4): write-through, cache-disable for MMIO
            crate::kernel::startup::arch_map_phys_range(vpage_start, num_pages, ppage_start, (1 << 3) | (1 << 4));
            // Return linear address
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) as u64);
            regs.rcx = (regs.rcx & !0xFFFF) | ((base & 0xFFFF) as u64);
            clear_carry(regs);
        }
        // AX=0801h — Free Physical Address Mapping (no-op, we don't track)
        0x0801 => {
            clear_carry(regs);
        }
        _ => {
            dos_trace!("  DPMI: unhandled INT 31h AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:04x}:{:#x}",
                ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.code_seg(), regs.ip32());
            set_carry(regs);
            regs.rax = (regs.rax & !0xFFFF) | 0x8001; // unsupported function
        }
    }

    dos_trace!("[INT31 RET] AX={:04x} CF={:x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        regs.rax as u16, regs.frame.rflags & 1,
        regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    trace_client_selector_leak("dpmi_int31.exit", regs);
    thread::KernelAction::Done
}

// ============================================================================
// Real-mode callbacks (INT 31h/0300h, 0301h)
// ============================================================================

/// DPMI real-mode call structure (50 bytes at ES:EDI)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RmCallStruct {
    edi: u32, esi: u32, ebp: u32, _reserved: u32,
    ebx: u32, edx: u32, ecx: u32, eax: u32,
    flags: u16, es: u16, ds: u16, fs: u16, gs: u16,
    ip: u16, cs: u16, sp: u16, ss: u16,
}

/// INT 31h/0300h — Simulate Real Mode Interrupt
/// Trace helper: peek 16 bytes at RM linear (ds<<4)+edx and print ASCII.
/// Used to see what filename/buffer DOS/4GW hands to real mode.
fn dump_ds_dx(ds: u16, edx: u32) {
    let linear = ((ds as u32) << 4).wrapping_add(edx & 0xFFFF);
    if linear >= 0x110000 { return; } // guard against non-low memory
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = unsafe { core::ptr::read_volatile((linear + i as u32) as *const u8) };
    }
    dos_trace!(
        "[DPMI]   DS:DX@{:05X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}  '{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}'",
        linear,
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        printable(bytes[0]), printable(bytes[1]), printable(bytes[2]), printable(bytes[3]),
        printable(bytes[4]), printable(bytes[5]), printable(bytes[6]), printable(bytes[7]),
        printable(bytes[8]), printable(bytes[9]), printable(bytes[10]), printable(bytes[11]),
        printable(bytes[12]), printable(bytes[13]), printable(bytes[14]), printable(bytes[15]),
    );
}

fn printable(b: u8) -> char {
    if (0x20..0x7F).contains(&b) { b as char } else { '.' }
}

fn simulate_real_mode_int(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let int_num = regs.rbx as u8;

    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    // Read the real-mode call structure from ES:EDI (use client_use32, not cs_32)
    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    { let (ax, bx, cx, dx, ds, es, edi) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi);
      dos_trace!("[DPMI] 0300 int={:02X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X}",
        int_num, ax, bx, cx, dx, ds, es, edi);
      dump_ds_dx(ds, rm.edx); }

    // Use SS:SP from structure if provided, else our dedicated RM stack.
    // The default must NOT overlap the client's data area (PSP_SEGMENT is unsafe).
    let used_dedicated = rm.ss == 0;
    let rm_ss = if rm.ss != 0 { rm.ss } else { dos::rm_stack_seg() };
    let rm_sp = if rm.sp != 0 { rm.sp } else { super::mode_transitions::rm_stack_top() };

    // Save PM state + rm_struct_addr stub-arg on locked stack (CALL slot).
    // When using the dedicated RM stack, snapshot it first so a nested
    // RM excursion can run on a fresh stack and the outer caller resumes
    // intact on unwind. The stub records this so SLOT_RM_IRET_CALL knows
    // whether to pop the snapshot.
    let stub = CallStubFrame::capture(regs, struct_addr, used_dedicated);
    super::mode_transitions::push_save(dos, regs);
    if used_dedicated { super::mode_transitions::push_rm_snapshot(dos); }
    dos.pc.host_stack_sp = host_stack_write_call_args(dos.pc.host_stack_sp, stub);

    // Get IVT entry for the interrupt
    let ivt_off = machine::read_u16(0, (int_num as u32) * 4);
    let ivt_seg = machine::read_u16(0, (int_num as u32) * 4 + 2);

    // Set up VM86 state
    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    // RM IRET frame target: SLOT_RM_IRET_CALL.
    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // Push return IRET frame on VM86 stack
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Set CS:IP to the IVT handler
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;

    dos_trace!("[DPMI] simulate INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        int_num, ivt_seg, ivt_off, rm_ss, rm_sp.wrapping_sub(6));

    // Now in VM86 mode — the event loop will execute the BIOS handler.
    // When it IRETs to callback_stub, INT 31h fires, and callback_return() is called.
    thread::KernelAction::Done
}

/// Reflect a software INT from protected mode to real mode via the IVT.
/// Used when a DPMI client executes `INT xx` and no PM handler is installed.
/// Per DPMI 0.9 §2.4 / §3.2: EAX/EBX/ECX/EDX/ESI/EDI/EBP and flags are
/// passed unaltered; segment registers are undefined in real mode. Any API
/// that passes pointers via segments is the DOS extender's responsibility
/// to translate via its own INT 21h hook — not the host's.
fn reflect_int_to_real_mode(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    // Save client state, snapshot the dedicated RM stack onto the
    // locked stack, then run BIOS on a fresh dedicated RM stack. BIOS
    // runs on a kernel-owned RM stack — never on the client's own VM86
    // stack — so a HW IRQ landing during a sensitive moment in the
    // client (e.g. just after exec_return) can't trample the client's
    // saved registers / return address. The snapshot+restore pair on
    // the locked stack provides reentrance for nested kernel-orchestrated
    // RM excursions. Works for VM86 and PM clients alike — no DPMI
    // session required.
    super::mode_transitions::push_save(dos, regs);
    super::mode_transitions::push_rm_snapshot(dos);

    // Get IVT entry
    let ivt_off = machine::read_u16(0, (vector as u32) * 4);
    let ivt_seg = machine::read_u16(0, (vector as u32) * 4 + 2);

    regs.frame.ss = dos::rm_stack_seg() as u64;
    regs.frame.rsp = super::mode_transitions::rm_stack_top() as u64;

    // Push RM IRET frame targeting SLOT_RM_IRET_REFLECT.
    // Push trampoline IRET frame on the RM slab, mirroring what the CPU's
    // own INT n in real mode would push: FLAGS / CS / IP. FLAGS is the
    // client's flags *unmodified* — that's what real-mode INT writes,
    // and it's what BIOS IRET pops back. The handler runs with IF=0
    // because we set it on `regs.frame.rflags` below, not by mutating
    // the on-stack frame. Pushing 0 (or modifying flags here) would let
    // `rm_iret_reflect`'s status-flag passthrough (CF/ZF/DF/...) snapshot
    // wrong values and silently corrupt the client across the IRQ.
    let ret_flags = regs.flags32() as u16;
    let ret_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_REFLECT);
    let ret_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, ret_flags);
    machine::vm86_push(regs, ret_seg);
    machine::vm86_push(regs, ret_off);

    // Enter the BIOS handler in VM86 with IF cleared — matches what the
    // CPU's own INT n does in real mode (preserves status flags, just
    // clears IF). VIF is owned by the arch layer (VME virtualization),
    // not us. IOPL=1 keeps cli/sti virtualized.
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    let flags = (regs.flags32() & !(machine::IF_FLAG | machine::IOPL_MASK))
        | machine::VM_FLAG
        | machine::IOPL_VM86;
    regs.frame.rflags = flags as u64;

    // Per DPMI, the host must not translate PM selectors into RM paragraphs
    // when reflecting a software interrupt. The extender/client is responsible
    // for any DOS-call marshaling that requires real-mode segment values.

    dos_trace!("[DPMI] reflect INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X} DS={:04X} ES={:04X}",
        vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32(), regs.rax as u16,
        regs.ds as u16, regs.es as u16);

    thread::KernelAction::Done
}

/// INT 31h/0301h — Call Real Mode Far Procedure
fn call_real_mode_proc(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let used_dedicated = rm.ss == 0;
    let rm_ss = if rm.ss != 0 { rm.ss } else { dos::rm_stack_seg() };
    let rm_sp = if rm.sp != 0 { rm.sp } else { super::mode_transitions::rm_stack_top() };

    // Save PM state + rm_struct_addr stub-arg on locked stack (CALL slot).
    // Snapshot dedicated RM stack iff we're using it (see simulate_real_mode_int).
    let stub = CallStubFrame::capture(regs, struct_addr, used_dedicated);
    super::mode_transitions::push_save(dos, regs);
    if used_dedicated { super::mode_transitions::push_rm_snapshot(dos); }
    dos.pc.host_stack_sp = host_stack_write_call_args(dos.pc.host_stack_sp, stub);

    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For FAR CALL: push return address (callback stub) as FAR return
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Jump to the far procedure
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;
    thread::KernelAction::Done
}

/// INT 31h/0302h — Call Real Mode Procedure with IRET Frame
fn call_real_mode_proc_iret(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    { let (ax, bx, cx, dx, ds, es, edi, cs, ip) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi, rm.cs, rm.ip);
      dos_trace!("[DPMI] 0302 AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X} CS:IP={:04X}:{:04X}",
        ax, bx, cx, dx, ds, es, edi, cs, ip);
      let (edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f) =
          (rm.edi, rm.esi, rm.ebp, rm.ebx, rm.edx, rm.ecx, rm.eax, rm.flags);
      dos_trace!("[DPMI] 0302 RMCS full: EDI={:08X} ESI={:08X} EBP={:08X} EBX={:08X} EDX={:08X} ECX={:08X} EAX={:08X} flags={:04X}",
        edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f);
      dump_ds_dx(ds, rm.edx); }

    let used_dedicated = rm.ss == 0;
    let rm_ss = if rm.ss != 0 { rm.ss } else { dos::rm_stack_seg() };
    let rm_sp = if rm.sp != 0 { rm.sp } else { super::mode_transitions::rm_stack_top() };

    let stub = CallStubFrame::capture(regs, struct_addr, used_dedicated);
    super::mode_transitions::push_save(dos, regs);
    if used_dedicated { super::mode_transitions::push_rm_snapshot(dos); }
    dos.pc.host_stack_sp = host_stack_write_call_args(dos.pc.host_stack_sp, stub);

    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For IRET frame: push FLAGS, CS, IP (callback return stub)
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;

    thread::KernelAction::Done
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub fn callback_entry(dos: &mut thread::DosState, regs: &mut Regs, cb_idx: usize) {
    let cb = match dos.dpmi.as_ref() {
        Some(d) => d.callbacks[cb_idx],
        None => {
            crate::println!("DPMI: callback entry but no DPMI state!");
            return;
        }
    };
    let (pm_cs, pm_eip, rm_struct_sel, rm_struct_off) = match cb {
        Some(cb) => cb,
        None => {
            crate::println!("DPMI: callback {} not allocated!", cb_idx);
            return;
        }
    };



    // Save current real-mode regs into the register structure
    let struct_addr = seg_base(&dos.ldt[..], rm_struct_sel).wrapping_add(rm_struct_off);

    let rm_call = RmCallStruct {
        edi: regs.rdi as u32,
        esi: regs.rsi as u32,
        ebp: regs.rbp as u32,
        _reserved: 0,
        ebx: regs.rbx as u32,
        edx: regs.rdx as u32,
        ecx: regs.rcx as u32,
        eax: regs.rax as u32,
        flags: regs.flags32() as u16,
        es: regs.es as u16,
        ds: regs.ds as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
        ip: regs.ip32() as u16,
        cs: regs.code_seg(),
        sp: regs.sp32() as u16,
        ss: regs.stack_seg(),
    };
    unsafe { *(struct_addr as *mut RmCallStruct) = rm_call; }

    // Save RM state + rm_struct_addr stub-arg on locked stack (CALL slot
    // — the PM callback's eventual unwind writes its post-handler RM
    // regs back into the RmCallStruct). RM→PM transition: PM handler
    // runs on locked PM stack, dedicated RM stack is untouched, so no
    // RmSnapshot push.
    let stub = CallStubFrame::capture(regs, struct_addr, /*used_dedicated_rm=*/ false);
    super::mode_transitions::push_save(dos, regs);
    dos.pc.host_stack_sp = host_stack_write_call_args(dos.pc.host_stack_sp, stub);

    // Switch to protected mode and call the PM handler.
    // DS:SI = selector:offset pointing to real-mode SS:SP
    // ES:DI = selector:offset pointing to register structure
    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.cs = pm_cs as u64;
    regs.set_ip32(pm_eip);
    regs.ds = rm_struct_sel as u64;  // DS:ESI = register structure
    regs.rsi = rm_struct_off as u64;
    regs.es = rm_struct_sel as u64;  // ES:EDI = register structure
    regs.rdi = rm_struct_off as u64;
}

/// SLOT_RM_IRET_REFLECT dispatch — implicit IVT-reflection unwind.
/// Called when VM86 IRETs from a BIOS handler we entered via
/// `reflect_int_to_real_mode`. Pops the `ModeSave` and restores
/// CS/EIP/SS/ESP/EFLAGS/segregs. GP regs are *not* in `ModeSave` — per
/// DPMI 0.9 §2.4 they round-trip through real mode (BIOS modifies them,
/// PM caller sees the modified values). Then ORs IF=1 into EFLAGS per
/// the spec's "default IRQ stub must STI before IRET" rule
/// (`feedback_dpmi_default_stub_sti`).
pub fn rm_iret_reflect(dos: &mut thread::DosState, regs: &mut Regs) {
    // Snapshot RM arithmetic flags before restore overwrites EFLAGS.
    // VM/IOPL/IF/TF/RF/NT must come from the saved PM state — copying
    // RM EFLAGS verbatim would set VM=1 and drop us back into VM86.
    const STATUS_MASK: u32 = 0x0CD5; // CF,PF,AF,ZF,SF,OF,DF
    let rm_arith = regs.flags32() & STATUS_MASK;

    // Restore the dedicated RM stack from its snapshot on the locked
    // stack, then pop the save and restore regs to the original PM
    // (or VM86) caller state.
    super::mode_transitions::pop_rm_snapshot(dos);
    super::mode_transitions::pop_save(dos).restore(regs);

    regs.set_flags32((regs.flags32() & !STATUS_MASK) | rm_arith);
    regs.frame.rflags |= machine::IF_FLAG as u64;

    dos_trace!("[DPMI] RM_IRET_REFLECT -> CS:EIP={:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
}

/// SLOT_RM_IRET_FORWARD dispatch — HW-IRQ default-stub bridge return.
///
/// Called when BIOS IRETs in RM after the kernel set up an RM excursion
/// via `vector_stub_reflect`'s outermost branch. The locked stack carries
/// the *outer* `ModeSave` from `deliver_pm_irq`'s cross-mode entry, the
/// dead iret frame deliver_pm_irq planted, and the rm_stack snapshot
/// pushed by `vector_stub_reflect`. We unwind all three synchronously
/// here — net result for the HW IRQ default-stub flow: a single
/// ModeSave, popped here.
///
/// We can't route this back through SLOT_PM_IRET via a synthesized iret
/// frame: between this fn returning and the user's CD 31 trap on
/// SLOT_PM_IRET, `raise_pending` runs at the next loop iteration and
/// will see `regs.SS == HOST_STACK_PM*_SEL`, take its
/// nested-on-host-stack branch, plant a new iret frame, and the new
/// vector_stub_reflect will misclassify the synthesized SLOT_PM_IRET
/// target as outermost — pushing a second rm_snapshot atop the live
/// outer save and corrupting the chain.
pub fn rm_iret_forward_to_pm(dos: &mut thread::DosState, regs: &mut Regs) {
    // Snapshot RM arithmetic flags before restore overwrites EFLAGS
    // (BIOS may have set CF/ZF/etc that the client expects preserved).
    const STATUS_MASK: u32 = 0x0CD5;
    let rm_arith = regs.flags32() & STATUS_MASK;

    super::mode_transitions::pop_rm_snapshot(dos);

    // host_stack_sp now points at the iret frame deliver_pm_irq planted;
    // those bytes are logically dead (the user consumed the iret with
    // the hardware iret that took them into vector_stub_reflect).
    // Advance past them so pop_save reads the outer ModeSave.
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);
    let iret_size: u32 = if client_use32 { 12 } else { 6 };
    dos.pc.host_stack_sp += iret_size;

    super::mode_transitions::pop_save(dos).restore(regs);

    // Pass through BIOS's status-flag updates and force IF=1
    // (default-stub STI rule the host owes the client per DPMI 0.9).
    regs.set_flags32((regs.flags32() & !STATUS_MASK) | rm_arith);
    regs.frame.rflags |= machine::IF_FLAG as u64;

    // HW-IRQ context ends here (parallels SLOT_PM_IRET → cross_mode_restore).
    super::IN_HW_IRQ_CONTEXT.store(false, core::sync::atomic::Ordering::Relaxed);

    dos_trace!("[DPMI] RM_IRET_FORWARD -> CS:EIP={:04x}:{:#x} SS:ESP={:04x}:{:#x}",
        regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
}

/// SLOT_RM_IRET_CALL dispatch — explicit PM→RM call unwind (0x0300/01/02
/// and `callback_entry`). Pops the `CallStubFrame`, writes current RM regs
/// (the post-call values) into the RmCallStruct at `rm_struct_addr`, then
/// restores the saved GP regs and pops the `ModeSave`. Restoration order
/// is critical: writeback uses *current* (post-RM) regs, so it must run
/// before `restore_gp` overwrites them.
pub fn rm_iret_call(dos: &mut thread::DosState, regs: &mut Regs) {
    let stub = host_stack_read_call_args(dos.pc.host_stack_sp);
    dos.pc.host_stack_sp += CALL_STUB_SIZE;
    // Restore the dedicated RM stack iff this excursion ran on it
    // (the recipe recorded the choice on push). User-supplied SS:SP
    // means BIOS pushed onto the user's stack; our dedicated buffer
    // was never touched, no snapshot to restore.
    if stub.used_dedicated_rm != 0 {
        super::mode_transitions::pop_rm_snapshot(dos);
    }
    let save = super::mode_transitions::pop_save(dos);

    // Writeback current RM regs into RmCallStruct so the PM caller sees
    // results. Must happen *before* GP-restore overwrites regs.
    let rm_struct_addr = { let f = stub; f.rm_struct_addr };
    let rm_struct = RmCallStruct {
        edi: regs.rdi as u32,
        esi: regs.rsi as u32,
        ebp: regs.rbp as u32,
        _reserved: 0,
        ebx: regs.rbx as u32,
        edx: regs.rdx as u32,
        ecx: regs.rcx as u32,
        eax: regs.rax as u32,
        flags: regs.flags32() as u16,
        es: regs.es as u16,
        ds: regs.ds as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
        ip: regs.ip32() as u16,
        cs: regs.code_seg(),
        sp: regs.sp32() as u16,
        ss: regs.stack_seg(),
    };
    unsafe { *(rm_struct_addr as *mut RmCallStruct) = rm_struct; }

    stub.restore_gp(regs);
    save.restore(regs);

    dos_trace!("[INT31 RET] AX={:04x} CF={:x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        regs.rax as u16, regs.flags32() & 1,
        regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    trace_client_selector_leak("rm_iret_call.restore", regs);
}

// ============================================================================
// DPMI exception dispatch — route CPU exceptions to client handlers
// ============================================================================

/// Dispatch a CPU exception to the client's exception handler (set via INT 31h/0203h).
/// If no handler is set, kill the thread.
///
/// DPMI 0.9 exception handler calling convention. The handler is called with a
/// FAR CALL. Frame width depends on the client type (16-bit clients get word
/// fields, 32-bit clients get dword fields).
///
/// 32-bit client frame:
///   [ESP+0]  Return EIP (points to DPMI host retf stub)
///   [ESP+4]  Return CS (DPMI host code selector)
///   [ESP+8]  Error code (dword)
///   [ESP+12] Faulting EIP
///   [ESP+16] Faulting CS
///   [ESP+20] Faulting EFLAGS
///   [ESP+24] Faulting ESP
///   [ESP+28] Faulting SS
///
/// 16-bit client frame (all fields are words):
///   [SP+0]   Return IP
///   [SP+2]   Return CS
///   [SP+4]   Error code
///   [SP+6]   Faulting IP
///   [SP+8]   Faulting CS
///   [SP+10]  Faulting FLAGS
///   [SP+12]  Faulting SP
///   [SP+14]  Faulting SS
pub fn dispatch_dpmi_exception(dos: &mut thread::DosState, regs: &mut Regs, exc_num: u32) -> thread::KernelAction {
    dos_trace!("[DPMI] EXCEPTION {} CS:EIP={:04x}:{:#x} err={:#x} DS={:04x} ES={:04x} FS={:04x} GS={:04x} SS:ESP={:04x}:{:#x}",
        exc_num, regs.code_seg(), regs.ip32(), regs.err_code,
        regs.ds as u16, regs.es as u16, regs.fs as u16, regs.gs as u16,
        regs.stack_seg(), regs.sp32());
    // No verbose dump on handled #GP/#PF -- DPMI clients routinely take
    // these for sensitive-insn emulation; the dump goes to VGA and clobbers
    // the user screen. The unhandled-exception path below still dumps.
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => {
            return thread::KernelAction::Exit(-(exc_num as i32));
        }
    };

    let (handler_sel, handler_off) = if (exc_num as usize) < 32 {
        dpmi.exc_vectors[exc_num as usize]
    } else {
        (0, 0)
    };

    if handler_sel == 0 && handler_off == 0 {
        // Per DPMI 0.9: software-INT exceptions (0/3/4 = #DE/#BP/#OF) reflect
        // to the real-mode IVT when the client has not installed a handler —
        // dpmiload uses INT 3 as "halt on error" and expects the real-mode
        // handler (a bare IRET stub) to bring it back. Hardware faults like
        // #GP (13) or #PF (14) must NOT be reflected: their IVT slots point
        // at unrelated services (e.g. INT 13h is BIOS disk I/O), and the
        // faulting instruction would just re-execute and refault, producing
        // an infinite loop. Terminate the client instead.
        if matches!(exc_num, 0 | 3 | 4) {
            return reflect_int_to_real_mode(dos, regs, exc_num as u8);
        }
        crate::println!("DPMI: exception {} at CS:EIP={:#06x}:{:#x} err={:#x}, no handler",
            exc_num, regs.frame.cs as u16, regs.ip32(), regs.err_code);
        startup::arch_dump_exception(dos, regs);
        return thread::KernelAction::Exit(-(exc_num as i32));
    }

    // Build exception frame on client's stack — width depends on client type.
    let use32 = dpmi.client_use32;
    let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
    let ss_32 = seg_is_32(&dos.ldt[..], regs.stack_seg());

    let mut sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };

    // Return address for the handler's RETF — point to our exception return
    // stub in the special-stub segment (CD 31 → pm_stub_dispatch).
    let stub_off = dos::STUB_BASE + dos::slot_offset(dos::SLOT_EXCEPTION_RET) as u32;

    if use32 {
        let push32 = |sp: &mut u32, val: u32| {
            *sp = sp.wrapping_sub(4);
            unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(*sp)) as *mut u32, val); }
        };
        push32(&mut sp, regs.frame.ss as u32);        // faulting SS
        push32(&mut sp, regs.sp32());                  // faulting ESP
        push32(&mut sp, regs.flags32());               // faulting EFLAGS
        push32(&mut sp, regs.frame.cs as u32);         // faulting CS
        push32(&mut sp, regs.ip32());                  // faulting EIP
        push32(&mut sp, regs.err_code as u32);         // error code
        push32(&mut sp, SPECIAL_STUB_SEL as u32);      // return CS
        push32(&mut sp, stub_off);                     // return EIP
    } else {
        let push16 = |sp: &mut u32, val: u16| {
            *sp = sp.wrapping_sub(2);
            unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(*sp)) as *mut u16, val); }
        };
        push16(&mut sp, regs.frame.ss as u16);         // faulting SS
        push16(&mut sp, regs.sp32() as u16);           // faulting SP
        push16(&mut sp, regs.flags32() as u16);        // faulting FLAGS
        push16(&mut sp, regs.frame.cs as u16);         // faulting CS
        push16(&mut sp, regs.ip32() as u16);           // faulting IP
        push16(&mut sp, regs.err_code as u16);         // error code
        push16(&mut sp, SPECIAL_STUB_SEL);             // return CS
        push16(&mut sp, stub_off as u16);              // return IP
    }

    // Set up regs to call the exception handler
    if ss_32 {
        regs.set_sp32(sp);
    } else {
        regs.set_sp32((regs.sp32() & !0xFFFF) | (sp & 0xFFFF));
    }
    regs.frame.cs = handler_sel as u64;
    regs.set_ip32(handler_off);

    thread::KernelAction::Done
}

/// Handle return from a DPMI exception handler. Reached when the handler RETFs
/// to our stub in the special-stub segment at SLOT_EXCEPTION_RET which then
/// executes CD 31, routed here via pm_stub_dispatch.
///
/// At this point regs.SS:SP points to the exception frame minus the return
/// address that the handler's RETF already popped. Frame width matches the
/// client type (16-bit clients have word fields, 32-bit clients have dword
/// fields).
///
/// 32-bit client frame remaining:
///   [ESP+0]  error code (dword)
///   [ESP+4]  faulting EIP (possibly modified)
///   [ESP+8]  faulting CS
///   [ESP+12] faulting EFLAGS
///   [ESP+16] faulting ESP
///   [ESP+20] faulting SS
///
/// 16-bit client frame remaining (all words):
///   [SP+0]   error code
///   [SP+2]   faulting IP
///   [SP+4]   faulting CS
///   [SP+6]   faulting FLAGS
///   [SP+8]   faulting SP
///   [SP+10]  faulting SS
fn exception_return(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => return thread::KernelAction::Done,
    };

    let use32 = dpmi.client_use32;
    let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
    let ss_32 = seg_is_32(&dos.ldt[..], regs.stack_seg());

    let mut sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };

    let (new_eip, new_cs, new_eflags, new_esp, new_ss);
    if use32 {
        let pop32 = |sp: &mut u32| -> u32 {
            let val = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(*sp)) as *const u32) };
            *sp = sp.wrapping_add(4);
            val
        };
        let _error_code = pop32(&mut sp);
        new_eip = pop32(&mut sp);
        new_cs = pop32(&mut sp) as u16;
        new_eflags = pop32(&mut sp);
        new_esp = pop32(&mut sp);
        new_ss = pop32(&mut sp) as u16;
    } else {
        let pop16 = |sp: &mut u32| -> u16 {
            let val = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(*sp)) as *const u16) };
            *sp = sp.wrapping_add(2);
            val
        };
        let _error_code = pop16(&mut sp);
        new_eip = pop16(&mut sp) as u32;
        new_cs = pop16(&mut sp);
        new_eflags = pop16(&mut sp) as u32;
        new_esp = pop16(&mut sp) as u32;
        new_ss = pop16(&mut sp);
    }

    regs.frame.cs = new_cs as u64;
    regs.set_ip32(new_eip);
    regs.frame.ss = new_ss as u64;
    if ss_32 {
        regs.set_sp32(new_esp);
    } else {
        regs.set_sp32((regs.sp32() & !0xFFFF) | (new_esp & 0xFFFF));
    }
    // Restore EFLAGS but preserve IOPL and VM
    let preserved = regs.flags32() & machine::PRESERVED_FLAGS;
    regs.set_flags32((new_eflags & !machine::PRESERVED_FLAGS) | preserved);
    trace_client_selector_leak("exception_return.out", regs);
    thread::KernelAction::Done
}

// ============================================================================
// Raw mode switch (INT 31h/0306h)
// ============================================================================

/// RM→PM transition: build the PM-side PSP view from the active RM PSP.
///
/// Captures the current RM PSP segment and PSP[0x2C] (so PM→RM can restore
/// them), rebuilds the fixed `PSP_SEL` LDT[4] descriptor with base = current
/// RM PSP * 16, and (for 32-bit clients per DPMI 0.9 §4.1) allocates a fresh
/// env selector and patches PSP[0x2C] to point at it. Finally sets
/// `dos.current_psp = PSP_SEL` so PM-side AH=51/62 reflections return a value
/// the client can load into ES.
///
/// 16-bit clients (DOS/16M) read PSP[0x2C] as an RM segment, so leave it
/// unpatched — the env_ldt_idx stays 0 and PM→RM has nothing to undo.
fn enter_pm_psp_view(dos: &mut thread::DosState) {
    let rm_psp = dos.current_psp;
    let psp_base = (rm_psp as u32) * 16;
    let env_seg = unsafe { core::ptr::read_volatile((psp_base + 0x2C) as *const u16) };

    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };

    dpmi.saved_rm_psp = rm_psp;
    dpmi.saved_rm_env = env_seg;

    // PSP_SEL descriptor: base = active RM PSP, limit = 64K. Spec says
    // limit=100h but real extenders (DOS/4GW) reuse ES as scratch and need
    // the full 64K window.
    dos.ldt[PSP_LDT_IDX] = DpmiState::make_data_desc_ex(psp_base, 0xFFFF, false);
    dos.ldt_alloc[0] |= 1 << PSP_LDT_IDX;

    dpmi.env_ldt_idx = 0;
    if dpmi.client_use32 && env_seg != 0 {
        if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
            let env_base = (env_seg as u32) * 16;
            dos.ldt[idx] = DpmiState::make_data_desc_ex(env_base, 0xFFFF, false);
            let env_sel = DpmiState::idx_to_sel(idx);
            unsafe { core::ptr::write_volatile((psp_base + 0x2C) as *mut u16, env_sel); }
            dpmi.env_ldt_idx = idx;
        }
    }

    dos.current_psp = PSP_SEL;
}

/// PM→RM transition: undo the PM-side PSP view set up by `enter_pm_psp_view`.
///
/// Restores the original PSP[0x2C] (32-bit clients), frees the env selector
/// LDT slot, and sets `dos.current_psp` back to the RM PSP segment captured
/// on entry so reflected AH=51/62 returns an RM-loadable value.
fn restore_rm_psp_view(dos: &mut thread::DosState) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };
    let rm_psp = dpmi.saved_rm_psp;
    let psp_base = (rm_psp as u32) * 16;

    if dpmi.env_ldt_idx != 0 {
        unsafe { core::ptr::write_volatile((psp_base + 0x2C) as *mut u16, dpmi.saved_rm_env); }
        let idx = dpmi.env_ldt_idx;
        free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
        dpmi.env_ldt_idx = 0;
    }

    dos.current_psp = rm_psp;
}

/// PM-to-real raw mode switch.
/// Raw mode switch PM→real. Called via unified stub slot SLOT_PM_TO_REAL.
/// AX has new DS directly (stub is just CD 31, no register clobbering).
///
/// Register convention (set by caller before CALL FAR):
///   AX = new real-mode DS
///   CX = new real-mode ES
///   DX = new real-mode SS
///   BX = new real-mode SP
///   SI = new real-mode CS
///   DI = new real-mode IP
fn raw_switch_pm_to_real(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_sp = regs.rbx as u16;
    let new_cs = regs.rsi as u16;
    let new_ip = regs.rdi as u16;

    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.raw_pm_state = capture_protected_mode_state(regs);
    }
    restore_rm_psp_view(dos);

    // Set VM86 mode
    regs.frame.rflags |= (machine::VM_FLAG | machine::IF_FLAG) as u64;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_ip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_sp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    dos_trace!("[DPMI] raw PM->RM {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        new_cs, new_ip, new_ss, new_sp);
    thread::KernelAction::Done
}

/// Real-to-PM raw mode switch.
/// Called from rm_int31_dispatch when VM86 code executes `CALL FAR` to
/// stub slot SLOT_RAW_REAL_TO_PM (INT 31h trap).
///
/// Register convention (set by caller before CALL FAR):
///   AX = new PM DS selector
///   CX = new PM ES selector
///   DX = new PM SS selector
///   (E)BX = new PM (E)SP
///   SI = new PM CS selector
///   (E)DI = new PM (E)IP
pub fn raw_switch_real_to_pm(dos: &mut thread::DosState, regs: &mut Regs) {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_cs = regs.rsi as u16;
    let saved_rm_state = capture_real_mode_state(
        regs,
        regs.code_seg(),
        regs.ip32() as u16,
        regs.stack_seg(),
        regs.sp32() as u16,
    );

    // Determine destination operand size from the target CS/SS descriptors,
    // so 16-bit clients don't pick up garbage in EBX/EDI upper bits.
    let (new_esp, new_eip) = {
        let cs_32 = seg_is_32(&dos.ldt[..], new_cs);
        let ss_32 = seg_is_32(&dos.ldt[..], new_ss);
        let esp = if ss_32 { regs.rbx as u32 } else { regs.rbx as u32 & 0xFFFF };
        let eip = if cs_32 { regs.rdi as u32 } else { regs.rdi as u32 & 0xFFFF };
        (esp, eip)
    };

    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.raw_rm_state = saved_rm_state;
    }
    enter_pm_psp_view(dos);

    // Clear VM flag, enter protected mode
    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::IF_FLAG as u64;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_eip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_esp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    dos_trace!("[DPMI] raw RM->PM CS:EIP={:04X}:{:08X} SS:ESP={:04X}:{:08X} DS={:04X} ES={:04X}",
        new_cs, new_eip, new_ss, new_esp, new_ds, new_es);

    // No LDT reload: `dos.ldt` is the same per-thread buffer context switch
    // already loaded LDTR for; raw mode switch doesn't swap it.
}

// ============================================================================
// Helpers
// ============================================================================

/// Get the base address for any selector (GDT or LDT).
/// GDT selectors (TI=0) are flat (base=0).
/// Takes `ldt` as a slice (not `&DosState`) so the borrow checker accepts
/// calls from contexts where another field of DosState is held mutably.
pub fn seg_base(ldt: &[u64], sel: u16) -> u32 {
    if sel & 4 != 0 {
        let idx = (sel >> 3) as usize;
        if idx < ldt.len() { DpmiState::desc_base(ldt[idx]) } else { 0 }
    } else {
        0
    }
}

/// Get the D/B (default size) bit for any selector.
/// GDT selectors are treated as 32-bit.
pub fn seg_is_32(ldt: &[u64], sel: u16) -> bool {
    if sel & 4 != 0 {
        let idx = (sel >> 3) as usize;
        if idx < ldt.len() { DpmiState::desc_is_32(ldt[idx]) } else { true }
    } else {
        true
    }
}

/// Compute flat address from selector:offset.
/// Address size (16 vs 32 bit offset) determined by CS descriptor's D/B bit.
fn flat_addr(ldt: &[u64], seg: u16, offset: u32, cs_32: bool) -> u32 {
    let offset = if cs_32 { offset } else { offset & 0xFFFF };
    seg_base(ldt, seg).wrapping_add(offset)
}

fn capture_real_mode_state(regs: &Regs, cs: u16, ip: u16, ss: u16, sp: u16) -> RawModeState {
    RawModeState {
        flags: regs.flags32() as u32,
        cs,
        ip: ip as u32,
        ss,
        sp: sp as u32,
        ds: regs.ds as u16,
        es: regs.es as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
    }
}

fn capture_protected_mode_state(regs: &Regs) -> RawModeState {
    RawModeState {
        flags: regs.flags32(),
        cs: regs.code_seg(),
        ip: regs.ip32(),
        ss: regs.stack_seg(),
        sp: regs.sp32(),
        ds: regs.ds as u16,
        es: regs.es as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
    }
}

fn real_mode_state_buffer_addr(regs: &Regs) -> u32 {
    ((regs.es as u32) << 4).wrapping_add((regs.rdi as u32) & 0xFFFF)
}

fn save_restore_real_mode_state(dos: &mut thread::DosState, regs: &Regs) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(dpmi) => dpmi,
        None => return,
    };
    let buf_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
    match regs.rax as u8 {
        0 => unsafe { core::ptr::write_unaligned(buf_addr as *mut RawModeState, dpmi.raw_rm_state) },
        1 => unsafe { dpmi.raw_rm_state = core::ptr::read_unaligned(buf_addr as *const RawModeState) },
        al => crate::kernel::dos::dos_trace!(
            "DPMI save_restore_raw_mode unsupported AL={:02X}", al),
    }
}

pub fn save_restore_protected_mode_state(dos: &mut thread::DosState, regs: &Regs) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(dpmi) => dpmi,
        None => return,
    };
    let buf_addr = real_mode_state_buffer_addr(regs);
    match regs.rax as u8 {
        0 => unsafe { core::ptr::write_unaligned(buf_addr as *mut RawModeState, dpmi.raw_pm_state) },
        1 => unsafe { dpmi.raw_pm_state = core::ptr::read_unaligned(buf_addr as *const RawModeState) },
        al => crate::kernel::dos::dos_trace!(
            "DPMI save_restore_pm_state unsupported AL={:02X}", al),
    }
}

fn trace_client_selector_leak(_label: &str, _regs: &Regs) {}

fn set_carry(regs: &mut Regs) {
    regs.set_flag32(1); // CF
}

fn clear_carry(regs: &mut Regs) {
    regs.clear_flag32(1); // CF
}
