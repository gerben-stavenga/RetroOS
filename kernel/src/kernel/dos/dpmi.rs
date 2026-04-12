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
use crate::kernel::machine;
use crate::kernel::startup;
use crate::{Regs, dbg_println};

/// Trace DPMI calls when enabled. Toggle with DPMI_TRACE.
const DPMI_TRACE: bool = false;

macro_rules! dpmi_trace {
    ($($arg:tt)*) => {
        if DPMI_TRACE {
            crate::dbg_println!($($arg)*);
        }
    };
}

/// Number of LDT entries
const LDT_ENTRIES: usize = 8192;

/// LDT index of the "low memory" selector. Base=0, limit=1MB, 16-bit.
/// DOS handlers that need to return a pointer to a fixed low-memory byte
/// (INDOS flag, LOL, IVT vectors) use this as ES; BX is the linear address.
pub const LOW_MEM_LDT_IDX: usize = 6;

/// Selector value for LOW_MEM_LDT_IDX (TI=1, RPL=3).
pub const LOW_MEM_SEL: u16 = ((LOW_MEM_LDT_IDX as u16) << 3) | 4 | 3;
/// Maximum DPMI memory blocks
const MAX_MEM_BLOCKS: usize = 256;
/// Base address for DPMI linear memory allocations
const MEM_BASE: u32 = 0x0050_0000;

/// Maximum number of real-mode callbacks (INT 31h/0303h)
const MAX_CALLBACKS: usize = 16;

/// Per-thread DPMI state (heap-allocated, attached to Thread.dpmi)
pub struct DpmiState {
    /// Local Descriptor Table entries
    pub ldt: Box<[u64; LDT_ENTRIES]>,
    /// LDT allocation bitmap (1 = in use). 8192 bits = 256 u32s.
    pub ldt_alloc: [u32; LDT_ENTRIES / 32],
    /// Linear memory blocks allocated via INT 31h/0501h
    pub mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub mem_next: u32,
    /// Saved protected-mode state during real-mode callbacks (INT 31h/0300h)
    pub rm_save: Option<SavedPmState>,
    /// Protected-mode interrupt vectors (set via INT 31h/0205h)
    /// (selector, offset) for each vector 0x00-0xFF
    pub pm_vectors: [(u16, u32); 256],
    /// Exception handler vectors (set via INT 31h/0203h)
    /// (selector, offset) for exceptions 0x00-0x1F
    pub exc_vectors: [(u16, u32); 32],
    /// Real-mode callbacks (INT 31h/0303h)
    /// Each entry: Some((pm_cs, pm_eip, rm_struct_sel, rm_struct_off))
    pub callbacks: [Option<(u16, u32, u16, u32)>; MAX_CALLBACKS],
    /// Dedicated real-mode stack segment for INT 31h/0300h simulation.
    /// Allocated from DOS heap so it doesn't overlap with the client's data.
    pub rm_stack_seg: u16,
    /// Client mode bit-width as declared at INT 2F/1687h → entry point.
    /// Determines the operand size used for FAR CALL/INT frames the client
    /// places on its own stack (4 vs 8 bytes for CALL FAR, 6 vs 12 bytes for
    /// INT). The stub LDT segment itself is 16-bit, so we can't infer this
    /// from the trapped CS — we must remember what the client declared.
    pub client_use32: bool,
    /// Original real-mode environment segment from PSP[0x2C] before we
    /// patched it to a selector at dpmi_enter. Per DPMI 0.9 spec, the host
    /// converts PSP[0x2C] to a descriptor on PM entry; we keep the original
    /// segment so in-process child exec can inherit the env block.
    pub env_seg_orig: u16,
    /// Stack of interrupted PM frames saved by `deliver_hw_irq`. The client's
    /// PM HW IRQ handler IRETs to a host trampoline stub (SLOT_HW_IRQ_RET)
    /// instead of directly to the interrupted code, because ring-3 IRET with
    /// IOPL=0 silently discards the IF bit being popped — the host has to do
    /// the IF restore by hand. Each entry is (cs, eip, flags) of the frame
    /// that was executing when the IRQ fired. Nested HW IRQs push, returns pop.
    pub hw_irq_frames: alloc::vec::Vec<(u16, u32, u32)>,
}

/// A DPMI linear memory block
#[derive(Clone, Copy)]
pub struct MemBlock {
    pub base: u32,
    pub size: u32,
}

/// Saved protected-mode state for real-mode callbacks
pub struct SavedPmState {
    pub regs: Regs,
    /// Pointer to the 50-byte real-mode call structure (in PM address space).
    /// 0 = implicit reflection (no register structure to update on return).
    pub rm_struct_addr: u32,
    /// IVT vector that was reflected (only meaningful when rm_struct_addr == 0).
    /// callback_return uses this to apply DPMI selector/segment translation
    /// for INT 21h PSP-related calls (AH=51/62).
    pub vector: u8,
}

impl DpmiState {
    pub fn new() -> Self {
        // Allocate the 64KB LDT directly on the heap. `Box::new([0u64; N])`
        // would materialize the array on the stack first and then copy it,
        // overflowing the kernel stack for large N. `vec![0u64; N]` uses the
        // `alloc_zeroed` specialization for primitive types and never touches
        // the stack.
        let ldt: Box<[u64; LDT_ENTRIES]> = alloc::vec![0u64; LDT_ENTRIES]
            .into_boxed_slice()
            .try_into()
            .ok()
            .expect("LDT size mismatch");
        Self {
            ldt,
            ldt_alloc: [0u32; LDT_ENTRIES / 32],
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            rm_save: None,
            pm_vectors: [(0, 0); 256],
            exc_vectors: [(0, 0); 32],
            callbacks: [None; MAX_CALLBACKS],
            rm_stack_seg: 0,
            client_use32: false,
            env_seg_orig: 0,
            hw_irq_frames: alloc::vec::Vec::new(),
        }
    }

    /// Allocate an LDT selector. Returns index (1-255) or None.
    fn alloc_ldt(&mut self) -> Option<usize> {
        for idx in 1..LDT_ENTRIES {
            let word = idx / 32;
            let bit = idx % 32;
            if self.ldt_alloc[word] & (1 << bit) == 0 {
                self.ldt_alloc[word] |= 1 << bit;
                return Some(idx);
            }
        }
        None
    }

    /// Free an LDT selector by index.
    fn free_ldt(&mut self, idx: usize) {
        if idx > 0 && idx < LDT_ENTRIES {
            let word = idx / 32;
            let bit = idx % 32;
            self.ldt_alloc[word] &= !(1 << bit);
            self.ldt[idx] = 0;
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
    fn desc_limit(desc: u64) -> u32 {
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

// ============================================================================
// DPMI entry — mode switch from Dos/VM86 to Dos/DPMI (protected mode)
// ============================================================================

/// Switch from VM86 to 32-bit protected mode.
/// Called from stub_dispatch when the DPMI entry stub executes.
pub fn dpmi_enter(dos: &mut thread::DosState, regs: &mut Regs) {
    let client_type = regs.rax as u16; // AX: 0=16-bit, 1=32-bit
    // Save VM86 register state for the FAR CALL return address
    // The FAR CALL pushed CS:IP on the real-mode stack.
    // Pop the return address so we know where to resume in PM.
    let ret_ip = machine::vm86_pop(regs);
    let ret_cs = machine::vm86_pop(regs);
    dpmi_trace!("[DPMI] ENTER AX={} ({}bit client) caller={:04X}:{:04X} psp={:04X}",
        client_type, if client_type != 0 { 32 } else { 16 },
        ret_cs, ret_ip, dos.current_psp);

    let real_ss = regs.stack_seg();
    let real_sp = regs.sp32() as u16;

    // Allocate DPMI state
    let mut dpmi = DpmiState::new();
    dpmi.client_use32 = client_type != 0;

    // Set up initial LDT entries.
    // CS stays 16-bit: the return from mode switch is still 16-bit stub code.
    // SS must be 32-bit for 32-bit clients so interrupts save/restore full ESP.
    // DS/ES stay 16-bit (data segments don't affect stack width).
    let use32 = client_type != 0;

    // Index 1: CS — code, base = ret_cs * 16 (caller's CS, not stub segment)
    let cs_base = (ret_cs as u32) * 16;
    dpmi.ldt[1] = DpmiState::make_code_desc_ex(cs_base, 0xFFFF, false);
    dpmi.ldt_alloc[0] |= 1 << 1;

    // Index 2: DS — data, base = real-mode DS * 16, limit = 64K
    // Use the caller's DS (not PSP) so the stub can access its own data.
    let ds_base = (regs.ds as u32) * 16;
    dpmi.ldt[2] = DpmiState::make_data_desc_ex(ds_base, 0xFFFF, false);
    dpmi.ldt_alloc[0] |= 1 << 2;

    // Index 3: SS — stack, base = real_ss * 16, limit = 64K
    // 32-bit clients need B=1 so the CPU uses full ESP during interrupts.
    let ss_base = (real_ss as u32) * 16;
    dpmi.ldt[3] = DpmiState::make_data_desc_ex(ss_base, 0xFFFF, use32);
    dpmi.ldt_alloc[0] |= 1 << 3;

    // Index 4: ES — PSP selector. The DPMI 0.9 spec says limit=100h, but
    // many real-world DOS extenders (DOS/4GW, etc.) reuse ES as a scratch
    // data segment before reloading it, and crash if the limit is too tight.
    // Give it a 64KB limit for compatibility. Use the current PSP, not a
    // hardcoded segment, so child execs get a selector pointing at their own.
    let psp_seg = dos.current_psp;
    let psp_base = (psp_seg as u32) * 16;
    dpmi.ldt[4] = DpmiState::make_data_desc_ex(psp_base, 0xFFFF, false);
    dpmi.ldt_alloc[0] |= 1 << 4;

    // Index 5: stub code segment (base=0, limit=0x0FFF) for RETF stubs
    // Used by INT 31h/0305h PM save/restore entry point
    dpmi.ldt[5] = DpmiState::make_code_desc_ex(0, 0x0FFF, false);
    dpmi.ldt_alloc[0] |= 1 << 5;

    // Index 6: low-memory data selector (base=0, limit=1MB, 16-bit).
    // Used by DOS handlers that need to return a pointer to a fixed
    // low-memory structure (INDOS flag, LOL, DTA, IVT vectors): the PM
    // client gets ES = LOW_MEM_SEL and BX = full 20-bit linear address
    // (all conventional-memory structs fit in the low 64KB).
    dpmi.ldt[LOW_MEM_LDT_IDX] = DpmiState::make_data_desc_ex(0, 0xFFFFF, false);
    dpmi.ldt_alloc[0] |= 1 << LOW_MEM_LDT_IDX;

    let cs_sel = DpmiState::idx_to_sel(1);
    let ds_sel = DpmiState::idx_to_sel(2);
    let ss_sel = DpmiState::idx_to_sel(3);
    let es_sel = DpmiState::idx_to_sel(4);


    // Load LDT via arch call
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

    // Switch regs from VM86 to protected mode:
    // Clear VM flag, set PM selectors, set EIP to return offset
    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::IF_FLAG as u64;
    regs.frame.cs = cs_sel as u64;
    regs.frame.rip = ret_ip as u64;
    regs.frame.ss = ss_sel as u64;
    regs.frame.rsp = real_sp as u64;
    regs.ds = ds_sel as u64;
    regs.es = es_sel as u64;
    regs.fs = 0;
    regs.gs = 0;

    // Allocate a dedicated real-mode stack for INT 31h/0300h simulation.
    // Must not overlap the client's data area. Grab 256 bytes (16 paragraphs)
    // from the DOS heap.
    let rm_stack_seg = dos.heap_seg;
    dos.heap_seg = rm_stack_seg.wrapping_add(0x10); // 256 bytes
    dpmi.rm_stack_seg = rm_stack_seg;

    // DPMI 0.9 §4.1: "The environment pointer in the client program's PSP
    // is automatically converted to a selector during the mode switch."
    // 32-bit DOS extenders (DOS/4GW etc.) follow the spec and read PSP[0x2C]
    // as a selector. 16-bit extenders (DOS/16M, used by Borland tools) are
    // non-conformant and read PSP[0x2C] as a real-mode segment, shifting it
    // left 4 to compute a base — so patching it for 16-bit clients corrupts
    // their env-block selector. Patch only for 32-bit clients.
    let env_seg = unsafe { *((psp_base + 0x2C) as *const u16) };
    dpmi.env_seg_orig = env_seg;
    if use32 && env_seg != 0 {
        if let Some(idx) = dpmi.alloc_ldt() {
            let env_base = (env_seg as u32) * 16;
            dpmi.ldt[idx] = DpmiState::make_data_desc_ex(env_base, 0xFFFF, false);
            let env_sel = DpmiState::idx_to_sel(idx);
            unsafe { *((psp_base + 0x2C) as *mut u16) = env_sel; }
        }
    }

    // pm_vectors stays zero-initialized: sel=0 means "no client handler",
    // which signals reflect-to-real-mode in dpmi_soft_int. INT 31h/0204h
    // synthesizes the stub address on demand for clients that chain to the
    // default handler.

    // Store DPMI state on thread
    dos.dpmi = Some(Box::new(dpmi));

}

// PM #GP monitor lives in `arch/monitor.rs`. The arch decoder handles
// CLI/STI/PUSHF/POPF/IRET directly (fast-path iret to user) and bubbles
// INT/HLT/IN/OUT/INS/OUTS up as `KernelEvent`s. PM software-INT dispatch
// for installed DPMI client vectors is handled by `dpmi_soft_int` below.

// ============================================================================
// DPMI software INT dispatch (vectors 0x30-0xFF, DPL=3 in IDT)
// ============================================================================

/// Handle a software INT from DPMI protected mode that arrived as a direct
/// IDT event (DPL=3 vectors). Dispatch to PM handler if installed, else
/// reflect to real mode via IVT.
pub fn dpmi_soft_int(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    dpmi_trace!("[DPMI] SOFTINT {:02X} CS:EIP={:04x}:{:#x}", vector, regs.code_seg(), regs.ip32());
    let (sel, off) = dos.dpmi.as_ref().unwrap().pm_vectors[vector as usize];
    if sel == 0 && matches!(vector, 0x13 | 0x20 | 0x21 | 0x25 | 0x26 | 0x28 | 0x2E | 0x2F) {
        return dos::dispatch_kernel_syscall(kt, dos, regs, vector);
    }
    let dpmi = dos.dpmi.as_mut().unwrap();
    if sel != 0 {
        // PM handler installed — push a host trampoline IRET frame and dispatch.
        //
        // We cannot push the interrupted CS:EIP directly, because when the
        // client handler IRETs, ring-3 IRET with IOPL=0 silently discards the
        // popped IF bit. Any handler that does CLI in its body (DOS32A's
        // INT 21h shim does) would leave the client with IF=0 forever.
        //
        // Instead we route the return through SLOT_HW_IRQ_RET (same trampoline
        // used by HW IRQ delivery): the frame we push points at the stub's
        // `CD 31`; when the client IRETs it lands there, we pop the snapshot
        // from `hw_irq_frames` and restore CS:EIP/IF/VIP by hand.
        //
        // 16-bit clients get a 6-byte IRETW frame; 32-bit a 12-byte IRETD frame.
        let use32 = dpmi.client_use32;
        let ss_sel = regs.frame.ss as u16;
        let ss_base = seg_base(dpmi, ss_sel);
        let ss_32 = seg_is_32(dpmi, ss_sel);

        let saved_cs = regs.code_seg();
        let saved_eip = regs.ip32();
        let saved_flags = regs.flags32();

        let stub_sel = DpmiState::idx_to_sel(5);
        let stub_eip = dos::STUB_BASE + (dos::SLOT_HW_IRQ_RET as u32) * 2;

        let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
        let frame_size: u32 = if use32 { 12 } else { 6 };
        let new_sp = sp.wrapping_sub(frame_size);
        if ss_32 { regs.set_sp32(new_sp); }
        else { regs.set_sp32((regs.sp32() & !0xFFFF) | (new_sp & 0xFFFF)); }
        unsafe {
            let base = ss_base.wrapping_add(new_sp);
            if use32 {
                let p = base as *mut u32;
                core::ptr::write_unaligned(p, stub_eip);
                core::ptr::write_unaligned(p.add(1), stub_sel as u32);
                core::ptr::write_unaligned(p.add(2), saved_flags);
            } else {
                let p = base as *mut u16;
                core::ptr::write_unaligned(p, stub_eip as u16);
                core::ptr::write_unaligned(p.add(1), stub_sel);
                core::ptr::write_unaligned(p.add(2), saved_flags as u16);
            }
        }
        dpmi.hw_irq_frames.push((saved_cs, saved_eip, saved_flags));
        regs.set_cs32(sel as u32);
        regs.set_ip32(off);
        thread::KernelAction::Done
    } else {
        // No PM handler — reflect to real mode
        reflect_int_to_real_mode(dos, regs, vector)
    }
}

// ============================================================================
// PM stub dispatch — INT 31h from the unified CD 31 array
// ============================================================================

/// Dispatch INT 31h that came from the stub segment (CS == stub_sel).
/// Slot = (EIP - STUB_BASE - 2) / 2.
fn pm_stub_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let eip = regs.ip32();
    let stub_base = dos::STUB_BASE;
    let slot = ((eip.wrapping_sub(stub_base + 2)) / 2) as u8;
    dpmi_trace!("[DPMI] STUB slot={:#04x} EIP={:#x}", slot, eip);

    match slot {
        dos::SLOT_EXCEPTION_RET => {
            return exception_return(dos, regs);
        }
        dos::SLOT_HW_IRQ_RET => {
            return hw_irq_return(dos, regs);
        }
        dos::SLOT_PM_TO_REAL => {
            return raw_switch_pm_to_real(dos, regs);
        }
        dos::SLOT_SAVE_RESTORE => {
            // No-op save/restore: pop the far-call return address and resume caller.
            // Frame size depends on the client's operand size: 16-bit CALL FAR
            // pushed IP+CS as 4 bytes; 32-bit CALL FAR pushed EIP+CS as 8 bytes.
            let dpmi = dos.dpmi.as_ref().unwrap();
            let use32 = dpmi.client_use32;
            let ss_base = seg_base(dpmi, regs.stack_seg());
            let ss_32 = seg_is_32(dpmi, regs.stack_seg());
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
        _ => {
            // Default: reflect to real mode via IVT.
            // The CD 31 stub has no IRETD, so we must pop the IRET frame
            // (pushed by deliver_hw_irq or INT dispatch) from the PM stack
            // before saving state. This way callback_return restores to the
            // original interrupted code, not the next stub entry.
            // Frame width matches what we pushed in deliver_hw_irq/dpmi_soft_int:
            // 16-bit clients get a 6-byte IRETW frame, 32-bit a 12-byte IRETD frame.
            let dpmi = dos.dpmi.as_ref().unwrap();
            let use32 = dpmi.client_use32;
            let ss_base = seg_base(dpmi, regs.stack_seg());
            let ss_32 = seg_is_32(dpmi, regs.stack_seg());
            let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
            let (ret_eip, ret_cs, ret_flags, frame_size) = if use32 {
                let eip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u32) };
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u32) };
                let fl = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 8)) as *const u32) };
                (eip, cs, fl, 12u32)
            } else {
                let ip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u16) } as u32;
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 2)) as *const u16) } as u32;
                let fl = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u16) } as u32;
                (ip, cs, fl, 6u32)
            };
            let new_sp = sp.wrapping_add(frame_size);
            if ss_32 { regs.set_sp32(new_sp); }
            else { regs.set_sp32((regs.sp32() & !0xFFFF) | (new_sp & 0xFFFF)); }
            regs.set_ip32(ret_eip);
            regs.set_cs32(ret_cs);
            let preserved = regs.flags32() & machine::PRESERVED_FLAGS;
            regs.set_flags32((ret_flags & !machine::PRESERVED_FLAGS) | preserved);
            reflect_int_to_real_mode(dos, regs, slot)
        }
    }
}

// ============================================================================
// INT 31h — DPMI services
// ============================================================================

/// Handle INT 31h from protected mode. Called from event loop when event=0x31.
/// If CS is the stub segment, dispatch by slot number (reflect or PM-only stubs).
/// Otherwise, dispatch as DPMI API by AX.
pub fn dpmi_int31(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: INT 31h but no DPMI state!");
            set_carry(regs);
            return thread::KernelAction::Done;
        }
    };

    // Unified stub array dispatch: CD 31 from stub segment → slot-based routing
    let stub_sel = DpmiState::idx_to_sel(5);
    if regs.code_seg() == stub_sel {
        return pm_stub_dispatch(dos, regs);
    }

    // Determine code segment address size — use16 means register offsets are 16-bit
    let cs_32 = seg_is_32(dpmi, regs.code_seg());

    let ax = regs.rax as u16;
    dpmi_trace!("[DPMI] INT31 AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:04x}:{:#x}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16, regs.code_seg(), regs.ip32());

    match ax {
        // AX=0000h — Allocate LDT Descriptors
        // CX = number of descriptors
        // Returns: AX = base selector
        0x0000 => {
            let count = (regs.rcx & 0xFFFF) as usize;
            if count == 0 { set_carry(regs); return thread::KernelAction::Done; }
            // Allocate contiguous selectors (simplified: allocate one at a time)
            // DPMI spec: allocated descriptors must be present, DPL=3, data, writable
            let first = dpmi.alloc_ldt();
            match first {
                Some(idx) => {
                    dpmi.ldt[idx] = DpmiState::make_data_desc(0, 0);
                    for _ in 1..count {
                        if let Some(extra) = dpmi.alloc_ldt() {
                            dpmi.ldt[extra] = DpmiState::make_data_desc(0, 0);
                        }
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
            dpmi.free_ldt(idx);
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
            if let Some(idx) = dpmi.alloc_ldt() {
                dpmi.ldt[idx] = DpmiState::make_data_desc_ex(base, 0xFFFF, false);
                let sel = DpmiState::idx_to_sel(idx);
                regs.rax = (regs.rax & !0xFFFF) | sel as u64;
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
                let base = DpmiState::desc_base(dpmi.ldt[idx]);
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
                DpmiState::set_desc_base(&mut dpmi.ldt[idx], base);
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
                DpmiState::set_desc_limit(&mut dpmi.ldt[idx], limit);
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
                // Replace access byte (bits 40-47) and flags nibble (bits 52-55)
                dpmi.ldt[idx] &= !0x00F0_FF00_0000_0000;
                dpmi.ldt[idx] |= (cl as u64) << 40;
                dpmi.ldt[idx] |= ((ch & 0xF0) as u64) << 48;
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
                if let Some(new_idx) = dpmi.alloc_ldt() {
                    let mut desc = dpmi.ldt[src_idx];
                    // Change type from code to data (clear bit 3 of type nibble = execute bit)
                    // Access byte bit 43 = execute. Clear it, set writable (bit 41)
                    desc &= !(1u64 << 43); // clear execute
                    desc |= 1u64 << 41;    // set writable
                    dpmi.ldt[new_idx] = desc;
                    let new_sel = DpmiState::idx_to_sel(new_idx);
                    regs.rax = (regs.rax & !0xFFFF) | new_sel as u64;
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
                let dest = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
                unsafe { core::ptr::write_unaligned(dest as *mut u64, dpmi.ldt[idx]); }
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
                let src = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
                let new_desc = unsafe { core::ptr::read_unaligned(src as *const u64) };
                dpmi.ldt[idx] = new_desc;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0100h — Allocate DOS Memory Block
        // BX = paragraphs. Returns: AX = real-mode segment, DX = selector
        0x0100 => {
            let paragraphs = regs.rbx as u16;
            // Allocate from DOS conventional memory (simplified: use heap_seg)
            let seg = dos.heap_seg;
            dos.heap_seg = seg.wrapping_add(paragraphs);
            // Create a data descriptor for this block
            let dpmi = dos.dpmi.as_mut().unwrap();
            if let Some(idx) = dpmi.alloc_ldt() {
                let base = (seg as u32) * 16;
                let limit = (paragraphs as u32) * 16 - 1;
                dpmi.ldt[idx] = DpmiState::make_data_desc(base, limit);
                let sel = DpmiState::idx_to_sel(idx);
                regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | sel as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0101h — Free DOS Memory Block
        // DX = selector
        0x0101 => {
            let sel = regs.rdx as u16;
            let idx = DpmiState::sel_to_idx(sel);
            dpmi.free_ldt(idx);
            clear_carry(regs);
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
            crate::dbg_println!("[DPMI] 0201 set RM vec {:02X} = {:04X}:{:04X}", int_num, seg, off);
            machine::write_u16(0, (int_num as u32) * 4, off);
            machine::write_u16(0, (int_num as u32) * 4 + 2, seg);
            clear_carry(regs);
        }
        // AX=0202h — Get Processor Exception Handler Vector
        // BL = exception number (0x00-0x1F). Returns: CX:EDX = selector:offset
        0x0202 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
                let (sel, off) = dpmi.exc_vectors[exc as usize];
                regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
                regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0203h — Set Processor Exception Handler Vector
        // BL = exception number (0x00-0x1F), CX:EDX = selector:offset
        0x0203 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
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
            let (sel, off) = dpmi.pm_vectors[int_num as usize];
            let (sel, off) = if sel == 0 {
                let stub_sel = DpmiState::idx_to_sel(5);
                let stub_off = dos::STUB_BASE + (int_num as u32) * 2;
                (stub_sel, stub_off)
            } else {
                (sel, off)
            };
            regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
            regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0205h — Set Protected Mode Interrupt Vector
        // BL = interrupt number, CX:EDX = selector:offset
        0x0205 => {
            let int_num = regs.rbx as u8;
            crate::dbg_println!("[DPMI] 0205 set vec {:02X} = {:04X}:{:#X}", int_num, regs.rcx as u16, regs.rdx as u32);
            dpmi.pm_vectors[int_num as usize] = (regs.rcx as u16, regs.rdx as u32);
            clear_carry(regs);
        }
        // AX=0300h — Simulate Real Mode Interrupt
        // BL = interrupt number, ES:EDI = real-mode call structure (50 bytes)
        0x0300 => {
            return simulate_real_mode_int(dos, regs, cs_32);
        }
        // AX=0301h — Call Real Mode Far Procedure
        // ES:EDI = real-mode call structure
        0x0301 => {
            return call_real_mode_proc(dos, regs, cs_32);
        }
        // AX=0302h — Call Real Mode Procedure with IRET Frame
        // ES:EDI = real-mode call structure (procedure returns via IRET)
        0x0302 => {
            return call_real_mode_proc_iret(dos, regs, cs_32);
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
        // ES:EDI = 48-byte buffer
        0x0500 => {
            let dest = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
            // Fill with "lots of memory available"
            let info = [
                16 * 1024 * 1024, // Largest available block
                4096,             // Maximum unlocked page allocation
                4096,             // Maximum locked page allocation
                16 * 1024 / 4,    // Linear address space size in pages
                4096,             // Total unlocked pages
                4096,             // Total free pages
                4096,             // Total physical pages
                16 * 1024 / 4,    // Free linear address space in pages
                0,                // Size of paging file/partition in pages
                0,                // Reserved
                0,                // Reserved
                0,                // Reserved
            ];
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
        // Returns buffer size and save/restore entry points
        0x0305 => {
            regs.rax = (regs.rax & !0xFFFF);  // AX=0: no buffer needed
            // Real-mode save/restore: stub slot SLOT_SAVE_RESTORE
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u64;
            // Protected-mode save/restore: stub_sel:STUB_BASE + SLOT_SAVE_RESTORE*2
            let stub_sel = DpmiState::idx_to_sel(5);
            regs.rsi = (regs.rsi & !0xFFFF) | stub_sel as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (dos::STUB_BASE + dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u32) as u64;
            clear_carry(regs);
        }
        // AX=0306h — Get Raw Mode Switch Addresses
        // Returns real-to-PM and PM-to-real switch entry points
        0x0306 => {
            // BX:CX = real-to-PM entry point (real-mode segment:offset)
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_RAW_REAL_TO_PM) as u64;
            // SI:(E)DI = PM-to-real entry point (selector:offset)
            let stub_sel = DpmiState::idx_to_sel(5);
            regs.rsi = (regs.rsi & !0xFFFF) | stub_sel as u64;
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
            crate::kernel::startup::arch_map_phys_range(vpage_start, num_pages, ppage_start, 0);
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
            crate::dbg_println!("  DPMI: unhandled INT 31h AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:04x}:{:#x}",
                ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.code_seg(), regs.ip32());
            set_carry(regs);
            regs.rax = (regs.rax & !0xFFFF) | 0x8001; // unsupported function
        }
    }

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
fn simulate_real_mode_int(dos: &mut thread::DosState, regs: &mut Regs, cs_32: bool) -> thread::KernelAction {
    let dpmi = dos.dpmi.as_mut().unwrap();
    let int_num = regs.rbx as u8;

    // Read the real-mode call structure from ES:EDI
    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let rm_cs = rm.cs;
    let rm_ip = rm.ip;

    // Save current protected-mode state
    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
        vector: 0xFF,
    });

    // Get IVT entry for the interrupt
    let ivt_off = machine::read_u16(0, (int_num as u32) * 4);
    let ivt_seg = machine::read_u16(0, (int_num as u32) * 4 + 2);

    // Use SS:SP from structure if provided, else use our dedicated RM stack.
    // The default must NOT overlap the client's data area (COM_SEGMENT is unsafe).
    let rm_ss = if rm.ss != 0 { rm.ss } else { dpmi.rm_stack_seg };
    let rm_sp = if rm.sp != 0 { rm.sp } else { 0x00FE }; // top of 256-byte segment

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

    // Push IRET frame for callback return: FLAGS, callback_stub_seg, callback_stub_off
    // The callback stub (SLOT_CALLBACK_RET) does INT 31h which triggers callback_return
    let callback_off: u16 = dos::slot_offset(dos::SLOT_CALLBACK_RET);
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
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::VIF_FLAG) as u64;

    crate::dbg_println!("[DPMI] simulate INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        int_num, ivt_seg, ivt_off, rm_ss, rm_sp.wrapping_sub(6));

    // Now in VM86 mode — the event loop will execute the BIOS handler.
    // When it IRETs to callback_stub, INT 31h fires, and callback_return() is called.
    thread::KernelAction::Done
}

/// Reflect a software INT from protected mode to real mode via the IVT.
/// Used when a DPMI client executes `INT xx` and no PM handler is installed.
/// The current PM registers (with IP already past the INT) are saved;
/// the low 16 bits of EAX/EBX/ECX/EDX/ESI/EDI/EBP + segment regs are
/// forwarded to the real-mode handler.  On return (callback_return),
/// the updated real-mode registers are copied back before resuming PM.
fn reflect_int_to_real_mode(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) -> thread::KernelAction {
    let dpmi = dos.dpmi.as_mut().unwrap();

    // Translate PM selector bases to real-mode segments (base >> 4)
    let rm_ds = (seg_base(dpmi, regs.ds as u16) >> 4) as u16;
    let rm_es = (seg_base(dpmi, regs.es as u16) >> 4) as u16;
    let rm_fs = (seg_base(dpmi, regs.fs as u16) >> 4) as u16;
    let rm_gs = (seg_base(dpmi, regs.gs as u16) >> 4) as u16;

    // INT 21h PSP-related calls — DPMI clients pass PSPs as selectors, not
    // real-mode segments. Translate inputs (AH=50h Set PSP) here so the
    // real-mode handler sees a segment; AH=51h/62h outputs are translated
    // back in callback_return.
    if vector == 0x21 {
        let ah = (regs.rax >> 8) as u8;
        if ah == 0x50 {
            let bx_sel = regs.rbx as u16;
            let psp_seg = (seg_base(dpmi, bx_sel) >> 4) as u16;
            regs.rbx = (regs.rbx & !0xFFFF) | psp_seg as u64;
        }
    }


    // Save protected-mode state (rm_struct_addr=0 signals implicit reflection)
    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: 0,
        vector,
    });

    // Get IVT entry
    let ivt_off = machine::read_u16(0, (vector as u32) * 4);
    let ivt_seg = machine::read_u16(0, (vector as u32) * 4 + 2);

    // Use the dedicated DPMI real-mode stack (not COM_SEGMENT which overlaps client data)
    let rm_ss = dpmi.rm_stack_seg;
    let rm_sp: u16 = 0x00FE;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // Push callback return IRET frame on VM86 stack
    let callback_off: u16 = dos::slot_offset(dos::SLOT_CALLBACK_RET);
    let callback_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, 0); // flags
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Set VM86 entry to IVT handler
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::VIF_FLAG) as u64;

    // Set translated real-mode segments
    regs.ds = rm_ds as u64;
    regs.es = rm_es as u64;
    regs.fs = rm_fs as u64;
    regs.gs = rm_gs as u64;

    crate::dbg_println!("[DPMI] reflect INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X}",
        vector, ivt_seg, ivt_off, regs.stack_seg(), regs.sp32(), regs.rax as u16);

    thread::KernelAction::Done
}

/// INT 31h/0301h — Call Real Mode Far Procedure
fn call_real_mode_proc(dos: &mut thread::DosState, regs: &mut Regs, cs_32: bool) -> thread::KernelAction {
    let dpmi = dos.dpmi.as_mut().unwrap();

    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let rm_cs = rm.cs;
    let rm_ip = rm.ip;

    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
        vector: 0xFF,
    });

    let rm_ss = if rm.ss != 0 { rm.ss } else { dpmi.rm_stack_seg };
    let rm_sp = if rm.sp != 0 { rm.sp } else { 0x00FE };

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

    let callback_off: u16 = dos::slot_offset(dos::SLOT_CALLBACK_RET);
    let callback_seg: u16 = dos::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For FAR CALL: push return address (callback stub) as FAR return
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Jump to the far procedure
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::VIF_FLAG) as u64;
    thread::KernelAction::Done
}

/// INT 31h/0302h — Call Real Mode Procedure with IRET Frame
fn call_real_mode_proc_iret(dos: &mut thread::DosState, regs: &mut Regs, cs_32: bool) -> thread::KernelAction {
    let dpmi = dos.dpmi.as_mut().unwrap();

    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
        vector: 0xFF,
    });

    let rm_ss = if rm.ss != 0 { rm.ss } else { dpmi.rm_stack_seg };
    let rm_sp = if rm.sp != 0 { rm.sp } else { 0x00FE };

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

    let callback_off: u16 = dos::slot_offset(dos::SLOT_CALLBACK_RET);
    let callback_seg: u16 = dos::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For IRET frame: push FLAGS, CS, IP (callback return stub)
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::VIF_FLAG) as u64;

    thread::KernelAction::Done
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub fn callback_entry(dos: &mut thread::DosState, regs: &mut Regs, cb_idx: usize) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: callback entry but no DPMI state!");
            return;
        }
    };

    let (pm_cs, pm_eip, rm_struct_sel, rm_struct_off) = match dpmi.callbacks[cb_idx] {
        Some(cb) => cb,
        None => {
            crate::println!("DPMI: callback {} not allocated!", cb_idx);
            return;
        }
    };



    // Save current real-mode regs into the register structure
    let struct_addr = seg_base(dpmi, rm_struct_sel).wrapping_add(rm_struct_off);

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

    // Save real-mode state so callback_return can restore it
    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
        vector: 0xFF,
    });

    // Switch to protected mode and call the PM handler
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

/// Return from real-mode callback to protected mode.
/// Called from stub_dispatch when the callback return stub fires.
pub fn callback_return(dos: &mut thread::DosState, regs: &mut Regs) {
    dpmi_trace!("[DPMI] CALLBACK_RET from {:04x}:{:04x}", regs.code_seg(), regs.ip32() as u16);
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: callback return but no DPMI state!");
            return;
        }
    };

    let mut saved = match dpmi.rm_save.take() {
        Some(s) => s,
        None => {
            crate::println!("DPMI: callback return but no saved PM state!");
            return;
        }
    };

    if saved.rm_struct_addr != 0 {
        // Explicit INT 31h/0300h call — copy results back to call structure
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
        unsafe { *(saved.rm_struct_addr as *mut RmCallStruct) = rm_struct; }
    } else {
        // Implicit INT reflection — propagate real-mode register results
        // back into the PM registers so the caller sees return values.
        // Snapshot saved-PM AH before reborrowing for register propagation;
        // it's the AH of the original (pre-reflection) PM call, which tells
        // us whether to apply INT 21h PSP translation.
        let saved_ah = (saved.regs.rax >> 8) as u8;
        let saved_vec = saved.vector;
        let pm_regs = &mut saved.regs;
        pm_regs.rax = (pm_regs.rax & !0xFFFFFFFF) | regs.rax & 0xFFFFFFFF;
        pm_regs.rbx = (pm_regs.rbx & !0xFFFFFFFF) | regs.rbx & 0xFFFFFFFF;
        pm_regs.rcx = (pm_regs.rcx & !0xFFFFFFFF) | regs.rcx & 0xFFFFFFFF;
        pm_regs.rdx = (pm_regs.rdx & !0xFFFFFFFF) | regs.rdx & 0xFFFFFFFF;
        pm_regs.rsi = (pm_regs.rsi & !0xFFFFFFFF) | regs.rsi & 0xFFFFFFFF;
        pm_regs.rdi = (pm_regs.rdi & !0xFFFFFFFF) | regs.rdi & 0xFFFFFFFF;
        pm_regs.rbp = (pm_regs.rbp & !0xFFFFFFFF) | regs.rbp & 0xFFFFFFFF;
        // Propagate carry flag (for DOS error reporting)
        let rm_cf = regs.flags32() & 1;
        pm_regs.set_flags32((pm_regs.flags32() & !1) | rm_cf);

        // INT 21h PSP-result translation — convert real-mode PSP segment in
        // BX back to a PM selector for AH=51h (Get PSP) and AH=62h (Get PSP).
        if saved_vec == 0x21 && (saved_ah == 0x51 || saved_ah == 0x62) {
            let psp_seg = regs.rbx as u16;
            let psp_sel = find_psp_selector(dpmi, psp_seg);
            pm_regs.rbx = (pm_regs.rbx & !0xFFFF) | psp_sel as u64;
            dpmi_trace!("[DPMI] AH={:02X} translate BX seg={:04X} -> sel={:04X}",
                saved_ah, psp_seg, psp_sel);
        }
    }

    // Restore protected-mode state
    *regs = saved.regs;
    trace_client_selector_leak("callback_return.restore", regs);

    // Reload LDT (may have been changed during VM86 execution)
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

}

// ============================================================================
// DPMI hardware IRQ delivery to protected-mode handlers
// ============================================================================

/// Deliver a hardware interrupt to the DPMI client's PM interrupt handler.
/// `vector` is the interrupt vector number (e.g. 0x09 for keyboard, 0x08 for timer).
/// If a PM handler is installed (INT 31h/0205h), push an IRET frame on the
/// client stack and redirect CS:EIP. Otherwise reflect the IRQ to real mode
/// via the IVT — same fast path as `dpmi_soft_int` uses for unhooked INT N.
pub fn deliver_hw_irq(dos: &mut thread::DosState, regs: &mut Regs, vector: u8) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };

    let (sel, off) = dpmi.pm_vectors[vector as usize];
    if sel == 0 {
        // No PM handler — reflect to real mode via the IVT (DPMI 0.9 spec:
        // the default PM handler for HW IRQs is a stub that reflects to the
        // real-mode handler, which the client may then chain to).
        let _ = reflect_int_to_real_mode(dos, regs, vector);
        return;
    }

    let use32 = dpmi.client_use32;
    let ss_sel = regs.frame.ss as u16;
    let ss_base = seg_base(dpmi, ss_sel);
    let ss_32 = seg_is_32(dpmi, ss_sel);

    // Snapshot the interrupted frame before any mutation. The client's HW IRQ
    // handler will IRET to a host trampoline stub, not back here directly, so
    // we stash these for `hw_irq_return` to restore when the stub fires.
    let saved_cs = regs.code_seg();
    let saved_eip = regs.ip32();
    let saved_flags = regs.flags32();

    // The frame we push on the client stack points at the host trampoline
    // stub (SLOT_HW_IRQ_RET). When the client handler IRETs, it lands there;
    // the stub's `CD 31` then traps back into the kernel via `hw_irq_return`.
    // Note: ring-3 IRET with IOPL=0 silently ignores the popped IF bit, so
    // we cannot rely on stacked flags to restore vIF — that's done by hand
    // in `hw_irq_return` from `saved_flags`.
    let stub_sel = DpmiState::idx_to_sel(5);
    let stub_eip = dos::STUB_BASE + (dos::SLOT_HW_IRQ_RET as u32) * 2;

    // Push IRET frame: 16-bit clients get IRETW (6 bytes), 32-bit IRETD (12 bytes).
    let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
    let frame_size: u32 = if use32 { 12 } else { 6 };
    let new_sp = sp.wrapping_sub(frame_size);
    if ss_32 {
        regs.set_sp32(new_sp);
    } else {
        regs.set_sp32((regs.sp32() & !0xFFFF) | (new_sp & 0xFFFF));
    }
    let lin = ss_base.wrapping_add(new_sp);
    unsafe {
        if use32 {
            let p = lin as *mut u32;
            core::ptr::write_unaligned(p, stub_eip);
            core::ptr::write_unaligned(p.add(1), stub_sel as u32);
            core::ptr::write_unaligned(p.add(2), saved_flags);
        } else {
            let p = lin as *mut u16;
            core::ptr::write_unaligned(p, stub_eip as u16);
            core::ptr::write_unaligned(p.add(1), stub_sel);
            core::ptr::write_unaligned(p.add(2), saved_flags as u16);
        }
    }

    dpmi.hw_irq_frames.push((saved_cs, saved_eip, saved_flags));

    dpmi_trace!("[DPMI] HW_IRQ vec={:#04x} -> {:04x}:{:#x} from {:04x}:{:#x}",
        vector, sel, off, saved_cs, saved_eip);
    regs.set_cs32(sel as u32);
    regs.set_ip32(off);

    // Interrupt-gate semantics: clear virtual IF on entry. vIF will be
    // restored from `saved_flags` by `hw_irq_return`.
    regs.frame.rflags &= !(1u64 << 9);

    // Set ISR bit so vpic won't deliver another interrupt until EOI
    let irq_num = vector.wrapping_sub(8);
    if irq_num < 8 {
        dos.pc.vpic.isr |= 1 << irq_num;
    }
}

/// Trampoline fired when the client IRETs out of a PM HW IRQ handler.
///
/// `deliver_hw_irq` pushed a fake IRET frame on the client stack whose CS:EIP
/// points at the SLOT_HW_IRQ_RET stub (`CD 31`). The client handler's IRET
/// pops that frame — SS:SP is now back at the value the interrupted code
/// had when the IRQ fired (assuming the handler kept its stack balanced) —
/// lands at the stub, which traps into `pm_stub_dispatch` → here.
///
/// We pop the saved frame from `hw_irq_frames` and restore CS:EIP plus the
/// saved vIF, because ring-3 IRET with IOPL=0 silently drops the IF bit and
/// could not have restored it on its own. All other flag bits were already
/// popped correctly by the client's IRET, so we only patch bits 9 (IF) and
/// 20 (VIP) from the saved image.
pub fn hw_irq_return(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: hw_irq_return but no DPMI state!");
            return thread::KernelAction::Done;
        }
    };
    let (cs, eip, flags) = match dpmi.hw_irq_frames.pop() {
        Some(f) => f,
        None => {
            crate::println!("DPMI: hw_irq_return with empty saved stack");
            return thread::KernelAction::Done;
        }
    };
    regs.set_cs32(cs as u32);
    regs.set_ip32(eip);
    // Restore vIF and VIP from the snapshot. Leave IOPL/VM alone.
    const IF_BIT: u64 = 1 << 9;
    const VIP_BIT: u64 = 1 << 20;
    let saved_if = (flags as u64) & IF_BIT;
    let saved_vip = (flags as u64) & VIP_BIT;
    regs.frame.rflags = (regs.frame.rflags & !(IF_BIT | VIP_BIT)) | saved_if | saved_vip;
    dpmi_trace!("[DPMI] HW_IRQ_RET -> {:04x}:{:#x} flags={:#x}", cs, eip, flags);
    thread::KernelAction::Done
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
    dpmi_trace!("[DPMI] EXCEPTION {} CS:EIP={:04x}:{:#x} err={:#x}",
        exc_num, regs.code_seg(), regs.ip32(), regs.err_code);
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
        crate::println!("{:?}", regs);
        return thread::KernelAction::Exit(-(exc_num as i32));
    }

    // Build exception frame on client's stack — width depends on client type.
    let use32 = dpmi.client_use32;
    let ss_base = seg_base(dpmi, regs.stack_seg());
    let ss_32 = seg_is_32(dpmi, regs.stack_seg());

    let mut sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };

    // Return address for the handler's RETF — point to our exception return stub
    // at LDT[5]:STUB_BASE + SLOT_EXCEPTION_RET*2 (CD 31 → pm_stub_dispatch)
    let stub_sel = DpmiState::idx_to_sel(5);
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
        push32(&mut sp, stub_sel as u32);              // return CS
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
        push16(&mut sp, stub_sel);                     // return CS
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
/// to our stub (LDT[5]:SLOT_EXCEPTION_RET) which then executes CD 31, routed
/// here via pm_stub_dispatch.
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
    let ss_base = seg_base(dpmi, regs.stack_seg());
    let ss_32 = seg_is_32(dpmi, regs.stack_seg());

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
fn raw_switch_pm_to_real(_dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_sp = regs.rbx as u16;
    let new_cs = regs.rsi as u16;
    let new_ip = regs.rdi as u16;

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
    crate::dbg_println!("[DPMI] raw PM->RM {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        new_cs, new_ip, new_ss, new_sp);
    thread::KernelAction::Done
}

/// Real-to-PM raw mode switch.
/// Called from stub_dispatch when VM86 code executes `CALL FAR` to
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

    // Determine destination operand size from the target CS/SS descriptors,
    // so 16-bit clients don't pick up garbage in EBX/EDI upper bits.
    let (new_esp, new_eip) = match dos.dpmi.as_ref() {
        Some(dpmi) => {
            let cs_32 = seg_is_32(dpmi, new_cs);
            let ss_32 = seg_is_32(dpmi, new_ss);
            let esp = if ss_32 { regs.rbx as u32 } else { regs.rbx as u32 & 0xFFFF };
            let eip = if cs_32 { regs.rdi as u32 } else { regs.rdi as u32 & 0xFFFF };
            (esp, eip)
        }
        None => (regs.rbx as u32 & 0xFFFF, regs.rdi as u32 & 0xFFFF),
    };

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
    dpmi_trace!("[DPMI] raw RM->PM CS:EIP={:04X}:{:08X} SS:ESP={:04X}:{:08X} DS={:04X} ES={:04X}",
        new_cs, new_eip, new_ss, new_esp, new_ds, new_es);

    // Reload LDT (thread must have DPMI state)
    if let Some(ref dpmi) = dos.dpmi {
        let ldt_ptr = dpmi.ldt.as_ptr() as u32;
        let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
        startup::arch_load_ldt(ldt_ptr, ldt_limit);
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Find an LDT selector whose base equals `psp_seg * 16`.
/// Used to translate INT 21h AH=51/62 results from a real-mode PSP segment
/// to the selector form that DPMI clients expect. Falls back to LDT[4]
/// (the canonical PSP selector set up at dpmi_enter) when no match is found.
fn find_psp_selector(dpmi: &DpmiState, psp_seg: u16) -> u16 {
    let target_base = (psp_seg as u32) * 16;
    for idx in 1..LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        if dpmi.ldt_alloc[word] & (1 << bit) != 0
            && DpmiState::desc_base(dpmi.ldt[idx]) == target_base
        {
            return DpmiState::idx_to_sel(idx);
        }
    }
    DpmiState::idx_to_sel(4)
}

/// Get the base address for any selector (GDT or LDT).
/// GDT selectors (TI=0) are flat (base=0).
pub fn seg_base(dpmi: &DpmiState, sel: u16) -> u32 {
    if sel & 4 != 0 {
        // LDT selector (TI=1)
        let idx = (sel >> 3) as usize;
        if idx < LDT_ENTRIES { DpmiState::desc_base(dpmi.ldt[idx]) } else { 0 }
    } else {
        0
    }
}

/// Get the D/B (default size) bit for any selector.
/// GDT selectors are treated as 32-bit.
pub fn seg_is_32(dpmi: &DpmiState, sel: u16) -> bool {
    if sel & 4 != 0 {
        let idx = (sel >> 3) as usize;
        if idx < LDT_ENTRIES { DpmiState::desc_is_32(dpmi.ldt[idx]) } else { true }
    } else {
        true
    }
}

/// Compute flat address from selector:offset.
/// Address size (16 vs 32 bit offset) determined by CS descriptor's D/B bit.
fn flat_addr(dpmi: &DpmiState, seg: u16, offset: u32, cs_32: bool) -> u32 {
    let offset = if cs_32 { offset } else { offset & 0xFFFF };
    seg_base(dpmi, seg).wrapping_add(offset)
}

fn trace_client_selector_leak(_label: &str, _regs: &Regs) {}

fn set_carry(regs: &mut Regs) {
    regs.set_flag32(1); // CF
}

fn clear_carry(regs: &mut Regs) {
    regs.clear_flag32(1); // CF
}
