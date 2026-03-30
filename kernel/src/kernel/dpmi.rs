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
use crate::kernel::vm86;
use crate::kernel::startup;
use crate::{Regs, dbg_println};

/// Number of LDT entries
const LDT_ENTRIES: usize = 256;
/// Maximum DPMI memory blocks
const MAX_MEM_BLOCKS: usize = 32;
/// Base address for DPMI linear memory allocations
const MEM_BASE: u32 = 0x0050_0000;

/// Maximum number of real-mode callbacks (INT 31h/0303h)
const MAX_CALLBACKS: usize = 16;
/// Base offset within STUB_SEG for callback entry stubs (each 2 bytes: CD F0)
const CB_STUB_OFFSET: u16 = 0x0030;

/// Per-thread DPMI state (heap-allocated, attached to Thread.dpmi)
pub struct DpmiState {
    /// Local Descriptor Table entries
    pub ldt: Box<[u64; LDT_ENTRIES]>,
    /// LDT allocation bitmap (1 = in use). 256 bits = 8 u32s.
    pub ldt_alloc: [u32; 8],
    /// Linear memory blocks allocated via INT 31h/0501h
    pub mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub mem_next: u32,
    /// Saved protected-mode state during real-mode callbacks (INT 31h/0300h)
    pub rm_save: Option<SavedPmState>,
    /// Virtual interrupt flag for protected-mode code
    pub vif: bool,
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
    /// Pointer to the 50-byte real-mode call structure (in PM address space)
    pub rm_struct_addr: u32,
}

impl DpmiState {
    pub fn new() -> Self {
        Self {
            ldt: Box::new([0u64; LDT_ENTRIES]),
            ldt_alloc: [0u32; 8],
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            rm_save: None,
            vif: true,
            pm_vectors: [(0, 0); 256],
            exc_vectors: [(0, 0); 32],
            callbacks: [None; MAX_CALLBACKS],
            rm_stack_seg: 0,
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
/// Called from f0h_dispatch when the DPMI entry stub executes.
pub fn dpmi_enter(thread: &mut thread::Thread, regs: &mut Regs) {
    let client_type = regs.rax as u16; // AX: 0=16-bit, 1=32-bit
    dbg_println!("DPMI enter: AX={} ({}bit client)", client_type, if client_type != 0 { 32 } else { 16 });

    // Save VM86 register state for the FAR CALL return address
    // The FAR CALL pushed CS:IP on the real-mode stack.
    // Pop the return address so we know where to resume in PM.
    let ret_ip = vm86::vm86_pop(regs);
    let ret_cs = vm86::vm86_pop(regs);

    let real_ss = regs.stack_seg();
    let real_sp = regs.sp32() as u16;

    // Allocate DPMI state
    let mut dpmi = DpmiState::new();

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

    // Index 4: ES — PSP selector (DPMI spec: ES=PSP on entry)
    let psp_base = (vm86::COM_SEGMENT as u32) * 16;
    dpmi.ldt[4] = DpmiState::make_data_desc_ex(psp_base, 0xFFFF, false);
    dpmi.ldt_alloc[0] |= 1 << 4;

    // Index 5: stub code segment (base=0, limit=0x0FFF) for RETF stubs
    // Used by INT 31h/0305h PM save/restore entry point
    dpmi.ldt[5] = DpmiState::make_code_desc_ex(0, 0x0FFF, false);
    dpmi.ldt_alloc[0] |= 1 << 5;

    let cs_sel = DpmiState::idx_to_sel(1);
    let ds_sel = DpmiState::idx_to_sel(2);
    let ss_sel = DpmiState::idx_to_sel(3);
    let es_sel = DpmiState::idx_to_sel(4);


    // Load LDT via arch call
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

    dbg_println!("DPMI enter: ret_cs={:#06x} ret_ip={:#06x} cs_base={:#x} ds_base={:#x} ss_base={:#x}",
        ret_cs, ret_ip, cs_base, ds_base, ss_base);

    // Switch regs from VM86 to protected mode:
    // Clear VM flag, set PM selectors, set EIP to return offset
    const VM_FLAG: u64 = 1 << 17;
    const IF_FLAG: u64 = 1 << 9;

    regs.frame.rflags &= !VM_FLAG;
    regs.frame.rflags |= IF_FLAG;
    regs.frame.cs = cs_sel as u64;
    regs.frame.rip = ret_ip as u64;
    regs.frame.ss = ss_sel as u64;
    regs.frame.rsp = real_sp as u64;
    regs.ds = ds_sel as u64;
    regs.es = es_sel as u64;
    regs.fs = 0;
    regs.gs = 0;

    dbg_println!("DPMI enter: CS={:#06x}:{:#x} SS={:#06x}:{:#x} DS={:#06x} ES={:#06x}",
        cs_sel, ret_ip, ss_sel, real_sp, ds_sel, es_sel);
    dbg_println!(
        "DPMI enter: sel 0x20 -> idx={} ti={} rpl={} base={:#x}",
        DpmiState::sel_to_idx(0x20),
        (0x20 >> 2) & 1,
        0x20 & 3,
        seg_base(&dpmi, 0x20),
    );

    // Dump code at the return point and at the 0306h failure handler
    let flat_ret = cs_base.wrapping_add(ret_ip as u32);
    let code: [u8; 256] = unsafe { core::ptr::read(flat_ret as *const [u8; 256]) };
    for i in 0..4 {
        dbg_println!("Code+{:02x}: {:02x?}", i*64, &code[i*64..(i+1)*64]);
    }
    let fallback_flat = cs_base.wrapping_add(0x713c);
    let fallback_code: [u8; 64] = unsafe { core::ptr::read(fallback_flat as *const [u8; 64]) };
    for i in 0..4 {
        dbg_println!("Fallback713c+{:02x}: {:02x?}", i * 16, &fallback_code[i * 16..(i + 1) * 16]);
    }
    let pm_stub: [u8; 48] = unsafe { core::ptr::read(0x0500 as *const [u8; 48]) };
    for i in 0..3 {
        dbg_println!("PmStub+{:02x}: {:02x?}", i * 16, &pm_stub[i * 16..(i + 1) * 16]);
    }
    // Dump far pointer at DS:0x0E6C (used by CALL FAR [0x0E6C] in DOS4GW)
    let far_ptr_addr = ds_base.wrapping_add(0x0E6C);
    let far_ptr: [u8; 4] = unsafe { core::ptr::read(far_ptr_addr as *const [u8; 4]) };
    let far_off = u16::from_le_bytes([far_ptr[0], far_ptr[1]]);
    let far_seg = u16::from_le_bytes([far_ptr[2], far_ptr[3]]);
    dbg_println!("Far ptr at DS:0E6C (linear {:#x}): {:04x}:{:04x}", far_ptr_addr, far_seg, far_off);

    // Allocate a dedicated real-mode stack for INT 31h/0300h simulation.
    // Must not overlap the client's data area. Grab 256 bytes (16 paragraphs)
    // from the DOS heap.
    let rm_stack_seg = thread.vm86.heap_seg;
    thread.vm86.heap_seg = rm_stack_seg.wrapping_add(0x10); // 256 bytes
    dpmi.rm_stack_seg = rm_stack_seg;

    // Store DPMI state on thread
    thread.dpmi = Some(Box::new(dpmi));

}

// ============================================================================
// DPMI monitor — GP fault handler for protected-mode DOS code
// ============================================================================

/// Handle GP fault (#13) from 32-bit protected mode (Dos thread in DPMI mode).
/// Only handles sensitive instructions that cause #GP from ring 3:
/// I/O, CLI/STI, PUSHF/POPF, HLT, IRET. INT instructions arrive as direct
/// events via the IDT (DPL=3 for 0x30-0xFF).
pub fn dpmi_monitor(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = match thread.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: GP fault but no DPMI state!");
            return None;
        }
    };

    // Get flat EIP: CS base + EIP
    let cs_32 = seg_is_32(dpmi, regs.code_seg());
    let flat_eip = seg_base(dpmi, regs.code_seg()).wrapping_add(regs.ip32());

    let ss_base = seg_base(dpmi, regs.stack_seg());
    let ss_32 = seg_is_32(dpmi, regs.stack_seg());

    // Helper: get/set SP respecting SS B bit
    let get_sp = |regs: &Regs| -> u32 {
        if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF }
    };
    let set_sp = |regs: &mut Regs, val: u32| {
        if ss_32 {
            regs.set_sp32(val);
        } else {
            regs.set_sp32((regs.sp32() & !0xFFFF) | (val & 0xFFFF));
        }
    };

    // Parse prefix bytes
    let mut offset = 0u32;
    let mut op_size_override = false;
    loop {
        let b = unsafe { *((flat_eip.wrapping_add(offset)) as *const u8) };
        match b {
            0x66 => { op_size_override = true; offset += 1; }
            _ => break,
        }
    }

    // Effective operand size: 32 if (cs_32 XOR override)
    let op32 = cs_32 ^ op_size_override;

    // Read instruction byte(s)
    let opcode = unsafe { *((flat_eip.wrapping_add(offset)) as *const u8) };
    let mut advance = offset + 1;

    crate::dbg_println!("GP13 EIP={:#x} op={:#04x} cs32={}", regs.ip32(), opcode, cs_32);
    if opcode == 0x0F {
        let op2 = unsafe { *((flat_eip.wrapping_add(offset + 1)) as *const u8) };
        let modrm = unsafe { *((flat_eip.wrapping_add(offset + 2)) as *const u8) };
        crate::dbg_println!(
            "GP13 ext EIP={:#x} op2={:#04x} modrm={:#04x} AX={:04x} BX={:04x} CX={:04x} DX={:04x} DS={:04x} ES={:04x} SS={:04x}",
            regs.ip32(),
            op2,
            modrm,
            regs.rax as u16,
            regs.rbx as u16,
            regs.rcx as u16,
            regs.rdx as u16,
            regs.ds as u16,
            regs.es as u16,
            regs.stack_seg(),
        );
    }

    match opcode {
        // CLI — clear virtual IF
        0xFA => {
            dpmi.vif = false;
        }
        // STI — set virtual IF
        0xFB => {
            dpmi.vif = true;
        }
        // PUSHF — push flags with virtual IF
        0x9C => {
            let mut flags = regs.flags32();
            if dpmi.vif { flags |= 1 << 9; } else { flags &= !(1 << 9); }
            let sp = get_sp(regs);
            if op32 {
                let new_sp = sp.wrapping_sub(4);
                set_sp(regs, new_sp);
                unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(new_sp)) as *mut u32, flags); }
            } else {
                let new_sp = sp.wrapping_sub(2);
                set_sp(regs, new_sp);
                unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(new_sp)) as *mut u16, flags as u16); }
            }
        }
        // POPF — pop flags, extract virtual IF
        0x9D => {
            let sp = get_sp(regs);
            let flags = if op32 {
                let v = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u32) };
                set_sp(regs, sp.wrapping_add(4));
                v
            } else {
                let v = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u16) } as u32;
                set_sp(regs, sp.wrapping_add(2));
                v
            };
            dpmi.vif = flags & (1 << 9) != 0;
            let preserved = regs.flags32() & (0x3000 | (1 << 17));
            regs.set_flags32((flags & !(0x3000 | (1 << 17))) | preserved);
        }
        // HLT — yield
        0xF4 => {
            regs.set_ip32(regs.ip32().wrapping_add(advance));
            trace_client_selector_leak("dpmi_monitor.hlt", regs);
            thread::save_state(thread, regs);
            thread.state = thread::ThreadState::Ready;
            return thread::schedule();
        }
        // IRET — pop IP/CS/FLAGS, size depends on operand size
        0xCF => {
            let sp = get_sp(regs);
            if op32 {
                let new_eip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u32) };
                let new_cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u32) } as u16;
                let new_flags = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 8)) as *const u32) };
                crate::dbg_println!("IRET32 ss_base={:#x} sp={:#x} → EIP={:#010x} CS={:#06x} FL={:#010x}",
                    ss_base, sp, new_eip, new_cs, new_flags);
                set_sp(regs, sp.wrapping_add(12));
                regs.set_ip32(new_eip);
                regs.set_cs32(new_cs as u32);
                dpmi.vif = new_flags & (1 << 9) != 0;
                let preserved = regs.flags32() & (0x3000 | (1 << 17));
                regs.set_flags32((new_flags & !(0x3000 | (1 << 17))) | preserved);
            } else {
                let new_ip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u16) };
                let new_cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 2)) as *const u16) };
                let new_flags = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u16) } as u32;
                crate::dbg_println!("IRET16 ss_base={:#x} sp={:#x} → IP={:#06x} CS={:#06x} FL={:#06x}",
                    ss_base, sp, new_ip, new_cs, new_flags);
                set_sp(regs, sp.wrapping_add(6));
                regs.set_ip32(new_ip as u32);
                regs.set_cs32(new_cs as u32);
                dpmi.vif = new_flags & (1 << 9) != 0;
                let preserved = regs.flags32() & (0x3000 | (1 << 17));
                regs.set_flags32((new_flags & !(0x3000 | (1 << 17))) | preserved);
            }
            trace_client_selector_leak("dpmi_monitor.iret", regs);
            return None; // Don't advance IP — we set it
        }
        // IN AL, imm8
        0xE4 => {
            let port = unsafe { *(flat_eip.wrapping_add(1) as *const u8) } as u16;
            advance = 2;
            match vm86::emulate_inb(port) {
                Ok(val) => { regs.rax = (regs.rax & !0xFF) | val as u64; }
                Err(_) => {}
            }
        }
        // IN AL, DX
        0xEC => {
            let port = regs.rdx as u16;
            match vm86::emulate_inb(port) {
                Ok(val) => { regs.rax = (regs.rax & !0xFF) | val as u64; }
                Err(_) => {}
            }
        }
        // OUT imm8, AL
        0xE6 => {
            let port = unsafe { *(flat_eip.wrapping_add(1) as *const u8) } as u16;
            advance = 2;
            let _ = vm86::emulate_outb(port, regs.rax as u8);
        }
        // OUT DX, AL
        0xEE => {
            let port = regs.rdx as u16;
            let _ = vm86::emulate_outb(port, regs.rax as u8);
        }
        // IN AX, imm8 (16-bit)
        0xE5 => {
            let port = unsafe { *(flat_eip.wrapping_add(1) as *const u8) } as u16;
            advance = 2;
            let lo = vm86::emulate_inb(port).unwrap_or(0xFF);
            let hi = vm86::emulate_inb(port + 1).unwrap_or(0xFF);
            regs.rax = (regs.rax & !0xFFFF) | lo as u64 | ((hi as u64) << 8);
        }
        // IN AX, DX (16-bit)
        0xED => {
            let port = regs.rdx as u16;
            let lo = vm86::emulate_inb(port).unwrap_or(0xFF);
            let hi = vm86::emulate_inb(port + 1).unwrap_or(0xFF);
            regs.rax = (regs.rax & !0xFFFF) | lo as u64 | ((hi as u64) << 8);
        }
        // OUT imm8, AX (16-bit)
        0xE7 => {
            let port = unsafe { *(flat_eip.wrapping_add(1) as *const u8) } as u16;
            advance = 2;
            let _ = vm86::emulate_outb(port, regs.rax as u8);
            let _ = vm86::emulate_outb(port + 1, (regs.rax >> 8) as u8);
        }
        // OUT DX, AX (16-bit)
        0xEF => {
            let port = regs.rdx as u16;
            let _ = vm86::emulate_outb(port, regs.rax as u8);
            let _ = vm86::emulate_outb(port + 1, (regs.rax >> 8) as u8);
        }
        // INT imm8 — software interrupt (GP faults because IDT DPL=0 for vectors < 0x30)
        0xCD => {
            let vector = unsafe { *((flat_eip.wrapping_add(offset + 1)) as *const u8) };
            advance = offset + 2;
            let new_ip = regs.ip32().wrapping_add(advance);
            let new_ip = if cs_32 { new_ip } else { new_ip & 0xFFFF };
            // Push 32-bit IRET frame on client stack.
            // DPMI interrupt dispatch uses 32-bit gates — always push dwords,
            // regardless of caller's operand size.  The handler's IRET (often
            // o32 IRET in use16 code) expects 32-bit values.
            let sp = get_sp(regs);
            let new_sp = sp.wrapping_sub(12);
            set_sp(regs, new_sp);
            unsafe {
                core::ptr::write_unaligned((ss_base.wrapping_add(new_sp)) as *mut u32, new_ip);
                core::ptr::write_unaligned((ss_base.wrapping_add(new_sp + 4)) as *mut u32, regs.code_seg() as u32);
                core::ptr::write_unaligned((ss_base.wrapping_add(new_sp + 8)) as *mut u32, regs.flags32());
            }
            // Dispatch to PM interrupt handler
            let dpmi = thread.dpmi.as_ref().unwrap();
            let (sel, off) = dpmi.pm_vectors[vector as usize];
            if sel != 0 {
                regs.set_cs32(sel as u32);
                regs.set_ip32(off);
            } else {
                // No PM handler installed — reflect to real mode via IVT.
                // Undo the stack push (the PM IRET frame is not needed).
                set_sp(regs, sp);
                // Save PM state with IP past the INT instruction.
                regs.set_ip32(new_ip);
                return reflect_int_to_real_mode(thread, regs, vector);
            }
            trace_client_selector_leak("dpmi_monitor.int", regs);
            return None;
        }
        _ => {
            // Not a sensitive instruction — dispatch to client exception handler
            let modrm = unsafe { *((flat_eip.wrapping_add(offset + 1)) as *const u8) };
            crate::println!("GP13 unhandled op={:#04x} modrm={:#04x} err={:#x} CS:EIP={:04x}:{:#x} AX={:04x} BX={:04x} CX={:04x} DX={:04x} DS={:04x} ES={:04x}",
                opcode, modrm, regs.err_code, regs.code_seg(), regs.ip32(),
                regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.ds as u16, regs.es as u16);
            crate::dbg_println!("GP13 unhandled op={:#04x} modrm={:#04x} err={:#x} CS:EIP={:04x}:{:#x}",
                opcode, modrm, regs.err_code, regs.code_seg(), regs.ip32());
            return dispatch_dpmi_exception(thread, regs, 13);
        }
    }

    let new_ip = regs.ip32().wrapping_add(advance);
    if cs_32 {
        regs.set_ip32(new_ip);
    } else {
        regs.set_ip32(new_ip & 0xFFFF);
    }
    trace_client_selector_leak("dpmi_monitor.step", regs);
    None
}

// ============================================================================
// INT 31h — DPMI services
// ============================================================================

/// Handle INT 31h from protected mode. Called from event loop when event=0x31.
pub fn dpmi_int31(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = match thread.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: INT 31h but no DPMI state!");
            set_carry(regs);
            return None;
        }
    };

    // Determine code segment address size — use16 means register offsets are 16-bit
    let cs_32 = seg_is_32(dpmi, regs.code_seg());

    let ax = regs.rax as u16;
    if ax != 0x0202 && ax != 0x0203 && ax != 0x0204 && ax != 0x0205 && ax != 0xFF00 && ax != 0xFF01 {
        crate::dbg_println!("INT31 AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:#06x}:{:#x} SS:ESP={:#06x}:{:#x}",
            ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
            regs.frame.cs as u16, regs.ip32(), regs.frame.ss as u16, regs.sp32());
    }

    match ax {
        // AX=0000h — Allocate LDT Descriptors
        // CX = number of descriptors
        // Returns: AX = base selector
        0x0000 => {
            let count = (regs.rcx & 0xFFFF) as usize;
            if count == 0 { set_carry(regs); return None; }
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
                    dbg_println!("  0000 alloc count={} -> sel={:#06x} idx={}", count, sel, idx);
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
                dbg_println!("  0007 set base sel={:#06x} idx={} base={:#x}", sel, idx, base);
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
                dbg_println!("  0008 set limit sel={:#06x} idx={} limit={:#x}", sel, idx, limit);
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
                dbg_println!("  0009 set rights sel={:#06x} idx={} access={:#04x} ext={:#04x}", sel, idx, cl, ch);
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
                    dbg_println!("  000A alias src={:#06x} -> sel={:#06x} idx={}", sel, new_sel, new_idx);
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
                dbg_println!("  000B get sel={:#06x} idx={} desc={:#018x} base={:#x} lim={:#x} 32={}",
                    sel, idx, dpmi.ldt[idx],
                    DpmiState::desc_base(dpmi.ldt[idx]), DpmiState::desc_limit(dpmi.ldt[idx]),
                    DpmiState::desc_is_32(dpmi.ldt[idx]));
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
                let es_base = seg_base(dpmi, regs.es as u16);
                let es_32 = seg_is_32(dpmi, regs.es as u16);
                let src = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
                let raw_bytes = unsafe { core::slice::from_raw_parts(src as *const u8, 8) };
                dbg_println!("  000C ES={:#06x} es_base={:#x} es_32={} EDI={:#010x} cs_32={} flat={:#010x} raw=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                    regs.es as u16, es_base, es_32,
                    regs.rdi as u32, cs_32, src,
                    raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3],
                    raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]);
                let new_desc = unsafe { core::ptr::read_unaligned(src as *const u64) };
                let old_desc = dpmi.ldt[idx];
                dpmi.ldt[idx] = new_desc;
                dbg_println!("  000C set sel={:#06x} idx={} old={:#018x} new={:#018x} base={:#x} lim={:#x} 32={}",
                    sel, idx, old_desc, new_desc,
                    DpmiState::desc_base(new_desc), DpmiState::desc_limit(new_desc),
                    DpmiState::desc_is_32(new_desc));
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
            let seg = thread.vm86.heap_seg;
            thread.vm86.heap_seg = seg.wrapping_add(paragraphs);
            // Create a data descriptor for this block
            if let Some(idx) = dpmi.alloc_ldt() {
                let base = (seg as u32) * 16;
                let limit = (paragraphs as u32) * 16 - 1;
                dpmi.ldt[idx] = DpmiState::make_data_desc(base, limit);
                let sel = DpmiState::idx_to_sel(idx);
                regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | sel as u64;
                dbg_println!("  0100 alloc dos paragraphs={} rm_seg={:#06x} -> sel={:#06x} idx={} base={:#x} limit={:#x}",
                    paragraphs, seg, sel, idx, base, limit);
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
            let off = vm86::read_u16(0, (int_num as u32) * 4);
            let seg = vm86::read_u16(0, (int_num as u32) * 4 + 2);
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
            vm86::write_u16(0, (int_num as u32) * 4, off);
            vm86::write_u16(0, (int_num as u32) * 4 + 2, seg);
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
        0x0204 => {
            let int_num = regs.rbx as u8;
            let (sel, off) = dpmi.pm_vectors[int_num as usize];
            regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
            regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0205h — Set Protected Mode Interrupt Vector
        // BL = interrupt number, CX:EDX = selector:offset
        0x0205 => {
            let int_num = regs.rbx as u8;
            dpmi.pm_vectors[int_num as usize] = (regs.rcx as u16, regs.rdx as u32);
            clear_carry(regs);
        }
        // AX=0300h — Simulate Real Mode Interrupt
        // BL = interrupt number, ES:EDI = real-mode call structure (50 bytes)
        0x0300 => {
            return simulate_real_mode_int(thread, regs, cs_32);
        }
        // AX=0301h — Call Real Mode Far Procedure
        // ES:EDI = real-mode call structure
        0x0301 => {
            return call_real_mode_proc(thread, regs, cs_32);
        }
        // AX=0302h — Call Real Mode Procedure with IRET Frame
        // ES:EDI = real-mode call structure (procedure returns via IRET)
        0x0302 => {
            return call_real_mode_proc_iret(thread, regs, cs_32);
        }
        // AX=0303h — Allocate Real Mode Callback Address
        // DS:SI = PM callback handler, ES:DI = real-mode register structure
        // Returns: CX:DX = real-mode callback address (segment:offset)
        0x0303 => {
            let dpmi = thread.dpmi.as_mut().unwrap();
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
                    // Return real-mode address: STUB_SEG:(CB_STUB_OFFSET + i*2)
                    let rm_off = CB_STUB_OFFSET + (i as u16) * 2;
                    regs.rcx = (regs.rcx & !0xFFFF) | vm86::STUB_SEG as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | rm_off as u64;
                    crate::dbg_println!("  0303 alloc callback {} → {:04x}:{:04x} handler={:04x}:{:x}",
                        i, vm86::STUB_SEG, rm_off, regs.ds as u16, regs.rsi as u32);
                    clear_carry(regs);
                }
                None => set_carry(regs),
            }
        }
        // AX=0304h — Free Real Mode Callback Address
        // CX:DX = real-mode callback address to free
        0x0304 => {
            let dpmi = thread.dpmi.as_mut().unwrap();
            let off = regs.rdx as u16;
            if off >= CB_STUB_OFFSET && off < CB_STUB_OFFSET + (MAX_CALLBACKS as u16) * 2 {
                let idx = ((off - CB_STUB_OFFSET) / 2) as usize;
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
            regs.rdx = (regs.rdx & !0xFFFF) | 0x70_20; // DH=0x20 master PIC, DL=0x70 slave PIC — wait, reversed
            // DH = master PIC base (IRQ 0 = INT 20h), DL = slave PIC base (IRQ 8 = INT 70h)
            // Actually DPMI convention: DH = master PIC base vector, DL = slave PIC base vector
            regs.rdx = (regs.rdx & !0xFFFF) | ((0x20 << 8) | 0x70) as u64;
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
            if size == 0 { set_carry(regs); return None; }
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
            if !stored { set_carry(regs); return None; }
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
            // Simple approach: allocate new block (old memory is demand-paged anyway)
            let aligned = (new_size + 0xFFF) & !0xFFF;
            let base = dpmi.mem_next;
            dpmi.mem_next = dpmi.mem_next.wrapping_add(aligned);
            // Remove old block, add new
            for slot in dpmi.mem_blocks.iter_mut() {
                if let Some(blk) = slot {
                    if blk.base == handle {
                        *slot = Some(MemBlock { base, size: aligned });
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
            let prev = if dpmi.vif { 1u64 } else { 0u64 };
            dpmi.vif = false;
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0901h — Get and Enable Virtual Interrupt State
        0x0901 => {
            let prev = if dpmi.vif { 1u64 } else { 0u64 };
            dpmi.vif = true;
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0902h — Get Virtual Interrupt State
        0x0902 => {
            regs.rax = (regs.rax & !0xFF) | if dpmi.vif { 1 } else { 0 };
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
            // Real-mode save/restore: point to RETF in stub area (0x0050:0x0002)
            regs.rbx = (regs.rbx & !0xFFFF) | vm86::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | 0x0002;  // offset of RETF byte
            // Protected-mode save/restore: stub code selector:0x0502 (RETF at linear 0x0502)
            let stub_sel = DpmiState::idx_to_sel(5);
            regs.rsi = (regs.rsi & !0xFFFF) | stub_sel as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | 0x0502;  // offset = linear addr (base=0)
            dbg_println!("  0305 save/restore rm={:04x}:{:04x} pm={:04x}:{:#x}", vm86::STUB_SEG, 0x0002u16, stub_sel, 0x0502u16);
            clear_carry(regs);
        }
        // AX=0306h — Get Raw Mode Switch Addresses
        // Returns real-to-PM and PM-to-real switch entry points
        0x0306 => {
            // BX:CX = real-to-PM entry point (real-mode segment:offset)
            regs.rbx = (regs.rbx & !0xFFFF) | vm86::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | 0x0021;  // offset of real-to-PM stub
            // SI:(E)DI = PM-to-real entry point (selector:offset)
            let stub_sel = DpmiState::idx_to_sel(5);  // LDT[5]: base=0 code segment
            regs.rsi = (regs.rsi & !0xFFFF) | stub_sel as u64;
            regs.rdi = (regs.rdi & !0xFFFFFFFF) | 0x0523;  // offset of PUSH AX; MOV AX,FF01; INT 31h
            dbg_println!("  0306 raw switch rm->pm={:04x}:{:04x} pm->rm={:04x}:{:#x}", vm86::STUB_SEG, 0x0021u16, stub_sel, 0x0523u16);
            clear_carry(regs);
        }
        // AX=FF00h — Private: exception handler return
        0xFF00 => {
            return exception_return(thread, regs);
        }
        // AX=FF01h — Private: raw mode switch PM→real
        // Stub did PUSH AX (saved new DS) then MOV AX,FF01; INT 31h
        // Remaining regs per raw switch convention: BX=SP, CX=ES, DX=SS, SI=CS, DI=IP
        0xFF01 => {
            return raw_switch_pm_to_real(thread, regs);
        }
        // AX=0507h — Set Page Attributes (DPMI 1.0)
        // All our memory is committed, so this is a no-op.
        0x0507 => {
            clear_carry(regs);
        }
        _ => {
            panic!("DPMI: unhandled INT 31h AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:04x}:{:#x}",
                ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.code_seg(), regs.ip32());
        }
    }

    trace_client_selector_leak("dpmi_int31.exit", regs);
    None
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
fn simulate_real_mode_int(thread: &mut thread::Thread, regs: &mut Regs, cs_32: bool) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();
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
    });

    // Set up VM86 regs for real-mode interrupt
    const VM_FLAG: u32 = 1 << 17;
    const IF_FLAG: u32 = 1 << 9;
    const VIF_FLAG: u32 = 1 << 19;

    // Get IVT entry for the interrupt
    let ivt_off = vm86::read_u16(0, (int_num as u32) * 4);
    let ivt_seg = vm86::read_u16(0, (int_num as u32) * 4 + 2);

    // Diagnostic: check if IVT still points to our stub
    if ivt_seg != vm86::STUB_SEG || ivt_off < 0x0008 || ivt_off > 0x0020 {
        crate::println!("WARN: IVT[{:#04x}] = {:04X}:{:04X} (expected 0050:xxxx)",
            int_num, ivt_seg, ivt_off);
        // Dump IVT bytes at the entry
        let lin = (int_num as u32) * 4;
        let b0 = unsafe { *(lin as *const u8) };
        let b1 = unsafe { *((lin+1) as *const u8) };
        let b2 = unsafe { *((lin+2) as *const u8) };
        let b3 = unsafe { *((lin+3) as *const u8) };
        crate::println!("  IVT bytes at {:#x}: [{:02x} {:02x} {:02x} {:02x}]", lin, b0, b1, b2, b3);
        // Also dump struct SS:SP
        let (ax, ss, sp) = (rm.eax as u16, rm.ss, rm.sp);
        crate::println!("  rm struct: AX={:04x} SS={:04x} SP={:04x}", ax, ss, sp);
    }

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
    // The callback stub at 0x0050:0x0006 does INT F0h which triggers callback_return
    let callback_off: u16 = 0x0006;
    let callback_seg: u16 = vm86::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // Push return IRET frame on VM86 stack
    vm86::vm86_push(regs, rm.flags);
    vm86::vm86_push(regs, callback_seg);
    vm86::vm86_push(regs, callback_off);

    // Set CS:IP to the IVT handler
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (VM_FLAG | IF_FLAG | VIF_FLAG) as u64;

    // Now in VM86 mode — the event loop will execute the BIOS handler.
    // When it IRETs to callback_stub, INT F0h fires, and callback_return() is called.
    None
}

/// Reflect a software INT from protected mode to real mode via the IVT.
/// Used when a DPMI client executes `INT xx` and no PM handler is installed.
/// The current PM registers (with IP already past the INT) are saved;
/// the low 16 bits of EAX/EBX/ECX/EDX/ESI/EDI/EBP + segment regs are
/// forwarded to the real-mode handler.  On return (callback_return),
/// the updated real-mode registers are copied back before resuming PM.
fn reflect_int_to_real_mode(thread: &mut thread::Thread, regs: &mut Regs, vector: u8) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();

    // Translate PM selector bases to real-mode segments (base >> 4)
    let rm_ds = (seg_base(dpmi, regs.ds as u16) >> 4) as u16;
    let rm_es = (seg_base(dpmi, regs.es as u16) >> 4) as u16;
    let rm_fs = (seg_base(dpmi, regs.fs as u16) >> 4) as u16;
    let rm_gs = (seg_base(dpmi, regs.gs as u16) >> 4) as u16;

    crate::dbg_println!("DPMI reflect INT {:#04x} AX={:04x} BX={:04x} CX={:04x} DX={:04x} DS={:04x}->{:04x} ES={:04x}->{:04x}",
        vector, regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.ds as u16, rm_ds, regs.es as u16, rm_es);

    // Save protected-mode state (rm_struct_addr=0 signals implicit reflection)
    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: 0,
    });

    const VM_FLAG: u32 = 1 << 17;
    const IF_FLAG: u32 = 1 << 9;
    const VIF_FLAG: u32 = 1 << 19;

    // Get IVT entry
    let ivt_off = vm86::read_u16(0, (vector as u32) * 4);
    let ivt_seg = vm86::read_u16(0, (vector as u32) * 4 + 2);

    // Use the dedicated DPMI real-mode stack (not COM_SEGMENT which overlaps client data)
    let rm_ss = dpmi.rm_stack_seg;
    let rm_sp: u16 = 0x00FE;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // Push callback return IRET frame on VM86 stack
    let callback_off: u16 = 0x0006;
    let callback_seg: u16 = vm86::STUB_SEG;
    vm86::vm86_push(regs, 0); // flags
    vm86::vm86_push(regs, callback_seg);
    vm86::vm86_push(regs, callback_off);

    // Set VM86 entry to IVT handler
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (VM_FLAG | IF_FLAG | VIF_FLAG) as u64;

    // Set translated real-mode segments
    regs.ds = rm_ds as u64;
    regs.es = rm_es as u64;
    regs.fs = rm_fs as u64;
    regs.gs = rm_gs as u64;

    None
}

/// INT 31h/0301h — Call Real Mode Far Procedure
fn call_real_mode_proc(thread: &mut thread::Thread, regs: &mut Regs, cs_32: bool) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();

    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let rm_cs = rm.cs;
    let rm_ip = rm.ip;

    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
    });

    const VM_FLAG: u32 = 1 << 17;
    const IF_FLAG: u32 = 1 << 9;
    const VIF_FLAG: u32 = 1 << 19;

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

    let callback_off: u16 = 0x0006;
    let callback_seg: u16 = vm86::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For FAR CALL: push return address (callback stub) as FAR return
    vm86::vm86_push(regs, callback_seg);
    vm86::vm86_push(regs, callback_off);

    // Jump to the far procedure
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (VM_FLAG | IF_FLAG | VIF_FLAG) as u64;
    crate::dbg_println!(
        "  0302 handoff flags={:#x} vm={} CS={:04x} SS={:04x} DS={:04x} ES={:04x}",
        regs.flags(),
        (regs.flags() >> 17) & 1,
        regs.code_seg(),
        regs.stack_seg(),
        regs.ds as u16,
        regs.es as u16,
    );

    None
}

/// INT 31h/0302h — Call Real Mode Procedure with IRET Frame
fn call_real_mode_proc_iret(thread: &mut thread::Thread, regs: &mut Regs, cs_32: bool) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();

    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32, cs_32);
    crate::dbg_println!("  0302 ES={:#06x} EDI={:#x} cs_32={} flat={:#x}",
        regs.es as u16, regs.rdi as u32, cs_32, struct_addr);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };
    let rm_cs_v = rm.cs; let rm_ip_v = rm.ip; let rm_ss_v = rm.ss; let rm_sp_v = rm.sp;
    let rm_ds_v = rm.ds; let rm_es_v = rm.es; let rm_ax_v = rm.eax as u16;
    crate::dbg_println!("  0302 rm CS:IP={:04x}:{:04x} SS:SP={:04x}:{:04x} DS={:04x} ES={:04x} AX={:04x}",
        rm_cs_v, rm_ip_v, rm_ss_v, rm_sp_v, rm_ds_v, rm_es_v, rm_ax_v);

    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
    });

    const VM_FLAG: u32 = 1 << 17;
    const IF_FLAG: u32 = 1 << 9;
    const VIF_FLAG: u32 = 1 << 19;

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

    let callback_off: u16 = 0x0006;
    let callback_seg: u16 = vm86::STUB_SEG;

    regs.frame.ss = rm_ss as u64;
    regs.frame.rsp = rm_sp as u64;

    // For IRET frame: push FLAGS, CS, IP (callback return stub)
    vm86::vm86_push(regs, rm.flags);
    vm86::vm86_push(regs, callback_seg);
    vm86::vm86_push(regs, callback_off);

    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (VM_FLAG | IF_FLAG | VIF_FLAG) as u64;

    None
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub fn callback_entry(thread: &mut thread::Thread, regs: &mut Regs, cb_idx: usize) {
    let dpmi = match thread.dpmi.as_mut() {
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

    crate::dbg_println!("DPMI: callback {} entry, handler={:04x}:{:#x}", cb_idx, pm_cs, pm_eip);

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
    });

    // Switch to protected mode and call the PM handler
    // DS:SI = selector:offset pointing to real-mode SS:SP
    // ES:DI = selector:offset pointing to register structure
    const VM_FLAG: u64 = 1 << 17;
    regs.frame.rflags &= !VM_FLAG;
    regs.frame.cs = pm_cs as u64;
    regs.set_ip32(pm_eip);
    regs.ds = rm_struct_sel as u64;  // DS:ESI = register structure
    regs.rsi = rm_struct_off as u64;
    regs.es = rm_struct_sel as u64;  // ES:EDI = register structure
    regs.rdi = rm_struct_off as u64;
}

/// Return from real-mode callback to protected mode.
/// Called from f0h_dispatch when the callback return stub fires.
pub fn callback_return(thread: &mut thread::Thread, regs: &mut Regs) {
    let dpmi = match thread.dpmi.as_mut() {
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
        { let (a,b,c,d,si,di,ds,es) = (rm_struct.eax as u16, rm_struct.ebx as u16,
            rm_struct.ecx as u16, rm_struct.edx as u16,
            rm_struct.esi as u16, rm_struct.edi as u16,
            rm_struct.ds, rm_struct.es);
          crate::dbg_println!("  cb_ret struct@{:#x} AX={:04x} BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
            saved.rm_struct_addr, a, b, c, d, si, di, ds, es); }
        unsafe { *(saved.rm_struct_addr as *mut RmCallStruct) = rm_struct; }
    } else {
        // Implicit INT reflection — propagate real-mode register results
        // back into the PM registers so the caller sees return values.
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
    }

    // Restore protected-mode state
    crate::dbg_println!("  cb_ret pm AX={:04x} BX={:04x} CX={:04x} DX={:04x} CS:EIP={:04x}:{:#x}",
        saved.regs.rax as u16, saved.regs.rbx as u16,
        saved.regs.rcx as u16, saved.regs.rdx as u16,
        saved.regs.code_seg(), saved.regs.ip32());
    *regs = saved.regs;
    trace_client_selector_leak("callback_return.restore", regs);

    // Reload LDT (may have been changed during VM86 execution)
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

}

// ============================================================================
// DPMI exception dispatch — route CPU exceptions to client handlers
// ============================================================================

/// Dispatch a CPU exception to the client's exception handler (set via INT 31h/0203h).
/// If no handler is set, kill the thread.
///
/// DPMI exception handler calling convention (32-bit client):
/// The handler is called with a FAR CALL. Stack frame:
///   [ESP+0]  Return EIP (points to DPMI host retf stub)
///   [ESP+4]  Return CS (DPMI host code selector)
///   [ESP+8]  Error code
///   [ESP+12] Faulting EIP
///   [ESP+16] Faulting CS
///   [ESP+20] Faulting EFLAGS
///   [ESP+24] Faulting ESP (optional, for SS faults)
///   [ESP+28] Faulting SS (optional, for SS faults)
pub fn dispatch_dpmi_exception(thread: &mut thread::Thread, regs: &mut Regs, exc_num: u32) -> Option<usize> {
    let dpmi = match thread.dpmi.as_ref() {
        Some(d) => d,
        None => {
            let next = thread::exit_thread(-(exc_num as i32));
            return Some(next);
        }
    };

    let (handler_sel, handler_off) = if (exc_num as usize) < 32 {
        dpmi.exc_vectors[exc_num as usize]
    } else {
        (0, 0)
    };

    if handler_sel == 0 && handler_off == 0 {
        // No handler set — kill
        crate::println!("DPMI: exception {} at CS:EIP={:#06x}:{:#x} err={:#x}, no handler",
            exc_num, regs.frame.cs as u16, regs.ip32(), regs.err_code);
        crate::println!("{:?}", regs);
        let next = thread::exit_thread(-(exc_num as i32));
        return Some(next);
    }

    // Build exception frame on client's stack
    let ss_base = seg_base(dpmi, regs.stack_seg());
    let ss_32 = seg_is_32(dpmi, regs.stack_seg());

    let mut sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };

    // Push exception frame (growing down)
    let push32 = |sp: &mut u32, val: u32| {
        *sp = sp.wrapping_sub(4);
        unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(*sp)) as *mut u32, val); }
    };

    // DPMI exception frame: pushed from high to low address
    // The handler sees: [ESP] = retaddr_eip, [ESP+4] = retaddr_cs, [ESP+8] = error_code, ...
    push32(&mut sp, regs.frame.ss as u32);        // faulting SS
    push32(&mut sp, regs.sp32());                  // faulting ESP
    push32(&mut sp, regs.flags32());               // faulting EFLAGS
    push32(&mut sp, regs.frame.cs as u32);         // faulting CS
    push32(&mut sp, regs.ip32());                  // faulting EIP
    push32(&mut sp, regs.err_code as u32);         // error code
    // Return address for the handler's RETF — point to our exception return stub
    // at LDT[5]:0x052A which does MOV AX,0xFF00; INT 31h
    let stub_sel = DpmiState::idx_to_sel(5);
    push32(&mut sp, stub_sel as u32);              // return CS
    push32(&mut sp, 0x052A);                       // return EIP

    // Dump faulting instruction bytes
    let fault_cs_base = seg_base(dpmi, regs.frame.cs as u16);
    let fault_flat = fault_cs_base.wrapping_add(regs.ip32());
    let fault_bytes: [u8; 8] = unsafe { core::ptr::read(fault_flat as *const [u8; 8]) };
    let opcode = fault_bytes[0];
    let handler_base = seg_base(dpmi, handler_sel);
    let handler_flat = handler_base.wrapping_add(handler_off);
    let handler_bytes: [u8; 64] = unsafe { core::ptr::read(handler_flat as *const [u8; 64]) };
    dbg_println!("DPMI exc {} → handler {:04x}:{:#x} from {:04x}:{:#x} err={:#x} op={:#04x} bytes={:02x?}",
        exc_num, handler_sel, handler_off, regs.frame.cs as u16, regs.ip32(), regs.err_code, opcode, fault_bytes);
    dbg_println!(
        "  regs: AX={:04x} BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} BP={:04x} SP={:04x}",
        regs.rax as u16,
        regs.rbx as u16,
        regs.rcx as u16,
        regs.rdx as u16,
        regs.rsi as u16,
        regs.rdi as u16,
        regs.rbp as u16,
        regs.sp32() as u16,
    );
    dbg_println!(
        "  segs: CS={:04x} IP={:04x} SS={:04x} SP32={:#x} DS={:04x} ES={:04x} FS={:04x} GS={:04x} FL={:#x}",
        regs.frame.cs as u16,
        regs.ip32() as u16,
        regs.frame.ss as u16,
        regs.sp32(),
        regs.ds as u16,
        regs.es as u16,
        regs.fs as u16,
        regs.gs as u16,
        regs.flags32(),
    );
    for i in 0..4 {
        dbg_println!("  handler+{:02x}: {:02x?}", i * 16, &handler_bytes[i * 16..(i + 1) * 16]);
    }
    trace_client_selector_leak("dispatch_dpmi_exception.in", regs);
    if (regs.ds as u16) == 0x20 || (regs.es as u16) == 0x20 {
        dump_ldt(dpmi, "dispatch_dpmi_exception.in");
    }

    // Set up regs to call the exception handler
    if ss_32 {
        regs.set_sp32(sp);
    } else {
        regs.set_sp32((regs.sp32() & !0xFFFF) | (sp & 0xFFFF));
    }
    regs.frame.cs = handler_sel as u64;
    regs.set_ip32(handler_off);

    dbg_println!("  frame: CS={:#x} EIP={:#x} FL={:#x} SS={:#x} ESP={:#x}",
        regs.frame.cs, regs.frame.rip, regs.frame.rflags, regs.frame.ss, regs.frame.rsp);
    dbg_println!("  DS={:#x} ES={:#x} FS={:#x} GS={:#x}",
        regs.ds, regs.es, regs.fs, regs.gs);
    trace_client_selector_leak("dispatch_dpmi_exception.out", regs);
    if (regs.ds as u16) == 0x20 || (regs.es as u16) == 0x20 {
        dump_ldt(dpmi, "dispatch_dpmi_exception.out");
    }

    None
}

/// Handle return from a DPMI exception handler (event 0xF2 from PM).
/// The handler did RETF which popped the return CS:EIP (our stub).
/// The stub did INT F2h. Now we pop the exception frame from the stack
/// and restore the (possibly modified) faulting context.
///
/// Stack at this point (from the handler's perspective, the RETF already popped
/// the return address; INT F2h pushed SS/ESP/EFLAGS/CS/EIP on kernel stack):
///   [old ESP+0]  error code
///   [old ESP+4]  faulting EIP (possibly modified by handler)
///   [old ESP+8]  faulting CS
///   [old ESP+12] faulting EFLAGS
///   [old ESP+16] faulting ESP
///   [old ESP+20] faulting SS
fn exception_return(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = match thread.dpmi.as_ref() {
        Some(d) => d,
        None => return None,
    };

    // The INT F2h trap saved the handler's CS:EIP (stub) and SS:ESP on kernel stack.
    // regs.frame.ss/rsp reflect the handler's stack AFTER the RETF popped return addr.
    // The exception frame starts at the current ESP.
    let ss_base = seg_base(dpmi, regs.stack_seg());
    let ss_32 = seg_is_32(dpmi, regs.stack_seg());

    let mut sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };

    let pop32 = |sp: &mut u32| -> u32 {
        let val = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(*sp)) as *const u32) };
        *sp = sp.wrapping_add(4);
        val
    };

    dbg_println!("exc_ret: ss_base={:#x} ss={:#x} sp={:#x}", ss_base, regs.stack_seg(), sp);
    // Dump raw bytes at the exception frame
    let frame_bytes: [u8; 24] = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const [u8; 24]) };
    dbg_println!("exc_ret frame: {:02x?}", frame_bytes);

    let _error_code = pop32(&mut sp);
    let new_eip = pop32(&mut sp);
    let new_cs = pop32(&mut sp) as u16;
    let new_eflags = pop32(&mut sp);
    let new_esp = pop32(&mut sp);
    let new_ss = pop32(&mut sp) as u16;

    dbg_println!("exc_ret: err={:#x} eip={:#x} cs={:#x} efl={:#x} esp={:#x} ss={:#x}",
        _error_code, new_eip, new_cs, new_eflags, new_esp, new_ss);

    regs.frame.cs = new_cs as u64;
    regs.set_ip32(new_eip);
    regs.frame.ss = new_ss as u64;
    regs.set_sp32(new_esp);
    // Restore EFLAGS but preserve IOPL and VM
    let preserved = regs.flags32() & (0x3000 | (1 << 17));
    regs.set_flags32((new_eflags & !(0x3000 | (1 << 17))) | preserved);
    trace_client_selector_leak("exception_return.out", regs);
    None
}

// ============================================================================
// Raw mode switch (INT 31h/0306h)
// ============================================================================

/// PM-to-real raw mode switch.
/// Called via INT 31h/0xFF01 from the stub: PUSH AX; MOV AX,0xFF01; INT 31h.
/// The caller's AX (= new DS) was pushed on the user stack by the stub.
///
/// Register convention (set by caller before CALL FAR):
///   AX = new real-mode DS  (saved on stack by stub, AX now = 0xFF01)
///   CX = new real-mode ES
///   DX = new real-mode SS
///   BX = new real-mode SP
///   SI = new real-mode CS
///   DI = new real-mode IP
fn raw_switch_pm_to_real(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = thread.dpmi.as_ref().unwrap();
    crate::dbg_println!(
        "Raw PM→real in: AX={:04x} BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} CS:IP={:04x}:{:04x} SS:SP={:04x}:{:04x} DS={:04x} ES={:04x}",
        regs.rax as u16,
        regs.rbx as u16,
        regs.rcx as u16,
        regs.rdx as u16,
        regs.rsi as u16,
        regs.rdi as u16,
        regs.code_seg(),
        regs.ip32() as u16,
        regs.stack_seg(),
        regs.sp32() as u16,
        regs.ds as u16,
        regs.es as u16,
    );

    // Read saved AX (new DS) from user stack — stub did PUSH AX before INT 31h
    let ss_base = seg_base(dpmi, regs.stack_seg());
    let new_ds = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(regs.sp32())) as *const u16) };

    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_sp = regs.rbx as u16;
    let new_cs = regs.rsi as u16;
    let new_ip = regs.rdi as u16;

    dbg_println!("Raw PM→real: CS:IP={:04x}:{:04x} SS:SP={:04x}:{:04x} DS={:04x} ES={:04x}",
        new_cs, new_ip, new_ss, new_sp, new_ds, new_es);

    // Set VM86 mode
    const VM_FLAG: u64 = 1 << 17;
    const IF_FLAG: u64 = 1 << 9;

    regs.frame.rflags |= VM_FLAG | IF_FLAG;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_ip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_sp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    crate::dbg_println!(
        "Raw PM→real out: AX={:04x} BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} CS:IP={:04x}:{:04x} SS:SP={:04x}:{:04x} DS={:04x} ES={:04x} FLAGS={:#x}",
        regs.rax as u16,
        regs.rbx as u16,
        regs.rcx as u16,
        regs.rdx as u16,
        regs.rsi as u16,
        regs.rdi as u16,
        regs.code_seg(),
        regs.ip32() as u16,
        regs.stack_seg(),
        regs.sp32() as u16,
        regs.ds as u16,
        regs.es as u16,
        regs.flags(),
    );
    trace_client_selector_leak("raw_switch_pm_to_real.out", regs);
    None
}

/// Real-to-PM raw mode switch.
/// Called from f0h_dispatch when VM86 code executes `CALL FAR` to the
/// real-to-PM entry stub (0x0050:0x0021 → INT F0h trap).
///
/// Register convention (set by caller before CALL FAR):
///   AX = new PM DS selector
///   CX = new PM ES selector
///   DX = new PM SS selector
///   (E)BX = new PM (E)SP
///   SI = new PM CS selector
///   (E)DI = new PM (E)IP
pub fn raw_switch_real_to_pm(thread: &mut thread::Thread, regs: &mut Regs) {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_esp = regs.rbx as u32;
    let new_cs = regs.rsi as u16;
    let new_eip = regs.rdi as u32;

    dbg_println!("Raw real→PM: CS:EIP={:04x}:{:#x} SS:ESP={:04x}:{:#x} DS={:04x} ES={:04x}",
        new_cs, new_eip, new_ss, new_esp, new_ds, new_es);

    // Clear VM flag, enter protected mode
    const VM_FLAG: u64 = 1 << 17;
    const IF_FLAG: u64 = 1 << 9;

    regs.frame.rflags &= !VM_FLAG;
    regs.frame.rflags |= IF_FLAG;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_eip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_esp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    trace_client_selector_leak("raw_switch_real_to_pm.out", regs);

    // Reload LDT (thread must have DPMI state)
    if let Some(ref dpmi) = thread.dpmi {
        let ldt_ptr = dpmi.ldt.as_ptr() as u32;
        let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
        startup::arch_load_ldt(ldt_ptr, ldt_limit);
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Get the base address for any selector (GDT or LDT).
/// GDT selectors (TI=0) are flat (base=0).
fn seg_base(dpmi: &DpmiState, sel: u16) -> u32 {
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
fn seg_is_32(dpmi: &DpmiState, sel: u16) -> bool {
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

fn dump_ldt(dpmi: &DpmiState, tag: &str) {
    dbg_println!("LDT dump [{}]:", tag);
    for idx in 0..16 {
        let desc = dpmi.ldt[idx];
        if desc != 0 {
            dbg_println!(
                "  idx={} sel={:#06x} desc={:#018x} base={:#x} lim={:#x} 32={} code={}",
                idx,
                DpmiState::idx_to_sel(idx),
                desc,
                DpmiState::desc_base(desc),
                DpmiState::desc_limit(desc),
                DpmiState::desc_is_32(desc),
                (desc >> 43) & 1 != 0,
            );
        }
    }
}

fn trace_client_selector_leak(label: &str, regs: &Regs) {
    let ds = regs.ds as u16;
    let es = regs.es as u16;
    let fs = regs.fs as u16;
    let gs = regs.gs as u16;
    let cs = regs.code_seg();
    let ss = regs.stack_seg();

    if !(is_flat_user_gdt(ds)
        || is_flat_user_gdt(es)
        || is_flat_user_gdt(fs)
        || is_flat_user_gdt(gs)
        || is_flat_user_gdt(cs)
        || is_flat_user_gdt(ss))
    {
        return;
    }

    dbg_println!(
        "DPMI selector leak [{}]: AX={:04x} BX={:04x} CX={:04x} DX={:04x} CS:IP={:04x}:{:x} SS:SP={:04x}:{:x} DS={:04x} ES={:04x} FS={:04x} GS={:04x}",
        label,
        regs.rax as u16,
        regs.rbx as u16,
        regs.rcx as u16,
        regs.rdx as u16,
        cs,
        regs.ip32(),
        ss,
        regs.sp32(),
        ds,
        es,
        fs,
        gs,
    );
}

fn is_flat_user_gdt(sel: u16) -> bool {
    matches!(
        sel & !3,
        x if x == (crate::arch::descriptors::USER_CS & !3)
            || x == (crate::arch::descriptors::USER_DS & !3)
            || x == (crate::arch::descriptors::USER_CS64 & !3)
    )
}

fn set_carry(regs: &mut Regs) {
    regs.set_flag32(1); // CF
}

fn clear_carry(regs: &mut Regs) {
    regs.clear_flag32(1); // CF
}
