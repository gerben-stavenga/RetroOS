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

    /// Build a 32-bit data descriptor (present, DPL=3, writable)
    fn make_data_desc(base: u32, limit: u32) -> u64 {
        // Access: Present(1) | DPL=3 | S=1 | Type=data,writable (0x92 | 0x60 = 0xF2)
        // Granularity: G depends on limit size, D/B=1 (32-bit)
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xF2; // Present | DPL=3 | S=1 | Data | Writable
        let flags: u64 = (g << 7) | (1 << 6); // G | D/B=1 (32-bit)
        build_descriptor(base, limit_val, access, flags)
    }

    /// Build a 32-bit code descriptor (present, DPL=3, readable)
    fn make_code_desc(base: u32, limit: u32) -> u64 {
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xFA; // Present | DPL=3 | S=1 | Code | Readable
        let flags: u64 = (g << 7) | (1 << 6); // G | D/B=1 (32-bit)
        build_descriptor(base, limit_val, access, flags)
    }

    /// Get the base address from an LDT descriptor
    fn desc_base(desc: u64) -> u32 {
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

/// Build an x86 segment descriptor from components
fn build_descriptor(base: u32, limit: u32, access: u64, flags: u64) -> u64 {
    let mut desc: u64 = 0;
    // Limit 15:0
    desc |= (limit & 0xFFFF) as u64;
    // Base 15:0
    desc |= ((base & 0xFFFF) as u64) << 16;
    // Base 23:16
    desc |= (((base >> 16) & 0xFF) as u64) << 32;
    // Access byte
    desc |= access << 40;
    // Limit 19:16 + flags
    desc |= ((limit >> 16) & 0x0F) as u64 | (flags & 0xF0);
    desc <<= 0; // noop, just for clarity
    // Actually the flags go at bits 52-55
    desc &= !0x00F0_0000_0000_0000;
    desc |= (((limit >> 16) & 0x0F) as u64) << 48;
    desc |= (flags << 52) & 0x00F0_0000_0000_0000;
    // Base 31:24
    desc |= (((base >> 24) & 0xFF) as u64) << 56;
    desc
}

// ============================================================================
// DPMI entry — mode switch from Dos/VM86 to Dos/DPMI (protected mode)
// ============================================================================

/// Switch from VM86 to 32-bit protected mode.
/// Called from f0h_dispatch when the DPMI entry stub executes.
pub fn dpmi_enter(thread: &mut thread::Thread, regs: &mut Regs) {
    dbg_println!("DPMI: entering protected mode");

    // Save VM86 register state for the FAR CALL return address
    // The FAR CALL pushed CS:IP on the real-mode stack.
    // Pop the return address so we know where to resume in PM.
    let ret_ip = vm86::vm86_pop(regs);
    let ret_cs = vm86::vm86_pop(regs);
    dbg_println!("DPMI: FAR CALL return = {:04X}:{:04X}", ret_cs, ret_ip);

    let real_cs = regs.code_seg();
    let real_ss = regs.stack_seg();
    let real_sp = regs.sp32() as u16;

    // Allocate DPMI state
    let mut dpmi = DpmiState::new();

    // Set up initial LDT entries:
    // Index 1: CS — code, base = real_cs * 16, limit = 64K, 32-bit
    let cs_base = (real_cs as u32) * 16;
    dpmi.ldt[1] = DpmiState::make_code_desc(cs_base, 0xFFFF);
    dpmi.ldt_alloc[0] |= 1 << 1;

    // Index 2: DS — data, base = PSP segment * 16, limit = 64K
    let ds_base = (vm86::COM_SEGMENT as u32) * 16;
    dpmi.ldt[2] = DpmiState::make_data_desc(ds_base, 0xFFFF);
    dpmi.ldt_alloc[0] |= 1 << 2;

    // Index 3: SS — stack, base = real_ss * 16, limit = 64K, 32-bit
    let ss_base = (real_ss as u32) * 16;
    dpmi.ldt[3] = DpmiState::make_data_desc(ss_base, 0xFFFF);
    dpmi.ldt_alloc[0] |= 1 << 3;

    // Index 4: ES — alias of DS
    dpmi.ldt[4] = dpmi.ldt[2];
    dpmi.ldt_alloc[0] |= 1 << 4;

    let cs_sel = DpmiState::idx_to_sel(1);
    let ds_sel = DpmiState::idx_to_sel(2);
    let ss_sel = DpmiState::idx_to_sel(3);
    let es_sel = DpmiState::idx_to_sel(4);

    dbg_println!("DPMI: CS={:#06x} (base={:#x}), DS={:#06x} (base={:#x}), SS={:#06x} (base={:#x})",
        cs_sel, cs_base, ds_sel, ds_base, ss_sel, ss_base);

    // Load LDT via arch call
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

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

    // Store DPMI state on thread
    thread.dpmi = Some(Box::new(dpmi));

    dbg_println!("DPMI: now in protected mode, EIP={:#x}, ESP={:#x}", ret_ip, real_sp);
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
    let cs_idx = DpmiState::sel_to_idx(regs.code_seg());
    let cs_base = if cs_idx < LDT_ENTRIES {
        DpmiState::desc_base(dpmi.ldt[cs_idx])
    } else {
        0
    };
    let flat_eip = cs_base.wrapping_add(regs.ip32());

    // Read instruction byte(s)
    let opcode = unsafe { *(flat_eip as *const u8) };
    let mut advance = 1u32;

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
            // Push onto PM stack
            let ss_idx = DpmiState::sel_to_idx(regs.stack_seg());
            let ss_base = if ss_idx < LDT_ENTRIES { DpmiState::desc_base(dpmi.ldt[ss_idx]) } else { 0 };
            let new_sp = regs.sp32().wrapping_sub(4);
            regs.set_sp32(new_sp);
            unsafe { *((ss_base.wrapping_add(new_sp)) as *mut u32) = flags; }
        }
        // POPF — pop flags, extract virtual IF
        0x9D => {
            let ss_idx = DpmiState::sel_to_idx(regs.stack_seg());
            let ss_base = if ss_idx < LDT_ENTRIES { DpmiState::desc_base(dpmi.ldt[ss_idx]) } else { 0 };
            let sp = regs.sp32();
            let flags = unsafe { *((ss_base.wrapping_add(sp)) as *const u32) };
            regs.set_sp32(sp.wrapping_add(4));
            dpmi.vif = flags & (1 << 9) != 0;
            // Don't let PM code change IOPL or VM
            let preserved = regs.flags32() & (0x3000 | (1 << 17));
            regs.set_flags32((flags & !(0x3000 | (1 << 17))) | preserved);
        }
        // HLT — yield
        0xF4 => {
            regs.set_ip32(regs.ip32().wrapping_add(advance));
            thread::save_state(thread, regs);
            thread.state = thread::ThreadState::Ready;
            return thread::schedule();
        }
        // IRET — pop EIP/CS/EFLAGS from PM stack (32-bit)
        0xCF => {
            let ss_idx = DpmiState::sel_to_idx(regs.stack_seg());
            let ss_base = if ss_idx < LDT_ENTRIES { DpmiState::desc_base(dpmi.ldt[ss_idx]) } else { 0 };
            let sp = regs.sp32();
            let new_eip = unsafe { *((ss_base.wrapping_add(sp)) as *const u32) };
            let new_cs = unsafe { *((ss_base.wrapping_add(sp + 4)) as *const u32) } as u16;
            let new_flags = unsafe { *((ss_base.wrapping_add(sp + 8)) as *const u32) };
            regs.set_sp32(sp.wrapping_add(12));
            regs.set_ip32(new_eip);
            regs.set_cs32(new_cs as u32);
            dpmi.vif = new_flags & (1 << 9) != 0;
            let preserved = regs.flags32() & (0x3000 | (1 << 17));
            regs.set_flags32((new_flags & !(0x3000 | (1 << 17))) | preserved);
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
        _ => {
            crate::println!("DPMI: unhandled GP fault opcode={:#04x} at {:#x}", opcode, flat_eip);
            crate::println!("{:?}", regs);
            // Kill the thread
            let next = thread::exit_thread(-13);
            return Some(next);
        }
    }

    regs.set_ip32(regs.ip32().wrapping_add(advance));
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

    let ax = regs.rax as u16;
    dbg_println!("DPMI INT 31h: AX={:04X}", ax);

    match ax {
        // AX=0000h — Allocate LDT Descriptors
        // CX = number of descriptors
        // Returns: AX = base selector
        0x0000 => {
            let count = (regs.rcx & 0xFFFF) as usize;
            if count == 0 { set_carry(regs); return None; }
            // Allocate contiguous selectors (simplified: allocate one at a time)
            let first = dpmi.alloc_ldt();
            match first {
                Some(idx) => {
                    for _ in 1..count {
                        dpmi.alloc_ldt(); // best-effort contiguous
                    }
                    regs.rax = (regs.rax & !0xFFFF) | DpmiState::idx_to_sel(idx) as u64;
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
                    regs.rax = (regs.rax & !0xFFFF) | DpmiState::idx_to_sel(new_idx) as u64;
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
                let dest = flat_addr(dpmi, regs.es as u16, regs.rdi as u32);
                unsafe { *(dest as *mut u64) = dpmi.ldt[idx]; }
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
                let src = flat_addr(dpmi, regs.es as u16, regs.rdi as u32);
                dpmi.ldt[idx] = unsafe { *(src as *const u64) };
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
                regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | DpmiState::idx_to_sel(idx) as u64;
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
            return simulate_real_mode_int(thread, regs);
        }
        // AX=0301h — Call Real Mode Far Procedure
        // ES:EDI = real-mode call structure
        0x0301 => {
            return call_real_mode_proc(thread, regs);
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
            let dest = flat_addr(dpmi, regs.es as u16, regs.rdi as u32);
            // Fill with "lots of memory available"
            let buf = dest as *mut u32;
            unsafe {
                // Largest available block
                *buf.add(0) = 16 * 1024 * 1024; // 16MB
                // Maximum unlocked page allocation
                *buf.add(1) = 4096;
                // Maximum locked page allocation
                *buf.add(2) = 4096;
                // Linear address space size in pages
                *buf.add(3) = 16 * 1024 / 4;
                // Total unlocked pages
                *buf.add(4) = 4096;
                // Total free pages
                *buf.add(5) = 4096;
                // Total physical pages
                *buf.add(6) = 4096;
                // Free linear address space in pages
                *buf.add(7) = 16 * 1024 / 4;
                // Size of paging file/partition in pages
                *buf.add(8) = 0;
                // Reserved (3 dwords)
                *buf.add(9) = 0;
                *buf.add(10) = 0;
                *buf.add(11) = 0;
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
            dbg_println!("DPMI 0501: alloc {:#x} bytes at {:#x}", aligned, base);
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
        _ => {
            dbg_println!("DPMI: unhandled INT 31h AX={:04X}", ax);
            set_carry(regs);
        }
    }

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
fn simulate_real_mode_int(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();
    let int_num = regs.rbx as u8;

    // Read the real-mode call structure from ES:EDI
    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let rm_cs = rm.cs;
    let rm_ip = rm.ip;
    dbg_println!("DPMI 0300: simulate INT {:02X}, CS:IP={:04X}:{:04X}", int_num, rm_cs, rm_ip);

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

    // Use SS:SP from structure if provided, else use a default
    let rm_ss = if rm.ss != 0 { rm.ss } else { vm86::COM_SEGMENT };
    let rm_sp = if rm.sp != 0 { rm.sp } else { 0xFFFE };

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

/// INT 31h/0301h — Call Real Mode Far Procedure
fn call_real_mode_proc(thread: &mut thread::Thread, regs: &mut Regs) -> Option<usize> {
    let dpmi = thread.dpmi.as_mut().unwrap();

    let struct_addr = flat_addr(dpmi, regs.es as u16, regs.rdi as u32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    let rm_cs = rm.cs;
    let rm_ip = rm.ip;
    dbg_println!("DPMI 0301: call far {:04X}:{:04X}", rm_cs, rm_ip);

    dpmi.rm_save = Some(SavedPmState {
        regs: *regs,
        rm_struct_addr: struct_addr,
    });

    const VM_FLAG: u32 = 1 << 17;
    const IF_FLAG: u32 = 1 << 9;
    const VIF_FLAG: u32 = 1 << 19;

    let rm_ss = if rm.ss != 0 { rm.ss } else { vm86::COM_SEGMENT };
    let rm_sp = if rm.sp != 0 { rm.sp } else { 0xFFFE };

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

    None
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

    let saved = match dpmi.rm_save.take() {
        Some(s) => s,
        None => {
            crate::println!("DPMI: callback return but no saved PM state!");
            return;
        }
    };

    // Copy real-mode results back to the call structure
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

    // Restore protected-mode state
    *regs = saved.regs;

    // Reload LDT (may have been changed during VM86 execution)
    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
    let ldt_limit = (LDT_ENTRIES * 8 - 1) as u32;
    startup::arch_load_ldt(ldt_ptr, ldt_limit);

    dbg_println!("DPMI: callback return, back to PM");
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute flat address from selector:offset using LDT
fn flat_addr(dpmi: &DpmiState, sel: u16, offset: u32) -> u32 {
    let idx = DpmiState::sel_to_idx(sel);
    let base = if idx < LDT_ENTRIES {
        DpmiState::desc_base(dpmi.ldt[idx])
    } else {
        0
    };
    base.wrapping_add(offset)
}

fn set_carry(regs: &mut Regs) {
    regs.set_flag32(1); // CF
}

fn clear_carry(regs: &mut Regs) {
    regs.clear_flag32(1); // CF
}
