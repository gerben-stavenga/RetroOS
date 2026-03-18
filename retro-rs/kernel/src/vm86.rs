//! VM86 mode support for DOS .COM program execution
//!
//! Provides:
//! - VM86 monitor (handles GP faults from sensitive instructions)
//! - DOS INT 21h emulation (basic character/string I/O, exit)
//! - BIOS INT 10h emulation (teletype output)
//! - IVT setup (fills 256 entries pointing at IRET stub)
//! - .COM file loader

use crate::thread;
use crate::vga;
use crate::println;
use crate::Regs;

/// .COM load segment (standard DOS convention: PSP at seg:0000, code at seg:0100)
const COM_SEGMENT: u16 = 0x1000;
/// .COM code offset within segment
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer (top of 64KB segment)
const COM_SP: u16 = 0xFFFE;

/// Segment where the IRET stub lives (0xF000:0x0000)
const IVT_HANDLER_SEG: u16 = 0xF000;
const IVT_HANDLER_OFF: u16 = 0x0000;

// ============================================================================
// VM86 monitor — handles GP faults for sensitive instructions
// ============================================================================

/// Read a byte from the VM86 address space at CS:IP and advance IP
fn fetch_byte(regs: &mut Regs) -> u8 {
    unsafe {
        let cs = regs.frame.f32.cs;
        let ip = regs.frame.f32.eip;
        let linear = (cs << 4) + ip;
        let byte = *(linear as *const u8);
        regs.frame.f32.eip = ip + 1;
        byte
    }
}

/// Read a u16 from a real-mode seg:off address
fn read_u16(seg: u32, off: u32) -> u16 {
    let linear = (seg << 4) + off;
    unsafe { *(linear as *const u16) }
}

/// Write a u16 to a real-mode seg:off address
fn write_u16(seg: u32, off: u32, val: u16) {
    let linear = (seg << 4) + off;
    unsafe { *(linear as *mut u16) = val; }
}

/// Push a u16 onto the VM86 stack (SS:SP)
fn vm86_push(regs: &mut Regs, val: u16) {
    unsafe {
        regs.frame.f32.esp = regs.frame.f32.esp.wrapping_sub(2);
        write_u16(regs.frame.f32.ss, regs.frame.f32.esp, val);
    }
}

/// Pop a u16 from the VM86 stack (SS:SP)
fn vm86_pop(regs: &mut Regs) -> u16 {
    unsafe {
        let val = read_u16(regs.frame.f32.ss, regs.frame.f32.esp);
        regs.frame.f32.esp = regs.frame.f32.esp.wrapping_add(2);
        val
    }
}

/// VM86 monitor — called from GP fault handler when EFLAGS.VM=1.
/// Emulates sensitive instructions that cause GP faults in VM86 mode.
pub fn vm86_monitor(regs: &mut Regs) {
    let opcode = fetch_byte(regs);

    match opcode {
        // INT n (0xCD nn)
        0xCD => {
            let int_num = fetch_byte(regs);
            handle_vm86_int(regs, int_num);
        }
        // IRET (0xCF) — pop IP, CS, FLAGS from VM86 stack
        0xCF => {
            let ip = vm86_pop(regs);
            let cs = vm86_pop(regs);
            let flags = vm86_pop(regs);
            unsafe {
                regs.frame.f32.eip = ip as u32;
                regs.frame.f32.cs = cs as u32;
                // Preserve VM and IOPL, merge rest from popped flags
                let preserved = regs.frame.f32.eflags & 0x0002_0000; // VM flag
                regs.frame.f32.eflags = (flags as u32 & !0x0002_0000) | preserved | (1 << 9); // keep VM, force IF
            }
            // Update virtual IF
            if let Some(t) = thread::current() {
                t.vm86_vif = (flags & (1 << 9)) != 0;
            }
        }
        // CLI (0xFA)
        0xFA => {
            if let Some(t) = thread::current() {
                t.vm86_vif = false;
            }
        }
        // STI (0xFB)
        0xFB => {
            if let Some(t) = thread::current() {
                t.vm86_vif = true;
            }
        }
        // PUSHF (0x9C) — push FLAGS with virtual IF
        0x9C => {
            let vif = thread::current().map_or(true, |t| t.vm86_vif);
            let mut flags = unsafe { regs.frame.f32.eflags as u16 };
            if vif { flags |= 1 << 9; } else { flags &= !(1 << 9); }
            vm86_push(regs, flags);
        }
        // POPF (0x9D) — pop FLAGS, update virtual IF
        0x9D => {
            let flags = vm86_pop(regs);
            if let Some(t) = thread::current() {
                t.vm86_vif = (flags & (1 << 9)) != 0;
            }
            unsafe {
                let preserved = regs.frame.f32.eflags & 0x0002_0000; // VM
                regs.frame.f32.eflags = (flags as u32 & !0x0002_0000) | preserved | (1 << 9);
            }
        }
        // IN AL, imm8 (0xE4)
        0xE4 => {
            let port = fetch_byte(regs) as u16;
            regs.rax = (regs.rax & !0xFF) | crate::x86::inb(port) as u64;
        }
        // IN AX, imm8 (0xE5)
        0xE5 => {
            let port = fetch_byte(regs) as u16;
            regs.rax = (regs.rax & !0xFFFF) | crate::x86::inw(port) as u64;
        }
        // OUT imm8, AL (0xE6)
        0xE6 => {
            let port = fetch_byte(regs) as u16;
            crate::x86::outb(port, regs.rax as u8);
        }
        // OUT imm8, AX (0xE7)
        0xE7 => {
            let port = fetch_byte(regs) as u16;
            // outw not critical, just use outb for low byte
            crate::x86::outb(port, regs.rax as u8);
        }
        // IN AL, DX (0xEC)
        0xEC => {
            let port = regs.rdx as u16;
            regs.rax = (regs.rax & !0xFF) | crate::x86::inb(port) as u64;
        }
        // IN AX, DX (0xED)
        0xED => {
            let port = regs.rdx as u16;
            regs.rax = (regs.rax & !0xFFFF) | crate::x86::inw(port) as u64;
        }
        // OUT DX, AL (0xEE)
        0xEE => {
            let port = regs.rdx as u16;
            crate::x86::outb(port, regs.rax as u8);
        }
        // OUT DX, AX (0xEF)
        0xEF => {
            let port = regs.rdx as u16;
            crate::x86::outb(port, regs.rax as u8);
        }
        // HLT (0xF4) — yield
        0xF4 => {
            crate::x86::sti();
            crate::x86::hlt();
        }
        _ => {
            println!("\x1b[91mVM86: unhandled opcode {:#04x} at {:04x}:{:04x}\x1b[0m",
                opcode, unsafe { regs.frame.f32.cs }, unsafe { regs.frame.f32.eip } - 1);
            // Kill the VM86 thread
            thread::exit_thread(-11);
        }
    }
}

// ============================================================================
// INT dispatch — intercept DOS/BIOS calls, reflect others via IVT
// ============================================================================

/// Handle INT n from VM86 mode
fn handle_vm86_int(regs: &mut Regs, int_num: u8) {
    match int_num {
        0x10 => int_10h(regs),
        0x20 => {
            // INT 20h — DOS program terminate
            thread::exit_thread(0);
        }
        0x21 => int_21h(regs),
        _ => {
            // Reflect through IVT: push FLAGS, CS, IP and jump to IVT handler
            let flags = unsafe { regs.frame.f32.eflags as u16 };
            let cs = unsafe { regs.frame.f32.cs as u16 };
            let ip = unsafe { regs.frame.f32.eip as u16 };

            vm86_push(regs, flags);
            vm86_push(regs, cs);
            vm86_push(regs, ip);

            // Read IVT entry (4 bytes: offset:segment at int_num * 4)
            let ivt_off = read_u16(0, (int_num as u32) * 4);
            let ivt_seg = read_u16(0, (int_num as u32) * 4 + 2);

            unsafe {
                regs.frame.f32.eip = ivt_off as u32;
                regs.frame.f32.cs = ivt_seg as u32;
            }
        }
    }
}

// ============================================================================
// BIOS INT 10h — Video services
// ============================================================================

fn int_10h(regs: &mut Regs) {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=0x0E: Teletype output
        0x0E => {
            let ch = regs.rax as u8;
            vga::vga().putchar(ch);
        }
        _ => {
            // Ignore unsupported INT 10h functions
        }
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(regs: &mut Regs) {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            vga::vga().putchar(regs.rdx as u8);
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let ds = regs.ds as u32;
            let dx = regs.rdx as u32;
            let mut addr = (ds << 4) + dx;
            loop {
                let ch = unsafe { *(addr as *const u8) };
                if ch == b'$' { break; }
                vga::vga().putchar(ch);
                addr += 1;
                // Safety limit
                if addr > 0xFFFFF { break; }
            }
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            let code = regs.rax as u8;
            thread::exit_thread(code as i32);
        }
        _ => {
            println!("VM86: unhandled INT 21h AH={:#04x}", ah);
        }
    }
}

// ============================================================================
// IVT setup — fill all 256 entries with a pointer to an IRET instruction
// ============================================================================

/// Set up the Interrupt Vector Table at address 0x0000-0x03FF.
/// All 256 entries point to IVT_HANDLER_SEG:IVT_HANDLER_OFF (0xF000:0x0000).
/// We also write an IRET opcode (0xCF) at linear address 0xF0000.
pub fn setup_ivt() {
    // Write IRET instruction at the handler address
    let iret_addr = ((IVT_HANDLER_SEG as u32) << 4) + IVT_HANDLER_OFF as u32;
    unsafe {
        *(iret_addr as *mut u8) = 0xCF; // IRET opcode
    }

    // Fill IVT (256 entries, 4 bytes each: offset:segment)
    for i in 0..256u32 {
        let entry_addr = i * 4;
        unsafe {
            *(entry_addr as *mut u16) = IVT_HANDLER_OFF;
            *((entry_addr + 2) as *mut u16) = IVT_HANDLER_SEG;
        }
    }
}

// ============================================================================
// .COM file loader
// ============================================================================

/// Load a .COM binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// Layout:
///   Segment COM_SEGMENT (0x1000):
///     0x0000-0x00FF: PSP (Program Segment Prefix)
///       PSP[0..2] = INT 20h (CD 20) — program termination
///     0x0100-...:    .COM binary code
///   Stack at COM_SEGMENT:COM_SP (top of segment)
pub fn load_com(data: &[u8]) -> (u16, u16, u16, u16) {
    let base = (COM_SEGMENT as u32) << 4;

    // Write INT 20h (CD 20) at PSP offset 0 — so RET from .COM terminates
    unsafe {
        *(base as *mut u8) = 0xCD;
        *((base + 1) as *mut u8) = 0x20;
    }

    // Copy .COM data at offset 0x100
    let load_addr = base + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            data.len(),
        );
    }

    (COM_SEGMENT, COM_OFFSET, COM_SEGMENT, COM_SP)
}
