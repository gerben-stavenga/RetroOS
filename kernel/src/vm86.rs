//! VM86 mode support for DOS program execution (.COM and .EXE)
//!
//! Provides:
//! - VM86 monitor (handles GP faults from sensitive instructions)
//! - DOS INT 21h emulation (basic character/string I/O, exit)
//! - Virtual hardware (PIC, keyboard) for per-thread device emulation
//! - Signal delivery (hardware IRQs reflected through BIOS IVT)
//! - .COM and MZ .EXE file loaders
//!
//! The BIOS ROM at 0xF0000-0xFFFFF and the BIOS IVT at 0x0000-0x03FF are
//! preserved from the original hardware state (via COW page 0). BIOS handlers
//! work transparently because their I/O instructions trap through the TSS IOPB
//! to our virtual devices.

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



// ============================================================================
// Virtual hardware — per-thread PIC and keyboard emulation
// ============================================================================

/// Virtual 8259 PIC (one per thread, master only)
pub struct VirtualPic {
    pub isr: u8,  // In-Service Register
    pub imr: u8,  // Interrupt Mask Register
}

impl VirtualPic {
    pub const fn new() -> Self {
        Self { isr: 0, imr: 0 }
    }

    /// Non-specific EOI: clear highest-priority (lowest-numbered) in-service bit
    pub fn eoi(&mut self) {
        if self.isr != 0 {
            self.isr &= self.isr - 1; // clear lowest set bit
        }
    }

    /// Mark an IRQ as in-service (called when delivering a signal)
    pub fn set_in_service(&mut self, irq: u8) {
        self.isr |= 1 << irq;
    }
}

const KBD_BUF_SIZE: usize = 32;

/// Virtual keyboard controller (scancode buffer)
pub struct VirtualKeyboard {
    buffer: [u8; KBD_BUF_SIZE],
    head: usize,
    tail: usize,
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self { buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0 }
    }

    /// Buffer a scancode from the real keyboard IRQ handler
    pub fn push(&mut self, scancode: u8) {
        let next = (self.tail + 1) % KBD_BUF_SIZE;
        if next != self.head {
            self.buffer[self.tail] = scancode;
            self.tail = next;
        }
    }

    /// Read next scancode (port 0x60 emulation)
    pub fn pop(&mut self) -> u8 {
        if self.head == self.tail {
            return 0;
        }
        let sc = self.buffer[self.head];
        self.head = (self.head + 1) % KBD_BUF_SIZE;
        sc
    }

    /// Check if data is available (port 0x64 bit 0)
    pub fn has_data(&self) -> bool {
        self.head != self.tail
    }

    /// Pop next key-down scancode, skipping releases (for INT 16h AH=0)
    pub fn pop_key(&mut self) -> Option<u8> {
        while self.head != self.tail {
            let sc = self.buffer[self.head];
            self.head = (self.head + 1) % KBD_BUF_SIZE;
            if sc & 0x80 == 0 {
                return Some(sc);
            }
        }
        None
    }

    /// Peek next key-down scancode without consuming (for INT 16h AH=1)
    pub fn peek_key(&self) -> Option<u8> {
        let mut i = self.head;
        while i != self.tail {
            let sc = self.buffer[i];
            if sc & 0x80 == 0 {
                return Some(sc);
            }
            i = (i + 1) % KBD_BUF_SIZE;
        }
        None
    }
}

// ============================================================================
// Virtual I/O port emulation
// ============================================================================

/// Emulate IN from a port. VGA ports never reach here (allowed via IOPB).
/// Returns Ok(byte) or Err(switch_target) if the thread must be killed.
fn emulate_inb(port: u16) -> Result<u8, Option<usize>> {
    match port {
        // Master PIC command (read ISR)
        0x20 => Ok(thread::current().vpic.isr),
        // Master PIC data (read IMR)
        0x21 => Ok(thread::current().vpic.imr),
        // Keyboard data port
        0x60 => Ok(thread::current().vkbd.pop()),
        // Keyboard status port (bit 0 = output buffer full)
        0x64 => Ok(if thread::current().vkbd.has_data() { 1 } else { 0 }),
        // Unknown ports: return 0xFF (unpopulated bus)
        _ => Ok(0xFF)
    }
}

/// Emulate OUT to a port. VGA ports never reach here (allowed via IOPB).
/// Returns Ok(()) or Err(switch_target) if the thread must be killed.
fn emulate_outb(port: u16, val: u8) -> Result<(), Option<usize>> {
    match port {
        // Master PIC command
        0x20 => {
            if val == 0x20 {
                // Non-specific EOI
                thread::current().vpic.eoi();
            }
            Ok(())
        }
        // Master PIC data (write IMR)
        0x21 => {
            thread::current().vpic.imr = val;
            Ok(())
        }
        // Slave PIC command
        0xA0 => Ok(()),
        // Slave PIC data
        0xA1 => Ok(()),
        // Keyboard controller command
        0x64 => Ok(()),
        // Unknown ports: silently ignore (BIOS probes various ports during mode switches)
        _ => Ok(())
    }
}

// ============================================================================
// Signal delivery — reflect hardware IRQs to VM86 threads via IVT
// ============================================================================

/// Deliver an IRQ event to a VM86 thread: buffer data, reflect through IVT.
pub fn deliver_irq(thread: &mut thread::Thread, regs: &mut Regs, event: crate::irq::Irq) {
    use crate::irq::Irq;
    if let Irq::Key(sc) = event { thread.vkbd.push(sc); }
    let irq = event.irq_num();
    thread.vpic.set_in_service(irq);
    let int_num = irq + 8; // IRQ 0 = INT 8, IRQ 1 = INT 9, etc.
    reflect_interrupt(regs, int_num);
}

/// Reflect an interrupt through the IVT: push FLAGS/CS/IP, set CS:IP to handler.
fn reflect_interrupt(regs: &mut Regs, int_num: u8) {
    unsafe {
        vm86_push(regs, regs.frame.f32.eflags as u16);
        vm86_push(regs, regs.frame.f32.cs as u16);
        vm86_push(regs, regs.frame.f32.eip as u16);

        regs.frame.f32.eip = read_u16(0, (int_num as u32) * 4) as u32;
        regs.frame.f32.cs = read_u16(0, (int_num as u32) * 4 + 2) as u32;
    }
}

// ============================================================================
// VM86 monitor — handles GP faults for sensitive instructions
//
// VGA ports (0x3C0-0x3DF) are allowed via the TSS IOPB and never reach here.
// All other I/O ports are denied by the IOPB, so IN/OUT on them traps here.
// We block non-VGA I/O: return 0xFF for IN, no-op for OUT.
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

/// Read a u16 from a real-mode seg:off address (unaligned-safe, null-safe)
fn read_u16(seg: u32, off: u32) -> u16 {
    let linear = (seg << 4) + off;
    let val: u16;
    unsafe {
        core::arch::asm!(
            "movzx {val:e}, word ptr [{addr}]",
            addr = in(reg) linear,
            val = out(reg) val,
            options(readonly, nostack),
        );
    }
    val
}

/// Write a u16 to a real-mode seg:off address (unaligned-safe, null-safe)
fn write_u16(seg: u32, off: u32, val: u16) {
    let linear = (seg << 4) + off;
    unsafe {
        core::arch::asm!(
            "mov word ptr [{addr}], {val:x}",
            addr = in(reg) linear,
            val = in(reg) val,
            options(nostack),
        );
    }
}

/// Push a u16 onto the VM86 stack (SS:SP)
fn vm86_push(regs: &mut Regs, val: u16) {
    unsafe {
        let sp = (regs.frame.f32.esp as u16).wrapping_sub(2);
        regs.frame.f32.esp = (regs.frame.f32.esp & 0xFFFF0000) | sp as u32;
        write_u16(regs.frame.f32.ss, sp as u32, val);
    }
}

/// Pop a u16 from the VM86 stack (SS:SP)
fn vm86_pop(regs: &mut Regs) -> u16 {
    unsafe {
        let sp = regs.frame.f32.esp as u16;
        let val = read_u16(regs.frame.f32.ss, sp as u32);
        regs.frame.f32.esp = (regs.frame.f32.esp & 0xFFFF0000) | sp.wrapping_add(2) as u32;
        val
    }
}

/// VM86 monitor — called from GP fault handler when EFLAGS.VM=1.
/// Emulates sensitive instructions that cause GP faults in VM86 mode.
/// Returns Some(idx) if a context switch is needed.
pub fn vm86_monitor(regs: &mut Regs) -> Option<usize> {
    let opcode = fetch_byte(regs);

    match opcode {
        // INT n (0xCD nn)
        0xCD => {
            let int_num = fetch_byte(regs);
            handle_vm86_int(regs, int_num)
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
            thread::current().vm86_vif = (flags & (1 << 9)) != 0;
            None
        }
        // CLI (0xFA)
        0xFA => {
            thread::current().vm86_vif = false;
            None
        }
        // STI (0xFB)
        0xFB => {
            thread::current().vm86_vif = true;
            None
        }
        // PUSHF (0x9C) — push FLAGS with virtual IF
        0x9C => {
            let vif = thread::current().vm86_vif;
            let mut flags = unsafe { regs.frame.f32.eflags as u16 };
            if vif { flags |= 1 << 9; } else { flags &= !(1 << 9); }
            vm86_push(regs, flags);
            None
        }
        // POPF (0x9D) — pop FLAGS, update virtual IF
        0x9D => {
            let flags = vm86_pop(regs);
            thread::current().vm86_vif = (flags & (1 << 9)) != 0;
            unsafe {
                let preserved = regs.frame.f32.eflags & 0x0002_0000; // VM
                regs.frame.f32.eflags = (flags as u32 & !0x0002_0000) | preserved | (1 << 9);
            }
            None
        }
        // INSB (0x6C) — IN byte from port DX to ES:DI, advance DI
        0x6C => {
            let port = regs.rdx as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            write_u16(regs.es as u32, regs.rdi as u32, val as u16);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(1); // DF=1
            } else {
                regs.rdi = regs.rdi.wrapping_add(1);
            }
            None
        }
        // INSW (0x6D) — IN word from port DX to ES:DI, advance DI
        0x6D => {
            let port = regs.rdx as u16;
            let lo = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            let hi = match emulate_inb(port + 1) { Ok(v) => v, Err(sw) => return sw };
            let val = (hi as u16) << 8 | lo as u16;
            write_u16(regs.es as u32, regs.rdi as u32, val);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(2);
            } else {
                regs.rdi = regs.rdi.wrapping_add(2);
            }
            None
        }
        // OUTSB (0x6E) — OUT byte from DS:SI to port DX, advance SI
        0x6E => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32) as u8;
            if let Err(sw) = emulate_outb(port, val) { return sw; }
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(1);
            } else {
                regs.rsi = regs.rsi.wrapping_add(1);
            }
            None
        }
        // OUTSW (0x6F) — OUT word from DS:SI to port DX, advance SI
        0x6F => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32);
            if let Err(sw) = emulate_outb(port, val as u8) { return sw; }
            if let Err(sw) = emulate_outb(port + 1, (val >> 8) as u8) { return sw; }
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(2);
            } else {
                regs.rsi = regs.rsi.wrapping_add(2);
            }
            None
        }
        // IN AL, imm8 (0xE4)
        0xE4 => {
            let port = fetch_byte(regs) as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            regs.rax = (regs.rax & !0xFF) | val as u64;
            None
        }
        // IN AX, imm8 (0xE5)
        0xE5 => {
            let port = fetch_byte(regs) as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            regs.rax = (regs.rax & !0xFFFF) | val as u64;
            None
        }
        // OUT imm8, AL (0xE6)
        0xE6 => {
            let port = fetch_byte(regs) as u16;
            if let Err(sw) = emulate_outb(port, regs.rax as u8) { return sw; }
            None
        }
        // OUT imm8, AX (0xE7)
        0xE7 => {
            let port = fetch_byte(regs) as u16;
            if let Err(sw) = emulate_outb(port, regs.rax as u8) { return sw; }
            None
        }
        // IN AL, DX (0xEC)
        0xEC => {
            let port = regs.rdx as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            regs.rax = (regs.rax & !0xFF) | val as u64;
            None
        }
        // IN AX, DX (0xED)
        0xED => {
            let port = regs.rdx as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(sw) => return sw };
            regs.rax = (regs.rax & !0xFFFF) | val as u64;
            None
        }
        // OUT DX, AL (0xEE)
        0xEE => {
            let port = regs.rdx as u16;
            if let Err(sw) = emulate_outb(port, regs.rax as u8) { return sw; }
            None
        }
        // OUT DX, AX (0xEF)
        0xEF => {
            let port = regs.rdx as u16;
            if let Err(sw) = emulate_outb(port, regs.rax as u8) { return sw; }
            None
        }
        // HLT (0xF4) — save state and yield to another thread
        0xF4 => {
            let current = thread::current();
            thread::save_state(current, regs);
            current.state = thread::ThreadState::Ready;
            thread::schedule()
        }
        _ => {
            println!("\x1b[91mVM86: unhandled opcode {:#04x} at {:04x}:{:04x}\x1b[0m",
                opcode, unsafe { regs.frame.f32.cs }, unsafe { regs.frame.f32.eip } - 1);
            // Kill the VM86 thread
            thread::exit_thread(-11)
        }
    }
}

// ============================================================================
// INT dispatch — intercept DOS/BIOS calls, reflect others via IVT
// ============================================================================

/// Handle INT n from VM86 mode. Returns Some(idx) if a context switch is needed.
fn handle_vm86_int(regs: &mut Regs, int_num: u8) -> Option<usize> {
    match int_num {
        0x20 => {
            // INT 20h — DOS program terminate
            thread::exit_thread(0)
        }
        0x16 => int_16h(regs),
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
            None
        }
    }
}

// ============================================================================
// BIOS INT 16h — Keyboard services
// ============================================================================

fn int_16h(regs: &mut Regs) -> Option<usize> {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=0x00: Wait for keypress, return scancode in AH, ASCII in AL
        0x00 => {
            let t = thread::current();
            match t.vkbd.pop_key() {
                Some(scancode) => {
                    let ascii = crate::keyboard::scancode_to_ascii(scancode);
                    regs.rax = (regs.rax & !0xFFFF) | ((scancode as u64) << 8) | ascii as u64;
                    None
                }
                None => {
                    // No key available — yield and retry (back up IP to re-execute INT 16h)
                    unsafe {
                        regs.frame.f32.eip = regs.frame.f32.eip.wrapping_sub(2);
                    }
                    thread::save_state(t, regs);
                    t.state = thread::ThreadState::Ready;
                    thread::schedule()
                }
            }
        }
        // AH=0x01: Check for keypress (non-blocking), ZF=1 if no key
        0x01 => {
            let t = thread::current();
            if let Some(scancode) = t.vkbd.peek_key() {
                let ascii = crate::keyboard::scancode_to_ascii(scancode);
                regs.rax = (regs.rax & !0xFFFF) | ((scancode as u64) << 8) | ascii as u64;
                // Clear ZF (key available)
                unsafe { regs.frame.f32.eflags &= !(1 << 6); }
            } else {
                // Set ZF (no key)
                unsafe { regs.frame.f32.eflags |= 1 << 6; }
            }
            None
        }
        _ => {
            println!("VM86: unhandled INT 16h AH={:#04x}", ah);
            None
        }
    }
}


// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(regs: &mut Regs) -> Option<usize> {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            vga::vga().putchar(regs.rdx as u8);
            None
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
            None
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            let off = regs.rdx as u16;
            let seg = regs.ds as u16;
            write_u16(0, (int_num as u32) * 4, off);
            write_u16(0, (int_num as u32) * 4 + 2, seg);
            None
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | 2; // C:
            None
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = ((regs.ds as u32) << 4) + regs.rdx as u32;
            thread::current().vm86_dta = dta;
            None
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 3.30
            regs.rax = (regs.rax & !0xFFFF) | 0x1E03; // AL=3 (major), AH=30 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            None
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            let off = read_u16(0, (int_num as u32) * 4);
            let seg = read_u16(0, (int_num as u32) * 4 + 2);
            regs.rbx = off as u64;
            regs.es = seg as u64;
            None
        }
        // AH=0x38: Get country information — return minimal stub
        0x38 => {
            // Just clear carry (success) with zeroed-out info at DS:DX
            let addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, 34);
                // Currency symbol = '$'
                *(addr as *mut u8).add(2) = b'$';
            }
            // Clear carry flag (success)
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=buffer)
        0x47 => {
            // Return root directory "\" (empty string = root)
            let addr = ((regs.ds as u32) << 4) + regs.rsi as u32;
            unsafe { *(addr as *mut u8) = 0; }
            // Clear carry flag (success)
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x3D: Open file (DS:DX=filename, AL=access mode)
        0x3D => {
            // No filesystem — return error (file not found)
            regs.rax = (regs.rax & !0xFFFF) | 2; // error code 2 = file not found
            unsafe { regs.frame.f32.eflags |= 1; } // set carry
            None
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            // No-op, clear carry
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            // Return 0 bytes read (EOF)
            regs.rax = (regs.rax & !0xFFFF);
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => {
            // No files found
            regs.rax = (regs.rax & !0xFFFF) | 18; // error 18 = no more files
            unsafe { regs.frame.f32.eflags |= 1; } // set carry
            None
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            regs.rax = (regs.rax & !0xFFFF) | 18;
            unsafe { regs.frame.f32.eflags |= 1; }
            None
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            let code = regs.rax as u8;
            thread::exit_thread(code as i32)
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = thread::current().vm86_dta;
            regs.rbx = (dta & 0xF) as u64;
            regs.es = (dta >> 4) as u64;
            None
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            // Not enough memory
            regs.rax = (regs.rax & !0xFFFF) | 8; // error 8 = insufficient memory
            regs.rbx = 0; // largest block available = 0
            unsafe { regs.frame.f32.eflags |= 1; }
            None
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            // Pretend success
            unsafe { regs.frame.f32.eflags &= !1; }
            None
        }
        // AH=0x44: IOCTL (various subfunctions)
        0x44 => {
            // Return error for most subfunctions
            regs.rax = (regs.rax & !0xFFFF) | 1; // error 1 = invalid function
            unsafe { regs.frame.f32.eflags |= 1; }
            None
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C)
        0x0E => {
            regs.rax = (regs.rax & !0xFF) | 3; // AL = number of logical drives
            None
        }
        // AH=0x3C: Create file
        0x3C => {
            regs.rax = (regs.rax & !0xFFFF) | 5; // error 5 = access denied
            unsafe { regs.frame.f32.eflags |= 1; }
            None
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            // Handle 1=stdout, 2=stderr
            if handle == 1 || handle == 2 {
                let addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
                for i in 0..count as u32 {
                    let ch = unsafe { *((addr + i) as *const u8) };
                    vga::vga().putchar(ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 5; // access denied
                unsafe { regs.frame.f32.eflags |= 1; }
            }
            None
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            regs.rax = (regs.rax & !0xFFFF) | 6; // error 6 = invalid handle
            unsafe { regs.frame.f32.eflags |= 1; }
            None
        }
        _ => {
            println!("VM86: unhandled INT 21h AH={:#04x}", ah);
            None
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
/// Interrupts we emulate in the monitor (INT 10h, 20h, 21h) are trapped
/// via the TSS interrupt redirection bitmap and never reach the IVT.
pub fn setup_ivt() {
    // Nothing to do — the BIOS IVT is already set up from the COW page 0 copy.
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Write the PSP (Program Segment Prefix) at the given segment.
/// PSP[0..2] = code to restore VGA mode 3 and terminate (INT 20h).
/// When a .COM returns (RET → PSP:0000) or an .EXE calls INT 20h,
/// this restores text mode before exit.
fn write_psp(segment: u16) {
    let base = (segment as u32) << 4;
    unsafe {
        let p = base as *mut u8;
        *p.add(0) = 0xB8;  // MOV AX, 0003h
        *p.add(1) = 0x03;
        *p.add(2) = 0x00;
        *p.add(3) = 0xCD;  // INT 10h
        *p.add(4) = 0x10;
        *p.add(5) = 0xCD;  // INT 20h
        *p.add(6) = 0x20;
    }
}

/// Check if data starts with the MZ signature.
pub fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Load a .COM binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// Layout:
///   Segment COM_SEGMENT (0x1000):
///     0x0000-0x00FF: PSP (Program Segment Prefix)
///     0x0100-...:    .COM binary code
///   Stack at COM_SEGMENT:COM_SP (top of segment)
pub fn load_com(data: &[u8]) -> (u16, u16, u16, u16) {
    write_psp(COM_SEGMENT);

    // Copy .COM data at offset 0x100
    let base = (COM_SEGMENT as u32) << 4;
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
pub fn load_exe(data: &[u8]) -> Option<(u16, u16, u16, u16)> {
    if data.len() < 28 {
        return None;
    }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
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

    // Load segment: PSP is at COM_SEGMENT, load module starts one segment after
    let psp_segment = COM_SEGMENT;
    let load_segment = psp_segment + 0x10; // 256 bytes after PSP base

    write_psp(psp_segment);

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

    Some((cs, init_ip, ss, init_sp))
}
