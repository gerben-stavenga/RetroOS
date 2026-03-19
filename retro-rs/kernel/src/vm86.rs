//! VM86 mode support for DOS .COM program execution
//!
//! Provides:
//! - VM86 monitor (handles GP faults from sensitive instructions)
//! - DOS INT 21h emulation (basic character/string I/O, exit)
//! - Virtual hardware (PIC, keyboard) for per-thread device emulation
//! - Signal delivery (hardware IRQs reflected through BIOS IVT)
//! - .COM file loader
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
}

// ============================================================================
// Virtual I/O port emulation
// ============================================================================

/// Emulate IN from a port. VGA ports never reach here (allowed via IOPB).
fn emulate_inb(port: u16) -> u8 {
    match port {
        // Master PIC command (read ISR)
        0x20 => thread::current().map_or(0, |t| t.vpic.isr),
        // Master PIC data (read IMR)
        0x21 => thread::current().map_or(0xFF, |t| t.vpic.imr),
        // Keyboard data port
        0x60 => thread::current().map_or(0, |t| t.vkbd.pop()),
        // Keyboard status port (bit 0 = output buffer full)
        0x64 => thread::current().map_or(0, |t| if t.vkbd.has_data() { 1 } else { 0 }),
        _ => {
            println!("\x1b[91mVM86: illegal IN from port {:#06x}\x1b[0m", port);
            thread::exit_thread(-11);
        }
    }
}

/// Emulate OUT to a port. VGA ports never reach here (allowed via IOPB).
fn emulate_outb(port: u16, val: u8) {
    match port {
        // Master PIC command
        0x20 => {
            if val == 0x20 {
                // Non-specific EOI
                if let Some(t) = thread::current() { t.vpic.eoi(); }
            }
        }
        // Master PIC data (write IMR)
        0x21 => {
            if let Some(t) = thread::current() { t.vpic.imr = val; }
        }
        // Slave PIC command
        0xA0 => {
            // EOI to slave — acknowledge, no virtual slave PIC for now
        }
        // Slave PIC data
        0xA1 => {}
        // Keyboard controller command
        0x64 => {}
        _ => {
            println!("\x1b[91mVM86: illegal OUT to port {:#06x}\x1b[0m", port);
            thread::exit_thread(-11);
        }
    }
}

// ============================================================================
// Signal delivery — reflect hardware IRQs to VM86 threads via IVT
// ============================================================================

/// Deliver all pending signals to a VM86 thread by pushing FLAGS/CS/IP
/// onto its stack and redirecting CS:IP to the IVT handler.
/// Each delivered signal nests: the innermost runs first, IRET unwinds.
pub fn deliver_pending_signals(thread: &mut thread::Thread) {
    while thread.pending_signals != 0 {
        let irq = thread.pending_signals.trailing_zeros();
        thread.pending_signals &= !(1 << irq);
        thread.vpic.set_in_service(irq as u8);
        let int_num = (irq + 8) as u8; // IRQ 0 = INT 8, IRQ 1 = INT 9, etc.
        reflect_interrupt(&mut thread.cpu_state, int_num);
    }
}

/// Deliver pending signals using a live Regs on the interrupt stack.
/// Called from isr_handler before returning to VM86 (inline return path).
pub fn deliver_pending_signals_inline(regs: &mut Regs) {
    if let Some(thread) = thread::current() {
        while thread.pending_signals != 0 {
            let irq = thread.pending_signals.trailing_zeros();
            thread.pending_signals &= !(1 << irq);
            thread.vpic.set_in_service(irq as u8);
            let int_num = (irq + 8) as u8;
            reflect_interrupt(regs, int_num);
        }
    }
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
        // INSB (0x6C) — IN byte from port DX to ES:DI, advance DI
        0x6C => {
            let port = regs.rdx as u16;
            let val = emulate_inb(port);
            write_u16(regs.es as u32, regs.rdi as u32, val as u16);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(1); // DF=1
            } else {
                regs.rdi = regs.rdi.wrapping_add(1);
            }
        }
        // OUTSB (0x6E) — OUT byte from DS:SI to port DX, advance SI
        0x6E => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32) as u8;
            emulate_outb(port, val);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(1);
            } else {
                regs.rsi = regs.rsi.wrapping_add(1);
            }
        }
        // IN AL, imm8 (0xE4)
        0xE4 => {
            let port = fetch_byte(regs) as u16;
            regs.rax = (regs.rax & !0xFF) | emulate_inb(port) as u64;
        }
        // IN AX, imm8 (0xE5)
        0xE5 => {
            let port = fetch_byte(regs) as u16;
            regs.rax = (regs.rax & !0xFFFF) | emulate_inb(port) as u64;
        }
        // OUT imm8, AL (0xE6)
        0xE6 => {
            let port = fetch_byte(regs) as u16;
            emulate_outb(port, regs.rax as u8);
        }
        // OUT imm8, AX (0xE7)
        0xE7 => {
            let port = fetch_byte(regs) as u16;
            emulate_outb(port, regs.rax as u8);
        }
        // IN AL, DX (0xEC)
        0xEC => {
            let port = regs.rdx as u16;
            regs.rax = (regs.rax & !0xFF) | emulate_inb(port) as u64;
        }
        // IN AX, DX (0xED)
        0xED => {
            let port = regs.rdx as u16;
            regs.rax = (regs.rax & !0xFFFF) | emulate_inb(port) as u64;
        }
        // OUT DX, AL (0xEE)
        0xEE => {
            let port = regs.rdx as u16;
            emulate_outb(port, regs.rax as u8);
        }
        // OUT DX, AX (0xEF)
        0xEF => {
            let port = regs.rdx as u16;
            emulate_outb(port, regs.rax as u8);
        }
        // HLT (0xF4) — save state and yield to another thread
        0xF4 => {
            if let Some(current) = thread::current() {
                thread::save_state(current, regs);
                current.state = thread::ThreadState::Ready;
                thread::schedule();
            }
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
