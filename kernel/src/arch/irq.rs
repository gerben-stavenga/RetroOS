//! Programmable Interrupt Controller (8259 PIC) and IRQ handling

use crate::pipe::Pipe;
use crate::arch::x86::{inb, outb};
use crate::Regs;

/// PIC ports
const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

/// End of Interrupt command
const EOI: u8 = 0x20;

/// IRQ offset in IDT (IRQ0 = interrupt 32)
pub const IRQ_OFFSET: u8 = 32;

// ============================================================================
// IRQ event queue
// ============================================================================

/// Typed IRQ event. Each hardware IRQ captures its data and pushes one of these.
#[derive(Clone, Copy)]
pub enum Irq {
    Tick,
    Key(u8), // raw PS/2 scancode (press and release)
}

impl Irq {
    /// Hardware IRQ number for VM86 signal delivery
    pub fn irq_num(&self) -> u8 {
        match self {
            Irq::Tick => 0,
            Irq::Key(_) => 1,
        }
    }
}

/// Global IRQ event queue for discrete events (keyboard).
/// Timer ticks use a separate counter to avoid flooding and evicting keys.
static mut QUEUE: Pipe<Irq, 256> = Pipe::new(Irq::Tick);

/// Timer tick counter (incremented immediately for get_ticks/sleep_ticks)
static mut TIMER_TICKS: u64 = 0;

/// Pending timer ticks for VM86 delivery (separate from queue to avoid evicting keys)
static mut PENDING_TICKS: u32 = 0;

/// Drain all queued IRQ events, calling f for each.
pub fn drain(f: impl FnMut(Irq)) {
    unsafe { (*(&raw mut QUEUE)).drain(f); }
}

/// Take pending tick count (returns count and resets to 0).
pub fn take_pending_ticks() -> u32 {
    unsafe {
        let t = core::ptr::read_volatile(&raw const PENDING_TICKS);
        core::ptr::write_volatile(&raw mut PENDING_TICKS, 0);
        t
    }
}

/// Discard all queued IRQ events.
pub fn drain_discard() {
    unsafe {
        (*(&raw mut QUEUE)).clear();
        core::ptr::write_volatile(&raw mut PENDING_TICKS, 0);
    }
}

// ============================================================================
// PIC initialization
// ============================================================================

/// Initialize a PIC chip
fn init_pic(cmd_port: u16, data_port: u16, offset: u8, cascade: u8) {
    // ICW1: Initialize + ICW4 needed
    outb(cmd_port, 0x11);
    // ICW2: Interrupt vector offset
    outb(data_port, offset);
    // ICW3: Cascade identity
    outb(data_port, cascade);
    // ICW4: 8086 mode
    outb(data_port, 0x01);
    // Set PIC to ISR mode (for spurious IRQ detection)
    outb(cmd_port, 0x0B);
    // Mask all interrupts except cascade on master
    let mask = if cmd_port == MASTER_CMD { !cascade } else { 0xFF };
    outb(data_port, mask);
}

/// Remap PIC to use interrupts 32-47 instead of 0-15
pub fn remap_pic() {
    const CASCADE_IRQ: u8 = 2;
    init_pic(MASTER_CMD, MASTER_DATA, IRQ_OFFSET, 1 << CASCADE_IRQ);
    init_pic(SLAVE_CMD, SLAVE_DATA, IRQ_OFFSET + 8, CASCADE_IRQ);
}

/// Initialize PIT (Programmable Interval Timer) for timer interrupts
pub fn init_pit(frequency: u32) {
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_CMD: u16 = 0x43;
    const PIT_FREQUENCY: u32 = 1193182;

    outb(PIT_CMD, 0x36);
    let divisor = if frequency == 0 {
        0
    } else {
        (PIT_FREQUENCY / frequency).clamp(1, 65535) as u16
    };
    outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
    outb(PIT_CHANNEL0, (divisor >> 8) as u8);
}

/// Unmask an IRQ on the PIC
fn unmask_irq(irq: u8) {
    let (port, bit) = if irq < 8 {
        (MASTER_DATA, irq)
    } else {
        (SLAVE_DATA, irq - 8)
    };
    let mask = inb(port);
    outb(port, mask & !(1 << bit));
}

/// Initialize interrupts (PIC, PIT, unmask timer + keyboard)
pub fn init_interrupts() {
    remap_pic();
    init_pit(1000); // 1000 Hz timer
    unmask_irq(0);  // timer
    unmask_irq(1);  // keyboard
}

// ============================================================================
// IRQ dispatch
// ============================================================================

/// F12 debug: dump interrupted thread's CS:IP, BIOS timer, and code bytes
fn dump_thread_state(regs: &Regs) {
    unsafe {
        let tid = if crate::thread::is_initialized() { crate::thread::current().tid } else { -1 };
        let vm86 = regs.flags32() & (1 << 17) != 0;
        if vm86 {
            let vif = regs.flags32() & (1 << 9) != 0; // IF = virtual interrupt flag after arch swap
            let lin = (regs.cs32() << 4) + regs.ip32();
            let b = core::slice::from_raw_parts(lin as *const u8, 16);
            let ticks = *(0x46Cu32 as *const u32);
            let isr = if crate::thread::is_initialized() { crate::thread::current().vm86.vpic.isr } else { 0 };
            crate::dbg_println!("[DBG] tid={} VM86 {:04X}:{:04X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} SS:SP={:04X}:{:04X} flags={:04X} VIF={} ISR={:02X} ticks={} code={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                tid, regs.code_seg(), regs.ip32(),
                regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.ds as u16, regs.stack_seg(), regs.sp32(),
                regs.flags32() as u16, vif, isr, ticks,
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            // Dump VGA text buffer (80x25, char+attr interleaved at 0xB8000)
            let vga = core::slice::from_raw_parts(0xB8000 as *const u8, 4000);
            for row in 0..25 {
                let mut line = [b'.'; 80];
                for col in 0..80 {
                    let ch = vga[(row * 80 + col) * 2];
                    line[col] = if ch >= 0x20 && ch < 0x7F { ch } else { b'.' };
                }
                crate::dbg_println!("[VGA {:02}] {}", row,
                    core::str::from_utf8(&line).unwrap_or("???"));
            }
        } else {
            crate::dbg_println!("[DBG] tid={} PM EIP={:#010x}", tid, regs.ip32());
        }
    }
}

/// Handle an IRQ: PIC ACK, read hardware data, push typed event to queue.
pub fn handle_irq(regs: &mut Regs) {
    let irq = (regs.int_num - IRQ_OFFSET as u64) as u8;

    let (pic_port, irq_bit) = if irq < 8 {
        (MASTER_CMD, 1u8 << irq)
    } else {
        outb(MASTER_CMD, EOI);
        (SLAVE_CMD, 1u8 << (irq - 8))
    };

    // Check for spurious IRQ (IRQ 7 or 15)
    if irq_bit == 0x80 {
        let isr = inb(pic_port);
        if (isr & irq_bit) == 0 {
            return;
        }
    }

    // Mask, EOI, handle, unmask
    let data_port = pic_port + 1;
    let mask = inb(data_port);
    outb(data_port, mask | irq_bit);
    outb(pic_port, EOI);

    // Read hardware data and push typed event
    let event = match irq {
        0 => {
            unsafe {
                let t = core::ptr::read_volatile(&raw const TIMER_TICKS);
                core::ptr::write_volatile(&raw mut TIMER_TICKS, t + 1);
                let p = core::ptr::read_volatile(&raw const PENDING_TICKS);
                core::ptr::write_volatile(&raw mut PENDING_TICKS, p + 1);
            }
            None // ticks use PENDING_TICKS counter, not the queue
        }
        1 => {
            let sc = inb(0x60);
            if sc == 0x58 {
                // F12: dump current thread's CS:IP for debugging hung VM86
                dump_thread_state(regs);
                None
            } else {
                Some(Irq::Key(sc))
            }
        }
        _ => None,
    };

    if let Some(e) = event {
        unsafe { (*(&raw mut QUEUE)).push(e); }
    }

    outb(data_port, mask);
}

/// Get timer ticks
pub fn get_ticks() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const TIMER_TICKS) }
}

/// Sleep for N timer ticks (blocks with interrupts enabled)
pub fn sleep_ticks(ticks: u64) {
    let target = get_ticks() + ticks;
    while get_ticks() < target {
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)); }
    }
}
