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
    /// One PS/2 mouse motion/button packet decoded into deltas + button mask.
    /// `dx` / `dy` are signed motion since the previous packet (PS/2 reports
    /// +Y as up; we flip so `+dy` means screen-down). `buttons`: bit 0 left,
    /// bit 1 right, bit 2 middle. Consumer is responsible for accumulating
    /// position and clamping to a screen range.
    Mouse { dx: i16, dy: i16, buttons: u8 },
}

impl Irq {
    /// Hardware IRQ number for VM86 signal delivery
    pub fn irq_num(&self) -> u8 {
        match self {
            Irq::Tick => 0,
            Irq::Key(_) => 1,
            Irq::Mouse { .. } => 12,
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

/// PS/2 mouse 3-byte packet assembly state. Packets stream in over IRQ 12;
/// we accumulate three bytes, decode to dx/dy/buttons, push one Irq::Mouse,
/// and reset.
static mut MOUSE_PACKET: [u8; 3] = [0; 3];
static mut MOUSE_PACKET_IDX: u8 = 0;

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

/// Initialize interrupts (PIC, PIT, unmask timer + keyboard + mouse)
pub fn init_interrupts() {
    remap_pic();
    init_pit(1000); // 1000 Hz timer
    unmask_irq(0);  // timer
    unmask_irq(1);  // keyboard
    init_mouse();
    // Drain any byte left in the 8042 output buffer by the BIOS or by a key
    // pressed before we unmasked IRQ1. The 8042 only edges IRQ1 when OBF
    // transitions 0→1, so a stuck OBF locks out all subsequent keypresses.
    while inb(0x64) & 1 != 0 {
        let _ = inb(0x60);
    }
}

// ============================================================================
// PS/2 mouse (8042 controller AUX port, IRQ 12)
// ============================================================================

/// Wait until the 8042 input buffer is empty so we can write a command/data.
fn ps2_wait_in() {
    while inb(0x64) & 0x02 != 0 {}
}

/// Wait until the 8042 output buffer has data ready.
fn ps2_wait_out() {
    while inb(0x64) & 0x01 == 0 {}
}

/// Initialize PS/2 mouse: enable AUX port, turn on AUX IRQ in the controller
/// config, kick the mouse into streaming mode (one 3-byte packet per motion
/// or button event), and unmask IRQ 12.
fn init_mouse() {
    // Enable AUX (mouse) port on the 8042.
    ps2_wait_in();
    outb(0x64, 0xA8);

    // Read controller config byte (cmd 0x20).
    ps2_wait_in();
    outb(0x64, 0x20);
    ps2_wait_out();
    let mut cfg = inb(0x60);
    // bit 1 = AUX IRQ enable; bit 5 = AUX clock disable (must be 0 for AUX).
    cfg = (cfg | 0x02) & !0x20;
    // Write modified config back (cmd 0x60).
    ps2_wait_in();
    outb(0x64, 0x60);
    ps2_wait_in();
    outb(0x60, cfg);

    // Tell mouse to stream packets (mouse cmd 0xF4, sent via 0xD4 prefix).
    ps2_wait_in();
    outb(0x64, 0xD4);
    ps2_wait_in();
    outb(0x60, 0xF4);
    ps2_wait_out();
    let _ack = inb(0x60); // 0xFA expected; not actionable

    unmask_irq(12);
}

// ============================================================================
// IRQ dispatch
// ============================================================================

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
        1 => Some(Irq::Key(inb(0x60))),
        12 => mouse_packet_byte(inb(0x60)),
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

/// Feed one byte from the 8042 AUX data port into the 3-byte PS/2 packet
/// state machine. Returns `Some(Irq::Mouse{..})` when the packet completes,
/// `None` while still assembling. Drops byte 0 candidates that don't have
/// the always-1 sync bit (bit 3), so a desynced stream can recover.
fn mouse_packet_byte(byte: u8) -> Option<Irq> {
    unsafe {
        let idx = core::ptr::read_volatile(&raw const MOUSE_PACKET_IDX);
        if idx == 0 && byte & 0x08 == 0 {
            return None;
        }
        MOUSE_PACKET[idx as usize] = byte;
        if idx == 2 {
            let b0 = MOUSE_PACKET[0];
            let dx = MOUSE_PACKET[1] as i16 - if b0 & 0x10 != 0 { 0x100 } else { 0 };
            // PS/2 reports +Y as up; flip so +dy means screen-down.
            let dy = -(MOUSE_PACKET[2] as i16 - if b0 & 0x20 != 0 { 0x100 } else { 0 });
            core::ptr::write_volatile(&raw mut MOUSE_PACKET_IDX, 0);
            Some(Irq::Mouse { dx, dy, buttons: b0 & 0x07 })
        } else {
            core::ptr::write_volatile(&raw mut MOUSE_PACKET_IDX, idx + 1);
            None
        }
    }
}
