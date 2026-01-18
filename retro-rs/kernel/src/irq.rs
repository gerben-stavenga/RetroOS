//! Programmable Interrupt Controller (8259 PIC) and IRQ handling

use crate::println;
use crate::x86::{inb, outb};
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

/// IRQ handlers (16 IRQs: 0-7 master, 8-15 slave)
static mut IRQ_HANDLERS: [Option<fn()>; 16] = [None; 16];

/// Timer tick counter
static mut TIMER_TICKS: u64 = 0;

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
    const CASCADE_IRQ: u8 = 2; // Slave connected to IRQ2

    // Initialize master PIC (IRQs 0-7 -> interrupts 32-39)
    init_pic(MASTER_CMD, MASTER_DATA, IRQ_OFFSET, 1 << CASCADE_IRQ);

    // Initialize slave PIC (IRQs 8-15 -> interrupts 40-47)
    init_pic(SLAVE_CMD, SLAVE_DATA, IRQ_OFFSET + 8, CASCADE_IRQ);
}

/// Initialize PIT (Programmable Interval Timer) for timer interrupts
pub fn init_pit(frequency: u32) {
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_CMD: u16 = 0x43;
    const PIT_FREQUENCY: u32 = 1193182;

    // Mode 3 (square wave), channel 0, lo/hi byte access
    outb(PIT_CMD, 0x36);

    // Calculate and set divisor
    let divisor = if frequency == 0 {
        0 // 0 means 65536
    } else {
        (PIT_FREQUENCY / frequency).clamp(1, 65535) as u16
    };

    outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
    outb(PIT_CHANNEL0, (divisor >> 8) as u8);
}

/// Register an IRQ handler and unmask the IRQ
pub fn register_irq(irq: u8, handler: fn()) -> bool {
    if irq >= 16 {
        return false;
    }

    let (port, bit) = if irq < 8 {
        (MASTER_DATA, irq)
    } else {
        (SLAVE_DATA, irq - 8)
    };

    let mask = inb(port);
    let irq_bit = 1 << bit;

    // Check if already enabled
    if (mask & irq_bit) == 0 {
        return false;
    }

    // Unmask IRQ
    outb(port, mask & !irq_bit);

    unsafe {
        IRQ_HANDLERS[irq as usize] = Some(handler);
    }

    true
}

/// Timer interrupt handler
fn timer_handler() {
    unsafe {
        TIMER_TICKS += 1;
    }
    // TODO: Call scheduler
}

/// Keyboard interrupt handler
fn keyboard_handler() {
    let scancode = inb(0x60);
    // TODO: Process key
    println!("Key: {:#04x}", scancode);
}

/// Initialize interrupts (PIC, PIT, register handlers)
pub fn init_interrupts() {
    remap_pic();
    init_pit(1000); // 1000 Hz timer

    register_irq(0, timer_handler);
    register_irq(1, keyboard_handler);
}

/// Handle an IRQ (called from isr_handler for interrupts 32-47)
pub fn handle_irq(regs: &mut Regs) {
    let irq = (regs.int_num - IRQ_OFFSET as u32) as u8;

    let (pic_port, irq_bit) = if irq < 8 {
        (MASTER_CMD, 1u8 << irq)
    } else {
        // Slave IRQ - send EOI to master first (for cascade)
        outb(MASTER_CMD, EOI);
        (SLAVE_CMD, 1u8 << (irq - 8))
    };

    // Check for spurious IRQ (IRQ 7 or 15)
    if irq_bit == 0x80 {
        let isr = inb(pic_port);
        if (isr & irq_bit) == 0 {
            return; // Spurious, ignore
        }
    }

    // Mask this IRQ temporarily
    let data_port = pic_port + 1;
    let mask = inb(data_port);
    outb(data_port, mask | irq_bit);

    // Send EOI
    outb(pic_port, EOI);

    // Call handler (with interrupts enabled)
    unsafe {
        if let Some(handler) = IRQ_HANDLERS[irq as usize] {
            crate::x86::sti();
            handler();
            crate::x86::cli();
        }
    }

    // Unmask IRQ
    outb(data_port, mask);
}

/// Get timer ticks
pub fn get_ticks() -> u64 {
    unsafe { TIMER_TICKS }
}
