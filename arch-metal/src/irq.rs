//! Programmable Interrupt Controller (8259 PIC) and IRQ handling

use lib::pipe::Pipe;
use crate::x86::{inb, outb};
use arch_abi::Regs;

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

/// Typed IRQ event — the backend-agnostic contract, defined in `arch-abi` and
/// re-exported so `crate::Irq` keeps resolving. The PIC plumbing below
/// constructs and queues these.
pub use arch_abi::Irq;

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
    // This kernel is PIC-only, so make sure the 8259's INTR reaches the CPU.
    // In x2APIC mode keep the firmware-selected mode and use its MSR interface
    // to establish virtual-wire routing. Tearing x2APIC down here is fragile
    // on real firmware and unnecessary. The xAPIC path still disables the
    // LAPIC because its MMIO page is not mapped this early.
    const IA32_APIC_BASE: u32 = 0x1B;
    const APIC_ENABLE: u64 = 1 << 11;
    const X2APIC_ENABLE: u64 = 1 << 10;
    const X2APIC_SVR: u32 = 0x80F;
    const X2APIC_LVT_LINT0: u32 = 0x835;
    const APIC_SOFTWARE_ENABLE: u64 = 1 << 8;
    const APIC_DELIVERY_EXTINT: u64 = 7 << 8;

    lib::println!("IRQ: APIC routing");
    let apic_base = crate::x86::rdmsr(IA32_APIC_BASE);
    let modern_x2apic =
        apic_base & (APIC_ENABLE | X2APIC_ENABLE) == (APIC_ENABLE | X2APIC_ENABLE);
    if modern_x2apic {
        // x2APIC registers are MSR 0x800 + (xAPIC MMIO offset >> 4).
        // Enable the local APIC in SVR before unmasking LINT0; with software
        // enable clear, hardware forces all LVT entries masked.
        let svr = crate::x86::rdmsr(X2APIC_SVR);
        unsafe {
            crate::x86::wrmsr(X2APIC_SVR, (svr & 0x3FF) | APIC_SOFTWARE_ENABLE);
            crate::x86::wrmsr(X2APIC_LVT_LINT0, APIC_DELIVERY_EXTINT);
        }
    } else if apic_base & APIC_ENABLE != 0 {
        unsafe { crate::x86::wrmsr(IA32_APIC_BASE, apic_base & !APIC_ENABLE) };
    }

    lib::println!("IRQ: PIC");
    remap_pic();
    lib::println!("IRQ: PIT");
    init_pit(1000); // 1000 Hz timer
    unmask_irq(0);  // timer

    // x2APIC firmware identifies the modern UEFI machines targeted here.
    // Their keyboard/touchpad are USB or I2C devices, and direct accesses to
    // legacy 8042 ports may enter firmware/SMM emulation or reset the machine.
    // Leave all legacy input IRQs masked until proper xHCI/I2C drivers exist.
    if modern_x2apic {
        lib::println!("IRQ: legacy input skipped");
        return;
    }

    // Drain any byte left in the 8042 output buffer by BIOS or a key pressed
    // before our handler is in place. Must happen BEFORE init_mouse: that
    // function reads 0x60 expecting the controller config byte, but if a
    // scancode is sitting in OBF it'd read that instead and write it back
    // as cfg — typically clearing bit 0 (KBD IRQ) and setting bit 4 (KBD
    // clock disable), silently killing the keyboard for the rest of the
    // boot. Also, the 8042 only edges IRQ1 when OBF transitions 0→1, so a
    // stuck OBF locks out subsequent keypresses regardless.
    // Bounded for the same no-i8042 reason as ps2_wait_in: port 0x64 reading
    // 0xFF keeps OBF set forever and this drain would hang the boot.
    lib::println!("IRQ: keyboard");
    for _ in 0..1_000 {
        if inb(0x64) & 1 == 0 {
            break;
        }
        let _ = inb(0x60);
    }
    unmask_irq(1);  // keyboard
    lib::println!("IRQ: mouse probe");
    if init_mouse() {
        lib::println!("IRQ: mouse ready");

        // The emulated legacy machine that supplies a PS/2 mouse may also
        // supply an ISA Sound Blaster on IRQ 5 or 7. Keep these masked on
        // modern machines where the legacy-controller probe failed.
        unmask_irq(5);
        unmask_irq(7);
    } else {
        lib::println!("IRQ: mouse unavailable");
    }
}

// ============================================================================
// PS/2 mouse (8042 controller AUX port, IRQ 12)
// ============================================================================

/// Wait until the 8042 input buffer is empty so we can write a command/data.
/// BOUNDED: a machine with no i8042 (USB-only laptop keyboards) reads 0xFF
/// from port 0x64 — busy bits permanently set — and an unbounded spin hangs
/// the whole boot at a black screen. Give up after ~100k polls.
fn ps2_wait_in() -> bool {
    for _ in 0..100_000 {
        if inb(0x64) & 0x02 == 0 {
            return true;
        }
    }
    false
}

/// Wait until the 8042 output buffer has data ready (bounded, see above).
fn ps2_wait_out() -> bool {
    for _ in 0..100_000 {
        if inb(0x64) & 0x01 != 0 {
            return true;
        }
    }
    false
}

/// Initialize PS/2 mouse: enable AUX port, turn on AUX IRQ in the controller
/// config, kick the mouse into streaming mode (one 3-byte packet per motion
/// or button event), and unmask IRQ 12.
fn init_mouse() -> bool {
    // A machine without an 8042 commonly returns all ones for the unmapped
    // status port. Do not turn that into a fabricated controller config and
    // continue sending commands through firmware/SMM I/O emulation.
    if inb(0x64) == 0xFF {
        return false;
    }

    // Enable AUX (mouse) port on the 8042.
    if !ps2_wait_in() {
        return false;
    }
    outb(0x64, 0xA8);

    // Read controller config byte (cmd 0x20).
    if !ps2_wait_in() {
        return false;
    }
    outb(0x64, 0x20);
    if !ps2_wait_out() {
        return false;
    }
    let mut cfg = inb(0x60);
    if cfg == 0xFF {
        return false;
    }
    // bit 1 = AUX IRQ enable; bit 5 = AUX clock disable (must be 0 for AUX).
    cfg = (cfg | 0x02) & !0x20;
    // Write modified config back (cmd 0x60).
    if !ps2_wait_in() {
        return false;
    }
    outb(0x64, 0x60);
    if !ps2_wait_in() {
        return false;
    }
    outb(0x60, cfg);

    // Tell mouse to stream packets (mouse cmd 0xF4, sent via 0xD4 prefix).
    if !ps2_wait_in() {
        return false;
    }
    outb(0x64, 0xD4);
    if !ps2_wait_in() {
        return false;
    }
    outb(0x60, 0xF4);
    if !ps2_wait_out() || inb(0x60) != 0xFA {
        return false;
    }

    unmask_irq(12);
    true
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

    // Read hardware data and push typed event. Device-specific IRQs that are
    // not acknowledged here remain masked until the guest-visible device ack
    // path re-arms the line.
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
        _ => Some(Irq::Hw(irq)),
    };

    if let Some(e) = event {
        unsafe { (*(&raw mut QUEUE)).push(e); }
    }

    // Re-unmask only lines whose device was acked inline above. Generic
    // `Hw` lines are still asserted by their device, so leaving them masked
    // prevents a host-side storm until the guest-visible ack path re-arms.
    let inline_acked = matches!(irq, 0 | 1 | 12);
    if inline_acked {
        outb(data_port, mask);
    }
}

/// Re-arm an IRQ line previously left masked by `handle_irq` (a deferred-
/// ack `Irq::Hw` line). Called from the kernel once the guest has acked
/// the device so the next interrupt can be delivered.
pub fn rearm_irq(irq: u8) {
    unmask_irq(irq);
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
