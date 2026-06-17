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

/// Push a keyboard scancode into the queue from a non-IRQ source — the xHCI
/// USB-HID keyboard `poll()`. Same sink the i8042 IRQ1 handler feeds, so the
/// kernel sees one uniform key-event stream regardless of the source.
pub fn push_key(sc: u8) {
    unsafe { (*(&raw mut QUEUE)).push(Irq::Key(sc)); }
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

// ============================================================================
// LAPIC timer — PIT-independent system tick for modern (PIT-less) hardware
// ============================================================================
//
// Modern UEFI laptops frequently have no usable legacy 8254 PIT, so IRQ0 never
// fires and the event loop's first hlt-on-tick freezes the boot (reproduced as
// the "hangs at Starting DN" symptom on an AMD Razer laptop; locally with QEMU
// `-M q35,pit=off`). The local APIC timer is always present; we run it as the
// system tick, feeding the same TIMER_TICKS/PENDING_TICKS counters the PIC IRQ0
// path fed. The HPET (fixed, self-describing frequency at the de-facto-standard
// base 0xFED00000) is the calibration reference — with no PIT there is no other
// fixed clock to derive the rate from.

// xAPIC MMIO register offsets (the x2APIC MSR is 0x800 + offset/16).
const LAPIC_SVR: u32 = 0xF0;
const LAPIC_EOI: u32 = 0xB0;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_DIV_CONF: u32 = 0x3E0;
const LAPIC_INIT_COUNT: u32 = 0x380;
const LAPIC_CUR_COUNT: u32 = 0x390;

const LAPIC_SW_ENABLE: u32 = 1 << 8;       // SVR bit 8: software-enable the LAPIC
const LVT_TIMER_PERIODIC: u32 = 1 << 17;   // LVT timer: periodic mode
const LVT_MASKED: u32 = 1 << 16;
const LVT_DELIVERY_EXTINT: u32 = 7 << 8;   // LVT delivery mode = ExtINT
const LAPIC_DIV_1: u32 = 0b1011;           // divide-config: bus clock / 1
// Tick vector reuses the IRQ0 slot (32) so the existing `32..=47 => handle_irq`
// dispatch and Irq::Tick semantics apply unchanged.
const LAPIC_TIMER_VECTOR: u32 = IRQ_OFFSET as u32;
// Spurious-interrupt vector: low nibble must be 0xF on P6/early CPUs, and 0x2F
// lands in the PIC range where handle_irq's spurious-IRQ15 check returns
// cleanly without us touching the kernel's vector dispatch.
const LAPIC_SPURIOUS_VECTOR: u32 = 0x2F;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;     // global enable
const APIC_BASE_X2: u64 = 1 << 10;         // x2APIC mode

// MMIO windows: one page each, just above the framebuffer window (mapped the
// same way fbcon maps the framebuffer — cache-disabled, persistent).
const LAPIC_MMIO_VA: usize = 0xFFF0_0000;
const LAPIC_PHYS: u64 = 0xFEE0_0000;
const HPET_MMIO_VA: usize = 0xFFF0_1000;
const HPET_PHYS: u64 = 0xFED0_0000;

// false => x2APIC (MSR access); true after we map MMIO for the xAPIC path.
static mut LAPIC_X2: bool = false;
/// Set once the LAPIC timer is the live tick source (so handle_irq routes the
/// vector-0x20 EOI to the LAPIC instead of running the PIC ack dance).
static mut LAPIC_TIMER_ACTIVE: bool = false;

pub fn lapic_timer_active() -> bool {
    unsafe { core::ptr::read_volatile(&raw const LAPIC_TIMER_ACTIVE) }
}

fn lapic_write(off: u32, val: u32) {
    unsafe {
        if LAPIC_X2 {
            crate::x86::wrmsr(0x800 + (off >> 4), val as u64);
        } else {
            core::ptr::write_volatile((LAPIC_MMIO_VA + off as usize) as *mut u32, val);
        }
    }
}
fn lapic_read(off: u32) -> u32 {
    unsafe {
        if LAPIC_X2 {
            crate::x86::rdmsr(0x800 + (off >> 4)) as u32
        } else {
            core::ptr::read_volatile((LAPIC_MMIO_VA + off as usize) as *const u32)
        }
    }
}

fn map_mmio_page(va: usize, phys: u64) {
    crate::paging2::map_user_page_phys(
        va / crate::paging2::PAGE_SIZE,
        phys / crate::paging2::PAGE_SIZE as u64,
        crate::paging2::flags::CACHE_DISABLE,
    );
}

/// Measure the LAPIC timer input frequency against the HPET (a fixed,
/// self-describing clock) and return the periodic initial-count for ~1000 Hz.
/// Returns None when no usable HPET is present (then there is no fixed
/// reference and the caller falls back to the PIT).
fn calibrate_lapic_via_hpet() -> Option<u32> {
    map_mmio_page(HPET_MMIO_VA, HPET_PHYS);
    let hpet_read = |off: usize| -> u64 {
        unsafe { core::ptr::read_volatile((HPET_MMIO_VA + off) as *const u64) }
    };
    // GEN_CAP_ID[63:32] = main-counter period in femtoseconds. A valid HPET
    // period is non-zero and at most 100 ns (10 MHz minimum per the spec).
    let period_fs = (hpet_read(0x00) >> 32) as u32;
    if period_fs == 0 || period_fs > 100_000_000 {
        return None;
    }
    let hpet_hz = 1_000_000_000_000_000u64 / period_fs as u64;
    // Enable the HPET main counter (GEN_CONF bit 0).
    let conf = hpet_read(0x10);
    unsafe { core::ptr::write_volatile((HPET_MMIO_VA + 0x10) as *mut u64, conf | 1); }

    // One-shot, divide-by-1, masked, max count — just a free-running down-counter.
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_INIT_COUNT, 0xFFFF_FFFF);

    // Count LAPIC ticks over a 10 ms HPET window.
    let window = hpet_hz / 100;
    let t0 = hpet_read(0xF0);
    let c0 = lapic_read(LAPIC_CUR_COUNT);
    while hpet_read(0xF0).wrapping_sub(t0) < window {}
    let c1 = lapic_read(LAPIC_CUR_COUNT);
    lapic_write(LAPIC_INIT_COUNT, 0); // stop

    let elapsed = c0.wrapping_sub(c1); // counts down
    if elapsed == 0 {
        return None;
    }
    let lapic_hz = elapsed as u64 * 100;
    Some(((lapic_hz / 1000).max(1)) as u32)
}

/// Bring up the LAPIC timer as the system tick. Returns true on success; false
/// (no APIC, LAPIC globally disabled, or no HPET to calibrate against) leaves
/// the caller on the legacy PIT path.
fn setup_lapic_timer() -> bool {
    // APIC-base MSR is architectural only from P6; a P5-class part #GPs on the
    // RDMSR (86Box pentium_p54c). Pre-P6 is a pure-PIC machine anyway.
    let (sig, _, _, _) = crate::x86::cpuid(1);
    if (sig >> 8) & 0xF < 6 {
        return false;
    }
    let base = crate::x86::rdmsr(IA32_APIC_BASE);
    if base & APIC_BASE_ENABLE == 0 {
        return false; // LAPIC globally disabled by firmware — stay on PIT.
    }
    // Keep the firmware-selected mode: x2APIC => MSRs, xAPIC => map the MMIO
    // page. We deliberately do NOT promote xAPIC->x2APIC (it would perturb the
    // legacy-input heuristic and is unnecessary).
    unsafe {
        LAPIC_X2 = base & APIC_BASE_X2 != 0;
        if !LAPIC_X2 {
            map_mmio_page(LAPIC_MMIO_VA, LAPIC_PHYS);
        }
    }

    // Software-enable the LAPIC (required for the timer to count and for LVT
    // entries to unmask), then route LINT0 = ExtINT so 8259-delivered IRQs
    // (keyboard/mouse) still reach the CPU now that the LAPIC owns the local
    // interrupt pins.
    lapic_write(LAPIC_SVR, LAPIC_SW_ENABLE | LAPIC_SPURIOUS_VECTOR);
    lapic_write(LAPIC_LVT_LINT0, LVT_DELIVERY_EXTINT);

    let init_count = match calibrate_lapic_via_hpet() {
        Some(c) => c,
        None => return false,
    };

    // Start the periodic timer on vector 0x20.
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_VECTOR | LVT_TIMER_PERIODIC);
    lapic_write(LAPIC_INIT_COUNT, init_count);
    unsafe { core::ptr::write_volatile(&raw mut LAPIC_TIMER_ACTIVE, true); }
    lib::println!("IRQ: LAPIC timer tick (init_count={})", init_count);
    true
}

/// Legacy fallback: ensure the 8259 INTR reaches the CPU (the old APIC-routing
/// logic) and drive the tick from the PIT. Used when the LAPIC timer can't be
/// brought up (no APIC / no HPET reference).
fn legacy_intr_and_pit() {
    const X2APIC_SVR: u32 = 0x80F;
    const X2APIC_LVT_LINT0: u32 = 0x835;
    const APIC_SOFTWARE_ENABLE: u64 = 1 << 8;
    const APIC_DELIVERY_EXTINT: u64 = 7 << 8;

    let (sig, _, _, edx) = crate::x86::cpuid(1);
    let family = (sig >> 8) & 0xF;
    if family >= 6 && edx & (1 << 9) != 0 {
        let base = crate::x86::rdmsr(IA32_APIC_BASE);
        if base & (APIC_BASE_ENABLE | APIC_BASE_X2) == (APIC_BASE_ENABLE | APIC_BASE_X2) {
            let svr = crate::x86::rdmsr(X2APIC_SVR);
            unsafe {
                crate::x86::wrmsr(X2APIC_SVR, (svr & 0x3FF) | APIC_SOFTWARE_ENABLE);
                crate::x86::wrmsr(X2APIC_LVT_LINT0, APIC_DELIVERY_EXTINT);
            }
        } else if base & APIC_BASE_ENABLE != 0 {
            // Disable a firmware-enabled xAPIC so LINT0 reverts to the legacy
            // INTR wire (its MMIO page isn't mapped on this path).
            unsafe { crate::x86::wrmsr(IA32_APIC_BASE, base & !APIC_BASE_ENABLE) };
        }
    }
    lib::println!("IRQ: PIT");
    init_pit(1000); // 1000 Hz timer
    unmask_irq(0);  // timer
}

// ============================================================================
// I/O APIC — external IRQ routing in APIC mode (modern UEFI machines)
// ============================================================================
//
// In LAPIC mode the 8259 is bypassed: external device IRQs (keyboard GSI1,
// mouse GSI12) are delivered through the I/O APIC to the BSP local APIC at a
// fixed vector and acked with a LAPIC EOI. Legacy machines never touch this —
// the PIC path stands. The I/O APIC sits at the architectural default
// 0xFEC00000 (ACPI MADT could relocate it, but QEMU q35 and PC-class firmware
// use the default; revisit if a board moves it).
const IOAPIC_PHYS: u64 = 0xFEC0_0000;
const IOAPIC_MMIO_VA: usize = 0xFFF0_2000; // next page after LAPIC (F0000)/HPET (F1000)
static mut IOAPIC_READY: bool = false;

/// Indirect register access: select the register via IOREGSEL (+0x00), then
/// read/write its value through IOWIN (+0x10).
fn ioapic_write(reg: u32, val: u32) {
    unsafe {
        core::ptr::write_volatile(IOAPIC_MMIO_VA as *mut u32, reg);
        core::ptr::write_volatile((IOAPIC_MMIO_VA + 0x10) as *mut u32, val);
    }
}

/// The BSP local-APIC ID — the I/O APIC redirection destination (physical mode,
/// uniprocessor). x2APIC holds the full ID in MSR 0x802; xAPIC in bits 24-31 of
/// the memory-mapped ID register (0x20).
fn bsp_apic_id() -> u32 {
    unsafe {
        if LAPIC_X2 {
            crate::x86::rdmsr(0x802) as u32
        } else {
            lapic_read(0x20) >> 24
        }
    }
}

/// Route ISA IRQ line `gsi` to `vector` on the BSP: fixed delivery, physical
/// destination, edge-triggered, active-high, unmasked. ISA IRQs map 1:1 to GSIs
/// for the keyboard (1) and mouse (12); the timer (often overridden to GSI2) is
/// not routed here — the LAPIC timer owns the tick.
fn ioapic_route(gsi: u8, vector: u8) {
    unsafe {
        if !IOAPIC_READY {
            map_mmio_page(IOAPIC_MMIO_VA, IOAPIC_PHYS);
            IOAPIC_READY = true;
        }
    }
    let idx = 0x10 + 2 * gsi as u32;
    // High dword: destination APIC ID in bits 56-63 (bits 24-31 of this word).
    ioapic_write(idx + 1, bsp_apic_id() << 24);
    // Low dword: vector in bits 0-7; all other fields 0 (fixed / physical /
    // edge / active-high) and bit 16 (mask) clear = unmasked.
    ioapic_write(idx, vector as u32);
}

/// Probe whether an 8042 keyboard controller is present. A board with no i8042
/// (USB-only modern laptop, legacy-free firmware) floats the status port high —
/// 0xFF. Read-only: we issue no command, since writing to a phantom 8042 traps
/// to SMM on some firmware. This replaces guessing "no keyboard" from x2APIC.
fn i8042_present() -> bool {
    inb(0x64) != 0xFF
}

/// Initialize interrupts (PIC + tick source + keyboard/mouse)
pub fn init_interrupts() {
    lib::println!("IRQ: PIC");
    remap_pic();

    // Pick the interrupt mode ONCE: LAPIC timer succeeds ⇒ APIC mode (IOAPIC
    // routes device IRQs, LAPIC EOI); else the legacy 8259 path (PIT tick, PIC
    // delivery). The keyboard and mouse below follow that same decision — the
    // half-state (LAPIC timer but PIC keyboard) is what left modern boxes with
    // a dead keyboard: the tick survived on the LAPIC while IRQ1 rode the PIC
    // whose INTR the firmware had cut.
    let apic = setup_lapic_timer();
    if !apic {
        legacy_intr_and_pit();
    }

    // Probe the xHCI controller (the USB-HID keyboard source on legacy-free
    // machines). WIP: reports the controller for now; once the HID read path
    // lands it becomes the keyboard when no i8042 answers below.
    crate::xhci::init();

    // Keyboard/mouse SOURCE is a separate axis from delivery: PROBE the i8042
    // rather than guessing "no keyboard" from x2APIC. A real controller (many
    // laptops expose the internal keyboard as PS/2 via the EC) is used either
    // way — routed through the IOAPIC in APIC mode, the PIC otherwise. A truly
    // legacy-free box (no i8042) needs the xHCI USB-HID driver (not yet here).
    if !i8042_present() {
        lib::println!("IRQ: no i8042 (USB-HID keyboard not yet supported)");
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
    lib::println!("IRQ: keyboard");
    for _ in 0..1_000 {
        if inb(0x64) & 1 == 0 {
            break;
        }
        let _ = inb(0x60);
    }
    if apic {
        ioapic_route(1, IRQ_OFFSET + 1); // keyboard GSI1
    } else {
        unmask_irq(1);
    }

    lib::println!("IRQ: mouse probe");
    if init_mouse() {
        lib::println!("IRQ: mouse ready");
        if apic {
            ioapic_route(12, IRQ_OFFSET + 12); // mouse GSI12
        } else {
            unmask_irq(12);
            // The emulated legacy machine that supplies a PS/2 mouse may also
            // supply an ISA Sound Blaster on IRQ 5 or 7 (legacy delivery only).
            unmask_irq(5);
            unmask_irq(7);
        }
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

    // IRQ12 line enable is left to the caller: IOAPIC route in APIC mode, or
    // unmask_irq(12) on the PIC in legacy mode.
    true
}

/// Boot diagnostic: with IF still 0 (interrupts not yet enabled), interrogate
/// the timer chain directly so a freeze-at-first-IRQ on real hardware becomes
/// readable on the VGA console instead of a black hang. Isolates the break:
///   1. Is the 8254 PIT counting?      (latch + sample channel 0 repeatedly)
///   2. Does the 8259 master see IRQ0?  (read IRR bit 0 — IRQ0 is unmasked but
///      IF=0, so the request latches and stays pending, never acked)
/// If both pass but the kernel still freezes, the break is CPU delivery —
/// LINT0 / virtual-wire routing through the (x2)APIC, the known UEFI failure.
pub fn timer_selftest() {
    // --- 1. PIT channel 0 counting? Sample the latched counter several times.
    let mut samples = [0u16; 8];
    for s in samples.iter_mut() {
        outb(0x43, 0x00); // latch channel 0
        let lo = inb(0x40) as u16;
        let hi = inb(0x40) as u16;
        *s = lo | (hi << 8);
        // crude I/O delay so successive samples land in different counts
        for _ in 0..2000 { let _ = inb(0x80); }
    }
    let counting = samples.iter().any(|&v| v != samples[0]);
    lib::println!(
        "SELFTEST PIT counting={} samples={:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X}",
        counting as u8,
        samples[0], samples[1], samples[2], samples[3],
        samples[4], samples[5], samples[6], samples[7],
    );

    // --- 2. 8259 master IRR — does the PIT pulse reach the PIC? IRQ0 was
    // unmasked in init_interrupts; with IF=0 the request latches in IRR.
    // OCW3 0x0A selects IRR for the next read; restore ISR mode (0x0B) after,
    // since handle_irq's spurious check relies on the default ISR read.
    let mut irr_seen = 0u8;
    for _ in 0..8 {
        outb(MASTER_CMD, 0x0A);
        irr_seen |= inb(MASTER_CMD);
        for _ in 0..2000 { let _ = inb(0x80); }
    }
    outb(MASTER_CMD, 0x0B);
    let mask = inb(MASTER_DATA);
    lib::println!(
        "SELFTEST PIC master IRR(seen)={:08b} IMR={:08b} IRQ0_pending={} IRQ0_masked={}",
        irr_seen, mask, irr_seen & 1, mask & 1,
    );

    // --- 3. APIC routing recap (which delivery path init_interrupts took).
    let (sig, _, ecx1, edx1) = crate::x86::cpuid(1);
    let family = (sig >> 8) & 0xF;
    let has_apic = family >= 6 && edx1 & (1 << 9) != 0;
    if has_apic {
        let base = crate::x86::rdmsr(0x1B);
        let mode = if base & (1 << 11) == 0 { "disabled" }
            else if base & (1 << 10) != 0 { "x2apic" }
            else { "xapic" };
        lib::println!(
            "SELFTEST APIC base={:#x} mode={} (LINT0 ExtINT route is what carries IRQ0)",
            base, mode,
        );
    } else {
        lib::println!("SELFTEST APIC none (pure-PIC machine, INTR direct)");
    }

    // --- 4. CPU timer capabilities — picks the LAPIC-timer calibration path
    // (no PIT means TSC/CPUID is the only fixed reference we have).
    let (maxleaf, vb, vc, vd) = crate::x86::cpuid(0);
    let vendor = [
        vb as u8, (vb >> 8) as u8, (vb >> 16) as u8, (vb >> 24) as u8,
        vd as u8, (vd >> 8) as u8, (vd >> 16) as u8, (vd >> 24) as u8,
        vc as u8, (vc >> 8) as u8, (vc >> 16) as u8, (vc >> 24) as u8,
    ];
    lib::println!(
        "SELFTEST CPU vendor={} family={} tsc_deadline={} x2apic_cap={} invtsc={}",
        core::str::from_utf8(&vendor).unwrap_or("????????????"),
        family,
        (ecx1 >> 24) & 1, (ecx1 >> 21) & 1,
        if crate::x86::cpuid(0x8000_0007).3 & (1 << 8) != 0 { 1 } else { 0 },
    );
    if maxleaf >= 0x15 {
        let (den, num, crystal, _) = crate::x86::cpuid(0x15);
        lib::println!("SELFTEST CPUID.15H den={} num={} crystal_hz={}", den, num, crystal);
    } else {
        lib::println!("SELFTEST CPUID.15H unavailable (maxleaf={:#x})", maxleaf);
    }
    if maxleaf >= 0x16 {
        let (base_mhz, max_mhz, bus_mhz, _) = crate::x86::cpuid(0x16);
        lib::println!("SELFTEST CPUID.16H base={}MHz max={}MHz bus={}MHz", base_mhz, max_mhz, bus_mhz);
    } else {
        lib::println!("SELFTEST CPUID.16H unavailable");
    }
}

// ============================================================================
// IRQ dispatch
// ============================================================================

/// Handle an IRQ: PIC ACK, read hardware data, push typed event to queue.
pub fn handle_irq(regs: &mut Regs) {
    let irq = (regs.int_num - IRQ_OFFSET as u64) as u8;

    // APIC mode: the tick is the LAPIC timer (vector 0x20 from the local APIC)
    // and keyboard/mouse arrive through the I/O APIC — the 8259 is bypassed
    // entirely. Read the device inline and ack with a single LAPIC EOI; none of
    // the PIC mask/ack dance below applies. (`lapic_timer_active()` is the
    // APIC-mode flag: it is set iff setup_lapic_timer succeeded.)
    if lapic_timer_active() {
        match irq {
            0 => {
                unsafe {
                    let t = core::ptr::read_volatile(&raw const TIMER_TICKS);
                    core::ptr::write_volatile(&raw mut TIMER_TICKS, t + 1);
                    let p = core::ptr::read_volatile(&raw const PENDING_TICKS);
                    core::ptr::write_volatile(&raw mut PENDING_TICKS, p + 1);
                }
                // Poll the USB-HID keyboard (if any) into the same key queue.
                crate::xhci::poll();
            }
            1 => unsafe { (*(&raw mut QUEUE)).push(Irq::Key(inb(0x60))); },
            12 => {
                if let Some(e) = mouse_packet_byte(inb(0x60)) {
                    unsafe { (*(&raw mut QUEUE)).push(e); }
                }
            }
            _ => unsafe { (*(&raw mut QUEUE)).push(Irq::Hw(irq)); },
        }
        lapic_write(LAPIC_EOI, 0);
        return;
    }

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
