//! Programmable Interrupt Controller (8259 PIC) and IRQ handling

use crate::x86::{inb, outb};
use arch_abi::Regs;
use core::sync::atomic::{AtomicU32, Ordering};

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

/// Private IDT range reserved for kernel MSI sources. These gates are DPL0,
/// unlike the guest-callable software-interrupt range below them.
pub const MSI_VECTOR_BASE: u8 = 0xF8;
pub const MSI_SOURCE_COUNT: u8 = 7;

/// Device-owned input sink installed during boot. Arch retains no input data.
#[thread_local]
static mut INPUT_SINK: fn(Irq, u64) = |_, _| {};

fn post(event: Irq, timestamp: u64) { unsafe { INPUT_SINK(event, timestamp); } }
#[thread_local]
static IRQ0_HANDLED: AtomicU32 = AtomicU32::new(0);
const PIT_INPUT_HZ: u64 = 1_193_182;
const PIT_CHANNEL2: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;
const NS_SHIFT: u32 = 32;

#[derive(Clone, Copy)]
enum ClockSource {
    Uninitialized,
    Tsc,
    Hpet,
    Pit2,
}

/// Frozen clocksource selection and conversion facts. Initialized once before
/// interrupts are enabled, then read normally; none of these fields is live
/// interrupt state.
#[derive(Clone, Copy)]
struct Clock {
    source: ClockSource,
    /// 32.32 fixed-point nanoseconds per source cycle.
    ns_mult: u64,
    epoch: u64,
    /// HPET remains the LAPIC calibration reference even when TSC is selected.
    hpet_hz: u64,
    hpet_mask: u64,
}

static mut CLOCK: Clock = Clock {
    source: ClockSource::Uninitialized,
    ns_mult: 0,
    epoch: 0,
    hpet_hz: 0,
    hpet_mask: 0,
};
/// PS/2 mouse 3-byte packet assembly state. Packets stream in over IRQ 12;
/// we accumulate three bytes, decode to dx/dy/buttons, push one Irq::Mouse,
/// and reset.
static mut MOUSE_PACKET: [u8; 3] = [0; 3];
static mut MOUSE_PACKET_IDX: u8 = 0;

/// Snapshot the master PIC without leaving its OCW3 selector in IRR mode.
/// The short IF mask keeps the ISR/IRR/IMR readings in one interrupt epoch.
fn master_pic_state() -> (u8, u8, u8) {
    let restore_if = crate::x86::interrupts_enabled();
    crate::x86::cli();
    outb(MASTER_CMD, 0x0B);
    let isr = inb(MASTER_CMD);
    outb(MASTER_CMD, 0x0A);
    let irr = inb(MASTER_CMD);
    outb(MASTER_CMD, 0x0B);
    let imr = inb(MASTER_DATA);
    if restore_if { crate::x86::sti(); }
    (irr, isr, imr)
}

/// Push a keyboard scancode into the queue from a non-IRQ source — the xHCI
/// USB-HID keyboard `poll()`. Polled reports carry observation time: the
/// controller cannot recover when the USB report originally arrived. This is
/// the same sink as i8042 IRQ1, so the kernel sees one uniform key stream.
pub fn push_key(sc: u8) {
    { post(Irq::Key(sc), now(false)); }
}

/// Push one already-decoded pointing-device report. USB HID and i8042 use the
/// same canonical event, so focus routing and the DOS INT 33h implementation do
/// not depend on which physical bus supplied the mouse.
pub fn push_mouse(dx: i16, dy: i16, buttons: u8) {
    { post(Irq::Mouse { dx, dy, buttons }, now(false)); }
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

/// Program channel 0 as a one-shot interrupt source.
fn pit_alarm_count(count: u16) {
    outb(PIT_COMMAND, 0x30);
    outb(0x40, count as u8);
    outb(0x40, (count >> 8) as u8);
}

/// Reserve physical PIT channel 2 as a free-running 16-bit clock. DOS sees a
/// fully virtual PIT/speaker, so the real speaker is disconnected and its
/// counter can use the maximum 65,536-cycle period (~54.9 ms).
fn init_pit2_clock() {
    outb(PIT_COMMAND, 0xB4); // channel 2, lo/hi, mode 2 rate generator
    outb(PIT_CHANNEL2, 0);
    outb(PIT_CHANNEL2, 0);   // zero encodes 65,536
    outb(0x61, (inb(0x61) | 0x01) & !0x02); // gate on, speaker disconnected
}

/// Atomically latch channel 2, then read its low/high count bytes.
fn pit2_count() -> u16 {
    outb(PIT_COMMAND, 0x80); // latch channel 2
    let lo = inb(PIT_CHANNEL2) as u16;
    lo | ((inb(PIT_CHANNEL2) as u16) << 8)
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
// LAPIC alarm — PIT-independent wakeups for modern (PIT-less) hardware
// ============================================================================
//
// Modern UEFI laptops frequently have no usable legacy 8254 PIT, so IRQ0 never
// fires and the event loop's first idle wait freezes the boot (reproduced as
// the "hangs at Starting DN" symptom on an AMD Razer laptop; locally with QEMU
// `-M q35,pit=off`). The local APIC timer is always present; we run it as the
// alarm source, returning control to the event loop without manufacturing
// elapsed time. Calibrate it against HPET where available, or poll PIT channel
// 2 on machines whose firmware omits HPET but has a working legacy PIT.

// xAPIC MMIO register offsets (the x2APIC MSR is 0x800 + offset/16).
const LAPIC_SVR: u32 = 0xF0;
const LAPIC_EOI: u32 = 0xB0;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_DIV_CONF: u32 = 0x3E0;
const LAPIC_INIT_COUNT: u32 = 0x380;
const LAPIC_CUR_COUNT: u32 = 0x390;

const LAPIC_SW_ENABLE: u32 = 1 << 8;       // SVR bit 8: software-enable the LAPIC
const LVT_MASKED: u32 = 1 << 16;
const LVT_DELIVERY_EXTINT: u32 = 7 << 8;   // LVT delivery mode = ExtINT
const LAPIC_DIV_1: u32 = 0b1011;           // divide-config: bus clock / 1
// The timer vector reuses the IRQ0 slot (32) so the existing `32..=47 =>
// handle_irq` dispatch applies unchanged.
const LAPIC_TIMER_VECTOR: u32 = IRQ_OFFSET as u32;
// Dedicated DPL0 vector, outside both ISA and MSI delivery. The low nibble
// must be 0xF on P6/early CPUs. Trap entry discards it without sending EOI.
pub(crate) const LAPIC_SPURIOUS_VECTOR: u32 = 0xFF;
const _: () = assert!(MSI_VECTOR_BASE as u32 + MSI_SOURCE_COUNT as u32 == LAPIC_SPURIOUS_VECTOR);

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;     // global enable
const APIC_BASE_X2: u64 = 1 << 10;         // x2APIC mode

// MMIO windows: one page each, just above the framebuffer window (mapped the
// same way fbcon maps the framebuffer — cache-disabled, persistent).
const LAPIC_MMIO_VA: usize = 0xFFF0_0000;
const LAPIC_PHYS: u64 = 0xFEE0_0000;
const HPET_MMIO_VA: usize = 0xFFF0_1000;
static mut HPET_REGISTER_OFFSET: usize = 0;
// A failed/disabled timer must not hang boot while we wait for its counter.
// At one million volatile polls, even a slow legacy bridge gets ample time to
// cover the 1 ms probe and 10 ms calibration windows.
const TIMER_POLL_LIMIT: u32 = 1_000_000;

// false => x2APIC (MSR access); true after we map MMIO for the xAPIC path.
#[thread_local]
static mut LAPIC_X2: bool = false;
/// Set once the LAPIC timer is the live alarm source (so handle_irq routes the
/// vector-0x20 EOI to the LAPIC instead of running the PIC ack dance).
#[thread_local]
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
    crate::paging2::map_kernel_page(
        va / crate::paging2::PAGE_SIZE,
        phys / crate::paging2::PAGE_SIZE as u64,
        crate::paging2::flags::CACHE_DISABLE,
    );
}

/// Read the HPET main counter without tearing on this 32-bit kernel.
fn hpet_counter(mask: u64) -> u64 {
    let offset = unsafe { core::ptr::read_volatile(&raw const HPET_REGISTER_OFFSET) };
    let lo = (HPET_MMIO_VA + offset + 0xF0) as *const u32;
    if mask == u64::from(u32::MAX) {
        return u64::from(unsafe { core::ptr::read_volatile(lo) });
    }
    let hi = (HPET_MMIO_VA + offset + 0xF4) as *const u32;
    loop {
        let hi0 = unsafe { core::ptr::read_volatile(hi) };
        let low = unsafe { core::ptr::read_volatile(lo) };
        let hi1 = unsafe { core::ptr::read_volatile(hi) };
        if hi0 == hi1 {
            return (u64::from(hi0) << 32) | u64::from(low);
        }
    }
}

/// Wait for the HPET main counter to advance, with a finite bound. Firmware may
/// leave HPET disabled or decode it at a different base; a stationary counter
/// must select the PIT fallback instead of wedging early boot.
fn wait_hpet_delta(start: u64, target: u64, mask: u64) -> Option<u64> {
    for _ in 0..TIMER_POLL_LIMIT {
        let now = hpet_counter(mask);
        if now.wrapping_sub(start) & mask >= target {
            return Some(now);
        }
    }
    None
}

fn wait_pit2_delta(start: u16, target: u16) -> Option<u16> {
    for _ in 0..TIMER_POLL_LIMIT {
        let now = pit2_count();
        if start.wrapping_sub(now) >= target {
            return Some(now);
        }
    }
    None
}

/// Enable and describe the architectural HPET at its ACPI-provided base.
/// `None` leaves both the clock and LAPIC calibration on PIT paths.
fn init_hpet(physical_base: Option<u64>) -> Option<(u64, u64)> {
    let physical_base = physical_base?;
    let page_offset = (physical_base & (crate::paging2::PAGE_SIZE as u64 - 1)) as usize;
    if page_offset > crate::paging2::PAGE_SIZE - 0x100 {
        return None;
    }
    unsafe { core::ptr::write_volatile(&raw mut HPET_REGISTER_OFFSET, page_offset); }
    map_mmio_page(HPET_MMIO_VA, physical_base);
    let hpet_va = HPET_MMIO_VA + page_offset;
    let capabilities = unsafe {
        core::ptr::read_volatile(hpet_va as *const u64)
    };
    let period_fs = (capabilities >> 32) as u32;
    if period_fs == 0 || period_fs > 100_000_000 {
        return None;
    }
    let hz = 1_000_000_000_000_000u64 / u64::from(period_fs);
    let mask = if capabilities & (1 << 13) != 0 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let conf = unsafe {
        core::ptr::read_volatile((hpet_va + 0x10) as *const u64)
    };
    unsafe {
        core::ptr::write_volatile((hpet_va + 0x10) as *mut u64, conf | 1);
    }
    let start = hpet_counter(mask);
    wait_hpet_delta(start, (hz / 1000).max(1), mask)?;
    Some((hz, mask))
}

/// A hypervisor owns the virtual CPU's TSC and this kernel runs only one CPU,
/// so there is neither package skew nor migration between counters. Calibrate
/// it against HPET just like an invariant hardware TSC, even when the virtual
/// CPU model neglects to advertise CPUID.80000007H:EDX.invariant_tsc.
fn stable_tsc() -> bool {
    let cpu = crate::x86::cpu_capabilities();
    // Hypervisor presence says nothing about instruction availability. Old
    // CPUs (and deliberately restricted VM models) must use HPET/PIT instead.
    cpu.tsc() && (cpu.invariant_tsc() || cpu.hypervisor())
}

fn calibrate_tsc(hpet: Option<(u64, u64)>) -> Option<u64> {
    if let Some((hpet_hz, mask)) = hpet {
        let window = (hpet_hz / 100).max(1);
        let h0 = hpet_counter(mask);
        let t0 = crate::x86::rdtsc();
        let h1 = wait_hpet_delta(h0, window, mask)?;
        let t1 = crate::x86::rdtsc();
        let elapsed = h1.wrapping_sub(h0) & mask;
        return (elapsed != 0).then(||
            (u128::from(t1.wrapping_sub(t0)) * u128::from(hpet_hz)
                / u128::from(elapsed)) as u64);
    }

    // No HPET: channel 2 still provides a fixed calibration interval. The
    // 10 ms window is well below its 54.9 ms wrap, so modular subtraction is
    // unambiguous even when the initial count is near zero.
    let window = (PIT_INPUT_HZ / 100) as u16;
    let p0 = pit2_count();
    let t0 = crate::x86::rdtsc();
    let p1 = wait_pit2_delta(p0, window)?;
    let t1 = crate::x86::rdtsc();
    let elapsed = u64::from(p0.wrapping_sub(p1));
    (elapsed != 0).then(||
        (u128::from(t1.wrapping_sub(t0)) * u128::from(PIT_INPUT_HZ)
            / u128::from(elapsed)) as u64)
}

fn init_monotonic_clock(hpet_base: Option<u64>) {
    init_pit2_clock();
    let mut hpet = init_hpet(hpet_base);
    let tsc_hz = if stable_tsc() {
        match calibrate_tsc(hpet) {
            Some(hz) => Some(hz),
            None if hpet.is_some() => {
                // A counter that passed the initial probe but stopped during
                // calibration is not a usable clock source. Retry against
                // PIT2 and keep the later LAPIC setup on its PIT fallback too.
                hpet = None;
                calibrate_tsc(None)
            }
            None => None,
        }
    } else {
        None
    };
    let (source, hz) = if let Some(hz) = tsc_hz.filter(|&hz| hz != 0) {
        (ClockSource::Tsc, hz)
    } else if let Some((hz, _)) = hpet {
        (ClockSource::Hpet, hz)
    } else {
        (ClockSource::Pit2, PIT_INPUT_HZ)
    };
    unsafe {
        CLOCK = Clock {
            source,
            ns_mult: ((u128::from(1_000_000_000u64) << NS_SHIFT) / u128::from(hz)) as u64,
            epoch: 0,
            hpet_hz: hpet.map_or(0, |(hpet_hz, _)| hpet_hz),
            hpet_mask: hpet.map_or(0, |(_, mask)| mask),
        };
    }
    let _ = now(true);
    lib::compact_println!("Clock: {} {} Hz", match source {
        ClockSource::Tsc => "stable TSC",
        ClockSource::Hpet => "HPET",
        ClockSource::Pit2 => "PIT channel 2",
        ClockSource::Uninitialized => "uninitialized",
    }, hz);
}

/// Measure the LAPIC timer input frequency against the HPET (a fixed,
/// self-describing clock) and return its frequency in Hz.
/// Returns None when no usable HPET is present (then there is no fixed
/// reference and the caller falls back to the PIT).
fn calibrate_lapic_via_hpet() -> Option<u64> {
    let clock = unsafe { CLOCK };
    let hpet_hz = clock.hpet_hz;
    let counter_mask = clock.hpet_mask;
    if hpet_hz == 0 { return None; }

    // One-shot, divide-by-1, masked, max count — just a free-running down-counter.
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_INIT_COUNT, 0xFFFF_FFFF);

    // Count LAPIC ticks over a 10 ms HPET window.
    let window = hpet_hz / 100;
    let t0 = hpet_counter(counter_mask);
    let c0 = lapic_read(LAPIC_CUR_COUNT);
    if wait_hpet_delta(t0, window, counter_mask).is_none() {
        lapic_write(LAPIC_INIT_COUNT, 0);
        return None;
    }
    let c1 = lapic_read(LAPIC_CUR_COUNT);
    let t1 = hpet_counter(counter_mask);
    lapic_write(LAPIC_INIT_COUNT, 0); // stop

    let elapsed = c0.wrapping_sub(c1); // counts down
    let hpet_elapsed = t1.wrapping_sub(t0) & counter_mask;
    if elapsed == 0 || hpet_elapsed == 0 {
        return None;
    }
    // Use the interval we actually observed. The vCPU can be preempted by the
    // host after the 10 ms deadline but before it samples the counters again;
    // treating such an overshot window as exactly 10 ms overestimates the
    // LAPIC frequency and makes the programmed system tick proportionally
    // slow. This was visible as a 44.1 kHz sink requiring a ~56 kHz numerical
    // mix rate to stay full on intermittent KVM boots.
    let lapic_hz = (elapsed as u128 * hpet_hz as u128 / hpet_elapsed as u128) as u64;
    Some(lapic_hz)
}

/// Calibrate the LAPIC timer against PIT channel 2 when firmware has no HPET
/// table. Channel 2 is polled, so this works even if PIC IRQ0 cannot reach the
/// CPU. Keeping the LAPIC timer active avoids disabling a firmware-enabled
/// APIC and assuming the chipset will reconnect the PIC to direct INTR.
fn calibrate_lapic_via_pit2() -> Option<u64> {
    let target = (PIT_INPUT_HZ / 100) as u16; // about 10 ms
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_INIT_COUNT, 0xFFFF_FFFF);

    let p0 = pit2_count();
    let c0 = lapic_read(LAPIC_CUR_COUNT);
    if wait_pit2_delta(p0, target).is_none() {
        lapic_write(LAPIC_INIT_COUNT, 0);
        return None;
    }
    let c1 = lapic_read(LAPIC_CUR_COUNT);
    let p1 = pit2_count();
    lapic_write(LAPIC_INIT_COUNT, 0);

    let pit_elapsed = u64::from(p0.wrapping_sub(p1));
    let lapic_elapsed = u64::from(c0.wrapping_sub(c1));
    if pit_elapsed < u64::from(target) || lapic_elapsed == 0 {
        return None;
    }
    let lapic_hz = (u128::from(lapic_elapsed) * u128::from(PIT_INPUT_HZ)
        / u128::from(pit_elapsed)) as u64;
    Some(lapic_hz)
}

/// Bring up the LAPIC timer as the alarm source. Returns true on success; false
/// (no APIC, LAPIC globally disabled, or no usable reference clock) leaves
/// the caller on the legacy PIT path.
fn setup_lapic_timer() -> bool {
    // APIC-base MSR is architectural only from P6; a P5-class part #GPs on the
    // RDMSR (86Box pentium_p54c). Pre-P6 is a pure-PIC machine anyway.
    if crate::x86::cpu_capabilities().family < 6 {
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

    let (frequency, reference) = if let Some(c) = calibrate_lapic_via_hpet() {
        (c, "HPET")
    } else if let Some(c) = calibrate_lapic_via_pit2() {
        (c, "PIT2")
    } else {
        return false;
    };

    unsafe {
        LAPIC_HZ = frequency;
        TSC_DEADLINE = matches!(CLOCK.source, ClockSource::Tsc)
            && crate::x86::cpu_capabilities().tsc_deadline();
    }
    // One interrupt checks delivery after IF is enabled. There is no boot heartbeat.
    let init_count = (frequency / 1000).max(1).min(u32::MAX as u64) as u32;
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_VECTOR);
    lapic_write(LAPIC_INIT_COUNT, init_count);
    unsafe { core::ptr::write_volatile(&raw mut LAPIC_TIMER_ACTIVE, true); }
    lib::compact_println!("IRQ: LAPIC alarm (hz={} ref={} tsc_deadline={})", frequency, reference, unsafe { TSC_DEADLINE });
    true
}

/// Legacy fallback: ensure the 8259 INTR reaches the CPU (the old APIC-routing
/// logic) and drive alarms from the PIT. Used when the LAPIC timer can't be
/// brought up (no APIC / no HPET reference).
fn legacy_intr_and_pit() {
    const X2APIC_SVR: u32 = 0x80F;
    const X2APIC_LVT_LINT0: u32 = 0x835;
    const APIC_SOFTWARE_ENABLE: u64 = 1 << 8;
    const APIC_DELIVERY_EXTINT: u64 = 7 << 8;

    let cpu = crate::x86::cpu_capabilities();
    if cpu.family >= 6 && cpu.apic() {
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
    lib::compact_println!("IRQ: PIT");
    pit_alarm_count((PIT_INPUT_HZ / 1000) as u16); // one delivery-test alarm
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

/// Change only the mask on an established ISA route. Protect the indirect
/// register selection from interrupts on this CPU, as in `ioapic_route`.
fn ioapic_set_mask(irq: u8, masked: bool) {
    let restore_if = crate::x86::interrupts_enabled();
    crate::x86::cli();
    let reg = 0x10 + 2 * u32::from(irq);
    unsafe {
        core::ptr::write_volatile(IOAPIC_MMIO_VA as *mut u32, reg);
        let entry = core::ptr::read_volatile((IOAPIC_MMIO_VA + 0x10) as *const u32);
        let entry = if masked { entry | (1 << 16) } else { entry & !(1 << 16) };
        ioapic_write(reg, entry);
    }
    if restore_if {
        crate::x86::sti();
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
/// not routed here — the LAPIC timer owns alarm delivery.
fn ioapic_route(gsi: u8, vector: u8) {
    let restore_if = crate::x86::interrupts_enabled();
    crate::x86::cli();
    unsafe {
        if !IOAPIC_READY {
            map_mmio_page(IOAPIC_MMIO_VA, IOAPIC_PHYS);
            IOAPIC_READY = true;
        }
    }
    let idx = 0x10 + 2 * gsi as u32;
    // High dword: destination APIC ID in bits 56-63 (bits 24-31 of this word).
    ioapic_write(idx + 1, bsp_apic_id() << 24);
    // Fixed delivery, active-high, edge-triggered and unmasked.
    ioapic_write(idx, vector as u32);
    if restore_if {
        crate::x86::sti();
    }
}

/// Probe whether an 8042 keyboard controller is present. A board with no i8042
/// (USB-only modern laptop, legacy-free firmware) floats the status port high —
/// 0xFF. Read-only: we issue no command, since writing to a phantom 8042 traps
/// to SMM on some firmware. This replaces guessing "no keyboard" from x2APIC.
fn i8042_present() -> bool {
    inb(0x64) != 0xFF
}

/// Initialize interrupts (PIC + alarm source + keyboard/mouse)
pub fn init_interrupts(
    hpet_base: Option<u64>,
    mut progress: impl FnMut(&str),
    input_sink: fn(Irq, u64),
) {
    // Installed before enabling BSP device interrupts.
    unsafe { INPUT_SINK = input_sink; }
    progress("PIC setup");
    lib::compact_println!("IRQ: PIC");
    remap_pic();
    progress("clock calibration (PIT/HPET/TSC)");
    init_monotonic_clock(hpet_base);

    // Pick the interrupt mode ONCE: LAPIC timer succeeds ⇒ APIC mode (IOAPIC
    // routes device IRQs, LAPIC EOI); else the legacy 8259 path (PIT alarm, PIC
    // delivery). The keyboard and mouse below follow that same decision — the
    // half-state (LAPIC timer but PIC keyboard) is what left modern boxes with
    // a dead keyboard: the timer worked on the LAPIC while IRQ1 rode the PIC
    // whose INTR the firmware had cut.
    // Record the firmware APIC state before our fallback can disable xAPIC.
    // CPUID's APIC bit may itself clear after that transition, so the later
    // self-test alone cannot reveal what the firmware configured.
    let cpu = crate::x86::cpu_capabilities();
    if cpu.family >= 6 {
        lib::compact_println!(
            "IRQ: APIC initial cpuid={} base={:#x}",
            cpu.apic() as u8,
            crate::x86::rdmsr(IA32_APIC_BASE),
        );
    }
    progress("local APIC timer");
    let apic = setup_lapic_timer();
    if !apic {
        legacy_intr_and_pit();
    }

    progress("PS/2 keyboard and mouse");

    // Keyboard/mouse SOURCE is a separate axis from delivery: PROBE the i8042
    // rather than guessing "no keyboard" from x2APIC. A real controller (many
    // laptops expose the internal keyboard as PS/2 via the EC) is used either
    // way — routed through the IOAPIC in APIC mode, the PIC otherwise. A truly
    // legacy-free box (no i8042) relies on the kernel's other input drivers.
    if !i8042_present() {
        // No PS/2 controller, so there is no legacy device IRQ to route.
        lib::compact_println!("IRQ: no i8042 - using platform input devices");
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
    lib::compact_println!("IRQ: keyboard");
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

    lib::compact_println!("IRQ: mouse probe");
    if init_mouse() {
        lib::compact_println!("IRQ: mouse ready");
        // Only the mouse's own line. A device's interrupt is enabled by
        // whoever probed that device (`isa_enable_irq`), never as a side
        // effect of an unrelated probe — the SB lines used to be unmasked
        // here on the theory that a PS/2 mouse implies a legacy ISA machine.
        if apic {
            ioapic_route(12, IRQ_OFFSET + 12); // mouse GSI12
        } else {
            unmask_irq(12);
        }
    } else {
        lib::compact_println!("IRQ: mouse unavailable");
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
///   2. Does the 8259 master see IRQ0?  (read IRR bit 0; the line is unmasked
///      only on the legacy PIT path, and IF is still 0)
///
/// If both pass but the kernel still freezes, the break is CPU delivery —
/// LINT0 / virtual-wire routing through the (x2)APIC, the known UEFI failure.
pub fn timer_selftest(screen: &mut lib::term::Term) {
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
    lib::compact_screenln!(screen,
        "SELFTEST PIT counting={} samples={:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X}",
        counting as u8,
        samples[0], samples[1], samples[2], samples[3],
        samples[4], samples[5], samples[6], samples[7],
    );

    // --- 2. 8259 master IRR — does the PIT pulse reach the PIC? The legacy
    // path unmasks IRQ0; LAPIC mode leaves it masked. With IF=0 a pending
    // legacy request remains in IRR.
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
    lib::compact_screenln!(screen,
        "SELFTEST PIC master IRR(seen)={:08b} IMR={:08b} IRQ0_pending={} IRQ0_masked={}",
        irr_seen, mask, irr_seen & 1, mask & 1,
    );

    // --- 3. APIC routing recap. CPUID may hide the APIC feature even when
    // IA32_APIC_BASE is readable. setup_lapic_timer() already reads this MSR
    // on family >= 6, so inspect the actual base and LINT0 state here too.
    let cpu = crate::x86::cpu_capabilities();
    let family = cpu.family;
    let cpuid_apic = cpu.apic();
    if family >= 6 {
        let base = crate::x86::rdmsr(IA32_APIC_BASE);
        if base & APIC_BASE_ENABLE != 0 {
            let mode = if base & APIC_BASE_X2 != 0 { "x2apic" } else { "xapic" };
            lib::compact_screenln!(screen,
                "SELFTEST APIC cpuid={} base={:#x} mode={} SVR={:#x} LINT0={:#x} timer_active={}",
                cpuid_apic as u8, base, mode,
                lapic_read(LAPIC_SVR), lapic_read(LAPIC_LVT_LINT0),
                lapic_timer_active() as u8,
            );
        } else {
            lib::compact_screenln!(screen,
                "SELFTEST APIC cpuid={} base={:#x} mode=disabled (PIC needs direct INTR)",
                cpuid_apic as u8, base,
            );
        }
    } else {
        lib::compact_screenln!(screen, "SELFTEST APIC pre-P6 (PIC needs direct INTR)");
    }

    // --- 4. CPU timer capabilities — picks the LAPIC-timer calibration path
    // (no PIT means TSC/CPUID is the only fixed reference we have).
    lib::compact_screenln!(screen,
        "SELFTEST CPU vendor={} family={} tsc_deadline={} x2apic_cap={} invtsc={}",
        core::str::from_utf8(&cpu.vendor).unwrap_or("????????????"),
        family, cpu.tsc_deadline() as u8, cpu.x2apic() as u8, cpu.invariant_tsc() as u8,
    );
    if let Some(ratio) = cpu.tsc_ratio {
        lib::compact_screenln!(screen, "SELFTEST TSC den={} num={} crystal_hz={}",
            ratio.denominator, ratio.numerator, ratio.crystal_hz);
    } else {
        lib::compact_screenln!(screen, "SELFTEST TSC ratio unavailable");
    }
    if let Some(frequency) = cpu.frequency {
        lib::compact_screenln!(screen, "SELFTEST CPU base={}MHz max={}MHz bus={}MHz",
            frequency.base_mhz, frequency.max_mhz, frequency.bus_mhz);
    } else {
        lib::compact_screenln!(screen, "SELFTEST CPU frequency unavailable");
    }
}

/// Check the delivery side after `enter_ring1` has set IF. The pre-IRET
/// self-test cannot show whether the CPU accepts the selected timer interrupt
/// and enters our IRQ0 handler.
pub fn timer_delivery_selftest(screen: &mut lib::term::Term) {
    let if_on = crate::x86::interrupts_enabled();
    let (irr, isr, imr) = master_pic_state();
    lib::compact_screenln!(
        screen,
        "SELFTEST IRQ0 delivery count={} IF={} PIC IRR={:02X} ISR={:02X} IMR={:02X}",
        IRQ0_HANDLED.load(Ordering::Relaxed), if_on as u8, irr, isr, imr,
    );
}

// ============================================================================
// IRQ dispatch
// ============================================================================

/// Handle an IRQ: PIC ACK, read hardware data, push typed event to queue.
pub fn handle_irq(regs: &mut Regs) {
    let timestamp_ns = now(false);
    let vector = regs.int_num as u8;
    if vector >= MSI_VECTOR_BASE {
        let source = vector - MSI_VECTOR_BASE;
        { post(Irq::Msi(source), timestamp_ns); }
        // MSI is LAPIC-delivered and edge-triggered.
        lapic_write(LAPIC_EOI, 0);
        return;
    }
    let irq = vector - IRQ_OFFSET;
    if irq == 0 {
        IRQ0_HANDLED.fetch_add(1, Ordering::Relaxed);
        // Before the event loop owns alarms, only a wrapping clock needs
        // another interrupt. The initial delivery-test alarm otherwise ends.
        if !unsafe { ALARM_MODE } && let Some(interval) = clock_maintenance_interval() {
            if lapic_timer_active() {
                let count = (u128::from(interval) * u128::from(unsafe { LAPIC_HZ }))
                    .div_ceil(1_000_000_000).clamp(1, u128::from(u32::MAX)) as u32;
                lapic_write(LAPIC_INIT_COUNT, count);
            } else {
                pit_alarm_count((interval * PIT_INPUT_HZ / 1_000_000_000).clamp(1, 65535) as u16);
            }
        }
    }

    // APIC mode: alarms use the LAPIC timer (vector 0x20 from the local APIC)
    // and keyboard/mouse arrive through the I/O APIC — the 8259 is bypassed
    // entirely. Deferred device IRQs stay masked until their consumer calls
    // `isa_unmask_irq`, just as on the 8259 path. (`lapic_timer_active()` is the
    // APIC-mode flag: it is set iff setup_lapic_timer succeeded.)
    if lapic_timer_active() {
        if !matches!(irq, 0 | 1 | 12) {
            ioapic_set_mask(irq, true);
        }
        lapic_write(LAPIC_EOI, 0);
        match irq {
            0 => {}, // pure wakeup; the execution trap returns to the kernel
            1 => { post(Irq::Key(inb(0x60)), timestamp_ns); },
            12 => {
                if let Some(e) = mouse_packet_byte(inb(0x60)) {
                    { post(e, timestamp_ns); }
                }
            }
            _ => { post(Irq::Hw(irq), timestamp_ns); },
        }
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
        0 => None, // pure wakeup; no event is enqueued
        1 => Some(Irq::Key(inb(0x60))),
        12 => mouse_packet_byte(inb(0x60)),
        _ => Some(Irq::Hw(irq)),
    };

    if let Some(e) = event {
        { post(e, timestamp_ns); }
    }

    // Re-unmask only lines whose device was acked inline above. Generic
    // `Hw` lines are still asserted by their device, so leaving them masked
    // prevents a host-side storm until the guest-visible ack path re-arms.
    let inline_acked = matches!(irq, 0 | 1 | 12);
    if inline_acked {
        outb(data_port, mask);
    }
}

/// Unmask an ISA IRQ previously left masked by `handle_irq`. The device
/// consumer calls this after servicing the interrupt; for passed-through SB,
/// that completion is the guest's virtual PIC EOI. Physical EOI was sent
/// immediately by `handle_irq` on either controller.
pub fn isa_unmask_irq(irq: u8) {
    if lapic_timer_active() {
        ioapic_set_mask(irq, false);
    } else {
        unmask_irq(irq);
    }
}

/// Build an MSI `(message_address, message_data)` that delivers `source` as a
/// private kernel vector and queues `Irq::Msi(source)`. MSI is
/// edge-triggered and LAPIC-delivered, so it needs no PIC mask/unmask and no
/// IOAPIC routing — only that the LAPIC is up. `source` is an identity in the
/// backend's private MSI namespace.
///
/// xAPIC physical-mode format: address `0xFEE0_0000 | (apic_id << 12)`, data =
/// the low-8-bit vector (delivery mode fixed, edge). Returns `None` in PIC-only
/// mode (no LAPIC → MSI cannot be delivered; the device must fall back to a
/// wired line or polling).
pub fn msi_target(source: u8) -> Option<(u64, u32)> {
    if !lapic_timer_active() || source >= MSI_SOURCE_COUNT {
        return None;
    }
    let addr = LAPIC_PHYS | ((bsp_apic_id() as u64) << 12);
    let data = (MSI_VECTOR_BASE + source) as u32;
    Some((addr, data))
}

/// Route and unmask an ISA edge-triggered, active-high line.
pub fn isa_enable_irq(line: u8) {
    if lapic_timer_active() {
        ioapic_route(line, IRQ_OFFSET + line);
    } else {
        unmask_irq(line);
    }
}

/// Frozen calibration for a user-space clock reader. HPET/PIT require kernel
/// access and must never be represented as a TSC clock.
pub fn user_tsc_clock() -> Option<(u64, u64)> {
    let clock = unsafe { CLOCK };
    matches!(clock.source, ClockSource::Tsc).then_some((clock.epoch, clock.ns_mult))
}

/// High-resolution monotonic time in nanoseconds, also sampled at IRQ entry.
/// TSC/64-bit HPET are read-only; PIT2 and 32-bit HPET extension state needs
/// an interrupt-masked cross-core critical section.
pub fn now(init: bool) -> u64 {
    static CLOCK_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static mut PIT2_LAST_COUNT: u16 = 0;
    static mut PIT2_CYCLES: u64 = 0;
    static mut HPET_LAST_COUNTER: u64 = 0;
    static mut HPET_CYCLES: u64 = 0;

    let clock = unsafe { CLOCK };
    if init {
        unsafe {
            match clock.source {
                ClockSource::Tsc => CLOCK.epoch = crate::x86::rdtsc(),
                ClockSource::Hpet if clock.hpet_mask == u64::MAX =>
                    CLOCK.epoch = hpet_counter(clock.hpet_mask),
                ClockSource::Hpet => {
                    HPET_LAST_COUNTER = hpet_counter(clock.hpet_mask);
                    HPET_CYCLES = 0;
                }
                ClockSource::Pit2 => {
                    PIT2_LAST_COUNT = pit2_count();
                    PIT2_CYCLES = 0;
                }
                ClockSource::Uninitialized => {}
            }
        }
        return 0;
    }

    let ticks = match clock.source {
        ClockSource::Tsc => crate::x86::rdtsc().wrapping_sub(clock.epoch),
        ClockSource::Hpet if clock.hpet_mask == u64::MAX =>
            hpet_counter(clock.hpet_mask).wrapping_sub(clock.epoch),
        ClockSource::Hpet => {
            // Interrupt entry now reads this clock too. Protect the shared
            // 32-bit HPET extension just like the PIT extension below.
            let restore_if = crate::x86::interrupts_enabled();
            crate::x86::cli();
            while CLOCK_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                core::hint::spin_loop();
            }
            let total = unsafe {
                let count = hpet_counter(clock.hpet_mask);
                let elapsed = count.wrapping_sub(HPET_LAST_COUNTER) & clock.hpet_mask;
                HPET_LAST_COUNTER = count;
                HPET_CYCLES = HPET_CYCLES.wrapping_add(elapsed);
                HPET_CYCLES
            };
            CLOCK_LOCK.store(false, Ordering::Release);
            if restore_if { crate::x86::sti(); }
            total
        },
        ClockSource::Pit2 => {
            let restore_if = crate::x86::interrupts_enabled();
            crate::x86::cli();
            while CLOCK_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                core::hint::spin_loop();
            }
            let count = pit2_count();
            let total = unsafe {
                let elapsed = PIT2_LAST_COUNT.wrapping_sub(count) as u64;
                PIT2_LAST_COUNT = count;
                PIT2_CYCLES = PIT2_CYCLES.wrapping_add(elapsed);
                PIT2_CYCLES
            };
            CLOCK_LOCK.store(false, Ordering::Release);
            if restore_if { crate::x86::sti(); }
            total
        }
        ClockSource::Uninitialized => 0,
    };
    mul_u64_u64_shr32(ticks, clock.ns_mult)
}

/// Low 64 bits of `(a * b) >> 32`, using only the i686 CPU's native
/// 32x32->64 multiply. Expressing this as `u128` pulls a general wide-multiply
/// routine into every `now()` call and is prohibitively expensive under TCG.
#[inline]
fn mul_u64_u64_shr32(a: u64, b: u64) -> u64 {
    let a0 = u64::from(a as u32);
    let a1 = a >> 32;
    let b0 = u64::from(b as u32);
    let b1 = b >> 32;
    ((a0 * b0) >> 32)
        .wrapping_add(a0 * b1)
        .wrapping_add(a1 * b0)
        .wrapping_add((a1 * b1) << 32)
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

// Alarm state belongs to this CPU. Programming and sleep run in ring 0 with
// interrupts masked; input and elapsed alarms survive the return through ring 1.
#[thread_local]
static mut LAPIC_HZ: u64 = 0;
#[thread_local]
static mut TSC_DEADLINE: bool = false;
#[thread_local]
static mut ALARM_MODE: bool = false;
const IA32_TSC_DEADLINE: u32 = 0x6e0;

#[inline(never)]
pub fn arm_alarm(deadline: Option<u64>) {
    unsafe { ALARM_MODE = true; }
    let current = now(false);
    // Clock wrap maintenance stays internal to the clock driver.
    let deadline = match (deadline, clock_maintenance_interval()) {
        (Some(end), Some(interval)) => Some(end.min(current.saturating_add(interval))),
        (None, Some(interval)) => Some(current.saturating_add(interval)),
        (deadline, None) => deadline,
    };
    if lapic_timer_active() {
        if unsafe { TSC_DEADLINE } {
            lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_VECTOR | (2 << 17));
            unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
            let cycles = deadline.map_or(0, |end| {
                let clock = unsafe { CLOCK };
                let offset = ((u128::from(end) << 32).div_ceil(u128::from(clock.ns_mult)))
                    .min(u128::from(u64::MAX)) as u64;
                clock.epoch.saturating_add(offset).max(crate::x86::rdtsc().saturating_add(1))
            });
            unsafe { crate::x86::wrmsr(IA32_TSC_DEADLINE, cycles); }
        } else {
            lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_VECTOR);
            let count = deadline.map_or(0, |end| {
                (u128::from(end.saturating_sub(current)) * u128::from(unsafe { LAPIC_HZ }))
                    .div_ceil(1_000_000_000).clamp(1, u128::from(u32::MAX)) as u32
            });
            lapic_write(LAPIC_INIT_COUNT, count);
        }
    } else {
        // Channel 0 has no gate pin. Mask its IRQ when disarmed; the next
        // programming replaces its one-shot count before unmasking it.
        outb(MASTER_DATA, inb(MASTER_DATA) | 1);
        if let Some(end) = deadline {
            let count = (u128::from(end.saturating_sub(current)) * u128::from(PIT_INPUT_HZ))
                .div_ceil(1_000_000_000).clamp(1, 65535) as u16;
            pit_alarm_count(count);
            unmask_irq(0);
        }
    }
}

pub fn idle(max_ns: u64) {
    if max_ns == 0 { return; }
    arm_alarm(Some(now(false).saturating_add(max_ns)));
    // INT 80 entered with IF clear; STI/HLT accepts an IRQ atomically.
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)); }
    arm_alarm(None);
}

fn clock_maintenance_interval() -> Option<u64> {
    let clock = unsafe { CLOCK };
    match clock.source {
        ClockSource::Pit2 => Some(20_000_000),
        ClockSource::Hpet if clock.hpet_mask != u64::MAX =>
            Some((u128::from(clock.hpet_mask) * 1_000_000_000
                / u128::from(clock.hpet_hz.max(1)) / 2).clamp(1, u128::from(u64::MAX)) as u64),
        _ => None,
    }
}

/// Immutable BSP calibration for initializing another CPU's local alarm.
#[derive(Clone, Copy)]
pub struct WorkerTimer { hz: u64, deadline: bool }
pub fn worker_timer() -> Option<WorkerTimer> {
    if !lapic_timer_active() || !matches!(unsafe { CLOCK.source }, ClockSource::Tsc) { return None; }
    Some(WorkerTimer { hz: unsafe { LAPIC_HZ }, deadline: unsafe { TSC_DEADLINE } })
}
/// AP ring-0 bring-up; external device interrupts continue to target the BSP.
pub fn init_worker_timer(timer: WorkerTimer) {
    let base = crate::x86::rdmsr(IA32_APIC_BASE);
    unsafe { LAPIC_X2 = base & APIC_BASE_X2 != 0; LAPIC_HZ = timer.hz; TSC_DEADLINE = timer.deadline; }
    lapic_write(LAPIC_SVR, LAPIC_SW_ENABLE | LAPIC_SPURIOUS_VECTOR);
    lapic_write(LAPIC_LVT_LINT0, LVT_MASKED);
    lapic_write(0x360, LVT_MASKED); // LINT1: no firmware NMI routing on workers.
    lapic_write(LAPIC_DIV_CONF, LAPIC_DIV_1);
    lapic_write(LAPIC_LVT_TIMER, LAPIC_TIMER_VECTOR | LVT_MASKED);
    lapic_write(LAPIC_INIT_COUNT, 0);
    unsafe { LAPIC_TIMER_ACTIVE = true; }
}
pub(crate) fn interrupt_processor(processor: u32) {
    if unsafe { LAPIC_X2 } {
        unsafe { crate::x86::wrmsr(0x830, (u64::from(processor) << 32) | u64::from(LAPIC_TIMER_VECTOR)); }
    } else {
        while lapic_read(0x300) & (1 << 12) != 0 { core::hint::spin_loop(); }
        lapic_write(0x310, processor << 24);
        lapic_write(0x300, LAPIC_TIMER_VECTOR);
    }
}
