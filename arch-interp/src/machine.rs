//! Machine services: FPU blob, port I/O, timing, halt — the interpreter's
//! analogue of `kernel/src/arch/x86.rs` + the timer/IRQ bits of `irq.rs`.

use arch_abi::Irq;
use core::sync::atomic::{AtomicU64, Ordering};

/// FPU/SSE save area. Same 512-byte FXSAVE-shaped blob the kernel saves and
/// restores opaquely. On the interpreter the live FPU state lives inside the
/// software core, so save/restore against this blob are handled by the Vcpu
/// run path (M2); the kernel only ever moves the blob around.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState(pub [u8; 512]);

impl FxState {
    pub const fn zeroed() -> Self { Self([0; 512]) }
    /// No-op on the interpreter (FPU state is the software core's; M2 wires the
    /// real save/restore through `arch_switch_to`).
    pub fn save(&mut self) {}
    pub fn restore(&self) {}
}

/// A zeroed FPU template for seeding a new thread's save area.
pub fn clean_fx_template() -> FxState { FxState::zeroed() }

// ── Port I/O ───────────────────────────────────────────────────────────────
//
// On metal these reach real hardware. The interpreter routes them to its device
// layer (`devices.rs`) — e.g. the ATA disk — so the kernel's own port I/O (the
// `hdd.rs` PIO disk driver) works and `kernel::startup()` runs unchanged. Ports
// with no device behind them read the ISA "no device" value 0xFF and drop
// writes. (Guest-side IN/OUT is a different path — it surfaces as a
// `KernelEvent::In/Out` from `do_arch_execute`.)

pub fn inb(port: u16) -> u8 { crate::devices::port_in(port, 1) as u8 }
pub fn inw(port: u16) -> u16 { crate::devices::port_in(port, 2) as u16 }
pub fn outb(port: u16, value: u8) { crate::devices::port_out(port, 1, value as u32); }
pub fn outw(port: u16, value: u16) { crate::devices::port_out(port, 2, value as u32); }

/// Monotonic cycle counter. Deterministic stand-in for the TSC.
pub fn rdtsc() -> u64 {
    static TSC: AtomicU64 = AtomicU64::new(0);
    TSC.fetch_add(1000, Ordering::Relaxed)
}

/// Power off — exit the host process.
pub fn shutdown() -> ! {
    std::process::exit(0)
}

/// Disable interrupts and halt forever (panic/shutdown failure path).
pub fn halt_forever() -> ! {
    std::process::exit(0)
}

// ── Timer / IRQ queue ────────────────────────────────────────────────────
//
// On metal `get_ticks` reads `TIMER_TICKS`, a 1 kHz counter the real PIT ISR
// bumps; `take_pending_ticks` reports how many of those host ticks the event
// loop hasn't consumed. The virtual PIT (`vpit.rs`) and RTC (`vrtc.rs`) read
// `get_ticks` to compute elapsed input cycles, so the guest sees IRQ0 at its
// programmed rate (18.2 Hz by default) and the BIOS INT 8 stub (`calls.rs`)
// advances `0040:006C`.
//
// The interpreter has no PIT ISR. We must NOT derive this clock from wall time:
// the interpreter runs the guest at full host speed (hundreds of MIPS) with no
// pacing, so a wall-clock 55 ms tick would span tens of millions of guest
// instructions — the guest perceives a multi-hundred-MHz CPU and period
// software overflows its timing loops (Turbo Pascal's CRT delay calibration
// counts loop iterations between ticks into a 16-bit word, then `DIV`s by it —
// too many iterations #DEs with "Runtime error 200"). Instead we anchor the
// clock to *retired guest instructions* (`advance_virtual_time`, called per run
// slice), modelling a fixed ~VIRT_INSTR_PER_MS MIPS CPU. This both fixes the
// calibration overflow and makes timing reproducible run-to-run.

/// Virtual CPU speed: guest instructions per millisecond of guest-perceived
/// time. ~2 MIPS models a 386/486-class machine — slow enough that period
/// delay-calibration loops keep their per-tick counts well inside 16 bits.
const VIRT_INSTR_PER_MS: u64 = 2_000;

/// Retired guest instructions, the source of virtual time.
static VIRT_CYCLES: AtomicU64 = AtomicU64::new(0);

/// Advance virtual time by `instructions` retired in a run slice. Called by the
/// CPU core (`cpu::execute`) after each `emu_start`.
pub fn advance_virtual_time(instructions: u64) {
    VIRT_CYCLES.fetch_add(instructions, Ordering::Relaxed);
}

/// Guest-perceived milliseconds — the interpreter's 1 kHz host tick clock,
/// derived from retired instructions.
pub fn get_ticks() -> u64 {
    VIRT_CYCLES.load(Ordering::Relaxed) / VIRT_INSTR_PER_MS
}

/// Host ticks (ms) elapsed since the previous call. Drives the event loop's
/// `Irq::Tick` pump; the vpit coalesces a burst into one pending IRQ0.
pub fn take_pending_ticks() -> u32 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = get_ticks();
    let last = LAST.swap(now, Ordering::Relaxed);
    now.saturating_sub(last).min(64) as u32
}

pub fn drain(_f: impl FnMut(Irq)) {}

/// Physical free-page count, for diagnostic logging only. The interpreter has
/// no physical frame allocator yet (M3); report 0.
pub fn free_page_count() -> usize { 0 }
