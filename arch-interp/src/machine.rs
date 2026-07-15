//! Machine services: FPU blob, port I/O, timing, halt — the interpreter's
//! analogue of `kernel/src/arch/x86.rs` + the timer/IRQ bits of `irq.rs`.

use arch_abi::Irq;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// FPU/SSE save area. Same 512-byte FXSAVE-shaped blob the kernel saves and
/// restores opaquely. On the interpreter the live FPU state lives inside the
/// software core, so save/restore against this blob are handled by the Vcpu
/// run path (M2); the kernel only ever moves the blob around.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState(pub [u8; 512]);

impl Default for FxState {
    fn default() -> Self { Self::zeroed() }
}

impl FxState {
    pub const fn zeroed() -> Self { Self([0; 512]) }
    /// No-op on the interpreter (FPU state is the software core's; M2 wires the
    /// real save/restore through `arch_switch_to`).
    pub fn save(&mut self) {}
    pub fn restore(&self) {}
}

/// A clean FPU template for seeding a new thread's save area — like metal's
/// boot-time `fxsave` snapshot, NOT all-zero: MXCSR=0 leaves every SSE
/// exception unmasked, so the first flag-setting SSE op in a fresh thread
/// (glibc's SSE memchr/strlen) raises #XM (Exception 19) on the KVM engine.
/// x87 FCW likewise defaults to 0x037F.
pub fn clean_fx_template() -> FxState {
    let mut fx = FxState::zeroed();
    fx.0[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
    fx.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
    fx
}

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
pub fn inl(port: u16) -> u32 { crate::devices::port_in(port, 4) }
/// Bulk word read (`rep insw` on metal). Hosted has no exit to amortize, so
/// the loop IS the primitive.
pub fn insw(port: u16, buf: &mut [u16]) {
    for w in buf.iter_mut() {
        *w = crate::devices::port_in(port, 2) as u16;
    }
}
pub fn outb(port: u16, value: u8) { crate::devices::port_out(port, 1, value as u32); }
pub fn outw(port: u16, value: u16) { crate::devices::port_out(port, 2, value as u32); }
/// Bulk word write (`rep outsw` on metal). Hosted has no exit to amortize, so
/// the loop IS the primitive — the write-direction twin of [`insw`].
pub fn outsw(port: u16, buf: &[u16]) {
    for &w in buf.iter() {
        crate::devices::port_out(port, 2, w as u32);
    }
}
pub fn outl(port: u16, value: u32) { crate::devices::port_out(port, 4, value); }

/// Monotonic cycle counter. Deterministic stand-in for the TSC (TCG engine).
#[cfg(feature = "tcg")]
pub fn rdtsc() -> u64 {
    static TSC: AtomicU64 = AtomicU64::new(0);
    TSC.fetch_add(1000, Ordering::Relaxed)
}

/// The real TSC (KVM engine): guest RDTSC executes natively (CR4.TSD=0), so
/// the kernel-side reading must come from the same clock to stay coherent.
#[cfg(feature = "kvm")]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
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
/// time. ~6 MIPS models a mid-range 486 — slow enough that period
/// delay-calibration loops keep their per-tick counts inside 16 bits (the
/// real-hardware "Runtime error 200" cliff is Pentium-class, ~100 MIPS),
/// fast enough that a 206 Hz game timer ISR (Duke3D's OPL music service,
/// hundreds of port I/Os per tick) completes well within its tick interval.
/// At the previous 2 MIPS the Duke3D demo loop structurally overran the
/// interval: every tick landed mid-chain, the excursion nesting only ever
/// grew, and DOS/4GW died with error 2002 (transfer stack overflow).
#[cfg(feature = "tcg")]
const VIRT_INSTR_PER_MS: u64 = 6_000;

/// Retired guest instructions, the source of virtual time.
#[cfg(feature = "tcg")]
static VIRT_CYCLES: AtomicU64 = AtomicU64::new(0);

/// Advance virtual time by `instructions` retired in a run slice. Called by the
/// CPU core (`cpu::execute`) after each `emu_start`.
#[cfg(feature = "tcg")]
pub fn advance_virtual_time(instructions: u64) {
    VIRT_CYCLES.fetch_add(instructions, Ordering::Relaxed);
}

/// Guest-perceived milliseconds — the interpreter's 1 kHz host tick clock,
/// derived from retired instructions.
#[cfg(feature = "tcg")]
pub fn get_ticks() -> u64 {
    VIRT_CYCLES.load(Ordering::Relaxed) / VIRT_INSTR_PER_MS
}

/// Guest-perceived milliseconds on the KVM engine: real elapsed time. The
/// instruction-anchored rationale above is TCG-specific — TCG throughput is
/// wildly variable, so wall time there desyncs from retired work. Under KVM
/// the guest runs at genuine native speed, exactly like metal, where the PIT
/// counts real milliseconds; DOS calibration loops behave as on real (fast)
/// hardware.
#[cfg(feature = "kvm")]
pub fn get_ticks() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

/// Host ticks (ms) elapsed since the previous call. Drives the event loop's
/// `Irq::Tick` pump; the vpit coalesces a burst into one pending IRQ0.
pub fn take_pending_ticks() -> u32 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = get_ticks();
    let last = LAST.swap(now, Ordering::Relaxed);
    now.saturating_sub(last).min(64) as u32
}

// Host-posted input events (keyboard, …) awaiting delivery to the kernel event
// loop — the interpreter's analogue of metal's `irq.rs` QUEUE that a real
// keyboard IRQ pushes into. The hosted `main` owns the *source* (a stdin reader
// that translates terminal bytes to PC scancodes); arch just provides the queue
// + `drain`, so the kernel sees identical `Irq::Key` events on both backends.
static INPUT_QUEUE: std::sync::Mutex<std::collections::VecDeque<Irq>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());

// The CPU's INTR line — our `cpu->interrupt_request`. The CPU core's block hook
// (`cpu::execute`) checks `irq_line()` before each basic block, exactly like
// QEMU's `cpu_handle_interrupt` before each TB, and bails to the kernel (which
// injects via `deliver_pm_irq`) when it's asserted and the guest has IF=1.
//
// Two independent contributors, each cleared by its owner so neither can wedge
// the line: host input awaiting `drain` (set by `post_irq`, cleared by `drain` —
// the only contributor for the Linux/tty path), and the kernel's virtual PIC
// (set/cleared by `set_irq_line` from DOS `raise_pending`).
static INPUT_PENDING: AtomicBool = AtomicBool::new(false);
static VPIC_LINE: AtomicBool = AtomicBool::new(false);

/// Assert/deassert the CPU INTR line from the kernel's virtual PIC.
pub fn set_irq_line(asserted: bool) {
    VPIC_LINE.store(asserted, Ordering::Relaxed);
}

/// Read the INTR line (CPU core, per basic block — two cheap atomic loads).
#[inline]
pub(crate) fn irq_line() -> bool {
    INPUT_PENDING.load(Ordering::Relaxed) || VPIC_LINE.load(Ordering::Relaxed)
}

/// Post a hardware-input event from the host side (called off the CPU thread,
/// e.g. by main's stdin reader). Mirrors a device asserting an IRQ on metal:
/// queue the event and raise the input line so the CPU bails out to service it.
/// The flag is set under the queue lock so it stays consistent with `drain`.
pub fn post_irq(irq: Irq) {
    if let Ok(mut q) = INPUT_QUEUE.lock() {
        q.push_back(irq);
        INPUT_PENDING.store(true, Ordering::Relaxed);
    }
}

/// Drain queued input events into the kernel event loop. Collect under the lock
/// then dispatch unlocked, so `f` (kernel keyboard handling) can't deadlock the
/// poster.
pub fn drain(mut f: impl FnMut(Irq)) {
    let events: std::vec::Vec<Irq> = match INPUT_QUEUE.lock() {
        Ok(mut q) => {
            let v = q.drain(..).collect();
            // Clear under the lock, atomically with emptying the queue, so a
            // concurrent `post_irq` can't be lost (it re-asserts under the lock).
            INPUT_PENDING.store(false, Ordering::Relaxed);
            v
        }
        Err(_) => return,
    };
    for e in events {
        f(e);
    }
}

/// Physical free-page count, for diagnostic logging only. The interpreter has
/// no physical frame allocator yet (M3); report 0.
pub fn free_page_count() -> usize { 0 }
