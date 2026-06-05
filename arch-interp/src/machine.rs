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
// M2 will drive these from the instruction-counted run slices (deterministic
// timer ticks) and surface keyboard/mouse via the virtual device layer. For
// now there are no queued events.

pub fn get_ticks() -> u64 { 0 }
pub fn take_pending_ticks() -> u32 { 0 }
pub fn drain(_f: impl FnMut(Irq)) {}

/// Physical free-page count, for diagnostic logging only. The interpreter has
/// no physical frame allocator yet (M3); report 0.
pub fn free_page_count() -> usize { 0 }
