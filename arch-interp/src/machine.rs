//! Machine services: FPU blob, port I/O, timing, halt — the interpreter's
//! analogue of `kernel/src/arch/x86.rs` + the timer/IRQ bits of `irq.rs`.

use arch_abi::Irq;
#[cfg(feature = "tcg")]
use core::sync::atomic::Ordering;
#[cfg(feature = "tcg")]
use core::sync::atomic::AtomicU64;

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
    /// real save/restore through `Core::switch_fx`).
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
// layer (`devices.rs`), so the kernel's own port I/O (the
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

/// Power off — exit the host process.
pub fn shutdown() -> ! {
    if crate::suite_control::enabled() {
        if let Some((w, h, pixels)) = crate::vga::peek_frame() {
            crate::screendump::write_suite_frame(w, h, &pixels);
        }
    }
    std::process::exit(0)
}

/// Disable interrupts and halt forever (panic/shutdown failure path).
pub fn halt_forever() -> ! {
    std::process::exit(0)
}

// Hosted engines share one monotonic host clock and bounded host wait.
static INPUT_READY: std::sync::Condvar = std::sync::Condvar::new();

pub fn idle(max_time: core::time::Duration) {
    if max_time.is_zero() { return; }
    let wake = INPUT_WAKE.lock().unwrap();
    drop(INPUT_READY.wait_timeout(wake, max_time).unwrap());
}

pub fn now() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed().as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

// Input data is delivered directly to the device owner. Only interruption of
// a running/waiting CPU belongs to the backend.
static INPUT_SINK: std::sync::OnceLock<fn(Irq, u64)> = std::sync::OnceLock::new();
pub fn install_input_sink(sink: fn(Irq, u64)) {
    assert!(INPUT_SINK.set(sink).is_ok(), "input sink already installed");
}
static INPUT_WAKE: std::sync::Mutex<()> = std::sync::Mutex::new(());


// New host arrivals interrupt TCG at its next block boundary. Each execute
// snapshots this sequence, so historical input never interrupts a later run.
#[cfg(feature = "tcg")]
static INPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "tcg")]
pub(crate) fn input_sequence() -> u64 { INPUT_SEQUENCE.load(Ordering::Acquire) }

/// Post a hardware-input event from the host side (called off the CPU thread,
/// e.g. by main's stdin reader). Mirrors a device asserting an IRQ on metal:
/// deliver the data to its owner and interrupt any running or waiting CPU.
pub fn post_irq(irq: Irq) {
    let timestamp_ns = now();
    if let Some(sink) = INPUT_SINK.get() { sink(irq, timestamp_ns); }
    let _wake = INPUT_WAKE.lock().unwrap();
    #[cfg(feature = "tcg")]
    INPUT_SEQUENCE.fetch_add(1, Ordering::Release);
    INPUT_READY.notify_one();
    #[cfg(feature = "kvm")]
    crate::kvm::kick();
}
