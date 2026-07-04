//! Per-personality I/O port policy, derived from the platform — the typed
//! replacement for ad-hoc global `allow_io_ports` pokes.
//!
//! The I/O bitmap is hardware mechanism (arch owns it); WHICH ports a thread
//! may touch is kernel policy, rebuilt on every swap-in from three typed
//! inputs — personality, [`platform::Display`], and console focus:
//!
//!   - DOS, focused, real card: the VGA register window (0x3C0 and 0x3DA
//!     stay trapped: AC flip-flop tracking + retrace fabrication), plus any
//!     granted device windows.
//!   - DOS, background: granted device windows only — its VGA programming
//!     traps into the thread's own VgaState model while the focused thread
//!     owns the card.
//!   - Linux / native: nothing, ever. A trapped port from Linux is a fault,
//!     not an emulation request (the personality dispatcher exits the
//!     process on `KE::In`/`KE::Out`).
//!
//! Everything is derived — there is no runtime grant table. The OPL window
//! rides with `platform::Audio::SbPassthrough` for every DOS thread:
//! background FM music keeps playing; the display does not follow focus,
//! audio does not follow it either.

use crate::kernel::platform;
use crate::kernel::thread::Personality;

/// Rebuild the live I/O bitmap for a thread taking the CPU: deny-all
/// baseline, then exactly what its personality + focus state allow. Called
/// on every swap-in (and once for the initial program).
pub fn apply<A: crate::Arch>(machine: &mut A, personality: &Personality<A>, focused: bool) {
    machine.reset_io_bitmap();
    match personality {
        Personality::Dos(_) => {
            if focused && platform::get().display.vga_passthrough() {
                machine.allow_io_ports(0x3C1, 25); // 0x3C1..=0x3D9
                machine.allow_io_ports(0x3DB, 5); // 0x3DB..=0x3DF
            }
            // A real SB implies a real OPL: FM music writes (frequent) go
            // straight to the card; emulated stays trapped so `emu_*`
            // answers FM detection.
            if platform::get().audio.sb_passthrough() {
                machine.allow_io_ports(0x388, 2);
            }
        }
        // Linux: no ports. The deny-all baseline stands.
        Personality::Linux(_) => {}
    }
}
