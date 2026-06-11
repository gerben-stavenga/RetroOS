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
//! Grants (e.g. the OPL window once SB passthrough engages) are dynamic but
//! few; they apply to every DOS thread — background music keeps playing,
//! the display does not follow.

use crate::kernel::platform;
use crate::kernel::thread::Personality;
use arch_abi::Arch;

/// Dynamically granted DOS port windows (device passthrough). Fixed table:
/// grants are rare (OPL today, maybe SB DSP/mixer later).
static mut GRANTS: [(u16, u16); 4] = [(0, 0); 4];

/// Grant a port window to the DOS personality (all DOS threads) and open it
/// in the live bitmap immediately — grants happen while emulating a DOS
/// port access, so the running thread is necessarily DOS.
pub fn grant_dos_ports(machine: &mut crate::TheArch, port: u16, count: u16) {
    unsafe {
        let g = &mut *(&raw mut GRANTS);
        if let Some(slot) = g.iter_mut().find(|s| **s == (0, 0) || **s == (port, count)) {
            *slot = (port, count);
        } else {
            panic!("io_policy: grant table full");
        }
    }
    machine.allow_io_ports(port, count as usize);
}

/// Rebuild the live I/O bitmap for a thread taking the CPU: deny-all
/// baseline, then exactly what its personality + focus state allow. Called
/// on every swap-in (and once for the initial program).
pub fn apply(machine: &mut crate::TheArch, personality: &Personality, focused: bool) {
    machine.reset_io_bitmap();
    match personality {
        Personality::Dos(_) => {
            if focused && platform::get().display.vga_passthrough() {
                machine.allow_io_ports(0x3C1, 25); // 0x3C1..=0x3D9
                machine.allow_io_ports(0x3DB, 5); // 0x3DB..=0x3DF
            }
            unsafe {
                for &(p, c) in (&*(&raw const GRANTS)).iter() {
                    if c != 0 {
                        machine.allow_io_ports(p, c as usize);
                    }
                }
            }
        }
        // Linux: no ports. The deny-all baseline stands.
        Personality::Linux(_) => {}
    }
}
