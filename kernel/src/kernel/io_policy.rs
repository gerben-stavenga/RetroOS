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
                // The DSP window, port by port: the IOPB is a bitmap, so
                // only what genuinely needs interception traps (see
                // `trap_mask`) and the rest reaches the card directly.
                if let Personality::Dos(dos) = personality {
                    let mask = dos.pc.sb.trap_mask();
                    for off in 0..16u16 {
                        if mask & (1 << off) == 0 {
                            machine.allow_io_ports(dos.pc.sb.io_base + off, 1);
                        }
                    }
                }
                // The MPU-401 window the guest declared (BLASTER `P`). In
                // native mode the emulated MPU stands down, so these reach
                // whatever the owner actually has there — a real MPU, a
                // wavetable daughterboard, an external module.
                if let Personality::Dos(dos) = personality
                    && dos.pc.mpu.present
                {
                    machine.allow_io_ports(dos.pc.mpu.base, 2);
                }
                // The 8237 windows are NEVER granted, in any configuration:
                // vdma is not a channel relabeler but an ADDRESS translator —
                // the guest programs DOS-physical buffer addresses while its
                // pages are COW-relocated, so a direct write would make the
                // card DMA the wrong memory. Strap alignment can make the
                // channel numbers an identity; it cannot make the addresses
                // one. (Tried 2026-07-26 for Pinball Fantasies' count-poll
                // storm; it silenced the card. The poll cost is real but
                // must be attacked inside the trap, not by ungating it.)
            }
        }
        // Linux: no ports. The deny-all baseline stands.
        Personality::Linux(_) => {}
    }
}
