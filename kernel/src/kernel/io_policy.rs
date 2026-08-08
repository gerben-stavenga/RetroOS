//! Per-personality I/O port policy, derived from the platform — the typed
//! replacement for ad-hoc global `allow_io_ports` pokes.
//!
//! The I/O bitmap is hardware mechanism (arch owns it); WHICH ports a thread
//! may touch is kernel policy, rebuilt at every guest entry from the running
//! personality's I/O capabilities and the platform:
//!
//!   - DOS owning the real card: the VGA register window (0x3C0 and 0x3DA
//!     stay trapped: AC flip-flop tracking + retrace fabrication), plus any
//!     granted device windows.
//!   - DOS owning emulated VGA: granted device windows only — VGA programming
//!     traps into the thread's own VgaState model.
//!   - Linux: nothing, ever. A trapped port from Linux is a fault,
//!     not an emulation request (the personality dispatcher exits the
//!     process on `KE::In`/`KE::Out`).
//!
//! Everything is derived — there is no runtime grant table. The OPL window
//! rides with `platform::Audio::SbPassthrough` for every DOS thread:
//! background FM music keeps playing; the display does not follow focus,
//! audio does not follow it either.

use crate::kernel::platform;
use crate::kernel::thread::Personality;

/// Rebuild the live I/O bitmap from the running personality's capabilities:
/// deny everything, then open exactly the windows represented by its state.
///
/// Called only by the CPU-loan boundary immediately before guest execution.
pub(super) fn apply<A: crate::Arch>(machine: &mut A, personality: &Personality<A>) {
    machine.reset_io_bitmap();
    match personality {
        Personality::Dos(_) => {
            if matches!(personality, Personality::Dos(dos)
                if matches!(dos.pc.vga, crate::kernel::dos::DosVga::Native(_)))
            {
                machine.allow_io_ports(0x3C1, 25); // 0x3C1..=0x3D9
                machine.allow_io_ports(0x3DB, 5); // 0x3DB..=0x3DF
                // 0x3C0/0x3DA go direct too when save/restore can recover
                // the AC sequencing state from the card instead of a trap
                // tracker (see `drivers::vga_hw::save`). Trapping these
                // costs the guest a VM86 round-trip per retrace poll — a
                // palette fade is thousands of 0x3DA reads per frame, and a
                // game that waits on retrace can poll tens of thousands of
                // times before it gives up.
                if platform::get().vga_ports_direct() {
                    machine.allow_io_ports(0x3C0, 1);
                    machine.allow_io_ports(0x3DA, 1);
                }
            }
            // Ports are granted to a guest that holds the REAL card, and to
            // no other: an emulated card's window must keep trapping, or the
            // model never sees the traffic it exists to answer. Holding the
            // card is exactly `SbDevice::Native`, so the match that decides
            // this also hands over the wiring the grant needs.
            if let Personality::Dos(dos) = personality
                && let crate::kernel::dos::SbDevice::Native { pt, .. } = &dos.pc.sb.device
            {
                // A real SB implies a real OPL: FM music writes (frequent) go
                // straight to the card.
                machine.allow_io_ports(0x388, 2);
                // The DSP window, port by port: the IOPB is a bitmap, so
                // only what genuinely needs interception traps (see
                // `trap_mask`) and the rest reaches the card directly.
                let mask = pt.trap_mask(&dos.pc.sb.blaster);
                for off in 0..16u16 {
                    if mask & (1 << off) == 0 {
                        machine.allow_io_ports(dos.pc.sb.blaster.io_base + off, 1);
                    }
                }
                // The MPU-401 window the guest declared (BLASTER `P`). In
                // native mode the emulated MPU stands down, so these reach
                // whatever the owner actually has there — a real MPU, a
                // wavetable daughterboard, an external module.
                if dos.pc.mpu.present {
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

/// Execution policy for a kernel-owned video-BIOS excursion. Possession of
/// `NativeVga` is the capability. The hot VGA register window goes direct;
/// less common ROM accesses (including PCI config space) trap and are forwarded
/// synchronously by `BiosDisplayWorkspace`. The ordinary guest-entry boundary rebuilds
/// the next thread's narrower bitmap afterward.
pub(crate) fn apply_bios_display<A: crate::Arch>(
    machine: &mut A,
    _bios_display: &crate::kernel::platform::NativeVga,
) {
    machine.reset_io_bitmap();
    machine.allow_io_ports(0x3C0, 0x20);
}
