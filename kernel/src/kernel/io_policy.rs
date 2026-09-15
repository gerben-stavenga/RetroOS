//! Per-personality I/O port policy, derived from the platform — the typed
//! replacement for ad-hoc global `allow_io_ports` pokes.
//!
//! The I/O bitmap is hardware mechanism (arch owns it); WHICH ports a thread
//! may touch is kernel policy, rebuilt at every guest entry from the running
//! personality's I/O capabilities and the platform:
//!
//!   - DOS owning the real card: the complete VGA register window is direct,
//!     including 0x3C0 and 0x3DA, plus any granted device windows.
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

use crate::kernel::thread::Personality;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PolicyKey {
    native_vga: bool,
    native_sb: bool,
    sb_base: u16,
    sb_trap_mask: u16,
    mpu_base: u16,
}

/// Compact identity of everything that can alter a guest's direct-I/O grant.
/// Reading this on every entry is cheap; rebuilding 124 bitmap bytes and all
/// of the individual port grants is not.
pub(super) fn key<A: crate::Arch>(
    personality: &Personality<A>,
    bios: &crate::kernel::bios_display::BiosDisplayWorkspace<A>,
) -> PolicyKey {
    let mut key = PolicyKey {
        native_vga: false,
        native_sb: false,
        sb_base: 0,
        sb_trap_mask: 0,
        mpu_base: 0,
    };
    if let Personality::Dos(dos) = personality {
        key.native_vga = dos.pc.vga.native_legacy_vga(bios);
        if let crate::kernel::dos::SbDevice::Native { pt, .. } = &dos.pc.sb.device {
            key.native_sb = true;
            key.sb_base = dos.pc.sb.blaster.io_base;
            key.sb_trap_mask = pt.trap_mask(&dos.pc.sb.blaster);
            if dos.pc.mpu.present {
                key.mpu_base = dos.pc.mpu.base;
            }
        }
    }
    key
}

/// Rebuild the live I/O bitmap from the running personality's capabilities:
/// deny everything, then open exactly the windows represented by its state.
///
/// Called only by the CPU-loan boundary immediately before guest execution.
pub(super) fn for_key(key: PolicyKey) -> arch_abi::IoPolicy {
    let mut policy = arch_abi::IoPolicy::deny_all();
    if key.native_vga {
        policy.allow(0x3C1, 25); // 0x3C1..=0x3D9
        policy.allow(0x3DB, 5); // 0x3DB..=0x3DF
        policy.allow(0x3C0, 1);
        policy.allow(0x3DA, 1);
    }
    // Ports are granted to a guest that holds the REAL card, and to no other:
    // an emulated card's window must keep trapping, or the model never sees
    // the traffic it exists to answer.
    if key.native_sb {
        policy.allow(0x388, 2);
        for off in 0..16u16 {
            if key.sb_trap_mask & (1 << off) == 0 {
                policy.allow(key.sb_base + off, 1);
            }
        }
        if key.mpu_base != 0 {
            policy.allow(key.mpu_base, 2);
        }
        // The 8237 windows remain trapped: vdma translates guest-physical
        // addresses, so direct DMA-controller access would target wrong pages.
    }
    policy
}

/// Execution policy for a kernel-owned video-BIOS excursion. Possession of
/// `NativeVga` is the capability. The hot VGA register window goes direct;
/// less common ROM accesses (including PCI config space) trap and are forwarded
/// synchronously by `BiosDisplayWorkspace`. The ordinary guest-entry boundary rebuilds
/// the next thread's narrower bitmap afterward.
pub(crate) fn bios_display(
    _bios_display: &crate::kernel::platform::VgaCap,
) -> arch_abi::IoPolicy {
    let mut policy = arch_abi::IoPolicy::deny_all();
    // Native VBE firmware may use the Bochs/QEMU-compatible DISPI index/data
    // window. The BIOS workspace is trusted and isolated; trapping these
    // instructions back through the kernel turns every bank change into nested
    // monitor exits. Three byte ports cover word accesses at 1CEh and 1CFh.
    policy.allow(0x1CE, 3);
    policy.allow(0x3C0, 0x20);
    policy
}
