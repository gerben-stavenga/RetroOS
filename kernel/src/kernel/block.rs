//! Block-device facade — one `read_sectors` for the filesystems, backed by
//! whichever disk this machine actually has.
//!
//! Detection happens once at startup, below the filesystem layer, so
//! tarfs/lwext4/MBR code is identical on every platform:
//!   - ATA PIO (legacy BIOS machines, QEMU/Bochs/86Box IDE, the interpreter's
//!     emulated controller) — probed first, bounded, no hang on absent ports.
//!   - NVMe (UEFI-class machines: the run_uefi.sh mock, modern laptops).

use alloc::{boxed::Box, collections::BTreeMap};
use core::sync::atomic::{AtomicU8, Ordering};
use crate::kernel::{hdd, nvme};
use lib::println;

const NONE: u8 = 0;
const ATA: u8 = 1;
const NVME: u8 = 2;

static KIND: AtomicU8 = AtomicU8::new(NONE);

/// Volatile write overlay — the real-hardware safety net. When armed (real
/// metal, where the disk is someone's actual home partition), `write_sectors`
/// diverts every sector into this kernel-heap map and `read_sectors` patches
/// them back over the device reads: the filesystems above stay fully writable
/// (lwext4 journals, savegames, configs), but the device itself is never
/// written and power-off discards everything. QEMU/hosted runs — where the
/// disk is a disposable image file — leave it unarmed and write through.
///
/// Single kernel thread (same invariant as the fs layer above); accessed via
/// `&raw mut` like the other kernel statics.
static mut OVERLAY: Option<BTreeMap<u32, Box<[u8; 512]>>> = None;

fn overlay() -> &'static mut Option<BTreeMap<u32, Box<[u8; 512]>>> {
    // A static's address is never null, so `as_mut` always yields Some.
    unsafe { (&raw mut OVERLAY).as_mut().unwrap() }
}

/// Arm the volatile write overlay. Call once at startup, after the platform
/// probe and before any filesystem mounts.
pub fn arm_ram_overlay() {
    *overlay() = Some(BTreeMap::new());
}

/// Probe and select the boot disk. Called once from `startup` before the
/// partition scan.
pub fn init<A: crate::Arch>(machine: &mut A) {
    if hdd::probe() {
        hdd::reset(); // needed when booted via GRUB (controller left idle)
        KIND.store(ATA, Ordering::Relaxed);
        println!("Storage: ATA (PIO)");
    } else if nvme::init(machine) {
        KIND.store(NVME, Ordering::Relaxed);
        println!("Storage: NVMe");
    } else {
        println!("Storage: none detected");
    }
}

/// Read `buffer.len().div_ceil(512)` sectors starting at `lba`. Sectors the
/// armed overlay holds shadow the device contents.
pub fn read_sectors(lba: u32, buffer: &mut [u8]) -> u32 {
    let n = match KIND.load(Ordering::Relaxed) {
        ATA => hdd::read_sectors(lba, buffer),
        NVME => nvme::read_sectors(lba, buffer),
        _ => {
            buffer.fill(0);
            0
        }
    };
    if let Some(map) = overlay().as_ref()
        && !map.is_empty()
    {
        for (i, chunk) in buffer.chunks_mut(512).enumerate() {
            if let Some(s) = map.get(&(lba + i as u32)) {
                chunk.copy_from_slice(&s[..chunk.len()]);
            }
        }
    }
    n
}

/// Write `buffer.len().div_ceil(512)` sectors starting at `lba` — into the
/// volatile overlay when armed (real metal), through to the device otherwise.
/// Returns sectors written (0 = no device).
pub fn write_sectors(lba: u32, buffer: &[u8]) -> u32 {
    if overlay().is_some() {
        for (i, chunk) in buffer.chunks(512).enumerate() {
            let sector = lba + i as u32;
            let mut s = Box::new([0u8; 512]);
            if chunk.len() == 512 {
                s.copy_from_slice(chunk);
            } else {
                // Partial trailing sector: seed with the current contents
                // (overlay-aware read; no map borrow is held across it).
                read_sectors(sector, &mut s[..]);
                s[..chunk.len()].copy_from_slice(chunk);
            }
            overlay().as_mut().unwrap().insert(sector, s);
        }
        return buffer.len().div_ceil(512) as u32;
    }
    match KIND.load(Ordering::Relaxed) {
        ATA => hdd::write_sectors(lba, buffer),
        NVME => nvme::write_sectors(lba, buffer),
        _ => 0,
    }
}
