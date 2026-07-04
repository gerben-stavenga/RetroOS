//! Block-device facade — one `read_sectors` for the filesystems, backed by
//! whichever disk this machine actually has.
//!
//! Detection happens once at startup, below the filesystem layer, so
//! tarfs/ext4fs/MBR code is identical on every platform:
//!   - ATA PIO (legacy BIOS machines, QEMU/Bochs/86Box IDE, the interpreter's
//!     emulated controller) — probed first, bounded, no hang on absent ports.
//!   - NVMe (UEFI-class machines: the run_uefi.sh mock, modern laptops).

use core::sync::atomic::{AtomicU8, Ordering};
use crate::kernel::{hdd, nvme};
use lib::println;

const NONE: u8 = 0;
const ATA: u8 = 1;
const NVME: u8 = 2;

static KIND: AtomicU8 = AtomicU8::new(NONE);

/// Probe and select the boot disk. Called once from `startup` before the
/// partition scan.
pub fn init<A: crate::Arch>(arch: &mut A) {
    if hdd::probe() {
        hdd::reset(); // needed when booted via GRUB (controller left idle)
        KIND.store(ATA, Ordering::Relaxed);
        println!("Storage: ATA (PIO)");
    } else if nvme::init(arch) {
        KIND.store(NVME, Ordering::Relaxed);
        println!("Storage: NVMe");
    } else {
        println!("Storage: none detected");
    }
}

/// Read `buffer.len().div_ceil(512)` sectors starting at `lba`.
pub fn read_sectors(lba: u32, buffer: &mut [u8]) -> u32 {
    match KIND.load(Ordering::Relaxed) {
        ATA => hdd::read_sectors(lba, buffer),
        NVME => nvme::read_sectors(lba, buffer),
        _ => {
            buffer.fill(0);
            0
        }
    }
}
