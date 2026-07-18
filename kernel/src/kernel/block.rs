//! Block-device layer — the `Disk` interface the filesystems read through,
//! and the probe that discovers which disks this machine has.
//!
//! Drivers below implement [`Disk`] and answer "what is here, and how do I
//! move sectors"; they never know which disk is the boot disk. That choice —
//! and the whole mount tree — belongs to `startup`.
//!
//! `dyn` rather than an enum because the transport set is open: ATA, NVMe,
//! virtio and USB mass storage are standards from outside RetroOS, and each
//! new one should be a new file, not an edit to a central type.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use crate::kernel::drivers::{hdd::{self, AtaDisk}, nvme::NvmeDisk};
use lib::println;

/// One block device: a physical disk, an NVMe namespace, or a wrapper around
/// either (see the RAM overlay). Addressing is 512-byte LBAs throughout.
pub trait Disk {
    /// Read `buf.len().div_ceil(512)` sectors from `lba`. Returns sectors read.
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32;
    /// Write `buf.len().div_ceil(512)` sectors at `lba`. Returns sectors written.
    fn write(&self, lba: u64, buf: &[u8]) -> u32;
    /// Capacity in 512-byte sectors.
    fn sectors(&self) -> u64;
    /// Stable short name for logs and mount points: "ata0", "nvme0n1".
    fn name(&self) -> &str;
}

/// The disk the filesystems currently read through.
///
/// TEMPORARY. This is the last remnant of the old single-disk `KIND` global,
/// kept only so the existing `read_sectors(lba, ..)` call sites compile
/// unchanged during this step. It disappears in the next one, when `Volume`
/// carries the device reference to each filesystem and nothing needs to ask
/// "which disk" of a static.
static mut BOOT_DISK: Option<&'static dyn Disk> = None;

fn boot_disk() -> Option<&'static dyn Disk> {
    unsafe { *(&raw const BOOT_DISK) }
}

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
static mut OVERLAY: Option<BTreeMap<u64, Box<[u8; 512]>>> = None;

fn overlay() -> &'static mut Option<BTreeMap<u64, Box<[u8; 512]>>> {
    // A static's address is never null, so `as_mut` always yields Some.
    unsafe { (&raw mut OVERLAY).as_mut().unwrap() }
}

/// Arm the volatile write overlay. Call once at startup, after the platform
/// probe and before any filesystem mounts.
pub fn arm_ram_overlay() {
    *overlay() = Some(BTreeMap::new());
}

/// Discover every disk on this machine, in a stable order: the legacy ATA
/// channels (master then slave) first, then NVMe.
///
/// The order is fixed so results are reproducible across runs; it is *not* a
/// priority ranking, and this function makes no claim about which disk
/// matters. Each disk is leaked to `&'static` at boot lifetime, exactly as
/// `vfs` does with its filesystems.
pub fn probe<A: crate::Arch>(machine: &mut A) -> Vec<&'static dyn Disk> {
    let mut disks: Vec<&'static dyn Disk> = Vec::new();
    for (base, ctrl) in hdd::CHANNELS {
        for drive in 0..2 {
            if let Some(d) = AtaDisk::probe(base, ctrl, drive) {
                disks.push(Box::leak(Box::new(d)));
            }
        }
    }
    if let Some(d) = NvmeDisk::probe(machine) {
        disks.push(Box::leak(Box::new(d)));
    }
    disks
}

/// Probe and select the boot disk. Called once from `startup` before the
/// partition scan.
///
/// TEMPORARY, alongside [`BOOT_DISK`]: this takes the first disk found,
/// reproducing the old ATA-else-NVMe chain exactly. Enumeration already
/// returns all of them; teaching the mount policy to use more than one is a
/// later step.
pub fn init<A: crate::Arch>(machine: &mut A) {
    let disk = probe(machine).first().copied();
    match disk {
        Some(d) => println!("Storage: {} ({} MB)", d.name(), d.sectors() / 2048),
        None => println!("Storage: none detected"),
    }
    unsafe { BOOT_DISK = disk };
}

/// Read `buffer.len().div_ceil(512)` sectors starting at `lba`. Sectors the
/// armed overlay holds shadow the device contents.
pub fn read_sectors(lba: u32, buffer: &mut [u8]) -> u32 {
    let n = match boot_disk() {
        Some(d) => d.read(lba as u64, buffer),
        None => {
            buffer.fill(0);
            0
        }
    };
    if let Some(map) = overlay().as_ref()
        && !map.is_empty()
    {
        for (i, chunk) in buffer.chunks_mut(512).enumerate() {
            if let Some(s) = map.get(&(lba as u64 + i as u64)) {
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
            let sector = lba as u64 + i as u64;
            let mut s = Box::new([0u8; 512]);
            if chunk.len() == 512 {
                s.copy_from_slice(chunk);
            } else {
                // Partial trailing sector: seed with the current contents
                // (overlay-aware read; no map borrow is held across it).
                read_sectors(sector as u32, &mut s[..]);
                s[..chunk.len()].copy_from_slice(chunk);
            }
            overlay().as_mut().unwrap().insert(sector, s);
        }
        return buffer.len().div_ceil(512) as u32;
    }
    match boot_disk() {
        Some(d) => d.write(lba as u64, buffer),
        None => 0,
    }
}
