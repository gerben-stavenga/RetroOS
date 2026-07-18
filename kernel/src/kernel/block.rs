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

/// A contiguous extent on a disk — what a filesystem reads through.
///
/// This is the unit the rest of the kernel handles: it names the device, where
/// the extent starts, and — crucially — how long it is. Nothing above needs to
/// ask a global "which disk"; whoever holds a `Volume` already knows.
///
/// Addressing is VOLUME-RELATIVE and bounds-checked, so a filesystem cannot
/// read past its own extent into whatever follows on the disk.
#[derive(Clone, Copy)]
pub struct Volume {
    disk: &'static dyn Disk,
    start: u64,
    /// Length of the extent in 512-byte sectors.
    pub sectors: u64,
}

impl Volume {
    /// The whole disk as one volume — for partition-table scans, which by
    /// definition address the device rather than any partition on it.
    pub fn whole(disk: &'static dyn Disk) -> Volume {
        Volume { disk, start: 0, sectors: disk.sectors() }
    }

    /// An extent within `disk`, clamped to the device's real capacity so a
    /// bogus partition entry can't manufacture reach the hardware lacks.
    pub fn new(disk: &'static dyn Disk, start: u64, sectors: u64) -> Volume {
        let sectors = sectors.min(disk.sectors().saturating_sub(start));
        Volume { disk, start, sectors }
    }

    /// The disk this extent lives on.
    pub fn disk(&self) -> &'static dyn Disk {
        self.disk
    }

    /// Read `buf.len().div_ceil(512)` sectors from volume-relative `lba`.
    /// Returns sectors actually read from the device.
    ///
    /// Anything past the end of the extent reads as ZEROS rather than as the
    /// neighbouring partition's bytes. That is the whole point of carrying the
    /// length: a filesystem that miscalculates an offset gets an obviously
    /// empty block, not plausible garbage from somewhere else on the disk.
    pub fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        let want = buf.len().div_ceil(512) as u64;
        let avail = self.sectors.saturating_sub(lba).min(want);
        let n = ((avail * 512) as usize).min(buf.len());
        let (inside, past_end) = buf.split_at_mut(n);
        past_end.fill(0);
        if inside.is_empty() {
            return 0;
        }
        let got = self.disk.read(self.start + lba, inside);
        apply_overlay(self.start + lba, inside);
        got
    }

    /// Write `buf.len().div_ceil(512)` sectors at volume-relative `lba`.
    /// Bytes past the end of the extent are DROPPED, not written to whatever
    /// follows. Returns sectors written.
    pub fn write(&self, lba: u64, buf: &[u8]) -> u32 {
        let want = buf.len().div_ceil(512) as u64;
        let avail = self.sectors.saturating_sub(lba).min(want);
        let n = ((avail * 512) as usize).min(buf.len());
        if n == 0 {
            return 0;
        }
        write_through(self, lba, &buf[..n])
    }
}

/// Volatile write overlay — the real-hardware safety net. When armed (real
/// metal, where the disk is someone's actual home partition), `Volume::write`
/// diverts every sector into this kernel-heap map and `Volume::read` patches
/// them back over the device reads: the filesystems above stay fully writable
/// (lwext4 journals, savegames, configs), but the device itself is never
/// written and power-off discards everything. QEMU/hosted runs — where the
/// disk is a disposable image file — leave it unarmed and write through.
///
/// Keyed by DEVICE-ABSOLUTE sector, and still one map for the whole system —
/// which is only correct while a single disk is in use. It becomes a `Disk`
/// that wraps a `Disk`, composed per-device by startup, in a later step.
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

/// Patch armed-overlay sectors over a freshly read buffer. `abs` is the
/// device-absolute LBA of `buf`'s first sector.
fn apply_overlay(abs: u64, buf: &mut [u8]) {
    if let Some(map) = overlay().as_ref()
        && !map.is_empty()
    {
        for (i, chunk) in buf.chunks_mut(512).enumerate() {
            if let Some(s) = map.get(&(abs + i as u64)) {
                chunk.copy_from_slice(&s[..chunk.len()]);
            }
        }
    }
}

/// The write half: into the volatile overlay when armed (real metal), through
/// to the device otherwise. `lba` is volume-relative; the overlay is keyed by
/// device-absolute sector.
fn write_through(vol: &Volume, lba: u64, buf: &[u8]) -> u32 {
    let abs = vol.start + lba;
    if overlay().is_some() {
        for (i, chunk) in buf.chunks(512).enumerate() {
            let sector = abs + i as u64;
            let mut s = Box::new([0u8; 512]);
            if chunk.len() == 512 {
                s.copy_from_slice(chunk);
            } else {
                // Partial trailing sector: seed with the current contents
                // (overlay-aware read; no map borrow is held across it).
                vol.read(lba + i as u64, &mut s[..]);
                s[..chunk.len()].copy_from_slice(chunk);
            }
            overlay().as_mut().unwrap().insert(sector, s);
        }
        return buf.len().div_ceil(512) as u32;
    }
    vol.disk.write(abs, buf)
}
