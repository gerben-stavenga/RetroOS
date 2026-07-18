//! The volatile write overlay — a [`Disk`] that wraps a [`Disk`].
//!
//! On real hardware the boot disk is someone's actual home partition, so
//! writes must not reach it. Wrapping the device diverts every write into a
//! kernel-heap map that later reads see through: the filesystems above stay
//! fully writable (lwext4 journals, savegames, configs) while the platter is
//! never touched, and power-off discards everything.
//!
//! This is deliberately NOT a mode flag on the block layer. Wrapping happens
//! once, at composition time in `startup`, and the wrapped disk is then the
//! only reference anyone holds — so the protection is structural. There is no
//! "is the overlay armed?" question for a write path to forget to ask, and no
//! way to address the real device once it has been wrapped away.
//!
//! Each overlay belongs to ONE disk, so a machine can protect its internal
//! drive while writing through to an attached scratch disk. The old global
//! could only be all-or-nothing.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::cell::RefCell;
use super::Disk;

pub struct RamOverlay {
    inner: &'static dyn Disk,
    /// Device-absolute sector → its shadowed contents.
    ///
    /// `RefCell` rather than a lock: the fs layer is single-threaded (the same
    /// invariant `vfs` and `lwext4` already rely on), and no interrupt path
    /// reaches a disk.
    map: RefCell<BTreeMap<u64, Box<[u8; 512]>>>,
}

impl RamOverlay {
    pub fn wrap(inner: &'static dyn Disk) -> RamOverlay {
        RamOverlay { inner, map: RefCell::new(BTreeMap::new()) }
    }
}

impl Disk for RamOverlay {
    /// Read from the device, then let any shadowed sectors win.
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        let n = self.inner.read(lba, buf);
        let map = self.map.borrow();
        if !map.is_empty() {
            for (i, chunk) in buf.chunks_mut(512).enumerate() {
                if let Some(s) = map.get(&(lba + i as u64)) {
                    chunk.copy_from_slice(&s[..chunk.len()]);
                }
            }
        }
        n
    }

    /// Absorb the write. The device is never touched.
    fn write(&self, lba: u64, buf: &[u8]) -> u32 {
        for (i, chunk) in buf.chunks(512).enumerate() {
            let sector = lba + i as u64;
            let mut s = Box::new([0u8; 512]);
            if chunk.len() == 512 {
                s.copy_from_slice(chunk);
            } else {
                // Partial trailing sector: seed with what is currently there
                // (overlay-aware, so a previous partial write isn't lost).
                // Read before borrowing the map — `read` borrows it too.
                self.read(sector, &mut s[..]);
                s[..chunk.len()].copy_from_slice(chunk);
            }
            self.map.borrow_mut().insert(sector, s);
        }
        buf.len().div_ceil(512) as u32
    }

    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    /// The wrapped disk's own name — an overlay is a policy applied to a
    /// device, not a different device, and logs/mount points should not shift
    /// depending on whether writes persist.
    fn name(&self) -> &str {
        self.inner.name()
    }
}
