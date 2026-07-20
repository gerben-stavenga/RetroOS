//! I/O counters for the profile dump — temporary diagnostics.
//!
//! These exist to answer one question that static reading of the code cannot:
//! when a DOS directory listing takes tens of milliseconds PER ENTRY on an
//! NVMe SSD, is the kernel issuing a huge NUMBER of device reads, or a small
//! number of very SLOW ones? Those have opposite fixes — a cache versus the
//! driver — and the ratio below separates them in a single run.
//!
//! Deliberately counts only, no cycle timing: `rdtsc` lives on the `Arch`
//! trait and `Volume::read` has no `machine`, so timing here would mean
//! widening the arch boundary for a diagnostic. The counts are enough:
//!
//!   reads/entry ≈ 1000  →  metadata is being re-read; the 8-buffer lwext4
//!                          bcache (8 KiB against a 1 KiB block size) thrashes.
//!   reads/entry ≈ 10    →  few reads, so each must cost ~milliseconds; look
//!                          at the driver (NVMe's 4 KiB-per-command poll loop).
//!
//! `resolve`/`symlink_probes` test the other suspect independently: every
//! `is_symlink` inside `Lwext4Fs::resolve` is a full lookup from the mount
//! root, so one "path resolution" is really O(path depth) of them.
//!
//! Single-threaded kernel/event-loop context, same argument as `SLICE_PARTS`
//! in `startup`: plain statics, no locking. Increments are unconditional —
//! one add against a device read is not measurable — but only the profile
//! dump reads them.

/// Counter slots. Kept as an array (not named fields) so a snapshot is one
/// copy and reset is one store, matching the `SLICE_PARTS` idiom.
#[derive(Clone, Copy, Default)]
pub struct IoStats {
    /// `Volume::read` calls — every read the filesystems make, post-cache.
    pub vol_reads: u64,
    /// Sectors those calls asked for, to show the average request size.
    pub vol_sectors: u64,
    /// `bdev_bread` calls from lwext4 (≈ `vol_reads` unless something else
    /// is reading the disk; a divergence names that other reader).
    pub breads: u64,
    /// `ext4_dir_open` calls inside `readdir` — one per batch if the cookie
    /// is doing its job, one per ENTRY if it regressed.
    pub dir_opens: u64,
    /// Directory entries handed back by `readdir`. The denominator.
    pub dirents: u64,
    /// `Lwext4Fs::resolve` calls (one per path made physical).
    pub resolves: u64,
    /// `is_symlink` probes inside those — the O(depth) amplifier.
    pub symlink_probes: u64,
    /// `lwext4::stat` calls (size+mode+mtime in one inode read).
    pub stats: u64,
}

static mut IO: IoStats = IoStats {
    vol_reads: 0,
    vol_sectors: 0,
    breads: 0,
    dir_opens: 0,
    dirents: 0,
    resolves: 0,
    symlink_probes: 0,
    stats: 0,
};

fn io() -> &'static mut IoStats {
    let p = &raw mut IO;
    unsafe { &mut *p }
}

pub fn vol_read(sectors: u64) {
    let s = io();
    s.vol_reads += 1;
    s.vol_sectors += sectors;
}

pub fn bread() {
    io().breads += 1;
}

pub fn dir_open() {
    io().dir_opens += 1;
}

pub fn dirents(n: u64) {
    io().dirents += n;
}

pub fn resolve() {
    io().resolves += 1;
}

pub fn symlink_probe() {
    io().symlink_probes += 1;
}

pub fn stat() {
    io().stats += 1;
}

/// Read the counters without disturbing them.
pub fn snapshot() -> IoStats {
    *io()
}

/// Zero the counters — called at the end of each profile dump window so the
/// numbers describe that window, not all of history.
pub fn reset() {
    *io() = IoStats::default();
}
