//! I/O counters for the profile dump — temporary diagnostics.
//!
//! These count volume reads and request sizes without coupling the diagnostic
//! to a particular filesystem implementation. They distinguish repeated
//! metadata reads from expensive device operations.
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
}

static mut IO: IoStats = IoStats {
    vol_reads: 0,
    vol_sectors: 0,
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

/// Read the counters without disturbing them.
pub fn snapshot() -> IoStats {
    *io()
}

/// Zero the counters — called at the end of each profile dump window so the
/// numbers describe that window, not all of history.
pub fn reset() {
    *io() = IoStats::default();
}
