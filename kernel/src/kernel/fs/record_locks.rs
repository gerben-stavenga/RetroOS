//! Process-owned advisory byte-range locks, independent of a guest ABI.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
static CHANGED: AtomicBool = AtomicBool::new(false);
pub fn notify_changed() {
    CHANGED.store(true, Ordering::Release);
}
pub fn take_changed() -> bool {
    CHANGED.swap(false, Ordering::AcqRel)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileKey(pub u8, pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub file: FileKey,
    pub owner: i32,
    pub kind: Kind,
    pub start: u64,
    /// Exclusive end; u64::MAX means through EOF, including future growth.
    pub end: u64,
}
#[derive(Default)]
pub struct Table {
    records: Vec<Record>,
}
impl Table {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }
    pub fn conflict(&self, request: Record) -> Option<Record> {
        self.records
            .iter()
            .copied()
            .filter(|r| {
                r.file == request.file
                    && r.owner != request.owner
                    && r.start < request.end
                    && request.start < r.end
                    && (r.kind == Kind::Write || request.kind == Kind::Write)
            })
            .min_by_key(|r| (r.start, r.owner))
    }
    pub fn set(&mut self, request: Record, unlock: bool) -> i32 {
        if !unlock && self.conflict(request).is_some() {
            return -11;
        }
        let mut next = Vec::new();
        for r in &self.records {
            if r.file != request.file
                || r.owner != request.owner
                || r.end <= request.start
                || request.end <= r.start
            {
                next.push(*r);
            } else {
                if r.start < request.start {
                    next.push(Record {
                        end: request.start,
                        ..*r
                    });
                }
                if request.end < r.end {
                    next.push(Record {
                        start: request.end,
                        ..*r
                    });
                }
            }
        }
        if !unlock {
            next.push(request);
        }
        next.sort_unstable_by_key(|r| (r.file.0, r.file.1, r.owner, r.start));
        let mut merged: Vec<Record> = Vec::new();
        for r in next {
            if let Some(last) = merged.last_mut()
                && last.file == r.file
                && last.owner == r.owner
                && last.kind == r.kind
                && r.start <= last.end
            {
                last.end = last.end.max(r.end);
            } else {
                merged.push(r);
            }
        }
        self.records = merged;
        0
    }
    /// POSIX close releases all of this process's locks on the file, even
    /// when other descriptors for the same inode remain open.
    pub fn release(&mut self, file: FileKey, owner: i32) {
        self.records.retain(|r| r.file != file || r.owner != owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock(owner: i32, kind: Kind, start: u64, end: u64) -> Record {
        Record {
            file: FileKey(0, 7),
            owner,
            kind,
            start,
            end,
        }
    }
    #[test]
    fn shared_readers_conflict_with_writers_and_mounts_are_independent() {
        let mut t = Table::new();
        assert_eq!(t.set(lock(1, Kind::Read, 0, u64::MAX), false), 0);
        assert_eq!(t.set(lock(2, Kind::Read, 3, 8), false), 0);
        assert_eq!(t.set(lock(2, Kind::Write, 3, 8), false), -11);
        assert_eq!(t.conflict(lock(2, Kind::Write, 3, 8)).unwrap().owner, 1);
        let mut other = lock(2, Kind::Write, 3, 8);
        other.file.0 = 1;
        assert_eq!(t.set(other, false), 0);
        t.release(FileKey(0, 7), 1);
        assert_eq!(t.set(lock(2, Kind::Write, 3, 8), false), 0);
    }
    #[test]
    fn conversion_partial_unlock_and_ranges_above_four_gib() {
        let mut t = Table::new();
        assert_eq!(t.set(lock(1, Kind::Write, 0, u64::MAX), false), 0);
        assert_eq!(t.set(lock(1, Kind::Read, 5, 10), false), 0);
        assert_eq!(t.records.len(), 3);
        assert_eq!(t.set(lock(2, Kind::Read, 5, 10), false), 0);
        assert_eq!(t.set(lock(2, Kind::Read, 9, 11), false), -11);
        let high = 1u64 << 40;
        assert_eq!(t.set(lock(1, Kind::Write, high, high + 10), true), 0);
        assert_eq!(t.set(lock(2, Kind::Write, high, high + 10), false), 0);
        assert_eq!(t.set(lock(2, Kind::Write, high + 9, high + 11), false), -11);
        t.release(FileKey(0, 7), 1);
        t.release(FileKey(0, 7), 2);
        assert!(t.records.is_empty());
    }
}
