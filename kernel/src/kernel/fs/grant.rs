//! The write-permission rule, and nothing else.
//!
//! File-content writes use the mount's owner/write grant. Namespace changes
//! follow POSIX directory permissions: write and search on the parent, with
//! the sticky bit restricting removal to the directory owner or victim owner.

use crate::kernel::vfs::{Filesystem, Meta};

/// The owner's read/write bits — the grant this rule looks for.
const S_IWUSR: u32 = 0o200;
const S_IRUSR: u32 = 0o400;

/// Who decides whether a write to a mount is allowed. A closed set, so an
/// enum — adding a kind breaks every site that must handle one.
///
/// Centralizing enforcement in the VFS means EVERY mount needs an answer here,
/// not just the ones with ownership bits. Getting this wrong is silent: the
/// first version defaulted everything to "no grant, so read-only" and made the
/// host filesystem and the boot TAR unwritable, which the
/// COMMAND.COM bootstrap caught by failing to compile.
#[derive(Clone, Copy)]
pub enum WriteAccess {
    /// Nothing on this mount may be written.
    None,
    /// File writes use the owner/write grant; namespace changes use POSIX
    /// directory permissions (ext4, which has ownership).
    Granted(Grant),
    /// The backing filesystem governs its own access: the host punch-through
    /// (where the host OS already enforces real permissions) and the RAM
    /// overlay (ours by construction). The VFS adds no rule of its own.
    Delegated,
}

/// RetroOS's identity on one mount: the user owning its home directory.
///
/// That user IS its identity by definition — whatever owns RetroOS's home is
/// what RetroOS is — so nothing needs pinning or an `/etc/passwd` parse.
#[derive(Clone, Copy)]
pub struct Grant {
    uid: u32,
    gid: u32,
}

impl Grant {
    /// Derive the grant from the user owning `home` on `fs`.
    ///
    /// `None` when `home` cannot be stat'ed: an unreadable identity means no
    /// grant at all. Callers must treat that as "nothing is writable" rather
    /// than guessing a uid.
    pub fn from_home(fs: &dyn Filesystem, home: &[u8]) -> Option<Grant> {
        let home = home.strip_suffix(b"/").unwrap_or(home);
        let meta = fs.meta(home)?;
        Some(Grant { uid: meta.uid, gid: meta.gid })
    }

    /// The rule: ours, and owner-writable.
    pub fn allows(&self, m: &Meta) -> bool {
        m.uid == self.uid && m.mode & S_IWUSR != 0
    }

    /// Effective identity is the home owner and primary group.
    pub fn directory_access(&self, meta: &Meta, requested: u32) -> bool {
        if self.uid == 0 { return true; }
        let shift = if meta.uid == self.uid { 6 } else if meta.gid == self.gid { 3 } else { 0 };
        (meta.mode >> shift) & requested == requested
    }

    pub fn may_remove(&self, parent: &Meta, victim: &Meta) -> bool {
        parent.mode & 0o1000 == 0 || self.uid == 0
            || self.uid == parent.uid || self.uid == victim.uid
    }

    /// The mode a newly created object should carry so we can reopen it:
    /// owner read/write (the VFS also stamps our UID).
    pub fn claim_mode(&self, current: u32) -> u32 {
        current | S_IWUSR | S_IRUSR
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }
}

/// The parent directory of `path`, whose permissions govern creating and
/// deleting within it (the Unix rule — the object itself may not exist yet).
/// `None` for an empty path, which has no parent.
pub fn parent_of(path: &[u8]) -> Option<&[u8]> {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    Some(match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[..i],
        None => b"", // mount root
    })
}

#[cfg(test)]
mod namespace_tests {
    use super::*;
    #[test]
    fn directory_modes_and_sticky_ownership() {
        let user = Grant { uid: 1000, gid: 100 };
        for (uid, gid, mode, allowed) in [
            (1000, 200, 0o700, true), (1000, 100, 0o600, false),
            (1000, 100, 0o500, false), (2000, 100, 0o070, true),
            (2000, 200, 0o007, true), (1000, 100, 0o077, false),
        ] {
            assert_eq!(user.directory_access(&Meta { uid, gid, mode }, 3), allowed);
        }
        let foreign = Meta { uid: 2000, gid: 200, mode: 0o444 };
        let owned = Meta { uid: 1000, ..foreign };
        let sticky = Meta { uid: 3000, gid: 300, mode: 0o1777 };
        assert!(!user.may_remove(&sticky, &foreign));
        assert!(user.may_remove(&sticky, &owned));
        assert!(user.may_remove(&Meta { uid: 1000, ..sticky }, &foreign));
        assert!(user.may_remove(&Meta { mode: 0o777, ..sticky }, &foreign));
        assert!(Grant { uid: 0, gid: 0 }.may_remove(&sticky, &foreign));
    }
}
