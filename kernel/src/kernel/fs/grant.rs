//! The write-permission rule, and nothing else.
//!
//! RetroOS may write an object exactly when the object belongs to RetroOS's
//! own group AND carries the group-write bit. That is the whole policy. It is
//! stated here once, as a pure predicate over the facts a filesystem reports
//! (`vfs::Meta`), so it can be read, reasoned about and tested on its own.
//!
//! Two things are deliberately NOT here:
//!
//! * **Enforcement.** `vfs` applies this at the single point every file
//!   operation already passes through. A per-mount decorator was the obvious
//!   alternative and is the wrong shape for a security rule: its failure mode
//!   is silent — mount the raw driver anywhere and the policy is simply gone,
//!   with nothing to grep for. One choke point cannot be forgotten.
//! * **Lookup.** Only a filesystem can read an inode, so it reports `Meta`;
//!   deciding what those numbers mean is this module's job and no driver's.
//!
//! The host grants access per file or directory with `chgrp retroos` +
//! `chmod g+w` — ordinary Unix administration — and RetroOS can touch nothing
//! else, no matter where it is or how it was reached. Symlinks stop mattering:
//! drivers resolve them before reporting, so a link to `/etc/passwd` is
//! refused because passwd isn't ours, not because of where the link pointed.

use crate::kernel::vfs::{Filesystem, Meta};

/// The group's read/write bits — the grant this rule looks for.
const S_IWGRP: u32 = 0o020;
const S_IRGRP: u32 = 0o040;

/// Who decides whether a write to a mount is allowed. A closed set, so an
/// enum — adding a kind breaks every site that must handle one.
///
/// Centralizing enforcement in the VFS means EVERY mount needs an answer here,
/// not just the ones with ownership bits. Getting this wrong is silent: the
/// first version defaulted everything to "no grant, so read-only" and made the
/// host filesystem, the boot TAR and the RAM overlay unwritable, which the
/// COMMAND.COM bootstrap caught by failing to compile.
#[derive(Clone, Copy)]
pub enum WriteAccess {
    /// Nothing on this mount may be written.
    None,
    /// RetroOS's group+write-bit rule applies (ext4, which has ownership).
    Granted(Grant),
    /// The backing filesystem governs its own access: the host punch-through
    /// (where the host OS already enforces real permissions) and the RAM
    /// overlay (ours by construction). The VFS adds no rule of its own.
    Delegated,
}

/// RetroOS's identity on one mount: the group owning its home directory.
///
/// That group IS its identity by definition — whatever owns RetroOS's home is
/// what RetroOS is — so nothing needs pinning or an `/etc/group` parse.
#[derive(Clone, Copy)]
pub struct Grant {
    gid: u32,
}

impl Grant {
    /// Derive the grant from the group owning `home` on `fs`.
    ///
    /// `None` when `home` cannot be stat'ed: an unreadable identity means no
    /// grant at all. Callers must treat that as "nothing is writable" rather
    /// than guessing a gid.
    pub fn from_home(fs: &dyn Filesystem, home: &[u8]) -> Option<Grant> {
        let home = home.strip_suffix(b"/").unwrap_or(home);
        Some(Grant { gid: fs.meta(home)?.gid })
    }

    /// The rule: ours, and group-writable.
    pub fn allows(&self, m: &Meta) -> bool {
        m.gid == self.gid && m.mode & S_IWGRP != 0
    }

    /// The mode a newly created object should carry so we can reopen it: our
    /// group, plus group read/write.
    pub fn claim_mode(&self, current: u32) -> u32 {
        current | S_IWGRP | S_IRGRP
    }

    pub fn gid(&self) -> u32 {
        self.gid
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
