//! A safe API over lwext4.
//!
//! Every raw entry point in `lwext4_sys` is wrapped exactly once here, and the
//! wrapper owns the discipline that makes the call sound: NUL-terminated paths
//! (a `&CStr`, so it cannot be otherwise), buffer lengths taken from the slice
//! rather than passed alongside it, and handles that close themselves.
//!
//! Callers get no pointers and write no `unsafe`. The `unsafe` that remains
//! lives one line beneath the declaration it guards, which is the point: it is
//! auditable in one sitting instead of smeared across the filesystem logic.
//!
//! ## What this does and does not promise
//!
//! It rules out the ways *we* could cause undefined behaviour: unterminated
//! paths, wrong lengths, use-after-close. It cannot make lwext4 itself correct,
//! and lwext4's device/mount registries are global C state, so this type is
//! neither `Send` nor `Sync` and callers must keep to one thread — the same
//! invariant the rest of the RetroOS filesystem layer already relies on.
//!
//! Device registration is deliberately absent: registering a block device means
//! handing C a struct full of function pointers, which no wrapper can make
//! safe. That stays with the code that builds the callbacks.

#![no_std]

use core::ffi::CStr;
use lwext4_sys as sys;

/// Result of an lwext4 call: `Ok` or the library's errno.
pub type Result<T> = core::result::Result<T, i32>;

fn check(rc: i32) -> Result<()> {
    if rc == sys::EOK { Ok(()) } else { Err(rc) }
}

/// Mount the registered device `dev` at `mount_point`.
pub fn mount(dev: &CStr, mount_point: &CStr, read_only: bool) -> Result<()> {
    check(unsafe { sys::ext4_mount(dev.as_ptr().cast(), mount_point.as_ptr().cast(), read_only) })
}

pub fn umount(mount_point: &CStr) -> Result<()> {
    check(unsafe { sys::ext4_umount(mount_point.as_ptr().cast()) })
}

/// Start journalling (a no-op on a filesystem without one).
pub fn journal_start(mount_point: &CStr) -> Result<()> {
    check(unsafe { sys::ext4_journal_start(mount_point.as_ptr().cast()) })
}

pub fn remove(path: &CStr) -> Result<()> {
    check(unsafe { sys::ext4_fremove(path.as_ptr().cast()) })
}

/// POSIX mode bits, or `None` if the path can't be stat'ed.
pub fn mode_get(path: &CStr) -> Option<u32> {
    let mut mode = 0u32;
    (unsafe { sys::ext4_mode_get(path.as_ptr().cast(), &mut mode) } == sys::EOK).then_some(mode)
}

pub fn mode_set(path: &CStr, mode: u32) -> Result<()> {
    check(unsafe { sys::ext4_mode_set(path.as_ptr().cast(), mode) })
}

/// `(uid, gid)`, or `None` if the path can't be stat'ed.
pub fn owner_get(path: &CStr) -> Option<(u32, u32)> {
    let (mut uid, mut gid) = (0u32, 0u32);
    (unsafe { sys::ext4_owner_get(path.as_ptr().cast(), &mut uid, &mut gid) } == sys::EOK)
        .then_some((uid, gid))
}

pub fn owner_set(path: &CStr, uid: u32, gid: u32) -> Result<()> {
    check(unsafe { sys::ext4_owner_set(path.as_ptr().cast(), uid, gid) })
}

/// Is `path`'s FINAL component itself a symlink? Does not follow it.
pub fn is_symlink(path: &CStr) -> bool {
    unsafe { sys::ext4_inode_exist(path.as_ptr().cast(), sys::EXT4_DE_SYMLINK) == sys::EOK }
}

/// Read a symlink's target into `buf`, returning the byte count.
pub fn readlink(path: &CStr, buf: &mut [u8]) -> Option<usize> {
    let mut rcnt = 0usize;
    // Length comes from the slice, so it cannot disagree with the buffer.
    let rc = unsafe {
        sys::ext4_readlink(path.as_ptr().cast(), buf.as_mut_ptr(), buf.len(), &mut rcnt)
    };
    (rc == sys::EOK).then(|| rcnt.min(buf.len()))
}

/// An open file. Closes itself on drop, so it cannot outlive its handle.
pub struct File(sys::Ext4File);

impl File {
    /// `flags` is an fopen-style mode string: `r`, `w`, `rb+`, …
    pub fn open(path: &CStr, flags: &CStr) -> Result<File> {
        let mut f: sys::Ext4File = unsafe { core::mem::zeroed() };
        check(unsafe { sys::ext4_fopen(&mut f, path.as_ptr().cast(), flags.as_ptr().cast()) })?;
        Ok(File(f))
    }

    /// Read into `buf`, returning the byte count (short at EOF).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut rcnt = 0usize;
        check(unsafe { sys::ext4_fread(&mut self.0, buf.as_mut_ptr(), buf.len(), &mut rcnt) })?;
        Ok(rcnt.min(buf.len()))
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut wcnt = 0usize;
        check(unsafe { sys::ext4_fwrite(&mut self.0, buf.as_ptr(), buf.len(), &mut wcnt) })?;
        Ok(wcnt.min(buf.len()))
    }

    /// Seek from the start of the file.
    pub fn seek_to(&mut self, offset: u64) -> Result<()> {
        check(unsafe { sys::ext4_fseek(&mut self.0, offset as i64, sys::SEEK_SET) })
    }

    pub fn size(&mut self) -> u64 {
        unsafe { sys::ext4_fsize(&mut self.0) }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { sys::ext4_fclose(&mut self.0) };
    }
}

/// One directory entry, copied out of C's buffer so it borrows nothing.
pub struct Entry {
    pub name: [u8; 256],
    pub name_len: usize,
    pub is_dir: bool,
    /// The dirent's own type says symlink — it has NOT been followed, so a
    /// caller wanting the target's nature must resolve it itself.
    pub is_symlink: bool,
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// An open directory. Closes itself on drop.
pub struct Dir(sys::Ext4Dir);

impl Dir {
    pub fn open(path: &CStr) -> Result<Dir> {
        let mut d: sys::Ext4Dir = unsafe { core::mem::zeroed() };
        check(unsafe { sys::ext4_dir_open(&mut d, path.as_ptr().cast()) })?;
        Ok(Dir(d))
    }

    /// Does this path open as a directory? The cheap existence test.
    pub fn exists(path: &CStr) -> bool {
        Dir::open(path).is_ok()
    }
}

impl Iterator for Dir {
    type Item = Entry;

    /// The entry C hands back points into the `Ext4Dir` we own and is
    /// invalidated by the next call, so the name is copied out immediately —
    /// which is also why `Entry` has no lifetime.
    fn next(&mut self) -> Option<Entry> {
        let de = unsafe { sys::ext4_dir_entry_next(&mut self.0) };
        if de.is_null() {
            return None;
        }
        let de = unsafe { &*de };
        let len = (de.name_length as usize).min(de.name.len());
        let mut name = [0u8; 256];
        name[..len].copy_from_slice(&de.name[..len]);
        Some(Entry {
            name,
            name_len: len,
            is_dir: de.inode_type == sys::EXT4_DE_DIR,
            is_symlink: i32::from(de.inode_type) == sys::EXT4_DE_SYMLINK,
        })
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        unsafe { sys::ext4_dir_close(&mut self.0) };
    }
}
