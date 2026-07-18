//! Writable ext4 via the lwext4 C library — replaces the read-only ext4-view
//! `Ext4Fs`. lwext4 does real journaled read+write, so savegames, logs and
//! setup files persist across reboots.
//!
//! Backend-agnostic, exactly like the old `Ext4Fs`: the lwext4 C is linked into
//! both backends (metal `//third_party/lwext4:lwext4_obj`, hosted
//! `@lwext4//:lwext4_host`), and the runtime `Media` probe decides when this is
//! mounted. The freestanding C-runtime symbols lwext4 needs on metal
//! (malloc/str*/qsort) come from `arch-metal::cshim`; hosted uses the host libc.
//!
//! lwext4's device/mount registry is global C state, so each mount gets a
//! unique device name + lwext4 mount point (`/m0/`, `/m1/`, …); this wrapper
//! prepends that prefix to every VFS path. The block device is device-absolute
//! (lwext4 folds `part_offset` into the block id it hands `bread`/`bwrite`), so
//! the callbacks go straight to `block::read/write_sectors`.

extern crate alloc;

use alloc::boxed::Box;
use crate::kernel::block::Volume;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};
use core::ffi::CStr;

mod bridge;



/// Does the ext partition at `part_lba` look like a Linux root (`/etc`+`/usr`)?
/// Read-only mount → check → unmount, leaving lwext4's global registry clean so
/// the real root mount can reuse the same partition. Used only to disambiguate
/// a multi-ext disk (a laptop's data partition vs its real root).
pub fn is_linux_root(vol: &Volume) -> bool {
    const DEV: &CStr = c"ext4probe";
    const MP: &CStr = c"/probe/";
    if !bridge::register_device(vol, DEV) {
        return false;
    }
    if lwext4::mount(DEV, MP, true).is_err() {
        bridge::unregister_device(DEV);
        return false;
    }
    let has = lwext4::Dir::exists(c"/probe/etc") && lwext4::Dir::exists(c"/probe/usr");
    let _ = lwext4::umount(MP);
    bridge::unregister_device(DEV);
    has
}

/// Append `n` as decimal ASCII.
fn push_decimal(out: &mut Vec<u8>, n: usize) {
    if n >= 10 {
        push_decimal(out, n / 10);
    }
    out.push(b'0' + (n % 10) as u8);
}

/// partition), matching how the kernel would resolve `/..` == `/`.
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut segs: Vec<&[u8]> = Vec::new();
    for seg in path.split(|&b| b == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = Vec::with_capacity(path.len());
    for (i, s) in segs.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(s);
    }
    out
}

/// Leak a NUL-terminated copy of `s` (boot-lifetime), returning its pointer.
fn leak_cstr(s: &[u8]) -> &'static CStr {
    let mut v: Vec<u8> = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    // NUL pushed above, so this is infallible.
    CStr::from_bytes_with_nul(Box::leak(v.into_boxed_slice())).unwrap()
}

/// An open lwext4 file plus whether writes to it are permitted (the file lives
/// inside the writable subtree). `write` consults this so a handle opened
/// outside the writable root can never mutate the disk.
struct OpenFile {
    file: lwext4::File,
    writable: bool,
}

/// How a filesystem is mounted. A closed set RetroOS defines, so an enum.
///
/// This used to be inferred from the mount slot (`read_only = index != 0`),
/// which made a registry housekeeping number decide a security property.
/// The caller states it now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountMode {
    /// Writable as far as the MOUNT is concerned. Whether a given caller may
    /// write a given object is policy, decided by `fs::grant`, not here.
    ReadWrite,
    /// Read-only at the lwext4 level. The VFS refuses writes to such a mount
    /// as well, so this is defence in depth, not the only barrier.
    ReadOnly,
}

/// The lwext4-backed filesystem — one instance per mounted ext4 partition.
pub struct Lwext4Fs {
    /// lwext4 mount-point prefix incl. trailing slash, no NUL, e.g. `b"/m0/"`.
    mp: Vec<u8>,
    open_files: RefCell<BTreeMap<u64, OpenFile>>,
    next_handle: Cell<u64>,
}

impl Lwext4Fs {
    /// Register + mount the ext4 filesystem filling `vol`.
    ///
    /// `slot` is nothing but a name: lwext4's device and mount-point registries
    /// are global C state keyed by string, so each mount needs a distinct one.
    /// It carries no policy — see [`MountMode`] for that — and no identity;
    /// the device this filesystem lives on travels in `vol`.
    pub fn new(vol: Volume, slot: usize, mode: MountMode) -> Result<Self, &'static str> {
        // Decimal, so slots past 9 keep working; the prefix stays short
        // because it is prepended to every path this mount resolves.
        let mut name = Vec::new();
        name.extend_from_slice(b"ext4dev");
        push_decimal(&mut name, slot);
        let dev_name = leak_cstr(&name);

        let mut mp = Vec::new();
        mp.extend_from_slice(b"/m");
        push_decimal(&mut mp, slot);
        mp.push(b'/');
        let mp_c = leak_cstr(&mp);

        if !bridge::register_device(&vol, dev_name) {
            return Err("ext4_device_register failed");
        }
        if lwext4::mount(dev_name, mp_c, mode == MountMode::ReadOnly).is_err() {
            bridge::unregister_device(dev_name);
            return Err("ext4_mount failed");
        }
        // Journal recovery + transactions (transparent no-op if the fs has no
        // journal). NOTE: no write-back caching — writes go through
        // synchronously so they are durable at close without an explicit
        // flush/umount on the (abrupt) kernel shutdown path.
        let _ = lwext4::journal_start(mp_c);

        let fs = Lwext4Fs {
            mp,
            open_files: RefCell::new(BTreeMap::new()),
            next_handle: Cell::new(1),
        };
        Ok(fs)
    }

    /// Build a NUL-terminated lwext4 absolute path (`<mp><rel>\0`) in `buf`,
    /// following symlinks first — so callers address the physical object.
    /// Use [`cpath_nofollow`] where the link ITSELF is the subject.
    fn cpath<'b>(&self, rel: &[u8], buf: &'b mut [u8; 320]) -> Option<&'b CStr> {
        let real = self.real(rel);
        self.cpath_nofollow(&real, buf)
    }

    /// Build a NUL-terminated lwext4 absolute path (`<mp><rel>\0`) in `buf`.
    fn cpath_nofollow<'b>(&self, rel: &[u8], buf: &'b mut [u8; 320]) -> Option<&'b CStr> {
        let mut n = 0;
        for &b in self.mp.iter().chain(rel.iter()) {
            if n >= buf.len() - 1 {
                return None;
            }
            buf[n] = b;
            n += 1;
        }
        // Drop a trailing slash (lwext4 wants none for files); keep bare mp.
        if n > self.mp.len() && buf[n - 1] == b'/' {
            n -= 1;
        }
        buf[n] = 0;
        // The NUL is in place by construction, so this cannot fail — and from
        // here on the path is a &CStr, which the safe API requires. No call
        // site can hand lwext4 an unterminated string.
        CStr::from_bytes_with_nul(&buf[..=n]).ok()
    }

    fn stat_mode(cpath: &CStr, is_dir: bool) -> u16 {
        if let Some(mode) = lwext4::mode_get(cpath) {
            (mode & 0xFFF) as u16
        } else if is_dir {
            0o755
        } else {
            0o644
        }
    }

    /// Is `rel`'s final component a symlink? (No-follow.)
    fn is_symlink(&self, rel: &[u8]) -> bool {
        let mut buf = [0u8; 320];
        match self.cpath_nofollow(rel, &mut buf) {
            Some(cpath) => lwext4::is_symlink(cpath),
            None => false,
        }
    }

    /// Read `rel`'s symlink target (mount-relative in, raw target out).
    fn readlink(&self, rel: &[u8]) -> Option<Vec<u8>> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath_nofollow(rel, &mut buf)?;
        let mut tgt = [0u8; 256];
        let rcnt = lwext4::readlink(cpath, &mut tgt)?;
        Some(tgt[..rcnt].to_vec())
    }

    /// Resolve every symlink in `rel` to the physical path lwext4 can open.
    ///
    /// lwext4's own lookup does NOT follow symlinks (only `ext4_readlink` reads
    /// them), so a symlinked directory otherwise surfaces as a "file" whose
    /// contents are its target string — a real `home/retroos` full of symlinks
    /// listed as garbage. Resolve here, once, and hand lwext4 a real path.
    ///
    /// Targets are interpreted INSIDE this mount: a leading `/` means the mount
    /// root (the ext4 partition's own root), not the VFS root — the same frame
    /// the link was authored in when the partition was someone's `/`. Bounded by
    /// `MAX_HOPS` so a symlink loop terminates instead of hanging.
    fn resolve(&self, rel: &[u8]) -> Option<Vec<u8>> {
        const MAX_HOPS: u32 = 16;
        let mut path = normalize(rel);
        let mut hops = 0;
        loop {
            // Leftmost symlink component (or the whole path).
            let mut at = None;
            for (i, &b) in path.iter().enumerate() {
                if b == b'/' && i > 0 && self.is_symlink(&path[..i]) {
                    at = Some(i);
                    break;
                }
            }
            if at.is_none() && !path.is_empty() && self.is_symlink(&path) {
                at = Some(path.len());
            }
            let Some(i) = at else { return Some(path) };
            hops += 1;
            if hops > MAX_HOPS {
                return None; // loop, or a chain too deep to be real
            }
            let target = self.readlink(&path[..i])?;
            let mut next = Vec::with_capacity(path.len() + target.len());
            if target.first() == Some(&b'/') {
                next.extend_from_slice(&target[1..]); // mount-absolute
            } else {
                // Relative to the link's own directory.
                let parent = path[..i].iter().rposition(|&b| b == b'/').unwrap_or(0);
                next.extend_from_slice(&path[..parent]);
                if !next.is_empty() {
                    next.push(b'/');
                }
                next.extend_from_slice(&target);
            }
            next.extend_from_slice(&path[i..]); // the untraversed remainder
            path = normalize(&next);
        }
    }

    /// `resolve`, falling back to the original path when it resolves to nothing
    /// (a broken/looping link) so callers keep their previous behaviour: lwext4
    /// reports the miss, we don't invent one.
    fn real(&self, rel: &[u8]) -> Vec<u8> {
        self.resolve(rel).unwrap_or_else(|| rel.to_vec())
    }

    fn alloc_handle(&self, file: lwext4::File, writable: bool) -> u64 {
        let h = self.next_handle.get();
        self.next_handle.set(h.wrapping_add(1));
        self.open_files.borrow_mut().insert(h, OpenFile { file, writable });
        h
    }
}

impl Filesystem for Lwext4Fs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath(path, &mut buf)?;
        // Open as permissively as the MOUNT permits — read-write if lwext4
        // allows it, else read-only. Whether this CALLER may write is not the
        // driver's question; the policy layer above decides that.
        // One open, not two: the mode that succeeded IS the answer to whether
        // this handle can write. (An earlier version re-opened the file just to
        // compute that flag, doubling every open.)
        let (mut file, writable) = match lwext4::File::open(cpath, c"r+b") {
            Ok(f) => (f, true),
            Err(_) => (lwext4::File::open(cpath, c"rb").ok()?, false),
        };
        let size = file.size() as u32;
        let mode = Self::stat_mode(cpath, false);
        let handle = self.alloc_handle(file, writable);
        Some(Vnode { handle, size, mode })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let mut files = self.open_files.borrow_mut();
        let Some(of) = files.get_mut(&handle) else {
            return 0;
        };
        if of.file.seek_to(offset as u64).is_err() {
            return 0;
        }
        match of.file.read(buf) {
            Ok(n) => n as i32,
            Err(_) => 0,
        }
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        let mut files = self.open_files.borrow_mut();
        let Some(of) = files.get_mut(&handle) else {
            return -9;
        };
        // Reject writes to a handle outside the writable root (-30 = EROFS).
        if !of.writable {
            return -30;
        }
        if of.file.seek_to(offset as u64).is_err() {
            return -5;
        }
        match of.file.write(data) {
            Ok(n) => n as i32,
            Err(_) => -5,
        }
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath(path, &mut buf)?;
        // "wb": create + truncate for writing.
        let file = lwext4::File::open(cpath, c"wb").ok()?;
        let handle = self.alloc_handle(file, true);
        Some(Vnode { handle, size: 0, mode: 0o664 })
    }

    /// lwext4 has a real create — so a `None` from [`Self::create`] means
    /// DENIED, not "unsupported". The VFS must surface it as an error instead
    /// of silently substituting a RAM file.
    fn supports_create(&self) -> bool {
        true
    }

    fn readdir(&self, dir: &[u8], index: usize) -> Option<DirEntry> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath(dir, &mut buf)?;
        let d = lwext4::Dir::open(cpath).ok()?;
        let mut i = 0usize;
        let mut result = None;
        for e in d {
            let name = e.name();
            if name == b"." || name == b".." || name.is_empty() {
                continue;
            }
            if i == index {
                let mut rel = Vec::with_capacity(dir.len() + 1 + name.len());
                rel.extend_from_slice(dir);
                if !rel.is_empty() && *rel.last().unwrap() != b'/' {
                    rel.push(b'/');
                }
                rel.extend_from_slice(name);
                // A symlink must present its TARGET's identity: the dirent type
                // says SYMLINK, and reporting that as a plain file made a
                // symlinked directory list as a corrupt "file" whose bytes are
                // the target path. Resolve, then classify off the real object.
                let is_dir = if e.is_symlink {
                    self.dir_exists(&rel)
                } else {
                    e.is_dir
                };
                let name_len = name.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len,
                    size: 0,
                    is_dir,
                    mode: if is_dir { 0o755 } else { 0o644 },
                };
                de.name[..name_len].copy_from_slice(&name[..name_len]);
                // Size/mode for regular files: open the (resolved) child.
                if !is_dir {
                    let mut child = [0u8; 320];
                    if let Some(cchild) = self.cpath(&rel, &mut child) {
                        if let Ok(mut f) = lwext4::File::open(cchild, c"rb") {
                            de.size = f.size() as u32;
                            de.mode = Self::stat_mode(cchild, false);
                        }
                    }
                }
                result = Some(de);
                break;
            }
            i += 1;
        }
        result // the Dir closed itself on drop
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return false;
        };
        lwext4::Dir::exists(cpath)
    }

    /// Report the inode's owner and mode. Symlinks are followed: a write hits
    /// the TARGET, so the target's facts are the relevant ones.
    fn meta(&self, path: &[u8]) -> Option<crate::kernel::vfs::Meta> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath(path, &mut buf)?;
        let (uid, gid) = lwext4::owner_get(cpath)?;
        let mode = lwext4::mode_get(cpath)?;
        Some(crate::kernel::vfs::Meta { uid, gid, mode })
    }

    fn set_meta(&self, path: &[u8], uid: u32, gid: u32, mode: u32) -> bool {
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return false;
        };
        lwext4::owner_set(cpath, uid, gid).is_ok() && lwext4::mode_set(cpath, mode).is_ok()
    }

    fn clunk(&self, handle: u64) {
        // Dropping the entry closes the file — the handle cannot outlive it.
        self.open_files.borrow_mut().remove(&handle);
    }

    fn remove(&self, path: &[u8]) -> i32 {
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return -1;
        };
        if lwext4::remove(cpath).is_ok() {
            0
        } else {
            -1
        }
    }
}

