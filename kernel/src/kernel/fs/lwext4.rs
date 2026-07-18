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
use core::ffi::c_void;

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};

const EOK: i32 = 0;
const SEEK_SET: u32 = 0;
/// POSIX permission bits we care about: the group's read/write bits — the
/// grant RetroOS looks for (`chmod g+w`).
const S_IWGRP: u32 = 0o020;
const S_IRGRP: u32 = 0o040;

const EXT4_DE_DIR: u8 = 2;
const EXT4_DE_SYMLINK: i32 = 7;

// ── lwext4 on-disk-facing C structs (repr(C), field order per the headers) ──

#[repr(C)]
struct Ext4BlockdevIface {
    open: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    bread: Option<unsafe extern "C" fn(*mut Ext4Blockdev, *mut u8, u64, u32) -> i32>,
    bwrite: Option<unsafe extern "C" fn(*mut Ext4Blockdev, *const u8, u64, u32) -> i32>,
    close: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    lock: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    unlock: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    ph_bsize: u32,
    ph_bcnt: u64,
    ph_bbuf: *mut u8,
    ph_refctr: u32,
    bread_ctr: u32,
    bwrite_ctr: u32,
    p_user: *mut c_void,
}

#[repr(C)]
struct Ext4Blockdev {
    bdif: *mut Ext4BlockdevIface,
    part_offset: u64,
    part_size: u64,
    bc: *mut c_void,
    lg_bsize: u32,
    lg_bcnt: u64,
    cache_write_back: u32,
    fs: *mut c_void,
    journal: *mut c_void,
}

#[repr(C)]
struct Ext4File {
    mp: *mut c_void,
    inode: u32,
    flags: u32,
    fsize: u64,
    fpos: u64,
}

#[repr(C)]
struct Ext4Direntry {
    inode: u32,
    entry_length: u16,
    name_length: u8,
    inode_type: u8,
    name: [u8; 255],
}

#[repr(C)]
struct Ext4Dir {
    f: Ext4File,
    de: Ext4Direntry,
    next_off: u64,
}

unsafe extern "C" {
    fn ext4_device_register(bd: *mut Ext4Blockdev, dev_name: *const u8) -> i32;
    fn ext4_mount(dev_name: *const u8, mount_point: *const u8, read_only: bool) -> i32;
    fn ext4_journal_start(mount_point: *const u8) -> i32;
    fn ext4_fopen(file: *mut Ext4File, path: *const u8, flags: *const u8) -> i32;
    fn ext4_fread(file: *mut Ext4File, buf: *mut u8, size: usize, rcnt: *mut usize) -> i32;
    fn ext4_fwrite(file: *mut Ext4File, buf: *const u8, size: usize, wcnt: *mut usize) -> i32;
    fn ext4_fclose(file: *mut Ext4File) -> i32;
    fn ext4_fseek(file: *mut Ext4File, offset: i64, origin: u32) -> i32;
    fn ext4_fsize(file: *mut Ext4File) -> u64;
    fn ext4_fremove(path: *const u8) -> i32;
    fn ext4_dir_open(dir: *mut Ext4Dir, path: *const u8) -> i32;
    fn ext4_dir_close(dir: *mut Ext4Dir) -> i32;
    fn ext4_dir_entry_next(dir: *mut Ext4Dir) -> *const Ext4Direntry;
    fn ext4_mode_get(path: *const u8, mode: *mut u32) -> i32;
    fn ext4_mode_set(path: *const u8, mode: u32) -> i32;
    fn ext4_owner_get(path: *const u8, uid: *mut u32, gid: *mut u32) -> i32;
    fn ext4_owner_set(path: *const u8, uid: u32, gid: u32) -> i32;
    fn ext4_readlink(path: *const u8, buf: *mut u8, bufsize: usize, rcnt: *mut usize) -> i32;
    fn ext4_umount(mount_point: *const u8) -> i32;
    fn ext4_device_unregister(dev_name: *const u8) -> i32;
    /// No-follow check: EOK iff `path`'s final component is itself a symlink
    /// (ext4_generic_open2 with the SYMLINK filetype doesn't chase it).
    fn ext4_inode_exist(path: *const u8, ftype: i32) -> i32;
}

/// Does the ext partition at `part_lba` look like a Linux root (`/etc`+`/usr`)?
/// Read-only mount → check → unmount, leaving lwext4's global registry clean so
/// the real root mount can reuse the same partition. Used only to disambiguate
/// a multi-ext disk (a laptop's data partition vs its real root).
pub fn is_linux_root(vol: &Volume) -> bool {
    unsafe fn dir_exists_c(cpath: *const u8) -> bool {
        let mut d: Ext4Dir = unsafe { core::mem::zeroed() };
        if unsafe { ext4_dir_open(&mut d, cpath) } == EOK {
            unsafe { ext4_dir_close(&mut d) };
            true
        } else {
            false
        }
    }
    let Some(part_size) = fs_extent(vol) else {
        return false;
    };
    unsafe {
        let bdev = Box::leak(Box::new(Ext4Blockdev {
            bdif: new_iface(*vol),
            part_offset: 0, // the Volume IS the partition; ids are relative to it
            part_size,
            bc: core::ptr::null_mut(),
            lg_bsize: 0,
            lg_bcnt: 0,
            cache_write_back: 0,
            fs: core::ptr::null_mut(),
            journal: core::ptr::null_mut(),
        }));
        let dev: *const u8 = c"ext4probe".as_ptr().cast();
        let mp: *const u8 = c"/probe/".as_ptr().cast();
        if ext4_device_register(bdev, dev) != EOK {
            return false;
        }
        if ext4_mount(dev, mp, true) != EOK {
            ext4_device_unregister(dev);
            return false;
        }
        let has = dir_exists_c(c"/probe/etc".as_ptr().cast()) && dir_exists_c(c"/probe/usr".as_ptr().cast());
        ext4_umount(mp);
        ext4_device_unregister(dev);
        has
    }
}

// ── The block-device bridge: lwext4 ↔ RetroOS `block` layer ─────────────────
// `bread`/`bwrite` receive DEVICE-ABSOLUTE block ids (lwext4 already folded in
// `part_offset`), and `ph_bsize` is 512, so the id is the LBA directly.
//
// Which DEVICE those ids address comes from the mount itself: lwext4 hands
// every callback the `Ext4Blockdev` it was invoked for, and that struct's
// interface carries our `Volume` in its `p_user` slot. Nothing here consults a
// global — two mounts on two different disks stay distinct.

/// The mount's volume, recovered from the callback's own device pointer.
unsafe fn vol_of(bdev: *mut Ext4Blockdev) -> &'static Volume {
    unsafe { &*((*(*bdev).bdif).p_user as *const Volume) }
}

unsafe extern "C" fn bdev_open(_bdev: *mut Ext4Blockdev) -> i32 {
    EOK
}
unsafe extern "C" fn bdev_close(_bdev: *mut Ext4Blockdev) -> i32 {
    EOK
}
unsafe extern "C" fn bdev_bread(bdev: *mut Ext4Blockdev, buf: *mut u8, blk_id: u64, blk_cnt: u32) -> i32 {
    // Sparse holes are zero-filled inside `ext4_fread` itself (our lwext4 patch
    // adds the hole guard to the aligned/direct and tail paths that upstream
    // omits — only its head path had it), so a hole never reaches the block
    // layer here. This is a plain device read.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, blk_cnt as usize * 512) };
    unsafe { vol_of(bdev) }.read(blk_id, slice);
    EOK
}
unsafe extern "C" fn bdev_bwrite(bdev: *mut Ext4Blockdev, buf: *const u8, blk_id: u64, blk_cnt: u32) -> i32 {
    let slice = unsafe { core::slice::from_raw_parts(buf, blk_cnt as usize * 512) };
    unsafe { vol_of(bdev) }.write(blk_id, slice);
    EOK
}

// Each mount gets its OWN interface: its own scratch block buffer, and its own
// `Volume` in `p_user` for the callbacks to route on. The shared static these
// replace was safe only by the single-threaded-boot argument, and it could not
// have described two mounts on two different disks at all.
fn new_iface(vol: Volume) -> *mut Ext4BlockdevIface {
    let bbuf: &'static mut [u8; 512] = Box::leak(Box::new([0u8; 512]));
    let vol: &'static Volume = Box::leak(Box::new(vol));
    Box::leak(Box::new(Ext4BlockdevIface {
        open: Some(bdev_open),
        bread: Some(bdev_bread),
        bwrite: Some(bdev_bwrite),
        close: Some(bdev_close),
        lock: None,
        unlock: None,
        ph_bsize: 512,
        ph_bcnt: vol.sectors,
        ph_bbuf: bbuf.as_mut_ptr(),
        ph_refctr: 0,
        bread_ctr: 0,
        bwrite_ctr: 0,
        p_user: vol as *const Volume as *mut c_void,
    }))
}

/// Leak a NUL-terminated copy of `s` (boot-lifetime), returning its pointer.
/// The filesystem's true extent, read from its own superblock (1024 B into the
/// partition = sector +2): `s_blocks_count × block_size`. `None` = no ext
/// superblock there.
///
/// This MUST be exact, not a guess. lwext4 takes `part_size` as gospel: it sets
/// `lg_bcnt = part_size / block_size` (the fs's logical block count) and EINVALs
/// every access past it (`ext4_blockdev.c` :126, :224, :324, :394) — but nothing
/// validates it against the superblock at mount time. So a `part_size` that is
/// too small mounts CLEANLY and then silently fails every read beyond it: a real
/// laptop root (flex_bg scatters inode tables and directory blocks across the
/// whole partition) mounts and lists as EMPTY. The old hard-coded 128 GiB was
/// invisible only because the built image's ext4 partition is 1 GiB.
/// The extent lwext4 may address, in bytes.
///
/// Two sources now disagree in principle, so both get consulted: the PARTITION
/// TABLE says how much disk belongs to this filesystem, and the SUPERBLOCK says
/// how much of it the filesystem claims. The smaller wins — a superblock
/// claiming more than its partition holds is corrupt or misread, and honouring
/// it would let lwext4 address a neighbour's sectors.
///
/// Before the table's extent reached this layer, the superblock was the only
/// source and therefore had to be exactly right (see below). It is now a
/// cross-check.
fn fs_extent(vol: &Volume) -> Option<u64> {
    let from_sb = part_size_from_superblock(vol)?;
    let from_table = vol.sectors * 512;
    if from_sb > from_table {
        crate::println!(
            "ext4: superblock claims {} bytes but the partition holds {}; clamping",
            from_sb, from_table);
    }
    Some(from_sb.min(from_table))
}

fn part_size_from_superblock(vol: &Volume) -> Option<u64> {
    let mut sb = [0u8; 512];
    vol.read(2, &mut sb);
    let rd32 = |off: usize| u32::from_le_bytes(sb[off..off + 4].try_into().unwrap());
    if u16::from_le_bytes([sb[0x38], sb[0x39]]) != 0xEF53 {
        return None; // s_magic
    }
    let log_bs = rd32(0x18); // s_log_block_size: block size = 1024 << it
    if log_bs > 6 {
        return None; // 1 KiB..64 KiB is the whole legal range
    }
    // s_blocks_count_hi is only meaningful with INCOMPAT_64BIT; ignore it
    // otherwise so a stale/garbage high word can't inflate the size.
    let hi = if rd32(0x60) & 0x80 != 0 { rd32(0x150) as u64 } else { 0 };
    let blocks = (hi << 32) | rd32(0x04) as u64; // s_blocks_count
    blocks.checked_mul(1024u64 << log_bs)
}

/// Lexically fold `.` / `..` / empty segments out of a mount-relative path.
/// A `..` above the mount root is clamped at the root (it can't escape the
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

fn leak_cstr(s: &[u8]) -> *const u8 {
    let mut v: Vec<u8> = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    Box::leak(v.into_boxed_slice()).as_ptr()
}

/// An open lwext4 file plus whether writes to it are permitted (the file lives
/// inside the writable subtree). `write` consults this so a handle opened
/// outside the writable root can never mutate the disk.
struct OpenFile {
    file: Ext4File,
    writable: bool,
}

/// The lwext4-backed filesystem — one instance per mounted ext4 partition.
pub struct Lwext4Fs {
    /// lwext4 mount-point prefix incl. trailing slash, no NUL, e.g. `b"/m0/"`.
    mp: Vec<u8>,
    /// RetroOS's own group — the gid of the C: root directory, read once at
    /// mount. It IS the "retroos group" by definition: whatever owns RetroOS's
    /// home is its identity, so nothing needs pinning or an /etc/group parse.
    ///
    /// This gid plus the group-write bit is the WHOLE write policy (see
    /// [`Self::writable`]): the host grants access with `chgrp retroos` +
    /// `chmod g+w`, exactly as it would to any other Unix user, and RetroOS can
    /// touch nothing else on the partition. `None` = read-only mount (the extra
    /// partitions, or a C: root we couldn't stat).
    grant_gid: Option<u32>,
    open_files: RefCell<BTreeMap<u64, OpenFile>>,
    next_handle: Cell<u64>,
}

impl Lwext4Fs {
    /// Register + mount the ext4 filesystem filling `vol`. `index`
    /// disambiguates the global lwext4 device name / mount point.
    pub fn new(vol: Volume, index: usize) -> Result<Self, &'static str> {
        let part_size = fs_extent(&vol).ok_or("no ext4 superblock at partition start")?;
        unsafe {
            let bdev = Box::leak(Box::new(Ext4Blockdev {
                bdif: new_iface(vol),
                part_offset: 0, // the Volume IS the partition; ids are relative to it
                part_size,
                bc: core::ptr::null_mut(),
                lg_bsize: 0,
                lg_bcnt: 0,
                cache_write_back: 0,
                fs: core::ptr::null_mut(),
                journal: core::ptr::null_mut(),
            }));

            let mut name = Vec::new();
            name.extend_from_slice(b"ext4dev");
            name.push(b'0' + index as u8);
            let dev_name = leak_cstr(&name);

            let mut mp = Vec::new();
            mp.extend_from_slice(b"/m");
            mp.push(b'0' + index as u8);
            mp.push(b'/');
            let mp_c = leak_cstr(&mp);

            // Only the boot root (index 0) may write at all. Extra partitions (a
            // laptop's data / other-distro partitions) are mounted READ-ONLY at
            // the lwext4 level AND get no grant gid — defence in depth.
            let read_only = index != 0;

            if ext4_device_register(bdev, dev_name) != EOK {
                return Err("ext4_device_register failed");
            }
            if ext4_mount(dev_name, mp_c, read_only) != EOK {
                return Err("ext4_mount failed");
            }
            // Journal recovery + transactions (transparent no-op if the fs has
            // no journal). NOTE: no write-back caching — writes go through
            // synchronously so they're durable at close without an explicit
            // flush/umount on the (abrupt) kernel shutdown path. Fine for the
            // savegame/log/config workload; revisit if bulk writes need speed.
            ext4_journal_start(mp_c);

            let mut fs = Lwext4Fs {
                mp,
                grant_gid: None,
                open_files: RefCell::new(BTreeMap::new()),
                next_handle: Cell::new(1),
            };
            // RetroOS's identity: the group owning its own home (the C: root).
            // Must run AFTER the mount — it reads the directory's inode.
            if index == 0 {
                let cr = crate::kernel::dos::c_root();
                let root = cr.strip_suffix(b"/").unwrap_or(cr);
                fs.grant_gid = fs.gid_of(root);
            }
            Ok(fs)
        }
    }

    /// Build a NUL-terminated lwext4 absolute path (`<mp><rel>\0`) in `buf`,
    /// following symlinks first — so callers address the physical object.
    /// Use [`cpath_nofollow`] where the link ITSELF is the subject.
    fn cpath(&self, rel: &[u8], buf: &mut [u8; 320]) -> Option<*const u8> {
        let real = self.real(rel);
        self.cpath_nofollow(&real, buf)
    }

    /// Build a NUL-terminated lwext4 absolute path (`<mp><rel>\0`) in `buf`.
    fn cpath_nofollow(&self, rel: &[u8], buf: &mut [u8; 320]) -> Option<*const u8> {
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
        Some(buf.as_ptr())
    }

    fn stat_mode(cpath: *const u8, is_dir: bool) -> u16 {
        let mut mode: u32 = 0;
        if unsafe { ext4_mode_get(cpath, &mut mode) } == EOK {
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
            Some(cpath) => (unsafe { ext4_inode_exist(cpath, EXT4_DE_SYMLINK) }) == EOK,
            None => false,
        }
    }

    /// Read `rel`'s symlink target (mount-relative in, raw target out).
    fn readlink(&self, rel: &[u8]) -> Option<Vec<u8>> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath_nofollow(rel, &mut buf)?;
        let mut tgt = [0u8; 256];
        let mut rcnt = 0usize;
        if unsafe { ext4_readlink(cpath, tgt.as_mut_ptr(), tgt.len(), &mut rcnt) } != EOK {
            return None;
        }
        Some(tgt[..rcnt.min(tgt.len())].to_vec())
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

    /// The group owning `rel` (symlinks followed — the target's inode is what a
    /// write would actually hit).
    fn gid_of(&self, rel: &[u8]) -> Option<u32> {
        let mut buf = [0u8; 320];
        let cpath = self.cpath(rel, &mut buf)?;
        let (mut uid, mut gid) = (0u32, 0u32);
        (unsafe { ext4_owner_get(cpath, &mut uid, &mut gid) } == EOK).then_some(gid)
    }

    /// May RetroOS write the object at `path`? The ext4 inode answers: it must
    /// belong to RetroOS's group AND carry the group-write bit.
    ///
    /// This is the whole policy. It replaces the old path-prefix zone, and is
    /// both stricter and more useful: the host grants access per file/dir with
    /// `chgrp retroos` + `chmod g+w` — ordinary Unix administration — and
    /// RetroOS can touch nothing else, no matter where it is or how it was
    /// reached. Symlinks stop mattering (we judge the resolved inode, so a link
    /// to `/etc/passwd` is refused because passwd isn't ours, not because of
    /// where the link pointed), and games linked in from elsewhere on the
    /// partition are writable exactly when the host says so.
    fn writable(&self, path: &[u8]) -> bool {
        let Some(grant) = self.grant_gid else {
            return false; // read-only mount
        };
        if self.gid_of(path) != Some(grant) {
            return false;
        }
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return false;
        };
        let mut mode: u32 = 0;
        unsafe { ext4_mode_get(cpath, &mut mode) == EOK && mode & S_IWGRP != 0 }
    }

    /// May RetroOS create/delete `path`? Unix rule: that's a write to the
    /// PARENT directory, so the parent's group + group-write bit decide (the
    /// file itself doesn't exist yet).
    fn may_create_in_parent(&self, path: &[u8]) -> bool {
        let real = normalize(path);
        if real.is_empty() {
            return false;
        }
        let parent = match real.iter().rposition(|&b| b == b'/') {
            Some(i) => &real[..i],
            None => b"", // mount root
        };
        self.writable(parent)
    }

    /// Stamp a newly created file as RetroOS's own: our group + group-write.
    /// Without this the file would inherit whatever lwext4 defaults to and we
    /// could not reopen our own savegame for writing next time.
    fn claim(&self, path: &[u8]) {
        let Some(grant) = self.grant_gid else { return };
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else { return };
        let (mut uid, mut gid) = (0u32, 0u32);
        unsafe {
            ext4_owner_get(cpath, &mut uid, &mut gid);
            ext4_owner_set(cpath, uid, grant);
            let mut mode: u32 = 0;
            if ext4_mode_get(cpath, &mut mode) == EOK {
                ext4_mode_set(cpath, mode | S_IWGRP | S_IRGRP);
            }
        }
    }

    fn alloc_handle(&self, file: Ext4File, writable: bool) -> u64 {
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
        // A handle is writable only if the inode is ours (group + g+w);
        // everything else opens read-only so it can never mutate the disk.
        let writable = self.writable(path);
        let mut file: Ext4File = unsafe { core::mem::zeroed() };
        let rw_flags: &[u8] = if writable { b"r+b\0" } else { b"rb\0" };
        if unsafe { ext4_fopen(&mut file, cpath, rw_flags.as_ptr()) } != EOK
            && unsafe { ext4_fopen(&mut file, cpath, c"rb".as_ptr().cast()) } != EOK
        {
            return None;
        }
        let size = unsafe { ext4_fsize(&mut file) } as u32;
        let mode = Self::stat_mode(cpath, false);
        let handle = self.alloc_handle(file, writable);
        Some(Vnode { handle, size, mode })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let mut files = self.open_files.borrow_mut();
        let Some(of) = files.get_mut(&handle) else {
            return 0;
        };
        let fp = &mut of.file as *mut Ext4File;
        unsafe {
            if ext4_fseek(fp, offset as i64, SEEK_SET) != EOK {
                return 0;
            }
            let mut rcnt: usize = 0;
            if ext4_fread(fp, buf.as_mut_ptr(), buf.len(), &mut rcnt) != EOK {
                return 0;
            }
            rcnt as i32
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
        let fp = &mut of.file as *mut Ext4File;
        unsafe {
            if ext4_fseek(fp, offset as i64, SEEK_SET) != EOK {
                return -5;
            }
            let mut wcnt: usize = 0;
            if ext4_fwrite(fp, data.as_ptr(), data.len(), &mut wcnt) != EOK {
                return -5;
            }
            wcnt as i32
        }
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        // Creating (or truncating) is a write. An existing file must itself be
        // ours; a new one needs write permission on its parent directory —
        // the ordinary Unix rule.
        let exists = self.gid_of(path).is_some();
        let ok = if exists { self.writable(path) } else { self.may_create_in_parent(path) };
        if !ok {
            return None;
        }
        let mut buf = [0u8; 320];
        let cpath = self.cpath(path, &mut buf)?;
        let mut file: Ext4File = unsafe { core::mem::zeroed() };
        // "wb": create + truncate for writing.
        if unsafe { ext4_fopen(&mut file, cpath, c"wb".as_ptr().cast()) } != EOK {
            return None;
        }
        // Stamp it ours so we can reopen it for writing later.
        if !exists {
            self.claim(path);
        }
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
        let mut d: Ext4Dir = unsafe { core::mem::zeroed() };
        if unsafe { ext4_dir_open(&mut d, cpath) } != EOK {
            return None;
        }
        let mut i = 0usize;
        let mut result = None;
        loop {
            let e = unsafe { ext4_dir_entry_next(&mut d) };
            if e.is_null() {
                break;
            }
            let e = unsafe { &*e };
            let nlen = e.name_length as usize;
            let name = &e.name[..nlen.min(255)];
            if name == b"." || name == b".." || nlen == 0 {
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
                let is_dir = if i32::from(e.inode_type) == EXT4_DE_SYMLINK {
                    self.dir_exists(&rel)
                } else {
                    e.inode_type == EXT4_DE_DIR
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
                        let mut f: Ext4File = unsafe { core::mem::zeroed() };
                        if unsafe { ext4_fopen(&mut f, cchild, c"rb".as_ptr().cast()) } == EOK {
                            de.size = unsafe { ext4_fsize(&mut f) } as u32;
                            de.mode = Self::stat_mode(cchild, false);
                            unsafe { ext4_fclose(&mut f) };
                        }
                    }
                }
                result = Some(de);
                break;
            }
            i += 1;
        }
        unsafe { ext4_dir_close(&mut d) };
        result
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return false;
        };
        let mut d: Ext4Dir = unsafe { core::mem::zeroed() };
        if unsafe { ext4_dir_open(&mut d, cpath) } == EOK {
            unsafe { ext4_dir_close(&mut d) };
            true
        } else {
            false
        }
    }

    fn clunk(&self, handle: u64) {
        if let Some(mut of) = self.open_files.borrow_mut().remove(&handle) {
            unsafe { ext4_fclose(&mut of.file) };
        }
    }

    fn remove(&self, path: &[u8]) -> i32 {
        // Unlinking mutates the PARENT directory, so that is what must be ours
        // (Unix rule) — and the victim itself must be ours too, so a link we
        // may traverse can't be used to delete something we may not write.
        if !self.may_create_in_parent(path) || !self.writable(path) {
            return -1;
        }
        let mut buf = [0u8; 320];
        let Some(cpath) = self.cpath(path, &mut buf) else {
            return -1;
        };
        if unsafe { ext4_fremove(cpath) } == EOK {
            0
        } else {
            -1
        }
    }
}
