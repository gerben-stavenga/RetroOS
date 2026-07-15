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
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ffi::c_void;

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};

const EOK: i32 = 0;
const SEEK_SET: u32 = 0;
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
pub fn is_linux_root(part_lba: u32) -> bool {
    unsafe fn dir_exists_c(cpath: *const u8) -> bool {
        let mut d: Ext4Dir = unsafe { core::mem::zeroed() };
        if unsafe { ext4_dir_open(&mut d, cpath) } == EOK {
            unsafe { ext4_dir_close(&mut d) };
            true
        } else {
            false
        }
    }
    unsafe {
        if IFACE.ph_bbuf.is_null() {
            IFACE.ph_bbuf = core::ptr::addr_of_mut!(PH_BBUF) as *mut u8;
        }
        let bdev = Box::leak(Box::new(Ext4Blockdev {
            bdif: core::ptr::addr_of_mut!(IFACE),
            part_offset: part_lba as u64 * 512,
            part_size: 0x20_0000_0000,
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

unsafe extern "C" fn bdev_open(_bdev: *mut Ext4Blockdev) -> i32 {
    EOK
}
unsafe extern "C" fn bdev_close(_bdev: *mut Ext4Blockdev) -> i32 {
    EOK
}
unsafe extern "C" fn bdev_bread(_bdev: *mut Ext4Blockdev, buf: *mut u8, blk_id: u64, blk_cnt: u32) -> i32 {
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, blk_cnt as usize * 512) };
    crate::kernel::block::read_sectors(blk_id as u32, slice);
    EOK
}
unsafe extern "C" fn bdev_bwrite(_bdev: *mut Ext4Blockdev, buf: *const u8, blk_id: u64, blk_cnt: u32) -> i32 {
    let slice = unsafe { core::slice::from_raw_parts(buf, blk_cnt as usize * 512) };
    crate::kernel::block::write_sectors(blk_id as u32, slice);
    EOK
}

// One physical disk → one shared interface (a scratch block buffer + the
// callbacks). Each partition gets its own `Ext4Blockdev` (own `part_offset`)
// pointing at this. Single-threaded boot, so the shared `ph_bbuf` is safe.
static mut PH_BBUF: [u8; 512] = [0; 512];
static mut IFACE: Ext4BlockdevIface = Ext4BlockdevIface {
    open: Some(bdev_open),
    bread: Some(bdev_bread),
    bwrite: Some(bdev_bwrite),
    close: Some(bdev_close),
    lock: None,
    unlock: None,
    ph_bsize: 512,
    ph_bcnt: 0x1_0000_0000, // permissive device size; the superblock sets the real fs extent
    ph_bbuf: core::ptr::null_mut(),
    ph_refctr: 0,
    bread_ctr: 0,
    bwrite_ctr: 0,
    p_user: core::ptr::null_mut(),
};

/// Leak a NUL-terminated copy of `s` (boot-lifetime), returning its pointer.
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
    /// The ONLY subtree writes are allowed under (VFS-relative, no leading or
    /// trailing slash), e.g. `b"home/retroos"` for the DOS `C:`. `None` = the
    /// whole mount is read-only. Everything outside this is read-only so RetroOS
    /// can never clobber the host's `/bin`, `/etc`, other partitions, etc.
    writable_root: Option<Vec<u8>>,
    open_files: RefCell<BTreeMap<u64, OpenFile>>,
    next_handle: Cell<u64>,
}

impl Lwext4Fs {
    /// Register + mount the ext4 partition starting at `part_lba`. `index`
    /// disambiguates the global lwext4 device name / mount point.
    pub fn new(part_lba: u32, index: usize) -> Result<Self, &'static str> {
        unsafe {
            if IFACE.ph_bbuf.is_null() {
                IFACE.ph_bbuf = core::ptr::addr_of_mut!(PH_BBUF) as *mut u8;
            }
            let bdev = Box::leak(Box::new(Ext4Blockdev {
                bdif: core::ptr::addr_of_mut!(IFACE),
                part_offset: part_lba as u64 * 512,
                part_size: 0x20_0000_0000, // permissive (128 GiB); reads stay within the fs
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

            // Only the boot root (index 0) is writable, and only within the DOS
            // `C:` subtree — tracked from `dos::c_root()` (default `home/retroos/`;
            // the in-OS build toolchain sets it to `""` = the whole mount). Extra
            // partitions (a laptop's data / other-distro partitions) are mounted
            // READ-ONLY at the lwext4 level AND have no writable root — defence in
            // depth so RetroOS can never write to them.
            let (read_only, writable_root) = if index == 0 {
                let cr = crate::kernel::dos::c_root();
                // Store without a trailing slash to match the prefix checks.
                let root = cr.strip_suffix(b"/").unwrap_or(cr);
                (false, Some(root.to_vec()))
            } else {
                (true, None)
            };

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

            Ok(Lwext4Fs {
                mp,
                writable_root,
                open_files: RefCell::new(BTreeMap::new()),
                next_handle: Cell::new(1),
            })
        }
    }

    /// Build a NUL-terminated lwext4 absolute path (`<mp><rel>\0`) in `buf`.
    fn cpath(&self, rel: &[u8], buf: &mut [u8; 320]) -> Option<*const u8> {
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

    /// May a write touch `path` (VFS-relative, no leading slash)? True only for
    /// paths at or under `writable_root` (the DOS `C:` = `home/retroos`).
    /// Lexical zone check: `path` is at/under `writable_root`, with no `..`
    /// segment (which lwext4 would resolve out of the zone despite a prefix
    /// match). Necessary but not sufficient — see `write_allowed`.
    fn in_zone(&self, path: &[u8]) -> bool {
        let Some(root) = &self.writable_root else {
            return false;
        };
        if path.split(|&b| b == b'/').any(|seg| seg == b"..") {
            return false;
        }
        // Empty root means `C:` IS the whole mount (the in-OS build toolchain's
        // `c_root=""`): everything is in-zone (still minus `..`).
        if root.is_empty() {
            return true;
        }
        path == root.as_slice()
            || (path.len() > root.len() && path.starts_with(root) && path[root.len()] == b'/')
    }

    /// Is `rel`'s final component a symlink? (No-follow — the real escape check.)
    fn is_symlink(&self, rel: &[u8]) -> bool {
        let mut buf = [0u8; 320];
        match self.cpath(rel, &mut buf) {
            Some(cpath) => (unsafe { ext4_inode_exist(cpath, EXT4_DE_SYMLINK) }) == EOK,
            None => false,
        }
    }

    /// May a write touch `path`? Lexically in-zone AND no path component is a
    /// symlink — so the (already-resolved-lexically) string path is also the
    /// physical path lwext4 will resolve, closing the `home/retroos/link → /bin`
    /// escape. Only called when a write is actually attempted, so the per-
    /// component `ext4_inode_exist` cost is off the read hot path.
    fn write_allowed(&self, path: &[u8]) -> bool {
        if !self.in_zone(path) {
            return false;
        }
        // Check every prefix component (and the full path) for a symlink. We
        // reject at the first, so components before it are confirmed real dirs
        // and the string prefixes are the true physical prefixes.
        for (i, &b) in path.iter().enumerate() {
            if b == b'/' && i > 0 && self.is_symlink(&path[..i]) {
                return false;
            }
        }
        !path.is_empty() && !self.is_symlink(path)
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
        // Only open read+write inside the writable root; everywhere else is
        // opened read-only so a handle can never mutate a protected path.
        let writable = self.write_allowed(path);
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
        // Creating a file is a write — only inside the writable root.
        if !self.write_allowed(path) {
            return None;
        }
        let mut buf = [0u8; 320];
        let cpath = self.cpath(path, &mut buf)?;
        let mut file: Ext4File = unsafe { core::mem::zeroed() };
        // "wb": create + truncate for writing.
        if unsafe { ext4_fopen(&mut file, cpath, c"wb".as_ptr().cast()) } != EOK {
            return None;
        }
        let handle = self.alloc_handle(file, true);
        Some(Vnode { handle, size: 0, mode: 0o644 })
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
                let is_dir = e.inode_type == EXT4_DE_DIR;
                let name_len = name.len().min(100);
                let mut de = DirEntry {
                    name: [0; 100],
                    name_len,
                    size: 0,
                    is_dir,
                    mode: if is_dir { 0o755 } else { 0o644 },
                };
                de.name[..name_len].copy_from_slice(&name[..name_len]);
                // Size for regular files: open the child and read its size.
                if !is_dir {
                    let mut child = [0u8; 320];
                    let mut rel = Vec::with_capacity(dir.len() + 1 + name.len());
                    rel.extend_from_slice(dir);
                    if !rel.is_empty() && *rel.last().unwrap() != b'/' {
                        rel.push(b'/');
                    }
                    rel.extend_from_slice(name);
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
        // Deleting is a write — only inside the writable root.
        if !self.write_allowed(path) {
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
