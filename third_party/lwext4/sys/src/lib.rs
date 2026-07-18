//! Raw FFI bindings to lwext4 — the C ext2/3/4 implementation.
//!
//! Declarations only: the `repr(C)` structs, the entry points, and the
//! constants the headers define. No policy, no block device, no RetroOS
//! types — everything here describes the C library exactly as it is, so it
//! versions with the C source next door (including our `fread-hole.patch`)
//! rather than with the kernel that consumes it.
//!
//! Linking is the consumer's job: this crate declares symbols and links
//! nothing, so a binary that never calls in pulls nothing in. The kernel's
//! BUILD supplies the freestanding object (metal) or `@lwext4//:lwext4_host`.
//!
//! Everything is `pub` and every field is exposed, because the caller has to
//! build these structs itself — that is what a `-sys` crate is. The safe
//! wrapper lives in `kernel/src/kernel/fs/lwext4/`.

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::c_void;

pub const EOK: i32 = 0;
pub const SEEK_SET: u32 = 0;
pub const EXT4_DE_DIR: u8 = 2;
pub const EXT4_DE_SYMLINK: i32 = 7;

// ── lwext4 on-disk-facing C structs (repr(C), field order per the headers) ──

#[repr(C)]
pub struct Ext4BlockdevIface {
    pub open: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    pub bread: Option<unsafe extern "C" fn(*mut Ext4Blockdev, *mut u8, u64, u32) -> i32>,
    pub bwrite: Option<unsafe extern "C" fn(*mut Ext4Blockdev, *const u8, u64, u32) -> i32>,
    pub close: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    pub lock: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    pub unlock: Option<unsafe extern "C" fn(*mut Ext4Blockdev) -> i32>,
    pub ph_bsize: u32,
    pub ph_bcnt: u64,
    pub ph_bbuf: *mut u8,
    pub ph_refctr: u32,
    pub bread_ctr: u32,
    pub bwrite_ctr: u32,
    pub p_user: *mut c_void,
}

#[repr(C)]
pub struct Ext4Blockdev {
    pub bdif: *mut Ext4BlockdevIface,
    pub part_offset: u64,
    pub part_size: u64,
    pub bc: *mut c_void,
    pub lg_bsize: u32,
    pub lg_bcnt: u64,
    pub cache_write_back: u32,
    pub fs: *mut c_void,
    pub journal: *mut c_void,
}

#[repr(C)]
pub struct Ext4File {
    pub mp: *mut c_void,
    pub inode: u32,
    pub flags: u32,
    pub fsize: u64,
    pub fpos: u64,
}

#[repr(C)]
pub struct Ext4Direntry {
    pub inode: u32,
    pub entry_length: u16,
    pub name_length: u8,
    pub inode_type: u8,
    pub name: [u8; 255],
}

#[repr(C)]
pub struct Ext4Dir {
    pub f: Ext4File,
    pub de: Ext4Direntry,
    pub next_off: u64,
}

unsafe extern "C" {
    pub fn ext4_device_register(bd: *mut Ext4Blockdev, dev_name: *const u8) -> i32;
    pub fn ext4_mount(dev_name: *const u8, mount_point: *const u8, read_only: bool) -> i32;
    pub fn ext4_journal_start(mount_point: *const u8) -> i32;
    pub fn ext4_fopen(file: *mut Ext4File, path: *const u8, flags: *const u8) -> i32;
    pub fn ext4_fread(file: *mut Ext4File, buf: *mut u8, size: usize, rcnt: *mut usize) -> i32;
    pub fn ext4_fwrite(file: *mut Ext4File, buf: *const u8, size: usize, wcnt: *mut usize) -> i32;
    pub fn ext4_fclose(file: *mut Ext4File) -> i32;
    pub fn ext4_fseek(file: *mut Ext4File, offset: i64, origin: u32) -> i32;
    pub fn ext4_fsize(file: *mut Ext4File) -> u64;
    pub fn ext4_fremove(path: *const u8) -> i32;
    pub fn ext4_dir_open(dir: *mut Ext4Dir, path: *const u8) -> i32;
    pub fn ext4_dir_close(dir: *mut Ext4Dir) -> i32;
    pub fn ext4_dir_entry_next(dir: *mut Ext4Dir) -> *const Ext4Direntry;
    pub fn ext4_mode_get(path: *const u8, mode: *mut u32) -> i32;
    pub fn ext4_mode_set(path: *const u8, mode: u32) -> i32;
    pub fn ext4_owner_get(path: *const u8, uid: *mut u32, gid: *mut u32) -> i32;
    pub fn ext4_owner_set(path: *const u8, uid: u32, gid: u32) -> i32;
    pub fn ext4_readlink(path: *const u8, buf: *mut u8, bufsize: usize, rcnt: *mut usize) -> i32;
    pub fn ext4_umount(mount_point: *const u8) -> i32;
    pub fn ext4_device_unregister(dev_name: *const u8) -> i32;
    /// No-follow check: EOK iff `path`'s final component is itself a symlink
    /// (ext4_generic_open2 with the SYMLINK filetype doesn't chase it).
    pub fn ext4_inode_exist(path: *const u8, ftype: i32) -> i32;
}
