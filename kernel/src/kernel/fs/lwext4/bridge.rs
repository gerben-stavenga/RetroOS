//! The bridge between lwext4 and RetroOS's block layer.
//!
//! Everything that turns "the C library wants block N" into "read sector N of
//! this Volume" lives here: the callbacks lwext4 invokes, the per-mount
//! interface carrying the Volume they route on, and the extent arithmetic that
//! bounds a mount.
//!
//! The half in `mod.rs` is about files, paths and permissions; this half is
//! about sectors, and knows nothing about a VFS.

use alloc::boxed::Box;
use core::ffi::c_void;
use crate::kernel::block::Volume;
use core::ffi::CStr;
use lwext4_sys::*;

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

/// Register `vol` with lwext4 under `name`. False if the volume carries no ext
/// superblock, or the library's device registry is full.
///
/// The `Ext4Blockdev` never leaves this module: registering means handing C a
/// struct full of function pointers, which no wrapper can make safe, so the
/// raw part stays here with the callbacks it points at. Everything above talks
/// in Volumes and names.
pub fn register_device(vol: &Volume, name: &CStr) -> bool {
    let Some(bdev) = new_bdev(vol) else { return false };
    unsafe { ext4_device_register(bdev, name.as_ptr().cast()) == EOK }
}

/// Drop a registration made by [`register_device`].
pub fn unregister_device(name: &CStr) -> bool {
    unsafe { ext4_device_unregister(name.as_ptr().cast()) == EOK }
}

/// Build an `Ext4Blockdev` ready to register for `vol`, or `None` when there
/// is no ext superblock at its start.
///
/// Both callers — the real mount and the is-this-a-Linux-root probe — used to
/// open-code this identically, which is exactly how `part_offset` or the
/// interface could have drifted apart between them.
fn new_bdev(vol: &Volume) -> Option<*mut Ext4Blockdev> {
    let part_size = fs_extent(vol)?;
    Some(Box::leak(Box::new(Ext4Blockdev {
        bdif: new_iface(*vol),
        part_offset: 0, // the Volume IS the partition; ids are relative to it
        part_size,
        bc: core::ptr::null_mut(),
        lg_bsize: 0,
        lg_bcnt: 0,
        cache_write_back: 0,
        fs: core::ptr::null_mut(),
        journal: core::ptr::null_mut(),
    })))
}
