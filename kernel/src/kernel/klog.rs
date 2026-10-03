//! DOS/VFS views of the allocation-free `klog` crate.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};

const KLOG_HANDLE: u64 = 1;
const KLOG_NAMES: [&[u8]; 2] = [b"klog", b"klog.txt"];
static mut KLOG_BYTES: [u8; klog::DEFAULT_CAPACITY] = [0; klog::DEFAULT_CAPACITY];
static SAVED_THROUGH: AtomicUsize = AtomicUsize::new(0);
const LIVE_FILE_LIMIT: usize = 16 * 1024 * 1024;
static LIVE_FILE_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_DIRTY: AtomicBool = AtomicBool::new(false);
// -1: not started, -2: failed and disabled. Only startup/event-loop code uses
// this handle; the byte logger itself never enters the filesystem.
static LIVE_HANDLE: AtomicI32 = AtomicI32::new(-1);
// 0 is KLOG.TXT; later boots use KLOG0001.TXT, etc. Live capture uses the
// same index as the startup snapshot.
static ACTIVE_LOG_INDEX: AtomicUsize = AtomicUsize::new(0);
const MAX_LOG_INDEX: usize = 9999;

pub struct KLogFs;

pub static KLOG_FS: KLogFs = KLogFs;

/// Attach the kernel-owned static storage to the shared log machinery. Entry
/// code calls this before installing its debug sink, so no heap is required
/// and all subsequent boot messages are retained.
pub fn init() {
    unsafe {
        klog::init(&mut *core::ptr::addr_of_mut!(KLOG_BYTES));
    }
}

pub use klog::line;

/// Save one stable pre-launch snapshot through the normal C: write policy.
/// A failed export must not prevent the interactive startup program running.
pub fn save_boot_snapshot<A: crate::Arch>(machine: &mut A) -> Result<(), i32> {
    use crate::kernel::{thread::{FdKind, MAX_FDS}, vfs};

    // Copy before filesystem I/O, which can itself append diagnostics. Start
    // the later live writer at this point so no subsequent byte is skipped.
    let captured_through = klog::total_bytes();
    let mut bytes = alloc::vec![0; klog::byte_len() as usize];
    let len = klog::read(0, &mut bytes);
    bytes.truncate(len);
    let (index, path) = next_backing_path().ok_or(-28)?;
    let mut fds = [FdKind::None; MAX_FDS];
    let fd = vfs::create(&path, &mut fds);
    if fd < 0 {
        return Err(fd);
    }
    let result = (|| {
        let mut offset = 0;
        while offset < bytes.len() {
            let n = vfs::write(machine, fd, &bytes[offset..], &fds);
            if n <= 0 {
                return Err(if n == 0 { -5 } else { n });
            }
            offset += n as usize;
        }
        let status = vfs::flush(fd, &fds);
        if status < 0 { return Err(status); }
        Ok(())
    })();
    let status = vfs::close(fd, &mut fds);
    let result = result.and(if status < 0 { Err(status) } else { Ok(()) });
    if result.is_ok() {
        ACTIVE_LOG_INDEX.store(index, Ordering::Release);
        SAVED_THROUGH.store(captured_through, Ordering::Release);
    }
    result
}

fn filename(index: usize) -> Vec<u8> {
    if index == 0 {
        return b"KLOG.TXT".to_vec();
    }
    let mut name = b"KLOG0000.TXT".to_vec();
    let mut number = index;
    for digit in (4..8).rev() {
        name[digit] = b'0' + (number % 10) as u8;
        number /= 10;
    }
    name
}

pub fn saved_filename() -> Vec<u8> {
    filename(ACTIVE_LOG_INDEX.load(Ordering::Acquire))
}

fn backing_path(index: usize) -> Vec<u8> {
    let mut path = crate::kernel::dos::c_root().to_vec();
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(&filename(index));
    path
}

fn next_backing_path() -> Option<(usize, Vec<u8>)> {
    for index in 0..=MAX_LOG_INDEX {
        let path = backing_path(index);
        if !crate::kernel::vfs::path_exists(&path) {
            return Some((index, path));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::filename;

    #[test]
    fn numbered_logs_keep_dos_short_names() {
        assert_eq!(filename(0), b"KLOG.TXT");
        assert_eq!(filename(1), b"KLOG0001.TXT");
        assert_eq!(filename(9999), b"KLOG9999.TXT");
    }
}

/// Open the boot snapshot for incremental, durable appends. Called only after
/// the initial snapshot succeeds; never from the logging or interrupt path.
pub fn start_live_capture() -> Result<(), i32> {
    use crate::kernel::vfs;
    if LIVE_HANDLE.load(Ordering::Acquire) >= 0 {
        return Ok(());
    }
    let handle = vfs::open_to_handle(&backing_path(ACTIVE_LOG_INDEX.load(Ordering::Acquire)));
    if handle < 0 {
        return Err(handle);
    }
    let offset = vfs::seek_by_handle(handle, 0, 2);
    if offset < 0 {
        vfs::close_vfs_handle(handle);
        return Err(offset);
    }
    LIVE_FILE_BYTES.store(offset as usize, Ordering::Release);
    LIVE_HANDLE.store(handle, Ordering::Release);
    Ok(())
}

/// Append new klog bytes to the selected boot file and flush them to the backing volume.
/// Call at safe execution boundaries, not from `log::stream`: a log can be
/// emitted while the VFS is locked or an interrupt handler is running.
pub fn sync_live() {
    use crate::kernel::vfs;
    let handle = LIVE_HANDLE.load(Ordering::Acquire);
    if handle < 0 {
        return;
    }
    let end = klog::total_bytes();
    let mut next = SAVED_THROUGH.load(Ordering::Acquire);
    if next >= end && !LIVE_DIRTY.load(Ordering::Acquire) {
        return;
    }
    let mut chunk = [0u8; 1024];
    while next < end {
        let (start, available) = klog::read_since(next, &mut chunk);
        if start != next {
            let marker = b"\n[klog: ring overrun]\n";
            let Some(written) = vfs::try_write_by_handle(handle, marker) else { return };
            if written != marker.len() as i32 {
                LIVE_HANDLE.store(-2, Ordering::Release);
                vfs::close_vfs_handle(handle);
                return;
            }
            LIVE_FILE_BYTES.fetch_add(marker.len(), Ordering::Relaxed);
            LIVE_DIRTY.store(true, Ordering::Release);
            next = start;
            SAVED_THROUGH.store(next, Ordering::Release);
        }
        let remaining = LIVE_FILE_LIMIT.saturating_sub(LIVE_FILE_BYTES.load(Ordering::Relaxed));
        let n = available.min(end.saturating_sub(start)).min(remaining);
        if n == 0 {
            break;
        }
        let Some(written) = vfs::try_write_by_handle(handle, &chunk[..n]) else { return };
        if written <= 0 {
            LIVE_HANDLE.store(-2, Ordering::Release);
            vfs::close_vfs_handle(handle);
            return;
        }
        LIVE_FILE_BYTES.fetch_add(written as usize, Ordering::Relaxed);
        LIVE_DIRTY.store(true, Ordering::Release);
        next += written as usize;
        SAVED_THROUGH.store(next, Ordering::Release);
    }
    let Some(flushed) = vfs::try_flush_by_handle(handle) else { return };
    if flushed < 0 {
        LIVE_HANDLE.store(-2, Ordering::Release);
        vfs::close_vfs_handle(handle);
    } else {
        LIVE_DIRTY.store(false, Ordering::Release);
        if LIVE_FILE_BYTES.load(Ordering::Relaxed) >= LIVE_FILE_LIMIT {
            LIVE_HANDLE.store(-2, Ordering::Release);
            vfs::close_vfs_handle(handle);
        }
    }
}

fn is_klog_path(path: &[u8]) -> bool {
    KLOG_NAMES.contains(&path)
}

impl Filesystem for KLogFs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        if is_klog_path(path) {
            Some(Vnode {
                handle: KLOG_HANDLE,
                size: klog::byte_len(),
                mode: 0o444,
            })
        } else {
            None
        }
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], size: u32) -> i32 {
        if handle != KLOG_HANDLE {
            return -2;
        }
        if offset >= size {
            return 0;
        }
        let n = buf.len().min((size - offset) as usize);
        klog::read(offset, &mut buf[..n]) as i32
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if !dir.is_empty() {
            return None;
        }
        // A fixed handful of synthetic names, so the cookie is just the index.
        for (i, name) in KLOG_NAMES.iter().enumerate().skip(cookie as usize) {
            if out.len() >= max {
                return Some(i as u64);
            }
            let len = name.len().min(100);
            let mut de = DirEntry {
                name: alloc::vec![0; len],
                name_len: len,
                size: klog::byte_len(),
                is_dir: false,
                is_symlink: false,
                mode: 0o444,
                dos_attributes: None,
                mtime: 0,
                node: 0,
                short_name: None,
                mount_idx: 0,
            };
            de.name[..len].copy_from_slice(&name[..len]);
            out.push(de);
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty()
    }

    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 {
        -1
    }
}
