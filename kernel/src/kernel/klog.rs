//! DOS/VFS views of the allocation-free `klog` crate.

extern crate alloc;
use alloc::vec::Vec;

use crate::kernel::vfs::{DirEntry, Filesystem, Vnode};

const KLOG_HANDLE: u64 = 1;
const KLOG_NAMES: [&[u8]; 2] = [b"klog", b"klog.txt"];
static mut KLOG_BYTES: [u8; klog::DEFAULT_CAPACITY] = [0; klog::DEFAULT_CAPACITY];

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
    use crate::kernel::{dos, thread::{FdKind, MAX_FDS}, vfs};

    // Copy before filesystem I/O, which can itself append diagnostics.
    let mut bytes = alloc::vec![0; klog::byte_len() as usize];
    let len = klog::read(0, &mut bytes);
    bytes.truncate(len);
    let mut path = dos::c_root().to_vec();
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(b"KLOG.TXT");
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
        if status < 0 { Err(status) } else { Ok(()) }
    })();
    let status = vfs::close(fd, &mut fds);
    result.and(if status < 0 { Err(status) } else { Ok(()) })
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
