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
                name: [0; 100],
                name_len: len,
                size: klog::byte_len(),
                is_dir: false,
                is_symlink: false,
                mode: 0o444,
                mtime: 0,
                node: 0,
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
