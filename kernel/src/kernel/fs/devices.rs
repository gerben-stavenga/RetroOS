//! Kernel-owned device files, independent of the root filesystem backend.
use crate::kernel::vfs::{DirEntry, Filesystem, Meta, Vnode};
use alloc::vec::Vec;

pub struct DeviceFs;
pub static DEVICES: DeviceFs = DeviceFs;
const NULL: u64 = 1;
const CHARACTER: u16 = 0o20666;

impl Filesystem for DeviceFs {
    fn format_name(&self) -> &'static str {
        "devices"
    }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        (path == b"null").then_some(Vnode {
            handle: NULL,
            size: 0,
            mode: CHARACTER,
        })
    }
    fn open_node(&self, node: u64) -> Option<Vnode> {
        if node == NULL {
            self.open(b"null")
        } else {
            None
        }
    }
    fn read(&self, handle: u64, _offset: u32, _buf: &mut [u8], _size: u32) -> i32 {
        if handle == NULL { 0 } else { -9 }
    }
    fn write(&self, handle: u64, _offset: u32, data: &[u8]) -> i32 {
        if handle == NULL {
            i32::try_from(data.len()).unwrap_or(-22)
        } else {
            -9
        }
    }
    fn seek(&self, handle: u64, _offset: i32, whence: i32) -> Option<i32> {
        Some(if handle != NULL {
            -9
        } else if (0..=2).contains(&whence) {
            0
        } else {
            -22
        })
    }
    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty()
    }
    fn create(&self, path: &[u8]) -> Option<Vnode> {
        self.open(path)
    }
    fn supports_create(&self) -> bool {
        true
    }
    fn meta(&self, path: &[u8]) -> Option<Meta> {
        let mode = if path.is_empty() {
            0o755
        } else {
            self.open(path)?.mode
        };
        Some(Meta {
            uid: 0,
            gid: 0,
            mode: u32::from(mode),
        })
    }
    fn resize(&self, _handle: u64, _size: u32) -> i32 {
        -22
    }
    fn readdir(
        &self,
        path: &[u8],
        cookie: u64,
        out: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        if path.is_empty() && cookie == 0 && max != 0 {
            out.push(DirEntry {
                name: b"null".to_vec(),
                name_len: 4,
                short_name: None,
                size: 0,
                is_dir: false,
                is_symlink: false,
                mode: CHARACTER,
                dos_attributes: None,
                mtime: 0,
                node: NULL,
                mount_idx: 0,
            });
        }
        None
    }
}
