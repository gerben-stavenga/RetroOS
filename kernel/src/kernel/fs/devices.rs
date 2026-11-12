//! Kernel-owned device files, independent of the root filesystem backend.
use crate::kernel::vfs::{DirEntry, Filesystem, Meta, Vnode};
use alloc::vec::Vec;

pub struct DeviceFs;
pub static DEVICES: DeviceFs = DeviceFs;
const NULL: u64 = 1;
const RANDOM: u64 = 2;
const URANDOM: u64 = 3;
const CHARACTER: u16 = 0o20666;

impl Filesystem for DeviceFs {
    fn format_name(&self) -> &'static str {
        "devices"
    }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let handle = match path { b"null" => NULL, b"random" => RANDOM, b"urandom" => URANDOM, _ => return None };
        Some(Vnode { handle, size: 0, mode: CHARACTER })
    }
    fn open_node(&self, node: u64) -> Option<Vnode> {
        match node { NULL => self.open(b"null"), RANDOM => self.open(b"random"), URANDOM => self.open(b"urandom"), _ => None }
    }
    fn read(&self, handle: u64, _offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        match handle {
            NULL => 0,
            RANDOM | URANDOM => {
                let n = buf.len().min(65536);
                crate::kernel::random::fill(&mut buf[..n]).map_or(-11, |_| n as i32)
            }
            _ => -9,
        }
    }
    fn write(&self, handle: u64, _offset: u32, data: &[u8]) -> i32 {
        if matches!(handle, NULL | RANDOM | URANDOM) {
            i32::try_from(data.len()).unwrap_or(-22)
        } else {
            -9
        }
    }
    fn seek(&self, handle: u64, _offset: i32, whence: i32) -> Option<i32> {
        Some(if !matches!(handle, NULL | RANDOM | URANDOM) {
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
    fn discard_sink(&self, handle: u64) -> bool { handle == NULL }
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
        if !path.is_empty() { return None; }
        let names: [&[u8]; 3] = [b"null", b"random", b"urandom"];
        let start = usize::try_from(cookie).ok()?.min(names.len());
        let end = start.saturating_add(max).min(names.len());
        for (index, name) in names.iter().enumerate().take(end).skip(start) {
            out.push(DirEntry {
                name: name.to_vec(), name_len: name.len(), short_name: None,
                size: 0, is_dir: false, is_symlink: false, mode: CHARACTER,
                dos_attributes: None, mtime: 0, node: index as u64 + 1, mount_idx: 0,
            });
        }
        (end < names.len()).then_some(end as u64)
    }
}
