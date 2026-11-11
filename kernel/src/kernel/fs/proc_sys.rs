//! Kernel-owned /proc/sys/kernel/random files, independent of a mounted root.
use crate::kernel::vfs::{DirEntry, Filesystem, Meta, Vnode};
use alloc::vec::Vec;
use spin::Mutex;

pub struct RandomSysctl {
    boot_id: Mutex<Option<[u8; 37]>>,
}
pub static RANDOM_SYSCTL: RandomSysctl = RandomSysctl { boot_id: Mutex::new(None) };
const BOOT_ID: u64 = 1;

fn uuid(mut bytes: [u8; 16]) -> [u8; 37] {
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let mut text = [b'\n'; 37];
    let mut at = 0;
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) { text[at] = b'-'; at += 1; }
        for nibble in [byte >> 4, byte & 15] {
            text[at] = b"0123456789abcdef"[nibble as usize]; at += 1;
        }
    }
    text
}
impl RandomSysctl {
    fn read_with(&self, offset: u32, out: &mut [u8], fill: impl FnOnce(&mut [u8]) -> Result<(), crate::kernel::random::Unavailable>) -> i32 {
        if out.is_empty() || offset >= 37 { return 0; }
        let mut cached = self.boot_id.lock();
        if cached.is_none() {
            let mut bytes = [0; 16];
            if fill(&mut bytes).is_err() { return -11; }
            *cached = Some(uuid(bytes));
        }
        let text = cached.as_ref().unwrap();
        let start = offset as usize;
        let count = out.len().min(text.len() - start);
        out[..count].copy_from_slice(&text[start..start + count]);
        count as i32
    }
}
impl Filesystem for RandomSysctl {
    fn format_name(&self) -> &'static str { "proc-sys" }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        (path == b"boot_id").then_some(Vnode { handle: BOOT_ID, size: 37, mode: 0o100444 })
    }
    fn open_node(&self, node: u64) -> Option<Vnode> { if node == BOOT_ID { self.open(b"boot_id") } else { None } }
    fn file_identity(&self, handle: u64) -> Option<u64> { (handle == BOOT_ID).then_some(BOOT_ID) }
    fn read(&self, handle: u64, offset: u32, out: &mut [u8], _size: u32) -> i32 {
        if handle != BOOT_ID { return -9; }
        self.read_with(offset, out, crate::kernel::random::fill)
    }
    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 { -30 }
    fn resize(&self, _handle: u64, _size: u32) -> i32 { -30 }
    fn dir_exists(&self, path: &[u8]) -> bool { path.is_empty() }
    fn meta(&self, path: &[u8]) -> Option<Meta> {
        Some(Meta { uid: 0, gid: 0, mode: if path.is_empty() { 0o40555 } else { u32::from(self.open(path)?.mode) } })
    }
    fn readdir(&self, path: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if path.is_empty() && cookie == 0 && max != 0 {
            out.push(DirEntry { name: b"boot_id".to_vec(), name_len: 7, short_name: None, size: 37,
                is_dir: false, is_symlink: false, mode: 0o100444, dos_attributes: None,
                mtime: 0, node: BOOT_ID, mount_idx: 0 });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_uuid_is_cached_across_partial_reads_without_an_entropy_fallback() {
        let fs = RandomSysctl { boot_id: Mutex::new(None) };
        let mut output = [0; 37];
        assert_eq!(fs.read_with(0, &mut output, |_| Err(crate::kernel::random::Unavailable)), -11);
        assert_eq!(fs.read_with(0, &mut output[..11], |bytes| { bytes.fill(0xab); Ok(()) }), 11);
        assert_eq!(fs.read_with(11, &mut output[11..], |_| panic!("boot ID must be cached")), 26);
        assert_eq!(&output, b"abababab-abab-4bab-abab-abababababab\n");
        assert_eq!(fs.read_with(37, &mut output, |_| panic!()), 0);
        assert_eq!(fs.read_with(u32::MAX, &mut output, |_| panic!()), 0);
        assert_eq!(fs.read_with(0, &mut [], |_| panic!()), 0);
        let mut again = [0; 37];
        assert_eq!(fs.read_with(0, &mut again, |_| panic!()), 37);
        assert_eq!(output, again);
        let another = RandomSysctl { boot_id: Mutex::new(None) };
        assert_eq!(another.read_with(0, &mut again, |bytes| { bytes.fill(0xcd); Ok(()) }), 37);
        assert_ne!(output, again);
    }
}
