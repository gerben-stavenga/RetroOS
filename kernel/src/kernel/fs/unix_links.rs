//! Preserve packaged /bin symlinks when the boot transport is FAT.
//! The build records link targets; this read-only layer presents ordinary
//! symlinks to the common VFS, which resolves them across mount boundaries.
use super::super::vfs::{DirEntry, Filesystem, Vnode};
use alloc::{vec, vec::Vec};

pub struct UnixLinks(Vec<(Vec<u8>, Vec<u8>)>);
impl UnixLinks {
    pub fn load(source: &dyn Filesystem, path: &[u8]) -> Option<Self> {
        let node = source.open(path)?;
        if node.size > 65536 {
            source.clunk(node.handle);
            return None;
        }
        let mut data = vec![0; node.size as usize];
        let read = source.read(node.handle, 0, &mut data, node.size);
        source.clunk(node.handle);
        if read != node.size as i32 { return None; }
        let mut links = Vec::new();
        for line in data.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let separator = line.iter().position(|b| *b == b'\t')?;
            let (name, target) = (&line[..separator], &line[separator+1..]);
            if name.is_empty() || name.contains(&b'/') || target.is_empty() { return None; }
            links.push((name.to_vec(), target.to_vec()));
        }
        Some(Self(links))
    }
}
impl Filesystem for UnixLinks {
    fn open(&self, _: &[u8]) -> Option<Vnode> { None }
    fn read(&self, _: u64, _: u32, _: &mut [u8], _: u32) -> i32 { -2 }
    fn dir_exists(&self, path: &[u8]) -> bool { path.is_empty() }
    fn readlink(&self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        let (_, target) = self.0.iter().find(|(name, _)| name == path)?;
        if target.len() > out.len() { return None; }
        out[..target.len()].copy_from_slice(target);
        Some(target.len())
    }
    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        if !dir.is_empty() { return None; }
        let start = usize::try_from(cookie).ok()?;
        let end = start.saturating_add(max).min(self.0.len());
        for (name, target) in self.0.iter().take(end).skip(start) {
            out.push(DirEntry {
                name: name.clone(), name_len: name.len(), short_name: None,
                size: target.len() as u32, is_dir: false, is_symlink: true,
                mode: 0o777, dos_attributes: None, mtime: 0, node: 0, mount_idx: 0,
            });
        }
        (end < self.0.len()).then_some(end as u64)
    }
}
