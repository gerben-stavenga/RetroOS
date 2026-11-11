//! Bounded executable snapshots. Exec used to stream every byte again even
//! for a short-lived --version child immediately followed by the same image.
//! Cache identity/version belongs to VFS, where writes can invalidate it.
use super::*;
use alloc::sync::Arc;

pub(super) struct Image {
    pub(super) key: (u8, u64),
    path: Vec<u8>,
    version: ContentVersion,
    file_size: usize,
    bytes: Arc<Vec<u8>>,
}

impl Vfs {
    pub(super) fn invalidate_executable_path(&mut self, path: &[u8]) {
        // Needed for path-identity backends and directory renames. Stable
        // inode identities also remain safe when names/inodes are reused.
        let identities: Vec<_> = self.executables.iter().filter(|image|
            image.path == path || image.path.strip_prefix(path).is_some_and(|tail| tail.starts_with(b"/")))
            .map(|image| image.key).collect();
        self.executables.retain(|image| !identities.contains(&image.key));
    }
    pub(super) fn invalidate_executable(&mut self, handle: i32) {
        if let Ok((mount, id, _)) = self.mapping_key(handle, 0) {
            self.executables.retain(|image| image.key != (mount, id));
        }
    }

    fn executable_image(&mut self, handle: i32, free_bytes: usize, end: usize) -> Result<Option<Arc<Vec<u8>>>, i32> {
        let (mount, identity, _) = self.mapping_key(handle, 0)?;
        let entry = &self.file_table[handle as usize];
        let (fid, size, path) = (entry.vnode.handle, entry.vnode.size as usize, entry.path.clone());
        let key = (mount, identity);
        // Reclaimable snapshots may use at most a third of available memory,
        // with a virtual-address-space ceiling. No fixed RAM requirement.
        let retained: usize = self.executables.iter().map(|image| image.bytes.len()).sum();
        let budget = free_bytes.saturating_add(retained) / 3;
        let budget = budget.min(384 * 1024 * 1024);
        let mut retained = retained;
        while retained > budget {
            retained -= self.executables.remove(0).bytes.len();
        }
        if end > size { return Err(-8); }
        if end == 0 || end > budget || self.file_is_mapped(handle) { return Ok(None); }
        let fs = self.mount_fs(mount);
        let Some(version) = fs.content_version(fid)? else {
            self.invalidate_executable(handle);
            return Ok(None);
        };
        self.executables.retain(|image| image.key != key || (image.version == version && image.file_size == size && image.bytes.len() >= end));
        if let Some(index) = self.executables.iter().position(|image| image.key == key) {
            let image = self.executables.remove(index);
            let bytes = image.bytes.clone();
            self.executables.push(image);
            return Ok(Some(bytes));
        }
        let mut retained: usize = self.executables.iter().map(|image| image.bytes.len()).sum();
        while retained + end > budget {
            retained -= self.executables.remove(0).bytes.len();
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(end).is_err() { return Ok(None); }
        bytes.resize(end, 0);
        // No writable shared aliases exist and no guest runs under this lock.
        // Validate the external version before and after the complete read,
        // instead of a remote metadata request for each 64 KiB of one exec.
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + 64 * 1024).min(bytes.len());
            let sample = crate::kernel::event_profile::file_io_start();
            let n = fs.read(fid, offset as u32, &mut bytes[offset..end], size as u32);
            crate::kernel::event_profile::file_io_finish(7, n.max(0) as usize, sample);
            if n <= 0 || n as usize > end - offset { return Err(if n < 0 { n } else { -5 }); }
            offset += n as usize;
        }
        if fs.content_version(fid)? != Some(version) { return Err(-11); }
        let bytes = Arc::new(bytes);
        self.executables.push(Image { key, path, version, file_size: size, bytes: bytes.clone() });
        Ok(Some(bytes))
    }
}

pub(crate) fn image(handle: i32, free_bytes: usize, end: usize) -> Result<Option<Arc<Vec<u8>>>, i32> {
    VFS.lock().executable_image(handle, free_bytes, end)
}

/// Release optional snapshots before low-memory guest workloads need frames.
pub(crate) fn reclaim() { VFS.lock().executables.clear(); }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::cell::{Cell, RefCell};
    struct Backend { bytes: RefCell<Vec<u8>>, revision: Cell<u64>, reads: Cell<usize>, fail: Cell<bool>, change_during_read: Cell<bool> }
    impl Filesystem for Backend {
        fn open(&self, _: &[u8]) -> Option<Vnode> { Some(Vnode { handle: 1, size: self.bytes.borrow().len() as u32, mode: 0o755 }) }
        fn file_identity(&self, _: u64) -> Option<u64> { Some(42) }
        fn content_version(&self, _: u64) -> Result<Option<ContentVersion>, i32> {
            if self.fail.get() { return Err(-5); }
            Ok(Some(ContentVersion { revision: [self.revision.get(), 0, 0], size: Some(self.bytes.borrow().len() as u32) }))
        }
        fn read(&self, _: u64, offset: u32, out: &mut [u8], _: u32) -> i32 {
            self.reads.set(self.reads.get()+1);
            if self.change_during_read.get() { self.revision.set(self.revision.get()+1); }
            let bytes = self.bytes.borrow();
            let n = out.len().min(bytes.len().saturating_sub(offset as usize)).min(701);
            out[..n].copy_from_slice(&bytes[offset as usize..offset as usize+n]); n as i32
        }
        fn write(&self, _: u64, offset: u32, data: &[u8]) -> i32 {
            self.bytes.borrow_mut()[offset as usize..offset as usize+data.len()].copy_from_slice(data); data.len() as i32
        }
        fn resize(&self, _: u64, size: u32) -> i32 { self.bytes.borrow_mut().resize(size as usize, 0); 0 }
        fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> { None }
        fn dir_exists(&self, path: &[u8]) -> bool { path.is_empty() }
    }
    fn setup() -> (Vfs, &'static Backend, i32) {
        let fs = Box::leak(Box::new(Backend { bytes: RefCell::new(alloc::vec![3; 100003]), revision: Cell::new(0), reads: Cell::new(0), fail: Cell::new(false), change_during_read: Cell::new(false) }));
        let mut vfs = Vfs::new(); vfs.mount(b"", fs);
        let h = vfs.install_handle(b"file", 1, 0, fs.open(b"file").unwrap(), true);
        (vfs, fs, h)
    }
    const FREE: usize = 4 * 1024 * 1024;
    #[test]
    fn exec_reuses_short_reads_across_close_and_hard_link_opens() {
        let (mut vfs, fs, h) = setup();
        let first = vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap();
        assert_eq!(&**first, &*fs.bytes.borrow());
        let reads = fs.reads.get(); assert!(reads > 1);
        assert_eq!(vfs.close_handle(h), 0);
        let h = vfs.install_handle(b"alias", 2, 0, fs.open(b"alias").unwrap(), true);
        assert!(Arc::ptr_eq(&first, &vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap()));
        assert_eq!(fs.reads.get(), reads);
        assert!(vfs.executable_image(h, 0, fs.bytes.borrow().len()).unwrap().is_none());
        assert!(vfs.executables.is_empty(), "memory pressure releases retained snapshots");
    }
    #[test]
    fn same_size_local_writes_and_external_changes_invalidate_exec() {
        let (mut vfs, fs, h) = setup();
        let first = vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap();
        assert_eq!(vfs.write_at_by_handle(h, 7, b"new"), 3);
        let second = vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap();
        assert_eq!(&second[7..10], b"new"); assert_eq!(&first[7..10], &[3;3]);
        fs.bytes.borrow_mut()[9] = 8; fs.revision.set(1);
        assert_eq!(vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap()[9], 8);
        fs.fail.set(true);
        assert_eq!(vfs.executable_image(h, FREE, fs.bytes.borrow().len()), Err(-5));
        fs.fail.set(false);
        assert_eq!(vfs.resize_by_handle(h, 4), 0);
        assert_eq!(vfs.executable_image(h, FREE, fs.bytes.borrow().len()).unwrap().unwrap().len(), 4);
    }
    #[test]
    fn changed_during_read_is_not_published_as_an_executable_snapshot() {
        let (mut vfs, fs, h) = setup(); fs.change_during_read.set(true);
        assert_eq!(vfs.executable_image(h, FREE, fs.bytes.borrow().len()), Err(-11));
        assert!(vfs.executables.is_empty());
    }
}
