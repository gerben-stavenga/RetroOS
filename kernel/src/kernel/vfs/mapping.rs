//! One kernel-owned file-content cache for every VFS backend.
//! Ordinary reads, pread, private-mapping fills and shared mappings use these
//! same pages. Clean pages share one bounded LRU; live mappings pin their pages.
//! Writes go through to the backend; mapped modifications retain their existing
//! fsync/unmap writeback semantics. Backends only supply identity and freshness.
//! Guest execution is stopped whenever the VFS lock accesses their kernel view.
use super::*;
use core::ptr::NonNull;
use alloc::boxed::Box;

const PAGE_SIZE: usize = 4096;
const PAGE_LIMIT: usize = 512;
const READ_BATCH: usize = 32768;

pub type Key = (u8, u64, u32);

pub(super) struct Page {
    base: usize,
    refs: usize,
    handle: i32,
    writable: bool,
    // Ordinary cache pages own heap bytes. A mapped page instead owns an Arch
    // allocation until its last alias is released (interpreter frames are not
    // interchangeable with heap pointers).
    heap: Option<Box<[u8]>>,
    version: ContentVersion,
    used: u64,
}

impl Page {
    fn clean(bytes: Box<[u8]>, version: ContentVersion, used: u64) -> Self {
        Self { base: bytes.as_ptr() as usize, refs: 0, handle: -1,
            writable: false, heap: Some(bytes), version, used }
    }
    pub(super) fn pinned(&self) -> bool { self.handle >= 0 }
}

impl Vfs {
    pub(super) fn has_mapped_path(&self, path: &[u8]) -> bool {
        self.file_pages.iter().any(|(&(mount, identity, _), page)| {
            if !page.pinned() { return false; }
            if self.file_table[page.handle as usize].path == path { return true; }
            // Bind aliases resolve to the same backend-relative pathname.
            self.backend_path_id(mount, path) == identity
        })
    }
    pub(super) fn zero_mapping_growth(&mut self, handle: i32, old_size: u32, size: u32) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, 0) else { return; };
        for (&(_, _, page), entry) in self.file_pages.range_mut((mount, ino, old_size / 4096)..=(mount, ino, size / 4096)) {
            let start = u64::from(page) * 4096;
            let lo = start.max(u64::from(old_size));
            let hi = (start + 4096).min(u64::from(size));
            if hi > lo {
                unsafe { core::ptr::write_bytes((entry.base + (lo - start) as usize) as *mut u8, 0, (hi - lo) as usize); }
            }
        }
    }
    pub(super) fn mapping_key(&self, handle: i32, offset: u32) -> Result<Key, i32> {
        let entry = self.file_table.get(handle as usize).filter(|e| e.refcount != 0).ok_or(-9)?;
        Ok((entry.mount_idx, entry.cache_id, offset / 4096))
    }

    fn flush_page(&mut self, key: Key) -> i32 {
        let Some(page) = self.file_pages.get(&key) else { return 0; };
        if !page.writable { return 0; }
        let (base, handle) = (page.base, page.handle);
        let entry = &self.file_table[handle as usize];
        let offset = key.2 * 4096;
        let length = entry.vnode.size.saturating_sub(offset).min(4096) as usize;
        // The mapping owns this allocation. Guests cannot run under this lock.
        let data = unsafe { core::slice::from_raw_parts(base as *const u8, length) };
        let (mount, fid) = (entry.mount_idx, entry.vnode.handle);
        let mut written = 0;
        while written < length {
            let n = self.mount_fs(mount).write(fid, offset + written as u32, &data[written..]);
            if n <= 0 { return if n < 0 { n } else { -5 }; }
            written += n as usize;
        }
        self.touch_handle(handle);
        0
    }

    pub(super) fn flush_mappings(&mut self, handle: i32) -> i32 {
        let Ok((mount, ino, _)) = self.mapping_key(handle, 0) else { return -9; };
        let keys: Vec<_> = self.file_pages.range((mount, ino, 0)..=(mount, ino, u32::MAX))
            .map(|(&key, _)| key).collect();
        for key in keys {
            let status = self.flush_page(key);
            if status < 0 { return status; }
        }
        0
    }

    pub(super) fn drop_clean_pages(&mut self) {
        self.file_pages.retain(|_, page| page.pinned());
    }

    pub(super) fn invalidate_file_pages(&mut self, handle: i32) {
        let Ok((mount, identity, _)) = self.mapping_key(handle, 0) else { return; };
        self.file_pages.retain(|&(m, ino, _), page| m != mount || ino != identity || page.pinned());
    }

    pub(super) fn file_is_mapped(&self, handle: i32) -> bool {
        let Ok((mount, identity, _)) = self.mapping_key(handle, 0) else { return false; };
        self.file_pages.range((mount, identity, 0)..=(mount, identity, u32::MAX))
            .any(|(_, page)| page.pinned())
    }

    fn make_page_room(&mut self) -> bool {
        while self.file_pages.len() >= PAGE_LIMIT {
            let victim = self.file_pages.iter().filter(|(_, p)| !p.pinned())
                .min_by_key(|(_, p)| p.used).map(|(&key, _)| key);
            let Some(victim) = victim else { return false; };
            self.file_pages.remove(&victim);
        }
        true
    }

    fn check_content(&mut self, handle: i32) -> Result<Option<ContentVersion>, i32> {
        let (mount, identity, _) = self.mapping_key(handle, 0)?;
        let fid = self.file_table[handle as usize].vnode.handle;
        let version = self.mount_fs(mount).content_version(fid)?;
        // Pinned aliases cannot be discarded. Refresh clean aliases in-place
        // below; writable mappings retain ownership until writeback.
        self.file_pages.retain(|&(m, ino, _), page| {
            m != mount || ino != identity || page.pinned() || Some(page.version) == version
        });
        if let Some(size) = version.and_then(|v| v.size) {
            for e in &mut self.file_table {
                if e.refcount != 0 && e.mount_idx == mount && e.cache_id == identity {
                    e.vnode.size = size;
                }
            }
        }
        Ok(version)
    }

    pub(super) fn cached_read(&mut self, handle: i32, offset: u32, out: &mut [u8]) -> i32 {
        let Some(e) = self.file_table.get(handle as usize).filter(|e| e.refcount != 0) else { return -9; };
        let (mount, fid, size, mode) = (e.mount_idx, e.vnode.handle, e.vnode.size, e.vnode.mode);
        if !matches!(mode & 0o170000, 0 | 0o100000) {
            return self.mount_fs(mount).read(fid, offset, out, size);
        }
        if out.is_empty() { return 0; }
        let version = match self.check_content(handle) {
            Ok(Some(version)) => version,
            Ok(None) => return self.mount_fs(mount).read(fid, offset, out, size),
            Err(error) => return error,
        };
        let size = self.file_table[handle as usize].vnode.size;
        let length = out.len().min(size.saturating_sub(offset) as usize).min(i32::MAX as usize);
        let mut done = 0;
        while done < length {
            let position = offset + done as u32;
            let key = self.mapping_key(handle, position).unwrap();
            let within = position as usize % PAGE_SIZE;
            let count = (length - done).min(PAGE_SIZE - within);
            let stale = self.file_pages.get(&key).is_some_and(|p| p.version != version && !p.writable);
            if stale {
                let base = self.file_pages[&key].base;
                let mut bytes = alloc::vec![0; PAGE_SIZE];
                let start = key.2 * PAGE_SIZE as u32;
                let wanted = size.saturating_sub(start).min(PAGE_SIZE as u32) as usize;
                let n = self.mount_fs(mount).read(fid, start, &mut bytes[..wanted], size);
                if n != wanted as i32 { return if done != 0 { done as i32 } else if n < 0 { n } else { -5 }; }
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, PAGE_SIZE); }
                self.file_pages.get_mut(&key).unwrap().version = version;
            }
            if !self.file_pages.contains_key(&key) {
                // Batch adjacent misses so SMB keeps its normal 32 KiB request
                // size, rather than issuing one network round trip per page.
                let start = position - within as u32;
                let mut wanted = (size - start).min(READ_BATCH as u32) as usize;
                for delta in 1..wanted.div_ceil(PAGE_SIZE) {
                    if self.file_pages.contains_key(&(key.0, key.1, key.2 + delta as u32)) {
                        wanted = delta * PAGE_SIZE;
                        break;
                    }
                }
                let mut bytes = alloc::vec![0; wanted];
                let mut got = 0;
                let mut error = 0;
                while got < wanted {
                    let n = self.mount_fs(mount).read(fid, start + got as u32, &mut bytes[got..], size);
                    if n <= 0 { error = n; break; }
                    if n as usize > wanted - got { error = -5; break; }
                    got += n as usize;
                }
                // Only complete pages (including a verified final EOF page)
                // are reusable. Never turn a short read/error into cached zeros.
                for begin in (0..got).step_by(PAGE_SIZE) {
                    let end = (begin + PAGE_SIZE).min(wanted);
                    if end > got || !self.make_page_room() { break; }
                    let mut page = alloc::vec![0; PAGE_SIZE].into_boxed_slice();
                    page[..end - begin].copy_from_slice(&bytes[begin..end]);
                    self.page_clock = self.page_clock.wrapping_add(1);
                    self.file_pages.insert((key.0, key.1, key.2 + (begin / PAGE_SIZE) as u32),
                        Page::clean(page, version, self.page_clock));
                }
                if !self.file_pages.contains_key(&key) {
                    let n = count.min(got.saturating_sub(within));
                    out[done..done + n].copy_from_slice(&bytes[within.min(got)..within.min(got) + n]);
                    done += n;
                    if n < count { return if done > 0 { done as i32 } else { error }; }
                    continue;
                }
            }
            self.page_clock = self.page_clock.wrapping_add(1);
            let page = self.file_pages.get_mut(&key).unwrap();
            page.used = self.page_clock;
            unsafe { core::ptr::copy((page.base + within) as *const u8, out.as_mut_ptr().add(done), count); }
            done += count;
        }
        done as i32
    }

    pub(super) fn mapped_write(&mut self, handle: i32, offset: u32, data: &[u8]) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, offset) else { return; };
        let end = u64::from(offset) + data.len() as u64;
        for (&(_, _, page), entry) in self.file_pages.range_mut((mount, ino, offset / 4096)..=(mount, ino, (end / 4096) as u32)) {
            let start = u64::from(page) * 4096;
            let lo = start.max(u64::from(offset));
            let hi = (start + 4096).min(end);
            if hi > lo {
                unsafe { core::ptr::copy(data.as_ptr().add((lo - u64::from(offset)) as usize),
                    (entry.base + (lo - start) as usize) as *mut u8, (hi - lo) as usize); }
            }
        }
    }
}

pub fn validate(handle: i32, offset: usize, length: usize, writable: bool) -> Result<(), i32> {
    let vfs = VFS.lock();
    let e = vfs.file_table.get(handle as usize).filter(|e| e.refcount != 0).ok_or(-9)?;
    if !matches!(e.vnode.mode & 0o170000, 0 | 0o100000) { return Err(-19); }
    if writable && !e.writable { return Err(-30); }
    if offset & 4095 != 0 { return Err(-22); }
    // Until mapped truncation can deliver SIGBUS, reject pages wholly beyond
    // EOF. A partial final page is zero-filled and never extends the file.
    if offset.checked_add(length).is_none_or(|end| end > (e.vnode.size as usize).div_ceil(4096) * 4096) {
        return Err(-22);
    }
    Ok(())
}

pub fn acquire<A: crate::Arch>(machine: &mut A, handle: i32, offset: u32, writable: bool) -> Result<(Key, NonNull<u8>), i32> {
    let mut vfs = VFS.lock();
    let key = vfs.mapping_key(handle, offset)?;
    let mut bytes = alloc::vec![0; PAGE_SIZE];
    let n = vfs.cached_read(handle, offset, &mut bytes);
    if n < 0 { return Err(n); }
    let expected = vfs.file_table[handle as usize].vnode.size.saturating_sub(offset).min(PAGE_SIZE as u32);
    if n as u32 != expected { return Err(-5); }
    if !vfs.file_pages.contains_key(&key) {
        vfs.make_page_room();
        vfs.file_pages.insert(key, Page::clean(bytes.into_boxed_slice(), ContentVersion::LOCAL, 0));
    }
    if !vfs.file_pages.get(&key).unwrap().pinned() {
        let base = machine.alloc_shared_pages(1);
        let page = vfs.file_pages.get_mut(&key).unwrap();
        unsafe { core::ptr::copy_nonoverlapping(page.base as *const u8, base.as_ptr(), PAGE_SIZE); }
        page.heap = None;
        page.base = base.as_ptr() as usize;
        page.handle = handle;
        vfs.add_ref(handle);
    } else if writable && !vfs.file_table[vfs.file_pages[&key].handle as usize].writable {
        let previous = vfs.file_pages.get_mut(&key).unwrap().handle;
        vfs.add_ref(handle);
        vfs.file_pages.get_mut(&key).unwrap().handle = handle;
        vfs.close_handle(previous);
    }
    let page = vfs.file_pages.get_mut(&key).unwrap();
    page.refs += 1;
    page.writable |= writable;
    Ok((key, NonNull::new(page.base as *mut u8).unwrap()))
}

pub fn retain(key: Key) {
    VFS.lock().file_pages.get_mut(&key).expect("live mapped file page").refs += 1;
}

/// Caller must remove its guest alias before releasing the last reference.
pub fn release<A: crate::Arch>(machine: &mut A, key: Key) {
    let mut vfs = VFS.lock();
    let page = vfs.file_pages.get_mut(&key).expect("live mapped file page");
    page.refs -= 1;
    if page.refs != 0 { return; }
    let status = vfs.flush_page(key);
    if status < 0 {
        // Preserve modified RAM and its backing handle for later fsync/shutdown
        // retry rather than silently discarding data on a storage failure.
        crate::compact_dbg_println!("mapped file writeback failed: {}", status);
        return;
    }
    let page = vfs.file_pages.remove(&key).unwrap();
    let mut bytes = alloc::vec![0; PAGE_SIZE].into_boxed_slice();
    unsafe { core::ptr::copy_nonoverlapping(page.base as *const u8, bytes.as_mut_ptr(), PAGE_SIZE); }
    unsafe { machine.free_shared_pages(NonNull::new(page.base as *mut u8).unwrap(), 1); }
    // Drop the mapping's fid before retaining clean bytes; cache entries must
    // not keep backend handles open or postpone their close-time flush.
    let status = vfs.close_handle(page.handle);
    if status >= 0 && vfs.make_page_room() {
        let used = vfs.page_clock;
        vfs.file_pages.insert(key, Page::clean(bytes, page.version, used));
    }
    if status < 0 { crate::compact_dbg_println!("mapped file close failed: {}", status); }
}

pub fn sync(key: Key) -> i32 {
    let mut vfs = VFS.lock();
    let Some(page) = vfs.file_pages.get(&key) else { return -12; };
    let handle = page.handle;
    let status = vfs.flush_handle(handle);
    if status < 0 { return status; }
    match vfs.handle_object(handle) { Some(object) => object.fs.sync(), None => -9 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    struct Backend {
        bytes: RefCell<Vec<u8>>,
        reads: Cell<usize>,
        revision: Cell<u64>,
        fail: Cell<bool>,
        chunk: Cell<usize>,
        closed: Cell<usize>,
    }
    impl Filesystem for Backend {
        fn open(&self, _: &[u8]) -> Option<Vnode> {
            Some(Vnode { handle: 1, size: self.bytes.borrow().len() as u32, mode: 0o644 })
        }
        fn content_version(&self, _: u64) -> Result<Option<ContentVersion>, i32> {
            if self.fail.get() { return Err(-5); }
            Ok(Some(ContentVersion { revision: [self.revision.get(), 0, 0], size: Some(self.bytes.borrow().len() as u32) }))
        }
        fn read(&self, _: u64, offset: u32, out: &mut [u8], _: u32) -> i32 {
            self.reads.set(self.reads.get() + 1);
            let bytes = self.bytes.borrow();
            let start = (offset as usize).min(bytes.len());
            let n = out.len().min(bytes.len() - start).min(self.chunk.get());
            out[..n].copy_from_slice(&bytes[start..start + n]);
            n as i32
        }
        fn write(&self, _: u64, offset: u32, data: &[u8]) -> i32 {
            let mut bytes = self.bytes.borrow_mut();
            let end = offset as usize + data.len();
            if end > bytes.len() { bytes.resize(end, 0); }
            bytes[offset as usize..end].copy_from_slice(data);
            data.len() as i32
        }
        fn resize(&self, _: u64, size: u32) -> i32 { self.bytes.borrow_mut().resize(size as usize, 0); 0 }
        fn clunk(&self, _: u64) -> i32 { self.closed.set(self.closed.get() + 1); 0 }
        fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> { None }
        fn dir_exists(&self, path: &[u8]) -> bool { path.is_empty() }
    }
    fn setup(size: usize) -> (Vfs, &'static Backend, i32) {
        let fs = Box::leak(Box::new(Backend {
            bytes: RefCell::new((0..size).map(|n| n as u8).collect()),
            reads: Cell::new(0), revision: Cell::new(0), fail: Cell::new(false),
            chunk: Cell::new(usize::MAX), closed: Cell::new(0),
        }));
        let mut vfs = Vfs::new();
        vfs.mount(b"", fs);
        let handle = vfs.install_handle(b"file", 1, 0, fs.open(b"file").unwrap(), true);
        (vfs, fs, handle)
    }

    #[test]
    fn regular_reads_share_pages_across_handles_and_close() {
        let (mut vfs, fs, h) = setup(READ_BATCH * 2);
        let mut out = [0; 8000];
        assert_eq!(vfs.cached_read(h, 123, &mut out), 8000);
        assert!(out.iter().enumerate().all(|(i, b)| *b == (i + 123) as u8));
        assert_eq!(fs.reads.get(), 1);
        assert_eq!(vfs.close_handle(h), 0);
        assert_eq!(fs.closed.get(), 1, "clean cache must not retain a fid");
        let other = vfs.install_handle(b"file", 2, 0, fs.open(b"file").unwrap(), true);
        assert_eq!(vfs.cached_read(other, 456, &mut out), 8000);
        assert_eq!(fs.reads.get(), 1, "reopen uses the same cached contents");
    }

    #[test]
    fn writes_truncate_growth_and_external_versions_are_coherent() {
        let (mut vfs, fs, h) = setup(8192);
        let mut out = [0; 8];
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert_eq!(vfs.write_at_by_handle(h, 0, b"abcdefgh"), 8);
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert_eq!(&out, b"abcdefgh");
        assert_eq!(fs.reads.get(), 1, "write-through updates the existing cached page");
        assert_eq!(vfs.resize_by_handle(h, 4), 0, "ordinary cache pages must not block truncation");
        assert_eq!(vfs.cached_read(h, 0, &mut out), 4);
        assert_eq!(vfs.resize_by_handle(h, 8192), 0);
        assert_eq!(vfs.cached_read(h, 4, &mut out), 8);
        assert_eq!(out, [0; 8]);
        fs.bytes.borrow_mut()[..8].copy_from_slice(b"external");
        fs.revision.set(1);
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert_eq!(&out, b"external");
        fs.bytes.borrow_mut().truncate(3);
        fs.revision.set(2);
        assert_eq!(vfs.cached_read(h, 0, &mut out), 3);
        fs.fail.set(true);
        assert_eq!(vfs.cached_read(h, 0, &mut out), -5, "failed validation must not serve cached bytes");
    }

    #[test]
    fn mapped_bytes_and_regular_io_use_one_page() {
        let (mut vfs, fs, h) = setup(4096);
        let mut out = [0; 8];
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        let key = vfs.mapping_key(h, 0).unwrap();
        // Model a live guest alias without needing a particular architecture.
        let page = vfs.file_pages.get_mut(&key).unwrap();
        page.handle = h;
        page.refs = 1;
        page.writable = true;
        unsafe { core::ptr::copy_nonoverlapping(b"mapped!!".as_ptr(), page.base as *mut u8, 8); }
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert_eq!(&out, b"mapped!!");
        assert_eq!(fs.reads.get(), 1);
        assert_eq!(vfs.write_at_by_handle(h, 0, b"write!!!"), 8);
        let page = &vfs.file_pages[&key];
        assert_eq!(unsafe { core::slice::from_raw_parts(page.base as *const u8, 8) }, b"write!!!");
        assert_eq!(vfs.resize_by_handle(h, 1), -16);
        assert_eq!(vfs.flush_mappings(h), 0);
        assert_eq!(&fs.bytes.borrow()[..8], b"write!!!");
    }

    #[test]
    fn writing_another_file_does_not_evict_hot_pages() {
        let (mut vfs, fs, h) = setup(4096);
        let other = vfs.install_handle(b"other", 2, 0, fs.open(b"other").unwrap(), true);
        let mut out = [0; 8];
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        let key = vfs.mapping_key(h, 0).unwrap();
        assert_eq!(vfs.write_at_by_handle(other, 0, b"changed!"), 8);
        assert!(vfs.file_pages.contains_key(&key));
    }

    #[test]
    fn short_reads_eof_and_eviction_do_not_create_false_data() {
        let (mut vfs, fs, h) = setup((PAGE_LIMIT + 16) * PAGE_SIZE + 3);
        fs.chunk.set(37);
        let mut out = [0; 8];
        let end = fs.bytes.borrow().len() as u32;
        assert_eq!(vfs.cached_read(h, end - 3, &mut out), 3);
        assert_eq!(&out[..3], &[0, 1, 2]);
        assert_eq!(vfs.cached_read(h, end, &mut out), 0);
        fs.chunk.set(usize::MAX);
        for page in 0..PAGE_LIMIT + 16 {
            assert_eq!(vfs.cached_read(h, (page * PAGE_SIZE) as u32, &mut out), 8);
        }
        assert!(vfs.file_pages.len() <= PAGE_LIMIT);
        let before = fs.reads.get();
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert!(fs.reads.get() > before);
        assert_eq!(out, [0, 1, 2, 3, 4, 5, 6, 7]);
    }
}
