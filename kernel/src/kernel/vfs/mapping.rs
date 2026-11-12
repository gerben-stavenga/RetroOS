//! One kernel-owned file-content cache for every VFS backend.
//! Ordinary reads, pread, private-mapping fills and shared mappings use these
//! same physical frames. Clean pages are reclaimable; shared mappings pin them.
//! Writes go through to the backend; mapped modifications retain their existing
//! fsync/unmap writeback semantics. Backends only supply identity and freshness.
//! Guest execution is stopped whenever the VFS lock accesses their kernel view.
use super::*;
use crate::kernel::cache::{self, Frame};

const PAGE_SIZE: usize = 4096;
const PAGE_LIMIT: usize = 512;
const READ_BATCH: usize = 32768;
const BULK_READ_BATCH: usize = 128 * 1024;

pub type Key = (u8, u64, u32);

pub(super) struct Page {
    refs: usize,
    handle: i32,
    writable: bool,
    data: Frame,
    version: ContentVersion,
    used: u64,
}

impl Page {
    fn clean(bytes: &[u8], version: ContentVersion, used: u64) -> Result<Self, i32> {
        Ok(Self { refs: 0, handle: -1, writable: false,
            data: Frame::new(bytes)?, version, used })
    }
    pub(super) fn pinned(&self) -> bool { self.handle >= 0 }
}

impl Vfs {
    pub(super) fn has_mapped_path(&self, path: &[u8]) -> bool {
        self.mapped_handles.keys().any(|&handle| {
            let entry = &self.file_table[handle as usize];
            if entry.path == path { return true; }
            // Bind aliases resolve to the same backend-relative pathname.
            self.backend_path_id(entry.mount_idx, path) == entry.cache_id
        })
    }

    fn pin_mapping_handle(&mut self, handle: i32) {
        self.add_ref(handle);
        *self.mapped_handles.entry(handle).or_default() += 1;
    }

    fn unpin_mapping_handle(&mut self, handle: i32) -> i32 {
        let count = self.mapped_handles.get_mut(&handle).expect("pinned mapping handle");
        *count -= 1;
        if *count == 0 { self.mapped_handles.remove(&handle); }
        self.close_handle(handle)
    }
    pub(super) fn zero_mapping_growth(&mut self, handle: i32, old_size: u32, size: u32) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, 0) else { return; };
        for (&(_, _, page), entry) in self.file_pages.range_mut((mount, ino, old_size / 4096)..=(mount, ino, size / 4096)) {
            let start = u64::from(page) * 4096;
            let lo = start.max(u64::from(old_size));
            let hi = (start + 4096).min(u64::from(size));
            if hi > lo {
                entry.data.write((lo - start) as usize, &alloc::vec![0; (hi - lo) as usize]);
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
        let handle = page.handle;
        let entry = &self.file_table[handle as usize];
        let offset = key.2 * 4096;
        let length = entry.vnode.size.saturating_sub(offset).min(4096) as usize;
        let mut data = alloc::vec![0; length];
        page.data.read(0, &mut data);
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

    pub(super) fn forget_empty_cache_file(&mut self, key: (u8, u64)) {
        if self.file_pages.range((key.0, key.1, 0)..=(key.0, key.1, u32::MAX)).next().is_none()
            && !self.file_table.iter().any(|entry| entry.refcount != 0 && (entry.mount_idx, entry.cache_id) == key)
        {
            self.cached_paths.remove(&key);
            self.validated_versions.remove(&key);
        }
    }

    pub(super) fn drop_clean_pages(&mut self) {
        self.file_pages.retain(|_, page| page.pinned());
        self.clean_pages.clear();
        let pages = &self.file_pages;
        self.cached_paths.retain(|&(mount, id), _|
            pages.range((mount, id, 0)..=(mount, id, u32::MAX)).next().is_some());
        self.validated_versions.retain(|&(mount, id), _|
            pages.range((mount, id, 0)..=(mount, id, u32::MAX)).next().is_some());
    }

    /// Invalidate one identity with a range lookup, not a whole-cache scan.
    pub(super) fn invalidate_cached_file(&mut self, key: (u8, u64)) {
        let keys: Vec<_> = self.file_pages.range((key.0, key.1, 0)..=(key.0, key.1, u32::MAX))
            .filter_map(|(&key, page)| (!page.pinned()).then_some(key)).collect();
        for key in keys { self.file_pages.remove(&key); self.clean_pages.remove(key); }
        self.validated_versions.remove(&key);
        self.forget_empty_cache_file(key);
    }

    pub(super) fn invalidate_file_pages(&mut self, handle: i32) {
        let Ok((mount, identity, _)) = self.mapping_key(handle, 0) else { return; };
        self.invalidate_cached_file((mount, identity));
    }

    /// Closed path-identity files retain only their backend-relative name.
    /// Directory renames retire that subtree. Stable inode source pages stay
    /// valid across renames; an unlink/replaced victim must retire its identity.
    pub(super) fn namespace_cache_keys(&self, object: &ResolvedObject, preserve_stable: bool) -> Vec<(u8, u64)> {
        if object.stat.is_dir {
            return self.cached_paths.iter().filter_map(|(&key, path)| {
                (key.0 == object.mount_idx && (path.as_slice() == object.subpath()
                    || path.strip_prefix(object.subpath()).is_some_and(|tail| tail.starts_with(b"/"))))
                    .then_some(key)
            }).collect();
        }
        if object.stat.is_symlink { return Vec::new(); }
        let path_key = (object.mount_idx, path_ino(object.subpath()));
        if self.cached_paths.contains_key(&path_key) { return alloc::vec![path_key]; }
        let Some(node) = object.fs.open(object.subpath()) else { return Vec::new(); };
        let identity = object.fs.file_identity(node.handle);
        object.fs.clunk(node.handle);
        match identity {
            Some(id) if !preserve_stable => alloc::vec![(object.mount_idx, id)],
            None => alloc::vec![path_key],
            _ => Vec::new(),
        }
    }

    pub(super) fn file_is_mapped(&self, handle: i32) -> bool {
        let Ok((mount, identity, _)) = self.mapping_key(handle, 0) else { return false; };
        self.file_pages.range((mount, identity, 0)..=(mount, identity, u32::MAX))
            .any(|(_, page)| page.pinned())
    }

    fn evict_clean_page(&mut self) -> Option<Frame> {
        while let Some(key) = self.clean_pages.pop() {
            if self.file_pages.get(&key).is_some_and(|p| !p.pinned()) {
                let page = self.file_pages.remove(&key).unwrap();
                self.forget_empty_cache_file((key.0, key.1));
                return Some(page.data);
            }
        }
        None
    }

    fn make_page_room(&mut self) -> bool {
        if let Some(a) = cache::access() {
            while (a.free)() <= cache::reserve() {
                let Some(frame) = self.evict_clean_page() else { return false; };
                drop(frame);
            }
        } else {
            while self.clean_pages.len() >= PAGE_LIMIT { drop(self.evict_clean_page()); }
        }
        true
    }

    fn cache_page(&mut self, key: Key, page: Page) {
        self.clean_pages.touch(key, page.used);
        self.file_pages.insert(key, page);
    }

    fn check_content(&mut self, handle: i32) -> Result<Option<ContentVersion>, i32> {
        let (mount, identity, _) = self.mapping_key(handle, 0)?;
        let fid = self.file_table[handle as usize].vnode.handle;
        let version = self.mount_fs(mount).content_version(fid)?;
        if version.is_some() && self.file_table[handle as usize].cache_path_based
            && !self.cached_paths.contains_key(&(mount, identity))
        {
            let path = self.file_table[handle as usize].path.clone();
            let mut relative = None;
            self.visit_layers(&path, ALIAS_DEPTH, &mut |index, _, subpath| {
                if index != mount { return false; }
                relative = Some(subpath.to_vec()); true
            });
            if let Some(path) = relative { self.cached_paths.insert((mount, identity), path); }
        }
        if version.is_some() && self.validated_versions.get(&(mount, identity)) == version.as_ref() {
            return Ok(version);
        }
        if let Some(version) = version { self.validated_versions.insert((mount, identity), version); }
        else { self.validated_versions.remove(&(mount, identity)); }
        // Pinned aliases cannot be discarded. Refresh clean aliases in-place
        // below; writable mappings retain ownership until writeback.
        let stale: Vec<_> = self.file_pages.range((mount, identity, 0)..=(mount, identity, u32::MAX))
            .filter_map(|(&key, page)| (!page.pinned() && Some(page.version) != version).then_some(key)).collect();
        for key in stale {
            self.file_pages.remove(&key);
            self.clean_pages.remove(key);
        }
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
        self.fill_cache(handle, offset, out, true)
    }

    fn fill_cache(&mut self, handle: i32, offset: u32, out: &mut [u8], copy: bool) -> i32 {
        let Some(e) = self.file_table.get(handle as usize).filter(|e| e.refcount != 0) else { return -9; };
        let (mount, fid, size, mode) = (e.mount_idx, e.vnode.handle, e.vnode.size, e.vnode.mode);
        if !matches!(mode & 0o170000, 0 | 0o100000) {
            return self.mount_fs(mount).read(fid, offset, out, size);
        }
        if out.is_empty() { return 0; }
        let sample = crate::kernel::event_profile::file_io_start();
        let version = self.check_content(handle);
        crate::kernel::event_profile::file_io_finish(13, out.len(), sample);
        let version = match version {
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
                let mut bytes = alloc::vec![0; PAGE_SIZE];
                let start = key.2 * PAGE_SIZE as u32;
                let wanted = size.saturating_sub(start).min(PAGE_SIZE as u32) as usize;
                let n = self.mount_fs(mount).read(fid, start, &mut bytes[..wanted], size);
                if n != wanted as i32 { return if done != 0 { done as i32 } else if n < 0 { n } else { -5 }; }
                self.file_pages.get_mut(&key).unwrap().data.write(0, &bytes);
                self.file_pages.get_mut(&key).unwrap().version = version;
            }
            if !self.file_pages.contains_key(&key) {
                let _miss = crate::kernel::event_profile::FileIoScope::start(14, length - done);
                // Small consumers keep modest read-ahead. Bulk reads and ELF
                // mappings amortize storage commands over a larger fill; each
                // backend still applies its negotiated transport limits.
                let start = position - within as u32;
                let batch = if out.len() >= READ_BATCH * 2 { BULK_READ_BATCH } else { READ_BATCH };
                let mut wanted = (size - start).min(batch as u32) as usize;
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
                let _insert = crate::kernel::event_profile::FileIoScope::start(16, got);
                for begin in (0..got).step_by(PAGE_SIZE) {
                    let end = (begin + PAGE_SIZE).min(wanted);
                    if end > got || !self.make_page_room() { break; }
                    let mut tail;
                    let data = if end - begin == PAGE_SIZE { &bytes[begin..end] }
                    else {
                        tail = alloc::vec![0; PAGE_SIZE];
                        tail[..end - begin].copy_from_slice(&bytes[begin..end]);
                        &tail
                    };
                    self.page_clock = self.page_clock.wrapping_add(1);
                    if let Ok(page) = Page::clean(data, version, self.page_clock) {
                        self.cache_page((key.0, key.1, key.2 + (begin / PAGE_SIZE) as u32), page);
                    }
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
            if !page.pinned() { self.clean_pages.touch(key, self.page_clock); }
            if copy { page.data.read(within, &mut out[done..done + count]); }
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
                let at = (lo - u64::from(offset)) as usize;
                entry.data.write((lo - start) as usize, &data[at..at + (hi - lo) as usize]);
            }
        }
    }
}

pub fn validate(handle: i32, offset: usize, length: usize, writable: bool) -> Result<(), i32> {
    let vfs = VFS.lock();
    let e = vfs.file_table.get(handle as usize).filter(|e| e.refcount != 0).ok_or(-9)?;
    if !matches!(e.vnode.mode & 0o170000, 0 | 0o100000) { return Err(-19); }
    if writable && matches!(e.access, OpenAccess::Read) { return Err(-13); }
    if writable && !e.writable { return Err(-30); }
    if offset & 4095 != 0 { return Err(-22); }
    // Until mapped truncation can deliver SIGBUS, reject pages wholly beyond
    // EOF. A partial final page is zero-filled and never extends the file.
    if offset.checked_add(length).is_none_or(|end| end > (e.vnode.size as usize).div_ceil(4096) * 4096) {
        return Err(-22);
    }
    Ok(())
}

pub fn acquire<A: crate::Arch>(_machine: &mut A, handle: i32, offset: u32, writable: bool) -> Result<(Key, u64), i32> {
    let mut vfs = VFS.lock();
    let key = vfs.mapping_key(handle, offset)?;
    let mut bytes = alloc::vec![0; PAGE_SIZE];
    let n = vfs.cached_read(handle, offset, &mut bytes);
    if n < 0 { return Err(n); }
    let expected = vfs.file_table[handle as usize].vnode.size.saturating_sub(offset).min(PAGE_SIZE as u32);
    if n as u32 != expected { return Err(-5); }
    if !vfs.file_pages.contains_key(&key) { return Err(-12); }
    let physical = vfs.file_pages[&key].data.physical().ok_or(-12)?;
    if !vfs.file_pages[&key].pinned() {
        vfs.file_pages.get_mut(&key).unwrap().handle = handle;
        vfs.pin_mapping_handle(handle);
    } else if writable && !vfs.file_table[vfs.file_pages[&key].handle as usize].writable {
        let previous = vfs.file_pages[&key].handle;
        vfs.pin_mapping_handle(handle);
        vfs.file_pages.get_mut(&key).unwrap().handle = handle;
        vfs.unpin_mapping_handle(previous);
    }
    let page = vfs.file_pages.get_mut(&key).unwrap();
    page.refs += 1;
    page.writable |= writable;
    Ok((key, physical))
}

/// Private mappings own counted aliases. They need no retained backend handle
/// and survive eviction, close and fork through architecture frame ownership.
pub fn map_private<A: crate::Arch>(machine: &mut A, handle: i32, offset: usize,
    base: usize, length: usize, protection: u64) -> Result<(), i32>
{
    if offset & 4095 != 0 { return Err(-22); }
    let mut vfs = VFS.lock();
    let mut buffer = alloc::vec![0; BULK_READ_BATCH];
    let pages = length.div_ceil(4096);
    offset.checked_add(pages.checked_mul(4096).ok_or(-22)?).ok_or(-22)?;
    let version = vfs.check_content(handle)?;
    let file_size = vfs.file_table[handle as usize].vnode.size as usize;
    let mut page = 0;
    while page < pages {
        let at = offset.checked_add(page * 4096).filter(|&n| n <= u32::MAX as usize).ok_or(-22)?;
        let count = (pages - page).min(BULK_READ_BATCH / 4096);
        let wanted = (count * 4096).min(file_size.saturating_sub(at));
        let missing = (0..count).any(|index| {
            let position = at + index * 4096;
            position < file_size && vfs.mapping_key(handle, position as u32).is_ok_and(|key|
                vfs.file_pages.get(&key).is_none_or(|page| !page.writable && Some(page.version) != version))
        });
        if wanted > 0 && missing {
            let n = vfs.fill_cache(handle, at as u32, &mut buffer[..wanted], false);
            if n < 0 { return Err(n); }
            if n as usize != wanted { return Err(-5); }
        }
        for index in 0..count {
            let address = base + (page + index) * 4096;
            if at + index * 4096 >= file_size {
                machine.map_fresh_range(address / 4096, 1);
                machine.set_page_flags(address / 4096, 1, protection & 2 != 0, protection & 4 != 0);
                continue;
            }
            let key = vfs.mapping_key(handle, (at + index * 4096) as u32)?;
            let frame = vfs.file_pages.get(&key).and_then(|p| p.data.physical()).ok_or(-12)?;
            if !machine.map_frame(address / 4096, frame, false, protection & 2 != 0, protection & 4 != 0) {
                return Err(-12);
            }
        }
        page += count;
    }
    Ok(())
}

/// Called by the physical allocator on exhaustion, including ring 0. Never
/// reenter VFS or privileged frame operations: only transfer exclusive frames.
pub(crate) fn reclaim_frame() -> Option<u64> {
    let mut vfs = VFS.try_lock()?;
    while let Some(frame) = vfs.evict_clean_page() {
        if let Some(frame) = frame.into_reclaimed() { return Some(frame); }
    }
    None
}

pub(crate) fn reclaim_pressure() {
    if let Some(mut vfs) = VFS.try_lock() { vfs.make_page_room(); }
}

pub fn retain(key: Key) {
    VFS.lock().file_pages.get_mut(&key).expect("live mapped file page").refs += 1;
}

/// Caller must remove its guest alias before releasing the last reference.
pub fn release<A: crate::Arch>(_machine: &mut A, key: Key) {
    let mut vfs = VFS.lock();
    let page = vfs.file_pages.get_mut(&key).expect("live mapped file page");
    page.refs -= 1;
    if page.refs != 0 { return; }
    let status = vfs.flush_page(key);
    if status < 0 {
        crate::compact_dbg_println!("mapped file writeback failed: {}", status);
        return;
    }
    let handle = vfs.file_pages[&key].handle;
    let page = vfs.file_pages.get_mut(&key).unwrap();
    page.handle = -1;
    page.writable = false;
    let used = vfs.page_clock;
    vfs.clean_pages.touch(key, used);
    let status = vfs.unpin_mapping_handle(handle);
    if status < 0 { vfs.drop_clean_pages(); }
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
    use alloc::boxed::Box;
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
    fn pinned_mappings_do_not_consume_the_clean_read_cache_budget() {
        let (mut vfs, fs, h) = setup(READ_BATCH * 2);
        for index in 0..PAGE_LIMIT + 1 {
            let mut page = Page::clean(&alloc::vec![0; PAGE_SIZE], ContentVersion::LOCAL, 0).unwrap();
            page.handle = h;
            page.refs = 1;
            vfs.pin_mapping_handle(h);
            vfs.file_pages.insert((0, 999, index as u32), page);
        }
        let mut bytes = [0; 8192];
        assert_eq!(vfs.cached_read(h, 0, &mut bytes), 8192);
        assert_eq!(fs.reads.get(), 1, "one read-ahead batch serves both pages");
        assert_eq!(vfs.cached_read(h, 8192, &mut bytes), 8192);
        assert_eq!(fs.reads.get(), 1, "prefetched bytes survive alongside live mappings");
        assert_eq!(vfs.file_pages.values().filter(|p| p.pinned()).count(), PAGE_LIMIT + 1);
        assert!(vfs.file_pages.values().filter(|p| !p.pinned()).count() <= PAGE_LIMIT);
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
    fn large_reads_reuse_the_same_file_pages() {
        let (mut vfs, fs, h) = setup(1024 * 1024);
        // ELF metadata reads cache an initial 32 KiB. A following segment
        // starts inside that cached run and reads in 64 KiB chunks.
        let mut header = [0; 64];
        assert_eq!(vfs.cached_read(h, 0, &mut header), 64);
        let mut output = alloc::vec![0; 64 * 1024];
        for chunk in 0..8 {
            let offset = PAGE_SIZE + chunk * output.len();
            assert_eq!(vfs.cached_read(h, offset as u32, &mut output), output.len() as i32);
            assert!(output.iter().enumerate().all(|(i, &b)| b == (offset + i) as u8));
        }
        let reads = fs.reads.get();
        for chunk in 0..8 {
            let offset = PAGE_SIZE + chunk * output.len();
            assert_eq!(vfs.cached_read(h, offset as u32, &mut output), output.len() as i32);
        }
        assert_eq!(fs.reads.get(), reads, "large reads retain reusable pages");
    }

    #[test]
    fn bulk_cache_fills_amortize_backend_requests_without_changing_small_reads() {
        let (mut vfs, fs, handle) = setup(512 * 1024);
        let mut small = [0; 1];
        assert_eq!(vfs.cached_read(handle, 0, &mut small), 1);
        assert_eq!(vfs.file_pages.len(), READ_BATCH / PAGE_SIZE);
        let before = fs.reads.get();
        let mut bulk = alloc::vec![0; 256 * 1024];
        assert_eq!(vfs.cached_read(handle, 128 * 1024, &mut bulk), bulk.len() as i32);
        assert_eq!(fs.reads.get() - before, 2, "bulk consumers need two 128 KiB backend fills");
        assert!(bulk.iter().enumerate().all(|(i, &b)| b == (128 * 1024 + i) as u8));
    }

    #[test]
    fn streaming_reads_preserve_mapped_changes_and_external_freshness() {
        let (mut vfs, fs, h) = setup(256 * 1024);
        let mut small = [0; 8];
        assert_eq!(vfs.cached_read(h, 128 * 1024, &mut small), 8);
        let key = vfs.mapping_key(h, 128 * 1024).unwrap();
        let page = vfs.file_pages.get_mut(&key).unwrap();
        page.handle = h;
        page.refs = 1;
        page.writable = true;
        page.data.write(0, &[99]);
        let mut output = alloc::vec![0; 256 * 1024];
        assert_eq!(vfs.cached_read(h, 0, &mut output), output.len() as i32);
        assert_eq!(output[128 * 1024], 99);
        assert!(output.iter().enumerate().all(|(i, &b)| b == if i == 128 * 1024 { 99 } else { i as u8 }));
        assert_eq!(vfs.file_pages.len(), 64, "large reads use the same cache as mappings");
        fs.bytes.borrow_mut()[0] = 77;
        fs.revision.set(1);
        assert_eq!(vfs.cached_read(h, 0, &mut output), output.len() as i32);
        assert_eq!(output[0], 77);
        assert_eq!(output[128 * 1024], 99, "writable mapping retains ownership");
        fs.fail.set(true);
        assert_eq!(vfs.cached_read(h, 0, &mut output), -5);
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
        page.data.write(0, b"mapped!!");
        assert_eq!(vfs.cached_read(h, 0, &mut out), 8);
        assert_eq!(&out, b"mapped!!");
        assert_eq!(fs.reads.get(), 1);
        assert_eq!(vfs.write_at_by_handle(h, 0, b"write!!!"), 8);
        let page = &vfs.file_pages[&key];
        let mut bytes = [0; 8]; page.data.read(0, &mut bytes);
        assert_eq!(&bytes, b"write!!!");
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
