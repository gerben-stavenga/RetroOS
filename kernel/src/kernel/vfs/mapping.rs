//! Kernel-owned file pages, shared by guest mappings and ordinary VFS I/O.
//! Guest execution is stopped whenever the VFS lock accesses their kernel view.
use super::*;
use core::ptr::NonNull;

pub type Key = (u8, u64, u32);

pub(super) struct Page {
    base: usize,
    refs: usize,
    handle: i32,
    writable: bool,
}

impl Vfs {
    pub(super) fn has_mapped_path(&self, path: &[u8]) -> bool {
        self.mapped_pages.values().any(|page| self.file_table[page.handle as usize].path == path)
    }
    pub(super) fn zero_mapping_growth(&mut self, handle: i32, old_size: u32, size: u32) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, 0) else { return; };
        for (&(_, _, page), entry) in self.mapped_pages.range_mut((mount, ino, old_size / 4096)..=(mount, ino, size / 4096)) {
            let start = u64::from(page) * 4096;
            let lo = start.max(u64::from(old_size));
            let hi = (start + 4096).min(u64::from(size));
            if hi > lo {
                unsafe { core::ptr::write_bytes((entry.base + (lo - start) as usize) as *mut u8, 0, (hi - lo) as usize); }
            }
        }
    }
    fn mapping_key(&self, handle: i32, offset: u32) -> Result<Key, i32> {
        let entry = self.file_table.get(handle as usize).filter(|e| e.refcount != 0).ok_or(-9)?;
        Ok((entry.mount_idx, entry.ino, offset / 4096))
    }

    fn flush_page(&mut self, key: Key) -> i32 {
        let Some(page) = self.mapped_pages.get(&key) else { return 0; };
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
        let keys: Vec<_> = self.mapped_pages.range((mount, ino, 0)..=(mount, ino, u32::MAX))
            .map(|(&key, _)| key).collect();
        for key in keys {
            let status = self.flush_page(key);
            if status < 0 { return status; }
        }
        0
    }

    pub(super) fn mapped_read(&self, handle: i32, offset: u32, data: &mut [u8]) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, offset) else { return; };
        let end = u64::from(offset) + data.len() as u64;
        for (&(_, _, page), entry) in self.mapped_pages.range((mount, ino, offset / 4096)..=(mount, ino, (end / 4096) as u32)) {
            let start = u64::from(page) * 4096;
            let lo = start.max(u64::from(offset));
            let hi = (start + 4096).min(end);
            if hi > lo {
                // Cache and guest aliases refer to the same live allocation.
                unsafe { core::ptr::copy((entry.base + (lo - start) as usize) as *const u8,
                    data.as_mut_ptr().add((lo - u64::from(offset)) as usize), (hi - lo) as usize); }
            }
        }
    }

    pub(super) fn mapped_write(&mut self, handle: i32, offset: u32, data: &[u8]) {
        let Ok((mount, ino, _)) = self.mapping_key(handle, offset) else { return; };
        let end = u64::from(offset) + data.len() as u64;
        for (&(_, _, page), entry) in self.mapped_pages.range_mut((mount, ino, offset / 4096)..=(mount, ino, (end / 4096) as u32)) {
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
    if !vfs.mapped_pages.contains_key(&key) {
        let base = machine.alloc_shared_pages(1);
        let e = &vfs.file_table[handle as usize];
        let data = unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), 4096) };
        let length = e.vnode.size.saturating_sub(offset).min(4096) as usize;
        let mut read = 0;
        while read < length {
            let n = vfs.mount_fs(e.mount_idx).read(e.vnode.handle, offset + read as u32, &mut data[read..length], e.vnode.size);
            if n <= 0 {
                unsafe { machine.free_shared_pages(base, 1); }
                return Err(if n < 0 { n } else { -5 });
            }
            read += n as usize;
        }
        vfs.add_ref(handle);
        vfs.mapped_pages.insert(key, Page { base: base.as_ptr() as usize, refs: 0, handle, writable: false });
    }
    let page = vfs.mapped_pages.get_mut(&key).unwrap();
    page.refs += 1;
    page.writable |= writable;
    Ok((key, NonNull::new(page.base as *mut u8).unwrap()))
}

pub fn retain(key: Key) {
    VFS.lock().mapped_pages.get_mut(&key).expect("live mapped file page").refs += 1;
}

/// Caller must remove its guest alias before releasing the last reference.
pub fn release<A: crate::Arch>(machine: &mut A, key: Key) {
    let mut vfs = VFS.lock();
    let page = vfs.mapped_pages.get_mut(&key).expect("live mapped file page");
    page.refs -= 1;
    if page.refs != 0 { return; }
    let status = vfs.flush_page(key);
    if status < 0 {
        // Preserve modified RAM and its backing handle for later fsync/shutdown
        // retry rather than silently discarding data on a storage failure.
        crate::compact_dbg_println!("mapped file writeback failed: {}", status);
        return;
    }
    let page = vfs.mapped_pages.remove(&key).unwrap();
    unsafe { machine.free_shared_pages(NonNull::new(page.base as *mut u8).unwrap(), 1); }
    let status = vfs.close_handle(page.handle);
    if status < 0 { crate::compact_dbg_println!("mapped file close failed: {}", status); }
}

pub fn sync(key: Key) -> i32 {
    let mut vfs = VFS.lock();
    let Some(page) = vfs.mapped_pages.get(&key) else { return -12; };
    let handle = page.handle;
    let status = vfs.flush_handle(handle);
    if status < 0 { return status; }
    match vfs.handle_object(handle) { Some(object) => object.fs.sync(), None => -9 }
}
