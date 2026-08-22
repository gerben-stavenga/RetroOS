//! RetroOS VFS adapter for the portable ext4 engine.
//!
//! This is RetroOS's ext2/3/4 filesystem backend for both writable roots and
//! additional read-only volumes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::kernel::block::Volume;
use crate::kernel::vfs::{DirEntry, Filesystem, Meta, Vnode};
use portable_ext4::{
    DirectoryEntry as ExtDirectoryEntry, Ext4, Inode, InodeMetadataUpdate, Storage, Timestamp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeError {
    OutOfBounds,
    ShortRead,
    ShortWrite,
}

/// Byte-addressed exact I/O over RetroOS's sector-addressed partition view.
pub struct VolumeStorage {
    volume: Volume,
}

impl VolumeStorage {
    pub fn new(volume: Volume) -> Self {
        Self { volume }
    }
}

impl Storage for VolumeStorage {
    type Error = VolumeError;

    fn len(&self) -> u64 {
        self.volume.sectors.saturating_mul(512)
    }

    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = offset
            .checked_add(dst.len() as u64)
            .filter(|end| *end <= self.len())
            .ok_or(VolumeError::OutOfBounds)?;
        if dst.is_empty() {
            return Ok(());
        }
        if offset.is_multiple_of(512) && dst.len().is_multiple_of(512) {
            let expected = dst.len() / 512;
            if self.volume.read(offset / 512, dst) as usize != expected {
                return Err(VolumeError::ShortRead);
            }
            return Ok(());
        }

        let mut position = offset;
        let mut copied = 0usize;
        let mut sector = [0u8; 512];
        while position < end {
            let lba = position / 512;
            if self.volume.read(lba, &mut sector) != 1 {
                return Err(VolumeError::ShortRead);
            }
            let within = (position % 512) as usize;
            let amount = (dst.len() - copied).min(512 - within);
            dst[copied..copied + amount].copy_from_slice(&sector[within..within + amount]);
            copied += amount;
            position += amount as u64;
        }
        Ok(())
    }

    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), Self::Error> {
        let end = offset
            .checked_add(src.len() as u64)
            .filter(|end| *end <= self.len())
            .ok_or(VolumeError::OutOfBounds)?;
        if src.is_empty() {
            return Ok(());
        }
        if offset.is_multiple_of(512) && src.len().is_multiple_of(512) {
            let expected = src.len() / 512;
            if self.volume.write(offset / 512, src) as usize != expected {
                return Err(VolumeError::ShortWrite);
            }
            return Ok(());
        }

        let mut position = offset;
        let mut copied = 0usize;
        let mut sector = [0u8; 512];
        while position < end {
            let lba = position / 512;
            if self.volume.read(lba, &mut sector) != 1 {
                return Err(VolumeError::ShortRead);
            }
            let within = (position % 512) as usize;
            let amount = (src.len() - copied).min(512 - within);
            sector[within..within + amount].copy_from_slice(&src[copied..copied + amount]);
            if self.volume.write(lba, &sector) != 1 {
                return Err(VolumeError::ShortWrite);
            }
            copied += amount;
            position += amount as u64;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct OpenFile {
    inode: Inode,
}

/// Writable VFS adapter for the portable ext4 engine.
pub struct PortableExt4Fs {
    filesystem: RefCell<Ext4<VolumeStorage>>,
    open_files: RefCell<BTreeMap<u64, OpenFile>>,
    next_handle: Cell<u64>,
}

impl PortableExt4Fs {
    pub fn new(volume: Volume) -> Result<Self, &'static str> {
        let filesystem =
            Ext4::mount(VolumeStorage::new(volume)).map_err(|_| "portable ext4 mount failed")?;
        Ok(Self {
            filesystem: RefCell::new(filesystem),
            open_files: RefCell::new(BTreeMap::new()),
            next_handle: Cell::new(1),
        })
    }

    fn path(path: &[u8]) -> Option<String> {
        let path = core::str::from_utf8(path).ok()?;
        let mut absolute = String::with_capacity(path.len() + 1);
        absolute.push('/');
        absolute.push_str(path.trim_start_matches('/'));
        Some(absolute)
    }

    fn allocate_handle(&self, inode: Inode) -> u64 {
        let handle = self.next_handle.get();
        self.next_handle.set(handle.wrapping_add(1));
        self.open_files
            .borrow_mut()
            .insert(handle, OpenFile { inode });
        handle
    }

    fn split_parent(path: &str) -> Option<(&str, &str)> {
        let (parent, name) = path.rsplit_once('/')?;
        if name.is_empty() {
            return None;
        }
        Some((if parent.is_empty() { "/" } else { parent }, name))
    }

    fn reserve_for_data(data_len: usize) -> usize {
        data_len.div_ceil(4096).saturating_add(64)
    }

    fn find_entry(
        filesystem: &mut Ext4<VolumeStorage>,
        directory: &Inode,
        name: &[u8],
    ) -> Result<Option<ExtDirectoryEntry>, ()> {
        let mut cookie = 0;
        loop {
            let mut entries = Vec::new();
            let next = filesystem
                .list(directory, cookie, &mut entries, 64)
                .map_err(|_| ())?;
            if let Some(entry) = entries.into_iter().find(|entry| entry.name == name) {
                return Ok(Some(entry));
            }
            match next {
                Some(next) => cookie = next,
                None => return Ok(None),
            }
        }
    }

    fn resolve_in(
        filesystem: &mut Ext4<VolumeStorage>,
        path: &str,
        follow_final: bool,
    ) -> Result<Inode, ()> {
        let mut current = path.to_string();
        for _ in 0..40 {
            let components: Vec<String> = current
                .split('/')
                .filter(|component| !component.is_empty() && *component != ".")
                .map(ToString::to_string)
                .collect();
            let mut inode = filesystem.root().map_err(|_| ())?;
            let mut followed = false;
            for (index, component) in components.iter().enumerate() {
                if component == ".." || !inode.is_directory() {
                    return Err(());
                }
                inode = Self::find_entry(filesystem, &inode, component.as_bytes())?
                    .ok_or(())?
                    .inode;
                if inode.is_symlink() && (follow_final || index + 1 != components.len()) {
                    let target = filesystem.read_symlink(&inode).map_err(|_| ())?;
                    let target = core::str::from_utf8(&target).map_err(|_| ())?;
                    let parent = if index == 0 {
                        "/".to_string()
                    } else {
                        format!("/{}/", components[..index].join("/"))
                    };
                    let remainder = components[index + 1..].join("/");
                    current = if target.starts_with('/') {
                        format!("{target}/{remainder}")
                    } else {
                        format!("{parent}{target}/{remainder}")
                    };
                    followed = true;
                    break;
                }
            }
            if !followed {
                return Ok(inode);
            }
        }
        Err(())
    }

    fn resolve(&self, path: &str, follow_final: bool) -> Result<Inode, ()> {
        Self::resolve_in(&mut self.filesystem.borrow_mut(), path, follow_final)
    }

    fn parent_entry(&self, path: &str) -> Result<(Inode, ExtDirectoryEntry), ()> {
        let (parent_path, name) = Self::split_parent(path).ok_or(())?;
        let mut filesystem = self.filesystem.borrow_mut();
        let parent = Self::resolve_in(&mut filesystem, parent_path, true)?;
        let entry = Self::find_entry(&mut filesystem, &parent, name.as_bytes())?.ok_or(())?;
        Ok((parent, entry))
    }

    fn commit(
        &self,
        reserve: usize,
        operation: impl FnOnce(
            &mut portable_ext4::Transaction<'_, VolumeStorage>,
        ) -> Result<(), portable_ext4::Error<VolumeError>>,
    ) -> bool {
        let mut filesystem = self.filesystem.borrow_mut();
        let mut transaction = filesystem.begin_transaction();
        transaction.reserve_blocks(reserve).is_ok()
            && operation(&mut transaction).is_ok()
            && transaction.commit().is_ok()
    }
}

/// Does `volume` contain an ext superblock?
///
/// Partition type bytes and GUIDs are only declarations. Probe the on-disk
/// magic so an ext filesystem is found regardless of how its partition was
/// labelled, while unsupported ext features still produce a useful mount
/// error instead of making the filesystem disappear from discovery.
pub fn is_ext(volume: &Volume) -> bool {
    let mut storage = VolumeStorage::new(*volume);
    let mut magic = [0u8; 2];
    storage.read(1024 + 56, &mut magic).is_ok() && magic == [0x53, 0xef]
}

/// Does this ext volume look like a Linux root (`/etc` and `/usr`)?
///
/// Used only to disambiguate disks containing more than one ext partition.
pub fn is_linux_root(volume: &Volume) -> bool {
    PortableExt4Fs::new(*volume)
        .is_ok_and(|filesystem| filesystem.dir_exists(b"etc") && filesystem.dir_exists(b"usr"))
}

impl Filesystem for PortableExt4Fs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let path = Self::path(path)?;
        let inode = self.resolve(&path, true).ok()?;
        if inode.is_directory() {
            return None;
        }
        Some(Vnode {
            handle: self.allocate_handle(inode.clone()),
            size: inode.size.min(u64::from(u32::MAX)) as u32,
            mode: inode.mode & 0x0fff,
        })
    }

    fn read(&self, handle: u64, offset: u32, buffer: &mut [u8], _size: u32) -> i32 {
        let inode = {
            let files = self.open_files.borrow();
            let Some(file) = files.get(&handle) else {
                return -9;
            };
            file.inode.clone()
        };
        self.filesystem
            .borrow_mut()
            .read_inode(&inode, u64::from(offset), buffer)
            .map_or(-5, |count| count as i32)
    }

    fn write(&self, handle: u64, offset: u32, data: &[u8]) -> i32 {
        let inode = {
            let files = self.open_files.borrow();
            let Some(file) = files.get(&handle) else {
                return -9;
            };
            file.inode.clone()
        };
        let offset = u64::from(offset);
        let current = match self.filesystem.borrow_mut().refresh(&inode) {
            Ok(inode) => inode,
            Err(_) => return -5,
        };
        if offset > current.size
            && !self.commit(
                Self::reserve_for_data((offset - current.size) as usize),
                |transaction| transaction.resize_inode(&current, offset),
            )
        {
            return -5;
        }
        if data.is_empty() {
            return 0;
        }
        let inode = match self.filesystem.borrow_mut().refresh(&inode) {
            Ok(inode) => inode,
            Err(_) => return -5,
        };
        if self.commit(Self::reserve_for_data(data.len()), |transaction| {
            transaction.write_inode(&inode, offset, data)
        }) {
            data.len() as i32
        } else {
            -5
        }
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        let path = Self::path(path)?;
        let exists = self.resolve(&path, true).ok();
        let success = if let Some(inode) = exists {
            !inode.is_directory()
                && self.commit(64, |transaction| transaction.resize_inode(&inode, 0))
        } else {
            let (parent, name) = Self::split_parent(&path)?;
            let parent = self.resolve(parent, true).ok()?;
            self.commit(64, |transaction| {
                transaction
                    .create_file(&parent, name.as_bytes(), 0o664)
                    .map(|_| ())
            })
        };
        if !success {
            return None;
        }
        let inode = self.resolve(&path, true).ok()?;
        Some(Vnode {
            handle: self.allocate_handle(inode),
            size: 0,
            mode: 0o664,
        })
    }

    fn supports_create(&self) -> bool {
        true
    }

    fn mkdir(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Some((parent, name)) = Self::split_parent(&path) else {
            return -22;
        };
        let Ok(parent) = self.resolve(parent, true) else {
            return -2;
        };
        if self.commit(64, |transaction| {
            transaction
                .create_directory(&parent, name.as_bytes(), 0o775)
                .map(|_| ())
        }) {
            0
        } else {
            -5
        }
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    fn rmdir(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Ok((parent, entry)) = self.parent_entry(&path) else {
            return -2;
        };
        if self.commit(64, |transaction| {
            transaction.remove_directory(&parent, &entry)
        }) {
            0
        } else {
            -5
        }
    }

    fn rename(&self, path: &[u8], new_path: &[u8]) -> i32 {
        let (Some(path), Some(new_path)) = (Self::path(path), Self::path(new_path)) else {
            return -22;
        };
        let Ok((old_parent, source)) = self.parent_entry(&path) else {
            return -2;
        };
        let Some((new_parent_path, new_name)) = Self::split_parent(&new_path) else {
            return -22;
        };
        let Ok(new_parent) = self.resolve(new_parent_path, true) else {
            return -2;
        };
        let destination = {
            let mut filesystem = self.filesystem.borrow_mut();
            match Self::find_entry(&mut filesystem, &new_parent, new_name.as_bytes()) {
                Ok(entry) => entry,
                Err(()) => return -5,
            }
        };
        if !self.commit(96, |transaction| {
            transaction.move_entry(
                &old_parent,
                &source,
                &new_parent,
                new_name.as_bytes(),
                destination.as_ref(),
            )
        }) {
            return -5;
        }
        0
    }

    fn supports_directory_mutation(&self) -> bool {
        true
    }

    fn flush(&self, _path: &[u8]) -> i32 {
        0
    }

    fn readdir(
        &self,
        directory: &[u8],
        cookie: u64,
        output: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        let path = Self::path(directory)?;
        let directory = self.resolve(&path, true).ok()?;
        let mut entries = Vec::new();
        let next = self
            .filesystem
            .borrow_mut()
            .list(&directory, cookie, &mut entries, max)
            .ok()?;
        for entry in entries {
            let name_len = entry.name.len().min(100);
            let mut result = DirEntry {
                name: [0; 100],
                name_len,
                size: if entry.inode.is_directory() {
                    0
                } else {
                    entry.inode.size.min(u64::from(u32::MAX)) as u32
                },
                is_dir: entry.inode.is_directory(),
                mode: entry.inode.mode & 0x0fff,
                mtime: u32::try_from(entry.inode.modified.seconds).unwrap_or(0),
            };
            result.name[..name_len].copy_from_slice(&entry.name[..name_len]);
            output.push(result);
        }
        next
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        Self::path(path).is_some_and(|path| {
            self.resolve(&path, true)
                .is_ok_and(|inode| inode.is_directory())
        })
    }

    fn mtime(&self, path: &[u8]) -> Option<u32> {
        let path = Self::path(path)?;
        self.resolve(&path, true)
            .ok()
            .and_then(|inode| u32::try_from(inode.modified.seconds).ok())
    }

    fn set_mtime(&self, path: &[u8], mtime: u32) -> bool {
        let Some(path) = Self::path(path) else {
            return false;
        };
        let Ok(inode) = self.resolve(&path, true) else {
            return false;
        };
        self.commit(4, |transaction| {
            transaction.set_inode_times(
                &inode,
                None,
                Some(Timestamp {
                    seconds: i64::from(mtime),
                    nanoseconds: 0,
                }),
                None,
            )
        })
    }

    fn meta(&self, path: &[u8]) -> Option<Meta> {
        let path = Self::path(path)?;
        let inode = self.resolve(&path, true).ok()?;
        Some(Meta {
            uid: inode.uid,
            gid: inode.gid,
            mode: u32::from(inode.mode),
        })
    }

    fn set_meta(&self, path: &[u8], uid: u32, gid: u32, mode: u32) -> bool {
        let Some(path) = Self::path(path) else {
            return false;
        };
        let Ok(permissions) = u16::try_from(mode & 0x0fff) else {
            return false;
        };
        let Ok(inode) = self.resolve(&path, true) else {
            return false;
        };
        self.commit(4, |transaction| {
            transaction.update_metadata(
                &inode,
                InodeMetadataUpdate {
                    permissions: Some(permissions),
                    uid: Some(uid),
                    gid: Some(gid),
                    ..InodeMetadataUpdate::default()
                },
            )
        })
    }

    fn remove(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Ok((parent, entry)) = self.parent_entry(&path) else {
            return -2;
        };
        if self
            .open_files
            .borrow()
            .values()
            .any(|file| file.inode.number == entry.inode.number)
        {
            return -16;
        }
        if self.commit(64, |transaction| transaction.remove_entry(&parent, &entry)) {
            0
        } else {
            -5
        }
    }

    fn clunk(&self, handle: u64) {
        self.open_files.borrow_mut().remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Filesystem, PortableExt4Fs, is_ext};
    use crate::kernel::block::{Disk, Volume};
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    struct ImageDisk {
        bytes: RefCell<Vec<u8>>,
    }

    impl Disk for ImageDisk {
        fn read(&self, lba: u64, buffer: &mut [u8]) -> u32 {
            let start = lba as usize * 512;
            let bytes = self.bytes.borrow();
            let Some(bytes) = bytes.get(start..start + buffer.len()) else {
                return 0;
            };
            buffer.copy_from_slice(bytes);
            buffer.len().div_ceil(512) as u32
        }

        fn write(&self, lba: u64, buffer: &[u8]) -> u32 {
            let start = lba as usize * 512;
            let mut bytes = self.bytes.borrow_mut();
            let Some(destination) = bytes.get_mut(start..start + buffer.len()) else {
                return 0;
            };
            destination.copy_from_slice(buffer);
            buffer.len().div_ceil(512) as u32
        }

        fn sectors(&self) -> u64 {
            (self.bytes.borrow().len() / 512) as u64
        }

        fn name(&self) -> &str {
            "portable-ext4-test"
        }
    }

    fn filesystem_from(relative: &str) -> PortableExt4Fs {
        let image =
            std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap()).join(relative);
        let bytes = std::fs::read(image).unwrap();
        let disk: &'static dyn Disk = Box::leak(Box::new(ImageDisk {
            bytes: RefCell::new(bytes),
        }));
        PortableExt4Fs::new(Volume::whole(disk)).unwrap()
    }

    fn filesystem() -> PortableExt4Fs {
        filesystem_from(env!("EXT4_MODERN_IMAGE"))
    }

    fn volume(bytes: Vec<u8>) -> Volume {
        let disk: &'static dyn Disk = Box::leak(Box::new(ImageDisk {
            bytes: RefCell::new(bytes),
        }));
        Volume::whole(disk)
    }

    #[test]
    fn ext_probe_reads_the_superblock_magic() {
        let mut image = vec![0; 2048];
        image[1024 + 56..1024 + 58].copy_from_slice(&[0x53, 0xef]);
        assert!(is_ext(&volume(image)));
        assert!(!is_ext(&volume(vec![0; 2048])));
    }

    #[test]
    fn vfs_adapter_mounts_current_distro_default_profile() {
        let filesystem = filesystem_from(env!("EXT4_MODERN_DEFAULTS_IMAGE"));
        let file = filesystem.open(b"file-0.txt").unwrap();
        let mut contents = [0; 14];
        assert_eq!(
            filesystem.read(file.handle, 0, &mut contents, file.size),
            14
        );
        assert_eq!(&contents, b"portable ext4\n");
    }

    #[test]
    fn vfs_adapter_reads_symlinks_and_resumes_directories() {
        let fs = filesystem();
        let vnode = fs.open(b"dir/hello.link").unwrap();
        let mut contents = [0; 14];
        assert_eq!(fs.read(vnode.handle, 0, &mut contents, vnode.size), 14);
        assert_eq!(&contents, b"portable ext4\n");
        fs.clunk(vnode.handle);

        let mut entries = Vec::new();
        let mut cookie = 0;
        loop {
            match fs.readdir(b"dir", cookie, &mut entries, 19) {
                Some(next) => cookie = next,
                None => break,
            }
        }
        assert_eq!(entries.len(), 303);
        assert!(
            entries
                .iter()
                .any(|entry| { &entry.name[..entry.name_len] == b"file-299" && entry.size == 14 })
        );
    }

    #[test]
    fn vfs_adapter_mutates_files_and_directories() {
        let fs = filesystem();
        let vnode = fs.create(b"adapter-new").unwrap();
        let payload = vec![0x5a; 6000];
        assert_eq!(fs.write(vnode.handle, 0, &payload), payload.len() as i32);
        fs.clunk(vnode.handle);

        let vnode = fs.open(b"adapter-new").unwrap();
        let mut contents = vec![0; payload.len()];
        assert_eq!(
            fs.read(vnode.handle, 0, &mut contents, vnode.size),
            payload.len() as i32
        );
        assert_eq!(contents, payload);
        fs.clunk(vnode.handle);

        assert_eq!(fs.mkdir(b"adapter-dir"), 0);
        assert_eq!(fs.rename(b"adapter-new", b"adapter-dir/moved"), 0);
        assert!(fs.set_mtime(b"adapter-dir/moved", 1_700_000_000));
        assert!(fs.set_meta(b"adapter-dir/moved", 12, 34, 0o640));
        assert_eq!(fs.mtime(b"adapter-dir/moved"), Some(1_700_000_000));
        assert_eq!(fs.remove(b"adapter-dir/moved"), 0);
        assert_eq!(fs.rmdir(b"adapter-dir"), 0);
    }
}
