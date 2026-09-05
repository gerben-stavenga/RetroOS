//! POSIX/VFS policy over the graph-only ext4 storage engine.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use crate::kernel::block::Volume;
use crate::kernel::vfs::{DirEntry, Filesystem, Meta, Stat, Vnode};
use portable_ext4::ext4::{
    AttributeUpdate, Blob, EdgeCursor, EdgeHandle, Node, Object, ObjectInfo,
};
use portable_ext4::{Error, Filesystem as HandleFilesystem, Storage, StorageError};

const TYPE_MASK: u16 = 0xf000;
const TYPE_NODE: u16 = 0x4000;
const TYPE_BLOB: u16 = 0x8000;
const TYPE_SYMLINK: u16 = 0xa000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeError {
    OutOfBounds,
    ShortRead,
    ShortWrite,
}

pub struct VolumeStorage {
    volume: Volume,
}

enum Transfer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl Transfer<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Read(bytes) => bytes.len(),
            Self::Write(bytes) => bytes.len(),
        }
    }
}

impl VolumeStorage {
    pub fn new(volume: Volume) -> Self {
        Self { volume }
    }

    #[inline(never)]
    fn transfer(&mut self, offset: u64, mut transfer: Transfer<'_>) -> Result<(), StorageError> {
        let len = transfer.len();
        let end = offset
            .checked_add(len as u64)
            .filter(|end| *end <= self.volume.sectors.saturating_mul(512))
            .ok_or(VolumeError::OutOfBounds)
            .map_err(StorageError::new)?;
        if len == 0 {
            return Ok(());
        }
        if offset.is_multiple_of(512) && len.is_multiple_of(512) {
            let writing = matches!(transfer, Transfer::Write(_));
            let transferred = match &mut transfer {
                Transfer::Read(bytes) => self.volume.read(offset / 512, bytes),
                Transfer::Write(bytes) => self.volume.write(offset / 512, bytes),
            } as usize;
            if transferred != len / 512 {
                return Err(StorageError::new(if writing {
                    VolumeError::ShortWrite
                } else {
                    VolumeError::ShortRead
                }));
            }
            return Ok(());
        }
        let mut position = offset;
        let mut copied = 0;
        let mut sector = [0; 512];
        while position < end {
            let lba = position / 512;
            if self.volume.read(lba, &mut sector) != 1 {
                return Err(StorageError::new(VolumeError::ShortRead));
            }
            let within = (position % 512) as usize;
            let amount = (len - copied).min(512 - within);
            match &mut transfer {
                Transfer::Read(bytes) => {
                    bytes[copied..copied + amount].copy_from_slice(&sector[within..within + amount])
                }
                Transfer::Write(bytes) => {
                    sector[within..within + amount]
                        .copy_from_slice(&bytes[copied..copied + amount]);
                    if self.volume.write(lba, &sector) != 1 {
                        return Err(StorageError::new(VolumeError::ShortWrite));
                    }
                }
            }
            copied += amount;
            position += amount as u64;
        }
        Ok(())
    }
}

impl Storage for VolumeStorage {
    fn len(&self) -> u64 {
        self.volume.sectors.saturating_mul(512)
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.transfer(offset, Transfer::Read(output))
    }

    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
        self.transfer(offset, Transfer::Write(input))
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Default)]
struct OpenFiles {
    slots: Vec<Option<Object>>,
}

impl OpenFiles {
    fn insert(&mut self, object: Object) -> u64 {
        if let Some(index) = self.slots.iter().position(Option::is_none) {
            self.slots[index] = Some(object);
            return index as u64 + 1;
        }
        self.slots.push(Some(object));
        self.slots.len() as u64
    }

    fn get(&self, handle: u64) -> Option<Object> {
        self.slots.get(handle.checked_sub(1)? as usize).copied()?
    }

    fn contains(&self, object: Object) -> bool {
        self.slots.iter().flatten().any(|open| *open == object)
    }

    fn remove(&mut self, handle: u64) {
        if let Some(slot) = handle
            .checked_sub(1)
            .and_then(|index| self.slots.get_mut(index as usize))
        {
            *slot = None;
        }
    }
}

#[derive(Clone, Copy)]
struct LocatedEdge {
    handle: EdgeHandle,
    object: Object,
}

struct MountedExt4 {
    filesystem: HandleFilesystem,
    storage: VolumeStorage,
}

impl MountedExt4 {
    fn parts(&mut self) -> (&mut HandleFilesystem, &mut VolumeStorage) {
        (&mut self.filesystem, &mut self.storage)
    }
}

pub struct PortableExt4Fs {
    mounted: RefCell<MountedExt4>,
    open: RefCell<OpenFiles>,
}

impl PortableExt4Fs {
    pub fn new(volume: Volume) -> Result<Self, &'static str> {
        let mut storage = VolumeStorage::new(volume);
        let filesystem = HandleFilesystem::mount(&mut storage)
            .map_err(|_| "portable ext4 mount failed")?;
        Ok(Self {
            mounted: RefCell::new(MountedExt4 {
                filesystem,
                storage,
            }),
            open: RefCell::new(OpenFiles::default()),
        })
    }

    fn path(path: &[u8]) -> Option<&[u8]> {
        let first = path
            .iter()
            .position(|byte| *byte != b'/')
            .unwrap_or(path.len());
        (!path.contains(&0)).then_some(&path[first..])
    }

    fn split_parent(path: &[u8]) -> Option<(&[u8], &[u8])> {
        let (parent, name) = match path.iter().rposition(|byte| *byte == b'/') {
            Some(slash) => (&path[..slash], &path[slash + 1..]),
            None => (&b""[..], path),
        };
        (!name.is_empty()).then_some((parent, name))
    }

    fn resolve_in(
        mounted: &mut MountedExt4,
        path: &[u8],
    ) -> Result<ObjectInfo, Error> {
        let (filesystem, storage) = mounted.parts();
        let root = filesystem.root(storage)?;
        let mut info = filesystem.inspect(storage, Object::Node(root))?;
        for name in path
            .split(|byte| *byte == b'/')
            .filter(|name| !name.is_empty())
        {
            if matches!(name, b"." | b"..") || name.len() > 255 {
                return Err(Error::InvalidArgument);
            }
            let node = info.node().ok_or(Error::NotDirectory)?;
            let (_, object) = filesystem
                .find(storage, node, name)?
                .ok_or(Error::NotFound)?;
            info = filesystem.inspect(storage, object)?;
        }
        Ok(info)
    }

    fn resolve(&self, path: &[u8]) -> Result<ObjectInfo, Error> {
        Self::resolve_in(&mut self.mounted.borrow_mut(), path)
    }

    fn parent_edge(&self, path: &[u8]) -> Result<(Node, LocatedEdge), Error> {
        let (parent_path, name) = Self::split_parent(path).ok_or(Error::InvalidArgument)?;
        let mut mounted = self.mounted.borrow_mut();
        let parent = Self::resolve_in(&mut mounted, parent_path)?
            .node()
            .ok_or(Error::NotDirectory)?;
        let (filesystem, storage) = mounted.parts();
        let (handle, object) = filesystem
            .find(storage, parent, name)?
            .ok_or(Error::NotFound)?;
        Ok((parent, LocatedEdge { handle, object }))
    }

    fn is_symlink(info: ObjectInfo) -> bool {
        info.format & TYPE_MASK == TYPE_SYMLINK
    }

    fn open_info(&self, info: ObjectInfo) -> Option<Vnode> {
        if info.node().is_some() || Self::is_symlink(info) {
            return None;
        }
        Some(Vnode {
            handle: self.open.borrow_mut().insert(info.object),
            size: info.size.min(u64::from(u32::MAX)) as u32,
            mode: info.format & 0x0fff,
        })
    }

    fn readlink_info(&self, info: ObjectInfo, output: &mut [u8]) -> Option<usize> {
        if !Self::is_symlink(info) {
            return None;
        }
        let count = output.len().min(info.size as usize);
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .read(storage, info.blob()?, 0, &mut output[..count])
            .ok()
    }

    fn append_entries(
        &self,
        node: Node,
        cookie: u64,
        output: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        let mut appended = 0;
        let next = filesystem
            .entries(
                storage,
                node,
                EdgeCursor::from_position(cookie),
                &mut |edge, info| {
                    output.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                    let name_len = edge.name.len().min(100);
                    let mut entry = DirEntry {
                        name: [0; 100],
                        name_len,
                        size: info.size.min(u64::from(u32::MAX)) as u32,
                        is_dir: info.node().is_some(),
                        is_symlink: Self::is_symlink(info),
                        mode: info.format & 0x0fff,
                        mtime: info.modified,
                        node: info.object.opaque(),
                        mount_idx: 0,
                    };
                    entry.name[..name_len].copy_from_slice(&edge.name[..name_len]);
                    output.push(entry);
                    appended += 1;
                    Ok(appended < max)
                },
            )
            .ok()?;
        next.map(EdgeCursor::position)
    }
}

pub fn is_ext(volume: &Volume) -> bool {
    let mut storage = VolumeStorage::new(*volume);
    let mut magic = [0; 2];
    storage.read(1024 + 56, &mut magic).is_ok() && magic == [0x53, 0xef]
}

pub fn is_linux_root(volume: &Volume) -> bool {
    PortableExt4Fs::new(*volume)
        .is_ok_and(|filesystem| filesystem.dir_exists(b"etc") && filesystem.dir_exists(b"usr"))
}

impl Filesystem for PortableExt4Fs {
    fn root_node(&self) -> Option<u64> {
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .root(storage)
            .ok()
            .map(|node| Object::Node(node).opaque())
    }

    fn open(&self, path: &[u8]) -> Option<Vnode> {
        self.open_info(self.resolve(Self::path(path)?).ok()?)
    }

    fn open_node(&self, node: u64) -> Option<Vnode> {
        let object = Object::from_opaque(node)?;
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        let info = filesystem.inspect(storage, object).ok()?;
        drop(mounted);
        self.open_info(info)
    }

    fn readlink_node(&self, node: u64, output: &mut [u8]) -> Option<usize> {
        let object = Object::from_opaque(node)?;
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        let info = filesystem.inspect(storage, object).ok()?;
        drop(mounted);
        self.readlink_info(info, output)
    }

    fn readdir_node(
        &self,
        node: u64,
        cookie: u64,
        output: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        let Object::Node(node) = Object::from_opaque(node)? else {
            return None;
        };
        self.append_entries(node, cookie, output, max)
    }

    fn readlink(&self, path: &[u8], output: &mut [u8]) -> Option<usize> {
        self.readlink_info(self.resolve(Self::path(path)?).ok()?, output)
    }

    fn stat(&self, path: &[u8], _follow_final: bool) -> Option<Stat> {
        let info = self.resolve(Self::path(path)?).ok()?;
        Some(Stat {
            size: info.size.min(u64::from(u32::MAX)) as u32,
            mode: info.format & 0x0fff,
            is_dir: info.node().is_some(),
            is_symlink: Self::is_symlink(info),
            ino: info.object.opaque(),
        })
    }

    fn read(&self, handle: u64, offset: u32, output: &mut [u8], _size: u32) -> i32 {
        let Some(Object::Blob(blob)) = self.open.borrow().get(handle) else {
            return -9;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .read(storage, blob, u64::from(offset), output)
            .map_or(-5, |count| count as i32)
    }

    fn write(&self, handle: u64, offset: u32, input: &[u8]) -> i32 {
        let Some(Object::Blob(blob)) = self.open.borrow().get(handle) else {
            return -9;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .write(storage, blob, u64::from(offset), input)
            .map_or(-5, |_| input.len() as i32)
    }

    fn create(&self, path: &[u8]) -> Option<Vnode> {
        let path = Self::path(path)?;
        if let Ok(mut info) = self.resolve(path) {
            let blob = graph_blob(info)?;
            let mut mounted = self.mounted.borrow_mut();
            let (filesystem, storage) = mounted.parts();
            filesystem.resize(storage, blob, 0).ok()?;
            info.size = 0;
            drop(mounted);
            return self.open_info(info);
        }
        let (parent_path, name) = Self::split_parent(path)?;
        let parent = self.resolve(parent_path).ok()?.node()?;
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        let object = filesystem
            .create_blob(
                storage,
                parent,
                name,
                AttributeUpdate {
                    format: Some(TYPE_BLOB | 0o664),
                    ..AttributeUpdate::default()
                },
            )
            .ok()?;
        let info = filesystem.inspect(storage, object).ok()?;
        drop(mounted);
        self.open_info(info)
    }

    fn supports_create(&self) -> bool {
        true
    }

    fn mkdir(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Some((parent_path, name)) = Self::split_parent(path) else {
            return -22;
        };
        let Ok(parent) = self
            .resolve(parent_path)
            .and_then(|info| info.node().ok_or(Error::NotDirectory))
        else {
            return -5;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .create_node(
                storage,
                parent,
                name,
                AttributeUpdate {
                    format: Some(TYPE_NODE | 0o775),
                    ..AttributeUpdate::default()
                },
            )
            .map_or(-5, |_| 0)
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    fn rmdir(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Ok((_, edge)) = self.parent_edge(path) else {
            return -2;
        };
        if !matches!(edge.object, Object::Node(_)) {
            return -20;
        }
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .remove(storage, edge.handle)
            .map_or(-5, |_| 0)
    }

    fn rename(&self, path: &[u8], new_path: &[u8]) -> i32 {
        let (Some(path), Some(new_path)) = (Self::path(path), Self::path(new_path)) else {
            return -22;
        };
        let Some((target_parent_path, target_name)) = Self::split_parent(new_path) else {
            return -22;
        };
        let Ok((_, source)) = self.parent_edge(path) else {
            return -2;
        };
        let Ok(target_parent) = self
            .resolve(target_parent_path)
            .and_then(|info| info.node().ok_or(Error::NotDirectory))
        else {
            return -5;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        match filesystem.find(storage, target_parent, target_name) {
            Ok(Some((_, target))) => {
                if matches!(source.object, Object::Node(_)) != matches!(target, Object::Node(_)) {
                    return -22;
                }
            }
            Ok(None) => {}
            Err(_) => return -5,
        }
        filesystem
            .move_edge(storage, source.handle, target_parent, target_name)
            .map_or(-5, |_| 0)
    }

    fn supports_directory_mutation(&self) -> bool {
        true
    }

    fn readdir(
        &self,
        path: &[u8],
        cookie: u64,
        output: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        let node = self.resolve(Self::path(path)?).ok()?.node()?;
        self.append_entries(node, cookie, output, max)
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        Self::path(path)
            .is_some_and(|path| self.resolve(path).is_ok_and(|info| info.node().is_some()))
    }

    fn mtime(&self, path: &[u8]) -> Option<u32> {
        Some(self.resolve(Self::path(path)?).ok()?.modified)
    }

    fn set_mtime(&self, path: &[u8], mtime: u32) -> bool {
        let Some(path) = Self::path(path) else {
            return false;
        };
        let Ok(info) = self.resolve(path) else {
            return false;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .update_attributes(
                storage,
                info.object,
                AttributeUpdate {
                    modified: Some(mtime),
                    ..AttributeUpdate::default()
                },
            )
            .is_ok()
    }

    fn meta(&self, path: &[u8]) -> Option<Meta> {
        let info = self.resolve(Self::path(path)?).ok()?;
        Some(Meta {
            uid: info.owner,
            gid: info.group,
            mode: u32::from(info.format),
        })
    }

    fn set_meta(&self, path: &[u8], uid: u32, gid: u32, mode: u32) -> bool {
        let Some(path) = Self::path(path) else {
            return false;
        };
        let Ok(info) = self.resolve(path) else {
            return false;
        };
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .update_attributes(
                storage,
                info.object,
                AttributeUpdate {
                    format: Some((info.format & TYPE_MASK) | mode as u16 & 0x0fff),
                    owner: Some(uid),
                    group: Some(gid),
                    ..AttributeUpdate::default()
                },
            )
            .is_ok()
    }

    fn remove(&self, path: &[u8]) -> i32 {
        let Some(path) = Self::path(path) else {
            return -22;
        };
        let Ok((_, edge)) = self.parent_edge(path) else {
            return -2;
        };
        if matches!(edge.object, Object::Node(_)) {
            return -21;
        }
        if self.open.borrow().contains(edge.object) {
            return -16;
        }
        let mut mounted = self.mounted.borrow_mut();
        let (filesystem, storage) = mounted.parts();
        filesystem
            .remove(storage, edge.handle)
            .map_or(-5, |_| 0)
    }

    fn clunk(&self, handle: u64) {
        self.open.borrow_mut().remove(handle);
    }
}

fn graph_blob(info: ObjectInfo) -> Option<Blob> {
    info.blob()
        .filter(|_| info.format & TYPE_MASK != TYPE_SYMLINK)
}
