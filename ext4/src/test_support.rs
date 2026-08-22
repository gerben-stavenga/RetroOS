//! Deterministic storage for fault and power-loss testing.
//!
//! This is public rather than `cfg(test)`: downstream kernels should be able to
//! run the exact same filesystem code against the model in their own tests.

use crate::{
    Corrupt, DirectoryEntry, Error, Ext4, Inode, InodeMetadataUpdate, Storage, Timestamp,
    Transaction,
};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Path-shaped conveniences used only by the image-validation corpus.
///
/// Production users deliberately see only inode and directory-entry APIs.
pub trait PathExt4 {
    fn stat<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<Inode, Error<S::Error>>;
    fn read<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error<S::Error>>;
    fn read_link<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<Vec<u8>, Error<S::Error>>;
    fn read_dir<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error<S::Error>>;
}

impl PathExt4 for Ext4 {
    fn stat<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<Inode, Error<S::Error>> {
        resolve_path(self, storage, path, true)
    }

    fn read<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error<S::Error>> {
        let inode = resolve_path(self, storage, path, true)?;
        self.read_inode(storage, &inode, offset, dst)
    }

    fn read_link<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let inode = resolve_path(self, storage, path, false)?;
        self.read_symlink(storage, &inode)
    }

    fn read_dir<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error<S::Error>> {
        let inode = resolve_path(self, storage, path, true)?;
        self.list(storage, &inode, cookie, output, max)
    }
}

pub trait PathTransaction {
    fn set_metadata<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        update: InodeMetadataUpdate,
    ) -> Result<(), Error<S::Error>>;
    fn chmod<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        permissions: u16,
    ) -> Result<(), Error<S::Error>>;
    fn chown<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error<S::Error>>;
    fn set_times<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
    ) -> Result<(), Error<S::Error>>;
    fn write_at<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>>;
    fn overwrite<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>>;
    fn append_zeroed_block<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<u64, Error<S::Error>>;
    fn initialize_file<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        data: &[u8],
    ) -> Result<(), Error<S::Error>>;
    fn append<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        data: &[u8],
    ) -> Result<(), Error<S::Error>>;
    fn create_empty_file<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &str,
        name: &str,
        permissions: u16,
    ) -> Result<u32, Error<S::Error>>;
    fn symlink<S: Storage>(
        &mut self,
        storage: &mut S,
        target: &str,
        path: &str,
    ) -> Result<u32, Error<S::Error>>;
    fn link<S: Storage>(
        &mut self,
        storage: &mut S,
        existing: &str,
        path: &str,
    ) -> Result<(), Error<S::Error>>;
    fn mkdir<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &str,
        name: &str,
        permissions: u16,
    ) -> Result<u32, Error<S::Error>>;
    fn unlink<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<(), Error<S::Error>>;
    fn rmdir<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<(), Error<S::Error>>;
    fn rename<S: Storage>(
        &mut self,
        storage: &mut S,
        old: &str,
        new: &str,
    ) -> Result<(), Error<S::Error>>;
    fn resize<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        size: u64,
    ) -> Result<(), Error<S::Error>>;
    fn truncate_to_zero<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<u64, Error<S::Error>>;
}

impl PathTransaction for Transaction<'_> {
    fn set_metadata<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        update: InodeMetadataUpdate,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.update_metadata(storage, &inode, update)
    }

    fn chmod<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        permissions: u16,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.chmod_inode(storage, &inode, permissions)
    }

    fn chown<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.chown_inode(storage, &inode, uid, gid)
    }

    fn set_times<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.set_inode_times(storage, &inode, accessed, modified, changed)
    }

    fn write_at<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.write_inode(storage, &inode, offset, data)
    }

    fn overwrite<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.overwrite_inode_range(storage, &inode, offset, data)
    }

    fn append_zeroed_block<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<u64, Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.append_zeroed_inode_block(storage, &inode)
    }

    fn initialize_file<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.initialize_inode(storage, &inode, data)
    }

    fn append<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.append_inode(storage, &inode, data)
    }

    fn create_empty_file<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &str,
        name: &str,
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        let parent = resolve_path(self.filesystem, storage, parent, true)?;
        self.create_file(storage, &parent, name.as_bytes(), permissions)
    }

    fn symlink<S: Storage>(
        &mut self,
        storage: &mut S,
        target: &str,
        path: &str,
    ) -> Result<u32, Error<S::Error>> {
        let normalized = normalize(path)?;
        let (parent, name) = split_parent(&normalized)?;
        let parent = resolve_path(self.filesystem, storage, parent, true)?;
        self.create_symlink(storage, &parent, name.as_bytes(), target.as_bytes())
    }

    fn link<S: Storage>(
        &mut self,
        storage: &mut S,
        existing: &str,
        path: &str,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, existing, false)?;
        let normalized = normalize(path)?;
        let (parent, name) = split_parent(&normalized)?;
        let parent = resolve_path(self.filesystem, storage, parent, true)?;
        self.create_link(storage, &inode, &parent, name.as_bytes())
    }

    fn mkdir<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &str,
        name: &str,
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        let parent = resolve_path(self.filesystem, storage, parent, true)?;
        self.create_directory(storage, &parent, name.as_bytes(), permissions)
    }

    fn unlink<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<(), Error<S::Error>> {
        let (parent, entry) = resolve_parent_entry(self.filesystem, storage, path)?;
        self.remove_entry(storage, &parent, &entry)
    }

    fn rmdir<S: Storage>(&mut self, storage: &mut S, path: &str) -> Result<(), Error<S::Error>> {
        let (parent, entry) = resolve_parent_entry(self.filesystem, storage, path)?;
        self.remove_directory(storage, &parent, &entry)
    }

    fn rename<S: Storage>(
        &mut self,
        storage: &mut S,
        old: &str,
        new: &str,
    ) -> Result<(), Error<S::Error>> {
        let (old_parent, source) = resolve_parent_entry(self.filesystem, storage, old)?;
        let normalized = normalize(new)?;
        let (new_parent_path, new_name) = split_parent(&normalized)?;
        let new_parent = resolve_path(self.filesystem, storage, new_parent_path, true)?;
        let destination = find_entry(self.filesystem, storage, &new_parent, new_name.as_bytes())?;
        self.move_entry(
            storage,
            &old_parent,
            &source,
            &new_parent,
            new_name.as_bytes(),
            destination.as_ref(),
        )
    }

    fn resize<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
        size: u64,
    ) -> Result<(), Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.resize_inode(storage, &inode, size)
    }

    fn truncate_to_zero<S: Storage>(
        &mut self,
        storage: &mut S,
        path: &str,
    ) -> Result<u64, Error<S::Error>> {
        let inode = resolve_path(self.filesystem, storage, path, true)?;
        self.truncate_inode(storage, &inode)
    }
}

fn normalize<E>(path: &str) -> Result<String, Error<E>> {
    if !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(Corrupt::InvalidPath.into());
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component if component.len() <= 255 => components.push(component),
            _ => return Err(Corrupt::InvalidPath.into()),
        }
    }
    Ok(format!("/{}", components.join("/")))
}

fn split_parent<E>(path: &str) -> Result<(&str, &str), Error<E>> {
    let (parent, name) = path.rsplit_once('/').ok_or(Error::InvalidArgument)?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(Error::InvalidArgument);
    }
    Ok((if parent.is_empty() { "/" } else { parent }, name))
}

fn find_entry<S: Storage>(
    filesystem: &mut Ext4,
    storage: &mut S,
    directory: &Inode,
    name: &[u8],
) -> Result<Option<DirectoryEntry>, Error<S::Error>> {
    let mut cookie = 0;
    loop {
        let mut entries = Vec::new();
        let next = filesystem.list(storage, directory, cookie, &mut entries, 64)?;
        if let Some(entry) = entries.into_iter().find(|entry| entry.name == name) {
            return Ok(Some(entry));
        }
        match next {
            Some(next) => cookie = next,
            None => return Ok(None),
        }
    }
}

fn resolve_parent_entry<S: Storage>(
    filesystem: &mut Ext4,
    storage: &mut S,
    path: &str,
) -> Result<(Inode, DirectoryEntry), Error<S::Error>> {
    let normalized = normalize(path)?;
    let (parent, name) = split_parent(&normalized)?;
    let parent = resolve_path(filesystem, storage, parent, true)?;
    let entry =
        find_entry(filesystem, storage, &parent, name.as_bytes())?.ok_or(Error::NotFound)?;
    Ok((parent, entry))
}

fn resolve_path<S: Storage>(
    filesystem: &mut Ext4,
    storage: &mut S,
    path: &str,
    follow_final: bool,
) -> Result<Inode, Error<S::Error>> {
    let mut current = normalize(path)?;
    for _ in 0..40 {
        let owned_components: Vec<String> = current
            .split('/')
            .filter(|component| !component.is_empty())
            .map(ToString::to_string)
            .collect();
        let mut inode = filesystem.root(storage)?;
        let mut followed = false;
        for (index, component) in owned_components.iter().enumerate() {
            if !inode.is_directory() {
                return Err(Error::NotDirectory);
            }
            let entry = find_entry(filesystem, storage, &inode, component.as_bytes())?
                .ok_or(Error::NotFound)?;
            inode = entry.inode;
            if inode.is_symlink() && (follow_final || index + 1 != owned_components.len()) {
                let target = filesystem.read_symlink(storage, &inode)?;
                let target = core::str::from_utf8(&target).map_err(|_| Corrupt::InvalidPath)?;
                let parent = if index == 0 {
                    "/".to_string()
                } else {
                    format!("/{}/", owned_components[..index].join("/"))
                };
                let remainder = owned_components[index + 1..].join("/");
                let expanded = if target.starts_with('/') {
                    format!("{target}/{remainder}")
                } else {
                    format!("{parent}{target}/{remainder}")
                };
                current = normalize(&expanded)?;
                followed = true;
                break;
            }
        }
        if !followed {
            return Ok(inode);
        }
    }
    Err(Corrupt::InvalidPath.into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Effect {
    pub sequence: usize,
    pub kind: EffectKind,
    pub offset: u64,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inject {
    None,
    IoErrorAt(usize),
    PowerLossAt(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    OutOfBounds,
    InjectedIo,
    PowerLoss,
}

#[derive(Clone, Debug)]
struct PendingWrite {
    offset: usize,
    bytes: Vec<u8>,
}

/// A byte-addressed device with explicit volatile and durable state.
///
/// Successful writes are immediately visible to reads but do not become
/// durable until `flush`. Before simulating a power loss, tests may call
/// `persist_pending_prefix` to model any ordered prefix having reached media.
#[derive(Clone, Debug)]
pub struct ModelStorage {
    durable: Vec<u8>,
    visible: Vec<u8>,
    pending: Vec<PendingWrite>,
    effects: Vec<Effect>,
    inject: Inject,
    next_sequence: usize,
}

impl ModelStorage {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            durable: bytes.clone(),
            visible: bytes,
            pending: Vec::new(),
            effects: Vec::new(),
            inject: Inject::None,
            next_sequence: 0,
        }
    }

    pub fn with_injection(mut self, inject: Inject) -> Self {
        self.inject = inject;
        self
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    pub fn durable_bytes(&self) -> &[u8] {
        &self.durable
    }

    pub fn pending_writes(&self) -> usize {
        self.pending.len()
    }

    /// Persist an ordered prefix of currently pending writes, then lose power.
    pub fn persist_pending_prefix(&mut self, count: usize) {
        self.persist_pending_with_torn(count.min(self.pending.len()), 0)
            .unwrap();
    }

    /// Persist `complete` whole pending writes and `torn_bytes` of the next
    /// write, then lose power. This models a device whose atomic-write unit is
    /// smaller than the filesystem write submitted to it.
    pub fn persist_pending_with_torn(
        &mut self,
        complete: usize,
        torn_bytes: usize,
    ) -> Result<(), ModelError> {
        if complete > self.pending.len()
            || (torn_bytes != 0
                && self
                    .pending
                    .get(complete)
                    .is_none_or(|write| torn_bytes > write.bytes.len()))
        {
            return Err(ModelError::OutOfBounds);
        }
        for write in self.pending.iter().take(complete) {
            let end = write.offset + write.bytes.len();
            self.durable[write.offset..end].copy_from_slice(&write.bytes);
        }
        if torn_bytes != 0 {
            let write = &self.pending[complete];
            self.durable[write.offset..write.offset + torn_bytes]
                .copy_from_slice(&write.bytes[..torn_bytes]);
        }
        self.power_loss();
        Ok(())
    }

    /// Discard volatile state, as reconstructing the device after power loss.
    pub fn power_loss(&mut self) {
        self.visible.clone_from(&self.durable);
        self.pending.clear();
    }

    fn begin(&mut self, kind: EffectKind, offset: u64, len: usize) -> Result<(), ModelError> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.effects.push(Effect {
            sequence,
            kind,
            offset,
            len,
        });
        match self.inject {
            Inject::IoErrorAt(n) if n == sequence => Err(ModelError::InjectedIo),
            Inject::PowerLossAt(n) if n == sequence => {
                self.power_loss();
                Err(ModelError::PowerLoss)
            }
            _ => Ok(()),
        }
    }

    fn range(&self, offset: u64, len: usize) -> Result<core::ops::Range<usize>, ModelError> {
        let start = usize::try_from(offset).map_err(|_| ModelError::OutOfBounds)?;
        let end = start.checked_add(len).ok_or(ModelError::OutOfBounds)?;
        if end > self.visible.len() {
            return Err(ModelError::OutOfBounds);
        }
        Ok(start..end)
    }
}

impl Storage for ModelStorage {
    type Error = ModelError;

    fn len(&self) -> u64 {
        self.visible.len() as u64
    }

    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.begin(EffectKind::Read, offset, dst.len())?;
        let range = self.range(offset, dst.len())?;
        dst.copy_from_slice(&self.visible[range]);
        Ok(())
    }

    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), Self::Error> {
        self.begin(EffectKind::Write, offset, src.len())?;
        let range = self.range(offset, src.len())?;
        self.visible[range.clone()].copy_from_slice(src);
        self.pending.push(PendingWrite {
            offset: range.start,
            bytes: src.to_vec(),
        });
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.begin(EffectKind::Flush, 0, 0)?;
        self.durable.clone_from(&self.visible);
        self.pending.clear();
        Ok(())
    }
}
