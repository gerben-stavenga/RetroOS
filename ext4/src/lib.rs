//! Portable, synchronous ext2/3/4 filesystem machinery.
//!
//! The crate is deliberately built around one rule: every persistent effect
//! crosses [`Storage`]. There is no libc, kernel, executor, clock, global
//! registry, or hidden block cache. This makes every I/O error and power-loss
//! boundary controllable in ordinary host tests.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod checksum;
mod directory;
mod extent_tree;
mod inode;
mod journal;
mod ondisk;
mod storage;
pub mod test_support;
mod transaction;
mod xattr;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use directory::{BlockKind as DirectoryBlockKind, DirectoryBlock, records as directory_records};
use extent_tree::{ExtentIdentity, ExtentState, ExtentTree};
use inode::{InodeBlockMap, InodeRecord, InodeTableBlock};
pub use ondisk::Superblock;
use ondisk::{checked_read, le32};
pub use storage::Storage;
pub use transaction::Transaction;
use xattr::{ExternalXattrBlock, XattrTable, XattrValue};

const ROOT_INODE: u32 = 2;
const EXTENTS_FL: u32 = 0x0008_0000;
const EA_INODE_FL: u32 = 0x0020_0000;
const ENCRYPT_FL: u32 = 0x0000_0800;
const INLINE_DATA_FL: u32 = 0x1000_0000;
const DIRECTORY_INDEX_FL: u32 = 0x0000_1000;
const EXTENT_MAGIC: u16 = 0xf30a;
const MODE_TYPE_MASK: u16 = 0xf000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xa000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Corrupt {
    BadMagic,
    InvalidBlockSize,
    InvalidGeometry,
    InvalidFeatureCombination,
    AddressOverflow,
    SuperblockChecksum,
    GroupDescriptorChecksum(u32),
    BlockBitmapChecksum(u32),
    InodeBitmapChecksum(u32),
    InodeChecksum(u32),
    DirectoryChecksum(u32),
    ExtentChecksum(u32),
    FilesystemPastEnd { fs_bytes: u64, storage_len: u64 },
    ReadPastEnd { offset: u64, len: usize },
    InvalidGroup(u32),
    InvalidInode(u32),
    InvalidInodeTable,
    InvalidExtentHeader,
    InvalidExtentTree,
    InvalidLegacyBlockMap,
    InvalidBlockBitmap,
    InvalidFreeBlockCount,
    ExtentPastEnd,
    InvalidDirectory,
    InvalidPath,
    InvalidJournal,
    JournalChecksum,
    InvalidExtendedAttributes(u32),
    ExtendedAttributeChecksum(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Unsupported {
    IncompatibleFeatures(u32),
    ExternalJournal,
    JournalFeatures {
        compat: u32,
        incompat: u32,
        ro_compat: u32,
    },
    JournalWriteProfile,
    ExtentTreeTooDeep,
    MutationProfile,
    ExtentMutation,
    InlineData,
    Encryption,
}

pub enum Error {
    Storage(Box<dyn Any>),
    Corrupt(Corrupt),
    Unsupported(Unsupported),
    OutOfMemory,
    NotFound,
    NotDirectory,
    InvalidArgument,
    ReservationExhausted,
    AlreadyExists,
    NotEmpty,
}

/// Fallible `Vec::push`, expressed once so filesystem algorithms do not each
/// carry their own allocation-error plumbing.
pub(crate) fn try_push<T>(values: &mut Vec<T>, value: T) -> Result<(), Error> {
    values.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
    values.push(value);
    Ok(())
}

/// Fallible `Vec::insert`, preserving the vector when allocation fails.
pub(crate) fn try_insert<T>(values: &mut Vec<T>, index: usize, value: T) -> Result<(), Error> {
    values.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
    values.insert(index, value);
    Ok(())
}

#[inline(never)]
pub(crate) fn zeroed_bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| Error::OutOfMemory)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

#[inline(never)]
pub(crate) fn copy_bytes(source: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| Error::OutOfMemory)?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

impl Error {
    pub fn storage_is<T: core::any::Any + PartialEq>(&self, expected: &T) -> bool {
        matches!(self, Self::Storage(error) if error.downcast_ref::<T>() == Some(expected))
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Corrupt(left), Self::Corrupt(right)) => left == right,
            (Self::Unsupported(left), Self::Unsupported(right)) => left == right,
            (Self::OutOfMemory, Self::OutOfMemory)
            | (Self::NotFound, Self::NotFound)
            | (Self::NotDirectory, Self::NotDirectory)
            | (Self::InvalidArgument, Self::InvalidArgument)
            | (Self::ReservationExhausted, Self::ReservationExhausted)
            | (Self::AlreadyExists, Self::AlreadyExists)
            | (Self::NotEmpty, Self::NotEmpty) => true,
            _ => false,
        }
    }
}

impl Eq for Error {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(_) => f.write_str("Storage(..)"),
            Self::Corrupt(error) => f.debug_tuple("Corrupt").field(error).finish(),
            Self::Unsupported(error) => f.debug_tuple("Unsupported").field(error).finish(),
            Self::OutOfMemory => f.write_str("OutOfMemory"),
            Self::NotFound => f.write_str("NotFound"),
            Self::NotDirectory => f.write_str("NotDirectory"),
            Self::InvalidArgument => f.write_str("InvalidArgument"),
            Self::ReservationExhausted => f.write_str("ReservationExhausted"),
            Self::AlreadyExists => f.write_str("AlreadyExists"),
            Self::NotEmpty => f.write_str("NotEmpty"),
        }
    }
}

/// Failures from transaction preparation that perform no storage I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    OutOfMemory,
    InvalidArgument,
    ReservationExhausted,
}

impl From<FsError> for Error {
    fn from(value: FsError) -> Self {
        match value {
            FsError::OutOfMemory => Self::OutOfMemory,
            FsError::InvalidArgument => Self::InvalidArgument,
            FsError::ReservationExhausted => Self::ReservationExhausted,
        }
    }
}

impl From<Corrupt> for Error {
    fn from(value: Corrupt) -> Self {
        Self::Corrupt(value)
    }
}

impl From<Unsupported> for Error {
    fn from(value: Unsupported) -> Self {
        Self::Unsupported(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(_) => f.write_str("storage error"),
            Self::Corrupt(e) => write!(f, "corrupt ext filesystem: {e:?}"),
            Self::Unsupported(e) => write!(f, "unsupported ext feature: {e:?}"),
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::NotFound => f.write_str("file not found"),
            Self::NotDirectory => f.write_str("path component is not a directory"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::ReservationExhausted => f.write_str("transaction reservation exhausted"),
            Self::AlreadyExists => f.write_str("directory entry already exists"),
            Self::NotEmpty => f.write_str("directory not empty"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeOsData {
    pub osd1: [u8; 4],
    pub osd2: [u8; 12],
}

impl Default for InodeOsData {
    fn default() -> Self {
        Self {
            osd1: [0; 4],
            osd2: [0; 12],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    pub number: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub accessed: Timestamp,
    pub modified: Timestamp,
    pub changed: Timestamp,
    pub os_data: InodeOsData,
    flags: u32,
    generation: u32,
    blocks_512: u64,
    external_xattr_block: u64,
    block_map: InodeBlockMap,
    inline_data: Option<Vec<u8>>,
}

/// A Unix timestamp supplied by filesystem-independent policy code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// Optional inode metadata changes applied as one transaction.
///
/// `permissions` contains only the permission and special bits (`0o7777`);
/// the inode's file type is preserved. Omitted fields remain unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InodeMetadataUpdate {
    pub permissions: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub accessed: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub changed: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: Vec<u8>,
    pub file_type: u8,
    pub inode: Inode,
}

/// One ext4 extended attribute without imposing Linux namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedAttribute {
    pub namespace: u8,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Inode {
    pub fn is_directory(&self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_DIRECTORY
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & MODE_TYPE_MASK == 0xa000
    }

    pub(crate) fn directory_file_type(&self) -> Option<u8> {
        match self.mode & MODE_TYPE_MASK {
            MODE_REGULAR => Some(1),
            MODE_DIRECTORY => Some(2),
            MODE_SYMLINK => Some(7),
            _ => None,
        }
    }
}

/// Interpreted state for a mounted filesystem.
///
/// Storage is caller-owned and supplied explicitly to every operation that
/// can perform I/O.
pub struct Ext4 {
    superblock: Superblock,
    overlay: Vec<(u64, Vec<u8>)>,
}

/// The logical-to-physical block mapping of one inode, decoded once and then
/// shared by sequential readers.
pub(crate) struct InodeBlocks {
    extents: Option<ExtentTree>,
}

impl InodeBlocks {
    pub(crate) fn open(
        filesystem: &mut Ext4,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<Self, Error> {
        let extents = if inode.flags & EXTENTS_FL != 0 && inode.flags & INLINE_DATA_FL == 0 {
            Some(filesystem.load_extent_tree(storage, inode)?)
        } else {
            None
        };
        Ok(Self { extents })
    }

    #[inline(never)]
    pub(crate) fn physical(
        &self,
        filesystem: &mut Ext4,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        match &self.extents {
            Some(tree) => Ok(u32::try_from(logical)
                .ok()
                .and_then(|logical| tree.lookup(logical))
                .and_then(|(physical, state)| (state == ExtentState::Written).then_some(physical))),
            None => filesystem.map_legacy_block(storage, inode, logical),
        }
    }

    #[inline(never)]
    fn read(
        &self,
        filesystem: &mut Ext4,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        if let Some(data) = &inode.inline_data {
            if offset >= inode.size || dst.is_empty() {
                return Ok(0);
            }
            let start = usize::try_from(offset).map_err(|_| Corrupt::AddressOverflow)?;
            let amount = dst.len().min(data.len() - start);
            dst[..amount].copy_from_slice(&data[start..start + amount]);
            return Ok(amount);
        }
        if inode.flags & INLINE_DATA_FL != 0 {
            return Err(Unsupported::InlineData.into());
        }
        if inode.flags & ENCRYPT_FL != 0 {
            return Err(Unsupported::Encryption.into());
        }
        if offset >= inode.size || dst.is_empty() {
            return Ok(0);
        }
        let wanted = usize::try_from((inode.size - offset).min(dst.len() as u64))
            .map_err(|_| Corrupt::AddressOverflow)?;
        let block_size = u64::from(filesystem.superblock.block_size);
        let mut done = 0;
        while done < wanted {
            let position = offset + done as u64;
            let logical = position / block_size;
            let within = position % block_size;
            let amount = (wanted - done).min((block_size - within) as usize);
            match self.physical(filesystem, storage, inode, logical)? {
                Some(physical) => {
                    let disk_offset = physical
                        .checked_mul(block_size)
                        .and_then(|v| v.checked_add(within))
                        .ok_or(Corrupt::AddressOverflow)?;
                    filesystem.read_storage(storage, disk_offset, &mut dst[done..done + amount])?;
                }
                None => dst[done..done + amount].fill(0),
            }
            done += amount;
        }
        Ok(done)
    }
}

impl Ext4 {
    pub fn mount(storage: &mut dyn Storage) -> Result<Self, Error> {
        let superblock = Superblock::load(storage)?;
        let mut filesystem = Self {
            superblock,
            overlay: Vec::new(),
        };
        if filesystem.superblock.needs_recovery() {
            filesystem.replay_journal(storage)?;
        }
        Ok(filesystem)
    }

    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }
    pub fn block_count(&self) -> u64 {
        self.superblock.blocks_count
    }
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }
    /// Begin an isolated block transaction. Dropping it performs no writes.
    pub fn begin_transaction<'f, 's>(
        &'f mut self,
        storage: &'s mut dyn Storage,
    ) -> Transaction<'f, 's> {
        Transaction::new(self, storage)
    }

    /// Number of filesystem blocks supplied by committed journal records.
    pub fn recovered_blocks(&self) -> usize {
        self.overlay.len()
    }

    #[inline(never)]
    fn read_storage(
        &mut self,
        storage: &mut dyn Storage,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<(), Error> {
        checked_read(storage, offset, dst)?;
        if dst.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size);
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(Corrupt::AddressOverflow)?;
        let first = offset / block_size;
        let last = (end - 1) / block_size;
        for number in first..=last {
            let Ok(index) = self
                .overlay
                .binary_search_by_key(&number, |(target, _)| *target)
            else {
                continue;
            };
            let block = &self.overlay[index].1;
            let block_start = number
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let block_end = block_start
                .checked_add(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let start = offset.max(block_start);
            let stop = end.min(block_end);
            if start < stop {
                let destination =
                    usize::try_from(start - offset).map_err(|_| Corrupt::AddressOverflow)?;
                let source =
                    usize::try_from(start - block_start).map_err(|_| Corrupt::AddressOverflow)?;
                let len = usize::try_from(stop - start).map_err(|_| Corrupt::AddressOverflow)?;
                dst[destination..destination + len].copy_from_slice(&block[source..source + len]);
            }
        }
        Ok(())
    }

    /// Return the filesystem's well-known starting inode.
    pub fn root(&mut self, storage: &mut dyn Storage) -> Result<Inode, Error> {
        self.load_inode(storage, ROOT_INODE)
    }

    /// Load an inode by the identity returned from a directory listing.
    /// Name resolution belongs to the caller; this does not search a directory.
    pub fn inode(&mut self, storage: &mut dyn Storage, number: u32) -> Result<Inode, Error> {
        self.load_inode(storage, number)
    }

    /// Reload an inode identity from disk, rejecting a reused identity.
    pub fn refresh(&mut self, storage: &mut dyn Storage, inode: &Inode) -> Result<Inode, Error> {
        let current = self.load_inode(storage, inode.number)?;
        if current.generation != inode.generation {
            return Err(Error::NotFound);
        }
        Ok(current)
    }

    pub fn read_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        let inode = self.refresh(storage, inode)?;
        self.read_inode_data(storage, &inode, offset, dst)
    }

    /// Read the target bytes stored in a symbolic-link inode.
    pub fn read_symlink(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<Vec<u8>, Error> {
        let inode = self.refresh(storage, inode)?;
        if !inode.is_symlink() {
            return Err(Error::InvalidArgument);
        }
        self.read_symlink_inode(storage, &inode)
    }

    /// Return every inode-body and external-block extended attribute.
    /// Namespace access policy and prefix mapping belong to the caller.
    pub fn extended_attributes(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<Vec<ExtendedAttribute>, Error> {
        let current = self.refresh(storage, inode)?;
        let record = self.read_inode_record(storage, current.number)?;
        let mut pending = Vec::new();
        if let Some(table) = record.extra.xattrs {
            append_xattrs(&mut pending, table.entries)?;
        }

        if current.external_xattr_block != 0 {
            let block = self.read_external_xattr_block(storage, &current)?;
            append_xattrs(&mut pending, block.table.entries)?;
        }
        let mut attributes = Vec::new();
        attributes
            .try_reserve_exact(pending.len())
            .map_err(|_| Error::OutOfMemory)?;
        for attribute in pending {
            let value = match attribute.value {
                XattrValue::Inline { bytes, .. } => bytes,
                XattrValue::Inode { number, size } => {
                    self.read_extended_attribute_inode(storage, number, size)?
                }
            };
            attributes.push(ExtendedAttribute {
                namespace: attribute.namespace,
                name: attribute.name,
                value,
            });
        }
        Ok(attributes)
    }

    fn read_extended_attribute_inode(
        &mut self,
        storage: &mut dyn Storage,
        number: u32,
        size: usize,
    ) -> Result<Vec<u8>, Error> {
        if self.superblock.feature_incompat & ondisk::INCOMPAT_EA_INODE == 0 {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let record = self.read_inode_record(storage, number)?;
        let inode = self.load_inode(storage, number)?;
        if inode.mode & MODE_TYPE_MASK != MODE_REGULAR
            || inode.flags & EA_INODE_FL == 0
            || inode.size != size as u64
            || record.base.changed == 0 && le32(&record.base.os_data.osd1, 0) == 0
        {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let mut value = zeroed_bytes(size)?;
        if self.read_inode_data(storage, &inode, 0, &mut value)? != size {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let mut checksum = checksum::Checksum::with_seed(self.superblock.checksum_seed);
        checksum.update(&value);
        if checksum.finalize() != record.base.accessed {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        Ok(value)
    }

    fn read_external_xattr_block(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<ExternalXattrBlock, Error> {
        let number = inode.external_xattr_block;
        if number == 0 || number >= self.superblock.blocks_count {
            return Err(Corrupt::InvalidExtendedAttributes(inode.number).into());
        }
        let mut block = self.new_block_buffer()?;
        self.read_storage(
            storage,
            number
                .checked_mul(u64::from(self.superblock.block_size))
                .ok_or(Corrupt::AddressOverflow)?,
            &mut block,
        )?;
        ExternalXattrBlock::decode(
            &block,
            inode.number,
            number,
            self.superblock.checksum_seed,
            self.superblock.has_metadata_checksums(),
        )
    }

    fn read_symlink_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<Vec<u8>, Error> {
        let len = usize::try_from(inode.size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut target = zeroed_bytes(len)?;
        if let Some(inline) = inode.block_map.fast_symlink() {
            if inline.len() != len {
                return Err(Corrupt::InvalidInode(inode.number).into());
            }
            target.copy_from_slice(inline);
            return Ok(target);
        }
        if self.read_inode_data(storage, inode, 0, &mut target)? != len {
            return Err(Corrupt::InvalidInode(inode.number).into());
        }
        Ok(target)
    }

    /// Append at most `max` checked directory entries, resuming from an opaque
    /// byte cookie returned by the previous call. `None` means end of directory.
    #[inline(never)]
    pub fn list(
        &mut self,
        storage: &mut dyn Storage,
        directory: &Inode,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error> {
        if max == 0 {
            return Err(Error::InvalidArgument);
        }
        let directory = self.refresh(storage, directory)?;
        if !directory.is_directory() {
            return Err(Error::NotDirectory);
        }
        if cookie > directory.size {
            return Err(Error::InvalidArgument);
        }
        if directory.flags & INLINE_DATA_FL != 0 {
            return self.list_inline_directory(storage, &directory, cookie, output, max);
        }
        let initial_len = output.len();
        output.try_reserve(max).map_err(|_| Error::OutOfMemory)?;
        let block_size = u64::from(self.superblock.block_size);
        let blocks = directory.size.div_ceil(block_size);
        let first_logical = cookie / block_size;
        let first_within =
            usize::try_from(cookie % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut block = self.new_block_buffer()?;
        let mapping = InodeBlocks::open(self, storage, &directory)?;

        for logical in first_logical..blocks {
            block.fill(0);
            let block_offset = logical
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let count = usize::try_from((directory.size - block_offset).min(block_size))
                .map_err(|_| Corrupt::AddressOverflow)?;
            mapping.read(self, storage, &directory, block_offset, &mut block[..count])?;
            block.truncate(count);
            let checked = DirectoryBlock::new(
                self.superblock.checksum_seed,
                self.superblock.has_metadata_checksums(),
                &directory,
                logical,
                block,
            )?;
            if checked.kind != DirectoryBlockKind::Leaf {
                block = checked.into_bytes()?;
                block.resize(self.superblock.block_size as usize, 0);
                continue;
            }
            let end = checked.records_end();
            let wanted = if logical == first_logical {
                first_within
            } else {
                0
            };
            let mut cookie_is_boundary = wanted == 0;
            let records = checked.leaf_records().ok_or(Corrupt::InvalidDirectory)?;
            for entry in records {
                let (next, number, file_type, name) =
                    (entry.next, entry.inode, entry.file_type, entry.name);
                if entry.offset == wanted {
                    cookie_is_boundary = true;
                }
                if entry.offset >= wanted && number != 0 {
                    if name != b"." && name != b".." {
                        self.push_directory_entry(storage, output, number, file_type, name)?;
                        if output.len() - initial_len == max {
                            return Ok(Some(
                                block_offset
                                    .checked_add(next as u64)
                                    .ok_or(Corrupt::AddressOverflow)?,
                            ));
                        }
                    }
                }
            }
            block = checked.into_bytes()?;
            block.resize(self.superblock.block_size as usize, 0);
            if logical == first_logical && wanted != end && !cookie_is_boundary {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(None)
    }

    fn list_inline_directory(
        &mut self,
        storage: &mut dyn Storage,
        directory: &Inode,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error> {
        let data = directory
            .inline_data
            .as_ref()
            .ok_or(Unsupported::InlineData)?;
        let wanted = usize::try_from(cookie).map_err(|_| Error::InvalidArgument)?;
        if wanted > data.len() {
            return Err(Error::InvalidArgument);
        }
        output.try_reserve(max).map_err(|_| Error::OutOfMemory)?;
        let initial_len = output.len();
        let mut cookie_is_boundary = wanted == 0;
        let mut records = directory_records(data);
        while let Some(entry) = records.next()? {
            if entry.offset == wanted {
                cookie_is_boundary = true;
            }
            if entry.offset >= wanted && entry.inode != 0 {
                self.push_directory_entry(
                    storage,
                    output,
                    entry.inode,
                    entry.file_type,
                    entry.name,
                )?;
                if output.len() - initial_len == max {
                    return Ok(Some(entry.next as u64));
                }
            }
        }
        if wanted != data.len() && !cookie_is_boundary {
            return Err(Error::InvalidArgument);
        }
        Ok(None)
    }

    #[inline(never)]
    fn push_directory_entry(
        &mut self,
        storage: &mut dyn Storage,
        output: &mut Vec<DirectoryEntry>,
        number: u32,
        file_type: u8,
        name: &[u8],
    ) -> Result<(), Error> {
        let owned_name = copy_bytes(name)?;
        output.push(DirectoryEntry {
            name: owned_name,
            file_type,
            inode: self.load_inode(storage, number)?,
        });
        Ok(())
    }

    fn new_block_buffer(&self) -> Result<Vec<u8>, Error> {
        zeroed_bytes(self.superblock.block_size as usize)
    }

    #[inline(never)]
    fn read_group_descriptor(
        &mut self,
        storage: &mut dyn Storage,
        group: u32,
    ) -> Result<ondisk::GroupDescriptor, Error> {
        if group >= self.superblock.group_count() {
            return Err(Corrupt::InvalidGroup(group).into());
        }
        let len = usize::from(self.superblock.descriptor_size);
        let offset = self
            .superblock
            .descriptor_offset(group)
            .ok_or(Corrupt::AddressOverflow)?;
        let mut descriptor = zeroed_bytes(len)?;
        self.read_storage(storage, offset, &mut descriptor)?;
        ondisk::GroupDescriptor::new(&self.superblock, group, descriptor)
    }

    fn read_inode_record(
        &mut self,
        storage: &mut dyn Storage,
        number: u32,
    ) -> Result<InodeRecord, Error> {
        if number == 0 || number > self.superblock.inodes_count {
            return Err(Corrupt::InvalidInode(number).into());
        }
        let zero_based = number - 1;
        let group = zero_based / self.superblock.inodes_per_group;
        let index = zero_based % self.superblock.inodes_per_group;
        let inode_table = self.read_group_descriptor(storage, group)?.inode_table;
        if inode_table == 0 || inode_table >= self.superblock.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        let byte = inode_table
            .checked_mul(u64::from(self.superblock.block_size))
            .and_then(|v| v.checked_add(u64::from(index) * u64::from(self.superblock.inode_size)))
            .ok_or(Corrupt::AddressOverflow)?;
        let block_size = u64::from(self.superblock.block_size);
        let block_number = byte / block_size;
        let offset = usize::try_from(byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut bytes = self.new_block_buffer()?;
        self.read_storage(
            storage,
            block_number
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?,
            &mut bytes,
        )?;
        let (table, selected) = InodeTableBlock::containing(
            &bytes,
            usize::from(self.superblock.inode_size),
            number,
            offset,
            self.superblock.checksum_seed,
        )?;
        table.into_record(selected)
    }

    #[inline(never)]
    pub(crate) fn load_inode(
        &mut self,
        storage: &mut dyn Storage,
        number: u32,
    ) -> Result<Inode, Error> {
        let record = self.read_inode_record(storage, number)?;
        if self.superblock.has_metadata_checksums() {
            record.verify_checksum()?;
        }
        let generation = record.base.generation;
        let mode = record.base.mode;
        if mode == 0 {
            return Err(Corrupt::InvalidInode(number).into());
        }
        let size = record.size();
        let uid = record.uid();
        let gid = record.gid();
        let block_map = record.base.block_map.clone();
        let flags = record.base.flags;
        let inline_data = if flags & INLINE_DATA_FL != 0
            && matches!(
                mode & MODE_TYPE_MASK,
                MODE_REGULAR | MODE_DIRECTORY | MODE_SYMLINK
            ) {
            Some(parse_inline_data(
                number,
                mode,
                size,
                block_map.inline_prefix()?,
                record.extra.xattrs.as_ref(),
            )?)
        } else {
            None
        };
        let blocks_512 = record.blocks_512();
        let external_xattr_block = record
            .external_xattr_block(self.superblock.feature_incompat & ondisk::INCOMPAT_64BIT != 0);
        let (accessed, changed, modified) = if flags & EA_INODE_FL != 0 {
            let zero = Timestamp {
                seconds: 0,
                nanoseconds: 0,
            };
            (zero, zero, zero)
        } else {
            (
                record.timestamp(0x08, 0x8c)?,
                record.timestamp(0x0c, 0x84)?,
                record.timestamp(0x10, 0x88)?,
            )
        };
        Ok(Inode {
            number,
            mode,
            uid,
            gid,
            size,
            links: record.base.links,
            accessed,
            modified,
            changed,
            os_data: record.base.os_data,
            flags,
            generation,
            blocks_512,
            external_xattr_block,
            block_map,
            inline_data,
        })
    }

    fn read_inode_data(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        InodeBlocks::open(self, storage, inode)?.read(self, storage, inode, offset, dst)
    }

    fn map_file_block(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        InodeBlocks::open(self, storage, inode)?.physical(self, storage, inode, logical)
    }

    #[inline(never)]
    fn map_legacy_block(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        const DIRECT_BLOCKS: u64 = 12;
        let map = inode.block_map.legacy()?;
        if logical < DIRECT_BLOCKS {
            return self.validate_legacy_pointer(u64::from(map.direct[logical as usize]));
        }

        let pointers = u64::from(self.superblock.block_size / 4);
        let double_capacity = pointers
            .checked_mul(pointers)
            .ok_or(Corrupt::AddressOverflow)?;
        let triple_capacity = double_capacity
            .checked_mul(pointers)
            .ok_or(Corrupt::AddressOverflow)?;
        let mut remaining = logical - DIRECT_BLOCKS;
        if remaining < pointers {
            return self.follow_legacy_indirect(storage, u64::from(map.indirect), &[remaining]);
        }
        remaining -= pointers;
        if remaining < double_capacity {
            return self.follow_legacy_indirect(
                storage,
                u64::from(map.double_indirect),
                &[remaining / pointers, remaining % pointers],
            );
        }
        remaining -= double_capacity;
        if remaining < triple_capacity {
            return self.follow_legacy_indirect(
                storage,
                u64::from(map.triple_indirect),
                &[
                    remaining / double_capacity,
                    (remaining % double_capacity) / pointers,
                    remaining % pointers,
                ],
            );
        }
        Err(Corrupt::InvalidLegacyBlockMap.into())
    }

    fn follow_legacy_indirect(
        &mut self,
        storage: &mut dyn Storage,
        mut physical: u64,
        indexes: &[u64],
    ) -> Result<Option<u64>, Error> {
        let pointers = u64::from(self.superblock.block_size / 4);
        let block_size = u64::from(self.superblock.block_size);
        let mut block = self.new_block_buffer()?;
        for &index in indexes {
            if physical == 0 {
                return Ok(None);
            }
            if physical >= self.superblock.blocks_count || index >= pointers {
                return Err(Corrupt::InvalidLegacyBlockMap.into());
            }
            self.read_storage(
                storage,
                physical
                    .checked_mul(block_size)
                    .ok_or(Corrupt::AddressOverflow)?,
                &mut block,
            )?;
            physical = u64::from(le32(
                &block,
                usize::try_from(index * 4).map_err(|_| Corrupt::AddressOverflow)?,
            ));
        }
        self.validate_legacy_pointer(physical)
    }

    fn validate_legacy_pointer(&self, physical: u64) -> Result<Option<u64>, Error> {
        if physical == 0 {
            Ok(None)
        } else if physical < self.superblock.blocks_count {
            Ok(Some(physical))
        } else {
            Err(Corrupt::InvalidLegacyBlockMap.into())
        }
    }

    #[inline(never)]
    fn load_extent_tree(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<ExtentTree, Error> {
        let block_size = self.superblock.block_size as usize;
        let blocks_count = self.superblock.blocks_count;
        let identity = ExtentIdentity {
            checksum_seed: self.superblock.checksum_seed,
            inode: inode.number,
            generation: inode.generation,
            metadata_checksums: self.superblock.has_metadata_checksums(),
        };
        ExtentTree::load(
            inode.block_map.extent_root()?,
            block_size,
            blocks_count,
            identity,
            &mut |number| {
                let mut block = self.new_block_buffer()?;
                let offset = number
                    .checked_mul(block_size as u64)
                    .ok_or(Corrupt::AddressOverflow)?;
                self.read_storage(storage, offset, &mut block)?;
                Ok(block)
            },
        )
    }
}

fn append_xattrs(
    output: &mut Vec<xattr::XattrEntry>,
    mut entries: Vec<xattr::XattrEntry>,
) -> Result<(), Error> {
    output
        .try_reserve_exact(entries.len())
        .map_err(|_| Error::OutOfMemory)?;
    output.append(&mut entries);
    Ok(())
}

fn parse_inline_data(
    inode: u32,
    mode: u16,
    size: u64,
    block_map: &[u8; 60],
    xattrs: Option<&XattrTable>,
) -> Result<Vec<u8>, Error> {
    let size = usize::try_from(size).map_err(|_| Corrupt::InvalidInode(inode))?;
    let directory = mode & MODE_TYPE_MASK == MODE_DIRECTORY;
    let total = if directory {
        size.checked_sub(4).ok_or(Corrupt::InvalidInode(inode))?
    } else {
        size
    };
    let prefix_start = if directory { 4 } else { 0 };
    let prefix = total.min(block_map.len() - prefix_start);
    let mut data = Vec::new();
    data.try_reserve_exact(total)
        .map_err(|_| Error::OutOfMemory)?;
    data.extend_from_slice(&block_map[prefix_start..prefix_start + prefix]);
    if size <= block_map.len() {
        return Ok(data);
    }

    let wanted = size - block_map.len();
    let table = xattrs.ok_or(Corrupt::InvalidInode(inode))?;
    let Some(entry) = table.find(7, b"data") else {
        return Err(Corrupt::InvalidInode(inode).into());
    };
    match &entry.value {
        XattrValue::Inline { bytes, .. } if bytes.len() == wanted => {
            data.extend_from_slice(bytes);
            Ok(data)
        }
        _ => Err(Corrupt::InvalidInode(inode).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::{EXT4_MAGIC, SUPERBLOCK_OFFSET};
    use crate::test_support::{EffectKind, Inject, ModelError, ModelStorage, PathExt4};

    fn mounted(image: Vec<u8>) -> (Ext4, ModelStorage) {
        let mut storage = ModelStorage::new(image);
        let filesystem = Ext4::mount(&mut storage).unwrap();
        (filesystem, storage)
    }

    fn put16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_be16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn put_be32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn extent(image: &mut [u8], offset: usize, physical: u32) {
        extent_len(image, offset, physical, 1);
    }

    fn extent_len(image: &mut [u8], offset: usize, physical: u32, len: u16) {
        put16(image, offset, EXTENT_MAGIC);
        put16(image, offset + 2, 1);
        put16(image, offset + 4, 4);
        put16(image, offset + 6, 0);
        put32(image, offset + 12, 0);
        put16(image, offset + 16, len);
        put16(image, offset + 18, 0);
        put32(image, offset + 20, physical);
    }

    pub(crate) fn image() -> Vec<u8> {
        const BLOCK: usize = 1024;
        let mut image = vec![0; 32 * BLOCK];
        let sb = SUPERBLOCK_OFFSET as usize;
        put32(&mut image, sb, 16); // inodes_count
        put32(&mut image, sb + 0x04, 32); // blocks_count
        put32(&mut image, sb + 0x14, 1); // first_data_block
        put32(&mut image, sb + 0x18, 0); // 1 KiB blocks
        put32(&mut image, sb + 0x20, 32); // blocks_per_group
        put32(&mut image, sb + 0x28, 16); // inodes_per_group
        put16(&mut image, sb + 0x38, EXT4_MAGIC);
        put32(&mut image, sb + 0x4c, 1); // dynamic revision
        put32(&mut image, sb + 0x54, 11); // first non-reserved inode
        put16(&mut image, sb + 0x58, 128); // inode size
        put32(
            &mut image,
            sb + 0x60,
            ondisk::INCOMPAT_FILETYPE | ondisk::INCOMPAT_EXTENTS,
        );

        put32(&mut image, 2 * BLOCK + 8, 5); // group 0 inode table

        let root = 5 * BLOCK + 128; // inode 2
        put16(&mut image, root, 0x41ed);
        put32(&mut image, root + 4, BLOCK as u32);
        put16(&mut image, root + 0x1a, 2);
        put32(&mut image, root + 0x20, EXTENTS_FL);
        extent(&mut image, root + 0x28, 10);

        let hello = 5 * BLOCK + 256; // inode 3
        put16(&mut image, hello, 0x81a4);
        put32(&mut image, hello + 4, 5);
        put16(&mut image, hello + 0x1a, 1);
        put32(&mut image, hello + 0x20, EXTENTS_FL);
        extent(&mut image, hello + 0x28, 11);

        let dir = 10 * BLOCK;
        put32(&mut image, dir, 2);
        put16(&mut image, dir + 4, 12);
        image[dir + 6] = 1;
        image[dir + 7] = 2;
        image[dir + 8] = b'.';
        put32(&mut image, dir + 12, 2);
        put16(&mut image, dir + 16, 12);
        image[dir + 18] = 2;
        image[dir + 19] = 2;
        image[dir + 20..dir + 22].copy_from_slice(b"..");
        put32(&mut image, dir + 24, 3);
        put16(&mut image, dir + 28, (BLOCK - 24) as u16);
        image[dir + 30] = 5;
        image[dir + 31] = 1;
        image[dir + 32..dir + 37].copy_from_slice(b"hello");
        image[11 * BLOCK..11 * BLOCK + 5].copy_from_slice(b"hello");
        image
    }

    fn legacy_image() -> Vec<u8> {
        const BLOCK: usize = 1024;
        let mut image = image();
        let inode = 5 * BLOCK + 256; // inode 3
        put32(&mut image, inode + 0x20, 0);
        image[inode + 0x28..inode + 0x64].fill(0);
        put32(&mut image, inode + 0x28, 11);
        image
    }

    fn journal_image(with_commit: bool, with_revoke: bool) -> Vec<u8> {
        const BLOCK: usize = 1024;
        const MAGIC: u32 = 0xc03b_3998;
        let mut image = image();
        let sb = SUPERBLOCK_OFFSET as usize;
        put32(&mut image, sb + 0x5c, 4); // has_journal
        put32(
            &mut image,
            sb + 0x60,
            ondisk::INCOMPAT_FILETYPE | ondisk::INCOMPAT_EXTENTS | ondisk::INCOMPAT_RECOVER,
        );
        put32(&mut image, sb + 0xe0, 8); // journal inode

        let journal_inode = 5 * BLOCK + 7 * 128;
        put16(&mut image, journal_inode, 0x8180);
        put32(&mut image, journal_inode + 4, (8 * BLOCK) as u32);
        put16(&mut image, journal_inode + 0x1a, 1);
        put32(&mut image, journal_inode + 0x20, EXTENTS_FL);
        extent_len(&mut image, journal_inode + 0x28, 20, 8);

        let journal_super = 20 * BLOCK;
        put_be32(&mut image, journal_super, MAGIC);
        put_be32(&mut image, journal_super + 4, 4);
        put_be32(&mut image, journal_super + 0x0c, BLOCK as u32);
        put_be32(&mut image, journal_super + 0x10, 8);
        put_be32(&mut image, journal_super + 0x14, 1);
        put_be32(&mut image, journal_super + 0x18, 1);
        put_be32(&mut image, journal_super + 0x1c, 1);
        if with_revoke {
            put_be32(&mut image, journal_super + 0x28, 1);
        }

        let descriptor = 21 * BLOCK;
        put_be32(&mut image, descriptor, MAGIC);
        put_be32(&mut image, descriptor + 4, 1);
        put_be32(&mut image, descriptor + 8, 1);
        put_be32(&mut image, descriptor + 12, 11);
        put_be16(&mut image, descriptor + 16, 0);
        put_be16(&mut image, descriptor + 18, 8); // last; explicit zero UUID follows

        let journal_data = image[11 * BLOCK..12 * BLOCK].to_vec();
        image[22 * BLOCK..23 * BLOCK].copy_from_slice(&journal_data);
        image[22 * BLOCK..22 * BLOCK + 5].copy_from_slice(b"new!!");
        if with_commit {
            let commit = 23 * BLOCK;
            put_be32(&mut image, commit, MAGIC);
            put_be32(&mut image, commit + 4, 2);
            put_be32(&mut image, commit + 8, 1);
        }

        if with_revoke {
            let revoke = 24 * BLOCK;
            put_be32(&mut image, revoke, MAGIC);
            put_be32(&mut image, revoke + 4, 5);
            put_be32(&mut image, revoke + 8, 2);
            put_be32(&mut image, revoke + 12, 20);
            put_be32(&mut image, revoke + 16, 11);
            let commit = 25 * BLOCK;
            put_be32(&mut image, commit, MAGIC);
            put_be32(&mut image, commit + 4, 2);
            put_be32(&mut image, commit + 8, 2);
        }
        image
    }

    fn checksummed_journal_image() -> Vec<u8> {
        const BLOCK: usize = 1024;
        let mut image = journal_image(true, false);
        let seed = journal::crc32c(u32::MAX, &[0; 16]);

        let journal_super = 20 * BLOCK;
        put_be32(&mut image, journal_super + 0x28, 16); // checksum v3
        image[journal_super + 0x50] = 4; // CRC32C
        put_be32(&mut image, journal_super + 0xfc, 0);
        let checksum = journal::crc32c(u32::MAX, &image[journal_super..journal_super + BLOCK]);
        put_be32(&mut image, journal_super + 0xfc, checksum);

        let descriptor = 21 * BLOCK;
        let data = 22 * BLOCK;
        let data_checksum = journal::crc32c(
            journal::crc32c(seed, &1u32.to_be_bytes()),
            &image[data..data + BLOCK],
        );
        put_be32(&mut image, descriptor + 24, data_checksum);
        put_be32(&mut image, descriptor + BLOCK - 4, 0);
        let descriptor_checksum = journal::crc32c(seed, &image[descriptor..descriptor + BLOCK]);
        put_be32(&mut image, descriptor + BLOCK - 4, descriptor_checksum);

        let commit = 23 * BLOCK;
        put_be32(&mut image, commit + 16, 0);
        let commit_checksum = journal::crc32c(seed, &image[commit..commit + BLOCK]);
        put_be32(&mut image, commit + 16, commit_checksum);
        image
    }

    #[test]
    fn mounts_and_reads_extent_file() {
        let (mut fs, mut storage) = mounted(image());
        assert_eq!(fs.block_size(), 1024);
        let mut output = [0; 8];
        assert_eq!(fs.read(&mut storage, "/hello", 0, &mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"hello");
        assert_eq!(fs.stat(&mut storage, "/").unwrap().number, ROOT_INODE);
    }

    #[test]
    fn reads_legacy_direct_block_file() {
        let (mut fs, mut storage) = mounted(legacy_image());
        let mut output = [0; 8];
        assert_eq!(fs.read(&mut storage, "/hello", 0, &mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"hello");
    }

    #[test]
    fn maps_single_double_and_triple_indirect_boundaries() {
        const BLOCK: usize = 1024;
        let mut image = legacy_image();
        let inode_offset = 5 * BLOCK + 256;
        put32(&mut image, inode_offset + 0x28 + 12 * 4, 12);
        put32(&mut image, 12 * BLOCK, 13);
        put32(&mut image, 12 * BLOCK + 255 * 4, 14);

        put32(&mut image, inode_offset + 0x28 + 13 * 4, 15);
        put32(&mut image, 15 * BLOCK, 16);
        put32(&mut image, 16 * BLOCK, 17);

        put32(&mut image, inode_offset + 0x28 + 14 * 4, 18);
        put32(&mut image, 18 * BLOCK, 19);
        put32(&mut image, 19 * BLOCK, 20);
        put32(&mut image, 20 * BLOCK, 21);

        let (mut fs, mut storage) = mounted(image);
        let inode = fs.load_inode(&mut storage, 3).unwrap();
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 0).unwrap(),
            Some(11)
        );
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 12).unwrap(),
            Some(13)
        );
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 12 + 255).unwrap(),
            Some(14)
        );
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 12 + 256).unwrap(),
            Some(17)
        );
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 12 + 256 + 256 * 256)
                .unwrap(),
            Some(21)
        );
        assert_eq!(fs.map_file_block(&mut storage, &inode, 13).unwrap(), None);
    }

    #[test]
    fn rejects_legacy_pointer_past_filesystem_end() {
        const BLOCK: usize = 1024;
        let mut image = legacy_image();
        put32(&mut image, 5 * BLOCK + 256 + 0x28, 32);
        let (mut fs, mut storage) = mounted(image);
        let inode = fs.load_inode(&mut storage, 3).unwrap();
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 0).unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );

        let mut image = legacy_image();
        put32(&mut image, 5 * BLOCK + 256 + 0x28 + 12 * 4, 32);
        let (mut fs, mut storage) = mounted(image);
        let inode = fs.load_inode(&mut storage, 3).unwrap();
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, 12).unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );

        let pointers = (BLOCK / 4) as u64;
        let past_capacity = 12 + pointers + pointers * pointers + pointers * pointers * pointers;
        assert_eq!(
            fs.map_file_block(&mut storage, &inode, past_capacity)
                .unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );
    }

    #[test]
    fn committed_journal_data_is_a_read_overlay() {
        let original = journal_image(true, false);
        let (mut fs, mut storage) = mounted(original.clone());
        let mut output = [0; 5];
        assert_eq!(fs.read(&mut storage, "/hello", 0, &mut output).unwrap(), 5);
        assert_eq!(&output, b"new!!");
        assert_eq!(fs.recovered_blocks(), 1);
        assert_eq!(storage.durable_bytes(), original);
    }

    #[test]
    fn incomplete_transaction_never_becomes_visible() {
        let (mut fs, mut storage) = mounted(journal_image(false, false));
        let mut output = [0; 5];
        fs.read(&mut storage, "/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"hello");
        assert_eq!(fs.recovered_blocks(), 0);
    }

    #[test]
    fn later_committed_revoke_suppresses_replay() {
        let (mut fs, mut storage) = mounted(journal_image(true, true));
        let mut output = [0; 5];
        fs.read(&mut storage, "/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"hello");
        assert_eq!(fs.recovered_blocks(), 0);
    }

    #[test]
    fn checksum_v3_validates_super_descriptor_data_and_commit() {
        let image = checksummed_journal_image();
        let (mut fs, mut storage) = mounted(image.clone());
        let mut output = [0; 5];
        fs.read(&mut storage, "/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"new!!");

        for offset in [
            20 * 1024 + 0x18,
            21 * 1024 + 40,
            22 * 1024 + 8,
            23 * 1024 + 24,
        ] {
            let mut corrupt = image.clone();
            corrupt[offset] ^= 1;
            let mut storage = ModelStorage::new(corrupt);
            assert!(matches!(
                Ext4::mount(&mut storage),
                Err(Error::Corrupt(Corrupt::JournalChecksum))
            ));
        }
    }

    #[test]
    fn every_journal_read_effect_can_fail_cleanly() {
        let image = journal_image(true, false);
        let (_successful, storage) = mounted(image.clone());
        let effects = storage.effects().len();
        assert!(effects >= 8);
        for sequence in 0..effects {
            let mut storage =
                ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
            assert!(matches!(
                Ext4::mount(&mut storage),
                Err(Error::Storage(error))
                    if error.downcast_ref::<ModelError>() == Some(&ModelError::InjectedIo)
            ));
        }
    }

    #[test]
    fn every_read_effect_can_fail_cleanly() {
        let (mut successful, mut successful_storage) = mounted(image());
        let mut output = [0; 5];
        successful
            .read(&mut successful_storage, "/hello", 0, &mut output)
            .unwrap();
        let effects = successful_storage.effects().len();
        assert!(effects >= 6);

        for sequence in 0..effects {
            let mut storage =
                ModelStorage::new(image()).with_injection(Inject::IoErrorAt(sequence));
            match Ext4::mount(&mut storage) {
                Err(Error::Storage(error))
                    if error.downcast_ref::<ModelError>() == Some(&ModelError::InjectedIo) => {}
                Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
                Ok(mut fs) => {
                    let error = fs.read(&mut storage, "/hello", 0, &mut output).unwrap_err();
                    assert!((error).storage_is(&ModelError::InjectedIo));
                }
            }
        }
    }

    #[test]
    fn writes_are_not_durable_until_flush() {
        let mut storage = ModelStorage::new(vec![0; 16]);
        storage.write(4, b"new").unwrap();
        assert_eq!(storage.pending_writes(), 1);
        storage.power_loss();
        let mut bytes = [1; 3];
        storage.read(4, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 3]);

        storage.write(4, b"new").unwrap();
        storage.flush().unwrap();
        storage.power_loss();
        storage.read(4, &mut bytes).unwrap();
        assert_eq!(&bytes, b"new");
    }

    #[test]
    fn transaction_dirty_blocks_are_private_and_preallocated() {
        const BLOCK: usize = 1024;
        let (mut fs, mut storage) = mounted(image());
        let effects_before = storage.effects().len();
        {
            let mut transaction = fs.begin_transaction(&mut storage);
            transaction.reserve_blocks(1).unwrap();
            assert_eq!(transaction.reserved_blocks(), 1);

            let mut replacement = vec![0; BLOCK];
            replacement[..5].copy_from_slice(b"new!!");
            transaction.write_block(11, &replacement).unwrap();
            assert_eq!(transaction.dirty_blocks(), 1);
            assert_eq!(transaction.reserved_blocks(), 0);
            assert!(transaction.is_dirty(11));

            replacement[..5].copy_from_slice(b"again");
            transaction.write_block(11, &replacement).unwrap();
            let mut visible = vec![0; BLOCK];
            transaction.read_block(11, &mut visible).unwrap();
            assert_eq!(&visible[..5], b"again");
        }

        assert_eq!(storage.effects().len(), effects_before);
        assert!(
            storage
                .effects()
                .iter()
                .all(|effect| effect.kind != EffectKind::Write)
        );
        let mut contents = [0; 5];
        fs.read(&mut storage, "/hello", 0, &mut contents).unwrap();
        assert_eq!(&contents, b"hello");
    }

    #[test]
    fn transaction_modify_loads_once_and_reads_its_own_write() {
        const BLOCK: usize = 1024;
        let (mut fs, mut storage) = mounted(image());
        let effects_before = storage.effects().len();
        {
            let mut transaction = fs.begin_transaction(&mut storage);
            transaction.reserve_blocks(1).unwrap();
            transaction
                .modify_block(11, |block| block[..5].copy_from_slice(b"new!!"))
                .unwrap();
            let mut contents = vec![0; BLOCK];
            transaction.read_block(11, &mut contents).unwrap();
            assert_eq!(&contents[..5], b"new!!");
        }
        assert_eq!(storage.effects().len(), effects_before + 1);
        assert_eq!(storage.effects().last().unwrap().kind, EffectKind::Read);
    }

    #[test]
    fn transaction_enforces_reservations_and_block_bounds() {
        const BLOCK: usize = 1024;
        let (mut fs, mut storage) = mounted(image());
        let mut transaction = fs.begin_transaction(&mut storage);
        let block = vec![0; BLOCK];
        assert_eq!(
            transaction.write_block(11, &block).unwrap_err(),
            FsError::ReservationExhausted
        );
        assert_eq!(
            transaction.read_block(32, &mut [0; BLOCK]).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            transaction.write_block(11, &[0; 4]).unwrap_err(),
            FsError::InvalidArgument
        );
        assert_eq!(transaction.dirty_blocks(), 0);
    }

    #[test]
    fn failed_transaction_load_returns_its_reserved_buffer() {
        let (_successful, successful_storage) = mounted(image());
        let next_effect = successful_storage.effects().len();

        let mut storage = ModelStorage::new(image()).with_injection(Inject::IoErrorAt(next_effect));
        let mut fs = Ext4::mount(&mut storage).unwrap();
        let mut transaction = fs.begin_transaction(&mut storage);
        transaction.reserve_blocks(1).unwrap();
        assert!(
            (transaction.modify_block(11, |_| {}).unwrap_err()).storage_is(&ModelError::InjectedIo)
        );
        assert_eq!(transaction.dirty_blocks(), 0);
        assert_eq!(transaction.reserved_blocks(), 1);
    }

    #[test]
    fn model_can_tear_a_pending_write() {
        let mut storage = ModelStorage::new(vec![0; 16]);
        storage.write(4, b"abcdef").unwrap();
        storage.persist_pending_with_torn(0, 3).unwrap();
        let mut bytes = [0; 6];
        storage.read(4, &mut bytes).unwrap();
        assert_eq!(&bytes, b"abc\0\0\0");
    }

    #[test]
    fn rejects_bad_superblock_checksum() {
        let mut image = image();
        let sb = SUPERBLOCK_OFFSET as usize;
        put32(&mut image, sb + 0x64, ondisk::RO_COMPAT_METADATA_CSUM);
        let mut storage = ModelStorage::new(image);
        assert_eq!(
            Ext4::mount(&mut storage).err(),
            Some(Error::Corrupt(Corrupt::SuperblockChecksum)),
        );
    }
}
