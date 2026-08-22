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
mod journal;
mod ondisk;
mod storage;
pub mod test_support;
mod transaction;

use alloc::vec::Vec;
use core::fmt;
pub use ondisk::Superblock;
use ondisk::{checked_read, le16, le32};
pub use storage::Storage;
pub use transaction::Transaction;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryBlockKind {
    Leaf,
    Root,
    Internal,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    Storage(E),
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

impl<E> From<Corrupt> for Error<E> {
    fn from(value: Corrupt) -> Self {
        Self::Corrupt(value)
    }
}

impl<E> From<Unsupported> for Error<E> {
    fn from(value: Unsupported) -> Self {
        Self::Unsupported(value)
    }
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
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
    flags: u32,
    generation: u32,
    blocks_512: u64,
    external_xattr_block: u64,
    block_map: [u8; 60],
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

struct PendingExtendedAttribute {
    namespace: u8,
    name: Vec<u8>,
    value: PendingExtendedAttributeValue,
}

enum PendingExtendedAttributeValue {
    Inline(Vec<u8>),
    Inode { number: u32, size: usize },
}

impl Inode {
    pub fn is_directory(&self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_DIRECTORY
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & MODE_TYPE_MASK == 0xa000
    }
}

fn decode_inode_timestamp<E>(
    raw: &[u8],
    seconds_offset: usize,
    extra_offset: usize,
    inode_number: u32,
) -> Result<Timestamp, Error<E>> {
    let seconds = i64::from(le32(raw, seconds_offset) as i32);
    let extra = if extra_offset + 4 <= raw.len() {
        le32(raw, extra_offset)
    } else {
        0
    };
    let nanoseconds = extra >> 2;
    if nanoseconds >= 1_000_000_000 {
        return Err(Corrupt::InvalidInode(inode_number).into());
    }
    Ok(Timestamp {
        seconds: seconds + (i64::from(extra & 3) << 32),
        nanoseconds,
    })
}

/// A mounted filesystem that owns its storage object.
pub struct Ext4<S> {
    storage: S,
    superblock: Superblock,
    overlay: Vec<(u64, Vec<u8>)>,
}

impl<S: Storage> Ext4<S> {
    pub fn mount(mut storage: S) -> Result<Self, Error<S::Error>> {
        let superblock = Superblock::load(&mut storage)?;
        let mut filesystem = Self {
            storage,
            superblock,
            overlay: Vec::new(),
        };
        if filesystem.superblock.needs_recovery() {
            filesystem.replay_journal()?;
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
    pub fn storage(&self) -> &S {
        &self.storage
    }
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Begin an isolated block transaction. Dropping it performs no writes.
    pub fn begin_transaction(&mut self) -> Transaction<'_, S> {
        Transaction::new(self)
    }

    /// Number of filesystem blocks supplied by committed journal records.
    pub fn recovered_blocks(&self) -> usize {
        self.overlay.len()
    }

    fn read_storage(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Error<S::Error>> {
        checked_read(&mut self.storage, offset, dst)?;
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
    pub fn root(&mut self) -> Result<Inode, Error<S::Error>> {
        self.load_inode(ROOT_INODE)
    }

    /// Reload an inode identity from disk, rejecting a reused identity.
    pub fn refresh(&mut self, inode: &Inode) -> Result<Inode, Error<S::Error>> {
        let current = self.load_inode(inode.number)?;
        if current.generation != inode.generation {
            return Err(Error::NotFound);
        }
        Ok(current)
    }

    pub fn read_inode(
        &mut self,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error<S::Error>> {
        let inode = self.refresh(inode)?;
        self.read_inode_data(&inode, offset, dst)
    }

    /// Read the target bytes stored in a symbolic-link inode.
    pub fn read_symlink(&mut self, inode: &Inode) -> Result<Vec<u8>, Error<S::Error>> {
        let inode = self.refresh(inode)?;
        if !inode.is_symlink() {
            return Err(Error::InvalidArgument);
        }
        self.read_symlink_inode(&inode)
    }

    /// Return every inode-body and external-block extended attribute.
    /// Namespace access policy and prefix mapping belong to the caller.
    pub fn extended_attributes(
        &mut self,
        inode: &Inode,
    ) -> Result<Vec<ExtendedAttribute>, Error<S::Error>> {
        let current = self.refresh(inode)?;
        let raw = self.read_raw_inode(current.number)?;
        let mut pending = Vec::new();
        if raw.len() >= 0x84 {
            let header = 128usize
                .checked_add(usize::from(le16(&raw, 0x80)))
                .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= raw.len()))
                .ok_or(Corrupt::InvalidExtendedAttributes(current.number))?;
            if le32(&raw, header) == 0xea02_0000 {
                parse_extended_attributes(
                    current.number,
                    &raw,
                    header + 4,
                    header + 4,
                    &mut pending,
                )?;
            }
        }

        if current.external_xattr_block != 0 {
            let block = self.read_external_xattr_block(&current)?;
            parse_extended_attributes(current.number, &block, 32, 0, &mut pending)?;
        }
        let mut attributes = Vec::new();
        attributes
            .try_reserve_exact(pending.len())
            .map_err(|_| Error::OutOfMemory)?;
        for attribute in pending {
            let value = match attribute.value {
                PendingExtendedAttributeValue::Inline(value) => value,
                PendingExtendedAttributeValue::Inode { number, size } => {
                    self.read_extended_attribute_inode(number, size)?
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
        number: u32,
        size: usize,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        if self.superblock.feature_incompat & ondisk::INCOMPAT_EA_INODE == 0 {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let raw = self.read_raw_inode(number)?;
        let inode = self.load_inode(number)?;
        if inode.mode & MODE_TYPE_MASK != MODE_REGULAR
            || inode.flags & EA_INODE_FL == 0
            || inode.size != size as u64
            || le32(&raw, 0x0c) == 0 && le32(&raw, 0x24) == 0
        {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(size)
            .map_err(|_| Error::OutOfMemory)?;
        value.resize(size, 0);
        if self.read_inode_data(&inode, 0, &mut value)? != size {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        let mut checksum = checksum::Checksum::with_seed(self.superblock.checksum_seed);
        checksum.update(&value);
        if checksum.finalize() != le32(&raw, 0x08) {
            return Err(Corrupt::InvalidExtendedAttributes(number).into());
        }
        Ok(value)
    }

    fn read_external_xattr_block(&mut self, inode: &Inode) -> Result<Vec<u8>, Error<S::Error>> {
        let number = inode.external_xattr_block;
        if number == 0 || number >= self.superblock.blocks_count {
            return Err(Corrupt::InvalidExtendedAttributes(inode.number).into());
        }
        let mut block = self.new_block_buffer()?;
        self.read_storage(
            number
                .checked_mul(u64::from(self.superblock.block_size))
                .ok_or(Corrupt::AddressOverflow)?,
            &mut block,
        )?;
        if block.len() < 32
            || le32(&block, 0) != 0xea02_0000
            || le32(&block, 4) == 0
            || le32(&block, 8) != 1
            || block[0x14..0x20].iter().any(|byte| *byte != 0)
        {
            return Err(Corrupt::InvalidExtendedAttributes(inode.number).into());
        }
        if self.superblock.has_metadata_checksums() {
            let expected = le32(&block, 0x10);
            block[0x10..0x14].fill(0);
            update_external_xattr_checksum(self.superblock.checksum_seed, number, &mut block);
            if le32(&block, 0x10) != expected {
                return Err(Corrupt::ExtendedAttributeChecksum(number).into());
            }
        }
        Ok(block)
    }

    fn read_symlink_inode(&mut self, inode: &Inode) -> Result<Vec<u8>, Error<S::Error>> {
        let len = usize::try_from(inode.size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut target = Vec::new();
        target
            .try_reserve_exact(len)
            .map_err(|_| Error::OutOfMemory)?;
        target.resize(len, 0);
        if inode.blocks_512 == 0 && len <= inode.block_map.len() {
            target.copy_from_slice(&inode.block_map[..len]);
            return Ok(target);
        }
        if self.read_inode_data(inode, 0, &mut target)? != len {
            return Err(Corrupt::InvalidInode(inode.number).into());
        }
        Ok(target)
    }

    /// Append at most `max` checked directory entries, resuming from an opaque
    /// byte cookie returned by the previous call. `None` means end of directory.
    pub fn list(
        &mut self,
        directory: &Inode,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error<S::Error>> {
        if max == 0 {
            return Err(Error::InvalidArgument);
        }
        let directory = self.refresh(directory)?;
        if !directory.is_directory() {
            return Err(Error::NotDirectory);
        }
        if cookie > directory.size {
            return Err(Error::InvalidArgument);
        }
        if directory.flags & INLINE_DATA_FL != 0 {
            return self.list_inline_directory(&directory, cookie, output, max);
        }
        let initial_len = output.len();
        output.try_reserve(max).map_err(|_| Error::OutOfMemory)?;
        let block_size = u64::from(self.superblock.block_size);
        let blocks = directory.size.div_ceil(block_size);
        let first_logical = cookie / block_size;
        let first_within =
            usize::try_from(cookie % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut block = self.new_block_buffer()?;

        for logical in first_logical..blocks {
            block.fill(0);
            let block_offset = logical
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let count = self.read_inode_data(&directory, block_offset, &mut block)?;
            let kind = self.directory_block_kind(&directory, logical, count, &block);
            if self.superblock.has_metadata_checksums() {
                self.verify_directory_checksum(&directory, kind, count, &block)?;
            }
            if kind != DirectoryBlockKind::Leaf {
                continue;
            }
            let end = if self.superblock.has_metadata_checksums() {
                count.checked_sub(12).ok_or(Corrupt::InvalidDirectory)?
            } else {
                count
            };
            let wanted = if logical == first_logical {
                first_within
            } else {
                0
            };
            let mut cursor = 0usize;
            let mut cookie_is_boundary = wanted == 0;
            while cursor < end {
                if end - cursor < 8 {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let number = le32(&block, cursor);
                let record_len = usize::from(le16(&block, cursor + 4));
                let name_len = usize::from(block[cursor + 6]);
                if record_len < 8
                    || !record_len.is_multiple_of(4)
                    || record_len > end - cursor
                    || name_len > record_len - 8
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                if cursor == wanted {
                    cookie_is_boundary = true;
                }
                let next = cursor + record_len;
                if cursor >= wanted && number != 0 {
                    let name = &block[cursor + 8..cursor + 8 + name_len];
                    if name != b"." && name != b".." {
                        let mut owned_name = Vec::new();
                        owned_name
                            .try_reserve_exact(name_len)
                            .map_err(|_| Error::OutOfMemory)?;
                        owned_name.extend_from_slice(name);
                        let inode = self.load_inode(number)?;
                        output.push(DirectoryEntry {
                            name: owned_name,
                            file_type: block[cursor + 7],
                            inode,
                        });
                        if output.len() - initial_len == max {
                            return Ok(Some(
                                block_offset
                                    .checked_add(next as u64)
                                    .ok_or(Corrupt::AddressOverflow)?,
                            ));
                        }
                    }
                }
                cursor = next;
            }
            if logical == first_logical && wanted != end && !cookie_is_boundary {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(None)
    }

    fn list_inline_directory(
        &mut self,
        directory: &Inode,
        cookie: u64,
        output: &mut Vec<DirectoryEntry>,
        max: usize,
    ) -> Result<Option<u64>, Error<S::Error>> {
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
        let mut cursor = 0usize;
        let mut cookie_is_boundary = wanted == 0;
        while cursor < data.len() {
            if data.len() - cursor < 8 {
                return Err(Corrupt::InvalidDirectory.into());
            }
            let number = le32(data, cursor);
            let record_len = usize::from(le16(data, cursor + 4));
            let name_len = usize::from(data[cursor + 6]);
            if record_len < 8
                || !record_len.is_multiple_of(4)
                || record_len > data.len() - cursor
                || name_len > record_len - 8
            {
                return Err(Corrupt::InvalidDirectory.into());
            }
            if cursor == wanted {
                cookie_is_boundary = true;
            }
            let next = cursor + record_len;
            if cursor >= wanted && number != 0 {
                let mut name = Vec::new();
                name.try_reserve_exact(name_len)
                    .map_err(|_| Error::OutOfMemory)?;
                name.extend_from_slice(&data[cursor + 8..cursor + 8 + name_len]);
                output.push(DirectoryEntry {
                    name,
                    file_type: data[cursor + 7],
                    inode: self.load_inode(number)?,
                });
                if output.len() - initial_len == max {
                    return Ok(Some(next as u64));
                }
            }
            cursor = next;
        }
        if wanted != data.len() && !cookie_is_boundary {
            return Err(Error::InvalidArgument);
        }
        Ok(None)
    }

    fn new_block_buffer(&self) -> Result<Vec<u8>, Error<S::Error>> {
        let len = self.superblock.block_size as usize;
        let mut result = Vec::new();
        result
            .try_reserve_exact(len)
            .map_err(|_| Error::OutOfMemory)?;
        result.resize(len, 0);
        Ok(result)
    }

    fn read_group_descriptor(&mut self, group: u32) -> Result<Vec<u8>, Error<S::Error>> {
        if group >= self.superblock.group_count() {
            return Err(Corrupt::InvalidGroup(group).into());
        }
        let len = usize::from(self.superblock.descriptor_size);
        let offset = self
            .superblock
            .descriptor_offset(group)
            .ok_or(Corrupt::AddressOverflow)?;
        let mut descriptor = Vec::new();
        descriptor
            .try_reserve_exact(len)
            .map_err(|_| Error::OutOfMemory)?;
        descriptor.resize(len, 0);
        self.read_storage(offset, &mut descriptor)?;
        if self.superblock.has_metadata_checksums() {
            let expected = le16(&descriptor, 0x1e);
            let mut checksum = checksum::Checksum::with_seed(self.superblock.checksum_seed);
            checksum.update_u32_le(group);
            checksum.update(&descriptor[..0x1e]);
            checksum.update_u16_le(0);
            checksum.update(&descriptor[0x20..]);
            if checksum.finalize() as u16 != expected {
                return Err(Corrupt::GroupDescriptorChecksum(group).into());
            }
        } else if self.superblock.feature_ro_compat & ondisk::RO_COMPAT_GDT_CSUM != 0 {
            let expected = le16(&descriptor, 0x1e);
            if legacy_group_descriptor_checksum(&self.superblock.uuid, group, &descriptor)
                != expected
            {
                return Err(Corrupt::GroupDescriptorChecksum(group).into());
            }
        }
        Ok(descriptor)
    }

    fn read_raw_inode(&mut self, number: u32) -> Result<Vec<u8>, Error<S::Error>> {
        if number == 0 || number > self.superblock.inodes_count {
            return Err(Corrupt::InvalidInode(number).into());
        }
        let zero_based = number - 1;
        let group = zero_based / self.superblock.inodes_per_group;
        let index = zero_based % self.superblock.inodes_per_group;
        let descriptor = self.read_group_descriptor(group)?;
        let mut inode_table = u64::from(le32(&descriptor, 8));
        if self.superblock.feature_incompat & ondisk::INCOMPAT_64BIT != 0 {
            inode_table |= u64::from(le32(&descriptor, 40)) << 32;
        }
        if inode_table == 0 || inode_table >= self.superblock.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        let offset = inode_table
            .checked_mul(u64::from(self.superblock.block_size))
            .and_then(|v| v.checked_add(u64::from(index) * u64::from(self.superblock.inode_size)))
            .ok_or(Corrupt::AddressOverflow)?;
        let len = usize::from(self.superblock.inode_size);
        let mut raw = Vec::new();
        raw.try_reserve_exact(len).map_err(|_| Error::OutOfMemory)?;
        raw.resize(len, 0);
        self.read_storage(offset, &mut raw)?;

        let generation = le32(&raw, 0x64);
        if self.superblock.has_metadata_checksums() {
            let expected_lo = le16(&raw, 0x7c);
            raw[0x7c..0x7e].fill(0);
            let expected_hi = if raw.len() >= 0x84 {
                let value = le16(&raw, 0x82);
                raw[0x82..0x84].fill(0);
                Some(value)
            } else {
                None
            };
            let mut checksum = checksum::Checksum::with_seed(self.superblock.checksum_seed);
            checksum.update_u32_le(number);
            checksum.update_u32_le(generation);
            checksum.update(&raw);
            let actual = checksum.finalize();
            let matches = expected_hi.map_or(actual as u16 == expected_lo, |expected_hi| {
                actual == u32::from(expected_lo) | (u32::from(expected_hi) << 16)
            });
            if !matches {
                return Err(Corrupt::InodeChecksum(number).into());
            }
        }
        Ok(raw)
    }

    pub(crate) fn load_inode(&mut self, number: u32) -> Result<Inode, Error<S::Error>> {
        let raw = self.read_raw_inode(number)?;
        let generation = le32(&raw, 0x64);
        let mode = le16(&raw, 0);
        if mode == 0 {
            return Err(Corrupt::InvalidInode(number).into());
        }
        let size = u64::from(le32(&raw, 4)) | (u64::from(le32(&raw, 0x6c)) << 32);
        let uid = u32::from(le16(&raw, 2)) | (u32::from(le16(&raw, 0x78)) << 16);
        let gid = u32::from(le16(&raw, 0x18)) | (u32::from(le16(&raw, 0x7a)) << 16);
        let mut block_map = [0; 60];
        block_map.copy_from_slice(&raw[0x28..0x64]);
        let flags = le32(&raw, 0x20);
        let inline_data = if flags & INLINE_DATA_FL != 0
            && matches!(
                mode & MODE_TYPE_MASK,
                MODE_REGULAR | MODE_DIRECTORY | MODE_SYMLINK
            ) {
            Some(parse_inline_data(number, mode, size, &raw, &block_map)?)
        } else {
            None
        };
        let blocks_512 = u64::from(le32(&raw, 0x1c)) | (u64::from(le16(&raw, 0x74)) << 32);
        let external_xattr_block = u64::from(le32(&raw, 0x68))
            | if self.superblock.feature_incompat & ondisk::INCOMPAT_64BIT != 0 {
                u64::from(le16(&raw, 0x76)) << 32
            } else {
                0
            };
        let (accessed, changed, modified) = if flags & EA_INODE_FL != 0 {
            let zero = Timestamp {
                seconds: 0,
                nanoseconds: 0,
            };
            (zero, zero, zero)
        } else {
            (
                decode_inode_timestamp(&raw, 0x08, 0x8c, number)?,
                decode_inode_timestamp(&raw, 0x0c, 0x84, number)?,
                decode_inode_timestamp(&raw, 0x10, 0x88, number)?,
            )
        };
        Ok(Inode {
            number,
            mode,
            uid,
            gid,
            size,
            links: le16(&raw, 0x1a),
            accessed,
            modified,
            changed,
            flags,
            generation,
            blocks_512,
            external_xattr_block,
            block_map,
            inline_data,
        })
    }

    fn directory_block_kind(
        &self,
        directory: &Inode,
        logical: u64,
        count: usize,
        block: &[u8],
    ) -> DirectoryBlockKind {
        if directory.flags & DIRECTORY_INDEX_FL == 0 {
            DirectoryBlockKind::Leaf
        } else if logical == 0 {
            DirectoryBlockKind::Root
        } else if count >= 8 && usize::from(le16(block, 4)) == block.len() {
            DirectoryBlockKind::Internal
        } else {
            DirectoryBlockKind::Leaf
        }
    }

    fn verify_directory_checksum(
        &self,
        directory: &Inode,
        kind: DirectoryBlockKind,
        count: usize,
        block: &[u8],
    ) -> Result<(), Error<S::Error>> {
        if count != block.len() {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let mut checksum = self.inode_checksum_base(directory);
        let expected = match kind {
            DirectoryBlockKind::Leaf => {
                if block.len() < 12 {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let tail = block.len() - 12;
                if le32(block, tail) != 0
                    || le16(block, tail + 4) != 12
                    || block[tail + 6] != 0
                    || block[tail + 7] != 0xde
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                checksum.update(&block[..tail]);
                le32(block, block.len() - 4)
            }
            DirectoryBlockKind::Root | DirectoryBlockKind::Internal => {
                if block.len() < 8 {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let tail = block.len() - 8;
                let limit_offset = if kind == DirectoryBlockKind::Root {
                    0x20
                } else {
                    0x08
                };
                if limit_offset + 4 > tail {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let entries = usize::from(le16(block, limit_offset + 2));
                let hashed_bytes = entries
                    .checked_mul(8)
                    .and_then(|bytes| limit_offset.checked_add(bytes))
                    .filter(|end| *end <= tail)
                    .ok_or(Corrupt::InvalidDirectory)?;
                checksum.update(&block[..hashed_bytes]);
                checksum.update_u32_le(le32(block, tail));
                checksum.update_u32_le(0);
                le32(block, tail + 4)
            }
        };
        if checksum.finalize() != expected {
            return Err(Corrupt::DirectoryChecksum(directory.number).into());
        }
        Ok(())
    }

    fn read_inode_data(
        &mut self,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error<S::Error>> {
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
        let block_size = u64::from(self.superblock.block_size);
        let mut done = 0;
        while done < wanted {
            let position = offset + done as u64;
            let logical = position / block_size;
            let within = position % block_size;
            let amount = (wanted - done).min((block_size - within) as usize);
            match self.map_file_block(inode, logical)? {
                Some(physical) => {
                    let disk_offset = physical
                        .checked_mul(block_size)
                        .and_then(|v| v.checked_add(within))
                        .ok_or(Corrupt::AddressOverflow)?;
                    self.read_storage(disk_offset, &mut dst[done..done + amount])?;
                }
                None => dst[done..done + amount].fill(0),
            }
            done += amount;
        }
        Ok(done)
    }

    fn map_file_block(
        &mut self,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error<S::Error>> {
        if inode.flags & EXTENTS_FL == 0 {
            return self.map_legacy_block(inode, logical);
        }
        let root = inode.block_map;
        self.map_extent_node(&root, logical, 0, inode, false)
    }

    fn map_legacy_block(
        &mut self,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error<S::Error>> {
        const DIRECT_BLOCKS: u64 = 12;
        if logical < DIRECT_BLOCKS {
            return self
                .validate_legacy_pointer(u64::from(le32(&inode.block_map, logical as usize * 4)));
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
            return self
                .follow_legacy_indirect(u64::from(le32(&inode.block_map, 12 * 4)), &[remaining]);
        }
        remaining -= pointers;
        if remaining < double_capacity {
            return self.follow_legacy_indirect(
                u64::from(le32(&inode.block_map, 13 * 4)),
                &[remaining / pointers, remaining % pointers],
            );
        }
        remaining -= double_capacity;
        if remaining < triple_capacity {
            return self.follow_legacy_indirect(
                u64::from(le32(&inode.block_map, 14 * 4)),
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
        mut physical: u64,
        indexes: &[u64],
    ) -> Result<Option<u64>, Error<S::Error>> {
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

    fn validate_legacy_pointer(&self, physical: u64) -> Result<Option<u64>, Error<S::Error>> {
        if physical == 0 {
            Ok(None)
        } else if physical < self.superblock.blocks_count {
            Ok(Some(physical))
        } else {
            Err(Corrupt::InvalidLegacyBlockMap.into())
        }
    }

    fn map_extent_node(
        &mut self,
        node: &[u8],
        logical: u64,
        traversed: u16,
        inode: &Inode,
        external: bool,
    ) -> Result<Option<u64>, Error<S::Error>> {
        if node.len() < 12 || le16(node, 0) != EXTENT_MAGIC {
            return Err(Corrupt::InvalidExtentHeader.into());
        }
        let entries = usize::from(le16(node, 2));
        let max = usize::from(le16(node, 4));
        let depth = le16(node, 6);
        if depth > 5 || traversed > 5 {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        let capacity = (node.len() - 12) / 12;
        if entries > max || max > capacity {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        if external && self.superblock.has_metadata_checksums() {
            let checksum_offset = 12usize
                .checked_add(max.checked_mul(12).ok_or(Corrupt::AddressOverflow)?)
                .ok_or(Corrupt::AddressOverflow)?;
            if checksum_offset + 4 > node.len() {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            let expected = le32(node, checksum_offset);
            let mut checksum = self.inode_checksum_base(inode);
            checksum.update(&node[..checksum_offset]);
            if checksum.finalize() != expected {
                return Err(Corrupt::ExtentChecksum(inode.number).into());
            }
        }

        if depth == 0 {
            let mut previous = None;
            for i in 0..entries {
                let at = 12 + i * 12;
                let start_logical = u64::from(le32(node, at));
                if previous.is_some_and(|p| start_logical <= p) {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                previous = Some(start_logical);
                let encoded_len = le16(node, at + 4);
                if encoded_len == 0 {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                let initialized = encoded_len <= 32768;
                let len = if initialized {
                    u64::from(encoded_len)
                } else {
                    u64::from(encoded_len - 32768)
                };
                if logical >= start_logical && logical - start_logical < len {
                    if !initialized {
                        return Ok(None);
                    }
                    let physical_start =
                        u64::from(le32(node, at + 8)) | (u64::from(le16(node, at + 6)) << 32);
                    let physical = physical_start
                        .checked_add(logical - start_logical)
                        .ok_or(Corrupt::AddressOverflow)?;
                    if physical >= self.superblock.blocks_count {
                        return Err(Corrupt::ExtentPastEnd.into());
                    }
                    return Ok(Some(physical));
                }
            }
            return Ok(None);
        }

        let mut child = None;
        let mut previous = None;
        for i in 0..entries {
            let at = 12 + i * 12;
            let start_logical = u64::from(le32(node, at));
            if previous.is_some_and(|p| start_logical <= p) {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            previous = Some(start_logical);
            if start_logical <= logical {
                child = Some(u64::from(le32(node, at + 4)) | (u64::from(le16(node, at + 8)) << 32));
            } else {
                break;
            }
        }
        let Some(child) = child else { return Ok(None) };
        if child == 0 || child >= self.superblock.blocks_count {
            return Err(Corrupt::ExtentPastEnd.into());
        }
        let mut bytes = self.new_block_buffer()?;
        self.read_storage(
            child
                .checked_mul(u64::from(self.superblock.block_size))
                .ok_or(Corrupt::AddressOverflow)?,
            &mut bytes,
        )?;
        if le16(&bytes, 6).checked_add(1) != Some(depth) {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        self.map_extent_node(&bytes, logical, traversed + 1, inode, true)
    }

    fn inode_checksum_base(&self, inode: &Inode) -> checksum::Checksum {
        let mut checksum = checksum::Checksum::with_seed(self.superblock.checksum_seed);
        checksum.update_u32_le(inode.number);
        checksum.update_u32_le(inode.generation);
        checksum
    }
}

fn parse_extended_attributes<E>(
    inode: u32,
    bytes: &[u8],
    entries: usize,
    value_base: usize,
    output: &mut Vec<PendingExtendedAttribute>,
) -> Result<(), Error<E>> {
    let table_end = extended_attribute_table_end(bytes, entries, inode)?;
    let mut cursor = entries;
    while cursor < table_end - 4 {
        let name_len = usize::from(bytes[cursor]);
        let entry_len = (16usize
            .checked_add(name_len)
            .ok_or(Corrupt::InvalidExtendedAttributes(inode))?
            + 3)
            & !3;
        let next = cursor
            .checked_add(entry_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
        let value_inode = le32(bytes, cursor + 4);
        let value_size = usize::try_from(le32(bytes, cursor + 8))
            .map_err(|_| Corrupt::InvalidExtendedAttributes(inode))?;
        let mut name = Vec::new();
        name.try_reserve_exact(name_len)
            .map_err(|_| Error::OutOfMemory)?;
        name.extend_from_slice(&bytes[cursor + 16..cursor + 16 + name_len]);
        let value = if value_inode == 0 {
            let value = value_base
                .checked_add(usize::from(le16(bytes, cursor + 2)))
                .filter(|offset| {
                    (value_size == 0 || *offset >= table_end)
                        && offset
                            .checked_add(value_size)
                            .is_some_and(|end| end <= bytes.len())
                })
                .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(value_size)
                .map_err(|_| Error::OutOfMemory)?;
            owned.extend_from_slice(&bytes[value..value + value_size]);
            PendingExtendedAttributeValue::Inline(owned)
        } else {
            PendingExtendedAttributeValue::Inode {
                number: value_inode,
                size: value_size,
            }
        };
        output.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        output.push(PendingExtendedAttribute {
            namespace: bytes[cursor + 1],
            name,
            value,
        });
        cursor = next;
    }
    Ok(())
}

fn extended_attribute_table_end<E>(
    bytes: &[u8],
    entries: usize,
    inode: u32,
) -> Result<usize, Error<E>> {
    let mut cursor = entries;
    loop {
        if cursor.checked_add(4).is_none_or(|end| end > bytes.len()) {
            return Err(Corrupt::InvalidExtendedAttributes(inode).into());
        }
        if le32(bytes, cursor) == 0 {
            return Ok(cursor + 4);
        }
        if cursor.checked_add(16).is_none_or(|end| end > bytes.len()) {
            return Err(Corrupt::InvalidExtendedAttributes(inode).into());
        }
        let name_len = usize::from(bytes[cursor]);
        let entry_len = (16usize
            .checked_add(name_len)
            .ok_or(Corrupt::InvalidExtendedAttributes(inode))?
            + 3)
            & !3;
        cursor = cursor
            .checked_add(entry_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
    }
}

fn parse_inline_data<E>(
    inode: u32,
    mode: u16,
    size: u64,
    raw: &[u8],
    block_map: &[u8; 60],
) -> Result<Vec<u8>, Error<E>> {
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

    if raw.len() < 0x84 {
        return Err(Corrupt::InvalidInode(inode).into());
    }
    let header = 128usize
        .checked_add(usize::from(le16(raw, 0x80)))
        .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= raw.len()))
        .ok_or(Corrupt::InvalidInode(inode))?;
    if le32(raw, header) != 0xea02_0000 {
        return Err(Corrupt::InvalidInode(inode).into());
    }
    let entries = header + 4;
    let mut cursor = entries;
    let wanted = size - block_map.len();
    while cursor.checked_add(16).is_some_and(|end| end <= raw.len()) {
        if le32(raw, cursor) == 0 {
            break;
        }
        let name_len = usize::from(raw[cursor]);
        let entry_len = (16usize
            .checked_add(name_len)
            .ok_or(Corrupt::InvalidInode(inode))?
            + 3)
            & !3;
        let entry_end = cursor
            .checked_add(entry_len)
            .filter(|end| *end <= raw.len())
            .ok_or(Corrupt::InvalidInode(inode))?;
        if raw[cursor + 1] == 7 && name_len == 4 && &raw[cursor + 16..cursor + 20] == b"data" {
            let value_inum = le32(raw, cursor + 4);
            let value_size =
                usize::try_from(le32(raw, cursor + 8)).map_err(|_| Corrupt::InvalidInode(inode))?;
            let value = entries
                .checked_add(usize::from(le16(raw, cursor + 2)))
                .filter(|offset| {
                    offset
                        .checked_add(value_size)
                        .is_some_and(|end| end <= raw.len())
                })
                .ok_or(Corrupt::InvalidInode(inode))?;
            if value_inum != 0 || value_size != wanted {
                return Err(Corrupt::InvalidInode(inode).into());
            }
            data.extend_from_slice(&raw[value..value + value_size]);
            return Ok(data);
        }
        cursor = entry_end;
    }
    Err(Corrupt::InvalidInode(inode).into())
}

fn legacy_group_descriptor_checksum(uuid: &[u8; 16], group: u32, descriptor: &[u8]) -> u16 {
    let mut checksum = crc16(u16::MAX, uuid);
    checksum = crc16(checksum, &group.to_le_bytes());
    checksum = crc16(checksum, &descriptor[..0x1e]);
    if descriptor.len() > 0x20 {
        checksum = crc16(checksum, &descriptor[0x20..]);
    }
    checksum
}

fn update_external_xattr_checksum(seed: u32, number: u64, block: &mut [u8]) {
    block[0x10..0x14].fill(0);
    let mut checksum = checksum::Checksum::with_seed(seed);
    checksum.update(&number.to_le_bytes());
    checksum.update(block);
    block[0x10..0x14].copy_from_slice(&checksum.finalize().to_le_bytes());
}

fn crc16(mut checksum: u16, bytes: &[u8]) -> u16 {
    for &byte in bytes {
        checksum ^= u16::from(byte);
        for _ in 0..8 {
            checksum = if checksum & 1 != 0 {
                (checksum >> 1) ^ 0xa001
            } else {
                checksum >> 1
            };
        }
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::{EXT4_MAGIC, SUPERBLOCK_OFFSET};
    use crate::test_support::{EffectKind, Inject, ModelError, ModelStorage, PathExt4};

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
        let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
        assert_eq!(fs.block_size(), 1024);
        let mut output = [0; 8];
        assert_eq!(fs.read("/hello", 0, &mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"hello");
        assert_eq!(fs.stat("/").unwrap().number, ROOT_INODE);
    }

    #[test]
    fn reads_legacy_direct_block_file() {
        let mut fs = Ext4::mount(ModelStorage::new(legacy_image())).unwrap();
        let mut output = [0; 8];
        assert_eq!(fs.read("/hello", 0, &mut output).unwrap(), 5);
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

        let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
        let inode = fs.load_inode(3).unwrap();
        assert_eq!(fs.map_file_block(&inode, 0).unwrap(), Some(11));
        assert_eq!(fs.map_file_block(&inode, 12).unwrap(), Some(13));
        assert_eq!(fs.map_file_block(&inode, 12 + 255).unwrap(), Some(14));
        assert_eq!(fs.map_file_block(&inode, 12 + 256).unwrap(), Some(17));
        assert_eq!(
            fs.map_file_block(&inode, 12 + 256 + 256 * 256).unwrap(),
            Some(21)
        );
        assert_eq!(fs.map_file_block(&inode, 13).unwrap(), None);
    }

    #[test]
    fn rejects_legacy_pointer_past_filesystem_end() {
        const BLOCK: usize = 1024;
        let mut image = legacy_image();
        put32(&mut image, 5 * BLOCK + 256 + 0x28, 32);
        let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
        let inode = fs.load_inode(3).unwrap();
        assert_eq!(
            fs.map_file_block(&inode, 0).unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );

        let mut image = legacy_image();
        put32(&mut image, 5 * BLOCK + 256 + 0x28 + 12 * 4, 32);
        let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
        let inode = fs.load_inode(3).unwrap();
        assert_eq!(
            fs.map_file_block(&inode, 12).unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );

        let pointers = (BLOCK / 4) as u64;
        let past_capacity = 12 + pointers + pointers * pointers + pointers * pointers * pointers;
        assert_eq!(
            fs.map_file_block(&inode, past_capacity).unwrap_err(),
            Error::Corrupt(Corrupt::InvalidLegacyBlockMap)
        );
    }

    #[test]
    fn committed_journal_data_is_a_read_overlay() {
        let original = journal_image(true, false);
        let mut fs = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
        let mut output = [0; 5];
        assert_eq!(fs.read("/hello", 0, &mut output).unwrap(), 5);
        assert_eq!(&output, b"new!!");
        assert_eq!(fs.recovered_blocks(), 1);
        assert_eq!(fs.into_storage().durable_bytes(), original);
    }

    #[test]
    fn incomplete_transaction_never_becomes_visible() {
        let mut fs = Ext4::mount(ModelStorage::new(journal_image(false, false))).unwrap();
        let mut output = [0; 5];
        fs.read("/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"hello");
        assert_eq!(fs.recovered_blocks(), 0);
    }

    #[test]
    fn later_committed_revoke_suppresses_replay() {
        let mut fs = Ext4::mount(ModelStorage::new(journal_image(true, true))).unwrap();
        let mut output = [0; 5];
        fs.read("/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"hello");
        assert_eq!(fs.recovered_blocks(), 0);
    }

    #[test]
    fn checksum_v3_validates_super_descriptor_data_and_commit() {
        let image = checksummed_journal_image();
        let mut fs = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
        let mut output = [0; 5];
        fs.read("/hello", 0, &mut output).unwrap();
        assert_eq!(&output, b"new!!");

        for offset in [
            20 * 1024 + 0x18,
            21 * 1024 + 40,
            22 * 1024 + 8,
            23 * 1024 + 24,
        ] {
            let mut corrupt = image.clone();
            corrupt[offset] ^= 1;
            assert!(matches!(
                Ext4::mount(ModelStorage::new(corrupt)),
                Err(Error::Corrupt(Corrupt::JournalChecksum))
            ));
        }
    }

    #[test]
    fn every_journal_read_effect_can_fail_cleanly() {
        let image = journal_image(true, false);
        let successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
        let effects = successful.storage().effects().len();
        assert!(effects >= 8);
        for sequence in 0..effects {
            assert!(matches!(
                Ext4::mount(
                    ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence))
                ),
                Err(Error::Storage(ModelError::InjectedIo))
            ));
        }
    }

    #[test]
    fn every_read_effect_can_fail_cleanly() {
        let mut successful = Ext4::mount(ModelStorage::new(image())).unwrap();
        let mut output = [0; 5];
        successful.read("/hello", 0, &mut output).unwrap();
        let effects = successful.storage().effects().len();
        assert!(effects >= 6);

        for sequence in 0..effects {
            let storage = ModelStorage::new(image()).with_injection(Inject::IoErrorAt(sequence));
            match Ext4::mount(storage) {
                Err(Error::Storage(ModelError::InjectedIo)) => {}
                Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
                Ok(mut fs) => {
                    let error = fs.read("/hello", 0, &mut output).unwrap_err();
                    assert_eq!(error, Error::Storage(ModelError::InjectedIo));
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
        let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
        let effects_before = fs.storage().effects().len();
        {
            let mut transaction = fs.begin_transaction();
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

        assert_eq!(fs.storage().effects().len(), effects_before);
        assert!(
            fs.storage()
                .effects()
                .iter()
                .all(|effect| effect.kind != EffectKind::Write)
        );
        let mut contents = [0; 5];
        fs.read("/hello", 0, &mut contents).unwrap();
        assert_eq!(&contents, b"hello");
    }

    #[test]
    fn transaction_modify_loads_once_and_reads_its_own_write() {
        const BLOCK: usize = 1024;
        let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
        let effects_before = fs.storage().effects().len();
        {
            let mut transaction = fs.begin_transaction();
            transaction.reserve_blocks(1).unwrap();
            transaction
                .modify_block(11, |block| block[..5].copy_from_slice(b"new!!"))
                .unwrap();
            let mut contents = vec![0; BLOCK];
            transaction.read_block(11, &mut contents).unwrap();
            assert_eq!(&contents[..5], b"new!!");
        }
        assert_eq!(fs.storage().effects().len(), effects_before + 1);
        assert_eq!(
            fs.storage().effects().last().unwrap().kind,
            EffectKind::Read
        );
    }

    #[test]
    fn transaction_enforces_reservations_and_block_bounds() {
        const BLOCK: usize = 1024;
        let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
        let mut transaction = fs.begin_transaction();
        let block = vec![0; BLOCK];
        assert_eq!(
            transaction.write_block(11, &block).unwrap_err(),
            Error::ReservationExhausted
        );
        assert_eq!(
            transaction.read_block(32, &mut [0; BLOCK]).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            transaction.write_block(11, &[0; 4]).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(transaction.dirty_blocks(), 0);
    }

    #[test]
    fn failed_transaction_load_returns_its_reserved_buffer() {
        let successful = Ext4::mount(ModelStorage::new(image())).unwrap();
        let next_effect = successful.storage().effects().len();
        drop(successful);

        let storage = ModelStorage::new(image()).with_injection(Inject::IoErrorAt(next_effect));
        let mut fs = Ext4::mount(storage).unwrap();
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(1).unwrap();
        assert_eq!(
            transaction.modify_block(11, |_| {}).unwrap_err(),
            Error::Storage(ModelError::InjectedIo)
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
        assert_eq!(
            Ext4::mount(ModelStorage::new(image)).err(),
            Some(Error::Corrupt(Corrupt::SuperblockChecksum)),
        );
    }
}
