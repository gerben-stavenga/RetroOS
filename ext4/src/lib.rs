//! Portable, synchronous ext4 graph storage.
//!
//! Persistent effects cross [`Storage`]. The graph engine models inode-backed
//! byte blobs and labelled edges; policy such as paths and POSIX files belongs
//! to its caller. [`BlockOverlay`] and [`GraphJournal`] provide atomic JBD2
//! persistence without a second filesystem implementation.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod checksum;
pub mod ext4;
mod filesystem;
mod journal;
mod overlay;
mod storage;
pub mod test_support;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::fmt;

pub use filesystem::Filesystem;
pub use journal::GraphJournal;
pub use overlay::BlockOverlay;
pub use storage::{Storage, StorageError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Corrupt {
    BadMagic,
    InvalidBlockSize,
    InvalidGeometry,
    AddressOverflow,
    SuperblockChecksum,
    DirectoryChecksum(u32),
    ExtentChecksum(u32),
    FilesystemPastEnd,
    ReadPastEnd,
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
    InvalidJournal,
    JournalChecksum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Unsupported {
    ExternalJournal,
    JournalFeatures,
    JournalWriteProfile,
    MutationProfile,
    ExtentMutation,
    InlineData,
}

pub enum Error {
    Storage(StorageError),
    Corrupt(Corrupt),
    Unsupported(Unsupported),
    OutOfMemory,
    NotFound,
    NotDirectory,
    InvalidArgument,
    AlreadyExists,
    NotEmpty,
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
            Self::AlreadyExists => f.write_str("AlreadyExists"),
            Self::NotEmpty => f.write_str("NotEmpty"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(_) => f.write_str("storage error"),
            Self::Corrupt(error) => write!(f, "corrupt ext filesystem: {error:?}"),
            Self::Unsupported(error) => write!(f, "unsupported ext feature: {error:?}"),
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::NotFound => f.write_str("object not found"),
            Self::NotDirectory => f.write_str("object is not a node"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::AlreadyExists => f.write_str("edge already exists"),
            Self::NotEmpty => f.write_str("node not empty"),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsError {
    OutOfMemory,
    InvalidArgument,
}

pub(crate) struct BlockEdit {
    pub(crate) number: u64,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn apply_block_edits(
    blocks: &[BlockEdit],
    block_size: u64,
    offset: u64,
    output: &mut [u8],
) {
    if output.is_empty() {
        return;
    }
    let end = offset.saturating_add(output.len() as u64);
    for number in offset / block_size..=(end - 1) / block_size {
        let Ok(index) = blocks.binary_search_by_key(&number, |block| block.number) else {
            continue;
        };
        let block_start = number.saturating_mul(block_size);
        let start = offset.max(block_start);
        let stop = end.min(block_start.saturating_add(block_size));
        let destination = (start - offset) as usize;
        let source = (start - block_start) as usize;
        let length = (stop - start) as usize;
        output[destination..destination + length]
            .copy_from_slice(&blocks[index].bytes[source..source + length]);
    }
}

pub(crate) fn try_push<T>(values: &mut Vec<T>, value: T) -> Result<(), Error> {
    values.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
    values.push(value);
    Ok(())
}

pub(crate) fn try_insert<T>(values: &mut Vec<T>, index: usize, value: T) -> Result<(), Error> {
    values.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
    values.insert(index, value);
    Ok(())
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
