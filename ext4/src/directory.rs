//! Checked access to ext4 directory blocks and records.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{Corrupt, DIRECTORY_INDEX_FL, Error, Inode, Unsupported};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockKind {
    Leaf,
    Root,
    Internal,
}

pub(crate) struct Record<'a> {
    pub(crate) next: usize,
    pub(crate) inode: u32,
    pub(crate) file_type: u8,
    pub(crate) name: &'a [u8],
}

pub(crate) fn record(bytes: &[u8], cursor: usize) -> Result<Record<'_>, Error> {
    if bytes.len().saturating_sub(cursor) < 8 {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let record_len = usize::from(le16(bytes, cursor + 4));
    let name_len = usize::from(bytes[cursor + 6]);
    let next = cursor
        .checked_add(record_len)
        .filter(|next| {
            record_len >= 8
                && record_len.is_multiple_of(4)
                && *next <= bytes.len()
                && name_len <= record_len - 8
        })
        .ok_or(Corrupt::InvalidDirectory)?;
    Ok(Record {
        next,
        inode: le32(bytes, cursor),
        file_type: bytes[cursor + 7],
        name: &bytes[cursor + 8..cursor + 8 + name_len],
    })
}

/// A validated view of one directory block.
pub(crate) struct DirectoryBlock {
    checksum_seed: u32,
    inode: u32,
    generation: u32,
    pub(crate) kind: BlockKind,
    pub(crate) logical: u64,
    pub(crate) records_end: usize,
    pub(crate) bytes: Vec<u8>,
}

impl DirectoryBlock {
    pub(crate) fn initialize(
        checksum_seed: u32,
        inode: u32,
        generation: u32,
        logical: u64,
        parent: Option<u32>,
        mut bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        let tail = bytes
            .len()
            .checked_sub(12)
            .filter(|tail| *tail >= if parent.is_some() { 24 } else { 8 })
            .filter(|tail| *tail <= usize::from(u16::MAX))
            .ok_or(Corrupt::InvalidDirectory)?;
        bytes.fill(0);
        if let Some(parent) = parent {
            write_entry(&mut bytes, 0, inode, 12, b".", 2);
            write_entry(&mut bytes, 12, parent, tail - 12, b"..", 2);
        } else {
            put_le16(&mut bytes, 4, tail as u16);
        }
        put_le16(&mut bytes, tail + 4, 12);
        bytes[tail + 7] = 0xde;
        let mut block = Self {
            checksum_seed,
            inode,
            generation,
            kind: BlockKind::Leaf,
            logical,
            records_end: tail,
            bytes,
        };
        block.update_checksum()?;
        Ok(block)
    }

    pub(crate) fn new(
        checksum_seed: u32,
        metadata_checksums: bool,
        directory: &Inode,
        logical: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        let kind = if directory.flags & DIRECTORY_INDEX_FL == 0 {
            BlockKind::Leaf
        } else if logical == 0 {
            BlockKind::Root
        } else if bytes.len() >= 8 && usize::from(le16(&bytes, 4)) == bytes.len() {
            BlockKind::Internal
        } else {
            BlockKind::Leaf
        };
        let records_end = match (kind, metadata_checksums) {
            (BlockKind::Leaf, true) => bytes
                .len()
                .checked_sub(12)
                .ok_or(Corrupt::InvalidDirectory)?,
            (BlockKind::Leaf, false) => bytes.len(),
            _ => 0,
        };
        let block = Self {
            checksum_seed,
            inode: directory.number,
            generation: directory.generation,
            kind,
            logical,
            records_end,
            bytes,
        };
        if metadata_checksums {
            block.verify_checksum()?;
        }
        Ok(block)
    }

    pub(crate) fn find(&self, name: &[u8]) -> Result<Option<u32>, Error> {
        if self.kind != BlockKind::Leaf {
            return Ok(None);
        }
        let mut cursor = 0;
        while cursor < self.records_end {
            let entry = record(&self.bytes[..self.records_end], cursor)?;
            if entry.inode != 0 && entry.name == name {
                return Ok(Some(entry.inode));
            }
            cursor = entry.next;
        }
        Ok(None)
    }

    pub(crate) fn parent(&self) -> Result<u32, Error> {
        self.parent_field().map(|(_, inode)| inode)
    }

    fn parent_field(&self) -> Result<(usize, u32), Error> {
        match self.kind {
            BlockKind::Leaf => {
                let dot = record(&self.bytes[..self.records_end], 0)?;
                if dot.inode != self.inode
                    || dot.file_type != 2
                    || dot.name != b"."
                    || dot.next < 12
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let dotdot = record(&self.bytes[..self.records_end], dot.next)?;
                if dotdot.inode == 0
                    || dotdot.file_type != 2
                    || dotdot.name != b".."
                    || dotdot.next - dot.next < 12
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                Ok((dot.next, dotdot.inode))
            }
            BlockKind::Root => {
                if self.bytes.len() < 24
                    || le16(&self.bytes, 16) < 12
                    || self.bytes[18] != 2
                    || &self.bytes[20..22] != b".."
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let parent = le32(&self.bytes, 12);
                if parent == 0 {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                Ok((12, parent))
            }
            BlockKind::Internal => Err(Corrupt::InvalidDirectory.into()),
        }
    }

    pub(crate) fn insert(&mut self, inode: u32, name: &[u8], file_type: u8) -> Result<(), Error> {
        if self.kind != BlockKind::Leaf
            || inode == 0
            || name.is_empty()
            || name.len() > 255
            || !matches!(file_type, 1 | 2 | 7)
        {
            return Err(Error::InvalidArgument);
        }
        let needed = (8 + name.len() + 3) & !3;
        let mut cursor = 0;
        let mut insertion = None;
        while cursor < self.records_end {
            let entry = record(&self.bytes[..self.records_end], cursor)?;
            let record_len = entry.next - cursor;
            if insertion.is_none() {
                if entry.inode == 0 && record_len >= needed {
                    insertion = Some((cursor, record_len, None));
                } else if entry.inode != 0 {
                    let used = (8 + entry.name.len() + 3) & !3;
                    if record_len - used >= needed {
                        insertion = Some((cursor + used, record_len - used, Some((cursor, used))));
                    }
                }
            }
            cursor = entry.next;
        }
        let (at, record_len, split_previous) = insertion.ok_or(Unsupported::ExtentMutation)?;
        if let Some((previous, previous_len)) = split_previous {
            put_le16(&mut self.bytes, previous + 4, previous_len as u16);
        }
        self.bytes[at..at + record_len].fill(0);
        write_entry(&mut self.bytes, at, inode, record_len, name, file_type);
        self.update_checksum()
    }

    pub(crate) fn remove(&mut self, name: &[u8], inode: u32) -> Result<(), Error> {
        self.edit(name, inode, None)
    }

    pub(crate) fn replace(
        &mut self,
        name: &[u8],
        old: u32,
        new: u32,
        file_type: u8,
    ) -> Result<(), Error> {
        if new == 0 || !matches!(file_type, 1 | 2 | 7) {
            return Err(Error::InvalidArgument);
        }
        self.edit(name, old, Some((new, file_type)))
    }

    fn edit(
        &mut self,
        name: &[u8],
        expected: u32,
        replacement: Option<(u32, u8)>,
    ) -> Result<(), Error> {
        if self.kind != BlockKind::Leaf || expected == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut cursor = 0;
        let mut previous = None;
        while cursor < self.records_end {
            let entry = record(&self.bytes[..self.records_end], cursor)?;
            let next = entry.next;
            let entry_inode = entry.inode;
            let matches = entry_inode != 0 && entry.name == name;
            if matches {
                if entry_inode != expected {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                if let Some((new, file_type)) = replacement {
                    put_le32(&mut self.bytes, cursor, new);
                    self.bytes[cursor + 7] = file_type;
                } else if let Some(previous) = previous {
                    let previous_len = usize::from(le16(&self.bytes, previous + 4));
                    let merged = previous_len
                        .checked_add(next - cursor)
                        .filter(|length| previous + *length <= self.records_end)
                        .ok_or(Corrupt::InvalidDirectory)?;
                    self.bytes[cursor..next].fill(0);
                    put_le16(&mut self.bytes, previous + 4, merged as u16);
                } else {
                    put_le32(&mut self.bytes, cursor, 0);
                    self.bytes[cursor + 6..next].fill(0);
                }
                return self.update_checksum();
            }
            previous = Some(cursor);
            cursor = next;
        }
        Err(Error::NotFound)
    }

    pub(crate) fn replace_parent(&mut self, old: u32, new: u32) -> Result<(), Error> {
        if new == 0 {
            return Err(Error::InvalidArgument);
        }
        let (offset, parent) = self.parent_field()?;
        if parent != old {
            return Err(Corrupt::InvalidDirectory.into());
        }
        put_le32(&mut self.bytes, offset, new);
        self.update_checksum()
    }

    fn verify_checksum(&self) -> Result<(), Error> {
        let (offset, checksum) = self.checksum_field()?;
        if le32(&self.bytes, offset) != checksum {
            return Err(Corrupt::DirectoryChecksum(self.inode).into());
        }
        Ok(())
    }

    fn update_checksum(&mut self) -> Result<(), Error> {
        let (offset, checksum) = self.checksum_field()?;
        put_le32(&mut self.bytes, offset, checksum);
        Ok(())
    }

    fn checksum_field(&self) -> Result<(usize, u32), Error> {
        let (offset, hashed) = match self.kind {
            BlockKind::Leaf => {
                let tail = self.records_end;
                if le32(&self.bytes, tail) != 0
                    || le16(&self.bytes, tail + 4) != 12
                    || self.bytes[tail + 6] != 0
                    || self.bytes[tail + 7] != 0xde
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                (tail + 8, tail)
            }
            BlockKind::Root | BlockKind::Internal => {
                let tail = self
                    .bytes
                    .len()
                    .checked_sub(8)
                    .ok_or(Corrupt::InvalidDirectory)?;
                (tail + 4, indexed_hashed_end(self.kind, &self.bytes, tail)?)
            }
        };
        let mut checksum = Checksum::with_seed(self.checksum_seed);
        checksum.update_u32_le(self.inode);
        checksum.update_u32_le(self.generation);
        checksum.update(&self.bytes[..hashed]);
        if self.kind != BlockKind::Leaf {
            checksum.update_u32_le(le32(&self.bytes, offset - 4));
            checksum.update_u32_le(0);
        }
        Ok((offset, checksum.finalize()))
    }
}

fn indexed_hashed_end(kind: BlockKind, bytes: &[u8], tail: usize) -> Result<usize, Error> {
    let limit_offset = match kind {
        BlockKind::Root => 0x20,
        BlockKind::Internal => 0x08,
        BlockKind::Leaf => return Err(Corrupt::InvalidDirectory.into()),
    };
    if limit_offset + 4 > tail {
        return Err(Corrupt::InvalidDirectory.into());
    }
    usize::from(le16(bytes, limit_offset + 2))
        .checked_mul(8)
        .and_then(|size| limit_offset.checked_add(size))
        .filter(|end| *end <= tail)
        .ok_or(Corrupt::InvalidDirectory.into())
}

fn write_entry(bytes: &mut [u8], at: usize, inode: u32, len: usize, name: &[u8], kind: u8) {
    put_le32(bytes, at, inode);
    put_le16(bytes, at + 4, len as u16);
    bytes[at + 6] = name.len() as u8;
    bytes[at + 7] = kind;
    bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
}
