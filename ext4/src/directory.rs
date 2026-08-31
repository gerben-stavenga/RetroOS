//! Checked access to ext4 directory blocks and records.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{Corrupt, DIRECTORY_INDEX_FL, Error, Inode, Unsupported, copy_bytes, try_push};
use alloc::vec::Vec;

pub(crate) fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
        && !name.contains(&0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockKind {
    Leaf,
    Root,
    Internal,
}

pub(crate) struct Record<'a> {
    pub(crate) offset: usize,
    pub(crate) next: usize,
    pub(crate) inode: u32,
    pub(crate) file_type: u8,
    pub(crate) name: &'a [u8],
}

#[inline(never)]
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
        offset: cursor,
        next,
        inode: le32(bytes, cursor),
        file_type: bytes[cursor + 7],
        name: &bytes[cursor + 8..cursor + 8 + name_len],
    })
}

pub(crate) struct Records<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

struct DirectoryRecord {
    inode: u32,
    file_type: u8,
    name: Vec<u8>,
    record_len: usize,
    padding: Vec<u8>,
}

struct DirectoryLeaf {
    records: Vec<DirectoryRecord>,
    checksum_tail: bool,
}

struct HTreeEntry {
    hash: u32,
    block: u32,
}

struct HTreeIndex {
    limit: u16,
    count: u16,
    entries: Vec<HTreeEntry>,
    padding: Vec<u8>,
    tail_reserved: Option<u32>,
}

struct HTreeRoot {
    dot_inode: u32,
    parent_inode: u32,
    hash_version: u8,
    info_length: u8,
    indirect_levels: u8,
    flags: u8,
    index: HTreeIndex,
}

struct HTreeNode {
    index: HTreeIndex,
}

enum DirectoryData {
    Leaf(DirectoryLeaf),
    Root(HTreeRoot),
    Internal(HTreeNode),
}

pub(crate) struct LeafRecords<'a> {
    records: &'a [DirectoryRecord],
    index: usize,
    offset: usize,
}

impl<'a> Iterator for LeafRecords<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.records.get(self.index)?;
        let offset = self.offset;
        self.offset += entry.record_len;
        self.index += 1;
        Some(Record {
            offset,
            next: self.offset,
            inode: entry.inode,
            file_type: entry.file_type,
            name: &entry.name,
        })
    }
}

pub(crate) fn records(bytes: &[u8]) -> Records<'_> {
    Records { bytes, cursor: 0 }
}

impl<'a> Records<'a> {
    #[inline(never)]
    pub(crate) fn next(&mut self) -> Result<Option<Record<'a>>, Error> {
        if self.cursor == self.bytes.len() {
            return Ok(None);
        }
        let entry = record(self.bytes, self.cursor)?;
        self.cursor = entry.next;
        Ok(Some(entry))
    }
}

/// A validated view of one directory block.
pub(crate) struct DirectoryBlock {
    checksum_seed: u32,
    inode: u32,
    generation: u32,
    pub(crate) kind: BlockKind,
    pub(crate) logical: u64,
    block_size: usize,
    data: DirectoryData,
}

impl DirectoryRecord {
    fn decode(bytes: &[u8], cursor: usize) -> Result<Self, Error> {
        let view = record(bytes, cursor)?;
        let name = copy_bytes(view.name)?;
        let padding = copy_bytes(&bytes[cursor + 8 + name.len()..view.next])?;
        Ok(Self {
            inode: view.inode,
            file_type: view.file_type,
            name,
            record_len: view.next - cursor,
            padding,
        })
    }

    fn minimum_len(&self) -> usize {
        (8 + self.name.len() + 3) & !3
    }

    fn encode(&self, bytes: &mut [u8], at: usize) {
        put_le32(bytes, at, self.inode);
        put_le16(bytes, at + 4, self.record_len as u16);
        bytes[at + 6] = self.name.len() as u8;
        bytes[at + 7] = self.file_type;
        bytes[at + 8..at + 8 + self.name.len()].copy_from_slice(&self.name);
        let padding = &mut bytes[at + 8 + self.name.len()..at + self.record_len];
        padding.fill(0);
        let amount = padding.len().min(self.padding.len());
        padding[..amount].copy_from_slice(&self.padding[..amount]);
    }
}

impl HTreeIndex {
    fn decode(bytes: &[u8], at: usize, checksummed: bool) -> Result<Self, Error> {
        let tail = bytes.len() - usize::from(checksummed) * 8;
        if at + 8 > tail {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let limit = le16(bytes, at);
        let count = le16(bytes, at + 2);
        if count == 0 || count > limit {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let end = at
            .checked_add(usize::from(limit) * 8)
            .filter(|end| *end <= tail)
            .ok_or(Corrupt::InvalidDirectory)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(usize::from(limit))
            .map_err(|_| Error::OutOfMemory)?;
        entries.push(HTreeEntry {
            hash: 0,
            block: le32(bytes, at + 4),
        });
        for slot in 1..usize::from(limit) {
            entries.push(HTreeEntry {
                hash: le32(bytes, at + slot * 8),
                block: le32(bytes, at + slot * 8 + 4),
            });
        }
        Ok(Self {
            limit,
            count,
            entries,
            padding: copy_bytes(&bytes[end..tail])?,
            tail_reserved: checksummed.then(|| le32(bytes, tail)),
        })
    }

    fn encode(&self, bytes: &mut [u8], at: usize) {
        put_le16(bytes, at, self.limit);
        put_le16(bytes, at + 2, self.count);
        put_le32(bytes, at + 4, self.entries[0].block);
        for (slot, entry) in self.entries.iter().enumerate().skip(1) {
            put_le32(bytes, at + slot * 8, entry.hash);
            put_le32(bytes, at + slot * 8 + 4, entry.block);
        }
        let end = at + usize::from(self.limit) * 8;
        bytes[end..end + self.padding.len()].copy_from_slice(&self.padding);
        if let Some(reserved) = self.tail_reserved {
            let tail = bytes.len() - 8;
            put_le32(bytes, tail, reserved);
            put_le32(bytes, tail + 4, 0);
        }
    }
}

impl DirectoryBlock {
    pub(crate) fn initialize(
        checksum_seed: u32,
        inode: u32,
        generation: u32,
        logical: u64,
        parent: Option<u32>,
        bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        let records_end = bytes
            .len()
            .checked_sub(12)
            .filter(|end| *end >= if parent.is_some() { 24 } else { 8 })
            .filter(|end| *end <= usize::from(u16::MAX))
            .ok_or(Corrupt::InvalidDirectory)?;
        let mut records = Vec::new();
        if let Some(parent) = parent {
            try_push(&mut records, Self::new_record(inode, 12, b".", 2)?)?;
            try_push(
                &mut records,
                Self::new_record(parent, records_end - 12, b"..", 2)?,
            )?;
        } else {
            try_push(&mut records, Self::new_record(0, records_end, b"", 0)?)?;
        }
        Ok(Self {
            checksum_seed,
            inode,
            generation,
            kind: BlockKind::Leaf,
            logical,
            block_size: bytes.len(),
            data: DirectoryData::Leaf(DirectoryLeaf {
                records,
                checksum_tail: true,
            }),
        })
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
        if metadata_checksums {
            verify_directory_checksum(
                checksum_seed,
                directory.number,
                directory.generation,
                kind,
                &bytes,
            )?;
        }
        let data = match kind {
            BlockKind::Leaf => {
                let end = bytes.len() - usize::from(metadata_checksums) * 12;
                let mut entries = Vec::new();
                let mut cursor = 0;
                while cursor < end {
                    let entry = DirectoryRecord::decode(&bytes[..end], cursor)?;
                    cursor += entry.record_len;
                    try_push(&mut entries, entry)?;
                }
                DirectoryData::Leaf(DirectoryLeaf {
                    records: entries,
                    checksum_tail: metadata_checksums,
                })
            }
            BlockKind::Root => {
                if bytes.len() < 40
                    || le32(&bytes, 0) != directory.number
                    || le16(&bytes, 4) != 12
                    || bytes[6] != 1
                    || bytes[7] != 2
                    || &bytes[8..9] != b"."
                    || le16(&bytes, 16) as usize != bytes.len() - 12
                    || bytes[18] != 2
                    || bytes[19] != 2
                    || &bytes[20..22] != b".."
                    || le32(&bytes, 24) != 0
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                DirectoryData::Root(HTreeRoot {
                    dot_inode: le32(&bytes, 0),
                    parent_inode: le32(&bytes, 12),
                    hash_version: bytes[28],
                    info_length: bytes[29],
                    indirect_levels: bytes[30],
                    flags: bytes[31],
                    index: HTreeIndex::decode(&bytes, 32, metadata_checksums)?,
                })
            }
            BlockKind::Internal => {
                if le32(&bytes, 0) != 0
                    || le16(&bytes, 4) as usize != bytes.len()
                    || bytes[6] != 0
                    || bytes[7] != 0
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                DirectoryData::Internal(HTreeNode {
                    index: HTreeIndex::decode(&bytes, 8, metadata_checksums)?,
                })
            }
        };
        Ok(Self {
            checksum_seed,
            inode: directory.number,
            generation: directory.generation,
            kind,
            logical,
            block_size: bytes.len(),
            data,
        })
    }

    fn new_record(
        inode: u32,
        record_len: usize,
        name: &[u8],
        file_type: u8,
    ) -> Result<DirectoryRecord, Error> {
        Ok(DirectoryRecord {
            inode,
            file_type,
            name: copy_bytes(name)?,
            record_len,
            padding: Vec::new(),
        })
    }

    pub(crate) fn leaf_records(&self) -> Option<LeafRecords<'_>> {
        let DirectoryData::Leaf(leaf) = &self.data else {
            return None;
        };
        Some(LeafRecords {
            records: &leaf.records,
            index: 0,
            offset: 0,
        })
    }

    pub(crate) fn records_end(&self) -> usize {
        match &self.data {
            DirectoryData::Leaf(leaf) => leaf.records.iter().map(|entry| entry.record_len).sum(),
            _ => 0,
        }
    }

    pub(crate) fn find(&self, name: &[u8]) -> Result<Option<u32>, Error> {
        Ok(self.leaf_records().and_then(|mut records| {
            records
                .find(|entry| entry.inode != 0 && entry.name == name)
                .map(|entry| entry.inode)
        }))
    }

    pub(crate) fn parent(&self) -> Result<u32, Error> {
        match &self.data {
            DirectoryData::Root(root) if root.parent_inode != 0 => Ok(root.parent_inode),
            DirectoryData::Leaf(leaf) if leaf.records.len() >= 2 => {
                let dot = &leaf.records[0];
                let dotdot = &leaf.records[1];
                if dot.inode == self.inode
                    && dot.name == b"."
                    && dot.file_type == 2
                    && dotdot.inode != 0
                    && dotdot.name == b".."
                    && dotdot.file_type == 2
                {
                    Ok(dotdot.inode)
                } else {
                    Err(Corrupt::InvalidDirectory.into())
                }
            }
            _ => Err(Corrupt::InvalidDirectory.into()),
        }
    }

    pub(crate) fn insert(&mut self, inode: u32, name: &[u8], file_type: u8) -> Result<(), Error> {
        if inode == 0 || !valid_name(name) || !matches!(file_type, 1 | 2 | 7) {
            return Err(Error::InvalidArgument);
        }
        let DirectoryData::Leaf(leaf) = &mut self.data else {
            return Err(Error::InvalidArgument);
        };
        let needed = (8 + name.len() + 3) & !3;
        for index in 0..leaf.records.len() {
            let used = leaf.records[index].minimum_len();
            if leaf.records[index].inode == 0 && leaf.records[index].record_len >= needed {
                let len = leaf.records[index].record_len;
                leaf.records[index] = Self::new_record(inode, len, name, file_type)?;
                return Ok(());
            }
            if leaf.records[index].inode != 0 && leaf.records[index].record_len - used >= needed {
                let len = leaf.records[index].record_len - used;
                leaf.records[index].record_len = used;
                leaf.records[index].padding.clear();
                leaf.records
                    .try_reserve(1)
                    .map_err(|_| Error::OutOfMemory)?;
                leaf.records
                    .insert(index + 1, Self::new_record(inode, len, name, file_type)?);
                return Ok(());
            }
        }
        Err(Unsupported::ExtentMutation.into())
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
        let DirectoryData::Leaf(leaf) = &mut self.data else {
            return Err(Error::InvalidArgument);
        };
        let index = leaf
            .records
            .iter()
            .position(|entry| entry.inode != 0 && entry.name == name)
            .ok_or(Error::NotFound)?;
        if leaf.records[index].inode != expected {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if let Some((inode, file_type)) = replacement {
            leaf.records[index].inode = inode;
            leaf.records[index].file_type = file_type;
        } else if index != 0 {
            let removed = leaf.records.remove(index);
            let previous = &mut leaf.records[index - 1];
            previous.record_len += removed.record_len;
            let padding = previous.record_len - 8 - previous.name.len();
            previous.padding.resize(padding, 0);
        } else {
            let len = leaf.records[0].record_len;
            leaf.records[0] = Self::new_record(0, len, b"", 0)?;
        }
        Ok(())
    }

    pub(crate) fn replace_parent(&mut self, old: u32, new: u32) -> Result<(), Error> {
        if new == 0 || self.parent()? != old {
            return Err(Corrupt::InvalidDirectory.into());
        }
        match &mut self.data {
            DirectoryData::Root(root) => root.parent_inode = new,
            DirectoryData::Leaf(leaf) => leaf.records[1].inode = new,
            _ => return Err(Corrupt::InvalidDirectory.into()),
        }
        Ok(())
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, Error> {
        let mut bytes = crate::zeroed_bytes(self.block_size)?;
        let checksummed = match &self.data {
            DirectoryData::Leaf(leaf) => leaf.checksum_tail,
            DirectoryData::Root(root) => root.index.tail_reserved.is_some(),
            DirectoryData::Internal(node) => node.index.tail_reserved.is_some(),
        };
        match &self.data {
            DirectoryData::Leaf(leaf) => {
                let mut at = 0;
                for entry in &leaf.records {
                    entry.encode(&mut bytes, at);
                    at += entry.record_len;
                }
                if leaf.checksum_tail {
                    put_le16(&mut bytes, at + 4, 12);
                    bytes[at + 7] = 0xde;
                }
            }
            DirectoryData::Root(root) => {
                write_fixed_entry(&mut bytes, 0, root.dot_inode, 12, b".", 2);
                write_fixed_entry(
                    &mut bytes,
                    12,
                    root.parent_inode,
                    self.block_size - 12,
                    b"..",
                    2,
                );
                bytes[28] = root.hash_version;
                bytes[29] = root.info_length;
                bytes[30] = root.indirect_levels;
                bytes[31] = root.flags;
                root.index.encode(&mut bytes, 32);
            }
            DirectoryData::Internal(node) => {
                put_le16(&mut bytes, 4, self.block_size as u16);
                node.index.encode(&mut bytes, 8);
            }
        }
        if checksummed {
            write_directory_checksum(
                self.checksum_seed,
                self.inode,
                self.generation,
                self.kind,
                &mut bytes,
            )?;
        }
        Ok(bytes)
    }
}

fn checksum_field(kind: BlockKind, bytes: &[u8]) -> Result<(usize, usize), Error> {
    match kind {
        BlockKind::Leaf => {
            let tail = bytes
                .len()
                .checked_sub(12)
                .ok_or(Corrupt::InvalidDirectory)?;
            if le32(bytes, tail) != 0
                || le16(bytes, tail + 4) != 12
                || bytes[tail + 6] != 0
                || bytes[tail + 7] != 0xde
            {
                return Err(Corrupt::InvalidDirectory.into());
            }
            Ok((tail + 8, tail))
        }
        BlockKind::Root | BlockKind::Internal => {
            let tail = bytes
                .len()
                .checked_sub(8)
                .ok_or(Corrupt::InvalidDirectory)?;
            let at = if kind == BlockKind::Root { 32 } else { 8 };
            let hashed = at + usize::from(le16(bytes, at + 2)) * 8;
            if hashed > tail {
                return Err(Corrupt::InvalidDirectory.into());
            }
            Ok((tail + 4, hashed))
        }
    }
}

fn directory_checksum(
    seed: u32,
    inode: u32,
    generation: u32,
    kind: BlockKind,
    bytes: &[u8],
) -> Result<u32, Error> {
    let (field, hashed) = checksum_field(kind, bytes)?;
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(inode);
    checksum.update_u32_le(generation);
    checksum.update(&bytes[..hashed]);
    if kind != BlockKind::Leaf {
        checksum.update_u32_le(le32(bytes, field - 4));
        checksum.update_u32_le(0);
    }
    Ok(checksum.finalize())
}

fn verify_directory_checksum(
    seed: u32,
    inode: u32,
    generation: u32,
    kind: BlockKind,
    bytes: &[u8],
) -> Result<(), Error> {
    let (field, _) = checksum_field(kind, bytes)?;
    if le32(bytes, field) != directory_checksum(seed, inode, generation, kind, bytes)? {
        return Err(Corrupt::DirectoryChecksum(inode).into());
    }
    Ok(())
}

fn write_directory_checksum(
    seed: u32,
    inode: u32,
    generation: u32,
    kind: BlockKind,
    bytes: &mut [u8],
) -> Result<(), Error> {
    let (field, _) = checksum_field(kind, bytes)?;
    let checksum = directory_checksum(seed, inode, generation, kind, bytes)?;
    put_le32(bytes, field, checksum);
    Ok(())
}

fn write_fixed_entry(bytes: &mut [u8], at: usize, inode: u32, len: usize, name: &[u8], kind: u8) {
    put_le32(bytes, at, inode);
    put_le16(bytes, at + 4, len as u16);
    bytes[at + 6] = name.len() as u8;
    bytes[at + 7] = kind;
    bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
}
