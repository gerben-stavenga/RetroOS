//! Typed ext4 extended-attribute tables and external blocks.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{Corrupt, Error, copy_bytes, try_push, zeroed_bytes};
use alloc::vec::Vec;

pub(crate) const MAGIC: u32 = 0xea02_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum XattrValue {
    Inline { offset: u16, bytes: Vec<u8> },
    Inode { number: u32, size: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XattrEntry {
    pub(crate) namespace: u8,
    pub(crate) name: Vec<u8>,
    pub(crate) value: XattrValue,
    pub(crate) hash: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XattrTable {
    pub(crate) entries: Vec<XattrEntry>,
    entry_offset: usize,
    value_base: usize,
    storage_size: usize,
}

impl XattrTable {
    #[inline(never)]
    pub(crate) fn decode(
        inode: u32,
        bytes: &[u8],
        entry_offset: usize,
        value_base: usize,
    ) -> Result<Self, Error> {
        let table_end = table_end(bytes, entry_offset, inode)?;
        let mut entries = Vec::new();
        let mut cursor = entry_offset;
        while cursor < table_end - 4 {
            let name_len = usize::from(bytes[cursor]);
            let entry_len = aligned_entry_size(name_len, inode)?;
            let next = cursor
                .checked_add(entry_len)
                .filter(|end| *end <= bytes.len())
                .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
            let value_inode = le32(bytes, cursor + 4);
            let value_size = usize::try_from(le32(bytes, cursor + 8))
                .map_err(|_| Corrupt::InvalidExtendedAttributes(inode))?;
            let value = if value_inode == 0 {
                let relative = le16(bytes, cursor + 2);
                let offset = value_base
                    .checked_add(usize::from(relative))
                    .filter(|offset| {
                        (value_size == 0 || *offset >= table_end)
                            && offset
                                .checked_add(value_size)
                                .is_some_and(|end| end <= bytes.len())
                    })
                    .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
                XattrValue::Inline {
                    offset: relative,
                    bytes: copy_bytes(&bytes[offset..offset + value_size])?,
                }
            } else {
                XattrValue::Inode {
                    number: value_inode,
                    size: value_size,
                }
            };
            try_push(
                &mut entries,
                XattrEntry {
                    namespace: bytes[cursor + 1],
                    name: copy_bytes(&bytes[cursor + 16..cursor + 16 + name_len])?,
                    value,
                    hash: le32(bytes, cursor + 12),
                },
            )?;
            cursor = next;
        }
        Ok(Self {
            entries,
            entry_offset,
            value_base,
            storage_size: bytes.len(),
        })
    }

    pub(crate) fn find(&self, namespace: u8, name: &[u8]) -> Option<&XattrEntry> {
        self.entries
            .iter()
            .find(|entry| entry.namespace == namespace && entry.name == name)
    }

    pub(crate) fn encode_into(&self, bytes: &mut [u8], inode: u32) -> Result<(), Error> {
        if bytes.len() != self.storage_size {
            return Err(Corrupt::InvalidExtendedAttributes(inode).into());
        }
        let mut cursor = self.entry_offset;
        for entry in &self.entries {
            let entry_len = aligned_entry_size(entry.name.len(), inode)?;
            let next = cursor
                .checked_add(entry_len)
                .filter(|end| end.checked_add(4).is_some_and(|end| end <= bytes.len()))
                .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
            bytes[cursor] = u8::try_from(entry.name.len())
                .map_err(|_| Corrupt::InvalidExtendedAttributes(inode))?;
            bytes[cursor + 1] = entry.namespace;
            put_le32(bytes, cursor + 12, entry.hash);
            match &entry.value {
                XattrValue::Inline {
                    offset,
                    bytes: value,
                } => {
                    put_le32(bytes, cursor + 8, value.len() as u32);
                    put_le16(bytes, cursor + 2, *offset);
                    let at = self
                        .value_base
                        .checked_add(usize::from(*offset))
                        .filter(|at| {
                            at.checked_add(value.len())
                                .is_some_and(|end| end <= bytes.len())
                        })
                        .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
                    bytes[at..at + value.len()].copy_from_slice(value);
                }
                XattrValue::Inode { number, size } => {
                    put_le32(bytes, cursor + 4, *number);
                    put_le32(bytes, cursor + 8, *size as u32);
                }
            }
            bytes[cursor + 16..cursor + 16 + entry.name.len()].copy_from_slice(&entry.name);
            cursor = next;
        }
        put_le32(bytes, cursor, 0);
        Ok(())
    }
}

/// One complete block-resident xattr object. The entry table and values are
/// typed; `references` is the only field unlink needs to mutate.
pub(crate) struct ExternalXattrBlock {
    pub(crate) references: u32,
    blocks: u32,
    hash: u32,
    reserved: [u32; 3],
    pub(crate) table: XattrTable,
}

impl ExternalXattrBlock {
    #[inline(never)]
    pub(crate) fn decode(
        bytes: &[u8],
        inode: u32,
        number: u64,
        checksum_seed: u32,
        metadata_checksums: bool,
    ) -> Result<Self, Error> {
        if bytes.len() < 32
            || le32(bytes, 0) != MAGIC
            || le32(bytes, 4) == 0
            || le32(bytes, 8) != 1
            || bytes[0x14..0x20].iter().any(|byte| *byte != 0)
        {
            return Err(Corrupt::InvalidExtendedAttributes(inode).into());
        }
        if metadata_checksums && checksum(checksum_seed, number, bytes) != le32(bytes, 0x10) {
            return Err(Corrupt::ExtendedAttributeChecksum(number).into());
        }
        Ok(Self {
            references: le32(bytes, 4),
            blocks: le32(bytes, 8),
            hash: le32(bytes, 0x0c),
            reserved: [le32(bytes, 0x14), le32(bytes, 0x18), le32(bytes, 0x1c)],
            table: XattrTable::decode(inode, bytes, 32, 0)?,
        })
    }

    #[inline(never)]
    pub(crate) fn encode(
        &self,
        number: u64,
        checksum_seed: u32,
        metadata_checksums: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = zeroed_bytes(self.table.storage_size)?;
        put_le32(&mut bytes, 0, MAGIC);
        put_le32(&mut bytes, 4, self.references);
        put_le32(&mut bytes, 8, self.blocks);
        put_le32(&mut bytes, 0x0c, self.hash);
        for (index, value) in self.reserved.iter().enumerate() {
            put_le32(&mut bytes, 0x14 + index * 4, *value);
        }
        self.table.encode_into(&mut bytes, 0)?;
        if metadata_checksums {
            let value = checksum(checksum_seed, number, &bytes);
            put_le32(&mut bytes, 0x10, value);
        }
        Ok(bytes)
    }
}

fn aligned_entry_size(name_len: usize, inode: u32) -> Result<usize, Error> {
    16usize
        .checked_add(name_len)
        .and_then(|size| size.checked_add(3))
        .map(|size| size & !3)
        .ok_or_else(|| Corrupt::InvalidExtendedAttributes(inode).into())
}

fn table_end(bytes: &[u8], entries: usize, inode: u32) -> Result<usize, Error> {
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
        cursor = cursor
            .checked_add(aligned_entry_size(usize::from(bytes[cursor]), inode)?)
            .filter(|end| *end <= bytes.len())
            .ok_or(Corrupt::InvalidExtendedAttributes(inode))?;
    }
}

fn checksum(seed: u32, number: u64, bytes: &[u8]) -> u32 {
    let mut checksum = Checksum::with_seed(seed);
    checksum.update(&number.to_le_bytes());
    checksum.update(&bytes[..0x10]);
    checksum.update(&[0; 4]);
    checksum.update(&bytes[0x14..]);
    checksum.finalize()
}
