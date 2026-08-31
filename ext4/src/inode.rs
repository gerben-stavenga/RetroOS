//! Lossless codecs for ext inode-table blocks and their records.

use crate::checksum::Checksum;
use crate::extent_tree::{Extent, ExtentRoot, ExtentState};
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::xattr::{MAGIC as XATTR_MAGIC, XattrTable};
use crate::{
    Corrupt, EXTENTS_FL, Error, Inode, InodeMetadataUpdate, InodeOsData, Timestamp, Unsupported,
    zeroed_bytes,
};
use alloc::vec::Vec;

const BASE_SIZE: usize = 128;

pub(crate) struct InodeExtra {
    storage_size: usize,
    declared_size: u16,
    checksum_high: Option<u16>,
    changed_extra: Option<u32>,
    modified_extra: Option<u32>,
    accessed_extra: Option<u32>,
    created: Option<u32>,
    created_extra: Option<u32>,
    version_high: Option<u32>,
    project_id: Option<u32>,
    unknown_fields: Vec<u8>,
    pub(crate) xattrs: Option<XattrTable>,
    body_padding: Vec<u8>,
}

impl InodeExtra {
    fn decode(bytes: &[u8], inode: u32) -> Result<Self, Error> {
        let storage_size = bytes.len().saturating_sub(BASE_SIZE);
        if storage_size == 0 {
            return Ok(Self::empty());
        }
        let declared_size = le16(bytes, BASE_SIZE);
        let size = usize::from(declared_size);
        if size > storage_size || !size.is_multiple_of(4) {
            return Err(Corrupt::InvalidInode(inode).into());
        }
        let field =
            |relative: usize| (relative + 4 <= size).then(|| le32(bytes, BASE_SIZE + relative));
        let unknown_start = BASE_SIZE + size.min(32);
        let body_start = BASE_SIZE + size;
        let mut unknown_fields = zeroed_bytes(body_start - unknown_start)?;
        unknown_fields.copy_from_slice(&bytes[unknown_start..body_start]);
        let has_xattrs = body_start
            .checked_add(4)
            .is_some_and(|end| end <= bytes.len() && le32(bytes, body_start) == XATTR_MAGIC);
        let xattrs = has_xattrs
            .then(|| XattrTable::decode(inode, bytes, body_start + 4, body_start + 4))
            .transpose()?;
        let mut body_padding = if has_xattrs {
            Vec::new()
        } else {
            zeroed_bytes(bytes.len() - body_start)?
        };
        if !has_xattrs {
            body_padding.copy_from_slice(&bytes[body_start..]);
        }
        Ok(Self {
            storage_size,
            declared_size,
            checksum_high: (size >= 4).then(|| le16(bytes, BASE_SIZE + 2)),
            changed_extra: field(4),
            modified_extra: field(8),
            accessed_extra: field(12),
            created: field(16),
            created_extra: field(20),
            version_high: field(24),
            project_id: field(28),
            unknown_fields,
            xattrs,
            body_padding,
        })
    }

    fn empty() -> Self {
        Self {
            storage_size: 0,
            declared_size: 0,
            checksum_high: None,
            changed_extra: None,
            modified_extra: None,
            accessed_extra: None,
            created: None,
            created_extra: None,
            version_high: None,
            project_id: None,
            unknown_fields: Vec::new(),
            xattrs: None,
            body_padding: Vec::new(),
        }
    }

    fn encode(&self, bytes: &mut [u8], inode: u32) -> Result<(), Error> {
        if bytes.len() != BASE_SIZE + self.storage_size {
            return Err(Corrupt::InvalidInode(inode).into());
        }
        if self.storage_size == 0 {
            return Ok(());
        }
        put_le16(bytes, BASE_SIZE, self.declared_size);
        if let Some(value) = self.checksum_high {
            put_le16(bytes, BASE_SIZE + 2, value);
        }
        for (relative, value) in [
            (4, self.changed_extra),
            (8, self.modified_extra),
            (12, self.accessed_extra),
            (16, self.created),
            (20, self.created_extra),
            (24, self.version_high),
            (28, self.project_id),
        ] {
            if let Some(value) = value {
                put_le32(bytes, BASE_SIZE + relative, value);
            }
        }
        let size = usize::from(self.declared_size);
        let unknown_start = BASE_SIZE + size.min(32);
        if self.unknown_fields.len() != BASE_SIZE + size - unknown_start {
            return Err(Corrupt::InvalidInode(inode).into());
        }
        bytes[unknown_start..BASE_SIZE + size].copy_from_slice(&self.unknown_fields);
        let body = BASE_SIZE + size;
        if let Some(xattrs) = &self.xattrs {
            put_le32(bytes, body, XATTR_MAGIC);
            xattrs.encode_into(bytes, inode)?;
        } else {
            if self.body_padding.len() != bytes.len() - body {
                return Err(Corrupt::InvalidInode(inode).into());
            }
            bytes[body..].copy_from_slice(&self.body_padding);
        }
        Ok(())
    }

    fn reset(&mut self) {
        let declared_size = if self.storage_size >= 32 { 32 } else { 0 };
        *self = Self {
            storage_size: self.storage_size,
            declared_size,
            checksum_high: (self.storage_size >= 4).then_some(0),
            changed_extra: (self.storage_size >= 8).then_some(0),
            modified_extra: (self.storage_size >= 12).then_some(0),
            accessed_extra: (self.storage_size >= 16).then_some(0),
            created: (self.storage_size >= 20).then_some(0),
            created_extra: (self.storage_size >= 24).then_some(0),
            version_high: (self.storage_size >= 28).then_some(0),
            project_id: (self.storage_size >= 32).then_some(0),
            unknown_fields: Vec::new(),
            xattrs: None,
            body_padding: alloc::vec![0; self.storage_size - usize::from(declared_size)],
        };
    }

    fn clear(&mut self) {
        *self = Self {
            storage_size: self.storage_size,
            body_padding: alloc::vec![0; self.storage_size],
            ..Self::empty()
        };
    }

    fn extra_timestamp(&self, absolute: usize) -> Option<u32> {
        match absolute {
            0x84 => self.changed_extra,
            0x88 => self.modified_extra,
            0x8c => self.accessed_extra,
            _ => None,
        }
    }

    fn set_extra_timestamp(&mut self, absolute: usize, value: u32) -> bool {
        let field = match absolute {
            0x84 => &mut self.changed_extra,
            0x88 => &mut self.modified_extra,
            0x8c => &mut self.accessed_extra,
            _ => return false,
        };
        if field.is_none() {
            return false;
        }
        *field = Some(value);
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyBlockMap {
    pub(crate) direct: [u32; 12],
    pub(crate) indirect: u32,
    pub(crate) double_indirect: u32,
    pub(crate) triple_indirect: u32,
}

impl LegacyBlockMap {
    fn decode(bytes: &[u8; 60]) -> Self {
        let mut direct = [0; 12];
        for (index, pointer) in direct.iter_mut().enumerate() {
            *pointer = le32(bytes, index * 4);
        }
        Self {
            direct,
            indirect: le32(bytes, 48),
            double_indirect: le32(bytes, 52),
            triple_indirect: le32(bytes, 56),
        }
    }

    fn encode(&self, bytes: &mut [u8; 60]) {
        for (index, pointer) in self.direct.iter().enumerate() {
            put_le32(bytes, index * 4, *pointer);
        }
        put_le32(bytes, 48, self.indirect);
        put_le32(bytes, 52, self.double_indirect);
        put_le32(bytes, 56, self.triple_indirect);
    }
}

/// The four meanings ext assigns to the inode-resident 60-byte `i_block`
/// field. Byte arrays remain only where the field itself contains file data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InodeBlockMap {
    Extents(ExtentRoot),
    Legacy(LegacyBlockMap),
    InlineData([u8; 60]),
    FastSymlink { target: Vec<u8>, padding: Vec<u8> },
}

impl InodeBlockMap {
    fn decode(
        bytes: &[u8; 60],
        mode: u16,
        flags: u32,
        size: u64,
        blocks_512: u64,
    ) -> Result<Self, Error> {
        if flags & crate::INLINE_DATA_FL != 0 {
            return Ok(Self::InlineData(*bytes));
        }
        if flags & EXTENTS_FL != 0 {
            return Ok(Self::Extents(ExtentRoot::decode(bytes)?));
        }
        if mode & 0xf000 == 0xa000 && blocks_512 == 0 && size <= 60 {
            let len = size as usize;
            let mut target = Vec::new();
            target
                .try_reserve_exact(len)
                .map_err(|_| Error::OutOfMemory)?;
            target.extend_from_slice(&bytes[..len]);
            let mut padding = Vec::new();
            padding
                .try_reserve_exact(60 - len)
                .map_err(|_| Error::OutOfMemory)?;
            padding.extend_from_slice(&bytes[len..]);
            return Ok(Self::FastSymlink { target, padding });
        }
        Ok(Self::Legacy(LegacyBlockMap::decode(bytes)))
    }

    fn encode(&self, bytes: &mut [u8; 60]) -> Result<(), Error> {
        bytes.fill(0);
        match self {
            Self::Extents(root) => root.encode(bytes),
            Self::Legacy(map) => {
                map.encode(bytes);
                Ok(())
            }
            Self::InlineData(data) => {
                bytes.copy_from_slice(data);
                Ok(())
            }
            Self::FastSymlink { target, padding } => {
                if target.len() + padding.len() != bytes.len() {
                    return Err(Error::InvalidArgument);
                }
                bytes[..target.len()].copy_from_slice(target);
                bytes[target.len()..].copy_from_slice(padding);
                Ok(())
            }
        }
    }

    pub(crate) fn extent_root(&self) -> Result<&ExtentRoot, Error> {
        match self {
            Self::Extents(root) => Ok(root),
            _ => Err(Corrupt::InvalidExtentTree.into()),
        }
    }

    pub(crate) fn legacy(&self) -> Result<&LegacyBlockMap, Error> {
        match self {
            Self::Legacy(map) => Ok(map),
            _ => Err(Corrupt::InvalidLegacyBlockMap.into()),
        }
    }

    pub(crate) fn inline_prefix(&self) -> Result<&[u8; 60], Error> {
        match self {
            Self::InlineData(data) => Ok(data),
            _ => Err(Corrupt::InvalidInode(0).into()),
        }
    }

    pub(crate) fn fast_symlink(&self) -> Option<&[u8]> {
        match self {
            Self::FastSymlink { target, .. } => Some(target),
            _ => None,
        }
    }
}

pub(crate) struct InodeBase {
    pub(crate) mode: u16,
    uid_low: u16,
    size_low: u32,
    pub(crate) accessed: u32,
    pub(crate) changed: u32,
    pub(crate) modified: u32,
    deleted: u32,
    gid_low: u16,
    pub(crate) links: u16,
    blocks_low: u32,
    pub(crate) flags: u32,
    pub(crate) os_data: InodeOsData,
    pub(crate) block_map: InodeBlockMap,
    pub(crate) generation: u32,
    external_xattr_low: u32,
    size_high: u32,
    obsolete_fragment: u32,
}

impl Default for InodeBase {
    fn default() -> Self {
        Self {
            mode: 0,
            uid_low: 0,
            size_low: 0,
            accessed: 0,
            changed: 0,
            modified: 0,
            deleted: 0,
            gid_low: 0,
            links: 0,
            blocks_low: 0,
            flags: 0,
            os_data: InodeOsData::default(),
            block_map: InodeBlockMap::Legacy(LegacyBlockMap {
                direct: [0; 12],
                indirect: 0,
                double_indirect: 0,
                triple_indirect: 0,
            }),
            generation: 0,
            external_xattr_low: 0,
            size_high: 0,
            obsolete_fragment: 0,
        }
    }
}

impl InodeBase {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mode = le16(bytes, 0);
        let size = u64::from(le32(bytes, 4)) | (u64::from(le32(bytes, 0x6c)) << 32);
        let flags = le32(bytes, 0x20);
        let blocks_512 = u64::from(le32(bytes, 0x1c)) | (u64::from(le16(bytes, 0x74)) << 32);
        let raw_block_map: [u8; 60] = bytes[0x28..0x64].try_into().unwrap();
        Ok(Self {
            mode,
            uid_low: le16(bytes, 2),
            size_low: le32(bytes, 4),
            accessed: le32(bytes, 8),
            changed: le32(bytes, 0x0c),
            modified: le32(bytes, 0x10),
            deleted: le32(bytes, 0x14),
            gid_low: le16(bytes, 0x18),
            links: le16(bytes, 0x1a),
            blocks_low: le32(bytes, 0x1c),
            flags,
            os_data: InodeOsData {
                osd1: bytes[0x24..0x28].try_into().unwrap(),
                osd2: bytes[0x74..0x80].try_into().unwrap(),
            },
            block_map: InodeBlockMap::decode(&raw_block_map, mode, flags, size, blocks_512)?,
            generation: le32(bytes, 0x64),
            external_xattr_low: le32(bytes, 0x68),
            size_high: le32(bytes, 0x6c),
            obsolete_fragment: le32(bytes, 0x70),
        })
    }

    fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        put_le16(bytes, 0, self.mode);
        put_le16(bytes, 2, self.uid_low);
        put_le32(bytes, 4, self.size_low);
        put_le32(bytes, 8, self.accessed);
        put_le32(bytes, 0x0c, self.changed);
        put_le32(bytes, 0x10, self.modified);
        put_le32(bytes, 0x14, self.deleted);
        put_le16(bytes, 0x18, self.gid_low);
        put_le16(bytes, 0x1a, self.links);
        put_le32(bytes, 0x1c, self.blocks_low);
        put_le32(bytes, 0x20, self.flags);
        bytes[0x24..0x28].copy_from_slice(&self.os_data.osd1);
        self.block_map
            .encode((&mut bytes[0x28..0x64]).try_into().unwrap())?;
        put_le32(bytes, 0x64, self.generation);
        put_le32(bytes, 0x68, self.external_xattr_low);
        put_le32(bytes, 0x6c, self.size_high);
        put_le32(bytes, 0x70, self.obsolete_fragment);
        bytes[0x74..0x80].copy_from_slice(&self.os_data.osd2);
        Ok(())
    }
}

/// One decoded inode-table element, including its typed extension fields and
/// optional inline extended-attribute table.
pub(crate) struct InodeRecord {
    pub(crate) base: InodeBase,
    pub(crate) extra: InodeExtra,
    pub(crate) checksum_seed: u32,
    pub(crate) number: u32,
}

impl InodeRecord {
    fn decode(bytes: &[u8], checksum_seed: u32, number: u32) -> Result<Self, Error> {
        if bytes.len() < BASE_SIZE || number == 0 {
            return Err(Corrupt::InvalidInode(number).into());
        }
        Ok(Self {
            base: InodeBase::decode(bytes)?,
            extra: InodeExtra::decode(bytes, number)?,
            checksum_seed,
            number,
        })
    }

    fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        self.base.encode(bytes)?;
        self.extra.encode(bytes, self.number)
    }

    pub(crate) fn verify_identity(&self, inode: &Inode) -> Result<(), Corrupt> {
        if self.number != inode.number || self.base.generation != inode.generation {
            return Err(Corrupt::InvalidInode(inode.number));
        }
        Ok(())
    }

    pub(crate) fn verify_checksum(&self) -> Result<(), Error> {
        let expected_low = le16(&self.base.os_data.osd2, 8);
        let expected_high = self.extra.checksum_high;
        let checksum = self.checksum()?;
        let valid = expected_high.map_or(checksum as u16 == expected_low, |high| {
            checksum == u32::from(expected_low) | (u32::from(high) << 16)
        });
        if !valid {
            return Err(Corrupt::InodeChecksum(self.number).into());
        }
        Ok(())
    }

    pub(crate) fn uid(&self) -> u32 {
        u32::from(self.base.uid_low) | (u32::from(le16(&self.base.os_data.osd2, 4)) << 16)
    }

    pub(crate) fn gid(&self) -> u32 {
        u32::from(self.base.gid_low) | (u32::from(le16(&self.base.os_data.osd2, 6)) << 16)
    }

    pub(crate) fn size(&self) -> u64 {
        u64::from(self.base.size_low) | (u64::from(self.base.size_high) << 32)
    }

    pub(crate) fn blocks_512(&self) -> u64 {
        u64::from(self.base.blocks_low) | (u64::from(le16(&self.base.os_data.osd2, 0)) << 32)
    }

    pub(crate) fn external_xattr_block(&self, wide: bool) -> u64 {
        u64::from(self.base.external_xattr_low)
            | if wide {
                u64::from(le16(&self.base.os_data.osd2, 2)) << 32
            } else {
                0
            }
    }

    pub(crate) fn timestamp(
        &self,
        seconds_offset: usize,
        extra_offset: usize,
    ) -> Result<Timestamp, Error> {
        let low = match seconds_offset {
            0x08 => self.base.accessed,
            0x0c => self.base.changed,
            0x10 => self.base.modified,
            _ => return Err(Corrupt::InvalidInode(self.number).into()),
        };
        let extra = self.extra.extra_timestamp(extra_offset).unwrap_or(0);
        let nanoseconds = extra >> 2;
        if nanoseconds >= 1_000_000_000 {
            return Err(Corrupt::InvalidInode(self.number).into());
        }
        Ok(Timestamp {
            seconds: i64::from(low as i32) + (i64::from(extra & 3) << 32),
            nanoseconds,
        })
    }

    pub(crate) fn set_size(&mut self, size: u64) {
        self.base.size_low = size as u32;
        self.base.size_high = (size >> 32) as u32;
    }

    pub(crate) fn set_blocks_512(&mut self, sectors: u64) {
        self.base.blocks_low = sectors as u32;
        put_le16(&mut self.base.os_data.osd2, 0, (sectors >> 32) as u16);
    }

    #[inline(never)]
    pub(crate) fn apply_metadata(&mut self, update: InodeMetadataUpdate) -> Result<(), Error> {
        if let Some(permissions) = update.permissions {
            if permissions & !0o7777 != 0 {
                return Err(Error::InvalidArgument);
            }
            self.base.mode = self.base.mode & 0xf000 | permissions;
        }
        if let Some(uid) = update.uid {
            self.base.uid_low = uid as u16;
            put_le16(&mut self.base.os_data.osd2, 4, (uid >> 16) as u16);
        }
        if let Some(gid) = update.gid {
            self.base.gid_low = gid as u16;
            put_le16(&mut self.base.os_data.osd2, 6, (gid >> 16) as u16);
        }
        if let Some(timestamp) = update.accessed {
            self.set_timestamp(0x08, 0x8c, timestamp)?;
        }
        if let Some(timestamp) = update.changed {
            self.set_timestamp(0x0c, 0x84, timestamp)?;
        }
        if let Some(timestamp) = update.modified {
            self.set_timestamp(0x10, 0x88, timestamp)?;
        }
        Ok(())
    }

    fn set_timestamp(
        &mut self,
        seconds_offset: usize,
        extra_offset: usize,
        timestamp: Timestamp,
    ) -> Result<(), Error> {
        if timestamp.nanoseconds >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        let low = timestamp.seconds as i32;
        let epoch = (timestamp.seconds - i64::from(low)) >> 32;
        if !(0..=3).contains(&epoch) {
            return Err(Error::InvalidArgument);
        }
        let extra = (timestamp.nanoseconds << 2) | epoch as u32;
        if !self.extra.set_extra_timestamp(extra_offset, extra) && extra != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        match seconds_offset {
            0x08 => self.base.accessed = low as u32,
            0x0c => self.base.changed = low as u32,
            0x10 => self.base.modified = low as u32,
            _ => return Err(Corrupt::InvalidInode(self.number).into()),
        }
        Ok(())
    }

    fn initialize(&mut self) {
        self.base = InodeBase::default();
        self.extra.reset();
    }

    pub(crate) fn clear(&mut self) {
        self.base = InodeBase::default();
        self.extra.clear();
    }

    pub(crate) fn initialize_regular(&mut self, permissions: u16) {
        self.initialize();
        self.base.mode = 0x8000 | permissions;
        self.base.links = 1;
        self.base.flags = EXTENTS_FL;
        self.base.block_map = InodeBlockMap::Extents(ExtentRoot::empty());
    }

    pub(crate) fn initialize_fast_symlink(&mut self, target: &[u8]) -> Result<(), Error> {
        if target.is_empty() || target.len() > 60 {
            return Err(Error::InvalidArgument);
        }
        self.initialize();
        self.base.mode = 0xa000 | 0o777;
        self.base.size_low = target.len() as u32;
        self.base.links = 1;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(target.len())
            .map_err(|_| Error::OutOfMemory)?;
        owned.extend_from_slice(target);
        self.base.block_map = InodeBlockMap::FastSymlink {
            target: owned,
            padding: zeroed_bytes(60 - target.len())?,
        };
        Ok(())
    }

    pub(crate) fn initialize_directory(
        &mut self,
        permissions: u16,
        physical: u64,
        block_size: u64,
    ) -> Result<(), Error> {
        if physical >> 48 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        self.initialize();
        self.base.mode = 0x4000 | permissions;
        self.set_size(block_size);
        self.base.links = 2;
        self.set_blocks_512(block_size / 512);
        self.base.flags = EXTENTS_FL;
        self.base.block_map = InodeBlockMap::Extents(ExtentRoot::single(Extent::new(
            0,
            physical,
            1,
            ExtentState::Written,
        )?));
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        put_le16(&mut self.base.os_data.osd2, 8, 0);
        if self.extra.checksum_high.is_some() {
            self.extra.checksum_high = Some(0);
        }
        let checksum = self.checksum()?;
        put_le16(&mut self.base.os_data.osd2, 8, checksum as u16);
        if self.extra.checksum_high.is_some() {
            self.extra.checksum_high = Some((checksum >> 16) as u16);
        }
        Ok(())
    }

    fn checksum(&self) -> Result<u32, Error> {
        let mut bytes = zeroed_bytes(BASE_SIZE + self.extra.storage_size)?;
        self.encode(&mut bytes)?;
        put_le16(&mut bytes, 0x7c, 0);
        if self.extra.checksum_high.is_some() {
            put_le16(&mut bytes, 0x82, 0);
        }
        let mut checksum = Checksum::with_seed(self.checksum_seed);
        checksum.update_u32_le(self.number);
        checksum.update_u32_le(self.base.generation);
        checksum.update(&bytes);
        Ok(checksum.finalize())
    }
}

/// A decoded inode-table disk block. Every slot is represented as a proper
/// record, while encoding still produces exactly one journalable disk block.
pub(crate) struct InodeTableBlock {
    records: Vec<InodeRecord>,
    record_size: usize,
}

impl InodeTableBlock {
    pub(crate) fn containing(
        bytes: &[u8],
        record_size: usize,
        number: u32,
        offset: usize,
        checksum_seed: u32,
    ) -> Result<(Self, usize), Error> {
        if record_size < BASE_SIZE
            || !record_size.is_power_of_two()
            || !bytes.len().is_multiple_of(record_size)
            || !offset.is_multiple_of(record_size)
            || offset + record_size > bytes.len()
        {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        let selected = offset / record_size;
        let selected_u32 = u32::try_from(selected).map_err(|_| Corrupt::AddressOverflow)?;
        let first = number
            .checked_sub(selected_u32)
            .ok_or(Corrupt::InvalidInode(number))?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(bytes.len() / record_size)
            .map_err(|_| Error::OutOfMemory)?;
        for (index, raw) in bytes.chunks_exact(record_size).enumerate() {
            let number = first
                .checked_add(u32::try_from(index).map_err(|_| Corrupt::AddressOverflow)?)
                .ok_or(Corrupt::AddressOverflow)?;
            records.push(InodeRecord::decode(raw, checksum_seed, number)?);
        }
        Ok((
            Self {
                records,
                record_size,
            },
            selected,
        ))
    }

    pub(crate) fn record_mut(&mut self, index: usize) -> Result<&mut InodeRecord, Error> {
        self.records
            .get_mut(index)
            .ok_or_else(|| Corrupt::InvalidInodeTable.into())
    }

    pub(crate) fn into_record(self, index: usize) -> Result<InodeRecord, Error> {
        self.records
            .into_iter()
            .nth(index)
            .ok_or_else(|| Corrupt::InvalidInodeTable.into())
    }

    pub(crate) fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        if bytes.len() != self.records.len() * self.record_size {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        for (record, raw) in self
            .records
            .iter()
            .zip(bytes.chunks_exact_mut(self.record_size))
        {
            record.encode(raw)?;
        }
        Ok(())
    }
}
