use crate::checksum::Checksum;
use crate::{Corrupt, Error, Storage, Unsupported};
use alloc::vec::Vec;

pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
pub(crate) const EXT4_MAGIC: u16 = 0xef53;

pub(crate) const INCOMPAT_FILETYPE: u32 = 0x0002;
pub(crate) const INCOMPAT_RECOVER: u32 = 0x0004;
pub(crate) const INCOMPAT_META_BG: u32 = 0x0010;
pub(crate) const INCOMPAT_EXTENTS: u32 = 0x0040;
pub(crate) const INCOMPAT_64BIT: u32 = 0x0080;
pub(crate) const INCOMPAT_MMP: u32 = 0x0100;
pub(crate) const INCOMPAT_FLEX_BG: u32 = 0x0200;
pub(crate) const INCOMPAT_EA_INODE: u32 = 0x0400;
pub(crate) const INCOMPAT_CSUM_SEED: u32 = 0x2000;
pub(crate) const INCOMPAT_LARGE_DIR: u32 = 0x4000;
pub(crate) const INCOMPAT_INLINE_DATA: u32 = 0x8000;
pub(crate) const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
pub(crate) const INCOMPAT_CASEFOLD: u32 = 0x2_0000;
pub(crate) const COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub(crate) const COMPAT_SPARSE_SUPER2: u32 = 0x0200;

pub(crate) const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub(crate) const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub(crate) const RO_COMPAT_BIGALLOC: u32 = 0x0200;

const READ_INCOMPAT: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGE_DIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub(crate) first_inode: u32,
    pub descriptor_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub checksum_seed: u32,
    pub journal_inode: u32,
    pub(crate) reserved_gdt_blocks: u16,
    pub(crate) backup_bgs: [u32; 2],
    pub(crate) first_meta_bg: u32,
}

impl Superblock {
    #[inline(never)]
    pub(crate) fn load(storage: &mut dyn Storage) -> Result<Self, Error> {
        let mut bytes = [0u8; SUPERBLOCK_SIZE];
        checked_read(storage, SUPERBLOCK_OFFSET, &mut bytes)?;
        Self::parse(&bytes, storage.len())
    }

    fn parse(b: &[u8; SUPERBLOCK_SIZE], storage_len: u64) -> Result<Self, Error> {
        if le16(b, 0x38) != EXT4_MAGIC {
            return Err(Corrupt::BadMagic.into());
        }

        let log_block_size = le32(b, 0x18);
        let block_size = 1024u32
            .checked_shl(log_block_size)
            .filter(|size| matches!(size, 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536))
            .ok_or(Corrupt::InvalidBlockSize)?;

        let feature_compat = le32(b, 0x5c);
        let feature_incompat = le32(b, 0x60);
        let feature_ro_compat = le32(b, 0x64);

        let unknown = feature_incompat & !READ_INCOMPAT;
        if unknown != 0 {
            return Err(Unsupported::IncompatibleFeatures(unknown).into());
        }
        let has_metadata_checksums = feature_ro_compat & RO_COMPAT_METADATA_CSUM != 0;
        if feature_incompat & INCOMPAT_CSUM_SEED != 0 && !has_metadata_checksums {
            return Err(Corrupt::InvalidFeatureCombination.into());
        }

        let blocks_lo = u64::from(le32(b, 0x04));
        let blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 {
            u64::from(le32(b, 0x150))
        } else {
            0
        };
        let blocks_count = blocks_lo | (blocks_hi << 32);
        let first_data_block = le32(b, 0x14);
        let blocks_per_group = le32(b, 0x20);
        let inodes_count = le32(b, 0x00);
        let inodes_per_group = le32(b, 0x28);
        let dynamic_revision = le32(b, 0x4c) != 0;
        let inode_size = if !dynamic_revision {
            128
        } else {
            le16(b, 0x58)
        };
        let first_inode = if dynamic_revision { le32(b, 0x54) } else { 11 };
        let descriptor_size = if feature_incompat & INCOMPAT_64BIT != 0 {
            le16(b, 0xfe).max(64)
        } else {
            32
        };

        if blocks_count <= u64::from(first_data_block)
            || blocks_per_group == 0
            || inodes_count < 2
            || inodes_per_group == 0
            || inode_size < 128
            || first_inode == 0
            || first_inode > inodes_count
            || !inode_size.is_multiple_of(4)
            || u32::from(inode_size) > block_size
            || descriptor_size < 32
            || !descriptor_size.is_multiple_of(8)
            || u32::from(descriptor_size) > block_size
        {
            return Err(Corrupt::InvalidGeometry.into());
        }

        let block_groups =
            (blocks_count - u64::from(first_data_block)).div_ceil(u64::from(blocks_per_group));
        let inode_groups = u64::from(inodes_count).div_ceil(u64::from(inodes_per_group));
        if inode_groups > block_groups || block_groups > u64::from(u32::MAX) {
            return Err(Corrupt::InvalidGeometry.into());
        }

        let fs_bytes = blocks_count
            .checked_mul(u64::from(block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        if fs_bytes > storage_len {
            return Err(Corrupt::FilesystemPastEnd {
                fs_bytes,
                storage_len,
            }
            .into());
        }

        let mut uuid = [0; 16];
        uuid.copy_from_slice(&b[0x68..0x78]);
        if has_metadata_checksums {
            let expected = le32(b, 0x3fc);
            let mut checksum = Checksum::new();
            checksum.update(&b[..0x3fc]);
            if checksum.finalize() != expected {
                return Err(Corrupt::SuperblockChecksum.into());
            }
        }
        let checksum_seed = if feature_incompat & INCOMPAT_CSUM_SEED != 0 {
            le32(b, 0x270)
        } else {
            let mut checksum = Checksum::new();
            checksum.update(&uuid);
            checksum.finalize()
        };
        let journal_inode = le32(b, 0xe0);
        let reserved_gdt_blocks = le16(b, 0xce);
        let backup_bgs = [le32(b, 0x24c), le32(b, 0x250)];
        let first_meta_bg = le32(b, 0x104);
        let descriptors_per_block = block_size / u32::from(descriptor_size);
        let descriptor_blocks = block_groups.div_ceil(u64::from(descriptors_per_block));
        if feature_incompat & INCOMPAT_META_BG != 0 && u64::from(first_meta_bg) > descriptor_blocks
        {
            return Err(Corrupt::InvalidGeometry.into());
        }
        if feature_incompat & INCOMPAT_RECOVER != 0 {
            if feature_compat & COMPAT_HAS_JOURNAL == 0 {
                return Err(Corrupt::InvalidFeatureCombination.into());
            }
            if journal_inode == 0 {
                return Err(Unsupported::ExternalJournal.into());
            }
        }
        Ok(Self {
            inodes_count,
            blocks_count,
            first_data_block,
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            descriptor_size,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            uuid,
            checksum_seed,
            journal_inode,
            reserved_gdt_blocks,
            backup_bgs,
            first_meta_bg,
        })
    }

    pub(crate) fn group_count(&self) -> u32 {
        let data_blocks = self.blocks_count - u64::from(self.first_data_block);
        // Mount validation proves the result fits in u32.
        data_blocks.div_ceil(u64::from(self.blocks_per_group)) as u32
    }

    pub(crate) fn descriptor_table_offset(&self) -> u64 {
        (u64::from(self.first_data_block) + 1) * u64::from(self.block_size)
    }

    /// Locate one descriptor in either the original contiguous GDT or the
    /// descriptor block at the head of its meta block group.
    pub(crate) fn descriptor_offset(&self, group: u32) -> Option<u64> {
        let descriptor_size = u64::from(self.descriptor_size);
        let descriptors_per_block = u64::from(self.block_size) / descriptor_size;
        let descriptor_block = u64::from(group) / descriptors_per_block;
        let within = u64::from(group) % descriptors_per_block;
        let block = if self.feature_incompat & INCOMPAT_META_BG == 0
            || descriptor_block < u64::from(self.first_meta_bg)
        {
            u64::from(self.first_data_block)
                .checked_add(1)?
                .checked_add(descriptor_block)?
        } else {
            let first_group = descriptor_block.checked_mul(descriptors_per_block)?;
            let first_block = u64::from(self.first_data_block)
                .checked_add(first_group.checked_mul(u64::from(self.blocks_per_group))?)?;
            first_block.checked_add(u64::from(self.group_has_super(first_group as u32)))?
        };
        block
            .checked_mul(u64::from(self.block_size))?
            .checked_add(within.checked_mul(descriptor_size)?)
    }

    pub(crate) fn group_has_super(&self, group: u32) -> bool {
        if group == 0 {
            return true;
        }
        if self.feature_compat & COMPAT_SPARSE_SUPER2 != 0 {
            return self.backup_bgs.contains(&group);
        }
        if self.feature_ro_compat & 0x0001 == 0 {
            return true;
        }
        group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
    }

    pub(crate) fn has_metadata_checksums(&self) -> bool {
        self.feature_ro_compat & RO_COMPAT_METADATA_CSUM != 0
    }

    pub(crate) fn needs_recovery(&self) -> bool {
        self.feature_incompat & INCOMPAT_RECOVER != 0
    }

    pub(crate) fn update_free_counts(
        &self,
        raw: &mut [u8],
        blocks: u64,
        inode: bool,
        allocate: bool,
    ) -> Result<(), Error> {
        fn change(
            raw: &mut [u8],
            offsets: (usize, Option<usize>),
            amount: u64,
            max: u64,
            subtract: bool,
        ) -> Result<(), Error> {
            let old = u64::from(le32(raw, offsets.0))
                | offsets.1.map_or(0, |high| u64::from(le32(raw, high)) << 32);
            let new = if subtract {
                old.checked_sub(amount)
            } else {
                old.checked_add(amount).filter(|value| *value <= max)
            }
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
            put_le32(raw, offsets.0, new as u32);
            if let Some(high) = offsets.1 {
                put_le32(raw, high, (new >> 32) as u32);
            }
            Ok(())
        }
        if blocks != 0 {
            change(
                raw,
                (0x0c, Some(0x158)),
                blocks,
                self.blocks_count,
                allocate,
            )?;
        }
        if inode {
            change(raw, (0x10, None), 1, u64::from(self.inodes_count), allocate)?;
        }
        let mut checksum = Checksum::new();
        checksum.update(&raw[..0x3fc]);
        put_le32(raw, 0x3fc, checksum.finalize());
        Ok(())
    }
}

/// One checked block-group descriptor.
///
/// Field widths, byte offsets, counter bounds and descriptor checksums belong
/// here. Allocation code deals in group resources rather than raw ext4 bytes.
pub(crate) struct GroupDescriptor {
    pub(crate) group: u32,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) enum BitmapKind {
    Block,
    Inode,
}

impl GroupDescriptor {
    pub(crate) fn new(superblock: &Superblock, group: u32, bytes: Vec<u8>) -> Result<Self, Error> {
        if group >= superblock.group_count()
            || bytes.len() != usize::from(superblock.descriptor_size)
        {
            return Err(Corrupt::InvalidGroup(group).into());
        }
        let expected = le16(&bytes, 0x1e);
        if superblock.has_metadata_checksums() {
            let mut checksum = Checksum::with_seed(superblock.checksum_seed);
            checksum.update_u32_le(group);
            checksum.update(&bytes[..0x1e]);
            checksum.update_u16_le(0);
            checksum.update(&bytes[0x20..]);
            if checksum.finalize() as u16 != expected {
                return Err(Corrupt::GroupDescriptorChecksum(group).into());
            }
        } else if superblock.feature_ro_compat & RO_COMPAT_GDT_CSUM != 0
            && legacy_descriptor_checksum(&superblock.uuid, group, &bytes) != expected
        {
            return Err(Corrupt::GroupDescriptorChecksum(group).into());
        }
        Ok(Self { group, bytes })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn wide32(&self, low: usize, high: usize) -> u64 {
        u64::from(le32(&self.bytes, low))
            | self
                .bytes
                .get(high..high + 4)
                .map_or(0, |bytes| u64::from(le32(bytes, 0)) << 32)
    }

    fn wide16(&self, low: usize, high: usize) -> u64 {
        u64::from(le16(&self.bytes, low))
            | self
                .bytes
                .get(high..high + 2)
                .map_or(0, |bytes| u64::from(le16(bytes, 0)) << 16)
    }

    fn set_wide16(&mut self, low: usize, high: usize, value: u64) -> Result<(), Error> {
        if value > u64::from(u32::MAX) || value > u64::from(u16::MAX) && self.bytes.len() < high + 2
        {
            return Err(Corrupt::InvalidFreeBlockCount.into());
        }
        put_le16(&mut self.bytes, low, value as u16);
        if self.bytes.len() >= high + 2 {
            put_le16(&mut self.bytes, high, (value >> 16) as u16);
        }
        Ok(())
    }

    fn decrease(&mut self, field: (usize, usize), amount: u64) -> Result<(), Error> {
        self.set_wide16(
            field.0,
            field.1,
            self.wide16(field.0, field.1)
                .checked_sub(amount)
                .ok_or(Corrupt::InvalidFreeBlockCount)?,
        )
    }

    fn increase(&mut self, field: (usize, usize), amount: u64, max: u64) -> Result<(), Error> {
        let value = self
            .wide16(field.0, field.1)
            .checked_add(amount)
            .filter(|value| *value <= max)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        self.set_wide16(field.0, field.1, value)
    }

    pub(crate) fn bitmap(&self, kind: BitmapKind) -> u64 {
        let (low, high) = match kind {
            BitmapKind::Block => (0, 0x20),
            BitmapKind::Inode => (4, 0x24),
        };
        self.wide32(low, high)
    }

    pub(crate) fn inode_table(&self) -> u64 {
        self.wide32(8, 0x28)
    }

    pub(crate) fn free_blocks(&self) -> u64 {
        self.wide16(0x0c, 0x2c)
    }

    pub(crate) fn free_inodes(&self) -> u64 {
        self.wide16(0x0e, 0x2e)
    }

    pub(crate) fn flags(&self) -> u16 {
        le16(&self.bytes, 0x12)
    }

    pub(crate) fn clear_flag(&mut self, flag: u16) {
        let flags = self.flags() & !flag;
        put_le16(&mut self.bytes, 0x12, flags);
    }

    pub(crate) fn allocate_blocks(&mut self, amount: u64) -> Result<(), Error> {
        self.decrease((0x0c, 0x2c), amount)
    }

    pub(crate) fn release_blocks(&mut self, amount: u64, blocks: u64) -> Result<(), Error> {
        self.increase((0x0c, 0x2c), amount, blocks)
    }

    pub(crate) fn allocate_inode(
        &mut self,
        index: u64,
        inodes: u64,
        directory: bool,
    ) -> Result<(), Error> {
        self.decrease((0x0e, 0x2e), 1)?;
        let unused = self.wide16(0x1c, 0x3c);
        if unused > inodes || index >= inodes {
            return Err(Corrupt::InvalidFreeBlockCount.into());
        }
        let initialized = inodes - unused;
        if index >= initialized {
            self.set_wide16(0x1c, 0x3c, inodes - index - 1)?;
        }
        if directory {
            self.increase((0x10, 0x30), 1, inodes)?;
        }
        Ok(())
    }

    pub(crate) fn release_inode(&mut self, inodes: u64, directory: bool) -> Result<(), Error> {
        self.increase((0x0e, 0x2e), 1, inodes)?;
        if directory {
            let used = self.wide16(0x10, 0x30);
            if used > inodes {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            }
            self.decrease((0x10, 0x30), 1)?;
        }
        Ok(())
    }

    pub(crate) fn bitmap_checksum(&self, kind: BitmapKind) -> u32 {
        let (low, high) = match kind {
            BitmapKind::Block => (0x18, 0x38),
            BitmapKind::Inode => (0x1a, 0x3a),
        };
        self.wide16(low, high) as u32
    }

    pub(crate) fn set_bitmap_checksum(&mut self, kind: BitmapKind, checksum: u32) {
        let (low, high) = match kind {
            BitmapKind::Block => (0x18, 0x38),
            BitmapKind::Inode => (0x1a, 0x3a),
        };
        put_le16(&mut self.bytes, low, checksum as u16);
        if self.bytes.len() >= high + 2 {
            put_le16(&mut self.bytes, high, (checksum >> 16) as u16);
        }
    }

    pub(crate) fn finish(&mut self, superblock: &Superblock) {
        put_le16(&mut self.bytes, 0x1e, 0);
        let checksum = if superblock.has_metadata_checksums() {
            let mut checksum = Checksum::with_seed(superblock.checksum_seed);
            checksum.update_u32_le(self.group);
            checksum.update(&self.bytes);
            checksum.finalize() as u16
        } else {
            legacy_descriptor_checksum(&superblock.uuid, self.group, &self.bytes)
        };
        put_le16(&mut self.bytes, 0x1e, checksum);
    }
}

fn legacy_descriptor_checksum(uuid: &[u8; 16], group: u32, descriptor: &[u8]) -> u16 {
    let mut checksum = crc16(u16::MAX, uuid);
    checksum = crc16(checksum, &group.to_le_bytes());
    checksum = crc16(checksum, &descriptor[..0x1e]);
    if descriptor.len() > 0x20 {
        checksum = crc16(checksum, &descriptor[0x20..]);
    }
    checksum
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

pub(crate) fn put_le16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_le32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < 1 {
        return false;
    }
    while value.is_multiple_of(base) {
        value /= base;
    }
    value == 1
}

pub(crate) fn checked_read(
    storage: &mut dyn Storage,
    offset: u64,
    dst: &mut [u8],
) -> Result<(), Error> {
    let end = offset
        .checked_add(u64::try_from(dst.len()).map_err(|_| Corrupt::AddressOverflow)?)
        .ok_or(Corrupt::AddressOverflow)?;
    if end > storage.len() {
        return Err(Corrupt::ReadPastEnd {
            offset,
            len: dst.len(),
        }
        .into());
    }
    storage.read(offset, dst).map_err(Error::Storage)
}

pub(crate) fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
