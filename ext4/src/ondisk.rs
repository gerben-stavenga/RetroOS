use crate::checksum::Checksum;
use crate::{Corrupt, Error, Storage, Unsupported};

pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
pub(crate) const EXT4_MAGIC: u16 = 0xef53;

pub(crate) const INCOMPAT_FILETYPE: u32 = 0x0002;
pub(crate) const INCOMPAT_RECOVER: u32 = 0x0004;
pub(crate) const INCOMPAT_META_BG: u32 = 0x0010;
pub(crate) const INCOMPAT_EXTENTS: u32 = 0x0040;
pub(crate) const INCOMPAT_64BIT: u32 = 0x0080;
pub(crate) const INCOMPAT_FLEX_BG: u32 = 0x0200;
pub(crate) const INCOMPAT_CSUM_SEED: u32 = 0x2000;
pub(crate) const COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub(crate) const COMPAT_SPARSE_SUPER2: u32 = 0x0200;

pub(crate) const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub(crate) const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub(crate) const RO_COMPAT_BIGALLOC: u32 = 0x0200;

const READ_INCOMPAT: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_CSUM_SEED;

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
}

impl Superblock {
    pub(crate) fn load<S: Storage>(storage: &mut S) -> Result<Self, Error<S::Error>> {
        let mut bytes = [0u8; SUPERBLOCK_SIZE];
        checked_read(storage, SUPERBLOCK_OFFSET, &mut bytes)?;
        Self::parse(&bytes, storage.len())
    }

    fn parse<E>(b: &[u8; SUPERBLOCK_SIZE], storage_len: u64) -> Result<Self, Error<E>> {
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

        if feature_incompat & INCOMPAT_META_BG != 0 {
            return Err(Unsupported::MetaBlockGroups.into());
        }
        let unknown = feature_incompat & !READ_INCOMPAT;
        if unknown != 0 {
            return Err(Unsupported::IncompatibleFeatures(unknown).into());
        }
        let has_metadata_checksums = feature_ro_compat & RO_COMPAT_METADATA_CSUM != 0;
        if !has_metadata_checksums && feature_ro_compat & RO_COMPAT_GDT_CSUM != 0 {
            return Err(Unsupported::LegacyGroupChecksums.into());
        }
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

    pub(crate) fn has_metadata_checksums(&self) -> bool {
        self.feature_ro_compat & RO_COMPAT_METADATA_CSUM != 0
    }

    pub(crate) fn needs_recovery(&self) -> bool {
        self.feature_incompat & INCOMPAT_RECOVER != 0
    }
}

pub(crate) fn checked_read<S: Storage>(
    storage: &mut S,
    offset: u64,
    dst: &mut [u8],
) -> Result<(), Error<S::Error>> {
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
