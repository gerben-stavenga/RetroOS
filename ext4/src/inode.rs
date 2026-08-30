//! Checked access to one ext inode record.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{
    Corrupt, EXTENT_MAGIC, EXTENTS_FL, Error, Inode, InodeMetadataUpdate, Timestamp, Unsupported,
};

pub(crate) struct InodeRecord<'a> {
    pub(crate) raw: &'a mut [u8],
    pub(crate) checksum_seed: u32,
    pub(crate) number: u32,
    pub(crate) generation: u32,
}

impl<'a> InodeRecord<'a> {
    pub(crate) fn new(raw: &'a mut [u8], checksum_seed: u32, number: u32) -> Result<Self, Corrupt> {
        if raw.len() < 128 || number == 0 {
            return Err(Corrupt::InvalidInode(number));
        }
        let generation = le32(raw, 0x64);
        Ok(Self {
            raw,
            checksum_seed,
            number,
            generation,
        })
    }

    pub(crate) fn for_update(
        raw: &'a mut [u8],
        checksum_seed: u32,
        inode: &Inode,
    ) -> Result<Self, Corrupt> {
        let record = Self::new(raw, checksum_seed, inode.number)?;
        (record.generation == inode.generation)
            .then_some(record)
            .ok_or(Corrupt::InvalidInode(inode.number))
    }

    pub(crate) fn verify_checksum(&mut self) -> Result<(), Error> {
        let expected_low = le16(self.raw, 0x7c);
        let expected_high = (self.raw.len() >= 0x84).then(|| le16(self.raw, 0x82));
        put_le16(self.raw, 0x7c, 0);
        if self.raw.len() >= 0x84 {
            put_le16(self.raw, 0x82, 0);
        }
        let checksum = self.checksum();
        put_le16(self.raw, 0x7c, expected_low);
        if let Some(expected_high) = expected_high {
            put_le16(self.raw, 0x82, expected_high);
        }
        let valid = expected_high.map_or(checksum as u16 == expected_low, |high| {
            checksum == u32::from(expected_low) | (u32::from(high) << 16)
        });
        if !valid {
            return Err(Corrupt::InodeChecksum(self.number).into());
        }
        Ok(())
    }

    pub(crate) fn mode(&self) -> u16 {
        le16(self.raw, 0)
    }

    pub(crate) fn uid(&self) -> u32 {
        u32::from(le16(self.raw, 2)) | (u32::from(le16(self.raw, 0x78)) << 16)
    }

    pub(crate) fn gid(&self) -> u32 {
        u32::from(le16(self.raw, 0x18)) | (u32::from(le16(self.raw, 0x7a)) << 16)
    }

    pub(crate) fn size(&self) -> u64 {
        u64::from(le32(self.raw, 4)) | (u64::from(le32(self.raw, 0x6c)) << 32)
    }

    pub(crate) fn links(&self) -> u16 {
        le16(self.raw, 0x1a)
    }

    pub(crate) fn flags(&self) -> u32 {
        le32(self.raw, 0x20)
    }

    pub(crate) fn blocks_512(&self) -> u64 {
        u64::from(le32(self.raw, 0x1c)) | (u64::from(le16(self.raw, 0x74)) << 32)
    }

    pub(crate) fn external_xattr_block(&self, wide: bool) -> u64 {
        u64::from(le32(self.raw, 0x68))
            | if wide {
                u64::from(le16(self.raw, 0x76)) << 32
            } else {
                0
            }
    }

    pub(crate) fn block_map(&self) -> [u8; 60] {
        self.raw[0x28..0x64].try_into().unwrap()
    }

    pub(crate) fn timestamp(
        &self,
        seconds_offset: usize,
        extra_offset: usize,
    ) -> Result<Timestamp, Error> {
        let seconds = i64::from(le32(self.raw, seconds_offset) as i32);
        let extra = if extra_offset + 4 <= self.raw.len() {
            le32(self.raw, extra_offset)
        } else {
            0
        };
        let nanoseconds = extra >> 2;
        if nanoseconds >= 1_000_000_000 {
            return Err(Corrupt::InvalidInode(self.number).into());
        }
        Ok(Timestamp {
            seconds: seconds + (i64::from(extra & 3) << 32),
            nanoseconds,
        })
    }

    pub(crate) fn set_links(&mut self, links: u16) {
        put_le16(self.raw, 0x1a, links);
    }

    pub(crate) fn set_size(&mut self, size: u64) {
        put_le32(self.raw, 4, size as u32);
        put_le32(self.raw, 0x6c, (size >> 32) as u32);
    }

    pub(crate) fn set_blocks_512(&mut self, sectors: u64) {
        put_le32(self.raw, 0x1c, sectors as u32);
        put_le16(self.raw, 0x74, (sectors >> 32) as u16);
    }

    pub(crate) fn extent_root_mut(&mut self) -> &mut [u8] {
        &mut self.raw[0x28..0x64]
    }

    #[inline(never)]
    pub(crate) fn apply_metadata(&mut self, update: InodeMetadataUpdate) -> Result<(), Error> {
        if let Some(permissions) = update.permissions {
            if permissions & !0o7777 != 0 {
                return Err(Error::InvalidArgument);
            }
            put_le16(self.raw, 0, self.mode() & 0xf000 | permissions);
        }
        if let Some(uid) = update.uid {
            put_le16(self.raw, 2, uid as u16);
            put_le16(self.raw, 0x78, (uid >> 16) as u16);
        }
        if let Some(gid) = update.gid {
            put_le16(self.raw, 0x18, gid as u16);
            put_le16(self.raw, 0x7a, (gid >> 16) as u16);
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
        if timestamp.nanoseconds != 0 || epoch != 0 {
            if extra_offset + 4 > self.raw.len() {
                return Err(Unsupported::MutationProfile.into());
            }
            put_le32(
                self.raw,
                extra_offset,
                (timestamp.nanoseconds << 2) | epoch as u32,
            );
        } else if extra_offset + 4 <= self.raw.len() {
            put_le32(self.raw, extra_offset, 0);
        }
        put_le32(self.raw, seconds_offset, low as u32);
        Ok(())
    }

    pub(crate) fn initialize_regular(&mut self, permissions: u16) {
        self.raw.fill(0);
        put_le16(self.raw, 0, 0x8000 | permissions);
        put_le16(self.raw, 0x1a, 1);
        put_le32(self.raw, 0x20, EXTENTS_FL);
        let root = &mut self.raw[0x28..0x64];
        put_le16(root, 0, EXTENT_MAGIC);
        put_le16(root, 4, 4);
        if self.raw.len() >= 0x84 {
            put_le16(self.raw, 0x80, 32);
        }
    }

    pub(crate) fn initialize_fast_symlink(&mut self, target: &[u8]) -> Result<(), Error> {
        if target.is_empty() || target.len() > 60 || self.raw.len() < 0x84 {
            return Err(Error::InvalidArgument);
        }
        self.raw.fill(0);
        put_le16(self.raw, 0, 0xa000 | 0o777);
        put_le32(self.raw, 4, target.len() as u32);
        put_le16(self.raw, 0x1a, 1);
        self.raw[0x28..0x28 + target.len()].copy_from_slice(target);
        put_le16(self.raw, 0x80, 32);
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
        self.raw.fill(0);
        put_le16(self.raw, 0, 0x4000 | permissions);
        self.set_size(block_size);
        put_le16(self.raw, 0x1a, 2);
        self.set_blocks_512(block_size / 512);
        put_le32(self.raw, 0x20, EXTENTS_FL);
        let root = &mut self.raw[0x28..0x64];
        put_le16(root, 0, EXTENT_MAGIC);
        put_le16(root, 2, 1);
        put_le16(root, 4, 4);
        put_le32(root, 12, 0);
        put_le16(root, 16, 1);
        put_le16(root, 18, (physical >> 32) as u16);
        put_le32(root, 20, physical as u32);
        if self.raw.len() >= 0x84 {
            put_le16(self.raw, 0x80, 32);
        }
        Ok(())
    }

    pub(crate) fn finish(self) {
        put_le16(self.raw, 0x7c, 0);
        if self.raw.len() >= 0x84 {
            put_le16(self.raw, 0x82, 0);
        }
        let checksum = self.checksum();
        put_le16(self.raw, 0x7c, checksum as u16);
        if self.raw.len() >= 0x84 {
            put_le16(self.raw, 0x82, (checksum >> 16) as u16);
        }
    }

    fn checksum(&self) -> u32 {
        let mut checksum = Checksum::with_seed(self.checksum_seed);
        checksum.update_u32_le(self.number);
        checksum.update_u32_le(self.generation);
        checksum.update(self.raw);
        checksum.finalize()
    }
}
