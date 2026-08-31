//! JBD2 recovery and constrained transaction writing.
//!
//! Recovery retains committed blocks as a volatile overlay. The writer uses
//! explicit durability barriers around activation, commit, checkpoint, and
//! cleanup so every interrupted state is either old or replayable.

use crate::checksum::Checksum;
use crate::ondisk;
use crate::transaction::DirtyBlock;
use crate::{
    Corrupt, Error, Ext4, Inode, InodeBlocks, Storage, Unsupported, copy_bytes, try_insert,
    try_push,
};
use alloc::vec::Vec;

const MAGIC: u32 = 0xc03b_3998;
const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

const COMPAT_CHECKSUM_V1: u32 = 1;
const INCOMPAT_REVOKE: u32 = 1;
const INCOMPAT_64BIT: u32 = 2;
const INCOMPAT_ASYNC_COMMIT: u32 = 4;
const INCOMPAT_CSUM_V2: u32 = 8;
const INCOMPAT_CSUM_V3: u32 = 16;
const INCOMPAT_FAST_COMMIT: u32 = 32;

const FLAG_ESCAPE: u32 = 1;
const FLAG_SAME_UUID: u32 = 2;
const FLAG_DELETED: u32 = 4;
const FLAG_LAST: u32 = 8;
const KNOWN_FLAGS: u32 = FLAG_ESCAPE | FLAG_SAME_UUID | FLAG_DELETED | FLAG_LAST;

#[derive(Clone, Copy)]
struct Format {
    max_len: u32,
    first: u32,
    sequence: u32,
    start: u32,
    incompat: u32,
    uuid: [u8; 16],
    checksum_seed: u32,
}

impl Format {
    fn csum_v2(self) -> bool {
        self.incompat & INCOMPAT_CSUM_V2 != 0
    }

    fn csum_v3(self) -> bool {
        self.incompat & INCOMPAT_CSUM_V3 != 0
    }

    fn has_checksums(self) -> bool {
        self.csum_v2() || self.csum_v3()
    }

    fn is_64bit(self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }

    fn tag_len(self) -> usize {
        if self.csum_v3() {
            16
        } else if self.is_64bit() {
            12
        } else {
            8
        }
    }

    fn advance(self, block: u32) -> u32 {
        if block + 1 == self.max_len {
            self.first
        } else {
            block + 1
        }
    }
}

struct LoggedBlock {
    sequence: u32,
    target: u64,
    bytes: Vec<u8>,
}

struct Revoke {
    sequence: u32,
    target: u64,
}

struct Tag {
    target: u64,
    flags: u32,
    checksum: u32,
}

struct Tags<'a> {
    format: Format,
    bytes: &'a [u8],
    cursor: usize,
    end: usize,
    have_uuid: bool,
    finished: bool,
}

impl<'a> Tags<'a> {
    fn new(format: Format, bytes: &'a [u8]) -> Self {
        Self {
            format,
            bytes,
            cursor: 12,
            end: bytes.len() - usize::from(format.has_checksums()) * 4,
            have_uuid: false,
            finished: false,
        }
    }

    #[inline(never)]
    fn next(&mut self) -> Result<Option<Tag>, Error> {
        if self.finished {
            return Ok(None);
        }
        let tag_len = self.format.tag_len();
        if self.cursor + tag_len > self.end {
            return Err(Corrupt::InvalidJournal.into());
        }
        let low = u64::from(be32(self.bytes, self.cursor));
        let (flags, checksum, high) = if self.format.csum_v3() {
            (
                be32(self.bytes, self.cursor + 4),
                be32(self.bytes, self.cursor + 12),
                be32(self.bytes, self.cursor + 8),
            )
        } else {
            (
                u32::from(be16(self.bytes, self.cursor + 6)),
                u32::from(be16(self.bytes, self.cursor + 4)),
                if self.format.is_64bit() {
                    be32(self.bytes, self.cursor + 8)
                } else {
                    0
                },
            )
        };
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Corrupt::InvalidJournal.into());
        }
        self.cursor += tag_len;
        if flags & FLAG_SAME_UUID == 0 {
            if self.cursor + 16 > self.end
                || self.bytes[self.cursor..self.cursor + 16] != self.format.uuid
            {
                return Err(Corrupt::InvalidJournal.into());
            }
            self.cursor += 16;
            self.have_uuid = true;
        } else if !self.have_uuid {
            return Err(Corrupt::InvalidJournal.into());
        }
        self.finished = flags & FLAG_LAST != 0;
        Ok(Some(Tag {
            target: low | (u64::from(high) << 32),
            flags,
            checksum,
        }))
    }
}

struct Journal {
    inode: Inode,
    blocks: InodeBlocks,
}

impl Journal {
    #[inline(never)]
    fn open(filesystem: &mut Ext4, storage: &mut dyn Storage) -> Result<Self, Error> {
        let inode = filesystem.load_inode(storage, filesystem.superblock.journal_inode)?;
        if inode.mode & 0xf000 != 0x8000 {
            return Err(Corrupt::InvalidJournal.into());
        }
        let blocks = InodeBlocks::open(filesystem, storage, &inode)?;
        Ok(Self { inode, blocks })
    }

    fn physical(
        &self,
        filesystem: &mut Ext4,
        storage: &mut dyn Storage,
        logical: u32,
    ) -> Result<u64, Error> {
        self.blocks
            .physical(filesystem, storage, &self.inode, u64::from(logical))?
            .filter(|physical| *physical < filesystem.superblock.blocks_count)
            .ok_or(Corrupt::InvalidJournal.into())
    }

    #[inline(never)]
    fn read(
        &self,
        filesystem: &mut Ext4,
        storage: &mut dyn Storage,
        logical: u32,
    ) -> Result<Vec<u8>, Error> {
        let physical = self.physical(filesystem, storage, logical)?;
        let mut bytes = filesystem.new_block_buffer()?;
        let offset = physical
            .checked_mul(u64::from(filesystem.superblock.block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        filesystem.read_storage(storage, offset, &mut bytes)?;
        Ok(bytes)
    }
}

impl Ext4 {
    #[inline(never)]
    pub(crate) fn commit_journal(
        &mut self,
        storage: &mut dyn Storage,
        dirty: &[DirtyBlock],
    ) -> Result<(), Error> {
        if dirty.is_empty() {
            return Ok(());
        }
        if self.superblock.needs_recovery()
            || !self.overlay.is_empty()
            || self.superblock.block_size != 4096
        {
            return Err(Unsupported::JournalWriteProfile.into());
        }

        let journal = Journal::open(self, storage)?;
        let format = self.load_journal_format(storage, &journal)?;
        if format.start != 0
            || (!format.csum_v3() && format.has_checksums())
            || format.incompat & INCOMPAT_ASYNC_COMMIT != 0
        {
            return Err(Unsupported::JournalWriteProfile.into());
        }
        let count = u32::try_from(dirty.len()).map_err(|_| Error::InvalidArgument)?;
        let commit_logical = format
            .first
            .checked_add(count)
            .and_then(|block| block.checked_add(1))
            .filter(|block| *block < format.max_len)
            .ok_or(Unsupported::JournalWriteProfile)?;
        let descriptor_capacity =
            self.superblock.block_size as usize - usize::from(format.has_checksums()) * 4;
        let tags_len = dirty
            .len()
            .checked_mul(format.tag_len())
            .and_then(|bytes| bytes.checked_add(16))
            .and_then(|bytes| bytes.checked_add(12))
            .ok_or(Corrupt::AddressOverflow)?;
        if tags_len > descriptor_capacity {
            return Err(Unsupported::JournalWriteProfile.into());
        }

        let superblock_target = ondisk::SUPERBLOCK_OFFSET / u64::from(self.superblock.block_size);
        let final_superblock = dirty
            .iter()
            .find(|block| block.number == superblock_target)
            .ok_or(Unsupported::JournalWriteProfile)?;
        let mut activation_superblock = self.new_block_buffer()?;
        let superblock_offset = superblock_target
            .checked_mul(u64::from(self.superblock.block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        self.read_storage(storage, superblock_offset, &mut activation_superblock)?;
        enable_recovery(&mut activation_superblock)?;
        let mut checkpoint_superblock = copy_bytes(&final_superblock.bytes)?;
        enable_recovery(&mut checkpoint_superblock)?;

        let mut descriptor = self.new_block_buffer()?;
        put_be32(&mut descriptor, 0, MAGIC);
        put_be32(&mut descriptor, 4, DESCRIPTOR);
        put_be32(&mut descriptor, 8, format.sequence);
        let mut cursor = 12usize;
        let mut escaped = self.new_block_buffer()?;
        for (index, block) in dirty.iter().enumerate() {
            if block.bytes.len() != self.superblock.block_size as usize
                || block.number >= self.superblock.blocks_count
            {
                return Err(Error::InvalidArgument);
            }
            let escape = be32(&block.bytes, 0) == MAGIC;
            let data = if escape {
                escaped.copy_from_slice(&block.bytes);
                escaped[..4].fill(0);
                &escaped
            } else {
                &block.bytes
            };
            let mut flags = if index == 0 { 0 } else { FLAG_SAME_UUID };
            if escape {
                flags |= FLAG_ESCAPE;
            }
            if index + 1 == dirty.len() {
                flags |= FLAG_LAST;
            }
            let checksum = if format.csum_v3() {
                crc32c(
                    crc32c(format.checksum_seed, &format.sequence.to_be_bytes()),
                    data,
                )
            } else {
                0
            };
            cursor = write_tag(
                format,
                &mut descriptor,
                cursor,
                Tag {
                    target: block.number,
                    flags,
                    checksum,
                },
            );
        }
        if format.has_checksums() {
            update_metadata_checksum(format, &mut descriptor);
        }

        let mut commit = self.new_block_buffer()?;
        put_be32(&mut commit, 0, MAGIC);
        put_be32(&mut commit, 4, COMMIT);
        put_be32(&mut commit, 8, format.sequence);
        if format.has_checksums() {
            update_commit_checksum(format, &mut commit);
        }

        let mut active_journal_superblock = journal.read(self, storage, 0)?;
        put_be32(&mut active_journal_superblock, 0x18, format.sequence);
        put_be32(&mut active_journal_superblock, 0x1c, format.first);
        if format.has_checksums() {
            update_journal_superblock_checksum(&mut active_journal_superblock);
        }
        let mut clean_journal_superblock = copy_bytes(&active_journal_superblock)?;
        put_be32(
            &mut clean_journal_superblock,
            0x18,
            format.sequence.wrapping_add(1),
        );
        put_be32(&mut clean_journal_superblock, 0x1c, 0);
        if format.has_checksums() {
            update_journal_superblock_checksum(&mut clean_journal_superblock);
        }

        let mut journal_offsets = Vec::new();
        journal_offsets
            .try_reserve_exact(dirty.len() + 3)
            .map_err(|_| Error::OutOfMemory)?;
        record_journal_offset(
            &mut journal_offsets,
            dirty,
            journal.physical(self, storage, 0)?,
        )?;
        for logical in format.first..=commit_logical {
            let physical = journal.physical(self, storage, logical)?;
            record_journal_offset(&mut journal_offsets, dirty, physical)?;
        }
        let journal_superblock_physical = journal_offsets[0];
        let descriptor_physical = journal_offsets[1];
        let commit_physical = *journal_offsets.last().ok_or(Corrupt::InvalidJournal)?;

        // Prepare an ignored transaction while the journal is still clean.
        self.write_physical_block(storage, descriptor_physical, &descriptor)?;
        for (index, block) in dirty.iter().enumerate() {
            let bytes = if be32(&block.bytes, 0) == MAGIC {
                escaped.copy_from_slice(&block.bytes);
                escaped[..4].fill(0);
                &escaped
            } else {
                &block.bytes
            };
            self.write_physical_block(storage, journal_offsets[index + 2], bytes)?;
        }
        self.flush_storage(storage)?;

        // Activate recovery only after every descriptor and data block is durable.
        self.write_physical_block(storage, superblock_target, &activation_superblock)?;
        self.write_physical_block(
            storage,
            journal_superblock_physical,
            &active_journal_superblock,
        )?;
        self.flush_storage(storage)?;

        // The commit block is the atomic visibility boundary.
        self.write_physical_block(storage, commit_physical, &commit)?;
        self.flush_storage(storage)?;

        // Keep needs_recovery set until every home block is durable.
        for block in dirty {
            let bytes = if block.number == superblock_target {
                &checkpoint_superblock
            } else {
                &block.bytes
            };
            self.write_physical_block(storage, block.number, bytes)?;
        }
        self.flush_storage(storage)?;

        // The checkpoint is complete, so either cleanup write may reach media first.
        self.write_physical_block(storage, superblock_target, &final_superblock.bytes)?;
        self.write_physical_block(
            storage,
            journal_superblock_physical,
            &clean_journal_superblock,
        )?;
        self.flush_storage(storage)?;
        Ok(())
    }

    #[inline(never)]
    pub(super) fn replay_journal(&mut self, storage: &mut dyn Storage) -> Result<(), Error> {
        let journal = Journal::open(self, storage)?;
        let format = self.load_journal_format(storage, &journal)?;
        if format.start == 0 {
            return Ok(());
        }

        let mut logged = Vec::new();
        let mut revokes = Vec::new();
        let mut pending_blocks = Vec::new();
        let mut pending_revokes = Vec::new();
        let mut block = format.start;
        let mut sequence = format.sequence;
        let mut visited = 0u32;

        while visited < format.max_len - format.first {
            let bytes = journal.read(self, storage, block)?;
            visited += 1;
            if be32(&bytes, 0) != MAGIC || be32(&bytes, 8) != sequence {
                break;
            }
            match be32(&bytes, 4) {
                DESCRIPTOR => {
                    verify_metadata_checksum(format, &bytes)?;
                    let mut tags = Tags::new(format, &bytes);
                    block = format.advance(block);
                    while let Some(tag) = tags.next()? {
                        if visited >= format.max_len - format.first {
                            return Err(Corrupt::InvalidJournal.into());
                        }
                        let mut data = journal.read(self, storage, block)?;
                        visited += 1;
                        verify_data_checksum(format, sequence, &tag, &data)?;
                        if tag.flags & FLAG_ESCAPE != 0 {
                            data[..4].copy_from_slice(&MAGIC.to_be_bytes());
                        }
                        if tag.flags & FLAG_DELETED == 0 {
                            try_push(
                                &mut pending_blocks,
                                LoggedBlock {
                                    sequence,
                                    target: tag.target,
                                    bytes: data,
                                },
                            )?;
                        }
                        block = format.advance(block);
                    }
                    continue;
                }
                REVOKE => {
                    if format.incompat & INCOMPAT_REVOKE == 0 {
                        return Err(Corrupt::InvalidJournal.into());
                    }
                    verify_metadata_checksum(format, &bytes)?;
                    parse_revokes(format, sequence, &bytes, &mut pending_revokes)?;
                }
                COMMIT => {
                    verify_commit_checksum(format, &bytes)?;
                    append(&mut logged, &mut pending_blocks)?;
                    append(&mut revokes, &mut pending_revokes)?;
                    sequence = sequence.wrapping_add(1);
                }
                _ => break,
            }
            block = format.advance(block);
        }

        for update in logged {
            if revokes.iter().any(|revoke| {
                revoke.target == update.target && tid_ge(revoke.sequence, update.sequence)
            }) {
                continue;
            }
            if update.target >= self.superblock.blocks_count {
                return Err(Corrupt::InvalidJournal.into());
            }
            match self
                .overlay
                .binary_search_by_key(&update.target, |(target, _)| *target)
            {
                Ok(index) => self.overlay[index].1 = update.bytes,
                Err(index) => {
                    try_insert(&mut self.overlay, index, (update.target, update.bytes))?;
                }
            }
        }
        Ok(())
    }

    fn load_journal_format(
        &mut self,
        storage: &mut dyn Storage,
        journal: &Journal,
    ) -> Result<Format, Error> {
        let bytes = journal.read(self, storage, 0)?;
        if be32(&bytes, 0) != MAGIC || be32(&bytes, 4) != SUPERBLOCK_V2 {
            return Err(Corrupt::InvalidJournal.into());
        }
        let block_size = be32(&bytes, 0x0c);
        let max_len = be32(&bytes, 0x10);
        let first = be32(&bytes, 0x14);
        let sequence = be32(&bytes, 0x18);
        let start = be32(&bytes, 0x1c);
        let compat = be32(&bytes, 0x24);
        let incompat = be32(&bytes, 0x28);
        let ro_compat = be32(&bytes, 0x2c);
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&bytes[0x30..0x40]);

        let known_incompat = INCOMPAT_REVOKE
            | INCOMPAT_64BIT
            | INCOMPAT_ASYNC_COMMIT
            | INCOMPAT_CSUM_V2
            | INCOMPAT_CSUM_V3
            | INCOMPAT_FAST_COMMIT;
        let unsupported = incompat & !known_incompat;
        if compat & COMPAT_CHECKSUM_V1 != 0
            || compat & !COMPAT_CHECKSUM_V1 != 0
            || ro_compat != 0
            || unsupported != 0
            || incompat & INCOMPAT_FAST_COMMIT != 0
        {
            return Err(Unsupported::JournalFeatures {
                compat,
                incompat,
                ro_compat,
            }
            .into());
        }
        if incompat & INCOMPAT_CSUM_V2 != 0 && incompat & INCOMPAT_CSUM_V3 != 0 {
            return Err(Corrupt::InvalidJournal.into());
        }
        if incompat & INCOMPAT_ASYNC_COMMIT != 0
            && incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) == 0
        {
            return Err(Corrupt::InvalidJournal.into());
        }
        if block_size != self.superblock.block_size
            || max_len < 4
            || u64::from(max_len) > journal.inode.size / u64::from(block_size)
            || first == 0
            || first >= max_len
            || start != 0 && (start < first || start >= max_len)
            || uuid != self.superblock.uuid
        {
            return Err(Corrupt::InvalidJournal.into());
        }
        let checksum_seed = crc32c(u32::MAX, &uuid);
        let format = Format {
            max_len,
            first,
            sequence,
            start,
            incompat,
            uuid,
            checksum_seed,
        };
        if format.has_checksums() {
            if bytes[0x50] != 4 {
                return Err(Unsupported::JournalFeatures {
                    compat,
                    incompat,
                    ro_compat,
                }
                .into());
            }
            let expected = be32(&bytes, 0xfc);
            let checksum = crc32c(
                crc32c(crc32c(u32::MAX, &bytes[..0xfc]), &[0; 4]),
                &bytes[0x100..1024],
            );
            if checksum != expected {
                return Err(Corrupt::JournalChecksum.into());
            }
        }
        Ok(format)
    }

    #[inline(never)]
    fn write_physical_block(
        &mut self,
        storage: &mut dyn Storage,
        physical: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if physical >= self.superblock.blocks_count
            || bytes.len() != self.superblock.block_size as usize
        {
            return Err(Corrupt::InvalidJournal.into());
        }
        let offset = physical
            .checked_mul(u64::from(self.superblock.block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        storage.write(offset, bytes).map_err(Error::Storage)
    }

    #[inline(never)]
    fn flush_storage(&mut self, storage: &mut dyn Storage) -> Result<(), Error> {
        storage.flush().map_err(Error::Storage)
    }
}

fn enable_recovery(block: &mut [u8]) -> Result<(), Error> {
    let offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block.len() as u64)
        .map_err(|_| Corrupt::AddressOverflow)?;
    if offset + ondisk::SUPERBLOCK_SIZE > block.len()
        || crate::ondisk::le16(block, offset + 0x38) != ondisk::EXT4_MAGIC
    {
        return Err(Corrupt::BadMagic.into());
    }
    let incompat = crate::ondisk::le32(block, offset + 0x60) | ondisk::INCOMPAT_RECOVER;
    block[offset + 0x60..offset + 0x64].copy_from_slice(&incompat.to_le_bytes());
    let superblock = &mut block[offset..offset + ondisk::SUPERBLOCK_SIZE];
    let mut checksum = Checksum::new();
    checksum.update(&superblock[..0x3fc]);
    superblock[0x3fc..0x400].copy_from_slice(&checksum.finalize().to_le_bytes());
    Ok(())
}

fn record_journal_offset(
    offsets: &mut Vec<u64>,
    dirty: &[DirtyBlock],
    physical: u64,
) -> Result<(), Error> {
    if dirty.iter().any(|block| block.number == physical) || offsets.contains(&physical) {
        return Err(Corrupt::InvalidJournal.into());
    }
    offsets.push(physical);
    Ok(())
}

fn write_tag(format: Format, bytes: &mut [u8], mut cursor: usize, tag: Tag) -> usize {
    put_be32(bytes, cursor, tag.target as u32);
    if format.csum_v3() {
        put_be32(bytes, cursor + 4, tag.flags);
        put_be32(bytes, cursor + 8, (tag.target >> 32) as u32);
        put_be32(bytes, cursor + 12, tag.checksum);
    } else {
        put_be16(bytes, cursor + 4, 0);
        put_be16(bytes, cursor + 6, tag.flags as u16);
        if format.is_64bit() {
            put_be32(bytes, cursor + 8, (tag.target >> 32) as u32);
        }
    }
    cursor += format.tag_len();
    if tag.flags & FLAG_SAME_UUID == 0 {
        bytes[cursor..cursor + 16].copy_from_slice(&format.uuid);
        cursor += 16;
    }
    cursor
}

#[inline(never)]
fn update_metadata_checksum(format: Format, bytes: &mut [u8]) {
    let tail = bytes.len() - 4;
    bytes[tail..].fill(0);
    let checksum = crc32c(format.checksum_seed, bytes);
    put_be32(bytes, tail, checksum);
}

#[inline(never)]
fn update_commit_checksum(format: Format, bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let checksum = crc32c(format.checksum_seed, bytes);
    put_be32(bytes, 16, checksum);
}

fn update_journal_superblock_checksum(bytes: &mut [u8]) {
    bytes[0xfc..0x100].fill(0);
    let checksum = crc32c(u32::MAX, &bytes[..1024]);
    put_be32(bytes, 0xfc, checksum);
}

#[inline(never)]
fn parse_revokes(
    format: Format,
    sequence: u32,
    bytes: &[u8],
    output: &mut Vec<Revoke>,
) -> Result<(), Error> {
    let count = usize::try_from(be32(bytes, 12)).map_err(|_| Corrupt::InvalidJournal)?;
    let checksum_len = usize::from(format.has_checksums()) * 4;
    if count < 16 || count > bytes.len() - checksum_len {
        return Err(Corrupt::InvalidJournal.into());
    }
    let record_len = if format.is_64bit() { 8 } else { 4 };
    if !(count - 16).is_multiple_of(record_len) {
        return Err(Corrupt::InvalidJournal.into());
    }
    for cursor in (16..count).step_by(record_len) {
        let target = if format.is_64bit() {
            be64(bytes, cursor)
        } else {
            u64::from(be32(bytes, cursor))
        };
        try_push(output, Revoke { sequence, target })?;
    }
    Ok(())
}

#[inline(never)]
fn verify_metadata_checksum(format: Format, bytes: &[u8]) -> Result<(), Error> {
    if !format.has_checksums() {
        return Ok(());
    }
    let tail = bytes.len() - 4;
    let expected = be32(bytes, tail);
    let mut checksum = crc32c(format.checksum_seed, &bytes[..tail]);
    checksum = crc32c(checksum, &[0; 4]);
    if checksum != expected {
        return Err(Corrupt::JournalChecksum.into());
    }
    Ok(())
}

#[inline(never)]
fn verify_data_checksum(
    format: Format,
    sequence: u32,
    tag: &Tag,
    bytes: &[u8],
) -> Result<(), Error> {
    if !format.has_checksums() {
        return Ok(());
    }
    let checksum = crc32c(crc32c(format.checksum_seed, &sequence.to_be_bytes()), bytes);
    let valid = if format.csum_v3() {
        checksum == tag.checksum
    } else {
        checksum as u16 == tag.checksum as u16
    };
    if !valid {
        return Err(Corrupt::JournalChecksum.into());
    }
    Ok(())
}

#[inline(never)]
fn verify_commit_checksum(format: Format, bytes: &[u8]) -> Result<(), Error> {
    if !format.has_checksums() {
        return Ok(());
    }
    let expected = be32(bytes, 16);
    let mut checksum = crc32c(format.checksum_seed, &bytes[..16]);
    checksum = crc32c(checksum, &[0; 4]);
    checksum = crc32c(checksum, &bytes[20..]);
    if checksum != expected {
        return Err(Corrupt::JournalChecksum.into());
    }
    Ok(())
}

#[inline(never)]
fn append<T>(destination: &mut Vec<T>, source: &mut Vec<T>) -> Result<(), Error> {
    destination
        .try_reserve(source.len())
        .map_err(|_| Error::OutOfMemory)?;
    destination.append(source);
    Ok(())
}

fn tid_ge(left: u32, right: u32) -> bool {
    left.wrapping_sub(right) < 0x8000_0000
}

pub(super) fn crc32c(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn be64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn put_be32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_be16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn crc32c_matches_standard_vector_before_final_xor() {
        assert_eq!(crc32c(u32::MAX, b"123456789"), 0x1cf9_6d7c);
    }
}
