//! JBD2 recovery and constrained transaction writing.
//!
//! Recovery retains committed blocks as a volatile overlay. The writer uses
//! explicit durability barriers around activation, commit, checkpoint, and
//! cleanup so every interrupted state is either old or replayable.

use crate::checksum::Checksum;
use crate::ext4::{
    Blob as GraphBlob, Ext4 as Graph, SUPERBLOCK_MAGIC, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE,
};
use crate::overlay::RamOverlay;
use crate::{BlockEdit, Corrupt, Error, Storage, Unsupported, copy_bytes, try_insert, try_push};
use alloc::vec::Vec;

const MAGIC: u32 = 0xc03b_3998;
const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

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

/// JBD2 as a storage transport beneath the graph engine.
pub struct GraphJournal {
    block_size: u32,
    blocks_count: u64,
    uuid: [u8; 16],
    blob: GraphBlob,
    blob_size: u64,
    overlay: RamOverlay,
}

impl GraphJournal {
    pub fn mount(graph: &mut Graph, storage: &mut dyn Storage) -> Result<Self, Error> {
        let blob = graph.journal_blob()?;
        let info = graph.inspect(storage, crate::ext4::Object::Blob(blob))?;
        if info.format & 0xf000 != 0x8000 {
            return Err(Corrupt::InvalidJournal.into());
        }
        let mut journal = Self {
            block_size: graph.block_size,
            blocks_count: graph.blocks_count,
            uuid: graph.uuid,
            blob,
            blob_size: info.size,
            overlay: RamOverlay::default(),
        };
        if graph.needs_recovery() {
            journal.replay(graph, storage)?;
        }
        Ok(journal)
    }

    pub fn read_recovered(
        &self,
        storage: &mut dyn Storage,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Error> {
        offset
            .checked_add(output.len() as u64)
            .filter(|end| *end <= storage.len())
            .ok_or(Corrupt::ReadPastEnd)?;
        storage.read(offset, output).map_err(Error::Storage)?;
        self.overlay
            .apply(u64::from(self.block_size), offset, output);
        Ok(())
    }

    pub(crate) fn read_storage(
        &self,
        storage: &mut dyn Storage,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), crate::StorageError> {
        storage.read(offset, output)?;
        self.overlay
            .apply(u64::from(self.block_size), offset, output);
        Ok(())
    }

    fn buffer(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        Ok(bytes)
    }

    fn physical(
        &self,
        graph: &Graph,
        storage: &mut dyn Storage,
        logical: u32,
    ) -> Result<u64, Error> {
        graph
            .blob_block(storage, self.blob, u64::from(logical))
            .and_then(|block| {
                (block < self.blocks_count)
                    .then_some(block)
                    .ok_or(Corrupt::InvalidJournal.into())
            })
    }

    fn read_log(
        &self,
        graph: &Graph,
        storage: &mut dyn Storage,
        logical: u32,
    ) -> Result<Vec<u8>, Error> {
        let physical = self.physical(graph, storage, logical)?;
        let mut bytes = self.buffer()?;
        self.read_recovered(storage, physical * u64::from(self.block_size), &mut bytes)?;
        Ok(bytes)
    }

    fn format(&self, graph: &Graph, storage: &mut dyn Storage) -> Result<Format, Error> {
        let bytes = self.read_log(graph, storage, 0)?;
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
        let known = INCOMPAT_REVOKE
            | INCOMPAT_64BIT
            | INCOMPAT_ASYNC_COMMIT
            | INCOMPAT_CSUM_V2
            | INCOMPAT_CSUM_V3
            | INCOMPAT_FAST_COMMIT;
        if compat != 0
            || ro_compat != 0
            || incompat & !known != 0
            || incompat & INCOMPAT_FAST_COMMIT != 0
            || incompat & INCOMPAT_CSUM_V2 != 0 && incompat & INCOMPAT_CSUM_V3 != 0
            || incompat & INCOMPAT_ASYNC_COMMIT != 0
                && incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) == 0
            || block_size != self.block_size
            || max_len < 4
            || u64::from(max_len) > self.blob_size / u64::from(block_size)
            || first == 0
            || first >= max_len
            || start != 0 && (start < first || start >= max_len)
            || uuid != self.uuid
        {
            return Err(Corrupt::InvalidJournal.into());
        }
        let format = Format {
            max_len,
            first,
            sequence,
            start,
            incompat,
            uuid,
            checksum_seed: crc32c(u32::MAX, &uuid),
        };
        if format.has_checksums() {
            if bytes[0x50] != 4 {
                return Err(Unsupported::JournalFeatures.into());
            }
            verify_checksum(u32::MAX, &bytes, 0xfc, 1024)?;
        }
        Ok(format)
    }

    fn replay(&mut self, graph: &Graph, storage: &mut dyn Storage) -> Result<(), Error> {
        let format = self.format(graph, storage)?;
        if format.start == 0 {
            return Ok(());
        }
        let mut logged = Vec::new();
        let mut revokes = Vec::new();
        let mut pending_blocks = Vec::new();
        let mut pending_revokes = Vec::new();
        let mut block = format.start;
        let mut sequence = format.sequence;
        let mut visited = 0;
        while visited < format.max_len - format.first {
            let bytes = self.read_log(graph, storage, block)?;
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
                        let mut data = self.read_log(graph, storage, block)?;
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
            if update.target >= self.blocks_count {
                return Err(Corrupt::InvalidJournal.into());
            }
            match self.overlay.index(update.target) {
                Ok(index) => self.overlay.blocks[index].bytes = update.bytes,
                Err(index) => try_insert(
                    &mut self.overlay.blocks,
                    index,
                    BlockEdit {
                        number: update.target,
                        bytes: update.bytes,
                    },
                )?,
            }
        }
        Ok(())
    }

    fn write_block(
        &self,
        storage: &mut dyn Storage,
        physical: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if physical >= self.blocks_count || bytes.len() != self.block_size as usize {
            return Err(Corrupt::InvalidJournal.into());
        }
        storage
            .write(physical * u64::from(self.block_size), bytes)
            .map_err(Error::Storage)
    }

    pub fn commit_blocks(
        &mut self,
        graph: &Graph,
        storage: &mut dyn Storage,
        blocks: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), Error> {
        if blocks.is_empty() {
            return Ok(());
        }
        if !self.overlay.blocks.is_empty() {
            return Err(Unsupported::JournalWriteProfile.into());
        }
        let mut dirty = RamOverlay::default();
        dirty
            .blocks
            .try_reserve_exact(blocks.len())
            .map_err(|_| Error::OutOfMemory)?;
        let mut previous = None;
        for (number, bytes) in blocks {
            if previous.is_some_and(|previous| number <= previous) {
                return Err(Error::InvalidArgument);
            }
            previous = Some(number);
            dirty.blocks.push(BlockEdit { number, bytes });
        }
        let format = self.format(graph, storage)?;
        if format.start != 0
            || (!format.csum_v3() && format.has_checksums())
            || format.incompat & INCOMPAT_ASYNC_COMMIT != 0
        {
            return Err(Unsupported::JournalWriteProfile.into());
        }
        let count = u32::try_from(dirty.blocks.len()).map_err(|_| Error::InvalidArgument)?;
        let commit_logical = format
            .first
            .checked_add(count)
            .and_then(|block| block.checked_add(1))
            .filter(|block| *block < format.max_len)
            .ok_or(Unsupported::JournalWriteProfile)?;
        let capacity = self.block_size as usize - usize::from(format.has_checksums()) * 4;
        let tags_len = dirty
            .blocks
            .len()
            .checked_mul(format.tag_len())
            .and_then(|bytes| bytes.checked_add(28))
            .ok_or(Corrupt::AddressOverflow)?;
        if tags_len > capacity {
            return Err(Unsupported::JournalWriteProfile.into());
        }

        let superblock_target = SUPERBLOCK_OFFSET / u64::from(self.block_size);
        let final_superblock_index = dirty.index(superblock_target).ok();
        let mut activation = self.buffer()?;
        self.read_recovered(
            storage,
            superblock_target * u64::from(self.block_size),
            &mut activation,
        )?;
        let final_superblock = if let Some(index) = final_superblock_index {
            copy_bytes(&dirty.blocks[index].bytes)?
        } else {
            copy_bytes(&activation)?
        };
        enable_recovery(&mut activation)?;
        let mut checkpoint = copy_bytes(&final_superblock)?;
        enable_recovery(&mut checkpoint)?;

        let mut descriptor = self.buffer()?;
        write_header(&mut descriptor, DESCRIPTOR, format.sequence);
        let mut cursor = 12;
        let mut escaped = self.buffer()?;
        for (index, block) in dirty.blocks.iter().enumerate() {
            if block.bytes.len() != self.block_size as usize || block.number >= self.blocks_count {
                return Err(Error::InvalidArgument);
            }
            let (data, escape) = journal_data(block, &mut escaped);
            let mut flags = if index == 0 { 0 } else { FLAG_SAME_UUID };
            if escape {
                flags |= FLAG_ESCAPE;
            }
            if index + 1 == dirty.blocks.len() {
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
            let length = descriptor.len();
            update_checksum(format.checksum_seed, &mut descriptor, length - 4, length);
        }
        let mut commit = self.buffer()?;
        write_header(&mut commit, COMMIT, format.sequence);
        if format.has_checksums() {
            let length = commit.len();
            update_checksum(format.checksum_seed, &mut commit, 16, length);
        }

        let mut active_jsb = self.read_log(graph, storage, 0)?;
        put_be32(&mut active_jsb, 0x18, format.sequence);
        put_be32(&mut active_jsb, 0x1c, format.first);
        if format.has_checksums() {
            update_checksum(u32::MAX, &mut active_jsb, 0xfc, 1024);
        }
        let mut clean_jsb = copy_bytes(&active_jsb)?;
        put_be32(&mut clean_jsb, 0x18, format.sequence.wrapping_add(1));
        put_be32(&mut clean_jsb, 0x1c, 0);
        if format.has_checksums() {
            update_checksum(u32::MAX, &mut clean_jsb, 0xfc, 1024);
        }

        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(dirty.blocks.len() + 3)
            .map_err(|_| Error::OutOfMemory)?;
        record_journal_offset(
            &mut offsets,
            &dirty.blocks,
            self.physical(graph, storage, 0)?,
        )?;
        for logical in format.first..=commit_logical {
            record_journal_offset(
                &mut offsets,
                &dirty.blocks,
                self.physical(graph, storage, logical)?,
            )?;
        }
        let journal_super = offsets[0];
        let descriptor_block = offsets[1];
        let commit_block = *offsets.last().ok_or(Corrupt::InvalidJournal)?;

        self.write_block(storage, descriptor_block, &descriptor)?;
        for (index, block) in dirty.blocks.iter().enumerate() {
            let (bytes, _) = journal_data(block, &mut escaped);
            self.write_block(storage, offsets[index + 2], bytes)?;
        }
        storage.flush().map_err(Error::Storage)?;
        self.write_block(storage, superblock_target, &activation)?;
        self.write_block(storage, journal_super, &active_jsb)?;
        storage.flush().map_err(Error::Storage)?;
        self.write_block(storage, commit_block, &commit)?;
        storage.flush().map_err(Error::Storage)?;

        let committed = dirty;
        let checkpoint_result = (|| {
            for block in &committed.blocks {
                self.write_block(
                    storage,
                    block.number,
                    if block.number == superblock_target {
                        &checkpoint
                    } else {
                        &block.bytes
                    },
                )?;
            }
            storage.flush().map_err(Error::Storage)?;
            self.write_block(storage, superblock_target, &final_superblock)?;
            self.write_block(storage, journal_super, &clean_jsb)?;
            storage.flush().map_err(Error::Storage)
        })();
        match checkpoint_result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.overlay = committed;
                Err(error)
            }
        }
    }
}

fn journal_data<'a>(block: &'a BlockEdit, escaped: &'a mut [u8]) -> (&'a [u8], bool) {
    let escape = be32(&block.bytes, 0) == MAGIC;
    if escape {
        escaped.copy_from_slice(&block.bytes);
        escaped[..4].fill(0);
        (escaped, true)
    } else {
        (&block.bytes, false)
    }
}

fn enable_recovery(block: &mut [u8]) -> Result<(), Error> {
    let offset = usize::try_from(SUPERBLOCK_OFFSET % block.len() as u64)
        .map_err(|_| Corrupt::AddressOverflow)?;
    if offset + SUPERBLOCK_SIZE > block.len()
        || u16::from_le_bytes([block[offset + 0x38], block[offset + 0x39]]) != SUPERBLOCK_MAGIC
    {
        return Err(Corrupt::BadMagic.into());
    }
    let incompat = u32::from_le_bytes([
        block[offset + 0x60],
        block[offset + 0x61],
        block[offset + 0x62],
        block[offset + 0x63],
    ]) | 0x0004;
    block[offset + 0x60..offset + 0x64].copy_from_slice(&incompat.to_le_bytes());
    let superblock = &mut block[offset..offset + SUPERBLOCK_SIZE];
    let mut checksum = Checksum::new();
    checksum.update(&superblock[..0x3fc]);
    superblock[0x3fc..0x400].copy_from_slice(&checksum.finalize().to_le_bytes());
    Ok(())
}

fn record_journal_offset(
    offsets: &mut Vec<u64>,
    dirty: &[BlockEdit],
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

fn write_header(bytes: &mut [u8], kind: u32, sequence: u32) {
    put_be32(bytes, 0, MAGIC);
    put_be32(bytes, 4, kind);
    put_be32(bytes, 8, sequence);
}

#[inline(never)]
fn update_checksum(seed: u32, bytes: &mut [u8], field: usize, length: usize) {
    bytes[field..field + 4].fill(0);
    let checksum = crc32c(seed, &bytes[..length]);
    put_be32(bytes, field, checksum);
}

#[inline(never)]
fn verify_checksum(seed: u32, bytes: &[u8], field: usize, length: usize) -> Result<(), Error> {
    let expected = be32(bytes, field);
    let checksum = crc32c(crc32c(seed, &bytes[..field]), &[0; 4]);
    if crc32c(checksum, &bytes[field + 4..length]) != expected {
        return Err(Corrupt::JournalChecksum.into());
    }
    Ok(())
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
    verify_checksum(format.checksum_seed, bytes, bytes.len() - 4, bytes.len())
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
    verify_checksum(format.checksum_seed, bytes, 16, bytes.len())
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
