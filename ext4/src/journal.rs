//! JBD2 recovery and constrained transaction writing.
//!
//! Recovery retains committed blocks as a volatile overlay. The writer uses
//! explicit durability barriers around activation, commit, checkpoint, and
//! cleanup so every interrupted state is either old or replayable.

use crate::checksum::Checksum;
use crate::ext4::{
    Blob as GraphBlob, Ext4 as Graph, Le32, SUPERBLOCK_MAGIC, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE,
    Superblock,
};
use crate::overlay::BlockChanges;
use crate::{BlockEdit, Corrupt, Error, Storage, Unsupported, copy_bytes, try_insert, try_push};
use alloc::vec::Vec;
use bytemuck::{Pod, Zeroable};
use core::mem::{offset_of, size_of};

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
const EXT4_INCOMPAT_RECOVER: u32 = 0x0004;

macro_rules! big_endian {
    ($name:ident, $native:ty, $size:expr) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Pod, Zeroable)]
        struct $name([u8; $size]);

        impl $name {
            const fn new(value: $native) -> Self {
                Self(value.to_be_bytes())
            }

            const fn get(self) -> $native {
                <$native>::from_be_bytes(self.0)
            }
        }
    };
}

big_endian!(Be16, u16, 2);
big_endian!(Be32, u32, 4);

#[repr(transparent)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Be64([u8; 8]);

impl Be64 {
    const fn get(self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalHeader {
    magic: Be32,
    kind: Be32,
    sequence: Be32,
}

impl JournalHeader {
    fn new(kind: u32, sequence: u32) -> Self {
        Self {
            magic: Be32::new(MAGIC),
            kind: Be32::new(kind),
            sequence: Be32::new(sequence),
        }
    }
}

/// The complete 1024-byte JBD2 superblock.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalSuperblock {
    header: JournalHeader,
    block_size: Be32,
    max_len: Be32,
    first: Be32,
    sequence: Be32,
    start: Be32,
    errno: Be32,
    compatible: Be32,
    incompatible: Be32,
    read_only_compatible: Be32,
    uuid: [u8; 16],
    users: Be32,
    dynamic_superblock: Be32,
    max_transaction: Be32,
    max_transaction_data: Be32,
    checksum_type: u8,
    padding: [u8; 3],
    reserved: [Be32; 42],
    checksum: Be32,
    user_ids: [[u8; 48]; 16],
}

impl JournalSuperblock {
    fn set_state(
        bytes: &mut [u8],
        sequence: u32,
        start: u32,
        checksummed: bool,
    ) -> Result<(), Error> {
        let mut disk = record_at::<Self>(bytes, 0)?;
        disk.sequence = Be32::new(sequence);
        disk.start = Be32::new(start);
        write_record_at(bytes, 0, &disk)?;
        if checksummed {
            update_checksum(
                u32::MAX,
                bytes,
                offset_of!(Self, checksum),
                size_of::<Self>(),
            );
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalCommitHeader {
    header: JournalHeader,
    checksum_type: u8,
    checksum_size: u8,
    padding: [u8; 2],
    checksum: [Be32; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalRevokeHeader {
    header: JournalHeader,
    count: Be32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalTag32 {
    target: Be32,
    checksum: Be16,
    flags: Be16,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalTag64 {
    lo: JournalTag32,
    target_high: Be32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct JournalTag3 {
    target: Be32,
    flags: Be32,
    target_high: Be32,
    checksum: Be32,
}

const _: [(); 12] = [(); size_of::<JournalHeader>()];
const _: [(); 1024] = [(); size_of::<JournalSuperblock>()];
const _: [(); 48] = [(); size_of::<JournalCommitHeader>()];
const _: [(); 16] = [(); size_of::<JournalRevokeHeader>()];
const _: [(); 8] = [(); size_of::<JournalTag32>()];
const _: [(); 12] = [(); size_of::<JournalTag64>()];
const _: [(); 16] = [(); size_of::<JournalTag3>()];

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
            size_of::<JournalTag3>()
        } else if self.is_64bit() {
            size_of::<JournalTag64>()
        } else {
            size_of::<JournalTag32>()
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

/// A bounded walk through the circular data area of a JBD2 log.
struct JournalRing {
    format: Format,
    next: u32,
    remaining: u32,
}

impl JournalRing {
    fn new(format: Format) -> Self {
        Self {
            format,
            next: format.start,
            remaining: format.max_len - format.first,
        }
    }

    fn take(&mut self) -> Option<u32> {
        if self.remaining == 0 {
            return None;
        }
        let block = self.next;
        self.next = self.format.advance(block);
        self.remaining -= 1;
        Some(block)
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
            cursor: size_of::<JournalHeader>(),
            end: bytes.len() - usize::from(format.has_checksums()) * size_of::<Be32>(),
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
        let (low, flags, checksum, high) = if self.format.csum_v3() {
            let tag = record_at::<JournalTag3>(self.bytes, self.cursor)?;
            (
                tag.target.get(),
                tag.flags.get(),
                tag.checksum.get(),
                tag.target_high.get(),
            )
        } else if self.format.is_64bit() {
            let tag = record_at::<JournalTag64>(self.bytes, self.cursor)?;
            (
                tag.lo.target.get(),
                u32::from(tag.lo.flags.get()),
                u32::from(tag.lo.checksum.get()),
                tag.target_high.get(),
            )
        } else {
            let tag = record_at::<JournalTag32>(self.bytes, self.cursor)?;
            (
                tag.target.get(),
                u32::from(tag.flags.get()),
                u32::from(tag.checksum.get()),
                0,
            )
        };
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Corrupt::InvalidJournal.into());
        }
        self.cursor += tag_len;
        if flags & FLAG_SAME_UUID == 0 {
            if self.cursor + self.format.uuid.len() > self.end
                || self.bytes[self.cursor..self.cursor + self.format.uuid.len()] != self.format.uuid
            {
                return Err(Corrupt::InvalidJournal.into());
            }
            self.cursor += self.format.uuid.len();
            self.have_uuid = true;
        } else if !self.have_uuid {
            return Err(Corrupt::InvalidJournal.into());
        }
        self.finished = flags & FLAG_LAST != 0;
        Ok(Some(Tag {
            target: u64::from(low) | (u64::from(high) << 32),
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
    overlay: BlockChanges,
}

impl GraphJournal {
    #[inline(never)]
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
            overlay: BlockChanges::default(),
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
        let disk = record_at::<JournalSuperblock>(&bytes, 0)?;
        if disk.header.magic.get() != MAGIC || disk.header.kind.get() != SUPERBLOCK_V2 {
            return Err(Corrupt::InvalidJournal.into());
        }
        let block_size = disk.block_size.get();
        let max_len = disk.max_len.get();
        let first = disk.first.get();
        let sequence = disk.sequence.get();
        let start = disk.start.get();
        let compat = disk.compatible.get();
        let incompat = disk.incompatible.get();
        let ro_compat = disk.read_only_compatible.get();
        let uuid = disk.uuid;
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
            if disk.checksum_type != 4 {
                return Err(Unsupported::JournalFeatures.into());
            }
            verify_checksum(
                u32::MAX,
                &bytes,
                offset_of!(JournalSuperblock, checksum),
                size_of::<JournalSuperblock>(),
            )?;
        }
        Ok(format)
    }

    #[inline(never)]
    fn replay(&mut self, graph: &Graph, storage: &mut dyn Storage) -> Result<(), Error> {
        let format = self.format(graph, storage)?;
        if format.start == 0 {
            return Ok(());
        }
        let mut logged = Vec::new();
        let mut revokes = Vec::new();
        let mut committed_blocks = 0;
        let mut committed_revokes = 0;
        let mut sequence = format.sequence;
        let mut ring = JournalRing::new(format);
        while let Some(block) = ring.take() {
            let bytes = self.read_log(graph, storage, block)?;
            let header = record_at::<JournalHeader>(&bytes, 0)?;
            if header.magic.get() != MAGIC || header.sequence.get() != sequence {
                break;
            }
            match header.kind.get() {
                DESCRIPTOR => {
                    verify_metadata_checksum(format, &bytes)?;
                    let mut tags = Tags::new(format, &bytes);
                    while let Some(tag) = tags.next()? {
                        let block = ring.take().ok_or(Corrupt::InvalidJournal)?;
                        let mut data = self.read_log(graph, storage, block)?;
                        verify_data_checksum(format, sequence, &tag, &data)?;
                        if tag.flags & FLAG_ESCAPE != 0 {
                            write_record_at(&mut data, 0, &Be32::new(MAGIC))?;
                        }
                        if tag.flags & FLAG_DELETED == 0 {
                            try_push(
                                &mut logged,
                                LoggedBlock {
                                    sequence,
                                    target: tag.target,
                                    bytes: data,
                                },
                            )?;
                        }
                    }
                    continue;
                }
                REVOKE => {
                    if format.incompat & INCOMPAT_REVOKE == 0 {
                        return Err(Corrupt::InvalidJournal.into());
                    }
                    verify_metadata_checksum(format, &bytes)?;
                    parse_revokes(format, sequence, &bytes, &mut revokes)?;
                }
                COMMIT => {
                    verify_commit_checksum(format, &bytes)?;
                    committed_blocks = logged.len();
                    committed_revokes = revokes.len();
                    sequence = sequence.wrapping_add(1);
                }
                _ => break,
            }
        }
        logged.truncate(committed_blocks);
        revokes.truncate(committed_revokes);
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

    #[inline(never)]
    fn encode_descriptor(
        &self,
        format: Format,
        dirty: &BlockChanges,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let capacity = self.block_size as usize - usize::from(format.has_checksums()) * 4;
        let tags_len = dirty
            .blocks
            .len()
            .checked_mul(format.tag_len())
            .and_then(|bytes| bytes.checked_add(size_of::<JournalHeader>() + format.uuid.len()))
            .ok_or(Corrupt::AddressOverflow)?;
        if tags_len > capacity {
            return Err(Unsupported::JournalWriteProfile.into());
        }

        let mut descriptor = self.buffer()?;
        write_record_at(
            &mut descriptor,
            0,
            &JournalHeader::new(DESCRIPTOR, format.sequence),
        )?;
        let mut cursor = size_of::<JournalHeader>();
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
            )?;
        }
        if format.has_checksums() {
            let length = descriptor.len();
            update_checksum(format.checksum_seed, &mut descriptor, length - 4, length);
        }
        Ok((descriptor, escaped))
    }

    #[inline(never)]
    fn journal_offsets(
        &self,
        graph: &Graph,
        storage: &mut dyn Storage,
        format: Format,
        commit: u32,
        dirty: &BlockChanges,
    ) -> Result<Vec<u64>, Error> {
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(dirty.blocks.len() + 3)
            .map_err(|_| Error::OutOfMemory)?;
        record_journal_offset(
            &mut offsets,
            &dirty.blocks,
            self.physical(graph, storage, 0)?,
        )?;
        for logical in format.first..=commit {
            record_journal_offset(
                &mut offsets,
                &dirty.blocks,
                self.physical(graph, storage, logical)?,
            )?;
        }
        Ok(offsets)
    }

    #[inline(never)]
    pub fn commit_blocks(
        &mut self,
        graph: &Graph,
        storage: &mut dyn Storage,
        blocks: BlockChanges,
    ) -> Result<(), Error> {
        if blocks.blocks.is_empty() {
            return Ok(());
        }
        if !self.overlay.blocks.is_empty() {
            return Err(Unsupported::JournalWriteProfile.into());
        }
        let dirty = blocks;
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
        let mut final_superblock = final_superblock;
        let recovery_fields = enable_recovery(&mut final_superblock)?;

        let (mut descriptor, mut escaped) = self.encode_descriptor(format, &dirty)?;
        let mut active_jsb = self.read_log(graph, storage, 0)?;
        JournalSuperblock::set_state(
            &mut active_jsb,
            format.sequence,
            format.first,
            format.has_checksums(),
        )?;
        let offsets = self.journal_offsets(graph, storage, format, commit_logical, &dirty)?;
        let journal_super = offsets[0];
        let descriptor_block = offsets[1];
        let commit_block = *offsets.last().ok_or(Corrupt::InvalidJournal)?;

        self.write_block(storage, descriptor_block, &descriptor)?;
        for (index, block) in dirty.blocks.iter().enumerate() {
            let (bytes, _) = journal_data(block, &mut escaped);
            self.write_block(storage, offsets[index + 2], bytes)?;
        }
        storage.flush().map_err(Error::Storage)?;

        descriptor.fill(0);
        write_record_at(
            &mut descriptor,
            0,
            &JournalHeader::new(COMMIT, format.sequence),
        )?;
        if format.has_checksums() {
            let length = descriptor.len();
            update_checksum(
                format.checksum_seed,
                &mut descriptor,
                offset_of!(JournalCommitHeader, checksum),
                length,
            );
        }
        self.write_block(storage, superblock_target, &activation)?;
        self.write_block(storage, journal_super, &active_jsb)?;
        storage.flush().map_err(Error::Storage)?;
        self.write_block(storage, commit_block, &descriptor)?;
        storage.flush().map_err(Error::Storage)?;

        JournalSuperblock::set_state(
            &mut active_jsb,
            format.sequence.wrapping_add(1),
            0,
            format.has_checksums(),
        )?;

        let committed = dirty;
        let checkpoint_result = (|| {
            for block in &committed.blocks {
                self.write_block(
                    storage,
                    block.number,
                    if block.number == superblock_target {
                        &final_superblock
                    } else {
                        &block.bytes
                    },
                )?;
            }
            storage.flush().map_err(Error::Storage)?;
            restore_recovery(&mut final_superblock, recovery_fields)?;
            self.write_block(storage, superblock_target, &final_superblock)?;
            self.write_block(storage, journal_super, &active_jsb)?;
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
    let escape = record_at::<Be32>(&block.bytes, 0).is_ok_and(|magic| magic.get() == MAGIC);
    if escape {
        escaped.copy_from_slice(&block.bytes);
        escaped[..size_of::<Be32>()].fill(0);
        (escaped, true)
    } else {
        (&block.bytes, false)
    }
}

#[derive(Clone, Copy)]
struct RecoveryFields {
    incompatible: Le32,
    checksum: Le32,
}

fn superblock_in_block(block: &mut [u8]) -> Result<&mut Superblock, Error> {
    let offset = usize::try_from(SUPERBLOCK_OFFSET % block.len() as u64)
        .map_err(|_| Corrupt::AddressOverflow)?;
    let end = offset
        .checked_add(SUPERBLOCK_SIZE)
        .filter(|end| *end <= block.len())
        .ok_or(Corrupt::BadMagic)?;
    Ok(bytemuck::from_bytes_mut::<Superblock>(
        &mut block[offset..end],
    ))
}

fn enable_recovery(block: &mut [u8]) -> Result<RecoveryFields, Error> {
    let superblock = superblock_in_block(block)?;
    if superblock.magic.get() != SUPERBLOCK_MAGIC {
        return Err(Corrupt::BadMagic.into());
    }
    let previous = RecoveryFields {
        incompatible: superblock.feature_incompat,
        checksum: superblock.checksum,
    };
    superblock.feature_incompat =
        Le32::new(superblock.feature_incompat.get() | EXT4_INCOMPAT_RECOVER);
    superblock.checksum = Le32::new(0);
    let mut checksum = Checksum::new();
    checksum.update(&bytemuck::bytes_of(superblock)[..offset_of!(Superblock, checksum)]);
    superblock.checksum = Le32::new(checksum.finalize());
    Ok(previous)
}

fn restore_recovery(block: &mut [u8], fields: RecoveryFields) -> Result<(), Error> {
    let superblock = superblock_in_block(block)?;
    superblock.feature_incompat = fields.incompatible;
    superblock.checksum = fields.checksum;
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

fn write_tag(
    format: Format,
    bytes: &mut [u8],
    mut cursor: usize,
    tag: Tag,
) -> Result<usize, Error> {
    if format.csum_v3() {
        write_record_at(
            bytes,
            cursor,
            &JournalTag3 {
                target: Be32::new(tag.target as u32),
                flags: Be32::new(tag.flags),
                target_high: Be32::new((tag.target >> 32) as u32),
                checksum: Be32::new(tag.checksum),
            },
        )?;
    } else if format.is_64bit() {
        write_record_at(
            bytes,
            cursor,
            &JournalTag64 {
                lo: JournalTag32 {
                    target: Be32::new(tag.target as u32),
                    checksum: Be16::new(0),
                    flags: Be16::new(tag.flags as u16),
                },
                target_high: Be32::new((tag.target >> 32) as u32),
            },
        )?;
    } else {
        write_record_at(
            bytes,
            cursor,
            &JournalTag32 {
                target: Be32::new(tag.target as u32),
                checksum: Be16::new(0),
                flags: Be16::new(tag.flags as u16),
            },
        )?;
    }
    cursor += format.tag_len();
    if tag.flags & FLAG_SAME_UUID == 0 {
        bytes[cursor..cursor + format.uuid.len()].copy_from_slice(&format.uuid);
        cursor += format.uuid.len();
    }
    Ok(cursor)
}

#[inline(never)]
fn update_checksum(seed: u32, bytes: &mut [u8], field: usize, length: usize) {
    let checksum = checksum_with_zero(seed, bytes, field, length);
    bytes[field..field + size_of::<Be32>()]
        .copy_from_slice(bytemuck::bytes_of(&Be32::new(checksum)));
}

#[inline(never)]
fn verify_checksum(seed: u32, bytes: &[u8], field: usize, length: usize) -> Result<(), Error> {
    let expected = record_at::<Be32>(bytes, field)?.get();
    if checksum_with_zero(seed, bytes, field, length) != expected {
        return Err(Corrupt::JournalChecksum.into());
    }
    Ok(())
}

#[inline(never)]
fn checksum_with_zero(seed: u32, bytes: &[u8], field: usize, length: usize) -> u32 {
    let checksum = crc32c(crc32c(seed, &bytes[..field]), &[0; size_of::<Be32>()]);
    crc32c(checksum, &bytes[field + size_of::<Be32>()..length])
}

#[inline(never)]
fn parse_revokes(
    format: Format,
    sequence: u32,
    bytes: &[u8],
    output: &mut Vec<Revoke>,
) -> Result<(), Error> {
    let header = record_at::<JournalRevokeHeader>(bytes, 0)?;
    let count = usize::try_from(header.count.get()).map_err(|_| Corrupt::InvalidJournal)?;
    let checksum_len = usize::from(format.has_checksums()) * size_of::<Be32>();
    if count < size_of::<JournalRevokeHeader>() || count > bytes.len() - checksum_len {
        return Err(Corrupt::InvalidJournal.into());
    }
    let record_len = if format.is_64bit() {
        size_of::<Be64>()
    } else {
        size_of::<Be32>()
    };
    if !(count - size_of::<JournalRevokeHeader>()).is_multiple_of(record_len) {
        return Err(Corrupt::InvalidJournal.into());
    }
    for cursor in (size_of::<JournalRevokeHeader>()..count).step_by(record_len) {
        let target = if format.is_64bit() {
            record_at::<Be64>(bytes, cursor)?.get()
        } else {
            u64::from(record_at::<Be32>(bytes, cursor)?.get())
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
    verify_checksum(
        format.checksum_seed,
        bytes,
        offset_of!(JournalCommitHeader, checksum),
        bytes.len(),
    )
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

fn record_at<T: Pod>(bytes: &[u8], offset: usize) -> Result<T, Error> {
    bytes
        .get(offset..offset + size_of::<T>())
        .map(|bytes| *bytemuck::from_bytes(bytes))
        .ok_or(Corrupt::InvalidJournal.into())
}

fn write_record_at<T: Pod>(bytes: &mut [u8], offset: usize, record: &T) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset + size_of::<T>())
        .ok_or(Corrupt::InvalidJournal)?
        .copy_from_slice(bytemuck::bytes_of(record));
    Ok(())
}
