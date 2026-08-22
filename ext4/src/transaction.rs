//! Transaction-private dirty blocks and fallible memory reservations.
//!
//! Dirty blocks remain isolated until [`Transaction::commit`] serializes them
//! through the internal JBD2 journal.

use crate::checksum::Checksum;
use crate::ondisk::{self, le16, le32};
use crate::{
    Corrupt, DirectoryEntry, Error, Ext4, FsError, Inode, InodeMetadataUpdate, Storage, Timestamp,
    Unsupported,
};
use alloc::vec::Vec;

pub(crate) struct DirtyBlock {
    pub(crate) number: u64,
    pub(crate) bytes: Vec<u8>,
}

/// Typed access to one ext inode record.
///
/// Filesystem operations express metadata changes here; byte offsets and ext4
/// timestamp encoding do not escape into namespace or policy-shaped APIs.
struct InodeEditor<'a> {
    raw: &'a mut [u8],
    checksum_seed: u32,
    number: u32,
    generation: u32,
}

impl<'a> InodeEditor<'a> {
    fn new(
        raw: &'a mut [u8],
        checksum_seed: u32,
        number: u32,
        generation: u32,
    ) -> Result<Self, Corrupt> {
        if raw.len() < 128 || number == 0 {
            return Err(Corrupt::InvalidInode(number));
        }
        Ok(Self {
            raw,
            checksum_seed,
            number,
            generation,
        })
    }

    fn set_links(&mut self, links: u16) {
        put_le16(self.raw, 0x1a, links);
    }

    fn set_extent_mapping<E>(
        &mut self,
        physical: &[u64],
        size: u64,
        block_size: u64,
        nodes: &mut [DirtyBlock],
    ) -> Result<(), Error<E>> {
        write_extent_mapping(
            self.raw,
            physical,
            size,
            block_size,
            (self.checksum_seed, self.number, self.generation),
            nodes,
        )
    }

    fn clear_extent_mapping<E>(&mut self) -> Result<(), Error<E>> {
        let root = self
            .raw
            .get(0x28..0x64)
            .ok_or(Corrupt::InvalidInode(self.number))?;
        if le16(root, 0) != super::EXTENT_MAGIC {
            return Err(Unsupported::ExtentMutation.into());
        }
        put_le32(self.raw, 4, 0);
        put_le32(self.raw, 0x6c, 0);
        put_le32(self.raw, 0x1c, 0);
        put_le16(self.raw, 0x74, 0);
        let root = &mut self.raw[0x28..0x64];
        root.fill(0);
        put_le16(root, 0, super::EXTENT_MAGIC);
        put_le16(root, 4, 4);
        Ok(())
    }

    fn initialize_regular(&mut self, permissions: u16) {
        initialize_empty_inode(self.raw, permissions);
    }

    fn initialize_fast_symlink<E>(&mut self, target: &[u8]) -> Result<(), Error<E>> {
        initialize_fast_symlink(self.raw, target)
    }

    fn initialize_directory<E>(
        &mut self,
        permissions: u16,
        physical: u64,
        block_size: u64,
    ) -> Result<(), Error<E>> {
        initialize_directory_inode(self.raw, permissions, physical, block_size)
    }

    fn apply_metadata<E>(&mut self, update: InodeMetadataUpdate) -> Result<(), Error<E>> {
        if let Some(permissions) = update.permissions {
            if permissions & !0o7777 != 0 {
                return Err(Error::InvalidArgument);
            }
            let file_type = le16(self.raw, 0) & 0xf000;
            put_le16(self.raw, 0, file_type | permissions);
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

    fn set_timestamp<E>(
        &mut self,
        seconds_offset: usize,
        extra_offset: usize,
        timestamp: Timestamp,
    ) -> Result<(), Error<E>> {
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

    fn finish(self) {
        update_inode_checksum(self.checksum_seed, self.number, self.generation, self.raw);
    }
}

/// A prospective metadata change keyed by physical filesystem block.
///
/// Namespace operations often touch several logical objects which happen to
/// share a descriptor or inode-table block.  Keeping those edits in one cache
/// makes that aliasing ordinary instead of forcing every operation to build a
/// list of supposedly-distinct block numbers and special-case collisions.
struct MetadataMutation {
    blocks: Vec<DirtyBlock>,
}

impl MetadataMutation {
    fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    fn load<S: Storage>(
        &mut self,
        transaction: &mut TransactionIo<'_, '_, S>,
        number: u64,
    ) -> Result<(), Error<S::Error>> {
        let Err(index) = self.index(number) else {
            return Ok(());
        };
        let bytes = transaction.read_owned_block(number)?;
        self.blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.blocks.insert(index, DirtyBlock { number, bytes });
        Ok(())
    }

    fn adopt<E>(&mut self, number: u64, bytes: Vec<u8>) -> Result<(), Error<E>> {
        let index = match self.index(number) {
            Ok(_) => return Err(Corrupt::InvalidDirectory.into()),
            Err(index) => index,
        };
        self.blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.blocks.insert(index, DirtyBlock { number, bytes });
        Ok(())
    }

    fn adopt_block<E>(&mut self, block: DirtyBlock) -> Result<(), Error<E>> {
        self.adopt(block.number, block.bytes)
    }

    fn adopt_blocks<E>(
        &mut self,
        blocks: impl IntoIterator<Item = DirtyBlock>,
    ) -> Result<(), Error<E>> {
        for block in blocks {
            self.adopt_block(block)?;
        }
        Ok(())
    }

    fn adopt_group_edits<E>(&mut self, groups: Vec<GroupEdit>) -> Result<(), Error<E>> {
        for group in groups {
            if let Some(bitmap) = group.block_bitmap {
                self.adopt_block(bitmap)?;
            }
        }
        Ok(())
    }

    fn get_mut(&mut self, number: u64) -> Result<&mut [u8], Corrupt> {
        let index = self.index(number).map_err(|_| Corrupt::InvalidDirectory)?;
        Ok(&mut self.blocks[index].bytes)
    }

    fn edit_inode<S: Storage, F>(
        &mut self,
        transaction: &mut TransactionIo<'_, '_, S>,
        inode: &Inode,
        edit: F,
    ) -> Result<(), Error<S::Error>>
    where
        F: FnOnce(&mut InodeEditor<'_>) -> Result<(), Error<S::Error>>,
    {
        let (block_number, offset) = transaction.inode_location(inode.number)?;
        let inode_size = usize::from(transaction.filesystem.superblock.inode_size);
        let checksum_seed = transaction.filesystem.superblock.checksum_seed;
        self.load(transaction, block_number)?;
        let block = self.get_mut(block_number)?;
        let end = offset
            .checked_add(inode_size)
            .filter(|end| *end <= block.len())
            .ok_or(Corrupt::InvalidInodeTable)?;
        let raw = &mut block[offset..end];
        let mut editor = InodeEditor::new(raw, checksum_seed, inode.number, inode.generation)?;
        edit(&mut editor)?;
        editor.finish();
        Ok(())
    }

    fn stage<S: Storage>(
        self,
        transaction: &mut TransactionIo<'_, '_, S>,
    ) -> Result<(), Error<S::Error>> {
        if transaction.available.len() < self.blocks.len() {
            return Err(Error::ReservationExhausted);
        }
        for block in self.blocks {
            transaction.write_block(block.number, &block.bytes)?;
        }
        Ok(())
    }

    fn index(&self, number: u64) -> Result<usize, usize> {
        self.blocks
            .binary_search_by_key(&number, |block| block.number)
    }
}

/// Typed access to one checked directory leaf.
///
/// The inode identity and checksum seed travel with the block, so namespace
/// code only expresses entry operations and cannot accidentally checksum a
/// directory block as a different inode.
struct DirectoryEditor<'a> {
    checksum_seed: u32,
    inode: &'a Inode,
    bytes: &'a mut [u8],
}

struct DirectoryNode {
    logical: u64,
    kind: crate::DirectoryBlockKind,
    block: DirtyBlock,
    dirty: bool,
}

/// A checked, representation-aware directory mutation view.
///
/// Namespace operations deal in names and inode numbers; this object owns the
/// mapping from those operations to physical leaf blocks.  Loading, checksum
/// validation, duplicate detection, and multi-block scanning happen once.
struct DirectoryTree {
    checksum_seed: u32,
    inode: Inode,
    nodes: Vec<DirectoryNode>,
}

impl DirectoryTree {
    fn load<S: Storage>(
        transaction: &mut TransactionIo<'_, '_, S>,
        inode: &Inode,
    ) -> Result<Self, Error<S::Error>> {
        if !inode.is_directory() {
            return Err(Error::NotDirectory);
        }
        let block_size = u64::from(transaction.filesystem.superblock.block_size);
        if inode.size == 0 || !inode.size.is_multiple_of(block_size) {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let count = inode.size / block_size;
        let count_usize = usize::try_from(count).map_err(|_| Corrupt::AddressOverflow)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(count_usize)
            .map_err(|_| Error::OutOfMemory)?;
        for logical in 0..count {
            let physical = transaction
                .map_file_block(inode, logical)?
                .ok_or(Corrupt::InvalidDirectory)?;
            if nodes
                .iter()
                .any(|node: &DirectoryNode| node.block.number == physical)
            {
                return Err(Corrupt::InvalidDirectory.into());
            }
            let bytes = transaction.read_owned_block(physical)?;
            let kind =
                transaction
                    .filesystem
                    .directory_block_kind(inode, logical, bytes.len(), &bytes);
            transaction
                .filesystem
                .verify_directory_checksum(inode, kind, bytes.len(), &bytes)?;
            nodes.push(DirectoryNode {
                logical,
                kind,
                block: DirtyBlock {
                    number: physical,
                    bytes,
                },
                dirty: false,
            });
        }
        Ok(Self {
            checksum_seed: transaction.filesystem.superblock.checksum_seed,
            inode: inode.clone(),
            nodes,
        })
    }

    fn insert<E>(&mut self, number: u32, name: &[u8], kind: u8) -> Result<(), Error<E>> {
        if self.find(name)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        // Choosing an arbitrary checked leaf is correct for a linear directory.
        // HTree insertion additionally needs hash-directed selection/splitting.
        if self.inode.flags & super::DIRECTORY_INDEX_FL != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        for node in &mut self.nodes {
            if node.kind != crate::DirectoryBlockKind::Leaf {
                continue;
            }
            match DirectoryEditor::new(self.checksum_seed, &self.inode, &mut node.block.bytes)
                .insert(number, name, kind)
            {
                Ok(()) => {
                    node.dirty = true;
                    return Ok(());
                }
                Err(Error::Unsupported(Unsupported::ExtentMutation)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Unsupported::ExtentMutation.into())
    }

    fn remove<E>(&mut self, number: u32, name: &[u8]) -> Result<(), Error<E>> {
        let index = self
            .find(name)?
            .filter(|(_, found)| *found == number)
            .map(|(index, _)| index)
            .ok_or(Error::NotFound)?;
        let node = &mut self.nodes[index];
        DirectoryEditor::new(self.checksum_seed, &self.inode, &mut node.block.bytes)
            .remove(number, name)?;
        node.dirty = true;
        Ok(())
    }

    fn replace<E>(
        &mut self,
        old_number: u32,
        new_number: u32,
        name: &[u8],
        kind: u8,
    ) -> Result<(), Error<E>> {
        let index = self
            .find(name)?
            .filter(|(_, found)| *found == old_number)
            .map(|(index, _)| index)
            .ok_or(Error::NotFound)?;
        let node = &mut self.nodes[index];
        DirectoryEditor::new(self.checksum_seed, &self.inode, &mut node.block.bytes)
            .replace(old_number, new_number, name, kind)?;
        node.dirty = true;
        Ok(())
    }

    fn set_parent<E>(&mut self, old_parent: u32, new_parent: u32) -> Result<(), Error<E>> {
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.logical == 0)
            .ok_or(Corrupt::InvalidDirectory)?;
        match node.kind {
            crate::DirectoryBlockKind::Leaf => {
                DirectoryEditor::new(self.checksum_seed, &self.inode, &mut node.block.bytes)
                    .set_parent(old_parent, new_parent)?;
            }
            crate::DirectoryBlockKind::Root => {
                if node.block.bytes.len() < 24
                    || le32(&node.block.bytes, 12) != old_parent
                    || le16(&node.block.bytes, 16) < 12
                    || node.block.bytes[18] != 2
                    || &node.block.bytes[20..22] != b".."
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                put_le32(&mut node.block.bytes, 12, new_parent);
                update_directory_index_checksum(
                    self.checksum_seed,
                    &self.inode,
                    node.kind,
                    &mut node.block.bytes,
                )?;
            }
            crate::DirectoryBlockKind::Internal => {
                return Err(Corrupt::InvalidDirectory.into());
            }
        }
        node.dirty = true;
        Ok(())
    }

    fn validate_empty<E>(&self, parent_number: u32) -> Result<(), Error<E>> {
        let indexed = self.inode.flags & super::DIRECTORY_INDEX_FL != 0;
        let mut dot = false;
        let mut dotdot = false;
        if indexed {
            let root = self
                .nodes
                .iter()
                .find(|node| node.logical == 0 && node.kind == crate::DirectoryBlockKind::Root)
                .ok_or(Corrupt::InvalidDirectory)?;
            if directory_parent_entry(&root.block.bytes, self.inode.number)? != parent_number {
                return Err(Corrupt::InvalidDirectory.into());
            }
            dot = true;
            dotdot = true;
        }
        for node in &self.nodes {
            if node.kind != crate::DirectoryBlockKind::Leaf {
                continue;
            }
            let tail = node
                .block
                .bytes
                .len()
                .checked_sub(12)
                .ok_or(Corrupt::InvalidDirectory)?;
            let mut cursor = 0usize;
            while cursor < tail {
                if tail - cursor < 8 {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let number = le32(&node.block.bytes, cursor);
                let record_len = usize::from(le16(&node.block.bytes, cursor + 4));
                let name_len = usize::from(node.block.bytes[cursor + 6]);
                if record_len < 8
                    || !record_len.is_multiple_of(4)
                    || cursor + record_len > tail
                    || name_len > record_len - 8
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                if number != 0 {
                    let name = &node.block.bytes[cursor + 8..cursor + 8 + name_len];
                    match name {
                        b"." if !indexed && !dot && number == self.inode.number => dot = true,
                        b".." if !indexed && !dotdot && number == parent_number => dotdot = true,
                        _ => return Err(Error::NotEmpty),
                    }
                }
                cursor += record_len;
            }
        }
        if !dot || !dotdot {
            return Err(Corrupt::InvalidDirectory.into());
        }
        Ok(())
    }

    fn find<E>(&self, name: &[u8]) -> Result<Option<(usize, u32)>, Error<E>> {
        for (index, node) in self.nodes.iter().enumerate() {
            if node.kind != crate::DirectoryBlockKind::Leaf {
                continue;
            }
            if let Some(number) = find_directory_entry(&node.block.bytes, name)? {
                return Ok(Some((index, number)));
            }
        }
        Ok(None)
    }

    fn into_dirty_blocks(self) -> Vec<DirtyBlock> {
        self.nodes
            .into_iter()
            .filter_map(|node| node.dirty.then_some(node.block))
            .collect()
    }
}

impl<'a> DirectoryEditor<'a> {
    fn new(checksum_seed: u32, inode: &'a Inode, bytes: &'a mut [u8]) -> Self {
        Self {
            checksum_seed,
            inode,
            bytes,
        }
    }

    fn insert<E>(&mut self, number: u32, name: &[u8], kind: u8) -> Result<(), Error<E>> {
        insert_directory_entry(
            self.checksum_seed,
            self.inode,
            self.bytes,
            number,
            name,
            kind,
        )
    }

    fn remove<E>(&mut self, number: u32, name: &[u8]) -> Result<(), Error<E>> {
        remove_directory_entry(self.checksum_seed, self.inode, self.bytes, number, name)
    }

    fn replace<E>(
        &mut self,
        old_number: u32,
        new_number: u32,
        name: &[u8],
        kind: u8,
    ) -> Result<(), Error<E>> {
        replace_directory_entry(
            self.checksum_seed,
            self.inode,
            self.bytes,
            old_number,
            new_number,
            name,
            kind,
        )
    }

    fn set_parent<E>(&mut self, old_parent: u32, new_parent: u32) -> Result<(), Error<E>> {
        replace_directory_parent(
            self.checksum_seed,
            self.inode,
            self.bytes,
            old_parent,
            new_parent,
        )
    }
}

struct GroupEdit {
    number: u32,
    descriptor: Vec<u8>,
    block_bitmap: Option<DirtyBlock>,
}

struct Allocation {
    blocks: Vec<u64>,
    groups: Vec<GroupEdit>,
}

struct InodeAllocation {
    number: u32,
    index: u64,
    inode_table: u64,
    group_number: u32,
    resources: Allocation,
    inode_bitmap: DirtyBlock,
}

struct DirectoryGrowth {
    inode: Inode,
    physical: Vec<u64>,
    size: u64,
    extent_nodes: Vec<DirtyBlock>,
}

/// Filesystem-independent mutation view of one regular file.
///
/// Public operation names impose policy contracts; this object decides whether
/// a byte write only touches existing blocks or also changes allocation and
/// the extent tree.
struct FileEditor {
    inode: Inode,
}

struct FileEditResult {
    first_allocated: Option<u64>,
}

enum FileGrowth<'a> {
    Write { offset: u64, data: &'a [u8] },
    ZeroFill { new_size: u64 },
}

impl FileGrowth<'_> {
    fn range<E>(&self, old_size: u64) -> Result<(u64, u64), Error<E>> {
        match self {
            Self::Write { offset, data } => Ok((
                *offset,
                offset
                    .checked_add(u64::try_from(data.len()).map_err(|_| Corrupt::AddressOverflow)?)
                    .ok_or(Corrupt::AddressOverflow)?,
            )),
            Self::ZeroFill { new_size } => Ok((old_size, *new_size)),
        }
    }

    fn apply<E>(
        &self,
        block: &mut [u8],
        block_start: u64,
        write_start: u64,
        write_end: u64,
    ) -> Result<(), Error<E>> {
        let within =
            usize::try_from(write_start - block_start).map_err(|_| Corrupt::AddressOverflow)?;
        let amount =
            usize::try_from(write_end - write_start).map_err(|_| Corrupt::AddressOverflow)?;
        match self {
            Self::Write { offset, data } => {
                let source =
                    usize::try_from(write_start - offset).map_err(|_| Corrupt::AddressOverflow)?;
                block[within..within + amount].copy_from_slice(&data[source..source + amount]);
            }
            Self::ZeroFill { .. } => block[within..within + amount].fill(0),
        }
        Ok(())
    }
}

impl FileEditor {
    fn new<E>(inode: Inode) -> Result<Self, Error<E>> {
        if inode.mode & 0xf000 != 0x8000 || inode.flags & super::EXTENTS_FL == 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        Ok(Self { inode })
    }

    fn write_at<S: Storage>(
        &self,
        transaction: &mut TransactionIo<'_, '_, S>,
        offset: u64,
        data: &[u8],
    ) -> Result<FileEditResult, Error<S::Error>> {
        if data.is_empty() {
            return Ok(FileEditResult {
                first_allocated: None,
            });
        }
        if !transaction.dirty.is_empty() {
            return Err(Error::ReservationExhausted);
        }
        if offset > self.inode.size {
            return Err(Unsupported::ExtentMutation.into());
        }
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Corrupt::AddressOverflow)?)
            .ok_or(Corrupt::AddressOverflow)?;
        if end <= self.inode.size {
            transaction
                .overwrite_inode(&self.inode, offset, data)
                .map(|()| FileEditResult {
                    first_allocated: None,
                })
        } else {
            transaction.extend_file(&self.inode, FileGrowth::Write { offset, data })
        }
    }

    fn resize<S: Storage>(
        &self,
        transaction: &mut TransactionIo<'_, '_, S>,
        new_size: u64,
    ) -> Result<(), Error<S::Error>> {
        if !transaction.dirty.is_empty() {
            return Err(Error::ReservationExhausted);
        }
        match new_size.cmp(&self.inode.size) {
            core::cmp::Ordering::Equal => Ok(()),
            core::cmp::Ordering::Greater => transaction
                .extend_file(&self.inode, FileGrowth::ZeroFill { new_size })
                .map(|_| ()),
            core::cmp::Ordering::Less => transaction.shrink_file(&self.inode, new_size).map(|_| ()),
        }
    }
}

struct BlockRelease {
    group: u32,
    indices: Vec<u64>,
}

struct ExtentOwnership {
    data: Vec<(u64, u64)>,
    tree: Vec<u64>,
    logical_blocks: u64,
}

struct ReleasedInodeBlocks {
    groups: Vec<GroupEdit>,
    released: u64,
    retained_xattr_block: Option<DirtyBlock>,
}

struct PreparedInodeRelease {
    superblock: DirtyBlock,
    descriptors: Vec<DirtyBlock>,
    block_bitmaps: Vec<DirtyBlock>,
    inode_bitmap: DirtyBlock,
    inode_block: DirtyBlock,
    retained_xattr_block: Option<DirtyBlock>,
}

#[derive(Clone, Copy)]
enum ReleaseKind {
    Regular,
    Directory,
    FastSymlink,
}

/// An isolated set of prospective filesystem-block changes.
///
/// A caller must reserve buffers before dirtying new blocks. Reservation does
/// every allocation needed to consume those slots, so subsequent full-block
/// writes cannot fail from allocation. Reads and modifications can still fail
/// when loading an unchanged block from storage.
pub struct Transaction<'a> {
    pub(crate) filesystem: &'a mut Ext4,
    dirty: Vec<DirtyBlock>,
    available: Vec<Vec<u8>>,
}

struct TransactionIo<'a, 'f, S> {
    transaction: &'a mut Transaction<'f>,
    storage: &'a mut S,
}

impl<'f, S> core::ops::Deref for TransactionIo<'_, 'f, S> {
    type Target = Transaction<'f>;

    fn deref(&self) -> &Self::Target {
        self.transaction
    }
}

impl<'f, S> core::ops::DerefMut for TransactionIo<'_, 'f, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.transaction
    }
}

impl<'a> Transaction<'a> {
    pub(crate) fn new(filesystem: &'a mut Ext4) -> Self {
        Self {
            filesystem,
            dirty: Vec::new(),
            available: Vec::new(),
        }
    }

    fn io<'s, S: Storage>(&'s mut self, storage: &'s mut S) -> TransactionIo<'s, 'a, S> {
        TransactionIo {
            transaction: self,
            storage,
        }
    }

    pub fn reserve_blocks(&mut self, additional: usize) -> Result<(), FsError> {
        let total = self
            .dirty
            .len()
            .checked_add(self.available.len())
            .and_then(|value| value.checked_add(additional))
            .ok_or(FsError::InvalidArgument)?;
        if u64::try_from(total).map_err(|_| FsError::InvalidArgument)?
            > self.filesystem.superblock.blocks_count
        {
            return Err(FsError::InvalidArgument);
        }
        let block_size = self.filesystem.superblock.block_size as usize;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(additional)
            .map_err(|_| FsError::OutOfMemory)?;
        for _ in 0..additional {
            let mut block = Vec::new();
            block
                .try_reserve_exact(block_size)
                .map_err(|_| FsError::OutOfMemory)?;
            block.resize(block_size, 0);
            buffers.push(block);
        }
        self.dirty
            .try_reserve(self.available.len() + additional)
            .map_err(|_| FsError::OutOfMemory)?;
        self.available
            .try_reserve(additional)
            .map_err(|_| FsError::OutOfMemory)?;
        self.available.append(&mut buffers);
        Ok(())
    }

    pub fn dirty_blocks(&self) -> usize {
        self.dirty.len()
    }

    pub fn reserved_blocks(&self) -> usize {
        self.available.len()
    }

    pub fn is_dirty(&self, number: u64) -> bool {
        self.dirty
            .binary_search_by_key(&number, |block| block.number)
            .is_ok()
    }

    pub fn commit<S: Storage>(self, storage: &mut S) -> Result<(), Error<S::Error>> {
        self.filesystem.commit_journal(storage, &self.dirty)
    }

    pub fn update_metadata<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        update: InodeMetadataUpdate,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).update_metadata(inode, update)
    }

    pub fn chmod_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        permissions: u16,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).chmod_inode(inode, permissions)
    }

    pub fn chown_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).chown_inode(inode, uid, gid)
    }

    pub fn set_inode_times<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage)
            .set_inode_times(inode, accessed, modified, changed)
    }

    pub fn write_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).write_inode(inode, offset, data)
    }

    pub fn overwrite_inode_range<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).overwrite_inode_range(inode, offset, data)
    }

    pub fn append_zeroed_inode_block<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
    ) -> Result<u64, Error<S::Error>> {
        self.io(storage).append_zeroed_inode_block(inode)
    }

    pub fn initialize_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).initialize_inode(inode, data)
    }

    pub fn append_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).append_inode(inode, data)
    }

    pub fn create_file<S: Storage>(
        &mut self,
        storage: &mut S,
        directory: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        self.io(storage).create_file(directory, name, permissions)
    }

    pub fn create_symlink<S: Storage>(
        &mut self,
        storage: &mut S,
        directory: &Inode,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, Error<S::Error>> {
        self.io(storage).create_symlink(directory, name, target)
    }

    pub fn create_link<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        parent: &Inode,
        name: &[u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).create_link(inode, parent, name)
    }

    pub fn create_directory<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        self.io(storage).create_directory(parent, name, permissions)
    }

    pub fn remove_entry<S: Storage>(
        &mut self,
        storage: &mut S,
        directory: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).remove_entry(directory, entry)
    }

    pub fn remove_directory<S: Storage>(
        &mut self,
        storage: &mut S,
        parent: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).remove_directory(parent, entry)
    }

    pub fn move_entry<S: Storage>(
        &mut self,
        storage: &mut S,
        old_parent: &Inode,
        source: &DirectoryEntry,
        new_parent: &Inode,
        new_name: &[u8],
        destination: Option<&DirectoryEntry>,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage)
            .move_entry(old_parent, source, new_parent, new_name, destination)
    }

    pub fn resize_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
        new_size: u64,
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).resize_inode(inode, new_size)
    }

    pub fn truncate_inode<S: Storage>(
        &mut self,
        storage: &mut S,
        inode: &Inode,
    ) -> Result<u64, Error<S::Error>> {
        self.io(storage).truncate_inode(inode)
    }

    pub fn read_block<S: Storage>(
        &mut self,
        storage: &mut S,
        number: u64,
        dst: &mut [u8],
    ) -> Result<(), Error<S::Error>> {
        self.io(storage).read_block(number, dst)
    }

    pub fn write_block(&mut self, number: u64, src: &[u8]) -> Result<(), FsError> {
        if number >= self.filesystem.superblock.blocks_count
            || src.len() != self.filesystem.superblock.block_size as usize
        {
            return Err(FsError::InvalidArgument);
        }
        match self
            .dirty
            .binary_search_by_key(&number, |block| block.number)
        {
            Ok(index) => self.dirty[index].bytes.copy_from_slice(src),
            Err(index) => {
                let bytes = self.available.pop().ok_or(FsError::ReservationExhausted)?;
                self.dirty.insert(index, DirtyBlock { number, bytes });
                self.dirty[index].bytes.copy_from_slice(src);
            }
        }
        Ok(())
    }

    pub fn modify_block<S: Storage, F>(
        &mut self,
        storage: &mut S,
        number: u64,
        modify: F,
    ) -> Result<(), Error<S::Error>>
    where
        F: FnOnce(&mut [u8]),
    {
        self.io(storage).modify_block(number, modify)
    }
}

impl<S: Storage> TransactionIo<'_, '_, S> {
    fn map_file_block(
        &mut self,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error<S::Error>> {
        self.transaction
            .filesystem
            .map_file_block(self.storage, inode, logical)
    }

    fn read_external_xattr_block(&mut self, inode: &Inode) -> Result<Vec<u8>, Error<S::Error>> {
        self.transaction
            .filesystem
            .read_external_xattr_block(self.storage, inode)
    }

    /// Apply filesystem-independent inode metadata as one checked edit.
    ///
    /// This is the layout-free primitive beneath policy-shaped APIs such as
    /// [`Self::chmod`], [`Self::chown`], and [`Self::set_times`].
    pub fn update_metadata(
        &mut self,
        inode: &Inode,
        update: InodeMetadataUpdate,
    ) -> Result<(), Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 2;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if update == InodeMetadataUpdate::default() {
            return Ok(());
        }
        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let mut metadata = MetadataMutation::new();
        metadata.load(self, superblock_number)?;
        metadata.edit_inode(self, &inode, |editor| editor.apply_metadata(update))?;
        metadata.stage(self)
    }

    /// Change permission and special bits while preserving the inode type.
    pub fn chmod_inode(&mut self, inode: &Inode, permissions: u16) -> Result<(), Error<S::Error>> {
        self.update_metadata(
            inode,
            InodeMetadataUpdate {
                permissions: Some(permissions),
                ..InodeMetadataUpdate::default()
            },
        )
    }

    /// Change either owner ID; `None` preserves that field.
    pub fn chown_inode(
        &mut self,
        inode: &Inode,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error<S::Error>> {
        self.update_metadata(
            inode,
            InodeMetadataUpdate {
                uid,
                gid,
                ..InodeMetadataUpdate::default()
            },
        )
    }

    /// Set any subset of access, modification, and status-change timestamps.
    pub fn set_inode_times(
        &mut self,
        inode: &Inode,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
    ) -> Result<(), Error<S::Error>> {
        self.update_metadata(
            inode,
            InodeMetadataUpdate {
                accessed,
                modified,
                changed,
                ..InodeMetadataUpdate::default()
            },
        )
    }

    /// Write bytes at or before EOF, growing the file when the range crosses it.
    ///
    /// Sparse gaps are deliberately a separate `resize` concern: `offset` may
    /// equal EOF but may not skip beyond it.
    pub fn write_inode(
        &mut self,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        if !self.dirty.is_empty() {
            return Err(Error::ReservationExhausted);
        }
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        file.write_at(self, offset, data).map(|_| ())
    }

    /// Overwrite bytes already backed by initialized extents.
    ///
    /// Growth and sparse-hole allocation are handled by the allocation path;
    /// this operation deliberately refuses either rather than partially
    /// writing. The unchanged superblock is included because JBD2 activation
    /// and cleanup manage its recovery flag.
    pub fn overwrite_inode_range(
        &mut self,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        if data.is_empty() {
            return Ok(());
        }
        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Corrupt::AddressOverflow)?)
            .filter(|end| *end <= inode.size)
            .ok_or(Unsupported::ExtentMutation)?;
        FileEditor::new(inode)?
            .write_at(self, offset, data)
            .map(|_| ())
    }

    fn overwrite_inode(
        &mut self,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Corrupt::AddressOverflow)?)
            .ok_or(Corrupt::AddressOverflow)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let first = offset / block_size;
        let last = (end - 1) / block_size;
        let block_count =
            usize::try_from(last - first + 1).map_err(|_| Corrupt::AddressOverflow)?;
        if self.available.len() < block_count + 1 {
            return Err(Error::ReservationExhausted);
        }

        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(block_count)
            .map_err(|_| Error::OutOfMemory)?;
        let mut copied = 0usize;
        for logical in first..=last {
            let physical = self
                .map_file_block(inode, logical)?
                .ok_or(Unsupported::ExtentMutation)?;
            if physical == 0
                || replacements
                    .iter()
                    .any(|block: &DirtyBlock| block.number == physical)
            {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            let mut block = self.read_owned_block(physical)?;
            let block_start = logical * block_size;
            let write_start = offset.max(block_start);
            let write_end = end.min(block_start + block_size);
            let within =
                usize::try_from(write_start - block_start).map_err(|_| Corrupt::AddressOverflow)?;
            let amount =
                usize::try_from(write_end - write_start).map_err(|_| Corrupt::AddressOverflow)?;
            block[within..within + amount].copy_from_slice(&data[copied..copied + amount]);
            copied += amount;
            replacements.push(DirtyBlock {
                number: physical,
                bytes: block,
            });
        }

        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        if replacements
            .iter()
            .any(|block| block.number == superblock_number)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let superblock = self.read_owned_block(superblock_number)?;
        self.stage_overwrite(
            DirtyBlock {
                number: superblock_number,
                bytes: superblock,
            },
            replacements,
        )
    }

    /// Compatibility wrapper for writing one zero-filled block to an empty file.
    pub fn append_zeroed_inode_block(&mut self, inode: &Inode) -> Result<u64, Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 5;
        if self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        if file.inode.size != 0 || file.inode.blocks_512 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        let zero = self.zero_block()?;
        file.write_at(self, 0, &zero)?
            .first_allocated
            .ok_or(Corrupt::InvalidExtentTree.into())
    }

    /// Fill an empty extent-formatted file with an arbitrary multi-block value.
    pub fn initialize_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error<S::Error>> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        if file.inode.size != 0 || file.inode.blocks_512 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        file.write_at(self, 0, data).map(|_| ())
    }

    /// Append bytes using the general file editor.
    pub fn append_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error<S::Error>> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        file.write_at(self, file.inode.size, data).map(|_| ())
    }

    fn extend_file(
        &mut self,
        inode: &Inode,
        growth: FileGrowth<'_>,
    ) -> Result<FileEditResult, Error<S::Error>> {
        self.validate_mutation_profile()?;
        let (offset, new_size) = growth.range(inode.size)?;
        if offset > inode.size {
            return Err(Unsupported::ExtentMutation.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let block_size_usize = usize::try_from(block_size).map_err(|_| Corrupt::AddressOverflow)?;
        if new_size <= inode.size {
            return Err(Unsupported::ExtentMutation.into());
        }
        let old_blocks = inode.size.div_ceil(block_size);
        let new_blocks = new_size.div_ceil(block_size);
        let added_blocks = new_blocks - old_blocks;
        let added_blocks_usize =
            usize::try_from(added_blocks).map_err(|_| Corrupt::AddressOverflow)?;
        let ownership = self.read_extent_ownership(inode)?;
        let existing_nodes = ownership.tree;
        let old_blocks_usize = usize::try_from(old_blocks).map_err(|_| Corrupt::AddressOverflow)?;
        let all_blocks_usize = usize::try_from(new_blocks).map_err(|_| Corrupt::AddressOverflow)?;
        let mut physical_blocks = Vec::new();
        physical_blocks
            .try_reserve_exact(all_blocks_usize)
            .map_err(|_| Error::OutOfMemory)?;
        for (physical, length) in ownership.data {
            for number in physical..physical + length {
                physical_blocks.push(number);
            }
        }
        if physical_blocks.len() != old_blocks_usize {
            return Err(Unsupported::ExtentMutation.into());
        }
        let expected_sectors = old_blocks
            .checked_add(u64::try_from(existing_nodes.len()).map_err(|_| Corrupt::AddressOverflow)?)
            .ok_or(Corrupt::AddressOverflow)?
            .checked_mul(block_size / 512)
            .ok_or(Corrupt::AddressOverflow)?;
        if inode.blocks_512 != expected_sectors {
            return Err(Unsupported::ExtentMutation.into());
        }

        let inode_group =
            (inode.number - 1) / self.transaction.filesystem.superblock.inodes_per_group;
        let inode_descriptor = self
            .transaction
            .filesystem
            .read_group_descriptor(self.storage, inode_group)?;
        let inode_table = u64::from(le32(&inode_descriptor, 8))
            | (u64::from(le32(&inode_descriptor, 0x28)) << 32);
        let mut allocation = self.allocate_blocks(added_blocks_usize)?;
        if allocation
            .blocks
            .iter()
            .any(|physical| physical_blocks.contains(physical))
        {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        physical_blocks.extend_from_slice(&allocation.blocks);
        let node_capacity = (block_size_usize - 16) / 12;
        let old_run_count = extent_count(&physical_blocks[..old_blocks_usize])?;
        let old_shape = extent_tree_shape(old_run_count, 4, node_capacity)?;
        let old_nodes = extent_tree_node_count(&old_shape)?;
        if old_nodes != existing_nodes.len() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let run_count = extent_count(&physical_blocks)?;
        let shape = extent_tree_shape(run_count, 4, node_capacity)?;
        let required_nodes = extent_tree_node_count(&shape)?;
        if required_nodes < existing_nodes.len()
            || shape
                .iter()
                .enumerate()
                .any(|(level, count)| *count < old_shape.get(level).copied().unwrap_or(0))
        {
            return Err(Unsupported::ExtentMutation.into());
        }
        let new_nodes = required_nodes - existing_nodes.len();
        self.extend_allocation(&mut allocation, new_nodes)?;
        let mut allocated = allocation.blocks;
        let allocated_node_numbers = allocated.split_off(added_blocks_usize);
        let first_allocated = allocated.first().copied();
        let allocation_groups = allocation.groups;

        let node_numbers = merge_extent_node_numbers(
            &old_shape,
            &shape,
            &existing_nodes,
            &allocated_node_numbers,
        )?;

        let descriptor_blocks = self.descriptor_blocks(&allocation_groups)?;
        let superblock_block_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let inode_index =
            u64::from((inode.number - 1) % self.transaction.filesystem.superblock.inodes_per_group);
        let inode_byte = inode_table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(
                    inode_index * u64::from(self.transaction.filesystem.superblock.inode_size),
                )
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let inode_block_number = inode_byte / block_size;
        let inode_offset =
            usize::try_from(inode_byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        let mut superblock_block = self.read_owned_block(superblock_block_number)?;
        let mut inode_block = self.read_owned_block(inode_block_number)?;
        if inode_offset
            .checked_add(inode_size)
            .filter(|end| *end <= inode_block.len())
            .is_none()
        {
            return Err(Corrupt::InvalidInode(inode.number).into());
        }

        let mut payloads = Vec::new();
        let first_touched = offset / block_size;
        let touched_blocks =
            usize::try_from(new_blocks - first_touched).map_err(|_| Corrupt::AddressOverflow)?;
        payloads
            .try_reserve_exact(touched_blocks + required_nodes)
            .map_err(|_| Error::OutOfMemory)?;
        for logical in first_touched..new_blocks {
            let physical = physical_blocks
                .get(usize::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?)
                .copied()
                .ok_or(Corrupt::InvalidExtentTree)?;
            let mut block = if logical < old_blocks {
                self.read_owned_block(physical)?
            } else {
                self.zero_block()?
            };
            let block_start = logical
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let write_start = offset.max(block_start);
            let write_end = new_size.min(
                block_start
                    .checked_add(block_size)
                    .ok_or(Corrupt::AddressOverflow)?,
            );
            growth.apply(&mut block, block_start, write_start, write_end)?;
            payloads.push(DirtyBlock {
                number: physical,
                bytes: block,
            });
        }

        let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        let raw_superblock =
            &mut superblock_block[superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
        decrement_superblock_free_blocks_by(
            raw_superblock,
            added_blocks
                .checked_add(new_nodes as u64)
                .ok_or(Corrupt::AddressOverflow)?,
        )?;
        update_superblock_checksum(raw_superblock);

        let mut extent_nodes = Vec::new();
        extent_nodes
            .try_reserve_exact(required_nodes)
            .map_err(|_| Error::OutOfMemory)?;
        for number in node_numbers {
            extent_nodes.push(DirtyBlock {
                number,
                bytes: if existing_nodes.contains(&number) {
                    self.read_owned_block(number)?
                } else {
                    self.zero_block()?
                },
            });
        }
        let raw_inode = &mut inode_block[inode_offset..inode_offset + inode_size];
        let mut editor = InodeEditor::new(
            raw_inode,
            self.transaction.filesystem.superblock.checksum_seed,
            inode.number,
            inode.generation,
        )?;
        editor.set_extent_mapping(&physical_blocks, new_size, block_size, &mut extent_nodes)?;
        editor.finish();
        for node in extent_nodes {
            payloads.push(node);
        }

        self.stage_file_allocation(
            DirtyBlock {
                number: superblock_block_number,
                bytes: superblock_block,
            },
            DirtyBlock {
                number: inode_block_number,
                bytes: inode_block,
            },
            descriptor_blocks,
            allocation_groups,
            payloads,
        )?;
        Ok(FileEditResult { first_allocated })
    }

    /// Create an empty regular file in a checked mutable directory.
    pub fn create_file(
        &mut self,
        directory: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        self.create_inode_entry(directory, name, permissions, 1, |editor, permissions| {
            editor.initialize_regular(permissions);
            Ok(())
        })
    }

    /// Create an inline (fast) symbolic link.
    pub fn create_symlink(
        &mut self,
        directory: &Inode,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, Error<S::Error>> {
        if target.is_empty() || target.len() > 60 || target.contains(&0) {
            return Err(Error::InvalidArgument);
        }
        self.create_inode_entry(directory, name, 0o777, 7, |editor, _| {
            editor.initialize_fast_symlink(target)
        })
    }

    fn create_inode_entry<F>(
        &mut self,
        directory: &Inode,
        name: &[u8],
        permissions: u16,
        file_type: u8,
        initialize: F,
    ) -> Result<u32, Error<S::Error>>
    where
        F: FnOnce(&mut InodeEditor<'_>, u16) -> Result<(), Error<S::Error>>,
    {
        const REQUIRED_DIRTY_BLOCKS: usize = 5;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
            || permissions & !0o777 != 0
            || !matches!(file_type, 1 | 7)
        {
            return Err(Error::InvalidArgument);
        }

        let directory = self
            .transaction
            .filesystem
            .refresh(self.storage, directory)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let mut directory_tree = DirectoryTree::load(self, &directory)?;

        let mut allocation = self.allocate_inode()?;
        let inode_number = allocation.number;
        let inode_bitmap_number = allocation.inode_bitmap.number;
        let superblock_block_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let inode_byte = allocation
            .inode_table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(
                    allocation.index * u64::from(self.transaction.filesystem.superblock.inode_size),
                )
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let inode_block_number = inode_byte / block_size;
        let inode_offset =
            usize::try_from(inode_byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        if inode_offset + inode_size > self.transaction.filesystem.superblock.block_size as usize {
            return Err(Unsupported::MutationProfile.into());
        }

        let mut superblock_block = self.read_owned_block(superblock_block_number)?;
        let mut inode_block = self.read_owned_block(inode_block_number)?;

        let growth = self.insert_into_directory(
            &mut directory_tree,
            &mut allocation.resources,
            inode_number,
            name,
            file_type,
        )?;
        let descriptor_blocks = self.descriptor_blocks(&allocation.resources.groups)?;
        let allocated_blocks = u64::try_from(allocation.resources.blocks.len())
            .map_err(|_| Corrupt::AddressOverflow)?;
        let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        let superblock =
            &mut superblock_block[superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
        decrement_superblock_free_inodes(superblock)?;
        decrement_superblock_free_blocks_by(superblock, allocated_blocks)?;
        update_superblock_checksum(superblock);

        let raw_inode = &mut inode_block[inode_offset..inode_offset + inode_size];
        let mut editor = InodeEditor::new(
            raw_inode,
            self.transaction.filesystem.superblock.checksum_seed,
            inode_number,
            0,
        )?;
        initialize(&mut editor, permissions)?;
        editor.finish();

        let mut metadata = MetadataMutation::new();
        metadata.adopt(superblock_block_number, superblock_block)?;
        for block in descriptor_blocks {
            metadata.adopt(block.number, block.bytes)?;
        }
        metadata.adopt(inode_bitmap_number, allocation.inode_bitmap.bytes)?;
        metadata.adopt_group_edits(allocation.resources.groups)?;
        metadata.adopt(inode_block_number, inode_block)?;
        if let Some(growth) = growth {
            self.apply_directory_growth(&mut metadata, growth)?;
        }
        metadata.adopt_blocks(directory_tree.into_dirty_blocks())?;
        metadata.stage(self)?;
        Ok(inode_number)
    }

    /// Create another directory entry for an existing non-directory inode.
    pub fn create_link(
        &mut self,
        inode: &Inode,
        parent: &Inode,
        name: &[u8],
    ) -> Result<(), Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 3;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }

        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        if inode.is_directory() || inode.links == u16::MAX {
            return Err(Error::InvalidArgument);
        }
        let file_type = match inode.mode & 0xf000 {
            0x8000 => 1,
            0xa000 => 7,
            _ => return Err(Unsupported::MutationProfile.into()),
        };
        let parent = self.transaction.filesystem.refresh(self.storage, parent)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let mut directory_tree = DirectoryTree::load(self, &parent)?;
        let mut resources = Allocation {
            blocks: Vec::new(),
            groups: Vec::new(),
        };
        let growth = self.insert_into_directory(
            &mut directory_tree,
            &mut resources,
            inode.number,
            name,
            file_type,
        )?;
        let descriptor_blocks = self.descriptor_blocks(&resources.groups)?;

        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let mut superblock = self.read_owned_block(superblock_number)?;
        if !resources.blocks.is_empty() {
            let offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
                .map_err(|_| Corrupt::AddressOverflow)?;
            let raw = &mut superblock[offset..offset + ondisk::SUPERBLOCK_SIZE];
            decrement_superblock_free_blocks_by(
                raw,
                u64::try_from(resources.blocks.len()).map_err(|_| Corrupt::AddressOverflow)?,
            )?;
            update_superblock_checksum(raw);
        }
        let mut metadata = MetadataMutation::new();
        metadata.adopt(superblock_number, superblock)?;
        metadata.adopt_blocks(descriptor_blocks)?;
        metadata.adopt_group_edits(resources.groups)?;
        metadata.edit_inode(self, &inode, |editor| {
            editor.set_links(inode.links + 1);
            Ok(())
        })?;
        if let Some(growth) = growth {
            self.apply_directory_growth(&mut metadata, growth)?;
        }
        metadata.adopt_blocks(directory_tree.into_dirty_blocks())?;
        metadata.stage(self)
    }

    /// Create a checked directory below a mutable directory.
    pub fn create_directory(
        &mut self,
        parent: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 8;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
            || permissions & !0o777 != 0
        {
            return Err(Error::InvalidArgument);
        }

        let parent = self.transaction.filesystem.refresh(self.storage, parent)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        if !parent.is_directory() || parent.links == u16::MAX {
            return Err(Unsupported::MutationProfile.into());
        }
        let mut parent_tree = DirectoryTree::load(self, &parent)?;

        let mut allocation = self.allocate_inode()?;
        self.extend_allocation(&mut allocation.resources, 1)?;
        let directory_block_number = allocation.resources.blocks[0];
        let inode_group = allocation
            .resources
            .groups
            .binary_search_by_key(&allocation.group_number, |group| group.number)
            .map_err(|_| Corrupt::InvalidGroup(allocation.group_number))?;
        increment_descriptor_used_directories(
            &mut allocation.resources.groups[inode_group].descriptor,
            u64::from(self.transaction.filesystem.superblock.inodes_per_group),
        )?;
        update_group_descriptor_checksum(
            self.transaction.filesystem.superblock.checksum_seed,
            allocation.group_number,
            &mut allocation.resources.groups[inode_group].descriptor,
        );
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        let inode_byte = allocation
            .inode_table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(
                    allocation.index * u64::from(self.transaction.filesystem.superblock.inode_size),
                )
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let inode_block_number = inode_byte / block_size;
        let inode_offset =
            usize::try_from(inode_byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;

        if inode_offset + inode_size > block_size as usize {
            return Err(Corrupt::InvalidInodeTable.into());
        }

        let superblock_block_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let growth = self.insert_into_directory(
            &mut parent_tree,
            &mut allocation.resources,
            allocation.number,
            name,
            2,
        )?;
        let descriptor_blocks = self.descriptor_blocks(&allocation.resources.groups)?;
        let allocated_blocks = u64::try_from(allocation.resources.blocks.len())
            .map_err(|_| Corrupt::AddressOverflow)?;
        let mut directory_block = self.zero_block()?;
        initialize_directory_block(
            self.transaction.filesystem.superblock.checksum_seed,
            allocation.number,
            0,
            parent.number,
            &mut directory_block,
        )?;

        let mut metadata = MetadataMutation::new();
        metadata.adopt(
            inode_block_number,
            self.read_owned_block(inode_block_number)?,
        )?;
        let mut editor = InodeEditor::new(
            &mut metadata.get_mut(inode_block_number)?[inode_offset..inode_offset + inode_size],
            self.transaction.filesystem.superblock.checksum_seed,
            allocation.number,
            0,
        )?;
        editor.initialize_directory(permissions, directory_block_number, block_size)?;
        editor.finish();
        metadata.edit_inode(self, &parent, |editor| {
            editor.set_links(parent.links + 1);
            Ok(())
        })?;
        if let Some(growth) = growth {
            self.apply_directory_growth(&mut metadata, growth)?;
        }

        let mut superblock_block = self.read_owned_block(superblock_block_number)?;
        let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        let raw_superblock =
            &mut superblock_block[superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
        decrement_superblock_free_inodes(raw_superblock)?;
        decrement_superblock_free_blocks_by(raw_superblock, allocated_blocks)?;
        update_superblock_checksum(raw_superblock);

        metadata.adopt(superblock_block_number, superblock_block)?;
        metadata.adopt_blocks(descriptor_blocks)?;
        metadata.adopt(
            allocation.inode_bitmap.number,
            allocation.inode_bitmap.bytes,
        )?;
        metadata.adopt_group_edits(allocation.resources.groups)?;
        metadata.adopt(directory_block_number, directory_block)?;
        metadata.adopt_blocks(parent_tree.into_dirty_blocks())?;
        metadata.stage(self)?;
        Ok(allocation.number)
    }

    /// Remove a link-count-one regular file with checked initialized extents.
    pub fn remove_entry(
        &mut self,
        directory: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error<S::Error>> {
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() {
            return Err(Error::ReservationExhausted);
        }

        if entry.name.is_empty() || entry.name == b"." || entry.name == b".." {
            return Err(Error::InvalidArgument);
        }
        let directory = self
            .transaction
            .filesystem
            .refresh(self.storage, directory)?;
        let inode = self
            .transaction
            .filesystem
            .refresh(self.storage, &entry.inode)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        if !directory.is_directory()
            || inode.links == 0
            || !matches!(inode.mode & 0xf000, 0x8000 | 0xa000)
        {
            return Err(Unsupported::MutationProfile.into());
        }
        let mut directory_tree = DirectoryTree::load(self, &directory)?;
        directory_tree.remove(inode.number, &entry.name)?;
        if inode.links > 1 {
            let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
            let superblock = self.read_owned_block(superblock_number)?;
            let mut metadata = MetadataMutation::new();
            metadata.adopt(superblock_number, superblock)?;
            metadata.adopt_blocks(directory_tree.into_dirty_blocks())?;
            metadata.edit_inode(self, &inode, |editor| {
                editor.set_links(inode.links - 1);
                Ok(())
            })?;
            return metadata.stage(self);
        }
        let kind = if inode.is_symlink() {
            ReleaseKind::FastSymlink
        } else {
            ReleaseKind::Regular
        };
        let release = self.prepare_inode_release(&inode, kind)?;
        self.stage_inode_release(release, directory_tree.into_dirty_blocks())
    }

    /// Remove a checked empty directory from a mutable parent directory.
    pub fn remove_directory(
        &mut self,
        parent: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 7;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if entry.name.is_empty() || entry.name == b"." || entry.name == b".." {
            return Err(Error::InvalidArgument);
        }
        let parent = self.transaction.filesystem.refresh(self.storage, parent)?;
        let directory = self
            .transaction
            .filesystem
            .refresh(self.storage, &entry.inode)?;
        if !parent.is_directory() || parent.links == 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        let mut parent_tree = DirectoryTree::load(self, &parent)?;
        let release = self.prepare_empty_directory_release(&directory, parent.number)?;
        parent_tree.remove(directory.number, &entry.name)?;
        self.stage_replaced_directory(release, parent_tree.into_dirty_blocks(), &parent)
    }

    /// Rename between checked directories, reclaiming a replaced regular file.
    pub fn move_entry(
        &mut self,
        old_parent: &Inode,
        source: &DirectoryEntry,
        new_parent: &Inode,
        new_name: &[u8],
        destination: Option<&DirectoryEntry>,
    ) -> Result<(), Error<S::Error>> {
        const REQUIRED_DIRTY_BLOCKS: usize = 3;
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if new_name.is_empty()
            || new_name.len() > 255
            || new_name == b"."
            || new_name == b".."
            || new_name.contains(&b'/')
            || new_name.contains(&0)
        {
            return Err(Error::InvalidArgument);
        }
        if old_parent.number == new_parent.number && source.name == new_name {
            return Ok(());
        }

        let old_parent = self
            .transaction
            .filesystem
            .refresh(self.storage, old_parent)?;
        let source_inode = self
            .transaction
            .filesystem
            .refresh(self.storage, &source.inode)?;
        let new_parent = self
            .transaction
            .filesystem
            .refresh(self.storage, new_parent)?;
        let destination = match destination {
            Some(destination) if destination.inode.number == source_inode.number => return Ok(()),
            Some(destination) => Some(
                self.transaction
                    .filesystem
                    .refresh(self.storage, &destination.inode)?,
            ),
            None => None,
        };
        if !old_parent.is_directory() || !new_parent.is_directory() {
            return Err(Unsupported::MutationProfile.into());
        }
        let file_type = match source_inode.mode & 0xf000 {
            0x8000 => 1,
            0x4000 => 2,
            0xa000 => 7,
            _ => return Err(Unsupported::MutationProfile.into()),
        };
        if file_type == 2 && old_parent.number != new_parent.number {
            self.ensure_directory_move_acyclic(source_inode.number, &new_parent)?;
        }
        if file_type == 2 && (source_inode.links < 2 || old_parent.links == 0) {
            return Err(Unsupported::MutationProfile.into());
        }

        let mut old_tree = DirectoryTree::load(self, &old_parent)?;
        if old_parent.number == new_parent.number {
            if let Some(destination) = destination {
                if file_type == 2 {
                    let release =
                        self.prepare_empty_directory_release(&destination, new_parent.number)?;
                    old_tree.replace(
                        destination.number,
                        source_inode.number,
                        new_name,
                        file_type,
                    )?;
                    old_tree.remove(source_inode.number, &source.name)?;
                    return self.stage_replaced_directory(
                        release,
                        old_tree.into_dirty_blocks(),
                        &old_parent,
                    );
                }
                let release = self.prepare_inode_release(&destination, ReleaseKind::Regular)?;
                old_tree.replace(destination.number, source_inode.number, new_name, file_type)?;
                old_tree.remove(source_inode.number, &source.name)?;
                return self.stage_inode_release(release, old_tree.into_dirty_blocks());
            }
            old_tree.remove(source_inode.number, &source.name)?;
            let mut resources = Allocation {
                blocks: Vec::new(),
                groups: Vec::new(),
            };
            let growth = self.insert_into_directory(
                &mut old_tree,
                &mut resources,
                source_inode.number,
                new_name,
                file_type,
            )?;
            let mut metadata = MetadataMutation::new();
            self.apply_block_allocation(&mut metadata, resources)?;
            if let Some(growth) = growth {
                self.apply_directory_growth(&mut metadata, growth)?;
            }
            metadata.adopt_blocks(old_tree.into_dirty_blocks())?;
            return metadata.stage(self);
        }

        let mut new_tree = DirectoryTree::load(self, &new_parent)?;
        if let Some(destination) = destination {
            if file_type == 2 {
                let release =
                    self.prepare_empty_directory_release(&destination, new_parent.number)?;
                let mut source_tree = DirectoryTree::load(self, &source_inode)?;
                source_tree.set_parent(old_parent.number, new_parent.number)?;
                new_tree.replace(destination.number, source_inode.number, new_name, file_type)?;
                old_tree.remove(source_inode.number, &source.name)?;
                let mut namespace = old_tree.into_dirty_blocks();
                namespace
                    .try_reserve(new_tree.nodes.len() + source_tree.nodes.len())
                    .map_err(|_| Error::OutOfMemory)?;
                namespace.extend(new_tree.into_dirty_blocks());
                namespace.extend(source_tree.into_dirty_blocks());
                return self.stage_replaced_directory(release, namespace, &old_parent);
            }
            let release = self.prepare_inode_release(&destination, ReleaseKind::Regular)?;
            new_tree.replace(destination.number, source_inode.number, new_name, file_type)?;
            old_tree.remove(source_inode.number, &source.name)?;
            let mut namespace = old_tree.into_dirty_blocks();
            namespace
                .try_reserve(new_tree.nodes.len())
                .map_err(|_| Error::OutOfMemory)?;
            namespace.extend(new_tree.into_dirty_blocks());
            return self.stage_inode_release(release, namespace);
        }
        if file_type == 2 {
            if new_parent.links == u16::MAX {
                return Err(Unsupported::MutationProfile.into());
            }
            let mut source_tree = DirectoryTree::load(self, &source_inode)?;
            source_tree.set_parent(old_parent.number, new_parent.number)?;

            let mut metadata = MetadataMutation::new();
            old_tree.remove(source_inode.number, &source.name)?;
            let mut resources = Allocation {
                blocks: Vec::new(),
                groups: Vec::new(),
            };
            let growth = self.insert_into_directory(
                &mut new_tree,
                &mut resources,
                source_inode.number,
                new_name,
                file_type,
            )?;
            self.apply_block_allocation(&mut metadata, resources)?;
            if let Some(growth) = growth {
                self.apply_directory_growth(&mut metadata, growth)?;
            }
            metadata.adopt_blocks(old_tree.into_dirty_blocks())?;
            metadata.adopt_blocks(new_tree.into_dirty_blocks())?;
            metadata.adopt_blocks(source_tree.into_dirty_blocks())?;
            metadata.edit_inode(self, &old_parent, |editor| {
                editor.set_links(old_parent.links - 1);
                Ok(())
            })?;
            metadata.edit_inode(self, &new_parent, |editor| {
                editor.set_links(new_parent.links + 1);
                Ok(())
            })?;
            metadata.stage(self)?;
            return Ok(());
        }
        old_tree.remove(source_inode.number, &source.name)?;
        let mut resources = Allocation {
            blocks: Vec::new(),
            groups: Vec::new(),
        };
        let growth = self.insert_into_directory(
            &mut new_tree,
            &mut resources,
            source_inode.number,
            new_name,
            file_type,
        )?;
        let mut metadata = MetadataMutation::new();
        self.apply_block_allocation(&mut metadata, resources)?;
        if let Some(growth) = growth {
            self.apply_directory_growth(&mut metadata, growth)?;
        }
        metadata.adopt_blocks(old_tree.into_dirty_blocks())?;
        metadata.adopt_blocks(new_tree.into_dirty_blocks())?;
        metadata.stage(self)
    }

    /// Resize a regular file through its allocation-aware editor.
    pub fn resize_inode(&mut self, inode: &Inode, new_size: u64) -> Result<(), Error<S::Error>> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        file.resize(self, new_size)
    }

    /// Release checked initialized extents and reduce a regular file to size 0.
    pub fn truncate_inode(&mut self, inode: &Inode) -> Result<u64, Error<S::Error>> {
        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        if inode.size == 0 && inode.blocks_512 == 0 {
            return Ok(0);
        }
        self.shrink_file(&inode, 0)
    }

    fn shrink_file(&mut self, inode: &Inode, new_size: u64) -> Result<u64, Error<S::Error>> {
        self.validate_mutation_profile()?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let block_size_usize = usize::try_from(block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let old_blocks = inode.size.div_ceil(block_size);
        let kept_blocks = new_size.div_ceil(block_size);
        if new_size >= inode.size || kept_blocks > old_blocks {
            return Err(Error::InvalidArgument);
        }

        let ownership = self.read_extent_ownership(inode)?;
        let existing_nodes = ownership.tree;
        let old_blocks_usize = usize::try_from(old_blocks).map_err(|_| Corrupt::AddressOverflow)?;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(old_blocks_usize)
            .map_err(|_| Error::OutOfMemory)?;
        for (start, length) in ownership.data {
            for number in start..start + length {
                physical.push(number);
            }
        }
        if physical.len() != old_blocks_usize || ownership.logical_blocks != old_blocks {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let expected_sectors = u64::try_from(physical.len() + existing_nodes.len())
            .map_err(|_| Corrupt::AddressOverflow)?
            .checked_mul(block_size / 512)
            .ok_or(Corrupt::AddressOverflow)?;
        if inode.blocks_512 != expected_sectors {
            return Err(Unsupported::ExtentMutation.into());
        }

        let node_capacity = (block_size_usize - 16) / 12;
        let old_shape = extent_tree_shape(extent_count(&physical)?, 4, node_capacity)?;
        let kept = usize::try_from(kept_blocks).map_err(|_| Corrupt::AddressOverflow)?;
        let new_shape = extent_tree_shape(extent_count(&physical[..kept])?, 4, node_capacity)?;
        if extent_tree_node_count(&old_shape)? != existing_nodes.len()
            || new_shape.len() > old_shape.len()
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }

        let mut retained_nodes = Vec::new();
        let mut released_nodes = Vec::new();
        retained_nodes
            .try_reserve_exact(extent_tree_node_count(&new_shape)?)
            .map_err(|_| Error::OutOfMemory)?;
        released_nodes
            .try_reserve_exact(existing_nodes.len() - extent_tree_node_count(&new_shape)?)
            .map_err(|_| Error::OutOfMemory)?;
        let mut old_offset = 0usize;
        for (level, &old_count) in old_shape.iter().enumerate() {
            let retain = new_shape.get(level).copied().unwrap_or(0);
            if retain > old_count {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            retained_nodes.extend_from_slice(&existing_nodes[old_offset..old_offset + retain]);
            released_nodes
                .extend_from_slice(&existing_nodes[old_offset + retain..old_offset + old_count]);
            old_offset += old_count;
        }

        let released_runs = extent_runs(&physical[kept..])?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(released_runs.len() + released_nodes.len())
            .map_err(|_| Error::OutOfMemory)?;
        ranges.extend(
            released_runs
                .into_iter()
                .map(|run| (run.physical, u64::from(run.length))),
        );
        ranges.extend(released_nodes.into_iter().map(|number| (number, 1)));
        let (groups, released) = self.release_blocks(&ranges)?;
        let descriptor_blocks = self.descriptor_blocks(&groups)?;

        let mut extent_nodes = Vec::new();
        extent_nodes
            .try_reserve_exact(retained_nodes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for number in retained_nodes {
            extent_nodes.push(DirtyBlock {
                number,
                bytes: self.read_owned_block(number)?,
            });
        }

        let mut metadata = MetadataMutation::new();
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        metadata.load(self, superblock_number)?;
        let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        let raw_superblock = &mut metadata.get_mut(superblock_number)?
            [superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
        increment_superblock_free_blocks(
            raw_superblock,
            released,
            self.transaction.filesystem.superblock.blocks_count,
        )?;
        update_superblock_checksum(raw_superblock);
        metadata.adopt_blocks(descriptor_blocks)?;
        metadata.adopt_group_edits(groups)?;

        if !new_size.is_multiple_of(block_size) {
            let last = physical[kept - 1];
            let mut block = self.read_owned_block(last)?;
            let tail =
                usize::try_from(new_size % block_size).map_err(|_| Corrupt::AddressOverflow)?;
            block[tail..].fill(0);
            metadata.adopt(last, block)?;
        }

        let (inode_block, inode_offset) = self.inode_location(inode.number)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        metadata.load(self, inode_block)?;
        let raw = &mut metadata.get_mut(inode_block)?[inode_offset..inode_offset + inode_size];
        let mut editor = InodeEditor::new(
            raw,
            self.transaction.filesystem.superblock.checksum_seed,
            inode.number,
            inode.generation,
        )?;
        if kept == 0 {
            editor.clear_extent_mapping()?;
        } else {
            editor.set_extent_mapping(
                &physical[..kept],
                new_size,
                block_size,
                &mut extent_nodes,
            )?;
        }
        editor.finish();
        metadata.adopt_blocks(extent_nodes)?;
        metadata.stage(self)?;
        Ok(released)
    }

    /// Read one filesystem block through this transaction's private view.
    pub fn read_block(&mut self, number: u64, dst: &mut [u8]) -> Result<(), Error<S::Error>> {
        if number >= self.transaction.filesystem.superblock.blocks_count
            || dst.len() != self.transaction.filesystem.superblock.block_size as usize
        {
            return Err(Error::InvalidArgument);
        }
        match self.dirty_index(number) {
            Ok(index) => dst.copy_from_slice(&self.dirty[index].bytes),
            Err(_) => {
                let offset = self.block_offset(number)?;
                self.transaction
                    .filesystem
                    .read_storage(self.storage, offset, dst)?;
            }
        }
        Ok(())
    }

    /// Replace one complete filesystem block in the private dirty set.
    pub fn write_block(&mut self, number: u64, src: &[u8]) -> Result<(), Error<S::Error>> {
        if number >= self.transaction.filesystem.superblock.blocks_count
            || src.len() != self.transaction.filesystem.superblock.block_size as usize
        {
            return Err(Error::InvalidArgument);
        }
        match self.dirty_index(number) {
            Ok(index) => self.dirty[index].bytes.copy_from_slice(src),
            Err(index) => {
                let dirty = self.insert_reserved(number, index)?;
                self.dirty[dirty].bytes.copy_from_slice(src);
            }
        }
        Ok(())
    }

    /// Load and mutate one complete block, preserving its private version.
    pub fn modify_block<F>(&mut self, number: u64, modify: F) -> Result<(), Error<S::Error>>
    where
        F: FnOnce(&mut [u8]),
    {
        if number >= self.transaction.filesystem.superblock.blocks_count {
            return Err(Error::InvalidArgument);
        }
        let index = match self.dirty_index(number) {
            Ok(index) => index,
            Err(index) => {
                let mut bytes = self.available.pop().ok_or(Error::ReservationExhausted)?;
                let offset = self.block_offset(number)?;
                if let Err(error) =
                    self.transaction
                        .filesystem
                        .read_storage(self.storage, offset, &mut bytes)
                {
                    self.available.push(bytes);
                    return Err(error);
                }
                self.dirty.insert(index, DirtyBlock { number, bytes });
                index
            }
        };
        modify(&mut self.dirty[index].bytes);
        Ok(())
    }

    fn dirty_index(&self, number: u64) -> Result<usize, usize> {
        self.dirty
            .binary_search_by_key(&number, |block| block.number)
    }

    fn insert_reserved(&mut self, number: u64, index: usize) -> Result<usize, Error<S::Error>> {
        let bytes = self.available.pop().ok_or(Error::ReservationExhausted)?;
        self.dirty.insert(index, DirtyBlock { number, bytes });
        Ok(index)
    }

    fn block_offset(&self, number: u64) -> Result<u64, Error<S::Error>> {
        number
            .checked_mul(u64::from(self.transaction.filesystem.superblock.block_size))
            .ok_or(Corrupt::AddressOverflow.into())
    }

    fn insert_into_directory(
        &mut self,
        tree: &mut DirectoryTree,
        resources: &mut Allocation,
        inode_number: u32,
        name: &[u8],
        file_type: u8,
    ) -> Result<Option<DirectoryGrowth>, Error<S::Error>> {
        match tree.insert(inode_number, name, file_type) {
            Ok(()) => Ok(None),
            Err(Error::Unsupported(Unsupported::ExtentMutation)) => {
                let growth = self.grow_linear_directory(tree, resources)?;
                tree.insert(inode_number, name, file_type)?;
                Ok(Some(growth))
            }
            Err(error) => Err(error),
        }
    }

    fn grow_linear_directory(
        &mut self,
        tree: &mut DirectoryTree,
        resources: &mut Allocation,
    ) -> Result<DirectoryGrowth, Error<S::Error>> {
        if tree.inode.flags & super::DIRECTORY_INDEX_FL != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let block_size_usize = usize::try_from(block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let ownership = self.read_extent_ownership(&tree.inode)?;
        let existing_nodes = ownership.tree;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(tree.nodes.len() + 1)
            .map_err(|_| Error::OutOfMemory)?;
        for (start, length) in ownership.data {
            for number in start..start + length {
                physical.push(number);
            }
        }
        if ownership.logical_blocks != tree.nodes.len() as u64
            || physical.len() != tree.nodes.len()
            || physical
                .iter()
                .zip(&tree.nodes)
                .any(|(physical, node)| *physical != node.block.number)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }

        let old_runs = extent_count(&physical)?;
        let node_capacity = (block_size_usize - 16) / 12;
        let old_shape = extent_tree_shape(old_runs, 4, node_capacity)?;
        if extent_tree_node_count(&old_shape)? != existing_nodes.len() {
            return Err(Corrupt::InvalidExtentTree.into());
        }

        let allocation_start = resources.blocks.len();
        self.extend_allocation(resources, 1)?;
        let leaf_number = resources.blocks[allocation_start];
        physical.push(leaf_number);
        let new_shape = extent_tree_shape(extent_count(&physical)?, 4, node_capacity)?;
        let required_nodes = extent_tree_node_count(&new_shape)?;
        if required_nodes < existing_nodes.len() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        self.extend_allocation(resources, required_nodes - existing_nodes.len())?;
        let node_numbers = merge_extent_node_numbers(
            &old_shape,
            &new_shape,
            &existing_nodes,
            &resources.blocks[allocation_start + 1..],
        )?;
        let mut extent_nodes = Vec::new();
        extent_nodes
            .try_reserve_exact(node_numbers.len())
            .map_err(|_| Error::OutOfMemory)?;
        for number in node_numbers {
            let bytes = if existing_nodes.contains(&number) {
                self.read_owned_block(number)?
            } else {
                self.zero_block()?
            };
            extent_nodes.push(DirtyBlock { number, bytes });
        }

        let mut leaf = self.zero_block()?;
        initialize_empty_directory_leaf(
            self.transaction.filesystem.superblock.checksum_seed,
            tree.inode.number,
            tree.inode.generation,
            &mut leaf,
        )?;
        let logical = u64::try_from(tree.nodes.len()).map_err(|_| Corrupt::AddressOverflow)?;
        tree.nodes.push(DirectoryNode {
            logical,
            kind: crate::DirectoryBlockKind::Leaf,
            block: DirtyBlock {
                number: leaf_number,
                bytes: leaf,
            },
            dirty: true,
        });
        let size = logical
            .checked_add(1)
            .and_then(|blocks| blocks.checked_mul(block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        Ok(DirectoryGrowth {
            inode: tree.inode.clone(),
            physical,
            size,
            extent_nodes,
        })
    }

    fn apply_directory_growth(
        &mut self,
        metadata: &mut MetadataMutation,
        mut growth: DirectoryGrowth,
    ) -> Result<(), Error<S::Error>> {
        let (block_number, offset) = self.inode_location(growth.inode.number)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        let checksum_seed = self.transaction.filesystem.superblock.checksum_seed;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        metadata.load(self, block_number)?;
        let block = metadata.get_mut(block_number)?;
        let end = offset
            .checked_add(inode_size)
            .filter(|end| *end <= block.len())
            .ok_or(Corrupt::InvalidInodeTable)?;
        let raw = &mut block[offset..end];
        let mut editor = InodeEditor::new(
            raw,
            checksum_seed,
            growth.inode.number,
            growth.inode.generation,
        )?;
        editor.set_extent_mapping(
            &growth.physical,
            growth.size,
            block_size,
            &mut growth.extent_nodes,
        )?;
        editor.finish();
        metadata.adopt_blocks(growth.extent_nodes)
    }

    fn apply_block_allocation(
        &mut self,
        metadata: &mut MetadataMutation,
        resources: Allocation,
    ) -> Result<(), Error<S::Error>> {
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        metadata.load(self, superblock_number)?;
        if !resources.blocks.is_empty() {
            let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
                .map_err(|_| Corrupt::AddressOverflow)?;
            let raw = &mut metadata.get_mut(superblock_number)?
                [superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
            decrement_superblock_free_blocks_by(
                raw,
                u64::try_from(resources.blocks.len()).map_err(|_| Corrupt::AddressOverflow)?,
            )?;
            update_superblock_checksum(raw);
        }
        let descriptor_blocks = self.descriptor_blocks(&resources.groups)?;
        metadata.adopt_blocks(descriptor_blocks)?;
        metadata.adopt_group_edits(resources.groups)
    }

    fn allocate_blocks(&mut self, wanted: usize) -> Result<Allocation, Error<S::Error>> {
        let mut allocation = Allocation {
            blocks: Vec::new(),
            groups: Vec::new(),
        };
        self.extend_allocation(&mut allocation, wanted)?;
        Ok(allocation)
    }

    /// Add blocks to an allocation while preserving its prospective bitmap
    /// edits. This lets callers allocate data first, inspect its extent shape,
    /// and then request exactly the tree metadata that shape requires.
    fn extend_allocation(
        &mut self,
        allocation: &mut Allocation,
        wanted: usize,
    ) -> Result<(), Error<S::Error>> {
        let target = allocation
            .blocks
            .len()
            .checked_add(wanted)
            .ok_or(Corrupt::AddressOverflow)?;
        allocation
            .blocks
            .try_reserve_exact(wanted)
            .map_err(|_| Error::OutOfMemory)?;
        allocation
            .groups
            .try_reserve_exact(self.transaction.filesystem.superblock.group_count() as usize)
            .map_err(|_| Error::OutOfMemory)?;
        let first_data = u64::from(self.transaction.filesystem.superblock.first_data_block);
        let blocks_per_group = u64::from(self.transaction.filesystem.superblock.blocks_per_group);
        let group_count = self.transaction.filesystem.superblock.group_count();
        let mut group_order = Vec::new();
        group_order
            .try_reserve_exact(group_count as usize)
            .map_err(|_| Error::OutOfMemory)?;
        for edit in &allocation.groups {
            group_order.push(edit.number);
        }
        for group in 0..group_count {
            if allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.number)
                .is_err()
            {
                group_order.push(group);
            }
        }

        for group in group_order {
            if allocation.blocks.len() == target {
                break;
            }
            let existing = allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.number);
            let (mut descriptor, mut bitmap) = match existing {
                Ok(position) => {
                    let mut edit = allocation.groups.remove(position);
                    let bitmap_number = u64::from(le32(&edit.descriptor, 0))
                        | (u64::from(le32(&edit.descriptor, 0x20)) << 32);
                    let bitmap = match edit.block_bitmap.take() {
                        Some(block) if block.number == bitmap_number => block.bytes,
                        Some(_) => return Err(Corrupt::InvalidBlockBitmap.into()),
                        None => {
                            let bitmap = self.read_owned_block(bitmap_number)?;
                            self.verify_block_bitmap_checksum(group, &edit.descriptor, &bitmap)?;
                            bitmap
                        }
                    };
                    (edit.descriptor, bitmap)
                }
                Err(_) => {
                    let mut descriptor = self
                        .transaction
                        .filesystem
                        .read_group_descriptor(self.storage, group)?;
                    let bitmap_number = u64::from(le32(&descriptor, 0))
                        | (u64::from(le32(&descriptor, 0x20)) << 32);
                    let bitmap = if le16(&descriptor, 0x12) & 0x0002 != 0 {
                        if group == 0 {
                            return Err(Corrupt::InvalidBlockBitmap.into());
                        }
                        let group_start = first_data
                            .checked_add(u64::from(group) * blocks_per_group)
                            .ok_or(Corrupt::AddressOverflow)?;
                        let group_blocks = self
                            .filesystem
                            .superblock
                            .blocks_count
                            .checked_sub(group_start)
                            .map(|remaining| remaining.min(blocks_per_group))
                            .ok_or(Corrupt::InvalidGroup(group))?;
                        let (bitmap, computed_free) = self.initialize_block_bitmap(
                            group,
                            &descriptor,
                            group_start,
                            group_blocks,
                        )?;
                        let stored_free = u64::from(le16(&descriptor, 0x0c))
                            | (u64::from(le16(&descriptor, 0x2c)) << 16);
                        if stored_free != computed_free {
                            return Err(Corrupt::InvalidFreeBlockCount.into());
                        }
                        let flags = le16(&descriptor, 0x12) & !0x0002;
                        put_le16(&mut descriptor, 0x12, flags);
                        bitmap
                    } else {
                        let bitmap = self.read_owned_block(bitmap_number)?;
                        self.verify_block_bitmap_checksum(group, &descriptor, &bitmap)?;
                        bitmap
                    };
                    (descriptor, bitmap)
                }
            };
            let bitmap_number =
                u64::from(le32(&descriptor, 0)) | (u64::from(le32(&descriptor, 0x20)) << 32);
            let group_start = first_data
                .checked_add(u64::from(group) * blocks_per_group)
                .ok_or(Corrupt::AddressOverflow)?;
            let group_blocks = self
                .filesystem
                .superblock
                .blocks_count
                .checked_sub(group_start)
                .map(|remaining| remaining.min(blocks_per_group))
                .ok_or(Corrupt::InvalidGroup(group))?;
            let free =
                u64::from(le16(&descriptor, 0x0c)) | (u64::from(le16(&descriptor, 0x2c)) << 16);
            if free == 0 {
                if existing.is_ok() {
                    let position = allocation
                        .groups
                        .binary_search_by_key(&group, |edit| edit.number)
                        .unwrap_or_else(|position| position);
                    allocation.groups.insert(
                        position,
                        GroupEdit {
                            number: group,
                            descriptor,
                            block_bitmap: Some(DirtyBlock {
                                number: bitmap_number,
                                bytes: bitmap,
                            }),
                        },
                    );
                }
                continue;
            }
            let before = allocation.blocks.len();
            for bit in 0..group_blocks {
                let index = usize::try_from(bit).map_err(|_| Corrupt::AddressOverflow)?;
                if bitmap[index / 8] & (1 << (index % 8)) == 0 {
                    bitmap[index / 8] |= 1 << (index % 8);
                    allocation.blocks.push(group_start + bit);
                    if allocation.blocks.len() == target {
                        break;
                    }
                }
            }
            let count = allocation.blocks.len() - before;
            if count == 0 {
                continue;
            }
            let count = u64::try_from(count).map_err(|_| Corrupt::AddressOverflow)?;
            decrement_descriptor_free_blocks_by(&mut descriptor, count)?;
            let checksum = self.block_bitmap_checksum(&bitmap);
            put_le16(&mut descriptor, 0x18, checksum as u16);
            put_le16(&mut descriptor, 0x38, (checksum >> 16) as u16);
            update_group_descriptor_checksum(
                self.transaction.filesystem.superblock.checksum_seed,
                group,
                &mut descriptor,
            );
            let position = allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.number)
                .unwrap_or_else(|position| position);
            allocation.groups.insert(
                position,
                GroupEdit {
                    number: group,
                    descriptor,
                    block_bitmap: Some(DirtyBlock {
                        number: bitmap_number,
                        bytes: bitmap,
                    }),
                },
            );
        }
        if allocation.blocks.len() != target {
            return Err(Corrupt::InvalidFreeBlockCount.into());
        }
        Ok(())
    }

    fn initialize_block_bitmap(
        &self,
        group: u32,
        descriptor: &[u8],
        group_start: u64,
        group_blocks: u64,
    ) -> Result<(Vec<u8>, u64), Error<S::Error>> {
        let superblock = &self.transaction.filesystem.superblock;
        let mut bitmap = self.zero_block()?;
        let has_super = if group == 0 {
            true
        } else if superblock.feature_compat & ondisk::COMPAT_SPARSE_SUPER2 != 0 {
            superblock.backup_bgs.contains(&group)
        } else if group <= 1 || superblock.feature_ro_compat & 0x0001 == 0 {
            true
        } else {
            group % 2 == 1
                && (is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7))
        };
        let descriptor_blocks = u64::from(superblock.group_count())
            .checked_mul(u64::from(superblock.descriptor_size))
            .ok_or(Corrupt::AddressOverflow)?
            .div_ceil(u64::from(superblock.block_size));
        let base_metadata = if has_super {
            1u64.checked_add(descriptor_blocks)
                .and_then(|value| value.checked_add(u64::from(superblock.reserved_gdt_blocks)))
                .ok_or(Corrupt::AddressOverflow)?
        } else {
            0
        };
        if base_metadata > group_blocks {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        set_bitmap_range(&mut bitmap, 0, base_metadata)?;

        let group_end = group_start
            .checked_add(group_blocks)
            .ok_or(Corrupt::AddressOverflow)?;
        let block_bitmap =
            u64::from(le32(descriptor, 0)) | (u64::from(le32(descriptor, 0x20)) << 32);
        let inode_bitmap =
            u64::from(le32(descriptor, 4)) | (u64::from(le32(descriptor, 0x24)) << 32);
        let inode_table =
            u64::from(le32(descriptor, 8)) | (u64::from(le32(descriptor, 0x28)) << 32);
        for metadata in [block_bitmap, inode_bitmap] {
            if metadata >= superblock.blocks_count {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            if group_start <= metadata && metadata < group_end {
                set_bitmap_range(&mut bitmap, metadata - group_start, 1)?;
            }
        }
        let inode_table_blocks = u64::from(superblock.inodes_per_group)
            .checked_mul(u64::from(superblock.inode_size))
            .ok_or(Corrupt::AddressOverflow)?
            .div_ceil(u64::from(superblock.block_size));
        let inode_table_end = inode_table
            .checked_add(inode_table_blocks)
            .filter(|end| *end <= superblock.blocks_count)
            .ok_or(Corrupt::InvalidInodeTable)?;
        let overlap_start = inode_table.max(group_start);
        let overlap_end = inode_table_end.min(group_end);
        if overlap_start < overlap_end {
            set_bitmap_range(
                &mut bitmap,
                overlap_start - group_start,
                overlap_end - overlap_start,
            )?;
        }

        let bitmap_bits = u64::try_from(bitmap.len())
            .map_err(|_| Corrupt::AddressOverflow)?
            .checked_mul(8)
            .ok_or(Corrupt::AddressOverflow)?;
        set_bitmap_range(&mut bitmap, group_blocks, bitmap_bits - group_blocks)?;
        let used = (0..group_blocks)
            .filter(|bit| bitmap[*bit as usize / 8] & (1 << (*bit as usize % 8)) != 0)
            .count();
        let used = u64::try_from(used).map_err(|_| Corrupt::AddressOverflow)?;
        Ok((bitmap, group_blocks - used))
    }

    fn allocate_inode(&mut self) -> Result<InodeAllocation, Error<S::Error>> {
        let inodes_per_group = u64::from(self.transaction.filesystem.superblock.inodes_per_group);
        let bitmap_bits = u64::from(self.transaction.filesystem.superblock.block_size) * 8;
        let group_count = self.transaction.filesystem.superblock.group_count();
        let inodes_count = u64::from(self.transaction.filesystem.superblock.inodes_count);
        let blocks_count = self.transaction.filesystem.superblock.blocks_count;
        let first_data_block = u64::from(self.transaction.filesystem.superblock.first_data_block);
        let blocks_per_group = u64::from(self.transaction.filesystem.superblock.blocks_per_group);
        let first_inode = u64::from(self.transaction.filesystem.superblock.first_inode);
        let checksum_seed = self.transaction.filesystem.superblock.checksum_seed;
        for group_number in 0..group_count {
            let group_first = u64::from(group_number) * inodes_per_group;
            let group_inodes = inodes_count
                .checked_sub(group_first)
                .map(|remaining| remaining.min(inodes_per_group))
                .ok_or(Corrupt::InvalidGroup(group_number))?;
            if group_inodes == 0 {
                break;
            }
            let mut descriptor = self
                .transaction
                .filesystem
                .read_group_descriptor(self.storage, group_number)?;
            let free =
                u64::from(le16(&descriptor, 0x0e)) | (u64::from(le16(&descriptor, 0x2e)) << 16);
            if free == 0 {
                continue;
            }
            if free > group_inodes {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            }

            let mut initialized_block_bitmap = None;
            if le16(&descriptor, 0x12) & 0x0002 != 0 {
                if group_number == 0 {
                    return Err(Corrupt::InvalidBlockBitmap.into());
                }
                let group_start = first_data_block
                    .checked_add(u64::from(group_number) * blocks_per_group)
                    .ok_or(Corrupt::AddressOverflow)?;
                let group_blocks = blocks_count
                    .checked_sub(group_start)
                    .map(|remaining| remaining.min(blocks_per_group))
                    .ok_or(Corrupt::InvalidGroup(group_number))?;
                let (bitmap, computed_free) = self.initialize_block_bitmap(
                    group_number,
                    &descriptor,
                    group_start,
                    group_blocks,
                )?;
                let stored_free =
                    u64::from(le16(&descriptor, 0x0c)) | (u64::from(le16(&descriptor, 0x2c)) << 16);
                if stored_free != computed_free {
                    return Err(Corrupt::InvalidFreeBlockCount.into());
                }
                let bitmap_number =
                    u64::from(le32(&descriptor, 0)) | (u64::from(le32(&descriptor, 0x20)) << 32);
                let checksum = self.block_bitmap_checksum(&bitmap);
                put_le16(&mut descriptor, 0x18, checksum as u16);
                put_le16(&mut descriptor, 0x38, (checksum >> 16) as u16);
                let flags = le16(&descriptor, 0x12) & !0x0002;
                put_le16(&mut descriptor, 0x12, flags);
                initialized_block_bitmap = Some(DirtyBlock {
                    number: bitmap_number,
                    bytes: bitmap,
                });
            }

            let inode_bitmap_number =
                u64::from(le32(&descriptor, 4)) | (u64::from(le32(&descriptor, 0x24)) << 32);
            let inode_table =
                u64::from(le32(&descriptor, 8)) | (u64::from(le32(&descriptor, 0x28)) << 32);
            if inode_bitmap_number >= blocks_count || inode_table >= blocks_count {
                return Err(Corrupt::InvalidInodeTable.into());
            }
            let was_uninitialized = le16(&descriptor, 0x12) & 0x0001 != 0;
            let mut bitmap = if was_uninitialized {
                if group_number == 0
                    || free != group_inodes
                    || le16(&descriptor, 0x12) & 0x0004 == 0
                {
                    return Err(Corrupt::InvalidBlockBitmap.into());
                }
                let mut bitmap = self.zero_block()?;
                set_bitmap_range(&mut bitmap, group_inodes, bitmap_bits - group_inodes)?;
                let flags = le16(&descriptor, 0x12) & !0x0001;
                put_le16(&mut descriptor, 0x12, flags);
                bitmap
            } else {
                let bitmap = self.read_owned_block(inode_bitmap_number)?;
                self.verify_inode_bitmap_checksum(group_number, &descriptor, &bitmap)?;
                bitmap
            };
            let start = if group_number == 0 {
                first_inode - 1
            } else {
                0
            };
            let Some(index) = (start..group_inodes)
                .find(|index| bitmap[*index as usize / 8] & (1 << (*index as usize % 8)) == 0)
            else {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            };
            bitmap[index as usize / 8] |= 1 << (index as usize % 8);
            decrement_descriptor_free_inodes(&mut descriptor)?;
            update_unused_inode_count(&mut descriptor, index, inodes_per_group)?;
            let checksum = self.inode_bitmap_checksum(&bitmap);
            put_le16(&mut descriptor, 0x1a, checksum as u16);
            put_le16(&mut descriptor, 0x3a, (checksum >> 16) as u16);
            update_group_descriptor_checksum(checksum_seed, group_number, &mut descriptor);
            let number = group_first
                .checked_add(index)
                .and_then(|number| number.checked_add(1))
                .and_then(|number| u32::try_from(number).ok())
                .ok_or(Corrupt::AddressOverflow)?;
            return Ok(InodeAllocation {
                number,
                index,
                inode_table,
                group_number,
                resources: Allocation {
                    blocks: Vec::new(),
                    groups: alloc::vec![GroupEdit {
                        number: group_number,
                        descriptor,
                        block_bitmap: initialized_block_bitmap,
                    }],
                },
                inode_bitmap: DirtyBlock {
                    number: inode_bitmap_number,
                    bytes: bitmap,
                },
            });
        }
        Err(Corrupt::InvalidFreeBlockCount.into())
    }

    fn release_inode_root_blocks(
        &mut self,
        inode: &Inode,
    ) -> Result<ReleasedInodeBlocks, Error<S::Error>> {
        let ownership = self.read_extent_ownership(inode)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let logical_blocks = ownership.logical_blocks;
        let mut ranges = ownership.data;
        let owned_blocks = ranges
            .iter()
            .try_fold(ownership.tree.len() as u64, |total, range| {
                total.checked_add(range.1).ok_or(Corrupt::AddressOverflow)
            })?;
        ranges
            .try_reserve_exact(ownership.tree.len() + usize::from(inode.external_xattr_block != 0))
            .map_err(|_| Error::OutOfMemory)?;
        ranges.extend(ownership.tree.into_iter().map(|number| (number, 1)));
        let mut retained_xattr_block = None;
        if inode.external_xattr_block != 0 {
            let mut block = self.read_external_xattr_block(inode)?;
            let references = le32(&block, 4);
            if references == 1 {
                ranges.push((inode.external_xattr_block, 1));
            } else {
                put_le32(&mut block, 4, references - 1);
                super::update_external_xattr_checksum(
                    self.transaction.filesystem.superblock.checksum_seed,
                    inode.external_xattr_block,
                    &mut block,
                );
                retained_xattr_block = Some(DirtyBlock {
                    number: inode.external_xattr_block,
                    bytes: block,
                });
            }
        }
        let (groups, released) = self.release_blocks(&ranges)?;
        if logical_blocks != inode.size.div_ceil(block_size)
            || inode.blocks_512
                != owned_blocks
                    .checked_add(u64::from(inode.external_xattr_block != 0))
                    .and_then(|blocks| blocks.checked_mul(block_size / 512))
                    .ok_or(Corrupt::AddressOverflow)?
        {
            return Err(Unsupported::ExtentMutation.into());
        }
        Ok(ReleasedInodeBlocks {
            groups,
            released,
            retained_xattr_block,
        })
    }

    fn release_blocks(
        &mut self,
        ranges: &[(u64, u64)],
    ) -> Result<(Vec<GroupEdit>, u64), Error<S::Error>> {
        let mut releases: Vec<BlockRelease> = Vec::new();
        releases
            .try_reserve_exact(ranges.len())
            .map_err(|_| Error::OutOfMemory)?;
        let mut released = 0u64;
        let first_data = u64::from(self.transaction.filesystem.superblock.first_data_block);
        let blocks_per_group = u64::from(self.transaction.filesystem.superblock.blocks_per_group);
        for &(physical, length) in ranges {
            released = released
                .checked_add(length)
                .ok_or(Corrupt::AddressOverflow)?;
            let end = physical
                .checked_add(length)
                .filter(|end| *end <= self.transaction.filesystem.superblock.blocks_count)
                .ok_or(Corrupt::InvalidExtentTree)?;
            for number in physical..end {
                let relative = number
                    .checked_sub(first_data)
                    .ok_or(Corrupt::InvalidExtentTree)?;
                let group = u32::try_from(relative / blocks_per_group)
                    .map_err(|_| Corrupt::AddressOverflow)?;
                let group_start = first_data
                    .checked_add(u64::from(group) * blocks_per_group)
                    .ok_or(Corrupt::AddressOverflow)?;
                let index = number - group_start;
                let position = match releases.binary_search_by_key(&group, |entry| entry.group) {
                    Ok(position) => position,
                    Err(position) => {
                        releases.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                        releases.insert(
                            position,
                            BlockRelease {
                                group,
                                indices: Vec::new(),
                            },
                        );
                        position
                    }
                };
                if releases[position].indices.contains(&index) {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                releases[position]
                    .indices
                    .try_reserve(1)
                    .map_err(|_| Error::OutOfMemory)?;
                releases[position].indices.push(index);
            }
        }

        let mut groups = Vec::new();
        groups
            .try_reserve_exact(releases.len())
            .map_err(|_| Error::OutOfMemory)?;
        for release in releases {
            let mut descriptor = self
                .transaction
                .filesystem
                .read_group_descriptor(self.storage, release.group)?;
            if le16(&descriptor, 0x12) & 0x0002 != 0 {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let bitmap_number =
                u64::from(le32(&descriptor, 0)) | (u64::from(le32(&descriptor, 0x20)) << 32);
            if bitmap_number >= self.transaction.filesystem.superblock.blocks_count {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let group_start = first_data
                .checked_add(u64::from(release.group) * blocks_per_group)
                .ok_or(Corrupt::AddressOverflow)?;
            let group_blocks = self
                .filesystem
                .superblock
                .blocks_count
                .checked_sub(group_start)
                .map(|remaining| remaining.min(blocks_per_group))
                .ok_or(Corrupt::InvalidGroup(release.group))?;
            let (reserved, _) = self.initialize_block_bitmap(
                release.group,
                &descriptor,
                group_start,
                group_blocks,
            )?;
            let mut bitmap = self.read_owned_block(bitmap_number)?;
            self.verify_block_bitmap_checksum(release.group, &descriptor, &bitmap)?;
            for &index in &release.indices {
                let index = usize::try_from(index).map_err(|_| Corrupt::AddressOverflow)?;
                if reserved[index / 8] & (1 << (index % 8)) != 0
                    || bitmap[index / 8] & (1 << (index % 8)) == 0
                {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                bitmap[index / 8] &= !(1 << (index % 8));
            }
            increment_descriptor_free_blocks(
                &mut descriptor,
                release.indices.len() as u64,
                group_blocks,
            )?;
            let checksum = self.block_bitmap_checksum(&bitmap);
            put_le16(&mut descriptor, 0x18, checksum as u16);
            put_le16(&mut descriptor, 0x38, (checksum >> 16) as u16);
            update_group_descriptor_checksum(
                self.transaction.filesystem.superblock.checksum_seed,
                release.group,
                &mut descriptor,
            );
            groups.push(GroupEdit {
                number: release.group,
                descriptor,
                block_bitmap: Some(DirtyBlock {
                    number: bitmap_number,
                    bytes: bitmap,
                }),
            });
        }
        Ok((groups, released))
    }
    /// Return every block owned by a fully allocated extent inode, separating
    /// file data from extent-tree metadata.  Namespace mutation consumes this
    /// one checked description instead of knowing which tree depth was used.
    fn read_extent_ownership(&mut self, inode: &Inode) -> Result<ExtentOwnership, Error<S::Error>> {
        let root = &inode.block_map;
        validate_extent_header(root, 4)?;
        let depth = le16(root, 6);
        if depth > 5 {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        let mut ownership = ExtentOwnership {
            data: Vec::new(),
            tree: Vec::new(),
            logical_blocks: 0,
        };
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(usize::from(depth))
            .map_err(|_| Error::OutOfMemory)?;
        levels.resize_with(usize::from(depth), Vec::new);
        self.collect_extent_ownership_node(root, depth, inode, &mut ownership, &mut levels)?;
        for level in levels {
            ownership
                .tree
                .try_reserve_exact(level.len())
                .map_err(|_| Error::OutOfMemory)?;
            ownership.tree.extend(level);
        }
        for &tree in &ownership.tree {
            if ownership
                .data
                .iter()
                .any(|(start, length)| *start <= tree && tree < *start + *length)
            {
                return Err(Corrupt::InvalidExtentTree.into());
            }
        }
        if ownership.data.iter().any(|(start, length)| {
            start
                .checked_add(*length)
                .is_none_or(|end| end > self.transaction.filesystem.superblock.blocks_count)
        }) {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        Ok(ownership)
    }

    fn collect_extent_ownership_node(
        &mut self,
        node: &[u8],
        depth: u16,
        inode: &Inode,
        ownership: &mut ExtentOwnership,
        levels: &mut [Vec<u64>],
    ) -> Result<(), Error<S::Error>> {
        if le16(node, 6) != depth {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        if depth == 0 {
            return collect_extent_leaf(node, ownership);
        }
        let entries = usize::from(le16(node, 2));
        if entries == 0 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let child_depth = depth - 1;
        let mut previous = None;
        for index in 0..entries {
            let at = 12 + index * 12;
            let logical = u64::from(le32(node, at));
            if previous.is_some_and(|value| logical <= value) || logical != ownership.logical_blocks
            {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            previous = Some(logical);
            let number = u64::from(le32(node, at + 4)) | (u64::from(le16(node, at + 8)) << 32);
            if number == 0
                || number >= self.transaction.filesystem.superblock.blocks_count
                || levels.iter().any(|level| level.contains(&number))
                || ownership
                    .data
                    .iter()
                    .any(|(start, length)| *start <= number && number < *start + *length)
            {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            let child = self.read_owned_block(number)?;
            validate_extent_header(&child, (child.len() - 12) / 12)?;
            if le16(&child, 6) != child_depth {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            verify_extent_block_checksum(
                self.transaction.filesystem.superblock.checksum_seed,
                inode,
                &child,
                self.transaction
                    .filesystem
                    .superblock
                    .has_metadata_checksums(),
            )?;
            self.collect_extent_ownership_node(&child, child_depth, inode, ownership, levels)?;
            levels[usize::from(child_depth)]
                .try_reserve(1)
                .map_err(|_| Error::OutOfMemory)?;
            levels[usize::from(child_depth)].push(number);
        }
        Ok(())
    }

    fn prepare_inode_release(
        &mut self,
        inode: &Inode,
        kind: ReleaseKind,
    ) -> Result<PreparedInodeRelease, Error<S::Error>> {
        let valid = match kind {
            ReleaseKind::Regular => {
                inode.mode & 0xf000 == 0x8000
                    && inode.links == 1
                    && inode.flags == super::EXTENTS_FL
            }
            ReleaseKind::Directory => {
                inode.mode & 0xf000 == 0x4000
                    && inode.links == 2
                    && inode.flags & !(super::EXTENTS_FL | super::DIRECTORY_INDEX_FL) == 0
                    && inode.flags & super::EXTENTS_FL != 0
            }
            ReleaseKind::FastSymlink => {
                inode.mode & 0xf000 == 0xa000
                    && inode.links == 1
                    && inode.size <= 60
                    && inode.blocks_512 == 0
            }
        };
        if !valid {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let released = match kind {
            ReleaseKind::FastSymlink => ReleasedInodeBlocks {
                groups: Vec::new(),
                released: 0,
                retained_xattr_block: None,
            },
            ReleaseKind::Regular | ReleaseKind::Directory => {
                self.release_inode_root_blocks(inode)?
            }
        };
        let ReleasedInodeBlocks {
            mut groups,
            released: released_blocks,
            retained_xattr_block,
        } = released;
        let zero_based = inode
            .number
            .checked_sub(1)
            .ok_or(Corrupt::InvalidInode(inode.number))?;
        let inode_group = zero_based / self.transaction.filesystem.superblock.inodes_per_group;
        let inode_index =
            u64::from(zero_based % self.transaction.filesystem.superblock.inodes_per_group);
        let position = match groups.binary_search_by_key(&inode_group, |group| group.number) {
            Ok(position) => position,
            Err(position) => {
                let descriptor = self
                    .transaction
                    .filesystem
                    .read_group_descriptor(self.storage, inode_group)?;
                groups.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                groups.insert(
                    position,
                    GroupEdit {
                        number: inode_group,
                        descriptor,
                        block_bitmap: None,
                    },
                );
                position
            }
        };
        let descriptor = &mut groups[position].descriptor;
        if le16(descriptor, 0x12) & 0x0001 != 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let inode_bitmap_number =
            u64::from(le32(descriptor, 4)) | (u64::from(le32(descriptor, 0x24)) << 32);
        let inode_table =
            u64::from(le32(descriptor, 8)) | (u64::from(le32(descriptor, 0x28)) << 32);
        if inode_bitmap_number >= self.transaction.filesystem.superblock.blocks_count
            || inode_table >= self.transaction.filesystem.superblock.blocks_count
        {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        let mut inode_bitmap = self.read_owned_block(inode_bitmap_number)?;
        self.verify_inode_bitmap_checksum(inode_group, descriptor, &inode_bitmap)?;
        let bit = usize::try_from(inode_index).map_err(|_| Corrupt::AddressOverflow)?;
        if inode_bitmap[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        inode_bitmap[bit / 8] &= !(1 << (bit % 8));
        increment_descriptor_free_inodes(
            descriptor,
            u64::from(self.transaction.filesystem.superblock.inodes_per_group),
        )?;
        if matches!(kind, ReleaseKind::Directory) {
            decrement_descriptor_used_directories(
                descriptor,
                u64::from(self.transaction.filesystem.superblock.inodes_per_group),
            )?;
        }
        let checksum = self.inode_bitmap_checksum(&inode_bitmap);
        put_le16(descriptor, 0x1a, checksum as u16);
        put_le16(descriptor, 0x3a, (checksum >> 16) as u16);
        update_group_descriptor_checksum(
            self.transaction.filesystem.superblock.checksum_seed,
            inode_group,
            descriptor,
        );
        let descriptors = self.descriptor_blocks(&groups)?;

        let inode_byte = inode_table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(
                    inode_index * u64::from(self.transaction.filesystem.superblock.inode_size),
                )
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let inode_block_number = inode_byte / block_size;
        let inode_offset =
            usize::try_from(inode_byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        let mut inode_block = self.read_owned_block(inode_block_number)?;
        if inode_offset + inode_size > inode_block.len() {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        inode_block[inode_offset..inode_offset + inode_size].fill(0);

        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let mut superblock = self.read_owned_block(superblock_number)?;
        let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        let raw = &mut superblock[superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
        increment_superblock_free_inodes(
            raw,
            u64::from(self.transaction.filesystem.superblock.inodes_count),
        )?;
        increment_superblock_free_blocks(
            raw,
            released_blocks,
            self.transaction.filesystem.superblock.blocks_count,
        )?;
        update_superblock_checksum(raw);

        let mut block_bitmaps = Vec::new();
        block_bitmaps
            .try_reserve_exact(groups.len())
            .map_err(|_| Error::OutOfMemory)?;
        for group in groups {
            if let Some(block) = group.block_bitmap {
                block_bitmaps.push(block);
            }
        }
        Ok(PreparedInodeRelease {
            superblock: DirtyBlock {
                number: superblock_number,
                bytes: superblock,
            },
            descriptors,
            block_bitmaps,
            inode_bitmap: DirtyBlock {
                number: inode_bitmap_number,
                bytes: inode_bitmap,
            },
            inode_block: DirtyBlock {
                number: inode_block_number,
                bytes: inode_block,
            },
            retained_xattr_block,
        })
    }

    fn prepare_empty_directory_release(
        &mut self,
        directory: &Inode,
        parent_number: u32,
    ) -> Result<PreparedInodeRelease, Error<S::Error>> {
        if !directory.is_directory() || directory.links != 2 {
            return Err(Unsupported::MutationProfile.into());
        }
        DirectoryTree::load(self, directory)?.validate_empty(parent_number)?;
        self.prepare_inode_release(directory, ReleaseKind::Directory)
    }

    fn stage_file_allocation(
        &mut self,
        superblock: DirtyBlock,
        inode: DirtyBlock,
        descriptors: Vec<DirtyBlock>,
        groups: Vec<GroupEdit>,
        payloads: Vec<DirtyBlock>,
    ) -> Result<(), Error<S::Error>> {
        let mut metadata = MetadataMutation::new();
        metadata.adopt_block(superblock)?;
        metadata.adopt_block(inode)?;
        metadata.adopt_blocks(descriptors)?;
        metadata.adopt_group_edits(groups)?;
        metadata.adopt_blocks(payloads)?;
        metadata.stage(self)
    }

    fn stage_overwrite(
        &mut self,
        superblock: DirtyBlock,
        data: Vec<DirtyBlock>,
    ) -> Result<(), Error<S::Error>> {
        let mut metadata = MetadataMutation::new();
        metadata.adopt_block(superblock)?;
        metadata.adopt_blocks(data)?;
        metadata.stage(self)
    }

    fn stage_inode_release(
        &mut self,
        release: PreparedInodeRelease,
        namespace: Vec<DirtyBlock>,
    ) -> Result<(), Error<S::Error>> {
        let mut metadata = MetadataMutation::new();
        metadata.adopt_block(release.superblock)?;
        metadata.adopt_blocks(release.descriptors)?;
        metadata.adopt_blocks(release.block_bitmaps)?;
        metadata.adopt_block(release.inode_bitmap)?;
        metadata.adopt_block(release.inode_block)?;
        if let Some(block) = release.retained_xattr_block {
            metadata.adopt_block(block)?;
        }
        metadata.adopt_blocks(namespace)?;
        metadata.stage(self)
    }

    fn stage_replaced_directory(
        &mut self,
        release: PreparedInodeRelease,
        namespace: Vec<DirtyBlock>,
        old_parent: &Inode,
    ) -> Result<(), Error<S::Error>> {
        let mut metadata = MetadataMutation::new();
        metadata.adopt_block(release.superblock)?;
        metadata.adopt_blocks(release.descriptors)?;
        metadata.adopt_blocks(release.block_bitmaps)?;
        metadata.adopt_block(release.inode_bitmap)?;
        metadata.adopt_block(release.inode_block)?;
        if let Some(block) = release.retained_xattr_block {
            metadata.adopt_block(block)?;
        }
        metadata.adopt_blocks(namespace)?;
        metadata.edit_inode(self, old_parent, |editor| {
            editor.set_links(old_parent.links - 1);
            Ok(())
        })?;
        metadata.stage(self)
    }

    fn descriptor_blocks(
        &mut self,
        groups: &[GroupEdit],
    ) -> Result<Vec<DirtyBlock>, Error<S::Error>> {
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let descriptor_size = u64::from(self.transaction.filesystem.superblock.descriptor_size);
        let table = self
            .transaction
            .filesystem
            .superblock
            .descriptor_table_offset();
        let mut blocks: Vec<DirtyBlock> = Vec::new();
        blocks
            .try_reserve_exact(groups.len())
            .map_err(|_| Error::OutOfMemory)?;
        for group in groups {
            let byte = table
                .checked_add(u64::from(group.number) * descriptor_size)
                .ok_or(Corrupt::AddressOverflow)?;
            let number = byte / block_size;
            let offset =
                usize::try_from(byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
            let index = match blocks.binary_search_by_key(&number, |block| block.number) {
                Ok(index) => index,
                Err(index) => {
                    let block = self.read_owned_block(number)?;
                    blocks.insert(
                        index,
                        DirtyBlock {
                            number,
                            bytes: block,
                        },
                    );
                    index
                }
            };
            let end = offset
                .checked_add(group.descriptor.len())
                .filter(|end| *end <= blocks[index].bytes.len())
                .ok_or(Corrupt::InvalidGroup(group.number))?;
            blocks[index].bytes[offset..end].copy_from_slice(&group.descriptor);
        }
        Ok(blocks)
    }

    fn inode_location(&mut self, number: u32) -> Result<(u64, usize), Error<S::Error>> {
        let zero_based = number
            .checked_sub(1)
            .filter(|number| *number < self.transaction.filesystem.superblock.inodes_count)
            .ok_or(Corrupt::InvalidInode(number))?;
        let group = zero_based / self.transaction.filesystem.superblock.inodes_per_group;
        let index = u64::from(zero_based % self.transaction.filesystem.superblock.inodes_per_group);
        let descriptor = self
            .transaction
            .filesystem
            .read_group_descriptor(self.storage, group)?;
        let table = u64::from(le32(&descriptor, 8)) | (u64::from(le32(&descriptor, 0x28)) << 32);
        if table >= self.transaction.filesystem.superblock.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let byte = table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(
                    index * u64::from(self.transaction.filesystem.superblock.inode_size),
                )
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let block = byte / block_size;
        let offset = usize::try_from(byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        if block >= self.transaction.filesystem.superblock.blocks_count
            || offset + usize::from(self.transaction.filesystem.superblock.inode_size)
                > block_size as usize
        {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        Ok((block, offset))
    }

    fn ensure_directory_move_acyclic(
        &mut self,
        source_number: u32,
        new_parent: &Inode,
    ) -> Result<(), Error<S::Error>> {
        let mut current = new_parent.clone();
        for _ in 0..self.transaction.filesystem.superblock.inodes_count {
            if current.number == source_number {
                return Err(Error::InvalidArgument);
            }
            if current.number == super::ROOT_INODE {
                return Ok(());
            }
            let parent_number = self.directory_parent_number(&current)?;
            if parent_number == current.number {
                return Err(Corrupt::InvalidDirectory.into());
            }
            current = self
                .transaction
                .filesystem
                .load_inode(self.storage, parent_number)?;
            if !current.is_directory() {
                return Err(Corrupt::InvalidDirectory.into());
            }
        }
        Err(Corrupt::InvalidDirectory.into())
    }

    fn directory_parent_number(&mut self, directory: &Inode) -> Result<u32, Error<S::Error>> {
        let block_size = usize::try_from(self.transaction.filesystem.superblock.block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        if !directory.is_directory() || directory.size < block_size as u64 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let number = self
            .map_file_block(directory, 0)?
            .ok_or(Corrupt::InvalidDirectory)?;
        let block = self.read_owned_block(number)?;
        let kind = self
            .filesystem
            .directory_block_kind(directory, 0, block_size, &block);
        self.transaction
            .filesystem
            .verify_directory_checksum(directory, kind, block_size, &block)?;
        directory_parent_entry(&block, directory.number)
    }

    fn validate_mutation_profile(&self) -> Result<(), Error<S::Error>> {
        const ALLOWED_RO_COMPAT: u32 = 0x0001 // sparse_super
            | 0x0002 // large_file
            | 0x0008 // huge_file
            | 0x0020 // dir_nlink
            | 0x0040 // extra_isize
            | ondisk::RO_COMPAT_METADATA_CSUM;
        const ALLOWED_INCOMPAT: u32 = ondisk::INCOMPAT_FILETYPE
            | ondisk::INCOMPAT_EXTENTS
            | ondisk::INCOMPAT_64BIT
            | ondisk::INCOMPAT_FLEX_BG
            | ondisk::INCOMPAT_CSUM_SEED;
        let superblock = &self.transaction.filesystem.superblock;
        if superblock.block_size != 4096
            || superblock.descriptor_size != 64
            || !superblock.has_metadata_checksums()
            || superblock.feature_incompat & ondisk::INCOMPAT_EXTENTS == 0
            || superblock.feature_incompat & ondisk::INCOMPAT_64BIT == 0
            || superblock.feature_ro_compat & ondisk::RO_COMPAT_BIGALLOC != 0
            || superblock.feature_ro_compat & !ALLOWED_RO_COMPAT != 0
            || superblock.feature_incompat & !ALLOWED_INCOMPAT != 0
            || superblock.first_data_block != 0
            || u64::from(superblock.blocks_per_group) > u64::from(superblock.block_size) * 8
            || u64::from(superblock.inodes_per_group) > u64::from(superblock.block_size) * 8
            || !superblock
                .block_size
                .is_multiple_of(u32::from(superblock.descriptor_size))
            || !superblock
                .block_size
                .is_multiple_of(u32::from(superblock.inode_size))
        {
            return Err(Unsupported::MutationProfile.into());
        }
        Ok(())
    }

    fn read_owned_block(&mut self, number: u64) -> Result<Vec<u8>, Error<S::Error>> {
        let mut block = self.transaction.filesystem.new_block_buffer()?;
        self.read_block(number, &mut block)?;
        Ok(block)
    }

    fn zero_block(&self) -> Result<Vec<u8>, Error<S::Error>> {
        self.transaction.filesystem.new_block_buffer()
    }

    fn block_bitmap_checksum(&self, bitmap: &[u8]) -> u32 {
        let bytes = usize::try_from(
            self.transaction
                .filesystem
                .superblock
                .blocks_per_group
                .div_ceil(8),
        )
        .unwrap_or(bitmap.len())
        .min(bitmap.len());
        let mut checksum =
            Checksum::with_seed(self.transaction.filesystem.superblock.checksum_seed);
        checksum.update(&bitmap[..bytes]);
        checksum.finalize()
    }

    fn inode_bitmap_checksum(&self, bitmap: &[u8]) -> u32 {
        let bytes = usize::try_from(
            self.transaction
                .filesystem
                .superblock
                .inodes_per_group
                .div_ceil(8),
        )
        .unwrap_or(bitmap.len());
        let mut checksum =
            Checksum::with_seed(self.transaction.filesystem.superblock.checksum_seed);
        checksum.update(&bitmap[..bytes]);
        checksum.finalize()
    }

    fn verify_block_bitmap_checksum(
        &self,
        group: u32,
        descriptor: &[u8],
        bitmap: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let expected =
            u32::from(le16(descriptor, 0x18)) | (u32::from(le16(descriptor, 0x38)) << 16);
        if self.block_bitmap_checksum(bitmap) != expected {
            return Err(Corrupt::BlockBitmapChecksum(group).into());
        }
        Ok(())
    }

    fn verify_inode_bitmap_checksum(
        &self,
        group: u32,
        descriptor: &[u8],
        bitmap: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let expected =
            u32::from(le16(descriptor, 0x1a)) | (u32::from(le16(descriptor, 0x3a)) << 16);
        if self.inode_bitmap_checksum(bitmap) != expected {
            return Err(Corrupt::InodeBitmapChecksum(group).into());
        }
        Ok(())
    }
}

fn decrement_descriptor_free_blocks_by<E>(
    descriptor: &mut [u8],
    amount: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le16(descriptor, 0x0c)) | (u64::from(le16(descriptor, 0x2c)) << 16);
    let free = free
        .checked_sub(amount)
        .filter(|free| *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0c, free as u16);
    put_le16(descriptor, 0x2c, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_free_blocks<E>(
    descriptor: &mut [u8],
    amount: u64,
    group_blocks: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le16(descriptor, 0x0c)) | (u64::from(le16(descriptor, 0x2c)) << 16);
    let free = free
        .checked_add(amount)
        .filter(|free| *free <= group_blocks && *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0c, free as u16);
    put_le16(descriptor, 0x2c, (free >> 16) as u16);
    Ok(())
}

fn decrement_descriptor_free_inodes<E>(descriptor: &mut [u8]) -> Result<(), Error<E>> {
    let free = u32::from(le16(descriptor, 0x0e)) | (u32::from(le16(descriptor, 0x2e)) << 16);
    let free = free.checked_sub(1).ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0e, free as u16);
    put_le16(descriptor, 0x2e, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_free_inodes<E>(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le16(descriptor, 0x0e)) | (u64::from(le16(descriptor, 0x2e)) << 16);
    let free = free
        .checked_add(1)
        .filter(|free| *free <= inodes_per_group && *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0e, free as u16);
    put_le16(descriptor, 0x2e, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_used_directories<E>(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error<E>> {
    let used = u64::from(le16(descriptor, 0x10)) | (u64::from(le16(descriptor, 0x30)) << 16);
    let used = used
        .checked_add(1)
        .filter(|used| *used <= inodes_per_group && *used <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x10, used as u16);
    put_le16(descriptor, 0x30, (used >> 16) as u16);
    Ok(())
}

fn decrement_descriptor_used_directories<E>(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error<E>> {
    let used = u64::from(le16(descriptor, 0x10)) | (u64::from(le16(descriptor, 0x30)) << 16);
    if used > inodes_per_group {
        return Err(Corrupt::InvalidFreeBlockCount.into());
    }
    let used = used.checked_sub(1).ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x10, used as u16);
    put_le16(descriptor, 0x30, (used >> 16) as u16);
    Ok(())
}

fn update_unused_inode_count<E>(
    descriptor: &mut [u8],
    allocated_index: u64,
    inodes_per_group: u64,
) -> Result<(), Error<E>> {
    let unused = u64::from(le16(descriptor, 0x1c)) | (u64::from(le16(descriptor, 0x3c)) << 16);
    if unused > inodes_per_group || allocated_index >= inodes_per_group {
        return Err(Corrupt::InvalidFreeBlockCount.into());
    }
    let initialized = inodes_per_group - unused;
    if allocated_index >= initialized {
        let new_unused = inodes_per_group - allocated_index - 1;
        put_le16(descriptor, 0x1c, new_unused as u16);
        put_le16(descriptor, 0x3c, (new_unused >> 16) as u16);
    }
    Ok(())
}

fn decrement_superblock_free_blocks_by<E>(
    superblock: &mut [u8],
    amount: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le32(superblock, 0x0c)) | (u64::from(le32(superblock, 0x158)) << 32);
    let free = free
        .checked_sub(amount)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x0c, free as u32);
    put_le32(superblock, 0x158, (free >> 32) as u32);
    Ok(())
}

fn increment_superblock_free_blocks<E>(
    superblock: &mut [u8],
    amount: u64,
    blocks_count: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le32(superblock, 0x0c)) | (u64::from(le32(superblock, 0x158)) << 32);
    let free = free
        .checked_add(amount)
        .filter(|free| *free <= blocks_count)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x0c, free as u32);
    put_le32(superblock, 0x158, (free >> 32) as u32);
    Ok(())
}

fn decrement_superblock_free_inodes<E>(superblock: &mut [u8]) -> Result<(), Error<E>> {
    let free = le32(superblock, 0x10)
        .checked_sub(1)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x10, free);
    Ok(())
}

fn increment_superblock_free_inodes<E>(
    superblock: &mut [u8],
    inodes_count: u64,
) -> Result<(), Error<E>> {
    let free = u64::from(le32(superblock, 0x10));
    let free = free
        .checked_add(1)
        .filter(|free| *free <= inodes_count && *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x10, free as u32);
    Ok(())
}

fn update_group_descriptor_checksum(seed: u32, group: u32, descriptor: &mut [u8]) {
    put_le16(descriptor, 0x1e, 0);
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(group);
    checksum.update(descriptor);
    put_le16(descriptor, 0x1e, checksum.finalize() as u16);
}

fn update_superblock_checksum(superblock: &mut [u8]) {
    let mut checksum = Checksum::new();
    checksum.update(&superblock[..0x3fc]);
    put_le32(superblock, 0x3fc, checksum.finalize());
}

fn extent_count<E>(allocated: &[u64]) -> Result<usize, Error<E>> {
    Ok(extent_runs(allocated)?.len())
}

#[derive(Clone, Copy)]
struct ExtentRun {
    logical: u64,
    physical: u64,
    length: u16,
}

#[derive(Clone, Copy)]
struct ExtentIndex {
    logical: u64,
    physical: u64,
}

fn extent_runs<E>(allocated: &[u64]) -> Result<Vec<ExtentRun>, Error<E>> {
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(allocated.len())
        .map_err(|_| Error::OutOfMemory)?;
    let mut count = 0usize;
    let mut run = 0usize;
    let mut previous = None;
    let mut start = 0u64;
    for (logical, &physical) in allocated.iter().enumerate() {
        if previous.and_then(|value: u64| value.checked_add(1)) != Some(physical) || run == 32_768 {
            count = count.checked_add(1).ok_or(Corrupt::AddressOverflow)?;
            if run != 0 {
                extents.push(ExtentRun {
                    logical: logical as u64 - run as u64,
                    physical: start,
                    length: run as u16,
                });
            }
            start = physical;
            run = 0;
        }
        run += 1;
        previous = Some(physical);
    }
    if run != 0 {
        extents.push(ExtentRun {
            logical: allocated.len() as u64 - run as u64,
            physical: start,
            length: run as u16,
        });
    }
    debug_assert_eq!(count, extents.len());
    Ok(extents)
}

fn validate_extent_header<E>(node: &[u8], capacity: usize) -> Result<(), Error<E>> {
    if node.len() < 12 || le16(node, 0) != super::EXTENT_MAGIC {
        return Err(Corrupt::InvalidExtentHeader.into());
    }
    let entries = usize::from(le16(node, 2));
    let max = usize::from(le16(node, 4));
    if entries > max || max > capacity {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    Ok(())
}

fn verify_extent_block_checksum<E>(
    seed: u32,
    inode: &Inode,
    node: &[u8],
    enabled: bool,
) -> Result<(), Error<E>> {
    if !enabled {
        return Ok(());
    }
    let checksum_offset = 12usize
        .checked_add(
            usize::from(le16(node, 4))
                .checked_mul(12)
                .ok_or(Corrupt::AddressOverflow)?,
        )
        .ok_or(Corrupt::AddressOverflow)?;
    if checksum_offset + 4 > node.len() {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(inode.number);
    checksum.update_u32_le(inode.generation);
    checksum.update(&node[..checksum_offset]);
    if checksum.finalize() != le32(node, checksum_offset) {
        return Err(Corrupt::ExtentChecksum(inode.number).into());
    }
    Ok(())
}

fn collect_extent_leaf<E>(node: &[u8], ownership: &mut ExtentOwnership) -> Result<(), Error<E>> {
    let entries = usize::from(le16(node, 2));
    ownership
        .data
        .try_reserve_exact(entries)
        .map_err(|_| Error::OutOfMemory)?;
    for index in 0..entries {
        let at = 12 + index * 12;
        let logical = u64::from(le32(node, at));
        let encoded_length = le16(node, at + 4);
        if encoded_length == 0 || encoded_length > 32_768 || logical != ownership.logical_blocks {
            return Err(Unsupported::ExtentMutation.into());
        }
        let length = u64::from(encoded_length);
        let physical = u64::from(le32(node, at + 8)) | (u64::from(le16(node, at + 6)) << 32);
        let end = physical
            .checked_add(length)
            .ok_or(Corrupt::AddressOverflow)?;
        if ownership
            .data
            .iter()
            .any(|(start, existing)| physical < *start + *existing && *start < end)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        ownership.data.push((physical, length));
        ownership.logical_blocks = ownership
            .logical_blocks
            .checked_add(length)
            .ok_or(Corrupt::AddressOverflow)?;
    }
    Ok(())
}

fn write_extent_mapping<E>(
    inode: &mut [u8],
    allocated: &[u64],
    size: u64,
    block_size: u64,
    identity: (u32, u32, u32),
    nodes: &mut [DirtyBlock],
) -> Result<(), Error<E>> {
    let root = inode.get_mut(0x28..0x64).ok_or(Corrupt::InvalidInode(0))?;
    let runs = extent_runs(allocated)?;
    if allocated.is_empty() || le16(root, 0) != super::EXTENT_MAGIC {
        return Err(Unsupported::ExtentMutation.into());
    }

    let root_capacity = usize::from(le16(root, 4));
    let node_capacity = usize::try_from(
        block_size
            .checked_sub(16)
            .ok_or(Corrupt::InvalidExtentTree)?
            / 12,
    )
    .map_err(|_| Corrupt::AddressOverflow)?;
    let shape = extent_tree_shape(runs.len(), root_capacity, node_capacity)?;
    let required_nodes = shape.iter().try_fold(0usize, |total, count| {
        total.checked_add(*count).ok_or(Corrupt::AddressOverflow)
    })?;
    if nodes.len() != required_nodes
        || nodes.iter().enumerate().any(|(index, node)| {
            node.number == 0
                || node.number >> 48 != 0
                || node.bytes.len() != block_size as usize
                || nodes[..index]
                    .iter()
                    .any(|previous| previous.number == node.number)
                || allocated.contains(&node.number)
        })
    {
        return Err(Corrupt::InvalidExtentTree.into());
    }

    root[12..].fill(0);
    if shape.is_empty() {
        if runs.len() > root_capacity {
            return Err(Unsupported::ExtentMutation.into());
        }
        put_le16(root, 2, runs.len() as u16);
        put_le16(root, 6, 0);
        write_extent_entries(root, &runs)?;
    } else {
        let mut summaries = Vec::new();
        summaries
            .try_reserve_exact(shape[0])
            .map_err(|_| Error::OutOfMemory)?;
        for (block, chunk) in nodes[..shape[0]].iter_mut().zip(runs.chunks(node_capacity)) {
            initialize_extent_node(&mut block.bytes, chunk.len(), node_capacity, 0);
            write_extent_entries(&mut block.bytes, chunk)?;
            checksum_extent_node(&mut block.bytes, node_capacity, identity);
            summaries.push(ExtentIndex {
                logical: chunk[0].logical,
                physical: block.number,
            });
        }

        let mut node_offset = shape[0];
        for (level, &node_count) in shape.iter().enumerate().skip(1) {
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(node_count)
                .map_err(|_| Error::OutOfMemory)?;
            for (block, chunk) in nodes[node_offset..node_offset + node_count]
                .iter_mut()
                .zip(summaries.chunks(node_capacity))
            {
                initialize_extent_node(&mut block.bytes, chunk.len(), node_capacity, level as u16);
                write_extent_indexes(&mut block.bytes, chunk)?;
                checksum_extent_node(&mut block.bytes, node_capacity, identity);
                parents.push(ExtentIndex {
                    logical: chunk[0].logical,
                    physical: block.number,
                });
            }
            summaries = parents;
            node_offset += node_count;
        }

        put_le16(root, 2, summaries.len() as u16);
        put_le16(root, 4, 4);
        put_le16(root, 6, shape.len() as u16);
        write_extent_indexes(root, &summaries)?;
    }
    put_le32(inode, 4, size as u32);
    put_le32(inode, 0x6c, (size >> 32) as u32);

    let sectors = u64::try_from(allocated.len() + nodes.len())
        .map_err(|_| Corrupt::AddressOverflow)?
        .checked_mul(block_size / 512)
        .filter(|sectors| *sectors < (1u64 << 48))
        .ok_or(Corrupt::AddressOverflow)?;
    put_le32(inode, 0x1c, sectors as u32);
    put_le16(inode, 0x74, (sectors >> 32) as u16);
    Ok(())
}

fn extent_tree_shape<E>(
    entries: usize,
    root_capacity: usize,
    node_capacity: usize,
) -> Result<Vec<usize>, Error<E>> {
    if root_capacity == 0 || node_capacity == 0 {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut shape = Vec::new();
    let mut count = entries;
    while count > root_capacity {
        count = count.div_ceil(node_capacity);
        shape.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        shape.push(count);
        if shape.len() > 5 {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
    }
    Ok(shape)
}

fn extent_tree_node_count<E>(shape: &[usize]) -> Result<usize, Error<E>> {
    shape.iter().try_fold(0usize, |total, count| {
        total
            .checked_add(*count)
            .ok_or(Corrupt::AddressOverflow.into())
    })
}

fn merge_extent_node_numbers<E>(
    old_shape: &[usize],
    new_shape: &[usize],
    existing: &[u64],
    allocated: &[u64],
) -> Result<Vec<u64>, Error<E>> {
    let required = extent_tree_node_count(new_shape)?;
    if extent_tree_node_count(old_shape)? != existing.len()
        || required != existing.len() + allocated.len()
        || old_shape.len() > new_shape.len()
        || old_shape
            .iter()
            .enumerate()
            .any(|(level, count)| *count > new_shape[level])
    {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(required)
        .map_err(|_| Error::OutOfMemory)?;
    let mut old_offset = 0usize;
    let mut new_offset = 0usize;
    for (level, &count) in new_shape.iter().enumerate() {
        let retained = old_shape.get(level).copied().unwrap_or(0);
        if retained > count {
            return Err(Unsupported::ExtentMutation.into());
        }
        nodes.extend_from_slice(&existing[old_offset..old_offset + retained]);
        old_offset += retained;
        let added = count - retained;
        nodes.extend_from_slice(&allocated[new_offset..new_offset + added]);
        new_offset += added;
    }
    if old_offset != existing.len() || new_offset != allocated.len() {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    Ok(nodes)
}

fn initialize_extent_node(bytes: &mut [u8], entries: usize, max: usize, depth: u16) {
    bytes.fill(0);
    put_le16(bytes, 0, super::EXTENT_MAGIC);
    put_le16(bytes, 2, entries as u16);
    put_le16(bytes, 4, max as u16);
    put_le16(bytes, 6, depth);
}

fn checksum_extent_node(bytes: &mut [u8], capacity: usize, identity: (u32, u32, u32)) {
    let checksum_offset = 12 + capacity * 12;
    let (seed, number, generation) = identity;
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(number);
    checksum.update_u32_le(generation);
    checksum.update(&bytes[..checksum_offset]);
    put_le32(bytes, checksum_offset, checksum.finalize());
}

fn write_extent_entries<E>(target: &mut [u8], runs: &[ExtentRun]) -> Result<(), Error<E>> {
    for (entry, run) in runs.iter().enumerate() {
        if run.physical >> 48 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        let logical = u32::try_from(run.logical).map_err(|_| Corrupt::AddressOverflow)?;
        let at = 12 + entry * 12;
        put_le32(target, at, logical);
        put_le16(target, at + 4, run.length);
        put_le16(target, at + 6, (run.physical >> 32) as u16);
        put_le32(target, at + 8, run.physical as u32);
    }
    Ok(())
}

fn write_extent_indexes<E>(target: &mut [u8], indexes: &[ExtentIndex]) -> Result<(), Error<E>> {
    for (entry, index) in indexes.iter().enumerate() {
        if index.physical == 0 || index.physical >> 48 != 0 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let at = 12 + entry * 12;
        put_le32(
            target,
            at,
            u32::try_from(index.logical).map_err(|_| Corrupt::AddressOverflow)?,
        );
        put_le32(target, at + 4, index.physical as u32);
        put_le16(target, at + 8, (index.physical >> 32) as u16);
    }
    Ok(())
}

fn update_inode_checksum(seed: u32, number: u32, generation: u32, inode: &mut [u8]) {
    put_le16(inode, 0x7c, 0);
    if inode.len() >= 0x84 {
        put_le16(inode, 0x82, 0);
    }
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(number);
    checksum.update_u32_le(generation);
    checksum.update(inode);
    let checksum = checksum.finalize();
    put_le16(inode, 0x7c, checksum as u16);
    if inode.len() >= 0x84 {
        put_le16(inode, 0x82, (checksum >> 16) as u16);
    }
}

fn initialize_empty_inode(inode: &mut [u8], permissions: u16) {
    inode.fill(0);
    put_le16(inode, 0, 0x8000 | permissions);
    put_le16(inode, 0x1a, 1);
    put_le32(inode, 0x20, super::EXTENTS_FL);
    let root = &mut inode[0x28..0x64];
    put_le16(root, 0, super::EXTENT_MAGIC);
    put_le16(root, 4, 4);
    if inode.len() >= 0x84 {
        put_le16(inode, 0x80, 32);
    }
}

fn initialize_fast_symlink<E>(inode: &mut [u8], target: &[u8]) -> Result<(), Error<E>> {
    if target.is_empty() || target.len() > 60 || inode.len() < 0x84 {
        return Err(Error::InvalidArgument);
    }
    inode.fill(0);
    put_le16(inode, 0, 0xa000 | 0o777);
    put_le32(inode, 4, target.len() as u32);
    put_le16(inode, 0x1a, 1);
    inode[0x28..0x28 + target.len()].copy_from_slice(target);
    put_le16(inode, 0x80, 32);
    Ok(())
}

fn initialize_directory_inode<E>(
    inode: &mut [u8],
    permissions: u16,
    physical: u64,
    block_size: u64,
) -> Result<(), Error<E>> {
    if physical >> 48 != 0 {
        return Err(Unsupported::ExtentMutation.into());
    }
    inode.fill(0);
    put_le16(inode, 0, 0x4000 | permissions);
    put_le32(inode, 4, block_size as u32);
    put_le32(inode, 0x6c, (block_size >> 32) as u32);
    put_le16(inode, 0x1a, 2);
    let sectors = block_size / 512;
    put_le32(inode, 0x1c, sectors as u32);
    put_le16(inode, 0x74, (sectors >> 32) as u16);
    put_le32(inode, 0x20, super::EXTENTS_FL);
    let root = &mut inode[0x28..0x64];
    put_le16(root, 0, super::EXTENT_MAGIC);
    put_le16(root, 2, 1);
    put_le16(root, 4, 4);
    put_le32(root, 12, 0);
    put_le16(root, 16, 1);
    put_le16(root, 18, (physical >> 32) as u16);
    put_le32(root, 20, physical as u32);
    if inode.len() >= 0x84 {
        put_le16(inode, 0x80, 32);
    }
    Ok(())
}

fn initialize_directory_block<E>(
    checksum_seed: u32,
    inode_number: u32,
    generation: u32,
    parent_number: u32,
    block: &mut [u8],
) -> Result<(), Error<E>> {
    let tail = block
        .len()
        .checked_sub(12)
        .filter(|tail| *tail >= 24 && *tail <= usize::from(u16::MAX))
        .ok_or(Corrupt::InvalidDirectory)?;
    block.fill(0);
    put_le32(block, 0, inode_number);
    put_le16(block, 4, 12);
    block[6] = 1;
    block[7] = 2;
    block[8] = b'.';
    put_le32(block, 12, parent_number);
    put_le16(block, 16, (tail - 12) as u16);
    block[18] = 2;
    block[19] = 2;
    block[20..22].copy_from_slice(b"..");
    put_le16(block, tail + 4, 12);
    block[tail + 7] = 0xde;
    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(inode_number);
    checksum.update_u32_le(generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn initialize_empty_directory_leaf<E>(
    checksum_seed: u32,
    inode_number: u32,
    generation: u32,
    block: &mut [u8],
) -> Result<(), Error<E>> {
    let tail = block
        .len()
        .checked_sub(12)
        .filter(|tail| *tail >= 8 && *tail <= usize::from(u16::MAX))
        .ok_or(Corrupt::InvalidDirectory)?;
    block.fill(0);
    put_le16(block, 4, tail as u16);
    put_le16(block, tail + 4, 12);
    block[tail + 7] = 0xde;
    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(inode_number);
    checksum.update_u32_le(generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn directory_parent_entry<E>(block: &[u8], inode_number: u32) -> Result<u32, Error<E>> {
    if block.len() < 24
        || le32(block, 0) != inode_number
        || le16(block, 4) < 12
        || block[6] != 1
        || block[7] != 2
        || block[8] != b'.'
    {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let parent = usize::from(le16(block, 4));
    if parent + 10 > block.len()
        || le32(block, parent) == 0
        || le16(block, parent + 4) < 12
        || block[parent + 6] != 2
        || block[parent + 7] != 2
        || &block[parent + 8..parent + 10] != b".."
    {
        return Err(Corrupt::InvalidDirectory.into());
    }
    Ok(le32(block, parent))
}

fn replace_directory_parent<E>(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    old_parent: u32,
    new_parent: u32,
) -> Result<(), Error<E>> {
    if directory_parent_entry(block, directory.number)? != old_parent || new_parent == 0 {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let parent = usize::from(le16(block, 4));
    put_le32(block, parent, new_parent);
    let tail = block
        .len()
        .checked_sub(12)
        .ok_or(Corrupt::InvalidDirectory)?;
    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(directory.number);
    checksum.update_u32_le(directory.generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn insert_directory_entry<E>(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    inode_number: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), Error<E>> {
    if !matches!(file_type, 1 | 2 | 7) {
        return Err(Error::InvalidArgument);
    }
    let tail = block
        .len()
        .checked_sub(12)
        .ok_or(Corrupt::InvalidDirectory)?;
    let needed = (8 + name.len() + 3) & !3;
    let mut cursor = 0usize;
    let mut insertion = None;
    while cursor < tail {
        if tail - cursor < 8 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let entry_inode = le32(block, cursor);
        let record_len = usize::from(le16(block, cursor + 4));
        let name_len = usize::from(block[cursor + 6]);
        if record_len < 8
            || !record_len.is_multiple_of(4)
            || cursor + record_len > tail
            || name_len > record_len - 8
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if entry_inode != 0 && &block[cursor + 8..cursor + 8 + name_len] == name {
            return Err(Error::AlreadyExists);
        }
        if insertion.is_none() {
            if entry_inode == 0 && record_len >= needed {
                insertion = Some((cursor, record_len, None));
            } else if entry_inode != 0 {
                let used = (8 + name_len + 3) & !3;
                if record_len - used >= needed {
                    insertion = Some((cursor + used, record_len - used, Some((cursor, used))));
                }
            }
        }
        cursor += record_len;
    }
    if cursor != tail {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let (at, record_len, split_previous) = insertion.ok_or(Unsupported::ExtentMutation)?;
    if let Some((previous, previous_len)) = split_previous {
        put_le16(block, previous + 4, previous_len as u16);
    }
    block[at..at + record_len].fill(0);
    put_le32(block, at, inode_number);
    put_le16(block, at + 4, record_len as u16);
    block[at + 6] = name.len() as u8;
    block[at + 7] = file_type;
    block[at + 8..at + 8 + name.len()].copy_from_slice(name);

    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(directory.number);
    checksum.update_u32_le(directory.generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn remove_directory_entry<E>(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    inode_number: u32,
    name: &[u8],
) -> Result<(), Error<E>> {
    let tail = block
        .len()
        .checked_sub(12)
        .ok_or(Corrupt::InvalidDirectory)?;
    let mut cursor = 0usize;
    let mut previous = None;
    let mut removed = false;
    while cursor < tail {
        if tail - cursor < 8 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let entry_inode = le32(block, cursor);
        let record_len = usize::from(le16(block, cursor + 4));
        let name_len = usize::from(block[cursor + 6]);
        if record_len < 8
            || !record_len.is_multiple_of(4)
            || cursor + record_len > tail
            || name_len > record_len - 8
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if entry_inode != 0 && &block[cursor + 8..cursor + 8 + name_len] == name {
            if entry_inode != inode_number {
                return Err(Corrupt::InvalidDirectory.into());
            }
            if let Some(previous) = previous {
                let previous_len = usize::from(le16(block, previous + 4));
                let merged = previous_len
                    .checked_add(record_len)
                    .filter(|length| previous + *length <= tail)
                    .ok_or(Corrupt::InvalidDirectory)?;
                block[cursor..cursor + record_len].fill(0);
                put_le16(block, previous + 4, merged as u16);
            } else {
                put_le32(block, cursor, 0);
                block[cursor + 6..cursor + record_len].fill(0);
            }
            removed = true;
            break;
        }
        previous = Some(cursor);
        cursor += record_len;
    }
    if !removed {
        return Err(Error::NotFound);
    }

    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(directory.number);
    checksum.update_u32_le(directory.generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn find_directory_entry<E>(block: &[u8], name: &[u8]) -> Result<Option<u32>, Error<E>> {
    let tail = block
        .len()
        .checked_sub(12)
        .ok_or(Corrupt::InvalidDirectory)?;
    let mut cursor = 0usize;
    while cursor < tail {
        if tail - cursor < 8 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let inode = le32(block, cursor);
        let record_len = usize::from(le16(block, cursor + 4));
        let name_len = usize::from(block[cursor + 6]);
        if record_len < 8
            || !record_len.is_multiple_of(4)
            || cursor + record_len > tail
            || name_len > record_len - 8
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if inode != 0 && &block[cursor + 8..cursor + 8 + name_len] == name {
            return Ok(Some(inode));
        }
        cursor += record_len;
    }
    if cursor != tail {
        return Err(Corrupt::InvalidDirectory.into());
    }
    Ok(None)
}

fn update_directory_index_checksum<E>(
    seed: u32,
    directory: &Inode,
    kind: crate::DirectoryBlockKind,
    block: &mut [u8],
) -> Result<(), Error<E>> {
    let tail = block
        .len()
        .checked_sub(8)
        .ok_or(Corrupt::InvalidDirectory)?;
    let limit_offset = match kind {
        crate::DirectoryBlockKind::Root => 0x20,
        crate::DirectoryBlockKind::Internal => 0x08,
        crate::DirectoryBlockKind::Leaf => return Err(Corrupt::InvalidDirectory.into()),
    };
    if limit_offset + 4 > tail {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let entries = usize::from(le16(block, limit_offset + 2));
    let hashed_bytes = entries
        .checked_mul(8)
        .and_then(|bytes| limit_offset.checked_add(bytes))
        .filter(|end| *end <= tail)
        .ok_or(Corrupt::InvalidDirectory)?;
    let mut checksum = Checksum::with_seed(seed);
    checksum.update_u32_le(directory.number);
    checksum.update_u32_le(directory.generation);
    checksum.update(&block[..hashed_bytes]);
    checksum.update_u32_le(le32(block, tail));
    checksum.update_u32_le(0);
    put_le32(block, tail + 4, checksum.finalize());
    Ok(())
}

fn replace_directory_entry<E>(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    old_inode: u32,
    new_inode: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), Error<E>> {
    if old_inode == 0 || new_inode == 0 || !matches!(file_type, 1 | 2 | 7) {
        return Err(Error::InvalidArgument);
    }
    let tail = block
        .len()
        .checked_sub(12)
        .ok_or(Corrupt::InvalidDirectory)?;
    let mut cursor = 0usize;
    let mut replaced = false;
    while cursor < tail {
        if tail - cursor < 8 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let inode = le32(block, cursor);
        let record_len = usize::from(le16(block, cursor + 4));
        let name_len = usize::from(block[cursor + 6]);
        if record_len < 8
            || !record_len.is_multiple_of(4)
            || cursor + record_len > tail
            || name_len > record_len - 8
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if inode != 0 && &block[cursor + 8..cursor + 8 + name_len] == name {
            if inode != old_inode {
                return Err(Corrupt::InvalidDirectory.into());
            }
            put_le32(block, cursor, new_inode);
            block[cursor + 7] = file_type;
            replaced = true;
            break;
        }
        cursor += record_len;
    }
    if !replaced {
        return Err(Error::NotFound);
    }
    let mut checksum = Checksum::with_seed(checksum_seed);
    checksum.update_u32_le(directory.number);
    checksum.update_u32_le(directory.generation);
    checksum.update(&block[..tail]);
    put_le32(block, tail + 8, checksum.finalize());
    Ok(())
}

fn is_power_of(mut value: u32, base: u32) -> bool {
    while value > 1 && value.is_multiple_of(base) {
        value /= base;
    }
    value == 1
}

fn set_bitmap_range<E>(bitmap: &mut [u8], start: u64, len: u64) -> Result<(), Error<E>> {
    let end = start.checked_add(len).ok_or(Corrupt::AddressOverflow)?;
    let bits = u64::try_from(bitmap.len())
        .map_err(|_| Corrupt::AddressOverflow)?
        .checked_mul(8)
        .ok_or(Corrupt::AddressOverflow)?;
    if end > bits {
        return Err(Corrupt::InvalidBlockBitmap.into());
    }
    for bit in start..end {
        let bit = usize::try_from(bit).map_err(|_| Corrupt::AddressOverflow)?;
        bitmap[bit / 8] |= 1 << (bit % 8);
    }
    Ok(())
}

fn put_le16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ModelStorage, PathExt4};
    use alloc::vec;

    #[test]
    fn extent_writer_splits_full_leaf_and_checksums_each_child() {
        const BLOCK_SIZE: u64 = 4096;
        const SEED: u32 = 0x1234_5678;
        const INODE_NUMBER: u32 = 37;
        const GENERATION: u32 = 9;

        let mut inode = vec![0; 256];
        put_le16(&mut inode, 0x28, super::super::EXTENT_MAGIC);
        put_le16(&mut inode, 0x2c, 4);
        let physical: Vec<u64> = (0..341).map(|index| 1000 + index * 2).collect();
        let mut leaves = vec![
            DirtyBlock {
                number: 800,
                bytes: vec![0; BLOCK_SIZE as usize],
            },
            DirtyBlock {
                number: 801,
                bytes: vec![0; BLOCK_SIZE as usize],
            },
        ];

        let mut editor = InodeEditor::new(&mut inode, SEED, INODE_NUMBER, GENERATION).unwrap();
        editor
            .set_extent_mapping::<()>(
                &physical,
                physical.len() as u64 * BLOCK_SIZE,
                BLOCK_SIZE,
                &mut leaves,
            )
            .unwrap();
        editor.finish();

        let root = &inode[0x28..0x64];
        assert_eq!(le16(root, 2), 2);
        assert_eq!(le16(root, 6), 1);
        assert_eq!(le32(root, 12), 0);
        assert_eq!(le32(root, 24), 340);
        assert_eq!(le16(&leaves[0].bytes, 2), 340);
        assert_eq!(le16(&leaves[1].bytes, 2), 1);
        assert_eq!(le32(&leaves[1].bytes, 12), 340);
        assert_eq!(le32(&leaves[1].bytes, 20), physical[340] as u32);

        for leaf in &leaves {
            let checksum_offset = 4092;
            let mut checksum = Checksum::with_seed(SEED);
            checksum.update_u32_le(INODE_NUMBER);
            checksum.update_u32_le(GENERATION);
            checksum.update(&leaf.bytes[..checksum_offset]);
            assert_eq!(le32(&leaf.bytes, checksum_offset), checksum.finalize());
        }
        assert_eq!(
            u64::from(le32(&inode, 0x1c)) | (u64::from(le16(&inode, 0x74)) << 32),
            343 * (BLOCK_SIZE / 512)
        );
    }

    #[test]
    fn extent_writer_grows_existing_full_leaf_without_changing_its_identity() {
        const BLOCK_SIZE: u64 = 4096;
        let mut inode = vec![0; 256];
        put_le16(&mut inode, 0x28, super::super::EXTENT_MAGIC);
        put_le16(&mut inode, 0x2c, 4);
        let mut physical: Vec<u64> = (0..340).map(|index| 2000 + index * 2).collect();
        let mut leaves = vec![DirtyBlock {
            number: 900,
            bytes: vec![0; BLOCK_SIZE as usize],
        }];
        let mut editor = InodeEditor::new(&mut inode, 7, 41, 3).unwrap();
        editor
            .set_extent_mapping::<()>(
                &physical,
                physical.len() as u64 * BLOCK_SIZE,
                BLOCK_SIZE,
                &mut leaves,
            )
            .unwrap();
        editor.finish();
        let original_number = leaves[0].number;

        physical.push(4000);
        leaves.push(DirtyBlock {
            number: 901,
            bytes: vec![0; BLOCK_SIZE as usize],
        });
        let mut editor = InodeEditor::new(&mut inode, 7, 41, 3).unwrap();
        editor
            .set_extent_mapping::<()>(
                &physical,
                physical.len() as u64 * BLOCK_SIZE,
                BLOCK_SIZE,
                &mut leaves,
            )
            .unwrap();
        editor.finish();

        let root = &inode[0x28..0x64];
        assert_eq!(le16(root, 2), 2);
        assert_eq!(le32(root, 16), original_number as u32);
        assert_eq!(le32(root, 28), 901);
        assert_eq!(le32(root, 24), 340);
        assert_eq!(le16(&leaves[0].bytes, 2), 340);
        assert_eq!(le16(&leaves[1].bytes, 2), 1);
    }

    #[test]
    fn extent_writer_builds_depth_two_with_the_same_bottom_up_loop() {
        const BLOCK_SIZE: u64 = 4096;
        let mut inode = vec![0; 256];
        put_le16(&mut inode, 0x28, super::super::EXTENT_MAGIC);
        put_le16(&mut inode, 0x2c, 4);
        let physical: Vec<u64> = (0..1361).map(|index| 5000 + index * 2).collect();
        let mut nodes: Vec<DirtyBlock> = (0..6)
            .map(|index| DirtyBlock {
                number: 1000 + index,
                bytes: vec![0; BLOCK_SIZE as usize],
            })
            .collect();

        let mut editor = InodeEditor::new(&mut inode, 11, 43, 5).unwrap();
        editor
            .set_extent_mapping::<()>(
                &physical,
                physical.len() as u64 * BLOCK_SIZE,
                BLOCK_SIZE,
                &mut nodes,
            )
            .unwrap();
        editor.finish();

        let root = &inode[0x28..0x64];
        assert_eq!(le16(root, 2), 1);
        assert_eq!(le16(root, 6), 2);
        assert_eq!(le32(root, 16), 1005);
        assert_eq!(le16(&nodes[0].bytes, 6), 0);
        assert_eq!(le16(&nodes[0].bytes, 2), 340);
        assert_eq!(le16(&nodes[4].bytes, 2), 1);
        assert_eq!(le16(&nodes[5].bytes, 6), 1);
        assert_eq!(le16(&nodes[5].bytes, 2), 5);
        for index in 0..5 {
            let at = 12 + index * 12;
            assert_eq!(le32(&nodes[5].bytes, at), (index * 340) as u32);
            assert_eq!(le32(&nodes[5].bytes, at + 4), 1000 + index as u32);
        }
    }

    #[test]
    fn growing_a_level_inserts_new_nodes_at_their_level_boundary() {
        assert_eq!(
            merge_extent_node_numbers::<()>(&[4], &[5, 1], &[10, 11, 12, 13], &[20, 21]).unwrap(),
            vec![10, 11, 12, 13, 20, 21]
        );
        assert_eq!(
            merge_extent_node_numbers::<()>(&[5, 1], &[6, 1], &[10, 11, 12, 13, 14, 30], &[20],)
                .unwrap(),
            vec![10, 11, 12, 13, 14, 20, 30]
        );
    }

    #[test]
    fn ownership_walk_flattens_a_depth_two_tree_by_level() {
        const BLOCK: usize = 1024;
        let mut image = crate::tests::image();
        let inode = 5 * BLOCK + 256;
        image[inode + 0x28..inode + 0x64].fill(0);
        put_le16(&mut image, inode + 0x28, super::super::EXTENT_MAGIC);
        put_le16(&mut image, inode + 0x2a, 1);
        put_le16(&mut image, inode + 0x2c, 4);
        put_le16(&mut image, inode + 0x2e, 2);
        put_le32(&mut image, inode + 0x38, 20);

        let index = 20 * BLOCK;
        put_le16(&mut image, index, super::super::EXTENT_MAGIC);
        put_le16(&mut image, index + 2, 1);
        put_le16(&mut image, index + 4, 84);
        put_le16(&mut image, index + 6, 1);
        put_le32(&mut image, index + 16, 21);

        let leaf = 21 * BLOCK;
        put_le16(&mut image, leaf, super::super::EXTENT_MAGIC);
        put_le16(&mut image, leaf + 2, 1);
        put_le16(&mut image, leaf + 4, 84);
        put_le16(&mut image, leaf + 6, 0);
        put_le16(&mut image, leaf + 16, 1);
        put_le32(&mut image, leaf + 20, 11);

        let mut storage = ModelStorage::new(image);
        let mut filesystem = Ext4::mount(&mut storage).unwrap();
        let inode = filesystem.stat(&mut storage, "/hello").unwrap();
        let mut transaction = filesystem.begin_transaction();
        let ownership = transaction
            .io(&mut storage)
            .read_extent_ownership(&inode)
            .unwrap();
        assert_eq!(ownership.data, vec![(11, 1)]);
        assert_eq!(ownership.tree, vec![21, 20]);
        assert_eq!(ownership.logical_blocks, 1);
    }
}
