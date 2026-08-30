//! Transaction-private dirty blocks and fallible memory reservations.
//!
//! Dirty blocks remain isolated until [`Transaction::commit`] serializes them
//! through the internal JBD2 journal.

use crate::checksum::Checksum;
use crate::extent_tree::{Extent, ExtentIdentity, ExtentState, ExtentTree};
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

    fn set_extent_tree(
        &mut self,
        tree: &ExtentTree,
        size: u64,
        block_size: u64,
        metadata_checksums: bool,
        extra_owned_blocks: u64,
    ) -> Result<Vec<DirtyBlock>, Error> {
        let root = self
            .raw
            .get_mut(0x28..0x64)
            .ok_or(Corrupt::InvalidInode(self.number))?;
        tree.write_root(root)?;
        put_le32(self.raw, 4, size as u32);
        put_le32(self.raw, 0x6c, (size >> 32) as u32);
        let data_blocks = tree
            .data_extents()?
            .into_iter()
            .try_fold(0u64, |total, extent| {
                total
                    .checked_add(u64::from(extent.length))
                    .ok_or(Corrupt::AddressOverflow)
            })?;
        let tree_blocks = u64::try_from(tree.external_blocks_by_level()?.len())
            .map_err(|_| Corrupt::AddressOverflow)?;
        let sectors = data_blocks
            .checked_add(tree_blocks)
            .and_then(|blocks| blocks.checked_add(extra_owned_blocks))
            .and_then(|blocks| blocks.checked_mul(block_size / 512))
            .filter(|sectors| *sectors < (1_u64 << 48))
            .ok_or(Corrupt::AddressOverflow)?;
        put_le32(self.raw, 0x1c, sectors as u32);
        put_le16(self.raw, 0x74, (sectors >> 32) as u16);
        let serialized = tree.serialize_dirty(
            usize::try_from(block_size).map_err(|_| Corrupt::AddressOverflow)?,
            ExtentIdentity {
                checksum_seed: self.checksum_seed,
                inode: self.number,
                generation: self.generation,
                metadata_checksums,
            },
        )?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(serialized.len())
            .map_err(|_| Error::OutOfMemory)?;
        for node in serialized {
            nodes.push(DirtyBlock {
                number: node.number,
                bytes: node.bytes,
            });
        }
        Ok(nodes)
    }

    fn initialize_regular(&mut self, permissions: u16) {
        initialize_empty_inode(self.raw, permissions);
    }

    fn initialize_fast_symlink(&mut self, target: &[u8]) -> Result<(), Error> {
        initialize_fast_symlink(self.raw, target)
    }

    fn initialize_directory(
        &mut self,
        permissions: u16,
        physical: u64,
        block_size: u64,
    ) -> Result<(), Error> {
        initialize_directory_inode(self.raw, permissions, physical, block_size)
    }

    fn apply_metadata(&mut self, update: InodeMetadataUpdate) -> Result<(), Error> {
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

    fn load(&mut self, transaction: &mut TransactionIo<'_, '_>, number: u64) -> Result<(), Error> {
        let Err(index) = self.index(number) else {
            return Ok(());
        };
        let bytes = transaction.read_owned_block(number)?;
        self.blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.blocks.insert(index, DirtyBlock { number, bytes });
        Ok(())
    }

    fn adopt(&mut self, number: u64, bytes: Vec<u8>) -> Result<(), Error> {
        let index = match self.index(number) {
            Ok(_) => return Err(Corrupt::InvalidDirectory.into()),
            Err(index) => index,
        };
        self.blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.blocks.insert(index, DirtyBlock { number, bytes });
        Ok(())
    }

    fn adopt_block(&mut self, block: DirtyBlock) -> Result<(), Error> {
        self.adopt(block.number, block.bytes)
    }

    fn adopt_blocks(&mut self, blocks: impl IntoIterator<Item = DirtyBlock>) -> Result<(), Error> {
        for block in blocks {
            self.adopt_block(block)?;
        }
        Ok(())
    }

    fn adopt_group_edits(&mut self, groups: Vec<GroupEdit>) -> Result<(), Error> {
        for group in groups {
            if let Some(bitmap) = group.block_bitmap {
                self.adopt_block(bitmap)?;
            }
            if let Some(bitmap) = group.inode_bitmap {
                self.adopt_block(bitmap)?;
            }
        }
        Ok(())
    }

    fn get_mut(&mut self, number: u64) -> Result<&mut [u8], Corrupt> {
        let index = self.index(number).map_err(|_| Corrupt::InvalidDirectory)?;
        Ok(&mut self.blocks[index].bytes)
    }

    fn edit_inode(
        &mut self,
        transaction: &mut TransactionIo<'_, '_>,
        inode: &Inode,
        edit: &mut dyn FnMut(&mut InodeEditor<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
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

    fn set_inode_links(
        &mut self,
        transaction: &mut TransactionIo<'_, '_>,
        inode: &Inode,
        links: u16,
    ) -> Result<(), Error> {
        self.edit_inode(transaction, inode, &mut |editor| {
            editor.set_links(links);
            Ok(())
        })
    }

    fn stage(self, transaction: &mut TransactionIo<'_, '_>) -> Result<(), Error> {
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
    fn load(transaction: &mut TransactionIo<'_, '_>, inode: &Inode) -> Result<Self, Error> {
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

    fn insert(&mut self, number: u32, name: &[u8], kind: u8) -> Result<(), Error> {
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

    fn remove(&mut self, number: u32, name: &[u8]) -> Result<(), Error> {
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

    fn replace(
        &mut self,
        old_number: u32,
        new_number: u32,
        name: &[u8],
        kind: u8,
    ) -> Result<(), Error> {
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

    fn set_parent(&mut self, old_parent: u32, new_parent: u32) -> Result<(), Error> {
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

    fn validate_empty(&self, parent_number: u32) -> Result<(), Error> {
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

    fn find(&self, name: &[u8]) -> Result<Option<(usize, u32)>, Error> {
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

    fn insert(&mut self, number: u32, name: &[u8], kind: u8) -> Result<(), Error> {
        insert_directory_entry(
            self.checksum_seed,
            self.inode,
            self.bytes,
            number,
            name,
            kind,
        )
    }

    fn remove(&mut self, number: u32, name: &[u8]) -> Result<(), Error> {
        remove_directory_entry(self.checksum_seed, self.inode, self.bytes, number, name)
    }

    fn replace(
        &mut self,
        old_number: u32,
        new_number: u32,
        name: &[u8],
        kind: u8,
    ) -> Result<(), Error> {
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

    fn set_parent(&mut self, old_parent: u32, new_parent: u32) -> Result<(), Error> {
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
    inode_bitmap: Option<DirtyBlock>,
}

struct GroupEditor {
    edit: GroupEdit,
    start: u64,
    blocks: u64,
    first_inode: u64,
    inodes: u64,
    block_bitmap_number: u64,
    inode_bitmap_number: u64,
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
}

struct DirectoryGrowth {
    inode: Inode,
    tree: ExtentTree,
    size: u64,
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

#[derive(Clone, Copy)]
enum CreateKind<'a> {
    Regular,
    Symlink(&'a [u8]),
    Directory,
}

impl CreateKind<'_> {
    fn file_type(self) -> u8 {
        match self {
            Self::Regular => 1,
            Self::Symlink(_) => 7,
            Self::Directory => 2,
        }
    }

    fn required_blocks(self) -> usize {
        if matches!(self, Self::Directory) {
            8
        } else {
            5
        }
    }
}

enum FileGrowth<'a> {
    Write { offset: u64, data: &'a [u8] },
    ZeroFill { new_size: u64 },
}

impl FileGrowth<'_> {
    fn range(&self, old_size: u64) -> Result<(u64, u64), Error> {
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

    fn apply(
        &self,
        block: &mut [u8],
        block_start: u64,
        write_start: u64,
        write_end: u64,
    ) -> Result<(), Error> {
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
    fn new(inode: Inode) -> Result<Self, Error> {
        if inode.mode & 0xf000 != 0x8000 || inode.flags & super::EXTENTS_FL == 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        Ok(Self { inode })
    }

    fn write_at(
        &self,
        transaction: &mut TransactionIo<'_, '_>,
        offset: u64,
        data: &[u8],
    ) -> Result<FileEditResult, Error> {
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
            match transaction.overwrite_inode(&self.inode, offset, data) {
                Ok(()) => {
                    return Ok(FileEditResult {
                        first_allocated: None,
                    });
                }
                Err(Error::Unsupported(Unsupported::ExtentMutation)) => {}
                Err(error) => return Err(error),
            }
        }
        transaction.extend_file(&self.inode, FileGrowth::Write { offset, data })
    }

    fn resize(&self, transaction: &mut TransactionIo<'_, '_>, new_size: u64) -> Result<(), Error> {
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

struct ReleasedInodeBlocks {
    resources: ResourceRelease,
    retained_xattr_block: Option<DirtyBlock>,
}

struct PreparedInodeRelease {
    resources: ResourceRelease,
    inode_block: DirtyBlock,
    retained_xattr_block: Option<DirtyBlock>,
}

struct ResourceRelease {
    blocks: u64,
    groups: Vec<GroupEdit>,
}

enum ResourceUpdate {
    Allocate(Allocation),
    Release(ResourceRelease),
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

struct TransactionIo<'a, 'f> {
    transaction: &'a mut Transaction<'f>,
    storage: &'a mut dyn Storage,
}

impl<'f> core::ops::Deref for TransactionIo<'_, 'f> {
    type Target = Transaction<'f>;

    fn deref(&self) -> &Self::Target {
        self.transaction
    }
}

impl<'f> core::ops::DerefMut for TransactionIo<'_, 'f> {
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

    fn io<'s>(&'s mut self, storage: &'s mut dyn Storage) -> TransactionIo<'s, 'a> {
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

    #[inline(never)]
    pub fn commit(self, storage: &mut dyn Storage) -> Result<(), Error> {
        self.filesystem.commit_journal(storage, &self.dirty)
    }

    pub fn update_metadata(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        update: InodeMetadataUpdate,
    ) -> Result<(), Error> {
        self.io(storage).update_metadata(inode, update)
    }

    pub fn chmod_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        permissions: u16,
    ) -> Result<(), Error> {
        self.io(storage).chmod_inode(inode, permissions)
    }

    pub fn chown_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error> {
        self.io(storage).chown_inode(inode, uid, gid)
    }

    pub fn set_inode_times(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
    ) -> Result<(), Error> {
        self.io(storage)
            .set_inode_times(inode, accessed, modified, changed)
    }

    pub fn write_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        self.io(storage).write_inode(inode, offset, data)
    }

    pub fn overwrite_inode_range(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        self.io(storage).overwrite_inode_range(inode, offset, data)
    }

    pub fn append_zeroed_inode_block(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<u64, Error> {
        self.io(storage).append_zeroed_inode_block(inode)
    }

    pub fn initialize_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        data: &[u8],
    ) -> Result<(), Error> {
        self.io(storage).initialize_inode(inode, data)
    }

    pub fn append_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        data: &[u8],
    ) -> Result<(), Error> {
        self.io(storage).append_inode(inode, data)
    }

    pub fn create_file(
        &mut self,
        storage: &mut dyn Storage,
        directory: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error> {
        self.io(storage).create_file(directory, name, permissions)
    }

    pub fn create_symlink(
        &mut self,
        storage: &mut dyn Storage,
        directory: &Inode,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, Error> {
        self.io(storage).create_symlink(directory, name, target)
    }

    pub fn create_link(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        parent: &Inode,
        name: &[u8],
    ) -> Result<(), Error> {
        self.io(storage).create_link(inode, parent, name)
    }

    pub fn create_directory(
        &mut self,
        storage: &mut dyn Storage,
        parent: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error> {
        self.io(storage).create_directory(parent, name, permissions)
    }

    pub fn remove_entry(
        &mut self,
        storage: &mut dyn Storage,
        directory: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error> {
        self.io(storage).remove_entry(directory, entry)
    }

    pub fn remove_directory(
        &mut self,
        storage: &mut dyn Storage,
        parent: &Inode,
        entry: &DirectoryEntry,
    ) -> Result<(), Error> {
        self.io(storage).remove_directory(parent, entry)
    }

    pub fn move_entry(
        &mut self,
        storage: &mut dyn Storage,
        old_parent: &Inode,
        source: &DirectoryEntry,
        new_parent: &Inode,
        new_name: &[u8],
        destination: Option<&DirectoryEntry>,
    ) -> Result<(), Error> {
        self.io(storage)
            .move_entry(old_parent, source, new_parent, new_name, destination)
    }

    pub fn resize_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        new_size: u64,
    ) -> Result<(), Error> {
        self.io(storage).resize_inode(inode, new_size)
    }

    pub fn truncate_inode(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
    ) -> Result<u64, Error> {
        self.io(storage).truncate_inode(inode)
    }

    pub fn read_block(
        &mut self,
        storage: &mut dyn Storage,
        number: u64,
        dst: &mut [u8],
    ) -> Result<(), Error> {
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

    pub fn modify_block<F>(
        &mut self,
        storage: &mut dyn Storage,
        number: u64,
        modify: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut [u8]),
    {
        self.io(storage).modify_block(number, modify)
    }
}

impl TransactionIo<'_, '_> {
    fn map_file_block(&mut self, inode: &Inode, logical: u64) -> Result<Option<u64>, Error> {
        self.transaction
            .filesystem
            .map_file_block(self.storage, inode, logical)
    }

    fn read_external_xattr_block(&mut self, inode: &Inode) -> Result<Vec<u8>, Error> {
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
    ) -> Result<(), Error> {
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
        metadata.edit_inode(self, &inode, &mut |editor| editor.apply_metadata(update))?;
        metadata.stage(self)
    }

    /// Change permission and special bits while preserving the inode type.
    pub fn chmod_inode(&mut self, inode: &Inode, permissions: u16) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    pub fn write_inode(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Corrupt::AddressOverflow)?)
            .filter(|end| *end <= inode.size)
            .ok_or(Unsupported::ExtentMutation)?;
        self.overwrite_inode(&inode, offset, data)
    }

    fn overwrite_inode(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<(), Error> {
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
    pub fn append_zeroed_inode_block(&mut self, inode: &Inode) -> Result<u64, Error> {
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
    pub fn initialize_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        if file.inode.size != 0 || file.inode.blocks_512 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        file.write_at(self, 0, data).map(|_| ())
    }

    /// Append bytes using the general file editor.
    pub fn append_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        file.write_at(self, file.inode.size, data).map(|_| ())
    }

    fn extend_file(
        &mut self,
        inode: &Inode,
        growth: FileGrowth<'_>,
    ) -> Result<FileEditResult, Error> {
        self.validate_mutation_profile()?;
        let (offset, requested_end) = growth.range(inode.size)?;
        let new_size = match growth {
            FileGrowth::Write { .. } => inode.size.max(requested_end),
            FileGrowth::ZeroFill { .. } => requested_end,
        };
        if offset > inode.size
            || matches!(growth, FileGrowth::ZeroFill { .. }) && new_size <= inode.size
        {
            return Err(Unsupported::ExtentMutation.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let old_blocks = inode.size.div_ceil(block_size);
        let new_blocks = new_size.div_ceil(block_size);
        if new_blocks > (1_u64 << 32) {
            return Err(Unsupported::ExtentMutation.into());
        }
        let mut tree = self.read_extent_tree(inode)?;
        let existing = tree.data_extents()?;
        if existing
            .last()
            .is_some_and(|extent| extent.logical_end() > old_blocks)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let data_blocks = existing.iter().try_fold(0u64, |total, extent| {
            total
                .checked_add(u64::from(extent.length))
                .ok_or(Corrupt::AddressOverflow)
        })?;
        let tree_blocks = u64::try_from(tree.external_blocks_by_level()?.len())
            .map_err(|_| Corrupt::AddressOverflow)?;
        let expected_sectors = data_blocks
            .checked_add(tree_blocks)
            .and_then(|blocks| blocks.checked_add(u64::from(inode.external_xattr_block != 0)))
            .and_then(|blocks| blocks.checked_mul(block_size / 512))
            .ok_or(Corrupt::AddressOverflow)?;
        if inode.blocks_512 != expected_sectors {
            return Err(Unsupported::ExtentMutation.into());
        }

        let (first_touched, last_touched) = match growth {
            FileGrowth::Write { .. } => (offset / block_size, requested_end.div_ceil(block_size)),
            FileGrowth::ZeroFill { .. } => (new_blocks, new_blocks),
        };
        tree.set_state(first_touched, last_touched, ExtentState::Written)?;
        let mut missing = 0usize;
        for logical in first_touched..last_touched {
            match tree.lookup(u32::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?) {
                None => missing = missing.checked_add(1).ok_or(Corrupt::AddressOverflow)?,
                Some((_, ExtentState::Written)) => {}
                Some((_, ExtentState::Unwritten)) => unreachable!(),
            }
        }

        let mut allocation = self.allocate_blocks(missing)?;
        let mut next_data = allocation.blocks.iter().copied();
        for logical in first_touched..last_touched {
            let logical = u32::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?;
            if tree.lookup(logical).is_none() {
                tree.insert(Extent::new(
                    logical,
                    next_data.next().ok_or(Corrupt::InvalidBlockBitmap)?,
                    1,
                    ExtentState::Written,
                )?)?;
            }
        }
        if next_data.next().is_some() {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let metadata_blocks = tree.unassigned_blocks();
        self.extend_allocation(&mut allocation, metadata_blocks)?;
        tree.assign_blocks(&allocation.blocks[missing..])?;
        let first_allocated = allocation.blocks.first().copied().filter(|_| missing != 0);

        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(
                usize::try_from(last_touched - first_touched)
                    .map_err(|_| Corrupt::AddressOverflow)?,
            )
            .map_err(|_| Error::OutOfMemory)?;
        for logical in first_touched..last_touched {
            let physical = tree
                .lookup(u32::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?)
                .filter(|(_, state)| *state == ExtentState::Written)
                .map(|(physical, _)| physical)
                .ok_or(Corrupt::InvalidExtentTree)?;
            let originally_unwritten = existing.iter().any(|extent| {
                extent.state == ExtentState::Unwritten
                    && u64::from(extent.logical) <= logical
                    && logical < extent.logical_end()
            });
            let mut block =
                if allocation.blocks[..missing].contains(&physical) || originally_unwritten {
                    self.zero_block()?
                } else {
                    self.read_owned_block(physical)?
                };
            let block_start = logical
                .checked_mul(block_size)
                .ok_or(Corrupt::AddressOverflow)?;
            growth.apply(
                &mut block,
                block_start,
                offset.max(block_start),
                requested_end.min(
                    block_start
                        .checked_add(block_size)
                        .ok_or(Corrupt::AddressOverflow)?,
                ),
            )?;
            payloads.push(DirtyBlock {
                number: physical,
                bytes: block,
            });
        }

        let mut metadata = MetadataMutation::new();
        self.apply_resources(&mut metadata, ResourceUpdate::Allocate(allocation))?;
        for payload in payloads {
            metadata.adopt_block(payload)?;
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
        let extent_nodes = editor.set_extent_tree(
            &tree,
            new_size,
            block_size,
            self.transaction
                .filesystem
                .superblock
                .has_metadata_checksums(),
            u64::from(inode.external_xattr_block != 0),
        )?;
        editor.finish();
        metadata.adopt_blocks(extent_nodes)?;
        metadata.stage(self)?;
        Ok(FileEditResult { first_allocated })
    }

    /// Create an empty regular file in a checked mutable directory.
    pub fn create_file(
        &mut self,
        directory: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error> {
        self.create_inode_entry(directory, name, permissions, CreateKind::Regular)
    }

    /// Create an inline (fast) symbolic link.
    pub fn create_symlink(
        &mut self,
        directory: &Inode,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, Error> {
        self.create_inode_entry(directory, name, 0o777, CreateKind::Symlink(target))
    }

    #[inline(never)]
    fn create_inode_entry(
        &mut self,
        parent: &Inode,
        name: &[u8],
        permissions: u16,
        kind: CreateKind<'_>,
    ) -> Result<u32, Error> {
        self.validate_mutation_profile()?;
        if !self.dirty.is_empty() || self.available.len() < kind.required_blocks() {
            return Err(Error::ReservationExhausted);
        }
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
            || permissions & !0o777 != 0
            || matches!(kind, CreateKind::Symlink(target) if target.is_empty() || target.len() > 60 || target.contains(&0))
        {
            return Err(Error::InvalidArgument);
        }

        let parent = self.transaction.filesystem.refresh(self.storage, parent)?;
        if matches!(kind, CreateKind::Directory)
            && (!parent.is_directory() || parent.links == u16::MAX)
        {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let mut parent_tree = DirectoryTree::load(self, &parent)?;

        let mut allocation = self.allocate_inode()?;
        let inode_number = allocation.number;
        let directory_block_number = if matches!(kind, CreateKind::Directory) {
            self.extend_allocation(&mut allocation.resources, 1)?;
            let group = allocation
                .resources
                .groups
                .binary_search_by_key(&allocation.group_number, |group| group.number)
                .map_err(|_| Corrupt::InvalidGroup(allocation.group_number))?;
            increment_descriptor_used_directories(
                &mut allocation.resources.groups[group].descriptor,
                u64::from(self.transaction.filesystem.superblock.inodes_per_group),
            )?;
            update_group_descriptor_checksum(
                self.transaction.filesystem.superblock.checksum_seed,
                allocation.group_number,
                &mut allocation.resources.groups[group].descriptor,
            );
            Some(allocation.resources.blocks[0])
        } else {
            None
        };
        let (inode_block_number, inode_offset) =
            self.inode_table_location(allocation.inode_table, allocation.index)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);

        let growth = self.insert_into_directory(
            &mut parent_tree,
            &mut allocation.resources,
            inode_number,
            name,
            kind.file_type(),
        )?;
        let mut metadata = MetadataMutation::new();
        metadata.adopt(
            inode_block_number,
            self.read_owned_block(inode_block_number)?,
        )?;
        let raw_inode =
            &mut metadata.get_mut(inode_block_number)?[inode_offset..inode_offset + inode_size];
        let mut editor = InodeEditor::new(
            raw_inode,
            self.transaction.filesystem.superblock.checksum_seed,
            inode_number,
            0,
        )?;
        match kind {
            CreateKind::Regular => editor.initialize_regular(permissions),
            CreateKind::Symlink(target) => editor.initialize_fast_symlink(target)?,
            CreateKind::Directory => editor.initialize_directory(
                permissions,
                directory_block_number.unwrap(),
                block_size,
            )?,
        }
        editor.finish();

        if matches!(kind, CreateKind::Directory) {
            metadata.set_inode_links(self, &parent, parent.links + 1)?;
        }
        self.apply_directory_insertion(&mut metadata, allocation.resources, growth)?;
        if let Some(number) = directory_block_number {
            let mut block = self.zero_block()?;
            initialize_directory_block(
                self.transaction.filesystem.superblock.checksum_seed,
                inode_number,
                0,
                parent.number,
                &mut block,
            )?;
            metadata.adopt(number, block)?;
        }
        metadata.adopt_blocks(parent_tree.into_dirty_blocks())?;
        metadata.stage(self)?;
        Ok(inode_number)
    }

    /// Create another directory entry for an existing non-directory inode.
    pub fn create_link(&mut self, inode: &Inode, parent: &Inode, name: &[u8]) -> Result<(), Error> {
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
        let mut metadata = MetadataMutation::new();
        metadata.set_inode_links(self, &inode, inode.links + 1)?;
        self.apply_directory_insertion(&mut metadata, resources, growth)?;
        metadata.adopt_blocks(directory_tree.into_dirty_blocks())?;
        metadata.stage(self)
    }

    /// Create a checked directory below a mutable directory.
    pub fn create_directory(
        &mut self,
        parent: &Inode,
        name: &[u8],
        permissions: u16,
    ) -> Result<u32, Error> {
        self.create_inode_entry(parent, name, permissions, CreateKind::Directory)
    }

    /// Remove a link-count-one regular file with checked initialized extents.
    pub fn remove_entry(&mut self, directory: &Inode, entry: &DirectoryEntry) -> Result<(), Error> {
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
            metadata.set_inode_links(self, &inode, inode.links - 1)?;
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
        let cross_parent = old_parent.number != new_parent.number;
        let is_directory = file_type == 2;
        let replacing = destination.is_some();
        if is_directory && cross_parent {
            self.ensure_directory_move_acyclic(source_inode.number, &new_parent)?;
        }
        if is_directory && (source_inode.links < 2 || old_parent.links == 0) {
            return Err(Unsupported::MutationProfile.into());
        }
        if is_directory && cross_parent && !replacing && new_parent.links == u16::MAX {
            return Err(Unsupported::MutationProfile.into());
        }

        let mut old_tree = DirectoryTree::load(self, &old_parent)?;
        let mut new_tree = if cross_parent {
            Some(DirectoryTree::load(self, &new_parent)?)
        } else {
            None
        };
        let moved_directory = if is_directory && cross_parent {
            let mut tree = DirectoryTree::load(self, &source_inode)?;
            tree.set_parent(old_parent.number, new_parent.number)?;
            Some(tree)
        } else {
            None
        };
        let mut metadata = MetadataMutation::new();

        if let Some(destination) = destination {
            let release = if is_directory {
                self.prepare_empty_directory_release(&destination, new_parent.number)?
            } else {
                self.prepare_inode_release(&destination, ReleaseKind::Regular)?
            };
            self.apply_inode_release(&mut metadata, release)?;
            let target = match &mut new_tree {
                Some(tree) => tree,
                None => &mut old_tree,
            };
            target.replace(destination.number, source_inode.number, new_name, file_type)?;
            old_tree.remove(source_inode.number, &source.name)?;
        } else {
            old_tree.remove(source_inode.number, &source.name)?;
            let mut resources = Allocation {
                blocks: Vec::new(),
                groups: Vec::new(),
            };
            let target = match &mut new_tree {
                Some(tree) => tree,
                None => &mut old_tree,
            };
            let growth = self.insert_into_directory(
                target,
                &mut resources,
                source_inode.number,
                new_name,
                file_type,
            )?;
            self.apply_directory_insertion(&mut metadata, resources, growth)?;
        }

        metadata.adopt_blocks(old_tree.into_dirty_blocks())?;
        if let Some(tree) = new_tree {
            metadata.adopt_blocks(tree.into_dirty_blocks())?;
        }
        if let Some(tree) = moved_directory {
            metadata.adopt_blocks(tree.into_dirty_blocks())?;
        }
        if is_directory && (cross_parent || replacing) {
            metadata.set_inode_links(self, &old_parent, old_parent.links - 1)?;
        }
        if is_directory && cross_parent && !replacing {
            metadata.set_inode_links(self, &new_parent, new_parent.links + 1)?;
        }
        metadata.stage(self)
    }

    /// Resize a regular file through its allocation-aware editor.
    pub fn resize_inode(&mut self, inode: &Inode, new_size: u64) -> Result<(), Error> {
        let file = FileEditor::new(self.transaction.filesystem.refresh(self.storage, inode)?)?;
        file.resize(self, new_size)
    }

    /// Release checked initialized extents and reduce a regular file to size 0.
    pub fn truncate_inode(&mut self, inode: &Inode) -> Result<u64, Error> {
        let inode = self.transaction.filesystem.refresh(self.storage, inode)?;
        if inode.size == 0 && inode.blocks_512 == 0 {
            return Ok(0);
        }
        self.shrink_file(&inode, 0)
    }

    fn shrink_file(&mut self, inode: &Inode, new_size: u64) -> Result<u64, Error> {
        self.validate_mutation_profile()?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let old_blocks = inode.size.div_ceil(block_size);
        let kept_blocks = new_size.div_ceil(block_size);
        if new_size >= inode.size || kept_blocks > old_blocks {
            return Err(Error::InvalidArgument);
        }

        let mut tree = self.read_extent_tree(inode)?;
        let extents = tree.data_extents()?;
        if extents
            .last()
            .is_some_and(|extent| extent.logical_end() > old_blocks)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let data_blocks = extents.iter().try_fold(0u64, |total, extent| {
            total
                .checked_add(u64::from(extent.length))
                .ok_or(Corrupt::AddressOverflow)
        })?;
        let tree_blocks = u64::try_from(tree.external_blocks_by_level()?.len())
            .map_err(|_| Corrupt::AddressOverflow)?;
        let expected_sectors = data_blocks
            .checked_add(tree_blocks)
            .and_then(|blocks| blocks.checked_add(u64::from(inode.external_xattr_block != 0)))
            .and_then(|blocks| blocks.checked_mul(block_size / 512))
            .ok_or(Corrupt::AddressOverflow)?;
        if inode.blocks_512 != expected_sectors {
            return Err(Unsupported::ExtentMutation.into());
        }
        let removed = tree.remove(kept_blocks, 1_u64 << 32)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(removed.len() + tree.released_blocks().len())
            .map_err(|_| Error::OutOfMemory)?;
        ranges.extend(
            removed
                .into_iter()
                .map(|extent| (extent.physical, u64::from(extent.length))),
        );
        ranges.extend(tree.released_blocks().iter().map(|number| (*number, 1)));
        let released = self.release_blocks(&ranges)?;

        let mut metadata = MetadataMutation::new();
        let released_blocks = released.blocks;
        self.apply_resources(&mut metadata, ResourceUpdate::Release(released))?;

        if !new_size.is_multiple_of(block_size) && kept_blocks != 0 {
            let logical = u32::try_from(kept_blocks - 1).map_err(|_| Corrupt::AddressOverflow)?;
            if let Some((last, ExtentState::Written)) = tree.lookup(logical) {
                let mut block = self.read_owned_block(last)?;
                let tail =
                    usize::try_from(new_size % block_size).map_err(|_| Corrupt::AddressOverflow)?;
                block[tail..].fill(0);
                metadata.adopt(last, block)?;
            }
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
        let extent_nodes = editor.set_extent_tree(
            &tree,
            new_size,
            block_size,
            self.transaction
                .filesystem
                .superblock
                .has_metadata_checksums(),
            u64::from(inode.external_xattr_block != 0),
        )?;
        editor.finish();
        metadata.adopt_blocks(extent_nodes)?;
        metadata.stage(self)?;
        Ok(released_blocks)
    }

    /// Read one filesystem block through this transaction's private view.
    pub fn read_block(&mut self, number: u64, dst: &mut [u8]) -> Result<(), Error> {
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
    pub fn write_block(&mut self, number: u64, src: &[u8]) -> Result<(), Error> {
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
    pub fn modify_block<F>(&mut self, number: u64, modify: F) -> Result<(), Error>
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

    fn insert_reserved(&mut self, number: u64, index: usize) -> Result<usize, Error> {
        let bytes = self.available.pop().ok_or(Error::ReservationExhausted)?;
        self.dirty.insert(index, DirtyBlock { number, bytes });
        Ok(index)
    }

    fn block_offset(&self, number: u64) -> Result<u64, Error> {
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
    ) -> Result<Option<DirectoryGrowth>, Error> {
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
    ) -> Result<DirectoryGrowth, Error> {
        if tree.inode.flags & super::DIRECTORY_INDEX_FL != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let mut extent_tree = self.read_extent_tree(&tree.inode)?;
        if extent_tree
            .data_extents()?
            .last()
            .is_some_and(|extent| extent.logical_end() > tree.nodes.len() as u64)
            || tree.nodes.iter().any(|node| {
                u32::try_from(node.logical)
                    .ok()
                    .and_then(|logical| extent_tree.lookup(logical))
                    != Some((node.block.number, ExtentState::Written))
            })
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }

        let allocation_start = resources.blocks.len();
        self.extend_allocation(resources, 1)?;
        let leaf_number = resources.blocks[allocation_start];
        let logical = u32::try_from(tree.nodes.len()).map_err(|_| Corrupt::AddressOverflow)?;
        extent_tree.insert(Extent::new(logical, leaf_number, 1, ExtentState::Written)?)?;
        let new_nodes = extent_tree.unassigned_blocks();
        self.extend_allocation(resources, new_nodes)?;
        extent_tree.assign_blocks(&resources.blocks[allocation_start + 1..])?;

        let mut leaf = self.zero_block()?;
        initialize_empty_directory_leaf(
            self.transaction.filesystem.superblock.checksum_seed,
            tree.inode.number,
            tree.inode.generation,
            &mut leaf,
        )?;
        tree.nodes.push(DirectoryNode {
            logical: u64::from(logical),
            kind: crate::DirectoryBlockKind::Leaf,
            block: DirtyBlock {
                number: leaf_number,
                bytes: leaf,
            },
            dirty: true,
        });
        let size = u64::from(logical)
            .checked_add(1)
            .and_then(|blocks| blocks.checked_mul(block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        Ok(DirectoryGrowth {
            inode: tree.inode.clone(),
            tree: extent_tree,
            size,
        })
    }

    fn apply_directory_insertion(
        &mut self,
        metadata: &mut MetadataMutation,
        resources: Allocation,
        growth: Option<DirectoryGrowth>,
    ) -> Result<(), Error> {
        self.apply_resources(metadata, ResourceUpdate::Allocate(resources))?;
        if let Some(growth) = growth {
            self.apply_directory_growth(metadata, growth)?;
        }
        Ok(())
    }

    fn apply_directory_growth(
        &mut self,
        metadata: &mut MetadataMutation,
        growth: DirectoryGrowth,
    ) -> Result<(), Error> {
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
        let extent_nodes = editor.set_extent_tree(
            &growth.tree,
            growth.size,
            block_size,
            self.transaction
                .filesystem
                .superblock
                .has_metadata_checksums(),
            u64::from(growth.inode.external_xattr_block != 0),
        )?;
        editor.finish();
        metadata.adopt_blocks(extent_nodes)
    }

    fn apply_resources(
        &mut self,
        metadata: &mut MetadataMutation,
        update: ResourceUpdate,
    ) -> Result<(), Error> {
        let (blocks, allocating, groups) = match update {
            ResourceUpdate::Allocate(resources) => (
                u64::try_from(resources.blocks.len()).map_err(|_| Corrupt::AddressOverflow)?,
                true,
                resources.groups,
            ),
            ResourceUpdate::Release(resources) => (resources.blocks, false, resources.groups),
        };
        let inode_changed = groups.iter().any(|group| group.inode_bitmap.is_some());
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        metadata.load(self, superblock_number)?;
        if blocks != 0 || inode_changed {
            let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
                .map_err(|_| Corrupt::AddressOverflow)?;
            let raw = &mut metadata.get_mut(superblock_number)?
                [superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
            if allocating {
                if blocks != 0 {
                    decrement_superblock_free_blocks_by(raw, blocks)?;
                }
                if inode_changed {
                    decrement_superblock_free_inodes(raw)?;
                }
            } else {
                if blocks != 0 {
                    increment_superblock_free_blocks(
                        raw,
                        blocks,
                        self.transaction.filesystem.superblock.blocks_count,
                    )?;
                }
                if inode_changed {
                    increment_superblock_free_inodes(
                        raw,
                        u64::from(self.transaction.filesystem.superblock.inodes_count),
                    )?;
                }
            }
            update_superblock_checksum(raw);
        }
        let descriptor_blocks = self.descriptor_blocks(&groups)?;
        metadata.adopt_blocks(descriptor_blocks)?;
        metadata.adopt_group_edits(groups)?;
        Ok(())
    }

    fn allocate_blocks(&mut self, wanted: usize) -> Result<Allocation, Error> {
        let mut allocation = Allocation {
            blocks: Vec::new(),
            groups: Vec::new(),
        };
        self.extend_allocation(&mut allocation, wanted)?;
        Ok(allocation)
    }

    fn open_group(
        &mut self,
        number: u32,
        existing: Option<GroupEdit>,
    ) -> Result<GroupEditor, Error> {
        let edit = match existing {
            Some(edit) if edit.number == number => edit,
            Some(_) => return Err(Corrupt::InvalidGroup(number).into()),
            None => GroupEdit {
                number,
                descriptor: self
                    .transaction
                    .filesystem
                    .read_group_descriptor(self.storage, number)?,
                block_bitmap: None,
                inode_bitmap: None,
            },
        };
        let superblock = &self.transaction.filesystem.superblock;
        let start = u64::from(superblock.first_data_block)
            .checked_add(u64::from(number) * u64::from(superblock.blocks_per_group))
            .ok_or(Corrupt::AddressOverflow)?;
        let blocks = superblock
            .blocks_count
            .checked_sub(start)
            .map(|remaining| remaining.min(u64::from(superblock.blocks_per_group)))
            .ok_or(Corrupt::InvalidGroup(number))?;
        let first_inode = u64::from(number) * u64::from(superblock.inodes_per_group);
        let inodes = u64::from(superblock.inodes_count)
            .checked_sub(first_inode)
            .map(|remaining| remaining.min(u64::from(superblock.inodes_per_group)))
            .ok_or(Corrupt::InvalidGroup(number))?;
        let block_bitmap_number =
            u64::from(le32(&edit.descriptor, 0)) | (u64::from(le32(&edit.descriptor, 0x20)) << 32);
        let inode_bitmap_number =
            u64::from(le32(&edit.descriptor, 4)) | (u64::from(le32(&edit.descriptor, 0x24)) << 32);
        if block_bitmap_number >= superblock.blocks_count
            || inode_bitmap_number >= superblock.blocks_count
            || edit
                .block_bitmap
                .as_ref()
                .is_some_and(|bitmap| bitmap.number != block_bitmap_number)
            || edit
                .inode_bitmap
                .as_ref()
                .is_some_and(|bitmap| bitmap.number != inode_bitmap_number)
        {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        Ok(GroupEditor {
            edit,
            start,
            blocks,
            first_inode,
            inodes,
            block_bitmap_number,
            inode_bitmap_number,
        })
    }

    fn load_group_block_bitmap(
        &mut self,
        group: &mut GroupEditor,
        allow_initialize: bool,
    ) -> Result<(), Error> {
        if group.edit.block_bitmap.is_some() {
            return Ok(());
        }
        let bitmap = if le16(&group.edit.descriptor, 0x12) & 0x0002 != 0 {
            if !allow_initialize || group.edit.number == 0 {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let (bitmap, computed_free) = self.initialize_block_bitmap(
                group.edit.number,
                &group.edit.descriptor,
                group.start,
                group.blocks,
            )?;
            let stored_free = u64::from(le16(&group.edit.descriptor, 0x0c))
                | (u64::from(le16(&group.edit.descriptor, 0x2c)) << 16);
            if stored_free != computed_free {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            }
            let flags = le16(&group.edit.descriptor, 0x12) & !0x0002;
            put_le16(&mut group.edit.descriptor, 0x12, flags);
            bitmap
        } else {
            let bitmap = self.read_owned_block(group.block_bitmap_number)?;
            self.verify_block_bitmap_checksum(group.edit.number, &group.edit.descriptor, &bitmap)?;
            bitmap
        };
        group.edit.block_bitmap = Some(DirtyBlock {
            number: group.block_bitmap_number,
            bytes: bitmap,
        });
        Ok(())
    }

    fn load_group_inode_bitmap(
        &mut self,
        group: &mut GroupEditor,
        allow_initialize: bool,
    ) -> Result<(), Error> {
        if group.edit.inode_bitmap.is_some() {
            return Ok(());
        }
        let uninitialized = le16(&group.edit.descriptor, 0x12) & 0x0001 != 0;
        let bitmap = if uninitialized {
            let free = u64::from(le16(&group.edit.descriptor, 0x0e))
                | (u64::from(le16(&group.edit.descriptor, 0x2e)) << 16);
            if !allow_initialize
                || group.edit.number == 0
                || free != group.inodes
                || le16(&group.edit.descriptor, 0x12) & 0x0004 == 0
            {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let mut bitmap = self.zero_block()?;
            let bitmap_bits = u64::try_from(bitmap.len())
                .map_err(|_| Corrupt::AddressOverflow)?
                .checked_mul(8)
                .ok_or(Corrupt::AddressOverflow)?;
            set_bitmap_range(&mut bitmap, group.inodes, bitmap_bits - group.inodes)?;
            let flags = le16(&group.edit.descriptor, 0x12) & !0x0001;
            put_le16(&mut group.edit.descriptor, 0x12, flags);
            bitmap
        } else {
            let bitmap = self.read_owned_block(group.inode_bitmap_number)?;
            self.verify_inode_bitmap_checksum(group.edit.number, &group.edit.descriptor, &bitmap)?;
            bitmap
        };
        group.edit.inode_bitmap = Some(DirtyBlock {
            number: group.inode_bitmap_number,
            bytes: bitmap,
        });
        Ok(())
    }

    fn finish_group(&self, mut group: GroupEditor) -> GroupEdit {
        if let Some(bitmap) = &group.edit.block_bitmap {
            let checksum = self.block_bitmap_checksum(&bitmap.bytes);
            put_le16(&mut group.edit.descriptor, 0x18, checksum as u16);
            put_le16(&mut group.edit.descriptor, 0x38, (checksum >> 16) as u16);
        }
        if let Some(bitmap) = &group.edit.inode_bitmap {
            let checksum = self.inode_bitmap_checksum(&bitmap.bytes);
            put_le16(&mut group.edit.descriptor, 0x1a, checksum as u16);
            put_le16(&mut group.edit.descriptor, 0x3a, (checksum >> 16) as u16);
        }
        update_group_descriptor_checksum(
            self.transaction.filesystem.superblock.checksum_seed,
            group.edit.number,
            &mut group.edit.descriptor,
        );
        group.edit
    }

    /// Add blocks to an allocation while preserving its prospective bitmap
    /// edits. This lets callers allocate data first, inspect its extent shape,
    /// and then request exactly the tree metadata that shape requires.
    fn extend_allocation(
        &mut self,
        allocation: &mut Allocation,
        wanted: usize,
    ) -> Result<(), Error> {
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
            let had_existing = existing.is_ok();
            let edit = existing
                .ok()
                .map(|position| allocation.groups.remove(position));
            let mut editor = self.open_group(group, edit)?;
            self.load_group_block_bitmap(&mut editor, true)?;
            let free = u64::from(le16(&editor.edit.descriptor, 0x0c))
                | (u64::from(le16(&editor.edit.descriptor, 0x2c)) << 16);
            if free == 0 {
                if had_existing {
                    let position = allocation
                        .groups
                        .binary_search_by_key(&group, |edit| edit.number)
                        .unwrap_or_else(|position| position);
                    let edit = self.finish_group(editor);
                    allocation.groups.insert(position, edit);
                }
                continue;
            }
            let before = allocation.blocks.len();
            let group_start = editor.start;
            let group_blocks = editor.blocks;
            let bitmap = &mut editor.edit.block_bitmap.as_mut().unwrap().bytes;
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
            decrement_descriptor_free_blocks_by(&mut editor.edit.descriptor, count)?;
            let position = allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.number)
                .unwrap_or_else(|position| position);
            let edit = self.finish_group(editor);
            allocation.groups.insert(position, edit);
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
    ) -> Result<(Vec<u8>, u64), Error> {
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

    fn allocate_inode(&mut self) -> Result<InodeAllocation, Error> {
        let inodes_per_group = u64::from(self.transaction.filesystem.superblock.inodes_per_group);
        let group_count = self.transaction.filesystem.superblock.group_count();
        let first_inode = u64::from(self.transaction.filesystem.superblock.first_inode);
        for group_number in 0..group_count {
            let mut editor = self.open_group(group_number, None)?;
            if editor.inodes == 0 {
                break;
            }
            let free = u64::from(le16(&editor.edit.descriptor, 0x0e))
                | (u64::from(le16(&editor.edit.descriptor, 0x2e)) << 16);
            if free == 0 {
                continue;
            }
            if free > editor.inodes {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            }

            if le16(&editor.edit.descriptor, 0x12) & 0x0002 != 0 {
                self.load_group_block_bitmap(&mut editor, true)?;
            }

            let inode_table = u64::from(le32(&editor.edit.descriptor, 8))
                | (u64::from(le32(&editor.edit.descriptor, 0x28)) << 32);
            if inode_table >= self.transaction.filesystem.superblock.blocks_count {
                return Err(Corrupt::InvalidInodeTable.into());
            }
            self.load_group_inode_bitmap(&mut editor, true)?;
            let start = if group_number == 0 {
                first_inode - 1
            } else {
                0
            };
            let bitmap = &mut editor.edit.inode_bitmap.as_mut().unwrap().bytes;
            let Some(index) = (start..editor.inodes)
                .find(|index| bitmap[*index as usize / 8] & (1 << (*index as usize % 8)) == 0)
            else {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            };
            bitmap[index as usize / 8] |= 1 << (index as usize % 8);
            decrement_descriptor_free_inodes(&mut editor.edit.descriptor)?;
            update_unused_inode_count(&mut editor.edit.descriptor, index, inodes_per_group)?;
            let number = editor
                .first_inode
                .checked_add(index)
                .and_then(|number| number.checked_add(1))
                .and_then(|number| u32::try_from(number).ok())
                .ok_or(Corrupt::AddressOverflow)?;
            let edit = self.finish_group(editor);
            return Ok(InodeAllocation {
                number,
                index,
                inode_table,
                group_number,
                resources: Allocation {
                    blocks: Vec::new(),
                    groups: alloc::vec![edit],
                },
            });
        }
        Err(Corrupt::InvalidFreeBlockCount.into())
    }

    fn release_inode_root_blocks(&mut self, inode: &Inode) -> Result<ReleasedInodeBlocks, Error> {
        let tree = self.read_extent_tree(inode)?;
        let block_size = u64::from(self.transaction.filesystem.superblock.block_size);
        let extents = tree.data_extents()?;
        if extents
            .last()
            .is_some_and(|extent| extent.logical_end() > inode.size.div_ceil(block_size))
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let tree_blocks = tree.external_blocks_by_level()?;
        let owned_blocks = extents
            .iter()
            .try_fold(tree_blocks.len() as u64, |total, extent| {
                total
                    .checked_add(u64::from(extent.length))
                    .ok_or(Corrupt::AddressOverflow)
            })?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(
                extents.len() + tree_blocks.len() + usize::from(inode.external_xattr_block != 0),
            )
            .map_err(|_| Error::OutOfMemory)?;
        ranges.extend(
            extents
                .into_iter()
                .map(|extent| (extent.physical, u64::from(extent.length))),
        );
        ranges.extend(tree_blocks.into_iter().map(|number| (number, 1)));
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
        let resources = self.release_blocks(&ranges)?;
        if inode.blocks_512
            != owned_blocks
                .checked_add(u64::from(inode.external_xattr_block != 0))
                .and_then(|blocks| blocks.checked_mul(block_size / 512))
                .ok_or(Corrupt::AddressOverflow)?
        {
            return Err(Unsupported::ExtentMutation.into());
        }
        Ok(ReleasedInodeBlocks {
            resources,
            retained_xattr_block,
        })
    }

    fn release_blocks(&mut self, ranges: &[(u64, u64)]) -> Result<ResourceRelease, Error> {
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
            let mut editor = self.open_group(release.group, None)?;
            let (reserved, _) = self.initialize_block_bitmap(
                release.group,
                &editor.edit.descriptor,
                editor.start,
                editor.blocks,
            )?;
            self.load_group_block_bitmap(&mut editor, false)?;
            let bitmap = &mut editor.edit.block_bitmap.as_mut().unwrap().bytes;
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
                &mut editor.edit.descriptor,
                release.indices.len() as u64,
                editor.blocks,
            )?;
            groups.push(self.finish_group(editor));
        }
        Ok(ResourceRelease {
            blocks: released,
            groups,
        })
    }
    fn read_extent_tree(&mut self, inode: &Inode) -> Result<ExtentTree, Error> {
        let block_size = self.transaction.filesystem.superblock.block_size as usize;
        let identity = ExtentIdentity {
            checksum_seed: self.transaction.filesystem.superblock.checksum_seed,
            inode: inode.number,
            generation: inode.generation,
            metadata_checksums: self
                .transaction
                .filesystem
                .superblock
                .has_metadata_checksums(),
        };
        ExtentTree::load(
            &inode.block_map,
            block_size,
            self.transaction.filesystem.superblock.blocks_count,
            identity,
            |number| self.read_owned_block(number),
        )
    }

    fn prepare_inode_release(
        &mut self,
        inode: &Inode,
        kind: ReleaseKind,
    ) -> Result<PreparedInodeRelease, Error> {
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
        let released = match kind {
            ReleaseKind::FastSymlink => ReleasedInodeBlocks {
                resources: ResourceRelease {
                    blocks: 0,
                    groups: Vec::new(),
                },
                retained_xattr_block: None,
            },
            ReleaseKind::Regular | ReleaseKind::Directory => {
                self.release_inode_root_blocks(inode)?
            }
        };
        let ReleasedInodeBlocks {
            mut resources,
            retained_xattr_block,
        } = released;
        let zero_based = inode
            .number
            .checked_sub(1)
            .ok_or(Corrupt::InvalidInode(inode.number))?;
        let inode_group = zero_based / self.transaction.filesystem.superblock.inodes_per_group;
        let inode_index =
            u64::from(zero_based % self.transaction.filesystem.superblock.inodes_per_group);
        let (position, existing) = match resources
            .groups
            .binary_search_by_key(&inode_group, |group| group.number)
        {
            Ok(position) => (position, Some(resources.groups.remove(position))),
            Err(position) => {
                resources
                    .groups
                    .try_reserve(1)
                    .map_err(|_| Error::OutOfMemory)?;
                (position, None)
            }
        };
        let mut editor = self.open_group(inode_group, existing)?;
        let inode_table = u64::from(le32(&editor.edit.descriptor, 8))
            | (u64::from(le32(&editor.edit.descriptor, 0x28)) << 32);
        if inode_table >= self.transaction.filesystem.superblock.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        self.load_group_inode_bitmap(&mut editor, false)?;
        let inode_bitmap = &mut editor.edit.inode_bitmap.as_mut().unwrap().bytes;
        let bit = usize::try_from(inode_index).map_err(|_| Corrupt::AddressOverflow)?;
        if inode_bitmap[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        inode_bitmap[bit / 8] &= !(1 << (bit % 8));
        increment_descriptor_free_inodes(
            &mut editor.edit.descriptor,
            u64::from(self.transaction.filesystem.superblock.inodes_per_group),
        )?;
        if matches!(kind, ReleaseKind::Directory) {
            decrement_descriptor_used_directories(
                &mut editor.edit.descriptor,
                u64::from(self.transaction.filesystem.superblock.inodes_per_group),
            )?;
        }

        let (inode_block_number, inode_offset) =
            self.inode_table_location(inode_table, inode_index)?;
        let inode_size = usize::from(self.transaction.filesystem.superblock.inode_size);
        let mut inode_block = self.read_owned_block(inode_block_number)?;
        inode_block[inode_offset..inode_offset + inode_size].fill(0);
        let edit = self.finish_group(editor);
        resources.groups.insert(position, edit);
        Ok(PreparedInodeRelease {
            resources,
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
    ) -> Result<PreparedInodeRelease, Error> {
        if !directory.is_directory() || directory.links != 2 {
            return Err(Unsupported::MutationProfile.into());
        }
        DirectoryTree::load(self, directory)?.validate_empty(parent_number)?;
        self.prepare_inode_release(directory, ReleaseKind::Directory)
    }

    fn stage_overwrite(
        &mut self,
        superblock: DirtyBlock,
        data: Vec<DirtyBlock>,
    ) -> Result<(), Error> {
        let mut metadata = MetadataMutation::new();
        metadata.adopt_block(superblock)?;
        metadata.adopt_blocks(data)?;
        metadata.stage(self)
    }

    fn stage_inode_release(
        &mut self,
        release: PreparedInodeRelease,
        namespace: Vec<DirtyBlock>,
    ) -> Result<(), Error> {
        let mut metadata = MetadataMutation::new();
        self.apply_inode_release(&mut metadata, release)?;
        metadata.adopt_blocks(namespace)?;
        metadata.stage(self)
    }

    fn stage_replaced_directory(
        &mut self,
        release: PreparedInodeRelease,
        namespace: Vec<DirtyBlock>,
        old_parent: &Inode,
    ) -> Result<(), Error> {
        let mut metadata = MetadataMutation::new();
        self.apply_inode_release(&mut metadata, release)?;
        metadata.adopt_blocks(namespace)?;
        metadata.set_inode_links(self, old_parent, old_parent.links - 1)?;
        metadata.stage(self)
    }

    fn apply_inode_release(
        &mut self,
        metadata: &mut MetadataMutation,
        release: PreparedInodeRelease,
    ) -> Result<(), Error> {
        self.apply_resources(metadata, ResourceUpdate::Release(release.resources))?;
        metadata.adopt_block(release.inode_block)?;
        if let Some(block) = release.retained_xattr_block {
            metadata.adopt_block(block)?;
        }
        Ok(())
    }

    fn descriptor_blocks(&mut self, groups: &[GroupEdit]) -> Result<Vec<DirtyBlock>, Error> {
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

    fn inode_location(&mut self, number: u32) -> Result<(u64, usize), Error> {
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
        self.inode_table_location(table, index)
    }

    fn inode_table_location(&self, table: u64, index: u64) -> Result<(u64, usize), Error> {
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
    ) -> Result<(), Error> {
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

    fn directory_parent_number(&mut self, directory: &Inode) -> Result<u32, Error> {
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

    fn validate_mutation_profile(&self) -> Result<(), Error> {
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

    fn read_owned_block(&mut self, number: u64) -> Result<Vec<u8>, Error> {
        let mut block = self.transaction.filesystem.new_block_buffer()?;
        self.read_block(number, &mut block)?;
        Ok(block)
    }

    fn zero_block(&self) -> Result<Vec<u8>, Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        let expected =
            u32::from(le16(descriptor, 0x1a)) | (u32::from(le16(descriptor, 0x3a)) << 16);
        if self.inode_bitmap_checksum(bitmap) != expected {
            return Err(Corrupt::InodeBitmapChecksum(group).into());
        }
        Ok(())
    }
}

fn decrement_descriptor_free_blocks_by(descriptor: &mut [u8], amount: u64) -> Result<(), Error> {
    let free = u64::from(le16(descriptor, 0x0c)) | (u64::from(le16(descriptor, 0x2c)) << 16);
    let free = free
        .checked_sub(amount)
        .filter(|free| *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0c, free as u16);
    put_le16(descriptor, 0x2c, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_free_blocks(
    descriptor: &mut [u8],
    amount: u64,
    group_blocks: u64,
) -> Result<(), Error> {
    let free = u64::from(le16(descriptor, 0x0c)) | (u64::from(le16(descriptor, 0x2c)) << 16);
    let free = free
        .checked_add(amount)
        .filter(|free| *free <= group_blocks && *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0c, free as u16);
    put_le16(descriptor, 0x2c, (free >> 16) as u16);
    Ok(())
}

fn decrement_descriptor_free_inodes(descriptor: &mut [u8]) -> Result<(), Error> {
    let free = u32::from(le16(descriptor, 0x0e)) | (u32::from(le16(descriptor, 0x2e)) << 16);
    let free = free.checked_sub(1).ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0e, free as u16);
    put_le16(descriptor, 0x2e, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_free_inodes(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error> {
    let free = u64::from(le16(descriptor, 0x0e)) | (u64::from(le16(descriptor, 0x2e)) << 16);
    let free = free
        .checked_add(1)
        .filter(|free| *free <= inodes_per_group && *free <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x0e, free as u16);
    put_le16(descriptor, 0x2e, (free >> 16) as u16);
    Ok(())
}

fn increment_descriptor_used_directories(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error> {
    let used = u64::from(le16(descriptor, 0x10)) | (u64::from(le16(descriptor, 0x30)) << 16);
    let used = used
        .checked_add(1)
        .filter(|used| *used <= inodes_per_group && *used <= u64::from(u32::MAX))
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x10, used as u16);
    put_le16(descriptor, 0x30, (used >> 16) as u16);
    Ok(())
}

fn decrement_descriptor_used_directories(
    descriptor: &mut [u8],
    inodes_per_group: u64,
) -> Result<(), Error> {
    let used = u64::from(le16(descriptor, 0x10)) | (u64::from(le16(descriptor, 0x30)) << 16);
    if used > inodes_per_group {
        return Err(Corrupt::InvalidFreeBlockCount.into());
    }
    let used = used.checked_sub(1).ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le16(descriptor, 0x10, used as u16);
    put_le16(descriptor, 0x30, (used >> 16) as u16);
    Ok(())
}

fn update_unused_inode_count(
    descriptor: &mut [u8],
    allocated_index: u64,
    inodes_per_group: u64,
) -> Result<(), Error> {
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

fn decrement_superblock_free_blocks_by(superblock: &mut [u8], amount: u64) -> Result<(), Error> {
    let free = u64::from(le32(superblock, 0x0c)) | (u64::from(le32(superblock, 0x158)) << 32);
    let free = free
        .checked_sub(amount)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x0c, free as u32);
    put_le32(superblock, 0x158, (free >> 32) as u32);
    Ok(())
}

fn increment_superblock_free_blocks(
    superblock: &mut [u8],
    amount: u64,
    blocks_count: u64,
) -> Result<(), Error> {
    let free = u64::from(le32(superblock, 0x0c)) | (u64::from(le32(superblock, 0x158)) << 32);
    let free = free
        .checked_add(amount)
        .filter(|free| *free <= blocks_count)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x0c, free as u32);
    put_le32(superblock, 0x158, (free >> 32) as u32);
    Ok(())
}

fn decrement_superblock_free_inodes(superblock: &mut [u8]) -> Result<(), Error> {
    let free = le32(superblock, 0x10)
        .checked_sub(1)
        .ok_or(Corrupt::InvalidFreeBlockCount)?;
    put_le32(superblock, 0x10, free);
    Ok(())
}

fn increment_superblock_free_inodes(superblock: &mut [u8], inodes_count: u64) -> Result<(), Error> {
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

fn initialize_fast_symlink(inode: &mut [u8], target: &[u8]) -> Result<(), Error> {
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

fn initialize_directory_inode(
    inode: &mut [u8],
    permissions: u16,
    physical: u64,
    block_size: u64,
) -> Result<(), Error> {
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

fn initialize_directory_block(
    checksum_seed: u32,
    inode_number: u32,
    generation: u32,
    parent_number: u32,
    block: &mut [u8],
) -> Result<(), Error> {
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

fn initialize_empty_directory_leaf(
    checksum_seed: u32,
    inode_number: u32,
    generation: u32,
    block: &mut [u8],
) -> Result<(), Error> {
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

fn directory_parent_entry(block: &[u8], inode_number: u32) -> Result<u32, Error> {
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

fn replace_directory_parent(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    old_parent: u32,
    new_parent: u32,
) -> Result<(), Error> {
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

fn insert_directory_entry(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    inode_number: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), Error> {
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

fn remove_directory_entry(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    inode_number: u32,
    name: &[u8],
) -> Result<(), Error> {
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

fn find_directory_entry(block: &[u8], name: &[u8]) -> Result<Option<u32>, Error> {
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

fn update_directory_index_checksum(
    seed: u32,
    directory: &Inode,
    kind: crate::DirectoryBlockKind,
    block: &mut [u8],
) -> Result<(), Error> {
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

fn replace_directory_entry(
    checksum_seed: u32,
    directory: &Inode,
    block: &mut [u8],
    old_inode: u32,
    new_inode: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), Error> {
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

fn set_bitmap_range(bitmap: &mut [u8], start: u64, len: u64) -> Result<(), Error> {
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
