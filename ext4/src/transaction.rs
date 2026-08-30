//! Transaction-private dirty blocks and fallible memory reservations.
//!
//! Dirty blocks remain isolated until [`Transaction::commit`] serializes them
//! through the internal JBD2 journal.

use crate::checksum::Checksum;
use crate::directory::{
    BlockKind as DirectoryBlockKind, DirectoryBlock, record as directory_record,
};
use crate::extent_tree::{Extent, ExtentIdentity, ExtentState, ExtentTree, SerializedNode};
use crate::inode::InodeRecord;
use crate::ondisk::{self, le32, put_le32};
use crate::{
    Corrupt, DirectoryEntry, Error, Ext4, FsError, Inode, InodeMetadataUpdate, Storage, Timestamp,
    Unsupported,
};
use alloc::vec::Vec;

pub(crate) type DirtyBlock = SerializedNode;

#[inline(never)]
fn set_extent_tree(
    record: &mut InodeRecord<'_>,
    tree: &ExtentTree,
    size: u64,
    block_size: u64,
    metadata_checksums: bool,
    extra_owned_blocks: u64,
) -> Result<Vec<DirtyBlock>, Error> {
    tree.write_root(record.extent_root_mut())?;
    record.set_size(size);
    let blocks = tree
        .data_extents()?
        .into_iter()
        .try_fold(0u64, |sum, extent| {
            sum.checked_add(u64::from(extent.length))
                .ok_or(Corrupt::AddressOverflow)
        })?
        .checked_add(
            u64::try_from(tree.external_blocks()?.len()).map_err(|_| Corrupt::AddressOverflow)?,
        )
        .and_then(|n| n.checked_add(extra_owned_blocks))
        .ok_or(Corrupt::AddressOverflow)?;
    record.set_blocks_512(
        blocks
            .checked_mul(block_size / 512)
            .filter(|n| *n < 1_u64 << 48)
            .ok_or(Corrupt::AddressOverflow)?,
    );
    tree.serialize_dirty(
        usize::try_from(block_size).map_err(|_| Corrupt::AddressOverflow)?,
        ExtentIdentity {
            checksum_seed: record.checksum_seed,
            inode: record.number,
            generation: record.generation,
            metadata_checksums,
        },
    )
}

/// A sorted, unique map from physical block number to prospective contents.
///
/// Both an operation-local metadata edit and the enclosing transaction use
/// this representation. Moving edits between them therefore transfers block
/// buffers instead of searching again and copying a full filesystem block.
#[derive(Default)]
struct BlockEdits {
    blocks: Vec<DirtyBlock>,
}

impl BlockEdits {
    fn index(&self, number: u64) -> Result<usize, usize> {
        self.blocks
            .binary_search_by_key(&number, |block| block.number)
    }

    fn adopt(&mut self, block: DirtyBlock) -> Result<(), Error> {
        let index = match self.index(block.number) {
            Ok(_) => return Err(Corrupt::InvalidDirectory.into()),
            Err(index) => index,
        };
        self.blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.blocks.insert(index, block);
        Ok(())
    }
}

/// A prospective metadata change keyed by physical filesystem block.
///
/// Namespace operations often touch several logical objects which happen to
/// share a descriptor or inode-table block.  Keeping those edits in one cache
/// makes that aliasing ordinary instead of forcing every operation to build a
/// list of supposedly-distinct block numbers and special-case collisions.
#[derive(Default)]
struct MetadataMutation {
    blocks: BlockEdits,
}

impl MetadataMutation {
    #[inline(never)]
    fn load(&mut self, transaction: &mut Transaction<'_, '_>, number: u64) -> Result<(), Error> {
        let Err(index) = self.blocks.index(number) else {
            return Ok(());
        };
        let bytes = transaction.read_owned_block(number)?;
        self.blocks
            .blocks
            .try_reserve(1)
            .map_err(|_| Error::OutOfMemory)?;
        self.blocks
            .blocks
            .insert(index, DirtyBlock { number, bytes });
        Ok(())
    }

    fn adopt(&mut self, number: u64, bytes: Vec<u8>) -> Result<(), Error> {
        self.blocks.adopt(DirtyBlock { number, bytes })
    }

    fn adopt_blocks(&mut self, blocks: impl IntoIterator<Item = DirtyBlock>) -> Result<(), Error> {
        for block in blocks {
            self.adopt(block.number, block.bytes)?;
        }
        Ok(())
    }

    fn adopt_group_edits(&mut self, groups: Vec<GroupEdit>) -> Result<(), Error> {
        for group in groups {
            for bitmap in group.bitmaps.into_iter().flatten() {
                self.adopt(bitmap.number, bitmap.bytes)?;
            }
        }
        Ok(())
    }

    fn get_mut(&mut self, number: u64) -> Result<&mut [u8], Corrupt> {
        let index = self
            .blocks
            .index(number)
            .map_err(|_| Corrupt::InvalidDirectory)?;
        Ok(&mut self.blocks.blocks[index].bytes)
    }

    #[inline(never)]
    fn edit_inode(
        &mut self,
        transaction: &mut Transaction<'_, '_>,
        inode: &Inode,
        edit: &mut dyn FnMut(&mut InodeRecord<'_>) -> Result<(), Error>,
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
        let mut record = InodeRecord::for_update(raw, checksum_seed, inode)?;
        edit(&mut record)?;
        record.finish();
        Ok(())
    }

    fn set_inode_links(
        &mut self,
        transaction: &mut Transaction<'_, '_>,
        inode: &Inode,
        links: u16,
    ) -> Result<(), Error> {
        self.edit_inode(transaction, inode, &mut |editor| {
            editor.set_links(links);
            Ok(())
        })
    }

    #[inline(never)]
    fn stage(self, transaction: &mut Transaction<'_, '_>) -> Result<(), Error> {
        if transaction.available.len() < self.blocks.blocks.len() {
            return Err(Error::ReservationExhausted);
        }
        for block in self.blocks.blocks {
            transaction.adopt_dirty(block)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ExistingDirectoryEdit {
    Remove { number: u32 },
    Replace { old: u32, new: u32, kind: u8 },
}

struct DirectoryNode {
    number: u64,
    block: DirectoryBlock,
    dirty: bool,
}

/// A checked, representation-aware directory mutation view.
///
/// Namespace operations deal in names and inode numbers; this object owns the
/// mapping from those operations to physical leaf blocks.  Loading, checksum
/// validation, duplicate detection, and multi-block scanning happen once.
struct DirectoryTree {
    inode: Inode,
    nodes: Vec<DirectoryNode>,
}

impl DirectoryTree {
    #[inline(never)]
    fn load(transaction: &mut Transaction<'_, '_>, inode: &Inode) -> Result<Self, Error> {
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
        let extent_tree = if inode.flags & super::EXTENTS_FL != 0 {
            Some(transaction.read_extent_tree(inode)?)
        } else {
            None
        };
        for logical in 0..count {
            let physical = match &extent_tree {
                Some(tree) => u32::try_from(logical)
                    .ok()
                    .and_then(|logical| tree.lookup(logical))
                    .filter(|(_, state)| *state == ExtentState::Written)
                    .map(|(physical, _)| physical),
                None => transaction.map_file_block(inode, logical)?,
            }
            .ok_or(Corrupt::InvalidDirectory)?;
            if nodes
                .iter()
                .any(|node: &DirectoryNode| node.number == physical)
            {
                return Err(Corrupt::InvalidDirectory.into());
            }
            let bytes = transaction.read_owned_block(physical)?;
            let block = DirectoryBlock::new(
                transaction.filesystem.superblock.checksum_seed,
                transaction.filesystem.superblock.has_metadata_checksums(),
                inode,
                logical,
                bytes,
            )?;
            nodes.push(DirectoryNode {
                number: physical,
                block,
                dirty: false,
            });
        }
        Ok(Self {
            inode: inode.clone(),
            nodes,
        })
    }

    #[inline(never)]
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
            if node.block.kind != DirectoryBlockKind::Leaf {
                continue;
            }
            match node.block.insert(number, name, kind) {
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

    #[inline(never)]
    fn edit_existing(&mut self, name: &[u8], edit: ExistingDirectoryEdit) -> Result<(), Error> {
        for node in &mut self.nodes {
            if node.block.kind != DirectoryBlockKind::Leaf {
                continue;
            }
            let result = match edit {
                ExistingDirectoryEdit::Remove { number } => node.block.remove(name, number),
                ExistingDirectoryEdit::Replace { old, new, kind } => {
                    node.block.replace(name, old, new, kind)
                }
            };
            match result {
                Ok(()) => {
                    node.dirty = true;
                    return Ok(());
                }
                Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::NotFound)
    }

    #[inline(never)]
    fn set_parent(&mut self, old_parent: u32, new_parent: u32) -> Result<(), Error> {
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.block.logical == 0)
            .ok_or(Corrupt::InvalidDirectory)?;
        node.block.replace_parent(old_parent, new_parent)?;
        node.dirty = true;
        Ok(())
    }

    fn validate_empty(&mut self, parent_number: u32) -> Result<(), Error> {
        let indexed = self.inode.flags & super::DIRECTORY_INDEX_FL != 0;
        let mut dot = false;
        let mut dotdot = false;
        if indexed {
            let root = self
                .nodes
                .iter_mut()
                .find(|node| node.block.logical == 0 && node.block.kind == DirectoryBlockKind::Root)
                .ok_or(Corrupt::InvalidDirectory)?;
            if root.block.parent()? != parent_number {
                return Err(Corrupt::InvalidDirectory.into());
            }
            dot = true;
            dotdot = true;
        }
        for node in &mut self.nodes {
            if node.block.kind != DirectoryBlockKind::Leaf {
                continue;
            }
            let tail = node.block.records_end;
            let mut cursor = 0usize;
            while cursor < tail {
                let entry = directory_record(&node.block.bytes[..node.block.records_end], cursor)?;
                if entry.inode != 0 {
                    match entry.name {
                        b"." if !indexed && !dot && entry.inode == self.inode.number => dot = true,
                        b".." if !indexed && !dotdot && entry.inode == parent_number => {
                            dotdot = true
                        }
                        _ => return Err(Error::NotEmpty),
                    }
                }
                cursor = entry.next;
            }
        }
        if !dot || !dotdot {
            return Err(Corrupt::InvalidDirectory.into());
        }
        Ok(())
    }

    fn find(&mut self, name: &[u8]) -> Result<Option<(usize, u32)>, Error> {
        for (index, node) in self.nodes.iter_mut().enumerate() {
            if node.block.kind != DirectoryBlockKind::Leaf {
                continue;
            }
            if let Some(number) = node.block.find(name)? {
                return Ok(Some((index, number)));
            }
        }
        Ok(None)
    }

    fn into_dirty_blocks(self) -> Vec<DirtyBlock> {
        self.nodes
            .into_iter()
            .filter_map(|node| {
                node.dirty.then(|| DirtyBlock {
                    number: node.number,
                    bytes: node.block.bytes,
                })
            })
            .collect()
    }
}

struct GroupEdit {
    descriptor: ondisk::GroupDescriptor,
    bitmaps: [Option<DirtyBlock>; 2],
}

struct BlockGroup {
    edit: GroupEdit,
    start: u64,
    blocks: u64,
    first_inode: u64,
    inodes: u64,
    inodes_per_group: u64,
    bitmap_numbers: [u64; 2],
}

struct Bitmap<'a> {
    bytes: &'a mut [u8],
    bits: u64,
}

impl Bitmap<'_> {
    #[inline(never)]
    fn release(&mut self, bit: u64) -> Result<(), Error> {
        if bit >= self.bits {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let bit = usize::try_from(bit).map_err(|_| Corrupt::AddressOverflow)?;
        let (byte, mask) = (bit / 8, 1 << (bit % 8));
        if self.bytes[byte] & mask == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        self.bytes[byte] &= !mask;
        Ok(())
    }

    #[inline(never)]
    fn claim_free(&mut self, start: u64) -> Option<u64> {
        for bit in start..self.bits {
            let bit_index = bit as usize;
            let mask = 1 << (bit_index % 8);
            if self.bytes[bit_index / 8] & mask == 0 {
                self.bytes[bit_index / 8] |= mask;
                return Some(bit);
            }
        }
        None
    }
}

impl BlockGroup {
    #[inline(never)]
    fn allocate_blocks(&mut self, wanted: usize, output: &mut Vec<u64>) -> Result<usize, Error> {
        let before = output.len();
        let mut cursor = 0;
        let mut bitmap = Bitmap {
            bytes: &mut self.edit.bitmaps[ondisk::BitmapKind::Block as usize]
                .as_mut()
                .unwrap()
                .bytes,
            bits: self.blocks,
        };
        while output.len() - before < wanted {
            let bit = bitmap.claim_free(cursor);
            let Some(bit) = bit else { break };
            output.push(self.start + bit);
            cursor = bit + 1;
        }
        let allocated = output.len() - before;
        self.edit
            .descriptor
            .allocate_blocks(u64::try_from(allocated).map_err(|_| Corrupt::AddressOverflow)?)?;
        Ok(allocated)
    }

    #[inline(never)]
    fn release_blocks(&mut self, bits: &[u64], reserved: &[u8]) -> Result<(), Error> {
        let mut bitmap = Bitmap {
            bytes: &mut self.edit.bitmaps[ondisk::BitmapKind::Block as usize]
                .as_mut()
                .unwrap()
                .bytes,
            bits: self.blocks,
        };
        for &bit in bits {
            let bit_index = usize::try_from(bit).map_err(|_| Corrupt::AddressOverflow)?;
            if reserved[bit_index / 8] & (1 << (bit_index % 8)) != 0 {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            bitmap
                .release(bit)
                .map_err(|_| Error::Corrupt(Corrupt::InvalidExtentTree))?;
        }
        self.edit.descriptor.release_blocks(
            u64::try_from(bits.len()).map_err(|_| Corrupt::AddressOverflow)?,
            self.blocks,
        )
    }

    #[inline(never)]
    fn allocate_inode(&mut self, start: u64, directory: bool) -> Result<u64, Error> {
        let mut bitmap = Bitmap {
            bytes: &mut self.edit.bitmaps[ondisk::BitmapKind::Inode as usize]
                .as_mut()
                .unwrap()
                .bytes,
            bits: self.inodes,
        };
        let index = bitmap
            .claim_free(start)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        self.edit
            .descriptor
            .allocate_inode(index, self.inodes_per_group, directory)?;
        Ok(index)
    }

    #[inline(never)]
    fn release_inode(&mut self, index: u64, directory: bool) -> Result<(), Error> {
        Bitmap {
            bytes: &mut self.edit.bitmaps[ondisk::BitmapKind::Inode as usize]
                .as_mut()
                .unwrap()
                .bytes,
            bits: self.inodes,
        }
        .release(index)?;
        self.edit
            .descriptor
            .release_inode(self.inodes_per_group, directory)
    }
}

struct Allocation {
    blocks: Vec<u64>,
    groups: Vec<GroupEdit>,
}

struct InodeAllocation {
    number: u32,
    index: u64,
    inode_table: u64,
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

    #[inline(never)]
    fn write_at(
        &self,
        transaction: &mut Transaction<'_, '_>,
        offset: u64,
        data: &[u8],
    ) -> Result<Option<u64>, Error> {
        if data.is_empty() {
            return Ok(None);
        }
        if !transaction.dirty.blocks.is_empty() {
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
                    return Ok(None);
                }
                Err(Error::Unsupported(Unsupported::ExtentMutation)) => {}
                Err(error) => return Err(error),
            }
        }
        transaction.extend_file(&self.inode, FileGrowth::Write { offset, data })
    }

    #[inline(never)]
    fn resize(&self, transaction: &mut Transaction<'_, '_>, new_size: u64) -> Result<(), Error> {
        if !transaction.dirty.blocks.is_empty() {
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

struct GroupBlocks {
    group: u32,
    bits: Vec<u64>,
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
pub struct Transaction<'f, 's> {
    pub(crate) filesystem: &'f mut Ext4,
    pub(crate) storage: &'s mut dyn Storage,
    dirty: BlockEdits,
    available: Vec<Vec<u8>>,
}

impl<'f, 's> Transaction<'f, 's> {
    pub(crate) fn new(filesystem: &'f mut Ext4, storage: &'s mut dyn Storage) -> Self {
        Self {
            filesystem,
            storage,
            dirty: BlockEdits::default(),
            available: Vec::new(),
        }
    }

    pub fn reserve_blocks(&mut self, additional: usize) -> Result<(), FsError> {
        let total = self
            .dirty
            .blocks
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
            .blocks
            .try_reserve(self.available.len() + additional)
            .map_err(|_| FsError::OutOfMemory)?;
        self.available
            .try_reserve(additional)
            .map_err(|_| FsError::OutOfMemory)?;
        self.available.append(&mut buffers);
        Ok(())
    }

    pub fn dirty_blocks(&self) -> usize {
        self.dirty.blocks.len()
    }

    pub fn reserved_blocks(&self) -> usize {
        self.available.len()
    }

    pub fn is_dirty(&self, number: u64) -> bool {
        self.dirty.index(number).is_ok()
    }

    pub fn commit(self) -> Result<(), Error> {
        self.filesystem
            .commit_journal(self.storage, &self.dirty.blocks)
    }

    pub fn write_block(&mut self, number: u64, src: &[u8]) -> Result<(), FsError> {
        if number >= self.filesystem.superblock.blocks_count
            || src.len() != self.filesystem.superblock.block_size as usize
        {
            return Err(FsError::InvalidArgument);
        }
        match self.dirty.index(number) {
            Ok(index) => self.dirty.blocks[index].bytes.copy_from_slice(src),
            Err(index) => {
                let bytes = self.available.pop().ok_or(FsError::ReservationExhausted)?;
                self.dirty
                    .blocks
                    .insert(index, DirtyBlock { number, bytes });
                self.dirty.blocks[index].bytes.copy_from_slice(src);
            }
        }
        Ok(())
    }
}

impl Transaction<'_, '_> {
    fn map_file_block(&mut self, inode: &Inode, logical: u64) -> Result<Option<u64>, Error> {
        self.filesystem.map_file_block(self.storage, inode, logical)
    }

    fn read_external_xattr_block(&mut self, inode: &Inode) -> Result<Vec<u8>, Error> {
        self.filesystem
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
        if !self.dirty.blocks.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if update == InodeMetadataUpdate::default() {
            return Ok(());
        }
        let inode = self.filesystem.refresh(self.storage, inode)?;
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        let mut metadata = MetadataMutation::default();
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
        if !self.dirty.blocks.is_empty() {
            return Err(Error::ReservationExhausted);
        }
        let file = FileEditor::new(self.filesystem.refresh(self.storage, inode)?)?;
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
        let inode = self.filesystem.refresh(self.storage, inode)?;
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
        let block_size = u64::from(self.filesystem.superblock.block_size);
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
        let tree = self.read_extent_tree(inode)?;
        let mut copied = 0usize;
        for logical in first..=last {
            let physical = u32::try_from(logical)
                .ok()
                .and_then(|logical| tree.lookup(logical))
                .filter(|(_, state)| *state == ExtentState::Written)
                .map(|(physical, _)| physical)
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
        let file = FileEditor::new(self.filesystem.refresh(self.storage, inode)?)?;
        if file.inode.size != 0 || file.inode.blocks_512 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        let zero = self.zero_block()?;
        file.write_at(self, 0, &zero)?
            .ok_or(Corrupt::InvalidExtentTree.into())
    }

    /// Fill an empty extent-formatted file with an arbitrary multi-block value.
    pub fn initialize_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error> {
        let file = FileEditor::new(self.filesystem.refresh(self.storage, inode)?)?;
        if file.inode.size != 0 || file.inode.blocks_512 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        file.write_at(self, 0, data).map(|_| ())
    }

    /// Append bytes using the general file editor.
    pub fn append_inode(&mut self, inode: &Inode, data: &[u8]) -> Result<(), Error> {
        let file = FileEditor::new(self.filesystem.refresh(self.storage, inode)?)?;
        file.write_at(self, file.inode.size, data).map(|_| ())
    }

    #[inline(never)]
    fn extend_file(&mut self, inode: &Inode, growth: FileGrowth<'_>) -> Result<Option<u64>, Error> {
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
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let new_blocks = new_size.div_ceil(block_size);
        if new_blocks > (1_u64 << 32) {
            return Err(Unsupported::ExtentMutation.into());
        }
        let (mut tree, existing, _) = self.read_owned_extent_tree(inode)?;

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

        let mut metadata = MetadataMutation::default();
        self.apply_resources(&mut metadata, ResourceUpdate::Allocate(allocation))?;
        for payload in payloads {
            metadata.adopt(payload.number, payload.bytes)?;
        }
        self.stage_extent_tree(&mut metadata, inode, &tree, new_size)?;
        metadata.stage(self)?;
        Ok(first_allocated)
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
        if !self.dirty.blocks.is_empty() || self.available.len() < kind.required_blocks() {
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

        let parent = self.filesystem.refresh(self.storage, parent)?;
        if matches!(kind, CreateKind::Directory)
            && (!parent.is_directory() || parent.links == u16::MAX)
        {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let mut parent_tree = DirectoryTree::load(self, &parent)?;

        let mut allocation = self.allocate_inode(matches!(kind, CreateKind::Directory))?;
        let inode_number = allocation.number;
        let directory_block_number = if matches!(kind, CreateKind::Directory) {
            self.extend_allocation(&mut allocation.resources, 1)?;
            Some(allocation.resources.blocks[0])
        } else {
            None
        };
        let (inode_block_number, inode_offset) =
            self.inode_table_location(allocation.inode_table, allocation.index)?;
        let inode_size = usize::from(self.filesystem.superblock.inode_size);

        let growth = self.insert_into_directory(
            &mut parent_tree,
            &mut allocation.resources,
            inode_number,
            name,
            kind.file_type(),
        )?;
        let mut metadata = MetadataMutation::default();
        metadata.adopt(
            inode_block_number,
            self.read_owned_block(inode_block_number)?,
        )?;
        let raw_inode =
            &mut metadata.get_mut(inode_block_number)?[inode_offset..inode_offset + inode_size];
        let mut record = InodeRecord::new(
            raw_inode,
            self.filesystem.superblock.checksum_seed,
            inode_number,
        )?;
        match kind {
            CreateKind::Regular => record.initialize_regular(permissions),
            CreateKind::Symlink(target) => record.initialize_fast_symlink(target)?,
            CreateKind::Directory => record.initialize_directory(
                permissions,
                directory_block_number.unwrap(),
                block_size,
            )?,
        }
        record.finish();

        if matches!(kind, CreateKind::Directory) {
            metadata.set_inode_links(self, &parent, parent.links + 1)?;
        }
        self.apply_directory_insertion(&mut metadata, allocation.resources, growth)?;
        if let Some(number) = directory_block_number {
            let block = DirectoryBlock::initialize(
                self.filesystem.superblock.checksum_seed,
                inode_number,
                0,
                0,
                Some(parent.number),
                self.zero_block()?,
            )?
            .bytes;
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
        if !self.dirty.blocks.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }

        let inode = self.filesystem.refresh(self.storage, inode)?;
        if inode.is_directory() || inode.links == u16::MAX {
            return Err(Error::InvalidArgument);
        }
        let file_type = match inode.mode & 0xf000 {
            0x8000 => 1,
            0xa000 => 7,
            _ => return Err(Unsupported::MutationProfile.into()),
        };
        let parent = self.filesystem.refresh(self.storage, parent)?;
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
        let mut metadata = MetadataMutation::default();
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
        if !self.dirty.blocks.is_empty() {
            return Err(Error::ReservationExhausted);
        }

        if entry.name.is_empty() || entry.name == b"." || entry.name == b".." {
            return Err(Error::InvalidArgument);
        }
        let directory = self.filesystem.refresh(self.storage, directory)?;
        let inode = self.filesystem.refresh(self.storage, &entry.inode)?;
        let block_size = u64::from(self.filesystem.superblock.block_size);
        if !directory.is_directory()
            || inode.links == 0
            || !matches!(inode.mode & 0xf000, 0x8000 | 0xa000)
        {
            return Err(Unsupported::MutationProfile.into());
        }
        let mut directory_tree = DirectoryTree::load(self, &directory)?;
        directory_tree.edit_existing(
            &entry.name,
            ExistingDirectoryEdit::Remove {
                number: inode.number,
            },
        )?;
        if inode.links > 1 {
            let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
            let superblock = self.read_owned_block(superblock_number)?;
            let mut metadata = MetadataMutation::default();
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
        if !self.dirty.blocks.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
            return Err(Error::ReservationExhausted);
        }
        if entry.name.is_empty() || entry.name == b"." || entry.name == b".." {
            return Err(Error::InvalidArgument);
        }
        let parent = self.filesystem.refresh(self.storage, parent)?;
        let directory = self.filesystem.refresh(self.storage, &entry.inode)?;
        if !parent.is_directory() || parent.links == 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        let mut parent_tree = DirectoryTree::load(self, &parent)?;
        let release = self.prepare_empty_directory_release(&directory, parent.number)?;
        parent_tree.edit_existing(
            &entry.name,
            ExistingDirectoryEdit::Remove {
                number: directory.number,
            },
        )?;
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
        if !self.dirty.blocks.is_empty() || self.available.len() < REQUIRED_DIRTY_BLOCKS {
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

        let old_parent = self.filesystem.refresh(self.storage, old_parent)?;
        let source_inode = self.filesystem.refresh(self.storage, &source.inode)?;
        let new_parent = self.filesystem.refresh(self.storage, new_parent)?;
        let destination = match destination {
            Some(destination) if destination.inode.number == source_inode.number => return Ok(()),
            Some(destination) => Some(self.filesystem.refresh(self.storage, &destination.inode)?),
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
        let mut metadata = MetadataMutation::default();

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
            target.edit_existing(
                new_name,
                ExistingDirectoryEdit::Replace {
                    old: destination.number,
                    new: source_inode.number,
                    kind: file_type,
                },
            )?;
            old_tree.edit_existing(
                &source.name,
                ExistingDirectoryEdit::Remove {
                    number: source_inode.number,
                },
            )?;
        } else {
            old_tree.edit_existing(
                &source.name,
                ExistingDirectoryEdit::Remove {
                    number: source_inode.number,
                },
            )?;
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
        let file = FileEditor::new(self.filesystem.refresh(self.storage, inode)?)?;
        file.resize(self, new_size)
    }

    /// Release checked initialized extents and reduce a regular file to size 0.
    pub fn truncate_inode(&mut self, inode: &Inode) -> Result<u64, Error> {
        let inode = self.filesystem.refresh(self.storage, inode)?;
        if inode.size == 0 && inode.blocks_512 == 0 {
            return Ok(0);
        }
        self.shrink_file(&inode, 0)
    }

    fn shrink_file(&mut self, inode: &Inode, new_size: u64) -> Result<u64, Error> {
        self.validate_mutation_profile()?;
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let old_blocks = inode.size.div_ceil(block_size);
        let kept_blocks = new_size.div_ceil(block_size);
        if new_size >= inode.size || kept_blocks > old_blocks {
            return Err(Error::InvalidArgument);
        }

        let (mut tree, _, _) = self.read_owned_extent_tree(inode)?;
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

        let mut metadata = MetadataMutation::default();
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

        self.stage_extent_tree(&mut metadata, inode, &tree, new_size)?;
        metadata.stage(self)?;
        Ok(released_blocks)
    }

    /// Read one filesystem block through this transaction's private view.
    pub fn read_block(&mut self, number: u64, dst: &mut [u8]) -> Result<(), Error> {
        if number >= self.filesystem.superblock.blocks_count
            || dst.len() != self.filesystem.superblock.block_size as usize
        {
            return Err(Error::InvalidArgument);
        }
        match self.dirty_index(number) {
            Ok(index) => dst.copy_from_slice(&self.dirty.blocks[index].bytes),
            Err(_) => {
                let offset = self.block_offset(number)?;
                self.filesystem.read_storage(self.storage, offset, dst)?;
            }
        }
        Ok(())
    }

    /// Load and mutate one complete block, preserving its private version.
    pub fn modify_block<F>(&mut self, number: u64, modify: F) -> Result<(), Error>
    where
        F: FnOnce(&mut [u8]),
    {
        if number >= self.filesystem.superblock.blocks_count {
            return Err(Error::InvalidArgument);
        }
        let index = match self.dirty_index(number) {
            Ok(index) => index,
            Err(index) => {
                let mut bytes = self.available.pop().ok_or(Error::ReservationExhausted)?;
                let offset = self.block_offset(number)?;
                if let Err(error) = self
                    .filesystem
                    .read_storage(self.storage, offset, &mut bytes)
                {
                    self.available.push(bytes);
                    return Err(error);
                }
                self.dirty
                    .blocks
                    .insert(index, DirtyBlock { number, bytes });
                index
            }
        };
        modify(&mut self.dirty.blocks[index].bytes);
        Ok(())
    }

    fn dirty_index(&self, number: u64) -> Result<usize, usize> {
        self.dirty.index(number)
    }

    fn adopt_dirty(&mut self, mut block: DirtyBlock) -> Result<(), Error> {
        if block.number >= self.filesystem.superblock.blocks_count
            || block.bytes.len() != self.filesystem.superblock.block_size as usize
        {
            return Err(Error::InvalidArgument);
        }
        match self.dirty_index(block.number) {
            Ok(index) => core::mem::swap(&mut self.dirty.blocks[index].bytes, &mut block.bytes),
            Err(index) => {
                let _reserved = self.available.pop().ok_or(Error::ReservationExhausted)?;
                self.dirty.blocks.insert(index, block);
            }
        }
        Ok(())
    }

    fn block_offset(&self, number: u64) -> Result<u64, Error> {
        number
            .checked_mul(u64::from(self.filesystem.superblock.block_size))
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

    #[inline(never)]
    fn grow_linear_directory(
        &mut self,
        tree: &mut DirectoryTree,
        resources: &mut Allocation,
    ) -> Result<DirectoryGrowth, Error> {
        if tree.inode.flags & super::DIRECTORY_INDEX_FL != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let mut extent_tree = self.read_extent_tree(&tree.inode)?;
        if extent_tree
            .data_extents()?
            .last()
            .is_some_and(|extent| extent.logical_end() > tree.nodes.len() as u64)
            || tree.nodes.iter().any(|node| {
                u32::try_from(node.block.logical)
                    .ok()
                    .and_then(|logical| extent_tree.lookup(logical))
                    != Some((node.number, ExtentState::Written))
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

        let block = DirectoryBlock::initialize(
            self.filesystem.superblock.checksum_seed,
            tree.inode.number,
            tree.inode.generation,
            u64::from(logical),
            None,
            self.zero_block()?,
        )?;
        tree.nodes.push(DirectoryNode {
            number: leaf_number,
            block,
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
            self.stage_extent_tree(metadata, &growth.inode, &growth.tree, growth.size)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn stage_extent_tree(
        &mut self,
        metadata: &mut MetadataMutation,
        inode: &Inode,
        tree: &ExtentTree,
        size: u64,
    ) -> Result<(), Error> {
        let (block_number, offset) = self.inode_location(inode.number)?;
        let inode_size = usize::from(self.filesystem.superblock.inode_size);
        let checksum_seed = self.filesystem.superblock.checksum_seed;
        let block_size = u64::from(self.filesystem.superblock.block_size);
        metadata.load(self, block_number)?;
        let block = metadata.get_mut(block_number)?;
        let end = offset
            .checked_add(inode_size)
            .filter(|end| *end <= block.len())
            .ok_or(Corrupt::InvalidInodeTable)?;
        let raw = &mut block[offset..end];
        let mut record = InodeRecord::for_update(raw, checksum_seed, inode)?;
        let extent_nodes = set_extent_tree(
            &mut record,
            tree,
            size,
            block_size,
            self.filesystem.superblock.has_metadata_checksums(),
            u64::from(inode.external_xattr_block != 0),
        )?;
        record.finish();
        metadata.adopt_blocks(extent_nodes)
    }

    #[inline(never)]
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
        let inode_changed = groups
            .iter()
            .any(|group| group.bitmaps[ondisk::BitmapKind::Inode as usize].is_some());
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let superblock_number = ondisk::SUPERBLOCK_OFFSET / block_size;
        metadata.load(self, superblock_number)?;
        if blocks != 0 || inode_changed {
            let superblock_offset = usize::try_from(ondisk::SUPERBLOCK_OFFSET % block_size)
                .map_err(|_| Corrupt::AddressOverflow)?;
            let raw = &mut metadata.get_mut(superblock_number)?
                [superblock_offset..superblock_offset + ondisk::SUPERBLOCK_SIZE];
            self.filesystem.superblock.update_free_counts(
                raw,
                blocks,
                inode_changed,
                allocating,
            )?;
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
    ) -> Result<BlockGroup, Error> {
        let edit = match existing {
            Some(edit) if edit.descriptor.group == number => edit,
            Some(_) => return Err(Corrupt::InvalidGroup(number).into()),
            None => GroupEdit {
                descriptor: self
                    .filesystem
                    .read_group_descriptor(self.storage, number)?,
                bitmaps: [None, None],
            },
        };
        let superblock = &self.filesystem.superblock;
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
        let bitmap_numbers = [
            edit.descriptor.bitmap(ondisk::BitmapKind::Block),
            edit.descriptor.bitmap(ondisk::BitmapKind::Inode),
        ];
        for index in 0..2 {
            if bitmap_numbers[index] >= superblock.blocks_count
                || edit.bitmaps[index]
                    .as_ref()
                    .is_some_and(|bitmap| bitmap.number != bitmap_numbers[index])
            {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
        }
        Ok(BlockGroup {
            edit,
            start,
            blocks,
            first_inode,
            inodes,
            inodes_per_group: u64::from(superblock.inodes_per_group),
            bitmap_numbers,
        })
    }

    fn load_group_bitmap(
        &mut self,
        group: &mut BlockGroup,
        kind: ondisk::BitmapKind,
        allow_initialize: bool,
    ) -> Result<(), Error> {
        let index = kind as usize;
        if group.edit.bitmaps[index].is_some() {
            return Ok(());
        }
        let flag = match kind {
            ondisk::BitmapKind::Block => 0x0002,
            ondisk::BitmapKind::Inode => 0x0001,
        };
        let bitmap = if group.edit.descriptor.flags() & flag == 0 {
            let bitmap = self.read_owned_block(group.bitmap_numbers[index])?;
            self.verify_bitmap_checksum(
                kind,
                group.edit.descriptor.group,
                &group.edit.descriptor,
                &bitmap,
            )?;
            bitmap
        } else {
            if !allow_initialize || group.edit.descriptor.group == 0 {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let bitmap = match kind {
                ondisk::BitmapKind::Block => {
                    let (bitmap, free) = self.initialize_block_bitmap(
                        group.edit.descriptor.group,
                        &group.edit.descriptor,
                        group.start,
                        group.blocks,
                    )?;
                    if free != group.edit.descriptor.free_blocks() {
                        return Err(Corrupt::InvalidFreeBlockCount.into());
                    }
                    bitmap
                }
                ondisk::BitmapKind::Inode => {
                    if group.edit.descriptor.free_inodes() != group.inodes
                        || group.edit.descriptor.flags() & 0x0004 == 0
                    {
                        return Err(Corrupt::InvalidBlockBitmap.into());
                    }
                    let mut bitmap = self.zero_block()?;
                    let bits = u64::try_from(bitmap.len())
                        .map_err(|_| Corrupt::AddressOverflow)?
                        .checked_mul(8)
                        .ok_or(Corrupt::AddressOverflow)?;
                    set_bitmap_range(&mut bitmap, group.inodes, bits - group.inodes)?;
                    bitmap
                }
            };
            group.edit.descriptor.clear_flag(flag);
            bitmap
        };
        group.edit.bitmaps[index] = Some(DirtyBlock {
            number: group.bitmap_numbers[index],
            bytes: bitmap,
        });
        Ok(())
    }

    fn finish_group(&self, mut group: BlockGroup) -> GroupEdit {
        for kind in [ondisk::BitmapKind::Block, ondisk::BitmapKind::Inode] {
            if let Some(bitmap) = &group.edit.bitmaps[kind as usize] {
                let checksum = self.bitmap_checksum(kind, &bitmap.bytes);
                group.edit.descriptor.set_bitmap_checksum(kind, checksum);
            }
        }
        group.edit.descriptor.finish(&self.filesystem.superblock);
        group.edit
    }

    /// Add blocks to an allocation while preserving its prospective bitmap
    /// edits. This lets callers allocate data first, inspect its extent shape,
    /// and then request exactly the tree metadata that shape requires.
    #[inline(never)]
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
            .try_reserve_exact(self.filesystem.superblock.group_count() as usize)
            .map_err(|_| Error::OutOfMemory)?;
        let group_count = self.filesystem.superblock.group_count();
        let mut group_order = Vec::new();
        group_order
            .try_reserve_exact(group_count as usize)
            .map_err(|_| Error::OutOfMemory)?;
        for edit in &allocation.groups {
            group_order.push(edit.descriptor.group);
        }
        for group in 0..group_count {
            if allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.descriptor.group)
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
                .binary_search_by_key(&group, |edit| edit.descriptor.group);
            let had_existing = existing.is_ok();
            let edit = existing
                .ok()
                .map(|position| allocation.groups.remove(position));
            let mut editor = self.open_group(group, edit)?;
            self.load_group_bitmap(&mut editor, ondisk::BitmapKind::Block, true)?;
            let free = editor.edit.descriptor.free_blocks();
            if free == 0 {
                if had_existing {
                    let position = allocation
                        .groups
                        .binary_search_by_key(&group, |edit| edit.descriptor.group)
                        .unwrap_or_else(|position| position);
                    let edit = self.finish_group(editor);
                    allocation.groups.insert(position, edit);
                }
                continue;
            }
            let count =
                editor.allocate_blocks(target - allocation.blocks.len(), &mut allocation.blocks)?;
            if count == 0 {
                continue;
            }
            let position = allocation
                .groups
                .binary_search_by_key(&group, |edit| edit.descriptor.group)
                .unwrap_or_else(|position| position);
            let edit = self.finish_group(editor);
            allocation.groups.insert(position, edit);
        }
        if allocation.blocks.len() != target {
            return Err(Corrupt::InvalidFreeBlockCount.into());
        }
        Ok(())
    }

    #[inline(never)]
    fn initialize_block_bitmap(
        &self,
        group: u32,
        descriptor: &ondisk::GroupDescriptor,
        group_start: u64,
        group_blocks: u64,
    ) -> Result<(Vec<u8>, u64), Error> {
        let superblock = &self.filesystem.superblock;
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
        let block_bitmap = descriptor.bitmap(ondisk::BitmapKind::Block);
        let inode_bitmap = descriptor.bitmap(ondisk::BitmapKind::Inode);
        let inode_table = descriptor.inode_table();
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

    #[inline(never)]
    fn allocate_inode(&mut self, directory: bool) -> Result<InodeAllocation, Error> {
        let group_count = self.filesystem.superblock.group_count();
        let first_inode = u64::from(self.filesystem.superblock.first_inode);
        for group_number in 0..group_count {
            let mut editor = self.open_group(group_number, None)?;
            if editor.inodes == 0 {
                break;
            }
            let free = editor.edit.descriptor.free_inodes();
            if free == 0 {
                continue;
            }
            if free > editor.inodes {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            }

            if editor.edit.descriptor.flags() & 0x0002 != 0 {
                self.load_group_bitmap(&mut editor, ondisk::BitmapKind::Block, true)?;
            }

            let inode_table = editor.edit.descriptor.inode_table();
            if inode_table >= self.filesystem.superblock.blocks_count {
                return Err(Corrupt::InvalidInodeTable.into());
            }
            self.load_group_bitmap(&mut editor, ondisk::BitmapKind::Inode, true)?;
            let start = if group_number == 0 {
                first_inode - 1
            } else {
                0
            };
            let index = editor.allocate_inode(start, directory)?;
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
                resources: Allocation {
                    blocks: Vec::new(),
                    groups: alloc::vec![edit],
                },
            });
        }
        Err(Corrupt::InvalidFreeBlockCount.into())
    }

    fn release_inode_root_blocks(&mut self, inode: &Inode) -> Result<ReleasedInodeBlocks, Error> {
        let (_, extents, tree_blocks) = self.read_owned_extent_tree(inode)?;
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
                    self.filesystem.superblock.checksum_seed,
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
        Ok(ReleasedInodeBlocks {
            resources,
            retained_xattr_block,
        })
    }

    #[inline(never)]
    fn release_blocks(&mut self, ranges: &[(u64, u64)]) -> Result<ResourceRelease, Error> {
        let mut releases: Vec<GroupBlocks> = Vec::new();
        releases
            .try_reserve_exact(ranges.len())
            .map_err(|_| Error::OutOfMemory)?;
        let mut released = 0u64;
        let first_data = u64::from(self.filesystem.superblock.first_data_block);
        let blocks_per_group = u64::from(self.filesystem.superblock.blocks_per_group);
        for &(physical, length) in ranges {
            released = released
                .checked_add(length)
                .ok_or(Corrupt::AddressOverflow)?;
            let end = physical
                .checked_add(length)
                .filter(|end| *end <= self.filesystem.superblock.blocks_count)
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
                let bit = number - group_start;
                let position = match releases.binary_search_by_key(&group, |entry| entry.group) {
                    Ok(position) => position,
                    Err(position) => {
                        releases.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                        releases.insert(
                            position,
                            GroupBlocks {
                                group,
                                bits: Vec::new(),
                            },
                        );
                        position
                    }
                };
                if releases[position].bits.contains(&bit) {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                releases[position]
                    .bits
                    .try_reserve(1)
                    .map_err(|_| Error::OutOfMemory)?;
                releases[position].bits.push(bit);
            }
        }

        let mut groups = Vec::new();
        groups
            .try_reserve_exact(releases.len())
            .map_err(|_| Error::OutOfMemory)?;
        for release in releases {
            let mut group = self.open_group(release.group, None)?;
            let reserved = self
                .initialize_block_bitmap(
                    release.group,
                    &group.edit.descriptor,
                    group.start,
                    group.blocks,
                )?
                .0;
            self.load_group_bitmap(&mut group, ondisk::BitmapKind::Block, false)?;
            group.release_blocks(&release.bits, &reserved)?;
            groups.push(self.finish_group(group));
        }
        Ok(ResourceRelease {
            blocks: released,
            groups,
        })
    }
    fn read_extent_tree(&mut self, inode: &Inode) -> Result<ExtentTree, Error> {
        let block_size = self.filesystem.superblock.block_size as usize;
        let identity = ExtentIdentity {
            checksum_seed: self.filesystem.superblock.checksum_seed,
            inode: inode.number,
            generation: inode.generation,
            metadata_checksums: self.filesystem.superblock.has_metadata_checksums(),
        };
        ExtentTree::load(
            &inode.block_map,
            block_size,
            self.filesystem.superblock.blocks_count,
            identity,
            &mut |number| self.read_owned_block(number),
        )
    }

    fn read_owned_extent_tree(
        &mut self,
        inode: &Inode,
    ) -> Result<(ExtentTree, Vec<Extent>, Vec<u64>), Error> {
        let tree = self.read_extent_tree(inode)?;
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let extents = tree.data_extents()?;
        if extents
            .last()
            .is_some_and(|extent| extent.logical_end() > inode.size.div_ceil(block_size))
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let tree_blocks = tree.external_blocks()?;
        let owned_blocks = extents.iter().try_fold(
            u64::try_from(tree_blocks.len()).map_err(|_| Corrupt::AddressOverflow)?,
            |total, extent| {
                total
                    .checked_add(u64::from(extent.length))
                    .ok_or(Corrupt::AddressOverflow)
            },
        )?;
        let sectors = owned_blocks
            .checked_add(u64::from(inode.external_xattr_block != 0))
            .and_then(|blocks| blocks.checked_mul(block_size / 512))
            .ok_or(Corrupt::AddressOverflow)?;
        if inode.blocks_512 != sectors {
            return Err(Unsupported::ExtentMutation.into());
        }
        Ok((tree, extents, tree_blocks))
    }

    #[inline(never)]
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
        let inode_group = zero_based / self.filesystem.superblock.inodes_per_group;
        let inode_index = u64::from(zero_based % self.filesystem.superblock.inodes_per_group);
        let (position, existing) = match resources
            .groups
            .binary_search_by_key(&inode_group, |group| group.descriptor.group)
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
        let mut group = self.open_group(inode_group, existing)?;
        let inode_table = group.edit.descriptor.inode_table();
        if inode_table >= self.filesystem.superblock.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }

        let (inode_block_number, inode_offset) =
            self.inode_table_location(inode_table, inode_index)?;
        let inode_size = usize::from(self.filesystem.superblock.inode_size);
        let mut inode_block = self.read_owned_block(inode_block_number)?;
        inode_block[inode_offset..inode_offset + inode_size].fill(0);
        self.load_group_bitmap(&mut group, ondisk::BitmapKind::Inode, false)?;
        group.release_inode(inode_index, matches!(kind, ReleaseKind::Directory))?;
        let edit = self.finish_group(group);
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
        let mut metadata = MetadataMutation::default();
        metadata.adopt(superblock.number, superblock.bytes)?;
        metadata.adopt_blocks(data)?;
        metadata.stage(self)
    }

    fn stage_inode_release(
        &mut self,
        release: PreparedInodeRelease,
        namespace: Vec<DirtyBlock>,
    ) -> Result<(), Error> {
        let mut metadata = MetadataMutation::default();
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
        let mut metadata = MetadataMutation::default();
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
        metadata.adopt(release.inode_block.number, release.inode_block.bytes)?;
        if let Some(block) = release.retained_xattr_block {
            metadata.adopt(block.number, block.bytes)?;
        }
        Ok(())
    }

    fn descriptor_blocks(&mut self, groups: &[GroupEdit]) -> Result<Vec<DirtyBlock>, Error> {
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let descriptor_size = u64::from(self.filesystem.superblock.descriptor_size);
        let table = self.filesystem.superblock.descriptor_table_offset();
        let mut blocks: Vec<DirtyBlock> = Vec::new();
        blocks
            .try_reserve_exact(groups.len())
            .map_err(|_| Error::OutOfMemory)?;
        for group in groups {
            let byte = table
                .checked_add(u64::from(group.descriptor.group) * descriptor_size)
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
                .checked_add(group.descriptor.bytes().len())
                .filter(|end| *end <= blocks[index].bytes.len())
                .ok_or(Corrupt::InvalidGroup(group.descriptor.group))?;
            blocks[index].bytes[offset..end].copy_from_slice(group.descriptor.bytes());
        }
        Ok(blocks)
    }

    fn inode_location(&mut self, number: u32) -> Result<(u64, usize), Error> {
        let zero_based = number
            .checked_sub(1)
            .filter(|number| *number < self.filesystem.superblock.inodes_count)
            .ok_or(Corrupt::InvalidInode(number))?;
        let group = zero_based / self.filesystem.superblock.inodes_per_group;
        let index = u64::from(zero_based % self.filesystem.superblock.inodes_per_group);
        let descriptor = self.filesystem.read_group_descriptor(self.storage, group)?;
        let table = descriptor.inode_table();
        self.inode_table_location(table, index)
    }

    fn inode_table_location(&self, table: u64, index: u64) -> Result<(u64, usize), Error> {
        let block_size = u64::from(self.filesystem.superblock.block_size);
        let byte = table
            .checked_mul(block_size)
            .and_then(|offset| {
                offset.checked_add(index * u64::from(self.filesystem.superblock.inode_size))
            })
            .ok_or(Corrupt::AddressOverflow)?;
        let block = byte / block_size;
        let offset = usize::try_from(byte % block_size).map_err(|_| Corrupt::AddressOverflow)?;
        if block >= self.filesystem.superblock.blocks_count
            || offset + usize::from(self.filesystem.superblock.inode_size) > block_size as usize
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
        for _ in 0..self.filesystem.superblock.inodes_count {
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
            current = self.filesystem.load_inode(self.storage, parent_number)?;
            if !current.is_directory() {
                return Err(Corrupt::InvalidDirectory.into());
            }
        }
        Err(Corrupt::InvalidDirectory.into())
    }

    fn directory_parent_number(&mut self, directory: &Inode) -> Result<u32, Error> {
        let block_size = usize::try_from(self.filesystem.superblock.block_size)
            .map_err(|_| Corrupt::AddressOverflow)?;
        if !directory.is_directory() || directory.size < block_size as u64 {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let number = self
            .map_file_block(directory, 0)?
            .ok_or(Corrupt::InvalidDirectory)?;
        let block = self.read_owned_block(number)?;
        DirectoryBlock::new(
            self.filesystem.superblock.checksum_seed,
            self.filesystem.superblock.has_metadata_checksums(),
            directory,
            0,
            block,
        )?
        .parent()
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
        let superblock = &self.filesystem.superblock;
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
        let mut block = self.filesystem.new_block_buffer()?;
        self.read_block(number, &mut block)?;
        Ok(block)
    }

    fn zero_block(&self) -> Result<Vec<u8>, Error> {
        self.filesystem.new_block_buffer()
    }

    fn bitmap_checksum(&self, kind: ondisk::BitmapKind, bitmap: &[u8]) -> u32 {
        let bits = match kind {
            ondisk::BitmapKind::Block => self.filesystem.superblock.blocks_per_group,
            ondisk::BitmapKind::Inode => self.filesystem.superblock.inodes_per_group,
        };
        let bytes = usize::try_from(bits.div_ceil(8))
            .unwrap_or(bitmap.len())
            .min(bitmap.len());
        let mut checksum = Checksum::with_seed(self.filesystem.superblock.checksum_seed);
        checksum.update(&bitmap[..bytes]);
        checksum.finalize()
    }

    fn verify_bitmap_checksum(
        &self,
        kind: ondisk::BitmapKind,
        group: u32,
        descriptor: &ondisk::GroupDescriptor,
        bitmap: &[u8],
    ) -> Result<(), Error> {
        if self.bitmap_checksum(kind, bitmap) != descriptor.bitmap_checksum(kind) {
            return Err(match kind {
                ondisk::BitmapKind::Block => Corrupt::BlockBitmapChecksum(group),
                ondisk::BitmapKind::Inode => Corrupt::InodeBitmapChecksum(group),
            }
            .into());
        }
        Ok(())
    }
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
