//! Byte-exact structures used by the ext4 on-disk format.
//!
//! Their integer fields are byte arrays, so every fixed record has alignment
//! one and exactly the byte representation stored on disk.  Algorithms read
//! and write these records directly, then validate their members before use;
//! there is no second offset-based codec for the same layout.
//!
//! Records whose size is selected by filesystem metadata are represented as a
//! fixed prefix followed by an explicit byte tail.  In particular, inode size
//! comes from `Superblock::inode_size`, group-descriptor size comes from
//! `Superblock::desc_size`, and directory/xattr records contain trailing data.

use alloc::vec::Vec;
use bytemuck::{Pod, Zeroable};
use core::mem::size_of;

use crate::{Corrupt, Error, Storage, Unsupported};

pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
pub const INODE_BASE_SIZE: usize = 128;
pub const GROUP_DESCRIPTOR32_SIZE: usize = 32;
pub const GROUP_DESCRIPTOR64_SIZE: usize = 64;
pub(crate) const SUPERBLOCK_MAGIC: u16 = 0xef53;
pub const EXTENT_MAGIC: u16 = 0xf30a;
pub const XATTR_MAGIC: u32 = 0xea02_0000;

const ROOT_INODE: u32 = 2;
const MODE_TYPE: u16 = 0xf000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_SYMLINK: u16 = 0xa000;
const EXTENTS: u32 = 0x0008_0000;
const INDEXED_NODE: u32 = 0x0000_1000;
const INLINE_DATA: u32 = 0x1000_0000;
const XATTR_INDEX_SYSTEM: u8 = 7;
const INLINE_XATTR_NAME: &[u8] = b"data";
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const GROUP_INODE_UNINIT: u16 = 0x0001;
const GROUP_BLOCK_UNINIT: u16 = 0x0002;
const GROUP_INODE_ZEROED: u16 = 0x0004;
const COMPAT_SPARSE_SUPER2: u32 = 0x0200;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;

macro_rules! little_endian {
    ($name:ident, $native:ty, $size:expr) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
        pub(crate) struct $name(pub [u8; $size]);

        impl $name {
            pub const fn new(value: $native) -> Self {
                Self(value.to_le_bytes())
            }

            pub const fn get(self) -> $native {
                <$native>::from_le_bytes(self.0)
            }
        }

        impl From<$native> for $name {
            fn from(value: $native) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $native {
            fn from(value: $name) -> Self {
                value.get()
            }
        }
    };
}

little_endian!(Le16, u16, 2);
little_endian!(Le32, u32, 4);
little_endian!(Le64, u64, 8);

impl Le16 {
    fn set(&mut self, value: u16) {
        self.0 = value.to_le_bytes();
    }
}

impl Le32 {
    fn set(&mut self, value: u32) {
        self.0 = value.to_le_bytes();
    }
}

/// Identity of a byte-bearing object.  Ext4 inode numbers remain an internal
/// encoding detail of this strongly typed handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blob(u32);

/// Identity of an object whose bytes are an ext4 labelled-edge array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Object {
    Blob(Blob),
    Node(Node),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdgeCursor(u64);

/// Stable location of one edge in a node.
///
/// Names are deliberately absent.  Listing is the only primitive which turns
/// node bytes into names; subsequent operations use this integer handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeHandle {
    node: u32,
    object: u32,
    offset: u64,
}

/// One result produced while listing a node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Edge<'a> {
    pub handle: EdgeHandle,
    pub object: Object,
    pub name: &'a [u8],
}

/// Information intrinsic to the ext4 graph, without POSIX interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectInfo {
    pub object: Object,
    pub size: u64,
    pub references: u32,
    /// Uninterpreted ext4 inode-format bits.  Policy above the graph layer may
    /// assign meanings such as a POSIX object type and permissions.
    pub format: u16,
    pub owner: u32,
    pub group: u32,
    pub accessed: u32,
    pub modified: u32,
    pub changed: u32,
}

/// Optional replacement values for vertex attributes.  Ext4 stores these
/// fields but the graph layer deliberately does not assign file semantics to
/// them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AttributeUpdate {
    pub format: Option<u16>,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    pub accessed: Option<u32>,
    pub modified: Option<u32>,
    pub changed: Option<u32>,
}

impl ObjectInfo {
    pub const fn blob(self) -> Option<Blob> {
        match self.object {
            Object::Blob(blob) => Some(blob),
            Object::Node(_) => None,
        }
    }

    pub const fn node(self) -> Option<Node> {
        match self.object {
            Object::Blob(_) => None,
            Object::Node(node) => Some(node),
        }
    }
}

/// Ownership of one inode reference which is not currently an edge.
///
/// It is deliberately neither `Copy` nor `Clone`: `attach` and `release`
/// consume precisely one owned reference.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a detached graph reference must be attached or released"]
pub struct Detached {
    object: Object,
    generation: u32,
}

impl Blob {
    pub const fn number(self) -> u32 {
        self.0
    }
}

impl Node {
    pub const fn number(self) -> u32 {
        self.0
    }
}

impl Object {
    pub const fn number(self) -> u32 {
        match self {
            Self::Blob(blob) => blob.number(),
            Self::Node(node) => node.number(),
        }
    }

    pub const fn opaque(self) -> u64 {
        let kind = match self {
            Self::Blob(_) => 1,
            Self::Node(_) => 2,
        };
        (kind << 32) | self.number() as u64
    }

    pub const fn from_opaque(value: u64) -> Option<Self> {
        let number = value as u32;
        match value >> 32 {
            1 if number != 0 => Some(Self::Blob(Blob(number))),
            2 if number != 0 => Some(Self::Node(Node(number))),
            _ => None,
        }
    }
}

impl EdgeCursor {
    pub const START: Self = Self(0);

    pub const fn from_position(position: u64) -> Self {
        Self(position)
    }

    pub const fn position(self) -> u64 {
        self.0
    }
}

impl Detached {
    pub const fn object(&self) -> Object {
        self.object
    }
}

impl EdgeHandle {
    pub const fn node(self) -> u32 {
        self.node
    }

    pub const fn object(self) -> u32 {
        self.object
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }
}

/// Feature words retained verbatim because they determine how every other
/// on-disk structure is interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Features {
    pub compatible: u32,
    pub incompatible: u32,
    pub read_only_compatible: u32,
}

/// Mounted ext4 data-structure graph.
///
/// This is the state required to locate and validate structures after mount.
/// It contains no path cache, POSIX policy, journal, or owned storage.  A RAM
/// overlay can therefore be supplied as ordinary storage for writable use.
pub struct Ext4 {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub reserved_blocks: u64,
    pub free_blocks: u64,
    pub free_inodes: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub cluster_size: u32,
    pub blocks_per_group: u32,
    pub clusters_per_group: u32,
    pub inodes_per_group: u32,
    pub groups_count: u32,
    pub first_inode: u32,
    pub inode_size: u16,
    pub descriptor_size: u16,
    pub descriptors_per_block: u32,
    pub creator_os: u32,
    pub(crate) features: Features,
    pub uuid: [u8; 16],
    pub checksum_seed: u32,
    pub reserved_gdt_blocks: u16,
    pub first_meta_block_group: u32,
    pub backup_block_groups: [u32; 2],
    pub directory_hash_seed: [u32; 4],
    pub default_directory_hash: u8,
    pub log_groups_per_flex: u8,
    journal_inode: u32,
    needs_recovery: bool,
}

#[derive(Clone, Copy)]
struct Inode {
    number: u32,
    mode: u16,
    size: u64,
    references: u16,
    blocks_512: u64,
    flags: u32,
    generation: u32,
    block: [u8; 60],
    owner: u32,
    group: u32,
    accessed: u32,
    modified: u32,
    changed: u32,
}

impl Inode {
    fn object(self) -> Object {
        if self.mode & MODE_TYPE == MODE_DIRECTORY {
            Object::Node(Node(self.number))
        } else {
            Object::Blob(Blob(self.number))
        }
    }

    fn is_fast_blob(self) -> bool {
        self.mode & MODE_TYPE == MODE_SYMLINK
            && self.size <= 60
            && self.blocks_512 == 0
            && self.flags & (EXTENTS | INLINE_DATA) == 0
    }

    fn has_inline_bytes(self) -> bool {
        self.is_fast_blob() || self.flags & INLINE_DATA != 0
    }
}

impl Extent {
    fn logical(&self) -> u64 {
        u64::from(self.logical_block.get())
    }

    fn blocks(&self) -> u32 {
        let encoded = self.length.get();
        u32::from(if encoded > 0x8000 {
            encoded - 0x8000
        } else {
            encoded
        })
    }

    fn physical(&self) -> u64 {
        u64::from(self.physical_start_lo.get()) | (u64::from(self.physical_start_hi.get()) << 32)
    }

    fn end(&self) -> u64 {
        self.logical() + u64::from(self.blocks())
    }

    fn set_blocks(&mut self, blocks: u32) -> Result<(), Error> {
        let unwritten = self.length.get() > 0x8000;
        if blocks == 0 || blocks > 0x8000 || unwritten && blocks == 0x8000 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        self.length
            .set(blocks as u16 + if unwritten { 0x8000 } else { 0 });
        Ok(())
    }

    fn is_unwritten(&self) -> bool {
        self.length.get() > 0x8000
    }

    fn append(&mut self, right: Self) -> bool {
        let blocks = self.blocks();
        let merged = self.is_unwritten() == right.is_unwritten()
            && self.end() == right.logical()
            && self.physical() + u64::from(blocks) == right.physical()
            && blocks + right.blocks() <= if self.is_unwritten() { 0x7fff } else { 0x8000 };
        merged && self.set_blocks(blocks + right.blocks()).is_ok()
    }
}

impl ExtentIndex {
    fn logical(&self) -> u32 {
        self.logical_block.get()
    }

    fn block(&self) -> u64 {
        u64::from(self.child_lo.get()) | (u64::from(self.child_hi.get()) << 32)
    }

    fn from_child(logical: u32, block: u64) -> Result<Self, Error> {
        if block == 0 || block >> 48 != 0 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let mut index = Self::zeroed();
        index.logical_block.set(logical);
        index.child_lo.set(block as u32);
        index.child_hi.set((block >> 32) as u16);
        Ok(index)
    }
}

#[derive(Clone, Copy)]
enum ExtentNode<'a> {
    Root(&'a [u8; 60]),
    Block(u64),
}

struct Group {
    number: u32,
    offset: u64,
    descriptor: GroupDisk,
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks: u32,
    free_inodes: u32,
    used_directories: u32,
    unused_inodes: u32,
    flags: u16,
}

struct Materialized {
    physical: u64,
    zero: bool,
    first: u32,
    sibling: Option<ExtentIndex>,
}

#[derive(Clone, Copy)]
struct InlineValue {
    header: usize,
    entry: usize,
    entry_length: usize,
    entries_end: usize,
    value: usize,
    value_length: usize,
}

struct EdgeInsertion {
    offset: usize,
    replaced: Option<u32>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NodeBlockKind {
    Leaf,
    IndexRoot,
    Index,
}

enum GroupDisk {
    Short(GroupDescriptor32),
    Long(GroupDescriptor64),
}

impl GroupDisk {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Short(value) => bytemuck::bytes_of(value),
            Self::Long(value) => bytemuck::bytes_of(value),
        }
    }

    fn block_bitmap(&self) -> u64 {
        match self {
            Self::Short(value) => u64::from(value.block_bitmap_lo.get()),
            Self::Long(value) => {
                u64::from(value.lo.block_bitmap_lo.get())
                    | (u64::from(value.block_bitmap_hi.get()) << 32)
            }
        }
    }

    fn inode_bitmap(&self) -> u64 {
        match self {
            Self::Short(value) => u64::from(value.inode_bitmap_lo.get()),
            Self::Long(value) => {
                u64::from(value.lo.inode_bitmap_lo.get())
                    | (u64::from(value.inode_bitmap_hi.get()) << 32)
            }
        }
    }

    fn inode_table(&self) -> u64 {
        match self {
            Self::Short(value) => u64::from(value.inode_table_lo.get()),
            Self::Long(value) => {
                u64::from(value.lo.inode_table_lo.get())
                    | (u64::from(value.inode_table_hi.get()) << 32)
            }
        }
    }

    fn counts(&self) -> (u32, u32, u32) {
        match self {
            Self::Short(value) => (
                u32::from(value.free_blocks_count_lo.get()),
                u32::from(value.free_inodes_count_lo.get()),
                u32::from(value.used_directories_count_lo.get()),
            ),
            Self::Long(value) => (
                u32::from(value.lo.free_blocks_count_lo.get())
                    | (u32::from(value.free_blocks_count_hi.get()) << 16),
                u32::from(value.lo.free_inodes_count_lo.get())
                    | (u32::from(value.free_inodes_count_hi.get()) << 16),
                u32::from(value.lo.used_directories_count_lo.get())
                    | (u32::from(value.used_directories_count_hi.get()) << 16),
            ),
        }
    }

    fn flags(&self) -> u16 {
        match self {
            Self::Short(value) => value.flags.get(),
            Self::Long(value) => value.lo.flags.get(),
        }
    }

    fn unused_inodes(&self) -> u32 {
        match self {
            Self::Short(value) => u32::from(value.unused_inode_table_count_lo.get()),
            Self::Long(value) => {
                u32::from(value.lo.unused_inode_table_count_lo.get())
                    | (u32::from(value.unused_inode_table_count_hi.get()) << 16)
            }
        }
    }

    fn set_unused_inodes(&mut self, unused: u32) {
        let base = match self {
            Self::Short(value) => value,
            Self::Long(value) => &mut value.lo,
        };
        base.unused_inode_table_count_lo.set(unused as u16);
        if let Self::Long(value) = self {
            value.unused_inode_table_count_hi.set((unused >> 16) as u16);
        }
    }

    fn set_counts(&mut self, blocks: u32, inodes: u32, directories: u32, flags: u16) {
        let base = match self {
            Self::Short(value) => value,
            Self::Long(value) => &mut value.lo,
        };
        base.free_blocks_count_lo.set(blocks as u16);
        base.free_inodes_count_lo.set(inodes as u16);
        base.used_directories_count_lo.set(directories as u16);
        base.flags.set(flags);
        if let Self::Long(value) = self {
            value.free_blocks_count_hi.set((blocks >> 16) as u16);
            value.free_inodes_count_hi.set((inodes >> 16) as u16);
            value
                .used_directories_count_hi
                .set((directories >> 16) as u16);
        }
    }

    fn set_bitmap_checksum(&mut self, inode: bool, checksum: u32) {
        let base = match self {
            Self::Short(value) => value,
            Self::Long(value) => &mut value.lo,
        };
        if inode {
            base.inode_bitmap_checksum_lo.set(checksum as u16);
        } else {
            base.block_bitmap_checksum_lo.set(checksum as u16);
        }
        if let Self::Long(value) = self {
            if inode {
                value.inode_bitmap_checksum_hi.set((checksum >> 16) as u16);
            } else {
                value.block_bitmap_checksum_hi.set((checksum >> 16) as u16);
            }
        }
    }

    fn set_checksum(&mut self, checksum: u16) {
        match self {
            Self::Short(value) => value.checksum.set(checksum),
            Self::Long(value) => value.lo.checksum.set(checksum),
        }
    }
}

impl Ext4 {
    /// Read and validate the superblock once, retaining only the state needed
    /// by subsequent graph operations.
    pub fn mount(storage: &mut dyn Storage) -> Result<Self, Error> {
        let superblock: Superblock = read_record(storage, SUPERBLOCK_OFFSET)?;
        if superblock.magic.get() != SUPERBLOCK_MAGIC {
            return Err(Corrupt::BadMagic.into());
        }
        let features = Features {
            compatible: superblock.feature_compat.get(),
            incompatible: superblock.feature_incompat.get(),
            read_only_compatible: superblock.feature_read_only_compat.get(),
        };
        let wide = features.incompatible & INCOMPAT_64BIT != 0;
        let high = |value: Le32| {
            if wide {
                u64::from(value.get()) << 32
            } else {
                0
            }
        };
        let blocks_count =
            u64::from(superblock.blocks_count_lo.get()) | high(superblock.blocks_count_hi);
        let reserved_blocks = u64::from(superblock.reserved_blocks_count_lo.get())
            | high(superblock.reserved_blocks_count_hi);
        let free_blocks = u64::from(superblock.free_blocks_count_lo.get())
            | high(superblock.free_blocks_count_hi);
        let block_size = 1024u32
            .checked_shl(superblock.log_block_size.get())
            .filter(|size| matches!(size, 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536))
            .ok_or(Corrupt::InvalidBlockSize)?;
        let cluster_size = 1024u32
            .checked_shl(superblock.log_cluster_size.get())
            .ok_or(Corrupt::InvalidGeometry)?;
        let inodes_count = superblock.inodes_count.get();
        let free_inodes = superblock.free_inodes_count.get();
        let first_data_block = superblock.first_data_block.get();
        let blocks_per_group = superblock.blocks_per_group.get();
        let clusters_per_group = superblock.clusters_per_group.get();
        let inodes_per_group = superblock.inodes_per_group.get();
        let dynamic = superblock.revision_level.get() != 0;
        let first_inode = if dynamic {
            superblock.first_inode.get()
        } else {
            11
        };
        let inode_size = if dynamic {
            superblock.inode_size.get()
        } else {
            128
        };
        let descriptor_size = if wide {
            superblock
                .desc_size
                .get()
                .max(GROUP_DESCRIPTOR64_SIZE as u16)
        } else {
            GROUP_DESCRIPTOR32_SIZE as u16
        };
        if blocks_count <= u64::from(first_data_block)
            || reserved_blocks > blocks_count
            || free_blocks > blocks_count
            || free_inodes > inodes_count
            || blocks_per_group == 0
            || clusters_per_group == 0
            || inodes_per_group == 0
            || inodes_count < ROOT_INODE
            || first_inode == 0
            || first_inode > inodes_count
            || inode_size < INODE_BASE_SIZE as u16
            || !inode_size.is_power_of_two()
            || u32::from(inode_size) > block_size
            || descriptor_size < GROUP_DESCRIPTOR32_SIZE as u16
            || !descriptor_size.is_multiple_of(8)
            || u32::from(descriptor_size) > block_size
        {
            return Err(Corrupt::InvalidGeometry.into());
        }
        let groups =
            (blocks_count - u64::from(first_data_block)).div_ceil(u64::from(blocks_per_group));
        let inode_groups = u64::from(inodes_count).div_ceil(u64::from(inodes_per_group));
        if groups > u64::from(u32::MAX) || inode_groups > groups {
            return Err(Corrupt::InvalidGeometry.into());
        }
        let filesystem_bytes = blocks_count
            .checked_mul(u64::from(block_size))
            .ok_or(Corrupt::AddressOverflow)?;
        if filesystem_bytes > storage.len() {
            return Err(Corrupt::FilesystemPastEnd.into());
        }
        if features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            let expected = superblock.checksum.get();
            let mut checksum = crate::checksum::Checksum::new();
            let bytes = bytemuck::bytes_of(&superblock);
            checksum.update(&bytes[..size_of::<Superblock>() - size_of::<Le32>()]);
            if checksum.finalize() != expected {
                return Err(Corrupt::SuperblockChecksum.into());
            }
        }
        let uuid = superblock.uuid;
        let checksum_seed = if features.incompatible & INCOMPAT_CSUM_SEED != 0 {
            superblock.checksum_seed.get()
        } else {
            let mut checksum = crate::checksum::Checksum::new();
            checksum.update(&uuid);
            checksum.finalize()
        };
        Ok(Self {
            inodes_count,
            blocks_count,
            reserved_blocks,
            free_blocks,
            free_inodes,
            first_data_block,
            block_size,
            cluster_size,
            blocks_per_group,
            clusters_per_group,
            inodes_per_group,
            groups_count: groups as u32,
            first_inode,
            inode_size,
            descriptor_size,
            descriptors_per_block: block_size / u32::from(descriptor_size),
            creator_os: superblock.creator_os.get(),
            features,
            uuid,
            checksum_seed,
            reserved_gdt_blocks: superblock.reserved_gdt_blocks.get(),
            first_meta_block_group: superblock.first_meta_block_group.get(),
            backup_block_groups: superblock.backup_block_groups.map(Le32::get),
            directory_hash_seed: superblock.hash_seed.map(Le32::get),
            default_directory_hash: superblock.default_hash_version,
            log_groups_per_flex: superblock.log_groups_per_flex,
            journal_inode: superblock.journal_inode.get(),
            needs_recovery: features.incompatible & 0x0004 != 0,
        })
    }

    pub(crate) fn journal_blob(&self) -> Result<Blob, Error> {
        (self.journal_inode != 0)
            .then_some(Blob(self.journal_inode))
            .ok_or(Unsupported::ExternalJournal.into())
    }

    pub(crate) fn needs_recovery(&self) -> bool {
        self.needs_recovery
    }

    pub(crate) fn blob_block(
        &self,
        storage: &mut dyn Storage,
        blob: Blob,
        logical: u64,
    ) -> Result<u64, Error> {
        let inode = self.inode(storage, blob.number())?;
        if inode.object() != Object::Blob(blob) {
            return Err(Corrupt::InvalidJournal.into());
        }
        self.map_block(storage, &inode, logical)?
            .ok_or(Corrupt::InvalidJournal.into())
    }

    pub fn root(&mut self, storage: &mut dyn Storage) -> Result<Node, Error> {
        let inode = self.inode(storage, ROOT_INODE)?;
        match inode.object() {
            Object::Node(node) => Ok(node),
            Object::Blob(_) => Err(Corrupt::InvalidInode(ROOT_INODE).into()),
        }
    }

    pub fn inspect(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
    ) -> Result<ObjectInfo, Error> {
        let inode = self.inode(storage, object.number())?;
        if inode.object() != object {
            return Err(Error::NotFound);
        }
        Ok(ObjectInfo {
            object,
            size: inode.size,
            references: u32::from(inode.references),
            format: inode.mode,
            owner: inode.owner,
            group: inode.group,
            accessed: inode.accessed,
            modified: inode.modified,
            changed: inode.changed,
        })
    }

    pub fn update_attributes(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
        update: AttributeUpdate,
    ) -> Result<(), Error> {
        self.edit_inode(storage, object.number(), &mut |base, inode| {
            if inode.object() != object {
                return Err(Error::NotFound);
            }
            if let Some(format) = update.format {
                let remains_same_graph_kind = match object {
                    Object::Node(_) => format & MODE_TYPE == MODE_DIRECTORY,
                    Object::Blob(_) => format & MODE_TYPE != MODE_DIRECTORY,
                };
                if !remains_same_graph_kind || format & MODE_TYPE == 0 {
                    return Err(Error::InvalidArgument);
                }
                base.mode.set(format);
            }
            if let Some(owner) = update.owner {
                base.uid_lo.set(owner as u16);
                let mut os =
                    bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
                os.uid_hi.set((owner >> 16) as u16);
                base.os_dependent_2.copy_from_slice(bytemuck::bytes_of(&os));
            }
            if let Some(group) = update.group {
                base.gid_lo.set(group as u16);
                let mut os =
                    bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
                os.gid_hi.set((group >> 16) as u16);
                base.os_dependent_2.copy_from_slice(bytemuck::bytes_of(&os));
            }
            if let Some(value) = update.accessed {
                base.access_time.set(value);
            }
            if let Some(value) = update.modified {
                base.modification_time.set(value);
            }
            if let Some(value) = update.changed {
                base.change_time.set(value);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Visit labelled edges while their containing block is borrowed.
    /// Return `true` from `visit` to continue or `false` to stop and receive a
    /// cursor for the next entry.
    pub fn edges(
        &mut self,
        storage: &mut dyn Storage,
        node: Node,
        cursor: EdgeCursor,
        visit: &mut dyn FnMut(Edge<'_>) -> Result<bool, Error>,
    ) -> Result<Option<EdgeCursor>, Error> {
        let inode = self.inode(storage, node.number())?;
        if inode.object() != Object::Node(node) || cursor.0 > inode.size {
            return Err(Error::NotDirectory);
        }
        let block_size = u64::from(self.block_size);
        let blocks = inode.size.div_ceil(block_size);
        for logical in cursor.0 / block_size..blocks {
            let (bytes, end, kind) = self.read_node_block(storage, &inode, logical)?;
            if kind != NodeBlockKind::Leaf {
                continue;
            }
            let base = logical * block_size;
            let mut within = 0;
            while within < end {
                let entry = record_at::<DirectoryEntryHeader>(&bytes, within)?;
                let object = entry.inode.get();
                let length = directory_record_length(entry.record_length, self.block_size as usize);
                let name_length = usize::from(entry.name_length);
                if length < size_of::<DirectoryEntryHeader>() + name_length
                    || !length.is_multiple_of(4)
                    || within + length > end
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                let next = within + length;
                let position = base + within as u64;
                if position >= cursor.0 && object != 0 {
                    let name = &bytes[within + size_of::<DirectoryEntryHeader>()
                        ..within + size_of::<DirectoryEntryHeader>() + name_length];
                    if !matches!(name, b"." | b"..") {
                        let target = match entry.file_type {
                            2 => Object::Node(Node(object)),
                            _ => Object::Blob(Blob(object)),
                        };
                        if !visit(Edge {
                            handle: EdgeHandle {
                                node: node.number(),
                                object,
                                offset: position,
                            },
                            object: target,
                            name,
                        })? {
                            let resume = base + next as u64;
                            return Ok((resume < inode.size).then_some(EdgeCursor(resume)));
                        }
                    }
                }
                within = next;
            }
        }
        Ok(None)
    }

    pub fn read(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let inode = self.inode(storage, blob.number())?;
        if inode.object() != Object::Blob(blob) {
            return Err(Error::InvalidArgument);
        }
        let available = inode.size.saturating_sub(offset);
        let count = output
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        self.read_inode(storage, &inode, offset, &mut output[..count])?;
        Ok(count)
    }

    fn descriptor_offset(&self, group: u32) -> Result<u64, Error> {
        if group >= self.groups_count {
            return Err(Corrupt::InvalidGroup(group).into());
        }
        let per_block = u64::from(self.descriptors_per_block);
        let descriptor_block = u64::from(group) / per_block;
        let within = u64::from(group) % per_block;
        let block = if self.features.incompatible & INCOMPAT_META_BG == 0
            || descriptor_block < u64::from(self.first_meta_block_group)
        {
            u64::from(self.first_data_block) + 1 + descriptor_block
        } else {
            let first_group = descriptor_block
                .checked_mul(per_block)
                .ok_or(Corrupt::AddressOverflow)?;
            u64::from(self.first_data_block)
                .checked_add(
                    first_group
                        .checked_mul(u64::from(self.blocks_per_group))
                        .ok_or(Corrupt::AddressOverflow)?,
                )
                .ok_or(Corrupt::AddressOverflow)?
        };
        block
            .checked_mul(u64::from(self.block_size))
            .and_then(|offset| offset.checked_add(within * u64::from(self.descriptor_size)))
            .ok_or(Corrupt::AddressOverflow.into())
    }

    fn group(&self, storage: &mut dyn Storage, number: u32) -> Result<Group, Error> {
        let offset = self.descriptor_offset(number)?;
        let descriptor = match usize::from(self.descriptor_size) {
            GROUP_DESCRIPTOR32_SIZE => GroupDisk::Short(read_record(storage, offset)?),
            GROUP_DESCRIPTOR64_SIZE => GroupDisk::Long(read_record(storage, offset)?),
            _ => return Err(Unsupported::MutationProfile.into()),
        };
        let (free_blocks, free_inodes, used_directories) = descriptor.counts();
        Ok(Group {
            number,
            offset,
            block_bitmap: descriptor.block_bitmap(),
            inode_bitmap: descriptor.inode_bitmap(),
            inode_table: descriptor.inode_table(),
            free_blocks,
            free_inodes,
            used_directories,
            unused_inodes: descriptor.unused_inodes(),
            flags: descriptor.flags(),
            descriptor,
        })
    }

    fn write_group(&self, storage: &mut dyn Storage, group: &mut Group) -> Result<(), Error> {
        group.descriptor.set_counts(
            group.free_blocks,
            group.free_inodes,
            group.used_directories,
            group.flags,
        );
        group.descriptor.set_unused_inodes(group.unused_inodes);
        if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            group.descriptor.set_checksum(0);
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(group.number);
            checksum.update(group.descriptor.bytes());
            let checksum = checksum.finalize() as u16;
            group.descriptor.set_checksum(checksum);
        } else if self.features.read_only_compatible & RO_COMPAT_GDT_CSUM != 0 {
            return Err(Unsupported::MutationProfile.into());
        }
        write_storage(storage, group.offset, group.descriptor.bytes())
    }

    fn bitmap_checksum(&self, bytes: &[u8], bits: u64) -> u32 {
        let count = usize::try_from(bits.div_ceil(8))
            .unwrap_or(bytes.len())
            .min(bytes.len());
        let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
        checksum.update(&bytes[..count]);
        checksum.finalize()
    }

    fn group_has_superblock(&self, group: u32) -> bool {
        if group == 0 {
            return true;
        }
        if self.features.compatible & COMPAT_SPARSE_SUPER2 != 0 {
            return self.backup_block_groups.contains(&group);
        }
        if self.features.read_only_compatible & RO_COMPAT_SPARSE_SUPER == 0 {
            return true;
        }
        fn is_power(mut value: u32, base: u32) -> bool {
            while value > 1 && value.is_multiple_of(base) {
                value /= base;
            }
            value == 1
        }
        group == 1 || is_power(group, 3) || is_power(group, 5) || is_power(group, 7)
    }

    fn mark_bitmap(bitmap: &mut [u8], start: u64, count: u64) -> Result<(), Error> {
        let end = start
            .checked_add(count)
            .filter(|end| *end <= bitmap.len() as u64 * 8)
            .ok_or(Corrupt::InvalidBlockBitmap)?;
        for bit in start..end {
            bitmap[bit as usize / 8] |= 1 << (bit % 8);
        }
        Ok(())
    }

    fn initialize_inode_bitmap(&self, group: &Group, count: u64) -> Result<Vec<u8>, Error> {
        if group.number == 0
            || group.flags & GROUP_INODE_ZEROED == 0
            || u64::from(group.free_inodes) != count
        {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bitmap.resize(self.block_size as usize, 0);
        let capacity = bitmap.len() as u64 * 8;
        Self::mark_bitmap(&mut bitmap, count, capacity - count)?;
        Ok(bitmap)
    }

    fn initialize_block_bitmap(
        &self,
        group: &Group,
        start: u64,
        count: u64,
    ) -> Result<Vec<u8>, Error> {
        if group.number == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bitmap.resize(self.block_size as usize, 0);
        if self.group_has_superblock(group.number) {
            let descriptor_blocks = (u64::from(self.groups_count)
                * u64::from(self.descriptor_size))
            .div_ceil(u64::from(self.block_size));
            let metadata = 1u64
                .checked_add(descriptor_blocks)
                .and_then(|value| value.checked_add(u64::from(self.reserved_gdt_blocks)))
                .filter(|value| *value <= count)
                .ok_or(Corrupt::InvalidBlockBitmap)?;
            Self::mark_bitmap(&mut bitmap, 0, metadata)?;
        }
        let end = start.checked_add(count).ok_or(Corrupt::AddressOverflow)?;
        for block in [group.block_bitmap, group.inode_bitmap] {
            if (start..end).contains(&block) {
                Self::mark_bitmap(&mut bitmap, block - start, 1)?;
            }
        }
        let table_blocks = (u64::from(self.inodes_per_group) * u64::from(self.inode_size))
            .div_ceil(u64::from(self.block_size));
        let table_end = group
            .inode_table
            .checked_add(table_blocks)
            .filter(|end| *end <= self.blocks_count)
            .ok_or(Corrupt::InvalidInodeTable)?;
        let overlap_start = group.inode_table.max(start);
        let overlap_end = table_end.min(end);
        if overlap_start < overlap_end {
            Self::mark_bitmap(
                &mut bitmap,
                overlap_start - start,
                overlap_end - overlap_start,
            )?;
        }
        let capacity = bitmap.len() as u64 * 8;
        Self::mark_bitmap(&mut bitmap, count, capacity - count)?;
        let used =
            bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>() as u64 - (capacity - count);
        if count - used != u64::from(group.free_blocks) {
            return Err(Corrupt::InvalidFreeBlockCount.into());
        }
        Ok(bitmap)
    }

    fn set_bitmap_checksum(
        &self,
        group: &mut Group,
        inode: bool,
        checksum: u32,
    ) -> Result<(), Error> {
        group.descriptor.set_bitmap_checksum(inode, checksum);
        Ok(())
    }

    fn update_superblock_counts(
        &mut self,
        storage: &mut dyn Storage,
        blocks: i64,
        inodes: i32,
    ) -> Result<(), Error> {
        let mut superblock: Superblock = read_record(storage, SUPERBLOCK_OFFSET)?;
        self.free_blocks = self
            .free_blocks
            .checked_add_signed(blocks)
            .filter(|value| *value <= self.blocks_count)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        self.free_inodes = self
            .free_inodes
            .checked_add_signed(inodes)
            .filter(|value| *value <= self.inodes_count)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        superblock.free_blocks_count_lo.set(self.free_blocks as u32);
        superblock.free_inodes_count.set(self.free_inodes);
        if self.features.incompatible & INCOMPAT_64BIT != 0 {
            superblock
                .free_blocks_count_hi
                .set((self.free_blocks >> 32) as u32);
        }
        if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            superblock.checksum.set(0);
            let mut checksum = crate::checksum::Checksum::new();
            let bytes = bytemuck::bytes_of(&superblock);
            checksum.update(&bytes[..size_of::<Superblock>() - size_of::<Le32>()]);
            superblock.checksum.set(checksum.finalize());
        }
        write_record(storage, SUPERBLOCK_OFFSET, &superblock)
    }

    fn allocate_inode(
        &mut self,
        storage: &mut dyn Storage,
        node: bool,
    ) -> Result<(u32, u32), Error> {
        for number in 0..self.groups_count {
            let mut group = self.group(storage, number)?;
            if group.free_inodes == 0 {
                continue;
            }
            if group.inode_bitmap == 0 || group.inode_bitmap >= self.blocks_count {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let group_first = u64::from(number) * u64::from(self.inodes_per_group);
            let count = u64::from(self.inodes_count)
                .saturating_sub(group_first)
                .min(u64::from(self.inodes_per_group));
            let mut bitmap = if group.flags & GROUP_INODE_UNINIT != 0 {
                let bitmap = self.initialize_inode_bitmap(&group, count)?;
                group.flags &= !GROUP_INODE_UNINIT;
                bitmap
            } else {
                let mut bitmap = Vec::new();
                bitmap
                    .try_reserve_exact(self.block_size as usize)
                    .map_err(|_| Error::OutOfMemory)?;
                bitmap.resize(self.block_size as usize, 0);
                read_storage(
                    storage,
                    group.inode_bitmap * u64::from(self.block_size),
                    &mut bitmap,
                )?;
                bitmap
            };
            let first = if number == 0 {
                u64::from(self.first_inode - 1)
            } else {
                0
            };
            let Some(index) =
                (first..count).find(|index| bitmap[*index as usize / 8] & (1 << (*index % 8)) == 0)
            else {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            };
            bitmap[index as usize / 8] |= 1 << (index % 8);
            group.free_inodes = group
                .free_inodes
                .checked_sub(1)
                .ok_or(Corrupt::InvalidFreeBlockCount)?;
            let initialized = count
                .checked_sub(u64::from(group.unused_inodes))
                .ok_or(Corrupt::InvalidInodeTable)?;
            if index >= initialized {
                group.unused_inodes =
                    u32::try_from(count - index - 1).map_err(|_| Corrupt::InvalidInodeTable)?;
            }
            if node {
                group.used_directories = group
                    .used_directories
                    .checked_add(1)
                    .ok_or(Corrupt::InvalidFreeBlockCount)?;
            }
            let checksum = self.bitmap_checksum(&bitmap, u64::from(self.inodes_per_group));
            self.set_bitmap_checksum(&mut group, true, checksum)?;
            write_storage(
                storage,
                group.inode_bitmap * u64::from(self.block_size),
                &bitmap,
            )?;
            self.write_group(storage, &mut group)?;
            self.update_superblock_counts(storage, 0, -1)?;

            let inode =
                u32::try_from(group_first + index + 1).map_err(|_| Corrupt::AddressOverflow)?;
            let offset = group
                .inode_table
                .checked_mul(u64::from(self.block_size))
                .and_then(|value| value.checked_add(index * u64::from(self.inode_size)))
                .ok_or(Corrupt::AddressOverflow)?;
            let old: Inode128 = read_record(storage, offset)?;
            let generation = old.generation.get().wrapping_add(1).max(1);
            let mut raw = Vec::new();
            raw.try_reserve_exact(usize::from(self.inode_size))
                .map_err(|_| Error::OutOfMemory)?;
            raw.resize(usize::from(self.inode_size), 0);
            let mut base = Inode128::zeroed();
            base.mode.set(if node { 0x4000 } else { 0x8000 });
            base.links_count.set(if node { 2 } else { 1 });
            base.flags.set(EXTENTS);
            base.generation.set(generation);
            let mut root = ExtentLeafRoot::zeroed();
            root.header.magic.set(EXTENT_MAGIC);
            root.header.max_entries.set(root.entries.len() as u16);
            base.block.copy_from_slice(bytemuck::bytes_of(&root));
            raw[..INODE_BASE_SIZE].copy_from_slice(bytemuck::bytes_of(&base));
            let mut extra = (raw.len() >= size_of::<Inode160>()).then(InodeExtra32::zeroed);
            if let Some(extra) = &mut extra {
                extra.extra_inode_size.set(size_of::<InodeExtra32>() as u16);
                raw[INODE_BASE_SIZE..size_of::<Inode160>()]
                    .copy_from_slice(bytemuck::bytes_of(extra));
            }
            if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
                let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
                checksum.update_u32_le(inode);
                checksum.update_u32_le(generation);
                checksum.update(&raw);
                let checksum = checksum.finalize();
                let mut os_data = LinuxInodeOsData2::zeroed();
                os_data.checksum_lo.set(checksum as u16);
                base.os_dependent_2
                    .copy_from_slice(bytemuck::bytes_of(&os_data));
                raw[..INODE_BASE_SIZE].copy_from_slice(bytemuck::bytes_of(&base));
                if let Some(extra) = &mut extra {
                    extra.checksum_hi.set((checksum >> 16) as u16);
                    raw[INODE_BASE_SIZE..size_of::<Inode160>()]
                        .copy_from_slice(bytemuck::bytes_of(extra));
                }
            }
            write_storage(storage, offset, &raw)?;
            return Ok((inode, generation));
        }
        Err(Corrupt::InvalidFreeBlockCount.into())
    }

    fn allocate_block(&mut self, storage: &mut dyn Storage) -> Result<u64, Error> {
        for number in 0..self.groups_count {
            let mut group = self.group(storage, number)?;
            if group.free_blocks == 0 {
                continue;
            }
            if group.block_bitmap == 0 || group.block_bitmap >= self.blocks_count {
                return Err(Corrupt::InvalidBlockBitmap.into());
            }
            let start = u64::from(self.first_data_block)
                + u64::from(number) * u64::from(self.blocks_per_group);
            let count = self
                .blocks_count
                .saturating_sub(start)
                .min(u64::from(self.blocks_per_group));
            let mut bitmap = if group.flags & GROUP_BLOCK_UNINIT != 0 {
                let bitmap = self.initialize_block_bitmap(&group, start, count)?;
                group.flags &= !GROUP_BLOCK_UNINIT;
                bitmap
            } else {
                let mut bitmap = Vec::new();
                bitmap
                    .try_reserve_exact(self.block_size as usize)
                    .map_err(|_| Error::OutOfMemory)?;
                bitmap.resize(self.block_size as usize, 0);
                read_storage(
                    storage,
                    group.block_bitmap * u64::from(self.block_size),
                    &mut bitmap,
                )?;
                bitmap
            };
            let Some(index) =
                (0..count).find(|index| bitmap[*index as usize / 8] & (1 << (*index % 8)) == 0)
            else {
                return Err(Corrupt::InvalidFreeBlockCount.into());
            };
            bitmap[index as usize / 8] |= 1 << (index % 8);
            group.free_blocks = group
                .free_blocks
                .checked_sub(1)
                .ok_or(Corrupt::InvalidFreeBlockCount)?;
            let checksum = self.bitmap_checksum(&bitmap, u64::from(self.blocks_per_group));
            self.set_bitmap_checksum(&mut group, false, checksum)?;
            write_storage(
                storage,
                group.block_bitmap * u64::from(self.block_size),
                &bitmap,
            )?;
            self.write_group(storage, &mut group)?;
            self.update_superblock_counts(storage, -1, 0)?;
            return Ok(start + index);
        }
        Err(Corrupt::InvalidFreeBlockCount.into())
    }

    fn release_block(&mut self, storage: &mut dyn Storage, block: u64) -> Result<(), Error> {
        let relative = block
            .checked_sub(u64::from(self.first_data_block))
            .ok_or(Corrupt::InvalidBlockBitmap)?;
        let number = u32::try_from(relative / u64::from(self.blocks_per_group))
            .map_err(|_| Corrupt::InvalidBlockBitmap)?;
        let index = relative % u64::from(self.blocks_per_group);
        let mut group = self.group(storage, number)?;
        if group.flags & GROUP_BLOCK_UNINIT != 0
            || group.block_bitmap == 0
            || group.block_bitmap >= self.blocks_count
        {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bitmap.resize(self.block_size as usize, 0);
        read_storage(
            storage,
            group.block_bitmap * u64::from(self.block_size),
            &mut bitmap,
        )?;
        let byte = bitmap
            .get_mut(index as usize / 8)
            .ok_or(Corrupt::InvalidBlockBitmap)?;
        let mask = 1 << (index % 8);
        if *byte & mask == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        *byte &= !mask;
        group.free_blocks = group
            .free_blocks
            .checked_add(1)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        let checksum = self.bitmap_checksum(&bitmap, u64::from(self.blocks_per_group));
        self.set_bitmap_checksum(&mut group, false, checksum)?;
        write_storage(
            storage,
            group.block_bitmap * u64::from(self.block_size),
            &bitmap,
        )?;
        self.write_group(storage, &mut group)?;
        self.update_superblock_counts(storage, 1, 0)
    }

    fn release_inode(&mut self, storage: &mut dyn Storage, inode: Inode) -> Result<(), Error> {
        let index = inode
            .number
            .checked_sub(1)
            .ok_or(Corrupt::InvalidInode(inode.number))?;
        let number = index / self.inodes_per_group;
        let within = u64::from(index % self.inodes_per_group);
        let mut group = self.group(storage, number)?;
        if group.flags & GROUP_INODE_UNINIT != 0
            || group.inode_bitmap == 0
            || group.inode_bitmap >= self.blocks_count
        {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bitmap.resize(self.block_size as usize, 0);
        read_storage(
            storage,
            group.inode_bitmap * u64::from(self.block_size),
            &mut bitmap,
        )?;
        let byte = bitmap
            .get_mut(within as usize / 8)
            .ok_or(Corrupt::InvalidBlockBitmap)?;
        let mask = 1 << (within % 8);
        if *byte & mask == 0 {
            return Err(Corrupt::InvalidBlockBitmap.into());
        }
        *byte &= !mask;
        group.free_inodes = group
            .free_inodes
            .checked_add(1)
            .ok_or(Corrupt::InvalidFreeBlockCount)?;
        if matches!(inode.object(), Object::Node(_)) {
            group.used_directories = group
                .used_directories
                .checked_sub(1)
                .ok_or(Corrupt::InvalidFreeBlockCount)?;
        }
        let checksum = self.bitmap_checksum(&bitmap, u64::from(self.inodes_per_group));
        self.set_bitmap_checksum(&mut group, true, checksum)?;
        write_storage(
            storage,
            group.inode_bitmap * u64::from(self.block_size),
            &bitmap,
        )?;
        self.write_group(storage, &mut group)?;
        self.update_superblock_counts(storage, 0, 1)
    }

    fn initialize_node(
        &self,
        storage: &mut dyn Storage,
        inode: u32,
        generation: u32,
        block: u64,
    ) -> Result<(), Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        let data_end = bytes
            .len()
            .checked_sub(
                if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
                    12
                } else {
                    0
                },
            )
            .filter(|end| *end >= 24 && *end <= self.block_size as usize)
            .ok_or(Corrupt::InvalidDirectory)?;
        write_edge_record(&mut bytes, self.block_size as usize, 0, inode, 12, b".", 2)?;
        write_edge_record(
            &mut bytes,
            self.block_size as usize,
            12,
            inode,
            data_end - 12,
            b"..",
            2,
        )?;
        if data_end != bytes.len() {
            let mut tail = DirectoryEntryTail::zeroed();
            tail.record_length
                .set(size_of::<DirectoryEntryTail>() as u16);
            tail.reserved_file_type = 0xde;
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(inode);
            checksum.update_u32_le(generation);
            checksum.update(&bytes[..data_end]);
            tail.checksum.set(checksum.finalize());
            bytes[data_end..].copy_from_slice(bytemuck::bytes_of(&tail));
        }
        write_storage(storage, block * u64::from(self.block_size), &bytes)
    }

    fn read_node_block(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<(Vec<u8>, usize, NodeBlockKind), Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        self.read_inode(
            storage,
            inode,
            logical * u64::from(self.block_size),
            &mut bytes,
        )?;
        let indexed = inode.flags & INDEXED_NODE != 0;
        let kind = if !indexed {
            NodeBlockKind::Leaf
        } else if logical == 0 {
            NodeBlockKind::IndexRoot
        } else if bytes.len() >= 8
            && directory_record_length(Le16([bytes[4], bytes[5]]), self.block_size as usize)
                == bytes.len()
        {
            NodeBlockKind::Index
        } else {
            NodeBlockKind::Leaf
        };
        let checksummed = self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0;
        if checksummed {
            self.verify_node_checksum(inode, kind, &bytes)?;
        }
        let data_end = match kind {
            NodeBlockKind::Leaf => {
                bytes.len() - usize::from(checksummed) * size_of::<DirectoryEntryTail>()
            }
            NodeBlockKind::IndexRoot | NodeBlockKind::Index => 0,
        };
        if data_end == 0 {
            if kind == NodeBlockKind::Leaf {
                return Err(Corrupt::InvalidDirectory.into());
            }
        }
        Ok((bytes, data_end, kind))
    }

    fn verify_node_checksum(
        &self,
        inode: &Inode,
        kind: NodeBlockKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let (field, hashed) = match kind {
            NodeBlockKind::Leaf => {
                let tail = bytes
                    .len()
                    .checked_sub(size_of::<DirectoryEntryTail>())
                    .ok_or(Corrupt::InvalidDirectory)?;
                let record = record_at::<DirectoryEntryTail>(bytes, tail)?;
                if record.reserved_zero_1.get() != 0
                    || usize::from(record.record_length.get()) != size_of::<DirectoryEntryTail>()
                    || record.reserved_zero_2 != 0
                    || record.reserved_file_type != 0xde
                {
                    return Err(Corrupt::InvalidDirectory.into());
                }
                (tail + 8, tail)
            }
            NodeBlockKind::IndexRoot | NodeBlockKind::Index => {
                let at = if kind == NodeBlockKind::IndexRoot {
                    32
                } else {
                    8
                };
                let count = bytes
                    .get(at + 2..at + 4)
                    .map(|raw| u16::from_le_bytes([raw[0], raw[1]]) as usize)
                    .ok_or(Corrupt::InvalidDirectory)?;
                let hashed = at
                    .checked_add(count * 8)
                    .filter(|hashed| *hashed <= bytes.len().saturating_sub(8))
                    .ok_or(Corrupt::InvalidDirectory)?;
                (bytes.len() - 4, hashed)
            }
        };
        let expected = u32::from_le_bytes(
            bytes[field..field + 4]
                .try_into()
                .map_err(|_| Corrupt::InvalidDirectory)?,
        );
        let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
        checksum.update_u32_le(inode.number);
        checksum.update_u32_le(inode.generation);
        checksum.update(&bytes[..hashed]);
        if kind != NodeBlockKind::Leaf {
            checksum.update(&bytes[field - 4..field]);
            checksum.update_u32_le(0);
        }
        if checksum.finalize() != expected {
            return Err(Corrupt::DirectoryChecksum(inode.number).into());
        }
        Ok(())
    }

    fn node_block(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<(Vec<u8>, usize), Error> {
        let (bytes, mut end, kind) = self.read_node_block(storage, inode, logical)?;
        if kind == NodeBlockKind::IndexRoot {
            end = bytes.len()
                - if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
                    size_of::<DirectoryEntryTail>()
                } else {
                    0
                };
        } else if kind == NodeBlockKind::Index {
            return Err(Corrupt::InvalidDirectory.into());
        }
        Ok((bytes, end))
    }

    fn store_node_block(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
        bytes: &mut [u8],
        data_end: usize,
    ) -> Result<(), Error> {
        if data_end != bytes.len() {
            let mut tail = DirectoryEntryTail::zeroed();
            tail.record_length
                .set(size_of::<DirectoryEntryTail>() as u16);
            tail.reserved_file_type = 0xde;
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(inode.number);
            checksum.update_u32_le(inode.generation);
            checksum.update(&bytes[..data_end]);
            tail.checksum.set(checksum.finalize());
            bytes[data_end..].copy_from_slice(bytemuck::bytes_of(&tail));
        }
        self.write_object(
            storage,
            inode.object(),
            logical * u64::from(self.block_size),
            bytes,
        )
    }

    fn edge_type(inode: Inode) -> u8 {
        match inode.mode & MODE_TYPE {
            0x8000 => 1,
            MODE_DIRECTORY => 2,
            MODE_SYMLINK => 7,
            0x2000 => 3,
            0x6000 => 4,
            0x1000 => 5,
            0xc000 => 6,
            _ => 0,
        }
    }

    fn inode_offset(&self, storage: &mut dyn Storage, number: u32) -> Result<u64, Error> {
        let index = number
            .checked_sub(1)
            .filter(|index| *index < self.inodes_count)
            .ok_or(Corrupt::InvalidInode(number))?;
        let group = index / self.inodes_per_group;
        let within = u64::from(index % self.inodes_per_group);
        let inode_table = self.group(storage, group)?.inode_table;
        if inode_table == 0 || inode_table >= self.blocks_count {
            return Err(Corrupt::InvalidInodeTable.into());
        }
        inode_table
            .checked_mul(u64::from(self.block_size))
            .and_then(|offset| offset.checked_add(within * u64::from(self.inode_size)))
            .ok_or(Corrupt::AddressOverflow.into())
    }

    fn inode(&self, storage: &mut dyn Storage, number: u32) -> Result<Inode, Error> {
        let offset = self.inode_offset(storage, number)?;
        let base: Inode128 = read_record(storage, offset)?;
        let inode = decode_inode(number, base)?;
        if inode.references == 0 {
            Err(Error::NotFound)
        } else {
            Ok(inode)
        }
    }

    fn inode_raw(&self, storage: &mut dyn Storage, number: u32) -> Result<Vec<u8>, Error> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(usize::from(self.inode_size))
            .map_err(|_| Error::OutOfMemory)?;
        raw.resize(usize::from(self.inode_size), 0);
        let offset = self.inode_offset(storage, number)?;
        read_storage(storage, offset, &mut raw)?;
        Ok(raw)
    }

    fn inline_value(raw: &[u8]) -> Result<InlineValue, Error> {
        if raw.len() < INODE_BASE_SIZE + size_of::<Le16>() {
            return Err(Corrupt::InvalidXattr.into());
        }
        let extra = usize::from(record_at::<Le16>(raw, INODE_BASE_SIZE)?.get());
        let header = INODE_BASE_SIZE
            .checked_add(extra)
            .filter(|offset| offset.is_multiple_of(4))
            .ok_or(Corrupt::InvalidXattr)?;
        let first = header
            .checked_add(size_of::<Le32>())
            .ok_or(Corrupt::InvalidXattr)?;
        if first
            .checked_add(4)
            .filter(|end| *end <= raw.len())
            .is_none()
            || record_at::<Le32>(raw, header)?.get() != XATTR_MAGIC
        {
            return Err(Corrupt::InvalidXattr.into());
        }

        let mut entry = first;
        let mut target = None;
        let mut values_begin = raw.len();
        let entries_end = loop {
            if entry
                .checked_add(4)
                .filter(|end| *end <= raw.len())
                .is_none()
            {
                return Err(Corrupt::InvalidXattr.into());
            }
            if raw[entry..entry + 4] == [0; 4] {
                break entry;
            }
            let disk = record_at::<XattrEntryHeader>(raw, entry)?;
            let entry_length = (size_of::<XattrEntryHeader>()
                .checked_add(usize::from(disk.name_length))
                .and_then(|size| size.checked_add(3))
                .ok_or(Corrupt::InvalidXattr)?)
                & !3;
            let next = entry
                .checked_add(entry_length)
                .filter(|next| *next <= raw.len())
                .ok_or(Corrupt::InvalidXattr)?;
            let name_end = entry + size_of::<XattrEntryHeader>() + usize::from(disk.name_length);
            let name = &raw[entry + size_of::<XattrEntryHeader>()..name_end];
            let value_length =
                usize::try_from(disk.value_size.get()).map_err(|_| Corrupt::InvalidXattr)?;
            if disk.value_inode.get() == 0 && value_length != 0 {
                let value = first
                    .checked_add(usize::from(disk.value_offset.get()))
                    .filter(|value| value.is_multiple_of(4))
                    .ok_or(Corrupt::InvalidXattr)?;
                let value_end = value
                    .checked_add(value_length)
                    .filter(|end| *end <= raw.len())
                    .ok_or(Corrupt::InvalidXattr)?;
                if value < next || value_end > raw.len() {
                    return Err(Corrupt::InvalidXattr.into());
                }
                values_begin = values_begin.min(value);
            }
            if disk.name_index == XATTR_INDEX_SYSTEM && name == INLINE_XATTR_NAME {
                if target.is_some() || disk.value_inode.get() != 0 {
                    return Err(Corrupt::InvalidXattr.into());
                }
                let value = if value_length == 0 {
                    raw.len()
                } else {
                    first
                        .checked_add(usize::from(disk.value_offset.get()))
                        .ok_or(Corrupt::InvalidXattr)?
                };
                target = Some(InlineValue {
                    header,
                    entry,
                    entry_length,
                    entries_end: 0,
                    value,
                    value_length,
                });
            }
            entry = next;
        };
        if entries_end + 4 > values_begin {
            return Err(Corrupt::InvalidXattr.into());
        }
        let mut target = target.ok_or(Corrupt::InvalidXattr)?;
        if target.value < entries_end + 4
            || target
                .value
                .checked_add(target.value_length)
                .filter(|end| *end <= raw.len())
                .is_none()
        {
            return Err(Corrupt::InvalidXattr.into());
        }
        target.entries_end = entries_end;
        Ok(target)
    }

    fn read_inline(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let end = offset
            .checked_add(output.len())
            .ok_or(Corrupt::AddressOverflow)?;
        if end > usize::try_from(inode.size).map_err(|_| Corrupt::AddressOverflow)? {
            return Err(Corrupt::ReadPastEnd.into());
        }
        let first_end = end.min(inode.block.len());
        if offset < first_end {
            output[..first_end - offset].copy_from_slice(&inode.block[offset..first_end]);
        }
        if end > inode.block.len() {
            let raw = self.inode_raw(storage, inode.number)?;
            let inline = Self::inline_value(&raw)?;
            let logical = offset.max(inode.block.len());
            let value_offset = logical - inode.block.len();
            let count = end - logical;
            if value_offset
                .checked_add(count)
                .filter(|end| *end <= inline.value_length)
                .is_none()
            {
                return Err(Corrupt::InvalidXattr.into());
            }
            output[logical - offset..].copy_from_slice(
                &raw[inline.value + value_offset..inline.value + value_offset + count],
            );
        }
        Ok(())
    }

    fn inline_capacity(raw: &[u8], inode: Inode) -> Result<usize, Error> {
        if inode.flags & INLINE_DATA != 0 {
            inode
                .block
                .len()
                .checked_add(Self::inline_value(raw)?.value_length)
                .ok_or(Corrupt::AddressOverflow.into())
        } else {
            Ok(inode.block.len())
        }
    }

    fn fill_inline(
        raw: &mut [u8],
        base: &mut Inode128,
        inode: Inode,
        start: usize,
        end: usize,
        value: u8,
    ) -> Result<(), Error> {
        let first_end = end.min(base.block.len());
        if start < first_end {
            base.block[start..first_end].fill(value);
        }
        if end > base.block.len() {
            let inline = Self::inline_value(raw)?;
            let logical = start.max(base.block.len());
            let value_start = logical - base.block.len();
            let value_end = end - base.block.len();
            if inode.flags & INLINE_DATA == 0 || value_end > inline.value_length {
                return Err(Corrupt::InvalidXattr.into());
            }
            raw[inline.value + value_start..inline.value + value_end].fill(value);
        }
        Ok(())
    }

    fn copy_inline(
        raw: &mut [u8],
        base: &mut Inode128,
        inode: Inode,
        offset: usize,
        input: &[u8],
    ) -> Result<(), Error> {
        let end = offset
            .checked_add(input.len())
            .ok_or(Corrupt::AddressOverflow)?;
        let first_end = end.min(base.block.len());
        if offset < first_end {
            base.block[offset..first_end].copy_from_slice(&input[..first_end - offset]);
        }
        if end > base.block.len() {
            let inline = Self::inline_value(raw)?;
            let logical = offset.max(base.block.len());
            let value_start = logical - base.block.len();
            let count = end - logical;
            if inode.flags & INLINE_DATA == 0 || value_start + count > inline.value_length {
                return Err(Corrupt::InvalidXattr.into());
            }
            raw[inline.value + value_start..inline.value + value_start + count]
                .copy_from_slice(&input[logical - offset..]);
        }
        Ok(())
    }

    fn convert_inline_to_extents(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
        inode: Inode,
    ) -> Result<(), Error> {
        let length = usize::try_from(inode.size).map_err(|_| Corrupt::AddressOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(length, 0);
        self.read_inline(storage, &inode, 0, &mut bytes)?;
        self.edit_inode_raw(storage, inode.number, &mut |raw, base, current| {
            if current.generation != inode.generation
                || current.object() != object
                || !current.has_inline_bytes()
            {
                return Err(Error::NotFound);
            }
            if current.flags & INLINE_DATA != 0 {
                let inline = Self::inline_value(raw)?;
                let through = inline
                    .entries_end
                    .checked_add(4)
                    .ok_or(Corrupt::InvalidXattr)?;
                raw.copy_within(inline.entry + inline.entry_length..through, inline.entry);
                raw[through - inline.entry_length..through].fill(0);
                let padded_value = inline
                    .value_length
                    .checked_add(3)
                    .ok_or(Corrupt::InvalidXattr)?
                    & !3;
                let value_end = inline
                    .value
                    .checked_add(padded_value)
                    .filter(|end| *end <= raw.len())
                    .ok_or(Corrupt::InvalidXattr)?;
                raw[inline.value..value_end].fill(0);
                if raw[inline.header + 4..inline.header + 8] == [0; 4] {
                    raw[inline.header..inline.header + 4].fill(0);
                }
            }
            let mut root = ExtentLeafRoot::zeroed();
            root.header.magic.set(EXTENT_MAGIC);
            root.header.max_entries.set(root.entries.len() as u16);
            base.block.copy_from_slice(bytemuck::bytes_of(&root));
            base.flags.set((current.flags & !INLINE_DATA) | EXTENTS);
            base.size_lo.set(0);
            base.size_hi.set(0);
            Ok(())
        })?;
        if !bytes.is_empty() {
            self.write_object(storage, object, 0, &bytes)?;
        }
        Ok(())
    }

    fn edit_inode(
        &self,
        storage: &mut dyn Storage,
        number: u32,
        edit: &mut dyn FnMut(&mut Inode128, Inode) -> Result<(), Error>,
    ) -> Result<Inode, Error> {
        self.edit_inode_raw(storage, number, &mut |_, base, inode| edit(base, inode))
    }

    fn edit_inode_raw(
        &self,
        storage: &mut dyn Storage,
        number: u32,
        edit: &mut dyn FnMut(&mut [u8], &mut Inode128, Inode) -> Result<(), Error>,
    ) -> Result<Inode, Error> {
        let offset = self.inode_offset(storage, number)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(usize::from(self.inode_size))
            .map_err(|_| Error::OutOfMemory)?;
        raw.resize(usize::from(self.inode_size), 0);
        read_storage(storage, offset, &mut raw)?;
        let mut base = bytemuck::pod_read_unaligned::<Inode128>(&raw[..INODE_BASE_SIZE]);
        let mut extra = (raw.len() >= size_of::<Inode160>())
            .then(|| bytemuck::pod_read_unaligned::<InodeExtra32>(&raw[INODE_BASE_SIZE..160]));
        let inode = decode_inode(number, base)?;
        edit(&mut raw, &mut base, inode)?;
        if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            let mut os_data =
                bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
            os_data.checksum_lo.set(0);
            base.os_dependent_2
                .copy_from_slice(bytemuck::bytes_of(&os_data));
            if let Some(extra) = &mut extra {
                extra.checksum_hi.set(0);
            }
            raw[..INODE_BASE_SIZE].copy_from_slice(bytemuck::bytes_of(&base));
            if let Some(extra) = &extra {
                raw[INODE_BASE_SIZE..160].copy_from_slice(bytemuck::bytes_of(extra));
            }
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(number);
            checksum.update_u32_le(base.generation.get());
            checksum.update(&raw);
            let checksum = checksum.finalize();
            os_data.checksum_lo.set(checksum as u16);
            base.os_dependent_2
                .copy_from_slice(bytemuck::bytes_of(&os_data));
            if let Some(extra) = &mut extra {
                extra.checksum_hi.set((checksum >> 16) as u16);
            }
        }
        raw[..INODE_BASE_SIZE].copy_from_slice(bytemuck::bytes_of(&base));
        if let Some(extra) = &extra {
            raw[INODE_BASE_SIZE..160].copy_from_slice(bytemuck::bytes_of(extra));
        }
        write_storage(storage, offset, &raw)?;
        decode_inode(number, base)
    }

    fn change_references(
        &self,
        storage: &mut dyn Storage,
        object: Object,
        generation: u32,
        change: i16,
    ) -> Result<Inode, Error> {
        self.edit_inode(storage, object.number(), &mut |base, inode| {
            if inode.object() != object || inode.generation != generation {
                return Err(Error::NotFound);
            }
            let references = inode
                .references
                .checked_add_signed(change)
                .ok_or(Unsupported::MutationProfile)?;
            base.links_count.set(references);
            Ok(())
        })
    }

    #[inline(never)]
    fn store_extent_inode(
        &self,
        storage: &mut dyn Storage,
        inode: Inode,
        root: [u8; 60],
        owned: i64,
        size: u64,
    ) -> Result<(), Error> {
        let blocks_512 = inode
            .blocks_512
            .checked_add_signed(
                owned
                    .checked_mul(i64::from(self.block_size / 512))
                    .ok_or(Corrupt::AddressOverflow)?,
            )
            .ok_or(Corrupt::AddressOverflow)?;
        self.edit_inode(storage, inode.number, &mut |base, current| {
            if current.generation != inode.generation {
                return Err(Error::NotFound);
            }
            base.size_lo.set(size as u32);
            base.size_hi.set((size >> 32) as u32);
            base.blocks_lo.set(blocks_512 as u32);
            let mut os_data =
                bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
            os_data.blocks_hi.set((blocks_512 >> 32) as u16);
            base.os_dependent_2
                .copy_from_slice(bytemuck::bytes_of(&os_data));
            base.block = root;
            Ok(())
        })?;
        Ok(())
    }

    fn read_inode(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Error> {
        if output.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(output.len() as u64)
            .filter(|end| *end <= inode.size)
            .ok_or(Corrupt::ReadPastEnd)?;
        if matches!(inode.object(), Object::Blob(_)) && inode.has_inline_bytes() {
            self.read_inline(
                storage,
                inode,
                usize::try_from(offset).map_err(|_| Corrupt::AddressOverflow)?,
                output,
            )?;
            return Ok(());
        }
        if inode.flags & INLINE_DATA != 0 {
            return Err(Unsupported::InlineData.into());
        }
        let block_size = u64::from(self.block_size);
        let mut position = offset;
        let mut written = 0;
        while position < end {
            let logical = position / block_size;
            let within = position % block_size;
            let count = usize::try_from((end - position).min(block_size - within))
                .map_err(|_| Corrupt::AddressOverflow)?;
            match self.map_block(storage, inode, logical)? {
                Some(physical) => {
                    let physical_offset = physical
                        .checked_mul(block_size)
                        .and_then(|value| value.checked_add(within))
                        .ok_or(Corrupt::AddressOverflow)?;
                    read_storage(
                        storage,
                        physical_offset,
                        &mut output[written..written + count],
                    )?;
                }
                None => output[written..written + count].fill(0),
            }
            position += count as u64;
            written += count;
        }
        Ok(())
    }

    fn map_block(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        if inode.flags & EXTENTS != 0 {
            self.map_extent(storage, inode, logical)
        } else {
            self.map_legacy(storage, inode, logical)
        }
    }

    fn extent_record<T: Pod + Zeroable>(
        &self,
        storage: &mut dyn Storage,
        node: ExtentNode<'_>,
        offset: usize,
    ) -> Result<T, Error> {
        match node {
            ExtentNode::Root(bytes) => bytes
                .get(offset..offset + size_of::<T>())
                .ok_or(Corrupt::InvalidExtentTree)
                .map(bytemuck::pod_read_unaligned)
                .map_err(Error::from),
            ExtentNode::Block(block) => {
                if block == 0
                    || block >= self.blocks_count
                    || offset + size_of::<T>() > self.block_size as usize
                {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                let address = block
                    .checked_mul(u64::from(self.block_size))
                    .and_then(|value| value.checked_add(offset as u64))
                    .ok_or(Corrupt::AddressOverflow)?;
                read_record(storage, address)
            }
        }
    }

    fn map_extent(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        let logical = u32::try_from(logical).map_err(|_| Corrupt::InvalidExtentTree)?;
        let mut node = ExtentNode::Root(&inode.block);
        loop {
            let header: ExtentHeader = self.extent_record(storage, node, 0)?;
            if header.magic.get() != EXTENT_MAGIC {
                return Err(Corrupt::InvalidExtentHeader.into());
            }
            let entries = usize::from(header.entries.get());
            let maximum = usize::from(header.max_entries.get());
            let depth = header.depth.get();
            let capacity = match node {
                ExtentNode::Root(_) => 4,
                ExtentNode::Block(_) => {
                    (self.block_size as usize - size_of::<ExtentHeader>()) / size_of::<Extent>()
                }
            };
            if entries > maximum || maximum > capacity || depth > 5 {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            if entries == 0 {
                return Ok(None);
            }
            let mut low = 0usize;
            let mut high = entries;
            while low < high {
                let middle = (low + high) / 2;
                let entry: ExtentIndex = self.extent_record(
                    storage,
                    node,
                    size_of::<ExtentHeader>() + middle * size_of::<ExtentIndex>(),
                )?;
                if entry.logical_block.get() <= logical {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            if low == 0 {
                return Ok(None);
            }
            if depth != 0 {
                let entry: ExtentIndex = self.extent_record(
                    storage,
                    node,
                    size_of::<ExtentHeader>() + (low - 1) * size_of::<ExtentIndex>(),
                )?;
                let child =
                    u64::from(entry.child_lo.get()) | (u64::from(entry.child_hi.get()) << 32);
                node = ExtentNode::Block(child);
                continue;
            }
            let entry: Extent = self.extent_record(
                storage,
                node,
                size_of::<ExtentHeader>() + (low - 1) * size_of::<Extent>(),
            )?;
            let start = entry.logical_block.get();
            let encoded_length = entry.length.get();
            let length = entry.blocks();
            if length == 0 || logical < start || logical - start >= length {
                return Ok(None);
            }
            if encoded_length > 0x8000 {
                return Ok(None);
            }
            let physical = u64::from(entry.physical_start_lo.get())
                | (u64::from(entry.physical_start_hi.get()) << 32);
            return physical
                .checked_add(u64::from(logical - start))
                .filter(|block| *block < self.blocks_count)
                .map(Some)
                .ok_or(Corrupt::ExtentPastEnd.into());
        }
    }

    fn pointer(&self, storage: &mut dyn Storage, block: u64, index: u64) -> Result<u64, Error> {
        let pointers = u64::from(self.block_size / 4);
        if block == 0 || block >= self.blocks_count || index >= pointers {
            return Ok(0);
        }
        let offset = block
            .checked_mul(u64::from(self.block_size))
            .and_then(|value| value.checked_add(index * size_of::<Le32>() as u64))
            .ok_or(Corrupt::AddressOverflow)?;
        Ok(u64::from(read_record::<Le32>(storage, offset)?.get()))
    }

    fn map_legacy(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        logical: u64,
    ) -> Result<Option<u64>, Error> {
        let map = bytemuck::pod_read_unaligned::<LegacyBlockMap>(&inode.block);
        let pointers = u64::from(self.block_size / 4);
        let (mut block, indexes, depth): (u64, [u64; 3], usize) = if logical < 12 {
            return Ok(match u64::from(map.direct[logical as usize].get()) {
                0 => None,
                block if block < self.blocks_count => Some(block),
                _ => return Err(Corrupt::InvalidLegacyBlockMap.into()),
            });
        } else if logical < 12 + pointers {
            (u64::from(map.indirect.get()), [logical - 12, 0, 0], 1)
        } else if logical < 12 + pointers + pointers * pointers {
            let index = logical - 12 - pointers;
            (
                u64::from(map.double_indirect.get()),
                [index / pointers, index % pointers, 0],
                2,
            )
        } else {
            let index = logical - 12 - pointers - pointers * pointers;
            let square = pointers
                .checked_mul(pointers)
                .ok_or(Corrupt::AddressOverflow)?;
            if index >= square * pointers {
                return Err(Corrupt::InvalidLegacyBlockMap.into());
            }
            (
                u64::from(map.triple_indirect.get()),
                [
                    index / square,
                    index / pointers % pointers,
                    index % pointers,
                ],
                3,
            )
        };
        for &index in &indexes[..depth] {
            if block == 0 {
                return Ok(None);
            }
            block = self.pointer(storage, block, index)?;
        }
        if block >= self.blocks_count {
            return Err(Corrupt::InvalidLegacyBlockMap.into());
        }
        Ok((block != 0).then_some(block))
    }

    fn extent_capacity(&self) -> Result<usize, Error> {
        (self.block_size as usize)
            .checked_sub(size_of::<ExtentHeader>() + size_of::<Le32>())
            .map(|bytes| bytes / size_of::<Extent>())
            .filter(|capacity| *capacity > 4 && *capacity <= usize::from(u16::MAX))
            .ok_or(Corrupt::InvalidExtentTree.into())
    }

    fn read_extent_node(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        block: u64,
        depth: u16,
    ) -> Result<(Vec<u8>, ExtentHeader), Error> {
        if block == 0 || block >= self.blocks_count {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        read_storage(storage, block * u64::from(self.block_size), &mut bytes)?;
        let header = record_at::<ExtentHeader>(&bytes, 0)?;
        let capacity = self.extent_capacity()?;
        if header.magic.get() != EXTENT_MAGIC
            || header.depth.get() != depth
            || usize::from(header.entries.get()) > capacity
            || usize::from(header.max_entries.get()) != capacity
        {
            return Err(Corrupt::InvalidExtentHeader.into());
        }
        if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            let checksum_at = size_of::<ExtentHeader>() + capacity * size_of::<Extent>();
            let expected = record_at::<Le32>(&bytes, checksum_at)?.get();
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(inode.number);
            checksum.update_u32_le(inode.generation);
            checksum.update(&bytes[..checksum_at]);
            if checksum.finalize() != expected {
                return Err(Corrupt::ExtentChecksum(inode.number).into());
            }
        }
        Ok((bytes, header))
    }

    #[inline(never)]
    fn write_extent_node<T: Pod>(
        &self,
        storage: &mut dyn Storage,
        inode: &Inode,
        block: u64,
        depth: u16,
        entries: &[T],
    ) -> Result<(), Error> {
        if size_of::<T>() != size_of::<Extent>() || block == 0 || block >= self.blocks_count {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let capacity = self.extent_capacity()?;
        if entries.is_empty() || entries.len() > capacity {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        let mut header = ExtentHeader::zeroed();
        header.magic.set(EXTENT_MAGIC);
        header.entries.set(entries.len() as u16);
        header.max_entries.set(capacity as u16);
        header.depth.set(depth);
        write_record_at(&mut bytes, 0, &header)?;
        write_records(&mut bytes, size_of::<ExtentHeader>(), entries)?;
        if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
            let checksum_at = size_of::<ExtentHeader>() + capacity * size_of::<Extent>();
            let mut checksum = crate::checksum::Checksum::with_seed(self.checksum_seed);
            checksum.update_u32_le(inode.number);
            checksum.update_u32_le(inode.generation);
            checksum.update(&bytes[..checksum_at]);
            write_record_at(&mut bytes, checksum_at, &Le32::new(checksum.finalize()))?;
        }
        write_storage(storage, block * u64::from(self.block_size), &bytes)
    }

    fn materialize_leaf(
        &mut self,
        storage: &mut dyn Storage,
        entries: &mut Vec<Extent>,
        logical: u32,
        owned: &mut i64,
    ) -> Result<(u64, bool), Error> {
        validate_extents(entries)?;
        let position = entries.partition_point(|extent| extent.logical_block.get() <= logical);
        if let Some(at) = position.checked_sub(1) {
            if entries[at].end() <= u64::from(logical) {
                return self.materialize_hole(storage, entries, logical, position, owned);
            }
            let extent = entries[at];
            let physical = extent.physical() + u64::from(logical) - extent.logical();
            if !extent.is_unwritten() {
                return Ok((physical, false));
            }
            entries.try_reserve(2).map_err(|_| Error::OutOfMemory)?;
            entries.remove(at);
            let before = logical - extent.logical_block.get();
            let after = extent.blocks() - before - 1;
            let mut insert = at;
            if before != 0 {
                let mut left = extent;
                left.set_blocks(before)?;
                entries.insert(insert, left);
                insert += 1;
            }
            let mut middle = extent;
            middle.logical_block.set(logical);
            middle.length.set(1);
            middle.physical_start_hi.set((physical >> 32) as u16);
            middle.physical_start_lo.set(physical as u32);
            entries.insert(insert, middle);
            insert += 1;
            if after != 0 {
                let mut right = extent;
                right.logical_block.set(logical + 1);
                right.physical_start_hi.set(((physical + 1) >> 32) as u16);
                right.physical_start_lo.set((physical + 1) as u32);
                right.set_blocks(after)?;
                entries.insert(insert, right);
            }
            merge_extents(entries);
            return Ok((physical, true));
        }
        self.materialize_hole(storage, entries, logical, position, owned)
    }

    fn materialize_hole(
        &mut self,
        storage: &mut dyn Storage,
        entries: &mut Vec<Extent>,
        logical: u32,
        position: usize,
        owned: &mut i64,
    ) -> Result<(u64, bool), Error> {
        let physical = self.allocate_block(storage)?;
        *owned += 1;
        entries.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        let mut extent = Extent::zeroed();
        extent.logical_block.set(logical);
        extent.length.set(1);
        extent.physical_start_hi.set((physical >> 32) as u16);
        extent.physical_start_lo.set(physical as u32);
        entries.insert(position, extent);
        merge_extents(entries);
        Ok((physical, true))
    }

    fn materialize_external(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        block: u64,
        depth: u16,
        logical: u32,
        owned: &mut i64,
    ) -> Result<Materialized, Error> {
        let (bytes, header) = self.read_extent_node(storage, inode, block, depth)?;
        let count = usize::from(header.entries.get());
        let capacity = self.extent_capacity()?;
        if depth == 0 {
            let mut entries = read_records::<Extent>(&bytes, size_of::<ExtentHeader>(), count)?;
            let (physical, zero) = self.materialize_leaf(storage, &mut entries, logical, owned)?;
            if !zero {
                return Ok(Materialized {
                    physical,
                    zero,
                    first: entries[0].logical_block.get(),
                    sibling: None,
                });
            }
            let sibling = if entries.len() > capacity {
                let right = entries.split_off(entries.len() / 2);
                let sibling = self.allocate_block(storage)?;
                *owned += 1;
                self.write_extent_node(storage, inode, sibling, 0, &right)?;
                Some(ExtentIndex::from_child(
                    right[0].logical_block.get(),
                    sibling,
                )?)
            } else {
                None
            };
            self.write_extent_node(storage, inode, block, 0, &entries)?;
            return Ok(Materialized {
                physical,
                zero,
                first: entries[0].logical_block.get(),
                sibling,
            });
        }

        let mut indexes = read_records::<ExtentIndex>(&bytes, size_of::<ExtentHeader>(), count)?;
        validate_indexes(&indexes)?;
        let at = indexes
            .partition_point(|index| index.logical() <= logical)
            .saturating_sub(1);
        let mut child = self.materialize_external(
            storage,
            inode,
            indexes[at].block(),
            depth - 1,
            logical,
            owned,
        )?;
        if !child.zero {
            child.first = indexes[0].logical();
            return Ok(child);
        }
        indexes[at].logical_block.set(child.first);
        if let Some(sibling) = child.sibling.take() {
            indexes.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
            indexes.insert(at + 1, sibling);
        }
        child.first = indexes[0].logical();
        child.sibling = if indexes.len() > capacity {
            let right = indexes.split_off(indexes.len() / 2);
            let sibling = self.allocate_block(storage)?;
            *owned += 1;
            self.write_extent_node(storage, inode, sibling, depth, &right)?;
            Some(ExtentIndex::from_child(right[0].logical(), sibling)?)
        } else {
            None
        };
        self.write_extent_node(storage, inode, block, depth, &indexes)?;
        Ok(child)
    }

    #[inline(never)]
    fn materialize_root(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        root: &mut [u8; 60],
        logical: u32,
        owned: &mut i64,
    ) -> Result<(u64, bool), Error> {
        let mut header = record_at::<ExtentHeader>(root, 0)?;
        if header.magic.get() != EXTENT_MAGIC
            || header.max_entries.get() != 4
            || header.entries.get() > 4
            || header.depth.get() > 5
        {
            return Err(Corrupt::InvalidExtentHeader.into());
        }
        let count = usize::from(header.entries.get());
        let depth = header.depth.get();
        if depth == 0 {
            let mut entries = read_records::<Extent>(root, size_of::<ExtentHeader>(), count)?;
            let result = self.materialize_leaf(storage, &mut entries, logical, owned)?;
            if !result.1 {
                return Ok(result);
            }
            if entries.len() <= 4 {
                root.fill(0);
                header.entries.set(entries.len() as u16);
                write_record_at(root, 0, &header)?;
                write_records(root, size_of::<ExtentHeader>(), &entries)?;
                return Ok(result);
            }
            let child = self.allocate_block(storage)?;
            *owned += 1;
            self.write_extent_node(storage, inode, child, 0, &entries)?;
            root.fill(0);
            header.entries.set(1);
            header.depth.set(1);
            write_record_at(root, 0, &header)?;
            write_record_at(
                root,
                size_of::<ExtentHeader>(),
                &ExtentIndex::from_child(entries[0].logical_block.get(), child)?,
            )?;
            return Ok(result);
        }

        let mut indexes = read_records::<ExtentIndex>(root, size_of::<ExtentHeader>(), count)?;
        validate_indexes(&indexes)?;
        let at = indexes
            .partition_point(|index| index.logical() <= logical)
            .saturating_sub(1);
        let mut changed = self.materialize_external(
            storage,
            inode,
            indexes[at].block(),
            depth - 1,
            logical,
            owned,
        )?;
        if !changed.zero {
            return Ok((changed.physical, false));
        }
        indexes[at].logical_block.set(changed.first);
        if let Some(sibling) = changed.sibling.take() {
            indexes.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
            indexes.insert(at + 1, sibling);
        }
        root.fill(0);
        if indexes.len() <= 4 {
            header.entries.set(indexes.len() as u16);
            write_record_at(root, 0, &header)?;
            write_records(root, size_of::<ExtentHeader>(), &indexes)?;
        } else {
            if depth == 5 {
                return Err(Unsupported::ExtentMutation.into());
            }
            let child = self.allocate_block(storage)?;
            *owned += 1;
            self.write_extent_node(storage, inode, child, depth, &indexes)?;
            header.entries.set(1);
            header.depth.set(depth + 1);
            write_record_at(root, 0, &header)?;
            write_record_at(
                root,
                size_of::<ExtentHeader>(),
                &ExtentIndex::from_child(indexes[0].logical(), child)?,
            )?;
        }
        Ok((changed.physical, changed.zero))
    }

    fn release_extent(
        &mut self,
        storage: &mut dyn Storage,
        extent: Extent,
        first: u64,
        owned: &mut i64,
    ) -> Result<Option<Extent>, Error> {
        let keep = first
            .saturating_sub(extent.logical())
            .min(u64::from(extent.blocks()));
        let release = u64::from(extent.blocks()) - keep;
        for offset in 0..release {
            self.release_block(storage, extent.physical() + keep + offset)?;
            *owned -= 1;
        }
        if keep == 0 {
            Ok(None)
        } else {
            let mut retained = extent;
            retained.set_blocks(keep as u32)?;
            Ok(Some(retained))
        }
    }

    fn truncate_external_extent(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        block: u64,
        depth: u16,
        first: u64,
        owned: &mut i64,
    ) -> Result<bool, Error> {
        let (bytes, header) = self.read_extent_node(storage, inode, block, depth)?;
        let count = usize::from(header.entries.get());
        if depth == 0 {
            let entries = read_records::<Extent>(&bytes, size_of::<ExtentHeader>(), count)?;
            validate_extents(&entries)?;
            let mut retained = Vec::new();
            retained
                .try_reserve_exact(entries.len())
                .map_err(|_| Error::OutOfMemory)?;
            for extent in entries {
                if extent.end() <= first {
                    retained.push(extent);
                } else if let Some(extent) = self.release_extent(storage, extent, first, owned)? {
                    retained.push(extent);
                }
            }
            if retained.is_empty() {
                return Ok(true);
            }
            self.write_extent_node(storage, inode, block, 0, &retained)?;
            return Ok(false);
        }

        let indexes = read_records::<ExtentIndex>(&bytes, size_of::<ExtentHeader>(), count)?;
        validate_indexes(&indexes)?;
        let start = indexes
            .partition_point(|index| u64::from(index.logical()) < first)
            .saturating_sub(1);
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(indexes.len())
            .map_err(|_| Error::OutOfMemory)?;
        retained.extend_from_slice(&indexes[..start]);
        for index in &indexes[start..] {
            if self.truncate_external_extent(
                storage,
                inode,
                index.block(),
                depth - 1,
                first,
                owned,
            )? {
                self.release_block(storage, index.block())?;
                *owned -= 1;
            } else {
                retained.push(*index);
            }
        }
        if retained.is_empty() {
            return Ok(true);
        }
        self.write_extent_node(storage, inode, block, depth, &retained)?;
        Ok(false)
    }

    #[inline(never)]
    fn truncate_root_extent(
        &mut self,
        storage: &mut dyn Storage,
        inode: &Inode,
        root: &mut [u8; 60],
        first: u64,
        owned: &mut i64,
    ) -> Result<(), Error> {
        let header = record_at::<ExtentHeader>(root, 0)?;
        if header.magic.get() != EXTENT_MAGIC
            || header.max_entries.get() != 4
            || header.entries.get() > 4
            || header.depth.get() > 5
        {
            return Err(Corrupt::InvalidExtentHeader.into());
        }
        let count = usize::from(header.entries.get());
        let depth = header.depth.get();
        if depth == 0 {
            let entries = read_records::<Extent>(root, size_of::<ExtentHeader>(), count)?;
            validate_extents(&entries)?;
            let mut retained = Vec::new();
            retained
                .try_reserve_exact(entries.len())
                .map_err(|_| Error::OutOfMemory)?;
            for extent in entries {
                if extent.end() <= first {
                    retained.push(extent);
                } else if let Some(extent) = self.release_extent(storage, extent, first, owned)? {
                    retained.push(extent);
                }
            }
            root.fill(0);
            let mut changed = header;
            changed.entries.set(retained.len() as u16);
            write_record_at(root, 0, &changed)?;
            return write_records(root, size_of::<ExtentHeader>(), &retained);
        }

        let indexes = read_records::<ExtentIndex>(root, size_of::<ExtentHeader>(), count)?;
        validate_indexes(&indexes)?;
        let start = indexes
            .partition_point(|index| u64::from(index.logical()) < first)
            .saturating_sub(1);
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(indexes.len())
            .map_err(|_| Error::OutOfMemory)?;
        retained.extend_from_slice(&indexes[..start]);
        for index in &indexes[start..] {
            if self.truncate_external_extent(
                storage,
                inode,
                index.block(),
                depth - 1,
                first,
                owned,
            )? {
                self.release_block(storage, index.block())?;
                *owned -= 1;
            } else {
                retained.push(*index);
            }
        }
        if retained.is_empty() {
            root.fill(0);
            let mut empty = ExtentHeader::zeroed();
            empty.magic.set(EXTENT_MAGIC);
            empty.max_entries.set(4);
            return write_record_at(root, 0, &empty);
        }
        root.fill(0);
        let mut changed = header;
        changed.entries.set(retained.len() as u16);
        write_record_at(root, 0, &changed)?;
        write_records(root, size_of::<ExtentHeader>(), &retained)?;

        loop {
            let header = record_at::<ExtentHeader>(root, 0)?;
            if header.depth.get() == 0 || header.entries.get() != 1 {
                break;
            }
            let index = record_at::<ExtentIndex>(root, size_of::<ExtentHeader>())?;
            let (bytes, child) =
                self.read_extent_node(storage, inode, index.block(), header.depth.get() - 1)?;
            if child.entries.get() > 4 {
                break;
            }
            root.fill(0);
            let mut collapsed = child;
            collapsed.max_entries.set(4);
            write_record_at(root, 0, &collapsed)?;
            let entry_bytes = usize::from(child.entries.get()) * size_of::<Extent>();
            root[size_of::<ExtentHeader>()..size_of::<ExtentHeader>() + entry_bytes]
                .copy_from_slice(
                    &bytes[size_of::<ExtentHeader>()..size_of::<ExtentHeader>() + entry_bytes],
                );
            self.release_block(storage, index.block())?;
            *owned -= 1;
        }
        Ok(())
    }

    pub fn write(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error> {
        self.write_object(storage, Object::Blob(blob), offset, input)
    }

    fn write_object(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error> {
        let mut inode = self.inode(storage, object.number())?;
        if inode.object() != object {
            return Err(Error::InvalidArgument);
        }
        if input.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(input.len() as u64)
            .ok_or(Corrupt::AddressOverflow)?;
        if matches!(object, Object::Blob(_)) && inode.has_inline_bytes() {
            let raw = self.inode_raw(storage, inode.number)?;
            if end <= Self::inline_capacity(&raw, inode)? as u64 {
                let start = usize::try_from(offset).map_err(|_| Corrupt::AddressOverflow)?;
                let finish = usize::try_from(end).map_err(|_| Corrupt::AddressOverflow)?;
                self.edit_inode_raw(storage, inode.number, &mut |raw, base, current| {
                    if current.generation != inode.generation || current.object() != object {
                        return Err(Error::NotFound);
                    }
                    if offset > current.size {
                        Self::fill_inline(
                            raw,
                            base,
                            current,
                            usize::try_from(current.size).map_err(|_| Corrupt::AddressOverflow)?,
                            start,
                            0,
                        )?;
                    }
                    Self::copy_inline(raw, base, current, start, input)?;
                    if end > current.size {
                        base.size_lo.set(finish as u32);
                        base.size_hi.set((end >> 32) as u32);
                    }
                    Ok(())
                })?;
                return Ok(());
            }
            self.convert_inline_to_extents(storage, object, inode)?;
            return self.write_object(storage, object, offset, input);
        }
        let block_size = u64::from(self.block_size);
        if inode.flags & INLINE_DATA != 0
            || inode.flags & EXTENTS == 0
            || self.cluster_size != self.block_size
            || end.div_ceil(block_size) > 1_u64 << 32
        {
            return Err(Unsupported::ExtentMutation.into());
        }
        if end > inode.size {
            self.resize_object(storage, object, end)?;
            inode = self.inode(storage, object.number())?;
        }
        let mut root = inode.block;
        let mut owned = 0i64;
        let mut zero = Vec::new();
        let mut position = offset;
        let mut consumed = 0;
        while position < end {
            let within = position % block_size;
            let count = usize::try_from((end - position).min(block_size - within))
                .map_err(|_| Corrupt::AddressOverflow)?;
            let (physical, initialize) = self.materialize_root(
                storage,
                &inode,
                &mut root,
                u32::try_from(position / block_size).map_err(|_| Corrupt::AddressOverflow)?,
                &mut owned,
            )?;
            let address = physical
                .checked_mul(block_size)
                .and_then(|value| value.checked_add(within))
                .ok_or(Corrupt::AddressOverflow)?;
            if initialize {
                if zero.is_empty() {
                    zero.try_reserve_exact(self.block_size as usize)
                        .map_err(|_| Error::OutOfMemory)?;
                    zero.resize(self.block_size as usize, 0);
                }
                write_storage(storage, physical * block_size, &zero)?;
            }
            write_storage(storage, address, &input[consumed..consumed + count])?;
            position += count as u64;
            consumed += count;
        }
        if owned != 0 || root != inode.block {
            self.store_extent_inode(storage, inode, root, owned, inode.size)?;
        }
        Ok(())
    }

    pub fn resize(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        size: u64,
    ) -> Result<(), Error> {
        self.resize_object(storage, Object::Blob(blob), size)
    }

    fn resize_object(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
        size: u64,
    ) -> Result<(), Error> {
        let inode = self.inode(storage, object.number())?;
        if inode.object() != object {
            return Err(Error::InvalidArgument);
        }
        if size == inode.size {
            return Ok(());
        }
        if matches!(object, Object::Blob(_)) && inode.has_inline_bytes() {
            let raw = self.inode_raw(storage, inode.number)?;
            if size <= Self::inline_capacity(&raw, inode)? as u64 {
                return self
                    .edit_inode_raw(storage, inode.number, &mut |raw, base, current| {
                        if current.generation != inode.generation || current.object() != object {
                            return Err(Error::NotFound);
                        }
                        Self::fill_inline(
                            raw,
                            base,
                            current,
                            usize::try_from(size.min(current.size))
                                .map_err(|_| Corrupt::AddressOverflow)?,
                            usize::try_from(size.max(current.size))
                                .map_err(|_| Corrupt::AddressOverflow)?,
                            0,
                        )?;
                        base.size_lo.set(size as u32);
                        base.size_hi.set((size >> 32) as u32);
                        Ok(())
                    })
                    .map(|_| ());
            }
            self.convert_inline_to_extents(storage, object, inode)?;
            return self.resize_object(storage, object, size);
        }
        if inode.flags & INLINE_DATA != 0 {
            return Err(Unsupported::InlineData.into());
        }
        if inode.flags & EXTENTS == 0 {
            return Err(Unsupported::ExtentMutation.into());
        }

        let block_size = u64::from(self.block_size);
        let new_blocks = size.div_ceil(block_size);
        if self.cluster_size != self.block_size || new_blocks > 1_u64 << 32 {
            return Err(Unsupported::ExtentMutation.into());
        }
        let mut root = inode.block;
        let mut owned = 0i64;
        if size < inode.size {
            self.truncate_root_extent(storage, &inode, &mut root, new_blocks, &mut owned)?;
        }

        let zero_from = if size < inode.size { size } else { inode.size };
        if zero_from % block_size != 0 {
            let logical = zero_from / block_size;
            let mut current = inode;
            current.block = root;
            if let Some(physical) = self.map_extent(storage, &current, logical)? {
                let within = zero_from % block_size;
                let count =
                    usize::try_from(block_size - within).map_err(|_| Corrupt::AddressOverflow)?;
                let mut zero = Vec::new();
                zero.try_reserve_exact(count)
                    .map_err(|_| Error::OutOfMemory)?;
                zero.resize(count, 0);
                write_storage(storage, physical * block_size + within, &zero)?;
            }
        }

        self.store_extent_inode(storage, inode, root, owned, size)
    }

    pub fn create_blob(&mut self, storage: &mut dyn Storage) -> Result<Detached, Error> {
        let (number, generation) = self.allocate_inode(storage, false)?;
        Ok(Detached {
            object: Object::Blob(Blob(number)),
            generation,
        })
    }

    pub fn create_node(&mut self, storage: &mut dyn Storage) -> Result<Detached, Error> {
        let (number, generation) = self.allocate_inode(storage, true)?;
        let block = self.allocate_block(storage)?;
        if block >> 48 != 0 {
            return Err(Unsupported::ExtentMutation.into());
        }
        self.edit_inode(storage, number, &mut |base, inode| {
            if inode.generation != generation {
                return Err(Error::NotFound);
            }
            base.size_lo.set(self.block_size);
            base.size_hi.set(0);
            let sectors = u64::from(self.block_size) / 512;
            base.blocks_lo.set(sectors as u32);
            let mut os_data =
                bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
            os_data.blocks_hi.set((sectors >> 32) as u16);
            base.os_dependent_2
                .copy_from_slice(bytemuck::bytes_of(&os_data));
            let mut root = ExtentLeafRoot::zeroed();
            root.header.magic.set(EXTENT_MAGIC);
            root.header.entries.set(1);
            root.header.max_entries.set(4);
            root.entries[0].length.set(1);
            root.entries[0].physical_start_hi.set((block >> 32) as u16);
            root.entries[0].physical_start_lo.set(block as u32);
            base.block.copy_from_slice(bytemuck::bytes_of(&root));
            Ok(())
        })?;
        self.initialize_node(storage, number, generation, block)?;
        Ok(Detached {
            object: Object::Node(Node(number)),
            generation,
        })
    }

    pub fn retain(&mut self, storage: &mut dyn Storage, blob: Blob) -> Result<Detached, Error> {
        let inode = self.inode(storage, blob.number())?;
        if inode.object() != Object::Blob(blob) || inode.references == u16::MAX {
            return Err(Error::InvalidArgument);
        }
        self.change_references(storage, Object::Blob(blob), inode.generation, 1)?;
        Ok(Detached {
            object: Object::Blob(blob),
            generation: inode.generation,
        })
    }

    fn back_edge(&self, storage: &mut dyn Storage, node: Node) -> Result<Node, Error> {
        let inode = self.inode(storage, node.number())?;
        let (bytes, end) = self.node_block(storage, &inode, 0)?;
        let mut offset = 0;
        while offset < end {
            let entry = record_at::<DirectoryEntryHeader>(&bytes, offset)?;
            let length = directory_record_length(entry.record_length, self.block_size as usize);
            let name_length = usize::from(entry.name_length);
            if length < size_of::<DirectoryEntryHeader>() + name_length || offset + length > end {
                return Err(Corrupt::InvalidDirectory.into());
            }
            let name = &bytes[offset + size_of::<DirectoryEntryHeader>()
                ..offset + size_of::<DirectoryEntryHeader>() + name_length];
            if entry.inode.get() != 0 && name == b".." {
                return Ok(Node(entry.inode.get()));
            }
            offset += length;
        }
        Err(Corrupt::InvalidDirectory.into())
    }

    fn set_back_edge(
        &mut self,
        storage: &mut dyn Storage,
        node: Node,
        target: Node,
    ) -> Result<(), Error> {
        let inode = self.inode(storage, node.number())?;
        let (mut bytes, end) = self.node_block(storage, &inode, 0)?;
        let mut offset = 0;
        while offset < end {
            let mut entry = record_at::<DirectoryEntryHeader>(&bytes, offset)?;
            let length = directory_record_length(entry.record_length, self.block_size as usize);
            let name_length = usize::from(entry.name_length);
            if length < size_of::<DirectoryEntryHeader>() + name_length || offset + length > end {
                return Err(Corrupt::InvalidDirectory.into());
            }
            let name = &bytes[offset + size_of::<DirectoryEntryHeader>()
                ..offset + size_of::<DirectoryEntryHeader>() + name_length];
            if entry.inode.get() != 0 && name == b".." {
                entry.inode.set(target.number());
                write_record_at(&mut bytes, offset, &entry)?;
                return self.store_node_block(storage, &inode, 0, &mut bytes, end);
            }
            offset += length;
        }
        Err(Corrupt::InvalidDirectory.into())
    }

    /// Replace an ext4 hash index with its equivalent linear edge array.
    ///
    /// The index is only an accelerator over the graph: all labelled edges
    /// already live in ordinary leaf blocks.  The root block stores `.` and
    /// `..` followed by index data in the slack of the second record.  Making
    /// that slack ordinary free record space and clearing the index flag lets
    /// the same edge algorithms serve both representations without carrying
    /// a second mutation engine.
    fn linearize_node(&mut self, storage: &mut dyn Storage, node: Node) -> Result<Inode, Error> {
        let inode = self.inode(storage, node.number())?;
        if inode.object() != Object::Node(node) {
            return Err(Error::NotDirectory);
        }
        if inode.flags & INDEXED_NODE == 0 {
            return Ok(inode);
        }

        let (mut bytes, end) = self.node_block(storage, &inode, 0)?;
        let dot = record_at::<DirectoryEntryHeader>(&bytes, 0)?;
        let dot_length = directory_record_length(dot.record_length, self.block_size as usize);
        let dot_name_start = size_of::<DirectoryEntryHeader>();
        if dot.inode.get() != node.number()
            || dot.name_length != 1
            || bytes.get(dot_name_start) != Some(&b'.')
            || dot_length < 12
            || dot_length >= end
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let parent = record_at::<DirectoryEntryHeader>(&bytes, dot_length)?;
        let parent_name_start = dot_length + size_of::<DirectoryEntryHeader>();
        if parent.inode.get() == 0
            || parent.name_length != 2
            || bytes.get(parent_name_start..parent_name_start + 2) != Some(&b".."[..])
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        write_edge_record(
            &mut bytes,
            self.block_size as usize,
            0,
            node.number(),
            dot_length,
            b".",
            2,
        )?;
        write_edge_record(
            &mut bytes,
            self.block_size as usize,
            dot_length,
            parent.inode.get(),
            end - dot_length,
            b"..",
            2,
        )?;
        self.store_node_block(storage, &inode, 0, &mut bytes, end)?;
        self.edit_inode(storage, inode.number, &mut |base, current| {
            if current.generation != inode.generation || current.object() != Object::Node(node) {
                return Err(Error::NotFound);
            }
            base.flags.set(current.flags & !INDEXED_NODE);
            Ok(())
        })
    }

    fn insert_edge(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        target: Inode,
    ) -> Result<EdgeInsertion, Error> {
        let mut inode = self.linearize_node(storage, parent)?;
        let blocks = inode.size.div_ceil(u64::from(self.block_size));
        for logical in 0..blocks {
            let (mut bytes, end) = self.node_block(storage, &inode, logical)?;
            if let Some(mut inserted) = insert_edge_record(
                &mut bytes,
                self.block_size as usize,
                end,
                name,
                target.number,
                Self::edge_type(target),
            )? {
                self.store_node_block(storage, &inode, logical, &mut bytes, end)?;
                inserted.offset += logical as usize * self.block_size as usize;
                return Ok(inserted);
            }
        }
        let logical = blocks;
        self.resize_object(
            storage,
            Object::Node(parent),
            (blocks + 1) * u64::from(self.block_size),
        )?;
        inode = self.inode(storage, parent.number())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(self.block_size as usize, 0);
        let end = bytes.len()
            - if self.features.read_only_compatible & RO_COMPAT_METADATA_CSUM != 0 {
                size_of::<DirectoryEntryTail>()
            } else {
                0
            };
        write_edge_record(
            &mut bytes,
            self.block_size as usize,
            0,
            target.number,
            end,
            name,
            Self::edge_type(target),
        )?;
        self.store_node_block(storage, &inode, logical, &mut bytes, end)?;
        Ok(EdgeInsertion {
            offset: logical as usize * self.block_size as usize,
            replaced: None,
        })
    }

    pub fn detach(
        &mut self,
        storage: &mut dyn Storage,
        edge: EdgeHandle,
    ) -> Result<Detached, Error> {
        let parent = Node(edge.node);
        let inode = self.linearize_node(storage, parent)?;
        let logical = edge.offset / u64::from(self.block_size);
        let within = (edge.offset % u64::from(self.block_size)) as usize;
        let (mut bytes, end) = self.node_block(storage, &inode, logical)?;
        remove_edge_record(
            &mut bytes,
            self.block_size as usize,
            end,
            within,
            edge.object,
        )?;
        self.store_node_block(storage, &inode, logical, &mut bytes, end)?;
        let target = self.inode(storage, edge.object)?;
        if let Object::Node(node) = target.object() {
            self.set_back_edge(storage, node, node)?;
            self.change_references(storage, Object::Node(parent), inode.generation, -1)?;
        }
        Ok(Detached {
            object: target.object(),
            generation: target.generation,
        })
    }

    pub fn attach(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        object: Detached,
    ) -> Result<(EdgeHandle, Option<Detached>), Error> {
        edge_record_size(name)?;
        let target = self.inode(storage, object.object.number())?;
        if target.object() != object.object || target.generation != object.generation {
            return Err(Error::NotFound);
        }
        if let Object::Node(node) = object.object {
            let mut ancestor = parent;
            for _ in 0..self.inodes_count {
                if ancestor == node {
                    return Err(Error::InvalidArgument);
                }
                let next = self.back_edge(storage, ancestor)?;
                if next == ancestor {
                    break;
                }
                ancestor = next;
            }
        }
        let inserted = self.insert_edge(storage, parent, name, target)?;
        let displaced = if let Some(number) = inserted.replaced {
            let inode = self.inode(storage, number)?;
            if let Object::Node(node) = inode.object() {
                self.set_back_edge(storage, node, node)?;
                let parent_inode = self.inode(storage, parent.number())?;
                self.change_references(storage, Object::Node(parent), parent_inode.generation, -1)?;
            }
            Some(Detached {
                object: inode.object(),
                generation: inode.generation,
            })
        } else {
            None
        };
        if let Object::Node(node) = object.object {
            self.set_back_edge(storage, node, parent)?;
            let parent_inode = self.inode(storage, parent.number())?;
            self.change_references(storage, Object::Node(parent), parent_inode.generation, 1)?;
        }
        Ok((
            EdgeHandle {
                node: parent.number(),
                object: target.number,
                offset: inserted.offset as u64,
            },
            displaced,
        ))
    }

    pub fn release(&mut self, storage: &mut dyn Storage, object: Detached) -> Result<(), Error> {
        let inode = self.inode(storage, object.object.number())?;
        if inode.generation != object.generation || inode.object() != object.object {
            return Err(Error::NotFound);
        }
        let last = match object.object {
            Object::Blob(_) => 1,
            Object::Node(node) => {
                let mut occupied = false;
                self.edges(storage, node, EdgeCursor::START, &mut |_| {
                    occupied = true;
                    Ok(false)
                })?;
                if occupied {
                    return Err(Error::NotEmpty);
                }
                2
            }
        };
        if inode.references < last {
            return Err(Corrupt::InvalidInode(inode.number).into());
        }
        if inode.references > last {
            self.change_references(storage, object.object, object.generation, -1)?;
            return Ok(());
        }
        self.resize_object(storage, object.object, 0)?;
        let released = self.edit_inode(storage, inode.number, &mut |base, current| {
            if current.generation != inode.generation || current.object() != object.object {
                return Err(Error::NotFound);
            }
            base.links_count.set(0);
            // Ext4 uses a non-zero deletion time to distinguish a reclaimed
            // inode from an allocated zero-link orphan.
            // No clock is part of the graph storage interface.  Use a valid
            // non-zero Unix timestamp sentinel, not a small value which ext4
            // can mistake for an inode number in the legacy orphan chain.
            base.deletion_time.set(1_700_000_000);
            Ok(())
        })?;
        self.release_inode(storage, released)
    }
}

fn record_at<T: Pod>(bytes: &[u8], offset: usize) -> Result<T, Error> {
    bytes
        .get(offset..offset + size_of::<T>())
        .map(bytemuck::pod_read_unaligned)
        .ok_or(Corrupt::ReadPastEnd.into())
}

fn write_record_at<T: Pod>(bytes: &mut [u8], offset: usize, record: &T) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset + size_of::<T>())
        .ok_or(Corrupt::ReadPastEnd)?
        .copy_from_slice(bytemuck::bytes_of(record));
    Ok(())
}

fn read_records<T: Pod>(bytes: &[u8], offset: usize, count: usize) -> Result<Vec<T>, Error> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| Error::OutOfMemory)?;
    for index in 0..count {
        records.push(record_at(bytes, offset + index * size_of::<T>())?);
    }
    Ok(records)
}

fn write_records<T: Pod>(bytes: &mut [u8], offset: usize, records: &[T]) -> Result<(), Error> {
    let length = records
        .len()
        .checked_mul(size_of::<T>())
        .ok_or(Corrupt::AddressOverflow)?;
    bytes
        .get_mut(offset..offset + length)
        .ok_or(Corrupt::ReadPastEnd)?
        .copy_from_slice(bytemuck::cast_slice(records));
    Ok(())
}

fn validate_extents(extents: &[Extent]) -> Result<(), Error> {
    let mut previous = 0;
    for (index, extent) in extents.iter().enumerate() {
        if extent.blocks() == 0
            || extent.physical() == 0
            || extent.physical() >> 48 != 0
            || index != 0 && extent.logical() < previous
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        previous = extent.end();
    }
    Ok(())
}

fn merge_extents(extents: &mut Vec<Extent>) {
    let mut write = 0;
    for read in 0..extents.len() {
        let extent = extents[read];
        if write != 0 && extents[write - 1].append(extent) {
            continue;
        }
        extents[write] = extent;
        write += 1;
    }
    extents.truncate(write);
}

fn validate_indexes(indexes: &[ExtentIndex]) -> Result<(), Error> {
    if indexes.is_empty() {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut previous = None;
    for index in indexes {
        if index.block() == 0
            || index.block() >> 48 != 0
            || previous.is_some_and(|logical| index.logical() <= logical)
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        previous = Some(index.logical());
    }
    Ok(())
}

fn read_storage(storage: &mut dyn Storage, offset: u64, output: &mut [u8]) -> Result<(), Error> {
    let end = offset
        .checked_add(output.len() as u64)
        .filter(|end| *end <= storage.len())
        .ok_or(Corrupt::ReadPastEnd)?;
    let _ = end;
    storage.read(offset, output).map_err(Error::Storage)
}

fn read_record<T: Pod + Zeroable>(storage: &mut dyn Storage, offset: u64) -> Result<T, Error> {
    let mut record = T::zeroed();
    read_storage(storage, offset, bytemuck::bytes_of_mut(&mut record))?;
    Ok(record)
}

fn write_record<T: Pod>(storage: &mut dyn Storage, offset: u64, record: &T) -> Result<(), Error> {
    write_storage(storage, offset, bytemuck::bytes_of(record))
}

fn decode_inode(number: u32, base: Inode128) -> Result<Inode, Error> {
    let mode = base.mode.get();
    let references = base.links_count.get();
    // A final release writes links_count = 0 before returning the decoded
    // record to the inode-bitmap reclamation step.  Public lookup rejects
    // such records in `inode`; decoding itself must still describe them.
    if mode == 0 {
        return Err(Corrupt::InvalidInode(number).into());
    }
    let os_data = bytemuck::pod_read_unaligned::<LinuxInodeOsData2>(&base.os_dependent_2);
    Ok(Inode {
        number,
        mode,
        size: u64::from(base.size_lo.get()) | (u64::from(base.size_hi.get()) << 32),
        references,
        blocks_512: u64::from(base.blocks_lo.get()) | (u64::from(os_data.blocks_hi.get()) << 32),
        flags: base.flags.get(),
        generation: base.generation.get(),
        block: base.block,
        owner: u32::from(base.uid_lo.get()) | (u32::from(os_data.uid_hi.get()) << 16),
        group: u32::from(base.gid_lo.get()) | (u32::from(os_data.gid_hi.get()) << 16),
        accessed: base.access_time.get(),
        modified: base.modification_time.get(),
        changed: base.change_time.get(),
    })
}

fn write_storage(storage: &mut dyn Storage, offset: u64, input: &[u8]) -> Result<(), Error> {
    offset
        .checked_add(input.len() as u64)
        .filter(|end| *end <= storage.len())
        .ok_or(Corrupt::ReadPastEnd)?;
    storage.write(offset, input).map_err(Error::Storage)
}

fn write_edge_record(
    bytes: &mut [u8],
    block_size: usize,
    offset: usize,
    inode: u32,
    length: usize,
    name: &[u8],
    file_type: u8,
) -> Result<(), Error> {
    if inode == 0
        || name.len() > 255
        || length < size_of::<DirectoryEntryHeader>() + name.len()
        || !length.is_multiple_of(4)
        || offset
            .checked_add(length)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(Corrupt::InvalidDirectory.into());
    }
    bytes[offset..offset + length].fill(0);
    let mut header = DirectoryEntryHeader::zeroed();
    header.inode.set(inode);
    header.record_length = directory_record_length_to_disk(length, block_size)?;
    header.name_length = name.len() as u8;
    header.file_type = file_type;
    let header_end = offset + size_of::<DirectoryEntryHeader>();
    bytes[offset..header_end].copy_from_slice(bytemuck::bytes_of(&header));
    bytes[header_end..header_end + name.len()].copy_from_slice(name);
    Ok(())
}

fn edge_record_size(name: &[u8]) -> Result<usize, Error> {
    if name.is_empty() || name.len() > 255 || name == b"." || name == b".." || name.contains(&b'/')
    {
        return Err(Error::InvalidArgument);
    }
    Ok((size_of::<DirectoryEntryHeader>() + name.len() + 3) & !3)
}

fn insert_edge_record(
    bytes: &mut [u8],
    block_size: usize,
    end: usize,
    name: &[u8],
    object: u32,
    file_type: u8,
) -> Result<Option<EdgeInsertion>, Error> {
    let needed = edge_record_size(name)?;
    let mut offset = 0;
    let mut slot = None;
    while offset < end {
        let mut entry = record_at::<DirectoryEntryHeader>(bytes, offset)?;
        let length = directory_record_length(entry.record_length, block_size);
        let name_length = usize::from(entry.name_length);
        let used = (size_of::<DirectoryEntryHeader>() + name_length + 3) & !3;
        if length < used || !length.is_multiple_of(4) || offset + length > end {
            return Err(Corrupt::InvalidDirectory.into());
        }
        let existing = &bytes[offset + size_of::<DirectoryEntryHeader>()
            ..offset + size_of::<DirectoryEntryHeader>() + name_length];
        if entry.inode.get() != 0 && existing == name {
            let replaced = entry.inode.get();
            entry.inode.set(object);
            entry.file_type = file_type;
            write_record_at(bytes, offset, &entry)?;
            return Ok(Some(EdgeInsertion {
                offset,
                replaced: Some(replaced),
            }));
        }
        if slot.is_none() {
            if entry.inode.get() == 0 && length >= needed {
                slot = Some((offset, length, None));
            } else if entry.inode.get() != 0 && length - used >= needed {
                slot = Some((offset + used, length - used, Some((offset, used))));
            }
        }
        offset += length;
    }
    if offset != end {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let Some((offset, available, split)) = slot else {
        return Ok(None);
    };
    if let Some((previous, used)) = split {
        let mut shortened = record_at::<DirectoryEntryHeader>(bytes, previous)?;
        shortened.record_length = directory_record_length_to_disk(used, block_size)?;
        write_record_at(bytes, previous, &shortened)?;
    }
    write_edge_record(
        bytes, block_size, offset, object, available, name, file_type,
    )?;
    Ok(Some(EdgeInsertion {
        offset,
        replaced: None,
    }))
}

fn remove_edge_record(
    bytes: &mut [u8],
    block_size: usize,
    end: usize,
    wanted: usize,
    object: u32,
) -> Result<(), Error> {
    let mut offset = 0;
    let mut previous = None;
    while offset < end {
        let mut entry = record_at::<DirectoryEntryHeader>(bytes, offset)?;
        let length = directory_record_length(entry.record_length, block_size);
        let name_length = usize::from(entry.name_length);
        if length < size_of::<DirectoryEntryHeader>() + name_length
            || !length.is_multiple_of(4)
            || offset + length > end
        {
            return Err(Corrupt::InvalidDirectory.into());
        }
        if offset == wanted {
            let name = &bytes[offset + size_of::<DirectoryEntryHeader>()
                ..offset + size_of::<DirectoryEntryHeader>() + name_length];
            if entry.inode.get() != object || matches!(name, b"." | b"..") {
                return Err(Error::NotFound);
            }
            if let Some(previous) = previous {
                let mut left = record_at::<DirectoryEntryHeader>(bytes, previous)?;
                let combined = directory_record_length(left.record_length, block_size)
                    .checked_add(length)
                    .ok_or(Corrupt::InvalidDirectory)?;
                left.record_length = directory_record_length_to_disk(combined, block_size)?;
                write_record_at(bytes, previous, &left)?;
            } else {
                entry.inode.set(0);
                entry.name_length = 0;
                entry.file_type = 0;
                write_record_at(bytes, offset, &entry)?;
            }
            return Ok(());
        }
        previous = Some(offset);
        offset += length;
    }
    Err(Error::NotFound)
}

pub(crate) fn directory_record_length(record: Le16, block_size: usize) -> usize {
    let length = usize::from(record.get());
    if block_size == 65536 {
        if length == usize::from(u16::MAX) || length == 0 {
            block_size
        } else {
            (length & 65532) | ((length & 3) << 16)
        }
    } else {
        length
    }
}

pub(crate) fn directory_record_length_to_disk(
    length: usize,
    block_size: usize,
) -> Result<Le16, Error> {
    if length > block_size || !length.is_multiple_of(4) {
        return Err(Corrupt::InvalidDirectory.into());
    }
    let encoded = if length < 65536 {
        length
    } else if length == block_size && block_size == 65536 {
        usize::from(u16::MAX)
    } else {
        (length & 65532) | ((length >> 16) & 3)
    };
    u16::try_from(encoded)
        .map(Le16::new)
        .map_err(|_| Corrupt::InvalidDirectory.into())
}

/// The 1024-byte superblock stored at byte 1024 (and in backup locations).
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct Superblock {
    pub inodes_count: Le32,
    pub blocks_count_lo: Le32,
    pub reserved_blocks_count_lo: Le32,
    pub free_blocks_count_lo: Le32,
    pub free_inodes_count: Le32,
    pub first_data_block: Le32,
    pub log_block_size: Le32,
    pub log_cluster_size: Le32,
    pub blocks_per_group: Le32,
    pub clusters_per_group: Le32,
    pub inodes_per_group: Le32,
    pub mount_time: Le32,
    pub write_time: Le32,
    pub mount_count: Le16,
    pub max_mount_count: Le16,
    pub magic: Le16,
    pub state: Le16,
    pub errors: Le16,
    pub minor_revision_level: Le16,
    pub last_check: Le32,
    pub check_interval: Le32,
    pub creator_os: Le32,
    pub revision_level: Le32,
    pub default_reserved_uid: Le16,
    pub default_reserved_gid: Le16,
    pub first_inode: Le32,
    pub inode_size: Le16,
    pub block_group_number: Le16,
    pub feature_compat: Le32,
    pub feature_incompat: Le32,
    pub feature_read_only_compat: Le32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algorithm_usage_bitmap: Le32,
    pub prealloc_blocks: u8,
    pub prealloc_directory_blocks: u8,
    pub reserved_gdt_blocks: Le16,
    pub journal_uuid: [u8; 16],
    pub journal_inode: Le32,
    pub journal_device: Le32,
    pub last_orphan: Le32,
    pub hash_seed: [Le32; 4],
    pub default_hash_version: u8,
    pub journal_backup_type: u8,
    pub desc_size: Le16,
    pub default_mount_options: Le32,
    pub first_meta_block_group: Le32,
    pub mkfs_time: Le32,
    pub journal_blocks: [Le32; 17],
    pub blocks_count_hi: Le32,
    pub reserved_blocks_count_hi: Le32,
    pub free_blocks_count_hi: Le32,
    pub min_extra_inode_size: Le16,
    pub wanted_extra_inode_size: Le16,
    pub flags: Le32,
    pub raid_stride: Le16,
    pub mmp_update_interval: Le16,
    pub mmp_block: Le64,
    pub raid_stripe_width: Le32,
    pub log_groups_per_flex: u8,
    pub checksum_type: u8,
    pub encryption_level: u8,
    pub reserved_pad: u8,
    pub kilobytes_written: Le64,
    pub snapshot_inode: Le32,
    pub snapshot_id: Le32,
    pub snapshot_reserved_blocks_count: Le64,
    pub snapshot_list: Le32,
    pub error_count: Le32,
    pub first_error_time: Le32,
    pub first_error_inode: Le32,
    pub first_error_block: Le64,
    pub first_error_function: [u8; 32],
    pub first_error_line: Le32,
    pub last_error_time: Le32,
    pub last_error_inode: Le32,
    pub last_error_line: Le32,
    pub last_error_block: Le64,
    pub last_error_function: [u8; 32],
    pub mount_options: [u8; 64],
    pub user_quota_inode: Le32,
    pub group_quota_inode: Le32,
    pub overhead_clusters: Le32,
    pub backup_block_groups: [Le32; 2],
    pub encryption_algorithms: [u8; 4],
    pub encryption_password_salt: [u8; 16],
    pub lost_and_found_inode: Le32,
    pub project_quota_inode: Le32,
    pub checksum_seed: Le32,
    pub write_time_hi: u8,
    pub mount_time_hi: u8,
    pub mkfs_time_hi: u8,
    pub last_check_hi: u8,
    pub first_error_time_hi: u8,
    pub last_error_time_hi: u8,
    pub first_error_error_code: u8,
    pub last_error_error_code: u8,
    pub encoding: Le16,
    pub encoding_flags: Le16,
    pub orphan_file_inode: Le32,
    pub reserved: [Le32; 94],
    pub checksum: Le32,
}

/// The original 32-byte block-group descriptor.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct GroupDescriptor32 {
    pub block_bitmap_lo: Le32,
    pub inode_bitmap_lo: Le32,
    pub inode_table_lo: Le32,
    pub free_blocks_count_lo: Le16,
    pub free_inodes_count_lo: Le16,
    pub used_directories_count_lo: Le16,
    pub flags: Le16,
    pub exclude_bitmap_lo: Le32,
    pub block_bitmap_checksum_lo: Le16,
    pub inode_bitmap_checksum_lo: Le16,
    pub unused_inode_table_count_lo: Le16,
    pub checksum: Le16,
}

/// The 64-byte descriptor used when the 64-bit filesystem feature is active.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct GroupDescriptor64 {
    pub lo: GroupDescriptor32,
    pub block_bitmap_hi: Le32,
    pub inode_bitmap_hi: Le32,
    pub inode_table_hi: Le32,
    pub free_blocks_count_hi: Le16,
    pub free_inodes_count_hi: Le16,
    pub used_directories_count_hi: Le16,
    pub unused_inode_table_count_hi: Le16,
    pub exclude_bitmap_hi: Le32,
    pub block_bitmap_checksum_hi: Le16,
    pub inode_bitmap_checksum_hi: Le16,
    pub reserved: Le32,
}

/// The mandatory first 128 bytes of every inode-table record.
///
/// `block` is intentionally opaque: depending on inode flags and type it is a
/// legacy block map, an extent-tree root, inline bytes, or a fast symlink.
/// The OS-dependent fields are likewise uninterpreted ext4 payload.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct Inode128 {
    pub mode: Le16,
    pub uid_lo: Le16,
    pub size_lo: Le32,
    pub access_time: Le32,
    pub change_time: Le32,
    pub modification_time: Le32,
    pub deletion_time: Le32,
    pub gid_lo: Le16,
    pub links_count: Le16,
    pub blocks_lo: Le32,
    pub flags: Le32,
    pub os_dependent_1: [u8; 4],
    pub block: [u8; 60],
    pub generation: Le32,
    pub file_acl_lo: Le32,
    pub size_hi: Le32,
    pub obsolete_fragment_address: Le32,
    pub os_dependent_2: [u8; 12],
}

/// The currently defined 32-byte extension immediately following `Inode128`.
/// An inode record may be larger; `extra_inode_size` says how much is valid.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct InodeExtra32 {
    pub extra_inode_size: Le16,
    pub checksum_hi: Le16,
    pub change_time_extra: Le32,
    pub modification_time_extra: Le32,
    pub access_time_extra: Le32,
    pub creation_time: Le32,
    pub creation_time_extra: Le32,
    pub version_hi: Le32,
    pub project_id: Le32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct Inode160 {
    pub base: Inode128,
    pub extra: InodeExtra32,
}

/// Linux interpretation of the otherwise creator-OS-specific inode tail.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct LinuxInodeOsData2 {
    blocks_hi: Le16,
    file_acl_hi: Le16,
    uid_hi: Le16,
    gid_hi: Le16,
    checksum_lo: Le16,
    reserved: Le16,
}

/// The legacy interpretation of the inode's 60-byte `block` payload.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct LegacyBlockMap {
    pub direct: [Le32; 12],
    pub indirect: Le32,
    pub double_indirect: Le32,
    pub triple_indirect: Le32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct ExtentHeader {
    pub magic: Le16,
    pub entries: Le16,
    pub max_entries: Le16,
    pub depth: Le16,
    pub generation: Le32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct Extent {
    pub logical_block: Le32,
    pub length: Le16,
    pub physical_start_hi: Le16,
    pub physical_start_lo: Le32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct ExtentIndex {
    pub logical_block: Le32,
    pub child_lo: Le32,
    pub child_hi: Le16,
    pub unused: Le16,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct ExtentLeafRoot {
    pub header: ExtentHeader,
    pub entries: [Extent; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct ExtentIndexRoot {
    pub header: ExtentHeader,
    pub entries: [ExtentIndex; 4],
}

/// Fixed prefix of a variable-length directory entry.
///
/// `name_length` name bytes follow this header. `record_length`, not the name
/// length, selects the next aligned entry.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct DirectoryEntryHeader {
    pub inode: Le32,
    pub record_length: Le16,
    pub name_length: u8,
    pub file_type: u8,
}

/// Checksum pseudo-entry occupying the final 12 bytes of a directory block.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct DirectoryEntryTail {
    pub reserved_zero_1: Le32,
    pub record_length: Le16,
    pub reserved_zero_2: u8,
    pub reserved_file_type: u8,
    pub checksum: Le32,
}

/// Header of an external extended-attribute block.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct XattrHeader {
    pub magic: Le32,
    pub reference_count: Le32,
    pub blocks: Le32,
    pub hash: Le32,
    pub checksum: Le32,
    pub reserved: [Le32; 3],
}

/// Fixed prefix of an extended-attribute entry; its padded name follows.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct XattrEntryHeader {
    pub name_length: u8,
    pub name_index: u8,
    pub value_offset: Le16,
    pub value_inode: Le32,
    pub value_size: Le32,
    pub hash: Le32,
}

const _: [(); 2] = [(); size_of::<Le16>()];
const _: [(); 4] = [(); size_of::<Le32>()];
const _: [(); 8] = [(); size_of::<Le64>()];
const _: [(); SUPERBLOCK_SIZE] = [(); size_of::<Superblock>()];
const _: [(); GROUP_DESCRIPTOR32_SIZE] = [(); size_of::<GroupDescriptor32>()];
const _: [(); GROUP_DESCRIPTOR64_SIZE] = [(); size_of::<GroupDescriptor64>()];
const _: [(); INODE_BASE_SIZE] = [(); size_of::<Inode128>()];
const _: [(); 32] = [(); size_of::<InodeExtra32>()];
const _: [(); 160] = [(); size_of::<Inode160>()];
const _: [(); 12] = [(); size_of::<LinuxInodeOsData2>()];
const _: [(); 60] = [(); size_of::<LegacyBlockMap>()];
const _: [(); 12] = [(); size_of::<ExtentHeader>()];
const _: [(); 12] = [(); size_of::<Extent>()];
const _: [(); 12] = [(); size_of::<ExtentIndex>()];
const _: [(); 60] = [(); size_of::<ExtentLeafRoot>()];
const _: [(); 60] = [(); size_of::<ExtentIndexRoot>()];
const _: [(); 8] = [(); size_of::<DirectoryEntryHeader>()];
const _: [(); 12] = [(); size_of::<DirectoryEntryTail>()];
const _: [(); 32] = [(); size_of::<XattrHeader>()];
const _: [(); 16] = [(); size_of::<XattrEntryHeader>()];
