//! In-memory model and edits for an ext4 extent tree.
//!
//! The inode root and external extent blocks have different capacities, but
//! they contain the same recursive data structure.  This module keeps that
//! distinction at the serialization boundary: insertion, removal, splitting,
//! promotion, and root collapse are expressed once for every legal depth.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{Corrupt, EXTENT_MAGIC, Error, Unsupported, try_insert, try_push, zeroed_bytes};
use alloc::vec::Vec;
use core::ops::Range;

pub(crate) const MAX_DEPTH: u16 = 5;
pub(crate) const ROOT_CAPACITY: usize = 4;
pub(crate) const WRITTEN_MAX_LEN: u32 = 32_768;
pub(crate) const UNWRITTEN_MAX_LEN: u32 = 32_767;

#[derive(Clone, Copy)]
pub(crate) struct ExtentIdentity {
    pub(crate) checksum_seed: u32,
    pub(crate) inode: u32,
    pub(crate) generation: u32,
    pub(crate) metadata_checksums: bool,
}

pub(crate) struct SerializedNode {
    pub(crate) number: u64,
    pub(crate) bytes: Vec<u8>,
}

type LogicalRange = Range<u64>;

pub(crate) struct Holes {
    ranges: Vec<LogicalRange>,
    pub(crate) blocks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtentState {
    Written,
    Unwritten,
}

/// One ext4 leaf record, in decoded form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Extent {
    pub(crate) logical: u32,
    pub(crate) physical: u64,
    pub(crate) length: u32,
    pub(crate) state: ExtentState,
}

/// One inode-resident extent-tree index record. Unlike an external
/// [`ExtentNode`], this is only a reference: loading the tree resolves it to
/// the child node stored in `block`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExtentIndex {
    pub(crate) logical: u32,
    pub(crate) block: u64,
}

/// The typed contents of the inode's fixed 60-byte extent-tree root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExtentRootEntries {
    Leaf(Vec<Extent>),
    Branch {
        depth: u16,
        indexes: Vec<ExtentIndex>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExtentRoot {
    pub(crate) generation: u32,
    pub(crate) entries: ExtentRootEntries,
    padding: Vec<u8>,
}

impl ExtentRoot {
    pub(crate) fn empty() -> Self {
        Self {
            generation: 0,
            entries: ExtentRootEntries::Leaf(Vec::new()),
            padding: alloc::vec![0; ROOT_CAPACITY * 12],
        }
    }

    pub(crate) fn single(extent: Extent) -> Self {
        Self {
            generation: 0,
            entries: ExtentRootEntries::Leaf(alloc::vec![extent]),
            padding: alloc::vec![0; (ROOT_CAPACITY - 1) * 12],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let depth = extent_header(bytes, ROOT_CAPACITY)?;
        if depth > MAX_DEPTH {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        let count = usize::from(le16(bytes, 2));
        if depth == 0 {
            let mut extents = Vec::new();
            extents
                .try_reserve_exact(count)
                .map_err(|_| Error::OutOfMemory)?;
            for index in 0..count {
                let at = 12 + index * 12;
                let encoded_length = le16(bytes, at + 4);
                let (length, state) = if encoded_length <= WRITTEN_MAX_LEN as u16 {
                    (u32::from(encoded_length), ExtentState::Written)
                } else {
                    (
                        u32::from(encoded_length) - WRITTEN_MAX_LEN,
                        ExtentState::Unwritten,
                    )
                };
                extents.push(Extent::new(
                    le32(bytes, at),
                    u64::from(le32(bytes, at + 8)) | (u64::from(le16(bytes, at + 6)) << 32),
                    length,
                    state,
                )?);
            }
            let mut padding = zeroed_bytes(60 - (12 + count * 12))?;
            padding.copy_from_slice(&bytes[12 + count * 12..60]);
            Ok(Self {
                generation: le32(bytes, 8),
                entries: ExtentRootEntries::Leaf(extents),
                padding,
            })
        } else {
            let mut indexes = Vec::new();
            indexes
                .try_reserve_exact(count)
                .map_err(|_| Error::OutOfMemory)?;
            let mut previous = None;
            for index in 0..count {
                let at = 12 + index * 12;
                let logical = le32(bytes, at);
                if previous.is_some_and(|value| logical <= value) {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                previous = Some(logical);
                indexes.push(ExtentIndex {
                    logical,
                    block: u64::from(le32(bytes, at + 4)) | (u64::from(le16(bytes, at + 8)) << 32),
                });
            }
            let mut padding = zeroed_bytes(60 - (12 + count * 12))?;
            padding.copy_from_slice(&bytes[12 + count * 12..60]);
            Ok(Self {
                generation: le32(bytes, 8),
                entries: ExtentRootEntries::Branch { depth, indexes },
                padding,
            })
        }
    }

    pub(crate) fn encode(&self, target: &mut [u8]) -> Result<(), Error> {
        if target.len() < 60 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        target.fill(0);
        put_le16(target, 0, EXTENT_MAGIC);
        put_le16(target, 4, ROOT_CAPACITY as u16);
        put_le32(target, 8, self.generation);
        match &self.entries {
            ExtentRootEntries::Leaf(extents) => {
                if extents.len() > ROOT_CAPACITY {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                put_le16(target, 2, extents.len() as u16);
                for (index, extent) in extents.iter().enumerate() {
                    let at = 12 + index * 12;
                    let length = match extent.state {
                        ExtentState::Written => extent.length,
                        ExtentState::Unwritten => extent.length + WRITTEN_MAX_LEN,
                    };
                    put_le32(target, at, extent.logical);
                    put_le16(target, at + 4, length as u16);
                    put_le16(target, at + 6, (extent.physical >> 32) as u16);
                    put_le32(target, at + 8, extent.physical as u32);
                }
                if self.padding.len() != (ROOT_CAPACITY - extents.len()) * 12 {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                target[12 + extents.len() * 12..].copy_from_slice(&self.padding);
            }
            ExtentRootEntries::Branch { depth, indexes } => {
                if *depth == 0
                    || *depth > MAX_DEPTH
                    || indexes.is_empty()
                    || indexes.len() > ROOT_CAPACITY
                {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                put_le16(target, 2, indexes.len() as u16);
                put_le16(target, 6, *depth);
                for (index, entry) in indexes.iter().enumerate() {
                    let at = 12 + index * 12;
                    put_le32(target, at, entry.logical);
                    put_le32(target, at + 4, entry.block as u32);
                    put_le16(target, at + 8, (entry.block >> 32) as u16);
                }
                if self.padding.len() != (ROOT_CAPACITY - indexes.len()) * 12 {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                target[12 + indexes.len() * 12..].copy_from_slice(&self.padding);
            }
        }
        Ok(())
    }
}

impl Extent {
    pub(crate) fn new(
        logical: u32,
        physical: u64,
        length: u32,
        state: ExtentState,
    ) -> Result<Self, Error> {
        let max = match state {
            ExtentState::Written => WRITTEN_MAX_LEN,
            ExtentState::Unwritten => UNWRITTEN_MAX_LEN,
        };
        if length == 0
            || length > max
            || physical == 0
            || physical >> 48 != 0
            || physical
                .checked_add(u64::from(length))
                .is_none_or(|end| end > (1_u64 << 48))
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        Ok(Self {
            logical,
            physical,
            length,
            state,
        })
    }

    pub(crate) fn logical_end(self) -> u64 {
        u64::from(self.logical) + u64::from(self.length)
    }

    fn overlaps(self, start: u64, end: u64) -> bool {
        u64::from(self.logical) < end && start < self.logical_end()
    }

    fn can_merge(self, right: Self) -> bool {
        let max = match self.state {
            ExtentState::Written => WRITTEN_MAX_LEN,
            ExtentState::Unwritten => UNWRITTEN_MAX_LEN,
        };
        self.state == right.state
            && self.logical_end() == u64::from(right.logical)
            && self.physical + u64::from(self.length) == right.physical
            && self.length + right.length <= max
    }
}

#[derive(Debug)]
pub(crate) enum NodeEntries {
    Leaf(Vec<Extent>),
    Branch(Vec<ExtentNode>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeLocation {
    Root,
    Block(u64),
    Unassigned,
}

/// One decoded node. Its storage location is explicit so inode-root handling
/// cannot accidentally be confused with allocation of a newly split node.
#[derive(Debug)]
pub(crate) struct ExtentNode {
    pub(crate) location: NodeLocation,
    pub(crate) dirty: bool,
    pub(crate) entries: NodeEntries,
}

impl ExtentNode {
    pub(crate) fn leaf(location: NodeLocation, extents: Vec<Extent>) -> Self {
        Self {
            location,
            dirty: false,
            entries: NodeEntries::Leaf(extents),
        }
    }

    pub(crate) fn branch(location: NodeLocation, children: Vec<Self>) -> Self {
        Self {
            location,
            dirty: false,
            entries: NodeEntries::Branch(children),
        }
    }

    pub(crate) fn depth(&self) -> u16 {
        match &self.entries {
            NodeEntries::Leaf(_) => 0,
            NodeEntries::Branch(children) => children.first().map_or(1, |child| child.depth() + 1),
        }
    }

    pub(crate) fn first_logical(&self) -> Option<u32> {
        match &self.entries {
            NodeEntries::Leaf(extents) => extents.first().map(|extent| extent.logical),
            NodeEntries::Branch(children) => children.first().and_then(Self::first_logical),
        }
    }

    fn is_empty(&self) -> bool {
        match &self.entries {
            NodeEntries::Leaf(extents) => extents.is_empty(),
            NodeEntries::Branch(children) => children.is_empty(),
        }
    }

    #[inline(never)]
    fn validate(&self, block_capacity: usize, root: bool) -> Result<(), Error> {
        let capacity = if root { ROOT_CAPACITY } else { block_capacity };
        match &self.entries {
            NodeEntries::Leaf(extents) => {
                if extents.len() > capacity || (!root && extents.is_empty()) {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                let mut previous = None;
                for &extent in extents {
                    Extent::new(extent.logical, extent.physical, extent.length, extent.state)?;
                    if previous.is_some_and(|end| u64::from(extent.logical) < end) {
                        return Err(Corrupt::InvalidExtentTree.into());
                    }
                    previous = Some(extent.logical_end());
                }
            }
            NodeEntries::Branch(children) => {
                if children.is_empty() || children.len() > capacity {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                let child_depth = children[0].depth();
                let mut previous = None;
                for child in children {
                    if child.depth() != child_depth
                        || !matches!(child.location, NodeLocation::Block(_))
                    {
                        return Err(Corrupt::InvalidExtentTree.into());
                    }
                    let first = child.first_logical().ok_or(Corrupt::InvalidExtentTree)?;
                    if previous.is_some_and(|value| first <= value) {
                        return Err(Corrupt::InvalidExtentTree.into());
                    }
                    previous = Some(first);
                    child.validate(block_capacity, false)?;
                }
            }
        }
        if self.depth() > MAX_DEPTH {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        Ok(())
    }

    #[inline(never)]
    fn insert(
        &mut self,
        extent: Extent,
        capacity: usize,
        block_capacity: usize,
    ) -> Result<Option<Self>, Error> {
        match &mut self.entries {
            NodeEntries::Leaf(extents) => {
                let position = extents
                    .binary_search_by_key(&extent.logical, |entry| entry.logical)
                    .unwrap_or_else(|position| position);
                if position
                    .checked_sub(1)
                    .and_then(|left| extents.get(left))
                    .is_some_and(|left| left.logical_end() > u64::from(extent.logical))
                    || extents
                        .get(position)
                        .is_some_and(|right| u64::from(right.logical) < extent.logical_end())
                {
                    return Err(Corrupt::InvalidExtentTree.into());
                }
                try_insert(extents, position, extent)?;
                merge_leaf(extents);
                self.dirty = true;
            }
            NodeEntries::Branch(children) => {
                let position = children
                    .partition_point(|child| {
                        child
                            .first_logical()
                            .is_some_and(|key| key <= extent.logical)
                    })
                    .saturating_sub(1);
                let promoted = children[position].insert(extent, block_capacity, block_capacity)?;
                if let Some(promoted) = promoted {
                    try_insert(children, position + 1, promoted)?;
                }
                self.dirty = true;
            }
        }
        Ok(self.split_overflow(capacity))
    }

    #[inline(never)]
    fn set_state_range(
        &mut self,
        start: u64,
        end: u64,
        state: ExtentState,
        capacity: usize,
        block_capacity: usize,
    ) -> Result<Option<Self>, Error> {
        let changed = match &mut self.entries {
            NodeEntries::Leaf(extents) => {
                let mut changed = false;
                let mut output = Vec::new();
                output
                    .try_reserve_exact(extents.len() + 2)
                    .map_err(|_| Error::OutOfMemory)?;
                for extent in extents.drain(..) {
                    if extent.state == state || !extent.overlaps(start, end) {
                        output.push(extent);
                        continue;
                    }
                    changed = true;
                    let (before, mut middle, after) = split_extent(extent, start, end);
                    if let Some(before) = before {
                        output.push(before);
                    }
                    middle.state = state;
                    output.push(middle);
                    if let Some(after) = after {
                        output.push(after);
                    }
                }
                merge_leaf(&mut output);
                *extents = output;
                changed
            }
            NodeEntries::Branch(children) => {
                let mut changed = false;
                let mut index = child_at(children, start);
                while index < children.len() {
                    if u64::from(
                        children[index]
                            .first_logical()
                            .ok_or(Corrupt::InvalidExtentTree)?,
                    ) >= end
                    {
                        break;
                    }
                    let was_dirty = children[index].dirty;
                    let sibling = children[index].set_state_range(
                        start,
                        end,
                        state,
                        block_capacity,
                        block_capacity,
                    )?;
                    changed |= children[index].dirty != was_dirty || sibling.is_some();
                    if let Some(sibling) = sibling {
                        try_insert(children, index + 1, sibling)?;
                        index += 1;
                    }
                    index += 1;
                }
                changed
            }
        };
        self.dirty |= changed;
        Ok(self.split_overflow(capacity))
    }

    fn entry_count(&self) -> usize {
        match &self.entries {
            NodeEntries::Leaf(extents) => extents.len(),
            NodeEntries::Branch(children) => children.len(),
        }
    }

    #[inline(never)]
    fn split_overflow(&mut self, capacity: usize) -> Option<Self> {
        if self.entry_count() <= capacity {
            return None;
        }
        let entries = match &mut self.entries {
            NodeEntries::Leaf(extents) => NodeEntries::Leaf(extents.split_off(extents.len() / 2)),
            NodeEntries::Branch(children) => {
                NodeEntries::Branch(children.split_off(children.len() / 2))
            }
        };
        Some(Self {
            location: NodeLocation::Unassigned,
            dirty: true,
            entries,
        })
    }

    #[inline(never)]
    fn remove_range(
        &mut self,
        start: u64,
        end: u64,
        removed_extents: &mut Vec<Extent>,
        released_nodes: &mut Vec<u64>,
    ) -> Result<bool, Error> {
        let changed = match &mut self.entries {
            NodeEntries::Leaf(extents) => remove_from_leaf(extents, start, end, removed_extents)?,
            NodeEntries::Branch(children) => {
                let mut changed = false;
                let mut index = child_at(children, start);
                while index < children.len() {
                    if u64::from(
                        children[index]
                            .first_logical()
                            .ok_or(Corrupt::InvalidExtentTree)?,
                    ) >= end
                    {
                        break;
                    }
                    changed |= children[index].remove_range(
                        start,
                        end,
                        removed_extents,
                        released_nodes,
                    )?;
                    if children[index].is_empty() {
                        let child = children.remove(index);
                        collect_blocks(child, released_nodes)?;
                        changed = true;
                    } else {
                        index += 1;
                    }
                }
                changed
            }
        };
        self.dirty |= changed;
        Ok(changed)
    }

    #[inline(never)]
    fn assign_new_blocks(&mut self, blocks: &mut impl Iterator<Item = u64>) -> Result<(), Error> {
        if self.location == NodeLocation::Unassigned {
            self.location = NodeLocation::Block(blocks.next().ok_or(Corrupt::InvalidExtentTree)?);
        }
        if let NodeEntries::Branch(children) = &mut self.entries {
            for child in children {
                child.assign_new_blocks(blocks)?;
            }
        }
        Ok(())
    }

    fn count_unassigned(&self) -> usize {
        usize::from(self.location == NodeLocation::Unassigned)
            + match &self.entries {
                NodeEntries::Leaf(_) => 0,
                NodeEntries::Branch(children) => children.iter().map(Self::count_unassigned).sum(),
            }
    }
}

/// A complete decoded extent tree. The root is always the inode-resident node
/// and therefore never owns an external block number.
#[derive(Debug)]
pub(crate) struct ExtentTree {
    pub(crate) root: ExtentNode,
    block_capacity: usize,
    pub(crate) released_nodes: Vec<u64>,
    root_generation: u32,
    root_padding: Vec<u8>,
}

impl ExtentTree {
    #[inline(never)]
    pub(crate) fn load(
        root: &ExtentRoot,
        block_size: usize,
        blocks_count: u64,
        identity: ExtentIdentity,
        read_block: &mut dyn FnMut(u64) -> Result<Vec<u8>, Error>,
    ) -> Result<Self, Error> {
        let block_capacity = block_size
            .checked_sub(16)
            .ok_or(Corrupt::InvalidExtentTree)?
            / 12;
        if block_capacity <= ROOT_CAPACITY {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let root_generation = root.generation;
        let root_padding = root.padding.clone();
        let depth = match &root.entries {
            ExtentRootEntries::Leaf(_) => 0,
            ExtentRootEntries::Branch { depth, .. } => *depth,
        };
        if depth > MAX_DEPTH {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        let mut root_bytes = [0; 60];
        root.encode(&mut root_bytes)?;
        let mut visited = Vec::new();
        let root = load_node(
            &root_bytes,
            NodeLocation::Root,
            depth,
            ROOT_CAPACITY,
            block_capacity,
            blocks_count,
            identity,
            &mut visited,
            read_block,
        )?;
        let mut tree = Self::new(root, block_capacity)?;
        tree.root_generation = root_generation;
        tree.root_padding = root_padding;
        let extents = tree.data_extents()?;
        for (index, extent) in extents.iter().enumerate() {
            if index != 0 && u64::from(extent.logical) < extents[index - 1].logical_end() {
                return Err(Corrupt::InvalidExtentTree.into());
            }
            let end = extent
                .physical
                .checked_add(u64::from(extent.length))
                .filter(|end| *end <= blocks_count)
                .ok_or(Corrupt::InvalidExtentTree)?;
            if visited.contains(&extent.physical)
                || visited
                    .iter()
                    .any(|block| extent.physical < *block && *block < end)
                || extents[..index].iter().any(|previous| {
                    extent.physical < previous.physical + u64::from(previous.length)
                        && previous.physical < end
                })
            {
                return Err(Corrupt::InvalidExtentTree.into());
            }
        }
        Ok(tree)
    }

    pub(crate) fn new(root: ExtentNode, block_capacity: usize) -> Result<Self, Error> {
        if root.location != NodeLocation::Root || block_capacity <= ROOT_CAPACITY {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        root.validate(block_capacity, true)?;
        Ok(Self {
            root,
            block_capacity,
            released_nodes: Vec::new(),
            root_generation: 0,
            root_padding: alloc::vec![0; ROOT_CAPACITY * 12],
        })
    }

    /// Insert allocator-owned physical blocks. The loaded tree was already
    /// validated and the allocator guarantees physical uniqueness; rescanning
    /// every physical extent here would turn keyed insertion into O(n).
    /// Logical overlap is rejected at the destination leaf.
    #[inline(never)]
    pub(crate) fn insert(&mut self, extent: Extent) -> Result<(), Error> {
        Extent::new(extent.logical, extent.physical, extent.length, extent.state)?;
        let sibling = self
            .root
            .insert(extent, self.block_capacity, self.block_capacity)?;
        if sibling.is_some() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        self.finish_growth()
    }

    /// Remove mappings in `[start, end)`, trimming or splitting boundary
    /// extents and preserving the physical offset of any surviving suffix.
    #[inline(never)]
    pub(crate) fn remove(&mut self, start: u64, end: u64) -> Result<Vec<Extent>, Error> {
        if start >= end {
            return Ok(Vec::new());
        }
        let mut removed_extents = Vec::new();
        self.root
            .remove_range(start, end, &mut removed_extents, &mut self.released_nodes)?;
        while let NodeEntries::Branch(children) = &mut self.root.entries {
            if children.is_empty() {
                self.root = ExtentNode {
                    location: NodeLocation::Root,
                    dirty: true,
                    entries: NodeEntries::Leaf(Vec::new()),
                };
                break;
            }
            if children.len() != 1 {
                break;
            }
            let mut child = children.remove(0);
            if let NodeLocation::Block(block) = child.location {
                try_push(&mut self.released_nodes, block)?;
            }
            child.location = NodeLocation::Root;
            child.dirty = true;
            self.root = child;
        }
        self.root.location = NodeLocation::Root;
        Ok(removed_extents)
    }

    /// Change the initialized state of every mapped block in `[start, end)`.
    /// Holes remain holes. Boundary records are split as needed, then ordinary
    /// insertion performs all merging, node splitting, and root promotion.
    #[inline(never)]
    pub(crate) fn set_state(
        &mut self,
        start: u64,
        end: u64,
        state: ExtentState,
    ) -> Result<(), Error> {
        if start >= end {
            return Ok(());
        }
        let sibling = self.root.set_state_range(
            start,
            end,
            state,
            self.block_capacity,
            self.block_capacity,
        )?;
        if sibling.is_some() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        self.finish_growth()
    }

    #[inline(never)]
    fn finish_growth(&mut self) -> Result<(), Error> {
        if self.root.entry_count() > ROOT_CAPACITY {
            let mut old_root = core::mem::replace(
                &mut self.root,
                ExtentNode::leaf(NodeLocation::Root, Vec::new()),
            );
            old_root.location = NodeLocation::Unassigned;
            self.root = ExtentNode {
                location: NodeLocation::Root,
                dirty: true,
                entries: NodeEntries::Branch(alloc::vec![old_root]),
            };
        }
        if self.root.depth() > MAX_DEPTH {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        Ok(())
    }

    pub(crate) fn unassigned_blocks(&self) -> usize {
        match &self.root.entries {
            NodeEntries::Leaf(_) => 0,
            NodeEntries::Branch(children) => {
                children.iter().map(ExtentNode::count_unassigned).sum()
            }
        }
    }

    #[inline(never)]
    pub(crate) fn assign_blocks(&mut self, blocks: &[u64]) -> Result<(), Error> {
        if blocks.len() != self.unassigned_blocks()
            || blocks.iter().enumerate().any(|(index, block)| {
                *block == 0
                    || *block >> 48 != 0
                    || blocks[..index].contains(block)
                    || node_contains_block(&self.root, *block)
                    || node_contains_data_block(&self.root, *block)
            })
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let mut blocks = blocks.iter().copied();
        if let NodeEntries::Branch(children) = &mut self.root.entries {
            for child in children {
                child.assign_new_blocks(&mut blocks)?;
            }
        }
        if blocks.next().is_some() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        Ok(())
    }

    #[inline(never)]
    pub(crate) fn data_extents(&self) -> Result<Vec<Extent>, Error> {
        fn collect(node: &ExtentNode, out: &mut Vec<Extent>) -> Result<(), Error> {
            match &node.entries {
                NodeEntries::Leaf(extents) => {
                    out.try_reserve_exact(extents.len())
                        .map_err(|_| Error::OutOfMemory)?;
                    out.extend_from_slice(extents);
                }
                NodeEntries::Branch(children) => {
                    for child in children {
                        collect(child, out)?;
                    }
                }
            }
            Ok(())
        }
        let mut extents = Vec::new();
        collect(&self.root, &mut extents)?;
        Ok(extents)
    }

    #[inline(never)]
    pub(crate) fn stats(&self) -> Result<(u64, u64), Error> {
        fn collect(
            node: &ExtentNode,
            logical_end: &mut u64,
            blocks: &mut u64,
        ) -> Result<(), Error> {
            *blocks = blocks
                .checked_add(u64::from(node.location != NodeLocation::Root))
                .ok_or(Corrupt::AddressOverflow)?;
            match &node.entries {
                NodeEntries::Leaf(extents) => {
                    for extent in extents {
                        *logical_end = extent.logical_end();
                        *blocks = blocks
                            .checked_add(u64::from(extent.length))
                            .ok_or(Corrupt::AddressOverflow)?;
                    }
                }
                NodeEntries::Branch(children) => {
                    for child in children {
                        collect(child, logical_end, blocks)?;
                    }
                }
            }
            Ok(())
        }
        let mut logical_end = 0;
        let mut blocks = 0;
        collect(&self.root, &mut logical_end, &mut blocks)?;
        Ok((logical_end, blocks))
    }

    #[inline(never)]
    pub(crate) fn visit_owned_ranges(
        &self,
        visit: &mut dyn FnMut(u64, u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        fn walk(
            node: &ExtentNode,
            visit: &mut dyn FnMut(u64, u64) -> Result<(), Error>,
        ) -> Result<(), Error> {
            if let NodeLocation::Block(number) = node.location {
                visit(number, 1)?;
            }
            match &node.entries {
                NodeEntries::Leaf(extents) => {
                    for extent in extents {
                        visit(extent.physical, u64::from(extent.length))?;
                    }
                }
                NodeEntries::Branch(children) => {
                    for child in children {
                        walk(child, visit)?;
                    }
                }
            }
            Ok(())
        }
        walk(&self.root, visit)
    }

    pub(crate) fn lookup(&self, logical: u32) -> Option<(u64, ExtentState)> {
        fn find(node: &ExtentNode, logical: u32) -> Option<(u64, ExtentState)> {
            match &node.entries {
                NodeEntries::Leaf(extents) => {
                    let position = extents.partition_point(|extent| extent.logical <= logical);
                    let extent = extents.get(position.checked_sub(1)?)?;
                    (u64::from(logical) < extent.logical_end()).then_some((
                        extent.physical + u64::from(logical - extent.logical),
                        extent.state,
                    ))
                }
                NodeEntries::Branch(children) => {
                    let position = children.partition_point(|child| {
                        child.first_logical().is_some_and(|first| first <= logical)
                    });
                    find(children.get(position.checked_sub(1)?)?, logical)
                }
            }
        }
        find(&self.root, logical)
    }

    /// Return the unmapped runs in `[start, end)` by walking only the keyed
    /// branch range that can intersect it.
    #[inline(never)]
    pub(crate) fn holes(&self, start: u64, end: u64) -> Result<Holes, Error> {
        if start > end || end > 1_u64 << 32 {
            return Err(Corrupt::AddressOverflow.into());
        }
        let mut holes = Holes {
            ranges: Vec::new(),
            blocks: 0,
        };
        let mut cursor = start;
        collect_holes(&self.root, &mut cursor, end, &mut holes)?;
        push_hole(&mut holes, cursor, end)?;
        Ok(holes)
    }

    /// Map previously discovered holes to allocator-owned blocks, coalescing
    /// adjacent physical blocks into the largest legal extent records.
    #[inline(never)]
    pub(crate) fn fill_holes(
        &mut self,
        holes: &Holes,
        blocks: &[u64],
        state: ExtentState,
    ) -> Result<(), Error> {
        if blocks.len() != holes.blocks {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let max_length = match state {
            ExtentState::Written => WRITTEN_MAX_LEN,
            ExtentState::Unwritten => UNWRITTEN_MAX_LEN,
        } as usize;
        let mut block = 0usize;
        for hole in &holes.ranges {
            let length =
                usize::try_from(hole.end - hole.start).map_err(|_| Corrupt::AddressOverflow)?;
            let mut offset = 0usize;
            while offset < length {
                let physical = *blocks.get(block).ok_or(Corrupt::InvalidExtentTree)?;
                let mut run = 1usize;
                while run < max_length
                    && offset + run < length
                    && blocks.get(block + run).copied() == physical.checked_add(run as u64)
                {
                    run += 1;
                }
                self.insert(Extent::new(
                    u32::try_from(hole.start + offset as u64)
                        .map_err(|_| Corrupt::AddressOverflow)?,
                    physical,
                    run as u32,
                    state,
                )?)?;
                offset += run;
                block += run;
            }
        }
        debug_assert_eq!(block, blocks.len());
        Ok(())
    }

    pub(crate) fn root_record(&self) -> Result<ExtentRoot, Error> {
        let entries = match &self.root.entries {
            NodeEntries::Leaf(extents) => ExtentRootEntries::Leaf(extents.clone()),
            NodeEntries::Branch(children) => {
                let mut indexes = Vec::new();
                indexes
                    .try_reserve_exact(children.len())
                    .map_err(|_| Error::OutOfMemory)?;
                for child in children {
                    let NodeLocation::Block(block) = child.location else {
                        return Err(Corrupt::InvalidExtentTree.into());
                    };
                    indexes.push(ExtentIndex {
                        logical: child.first_logical().ok_or(Corrupt::InvalidExtentTree)?,
                        block,
                    });
                }
                ExtentRootEntries::Branch {
                    depth: self.root.depth(),
                    indexes,
                }
            }
        };
        let count = match &entries {
            ExtentRootEntries::Leaf(extents) => extents.len(),
            ExtentRootEntries::Branch { indexes, .. } => indexes.len(),
        };
        let padding = if self.root_padding.len() == (ROOT_CAPACITY - count) * 12 {
            self.root_padding.clone()
        } else {
            alloc::vec![0; (ROOT_CAPACITY - count) * 12]
        };
        Ok(ExtentRoot {
            generation: self.root_generation,
            entries,
            padding,
        })
    }

    #[inline(never)]
    pub(crate) fn serialize_dirty(
        &self,
        block_size: usize,
        identity: ExtentIdentity,
    ) -> Result<Vec<SerializedNode>, Error> {
        fn collect(
            node: &ExtentNode,
            block_size: usize,
            capacity: usize,
            identity: ExtentIdentity,
            out: &mut Vec<SerializedNode>,
        ) -> Result<(), Error> {
            if node.dirty {
                let NodeLocation::Block(number) = node.location else {
                    return Err(Corrupt::InvalidExtentTree.into());
                };
                let mut bytes = zeroed_bytes(block_size)?;
                write_node(&mut bytes, node, capacity)?;
                if identity.metadata_checksums {
                    let checksum_offset = 12 + capacity * 12;
                    let mut checksum = Checksum::with_seed(identity.checksum_seed);
                    checksum.update_u32_le(identity.inode);
                    checksum.update_u32_le(identity.generation);
                    checksum.update(&bytes[..checksum_offset]);
                    put_le32(&mut bytes, checksum_offset, checksum.finalize());
                }
                try_push(out, SerializedNode { number, bytes })?;
            }
            if let NodeEntries::Branch(children) = &node.entries {
                for child in children {
                    collect(child, block_size, capacity, identity, out)?;
                }
            }
            Ok(())
        }

        let capacity = block_size
            .checked_sub(16)
            .ok_or(Corrupt::InvalidExtentTree)?
            / 12;
        let mut nodes = Vec::new();
        if let NodeEntries::Branch(children) = &self.root.entries {
            for child in children {
                collect(child, block_size, capacity, identity, &mut nodes)?;
            }
        }
        Ok(nodes)
    }

    #[cfg(test)]
    fn extents(&self) -> Vec<Extent> {
        fn collect(node: &ExtentNode, out: &mut Vec<Extent>) {
            match &node.entries {
                NodeEntries::Leaf(extents) => out.extend_from_slice(extents),
                NodeEntries::Branch(children) => {
                    for child in children {
                        collect(child, out);
                    }
                }
            }
        }
        let mut result = Vec::new();
        collect(&self.root, &mut result);
        result
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn load_node(
    bytes: &[u8],
    location: NodeLocation,
    expected_depth: u16,
    capacity: usize,
    block_capacity: usize,
    blocks_count: u64,
    identity: ExtentIdentity,
    visited: &mut Vec<u64>,
    read_block: &mut dyn FnMut(u64) -> Result<Vec<u8>, Error>,
) -> Result<ExtentNode, Error> {
    let depth = extent_header(bytes, capacity)?;
    if depth != expected_depth {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let entries = usize::from(le16(bytes, 2));
    if depth == 0 {
        if location != NodeLocation::Root && entries == 0 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(entries)
            .map_err(|_| Error::OutOfMemory)?;
        for index in 0..entries {
            let at = 12 + index * 12;
            let encoded_length = le16(bytes, at + 4);
            let (length, state) = if encoded_length <= WRITTEN_MAX_LEN as u16 {
                (u32::from(encoded_length), ExtentState::Written)
            } else {
                (
                    u32::from(encoded_length) - WRITTEN_MAX_LEN,
                    ExtentState::Unwritten,
                )
            };
            extents.push(Extent::new(
                le32(bytes, at),
                u64::from(le32(bytes, at + 8)) | (u64::from(le16(bytes, at + 6)) << 32),
                length,
                state,
            )?);
        }
        return Ok(ExtentNode::leaf(location, extents));
    }
    if entries == 0 {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(entries)
        .map_err(|_| Error::OutOfMemory)?;
    let mut previous = None;
    for index in 0..entries {
        let at = 12 + index * 12;
        let logical = le32(bytes, at);
        if previous.is_some_and(|value| logical <= value) {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        previous = Some(logical);
        let number = u64::from(le32(bytes, at + 4)) | (u64::from(le16(bytes, at + 8)) << 32);
        if number == 0 || number >= blocks_count || visited.contains(&number) {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        try_push(visited, number)?;
        let child_bytes = read_block(number)?;
        if child_bytes.len() != 12 + block_capacity * 12 + 4 {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        verify_node_checksum(&child_bytes, block_capacity, identity)?;
        let child = load_node(
            &child_bytes,
            NodeLocation::Block(number),
            depth - 1,
            block_capacity,
            block_capacity,
            blocks_count,
            identity,
            visited,
            read_block,
        )?;
        if child.first_logical() != Some(logical) {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        children.push(child);
    }
    Ok(ExtentNode::branch(location, children))
}

fn extent_header(bytes: &[u8], capacity: usize) -> Result<u16, Error> {
    if bytes.len() < 12 + capacity * 12
        || le16(bytes, 0) != EXTENT_MAGIC
        || usize::from(le16(bytes, 2)) > capacity
        || usize::from(le16(bytes, 4)) != capacity
    {
        return Err(Corrupt::InvalidExtentHeader.into());
    }
    Ok(le16(bytes, 6))
}

fn verify_node_checksum(
    bytes: &[u8],
    capacity: usize,
    identity: ExtentIdentity,
) -> Result<(), Error> {
    if !identity.metadata_checksums {
        return Ok(());
    }
    let checksum_offset = 12 + capacity * 12;
    if checksum_offset + 4 > bytes.len() {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    let mut checksum = Checksum::with_seed(identity.checksum_seed);
    checksum.update_u32_le(identity.inode);
    checksum.update_u32_le(identity.generation);
    checksum.update(&bytes[..checksum_offset]);
    if checksum.finalize() != le32(bytes, checksum_offset) {
        return Err(Corrupt::ExtentChecksum(identity.inode).into());
    }
    Ok(())
}

#[inline(never)]
fn write_node(target: &mut [u8], node: &ExtentNode, capacity: usize) -> Result<(), Error> {
    if target.len() < 12 + capacity * 12 || node.entry_count() > capacity {
        return Err(Corrupt::InvalidExtentTree.into());
    }
    target.fill(0);
    put_le16(target, 0, EXTENT_MAGIC);
    put_le16(target, 2, node.entry_count() as u16);
    put_le16(target, 4, capacity as u16);
    put_le16(target, 6, node.depth());
    match &node.entries {
        NodeEntries::Leaf(extents) => {
            for (index, extent) in extents.iter().enumerate() {
                let at = 12 + index * 12;
                let encoded_length = match extent.state {
                    ExtentState::Written => extent.length,
                    ExtentState::Unwritten => extent.length + WRITTEN_MAX_LEN,
                };
                put_le32(target, at, extent.logical);
                put_le16(target, at + 4, encoded_length as u16);
                put_le16(target, at + 6, (extent.physical >> 32) as u16);
                put_le32(target, at + 8, extent.physical as u32);
            }
        }
        NodeEntries::Branch(children) => {
            for (index, child) in children.iter().enumerate() {
                let NodeLocation::Block(number) = child.location else {
                    return Err(Corrupt::InvalidExtentTree.into());
                };
                let at = 12 + index * 12;
                put_le32(
                    target,
                    at,
                    child.first_logical().ok_or(Corrupt::InvalidExtentTree)?,
                );
                put_le32(target, at + 4, number as u32);
                put_le16(target, at + 8, (number >> 32) as u16);
            }
        }
    }
    Ok(())
}

fn merge_leaf(extents: &mut Vec<Extent>) {
    let mut index = 0;
    while index + 1 < extents.len() {
        if extents[index].can_merge(extents[index + 1]) {
            extents[index].length += extents[index + 1].length;
            extents.remove(index + 1);
        } else {
            index += 1;
        }
    }
}

fn split_extent(extent: Extent, start: u64, end: u64) -> (Option<Extent>, Extent, Option<Extent>) {
    debug_assert!(extent.overlaps(start, end));
    let extent_start = u64::from(extent.logical);
    let extent_end = extent.logical_end();
    let middle_start = start.max(extent_start);
    let middle_end = end.min(extent_end);
    let before = (extent_start < middle_start).then(|| Extent {
        length: (middle_start - extent_start) as u32,
        ..extent
    });
    let middle = Extent {
        logical: middle_start as u32,
        physical: extent.physical + middle_start - extent_start,
        length: (middle_end - middle_start) as u32,
        state: extent.state,
    };
    let after = (middle_end < extent_end).then(|| Extent {
        logical: middle_end as u32,
        physical: extent.physical + middle_end - extent_start,
        length: (extent_end - middle_end) as u32,
        state: extent.state,
    });
    (before, middle, after)
}

#[inline(never)]
fn remove_from_leaf(
    extents: &mut Vec<Extent>,
    start: u64,
    end: u64,
    removed_extents: &mut Vec<Extent>,
) -> Result<bool, Error> {
    let mut changed = false;
    let mut output = Vec::new();
    output
        .try_reserve_exact(extents.len() + 1)
        .map_err(|_| Error::OutOfMemory)?;
    for extent in extents.drain(..) {
        if !extent.overlaps(start, end) {
            output.push(extent);
            continue;
        }
        changed = true;
        let (before, removed, after) = split_extent(extent, start, end);
        try_push(removed_extents, removed)?;
        if let Some(before) = before {
            output.push(before);
        }
        if let Some(after) = after {
            output.push(after);
        }
    }
    merge_leaf(&mut output);
    *extents = output;
    Ok(changed)
}

fn collect_blocks(node: ExtentNode, blocks: &mut Vec<u64>) -> Result<(), Error> {
    if let NodeLocation::Block(block) = node.location {
        try_push(blocks, block)?;
    }
    if let NodeEntries::Branch(children) = node.entries {
        for child in children {
            collect_blocks(child, blocks)?;
        }
    }
    Ok(())
}

fn child_at(children: &[ExtentNode], logical: u64) -> usize {
    children
        .partition_point(|child| {
            child
                .first_logical()
                .is_some_and(|first| u64::from(first) <= logical)
        })
        .saturating_sub(1)
}

fn collect_holes(
    node: &ExtentNode,
    cursor: &mut u64,
    end: u64,
    holes: &mut Holes,
) -> Result<(), Error> {
    match &node.entries {
        NodeEntries::Leaf(extents) => {
            for extent in extents {
                if extent.logical_end() <= *cursor {
                    continue;
                }
                let logical = u64::from(extent.logical);
                if logical >= end {
                    break;
                }
                push_hole(holes, *cursor, logical.min(end))?;
                *cursor = extent.logical_end().min(end);
            }
        }
        NodeEntries::Branch(children) => {
            let mut index = child_at(children, *cursor);
            while index < children.len() && *cursor < end {
                let first = children[index]
                    .first_logical()
                    .ok_or(Corrupt::InvalidExtentTree)?;
                if u64::from(first) >= end {
                    break;
                }
                collect_holes(&children[index], cursor, end, holes)?;
                index += 1;
            }
        }
    }
    Ok(())
}

fn push_hole(holes: &mut Holes, start: u64, end: u64) -> Result<(), Error> {
    if start < end {
        holes.blocks = holes
            .blocks
            .checked_add(usize::try_from(end - start).map_err(|_| Corrupt::AddressOverflow)?)
            .ok_or(Corrupt::AddressOverflow)?;
        try_push(&mut holes.ranges, start..end)?;
    }
    Ok(())
}

fn node_contains_block(node: &ExtentNode, number: u64) -> bool {
    matches!(node.location, NodeLocation::Block(block) if block == number)
        || match &node.entries {
            NodeEntries::Leaf(_) => false,
            NodeEntries::Branch(children) => children
                .iter()
                .any(|child| node_contains_block(child, number)),
        }
}

fn node_contains_data_block(node: &ExtentNode, number: u64) -> bool {
    match &node.entries {
        NodeEntries::Leaf(extents) => extents.iter().any(|extent| {
            extent.physical <= number
                && number < extent.physical.saturating_add(u64::from(extent.length))
        }),
        NodeEntries::Branch(children) => children
            .iter()
            .any(|child| node_contains_data_block(child, number)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn extent(logical: u32, physical: u64, length: u32) -> Extent {
        Extent::new(logical, physical, length, ExtentState::Written).unwrap()
    }

    #[test]
    fn insertion_splits_and_promotes_at_every_level() {
        let root = ExtentNode::leaf(NodeLocation::Root, Vec::new());
        let mut tree = ExtentTree::new(root, 8).unwrap();
        for index in 0..80 {
            tree.insert(extent(index * 2, 1000 + u64::from(index) * 2, 1))
                .unwrap();
        }
        assert!(tree.root.depth() >= 2);
        assert!(tree.unassigned_blocks() > 0);
        let blocks: Vec<u64> = (1..=tree.unassigned_blocks() as u64).collect();
        tree.assign_blocks(&blocks).unwrap();
        tree.root.validate(8, true).unwrap();
        assert_eq!(tree.extents().len(), 80);
    }

    #[test]
    fn holes_are_preserved_and_boundary_extents_are_split() {
        let root = ExtentNode::leaf(
            NodeLocation::Root,
            vec![extent(0, 100, 8), extent(20, 200, 8)],
        );
        let mut tree = ExtentTree::new(root, 8).unwrap();
        tree.remove(3, 24).unwrap();
        assert_eq!(tree.extents(), vec![extent(0, 100, 3), extent(24, 204, 4)]);
    }

    #[test]
    fn adjacent_compatible_extents_merge_but_unwritten_does_not() {
        let root = ExtentNode::leaf(NodeLocation::Root, vec![extent(0, 100, 3)]);
        let mut tree = ExtentTree::new(root, 8).unwrap();
        tree.insert(extent(3, 103, 2)).unwrap();
        tree.insert(Extent::new(5, 105, 2, ExtentState::Unwritten).unwrap())
            .unwrap();
        assert_eq!(tree.extents().len(), 2);
        assert_eq!(tree.extents()[0], extent(0, 100, 5));
    }

    #[test]
    fn state_conversion_splits_boundaries_and_preserves_holes() {
        let unwritten = Extent::new(0, 100, 10, ExtentState::Unwritten).unwrap();
        let mut tree = ExtentTree::new(
            ExtentNode::leaf(NodeLocation::Root, vec![unwritten, extent(20, 200, 4)]),
            8,
        )
        .unwrap();
        tree.set_state(3, 22, ExtentState::Written).unwrap();
        assert_eq!(
            tree.extents(),
            vec![
                Extent::new(0, 100, 3, ExtentState::Unwritten).unwrap(),
                extent(3, 103, 7),
                extent(20, 200, 4),
            ]
        );
        assert_eq!(tree.lookup(15), None);
    }

    #[test]
    fn deletion_prunes_nodes_and_collapses_the_root() {
        let left = ExtentNode {
            location: NodeLocation::Block(10),
            dirty: false,
            entries: NodeEntries::Leaf(vec![extent(0, 100, 2)]),
        };
        let right = ExtentNode {
            location: NodeLocation::Block(11),
            dirty: false,
            entries: NodeEntries::Leaf(vec![extent(10, 200, 2)]),
        };
        let root = ExtentNode::branch(NodeLocation::Root, vec![left, right]);
        let mut tree = ExtentTree::new(root, 8).unwrap();
        tree.remove(0, 2).unwrap();
        assert_eq!(tree.root.depth(), 0);
        assert_eq!(tree.root.location, NodeLocation::Root);
        assert_eq!(tree.extents(), vec![extent(10, 200, 2)]);
        assert_eq!(tree.released_nodes, [10, 11]);
    }

    #[test]
    fn serialized_tree_round_trips_at_arbitrary_depth() {
        let mut tree =
            ExtentTree::new(ExtentNode::leaf(NodeLocation::Root, Vec::new()), 8).unwrap();
        for index in 0..40 {
            tree.insert(extent(index * 3, 1000 + u64::from(index) * 3, 1))
                .unwrap();
        }
        let assigned: Vec<u64> = (10..10 + tree.unassigned_blocks() as u64).collect();
        tree.assign_blocks(&assigned).unwrap();
        let identity = ExtentIdentity {
            checksum_seed: 0x1234_5678,
            inode: 42,
            generation: 7,
            metadata_checksums: true,
        };
        let root = tree.root_record().unwrap();
        let serialized = tree.serialize_dirty(112, identity).unwrap();
        let loaded = ExtentTree::load(&root, 112, 10_000, identity, &mut |number| {
            serialized
                .iter()
                .find(|node| node.number == number)
                .map(|node| node.bytes.clone())
                .ok_or(Error::NotFound)
        })
        .unwrap();
        assert_eq!(loaded.data_extents().unwrap(), tree.extents());
        assert_eq!(loaded.root.depth(), tree.root.depth());
    }

    #[test]
    fn final_logical_block_is_representable_and_removable() {
        let last = extent(u32::MAX, 100, 1);
        assert_eq!(last.logical_end(), 1_u64 << 32);
        let mut tree =
            ExtentTree::new(ExtentNode::leaf(NodeLocation::Root, vec![last]), 8).unwrap();
        let removed = tree.remove(u64::from(u32::MAX), 1_u64 << 32).unwrap();
        assert_eq!(removed, vec![last]);
        assert!(tree.extents().is_empty());
    }
}
