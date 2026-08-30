//! In-memory model and edits for an ext4 extent tree.
//!
//! The inode root and external extent blocks have different capacities, but
//! they contain the same recursive data structure.  This module keeps that
//! distinction at the serialization boundary: insertion, removal, splitting,
//! promotion, and root collapse are expressed once for every legal depth.

use crate::checksum::Checksum;
use crate::ondisk::{le16, le32, put_le16, put_le32};
use crate::{Corrupt, EXTENT_MAGIC, Error, Unsupported};
use alloc::vec::Vec;

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

    fn overlaps(&self, start: u64, end: u64) -> bool {
        match &self.entries {
            NodeEntries::Leaf(extents) => extents.iter().any(|extent| extent.overlaps(start, end)),
            NodeEntries::Branch(children) => {
                children.iter().any(|child| child.overlaps(start, end))
            }
        }
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
                extents.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                extents.insert(position, extent);
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
                    children.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                    children.insert(position + 1, promoted);
                }
                self.dirty = true;
            }
        }
        if self.entry_count() <= capacity {
            return Ok(None);
        }
        let sibling_entries = match &mut self.entries {
            NodeEntries::Leaf(extents) => NodeEntries::Leaf(extents.split_off(extents.len() / 2)),
            NodeEntries::Branch(children) => {
                NodeEntries::Branch(children.split_off(children.len() / 2))
            }
        };
        Ok(Some(Self {
            location: NodeLocation::Unassigned,
            dirty: true,
            entries: sibling_entries,
        }))
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
                    let extent_start = u64::from(extent.logical);
                    let extent_end = extent.logical_end();
                    let middle_start = start.max(extent_start);
                    let middle_end = end.min(extent_end);
                    if extent_start < middle_start {
                        output.push(Extent {
                            length: u32::try_from(middle_start - extent_start)
                                .map_err(|_| Corrupt::InvalidExtentTree)?,
                            ..extent
                        });
                    }
                    output.push(Extent {
                        logical: u32::try_from(middle_start)
                            .map_err(|_| Corrupt::InvalidExtentTree)?,
                        physical: extent.physical + (middle_start - extent_start),
                        length: u32::try_from(middle_end - middle_start)
                            .map_err(|_| Corrupt::InvalidExtentTree)?,
                        state,
                    });
                    if middle_end < extent_end {
                        output.push(Extent {
                            logical: u32::try_from(middle_end)
                                .map_err(|_| Corrupt::InvalidExtentTree)?,
                            physical: extent.physical + (middle_end - extent_start),
                            length: u32::try_from(extent_end - middle_end)
                                .map_err(|_| Corrupt::InvalidExtentTree)?,
                            state: extent.state,
                        });
                    }
                }
                merge_leaf(&mut output);
                *extents = output;
                changed
            }
            NodeEntries::Branch(children) => {
                let mut changed = false;
                let mut index = 0;
                while index < children.len() {
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
                        children.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                        children.insert(index + 1, sibling);
                        index += 1;
                    }
                    index += 1;
                }
                changed
            }
        };
        self.dirty |= changed;
        if self.entry_count() <= capacity {
            return Ok(None);
        }
        let sibling_entries = match &mut self.entries {
            NodeEntries::Leaf(extents) => NodeEntries::Leaf(extents.split_off(extents.len() / 2)),
            NodeEntries::Branch(children) => {
                NodeEntries::Branch(children.split_off(children.len() / 2))
            }
        };
        Ok(Some(Self {
            location: NodeLocation::Unassigned,
            dirty: true,
            entries: sibling_entries,
        }))
    }

    fn entry_count(&self) -> usize {
        match &self.entries {
            NodeEntries::Leaf(extents) => extents.len(),
            NodeEntries::Branch(children) => children.len(),
        }
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
                let mut index = 0;
                while index < children.len() {
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
    released_nodes: Vec<u64>,
}

impl ExtentTree {
    #[inline(never)]
    pub(crate) fn load(
        root: &[u8],
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
        let depth = extent_header(root, ROOT_CAPACITY)?;
        if depth > MAX_DEPTH {
            return Err(Unsupported::ExtentTreeTooDeep.into());
        }
        let mut visited = Vec::new();
        let root = load_node(
            root,
            NodeLocation::Root,
            depth,
            ROOT_CAPACITY,
            block_capacity,
            blocks_count,
            identity,
            &mut visited,
            read_block,
        )?;
        let tree = Self::new(root, block_capacity)?;
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
        })
    }

    #[inline(never)]
    pub(crate) fn insert(&mut self, extent: Extent) -> Result<(), Error> {
        Extent::new(extent.logical, extent.physical, extent.length, extent.state)?;
        if self
            .root
            .overlaps(u64::from(extent.logical), extent.logical_end())
            || node_overlaps_data(&self.root, extent.physical, u64::from(extent.length))
            || node_overlaps_block_range(&self.root, extent.physical, u64::from(extent.length))
        {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        let sibling = self
            .root
            .insert(extent, self.block_capacity, self.block_capacity)?;
        if sibling.is_some() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
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
                self.released_nodes
                    .try_reserve(1)
                    .map_err(|_| Error::OutOfMemory)?;
                self.released_nodes.push(block);
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
        if start >= end || !node_has_different_state(&self.root, start, end, state) {
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

    pub(crate) fn released_blocks(&self) -> &[u64] {
        &self.released_nodes
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

    /// Count unmapped logical blocks in `[start, end)`.
    #[inline(never)]
    pub(crate) fn count_holes(&self, start: u64, end: u64) -> Result<usize, Error> {
        let mut holes = 0usize;
        for logical in start..end {
            let logical = u32::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?;
            if self.lookup(logical).is_none() {
                holes = holes.checked_add(1).ok_or(Corrupt::AddressOverflow)?;
            }
        }
        Ok(holes)
    }

    /// Map every hole in `[start, end)` to the next supplied physical block.
    /// Existing mappings are preserved and the input must contain exactly one
    /// block for every hole.
    #[inline(never)]
    pub(crate) fn fill_holes(
        &mut self,
        start: u64,
        end: u64,
        blocks: &[u64],
        state: ExtentState,
    ) -> Result<(), Error> {
        let mut blocks = blocks.iter().copied();
        for logical in start..end {
            let logical = u32::try_from(logical).map_err(|_| Corrupt::AddressOverflow)?;
            if self.lookup(logical).is_none() {
                self.insert(Extent::new(
                    logical,
                    blocks.next().ok_or(Corrupt::InvalidExtentTree)?,
                    1,
                    state,
                )?)?;
            }
        }
        if blocks.next().is_some() {
            return Err(Corrupt::InvalidExtentTree.into());
        }
        Ok(())
    }

    #[inline(never)]
    pub(crate) fn external_blocks(&self) -> Result<Vec<u64>, Error> {
        fn collect(node: &ExtentNode, out: &mut Vec<u64>) -> Result<(), Error> {
            if let NodeLocation::Block(number) = node.location {
                out.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                out.push(number);
            }
            if let NodeEntries::Branch(children) = &node.entries {
                for child in children {
                    collect(child, out)?;
                }
            }
            Ok(())
        }

        let mut blocks = Vec::new();
        collect(&self.root, &mut blocks)?;
        Ok(blocks)
    }

    pub(crate) fn write_root(&self, target: &mut [u8]) -> Result<(), Error> {
        write_node(target, &self.root, ROOT_CAPACITY)
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
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(block_size)
                    .map_err(|_| Error::OutOfMemory)?;
                bytes.resize(block_size, 0);
                write_node(&mut bytes, node, capacity)?;
                if identity.metadata_checksums {
                    let checksum_offset = 12 + capacity * 12;
                    let mut checksum = Checksum::with_seed(identity.checksum_seed);
                    checksum.update_u32_le(identity.inode);
                    checksum.update_u32_le(identity.generation);
                    checksum.update(&bytes[..checksum_offset]);
                    put_le32(&mut bytes, checksum_offset, checksum.finalize());
                }
                out.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                out.push(SerializedNode { number, bytes });
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
        visited.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        visited.push(number);
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
        let extent_end = extent.logical_end();
        let removed_start = start.max(u64::from(extent.logical));
        let removed_end = end.min(extent_end);
        removed_extents
            .try_reserve(1)
            .map_err(|_| Error::OutOfMemory)?;
        removed_extents.push(Extent {
            logical: u32::try_from(removed_start).map_err(|_| Corrupt::InvalidExtentTree)?,
            physical: extent.physical + (removed_start - u64::from(extent.logical)),
            length: u32::try_from(removed_end - removed_start)
                .map_err(|_| Corrupt::InvalidExtentTree)?,
            state: extent.state,
        });
        if u64::from(extent.logical) < start {
            output.push(Extent {
                length: u32::try_from(start - u64::from(extent.logical))
                    .map_err(|_| Corrupt::InvalidExtentTree)?,
                ..extent
            });
        }
        if end < extent_end {
            let skipped = end - u64::from(extent.logical);
            output.push(Extent {
                logical: u32::try_from(end).map_err(|_| Corrupt::InvalidExtentTree)?,
                physical: extent.physical + skipped,
                length: u32::try_from(extent_end - end).map_err(|_| Corrupt::InvalidExtentTree)?,
                state: extent.state,
            });
        }
    }
    merge_leaf(&mut output);
    *extents = output;
    Ok(changed)
}

fn collect_blocks(node: ExtentNode, blocks: &mut Vec<u64>) -> Result<(), Error> {
    if let NodeLocation::Block(block) = node.location {
        blocks.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        blocks.push(block);
    }
    if let NodeEntries::Branch(children) = node.entries {
        for child in children {
            collect_blocks(child, blocks)?;
        }
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

fn node_overlaps_data(node: &ExtentNode, physical: u64, length: u64) -> bool {
    let end = physical.saturating_add(length);
    match &node.entries {
        NodeEntries::Leaf(extents) => extents.iter().any(|extent| {
            physical < extent.physical.saturating_add(u64::from(extent.length))
                && extent.physical < end
        }),
        NodeEntries::Branch(children) => children
            .iter()
            .any(|child| node_overlaps_data(child, physical, length)),
    }
}

fn node_overlaps_block_range(node: &ExtentNode, physical: u64, length: u64) -> bool {
    let end = physical.saturating_add(length);
    matches!(node.location, NodeLocation::Block(block) if physical <= block && block < end)
        || match &node.entries {
            NodeEntries::Leaf(_) => false,
            NodeEntries::Branch(children) => children
                .iter()
                .any(|child| node_overlaps_block_range(child, physical, length)),
        }
}

fn node_has_different_state(node: &ExtentNode, start: u64, end: u64, state: ExtentState) -> bool {
    match &node.entries {
        NodeEntries::Leaf(extents) => extents
            .iter()
            .any(|extent| extent.state != state && extent.overlaps(start, end)),
        NodeEntries::Branch(children) => children
            .iter()
            .any(|child| node_has_different_state(child, start, end, state)),
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
        assert_eq!(tree.released_blocks(), &[10, 11]);
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
        let mut root = [0u8; 60];
        tree.write_root(&mut root).unwrap();
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
