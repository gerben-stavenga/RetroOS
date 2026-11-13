//! Journaled filesystem composition over the ext4 graph.

use crate::ext4::{
    AttributeUpdate, Blob, Edge, EdgeCursor, EdgeHandle, Ext4 as Graph, Node, Object, ObjectInfo,
};
use crate::{BlockChanges, BlockOverlay, Error, GraphJournal, Storage, StorageError};

type Mutation<'a> = dyn FnMut(&mut Graph, &mut dyn Storage) -> Result<Option<Object>, Error> + 'a;

struct RecoveredStorage<'a> {
    base: &'a mut dyn Storage,
    journal: &'a GraphJournal,
    pending: &'a BlockChanges,
    block_size: u32,
}

impl<'a> RecoveredStorage<'a> {
    fn new(base: &'a mut dyn Storage, journal: &'a GraphJournal, pending: &'a BlockChanges, block_size: u32) -> Self {
        Self { base, journal, pending, block_size }
    }
}

impl Storage for RecoveredStorage<'_> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.read_with_kind(offset, output, crate::ReadKind::Metadata)
    }

    fn read_with_kind(&mut self, offset: u64, output: &mut [u8], kind: crate::ReadKind) -> Result<(), StorageError> {
        self.journal.read_storage(self.base, offset, output, kind)?;
        self.pending.apply(u64::from(self.block_size), offset, output);
        Ok(())
    }

    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
        self.base.write(offset, input)
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.base.flush()
    }
}

/// Allocation accounting from the mounted graph, after journal recovery.
#[derive(Clone, Copy, Debug)]
pub struct Statistics {
    pub block_size: u32,
    pub blocks: u64,
    pub free_blocks: u64,
    pub available_blocks: u64,
    pub inodes: u64,
    pub free_inodes: u64,
    pub uuid: [u8; 16],
}

/// A mounted ext4 filesystem whose public identities are graph handles.
///
/// Paths, symlink traversal, descriptors, credentials, and errno policy are
/// deliberately absent. Mutations are staged as complete blocks and committed
/// through the internal JBD2 journal as one operation.
pub struct Filesystem {
    graph: Graph,
    journal: GraphJournal,
    pending: BlockChanges,
    writeback_limit: usize,
    recover_orphans: bool,
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Blob,
    Node,
}

impl Filesystem {
    /// Group small mutations until sync or the bounded transaction fills.
    /// Visibility uses the same block overlay as recovery; journal ordering
    /// and barriers remain unchanged when a batch is committed.
    pub fn enable_writeback(&mut self, storage: &mut dyn Storage) -> Result<(), Error> {
        self.writeback_limit = self.journal.writeback_limit(&self.graph, storage)?;
        Ok(())
    }

    pub fn has_pending(&self) -> bool { !self.pending.blocks.is_empty() }

    fn commit_blocks(&mut self, storage: &mut dyn Storage, dirty: BlockChanges) -> Result<(), Error> {
        if let Err(error) = self.journal.commit_blocks(&self.graph, storage, dirty) {
            self.graph = Graph::mount(&mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size))?;
            self.graph.enable_decoded_metadata();
            return Err(error);
        }
        Ok(())
    }

    /// Make every staged mutation durable through the normal JBD2 writer.
    pub fn sync(&mut self, storage: &mut dyn Storage) -> Result<(), Error> {
        let dirty = core::mem::take(&mut self.pending);
        self.commit_blocks(storage, dirty)
    }

    pub fn statistics(&self) -> Statistics {
        Statistics {
            block_size: self.graph.block_size, blocks: self.graph.blocks_count,
            free_blocks: self.graph.free_blocks,
            available_blocks: self.graph.free_blocks.saturating_sub(self.graph.reserved_blocks),
            inodes: u64::from(self.graph.inodes_count), free_inodes: u64::from(self.graph.free_inodes),
            uuid: self.graph.uuid,
        }
    }

    #[inline(never)]
    pub fn mount(storage: &mut dyn Storage) -> Result<Self, Error> {
        let mut graph = Graph::mount(storage)?;
        let journal = GraphJournal::mount(&mut graph, storage)?;
        let pending = BlockChanges::default();
        let block_size = graph.block_size;
        let graph = Graph::mount(&mut RecoveredStorage::new(storage, &journal, &pending, block_size))?;
        graph.enable_decoded_metadata();
        Ok(Self { graph, journal, pending, writeback_limit: 0, recover_orphans: true })
    }

    pub fn root(&mut self, storage: &mut dyn Storage) -> Result<Node, Error> {
        self.graph
            .root(&mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size))
    }

    pub fn inspect(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
    ) -> Result<ObjectInfo, Error> {
        self.graph.inspect(
            &mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size),
            object,
        )
    }

    pub fn edges(
        &mut self,
        storage: &mut dyn Storage,
        node: Node,
        cursor: EdgeCursor,
        visit: &mut dyn FnMut(Edge<'_>) -> Result<bool, Error>,
    ) -> Result<Option<EdgeCursor>, Error> {
        self.graph.edges(
            &mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size),
            node,
            cursor,
            visit,
        )
    }

    pub fn entries(
        &mut self,
        storage: &mut dyn Storage,
        node: Node,
        cursor: EdgeCursor,
        visit: &mut dyn FnMut(Edge<'_>, ObjectInfo) -> Result<bool, Error>,
    ) -> Result<Option<EdgeCursor>, Error> {
        self.graph.entries(
            &mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size),
            node,
            cursor,
            visit,
        )
    }

    pub fn read(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.graph.read(
            &mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size),
            blob,
            offset,
            output,
        )
    }

    pub fn find(
        &mut self,
        storage: &mut dyn Storage,
        node: Node,
        name: &[u8],
    ) -> Result<Option<(EdgeHandle, Object)>, Error> {
        let block_size = self.graph.block_size;
        find(
            &mut self.graph,
            &mut RecoveredStorage::new(storage, &self.journal, &self.pending, block_size),
            node,
            name,
        )
    }

    fn mutate(
        &mut self,
        storage: &mut dyn Storage,
        operation: &mut Mutation<'_>,
    ) -> Result<Option<Object>, Error> {
        self.journal.checkpoint_recovery(&self.graph, storage)?;
        if self.recover_orphans {
            // Mount/probe stays read-only. The first authorized mutation
            // reclaims orphaned opens left by the previous boot, using the
            // same journal path as ordinary unlink and close.
            self.recover_orphans = false;
            let result = (|| {
                loop {
                    let object = self.graph.first_orphan(&mut RecoveredStorage::new(
                        storage, &self.journal, &self.pending, self.graph.block_size))?;
                    let Some(object) = object else { return Ok(()); };
                    self.release_orphan(storage, object)?;
                }
            })();
            if let Err(error) = result { self.recover_orphans = true; return Err(error); }
        }
        let (result, dirty) = {
            let mut recovered = RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size);
            let mut overlay = BlockOverlay::new(&mut recovered, self.graph.block_size);
            let counts_before = (self.graph.free_blocks, self.graph.free_inodes);
            let result = match operation(&mut self.graph, &mut overlay) {
                Ok(result) => result,
                Err(error) => {
                    let dirty = overlay.finish();
                    // Validation failures such as EEXIST did not mutate the
                    // graph. Remounting here discarded all warm decoded facts
                    // and allocation hints for an ordinary unsuccessful lookup.
                    if !dirty.blocks.is_empty()
                        || counts_before != (self.graph.free_blocks, self.graph.free_inodes)
                    {
                        self.graph = Graph::mount(&mut recovered)?;
                        self.graph.enable_decoded_metadata();
                    }
                    return Err(error);
                }
            };
            (result, overlay.finish())
        };
        if self.writeback_limit == 0 {
            self.commit_blocks(storage, dirty)?;
        } else {
            // A single unusually large operation keeps its old direct-commit
            // behavior. Small operations share a bounded journal transaction.
            let additional = dirty.blocks.iter().filter(|block| self.pending.index(block.number).is_err()).count();
            if self.pending.blocks.len() + additional > self.writeback_limit {
                self.sync(storage)?;
            }
            if dirty.blocks.len() >= self.writeback_limit {
                self.commit_blocks(storage, dirty)?;
            } else if let Err(error) = self.pending.merge(dirty) {
                self.graph = Graph::mount(&mut RecoveredStorage::new(storage, &self.journal, &self.pending, self.graph.block_size))?;
                self.graph.enable_decoded_metadata();
                return Err(error);
            }
        }
        Ok(result)
    }

    pub fn write(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            graph.write(storage, blob, offset, input)?;
            Ok(None)
        })?;
        Ok(())
    }

    pub fn resize(
        &mut self,
        storage: &mut dyn Storage,
        blob: Blob,
        size: u64,
    ) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            graph.resize(storage, blob, size)?;
            Ok(None)
        })?;
        Ok(())
    }

    pub fn update_attributes(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
        update: AttributeUpdate,
    ) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            graph.update_attributes(storage, object, update)?;
            Ok(None)
        })?;
        Ok(())
    }

    pub fn create_blob(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        self.create(storage, parent, name, attributes, ObjectKind::Blob)
    }

    /// Publish an initialized link blob and its directory edge in one journal
    /// transaction. Targets are opaque bytes; the caller interprets paths.
    pub fn create_link(
        &mut self, storage: &mut dyn Storage, parent: Node, name: &[u8],
        target: &[u8], mut attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        if target.is_empty() || target.contains(&0) { return Err(Error::InvalidArgument); }
        attributes.format = Some(0xa000 | (attributes.format.unwrap_or(0o777) & 0x0fff));
        self.mutate(storage, &mut |graph, storage| {
            if find(graph, storage, parent, name)?.is_some() { return Err(Error::AlreadyExists); }
            let detached = graph.create_link(storage, target)?;
            let object = detached.object();
            graph.update_attributes(storage, object, attributes)?;
            graph.attach(storage, parent, name, detached)?;
            Ok(Some(object))
        })?.ok_or(Error::InvalidArgument)
    }

    pub fn create_node(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        self.create(storage, parent, name, attributes, ObjectKind::Node)
    }

    /// Add an edge to the same blob, atomically with its reference count.
    pub fn hard_link(&mut self, storage: &mut dyn Storage, parent: Node, name: &[u8], object: Object) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            if find(graph, storage, parent, name)?.is_some() { return Err(Error::AlreadyExists); }
            let retained = graph.retain_blob(storage, object)?;
            graph.attach(storage, parent, name, retained)?;
            Ok(None)
        })?;
        Ok(())
    }

    #[inline(never)]
    fn create(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
        kind: ObjectKind,
    ) -> Result<Object, Error> {
        self.mutate(storage, &mut |graph, storage| {
            if find(graph, storage, parent, name)?.is_some() {
                return Err(Error::AlreadyExists);
            }
            let detached = match kind {
                ObjectKind::Blob => graph.create_blob(storage)?,
                ObjectKind::Node => graph.create_node(storage)?,
            };
            let object = detached.object();
            graph.update_attributes(storage, object, attributes)?;
            graph.attach(storage, parent, name, detached)?;
            Ok(Some(object))
        })?
        .ok_or(Error::InvalidArgument)
    }

    pub fn remove(
        &mut self,
        storage: &mut dyn Storage,
        edge: EdgeHandle,
    ) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            let detached = graph.detach(storage, edge)?;
            graph.release(storage, detached)?;
            Ok(None)
        })?;
        Ok(())
    }

    /// Remove a name while an external open retains the blob. Returns the
    /// zero-link object whose last close must call `release_orphan`.
    pub fn remove_open(&mut self, storage: &mut dyn Storage, edge: EdgeHandle) -> Result<Option<Object>, Error> {
        self.mutate(storage, &mut |graph, storage| graph.remove_open(storage, edge))
    }

    pub fn release_orphan(&mut self, storage: &mut dyn Storage, object: Object) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            graph.release_orphan(storage, object)?;
            Ok(None)
        })?;
        Ok(())
    }

    pub fn move_edge(
        &mut self,
        storage: &mut dyn Storage,
        edge: EdgeHandle,
        target: Node,
        name: &[u8],
    ) -> Result<(), Error> {
        self.mutate(storage, &mut |graph, storage| {
            let detached = graph.detach(storage, edge)?;
            let (_, displaced) = graph.attach(storage, target, name, detached)?;
            if let Some(displaced) = displaced {
                graph.release(storage, displaced)?;
            }
            Ok(None)
        })?;
        Ok(())
    }
}

fn find(
    graph: &mut Graph,
    storage: &mut dyn Storage,
    node: Node,
    name: &[u8],
) -> Result<Option<(EdgeHandle, Object)>, Error> {
    let mut found = None;
    graph.edges(storage, node, EdgeCursor::START, &mut |edge| {
        if edge.name == name {
            found = Some((edge.handle, edge.object));
            Ok(false)
        } else {
            Ok(true)
        }
    })?;
    Ok(found)
}
