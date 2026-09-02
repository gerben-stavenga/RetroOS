//! Owning, journaled filesystem composition over the ext4 graph.

use crate::ext4::{
    AttributeUpdate, Blob, Edge, EdgeCursor, EdgeHandle, Ext4 as Graph, Node, Object, ObjectInfo,
};
use crate::{BlockOverlay, Error, GraphJournal, Storage, StorageError};

struct RecoveredStorage<S> {
    base: S,
    journal: GraphJournal,
}

impl<S: Storage> RecoveredStorage<S> {
    fn commit(
        &mut self,
        graph: &Graph,
        blocks: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)>,
    ) -> Result<(), Error> {
        self.journal.commit_blocks(graph, &mut self.base, blocks)
    }
}

impl<S: Storage> Storage for RecoveredStorage<S> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.journal.read_storage(&mut self.base, offset, output)
    }

    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
        self.base.write(offset, input)
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.base.flush()
    }
}

/// A mounted ext4 filesystem whose public identities are graph handles.
///
/// Paths, symlink traversal, descriptors, credentials, and errno policy are
/// deliberately absent. Mutations are staged as complete blocks and committed
/// through the internal JBD2 journal as one operation.
pub struct Filesystem<S> {
    graph: Graph,
    storage: RecoveredStorage<S>,
}

impl<S: Storage> Filesystem<S> {
    pub fn mount(mut storage: S) -> Result<Self, Error> {
        let mut graph = Graph::mount(&mut storage)?;
        let journal = GraphJournal::mount(&mut graph, &mut storage)?;
        let mut storage = RecoveredStorage {
            base: storage,
            journal,
        };
        let graph = Graph::mount(&mut storage)?;
        Ok(Self { graph, storage })
    }

    pub fn into_storage(self) -> S {
        self.storage.base
    }

    pub fn root(&mut self) -> Result<Node, Error> {
        self.graph.root(&mut self.storage)
    }

    pub fn inspect(&mut self, object: Object) -> Result<ObjectInfo, Error> {
        self.graph.inspect(&mut self.storage, object)
    }

    pub fn edges(
        &mut self,
        node: Node,
        cursor: EdgeCursor,
        visit: &mut dyn FnMut(Edge<'_>) -> Result<bool, Error>,
    ) -> Result<Option<EdgeCursor>, Error> {
        self.graph.edges(&mut self.storage, node, cursor, visit)
    }

    pub fn read(&mut self, blob: Blob, offset: u64, output: &mut [u8]) -> Result<usize, Error> {
        self.graph.read(&mut self.storage, blob, offset, output)
    }

    pub fn find(&mut self, node: Node, name: &[u8]) -> Result<Option<(EdgeHandle, Object)>, Error> {
        find(&mut self.graph, &mut self.storage, node, name)
    }

    fn mutate<T>(
        &mut self,
        operation: &mut dyn FnMut(&mut Graph, &mut dyn Storage) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut overlay = BlockOverlay::new(&mut self.storage, self.graph.block_size);
        let result = match operation(&mut self.graph, &mut overlay) {
            Ok(result) => result,
            Err(error) => {
                drop(overlay);
                self.graph = Graph::mount(&mut self.storage)?;
                return Err(error);
            }
        };
        let dirty = overlay.finish();
        if let Err(error) = self.storage.commit(&self.graph, dirty) {
            self.graph = Graph::mount(&mut self.storage)?;
            return Err(error);
        }
        Ok(result)
    }

    pub fn write(&mut self, blob: Blob, offset: u64, input: &[u8]) -> Result<(), Error> {
        self.mutate(&mut |graph, storage| graph.write(storage, blob, offset, input))
    }

    pub fn resize(&mut self, blob: Blob, size: u64) -> Result<(), Error> {
        self.mutate(&mut |graph, storage| graph.resize(storage, blob, size))
    }

    pub fn update_attributes(
        &mut self,
        object: Object,
        update: AttributeUpdate,
    ) -> Result<(), Error> {
        self.mutate(&mut |graph, storage| graph.update_attributes(storage, object, update))
    }

    pub fn create_blob(
        &mut self,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        self.mutate(&mut |graph, storage| {
            if find(graph, storage, parent, name)?.is_some() {
                return Err(Error::AlreadyExists);
            }
            let detached = graph.create_blob(storage)?;
            let object = detached.object();
            graph.update_attributes(storage, object, attributes)?;
            graph.attach(storage, parent, name, detached)?;
            Ok(object)
        })
    }

    pub fn create_node(
        &mut self,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        self.mutate(&mut |graph, storage| {
            if find(graph, storage, parent, name)?.is_some() {
                return Err(Error::AlreadyExists);
            }
            let detached = graph.create_node(storage)?;
            let object = detached.object();
            graph.update_attributes(storage, object, attributes)?;
            graph.attach(storage, parent, name, detached)?;
            Ok(object)
        })
    }

    pub fn remove(&mut self, edge: EdgeHandle) -> Result<(), Error> {
        self.mutate(&mut |graph, storage| {
            let detached = graph.detach(storage, edge)?;
            graph.release(storage, detached)
        })
    }

    pub fn move_edge(&mut self, edge: EdgeHandle, target: Node, name: &[u8]) -> Result<(), Error> {
        self.mutate(&mut |graph, storage| {
            let detached = graph.detach(storage, edge)?;
            let (_, displaced) = graph.attach(storage, target, name, detached)?;
            if let Some(displaced) = displaced {
                graph.release(storage, displaced)?;
            }
            Ok(())
        })
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
