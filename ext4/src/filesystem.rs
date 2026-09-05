//! Journaled filesystem composition over the ext4 graph.

use crate::ext4::{
    AttributeUpdate, Blob, Edge, EdgeCursor, EdgeHandle, Ext4 as Graph, Node, Object, ObjectInfo,
};
use crate::{BlockOverlay, Error, GraphJournal, Storage, StorageError};

struct RecoveredStorage<'a> {
    base: &'a mut dyn Storage,
    journal: &'a GraphJournal,
}

impl<'a> RecoveredStorage<'a> {
    fn new(base: &'a mut dyn Storage, journal: &'a GraphJournal) -> Self {
        Self { base, journal }
    }
}

impl Storage for RecoveredStorage<'_> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.journal.read_storage(self.base, offset, output)
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
pub struct Filesystem {
    graph: Graph,
    journal: GraphJournal,
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Blob,
    Node,
}

impl Filesystem {
    #[inline(never)]
    pub fn mount(storage: &mut dyn Storage) -> Result<Self, Error> {
        let mut graph = Graph::mount(storage)?;
        let journal = GraphJournal::mount(&mut graph, storage)?;
        let graph = Graph::mount(&mut RecoveredStorage::new(storage, &journal))?;
        Ok(Self { graph, journal })
    }

    pub fn root(&mut self, storage: &mut dyn Storage) -> Result<Node, Error> {
        self.graph
            .root(&mut RecoveredStorage::new(storage, &self.journal))
    }

    pub fn inspect(
        &mut self,
        storage: &mut dyn Storage,
        object: Object,
    ) -> Result<ObjectInfo, Error> {
        self.graph.inspect(
            &mut RecoveredStorage::new(storage, &self.journal),
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
            &mut RecoveredStorage::new(storage, &self.journal),
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
            &mut RecoveredStorage::new(storage, &self.journal),
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
            &mut RecoveredStorage::new(storage, &self.journal),
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
        find(
            &mut self.graph,
            &mut RecoveredStorage::new(storage, &self.journal),
            node,
            name,
        )
    }

    fn mutate(
        &mut self,
        storage: &mut dyn Storage,
        operation: &mut dyn FnMut(
            &mut Graph,
            &mut dyn Storage,
        ) -> Result<Option<Object>, Error>,
    ) -> Result<Option<Object>, Error> {
        let mut recovered = RecoveredStorage::new(storage, &self.journal);
        let mut overlay = BlockOverlay::new(&mut recovered, self.graph.block_size);
        let result = match operation(&mut self.graph, &mut overlay) {
            Ok(result) => result,
            Err(error) => {
                drop(overlay);
                self.graph = Graph::mount(&mut recovered)?;
                return Err(error);
            }
        };
        let dirty = overlay.finish();
        drop(recovered);
        if let Err(error) = self.journal.commit_blocks(&self.graph, storage, dirty) {
            self.graph = Graph::mount(&mut RecoveredStorage::new(storage, &self.journal))?;
            return Err(error);
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

    pub fn create_node(
        &mut self,
        storage: &mut dyn Storage,
        parent: Node,
        name: &[u8],
        attributes: AttributeUpdate,
    ) -> Result<Object, Error> {
        self.create(storage, parent, name, attributes, ObjectKind::Node)
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
