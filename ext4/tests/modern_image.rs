use portable_ext4::test_support::{Inject, ModelError, ModelStorage};
use portable_ext4::Error;

fn image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_MODERN_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn multi_group_image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_MULTI_GROUP_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn inode_group_image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_INODE_GROUP_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn extent_mutation_image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_EXTENT_MUTATION_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn put_le16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn crc32c(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

fn update_fragmentation_checksums(bytes: &mut [u8]) {
    const SUPERBLOCK: usize = 1024;
    let block_size = 1024usize << le32(bytes, SUPERBLOCK + 0x18);
    let descriptor = block_size;
    let descriptor_size = usize::from(le16(bytes, SUPERBLOCK + 0xfe));
    let bitmap_block =
        (u64::from(le32(bytes, descriptor + 0x20)) << 32) | u64::from(le32(bytes, descriptor));
    let bitmap = bitmap_block as usize * block_size;
    let bitmap_bytes = le32(bytes, SUPERBLOCK + 0x20).div_ceil(8) as usize;
    let incompat = le32(bytes, SUPERBLOCK + 0x60);
    let seed = if incompat & 0x2000 != 0 {
        le32(bytes, SUPERBLOCK + 0x270)
    } else {
        crc32c(u32::MAX, &bytes[SUPERBLOCK + 0x68..SUPERBLOCK + 0x78])
    };
    let bitmap_checksum = crc32c(seed, &bytes[bitmap..bitmap + bitmap_bytes]);
    put_le16(bytes, descriptor + 0x18, bitmap_checksum as u16);
    put_le16(bytes, descriptor + 0x38, (bitmap_checksum >> 16) as u16);

    put_le16(bytes, descriptor + 0x1e, 0);
    let checksum = crc32c(seed, &0u32.to_le_bytes());
    let checksum = crc32c(checksum, &bytes[descriptor..descriptor + descriptor_size]);
    put_le16(bytes, descriptor + 0x1e, checksum as u16);

    let superblock_checksum = crc32c(u32::MAX, &bytes[SUPERBLOCK..SUPERBLOCK + 0x3fc]);
    put_le32(bytes, SUPERBLOCK + 0x3fc, superblock_checksum);
}

/// Occupy every second free group-0 block without attaching it to an inode.
/// The returned list can be released after the operation, restoring a
/// completely ordinary filesystem for e2fsck while forcing deterministic
/// one-block allocation runs during the operation under test.
fn add_artificial_fragmentation(bytes: &mut [u8], gaps: usize) -> Vec<u64> {
    const SUPERBLOCK: usize = 1024;
    let block_size = 1024usize << le32(bytes, SUPERBLOCK + 0x18);
    let descriptor = block_size;
    let blocks_per_group = u64::from(le32(bytes, SUPERBLOCK + 0x20));
    let bitmap_block =
        (u64::from(le32(bytes, descriptor + 0x20)) << 32) | u64::from(le32(bytes, descriptor));
    let bitmap = bitmap_block as usize * block_size;
    let mut marked = Vec::with_capacity(gaps);
    let mut leave_next = true;
    for block in 0..blocks_per_group {
        let byte = bitmap + block as usize / 8;
        let mask = 1 << (block as usize % 8);
        if bytes[byte] & mask != 0 {
            continue;
        }
        if leave_next {
            leave_next = false;
        } else {
            bytes[byte] |= mask;
            marked.push(block);
            leave_next = true;
            if marked.len() == gaps {
                break;
            }
        }
    }
    assert_eq!(marked.len(), gaps);
    adjust_artificial_free_counts(bytes, -(gaps as i64));
    update_fragmentation_checksums(bytes);
    marked
}

fn remove_artificial_fragmentation(bytes: &mut [u8], marked: &[u64]) {
    const SUPERBLOCK: usize = 1024;
    let block_size = 1024usize << le32(bytes, SUPERBLOCK + 0x18);
    let descriptor = block_size;
    let bitmap_block =
        (u64::from(le32(bytes, descriptor + 0x20)) << 32) | u64::from(le32(bytes, descriptor));
    let bitmap = bitmap_block as usize * block_size;
    for &block in marked {
        let byte = bitmap + block as usize / 8;
        let mask = 1 << (block as usize % 8);
        assert_ne!(bytes[byte] & mask, 0);
        bytes[byte] &= !mask;
    }
    adjust_artificial_free_counts(bytes, marked.len() as i64);
    update_fragmentation_checksums(bytes);
}

fn adjust_artificial_free_counts(bytes: &mut [u8], delta: i64) {
    const SUPERBLOCK: usize = 1024;
    let block_size = 1024usize << le32(bytes, SUPERBLOCK + 0x18);
    let descriptor = block_size;
    let group_free = u64::from(le16(bytes, descriptor + 0x0c))
        | (u64::from(le16(bytes, descriptor + 0x2c)) << 16);
    let super_free = u64::from(le32(bytes, SUPERBLOCK + 0x0c))
        | (u64::from(le32(bytes, SUPERBLOCK + 0x158)) << 32);
    let group_free = u64::try_from(group_free as i64 + delta).unwrap();
    let super_free = u64::try_from(super_free as i64 + delta).unwrap();
    put_le16(bytes, descriptor + 0x0c, group_free as u16);
    put_le16(bytes, descriptor + 0x2c, (group_free >> 16) as u16);
    put_le32(bytes, SUPERBLOCK + 0x0c, super_free as u32);
    put_le32(bytes, SUPERBLOCK + 0x158, (super_free >> 32) as u32);
}

#[test]
fn graph_api_reads_typed_objects_directly() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut data = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"root-data.bin" {
                data = Some(edge.object);
            }
            Ok(true)
        })
        .unwrap();
    let Object::Blob(blob) = data.unwrap() else {
        panic!("root-data.bin is not a blob")
    };
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .size,
        14
    );
    let mut contents = [0; 14];
    assert_eq!(
        graph.read(&mut storage, blob, 0, &mut contents).unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");
}

#[test]
fn graph_api_owns_detached_blob_references() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let created = graph.create_blob(&mut storage).unwrap();
    let Object::Blob(blob) = created.object() else {
        panic!("create_blob returned a node")
    };
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .references,
        1
    );
    let retained = graph.retain(&mut storage, blob).unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .references,
        2
    );
    graph.release(&mut storage, retained).unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .references,
        1
    );
}

#[test]
fn graph_api_resizes_extent_blob() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut data = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"root-data.bin" {
                data = Some(edge.object);
            }
            Ok(true)
        })
        .unwrap();
    let Object::Blob(blob) = data.unwrap() else {
        panic!("root-data.bin is not a blob")
    };

    graph.resize(&mut storage, blob, 15_000).unwrap();
    graph
        .write(&mut storage, blob, 3_500, b"cross-block-write")
        .unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .size,
        15_000
    );
    let mut grown = vec![0x55; 15_000];
    assert_eq!(
        graph.read(&mut storage, blob, 0, &mut grown).unwrap(),
        15_000
    );
    assert_eq!(&grown[..14], b"portable ext4\n");
    assert!(grown[14..3_500].iter().all(|byte| *byte == 0));
    assert_eq!(&grown[3_500..3_517], b"cross-block-write");
    assert!(grown[3_517..].iter().all(|byte| *byte == 0));

    graph.resize(&mut storage, blob, 5_000).unwrap();
    let mut shrunk = vec![0; 5_000];
    assert_eq!(
        graph.read(&mut storage, blob, 0, &mut shrunk).unwrap(),
        5_000
    );
    assert_eq!(&shrunk[..14], b"portable ext4\n");
    assert!(shrunk[14..3_500].iter().all(|byte| *byte == 0));
    assert_eq!(&shrunk[3_500..3_517], b"cross-block-write");
    assert!(shrunk[3_517..].iter().all(|byte| *byte == 0));

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-resized.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected graph resize:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn graph_api_collapses_external_extent_leaf() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    let mut fragmented = image();
    let artificial = add_artificial_fragmentation(&mut fragmented, 6);
    let mut storage = ModelStorage::new(fragmented);
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut data = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"root-empty.bin" {
                data = Some(edge.object);
            }
            Ok(true)
        })
        .unwrap();
    let Object::Blob(blob) = data.unwrap() else {
        panic!("root-empty.bin is not a blob")
    };

    for logical in 0..6 {
        graph
            .write(&mut storage, blob, logical * 4096, &[logical as u8 + 1])
            .unwrap();
    }
    for logical in 0..6 {
        let mut byte = [0];
        assert_eq!(
            graph
                .read(&mut storage, blob, logical * 4096, &mut byte)
                .unwrap(),
            1
        );
        assert_eq!(byte[0], logical as u8 + 1);
    }
    graph.resize(&mut storage, blob, 0).unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob))
            .unwrap()
            .size,
        0
    );

    storage.flush().unwrap();
    let mut durable = storage.durable_bytes().to_vec();
    remove_artificial_fragmentation(&mut durable, &artificial);
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-external-resized.img");
    std::fs::write(&output, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected graph external resize:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn graph_api_resizes_unwritten_extent() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    let mut storage = ModelStorage::new(extent_mutation_image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut data = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"unwritten.bin" {
                data = Some(edge.object);
            }
            Ok(true)
        })
        .unwrap();
    let Object::Blob(blob) = data.unwrap() else {
        panic!("unwritten.bin is not a blob")
    };

    graph.resize(&mut storage, blob, 5_000).unwrap();
    graph.resize(&mut storage, blob, 12_000).unwrap();
    graph
        .write(&mut storage, blob, 5_000, b"initialized-subrange")
        .unwrap();
    let mut contents = vec![1; 12_000];
    assert_eq!(
        graph.read(&mut storage, blob, 0, &mut contents).unwrap(),
        contents.len()
    );
    assert!(contents[..5_000].iter().all(|byte| *byte == 0));
    assert_eq!(&contents[5_000..5_020], b"initialized-subrange");
    assert!(contents[5_020..].iter().all(|byte| *byte == 0));

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-unwritten-resized.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected graph unwritten resize:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn graph_api_owns_edges_and_reclaims_objects() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();

    let blob = graph.create_blob(&mut storage).unwrap();
    let Object::Blob(blob_id) = blob.object() else {
        panic!("create_blob returned a node")
    };
    graph
        .write(&mut storage, blob_id, 0, b"graph payload")
        .unwrap();
    let (blob_edge, displaced) = graph
        .attach(&mut storage, root, b"graph-object", blob)
        .unwrap();
    assert!(displaced.is_none());
    let detached_blob = graph.detach(&mut storage, blob_edge).unwrap();
    let mut payload = [0; 13];
    assert_eq!(
        graph.read(&mut storage, blob_id, 0, &mut payload).unwrap(),
        payload.len()
    );
    assert_eq!(&payload, b"graph payload");
    graph.release(&mut storage, detached_blob).unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Blob(blob_id))
            .unwrap_err(),
        Error::NotFound
    );

    let node = graph.create_node(&mut storage).unwrap();
    let Object::Node(node_id) = node.object() else {
        panic!("create_node returned a blob")
    };
    let (node_edge, displaced) = graph
        .attach(&mut storage, root, b"graph-node", node)
        .unwrap();
    assert!(displaced.is_none());
    let detached_node = graph.detach(&mut storage, node_edge).unwrap();
    graph.release(&mut storage, detached_node).unwrap();
    assert_eq!(
        graph
            .inspect(&mut storage, Object::Node(node_id))
            .unwrap_err(),
        Error::NotFound
    );

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-owned-edges.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected graph ownership:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn graph_api_mutates_indexed_node_through_linear_graph_representation() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut directory = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"dir" {
                directory = Some(edge.object);
            }
            Ok(true)
        })
        .unwrap();
    let Object::Node(directory) = directory.unwrap() else {
        panic!("dir is not a node")
    };

    let mut original_edges = 0;
    let mut found_last = false;
    graph
        .edges(&mut storage, directory, Default::default(), &mut |edge| {
            original_edges += 1;
            found_last |= edge.name == b"file-299";
            Ok(true)
        })
        .unwrap();
    assert!(original_edges >= 306);
    assert!(found_last);

    let object = graph.create_blob(&mut storage).unwrap();
    let Object::Blob(blob) = object.object() else {
        panic!("create_blob returned a node")
    };
    graph
        .write(&mut storage, blob, 0, b"indexed graph")
        .unwrap();
    let (_, displaced) = graph
        .attach(&mut storage, directory, b"new-graph-edge", object)
        .unwrap();
    assert!(displaced.is_none());

    let mut found = false;
    graph
        .edges(&mut storage, directory, Default::default(), &mut |edge| {
            if edge.name == b"new-graph-edge" {
                assert_eq!(edge.object, Object::Blob(blob));
                found = true;
            }
            Ok(true)
        })
        .unwrap();
    assert!(found);

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-indexed-node.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected graph indexed-node conversion:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn graph_api_materializes_lazy_inode_and_block_groups() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::Storage;

    for (name, source, payload) in [
        ("lazy-inode", inode_group_image(), Vec::new()),
        ("lazy-block", multi_group_image(), vec![0x5a; 3 * 4096]),
    ] {
        let mut storage = ModelStorage::new(source);
        let mut graph = Graph::mount(&mut storage).unwrap();
        let root = graph.root(&mut storage).unwrap();
        let detached = graph.create_blob(&mut storage).unwrap();
        let Object::Blob(blob) = detached.object() else {
            panic!("create_blob returned a node")
        };
        graph.write(&mut storage, blob, 0, &payload).unwrap();
        graph
            .attach(&mut storage, root, name.as_bytes(), detached)
            .unwrap();

        storage.flush().unwrap();
        let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
            .join(format!("graph-{name}.img"));
        std::fs::write(&output, storage.durable_bytes()).unwrap();
        let check = std::process::Command::new("/usr/sbin/e2fsck")
            .args(["-fn", output.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "e2fsck rejected {name}:\n{}\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

#[test]
fn graph_composition_commits_complete_blocks_through_journal() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::{BlockOverlay, GraphJournal, Storage, StorageError};

    struct Recovered<'a> {
        journal: &'a GraphJournal,
        base: &'a mut ModelStorage,
    }

    impl Storage for Recovered<'_> {
        fn len(&self) -> u64 {
            self.base.len()
        }

        fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
            self.journal
                .read_recovered(self.base, offset, output)
                .map_err(|error| match error {
                    Error::Storage(error) => error,
                    _ => StorageError::new(ModelError::OutOfBounds),
                })
        }

        fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
            self.base.write(offset, input)
        }

        fn flush(&mut self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let mut journal = GraphJournal::mount(&mut graph, &mut storage).unwrap();
    let blocks = {
        let mut recovered = Recovered {
            journal: &journal,
            base: &mut storage,
        };
        graph = Graph::mount(&mut recovered).unwrap();
        let root = graph.root(&mut recovered).unwrap();
        let block_size = graph.block_size;
        let mut overlay = BlockOverlay::new(&mut recovered, block_size);
        let detached = graph.create_blob(&mut overlay).unwrap();
        let Object::Blob(blob) = detached.object() else {
            panic!("create_blob returned a node")
        };
        graph
            .write(&mut overlay, blob, 0, b"journal graph")
            .unwrap();
        graph
            .attach(&mut overlay, root, b"journal-graph", detached)
            .unwrap();
        overlay.finish()
    };
    journal.commit_blocks(&graph, &mut storage, blocks).unwrap();

    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut found = false;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            found |= edge.name == b"journal-graph";
            Ok(true)
        })
        .unwrap();
    assert!(found);

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("graph-journal.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected journaled graph composition:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_graph_journal_commit_effect_recovers_to_old_or_new_graph() {
    use portable_ext4::ext4::{Ext4 as Graph, Object};
    use portable_ext4::{BlockOverlay, GraphJournal, Storage, StorageError};

    struct Recovered<'a> {
        journal: &'a GraphJournal,
        base: &'a mut ModelStorage,
    }

    impl Storage for Recovered<'_> {
        fn len(&self) -> u64 {
            self.base.len()
        }

        fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
            self.journal
                .read_recovered(self.base, offset, output)
                .map_err(|error| match error {
                    Error::Storage(error) => error,
                    _ => StorageError::new(ModelError::OutOfBounds),
                })
        }

        fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
            self.base.write(offset, input)
        }

        fn flush(&mut self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn prepare(storage: &mut ModelStorage) -> (Graph, GraphJournal, Vec<(u64, Vec<u8>)>) {
        let mut graph = Graph::mount(storage).unwrap();
        let journal = GraphJournal::mount(&mut graph, storage).unwrap();
        let mut recovered = Recovered {
            journal: &journal,
            base: storage,
        };
        graph = Graph::mount(&mut recovered).unwrap();
        let root = graph.root(&mut recovered).unwrap();
        let block_size = graph.block_size;
        let mut overlay = BlockOverlay::new(&mut recovered, block_size);
        let detached = graph.create_blob(&mut overlay).unwrap();
        let Object::Blob(blob) = detached.object() else {
            panic!("create_blob returned a node")
        };
        graph.write(&mut overlay, blob, 0, b"atomic graph").unwrap();
        graph
            .attach(&mut overlay, root, b"atomic-graph", detached)
            .unwrap();
        let blocks = overlay.finish();
        drop(recovered);
        (graph, journal, blocks)
    }

    fn recovered_is_new(bytes: Vec<u8>) -> bool {
        let mut storage = ModelStorage::new(bytes);
        let mut graph = Graph::mount(&mut storage).unwrap();
        let journal = GraphJournal::mount(&mut graph, &mut storage).unwrap();
        let mut recovered = Recovered {
            journal: &journal,
            base: &mut storage,
        };
        let mut graph = Graph::mount(&mut recovered).unwrap();
        let root = graph.root(&mut recovered).unwrap();
        let mut found = false;
        graph
            .edges(&mut recovered, root, Default::default(), &mut |edge| {
                found |= edge.name == b"atomic-graph";
                Ok(true)
            })
            .unwrap();
        found
    }

    let source = image();
    let mut successful_storage = ModelStorage::new(source.clone());
    let (graph, mut journal, blocks) = prepare(&mut successful_storage);
    let commit_start = successful_storage.effects().len();
    journal
        .commit_blocks(&graph, &mut successful_storage, blocks)
        .unwrap();
    let commit_end = successful_storage.effects().len();

    let mut saw_old = false;
    let mut saw_new = false;
    for sequence in commit_start..commit_end {
        let mut storage =
            ModelStorage::new(source.clone()).with_injection(Inject::PowerLossAt(sequence));
        let (graph, mut journal, blocks) = prepare(&mut storage);
        let error = journal
            .commit_blocks(&graph, &mut storage, blocks)
            .unwrap_err();
        assert!(
            error.storage_is(&ModelError::PowerLoss),
            "effect {sequence}"
        );
        if recovered_is_new(storage.durable_bytes().to_vec()) {
            saw_new = true;
        } else {
            saw_old = true;
        }
    }
    assert!(saw_old && saw_new);
}

#[test]
fn handle_filesystem_owns_atomic_graph_composition() {
    use portable_ext4::ext4::{AttributeUpdate, Object};
    use portable_ext4::Filesystem;

    let storage = ModelStorage::new(image());
    let mut filesystem = Filesystem::mount(storage).unwrap();
    let root = filesystem.root().unwrap();
    let object = filesystem
        .create_blob(
            root,
            b"handle-file",
            AttributeUpdate {
                format: Some(0x8000 | 0o644),
                ..AttributeUpdate::default()
            },
        )
        .unwrap();
    let Object::Blob(blob) = object else {
        panic!("create_blob returned a node")
    };
    filesystem.write(blob, 0, b"handle filesystem").unwrap();
    let mut contents = [0; 17];
    assert_eq!(filesystem.read(blob, 0, &mut contents).unwrap(), 17);
    assert_eq!(&contents, b"handle filesystem");
    let (edge, found) = filesystem.find(root, b"handle-file").unwrap().unwrap();
    assert_eq!(found, object);
    filesystem.remove(edge).unwrap();
    assert!(filesystem.find(root, b"handle-file").unwrap().is_none());

    let storage = filesystem.into_storage();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("handle-filesystem.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected handle filesystem:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}
