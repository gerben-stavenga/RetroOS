use portable_ext4::Error;
use portable_ext4::test_support::{Inject, ModelError, ModelStorage};

fn image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_MODERN_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn check_orphan_image(storage: &ModelStorage, label: &str) {
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join(format!("orphan-{label}.img"));
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()]).output().unwrap();
    assert!(check.status.success(), "{}{}", String::from_utf8_lossy(&check.stdout), String::from_utf8_lossy(&check.stderr));
}

#[test]
fn hard_links_share_the_blob_and_survive_individual_removal() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    let mut storage = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    let root = fs.root(&mut storage).unwrap();
    let object = fs.create_blob(&mut storage, root, b"hard-source", AttributeUpdate::default()).unwrap();
    let Object::Blob(blob) = object else { panic!() };
    fs.write(&mut storage, blob, 0, b"shared contents").unwrap();
    fs.hard_link(&mut storage, root, b"hard-twin", object).unwrap();
    assert_eq!(fs.find(&mut storage, root, b"hard-twin").unwrap().unwrap().1, object);
    assert_eq!(fs.inspect(&mut storage, object).unwrap().references, 2);
    assert_eq!(fs.hard_link(&mut storage, root, b"hard-twin", object), Err(Error::AlreadyExists));
    assert_eq!(fs.inspect(&mut storage, object).unwrap().references, 2);
    storage.flush().unwrap();
    check_orphan_image(&storage, "hard-two-names");
    let source = fs.find(&mut storage, root, b"hard-source").unwrap().unwrap().0;
    assert_eq!(fs.remove_open(&mut storage, source).unwrap(), None);
    assert_eq!(fs.inspect(&mut storage, object).unwrap().references, 1);
    let mut bytes = [0; 15];
    fs.read(&mut storage, blob, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"shared contents");
    let twin = fs.find(&mut storage, root, b"hard-twin").unwrap().unwrap().0;
    fs.remove(&mut storage, twin).unwrap();
    assert!(matches!(fs.inspect(&mut storage, object), Err(Error::NotFound)));
    storage.flush().unwrap();
    check_orphan_image(&storage, "hard-final-release");
}

#[test]
fn hard_links_publish_the_edge_and_reference_count_atomically() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::AttributeUpdate;
    use portable_ext4::test_support::EffectKind;
    let mut prepared = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut prepared).unwrap();
    let root = fs.root(&mut prepared).unwrap();
    let object = fs.create_blob(&mut prepared, root, b"hard-source", AttributeUpdate::default()).unwrap();
    prepared.flush().unwrap();
    let baseline = prepared.durable_bytes().to_vec();
    let mut success = ModelStorage::new(baseline.clone());
    let mut fs = Filesystem::mount(&mut success).unwrap();
    let start = success.effects().len();
    fs.hard_link(&mut success, root, b"hard-twin", object).unwrap();
    let failures: Vec<_> = success.effects()[start..].iter().filter(|effect| effect.kind != EffectKind::Read)
        .map(|effect| effect.sequence).collect();
    for sequence in failures {
        let mut storage = ModelStorage::new(baseline.clone()).with_injection(Inject::PowerLossAt(sequence));
        let mut fs = Filesystem::mount(&mut storage).unwrap();
        assert!(fs.hard_link(&mut storage, root, b"hard-twin", object).is_err());
        let mut recovered = ModelStorage::new(storage.durable_bytes().to_vec());
        let mut fs = Filesystem::mount(&mut recovered).unwrap();
        let linked = fs.find(&mut recovered, root, b"hard-twin").unwrap().is_some();
        assert_eq!(fs.inspect(&mut recovered, object).unwrap().references, if linked { 2 } else { 1 });
        fs.sync(&mut recovered).unwrap(); recovered.flush().unwrap();
        check_orphan_image(&recovered, &format!("hard-link-{sequence}"));
    }
}

#[test]
fn open_unlink_retains_data_until_last_close_and_reclaims_orphan_chain() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    let mut storage = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    let root = fs.root(&mut storage).unwrap();
    let free = fs.statistics().free_inodes;
    let mut objects = Vec::new();
    for name in [b"orphan-a", b"orphan-b", b"orphan-c"] {
        let object = fs.create_blob(&mut storage, root, name, AttributeUpdate::default()).unwrap();
        let Object::Blob(blob) = object else { panic!() };
        fs.write(&mut storage, blob, 0, &[0x5a;8193]).unwrap();
        let (edge, _) = fs.find(&mut storage, root, name).unwrap().unwrap();
        assert_eq!(fs.remove_open(&mut storage, edge).unwrap(), Some(object));
        assert!(fs.find(&mut storage, root, name).unwrap().is_none());
        assert_eq!(fs.inspect(&mut storage, object).unwrap().references, 0);
        fs.write(&mut storage, blob, 0, b"open").unwrap();
        let mut bytes = [0;4];
        fs.read(&mut storage, blob, 0, &mut bytes).unwrap();
        assert_eq!(&bytes,b"open");
        objects.push(object);
    }
    // Remove the middle, head and tail; each splice is journaled.
    for index in [1,2,0] {
        fs.release_orphan(&mut storage, objects[index]).unwrap();
        assert!(fs.inspect(&mut storage, objects[index]).is_err());
    }
    assert_eq!(fs.statistics().free_inodes, free);
    storage.flush().unwrap();
    check_orphan_image(&storage, "closed");
}

#[test]
fn orphan_recovery_is_read_only_until_mutation_and_survives_power_loss() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    use portable_ext4::test_support::EffectKind;
    let mut initial = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut initial).unwrap();
    let root = fs.root(&mut initial).unwrap();
    let object = fs.create_blob(&mut initial, root, b"open-file", AttributeUpdate::default()).unwrap();
    let Object::Blob(blob) = object else { panic!() };
    fs.write(&mut initial, blob, 0, &[0x42;8193]).unwrap();
    initial.flush().unwrap();
    let source = initial.durable_bytes().to_vec();
    for closing in [false, true] {
        let mut success = ModelStorage::new(source.clone());
        let mut fs = Filesystem::mount(&mut success).unwrap();
        let root = fs.root(&mut success).unwrap();
        let edge = fs.find(&mut success,root,b"open-file").unwrap().unwrap().0;
        let mut start = success.effects().len();
        fs.remove_open(&mut success,edge).unwrap();
        if closing {
            start = success.effects().len();
            fs.release_orphan(&mut success,object).unwrap();
        }
        let failures: Vec<_> = success.effects()[start..].iter()
            .filter(|e| e.kind != EffectKind::Read).map(|e| e.sequence).collect();
        for sequence in failures {
            let mut io = ModelStorage::new(source.clone()).with_injection(Inject::PowerLossAt(sequence));
            let mut fs = Filesystem::mount(&mut io).unwrap();
            let root = fs.root(&mut io).unwrap();
            let edge = fs.find(&mut io,root,b"open-file").unwrap().unwrap().0;
            let result = fs.remove_open(&mut io,edge);
            if closing { result.unwrap(); assert!(fs.release_orphan(&mut io,object).is_err()); }
            else { assert!(result.is_err()); }
            let mut recovered = ModelStorage::new(io.durable_bytes().to_vec());
            let mut fs = Filesystem::mount(&mut recovered).unwrap();
            let root = fs.root(&mut recovered).unwrap();
            let still_named = fs.find(&mut recovered,root,b"open-file").unwrap().is_some();
            assert!(recovered.effects().iter().all(|e| e.kind == EffectKind::Read));
            let was_orphan = fs.inspect(&mut recovered,object).is_ok_and(|info| info.references == 0);
            let free_before = fs.statistics().free_inodes;
            fs.create_blob(&mut recovered,root,b"recovery-trigger",AttributeUpdate::default()).unwrap();
            assert_eq!(fs.statistics().free_inodes, free_before - 1 + u64::from(was_orphan));
            if still_named {
                let mut bytes = [0;4];
                fs.read(&mut recovered,blob,0,&mut bytes).unwrap();
                assert_eq!(bytes,[0x42;4]);
            }
            recovered.flush().unwrap();
            check_orphan_image(&recovered, &format!("{closing}-{sequence}"));
        }
    }
}

#[test]
fn journal_checkpoint_and_orphan_recovery_can_be_interrupted_again() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    use portable_ext4::test_support::EffectKind;
    let mut seed = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut seed).unwrap();
    let root = fs.root(&mut seed).unwrap();
    let object = fs.create_blob(&mut seed,root,b"open-recovery",AttributeUpdate::default()).unwrap();
    let Object::Blob(blob) = object else { panic!() };
    fs.write(&mut seed,blob,0,&[0x37;8193]).unwrap();
    seed.flush().unwrap();
    let source = seed.durable_bytes().to_vec();
    let mut run = ModelStorage::new(source.clone());
    let mut fs = Filesystem::mount(&mut run).unwrap();
    let root = fs.root(&mut run).unwrap();
    let edge = fs.find(&mut run,root,b"open-recovery").unwrap().unwrap().0;
    let start = run.effects().len();
    fs.remove_open(&mut run,edge).unwrap();
    // The fourth barrier is after the commit record and home writes. A cut
    // here leaves a committed log that must be checkpointed before writing.
    let cut = run.effects()[start..].iter().filter(|e| e.kind == EffectKind::Flush).nth(3).unwrap().sequence;
    let mut broken = ModelStorage::new(source).with_injection(Inject::PowerLossAt(cut));
    let mut fs = Filesystem::mount(&mut broken).unwrap();
    let root = fs.root(&mut broken).unwrap();
    let edge = fs.find(&mut broken,root,b"open-recovery").unwrap().unwrap().0;
    assert!(fs.remove_open(&mut broken,edge).is_err());
    let source = broken.durable_bytes().to_vec();
    let mut success = ModelStorage::new(source.clone());
    let mut fs = Filesystem::mount(&mut success).unwrap();
    let root = fs.root(&mut success).unwrap();
    assert!(fs.find(&mut success,root,b"open-recovery").unwrap().is_none());
    let start = success.effects().len();
    fs.create_blob(&mut success,root,b"after-recovery",AttributeUpdate::default()).unwrap();
    let cuts: Vec<_> = success.effects()[start..].iter().filter(|e| e.kind != EffectKind::Read).map(|e| e.sequence).collect();
    for cut in cuts {
        let mut io = ModelStorage::new(source.clone()).with_injection(Inject::PowerLossAt(cut));
        let mut fs = Filesystem::mount(&mut io).unwrap();
        let root = fs.root(&mut io).unwrap();
        assert!(fs.find(&mut io,root,b"open-recovery").unwrap().is_none());
        assert!(fs.create_blob(&mut io,root,b"after-recovery",AttributeUpdate::default()).is_err());
        let mut io = ModelStorage::new(io.durable_bytes().to_vec());
        let mut fs = Filesystem::mount(&mut io).unwrap();
        let root = fs.root(&mut io).unwrap();
        assert!(fs.find(&mut io,root,b"open-recovery").unwrap().is_none());
        fs.create_blob(&mut io,root,b"second-recovery",AttributeUpdate::default()).unwrap();
        io.flush().unwrap();
        check_orphan_image(&io,&format!("repeat-{cut}"));
    }
}

#[test]
fn e2fsck_recovers_our_open_unlinked_inode() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    let mut storage = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    let root = fs.root(&mut storage).unwrap();
    let before = fs.statistics().free_inodes;
    let object = fs.create_blob(&mut storage,root,b"linux-orphan",AttributeUpdate::default()).unwrap();
    let Object::Blob(blob) = object else { panic!() };
    fs.write(&mut storage,blob,0,&[0x61;8193]).unwrap();
    let edge = fs.find(&mut storage,root,b"linux-orphan").unwrap().unwrap().0;
    fs.remove_open(&mut storage,edge).unwrap();
    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap()).join("linux-orphan.img");
    std::fs::write(&output,storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fy",output.to_str().unwrap()]).output().unwrap();
    assert!(matches!(check.status.code(),Some(0 | 1)), "{}{}",String::from_utf8_lossy(&check.stdout),String::from_utf8_lossy(&check.stderr));
    let mut storage = ModelStorage::new(std::fs::read(output).unwrap());
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    assert_eq!(fs.statistics().free_inodes,before);
    let root = fs.root(&mut storage).unwrap();
    assert!(fs.find(&mut storage,root,b"linux-orphan").unwrap().is_none());
    check_orphan_image(&storage,"linux-recovered");
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

fn inline_data_image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_INLINE_DATA_IMAGE"));
    std::fs::read(image_path).unwrap()
}

fn runtime_block_image(path: &str) -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap()).join(path);
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
        .entries(&mut storage, root, Default::default(), &mut |edge, info| {
            if edge.name == b"root-data.bin" {
                data = Some((edge.object, info));
            }
            Ok(true)
        })
        .unwrap();
    let (Object::Blob(blob), info) = data.unwrap() else {
        panic!("root-data.bin is not a blob")
    };
    assert_eq!(info.object, Object::Blob(blob));
    assert_eq!(info.size, 14);
    let mut contents = [0; 14];
    assert_eq!(
        graph.read(&mut storage, blob, 0, &mut contents).unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");
}

#[test]
fn graph_blobs_share_fast_symlink_and_inline_data_storage() {
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

    let mut storage = ModelStorage::new(inline_data_image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut inline = None;
    let mut fast = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            match edge.name {
                b"inline.bin" => inline = Some(edge.object),
                b"fast.link" => fast = Some(edge.object),
                _ => {}
            }
            Ok(true)
        })
        .unwrap();
    let Object::Blob(inline) = inline.unwrap() else {
        panic!("inline.bin is not a blob")
    };
    let Object::Blob(fast) = fast.unwrap() else {
        panic!("fast.link is not a blob")
    };

    let original = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ--inline-data-payload--0123456789";
    let mut readback = vec![0; original.len()];
    assert_eq!(
        graph.read(&mut storage, inline, 0, &mut readback).unwrap(),
        original.len()
    );
    assert_eq!(readback, original);
    let mut target = [0; 19];
    assert_eq!(graph.read(&mut storage, fast, 0, &mut target).unwrap(), 19);
    assert_eq!(&target, b"short-inline-target");

    // This write crosses from i_block into system.data without exposing that
    // representation through the Blob API.
    graph
        .write(&mut storage, inline, 55, b"CROSS-INLINE")
        .unwrap();
    graph.resize(&mut storage, inline, 75).unwrap();
    graph.resize(&mut storage, inline, 90).unwrap();
    let mut within = vec![0xff; 90];
    assert_eq!(
        graph.read(&mut storage, inline, 0, &mut within).unwrap(),
        90
    );
    assert_eq!(&within[55..67], b"CROSS-INLINE");
    assert_eq!(&within[75..], &[0; 15]);

    // Exceeding the inode's inline capacity converts either encoding to the
    // same extent-backed Blob without changing its public identity.
    graph.write(&mut storage, inline, 150, b"extent").unwrap();
    let long_target =
        b"this-symbolic-link-target-is-deliberately-longer-than-sixty-bytes-for-extents";
    graph.write(&mut storage, fast, 0, long_target).unwrap();
    let mut converted = vec![0xff; 156];
    assert_eq!(
        graph.read(&mut storage, inline, 0, &mut converted).unwrap(),
        156
    );
    assert_eq!(&converted[90..150], &[0; 60]);
    assert_eq!(&converted[150..], b"extent");
    let mut converted_target = vec![0; long_target.len()];
    assert_eq!(
        graph
            .read(&mut storage, fast, 0, &mut converted_target)
            .unwrap(),
        long_target.len()
    );
    assert_eq!(converted_target, long_target);

    storage.flush().unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("inline-data-mutated.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected inline conversion:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let attribute = std::process::Command::new("/usr/sbin/debugfs")
        .args([
            "-R",
            "ea_get /inline.bin user.keep",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        attribute.status.success() && attribute.stdout.windows(9).any(|part| part == b"preserved"),
        "inline conversion lost an unrelated inode xattr:\n{}\n{}",
        String::from_utf8_lossy(&attribute.stdout),
        String::from_utf8_lossy(&attribute.stderr)
    );
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
    use portable_ext4::Storage;
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
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

    const EXTENTS: u64 = 350;
    let mut fragmented = image();
    let artificial = add_artificial_fragmentation(&mut fragmented, EXTENTS as usize);
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

    for logical in 0..EXTENTS {
        graph
            .write(&mut storage, blob, logical * 4096, &[logical as u8 + 1])
            .unwrap();
    }
    for logical in 0..EXTENTS {
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
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

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
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

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
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

    let mut storage = ModelStorage::new(image());
    let mut graph = Graph::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut directory = None;
    graph
        .edges(&mut storage, root, Default::default(), &mut |edge| {
            if edge.name == b"dir" {
                directory = Some((edge.handle, edge.object));
            }
            Ok(true)
        })
        .unwrap();
    let (directory_edge, Object::Node(directory)) = directory.unwrap() else {
        panic!("dir is not a node")
    };

    // Reparent the indexed node without first linearizing its own contents.
    // Its intrinsic `..` record changes, but the htree and its checksum must
    // remain an indexed directory until an edge mutation requires conversion.
    let detached = graph.detach(&mut storage, directory_edge).unwrap();
    let (_, displaced) = graph.attach(&mut storage, root, b"dir", detached).unwrap();
    assert!(displaced.is_none());

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
    use portable_ext4::Storage;
    use portable_ext4::ext4::{Ext4 as Graph, Object};

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
    use portable_ext4::{BlockChanges, BlockOverlay, GraphJournal, Storage, StorageError};

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

    fn prepare(storage: &mut ModelStorage) -> (Graph, GraphJournal, BlockChanges) {
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
fn handle_filesystem_journals_atomic_graph_composition() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::{AttributeUpdate, Object};

    let mut storage = ModelStorage::new(image());
    let mut filesystem = Filesystem::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let object = filesystem
        .create_blob(
            &mut storage,
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
    filesystem
        .write(&mut storage, blob, 0, b"handle filesystem")
        .unwrap();
    let mut contents = [0; 17];
    assert_eq!(
        filesystem
            .read(&mut storage, blob, 0, &mut contents)
            .unwrap(),
        17
    );
    assert_eq!(&contents, b"handle filesystem");
    let (edge, found) = filesystem
        .find(&mut storage, root, b"handle-file")
        .unwrap()
        .unwrap();
    assert_eq!(found, object);
    filesystem.remove(&mut storage, edge).unwrap();
    assert!(
        filesystem
            .find(&mut storage, root, b"handle-file")
            .unwrap()
            .is_none()
    );

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

#[test]
fn handle_filesystem_journals_runtime_block_sizes() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::{AttributeUpdate, Object};

    for (path, block_size) in [
        (env!("EXT4_RUNTIME_BLOCK_1024"), 1024usize),
        (env!("EXT4_RUNTIME_BLOCK_2048"), 2048),
        (env!("EXT4_RUNTIME_BLOCK_8192"), 8192),
        (env!("EXT4_RUNTIME_BLOCK_65536"), 65536),
    ] {
        let mut storage = ModelStorage::new(runtime_block_image(path));
        let mut filesystem = Filesystem::mount(&mut storage).unwrap();
        let root = filesystem.root(&mut storage).unwrap();
        let (_, dir_object) = filesystem
            .find(&mut storage, root, b"dir")
            .unwrap()
            .unwrap();
        let Object::Node(dir) = dir_object else {
            panic!("fixture directory is not a node");
        };
        let (seed_edge, seed_object) = filesystem
            .find(&mut storage, dir, b"seed.bin")
            .unwrap()
            .unwrap();
        let Object::Blob(seed) = seed_object else {
            panic!("fixture seed is not a blob");
        };

        // These do not alter allocation counters and therefore prove that a
        // journal transaction need not contain the ext4 superblock.
        filesystem.write(&mut storage, seed, 0, b"RUNTIME").unwrap();
        filesystem
            .update_attributes(
                &mut storage,
                seed_object,
                AttributeUpdate {
                    modified: Some(0x1234_5678),
                    ..AttributeUpdate::default()
                },
            )
            .unwrap();
        filesystem
            .move_edge(&mut storage, seed_edge, dir, b"renamed.bin")
            .unwrap();

        let created = filesystem
            .create_blob(
                &mut storage,
                dir,
                b"spanning.bin",
                AttributeUpdate::default(),
            )
            .unwrap();
        let Object::Blob(created) = created else {
            panic!("created object is not a blob");
        };
        let payload = vec![0x5a; block_size + 17];
        filesystem
            .write(&mut storage, created, 0, &payload)
            .unwrap();
        let mut readback = vec![0; payload.len()];
        assert_eq!(
            filesystem
                .read(&mut storage, created, 0, &mut readback)
                .unwrap(),
            payload.len()
        );
        assert_eq!(readback, payload);

        let output = std::env::temp_dir().join(format!("portable-ext4-{block_size}.img"));
        std::fs::write(&output, storage.durable_bytes()).unwrap();
        let checked = std::process::Command::new("/usr/sbin/e2fsck")
            .args(["-fy", output.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "e2fsck rejected {block_size}-byte filesystem:\n{}\n{}",
            String::from_utf8_lossy(&checked.stdout),
            String::from_utf8_lossy(&checked.stderr)
        );
    }
}

#[test]
fn symlink_creation_is_atomic_across_power_loss() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::AttributeUpdate;
    use portable_ext4::test_support::EffectKind;
    for target in [b"dir/hello.txt".as_slice(), b"directory-with-a-name-long-enough-to-force-block-backed-symbolic-links/hello.txt"] {
        let source = image();
        let mut successful = ModelStorage::new(source.clone());
        let mut fs = Filesystem::mount(&mut successful).unwrap();
        let root = fs.root(&mut successful).unwrap();
        let start = successful.effects().len();
        fs.create_link(&mut successful, root, b"atomic-link", target, AttributeUpdate::default()).unwrap();
        let sequences: Vec<_> = successful.effects()[start..].iter()
            .filter(|e| !matches!(e.kind, EffectKind::Read)).map(|e| e.sequence).collect();
        let mut saw_old = false;
        let mut saw_new = false;
        for sequence in sequences {
            let mut storage = ModelStorage::new(source.clone()).with_injection(Inject::PowerLossAt(sequence));
            let mut fs = Filesystem::mount(&mut storage).unwrap();
            let root = fs.root(&mut storage).unwrap();
            assert!(fs.create_link(&mut storage, root, b"atomic-link", target, AttributeUpdate::default()).is_err());
            let mut recovered = ModelStorage::new(storage.durable_bytes().to_vec());
            let mut fs = Filesystem::mount(&mut recovered).unwrap();
            let root = fs.root(&mut recovered).unwrap();
            match fs.find(&mut recovered, root, b"atomic-link").unwrap() {
                None => saw_old = true,
                Some((_, object)) => {
                    saw_new = true;
                    let info = fs.inspect(&mut recovered, object).unwrap();
                    assert_eq!(info.format & 0xf000, 0xa000);
                    assert_eq!(info.size as usize, target.len());
                    let mut bytes = vec![0; target.len()];
                    assert_eq!(fs.read(&mut recovered, info.blob().unwrap(), 0, &mut bytes).unwrap(), target.len());
                    assert_eq!(bytes, target);
                }
            }
        }
        assert!(saw_old && saw_new);
    }
}

#[test]
fn read_intent_survives_journal_and_transaction_overlays() {
    use portable_ext4::{BlockOverlay, Filesystem, ReadKind, Storage, StorageError};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    struct Recording {
        inner: ModelStorage,
        reads: Vec<ReadKind>,
    }
    impl Storage for Recording {
        fn len(&self) -> u64 { self.inner.len() }
        fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), StorageError> {
            self.read_with_kind(offset, out, ReadKind::Metadata)
        }
        fn read_with_kind(&mut self, offset: u64, out: &mut [u8], kind: ReadKind) -> Result<(), StorageError> {
            self.reads.push(kind);
            self.inner.read(offset, out)
        }
        fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError> {
            self.inner.write(offset, bytes)
        }
        fn flush(&mut self) -> Result<(), StorageError> { self.inner.flush() }
    }
    let mut storage = Recording { inner: ModelStorage::new(image()), reads: Vec::new() };
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    let root = fs.root(&mut storage).unwrap();
    let Object::Blob(blob) = fs.create_blob(&mut storage, root, b"read-intent", AttributeUpdate {
        format: Some(0x8000 | 0o644), ..AttributeUpdate::default()
    }).unwrap() else { panic!("expected file") };
    fs.write(&mut storage, blob, 0, &[0x5a; 8192]).unwrap();
    // A fresh mount exercises uncached metadata intent; a warm inode should
    // not manufacture metadata reads just to demonstrate the hint.
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    storage.reads.clear();
    let mut data = [0; 8192];
    assert_eq!(fs.read(&mut storage, blob, 0, &mut data).unwrap(), data.len());
    assert_eq!(data, [0x5a; 8192]);
    assert!(storage.reads.contains(&ReadKind::Metadata));
    assert!(storage.reads.contains(&ReadKind::FileData));
    storage.reads.clear();
    assert_eq!(fs.read(&mut storage, blob, 0, &mut data).unwrap(), data.len());
    assert!(!storage.reads.is_empty());
    assert!(storage.reads.iter().all(|kind| *kind == ReadKind::FileData));

    storage.reads.clear();
    let mut overlay = BlockOverlay::new(&mut storage, 4096);
    overlay.write(0, &[0xaa; 4096]).unwrap();
    overlay.read_with_kind(0, &mut data, ReadKind::FileData).unwrap();
    assert_eq!(data[..4096], [0xaa; 4096]);
    drop(overlay);
    assert_eq!(storage.reads, [ReadKind::FileData]);
}

#[test]
fn writeback_groups_visible_mutations_and_sync_persists_them() {
    use portable_ext4::{Filesystem, Storage};
    use portable_ext4::ext4::{AttributeUpdate, Object};
    use portable_ext4::test_support::EffectKind;
    let mut storage = ModelStorage::new(image());
    let mut filesystem = Filesystem::mount(&mut storage).unwrap();
    filesystem.enable_writeback(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let before = storage.effects().len();
    let a = filesystem.create_blob(&mut storage, root, b"batched-a", AttributeUpdate::default()).unwrap();
    let b = filesystem.create_blob(&mut storage, root, b"batched-b", AttributeUpdate::default()).unwrap();
    let Object::Blob(blob) = a else { panic!("not a blob"); };
    filesystem.write(&mut storage, blob, 0, b"first").unwrap();
    filesystem.write(&mut storage, blob, 5, b" second").unwrap();
    assert_eq!(filesystem.find(&mut storage, root, b"batched-b").unwrap().unwrap().1, b);
    let mut bytes = [0; 12];
    assert_eq!(filesystem.read(&mut storage, blob, 0, &mut bytes).unwrap(), 12);
    assert_eq!(&bytes, b"first second");
    assert!(!storage.effects()[before..].iter().any(|effect| effect.kind != EffectKind::Read));
    // Failed operations must preserve all previously staged edits.
    assert_eq!(filesystem.create_blob(&mut storage, root, b"batched-a", AttributeUpdate::default()).unwrap_err(), Error::AlreadyExists);
    assert!(filesystem.has_pending());
    filesystem.sync(&mut storage).unwrap();
    assert!(!filesystem.has_pending());
    assert_eq!(storage.effects()[before..].iter().filter(|effect| effect.kind == EffectKind::Flush).count(), 5);
    storage.power_loss();
    let mut recovered = Filesystem::mount(&mut storage).unwrap();
    let root = recovered.root(&mut storage).unwrap();
    let object = recovered.find(&mut storage, root, b"batched-a").unwrap().unwrap().1;
    let Object::Blob(blob) = object else { panic!("not a blob"); };
    assert_eq!(recovered.read(&mut storage, blob, 0, &mut bytes).unwrap(), 12);
    assert_eq!(&bytes, b"first second");
    assert!(recovered.find(&mut storage, root, b"batched-b").unwrap().is_some());
    storage.flush().unwrap();
}

#[test]
fn extending_files_does_not_rescan_exhausted_groups_for_every_block() {
    use portable_ext4::{Storage, ext4::{Ext4, EdgeCursor, Object}};
    use portable_ext4::test_support::EffectKind;
    let mut storage = ModelStorage::new(multi_group_image());
    let mut graph = Ext4::mount(&mut storage).unwrap();
    let root = graph.root(&mut storage).unwrap();
    let mut target = None;
    graph.edges(&mut storage, root, EdgeCursor::START, &mut |edge| {
        if edge.name == b"target.bin" { target = Some(edge.object); }
        Ok(true)
    }).unwrap();
    let Object::Blob(blob) = target.unwrap() else { panic!("target is not a file"); };
    // Group 0 has two free data blocks. This growth must leave it behind.
    graph.write(&mut storage, blob, 0, &[0x5a; 3 * 4096]).unwrap();
    let before = storage.effects().len();
    let payload = [0xa5; 32 * 4096];
    graph.write(&mut storage, blob, 3 * 4096, &payload).unwrap();
    let group_zero_reads = storage.effects()[before..].iter().filter(|effect| {
        effect.kind == EffectKind::Read && effect.offset == 4096 && effect.len == 64
    }).count();
    // Accessing the existing inode can still read group 0's descriptor;
    // allocating 32 new blocks must not add 32 exhausted-group probes.
    assert!(group_zero_reads < 12, "repeated exhausted-group searches: {group_zero_reads}");
    let mut readback = [0; 32 * 4096];
    assert_eq!(graph.read(&mut storage, blob, 3 * 4096, &mut readback).unwrap(), payload.len());
    assert_eq!(readback, payload);
    // Releasing earlier space must remain reusable after a hint advances.
    graph.resize(&mut storage, blob, 0).unwrap();
    graph.write(&mut storage, blob, 0, &payload).unwrap();
    assert_eq!(graph.read(&mut storage, blob, 0, &mut readback).unwrap(), payload.len());
    assert_eq!(readback, payload);
    storage.flush().unwrap();
}

#[test]
fn grouped_writeback_is_atomic_across_every_commit_failure() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::AttributeUpdate;
    fn stage(storage: &mut ModelStorage) -> Filesystem {
        let mut filesystem = Filesystem::mount(storage).unwrap();
        filesystem.enable_writeback(storage).unwrap();
        let root = filesystem.root(storage).unwrap();
        filesystem.create_blob(storage, root, b"group-one", AttributeUpdate::default()).unwrap();
        filesystem.create_node(storage, root, b"group-two", AttributeUpdate::default()).unwrap();
        filesystem
    }
    fn check(bytes: Vec<u8>) -> bool {
        let mut storage = ModelStorage::new(bytes);
        let mut filesystem = Filesystem::mount(&mut storage).unwrap();
        let root = filesystem.root(&mut storage).unwrap();
        let one = filesystem.find(&mut storage, root, b"group-one").unwrap().is_some();
        let two = filesystem.find(&mut storage, root, b"group-two").unwrap().is_some();
        assert_eq!(one, two, "partially published writeback batch");
        one
    }
    let source = image();
    let mut storage = ModelStorage::new(source.clone());
    let mut filesystem = stage(&mut storage);
    assert!(!check(storage.durable_bytes().to_vec()));
    let begin = storage.effects().len();
    filesystem.sync(&mut storage).unwrap();
    let end = storage.effects().len();
    let mut old = false;
    let mut new = false;
    for sequence in begin..end {
        let mut storage = ModelStorage::new(source.clone()).with_injection(Inject::PowerLossAt(sequence));
        let mut filesystem = stage(&mut storage);
        assert!(filesystem.sync(&mut storage).is_err());
        if check(storage.durable_bytes().to_vec()) { new = true; } else { old = true; }
    }
    assert!(old && new);
}

#[test]
fn bounded_writeback_rolls_over_without_losing_file_contents() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::{AttributeUpdate, Object};
    use portable_ext4::test_support::EffectKind;
    let mut storage = ModelStorage::new(image());
    let mut filesystem = Filesystem::mount(&mut storage).unwrap();
    filesystem.enable_writeback(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let begin = storage.effects().len();
    for number in 0..80u8 {
        let name = format!("rollover-{number}");
        let object = filesystem.create_blob(&mut storage, root, name.as_bytes(), AttributeUpdate::default()).unwrap();
        let Object::Blob(blob) = object else { panic!("not a blob"); };
        filesystem.write(&mut storage, blob, 0, &[number; 16384]).unwrap();
    }
    assert!(storage.effects()[begin..].iter().any(|effect| effect.kind == EffectKind::Flush));
    filesystem.sync(&mut storage).unwrap();
    let flushes = storage.effects()[begin..].iter().filter(|effect| effect.kind == EffectKind::Flush).count();
    assert!(flushes < 100, "small mutations were not grouped: {flushes}");
    storage.power_loss();
    let mut filesystem = Filesystem::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    for number in 0..80u8 {
        let name = format!("rollover-{number}");
        let object = filesystem.find(&mut storage, root, name.as_bytes()).unwrap().unwrap().1;
        let Object::Blob(blob) = object else { panic!("not a blob"); };
        let mut bytes = [0; 16384];
        assert_eq!(filesystem.read(&mut storage, blob, 0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(bytes, [number; 16384]);
    }
}

#[test]
fn decoded_inode_facts_are_reused_and_follow_mutation_rollback_and_reuse() {
    use portable_ext4::Filesystem;
    use portable_ext4::ext4::{AttributeUpdate, Object};
    let mut storage = ModelStorage::new(image());
    let mut fs = Filesystem::mount(&mut storage).unwrap();
    fs.enable_writeback(&mut storage).unwrap();
    let root = fs.root(&mut storage).unwrap();
    let attributes = AttributeUpdate { format: Some(0x8000 | 0o640), owner: Some(123),
        modified: Some(1700000000), ..AttributeUpdate::default() };
    let object = fs.create_blob(&mut storage, root, b"decoded-test", attributes).unwrap();
    let Object::Blob(blob) = object else { panic!() };
    let expected = fs.inspect(&mut storage, object).unwrap();
    let effects = storage.effects().len();
    for _ in 0..1000 {
        assert_eq!(fs.inspect(&mut storage, object).unwrap(), expected);
        assert_eq!(fs.root(&mut storage).unwrap(), root);
    }
    assert_eq!(storage.effects().len(), effects, "hot inode reads repeated storage work");
    fs.write(&mut storage, blob, 0, &[0x5a;8193]).unwrap();
    fs.update_attributes(&mut storage, object, AttributeUpdate { format: Some(0x8000|0o600),
        owner: Some(456), modified: Some(1700000123), ..AttributeUpdate::default() }).unwrap();
    // An aborted namespace mutation must not retire previously staged facts.
    assert!(fs.create_blob(&mut storage, root, b"decoded-test", attributes).is_err());
    let after_failure = storage.effects().len();
    let current = fs.inspect(&mut storage, object).unwrap();
    assert_eq!(storage.effects().len(), after_failure, "read-only failure discarded hot metadata");
    assert_eq!((current.size,current.owner,current.modified,current.format),
        (8193,456,1700000123,0x8000|0o600));
    let (edge,_) = fs.find(&mut storage,root,b"decoded-test").unwrap().unwrap();
    fs.remove(&mut storage,edge).unwrap();
    assert!(fs.inspect(&mut storage,object).is_err());
    let replacement = fs.create_blob(&mut storage,root,b"decoded-test",attributes).unwrap();
    assert_eq!(replacement,object,"fixture must exercise inode reuse");
    let current = fs.inspect(&mut storage,replacement).unwrap();
    assert_eq!((current.size,current.owner,current.modified,current.format),
        (0,123,1700000000,0x8000|0o640));
    fs.sync(&mut storage).unwrap();
    storage.power_loss();
    let mut recovered = Filesystem::mount(&mut storage).unwrap();
    assert_eq!(recovered.inspect(&mut storage,replacement).unwrap(),current);
}
