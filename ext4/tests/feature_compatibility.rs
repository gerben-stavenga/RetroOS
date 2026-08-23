use portable_ext4::test_support::{ModelStorage, PathExt4, PathTransaction};
use portable_ext4::{Corrupt, Error, Ext4, Inode};

fn image(relative: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap()).join(relative);
    std::fs::read(path).unwrap()
}

fn enumerate(filesystem: &mut Ext4, storage: &mut ModelStorage, root: &Inode) -> usize {
    let mut cookie = 0;
    let mut total = 0;
    loop {
        let mut entries = Vec::new();
        match filesystem
            .list(storage, root, cookie, &mut entries, 37)
            .unwrap()
        {
            Some(next) => cookie = next,
            None => {
                total += entries.len();
                return total;
            }
        }
        total += entries.len();
    }
}

fn mounts_and_enumerates(relative: &str, expected: usize) {
    let mut storage = ModelStorage::new(image(relative));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    assert_eq!(enumerate(&mut filesystem, &mut storage, &root), expected);
}

#[test]
fn mounts_orphan_file_filesystem() {
    mounts_and_enumerates(env!("EXT4_ORPHAN_FILE_IMAGE"), 2);
}

#[test]
fn reads_and_writes_current_distro_default_profile() {
    let mut storage = ModelStorage::new(image(env!("EXT4_MODERN_DEFAULTS_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let mut contents = [0; 14];
    assert_eq!(
        filesystem
            .read(&mut storage, "/file-0.txt", 0, &mut contents)
            .unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");

    {
        let mut transaction = filesystem.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        transaction
            .overwrite(&mut storage, "/file-0.txt", 0, b"modern")
            .unwrap();
        transaction.commit(&mut storage).unwrap();
    }
    assert_eq!(
        filesystem
            .read(&mut storage, "/file-0.txt", 0, &mut contents)
            .unwrap(),
        14
    );
    assert_eq!(&contents, b"modernle ext4\n");

    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("modern-defaults-write.img");
    std::fs::write(&output, storage.durable_bytes()).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected modern-default write:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn reads_descriptors_from_later_meta_block_groups() {
    mounts_and_enumerates(env!("EXT4_META_BG_IMAGE"), 401);
}

#[test]
fn validates_legacy_group_descriptor_checksums() {
    mounts_and_enumerates(env!("EXT4_LEGACY_GDT_CSUM_IMAGE"), 2);
}

#[test]
fn rejects_bad_legacy_group_descriptor_checksum() {
    let mut bytes = image(env!("EXT4_LEGACY_GDT_CSUM_IMAGE"));
    let descriptor = 4096;
    bytes[descriptor + 0x1c] ^= 1;
    let mut storage = ModelStorage::new(bytes);
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    assert_eq!(
        filesystem.root(&mut storage),
        Err(Error::Corrupt(Corrupt::GroupDescriptorChecksum(0)))
    );
}

#[test]
fn mounts_layout_compatible_modern_incompat_features() {
    mounts_and_enumerates(env!("EXT4_MODERN_INCOMPAT_IMAGE"), 2);
}

#[test]
fn reads_bigalloc_checksum_seed_sparse_super2_layout() {
    let mut storage = ModelStorage::new(image(env!("EXT4_MODERN_LAYOUT_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let mut entries = Vec::new();
    filesystem
        .list(&mut storage, &root, 0, &mut entries, 8)
        .unwrap();
    let file = entries
        .into_iter()
        .find(|entry| entry.name == b"file-0.txt")
        .unwrap();
    let mut contents = [0; 14];
    assert_eq!(
        filesystem
            .read_inode(&mut storage, &file.inode, 0, &mut contents)
            .unwrap(),
        contents.len()
    );
    assert_eq!(&contents, b"portable ext4\n");
}

#[test]
fn reads_inline_regular_file_data() {
    let mut storage = ModelStorage::new(image(env!("EXT4_INLINE_DATA_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let mut entries = Vec::new();
    filesystem
        .list(&mut storage, &root, 0, &mut entries, 8)
        .unwrap();
    let file = entries
        .into_iter()
        .find(|entry| entry.name == b"file-0.txt")
        .unwrap();
    let mut contents = [0; 64];
    let count = filesystem
        .read_inode(&mut storage, &file.inode, 0, &mut contents)
        .unwrap();
    assert_eq!(
        &contents[..count],
        &b"portable ext4\n".repeat(6)[..contents.len()]
    );
    let mut tail = [0; 32];
    let tail_count = filesystem
        .read_inode(&mut storage, &file.inode, contents.len() as u64, &mut tail)
        .unwrap();
    assert_eq!(
        &tail[..tail_count],
        &b"portable ext4\n".repeat(6)[contents.len()..]
    );
}

#[test]
fn enumerates_inline_directories() {
    let mut storage = ModelStorage::new(image(env!("EXT4_INLINE_DIRECTORY_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let mut entries = Vec::new();
    filesystem
        .list(&mut storage, &root, 0, &mut entries, 8)
        .unwrap();
    let tiny = entries
        .iter()
        .find(|entry| entry.name == b"tiny")
        .unwrap()
        .clone();
    let mut children = Vec::new();
    let mut cookie = 0;
    loop {
        match filesystem
            .list(&mut storage, &tiny.inode, cookie, &mut children, 2)
            .unwrap()
        {
            Some(next) => cookie = next,
            None => break,
        }
    }
    assert_eq!(children.len(), 6);
    assert!(children.iter().any(|entry| entry.name == b"child-5"));

    let link = entries
        .into_iter()
        .find(|entry| entry.name == b"long-link")
        .unwrap();
    assert_eq!(
        filesystem.read_symlink(&mut storage, &link.inode).unwrap(),
        b"012345678901234567890123456789012345678901234567890123456789012345678901234567890123"
    );
}

#[test]
fn reads_inode_body_and_external_extended_attributes() {
    let mut storage = ModelStorage::new(image(env!("EXT4_EXTENDED_ATTRIBUTES_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let root = filesystem.root(&mut storage).unwrap();
    let mut entries = Vec::new();
    filesystem
        .list(&mut storage, &root, 0, &mut entries, 8)
        .unwrap();
    let file = entries
        .into_iter()
        .find(|entry| entry.name == b"attributed.txt")
        .unwrap();
    let attributes = filesystem
        .extended_attributes(&mut storage, &file.inode)
        .unwrap();
    assert!(attributes.iter().any(|attribute| {
        attribute.namespace == 1 && attribute.name == b"small" && attribute.value == b"small-value"
    }));
    assert!(attributes.iter().any(|attribute| {
        attribute.namespace == 6
            && attribute.name == b"large"
            && attribute.value == vec![b'x'; 1000]
    }));
}

#[test]
fn unlink_releases_an_exclusive_external_xattr_block() {
    let mut storage = ModelStorage::new(image(env!("EXT4_EXTENDED_ATTRIBUTES_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    {
        let mut transaction = filesystem.begin_transaction();
        transaction.reserve_blocks(12).unwrap();
        transaction.unlink(&mut storage, "/attributed.txt").unwrap();
        transaction.commit(&mut storage).unwrap();
    }
    assert_eq!(
        filesystem.stat(&mut storage, "/attributed.txt"),
        Err(Error::NotFound)
    );
    let durable = storage.durable_bytes().to_vec();
    let output =
        std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap()).join("xattr-unlink.img");
    std::fs::write(&output, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected xattr unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn unlink_decrements_a_shared_external_xattr_block() {
    let mut storage = ModelStorage::new(image(env!("EXT4_EXTENDED_ATTRIBUTES_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    {
        let mut transaction = filesystem.begin_transaction();
        transaction.reserve_blocks(12).unwrap();
        transaction.unlink(&mut storage, "/shared-a.txt").unwrap();
        transaction.commit(&mut storage).unwrap();
    }
    assert_eq!(
        filesystem.stat(&mut storage, "/shared-a.txt"),
        Err(Error::NotFound)
    );
    let survivor = filesystem.stat(&mut storage, "/shared-b.txt").unwrap();
    let attributes = filesystem
        .extended_attributes(&mut storage, &survivor)
        .unwrap();
    assert!(attributes.iter().any(|attribute| {
        attribute.namespace == 6
            && attribute.name == b"shared"
            && attribute.value == vec![b'x'; 1000]
    }));

    let durable = storage.durable_bytes().to_vec();
    let output = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("shared-xattr-unlink.img");
    std::fs::write(&output, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected shared-xattr unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn reads_extended_attribute_values_from_ea_inodes() {
    let mut storage = ModelStorage::new(image(env!("EXT4_EA_INODE_IMAGE")));
    let mut filesystem = Ext4::mount(&mut storage).unwrap();
    let file = filesystem.stat(&mut storage, "/attributed.txt").unwrap();
    let attributes = filesystem.extended_attributes(&mut storage, &file).unwrap();
    assert!(attributes.iter().any(|attribute| {
        attribute.namespace == 1
            && attribute.name == b"large"
            && attribute.value == vec![b'z'; 4096]
    }));
}
