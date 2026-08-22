use portable_ext4::test_support::{EffectKind, Inject, ModelError, ModelStorage};
use portable_ext4::{Corrupt, Error, Ext4, Timestamp};

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

fn linear_directory_image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_LINEAR_DIRECTORY_IMAGE"));
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

fn put_be16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_be32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
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
    let bitmap_block = (u64::from(le32(bytes, descriptor + 0x20)) << 32)
        | u64::from(le32(bytes, descriptor));
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
/// The returned list can be released after the transaction, restoring a
/// completely ordinary filesystem for e2fsck while forcing deterministic
/// one-block allocation runs during the operation under test.
fn add_artificial_fragmentation(bytes: &mut [u8], gaps: usize) -> Vec<u64> {
    const SUPERBLOCK: usize = 1024;
    let block_size = 1024usize << le32(bytes, SUPERBLOCK + 0x18);
    let descriptor = block_size;
    let blocks_per_group = u64::from(le32(bytes, SUPERBLOCK + 0x20));
    let bitmap_block = (u64::from(le32(bytes, descriptor + 0x20)) << 32)
        | u64::from(le32(bytes, descriptor));
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
    let bitmap_block = (u64::from(le32(bytes, descriptor + 0x20)) << 32)
        | u64::from(le32(bytes, descriptor));
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

fn image_with_committed_journal_update() -> Vec<u8> {
    const SUPERBLOCK: usize = 1024;
    const JBD2_MAGIC: u32 = 0xc03b_3998;
    let mut bytes = image();
    let block_size = 1024usize << le32(&bytes, SUPERBLOCK + 0x18);

    let mut probe = Ext4::mount(ModelStorage::new(bytes.clone())).unwrap();
    let mut old_contents = [0; 14];
    probe.read("/dir/hello.txt", 0, &mut old_contents).unwrap();
    let target = probe.storage().effects().last().unwrap().offset / block_size as u64;

    let descriptor_table = block_size;
    let inode_table = le32(&bytes, descriptor_table + 8) as usize;
    let inode_size = usize::from(le16(&bytes, SUPERBLOCK + 0x58));
    let journal_inode = inode_table * block_size + 7 * inode_size;
    let extent_root = journal_inode + 0x28;
    assert_eq!(le16(&bytes, extent_root), 0xf30a);
    assert_eq!(le16(&bytes, extent_root + 6), 0);
    assert_eq!(le32(&bytes, extent_root + 12), 0);
    let journal_start = (u64::from(le16(&bytes, extent_root + 18)) << 32)
        | u64::from(le32(&bytes, extent_root + 20));
    let journal_start = journal_start as usize * block_size;

    let sequence = u32::from_be_bytes(
        bytes[journal_start + 0x18..journal_start + 0x1c]
            .try_into()
            .unwrap(),
    );
    put_be32(&mut bytes, journal_start + 0x1c, 1);

    let descriptor = journal_start + block_size;
    bytes[descriptor..descriptor + block_size].fill(0);
    put_be32(&mut bytes, descriptor, JBD2_MAGIC);
    put_be32(&mut bytes, descriptor + 4, 1);
    put_be32(&mut bytes, descriptor + 8, sequence);
    put_be32(&mut bytes, descriptor + 12, target as u32);
    put_be16(&mut bytes, descriptor + 18, 8); // last tag
    let uuid = bytes[journal_start + 0x30..journal_start + 0x40].to_vec();
    bytes[descriptor + 20..descriptor + 36].copy_from_slice(&uuid);

    let data = journal_start + 2 * block_size;
    let home = target as usize * block_size;
    let home_block = bytes[home..home + block_size].to_vec();
    bytes[data..data + block_size].copy_from_slice(&home_block);
    bytes[data..data + 14].copy_from_slice(b"journal ext4!\n");

    let commit = journal_start + 3 * block_size;
    bytes[commit..commit + block_size].fill(0);
    put_be32(&mut bytes, commit, JBD2_MAGIC);
    put_be32(&mut bytes, commit + 4, 2);
    put_be32(&mut bytes, commit + 8, sequence);

    let incompat = le32(&bytes, SUPERBLOCK + 0x60) | 4;
    bytes[SUPERBLOCK + 0x60..SUPERBLOCK + 0x64].copy_from_slice(&incompat.to_le_bytes());
    let checksum = crc32c(u32::MAX, &bytes[SUPERBLOCK..SUPERBLOCK + 0x3fc]);
    bytes[SUPERBLOCK + 0x3fc..SUPERBLOCK + 0x400].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn image_with_checksum_v3_journal() -> Vec<u8> {
    const SUPERBLOCK: usize = 1024;
    let mut bytes = image();
    let block_size = 1024usize << le32(&bytes, SUPERBLOCK + 0x18);
    let descriptor_table = block_size;
    let inode_table = le32(&bytes, descriptor_table + 8) as usize;
    let inode_size = usize::from(le16(&bytes, SUPERBLOCK + 0x58));
    let journal_inode = inode_table * block_size + 7 * inode_size;
    let extent_root = journal_inode + 0x28;
    assert_eq!(le16(&bytes, extent_root), 0xf30a);
    assert_eq!(le32(&bytes, extent_root + 12), 0);
    let journal_start = ((u64::from(le16(&bytes, extent_root + 18)) << 32)
        | u64::from(le32(&bytes, extent_root + 20))) as usize
        * block_size;

    put_be32(&mut bytes, journal_start + 0x28, 16);
    bytes[journal_start + 0x50] = 4;
    put_be32(&mut bytes, journal_start + 0xfc, 0);
    let checksum = crc32c(u32::MAX, &bytes[journal_start..journal_start + 1024]);
    put_be32(&mut bytes, journal_start + 0xfc, checksum);
    bytes
}

fn assert_atomic_file_view(bytes: &[u8], file_name: &str, context: &str) -> bool {
    let mut remounted = Ext4::mount(ModelStorage::new(bytes.to_vec()))
        .unwrap_or_else(|error| panic!("{context} failed remount: {error:?}"));
    let is_new = match remounted.stat(file_name) {
        Ok(inode) => {
            assert_eq!(inode.mode, 0o100644, "{context}");
            assert_eq!(inode.size, 0, "{context}");
            true
        }
        Err(Error::NotFound) => false,
        Err(error) => panic!("{context} exposed {error:?}"),
    };

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join(format!("journal-{context}.img"));
    std::fs::write(&output_path, bytes).unwrap();
    let recovery = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fy", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        matches!(recovery.status.code(), Some(0 | 1)),
        "e2fsck could not recover {context}:\n{}\n{}",
        String::from_utf8_lossy(&recovery.stdout),
        String::from_utf8_lossy(&recovery.stderr)
    );
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck recovery left errors in {context}:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    is_new
}

#[test]
fn reads_file_from_mke2fs_image() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let inode = fs.stat("/dir/hello.txt").unwrap();
    assert_eq!(inode.size, 14);

    let mut contents = [0; 32];
    let count = fs.read("/dir/hello.txt", 0, &mut contents).unwrap();
    assert_eq!(&contents[..count], b"portable ext4\n");

    let count = fs.read("/dir/file-299", 0, &mut contents).unwrap();
    assert_eq!(&contents[..count], b"portable ext4\n");
}

#[test]
fn iterates_indexed_directory_with_opaque_cookies_and_reads_symlink() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let mut entries = Vec::new();
    let mut cookie = 0;
    loop {
        let before = entries.len();
        match fs.read_dir("/dir", cookie, &mut entries, 17).unwrap() {
            Some(next) => {
                assert!(next > cookie);
                assert_eq!(entries.len() - before, 17);
                cookie = next;
            }
            None => break,
        }
    }
    assert_eq!(entries.len(), 303);
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(entries[0].name, b"empty.bin");
    assert!(entries.iter().any(|entry| entry.name == b"file-299"));
    let link = entries
        .iter()
        .find(|entry| entry.name == b"hello.link")
        .unwrap();
    assert!(link.inode.is_symlink());
    assert_eq!(fs.read_link("/dir/hello.link").unwrap(), b"hello.txt");
    let mut contents = [0; 14];
    assert_eq!(fs.read("/dir/hello.link", 0, &mut contents).unwrap(), 14);
    assert_eq!(&contents, b"portable ext4\n");
    assert_eq!(
        fs.read("/dir.link/hello.txt", 0, &mut contents).unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");
}

#[test]
fn replays_committed_journal_from_mke2fs_image_without_writing() {
    let image = image_with_committed_journal_update();
    let mut fs = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut contents = [0; 14];
    assert_eq!(fs.read("/dir/hello.txt", 0, &mut contents).unwrap(), 14);
    assert_eq!(&contents, b"journal ext4!\n");
    assert_eq!(fs.recovered_blocks(), 1);
    assert_eq!(fs.into_storage().durable_bytes(), image);
}

#[test]
fn commits_created_file_through_checksum_v3_journal() {
    let image = image_with_checksum_v3_journal();
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/", "committed.bin", 0o640)
            .unwrap();
        transaction.commit().unwrap();
    }
    let storage = fs.into_storage();
    assert_eq!(storage.pending_writes(), 0);
    let durable = storage.durable_bytes().to_vec();

    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let inode = remounted.stat("/committed.bin").unwrap();
    assert_eq!(inode.mode, 0o100640);
    assert_eq!(inode.size, 0);
    assert_eq!(remounted.recovered_blocks(), 0);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("journal-committed.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected journal commit:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn commits_through_normal_mke2fs_unchecksummed_journal() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/", "normal.bin", 0o644)
            .unwrap();
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/normal.bin").unwrap().mode, 0o100644);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("normal-journal-commit.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected normal journal commit:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn initializes_and_commits_multiblock_file() {
    let mut payload: Vec<u8> = (0..9000).map(|index| (index % 251) as u8).collect();
    payload[..4].copy_from_slice(&0xc03b_3998u32.to_be_bytes());
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction
            .initialize_file("/dir/empty.bin", &payload)
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 7);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/dir/empty.bin").unwrap().size, 9000);
    let mut contents = vec![0; payload.len()];
    assert_eq!(
        remounted.read("/dir/empty.bin", 0, &mut contents).unwrap(),
        payload.len()
    );
    assert_eq!(contents, payload);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("initialized-multiblock.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected initialized multi-block file:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn appends_across_partial_and_new_blocks() {
    let mut appended: Vec<u8> = (0..9000).map(|index| (index % 239) as u8).collect();
    appended[4082..4086].copy_from_slice(&0xc03b_3998u32.to_be_bytes());
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.append("/dir/hello.txt", &appended).unwrap();
        assert_eq!(transaction.dirty_blocks(), 7);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/dir/hello.txt").unwrap().size, 9014);
    let mut contents = vec![0; 9014];
    assert_eq!(
        remounted.read("/dir/hello.txt", 0, &mut contents).unwrap(),
        contents.len()
    );
    assert_eq!(&contents[..14], b"portable ext4\n");
    assert_eq!(&contents[14..], appended);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("appended-multiblock.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected appended multi-block file:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn writes_across_eof_and_resizes_through_one_file_editor() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let mut expected = vec![0x31; 9_000];
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(16).unwrap();
        transaction
            .initialize_file("/root-empty.bin", &expected)
            .unwrap();
        transaction.commit().unwrap();
    }

    let crossing = vec![0x72; 6_000];
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(16).unwrap();
        transaction
            .write_at("/root-empty.bin", 3_500, &crossing)
            .unwrap();
        transaction.commit().unwrap();
    }
    expected.resize(9_500, 0);
    expected[3_500..9_500].copy_from_slice(&crossing);

    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(16).unwrap();
        transaction.resize("/root-empty.bin", 15_000).unwrap();
        transaction.commit().unwrap();
    }
    expected.resize(15_000, 0);
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(16).unwrap();
        transaction.resize("/root-empty.bin", 5_000).unwrap();
        transaction.commit().unwrap();
    }
    expected.truncate(5_000);
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(16).unwrap();
        transaction.resize("/root-empty.bin", 7_000).unwrap();
        transaction.commit().unwrap();
    }
    expected.resize(7_000, 0);

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        remounted
            .read("/root-empty.bin", 0, &mut actual)
            .unwrap(),
        actual.len()
    );
    assert_eq!(actual, expected);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("file-editor-resize.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected file editor resize:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn allocates_one_transaction_across_two_block_groups() {
    let original = multi_group_image();
    let descriptor_table = 4096usize;
    let descriptor_size = usize::from(le16(&original, 1024 + 0xfe));
    assert_eq!(le32(&original, 1024 + 0x20), 1024);
    assert_eq!(descriptor_size, 64);
    let free = |bytes: &[u8], group: usize| {
        let descriptor = descriptor_table + group * descriptor_size;
        u64::from(le16(bytes, descriptor + 0x0c))
            | (u64::from(le16(bytes, descriptor + 0x2c)) << 16)
    };
    let flags =
        |bytes: &[u8], group: usize| le16(bytes, descriptor_table + group * descriptor_size + 0x12);
    assert_eq!(free(&original, 0), 2);
    assert!(free(&original, 1) >= 2);
    assert_ne!(flags(&original, 1) & 0x0002, 0);

    let payload: Vec<u8> = (0..9000).map(|index| (index % 197) as u8).collect();
    let mut fs = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        transaction
            .initialize_file("/target.bin", &payload)
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 8);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    assert_eq!(free(&durable, 0), 0);
    assert_eq!(free(&durable, 1), free(&original, 1) - 1);
    assert_eq!(flags(&durable, 1) & 0x0002, 0);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/target.bin").unwrap().size, 9000);
    let mut contents = vec![0; payload.len()];
    assert_eq!(
        remounted.read("/target.bin", 0, &mut contents).unwrap(),
        payload.len()
    );
    assert_eq!(contents, payload);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("allocated-across-groups.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected cross-group allocation:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_cross_group_allocation_read_is_fallible_before_dirtying() {
    let image = multi_group_image();
    let payload = vec![0x74; 9000];
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(8).unwrap();
    transaction
        .initialize_file("/target.bin", &payload)
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(8).unwrap();
                assert_eq!(
                    transaction
                        .initialize_file("/target.bin", &payload)
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn creates_inode_in_a_lazily_initialized_later_group() {
    let original = inode_group_image();
    let descriptor_table = 4096usize;
    let descriptor_size = usize::from(le16(&original, 1024 + 0xfe));
    let descriptor = |group: usize| descriptor_table + group * descriptor_size;
    let free_inodes = |bytes: &[u8], group: usize| {
        let at = descriptor(group);
        u32::from(le16(bytes, at + 0x0e)) | (u32::from(le16(bytes, at + 0x2e)) << 16)
    };
    let flags = |bytes: &[u8], group: usize| le16(bytes, descriptor(group) + 0x12);
    let unused = |bytes: &[u8], group: usize| {
        let at = descriptor(group);
        u32::from(le16(bytes, at + 0x1c)) | (u32::from(le16(bytes, at + 0x3c)) << 16)
    };
    assert_eq!(le32(&original, 1024 + 0x28), 1024);
    assert_eq!(free_inodes(&original, 0), 0);
    assert_eq!(free_inodes(&original, 1), 1024);
    assert_eq!(flags(&original, 1) & 0x0007, 0x0007);

    let mut fs = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
    let created;
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        created = transaction
            .create_empty_file("/create", "cross.bin", 0o640)
            .unwrap();
        assert_eq!(created, 1025);
        assert_eq!(transaction.dirty_blocks(), 6);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    assert_eq!(free_inodes(&durable, 1), 1023);
    assert_eq!(unused(&durable, 1), 1023);
    assert_eq!(flags(&durable, 1) & 0x0003, 0);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let inode = remounted.stat("/create/cross.bin").unwrap();
    assert_eq!(inode.number, created);
    assert_eq!(inode.mode, 0o100640);
    assert_eq!(inode.size, 0);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("inode-allocated-across-groups.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected cross-group inode allocation:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_cross_group_inode_read_is_fallible_before_dirtying() {
    let image = inode_group_image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    transaction
        .create_empty_file("/create", "cross.bin", 0o640)
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(6).unwrap();
                assert_eq!(
                    transaction
                        .create_empty_file("/create", "cross.bin", 0o640)
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn unlinks_an_empty_inode_from_a_later_group() {
    let image = inode_group_image();
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        assert_eq!(
            transaction
                .create_empty_file("/create", "cross-unlink.bin", 0o600)
                .unwrap(),
            1025
        );
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction.unlink("/create/cross-unlink.bin").unwrap();
        assert_eq!(transaction.dirty_blocks(), 5);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/create/cross-unlink.bin").unwrap_err(),
        Error::NotFound
    );
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-later-group-inode.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected later-group inode unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn creates_and_removes_directory_in_a_lazy_later_group() {
    let image = inode_group_image();
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        assert_eq!(transaction.mkdir("/create", "later", 0o755).unwrap(), 1025);
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.rmdir("/create/later").unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/create/later").unwrap_err(),
        Error::NotFound
    );
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("later-group-directory-round-trip.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected later-group directory round trip:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn commits_in_place_file_overwrite_through_journal() {
    let image = image_with_checksum_v3_journal();
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(2).unwrap();
        transaction.overwrite("/dir/hello.txt", 0, b"PORT").unwrap();
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let mut contents = [0; 14];
    assert_eq!(
        remounted.read("/dir/hello.txt", 0, &mut contents).unwrap(),
        14
    );
    assert_eq!(&contents, b"PORTable ext4\n");

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("journal-overwrite.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected overwrite:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_journal_commit_effect_loses_power_to_an_old_or_new_view() {
    let image = image_with_checksum_v3_journal();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let commit_start;
    {
        let mut transaction = successful.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/", "atomic.bin", 0o644)
            .unwrap();
        commit_start = transaction.storage().effects().len();
        transaction.commit().unwrap();
    }
    let effects = successful.storage().effects().to_vec();
    let commit_end = effects.len();
    assert!(
        effects[commit_start..]
            .iter()
            .any(|effect| effect.kind == EffectKind::Write)
    );
    assert!(
        effects[commit_start..]
            .iter()
            .any(|effect| effect.kind == EffectKind::Flush)
    );

    for sequence in commit_start..commit_end {
        let storage =
            ModelStorage::new(image.clone()).with_injection(Inject::PowerLossAt(sequence));
        let mut fs = Ext4::mount(storage).unwrap();
        let error = {
            let mut transaction = fs.begin_transaction();
            transaction.reserve_blocks(5).unwrap();
            transaction
                .create_empty_file("/", "atomic.bin", 0o644)
                .unwrap();
            transaction.commit().unwrap_err()
        };
        assert_eq!(error, Error::Storage(ModelError::PowerLoss));
        let durable = fs.into_storage().durable_bytes().to_vec();
        let _ = assert_atomic_file_view(&durable, "/atomic.bin", &format!("power-loss-{sequence}"));
    }
}

#[test]
fn every_failed_barrier_pending_prefix_is_old_or_new() {
    let image = image_with_checksum_v3_journal();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let commit_start;
    {
        let mut transaction = successful.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/", "prefix.bin", 0o644)
            .unwrap();
        commit_start = transaction.storage().effects().len();
        transaction.commit().unwrap();
    }
    let flushes: Vec<_> = successful.storage().effects()[commit_start..]
        .iter()
        .filter(|effect| effect.kind == EffectKind::Flush)
        .map(|effect| effect.sequence)
        .collect();
    assert_eq!(flushes.len(), 5);

    for (barrier, sequence) in flushes.into_iter().enumerate() {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        let mut fs = Ext4::mount(storage).unwrap();
        let error = {
            let mut transaction = fs.begin_transaction();
            transaction.reserve_blocks(5).unwrap();
            transaction
                .create_empty_file("/", "prefix.bin", 0o644)
                .unwrap();
            transaction.commit().unwrap_err()
        };
        assert_eq!(error, Error::Storage(ModelError::InjectedIo));
        let storage = fs.into_storage();
        let pending = storage.pending_writes();
        assert!(pending > 0);
        for prefix in 0..=pending {
            let mut crashed = storage.clone();
            crashed.persist_pending_prefix(prefix);
            let is_new = assert_atomic_file_view(
                crashed.durable_bytes(),
                "/prefix.bin",
                &format!("barrier-{sequence}-prefix-{prefix}"),
            );
            let expected_new = barrier > 2 || (barrier == 2 && prefix == pending);
            assert_eq!(is_new, expected_new, "barrier {barrier}, prefix {prefix}");
        }
    }
}

#[test]
fn stages_checked_bitmap_and_root_extent_mutation() {
    let image = image();
    let mut staged = image.clone();
    let mut fs = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let empty_inode = fs.stat("/dir/empty.bin").unwrap();
    assert_eq!(empty_inode.size, 0);
    let effects_before = fs.storage().effects().len();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        let allocated = transaction.append_zeroed_block("/dir/empty.bin").unwrap();
        assert_eq!(transaction.dirty_blocks(), 5);
        assert_eq!(transaction.reserved_blocks(), 0);

        let mut data = vec![1; 4096];
        transaction.read_block(allocated, &mut data).unwrap();
        assert_eq!(data, vec![0; 4096]);

        let mut superblock = vec![0; 4096];
        transaction.read_block(0, &mut superblock).unwrap();
        let old_free =
            u64::from(le32(&image, 1024 + 0x0c)) | (u64::from(le32(&image, 1024 + 0x158)) << 32);
        let new_free = u64::from(le32(&superblock, 1024 + 0x0c))
            | (u64::from(le32(&superblock, 1024 + 0x158)) << 32);
        assert_eq!(new_free, old_free - 1);

        let descriptor_offset = 4096;
        let bitmap = u64::from(le32(&image, descriptor_offset))
            | (u64::from(le32(&image, descriptor_offset + 0x20)) << 32);
        let mut bitmap_bytes = vec![0; 4096];
        transaction.read_block(bitmap, &mut bitmap_bytes).unwrap();
        assert_ne!(
            bitmap_bytes[allocated as usize / 8] & (1 << (allocated as usize % 8)),
            0
        );

        let inode_table = u64::from(le32(&image, descriptor_offset + 8))
            | (u64::from(le32(&image, descriptor_offset + 0x28)) << 32);
        let inode_size = u64::from(le16(&image, 1024 + 0x58));
        let inode_block =
            (inode_table * 4096 + u64::from(empty_inode.number - 1) * inode_size) / 4096;
        for number in [0, 1, bitmap, inode_block, allocated] {
            let mut block = vec![0; 4096];
            transaction.read_block(number, &mut block).unwrap();
            let offset = number as usize * 4096;
            staged[offset..offset + 4096].copy_from_slice(&block);
        }
    }
    assert!(
        fs.storage().effects()[effects_before..]
            .iter()
            .all(|effect| effect.kind == portable_ext4::test_support::EffectKind::Read)
    );
    assert_eq!(fs.stat("/dir/empty.bin").unwrap().size, 0);
    assert_eq!(fs.into_storage().durable_bytes(), image);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("staged-mutation.img");
    std::fs::write(&output_path, staged).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected staged transaction:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_mutation_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(5).unwrap();
    transaction.append_zeroed_block("/dir/empty.bin").unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(5).unwrap();
                assert_eq!(
                    transaction
                        .append_zeroed_block("/dir/empty.bin")
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }

    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    let mut transaction = fs.begin_transaction();
    transaction.reserve_blocks(4).unwrap();
    assert_eq!(
        transaction
            .append_zeroed_block("/dir/empty.bin")
            .unwrap_err(),
        Error::ReservationExhausted
    );
    assert_eq!(transaction.dirty_blocks(), 0);
}

#[test]
fn every_multiblock_initialize_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let payload = vec![0x5a; 9000];
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(7).unwrap();
    transaction
        .initialize_file("/dir/empty.bin", &payload)
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(7).unwrap();
                assert_eq!(
                    transaction
                        .initialize_file("/dir/empty.bin", &payload)
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn creates_and_appends_depth_one_extent_tree() {
    let mut expected = vec![0x51; 6 * 4096];
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(11).unwrap();
        transaction
            .initialize_file("/dir/empty.bin", &expected)
            .unwrap();
        transaction.commit().unwrap();
    }
    let appended = vec![0x72; 4096];
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        transaction.append("/dir/empty.bin", &appended).unwrap();
        transaction.commit().unwrap();
    }
    expected.extend_from_slice(&appended);

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        remounted.read("/dir/empty.bin", 0, &mut actual).unwrap(),
        actual.len()
    );
    assert_eq!(actual, expected);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("depth-one-extents.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected depth-one extent tree:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn append_splits_full_extent_leaf_on_fragmented_allocation() {
    let mut fragmented = image();
    let artificial = add_artificial_fragmentation(&mut fragmented, 341);
    let mut expected = vec![0x29; 340 * 4096];
    let mut fs = Ext4::mount(ModelStorage::new(fragmented)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(345).unwrap();
        transaction
            .initialize_file("/root-empty.bin", &expected)
            .unwrap();
        transaction.commit().unwrap();
    }
    let appended = vec![0x7a; 4096];
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.append("/root-empty.bin", &appended).unwrap();
        transaction.commit().unwrap();
    }
    expected.extend_from_slice(&appended);

    let mut durable = fs.into_storage().durable_bytes().to_vec();
    remove_artificial_fragmentation(&mut durable, &artificial);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        remounted.read("/root-empty.bin", 0, &mut actual).unwrap(),
        actual.len()
    );
    assert_eq!(actual, expected);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("split-extent-leaf.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected split extent leaf:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_leaf_split_read_is_fallible_before_dirtying() {
    let mut fragmented = image();
    add_artificial_fragmentation(&mut fragmented, 341);
    let mut initialized = Ext4::mount(ModelStorage::new(fragmented)).unwrap();
    {
        let mut transaction = initialized.begin_transaction();
        transaction.reserve_blocks(345).unwrap();
        transaction
            .initialize_file("/root-empty.bin", &vec![0x47; 340 * 4096])
            .unwrap();
        transaction.commit().unwrap();
    }
    let base = initialized.into_storage().durable_bytes().to_vec();
    let appended = vec![0x68; 4096];
    let mut successful = Ext4::mount(ModelStorage::new(base.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(7).unwrap();
    transaction.append("/root-empty.bin", &appended).unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(base.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(7).unwrap();
                assert_eq!(
                    transaction
                        .append("/root-empty.bin", &appended)
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn unlinks_file_with_external_extent_leaf() {
    let mut fragmented = image();
    let artificial = add_artificial_fragmentation(&mut fragmented, 6);
    let mut fs = Ext4::mount(ModelStorage::new(fragmented)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(11).unwrap();
        transaction
            .initialize_file("/root-empty.bin", &vec![0x63; 6 * 4096])
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.unlink("/root-empty.bin").unwrap();
        transaction.commit().unwrap();
    }

    let mut durable = fs.into_storage().durable_bytes().to_vec();
    remove_artificial_fragmentation(&mut durable, &artificial);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/root-empty.bin").unwrap_err(), Error::NotFound);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-external-extent-leaf.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected external-leaf unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_append_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let payload = vec![0x6b; 9000];
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(7).unwrap();
    transaction.append("/dir/hello.txt", &payload).unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(7).unwrap();
                assert_eq!(
                    transaction.append("/dir/hello.txt", &payload).unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }

    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    let mut transaction = fs.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    assert_eq!(
        transaction.append("/dir/hello.txt", &payload).unwrap_err(),
        Error::ReservationExhausted
    );
    assert_eq!(transaction.dirty_blocks(), 0);
}

#[test]
fn creates_checked_empty_inode_and_directory_entry() {
    let image = image();
    let mut staged = image.clone();
    let mut fs = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let descriptor_offset = 4096;
    let inode_bitmap = u64::from(le32(&image, descriptor_offset + 4))
        | (u64::from(le32(&image, descriptor_offset + 0x24)) << 32);
    let inode_table = u64::from(le32(&image, descriptor_offset + 8))
        | (u64::from(le32(&image, descriptor_offset + 0x28)) << 32);
    let inode_size = u64::from(le16(&image, 1024 + 0x58));
    let root_inode_offset = inode_table * 4096 + inode_size;
    let root_extent = root_inode_offset as usize + 0x28;
    assert_eq!(le16(&image, root_extent), 0xf30a);
    let root_block = (u64::from(le16(&image, root_extent + 18)) << 32)
        | u64::from(le32(&image, root_extent + 20));

    let created;
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        created = transaction
            .create_empty_file("/", "created.bin", 0o644)
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 5);

        let inode_block = (inode_table * 4096 + u64::from(created - 1) * inode_size) / 4096;
        for number in [0, 1, inode_bitmap, inode_block, root_block] {
            let mut block = vec![0; 4096];
            transaction.read_block(number, &mut block).unwrap();
            let offset = number as usize * 4096;
            staged[offset..offset + 4096].copy_from_slice(&block);
        }
    }
    assert!(matches!(fs.stat("/created.bin"), Err(Error::NotFound)));
    assert_eq!(fs.into_storage().durable_bytes(), image);

    let mut remounted = Ext4::mount(ModelStorage::new(staged.clone())).unwrap();
    let inode = remounted.stat("/created.bin").unwrap();
    assert_eq!(inode.number, created);
    assert_eq!(inode.mode, 0o100644);
    assert_eq!(inode.size, 0);

    let output_path =
        std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap()).join("created-file.img");
    std::fs::write(&output_path, staged).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected created inode:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn edits_linux_metadata_through_layout_free_apis() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(2).unwrap();
        transaction.chmod("/root-data.bin", 0o6750).unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(2).unwrap();
        transaction
            .chown("/root-data.bin", Some(0x1234_5678), Some(0x9abc_def0))
            .unwrap();
        transaction.commit().unwrap();
    }
    let accessed = Timestamp {
        seconds: -123,
        nanoseconds: 456,
    };
    let modified = Timestamp {
        seconds: 5_000_000_000,
        nanoseconds: 999_999_999,
    };
    let changed = Timestamp {
        seconds: 1_700_000_000,
        nanoseconds: 42,
    };
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(2).unwrap();
        transaction
            .set_times(
                "/root-data.bin",
                Some(accessed),
                Some(modified),
                Some(changed),
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let inode = remounted.stat("/root-data.bin").unwrap();
    assert_eq!(inode.mode, 0o106750);
    assert_eq!(inode.uid, 0x1234_5678);
    assert_eq!(inode.gid, 0x9abc_def0);
    assert_eq!(inode.accessed, accessed);
    assert_eq!(inode.modified, modified);
    assert_eq!(inode.changed, changed);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("inode-metadata.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected inode metadata edits:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_create_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(5).unwrap();
    transaction
        .create_empty_file("/", "created.bin", 0o644)
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(5).unwrap();
                assert_eq!(
                    transaction
                        .create_empty_file("/", "created.bin", 0o644)
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn creates_hard_links_and_fast_symlinks() {
    let original = image();
    let mut fs = Ext4::mount(ModelStorage::new(original)).unwrap();
    let source = fs.stat("/root-data.bin").unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction
            .link("/root-data.bin", "/root-data-link.bin")
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction.symlink("root-data.bin", "/root-data-link").unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let linked = remounted.stat("/root-data-link.bin").unwrap();
    assert_eq!(linked.number, source.number);
    assert_eq!(linked.links, source.links + 1);
    assert_eq!(
        remounted.read_link("/root-data-link").unwrap(),
        b"root-data.bin"
    );

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("links-and-symlink.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected links:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn unlinks_hard_links_and_fast_symlinks() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let original_links = fs.stat("/root-data.bin").unwrap().links;
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction
            .link("/root-data.bin", "/root-data-link.bin")
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction.symlink("root-data.bin", "/root-data-link").unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction.unlink("/root-data-link.bin").unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction.unlink("/root-data-link").unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/root-data-link.bin").unwrap_err(), Error::NotFound);
    assert_eq!(remounted.stat("/root-data-link").unwrap_err(), Error::NotFound);
    assert_eq!(remounted.stat("/root-data.bin").unwrap().links, original_links);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-links.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected unlinked links:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_link_creation_read_is_fallible_before_dirtying() {
    let original = image();
    for (reserved, operation) in [(3usize, 0u8), (5, 1)] {
        let mut successful = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
        let mut transaction = successful.begin_transaction();
        transaction.reserve_blocks(reserved).unwrap();
        if operation == 0 {
            transaction
                .link("/root-data.bin", "/root-data-link.bin")
                .unwrap();
        } else {
            transaction.symlink("root-data.bin", "/root-data-link").unwrap();
        }
        drop(transaction);
        let effects = successful.storage().effects().len();

        for sequence in 0..effects {
            let storage = ModelStorage::new(original.clone())
                .with_injection(Inject::IoErrorAt(sequence));
            match Ext4::mount(storage) {
                Err(Error::Storage(ModelError::InjectedIo)) => {}
                Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
                Ok(mut fs) => {
                    let mut transaction = fs.begin_transaction();
                    transaction.reserve_blocks(reserved).unwrap();
                    let error = if operation == 0 {
                        transaction
                            .link("/root-data.bin", "/root-data-link.bin")
                            .unwrap_err()
                    } else {
                        transaction
                            .symlink("root-data.bin", "/root-data-link")
                            .unwrap_err()
                    };
                    assert_eq!(error, Error::Storage(ModelError::InjectedIo));
                    assert_eq!(transaction.dirty_blocks(), 0);
                }
            }
        }
    }
}

#[test]
fn unlinks_empty_regular_file_and_releases_its_inode() {
    let original = image();
    let mut probe = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
    let inode = probe.stat("/root-empty.bin").unwrap();
    let inodes_per_group = le32(&original, 1024 + 0x28);
    let group = (inode.number - 1) / inodes_per_group;
    let descriptor_size = usize::from(le16(&original, 1024 + 0xfe));
    let descriptor = 4096 + group as usize * descriptor_size;
    let free_inodes = |bytes: &[u8]| {
        u32::from(le16(bytes, descriptor + 0x0e))
            | (u32::from(le16(bytes, descriptor + 0x2e)) << 16)
    };
    let super_free = le32(&original, 1024 + 0x10);
    let group_free = free_inodes(&original);

    let mut fs = Ext4::mount(ModelStorage::new(original)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction.unlink("/root-empty.bin").unwrap();
        assert_eq!(transaction.dirty_blocks(), 5);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    assert_eq!(le32(&durable, 1024 + 0x10), super_free + 1);
    assert_eq!(free_inodes(&durable), group_free + 1);

    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-empty.bin").unwrap_err(),
        Error::NotFound
    );
    let mut contents = [0; 14];
    assert_eq!(
        remounted.read("/dir/hello.txt", 0, &mut contents).unwrap(),
        contents.len()
    );
    assert_eq!(&contents, b"portable ext4\n");

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-empty-file.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected unlinked inode:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_unlink_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(5).unwrap();
    transaction.unlink("/root-empty.bin").unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(5).unwrap();
                assert_eq!(
                    transaction.unlink("/root-empty.bin").unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn unlinks_nonempty_regular_file_and_releases_its_data() {
    let image = image();
    let super_free_blocks = le32(&image, 1024 + 0x0c);
    let super_free_inodes = le32(&image, 1024 + 0x10);
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        transaction.unlink("/root-data.bin").unwrap();
        assert_eq!(transaction.dirty_blocks(), 6);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    assert_eq!(le32(&durable, 1024 + 0x0c), super_free_blocks + 1);
    assert_eq!(le32(&durable, 1024 + 0x10), super_free_inodes + 1);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-data.bin").unwrap_err(),
        Error::NotFound
    );

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-nonempty-file.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected non-empty unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_nonempty_unlink_read_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    transaction.unlink("/root-data.bin").unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(6).unwrap();
                assert_eq!(
                    transaction.unlink("/root-data.bin").unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn unlinks_file_whose_blocks_span_groups() {
    let image = multi_group_image();
    let payload = vec![0x39; 9000];
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        transaction
            .initialize_file("/target.bin", &payload)
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.unlink("/target.bin").unwrap();
        assert_eq!(transaction.dirty_blocks(), 7);
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/target.bin").unwrap_err(), Error::NotFound);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("unlinked-cross-group-file.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected cross-group unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn unlink_rejects_directory_target_without_dirtying() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let mut transaction = fs.begin_transaction();
    transaction.reserve_blocks(5).unwrap();
    assert_eq!(
        transaction.unlink("/dir").unwrap_err(),
        Error::Unsupported(portable_ext4::Unsupported::MutationProfile)
    );
    assert_eq!(transaction.dirty_blocks(), 0);
}

#[test]
fn unlinks_regular_file_and_symlink_from_indexed_directory() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    for path in ["/dir/hello.link", "/dir/hello.txt"] {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.unlink(path).unwrap();
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/dir/hello.link").unwrap_err(), Error::NotFound);
    assert_eq!(remounted.stat("/dir/hello.txt").unwrap_err(), Error::NotFound);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("indexed-directory-unlink.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected indexed-directory unlink:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn mutates_entries_across_multiblock_linear_directory() {
    let mut fs = Ext4::mount(ModelStorage::new(linear_directory_image())).unwrap();
    assert!(fs.stat("/linear").unwrap().size > 4096);
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/linear", "created.bin", 0o644)
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction
            .rename("/linear/file-499", "/linear/renamed-499")
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.unlink("/linear/file-498").unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert!(remounted.stat("/linear/created.bin").is_ok());
    assert!(remounted.stat("/linear/renamed-499").is_ok());
    assert_eq!(remounted.stat("/linear/file-499").unwrap_err(), Error::NotFound);
    assert_eq!(remounted.stat("/linear/file-498").unwrap_err(), Error::NotFound);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("multiblock-linear-directory.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected multi-block directory mutations:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn grows_a_full_multiblock_linear_directory() {
    let mut fs = Ext4::mount(ModelStorage::new(linear_directory_image())).unwrap();
    let original_size = fs.stat("/linear").unwrap().size;
    let mut grown = false;
    for index in 0..64 {
        let name = format!("growth-{index:02}");
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(12).unwrap();
        transaction
            .create_empty_file("/linear", &name, 0o644)
            .unwrap();
        transaction.commit().unwrap();
        if fs.stat("/linear").unwrap().size > original_size {
            grown = true;
            break;
        }
    }
    assert!(grown, "fixture still had room after 64 insertions");

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert!(remounted.stat("/linear/growth-00").is_ok());
    assert!(remounted.stat("/linear").unwrap().size > original_size);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("grown-linear-directory.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected grown linear directory:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn creates_checked_directory_and_supports_a_child_file() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let root_links = probe.stat("/").unwrap().links;
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    let created;
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        created = transaction.mkdir("/", "made", 0o750).unwrap();
        assert_eq!(transaction.dirty_blocks(), 8);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/made", "child.bin", 0o640)
            .unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    let directory = remounted.stat("/made").unwrap();
    assert_eq!(directory.number, created);
    assert!(directory.is_directory());
    assert_eq!(directory.mode, 0o40750);
    assert_eq!(directory.links, 2);
    assert_eq!(directory.size, 4096);
    assert_eq!(remounted.stat("/").unwrap().links, root_links + 1);
    assert_eq!(remounted.stat("/made/child.bin").unwrap().mode, 0o100640);
    let mut entries = Vec::new();
    assert_eq!(
        remounted.read_dir("/made", 0, &mut entries, 8).unwrap(),
        None
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"child.bin");

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("created-directory.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected created directory:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_mkdir_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(8).unwrap();
    transaction.mkdir("/", "made", 0o750).unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(8).unwrap();
                assert_eq!(
                    transaction.mkdir("/", "made", 0o750).unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn removes_checked_empty_directory_and_restores_parent_links() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let root_links = probe.stat("/").unwrap().links;
    assert!(probe.stat("/root-empty-dir").unwrap().is_directory());
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(7).unwrap();
        transaction.rmdir("/root-empty-dir").unwrap();
        assert_eq!(transaction.dirty_blocks(), 7);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-empty-dir").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(remounted.stat("/").unwrap().links, root_links - 1);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("removed-directory.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected removed directory:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_rmdir_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(7).unwrap();
    transaction.rmdir("/root-empty-dir").unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(7).unwrap();
                assert_eq!(
                    transaction.rmdir("/root-empty-dir").unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn rmdir_reports_nonempty_without_dirtying() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(8).unwrap();
        transaction.mkdir("/", "occupied", 0o755).unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(5).unwrap();
        transaction
            .create_empty_file("/occupied", "child.bin", 0o600)
            .unwrap();
        transaction.commit().unwrap();
    }
    let mut transaction = fs.begin_transaction();
    transaction.reserve_blocks(7).unwrap();
    assert_eq!(transaction.rmdir("/occupied").unwrap_err(), Error::NotEmpty);
    assert_eq!(transaction.dirty_blocks(), 0);
}

#[test]
fn renames_file_across_parents_and_directory_within_parent() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let file_number = probe.stat("/root-empty.bin").unwrap().number;
    let directory_number = probe.stat("/root-empty-dir").unwrap().number;
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction
            .rename("/root-empty.bin", "/root-empty-dir/moved.bin")
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 3);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        transaction
            .rename("/root-empty-dir", "/renamed-dir")
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 2);
        assert_eq!(transaction.reserved_blocks(), 1);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-empty.bin").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        remounted.stat("/root-empty-dir").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        remounted.stat("/renamed-dir").unwrap().number,
        directory_number
    );
    assert_eq!(
        remounted.stat("/renamed-dir/moved.bin").unwrap().number,
        file_number
    );

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("renamed-entries.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected renamed entries:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_cross_parent_rename_read_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(3).unwrap();
    transaction
        .rename("/root-empty.bin", "/root-empty-dir/moved.bin")
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(3).unwrap();
                assert_eq!(
                    transaction
                        .rename("/root-empty.bin", "/root-empty-dir/moved.bin")
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn rename_rejects_replacement_and_unsupported_parent_without_dirtying() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        assert_eq!(
            transaction
                .rename("/root-empty.bin", "/root-empty-dir")
                .unwrap_err(),
            Error::Unsupported(portable_ext4::Unsupported::MutationProfile)
        );
        assert_eq!(transaction.dirty_blocks(), 0);
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(3).unwrap();
        assert_eq!(
            transaction
                .rename("/root-empty-dir", "/dir/moved-dir")
                .unwrap_err(),
            Error::Unsupported(portable_ext4::Unsupported::MutationProfile)
        );
        assert_eq!(transaction.dirty_blocks(), 0);
    }
}

#[test]
fn replacement_rename_reclaims_nonempty_destination() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let source_number = probe.stat("/root-empty.bin").unwrap().number;
    let destination_number = probe.stat("/root-data.bin").unwrap().number;
    let free_blocks = le32(&image, 1024 + 0x0c);
    let free_inodes = le32(&image, 1024 + 0x10);
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        transaction
            .rename("/root-empty.bin", "/root-data.bin")
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 6);
        assert_eq!(transaction.reserved_blocks(), 0);
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    assert_eq!(le32(&durable, 1024 + 0x0c), free_blocks + 1);
    assert_eq!(le32(&durable, 1024 + 0x10), free_inodes + 1);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-empty.bin").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        remounted.stat("/root-data.bin").unwrap().number,
        source_number
    );
    assert_ne!(source_number, destination_number);
    assert_eq!(remounted.stat("/root-data.bin").unwrap().size, 0);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("replacement-rename.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected replacement rename:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn directory_rename_replaces_empty_directory() {
    let original = image();
    let mut probe = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
    let source = probe.stat("/move-left/branch").unwrap();
    let old_parent_links = probe.stat("/move-left").unwrap().links;
    let new_parent_links = probe.stat("/").unwrap().links;
    let mut fs = Ext4::mount(ModelStorage::new(original)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(9).unwrap();
        transaction
            .rename("/move-left/branch", "/root-empty-dir")
            .unwrap();
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/move-left/branch").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(remounted.stat("/root-empty-dir").unwrap().number, source.number);
    assert_eq!(
        remounted.stat("/move-left").unwrap().links,
        old_parent_links - 1
    );
    assert_eq!(remounted.stat("/").unwrap().links, new_parent_links);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("directory-replacement.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected directory replacement:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_directory_replacement_read_is_fallible_before_dirtying() {
    let original = image();
    let mut successful = Ext4::mount(ModelStorage::new(original.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(9).unwrap();
    transaction
        .rename("/move-left/branch", "/root-empty-dir")
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage =
            ModelStorage::new(original.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(9).unwrap();
                assert_eq!(
                    transaction
                        .rename("/move-left/branch", "/root-empty-dir")
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn replacement_rename_moves_file_across_parents() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let source_number = probe.stat("/root-data.bin").unwrap().number;
    let victim_number = probe.stat("/replace-dir/victim.bin").unwrap().number;
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        transaction
            .rename("/root-data.bin", "/replace-dir/victim.bin")
            .unwrap();
        assert_eq!(transaction.dirty_blocks(), 6);
        transaction.commit().unwrap();
    }
    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/root-data.bin").unwrap_err(),
        Error::NotFound
    );
    let moved = remounted.stat("/replace-dir/victim.bin").unwrap();
    assert_eq!(moved.number, source_number);
    assert_ne!(moved.number, victim_number);
    assert_eq!(moved.size, 14);

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("cross-parent-replacement-rename.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected cross-parent replacement rename:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_replacement_rename_read_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    transaction
        .rename("/root-empty.bin", "/root-data.bin")
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(6).unwrap();
                assert_eq!(
                    transaction
                        .rename("/root-empty.bin", "/root-data.bin")
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn moves_directory_across_parents_and_updates_dotdot_and_link_counts() {
    let image = image();
    let mut probe = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let source_number = probe.stat("/move-left/branch").unwrap().number;
    let left_links = probe.stat("/move-left").unwrap().links;
    let right_links = probe.stat("/move-right").unwrap().links;
    let mut fs = Ext4::mount(ModelStorage::new(image)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(6).unwrap();
        transaction
            .rename("/move-left/branch", "/move-right/branch")
            .unwrap();
        assert!((5..=6).contains(&transaction.dirty_blocks()));
        assert_eq!(
            transaction.dirty_blocks() + transaction.reserved_blocks(),
            6
        );
        transaction.commit().unwrap();
    }

    let durable = fs.into_storage().durable_bytes().to_vec();
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(
        remounted.stat("/move-left/branch").unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        remounted.stat("/move-right/branch").unwrap().number,
        source_number
    );
    assert_eq!(remounted.stat("/move-left").unwrap().links, left_links - 1);
    assert_eq!(
        remounted.stat("/move-right").unwrap().links,
        right_links + 1
    );

    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("cross-parent-directory-rename.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected cross-parent directory rename:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_cross_parent_directory_rename_read_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    transaction
        .rename("/move-left/branch", "/move-right/branch")
        .unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(6).unwrap();
                assert_eq!(
                    transaction
                        .rename("/move-left/branch", "/move-right/branch")
                        .unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn cross_parent_directory_rename_rejects_descendant_cycle() {
    let mut fs = Ext4::mount(ModelStorage::new(image())).unwrap();
    let mut transaction = fs.begin_transaction();
    transaction.reserve_blocks(6).unwrap();
    assert_eq!(
        transaction
            .rename("/move-left", "/move-left/branch/loop")
            .unwrap_err(),
        Error::InvalidArgument
    );
    assert_eq!(transaction.dirty_blocks(), 0);
}

#[test]
fn truncates_checked_root_extent_and_releases_its_block() {
    let image = image();
    let mut staged = image.clone();
    let mut fs = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let inode = fs.stat("/dir/hello.txt").unwrap();
    assert_eq!(inode.size, 14);

    let descriptor_offset = 4096;
    let bitmap = u64::from(le32(&image, descriptor_offset))
        | (u64::from(le32(&image, descriptor_offset + 0x20)) << 32);
    let inode_table = u64::from(le32(&image, descriptor_offset + 8))
        | (u64::from(le32(&image, descriptor_offset + 0x28)) << 32);
    let inode_size = u64::from(le16(&image, 1024 + 0x58));
    let inode_byte = inode_table * 4096 + u64::from(inode.number - 1) * inode_size;
    let inode_block = inode_byte / 4096;
    let extent_root = inode_byte as usize + 0x28;
    assert_eq!(le16(&image, extent_root), 0xf30a);
    assert_eq!(le16(&image, extent_root + 2), 1);
    let data_block = (u64::from(le16(&image, extent_root + 18)) << 32)
        | u64::from(le32(&image, extent_root + 20));

    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(4).unwrap();
        assert_eq!(transaction.truncate_to_zero("/dir/hello.txt").unwrap(), 1);
        assert_eq!(transaction.dirty_blocks(), 4);

        let mut bitmap_bytes = vec![0; 4096];
        transaction.read_block(bitmap, &mut bitmap_bytes).unwrap();
        assert_eq!(
            bitmap_bytes[data_block as usize / 8] & (1 << (data_block as usize % 8)),
            0
        );

        for number in [0, 1, bitmap, inode_block] {
            let mut block = vec![0; 4096];
            transaction.read_block(number, &mut block).unwrap();
            let offset = number as usize * 4096;
            staged[offset..offset + 4096].copy_from_slice(&block);
        }
    }
    assert_eq!(fs.stat("/dir/hello.txt").unwrap().size, 14);
    assert_eq!(fs.into_storage().durable_bytes(), image);

    let mut remounted = Ext4::mount(ModelStorage::new(staged.clone())).unwrap();
    assert_eq!(remounted.stat("/dir/hello.txt").unwrap().size, 0);
    let mut contents = [0; 14];
    assert_eq!(
        remounted.read("/dir/hello.txt", 0, &mut contents).unwrap(),
        0
    );

    let output_path =
        std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap()).join("truncated.img");
    std::fs::write(&output_path, staged).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected truncated inode:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn truncates_file_with_external_extent_leaf() {
    let mut fragmented = image();
    let artificial = add_artificial_fragmentation(&mut fragmented, 6);
    let mut fs = Ext4::mount(ModelStorage::new(fragmented)).unwrap();
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(11).unwrap();
        transaction
            .initialize_file("/root-empty.bin", &vec![0x35; 6 * 4096])
            .unwrap();
        transaction.commit().unwrap();
    }
    {
        let mut transaction = fs.begin_transaction();
        transaction.reserve_blocks(4).unwrap();
        assert_eq!(transaction.truncate_to_zero("/root-empty.bin").unwrap(), 7);
        transaction.commit().unwrap();
    }

    let mut durable = fs.into_storage().durable_bytes().to_vec();
    remove_artificial_fragmentation(&mut durable, &artificial);
    let mut remounted = Ext4::mount(ModelStorage::new(durable.clone())).unwrap();
    assert_eq!(remounted.stat("/root-empty.bin").unwrap().size, 0);
    let output_path = std::path::PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
        .join("truncated-external-extent-leaf.img");
    std::fs::write(&output_path, durable).unwrap();
    let check = std::process::Command::new("/usr/sbin/e2fsck")
        .args(["-fn", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "e2fsck rejected external-leaf truncate:\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn every_truncate_read_effect_is_fallible_before_dirtying() {
    let image = image();
    let mut successful = Ext4::mount(ModelStorage::new(image.clone())).unwrap();
    let mut transaction = successful.begin_transaction();
    transaction.reserve_blocks(4).unwrap();
    transaction.truncate_to_zero("/dir/hello.txt").unwrap();
    drop(transaction);
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image.clone()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => {
                let mut transaction = fs.begin_transaction();
                transaction.reserve_blocks(4).unwrap();
                assert_eq!(
                    transaction.truncate_to_zero("/dir/hello.txt").unwrap_err(),
                    Error::Storage(ModelError::InjectedIo)
                );
                assert_eq!(transaction.dirty_blocks(), 0);
            }
        }
    }
}

#[test]
fn detects_superblock_group_inode_and_directory_corruption() {
    let mut bad_superblock = image();
    bad_superblock[1024 + 0x10] ^= 1;
    assert!(matches!(
        Ext4::mount(ModelStorage::new(bad_superblock)).err(),
        Some(Error::Corrupt(Corrupt::SuperblockChecksum))
    ));

    let mut probe = Ext4::mount(ModelStorage::new(image())).unwrap();
    probe.stat("/").unwrap();
    let effects = probe.storage().effects();
    let group_descriptor = effects
        .iter()
        .find(|effect| effect.len == 64)
        .unwrap()
        .offset as usize;
    let root_inode = effects
        .iter()
        .find(|effect| effect.len == 256)
        .unwrap()
        .offset as usize;

    let mut bad_group = image();
    bad_group[group_descriptor + 12] ^= 1;
    let mut fs = Ext4::mount(ModelStorage::new(bad_group)).unwrap();
    assert!(matches!(
        fs.stat("/").unwrap_err(),
        Error::Corrupt(Corrupt::GroupDescriptorChecksum(0))
    ));

    let mut bad_inode = image();
    bad_inode[root_inode] ^= 1;
    let mut fs = Ext4::mount(ModelStorage::new(bad_inode)).unwrap();
    assert!(matches!(
        fs.stat("/").unwrap_err(),
        Error::Corrupt(Corrupt::InodeChecksum(2))
    ));

    let mut probe = Ext4::mount(ModelStorage::new(image())).unwrap();
    probe.stat("/dir").unwrap();
    let block_size = probe.block_size() as usize;
    let directory_block = probe
        .storage()
        .effects()
        .iter()
        .find(|effect| effect.len == block_size)
        .unwrap()
        .offset as usize;
    let mut bad_directory = image();
    bad_directory[directory_block + block_size - 1] ^= 1;
    let mut fs = Ext4::mount(ModelStorage::new(bad_directory)).unwrap();
    assert!(matches!(
        fs.stat("/dir").unwrap_err(),
        Error::Corrupt(Corrupt::DirectoryChecksum(2))
    ));
}

#[test]
fn every_effect_in_modern_indexed_lookup_is_fallible() {
    let mut successful = Ext4::mount(ModelStorage::new(image())).unwrap();
    let mut contents = [0; 14];
    successful.read("/dir/file-299", 0, &mut contents).unwrap();
    let effects = successful.storage().effects().len();

    for sequence in 0..effects {
        let storage = ModelStorage::new(image()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(storage) {
            Err(Error::Storage(ModelError::InjectedIo)) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => assert_eq!(
                fs.read("/dir/file-299", 0, &mut contents).unwrap_err(),
                Error::Storage(ModelError::InjectedIo),
            ),
        }
    }
}
