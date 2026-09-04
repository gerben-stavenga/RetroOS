use crate::checksum::Checksum;
use crate::ext4::{Inode128, Le16, Le32, Le64, Superblock};
use crate::journal::crc32c;
use core::mem::offset_of;

#[test]
fn ext4_crc_convention() {
    let mut checksum = Checksum::new();
    checksum.update_u32_le(1);
    checksum.update_u32_le(2);
    assert_eq!(checksum.finalize(), 0x858c_13d3);
}

#[test]
fn jbd2_crc32c_matches_standard_vector_before_final_xor() {
    assert_eq!(crc32c(u32::MAX, b"123456789"), 0x1cf9_6d7c);
}

#[test]
fn endian_scalars_are_stored_little_endian() {
    assert_eq!(Le16::new(0x1234).0, [0x34, 0x12]);
    assert_eq!(Le32::new(0x1234_5678).0, [0x78, 0x56, 0x34, 0x12]);
    assert_eq!(
        Le64::new(0x0123_4567_89ab_cdef).0,
        [0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
    );
}

#[test]
fn important_disk_offsets_match_ext4() {
    assert_eq!(offset_of!(Superblock, magic), 0x38);
    assert_eq!(offset_of!(Superblock, inode_size), 0x58);
    assert_eq!(offset_of!(Superblock, desc_size), 0xfe);
    assert_eq!(offset_of!(Superblock, checksum), 0x3fc);
    assert_eq!(offset_of!(Inode128, block), 0x28);
    assert_eq!(offset_of!(Inode128, os_dependent_2), 0x74);
}

#[test]
fn directory_record_lengths_cover_the_64k_encoding() {
    use crate::ext4::{directory_record_length, directory_record_length_to_disk};

    for length in [12, 4096, 65532, 65536] {
        let disk = directory_record_length_to_disk(length, 65536).unwrap();
        assert_eq!(directory_record_length(disk, 65536), length);
    }
    assert_eq!(
        directory_record_length_to_disk(65536, 65536).unwrap().get(),
        u16::MAX
    );
}
