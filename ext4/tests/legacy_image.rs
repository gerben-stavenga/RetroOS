use portable_ext4::test_support::{Inject, ModelError, ModelStorage, PathExt4};
use portable_ext4::{Error, Ext4};

fn image() -> Vec<u8> {
    let image_path = std::path::PathBuf::from(std::env::var_os("TEST_SRCDIR").unwrap())
        .join(env!("EXT4_LEGACY_IMAGE"));
    std::fs::read(image_path).unwrap()
}

#[test]
fn reads_direct_and_double_indirect_data_from_mke2fs_image() {
    let mut storage = ModelStorage::new(image());
    let mut fs = Ext4::mount(&mut storage).unwrap();
    let mut contents = [0; 14];
    assert_eq!(
        fs.read(&mut storage, "/hello.txt", 0, &mut contents)
            .unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");

    contents.fill(0);
    assert_eq!(
        fs.read(&mut storage, "/large.bin", 300 * 1024, &mut contents)
            .unwrap(),
        14
    );
    assert_eq!(&contents, b"portable ext4\n");
}

#[test]
fn every_legacy_lookup_effect_is_fallible() {
    let mut successful_storage = ModelStorage::new(image());
    let mut successful = Ext4::mount(&mut successful_storage).unwrap();
    let mut contents = [0; 14];
    successful
        .read(
            &mut successful_storage,
            "/large.bin",
            300 * 1024,
            &mut contents,
        )
        .unwrap();
    let effects = successful_storage.effects().len();

    for sequence in 0..effects {
        let mut storage = ModelStorage::new(image()).with_injection(Inject::IoErrorAt(sequence));
        match Ext4::mount(&mut storage) {
            Err(Error::Storage(error))
                if error.downcast_ref::<ModelError>() == Some(&ModelError::InjectedIo) => {}
            Err(other) => panic!("unexpected mount error at {sequence}: {other:?}"),
            Ok(mut fs) => assert!(
                fs.read(&mut storage, "/large.bin", 300 * 1024, &mut contents)
                    .unwrap_err()
                    .storage_is(&ModelError::InjectedIo)
            ),
        }
    }
}
