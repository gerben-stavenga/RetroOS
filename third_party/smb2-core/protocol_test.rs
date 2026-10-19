use smb2_core::{
    client::{signature, verify},
    msg::{directory_info::parse_entries, header::Header, query_directory::FileInformationClass},
    pack::{Pack, ReadCursor, Unpack, WriteCursor},
    types::Command,
};
#[test]
fn signatures_reject_modified_payloads_and_signature_bytes() {
    let mut out = WriteCursor::new();
    Header::new_request(Command::Read).pack(&mut out);
    out.write_bytes(b"authenticated contents");
    let mut message = out.into_inner();
    let key = [0x42; 16];
    let sig = signature(&message, &key).unwrap();
    message[48..64].copy_from_slice(&sig);
    assert!(verify(&message, &key).is_ok());
    for byte in 0..message.len() {
        message[byte] ^= 1;
        assert!(verify(&message, &key).is_err(), "tampered byte {byte}");
        message[byte] ^= 1;
    }
    assert!(verify(&message, &[0x41; 16]).is_err());
    for len in 0..64 {
        assert!(verify(&message[..len], &key).is_err());
    }
}
#[test]
fn malformed_headers_and_directory_chains_are_rejected() {
    for len in 0..64 {
        assert!(Header::unpack(&mut ReadCursor::new(&vec![0; len])).is_err());
    }
    let mut data = vec![0; 104];
    data[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_entries(FileInformationClass::FileIdBothDirectoryInformation, &data).is_err());
    data[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(parse_entries(FileInformationClass::FileIdBothDirectoryInformation, &data).is_err());
}

#[test]
fn response_offsets_are_honored_and_truncated_payloads_fail() {
    use smb2_core::msg::{read::ReadResponse, session_setup::SessionSetupResponse};
    let mut read = vec![0; 24];
    read[..2].copy_from_slice(&17u16.to_le_bytes());
    read[2] = 88;
    read[4..8].copy_from_slice(&3u32.to_le_bytes());
    read.extend_from_slice(b"ABC");
    assert_eq!(
        ReadResponse::unpack(&mut ReadCursor::new(&read))
            .unwrap()
            .data,
        b"ABC"
    );
    read.pop();
    assert!(ReadResponse::unpack(&mut ReadCursor::new(&read)).is_err());
    read[2] = 79;
    assert!(ReadResponse::unpack(&mut ReadCursor::new(&read)).is_err());
    let mut setup = vec![0; 16];
    setup[..2].copy_from_slice(&9u16.to_le_bytes());
    setup[4..6].copy_from_slice(&80u16.to_le_bytes());
    setup[6..8].copy_from_slice(&3u16.to_le_bytes());
    setup.extend_from_slice(b"XYZ");
    assert_eq!(
        SessionSetupResponse::unpack(&mut ReadCursor::new(&setup))
            .unwrap()
            .security_buffer,
        b"XYZ"
    );
    setup.pop();
    assert!(SessionSetupResponse::unpack(&mut ReadCursor::new(&setup)).is_err());
}

#[test]
fn mfsymlinks_match_linux_wire_format_and_reject_corruption() {
    use smb2_core::mfsymlink::{decode, encode, FILE_SIZE};
    let wire = encode(b"hello").unwrap();
    assert_eq!(wire.len(), FILE_SIZE);
    // Independent published MD5 test vector, not computed with the encoder.
    assert_eq!(&wire[..49], b"XSym\n0005\n5d41402abc4b2a76b9719d911017c592\nhello\n");
    assert_eq!(decode(&wire), Some(b"hello".as_slice()));
    for index in [0, 5, 9, 10, 41, 42, 43] {
        let mut corrupt = wire.clone();
        corrupt[index] ^= 1;
        assert!(decode(&corrupt).is_none(), "corrupt byte {index}");
    }
    for length in [1, 1023, 1024] {
        let target = vec![b'x'; length];
        assert_eq!(decode(&encode(&target).unwrap()), Some(target.as_slice()));
    }
    assert!(encode(b"").is_none());
    assert!(encode(b"nul\0byte").is_none());
    assert!(encode(&vec![b'x'; 1025]).is_none());
    assert!(decode(&vec![0; FILE_SIZE]).is_none());
    assert!(decode(&wire[..FILE_SIZE - 1]).is_none());
}
