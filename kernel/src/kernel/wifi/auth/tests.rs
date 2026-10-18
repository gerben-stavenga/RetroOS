use super::*;
const STA: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn rsn() -> Vec<u8> {
    vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
    ]
}
fn pmk() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(core::array::from_fn(|i| i as u8))
}
fn snonce() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 + 1)
}
fn anonce() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 + 33)
}
fn session() -> Supplicant {
    Supplicant::new(
        pmk(),
        STA,
        AP,
        Security::negotiate(&rsn()).unwrap(),
        snonce(),
    )
    .unwrap()
}
fn packet(info: u16, replay: u64, nonce: [u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 99];
    out[0] = 2;
    out[1] = 3;
    out[4] = 2;
    out[2..4].copy_from_slice(&((95 + data.len()) as u16).to_be_bytes());
    out[5..7].copy_from_slice(&info.to_be_bytes());
    out[7..9].copy_from_slice(&16u16.to_be_bytes());
    out[9..17].copy_from_slice(&replay.to_be_bytes());
    out[17..49].copy_from_slice(&nonce);
    out[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}
fn one() -> Vec<u8> {
    packet(2 | PAIRWISE | ACK, 1, anonce(), &[])
}
fn gtk(index: u8, key: u8) -> Vec<u8> {
    let mut out = vec![221, 22, 0, 15, 172, 1, index, 0];
    out.extend_from_slice(&[key; 16]);
    out
}
fn signed(info: u16, replay: u64, nonce: [u8; 32], plain: &[u8]) -> Vec<u8> {
    let keys = ptk(&pmk(), STA, AP, &snonce(), &anonce());
    let kw = KwAes128::new_from_slice(&keys[16..32]).unwrap();
    let mut ciphertext = vec![0; plain.len() + 8];
    kw.wrap_key(plain, &mut ciphertext).unwrap();
    let mut out = packet(info, replay, nonce, &ciphertext);
    let mic = mac(&keys[..16], &[&out]);
    out[81..97].copy_from_slice(&mic[..16]);
    out
}
fn three(replay: u64) -> Vec<u8> {
    let mut plain = vec![48, 20];
    plain.extend_from_slice(&rsn());
    plain.extend_from_slice(&gtk(1, 0x55));
    plain.extend_from_slice(&[221, 0]);
    signed(
        2 | PAIRWISE | ACK | INSTALL | MIC | SECURE | ENCRYPTED,
        replay,
        anonce(),
        &plain,
    )
}
#[test]
fn ptk_matches_independent_hmac_sha1_vector() {
    // Independently computed with Python's hashlib/hmac, using public
    // sequential test bytes, not a network password or captured key.
    let hex = "abd2a3f5c7c22ee0b672e2c21f4a4da205009d762b448f592719d622054dff8304b34243798ffe6428c1b0474657c1ac";
    let expected = (0..48)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(&ptk(&pmk(), STA, AP, &snonce(), &anonce())[..], expected);
}
#[test]
fn four_way_handshake_waits_for_hardware_install_and_never_reinstalls_duplicate_keys() {
    let mut s = session();
    let m2 = s.receive(&one()).unwrap();
    assert!(m2.keys.is_empty());
    let m2 = m2.reply.unwrap();
    assert_eq!(&m2[17..49], &snonce());
    assert_eq!(u16::from_be_bytes([m2[5], m2[6]]), 0x10a);
    assert_eq!(s.receive(&one()).unwrap().reply, Some(m2));
    let m3 = three(2);
    let result = s.receive(&m3).unwrap();
    assert!(result.reply.is_none());
    assert_eq!(result.keys.len(), 2);
    assert!(!s.complete());
    assert_eq!(
        result.keys[0].id,
        KeyId {
            pairwise: true,
            index: 0
        }
    );
    assert_eq!(
        result.keys[1].id,
        KeyId {
            pairwise: false,
            index: 1
        }
    );
    assert_eq!(*result.keys[1].bytes, [0x55; 16]);
    assert!(s.receive(&m3).unwrap().keys.is_empty());
    assert!(s.receive(&m3).unwrap().reply.is_none());
    let ack = s.installed().unwrap();
    assert!(s.complete());
    assert_eq!(u16::from_be_bytes([ack[5], ack[6]]), 0x30a);
    let duplicate = s.receive(&m3).unwrap();
    assert!(duplicate.keys.is_empty());
    assert_eq!(duplicate.reply, Some(ack));
    assert!(s.receive(&three(3)).unwrap().keys.is_empty()); // increasing replay retry, no PN reset
    assert!(matches!(s.receive(&m3), Err(Error::Replay)));
    assert!(s.installed().is_err());
}
#[test]
fn failed_mic_replay_and_key_unwrap_cannot_install_or_authorize() {
    let mut s = session();
    s.receive(&one()).unwrap();
    let mut bad = three(2);
    bad[81] ^= 1;
    assert!(matches!(s.receive(&bad), Err(Error::Mic)));
    assert!(!s.complete());
    assert!(s.installed().is_err());
    let m3 = three(2);
    for n in 0..m3.len() {
        assert!(s.receive(&m3[..n]).is_err());
    }
    let mut bad = m3.clone();
    bad[99] ^= 1;
    bad[81..97].fill(0);
    let keys = ptk(&pmk(), STA, AP, &snonce(), &anonce());
    let mic = mac(&keys[..16], &[&bad]);
    bad[81..97].copy_from_slice(&mic[..16]);
    assert!(matches!(s.receive(&bad), Err(Error::KeyData)));
    assert!(matches!(s.receive(&three(1)), Err(Error::Replay)));
    assert_eq!(s.receive(&m3).unwrap().keys.len(), 2);
}
#[test]
fn group_rekey_only_installs_a_new_gtk_and_preserves_ptk_packet_counters() {
    let mut s = session();
    s.receive(&one()).unwrap();
    s.receive(&three(2)).unwrap();
    s.installed().unwrap();
    let flags = 2 | ACK | MIC | SECURE | ENCRYPTED;
    let group = signed(flags, 3, [0; 32], &gtk(2, 0x66));
    let result = s.receive(&group).unwrap();
    assert_eq!(result.keys.len(), 1);
    assert_eq!(
        result.keys[0].id,
        KeyId {
            pairwise: false,
            index: 2
        }
    );
    assert!(result.reply.is_none());
    assert!(s.receive(&group).unwrap().keys.is_empty());
    assert!(
        s.receive(&signed(flags, 4, [0; 32], &gtk(1, 0x77)))
            .is_err()
    );
    let ack = s.installed().unwrap();
    assert_eq!(u16::from_be_bytes([ack[5], ack[6]]), 0x302);
    assert!(s.receive(&group).unwrap().keys.is_empty());
    assert!(
        s.receive(&signed(flags, 4, [0; 32], &gtk(2, 0x66)))
            .unwrap()
            .keys
            .is_empty()
    );
}
#[test]
fn cipher_akm_and_management_protection_requirements_are_negotiated() {
    let good = rsn();
    assert!(Security::negotiate(&good).is_ok());
    for n in 0..18 {
        assert!(Security::negotiate(&good[..n]).is_err());
    }
    let mut bad = good.clone();
    bad[5] = 2;
    assert!(Security::negotiate(&bad).is_err());
    let mut bad = good.clone();
    bad[17] = 8;
    assert!(Security::negotiate(&bad).is_err());
    let mut bad = good.clone();
    bad[18] = 0x40;
    assert!(Security::negotiate(&bad).is_err());
}
#[test]
fn ccmp_receive_counters_are_separate_and_never_accept_replays_or_uninstalled_keys() {
    let p = KeyId {
        pairwise: true,
        index: 0,
    };
    let g = KeyId {
        pairwise: false,
        index: 1,
    };
    let mut r = Replay::default();
    assert!(!r.accept(p, 1));
    r.install(p, 0);
    r.install(g, 10);
    assert!(r.accept(p, 1));
    assert!(!r.accept(p, 1));
    assert!(!r.accept(p, 0));
    assert!(!r.accept(g, 10));
    assert!(r.accept(g, 11));
    assert!(r.accept(p, 2));
    assert!(!r.accept(p, 1 << 48));
    assert!(!r.accept(
        KeyId {
            pairwise: false,
            index: 2
        },
        12
    ));
}
