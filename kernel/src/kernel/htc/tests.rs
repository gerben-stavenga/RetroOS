use super::*;
use alloc::vec;
fn control(words: &[u32]) -> Vec<u8> {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    frame(0, 0, false, &bytes).unwrap()
}
fn connected() -> State {
    let mut state = State::new();
    state
        .receive(&control(&[1 | (4 << 16), 64 | (9 << 16)]))
        .unwrap();
    state.connect(WMI_CONTROL).unwrap();
    state
        .receive(&control(&[
            3 | (u32::from(WMI_CONTROL) << 16),
            (2040 << 16) | (1 << 8),
            0,
        ]))
        .unwrap();
    state.connect(HTT_DATA).unwrap();
    state
        .receive(&control(&[
            3 | (u32::from(HTT_DATA) << 16),
            (248 << 16) | (2 << 8),
            0,
        ]))
        .unwrap();
    state
}
#[test]
fn control_negotiation_uses_firmware_endpoint_ids_and_wire_flags() {
    let mut state = State::new();
    assert!(state.connect(WMI_CONTROL).is_err());
    state
        .receive(&control(&[1 | (4 << 16), 64 | (9 << 16)]))
        .unwrap();
    let bytes = state.connect(WMI_CONTROL).unwrap();
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.endpoint, 0);
    assert_eq!(word(parsed.payload, 0).unwrap(), 2 | 0x1000000);
    assert_eq!(word(parsed.payload, 4).unwrap(), 4 << 8);
    assert!(state.connect(HTT_DATA).is_err());
    let mut state = connected();
    assert_eq!(state.endpoint(WMI_CONTROL), Some(1));
    assert_eq!(state.endpoint(HTT_DATA), Some(2));
    let setup = state.setup_complete().unwrap();
    assert_eq!(
        Frame::parse(&setup).unwrap().payload,
        &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}
#[test]
fn credits_are_charged_only_after_transport_accepts_packet() {
    let mut state = connected();
    let packet = state.prepare(WMI_CONTROL, &[0; 100]).unwrap();
    assert!(state.prepare(WMI_CONTROL, &[0; 200]).is_ok());
    state.commit(&packet).unwrap(); // 108 bytes consume two 64-byte credits
    assert_eq!(
        state.prepare(WMI_CONTROL, &[0; 200]).err(),
        Some(Error::Full)
    );
    assert_eq!(state.commit(&packet), Err(Error::State));
    // Trailer-only packet returns two WMI credits.
    let mut bytes = frame(1, 0, false, &[1, 4, 0, 0, 1, 2, 0, 0]).unwrap();
    bytes[1] = 2;
    bytes[4] = 8;
    assert!(state.receive(&bytes).unwrap().is_none());
    assert!(state.prepare(WMI_CONTROL, &[0; 200]).is_ok());
    let packet = state.prepare(HTT_DATA, &[0; 100]).unwrap();
    assert_eq!(packet.bytes[1], 0); // HTT service uses CE completion, not HTC credits
}
#[test]
fn malformed_frames_trailers_and_service_responses_fail() {
    let mut state = connected();
    let packet = frame(1, 0, false, b"hello").unwrap();
    for length in 0..packet.len() {
        assert!(Frame::parse(&packet[..length]).is_err());
    }
    let mut packet = packet;
    packet[0] = 16;
    assert!(Frame::parse(&packet).is_err());
    let mut packet = frame(1, 0, false, &[1, 12, 0, 0, 1, 2, 0, 0]).unwrap();
    packet[1] = 2;
    packet[4] = 8;
    assert!(state.receive(&packet).is_err());
    assert!(state.prepare(WMI_CONTROL, &vec![0; 2041]).is_err());
    let mut state = State::new();
    state
        .receive(&control(&[1 | (4 << 16), 64 | (9 << 16)]))
        .unwrap();
    state.connect(WMI_CONTROL).unwrap();
    assert!(matches!(
        state.receive(&control(&[3 | 0x1000000, 2, 0])),
        Err(Error::Rejected(2))
    ));
}
