use super::*;
use alloc::vec;
fn event(id: u32, values: &[(u16, &[u8])]) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    for (tag, data) in values {
        tlv(&mut bytes, *tag, data).unwrap();
    }
    bytes
}
fn base(ext: bool) -> Vec<u8> {
    let mut ready = vec![0; 76];
    ready[36..40].copy_from_slice(&2u32.to_le_bytes());
    let mut bitmap = vec![0; 128];
    if ext {
        bitmap[77 / 4 * 4] |= 1 << (77 % 4);
    }
    event(1, &[(32, &ready), (16, &bitmap)])
}
fn resources() -> Vec<u32> {
    let mut values = vec![0; 73];
    values[0] = (75 << 16) | 288;
    values
}
#[test]
fn startup_waits_for_advertised_extensions_before_sending_init() {
    let mut state = State::new();
    state.receive(&base(true)).unwrap();
    assert!(!state.services_ready());
    let mut bitmap = vec![0; 20];
    bitmap[4 + (220 - 128) / 32 * 4 + (220 % 32) / 8] |= 1 << (220 % 8);
    state.receive(&event(3, &[(559, &bitmap)])).unwrap();
    state.receive(&event(0x4009, &[(428, &[0; 4])])).unwrap();
    assert!(!state.services_ready());
    state.receive(&event(0x4022, &[(820, &[0; 4])])).unwrap();
    assert!(state.services_ready());
    let init = state.initialize_command(&resources()).unwrap();
    assert_eq!(word(&init, 0).unwrap(), 1);
    let values = tlvs(&init[4..]).unwrap();
    assert_eq!(
        values
            .iter()
            .map(|(tag, data)| (*tag, data.len()))
            .collect::<Vec<_>>(),
        [(74, 28), (75, 288), (18, 0)]
    );
    assert_eq!(state.rf_chains(), 2);
    state.mark_init_sent().unwrap();
    assert!(state.initialize_command(&resources()).is_err());
    let mut ready = vec![0; 36];
    ready[24..30].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    state.receive(&event(2, &[(35, &ready)])).unwrap();
    assert!(state.ready);
    assert_eq!(state.mac, [2, 3, 4, 5, 6, 7]);
}
#[test]
fn malformed_events_do_not_mark_firmware_ready() {
    for length in 0..base(false).len() {
        assert!(State::new().receive(&base(false)[..length]).is_err());
    }
    let mut state = State::new();
    state.receive(&base(false)).unwrap();
    assert!(state.services_ready());
    assert!(state.receive(&event(2, &[(35, &[0; 36])])).is_err());
    state.mark_init_sent().unwrap();
    let mut ready = vec![0; 36];
    ready[32..36].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        state.receive(&event(2, &[(35, &ready)])),
        Err(Error::Firmware(7))
    );
    assert!(!state.ready);
    ready[32..36].fill(0);
    assert!(state.receive(&event(2, &[(35, &ready)])).is_err()); // zero MAC
    assert!(state.initialize_command(&[0]).is_err());
    let unknown = event(0x123456, &[(65535, &[1, 2, 3])]);
    assert!(state.receive(&unknown).is_ok());
    assert!(state.receive(&event(0x16005, &[(397, &[0; 8])])).is_ok());
    assert!(state.receive(&event(0x16005, &[(397, &[0; 4])])).is_err());
}

#[test]
fn service_ready_uses_first_uint32_array_with_repeated_array_tags() {
    let mut bytes = base(true);
    // Real service-ready messages may include several arrays with the same
    // type tag. Neither an empty later array nor set bits there are services.
    tlv(&mut bytes, 16, &[]).unwrap();
    tlv(&mut bytes, 16, &[0xff; 128]).unwrap();
    let mut state = State::new();
    state.receive(&bytes).unwrap();
    assert_eq!(state.rf_chains(), 2);
    assert!(state.services[77]);
    assert_eq!(state.services.iter().filter(|enabled| **enabled).count(), 1);
    assert!(!state.services_ready());

    // A short first bitmap must not fall back to a later valid-looking one.
    let mut ready = vec![0; 76];
    ready[36..40].copy_from_slice(&2u32.to_le_bytes());
    assert!(
        State::new()
            .receive(&event(1, &[(32, &ready), (16, &[]), (16, &[0; 128])]))
            .is_err()
    );
    // Duplicate fixed fields remain ambiguous and invalid.
    let mut duplicate = base(false);
    tlv(&mut duplicate, 32, &ready).unwrap();
    assert!(State::new().receive(&duplicate).is_err());
}

#[test]
fn init_negotiates_extended_regulatory_events_only_when_firmware_advertises_them() {
    let mut state = State::new();
    state.receive(&base(false)).unwrap();
    let fields = resources();
    let init = state.initialize_command(&fields).unwrap();
    assert_eq!(
        word(required(&tlvs(&init[4..]).unwrap(), 75).unwrap(), 68 * 4).unwrap(),
        0
    );
    let mut bitmap = [0u8; 32]; // firmware also sends later service segments
    bitmap[..4].copy_from_slice(&(1u32 << 25).to_le_bytes()); // service 281
    state
        .receive(&event(3, &[(559, &[0; 20]), (16, &bitmap)]))
        .unwrap();
    let init = state.initialize_command(&fields).unwrap();
    assert_eq!(
        word(required(&tlvs(&init[4..]).unwrap(), 75).unwrap(), 68 * 4).unwrap(),
        1 << 4
    );
    assert_eq!(fields[69], 0); // retain the hardware profile's defaults
}

fn regulatory_event() -> Vec<u8> {
    let mut fixed = vec![0u8; 312];
    fixed[8..10].copy_from_slice(b"00");
    fixed[12..16].copy_from_slice(&2u32.to_le_bytes());
    fixed[12 * 4..13 * 4].copy_from_slice(&1u32.to_le_bytes());
    fixed[70 * 4..71 * 4].copy_from_slice(&1u32.to_le_bytes()); // LPI default client
    let mut rules = Vec::new();
    for (start, end, flags, psd) in [(2402, 2482, 2, 0), (5945, 6425, 1 << 9, 0x8000_00fb)] {
        let words: [u32; 4] = [start | (end << 16), 40 | (20 << 16), flags, psd];
        let data = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        tlv(&mut rules, 937, &data).unwrap();
    }
    event(0x3a003, &[(938, &fixed), (18, &rules)])
}

#[test]
fn regulatory_reports_preserve_restrictions_and_replace_only_the_matching_phy() {
    let mut state = State::new();
    let mut packet = regulatory_event();
    state.receive(&packet).unwrap();
    let report = &state.regulatory[0];
    assert_eq!(report.country, *b"00");
    assert_eq!(report.fixed.len(), 312);
    assert_eq!(report.counts[0], 1);
    assert_eq!(report.counts[5], 1);
    assert_eq!(report.rules[0][2], 2); // NO_IR must not disappear
    assert_eq!(report.rules[1][2..], [1 << 9, 0x8000_00fb]); // indoor and PSD bits
    packet[16..18].copy_from_slice(b"US");
    state.receive(&packet).unwrap();
    assert_eq!(state.regulatory.len(), 1);
    assert_eq!(state.regulatory[0].country, *b"US");
    packet[12..16].copy_from_slice(&1u32.to_le_bytes());
    state.receive(&packet).unwrap();
    assert_eq!(state.regulatory.len(), 2);
}

#[test]
fn truncated_or_inconsistent_regulatory_reports_do_not_replace_valid_state() {
    let packet = regulatory_event();
    for end in 0..packet.len() {
        assert!(State::new().receive(&packet[..end]).is_err());
    }
    let mut state = State::new();
    state.receive(&packet).unwrap();
    for (offset, value) in [(8, 1u32), (12, 9), (8 + 12 * 4, 11), (8 + 70 * 4, 6)] {
        let mut invalid = packet.clone();
        invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(state.receive(&invalid).is_err());
        assert_eq!(state.regulatory.len(), 1);
        assert_eq!(state.regulatory[0].country, *b"00");
    }
}

fn regulatory_event_with_extensions() -> Vec<u8> {
    // Synthetic packet with the exact outer sizes observed on hardware:
    // fixed=312, rules=120, two additional ARRAY_STRUCT bodies of 8 and 16.
    let mut fixed = vec![0u8; 312];
    fixed[8..10].copy_from_slice(b"00");
    fixed[12..16].copy_from_slice(&2u32.to_le_bytes());
    fixed[48..52].copy_from_slice(&2u32.to_le_bytes());
    fixed[52..56].copy_from_slice(&4u32.to_le_bytes());
    let mut rules = Vec::new();
    for (start, end, flags) in [
        (2402, 2482, 2u32),
        (2402, 2472, 2),
        (5170, 5250, 1 << 9),
        (5250, 5330, 1 << 3),
        (5490, 5730, (1 << 3) | 2),
        (5735, 5895, 2),
    ] {
        let words: [u32; 4] = [start | (end << 16), 40 | (20 << 16), flags, 0];
        let data = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        tlv(&mut rules, 937, &data).unwrap();
    }
    let mut extension_a = Vec::new();
    let mut extension_b = Vec::new();
    // Unknown extension tags remain opaque; their bytes cannot become rules.
    tlv(&mut extension_a, 1200, &[1, 2, 3, 4]).unwrap();
    tlv(&mut extension_b, 1201, &[5; 12]).unwrap();
    event(
        0x3a003,
        &[
            (938, &fixed),
            (18, &rules),
            (18, &extension_a),
            (18, &extension_b),
        ],
    )
}

#[test]
fn regulatory_arrays_are_positional_and_extensions_preserve_restrictions() {
    let packet = regulatory_event_with_extensions();
    assert_eq!(packet.len(), 476);
    let mut state = State::new();
    state.receive(&packet).unwrap();
    let report = &state.regulatory[0];
    assert_eq!(report.country, *b"00");
    assert_eq!(&report.counts[..2], &[2, 4]);
    assert_eq!(report.rules.len(), 6);
    assert_eq!(report.rules[0][2], 2); // NO_IR
    assert_eq!(report.rules[2][2], 1 << 9); // INDOOR_ONLY
    assert_eq!(report.rules[3][2], 1 << 3); // RADAR
    assert_eq!(report.rules[4][2], (1 << 3) | 2);
    assert_eq!(report.extensions.len(), 2);
    assert_eq!(report.extensions[0].len(), 8);
    assert_eq!(&report.extensions[0][4..], &[1, 2, 3, 4]);
    assert_eq!(&report.extensions[1][4..], &[5; 12]);
}

#[test]
fn regulatory_extensions_cannot_hide_invalid_rules_or_replace_valid_state() {
    let good = regulatory_event_with_extensions();
    let mut state = State::new();
    state.receive(&good).unwrap();
    let values = tlvs(&good[4..]).unwrap();
    let fixed = values[0].1;
    let rules = values[1].1;
    let mut invalid_rule = rules.to_vec();
    invalid_rule[..4].copy_from_slice(&((936u32 << 16) | 16).to_le_bytes());
    let invalid = [
        event(0x3a003, &[(938, fixed), (18, &[]), (18, rules)]),
        event(0x3a003, &[(938, fixed), (18, &invalid_rule), (18, rules)]),
        event(0x3a003, &[(938, fixed), (18, rules), (18, &[0; 3])]),
        event(0x3a003, &[(938, fixed), (18, rules), (938, fixed)]),
        good[..good.len() - 1].to_vec(),
    ];
    for packet in invalid {
        assert!(state.receive(&packet).is_err());
        assert_eq!(state.regulatory.len(), 1);
        assert_eq!(state.regulatory[0].rules.len(), 6);
        assert_eq!(state.regulatory[0].extensions.len(), 2);
        assert_eq!(state.regulatory[0].rules[4][2], (1 << 3) | 2);
    }
}

#[test]
fn captured_regulatory_event_accepts_legacy_tag_with_extended_rule_layout() {
    // Actual rejected WMI packet recovered from KLOG0002.TXT. Includes
    // legacy tag 608 with four-word rules and two independent struct arrays.
    let words: [u32; 119] = [
        0x0003a003, 0x03aa0138, 0x00000000, 0x00000000, 0x00003030, 0x00000002, 0x00000000,
        0x0000006c, 0x00000000, 0x00000000, 0x00000000, 0x00000028, 0x00000002, 0x000000a0,
        0x00000002, 0x00000004, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x0000ffff, 0x000000ff, 0x00000000, 0x00000000, 0x0000ffff, 0x0000ff00,
        0x00000000, 0x00000000, 0x00000000, 0x0000ffff, 0x00000000, 0x00000000, 0x00000000,
        0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x00000000, 0x00000003, 0x00000003,
        0x00000000, 0x00000000, 0x00000000, 0x0000ff01, 0x0000019e, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00008de8, 0x00000157, 0x00000000, 0x00000000, 0x0000f210, 0x00000157,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00120078, 0x02600010, 0x09a80962, 0x00140028,
        0x00000000, 0x00000000, 0x02600010, 0x09b20999, 0x00140014, 0x00000002, 0x00000000,
        0x02600010, 0x14d21432, 0x001400a0, 0x00000002, 0x00000000, 0x02600010, 0x16621572,
        0x001400a0, 0x00000002, 0x00000000, 0x02600010, 0x17071667, 0x001400a0, 0x00000002,
        0x00000000, 0x02600010, 0x1bd51739, 0x00140140, 0x00000002, 0x00000000, 0x00120008,
        0x04260004, 0x00000000, 0x00120010, 0x04570004, 0x000809a3, 0x04570004, 0x000209a8,
    ];
    let packet = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let mut state = State::new();
    state.receive(&packet).unwrap();
    let report = &state.regulatory[0];
    assert_eq!(report.country, *b"00");
    assert_eq!(report.counts, [2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(report.rules.len(), 6);
    assert_eq!(report.rules[0], [2402 | (2472 << 16), 0x140028, 0, 0]);
    assert!(
        report
            .raw_rules
            .iter()
            .all(|(tag, data)| *tag == 608 && data.len() == 16)
    );
    assert_eq!(report.rules[5], [5945 | (7125 << 16), 0x140140, 2, 0]);
    assert_eq!(report.extensions.len(), 2);
    assert_eq!(&report.extensions[1][4..8], &[0xa3, 0x09, 0x08, 0]);
    let plan = scan::channels(report);
    assert_eq!(plan.len(), 41); // 13 2.4-GHz and 28 5-GHz channels
    assert!(plan.iter().all(|c| c.frequency < 5900 && c.max_power == 20));
    let config = scan::RadioConfig {
        pdev: 0,
        regulatory_phy: 0,
    };
    assert!(scan::channel_list(config, &plan).unwrap().len() <= 2040);
}

#[test]
fn legacy_rule_tags_do_not_allow_missing_extended_restriction_fields() {
    let packet = regulatory_event();
    let values = tlvs(&packet[4..]).unwrap();
    let rules = tlvs(values[1].1).unwrap();
    let mut short_rules = Vec::new();
    tlv(&mut short_rules, 608, &rules[0].1[..12]).unwrap(); // missing PSD word
    tlv(&mut short_rules, 937, rules[1].1).unwrap();
    let invalid = event(0x3a003, &[(938, values[0].1), (18, &short_rules)]);
    let mut state = State::new();
    state.receive(&packet).unwrap();
    assert!(state.receive(&invalid).is_err());
    assert_eq!(state.regulatory[0].rules[1][2..], [1 << 9, 0x8000_00fb]);
}

#[test]
fn regulatory_rule_records_retain_additive_fields_for_other_firmware() {
    let packet = regulatory_event();
    let values = tlvs(&packet[4..]).unwrap();
    let rules = tlvs(values[1].1).unwrap();
    let mut extended = rules[0].1.to_vec();
    extended.extend_from_slice(&0x12345678u32.to_le_bytes());
    let mut array = Vec::new();
    tlv(&mut array, 937, &extended).unwrap();
    tlv(&mut array, 608, rules[1].1).unwrap();
    let packet = event(0x3a003, &[(938, values[0].1), (18, &array)]);
    let mut state = State::new();
    state.receive(&packet).unwrap();
    let report = &state.regulatory[0];
    assert_eq!(report.raw_rules[0], (937, extended));
    assert_eq!(report.raw_rules[1], (608, rules[1].1.to_vec()));
    assert_eq!(report.rules[0][2], 2); // NO_IR still applies
    assert_eq!(report.rules[1][2..], [1 << 9, 0x8000_00fb]);
}

#[test]
fn wmi_discovery_delivers_networks_and_ignores_bad_rf_frames() {
    use crate::kernel::wifi::scan::{Phase, Survey};
    let session = scan::Session {
        id: 0xa001,
        vdev: 0,
        deadline: 123,
    };
    let mut state = State::new();
    let mut survey = Survey::new();
    survey.begin();
    let scan_event = |kind: u32| {
        event(
            0x3001,
            &[(
                36,
                &[kind, 0, 2412, 1, 0xa001, 0, 0]
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
            )],
        )
    };
    state.receive(&scan_event(1)).unwrap();
    if let scan::Event::Scan(e) = state.next_event().unwrap() {
        survey.phase = session.phase(e).unwrap();
    } else {
        panic!("expected scan event");
    }
    let mut header = vec![0u8; 68];
    header[4..8].copy_from_slice(&45u32.to_le_bytes());
    header[16..20].copy_from_slice(&42u32.to_le_bytes());
    header[64..68].copy_from_slice(&2412u32.to_le_bytes());
    let mut frame = vec![0u8; 36];
    frame[0] = 0x80;
    frame[16] = 2;
    frame.extend_from_slice(&[0, 4, b't', b'e', b's', b't']);
    state
        .receive(&event(0x7001, &[(44, &header), (17, &frame[..40])]))
        .unwrap();
    assert!(state.next_event().is_none()); // invalid RF frame does not stop WMI
    state
        .receive(&event(0x7001, &[(44, &header), (17, &frame)]))
        .unwrap();
    if let scan::Event::Network(n) = state.next_event().unwrap() {
        survey.observe(n);
    } else {
        panic!("expected network");
    }
    state.receive(&scan_event(2)).unwrap();
    if let scan::Event::Scan(e) = state.next_event().unwrap() {
        survey.phase = session.phase(e).unwrap();
    } else {
        panic!("expected completion");
    }
    assert_eq!(survey.phase, Phase::Complete);
    assert_eq!(survey.networks.len(), 1);
    assert_eq!(survey.networks[0].ssid, b"test");
    assert!(survey.text().contains("-50 dBm open \"test\""));
    assert_eq!(state.management_stats.received, 2);
    assert_eq!(state.management_stats.decoded, 1);
    assert_eq!(state.management_stats.malformed, 1);
    assert_eq!(state.management_stats.queue_dropped, 0);
}

#[test]
fn rfkill_reports_physical_radio_state_without_inventing_a_default() {
    let mut state = State::new();
    assert_eq!(state.radio_on, None);
    let packet = |value: u32| {
        event(
            0x1e004,
            &[(
                231,
                &[48, 0, value]
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
            )],
        )
    };
    state.receive(&packet(1)).unwrap();
    assert_eq!(state.radio_on, Some(false));
    assert!(state.receive(&packet(0)).is_err());
    assert_eq!(state.radio_on, Some(false));
    state.receive(&packet(2)).unwrap();
    assert_eq!(state.radio_on, Some(true));
    let mut service = base(false);
    // WMI header + TLV header + sys_cap_info at fixed word 15.
    service[68..72].copy_from_slice(&2u32.to_le_bytes());
    state.receive(&service).unwrap();
    assert!(state.rfkill_supported);
}
