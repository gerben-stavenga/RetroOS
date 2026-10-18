use super::*;
use alloc::vec;

#[test]
fn phy_capabilities_preserve_absent_fields_and_validate_present_values() {
    let mut body = Vec::new();
    qmi::tlv(&mut body, 0x10, &[2]).unwrap();
    qmi::tlv(&mut body, 0x11, &255u32.to_le_bytes()).unwrap();
    qmi::tlv(&mut body, 0x13, &[1]).unwrap();
    let packet = qmi::encode(qmi::RESPONSE, 1, 0x57, &body).unwrap();
    assert_eq!(
        phy_capabilities(&qmi::Message::parse(&packet).unwrap()).unwrap(),
        PhyCapabilities {
            phys: Some(2),
            board: Some(255),
            single_chip_mlo: Some(true)
        }
    );
    let packet = qmi::encode(qmi::RESPONSE, 1, 0x57, &[]).unwrap();
    assert_eq!(
        phy_capabilities(&qmi::Message::parse(&packet).unwrap()).unwrap(),
        PhyCapabilities {
            phys: None,
            board: None,
            single_chip_mlo: None
        }
    );
    for (tag, value) in [
        (0x10, &[][..]),
        (0x10, &[1, 2][..]),
        (0x11, &[1, 2, 3][..]),
        (0x13, &[2][..]),
    ] {
        let packet = message(0x57, tag, value);
        assert!(phy_capabilities(&qmi::Message::parse(&packet).unwrap()).is_err());
    }
}

#[test]
fn firmware_logging_request_matches_successful_linux_capture() {
    assert_eq!(firmware_logging().unwrap(), &[0x10, 1, 0, 1]);
}

#[test]
fn single_chip_firmware_topology_matches_successful_linux_host_capabilities() {
    let chip = &super::super::hardware::SUPPORTED[0];
    let phy = PhyCapabilities {
        phys: Some(2),
        board: None,
        single_chip_mlo: Some(true),
    };
    let topology = firmware_topology(chip.single_chip_mlo, &phy)
        .unwrap()
        .unwrap();
    // Exact HOST_CAP TLV body from the successful Linux packet, including
    // unused partner-chip records, not just the MLO enable bit.
    let expected = [
        0x10, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x0e, 0x14, 0x01, 0x00, 0x01,
        0x16, 0x01, 0x00, 0x01, 0x17, 0x01, 0x00, 0x01, 0x1a, 0x01, 0x00, 0x00, 0x1c, 0x01, 0x00,
        0x00, 0x21, 0x01, 0x00, 0x01, 0x22, 0x02, 0x00, 0x00, 0x00, 0x23, 0x01, 0x00, 0xff, 0x24,
        0x02, 0x00, 0x20, 0x00, 0x25, 0x01, 0x00, 0x01, 0x26, 0x12, 0x00, 0x00, 0x02, 0x00, 0x01,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27,
        0x08, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(host_capabilities(Some(topology)).unwrap(), expected);
}

#[test]
fn firmware_topology_requires_profile_and_firmware_support_and_bounds_link_ids() {
    let chip = &super::super::hardware::SUPPORTED[0];
    for (phys, supported) in [(None, Some(true)), (Some(2), None), (Some(2), Some(false))] {
        let phy = PhyCapabilities {
            phys,
            board: None,
            single_chip_mlo: supported,
        };
        assert!(
            firmware_topology(chip.single_chip_mlo, &phy)
                .unwrap()
                .is_none()
        );
    }
    let mut phy = PhyCapabilities {
        phys: Some(2),
        board: None,
        single_chip_mlo: Some(true),
    };
    assert!(firmware_topology(None, &phy).unwrap().is_none());
    for links in [0, 3, 255] {
        phy.phys = Some(links);
        assert!(firmware_topology(chip.single_chip_mlo, &phy).is_err());
    }
    phy.phys = Some(1);
    for (chip_id, peer_limit) in [(256, 32), (0, 0)] {
        let invalid = super::super::hardware::SingleChipMlo {
            chip_id,
            group_id: 255,
            peer_limit,
        };
        assert!(firmware_topology(Some(invalid), &phy).is_err());
    }
    let topology = firmware_topology(chip.single_chip_mlo, &phy)
        .unwrap()
        .unwrap();
    let packet = qmi::encode(
        qmi::REQUEST,
        1,
        0x34,
        &host_capabilities(Some(topology)).unwrap(),
    )
    .unwrap();
    let packet = qmi::Message::parse(&packet).unwrap();
    assert_eq!(
        packet.required(0x26).unwrap(),
        &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn firmware_topology_memory_is_included_in_the_dma_budget() {
    let mut segment = Vec::new();
    segment.push(1);
    segment.extend_from_slice(&4096u32.to_le_bytes());
    segment.extend_from_slice(&8u32.to_le_bytes());
    segment.push(0);
    let packet = message(0x35, 1, &segment);
    assert_eq!(
        memory_request(&qmi::Message::parse(&packet).unwrap()).unwrap(),
        vec![Segment {
            size: 4096,
            kind: 8
        }]
    );
    segment[1..5].copy_from_slice(&((MAX_MEMORY + 4096) as u32).to_le_bytes());
    let packet = message(0x35, 1, &segment);
    assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
}

#[test]
fn diagnostic_read_encodes_three_scalars_and_rejects_unbounded_reads() {
    let body = diagnostic_request(0x1f26900, 0, 512).unwrap();
    assert_eq!(body.len(), 21);
    let bytes = qmi::encode(qmi::REQUEST, 1, 0x30, &body).unwrap();
    let request = qmi::Message::parse(&bytes).unwrap();
    assert_eq!(word(request.required(1).unwrap()).unwrap(), 0x1f26900);
    assert_eq!(word(request.required(2).unwrap()).unwrap(), 0);
    assert_eq!(word(request.required(3).unwrap()).unwrap(), 512);
    for (address, length) in [
        (0x1000, 0),
        (0x1000, 513),
        (0x1000, 516),
        (0x1001, 4),
        (0x1000, 3),
        (0xffff_fffc, 512),
    ] {
        assert!(diagnostic_request(address, 0, length).is_err());
    }
}

#[test]
fn diagnostic_read_reply_requires_the_exact_declared_byte_count() {
    let packet = message(0x30, 0x10, &[4, 0, 0, 255, b'A', 0]);
    assert_eq!(
        diagnostic_response(&qmi::Message::parse(&packet).unwrap(), 4).unwrap(),
        &[0, 255, b'A', 0]
    );
    for data in [
        &[][..],
        &[4][..],
        &[4, 0, 1, 2, 3][..],
        &[3, 0, 1, 2, 3, 4][..],
        &[4, 0, 1, 2, 3, 4, 5][..],
    ] {
        let packet = message(0x30, 0x10, data);
        assert!(diagnostic_response(&qmi::Message::parse(&packet).unwrap(), 4).is_err());
    }
}

#[test]
fn paging_dump_preserves_rddm_and_records_only_requested_host_ddr() {
    struct Snapshot(&'static [u8], u64);
    impl Memory for Snapshot {
        fn physical(&self) -> u64 {
            self.1
        }
        fn read32(&self, _: usize) -> u32 {
            unreachable!()
        }
        fn write32(&mut self, _: usize, _: u32) {
            unreachable!()
        }
        fn copy_in(&mut self, _: usize, _: &[u8]) {
            unreachable!()
        }
        fn copy_out(&self, offset: usize, count: usize) -> Vec<u8> {
            self.0[offset..offset + count].to_vec()
        }
    }
    let memory = [
        HostMemory {
            region: Snapshot(b"abcPAD", 0x5800000),
            kind: 1,
            bytes: 3,
        },
        HostMemory {
            region: Snapshot(b"calibration", 0x6000000),
            kind: 4,
            bytes: 11,
        },
        HostMemory {
            region: Snapshot(b"defgPAD", 0x6800000),
            kind: 1,
            bytes: 4,
        },
    ];
    let mut dump = b"raw RDDM".to_vec();
    append_paging_dump(&mut dump, &memory, None);
    assert_eq!(&dump[..8], b"raw RDDM");
    assert_eq!(&dump[8..16], b"RTWFPAGE");
    assert_eq!(word(&dump[16..20]).unwrap(), 1);
    assert_eq!(word(&dump[20..24]).unwrap(), 2);
    assert_eq!(&dump[24..32], &[1, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(
        u64::from_le_bytes(dump[32..40].try_into().unwrap()),
        0x5800000
    );
    assert_eq!(&dump[40..48], &[1, 0, 0, 0, 4, 0, 0, 0]);
    assert_eq!(&dump[56..63], b"abcdefg");
    assert_eq!(&dump[63..71], b"RTWFEND1");
    assert_eq!(u64::from_le_bytes(dump[71..79].try_into().unwrap()), 8);
    assert_eq!(dump.len(), 79);
    let mut dump = b"raw RDDM".to_vec();
    append_paging_dump(&mut dump, &memory, Some((0x6a00000, b"CE bytes")));
    assert_eq!(word(&dump[20..24]).unwrap(), 3);
    assert_eq!(word(&dump[56..60]).unwrap(), 0x100);
    assert_eq!(word(&dump[60..64]).unwrap(), 8);
    assert_eq!(
        u64::from_le_bytes(dump[64..72].try_into().unwrap()),
        0x6a00000
    );
    assert_eq!(&dump[72..87], b"abcdefgCE bytes");
    assert_eq!(&dump[87..95], b"RTWFEND1");
    assert_eq!(u64::from_le_bytes(dump[95..103].try_into().unwrap()), 8);
    let topology_memory = [HostMemory {
        region: Snapshot(b"MLOpadding", 0x7000000),
        kind: 8,
        bytes: 3,
    }];
    let mut dump = b"raw RDDM".to_vec();
    append_paging_dump(&mut dump, &topology_memory, None);
    assert_eq!(word(&dump[20..24]).unwrap(), 1);
    assert_eq!(word(&dump[24..28]).unwrap(), 8);
    assert_eq!(word(&dump[28..32]).unwrap(), 3);
    assert_eq!(&dump[40..43], b"MLO");
    assert_eq!(&dump[43..51], b"RTWFEND1");
}

#[test]
fn memory_response_matches_two_packed_wlanfw_descriptors() {
    // Linux qmi.c encodes each nested record as u64 address, u32 size,
    // signed-u32 type, u8 restore, with a u8 array count and no struct padding.
    let body = memory_response(&[
        (
            Segment {
                size: 7_012_352,
                kind: 1,
            },
            0x0380_0000,
        ),
        (
            Segment {
                size: 8_454_144,
                kind: 4,
            },
            0x0400_0000,
        ),
    ])
    .unwrap();
    assert_eq!(
        body,
        [
            1, 35, 0, 2, 0, 0, 0x80, 3, 0, 0, 0, 0, 0, 0, 0x6b, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
            0, 0, 0, 0, 0x81, 0, 4, 0, 0, 0, 0,
        ]
    );
    assert!(memory_response(&[]).is_err());
}

fn message(id: u16, tag: u8, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    qmi::tlv(&mut body, tag, data).unwrap();
    qmi::encode(qmi::INDICATION, 0, id, &body).unwrap()
}

#[test]
fn memory_indication_decodes_nested_variable_arrays() {
    // One segment with a config, followed by a segment without configs.
    let mut bytes = vec![2];
    bytes.extend_from_slice(&8192u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&4096u32.to_le_bytes());
    bytes.extend_from_slice(&1024u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&4096u32.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.push(0);
    let packet = message(0x35, 1, &bytes);
    let decoded = memory_request(&qmi::Message::parse(&packet).unwrap()).unwrap();
    assert_eq!(
        decoded,
        [
            Segment {
                size: 8192,
                kind: 1
            },
            Segment {
                size: 4096,
                kind: 3
            }
        ]
    );
    for end in 0..bytes.len() {
        let packet = message(0x35, 1, &bytes[..end]);
        assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
    }
    // Config extends past its segment, and an excessive top-level count.
    bytes[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    let packet = message(0x35, 1, &bytes);
    assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
    let packet = message(0x35, 1, &[53]);
    assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
}

#[test]
fn firmware_memory_limit_and_empty_requests_are_checked_before_allocation() {
    for size in [0, u32::MAX, (MAX_MEMORY + 4096) as u32] {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0);
        let packet = message(0x35, 1, &bytes);
        assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
    }
    let packet = message(0x35, 1, &[0]);
    assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
    let mut bytes = vec![2];
    for _ in 0..2 {
        bytes.extend_from_slice(&((MAX_MEMORY / 2 + 1) as u32).to_le_bytes());
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.push(0);
    }
    let packet = message(0x35, 1, &bytes);
    assert!(memory_request(&qmi::Message::parse(&packet).unwrap()).is_err());
}

fn element(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out.resize(out.len().div_ceil(4) * 4, 0x6d);
}
fn bundle() -> Vec<u8> {
    let mut bytes = b"QCA-ATH12K-BOARD\0mmm".to_vec();
    let mut entry = Vec::new();
    element(&mut entry, 0, b"wrong-board");
    element(&mut entry, 1, b"wrong-data");
    element(&mut entry, 0, b"our-board");
    element(&mut entry, 0, b"alias");
    element(&mut entry, 1, b"correct-board");
    element(&mut bytes, 0, &entry);
    let mut entry = Vec::new();
    element(&mut entry, 0, b"bus=pci");
    element(&mut entry, 1, b"regdb");
    element(&mut bytes, 1, &entry);
    bytes
}

#[test]
fn board_bundle_respects_names_aliases_kinds_and_padding() {
    let bytes = bundle();
    assert_eq!(
        board_entry(&bytes, 0, b"our-board").unwrap(),
        Some(b"correct-board".as_slice())
    );
    assert_eq!(
        board_entry(&bytes, 0, b"alias").unwrap(),
        Some(b"correct-board".as_slice())
    );
    assert_eq!(board_entry(&bytes, 0, b"unknown").unwrap(), None);
    assert_eq!(board_entry(&bytes, 1, b"our-board").unwrap(), None);
    assert_eq!(
        board_entry(&bytes, 1, b"bus=pci").unwrap(),
        Some(b"regdb".as_slice())
    );
    let mut valid_ends = vec![20];
    let mut tail = &bytes[20..];
    while !tail.is_empty() {
        tail = ie(tail).unwrap().2;
        valid_ends.push(bytes.len() - tail.len());
    }
    for end in 0..bytes.len() {
        let result = board_entry(&bytes[..end], 0, b"our-board");
        assert_eq!(result.is_ok(), valid_ends.contains(&end));
    }
    let mut bad = bytes.clone();
    bad[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(board_entry(&bad, 0, b"our-board").is_err());
    bad[0] = 0;
    assert!(board_entry(&bad, 0, b"our-board").is_err());
    // A second exact entry must not silently select one of two profiles.
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes[20..]);
    assert!(board_entry(&duplicate, 0, b"our-board").is_err());
}

#[test]
fn download_chunks_use_remaining_length_and_only_mark_last_segment() {
    for (segment, length, remaining, end) in [(0, CHUNK, CHUNK + 1, 0), (1, 1, 1, 1)] {
        let body = download_request(255, 4, CHUNK + 1, segment, &vec![0xa5; length]).unwrap();
        let bytes = qmi::encode(qmi::REQUEST, 1, 0x25, &body).unwrap();
        let message = qmi::Message::parse(&bytes).unwrap();
        assert_eq!(word(message.get(0x11).unwrap()).unwrap(), remaining as u32);
        assert_eq!(word(message.get(0x12).unwrap()).unwrap(), segment as u32);
        assert_eq!(message.get(0x14).unwrap(), &[end]);
        assert_eq!(message.get(0x15).unwrap(), &[4]);
        let data = message.get(0x13).unwrap();
        assert_eq!(u16::from_le_bytes([data[0], data[1]]) as usize, length);
        assert_eq!(&data[2..], &vec![0xa5; length]);
    }
    assert!(download_request(255, 1, CHUNK + 1, 1, &[]).is_err());
    assert!(download_request(255, 1, CHUNK + 1, 2, &[1]).is_err());
}

#[test]
fn capability_reply_requires_chip_and_validates_optional_scalar_widths() {
    let packet = message(0x24, 0x10, &[2, 0, 0, 0, 4, 0, 0, 0]);
    let caps = capabilities(&qmi::Message::parse(&packet).unwrap()).unwrap();
    assert_eq!((caps.chip, caps.board), (2, 255));
    for value in [&[2][..], &[0; 12][..]] {
        let packet = message(0x24, 0x10, value);
        assert!(capabilities(&qmi::Message::parse(&packet).unwrap()).is_err());
    }
}

#[test]
fn device_memory_capability_has_four_fixed_u64_pairs() {
    assert_eq!(device_memory(None).unwrap(), None);
    let mut bytes = [0u8; 64];
    bytes[..8].copy_from_slice(&0x1000b00000u64.to_le_bytes());
    bytes[8..16].copy_from_slice(&4096u64.to_le_bytes());
    // Later records must not replace the designated CMEM region at index 0.
    bytes[16..24].copy_from_slice(&0xffff_ffff_ffff_ffffu64.to_le_bytes());
    assert_eq!(
        device_memory(Some(&bytes)).unwrap(),
        Some((0x1000b00000, 4096))
    );
    for length in 0..64 {
        assert!(device_memory(Some(&bytes[..length])).is_err());
    }
    assert!(device_memory(Some(&[0; 65])).is_err());
}
#[test]
fn host_without_firmware_topology_does_not_advertise_calibration_or_mlo_support() {
    let bytes = qmi::encode(qmi::REQUEST, 1, 0x34, &host_capabilities(None).unwrap()).unwrap();
    let request = qmi::Message::parse(&bytes).unwrap();
    assert_eq!(request.get(0x13).unwrap(), &[0x0e]);
    assert_eq!(request.get(0x1a).unwrap(), &[0]);
    assert_eq!(request.get(0x21).unwrap(), &[0]);
    let bytes = qmi::encode(qmi::REQUEST, 1, 0x20, &registration().unwrap()).unwrap();
    let request = qmi::Message::parse(&bytes).unwrap();
    assert_eq!(word(request.get(0x15).unwrap()).unwrap(), 0x4b4e454c);
    for tag in [0x10, 0x16, 0x17, 0x18, 0x1b] {
        assert_eq!(request.get(tag).unwrap(), &[1]);
    }
}

#[test]
fn wcn7850_configuration_encodes_target_pipes_and_service_mapping() {
    let chip = &super::super::hardware::SUPPORTED[0];
    let bytes = qmi::encode(
        qmi::REQUEST,
        1,
        0x23,
        &wlan_configuration(chip.ce, chip.shadow_targets).unwrap(),
    )
    .unwrap();
    let request = qmi::Message::parse(&bytes).unwrap();
    assert_eq!(bytes.len(), 517); // successful Linux WLAN_CONFIG wire length
    assert_eq!(request.get(0x10).unwrap(), b"WIN");
    let pipes = request.get(0x11).unwrap();
    assert_eq!(pipes.len(), 1 + 9 * 20);
    assert_eq!(pipes[0], 9);
    assert_eq!(word(&pipes[1 + 4 * 20 + 16..1 + 5 * 20]).unwrap(), 8); // HTT disables interrupts
    let services = request.get(0x12).unwrap();
    assert_eq!(services.len(), 1 + 14 * 12);
    assert_eq!(services[0], 14);
    let wmi_out = &services[1 + 8 * 12..1 + 9 * 12];
    assert_eq!(word(&wmi_out[..4]).unwrap(), 0x100);
    assert_eq!(word(&wmi_out[4..8]).unwrap(), 2);
    assert_eq!(word(&wmi_out[8..]).unwrap(), 3);
    let shadows = request.get(0x17).unwrap(); // shadow-v3 is tag 0x17, not 0x16
    assert_eq!(shadows.len(), 145);
    assert_eq!(shadows[0], 36);
    for (index, target) in chip.shadow_targets.iter().enumerate() {
        assert_eq!(
            word(&shadows[1 + index * 4..5 + index * 4]).unwrap(),
            *target
        );
    }
    let needed = ce::Engine::<Dma>::required_bytes(chip.ce).unwrap();
    assert!(needed < 2 * 1024 * 1024);
}

#[test]
fn wlan_configuration_rejects_ambiguous_or_invalid_shadow_maps() {
    let chip = &super::super::hardware::SUPPORTED[0];
    for shadows in [
        &[0xa3b04c, 0xa3b04c][..],
        &[0xa3b04d][..],
        &[0x02000000][..],
    ] {
        assert!(wlan_configuration(chip.ce, shadows).is_err());
    }
    assert!(wlan_configuration(chip.ce, &[0x100; 61]).is_err());
    assert!(wlan_configuration(chip.ce, &[]).is_ok()); // other profiles can use direct MMIO
}

#[test]
fn wcn7850_wmi_resources_match_single_pdev_layout() {
    let chip = &super::super::hardware::SUPPORTED[0];
    let resources = (chip.wmi_resources)(2);
    assert_eq!(resources.len(), 73);
    assert_eq!(resources[0], (75 << 16) | 288);
    assert_eq!(&resources[1..10], &[4, 16, 3, 3, 2, 32, 16, 3, 3]);
    assert_eq!(resources[14], 1);
    assert_eq!(resources[29], 0x400);
    assert_eq!((resources[54], resources[57]), (1, 1));
    assert_eq!(resources[69], 0); // no unsupported host regulatory event capability
}

#[test]
fn wcn7850_resources_match_successful_linux_startup_capture() {
    // Captured on this WCN7850 with Linux 7.0.0-38: INIT length 328,
    // followed by firmware ready. The generic WMI layer negotiates the
    // regulatory host-service flag separately, so leave resource word 69 zero.
    let expected = [
        0x4b0120, 4, 16, 3, 3, 2, 32, 16, 3, 3, 100, 100, 100, 40, 1, 4, 3, 3, 8, 0, 0, 0, 0x400,
        0, 0, 0, 0, 0, 2, 0x400, 10, 1, 8, 2, 32, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0x40020, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x210, 0, 0, 0, 0,
    ];
    let chip = &super::super::hardware::SUPPORTED[0];
    assert_eq!((chip.wmi_resources)(2).as_slice(), &expected);
}
