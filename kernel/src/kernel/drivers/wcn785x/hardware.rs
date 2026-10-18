// SPDX-License-Identifier: BSD-3-Clause-Clear
// WCN7850 pipe/resource defaults reference Linux ath12k hw.c/ce.c/wmi.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! Validated hardware profiles. Do not enable another PCI ID until its
//! firmware, register map, and boot sequence have been verified.
use crate::kernel::{
    drivers::{ce, mhi::Channels, qca_dp},
    qrtr::Service,
};

use alloc::{vec, vec::Vec};

pub(super) struct Chip {
    pub pci_id: u32,
    pub name: &'static str,
    pub bar_bytes: usize,
    pub soc_major: u32,
    pub firmware: &'static str,
    pub firmware_limit: usize,
    pub dma_bits: u32,
    pub channels: Channels,
    pub control_service: Service,
    pub hot_reset: u32,
    pub mission_settle_ms: u64,
    pub ce: ce::Config,
    pub shadow_base: u32,
    pub shadow_targets: &'static [u32],
    pub single_chip_mlo: Option<SingleChipMlo>,
    pub wmi_resources: fn(u32) -> Vec<u32>,
    pub radio: crate::kernel::wmi::scan::RadioConfig,
    pub radio_setup: crate::kernel::wmi::radio::Config,
    pub receive: qca_dp::rx::Config,
    pub rx_layout: crate::kernel::htt::RxLayout,
    pub dump_bytes: usize,
    pub packet_engine: qca_dp::Config,
    pub cookies: qca_dp::cookie::Config,
    pub assertion_read: Option<DiagnosticRead>,
}

/// Firmware topology identifiers, distinct from QMI's silicon chip ID.
#[derive(Clone, Copy)]
pub(super) struct SingleChipMlo {
    pub chip_id: u16,
    pub group_id: u8,
    pub peer_limit: u16,
}

pub(super) struct DiagnosticRead {
    pub firmware: u32,
    pub address: u32,
    pub memory_type: u32,
    pub bytes: u32,
}

const fn dp_ring(
    r0: u32,
    r2: u32,
    id: u32,
    entries: usize,
    words: usize,
    destination: bool,
    command_numbers: bool,
) -> qca_dp::RingConfig {
    qca_dp::RingConfig {
        r0,
        r2,
        id,
        entries,
        words,
        destination,
        command_numbers,
    }
}

// Linux ath12k hal.c/hw.c WCN7850 SRNG map and dp.c common setup.
// TCL queues 0/1/2 complete on WBM rings 0/2/4; ring 3 is RX errors.
const WCN7850_COMMON_RINGS: [qca_dp::RingConfig; 12] = [
    dp_ring(0xa3437c, 0xa37010, 121, 64, 8, false, false),
    dp_ring(0xa44900, 0xa46000, 24, 512, 8, false, false),
    dp_ring(0xa34e08, 0xa370c8, 128, 32768, 8, true, false),
    dp_ring(0xa44978, 0xa46008, 25, 512, 8, false, false),
    dp_ring(0xa34ef8, 0xa370d8, 130, 32768, 8, true, false),
    dp_ring(0xa449f0, 0xa46010, 26, 512, 8, false, false),
    dp_ring(0xa34fe8, 0xa370e8, 132, 32768, 8, true, false),
    dp_ring(0xa38304, 0xa3b028, 16, 32, 8, false, false),
    dp_ring(0xa34f70, 0xa370e0, 131, 1024, 8, true, false),
    dp_ring(0xa388a4, 0xa3b088, 0, 128, 8, true, false),
    dp_ring(0xa3828c, 0xa3b020, 20, 128, 12, false, true),
    dp_ring(0xa38a84, 0xa3b0a8, 21, 2048, 28, true, false),
];

// Ordered shadow-v3 doorbells from Linux's WCN7850 SRNG/CE configuration,
// verified against QMI WLAN_CONFIG TLV 0x17 in the successful Linux capture.
const WCN7850_SHADOW_TARGETS: &[u32] = &[
    0x00a3b04c, 0x00a3b054, 0x00a3b05c, 0x00a3b064, 0x00a3b06c, 0x00a3b074, 0x00a3b07c, 0x00a3b084,
    0x00a3b08c, 0x00a3b028, 0x00a3b020, 0x00a3b0ac, 0x00a46000, 0x00a46008, 0x00a46010, 0x00a46018,
    0x00a46020, 0x00a46028, 0x00a4604c, 0x00a370b8, 0x00a37010, 0x00a370cc, 0x00a370d4, 0x00a370dc,
    0x00a370e4, 0x00a370ec, 0x00a370f4, 0x00a370fc, 0x00a37104, 0x01b80400, 0x01b83400, 0x01b8340c,
    0x01b85400, 0x01b8540c, 0x01b86400, 0x01b88400,
];

const HOST_PIPES: &[ce::Pipe] = &[
    ce::Pipe {
        tx: 16,
        rx: 0,
        buffer_bytes: 2048,
    },
    ce::Pipe {
        tx: 0,
        rx: 512,
        buffer_bytes: 2048,
    },
    ce::Pipe {
        tx: 0,
        rx: 64,
        buffer_bytes: 2048,
    },
    ce::Pipe {
        tx: 32,
        rx: 0,
        buffer_bytes: 2048,
    },
    ce::Pipe {
        tx: 2048,
        rx: 0,
        buffer_bytes: 256,
    },
    ce::Pipe {
        tx: 0,
        rx: 0,
        buffer_bytes: 0,
    },
    ce::Pipe {
        tx: 0,
        rx: 0,
        buffer_bytes: 0,
    },
    ce::Pipe {
        tx: 0,
        rx: 0,
        buffer_bytes: 2048,
    },
    ce::Pipe {
        tx: 0,
        rx: 0,
        buffer_bytes: 0,
    },
];
// WLANFW wire definitions, matching ath12k's WCN7850 target configuration.
const TARGET_PIPES: &[[u32; 5]] = &[
    [0, 2, 32, 2048, 0],
    [1, 1, 32, 2048, 0],
    [2, 1, 32, 2048, 0],
    [3, 2, 32, 2048, 0],
    [4, 2, 256, 256, 8],
    [5, 1, 32, 2048, 0],
    [6, 3, 32, 16384, 0],
    [7, 4, 0, 0, 8],
    [8, 3, 32, 16384, 0],
];
const SERVICES: &[[u32; 3]] = &[
    [0x104, 2, 3],
    [0x104, 1, 2],
    [0x102, 2, 3],
    [0x102, 1, 2],
    [0x101, 2, 3],
    [0x101, 1, 2],
    [0x103, 2, 3],
    [0x103, 1, 2],
    [0x100, 2, 3],
    [0x100, 1, 2],
    [1, 2, 0],
    [1, 1, 2],
    [0x300, 2, 4],
    [0x300, 1, 1],
];

pub(super) const SUPPORTED: &[Chip] = &[Chip {
    pci_id: 0x1107_17cb,
    name: "WCN7850 hw2.0",
    bar_bytes: 2 * 1024 * 1024,
    soc_major: 2,
    firmware: "ath12k/WCN7850/hw2.0/amss.bin",
    firmware_limit: 32 * 1024 * 1024,
    dma_bits: 32,
    channels: Channels::new(20, 21).unwrap(),
    control_service: Service {
        id: 0x45,
        instance: 0x101,
    },
    // WCN7850 differs from QCN9274: Linux correction 7588a893cde5.
    hot_reset: 0x01e4_0304,
    // OpenBSD qwx waits 1000 us after AMSS before starting IPCR.
    // WCN7850 KLOG0025 confirms IPCR/WLANFW discovery with this delay;
    // the preceding build timed out starting channel 20.
    mission_settle_ms: 1,
    shadow_base: 0x8fc,
    shadow_targets: WCN7850_SHADOW_TARGETS,
    single_chip_mlo: Some(SingleChipMlo {
        chip_id: 0,
        group_id: 255,
        peer_limit: 32,
    }),
    wmi_resources: wcn7850_resources,
    // Linux's single_pdev_only WCN7850 exposes one logical pdev (0),
    // despite the firmware's two physical regulatory reports.
    radio: crate::kernel::wmi::scan::RadioConfig {
        pdev: 0,
        regulatory_phy: 0,
    },
    radio_setup: crate::kernel::wmi::radio::Config {
        tx_mask: 3,
        rx_mask: 3,
        rfkill: Some(crate::kernel::wmi::radio::RfKill {
            pin: 48,
            function: 0,
            on_high: true,
        }),
    },
    receive: qca_dp::rx::Config {
        rings: &[
            qca_dp::rx::RingConfig {
                id: 5,
                pdev: 0,
                direction: 2,
                role: qca_dp::rx::Role::Refill,
                entries: 4096,
                words: 2,
            },
            qca_dp::rx::RingConfig {
                id: 0,
                pdev: 1,
                direction: 1,
                role: qca_dp::rx::Role::Mac,
                entries: 2048,
                words: 2,
            },
            qca_dp::rx::RingConfig {
                id: 0,
                pdev: 2,
                direction: 1,
                role: qca_dp::rx::Role::Mac,
                entries: 2048,
                words: 2,
            },
            qca_dp::rx::RingConfig {
                id: 7,
                pdev: 1,
                direction: 0,
                role: qca_dp::rx::Role::Exception,
                entries: 1024,
                words: 8,
            },
            qca_dp::rx::RingConfig {
                id: 1,
                pdev: 1,
                direction: 1,
                role: qca_dp::rx::Role::Monitor,
                entries: 1024,
                words: 2,
            },
            qca_dp::rx::RingConfig {
                id: 1,
                pdev: 2,
                direction: 1,
                role: qca_dp::rx::Role::Monitor,
                entries: 1024,
                words: 2,
            },
        ],
        buffers: 8192,
        buffer_bytes: 2048,
        return_manager: 6,
    },
    // sizeof/offsetof against Linux v7.0's hal_rx_desc_wcn7850: 400 bytes,
    // MPDU tag at 144, MSDU tag at 0 and packet-header TLV at 272.
    rx_layout: crate::kernel::htt::RxLayout {
        packet: 400,
        mpdu: 144,
        msdu: 0,
        header: 272,
    },
    dump_bytes: 0x780000,
    // KLOG0035: WLANFW rejected the optional diagnostic read (QMI error 48).
    assertion_read: None,
    cookies: qca_dp::cookie::Config {
        reo: 0xa38050,
        wbm: 0xa34040,
        wbm_rings: 0x3a, // WCN7850 WBM rings 0, 2, 3, 4
        tx_pages: 256,   // four pools of 32768 slots / 512 entries per page
        rx_pages: 24,    // 12288 slots / 512 entries per page
    },
    packet_engine: qca_dp::Config {
        idle_r0: 0x00a3_4000 + 0xd3c,
        idle_r2: 0x00a3_4000 + 0x30b8,
        reo_r0: 0x00a3_8000 + 0x4e4,
        reo_r2: 0x00a3_8000 + 0x3048,
        link_entries: 32768,
        reo_entries: 2048,
        reo_count: 8,
        common: &WCN7850_COMMON_RINGS,
        reo_setup: Some(qca_dp::ReoConfig {
            base: 0xa38000,
            misc: 0xa38b7c,
            aging: 0xa38b08,
        }),
    },
    ce: ce::Config {
        base: 0x01b8_0000,
        stride: 0x2000,
        pipes: HOST_PIPES,
        target: TARGET_PIPES,
        services: SERVICES,
        control_receive: &[1, 2],
    },
}];

fn wcn7850_resources(chains: u32) -> Vec<u32> {
    // Word offsets in ath12k_wmi_resource_config_params, including its TLV header.
    let mut fields = vec![0u32; 73];
    fields[0] = (75 << 16) | (72 * 4);
    let mask = (1u32 << chains) - 1;
    for (field, value) in [
        (1, 4),  // vdevs
        (2, 16), // peers
        (3, 3),
        (4, 3), // offload peers/reorder buffers
        (5, 2),
        (6, 32),
        (7, 16), // keys, TIDs, AST skid
        (8, mask),
        (9, mask),
        (10, 100),
        (11, 100),
        (12, 100),
        (13, 40), // receive timeouts
        (14, 1),  // native Wi-Fi decapsulation
        (15, 4),
        (16, 3),
        (17, 3),
        (18, 8),    // scans, beacon miss, roaming limits
        (22, 1024), // firmware debug log
        (28, 2),
        (29, 0x400),
        (30, 10), // GTK offload, MSDUs, fragments
        (31, 1),
        (32, 8),
        (33, 2),
        (34, 32),
        (35, 22),
        (44, (1 << 5) | (1 << 18)), // 64-bit BSS channel info and ACK RSSI
        (54, 1),
        (57, 1),                   // pdev IDs and peer map/unmap version
        (68, (1 << 4) | (1 << 9)), // RX peer metadata v1 and next DTIM calculation
    ] {
        fields[field] = value;
    }
    fields
}
