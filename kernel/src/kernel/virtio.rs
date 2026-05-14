//! Modern virtio-pci (1.x) transport: device discovery + capability
//! parsing.
//!
//! Virtio 1.x splits its hardware interface across four configuration
//! regions, each located via a PCI vendor-specific capability (cap ID
//! 0x09) tagged with a `cfg_type` byte:
//!
//! ```text
//!   cfg_type 1 = COMMON     device + queue control registers
//!   cfg_type 2 = NOTIFY     doorbell window (one offset per queue)
//!   cfg_type 3 = ISR        interrupt status (legacy IRQ)
//!   cfg_type 4 = DEVICE     device-class-specific config block
//!   cfg_type 5 = PCI_CFG    alternate access via PCI config space
//! ```
//!
//! Each capability descriptor (after the 2-byte cap id + next header)
//! carries: cap length, cfg_type, BAR number, padding, offset, length.
//! The NOTIFY cap has an extra `notify_off_multiplier` u32 appended.
//!
//! This module discovers virtio devices and records WHERE their config
//! regions live. It does not yet map the BARs or speak the virtio
//! protocol — that comes in the next layer.

extern crate alloc;
use alloc::vec::Vec;

use crate::kernel::pci::{self, Bar, PciAddr, PciDevice};
use crate::kernel::pci::{read_config_u8, read_config_u32};

const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Modern virtio device IDs sit in 0x1040..=0x107F; the low 6 bits are
/// the virtio device-type number (1=net, 2=blk, ..., 25=sound).
const VIRTIO_MODERN_BASE: u16 = 0x1040;
const VIRTIO_MODERN_END: u16 = 0x1080;

/// PCI vendor-specific capability ID — virtio caps use this with a
/// per-cap `cfg_type` discriminator at byte 3.
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VirtioCfgType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    PciCfg = 5,
}

impl VirtioCfgType {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Common,
            2 => Self::Notify,
            3 => Self::Isr,
            4 => Self::Device,
            5 => Self::PciCfg,
            _ => return None,
        })
    }
}

/// One discovered virtio capability region.
#[derive(Clone, Copy, Debug)]
pub struct VirtioCap {
    pub cfg_type: VirtioCfgType,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    /// Only meaningful for `Notify`: per the spec, the doorbell address
    /// for queue Q is `cap.offset + queue_notify_off(Q) * multiplier`.
    pub notify_off_multiplier: u32,
}

/// A discovered modern virtio-pci device with its config-region map.
/// Not yet attached / initialized — just a parsed descriptor.
pub struct VirtioPciDevice {
    pub addr: PciAddr,
    pub device_id: u16,
    pub caps: Vec<VirtioCap>,
}

impl VirtioPciDevice {
    /// Virtio device-type number (1=net, 2=blk, ..., 25=sound) derived
    /// from the modern device-id encoding.
    pub fn device_type(&self) -> u16 {
        self.device_id.wrapping_sub(VIRTIO_MODERN_BASE)
    }

    pub fn find_cap(&self, cfg_type: VirtioCfgType) -> Option<&VirtioCap> {
        self.caps.iter().find(|c| c.cfg_type == cfg_type)
    }
}

/// Try to recognize a PCI device as a modern virtio device and parse
/// its capability list. Returns None for non-virtio devices or for
/// transitional/legacy virtio (device IDs 0x1000-0x103F).
pub fn try_attach(pci: &PciDevice) -> Option<VirtioPciDevice> {
    if pci.vendor != VIRTIO_VENDOR {
        return None;
    }
    if pci.device < VIRTIO_MODERN_BASE || pci.device >= VIRTIO_MODERN_END {
        return None;
    }
    let mut caps = Vec::new();
    for cap_off in pci::capabilities(pci.addr) {
        let cap_id = read_config_u8(pci.addr, cap_off);
        if cap_id != PCI_CAP_VENDOR_SPECIFIC {
            continue;
        }
        // Cap layout (per virtio 1.x §4.1.4.1):
        //   +0 cap_vndr (0x09)
        //   +1 cap_next
        //   +2 cap_len
        //   +3 cfg_type
        //   +4 bar
        //   +5..+8 padding / id
        //   +8 offset (u32)
        //   +12 length (u32)
        //   +16 notify_off_multiplier (u32, NOTIFY only)
        let cfg_byte = read_config_u8(pci.addr, cap_off + 3);
        let Some(cfg_type) = VirtioCfgType::from_byte(cfg_byte) else { continue };
        let bar = read_config_u8(pci.addr, cap_off + 4);
        let offset = read_config_u32(pci.addr, cap_off + 8);
        let length = read_config_u32(pci.addr, cap_off + 12);
        let notify_off_multiplier = if cfg_type == VirtioCfgType::Notify {
            read_config_u32(pci.addr, cap_off + 16)
        } else {
            0
        };
        caps.push(VirtioCap { cfg_type, bar, offset, length, notify_off_multiplier });
    }
    Some(VirtioPciDevice { addr: pci.addr, device_id: pci.device, caps })
}

/// Debugcon dump of a discovered virtio device's capability map and
/// BAR layout. For diagnostic logging at boot.
pub fn log_device(d: &VirtioPciDevice) {
    let kind = device_kind_name(d.device_type());
    crate::println!(
        "  virtio {:02x}:{:02x}.{}  device_id={:04x} ({}, type {})  caps={}",
        d.addr.bus, d.addr.device, d.addr.function,
        d.device_id, kind, d.device_type(), d.caps.len(),
    );
    for cap in &d.caps {
        let suffix = if cap.cfg_type == VirtioCfgType::Notify {
            alloc::format!(" notify_mult={}", cap.notify_off_multiplier)
        } else {
            alloc::string::String::new()
        };
        crate::println!(
            "    {:?} bar{} offset={:#x} length={:#x}{}",
            cap.cfg_type, cap.bar, cap.offset, cap.length, suffix,
        );
    }
    let mut idx = 0u8;
    while idx < 6 {
        match pci::read_bar(d.addr, idx) {
            None => {
                idx += 1;
            }
            Some((bar, consumed)) => {
                match bar {
                    Bar::Mem32 { base, prefetchable } => crate::println!(
                        "    bar{}: mem32 base={:#010x}{}",
                        idx, base, if prefetchable { " (prefetch)" } else { "" },
                    ),
                    Bar::Mem64 { base, prefetchable } => crate::println!(
                        "    bar{}: mem64 base={:#x}{}",
                        idx, base, if prefetchable { " (prefetch)" } else { "" },
                    ),
                    Bar::Io { port } => crate::println!(
                        "    bar{}: io port={:#x}", idx, port,
                    ),
                }
                idx += consumed;
            }
        }
    }
}

/// Map of modern virtio device-type numbers to short names. Only the
/// ones we might plausibly encounter on QEMU.
fn device_kind_name(t: u16) -> &'static str {
    match t {
        1 => "net",
        2 => "blk",
        3 => "console",
        4 => "rng",
        5 => "balloon",
        9 => "9p",
        16 => "gpu",
        18 => "input",
        19 => "vsock",
        25 => "sound",
        _ => "?",
    }
}
