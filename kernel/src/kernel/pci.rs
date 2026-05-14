//! PCI bus enumeration via legacy I/O-port configuration access.
//!
//! Uses CONFIG_ADDRESS at 0xCF8 + CONFIG_DATA at 0xCFC (Configuration
//! Mechanism #1). Covers everything we need on QEMU's q35/i440fx and on
//! real x86 hardware up to PCIe-via-CAM. PCIe Extended Configuration
//! Space (MMIO via ACPI MCFG) isn't implemented — not required yet.
//!
//! Single-bus enumeration only. Bridges aren't recursed into; QEMU's
//! default setup keeps all our devices on bus 0.
//!
//! This module is mechanism, not policy: it discovers and logs devices.
//! Driver binding lives elsewhere.
//!
//! ## Configuration address layout
//!
//! ```text
//!  31    30..24    23..16    15..11    10..8     7..2     1..0
//! [E ][reserved][  bus  ][ device ][ func ][ reg/4 ][ 00 ]
//! ```
//!
//! E=1 to enable, reg is the byte offset (multiple of 4). The low 2 bits
//! of register-within-dword are conveyed implicitly by the data port the
//! reader uses (CONFIG_DATA + 0..3) — but we always read the full dword
//! and shift, keeping the access aligned.
//!
//! ## Header type 0x00 (standard endpoint) layout used here
//!
//! ```text
//!  off  bytes  field
//!  00   2      vendor id     (0xFFFF = no device)
//!  02   2      device id
//!  04   2      command
//!  06   2      status
//!  08   1      revision id
//!  09   1      prog if
//!  0A   1      subclass
//!  0B   1      class code
//!  0E   1      header type   (bit 7 = multi-function)
//! ```

use crate::arch::{inl, outl};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const REG_VENDOR_DEVICE: u8 = 0x00;
const REG_STATUS: u8 = 0x06;
const REG_REVISION_CLASS: u8 = 0x08;
/// Offset of the header_type byte. Sits in the dword at 0x0C (which also
/// holds cache-line size, latency timer, and BIST); read_config_u8 takes
/// the byte-granular offset and does the right shift internally.
const REG_HEADER_TYPE: u8 = 0x0E;
const REG_BAR0: u8 = 0x10;
const REG_CAP_POINTER: u8 = 0x34;

const STATUS_CAP_LIST: u16 = 1 << 4;

/// (bus, device, function) tuple identifying a PCI configuration target.
#[derive(Clone, Copy)]
pub struct PciAddr {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddr {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }

    fn config_address(self, offset: u8) -> u32 {
        let bus = self.bus as u32;
        let dev = (self.device as u32) & 0x1F;
        let func = (self.function as u32) & 0x07;
        let off = (offset as u32) & 0xFC;
        0x8000_0000 | (bus << 16) | (dev << 11) | (func << 8) | off
    }
}

/// Read a 32-bit value from the device's configuration space. `offset`
/// must be 4-byte aligned; the low 2 bits are masked off.
pub fn read_config_u32(addr: PciAddr, offset: u8) -> u32 {
    outl(CONFIG_ADDRESS, addr.config_address(offset));
    inl(CONFIG_DATA)
}

/// Read a 16-bit value at any 2-byte-aligned offset.
pub fn read_config_u16(addr: PciAddr, offset: u8) -> u16 {
    let dword = read_config_u32(addr, offset & 0xFC);
    let shift = (offset & 0x02) * 8;
    (dword >> shift) as u16
}

/// Read an 8-bit value at any byte offset.
pub fn read_config_u8(addr: PciAddr, offset: u8) -> u8 {
    let dword = read_config_u32(addr, offset & 0xFC);
    let shift = (offset & 0x03) * 8;
    (dword >> shift) as u8
}

/// One discovered PCI function.
pub struct PciDevice {
    pub addr: PciAddr,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
}

impl PciDevice {
    pub fn is_multi_function(&self) -> bool {
        self.header_type & 0x80 != 0
    }

    pub fn header_layout(&self) -> u8 {
        self.header_type & 0x7F
    }
}

/// Probe a single (bus, device, function). Returns None if the slot is
/// empty (vendor id reads back as 0xFFFF).
pub fn probe(addr: PciAddr) -> Option<PciDevice> {
    let vd = read_config_u32(addr, REG_VENDOR_DEVICE);
    let vendor = vd as u16;
    if vendor == 0xFFFF {
        return None;
    }
    let device = (vd >> 16) as u16;
    let rc = read_config_u32(addr, REG_REVISION_CLASS);
    let prog_if = (rc >> 8) as u8;
    let subclass = (rc >> 16) as u8;
    let class = (rc >> 24) as u8;
    let header_type = read_config_u8(addr, REG_HEADER_TYPE);
    Some(PciDevice { addr, vendor, device, class, subclass, prog_if, header_type })
}

/// Walk bus 0 and log every present function via debugcon.
pub fn enumerate_and_log() {
    crate::println!("PCI bus 0:");
    for device in 0..32u8 {
        let base = PciAddr::new(0, device, 0);
        let Some(dev0) = probe(base) else { continue };
        log_device(&dev0);
        if dev0.is_multi_function() {
            for function in 1..8u8 {
                let faddr = PciAddr::new(0, device, function);
                if let Some(dev) = probe(faddr) {
                    log_device(&dev);
                }
            }
        }
    }
}

fn log_device(d: &PciDevice) {
    crate::println!(
        "  {:02x}:{:02x}.{}  {:04x}:{:04x}  class {:02x}.{:02x}.{:02x}  {}",
        d.addr.bus, d.addr.device, d.addr.function,
        d.vendor, d.device,
        d.class, d.subclass, d.prog_if,
        class_desc(d.class, d.subclass, d.vendor, d.device),
    );
    if let Some(v) = crate::kernel::virtio::try_attach(d) {
        crate::kernel::virtio::log_device(&v);
    }
}

/// Human-readable hint for the (class, subclass) pair. Falls through to
/// "?" when unknown; we only special-case the things we expect to meet.
/// Vendor/device override for a couple of devices that don't carry an
/// informative class (virtio devices report generic codes; the device id
/// 0x1009-0x103F is the giveaway).
/// One PCI Base Address Register decoded.
#[derive(Clone, Copy, Debug)]
pub enum Bar {
    /// 32-bit memory BAR.
    Mem32 { base: u32, prefetchable: bool },
    /// 64-bit memory BAR (consumes two consecutive BAR slots).
    Mem64 { base: u64, prefetchable: bool },
    /// I/O-port BAR.
    Io { port: u16 },
}

/// Read BAR `index` (0..=5). Returns the decoded BAR and the number of
/// BAR slots it occupies (1 for 32-bit/IO, 2 for 64-bit). Returns None
/// if the slot is empty (BAR reads as 0) or out of range.
pub fn read_bar(addr: PciAddr, index: u8) -> Option<(Bar, u8)> {
    if index >= 6 {
        return None;
    }
    let off = REG_BAR0 + index * 4;
    let lo = read_config_u32(addr, off);
    if lo == 0 {
        return None;
    }
    if lo & 1 != 0 {
        Some((Bar::Io { port: (lo & !0x3) as u16 }, 1))
    } else {
        let prefetchable = lo & 0x08 != 0;
        let bar_type = (lo >> 1) & 0x03;
        let base_lo = (lo & !0xF) as u64;
        if bar_type == 0x02 {
            if index >= 5 {
                return None;
            }
            let hi = read_config_u32(addr, off + 4) as u64;
            Some((Bar::Mem64 { base: (hi << 32) | base_lo, prefetchable }, 2))
        } else {
            Some((Bar::Mem32 { base: base_lo as u32, prefetchable }, 1))
        }
    }
}

/// Iterator over the entries of a PCI device's capability list. Yields
/// each capability's byte offset in configuration space. Caller reads
/// the cap header (id, next, ...) at that offset.
pub struct CapIter {
    addr: PciAddr,
    next: u8,
}

impl Iterator for CapIter {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        if self.next == 0 {
            return None;
        }
        let here = self.next;
        // Next-pointer lives in byte 1 of every cap header; mask the low
        // 2 bits per spec (cap entries are dword-aligned).
        self.next = read_config_u8(self.addr, here + 1) & 0xFC;
        Some(here)
    }
}

/// Walk the capability list, if present. Returns an empty iterator if
/// the device has no capabilities (status bit 4 clear).
pub fn capabilities(addr: PciAddr) -> CapIter {
    let status = read_config_u16(addr, REG_STATUS);
    let next = if status & STATUS_CAP_LIST != 0 {
        read_config_u8(addr, REG_CAP_POINTER) & 0xFC
    } else {
        0
    };
    CapIter { addr, next }
}

fn class_desc(class: u8, subclass: u8, vendor: u16, device: u16) -> &'static str {
    // Virtio: vendor 0x1AF4. Legacy device IDs 0x1000-0x103F encode the
    // subsystem; transitional/modern use the same vendor with 0x1040+.
    if vendor == 0x1AF4 {
        return match device {
            0x1000 | 0x1041 => "virtio-net",
            0x1001 | 0x1042 => "virtio-blk",
            0x1003 | 0x1043 => "virtio-console",
            0x1005 | 0x1045 => "virtio-rng",
            0x1009 | 0x1049 => "virtio-9p",
            0x1059 => "virtio-sound",
            _ => "virtio (unknown)",
        };
    }
    match (class, subclass) {
        (0x00, _) => "unclassified",
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, _) => "mass storage",
        (0x02, 0x00) => "Ethernet",
        (0x02, _) => "network",
        (0x03, 0x00) => "VGA controller",
        (0x03, _) => "display",
        (0x04, 0x01) => "audio (multimedia)",
        (0x04, 0x03) => "HD audio",
        (0x04, _) => "multimedia",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "bridge",
        (0x0C, 0x03) => "USB controller",
        (0x0C, _) => "serial bus",
        _ => "?",
    }
}
