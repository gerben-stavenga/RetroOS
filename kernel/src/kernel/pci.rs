//! PCI configuration-space access (mechanism #1: ports 0xCF8/0xCFC).
//!
//! Shared by the PCI device drivers (AC'97, NVMe). On a backend with no PCI
//! (the interpreter) every config read returns 0xFFFFFFFF, so probes find
//! nothing and callers fall back — the same "absent bus reads all-ones"
//! convention as ISA.

use arch_abi::Arch;

const PCI_CFG_ADDR: u16 = 0xCF8;
const PCI_CFG_DATA: u16 = 0xCFC;

fn cfg_addr(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}

pub fn read32(arch: &mut crate::TheArch, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    arch.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    arch.inl(PCI_CFG_DATA)
}

pub fn write32(arch: &mut crate::TheArch, bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    arch.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    arch.outl(PCI_CFG_DATA, val);
}

/// Find the first device matching `(class, subclass)` on buses 0-3.
/// Returns `(bus, dev)`.
pub fn find_class(arch: &mut crate::TheArch, class: u8, subclass: u8) -> Option<(u8, u8)> {
    for bus in 0..4u8 {
        for dev in 0..32u8 {
            let id = read32(arch, bus, dev, 0, 0x00);
            if id & 0xFFFF == 0xFFFF {
                continue; // empty slot
            }
            let classes = read32(arch, bus, dev, 0, 0x08);
            if (classes >> 24) as u8 == class && (classes >> 16) as u8 == subclass {
                return Some((bus, dev));
            }
        }
    }
    None
}
