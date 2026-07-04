//! PCI configuration-space access (mechanism #1: ports 0xCF8/0xCFC).
//!
//! Shared by the PCI device drivers (AC'97, NVMe). On a backend with no PCI
//! (the interpreter) every config read returns 0xFFFFFFFF, so probes find
//! nothing and callers fall back — the same "absent bus reads all-ones"
//! convention as ISA.


const PCI_CFG_ADDR: u16 = 0xCF8;
const PCI_CFG_DATA: u16 = 0xCFC;

fn cfg_addr(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}

pub fn read32<A: crate::Arch>(arch: &mut A, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    arch.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    arch.inl(PCI_CFG_DATA)
}

pub fn write32<A: crate::Arch>(arch: &mut A, bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    arch.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    arch.outl(PCI_CFG_DATA, val);
}

/// Find the first device matching `(class, subclass)`, returning
/// `(bus, dev, func)`. Spec-conformant brute-force enumeration: all 256 buses,
/// all 32 devices, and functions 1-7 on multi-function devices.
///
/// Both matter on real hardware: a controller commonly sits behind a PCIe root
/// port on a high bus (the dev laptop's xHCI is at 65:00.3 — bus 0x65,
/// function 3), so a buses-0-3 / function-0-only scan misses it and the device
/// probes as absent. Empty slots read all-ones (0xFFFF vendor id).
pub fn find_class<A: crate::Arch>(arch: &mut A, class: u8, subclass: u8) -> Option<(u8, u8, u8)> {
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                if read32(arch, bus, dev, func, 0x00) & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break; // function 0 absent ⇒ no device in this slot
                    }
                    continue;
                }
                let classes = read32(arch, bus, dev, func, 0x08);
                if (classes >> 24) as u8 == class && (classes >> 16) as u8 == subclass {
                    return Some((bus, dev, func));
                }
                // Probe functions 1-7 only on a multi-function device (header
                // type bit 7, at config offset 0x0C bit 23).
                if func == 0 && read32(arch, bus, dev, 0, 0x0C) & 0x0080_0000 == 0 {
                    break;
                }
            }
        }
    }
    None
}
