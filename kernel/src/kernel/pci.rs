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

pub fn read32<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    machine.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    machine.inl(PCI_CFG_DATA)
}

pub fn write32<A: crate::Arch>(machine: &mut A, bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    machine.outl(PCI_CFG_ADDR, cfg_addr(bus, dev, func, off));
    machine.outl(PCI_CFG_DATA, val);
}

/// PCI capability IDs we care about.
const CAP_MSI: u8 = 0x05;

/// Program a device's MSI capability with `(addr, data)` (from
/// [`crate::Arch::msi_alloc`]) and enable it, so the device signals interrupts
/// by memory write instead of a wired INTx line. Returns false if the device
/// has no capability list or no MSI capability (caller falls back to INTx /
/// polling). One vector only (Multiple-Message-Enable forced to 0).
///
/// Config layout of the MSI cap at offset `c`: `c+0x00` = [msg-control:16 |
/// next:8 | id:8]; `c+0x04` = message address low; then, if the control's
/// 64-bit-capable bit (7) is set, `c+0x08` = address high and `c+0x0C` = data,
/// else `c+0x08` = data. All accesses are dword-aligned (caps are 4-byte
/// aligned), so `read32`/`write32` suffice.
pub fn msi_enable<A: crate::Arch>(
    machine: &mut A, bus: u8, dev: u8, func: u8, addr: u64, data: u32,
) -> bool {
    // Status register (high 16 of dword 0x04), bit 4 = capabilities list present.
    if read32(machine, bus, dev, func, 0x04) >> 16 & (1 << 4) == 0 {
        return false;
    }
    let mut c = (read32(machine, bus, dev, func, 0x34) & 0xFC) as u8; // cap pointer
    while c != 0 {
        let head = read32(machine, bus, dev, func, c);
        if (head & 0xFF) as u8 == CAP_MSI {
            let ctrl = (head >> 16) as u16;
            let addr64 = ctrl & (1 << 7) != 0;
            write32(machine, bus, dev, func, c + 0x04, (addr as u32) & !0x3);
            if addr64 {
                write32(machine, bus, dev, func, c + 0x08, (addr >> 32) as u32);
                write32(machine, bus, dev, func, c + 0x0C, data & 0xFFFF);
            } else {
                write32(machine, bus, dev, func, c + 0x08, data & 0xFFFF);
            }
            // Rewrite message control: force MME=0 (bits 4-6 → one vector) and
            // set MSI-Enable (bit 0), preserving the id/next byte below it.
            let new_ctrl = (ctrl & !0x0070) | 0x0001;
            write32(machine, bus, dev, func, c, (head & 0xFFFF) | ((new_ctrl as u32) << 16));
            return true;
        }
        c = ((head >> 8) & 0xFC) as u8; // next-capability pointer
    }
    false
}

/// Find the first device matching `(class, subclass)`, returning
/// `(bus, dev, func)`. Spec-conformant brute-force enumeration: all 256 buses,
/// all 32 devices, and functions 1-7 on multi-function devices.
///
/// Both matter on real hardware: a controller commonly sits behind a PCIe root
/// port on a high bus (the dev laptop's xHCI is at 65:00.3 — bus 0x65,
/// function 3), so a buses-0-3 / function-0-only scan misses it and the device
/// probes as absent. Empty slots read all-ones (0xFFFF vendor id).
pub fn find_class<A: crate::Arch>(machine: &mut A, class: u8, subclass: u8) -> Option<(u8, u8, u8)> {
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                if read32(machine, bus, dev, func, 0x00) & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break; // function 0 absent ⇒ no device in this slot
                    }
                    continue;
                }
                let classes = read32(machine, bus, dev, func, 0x08);
                if (classes >> 24) as u8 == class && (classes >> 16) as u8 == subclass {
                    return Some((bus, dev, func));
                }
                // Probe functions 1-7 only on a multi-function device (header
                // type bit 7, at config offset 0x0C bit 23).
                if func == 0 && read32(machine, bus, dev, 0, 0x0C) & 0x0080_0000 == 0 {
                    break;
                }
            }
        }
    }
    None
}
