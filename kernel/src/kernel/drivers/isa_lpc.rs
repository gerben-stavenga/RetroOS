//! Opt-in dISAppointment LPC-to-ISA setup, adapted from rasteri's sapphisa.c:
//! https://github.com/rasteri/dISAppointment/blob/main/software/sapphisa.c
//! SPDX-License-Identifier: CC-BY-SA-4.0
//! This adaptation adds chipset gating, register verification and rollback,
//! and uses an 8237 reset that preserves the kernel's PIC configuration.
//! See THIRD_PARTY_LICENSES.md for attribution and license details.

use crate::kernel::pci;

trait Io {
    fn pci_read(&mut self, offset: u8) -> u32;
    fn pci_write(&mut self, offset: u8, value: u32);
    fn input(&mut self, port: u16) -> u8;
    fn out(&mut self, port: u16, value: u8);
}
struct Hardware<'a, A>(&'a mut A);
impl<A: crate::Arch> Io for Hardware<'_, A> {
    fn pci_read(&mut self, offset: u8) -> u32 { pci::read32(self.0, 0, 31, 0, offset) }
    fn pci_write(&mut self, offset: u8, value: u32) { pci::write32(self.0, 0, 31, 0, offset, value); }
    fn input(&mut self, port: u16) -> u8 { self.0.inb(port) }
    fn out(&mut self, port: u16, value: u8) { self.0.outb(port, value); }
}

// Explicit desktop Intel 6/7-series IDs, not a vendor-only or numeric-range
// match. Register layout: D31:F0 IO_EN at 82h, GENx_DEC at 84h..90h.
// Cross-reference coreboot src/southbridge/intel/bd82x6x and
// src/include/device/pci_ids.h. Other generations need separate validation.
fn supported(id: u32, class: u32) -> bool {
    id as u16 == 0x8086 && class >> 16 == 0x0601 && matches!(id >> 16,
        0x1C44 | 0x1C46 | 0x1C4A | 0x1C4C |
        0x1E44 | 0x1E45 | 0x1E46 | 0x1E47 | 0x1E48 | 0x1E49 | 0x1E4A)
}

// sapphisa defaults: SB/PnP address, MPU, OPL, PnP write-data.
const RANGES: [(u16, u8, u8); 4] = [
    (0x200, 0xFC, 0x20), (0x300, 0x70, 0x23),
    (0x388, 0x1C, 0x30), (0xA00, 0xFC, 0x33),
];
const BRIDGE_REGS: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 5, 6, 0x50, 0x51,
];
fn read(io: &mut impl Io, reg: u8) -> u8 { io.out(0x4E, reg); io.input(0x4F) }
fn write(io: &mut impl Io, reg: u8, value: u8) { io.out(0x4E, reg); io.out(0x4F, value); }

fn configure(io: &mut impl Io) -> &'static str {
    if !supported(io.pci_read(0), io.pci_read(8)) {
        return "skipped: unsupported LPC chipset (requires listed Intel 6/7-series)";
    }
    let enable = io.pci_read(0x80);
    io.pci_write(0x80, enable | 0x2000_0000); // forward 4E/4F for identification
    if io.pci_read(0x80) != enable | 0x2000_0000 {
        io.pci_write(0x80, enable);
        return "skipped: LPC configuration-port decode is locked";
    }
    io.out(0x4E, 0x26); io.out(0x4E, 0x26);
    let id = u32::from_be_bytes([read(io, 0x5A), read(io, 0x5B), read(io, 0x5D), read(io, 0x5E)]);
    if id != 0x0305_1934 {
        io.pci_write(0x80, enable);
        return "skipped: Fintek F85226 not found at 4E/4F";
    }
    let old_pci = core::array::from_fn::<_, 4, _>(|i| io.pci_read(0x84 + i as u8 * 4));
    let old_bridge = BRIDGE_REGS.map(|r| read(io, r));
    let mut good = true;
    for (i, &(base, mask, reg)) in RANGES.iter().enumerate() {
        let encoded = u32::from(base) | (u32::from(mask) << 16) | 1;
        io.pci_write(0x84 + i as u8 * 4, encoded);
        good &= io.pci_read(0x84 + i as u8 * 4) == encoded;
        for (r, v) in [(reg + 1, base as u8), (reg + 2, (base >> 8) as u8), (reg, mask | 3)] {
            write(io, r, v); good &= read(io, r) == v;
        }
    }
    // A17..19, 8MHz ISA clock and wait states, clock output, no power saving.
    for (r, v) in [(5, 0x0E), (6, 0x5D), (0x50, 0), (0x51, 0)] {
        write(io, r, v); good &= read(io, r) == v;
    }
    if !good {
        for (&r, &v) in BRIDGE_REGS.iter().zip(&old_bridge) { write(io, r, v); }
        for (i, &v) in old_pci.iter().enumerate() { io.pci_write(0x84 + i as u8 * 4, v); }
        io.pci_write(0x80, enable);
        return "failed register readback; restored previous LPC/bridge settings";
    }
    // Reset the two 8237s while all channels are masked; enable only the
    // secondary's cascade channel. SB programs/unmasks its own DMA later.
    // Do NOT copy sapphisa's out(21h, 0): that unmasks the kernel's PIC IRQs.
    io.out(0x0D, 0); io.out(0xDA, 0);
    io.out(0x08, 0); io.out(0xD0, 0);
    for port in [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A] { io.out(port, 0); }
    io.out(0xD6, 0xC0); // channel 4 cascade mode
    io.out(0xD4, 0); // unmask cascade, leave device channels masked
    "configured Intel LPC + Fintek F85226; ISA DMA initialized"
}

pub fn setup<A: crate::Arch>(machine: &mut A) {
    let result = configure(&mut Hardware(machine));
    crate::compact_println!("ISA LPC: dISAppointment: {}", result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    struct Fake { pci: [u32; 64], bridge: [u8; 256], index: u8, writes: Vec<(u16, u32)>, locked: bool }
    impl Fake {
        fn new() -> Self {
            let mut f = Self { pci: [0; 64], bridge: [0; 256], index: 0, writes: Vec::new(), locked: false };
            f.pci[0] = 0x1E44_8086; f.pci[2] = 0x0601_0000;
            for (r, v) in [(0x5A, 3), (0x5B, 5), (0x5D, 0x19), (0x5E, 0x34)] { f.bridge[r] = v; }
            f
        }
    }
    impl Io for Fake {
        fn pci_read(&mut self, r: u8) -> u32 { self.pci[r as usize / 4] }
        fn pci_write(&mut self, r: u8, v: u32) {
            self.writes.push((0x1000 + u16::from(r), v));
            if !(self.locked && r == 0x84) { self.pci[r as usize / 4] = v; }
        }
        fn input(&mut self, _: u16) -> u8 { self.bridge[self.index as usize] }
        fn out(&mut self, p: u16, v: u8) {
            self.writes.push((p, u32::from(v)));
            if p == 0x4E { self.index = v; }
            if p == 0x4F { self.bridge[self.index as usize] = v; }
        }
    }
    #[test]
    fn rejects_unknown_chipsets_without_writes() {
        for id in [0xFFFF_FFFF, 0x1E44_1022, 0x1234_8086] {
            let mut f = Fake::new(); f.pci[0] = id;
            assert!(configure(&mut f).starts_with("skipped")); assert!(f.writes.is_empty());
        }
    }
    #[test]
    fn missing_bridge_restores_config_decode() {
        let mut f = Fake::new(); f.bridge[0x5A] = 0xFF; f.pci[32] = 0x123;
        assert!(configure(&mut f).starts_with("skipped")); assert_eq!(f.pci[32], 0x123);
        assert!(!f.writes.iter().any(|&(p, _)| p == 0x4F || p == 0x0D));
    }
    #[test]
    fn locked_range_rolls_back_without_dma_reset() {
        let mut f = Fake::new(); f.locked = true;
        let before = (f.pci, f.bridge);
        assert!(configure(&mut f).starts_with("failed"));
        assert_eq!((f.pci, f.bridge), before);
        assert!(!f.writes.iter().any(|&(p, _)| p == 0x0D));
    }
    #[test]
    fn success_preserves_pic_and_enables_dma_cascade() {
        let mut f = Fake::new();
        assert!(configure(&mut f).starts_with("configured"));
        assert_eq!(f.pci[0x84 / 4], 0x00FC_0201);
        assert!(f.writes.contains(&(0xD6, 0xC0)));
        assert!(!f.writes.iter().any(|&(p, _)| p == 0x21 || p == 0xA1));
    }
}
