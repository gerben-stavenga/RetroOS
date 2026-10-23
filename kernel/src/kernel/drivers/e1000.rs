//! Intel 82540EM / 82574L Ethernet: common legacy DMA rings, polling, no offloads.
//! Controller-specific reset/NVM/link setup is separate from packet ownership.
//! References: Intel 8254x Software Developer's Manual and 82574 datasheet;
//! https://github.com/qemu/qemu/blob/master/hw/net/e1000x_regs.h
//! https://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf

use super::dma::{Mmio, Region};
use crate::kernel::{net::EthernetDevice, pci, portio};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

mod controller;
use controller::{Controller, Hardware};

const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EERD: usize = 0x0014;
const MDIC: usize = 0x0020;
const ICR: usize = 0x00c0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const TDBAL: usize = 0x3800;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const MTA: usize = 0x5200;
const RAL: usize = 0x5400;
const RAH: usize = 0x5404;
const BAR_BYTES: usize = 0x20000;
const DEPTH: usize = 64;
const DESCRIPTOR: usize = 16;
const BUFFER: usize = 2048;
const PACKETS: usize = crate::PAGE_SIZE;
const DD: u8 = 1;
const EOP: u8 = 2;
const FRAME_ERRORS: u8 = 0x97; // CE, SE, SEQ, CXE, RXE; checksums belong to IPv4.

struct Ring {
    va: usize,
    phys: u64,
}
impl Ring {
    fn allocate<A: crate::Arch>(machine: &mut A) -> Option<Self> {
        let memory = Region::allocate(
            machine,
            (PACKETS + DEPTH * BUFFER).div_ceil(crate::PAGE_SIZE),
            64,
        )?;
        Some(Self {
            va: memory.va,
            phys: memory.phys,
        })
    }
    fn descriptor(&self, index: usize) -> usize {
        self.va + index * DESCRIPTOR
    }
    fn packet(&self, index: usize) -> usize {
        self.va + PACKETS + index * BUFFER
    }
    fn read8(&self, index: usize, offset: usize) -> u8 {
        unsafe { core::ptr::read_volatile((self.descriptor(index) + offset) as *const u8) }
    }
    fn read16(&self, index: usize, offset: usize) -> u16 {
        unsafe { core::ptr::read_volatile((self.descriptor(index) + offset) as *const u16) }
    }
    fn write8(&self, index: usize, offset: usize, value: u8) {
        unsafe {
            core::ptr::write_volatile((self.descriptor(index) + offset) as *mut u8, value);
        }
    }
    fn write16(&self, index: usize, offset: usize, value: u16) {
        unsafe {
            core::ptr::write_volatile((self.descriptor(index) + offset) as *mut u16, value);
        }
    }
    fn write32(&self, index: usize, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.descriptor(index) + offset) as *mut u32, value);
        }
    }
    fn initialize(&self, receive: bool) {
        for index in 0..DEPTH {
            let physical = self.phys + PACKETS as u64 + (index * BUFFER) as u64;
            self.write32(index, 0, physical as u32);
            self.write32(index, 4, (physical >> 32) as u32);
            self.write32(index, 8, 0);
            self.write32(index, 12, if receive { 0 } else { DD as u32 });
        }
    }
}

pub struct IntelEthernet {
    registers: Mmio,
    rx: Ring,
    tx: Ring,
    mac: [u8; 6],
    rx_next: usize,
    rx_discard: bool,
    tx_next: usize,
    tx_clean: usize,
    tx_pending: usize,
}
impl IntelEthernet {
    fn bring_up<A: crate::Arch>(
        machine: &mut A,
        address: (u8, u8, u8),
        controller: &'static Controller,
    ) -> Option<Self> {
        let (b, d, f) = address;
        let low = pci::read32(machine, b, d, f, 0x10);
        if low & 1 != 0 || !matches!(low & 6, 0 | 4) {
            return None;
        }
        let high = if low & 6 == 4 {
            pci::read32(machine, b, d, f, 0x14)
        } else {
            0
        };
        let base = u64::from(low & !15) | (u64::from(high) << 32);
        if base == 0 || base.checked_add(BAR_BYTES as u64).is_none() {
            return None;
        }
        let command = pci::read32(machine, b, d, f, 4) & 0xffff;
        // Enable MMIO, suppress INTx and stop firmware DMA before resetting.
        let disabled = (command | 2 | (1 << 10)) & !4;
        pci::write32(machine, b, d, f, 4, disabled);
        let registers = Mmio::map(machine, base, BAR_BYTES)?;
        let hardware = Hardware {
            registers,
            controller,
        };
        let result = (|| {
            hardware.reset()?;
            let mac = hardware.mac_address()?;
            hardware.setup_link()?;
            let rx = Ring::allocate(machine)?;
            let tx = Ring::allocate(machine)?;
            rx.initialize(true);
            tx.initialize(false);
            // One untagged frame per legacy descriptor. No checksum offload,
            // multicast hash entries, RSS, jumbo frames or packet splitting.
            registers.write(RAL, u32::from_le_bytes(mac[..4].try_into().unwrap()));
            registers.write(
                RAH,
                u16::from_le_bytes(mac[4..].try_into().unwrap()) as u32 | (1 << 31),
            );
            for index in 1..16 {
                registers.write(RAL + index * 8, 0);
                registers.write(RAH + index * 8, 0);
            }
            for index in 0..128 {
                registers.write(MTA + index * 4, 0);
            }
            hardware.configure();
            registers.write64(RDBAL, rx.phys);
            registers.write(RDLEN, (DEPTH * DESCRIPTOR) as u32);
            registers.write(RDH, 0);
            registers.write(RDT, (DEPTH - 1) as u32);
            registers.write64(TDBAL, tx.phys);
            registers.write(TDLEN, (DEPTH * DESCRIPTOR) as u32);
            registers.write(TDH, 0);
            registers.write(TDT, 0);
            registers.write(TIPG, 10 | (8 << 10) | (6 << 20));
            fence(Ordering::SeqCst);
            pci::write32(machine, b, d, f, 4, disabled | 4);
            // EN | BAM | SECRC; default buffer size is 2048 bytes.
            registers.write(RCTL, (1 << 1) | (1 << 15) | (1 << 26));
            // EN | PSP | collision threshold 15 | collision distance 64.
            registers.write(TCTL, (1 << 1) | (1 << 3) | (15 << 4) | (64 << 12));
            let _ = registers.read(STATUS); // Flush posted MMIO writes.
            Some(Self {
                registers,
                rx,
                tx,
                mac,
                rx_next: 0,
                rx_discard: false,
                tx_next: 0,
                tx_clean: 0,
                tx_pending: 0,
            })
        })();
        if result.is_none() {
            registers.write(IMC, u32::MAX);
            registers.write(RCTL, 0);
            registers.write(TCTL, 0);
            let _ = registers.read(STATUS);
            pci::write32(machine, b, d, f, 4, disabled);
        }
        result
    }
    fn reclaim_tx(&mut self) {
        while self.tx_pending != 0 && self.tx.read8(self.tx_clean, 12) & DD != 0 {
            fence(Ordering::Acquire);
            self.tx_clean = (self.tx_clean + 1) % DEPTH;
            self.tx_pending -= 1;
        }
    }
}
impl EthernetDevice for IntelEthernet {
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        for _ in 0..DEPTH {
            let index = self.rx_next;
            let status = self.rx.read8(index, 12);
            if status & DD == 0 {
                return None;
            }
            fence(Ordering::Acquire);
            let length = self.rx.read16(index, 8) as usize;
            let errors = self.rx.read8(index, 13);
            let packet = if !self.rx_discard
                && status & EOP != 0
                && errors & FRAME_ERRORS == 0
                && (14..=1514).contains(&length)
            {
                Some(
                    unsafe {
                        core::slice::from_raw_parts(self.rx.packet(index) as *const u8, length)
                    }
                    .to_vec(),
                )
            } else {
                None
            };
            // Never expose a tail fragment as a separate Ethernet packet.
            self.rx_discard = status & EOP == 0;
            self.rx.write32(index, 8, 0);
            self.rx.write32(index, 12, 0);
            fence(Ordering::SeqCst);
            self.registers.write(RDT, index as u32);
            self.rx_next = (index + 1) % DEPTH;
            if packet.is_some() {
                return packet;
            }
        }
        None
    }
    fn can_transmit(&mut self) -> bool {
        self.reclaim_tx();
        let status = self.registers.read(STATUS);
        status != u32::MAX && status & 2 != 0 && self.tx_pending < DEPTH - 1
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        if !(14..=1514).contains(&frame.len()) || !self.can_transmit() {
            return false;
        }
        let index = self.tx_next;
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                self.tx.packet(index) as *mut u8,
                frame.len(),
            );
        }
        self.tx.write16(index, 8, frame.len() as u16);
        self.tx.write8(index, 10, 0);
        self.tx.write8(index, 11, 0x0b); // EOP | IFCS | RS, legacy format.
        self.tx.write32(index, 12, 0);
        fence(Ordering::SeqCst);
        self.tx_next = (index + 1) % DEPTH;
        self.tx_pending += 1;
        self.registers.write(TDT, self.tx_next as u32);
        true
    }
}
pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<IntelEthernet> {
    for address @ (b, d, f) in pci::find_classes(machine, 2, 0) {
        let id = pci::read32(machine, b, d, f, 0);
        let Some(controller) = Controller::identify(id) else {
            continue;
        };
        if let Some(nic) = IntelEthernet::bring_up(machine, address, controller) {
            let mac = nic.mac;
            crate::compact_println!(
                "intel-net: {} ready at {:02x}:{:02x}.{} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                controller.name,
                b,
                d,
                f,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            return Some(nic);
        }
        crate::compact_println!(
            "intel-net: {} initialization failed at {:02x}:{:02x}.{}",
            controller.name,
            b,
            d,
            f
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u64>, Vec<u64>, Vec<u32>, IntelEthernet) {
        let mut rx = alloc::vec![0u64; (PACKETS+DEPTH*BUFFER)/8];
        let mut tx = alloc::vec![0u64; (PACKETS+DEPTH*BUFFER)/8];
        let mut regs = alloc::vec![0u32; BAR_BYTES/4];
        regs[STATUS / 4] = 2;
        let registers = unsafe { Mmio::test_mapping(regs.as_mut_ptr(), BAR_BYTES) };
        let rx_ring = Ring {
            va: rx.as_mut_ptr() as usize,
            phys: 0x12345000,
        };
        let tx_ring = Ring {
            va: tx.as_mut_ptr() as usize,
            phys: 0x12367000,
        };
        rx_ring.initialize(true);
        tx_ring.initialize(false);
        (
            rx,
            tx,
            regs,
            IntelEthernet {
                registers,
                rx: rx_ring,
                tx: tx_ring,
                mac: [2; 6],
                rx_next: 0,
                rx_discard: false,
                tx_next: 0,
                tx_clean: 0,
                tx_pending: 0,
            },
        )
    }
    #[test]
    fn transmit_wrap_and_dma_ownership() {
        let (_rx, _tx, registers, mut nic) = fixture();
        for round in 0..4 {
            for _ in 0..DEPTH - 1 {
                assert!(nic.transmit(&[0xa5; 1514]));
            }
            assert!(!nic.transmit(&[0x5a; 60]));
            let clean = nic.tx_clean;
            assert_eq!(nic.tx.read16(clean, 8), 1514);
            assert_eq!(nic.tx.read8(clean, 11), 0x0b);
            assert_eq!(registers[TDT / 4], nic.tx_next as u32);
            let bytes =
                unsafe { core::slice::from_raw_parts(nic.tx.packet(clean) as *const u8, 1514) };
            assert!(bytes.iter().all(|b| *b == 0xa5));
            // A later completion cannot release an earlier owned descriptor.
            nic.tx.write8((clean + 1) % DEPTH, 12, DD);
            assert!(!nic.can_transmit());
            for offset in 0..DEPTH - 1 {
                nic.tx.write8((clean + offset) % DEPTH, 12, DD);
            }
            assert!(nic.can_transmit());
            assert_eq!(nic.tx_pending, 0);
            assert_eq!(nic.tx_next, ((round + 1) * (DEPTH - 1)) % DEPTH);
        }
        assert!(!nic.transmit(&[0; 1515]));
        assert!(!nic.transmit(&[0; 13]));
    }
    #[test]
    fn receive_bounds_errors_and_fragmented_frames() {
        let (_rx, _tx, registers, mut nic) = fixture();
        for index in 0..DEPTH {
            unsafe {
                core::ptr::write_bytes(nic.rx.packet(index) as *mut u8, index as u8, 60);
            }
            nic.rx.write16(index, 8, 60);
            nic.rx.write8(index, 12, DD | EOP);
        }
        nic.rx.write16(0, 8, 65535); // Device length must never index past DMA.
        nic.rx.write8(1, 13, 0x80);
        nic.rx.write8(2, 12, DD); // Missing EOP starts a discarded fragment chain.
        assert_eq!(nic.receive(), Some(alloc::vec![4;60]));
        assert_eq!(registers[RDT / 4], 4);
        for index in 5..DEPTH {
            assert_eq!(nic.receive(), Some(alloc::vec![index as u8;60]));
        }
        assert_eq!(nic.receive(), None);
        assert_eq!(nic.rx_next, 0);
        nic.rx.write16(0, 8, 60);
        nic.rx.write8(0, 12, DD | EOP);
        assert_eq!(nic.receive(), Some(alloc::vec![0;60]));
    }
}
