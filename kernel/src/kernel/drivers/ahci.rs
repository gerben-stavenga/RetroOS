//! Polled AHCI transport for the shared storage engine. One non-NCQ command
//! slot per SATA disk; 512-byte logical sectors and LBA48 are required.
//!
//! Register and command layouts: Intel AHCI 1.3.1, sections 3.3 and 4.2.
//! https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};
use super::dma::{Mmio, Region};
use super::storage::{Buffer, Command, Error, Hardware, Operation, Storage};
use crate::kernel::pci;

const PORT_BASE: usize = 0x100;
const PORT_SIZE: usize = 0x80;
const CLB: usize = 0;
const FB: usize = 0x08;
const IS: usize = 0x10;
const IE: usize = 0x14;
const CMD: usize = 0x18;
const TFD: usize = 0x20;
const SIG: usize = 0x24;
const SSTS: usize = 0x28;
const SERR: usize = 0x30;
const CI: usize = 0x38;
const ST: u32 = 1;
const FRE: u32 = 1 << 4;
const FR: u32 = 1 << 14;
const CR: u32 = 1 << 15;
const ERROR_BITS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27) | (1 << 24);
const TABLE: usize = 0x500;
const BOUNCE: usize = 0x1000;
const BOUNCE_PAGES: usize = 16;
const POLLS: usize = 10_000_000;

pub struct Ahci { regs: Mmio, port: usize, dma: Region }
pub type AhciDisk = Storage<Ahci>;

impl Ahci {
    fn read(&self, off: usize) -> u32 { self.regs.read(self.port + off) }
    fn write(&self, off: usize, value: u32) { self.regs.write(self.port + off, value); }
    fn wait_clear(&self, off: usize, bits: u32) -> Result<(), Error> {
        for _ in 0..POLLS {
            if self.read(off) & bits == 0 { return Ok(()); }
            core::hint::spin_loop();
        }
        Err(Error::Timeout)
    }

    fn issue(&mut self, opcode: u8, write: bool, lba: u64, sectors: u32, data: Option<u64>) -> Result<(), Error> {
        self.wait_clear(TFD, 0x88)?;
        self.wait_clear(CI, u32::MAX)?;
        // All descriptors are private to this port; slot zero is idle here.
        let header = unsafe { core::slice::from_raw_parts_mut(self.dma.va as *mut u32, 8) };
        let words = unsafe { core::slice::from_raw_parts_mut((self.dma.va + TABLE) as *mut u32, 0x100 / 4) };
        // Never borrow the received-FIS region: the HBA can update it even
        // while the command slot is idle.
        header.fill(0);
        words.fill(0);
        header[0] = 5 | if write { 1 << 6 } else { 0 }
            | if data.is_some() { 1 << 16 } else { 0 }; // CFL, W, PRDTL
        let table_phys = self.dma.phys + TABLE as u64;
        header[2] = table_phys as u32;
        header[3] = (table_phys >> 32) as u32;
        let fis = command_fis(opcode, lba, sectors);
        for (word, bytes) in words.iter_mut().zip(fis.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        if let Some(phys) = data {
            let prdt = 0x80 / 4;
            words[prdt] = phys as u32;
            words[prdt + 1] = (phys >> 32) as u32;
            words[prdt + 3] = sectors * 512 - 1;
        }
        self.write(SERR, u32::MAX);
        self.write(IS, u32::MAX);
        fence(Ordering::SeqCst);
        self.write(CI, 1);
        for _ in 0..POLLS {
            let status = self.read(IS);
            if status & ERROR_BITS != 0 { return Err(Error::Device((status >> 16) as u16)); }
            if self.read(CI) & 1 == 0 {
                fence(Ordering::SeqCst);
                return if self.read(TFD) & 0x21 == 0 { Ok(()) }
                    else { Err(Error::Device(self.read(TFD) as u16)) };
            }
            core::hint::spin_loop();
        }
        // The engine retains all DMA memory and refuses later submissions.
        Err(Error::Timeout)
    }
}

fn command_fis(opcode: u8, lba: u64, sectors: u32) -> [u8; 20] {
    let mut fis = [0; 20];
    fis[0] = 0x27; // Register H2D FIS
    fis[1] = 0x80; // command, not control
    fis[2] = opcode;
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    fis[7] = 0x40; // LBA
    fis[8] = (lba >> 24) as u8;
    fis[9] = (lba >> 32) as u8;
    fis[10] = (lba >> 40) as u8;
    fis[12] = sectors as u8;
    fis[13] = (sectors >> 8) as u8;
    fis
}

impl Hardware for Ahci {
    fn execute(&mut self, c: Command, buffer: &mut Buffer) -> Result<(), Error> {
        let opcode = match c.operation {
            Operation::Read => 0x25, // READ DMA EXT
            Operation::Write => 0x35, // WRITE DMA EXT
            Operation::Flush => 0xea, // FLUSH CACHE EXT
        };
        self.issue(opcode, c.operation == Operation::Write, c.lba, c.sectors,
            if c.operation == Operation::Flush { None } else { buffer.physical_address() })
    }
}

/// Probe the first AHCI controller and every directly attached SATA disk.
/// ATAPI and port multipliers are not exposed as block disks.
pub fn probe<A: crate::Arch>(machine: &mut A) -> Vec<AhciDisk> {
    let mut disks = Vec::new();
    let Some((bus, dev, func)) = pci::find_class(machine, 1, 6) else { return disks };
    if (pci::read32(machine, bus, dev, func, 8) >> 8) as u8 != 1 { return disks; }
    let bar = pci::read32(machine, bus, dev, func, 0x24);
    if bar & 1 != 0 || bar & 0xfffffff0 == 0 { return disks; }
    let command = pci::read32(machine, bus, dev, func, 4);
    pci::write32(machine, bus, dev, func, 4, (command & 0xffff) | 6);
    let Some(regs) = Mmio::map(machine, (bar & 0xfffffff0) as u64, 0x1100) else { return disks };
    // BIOS/OS handoff before changing any port's DMA addresses.
    if regs.read(0x24) & 1 != 0 {
        regs.write(0x28, regs.read(0x28) | 2);
        let mut released = false;
        for _ in 0..POLLS {
            if regs.read(0x28) & 0x11 == 0 { released = true; break; }
            core::hint::spin_loop();
        }
        if !released { return disks; }
    }
    regs.write(4, (regs.read(4) | (1 << 31)) & !2); // AHCI enable, polled interrupts
    let ports = regs.read(0x0c);
    let address_bits = if regs.read(0) & (1 << 31) != 0 { 64 } else { 32 };
    for index in 0..32 {
        if ports & (1 << index) == 0 { continue; }
        let port = PORT_BASE + index * PORT_SIZE;
        if regs.read(port + SSTS) & 0xf0f != 0x103 { continue; }
        // Stop both command and FIS reception engines before rebinding DMA.
        regs.write(port + CMD, regs.read(port + CMD) & !ST);
        let stopped = |bits| (0..POLLS).any(|_| regs.read(port + CMD) & bits == 0);
        if !stopped(CR) { continue; }
        regs.write(port + CMD, regs.read(port + CMD) & !FRE);
        if !stopped(FR) { continue; }
        let Some(dma) = Region::allocate(machine, 1 + BOUNCE_PAGES, address_bits) else { continue };
        regs.write64(port + CLB, dma.phys);
        regs.write64(port + FB, dma.phys + 0x400);
        regs.write(port + IE, 0);
        regs.write(port + SERR, u32::MAX);
        regs.write(port + IS, u32::MAX);
        regs.write(port + CMD, regs.read(port + CMD) | FRE);
        // Firmware need not have used this port. Its device signature is
        // unavailable until the initial device-to-host FIS has been received.
        // Supply our receive buffer and enable reception before classifying it.
        let identified = (0..POLLS).any(|_| {
            let signature = regs.read(port + SIG);
            signature != u32::MAX && signature != 0
        });
        if !identified || regs.read(port + SIG) != 0x101 { continue; }
        regs.write(port + CMD, regs.read(port + CMD) | ST);
        let mut controller = Ahci { regs, port, dma };
        // IDENTIFY uses the same port command machinery and transfer buffer.
        let phys = controller.dma.phys + BOUNCE as u64;
        if controller.issue(0xec, false, 0, 1, Some(phys)).is_err() { continue; }
        let words = unsafe { core::slice::from_raw_parts((controller.dma.va + BOUNCE) as *const u16, 256) };
        if words[83] & (1 << 10) == 0 { continue; }
        // Word 106 is valid only with bit14=1, bit15=0. Bit12 means a logical
        // sector larger than 256 words, which this 512-byte block API rejects.
        if words[106] & 0xc000 == 0x4000 && words[106] & (1 << 12) != 0 { continue; }
        let sectors = (0..4).fold(0u64, |n, i| n | ((words[100 + i] as u64) << (i * 16)));
        if sectors == 0 || sectors > 1 << 48 { continue; }
        let name = alloc::format!("ahci0p{index}");
        let buffer = unsafe { controller.dma.buffer(BOUNCE, BOUNCE_PAGES * crate::PAGE_SIZE) };
        disks.push(Storage::new(controller, buffer, sectors, &name));
    }
    disks
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_high_lba_and_sector_count_in_register_fis() {
        assert_eq!(command_fis(0x35, 0x123456789abc, 0x1234),
            [0x27, 0x80, 0x35, 0, 0xbc, 0x9a, 0x78, 0x40,
             0x56, 0x34, 0x12, 0, 0x34, 0x12, 0, 0, 0, 0, 0, 0]);
    }
}
