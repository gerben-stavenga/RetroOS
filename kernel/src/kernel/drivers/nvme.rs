//! NVMe block driver — the storage of UEFI-class machines (modern laptops
//! have no ATA: the SSD hangs directly off PCIe).
//!
//! Minimal by design: one admin queue pair + one I/O queue pair, polled
//! completions (no MSI/interrupts), and 512-byte LBAs. I/O uses a 22-page
//! bounce buffer described by one short PRP list.
//! Writes exist for the backing-file overlay's raw-sector persistence.
//!
//! Queues and bounce memory use the shared boot-lifetime DMA allocator.

use core::mem::size_of;
use super::dma::{Mmio, Region};
use super::storage::{Buffer, Command, Error, Hardware, Operation, Storage, poll};
use crate::kernel::pci;
use lib::compact_println;

const DMA_PAGES: usize = 28;

// Offsets inside the DMA region. Queues must be page-aligned (CC.MPS=0).
const ASQ_OFF: usize = 0x0000; // admin submission queue
const ACQ_OFF: usize = 0x1000; // admin completion queue
const IOSQ_OFF: usize = 0x2000; // I/O submission queue (qid 1)
const IOCQ_OFF: usize = 0x3000; // I/O completion queue (qid 1)
const IDENT_OFF: usize = 0x4000; // identify / scratch page
const BOUNCE_OFF: usize = 0x5000;
const BOUNCE_PAGES: usize = 22;
const PRP_LIST_OFF: usize = 0x1B000;

/// Queue depth (entries). 16 fits both rings comfortably in one page each
/// (SQ entry = 64 B, CQ entry = 16 B) and we only ever have one in flight.
const DEPTH: usize = 16;

const SECTORS_PER_PAGE: u32 = (crate::PAGE_SIZE / 512) as u32;

// Controller register offsets (from BAR0).
const R_CAP_HI: usize = 0x04;
const R_CC: usize = 0x14;
const R_CSTS: usize = 0x1C;
const R_AQA: usize = 0x24;
const R_ASQ: usize = 0x28;
const R_ACQ: usize = 0x30;
const DOORBELL_BASE: usize = 0x1000;

/// One submission/completion queue pair (admin or I/O).
struct Queue {
    regs: Mmio,
    sq_va: usize,
    cq_va: usize,
    sq_db: usize, // doorbell register offsets from BAR0
    cq_db: usize,
    tail: usize,
    head: usize,
    phase: bool, // expected CQE phase bit for new entries
}

impl Queue {
    /// Submit one 16-dword command and poll its completion. Returns the NVMe
    /// status field (0 = success) or 0xFFFF on timeout.
    fn exec(&mut self, cmd: &[u32; 16]) -> u16 {
        let sqe = (self.sq_va + self.tail * 64) as *mut u32;
        for (i, &dw) in cmd.iter().enumerate() {
            unsafe { core::ptr::write_volatile(sqe.add(i), dw) };
        }
        self.tail = (self.tail + 1) % DEPTH;
        self.regs.write(self.sq_db, self.tail as u32);

        let cqe = (self.cq_va + self.head * 16) as *const u32;
        poll(|| {
            let dw3 = unsafe { core::ptr::read_volatile(cqe.add(3)) };
            if ((dw3 >> 16) & 1) == self.phase as u32 {
                let status = (dw3 >> 17) as u16;
                self.head += 1;
                if self.head == DEPTH {
                    self.head = 0;
                    self.phase = !self.phase;
                }
                self.regs.write(self.cq_db, self.head as u32);
                return Some(status);
            }
            None
        }).unwrap_or(0xFFFF)
    }
}

pub struct Nvme {
    admin: Queue,
    io: Queue,
    dma: Region,
}

/// One NVMe namespace behind the shared storage transfer engine.
pub type NvmeDisk = Storage<Nvme>;

/// A zeroed command with opcode + nsid filled in.
fn cmd(opc: u8, nsid: u32) -> [u32; 16] {
    let mut c = [0u32; 16];
    c[0] = opc as u32;
    c[1] = nsid;
    c
}

/// PRP1 lives in dwords 6-7 of the SQE.
fn set_prp1(c: &mut [u32; 16], phys: u64) {
    c[6] = phys as u32;
    c[7] = (phys >> 32) as u32;
}

fn set_data_prps(c: &mut [u32; 16], dma: &Region, buffer_phys: u64, sectors: u32) {
    set_prp1(c, buffer_phys);
    if sectors <= SECTORS_PER_PAGE {
        return;
    }
    let pages = sectors.div_ceil(SECTORS_PER_PAGE) as usize;
    let second_page = buffer_phys + crate::PAGE_SIZE as u64;
    if pages == 2 {
        c[8] = second_page as u32;
        c[9] = (second_page >> 32) as u32;
        return;
    }
    let list_phys = dma.phys + PRP_LIST_OFF as u64;
    c[8] = list_phys as u32;
    c[9] = (list_phys >> 32) as u32;
    for page in 1..pages {
        unsafe {
            core::ptr::write_volatile(
                (dma.va + PRP_LIST_OFF + (page - 1) * size_of::<u64>()) as *mut u64,
                buffer_phys + page as u64 * crate::PAGE_SIZE as u64,
            );
        }
    }
}

/// Probe PCI for an NVMe controller (class 01h / subclass 08h) and bring it
/// up. `None` when there is no controller (legacy machine, or the
/// interpreter's absent bus) — not an error, and no side effects.
fn bring_up<A: crate::Arch>(machine: &mut A) -> Option<(Nvme, u64)> {
    let Some((bus, dev, func)) = pci::find_class(machine, 0x01, 0x08) else {
        return None; // no NVMe controller (legacy machine) — not an error
    };

    // Enable memory space + bus mastering.
    let pcmd = pci::read32(machine, bus, dev, func, 0x04);
    pci::write32(machine, bus, dev, func, 0x04, (pcmd & 0xFFFF) | 0x06);

    // BAR0: a (usually 64-bit) memory BAR. OVMF places it above 4 GB — fine:
    // the kernel VA space is 32-bit but PAE/compat PTEs carry 52-bit physical
    // addresses, so `map_phys_range` reaches it. (A legacy-paging 386 would
    // truncate, but no NVMe machine is a 386.)
    let bar0 = pci::read32(machine, bus, dev, func, 0x10);
    if bar0 & 1 != 0 {
        return None; // I/O BAR — not an NVMe register set
    }
    let is_64 = (bar0 >> 1) & 3 == 2;
    let bar_hi = if is_64 { pci::read32(machine, bus, dev, func, 0x14) } else { 0 };
    let bar_phys = ((bar_hi as u64) << 32) | (bar0 & 0xFFFF_FFF0) as u64;

    let registers = Mmio::map(machine, bar_phys, DOORBELL_BASE)?;
    let stride = 4usize << (registers.read(R_CAP_HI) & 0xF);
    let regs = Mmio::map(machine, bar_phys, DOORBELL_BASE + 3 * stride + 4)?;
    let dma = Region::allocate(machine, DMA_PAGES, 64)?;
    let dma_phys = dma.phys;

    // Doorbell stride: CAP.DSTRD (bits 35:32), in units of 4 bytes.
    let db = |qid: usize, is_cq: bool| DOORBELL_BASE + (2 * qid + is_cq as usize) * stride;

    // Reset: EN=0, wait !RDY; program admin queues; EN=1, wait RDY.
    regs.write(R_CC, 0);
    if !wait_csts(regs, 0) {
        return None;
    }
    regs.write(R_AQA, ((DEPTH as u32 - 1) << 16) | (DEPTH as u32 - 1));
    regs.write64(R_ASQ, dma_phys + ASQ_OFF as u64);
    regs.write64(R_ACQ, dma_phys + ACQ_OFF as u64);
    // IOCQES=4 (16B), IOSQES=6 (64B), MPS=0 (4K), CSS=0 (NVM), EN=1.
    regs.write(R_CC, (4 << 20) | (6 << 16) | 1);
    if !wait_csts(regs, 1) {
        compact_println!("NVMe: controller did not become ready (csts={:#x})", regs.read(R_CSTS));
        return None;
    }

    let mut n = Nvme {
        admin: Queue {
            regs,
            sq_va: dma.va + ASQ_OFF, cq_va: dma.va + ACQ_OFF,
            sq_db: db(0, false), cq_db: db(0, true),
            tail: 0, head: 0, phase: true,
        },
        io: Queue {
            regs,
            sq_va: dma.va + IOSQ_OFF, cq_va: dma.va + IOCQ_OFF,
            sq_db: db(1, false), cq_db: db(1, true),
            tail: 0, head: 0, phase: true,
        },
        dma,
    };

    // Identify namespace 1 (CNS=0) — verify the LBA format is 512 bytes.
    let mut c = cmd(0x06, 1);
    set_prp1(&mut c, dma_phys + IDENT_OFF as u64);
    // cdw10 = CNS 0 (namespace data structure)
    if n.admin.exec(&c) != 0 {
        compact_println!("NVMe: IDENTIFY failed");
        return None;
    }
    let ident = n.dma.va + IDENT_OFF;
    // NSZE (bytes 0..8): namespace size in logical blocks — the capacity.
    let sectors = unsafe { core::ptr::read_volatile(ident as *const u64) };
    let flbas = unsafe { core::ptr::read_volatile((ident + 26) as *const u8) } & 0xF;
    let lbads = unsafe {
        core::ptr::read_volatile((ident + 128 + flbas as usize * 4 + 2) as *const u8)
    };
    if lbads != 9 {
        compact_println!("NVMe: unsupported LBA size 2^{} (want 512)", lbads);
        return None;
    }

    // Create the I/O completion queue (opc 05h), then submission queue (01h).
    let mut c = cmd(0x05, 0);
    set_prp1(&mut c, dma_phys + IOCQ_OFF as u64);
    c[10] = ((DEPTH as u32 - 1) << 16) | 1; // qsize | qid
    c[11] = 1; // physically contiguous, no interrupts
    if n.admin.exec(&c) != 0 {
        compact_println!("NVMe: create IO CQ failed");
        return None;
    }
    let mut c = cmd(0x01, 0);
    set_prp1(&mut c, dma_phys + IOSQ_OFF as u64);
    c[10] = ((DEPTH as u32 - 1) << 16) | 1;
    c[11] = (1 << 16) | 1; // CQID 1 | physically contiguous
    if n.admin.exec(&c) != 0 {
        compact_println!("NVMe: create IO SQ failed");
        return None;
    }

    Some((n, sectors))
}

fn wait_csts(regs: Mmio, ready: u32) -> bool {
    poll(|| {
        let csts = regs.read(R_CSTS);
        if csts & 2 != 0 {
            compact_println!("NVMe: controller fatal status");
            return Some(false);
        }
        if csts & 1 == ready { return Some(true); }
        None
    }).unwrap_or(false)
}

impl Storage<Nvme> {
    /// Probe PCI and bring up the controller's namespace 1.
    pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<Self> {
        let (n, sectors) = bring_up(machine)?;
        // SAFETY: bring_up exclusively maps this permanently resident DMA
        // region. The bounce span is disjoint from queues and the PRP list.
        let buffer = unsafe { n.dma.buffer(BOUNCE_OFF, BOUNCE_PAGES * crate::PAGE_SIZE) };
        Some(Self::new(n, buffer, sectors, "nvme0n1"))
    }
}

impl Hardware for Nvme {
    fn execute(&mut self, request: Command, buffer: &mut Buffer) -> Result<(), Error> {
        let opcode = match request.operation {
            Operation::Read => 0x02,
            Operation::Write => 0x01,
            Operation::Flush => 0x00,
        };
        let mut c = cmd(opcode, 1);
        if request.operation != Operation::Flush {
            set_data_prps(&mut c, &self.dma,
                buffer.physical_address().expect("NVMe requires DMA memory"), request.sectors);
            c[10] = request.lba as u32;
            c[11] = (request.lba >> 32) as u32;
            c[12] = request.sectors - 1;
        }
        match self.io.exec(&c) {
            0 => Ok(()),
            0xffff => Err(Error::Timeout),
            status => Err(Error::Device(status)),
        }
    }
}
