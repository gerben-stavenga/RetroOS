//! NVMe block driver — the storage of UEFI-class machines (modern laptops
//! have no ATA: the SSD hangs directly off PCIe).
//!
//! Minimal by design: one admin queue pair + one I/O queue pair, polled
//! completions (no MSI/interrupts), 512-byte LBAs, reads in 4 KB chunks
//! through a bounce buffer (single-PRP commands — no PRP lists). That is
//! everything the boot path needs (MBR scan, TAR index, ext4 reads); writes
//! come with the writable-filesystem work.
//!
//! Memory: controller registers (BAR0) and the DMA region (queues + bounce)
//! are mapped into slices of the dead low-mem identity window, following the
//! AC'97 driver's stopgap pattern — AC'97 owns `LOW_MEM_BASE+0xC0000..+0xD1000`,
//! NVMe takes `+0xE0000..+0xEC000`. See memory `project_ac97_lowmem_dma_window_todo`
//! for the proper DMA-window-pool fix that should eventually replace both.

use arch_abi::Arch;
use spin::Mutex;
use crate::kernel::pci;
use lib::println;

/// Kernel VA for the controller registers (BAR0): 4 pages is ample — the
/// doorbells for qid 0/1 sit just past offset 0x1000 even at max stride.
const REGS_VA: usize = crate::LOW_MEM_BASE + 0xE0000;
const REGS_PAGES: usize = 4;
/// Kernel VA + size of the DMA region (queues, identify, bounce).
const DMA_VA: usize = crate::LOW_MEM_BASE + 0xE4000;
const DMA_PAGES: usize = 8;
/// PTE cache-disable — required for MMIO; harmless overkill for the DMA RAM.
const PTE_CACHE_DISABLE: u64 = 1 << 4;

// Offsets inside the DMA region. Queues must be page-aligned (CC.MPS=0).
const ASQ_OFF: usize = 0x0000; // admin submission queue
const ACQ_OFF: usize = 0x1000; // admin completion queue
const IOSQ_OFF: usize = 0x2000; // I/O submission queue (qid 1)
const IOCQ_OFF: usize = 0x3000; // I/O completion queue (qid 1)
const IDENT_OFF: usize = 0x4000; // identify / scratch page
const BOUNCE_OFF: usize = 0x5000; // 4 KB read bounce buffer

/// Queue depth (entries). 16 fits both rings comfortably in one page each
/// (SQ entry = 64 B, CQ entry = 16 B) and we only ever have one in flight.
const DEPTH: usize = 16;

/// Sectors per READ command: 4 KB = one PRP page, no PRP2/list needed.
const SECTORS_PER_CMD: u32 = 8;

// Controller register offsets (from BAR0).
const R_CAP_LO: usize = 0x00;
const R_CAP_HI: usize = 0x04;
const R_CC: usize = 0x14;
const R_CSTS: usize = 0x1C;
const R_AQA: usize = 0x24;
const R_ASQ: usize = 0x28;
const R_ACQ: usize = 0x30;
const DOORBELL_BASE: usize = 0x1000;

fn r32(off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((REGS_VA + off) as *const u32) }
}
fn w32(off: usize, v: u32) {
    unsafe { core::ptr::write_volatile((REGS_VA + off) as *mut u32, v) }
}
fn w64(off: usize, v: u64) {
    w32(off, v as u32);
    w32(off + 4, (v >> 32) as u32);
}

/// One submission/completion queue pair (admin or I/O).
struct Queue {
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
        w32(self.sq_db, self.tail as u32);

        let cqe = (self.cq_va + self.head * 16) as *const u32;
        for _ in 0..100_000_000u32 {
            let dw3 = unsafe { core::ptr::read_volatile(cqe.add(3)) };
            if ((dw3 >> 16) & 1) == self.phase as u32 {
                let status = (dw3 >> 17) as u16;
                self.head += 1;
                if self.head == DEPTH {
                    self.head = 0;
                    self.phase = !self.phase;
                }
                w32(self.cq_db, self.head as u32);
                return status;
            }
        }
        0xFFFF
    }
}

struct Nvme {
    admin: Queue,
    io: Queue,
    dma_phys: u64,
}

static NVME: Mutex<Option<Nvme>> = Mutex::new(None);

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

/// Probe PCI for an NVMe controller (class 01h / subclass 08h) and bring it
/// up. Returns true when ready to serve reads. Absent bus (interpreter) or
/// absent device: false, no side effects.
pub fn init(arch: &mut crate::TheArch) -> bool {
    let Some((bus, dev)) = pci::find_class(arch, 0x01, 0x08) else {
        return false; // no NVMe controller (legacy machine) — not an error
    };

    // Enable memory space + bus mastering.
    let pcmd = pci::read32(arch, bus, dev, 0, 0x04);
    pci::write32(arch, bus, dev, 0, 0x04, (pcmd & 0xFFFF) | 0x06);

    // BAR0: a (usually 64-bit) memory BAR. OVMF places it above 4 GB — fine:
    // the kernel VA space is 32-bit but PAE/compat PTEs carry 52-bit physical
    // addresses, so `map_phys_range` reaches it. (A legacy-paging 386 would
    // truncate, but no NVMe machine is a 386.)
    let bar0 = pci::read32(arch, bus, dev, 0, 0x10);
    if bar0 & 1 != 0 {
        return false; // I/O BAR — not an NVMe register set
    }
    let is_64 = (bar0 >> 1) & 3 == 2;
    let bar_hi = if is_64 { pci::read32(arch, bus, dev, 0, 0x14) } else { 0 };
    let bar_phys = ((bar_hi as u64) << 32) | (bar0 & 0xFFFF_FFF0) as u64;

    arch.map_phys_range(REGS_VA >> 12, REGS_PAGES, bar_phys >> 12, PTE_CACHE_DISABLE);

    // The controller is present (find_class matched) — being unable to back it
    // with DMA is a hard error, not a "no disk". Fail loud so a regression like
    // another driver stealing the pool is obvious, not a silent "Diskless".
    let dma_page = arch.alloc_phys_contig(DMA_PAGES, 0);
    assert!(dma_page != 0, "nvme: controller found but no DMA pool available");
    arch.map_phys_range(DMA_VA >> 12, DMA_PAGES, dma_page, PTE_CACHE_DISABLE);
    let dma_phys = dma_page * 0x1000;
    unsafe { core::ptr::write_bytes(DMA_VA as *mut u8, 0, DMA_PAGES * 0x1000) };

    // Doorbell stride: CAP.DSTRD (bits 35:32), in units of 4 bytes.
    let stride = 4usize << (r32(R_CAP_HI) & 0xF);
    let db = |qid: usize, is_cq: bool| DOORBELL_BASE + (2 * qid + is_cq as usize) * stride;

    // Reset: EN=0, wait !RDY; program admin queues; EN=1, wait RDY.
    w32(R_CC, 0);
    if !wait_csts(0) {
        return false;
    }
    w32(R_AQA, ((DEPTH as u32 - 1) << 16) | (DEPTH as u32 - 1));
    w64(R_ASQ, dma_phys + ASQ_OFF as u64);
    w64(R_ACQ, dma_phys + ACQ_OFF as u64);
    // IOCQES=4 (16B), IOSQES=6 (64B), MPS=0 (4K), CSS=0 (NVM), EN=1.
    w32(R_CC, (4 << 20) | (6 << 16) | 1);
    if !wait_csts(1) {
        println!("NVMe: controller did not become ready (csts={:#x})", r32(R_CSTS));
        return false;
    }

    let mut n = Nvme {
        admin: Queue {
            sq_va: DMA_VA + ASQ_OFF, cq_va: DMA_VA + ACQ_OFF,
            sq_db: db(0, false), cq_db: db(0, true),
            tail: 0, head: 0, phase: true,
        },
        io: Queue {
            sq_va: DMA_VA + IOSQ_OFF, cq_va: DMA_VA + IOCQ_OFF,
            sq_db: db(1, false), cq_db: db(1, true),
            tail: 0, head: 0, phase: true,
        },
        dma_phys,
    };

    // Identify namespace 1 (CNS=0) — verify the LBA format is 512 bytes.
    let mut c = cmd(0x06, 1);
    set_prp1(&mut c, dma_phys + IDENT_OFF as u64);
    // cdw10 = CNS 0 (namespace data structure)
    if n.admin.exec(&c) != 0 {
        println!("NVMe: IDENTIFY failed");
        return false;
    }
    let ident = DMA_VA + IDENT_OFF;
    let flbas = unsafe { core::ptr::read_volatile((ident + 26) as *const u8) } & 0xF;
    let lbads = unsafe {
        core::ptr::read_volatile((ident + 128 + flbas as usize * 4 + 2) as *const u8)
    };
    if lbads != 9 {
        println!("NVMe: unsupported LBA size 2^{} (want 512)", lbads);
        return false;
    }

    // Create the I/O completion queue (opc 05h), then submission queue (01h).
    let mut c = cmd(0x05, 0);
    set_prp1(&mut c, dma_phys + IOCQ_OFF as u64);
    c[10] = ((DEPTH as u32 - 1) << 16) | 1; // qsize | qid
    c[11] = 1; // physically contiguous, no interrupts
    if n.admin.exec(&c) != 0 {
        println!("NVMe: create IO CQ failed");
        return false;
    }
    let mut c = cmd(0x01, 0);
    set_prp1(&mut c, dma_phys + IOSQ_OFF as u64);
    c[10] = ((DEPTH as u32 - 1) << 16) | 1;
    c[11] = (1 << 16) | 1; // CQID 1 | physically contiguous
    if n.admin.exec(&c) != 0 {
        println!("NVMe: create IO SQ failed");
        return false;
    }

    *NVME.lock() = Some(n);
    true
}

fn wait_csts(ready: u32) -> bool {
    for _ in 0..10_000_000u32 {
        let csts = r32(R_CSTS);
        if csts & 2 != 0 {
            println!("NVMe: controller fatal status");
            return false;
        }
        if csts & 1 == ready {
            return true;
        }
    }
    false
}

/// Read sectors (512-byte LBAs) — same contract as `hdd::read_sectors`.
/// 4 KB chunks through the bounce buffer; short tails copy partially.
pub fn read_sectors(lba: u32, mut buffer: &mut [u8]) -> u32 {
    let total = buffer.len().div_ceil(512) as u32;
    let mut guard = NVME.lock();
    let n = guard.as_mut().expect("nvme::read_sectors before init");

    let mut current = lba;
    let mut remaining = total;
    while remaining > 0 {
        let batch = remaining.min(SECTORS_PER_CMD);
        let mut c = cmd(0x02, 1); // READ, nsid 1
        set_prp1(&mut c, n.dma_phys + BOUNCE_OFF as u64);
        c[10] = current; // starting LBA, low
        c[11] = 0;       // starting LBA, high
        c[12] = batch - 1; // 0-based count
        let status = n.io.exec(&c);
        if status != 0 {
            panic!("NVMe read failed: lba={:#x} status={:#x}", current, status);
        }
        let bytes = (batch as usize * 512).min(buffer.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                (DMA_VA + BOUNCE_OFF) as *const u8,
                buffer.as_mut_ptr(),
                bytes,
            );
        }
        buffer = &mut buffer[bytes..];
        current += batch;
        remaining -= batch;
    }
    total
}
