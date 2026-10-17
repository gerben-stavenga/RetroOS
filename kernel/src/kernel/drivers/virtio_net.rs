//! VirtIO 1.0+ PCI Ethernet, split RX/TX queues, software checksums and polling.
//! No offloads, merged RX buffers, packed rings, MSI, or legacy-only transport.
//! Reference: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html

use super::dma::{Mmio, Region};
use crate::kernel::{net::EthernetDevice, pci, portio};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

const DEPTH: usize = 64;
const BUFFER: usize = 2048;
const HEADER: usize = 12;
const AVAIL: usize = 1024;
const USED: usize = 4096;
const PACKETS: usize = 8192;

struct Queue {
    va: usize,
    phys: u64,
    size: u16,
    available: u16,
    consumed: u16,
    busy: [bool; DEPTH],
    notify: Mmio,
    notify_offset: usize,
    number: u16,
}

impl Queue {
    fn read16(&self, offset: usize) -> u16 {
        unsafe { core::ptr::read_volatile((self.va + offset) as *const u16) }
    }
    fn write16(&self, offset: usize, value: u16) {
        unsafe { core::ptr::write_volatile((self.va + offset) as *mut u16, value) }
    }
    fn write32(&self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile((self.va + offset) as *mut u32, value) }
    }
    fn packet(&self, id: u16) -> usize {
        self.va + PACKETS + usize::from(id) * BUFFER
    }
    fn free(&self) -> Option<u16> {
        (0..self.size).find(|&id| !self.busy[usize::from(id)])
    }

    fn submit(&mut self, id: u16, length: usize, receive: bool) {
        let off = usize::from(id) * 16;
        let address = self.phys + PACKETS as u64 + u64::from(id) * BUFFER as u64;
        self.write32(off, address as u32);
        self.write32(off + 4, (address >> 32) as u32);
        self.write32(off + 8, length as u32);
        self.write16(off + 12, if receive { 2 } else { 0 });
        self.write16(off + 14, 0);
        self.busy[usize::from(id)] = true;
        self.write16(AVAIL + 4 + usize::from(self.available % self.size) * 2, id);
        // Packet and descriptor stores precede publishing avail.idx to DMA.
        fence(Ordering::Release);
        self.available = self.available.wrapping_add(1);
        self.write16(AVAIL + 2, self.available);
        fence(Ordering::SeqCst);
        self.notify.write16(self.notify_offset, self.number);
    }

    fn completed(&mut self) -> Result<Option<(u16, usize)>, ()> {
        let used = self.read16(USED + 2);
        let pending = used.wrapping_sub(self.consumed);
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.size {
            return Err(());
        }
        fence(Ordering::Acquire);
        let off = USED + 4 + usize::from(self.consumed % self.size) * 8;
        let id = unsafe { core::ptr::read_volatile((self.va + off) as *const u32) };
        let len = unsafe { core::ptr::read_volatile((self.va + off + 4) as *const u32) };
        if id >= u32::from(self.size) || !self.busy[id as usize] {
            return Err(());
        }
        self.consumed = self.consumed.wrapping_add(1);
        self.busy[id as usize] = false;
        Ok(Some((id as u16, len as usize)))
    }
}

struct Cap {
    registers: Mmio,
    length: usize,
    multiplier: usize,
}

fn capabilities<A: crate::Arch>(
    machine: &mut A,
    address: (u8, u8, u8),
) -> Option<(Mmio, Cap, Mmio)> {
    let (b, d, f) = address;
    let mut common = None;
    let mut notify = None;
    let mut config = None;
    let mut cursor = (pci::read32(machine, b, d, f, 0x34) & 0xFC) as u8;
    let mut visited = [false; 64];
    while cursor >= 0x40 {
        let index = usize::from(cursor / 4);
        if visited[index] {
            return None;
        }
        visited[index] = true;
        let head = pci::read32(machine, b, d, f, cursor);
        let next = ((head >> 8) & 0xFC) as u8;
        if head as u8 == 9 && (head >> 16) as u8 >= 16 && cursor <= 0xF0 {
            let kind = head >> 24;
            if matches!(kind, 1 | 2 | 4) {
                let bar = (pci::read32(machine, b, d, f, cursor + 4) & 0xFF) as u8;
                if bar >= 6 {
                    return None;
                }
                let low = pci::read32(machine, b, d, f, 0x10 + bar * 4);
                if low & 1 != 0 {
                    return None;
                }
                let high = if low & 6 == 4 && bar < 5 {
                    pci::read32(machine, b, d, f, 0x14 + bar * 4)
                } else {
                    0
                };
                let base = u64::from(low & !15) | (u64::from(high) << 32);
                let offset = pci::read32(machine, b, d, f, cursor + 8);
                let len = pci::read32(machine, b, d, f, cursor + 12) as usize;
                if base == 0 || len == 0 || len > 65536 {
                    return None;
                }
                if (kind == 1 && offset % 4 != 0) || (kind == 2 && offset % 2 != 0) {
                    return None;
                }
                let registers = Mmio::map(machine, base.checked_add(u64::from(offset))?, len)?;
                match kind {
                    1 if len >= 56 => common = Some(registers),
                    2 if (head >> 16) as u8 >= 20 && cursor <= 0xEC => {
                        notify = Some(Cap {
                            registers,
                            length: len,
                            multiplier: pci::read32(machine, b, d, f, cursor + 16) as usize,
                        });
                    }
                    4 if len >= 6 => config = Some(registers),
                    _ => return None,
                }
            }
        }
        cursor = next;
    }
    Some((common?, notify?, config?))
}

fn make_queue<A: crate::Arch>(
    machine: &mut A,
    common: Mmio,
    notify: &Cap,
    number: u16,
) -> Option<Queue> {
    common.write16(22, number);
    if common.read16(28) != 0 {
        return None;
    }
    let maximum = common.read16(24);
    let size = maximum.min(DEPTH as u16);
    if size == 0 || !size.is_power_of_two() {
        return None;
    }
    let notify_offset = usize::from(common.read16(30)).checked_mul(notify.multiplier)?;
    if notify_offset % 2 != 0 || notify_offset.checked_add(2)? > notify.length {
        return None;
    }
    let dma = Region::allocate(
        machine,
        (PACKETS + usize::from(size) * BUFFER).div_ceil(crate::PAGE_SIZE),
        64,
    )?;
    let q = Queue {
        va: dma.va,
        phys: dma.phys,
        size,
        available: 0,
        consumed: 0,
        busy: [false; DEPTH],
        notify: notify.registers,
        notify_offset,
        number,
    };
    q.write16(AVAIL, 1); // Poll completions; suppress used-buffer interrupts.
    common.write16(24, size);
    common.write16(26, 0xFFFF);
    common.write64(32, dma.phys);
    common.write64(40, dma.phys + AVAIL as u64);
    common.write64(48, dma.phys + USED as u64);
    common.write16(28, 1);
    Some(q)
}

pub struct VirtioNet {
    common: Mmio,
    rx: Queue,
    tx: Queue,
    mac: [u8; 6],
    failed: bool,
}

impl VirtioNet {
    fn bring_up<A: crate::Arch>(machine: &mut A, address: (u8, u8, u8)) -> Option<Self> {
        let (b, d, f) = address;
        let (common, notify, config) = capabilities(machine, address)?;
        let command = pci::read32(machine, b, d, f, 4) & 0xFFFF;
        // Memory + DMA, no wired INTx: the event loop polls the RX/TX rings.
        pci::write32(machine, b, d, f, 4, command | 6 | (1 << 10));
        common.write8(20, 0);
        let deadline = portio::now_ns().saturating_add(100_000_000);
        while common.read8(20) != 0 {
            if portio::now_ns() >= deadline {
                return None;
            }
            core::hint::spin_loop();
        }
        common.write8(20, 1);
        common.write8(20, 3);
        let initialize = || -> Option<([u8; 6], u32)> {
            common.write(0, 1);
            if common.read(4) & 1 == 0 {
                return None;
            } // VIRTIO_F_VERSION_1
            common.write(0, 0);
            let features = common.read(4);
            if features & (1 << 5) == 0 {
                return None;
            } // MAC
            common.write(8, 0);
            common.write(12, 1 << 5);
            common.write(8, 1);
            common.write(12, 1);
            common.write8(20, 11); // ACKNOWLEDGE | DRIVER | FEATURES_OK
            if common.read8(20) & 8 == 0 {
                return None;
            }
            common.write16(16, 0xFFFF);
            if common.read16(18) < 2 {
                return None;
            }
            for _ in 0..16 {
                let generation = common.read8(21);
                let mac = core::array::from_fn(|i| config.read8(i));
                if generation == common.read8(21) && mac != [0; 6] && mac[0] & 1 == 0 {
                    return Some((mac, features));
                }
            }
            None
        };
        let result = (|| {
            let (mac, _) = initialize()?;
            let rx = make_queue(machine, common, &notify, 0)?;
            let tx = make_queue(machine, common, &notify, 1)?;
            let mut nic = Self {
                common,
                rx,
                tx,
                mac,
                failed: false,
            };
            common.write8(20, 15); // DRIVER_OK before publishing buffers.
            for id in 0..nic.rx.size {
                nic.rx.submit(id, BUFFER, true);
            }
            Some(nic)
        })();
        if result.is_none() {
            common.write8(20, common.read8(20) | 128);
        }
        result
    }

    fn fail(&mut self) {
        if !self.failed {
            crate::compact_println!("virtio-net: invalid completion; device stopped");
        }
        self.failed = true;
        self.common.write8(20, self.common.read8(20) | 128);
    }

    fn reclaim_tx(&mut self) {
        for _ in 0..self.tx.size {
            match self.tx.completed() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(()) => {
                    self.fail();
                    break;
                }
            }
        }
    }
}

impl EthernetDevice for VirtioNet {
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        if self.failed {
            return None;
        }
        for _ in 0..self.rx.size {
            let (id, len) = match self.rx.completed() {
                Ok(Some(value)) => value,
                Ok(None) => return None,
                Err(()) => {
                    self.fail();
                    return None;
                }
            };
            let packet = if (HEADER + 14..=HEADER + 1514).contains(&len) {
                let pointer = self.rx.packet(id) as *const u8;
                // The device relinquished this buffer through used.idx.
                let header = unsafe { core::slice::from_raw_parts(pointer, HEADER) };
                // MRG_RXBUF is not negotiated, so each completion is one
                // packet. num_buffers is not needed to walk buffer chains.
                if header[0] == 0 && header[1] == 0 {
                    Some(
                        unsafe { core::slice::from_raw_parts(pointer.add(HEADER), len - HEADER) }
                            .to_vec(),
                    )
                } else {
                    None
                }
            } else {
                None
            };
            self.rx.submit(id, BUFFER, true);
            if packet.is_some() {
                return packet;
            }
        }
        None
    }
    fn can_transmit(&mut self) -> bool {
        self.reclaim_tx();
        !self.failed && self.tx.free().is_some()
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        if !self.can_transmit() || frame.len() > 1514 {
            return false;
        }
        let Some(id) = self.tx.free() else {
            return false;
        };
        unsafe {
            let destination = self.tx.packet(id) as *mut u8;
            core::ptr::write_bytes(destination, 0, HEADER);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), destination.add(HEADER), frame.len());
        }
        self.tx.submit(id, HEADER + frame.len(), false);
        true
    }
}

pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<VirtioNet> {
    for address @ (b, d, f) in pci::find_classes(machine, 2, 0) {
        let id = pci::read32(machine, b, d, f, 0);
        if id != 0x1000_1AF4 && id != 0x1041_1AF4 {
            continue;
        }
        if let Some(nic) = VirtioNet::bring_up(machine, address) {
            let m = nic.mac;
            crate::compact_println!(
                "virtio-net: ready at {:02x}:{:02x}.{} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                b,
                d,
                f,
                m[0],
                m[1],
                m[2],
                m[3],
                m[4],
                m[5]
            );
            return Some(nic);
        }
        crate::compact_println!(
            "virtio-net: initialization failed at {:02x}:{:02x}.{}",
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

    fn fixture(size: u16, number: u16) -> (Vec<u64>, Vec<u32>, Queue) {
        let mut dma = alloc::vec![0u64; (PACKETS + usize::from(size) * BUFFER) / 8];
        let mut registers = alloc::vec![0u32; 16];
        let notify = unsafe { Mmio::test_mapping(registers.as_mut_ptr(), 64) };
        let queue = Queue {
            va: dma.as_mut_ptr() as usize,
            phys: 0x12345000,
            size,
            available: 0,
            consumed: 0,
            busy: [false; DEPTH],
            notify,
            notify_offset: 0,
            number,
        };
        (dma, registers, queue)
    }

    fn complete(q: &Queue, index: u16, id: u32, length: u32) {
        let off = USED + 4 + usize::from(index % q.size) * 8;
        q.write32(off, id);
        q.write32(off + 4, length);
        q.write16(USED + 2, index.wrapping_add(1));
    }

    #[test]
    fn dma_descriptors_and_indices_survive_u16_wrap() {
        let (_dma, registers, mut q) = fixture(2, 1);
        for sequence in 0..65540u32 {
            let id = (sequence % 2) as u16;
            q.submit(id, BUFFER, true);
            let words = unsafe {
                core::slice::from_raw_parts((q.va + usize::from(id) * 16) as *const u32, 4)
            };
            assert_eq!(
                words,
                &[
                    q.phys as u32 + PACKETS as u32 + u32::from(id) * BUFFER as u32,
                    0,
                    BUFFER as u32,
                    2
                ]
            );
            assert_eq!(q.read16(AVAIL + 2), (sequence as u16).wrapping_add(1));
            assert_eq!(registers[0], 1);
            complete(&q, sequence as u16, u32::from(id), 100);
            assert_eq!(q.completed(), Ok(Some((id, 100))));
            assert_eq!(q.completed(), Ok(None));
            assert!(!q.busy[usize::from(id)]);
        }
        q.submit(0, BUFFER, true);
        complete(&q, q.consumed, 2, 100);
        assert_eq!(q.completed(), Err(()));
        assert!(
            q.busy[0],
            "invalid device IDs must not release a live buffer"
        );
    }

    #[test]
    fn tx_backpressure_reuses_only_completed_dma_buffers() {
        let (_rx_dma, _rx_regs, rx) = fixture(2, 0);
        let (_tx_dma, _tx_regs, tx) = fixture(2, 1);
        let mut nic = VirtioNet {
            common: rx.notify,
            rx,
            tx,
            mac: [2; 6],
            failed: false,
        };
        let a = [0xA5; 60];
        let b = [0x5A; 60];
        assert!(nic.transmit(&a));
        assert!(nic.transmit(&b));
        assert!(!nic.can_transmit());
        assert!(!nic.transmit(&a));
        let first =
            unsafe { core::slice::from_raw_parts(nic.tx.packet(0) as *const u8, HEADER + 60) };
        assert_eq!(&first[..HEADER], &[0; HEADER]);
        assert_eq!(&first[HEADER..], &a);
        complete(&nic.tx, 0, 0, 0);
        assert!(nic.transmit(&b));
        let first =
            unsafe { core::slice::from_raw_parts(nic.tx.packet(0) as *const u8, HEADER + 60) };
        assert_eq!(&first[HEADER..], &b);
        assert!(nic.tx.busy[1], "the device still owns the second packet");
    }
}
