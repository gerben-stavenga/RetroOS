//! Shared synchronous storage transfer engine.
//!
//! The engine owns serialization, staging, sector rounding, capacity checks,
//! and failure containment. Hardware implementations issue one command against
//! its buffer: port PIO, bus-master DMA, or a controller submission queue.
//! Command encodings and completion protocols stay with the controller.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;
use crate::kernel::block::Disk;

pub const SECTOR: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation { Read, Write, Flush }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    pub operation: Operation,
    pub lba: u64,
    pub sectors: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Timeout, Device(u16) }

/// One controller's permanently mapped transfer region, or aligned PIO RAM.
/// DMA allocations remain resident even after a timed-out command: hardware
/// may still own them. The engine never accesses a failed transport again.
pub struct Buffer { backing: Backing }

enum Backing {
    Pio(Vec<u16>),
    Dma { va: usize, phys: u64, len: usize },
}

impl Buffer {
    pub fn pio(sectors: usize) -> Self {
        assert!(sectors > 0);
        Self { backing: Backing::Pio(alloc::vec![0; sectors * (SECTOR / 2)]) }
    }

    /// # Safety
    /// `va..va+len` must exclusively name coherent, permanently mapped DMA
    /// memory at `phys`. It must not overlap queues or other live allocations.
    /// No device may access it until its owning transport submits a command.
    pub unsafe fn dma(va: usize, phys: u64, len: usize) -> Self {
        assert!(va.is_multiple_of(2) && len > 0 && len.is_multiple_of(SECTOR));
        Self { backing: Backing::Dma { va, phys, len } }
    }

    pub fn physical_address(&self) -> Option<u64> {
        match self.backing { Backing::Dma { phys, .. } => Some(phys), _ => None }
    }

    pub fn words(&mut self) -> &mut [u16] {
        match &mut self.backing {
            Backing::Pio(words) => words,
            // SAFETY: the constructor guarantees mapping, ownership and alignment.
            Backing::Dma { va, len, .. } => unsafe {
                core::slice::from_raw_parts_mut(*va as *mut u16, *len / 2)
            },
        }
    }

    fn bytes(&mut self) -> &mut [u8] {
        let words = self.words();
        // SAFETY: every byte pattern is valid for u16; this reborrow is exclusive.
        unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), words.len() * 2) }
    }
}

pub trait Hardware {
    /// Execute one complete command, synchronously. On success the controller
    /// has relinquished the buffer. On error the engine quarantines it along
    /// with this transport, so a late DMA completion cannot corrupt new I/O.
    fn execute(&mut self, command: Command, buffer: &mut Buffer) -> Result<(), Error>;
}

struct State<H> { hardware: H, buffer: Buffer, failed: bool }

/// A disk and its transfer engine. The lock covers staging, submission, and
/// completion, not just the hardware doorbell.
pub struct Storage<H> {
    state: Mutex<State<H>>,
    sectors: u64,
    name: String,
}

impl<H: Hardware> Storage<H> {
    pub fn new(hardware: H, buffer: Buffer, sectors: u64, name: &str) -> Self {
        Self { state: Mutex::new(State { hardware, buffer, failed: false }),
            sectors, name: String::from(name) }
    }

    fn valid_count(&self, lba: u64, bytes: usize) -> Option<u32> {
        let count = u32::try_from(bytes.div_ceil(SECTOR)).ok()?;
        (lba <= self.sectors && u64::from(count) <= self.sectors - lba).then_some(count)
    }
}

impl<H: Hardware> State<H> {
    fn execute(&mut self, command: Command) -> bool {
        if self.failed { return false; }
        // Publish CPU-written data before the controller reads it, and observe
        // controller-written data only after its completion has been consumed.
        fence(Ordering::SeqCst);
        let result = self.hardware.execute(command, &mut self.buffer);
        fence(Ordering::SeqCst);
        self.failed = result.is_err();
        if let Err(error) = result {
            let operation = match command.operation {
                Operation::Read => "read", Operation::Write => "write", Operation::Flush => "flush",
            };
            match error {
                Error::Timeout => lib::compact_println!("Storage: {} timeout (lba={} sectors={})",
                    operation, command.lba, command.sectors),
                Error::Device(status) => lib::compact_println!("Storage: {} device error {:#x} (lba={} sectors={})",
                    operation, status, command.lba, command.sectors),
            }
        }
        result.is_ok()
    }
}

impl<H: Hardware> Disk for Storage<H> {
    fn read(&self, lba: u64, mut out: &mut [u8]) -> u32 {
        let Some(total) = self.valid_count(lba, out.len()) else { return 0 };
        if total == 0 { return 0; }
        let mut state = self.state.lock();
        if state.failed { return 0; }
        let max = (state.buffer.bytes().len() / SECTOR) as u32;
        let mut done = 0;
        while done < total {
            let sectors = (total - done).min(max);
            if !state.execute(Command { operation: Operation::Read, lba: lba + u64::from(done), sectors }) {
                break;
            }
            let bytes = out.len().min(sectors as usize * SECTOR);
            out[..bytes].copy_from_slice(&state.buffer.bytes()[..bytes]);
            out = &mut out[bytes..];
            done += sectors;
        }
        done
    }

    fn write(&self, lba: u64, mut input: &[u8]) -> u32 {
        let Some(total) = self.valid_count(lba, input.len()) else { return 0 };
        if total == 0 { return 0; }
        let mut state = self.state.lock();
        if state.failed { return 0; }
        let max = (state.buffer.bytes().len() / SECTOR) as u32;
        let mut done = 0;
        while done < total {
            let sectors = (total - done).min(max);
            let full_bytes = sectors as usize * SECTOR;
            let bytes = input.len().min(full_bytes);
            let staging = &mut state.buffer.bytes()[..full_bytes];
            staging[..bytes].copy_from_slice(&input[..bytes]);
            staging[bytes..].fill(0);
            if !state.execute(Command { operation: Operation::Write, lba: lba + u64::from(done), sectors }) {
                break;
            }
            input = &input[bytes..];
            done += sectors;
        }
        done
    }

    fn flush(&self) {
        // Disk::flush currently has no error channel. Never silently report a
        // failed durability barrier as success to a filesystem.
        if !self.state.lock().execute(Command { operation: Operation::Flush, lba: 0, sectors: 0 }) {
            lib::compact_panic!("storage flush failed: {}", self.name.as_str());
        }
    }

    fn sectors(&self) -> u64 { self.sectors }
    fn name(&self) -> &str { &self.name }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryDisk { data: Vec<u8>, calls: Vec<Command>, fail_at: Option<usize> }
    impl Hardware for MemoryDisk {
        fn execute(&mut self, c: Command, b: &mut Buffer) -> Result<(), Error> {
            self.calls.push(c);
            if self.fail_at == Some(self.calls.len()) { return Err(Error::Timeout); }
            if c.operation == Operation::Flush { return Ok(()); }
            let start = c.lba as usize * SECTOR;
            let end = start + c.sectors as usize * SECTOR;
            let bytes = &mut b.bytes()[..end - start];
            match c.operation {
                Operation::Read => bytes.copy_from_slice(&self.data[start..end]),
                Operation::Write => self.data[start..end].copy_from_slice(bytes),
                Operation::Flush => unreachable!(),
            }
            Ok(())
        }
    }
    fn disk(fail_at: Option<usize>) -> Storage<MemoryDisk> {
        Storage::new(MemoryDisk { data: alloc::vec![0xa5; 8 * SECTOR], calls: Vec::new(), fail_at },
            Buffer::pio(2), 8, "test")
    }

    #[test]
    fn batches_and_pads_only_the_final_sector() {
        let disk = disk(None);
        let input: Vec<_> = (0..(3 * SECTOR + 7)).map(|i| i as u8).collect();
        assert_eq!(disk.write(1, &input), 4);
        disk.flush();
        let mut output = alloc::vec![0; input.len() + 2];
        assert_eq!(disk.read(1, &mut output[1..input.len() + 1]), 4);
        assert_eq!(&output[1..input.len() + 1], &input);
        assert_eq!((output[0], output[input.len() + 1]), (0, 0));
        let state = disk.state.lock();
        assert_eq!(&state.hardware.data[..SECTOR], &[0xa5; SECTOR]);
        assert!(state.hardware.data[SECTOR + input.len()..5 * SECTOR].iter().all(|b| *b == 0));
        assert!(state.hardware.data[5 * SECTOR..].iter().all(|b| *b == 0xa5));
        assert_eq!(state.hardware.calls.iter().map(|c| (c.operation, c.lba, c.sectors)).collect::<Vec<_>>(),
            [(Operation::Write, 1, 2), (Operation::Write, 3, 2), (Operation::Flush, 0, 0),
             (Operation::Read, 1, 2), (Operation::Read, 3, 2)]);
    }

    #[test]
    fn rejects_out_of_range_and_empty_requests_without_hardware_access() {
        let disk = disk(None);
        assert_eq!(disk.write(8, &[1]), 0);
        assert_eq!(disk.read(u64::MAX, &mut [0; 512]), 0);
        assert_eq!(disk.write(7, &[1; 513]), 0);
        assert_eq!(disk.write(8, &[]), 0);
        assert_eq!(disk.read(0, &mut []), 0);
        assert!(disk.state.lock().hardware.calls.is_empty());
    }

    #[test]
    fn failed_command_preserves_unread_output_and_quarantines_buffer() {
        let disk = disk(Some(2));
        let mut output = [0x11; 3 * SECTOR];
        assert_eq!(disk.read(0, &mut output), 2);
        assert_eq!(&output[..2 * SECTOR], &[0xa5; 2 * SECTOR]);
        assert_eq!(&output[2 * SECTOR..], &[0x11; SECTOR]);
        assert_eq!(disk.write(0, &[2; SECTOR]), 0);
        assert_eq!(disk.read(0, &mut output), 0);
        let mut state = disk.state.lock();
        assert_eq!(state.hardware.calls.len(), 2);
        assert!(state.buffer.bytes().iter().all(|b| *b == 0xa5));
    }
}
