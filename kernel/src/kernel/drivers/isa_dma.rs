//! Permanent emulated ISA channel RAM, shared by guest aliases and the mixer.
//! Each channel has one kernel mapping. Reads never consult guest page tables.
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::Arch;

static BUFFERS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

#[derive(Clone, Copy)]
struct Buffer { address: usize, bytes: usize }
impl Buffer {
    fn get<A: Arch>(machine: &mut A, channel: usize) -> Option<Self> {
        let slot = BUFFERS.get(channel)?;
        let bytes = if channel < 4 { 65536 } else { 131072 };
        let mut address = slot.load(Ordering::Acquire);
        if address == 0 {
            // Only the guest core creates bindings; the media core receives
            // the already-published buffer and performs volatile reads only.
            let pages = bytes / 4096;
            address = machine.alloc_shared_pages(pages).as_ptr() as usize;
            slot.store(address, Ordering::Release);
        }
        Some(Self { address, bytes })
    }
    fn read(self, offset: usize, destination: &mut [u8]) {
        assert!(offset.checked_add(destination.len()).is_some_and(|end| end <= self.bytes));
        for (i, byte) in destination.iter_mut().enumerate() {
            // The guest can write concurrently on the execution core.
            // Do not form a Rust slice/reference to the live channel storage.
            *byte = unsafe { (self.address as *const u8).add(offset + i).read_volatile() };
        }
    }
}

pub(crate) struct Binding {
    buffer: Buffer,
    channel: usize,
    guest: usize,
    bytes: usize,
    offset: usize,
    vpage: usize,
    pages: usize,
}
impl Binding {
    pub(crate) fn matches(&self, channel: usize, guest: usize, bytes: usize) -> bool {
        self.channel == channel && self.guest == guest && self.bytes == bytes
    }
    pub(crate) fn new<A: Arch>(machine: &mut A, channel: usize, guest: usize, bytes: usize) -> Option<Self> {
        let buffer = Buffer::get(machine, channel)?;
        let offset = guest & (buffer.bytes - 1);
        if bytes == 0 || offset.checked_add(bytes)? > buffer.bytes { return None; }
        let vpage = guest / 4096;
        let pages = ((guest & 4095) + bytes).div_ceil(4096);
        let base = core::ptr::NonNull::new((buffer.address + (offset & !4095)) as *mut u8)?;
        let mut saved = alloc::vec![0; pages * 4096];
        machine.copy_from(vpage * 4096, &mut saved);
        // Preserve complete end pages, including non-DMA neighbour bytes.
        // Shared aliases leave the permanent channel frames out of COW and
        // teardown. This is software DMA: normal coherent RAM avoids turning
        // sound-buffer setup and neighbouring guest accesses into UC traffic.
        machine.unmap_range(vpage, pages);
        unsafe {
            machine.map_shared_pages(vpage, base, pages);
        }
        machine.copy_to(vpage * 4096, &saved);
        Some(Self { buffer, channel, guest, bytes, offset, vpage, pages })
    }
    pub(crate) fn read(&self, offset: usize, destination: &mut [u8]) {
        assert!(offset.checked_add(destination.len()).is_some_and(|end| end <= self.bytes));
        self.buffer.read(self.offset + offset, destination);
    }
    pub(crate) fn unbind<A: Arch>(self, machine: &mut A) {
        let mut saved = alloc::vec![0; self.pages * 4096];
        machine.copy_from(self.vpage * 4096, &mut saved);
        machine.map_fresh_range(self.vpage, self.pages);
        machine.copy_to(self.vpage * 4096, &saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dma_reads_observe_live_buffer_writes_without_a_snapshot() {
        let mut bytes = [10u8, 20, 30, 40];
        let address = bytes.as_mut_ptr() as usize;
        let buffer = Buffer { address, bytes: 4 };
        let mut output = [0; 2];
        buffer.read(1, &mut output);
        assert_eq!(output, [20, 30]);
        unsafe { (address as *mut u8).add(2).write_volatile(99); }
        buffer.read(1, &mut output);
        assert_eq!(output, [20, 99]);
    }
    #[test]
    fn a_binding_reads_only_its_offset_inside_the_channel_array() {
        let mut bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let binding = Binding { buffer: Buffer { address: bytes.as_mut_ptr() as usize, bytes: 8 },
            channel: 5, guest: 0x12345, bytes: 3, offset: 4, vpage: 0x12, pages: 1 };
        let mut output = [0; 2];
        binding.read(1, &mut output);
        assert_eq!(output, [5, 6]);
        assert!(binding.matches(5, 0x12345, 3));
        assert!(!binding.matches(1, 0x12345, 3));
    }
}
