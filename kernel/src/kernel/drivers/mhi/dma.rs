//! Boot-lifetime DMA backing for MHI controllers and segmented firmware.
use super::{Firmware, Memory, SEGMENT};
use crate::kernel::drivers::dma::Region;
use alloc::vec::Vec;

pub struct Dma(Region);
impl Dma {
    pub fn allocate<A: crate::Arch>(
        machine: &mut A,
        bytes: usize,
        address_bits: u32,
    ) -> Option<Self> {
        if bytes == 0 {
            return None;
        }
        Region::allocate(machine, bytes.div_ceil(crate::PAGE_SIZE), address_bits).map(Self)
    }
    /// Match the physical alignment guaranteed by coherent DMA allocation:
    /// the smallest power-of-two page order large enough for the buffer.
    pub fn allocate_aligned<A: crate::Arch>(
        machine: &mut A,
        bytes: usize,
        address_bits: u32,
    ) -> Option<Self> {
        if bytes == 0 {
            return None;
        }
        let pages = bytes.div_ceil(crate::PAGE_SIZE);
        let alignment = pages.checked_next_power_of_two()?;
        Region::allocate_aligned(machine, pages, alignment, address_bits).map(Self)
    }
    fn address(&self, offset: usize, count: usize) -> usize {
        assert!(
            offset
                .checked_add(count)
                .is_some_and(|end| end <= self.0.size_bytes())
        );
        self.0.va + offset
    }
}
impl Memory for Dma {
    fn physical(&self) -> u64 {
        self.0.phys
    }
    fn read32(&self, offset: usize) -> u32 {
        assert!(offset.is_multiple_of(4));
        unsafe { core::ptr::read_volatile(self.address(offset, 4) as *const u32) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        assert!(offset.is_multiple_of(4));
        unsafe {
            core::ptr::write_volatile(self.address(offset, 4) as *mut u32, value);
        }
    }
    fn copy_in(&mut self, offset: usize, bytes: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.address(offset, bytes.len()) as *mut u8,
                bytes.len(),
            );
        }
    }
    fn copy_out(&self, offset: usize, count: usize) -> Vec<u8> {
        unsafe { core::slice::from_raw_parts(self.address(offset, count) as *const u8, count) }
            .to_vec()
    }
}

/// Staged BHI/BHIE image. Format validation belongs to the device driver;
/// the shared MHI transport only handles its segmented byte representation.
pub struct Image {
    segments: Vec<Dma>,
    table: Dma,
    bytes: usize,
}
impl Image {
    pub fn allocate<A: crate::Arch>(
        machine: &mut A,
        bytes: &[u8],
        address_bits: u32,
    ) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let entries = bytes.len().div_ceil(SEGMENT);
        let mut table = Dma::allocate(machine, entries.checked_mul(16)?, address_bits)?;
        let mut segments = Vec::new();
        for (index, chunk) in bytes.chunks(SEGMENT).enumerate() {
            let mut segment = Dma::allocate(machine, chunk.len(), address_bits)?;
            segment.copy_in(0, chunk);
            table.write64(index * 16, segment.physical());
            table.write64(index * 16 + 8, chunk.len() as u64);
            segments.push(segment);
        }
        Some(Self {
            segments,
            table,
            bytes: bytes.len(),
        })
    }
    pub fn firmware(&self) -> Firmware {
        Firmware {
            first_stage: self.segments[0].physical(),
            first_bytes: self.bytes.min(SEGMENT),
            vectors: self.table.physical(),
            vector_bytes: self.segments.len() * 16,
        }
    }
}
