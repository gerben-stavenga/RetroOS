//! Boot-lifetime device mappings. Allocation is shared by storage transports;
//! controller protocols never select overlapping fixed low-memory windows.
//!
//! Mappings deliberately remain resident until reboot, including after failed
//! initialization or timeout. Reclaiming a region requires proving that its
//! controller can no longer bus-master into it.

use super::storage::Buffer;
use core::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(arch_abi::DEVICE_WINDOW_BASE);

fn reserve(pages: usize) -> Option<usize> {
    reserve_from(&NEXT, pages)
}

fn reserve_from(next: &AtomicUsize, pages: usize) -> Option<usize> {
    let bytes = pages.checked_mul(crate::PAGE_SIZE)?;
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |base| {
        base.checked_add(bytes)
            .filter(|end| *end <= arch_abi::DEVICE_WINDOW_END)
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_memory_has_order_alignment_and_padding_is_disjoint() {
        // Sizes actually requested by WCN7850 in KLOG0026.
        for bytes in [7_012_352usize, 8_454_144] {
            let pages = bytes.div_ceil(crate::PAGE_SIZE);
            let align = pages.next_power_of_two();
            for first in [1, 0x2e331, 0x30000, 0x301ff] {
                let (page, prefix, suffix) = aligned_span(first, pages, align).unwrap();
                assert!(page.is_multiple_of(align as u64));
                assert_eq!(first + prefix as u64, page);
                assert_eq!(prefix + pages + suffix, pages + align - 1);
                assert_eq!(
                    page + pages as u64 + suffix as u64,
                    first + (pages + align - 1) as u64
                );
                // A requested region never crosses its aligned power-of-two block.
                assert!((page * 4096 + bytes as u64) <= (page + align as u64) * 4096);
            }
        }
        assert_eq!(aligned_span(0x123, 5, 1), Some((0x123, 0, 0)));
        for (first, pages, align) in [(1, 0, 8), (1, 8, 0), (1, 8, 3), (u64::MAX, 8, 8)] {
            assert!(aligned_span(first, pages, align).is_none());
        }
    }

    #[test]
    fn firmware_staging_fits_alongside_registers_and_transport() {
        let next = AtomicUsize::new(arch_abi::DEVICE_WINDOW_BASE);
        // Allow other devices, the WCN785x BAR, the largest supported AMSS
        // image, its vector table, contexts, and IPCR packet storage.
        for bytes in [
            4usize * 1024 * 1024,
            2 * 1024 * 1024,
            32 * 1024 * 1024,
            4096,
            super::super::mhi::CONTEXT_BYTES,
            1024 * 1024,
        ] {
            assert!(reserve_from(&next, bytes.div_ceil(crate::PAGE_SIZE)).is_some());
        }
        let used = next.load(Ordering::Relaxed);
        assert!(reserve_from(&next, usize::MAX).is_none());
        assert_eq!(next.load(Ordering::Relaxed), used);
        let remaining = (arch_abi::DEVICE_WINDOW_END - used) / crate::PAGE_SIZE;
        assert!(reserve_from(&next, remaining).is_some());
        assert!(reserve_from(&next, 1).is_none());
        assert_eq!(next.load(Ordering::Relaxed), arch_abi::DEVICE_WINDOW_END);
    }
}

#[derive(Clone, Copy)]
pub struct Mmio {
    base: usize,
    len: usize,
}

impl Mmio {
    /// # Safety
    /// Test storage must remain alive and exclusively owned for every access.
    #[cfg(test)]
    pub(crate) unsafe fn test_mapping(base: *mut u32, len: usize) -> Self {
        Self {
            base: base as usize,
            len,
        }
    }
    pub fn read8(&self, offset: usize) -> u8 {
        assert!(offset < self.len);
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u8) }
    }
    pub fn read16(&self, offset: usize) -> u16 {
        assert!(offset.is_multiple_of(2) && offset + 2 <= self.len);
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u16) }
    }
    pub fn write8(&self, offset: usize, value: u8) {
        assert!(offset < self.len);
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u8, value) }
    }
    pub fn write16(&self, offset: usize, value: u16) {
        assert!(offset.is_multiple_of(2) && offset + 2 <= self.len);
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u16, value) }
    }
    pub fn map<A: crate::Arch>(machine: &mut A, phys: u64, bytes: usize) -> Option<Self> {
        let offset = (phys as usize) & (crate::PAGE_SIZE - 1);
        let pages = offset.checked_add(bytes)?.div_ceil(crate::PAGE_SIZE);
        let base = reserve(pages)?;
        machine.map_phys_range(
            base >> 12,
            pages,
            phys >> 12,
            arch_abi::MAP_PHYS_CACHE_DISABLE,
        );
        Some(Self {
            base: base + offset,
            len: bytes,
        })
    }
    pub fn read(&self, offset: usize) -> u32 {
        assert!(offset.is_multiple_of(4) && offset + 4 <= self.len);
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }
    pub fn write(&self, offset: usize, value: u32) {
        assert!(offset.is_multiple_of(4) && offset + 4 <= self.len);
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
    pub fn write64(&self, offset: usize, value: u64) {
        self.write(offset, value as u32);
        self.write(offset + 4, (value >> 32) as u32);
    }
}

pub struct Region {
    pub va: usize,
    pub phys: u64,
    bytes: usize,
}

// Return an aligned subrange and the unused prefix/suffix of an allocation.
// All quantities are pages. The caller owns the whole raw allocation.
fn aligned_span(first: u64, pages: usize, align: usize) -> Option<(u64, usize, usize)> {
    if pages == 0 || !align.is_power_of_two() {
        return None;
    }
    let aligned = first.checked_add(align as u64 - 1)? & !(align as u64 - 1);
    let prefix = usize::try_from(aligned.checked_sub(first)?).ok()?;
    let suffix = (align - 1).checked_sub(prefix)?;
    aligned
        .checked_add(pages as u64)?
        .checked_add(suffix as u64)?;
    Some((aligned, prefix, suffix))
}

impl Region {
    pub fn size_bytes(&self) -> usize {
        self.bytes
    }

    pub fn allocate<A: crate::Arch>(
        machine: &mut A,
        pages: usize,
        address_bits: u32,
    ) -> Option<Self> {
        Self::allocate_aligned(machine, pages, 1, address_bits)
    }

    /// Physically align a DMA range; the CPU mapping only requires page alignment.
    /// Unused padding is freed before the range is mapped or exposed to a device.
    pub fn allocate_aligned<A: crate::Arch>(
        machine: &mut A,
        pages: usize,
        alignment_pages: usize,
        address_bits: u32,
    ) -> Option<Self> {
        if pages == 0 || !alignment_pages.is_power_of_two() {
            return None;
        }
        let bytes = pages.checked_mul(crate::PAGE_SIZE)?;
        let raw_pages = pages.checked_add(alignment_pages - 1)?;
        let raw = machine.alloc_phys_contig(raw_pages);
        if raw == 0 {
            return None;
        }
        let span = (|| {
            let (page, prefix, suffix) = aligned_span(raw, pages, alignment_pages)?;
            let phys = page.checked_mul(crate::PAGE_SIZE as u64)?;
            let end = phys.checked_add(bytes as u64)?;
            if address_bits < 64 && end > (1u64 << address_bits) {
                return None;
            }
            let va = reserve(pages)?;
            Some((page, prefix, suffix, phys, va))
        })();
        let Some((page, prefix, suffix, phys, va)) = span else {
            machine.free_phys_contig(raw, raw_pages);
            return None;
        };
        if prefix != 0 {
            machine.free_phys_contig(raw, prefix);
        }
        if suffix != 0 {
            machine.free_phys_contig(page + pages as u64, suffix);
        }
        machine.map_phys_range(va >> 12, pages, page, 0);
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, bytes) };
        Some(Self { va, phys, bytes })
    }

    /// # Safety
    /// This span must have a single owner and be disjoint from the controller's
    /// queues/descriptors. It must not yet be accessed by hardware.
    pub unsafe fn buffer(&self, offset: usize, bytes: usize) -> Buffer {
        assert!(
            offset
                .checked_add(bytes)
                .is_some_and(|end| end <= self.bytes)
        );
        unsafe { Buffer::dma(self.va + offset, self.phys + offset as u64, bytes) }
    }
}
