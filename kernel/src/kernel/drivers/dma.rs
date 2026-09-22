//! Boot-lifetime device mappings. Allocation is shared by storage transports;
//! controller protocols never select overlapping fixed low-memory windows.
//!
//! Mappings deliberately remain resident until reboot, including after failed
//! initialization or timeout. Reclaiming a region requires proving that its
//! controller can no longer bus-master into it.

use core::sync::atomic::{AtomicUsize, Ordering};
use super::storage::Buffer;

static NEXT: AtomicUsize = AtomicUsize::new(arch_abi::DEVICE_WINDOW_BASE);

fn reserve(pages: usize) -> Option<usize> {
    let bytes = pages.checked_mul(crate::PAGE_SIZE)?;
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |base| {
        base.checked_add(bytes).filter(|end| *end <= arch_abi::DEVICE_WINDOW_END)
    }).ok()
}

#[derive(Clone, Copy)]
pub struct Mmio { base: usize, len: usize }

impl Mmio {
    pub fn map<A: crate::Arch>(machine: &mut A, phys: u64, bytes: usize) -> Option<Self> {
        let offset = (phys as usize) & (crate::PAGE_SIZE - 1);
        let pages = offset.checked_add(bytes)?.div_ceil(crate::PAGE_SIZE);
        let base = reserve(pages)?;
        machine.map_phys_range(base >> 12, pages, phys >> 12, arch_abi::MAP_PHYS_CACHE_DISABLE);
        Some(Self { base: base + offset, len: bytes })
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

pub struct Region { pub va: usize, pub phys: u64, bytes: usize }

impl Region {
    pub fn allocate<A: crate::Arch>(machine: &mut A, pages: usize, address_bits: u32) -> Option<Self> {
        let bytes = pages.checked_mul(crate::PAGE_SIZE)?;
        let page = machine.alloc_phys_contig(pages, 0);
        if page == 0 { return None; }
        let phys = page.checked_mul(crate::PAGE_SIZE as u64)?;
        if address_bits < 64 && phys.checked_add(bytes as u64)? > (1u64 << address_bits) {
            machine.free_phys_contig(page, pages);
            return None;
        }
        let Some(va) = reserve(pages) else {
            machine.free_phys_contig(page, pages);
            return None;
        };
        machine.map_phys_range(va >> 12, pages, page, 0);
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, bytes) };
        Some(Self { va, phys, bytes })
    }

    /// # Safety
    /// This span must have a single owner and be disjoint from the controller's
    /// queues/descriptors. It must not yet be accessed by hardware.
    pub unsafe fn buffer(&self, offset: usize, bytes: usize) -> Buffer {
        assert!(offset.checked_add(bytes).is_some_and(|end| end <= self.bytes));
        unsafe { Buffer::dma(self.va + offset, self.phys + offset as u64, bytes) }
    }
}
