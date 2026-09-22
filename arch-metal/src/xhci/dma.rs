//! xHCI DMA layout and scratchpad allocation, independent of MMIO.

pub(super) const DCBAA_OFF: usize = 0x0000; // device-context base address array
pub(super) const CMD_OFF: usize = 0x1000; // command ring (256 TRBs)
pub(super) const EVT_OFF: usize = 0x2000; // event ring (256 TRBs)
pub(super) const ERST_OFF: usize = 0x3000; // event ring segment table (1 entry)
pub(super) const INCTX_OFF: usize = 0x4000; // input context (Address Device / Configure EP)
pub(super) const DEVCTX0_OFF: usize = 0x5000; // retained device lane 0: output context
pub(super) const EP0_0_OFF: usize = 0x6000; // retained device lane 0: control transfer ring
pub(super) const XFER_OFF: usize = 0x7000; // control-transfer data buffer (descriptors)
pub(super) const INT0_OFF: usize = 0x8000; // HID interrupt pipe 0 transfer ring
pub(super) const REPORT0_OFF: usize = 0x9000; // HID interrupt pipe 0 report buffer
pub(super) const DEVCTX1_OFF: usize = 0xA000;
pub(super) const EP0_1_OFF: usize = 0xB000;
pub(super) const INT1_OFF: usize = 0xC000;
pub(super) const REPORT1_OFF: usize = 0xD000;
// The ten-bit scratchpad count can require 1023 pointers (two pages).
pub(super) const SCRATCH_OFF: usize = 0xE000;
pub(super) const DMA_PAGES: usize = 16;

/// Fill the array before publishing it to the controller. Scratchpad pages
/// need not be contiguous. The allocator returns permanent, zeroed DMA pages;
/// on failure the caller leaves the controller halted and the array unpublished.
pub(super) fn scratchpads(
    hcsp2: u32,
    array: &mut [u64],
    mut allocate_zeroed: impl FnMut() -> Option<u64>,
) -> Option<usize> {
    let count = ((((hcsp2 >> 21) & 31) << 5) | ((hcsp2 >> 27) & 31)) as usize;
    let entries = array.get_mut(..count)?;
    for entry in entries {
        *entry = allocate_zeroed()?;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x99_requires_sixteen_separate_zeroed_pages() {
        let mut array = [0; 1024];
        let mut allocated = 0;
        assert_eq!(scratchpads(0x84000054, &mut array, || {
            allocated += 1;
            Some(allocated * 0x3000)
        }), Some(16));
        assert_eq!(allocated, 16);
        assert_eq!(&array[..3], &[0x3000, 0x6000, 0x9000]);
        assert_eq!(array[15], 16 * 0x3000);
        assert_eq!(array[16], 0);
    }

    #[test]
    fn full_ten_bit_count_fits_without_touching_other_dma_structures() {
        let mut array = [0; (DMA_PAGES * 4096 - SCRATCH_OFF) / 8];
        assert_eq!(scratchpads((31 << 21) | (31 << 27), &mut array,
                              || Some(0x100000)), Some(1023));
        assert_eq!(array[1022], 0x100000);
        assert_eq!(array[1023], 0);
        let regions = [DCBAA_OFF, CMD_OFF, EVT_OFF, ERST_OFF, INCTX_OFF,
                       DEVCTX0_OFF, EP0_0_OFF, XFER_OFF, INT0_OFF, REPORT0_OFF,
                       DEVCTX1_OFF, EP0_1_OFF, INT1_OFF, REPORT1_OFF];
        for (i, offset) in regions.iter().enumerate() {
            assert!(offset + 4096 <= SCRATCH_OFF);
            assert_eq!(offset % 4096, 0);
            assert!(!regions[..i].contains(offset));
        }
    }

    #[test]
    fn zero_scratchpads_and_allocation_failure() {
        assert_eq!(scratchpads(0, &mut [], || panic!("must not allocate")), Some(0));
        let mut array = [0; 16];
        let mut calls = 0;
        assert_eq!(scratchpads(0x84000054, &mut array, || {
            calls += 1;
            (calls < 4).then_some(0x100000)
        }), None);
        assert_eq!(calls, 4);
        assert_eq!(array[3], 0);
        assert_eq!(scratchpads(0x84000054, &mut [0; 8],
                              || panic!("array too small")), None);
    }
}
