//! Guest-memory view for the shared sensitive-instruction monitor
//! (`arch_abi::monitor`), used identically by both engines.

use arch_abi::monitor::GuestView;

/// Hosted guest-memory view for the shared sensitive-instruction monitor.
///
/// Bound by `&mut` to the **interpreted thread's** address space — the
/// `RootPageTable` (a space id) carried in the live `REGS`. This is the only
/// correct basis for the monitor's reads/writes: the kernel moves the globally
/// `active` space around to peek other spaces (exec argv copy, focus VGA
/// snapshot), and the executing CPU's CR3 follows `active`, so neither names
/// the thread we are decoding. Resolving through the thread's own space id
/// (never `active`) is the software-MMU analogue of metal, where the faulting
/// thread's page tables are simply live during the #GP. The `&mut` is exactly
/// the "mut ref to the thread" guest writes (PUSHF/INT frames) and demand-paged
/// reads require.
///
/// All addresses are linear; access is byte-wise so a 16/32-bit access that
/// straddles a page boundary still lands correctly.
pub(crate) struct InterpView<'a> {
    pub(crate) space: &'a mut crate::space::RootPageTable,
}

impl InterpView<'_> {
    #[inline]
    fn load<const N: usize>(&mut self, lin: u32) -> [u8; N] {
        let id = self.space.0;
        let mut b = [0u8; N];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = unsafe { *crate::paging::resolve_in_space(id, lin.wrapping_add(i as u32)) };
        }
        b
    }
    #[inline]
    fn store(&mut self, lin: u32, src: &[u8]) {
        let id = self.space.0;
        for (i, &byte) in src.iter().enumerate() {
            unsafe { *crate::paging::resolve_in_space(id, lin.wrapping_add(i as u32)) = byte; }
        }
    }
}

impl GuestView for InterpView<'_> {
    #[inline]
    fn read8(&mut self, lin: u32) -> u8 { self.load::<1>(lin)[0] }
    #[inline]
    fn read16(&mut self, lin: u32) -> u16 { u16::from_le_bytes(self.load::<2>(lin)) }
    #[inline]
    fn read32(&mut self, lin: u32) -> u32 { u32::from_le_bytes(self.load::<4>(lin)) }
    #[inline]
    fn write16(&mut self, lin: u32, val: u16) { self.store(lin, &val.to_le_bytes()); }
    #[inline]
    fn write32(&mut self, lin: u32, val: u32) { self.store(lin, &val.to_le_bytes()); }
    #[inline]
    fn seg_base(&mut self, sel: u16) -> u32 { crate::desc::seg_base(sel) }
    #[inline]
    fn seg_is_32(&mut self, sel: u16) -> bool { crate::desc::seg_is_32(sel) }
    #[inline]
    fn int_intercepted(&mut self, vector: u8) -> bool { crate::desc::int_intercepted(vector) }
}
