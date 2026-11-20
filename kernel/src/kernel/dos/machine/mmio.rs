//! Kernel device selection and guest-memory policy for the shared decoder.
use crate::Regs;
use super::vga::{self, LegacyVgaState};
use planar::instruction::{Operands, FaultBus, emulate};

/// Decode and emulate a faulting device-window access at offset `off`. `cs_base`/
/// `def32` (default operand & address size) are resolved by the caller, which
/// has the LDT. Returns false (→ real SEGV) for an instruction we don't model,
/// so a gap is loud rather than silent corruption.
#[allow(clippy::too_many_arguments)] // planar #PF decode needs the full seg/mode context
/// What a trapped memory-window access is talking to.
///
/// A closed set defined by RetroOS (see `dyn` vs enum: the variants are ours,
/// not an external standard), so it is an enum with an exhaustive match. Both
/// devices present a window the guest writes with ordinary instructions, and
/// both need the *same* instruction decoder below — the only difference is
/// where the bytes land.
pub enum MmioTarget<'a> {
    /// The VGA planar aperture selected by GC[6], through the graphics
    /// controller. Text-font access commonly selects B8000 rather than A0000.
    Planar { vga: &'a mut LegacyVgaState, base: u32, len: u32 },
    /// The Voodoo's PCI aperture: registers, LFB and texture download.
    Voodoo(&'a mut super::vvoodoo::VVoodoo),
}

impl MmioTarget<'_> {
    #[inline]
    fn write8<A: crate::Arch>(&mut self, _machine: &mut A, off: u32, val: u8) {
        match self {
            Self::Planar { vga, .. } => vga::vram_write(_machine, vga, off, val),
            Self::Voodoo(vd) => vd.write8(off, val),
        }
    }

    #[inline]
    fn read8<A: crate::Arch>(&mut self, _machine: &mut A, off: u32) -> u8 {
        match self {
            Self::Planar { vga, .. } => vga::vram_read(_machine, vga, off),
            Self::Voodoo(vd) => vd.read8(off),
        }
    }

    /// End of the faulting instruction. The Voodoo commits any partial dword
    /// here; the VGA has nothing to settle, every byte already landed.
    #[inline]
    fn end_instruction(&mut self) {
        match self {
            Self::Voodoo(vd) => vd.flush(),
            Self::Planar { .. } => {},
        }
    }

    /// Offset of a guest linear address within this window, if it lands there.
    ///
    /// String ops can have either operand inside the trapped window, so they
    /// have to ask per byte instead of assuming A0000 the way this decoder did
    /// when the VGA was its only caller.
    #[inline]
    fn offset(&self, addr: u32) -> Option<u32> {
        match self {
            Self::Planar { base, len, .. } =>
                (*base..base.saturating_add(*len)).contains(&addr).then(|| addr - *base),
            Self::Voodoo(vd) => vd.aperture_offset(addr),
        }
    }
}


struct BackendBus<'a, 'b, A: crate::Arch> { machine: &'a mut A, target: &'a mut MmioTarget<'b> }
impl<A: crate::Arch> FaultBus for BackendBus<'_, '_, A> {
    fn read8(&mut self, off: u32) -> u8 { self.target.read8(self.machine, off) }
    fn write8(&mut self, off: u32, value: u8) { self.target.write8(self.machine, off, value); }
    fn offset(&self, address: u32) -> Option<u32> { self.target.offset(address) }
    fn accessible(&self, _: u32, _: u32, _: bool) -> bool { true }
    fn guest_read(&self, address: u32) -> u8 { self.machine.read::<u8>(address as u64) }
    fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
        self.machine.copy_from(u64::from(address), bytes);
    }
    fn guest_write(&mut self, address: u32, value: u8) { self.machine.write(address as u64, value); }
    fn fpu_st0(&self) -> [u8; 10] { self.machine.fpu_st0() }
    fn fpu_pop(&mut self) { self.machine.fpu_pop(); }
    fn end_instruction(&mut self) { self.target.end_instruction(); }
}

pub fn handle_mmio_fault<A: crate::Arch>(machine: &mut A, regs: &mut Regs, target: &mut MmioTarget<'_>, segments: &[u32; 6], def32: bool, off: u32) -> bool {
    let (mut ip, mut flags) = (regs.ip32(), regs.flags32());
    let handled = emulate(&mut BackendBus { machine, target },
        &mut Operands::wide([&mut regs.rax, &mut regs.rcx, &mut regs.rdx,
            &mut regs.rbx, &mut regs.frame.rsp, &mut regs.rbp, &mut regs.rsi, &mut regs.rdi],
            &mut ip, &mut flags),
        segments[1], def32, segments, off);
    regs.set_ip32(ip);
    regs.set_flags32(flags);
    handled
}
