//! Kernel guest-memory access for device instructions.
use crate::Regs;
use arch_abi::entry::TrapAccess;
use planar::instruction::{FaultBus, Operands};

struct GuestAccess<'a, A>(&'a mut A);

unsafe impl<A: crate::Core> TrapAccess for GuestAccess<'_, A> {
    fn segment(&self, selector: u16) -> (u32, u32, bool) {
        (A::seg_base(selector), u32::MAX, A::seg_is_32(selector))
    }
    fn resident(&self, address: u32, len: u32, _: bool) -> bool {
        address.checked_add(len).is_some_and(|end| end <= 0xc000_0000)
    }
    unsafe fn read(&self, address: u32) -> u8 { self.0.read(u64::from(address)) }
    unsafe fn read_bytes(&self, address: u32, bytes: &mut [u8]) {
        self.0.copy_from(u64::from(address), bytes);
    }
    unsafe fn write(&mut self, address: u32, byte: u8) { self.0.write(u64::from(address), byte); }
    fn fpu_st0(&self) -> [u8; 10] { self.0.fpu_st0() }
    fn fpu_pop(&mut self) { self.0.fpu_pop(); }
}

struct VoodooBus<'a, A> {
    machine: &'a mut A,
    device: &'a mut super::vvoodoo::VVoodoo,
}
impl<A: crate::Core> FaultBus for VoodooBus<'_, A> {
    fn read8(&mut self, off: u32) -> u8 { self.device.read8(off) }
    fn write8(&mut self, off: u32, value: u8) { self.device.write8(off, value); }
    fn offset(&self, address: u32) -> Option<u32> { self.device.aperture_offset(address) }
    fn accessible(&self, _: u32, _: u32, _: bool) -> bool { true }
    fn guest_read(&self, address: u32) -> u8 { self.machine.read(u64::from(address)) }
    fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
        self.machine.copy_from(u64::from(address), bytes);
    }
    fn guest_write(&mut self, address: u32, value: u8) { self.machine.write(u64::from(address), value); }
    fn fpu_st0(&self) -> [u8; 10] { self.machine.fpu_st0() }
    fn fpu_pop(&mut self) { self.machine.fpu_pop(); }
    fn end_instruction(&mut self) { self.device.flush(); }
}

fn operands(regs: &mut Regs, access: impl FnOnce(&mut Operands<'_>) -> bool) -> bool {
    let (mut ip, mut flags) = (regs.ip32(), regs.flags32());
    let handled = access(&mut Operands::wide([&mut regs.rax, &mut regs.rcx, &mut regs.rdx,
        &mut regs.rbx, &mut regs.frame.rsp, &mut regs.rbp, &mut regs.rsi, &mut regs.rdi],
        &mut ip, &mut flags));
    regs.set_ip32(ip);
    regs.set_flags32(flags);
    handled
}

pub fn voodoo_fault<A: crate::Core>(machine: &mut A, regs: &mut Regs, device: &mut super::vvoodoo::VVoodoo,
    segments: &[u32; 6], default32: bool, offset: u32) -> bool {
    operands(regs, |regs| planar::instruction::emulate(&mut VoodooBus { machine, device },
        regs, segments[1], default32, segments, offset))
}

pub fn planar_fault<A: crate::Core>(machine: &mut A, regs: &mut Regs, state: &super::vga::LegacyVgaState,
    segments: &[u32; 6], limit: u32, default32: bool, address: u32) -> bool {
    let Some(planes) = super::vga::live_vram_ptr_if_initialized() else { return false };
    let planes = unsafe { planar::Memory::mapped(planes.as_ptr(), 4 * 65536) };
    operands(regs, |regs| planar::instruction::planar_fault(&state.registers, planes,
        &mut GuestAccess(machine), regs, segments, limit, default32, address))
}
