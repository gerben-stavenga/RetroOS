//! EERD transport; the controller supplies its address and completion layout.
use super::{EERD, Hardware, wait};

pub(super) fn read_eerd(hw: &Hardware, word: u16, shift: u32, done: u32) -> Option<u16> {
    let registers = hw.registers;
    registers.write(EERD, 1 | ((word as u32) << shift));
    wait(registers, EERD, done, done, 10_000_000)?;
    Some((registers.read(EERD) >> 16) as u16)
}
