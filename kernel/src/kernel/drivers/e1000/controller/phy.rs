//! Shared MDIC access. Both supported copper PHYs use MDIO address 1.
use super::{Hardware, MDIC, PhyOps, wait};

pub(super) const MDIC_OPS: PhyOps = PhyOps { read, write };

fn read(hw: &Hardware, register: u32) -> Option<u16> {
    access(hw, register, None)
}
fn write(hw: &Hardware, register: u32, value: u16) -> Option<()> {
    access(hw, register, Some(value)).map(|_| ())
}
fn access(hw: &Hardware, register: u32, value: Option<u16>) -> Option<u16> {
    if register > 31 {
        return None;
    }
    let registers = hw.registers;
    registers.write(
        MDIC,
        (1 << 21)
            | (register << 16)
            | match value {
                Some(v) => (1 << 26) | v as u32,
                None => 2 << 26,
            },
    );
    wait(registers, MDIC, 1 << 28, 1 << 28, 10_000_000)?;
    let result = registers.read(MDIC);
    (result & (1 << 30) == 0).then_some(result as u16)
}
