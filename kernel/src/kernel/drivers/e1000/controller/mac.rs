//! Shared MAC operations for the supported discrete controllers.
use super::{CTRL, Hardware, ICR, IMC, RCTL, STATUS, TCTL, delay, wait};

pub(super) fn reset(hw: &Hardware) -> Option<()> {
    let registers = hw.registers;
    registers.write(IMC, u32::MAX);
    registers.write(RCTL, 0);
    registers.write(TCTL, 0);
    let _ = registers.read(STATUS);
    delay(10_000_000);
    registers.write(CTRL, registers.read(CTRL) | (1 << 26));
    wait(registers, CTRL, 1 << 26, 0, 100_000_000)?;
    // Allow NVM autoload before reading EEPROM or programming the PHY.
    delay(20_000_000);
    registers.write(IMC, u32::MAX);
    let _ = registers.read(ICR);
    Some(())
}

pub(super) fn setup_copper_link(hw: &Hardware) -> Option<()> {
    let control = (hw.controller.phy.read)(hw, 0)?;
    (hw.controller.phy.write)(
        hw,
        0,
        (control & !((1 << 11) | (1 << 10))) | (1 << 12) | (1 << 9),
    )?;
    let registers = hw.registers;
    let ctrl = registers.read(CTRL) & !((1 << 3) | (1 << 11) | (1 << 12) | (1 << 30) | (1 << 31));
    registers.write(CTRL, ctrl | (1 << 6) | (1 << 5)); // Link up, auto speed.
    Some(())
}

pub(super) fn configure(hw: &Hardware) {
    hw.registers.write(0x5000, 0); // RXCSUM: software checksums.
    hw.registers.write(IMC, u32::MAX);
}
