//! 82574L controller operations (handled by e1000e in Linux).
use super::{Controller, Hardware, MacOps, NvmOps, mac, nvm, phy, wait};

pub(super) static INFO: Controller = Controller {
    name: "82574L",
    mac: MacOps {
        reset,
        setup_link,
        configure,
    },
    phy: phy::MDIC_OPS,
    nvm: NvmOps { read: read_nvm },
};

fn reset(hw: &Hardware) -> Option<()> {
    mac::reset(hw)?;
    wait(hw.registers, 0x10, 1 << 9, 1 << 9, 100_000_000)?;
    hw.registers.write(0x5800, 0); // Disable wakeup filters.
    Some(())
}
fn read_nvm(hw: &Hardware, word: u16) -> Option<u16> {
    nvm::read_eerd(hw, word, 2, 1 << 1)
}
fn setup_link(hw: &Hardware) -> Option<()> {
    mac::setup_copper_link(hw)?;
    hw.registers
        .write(0x18, hw.registers.read(0x18) | (1 << 28)); // DRV_LOAD
    Some(())
}
fn configure(hw: &Hardware) {
    mac::configure(hw);
    let registers = hw.registers;
    registers.write(0x5008, 0); // RFCTL: legacy receive descriptors.
    registers.write(0xe0, 0); // IAM: no automatic interrupt masks.
    registers.write(0x281c, 0);
    registers.write(0x282c, 0);
    registers.write(0x3820, 0);
    registers.write(0x382c, 0);
}
