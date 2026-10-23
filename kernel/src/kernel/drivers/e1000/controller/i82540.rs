//! 82540EM controller operations (handled by e1000 in Linux).
use super::{Controller, Hardware, MacOps, NvmOps, mac, nvm, phy};

pub(super) static INFO: Controller = Controller {
    name: "82540EM",
    mac: MacOps {
        reset,
        setup_link: mac::setup_copper_link,
        configure: mac::configure,
    },
    phy: phy::MDIC_OPS,
    nvm: NvmOps { read: read_nvm },
};

fn reset(hw: &Hardware) -> Option<()> {
    mac::reset(hw)?;
    hw.registers.write(0x5800, 0); // Disable wakeup filters.
    Some(())
}
fn read_nvm(hw: &Hardware, word: u16) -> Option<u16> {
    nvm::read_eerd(hw, word, 8, 1 << 4)
}
