//! Linux-style controller descriptions and MAC/PHY/NVM operation tables.
//! PCI IDs select a complete implementation, not merely a register layout.
//! PCH/I219 needs its own operations before its PCI IDs can be added.
use super::{CTRL, EERD, ICR, IMC, MDIC, Mmio, RCTL, STATUS, TCTL, portio};

mod i82540;
mod i82574;
mod mac;
mod nvm;
mod phy;

pub(super) struct MacOps {
    pub reset: fn(&Hardware) -> Option<()>,
    pub setup_link: fn(&Hardware) -> Option<()>,
    pub configure: fn(&Hardware),
}
pub(super) struct PhyOps {
    pub read: fn(&Hardware, u32) -> Option<u16>,
    pub write: fn(&Hardware, u32, u16) -> Option<()>,
}
pub(super) struct NvmOps {
    pub read: fn(&Hardware, u16) -> Option<u16>,
}

pub(super) struct Controller {
    pub name: &'static str,
    pub mac: MacOps,
    pub phy: PhyOps,
    pub nvm: NvmOps,
}

impl Controller {
    pub fn identify(id: u32) -> Option<&'static Self> {
        // Explicit support table: related PCI IDs can require different PHY,
        // firmware ownership, reset and NVM access protocols.
        match id {
            0x100e_8086 => Some(&i82540::INFO),
            0x10d3_8086 => Some(&i82574::INFO),
            _ => None,
        }
    }
}

pub(super) struct Hardware {
    pub registers: Mmio,
    pub controller: &'static Controller,
}
impl Hardware {
    pub fn reset(&self) -> Option<()> {
        (self.controller.mac.reset)(self)
    }
    pub fn mac_address(&self) -> Option<[u8; 6]> {
        let mut mac = [0; 6];
        for word in 0..3 {
            let value = (self.controller.nvm.read)(self, word as u16)?;
            mac[word * 2..word * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
    }
    pub fn setup_link(&self) -> Option<()> {
        (self.controller.mac.setup_link)(self)
    }
    pub fn configure(&self) {
        (self.controller.mac.configure)(self)
    }
}

pub(super) fn delay(ns: u64) {
    let until = portio::now_ns().saturating_add(ns);
    while portio::now_ns() < until {
        core::hint::spin_loop();
    }
}
pub(super) fn wait(
    registers: Mmio,
    register: usize,
    mask: u32,
    expected: u32,
    timeout: u64,
) -> Option<()> {
    let until = portio::now_ns().saturating_add(timeout);
    loop {
        let value = registers.read(register);
        if value == u32::MAX {
            return None;
        }
        if value & mask == expected {
            return Some(());
        }
        if portio::now_ns() >= until {
            return None;
        }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_selection_rejects_unimplemented_controllers() {
        assert_eq!(Controller::identify(0x100e8086).unwrap().name, "82540EM");
        assert_eq!(Controller::identify(0x10d38086).unwrap().name, "82574L");
        for id in [0x100e1234, 0x10008086, 0x15b88086, 0x15f38086, 0xffffffff] {
            assert!(Controller::identify(id).is_none());
        }
    }

    // Exercise the shared MAC-address reader through a different NVM backend:
    // its contents and read failures must reach the caller without EERD access.
    static TEST_CONTROLLER: Controller = Controller {
        name: "test",
        mac: MacOps {
            reset: mac::reset,
            setup_link: mac::setup_copper_link,
            configure: mac::configure,
        },
        phy: phy::MDIC_OPS,
        nvm: NvmOps {
            read: |hw, word| {
                let value = hw.registers.read(word as usize * 4);
                (value != u32::MAX).then_some(value as u16)
            },
        },
    };

    #[test]
    fn mac_address_uses_selected_nvm_and_propagates_failures() {
        let mut words = [0x1102u32, 0x3322, 0x5544];
        let hw = Hardware {
            registers: unsafe { Mmio::test_mapping(words.as_mut_ptr(), 12) },
            controller: &TEST_CONTROLLER,
        };
        assert_eq!(hw.mac_address(), Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        hw.registers.write(4, u32::MAX);
        assert_eq!(hw.mac_address(), None);
        hw.registers.write(4, 0x3322);
        hw.registers.write(0, 0x1103); // Multicast cannot be a station address.
        assert_eq!(hw.mac_address(), None);
        for offset in [0, 4, 8] {
            hw.registers.write(offset, 0);
        }
        assert_eq!(hw.mac_address(), None);
    }
}
