//! xHCI 1.2 sections 4.22.1 and 7.1: acquire ownership before resetting a
//! firmware-owned controller. Register access is supplied by the MMIO driver.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error { InvalidCapability, BiosOwned }

pub(super) fn acquire(
    hccparams1: u32,
    mut read: impl FnMut(usize) -> u32,
    mut write_os: impl FnMut(usize),
    mut write_control: impl FnMut(usize, u32),
    mut now: impl FnMut() -> u64,
) -> Result<(), Error> {
    let mut offset = (hccparams1 >> 16) as usize * 4;
    while offset != 0 {
        if !(0x20..=0x10000 - 4).contains(&offset) {
            return Err(Error::InvalidCapability);
        }
        let header = read(offset);
        if header == u32::MAX { return Err(Error::InvalidCapability); }
        if header & 255 == 1 {
            if offset > 0x10000 - 8 { return Err(Error::InvalidCapability); }
            // The two ownership semaphores occupy separate bytes. Updating
            // only the OS byte cannot overwrite a concurrent BIOS release.
            write_os(offset + 3);
            let start = now();
            let mut owned = false;
            for _ in 0..1_000_000 {
                if read(offset) & ((1 << 16) | (1 << 24)) == 1 << 24 {
                    owned = true;
                    break;
                }
                if now().wrapping_sub(start) >= 1_000_000_000 { break; }
                core::hint::spin_loop();
            }
            // Keep firmware's controller intact when handoff fails. The PS/2
            // path may still provide input through BIOS legacy USB emulation.
            if !owned { return Err(Error::BiosOwned); }
            let control = read(offset + 4);
            // Preserve RsvdP bits, clear all five SMI enables, acknowledge the
            // three RW1C events. The USBSTS shadow status bits are read-only.
            write_control(offset + 4, (control & 0x000e_1fee) | 0xe000_0000);
        }
        let next = ((header >> 8) & 255) as usize * 4;
        if next == 0 { break; }
        offset += next;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn ownership_precedes_smi_disable_and_preserves_reserved_bits() {
        let owner = Cell::new(1 | (1 << 16));
        let requested = Cell::new(false);
        let written = Cell::new(false);
        assert_eq!(acquire(0x20 << 16, |offset| match offset {
            0x80 => owner.get(), 0x84 => 0xffff_ffff, _ => panic!("bad offset"),
        }, |offset| {
            assert_eq!(offset, 0x83);
            requested.set(true);
            owner.set(1 | (1 << 24));
        }, |offset, value| {
            assert!(requested.get());
            assert_eq!(offset, 0x84);
            assert_eq!(value, 0xe00e_1fee);
            written.set(true);
        }, || 0), Ok(()));
        assert!(written.get());
    }

    #[test]
    fn stuck_bios_ownership_leaves_control_register_untouched() {
        let clock = Cell::new(0);
        assert_eq!(acquire(0x20 << 16, |_| 1 | (1 << 16) | (1 << 24),
            |_| {}, |_, _| panic!("BIOS still owns controller"), || {
                clock.set(clock.get() + 100_000_000);
                clock.get()
            }), Err(Error::BiosOwned));
    }

    #[test]
    fn optional_and_chained_capabilities_are_bounded_by_mapping() {
        assert_eq!(acquire(0, |_| panic!(), |_| panic!(), |_, _| panic!(), || 0), Ok(()));
        assert_eq!(acquire(0x3fff << 16, |_| 2 | (1 << 8),
            |_| panic!(), |_, _| panic!(), || 0), Err(Error::InvalidCapability));
        assert_eq!(acquire(0x3fff << 16, |_| 1,
            |_| panic!(), |_, _| panic!(), || 0), Err(Error::InvalidCapability));
    }
}
