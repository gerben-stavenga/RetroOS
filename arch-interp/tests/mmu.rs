//! Software-MMU tests driven through the public arch surface: demand paging at
//! a high (sparse) guest address, per-space isolation across an address-space
//! switch (`Arch::activate`, the same primitive the kernel uses), and unmap →
//! demand-zero.

use core::ptr::null_mut;
use retroos_arch_interp as arch;
use arch_abi::Arch;

const HI: usize = 0x4000_0000; // sparse high VA (a flat reservation would never fit)

/// Make space `id` the active one exactly as the kernel does — `Arch::activate`
/// moves it into the active slot and returns the displaced (previous) space.
fn switch(id: u32) -> arch::RootPageTable {
    arch::Interp.activate(arch::RootPageTable(id), null_mut(), null_mut())
}

#[test]
fn demand_isolation_and_unmap() {
    arch::init_guest_ram(0);

    // Demand-commit at a sparse high address (proves the reserved-VA model).
    arch::mem().write::<u32>(HI, 0xCAFE_BABE);
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE);

    // A second space is isolated; the first space's contents survive a round
    // trip through it.
    let other = arch::new_space();
    let saved = switch(other);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "new space must be zero-isolated");
    arch::mem().write::<u32>(HI, 0x1234_5678);

    switch(saved.0); // back to the original space
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE, "space 0 preserved");

    // Unmap drops the page; the next access demand-zeroes it.
    arch::arch_unmap_range(HI / 4096, 1);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "unmapped page reads back zero");
}
