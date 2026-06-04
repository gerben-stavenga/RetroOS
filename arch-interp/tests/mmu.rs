//! Software-MMU tests driven through the public arch surface: demand paging at
//! a high (sparse) guest address, per-space isolation across `arch_switch_to`,
//! and unmap → demand-zero.

use core::ptr::null_mut;
use retroos_arch_interp as arch;

const HI: usize = 0x4000_0000; // sparse high VA (a flat reservation would never fit)

/// Switch the active space to `id` by handing `arch_switch_to` a Vcpu carrying
/// that space; returns the Vcpu (now holding the saved outgoing space).
fn switch(id: u32) -> arch::Vcpu {
    let mut v = arch::Vcpu::empty();
    v.space = arch::RootPageTable(id);
    arch::arch_switch_to(&mut v, null_mut(), null_mut());
    v
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
    let mut saved = switch(other);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "new space must be zero-isolated");
    arch::mem().write::<u32>(HI, 0x1234_5678);

    arch::arch_switch_to(&mut saved, null_mut(), null_mut()); // back to space 0
    assert_eq!(arch::mem().read::<u32>(HI), 0xCAFE_BABE, "space 0 preserved");

    // Unmap drops the page; the next access demand-zeroes it.
    arch::arch_unmap_range(HI / 4096, 1);
    assert_eq!(arch::mem().read::<u32>(HI), 0, "unmapped page reads back zero");
}
