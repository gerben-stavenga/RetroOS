//! Linux vDSO policy. Architecture supplies only immutable clocksource facts.
const IMAGE: &[u8] = include_bytes!(env!("RETROOS_VDSO64"));
const CLOCK_DATA: usize = 0x800;
const PAGE: usize = 4096;

/// Install only when user RDTSC uses the kernel's stable, calibrated clock.
/// Other clock sources/backends retain libc's normal syscall fallback.
pub(super) fn install<A: crate::Arch>(machine: &mut A, floor: usize,
    occupied: &mut alloc::vec::Vec<(usize, usize)>) -> Option<usize>
{
    let (epoch, multiplier) = machine.user_tsc_clock()?;
    let base = super::file_mapping::allocate_below(
        super::elf::USER_STACK_TOP - 0x0100_0000, floor, PAGE, occupied)?;
    machine.map_fresh_range(base / PAGE, 1);
    machine.copy_to(base, IMAGE);
    machine.write::<u64>(base + CLOCK_DATA, epoch);
    machine.write::<u64>(base + CLOCK_DATA + 8, multiplier);
    machine.set_page_flags(base / PAGE, 1, false, true);
    occupied.push((base, base + PAGE));
    Some(base)
}
