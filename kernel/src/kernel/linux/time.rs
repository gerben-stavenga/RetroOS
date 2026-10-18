//! Linux time structures have ABI-sized words, independent of kernel bitness.
use super::{Args, EFAULT, EINVAL, SyscallResult};
const TICK_NS: u64 = 10_000_000;
fn supported(clock: u64) -> bool {
    matches!(clock, 0 | 1 | 4 | 5 | 6 | 7)
}
fn pair(seconds: u64, fraction: u64, wide: bool) -> ([u8; 16], usize) {
    let mut out = [0; 16];
    if wide {
        out[..8].copy_from_slice(&seconds.to_le_bytes());
        out[8..].copy_from_slice(&fraction.to_le_bytes());
        (out, 16)
    } else {
        out[..4].copy_from_slice(&(seconds as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(fraction as u32).to_le_bytes());
        (out, 8)
    }
}
fn store<A: crate::Arch>(machine: &mut A, pointer: u64, seconds: u64, fraction: u64, wide: bool) {
    let (bytes, n) = pair(seconds, fraction, wide);
    machine.copy_to(pointer as usize, &bytes[..n]);
}
fn realtime() -> u64 {
    u64::from(crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0))
}
pub(super) fn clock_gettime<A: crate::Arch>(
    machine: &mut A,
    args: &Args,
    wide: bool,
) -> SyscallResult {
    if !supported(args.a0) {
        return SyscallResult::val(-EINVAL);
    }
    if args.a1 == 0 {
        return SyscallResult::val(-EFAULT);
    }
    let (seconds, nanos) = if matches!(args.a0, 0 | 5) {
        (realtime(), 0)
    } else {
        let ticks = machine.get_ticks();
        (ticks / 100, (ticks % 100) * TICK_NS)
    };
    store(machine, args.a1, seconds, nanos, wide);
    SyscallResult::val(0)
}
pub(super) fn clock_getres<A: crate::Arch>(
    machine: &mut A,
    args: &Args,
    wide: bool,
) -> SyscallResult {
    if !supported(args.a0) {
        return SyscallResult::val(-EINVAL);
    }
    if args.a1 != 0 {
        let realtime = matches!(args.a0, 0 | 5);
        store(
            machine,
            args.a1,
            u64::from(realtime),
            if realtime { 0 } else { TICK_NS },
            wide,
        );
    }
    SyscallResult::val(0)
}
pub(super) fn gettimeofday<A: crate::Arch>(
    machine: &mut A,
    args: &Args,
    wide: bool,
) -> SyscallResult {
    if args.a0 != 0 {
        store(machine, args.a0, realtime(), 0, wide);
    }
    if args.a1 != 0 {
        machine.copy_to(args.a1 as usize, &[0; 8]);
    }
    SyscallResult::val(0)
}
pub(super) fn time<A: crate::Arch>(machine: &mut A, args: &Args, wide: bool) -> SyscallResult {
    let seconds = realtime();
    if args.a0 != 0 {
        let bytes = seconds.to_le_bytes();
        machine.copy_to(args.a0 as usize, &bytes[..if wide { 8 } else { 4 }]);
    }
    SyscallResult::val64(seconds as i64)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timespec_and_timeval_fields_follow_the_guest_word_size() {
        let (bytes, n) = pair(1_792_345_678, 987_654_321, true);
        assert_eq!(n, 16);
        assert_eq!(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            1_792_345_678
        );
        assert_eq!(
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
            987_654_321
        );
        let (bytes, n) = pair(1_792_345_678, 987_654_321, false);
        assert_eq!(n, 8);
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            1_792_345_678
        );
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            987_654_321
        );
        assert!(!supported(u64::MAX));
        assert!(supported(1));
    }
}
