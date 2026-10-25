//! Optional per-program DOS CPU duty limit, independent of rendering.
//! Devices keep wall-clock time; only guest execution is delayed. This is
//! a percentage of native execution time, not an emulated MHz guarantee.

#[derive(Clone, Copy)]
pub struct CpuPacer {
    percent: u8,
    next_ns: u64,
}

impl Default for CpuPacer {
    fn default() -> Self { Self { percent: 100, next_ns: 0 } }
}

impl CpuPacer {
    pub fn from_percent(percent: u8) -> Self {
        if (1..=100).contains(&percent) { Self { percent, next_ns: 0 } }
        else { Self::default() }
    }

    pub fn from_env(env: &[u8]) -> Self {
        for entry in env.split(|&b| b == 0).take_while(|s| !s.is_empty()) {
            let Some(eq) = entry.iter().position(|&b| b == b'=') else { continue };
            if !entry[..eq].eq_ignore_ascii_case(b"DOS_CPU_PERCENT") { continue; }
            let value = &entry[eq + 1..];
            let percent = value.iter().try_fold(0u8, |n, &b| {
                if !b.is_ascii_digit() { return None; }
                n.checked_mul(10)?.checked_add(b - b'0')
            });
            if let Some(percent @ 1..=100) = percent {
                return Self { percent, next_ns: 0 };
            }
            break;
        }
        Self::default()
    }

    pub fn percent(&self) -> u8 { self.percent }
    pub fn limited(&self) -> bool { self.percent < 100 }
    pub fn ready(&self, now: u64) -> bool { now >= self.next_ns }

    pub fn charge(&mut self, start: u64, end: u64) {
        let delay = end.saturating_sub(start)
            .saturating_mul(u64::from(100 - self.percent)) / u64::from(self.percent);
        // A host scheduling pause must not create seconds of guest debt.
        // Charge only the most recent slice, never accumulate missed quotas.
        self.next_ns = end.saturating_add(delay.min(20_000_000));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_policy_keeps_cpu_and_xms_bits_separate() {
        let policy = super::super::LaunchPolicy::from_synth((5 << 10) | 0x100 | 0x200 | 2);
        assert_eq!(policy.cpu_percent, 25);
        assert_eq!(policy.viopl, 2);
        assert!(policy.xms32k);
        assert_eq!(super::super::LaunchPolicy::from_synth(1).cpu_percent, 0);
        assert_eq!(super::super::LaunchPolicy::from_synth(0x0201).cpu_percent, 0);
        assert_eq!(super::super::LaunchPolicy::from_synth(20 << 10).cpu_percent, 100);
        assert_eq!(super::super::LaunchPolicy::from_synth(63 << 10).cpu_percent, 0);
    }

    #[test]
    fn environment_is_bounded_and_stops_at_dos_terminator() {
        assert_eq!(CpuPacer::from_env(b"PATH=C:\\DOS\0dos_cpu_percent=25\0\0").percent(), 25);
        for env in [b"DOS_CPU_PERCENT=0\0".as_slice(), b"DOS_CPU_PERCENT=101\0",
            b"DOS_CPU_PERCENT=999999999\0", b"DOS_CPU_PERCENT=\0",
            b"DOS_CPU_PERCENT=-1\0", b"DOS_CPU_PERCENT=25x\0",
            b"PATH=C:\\DOS\0\0DOS_CPU_PERCENT=25\0"] {
            assert!(!CpuPacer::from_env(env).limited());
        }
    }

    #[test]
    fn duty_limit_counts_elapsed_kernel_time_without_banked_credit() {
        let mut p = CpuPacer::from_env(b"DOS_CPU_PERCENT=25\0");
        p.charge(1_000_000, 2_000_000);
        assert!(!p.ready(4_999_999));
        assert!(p.ready(5_000_000));
        // Time away from this thread grants no burst when it resumes.
        p.charge(100_000_000, 101_000_000);
        assert!(!p.ready(103_999_999));
        assert!(p.ready(104_000_000));
    }

    #[test]
    fn unlimited_and_long_or_reversed_clock_samples_are_safe() {
        let mut p = CpuPacer::default();
        p.charge(0, 1_000_000);
        assert!(p.ready(1_000_000));
        let mut p = CpuPacer::from_env(b"DOS_CPU_PERCENT=1\0");
        p.charge(0, 1_000_000_000);
        assert!(p.ready(1_020_000_000));
        p.charge(100, 50);
        assert!(p.ready(50));
        p.charge(0, u64::MAX);
        assert!(p.ready(u64::MAX));
    }
}
