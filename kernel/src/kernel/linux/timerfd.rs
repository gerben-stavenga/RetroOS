//! timerfd: a deadline on the kernel clock. The expiry count is derived from
//! the clock on demand, never ticked, so an idle timer costs nothing.
use super::{EFAULT, EINVAL, high_memory};

const TFD_NONBLOCK: u64 = 0x800;
const TFD_CLOEXEC: u64 = 0x80000;
const TFD_TIMER_ABSTIME: u64 = 1;
const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
const EPERM: i32 = 1;
const SECOND: u64 = 1_000_000_000;

pub(super) struct Timer {
    realtime: bool,
    /// First unread expiry, in `Arch::now` nanoseconds.
    expiry: Option<u64>,
    interval: u64,
    pub(super) nonblocking: bool,
}

/// One itimerspec half: (interval, value), both in nanoseconds.
pub(super) type Spec = (u64, u64);

impl Timer {
    pub(super) fn new(clock: u64, flags: u64) -> Result<Self, i32> {
        if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 { return Err(-EINVAL); }
        let realtime = match clock {
            0 => true,
            1 | 7 => false,
            8 | 9 => return Err(-EPERM), // *_ALARM needs CAP_WAKE_ALARM.
            _ => return Err(-EINVAL),
        };
        Ok(Self { realtime, expiry: None, interval: 0, nonblocking: flags & TFD_NONBLOCK != 0 })
    }
    pub(super) fn cloexec(flags: u64) -> bool { flags & TFD_CLOEXEC != 0 }

    pub(super) fn expirations(&self, now: u64) -> u64 {
        match self.expiry {
            Some(expiry) if now >= expiry => {
                if self.interval == 0 { 1 } else { 1 + (now - expiry) / self.interval }
            }
            _ => 0,
        }
    }
    /// The next expiry still in the future, for waking a parked waiter.
    pub(super) fn next_fire(&self, now: u64) -> Option<u64> {
        let expiry = self.expiry?;
        if now < expiry { Some(expiry) }
        else if self.interval == 0 { None }
        else { Some(expiry.saturating_add(self.expirations(now).saturating_mul(self.interval))) }
    }
    /// read(): consume and return the pending expirations.
    pub(super) fn take(&mut self, now: u64) -> u64 {
        let n = self.expirations(now);
        if n != 0 {
            self.expiry = (self.interval != 0)
                .then(|| self.expiry.unwrap().saturating_add(n.saturating_mul(self.interval)));
        }
        n
    }
    /// timerfd_gettime(): (interval, time until the next expiry).
    pub(super) fn current(&self, now: u64) -> Spec {
        (self.interval, self.next_fire(now).map_or(0, |end| end - now))
    }
    /// timerfd_settime(). `realtime_now` is CLOCK_REALTIME in nanoseconds,
    /// used only to place an absolute realtime deadline on the kernel clock.
    pub(super) fn set(&mut self, now: u64, realtime_now: u64, flags: u64, (interval, value): Spec) -> Result<Spec, i32> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 { return Err(-EINVAL); }
        let old = self.current(now);
        self.interval = interval;
        self.expiry = if value == 0 {
            None
        } else if flags & TFD_TIMER_ABSTIME == 0 {
            Some(now.saturating_add(value))
        } else if self.realtime {
            Some(now.saturating_add(value.saturating_sub(realtime_now)))
        } else {
            Some(value)
        };
        // CANCEL_ON_SET never fires: RetroOS has no way to step CLOCK_REALTIME.
        Ok(old)
    }
}

/// Read a struct itimerspec { it_interval, it_value }.
pub(super) fn read_spec<A: crate::Arch>(machine: &mut A, address: u64) -> Result<Spec, i32> {
    let mut bytes = [0; 32];
    if !high_memory::copy_from(machine, address, &mut bytes) { return Err(-EFAULT); }
    let half = |at: usize| {
        let seconds = i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let nanos = i64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
        if seconds < 0 || !(0..SECOND as i64).contains(&nanos) { return Err(-EINVAL); }
        Ok((seconds as u64).saturating_mul(SECOND).saturating_add(nanos as u64))
    };
    Ok((half(0)?, half(16)?))
}
pub(super) fn write_spec<A: crate::Arch>(machine: &mut A, address: u64, (interval, value): Spec) -> bool {
    let mut bytes = [0; 32];
    for (at, ns) in [(0, interval), (16, value)] {
        bytes[at..at + 8].copy_from_slice(&(ns / SECOND).to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&(ns % SECOND).to_le_bytes());
    }
    high_memory::copy_to(machine, address, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn armed(interval: u64, value: u64) -> Timer {
        let mut t = Timer::new(1, 0).unwrap();
        t.set(1000, 0, 0, (interval, value)).unwrap();
        t
    }
    #[test]
    fn one_shot_fires_once_then_disarms() {
        let mut t = armed(0, 50);
        assert_eq!(t.expirations(1049), 0);
        assert_eq!(t.expirations(5000), 1);
        assert_eq!(t.take(5000), 1);
        assert_eq!(t.take(9000), 0);
        assert_eq!(t.current(9000), (0, 0));
        assert_eq!(t.next_fire(9000), None);
    }
    #[test]
    fn periodic_counts_overruns_and_stays_in_phase() {
        let mut t = armed(10, 50); // fires at 1050, 1060, 1070, ...
        assert_eq!(t.take(1075), 3);
        assert_eq!(t.next_fire(1075), Some(1080));
        assert_eq!(t.current(1075), (10, 5));
        assert_eq!(t.take(1079), 0);
        assert_eq!(t.take(1080), 1);
    }
    #[test]
    fn rearm_returns_old_value_and_disarm_clears() {
        let mut t = armed(0, 50);
        assert_eq!(t.set(1020, 0, 0, (0, 0)).unwrap(), (0, 30));
        assert_eq!(t.expirations(1_000_000), 0);
    }
    #[test]
    fn absolute_deadlines_per_clock() {
        let mut mono = Timer::new(1, 0).unwrap();
        mono.set(1000, 0, TFD_TIMER_ABSTIME, (0, 1500)).unwrap();
        assert_eq!(mono.next_fire(1000), Some(1500));
        let mut real = Timer::new(0, 0).unwrap();
        real.set(1000, 7 * SECOND, TFD_TIMER_ABSTIME, (0, 7 * SECOND + 300)).unwrap();
        assert_eq!(real.next_fire(1000), Some(1300));
        real.set(1000, 7 * SECOND, TFD_TIMER_ABSTIME, (0, 5 * SECOND)).unwrap();
        assert_eq!(real.expirations(1000), 1); // a past absolute deadline is already due
    }
    #[test]
    fn rejects_bad_clocks_and_flags() {
        assert_eq!(Timer::new(2, 0).err(), Some(-EINVAL));
        assert_eq!(Timer::new(8, 0).err(), Some(-EPERM));
        assert_eq!(Timer::new(1, 4).err(), Some(-EINVAL));
        assert_eq!(armed(0, 0).set(0, 0, 4, (0, 1)).err(), Some(-EINVAL));
    }
}
