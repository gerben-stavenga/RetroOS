//! Logical deadlines owned by the event loop. Hardware IRQs only wake it.

/// A recurring service keeps its phase across unrelated guest exits. Missed
/// intervals coalesce into one service opportunity, without a catch-up burst.
pub(crate) struct Periodic { next: u64, interval: u64 }
impl Periodic {
    pub fn new(now: u64, interval: u64) -> Self {
        assert!(interval != 0);
        Self { next: now, interval }
    }
    pub fn consume(&mut self, now: u64) -> bool {
        if now < self.next { return false; }
        let periods = (now - self.next) / self.interval + 1;
        self.next = self.next.saturating_add(periods.saturating_mul(self.interval));
        true
    }
    pub fn deadline(&self) -> u64 { self.next }
}

/// Deadlines created in this iteration cannot precede its fixed time sample.
/// Work scheduled at `now` causes another pass instead of a guest entry.
pub(crate) struct Deadlines { now: u64, next: Option<u64> }
impl Deadlines {
    pub fn new(now: u64) -> Self { Self { now, next: None } }
    pub fn include(&mut self, deadline: Option<u64>) {
        if let Some(end) = deadline {
            let end = end.max(self.now);
            self.next = Some(self.next.map_or(end, |old| old.min(end)));
        }
    }
    pub fn next(&self) -> Option<u64> { self.next }
    pub fn immediate(&self) -> bool { self.next == Some(self.now) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn io_exits_do_not_postpone_recurring_work() {
        let mut service = Periodic::new(100, 20);
        assert!(service.consume(100));
        for now in 101..120 { assert!(!service.consume(now)); }
        assert_eq!(service.deadline(), 120);
        assert!(service.consume(179));
        assert_eq!(service.deadline(), 180);
    }
    #[test]
    fn cancellation_and_rescheduling_select_only_live_deadlines() {
        let mut deadlines = Deadlines::new(100);
        deadlines.include(None);
        assert_eq!(deadlines.next(), None);
        deadlines.include(Some(150));
        deadlines.include(Some(130));
        deadlines.include(Some(170));
        assert_eq!(deadlines.next(), Some(130));
        let mut next_pass = Deadlines::new(130);
        next_pass.include(Some(170)); // the earlier owner consumed/cancelled
        assert_eq!(next_pass.next(), Some(170));
    }
    #[test]
    fn immediate_work_keeps_the_cpu_in_the_loop() {
        let mut deadlines = Deadlines::new(100);
        deadlines.include(Some(80));
        assert!(deadlines.immediate());
        assert_eq!(deadlines.next(), Some(100));
    }
}
