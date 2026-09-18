//! Drain architecture events into the kernel event loop.

/// Loop-owned storage, retained across guest exits. Timer wakeups never need
/// heap storage; input bursts reuse the capacity from the preceding burst.
#[derive(Default)]
pub struct PendingEvents {
    pub events: alloc::vec::Vec<crate::Irq>,
    pub tick_wakeup: bool,
}

impl PendingEvents {
    #[inline(never)]
    pub fn drain<A: crate::Arch>(&mut self, machine: &mut A) {
        self.events.clear();
        self.tick_wakeup = false;
        machine.drain(&mut |event| self.push(event));
    }

    fn push(&mut self, event: crate::Irq) {
        if matches!(event, crate::Irq::Hw(0)) {
            self.tick_wakeup = true;
        } else {
            self.events.push(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_wakeups_do_not_allocate() {
        let mut pending = PendingEvents::default();
        for _ in 0..256 {
            pending.push(crate::Irq::Hw(0));
        }
        assert!(pending.tick_wakeup);
        assert!(pending.events.is_empty());
        assert_eq!(pending.events.capacity(), 0);
    }

    #[test]
    fn input_order_and_storage_survive_timer_filtering() {
        let mut pending = PendingEvents::default();
        pending.push(crate::Irq::Key(0x1e));
        pending.push(crate::Irq::Hw(0));
        pending.push(crate::Irq::Hw(5));
        pending.push(crate::Irq::Key(0x9e));
        assert!(matches!(pending.events.as_slice(),
            [crate::Irq::Key(0x1e), crate::Irq::Hw(5), crate::Irq::Key(0x9e)]));
        let capacity = pending.events.capacity();
        let storage = pending.events.as_ptr();
        pending.events.clear();
        pending.push(crate::Irq::Key(0x30));
        assert_eq!(pending.events.capacity(), capacity);
        assert_eq!(pending.events.as_ptr(), storage);
    }
}
