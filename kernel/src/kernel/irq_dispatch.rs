//! Drain architecture events into the kernel event loop.

/// Loop-owned storage for discrete events, retained across guest exits.
/// Timer alarms return directly from execute and never enter this queue; input bursts reuse the capacity from the preceding burst.
#[derive(Default)]
pub struct PendingEvents {
    pub events: alloc::vec::Vec<crate::Irq>,
}

impl PendingEvents {
    #[inline(never)]
    pub fn drain<A: crate::Arch>(&mut self, machine: &mut A) {
        self.events.clear();
        machine.drain(&mut |event, timestamp_ns| {
            crate::kernel::random::interrupt_event(&event, timestamp_ns);
            self.push(event);
        });
    }

    fn push(&mut self, event: crate::Irq) {
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_order_and_storage_survive_repeated_drains() {
        let mut pending = PendingEvents::default();
        pending.push(crate::Irq::Key(0x1e));
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
