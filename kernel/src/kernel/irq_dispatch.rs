//! Device-owned input storage. CPU interruption and queued data are independent.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const CAPACITY: usize = 256;
struct Slot {
    ready: AtomicBool,
    header: AtomicU32,
    motion: AtomicU32,
    timestamp_low: AtomicU32,
    timestamp_high: AtomicU32,
}

impl Slot {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            header: AtomicU32::new(0),
            motion: AtomicU32::new(0),
            timestamp_low: AtomicU32::new(0),
            timestamp_high: AtomicU32::new(0),
        }
    }

    fn publish(&self, event: crate::Irq, timestamp: u64) {
        use crate::Irq;
        let (tag, value, motion) = match event {
            Irq::Key(key) => (0, key, 0),
            Irq::Hw(line) => (1, line, 0),
            Irq::Msi(source) => (2, source, 0),
            Irq::Mouse { dx, dy, buttons } => {
                (3, buttons, u32::from(dx as u16) | (u32::from(dy as u16) << 16))
            }
        };
        self.header.store((tag << 8) | u32::from(value), Ordering::Relaxed);
        self.motion.store(motion, Ordering::Relaxed);
        self.timestamp_low.store(timestamp as u32, Ordering::Relaxed);
        self.timestamp_high.store((timestamp >> 32) as u32, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
    }

    fn read(&self) -> (crate::Irq, u64) {
        use crate::Irq;
        let header = self.header.load(Ordering::Relaxed);
        let value = header as u8;
        let event = match header >> 8 {
            0 => Irq::Key(value),
            1 => Irq::Hw(value),
            2 => Irq::Msi(value),
            3 => {
                let motion = self.motion.load(Ordering::Relaxed);
                Irq::Mouse { dx: motion as i16, dy: (motion >> 16) as i16, buttons: value }
            }
            _ => unreachable!("invalid device event"),
        };
        let timestamp = u64::from(self.timestamp_low.load(Ordering::Relaxed))
            | (u64::from(self.timestamp_high.load(Ordering::Relaxed)) << 32);
        (event, timestamp)
    }
}

// Exclusive reservation and ready publication keep each event and timestamp
// together. The payload uses 32-bit atomics so producers never take a lock.
static INPUT: [Slot; CAPACITY] = [const { Slot::new() }; CAPACITY];
static READ: AtomicUsize = AtomicUsize::new(0);
static WRITE: AtomicUsize = AtomicUsize::new(0);
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Device interrupt/host input sink. Allocation-free and never waits for a
/// consumer (which may be the interrupted thread). A full queue drops new input.
pub fn post(event: crate::Irq, timestamp_ns: u64) {
    let Ok(position) = WRITE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |write| {
        (write.wrapping_sub(READ.load(Ordering::Acquire)) < CAPACITY)
            .then_some(write.wrapping_add(1))
    }) else { return; };
    let slot = &INPUT[position % CAPACITY];
    slot.publish(event, timestamp_ns);
}

fn drain(mut consume: impl FnMut(crate::Irq, u64)) {
    if DRAINING.swap(true, Ordering::Acquire) { return; }
    // Snapshot the boundary: callbacks or interrupt producers can post without
    // extending this drain indefinitely.
    let end = WRITE.load(Ordering::Relaxed);
    let mut position = READ.load(Ordering::Relaxed);
    while position != end {
        let slot = &INPUT[position % CAPACITY];
        if !slot.ready.load(Ordering::Acquire) { break; }
        let (event, timestamp) = slot.read();
        slot.ready.store(false, Ordering::Relaxed);
        position = position.wrapping_add(1);
        READ.store(position, Ordering::Release);
        consume(event, timestamp);
    }
    DRAINING.store(false, Ordering::Release);
}

/// Loop-owned storage for discrete events, retained across guest exits.
/// Timer alarms return directly from execute and never enter this queue; input bursts reuse the capacity from the preceding burst.
#[derive(Default)]
pub struct PendingEvents {
    pub events: alloc::vec::Vec<crate::Irq>,
}

impl PendingEvents {
    #[inline(never)]
    pub fn drain(&mut self) {
        self.events.clear();
        drain(|event, timestamp_ns| {
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
    fn device_queue_preserves_order_timestamps_and_handles_full_and_reentrant_posts() {
        extern crate std;
        // Concurrent host devices reserve distinct slots; each producer's
        // arrival order and timestamps survive publication.
        let producers: alloc::vec::Vec<_> = (0..4).map(|device| std::thread::spawn(move || {
            for timestamp in 0..32 { post(crate::Irq::Hw(device), timestamp); }
        })).collect();
        for producer in producers { producer.join().unwrap(); }
        let mut expected = [0; 4];
        drain(|event, timestamp| {
            let crate::Irq::Hw(device) = event else { panic!("unexpected input") };
            assert_eq!(timestamp, expected[device as usize]);
            expected[device as usize] += 1;
        });
        assert_eq!(expected, [32; 4]);
        // Exercise wraparound, capacity and posts from inside a consumer.
        for _ in 0..3 {
            for timestamp in 0..CAPACITY as u64 { post(crate::Irq::Key(0x1e), timestamp); }
            post(crate::Irq::Key(0xff), 999); // full: drop new input
            let mut expected = 0;
            drain(|event, timestamp| {
                assert!(matches!(event, crate::Irq::Key(0x1e)));
                assert_eq!(timestamp, expected);
                expected += 1;
                if timestamp == 0 { post(crate::Irq::Key(0x9e), 1000); }
            });
            assert_eq!(expected, CAPACITY as u64);
            let mut received = 0;
            drain(|event, timestamp| {
                assert!(matches!(event, crate::Irq::Key(0x9e)));
                assert_eq!(timestamp, 1000);
                received += 1;
            });
            assert_eq!(received, 1);
        }
    }

    #[test]
    fn slot_preserves_signed_motion_and_full_timestamp() {
        let slot = Slot::new();
        let time = 0xabcd_1234_9876_ffff;
        slot.publish(crate::Irq::Mouse { dx: i16::MIN, dy: i16::MAX, buttons: u8::MAX }, time);
        let (event, timestamp) = slot.read();
        assert!(matches!(event, crate::Irq::Mouse { dx: i16::MIN, dy: i16::MAX, buttons: u8::MAX }));
        assert_eq!(timestamp, time);
    }

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
