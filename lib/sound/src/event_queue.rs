//! Fixed-capacity timestamp-event queues for guest-side producers and
//! deterministic audio-side consumers.

use core::mem::MaybeUninit;

use crate::timeline::TimedEvent;

/// A bounded FIFO queue. It never overwrites old events: a full push returns
/// the event to the caller and increments the overflow counter.
pub struct FixedEventQueue<T, const N: usize> {
    storage: [MaybeUninit<T>; N],
    head: usize,
    len: usize,
    high_water: usize,
    overflows: u64,
}

impl<T, const N: usize> FixedEventQueue<T, N> {
    pub const fn new() -> Self {
        Self {
            storage: [const { MaybeUninit::uninit() }; N],
            head: 0,
            len: 0,
            high_water: 0,
            overflows: 0,
        }
    }

    pub const fn capacity(&self) -> usize { N }

    pub const fn is_empty(&self) -> bool { self.len == 0 }

    pub const fn is_full(&self) -> bool { self.len == N }

    pub const fn len(&self) -> usize { self.len }

    pub const fn high_water(&self) -> usize { self.high_water }

    pub const fn overflows(&self) -> u64 { self.overflows }

    pub fn push(&mut self, event: T) -> Result<(), T> {
        if self.is_full() {
            self.overflows += 1;
            return Err(event);
        }
        let tail = (self.head + self.len) % N.max(1);
        // N=0 is a valid type-level instantiation; it is permanently full and
        // therefore returns above before this index is used.
        self.storage[tail].write(event);
        self.len += 1;
        self.high_water = self.high_water.max(self.len);
        Ok(())
    }

    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() { None } else {
            // SAFETY: every slot between head and head+len was initialized by
            // push and remains initialized until pop takes it.
            Some(unsafe { self.storage[self.head].assume_init_ref() })
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() { return None; }
        // SAFETY: head points at an initialized slot while len is nonzero.
        let value = unsafe { self.storage[self.head].assume_init_read() };
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(value)
    }
}

impl<T, const N: usize> Default for FixedEventQueue<T, N> {
    fn default() -> Self { Self::new() }
}

impl<T, const N: usize> Drop for FixedEventQueue<T, N> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

impl<T, const N: usize> FixedEventQueue<TimedEvent<T>, N> {
    /// Remove and return all events at or before `time`, preserving insertion
    /// order for equal timestamps.
    pub fn pop_through(&mut self, time: crate::timeline::AudioTime) -> Option<TimedEvent<T>> {
        if self.peek().is_some_and(|event| event.at <= time) {
            self.pop()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::{AudioTime, TimedEvent};

    #[test]
    fn fifo_and_equal_timestamp_order_are_preserved() {
        let mut q: FixedEventQueue<TimedEvent<u8>, 4> = FixedEventQueue::new();
        let at = AudioTime::from_micros(10);
        for value in [0x90, 0x3C, 0x7F, 0xFF] {
            q.push(TimedEvent { at, event: value }).unwrap();
        }
        assert_eq!(q.high_water(), 4);
        assert_eq!(q.pop_through(at).unwrap().event, 0x90);
        assert_eq!(q.pop_through(at).unwrap().event, 0x3C);
        assert_eq!(q.pop_through(at).unwrap().event, 0x7F);
        assert_eq!(q.pop_through(at).unwrap().event, 0xFF);
        assert!(q.pop_through(at).is_none());
    }

    #[test]
    fn full_queue_is_explicit_and_does_not_overwrite() {
        let mut q: FixedEventQueue<u8, 2> = FixedEventQueue::new();
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        assert_eq!(q.push(3), Err(3));
        assert_eq!(q.overflows(), 1);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
    }
}
