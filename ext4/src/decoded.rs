//! Bounded indexes of decoded metadata facts, never file/block contents.
//! Direct slots keep a hit allocation-free. Collisions only cause re-reading.
use alloc::vec::Vec;

pub(crate) struct Index<T: Copy, const CAPACITY: usize> {
    slots: Vec<Option<(u32, T)>>,
    unavailable: bool,
}
impl<T: Copy, const CAPACITY: usize> Index<T, CAPACITY> {
    pub const fn new() -> Self { Self { slots: Vec::new(), unavailable: false } }
    fn slot(key: u32) -> usize {
        // Mix all inode-number bits, including the allocation-group prefix.
        (key.wrapping_mul(0x9e37_79b9) as usize) >> (32 - CAPACITY.trailing_zeros())
    }
    pub fn get(&self, key: u32) -> Option<T> {
        self.slots.get(Self::slot(key)).copied().flatten()
            .and_then(|(stored, value)| (stored == key).then_some(value))
    }
    pub fn insert(&mut self, key: u32, value: T) {
        if self.unavailable { return; }
        if self.slots.is_empty() {
            assert!(CAPACITY.is_power_of_two() && CAPACITY > 1);
            if self.slots.try_reserve_exact(CAPACITY).is_err() {
                self.unavailable = true;
                return;
            }
            self.slots.resize(CAPACITY, None);
        }
        self.slots[Self::slot(key)] = Some((key, value));
    }
    pub fn remove(&mut self, key: u32) {
        if let Some(slot) = self.slots.get_mut(Self::slot(key))
            && slot.is_some_and(|(stored, _)| stored == key) { *slot = None; }
    }
}
