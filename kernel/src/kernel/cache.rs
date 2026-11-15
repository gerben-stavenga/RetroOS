//! Kernel cache storage. Contents are physical frames; only ownership and
//! indexes occupy permanent kernel address space. Arch supplies mechanisms.
use alloc::boxed::Box;
use spin::Once;

static INSTALLED: Once<()> = Once::new();
pub(crate) fn install(reclaim: fn() -> Option<u64>) {
    INSTALLED.call_once(|| ());
    super::phys_mm::set_reclaim(reclaim);
}
pub(crate) fn installed() -> bool { INSTALLED.get().is_some() }

pub(crate) fn reserve() -> usize {
    if installed() { (super::phys_mm::total_page_count() / 32).clamp(64, 8192) } else { 0 }
}

pub(crate) struct Frame {
    physical: Option<u64>,
    // Pure kernel tests without a machine use the same storage API.
    bytes: Option<Box<[u8]>>,
}
impl Frame {
    pub fn new(bytes: &[u8]) -> Result<Self, i32> {
        assert_eq!(bytes.len(), 4096);
        if installed() {
            let physical = super::memory::allocate_frame().ok_or(-12)?;
            super::platform::write_physical_frame(physical, 0, bytes);
            Ok(Self { physical: Some(physical), bytes: None })
        } else {
            Ok(Self { physical: None, bytes: Some(bytes.into()) })
        }
    }
    pub fn physical(&self) -> Option<u64> { self.physical }
    pub fn read(&self, offset: usize, bytes: &mut [u8]) {
        assert!(offset <= 4096 && bytes.len() <= 4096 - offset);
        if let Some(page) = self.physical { super::platform::read_physical_frame(page, offset, bytes); }
        else { bytes.copy_from_slice(&self.bytes.as_ref().unwrap()[offset..offset + bytes.len()]); }
    }
    pub fn write(&mut self, offset: usize, bytes: &[u8]) {
        assert!(offset <= 4096 && bytes.len() <= 4096 - offset);
        if let Some(page) = self.physical { super::platform::write_physical_frame(page, offset, bytes); }
        else { self.bytes.as_mut().unwrap()[offset..offset + bytes.len()].copy_from_slice(bytes); }
    }
    pub fn into_reclaimed(mut self) -> Option<u64> {
        let page = self.physical?;
        if usize::from(super::phys_mm::get_ref_count(page)) != 1 { return None; }
        self.physical.take()
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        if let Some(page) = self.physical { super::phys_mm::free_phys_page(page); }
    }
}

/// Shared eviction bookkeeping for file pages and block metadata. Entries are
/// ordered without scanning the payload map on each miss.
pub(crate) struct Lru<K: Ord + Copy> {
    keys: alloc::collections::BTreeMap<K, u64>,
    order: alloc::collections::BTreeSet<(u64, K)>,
}
impl<K: Ord + Copy> Lru<K> {
    pub const fn new() -> Self { Self { keys: alloc::collections::BTreeMap::new(), order: alloc::collections::BTreeSet::new() } }
    pub fn len(&self) -> usize { self.keys.len() }
    pub fn clear(&mut self) { self.keys.clear(); self.order.clear(); }
    pub fn remove(&mut self, key: K) {
        if let Some(old) = self.keys.remove(&key) { self.order.remove(&(old, key)); }
    }
    pub fn touch(&mut self, key: K, tick: u64) {
        self.remove(key);
        self.keys.insert(key, tick);
        self.order.insert((tick, key));
    }
    pub fn pop(&mut self) -> Option<K> {
        let (tick, key) = self.order.pop_first()?;
        let old = self.keys.remove(&key);
        debug_assert_eq!(old, Some(tick));
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lru_updates_and_invalidation_preserve_eviction_order() {
        let mut lru = Lru::new();
        lru.touch(1, 1); lru.touch(2, 2); lru.touch(1, 3);
        assert_eq!(lru.len(), 2);
        assert_eq!(lru.pop(), Some(2));
        lru.remove(1); assert_eq!(lru.pop(), None);
        lru.touch(3, 4); lru.clear(); assert_eq!(lru.len(), 0);
    }
    #[test]
    fn frame_storage_preserves_boundaries_and_partial_updates() {
        let mut frame = Frame::new(&[0x91; 4096]).unwrap();
        frame.write(4094, &[0x23, 0x45]);
        let mut bytes = [0; 4]; frame.read(4092, &mut bytes);
        assert_eq!(bytes, [0x91, 0x91, 0x23, 0x45]);
    }
}
