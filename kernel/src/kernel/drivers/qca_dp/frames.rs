//! Bounded DMA frames retained until an explicit matching completion.
use super::{Error, Memory, Result};
use core::sync::atomic::{Ordering, fence};
pub const BYTES: usize = 32 * 2048;
pub struct Frames<M> {
    memory: M,
    live: [Option<u32>; 32],
    sequence: u32,
}
impl<M: Memory> Frames<M> {
    pub fn new(memory: M) -> Self {
        Self {
            memory,
            live: [None; 32],
            sequence: 0,
        }
    }
    pub fn insert(&mut self, bytes: &[u8]) -> Result<(u32, u64)> {
        if bytes.is_empty() || bytes.len() > 2048 {
            return Err(Error::Packet);
        }
        let slot = self
            .live
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        self.sequence = self.sequence.wrapping_add(1) & 0x7ffffff;
        let id = (self.sequence << 5) | slot as u32;
        self.live[slot] = Some(id);
        self.memory.copy_in(slot * 2048, bytes);
        fence(Ordering::Release);
        Ok((id, self.memory.physical() + (slot * 2048) as u64))
    }
    pub fn complete(&mut self, id: u32) -> Result<()> {
        let slot = (id & 31) as usize;
        if self.live[slot] != Some(id) {
            return Err(Error::Pointer);
        }
        fence(Ordering::Acquire);
        self.live[slot] = None;
        for at in (slot * 2048..(slot + 1) * 2048).step_by(4) {
            self.memory.write32(at, 0);
        }
        Ok(())
    }
    pub fn busy(&self) -> bool {
        self.live.iter().any(Option::is_some)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::drivers::qca_dp::tests::Ram;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;
    #[test]
    fn a_stale_completion_cannot_release_a_reused_slot() {
        let mut pool = Frames::new(Ram(Rc::new(RefCell::new(vec![0; BYTES]))));
        let (old, _) = pool.insert(b"one").unwrap();
        pool.complete(old).unwrap();
        let (new, _) = pool.insert(b"two").unwrap();
        assert_ne!(old, new);
        assert_eq!(pool.complete(old), Err(Error::Pointer));
        assert!(pool.busy());
        pool.complete(new).unwrap();
        assert!(!pool.busy());
    }
}
