//! Concurrent device memory. The mapped guest aperture is an external CPU
//! writer; kernel accesses use byte atomics and never form mutable slices.
use core::sync::atomic::{AtomicU8, Ordering};
#[derive(Clone, Copy)]
pub struct Memory<'a> { bytes: &'a [AtomicU8] }
impl<'a> Memory<'a> {
    /// # Safety
    /// The range remains mapped for 'a. Concurrent kernel accesses must be
    /// atomic byte accesses; no mutable Rust slice may alias this storage.
    pub unsafe fn mapped(base: *mut u8, len: usize) -> Self {
        Self { bytes: unsafe { core::slice::from_raw_parts(base.cast(), len) } }
    }
    pub fn from_bytes(bytes: &'a [AtomicU8]) -> Self { Self { bytes } }
    pub fn len(self) -> usize { self.bytes.len() }
    pub fn is_empty(self) -> bool { self.bytes.is_empty() }
    #[inline] pub fn get(self, index: usize) -> Option<u8> {
        self.bytes.get(index).map(|v| v.load(Ordering::Relaxed))
    }
    #[inline] pub fn put(self, index: usize, value: u8) {
        self.bytes[index].store(value, Ordering::Relaxed);
    }
    pub fn range(self, start: usize, len: usize) -> Self {
        Self { bytes: &self.bytes[start..start + len] }
    }
    pub fn copy_from(self, source: &[u8]) {
        assert_eq!(source.len(), self.len());
        for (i, value) in source.iter().enumerate() { self.put(i, *value); }
    }
    pub fn fill(self, value: u8) {
        for byte in self.bytes { byte.store(value, Ordering::Relaxed); }
    }
}

impl Memory<'_> {
    pub fn transition(self, transition: crate::VramTransition) {
        let mut bytes: alloc::vec::Vec<u8> = (0..self.len()).map(|i| self.get(i).unwrap()).collect();
        transition.apply(&mut bytes);
        self.copy_from(&bytes);
    }
    pub fn load_font(self, layout: crate::VramLayout, map: usize,
        first: usize, font: &[u8], glyph_h: usize) {
        assert!(map < 8 && (1..=32).contains(&glyph_h));
        assert!(self.len() >= 4 * 65536);
        assert!(font.len().is_multiple_of(glyph_h) && first + font.len() / glyph_h <= 256);
        for i in 0..font.len() / glyph_h {
            for row in 0..32 {
                let value = if row < glyph_h { font[i * glyph_h + row] } else { 0 };
                self.put(layout.index(2, map * 0x2000 + (first + i) * 32 + row), value);
            }
        }
    }
}
