//! VGA memory with owning-model operations.
#[derive(Clone, Copy)]
pub struct Memory<'a>(planar::Memory<'a>);
impl<'a> Memory<'a> {
    pub unsafe fn mapped(p: *mut u8, n: usize) -> Self { Self(unsafe { planar::Memory::mapped(p, n) }) }
    pub fn from_bytes(b: &'a [core::sync::atomic::AtomicU8]) -> Self { Self(planar::Memory::from_bytes(b)) }
    pub fn planar(self) -> planar::Memory<'a> { self.0 }
    pub fn range(self, start: usize, len: usize) -> Self { Self(self.0.range(start, len)) }
}
impl<'a> core::ops::Deref for Memory<'a> {
    type Target = planar::Memory<'a>;
    fn deref(&self) -> &Self::Target { &self.0 }
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
