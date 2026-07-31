//! The four-component signed accumulator the pixel pipeline works in
//! (`rgbaint_t` in MAME).
//!
//! Every stage keeps components as signed 32-bit values and only clamps where
//! the hardware does, so intermediate over/underflow behaves like the chip.
//! Written as plain scalars: this is the SIMD-shaped inner loop, and keeping
//! it a pure function of its inputs is what lets it be vectorised — or handed
//! to a shader — later without touching the pipeline logic.

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rgba {
    pub a: i32,
    pub r: i32,
    pub g: i32,
    pub b: i32,
}

impl Rgba {
    #[inline]
    pub const fn new(a: i32, r: i32, g: i32, b: i32) -> Self {
        Self { a, r, g, b }
    }

    /// From a packed 0xAARRGGBB word.
    #[inline]
    pub const fn from_argb(v: u32) -> Self {
        Self {
            a: ((v >> 24) & 0xff) as i32,
            r: ((v >> 16) & 0xff) as i32,
            g: ((v >> 8) & 0xff) as i32,
            b: (v & 0xff) as i32,
        }
    }

    #[inline]
    pub const fn to_argb(self) -> u32 {
        ((self.a as u32 & 0xff) << 24)
            | ((self.r as u32 & 0xff) << 16)
            | ((self.g as u32 & 0xff) << 8)
            | (self.b as u32 & 0xff)
    }

    #[inline]
    pub const fn splat(v: i32) -> Self {
        Self { a: v, r: v, g: v, b: v }
    }

    #[inline]
    pub fn zero_rgb(&mut self) {
        self.r = 0;
        self.g = 0;
        self.b = 0;
    }

    #[inline]
    pub fn zero_alpha(&mut self) {
        self.a = 0;
    }

    /// Take the RGB of `self` and the alpha of `other` (`merge_alpha16`).
    #[inline]
    pub fn merge_alpha(&mut self, other: Rgba) {
        self.a = other.a;
    }

    /// Broadcast alpha across RGB, keeping alpha (`select_alpha32`).
    #[inline]
    pub const fn select_alpha(self) -> Self {
        Self::splat(self.a)
    }

    #[inline]
    pub fn sub(&mut self, o: Rgba) {
        self.a -= o.a;
        self.r -= o.r;
        self.g -= o.g;
        self.b -= o.b;
    }

    #[inline]
    pub fn add(&mut self, o: Rgba) {
        self.a += o.a;
        self.r += o.r;
        self.g += o.g;
        self.b += o.b;
    }

    #[inline]
    pub fn add_imm(&mut self, v: i32) {
        self.a += v;
        self.r += v;
        self.g += v;
        self.b += v;
    }

    #[inline]
    pub fn xor_imm(&mut self, a: i32, r: i32, g: i32, b: i32) {
        self.a ^= a;
        self.r ^= r;
        self.g ^= g;
        self.b ^= b;
    }

    #[inline]
    pub fn clamp_to_u8(&mut self) {
        self.a = self.a.clamp(0, 255);
        self.r = self.r.clamp(0, 255);
        self.g = self.g.clamp(0, 255);
        self.b = self.b.clamp(0, 255);
    }

    /// `self = clamp(((self * scale) >> 8) + add)`.
    #[inline]
    pub fn scale_add_and_clamp(&mut self, scale: Rgba, add: Rgba) {
        self.a = ((self.a * scale.a) >> 8) + add.a;
        self.r = ((self.r * scale.r) >> 8) + add.r;
        self.g = ((self.g * scale.g) >> 8) + add.g;
        self.b = ((self.b * scale.b) >> 8) + add.b;
        self.clamp_to_u8();
    }

    /// `self = clamp(((self * scale) + (other * oscale)) >> 8)`.
    #[inline]
    pub fn scale2_add_and_clamp(&mut self, scale: Rgba, other: Rgba, oscale: Rgba) {
        self.a = (self.a * scale.a + other.a * oscale.a) >> 8;
        self.r = (self.r * scale.r + other.r * oscale.r) >> 8;
        self.g = (self.g * scale.g + other.g * oscale.g) >> 8;
        self.b = (self.b * scale.b + other.b * oscale.b) >> 8;
        self.clamp_to_u8();
    }

    /// `self = clamp((self * v) >> 8)`.
    #[inline]
    pub fn scale_imm_and_clamp(&mut self, v: i32) {
        self.a = (self.a * v) >> 8;
        self.r = (self.r * v) >> 8;
        self.g = (self.g * v) >> 8;
        self.b = (self.b * v) >> 8;
        self.clamp_to_u8();
    }

    /// Bilinear blend of four texels with 8-bit S/T fractions
    /// (`bilinear_filter_rgbaint`).
    #[inline]
    pub fn bilinear(t0: u32, t1: u32, t2: u32, t3: u32, sfrac: u32, tfrac: u32) -> Self {
        let (p0, p1, p2, p3) = (
            Self::from_argb(t0),
            Self::from_argb(t1),
            Self::from_argb(t2),
            Self::from_argb(t3),
        );
        let (sf, tf) = (sfrac as i32, tfrac as i32);
        let lerp = |x: i32, y: i32, f: i32| x + (((y - x) * f) >> 8);
        let mix = |c0: i32, c1: i32, c2: i32, c3: i32| {
            let top = lerp(c0, c1, sf);
            let bot = lerp(c2, c3, sf);
            lerp(top, bot, tf)
        };
        Self {
            a: mix(p0.a, p1.a, p2.a, p3.a),
            r: mix(p0.r, p1.r, p2.r, p3.r),
            g: mix(p0.g, p1.g, p2.g, p3.g),
            b: mix(p0.b, p1.b, p2.b, p3.b),
        }
    }
}
