//! The GF1 logarithmic volume domain — the engine's canonical volume unit.
//!
//! A 16-bit register value encodes `1.mantissa × 2^exponent`: exponent in
//! bits 15..12, mantissa in bits 11..0. One exponent step is exactly ×2
//! (6.02 dB), which makes this the natural common currency for every
//! personality: GF1 volume registers are the identity map, and SF2
//! centibels convert by a constant integer factor (`cb * 68 / 10` units).

/// Log-volume register value → linear Q16 gain (≈1 at zero, 65528 ≈ unity
/// at 0xFFFF). Pure integer: `(1.mantissa) << exponent`, renormalized.
#[inline]
pub fn lin_q16(v: i32) -> i32 {
    let v = v.clamp(0, 0xFFFF);
    ((0x1000 | (v & 0xFFF)) << ((v >> 12) as u32)) >> 12
}
