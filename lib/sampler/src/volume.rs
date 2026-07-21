//! The GF1 logarithmic volume domain — the engine's canonical volume unit.
//!
//! A 16-bit register value encodes `1.mantissa × 2^exponent`: exponent in
//! bits 15..12, mantissa in bits 11..0. One exponent step is exactly ×2
//! (6.02 dB), which makes this the natural common currency for every
//! personality: GF1 volume registers are the identity map, and SF2
//! centibels convert by a constant integer factor (`cb * 68 / 10` units).

/// Fractional bits the ramp generator keeps *below* the GF1's 16-bit volume
/// register, so a ramp can advance by less than one register unit per frame.
///
/// This is what lets the rate register's 2-bit divider (1/8/64/512) be folded
/// into a per-frame increment instead of being paced by a countdown. The
/// hardware ramp is a pure function of elapsed frames; a countdown is extra
/// state, and extra state has phase that reprogramming can reset. DMX rewrites
/// voice ramps every ~20 ms — faster than the slow dividers' own period — so a
/// countdown model loses updates it should have made. Both reference
/// implementations avoid this the same way: DOSBox Staging scales its volume
/// index by 512 in `WriteVolRate`, and 86Box scales `rfreq` by 1<<10.
pub const RAMP_FRACT: u32 = 9;

/// Log-volume register value → linear Q16 gain (≈1 at zero, 65528 ≈ unity
/// at 0xFFFF). Pure integer: `(1.mantissa) << exponent`, renormalized.
/// Takes the plain 16-bit register value — callers holding a ramp-domain
/// volume shift down by [`RAMP_FRACT`] first.
#[inline]
pub fn lin_q16(v: i32) -> i32 {
    let v = v.clamp(0, 0xFFFF);
    ((0x1000 | (v & 0xFFF)) << ((v >> 12) as u32)) >> 12
}
