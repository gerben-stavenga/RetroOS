//! Latency controller for a sink host.
//!
//! A sink keeps the counters and the recovery rules; this helper turns those
//! counters into a gently-trimmed mix rate and source-frame cursor.

/// Fixed-point shift for the effective mix rate.
pub const RATE_FP_SHIFT: u32 = 16;

/// Loop bandwidth times the latency target, `w * T`, in thousandths. This is
/// the dimensionless form of the knob: `w` itself is not a property of the
/// controller but of how much queue there is to work with, so it is derived
/// per step as `w = OMEGA_TIMES_LATENCY/1000 / T`, with `T` the target depth
/// expressed in seconds.
///
/// The latency target is what the loop is allowed to spend. A deep queue can
/// be corrected slowly; a shallow one has to be corrected before it empties,
/// so the same clock error is more urgent. 0.03 puts the settling time `4/w`
/// at about 130 buffer-lengths, which is 1 rad/s at the 30 ms default — the
/// value that sounds right on metal — and scales from ~6 rad/s at a 5 ms
/// target to 0.5 at 60 ms.
///
/// Raising it costs pitch stability, and unevenly: `q`'s noise reaches the
/// rate through `2w` directly and through `w^2 dt` after integration, so the
/// low-latency end of the slider is inherently the noisier one. That is not a
/// flaw in the scaling — a small buffer genuinely cannot afford a slow loop.
const OMEGA_TIMES_LATENCY: i64 = 30;

/// State for one latency-controlled mixer.
///
/// The host feeds it the sink's counters, target latency and elapsed time;
/// the pacer feeds back the effective rate to mix at and the next source
/// frame index to stamp into a mix span.
pub struct Pacer {
    /// The controller state `s = rate + 2w q`, in frames/sec × 2^16: the rate
    /// we would mix at with the queue exactly on target. It is the running
    /// integral of the spring force, so it converges onto the sink's true
    /// consumption rate `c'` — learned, never measured. The rate given to
    /// [`Pacer::new`] is its initial value, not a reference it is pulled back
    /// toward, and it is free to float to wherever the hardware really runs.
    s_q16: i128,
}

impl Pacer {
    /// Start paced at `rate` frames/sec.
    pub const fn new(rate: u32) -> Self {
        Self {
            s_q16: (rate as i128) << RATE_FP_SHIFT,
        }
    }

    /// The controller state `s`, in frames/sec × 2^16 — also the rate to mix
    /// at when there is no feedback to correct against, since that is `s`
    /// with the spring relaxed.
    pub fn s_q16(&self) -> u64 {
        self.s_q16.max(0) as u64
    }

    /// A rate in whole frames/sec plus microframes.
    pub fn rate_hz(rate_q16: u64) -> (u64, u64) {
        let whole = rate_q16 >> RATE_FP_SHIFT;
        let frac = ((rate_q16 & ((1u64 << RATE_FP_SHIFT) - 1))
            as u128 * 1_000_000u128
            >> RATE_FP_SHIFT) as u64;
        (whole, frac)
    }

    /// Loop bandwidth for this operating point, in milliradians/sec:
    /// `w = k/T` with `T = target/rate` seconds, so `w_milli = 1000k *
    /// rate/target`. See [`OMEGA_TIMES_LATENCY`].
    fn omega_millirad(rate_hz: u64, target: u32) -> u64 {
        let target = u64::from(target).max(1);
        ((OMEGA_TIMES_LATENCY as u64) * rate_hz / target).max(1)
    }

    /// Advance the controller one pump and return the rate to mix at, in
    /// frames/sec × 2^16. Critically damped correction toward `target`.
    pub fn update_rate(&mut self, written: u64, consumed: u64, target: u32, dt_ms: u64) -> u64 {
        if dt_ms == 0 {
            return self.s_q16();
        }

        // Spring extension `q`. `written` must already include the frames the
        // caller is about to mix this pump: the sink's play cursor is current
        // while its write cursor is a pump stale, and comparing them as-is
        // invents a deficit of one pump's production — 48 frames at 1 ms, 480
        // on a 10 ms catch-up pump, always in the direction that makes the
        // controller speed up for audio that is merely not submitted yet.
        // Positive `q` is a queue deeper than the target.
        let anchor = consumed.saturating_add(u64::from(target));
        let q = i128::from(written) - i128::from(anchor);
        if target == 0 {
            return self.s_q16();
        }
        // Bandwidth from `s`, not from the emitted rate: the latter swings with
        // `q`, and the loop's bandwidth should not swing with it.
        let omega_m =
            i128::from(Self::omega_millirad(self.s_q16() >> RATE_FP_SHIFT, target));
        let one_q16 = i128::from(1u64 << RATE_FP_SHIFT);
        // s' = -w^2 q, integrated over the pump: the spring, slow and quiet.
        // The divisor carries w's milli scale twice over, and dt's once.
        self.s_q16 -= q * omega_m * omega_m * one_q16 * i128::from(dt_ms) / 1_000_000_000;
        // rate = s - 2w q: the dashpot, instant and carrying q's noise.
        // Together these are rate' = -[2w (rate - y') + w^2 (p - y)], since
        // rate - y' is q' — which is why q never has to be differentiated.
        (self.s_q16 - q * 2 * omega_m * one_q16 / 1_000).max(0) as u64
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rate_is_the_output_rate() {
        let pacer = Pacer::new(48_000);
        assert_eq!(pacer.s_q16(), 48_000u64 << RATE_FP_SHIFT);
        assert_eq!(Pacer::rate_hz(pacer.s_q16()), (48_000, 0));
    }

    /// The knob is `w*T`, so the latency slider moves `w` and the default
    /// operating point reproduces the 1 rad/s that was tuned by ear on metal.
    #[test]
    fn omega_tracks_the_latency_target() {
        let ms = |ms: u32| 48 * ms; // frames at 48 kHz
        assert_eq!(Pacer::omega_millirad(48_000, ms(30)), 1_000); // 1.0 rad/s
        assert_eq!(Pacer::omega_millirad(48_000, ms(5)), 6_000); // shallow: fast
        assert_eq!(Pacer::omega_millirad(48_000, ms(60)), 500); // deep: slow
        // Same latency in seconds at a different card rate is the same loop.
        assert_eq!(Pacer::omega_millirad(44_100, 44_100 * 30 / 1000), 1_000);
    }

    #[test]
    fn a_deep_queue_slows_the_rate_and_a_shallow_one_speeds_it() {
        let target = 1_440;
        // Queue 100 frames deeper than asked for: mix slower until it drains.
        let mut pacer = Pacer::new(48_000);
        let slow = pacer.update_rate(1_540, 0, target, 1);
        assert!(slow < 48_000u64 << RATE_FP_SHIFT, "slow = {slow}");
        // 100 frames short: mix faster.
        let mut pacer = Pacer::new(48_000);
        let fast = pacer.update_rate(1_340, 0, target, 1);
        assert!(fast > 48_000u64 << RATE_FP_SHIFT, "fast = {fast}");
    }
}
