//! Latency controller for a sink host.
//!
//! A sink keeps the counters and the recovery rules; this helper turns those
//! counters into a gently-trimmed mix rate and source-frame cursor.

/// Fixed-point shift for the effective mix rate.
pub const RATE_FP_SHIFT: u32 = 16;

/// Loop bandwidth, in milliradians/sec — the pitch-stability knob, kept at
/// milli resolution so it can be dialled below 1 rad/s.
///
/// Two paths carry `q` into the rate and they scale differently. The spring
/// integrates, `w^2 q dt` per pump, so its noise falls quadratically with `w`.
/// The dashpot is algebraic, `2w q`, so its noise falls only linearly and
/// dominates: one millisecond of cursor sampling phase (~48 frames at 48 kHz)
/// reaches the rate as `2w * 48`, which is 384 Hz at 4 rad/s and 96 Hz at 1.
///
/// The cost of lowering it is settling time, `4/w`. This design has no droop
/// to trade away — that was the old damper's price for a noise-free `q'` — so
/// a slow loop costs only how long a transient takes to clear, not steady
/// margin.
const OMEGA_MILLIRAD_PER_SEC: i64 = 1_000;

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
        let omega_m = i128::from(OMEGA_MILLIRAD_PER_SEC);
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
