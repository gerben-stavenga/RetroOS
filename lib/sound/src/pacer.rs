//! Latency controller for a sink host.
//!
//! A sink keeps the counters and the recovery rules; this helper turns those
//! counters into a gently-trimmed mix rate and source-frame cursor.

/// Fixed-point shift for the effective mix rate.
pub const RATE_FP_SHIFT: u32 = 16;

const TRACKING_OMEGA_PER_SEC: i64 = 8;
const FRAC_SCALE: u128 = 1000u128 << RATE_FP_SHIFT;

/// State for one latency-controlled mixer.
///
/// The host feeds it the sink's counters, target latency and elapsed time;
/// the pacer feeds back the effective rate to mix at and the next source
/// frame index to stamp into a mix span.
pub struct Pacer {
    nominal_rate: u32,
    /// Effective mix-rate offset from nominal, in frames/sec × 2^16.
    rate_offset_q16: i128,
    /// Effective output rate, in frames/sec × 2^16.
    effective_rate_q16: u64,
    /// Fractional output frames, in frames/sec × ms × 2^16.
    frac_q16: u128,
    /// Absolute CPU-produced frame index.
    pushed: u64,
    sink_present: bool,
    primed: bool,
}

impl Pacer {
    pub const fn new() -> Self {
        Self {
            nominal_rate: 0,
            rate_offset_q16: 0,
            effective_rate_q16: 0,
            frac_q16: 0,
            pushed: 0,
            sink_present: false,
            primed: false,
        }
    }

    /// Output-frame frontier at which an event arriving now should be stamped.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Effective mix rate, in frames/sec × 2^16.
    pub fn effective_rate_q16(&self) -> u64 {
        self.effective_rate_q16
    }

    /// Effective mix rate, in whole frames/sec plus microframes.
    pub fn effective_rate_hz(&self) -> (u64, u64) {
        let whole = self.effective_rate_q16 >> RATE_FP_SHIFT;
        let frac = ((self.effective_rate_q16 & ((1u64 << RATE_FP_SHIFT) - 1))
            as u128 * 1_000_000u128
            >> RATE_FP_SHIFT) as u64;
        (whole, frac)
    }

    /// Whether the sink is currently present.
    pub fn sink_present(&self) -> bool {
        self.sink_present
    }

    /// Update sink presence; returns true if the presence edge changed.
    pub fn set_sink_present(&mut self, present: bool) -> bool {
        if self.sink_present == present {
            return false;
        }
        self.sink_present = present;
        self.primed = false;
        true
    }

    /// Whether the physical pipe has already been primed with silence.
    pub fn primed(&self) -> bool {
        self.primed
    }

    /// Mark the physical pipe as primed.
    pub fn prime(&mut self) {
        self.primed = true;
    }

    /// The current nominal sink rate.
    pub fn nominal_rate(&self) -> u32 {
        self.nominal_rate
    }

    /// Reset the nominal rate. If unchanged, keep the controller state.
    pub fn set_nominal_rate(&mut self, rate: u32) {
        if self.nominal_rate == rate {
            return;
        }
        self.nominal_rate = rate;
        self.rate_offset_q16 = 0;
        self.effective_rate_q16 = u64::from(rate) << RATE_FP_SHIFT;
        self.frac_q16 = 0;
        self.primed = false;
    }

    /// Recovery from an underrun: the fractional frame clock no longer has a
    /// valid phase, but the rate controller keeps its current trim.
    pub fn recover_from_underrun(&mut self) {
        self.frac_q16 = 0;
        self.primed = false;
    }

    fn predicted_due_frames(&self, dt_ms: u64) -> u64 {
        let frac_q16 = self.frac_q16
            + u128::from(self.effective_rate_q16) * u128::from(dt_ms);
        (frac_q16 / FRAC_SCALE) as u64
    }

    /// Critically damped correction toward the requested queue depth.
    pub fn update_rate(&mut self, written: u64, consumed: u64, target: u32, dt_ms: u64) {
        if dt_ms == 0 {
            return;
        }

        let target_written = consumed.saturating_add(u64::from(target));
        let predicted_written = written.saturating_add(self.predicted_due_frames(dt_ms));
        let position_error = i128::from(target_written) - i128::from(predicted_written);
        let nominal_q16 = i128::from(self.nominal_rate) << RATE_FP_SHIFT;
        let rate_error_q16 = self.rate_offset_q16;
        let omega = i128::from(TRACKING_OMEGA_PER_SEC);
        let position_term_q16 = position_error
            * omega
            * omega
            * i128::from(1u64 << RATE_FP_SHIFT);
        let damping_term_q16 = rate_error_q16 * 2 * omega;
        let delta_q16 = (position_term_q16 - damping_term_q16) * i128::from(dt_ms) / 1000;
        self.rate_offset_q16 = rate_error_q16 + delta_q16;
        self.effective_rate_q16 = (nominal_q16 + self.rate_offset_q16).max(0) as u64;
    }

    /// Advance the source-frame accumulator by one pump interval.
    pub fn due_frames(&mut self, dt_ms: u64) -> u64 {
        let frac_q16 = self.frac_q16
            + u128::from(self.effective_rate_q16) * u128::from(dt_ms);
        let due = frac_q16 / FRAC_SCALE;
        self.frac_q16 = frac_q16 - due * FRAC_SCALE;
        due as u64
    }

    /// Advance the source-frame frontier after the host has mixed `due` frames.
    pub fn advance_pushed(&mut self, due: u64) {
        self.pushed += due;
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_rate_sets_the_output_rate() {
        let mut pacer = Pacer::new();
        pacer.set_nominal_rate(48_000);
        assert_eq!(pacer.effective_rate_q16(), 48_000u64 << RATE_FP_SHIFT);
        assert_eq!(pacer.effective_rate_hz(), (48_000, 0));
    }

    #[test]
    fn one_ms_at_48khz_produces_48_frames() {
        let mut pacer = Pacer::new();
        pacer.set_nominal_rate(48_000);
        assert_eq!(pacer.due_frames(1), 48);
        assert_eq!(pacer.pushed(), 0);
        pacer.advance_pushed(48);
        assert_eq!(pacer.pushed(), 48);
    }
}
