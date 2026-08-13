//! Architecture-neutral logical audio time and timestamped events.

/// Monotonic logical audio time, expressed in microseconds since the audio
/// clock's epoch. It is deliberately independent of VM86 timer delivery,
/// mixer cadence, and sink/DMA position.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct AudioTime(u64);

impl AudioTime {
    pub const ZERO: Self = Self(0);

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub const fn saturating_duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A device operation together with the logical time at which the guest
/// performed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedEvent<T> {
    pub at: AudioTime,
    pub event: T,
}

/// Whether a source should produce PCM or only advance its internal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderMode {
    ProducePcm,
    AdvanceOnly,
}

/// Convert the existing system-tick cadence into a lower-rate audio-service
/// wakeup. It is a scheduling aid only; callers still use `AudioTime` to
/// determine the actual elapsed interval.
pub struct ServiceDivider {
    period_ticks: u32,
    phase: u32,
}

impl ServiceDivider {
    pub const fn new(input_hz: u32, service_hz: u32) -> Self {
        let period_ticks = if service_hz == 0 || input_hz / service_hz == 0 {
            1
        } else {
            input_hz / service_hz
        };
        Self { period_ticks, phase: 0 }
    }

    /// Return how many service opportunities became due.
    pub fn advance(&mut self, ticks: u32) -> u32 {
        let total = self.phase.saturating_add(ticks);
        let due = total / self.period_ticks;
        self.phase = total % self.period_ticks;
        due
    }
}

/// Convert logical microseconds to a sample-frame position without floating
/// point arithmetic. Saturation avoids wrapping on malformed/future times.
pub const fn audio_time_to_frame(time: AudioTime, sample_rate: u32) -> u64 {
    ((time.as_micros() as u128 * sample_rate as u128) / 1_000_000) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_is_ordered_and_frame_conversion_is_integer() {
        let t = AudioTime::from_micros(1_000_000);
        assert!(t > AudioTime::ZERO);
        assert_eq!(audio_time_to_frame(t, 48_000), 48_000);
        assert_eq!(audio_time_to_frame(AudioTime::from_micros(500), 48_000), 24);
    }

    #[test]
    fn duration_does_not_underflow() {
        assert_eq!(
            AudioTime::from_micros(10).saturating_duration_since(AudioTime::from_micros(20)),
            0
        );
    }

    #[test]
    fn service_divider_preserves_batched_ticks() {
        let mut divider = ServiceDivider::new(1_000, 500);
        assert_eq!(divider.advance(1), 0);
        assert_eq!(divider.advance(1), 1);
        assert_eq!(divider.advance(5), 2);
        assert_eq!(divider.advance(1), 1);
    }
}
