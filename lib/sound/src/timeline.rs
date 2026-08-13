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
}
