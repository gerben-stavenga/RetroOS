//! Typematic for keyboard sources that report key transitions or held sets.

pub const REPEAT_DELAY_NS: u64 = 500_000_000;
pub const REPEAT_INTERVAL_NS: u64 = 33_333_333;

/// Repeat the newest ordinary key until it is released. The key is a Set-1
/// make code plus its E0 prefix flag.
#[derive(Clone, Copy, Default)]
pub struct KeyRepeat {
    key: Option<(u8, bool)>,
    deadline: u64,
}

impl KeyRepeat {
    pub const fn empty() -> Self {
        Self { key: None, deadline: 0 }
    }

    pub fn press(&mut self, key: (u8, bool), now: u64) {
        if !matches!(key.0, 0x1d | 0x2a | 0x36 | 0x38 | 0x3a | 0x45 | 0x46) {
            self.key = Some(key);
            self.deadline = now.wrapping_add(REPEAT_DELAY_NS);
        }
    }

    pub fn release(&mut self, key: (u8, bool)) {
        if self.key == Some(key) {
            self.key = None;
        }
    }

    pub fn poll(&mut self, now: u64) -> Option<(u8, bool)> {
        let key = self.key?;
        let late = now.wrapping_sub(self.deadline);
        if late >= (1u64 << 63) {
            return None;
        }
        // Stay on cadence even when the consumer polls less often than the
        // timer. Deliver at most one make code per poll.
        self.deadline = now.wrapping_add(REPEAT_INTERVAL_NS - late % REPEAT_INTERVAL_NS);
        Some(key)
    }
}
