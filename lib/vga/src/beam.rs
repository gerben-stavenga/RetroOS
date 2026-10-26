//! VGA beam events, independent of the CPU used to service the device.
//!
//! The caller consumes events in order, reading device registers/VRAM at
//! the corresponding event. Polling does not itself latch any registers.

/// Programmed timing, measured in character clocks and physical scanlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub dot_hz: u32,
    pub dots_per_clock: u8,
    pub horizontal_total: u16,
    pub horizontal_display: u16,
    pub horizontal_blank_start: u16,
    pub horizontal_blank_end: u16,
    pub vertical_total: u16,
    pub vertical_display: u16,
    pub blank_start: u16,
    pub blank_end: u16,
    pub retrace_start: u16,
    pub retrace_end: u16,
}

impl Timing {
    pub fn from_registers(misc: u8, seq: &[u8; 5], crtc: &[u8; 25]) -> Self {
        let overflow = crtc[7];
        let retrace_start = u16::from(crtc[0x10])
            | (u16::from(overflow & 4) << 6)
            | (u16::from(overflow & 0x80) << 2);
        let blank_start = u16::from(crtc[0x15])
            | (u16::from(overflow & 8) << 5)
            | (u16::from(crtc[9] & 0x20) << 4);
        Self {
            dot_hz: if misc & 0x0c == 4 { 28_322_000 } else { 25_175_000 },
            dots_per_clock: (if seq[1] & 1 != 0 { 8 } else { 9 })
                * if seq[1] & 8 != 0 { 2 } else { 1 },
            horizontal_total: u16::from(crtc[0]) + 5,
            horizontal_display: u16::from(crtc[1]) + 1,
            horizontal_blank_start: u16::from(crtc[2]),
            horizontal_blank_end: u16::from(crtc[2]) +
                ((u16::from((crtc[3] & 0x1f) | ((crtc[5] & 0x80) >> 2))
                    .wrapping_sub(u16::from(crtc[2]) + 1) & 0x3f) + 1),
            vertical_total: u16::from(crtc[6])
                + (u16::from(overflow & 1) << 8)
                + (u16::from(overflow & 0x20) << 4) + 2,
            vertical_display: u16::from(crtc[0x12])
                + (u16::from(overflow & 2) << 7)
                + (u16::from(overflow & 0x40) << 3) + 1,
            blank_start,
            blank_end: blank_start + ((u16::from(crtc[0x16])
                .wrapping_sub(blank_start + 1) & 0x7f) + 1),
            retrace_start,
            retrace_end: retrace_start + ((u16::from(crtc[0x11] & 15)
                .wrapping_sub(retrace_start + 1) & 15) + 1),
        }
    }

    fn valid(self) -> bool {
        self.dot_hz != 0 && self.dots_per_clock != 0
            && self.horizontal_total != 0 && self.vertical_total != 0
            && self.retrace_end >= self.retrace_start
            && self.blank_end >= self.blank_start
            && self.horizontal_blank_end >= self.horizontal_blank_start
    }

    pub fn clock_at(self, ns: u64) -> u64 {
        if !self.valid() { return 0; }
        (u128::from(ns) * u128::from(self.dot_hz)
            / (1_000_000_000 * u128::from(self.dots_per_clock)))
            .min(u128::from(u64::MAX)) as u64
    }

    /// First nanosecond at which a character-clock edge is observable.
    pub fn time_at(self, clock: u64) -> u64 {
        if !self.valid() { return u64::MAX; }
        (u128::from(clock) * 1_000_000_000 * u128::from(self.dots_per_clock))
            .div_ceil(u128::from(self.dot_hz)).min(u128::from(u64::MAX)) as u64
    }

    pub fn frame_clocks(self) -> u64 {
        u64::from(self.horizontal_total) * u64::from(self.vertical_total)
    }

    pub fn status(self, ns: u64) -> u8 {
        if !self.valid() { return 1; }
        let clock = self.clock_at(ns) % self.frame_clocks();
        let line = clock / u64::from(self.horizontal_total);
        let horizontal = clock % u64::from(self.horizontal_total);
        let retrace = self.in_interval(line, self.retrace_start, self.retrace_end);
        let disabled = line >= u64::from(self.vertical_display)
            || horizontal >= u64::from(self.horizontal_display);
        u8::from(disabled || retrace) | (u8::from(retrace) << 3)
    }

    fn in_interval(self, line: u64, start: u16, end: u16) -> bool {
        let total = u64::from(self.vertical_total);
        if u64::from(start) >= total { return false; }
        (line + total - u64::from(start)) % total < u64::from(end - start)
    }

    pub fn latch_epoch(self, ns: u64, edge_line: u16) -> u64 {
        if !self.valid() { return 0; }
        let clock = self.clock_at(ns);
        let edge = u64::from(edge_line) * u64::from(self.horizontal_total);
        if clock < edge { 0 } else { 1 + (clock - edge) / self.frame_clocks() }
    }
}

/// Ordering at a shared timestamp is intentional: latches precede row fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    RetraceStart,
    RetraceEnd,
    BlankStart,
    BlankEnd,
    HorizontalBlankEnd,
    FrameStart,
    RowStart,
    DisplayEnd,
    HorizontalBlankStart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub clock: u64,
    pub phase: Phase,
    pub frame: u64,
    pub line: u16,
}

/// A single consumer owns the cursor, on either the guest or media core.
/// `next` is bounded (one event); callers can interleave audio service while
/// catching up. Missed phases are never silently collapsed into one frame.
pub struct Sequencer {
    timing: Timing,
    after: (u64, Phase),
}

impl Sequencer {
    /// Attach at the current beam position. Earlier rows cannot be recovered;
    /// the consumer should wait for FrameStart before exposing a full image.
    pub fn new(timing: Timing, now_ns: u64) -> Self {
        Self { timing, after: (timing.clock_at(now_ns), Phase::HorizontalBlankStart) }
    }

    pub fn timing(&self) -> Timing { self.timing }

    /// Call after processing all old-clock events up to a register write.
    /// Reprogramming starts at the new clock's current position, not in the
    /// past. Ordinary address/panning/palette writes do not reprogram timing.
    pub fn reprogram(&mut self, timing: Timing, now_ns: u64) {
        if timing != self.timing { *self = Self::new(timing, now_ns); }
    }

    fn candidate(&self) -> Option<(u64, Phase)> {
        let timing = self.timing;
        if !timing.valid() { return None; }
        let horizontal = u64::from(timing.horizontal_total);
        let frame = timing.frame_clocks();
        let mut best = (u64::MAX, Phase::HorizontalBlankStart);
        let mut consider = |offset: u64, period: u64, phase: Phase| {
            let base = self.after.0 / period * period;
            let Some(mut clock) = base.checked_add(offset) else { return };
            if (clock, phase) <= self.after {
                let Some(next) = clock.checked_add(period) else { return };
                clock = next;
            }
            best = best.min((clock, phase));
        };
        for (line, phase) in [
            (timing.retrace_start, Phase::RetraceStart),
            (timing.retrace_end, Phase::RetraceEnd),
            (timing.blank_start, Phase::BlankStart),
            (timing.blank_end, Phase::BlankEnd),
        ] {
            // Start compares outside the programmed frame never fire.
            let start = match phase {
                Phase::RetraceEnd => timing.retrace_start,
                Phase::BlankEnd => timing.blank_start,
                _ => line,
            };
            if start < timing.vertical_total {
                consider(u64::from(line % timing.vertical_total) * horizontal, frame, phase);
            }
        }
        consider(0, frame, Phase::FrameStart);
        consider(0, horizontal, Phase::RowStart);
        if timing.horizontal_display < timing.horizontal_total {
            consider(u64::from(timing.horizontal_display), horizontal, Phase::DisplayEnd);
        }
        if timing.horizontal_blank_start < timing.horizontal_total {
            consider(u64::from(timing.horizontal_blank_start), horizontal, Phase::HorizontalBlankStart);
            consider(u64::from(timing.horizontal_blank_end % timing.horizontal_total),
                horizontal, Phase::HorizontalBlankEnd);
        }
        (best.0 != u64::MAX).then_some(best)
    }

    pub fn deadline_ns(&self) -> u64 {
        self.candidate().map_or(u64::MAX, |(clock, _)| self.timing.time_at(clock))
    }

    pub fn next(&mut self, now_ns: u64) -> Option<Event> {
        let (clock, phase) = self.candidate()?;
        if clock > self.timing.clock_at(now_ns) { return None; }
        self.after = (clock, phase);
        Some(Event {
            clock, phase,
            frame: clock / self.timing.frame_clocks(),
            line: ((clock % self.timing.frame_clocks())
                / u64::from(self.timing.horizontal_total)) as u16,
        })
    }
}
