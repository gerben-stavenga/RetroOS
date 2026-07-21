//! Per-voice state. Fields are `pub` on purpose: personalities read live
//! state back for guest register readback (GF1 current-address/current-volume
//! registers are exact shifts of `addr`/`vol`), and program voices by struct
//! assignment — no getter forest between a register file and its hardware.
//!
//! Everything here must stay zero-valid: [`Engine::new_boxed`] and resets
//! rely on all-zero bytes being a stopped, silent voice (see the SAFETY note
//! there). `LoopMode` is `repr(u8)` with `None = 0` for the same reason.

/// What happens when a running voice crosses its `end` (or `start`, when
/// playing backwards) boundary.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LoopMode {
    /// Stop and clamp at the boundary — unless [`Voice::rollover`] lets the
    /// address run on past it (the GF1's IRQ-without-stop streaming idiom).
    #[default]
    None = 0,
    /// Wrap to the opposite boundary, preserving the overshoot fraction.
    Forward,
    /// Reflect: reverse direction at the boundary.
    Bidi,
}

/// A hardware volume ramp in the log-volume register domain — the GF1's
/// per-voice ramp generator, and (retargeted segment by segment on RampEnd
/// events) the ADSR primitive for the MIDI personalities.
#[derive(Clone, Copy, Default)]
pub struct Ramp {
    pub running: bool,
    /// Amount added EVERY frame, in the same ramp-domain units as `floor` /
    /// `ceil` / `Voice::vol` (the GF1 16-bit volume register scaled up by
    /// [`volume::RAMP_FRACT`](crate::volume::RAMP_FRACT) fractional bits).
    ///
    /// Both the rate register's 6-bit field and its 2-bit divider are folded
    /// in here at write time, so the ramp advances on every frame and holds no
    /// phase state. That is deliberate: a countdown-paced ramp has phase, and
    /// DMX rewrites voice ramps faster than the slow dividers' own period,
    /// which reset that phase and cost the ramp updates it should have made.
    /// DOSBox Staging (`WriteVolRate`) and 86Box (`rfreq`) both do it this way.
    ///
    /// Note the 6-bit field counts in units of the volume's 12-bit significand
    /// (bit 4 of the 16-bit register), so the GF1 front-end also scales it by
    /// 16 on the way in. Feeding the raw field straight through made every ramp
    /// 16x too slow — a ~1.5 ms note attack took ~24 ms, and DMX busy-waits
    /// (interrupts off) for a ramp, which swallowed the guest's music ticks.
    pub inc: i32,
    /// Ramp boundaries, ramp-domain (GF1 ramp start/end registers hold the
    /// top byte: `reg << 8`, then scaled by `RAMP_FRACT`).
    pub floor: i32,
    pub ceil: i32,
    /// Direction: toward `floor` when set.
    pub down: bool,
    /// Boundary behavior, mirroring the wave loop: `looped` wraps (or
    /// reflects when `bidi` is also set); neither stops the ramp.
    pub bidi: bool,
    pub looped: bool,
    /// Raise a RampEnd event at each boundary.
    pub irq: bool,
}

/// Per-voice resonant lowpass — shaped for the SF2/EMU8000 voice model but a
/// pass-through stub until a personality needs it (the GF1 has no filter).
/// Adding the real 2-pole integer filter changes only this struct's `apply`.
#[derive(Clone, Copy, Default)]
pub struct VoiceFilter {
    pub enabled: bool,
    /// Cutoff/resonance in fixed point — unused until the filter lands;
    /// reserved so enabling it later reshapes no API.
    pub cutoff: i32,
    pub q: i32,
    pub state: [i32; 2],
}

impl VoiceFilter {
    #[inline]
    pub fn apply(&mut self, s: i32) -> i32 {
        if !self.enabled {
            return s;
        }
        s // real 2-pole integer lowpass lands with the SF2/AWE32 work
    }
}

#[derive(Clone, Copy, Default)]
pub struct Voice {
    pub running: bool,
    /// 16-bit little-endian signed frames when set; signed 8-bit otherwise.
    pub bits16: bool,
    /// Position / increment / loop boundaries, Q32.32 GF1 sample addresses.
    /// Width-agnostic: for 16-bit voices the bank/doubling transform to a DRAM
    /// byte offset is applied at fetch, not here, so these stay valid across a
    /// change of `bits16` and never need re-deriving from the register images.
    pub addr: u64,
    pub inc: u64,
    pub start: u64,
    pub end: u64,
    pub loop_mode: LoopMode,
    pub backwards: bool,
    /// Raise a wave-IRQ event on every boundary crossing.
    pub irq_on_end: bool,
    /// With `LoopMode::None`: keep running past the boundary instead of
    /// stopping (GF1 rollover bit — streaming players' refill idiom).
    pub rollover: bool,
    /// Current volume, ramp-domain: the GF1 16-bit log-volume register scaled
    /// up by [`volume::RAMP_FRACT`](crate::volume::RAMP_FRACT) fractional bits
    /// so the ramp can move it by less than a register unit per frame. Shift
    /// down by `RAMP_FRACT` for the register value or for `volume::lin_q16`.
    pub vol: i32,
    pub ramp: Ramp,
    /// Resolved stereo gains, Q12 (pan tables are personality policy).
    pub pan_l: u16,
    pub pan_r: u16,
    pub filter: VoiceFilter,
}

/// Voice-boundary IRQ events, OR-accumulated by the mix loop as per-voice
/// bitmasks; the personality drains them into its IRQ state each chunk.
#[derive(Default, Clone, Copy)]
pub struct Events {
    pub wave_irq: u32,
    pub ramp_irq: u32,
}

impl Events {
    pub fn any(&self) -> bool {
        self.wave_irq != 0 || self.ramp_irq != 0
    }
}
