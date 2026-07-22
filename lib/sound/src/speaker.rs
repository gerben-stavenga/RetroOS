//! The PC speaker: PIT channel 2 driving a cone through the 8255's port 61h.
//!
//! The smallest card here, and the only one with no IRQ, no DMA and no sample
//! memory — the host hands it two guest-programmed values and pulls frames.
//!
//! What it models is the *pin*, not the note:
//!
//! ```text
//! level = data_bit AND (gate_bit ? ch2_output : 1)
//!          (61h bit 1)  (61h bit 0)
//! ```
//!
//! which is the whole speaker. The host owns the left half of that expression
//! (it decodes port 61h) and the counter that produces `ch2_output`; this card
//! owns the square wave and nothing else.
//!
//! **Tone only, deliberately.** The three ways DOS software makes speaker
//! sound are a gated tone, a bit-banged 1-bit stream (gate off, the guest
//! toggling the data bit), and PWM/"RealSound" (rewriting the ch2 divisor at
//! sample rate). Only the first is modelled. That is what makes the card this
//! small: gate and divisor changes then happen at note boundaries — tens of
//! milliseconds — so the host sampling them once per pump is exact rather than
//! approximate, and no timestamps are needed anywhere.
//!
//! The cost of that choice, stated so it is a decision and not a bug someone
//! rediscovers: a gate pulse that both starts and ends between two pumps
//! merges into its neighbour or disappears. A game whose effects sound wrong
//! is the trigger to revisit, and the answer then is to derive the sample
//! clock from the guest's own pacing (as the SB pipe already does), never to
//! chase finer timestamps — the guest does not run in real time within a slice
//! either, so a finer host clock would buy nothing.

/// The 8254's input clock. Frequency is `PIT_HZ / divisor`, and that is the
/// card's entire notion of time: no `tick`, nothing to advance.
const PIT_HZ: u32 = 1_193_182;

const FULL: u32 = 1 << 16;
const HALF: u32 = 1 << 15;

pub struct Speaker {
    /// PIT channel 2 reload, exactly as the guest programmed it (0 = 65536).
    divisor: u16,
    /// Port 61h bit 0 — timer 2 gate.
    gate: bool,
    /// Port 61h bit 1 — speaker data enable.
    data: bool,
    /// Q16 position within the square's period. Free-running across gate
    /// changes: real hardware's counter is stopped by a low gate, but the
    /// phase it resumes at is not observable, and continuity here means a
    /// re-gated tone does not click.
    phase: u32,
}

impl Speaker {
    pub const fn new() -> Self {
        Speaker { divisor: 0, gate: false, data: false, phase: 0 }
    }

    /// PIT channel 2's reload value changed.
    pub fn set_divisor(&mut self, divisor: u16) {
        self.divisor = divisor;
    }

    /// Port 61h was written: bit 0 gates the counter, bit 1 enables the driver.
    pub fn set_port61(&mut self, val: u8) {
        self.gate = val & 0x01 != 0;
        self.data = val & 0x02 != 0;
    }

    /// Power-on state, for program exit — a program that leaves the speaker
    /// gated on must not beep into the next one.
    pub fn reset(&mut self) {
        *self = Speaker::new();
    }

    /// Whether the cone is being driven audibly. The host's stream-lifecycle
    /// predicate: there is no envelope and no hangover, so a silent speaker is
    /// silent the instant the guest clears either bit.
    ///
    /// The rate is an argument for the same reason every clock here is: a card
    /// reads nothing. It is needed because "audible" genuinely depends on it —
    /// a parked ultrasonic tone (see [`mix_into`](Self::mix_into)) is gated on
    /// but inaudible, and treating it as sound would hold the host's stream
    /// open for as long as a game sits at its title screen.
    pub fn audible(&self, rate: u32) -> bool {
        self.gate && self.data && rate != 0 && !self.above_nyquist(rate)
    }

    fn above_nyquist(&self, rate: u32) -> bool {
        (PIT_HZ as u64) * 2 >= self.div() as u64 * rate as u64
    }

    fn div(&self) -> u32 {
        if self.divisor == 0 { FULL } else { self.divisor as u32 }
    }

    /// Sum the square into the host's block at its mix rate.
    ///
    /// Each output sample is the *average* level over the frame it covers,
    /// not a point sample of the wave — edges land at their fractional
    /// position and the sample they straddle is weighted accordingly. A point
    /// sampler is what makes an emulated speaker sound harsh: tones run high
    /// enough that the square's harmonics fold back audibly at 44.1 kHz, and
    /// the fold-back moves with the note.
    ///
    /// Above Nyquist the fundamental itself would fold, and averaging does
    /// *not* save us there — it only collapses tones fast enough to complete
    /// several cycles inside one frame. So an ultrasonic divisor is silence by
    /// construction, which is also what the hardware does: the cone is a
    /// mechanical lowpass, and DOS software leans on that. Digger parks
    /// channel 2 at divisor 40 (29.8 kHz) with the gate left on whenever no
    /// effect is playing — rendered naively that is a continuous 14.2 kHz
    /// alias whine, which is exactly how this was found.
    pub fn mix_into(&mut self, rate: u32, gain: (i32, i32), block: &mut [(i32, i32)]) {
        if !self.audible(rate) {
            return;
        }
        // Cycles per frame, Q16. Rounded up to 1 so an implausibly long
        // divisor still advances rather than latching DC forever.
        let inc = (((PIT_HZ as u64) << 16) / (self.div() as u64 * rate as u64)).max(1) as u32;

        for slot in block.iter_mut() {
            let p0 = self.phase;
            let p1 = p0 + inc;
            // High time over [p0, p1) as a fraction of the interval, Q16.
            let duty = (((high_time(p1) - high_time(p0)) as u64) << 16) / inc as u64;
            // Q16 duty in 0..=1 becomes a level in -1..=+1.
            let level = (duty as i32) * 2 - FULL as i32;
            let amp = (level * i16::MAX as i32) >> 16;
            slot.0 += (amp * gain.0) >> 16;
            slot.1 += (amp * gain.1) >> 16;
            self.phase = p1 & (FULL - 1);
        }
    }
}

impl Default for Speaker {
    fn default() -> Self {
        Speaker::new()
    }
}

/// Total time the output has been high over `[0, p)`, in Q16 cycles — half of
/// every whole period, plus however much of the partial one falls in the
/// first half. Differencing this across a frame gives that frame's high time
/// exactly, however many edges it contains.
fn high_time(p: u32) -> u32 {
    (p >> 16) * HALF + (p & (FULL - 1)).min(HALF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(divisor: u16) -> Speaker {
        let mut s = Speaker::new();
        s.set_divisor(divisor);
        s.set_port61(0x03);
        s
    }

    /// The frequency the card actually produces, measured the way the WAV
    /// captures are: count zero crossings of a one-second render.
    fn measured_hz(divisor: u16, rate: u32) -> f64 {
        let mut s = on(divisor);
        let mut block = [(0i32, 0i32); 1024];
        let mut crossings = 0u32;
        let mut prev = 0i32;
        let mut frames = 0u32;
        while frames < rate {
            block.fill((0, 0));
            s.mix_into(rate, (1 << 16, 1 << 16), &mut block);
            for (l, _) in block.iter() {
                if (*l > 0) != (prev > 0) && *l != 0 {
                    crossings += 1;
                }
                prev = *l;
            }
            frames += block.len() as u32;
        }
        crossings as f64 / 2.0 * rate as f64 / frames as f64
    }

    #[test]
    fn frequency_matches_the_divisor() {
        // 0x04D3 is the divisor a BIOS beep uses (~896 Hz); 2394 is middle A.
        for div in [0x04D3u16, 2394, 1193, 9000] {
            let want = PIT_HZ as f64 / div as f64;
            let got = measured_hz(div, 44_100);
            assert!(
                (got - want).abs() / want < 0.01,
                "divisor {div}: want {want:.1} Hz, got {got:.1} Hz"
            );
        }
    }

    #[test]
    fn silent_unless_both_bits_are_set() {
        let mut block = [(0i32, 0i32); 64];
        for val in [0x00u8, 0x01, 0x02] {
            let mut s = on(2394);
            s.set_port61(val);
            block.fill((0, 0));
            s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
            assert!(!s.audible(44_100));
            assert!(block.iter().all(|&(l, r)| l == 0 && r == 0), "port61={val:#04x}");
        }
    }

    /// A square's mean is zero and its peak is full scale — the level the
    /// machine's scale constant is calibrated against. Averaged over ten
    /// seconds: the window is not a whole number of periods, so a shorter one
    /// reports the leftover half-cycle as DC (a tenth of a second at 498 Hz
    /// leaves ~130).
    fn amplitude_and_mean(divisor: u16) -> (i32, i64) {
        let mut s = on(divisor);
        let mut block = [(0i32, 0i32); 4410];
        let (mut peak, mut sum, mut frames) = (0i32, 0i64, 0i64);
        for _ in 0..100 {
            block.fill((0, 0));
            s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
            peak = peak.max(block.iter().map(|&(l, _)| l.abs()).max().unwrap());
            sum += block.iter().map(|&(l, _)| l as i64).sum::<i64>();
            frames += block.len() as i64;
        }
        (peak, sum / frames)
    }

    #[test]
    fn full_scale_square_centred_on_zero() {
        let (peak, mean) = amplitude_and_mean(2394);
        assert!(peak > 32_000, "peak {peak}");
        assert!(mean.abs() < 64, "dc offset {mean}");
    }

    /// An ultrasonic divisor is silence, not an alias.
    ///
    /// Divisor 40 is the case that matters and the one a naive renderer gets
    /// wrong: 29.8 kHz is only *just* above Nyquist, so it completes well
    /// under a cycle per frame and per-frame averaging does nothing for it —
    /// it folds to a continuous 14.2 kHz whine. Digger parks channel 2 there
    /// with the gate on whenever no effect is playing, so this is what a
    /// speaker-only game sounds like for most of its runtime. Divisor 1 alone
    /// (1.19 MHz, dozens of cycles per frame) passes even without the guard,
    /// which is exactly why it is not sufficient as a test.
    #[test]
    fn ultrasonic_divisors_are_silent() {
        for div in [40u16, 54, 1] {
            let mut s = on(div);
            assert!(!s.audible(44_100), "divisor {div} reported audible");
            let mut block = [(0i32, 0i32); 4410];
            s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
            assert!(block.iter().all(|&(l, r)| l == 0 && r == 0), "divisor {div} sounded");
        }
        // ...and the first divisor below Nyquist still sounds.
        assert!(on(55).audible(44_100));
    }

    /// Gain is applied per channel, so a host can pan or mute one side.
    #[test]
    fn gain_scales_each_channel() {
        let mut s = on(2394);
        let mut block = [(0i32, 0i32); 512];
        s.mix_into(44_100, (1 << 16, 1 << 15), &mut block);
        let l = block.iter().map(|&(l, _)| l.abs()).max().unwrap();
        let r = block.iter().map(|&(_, r)| r.abs()).max().unwrap();
        assert!((l - 2 * r).abs() <= 2, "l {l} r {r}");
    }
}
