//! AdLib / Sound Blaster FM synthesis (OPL2/OPL3), for the emulated SB.
//!
//! One [`nuked_opl3::Opl3Chip`] (a bit-exact, integer-only Nuked-OPL3 port)
//! synthesizes at the YMF262's native rate. The guest sees the full OPL3
//! register surface: the AdLib window `0x388-0x38B` and its SB mirrors
//! `base+0..3` / `base+8..9`, one shared address latch with the bank bit
//! taken from *which* address port was written — exactly the real chip's
//! decode. Timer/status behavior keeps vsb.rs's proven detection semantics
//! (start ⇒ instant expiry; ms ticks can't resolve the 80 µs timer, and
//! every probe only polls "did it expire").
//!
//! Output goes through the host's mixer pump: the chip adds its frames through
//! [`Fm::mix_into`] at the pump's rate (chip-native steps, zero-order hold —
//! the same resampling the codec drivers use). [`Fm::audible`] keeps the
//! canonical stream open through the between-notes hangover; once every
//! envelope is released and the driver has gone quiet the host parks the
//! stream. Passive like every card here: the clock arrives as an argument to
//! [`Fm::write`], never read; the chip owns no I/O.

use nuked_opl3::Opl3Chip;

/// The YMF262's native output rate (14.318 MHz master clock / 288).
pub const NATIVE_RATE: u32 = 49_716;

pub const OPERATOR_OFFSETS: [u16; 18] = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21,
];

/// The write-only programming and address latch shared by both renderers.
pub struct Registers {
    values: [Option<u8>; 512],
    index: u16,
}

impl Registers {
    pub fn index(&self) -> u16 { self.index }

    pub fn is_key_register(index: u16) -> bool {
        matches!(index, 0xb0..=0xb8 | 0x1b0..=0x1b8 | 0xbd)
    }

    /// Enable the selected OPL mode before programming operators, and restore
    /// melodic and rhythm keys only once the instruments and pitches are set.
    pub fn replay(&self, mut write: impl FnMut(u16, u8)) {
        for index in [0x105, 0x104] {
            if let Some(val) = self.values[index] { write(index as u16, val); }
        }
        for (index, val) in self.values.iter().enumerate() {
            let index = index as u16;
            if let Some(val) = val
                && !matches!(index, 0x104 | 0x105)
                && !Self::is_key_register(index)
            {
                write(index, *val);
            }
        }
        for index in (0xb0..=0xb8).chain(0x1b0..=0x1b8).chain([0xbd]) {
            if let Some(val) = self.values[index] { write(index as u16, val); }
        }
    }
}

/// Keep synthesizing this long after the last data-register write even with
/// all envelopes released — drivers pause between notes and between songs.
const HANGOVER_MS: u64 = 2_000;

/// Ceiling on queued-but-unapplied register writes (see `pending`). Deep
/// enough for any real driver's init burst (a full 22-register instrument
/// load is ~90 writes); a write storm past this gives up the inter-write
/// gap rather than the write, so the queue can never grow without bound.
const PENDING_MAX: usize = 4_096;

/// What a guest-visible FM port decodes to.
pub enum OplPort {
    /// Address latch write; the payload is the register file (bank) the
    /// port hard-wires: 0 for `0x388`/`base+0`/`base+8`, 1 for the OPL3
    /// extension ports `0x38A`/`base+2`.
    Addr(u8),
    /// Data write to the latched (bank, index) register.
    Data,
}

/// Decode a guest FM port against the SB base, or `None` if not an FM port.
/// Covers the AdLib block and both SB mirrors; reads of any of these return
/// the (single) status register.
pub fn decode_port(io_base: u16, p: u16) -> Option<OplPort> {
    match p {
        0x388 => Some(OplPort::Addr(0)),
        0x38A => Some(OplPort::Addr(1)),
        0x389 | 0x38B => Some(OplPort::Data),
        _ => match p.wrapping_sub(io_base) {
            0x0 | 0x8 => Some(OplPort::Addr(0)),
            0x2 => Some(OplPort::Addr(1)),
            0x1 | 0x3 | 0x9 => Some(OplPort::Data),
            _ => None,
        },
    }
}

/// Per-thread FM synthesizer state. Created lazily on the first FM register
/// write (the chip is ~20 KB of tables/slots; programs without FM never pay
/// for it), dropped with the rest of the SB state on program cleanup.
pub struct Fm {
    /// Native-rate synthesis core. Boxed: the chip is ~20 KB and `PcMachine`
    /// is per-thread state.
    chip: Option<alloc::boxed::Box<Opl3Chip>>,
    /// Shared address latch: `bank << 8 | index`, as the chip's `write_register`
    /// wants it. The bank bit comes from which address port was written.
    registers: Registers,
    /// Status register (timer expiry bits). Same instant-expiry semantics the
    /// detection stub had: bits 1-2 stay 0, which is also the "I am an OPL3"
    /// answer type probes look for.
    status: u8,
    /// `get_ticks()` at the last data-register write (activity hangover).
    last_write_ms: u64,
    /// Native-frame accumulator for the foreign-rate pull in `mix`.
    mix_acc: u32,
    /// Last native frame generated (zero-order hold for `mix`).
    hold: (i16, i16),
    /// Guest register writes not yet handed to the chip, released one per
    /// generated frame by `mix_into`.
    ///
    /// The chip does not retrigger a note on the key-on write itself: a write
    /// only flips the slot's `key` bit. The attack is armed inside the chip's
    /// per-sample envelope step, which fires only when it observes `key != 0`
    /// while the envelope is already in RELEASE — and RELEASE is itself set by
    /// an *earlier* per-sample step that saw `key == 0`. A note therefore
    /// re-attacks only if at least one frame is generated between the driver's
    /// key-off and its key-on.
    ///
    /// Real silicon is clocked continuously at `NATIVE_RATE`, so two OUTs are
    /// always ≥1 frame apart and that always holds. Our chip is clocked only by
    /// the mixer pump, so every write inside one pump window would otherwise
    /// land between the same two frames: a driver that writes key-off, fnum,
    /// key-on back-to-back (the usual shape) would never re-attack, and the
    /// note would hang at its sustain level — audible as music that keeps its
    /// melody but collapses to a fraction of its volume.
    pending: alloc::collections::VecDeque<(u16, u8)>,
}

impl Fm {
    pub fn new(now: u64, native: bool) -> Self {
        Fm {
            // new_boxed, NOT Box::new(Opl3Chip::new(..)): the by-value
            // constructor materializes the ~20 KB chip on the kernel stack,
            // which overflowed it on metal (creation happens in the guest's
            // OUT trap path).
            chip: (!native).then(|| Opl3Chip::new_boxed(NATIVE_RATE)),
            registers: Registers { values: [None; 512], index: 0 },
            status: 0,
            last_write_ms: now,
            mix_acc: 0,
            hold: (0, 0),
            pending: alloc::collections::VecDeque::new(),
        }
    }

    pub fn registers(&self) -> &Registers { &self.registers }

    pub fn suspend(&mut self) {
        self.chip = None;
        self.pending.clear();
        self.mix_acc = 0;
        self.hold = (0, 0);
    }

    pub fn resume(&mut self) {
        let mut chip = Opl3Chip::new_boxed(NATIVE_RATE);
        self.registers.replay(|index, val| chip.write_register(index, val));
        self.chip = Some(chip);
    }

    /// The status register — what a read of any FM window port returns.
    pub fn status(&self) -> u8 {
        self.status
    }

    /// Guest write to an FM port.
    pub fn write(&mut self, now: u64, port: OplPort, val: u8) {
        match port {
            OplPort::Addr(bank) => self.registers.index = ((bank as u16) << 8) | val as u16,
            OplPort::Data => {
                let index = self.registers.index;
                // Timer status reset is a strobe, not the timer configuration.
                if index != 0x004 || val & 0x80 == 0 {
                    self.registers.values[usize::from(index)] = Some(val);
                }
                // Voice/operator registers (0x20+ in either bank) are real
                // synthesis activity and (re)start the pump's hangover. The
                // low block — waveform-select enable, NTS, timers, NEW — is
                // detection/init traffic: a probe alone must not start a
                // (silent) stream.
                if (index & 0xFF) >= 0x20 {
                    self.last_write_ms = now;
                }
                if index == 0x004 {
                    // Timer control: bit7 = reset status/IRQ; bit0/1 = start
                    // T1/T2. Detection starts a timer then polls status for
                    // the expiry, so expire instantly (ms ticks can't resolve
                    // the real 80 µs period). The chip ignores timer registers
                    // (Nuked-OPL3 models synthesis only), so don't forward.
                    if val & 0x80 != 0 {
                        self.status = 0;
                    } else {
                        if val & 0x01 != 0 {
                            self.status |= 0xC0; // IRQ | T1 expired
                        }
                        if val & 0x02 != 0 {
                            self.status |= 0xA0; // IRQ | T2 expired
                        }
                    }
                    return;
                }
                let Some(chip) = &mut self.chip else { return; };
                if self.pending.len() >= PENDING_MAX {
                    let (reg, val) = self.pending.pop_front().unwrap();
                    chip.write_register(reg, val);
                }
                self.pending.push_back((index, val));
            }
        }
    }

    /// Whether the synth currently owes the sink audio: envelopes still
    /// sounding, or the driver wrote recently (between-notes hangover).
    /// The mixer pump keeps the canonical stream open while this holds.
    pub fn audible(&self, now: u64) -> bool {
        self.mixing() || now.saturating_sub(self.last_write_ms) < HANGOVER_MS
    }
}

/// The mixer pump pulls FM through the canonical mix-source shape.
impl Fm {
    /// Voices-only (no write hangover): a silent chip mixes silence — skip
    /// the work. (`audible` decides whether the *stream* stays open.) Queued
    /// writes also count: the queue drains a frame at a time from `mix_into`,
    /// so a chip whose only pending work is a key-on must still be pumped or
    /// the write would never reach it.
    pub fn mixing(&self) -> bool {
        self.chip.as_ref().is_some_and(|chip| chip.active_voice_count() > 0)
            || !self.pending.is_empty()
    }

    /// Add FM at the pump's rate: per output frame advance the chip by the
    /// corresponding number of native frames (zero-order hold on the last),
    /// summing into wide PCM with final clipping left to the sink. Each native
    /// frame releases one queued guest write, keeping writes ≥1 frame apart — see
    /// `pending`. No sub-block events: the OPL's guest-visible timers run on
    /// virtual time, not the stream.
    pub fn mix_into(
        &mut self,
        rate: u32,
        block: &mut [(i32, i32)],
        gain_q16: (i32, i32),
    ) {
        let Some(chip) = &mut self.chip else { return; };
        let rate = rate.max(4_000); // guest-programmed; never let it stall us
        let mut pair = [0i16; 2];
        for slot in block.iter_mut() {
            self.mix_acc += NATIVE_RATE;
            while self.mix_acc >= rate {
                self.mix_acc -= rate;
                if let Some((reg, val)) = self.pending.pop_front() {
                    chip.write_register(reg, val);
                }
                let _ = chip.generate(&mut pair);
                self.hold = (pair[0], pair[1]);
            }
            slot.0 += ((i64::from(self.hold.0) * i64::from(gain_q16.0)) >> 16) as i32;
            slot.1 += ((i64::from(self.hold.1) * i64::from(gain_q16.1)) >> 16) as i32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Fm, NATIVE_RATE, OplPort};

    #[test]
    fn native_writes_rebuild_a_held_note_and_preserve_the_address_latch() {
        let mut fm = Fm::new(0, true);
        for (index, val) in [
            (0x23, 0x21), (0x40, 0x3f), (0x63, 0xf0), (0x83, 0x0f),
            (0xa0, 0x98), (0xb0, 0x31),
        ] {
            fm.write(0, OplPort::Addr(0), index);
            fm.write(0, OplPort::Data, val);
        }
        assert!(!fm.mixing());
        assert_eq!(fm.registers().index(), 0xb0);
        fm.resume();
        let mut block = [(0, 0); 128];
        for _ in 0..8 {
            block.fill((0, 0));
            fm.mix_into(NATIVE_RATE, &mut block, (65_536, 65_536));
        }
        assert!(block.iter().any(|&(left, _)| left.abs() > 100));
        fm.suspend();
        fm.write(0, OplPort::Data, 0x11); // key-off to the still-selected register
        fm.resume();
        assert!(!fm.mixing());
    }

    #[test]
    fn boosted_opl_retains_headroom_before_final_output_gain() {
        let mut fm = super::Fm::new(0, false);
        fm.hold = (i16::MAX, i16::MIN);
        let mut block = [(123, -456)];
        // No native frame elapses: exercise the held sample at both rails.
        fm.mix_into(super::NATIVE_RATE * 2, &mut block, (141_000, 141_000));
        assert_eq!(block[0].0, 123 + ((i64::from(i16::MAX) * 141_000) >> 16) as i32);
        assert_eq!(block[0].1, -456 + ((i64::from(i16::MIN) * 141_000) >> 16) as i32);
        assert!(block[0].0 > i32::from(i16::MAX));
        assert!(block[0].1 < i32::from(i16::MIN));
    }
}
