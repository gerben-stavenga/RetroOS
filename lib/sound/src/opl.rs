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
    chip: alloc::boxed::Box<Opl3Chip>,
    /// Shared address latch: `bank << 8 | index`, as the chip's `write_register`
    /// wants it. The bank bit comes from which address port was written.
    index: u16,
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
    pub fn new(now: u64) -> Self {
        Fm {
            // new_boxed, NOT Box::new(Opl3Chip::new(..)): the by-value
            // constructor materializes the ~20 KB chip on the kernel stack,
            // which overflowed it on metal (creation happens in the guest's
            // OUT trap path).
            chip: Opl3Chip::new_boxed(NATIVE_RATE),
            index: 0,
            status: 0,
            last_write_ms: now,
            mix_acc: 0,
            hold: (0, 0),
            pending: alloc::collections::VecDeque::new(),
        }
    }

    /// The status register — what a read of any FM window port returns.
    pub fn status(&self) -> u8 {
        self.status
    }

    /// Guest write to an FM port.
    pub fn write(&mut self, now: u64, port: OplPort, val: u8) {
        match port {
            OplPort::Addr(bank) => self.index = ((bank as u16) << 8) | val as u16,
            OplPort::Data => {
                // Voice/operator registers (0x20+ in either bank) are real
                // synthesis activity and (re)start the pump's hangover. The
                // low block — waveform-select enable, NTS, timers, NEW — is
                // detection/init traffic: a probe alone must not start a
                // (silent) stream.
                if (self.index & 0xFF) >= 0x20 {
                    self.last_write_ms = now;
                }
                if self.index == 0x004 {
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
                if self.pending.len() >= PENDING_MAX {
                    let (reg, val) = self.pending.pop_front().unwrap();
                    self.chip.write_register(reg, val);
                }
                self.pending.push_back((self.index, val));
            }
        }
    }

    /// Whether the synth currently owes the sink audio: envelopes still
    /// sounding, or the driver wrote recently (between-notes hangover).
    /// The mixer pump keeps the canonical stream open while this holds.
    pub fn audible(&self, now: u64) -> bool {
        self.chip.active_voice_count() > 0
            || !self.pending.is_empty()
            || now.saturating_sub(self.last_write_ms) < HANGOVER_MS
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
        self.chip.active_voice_count() > 0 || !self.pending.is_empty()
    }

    /// Add FM at the pump's rate: per output frame advance the chip by the
    /// corresponding number of native frames (zero-order hold on the last),
    /// summing saturating. Each native frame first releases one queued guest
    /// write, which is what keeps consecutive writes ≥1 frame apart — see
    /// `pending`. No sub-block events: the OPL's guest-visible timers run on
    /// virtual time, not the stream.
    pub fn mix_into(
        &mut self,
        rate: u32,
        block: &mut [(i32, i32)],
        gain_q16: (i32, i32),
    ) {
        let rate = rate.max(4_000); // guest-programmed; never let it stall us
        let mut pair = [0i16; 2];
        for slot in block.iter_mut() {
            self.mix_acc += NATIVE_RATE;
            while self.mix_acc >= rate {
                self.mix_acc -= rate;
                if let Some((reg, val)) = self.pending.pop_front() {
                    self.chip.write_register(reg, val);
                }
                let _ = self.chip.generate(&mut pair);
                self.hold = (pair[0], pair[1]);
            }
            slot.0 += (self.hold.0 as i32 * gain_q16.0) >> 16;
            slot.1 += (self.hold.1 as i32 * gain_q16.1) >> 16;
        }
    }
}
