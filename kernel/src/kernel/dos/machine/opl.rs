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
//! Output goes through the machine mixer pump (`machine::audio_tick`): the
//! chip adds its frames through the common PCM-source mixer path and into
//! the pump's block at the pump's rate (chip-native steps, zero-order hold —
//! the same resampling the codec drivers use). [`OplFm::audible`] keeps the
//! canonical stream open through the between-notes hangover; once every
//! envelope is released and the driver has gone quiet the pump parks the
//! stream. State is per-thread and dropped on program cleanup like the rest
//! of the virtual SB.

use nuked_opl3::Opl3Chip;

/// The YMF262's native output rate (14.318 MHz master clock / 288).
pub(super) const NATIVE_RATE: u32 = 49_716;

/// Keep synthesizing this long after the last data-register write even with
/// all envelopes released — drivers pause between notes and between songs.
const HANGOVER_MS: u64 = 2_000;

/// What a guest-visible FM port decodes to.
pub(super) enum OplPort {
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
pub(super) fn decode_port(io_base: u16, p: u16) -> Option<OplPort> {
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
pub(super) struct OplFm {
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
}

impl OplFm {
    pub(super) fn new(now: u64) -> Self {
        OplFm {
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
        }
    }

    /// The status register — what a read of any FM window port returns.
    pub(super) fn status(&self) -> u8 {
        self.status
    }

    /// Guest write to an FM port.
    pub(super) fn write(&mut self, now: u64, port: OplPort, val: u8) {
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
                self.chip.write_register(self.index, val);
            }
        }
    }

    /// Whether the synth currently owes the sink audio: envelopes still
    /// sounding, or the driver wrote recently (between-notes hangover).
    /// The mixer pump keeps the canonical stream open while this holds.
    pub(super) fn audible(&self, now: u64) -> bool {
        self.chip.active_voice_count() > 0
            || now.saturating_sub(self.last_write_ms) < HANGOVER_MS
    }
}

/// The mixer pump pulls FM through the canonical mix-source shape.
impl OplFm {
    /// Voices-only (no write hangover): a silent chip mixes silence — skip
    /// the work. (`audible` decides whether the *stream* stays open.)
    pub(super) fn mixing(&self) -> bool {
        self.chip.active_voice_count() > 0
    }

    /// Add FM at the pump's rate: per output frame advance the chip by the
    /// corresponding number of native frames (zero-order hold on the last),
    /// summing saturating. No sub-block events: the OPL's guest-visible
    /// timers run on virtual time, not the stream.
    pub(super) fn mix_into<A: crate::Arch>(&mut self, _machine: &mut A, rate: u32, _base: u64, block: &mut [(i16, i16)]) {
        let rate = rate.max(4_000); // guest-programmed; never let it stall us
        let mut pair = [0i16; 2];
        for slot in block.iter_mut() {
            self.mix_acc += NATIVE_RATE;
            while self.mix_acc >= rate {
                self.mix_acc -= rate;
                let _ = self.chip.generate(&mut pair);
                self.hold = (pair[0], pair[1]);
            }
            slot.0 = slot.0.saturating_add(self.hold.0);
            slot.1 = slot.1.saturating_add(self.hold.1);
        }
    }
}
