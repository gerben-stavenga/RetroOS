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
//! Output follows the one-producer rule of the canonical `sound` sink:
//!
//!  - **standalone** (no DSP playback): [`OplFm::tick`] paces native-rate
//!    frames by virtual time straight into `sound::play` — the sink owns
//!    any resampling, like every other producer.
//!  - **mixed** (DSP playback active): the DSP stream owns the sink, and
//!    `emit_frames` pulls FM frames at the DSP rate via [`OplFm::mix_frame`]
//!    (chip-native steps, zero-order hold — the same resampling the codec
//!    drivers use) and adds them into the canonical i16-stereo frames.
//!
//! The synth pauses (and the stream parks) once every envelope is released
//! and the driver has gone quiet; state is per-thread and dropped on program
//! cleanup like the rest of the virtual SB.

use nuked_opl3::Opl3Chip;

/// The YMF262's native output rate (14.318 MHz master clock / 288).
const NATIVE_RATE: u32 = 49_716;

/// Keep synthesizing this long after the last data-register write even with
/// all envelopes released — drivers pause between notes and between songs.
const HANGOVER_MS: u64 = 2_000;

/// Longest virtual-time gap made up in one pump (first tick, or the task was
/// backgrounded): older backlog is dropped, not synthesized — nobody heard it.
const MAX_CATCHUP_MS: u64 = 100;

/// Frames per `sound::play` push in the standalone pump.
const CHUNK_FRAMES: usize = 128;

/// Canonical shape FM synthesis is produced in: signed 16-bit stereo.
const CANON: crate::kernel::sound::Format = crate::kernel::sound::Format {
    bits: 16,
    signed: true,
    channels: 2,
};

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
    /// `get_ticks()` at the last `tick` (standalone pacing).
    last_ms: u64,
    /// Sub-frame pacing accumulator, units of frames×1000 (as vsb's `frac`).
    frac: u64,
    /// Native-frame accumulator for the DSP-rate pull in `mix_frame`.
    mix_acc: u32,
    /// Last native frame generated (zero-order hold for `mix_frame`).
    hold: (i16, i16),
    /// A standalone stream is open (so going idle must `sound::stop`).
    streaming: bool,
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
            last_ms: now,
            frac: 0,
            mix_acc: 0,
            hold: (0, 0),
            streaming: false,
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
    fn audible(&self, now: u64) -> bool {
        self.chip.active_voice_count() > 0
            || now.saturating_sub(self.last_write_ms) < HANGOVER_MS
    }

    /// Whether `emit_frames` should pull FM into the DSP stream. Voices-only
    /// (no write hangover): a silent chip mixes silence, so skip the work.
    pub(super) fn mixing(&self) -> bool {
        self.chip.active_voice_count() > 0
    }

    /// Standalone pump — the per-quantum device tick. While the DSP stream is
    /// live it owns the sink and pulls FM itself (`mix_frame`), so this only
    /// re-anchors the pacing clock; otherwise synthesize the elapsed virtual
    /// time at native rate and push it to the canonical output.
    pub(super) fn tick<A: crate::Arch>(&mut self, machine: &mut A, dsp_streaming: bool) {
        let now = machine.get_ticks();
        let dt = now.saturating_sub(self.last_ms).min(MAX_CATCHUP_MS);
        self.last_ms = now;
        if dsp_streaming {
            // The DSP stream superseded ours mid-flight; it re-programs the
            // sink rate itself, so there is nothing to stop or flush.
            self.frac = 0;
            self.streaming = false;
            return;
        }
        if !self.audible(now) {
            if self.streaming {
                crate::kernel::sound::stop(machine, false); // pause, keep configured
                self.streaming = false;
            }
            self.frac = 0;
            return;
        }
        self.frac += NATIVE_RATE as u64 * dt;
        let mut n = self.frac / 1000;
        self.frac %= 1000;
        if n == 0 {
            return;
        }
        self.streaming = true;
        let mut pcm = [0i16; CHUNK_FRAMES * 2];
        let mut bytes = [0u8; CHUNK_FRAMES * 4];
        while n > 0 {
            let run = (n as usize).min(CHUNK_FRAMES);
            let _ = self.chip.generate_stream(&mut pcm[..run * 2]);
            for (i, s) in pcm[..run * 2].iter().enumerate() {
                bytes[i * 2..i * 2 + 2].copy_from_slice(&s.to_le_bytes());
            }
            crate::kernel::sound::play(machine, NATIVE_RATE, CANON, &bytes[..run * 4]);
            n -= run as u64;
        }
    }

    /// Pull one FM frame at the DSP stream's rate: advance the chip by the
    /// corresponding number of native frames (zero-order hold on the last).
    /// Keeps FM consumption locked to the DSP cursor, which is already paced
    /// by virtual time.
    pub(super) fn mix_frame(&mut self, rate: u32) -> (i16, i16) {
        let rate = rate.max(4_000); // guest-programmed; never let it stall us
        self.mix_acc += NATIVE_RATE;
        let mut pair = [0i16; 2];
        while self.mix_acc >= rate {
            self.mix_acc -= rate;
            let _ = self.chip.generate(&mut pair);
            self.hold = (pair[0], pair[1]);
        }
        self.hold
    }
}
