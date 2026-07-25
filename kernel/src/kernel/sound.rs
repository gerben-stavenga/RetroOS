//! Canonical kernel sound API — one PCM output path for every personality.
//!
//! Like [`vfs`](super::vfs), this is a *kernel* subsystem, not an machine concern.
//! It canonicalizes any source PCM — the Sound Blaster DSP wire formats today
//! (8/16-bit, mono/stereo, signed/unsigned); OSS / native producers later — into
//! one shape (**signed 16-bit, interleaved stereo**) and streams it to the
//! RetroOS canonical audio device.
//!
//! That device sits *below* the machine boundary and is reached through ordinary
//! port I/O — exactly as `vfs`→`hdd.rs` reaches the ATA disk via `arch::inb/
//! outb`, never a bespoke `Arch` method (so `trait Arch` stays minimal). The
//! hosted interpreter backs the port window with a WAV-to-disk sink (see
//! `machine-interp/src/devices.rs`, where `std` lives); metal leaves the window
//! unpopulated, so the kernel sound path is inert there and the existing SB
//! passthrough to a real card still produces sound.
//!
//! Routing is decided ONCE at boot (`platform::Audio`): the AC'97 codec
//! where one was found, the port window where a backend installed a sink,
//! nowhere otherwise — `play` just matches the type.

use core::sync::atomic::{AtomicU32, Ordering};

// RetroOS canonical audio device — a kernel-private ISA port window. It is
// *never* guest-visible: only the kernel addresses it, through `machine.outw`
// (guest `OUT`s surface as `KernelEvent::Out` and never reach this window). The
// sample rate fits in 16 bits (every SB rate is < 65536 Hz).
const AUDIO_SIG: u16 = 0x530; // R: signature ('RA'); W: sample rate (Hz)
const AUDIO_LEFT: u16 = 0x532; // W: latch the left i16
const AUDIO_RIGHT: u16 = 0x534; // W: right i16, and commit the (L,R) frame
const SIGNATURE: u16 = 0x5241; // 'R','A' — RetroOS Audio

/// Source PCM wire format, as a producer presents it (the Sound Blaster DSP
/// digital formats: 8-bit unsigned or 16-bit signed, mono or interleaved
/// stereo). The sound layer decodes this into canonical i16 stereo.
#[derive(Clone, Copy)]
pub struct Format {
    /// Sample width in bits: 8 or 16.
    pub bits: u8,
    /// True if samples are signed (16-bit SB DMA); false if unsigned (8-bit).
    pub signed: bool,
    /// 1 = mono, 2 = interleaved stereo (L,R).
    pub channels: u8,
}

impl Format {
    /// Bytes per interleaved frame (all channels).
    pub const fn frame_bytes(self) -> usize {
        (self.bits as usize / 8) * self.channels as usize
    }

    /// Decode one channel's sample at byte offset `byte` into canonical i16.
    fn sample_at(self, bytes: &[u8], byte: usize) -> i16 {
        if self.bits == 16 {
            // 16-bit DMA is signed little-endian.
            let lo = bytes[byte] as u16;
            let hi = bytes[byte + 1] as u16;
            (lo | (hi << 8)) as i16
        } else if self.signed {
            (bytes[byte] as i8 as i16) << 8
        } else {
            // 8-bit unsigned (bias 0x80) → signed, scaled to 16-bit.
            ((bytes[byte] as i16) - 128) << 8
        }
    }

    /// Decode frame `i` into (left, right) canonical i16. Mono duplicates.
    pub(crate) fn frame(self, bytes: &[u8], i: usize) -> (i16, i16) {
        let sb = (self.bits as usize) / 8;
        let base = i * self.frame_bytes();
        if self.channels == 2 {
            (self.sample_at(bytes, base), self.sample_at(bytes, base + sb))
        } else {
            let m = self.sample_at(bytes, base);
            (m, m)
        }
    }
}

/// Last rate programmed into the device, so we only re-emit `AUDIO_SIG` on change.
static LAST_RATE: AtomicU32 = AtomicU32::new(0);

/// Does a backend-installed sink answer behind the canonical port window?
/// Pure probe — called once by `platform::probe`, never cached here.
pub fn window_present<A: crate::Arch>(machine: &mut A) -> bool {
    machine.inw(AUDIO_SIG) == SIGNATURE
}

/// Canonical audio-sink interrupt router. Called by the kernel-global IRQ
/// dispatcher before personality/console routing. The interrupt is a wakeup;
/// each driver validates its status and reads its authoritative DMA cursor.
pub fn on_irq<A: crate::Arch>(machine: &mut A, event: crate::Irq) -> bool {
    use crate::kernel::platform::Audio;
    match (crate::kernel::platform::get().audio, event) {
        (Audio::EmulatedHda, crate::Irq::Msi(source))
            if source == crate::kernel::drivers::hda::MSI_SOURCE =>
        {
            crate::kernel::drivers::hda::on_irq()
        }
        (Audio::EmulatedAc97, crate::Irq::Hw(line))
            if Some(line) == crate::kernel::drivers::ac97::irq_line() =>
        {
            let ours = crate::kernel::drivers::ac97::on_irq(machine);
            if ours {
                machine.rearm_irq(line);
            }
            ours
        }
        (Audio::EmulatedAc97, crate::Irq::Msi(source))
            if crate::kernel::drivers::ac97::msi_active()
                && source == crate::kernel::drivers::ac97::MSI_SOURCE =>
        {
            crate::kernel::drivers::ac97::on_irq(machine)
        }
        (Audio::SbSink, crate::Irq::Hw(line))
            if Some(line) == crate::kernel::drivers::sb16::irq_line() =>
        {
            let ours = crate::kernel::drivers::sb16::on_irq(machine);
            if ours {
                machine.rearm_irq(line);
            }
            ours
        }
        _ => false,
    }
}

/// Stream a block of source PCM `bytes` (`fmt`, `rate` Hz) to the canonical
/// audio output, canonicalizing to i16 stereo on the way. The sink is the
/// boot-time platform decision; Silent drops it.
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => {
            crate::kernel::drivers::hda::play(machine, rate, fmt, bytes);
            return;
        }
        Audio::EmulatedAc97 => {
            crate::kernel::drivers::ac97::play(machine, rate, fmt, bytes);
            return;
        }
        Audio::SbSink => {
            crate::kernel::drivers::sb16::play(machine, rate, fmt, bytes);
            return;
        }
        Audio::EmulatedPortWindow => {}
        Audio::NativeSb | Audio::EmulatedSilent => return,
    }
    if LAST_RATE.swap(rate, Ordering::Relaxed) != rate {
        machine.outw(AUDIO_SIG, rate as u16);
    }
    let fb = fmt.frame_bytes();
    if fb == 0 {
        return;
    }
    for i in 0..bytes.len() / fb {
        let (l, r) = fmt.frame(bytes, i);
        machine.outw(AUDIO_LEFT, l as u16);
        machine.outw(AUDIO_RIGHT, r as u16);
    }
}

/// Tell the selected canonical output that the producer went idle. `park`
/// marks a real session end (DSP reset / program cleanup): the output may
/// power down its hardware fully, not just pause the stream.
pub fn stop<A: crate::Arch>(machine: &mut A, park: bool) {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::drivers::hda::stop(machine, park),
        Audio::SbSink => crate::kernel::drivers::sb16::stop(machine, park),
        Audio::NativeSb | Audio::EmulatedAc97 | Audio::EmulatedPortWindow | Audio::EmulatedSilent => {}
    }
}

/// The selected output's pipe counters, in **source-rate frames**:
/// `(written, consumed)` — frames accepted via [`play`] and frames the
/// hardware has actually claimed for playback, both since the output's
/// current stream session started. `None` when the output has no real-time
/// consumer (WAV port window, silent): there is no playback clock to read,
/// and the producer must pace itself by virtual time instead.
///
/// This is the pull side of the SB pipe model: the emulated DSP slaves its
/// guest-visible cursor (DMA counts, block IRQs) to `consumed`, so guest
/// timing derives from real playback — the same definition a real card's
/// DMA cursor has — instead of a free-running virtual clock that the sink
/// then has to absorb with a deep latency cushion.
pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::drivers::hda::position(),
        Audio::EmulatedAc97 => crate::kernel::drivers::ac97::position(machine),
        Audio::SbSink => crate::kernel::drivers::sb16::position(machine),
        Audio::NativeSb | Audio::EmulatedPortWindow | Audio::EmulatedSilent => None,
    }
}

/// Desired output pipe depth (playback latency), shared by every hardware sink.
/// Below ~one framebuffer-blit period a present stall can underrun it.
const PIPE_MS: u32 = 30;

/// The universal [`PIPE_MS`] depth in frames, or `None` when the active sink
/// has no real-time consumer clock. Probed once per playback session.
pub fn min_fill(rate: u32) -> Option<u32> {
    use crate::kernel::platform::Audio;
    let present = match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::drivers::hda::present(),
        Audio::EmulatedAc97 => crate::kernel::drivers::ac97::present(),
        Audio::SbSink => crate::kernel::drivers::sb16::present(),
        Audio::NativeSb | Audio::EmulatedPortWindow | Audio::EmulatedSilent => false,
    };
    present.then(|| rate * PIPE_MS / 1000)
}

/// Producer-side pacing for a *generated* PCM stream — the synth pumps (FM,
/// GUS wavetable) that make frames on demand rather than consuming a guest
/// ring. Answers one question per tick: how many frames are due now?
///
/// Slaved to the sink's playback position when it reports one ([`position`]):
/// keep [`min_fill`] frames queued ahead of the drain point, so the pump and
/// the codec share a clock by construction — the synth-side counterpart of
/// the vsb pipe model, and the reason the sink needs no clock-follow servo.
/// Paced by virtual time at the session rate otherwise (WAV window / silent
/// sinks have no consumer clock to read).
///
/// A session is keyed by rate: [`due`](Self::due) re-anchors itself when the
/// rate changes (the sink restarts its stream and counters then), and
/// [`reset`](Self::reset) parks it when the pump goes idle or is superseded.
pub struct Pace {
    rate: u32,
    /// Pipe depth target in source frames; 0 = synthetic (no sink position).
    fill: u32,
    use_pos: bool,
    /// Source frames pushed this session.
    pushed: u64,
    /// Sink `written` counter at our session start (`u64::MAX` = not yet
    /// anchored; computed as `written − pushed` on the tick after the first
    /// push, so anything queued before us drains first — see vsb).
    anchor: u64,
    /// Session frames the sink has consumed, as of the last [`due`] call
    /// (synthetic: everything pushed — an instant consumer). Interpolated: the
    /// sink confirms whole buffers per completion IRQ, and this advances smoothly
    /// between them (see `drained_from`/`drained_ms`/`drain_step`) so both
    /// production and the guest cursor derived from it advance evenly.
    drained: u64,
    /// Last buffer-granular consumed value, the ms it stepped, and the step size
    /// (buffer, learned) — for interpolating `drained` between completions.
    drained_from: u64,
    drained_ms: u64,
    drain_step: u64,
    /// Guest-clock accumulator, frames × 1000. Production is paced on
    /// `get_ticks` (real-time to ~1e-3); this keeps whole-frame credit so a
    /// partial block remains here until the next complete block is due. Used on
    /// a real sink too — the drain only sets the anchor and the wide drift band.
    frac: u64,
}

impl Pace {
    pub const fn new() -> Self {
        Pace {
            rate: 0, fill: 0, use_pos: false,
            pushed: 0, anchor: u64::MAX, drained: 0, frac: 0,
            drained_from: 0, drained_ms: 0, drain_step: 0,
        }
    }

    /// Park the pacer: next [`due`] starts a fresh session (fresh anchor).
    /// Call when the pump stops its stream or another producer takes the sink.
    pub fn reset(&mut self) {
        self.rate = 0;
        self.pushed = 0;
        self.anchor = u64::MAX;
        self.drained = 0;
        self.frac = 0;
        self.drained_from = 0;
        self.drained_ms = 0;
        self.drain_step = 0;
    }

    /// Force a fresh session on the next [`due`] even at an unchanged rate —
    /// the session-identity signal (a new stream-frame numbering starts at 0).
    /// The sink stream itself is untouched; the anchor math absorbs whatever
    /// is still queued from the previous numbering.
    pub fn rekey(&mut self) {
        self.reset();
    }

    /// Session frames pushed so far — the absolute frame index the *next*
    /// [`due`]'d frame will have. Producers stamp sub-block events with this.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Session frames consumed by the sink as of the last [`due`] — the
    /// drain clock that guest-visible cursors and event delivery derive from.
    pub fn drained(&self) -> u64 {
        self.drained
    }

    /// Frames due at `rate` after `dt_ms` of virtual time. The caller must
    /// push exactly this many frames to the sink before the next call.
    pub fn due<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        rate: u32,
        dt_ms: u64,
        block_frames: usize,
    ) -> u64 {
        let block = block_frames.max(1) as u64;
        if rate != self.rate {
            // New session (first tick, or a rate change — the sink restarts
            // its stream and counters on that): re-key and re-anchor.
            let fill = min_fill(rate);
            self.rate = rate;
            self.use_pos = fill.is_some();
            self.fill = fill.unwrap_or(0);
            self.pushed = 0;
            self.anchor = u64::MAX;
            self.frac = 0;
            self.drained_from = 0;
            self.drain_step = 0;
        }
        if self.use_pos {
            let (written, consumed) = position(machine).unwrap_or((0, 0));
            // Sink counters restarted under our session (another owner parked
            // or reset the stream — e.g. a child program's exit cleanup). Our
            // frame numbering is void; re-key so the anchor below is rebuilt
            // from the fresh counters instead of wedging `drained` at zero.
            if written < self.pushed {
                self.pushed = 0;
                self.anchor = u64::MAX;
                self.frac = 0;
                self.drained_from = 0;
                self.drained_ms = 0;
                self.drain_step = 0;
            }
            if self.anchor == u64::MAX && self.pushed > 0 {
                self.anchor = written.saturating_sub(self.pushed);
            }
            let coarse = if self.anchor == u64::MAX {
                0
            } else {
                consumed.saturating_sub(self.anchor)
            };
            // The sink confirms `consumed` one whole buffer per completion IRQ — a
            // coarse staircase. Interpolate it with real time so `drained` advances
            // evenly, like a real DMA cursor: re-anchor on each step, cap the
            // fraction at the last step (the buffer, learned from the step itself)
            // so it stays monotonic and never crosses the next, unconfirmed
            // boundary. This one smooth drain feeds BOTH the deficit below and the
            // guest-visible SB cursor — so production and that cursor advance
            // evenly instead of in buffer-sized bursts (the SFX-crackle source).
            let now = machine.get_ticks();
            if coarse != self.drained_from {
                self.drain_step = coarse - self.drained_from;
                self.drained_from = coarse;
                self.drained_ms = now;
            }
            let frac =
                (now.saturating_sub(self.drained_ms) * rate as u64 / 1000).min(self.drain_step);
            self.drained = coarse + frac;
            // Refill the deficit to keep `fill` frames queued ahead of the drain.
            // Production paces on this smoothed drain — real-time between the
            // completion anchors — so it tracks consumption without the coarse
            // buffer-step bursts (and without a get_ticks drift servo: the anchors
            // pin it to the true drain). At startup the deficit is the whole
            // `fill`, which primes the pipe in one go.
            let deficit = (self.drained + self.fill as u64).saturating_sub(self.pushed);
            let due = deficit / block * block;
            self.pushed += due;
            due
        } else {
            self.frac += rate as u64 * dt_ms;
            let available = self.frac / 1000;
            let due = available / block * block;
            self.frac -= due * 1000;
            self.pushed += due;
            self.drained = self.pushed; // instant consumer: drained ≡ pushed
            due
        }
    }
}

impl Default for Pace {
    fn default() -> Self {
        Self::new()
    }
}
