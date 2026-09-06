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
const SIGNATURE: u16 = 0x5241; // 'R','A' — RetroOS Audio

pub use sound::sink::Frame;
pub use sound::RATE_FP_SHIFT;

/// Times the play cursor caught the write cursor while a producer was feeding
/// us. One counter for the sink, not one per driver — it used to live in
/// `sb16` and be incremented for every device, which is the kind of thing the
/// library boundary makes impossible.
static UNDERRUNS: AtomicU32 = AtomicU32::new(0);
/// Times the dashpot pushed the mixing rate far from `s`; see [`advance`].
static RATE_SPIKES: AtomicU32 = AtomicU32::new(0);

/// One real-time window's worth of pump accounting, for when the mix rate
/// wanders and the sampled spike log cannot say why. Reported per ~3s of TSC;
/// read it against the sink itself rather than a TSC frequency, which is not
/// known here: `drained / 48000` IS the real elapsed time, so comparing it to
/// `dt_sum` (nanoseconds) says whether our clock is honest, and `produced` vs `drained` says
/// whether frames are going missing. Enabled with Trace (F12 → Debug).
#[derive(Default)]
struct Census {
    tsc0: u64,
    calls: u64,
    dt_sum: u64,
    drained: u64,
    produced: u64,
}
static PITCH_MIX_RATE_Q16_LO: AtomicU32 = AtomicU32::new(0);
static PITCH_MIX_RATE_Q16_HI: AtomicU32 = AtomicU32::new(0);

fn load64(lo: &AtomicU32, hi: &AtomicU32) -> u64 {
    (hi.load(Ordering::Relaxed) as u64) << 32 | lo.load(Ordering::Relaxed) as u64
}

fn store64(lo: &AtomicU32, hi: &AtomicU32, v: u64) {
    lo.store(v as u32, Ordering::Relaxed);
    hi.store((v >> 32) as u32, Ordering::Relaxed);
}

fn publish_mixing_rate_q16(pitch_rate_q16: u64) {
    store64(&PITCH_MIX_RATE_Q16_LO, &PITCH_MIX_RATE_Q16_HI, pitch_rate_q16);
}

/// The rate the audio is currently pitched to, in frames/sec × 2^16: the
/// pacer's steady `s`, the timebase sources render against — not the effective
/// frame-count rate, which swings with the latency servo and is audible in
/// nothing. Backs the OSD "Mix rate" readout.
pub fn mixing_rate_q16() -> u64 {
    load64(&PITCH_MIX_RATE_Q16_LO, &PITCH_MIX_RATE_Q16_HI)
}

/// Does a backend-installed sink answer behind the canonical port window?
/// Pure probe — called once by `platform::probe`, never cached here.
pub fn window_present<A: crate::Arch>(machine: &mut A) -> bool {
    machine.inw(AUDIO_SIG) == SIGNATURE
}

type Device = &'static mut (dyn sound::sink::Device + Send);

/// The machine's audio output: a `//lib:sound` sink over one of our cards.
/// Absence is represented by `Option<Sink>` at the ownership site; every
/// value of this type owns a real device and meaningful hardware cursors.
pub struct Sink {
    inner: sound::sink::Sink<Device>,
    producer: sound::Pacer,
    last_consumed: u64,
    ns_since_cursor: u64,
    rate_q16: Option<u64>,
    census: Census,
}

impl Sink {
    /// Build the sink the boot policy chose, taking the Sound Blaster when the
    /// owner asked for the mixer (`SB_AUDIO=mixed`) — and then holding it,
    /// which is what makes the sink its owner.
    pub fn new<A: crate::Arch>(
        machine: &mut A,
        probed: crate::kernel::platform::AudioToken,
        card: Option<crate::kernel::drivers::sb16::SbCard>,
    ) -> Option<Self> {
        use crate::kernel::platform::{Audio, AudioToken};
        // Probe mints one concrete device capability. The match exists only at
        // composition time; every runtime operation dispatches through it.
        let selected: Option<(&'static mut [Frame], Device)> = match (
            crate::kernel::platform::get().audio,
            probed,
            card,
        ) {
            (Audio::SbSink, _, Some(card)) => crate::kernel::drivers::sb16::adopt(machine, card)
                .map(|dev| (dev.ring(), dev as Device)),
            (Audio::EmulatedHda, AudioToken::Hda(dev), _) => {
                Some((dev.ring(), dev as Device))
            }
            (Audio::EmulatedAc97, AudioToken::Ac97(dev), _) => {
                Some((dev.ring(), dev as Device))
            }
            // The hosted WAV sink is not wired up: it has no ring, no cursor
            // and no completion event, so it cannot answer the `Device`
            // contract, and the kernel-side clock that used to stand in for
            // one was a second pacing path pretending to be a device. It comes
            // back as a real canonical audio card, with the host generating
            // the completions.
            (Audio::EmulatedPortWindow, _, _) => return None,
            // NativeSb: a DOS thread has the card, so the mixer has nothing to
            // play through. Same for a mixer mode with no card to take.
            _ => None,
        };
        let (buf, device) = selected?;
        let inner = sound::sink::Sink::new(buf, device);
        let rate = inner.rate();
        Some(Sink {
            inner,
            producer: sound::Pacer::new(rate),
            last_consumed: 0,
            ns_since_cursor: 0,
            rate_q16: None,
            census: Census::default(),
        })
    }

    /// Stream a block of wide mixed PCM, applying the final Q16 output gain.
    fn play(&mut self, frames: &[(i32, i32)], gain_q16: i32) {
        self.inner.submit(frames, gain_q16);
    }

    fn poll(&mut self) -> sound::sink::Report {
        self.inner.poll()
    }

    /// Re-anchor the physical pipe after the device overtook its producer.
    fn recover_from_underrun(&mut self) {
        self.inner.resync();
    }
}

/// Say out loud what the sink reported. The library has no console, and
/// whether an underrun is worth printing is a property of the machine.
fn say(report: sound::sink::Report) {
    if report.first_frame {
        // The difference between "armed" and "the DAC is actually consuming" —
        // where metal bring-up goes wrong, and invisible in a counter that
        // only reports problems.
        crate::compact_println!("sink: first frame played");
    }
    if let Some(u) = report.underrun {
        let n = UNDERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
            "WARNING: sound underrun #{} written_frames={} consumed_frames={}",
            n, u.written_frames, u.consumed_frames
        );
    }
}

/// Source-time rate used when there is no sink.
const DEFAULT_RATE: u32 = 44_100;

/// One span the source clock asks the active personality to advance and mix.
pub struct AudioSpan<'a> {
    /// Output frames per second a source expresses its phase against: the
    /// pacer's learned consumption rate `s`, i.e. the DAC's true steady rate.
    /// It deliberately is *not* the effective, latency-trimmed rate — that one
    /// swings with the queue and would bend every source's pitch as the loop
    /// hunts. The per-pump frame *count* still rides the trimmed rate (see
    /// [`advance`]); only the pitch timebase is pinned here so tuning holds.
    pub rate: u32,
    pub base_frame: u64,
    pub frames: &'a mut [(i32, i32)],
}

const MIX_CHUNK: usize = 128;

/// The emulated devices' frame clock. It exists with or without an output:
/// DOS hardware must continue consuming DMA and raising completion IRQs on a
/// silent machine. It deliberately knows nothing about rings or cursors.
pub struct Clock {
    produced_q16: u64,
}

impl Default for Clock {
    fn default() -> Self { Self::new() }
}

impl Clock {
    pub const fn new() -> Self {
        Self { produced_q16: 0 }
    }

    /// Absolute source-frame frontier: where an event arriving now is stamped.
    pub fn produced_frames(&self) -> u64 {
        self.produced_q16 >> RATE_FP_SHIFT
    }

    fn produce(&mut self, rate_q16: u64, dt_ns: u64) -> u64 {
        let before = self.produced_frames();
        self.produced_q16 +=
            (rate_q16 as u128 * dt_ns as u128 / 1_000_000_000) as u64;
        self.produced_frames() - before
    }

    fn frames_for(&self, rate_q16: u64, dt_ns: u64) -> u64 {
        let after = self.produced_q16 as u128
            + rate_q16 as u128 * dt_ns as u128 / 1_000_000_000;
        (after >> RATE_FP_SHIFT) as u64 - self.produced_frames()
    }
}

/// Advance emulated audio and, when present, feed the physical output. Without
/// a sink the same device clocks run at the canonical rate and their samples
/// are discarded; SB DMA, GF1 voices, MIDI envelopes, and completion events
/// therefore do not depend on output hardware existing.
#[inline(never)]
pub fn advance<A: crate::Arch>(
    machine: &mut A,
    clock: &mut Clock,
    mut sink: Option<&mut Sink>,
    dt_ns: u64,
    mut mix: impl FnMut(&mut A, AudioSpan<'_>),
) {
    let mut elapsed_ns = dt_ns;
    let mut written = 0;
    let mut consumed = 0;
    let mut fill = 0;
    let mut drained = 0;
    let rate_q16 = if let Some(output) = sink.as_deref_mut() {
        say(output.poll());
        let rate = output.inner.rate();
        let requested = (u64::from(rate)
            * u64::from(crate::kernel::osd::audio_latency_ms()))
            .div_ceil(1000);
        written = output.inner.written_frames();
        consumed = output.inner.consumed_frames();
        fill = requested.min(output.inner.max_ahead_frames()) as u32;
        if written < consumed {
            // The consumer crossed the producer frontier. Rebase immediately
            // and produce this pump at the reset cursor. Tell the pacer that
            // the new pipe is empty so it starts rebuilding the requested
            // depth; nominal-rate production from depth zero can otherwise
            // lose every race with a block-granular hardware cursor. This is
            // feedback, not priming: no silence is claimed and source time
            // advances only by this call's elapsed interval.
            output.recover_from_underrun();
            written = consumed;
            output.last_consumed = consumed;
            output.ns_since_cursor = 0;
            output.rate_q16 = Some(output.producer.update_rate(
                written, consumed, fill, elapsed_ns,
            ));
        }

        // Correct only when the block-granular play cursor moves. Between
        // completions its stale value is not a new latency measurement.
        output.ns_since_cursor += elapsed_ns;
        drained = consumed.saturating_sub(output.last_consumed);
        if drained > 0 {
            output.rate_q16 = Some(output.producer.update_rate(
                written, consumed, fill, output.ns_since_cursor,
            ));
            output.last_consumed = consumed;
            output.ns_since_cursor = 0;
        }
        output.rate_q16.unwrap_or_else(|| output.producer.s_q16())
    } else {
        u64::from(DEFAULT_RATE) << RATE_FP_SHIFT
    };

    if let Some(output) = sink.as_deref_mut() {
        let queued = output.inner.written_frames()
            .saturating_sub(output.inner.consumed_frames());
        let available = output.inner.safety_ceiling_frames().saturating_sub(queued);
        if clock.frames_for(rate_q16, elapsed_ns) > available {
            // A delayed kernel tick, or a device cursor which stopped moving,
            // cannot be caught up through a finite DMA ring. Re-anchor at the
            // consumer and discard this elapsed batch before asking sources to
            // render it; the next ordinary tick starts at the reset cursor.
            output.recover_from_underrun();
            output.last_consumed = output.inner.consumed_frames();
            output.ns_since_cursor = 0;
            output.rate_q16 = None;
            elapsed_ns = 0;
        }
    }

    let gain_q16 = sink.as_ref().map(|_| crate::kernel::osd::master_gain_q16());
    // Two different rates come out of the controller, and conflating them is
    // what detunes the mix. `rate_q16` is the effective rate `s - 2w q`: it
    // carries the dashpot's queue-noise on purpose, and its job is to set how
    // many frames this pump produces so the pipe holds its latency target.
    // Source *phase*, though, must be expressed against the DAC's true
    // consumption rate — the fixed hardware clock every produced frame is
    // ultimately played out at. A source resamples its voices by
    // `voice_rate / mix_rate` and the DAC replays the result at `c'`, so the
    // audible pitch is `voice_rate * c' / mix_rate`; feeding it the swinging
    // `rate_q16` bends every pitch by `c'/rate_q16` as the loop hunts. The
    // pacer's `s` is exactly the learned, dashpot-free estimate of `c'`, so it
    // is the timebase pitch must ride — the frame count still varies to fix
    // latency, but the DMA cursor that count drives only fluctuates within a
    // fraction of a percent and averages back onto the guest's programmed rate.
    let pitch_rate_q16 = sink
        .as_ref()
        .map(|o| o.producer.s_q16())
        .unwrap_or(u64::from(DEFAULT_RATE) << RATE_FP_SHIFT);
    let mix_rate = (pitch_rate_q16 >> RATE_FP_SHIFT) as u32;
    let mut frames = [(0i32, 0i32); MIX_CHUNK];
    let mut base = clock.produced_frames();
    let mut remaining = clock.produce(rate_q16, elapsed_ns);
    let produced = remaining;
    while remaining > 0 {
        let run = usize::try_from(remaining.min(MIX_CHUNK as u64)).unwrap();
        frames[..run].fill((0, 0));
        mix(machine, AudioSpan {
            rate: mix_rate,
            base_frame: base,
            frames: &mut frames[..run],
        });
        if let (Some(output), Some(gain_q16)) = (sink.as_deref_mut(), gain_q16) {
            output.play(&frames[..run], gain_q16);
        }
        base += run as u64;
        remaining -= run as u64;
    }
    // Publish the pitch timebase, not the effective frame-count rate. The OSD
    // "Mix rate" reads this, and after the pitch/count split it is `s` that the
    // audio actually plays at; `rate_q16` swings with the latency servo and no
    // longer describes anything audible. The instantaneous rate and its
    // deviation from `s` stay visible through the trace/census diagnostics.
    publish_mixing_rate_q16(pitch_rate_q16);

    let Some(output) = sink else { return };

    // Census over a fixed TSC window. `tsc_hz` is not known here, so the
    // window is expressed in TSC units and the report prints raw counts —
    // what matters is the RATIO of dt_sum to the window and of produced to
    // drained, both of which are unit-free.
    if crate::kernel::startup::trace_enabled() {
        let c = &mut output.census;
        let now = machine.rdtsc();
        if c.tsc0 == 0 {
            c.tsc0 = now;
        }
        c.calls += 1;
        c.dt_sum += elapsed_ns;
        c.drained += drained;
        c.produced += produced;
        // ~3e9 TSC ticks: a few seconds on any plausible clock.
        if now.wrapping_sub(c.tsc0) > 3_000_000_000 {
            let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
                "census: tsc={} calls={} dt_ns={} drained={} produced={} rate={} s={}",
                now - c.tsc0, c.calls, c.dt_sum, c.drained, c.produced,
                rate_q16 >> RATE_FP_SHIFT, output.producer.s_q16() >> RATE_FP_SHIFT,
            );
            *c = Census { tsc0: now, ..Census::default() };
        }
    }

    // Diagnostic: the mixing rate should now track `s` closely, because the
    // control step only runs when the cursor actually moved. A large gap means
    // `q` still carries something the gate did not filter out — log what
    // produced it, rate-limited so a sustained case cannot flood a 1 kHz pump.
    let s_hz = output.producer.s_q16() >> RATE_FP_SHIFT;
    let rate_hz = rate_q16 >> RATE_FP_SHIFT;
    if rate_hz.abs_diff(s_hz) > 500 && crate::kernel::startup::trace_enabled() {
        let n = RATE_SPIKES.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(256) {
            let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
                "audio: rate={} s={} depth={} target={} drained={} dt_ns={} cursor_ns={} (spike #{})",
                rate_hz,
                s_hz,
                written as i64 - consumed as i64,
                fill,
                drained,
                elapsed_ns,
                output.ns_since_cursor,
                n,
            );
        }
    }
}
