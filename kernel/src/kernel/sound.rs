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
pub use sound::{Pacer as Producer, RATE_FP_SHIFT};

/// Times the play cursor caught the write cursor while a producer was feeding
/// us. One counter for the sink, not one per driver — it used to live in
/// `sb16` and be incremented for every device, which is the kind of thing the
/// library boundary makes impossible.
static UNDERRUNS: AtomicU32 = AtomicU32::new(0);
static EFFECTIVE_MIX_RATE_Q16_LO: AtomicU32 = AtomicU32::new(0);
static EFFECTIVE_MIX_RATE_Q16_HI: AtomicU32 = AtomicU32::new(0);

fn load64(lo: &AtomicU32, hi: &AtomicU32) -> u64 {
    (hi.load(Ordering::Relaxed) as u64) << 32 | lo.load(Ordering::Relaxed) as u64
}

fn store64(lo: &AtomicU32, hi: &AtomicU32, v: u64) {
    lo.store(v as u32, Ordering::Relaxed);
    hi.store((v >> 32) as u32, Ordering::Relaxed);
}

fn publish_effective_mix_rate_q16(rate_q16: u64) {
    store64(&EFFECTIVE_MIX_RATE_Q16_LO, &EFFECTIVE_MIX_RATE_Q16_HI, rate_q16);
}

/// Current effective mix rate, in frames/sec × 2^16.
pub fn effective_mix_rate_q16() -> u64 {
    load64(&EFFECTIVE_MIX_RATE_Q16_LO, &EFFECTIVE_MIX_RATE_Q16_HI)
}

/// Does a backend-installed sink answer behind the canonical port window?
/// Pure probe — called once by `platform::probe`, never cached here.
pub fn window_present<A: crate::Arch>(machine: &mut A) -> bool {
    machine.inw(AUDIO_SIG) == SIGNATURE
}

type Device = &'static mut (dyn sound::sink::Device + Send);

/// The machine's audio output: a `//lib:sound` sink over one of our cards, or
/// nothing to play through.
///
/// `None` is not a mode, it is the absence of hardware: no card was found, or
/// a DOS thread holds the machine's Sound Blaster. Everything above reads the
/// same two counters either way and simply produces nothing when there is no
/// sink to produce for.
pub struct Sink {
    inner: Option<sound::sink::Sink<Device>>,
}

impl Sink {
    /// No hardware to play through.
    pub const fn empty() -> Self {
        Sink { inner: None }
    }

    /// Build the sink the boot policy chose, taking the Sound Blaster when the
    /// owner asked for the mixer (`SB_AUDIO=mixed`) — and then holding it,
    /// which is what makes the sink its owner.
    pub fn new<A: crate::Arch>(
        machine: &mut A,
        probed: crate::kernel::platform::AudioToken,
        card: Option<crate::kernel::drivers::sb16::SbCard>,
    ) -> Self {
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
            (Audio::EmulatedPortWindow, _, _) => return Sink::empty(),
            // NativeSb: a DOS thread has the card, so the mixer has nothing to
            // play through. Same for a mixer mode with no card to take.
            _ => None,
        };
        let Some((buf, device)) = selected else {
            return Sink::empty();
        };
        Sink { inner: Some(sound::sink::Sink::new(buf, device)) }
    }

    /// The rate this sink plays at — what a producer should MIX at.
    ///
    /// The sample rate is the device's to choose, not a constant the kernel
    /// imposes. Asking the sink means conversion happens once, in the mixer,
    /// where every source is already being rate-converted anyway.
    pub fn rate(&self) -> u32 {
        match &self.inner {
            Some(sink) => sink.rate(),
            None => DEFAULT_RATE,
        }
    }

    /// Stream a block of wide mixed PCM, applying the final Q16 output gain.
    pub fn play(&mut self, frames: &[(i32, i32)], gain_q16: i32) {
        if let Some(sink) = &mut self.inner {
            sink.submit(frames, gain_q16);
        }
    }

    /// `(written, consumed)` in frames. Both are absolute and share the sink's
    /// origin, so their difference IS the queue depth — there is no
    /// producer-side anchor between them, and `written` is the absolute index
    /// the next produced frame will have.
    pub fn counters(&self) -> (u64, u64) {
        match &self.inner {
            Some(sink) => (sink.written_frames(), sink.consumed_frames()),
            None => (0, 0),
        }
    }

    /// Queue depth requested by policy, capped inside the ring's latency
    /// headroom.
    pub fn target_fill(&self, rate: u32, latency_ms: u32) -> u32 {
        match &self.inner {
            Some(sink) => {
                let requested = (u64::from(rate) * u64::from(latency_ms)).div_ceil(1000);
                requested.min(sink.max_ahead_frames()) as u32
            }
            None => 0,
        }
    }

    pub fn present(&self) -> bool {
        self.inner.is_some()
    }

    pub fn poll(&mut self) -> sound::sink::Report {
        self.inner.as_mut().map_or_else(sound::sink::Report::default, |sink| sink.poll())
    }

    /// Re-anchor the physical pipe after the device overtook its producer.
    pub fn recover_from_underrun(&mut self) {
        if let Some(sink) = &mut self.inner {
            sink.resync();
        }
    }
}

/// Say out loud what the sink reported. The library has no console, and
/// whether an underrun is worth printing is a property of the machine.
fn say(report: sound::sink::Report) {
    if report.first_frame {
        // The difference between "armed" and "the DAC is actually consuming" —
        // where metal bring-up goes wrong, and invisible in a counter that
        // only reports problems.
        crate::println!("sink: first frame played");
    }
    if let Some(u) = report.underrun {
        let n = UNDERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
        crate::println!(
            "WARNING: sound underrun #{} written_frames={} consumed_frames={}",
            n, u.written_frames, u.consumed_frames
        );
    }
}

/// The rate a sink runs at when the device has no opinion.
const DEFAULT_RATE: u32 = 44_100;

/// The machine's one audio output.
///
/// It has to be reachable from the IRQ dispatcher (not on the event loop's
/// stack) and from the mixer pump deep inside a DOS thread, so it lives here
/// rather than being threaded — but it is a VALUE with methods, not a global
/// anyone matches on, and when it holds the Sound Blaster it holds it the same
/// way a thread does: by owning it.
static SINK: spin::Mutex<Sink> = spin::Mutex::new(Sink::empty());

/// Install the sink the boot policy chose. Called once, from `startup`.
pub fn install(sink: Sink) {
    *SINK.lock() = sink;
}

// ── the kernel-facing surface: one line each, straight to the sink ──────────

pub fn play(frames: &[(i32, i32)], gain_q16: i32) {
    SINK.lock().play(frames, gain_q16);
}

/// One span the global output pump asks the active personality to mix.
pub struct AudioSpan<'a> {
    /// Effective output frames per CPU second. This is gently trimmed around
    /// the device's nominal rate to hold the physical pipe at its target
    /// depth; sources use it for incremental phase, so their frequencies stay
    /// expressed in the CPU clock while the sample density changes.
    pub rate: u32,
    pub base_frame: u64,
    pub frames: &'a mut [(i32, i32)],
}

const MIX_CHUNK: usize = 128;

/// Advance the CPU-clocked producer, ask the active personality for those
/// frames, and append them to the physical sink. The sink clock only trims the
/// effective mix rate; it never decides when an emulated device advances.
pub fn pump<A: crate::Arch>(
    machine: &mut A,
    producer: &mut Producer,
    dt_ms: u64,
    mut mix: impl FnMut(&mut A, AudioSpan<'_>),
) {
    let report = SINK.lock().poll();
    say(report);
    let (nominal_rate, mut written, consumed, fill, present) = {
        let sink = SINK.lock();
        let rate = sink.rate();
        let (written, consumed) = sink.counters();
        let fill = sink.target_fill(rate, crate::kernel::osd::audio_latency_ms());
        (rate, written, consumed, fill, sink.present())
    };

    producer.set_nominal_rate(nominal_rate);
    publish_effective_mix_rate_q16(producer.effective_rate_q16());
    producer.set_sink_present(present);
    if present {
        if written <= consumed {
            // The consumer crossed the producer frontier, so the old latency
            // error and this pump's elapsed batch are both obsolete. Restart
            // the physical pipe at its target rather than trying to pace back
            // from an underrun.
            let mut sink = SINK.lock();
            sink.recover_from_underrun();
            written = sink.counters().0;
            producer.recover_from_underrun();
        }
        if producer.primed() {
            producer.update_rate(written, consumed, fill, dt_ms);
            publish_effective_mix_rate_q16(producer.effective_rate_q16());
        }
    }

    let gain_q16 = crate::kernel::osd::master_gain_q16();
    let mut frames = [(0i32, 0i32); MIX_CHUNK];

    // Prime physical latency with silence, not source time. The emulated SB
    // and synths begin advancing only in the CPU-clocked production loop below.
    if present && !producer.primed() {
        let mut prime = (consumed + u64::from(fill)).saturating_sub(written);
        while prime > 0 {
            let run = usize::try_from(prime.min(MIX_CHUNK as u64)).unwrap();
            frames[..run].fill((0, 0));
            play(&frames[..run], gain_q16);
            prime -= run as u64;
        }
        producer.prime();
        // Recovery establishes a new physical-time origin. Audio belonging
        // to the missed interval cannot be replayed without recreating the
        // overrun, so production resumes with the next CPU-time batch.
        return;
    }

    let due = producer.due_frames(dt_ms);
    let mut remaining = due;
    let mut base = producer.pushed();
    let mix_rate = (producer.effective_rate_q16() >> RATE_FP_SHIFT) as u32;
    while remaining > 0 {
        let run = usize::try_from(remaining.min(MIX_CHUNK as u64)).unwrap();
        frames[..run].fill((0, 0));
        mix(machine, AudioSpan {
            rate: mix_rate,
            base_frame: base,
            frames: &mut frames[..run],
        });
        play(&frames[..run], gain_q16);
        base += run as u64;
        remaining -= run as u64;
    }
    producer.advance_pushed(due);
}
