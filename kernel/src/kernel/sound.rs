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

/// Times the play cursor caught the write cursor while a producer was feeding
/// us. One counter for the sink, not one per driver — it used to live in
/// `sb16` and be incremented for every device, which is the kind of thing the
/// library boundary makes impossible.
static UNDERRUNS: AtomicU32 = AtomicU32::new(0);

/// Does a backend-installed sink answer behind the canonical port window?
/// Pure probe — called once by `platform::probe`, never cached here.
pub fn window_present<A: crate::Arch>(machine: &mut A) -> bool {
    machine.inw(AUDIO_SIG) == SIGNATURE
}

/// Which card is playing, and — for the Sound Blaster — the card itself.
///
/// This is the kernel's `sound::sink::Device`: ONE implementation of the
/// contract, dispatching to the three drivers. It replaced four separate
/// matches (`set_rate`, `start`, `halt`, `poll`) that each re-derived the same
/// answer, and before that five matches on `platform::Audio` — a global asked
/// once per question. The set is closed and ours, so it is an enum and adding
/// a card breaks every arm on purpose.
///
/// `Sb` holds the capability, which is what makes the sink one of the two
/// places the machine's Sound Blaster can be (the other is a DOS thread
/// driving it directly).
enum Card {
    Sb(crate::kernel::drivers::sb16::SbCard),
    Hda,
    Ac97,
}

impl sound::sink::Device for Card {
    /// Each card's rate, stated here and nowhere else. A rate is a property of
    /// the card, so it travels outward only: this is what the mixer renders to,
    /// and no code path hands a rate back down to a driver. HDA and AC'97 are
    /// fixed at their link's 48 kHz; the SB16 DSP plays whatever it is told and
    /// its driver programs itself for the rate named here.
    fn rate(&self) -> u32 {
        match self {
            Card::Hda | Card::Ac97 => 48_000,
            Card::Sb(_) => 44_100,
        }
    }

    fn block_frames(&self) -> usize {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::block_frames(),
            Card::Ac97 => crate::kernel::drivers::ac97::block_frames(),
            Card::Hda => crate::kernel::drivers::hda::block_frames(),
        }
    }

    fn start(&mut self) {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::start(),
            Card::Ac97 => crate::kernel::drivers::ac97::start(),
            Card::Hda => crate::kernel::drivers::hda::start(),
        }
    }

    fn halt(&mut self) {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::halt(),
            Card::Ac97 => crate::kernel::drivers::ac97::halt(),
            Card::Hda => crate::kernel::drivers::hda::halt(),
        }
    }

    fn blocks_played(&mut self) -> u64 {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::blocks_played(),
            Card::Ac97 => crate::kernel::drivers::ac97::blocks_played(),
            Card::Hda => crate::kernel::drivers::hda::blocks_played(),
        }
    }
}

impl Card {
    fn ring_frames(&self) -> usize {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::ring_frames(),
            Card::Ac97 => crate::kernel::drivers::ac97::ring_frames(),
            Card::Hda => crate::kernel::drivers::hda::ring_frames(),
        }
    }
}

/// The machine's audio output: a `//lib:sound` sink over one of our cards, or
/// nothing to play through.
///
/// `None` is not a mode, it is the absence of hardware: no card was found, or
/// a DOS thread holds the machine's Sound Blaster. Everything above reads the
/// same two counters either way and simply produces nothing when there is no
/// sink to produce for.
pub struct Sink {
    card: Option<sound::sink::Sink<Card>>,
}

impl Sink {
    /// No hardware to play through.
    pub const fn empty() -> Self {
        Sink { card: None }
    }

    /// Build the sink the boot policy chose, taking the Sound Blaster when the
    /// owner asked for the mixer (`SB_AUDIO=mixed`) — and then holding it,
    /// which is what makes the sink its owner.
    pub fn new<A: crate::Arch>(
        machine: &mut A,
        card: Option<crate::kernel::drivers::sb16::SbCard>,
    ) -> Self {
        use crate::kernel::platform::Audio;
        // Bring-up is the machine's: find the controller, map the transfer
        // ring, route the interrupt. Only once that has happened is there a
        // `Device` for the library to drive.
        let (mapped, card) = match (crate::kernel::platform::get().audio, card) {
            (Audio::SbSink, Some(card)) => (
                crate::kernel::drivers::sb16::adopt(machine, &card),
                Some(Card::Sb(card)),
            ),
            (Audio::EmulatedHda, _) => (crate::kernel::drivers::hda::adopt(), Some(Card::Hda)),
            (Audio::EmulatedAc97, _) => {
                (crate::kernel::drivers::ac97::adopt(machine), Some(Card::Ac97))
            }
            // The hosted WAV sink is not wired up: it has no ring, no cursor
            // and no completion event, so it cannot answer the `Device`
            // contract, and the kernel-side clock that used to stand in for
            // one was a second pacing path pretending to be a device. It comes
            // back as a real canonical audio card, with the host generating
            // the completions.
            (Audio::EmulatedPortWindow, _) => return Sink::empty(),
            // NativeSb: a DOS thread has the card, so the mixer has nothing to
            // play through. Same for a mixer mode with no card to take.
            _ => (None, None),
        };
        let (Some((va, _phys)), Some(card)) = (mapped, card) else {
            return Sink::empty();
        };
        // The device mapped the ring; hand the library a slice of it. This is
        // the one unsafe step in the sink — everything above it is a ring
        // buffer and arithmetic, which is why it lives in `//lib:sound`.
        let ring_frames = card.ring_frames();
        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut Frame, ring_frames) };
        Sink { card: Some(sound::sink::Sink::new(buf, card)) }
    }

    /// Hand the Sound Blaster back, if this sink is the one holding it. The
    /// sink survives with nothing to play through, which is the truth rather
    /// than a special state.
    pub fn try_into_sb(self) -> Result<(crate::kernel::drivers::sb16::SbCard, Self), Self> {
        match self.card {
            Some(sink) => match sink.into_device() {
                Card::Sb(card) => Ok((card, Sink::empty())),
                other => Err(Sink { card: Some(rebuild(other)) }),
            },
            None => Err(self),
        }
    }

    /// The rate this sink plays at — what a producer should MIX at.
    ///
    /// The sample rate is the device's to choose, not a constant the kernel
    /// imposes: an SB16 or an AC'97 with variable-rate audio plays whatever it
    /// is told, while an HDA codec may only offer 48 kHz. Asking the sink
    /// means the conversion happens once, in the mixer, where every source is
    /// already being rate-converted anyway.
    pub fn rate(&self) -> u32 {
        match &self.card {
            Some(sink) => sink.rate(),
            None => DEFAULT_RATE,
        }
    }

    /// Stream a block of wide mixed PCM, applying the final Q16 output gain.
    pub fn play(&mut self, frames: &[(i32, i32)], gain_q16: i32) {
        if let Some(sink) = &mut self.card {
            sink.submit(frames, gain_q16);
        }
    }

    /// `(written, consumed)` in frames. Both are absolute and share the sink's
    /// origin, so their difference IS the queue depth — there is no
    /// producer-side anchor between them, and `written` is the absolute index
    /// the next produced frame will have.
    pub fn counters(&self) -> (u64, u64) {
        match &self.card {
            Some(sink) => (sink.written_frames(), sink.consumed_frames()),
            None => (0, 0),
        }
    }

    /// Queue depth requested by policy, rounded up to the device's own block
    /// granularity and capped inside the ring's unambiguous producer half.
    pub fn target_fill(&self, rate: u32, latency_ms: u32) -> u32 {
        match &self.card {
            Some(sink) => {
                let block = sink.block_frames() as u64;
                let requested = (u64::from(rate) * u64::from(latency_ms)).div_ceil(1000);
                let aligned = requested.div_ceil(block) * block;
                aligned.min(sink.max_ahead_frames()) as u32
            }
            None => 0,
        }
    }

    pub fn present(&self) -> bool {
        self.card.is_some()
    }

    /// A sparse physical-device wakeup. Consumption is polled separately; an
    /// interrupt is only acknowledged here and never counted as a block.
    pub fn on_irq<A: crate::Arch>(&mut self, machine: &mut A, event: crate::Irq) -> bool {
        use crate::kernel::drivers::{ac97, hda, sb16};
        let Some(sink) = &mut self.card else { return false };
        let (mine, isa_line) = match (sink.device(), event) {
            (Card::Hda, crate::Irq::Msi(src)) => (src == hda::MSI_SOURCE, None),
            (Card::Hda, crate::Irq::Hw(line)) => (Some(line) == hda::irq_line(), Some(line)),
            (Card::Ac97, crate::Irq::Msi(src)) => {
                (ac97::msi_active() && src == ac97::MSI_SOURCE, None)
            }
            (Card::Ac97, crate::Irq::Hw(line)) => (Some(line) == ac97::irq_line(), Some(line)),
            (Card::Sb(_), crate::Irq::Hw(line)) => (Some(line) == sb16::irq_line(), Some(line)),
            _ => (false, None),
        };
        if !mine {
            return false;
        }
        let pending = match sink.device() {
            Card::Sb(_) => sb16::irq_pending(),
            Card::Ac97 => ac97::irq_pending(),
            Card::Hda => hda::irq_pending(),
        };
        if !pending {
            return false;
        }
        if let Some(line) = isa_line {
            machine.rearm_irq(line);
        }
        true
    }

    pub fn poll(&mut self) -> sound::sink::Report {
        self.card.as_mut().map_or_else(sound::sink::Report::default, |sink| sink.poll())
    }

    /// Re-anchor the physical pipe after the device overtook its producer.
    pub fn recover_from_underrun(&mut self) {
        if let Some(sink) = &mut self.card {
            sink.resync();
        }
    }
}

/// Put a sink back together around a device we did not want after all.
/// `into_device` halted it, so this re-arms from a fresh ring.
fn rebuild(card: Card) -> sound::sink::Sink<Card> {
    let va = match &card {
        Card::Sb(_) => crate::kernel::drivers::sb16::ring_va(),
        Card::Ac97 => crate::kernel::drivers::ac97::ring_va(),
        Card::Hda => crate::kernel::drivers::hda::ring_va(),
    };
    let ring_frames = card.ring_frames();
    let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut Frame, ring_frames) };
    sound::sink::Sink::new(buf, card)
}

/// Say out loud what the sink reported. The library has no console, and
/// whether an underrun is worth printing is a property of the machine.
fn say(report: sound::sink::Report) {
    if report.first_block {
        // The difference between "armed" and "the DAC is actually consuming" —
        // where metal bring-up goes wrong, and invisible in a counter that
        // only reports problems.
        crate::println!("sink: first block played");
    }
    if let Some(u) = report.underrun {
        let n = UNDERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 3 || n.is_multiple_of(64) {
            crate::println!(
                "WARNING: sound underrun #{} written_frames={} consumed_frames={}",
                n, u.written_frames, u.consumed_frames
            );
        }
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

/// Take the Sound Blaster off the sink, if the sink is what holds it.
pub fn take_sb_card() -> Option<crate::kernel::drivers::sb16::SbCard> {
    let mut g = SINK.lock();
    let sink = core::mem::replace(&mut *g, Sink::empty());
    match sink.try_into_sb() {
        Ok((card, rest)) => {
            *g = rest;
            Some(card)
        }
        Err(sink) => {
            *g = sink;
            None
        }
    }
}

// ── the kernel-facing surface: one line each, straight to the sink ──────────

pub fn play(frames: &[(i32, i32)], gain_q16: i32) {
    SINK.lock().play(frames, gain_q16);
}

pub fn on_irq<A: crate::Arch>(machine: &mut A, event: crate::Irq) -> bool {
    SINK.lock().on_irq(machine, event)
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
const TRIM_PPM_PER_FRAME: i64 = 8;
const MAX_TRIM_PPM: i64 = 25_000;

/// The CPU-clocked output producer. HDA/AC'97/SB consumption does not advance
/// this clock; it only supplies slow feedback that trims the number of output
/// samples made per CPU second and therefore holds pipe latency steady.
pub struct Producer {
    nominal_rate: u32,
    mix_rate: u32,
    /// Fractional output frames, in frames × 1000 (the event-loop tick is ms).
    frac: u64,
    /// Absolute CPU-produced frame index. Physical pipe priming is downstream
    /// silence and deliberately does not advance this source-time coordinate.
    pushed: u64,
    last_consumed: u64,
    sink_present: bool,
    primed: bool,
}

impl Producer {
    pub const fn new() -> Self {
        Self {
            nominal_rate: 0,
            mix_rate: 0,
            frac: 0,
            pushed: 0,
            last_consumed: 0,
            sink_present: false,
            primed: false,
        }
    }

    /// Output-frame frontier at which an event arriving now should be stamped.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    fn set_nominal_rate(&mut self, rate: u32) {
        if self.nominal_rate == rate {
            return;
        }
        self.nominal_rate = rate;
        self.mix_rate = rate;
        self.frac = 0;
        self.primed = false;
    }

    fn update_rate(&mut self, written: u64, consumed: u64, target: u32) {
        if consumed == self.last_consumed {
            return;
        }
        self.last_consumed = consumed;
        // Sample queue error only when the device reports a completion. At
        // that instant `consumed` is current; between completions its block
        // staircase would otherwise look like a false latency ramp.
        let queued = written.saturating_sub(consumed) as i64;
        let error = i64::from(target) - queued;
        let trim_ppm = (error * TRIM_PPM_PER_FRAME)
            .clamp(-MAX_TRIM_PPM, MAX_TRIM_PPM);
        self.mix_rate = ((u64::from(self.nominal_rate)
            * (1_000_000i64 + trim_ppm) as u64)
            / 1_000_000) as u32;
    }
}

impl Default for Producer {
    fn default() -> Self {
        Self::new()
    }
}

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
    if producer.sink_present != present {
        producer.sink_present = present;
        producer.primed = false;
    }
    if present {
        if written <= consumed {
            // The consumer crossed the producer frontier, so the old latency
            // error and this pump's elapsed batch are both obsolete. Restart
            // the physical pipe at its target rather than trying to pace back
            // from an underrun.
            let mut sink = SINK.lock();
            sink.recover_from_underrun();
            written = sink.counters().0;
            producer.frac = 0;
            producer.mix_rate = nominal_rate;
            producer.last_consumed = consumed;
            producer.primed = false;
        }
        if producer.primed {
            producer.update_rate(written, consumed, fill);
        } else {
            producer.last_consumed = consumed;
            producer.mix_rate = nominal_rate;
        }
    } else {
        producer.mix_rate = nominal_rate;
    }

    let gain_q16 = crate::kernel::osd::master_gain_q16();
    let mut frames = [(0i32, 0i32); MIX_CHUNK];

    // Prime physical latency with silence, not source time. The emulated SB
    // and synths begin advancing only in the CPU-clocked production loop below.
    if present && !producer.primed {
        let mut prime = (consumed + u64::from(fill)).saturating_sub(written);
        while prime > 0 {
            let run = usize::try_from(prime.min(MIX_CHUNK as u64)).unwrap();
            frames[..run].fill((0, 0));
            play(&frames[..run], gain_q16);
            prime -= run as u64;
        }
        producer.primed = true;
        // Recovery establishes a new physical-time origin. Audio belonging
        // to the missed interval cannot be replayed without recreating the
        // overrun, so production resumes with the next CPU-time batch.
        return;
    }

    producer.frac += u64::from(producer.mix_rate) * dt_ms;
    let mut due = producer.frac / 1000;
    producer.frac -= due * 1000;
    let mut base = producer.pushed;
    let pushed = base + due;
    while due > 0 {
        let run = usize::try_from(due.min(MIX_CHUNK as u64)).unwrap();
        frames[..run].fill((0, 0));
        mix(machine, AudioSpan {
            rate: producer.mix_rate,
            base_frame: base,
            frames: &mut frames[..run],
        });
        play(&frames[..run], gain_q16);
        base += run as u64;
        due -= run as u64;
    }
    producer.pushed = pushed;
}
