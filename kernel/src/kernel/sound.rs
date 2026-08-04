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

/// The producer's wire format and the ring geometry are the library's — see
/// `sound::sink`. Re-exported so the drivers and the mixer keep naming them
/// through `kernel::sound`.
pub use sound::sink::{BUF_BYTES, NUM_BUF, RING_BYTES};

/// Last rate programmed into the device, so we only re-emit `AUDIO_SIG` on change.
static LAST_RATE: AtomicU32 = AtomicU32::new(0);

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
    fn set_rate(&mut self, rate: u32) {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::set_rate(rate),
            Card::Ac97 => crate::kernel::drivers::ac97::set_rate(rate),
            Card::Hda => crate::kernel::drivers::hda::set_rate(rate),
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

    fn irq_pending(&mut self) -> bool {
        match self {
            Card::Sb(_) => crate::kernel::drivers::sb16::irq_pending(),
            Card::Ac97 => crate::kernel::drivers::ac97::irq_pending(),
            Card::Hda => crate::kernel::drivers::hda::irq_pending(),
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

/// The machine's audio output: a `//lib:sound` sink over one of our cards, or
/// nothing to play through.
///
/// `PortWindow` is not a card and never will be one — the hosted backend's WAV
/// sink has no ring, no completion interrupt and no cursor, because its
/// consumption is defined rather than observed. It stays a variant here rather
/// than pretending to implement a contract three of its clauses cannot mean.
enum Out {
    Card(sound::sink::Sink<Card>),
    PortWindow,
    Silent,
}

pub struct Sink {
    out: Out,
}

impl Sink {
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
            (Audio::EmulatedPortWindow, _) => return Sink { out: Out::PortWindow },
            // NativeSb: a DOS thread has the card, so the mixer has nothing to
            // play through. Same for a mixer mode with no card to take.
            _ => (None, None),
        };
        let (Some((va, _phys)), Some(card)) = (mapped, card) else {
            return Sink { out: Out::Silent };
        };
        let rate = match &card {
            // The codec's own rate: an HDA converter may not offer 44.1 kHz,
            // and adapting is the mixer's job, not a resampler's.
            Card::Hda => crate::kernel::drivers::hda::stream_rate(),
            _ => DEFAULT_RATE,
        };
        // The device mapped the ring; hand the library a slice of it. This is
        // the one unsafe step in the sink — everything above it is a ring
        // buffer and arithmetic, which is why it lives in `//lib:sound`.
        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, RING_BYTES) };
        Sink { out: Out::Card(sound::sink::Sink::new(buf, rate, card)) }
    }

    /// Hand the Sound Blaster back, if this sink is the one holding it. The
    /// sink survives with nothing to play through, which is the truth rather
    /// than a special state.
    pub fn try_into_sb(self) -> Result<(crate::kernel::drivers::sb16::SbCard, Self), Self> {
        match self.out {
            Out::Card(sink) => match sink.into_device() {
                Card::Sb(card) => Ok((card, Sink { out: Out::Silent })),
                other => Err(Sink { out: Out::Card(rebuild(other)) }),
            },
            out => Err(Sink { out }),
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
        match &self.out {
            Out::Card(sink) => sink.rate(),
            _ => DEFAULT_RATE,
        }
    }

    /// Stream a block of source PCM, canonicalized to i16 stereo on the way.
    pub fn play<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, frames: &[(i16, i16)]) {
        match &mut self.out {
            Out::Card(sink) => {
                sink.submit(rate, frames);
            }
            Out::PortWindow => port_window_play(machine, rate, frames),
            Out::Silent => {}
        }
    }

    /// The producer went idle. `park` marks a real session end.
    pub fn stop<A: crate::Arch>(&mut self, _machine: &mut A, park: bool) {
        if let Out::Card(sink) = &mut self.out {
            sink.stop(park);
        }
    }

    /// Pipe counters in source-rate frames: `(written, consumed)`. `None` when
    /// the device has no playback clock and the producer must pace itself by
    /// virtual time instead.
    pub fn position<A: crate::Arch>(&mut self, _machine: &mut A) -> Option<(u64, u64)> {
        let Out::Card(sink) = &mut self.out else { return None };
        // Interrupts can be late as well as coalesced, so take the device's
        // word for blocks played here too rather than only on the interrupt.
        let report = sink.service();
        say(report);
        Some(sink.position())
    }

    /// The universal [`PIPE_MS`] depth in frames, or `None` when this sink has
    /// no real-time consumer clock.
    pub fn min_fill(&self, rate: u32) -> Option<u32> {
        matches!(self.out, Out::Card(_)).then(|| rate * PIPE_MS / 1000)
    }

    /// Completion interrupt. Whether the LINE was ours is the machine's
    /// question — a shared INTx says nothing about which device raised it — so
    /// identity is matched here and the card only answers for its own status.
    pub fn on_irq<A: crate::Arch>(&mut self, machine: &mut A, event: crate::Irq) -> bool {
        use crate::kernel::drivers::{ac97, hda, sb16};
        let Out::Card(sink) = &mut self.out else { return false };
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
        if !mine || !sink.irq_pending() {
            return false;
        }
        let report = sink.service();
        say(report);
        if let Some(line) = isa_line {
            machine.rearm_irq(line);
        }
        true
    }

    /// Re-anchor after a long synchronous display handoff.
    pub fn recover_after_display_stall(&mut self) {
        if let Out::Card(sink) = &mut self.out {
            sink.resync();
        }
    }
}

/// Put a sink back together around a device we did not want after all.
/// `into_device` halted it, so this re-arms from a fresh ring.
fn rebuild(card: Card) -> sound::sink::Sink<Card> {
    let (va, rate) = match &card {
        Card::Sb(_) => (crate::kernel::drivers::sb16::ring_va(), DEFAULT_RATE),
        Card::Ac97 => (crate::kernel::drivers::ac97::ring_va(), DEFAULT_RATE),
        Card::Hda => (
            crate::kernel::drivers::hda::ring_va(),
            crate::kernel::drivers::hda::stream_rate(),
        ),
    };
    let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, RING_BYTES) };
    sound::sink::Sink::new(buf, rate, card)
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
                "sink: underrun #{} written={} played_frames={}",
                n, u.written, u.played_frames
            );
        }
    }
}

/// The canonical audio port window: no ring, no completion interrupt, no
/// cursor — the frames are written out and consumed by construction. The one
/// device whose consumption is defined rather than observed.
fn port_window_play<A: crate::Arch>(machine: &mut A, rate: u32, frames: &[(i16, i16)]) {
    if LAST_RATE.swap(rate, Ordering::Relaxed) != rate {
        machine.outw(AUDIO_SIG, rate as u16);
    }
    for &(l, r) in frames {
        machine.outw(AUDIO_LEFT, l as u16);
        machine.outw(AUDIO_RIGHT, r as u16);
    }
}

/// The rate a sink runs at when the device has no opinion.
const DEFAULT_RATE: u32 = 44_100;

/// Desired output pipe depth (playback latency), shared by every hardware sink.
/// Below ~one framebuffer-blit period a present stall can underrun it.
const PIPE_MS: u32 = 30;

/// The machine's one audio output.
///
/// It has to be reachable from the IRQ dispatcher (not on the event loop's
/// stack) and from the mixer pump deep inside a DOS thread, so it lives here
/// rather than being threaded — but it is a VALUE with methods, not a global
/// anyone matches on, and when it holds the Sound Blaster it holds it the same
/// way a thread does: by owning it.
static SINK: spin::Mutex<Sink> = spin::Mutex::new(Sink { out: Out::Silent });

/// Install the sink the boot policy chose. Called once, from `startup`.
pub fn install(sink: Sink) {
    *SINK.lock() = sink;
}

/// Take the Sound Blaster off the sink, if the sink is what holds it.
pub fn take_sb_card() -> Option<crate::kernel::drivers::sb16::SbCard> {
    let mut g = SINK.lock();
    let sink = core::mem::replace(&mut *g, Sink { out: Out::Silent });
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

pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, frames: &[(i16, i16)]) {
    SINK.lock().play(machine, rate, frames);
}

pub fn stop<A: crate::Arch>(machine: &mut A, park: bool) {
    SINK.lock().stop(machine, park);
}

pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    SINK.lock().position(machine)
}

pub fn min_fill(rate: u32) -> Option<u32> {
    SINK.lock().min_fill(rate)
}

/// The rate the active sink plays at — what a producer should mix at.
pub fn rate() -> u32 {
    SINK.lock().rate()
}

pub fn on_irq<A: crate::Arch>(machine: &mut A, event: crate::Irq) -> bool {
    SINK.lock().on_irq(machine, event)
}

pub fn recover_after_display_stall() {
    SINK.lock().recover_after_display_stall();
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
