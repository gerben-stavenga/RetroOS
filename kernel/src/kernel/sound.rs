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

/// **The** kernel audio sink: one output, whichever device serves it.
///
/// The kernel deals only with this type. It used to ask `platform::Audio`
/// which driver to call, in five separate matches — `play`, `stop`,
/// `position`, `min_fill` and `on_irq` each re-deriving the same answer from
/// a global. `Audio` is the boot-time POLICY (who owns the Sound Blaster);
/// which device is playing is a value, and this is it.
///
/// [`Device`] is deliberately not public: "which sound card" is the sink's
/// business, and nothing above it should be able to ask.
pub struct Sink {
    device: Device,
    /// The output ring — **the** implementation, shared by every device that
    /// has moved onto it. `None` for a device still driving its own (see
    /// `Device`) or one with nothing to play through.
    ring: Option<Ring>,
}

/// One ring of PCM, and the whole of the sink's bookkeeping.
///
/// This used to exist three times over — once in each of `hda`, `ac97` and
/// `sb16`, with the same counters, the same prime-then-start rule and the same
/// underrun test, and the same comment explaining that the interrupt is a
/// wakeup. None of that is device knowledge. What a device supplies is four
/// things: arm, halt, "is this interrupt mine", and how many blocks played.
///
/// The engine has NO clock and NO cursor. It learns of playback exactly one
/// way — [`on_block_played`](Self::on_block_played), called once per block, in
/// order, never lost, never duplicated. A device honours that contract by
/// reading its own cursor and emitting the difference, which is how a
/// coalesced interrupt (two blocks, one pending bit) still yields two calls.
/// Everything the engine needs follows: free space is `written − played·block`.
struct Ring {
    /// Kernel VA of the ring, and the physical address the device transfers
    /// from. The device maps it; the engine fills it.
    va: usize,
    phys: u32,
    /// Where the producer is writing.
    cur_buf: usize,
    cur_off: usize,
    /// Source frames accepted, and blocks the hardware has played.
    written: u64,
    played: u64,
    /// Rate the device is programmed for.
    rate: u32,
    /// `written` as of the previous played block, to tell an IDLE sink from a
    /// STARVED one. With the transfer always running, a sink with no producer
    /// plays silence forever and would otherwise report an underrun per block:
    /// true, useless, and drowning the real ones. An underrun is running dry
    /// while someone IS feeding us.
    fed_at_last_block: u64,
}

impl Ring {
    fn new(va: usize, phys: u32, rate: u32) -> Self {
        Ring { va, phys, cur_buf: 0, cur_off: 0, written: 0, played: 0, rate, fed_at_last_block: 0 }
    }

    /// One block reached the DAC. The only way playback is ever observed.
    ///
    /// Zeroes the block that just played. Auto-init DMA has no LVI gate — the
    /// device will come round and play these bytes again — so scrubbing behind
    /// the play cursor is what makes "the producer stopped feeding us" sound
    /// like silence instead of the last lap on repeat. It is also why the
    /// transfer can simply run for the sink's whole life: an unfed ring is a
    /// silent one, so there is no stopped state to arm out of.
    fn on_block_played(&mut self) {
        let played_buf = (self.played as usize) % NUM_BUF;
        unsafe {
            core::ptr::write_bytes((self.va + played_buf * BUF_BYTES) as *mut u8, 0, BUF_BYTES)
        };
        self.played += 1;
        let producing = self.written > self.fed_at_last_block;
        self.fed_at_last_block = self.written;
        // Underrun: the play cursor caught the write cursor while a producer
        // was feeding us. Audible as a gap now rather than as a repeat, but
        // still the thing to fix.
        if producing && self.written <= self.played * BUF_FRAMES as u64 {
            let n = crate::kernel::drivers::sb16::note_underrun();
            if n <= 3 || n.is_multiple_of(64) {
                crate::println!(
                    "sink: underrun #{} written={} played_frames={}",
                    n, self.written, self.played * BUF_FRAMES as u64
                );
            }
        }
    }

    /// Decode `bytes` into the ring as canonical i16 stereo.
    fn fill(&mut self, fmt: Format, bytes: &[u8]) {
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            let (l, r) = fmt.frame(bytes, i);
            let p = self.va + self.cur_buf * BUF_BYTES + self.cur_off;
            unsafe {
                core::ptr::write_volatile(p as *mut u16, l as u16);
                core::ptr::write_volatile((p + 2) as *mut u16, r as u16);
            }
            self.written += 1;
            self.cur_off += 4;
            if self.cur_off >= BUF_BYTES {
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
            }
        }
    }
}

// ── ring geometry, one definition for every device ──────────────────────────
/// Completion granularity: one interrupt per block. 512 signed-16 stereo
/// frames, ~11.6 ms at 44.1 kHz — a 30 ms pipe keeps about 2.6 blocks queued
/// while the block size halves interrupt pressure against a 256-frame one.
pub(crate) const BUF_BYTES: usize = 0x800;
const BUF_FRAMES: usize = BUF_BYTES / 4;
pub(crate) const NUM_BUF: usize = 32;
pub(crate) const RING_BYTES: usize = NUM_BUF * BUF_BYTES;
/// The one rate the mixer produces at, and therefore the rate a sink is armed
/// with. A source at another rate restarts the transfer.
const MIX_RATE: u32 = 44_100;

/// The devices that can serve the sink. A closed set — these are the cards
/// RetroOS drives, and adding one should break every match here on purpose.
enum Device {
    /// The physical Sound Blaster, HELD: this is one of the two places the
    /// machine's card can be (the other is a DOS thread driving it directly).
    Sb(crate::kernel::drivers::sb16::SbCard),
    Hda,
    Ac97,
    /// A backend installed a sink behind the canonical port window: the frames
    /// are written out through `outw` and consumed instantly, so this is the
    /// one device with no playback clock of its own.
    PortWindow,
    /// Nothing answers. Emulation still satisfies device detection; playback
    /// is dropped.
    Silent,
}

impl Sink {
    /// Build the sink the boot policy chose. Takes the Sound Blaster when the
    /// owner asked for the mixer (`SB_AUDIO=mixed`) — and then holds it, which
    /// is what makes the sink its owner.
    pub fn new<A: crate::Arch>(
        machine: &mut A,
        card: Option<crate::kernel::drivers::sb16::SbCard>,
    ) -> Self {
        use crate::kernel::platform::Audio;
        let device = match (crate::kernel::platform::get().audio, card) {
            (Audio::SbSink, Some(card)) => Device::Sb(card),
            (Audio::EmulatedHda, _) => Device::Hda,
            (Audio::EmulatedAc97, _) => Device::Ac97,
            (Audio::EmulatedPortWindow, _) => Device::PortWindow,
            // NativeSb: a DOS thread has the card, so the mixer has nothing to
            // play through. Same for a mixer mode with no card to take.
            _ => Device::Silent,
        };
        // A constructed sink is a RUNNING sink: the ring is armed here and the
        // device free-runs it for the sink's whole life. Nothing arms later,
        // so there is no "not yet started" state for a cursor read to fall
        // into, and no prime-vs-arm race to lose.
        let ring = match &device {
            Device::Sb(card) => crate::kernel::drivers::sb16::adopt(machine, card),
            Device::Ac97 => crate::kernel::drivers::ac97::adopt(machine),
            _ => None,
        };
        let mut sink = Sink { device, ring: ring.map(|(va, phys)| Ring::new(va, phys, MIX_RATE)) };
        if let Some((va, phys)) = ring {
            let _ = va;
            sink.dev_set_rate(machine, MIX_RATE);
            sink.dev_start(machine, phys);
        }
        sink
    }

    /// Hand the Sound Blaster back, if this sink is the one holding it. The
    /// sink survives with nothing to play through, which is the truth rather
    /// than a special state — `Err` is every other device, unchanged.
    pub fn try_into_sb(self) -> Result<(crate::kernel::drivers::sb16::SbCard, Self), Self> {
        match self.device {
            Device::Sb(card) => Ok((card, Sink { device: Device::Silent, ring: None })),
            device => Err(Sink { device, ring: self.ring }),
        }
    }

    /// Stream a block of source PCM (`fmt`, `rate` Hz), canonicalized to i16
    /// stereo on the way.
    pub fn play<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
        match self.device {
            Device::Hda => crate::kernel::drivers::hda::play(machine, rate, fmt, bytes),
            Device::Ac97 | Device::Sb(_) => self.submit(machine, rate, fmt, bytes),
            Device::PortWindow => port_window_play(machine, rate, fmt, bytes),
            Device::Silent => {}
        }
    }

    /// Engine path: fill the ring, and tell a gating device how far it may go.
    fn submit<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
        let Some(ring) = self.ring.as_mut() else { return };
        // A rate change restarts the transfer: the rate is latched when the
        // device is armed, and the counters are relative to it. Rare — the
        // mixer submits at one rate for a whole session.
        let restart = rate != 0 && rate != ring.rate;
        if restart {
            let (va, phys) = (ring.va, ring.phys);
            self.dev_set_rate(machine, rate);
            self.dev_start(machine, phys);
            self.ring = Some(Ring::new(va, phys, rate));
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.fill(fmt, bytes);
        }
    }

    // ── the primitives each device supplies ────────────────────────────────

    fn dev_set_rate<A: crate::Arch>(&mut self, machine: &mut A, rate: u32) {
        match self.device {
            Device::Sb(_) => crate::kernel::drivers::sb16::set_rate(machine, rate),
            Device::Ac97 => crate::kernel::drivers::ac97::set_rate(machine, rate),
            _ => {}
        }
    }

    fn dev_start<A: crate::Arch>(&mut self, machine: &mut A, phys: u32) {
        match self.device {
            Device::Sb(_) => crate::kernel::drivers::sb16::start(machine, phys),
            Device::Ac97 => crate::kernel::drivers::ac97::start(machine),
            _ => {}
        }
    }

    fn dev_halt<A: crate::Arch>(&mut self, machine: &mut A) {
        match self.device {
            Device::Sb(_) => crate::kernel::drivers::sb16::halt(machine),
            Device::Ac97 => crate::kernel::drivers::ac97::halt(machine),
            _ => {}
        }
    }

    /// Feed the engine the device's block reports.
    fn blocks_played(&mut self, blocks: u64) {
        if let Some(ring) = self.ring.as_mut() {
            for _ in 0..blocks {
                ring.on_block_played();
            }
        }
    }

    fn dev_poll<A: crate::Arch>(&mut self, machine: &mut A) -> u64 {
        match self.device {
            Device::Sb(_) => crate::kernel::drivers::sb16::poll(machine),
            Device::Ac97 => crate::kernel::drivers::ac97::poll(machine),
            _ => 0,
        }
    }

    /// The producer went idle. `park` marks a real session end (DSP reset /
    /// program cleanup): the device may power down, not just pause.
    pub fn stop<A: crate::Arch>(&mut self, machine: &mut A, park: bool) {
        match self.device {
            Device::Hda => crate::kernel::drivers::hda::stop(machine, park),
            Device::Sb(_) | Device::Ac97 => {
                // The transfer keeps running — an idle sink plays the silence
                // it is scrubbed to, which is what "stopped" sounds like and
                // costs one DMA channel doing nothing audible. Only `park` (a
                // real session end) stops the hardware.
                if self.ring.is_some() {
                    let va = self.ring.as_ref().map(|r| r.va).unwrap();
                    unsafe { core::ptr::write_bytes(va as *mut u8, 0, RING_BYTES) };
                    if park {
                        self.dev_halt(machine);
                    }
                }
            }
            Device::PortWindow | Device::Silent => {}
        }
    }

    /// Pipe counters in source-rate frames: `(written, consumed)`. `None` when
    /// the device has no playback clock, and the producer must pace itself by
    /// virtual time instead.
    pub fn position<A: crate::Arch>(&mut self, machine: &mut A) -> Option<(u64, u64)> {
        match self.device {
            Device::Hda => crate::kernel::drivers::hda::position(),
            Device::Ac97 | Device::Sb(_) => {
                // Interrupts can be late as well as coalesced, so take the
                // device's word for blocks played here too rather than only on
                // the interrupt: same contract, same accounting, asked at the
                // moment a producer wants to know.
                //
                // Only once armed. An unarmed channel's count register holds
                // whatever was last there, so polling it before `start` reads
                // a cursor for a transfer that does not exist and invents
                // played blocks against an empty ring — which then reports an
                // underrun per block, forever, with written=0.
                let fresh = self.dev_poll(machine);
                let ring = self.ring.as_mut()?;
                for _ in 0..fresh {
                    ring.on_block_played();
                }
                Some((ring.written, ring.played * BUF_FRAMES as u64))
            }
            Device::PortWindow | Device::Silent => None,
        }
    }

    /// The universal [`PIPE_MS`] depth in frames, or `None` when this device
    /// has no real-time consumer clock.
    pub fn min_fill(&self, rate: u32) -> Option<u32> {
        let present = match self.device {
            Device::Hda => crate::kernel::drivers::hda::present(),
            Device::Ac97 => self.ring.is_some(),
            Device::Sb(_) => self.ring.is_some(),
            Device::PortWindow | Device::Silent => false,
        };
        present.then(|| rate * PIPE_MS / 1000)
    }

    /// Completion interrupt. The device decides whether the event is its own —
    /// an MSI source or an ISA line it routed — and re-arms the line if it is.
    pub fn on_irq<A: crate::Arch>(&mut self, machine: &mut A, event: crate::Irq) -> bool {
        use crate::kernel::drivers::{ac97, hda, sb16};
        match (&self.device, event) {
            (Device::Hda, crate::Irq::Msi(source)) if source == hda::MSI_SOURCE => hda::on_irq(),
            (Device::Hda, crate::Irq::Hw(line)) if Some(line) == hda::irq_line() => {
                let ours = hda::on_irq();
                if ours {
                    machine.rearm_irq(line);
                }
                ours
            }
            (Device::Ac97, crate::Irq::Hw(line)) if Some(line) == ac97::irq_line() => {
                let (ours, blocks) = ac97::ack(machine);
                self.blocks_played(blocks);
                if ours {
                    machine.rearm_irq(line);
                }
                ours
            }
            (Device::Ac97, crate::Irq::Msi(source))
                if ac97::msi_active() && source == ac97::MSI_SOURCE =>
            {
                let (ours, blocks) = ac97::ack(machine);
                self.blocks_played(blocks);
                ours
            }
            (Device::Sb(_), crate::Irq::Hw(line)) if Some(line) == sb16::irq_line() => {
                let (ours, blocks) = sb16::ack(machine);
                self.blocks_played(blocks);
                if ours {
                    machine.rearm_irq(line);
                }
                ours
            }
            _ => false,
        }
    }

    /// Re-anchor after a long synchronous display handoff. Position-less
    /// devices have no producer to recover.
    pub fn recover_after_display_stall(&mut self) {
        if matches!(self.device, Device::Hda) {
            crate::kernel::drivers::hda::recover_after_stall();
        }
    }
}

/// The canonical audio port window: no ring, no completion interrupt, no
/// cursor — the frames are written out and consumed by construction. The one
/// device whose consumption is defined rather than observed.
fn port_window_play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
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
static SINK: spin::Mutex<Sink> = spin::Mutex::new(Sink { device: Device::Silent, ring: None });

/// Install the sink the boot policy chose. Called once, from `startup`.
pub fn install(sink: Sink) {
    *SINK.lock() = sink;
}

/// Take the Sound Blaster off the sink, if the sink is what holds it.
pub fn take_sb_card() -> Option<crate::kernel::drivers::sb16::SbCard> {
    let mut g = SINK.lock();
    let sink = core::mem::replace(&mut *g, Sink { device: Device::Silent, ring: None });
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

pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    SINK.lock().play(machine, rate, fmt, bytes);
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
