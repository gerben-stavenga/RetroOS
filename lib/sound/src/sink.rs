//! The output side: one ring of PCM, and the whole of a sink's bookkeeping.
//!
//! Same contract as the cards in this crate — nothing here reaches out. The
//! host supplies the memory and the frames — canonical i16 stereo, because a
//! sink is the end of the path and wire formats were decoded upstream — and
//! drives exactly two events:
//! [`Ring::fill`] when a producer has frames, and [`Ring::on_block_played`]
//! once per block the hardware consumed. Arming a device, reading its cursor
//! and acknowledging its interrupt are the host's, because those are the only
//! parts that touch a machine.
//!
//! This used to exist three times over in the kernel — once inside each of the
//! HDA, AC'97 and SB16 drivers, with the same counters, the same prime rule,
//! the same underrun test and the same comment explaining that an interrupt is
//! a wakeup. None of it was device knowledge, and none of it is kernel
//! knowledge either: it is a ring buffer and some arithmetic.
//!
//! A [`Device`] is the whole of what a sound card must supply: four calls,
//! none of which mention a machine. Where the bytes go, how the ring is
//! programmed and which interrupt line carries the completion are the host's;
//! how many blocks have played and what to do about it are this crate's.
//!
//! There is deliberately **no clock and no cursor** in here. Playback is
//! learned one way only: `on_block_played`, called once per block, in order,
//! never lost, never duplicated. A host honours that by reading its device's
//! cursor and emitting the *difference*, which is how a coalesced interrupt
//! (two completions, one pending bit) still yields two calls. Everything else
//! follows: free space is `written − played·block`.

/// Completion granularity: one interrupt per block. 512 signed-16 stereo
/// frames, ~11.6 ms at 44.1 kHz — a 30 ms pipe keeps about 2.6 blocks queued,
/// while the block size halves interrupt pressure against a 256-frame one.
pub const BUF_BYTES: usize = 0x800;
pub const BUF_FRAMES: usize = BUF_BYTES / 4;
pub const NUM_BUF: usize = 32;
pub const RING_BYTES: usize = NUM_BUF * BUF_BYTES;

/// The play cursor caught the write cursor while a producer was feeding us.
/// Reported rather than logged: this crate has no console, and what a host
/// does about it (count it, print it, ignore it) is the host's business.
#[derive(Clone, Copy, Debug)]
pub struct Underrun {
    pub written: u64,
    pub played_frames: u64,
}

/// One ring of PCM: the memory, the two cursors, and the counters.
pub struct Ring {
    buf: &'static mut [u8],
    /// Where the producer is writing.
    cur_buf: usize,
    cur_off: usize,
    /// Source frames accepted, and blocks the hardware has played.
    written: u64,
    played: u64,
    /// The rate the device is programmed for — carried so a host can tell a
    /// rate change from a session that is merely idle.
    rate: u32,
    /// `written` as of the previous played block, to tell an IDLE sink from a
    /// STARVED one. The transfer runs for the sink's whole life, so a sink
    /// with no producer plays silence forever and would otherwise report an
    /// underrun per block: true, useless, and drowning the real ones.
    fed_at_last_block: u64,
}

impl Ring {
    /// `buf` is the device's transfer ring, already mapped by the host and at
    /// least [`RING_BYTES`] long.
    pub fn new(buf: &'static mut [u8], rate: u32) -> Self {
        Ring {
            buf,
            cur_buf: 0,
            cur_off: 0,
            written: 0,
            played: 0,
            rate,
            fed_at_last_block: 0,
        }
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// `(written, played)` in source frames — the pipe counters a producer
    /// paces against.
    pub fn position(&self) -> (u64, u64) {
        (self.written, self.played * BUF_FRAMES as u64)
    }

    /// One block reached the DAC. The only way playback is ever observed.
    ///
    /// Zeroes the block that just played. A free-running transfer has no gate
    /// — the device will come round and play these bytes again — so scrubbing
    /// behind the play cursor is what makes "the producer stopped feeding us"
    /// sound like silence instead of the last lap on repeat. It is also why
    /// the transfer can simply run for the sink's whole life: an unfed ring is
    /// a silent one, so there is no stopped state to arm out of.
    pub fn on_block_played(&mut self) -> Option<Underrun> {
        let played_buf = (self.played as usize) % NUM_BUF;
        self.buf[played_buf * BUF_BYTES..(played_buf + 1) * BUF_BYTES].fill(0);
        self.played += 1;
        let producing = self.written > self.fed_at_last_block;
        self.fed_at_last_block = self.written;
        let played_frames = self.played * BUF_FRAMES as u64;
        (producing && self.written <= played_frames).then_some(Underrun {
            written: self.written,
            played_frames,
        })
    }

    /// Has anything played yet? A host's bring-up diagnostic: the difference
    /// between "armed" and "the DAC is actually consuming".
    pub fn silent_so_far(&self) -> bool {
        self.played == 0
    }

    /// Copy canonical frames into the ring.
    ///
    /// Signed 16-bit interleaved stereo, and nothing else. A sink is the END
    /// of the audio path: whatever wire format a card's DMA carried — 8-bit
    /// unsigned, mono, ADPCM — was decoded by that card on its way into the
    /// mix, which is the only place that knows what it meant. Taking a format
    /// here would mean the mixer encoding its own samples for us to decode
    /// again.
    pub fn fill(&mut self, frames: &[(i16, i16)]) {
        for &(l, r) in frames {
            let at = self.cur_buf * BUF_BYTES + self.cur_off;
            self.buf[at..at + 2].copy_from_slice(&(l as u16).to_le_bytes());
            self.buf[at + 2..at + 4].copy_from_slice(&(r as u16).to_le_bytes());
            self.written += 1;
            self.cur_off += 4;
            if self.cur_off >= BUF_BYTES {
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
            }
        }
    }

    /// Silence the whole ring — the producer went idle and the transfer keeps
    /// running, so what it plays should be nothing.
    pub fn silence(&mut self) {
        self.buf.fill(0);
    }

    /// Re-key for a new session at `rate`: the device restarted, so the
    /// counters it is relative to restart with it.
    pub fn restart(&mut self, rate: u32) {
        self.cur_buf = 0;
        self.cur_off = 0;
        self.written = 0;
        self.played = 0;
        self.fed_at_last_block = 0;
        self.rate = rate;
        self.silence();
    }

    /// Drop the write cursor onto the play cursor.
    ///
    /// After a stall longer than the pipe, the write cursor sits behind the
    /// play cursor: the ring is silent (every played block is scrubbed) but
    /// fresh audio would land in blocks that will not be played for a whole
    /// lap. Trading that lap of latency costs nothing, because the ring is
    /// silence either way.
    pub fn resync(&mut self) {
        self.cur_buf = (self.played as usize + 1) % NUM_BUF;
        self.cur_off = 0;
        self.written = (self.played + 1) * BUF_FRAMES as u64;
    }
}

/// What a sound card must supply to be a sink.
///
/// Four calls, and not one of them takes a machine handle: a device reaches
/// its own hardware however its host arranged that (injected port I/O, MMIO,
/// a hypervisor call), which is exactly the same discipline the cards in this
/// crate follow from the other direction. Bring-up — finding the controller,
/// mapping the transfer ring, routing the interrupt — happens before a
/// `Device` exists and is none of this crate's business.
pub trait Device {
    /// Program the output rate. The mixer produces at whatever the device
    /// asked for, so this is normally set once.
    fn set_rate(&mut self, rate: u32);

    /// Arm the transfer over the whole ring, and re-baseline the block count.
    /// A sink is armed once, at construction, and free-runs for its life —
    /// there is no stopped state, because an unfed ring plays the silence it
    /// is scrubbed to.
    fn start(&mut self);

    /// Stop the transfer. A real session end; an idle producer does not need
    /// this, it just stops feeding.
    fn halt(&mut self);

    /// Is a completion interrupt of MINE pending? Clears it. Deciding whether
    /// the LINE was ours is the host's — a shared INTx says nothing about
    /// which device raised it — so this answers only for the status register.
    fn irq_pending(&mut self) -> bool;

    /// Blocks played since the last call: exactly once per block, in order,
    /// never lost, never duplicated.
    ///
    /// A device honours that by reading its own cursor and returning the
    /// DIFFERENCE — which is how a coalesced interrupt (two completions, one
    /// pending bit) still accounts for two blocks. Returning an interrupt
    /// COUNT here would be lossy, and the sink has no way to tell.
    fn blocks_played(&mut self) -> u64;
}

/// A sound output: one ring, one device.
pub struct Sink<D: Device> {
    ring: Ring,
    dev: D,
}

impl<D: Device> Sink<D> {
    /// Arm `dev` over `buf` at `rate` and start playing. Constructing a sink
    /// starts it: silence is the ring's content, not a state of the device.
    pub fn new(buf: &'static mut [u8], rate: u32, mut dev: D) -> Self {
        dev.set_rate(rate);
        dev.start();
        Sink { ring: Ring::new(buf, rate), dev }
    }

    pub fn rate(&self) -> u32 {
        self.ring.rate()
    }

    pub fn device(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Take the device back, for a host that must hand its hardware on.
    pub fn into_device(mut self) -> D {
        self.dev.halt();
        self.dev
    }

    /// Accept produced PCM. A rate change re-arms the device, because the rate
    /// is latched when it starts and the counters are relative to it.
    pub fn submit(&mut self, rate: u32, frames: &[(i16, i16)]) -> Report {
        if rate != 0 && rate != self.ring.rate() {
            self.dev.set_rate(rate);
            self.dev.start();
            self.ring.restart(rate);
        }
        self.ring.fill(frames);
        Report::default()
    }

    /// Service the device: collect the blocks it has played and account for
    /// them. Safe to call without an interrupt — a late or coalesced one is
    /// exactly what the cursor difference is for.
    pub fn service(&mut self) -> Report {
        let blocks = self.dev.blocks_played();
        let mut report = Report::default();
        for _ in 0..blocks {
            report.first_block |= self.ring.silent_so_far();
            if let Some(u) = self.ring.on_block_played() {
                report.underrun = Some(u);
            }
        }
        report
    }

    /// Did this device raise the completion? Clears its status if so.
    pub fn irq_pending(&mut self) -> bool {
        self.dev.irq_pending()
    }

    /// `(written, played)` in source frames.
    pub fn position(&self) -> (u64, u64) {
        self.ring.position()
    }

    /// The producer went idle. The transfer keeps running and plays the
    /// silence the ring is scrubbed to; `park` is a real session end and stops
    /// the hardware.
    pub fn stop(&mut self, park: bool) {
        self.ring.silence();
        if park {
            self.dev.halt();
        }
    }

    /// Re-anchor after a stall longer than the pipe: drop the write cursor
    /// onto the play cursor, trading a lap of latency for nothing.
    pub fn resync(&mut self) {
        self.ring.resync();
    }
}

/// What a call to the sink turned up, for a host that wants to say so. This
/// crate has no console, and whether an underrun is worth printing is a
/// property of the machine, not of the ring.
#[derive(Clone, Copy, Default)]
pub struct Report {
    /// The very first block reached the DAC — the difference between "armed"
    /// and "actually consuming", which is where bring-up on real hardware
    /// goes wrong and which no error counter ever shows.
    pub first_block: bool,
    pub underrun: Option<Underrun>,
}
