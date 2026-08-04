//! The output side: one ring of PCM, and the whole of a sink's bookkeeping.
//!
//! Same contract as the cards in this crate — nothing here reaches out. The
//! host supplies the memory and the wide mixed frames; the sink applies the
//! final Q16 gain and clips once to device-ready i16 stereo. The host drives
//! two events: [`Sink::submit`] when a producer has frames and [`Sink::on_irq`]
//! when the device signals completion. Arming a device, reading its cursor and
//! acknowledging its interrupt happen through [`Device`].
//!
//! This used to exist three times over in the kernel — once inside each of the
//! HDA, AC'97 and SB16 drivers, with the same counters, the same prime rule,
//! the same underrun test and the same comment explaining that an interrupt is
//! a wakeup. None of it was device knowledge, and none of it is kernel
//! knowledge either: it is a ring buffer and some arithmetic.
//!
//! A [`Device`] is the whole of what a sound card must supply: one rate and
//! four operations, none of which mention a machine. Where the bytes go, how
//! the ring is programmed and which interrupt line carries the completion are
//! the host's; how many blocks completed and what to do about them are this
//! crate's.
//!
//! There is deliberately **no clock and no cursor** in here. Playback is
//! learned one way only: [`Sink::on_irq`], which asks the device how many
//! blocks completed since the previous interrupt. The device obtains that
//! number from its cursor difference, so a coalesced interrupt still accounts
//! for every block. The producer remains frame-granular; only device
//! completion is block-granular.

/// Completion granularity: one interrupt per block. 512 signed-16 stereo
/// frames, ~11.6 ms at 44.1 kHz — a 30 ms pipe keeps about 2.6 blocks queued,
/// while the block size halves interrupt pressure against a 256-frame one.
pub const BUF_BYTES: usize = 0x800;
/// One device PCM frame: `[left, right]`. RetroOS targets little-endian x86,
/// so this is also the DMA wire representation used by every hardware sink.
pub type Frame = [i16; 2];
pub const BUF_FRAMES: usize = BUF_BYTES / core::mem::size_of::<Frame>();
pub const NUM_BUF: usize = 32;
pub const RING_FRAMES: usize = NUM_BUF * BUF_FRAMES;
pub const RING_BYTES: usize = RING_FRAMES * core::mem::size_of::<Frame>();
/// Keep producer and consumer on the unambiguous half of the cyclic ring.
/// Normal pacing sits at only ~2.6 blocks; this is a hard fault ceiling, not
/// a latency target.
const MAX_AHEAD_FRAMES: u64 = (NUM_BUF as u64 / 2 - 1) * BUF_FRAMES as u64;

/// The play cursor caught the write cursor while a producer was feeding us.
/// Reported rather than logged: this crate has no console, and what a host
/// does about it (count it, print it, ignore it) is the host's business.
#[derive(Clone, Copy, Debug)]
pub struct Underrun {
    pub written_frames: u64,
    pub consumed_frames: u64,
}

/// What a sound card must supply to be a sink.
///
/// One property and four operations, and none takes a machine handle: a
/// device reaches its own hardware however its host arranged that (injected
/// port I/O, MMIO, a hypervisor call), which is exactly the same discipline the
/// cards in this crate follow from the other direction. Bring-up — finding the
/// controller, mapping the transfer ring, routing the interrupt — happens
/// before a `Device` exists and is none of this crate's business.
pub trait Device {
    /// The device's PCM rate. The producer renders at this rate; the ring
    /// itself only stores and counts frames and has no clock.
    fn rate(&self) -> u32;

    /// Program the device at [`Device::rate`], arm the transfer over the whole
    /// ring, and re-baseline the block count.
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
    dev: D,
    buf: &'static mut [Frame],
    write_pos: usize,
    written_frames: u64,
    completed_blocks: u64,
    /// Used to distinguish an idle sink from one that ran dry while its
    /// producer was active.
    written_frames_at_last_completion: u64,
}

impl<D: Device> Sink<D> {
    /// Arm `dev` over `buf` and start playing at the device's rate.
    /// Constructing a sink starts it: silence is the ring's content, not a
    /// state of the device.
    pub fn new(buf: &'static mut [Frame], mut dev: D) -> Self {
        buf.fill([0, 0]);
        dev.start();
        Sink {
            dev,
            buf,
            write_pos: 0,
            written_frames: 0,
            completed_blocks: 0,
            written_frames_at_last_completion: 0,
        }
    }

    pub fn rate(&self) -> u32 {
        self.dev.rate()
    }

    pub fn device(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Take the device back, for a host that must hand its hardware on.
    pub fn into_device(mut self) -> D {
        self.dev.halt();
        self.dev
    }

    /// Apply the final Q16 gain, clip once, and write device PCM into the ring.
    pub fn submit(&mut self, frames: &[(i32, i32)], gain_q16: i32) {
        let queued = self.written_frames.saturating_sub(self.consumed_frames());
        assert!(queued <= MAX_AHEAD_FRAMES, "audio producer passed ring ceiling");
        assert!(
            frames.len() as u64 <= MAX_AHEAD_FRAMES - queued,
            "audio producer overtook consumer"
        );
        for &(left, right) in frames {
            self.buf[self.write_pos] = [scale(left, gain_q16), scale(right, gain_q16)];
            self.write_pos = (self.write_pos + 1) % RING_FRAMES;
            self.written_frames += 1;
        }
    }

    /// Account for a completion interrupt. The device cursor may report more
    /// than one block when interrupts coalesce; each is delivered exactly once.
    pub fn on_irq(&mut self) -> Report {
        let blocks = self.dev.blocks_played();
        if blocks == 0 {
            return Report::default();
        }

        let first_block = self.completed_blocks == 0;
        for block in self.completed_blocks..self.completed_blocks + blocks {
            let slot = block as usize % NUM_BUF;
            self.buf[slot * BUF_FRAMES..(slot + 1) * BUF_FRAMES].fill([0, 0]);
        }
        self.completed_blocks += blocks;

        let producing = self.written_frames > self.written_frames_at_last_completion;
        self.written_frames_at_last_completion = self.written_frames;
        let consumed_frames = self.consumed_frames();
        let written_frames = self.written_frames;
        let underrun = (producing && written_frames <= consumed_frames).then_some(Underrun {
            written_frames,
            consumed_frames,
        });
        Report { first_block, underrun }
    }

    /// Did this device raise the completion? Clears its status if so.
    pub fn irq_pending(&mut self) -> bool {
        self.dev.irq_pending()
    }

    /// Frames consumed by the device, at block granularity.
    pub fn consumed_frames(&self) -> u64 {
        self.completed_blocks * BUF_FRAMES as u64
    }

    /// Frames accepted from the producer. This cursor is changed only by
    /// submission or an explicit producer-side stall recovery; a consumer
    /// completion never advances it.
    pub fn written_frames(&self) -> u64 {
        self.written_frames
    }

    /// Abandon an underrun's obsolete write position and resume at the first
    /// whole block the device has not begun playing.
    pub fn resync(&mut self) {
        self.write_pos = ((self.completed_blocks as usize + 1) % NUM_BUF) * BUF_FRAMES;
        self.written_frames = (self.completed_blocks + 1) * BUF_FRAMES as u64;
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

/// Apply a Q16 gain and narrow one wide mixer sample to the device format.
pub fn scale(sample: i32, gain_q16: i32) -> i16 {
    ((i64::from(sample) * i64::from(gain_q16)) >> 16)
        .clamp(i16::MIN as i64, i16::MAX as i64) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDevice {
        rate: u32,
        starts: u32,
        played: u64,
    }

    impl Device for TestDevice {
        fn rate(&self) -> u32 {
            self.rate
        }

        fn start(&mut self) {
            self.starts += 1;
        }

        fn halt(&mut self) {}

        fn irq_pending(&mut self) -> bool {
            false
        }

        fn blocks_played(&mut self) -> u64 {
            core::mem::take(&mut self.played)
        }
    }

    fn ring() -> &'static mut [Frame] {
        Box::leak(vec![[0; 2]; RING_FRAMES].into_boxed_slice())
    }

    #[test]
    fn device_owns_the_rate() {
        let mut sink = Sink::new(
            ring(),
            TestDevice { rate: 48_000, starts: 0, played: 0 },
        );
        assert_eq!(sink.rate(), 48_000);
        assert_eq!(sink.device().starts, 1);

        sink.submit(&[(1, -1); 32], 1 << 16);
        assert_eq!(sink.written_frames, 32);
        assert_eq!(sink.consumed_frames(), 0);
        assert_eq!(
            sink.device().starts,
            1,
            "submitting frames must not reprogram the device"
        );
    }

    #[test]
    fn block_completions_expose_consumed_frames() {
        let mut sink = Sink::new(
            ring(),
            TestDevice { rate: 8_000, starts: 0, played: 1 },
        );
        sink.submit(&[(1, 1)], 1 << 16);
        let report = sink.on_irq();
        assert!(report.first_block);
        assert_eq!(sink.consumed_frames(), BUF_FRAMES as u64);

        // A producer that fed us one frame against a whole block of drain ran
        // dry. The consumer reports it but does not move the producer cursor.
        let u = report.underrun.expect("fed, and still behind the DAC");
        assert_eq!(u.written_frames, 1);
        assert_eq!(sink.written_frames(), 1);
    }

    #[test]
    fn an_idle_sink_does_not_move_the_producer_cursor_or_fault() {
        let mut sink = Sink::new(ring(), TestDevice { rate: 44_100, starts: 0, played: 3 });
        // Nothing was ever submitted: the ring drains its initial silence,
        // which is not an underrun and does not count as production.
        let report = sink.on_irq();
        assert!(report.underrun.is_none());
        assert_eq!(sink.written_frames(), 0);
        assert_eq!(sink.consumed_frames(), 3 * BUF_FRAMES as u64);
    }

    #[test]
    #[should_panic(expected = "audio producer overtook consumer")]
    fn producer_must_not_lap_and_overwrite_the_live_half_of_the_ring() {
        let mut sink = Sink::new(ring(), TestDevice { rate: 44_100, starts: 0, played: 0 });
        let frames = vec![(1, 1); RING_FRAMES];
        sink.submit(&frames, 1 << 16);
    }

    #[test]
    fn fill_applies_gain_and_clips_in_the_dma_ring() {
        let mut sink = Sink::new(
            ring(),
            TestDevice { rate: 44_100, starts: 0, played: 0 },
        );
        sink.submit(&[(100_000, -100_000)], 1 << 15);
        assert_eq!(sink.buf[0], [i16::MAX, i16::MIN]);
    }

}
