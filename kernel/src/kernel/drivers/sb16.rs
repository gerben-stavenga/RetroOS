//! Sound Blaster 16 output — a kernel device driver (not machine code).
//!
//! On a machine whose real sound hardware is a Sound Blaster 16, the emulated
//! cards (`vsb`/`vgus`/`vmpu`) produce canonical PCM and the kernel `sound`
//! layer needs somewhere to play it. This driver is that sink: `sound::play`
//! dispatches here when the platform probe found a real SB16 (`Audio::SbSink`).
//!
//! It drives the real DSP for **16-bit signed-stereo auto-init DMA** on the ISA
//! 8237 (channel 5) — the SB16's own double-buffer scheme, where each completed
//! block raises **IRQ 5**. The interrupt wakes the event-driven audio track;
//! `on_irq` then reads the live 8237 cursor, so delayed/coalesced delivery does
//! not turn an event count into a false playback position.
//!
//! Only machine *primitives* are used — port I/O (`inb`/`outb`, for the DSP,
//! mixer, and the 8237), `dma_channel_buf` (the permanent contiguous channel-5
//! buffer, ISA-DMA-safe), and `map_phys_range` (to map it into kernel space) —
//! never any machine-side driver logic. The DMA window is shared with the
//! ac97/hda sinks (only one sink is ever active), see `ac97.rs`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::kernel::sound::Format;

// ── SB16 DSP / mixer ports (base 0x220; the card is machine-wide, so the sink
//    uses the canonical base, not a per-thread BLASTER relocation) ────────────
const BASE: u16 = 0x220;
const DSP_WRITE: u16 = BASE + 0x0C; // write command/data; bit7 = busy
const DSP_ACK16: u16 = BASE + 0x0F; // 16-bit IRQ acknowledge
const MIX_IDX: u16 = BASE + 0x04;
const MIX_DATA: u16 = BASE + 0x05;
const MIX_IRQ_STATUS: u8 = 0x82;
const MIX_IRQ_16BIT: u8 = 1 << 1;

// DSP commands.
const CMD_SPEAKER_ON: u8 = 0xD1;
const CMD_SET_RATE_OUT: u8 = 0x41; // output rate, big-endian 16-bit
const CMD_16BIT_AUTO_OUT: u8 = 0xB6; // 16-bit, auto-init, FIFO, D/A
const CMD_HALT_AUTO_16: u8 = 0xD5; // halt 16-bit DMA immediately
// Mono, signed (bit4 = signed, bit5 = stereo). QEMU's sb16 does not honour the
// DSP stereo bit on the 16-bit auto-init path — it plays the interleaved buffer
// as mono, which comes out at half speed / doubled — so the sink downmixes to
// mono and programs mono output. (Stereo out is a TODO pending the QEMU quirk.)
const MODE_SIGNED_MONO: u8 = 0x10;

// ── 8237 channel-5 (16-bit) registers ───────────────────────────────────────
const DMA_CHANNEL: usize = 5;
const DMA5_MASK: u16 = 0xD4; // write 0x05 to mask, 0x01 to unmask
const DMA5_MODE: u16 = 0xD6;
const DMA5_CLRFF: u16 = 0xD8;
const DMA5_ADDR: u16 = 0xC4; // word address (low then high)
const DMA5_COUNT: u16 = 0xC6; // word count − 1 (low then high)
const DMA5_PAGE: u16 = 0x8B;
// single(0x40) | auto-init(0x10) | read/mem→dev(0x08) | channel-local 1 (5−4).
const DMA5_MODE_AUTO_READ: u8 = 0x59;

// ── ring geometry (shares the stolen low-mem DMA window with ac97/hda) ───────
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
const PTE_CACHE_DISABLE: u64 = 1 << 4;
/// Completion-IRQ granularity: one interrupt per buffer. ≤ half the universal
/// pipe (see `sound::min_fill`) so ≥ 2 buffers stay queued (double-buffered).
/// Mono: one 16-bit sample per mixed stereo frame, so a buffer holds
/// `BUF_BYTES/2` frames.
const BUF_BYTES: usize = 0x200; // 512 B = 256 mono samples ≈ 5.8 ms @ 44.1 kHz
/// Playback frames (= mono samples) per buffer.
const BUF_FRAMES: usize = BUF_BYTES / 2;
const NUM_BUF: usize = 32;
const RING_BYTES: usize = NUM_BUF * BUF_BYTES;
/// Prime at least two completion blocks before starting the DSP. The shared
/// 30-ms pipe normally submits five blocks on its first pass; `submit` starts
/// only after that whole pass is in memory, rather than halfway through it.
const PRIME_BUFS: usize = 2;

struct Sb16 {
    dma_va: usize,
    dma_phys: u32,
    cur_buf: usize, // ring buffer currently being filled
    cur_off: usize, // byte offset within `cur_buf`
    running: bool,  // DSP auto-init playback started
    rate: u32,      // last programmed sample rate
    /// Pipe counters for [`position`], in source frames (the DAC runs at the
    /// source rate — no resampler). `written` = frames accepted by `submit`;
    /// `consumed_frames` comes from the live 8237 cursor whenever an IRQ wakes
    /// the driver; IRQ event counts themselves are not trusted.
    written: u64,
    consumed_frames: u64,
    last_dma_pos: u32,
}

static SB16: Mutex<Option<Sb16>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);
/// Diagnostic: times the play cursor caught the write cursor (underrun → the
/// DSP replays stale ring data since auto-init has no LVI gate → a click).
static UNDERRUNS: AtomicU32 = AtomicU32::new(0);
/// The IRQ line the card raises on block completion (read from the mixer at
/// bring-up), so `sound::on_irq` can match it. 0xFF until up.
static IRQ_LINE: AtomicU32 = AtomicU32::new(0xFF);

/// The routed completion-IRQ line, for `sound::on_irq`. `None` until up.
pub fn irq_line() -> Option<u8> {
    match IRQ_LINE.load(Ordering::Relaxed) {
        0xFF => None,
        n => Some(n as u8),
    }
}

/// The sink is up and reports a play position (so `sound::min_fill` returns the
/// universal pipe depth).
pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// Reset the DSP and read back the 0xAA ready byte. Pure presence probe —
/// `platform::probe` uses it for the Audio decision; an absent card reads 0xFF.
/// What a real Sound Blaster reported about itself. In native mode this IS
/// the guest's card, so these values become the fabricated `BLASTER`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SbCard {
    pub base: u16,
    /// DSP major version: 1/2 = SB 1.x/2.0, 3 = SB Pro, 4 = SB16.
    pub dsp_major: u8,
    /// IRQ / 8-bit DMA / 16-bit DMA, read from the SB16 mixer. `None` below
    /// DSP 4: those registers do not exist and jumper straps are physically
    /// invisible to software, so the owner declares them (`SB_AUDIO=native
    /// <irq> <dma>`). There is no default — a guessed IRQ silently loses
    /// every completion interrupt.
    pub wiring: Option<SbWiring>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SbWiring {
    pub irq: u8,
    pub dma8: u8,
    /// 16-bit channel; `None` on pre-SB16 cards, which have no 16-bit DMA.
    pub dma16: Option<u8>,
}

impl SbCard {
    /// Only an SB16 can back the emulated stack: our emulated card IS an
    /// SB16 (CT1745 mixer, 16-bit DMA) and the sink drives 16-bit
    /// signed-stereo auto-init DMA, which an SB Pro cannot do at all.
    pub fn can_be_sink(&self) -> bool {
        self.dsp_major >= 4
    }
}

/// Bases a Sound Blaster can be jumpered/PnP'd to. It answers a DSP reset
/// with 0xAA at exactly one; empty ISA space reads 0xFF.
const BASES: [u16; 4] = [0x220, 0x240, 0x260, 0x280];

/// Find the card: sweep the legal bases, ask what it is (DSP 0xE1), and on
/// an SB16 read how it is strapped.
pub fn scan<A: crate::Arch>(machine: &mut A) -> Option<SbCard> {
    let base = BASES.into_iter().find(|&b| dsp_reset_at(machine, b))?;
    let dsp_major = dsp_version_major(machine, base);
    let wiring = (dsp_major >= 4).then(|| read_wiring(machine, base));
    crate::println!(
        "sb: DSP {}.x at {:#05x}{}",
        dsp_major, base,
        if wiring.is_some() { " (SB16: wiring readable)" } else { " (pre-SB16: declare SB_AUDIO wiring)" }
    );
    Some(SbCard { base, dsp_major, wiring })
}

/// DSP `0xE1` — get version; the major byte is the generation.
fn dsp_version_major<A: crate::Arch>(machine: &mut A, base: u16) -> u8 {
    dsp_write_at(machine, base, 0xE1);
    let major = dsp_read_at(machine, base);
    let _minor = dsp_read_at(machine, base);
    major
}

/// SB16 mixer 0x80/0x81: the IRQ and DMA channels the card is strapped to
/// (Creative's bit assignments).
fn read_wiring<A: crate::Arch>(machine: &mut A, base: u16) -> SbWiring {
    machine.outb(base + 0x04, 0x80);
    let v = machine.inb(base + 0x05);
    let irq = if v & 0x01 != 0 { 2 } else if v & 0x02 != 0 { 5 }
        else if v & 0x04 != 0 { 7 } else if v & 0x08 != 0 { 10 } else { 5 };
    machine.outb(base + 0x04, 0x81);
    let d = machine.inb(base + 0x05);
    let dma8 = if d & 0x01 != 0 { 0 } else if d & 0x02 != 0 { 1 }
        else if d & 0x08 != 0 { 3 } else { 1 };
    let dma16 = if d & 0x20 != 0 { Some(5) } else if d & 0x40 != 0 { Some(6) }
        else if d & 0x80 != 0 { Some(7) } else { None };
    SbWiring { irq, dma8, dma16 }
}

fn dsp_reset_at<A: crate::Arch>(machine: &mut A, base: u16) -> bool {
    machine.outb(base + 0x06, 1);
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    machine.outb(base + 0x06, 0);
    for _ in 0..100_000 {
        if machine.inb(base + 0x0E) & 0x80 != 0 && machine.inb(base + 0x0A) == 0xAA {
            return true;
        }
    }
    false
}

fn dsp_write_at<A: crate::Arch>(machine: &mut A, base: u16, byte: u8) {
    for _ in 0..100_000 {
        if machine.inb(base + 0x0C) & 0x80 == 0 {
            machine.outb(base + 0x0C, byte);
            return;
        }
    }
}

fn dsp_read_at<A: crate::Arch>(machine: &mut A, base: u16) -> u8 {
    for _ in 0..100_000 {
        if machine.inb(base + 0x0E) & 0x80 != 0 {
            return machine.inb(base + 0x0A);
        }
    }
    0xFF
}

/// Bring up the SB16 the platform probe found. Driver init only.
pub fn init<A: crate::Arch>(machine: &mut A) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::SbSink {
        return;
    }
    if bring_up(machine) {
        PRESENT.store(true, Ordering::Relaxed);
    }
}

/// Write one DSP command/data byte once the write buffer is ready (bit7 clear).
fn dsp_write<A: crate::Arch>(machine: &mut A, byte: u8) {
    for _ in 0..100_000 {
        if machine.inb(DSP_WRITE) & 0x80 == 0 {
            break;
        }
    }
    machine.outb(DSP_WRITE, byte);
}

/// Read the SB16 mixer's IRQ-select register (0x80) into an IRQ line. Bits:
/// 1=IRQ2, 2=IRQ5, 4=IRQ7, 8=IRQ10. Defaults to 5 if the mixer is mute (0xFF).
fn bring_up<A: crate::Arch>(machine: &mut A) -> bool {

    let Some(card) = crate::kernel::platform::get().sb_card else { return false };
    let Some(w) = card.wiring else { return false }; // sink implies SB16
    machine.route_isa_irq(w.irq);

    // Map the permanent contiguous channel-5 buffer into the stolen low-mem
    // window so the kernel can write PCM; the DSP reads it by physical address.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        crate::println!("sb16: no channel-{} DMA buffer; skipping", DMA_CHANNEL);
        return false;
    }
    let pages = RING_BYTES.div_ceil(0x1000);
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    // Start from silence so the first auto-init lap before prime isn't garbage.
    unsafe { core::ptr::write_bytes(DMA_WIN_VA as *mut u8, 0, RING_BYTES) };

    machine.outb(MIX_IDX, 0x22); // master volume index
    machine.outb(MIX_DATA, 0xFF); // full
    dsp_write(machine, CMD_SPEAKER_ON);

    *SB16.lock() = Some(Sb16 {
        dma_va: DMA_WIN_VA,
        dma_phys,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
        written: 0,
        consumed_frames: 0,
        last_dma_pos: 0,
    });
    IRQ_LINE.store(w.irq as u32, Ordering::Relaxed);
    crate::println!("sb16: sink on {:#05x}, IRQ {}, DMA {}", card.base, w.irq, DMA_CHANNEL);
    true
}

impl Sb16 {
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + i * BUF_BYTES
    }

    fn set_rate<A: crate::Arch>(&mut self, machine: &mut A, rate: u32) {
        if rate != self.rate && rate != 0 {
            dsp_write(machine, CMD_SET_RATE_OUT);
            dsp_write(machine, (rate >> 8) as u8);
            dsp_write(machine, rate as u8);
            self.rate = rate;
        }
    }

    /// Program the 8237 for the whole ring in 16-bit auto-init, then start the
    /// DSP's 16-bit auto-init output with a per-buffer block length. Done once,
    /// after the first buffers are primed; the DSP then free-runs the ring and
    /// raises the completion IRQ every buffer.
    fn start<A: crate::Arch>(&mut self, machine: &mut A) {
        let word_addr = (self.dma_phys >> 1) & 0xFFFF;
        let words = (RING_BYTES / 2) as u32;
        machine.outb(DMA5_MASK, 0x05); // mask channel 5
        machine.outb(DMA5_CLRFF, 0);
        machine.outb(DMA5_MODE, DMA5_MODE_AUTO_READ);
        machine.outb(DMA5_ADDR, word_addr as u8);
        machine.outb(DMA5_ADDR, (word_addr >> 8) as u8);
        machine.outb(DMA5_PAGE, (self.dma_phys >> 16) as u8);
        machine.outb(DMA5_COUNT, (words - 1) as u8);
        machine.outb(DMA5_COUNT, ((words - 1) >> 8) as u8);
        machine.outb(DMA5_MASK, 0x01); // unmask channel 5
        self.last_dma_pos = 0;

        // DSP block length in 16-bit samples − 1 (one buffer per IRQ). Mono, so
        // a buffer is BUF_FRAMES samples.
        let block_samples = BUF_FRAMES as u16;
        dsp_write(machine, CMD_16BIT_AUTO_OUT);
        dsp_write(machine, MODE_SIGNED_MONO);
        dsp_write(machine, (block_samples - 1) as u8);
        dsp_write(machine, ((block_samples - 1) >> 8) as u8);
        self.running = true;
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
        self.set_rate(machine, rate);
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            let (l, r) = fmt.frame(bytes, i);
            let m = ((l as i32 + r as i32) / 2) as i16; // downmix to mono
            let p = self.buf_va(self.cur_buf) + self.cur_off;
            unsafe {
                core::ptr::write_volatile(p as *mut u16, m as u16);
            }
            self.written += 1;
            self.cur_off += 2;
            if self.cur_off >= BUF_BYTES {
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
            }
        }
        // Do not start from inside the copy loop. QEMU is allowed to schedule
        // DMA as soon as B6 is issued; starting after buffer two while the same
        // call is still filling buffers three through five lets playback race
        // the initial producer burst.
        if !self.running && self.written >= (PRIME_BUFS * BUF_FRAMES) as u64 {
            self.start(machine);
        }
    }
}

/// Stream a block of source PCM to the SB16 (called by `sound::play`).
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    let mut g = SB16.lock();
    if let Some(dev) = g.as_mut() {
        dev.submit(machine, rate, fmt, bytes);
    }
}

fn dma_count<A: crate::Arch>(machine: &mut A) -> u16 {
    machine.outb(DMA5_CLRFF, 0);
    let lo = machine.inb(DMA5_COUNT) as u16;
    let hi = machine.inb(DMA5_COUNT) as u16;
    (hi << 8) | lo
}

fn dma_pos_bytes<A: crate::Arch>(machine: &mut A) -> u32 {
    let words = (RING_BYTES / 2) as u32;
    // The 8237 exposes the count as two independently read bytes while DMA is
    // live. Around a low-byte borrow, one pair can be torn and appear to jump
    // almost a whole ring. Two nearby complete samples must differ by only a
    // handful of transfers; retry a few times and use the newest stable one.
    let mut count = dma_count(machine);
    for _ in 0..3 {
        let next = dma_count(machine);
        let forward = (count as u32 + words - next as u32) % words;
        count = next;
        if forward <= 32 {
            break;
        }
    }
    ((words - 1).wrapping_sub(count as u32) % words) * 2
}

fn update_cursor<A: crate::Arch>(dev: &mut Sb16, machine: &mut A) -> (u32, u32) {
    let ring = RING_BYTES as u32;
    let pos = dma_pos_bytes(machine);
    let delta = (pos + ring - dev.last_dma_pos) % ring;
    if delta != 0 {
        dev.consumed_frames += (delta / 2) as u64;
        dev.last_dma_pos = pos;
    }
    (pos, delta)
}

/// Service a block-completion interrupt. The mixer status distinguishes our
/// 16-bit DMA source on a potentially shared ISA line; the live 8237 cursor
/// supplies authoritative progress when the IRQ wakes the driver.
pub fn on_irq<A: crate::Arch>(machine: &mut A) -> bool {
    machine.outb(MIX_IDX, MIX_IRQ_STATUS);
    if machine.inb(MIX_DATA) & MIX_IRQ_16BIT == 0 {
        return false;
    }
    let mut g = SB16.lock();
    if let Some(dev) = g.as_mut()
        && dev.running
    {
        {
            // The IRQ is a wakeup, not an additional unit of elapsed time.
            // `position()` may already have observed this exact DMA cursor;
            // inventing a block when delta==0 moves last_dma_pos ahead of the
            // hardware and makes the next read look like a near-full-ring wrap.
            let (pos, delta) = update_cursor(dev, machine);
            // Diagnostic: has the play cursor reached the write cursor? (queued
            // buffers ≤ 0 → the next buffers the DSP plays are stale.)
            if dev.written <= dev.consumed_frames {
                let n = UNDERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 3 || n.is_multiple_of(64) {
                    crate::println!(
                        "sb16: underrun #{} written={} consumed={} dma_pos={} delta={}",
                        n, dev.written, dev.consumed_frames, pos, delta
                    );
                }
            }
        }
    }
    let _ = machine.inb(DSP_ACK16); // acknowledge the 16-bit completion IRQ
    true
}

/// Pipe counters for `sound::position`, in source frames: `written` accepted,
/// and `consumed` from the monotonicized live 8237 DMA cursor.
pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    let mut g = SB16.lock();
    let dev = g.as_mut()?;
    if dev.running {
        // ISA DSP interrupt latches can coalesce while auto-init DMA continues.
        // The IRQ remains the wakeup/ack path, but this cheap 8237 read prevents
        // a delayed latch service from hiding several already-consumed blocks.
        update_cursor(dev, machine);
    }
    Some((dev.written, dev.consumed_frames))
}

/// Producer went idle: halt DMA, reset the DSP state machine, and start the
/// next session from a clean, silent ring. Reset is deliberate here: a bare
/// D5 pause leaves a subsequent B6 auto-init command dependent on clone-specific
/// pause/continue state.
pub fn stop<A: crate::Arch>(machine: &mut A, _park: bool) {
    let mut g = SB16.lock();
    let Some(dev) = g.as_mut() else { return };
    if dev.running {
        dsp_write(machine, CMD_HALT_AUTO_16);
        machine.outb(DMA5_MASK, 0x05); // mask channel 5
    }
    let _ = dsp_reset_at(machine, BASE);
    dsp_write(machine, CMD_SPEAKER_ON);
    dev.running = false;
    dev.rate = 0;
    dev.cur_buf = 0;
    dev.cur_off = 0;
    dev.written = 0;
    dev.consumed_frames = 0;
    dev.last_dma_pos = 0;
    unsafe { core::ptr::write_bytes(dev.dma_va as *mut u8, 0, RING_BYTES) };
}
