//! Sound Blaster 16 output — a kernel device driver (not machine code).
//!
//! On a machine whose real sound hardware is a Sound Blaster 16, the emulated
//! cards (`vsb`/`vgus`/`vmpu`) produce canonical PCM and the kernel `sound`
//! layer needs somewhere to play it. This driver is that sink: `sound::play`
//! dispatches here when the platform probe found a real SB16 (`Audio::SbSink`).
//!
//! It drives the real DSP for **16-bit signed-stereo auto-init DMA** on the ISA
//! 8237 (channel 5). The DMA region is a circular ring divided into completion
//! blocks; each completed block raises **IRQ 5**. The interrupt wakes the
//! event-driven audio track;
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

// ── SB16 DSP / mixer port OFFSETS from the card's base ──────────────────────
//    The base is the card's own (`SbCard::base`), never a guess: a card
//    jumpered to 0x240 used to be driven through 0x220's ports, which is
//    nobody's card. Not a per-thread BLASTER relocation either — that is the
//    guest's declaration, and the sink is not a guest.
const DSP_ACK16: u16 = 0x0F; // 16-bit IRQ acknowledge
const MIX_IDX: u16 = 0x04;
const MIX_DATA: u16 = 0x05;
const MIX_IRQ_STATUS: u8 = 0x82;
const MIX_IRQ_16BIT: u8 = 1 << 1;

// DSP commands.
const CMD_SPEAKER_ON: u8 = 0xD1;
const CMD_SET_RATE_OUT: u8 = 0x41; // output rate, big-endian 16-bit
const CMD_16BIT_AUTO_OUT: u8 = 0xB6; // 16-bit, auto-init, FIFO, D/A
const CMD_HALT_AUTO_16: u8 = 0xD5; // halt 16-bit DMA immediately
const MODE_SIGNED_STEREO: u8 = 0x30; // bit5 stereo, bit4 signed

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
/// Completion-IRQ granularity: one interrupt per buffer. The geometry matches
/// AC97/HDA: 512 signed-16 stereo frames, ≈ 11.6 ms at 44.1 kHz. A 30-ms pipe
/// keeps about 2.6 buffers queued while the larger block halves completion-IRQ
/// pressure relative to the old 256-frame path.
const BUF_BYTES: usize = 0x800;
const BUF_FRAMES: usize = BUF_BYTES / 4;
const NUM_BUF: usize = 32;
const RING_BYTES: usize = NUM_BUF * BUF_BYTES;
/// Prime at least two completion blocks before starting the DSP. The shared
/// 30-ms pipe normally submits two-and-a-half blocks on its first pass;
/// `submit` starts only after that whole pass is in memory, rather than halfway
/// through it.
const PRIME_BUFS: usize = 2;

/// This driver's live output: the ports it drives and the stream it runs.
///
/// It does NOT hold the card. The capability lives in `sound::Sink`, which is
/// what makes the sink the card's owner; this is the driver state that exists
/// only while it does. `None` means no stream — no card, or one that cannot
/// carry 16-bit auto-init DMA, which is this sink's silence.
struct Sb16 {
    base: u16,
    stream: Stream,
}

/// A running 16-bit auto-init output: the ring, the DSP session, and the pipe
/// counters that `sound::position` reads.
struct Stream {
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

/// **The** physical Sound Blaster, as a capability: where it lives, what it
/// can play, and how it reaches us.
///
/// Minted exactly once, by [`scan`], and neither `Copy` nor `Clone` — holding
/// this value IS the authority to drive the card, so the machine's one card is
/// unforgeable. It sits in exactly one place at a time: the kernel's unclaimed
/// slot ([`sound::park_sb`](crate::kernel::sound::park_sb)), the mixer sink
/// ([`Sb16`]), or the DOS thread driving it natively (`vsb::NativeSb`).
///
/// There is deliberately no `Option` inside. A card whose wiring is unknown
/// cannot be driven by anyone, so "we don't know how to reach it" is not a
/// half-built capability — it is the absence of one, which is why [`scan`]
/// returns `Option<SbCard>` and every field here is unconditional. The three
/// values that used to stand in for this one (a `Copy` `SbCard` snapshot plus
/// `Platform::{sb_card, sb_wiring}`) let every DOS thread mint its own
/// "unique" card out of frozen facts; `Platform` now records only that a DSP
/// *answered* (`AudioHw::Sb`).
///
/// The card's generation is consumed at mint rather than stored: `scan` reads
/// the DSP version, uses it to decide whether a declared 16-bit channel is
/// real, and drops it. So `dma16.is_some()` is trustworthy *by construction* —
/// the one path that could have lied about a 16-bit channel is closed where
/// the truth was known — and it is exactly the mixer sink's precondition.
#[derive(Debug)]
pub struct SbCard {
    /// The port window the card decodes. The guest's own base (`BLASTER A`)
    /// may differ; native passthrough translates.
    pub base: u16,
    /// The line the card really asserts on completion.
    pub irq: u8,
    /// The real 8237 channel it is strapped to for 8-bit transfers.
    pub dma8: u8,
    /// Its 16-bit channel — `None` on a pre-SB16 card, which has none at all.
    /// Being `Some` is what makes this card usable as the kernel mixer's sink.
    pub dma16: Option<u8>,
}

impl SbCard {
    /// This card's own strap view, for comparing against what the guest was
    /// told (`BLASTER`) before deciding whether to restrap.
    pub fn wiring(&self) -> SbWiring {
        SbWiring { irq: self.irq, dma8: self.dma8, dma16: self.dma16 }
    }

    /// Move the card's soft-straps (mixer 0x80/0x81) and adopt whatever it
    /// ACCEPTED — an emulation that pins its wiring reports the old values
    /// back, and the holder must proceed from truth, not intent. Only the
    /// holder can call this, which is the point: the acting wiring is the
    /// card's, so it cannot drift from a copy kept somewhere else.
    ///
    /// Pre-SB16 cards have no such registers; there is nothing to move, and
    /// their declared wiring stands.
    pub fn restrap<A: crate::Arch>(&mut self, machine: &mut A, want: SbWiring) -> SbWiring {
        let got = strap_wiring(machine, self.base, want);
        self.irq = got.irq;
        self.dma8 = got.dma8;
        self.dma16 = got.dma16;
        got
    }
}

/// The strap subset: what an SB16's mixer registers 0x80/0x81 can report and
/// accept. Not the whole card — the base is a jumper/PnP fact no register
/// carries — which is why this is the shape of a strap read/write and not the
/// shape of the capability.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SbWiring {
    pub irq: u8,
    pub dma8: u8,
    /// 16-bit channel; `None` on pre-SB16 cards, which have no 16-bit DMA.
    pub dma16: Option<u8>,
}

/// Bases a Sound Blaster can be jumpered/PnP'd to. It answers a DSP reset
/// with 0xAA at exactly one; empty ISA space reads 0xFF.
const BASES: [u16; 4] = [0x220, 0x240, 0x260, 0x280];

/// Does a Sound Blaster answer anywhere? Presence only — the fact
/// `platform::probe` needs for its `AudioHw` verdict, long before CONFIG.SYS
/// is readable and therefore long before a card can be minted.
pub fn answers<A: crate::Arch>(machine: &mut A) -> bool {
    BASES.into_iter().any(|b| dsp_reset_at(machine, b))
}

/// Mint the machine's Sound Blaster capability: sweep the legal bases, ask
/// what the card is (DSP 0xE1), and settle how it is wired.
///
/// `declared` is the owner's `SB_AUDIO=native <irq> <dma>`, which is the only
/// source of truth for a pre-SB16 card: its straps are physical jumpers,
/// invisible to software. An SB16 reports its own, so a declaration is
/// redundant there and the mixer wins.
///
/// `None` — no capability — when no card answers, or when one does but nobody
/// can say how it is wired. That is not a defeat to paper over with a default:
/// a guessed IRQ silently loses every completion interrupt, and a card no
/// owner can reach is exactly a card nobody holds.
pub fn scan<A: crate::Arch>(machine: &mut A, declared: Option<SbWiring>) -> Option<SbCard> {
    let base = BASES.into_iter().find(|&b| dsp_reset_at(machine, b))?;
    let dsp_major = dsp_version_major(machine, base);
    let is_sb16 = dsp_major >= 4;
    let Some(w) = (if is_sb16 { Some(read_wiring(machine, base)) } else { declared }) else {
        crate::println!(
            "sb: DSP {}.x at {:#05x} — pre-SB16 straps are invisible to software; declare them as \
             `SB_AUDIO=native <irq> <dma>` in CONFIG.SYS. Running without the card.",
            dsp_major, base
        );
        return None;
    };
    // The DSP version's whole remaining job: decide whether a declared 16-bit
    // channel exists. Below DSP 4 there is no such channel on the silicon, so
    // a declaration of one is the owner describing a card they don't have —
    // say so, and mint the truth. After this, `dma16.is_some()` cannot lie.
    let dma16 = match (is_sb16, w.dma16) {
        (false, Some(h)) => {
            crate::println!(
                "sb: DSP {}.x has no 16-bit DMA channel — ignoring the declared HDMA{}",
                dsp_major, h
            );
            None
        }
        (_, d) => d,
    };
    crate::println!(
        "sb: DSP {}.x at {:#05x} — IRQ{} DMA{}{}{}",
        dsp_major, base, w.irq, w.dma8,
        dma16.map(|d| alloc::format!(" HDMA{}", d)).unwrap_or_default(),
        if is_sb16 { " (SB16: straps read from the mixer)" } else { " (declared)" }
    );
    Some(SbCard { base, irq: w.irq, dma8: w.dma8, dma16 })
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

/// Strap an SB16 to the wanted IRQ/DMA via mixer 0x80/0x81 — the card's own
/// soft-configuration (what Creative's DIAGNOSE wrote). This is NOT just
/// relabeling: the 0x81 high bits ENABLE the card's 16-bit DMA channel, and
/// cards default it off (Bochs powers up "DMA 1/0" — no 16-bit channel — and
/// a guest's 16-bit auto-init then never moves, see Pinball Fantasies'
/// count-poll stall). Returns what the card actually accepted (readback):
/// an emulation that pins its wiring reports the old values, and the caller
/// proceeds from truth, not intent.
pub fn strap_wiring<A: crate::Arch>(machine: &mut A, base: u16, want: SbWiring) -> SbWiring {
    let irq_bits: u8 = match want.irq {
        2 => 0x01,
        5 => 0x02,
        7 => 0x04,
        10 => 0x08,
        _ => 0x02,
    };
    let mut dma_bits: u8 = match want.dma8 {
        0 => 0x01,
        1 => 0x02,
        3 => 0x08,
        _ => 0x02,
    };
    match want.dma16 {
        Some(5) => dma_bits |= 0x20,
        Some(6) => dma_bits |= 0x40,
        Some(7) => dma_bits |= 0x80,
        _ => {}
    }
    machine.outb(base + 0x04, 0x80);
    machine.outb(base + 0x05, irq_bits);
    machine.outb(base + 0x04, 0x81);
    machine.outb(base + 0x05, dma_bits);
    read_wiring(machine, base)
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

/// Silence a channel's permanent DMA buffer.
///
/// The buffer is where the audio physically IS: `vsb::arm` aliases the guest's
/// pages onto these frames, and `unbind` copies the content back out to the
/// guest without clearing them. Leaving it loaded means an auto-init transfer
/// that gets unmasked with nothing new written replays the last lap — there is
/// no LVI gate to stop it — so a card handed on in silence can still be heard.
///
/// The fill is NOT zero on both channels. An 8-bit SB transfer is unsigned
/// with a 0x80 bias, so zeroing it writes full-scale negative DC — a rail, not
/// silence. 16-bit transfers are signed, where zero is exactly silence.
pub fn zero_channel_buf<A: crate::Arch>(machine: &mut A, chan: u8) {
    let page = machine.dma_channel_buf(chan as usize);
    if page == 0 {
        return;
    }
    // 64 KB window on an 8-bit channel, 128 KB on a 16-bit one.
    let (pages, fill) = if chan >= 4 { (32usize, 0x00u8) } else { (16usize, 0x80u8) };
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, page, PTE_CACHE_DISABLE);
    unsafe { core::ptr::write_bytes(DMA_WIN_VA as *mut u8, fill, pages * 0x1000) };
}

/// Take the machine's Sound Blaster as the kernel mixer's sink, for good.
/// Called by `sound::Sink` once it owns the card — it keeps the capability,
/// this driver keeps the stream, which is why the card comes in by reference.
///
/// A card with no 16-bit DMA channel plays **silence**: the ring geometry here
/// is 16-bit channel-5 specific (`DMA5_*` ports, word addressing), so an SB
/// Pro has nothing to run it on. Silence is the honest output — not a
/// downgrade to some 8-bit path nobody wrote, and not a mode switch behind the
/// owner's back.
pub fn adopt<A: crate::Arch>(machine: &mut A, card: &SbCard) {
    if card.dma16 != Some(DMA_CHANNEL as u8) {
        crate::println!(
            "sb16: sink needs 16-bit DMA channel {}, this card has {:?} — output is silent",
            DMA_CHANNEL, card.dma16
        );
        return;
    }
    let stream = open_stream(machine, card);
    PRESENT.store(stream.is_some(), Ordering::Relaxed);
    *SB16.lock() = stream.map(|stream| Sb16 { base: card.base, stream });
}

/// Program the card for 16-bit signed-stereo auto-init output on channel 5 and
/// map its ring. `None` if the machine has no channel-5 DMA buffer to give us,
/// which is silence for the same reason as above.
fn open_stream<A: crate::Arch>(machine: &mut A, card: &SbCard) -> Option<Stream> {
    machine.route_isa_irq(card.irq);

    // Map the permanent contiguous channel-5 buffer into the stolen low-mem
    // window so the kernel can write PCM; the DSP reads it by physical address.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        crate::println!("sb16: no channel-{} DMA buffer — output is silent", DMA_CHANNEL);
        return None;
    }
    let pages = RING_BYTES.div_ceil(0x1000);
    machine.map_phys_range(DMA_WIN_VA >> 12, pages, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    // Start from silence so the first auto-init lap before prime isn't garbage.
    unsafe { core::ptr::write_bytes(DMA_WIN_VA as *mut u8, 0, RING_BYTES) };

    machine.outb(card.base + MIX_IDX, 0x22); // master volume index
    machine.outb(card.base + MIX_DATA, 0xFF); // full
    dsp_write_at(machine, card.base, CMD_SPEAKER_ON);

    IRQ_LINE.store(card.irq as u32, Ordering::Relaxed);
    crate::println!("sb16: sink on {:#05x}, IRQ {}, DMA {}", card.base, card.irq, DMA_CHANNEL);
    Some(Stream {
        dma_va: DMA_WIN_VA,
        dma_phys,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
        written: 0,
        consumed_frames: 0,
        last_dma_pos: 0,
    })
}

impl Stream {
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + i * BUF_BYTES
    }

    fn set_rate<A: crate::Arch>(&mut self, machine: &mut A, base: u16, rate: u32) {
        if rate != self.rate && rate != 0 {
            dsp_write_at(machine, base, CMD_SET_RATE_OUT);
            dsp_write_at(machine, base, (rate >> 8) as u8);
            dsp_write_at(machine, base, rate as u8);
            self.rate = rate;
        }
    }

    /// Program the 8237 for the whole ring in 16-bit auto-init, then start the
    /// DSP's 16-bit auto-init output with a per-buffer block length. Done once,
    /// after the first buffers are primed; the DSP then free-runs the ring and
    /// raises the completion IRQ every buffer.
    fn start<A: crate::Arch>(&mut self, machine: &mut A, base: u16) {
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

        // DSP block length is in 16-bit transfers, not stereo frames: every
        // frame contributes left + right, hence BUF_BYTES/2 samples.
        let block_samples = (BUF_BYTES / 2) as u16;
        dsp_write_at(machine, base, CMD_16BIT_AUTO_OUT);
        dsp_write_at(machine, base, MODE_SIGNED_STEREO);
        dsp_write_at(machine, base, (block_samples - 1) as u8);
        dsp_write_at(machine, base, ((block_samples - 1) >> 8) as u8);
        self.running = true;
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit<A: crate::Arch>(&mut self, machine: &mut A, base: u16, rate: u32, fmt: Format, bytes: &[u8]) {
        self.set_rate(machine, base, rate);
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            let (l, r) = fmt.frame(bytes, i);
            let p = self.buf_va(self.cur_buf) + self.cur_off;
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
        // Do not start from inside the copy loop. Hardware may schedule DMA as
        // soon as B6 is issued; starting after buffer two while the same call
        // is still filling the remainder of the initial producer burst lets
        // playback race that copy.
        if !self.running && self.written >= (PRIME_BUFS * BUF_FRAMES) as u64 {
            self.start(machine, base);
        }
    }
}

/// Stream a block of source PCM to the SB16 (called by `sound::play`).
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    let mut g = SB16.lock();
    // No stream, or the card is on loan: the frames are dropped. That IS the
    // output of a sink that owns no silicon to play them through.
    if let Some((stream, base)) = g.as_mut().map(|d| (&mut d.stream, d.base)) {
        stream.submit(machine, base, rate, fmt, bytes);
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

fn update_cursor<A: crate::Arch>(dev: &mut Stream, machine: &mut A) -> (u32, u32) {
    let ring = RING_BYTES as u32;
    let pos = dma_pos_bytes(machine);
    let delta = (pos + ring - dev.last_dma_pos) % ring;
    if delta != 0 {
        dev.consumed_frames += (delta / 4) as u64;
        dev.last_dma_pos = pos;
    }
    (pos, delta)
}

/// Service a block-completion interrupt. The mixer status distinguishes our
/// 16-bit DMA source on a potentially shared ISA line; the live 8237 cursor
/// supplies authoritative progress when the IRQ wakes the driver.
pub fn on_irq<A: crate::Arch>(machine: &mut A) -> bool {
    let mut g = SB16.lock();
    // Nothing playing means this line is not ours to claim — with the card on
    // loan, asking the mixer would be reading silicon we do not own.
    let Some((stream, base)) = g.as_mut().map(|d| (&mut d.stream, d.base)) else { return false };
    machine.outb(base + MIX_IDX, MIX_IRQ_STATUS);
    if machine.inb(base + MIX_DATA) & MIX_IRQ_16BIT == 0 {
        return false;
    }
    if stream.running {
        // The IRQ is a wakeup, not an additional unit of elapsed time.
        // `position()` may already have observed this exact DMA cursor;
        // inventing a block when delta==0 moves last_dma_pos ahead of the
        // hardware and makes the next read look like a near-full-ring wrap.
        let (pos, delta) = update_cursor(stream, machine);
        // Diagnostic: has the play cursor reached the write cursor? (queued
        // buffers <= 0 -> the next buffers the DSP plays are stale.)
        if stream.written <= stream.consumed_frames {
            let n = UNDERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 3 || n.is_multiple_of(64) {
                crate::println!(
                    "sb16: underrun #{} written={} consumed={} dma_pos={} delta={}",
                    n, stream.written, stream.consumed_frames, pos, delta
                );
            }
        }
    }
    let _ = machine.inb(base + DSP_ACK16); // acknowledge the 16-bit completion IRQ
    true
}

/// Pipe counters for `sound::position`, in source frames: `written` accepted,
/// and `consumed` from the monotonicized live 8237 DMA cursor.
pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    let mut g = SB16.lock();
    let (stream, _) = g.as_mut().map(|d| (&mut d.stream, d.base))?;
    if stream.running {
        // ISA DSP interrupt latches can coalesce while auto-init DMA continues.
        // The IRQ remains the wakeup/ack path, but this cheap 8237 read prevents
        // a delayed latch service from hiding several already-consumed blocks.
        update_cursor(stream, machine);
    }
    Some((stream.written, stream.consumed_frames))
}

/// Producer went idle: halt DMA, reset the DSP state machine, and start the
/// next session from a clean, silent ring. Reset is deliberate here: a bare
/// D5 pause leaves a subsequent B6 auto-init command dependent on clone-specific
/// pause/continue state.
pub fn stop<A: crate::Arch>(machine: &mut A, _park: bool) {
    let mut g = SB16.lock();
    let Some((stream, base)) = g.as_mut().map(|d| (&mut d.stream, d.base)) else { return };
    if stream.running {
        dsp_write_at(machine, base, CMD_HALT_AUTO_16);
        machine.outb(DMA5_MASK, 0x05); // mask channel 5
    }
    let _ = dsp_reset_at(machine, base);
    dsp_write_at(machine, base, CMD_SPEAKER_ON);
    stream.running = false;
    stream.rate = 0;
    stream.cur_buf = 0;
    stream.cur_off = 0;
    stream.written = 0;
    stream.consumed_frames = 0;
    stream.last_dma_pos = 0;
    unsafe { core::ptr::write_bytes(stream.dma_va as *mut u8, 0, RING_BYTES) };
}
