//! Sound Blaster 16 output — a kernel device driver (not machine code).
//!
//! On a machine whose real sound hardware is a Sound Blaster 16, the emulated
//! cards (`vsb`/`vgus`/`vmpu`) produce canonical PCM and the kernel `sound`
//! layer needs somewhere to play it. This driver is that sink: `sound::play`
//! dispatches here when the platform probe found a real SB16 (`Audio::SbSink`).
//!
//! It drives the real DSP for **16-bit signed-stereo auto-init DMA** on the ISA
//! 8237 (channel 5). The DMA region is a circular ring. The kernel polls the
//! live 8237 cursor for accounting and leaves the DSP completion IRQ masked.
//!
//! Only machine *primitives* are used — port I/O (`inb`/`outb`, for the DSP,
//! mixer, and the 8237), `dma_channel_buf` (the permanent contiguous channel-5
//! buffer, ISA-DMA-safe), and `map_phys_range` (to map it into kernel space) —
//! never any machine-side driver logic. The DMA window is shared with the
//! ac97/hda sinks (only one sink is ever active), see `ac97.rs`.

// ── SB16 DSP / mixer port OFFSETS from the card's base ──────────────────────
//    The base is the card's own (`SbCard::base`), never a guess: a card
//    jumpered to 0x240 used to be driven through 0x220's ports, which is
//    nobody's card. Not a per-thread BLASTER relocation either — that is the
//    guest's declaration, and the sink is not a guest.
const MIX_IDX: u16 = 0x04;
const MIX_DATA: u16 = 0x05;

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
// ── ring geometry ───────────────────────────────────────────────────────────
const BUF_BYTES: usize = 0x800;
const BUF_FRAMES: usize = BUF_BYTES / core::mem::size_of::<crate::kernel::sound::Frame>();
const NUM_BUF: usize = 32;
const RING_BYTES: usize = NUM_BUF * BUF_BYTES;
const RING_FRAMES: usize = NUM_BUF * BUF_FRAMES;
/// The output rate this card programs into its DSP. The SB16 DAC will play
/// any rate it is handed, so unlike the other two this is a genuine choice
/// rather than a hardware fact — 44.1 kHz is the card's top quality mode. It
/// is stated for everyone as this card's arm of `sound::sink::Device::rate`.
const RATE: u32 = 44_100;

/// What only THIS card knows. The ring, the counters and the prime/underrun
/// bookkeeping belong to the sound sink — shared with every other device,
/// because none of it is Sound-Blaster-specific. What is left here is the 8237
/// channel-5 programming, the DSP session and its live DMA cursor.
pub struct Sb16 {
    base: u16,
    /// Physical base of the transfer ring, for (re)programming the 8237.
    phys: u32,
    /// Frames already reported to the sink. Re-baselined at `start`, so a
    /// restart never reports the previous session's frames.
    reported: u64,
    /// Last raw ring byte position, for accumulating across wraps.
    last_pos: u32,
    /// Bytes the DAC has consumed since `start`, monotonic.
    consumed: u64,
}

// Written once during single-threaded boot, then reachable only through the
// unique capability returned by `adopt`.
static mut SB16: Option<Sb16> = None;

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
        let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
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
            let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
                "sb: DSP {}.x has no 16-bit DMA channel — ignoring the declared HDMA{}",
                dsp_major, h
            );
            None
        }
        (_, d) => d,
    };
    let source = if is_sb16 { " (SB16: straps read from the mixer)" } else { " (declared)" };
    match dma16 {
        Some(dma16) => crate::compact_println!(
            "sb: DSP {}.x at {:#05x} — IRQ{} DMA{} HDMA{}{}",
            dsp_major, base, w.irq, w.dma8, dma16, source,
        ),
        None => crate::compact_println!(
            "sb: DSP {}.x at {:#05x} — IRQ{} DMA{}{}",
            dsp_major, base, w.irq, w.dma8, source,
        ),
    }
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
/// Returns the unique runtime device, or `None` if this card cannot be a sink.
pub fn adopt<A: crate::Arch>(machine: &mut A, card: SbCard) -> Option<&'static mut Sb16> {
    if card.dma16 != Some(DMA_CHANNEL as u8) {
        crate::compact_println!(
            "sb16: sink needs 16-bit DMA channel {}, this card has {:?} — output is silent",
            DMA_CHANNEL, card.dma16
        );
        return None;
    }
    let phys = open_ring(machine, &card)?;
    let device = Sb16 { base: card.base, phys, reported: 0, last_pos: 0, consumed: 0 };
    unsafe {
        let slot = &raw mut SB16;
        assert!((*slot).is_none(), "SB16 adopted twice");
        *slot = Some(device);
        (*slot).as_mut()
    }
}

/// Map the permanent channel-5 buffer and wake the card up. The ring's
/// CONTENT is the engine's business; this hands over where it lives.
fn open_ring<A: crate::Arch>(machine: &mut A, card: &SbCard) -> Option<u32> {
    // Map the permanent contiguous channel-5 buffer into the stolen low-mem
    // window so the kernel can write PCM; the DSP reads it by physical address.
    let phys_page = machine.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        crate::compact_println!("sb16: no channel-{} DMA buffer — output is silent", DMA_CHANNEL);
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

    crate::compact_println!("sb16: sink on {:#05x}, DMA {}", card.base, DMA_CHANNEL);
    Some(dma_phys)
}

// ── the four things a `sound::sink::Device` must do ─────────────────────────
//
// None of them take a machine handle: port I/O here goes through the injected
// surface (`kernel::portio`, the same backend functions `Arch::inb/outb` call,
// installed by the entry crate), exactly as the ATA and PCI-config drivers
// already reach their hardware. That is what lets the sink contract live in
// `//lib:sound` without knowing what an `Arch` is.

use crate::kernel::portio::{inb, outb};

impl Sb16 {
    pub fn ring(&mut self) -> &'static mut [crate::kernel::sound::Frame] {
        unsafe {
            core::slice::from_raw_parts_mut(
                DMA_WIN_VA as *mut crate::kernel::sound::Frame,
                RING_FRAMES,
            )
        }
    }
}

impl sound::sink::Device for Sb16 {
    fn rate(&self) -> u32 {
        RATE
    }

    fn block_frames(&self) -> usize {
        BUF_FRAMES
    }

    fn start(&mut self) {
        let word_addr = (self.phys >> 1) & 0xFFFF;
        let words = (RING_BYTES / 2) as u32;
        outb(DMA5_MASK, 0x05);
        outb(DMA5_CLRFF, 0);
        outb(DMA5_MODE, DMA5_MODE_AUTO_READ);
        outb(DMA5_ADDR, word_addr as u8);
        outb(DMA5_ADDR, (word_addr >> 8) as u8);
        outb(DMA5_PAGE, (self.phys >> 16) as u8);
        outb(DMA5_COUNT, (words - 1) as u8);
        outb(DMA5_COUNT, ((words - 1) >> 8) as u8);
        outb(DMA5_MASK, 0x01);
        self.last_pos = 0;
        self.consumed = 0;
        self.reported = 0;

        let block_samples = (RING_BYTES / 4) as u16;
        dsp_write(self.base, CMD_SET_RATE_OUT);
        dsp_write(self.base, (RATE >> 8) as u8);
        dsp_write(self.base, RATE as u8);
        dsp_write(self.base, CMD_16BIT_AUTO_OUT);
        dsp_write(self.base, MODE_SIGNED_STEREO);
        dsp_write(self.base, (block_samples - 1) as u8);
        dsp_write(self.base, ((block_samples - 1) >> 8) as u8);
        let _ = compact_fmt::writeln!(&mut lib::log::DebugCon,
            "sb16: stream RUN base={:#05x} ring={} block={}",
            self.base,
            RING_BYTES,
            BUF_BYTES
        );
    }

    fn halt(&mut self) {
        dsp_write(self.base, CMD_HALT_AUTO_16);
        outb(DMA5_MASK, 0x05);
        let _ = dsp_reset(self.base);
        dsp_write(self.base, CMD_SPEAKER_ON);
    }

    fn frames_played(&mut self) -> u64 {
        let ring = RING_BYTES as u32;
        let pos = dma_pos_bytes();
        let delta = (pos + ring - self.last_pos) % ring;
        if delta != 0 {
            self.consumed += delta as u64;
            self.last_pos = pos;
        }
        let played = self.consumed / core::mem::size_of::<crate::kernel::sound::Frame>() as u64;
        let fresh = played.saturating_sub(self.reported);
        self.reported = played;
        fresh
    }
}

fn dsp_write(base: u16, byte: u8) {
    for _ in 0..100_000 {
        if inb(base + 0x0C) & 0x80 == 0 {
            break;
        }
    }
    outb(base + 0x0C, byte);
}

fn dsp_reset(base: u16) -> bool {
    outb(base + 0x06, 1);
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    outb(base + 0x06, 0);
    for _ in 0..100_000 {
        if inb(base + 0x0E) & 0x80 != 0 && inb(base + 0x0A) == 0xAA {
            return true;
        }
    }
    false
}

fn dma_count() -> u16 {
    outb(DMA5_CLRFF, 0);
    let lo = inb(DMA5_COUNT) as u16;
    let hi = inb(DMA5_COUNT) as u16;
    (hi << 8) | lo
}

/// Where the DAC is in the ring, in bytes.
///
/// The 8237 exposes its 16-bit count through one 8-bit port plus a byte-pointer
/// flip-flop, and does not latch it for reading — so around a borrow the two
/// halves can come from different moments and the pair reads as a jump of
/// nearly a whole ring. Two nearby samples must differ by a handful of
/// transfers; retry until they do. (The guest never sees this: `vsb` serves it
/// a properly latched pair, which is the 8237 Intel should have built.)
fn dma_pos_bytes() -> u32 {
    let words = (RING_BYTES / 2) as u32;
    let mut count = dma_count();
    for _ in 0..3 {
        let next = dma_count();
        let forward = (count as u32 + words - next as u32) % words;
        count = next;
        if forward <= 32 {
            break;
        }
    }
    ((words - 1).wrapping_sub(count as u32) % words) * 2
}
