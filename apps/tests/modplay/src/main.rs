//! `modplay` — ProTracker `.MOD` player, a 32-bit dosrt DOS payload
//! (replaces the C `sbtest` as the SB test).
//!
//! Architecture:
//! - The `Module` parser owns the raw `.MOD` and renders one row at a
//!   time. `play_row` ALWAYS produces stereo L/R (Amiga 4-ch pan:
//!   ch0+ch3 → L, ch1+ch2 → R); callers decide what to do with it.
//! - The `Sample` trait abstracts the on-wire DMA frame format. `Mono`
//!   sums L+R; `Stereo` keeps L/R separate. Each variant knows how to
//!   serialize itself for either 8-bit-unsigned or 16-bit-signed DMA.
//! - The `sb::SoundBlaster` struct parses a BLASTER-style string (port,
//!   IRQ, DMA channel) at `init`, then exposes higher-level operations
//!   (`set_rate`, `program_dma`, `start_playback`, `ack_irq`, etc.) so
//!   `app_main` doesn't carry the long `outb`/`sb_write` chains.

#![no_std]
#![no_main]

use dosrt::{dos, putc, puthex32, puthex8, puts};
use dosrt::io::{inb, outb};

mod sb {
    use super::{inb, outb};

    /// Parse a BLASTER env-style string ("A220 I7 D1 H5 T6") into the
    /// pieces we care about. `A`=DSP base (hex), `I`=IRQ (dec), `D`=8-bit
    /// DMA channel (dec), `H`=16-bit DMA channel (dec). Missing keys
    /// keep the default. Tolerant of arbitrary whitespace; ignores `T`.
    fn parse_num(s: &[u8], hex: bool) -> (u32, usize) {
        let mut v = 0u32;
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            let d = if c.is_ascii_digit() { (c - b'0') as u32 }
                    else if hex && (b'A'..=b'F').contains(&c) { 10 + (c - b'A') as u32 }
                    else if hex && (b'a'..=b'f').contains(&c) { 10 + (c - b'a') as u32 }
                    else { break };
            v = v * if hex { 16 } else { 10 } + d;
            i += 1;
        }
        (v, i)
    }

    pub struct SoundBlaster {
        pub port: u16,
        pub irq: u8,
        pub dma_ch: u8,         // 0..3 = master 8237, 4..7 = slave (16-bit)
        pub bit16: bool,
        pub stereo: bool,
    }

    impl SoundBlaster {
        pub const EMPTY: Self = Self {
            port: 0x220, irq: 7, dma_ch: 1, bit16: false, stereo: false,
        };

        /// Parse `blaster_str` for port/IRQ/DMA, reset the DSP, check that
        /// 16-bit / stereo requests have an SB16. Returns `None` on a DSP
        /// reset failure or insufficient SB version.
        pub fn init(blaster_str: &[u8], bit16: bool, stereo: bool) -> Option<Self> {
            let mut port = 0x220u16;
            let mut irq = 7u8;
            let mut dma8 = 1u8;
            let mut dma16 = 5u8;
            let mut i = 0;
            while i < blaster_str.len() {
                while i < blaster_str.len()
                    && (blaster_str[i] == b' ' || blaster_str[i] == b'\t') { i += 1; }
                if i >= blaster_str.len() { break; }
                let key = blaster_str[i].to_ascii_uppercase();
                i += 1;
                let (val, n) = parse_num(&blaster_str[i..], key == b'A');
                i += n;
                match key {
                    b'A' => port = val as u16,
                    b'I' => irq = val as u8,
                    b'D' => dma8 = val as u8,
                    b'H' => dma16 = val as u8,
                    _ => {}                       // ignore T, P, ...
                }
            }
            let dma_ch = if bit16 { dma16 } else { dma8 };
            let sb = Self { port, irq, dma_ch, bit16, stereo };
            if !sb.dsp_reset() { return None; }
            let (vmaj, _) = sb.version();
            if (bit16 || stereo) && vmaj < 4 { return None; }
            Some(sb)
        }

        // ── Format-derived sizes used by callers ──────────────────────────
        pub const fn channels(&self) -> usize { if self.stereo { 2 } else { 1 } }
        pub const fn sample_bytes(&self) -> usize { if self.bit16 { 2 } else { 1 } }
        pub const fn frame_bytes(&self) -> usize { self.channels() * self.sample_bytes() }
        /// PM IDT vector that the SB IRQ raises. IRQ 0..7 → vector 0x08+IRQ
        /// (master PIC default-mapped); IRQ 8..15 → 0x70+(IRQ-8) (slave).
        pub const fn irq_vector(&self) -> u8 {
            if self.irq < 8 { 0x08 + self.irq } else { 0x70 + (self.irq - 8) }
        }

        // ── Raw DSP I/O ───────────────────────────────────────────────────
        fn dsp_reset(&self) -> bool {
            outb(self.port + 0x6, 1);
            for _ in 0..1000 { inb(self.port + 0x6); }
            outb(self.port + 0x6, 0);
            for _ in 0..10000 {
                if inb(self.port + 0xE) & 0x80 != 0 && inb(self.port + 0xA) == 0xAA {
                    return true;
                }
            }
            false
        }
        fn write_dsp(&self, v: u8) {
            while inb(self.port + 0xC) & 0x80 != 0 {}
            outb(self.port + 0xC, v);
        }
        fn read_dsp(&self) -> u8 {
            while inb(self.port + 0xE) & 0x80 == 0 {}
            inb(self.port + 0xA)
        }
        /// DSP cmd 0xE1: DSP version. (Major, minor). SB16 has major ≥ 4.
        pub fn version(&self) -> (u8, u8) {
            self.write_dsp(0xE1);
            (self.read_dsp(), self.read_dsp())
        }
        /// Speaker on, set output rate. SB16 uses 0x41 (hi/lo); pre-SB16
        /// 8-bit uses 0x40 (time constant). Both reach via this one method.
        pub fn set_rate(&self, srate: u32) {
            self.write_dsp(0xD1);
            if self.bit16 {
                self.write_dsp(0x41);
                self.write_dsp((srate >> 8) as u8);
                self.write_dsp(srate as u8);
            } else {
                let tc = (256u32 - 1_000_000 / srate) as u8;
                self.write_dsp(0x40);
                self.write_dsp(tc);
            }
        }
        /// Kick off auto-init DMA playback. `block_transfers` = the IRQ
        /// pacing (one IRQ per N 8237 transfers). Three command flavours:
        /// 16-bit → 0xB6, mode 0x10/0x30. 8-bit stereo → 0xC6 mode 0x20.
        /// 8-bit mono → 0x48 (block size) + 0x1C (legacy start).
        pub fn start_playback(&self, block_transfers: usize) {
            let block = (block_transfers - 1) as u16;
            match (self.bit16, self.stereo) {
                (true, _) => {
                    self.write_dsp(0xB6);
                    self.write_dsp(if self.stereo { 0x30 } else { 0x10 });
                    self.write_dsp(block as u8);
                    self.write_dsp((block >> 8) as u8);
                }
                (false, true) => {
                    self.write_dsp(0xC6);
                    self.write_dsp(0x20);     // unsigned stereo
                    self.write_dsp(block as u8);
                    self.write_dsp((block >> 8) as u8);
                }
                (false, false) => {
                    self.write_dsp(0x48);
                    self.write_dsp(block as u8);
                    self.write_dsp((block >> 8) as u8);
                    self.write_dsp(0x1C);
                }
            }
        }
        pub fn stop_playback(&self) {
            self.write_dsp(if self.bit16 { 0xD9 } else { 0xDA });
            self.write_dsp(0xD3);              // speaker off
        }
        /// IRQ-ack: read the DSP IRQ-status register (16-bit DMA IRQs need
        /// 0x22F instead of the 0x22E that 8-bit IRQs use on SB16).
        pub fn ack_irq(&self) {
            inb(self.port + if self.bit16 { 0xF } else { 0xE });
        }

        // ── 8237 DMA ──────────────────────────────────────────────────────
        /// Ports/state derived from the channel number. Master 8237 (ch<4)
        /// has byte-granular address/count; slave 8237 (ch≥4) counts words.
        fn dma_regs(&self) -> (u16, u16, u16, u16, u16, u16, u8) {
            // Page register lookup: per-channel, master+slave merged.
            const PAGE: [u16; 8] = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];
            let ch = self.dma_ch;
            let local = (ch & 3) as u16;
            if ch >= 4 {
                // slave (16-bit): addr 0xC0+local*4, count 0xC2+local*4
                (0xC0 + local * 4, 0xC2 + local * 4, PAGE[ch as usize],
                 0xD4, 0xD6, 0xD8, ch & 3)
            } else {
                // master (8-bit): addr local*2, count local*2+1
                (local * 2, local * 2 + 1, PAGE[ch as usize],
                 0x0A, 0x0B, 0x0C, ch & 3)
            }
        }
        /// Program our 8237 channel for auto-init read of `n_transfers`
        /// units (bytes for 8-bit, words for 16-bit) from physical `phys`.
        pub fn program_dma(&self, phys: u32, n_transfers: usize) {
            let (addr, count, page, mask, mode, clear_ff, slot) = self.dma_regs();
            let word_addr = self.dma_ch >= 4;
            let addr_val = if word_addr { (phys >> 1) as u16 } else { phys as u16 };
            let page_val = (phys >> 16) as u8;
            let n = (n_transfers - 1) as u16;
            outb(mask, 0x04 | slot);              // mask
            outb(clear_ff, 0x00);
            outb(mode, 0x40 | 0x10 | 0x08 | slot); // auto-init, single, read
            outb(addr, addr_val as u8);
            outb(addr, (addr_val >> 8) as u8);
            outb(page, page_val);
            outb(count, n as u8);
            outb(count, (n >> 8) as u8);
            outb(mask, slot);                     // unmask
        }
        /// Current down-count of our 8237 channel (in transfer units).
        pub fn read_dma_count(&self) -> u16 {
            let (_, count, _, _, _, clear_ff, _) = self.dma_regs();
            outb(clear_ff, 0x00);
            let lo = inb(count) as u16;
            let hi = inb(count) as u16;
            (hi << 8) | lo
        }
    }
}

// ============================================================================
// `Sample` trait + concrete on-wire DMA frame types.
//
// Each Sample IS the literal byte layout the DSP/DMA consumes — the DMA
// ring is `[S]`, and `pcm[i] = S::from(left, right)` writes the correct
// bytes directly. `#[repr(C)]` / `#[repr(transparent)]` pins the layout.
//
//   Mono8    : 1 byte  unsigned          (DSP cmd 0x1C / 0xC6 mode 0x00)
//   Stereo8  : 2 bytes unsigned L,R      (DSP cmd 0xC6 mode 0x20)
//   Mono16   : 1 i16   signed LE         (DSP cmd 0xB6 mode 0x10)
//   Stereo16 : 2 i16   signed LE L,R     (DSP cmd 0xB6 mode 0x30)
//
// The mod renderer always produces stereo L/R i16; `from(left, right)`
// folds that into the right wire format (mono = L+R; stereo = identity).
// ============================================================================

trait Sample: Copy + Default {
    fn from(left: i16, right: i16) -> Self;
}

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
struct Mono8(u8);

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Stereo8 { l: u8, r: u8 }

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
struct Mono16(i16);

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Stereo16 { l: i16, r: i16 }

/// 16-bit signed i16 → 8-bit unsigned: drop the low byte, bias to 0x80.
#[inline(always)] fn to_u8(v: i16) -> u8 { (((v >> 8) as i32) + 0x80) as u8 }

impl Sample for Mono8 {
    fn from(l: i16, r: i16) -> Self { Mono8(to_u8(l.saturating_add(r))) }
}
impl Sample for Stereo8 {
    fn from(l: i16, r: i16) -> Self { Stereo8 { l: to_u8(l), r: to_u8(r) } }
}
impl Sample for Mono16 {
    fn from(l: i16, r: i16) -> Self { Mono16(l.saturating_add(r)) }
}
impl Sample for Stereo16 {
    fn from(l: i16, r: i16) -> Self { Stereo16 { l, r } }
}

// ============================================================================
// MOD parser + per-row renderer (always stereo L/R out).
// ============================================================================

/// Big enough for the largest MOD we expect to play (e.g.
/// `\games\fantasy\intro.mod` is ~247 KB).
const FILEBUF_LEN: usize = 512 * 1024;
static mut FILEBUF: [u8; FILEBUF_LEN] = [0; FILEBUF_LEN];

/// Output rate (Hz). 22050 8-bit mono is within SB time-constant range.
const SRATE: u32 = 22050;
/// Amiga PAL: sample playback Hz = PAULA / period. PAULA ≈ 7093789.2/2.
const PAULA: u64 = 3_546_895;

fn be16(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 8) | b[o + 1] as u32
}

#[derive(Clone, Copy)]
struct Smp {
    data: u32, len: u32, loop_start: u32, loop_len: u32, vol: u8,
}
impl Smp {
    const EMPTY: Self = Self { data: 0, len: 0, loop_start: 0, loop_len: 0, vol: 0 };
}

#[derive(Clone, Copy)]
struct Module {
    n_patterns: usize,
    song_len: usize,
    order: [u8; 128],
    pat_base: usize,
    smp: [Smp; 31],
    raw_modfile: &'static [u8],
}

#[derive(Clone, Copy)]
struct ChannelState { smp: u8, pos: u64, step: u64, vol: u8 }
impl ChannelState {
    const EMPTY: Self = Self { smp: 0, pos: 0, step: 0, vol: 0 };
}

impl Module {
    const EMPTY: Self = Self {
        n_patterns: 0, song_len: 0, order: [0; 128],
        pat_base: 0, smp: [Smp::EMPTY; 31], raw_modfile: &[],
    };

    /// Render one row's audio. Always produces stereo L/R via Amiga hard
    /// pan (ch0+ch3 → left, ch1+ch2 → right). `left.len() == right.len()`
    /// = number of output frames; samples mix additively.
    pub fn play_row(&self, row: usize, chans: &mut [ChannelState; 4],
                    left: &mut [i16], right: &mut [i16]) {
        for s in left.iter_mut() { *s = 0; }
        for s in right.iter_mut() { *s = 0; }
        if self.song_len == 0 { return; }

        let order_idx = (row / 64) % self.song_len;
        let row_in_pat = row % 64;
        if order_idx >= 128 { return; }
        let pat = self.order[order_idx] as usize;
        let row_off = self.pat_base + pat * 1024 + row_in_pat * 16;

        // ── Decode this row's note triggers, update channel state.
        for c in 0..4 {
            let o = row_off + c * 4;
            if o + 4 > self.raw_modfile.len() { continue; }
            let b0 = self.raw_modfile[o];
            let b1 = self.raw_modfile[o + 1];
            let b2 = self.raw_modfile[o + 2];
            let b3 = self.raw_modfile[o + 3];
            let period = (((b0 & 0x0F) as u16) << 8) | b1 as u16;
            let sample = (b0 & 0xF0) | (b2 >> 4);
            let eff = b2 & 0x0F;
            let par = b3;

            if sample != 0 && (sample as usize) <= 31 {
                chans[c].smp = sample;
                chans[c].vol = self.smp[sample as usize - 1].vol;
            }
            if period != 0 {
                chans[c].step = (PAULA << 16) / (period as u64 * SRATE as u64);
                chans[c].pos = 0;
            }
            if eff == 0x0C { chans[c].vol = par.min(64); }
        }

        // ── Mix each active channel into its L/R lane.
        for c in 0..4 {
            if chans[c].smp == 0 || chans[c].step == 0 { continue; }
            let smp = self.smp[chans[c].smp as usize - 1];
            if smp.len == 0 { continue; }
            let looped = smp.loop_len > 2;
            let end = if looped { smp.loop_start + smp.loop_len } else { smp.len };
            // Amiga panning: ch0,3 → left; ch1,2 → right.
            let target: &mut [i16] = if c == 0 || c == 3 { left } else { right };

            for s in target.iter_mut() {
                let mut idx = (chans[c].pos >> 16) as u32;
                if idx >= end {
                    if looped {
                        let wrap = (idx - smp.loop_start) % smp.loop_len;
                        idx = smp.loop_start + wrap;
                        chans[c].pos = ((idx as u64) << 16)
                            | (chans[c].pos & 0xFFFF);
                    } else {
                        chans[c].step = 0;
                        break;
                    }
                }
                let fi = smp.data as usize + idx as usize;
                if fi >= self.raw_modfile.len() { chans[c].step = 0; break; }
                let v = self.raw_modfile[fi] as i8 as i32;
                let scaled = v * chans[c].vol as i32;
                *s = (*s).saturating_add(scaled as i16);
                chans[c].pos += chans[c].step;
            }
        }
    }
}

fn parse(raw_modfile: &'static [u8]) -> Option<Module> {
    if raw_modfile.len() < 1084 || &raw_modfile[1080..1084] != b"M.K." {
        return None;
    }
    let song_len = raw_modfile[950] as usize;
    let mut order = [0u8; 128];
    order.copy_from_slice(&raw_modfile[952..1080]);
    let mut n_patterns = 0usize;
    for &o in &order[..song_len] {
        if o as usize + 1 > n_patterns { n_patterns = o as usize + 1; }
    }
    let pat_base = 1084;
    let mut data_off = (pat_base + n_patterns * 1024) as u32;
    let mut smp = [Smp::EMPTY; 31];
    for i in 0..31 {
        let h = 20 + i * 30;
        let len = be16(raw_modfile, h + 22) * 2;
        let ls = be16(raw_modfile, h + 26) * 2;
        let ll = be16(raw_modfile, h + 28) * 2;
        smp[i] = Smp {
            data: data_off, len, loop_start: ls, loop_len: ll,
            vol: raw_modfile[h + 25].min(64),
        };
        data_off += len;
    }
    Some(Module { n_patterns, song_len, order, pat_base, smp, raw_modfile })
}

/// Default tempo: 125 BPM, speed 6 → 2646 samples per row at 22050 Hz.
const ROW_SAMPLES: usize = (SRATE as usize) * 5 * 6 / (125 * 2);

/// Streaming state. `pcm_buffer_pos` is the number of rendered (but
/// not-yet-DMA-consumed) frames pending in `left[0..pos]`/`right[0..pos]`.
const PCM_BUFFER_FRAMES: usize = ROW_SAMPLES + SEGSZ as usize;

struct Mixer {
    left: [i16; PCM_BUFFER_FRAMES],
    right: [i16; PCM_BUFFER_FRAMES],
    pcm_buffer_pos: usize,
    row: usize,
    chans: [ChannelState; 4],
}

impl Mixer {
    const fn new() -> Self {
        Self {
            left: [0; PCM_BUFFER_FRAMES],
            right: [0; PCM_BUFFER_FRAMES],
            pcm_buffer_pos: 0,
            row: 0,
            chans: [ChannelState::EMPTY; 4],
        }
    }
}

// ============================================================================
// DMA ring + fill loop. Generic over `Sample`.
// ============================================================================

const NSAMP: usize = 4096;
const SEGSZ: u16 = 256;
const NSEG: usize = NSAMP / SEGSZ as usize;

/// Global SB instance (populated by `app_main`). The ISR reads it.
static mut SB: sb::SoundBlaster = sb::SoundBlaster::EMPTY;
/// Shared ISR↔main state. Audio functions take borrows; the statics are
/// the rendezvous. The ring base pointer is type-erased; the ISR re-casts
/// to `*mut S` for the active Sample type via the 2×2 dispatch grid.
static mut MODULE: Module = Module::EMPTY;
static mut MIXER: Mixer = Mixer::new();
static mut ISR_RING: *mut u8 = core::ptr::null_mut();
static mut ISR_IRQS: u32 = 0;
/// Bottom-half flag: the ISR sets it, the main loop watches+clears it and
/// then does the refill in task context (poll-bool mode).
static mut IRQ_PENDING: bool = false;
/// When true, the ISR does the full refill itself (irq-mix mode); the
/// `next_fill` cursor then has to be ISR-owned static state.
static mut ISR_DOES_MIX: bool = false;
static mut ISR_NEXT_FILL: usize = 0;

/// Reinterpret the type-erased ring as a typed sample slice.
#[inline] unsafe fn ring_as<S: Sample>() -> &'static mut [S] {
    let p = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_RING)) };
    unsafe { core::slice::from_raw_parts_mut(p as *mut S, NSAMP) }
}

/// Convert the 8237's current down-count to a segment index.
fn current_play_seg(sb: &sb::SoundBlaster) -> usize {
    let total = NSAMP * sb.channels();
    let count = sb.read_dma_count() as usize;
    let played = (total - 1).wrapping_sub(count) % total;
    (played / sb.channels()) / SEGSZ as usize
}

/// Top up the L/R mixer until it has at least `seg.len()` frames of
/// pending audio, then write `seg[i] = S::from(left[i], right[i])`, then
/// shift the rest forward.
fn fill_segment<S: Sample>(
    module: &Module, mix: &mut Mixer, seg: &mut [S],
) {
    let n_frames = seg.len();
    while mix.pcm_buffer_pos < n_frames {
        let lo = mix.pcm_buffer_pos;
        let hi = lo + ROW_SAMPLES;
        module.play_row(mix.row, &mut mix.chans,
                        &mut mix.left[lo..hi], &mut mix.right[lo..hi]);
        mix.row += 1;
        mix.pcm_buffer_pos += ROW_SAMPLES;
    }
    for i in 0..n_frames {
        seg[i] = S::from(mix.left[i], mix.right[i]);
    }
    // Shift the unconsumed tail of left/right to the front. A
    // bounds-checked indexed loop — `copy_within` empirically miscompiles
    // here (stale `pcm_buffer_pos` spill); see feedback_copy_within_alloc_bug.
    let keep = mix.pcm_buffer_pos - n_frames;
    for i in 0..keep {
        mix.left[i] = mix.left[i + n_frames];
        mix.right[i] = mix.right[i + n_frames];
    }
    mix.pcm_buffer_pos = keep;
}

/// Render segments `*next_fill..target` (wrapping), advancing `next_fill`.
fn fill_ring_to<S: Sample>(
    module: &Module, mix: &mut Mixer, ring: &mut [S],
    next_fill: &mut usize, target: usize,
) {
    while *next_fill != target {
        let b = *next_fill * SEGSZ as usize;
        fill_segment::<S>(module, mix, &mut ring[b..b + SEGSZ as usize]);
        *next_fill = (*next_fill + 1) % NSEG;
    }
}

/// SB IRQ handler. Always: ack the SB, EOI the PIC, bump the counter.
/// Then either (irq-mix mode) do the whole refill here in interrupt
/// context, or (poll-bool mode) just raise `IRQ_PENDING` for the main
/// loop to pick up. The 3-way comparison — poll-dma / poll-bool / irq-mix
/// — exists to pin down whether the refill misbehaves *because* it runs
/// in interrupt context.
unsafe extern "C" fn sb_isr_body() {
    let sb = unsafe { &*core::ptr::addr_of!(SB) };
    sb.ack_irq();
    outb(0x20, 0x20);                              // PIC master EOI
    unsafe {
        let n = core::ptr::read_volatile(core::ptr::addr_of!(ISR_IRQS));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_IRQS), n + 1);
    }
    if !unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_DOES_MIX)) } {
        // poll-bool: defer the refill to the main loop.
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(IRQ_PENDING), true) };
        return;
    }
    // irq-mix: full refill in interrupt context.
    let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
    let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
    let mut nf = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_NEXT_FILL)) };
    let target = current_play_seg(sb);
    match (sb.bit16, sb.stereo) {
        (false, false) => fill_ring_to::<Mono8>(module, mix, unsafe { ring_as::<Mono8>() }, &mut nf, target),
        (false, true)  => fill_ring_to::<Stereo8>(module, mix, unsafe { ring_as::<Stereo8>() }, &mut nf, target),
        (true,  false) => fill_ring_to::<Mono16>(module, mix, unsafe { ring_as::<Mono16>() }, &mut nf, target),
        (true,  true)  => fill_ring_to::<Stereo16>(module, mix, unsafe { ring_as::<Stereo16>() }, &mut nf, target),
    }
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_NEXT_FILL), nf) };
}

/// Hardcoded for now; once `dosrt::env_get(b"BLASTER")` lands we read the
/// real value from PSP[0x2C]:0.
const BLASTER_STR: &[u8] = b"A220 I7 D1 H5 T6";

#[unsafe(no_mangle)]
pub fn app_main(argc: usize, argv: &[&[u8]]) {
    puts("\r\nmodplay: ");
    // Refill mode: `-p` poll the DMA count; `-i` refill inside the ISR;
    // default = poll-bool (ISR raises a flag, main loop refills).
    let mut poll_mode = false;
    let mut irq_mix = false;
    let mut bit16_mode = false;
    let mut stereo_mode = false;
    let mut path_arg: &[u8] = b"";
    for i in 1..argc {
        let a = argv[i];
        if a == b"-p" || a == b"poll" { poll_mode = true; }
        else if a == b"-i" || a == b"irq" { irq_mix = true; }
        else if a == b"-16" { bit16_mode = true; }
        else if a == b"-s" || a == b"stereo" { stereo_mode = true; }
        else if path_arg.is_empty() { path_arg = a; }
    }
    static mut PATHBUF: [u8; 128] = [0; 128];
    let pb = unsafe { &mut *core::ptr::addr_of_mut!(PATHBUF) };
    let plen = if !path_arg.is_empty() {
        let n = path_arg.len().min(pb.len() - 1);
        pb[..n].copy_from_slice(&path_arg[..n]);
        pb[n] = 0;
        n + 1
    } else {
        const DEFAULT: &[u8] = b"\\games\\fantasy\\intro.mod\0";
        pb[..DEFAULT.len()].copy_from_slice(DEFAULT);
        DEFAULT.len()
    };
    let path: &[u8] = &pb[..plen];
    puts(if poll_mode { "[poll-dma] " }
         else if irq_mix { "[irq-mix] " }
         else { "[poll-bool] " });
    puts(if bit16_mode { "[16-bit] " } else { "[8-bit] " });
    puts(if stereo_mode { "[stereo] " } else { "[mono] " });
    puts("file='");
    for &c in &path[..path.len() - 1] { putc(c); }
    puts("' ");

    let h = match dos::open(path) {
        Some(h) => h,
        None => { puts("open FAIL\r\n"); dos::exit(1); }
    };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(FILEBUF) };
    let n = dos::read(h, buf);
    dos::close(h);

    let raw_modfile: &'static [u8] = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(FILEBUF) as *const u8, n)
    };
    let parsed = match parse(raw_modfile) {
        Some(m) => m,
        None => { puts("parse FAIL\r\n"); dos::exit(1); }
    };
    unsafe { MODULE = parsed; }
    puts("npat=");
    puthex8(parsed.n_patterns as u8);
    puts(" songlen=");
    puthex8(parsed.song_len as u8);

    let sb = match sb::SoundBlaster::init(BLASTER_STR, bit16_mode, stereo_mode) {
        Some(sb) => sb,
        None => { puts(" sb init FAIL\r\n"); dos::exit(1); }
    };
    puts(" sbport=");
    puthex32(sb.port as u32);
    puts(" irq=");
    puthex8(sb.irq);
    puts(" dma=");
    puthex8(sb.dma_ch);
    let (vmaj, vmin) = sb.version();
    puts(" sbv=");
    puthex8(vmaj);
    putc(b'.');
    puthex8(vmin);
    sb.set_rate(SRATE);
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SB), sb); }
    // From now on we'll read SB via a borrow of the static.
    let sb: &sb::SoundBlaster = unsafe { &*core::ptr::addr_of!(SB) };

    // Conventional auto-init DMA ring (8237 needs <1 MB physical).
    let ring_bytes = NSAMP * sb.frame_bytes();
    let seg = match dosrt::dpmi::alloc_dos_mem((ring_bytes / 16) as u16) {
        Some((s, _)) => s,
        None => { puts(" ring FAIL\r\n"); dos::exit(1); }
    };
    // Type-erased ring base; we re-cast to `[S]` for the active sample type.
    let ring_ptr = dosrt::conv_flat_ptr(seg);
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_RING), ring_ptr);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_IRQS), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IRQ_PENDING), false);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_NEXT_FILL), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_DOES_MIX), irq_mix);
    }
    // Pre-fill the whole ring as `NSEG` back-to-back segments. One match
    // picks the right Sample type for the entire bring-up.
    {
        let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
        let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
        fn prime<S: Sample>(module: &Module, mix: &mut Mixer, ring: &mut [S]) {
            for s in 0..NSEG {
                let b = s * SEGSZ as usize;
                fill_segment::<S>(module, mix, &mut ring[b..b + SEGSZ as usize]);
            }
        }
        match (sb.bit16, sb.stereo) {
            (false, false) => prime::<Mono8>(module, mix, unsafe { ring_as::<Mono8>() }),
            (false, true)  => prime::<Stereo8>(module, mix, unsafe { ring_as::<Stereo8>() }),
            (true,  false) => prime::<Mono16>(module, mix, unsafe { ring_as::<Mono16>() }),
            (true,  true)  => prime::<Stereo16>(module, mix, unsafe { ring_as::<Stereo16>() }),
        }
    }

    // Install the PM HW-IRQ handler — needed by poll-bool and irq-mix,
    // not by poll-dma (which never looks at the IRQ).
    let old_imr = inb(0x21);
    if !poll_mode {
        if let Err(e) = dosrt::dpmi::install_handler(sb.irq_vector(), sb_isr_body) {
            puts(" set_pm_int FAIL=");
            puthex32(e as u32);
            dos::exit(1);
        }
        outb(0x21, old_imr & !(1u8 << sb.irq));   // unmask SB IRQ
    }

    // Program 8237 + kick the DSP. Counter unit matches transfer size, so
    // total transfers = NSAMP * channels and block (per-IRQ) = SEGSZ * ch.
    let dma_transfers = NSAMP * sb.channels();
    let seg_transfers = SEGSZ as usize * sb.channels();
    let phys = (seg as u32) << 4;
    sb.program_dma(phys, dma_transfers);
    sb.start_playback(seg_transfers);

    // irq-mix: the ISR owns the refill — the main task just idles.
    if irq_mix {
        loop { unsafe { core::arch::asm!("pause") }; }
    }

    // poll-dma / poll-bool: the refill runs here in task context.
    // poll-dma refills continuously; poll-bool waits for the ISR's
    // `IRQ_PENDING` flag before each refill.
    let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
    let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
    let mut next_fill: usize = 0;
    loop {
        if !poll_mode {
            while !unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IRQ_PENDING)) } {}
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(IRQ_PENDING), false) };
        }
        let target = current_play_seg(sb);
        match (sb.bit16, sb.stereo) {
            (false, false) => fill_ring_to::<Mono8>(module, mix, unsafe { ring_as::<Mono8>() }, &mut next_fill, target),
            (false, true)  => fill_ring_to::<Stereo8>(module, mix, unsafe { ring_as::<Stereo8>() }, &mut next_fill, target),
            (true,  false) => fill_ring_to::<Mono16>(module, mix, unsafe { ring_as::<Mono16>() }, &mut next_fill, target),
            (true,  true)  => fill_ring_to::<Stereo16>(module, mix, unsafe { ring_as::<Stereo16>() }, &mut next_fill, target),
        }
    }

    #[allow(unreachable_code)]
    {
        if !poll_mode {
            outb(0x21, old_imr);
        }
        sb.stop_playback();
        if !poll_mode {
            puts(" irqs=");
            let irqs = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_IRQS)) };
            puthex32(irqs);
        }
        puts(" (song end)\r\n");
    }
}
// crt0 (_start) + panic handler are provided by the `dosrt` crate.
