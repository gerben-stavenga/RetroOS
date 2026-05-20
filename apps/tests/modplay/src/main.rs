//! `modplay` — ProTracker `.MOD` player, a 32-bit dosrt DOS payload
//! (replaces the C `sbtest` as the SB test).
//!
//! Stage #22b: 4-channel ProTracker software mixer. The whole module is
//! loaded flat into the payload's memory (no 64 KB model limit), parsed,
//! and rendered to unsigned-8 mono PCM by a minimal Amiga replayer. SB
//! auto-init DMA (#23) consumes `render()` from its IRQ refill, exactly
//! like sbtest's `fill()`. Until then `_start` renders a chunk and prints
//! a non-silence signature so the mixer is verifiable headless.

#![no_std]
#![no_main]

use dosrt::{dos, putc, puthex32, puthex8, puts};
use dosrt::io::{inb, outb};

/// Sound Blaster DSP (ports proven by the C `sbtest`; here from PM Rust).
mod sb {
    use super::{inb, outb};
    const RESET: u16 = 0x226;
    const READ: u16 = 0x22A;
    const WSTAT: u16 = 0x22C;
    const RSTAT: u16 = 0x22E;

    pub fn reset() -> bool {
        outb(RESET, 1);
        for _ in 0..1000 { inb(RESET); }
        outb(RESET, 0);
        for _ in 0..10000 {
            if inb(RSTAT) & 0x80 != 0 && inb(READ) == 0xAA {
                return true;
            }
        }
        false
    }
    pub fn write(v: u8) {
        while inb(WSTAT) & 0x80 != 0 {}
        outb(WSTAT, v);
    }
    pub fn set_rate(srate: u32) {
        write(0xD1);                              // speaker on
        let tc = (256u32 - 1_000_000 / srate) as u8;
        write(0x40);
        write(tc);
    }
}

/// Big enough for the largest MOD we expect to play (e.g.
/// `\games\fantasy\intro.mod` is ~247 KB). If a file gets truncated,
/// any sample whose data lives in the cut tail reads out of bounds
/// and its channel goes silent.
const FILEBUF_LEN: usize = 512 * 1024;
static mut FILEBUF: [u8; FILEBUF_LEN] = [0; FILEBUF_LEN];

/// Output rate (Hz). 22050 8-bit mono is within SB time-constant range.
const SRATE: u32 = 22050;
/// Amiga PAL: sample playback Hz = PAULA / period. PAULA ≈ 7093789.2/2.
const PAULA: u64 = 3_546_895;

fn be16(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 8) | b[o + 1] as u32
}

/// 31 sample headers (PCM is signed 8-bit, in file order after patterns).
#[derive(Clone, Copy)]
struct Smp {
    data: u32,       // offset into `raw_modfile` of this sample's PCM
    len: u32,        // bytes
    loop_start: u32, // bytes
    loop_len: u32,   // bytes (>2 ⇒ looped)
    vol: u8,         // 0..64
}

impl Smp {
    const EMPTY: Self = Self {
        data: 0, len: 0, loop_start: 0, loop_len: 0, vol: 0,
    };
}

/// A parsed ProTracker `.MOD` plus a reference to the raw file bytes
/// (the pattern data and the PCM sample data both live in there, accessed
/// by `Smp::data` offsets and `pat_base`-relative pattern offsets).
#[derive(Clone, Copy)]
struct Module {
    n_patterns: usize,
    song_len: usize,
    order: [u8; 128],
    pat_base: usize,                 // offset of pattern data in raw_modfile
    smp: [Smp; 31],
    raw_modfile: &'static [u8],      // the whole `.MOD` file
}

/// Per-channel playback state, carried across rows so a sample that's
/// already playing keeps playing on rows with no new note (period=0).
#[derive(Clone, Copy)]
struct ChannelState {
    smp: u8,         // 1..31, 0 = no sample assigned yet
    pos: u64,        // 32.16 fixed sample index
    step: u64,       // 32.16 fixed step per output sample (0 = stopped)
    vol: u8,         // 0..64
}

impl ChannelState {
    const EMPTY: Self = Self { smp: 0, pos: 0, step: 0, vol: 0 };
}

impl Module {
    const EMPTY: Self = Self {
        n_patterns: 0,
        song_len: 0,
        order: [0; 128],
        pat_base: 0,
        smp: [Smp::EMPTY; 31],
        raw_modfile: &[],
    };

    /// Render one row's audio (4 channels mixed) into `out` as signed
    /// 16-bit PCM (silence = 0). `row` is a linear row index across the
    /// song; it wraps at `song_len * 64`. `chans` carries each channel's
    /// playback state across rows — a row with period=0 leaves the
    /// channel sustaining its previous sample; period≠0 retriggers from
    /// the start.
    pub fn play_row(&self, row: usize, chans: &mut [ChannelState; 4],
                    out: &mut [i16]) {
        // Reset to silence; channels mix additively from here.
        for s in out.iter_mut() {
            *s = 0;
        }
        if self.song_len == 0 {
            return;
        }
        let order_idx = (row / 64) % self.song_len;
        let row_in_pat = row % 64;
        if order_idx >= 128 {
            return;
        }
        let pat = self.order[order_idx] as usize;
        let row_off = self.pat_base + pat * 1024 + row_in_pat * 16;

        // ── Decode this row's note triggers, update each channel's state.
        for c in 0..4 {
            let o = row_off + c * 4;
            if o + 4 > self.raw_modfile.len() {
                continue;
            }
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
                // PAULA / period = sample rate. step(16.16) = rate * 65536 / SRATE.
                chans[c].step = (PAULA << 16) / (period as u64 * SRATE as u64);
                chans[c].pos = 0;       // retrigger from sample start
            }
            // Effect 0x0C: set volume.
            if eff == 0x0C {
                chans[c].vol = par.min(64);
            }
        }

        // ── Mix every active channel into out.
        for c in 0..4 {
            if chans[c].smp == 0 || chans[c].step == 0 {
                continue;
            }
            let smp = self.smp[chans[c].smp as usize - 1];
            if smp.len == 0 {
                continue;
            }
            // Loops wrap at loop_start + loop_len (NOT at smp.len —
            // the unlooped tail past the loop is unused).
            let looped = smp.loop_len > 2;
            let end = if looped { smp.loop_start + smp.loop_len } else { smp.len };

            for s in out.iter_mut() {
                let mut idx = (chans[c].pos >> 16) as u32;
                if idx >= end {
                    if looped {
                        let wrap = (idx - smp.loop_start) % smp.loop_len;
                        idx = smp.loop_start + wrap;
                        chans[c].pos = ((idx as u64) << 16)
                            | (chans[c].pos & 0xFFFF);
                    } else {
                        // Non-looped sample finished — stop this channel.
                        // Leave `smp` set so next row's period≠0 retriggers.
                        chans[c].step = 0;
                        break;
                    }
                }
                let fi = smp.data as usize + idx as usize;
                if fi >= self.raw_modfile.len() {
                    chans[c].step = 0;
                    break;
                }
                let v = self.raw_modfile[fi] as i8 as i32;
                // ±128 * 0..64 = ±8192. Four channels max ±32768 → i16
                // fits exactly; saturating_add covers the boundary case.
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
        if o as usize + 1 > n_patterns {
            n_patterns = o as usize + 1;
        }
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
            data: data_off,
            len,
            loop_start: ls,
            loop_len: ll,
            vol: raw_modfile[h + 25].min(64),
        };
        data_off += len;
    }
    Some(Module { n_patterns, song_len, order, pat_base, smp, raw_modfile })
}

/// Default tempo: 125 BPM, speed 6 → 2646 samples per row at 22050 Hz.
const ROW_SAMPLES: usize = (SRATE as usize) * 5 * 6 / (125 * 2);

/// Streaming state.
///
/// `pcm_buffer[0..pcm_buffer_pos]` holds samples that have already been
/// mixed by previous `play_row` calls and are waiting to be drained
/// into DMA segments. `pcm_buffer_pos` is the position at which the
/// next `play_row` appends — everything before that index is "done"
/// mixing and just needs to be copied out.
///
/// Buffer sizing: a refill only fires when `pcm_buffer_pos < SEGSZ`,
/// so peak `pcm_buffer_pos` after a render is `(SEGSZ - 1) + ROW_SAMPLES`.
const PCM_BUFFER_SIZE: usize = ROW_SAMPLES + SEGSZ as usize;

struct Mixer {
    pcm_buffer: [i16; PCM_BUFFER_SIZE],
    pcm_buffer_pos: usize,
    row: usize,
    chans: [ChannelState; 4],
}

impl Mixer {
    const fn new() -> Self {
        Self {
            pcm_buffer: [0; PCM_BUFFER_SIZE],
            pcm_buffer_pos: 0,
            row: 0,
            chans: [ChannelState::EMPTY; 4],
        }
    }
}

// ---- SB auto-init DMA, IRQ-driven --------------------------------------

const NSAMP: usize = 4096;
const SEGSZ: u16 = 256;
const NSEG: usize = NSAMP / SEGSZ as usize;
const SB_IRQ: u8 = 7;
const SB_VEC: u8 = 0x0F; // master PIC IRQ7 default-mapped to INT 0x0F

/// All ISR↔mainloop sharing happens through these statics; the audio
/// functions themselves operate only on borrowed parameters.
static mut MODULE: Module = Module::EMPTY;
static mut MIXER: Mixer = Mixer::new();
static mut ISR_RING: *mut u8 = core::ptr::null_mut();
static mut ISR_NEXT_FILL: usize = 0;
static mut ISR_IRQS: u32 = 0;

/// Sample 8237 ch1 current count → which segment the DSP is replaying.
fn current_play_seg() -> usize {
    outb(0x0C, 0x00);
    let lo = inb(0x03) as u16;
    let hi = inb(0x03) as u16;
    let count = ((hi << 8) | lo) as usize;
    let play_idx = (NSAMP - 1).wrapping_sub(count) % NSAMP;
    play_idx / SEGSZ as usize
}

/// Fill `seg` (one DMA segment, u8 offset-binary).
///
/// First, top up `pcm_buffer` by appending `play_row` output until it
/// has at least `seg.len()` samples. Then copy those `seg.len()`
/// samples out (converting i16 → u8 offset binary) and slide the
/// remainder back to the front of `pcm_buffer`.
fn fill_segment(module: &Module, mix: &mut Mixer, seg: &mut [u8]) {
    while mix.pcm_buffer_pos < seg.len() {
        let dst = &mut mix.pcm_buffer
            [mix.pcm_buffer_pos..mix.pcm_buffer_pos + ROW_SAMPLES];
        module.play_row(mix.row, &mut mix.chans, dst);
        mix.row += 1;
        mix.pcm_buffer_pos += ROW_SAMPLES;
    }
    for i in 0..seg.len() {
        let v = mix.pcm_buffer[i];
        seg[i] = (((v >> 8) as i32) + 0x80) as u8;
    }
    mix.pcm_buffer.copy_within(seg.len()..mix.pcm_buffer_pos, 0);
    mix.pcm_buffer_pos -= seg.len();
}

/// Advance the DMA fill cursor `next_fill` until it reaches the current
/// playing segment, rendering fresh audio into the ring behind the DSP.
fn fill_ring_to(
    module: &Module, mix: &mut Mixer,
    ring: &mut [u8], next_fill: &mut usize, target: usize,
) {
    while *next_fill != target {
        let b = *next_fill * SEGSZ as usize;
        fill_segment(module, mix, &mut ring[b..b + SEGSZ as usize]);
        *next_fill = (*next_fill + 1) % NSEG;
    }
}

/// Rust body of the SB IRQ handler. Called from the asm shim with DS/ES
/// already loaded to our data selector.
///
/// Ack the SB DSP + vPIC FIRST so subsequent IRQs can flow even if the
/// fill work below panics or stalls; otherwise vpic.isr stays set and
/// the whole IRQ pipeline (including timer ticks) goes dark.
#[unsafe(no_mangle)]
unsafe extern "C" fn sb_isr_body() {
    inb(0x22E); // SB ack: read DSP status = ack 8-bit DMA IRQ
    outb(0x20, 0x20); // PIC master EOI
    unsafe {
        let n = core::ptr::read_volatile(core::ptr::addr_of!(ISR_IRQS));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_IRQS), n + 1);
    }

    let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
    let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
    let ring_ptr =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_RING)) };
    let ring = unsafe { core::slice::from_raw_parts_mut(ring_ptr, NSAMP) };
    let mut nf = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_NEXT_FILL)) };
    fill_ring_to(module, mix, ring, &mut nf, current_play_seg());
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_NEXT_FILL), nf) };
}

// Asm shim. PM HW-IRQ entry per DPMI: DS/ES undefined; SS:ESP is a
// host-provided locked stack. CS & DS share base in our flat setup, so
// `cs:[OUR_DS]` reads our captured data selector and we load DS/ES.
core::arch::global_asm!(
    ".section .text.sb_isr,\"ax\"",
    ".code32",
    ".globl sb_isr",
    "sb_isr:",
    "pushad",
    "push ds",
    "push es",
    "mov ax, cs:[OUR_DS]",
    "mov ds, ax",
    "mov es, ax",
    "call sb_isr_body",
    "pop es",
    "pop ds",
    "popad",
    "iretd",
);

unsafe extern "C" {
    fn sb_isr();
}

/// Entry: dosrt's crt0 set up the environment and reconstructed
/// `argc`/`argv` from the stub's Borland argv.
///
/// Usage: `MODPLAY [-p|poll] <mod>` — `-p`/`poll` selects the poll
/// driver (no IRQ install); default is IRQ-driven.
#[unsafe(no_mangle)]
pub fn app_main(argc: usize, argv: &[&[u8]]) {
    puts("\r\nmodplay: ");
    // Walk argv: first non-flag arg is the path; `-p`/`poll` selects poll.
    let mut poll_mode = false;
    let mut path_arg: &[u8] = b"";
    for i in 1..argc {
        let a = argv[i];
        if a == b"-p" || a == b"poll" {
            poll_mode = true;
        } else if path_arg.is_empty() {
            path_arg = a;
        }
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
    puts(if poll_mode { "[poll] " } else { "[irq] " });
    puts("file='");
    for &c in &path[..path.len() - 1] {
        putc(c);
    }
    puts("' ");
    let h = match dos::open(path) {
        Some(h) => h,
        None => {
            puts("open FAIL\r\n");
            dos::exit(1);
        }
    };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(FILEBUF) };
    let n = dos::read(h, buf);
    dos::close(h);

    // Parse and store the module in the static `MODULE` slot. The
    // module borrows FILEBUF (also static), so the lifetime is 'static.
    let raw_modfile: &'static [u8] = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(FILEBUF) as *const u8, n)
    };
    let parsed = match parse(raw_modfile) {
        Some(m) => m,
        None => {
            puts("parse FAIL\r\n");
            dos::exit(1);
        }
    };
    unsafe { MODULE = parsed; }
    puts("npat=");
    puthex8(parsed.n_patterns as u8);
    puts(" songlen=");
    puthex8(parsed.song_len as u8);

    // #23a: can the PM payload reach the SB hardware ports?
    puts(" sb=");
    if !sb::reset() {
        puts("FAIL\r\n");
        dos::exit(1);
    }
    puts("OK");
    sb::set_rate(SRATE);

    // Conventional auto-init DMA ring (8237 needs <1 MB physical).
    let seg = match dosrt::dpmi::alloc_dos_mem((NSAMP / 16) as u16) {
        Some((s, _)) => s,
        None => {
            puts(" ring FAIL\r\n");
            dos::exit(1);
        }
    };
    let ring = unsafe {
        core::slice::from_raw_parts_mut(dosrt::conv_flat_ptr(seg), NSAMP)
    };
    // Pre-fill the whole ring by treating it as 16 back-to-back DMA
    // segments. Same code path as the IRQ refill — Module/Mixer are
    // passed as borrows; the IRQ handler picks up where this leaves off
    // because Mixer is the same static instance.
    {
        let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
        let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
        for s in 0..NSEG {
            let b = s * SEGSZ as usize;
            fill_segment(module, mix, &mut ring[b..b + SEGSZ as usize]);
        }
    }

    // Hand `ring` to the ISR. `MODULE` and `MIXER` are already populated
    // (parse + pre-fill above) and the ISR reads them via those statics.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_RING),
            ring.as_mut_ptr());
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_NEXT_FILL), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ISR_IRQS), 0);
    }

    // Install the PM HW-IRQ handler (only in IRQ mode).
    let old_imr = inb(0x21);
    if !poll_mode {
        let cs: u16;
        unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs) };
        let isr_off = sb_isr as usize as u32;
        if let Err(e) = dosrt::dpmi::set_pm_int(SB_VEC, cs, isr_off) {
            puts(" set_pm_int FAIL=");
            puthex32(e as u32);
            dos::exit(1);
        }
        outb(0x21, old_imr & !(1u8 << SB_IRQ));   // unmask SB IRQ
    }

    // Program 8237 ch1 auto-init over the whole ring, then kick the DSP.
    let phys = (seg as u32) << 4;
    let off = (phys & 0xFFFF) as u16;
    let page = (phys >> 16) as u8;
    outb(0x0A, 0x05);                         // mask ch1
    outb(0x0C, 0x00);                         // clear flip-flop
    outb(0x0B, 0x59);                         // ch1 read, auto-init
    outb(0x02, (off & 0xFF) as u8);
    outb(0x02, (off >> 8) as u8);
    outb(0x83, page);
    outb(0x03, ((NSAMP - 1) & 0xFF) as u8);
    outb(0x03, (((NSAMP - 1) >> 8) & 0xFF) as u8);
    outb(0x0A, 0x01);                         // unmask ch1
    sb::write(0x48);                          // set block size = SEGSZ
    sb::write(((SEGSZ - 1) & 0xFF) as u8);
    sb::write(((SEGSZ - 1) >> 8) as u8);
    sb::write(0x1C);                          // 8-bit auto-init DMA start

    if poll_mode {
        // Poll the 8237 current count; whenever the DSP has moved into a
        // new segment, refill behind it. No IRQ handler is installed, so
        // SB IRQs are reflected through the default stub (harmless IRET).
        let module: &Module = unsafe { &*core::ptr::addr_of!(MODULE) };
        let mix: &mut Mixer = unsafe { &mut *core::ptr::addr_of_mut!(MIXER) };
        let mut next_fill: usize = 0;          // ring is fully primed
        loop {
            fill_ring_to(module, mix, ring, &mut next_fill, current_play_seg());
        }
    } else {
        // IRQ-driven: the host enters PM with IF=1 and IRQ delivery is
        // host-driven (real IRQ traps → kernel raise_pending), so we
        // don't sti/cli from user code. Just spin — the ISR owns refill.
        loop {
            unsafe { core::arch::asm!("pause") };
        }
    }

    // Cleanup: re-mask SB IRQ (if it was unmasked), stop the DSP, exit auto-init.
    if !poll_mode {
        outb(0x21, old_imr);
    }
    sb::write(0xD3);                          // speaker off
    sb::write(0xDA);                          // exit auto-init

    if !poll_mode {
        puts(" irqs=");
        let irqs = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ISR_IRQS)) };
        puthex32(irqs);
    }
    puts(" (song end)\r\n");
    // Return → dosrt's _start calls dos::exit(0).
}
// crt0 (_start) + panic handler are provided by the `dosrt` crate.
