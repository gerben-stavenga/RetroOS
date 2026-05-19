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

const FILEBUF_LEN: usize = 96 * 1024;
static mut FILEBUF: [u8; FILEBUF_LEN] = [0; FILEBUF_LEN];

/// Output rate (Hz). 22050 8-bit mono is within SB time-constant range.
const SRATE: u32 = 22050;
/// Amiga PAL: sample playback Hz = PAULA / period. PAULA ≈ 7093789.2/2.
const PAULA: u64 = 3_546_895;

fn be16(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 8) | b[o + 1] as u32
}

/// 31 sample headers (PCM is signed 8-bit, in file order after patterns).
#[derive(Clone, Copy, Default)]
struct Smp {
    data: u32,       // file offset of PCM
    len: u32,        // bytes
    loop_start: u32, // bytes
    loop_len: u32,   // bytes (>2 ⇒ looped)
    vol: u8,         // 0..64
}

struct Module {
    n_patterns: usize,
    song_len: usize,
    order: [u8; 128],
    pat_base: usize, // file offset of pattern data
    smp: [Smp; 31],
}

fn parse(buf: &[u8]) -> Option<Module> {
    if buf.len() < 1084 || &buf[1080..1084] != b"M.K." {
        return None;
    }
    let song_len = buf[950] as usize;
    let mut order = [0u8; 128];
    order.copy_from_slice(&buf[952..1080]);
    let mut n_patterns = 0usize;
    for &o in &order[..song_len] {
        if o as usize + 1 > n_patterns {
            n_patterns = o as usize + 1;
        }
    }
    let pat_base = 1084;
    let mut data_off = (pat_base + n_patterns * 1024) as u32;
    let mut smp = [Smp::default(); 31];
    for i in 0..31 {
        let h = 20 + i * 30;
        let len = be16(buf, h + 22) * 2;
        let ls = be16(buf, h + 26) * 2;
        let ll = be16(buf, h + 28) * 2;
        smp[i] = Smp {
            data: data_off,
            len,
            loop_start: ls,
            loop_len: ll,
            vol: buf[h + 25].min(64),
        };
        data_off += len;
    }
    Some(Module { n_patterns, song_len, order, pat_base, smp })
}

#[derive(Clone, Copy, Default)]
struct Chan {
    smp: u8,    // 1..31, 0 = none
    period: u16,
    vol: u8,    // 0..64
    pos: u64,   // 32.16 fixed sample index
    step: u64,  // 32.16 increment per output sample
    active: bool,
}

struct Player<'a> {
    m: &'a Module,
    buf: &'a [u8],
    ch: [Chan; 4],
    order_idx: usize,
    row: usize,
    tick: u32,
    speed: u32,            // ticks per row (default 6)
    samp_per_tick: u32,    // SRATE*5/(BPM*2), BPM default 125
    samp_left: u32,        // countdown to next tick
    ended: bool,
}

fn step_for(period: u16) -> u64 {
    if period == 0 {
        return 0;
    }
    // play_hz = PAULA / period ; step(16.16) = play_hz * 65536 / SRATE
    (PAULA << 16) / (period as u64 * SRATE as u64)
}

impl<'a> Player<'a> {
    fn new(m: &'a Module, buf: &'a [u8]) -> Self {
        Player {
            m,
            buf,
            ch: [Chan::default(); 4],
            order_idx: 0,
            row: 0,
            tick: 0,
            speed: 6,
            samp_per_tick: SRATE * 5 / (125 * 2),
            samp_left: 0,
            ended: false,
        }
    }

    /// Process one tracker row (called on tick 0).
    fn do_row(&mut self) {
        let pat = self.m.order[self.order_idx] as usize;
        let row_off = self.m.pat_base + pat * 1024 + self.row * 16;
        let mut brk: Option<usize> = None;
        let mut jmp: Option<usize> = None;
        for c in 0..4 {
            let o = row_off + c * 4;
            if o + 4 > self.buf.len() {
                continue;
            }
            let b0 = self.buf[o];
            let b1 = self.buf[o + 1];
            let b2 = self.buf[o + 2];
            let b3 = self.buf[o + 3];
            let period = (((b0 & 0x0F) as u16) << 8) | b1 as u16;
            let sample = (b0 & 0xF0) | (b2 >> 4);
            let eff = b2 & 0x0F;
            let par = b3;

            let chan = &mut self.ch[c];
            if sample != 0 && (sample as usize) <= 31 {
                chan.smp = sample;
                chan.vol = self.m.smp[sample as usize - 1].vol;
            }
            if period != 0 {
                chan.period = period;
                chan.step = step_for(period);
                chan.pos = 0;
                chan.active = chan.smp != 0
                    && self.m.smp[chan.smp as usize - 1].len > 0;
            }
            match eff {
                0x0C => chan.vol = par.min(64),                  // set volume
                0x0F => {
                    if par < 0x20 {
                        if par != 0 { self.speed = par as u32; }
                    } else {
                        self.samp_per_tick = SRATE * 5 / (par as u32 * 2);
                    }
                }
                0x0B => jmp = Some(par as usize),                // pos jump
                0x0D => {
                    brk = Some(((par >> 4) * 10 + (par & 0x0F)) as usize); // break
                }
                _ => {}
            }
        }
        // Row/order advance for next do_row.
        if let Some(j) = jmp {
            self.order_idx = j;
            self.row = brk.unwrap_or(0);
        } else if let Some(b) = brk {
            self.order_idx += 1;
            self.row = b;
        } else {
            self.row += 1;
            if self.row >= 64 {
                self.row = 0;
                self.order_idx += 1;
            }
        }
        if self.order_idx >= self.m.song_len {
            self.order_idx = 0; // loop the song
            self.ended = true;  // (signals "wrapped" for the headless test)
        }
    }

    fn tick(&mut self) {
        if self.tick == 0 {
            self.do_row();
        }
        self.tick += 1;
        if self.tick >= self.speed {
            self.tick = 0;
        }
        self.samp_left = self.samp_per_tick;
    }

    /// Render `out.len()` unsigned-8 mono samples.
    fn render(&mut self, out: &mut [u8]) {
        for s in out.iter_mut() {
            if self.samp_left == 0 {
                self.tick();
            }
            self.samp_left -= 1;

            let mut acc: i32 = 0;
            for c in 0..4 {
                let ch = &mut self.ch[c];
                if !ch.active || ch.smp == 0 {
                    continue;
                }
                let sd = self.m.smp[ch.smp as usize - 1];
                let idx = (ch.pos >> 16) as u32;
                let end = if sd.loop_len > 2 {
                    sd.loop_start + sd.loop_len
                } else {
                    sd.len
                };
                if idx >= end {
                    if sd.loop_len > 2 {
                        ch.pos -= (sd.loop_len as u64) << 16;
                    } else {
                        ch.active = false;
                        continue;
                    }
                }
                let fi = sd.data as usize + (ch.pos >> 16) as usize;
                let v = if fi < self.buf.len() {
                    self.buf[fi] as i8 as i32
                } else {
                    0
                };
                acc += v * ch.vol as i32; // ±128 * 0..64
                ch.pos += ch.step;
            }
            // 4 ch * ±128 * 64 = ±32768 → >>8 → ±128, clamp, bias 0x80.
            let mut o = acc >> 8;
            if o > 127 {
                o = 127;
            } else if o < -128 {
                o = -128;
            }
            *s = (o + 128) as u8;
        }
    }
}

/// Entry: dosrt's crt0 set up the environment and reconstructed
/// `argc`/`argv` from the stub's Borland argv. `argv[1]` = module path.
#[unsafe(no_mangle)]
pub fn app_main(argc: usize, argv: &[&[u8]]) {
    puts("\r\nmodplay: ");
    // `MODPLAY <path>`; default to MOD2.MOD when no argument given.
    static mut PATHBUF: [u8; 128] = [0; 128];
    let pb = unsafe { &mut *core::ptr::addr_of_mut!(PATHBUF) };
    let plen = if argc > 1 {
        let a = argv[1];
        let n = a.len().min(pb.len() - 1);
        pb[..n].copy_from_slice(&a[..n]);
        pb[n] = 0;
        n + 1
    } else {
        pb[..9].copy_from_slice(b"MOD2.MOD\0");
        9
    };
    let path: &[u8] = &pb[..plen];
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

    let m = match parse(&buf[..n]) {
        Some(m) => m,
        None => {
            puts("parse FAIL\r\n");
            dos::exit(1);
        }
    };
    puts("npat=");
    puthex8(m.n_patterns as u8);
    puts(" songlen=");
    puthex8(m.song_len as u8);

    // Headless mixer check: render ~1 s, measure non-silence + a checksum.
    let mut pl = Player::new(&m, &buf[..n]);
    let mut block = [0u8; 4096];
    let mut nonsil: u32 = 0;
    let mut sum: u32 = 0;
    let mut mn: u8 = 255;
    let mut mx: u8 = 0;
    let secs = SRATE as usize; // ~1 s
    let mut done = 0usize;
    while done < secs {
        pl.render(&mut block);
        for &v in block.iter() {
            if v != 0x80 {
                nonsil += 1;
            }
            sum = sum.wrapping_add(v as u32);
            if v < mn { mn = v; }
            if v > mx { mx = v; }
        }
        done += block.len();
    }
    puts(" mix nonsil=");
    puthex32(nonsil);
    puts(" min=");
    puthex8(mn);
    puts(" max=");
    puthex8(mx);
    puts(" sum=");
    puthex32(sum);

    // #23a: can the PM payload reach the SB hardware ports?
    puts(" sb=");
    if !sb::reset() {
        puts("FAIL\r\n");
        dos::exit(1);
    }
    puts("OK");
    sb::set_rate(SRATE);

    // #23b: conventional auto-init DMA ring (8237 needs <1 MB physical).
    // Render the mixer straight into it (zero-copy), arm the virtualized
    // 8237, start 8-bit auto-init, and confirm the channel count moves.
    const NSAMP: usize = 4096;
    const SEGSZ: u16 = 256;
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
    pl.render(ring);

    let phys = (seg as u32) << 4;
    let off = (phys & 0xFFFF) as u16;
    let page = (phys >> 16) as u8;
    outb(0x0A, 0x05);                       // mask ch1
    outb(0x0C, 0x00);                       // clear flip-flop
    outb(0x0B, 0x59);                       // ch1 read, auto-init
    outb(0x02, (off & 0xFF) as u8);
    outb(0x02, (off >> 8) as u8);
    outb(0x83, page);                       // ch1 page
    outb(0x03, ((NSAMP - 1) & 0xFF) as u8);
    outb(0x03, (((NSAMP - 1) >> 8) & 0xFF) as u8);
    outb(0x0A, 0x01);                       // unmask ch1
    sb::write(0x48);                        // set block size = SEGSZ
    sb::write(((SEGSZ - 1) & 0xFF) as u8);
    sb::write(((SEGSZ - 1) >> 8) as u8);
    sb::write(0x1C);                        // 8-bit auto-init DMA start

    // #23c: poll-driven streaming. The 8237 count runs (NSAMP-1)→0 and
    // auto-init reloads it each ring pass; play index = (NSAMP-1)-count.
    // Re-render every segment the play head has passed. No IRQ handler.
    const NSEG: usize = NSAMP / SEGSZ as usize;
    let mut next_fill = 0usize;             // next consumed seg to refill
    let mut refills: u32 = 0;
    // Play one full pass of the module. `pl.ended` is set when the order
    // list wraps (do_row). A tiny post-end drain lets the last in-ring
    // segments finish instead of cutting the tail.
    let mut drain = NSEG as u32 + 2;
    while !pl.ended || drain > 0 {
        outb(0x0C, 0x00);
        let lo = inb(0x03) as u16;
        let hi = inb(0x03) as u16;
        let count = ((hi << 8) | lo) as usize;
        let play_idx = (NSAMP - 1).wrapping_sub(count) % NSAMP;
        let playing_seg = play_idx / SEGSZ as usize;
        while next_fill != playing_seg {
            let b = next_fill * SEGSZ as usize;
            pl.render(&mut ring[b..b + SEGSZ as usize]);
            next_fill = (next_fill + 1) % NSEG;
            refills += 1;
            if pl.ended && drain > 0 {
                drain -= 1;
            }
        }
    }
    sb::write(0xD3);                        // speaker off
    sb::write(0xDA);                        // exit auto-init
    puts(" refills=");
    puthex32(refills);
    puts(" (song end)\r\n");
    // Return → dosrt's _start calls dos::exit(0).
}
// crt0 (_start) + panic handler are provided by the `dosrt` crate.
