//! Sound Blaster (SB16 DSP + CT1745 mixer + the OPL on the same card).
//!
//! The emulated half of a Sound Blaster: the DSP command state machine, the
//! mixer register file, the play cursor, and the FM synth this card carries.
//! A host that has a *real* card wraps this and never instantiates it.
//!
//! Passive like every card in this crate — but the SB is the one that shows
//! why the contract is shaped the way it is. **It owns no sample memory.**
//! The GUS files its samples into its own DRAM and plays from there, so its
//! mix reads memory the card owns. The SB DSP streams the guest's DMA ring
//! straight to its DAC, so at mix time it needs bytes that live in *guest*
//! memory, which a passive card cannot reach.
//!
//! The resolution is a borrow, not a fetch: [`Sb::dsp_fetch`] says which
//! window of the ring the next mix block needs, the host moves those bytes
//! (it owns the 8237 and the guest's address space), and [`Sb::mix_dsp`]
//! resamples from the slice it is handed. The card reads it and forgets it —
//! sample bytes are never stored here. That is the same `&[u8]` the voice
//! engine already takes; only the owner differs.
//!
//! Everything else follows the usual rules: the clock arrives as an argument,
//! interrupts are *reported* rather than raised, and the DMA channel is a
//! number the card is told about for readback, never one it dereferences.

use crate::opl;
use alloc::boxed::Box;

/// How long the DSP keeps the canonical stream open after playback stops,
/// feeding silence (see [`Sb::owns_sink`]). Long enough to bridge
/// per-animation-frame sound-effect re-triggers (~150 ms), short enough that
/// FM music isn't held at the DSP rate for long once effects go quiet.
const DSP_HANGOVER_MS: u64 = 300;

/// CT1745 (SB16) mixer attenuation table: a 5-bit level in bits 7:3 of the
/// volume register, 2 dB per step, as a linear amplitude out of 32767. Taken
/// verbatim from 86Box `src/sound/snd_sb.c` (`sb_att_2dbstep_5bits`), whose
/// comment notes the 32767 ceiling deliberately leaves ~6 dB of headroom.
const ATT_2DB_5BIT: [u16; 32] = [
    25, 32, 41, 51, 65, 82, 103, 130, 164, 206,
    260, 327, 412, 519, 653, 822, 1036, 1304, 1641, 2067,
    2602, 3276, 4125, 5192, 6537, 8230, 10362, 13044, 16422, 20674,
    26027, 32767,
];

/// Fixed source scales on the card's analog summing node, in Q16. These — not
/// the mixer registers — set the FM-vs-DAC balance, and both cards' power-on
/// mixer defaults are *full* volume, so these are what you hear by default.
/// From 86Box's SB16 mix (`sb_get_buffer_sb16_awe32` / `sb_get_music_buffer_sb16_awe32`):
///
/// ```text
///   DAC: dsp.buffer * voice * master / 3.0
///   FM : opl_buf    * fm    * master * 0.7171630859375
/// ```
///
/// So FM sits **2.15x above** the DAC at equal digital full scale. Summing both
/// at unity (what we did before) therefore ran digital SFX ~9.5 dB too hot
/// against FM music, and pinned the sum at the clipping rail whenever a
/// full-scale sample played over a track.
///
/// Both sources are on *this* card, which is why the balance lives here. How
/// loud the card sits against a GUS is the host's mix policy, not the SB's.
const FM_SCALE_Q16: i32 = 47_000; // 0.7171630859375 == 47000/65536, exactly
const DAC_SCALE_Q16: i32 = 65_536 / 3;

/// Combine two Q16 gains without overflowing i32 on the way.
const fn combine_q16(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 16) as i32
}

/// The CT1745 (SB16) mixer register file.
///
/// Every volume register is a 5-bit level in bits 7:3 (2 dB/step, see
/// [`ATT_2DB_5BIT`]). The older register maps are *aliases*, exactly as on the
/// real chip: an SB Pro game writing 0x22/0x04/0x26 and an SB1/2 game writing
/// 0x02/0x06 both land in the same 0x30-0x35 pairs, so one code path serves
/// every generation. Games really do set these — they were previously accepted
/// and dropped, so a game turning its SFX down changed nothing.
#[derive(Clone, Copy)]
pub struct Mixer {
    regs: [u8; 256],
}

impl Mixer {
    /// Power-on state. `const`: the whole card is built in a const fn, so the
    /// defaults are spelled out here rather than via `reset()`.
    pub const fn new() -> Self {
        let mut regs = [0u8; 256];
        regs[0x30] = 0xF8; regs[0x31] = 0xF8; // master L/R
        regs[0x32] = 0xF8; regs[0x33] = 0xF8; // voice  L/R
        regs[0x34] = 0xF8; regs[0x35] = 0xF8; // FM     L/R
        regs[0x36] = 0xF8; regs[0x37] = 0xF8; // CD     L/R
        regs[0x3B] = 0x80;                    // PC speaker
        regs[0x04] = 0xEE; regs[0x22] = 0xEE; // legacy views of the same levels
        regs[0x26] = 0xEE; regs[0x28] = 0xEE;
        Mixer { regs }
    }

    /// Power-on / mixer-index-0 reset. Defaults are 86Box's `sb_ct1745_mixer_reset`:
    /// master, voice, FM and CD all at maximum (0xF8 → level 31 → unity), line/mic
    /// muted. A game that never touches the mixer gets full volume — which is why
    /// the FM/DAC balance has to come from the fixed scales, not from these.
    pub fn reset(&mut self) {
        *self = Mixer::new();
    }

    pub fn read(&self, index: u8) -> u8 {
        self.regs[index as usize]
    }

    pub fn write(&mut self, index: u8, val: u8) {
        if index == 0x00 {
            self.reset();
            return;
        }
        self.regs[index as usize] = val;
        // Legacy maps alias into the SB16 pairs (86Box snd_sb.c, CT1745 write).
        // `| 0x8` is the chip's low-bit fill when a coarser register is widened
        // into the 5-bit one. SB1/2 (0x02/0x06) carry one mono nibble in bits
        // 3:0; SB Pro (0x22/0x04/0x26) carry L in bits 7:4 and R in bits 3:0.
        let mono = ((val & 0x0F) << 4) | 0x8;
        let left = (val & 0xF0) | 0x8;
        let right = ((val & 0x0F) << 4) | 0x8;
        match index {
            0x02 => { self.regs[0x30] = mono; self.regs[0x31] = mono; }      // SB1/2 master
            0x06 => { self.regs[0x34] = mono; self.regs[0x35] = mono; }      // SB1/2 FM
            0x08 => { self.regs[0x36] = mono; self.regs[0x37] = mono; }      // SB1/2 CD
            0x22 => { self.regs[0x30] = left; self.regs[0x31] = right; }     // SB Pro master
            0x04 => { self.regs[0x32] = left; self.regs[0x33] = right; }     // SB Pro voice
            0x26 => { self.regs[0x34] = left; self.regs[0x35] = right; }     // SB Pro FM
            0x28 => { self.regs[0x36] = left; self.regs[0x37] = right; }     // SB Pro CD
            _ => {}
        }
    }

    /// Linear gain (Q16, unity = 65536) for a CT1745 volume register.
    fn level_q16(&self, reg: usize) -> i32 {
        // The table is an amplitude out of 32767; 86Box divides by 32768, so
        // Q16 gain is simply the entry doubled.
        ATT_2DB_5BIT[(self.regs[reg] >> 3) as usize] as i32 * 2
    }

    /// (left, right) Q16 gain the DSP's PCM is summed at: voice × master ÷ 3.
    pub fn voice_gain_q16(&self) -> (i32, i32) {
        let m = (self.level_q16(0x30), self.level_q16(0x31));
        (
            combine_q16(combine_q16(self.level_q16(0x32), m.0), DAC_SCALE_Q16),
            combine_q16(combine_q16(self.level_q16(0x33), m.1), DAC_SCALE_Q16),
        )
    }

    /// (left, right) Q16 gain the FM synth is summed at: fm × master × 0.7172.
    pub fn fm_gain_q16(&self) -> (i32, i32) {
        let m = (self.level_q16(0x30), self.level_q16(0x31));
        (
            combine_q16(combine_q16(self.level_q16(0x34), m.0), FM_SCALE_Q16),
            combine_q16(combine_q16(self.level_q16(0x35), m.1), FM_SCALE_Q16),
        )
    }
}

impl Default for Mixer {
    fn default() -> Self {
        Self::new()
    }
}

/// A DSP start-playback command the card has fully decoded, handed back to the
/// host so it can supply the ring geometry. The card knows *what kind* of
/// transfer the guest asked for; only the host can say where the guest's DMA
/// controller is pointing.
#[derive(Clone, Copy)]
pub struct Start {
    /// 8 or 16 bits per sample — also which DMA channel the host should read.
    pub bits: u8,
    pub stereo: bool,
    /// Single-cycle (play once, IRQ, stop) vs auto-init (loop the ring).
    pub single: bool,
    /// Transfer length carried by the command itself, when it had one.
    pub block_override: Option<u16>,
}

/// The window of the guest's DMA ring the next mix block needs. The host
/// copies these frames (wrapping at `buf_frames`) into a linear buffer and
/// hands it to [`Sb::mix_dsp`].
#[derive(Clone, Copy)]
pub struct Fetch {
    /// Guest-physical base of the ring, as the host reported it at start.
    pub gpa: u32,
    pub frame_bytes: u32,
    /// Ring length, for the host's wrap arithmetic.
    pub buf_frames: u32,
    /// Absolute DSP frame the window starts at, and one past its end.
    pub first: u64,
    pub end: u64,
    /// `end - first`, the number of frames the host must supply.
    pub source_frames: usize,
}

/// The emulated Sound Blaster: DSP + mixer + the FM synth on the same card.
pub struct Sb {
    // ── wiring the host strapped this card to (BLASTER), for decode/readback ──
    io_base: u16,
    irq: u8,
    dma8: u8,
    dma16: u8,

    /// DSP read-buffer FIFO (reset 0xAA, version bytes …) the guest pops from
    /// `base+0x0A`; `out_len` valid bytes starting at `out[0]`.
    out: [u8; 4],
    out_len: u8,
    /// Command awaiting parameter bytes (`None` = idle), and the parameters
    /// collected so far. SB DSP commands take 0–3 parameter bytes.
    cmd: Option<u8>,
    params: [u8; 3],
    param_got: u8,
    param_need: u8,
    /// Last value written to `base+0x06` (DSP reset register); the 1→0 edge
    /// triggers the reset handshake.
    reset_prev: u8,
    /// DSP test register (write 0xE4 → store, read 0xE8 → return). Some card
    /// detection routines round-trip a byte through it to confirm a real DSP.
    test_reg: u8,
    /// SB16 mixer register index (port base+4 write); its data port is base+5.
    mixer_index: u8,
    /// CT1745 mixer register file — the guest's volume settings.
    mixer: Mixer,
    /// Mixer reg 0x82 IRQ status: bit0 = 8-bit DMA IRQ pending, bit1 = 16-bit.
    /// Set when the SB IRQ is raised (by playback width); cleared when the guest
    /// acks (reads base+0xE for 8-bit / base+0xF for 16-bit). A 16-bit driver
    /// reads this to confirm "that was a *16-bit* DMA interrupt".
    irq_status: u8,
    /// DSP 0xF2/0xF3 (trigger 8-/16-bit IRQ) latched, same bit layout as
    /// `irq_status`. The BLASTER IRQ probe: drivers hook every candidate line,
    /// send 0xF2, and keep whichever handler fired — no IRQ means "broken card"
    /// (PoP 1.0 then drops sound entirely, AdLib included).
    trigger_irq: u8,

    /// True between a `start playback` command and a stop/reset.
    playing: bool,
    rate: u32,        // output sample rate (Hz)
    bits: u8,         // 8 or 16
    stereo: bool,     // false = mono, true = interleaved L/R
    block_param: u16, // DSP block size set by 0x48 (transfers − 1)
    /// Single-cycle DMA (DSP 0x14/0x91/0xC0/0xB0 without the auto-init bit):
    /// play the buffer ONCE, raise the IRQ at the end, then stop — vs auto-init
    /// (0x1C/0xC6/0xB6) which loops the ring and IRQs per block. Dune 2 speech
    /// uses single-cycle.
    single: bool,

    /// Ring geometry, as the host reported it at `begin`.
    buf_gpa: u32,      // guest-physical base of the ring
    buf_frames: u32,   // ring length in frames
    block_frames: u32, // frames between SB IRQs (one DMA block)
    /// Guest-visible frames played since playback start (monotonic).
    /// The DMA down-count derives from this, and block IRQs fire as it crosses
    /// block boundaries. Slaved to the sink's real playback position where the
    /// host reports one — a real SB's DMA cursor IS its playback position —
    /// leading it by [`slack`](Self::slack) so the guest's per-block refill
    /// lands before the codec reaches the data.
    cursor: u64,
    next_irq: u64,    // cursor value of the next block boundary (IRQ point)
    /// How far the guest clock leads the mixer's drain point (source frames):
    /// only what the guest ring is too small to cover — see [`Sb::begin`].
    slack: u32,
    /// This DSP playback (re)started: tell the host's pump to re-key its
    /// session so pump frames and DSP stream frames coincide.
    restarted: bool,
    /// Tiny single-cycle transfer: a DMA-wiring probe wanting its completion
    /// IRQ within milliseconds — completed on virtual time, not drain.
    probe: bool,
    /// Host clock at the first tick of a probe transfer.
    start_ms: u64,
    /// Block IRQs raised / serviced (guest read the DMA count or status port —
    /// poll-bool/poll-dma/irq-mix all do). Their gap is the commit horizon: a
    /// serviced block means the guest has refilled its slot, so the ring is
    /// committed one full lap past it.
    blocks_done: u64,
    blocks_acked: u64,
    /// Read counter behind the write-status busy flicker (see `base+0x0C`):
    /// bit 3 alternates the busy bit every 8 reads mid-transfer.
    write_busy: u8,
    /// The DSP owns the canonical sink beyond `playing`: after a single-cycle
    /// sample completes (or the guest pauses), the stream is held open for
    /// [`DSP_HANGOVER_MS`] feeding silence (FM still mixed in) instead of being
    /// torn down. Sound-effect chains re-trigger every ~150 ms (PoP's gate
    /// grinding); stopping the sink per sample meant a stream park/re-prime —
    /// and a rate flip against the FM free-run — around every effect.
    stream_hold: bool,
    /// Host clock when playback last stopped (hangover anchor).
    done_ms: u64,
    /// The last single-cycle transfer ran to terminal count: the guest-visible
    /// current-count reads 0xFFFF (the real 8237's post-TC underflow) until the
    /// channel is restarted. Completion pollers key on this (PoP 1.4's digi.drv
    /// waits for it after its level-transition sample — an IRQ alone does not
    /// unpark it).
    dma_tc: bool,
    /// 8237 status-register TC bits, one per global channel, accumulated since
    /// the last status read; reading a controller's status register clears its
    /// four bits, exactly like the real chip.
    tc_status: u8,

    /// FM synthesis (OPL2/OPL3). Lazily created on the first FM register write
    /// — the chip is ~20 KB and most programs never touch FM.
    opl: Option<opl::Fm>,
}

impl Sb {
    /// A powered-down card on the SB16 defaults (A220 I7 D1 H5).
    pub const fn new() -> Self {
        Sb {
            io_base: 0x220, irq: 7, dma8: 1, dma16: 5,
            out: [0; 4], out_len: 0,
            cmd: None, params: [0; 3], param_got: 0, param_need: 0,
            reset_prev: 0, test_reg: 0,
            mixer_index: 0, mixer: Mixer::new(), irq_status: 0, trigger_irq: 0,
            playing: false, rate: 22050, bits: 8, stereo: false, block_param: 0,
            single: false,
            buf_gpa: 0, buf_frames: 0, block_frames: 0,
            cursor: 0, next_irq: 0,
            slack: 0, restarted: false, probe: false, start_ms: 0,
            blocks_done: 0, blocks_acked: 0,
            write_busy: 0, dma_tc: false, tc_status: 0,
            stream_hold: false, done_ms: 0,
            opl: None,
        }
    }

    /// Strap the card: port base and the IRQ/DMA numbers it reports back
    /// through the mixer's configuration registers. The host owns the actual
    /// wiring (the guest's `BLASTER=` contract); these are for decode and
    /// readback only — the card never dereferences a channel number.
    pub fn set_wiring(&mut self, io_base: u16, irq: u8, dma8: u8, dma16: u8) {
        self.io_base = io_base;
        self.irq = irq;
        self.dma8 = dma8;
        self.dma16 = dma16;
    }

    fn push_out(&mut self, b: u8) {
        if (self.out_len as usize) < self.out.len() {
            self.out[self.out_len as usize] = b;
            self.out_len += 1;
        }
    }

    fn pop_out(&mut self) -> u8 {
        if self.out_len == 0 { return 0; }
        let b = self.out[0];
        self.out.copy_within(1..self.out_len as usize, 0);
        self.out_len -= 1;
        b
    }

    // ── ports ────────────────────────────────────────────────────────────

    /// Guest IN from a DSP/mixer/FM port.
    pub fn port_read(&mut self, p: u16) -> u8 {
        // OPL status register: a read of any FM window port returns the timer
        // status. Bits 1-2 are always 0 — the "this is an OPL3" answer type
        // probes look for. Before any FM write there is no chip yet: power-on
        // status is 0 anyway.
        if opl::decode_port(self.io_base, p).is_some() {
            return self.opl.as_ref().map_or(0, |o| o.status());
        }
        match p.wrapping_sub(self.io_base) {
            0x05 => match self.mixer_index {          // mixer data
                0x82 => self.irq_status,              // IRQ status (8/16-bit)
                0x80 => match self.irq {              // IRQ select
                    2 | 9 => 0x01, 5 => 0x02, 7 => 0x04, 10 => 0x08, _ => 0x04,
                },
                0x81 => (1u8 << (self.dma8 & 7)) | (1u8 << (self.dma16 & 7)), // DMA select
                // Everything else is the mixer register file: a game that
                // read-modify-writes a volume must see back what it set.
                i => self.mixer.read(i),
            },
            0x0A => self.pop_out(),                   // DSP read data
            // DSP write-buffer status: while a single-cycle transfer is in
            // flight, bit 7 (busy) FLICKERS — on the real chip it's a per-byte
            // buffer status, pulsing as the DSP services DMA between command
            // bytes (that's why 0xD0/pause can be sent mid-transfer at all).
            // Alternate it every 8 reads, DOSBox's proven model: a driver
            // waiting for busy sees it within 8 reads and one waiting for the
            // busy→idle edge sees that within 16 — microseconds, never a
            // block-long stall. PoP's per-frame "stop digitized sound" routine
            // needs BOTH: with always-ready it spins forever on wait-for-busy
            // (end-door hang); with busy-held-for-the-block it stalls a full
            // sample per game frame (1 fps, staccato gate grinding). Idle DSP
            // reads always-ready.
            0x0C => {
                if self.playing && self.single {
                    self.write_busy = self.write_busy.wrapping_add(1);
                    if self.write_busy & 8 != 0 { 0x80 } else { 0x00 }
                } else {
                    0x00
                }
            }
            0x0E => {                                 // read-status / 8-bit IRQ ack
                self.irq_status &= !0x01;             // reading acks the 8-bit IRQ
                self.blocks_acked = self.blocks_done; // block serviced: extend commit
                if self.out_len > 0 { 0x80 } else { 0x00 }
            }
            0x0F => {                                 // 16-bit IRQ ack
                self.irq_status &= !0x02;
                self.blocks_acked = self.blocks_done;
                0x00
            }
            _ => 0xFF,
        }
    }

    /// Guest OUT to a DSP/mixer/FM port. Returns a decoded start-playback
    /// command when one completed: the host must answer it with [`Sb::begin`],
    /// because only the host can read the guest's DMA controller.
    pub fn port_write(&mut self, p: u16, val: u8, now: u64) -> Option<Start> {
        // OPL2/OPL3 FM (AdLib 0x388-0x38B, or the SB mirrors at io_base+0..3
        // and +8/+9): address latch + data writes into the FM synth, created
        // on first touch.
        if let Some(port) = opl::decode_port(self.io_base, p) {
            self.opl
                .get_or_insert_with(|| opl::Fm::new(now))
                .write(now, port, val);
            return None;
        }
        match p.wrapping_sub(self.io_base) {
            0x04 => self.mixer_index = val,                    // mixer register select
            0x05 => self.mixer.write(self.mixer_index, val),   // mixer data
            0x06 => {
                // DSP reset: a 1→0 edge triggers the reset handshake.
                if self.reset_prev == 1 && val == 0 {
                    self.playing = false;
                    self.stream_hold = false;
                    // This resets only the SB DSP. The canonical sink is
                    // shared: GUS music or OPL may still be contributing, so
                    // the host powers it down only when every source is idle.
                    self.cmd = None;
                    self.param_got = 0;
                    self.out_len = 0;
                    self.push_out(0xAA); // reset acknowledge
                }
                self.reset_prev = val;
            }
            0x0C => return self.dsp_byte(val, now),            // DSP command / parameter
            _ => {}                                            // unmodeled: ignored
        }
        None
    }

    /// Feed one byte to the DSP command FSM: a parameter for the in-flight
    /// command, or the start of a new one.
    fn dsp_byte(&mut self, val: u8, now: u64) -> Option<Start> {
        if let Some(cmd) = self.cmd {
            self.params[self.param_got as usize] = val;
            self.param_got += 1;
            if self.param_got >= self.param_need {
                let start = self.exec(cmd, now);
                self.cmd = None;
                self.param_got = 0;
                return start;
            }
            return None;
        }
        // Parameter count by command (only the subset DSP clients use here).
        let need = match val {
            0x40 | 0xE0 | 0xE4 => 1,              // time constant; ident byte; test-reg write
            0x14 | 0x41 | 0x42 | 0x48 | 0x80 => 2, // single-cycle len, out/in rate, block, silence
            0xB0..=0xCF => 3,                      // SB16 16/8-bit DMA: mode + length lo/hi
            _ => 0,                               // 0x1C/0x90/0x91/0xE8 etc. take no params
        };
        if need > 0 {
            self.cmd = Some(val);
            self.param_need = need;
            self.param_got = 0;
            None
        } else {
            self.exec(val, now)
        }
    }

    /// Execute a fully-parameterized DSP command.
    fn exec(&mut self, cmd: u8, now: u64) -> Option<Start> {
        let p = self.params;
        match cmd {
            0xE1 => {
                self.push_out(4); // DSP version 4.5 (SB16)
                self.push_out(5);
            }
            // Detection helpers some drivers use to confirm a real DSP:
            0xE0 => self.push_out(!p[0]),        // identification: return ~byte
            0xE4 => self.test_reg = p[0],        // write test register
            0xE8 => self.push_out(self.test_reg), // read test register back
            0xF2 => self.trigger_irq |= 0x01,    // trigger 8-bit IRQ (IRQ probe)
            0xF3 => self.trigger_irq |= 0x02,    // trigger 16-bit IRQ
            0xD1 | 0xD4 => {}                    // speaker on / continue DMA
            0xD0 | 0xD3 | 0xD9 | 0xDA => {
                // Pause / speaker off / exit auto-init: playback stops, but the
                // stream is held open through the hangover — effect chains
                // pause-and-restart every animation frame.
                self.playing = false;
                self.done_ms = now;
            }
            0x40 => {
                let tc = p[0] as u32;
                self.rate = if tc < 256 { 1_000_000 / (256 - tc) } else { 22050 };
            }
            0x41 => self.rate = ((p[0] as u32) << 8) | p[1] as u32, // output rate (hi, lo)
            0x42 => {}                                              // input rate: ignore
            0x48 => self.block_param = (p[0] as u16) | ((p[1] as u16) << 8),
            // Legacy 8-bit mono output. 0x1C/0x90 = auto-init (block from 0x48);
            // 0x14 carries its single-cycle transfer length in the command.
            // 0x91 has no length parameters and falls back to the DMA count.
            0x1C | 0x90 => {
                return Some(Start { bits: 8, stereo: false, single: false, block_override: None });
            }
            0x14 => {
                return Some(Start {
                    bits: 8, stereo: false, single: true,
                    block_override: Some((p[0] as u16) | ((p[1] as u16) << 8)),
                });
            }
            0x91 => {
                return Some(Start { bits: 8, stereo: false, single: true, block_override: None });
            }
            // SB16 8-/16-bit output: mode byte + 16-bit length; bit1 = auto-init,
            // its absence = single-cycle. (0xC8.., 0xB8.. are input/ADC — ignored.)
            0xC0..=0xC7 => {
                return Some(Start {
                    bits: 8,
                    stereo: p[0] & 0x20 != 0,
                    single: cmd & 0x02 == 0,
                    block_override: Some((p[1] as u16) | ((p[2] as u16) << 8)),
                });
            }
            0xB0..=0xB7 => {
                return Some(Start {
                    bits: 16,
                    stereo: p[0] & 0x20 != 0,
                    single: cmd & 0x02 == 0,
                    block_override: Some((p[1] as u16) | ((p[2] as u16) << 8)),
                });
            }
            _ => {}
        }
        None
    }

    /// Answer a [`Start`]: begin playback over the ring the host just read out
    /// of the guest's DMA controller.
    ///
    /// `gpa`/`len_bytes` are that controller's programming — the card is told
    /// them, it does not go looking. `min_fill` is how deep the host's sink
    /// pipe runs (0 when the sink has no playback clock), which is the only
    /// thing the lead calculation below needs to know about the host.
    pub fn begin(&mut self, s: Start, gpa: u32, len_bytes: u32, min_fill: u32) {
        self.bits = s.bits;
        self.stereo = s.stereo;
        self.single = s.single;
        if let Some(b) = s.block_override {
            self.block_param = b;
        }
        let channels = if s.stereo { 2u32 } else { 1 };
        let frame_bytes = (s.bits as u32 / 8) * channels;
        self.buf_gpa = gpa;
        self.buf_frames = len_bytes.checked_div(frame_bytes).unwrap_or(0);
        // The DSP command's length is authoritative when it supplied one;
        // the 8237 count remains the physical ceiling (terminal count).
        // Auto-init raises an IRQ for each programmed DSP block.
        self.block_frames = if s.single {
            s.block_override
                .map(|n| ((n as u32 + 1) / channels).max(1))
                .unwrap_or(self.buf_frames.max(1))
                .min(self.buf_frames.max(1))
        } else {
            // Block size is "transfers − 1"; a transfer is one sample/channel.
            ((self.block_param as u32 + 1) / channels).max(1)
        };
        self.cursor = 0;
        self.next_irq = self.block_frames as u64;
        self.blocks_done = 0;
        self.blocks_acked = 0;
        self.restarted = true; // host pump: re-key session numbering
        // A single-cycle DMA transfer has its own finite device clock: it
        // starts when the DSP command arms DRQ and reaches terminal count
        // after `buf_frames / rate`, independent of how much older music is
        // queued in the final speaker sink. Treating only sub-256-byte blocks
        // this way made Duke3D's larger 16-bit channel-5 self-test wait behind
        // the GUS output cushion and time out as "conflicting DMA channel".
        // Auto-init rings remain slaved to the sink's continuous cursor.
        self.probe = s.single;
        self.start_ms = 0;
        // The guest clock leads the drain only by what the ring is too small
        // to cover: with ring ≥ fill + one block, the refill a block IRQ
        // commits always lands before the mix point reads its slot, and the
        // cursor can track audible playback exactly (slack = 0). Single-cycle
        // never needs a lead — its whole buffer is committed up front.
        self.slack = if s.single {
            0
        } else {
            (min_fill + self.block_frames).saturating_sub(self.buf_frames)
        };
        self.dma_tc = false; // restart re-loads the count registers
        self.playing = self.buf_frames > 0;
        if self.playing {
            self.stream_hold = true;
        }
    }

    // ── clock & interrupts ───────────────────────────────────────────────

    /// Advance the DSP's guest-visible clock and report whether the card wants
    /// its interrupt line raised.
    ///
    /// `drained`/`pushed` are the host sink's playback counters **in this
    /// card's frames**: frames the codec has actually consumed, and frames
    /// handed to it. The cursor — the DMA count and the block-boundary IRQs
    /// both derive from it — is `drained + slack`, capped at `pushed`. A real
    /// SB's DMA cursor IS its playback position; deriving it from what the
    /// codec has consumed reproduces exactly that. Also ends the hangover
    /// hold, and completes tiny probe transfers on virtual time (their IRQ
    /// can't wait for a stream to start draining).
    pub fn advance_clock(&mut self, now: u64, drained: u64, pushed: u64) -> bool {
        if !self.playing {
            // Hangover: the host keeps the stream fed (silence + synths) while
            // `stream_hold` keeps `owns_sink` true; effect chains re-trigger
            // onto a hot stream instead of a park/re-prime.
            if self.stream_hold && now.saturating_sub(self.done_ms) >= DSP_HANGOVER_MS {
                self.stream_hold = false;
            }
            return false;
        }
        let guest_now = if self.probe {
            // Single-cycle DMA advances continuously on the DSP's virtual
            // sample clock, independent of final-speaker stream priming.
            if self.start_ms == 0 {
                self.start_ms = now;
            }
            (now.saturating_sub(self.start_ms) * self.rate.max(1) as u64 / 1000)
                .min(self.next_irq)
        } else {
            (drained + self.slack as u64).min(pushed)
        };
        let mut raise = false;
        while self.playing && guest_now >= self.next_irq {
            self.block_irq();
            raise = true;
            if self.single {
                self.finish_single(now);
            } else {
                self.next_irq += self.block_frames as u64;
            }
        }
        if self.playing {
            self.cursor = guest_now;
        }
        raise
    }

    /// A block boundary passed: advance the cursor over it and latch the
    /// width-tagged mixer IRQ status. Putting the *line* up is the host's.
    fn block_irq(&mut self) {
        self.cursor = self.next_irq;
        self.blocks_done += 1;
        // Mixer IRQ-status bit by transfer width (16-bit drivers check this).
        self.irq_status |= if self.bits == 16 { 0x02 } else { 0x01 };
    }

    /// Single-cycle: one pass and stop (no loop). The 8237 side hit terminal
    /// count, so the current count underflows to 0xFFFF and the status TC bit
    /// latches until read; the stream stays held open through the hangover.
    fn finish_single(&mut self, now: u64) {
        self.playing = false;
        self.done_ms = now;
        self.dma_tc = true;
        let chan = if self.bits == 16 { self.dma16 } else { self.dma8 };
        self.tc_status |= 1 << (chan & 7);
    }

    /// A latched 0xF2/0xF3 trigger IRQ (the BLASTER IRQ probe) is pending:
    /// consume it and report that the line should go up. A real card answers
    /// within microseconds, so the host should sample this every slice.
    pub fn take_trigger(&mut self) -> bool {
        if self.trigger_irq == 0 {
            return false;
        }
        self.irq_status |= self.trigger_irq;
        self.trigger_irq = 0;
        true
    }

    /// Complete a single-cycle transfer too short for the host's pump clock to
    /// see, and report that the line should go up.
    ///
    /// A real card finishes a few-byte transfer in microseconds: the DSP
    /// command and its completion IRQ are, to the driver, back to back. A pump
    /// clock running once a millisecond puts the IRQ 1-2 ms late, which is an
    /// eternity to a driver probing how its card is wired: MONKEY2's
    /// SOUNBLAS.IMS arms a 1-byte transfer and re-masks the PIC a few
    /// instructions later, so on a fast backend it had already stopped
    /// listening and gave up with "Unable to initialize SoundDriver".
    pub fn take_probe(&mut self, now: u64) -> bool {
        if !self.probe || !self.playing {
            return false;
        }
        // Frames the pump clock cannot resolve: shorter than its 1 ms turn.
        if self.block_frames as u64 * 1000 >= self.rate.max(1) as u64 {
            return false;
        }
        self.block_irq();
        self.finish_single(now);
        true
    }

    // ── state the host's mixer pump asks about ───────────────────────────

    /// Playing, or holding the stream open through the hangover.
    pub fn owns_sink(&self) -> bool {
        self.playing || self.stream_hold
    }

    /// Rate the DSP stream runs the host's mixer session at.
    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// A DSP playback (re)started since the last call: the host's pump must
    /// re-key its session so pump frames and DSP stream frames coincide.
    pub fn take_restart(&mut self) -> bool {
        core::mem::take(&mut self.restarted)
    }

    /// Whether the FM synth wants the canonical stream held open (voices
    /// sounding, or the driver wrote between notes recently).
    pub fn fm_audible(&self, now: u64) -> bool {
        self.opl.as_ref().is_some_and(|o| o.audible(now))
    }

    /// Program-exit cleanup: stop the DSP and drop the FM chip so the next
    /// program sees a power-on card. Parking the host's sink is separate —
    /// it is shared with every other card.
    pub fn reset_for_exit(&mut self) {
        self.playing = false;
        self.stream_hold = false;
        self.out_len = 0;
        self.cmd = None;
        self.opl = None; // next program gets a power-on-fresh FM chip
    }

    // ── PCM ──────────────────────────────────────────────────────────────

    /// Auto-init commit horizon: how far into the ring the mix may read.
    /// Frames past it stay silent — an unserviced ring keeps cycling and
    /// replays, exactly like the real card. Single-cycle commits the whole
    /// buffer up front.
    fn committed_end(&self) -> u64 {
        if self.single {
            self.buf_frames as u64
        } else {
            (self.blocks_acked * self.block_frames as u64 + self.buf_frames as u64)
                .max(self.next_irq)
        }
    }

    /// Which window of the guest's ring the next mix block needs, or `None`
    /// when the DSP contributes nothing (idle, hangover, or starved past the
    /// commit horizon). `base` is the host's mix-session frame of `block[0]`,
    /// which — because [`begin`](Self::begin) asks for a re-key — is also this
    /// stream's frame.
    ///
    /// The card cannot fetch this itself; see the module note. The host copies
    /// `source_frames` frames starting at `first`, wrapping at `buf_frames`,
    /// and passes the linear result to [`mix_dsp`](Self::mix_dsp).
    pub fn dsp_fetch(&self, rate: u32, base: u64, block_frames: usize) -> Option<Fetch> {
        if !self.playing || rate == 0 {
            return None; // idle or hangover: the pump's zeros are our silence
        }
        let channels = if self.stereo { 2u32 } else { 1 };
        let frame_bytes = (self.bits as u32 / 8) * channels;
        if frame_bytes == 0 || self.buf_frames == 0 {
            return None;
        }
        let dsp_rate = self.rate.max(1) as u64;
        let first = base * dsp_rate / rate as u64;
        let last = (base + block_frames.saturating_sub(1) as u64) * dsp_rate / rate as u64;
        let end = (last + 1).min(self.committed_end());
        if first >= end {
            return None; // starved: leave the pump's silence
        }
        Some(Fetch {
            gpa: self.buf_gpa,
            frame_bytes,
            buf_frames: self.buf_frames,
            first,
            end,
            source_frames: (end - first) as usize,
        })
    }

    /// Decode source frame `i` of a fetched window into canonical i16 stereo.
    /// SB DMA is 8-bit unsigned or 16-bit signed little-endian; mono
    /// duplicates.
    fn frame(&self, src: &[u8], i: usize) -> (i16, i16) {
        let wide = self.bits == 16;
        let sw = if wide { 2usize } else { 1 };
        let stride = sw * if self.stereo { 2 } else { 1 };
        let at = |b: usize| -> i16 {
            if wide {
                let lo = *src.get(b).unwrap_or(&0) as u16;
                let hi = *src.get(b + 1).unwrap_or(&0) as u16;
                (lo | (hi << 8)) as i16
            } else {
                // 8-bit unsigned (bias 0x80) → signed, scaled to 16-bit.
                ((*src.get(b).unwrap_or(&128) as i16) - 128) << 8
            }
        };
        let base = i * stride;
        if self.stereo {
            (at(base), at(base + sw))
        } else {
            let m = at(base);
            (m, m)
        }
    }

    /// Sum the DSP stream into `block`, resampling from the ring window the
    /// host fetched. `src` is `f.source_frames` frames starting at `f.first`,
    /// linear (the host already un-wrapped the ring).
    ///
    /// The ring is the guest's, clocked at the guest's rate; `block` is the
    /// host's, at the canonical rate. Map each output frame back to the DSP
    /// frame playing at that instant (zero-order hold).
    pub fn mix_dsp(&self, rate: u32, base: u64, src: &[u8], f: &Fetch, block: &mut [(i32, i32)]) {
        let (gl, gr) = self.mixer.voice_gain_q16();
        let dsp_rate = self.rate.max(1) as u64;
        for (i, slot) in block.iter_mut().enumerate() {
            let s = (base + i as u64) * dsp_rate / rate as u64;
            if s >= f.end {
                break;
            }
            let (l, r) = self.frame(src, (s - f.first) as usize);
            slot.0 += (l as i32 * gl) >> 16;
            slot.1 += (r as i32 * gr) >> 16;
        }
    }

    /// Sum the FM synth into `block` (no-op when silent).
    pub fn mix_fm(&mut self, rate: u32, block: &mut [(i32, i32)]) {
        let gain = self.mixer.fm_gain_q16();
        if let Some(o) = self.opl.as_mut()
            && o.mixing()
        {
            o.mix_into(rate, block, gain);
        }
    }

    // ── DMA-controller readback ──────────────────────────────────────────
    //
    // The card holds the play state a guest's 8237 reads reflect; the host
    // owns the controller itself (its byte-pointer flip-flop, its programmed
    // base address) and composes the two.

    /// Whether a transfer is running — the host's test for "serve live state".
    pub fn playing(&self) -> bool {
        self.playing
    }

    /// The last single-cycle transfer ran to terminal count.
    pub fn at_terminal_count(&self) -> bool {
        self.dma_tc
    }

    /// The guest read the active channel's count: it serviced the block
    /// (it computed where to refill). Extend the commit horizon so the mix
    /// may read the ring one full lap past this block.
    pub fn mark_block_serviced(&mut self) {
        if self.playing {
            self.blocks_acked = self.blocks_done;
        }
    }

    /// Live `(current_count, transfers_consumed)` derived from the play
    /// cursor, in the channel's own transfer units. The host adds `consumed`
    /// to the programmed base address for the address register.
    pub fn dma_cursor(&self) -> (u16, u16) {
        let channels = if self.stereo { 2u64 } else { 1 };
        let total = (self.buf_frames as u64 * channels).max(1); // transfers
        let consumed = (self.cursor * channels) % total;
        let count = total.wrapping_sub(1).wrapping_sub(consumed) as u16;
        (count, consumed as u16)
    }

    /// Read-and-clear the 8237 status-register TC bits this card latched.
    /// `high` selects the second controller's four channels.
    pub fn take_tc_status(&mut self, high: bool) -> u8 {
        let base = if high { 4 } else { 0 };
        let bits = (self.tc_status >> base) & 0x0F;
        self.tc_status &= !(0x0F << base);
        bits
    }
}

impl Default for Sb {
    fn default() -> Self {
        Self::new()
    }
}

/// Heap-construct the card. `Sb` carries the FM chip inline once created;
/// build it on the heap when the owner lives on a constrained stack.
pub fn new_boxed() -> Box<Sb> {
    Box::new(Sb::new())
}
