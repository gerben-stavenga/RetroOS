//! Gravis UltraSound (GF1) — the first card over the unified voice engine.
//!
//! The GF1 is *almost* the engine itself in hardware: 32 wavetable voices
//! reading a 1 MB onboard DRAM, hardware log-volume ramps, 16-position pan —
//! so this file is deliberately thin: a register file + DRAM + IRQ/timer
//! state, with every voice computation delegated to [`Engine`](crate::Engine).
//! Unlike the MT-32/SC-55 world there is no licensing wall: the DRAM starts
//! empty and the *guest* uploads all sample data (its own files, or the
//! ULTRASND driver patches), so the emulation ships complete.
//!
//! Register access follows the GF1 scheme: voice page at `base+0x102`,
//! register select at `base+0x103`, data low/high at `base+0x104/0x105`.
//! 8-bit registers live on the high-byte port; 16-bit registers split across
//! both (a guest word-OUT to `+0x104` arrives here as the two byte writes).
//! Register *side effects* fire on the high-byte write, the completing byte
//! of either width. DRAM peek/poke goes through `base+0x107` at the address
//! in global registers 0x43/0x44 (no auto-increment — real GF1s have none;
//! drivers rewrite the address every byte).
//!
//! Passive, per the crate contract: the chip never reads a clock, never
//! touches an interrupt controller, and never learns where its DMA channel
//! points. [`Gf1::tick`] is handed the time, [`Gf1::take_irq`] reports that
//! the line went active, and [`Gf1::dma_write`] takes bytes the host already
//! fetched. Which port base, IRQ and DMA channel the card is strapped to is
//! host configuration (the guest's `ULTRASND=` contract); only `base` is
//! needed here, to decode.

use crate::{Engine, LoopMode, volume};
use alloc::boxed::Box;

/// Onboard sample DRAM: we model a fully-populated 1 MB board (every real
/// sizing probe pokes powers-of-two boundaries below this and finds RAM).
const DRAM_LEN: usize = 1 << 20;

/// GF1 voice/current/loop addresses live in one 29-bit fixed-point value —
/// 20 integer bits, 9 fraction bits — split across a high/low register pair.
fn comb(hi: u16, lo: u16) -> u32 {
    ((hi as u32) << 16) | lo as u32
}

/// GF1 combined address → engine Q32.32. Both sides hold the *same*
/// width-agnostic GF1 address: the 16-bit bank/doubling transform lives at the
/// DRAM fetch (`engine::fetch`), not here. Keeping the translation out of the
/// register path is what lets a voice-control write leave a live position
/// alone — there is no width-dependent derivation left for it to redo.
fn addr_q32(c: u32) -> u64 {
    let a = ((c >> 9) & 0xFFFFF) as u64;
    let frac = (c & 0x1FF) as u64;
    (a << 32) | (frac << 23)
}

/// Engine Q32.32 → GF1 combined address (readback of live voice state).
fn q32_addr(q: u64) -> u32 {
    let a = ((q >> 32) & 0xFFFFF) as u32;
    let frac = ((q >> 23) & 0x1FF) as u32;
    (a << 9) | frac
}

/// GF1 16-position pan → Q12 stereo gains (0 = full left, 15 = full right).
///
/// Constant-power law: `left = cos θ`, `right = sin θ` with θ swept 0..90° so
/// `left² + right² == unity` at every position — the pan the GUS SDK specifies
/// ("output power is held constant") and what DOSBox Staging's
/// `PopulatePanScalars` builds. A *linear* law (what this used to do) drops the
/// summed power 3 dB at centre (position 7 = 0.53/0.47, power ≈ 0.50), which
/// hollows out centred voices and smears the stereo image — audible on GUS SFX
/// as a "hole in the middle" / mistimed-speaker depth. The table is precomputed
/// (Q12, rounded from the cos/sin arc) because the engine is float-free; note
/// the arc is *asymmetric* about centre (divisor 7 below, 8 at/above), so the
/// two columns are not mirror images.
fn pan_gains(p: u16) -> (u16, u16) {
    // dosbox-staging PopulatePanScalars, ×4096 rounded: norm = (i−7)/(i<7?7:8),
    // angle = (norm+1)·π/4, left = cos, right = sin.
    const PAN: [(u16, u16); 16] = [
        (4096, 0), (4070, 459), (3993, 911), (3866, 1353),
        (3690, 1777), (3468, 2179), (3202, 2554), (2896, 2896),
        (2598, 3166), (2276, 3406), (1931, 3612), (1567, 3784),
        (1189, 3920), (799, 4017), (401, 4076), (0, 4096),
    ];
    PAN[(p & 15) as usize]
}

/// The GF1 card: its strapped port base plus the lazily-built chip state.
/// A guest that never probes the GUS never pays for the 1 MB DRAM.
pub struct Gf1 {
    /// ULTRASND port base (0x2X0; the GF1 register block is base+0x100).
    pub base: u16,
    core: Option<Box<Core>>,
}

/// The heavy state, heap-built on the first decoded port touch (1 MB DRAM +
/// the engine).
struct Core {
    dram: Box<[u8]>,
    engine: Box<Engine>,
    // ── register-file state machine ──
    voice_sel: u8,
    reg_sel: u8,
    /// Raw per-voice register images (write indices 0x00-0x0D): the readback
    /// source for programming registers. Live values (current address 0x8A/
    /// 0x8B, current volume 0x89) derive from the engine at playback.
    vregs: [[u16; 16]; 32],
    /// Global registers, raw: DMA control 0x41, DMA start 0x42, DRAM I/O
    /// address 0x43 (low 16) / 0x44 (bits 19:16), timer control 0x45,
    /// timer counts 0x46/0x47, sampling 0x48/0x49, reset 0x4C.
    reg41: u8,
    reg42: u16,
    reg43: u16,
    reg44: u8,
    reg45: u8,
    reg46: u8,
    reg47: u8,
    reg48: u8,
    reg49: u8,
    /// Reset register 0x4C: bit0 = running (0 holds the chip in reset),
    /// bit1 = DAC enable, bit2 = GF1 master IRQ enable.
    reset_reg: u8,
    /// Active-voices register 0x0E, raw ((n−1) & 0x1F; hardware clamps 14-32).
    active_reg: u8,
    /// 2X0 mix-control latch; bit 6 selects what a 2XB write means.
    mix_ctrl: u8,
    /// 2XB IRQ- or DMA-control latch. Stored for readback shape only — the
    /// actual wiring is the host's ULTRASND contract, same policy as the SB's
    /// BLASTER (the guest telling us differs from what its env said would be a
    /// driver bug, not a reconfiguration).
    irq_dma_latch: u8,
    /// AdLib-compatible window (2X8/2X9) index latch. The GF1 exposes its
    /// two rate timers through this OPL-shaped port pair (SBOS and tracker
    /// players clock music off them); index 0x04 is the timer control.
    adlib_index: u8,
    timers: [Timer; 2],
    /// Per-voice wave/ramp IRQ pending masks — the FIFO register 0x8F pops
    /// the lowest set voice. Fed by the engine's Events at playback.
    wave_pending: u32,
    ramp_pending: u32,
    /// Host clock at the last [`Gf1::tick`] (pacing anchor for the timers).
    last_ms: u64,
    /// The line went active for a reason that is *not* a standing condition:
    /// a rate-timer expiry or a DMA terminal count. Drained by
    /// [`Gf1::take_irq`]; the voice/ramp masks are level-like and reported
    /// straight from `wave_pending`/`ramp_pending`.
    irq_edge: bool,
    /// A reg-0x41 write with the enable bit set armed an upload; it stays
    /// armed until the host feeds it (the card cannot fetch — it has no idea
    /// where its DMA channel points).
    dma_armed: bool,
    /// Running DRAM destination and bytes accepted so far for the armed
    /// transfer. Both exist so the host may feed in as many chunks as it
    /// likes — a byte per DRQ, or the whole thing at once.
    dma_dest: usize,
    dma_done: usize,
    /// DMA terminal count, poll-visible: 0x41 readback bit 6 and IRQ-status
    /// bit 7; cleared by reading 0x41 (the hardware ack).
    dma_tc: bool,
    /// TC wants the GF1 IRQ (reg-0x41 bit 5 was set): delivered on the next
    /// tick, the same deferral a real transfer's completion has.
    dma_irq_latch: bool,
}

/// One GF1 rate timer. T1 counts 80 µs units, T2 320 µs; each reloads and
/// keeps running (they are rate generators, not one-shots).
#[derive(Clone, Copy, Default)]
struct Timer {
    running: bool,
    /// AdLib-window mask bit: expiry doesn't reach the status bits.
    masked: bool,
    /// Latched expiry — the AdLib-style status flag, cleared by the timer-
    /// control reset write (2X9 index 4, bit 7).
    expired: bool,
    /// µs accumulated toward the next expiry.
    acc_us: u32,
}

impl Core {
    fn new_boxed() -> Box<Core> {
        // Both big members are heap-built in place; the struct itself is
        // small enough (~1.2 KB of registers) that a by-value move is fine.
        let mut c = Box::new(Core {
            dram: alloc::vec![0u8; DRAM_LEN].into_boxed_slice(),
            engine: Engine::new_boxed(),
            voice_sel: 0,
            reg_sel: 0,
            vregs: [[0; 16]; 32],
            reg41: 0, reg42: 0, reg43: 0, reg44: 0,
            reg45: 0, reg46: 0, reg47: 0, reg48: 0, reg49: 0,
            reset_reg: 0,
            active_reg: 13, // hardware default: 14 voices
            mix_ctrl: 0x0B, // line/mic off, latches disabled — power-on value
            irq_dma_latch: 0,
            adlib_index: 0,
            timers: [Timer::default(); 2],
            wave_pending: 0,
            ramp_pending: 0,
            last_ms: 0,
            irq_edge: false,
            dma_armed: false,
            dma_dest: 0,
            dma_done: 0,
            dma_tc: false,
            dma_irq_latch: false,
        });
        c.engine.active = 14; // matches active_reg's power-on 13 (n−1)
        c
    }

    /// Native output rate: the GF1 trades voices for rate — 44100 Hz at 14
    /// voices down to 19293 Hz at 32 (617400/voices, the SDK table; the
    /// same constant DOSBox and dosemu use).
    fn native_rate(&self) -> u32 {
        617_400 / (self.engine.active as u32).clamp(14, 32)
    }

    /// DRAM I/O address from global regs 0x43/0x44 (20 bits).
    fn dram_addr(&self) -> usize {
        (((self.reg44 as usize & 0x0F) << 16) | self.reg43 as usize) & (DRAM_LEN - 1)
    }

    /// Chip reset (reset register bit0 held low): every voice silenced,
    /// register images cleared, IRQ latches dropped. DRAM contents survive —
    /// as on hardware, where reset touches the synth, not the memory.
    fn chip_reset(&mut self) {
        self.engine.reset();
        self.engine.active = 14;
        self.vregs = [[0; 16]; 32];
        self.active_reg = 13;
        self.reg41 = 0;
        self.reg45 = 0;
        self.timers = [Timer::default(); 2];
        self.wave_pending = 0;
        self.ramp_pending = 0;
        self.irq_edge = false;
        self.dma_armed = false;
        self.dma_dest = 0;
        self.dma_done = 0;
        self.dma_tc = false;
        self.dma_irq_latch = false;
    }

    /// The 2X6 IRQ status byte: bit2/3 = timer 1/2 (gated by their reg-0x45
    /// enables), bit5 wave, bit6 ramp, bit7 DMA TC (lands with the upload).
    fn irq_status(&self) -> u8 {
        let mut s = 0u8;
        if self.timers[0].expired && self.reg45 & 0x04 != 0 {
            s |= 0x04;
        }
        if self.timers[1].expired && self.reg45 & 0x08 != 0 {
            s |= 0x08;
        }
        if self.wave_pending != 0 {
            s |= 0x20;
        }
        if self.ramp_pending != 0 {
            s |= 0x40;
        }
        if self.dma_tc {
            s |= 0x80;
        }
        s
    }

    /// The AdLib-compatible status byte at 2X8: bit6 = T1 expired, bit5 =
    /// T2 expired (mask bits suppress), bit7 = either. OPL-shaped on
    /// purpose — that's what SBOS-era probes poll.
    fn adlib_status(&self) -> u8 {
        let mut s = 0u8;
        if self.timers[0].expired && !self.timers[0].masked {
            s |= 0xC0;
        }
        if self.timers[1].expired && !self.timers[1].masked {
            s |= 0xA0;
        }
        s
    }
}

impl Gf1 {
    /// A powered-down card strapped to `base`. Nothing is allocated until a
    /// decoded port is touched.
    pub const fn new(base: u16) -> Self {
        Gf1 { base, core: None }
    }

    /// Re-strap the port base (the host learned the guest's ULTRASND wiring).
    pub fn set_base(&mut self, base: u16) {
        self.base = base;
    }

    /// Ports this card decodes: the GF1 decodes two 16-port ISA blocks,
    /// `base+0x000..0x010` (mix/IRQ-status/timers/latches) and
    /// `base+0x100..0x110` (MIDI + the GF1 register file + DRAM I/O).
    ///
    /// Whether the card is *present at all* is host policy — a machine with
    /// no `ULTRASND=` must leave these ports floating, and that decision is
    /// not the chip's to make.
    pub fn owns(&self, p: u16) -> bool {
        p.wrapping_sub(self.base) < 0x10 || p.wrapping_sub(self.base + 0x100) < 0x10
    }

    /// Drop all chip state: the next touch sees a power-on card. Program-exit
    /// cleanup, and the counterpart of pulling the board.
    ///
    /// A card that no longer exists must not still be asking for service, so
    /// the host must also drop any request it has already latched on its
    /// interrupt controller — dropping the core here cannot unlatch that.
    pub fn power_off(&mut self) {
        self.core = None;
    }

    /// Selected (register, voice) — for host-side access tracing only.
    /// Never allocates: an untouched card reports the power-on pair.
    pub fn sel(&self) -> (u8, u8) {
        self.core.as_ref().map_or((0, 0), |c| (c.reg_sel, c.voice_sel))
    }

    /// The DRAM peek/poke address the register file currently points at —
    /// for host-side access tracing only.
    pub fn dram_addr(&self) -> usize {
        self.core.as_ref().map_or(0, |c| c.dram_addr())
    }

    fn core(&mut self) -> &mut Core {
        self.core.get_or_insert_with(Core::new_boxed)
    }

    /// Guest IN from a decoded port.
    pub fn port_in(&mut self, p: u16) -> u8 {
        let base = self.base;
        let c = self.core();
        let lo = p.wrapping_sub(base);
        if lo < 0x10 {
            return match lo {
                // IRQ status: bit2 T1, bit3 T2, bit5 wave, bit6 ramp,
                // bit7 DMA-TC, bits0/1 MIDI.
                0x06 => c.irq_status(),
                // AdLib-compatible timer status window.
                0x08 => c.adlib_status(),
                // 2XA reads back the 2X8 index latch — THE classic GUS
                // detection (DMX writes 0xAA to 2X8 and expects it here;
                // a real AdLib puts its status there, never the echo).
                0x0A => c.adlib_index,
                // Board revision: 0xFF = pre-3.7 board, no extra registers —
                // the simplest personality every driver accepts.
                0x0F => 0xFF,
                _ => 0xFF,
            };
        }
        match p.wrapping_sub(base + 0x100) {
            // MIDI 6850 status: TX register empty, no RX byte. The GM/MPU
            // card wires this for real later.
            0x00 => 0x02,
            0x01 => 0x00,
            0x02 => c.voice_sel,
            0x03 => c.reg_sel,
            0x04 => c.reg_read(false),
            0x05 => c.reg_read(true),
            0x07 => c.dram[c.dram_addr()],
            _ => 0xFF,
        }
    }

    /// Guest OUT to a decoded port.
    pub fn port_out(&mut self, p: u16, val: u8) {
        let base = self.base;
        let c = self.core();
        let lo = p.wrapping_sub(base);
        if lo < 0x10 {
            match lo {
                0x00 => c.mix_ctrl = val,
                0x08 => c.adlib_index = val,
                0x09 => {
                    // The OPL-shaped timer control (index 4): bit7 resets the
                    // expiry flags; otherwise bits 0/1 start T1/T2 and bits
                    // 6/5 mask them out of the status byte.
                    if c.adlib_index == 0x04 {
                        if val & 0x80 != 0 {
                            c.timers[0].expired = false;
                            c.timers[1].expired = false;
                        } else {
                            c.timers[0].running = val & 0x01 != 0;
                            c.timers[1].running = val & 0x02 != 0;
                            c.timers[0].masked = val & 0x40 != 0;
                            c.timers[1].masked = val & 0x20 != 0;
                        }
                    }
                }
                0x0B => c.irq_dma_latch = val,
                _ => {}
            }
            return;
        }
        match p.wrapping_sub(base + 0x100) {
            0x00 | 0x01 => {} // MIDI ctrl/data: absorbed until the GM work
            0x02 => c.voice_sel = val & 0x1F,
            0x03 => c.reg_sel = val,
            0x04 => c.reg_write(false, val),
            0x05 => c.reg_write(true, val),
            0x07 => {
                let a = c.dram_addr();
                c.dram[a] = val;
            }
            _ => {}
        }
    }

    /// Advance the rate timers to `now_ms` (host clock, milliseconds).
    ///
    /// The GF1's two timers are rate generators: T1 counts 80 µs units, T2
    /// 320 µs, and the count register holds 256 − n. Multiple expiries inside
    /// one tick coalesce — an unserviced edge-latched line coalesces on
    /// hardware too.
    pub fn tick(&mut self, now_ms: u64) {
        let Some(c) = self.core.as_mut() else { return };
        // First tick / long background gap: don't synthesize a backlog.
        let dt = now_ms.saturating_sub(c.last_ms).min(100) as u32;
        c.last_ms = now_ms;
        if dt == 0 {
            return;
        }
        let (reg45, reg46, reg47) = (c.reg45, c.reg46, c.reg47);
        // A DMA terminal count from a completed upload delivers its IRQ here,
        // one tick later — a real transfer isn't instant either.
        let mut want_irq = core::mem::take(&mut c.dma_irq_latch);
        for (i, t) in c.timers.iter_mut().enumerate() {
            if !t.running {
                t.acc_us = 0;
                continue;
            }
            let unit = if i == 0 { 80u32 } else { 320 };
            let count = if i == 0 { reg46 } else { reg47 };
            let period = unit * (256 - count as u32);
            t.acc_us += dt * 1000;
            if t.acc_us >= period {
                t.acc_us %= period;
                t.expired = true;
                if reg45 & (0x04 << i) != 0 {
                    want_irq = true;
                }
            }
        }
        if want_irq {
            c.irq_edge = true;
        }
    }

    /// Whether the GF1 wants service, consuming the one-shot part of that
    /// claim. Master IRQ enable is reset-register bit 2.
    ///
    /// Two kinds of source are folded together here. Voice wave/ramp
    /// boundaries are *standing* — they sit in the guest-visible pending
    /// masks until the ISR pops register 0x8F — so they are reported for as
    /// long as they stand. Timer expiries and DMA terminal counts are
    /// one-shot edges and are drained by the call.
    ///
    /// The GF1 line is edge-latched into an 8259 in every real machine, so
    /// the host owns the "is a request already latched" question; this only
    /// answers "does the chip want the line".
    pub fn take_irq(&mut self) -> bool {
        let Some(c) = self.core.as_mut() else { return false };
        let edge = core::mem::take(&mut c.irq_edge);
        if c.reset_reg & 0x04 == 0 {
            return false; // master disabled: the edge is dropped, not queued
        }
        edge || (c.wave_pending | c.ramp_pending) != 0
    }

    // ── sample upload (the card end of a DMA cycle) ──────────────────────

    /// A guest-programmed upload is armed and waiting for bytes. The card
    /// knows a transfer was kicked and what to do with the data; it does not
    /// know which channel it sits on or where that points — the host holds
    /// the DMA controller and the guest's memory.
    pub fn dma_armed(&self) -> bool {
        self.core.as_ref().is_some_and(|c| c.dma_armed)
    }

    /// Direction of the armed transfer: `true` = host memory → card DRAM (a
    /// sample upload, the only direction that carries data here). `false` is
    /// the GF1's DRAM→host record path, which completes without data.
    pub fn dma_to_card(&self) -> bool {
        self.core.as_ref().is_some_and(|c| c.reg41 & 0x02 == 0)
    }

    /// Hand the card `bytes` the host moved on its DMA channel, applying the
    /// reg-0x41 transforms on the way into DRAM — bit7 = invert MSB
    /// (unsigned→signed samples; bit6 picks 8- vs 16-bit sample width). The
    /// 16-bit-channel address doubling (bit2) was applied to the destination
    /// when the transfer armed. Returns bytes accepted, which is short of
    /// `bytes.len()` only when the upload would run off the end of DRAM.
    ///
    /// `tc` marks the controller reaching terminal count with this chunk: it
    /// completes the transfer, latches the poll-visible TC state, and (when
    /// reg-0x41 bit 5 is set) arms the completion IRQ for the next tick.
    /// Feed in one chunk or a hundred — the card counts what it received.
    pub fn dma_write(&mut self, bytes: &[u8], tc: bool) -> usize {
        let Some(c) = self.core.as_mut() else { return 0 };
        if !c.dma_armed {
            return 0;
        }
        let mut n = 0;
        if c.reg41 & 0x02 == 0 {
            n = bytes.len().min(DRAM_LEN.saturating_sub(c.dma_dest));
            // Sixteen-bit sample data inverts only the high byte of each
            // frame; eight-bit data inverts every byte. The parity is taken
            // from the running transfer offset, not this chunk's, so a
            // chunked feed lands identically to a single-shot one.
            let invert = c.reg41 & 0x80 != 0;
            let wide = c.reg41 & 0x40 != 0;
            for (i, &b) in bytes[..n].iter().enumerate() {
                let flip = invert && (!wide || (c.dma_done + i) & 1 == 1);
                c.dram[c.dma_dest + i] = if flip { b ^ 0x80 } else { b };
            }
            c.dma_dest += n;
            c.dma_done += n;
        }
        if tc {
            c.dma_armed = false;
            c.dma_tc = true;
            c.dma_irq_latch = c.reg41 & 0x20 != 0;
        }
        n
    }

    // ── PCM ──────────────────────────────────────────────────────────────

    /// Any voice still producing (the host's "is this card audible" test).
    /// DAC enable is reset-register bit 1.
    pub fn mixing(&self) -> bool {
        self.core
            .as_ref()
            .is_some_and(|c| c.reset_reg & 0x02 != 0 && c.engine.any_running())
    }

    /// Sum wavetable output into `block` at the host's mix rate (chip-native
    /// steps, zero-order hold), scaled by `gain` in Q16 — how loud this card
    /// sits against the others is the host's mix policy, not the chip's.
    ///
    /// Voice wave/ramp boundaries latch straight into the guest-visible
    /// pending masks as the voice crosses them, on the GF1's own clock, with
    /// no reference to any sink. Nothing is raised from here: a mix may run
    /// arbitrarily far ahead of the speaker, so asserting an interrupt at the
    /// point a sample was *generated* would deliver it early. The host raises
    /// from [`take_irq`](Self::take_irq).
    pub fn mix_into(&mut self, rate: u32, gain: (i32, i32), block: &mut [(i32, i32)]) {
        if !self.mixing() {
            return;
        }
        let Some(c) = self.core.as_mut() else { return };
        let native = c.native_rate();
        for slot in block.iter_mut() {
            let mut ev = crate::Events::default();
            let (l, r) = c.engine.mix_frame(&c.dram, native, rate, &mut ev);
            slot.0 += (l * gain.0) >> 16;
            slot.1 += (r * gain.1) >> 16;
            c.wave_pending |= ev.wave_irq;
            c.ramp_pending |= ev.ramp_irq;
        }
    }
}

impl Core {
    /// Which global registers are 16-bit (split across both data ports).
    /// Everything else global is 8-bit on the high port.
    fn glob_is16(reg: u8) -> bool {
        matches!(reg, 0x42 | 0x43)
    }

    /// Which per-voice registers are 16-bit. 8-bit: control 0x00, ramp
    /// rate/start/end 0x06-0x08, pan 0x0C, ramp control 0x0D.
    fn voice_is16(reg: u8) -> bool {
        matches!(reg, 0x01..=0x05 | 0x09..=0x0B)
    }

    /// The ramp increment PER FRAME, converted from the GF1 rate register
    /// (0x06) into the engine's ramp-domain volume units.
    ///
    /// The two ends of a ramp come from the 8-bit start/end registers, which
    /// hold the volume's TOP byte (`reg << 8`). The rate register's 6-bit
    /// increment is *not* in those units: it steps the volume's 12-bit
    /// significand, whose LSB is bit 4 of the 16-bit volume word. Hence `<< 4`.
    ///
    /// Getting this wrong is not a subtle detune — an unscaled increment makes
    /// every ramp 16x too long (a 1.5 ms attack becomes 24 ms), and DMX polls
    /// the ramp-done bit with interrupts disabled, so the guest sits in that
    /// spin long enough to miss its own 140 Hz music ticks.
    ///
    /// Bits 7..6 are the update-rate divider (1/8/64/512). They are folded in
    /// HERE, as a per-frame fractional rate, rather than paced by a countdown
    /// in the engine: DMX rewrites a voice's ramp roughly every 20 ms, which is
    /// shorter than the slow dividers' own period, so a countdown kept getting
    /// reset before it fired and the ramp made no progress at all. Both
    /// DOSBox Staging (`WriteVolRate`) and 86Box (`rfreq`) fold it the same way
    /// for the same reason — the extra `RAMP_FRACT` bits are what make a
    /// sub-unit-per-frame rate representable.
    fn ramp_inc(rate_reg: u16) -> i32 {
        let per_update = ((rate_reg & 0x3F) as i32) << 4;
        (per_update << volume::RAMP_FRACT) >> (3 * (rate_reg >> 6).min(3))
    }

    /// An 8-bit ramp bound register (0x07/0x08) into ramp-domain volume: the
    /// register holds the volume's top byte, then the ramp's fractional bits.
    fn ramp_bound(reg: u16) -> i32 {
        ((reg & 0xFF) as i32) << (8 + volume::RAMP_FRACT)
    }

    /// Byte write to the selected register (`high` = data-high port). The
    /// high byte completes a write for either width, so that's where the
    /// register's side effect fires (voice start, DMA kick, reset).
    fn reg_write(&mut self, high: bool, val: u8) {
        let reg = self.reg_sel;
        match reg {
            0x00..=0x0D => {
                let vi = self.voice_sel as usize;
                let slot = &mut self.vregs[vi][reg as usize];
                if Self::voice_is16(reg) {
                    if high {
                        *slot = (*slot & 0x00FF) | ((val as u16) << 8);
                    } else {
                        *slot = (*slot & 0xFF00) | val as u16;
                    }
                } else if high {
                    *slot = val as u16;
                }
                if high {
                    self.voice_reg_effect(vi, reg);
                }
            }
            0x0E if high => {
                self.active_reg = val & 0x3F;
                // (n−1) encoding; hardware clamps to the 14..32 range, and
                // the native output rate follows from the count.
                self.engine.active = (((val & 0x1F) as u32) + 1).clamp(14, 32) as u8;
            }
            0x41 if high => {
                self.reg41 = val;
                // Enable bit set = arm an upload. The destination is resolved
                // now, from reg 0x42 (<<4), including the 16-bit-channel
                // address doubling; the host feeds the bytes.
                if val & 0x01 != 0 {
                    let mut dest = (self.reg42 as usize) << 4;
                    if val & 0x04 != 0 {
                        dest = (dest & 0xC0000) | ((dest & 0x1FFFF) << 1);
                    }
                    self.dma_armed = true;
                    self.dma_dest = dest.min(DRAM_LEN);
                    self.dma_done = 0;
                }
            }
            0x42 => {
                if high {
                    self.reg42 = (self.reg42 & 0x00FF) | ((val as u16) << 8);
                } else {
                    self.reg42 = (self.reg42 & 0xFF00) | val as u16;
                }
            }
            0x43 => {
                if high {
                    self.reg43 = (self.reg43 & 0x00FF) | ((val as u16) << 8);
                } else {
                    self.reg43 = (self.reg43 & 0xFF00) | val as u16;
                }
            }
            0x44 if high => self.reg44 = val,
            // Timer control / IRQ enable (bit2 = T1, bit3 = T2). Dropping a
            // timer's enable bit is also its IRQ ACK: on the GF1 that clears the
            // latched overflow, exactly as it de-asserts the line. Music drivers
            // (Duke3D's GUS player) ack the timer purely through 0x45 — write 0
            // then re-arm — and never touch the AdLib 2X9 reset. Without clearing
            // `expired` here, `irq_status` keeps returning the timer bit, the ISR
            // sees T2 forever pending, and the IRQ storms → the mainline starves
            // (the GUS-music-while-SB-sfx hang). The 2X9 reset path still clears
            // `expired` independently for SBOS-style pollers.
            0x45 if high => {
                if val & 0x04 == 0 {
                    self.timers[0].expired = false;
                }
                if val & 0x08 == 0 {
                    self.timers[1].expired = false;
                }
                self.reg45 = val;
            }
            0x46 if high => self.reg46 = val,
            0x47 if high => self.reg47 = val,
            0x48 if high => self.reg48 = val,
            0x49 if high => self.reg49 = val,
            0x4C if high => {
                // Bit0 low holds the chip in reset; the 0→bit0 write is the
                // moment everything clears. Bits 1/2 (DAC, IRQ enable) only
                // mean anything while running.
                if val & 0x01 == 0 {
                    self.chip_reset();
                }
                self.reset_reg = val & 0x07;
            }
            _ => {}
        }
    }

    /// Map one just-written per-voice register onto the engine voice. The
    /// raw images in `vregs` stay the source of truth for programming
    /// readback; the engine holds the live playing state.
    fn voice_reg_effect(&mut self, vi: usize, reg: u8) {
        let raw = self.vregs[vi];
        let v = &mut self.engine.voices[vi];
        match reg {
            0x00 => {
                let ctrl = raw[0] as u8;
                v.bits16 = ctrl & 0x04 != 0;
                v.loop_mode = if ctrl & 0x08 != 0 {
                    if ctrl & 0x10 != 0 { LoopMode::Bidi } else { LoopMode::Forward }
                } else {
                    LoopMode::None
                };
                v.irq_on_end = ctrl & 0x20 != 0;
                v.backwards = ctrl & 0x40 != 0;
                // Mode bits and run/stop ONLY — a control write must not touch
                // the position. On the GF1 the current-address counter is
                // loaded by writes to registers 0x0A/0x0B and by nothing else;
                // DOSBox Staging's `UpdateCtrlState` is the same shape (it
                // writes `state` and the IRQ mask, never `pos`).
                //
                // This used to re-derive start/end/addr from the register
                // images here, because the old engine translated addresses for
                // the 16-bit bank layout at *write* time and so needed the
                // width this write declares. That guess cost a live voice its
                // position on every mid-note control write — the loop-bit clear
                // at sustain→release, or an IRQ-acknowledging read-modify-write
                // — teleporting it back to its note-on address (or to DRAM 0,
                // if the driver never rewrote 0x0A/0x0B). Now that the width
                // transform happens at fetch, there is nothing to re-derive.
                // Measured on DOOM's DMX driver: it re-writes voice control
                // ~20x/second on already-running voices while leaving 0x0A/0x0B
                // at the note-on value, so the old reload dragged live voices
                // back by up to ~10000 samples that often — every note kept
                // restarting its attack instead of reaching its sustain loop.
                v.running = ctrl & 0x03 == 0;
            }
            // Frequency control: the GF1 adds FC/2 per output frame in
            // 9-bit-fraction address units.
            0x01 => v.inc = ((raw[1] >> 1) as u64) << 23,
            0x02 | 0x03 => v.start = addr_q32(comb(raw[2], raw[3])),
            0x04 | 0x05 => v.end = addr_q32(comb(raw[4], raw[5])),
            0x06 => v.ramp.inc = Self::ramp_inc(raw[6]),
            0x07 => v.ramp.floor = Self::ramp_bound(raw[7]),
            0x08 => v.ramp.ceil = Self::ramp_bound(raw[8]),
            0x09 => v.vol = (raw[9] as i32) << volume::RAMP_FRACT,
            0x0A | 0x0B => v.addr = addr_q32(comb(raw[0xA], raw[0xB])),
            0x0C => {
                let (l, r) = pan_gains(raw[0xC]);
                v.pan_l = l;
                v.pan_r = r;
            }
            0x0D => {
                let rc = raw[0xD] as u8;
                v.rollover = rc & 0x04 != 0;
                v.ramp.looped = rc & 0x08 != 0;
                v.ramp.bidi = rc & 0x10 != 0;
                v.ramp.irq = rc & 0x20 != 0;
                v.ramp.down = rc & 0x40 != 0;
                if rc & 0x03 != 0 {
                    v.ramp.running = false;
                } else {
                    // Ramp start snapshots rate + bounds from their images.
                    // Note there is deliberately no pacing state to (re)set
                    // here — see `ramp_inc`. A rewrite must not cost progress.
                    v.ramp.inc = Self::ramp_inc(raw[6]);
                    v.ramp.floor = Self::ramp_bound(raw[7]);
                    v.ramp.ceil = Self::ramp_bound(raw[8]);
                    v.ramp.running = true;
                }
            }
            _ => {}
        }
    }

    /// Byte read of the selected register. Reads use the `0x80 | index`
    /// aliases for per-voice registers (hardware convention); programming
    /// registers echo their images, live state (current address/volume,
    /// stopped bits, IRQ-pending bits) comes from the engine.
    fn reg_read(&mut self, high: bool) -> u8 {
        let reg = self.reg_sel;
        let word = match reg {
            // Voice control: mode bits from the image, stopped state from
            // the engine, bit7 = wave IRQ pending for this voice.
            0x80 => {
                let vi = self.voice_sel as usize;
                let mut r = self.vregs[vi][0] & 0x7C;
                if !self.engine.voices[vi].running {
                    r |= 0x03;
                }
                if self.wave_pending & (1 << vi) != 0 {
                    r |= 0x80;
                }
                r
            }
            // Current volume / current address: live engine state.
            0x89 => (self.engine.voices[self.voice_sel as usize].vol >> volume::RAMP_FRACT)
                .clamp(0, 0xFFFF) as u16,
            0x8A | 0x8B => {
                let v = &self.engine.voices[self.voice_sel as usize];
                let c = q32_addr(v.addr);
                if reg == 0x8A { (c >> 16) as u16 } else { c as u16 }
            }
            // Ramp control: same composition as voice control.
            0x8D => {
                let vi = self.voice_sel as usize;
                let mut r = self.vregs[vi][0x0D] & 0x7C;
                if !self.engine.voices[vi].ramp.running {
                    r |= 0x03;
                }
                if self.ramp_pending & (1 << vi) != 0 {
                    r |= 0x80;
                }
                r
            }
            0x81..=0x8C => {
                let idx = (reg & 0x0F) as usize;
                self.vregs[self.voice_sel as usize][idx]
            }
            // Active voices: hardware sets the top two bits on readback.
            0x8E => 0xC0 | self.active_reg as u16,
            // Voice IRQ source: pop the lowest pending voice. Flag bits are
            // ACTIVE LOW (bit7 clear = wave IRQ, bit6 clear = ramp IRQ);
            // no voice pending reads 0xE0. Reading consumes the voice's
            // pending bits — the hardware FIFO drain loop every GUS ISR runs.
            0x8F => {
                let pend = self.wave_pending | self.ramp_pending;
                if pend == 0 {
                    0xE0
                } else {
                    let v = pend.trailing_zeros();
                    let mut r = v as u16 | 0x20;
                    if self.wave_pending & (1 << v) == 0 {
                        r |= 0x80;
                    }
                    if self.ramp_pending & (1 << v) == 0 {
                        r |= 0x40;
                    }
                    self.wave_pending &= !(1 << v);
                    self.ramp_pending &= !(1 << v);
                    r
                }
            }
            // DMA control readback: bit6 = terminal count reached; reading
            // is the ack (clears it and the IRQ-status bit).
            0x41 => {
                let r = (self.reg41 & 0xBF) as u16 | if self.dma_tc { 0x40 } else { 0 };
                self.dma_tc = false;
                r
            }
            0x45 => self.reg45 as u16,
            0x49 => self.reg49 as u16,
            0x4C => self.reset_reg as u16,
            _ => 0xFF,
        };
        let is16 = matches!(reg, 0x80..=0x8D if Self::voice_is16(reg & 0x0F))
            || Self::glob_is16(reg);
        if is16 {
            if high { (word >> 8) as u8 } else { word as u8 }
        } else {
            word as u8
        }
    }
}
