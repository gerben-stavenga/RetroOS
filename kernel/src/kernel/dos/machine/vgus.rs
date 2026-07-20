//! Virtual Gravis UltraSound (GF1) — the first personality over the unified
//! sampler engine (`//lib:sampler`).
//!
//! The GF1 is *almost* the engine itself in hardware: 32 wavetable voices
//! reading a 1 MB onboard DRAM, hardware log-volume ramps, 16-position pan —
//! so this file is deliberately thin: a register file + DRAM + IRQ/timer
//! glue, with every voice computation delegated to [`sampler::Engine`].
//! Unlike the MT-32/SC-55 world there is no licensing wall: the DRAM starts
//! empty and the *guest* uploads all sample data (its own files, or the
//! ULTRASND driver patches on C:), so the emulation ships complete.
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
//! Configuration comes from the guest's `ULTRASND=<base>,<dma>,<rdma>,
//! <irq>,<midi irq>` env var, the exact contract real drivers use; without
//! it the device stays absent (`owns` never claims a port).

use super::*;

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
/// DRAM fetch (`sampler::fetch`), not here. Keeping the translation out of the
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

/// GF1 16-position pan → Q12 stereo gains (0 = full left, 15 = full right;
/// linear law, unity 4096).
fn pan_gains(p: u16) -> (u16, u16) {
    let p = (p & 15) as u32;
    ((((15 - p) * 4096) / 15) as u16, ((p * 4096) / 15) as u16)
}

/// Always-present, tiny per-thread GUS state: the ULTRASND wiring and the
/// lazily-built core. Mirrors `SoundBlaster`'s shape — config outside,
/// heavy state behind an `Option`.
pub struct Gus {
    pub base: u16,   // ULTRASND port base (0x2X0; the GF1 block is base+0x100)
    pub irq: u8,     // ULTRASND GF1 IRQ (wave/ramp/DMA-TC/timers)
    pub dma_ch: u8,  // ULTRASND play DMA channel (sample upload)
    /// `ULTRASND=` seen in this program's env — the device exists. Absent
    /// hardware must stay absent: `owns` gates on this, so probes read 0xFF.
    pub present: bool,
    core: Option<alloc::boxed::Box<GusCore>>,
}

/// The heavy state, heap-built on the first decoded port touch (1 MB DRAM +
/// the engine; a program that never probes the GUS pays nothing).
struct GusCore {
    dram: alloc::boxed::Box<[u8]>,
    engine: alloc::boxed::Box<sampler::Engine>,
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
    /// actual wiring is the kernel's ULTRASND contract, same policy as the
    /// SB's BLASTER (the guest telling us differs from what its env said
    /// would be a driver bug, not a reconfiguration).
    irq_dma_latch: u8,
    /// AdLib-compatible window (2X8/2X9) index latch. The GF1 exposes its
    /// two rate timers through this OPL-shaped port pair (SBOS and tracker
    /// players clock music off them); index 0x04 is the timer control.
    adlib_index: u8,
    timers: [GusTimer; 2],
    /// Per-voice wave/ramp IRQ pending masks — the FIFO register 0x8F pops
    /// the lowest set voice. Fed by the engine's Events at playback.
    wave_pending: u32,
    ramp_pending: u32,
    /// `get_ticks()` at the last `tick` (virtual-time pacing anchor).
    last_ms: u64,
    /// Voice wave/ramp events discovered while mixing, stamped with the
    /// mixer-session frame they occur at: `(frame, wave_mask, ramp_mask)`.
    /// [`Gus::deliver_events`] latches them into the guest-visible pending
    /// masks and raises the GF1 IRQ when the sink's drain clock crosses the
    /// frame — audible-exact delivery, like the SB's block IRQs.
    events: alloc::collections::VecDeque<(u64, u32, u32)>,
    /// A reg-0x41 write with the enable bit set: the upload is serviced by
    /// `service_dma` right after the register write returns (it needs the
    /// machine and the 8237 shadow, which the register file never sees).
    dma_kick: bool,
    /// DMA terminal count, poll-visible: 0x41 readback bit 6 and IRQ-status
    /// bit 7; cleared by reading 0x41 (the hardware ack).
    dma_tc: bool,
    /// TC wants the GF1 IRQ (reg-0x41 bit 5 was set): delivered on the next
    /// tick, the same deferral the SB uses for its trigger IRQ.
    dma_irq_latch: bool,
}

/// One GF1 rate timer. T1 counts 80 µs units, T2 320 µs; each reloads and
/// keeps running (they are rate generators, not one-shots).
#[derive(Clone, Copy, Default)]
struct GusTimer {
    running: bool,
    /// AdLib-window mask bit: expiry doesn't reach the status bits.
    masked: bool,
    /// Latched expiry — the AdLib-style status flag, cleared by the timer-
    /// control reset write (2X9 index 4, bit 7).
    expired: bool,
    /// µs accumulated toward the next expiry.
    acc_us: u32,
}

impl GusCore {
    fn new_boxed() -> alloc::boxed::Box<GusCore> {
        // Both big members are heap-built in place; the struct itself is
        // small enough (~1.2 KB of registers) that a by-value move is fine.
        let mut c = alloc::boxed::Box::new(GusCore {
            dram: alloc::vec![0u8; DRAM_LEN].into_boxed_slice(),
            engine: sampler::Engine::new_boxed(),
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
            timers: [GusTimer::default(); 2],
            wave_pending: 0,
            ramp_pending: 0,
            last_ms: 0,
            events: alloc::collections::VecDeque::new(),
            dma_kick: false,
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
        self.timers = [GusTimer::default(); 2];
        self.wave_pending = 0;
        self.ramp_pending = 0;
        self.events.clear();
        self.dma_kick = false;
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

impl Gus {
    /// Absent until the program's env declares it (ULTRASND).
    pub fn new() -> Self {
        Gus { base: 0x240, irq: 5, dma_ch: 3, present: false, core: None }
    }

    /// Ports this card decodes: the GF1 decodes two 16-port ISA blocks,
    /// `base+0x000..0x010` (mix/IRQ-status/timers/latches) and
    /// `base+0x100..0x110` (MIDI + the GF1 register file + DRAM I/O).
    pub fn owns(&self, p: u16) -> bool {
        self.present
            && (p.wrapping_sub(self.base) < 0x10 || p.wrapping_sub(self.base + 0x100) < 0x10)
    }

    /// Apply this thread's `ULTRASND=<base>,<playdma>,<recdma>,<gf1irq>,
    /// <midiirq>` env string (base in hex, the rest decimal — the format
    /// every real driver and game setup writes). Missing/malformed values
    /// leave the defaults; the var's presence alone makes the card exist.
    pub fn configure_from_env(&mut self, env: &[u8]) {
        let Some(val) = env_var(env, b"ULTRASND") else { return };
        self.present = true;
        let mut it = val.split(|&b| b == b',');
        if let Some(n) = it.next().and_then(|t| parse_uint(t, 16)) {
            self.base = n as u16;
        }
        if let Some(n) = it.next().and_then(|t| parse_uint(t, 10)) {
            self.dma_ch = n as u8;
        }
        let _ = it.next(); // record DMA channel: recording is not modeled
        if let Some(n) = it.next().and_then(|t| parse_uint(t, 10)) {
            self.irq = n as u8;
        }
        // One line per program launch: which wiring this program's GUS got.
        // The counterpart of DMX's own "GUS1/GUS2 vs ain't responding" —
        // together they answer every "why is there no GUS music" report.
        crate::dbg_println!(
            "[gus] ULTRASND base={:03X} irq={} dma={}",
            self.base, self.irq, self.dma_ch
        );
    }

    /// Program-exit / exec cleanup: drop the whole core so the next program
    /// sees a power-on card (same lifecycle as the SB's `release_dma_pool`
    /// and the per-program OPL chip).
    pub fn reset<A: crate::Arch>(&mut self, machine: &mut A, vpic: &mut VirtualPic) {
        let _ = machine; // stream lifecycle is the mixer pump's (it parks on idle)
        // Lower the GF1 line as well as dropping the core. A voice/timer event
        // may already have latched the IRQ in the vPIC's IRR; dropping the card
        // does not unlatch it, so it stays pending and is delivered AFTER the
        // owning program is gone — straight through the interrupt vector that
        // program installed, into memory that has since been freed and reused.
        // That is a #UD on garbage (Hocus Pocus's GUS IRQ killing the shell
        // after HOCUSG.BAT finished). A card that no longer exists must not
        // still be asking for service.
        vpic.clear_request(self.irq);
        self.core = None;
        self.present = false;
    }

    /// Mixer-session restart: stamped event frames from the previous session
    /// numbering are meaningless — drop them.
    pub fn on_mix_session(&mut self) {
        if let Some(c) = self.core.as_mut() {
            c.events.clear();
        }
    }

    /// Deliver voice events whose stream frame the sink has played past
    /// (`drained` = the mixer's drain clock): latch the guest-visible
    /// pending masks and request the GF1 IRQ line (master enable is
    /// reset-register bit 2).
    pub fn deliver_events(&mut self, drained: u64, vpic: &mut super::vpic::VirtualPic) {
        let Some(c) = self.core.as_mut() else { return };
        let mut want_irq = false;
        while c.events.front().is_some_and(|&(f, _, _)| f <= drained) {
            let (_, wave, ramp) = c.events.pop_front().unwrap();
            c.wave_pending |= wave;
            c.ramp_pending |= ramp;
            want_irq = true;
        }
        if want_irq && c.reset_reg & 0x04 != 0 && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Per-quantum device tick, from `machine::audio_tick`: pace the rate
    /// timers by virtual time and raise the GF1 IRQ line for enabled,
    /// unserviced sources. Playback runs through the mixer pump (the
    /// common PCM-source path below); voice-event IRQs deliver separately, on the
    /// pump's drain clock ([`Gus::deliver_events`]).
    pub fn tick<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        vpic: &mut super::vpic::VirtualPic,
    ) {
        let Some(c) = self.core.as_mut() else { return };
        let now = machine.get_ticks();
        // First tick / long background gap: don't synthesize a backlog.
        let dt = now.saturating_sub(c.last_ms).min(100) as u32;
        c.last_ms = now;
        if dt == 0 {
            return;
        }
        let (reg45, reg46, reg47) = (c.reg45, c.reg46, c.reg47);
        // A DMA terminal count from the last register write delivers its IRQ
        // here, one tick later — a real transfer isn't instant either.
        let mut want_irq = core::mem::take(&mut c.dma_irq_latch);
        for (i, t) in c.timers.iter_mut().enumerate() {
            if !t.running {
                t.acc_us = 0;
                continue;
            }
            // T1 counts 80 µs units, T2 320 µs; the count register holds
            // 256 − n. Multiple expiries inside one ms tick coalesce — an
            // unserviced edge-latched 8259 line coalesces on hardware too.
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
        // Master IRQ enable is reset-register bit 2.
        if want_irq && c.reset_reg & 0x04 != 0 && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    fn core(&mut self) -> &mut GusCore {
        self.core.get_or_insert_with(GusCore::new_boxed)
    }

    /// Guest IN from a decoded port.
    pub fn io_read<A: crate::Arch>(&mut self, machine: &mut A, p: u16) -> u8 {
        let _ = machine;
        let base = self.base;
        let c = self.core();
        if super::PORT_TRACE {
            crate::dbg_println!("[gus] in  {:03X} (reg {:02X}v{})", p, c.reg_sel, c.voice_sel);
        }
        let lo = p.wrapping_sub(base);
        let v = if lo < 0x10 {
            match lo {
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
            }
        } else {
            let hi = p.wrapping_sub(base + 0x100);
            match hi {
                // MIDI 6850 status: TX register empty, no RX byte. The GM/MPU
                // personality wires this for real later.
                0x00 => 0x02,
                0x01 => 0x00,
                0x02 => c.voice_sel,
                0x03 => c.reg_sel,
                0x04 => c.reg_read(false),
                0x05 => c.reg_read(true),
                0x07 => {
                    let a = c.dram_addr();
                    if super::PORT_TRACE {
                        crate::dbg_println!("[gus] peek [{:05X}]={:02X}", a, c.dram[a]);
                    }
                    c.dram[a]
                }
                _ => 0xFF,
            }
        };
        gus_ring_record(false, p, v, c.reg_sel, c.voice_sel);
        v
    }

    /// Guest OUT to a decoded port.
    pub fn io_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        let base = self.base;
        let c = self.core();
        if super::PORT_TRACE {
            crate::dbg_println!("[gus] out {:03X} <- {:02X} (reg {:02X}v{})", p, val, c.reg_sel, c.voice_sel);
        }
        gus_ring_record(true, p, val, c.reg_sel, c.voice_sel);
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
        let hi = p.wrapping_sub(base + 0x100);
        match hi {
            0x00 | 0x01 => {} // MIDI ctrl/data: absorbed until the GM work
            0x02 => c.voice_sel = val & 0x1F,
            0x03 => c.reg_sel = val,
            0x04 => c.reg_write(false, val),
            0x05 => {
                c.reg_write(true, val);
                // A completed reg-0x41 write with the enable bit kicks an
                // upload; it runs here, where the machine and 8237 live.
                self.service_dma(machine, dma);
            }
            0x07 => {
                let a = c.dram_addr();
                if super::PORT_TRACE {
                    crate::dbg_println!("[gus] poke [{:05X}]={:02X}", a, val);
                }
                c.dram[a] = val;
            }
            _ => {}
        }
    }

    /// Service a kicked GF1 DMA transfer: move the guest buffer the virtual
    /// 8237 was programmed with into DRAM at (reg 0x42 << 4), applying the
    /// reg-0x41 transforms — bit2 = 16-bit ISA channel (bank-preserving
    /// address doubling, like 16-bit voice fetches), bit7 = invert MSB
    /// (unsigned→signed samples; bit6 picks 8- vs 16-bit sample width).
    /// Terminal count latches poll-visible state; the IRQ (bit5) is raised
    /// on the next tick — the same deferral the SB's trigger IRQ uses.
    fn service_dma<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237) {
        let ch = self.dma_ch as usize;
        let Some(c) = self.core.as_mut() else { return };
        if !core::mem::take(&mut c.dma_kick) {
            return;
        }
        // Direction bit set = DRAM→host (recording): complete without data.
        if c.reg41 & 0x02 == 0 && ch < 8 {
            let is16_chan = ch >= 4;
            let p = dma.ch[ch].prog;
            let (gpa, len) = chan_gpa_len(&p, is16_chan);
            let mut dest = (c.reg42 as usize) << 4;
            if c.reg41 & 0x04 != 0 {
                dest = (dest & 0xC0000) | ((dest & 0x1FFFF) << 1);
            }
            let len = (len as usize).min(DRAM_LEN.saturating_sub(dest));
            if len > 0 {
                let mut buf = alloc::vec![0u8; len];
                machine.copy_from(gpa as usize, &mut buf);
                if c.reg41 & 0x80 != 0 {
                    if c.reg41 & 0x40 != 0 {
                        for b in buf.iter_mut().skip(1).step_by(2) {
                            *b ^= 0x80;
                        }
                    } else {
                        for b in buf.iter_mut() {
                            *b ^= 0x80;
                        }
                    }
                }
                c.dram[dest..dest + len].copy_from_slice(&buf);
            }
        }
        c.dma_tc = true;
        c.dma_irq_latch = c.reg41 & 0x20 != 0;
    }
}

impl GusCore {
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

    /// The ramp increment, converted from the GF1 rate register (0x06) into the
    /// sampler's log-volume domain.
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
    fn ramp_inc(rate_reg: u16) -> u16 {
        (rate_reg & 0x3F) << 4
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
                // Enable bit set = kick an upload; serviced right after this
                // OUT returns (io_write has the machine + 8237 shadow).
                self.dma_kick = val & 0x01 != 0;
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
                    if ctrl & 0x10 != 0 { sampler::LoopMode::Bidi } else { sampler::LoopMode::Forward }
                } else {
                    sampler::LoopMode::None
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
            0x06 => {
                v.ramp.inc = Self::ramp_inc(raw[6]);
                v.ramp.shift = (raw[6] >> 6) as u8;
            }
            0x07 => v.ramp.floor = ((raw[7] & 0xFF) as i32) << 8,
            0x08 => v.ramp.ceil = ((raw[8] & 0xFF) as i32) << 8,
            0x09 => v.vol = raw[9] as i32,
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
                    v.ramp.inc = Self::ramp_inc(raw[6]);
                    v.ramp.shift = (raw[6] >> 6) as u8;
                    v.ramp.floor = ((raw[7] & 0xFF) as i32) << 8;
                    v.ramp.ceil = ((raw[8] & 0xFF) as i32) << 8;
                    v.ramp.frames_to_next = 1u16 << (3 * v.ramp.shift.min(3));
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
            0x89 => self.engine.voices[self.voice_sel as usize].vol.clamp(0, 0xFFFF) as u16,
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

/// The sink-owning DSP stream pulls GUS voices per frame while it plays —
/// the same canonical shape the OPL uses. Voice-boundary events latch for
/// the next tick's IRQ delivery (the vPIC isn't reachable from a pull).
impl Gus {
    pub(super) fn mixing(&self) -> bool {
        self.core
            .as_ref()
            .is_some_and(|c| c.reset_reg & 0x02 != 0 && c.engine.any_running())
    }

    /// Add wavetable output at the pump's rate (chip-native steps, zero-order
    /// hold), summing saturating. Voice wave/ramp events are stamped with the
    /// exact session frame they occur at and queued for [`Gus::deliver_events`]
    /// — they become guest-visible when that frame *plays*, not when it is
    /// generated `fill` early.
    pub(super) fn mix_into<A: crate::Arch>(&mut self, _machine: &mut A, rate: u32, base: u64, block: &mut [(i32, i32)]) {
        if !self.mixing() {
            return;
        }
        let Some(c) = self.core.as_mut() else { return };
        let native = c.native_rate();
        // Process every position in this final PCM block. `mix_frame` advances
        // the GF1/native-rate phase as needed; each native step walks all
        // active voices, including address/loop/stop and volume-ramp state.
        for (i, slot) in block.iter_mut().enumerate() {
            let mut ev = sampler::Events::default();
            let (l, r) = c.engine.mix_frame(&c.dram, native, rate, &mut ev);
            // Unity — the GF1's output is the mixer's reference level (86Box
            // `gus_get_buffer` adds it straight in) and the GUS has no guest
            // master volume; the per-voice ramps already carry it.
            slot.0 += (l * super::vsb::GUS_SCALE_Q16) >> 16;
            slot.1 += (r * super::vsb::GUS_SCALE_Q16) >> 16;
            if ev.any() {
                let at = base + i as u64;
                match c.events.back_mut() {
                    Some(e) if e.0 == at => {
                        e.1 |= ev.wave_irq;
                        e.2 |= ev.ramp_irq;
                    }
                    _ => c.events.push_back((at, ev.wave_irq, ev.ramp_irq)),
                }
            }
        }
    }
}

// ── Zero-perturbation GUS-access trace ring ──────────────────────────────
// One entry per decoded GUS port IN/OUT, written inline (pure stores, no I/O,
// no formatting) so it doesn't change instruction timing — the same idiom the
// virtual-IF ring (`mode_transitions::IF_RING`) uses, and for the same reason:
// the Duke3D "wedged in the GUS music ISR" hang is timing-sensitive and
// print-tracing (PORT_TRACE) hides it. Dumped only on the F12 state key via
// `dump_gus_ring()`, alongside the IF ring.
#[derive(Clone, Copy)]
struct GusEvt {
    write: bool,     // true = OUT, false = IN
    in_irq: bool,    // true = recorded while servicing a HW IRQ (ISR context)
    port: u16,
    val: u8,
    reg_sel: u8,     // selected GF1 register at access time
    voice_sel: u8,   // selected voice at access time
}

const GUS_RING_LEN: usize = 128;
static mut GUS_RING: [GusEvt; GUS_RING_LEN] = [GusEvt {
    write: false, in_irq: false, port: 0, val: 0, reg_sel: 0, voice_sel: 0,
}; GUS_RING_LEN];
static mut GUS_RING_POS: usize = 0;

#[inline]
fn gus_ring_record(write: bool, port: u16, val: u8, reg_sel: u8, voice_sel: u8) {
    let in_irq = super::super::IN_HW_IRQ_CONTEXT
        .load(core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let i = GUS_RING_POS % GUS_RING_LEN;
        GUS_RING[i] = GusEvt { write, in_irq, port, val, reg_sel, voice_sel };
        GUS_RING_POS = GUS_RING_POS.wrapping_add(1);
    }
}

/// F12 hook: dump the most recent GUS port accesses (oldest first). A stuck
/// GUS ISR shows up as a short cycle of the same (port, reg) repeating with
/// `irq=1`; an IRQ storm shows the same ISR-drain prologue re-appearing over
/// and over. `total` is the lifetime access count.
pub fn dump_gus_ring() {
    unsafe {
        let pos = GUS_RING_POS;
        let n = pos.min(GUS_RING_LEN);
        crate::dbg_println!("[GUSRING] {} accesses total, showing last {}", pos, n);
        for k in 0..n {
            let i = (pos - n + k) % GUS_RING_LEN;
            let e = GUS_RING[i];
            crate::dbg_println!(
                "[GUSRING] #{:03} {} {:03X} {}={:02X} reg={:02X} v={:02X} irq={}",
                pos - n + k, if e.write { "OUT" } else { "IN " }, e.port,
                if e.write { "val" } else { "->" }, e.val, e.reg_sel, e.voice_sel,
                e.in_irq as u8);
        }
    }
}
