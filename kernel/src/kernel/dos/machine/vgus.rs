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

use crate::Regs;
use super::*;

/// Onboard sample DRAM: we model a fully-populated 1 MB board (every real
/// sizing probe pokes powers-of-two boundaries below this and finds RAM).
const DRAM_LEN: usize = 1 << 20;

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
}

impl GusCore {
    fn new_boxed() -> alloc::boxed::Box<GusCore> {
        // Both big members are heap-built in place; the struct itself is
        // small enough (~1.2 KB of registers) that a by-value move is fine.
        alloc::boxed::Box::new(GusCore {
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
        })
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
        self.vregs = [[0; 16]; 32];
        self.active_reg = 13;
        self.reg41 = 0;
        self.reg45 = 0;
    }
}

impl Gus {
    /// Absent until the program's env declares it (ULTRASND).
    pub fn new() -> Self {
        Gus { base: 0x240, irq: 5, dma_ch: 1, present: false, core: None }
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
    }

    /// Program-exit / exec cleanup: drop the whole core so the next program
    /// sees a power-on card (same lifecycle as the SB's `release_dma_pool`
    /// and the per-program OPL chip).
    pub fn reset<A: crate::Arch>(&mut self, machine: &mut A) {
        let _ = machine;
        self.core = None;
        self.present = false;
    }

    fn core(&mut self) -> &mut GusCore {
        self.core.get_or_insert_with(GusCore::new_boxed)
    }

    /// Guest IN from a decoded port.
    pub fn io_read<A: crate::Arch>(&mut self, machine: &mut A, p: u16) -> u8 {
        let _ = machine;
        let base = self.base;
        let c = self.core();
        let lo = p.wrapping_sub(base);
        if lo < 0x10 {
            return match lo {
                // IRQ status: bit2 T1, bit3 T2, bit5 wave, bit6 ramp,
                // bit7 DMA-TC, bits0/1 MIDI. Sources land in later commits;
                // reads must already be well-defined (0 = nothing pending).
                0x06 => 0,
                // AdLib-compatible timer status window (detection reads it).
                0x08 => 0,
                // Board revision: 0xFF = pre-3.7 board, no extra registers —
                // the simplest personality every driver accepts.
                0x0F => 0xFF,
                _ => 0xFF,
            };
        }
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
            0x07 => c.dram[c.dram_addr()],
            _ => 0xFF,
        }
    }

    /// Guest OUT to a decoded port.
    pub fn io_write<A: crate::Arch>(&mut self, machine: &mut A, p: u16, val: u8) {
        let _ = machine;
        let base = self.base;
        let c = self.core();
        let lo = p.wrapping_sub(base);
        if lo < 0x10 {
            match lo {
                0x00 => c.mix_ctrl = val,
                // AdLib timer window + IRQ/DMA latches: stored; the timer
                // model lands in the next commit.
                0x08 | 0x09 => {}
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
            0x05 => c.reg_write(true, val),
            0x07 => {
                let a = c.dram_addr();
                c.dram[a] = val;
            }
            _ => {}
        }
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

    /// Byte write to the selected register (`high` = data-high port). The
    /// high byte completes a write for either width; that's where register
    /// side effects belong as they land (voice start, DMA kick, reset).
    fn reg_write(&mut self, high: bool, val: u8) {
        let reg = self.reg_sel;
        match reg {
            0x00..=0x0D => {
                let slot = &mut self.vregs[self.voice_sel as usize][reg as usize];
                if Self::voice_is16(reg) {
                    if high {
                        *slot = (*slot & 0x00FF) | ((val as u16) << 8);
                    } else {
                        *slot = (*slot & 0xFF00) | val as u16;
                    }
                } else if high {
                    *slot = val as u16;
                }
            }
            0x0E if high => self.active_reg = val & 0x3F,
            0x41 if high => self.reg41 = val,
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
            0x45 if high => self.reg45 = val,
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

    /// Byte read of the selected register. Reads use the `0x80 | index`
    /// aliases for per-voice registers (hardware convention); programming
    /// registers echo their images, hardware-status bits join with playback.
    fn reg_read(&mut self, high: bool) -> u8 {
        let reg = self.reg_sel;
        let word = match reg {
            0x80..=0x8D => {
                let idx = (reg & 0x0F) as usize;
                self.vregs[self.voice_sel as usize][idx]
            }
            // Active voices: hardware sets the top two bits on readback.
            0x8E => 0xC0 | self.active_reg as u16,
            0x41 => self.reg41 as u16,
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
