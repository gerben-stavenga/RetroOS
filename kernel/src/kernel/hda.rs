//! Intel High Definition Audio (HDA) output — a kernel device driver targeting
//! QEMU's `intel-hda` controller + `hda-duplex`/`hda-output` codec.
//!
//! The twin of [`ac97`](super::ac97): when the emulated SB (`dos/machine/vsb.rs`)
//! produces canonical PCM and the boot probe found an HDA controller (PCI class
//! 04:03), `sound::play` dispatches here. It differs from AC'97 in two ways:
//!
//!  * **MMIO, not port I/O.** HDA's registers live in a 64-bit *memory* BAR
//!    (BAR0), so we `map_phys_range` it present + cache-disabled (the NVMe-BAR
//!    pattern) and drive it with volatile reads/writes — the kernel never faults
//!    on it.
//!  * **A codec verb layer.** Unlike AC'97's flat mixer registers, the codec is
//!    programmed by sending *verbs* over the **CORB/RIRB** DMA rings, then a
//!    stream descriptor + BDL feed PCM exactly like AC'97's bus master.
//!
//! Everything else mirrors `ac97`: a 32-entry ring of PCM buffers in a borrowed
//! contiguous DMA buffer, primed then run, with the producer's run-ahead capped
//! by polling the hardware play position (`SDLPIB` here, `CIV` there) — no
//! interrupts.
//!
//! ## Topology (QEMU-specific)
//!
//! QEMU's codec exposes a tiny fixed widget graph, so we target it directly:
//! the output **DAC is NID 2** and the output **pin complex is NID 3** (AFG is
//! NID 1). A driver for real, quirky codecs would enumerate the graph via
//! `Get Parameter`/connection-list verbs; for QEMU the path is known, so we just
//! program it. If this ever needs to run against real hardware, replace
//! `configure_path` with an enumerator.
//!
//! ## DMA buffer placement (TEMPORARY — same stopgap as ac97)
//!
//! We borrow a `dma_channel_buf` (physically contiguous) and map it into kernel
//! space over the dead upper-memory slice of the low-mem identity window
//! (`LOW_MEM_BASE + 0xC0000..`). See `ac97`'s header and memory
//! `project_ac97_lowmem_dma_window_todo`; the proper fix is a real kernel
//! DMA-window pool. HDA and AC'97 are mutually exclusive (one `Audio` verdict),
//! so reusing the same window + DMA channel is safe.

use arch_abi::Arch;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::kernel::sound::Format;

const PTE_CACHE_DISABLE: u64 = 1 << 4;

// ── Stolen kernel VAs (dead UMA slice of the low-mem identity window) ─────────
/// HDA register BAR window (controller regs + stream descriptors, ≤ 16 KB).
const BAR_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_0000;
const BAR_PAGES: usize = 4;
/// DMA buffer window: CORB + RIRB + BDL + the PCM ring.
const DMA_WIN_VA: usize = crate::LOW_MEM_BASE + 0xC_8000;
/// Borrow the 16-bit ISA DMA channel's permanent contiguous buffer (128 KB / 32
/// pages). Free on an HDA host — the SB is emulated, not passed through, so the
/// real ISA channels are idle.
const DMA_CHANNEL: usize = 5;

// ── Controller registers (offsets into BAR0) ─────────────────────────────────
const GCAP: usize = 0x00; // w16: bits 8..11 ISS, 12..15 OSS
const GCTL: usize = 0x08; // d32: bit0 CRST (1 = run)
const STATESTS: usize = 0x0E; // w16: one bit per SDI link with a codec
const CORBLBASE: usize = 0x40; // d32
const CORBUBASE: usize = 0x44; // d32
const CORBWP: usize = 0x48; // w16: write pointer (entry index)
const CORBRP: usize = 0x4A; // w16: read pointer; bit15 = reset
const CORBCTL: usize = 0x4C; // b8: bit1 CORBRUN
const CORBSIZE: usize = 0x4E; // b8: bits1:0 size (0b10 = 256 entries)
const RIRBLBASE: usize = 0x50; // d32
const RIRBUBASE: usize = 0x54; // d32
const RIRBWP: usize = 0x58; // w16: write pointer; bit15 = reset
const RINTCNT: usize = 0x5A; // w16: response interrupt count
const RIRBCTL: usize = 0x5C; // b8: bit1 RIRBDMAEN
const RIRBSTS: usize = 0x5D; // b8: bit0 RINTFL (response interrupt), bit2 overrun
const RIRBSIZE: usize = 0x5E; // b8: bits1:0 size (0b10 = 256 entries)
const DPLBASE: usize = 0x70; // d32: DMA position buffer base; bit0 = enable
const DPUBASE: usize = 0x74; // d32: DMA position buffer base high

// Output stream descriptor register offsets (added to the descriptor base, which
// is 0x80 + ISS*0x20 — the first output stream sits past the input streams).
const SD_BASE: usize = 0x80;
const SD_STRIDE: usize = 0x20;
const SDCTL: usize = 0x00; // 3 bytes; bit0 SRST, bit1 RUN, bits20..23 stream tag
const SDLPIB: usize = 0x04; // d32: link position in buffer (bytes, RO)
const SDCBL: usize = 0x08; // d32: cyclic buffer length (bytes)
const SDLVI: usize = 0x0C; // w16: last valid BDL index
const SDFMT: usize = 0x12; // w16: stream format (same encoding as the codec)
const SDBDPL: usize = 0x18; // d32: BDL base low
const SDBDPU: usize = 0x1C; // d32: BDL base high

// ── CORB/RIRB/BDL/PCM layout within the borrowed DMA buffer ──────────────────
const CORB_ENTRIES: usize = 256; // 4 bytes each → 1 KB
const RIRB_ENTRIES: usize = 256; // 8 bytes each → 2 KB
const CORB_OFF: usize = 0x0000;
const RIRB_OFF: usize = 0x0400;
const BDL_OFF: usize = 0x0C00; // 128-byte aligned; NUM_BUF*16 = 512 bytes
const POS_OFF: usize = 0x0E00; // 128-byte aligned; DMA position buffer (8 strm*8)
const BUF_OFF: usize = 0x1000; // PCM ring starts on the next page
const DMA_PAGES: usize = (BUF_OFF + NUM_BUF * BUF_BYTES).div_ceil(0x1000);

// ── PCM ring geometry (mirror ac97) ──────────────────────────────────────────
const NUM_BUF: usize = 32;
const BUF_BYTES: usize = 0x800; // 2 KB = 512 stereo frames ≈ 23 ms @ 22 kHz
const PRIME_BUFS: usize = 3;
const MAX_AHEAD: usize = 6;
/// Stream tag bound between the descriptor and the DAC converter (1..15).
const STREAM_TAG: u32 = 1;
/// Fallback codec node IDs if enumeration fails (QEMU's usual layout).
const FALLBACK_DAC: u32 = 2;
const FALLBACK_PIN: u32 = 3;
/// Boot-time bring-up diagnostics to debugcon (flip on to debug the codec).
const DEBUG: bool = false;

static HDA: Mutex<Option<Hda>> = Mutex::new(None);

// ── MMIO helpers (volatile, the BAR is mapped present + PCD) ──────────────────
#[inline]
fn r8(off: usize) -> u8 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u8) }
}
#[inline]
fn r16(off: usize) -> u16 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u16) }
}
#[inline]
fn r32(off: usize) -> u32 {
    unsafe { read_volatile((BAR_WIN_VA + off) as *const u32) }
}
#[inline]
fn w8(off: usize, v: u8) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u8, v) }
}
#[inline]
fn w16(off: usize, v: u16) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u16, v) }
}
#[inline]
fn w32(off: usize, v: u32) {
    unsafe { write_volatile((BAR_WIN_VA + off) as *mut u32, v) }
}

struct Hda {
    dma_va: usize,
    dma_phys: u32,
    /// First output stream descriptor base (0x80 + ISS*0x20).
    sd: usize,
    /// Our private RIRB read cursor (the controller advances RIRBWP).
    rirb_rp: usize,
    /// Codec address of the first present codec.
    cad: u32,
    /// Output DAC + output pin node IDs (enumerated, not assumed).
    dac: u32,
    pin: u32,
    cur_buf: usize,
    cur_off: usize,
    running: bool,
    rate: u32,
}

/// Find an HDA controller (class 0x04, subclass 0x03) anywhere on PCI, via the
/// shared `pci::find_class` scan. Like `ac97::scan`, tolerant of a no-PCI
/// backend (all 0xFFFF…).
pub fn scan<A: crate::Arch>(arch: &mut A) -> Option<(u8, u8, u8)> {
    crate::kernel::pci::find_class(arch, 0x04, 0x03)
}

pub fn init<A: crate::Arch>(arch: &mut A) {
    if crate::kernel::platform::get().audio != crate::kernel::platform::Audio::EmulatedHda {
        return;
    }
    let (bus, dev, func) = scan(arch).expect("platform probe saw an HDA controller; scan must agree");
    let _ = bring_up(arch, bus, dev, func);
}

/// Bring up the controller + codec output path at `bus:dev.func`. Returns true
/// on success.
fn bring_up<A: crate::Arch>(arch: &mut A, bus: u8, dev: u8, func: u8) -> bool {
    // Enable memory space + bus master in the PCI command register (bits 1, 2).
    let cmd = crate::kernel::pci::read32(arch, bus, dev, func, 0x04);
    crate::kernel::pci::write32(arch, bus, dev, func, 0x04, (cmd & 0xFFFF) | 0x06);

    // BAR0 is a memory BAR. Read the high dword only if it is actually 64-bit
    // (type bits [2:1] == 0b10); a 32-bit BAR would make 0x14 a different reg.
    let bar0 = crate::kernel::pci::read32(arch, bus, dev, func, 0x10);
    let hi = if bar0 & 0x6 == 0x4 {
        crate::kernel::pci::read32(arch, bus, dev, func, 0x14) as u64
    } else {
        0
    };
    let bar_phys = (hi << 32) | (bar0 & 0xFFFF_FFF0) as u64;
    if bar_phys == 0 {
        return false;
    }
    arch.map_phys_range(BAR_WIN_VA >> 12, BAR_PAGES, bar_phys >> 12, PTE_CACHE_DISABLE);

    // Controller reset: drive CRST low, wait until it reads low, then high.
    w32(GCTL, 0);
    for _ in 0..1_000_000 {
        if r32(GCTL) & 1 == 0 {
            break;
        }
    }
    w32(GCTL, 1);
    let mut up = false;
    for _ in 0..1_000_000 {
        if r32(GCTL) & 1 != 0 {
            up = true;
            break;
        }
    }
    if !up {
        return false;
    }
    // Codecs need ≥ 521 µs after CRST to report in STATESTS; spin a cushion.
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
    let codecs = r16(STATESTS);
    if codecs == 0 {
        return false;
    }
    let cad = codecs.trailing_zeros();

    // Output stream descriptor base sits past the ISS input streams.
    let gcap = r16(GCAP);
    let iss = ((gcap >> 8) & 0xF) as usize;
    let sd = SD_BASE + iss * SD_STRIDE;

    // Map the borrowed contiguous DMA buffer.
    let phys_page = arch.dma_channel_buf(DMA_CHANNEL);
    if phys_page == 0 {
        return false;
    }
    arch.map_phys_range(DMA_WIN_VA >> 12, DMA_PAGES, phys_page, PTE_CACHE_DISABLE);
    let dma_phys = (phys_page * 0x1000) as u32;

    let mut d = Hda {
        dma_va: DMA_WIN_VA,
        dma_phys,
        sd,
        rirb_rp: 0,
        cad,
        dac: 0,
        pin: 0,
        cur_buf: 0,
        cur_off: 0,
        running: false,
        rate: 0,
    };

    // CORB/RIRB must run before any verb (enumeration uses verbs).
    d.setup_corb_rirb();
    if DEBUG {
        crate::println!(
            "hda: rings up corbctl={:#x} rirbctl={:#x} corbsz={:#x} rirbsz={:#x} corbwp={} corbrp={} rirbwp={}",
            r8(CORBCTL), r8(RIRBCTL), r8(CORBSIZE), r8(RIRBSIZE),
            r16(CORBWP), r16(CORBRP), r16(RIRBWP)
        );
        // Probe consecutive verbs: does the ring keep processing past the first?
        for p in [0x00u32, 0x02, 0x04, 0x09] {
            let r = d.verb(0, (0xF00 << 8) | p);
            crate::println!(
                "hda: probe param={:#04x} -> {:#x} corbwp={} corbrp={} rirbwp={} rirbsts={:#x}",
                p, r, r16(CORBWP), r16(CORBRP), r16(RIRBWP), r8(RIRBSTS)
            );
        }
    }
    d.enumerate();
    if d.dac == 0 {
        d.dac = FALLBACK_DAC;
    }
    if d.pin == 0 {
        d.pin = FALLBACK_PIN;
    }

    d.build_bdl();

    // Reset the output stream into a known state before programming it: assert
    // SDCTL.SRST, wait for it to read back, deassert, wait for it to clear. A
    // stream that was never reset may refuse to advance when RUN is set.
    w8(sd + SDCTL, 0x01);
    for _ in 0..100_000 {
        if r8(sd + SDCTL) & 0x01 != 0 {
            break;
        }
    }
    w8(sd + SDCTL, 0x00);
    for _ in 0..100_000 {
        if r8(sd + SDCTL) & 0x01 == 0 {
            break;
        }
    }

    // DMA position buffer (some QEMU builds advance this, not SDLPIB). Enable it
    // so we have a second, authoritative play-position source.
    w32(DPLBASE, (dma_phys + POS_OFF as u32) | 1);
    w32(DPUBASE, 0);

    // Point the stream descriptor at the BDL and cap its cyclic length.
    let bdl_phys = d.dma_phys + BDL_OFF as u32;
    w32(sd + SDBDPL, bdl_phys);
    w32(sd + SDBDPU, 0);
    w32(sd + SDCBL, (NUM_BUF * BUF_BYTES) as u32);
    w16(sd + SDLVI, (NUM_BUF - 1) as u16);
    // Stream tag in the descriptor control byte (bits 20..23 of the 3-byte CTL).
    w8(sd + SDCTL + 2, (STREAM_TAG << 4) as u8);

    d.configure_path();

    if DEBUG {
        crate::println!(
            "hda: bar={:#x} gcap={:#06x} iss={} oss={} statests={:#x} cad={} sd={:#x}",
            bar_phys, gcap, iss, (gcap >> 12) & 0xF, codecs, cad, sd
        );
        crate::println!("hda: dac=nid{} pin=nid{}", d.dac, d.pin);
    }

    *HDA.lock() = Some(d);
    true
}

impl Hda {
    fn buf_phys(&self, i: usize) -> u32 {
        self.dma_phys + (BUF_OFF + i * BUF_BYTES) as u32
    }
    fn buf_va(&self, i: usize) -> usize {
        self.dma_va + BUF_OFF + i * BUF_BYTES
    }

    /// Fill the BDL: entry i → PCM buffer i. Each HDA BDL entry is 16 bytes
    /// { addr:u64, len:u32, flags:u32 }; IOC stays off (we poll `SDLPIB`).
    fn build_bdl(&mut self) {
        for i in 0..NUM_BUF {
            let entry = self.dma_va + BDL_OFF + i * 16;
            unsafe {
                write_volatile(entry as *mut u32, self.buf_phys(i)); // addr low
                write_volatile((entry + 4) as *mut u32, 0); // addr high
                write_volatile((entry + 8) as *mut u32, BUF_BYTES as u32); // length
                write_volatile((entry + 12) as *mut u32, 0); // flags (IOC off)
            }
        }
    }

    /// Initialize and start the CORB (command) and RIRB (response) DMA rings.
    fn setup_corb_rirb(&mut self) {
        // Stop both engines before reprogramming their bases.
        w8(CORBCTL, 0);
        w8(RIRBCTL, 0);

        let corb_phys = self.dma_phys + CORB_OFF as u32;
        w32(CORBLBASE, corb_phys);
        w32(CORBUBASE, 0);
        w8(CORBSIZE, 0x02); // 256 entries
        // Reset the read pointer: set bit15, wait for it to read back, then clear.
        w16(CORBRP, 0x8000);
        for _ in 0..100_000 {
            if r16(CORBRP) & 0x8000 != 0 {
                break;
            }
        }
        w16(CORBRP, 0);
        w16(CORBWP, 0);

        let rirb_phys = self.dma_phys + RIRB_OFF as u32;
        w32(RIRBLBASE, rirb_phys);
        w32(RIRBUBASE, 0);
        w8(RIRBSIZE, 0x02); // 256 entries
        w16(RIRBWP, 0x8000); // reset the write pointer
        w16(RINTCNT, 0xFF); // high count; we also clear RIRBSTS per verb (see verb())
        self.rirb_rp = 0;

        w8(CORBCTL, 0x02); // CORBRUN
        w8(RIRBCTL, 0x02); // RIRBDMAEN
    }

    /// Send one verb to `nid` and return the codec's 32-bit response. `verb` is
    /// the pre-packed verb+payload field (bits 19:0 of the command).
    fn verb(&mut self, nid: u32, verb: u32) -> u32 {
        let cmd = (self.cad << 28) | (nid << 20) | (verb & 0xF_FFFF);
        // Push at (CORBWP + 1) and advance the write pointer.
        let wp = (r16(CORBWP) as usize + 1) % CORB_ENTRIES;
        unsafe {
            write_volatile((self.dma_va + CORB_OFF + wp * 4) as *mut u32, cmd);
        }
        w16(CORBWP, wp as u16);

        // The response lands at our next RIRB slot; wait for RIRBWP to reach it.
        let want = (self.rirb_rp + 1) % RIRB_ENTRIES;
        for _ in 0..1_000_000 {
            if (r16(RIRBWP) as usize) % RIRB_ENTRIES == want {
                break;
            }
            core::hint::spin_loop();
        }
        self.rirb_rp = want;
        // RIRB entry = { response: u32, response_ex: u32 }.
        let resp = unsafe { read_volatile((self.dma_va + RIRB_OFF + want * 8) as *const u32) };
        // Clear RIRBSTS (RINTFL bit0 / OIS bit2, both RW1C). QEMU's CORB engine
        // stops processing once it has written RINTCNT responses since the count
        // was last reset; clearing RIRBSTS resets that counter, so the NEXT verb
        // actually runs. Without this, only the first verb after setup executes
        // (corbrp/rirbwp freeze at 1) and the whole codec is left unconfigured.
        w8(RIRBSTS, 0x05);
        resp
    }

    /// Walk the codec graph and record the first output DAC + output-capable pin
    /// into `self.dac`/`self.pin` (0 if not found → bring_up uses the fallbacks).
    /// Real topology beats hardcoded NIDs across QEMU codec revisions / real HW.
    fn enumerate(&mut self) {
        // Root node 0 → the function groups it contains.
        let root = self.verb(0, (0xF00 << 8) | 0x04); // Get Subnode Count
        let fg_start = (root >> 16) & 0xFF;
        let fg_count = root & 0xFF;
        let mut afg = 0u32;
        for n in fg_start..fg_start + fg_count {
            if self.verb(n, (0xF00 << 8) | 0x05) & 0xFF == 0x01 {
                afg = n; // Audio Function Group
                break;
            }
        }
        if DEBUG {
            crate::println!("hda: enum root={:#x} fg_start={} fg_count={} afg={}", root, fg_start, fg_count, afg);
        }
        if afg == 0 {
            return;
        }
        // The AFG's subnodes are the widgets.
        let sub = self.verb(afg, (0xF00 << 8) | 0x04);
        let w_start = (sub >> 16) & 0xFF;
        let w_count = sub & 0xFF;
        for nid in w_start..w_start + w_count {
            let caps = self.verb(nid, (0xF00 << 8) | 0x09); // Audio Widget Capabilities
            match (caps >> 20) & 0xF {
                0x0 if self.dac == 0 => self.dac = nid, // Audio Output (DAC)
                0x4 if self.pin == 0
                    // Pin Complex — take the first output-capable one.
                    && self.verb(nid, (0xF00 << 8) | 0x0C) & (1 << 4) != 0 => {
                        self.pin = nid;
                    }
                _ => {}
            }
            if DEBUG {
                crate::println!("hda: nid{} caps={:#x} type={}", nid, caps, (caps >> 20) & 0xF);
            }
        }
    }

    /// Program the output path: route the DAC to the pin, power both up, unmute,
    /// and bind the stream tag. Format is set later (per rate) by `set_format`.
    fn configure_path(&mut self) {
        let (pin, dac) = (self.pin, self.dac);
        // Pin: power D0, enable output, select the DAC connection, unmute amp.
        self.verb(pin, 0x705 << 8); // Set Power State D0
        self.verb(pin, (0x707 << 8) | 0x40); // Set Pin Widget Control: OUT enable
        self.verb(pin, 0x701 << 8); // Set Connection Select: first input
        self.verb(pin, (0x3 << 16) | 0xB07F); // Set Amp: out, L+R, unmute, max gain
        // DAC: power D0, bind the stream tag / channel 0, unmute at full gain.
        self.verb(dac, 0x705 << 8); // Set Power State D0
        self.verb(dac, (0x706 << 8) | (STREAM_TAG << 4)); // Stream/Channel
        self.verb(dac, (0x3 << 16) | 0xB07F); // Set Amp: out, L+R, unmute, gain 0x7F
    }

    /// Encode a 16-bit stereo stream format for `rate` (HDA SDFMT / converter
    /// format encoding: base 44.1/48 kHz × multiple ÷ divisor). Unknown rates
    /// fall back to 44.1 kHz (QEMU resamples internally).
    fn fmt(rate: u32) -> u16 {
        let (base, div): (u16, u16) = match rate {
            44100 => (1, 0),
            22050 => (1, 1),
            11025 => (1, 3),
            48000 => (0, 0),
            24000 => (0, 1),
            16000 => (0, 2),
            12000 => (0, 3),
            8000 => (0, 5),
            // Odd SB rates (e.g. 22222 from DSP time constant 211) → nearest
            // 44.1 kHz submultiple. divisor = round(44100/rate), field = div-1.
            _ => {
                let divisor = ((44100 + rate / 2) / rate).clamp(1, 8);
                (1, (divisor - 1) as u16)
            }
        };
        // bit14 base | bits10:8 div | bits6:4 bits(001=16) | bits3:0 chan-1(1=stereo)
        (base << 14) | (div << 8) | (0b001 << 4) | 0x0001
    }

    /// (Re)program the stream + DAC converter format for `rate`. Requires the
    /// stream to be stopped; only called from the priming path (running == false).
    fn set_format(&mut self, rate: u32) {
        let f = Self::fmt(rate);
        w16(self.sd + SDFMT, f);
        let dac = self.dac;
        self.verb(dac, (0x2 << 16) | f as u32); // Set Converter Format
        self.rate = rate;
        if DEBUG {
            crate::println!("hda: set_format rate={} fmt={:#06x}", rate, f);
        }
    }

    /// Current play position as a buffer index, from the hardware byte position.
    fn play_buf(&self) -> usize {
        (r32(self.sd + SDLPIB) as usize / BUF_BYTES) % NUM_BUF
    }

    /// Play position (bytes) from the DMA position buffer — QEMU's authoritative
    /// source on builds that don't update the SDLPIB register.
    fn dma_pos(&self) -> u32 {
        let idx = (self.sd - SD_BASE) / SD_STRIDE;
        unsafe { read_volatile((self.dma_va + POS_OFF + idx * 8) as *const u32) }
    }

    fn stop(&mut self) {
        let ctl = r8(self.sd + SDCTL);
        w8(self.sd + SDCTL, ctl & !0x02); // clear RUN
        for _ in 0..100_000 {
            if r8(self.sd + SDCTL) & 0x02 == 0 {
                break;
            }
        }
    }

    /// Decode `bytes` (`fmt`) into canonical i16 stereo and stream into the ring.
    fn submit(&mut self, rate: u32, fmt: Format, bytes: &[u8]) {
        // A rate change needs a fresh format, which means stopping the stream and
        // re-priming. DOS playback sets one rate per session, so this is rare.
        if rate != 0 && rate != self.rate {
            if self.running {
                self.stop();
                self.running = false;
            }
            self.cur_buf = 0;
            self.cur_off = 0;
            self.set_format(rate);
        }
        let fb = fmt.frame_bytes();
        if fb == 0 {
            return;
        }
        for i in 0..bytes.len() / fb {
            // At each buffer boundary, cap how far we run ahead of the controller.
            if self.cur_off == 0 && self.running {
                let civ = self.play_buf();
                let ahead = (self.cur_buf + NUM_BUF - civ) % NUM_BUF;
                // Only throttle when genuinely AHEAD of the codec. A wrapped
                // value (>= half the ring) means the play position lapped us
                // (underrun) — feed hard to catch up, never stall.
                if (MAX_AHEAD..NUM_BUF / 2).contains(&ahead) {
                    if DEBUG {
                        crate::println!(
                            "hda: stall cur_buf={} civ={} lpib={} pos={} sdsts={:#x}",
                            self.cur_buf, civ, r32(self.sd + SDLPIB), self.dma_pos(), r8(self.sd + 0x03)
                        );
                    }
                    break;
                }
            }
            let (l, r) = fmt.frame(bytes, i);
            let p = self.buf_va(self.cur_buf) + self.cur_off;
            unsafe {
                write_volatile(p as *mut u16, l as u16);
                write_volatile((p + 2) as *mut u16, r as u16);
            }
            self.cur_off += 4;
            if self.cur_off >= BUF_BYTES {
                self.cur_buf = (self.cur_buf + 1) % NUM_BUF;
                self.cur_off = 0;
                // Start the stream once a small cushion is primed. Write RUN +
                // stream number as ONE dword so QEMU re-evaluates the codec<->
                // stream binding with the stream number visible (a byte-0-only
                // RUN write may not retrigger it → codec never drains the FIFO).
                if !self.running && self.cur_buf >= PRIME_BUFS {
                    w32(self.sd + SDCTL, 0x02 | (STREAM_TAG << 20));
                    self.running = true;
                    if DEBUG {
                        crate::println!(
                            "hda: stream RUN sdctl={:#010x} sdsts={:#x} cbl={} lvi={} fmt={:#06x}",
                            r32(self.sd + SDCTL), r8(self.sd + 0x03),
                            r32(self.sd + SDCBL), r16(self.sd + SDLVI), r16(self.sd + SDFMT)
                        );
                    }
                }
                // Heartbeat once per ring lap (~0.7 s): does the HW play position
                // actually advance? lpib stuck at 0 = DMA not progressing.
                if DEBUG && self.running && self.cur_buf == 0 {
                    crate::println!("hda: lpib={} sdsts={:#x}", r32(self.sd + SDLPIB), r8(self.sd + 0x03));
                }
            }
        }
    }
}

/// Stream a block of source PCM to the HDA codec (called by `sound::play` when an
/// HDA controller was discovered).
pub fn play<A: crate::Arch>(arch: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    let _ = arch;
    let mut g = HDA.lock();
    if let Some(dev) = g.as_mut() {
        dev.submit(rate, fmt, bytes);
    }
}
