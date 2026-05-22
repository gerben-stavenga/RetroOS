//! Virtual 8237 DMA controller + Sound Blaster DMA virtualization.

use super::*;

/// A private 64KB virtual slot for the guest mappings displaced while the
/// single ISA DMA pool backs an SB buffer. XMS starts after this range.
const SB_DMA_SHADOW_PAGE: usize = 0x120;

// Virtual 8237 DMA controller (generic — not SB-specific)
// ============================================================================
//
// A DOS program programs the 8237 with a *DOS-physical* buffer address,
// but runs paged in VM86, so the real DMA engine would fetch the wrong
// memory. We capture every channel's programming here; the SB-DMA layer
// (see [`SbDmaState`]) later translates the BLASTER-declared channel onto
// the real card's channel by remapping the guest buffer contiguous.
//
// Two cascaded controllers: #1 = 8-bit channels 0-3 (ports 0x00-0x0F),
// #2 = 16-bit channels 4-7 (ports 0xC0-0xDF, register stride ×2). Page
// registers live in the 0x80-0x8F block. Address/count are 16-bit,
// loaded low-then-high through a per-controller byte-pointer flip-flop.

/// A channel's captured guest programming (what we need to locate and
/// size the transfer): `addr`/`count` are in bytes for 8-bit channels,
/// in *words* for 16-bit channels (8237 quirk).
#[derive(Clone, Copy, Default)]
pub struct DmaProg {
    pub addr: u16,  // base address register (offset within its page)
    pub count: u16, // base count register (transfer length − 1)
    pub page: u8,   // page register (high address bits)
    pub mode: u8,   // mode register byte (transfer type, auto-init…)
}

/// One DMA channel. `prog` is **always present** — it mirrors the
/// 8237's base address/count/page/mode registers, which physically
/// persist across re-arms (single-cycle drivers rewrite only addr+count
/// each block, reusing mode/page). Two orthogonal control bits sit
/// beside it, exactly as on the real chip — neither discriminates
/// `prog`'s validity, both just gate behaviour, so every combination is
/// physically meaningful (no illegal states):
///  - `masked` — channel masked (DRQ ignored); starts masked.
///  - `armed`  — the current programming has been handed to the real
///    QEMU-8257, which is then authoritative for *current-count* reads
///    (live decrement, natural 0xFFFF at terminal). A fresh count
///    (re)write clears it; `maybe_remap` sets it. `prog` is untouched
///    by either, so a partial re-arm keeps the prior mode/page.
#[derive(Clone, Copy, Default)]
pub struct DmaChannel {
    pub prog: DmaProg,
    pub masked: bool,
    pub armed: bool,
}

/// Generic virtual 8237 pair. Indexed by absolute channel 0..7.
#[derive(Clone, Copy)]
pub struct Dma8237 {
    pub ch: [DmaChannel; 8],
    ff_lo: bool, // controller #1 (ch0-3) byte-pointer flip-flop
    ff_hi: bool, // controller #2 (ch4-7) byte-pointer flip-flop
    /// Per-channel count-program generation: bumped each time the guest
    /// finishes writing a channel's 16-bit count register. This is the
    /// reliable "(re)arm a transfer" signal — a single-cycle SB driver
    /// rewrites count every block (even to the same value), auto-init
    /// writes it once. The SB-DMA layer reprograms the real 8237 when
    /// this changes, independent of mask/unmask.
    pub count_gen: [u32; 8],
    /// Transient holder for the real QEMU-8257 16-bit current-count,
    /// snapshotted at the guest's low-byte read so the lo/hi pair is
    /// consistent. Not part of the programming shadow.
    read_latch: u16,
}

/// Standard PC/AT page-register port → absolute channel. 0x8F is the
/// refresh page (ch4 is the cascade channel, never used for transfers).
const DMA_PAGE_PORT: [(u16, usize); 7] = [
    (0x87, 0), (0x83, 1), (0x81, 2), (0x82, 3),
    (0x8B, 5), (0x89, 6), (0x8A, 7),
];

impl Dma8237 {
    pub fn new() -> Self {
        // Channels power up masked & un-armed, registers zeroed (count
        // 0 ⇒ `maybe_remap` won't act) until the guest programs them.
        let ch = [DmaChannel { prog: DmaProg::default(), masked: true, armed: false }; 8];
        Self { ch, ff_lo: false, ff_hi: false, count_gen: [0; 8], read_latch: 0 }
    }

    /// True if `port` (already 10-bit-folded) belongs to the 8237.
    pub fn owns(port: u16) -> bool {
        matches!(port, 0x00..=0x0F | 0xC0..=0xDF)
            || DMA_PAGE_PORT.iter().any(|&(p, _)| p == port)
    }

    fn ff(&mut self, hi: bool) -> &mut bool {
        if hi { &mut self.ff_hi } else { &mut self.ff_lo }
    }

    pub fn io_write(&mut self, port: u16, val: u8) {
        // Page registers.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            self.ch[chan].prog.page = val;
            return;
        }
        let hi = port >= 0xC0;
        // Normalize controller #2's ×2 register stride to 0..0x0F.
        let reg = if hi { ((port - 0xC0) >> 1) as u16 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                let ff = self.ff(hi);
                let flip = *ff;
                *ff = !*ff;
                let p = &mut self.ch[chan].prog;
                let r = if is_count { &mut p.count } else { &mut p.addr };
                if !flip { *r = (*r & 0xFF00) | val as u16; }
                else     { *r = (*r & 0x00FF) | ((val as u16) << 8); }
                if is_count {
                    // (Re)writing the count un-arms: count reads return
                    // the freshly-programmed base until `maybe_remap`
                    // re-arms onto the real chip. addr/page/mode persist.
                    self.ch[chan].armed = false;
                    if flip {
                        // High byte completes the 16-bit count: the
                        // (re)arm signal the SB-DMA layer keys off.
                        self.count_gen[chan] = self.count_gen[chan].wrapping_add(1);
                    }
                }
            }
            0x0B => { // mode: bits0-1 = channel
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].prog.mode = val;
            }
            0x0A => { // single mask: bits0-1 channel, bit2 = mask/unmask
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].masked = val & 0x04 != 0;
            }
            0x0C => { *self.ff(hi) = false; } // clear byte-pointer flip-flop
            0x0D => { // master clear: reset controller, all channels masked
                *self.ff(hi) = false;
                for c in chan_base..chan_base + 4 { self.ch[c].masked = true; }
            }
            0x0E => { for c in chan_base..chan_base + 4 { self.ch[c].masked = false; } }
            0x0F => { // write all mask bits (bits0-3 → the 4 channels)
                for i in 0..4 { self.ch[chan_base + i].masked = val & (1 << i) != 0; }
            }
            _ => {} // command/request regs: not needed by the SB path
        }
    }

    pub fn io_read(&mut self, port: u16) -> u8 {
        // Page registers read back the latched value.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            return self.ch[chan].prog.page;
        }
        let hi = port >= 0xC0;
        let reg = if hi { ((port - 0xC0) >> 1) as u16 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                // Captured guest programming (base registers). The armed
                // SB channel never reaches here for count — `dma_read`
                // intercepts and serves the live real QEMU-8257 instead.
                let p = self.ch[chan].prog;
                let v = if is_count { p.count } else { p.addr };
                let ff = self.ff(hi);
                let byte = if !*ff { v as u8 } else { (v >> 8) as u8 };
                *ff = !*ff;
                byte
            }
            0x08 => 0x00, // status: no TC, no requests pending in our model
            _ => 0xFF,
        }
    }
}

/// Per-thread Sound Blaster DMA state: the BLASTER-declared channel/IRQ
/// map plus the generic virtual 8237. The card itself (DSP/mixer/OPL3/
/// EMU8000) is pure passthrough; only this DMA indirection is virtual.
/// Slice 3 fills the remap binding; Slice 4 the IRQ relay.
pub struct SbDmaState {
    pub io_base: u16, // BLASTER A — DSP/mixer port base (passthrough target)
    pub irq: u8,      // BLASTER I — guest vPIC IRQ to inject on SB completion
    pub dma8: u8,     // BLASTER D — guest's 8-bit vDMA channel (0..3)
    pub dma16: u8,    // BLASTER H — guest's 16-bit vDMA channel (5..7)
    /// Real DMA channels QEMU's SB16 is wired to (`-device sb16,dma=`/
    /// `dma16=`; defaults 1/5). Independent of the guest's BLASTER —
    /// a guest channel-D transfer must drive *these* on the real 8237.
    pub host_dma8: u8,
    pub host_dma16: u8,
    pub dma: Dma8237, // generic virtual controller shadow
    // Remap binding: the contiguous phys run the guest buffer was moved
    // to, kept alive across blocks (auto-init reuses it; single-cycle
    // re-arms reuse it). Freed only when the buffer addr/len changes.
    pub remap_start_page: u64,
    pub remap_pages: usize,
    /// Buffer (DOS-phys addr, byte length) the current binding covers.
    last_gpa: u32,
    last_len: u32,
    /// Per-channel `count_gen` last acted on. The real 8237 is
    /// (re)programmed exactly when the guest bumps a channel's count
    /// generation (its per-block re-arm), not on mask/unmask — handles
    /// single-cycle drivers that re-arm without masking.
    last_gen: [u32; 8],
}

impl SbDmaState {
    /// Defaults: A220 I7 D1 H5 (guest sees SB IRQ 7; the host chip stays
    /// on its real line and the IRQ relay maps host→guest, so the two are
    /// intentionally decoupled). Overridden by the guest's `BLASTER=` env.
    pub fn new() -> Self {
        Self {
            io_base: 0x220, irq: 7, dma8: 1, dma16: 5,
            host_dma8: 1, host_dma16: 5, // QEMU `-device sb16` defaults
            dma: Dma8237::new(),
            remap_start_page: 0, remap_pages: 0,
            last_gpa: 0, last_len: 0, last_gen: [0; 8],
        }
    }

    /// DIAG: QEMU i8257 current count for the SB 8-bit host channel,
    /// sampled at IRQ-relay time — the moment the guest ISR is about to
    /// read it expecting terminal `0xFFFF`.
    pub fn diag_host_count8(&self) -> u16 {
        real_8237_count(self.host_dma8)
    }

    /// DIAG: is virtual channel `ch` currently armed (handed to the real
    /// chip and not yet completed/reprogrammed from our side)?
    pub fn dma_ch_armed(&self, ch: usize) -> bool {
        ch < 8 && self.dma.ch[ch].armed
    }

    /// Release the contiguous ISA-DMA pool binding this thread holds, if
    /// any. The pool is a single global slot ("foreground thread owns
    /// the card"); a thread that armed SB DMA and then exits or `exec`s
    /// must hand it back, or every later program's `maybe_remap` fails
    /// with "no contiguous DMA region". Idempotent. Also resets the
    /// per-channel re-arm cursor so a reused `SbDmaState` can't dangle.
    pub fn release_dma_pool(&mut self) {
        self.restore_guest_mapping();
        if self.remap_pages != 0 {
            crate::kernel::startup::arch_free_phys_contig(
                self.remap_start_page, self.remap_pages);
            self.remap_start_page = 0;
            self.remap_pages = 0;
        }
        self.last_gpa = 0;
        self.last_len = 0;
        self.last_gen = [0; 8];
    }

    /// Put the original guest PTEs back before the ISA DMA pool can be
    /// handed to another buffer. The live guest range currently names the
    /// pool; the private shadow range holds the PTEs it displaced.
    fn restore_guest_mapping(&mut self) {
        if self.remap_pages == 0 {
            return;
        }
        let vpage = (self.last_gpa as usize) >> 12;
        let span = self.remap_pages * 0x1000;
        unsafe {
            core::ptr::copy(
                (vpage << 12) as *const u8,
                (SB_DMA_SHADOW_PAGE << 12) as *mut u8,
                span);
        }
        crate::kernel::startup::arch_swap_page_entries(
            vpage, SB_DMA_SHADOW_PAGE, self.remap_pages);
        // The swap leaves the pool mapping in the private shadow. Clear it
        // before the pool is reused so no stale alias survives this binding.
        crate::kernel::startup::arch_unmap_range(
            SB_DMA_SHADOW_PAGE, self.remap_pages);
    }

    /// SB ports that pass straight through to the real card (QEMU
    /// `sb16`/`adlib`): the DSP/mixer block `[io_base, io_base+0x10)` and
    /// the OPL2/3 FM ports 0x388/0x389. Only the 8237 is virtual.
    pub fn is_passthrough(&self, p: u16) -> bool {
        (p >= self.io_base && p < self.io_base + 0x10) || matches!(p, 0x388 | 0x389)
    }

    /// DMA-port read. Two distinct sources of truth, never conflated:
    ///
    ///  - **armed SB channel, count register** → the *real* QEMU-8257's
    ///    live current-count (it's the actual transfer QEMU-sb16 paces):
    ///    decrements during playback, underflows to 0xFFFF at terminal
    ///    count — exactly real-hw semantics Dune2's `0x4D8` ISR expects.
    ///    Served here directly (own flip-flop split, latched at the
    ///    low-byte read so the lo/hi pair is consistent); the shadow
    ///    `ch[].count` is left untouched so `maybe_remap`'s programming
    ///    snapshot stays intact.
    ///  - **everything else** (not-yet-armed = programming snapshot,
    ///    non-SB channels, addr/page/status) → `Dma8237::io_read`, i.e.
    ///    the captured guest programming.
    pub fn dma_read(&mut self, port: u16) -> u8 {
        let (is_cnt, chan, hi_ctrl) = if port <= 0x0F {
            (port & 1 == 1, (port >> 1) as usize, false)
        } else if (0xC0..=0xDF).contains(&port) {
            let r = (port - 0xC0) >> 1;
            (r & 1 == 1, 4 + (r >> 1) as usize, true)
        } else { (false, 0, false) };

        let host = if chan == self.dma8 as usize { Some(self.host_dma8) }
                   else if chan == self.dma16 as usize { Some(self.host_dma16) }
                   else { None };
        if self.dma.ch[chan].armed {
            if let Some(h) = host {
                // Serve the *live* transfer state for the armed SB channel,
                // lo/hi via the controller byte-pointer flip-flop; snapshot
                // the full u16 at the low-byte read so the pair is coherent.
                let ff = if hi_ctrl { &mut self.dma.ff_hi }
                         else { &mut self.dma.ff_lo };
                let low = !*ff;
                *ff = !*ff;
                if low {
                    let live_count = real_8237_count(h);
                    let p = self.dma.ch[chan].prog;
                    self.dma.read_latch = if is_cnt {
                        // Count register: QEMU-8257's live current-count —
                        // decrements during playback, 0xFFFF at terminal
                        // (Dune2's 0x4D8 ISR relies on this).
                        live_count
                    } else {
                        // Address register: the 8237 advances the address as
                        // it decrements the count. Derive the current address
                        // from the count delta so it stays in the *guest*
                        // buffer space — the real chip holds the remapped
                        // contiguous address. ROTT / the Apogee Sound System
                        // track 16-bit playback progress by reading *this*,
                        // not the count; a frozen address looks like a dead
                        // DMA channel and fails their playback self-test.
                        p.addr.wrapping_add(p.count.wrapping_sub(live_count))
                    };
                }
                let v = self.dma.read_latch;
                return if low { v as u8 } else { (v >> 8) as u8 };
            }
        }
        self.dma.io_read(port)
    }

    /// Called after every virtual-8237 write. If the BLASTER-declared
    /// channel just became armed (unmasked, nonzero count), relocate the
    /// guest DMA buffer to a contiguous DMA-safe physical run and program
    /// the *real* 8237 with the translated address — the card then DMAs
    /// correct bytes. If the channel was masked, release the binding.
    pub fn maybe_remap(&mut self) {
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = self.dma8 as usize;
        let c16 = self.dma16 as usize;
        let armed8 = c8 < 4 && !self.dma.ch[c8].masked
            && self.dma.ch[c8].prog.count != 0;
        let armed16 = (5..8).contains(&c16) && !self.dma.ch[c16].masked
            && self.dma.ch[c16].prog.count != 0;

        // [SB-DMA] per-gate-evaluation trace disabled per request.

        let (chan, is16, host_chan) = if armed16 {
                (c16, true, self.host_dma16 as usize)
            } else if armed8 {
                (c8, false, self.host_dma8 as usize)
            } else {
                // Idle/masked — keep the binding (reused next block).
                return;
            };

        // Act only when the guest (re)armed this channel: it bumped
        // count_gen since we last acted. This is the per-block re-arm
        // signal regardless of whether the driver masks (single-cycle
        // rewrites count every block; auto-init writes it once). Skips
        // per-write spam without the old coarse mask/unmask latch.
        let cur_gen = self.dma.count_gen[chan];
        if self.last_gen[chan] == cur_gen { return; }
        self.last_gen[chan] = cur_gen;

        // The captured base programming — what we hand to the real chip.
        let p = self.dma.ch[chan].prog;
        let (gpa, len, blog2) = if is16 {
            (((p.page as u32) << 16) | ((p.addr as u32) << 1),
             ((p.count as u32) + 1) * 2, 17u32)
        } else {
            (((p.page as u32) << 16) | p.addr as u32,
             (p.count as u32) + 1, 16u32)
        };

        // SB DMA-channel probe: the driver arms several tiny (≤ a few
        // bytes) single-cycle transfers at assorted low addresses
        // (observed: gpa 0x0, 0x73, 0x6573, all len=4) purely to confirm
        // DMA+IRQ wiring — it ignores the data. The reliable signal is
        // the *size* (real audio blocks are KB; e.g. 0x3B81), not the
        // address. We must NOT repoint such pages (a stale page→pool
        // alias + pool reuse corrupts memory — kernel stub #UD at
        // gpa=0). But the transfer must still complete so the card
        // raises the IRQ, else the driver decides "no SB" and falls back
        // to subtitles. Point the real 8237 at a throwaway scratch
        // frame, no page remap. (Also covers any low-system address.)
        if len < 0x100 || (gpa & !0xFFF) < 0x1000 {
            let scratch = crate::kernel::startup::arch_alloc_phys_contig(1, blog2);
            if scratch != 0 {
                program_real_8237(host_chan as u8, (scratch as u32) * 0x1000,
                                   len, p.mode, is16);
                crate::kernel::startup::arch_free_phys_contig(scratch, 1);
            }
            // [SB-DMA] DMA-probe trace disabled per request.
            return;
        }

        let page_off = (gpa & 0xFFF) as usize;
        let num_pages = (page_off + len as usize + 0xFFF) / 0x1000;

        // (Re)locate the guest buffer onto a contiguous run only when the
        // buffer (addr/len) differs from the live binding. Auto-init
        // reuses the same buffer every block; since we repointed the
        // guest PTEs, its refills land straight in the contiguous pages
        // (true zero-copy) — no re-alloc/re-copy needed.
        if self.remap_pages == 0 || gpa != self.last_gpa || len != self.last_len {
            if self.remap_pages != 0 {
                self.restore_guest_mapping();
                crate::kernel::startup::arch_free_phys_contig(
                    self.remap_start_page, self.remap_pages);
                self.remap_start_page = 0;
                self.remap_pages = 0;
            }
            let contig =
                crate::kernel::startup::arch_alloc_phys_contig(num_pages, blog2);
            if contig == 0 {
                // [SB-DMA] "no contiguous DMA region" trace disabled per request.
                self.last_gen[chan] = cur_gen.wrapping_sub(1); // retry next arm
                return;
            }
            // The ring-1 kernel shares the VM86 address space, so the
            // guest buffer is directly at its DOS-physical = linear
            // address `gpa`. Snapshot it, repoint those pages onto the
            // contiguous run, write the bytes back (now contig-backed).
            let vbase = (gpa & !0xFFF) as usize;
            let span = num_pages * 0x1000;
            let mut snap = alloc::vec![0u8; span];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vbase as *const u8, snap.as_mut_ptr(), span);
            }
            crate::kernel::startup::arch_swap_page_entries(
                vbase >> 12, SB_DMA_SHADOW_PAGE, num_pages);
            crate::kernel::startup::arch_map_phys_range(
                vbase >> 12, num_pages, contig, 0);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    snap.as_ptr(), vbase as *mut u8, span);
            }
            self.remap_start_page = contig;
            self.remap_pages = num_pages;
            self.last_gpa = gpa;
            self.last_len = len;
        }

        // Always (re)program the real 8237 on every (re)arm — single-
        // cycle drivers re-arm per block, so the real controller must be
        // re-pointed each time even though the binding is unchanged.
        let phys = (self.remap_start_page as u32) * 0x1000 + page_off as u32;
        program_real_8237(host_chan as u8, phys, len, p.mode, is16);
        // Armed: the real QEMU-8257 is now authoritative for this
        // channel's current-count reads (live decrement + terminal
        // 0xFFFF). `prog` (base regs) persists for partial re-arms.
        self.dma.ch[chan].armed = true;
        // [SB-DMA] vch→hch arm trace + [cs:0x166]/[0x14C] sampling disabled per request.
    }

    /// Apply this thread's `BLASTER=Axxx Iy Dz Hw …` env string. Unknown
    /// or missing tokens leave the SB16 defaults. `env` is the raw DOS
    /// environment block (NUL-separated `KEY=VAL`, double-NUL terminated).
    pub fn configure_from_env(&mut self, env: &[u8]) {
        let Some(val) = env_var(env, b"BLASTER") else { return };
        for tok in val.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
            let (key, rest) = (tok[0].to_ascii_uppercase(), &tok[1..]);
            let radix = if key == b'A' || key == b'P' { 16 } else { 10 };
            let Some(n) = parse_uint(rest, radix) else { continue };
            match key {
                b'A' => self.io_base = n as u16,
                b'I' => self.irq = n as u8,
                b'D' => self.dma8 = n as u8,
                b'H' => self.dma16 = n as u8,
                _ => {}
            }
        }
    }
}

/// Look up `KEY` in a DOS environment block, returning its value bytes.
fn env_var<'a>(env: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < env.len() && env[i] != 0 {
        let end = env[i..].iter().position(|&b| b == 0).map(|p| i + p)?;
        let entry = &env[i..end];
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            if entry[..eq].eq_ignore_ascii_case(key) {
                return Some(&entry[eq + 1..]);
            }
        }
        i = end + 1;
    }
    None
}

/// Read the real (QEMU) 8237's live current-count for host channel
/// `host`. Standard sequence: clear the byte-pointer flip-flop, read
/// low then high. QEMU's 8257 decrements this as QEMU-sb16 actually
/// consumes the buffer, so it's exact for both progress and (terminal-
/// count) completion. Channel-native units (bytes for 0-3, words 5-7),
/// matching what the guest programmed.
fn real_8237_count(host: u8) -> u16 {
    use crate::arch::{inb, outb};
    let (clr_ff, cnt) = if host < 4 {
        (0x0Cu16, (host as u16) * 2 + 1)
    } else {
        (0xD8u16, 0xC0 + ((host - 4) as u16) * 4 + 2)
    };
    outb(clr_ff, 0);
    let lo = inb(cnt) as u16;
    let hi = inb(cnt) as u16;
    (hi << 8) | lo
}

/// Program the physical 8237 for `chan` with the translated `phys`
/// address / `len` bytes / `mode`. 8-bit channels (0-3) are byte-
/// addressed; 16-bit channels (5-7) are word-addressed (addr/count in
/// words, page bit16 implied). Standard sequence: mask, clear flip-flop,
/// mode, addr lo/hi, page, count lo/hi, unmask.
fn program_real_8237(chan: u8, phys: u32, len: u32, mode: u8, is16: bool) {
    use crate::arch::outb;
    // DIAG: snapshot QEMU's i8257 current count for this channel *before*
    // we overwrite it. Writing the count reloads now[COUNT]=0, so this
    // tells us whether a completed transfer (count ~0xFFFF) is being
    // clobbered back to base by a (re)arm that happened before the guest
    // read it to validate completion.
    // [SB-DMA] program_real_8237 entry trace + pre-count sampling disabled per request.
    // Standard PC/AT page-register ports indexed by absolute channel.
    const PAGE: [u8; 8] = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];
    if is16 {
        let m = (chan - 4) as u16;            // local 0..3 on controller #2
        let addr = (phys >> 1) & 0xFFFF;       // word address
        let cnt = (len / 2) - 1;               // word count − 1
        outb(0xD4, 0x04 | (chan - 4));         // mask channel
        outb(0xD8, 0);                         // clear byte-pointer flip-flop
        outb(0xD6, mode);
        outb(0xC0 + (m * 4) as u16, addr as u8);
        outb(0xC0 + (m * 4) as u16, (addr >> 8) as u8);
        outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        outb(0xC0 + (m * 4 + 2) as u16, cnt as u8);
        outb(0xC0 + (m * 4 + 2) as u16, (cnt >> 8) as u8);
        outb(0xD4, chan - 4);                  // unmask channel
    } else {
        let cnt = len - 1;                     // byte count − 1
        outb(0x0A, 0x04 | chan);               // mask channel
        outb(0x0C, 0);                         // clear byte-pointer flip-flop
        outb(0x0B, mode);
        outb((chan as u16) * 2, phys as u8);
        outb((chan as u16) * 2, (phys >> 8) as u8);
        outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        outb((chan as u16) * 2 + 1, cnt as u8);
        outb((chan as u16) * 2 + 1, (cnt >> 8) as u8);
        outb(0x0A, chan);                      // unmask channel
    }
}

fn parse_uint(s: &[u8], radix: u32) -> Option<u32> {
    let mut acc: u32 = 0;
    let mut any = false;
    for &b in s {
        let d = (b as char).to_digit(radix)?;
        acc = acc.checked_mul(radix)?.checked_add(d)?;
        any = true;
    }
    any.then_some(acc)
}

