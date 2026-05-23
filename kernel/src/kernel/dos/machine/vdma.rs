//! Virtual 8237 DMA controller + Sound Blaster DMA virtualization.

use super::*;

/// PTE cache-disable bit (x86 PCD). On RetroOS it doubles as the
/// "externally owned" mark — COW-fork and address-space teardown both
/// skip such frames — exactly what an aliased permanent DMA buffer needs.
/// Arch's `paging2::flags` is private, so the bit is duplicated here per
/// the arch-boundary rule (small primitives are copied, not cross-called).
const PTE_CACHE_DISABLE: u64 = 1 << 4;

// Virtual 8237 DMA controller (generic — not SB-specific)
// ============================================================================
//
// A DOS program programs the 8237 with a *DOS-physical* buffer address,
// but runs paged in VM86, so the real DMA engine would fetch the wrong
// memory. We capture every channel's programming here; `SbDmaState` maps
// the BLASTER-declared channel onto the real card's channel by remapping
// the guest buffer contiguous.
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
/// `prog`'s validity, and every combination is
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
    dsp_test_reg: u8,
    dsp_read_data: Option<u8>,
    dsp_expect_test_write: bool,
    /// Current alias binding. `bound_chan == 0xFF` ⇒ none. While bound,
    /// the guest's `bound_vpage..+bound_pages` linear pages alias DMA
    /// channel `bound_host`'s permanent buffer; `bound_gpa`/`bound_len`
    /// are the 8237 programming the binding was built for (rebind probe).
    bound_chan: u8,
    bound_host: u8,
    bound_gpa: u32,
    bound_len: u32,
    bound_vpage: usize,
    bound_pages: usize,
    /// Set while the binding is detached for a background task switch
    /// (`sb_suspend`); `sb_resume` re-materializes it.
    suspended: bool,
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
            dsp_test_reg: 0, dsp_read_data: None, dsp_expect_test_write: false,
            bound_chan: 0xFF, bound_host: 0xFF,
            bound_gpa: 0, bound_len: 0, bound_vpage: 0, bound_pages: 0,
            suspended: false, last_gen: [0; 8],
        }
    }

    /// Current QEMU i8257 count for the SB 8-bit host channel.
    pub fn diag_host_count8(&self) -> u16 {
        real_8237_count(self.host_dma8)
    }

    /// Whether virtual DMA channel `ch` is armed on the real chip.
    pub fn dma_ch_armed(&self, ch: usize) -> bool {
        ch < 8 && self.dma.ch[ch].armed
    }

    /// Release any SB-DMA binding this thread holds — exec/exit cleanup.
    /// The per-channel buffers are permanent; this just detaches the guest
    /// alias and clears the re-arm cursor so a reused `SbDmaState` can't
    /// dangle. Also resets the SB DSP and masks the host SB channels so
    /// the next program sees a clean card — without this, OMF re-launch
    /// from a launcher inherits OMF1's mid-playback DSP / armed-8237
    /// state and OMF2's sound-init probe falls into a "wait for the card
    /// to settle" timeout branch (526 `INT 21 AH=2C` calls in the hang
    /// trace). Idempotent.
    pub fn release_dma_pool(&mut self) {
        self.unbind();
        // SB DSP reset: write 1 then 0 to io_base+6. QEMU's sb16 processes
        // this atomically; the hardware ~3 µs hold is irrelevant under
        // emulation. Puts the DSP back in its post-power-on state so the
        // next program's reset+probe behaves like the first one's.
        crate::arch::outb(self.io_base + 0x06, 1);
        crate::arch::outb(self.io_base + 0x06, 0);
        // Stop any in-flight host DMA cold; the next bind reprograms and
        // unmasks. host_dma8/host_dma16 are the SB16's 8-bit/16-bit lines.
        mask_real_8237(self.host_dma8);
        mask_real_8237(self.host_dma16);
        self.suspended = false;
        self.last_gen = [0; 8];
    }

    /// SB ports that pass straight through to the real card (QEMU
    /// `sb16`/`adlib`): the DSP/mixer block `[io_base, io_base+0x10)` and
    /// the OPL2/3 FM ports 0x388/0x389. Only the 8237 is virtual.
    pub fn is_passthrough(&self, p: u16) -> bool {
        (p >= self.io_base && p < self.io_base + 0x10) || matches!(p, 0x388 | 0x389)
    }

    /// Read an SB DSP/mixer/OPL passthrough port, with a tiny compatibility
    /// shim for DSP command E4h/E8h (test register write/read). Some older
    /// games poll base+0Eh forever waiting for E8h to produce a byte; QEMU
    /// sb16 does not appear to surface that response through passthrough.
    pub fn sb_read(&mut self, p: u16) -> u8 {
        if p == self.io_base + 0x0A {
            if let Some(v) = self.dsp_read_data.take() {
                return v;
            }
        } else if p == self.io_base + 0x0E && self.dsp_read_data.is_some() {
            return 0x80;
        }
        crate::arch::inb(p)
    }

    /// Write an SB DSP/mixer/OPL passthrough port. DSP E4h/E8h are handled
    /// locally; all other traffic continues to the real QEMU sb16/adlib.
    pub fn sb_write(&mut self, p: u16, val: u8) {
        if p == self.io_base + 0x0C {
            if self.dsp_expect_test_write {
                self.dsp_test_reg = val;
                self.dsp_expect_test_write = false;
                return;
            }
            match val {
                0xE4 => {
                    self.dsp_expect_test_write = true;
                    return;
                }
                0xE8 => {
                    self.dsp_read_data = Some(self.dsp_test_reg);
                    return;
                }
                _ => {}
            }
        }
        crate::arch::outb(p, val);
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

    /// Called after every virtual-8237 write. When the BLASTER channel is
    /// (re)armed, alias the guest's DMA buffer onto that channel's
    /// permanent host buffer and program the real 8237. A no-op until the
    /// guest finishes a count write (the per-block re-arm signal).
    pub fn maybe_remap(&mut self) {
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = self.dma8 as usize;
        let c16 = self.dma16 as usize;
        let armed8 = c8 < 4 && !self.dma.ch[c8].masked
            && self.dma.ch[c8].prog.count != 0;
        let armed16 = (5..8).contains(&c16) && !self.dma.ch[c16].masked
            && self.dma.ch[c16].prog.count != 0;
        let (chan, is16, host) = if armed16 {
                (c16, true, self.host_dma16 as usize)
            } else if armed8 {
                (c8, false, self.host_dma8 as usize)
            } else {
                // Idle/masked — keep the binding (reused next block).
                return;
            };

        // Act only when the guest (re)armed this channel: it bumped
        // count_gen since we last acted. The per-block re-arm signal
        // regardless of whether the driver masks (single-cycle rewrites
        // count every block; auto-init writes it once).
        let cur_gen = self.dma.count_gen[chan];
        if self.last_gen[chan] == cur_gen { return; }
        self.last_gen[chan] = cur_gen;

        let p = self.dma.ch[chan].prog;
        let (gpa, len) = chan_gpa_len(&p, is16);
        self.arm(chan, host, is16, gpa, len, p.mode);
    }

    /// Alias the guest buffer at `gpa` onto host DMA channel `host`'s
    /// permanent buffer and program the real 8237. Driven from
    /// `maybe_remap` (a guest port write) and `sb_resume` (replaying the
    /// virtual-8237 state after a task switch).
    fn arm(&mut self, chan: usize, host: usize, is16: bool,
           gpa: u32, len: u32, mode: u8) {
        let bufpage = crate::kernel::startup::arch_dma_channel_buf(host);
        if bufpage == 0 { return; }              // no reserved buffer
        // The buffer sits at `off` inside its channel's 64 KB / 128 KB
        // window; the channel buffer is window-aligned, so the same `off`
        // lands it correctly. An ISA transfer never crosses the boundary.
        let win = if is16 { 0x1_FFFFu32 } else { 0xFFFFu32 };
        let off = gpa & win;
        let phys = (bufpage as u32) * 0x1000 + off;

        // SB DMA-channel probe: the driver fires tiny (≤ a few bytes)
        // single-cycle transfers at assorted low addresses purely to
        // confirm DMA+IRQ wiring — it ignores the data. Never alias those
        // (page 0 = IVT); point the real chip at the channel buffer
        // so the transfer completes and raises the IRQ.
        if len < 0x100 || (gpa & !0xFFF) < 0x1000 {
            program_real_8237(host as u8, phys, len, mode, is16);
            self.dma.ch[chan].armed = true;
            return;
        }

        // (Re)bind only when the guest buffer (channel/addr/len) changed.
        // Auto-init and single-cycle re-arms of the same buffer skip
        // straight to re-programming the real chip — true zero-copy: the
        // guest's refills already land in the channel buffer via the alias.
        let bound = self.bound_chan == chan as u8 && self.bound_host == host as u8
            && self.bound_gpa == gpa && self.bound_len == len;
        if !bound {
            if self.bound_gpa != 0 { self.unbind(); }
            let vbase     = (gpa & !0xFFF) as usize;
            let page_off  = (gpa & 0xFFF) as usize;
            let num_pages = (page_off + len as usize + 0xFFF) / 0x1000;
            let win_pgoff = ((off & !0xFFF) >> 12) as u64;
            // A well-formed ISA transfer never crosses its 64 KB / 128 KB
            // window; refuse one that would overrun the channel buffer.
            let buf_pages = if is16 { 32usize } else { 16usize };
            if win_pgoff as usize + num_pages > buf_pages { return; }
            let span = num_pages * 0x1000;
            // Snapshot the guest's pre-filled content — whole pages, so the
            // unrelated neighbour bytes on partial end pages survive.
            let mut snap = alloc::vec![0u8; span];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vbase as *const u8, snap.as_mut_ptr(), span);
            }
            // Free the guest's original frames, then alias the range onto
            // the channel buffer with CACHE_DISABLE — externally owned, so
            // COW-fork and address-space teardown both leave it intact.
            crate::kernel::startup::arch_free_range(vbase >> 12, num_pages);
            crate::kernel::startup::arch_map_phys_range(
                vbase >> 12, num_pages, bufpage + win_pgoff, PTE_CACHE_DISABLE);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    snap.as_ptr(), vbase as *mut u8, span);
            }
            self.bound_chan  = chan as u8;
            self.bound_host  = host as u8;
            self.bound_gpa   = gpa;
            self.bound_len   = len;
            self.bound_vpage = vbase >> 12;
            self.bound_pages = num_pages;
        }

        program_real_8237(host as u8, phys, len, mode, is16);
        // Armed: the real QEMU-8257 is now authoritative for this channel's
        // live addr/count reads (`dma_read` serves them).
        self.dma.ch[chan].armed = true;
    }

    /// Detach the current alias: hand the guest's buffer range fresh
    /// anonymous frames and copy the channel buffer's content back into
    /// them, so the partial-end-page neighbour data survives and the guest
    /// can reuse the linear range. The channel buffer is permanent. No-op
    /// when nothing is bound.
    fn unbind(&mut self) {
        if self.bound_gpa == 0 { return; }
        let vbase = self.bound_vpage << 12;
        let span  = self.bound_pages * 0x1000;
        let mut snap = alloc::vec![0u8; span];
        unsafe {
            core::ptr::copy_nonoverlapping(
                vbase as *const u8, snap.as_mut_ptr(), span);
        }
        crate::kernel::startup::arch_map_fresh_range(
            self.bound_vpage, self.bound_pages);
        unsafe {
            core::ptr::copy_nonoverlapping(
                snap.as_ptr(), vbase as *mut u8, span);
        }
        self.bound_chan  = 0xFF;
        self.bound_host  = 0xFF;
        self.bound_gpa   = 0;
        self.bound_len   = 0;
        self.bound_vpage = 0;
        self.bound_pages = 0;
    }

    /// Task switched to the background: detach the alias (the channel
    /// buffer's content is saved back into the task's own memory) and mask
    /// the real 8237 channel so the card stops pulling a buffer that's no
    /// longer ours. The virtual 8237 keeps the armed state; `sb_resume`
    /// replays it. Must run with this task's address space active.
    pub fn sb_suspend(&mut self) {
        if self.bound_gpa == 0 { return; }
        mask_real_8237(self.bound_host);
        self.unbind();
        self.suspended = true;
    }

    /// Task switched back to the foreground: re-materialize the binding —
    /// re-alias every channel the virtual 8237 still shows armed and
    /// reprogram the real 8237. Must run with this task's address space
    /// active.
    pub fn sb_resume(&mut self) {
        if !self.suspended { return; }
        self.suspended = false;
        for chan in 0..8 {
            if !self.dma.ch[chan].armed { continue; }
            let is16 = chan >= 4;
            let host = if is16 { self.host_dma16 } else { self.host_dma8 } as usize;
            let p = self.dma.ch[chan].prog;
            let (gpa, len) = chan_gpa_len(&p, is16);
            self.arm(chan, host, is16, gpa, len, p.mode);
        }
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

/// Decode a channel's captured 8237 programming into the (DOS-physical
/// buffer address, byte length) the SB-DMA layer works in. 16-bit
/// channels count words: addr is a word offset, count a word count − 1.
fn chan_gpa_len(p: &DmaProg, is16: bool) -> (u32, u32) {
    if is16 {
        (((p.page as u32) << 16) | ((p.addr as u32) << 1), ((p.count as u32) + 1) * 2)
    } else {
        (((p.page as u32) << 16) | p.addr as u32, (p.count as u32) + 1)
    }
}

/// Mask host DMA channel `chan` on the real 8237 — stops the card pulling
/// the channel buffer while the owning task is backgrounded.
fn mask_real_8237(chan: u8) {
    use crate::arch::outb;
    if (4..8).contains(&chan) { outb(0xD4, 0x04 | (chan - 4)); }
    else if chan < 4 { outb(0x0A, 0x04 | chan); }
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

