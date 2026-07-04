//! Virtual Sound Blaster card (DSP + SB-DMA virtualization).
//!
//! The SB is the one DOS sound device RetroOS virtualizes. It *uses* an ISA DMA
//! channel — the generic [`Dma8237`](super::vdma::Dma8237) shadow in `vdma.rs`,
//! exactly as a real SB card uses an 8237 channel — and runs in one of two
//! modes (passthrough vs emulated, the boot-time `platform::Audio` verdict):
//!
//!  - **Passthrough** — a real card answers (QEMU `sb16`/`adlib` on metal): DSP
//!    traffic forwards to it, and the guest's DMA buffer is remapped contiguous
//!    onto the real 8237 (`maybe_remap` → `arm`).
//!  - **Emulated** — no card answers (the hosted interpreter, or metal hardware
//!    with no SB16): a software DSP command FSM + a play cursor synthesize
//!    playback from the guest's DMA buffer into the canonical kernel `sound`
//!    API (`audio_tick`), with no real-card interaction at all.

use super::*;

/// PTE cache-disable bit (x86 PCD). On RetroOS it doubles as the
/// "externally owned" mark — COW-fork and address-space teardown both
/// skip such frames — exactly what an aliased permanent DMA buffer needs.
/// Arch's `paging2::flags` is private, so the bit is duplicated here per
/// the arch-boundary rule (small primitives are copied, not cross-called).
const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Software DSP/DMA playback engine — populated and driven only in
/// software-emulated mode. Turns the guest's DSP command stream + virtual-8237
/// buffer programming into canonical PCM (`sound::play`), paced by virtual time,
/// raising the SB IRQ once per completed DMA block exactly like the real card's
/// terminal count. See [`SoundBlaster::audio_tick`].
#[derive(Clone, Copy)]
struct EmuDsp {
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
    /// Minimal OPL2 (AdLib FM) state — *just enough to pass FM detection*, no
    /// synthesis. `opl_index` = the selected register (port 0x388 write);
    /// `opl_status` = the timer status the detect routine reads from 0x388.
    /// Without this, FM detection fails and Apogee games exit ("could not
    /// detect FM chip") before they ever reach digital sound.
    opl_index: u8,
    opl_status: u8,
    /// SB16 mixer register index (port base+4 write); its data port is base+5.
    mixer_index: u8,
    /// Mixer reg 0x82 IRQ status: bit0 = 8-bit DMA IRQ pending, bit1 = 16-bit.
    /// Set when the SB IRQ is raised (by playback width); cleared when the guest
    /// acks (reads base+0xE for 8-bit / base+0xF for 16-bit). A 16-bit driver
    /// reads this to confirm "that was a *16-bit* DMA interrupt".
    irq_status: u8,

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

    /// Ring geometry, snapshotted from the virtual 8237 at `start playback`.
    buf_gpa: u32,      // DOS-physical base of the auto-init ring
    buf_frames: u32,   // ring length in frames
    block_frames: u32, // frames between SB IRQs (one DMA block)
    /// Frames consumed since playback start (monotonic). `dma_read` derives the
    /// guest-visible down-count from this.
    cursor: u64,
    next_irq: u64,    // cursor value of the next block boundary (IRQ point)
    frac: u64,        // sub-frame pacing accumulator, units of frames×1000
    last_ms: u64,     // get_ticks() at the last `audio_tick`
    /// Set when a block boundary is reached and its IRQ raised; cleared when the
    /// guest reads the DMA count (services the block — poll-bool/poll-dma/irq-mix
    /// all do). While set, consumption freezes at the boundary so we never
    /// outrun the guest's refill (which would re-read stale ring data and repeat
    /// the previous lap's audio). Locks consume-rate to refill-rate.
    awaiting_ack: bool,
}

impl EmuDsp {
    const fn new() -> Self {
        EmuDsp {
            out: [0; 4], out_len: 0,
            cmd: None, params: [0; 3], param_got: 0, param_need: 0,
            reset_prev: 0, test_reg: 0, opl_index: 0, opl_status: 0,
            mixer_index: 0, irq_status: 0,
            playing: false, rate: 22050, bits: 8, stereo: false, block_param: 0,
            single: false,
            buf_gpa: 0, buf_frames: 0, block_frames: 0,
            cursor: 0, next_irq: 0, frac: 0, last_ms: 0,
            awaiting_ack: false,
        }
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
}

/// Per-thread Sound Blaster card state: the BLASTER-declared channel/IRQ map,
/// the generic virtual 8237 it drives, and either the passthrough remap binding
/// or the software DSP/DMA engine depending on `mode`.
pub struct SoundBlaster {
    /// The software DSP/DMA engine (used only when emulating).
    emu: EmuDsp,
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

impl SoundBlaster {
    /// Defaults: A220 I7 D1 H5 (guest sees SB IRQ 7; the host chip stays
    /// on its real line and the IRQ relay maps host→guest, so the two are
    /// intentionally decoupled). Overridden by the guest's `BLASTER=` env.
    pub fn new() -> Self {
        Self {
            emu: EmuDsp::new(),
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
    pub fn diag_host_count8<A: crate::Arch>(&self, machine: &mut A) -> u16 {
        real_8237_count(machine, self.host_dma8)
    }

    /// Whether the SB is serviced by the software emulation (no real card).
    pub fn is_emulated(&self) -> bool {
        self.emulated()
    }

    /// Whether virtual DMA channel `ch` is armed on the real chip.
    pub fn dma_ch_armed(&self, ch: usize) -> bool {
        ch < 8 && self.dma.ch[ch].armed
    }

    /// Release any SB-DMA binding this thread holds — exec/exit cleanup.
    /// The per-channel buffers are permanent; this just detaches the guest
    /// alias and clears the re-arm cursor so a reused `SoundBlaster` can't
    /// dangle. Also resets the SB DSP and masks the host SB channels so
    /// the next program sees a clean card — without this, OMF re-launch
    /// from a launcher inherits OMF1's mid-playback DSP / armed-8237
    /// state and OMF2's sound-init probe falls into a "wait for the card
    /// to settle" timeout branch (526 `INT 21 AH=2C` calls in the hang
    /// trace). Idempotent.
    pub fn release_dma_pool<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>) {
        if self.emulated() {
            // No real card / no buffer alias in emulation: just stop the
            // software DSP so the next program sees a clean, idle card.
            self.emu.playing = false;
            self.emu.out_len = 0;
            self.emu.cmd = None;
            return;
        }
        self.unbind(machine, regs);
        // SB DSP reset: write 1 then 0 to io_base+6. QEMU's sb16 processes
        // this atomically; the hardware ~3 µs hold is irrelevant under
        // emulation. Puts the DSP back in its post-power-on state so the
        // next program's reset+probe behaves like the first one's.
        machine.outb(self.io_base + 0x06, 1);
        machine.outb(self.io_base + 0x06, 0);
        // Stop any in-flight host DMA cold; the next bind reprograms and
        // unmasks. host_dma8/host_dma16 are the SB16's 8-bit/16-bit lines.
        mask_real_8237(machine, self.host_dma8);
        mask_real_8237(machine, self.host_dma16);
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
    pub fn sb_read<A: crate::Arch>(&mut self, machine: &mut A, p: u16) -> u8 {
        if self.emulated() {
            return self.emu_read(p);
        }
        if p == self.io_base + 0x0A {
            if let Some(v) = self.dsp_read_data.take() {
                return v;
            }
        } else if p == self.io_base + 0x0E && self.dsp_read_data.is_some() {
            return 0x80;
        }
        machine.inb(p)
    }

    /// Write an SB DSP/mixer/OPL passthrough port. DSP E4h/E8h are handled
    /// locally; all other traffic continues to the real QEMU sb16/adlib.
    pub fn sb_write<A: crate::Arch>(&mut self, machine: &mut A, p: u16, val: u8) {
        if self.emulated() {
            self.emu_write(p, val);
            return;
        }
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
        machine.outb(p, val);
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
    pub fn dma_read<A: crate::Arch>(&mut self, machine: &mut A, port: u16) -> u8 {
        // Channel-data ports only: DMA1 0x00..=0x07 (addr/count pairs for
        // chan 0..3), DMA2 0xC0..=0xCF (addr/count pairs for chan 4..7,
        // 4-byte stride per channel due to 16-bit alignment). Control
        // registers (0x08..=0x0F status/mask/etc., 0xD0..=0xDF for DMA2)
        // and page-register ports don't index into ch[] — route them to
        // io_read for the captured/synthetic control state. Without the
        // upper bound, port 0xD0 produced chan=8 and panicked on ch[8].
        let (is_cnt, chan, hi_ctrl) = if port <= 0x07 {
            (port & 1 == 1, (port >> 1) as usize, false)
        } else if (0xC0..=0xCF).contains(&port) {
            let r = (port - 0xC0) >> 1;
            (r & 1 == 1, 4 + (r >> 1) as usize, true)
        } else {
            return self.dma.io_read(machine, port);
        };

        // Emulated card: the live current-count comes from the software DSP's
        // play cursor (there is no real 8257 to interrogate).
        if self.emulated() {
            return self.emu_dma_read(is_cnt, chan, hi_ctrl);
        }

        let host = if chan == self.dma8 as usize { Some(self.host_dma8) }
                   else if chan == self.dma16 as usize { Some(self.host_dma16) }
                   else { None };
        if self.dma.ch[chan].armed
            && let Some(h) = host {
                // Serve the *live* transfer state for the armed SB channel,
                // lo/hi via the controller byte-pointer flip-flop; snapshot
                // the full u16 at the low-byte read so the pair is coherent.
                let ff = if hi_ctrl { &mut self.dma.ff_hi }
                         else { &mut self.dma.ff_lo };
                let low = !*ff;
                *ff = !*ff;
                if low {
                    let live_count = real_8237_count(machine, h);
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
        self.dma.io_read(machine, port)
    }

    /// Called after every virtual-8237 write. When the BLASTER channel is
    /// (re)armed, alias the guest's DMA buffer onto that channel's
    /// permanent host buffer and program the real 8237. A no-op until the
    /// guest finishes a count write (the per-block re-arm signal).
    pub fn maybe_remap<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>) {
        if self.emulated() {
            // No real chip to program / no buffer to alias: the virtual-8237
            // `prog` is already captured (io_write), and the software DSP reads
            // the guest buffer directly at playback. Nothing to remap.
            return;
        }
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
        self.arm(machine, regs, chan, host, is16, gpa, len, p.mode);
    }

    /// Alias the guest buffer at `gpa` onto host DMA channel `host`'s
    /// permanent buffer and program the real 8237. Driven from
    /// `maybe_remap` (a guest port write) and `sb_resume` (replaying the
    /// virtual-8237 state after a task switch).
    #[allow(clippy::too_many_arguments)]
    fn arm<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>, chan: usize, host: usize, is16: bool,
           gpa: u32, len: u32, mode: u8) {
        let bufpage = machine.dma_channel_buf(host);
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
            program_real_8237(machine, host as u8, phys, len, mode, is16);
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
            if self.bound_gpa != 0 { self.unbind(machine, regs); }
            let vbase     = (gpa & !0xFFF) as usize;
            let page_off  = (gpa & 0xFFF) as usize;
            let num_pages = (page_off + len as usize).div_ceil(0x1000);
            let win_pgoff = ((off & !0xFFF) >> 12) as u64;
            // A well-formed ISA transfer never crosses its 64 KB / 128 KB
            // window; refuse one that would overrun the channel buffer.
            let buf_pages = if is16 { 32usize } else { 16usize };
            if win_pgoff as usize + num_pages > buf_pages { return; }
            let span = num_pages * 0x1000;
            // Snapshot the guest's pre-filled content — whole pages, so the
            // unrelated neighbour bytes on partial end pages survive.
            let mut snap = alloc::vec![0u8; span];
            regs.copy_from(vbase, &mut snap);
            // Free the guest's original frames, then alias the range onto
            // the channel buffer with CACHE_DISABLE — externally owned, so
            // COW-fork and address-space teardown both leave it intact.
            machine.unmap_range(vbase >> 12, num_pages);
            machine.map_phys_range(
                vbase >> 12, num_pages, bufpage + win_pgoff, PTE_CACHE_DISABLE);
            regs.copy_to(vbase, &snap);
            self.bound_chan  = chan as u8;
            self.bound_host  = host as u8;
            self.bound_gpa   = gpa;
            self.bound_len   = len;
            self.bound_vpage = vbase >> 12;
            self.bound_pages = num_pages;
        }

        program_real_8237(machine, host as u8, phys, len, mode, is16);
        // Armed: the real QEMU-8257 is now authoritative for this channel's
        // live addr/count reads (`dma_read` serves them).
        self.dma.ch[chan].armed = true;
    }

    /// Detach the current alias: hand the guest's buffer range fresh
    /// anonymous frames and copy the channel buffer's content back into
    /// them, so the partial-end-page neighbour data survives and the guest
    /// can reuse the linear range. The channel buffer is permanent. No-op
    /// when nothing is bound.
    fn unbind<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>) {
        if self.bound_gpa == 0 { return; }
        let vbase = self.bound_vpage << 12;
        let span  = self.bound_pages * 0x1000;
        let mut snap = alloc::vec![0u8; span];
        regs.copy_from(vbase, &mut snap);
        machine.map_fresh_range(
            self.bound_vpage, self.bound_pages);
        regs.copy_to(vbase, &snap);
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
    pub fn sb_suspend<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>) {
        if self.emulated() { return; } // no real chip / alias to detach
        if self.bound_gpa == 0 { return; }
        mask_real_8237(machine, self.bound_host);
        self.unbind(machine, regs);
        self.suspended = true;
    }

    /// Task switched back to the foreground: re-materialize the binding —
    /// re-alias every channel the virtual 8237 still shows armed and
    /// reprogram the real 8237. Must run with this task's address space
    /// active.
    pub fn sb_resume<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>) {
        if self.emulated() { return; }
        if !self.suspended { return; }
        self.suspended = false;
        for chan in 0..8 {
            if !self.dma.ch[chan].armed { continue; }
            let is16 = chan >= 4;
            let host = if is16 { self.host_dma16 } else { self.host_dma8 } as usize;
            let p = self.dma.ch[chan].prog;
            let (gpa, len) = chan_gpa_len(&p, is16);
            self.arm(machine, regs, chan, host, is16, gpa, len, p.mode);
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

    // ── Software DSP/DMA emulation (platform::Audio emulated paths) ─────────
    //
    // Active only when no real card answers. The guest drives the standard SB16
    // DSP register file (reset, version, set-rate, auto-init playback); we run
    // the command FSM, then `audio_tick` consumes the guest's DMA ring into
    // canonical PCM (`sound::play`) paced by virtual time, raising the SB IRQ
    // per block. The virtual 8237 (`self.dma`) already captured the buffer
    // programming, so playback needs no real-chip interaction at all.

    /// Software emulation vs real-card passthrough — the boot-time platform
    /// probe's verdict (`platform::Audio`), not probed here. The OPL window
    /// for passthrough is part of the DOS io_policy template for the same
    /// reason: derived, not granted at runtime.
    fn emulated(&self) -> bool {
        !crate::kernel::platform::get().audio.sb_passthrough()
    }

    /// Emulated DSP/mixer port read.
    fn emu_read(&mut self, p: u16) -> u8 {
        // OPL2 status register (0x388 or io_base+8): timer-expiry bits the FM
        // detection routine checks.
        if p == 0x388 || p == self.io_base + 8 {
            return self.emu.opl_status;
        }
        match p.wrapping_sub(self.io_base) {
            0x05 => match self.emu.mixer_index {       // mixer data
                0x82 => self.emu.irq_status,           // IRQ status (8/16-bit)
                0x80 => match self.irq {               // IRQ select
                    2 | 9 => 0x01, 5 => 0x02, 7 => 0x04, 10 => 0x08, _ => 0x04,
                },
                0x81 => (1u8 << (self.dma8 & 7)) | (1u8 << (self.dma16 & 7)), // DMA select
                _ => 0x00,
            },
            0x0A => self.emu.pop_out(),                // DSP read data
            0x0C => 0x00,                              // write-status: always ready
            0x0E => {                                  // read-status / 8-bit IRQ ack
                self.emu.irq_status &= !0x01;          // reading acks the 8-bit IRQ
                self.emu.awaiting_ack = false;         // ...and releases the produce gate
                if self.emu.out_len > 0 { 0x80 } else { 0x00 }
            }
            0x0F => {                                  // 16-bit IRQ ack
                self.emu.irq_status &= !0x02;
                self.emu.awaiting_ack = false;
                0x00
            }
            _ => 0xFF,
        }
    }

    /// Emulated DSP/mixer port write.
    fn emu_write(&mut self, p: u16, val: u8) {
        // OPL2 FM (AdLib 0x388/0x389, or the SB's OPL at io_base+8/+9): index
        // register select + the timer-control register, enough for detection.
        if p == 0x388 || p == self.io_base + 8 {
            self.emu.opl_index = val;
            return;
        }
        if p == 0x389 || p == self.io_base + 9 {
            if self.emu.opl_index == 0x04 {
                // Timer control: bit7 = reset status/IRQ; bit0/1 = start T1/T2.
                // Detection starts a timer then reads status expecting it
                // "expired", so set the expiry bits on start (no real timing).
                if val & 0x80 != 0 {
                    self.emu.opl_status = 0;
                } else {
                    if val & 0x01 != 0 { self.emu.opl_status |= 0xC0; } // T1 → IRQ|T1
                    if val & 0x02 != 0 { self.emu.opl_status |= 0xA0; } // T2 → IRQ|T2
                }
            }
            return; // other FM registers: no synthesis (music stays silent)
        }
        match p.wrapping_sub(self.io_base) {
            0x04 => self.emu.mixer_index = val, // mixer register select
            0x05 => {}                          // mixer data: no mixing modeled
            0x06 => {
                // DSP reset: a 1→0 edge triggers the reset handshake.
                if self.emu.reset_prev == 1 && val == 0 {
                    self.emu.playing = false;
                    self.emu.cmd = None;
                    self.emu.param_got = 0;
                    self.emu.out_len = 0;
                    self.emu.push_out(0xAA); // reset acknowledge
                }
                self.emu.reset_prev = val;
            }
            0x0C => self.emu_dsp_byte(val), // DSP command / parameter port
            _ => {}                         // mixer index/data, OPL: ignored
        }
    }

    /// Feed one byte to the DSP command FSM: a parameter for the in-flight
    /// command, or the start of a new one.
    fn emu_dsp_byte(&mut self, val: u8) {
        if let Some(cmd) = self.emu.cmd {
            self.emu.params[self.emu.param_got as usize] = val;
            self.emu.param_got += 1;
            if self.emu.param_got >= self.emu.param_need {
                self.emu_exec(cmd);
                self.emu.cmd = None;
                self.emu.param_got = 0;
            }
            return;
        }
        // Parameter count by command (only the subset DSP clients use here).
        let need = match val {
            0x40 | 0xE0 | 0xE4 => 1,              // time constant; ident byte; test-reg write
            0x14 | 0x41 | 0x42 | 0x48 | 0x80 => 2, // single-cycle len, out/in rate, block, silence
            0xB0..=0xCF => 3,                      // SB16 16/8-bit DMA: mode + length lo/hi
            _ => 0,                               // 0x1C/0x90/0x91/0xE8 etc. take no params
        };
        if need > 0 {
            self.emu.cmd = Some(val);
            self.emu.param_need = need;
            self.emu.param_got = 0;
        } else {
            self.emu_exec(val);
        }
    }

    /// Execute a fully-parameterized DSP command.
    fn emu_exec(&mut self, cmd: u8) {
        let p = self.emu.params;
        match cmd {
            0xE1 => {
                self.emu.push_out(4); // DSP version 4.5 (SB16)
                self.emu.push_out(5);
            }
            // Detection helpers some drivers use to confirm a real DSP:
            0xE0 => self.emu.push_out(!p[0]), // identification: return ~byte
            0xE4 => self.emu.test_reg = p[0], // write test register
            0xE8 => self.emu.push_out(self.emu.test_reg), // read test register back
            0xD1 | 0xD4 => {}                          // speaker on / continue DMA
            0xD0 | 0xD3 | 0xD9 | 0xDA => self.emu.playing = false, // pause / speaker off / exit auto-init
            0x40 => {
                let tc = p[0] as u32;
                self.emu.rate = if tc < 256 { 1_000_000 / (256 - tc) } else { 22050 };
            }
            0x41 => self.emu.rate = ((p[0] as u32) << 8) | p[1] as u32, // output rate (hi, lo)
            0x42 => {}                                                  // input rate: ignore
            0x48 => self.emu.block_param = (p[0] as u16) | ((p[1] as u16) << 8),
            // Legacy 8-bit mono output. 0x1C/0x90 = auto-init (block from 0x48);
            // 0x14/0x91 = single-cycle (play once; length from the 8237).
            0x1C | 0x90 => self.emu_start(8, false, None, false),
            0x14 | 0x91 => self.emu_start(8, false, None, true),
            // SB16 8-/16-bit output: mode byte + 16-bit length; bit1 = auto-init,
            // its absence = single-cycle. (0xC8.., 0xB8.. are input/ADC — ignored.)
            0xC0..=0xC7 => {
                let stereo = p[0] & 0x20 != 0;
                let single = cmd & 0x02 == 0;
                self.emu_start(8, stereo, Some((p[1] as u16) | ((p[2] as u16) << 8)), single);
            }
            0xB0..=0xB7 => {
                let stereo = p[0] & 0x20 != 0;
                let single = cmd & 0x02 == 0;
                self.emu_start(16, stereo, Some((p[1] as u16) | ((p[2] as u16) << 8)), single);
            }
            _ => {}
        }
    }

    /// Begin auto-init playback: snapshot the ring geometry from the active
    /// BLASTER channel's virtual-8237 programming and arm the play cursor.
    fn emu_start(&mut self, bits: u8, stereo: bool, block_override: Option<u16>, single: bool) {
        self.emu.bits = bits;
        self.emu.stereo = stereo;
        self.emu.single = single;
        if let Some(b) = block_override {
            self.emu.block_param = b;
        }
        let channels = if stereo { 2u32 } else { 1 };

        let is16 = bits == 16;
        let chan = if is16 { self.dma16 as usize } else { self.dma8 as usize };
        let prog = self.dma.ch[chan].prog;
        let (gpa, len_bytes) = chan_gpa_len(&prog, is16);
        let frame_bytes = (bits as u32 / 8) * channels;
        self.emu.buf_gpa = gpa;
        self.emu.buf_frames = len_bytes.checked_div(frame_bytes).unwrap_or(0);
        // Single-cycle: the whole buffer is one block — IRQ fires at the end and
        // playback stops. Auto-init: IRQ per DSP block and the ring loops.
        self.emu.block_frames = if single {
            self.emu.buf_frames.max(1)
        } else {
            // Block size is "transfers − 1"; a transfer is one sample/channel.
            ((self.emu.block_param as u32 + 1) / channels).max(1)
        };
        self.emu.cursor = 0;
        self.emu.next_irq = self.emu.block_frames as u64;
        self.emu.frac = 0;
        self.emu.awaiting_ack = false;
        self.emu.playing = self.emu.buf_frames > 0;
    }

    /// Advance emulated playback by the virtual time elapsed since the last
    /// call: consume `rate × Δt` ring frames into the kernel sound API and
    /// raise the SB IRQ for each completed block. Self-pacing — the guest's
    /// per-block refill keeps up because we consume at exactly its sample rate,
    /// and the auto-init ring's prime gives the refill latency headroom.
    pub fn audio_tick<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        regs: &mut Vcpu<A::PageTable>,
        vpic: &mut super::vpic::VirtualPic,
    ) {
        if !self.emulated() {
            return;
        }
        if !self.emu.playing {
            self.emu.last_ms = machine.get_ticks(); // keep Δt small for first tick
            return;
        }
        // Frozen at a block boundary until the guest services the IRQ (clears
        // `awaiting_ack` by reading the DMA count). This is what stops the
        // consume cursor outrunning the guest's refill (which would re-read
        // stale ring frames and repeat the previous lap's audio).
        if self.emu.awaiting_ack {
            self.emu.last_ms = machine.get_ticks();
            return;
        }
        // Pace the play cursor by virtual time at the sample rate. The cursor is
        // the GUEST-VISIBLE playback position — the DMA count and the SB IRQ both
        // derive from it — so it must advance at the real rate: drivers verify
        // 16-bit DMA by watching the count move at the programmed rate (Duke3D
        // bails otherwise). On metal virtual time ≈ the AC'97 crystal, so this
        // stays rate-matched to the codec without a cushion/clock-follow (which
        // led the count and broke that verification).
        let now = machine.get_ticks();
        let dt = now.saturating_sub(self.emu.last_ms);
        self.emu.last_ms = now;
        if dt == 0 {
            return;
        }
        self.emu.frac += self.emu.rate as u64 * dt; // units: frames × 1000
        let mut advance = self.emu.frac / 1000;
        self.emu.frac %= 1000;
        if advance == 0 {
            return;
        }
        // Advance at most to the next block boundary, then gate on the guest.
        let to_boundary = self.emu.next_irq - self.emu.cursor; // ≥ 1
        if advance >= to_boundary {
            advance = to_boundary;
            self.emu.frac = 0; // discard the excess; we resume on the guest's ack
            self.emit_frames(machine, regs, advance);
            self.emu.cursor += advance;
            self.emu.awaiting_ack = true;
            // Mixer IRQ-status bit by transfer width (16-bit drivers check this).
            self.emu.irq_status |= if self.emu.bits == 16 { 0x02 } else { 0x01 };
            if !vpic.is_requested(self.irq) {
                vpic.raise(self.irq);
            }
            if self.emu.single {
                self.emu.playing = false; // single-cycle: one pass done, stop (no loop)
            } else {
                self.emu.next_irq += self.emu.block_frames as u64;
            }
        } else {
            self.emit_frames(machine, regs, advance);
            self.emu.cursor += advance;
        }
    }

    /// Copy `count` ring frames (from `cursor`, wrapping) out of guest memory
    /// and hand them to the kernel sound layer.
    fn emit_frames<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Vcpu<A::PageTable>, count: u64) {
        let channels = if self.emu.stereo { 2u32 } else { 1 };
        let frame_bytes = (self.emu.bits as u32 / 8) * channels;
        if frame_bytes == 0 || self.emu.buf_frames == 0 {
            return;
        }
        let fmt = crate::kernel::sound::Format {
            bits: self.emu.bits,
            signed: self.emu.bits == 16,
            channels: channels as u8,
        };
        let mut remaining = count;
        let mut pos = (self.emu.cursor % self.emu.buf_frames as u64) as u32;
        while remaining > 0 {
            let run = remaining.min((self.emu.buf_frames - pos) as u64) as u32;
            let mut scratch = alloc::vec![0u8; (run * frame_bytes) as usize];
            let addr = self.emu.buf_gpa as usize + (pos * frame_bytes) as usize;
            regs.copy_from(addr, &mut scratch);
            crate::kernel::sound::play(machine, self.emu.rate, fmt, &scratch);
            remaining -= run as u64;
            pos += run;
            if pos >= self.emu.buf_frames {
                pos = 0;
            }
        }
    }

    /// Emulated DMA current-address/count read: serve the active SB channel's
    /// live state from the play cursor (auto-init down-count), other channels
    /// from the captured base programming. Mirrors `dma_read`'s flip-flop split.
    fn emu_dma_read(&mut self, is_cnt: bool, chan: usize, hi_ctrl: bool) -> u8 {
        let is_active = chan == self.dma8 as usize || chan == self.dma16 as usize;
        // The guest reading the active channel's count = it serviced the block
        // (computed `current_play_seg` to refill). Release the consume gate so
        // playback advances in lock-step with the refill, never ahead of it.
        if is_cnt && is_active && self.emu.playing {
            self.emu.awaiting_ack = false;
        }
        let ff = if hi_ctrl { &mut self.dma.ff_hi } else { &mut self.dma.ff_lo };
        let low = !*ff;
        *ff = !*ff;
        if self.emu.playing && is_active {
            if low {
                let channels = if self.emu.stereo { 2u64 } else { 1 };
                let total = (self.emu.buf_frames as u64 * channels).max(1); // transfers
                let consumed = (self.emu.cursor * channels) % total;
                let count = total.wrapping_sub(1).wrapping_sub(consumed) as u16;
                let addr = self.dma.ch[chan].prog.addr.wrapping_add(consumed as u16);
                self.dma.read_latch = if is_cnt { count } else { addr };
            }
            let v = self.dma.read_latch;
            return if low { v as u8 } else { (v >> 8) as u8 };
        }
        let p = self.dma.ch[chan].prog;
        let v = if is_cnt { p.count } else { p.addr };
        if low { v as u8 } else { (v >> 8) as u8 }
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
fn mask_real_8237<A: crate::Arch>(machine: &mut A, chan: u8) {
    if (4..8).contains(&chan) { machine.outb(0xD4, 0x04 | (chan - 4)); }
    else if chan < 4 { machine.outb(0x0A, 0x04 | chan); }
}

/// Look up `KEY` in a DOS environment block, returning its value bytes.
fn env_var<'a>(env: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < env.len() && env[i] != 0 {
        let end = env[i..].iter().position(|&b| b == 0).map(|p| i + p)?;
        let entry = &env[i..end];
        if let Some(eq) = entry.iter().position(|&b| b == b'=')
            && entry[..eq].eq_ignore_ascii_case(key) {
                return Some(&entry[eq + 1..]);
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
fn real_8237_count<A: crate::Arch>(machine: &mut A, host: u8) -> u16 {
    let (clr_ff, cnt) = if host < 4 {
        (0x0Cu16, (host as u16) * 2 + 1)
    } else {
        (0xD8u16, 0xC0 + ((host - 4) as u16) * 4 + 2)
    };
    machine.outb(clr_ff, 0);
    let lo = machine.inb(cnt) as u16;
    let hi = machine.inb(cnt) as u16;
    (hi << 8) | lo
}

/// Program the physical 8237 for `chan` with the translated `phys`
/// address / `len` bytes / `mode`. 8-bit channels (0-3) are byte-
/// addressed; 16-bit channels (5-7) are word-addressed (addr/count in
/// words, page bit16 implied). Standard sequence: mask, clear flip-flop,
/// mode, addr lo/hi, page, count lo/hi, unmask.
fn program_real_8237<A: crate::Arch>(machine: &mut A, chan: u8, phys: u32, len: u32, mode: u8, is16: bool) {
    // Standard PC/AT page-register ports indexed by absolute channel.
    const PAGE: [u8; 8] = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];
    if is16 {
        let m = (chan - 4) as u16;            // local 0..3 on controller #2
        let addr = (phys >> 1) & 0xFFFF;       // word address
        let cnt = (len / 2) - 1;               // word count − 1
        machine.outb(0xD4, 0x04 | (chan - 4));         // mask channel
        machine.outb(0xD8, 0);                         // clear byte-pointer flip-flop
        machine.outb(0xD6, mode);
        machine.outb(0xC0 + (m * 4), addr as u8);
        machine.outb(0xC0 + (m * 4), (addr >> 8) as u8);
        machine.outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        machine.outb(0xC0 + (m * 4 + 2), cnt as u8);
        machine.outb(0xC0 + (m * 4 + 2), (cnt >> 8) as u8);
        machine.outb(0xD4, chan - 4);                  // unmask channel
    } else {
        let cnt = len - 1;                     // byte count − 1
        machine.outb(0x0A, 0x04 | chan);               // mask channel
        machine.outb(0x0C, 0);                         // clear byte-pointer flip-flop
        machine.outb(0x0B, mode);
        machine.outb((chan as u16) * 2, phys as u8);
        machine.outb((chan as u16) * 2, (phys >> 8) as u8);
        machine.outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        machine.outb((chan as u16) * 2 + 1, cnt as u8);
        machine.outb((chan as u16) * 2 + 1, (cnt >> 8) as u8);
        machine.outb(0x0A, chan);                      // unmask channel
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
