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
//!    API (`audio_tick`), with no real-card interaction at all. The cursor is
//!    slaved to the sink's real playback position where one exists (the pipe
//!    model — see [`SoundBlaster::dsp_tick`]), so guest-visible timing derives
//!    from what the codec actually plays, exactly as a real card's DMA cursor
//!    is its playback position. FM music goes through a real OPL2/OPL3 synth
//!    ([`opl`](super::opl)) on the same tick.

use crate::Regs;
use super::*;

/// How long the software DSP keeps the canonical stream open after playback
/// stops, feeding silence (see [`EmuDsp::stream_hold`]). Long enough to bridge
/// per-animation-frame sound-effect re-triggers (~150 ms), short enough that
/// FM music isn't held at the DSP rate for long once effects go quiet.
const DSP_HANGOVER_MS: u64 = 300;

/// PTE cache-disable bit (x86 PCD). On RetroOS it doubles as the
/// "externally owned" mark — COW-fork and address-space teardown both
/// skip such frames — exactly what an aliased permanent DMA buffer needs.
/// Arch's `paging2::flags` is private, so the bit is duplicated here per
/// the arch-boundary rule (small primitives are copied, not cross-called).
const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Software DSP/DMA playback engine — populated and driven only in
/// software-emulated mode. Turns the guest's DSP command stream + virtual-8237
/// buffer programming into canonical PCM (`sound::play`), paced by the sink's
/// real playback position (virtual time where the sink has no clock), raising
/// the SB IRQ once per completed DMA block exactly like the real card's
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
    /// SB16 mixer register index (port base+4 write); its data port is base+5.
    mixer_index: u8,
    /// Mixer reg 0x82 IRQ status: bit0 = 8-bit DMA IRQ pending, bit1 = 16-bit.
    /// Set when the SB IRQ is raised (by playback width); cleared when the guest
    /// acks (reads base+0xE for 8-bit / base+0xF for 16-bit). A 16-bit driver
    /// reads this to confirm "that was a *16-bit* DMA interrupt".
    irq_status: u8,
    /// DSP 0xF2/0xF3 (trigger 8-/16-bit IRQ) latched, same bit layout as
    /// `irq_status`; the next `audio_tick` raises it. The BLASTER IRQ probe:
    /// drivers hook every candidate line, send 0xF2, and keep whichever
    /// handler fired — no IRQ means "broken card" (PoP 1.0 then drops sound
    /// entirely, AdLib included).
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

    /// Ring geometry, snapshotted from the virtual 8237 at `start playback`.
    buf_gpa: u32,      // DOS-physical base of the auto-init ring
    buf_frames: u32,   // ring length in frames
    block_frames: u32, // frames between SB IRQs (one DMA block)
    /// Guest-visible frames played since playback start (monotonic).
    /// `dma_read` derives the down-count from this, and block IRQs fire as
    /// it crosses block boundaries. Slaved to the sink's real playback
    /// position when one exists (`use_pos`) — a real SB's DMA cursor IS its
    /// playback position — leading it by [`slack`](Self::slack) so the
    /// guest's per-block refill lands before the codec reaches the data.
    cursor: u64,
    next_irq: u64,    // cursor value of the next block boundary (IRQ point)
    /// How far the guest clock leads the mixer's drain point (source
    /// frames): only what the guest ring is too small to cover — see
    /// `emu_start`. Latency vs. a real card ≈ the sink's minimum fill.
    slack: u32,
    /// This DSP playback (re)started: tell the mixer pump to re-key its
    /// session so pump frame numbering restarts at our frame 0.
    restarted: bool,
    /// Tiny single-cycle transfer (same 0x100-byte threshold as the
    /// passthrough probe path): a DMA-wiring probe wanting its completion
    /// IRQ within milliseconds — completed on virtual time, not drain.
    probe: bool,
    /// `get_ticks()` at the first clock tick of a probe transfer.
    start_ms: u64,
    /// Block IRQs raised / serviced (guest read the DMA count or status
    /// port — poll-bool/poll-dma/irq-mix all do). Their gap is the commit
    /// horizon: a serviced block means the guest has refilled its slot, so
    /// the ring is committed one full lap past it. The synthetic clock
    /// freezes while `acked < done` (the classic boundary gate).
    blocks_done: u64,
    blocks_acked: u64,
    /// Read counter behind the write-status busy flicker (see the base+0x0C
    /// read): bit 3 alternates the busy bit every 8 reads mid-transfer.
    write_busy: u8,
    /// The DSP owns the canonical sink beyond `playing`: after a single-cycle
    /// sample completes (or the guest pauses), the stream is held open for
    /// [`DSP_HANGOVER_MS`] feeding silence (FM still mixed in) instead of
    /// being torn down. Sound-effect chains re-trigger every ~150 ms (PoP's
    /// gate grinding); stopping the sink per sample meant a stream
    /// park/re-prime — and a 11 kHz ↔ 49716 Hz rate flip against the FM
    /// free-run — around every effect, which stuttered on real codecs.
    stream_hold: bool,
    /// `get_ticks()` when playback last stopped (hangover anchor).
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
}

impl EmuDsp {
    const fn new() -> Self {
        EmuDsp {
            out: [0; 4], out_len: 0,
            cmd: None, params: [0; 3], param_got: 0, param_need: 0,
            reset_prev: 0, test_reg: 0,
            mixer_index: 0, irq_status: 0, trigger_irq: 0,
            playing: false, rate: 22050, bits: 8, stereo: false, block_param: 0,
            single: false,
            buf_gpa: 0, buf_frames: 0, block_frames: 0,
            cursor: 0, next_irq: 0,
            slack: 0, restarted: false, probe: false, start_ms: 0,
            blocks_done: 0, blocks_acked: 0,
            write_busy: 0, dma_tc: false, tc_status: 0,
            stream_hold: false, done_ms: 0,
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
/// and either the passthrough remap binding or the software DSP/DMA engine
/// depending on `mode`. The generic virtual 8237 it observes is bus
/// infrastructure shared with every DMA-using card, so it lives on
/// `PcMachine` and is passed in per call.
pub struct SoundBlaster {
    /// The software DSP/DMA engine (used only when emulating).
    emu: EmuDsp,
    /// FM synthesis (OPL2/OPL3), software-emulated mode only. Lazily created
    /// on the first FM register write — the chip is ~20 KB per thread and
    /// most programs never touch FM.
    opl: Option<opl::OplFm>,
    pub io_base: u16, // BLASTER A — DSP/mixer port base (passthrough target)
    pub irq: u8,      // BLASTER I — guest vPIC IRQ to inject on SB completion
    pub dma8: u8,     // BLASTER D — guest's 8-bit vDMA channel (0..3)
    pub dma16: u8,    // BLASTER H — guest's 16-bit vDMA channel (5..7)
    /// Real DMA channels QEMU's SB16 is wired to (`-device sb16,dma=`/
    /// `dma16=`; defaults 1/5). Independent of the guest's BLASTER —
    /// a guest channel-D transfer must drive *these* on the real 8237.
    pub host_dma8: u8,
    pub host_dma16: u8,
    dsp_test_reg: u8,
    dsp_read_data: Option<u8>,
    dsp_expect_test_write: bool,
    /// Parameter bytes still expected for the in-progress passthrough DSP
    /// command. While non-zero, a write to the command port is a parameter
    /// (length, time constant, …), not a new opcode — so it's never decoded
    /// as one (a length byte can equal any command code). Backs the busy-bit
    /// synthesis.
    dsp_param_bytes: u8,
    /// A *single-cycle* DSP DMA transfer is in flight on the passthrough card
    /// (a `0x14`/`0x16`/ADPCM start command was issued, or a `0xD4` continue).
    /// Set positively by those commands and cleared by `0xD0` (pause), DSP
    /// reset, exec/exit, or an 8237 (re)arm — so a stale/paused/reset transfer
    /// never reads busy. Backs the synthesized write-status busy flicker (see
    /// `sb_read`); a completed block also drops it via the live 8237 count.
    dsp_dma_active: bool,
    /// Read counter behind the passthrough write-status busy flicker: bit 3
    /// alternates the busy bit every 8 reads mid-transfer.
    dsp_write_busy: u8,
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
            opl: None,
            io_base: 0x220, irq: 7, dma8: 1, dma16: 5,
            host_dma8: 1, host_dma16: 5, // QEMU `-device sb16` defaults
            dsp_test_reg: 0, dsp_read_data: None, dsp_expect_test_write: false,
            dsp_param_bytes: 0, dsp_dma_active: false, dsp_write_busy: 0,
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
    pub fn dma_ch_armed(&self, dma: &Dma8237, ch: usize) -> bool {
        ch < 8 && dma.ch[ch].armed
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
    pub fn release_dma_pool<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs) {
        if self.emulated() {
            // No real card / no buffer alias in emulation: just stop the
            // software DSP so the next program sees a clean, idle card.
            self.emu.playing = false;
            self.emu.stream_hold = false;
            crate::kernel::sound::stop(machine, true); // session end: power down
            self.emu.out_len = 0;
            self.emu.cmd = None;
            self.opl = None; // next program gets a power-on-fresh FM chip
            return;
        }
        self.unbind(machine);
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
        self.dsp_param_bytes = 0;
        self.dsp_dma_active = false;
        self.dsp_expect_test_write = false;
    }

    /// SB ports this card decodes — the dispatch guard for both modes: the
    /// DSP/mixer block `[io_base, io_base+0x10)` and the OPL2/3 FM window
    /// 0x388-0x38B. In passthrough these go straight to the real card (QEMU
    /// `sb16`/`adlib`); emulated, to the software DSP / FM synth. Only the
    /// 8237 is virtual in passthrough.
    pub fn is_passthrough(&self, p: u16) -> bool {
        (p >= self.io_base && p < self.io_base + 0x10) || matches!(p, 0x388..=0x38B)
    }

    /// Read an SB DSP/mixer/OPL passthrough port, with a tiny compatibility
    /// shim for DSP command E4h/E8h (test register write/read). Some older
    /// games poll base+0Eh forever waiting for E8h to produce a byte; QEMU
    /// sb16 does not appear to surface that response through passthrough.
    pub fn sb_read<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16) -> u8 {
        if self.emulated() {
            return self.emu_read(p);
        }
        if p == self.io_base + 0x0A {
            if let Some(v) = self.dsp_read_data.take() {
                return v;
            }
        } else if p == self.io_base + 0x0E && self.dsp_read_data.is_some() {
            return 0x80;
        } else if p == self.io_base + 0x0C {
            // DSP write-buffer status. Bit 7 = 1 means the DSP can't yet
            // accept a command byte. QEMU's sb16 always reports ready (0),
            // but on the real chip the bit FLICKERS while a *single-cycle*
            // DMA transfer is in flight — it's a per-byte buffer status,
            // pulsing as the DSP services DMA between command bytes (which
            // is why 0xD0/pause can be sent mid-transfer at all). Synthesize
            // that flicker (alternate every 8 reads, DOSBox's proven model)
            // so a driver polling for busy, or for the busy→idle edge, sees
            // it within a few reads.
            //
            // Reproducer: Prince of Persia's per-frame "stop digitized sound"
            // routine (PRINCE.EXE file off 0x19E6F: wait-until-busy,
            // wait-until-idle, then DSP 0xD0/pause). On QEMU's always-ready
            // status the first wait spun forever — the end-door sound
            // repeated and the game hung. Holding busy for the whole block
            // (this shim's first iteration) stalled that routine a full
            // sample per game frame instead — 1 fps and staccato audio.
            //
            // Auto-init transfers (8237 mode bit 4 set) are left alone: real
            // hardware keeps accepting commands between auto-init blocks, and
            // our auto-init clients (Quake, Dune2, ROTT) must not stall here.
            let v = machine.inb(p);
            if self.dsp_single_cycle_busy(machine, dma) {
                self.dsp_write_busy = self.dsp_write_busy.wrapping_add(1);
                if self.dsp_write_busy & 8 != 0 {
                    return v | 0x80;
                }
            }
            return v;
        }
        machine.inb(p)
    }

    /// True while a single-cycle DSP DMA transfer is genuinely mid-block: a
    /// start/continue command is active *and* the real 8237's live current-
    /// count hasn't yet underflowed to the terminal 0xFFFF. Gates the DSP
    /// write-status busy flicker in `sb_read`. The `dsp_dma_active` flag is
    /// checked first, so an idle/paused/completed channel costs no port I/O.
    /// 16-bit single-cycle isn't modelled (no client polls for it); the
    /// 8-bit/ADPCM host channel is the only one a `0x14`-class command drives.
    /// The 8237 single-cycle mode check (bit 4 clear) keeps auto-init clients
    /// (Quake, Dune2, ROTT) unconditionally exempt — their busy bit stays 0
    /// even across a pause/continue — so their command polls never throttle.
    fn dsp_single_cycle_busy<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237) -> bool {
        self.dsp_dma_active
            && dma.ch[self.dma8 as usize].prog.mode & 0x10 == 0
            && real_8237_count(machine, self.host_dma8) != 0xFFFF
    }

    /// Write an SB DSP/mixer/OPL passthrough port. DSP E4h/E8h are handled
    /// locally; all other traffic continues to the real QEMU sb16/adlib.
    ///
    /// On the DSP command port we also run a minimal opcode/parameter tracker
    /// — enough to keep the synthesized write-status busy bit (see `sb_read`)
    /// honest across the start/pause/resume of a single-cycle transfer. It
    /// never suppresses a write: every byte still reaches QEMU. A DSP reset
    /// (write to base+0x06) clears the tracker.
    pub fn sb_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        if self.emulated() {
            self.emu_write(machine, dma, p, val);
            return;
        }
        if p == self.io_base + 0x06 {
            // DSP reset — drop any half-decoded command / transfer state.
            self.dsp_param_bytes = 0;
            self.dsp_dma_active = false;
            self.dsp_expect_test_write = false;
        } else if p == self.io_base + 0x0C {
            if self.dsp_expect_test_write {
                self.dsp_test_reg = val;
                self.dsp_expect_test_write = false;
                return;
            }
            // A parameter byte of the command in progress — forward it
            // verbatim and never re-decode it as an opcode (a length/time-
            // constant byte can equal any command code).
            if self.dsp_param_bytes > 0 {
                self.dsp_param_bytes -= 1;
            } else {
                // Command opcode. Track parameter length and the single-cycle
                // transfer-active flag; only commands relevant to busy-bit
                // accuracy and the local E4/E8 shim are special-cased — the
                // rest forward with no parameter expectation (a wrong guess
                // could only mis-set the single-cycle busy bit, which auto-
                // init clients never consult).
                match val {
                    0xE4 => { self.dsp_expect_test_write = true; return; }
                    0xE8 => { self.dsp_read_data = Some(self.dsp_test_reg); return; }
                    // Single-cycle DMA output start (8-bit / ADPCM): two
                    // length bytes follow, and the DSP is now mid-transfer.
                    0x14 | 0x16 | 0x74..=0x77 => {
                        self.dsp_param_bytes = 2;
                        self.dsp_dma_active = true;
                    }
                    0xD4 => self.dsp_dma_active = true,  // continue 8-bit DMA
                    0xD0 => self.dsp_dma_active = false, // pause 8-bit DMA
                    0x10 | 0x40 | 0xE0 | 0xE2 => self.dsp_param_bytes = 1,
                    0x48 | 0x80 => self.dsp_param_bytes = 2,
                    _ => {}
                }
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
    pub fn dma_read<A: crate::Arch>(&mut self, machine: &mut A, dma: &mut Dma8237, port: u16) -> u8 {
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
            // Emulated card: the controller status register carries the TC
            // bits the software DSP latched (bits 0-3, one per channel);
            // reading clears them — real-8237 semantics completion pollers
            // rely on. Passthrough continues to the shadow/real chip.
            if self.emulated() && (port == 0x08 || port == 0xD0) {
                let base = if port == 0xD0 { 4 } else { 0 };
                let bits = (self.emu.tc_status >> base) & 0x0F;
                self.emu.tc_status &= !(0x0F << base);
                return bits;
            }
            return dma.io_read(machine, port);
        };

        // Emulated card: the live current-count comes from the software DSP's
        // play cursor (there is no real 8257 to interrogate).
        if self.emulated() {
            return self.emu_dma_read(dma, is_cnt, chan, hi_ctrl);
        }

        let host = if chan == self.dma8 as usize { Some(self.host_dma8) }
                   else if chan == self.dma16 as usize { Some(self.host_dma16) }
                   else { None };
        if dma.ch[chan].armed
            && let Some(h) = host {
                // Serve the *live* transfer state for the armed SB channel,
                // lo/hi via the controller byte-pointer flip-flop; snapshot
                // the full u16 at the low-byte read so the pair is coherent.
                let ff = if hi_ctrl { &mut dma.ff_hi }
                         else { &mut dma.ff_lo };
                let low = !*ff;
                *ff = !*ff;
                if low {
                    let live_count = real_8237_count(machine, h);
                    let p = dma.ch[chan].prog;
                    dma.read_latch = if is_cnt {
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
                let v = dma.read_latch;
                return if low { v as u8 } else { (v >> 8) as u8 };
            }
        dma.io_read(machine, port)
    }

    /// Called after every virtual-8237 write. When the BLASTER channel is
    /// (re)armed, alias the guest's DMA buffer onto that channel's
    /// permanent host buffer and program the real 8237. A no-op until the
    /// guest finishes a count write (the per-block re-arm signal).
    pub fn maybe_remap<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237) {
        if self.emulated() {
            // No real chip to program / no buffer to alias: the virtual-8237
            // `prog` is already captured (io_write), and the software DSP reads
            // the guest buffer directly at playback. Nothing to remap.
            return;
        }
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = self.dma8 as usize;
        let c16 = self.dma16 as usize;
        let armed8 = c8 < 4 && !dma.ch[c8].masked
            && dma.ch[c8].prog.count != 0;
        let armed16 = (5..8).contains(&c16) && !dma.ch[c16].masked
            && dma.ch[c16].prog.count != 0;
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
        let cur_gen = dma.count_gen[chan];
        if self.last_gen[chan] == cur_gen { return; }
        self.last_gen[chan] = cur_gen;

        let p = dma.ch[chan].prog;
        let (gpa, len) = chan_gpa_len(&p, is16);
        self.arm(machine, regs, dma, chan, host, is16, gpa, len, p.mode);
    }

    /// Alias the guest buffer at `gpa` onto host DMA channel `host`'s
    /// permanent buffer and program the real 8237. Driven from
    /// `maybe_remap` (a guest port write) and `sb_resume` (replaying the
    /// virtual-8237 state after a task switch).
    #[allow(clippy::too_many_arguments)]
    fn arm<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs, dma: &mut Dma8237,
           chan: usize, host: usize, is16: bool,
           gpa: u32, len: u32, mode: u8) {
        let bufpage = machine.dma_channel_buf(host);
        if bufpage == 0 { return; }              // no reserved buffer
        // (Re)programming the 8237 only stages the next block; the DSP isn't
        // transferring until it gets the matching `0x14`-class start command.
        // Drop the busy flag here so the driver's "wait for DSP ready" poll
        // before that start (PoP re-arms the chip *then* issues 0x14 each
        // block) doesn't see a stale busy from the block just finished.
        self.dsp_dma_active = false;
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
            dma.ch[chan].armed = true;
            return;
        }

        // (Re)bind only when the guest buffer (channel/addr/len) changed.
        // Auto-init and single-cycle re-arms of the same buffer skip
        // straight to re-programming the real chip — true zero-copy: the
        // guest's refills already land in the channel buffer via the alias.
        let bound = self.bound_chan == chan as u8 && self.bound_host == host as u8
            && self.bound_gpa == gpa && self.bound_len == len;
        if !bound {
            if self.bound_gpa != 0 { self.unbind(machine); }
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
            machine.copy_from(vbase, &mut snap);
            // Free the guest's original frames, then alias the range onto
            // the channel buffer with CACHE_DISABLE — externally owned, so
            // COW-fork and address-space teardown both leave it intact.
            machine.unmap_range(vbase >> 12, num_pages);
            machine.map_phys_range(
                vbase >> 12, num_pages, bufpage + win_pgoff, PTE_CACHE_DISABLE);
            machine.copy_to(vbase, &snap);
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
        dma.ch[chan].armed = true;
    }

    /// Detach the current alias: hand the guest's buffer range fresh
    /// anonymous frames and copy the channel buffer's content back into
    /// them, so the partial-end-page neighbour data survives and the guest
    /// can reuse the linear range. The channel buffer is permanent. No-op
    /// when nothing is bound.
    fn unbind<A: crate::Arch>(&mut self, machine: &mut A) {
        if self.bound_gpa == 0 { return; }
        let vbase = self.bound_vpage << 12;
        let span  = self.bound_pages * 0x1000;
        let mut snap = alloc::vec![0u8; span];
        machine.copy_from(vbase, &mut snap);
        machine.map_fresh_range(
            self.bound_vpage, self.bound_pages);
        machine.copy_to(vbase, &snap);
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
    pub fn sb_suspend<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs) {
        if self.emulated() { return; } // no real chip / alias to detach
        if self.bound_gpa == 0 { return; }
        mask_real_8237(machine, self.bound_host);
        self.unbind(machine);
        self.suspended = true;
    }

    /// Task switched back to the foreground: re-materialize the binding —
    /// re-alias every channel the virtual 8237 still shows armed and
    /// reprogram the real 8237. Must run with this task's address space
    /// active.
    pub fn sb_resume<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237) {
        if self.emulated() { return; }
        if !self.suspended { return; }
        self.suspended = false;
        for chan in 0..8 {
            if !dma.ch[chan].armed { continue; }
            let is16 = chan >= 4;
            let host = if is16 { self.host_dma16 } else { self.host_dma8 } as usize;
            let p = dma.ch[chan].prog;
            let (gpa, len) = chan_gpa_len(&p, is16);
            self.arm(machine, regs, dma, chan, host, is16, gpa, len, p.mode);
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
    // canonical PCM (`sound::play`) paced by the sink's playback position
    // (virtual time where the sink has no clock), raising the SB IRQ per
    // block. The virtual 8237 (`self.dma`) already captured the buffer
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
        // OPL status register: a read of any FM window port returns the timer
        // status. Bits 1-2 are always 0 — the "this is an OPL3" answer type
        // probes look for. Before any FM write there is no chip yet: power-on
        // status is 0 anyway.
        if opl::decode_port(self.io_base, p).is_some() {
            return self.opl.as_ref().map_or(0, |o| o.status());
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
                if self.emu.playing && self.emu.single {
                    self.emu.write_busy = self.emu.write_busy.wrapping_add(1);
                    if self.emu.write_busy & 8 != 0 { 0x80 } else { 0x00 }
                } else {
                    0x00
                }
            }
            0x0E => {                                  // read-status / 8-bit IRQ ack
                self.emu.irq_status &= !0x01;          // reading acks the 8-bit IRQ
                self.emu.blocks_acked = self.emu.blocks_done; // block serviced: extend commit
                if self.emu.out_len > 0 { 0x80 } else { 0x00 }
            }
            0x0F => {                                  // 16-bit IRQ ack
                self.emu.irq_status &= !0x02;
                self.emu.blocks_acked = self.emu.blocks_done;
                0x00
            }
            _ => 0xFF,
        }
    }

    /// Emulated DSP/mixer port write.
    fn emu_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        // OPL2/OPL3 FM (AdLib 0x388-0x38B, or the SB mirrors at io_base+0..3
        // and +8/+9): address latch + data writes into the FM synth, created
        // on first touch. Timer semantics live in `opl.rs` (same instant-
        // expiry detection behavior as the old stub).
        if let Some(port) = opl::decode_port(self.io_base, p) {
            let now = machine.get_ticks();
            self.opl
                .get_or_insert_with(|| opl::OplFm::new(now))
                .write(now, port, val);
            return;
        }
        match p.wrapping_sub(self.io_base) {
            0x04 => self.emu.mixer_index = val, // mixer register select
            0x05 => {}                          // mixer data: no mixing modeled
            0x06 => {
                // DSP reset: a 1→0 edge triggers the reset handshake.
                if self.emu.reset_prev == 1 && val == 0 {
                    self.emu.playing = false;
                    self.emu.stream_hold = false;
                    crate::kernel::sound::stop(machine, true); // session end: power down
                    self.emu.cmd = None;
                    self.emu.param_got = 0;
                    self.emu.out_len = 0;
                    self.emu.push_out(0xAA); // reset acknowledge
                }
                self.emu.reset_prev = val;
            }
            0x0C => self.emu_dsp_byte(machine, dma, val), // DSP command / parameter port
            _ => {}                         // unmodeled DSP-block ports: ignored
        }
    }

    /// Feed one byte to the DSP command FSM: a parameter for the in-flight
    /// command, or the start of a new one.
    fn emu_dsp_byte<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, val: u8) {
        if let Some(cmd) = self.emu.cmd {
            self.emu.params[self.emu.param_got as usize] = val;
            self.emu.param_got += 1;
            if self.emu.param_got >= self.emu.param_need {
                self.emu_exec(machine, dma, cmd);
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
            self.emu_exec(machine, dma, val);
        }
    }

    /// Execute a fully-parameterized DSP command.
    fn emu_exec<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, cmd: u8) {
        let p = self.emu.params;
        if super::PORT_TRACE {
            crate::dbg_println!(
                "[dsp] cmd {:02X} p={:02X},{:02X},{:02X} ticks={}",
                cmd, p[0], p[1], p[2], machine.get_ticks()
            );
        }
        match cmd {
            0xE1 => {
                self.emu.push_out(4); // DSP version 4.5 (SB16)
                self.emu.push_out(5);
            }
            // Detection helpers some drivers use to confirm a real DSP:
            0xE0 => self.emu.push_out(!p[0]), // identification: return ~byte
            0xE4 => self.emu.test_reg = p[0], // write test register
            0xE8 => self.emu.push_out(self.emu.test_reg), // read test register back
            0xF2 => self.emu.trigger_irq |= 0x01,      // trigger 8-bit IRQ (IRQ probe)
            0xF3 => self.emu.trigger_irq |= 0x02,      // trigger 16-bit IRQ
            0xD1 | 0xD4 => {}                          // speaker on / continue DMA
            0xD0 | 0xD3 | 0xD9 | 0xDA => {
                // Pause / speaker off / exit auto-init: playback stops, but the
                // stream is held open through the hangover (dsp_tick) — effect
                // chains pause-and-restart every animation frame.
                self.emu.playing = false;
                self.emu.done_ms = machine.get_ticks();
            }
            0x40 => {
                let tc = p[0] as u32;
                self.emu.rate = if tc < 256 { 1_000_000 / (256 - tc) } else { 22050 };
            }
            0x41 => self.emu.rate = ((p[0] as u32) << 8) | p[1] as u32, // output rate (hi, lo)
            0x42 => {}                                                  // input rate: ignore
            0x48 => self.emu.block_param = (p[0] as u16) | ((p[1] as u16) << 8),
            // Legacy 8-bit mono output. 0x1C/0x90 = auto-init (block from 0x48);
            // 0x14/0x91 = single-cycle (play once; length from the 8237).
            0x1C | 0x90 => self.emu_start(dma, 8, false, None, false),
            0x14 | 0x91 => self.emu_start(dma, 8, false, None, true),
            // SB16 8-/16-bit output: mode byte + 16-bit length; bit1 = auto-init,
            // its absence = single-cycle. (0xC8.., 0xB8.. are input/ADC — ignored.)
            0xC0..=0xC7 => {
                let stereo = p[0] & 0x20 != 0;
                let single = cmd & 0x02 == 0;
                self.emu_start(dma, 8, stereo, Some((p[1] as u16) | ((p[2] as u16) << 8)), single);
            }
            0xB0..=0xB7 => {
                let stereo = p[0] & 0x20 != 0;
                let single = cmd & 0x02 == 0;
                self.emu_start(dma, 16, stereo, Some((p[1] as u16) | ((p[2] as u16) << 8)), single);
            }
            _ => {}
        }
    }

    /// Begin auto-init playback: snapshot the ring geometry from the active
    /// BLASTER channel's virtual-8237 programming and arm the play cursor.
    fn emu_start(&mut self, dma: &Dma8237, bits: u8, stereo: bool, block_override: Option<u16>, single: bool) {
        self.emu.bits = bits;
        self.emu.stereo = stereo;
        self.emu.single = single;
        if let Some(b) = block_override {
            self.emu.block_param = b;
        }
        let channels = if stereo { 2u32 } else { 1 };

        let is16 = bits == 16;
        let chan = if is16 { self.dma16 as usize } else { self.dma8 as usize };
        let prog = dma.ch[chan].prog;
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
        self.emu.blocks_done = 0;
        self.emu.blocks_acked = 0;
        self.emu.restarted = true; // mixer pump: re-key session numbering
        // DMA-wiring probes (tiny single-cycle transfers, the same 0x100-byte
        // threshold as the passthrough probe path) complete on virtual time —
        // they need the IRQ within milliseconds and are inaudible either way.
        self.emu.probe = single && len_bytes < 0x100;
        self.emu.start_ms = 0;
        // The guest clock leads the drain only by what the ring is too small
        // to cover: with ring ≥ fill + one block, the refill a block IRQ
        // commits always lands before the mix point reads its slot, and the
        // cursor can track audible playback exactly (slack = 0). Single-cycle
        // never needs a lead — its whole buffer is committed up front.
        let fill = crate::kernel::sound::min_fill(self.emu.rate).unwrap_or(0);
        self.emu.slack = if single {
            0
        } else {
            (fill + self.emu.block_frames).saturating_sub(self.emu.buf_frames)
        };
        self.emu.dma_tc = false; // restart re-loads the count registers
        self.emu.playing = self.emu.buf_frames > 0;
        if self.emu.playing {
            self.emu.stream_hold = true;
        }
        if super::PORT_TRACE {
            crate::dbg_println!(
                "[dsp] start bits={} single={} gpa={:08X} frames={} block={} playing={}",
                bits, single, self.emu.buf_gpa, self.emu.buf_frames,
                self.emu.block_frames, self.emu.playing
            );
        }
    }

    /// Advance emulated sound by the virtual time elapsed since the last call:
    /// the DSP's DMA playback (`dsp_tick`) and the FM synth. Exactly one of
    /// them produces into the canonical sink at a time — while the DSP stream
    /// is live it *pulls* FM frames itself (`emit_frames` mixes them in), so
    /// the FM pump only free-runs when the DSP is silent.
    /// Whether the software DSP owns the canonical sink right now: playing,
    /// or holding the stream open through the hangover. The top of the
    /// producer priority chain (DSP > GUS > OPL).
    pub fn dsp_owns_sink(&self) -> bool {
        self.emulated() && (self.emu.playing || self.emu.stream_hold)
    }

    /// Deliver a latched 0xF2/0xF3 trigger-IRQ (the BLASTER IRQ probe). A
    /// real card answers within microseconds; the next slice is well inside
    /// any probe's poll window.
    pub fn deliver_trigger_irq(&mut self, vpic: &mut super::vpic::VirtualPic) {
        if !self.emulated() || self.emu.trigger_irq == 0 {
            return;
        }
        self.emu.irq_status |= self.emu.trigger_irq;
        self.emu.trigger_irq = 0;
        if !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Rate the DSP stream runs the mixer session at.
    pub fn dsp_rate(&self) -> u32 {
        self.emu.rate
    }

    /// A DSP playback (re)started since the last call: the mixer pump must
    /// re-key its session so pump frames and DSP stream frames coincide.
    pub fn take_restart(&mut self) -> bool {
        core::mem::take(&mut self.emu.restarted)
    }

    /// Whether the FM synth wants the canonical stream held open (voices
    /// sounding, or the driver wrote between-notes recently).
    pub fn opl_audible(&self, now: u64) -> bool {
        self.opl.as_ref().is_some_and(|o| o.audible(now))
    }

    /// Add the FM synth's frames into the pump block (no-op when silent).
    pub fn mix_fm<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, base: u64, out: &mut [(i16, i16)]) {
        if let Some(opl) = self.opl.as_mut()
            && opl.mixing()
        {
            opl.mix(machine, rate, base, out);
        }
    }

    /// Add the DSP stream's guest-ring frames into the pump block. `base` is
    /// the mixer-session frame of `out[0]`, which — because `emu_start`
    /// re-keys the pump session — is also the DSP stream frame. Frames past
    /// the commit horizon (one ring lap beyond the last *serviced* block,
    /// floored at the next boundary: an unserviced ring keeps cycling and
    /// replays, exactly like the real card) stay silent.
    pub fn mix_dsp<A: crate::Arch>(&mut self, machine: &mut A, rate: u32, base: u64, out: &mut [(i16, i16)]) {
        if !self.emu.playing || rate != self.emu.rate {
            return; // idle or hangover: the pump's zeros are our silence
        }
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
        let committed = self.committed_end();
        let mut done = 0usize;
        while done < out.len() {
            let abs = base + done as u64;
            if abs >= committed {
                break; // starved: leave the pump's silence
            }
            let pos = (abs % self.emu.buf_frames as u64) as u32;
            let run = (out.len() - done)
                .min((committed - abs) as usize)
                .min((self.emu.buf_frames - pos) as usize);
            let mut scratch = alloc::vec![0u8; run * frame_bytes as usize];
            let addr = self.emu.buf_gpa as usize + (pos * frame_bytes) as usize;
            machine.copy_from(addr, &mut scratch);
            for (i, slot) in out[done..done + run].iter_mut().enumerate() {
                let (l, r) = fmt.frame(&scratch, i);
                slot.0 = slot.0.saturating_add(l);
                slot.1 = slot.1.saturating_add(r);
            }
            done += run;
        }
    }

    /// Auto-init commit horizon (see `mix_dsp`); single-cycle commits the
    /// whole buffer up front.
    fn committed_end(&self) -> u64 {
        if self.emu.single {
            self.emu.buf_frames as u64
        } else {
            (self.emu.blocks_acked * self.emu.block_frames as u64
                + self.emu.buf_frames as u64)
                .max(self.emu.next_irq)
        }
    }

    /// The DSP's guest-visible clock, driven by the mixer's drain point:
    /// the cursor — the DMA count and the block-boundary IRQs both derive
    /// from it — is `drained + slack`, capped at `pushed` (frames actually
    /// handed to the sink). A real SB's DMA cursor IS its playback position;
    /// deriving it from what the codec has consumed reproduces exactly that.
    /// Also ends the hangover hold, and completes tiny probe transfers on
    /// virtual time (their IRQ can't wait for a stream to start draining).
    pub fn dsp_clock_tick<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        vpic: &mut super::vpic::VirtualPic,
        drained: u64,
        pushed: u64,
    ) {
        if !self.emulated() {
            return;
        }
        let now = machine.get_ticks();
        if !self.emu.playing {
            // Hangover: the pump keeps the stream fed (silence + synths)
            // while `stream_hold` keeps `dsp_owns_sink` true; effect chains
            // re-trigger onto a hot stream instead of a park/re-prime.
            if self.emu.stream_hold
                && now.saturating_sub(self.emu.done_ms) >= DSP_HANGOVER_MS
            {
                self.emu.stream_hold = false;
            }
            return;
        }
        let guest_now = if self.emu.probe {
            // Probe transfers complete after their real duration on the
            // virtual clock — milliseconds, independent of stream priming.
            if self.emu.start_ms == 0 {
                self.emu.start_ms = now;
            }
            let len_ms = self.emu.buf_frames as u64 * 1000 / self.emu.rate.max(1) as u64;
            if now.saturating_sub(self.emu.start_ms) < len_ms {
                return;
            }
            self.emu.next_irq
        } else {
            (drained + self.emu.slack as u64).min(pushed)
        };
        while self.emu.playing && guest_now >= self.emu.next_irq {
            self.emu.cursor = self.emu.next_irq;
            self.emu.blocks_done += 1;
            // Mixer IRQ-status bit by transfer width (16-bit drivers check this).
            self.emu.irq_status |= if self.emu.bits == 16 { 0x02 } else { 0x01 };
            if super::PORT_TRACE {
                crate::dbg_println!(
                    "[dsp] boundary cursor={} single={} drained={} ticks={}",
                    self.emu.cursor, self.emu.single, drained, now
                );
            }
            if !vpic.is_requested(self.irq) {
                vpic.raise(self.irq);
            }
            if self.emu.single {
                self.emu.playing = false; // single-cycle: one pass done, stop (no loop)
                self.emu.done_ms = now;   // stream held open through the hangover
                // The 8237 side hit terminal count: current-count underflows to
                // 0xFFFF and the status TC bit latches until read.
                self.emu.dma_tc = true;
                let chan = if self.emu.bits == 16 { self.dma16 } else { self.dma8 };
                self.emu.tc_status |= 1 << (chan & 7);
            } else {
                self.emu.next_irq += self.emu.block_frames as u64;
            }
        }
        if self.emu.playing {
            self.emu.cursor = guest_now;
        }
    }

    /// Emulated DMA current-address/count read: serve the active SB channel's
    /// live state from the play cursor (auto-init down-count), other channels
    /// from the captured base programming. Mirrors `dma_read`'s flip-flop split.
    fn emu_dma_read(&mut self, dma: &mut Dma8237, is_cnt: bool, chan: usize, hi_ctrl: bool) -> u8 {
        let is_active = chan == self.dma8 as usize || chan == self.dma16 as usize;
        // The guest reading the active channel's count = it serviced the block
        // (computed `current_play_seg` to refill). Extend the commit horizon
        // so the pipe may read the ring one full lap past this block.
        if is_cnt && is_active && self.emu.playing {
            self.emu.blocks_acked = self.emu.blocks_done;
        }
        let ff = if hi_ctrl { &mut dma.ff_hi } else { &mut dma.ff_lo };
        let low = !*ff;
        *ff = !*ff;
        if self.emu.playing && is_active {
            if low {
                let channels = if self.emu.stereo { 2u64 } else { 1 };
                let total = (self.emu.buf_frames as u64 * channels).max(1); // transfers
                let consumed = (self.emu.cursor * channels) % total;
                let count = total.wrapping_sub(1).wrapping_sub(consumed) as u16;
                let addr = dma.ch[chan].prog.addr.wrapping_add(consumed as u16);
                dma.read_latch = if is_cnt { count } else { addr };
            }
            let v = dma.read_latch;
            return if low { v as u8 } else { (v >> 8) as u8 };
        }
        let p = dma.ch[chan].prog;
        // Post-terminal-count state: a finished single-cycle transfer reads
        // count 0xFFFF (underflow) and the address one past the end, until the
        // channel is restarted — not the base programming.
        let v = if is_active && self.emu.dma_tc {
            if is_cnt { 0xFFFF } else { p.addr.wrapping_add(p.count).wrapping_add(1) }
        } else if is_cnt {
            p.count
        } else {
            p.addr
        };
        if low { v as u8 } else { (v >> 8) as u8 }
    }
}

/// Mask host DMA channel `chan` on the real 8237 — stops the card pulling
/// the channel buffer while the owning task is backgrounded.
fn mask_real_8237<A: crate::Arch>(machine: &mut A, chan: u8) {
    if (4..8).contains(&chan) { machine.outb(0xD4, 0x04 | (chan - 4)); }
    else if chan < 4 { machine.outb(0x0A, 0x04 | chan); }
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
