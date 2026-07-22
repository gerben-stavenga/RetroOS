//! The machine's Sound Blaster: everything a card needs that is *not* the chip.
//!
//! The emulated chip itself is [`sound::sb::Sb`] — a passive state machine in
//! `//lib:sound` (DSP + CT1745 mixer + the OPL on the same card) that owns no
//! sample memory and reaches nothing. This file is the machine around it, and
//! it has a second job the GUS never had: the SB runs in one of two modes,
//! the boot-time `platform::Audio` verdict.
//!
//!  - **Passthrough** — a real card answers (QEMU `sb16`/`adlib` on metal): DSP
//!    traffic forwards to it, and the guest's DMA buffer is remapped contiguous
//!    onto the real 8237 (`maybe_remap` → `arm`). No library card exists; this
//!    is the kernel driving real hardware and cannot be anything else.
//!  - **Emulated** — no card answers (the hosted interpreter, or metal with no
//!    SB16): the library card runs the DSP command FSM and the play cursor,
//!    and this file supplies it with everything spatial and temporal — the
//!    clock, the vPIC line, the guest's DMA ring, the sink's pipe depth.
//!
//! The ring is the interesting one. The GUS files samples into its own DRAM
//! and mixes from memory it owns; the SB DSP streams the guest's DMA ring
//! straight to its DAC and owns nothing. So at mix time the card names the
//! window it needs ([`sound::sb::Sb::dsp_fetch`]) and *we* move those bytes —
//! the guest's address space is ours to reach, never the card's.

use crate::Regs;
use super::*;

/// PTE cache-disable bit (x86 PCD). On RetroOS it doubles as the
/// "externally owned" mark — COW-fork and address-space teardown both
/// skip such frames — exactly what an aliased permanent DMA buffer needs.
/// Arch's `paging2::flags` is private, so the bit is duplicated here per
/// the arch-boundary rule (small primitives are copied, not cross-called).
const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Level-matched to FM so a game's SFX balance does not depend on which music
/// device it picked. The GF1 has no guest-visible master volume (its per-voice
/// ramps carry it) and 86Box's `gus_get_buffer` adds `gus->buffer[]` straight
/// in, so this used to be unity — but the GF1 sums 32 voices where OPL has 9,
/// and measured on the same track (DOOM E1M8, 2 min of steady music) GUS came
/// out **3.74x / +11.5 dB above OPL** (rms 2719 vs 727). Digital SFX are scaled
/// for the FM balance, so under GUS music they were simply buried.
///
/// 65536/3.74: brings GUS music to the FM music level, leaving the DAC-vs-music
/// balance the same whichever music device the game selects. Re-measure with the
/// same method if either source's level changes.
///
/// This is *cross-card* balance, which is why it lives up here in the machine
/// and not in either card: how loud a GUS sits against a Sound Blaster is a
/// property of the mix, not of either chip. (The FM-vs-DAC balance *within*
/// the SB is the card's own, and moved into `//lib:sound` with it.)
pub(super) const GUS_SCALE_Q16: i32 = 17_500;

/// The General MIDI synth, level-matched the same way and for the same reason.
///
/// Measured exactly as `GUS_SCALE_Q16` was: DOOM E1M1, `sfx_volume 0` so the
/// capture is music alone, 40 s of steady playing from t=3 s, once with
/// `snd_musicdevice 5` (GUS) and once with `6` (MPU/General MIDI). GM came out
/// **2.27x above the GUS** (rms 1720 vs 757) — it plays the same `.PAT` bank,
/// but a GM sequence drives far more simultaneous voices than DMX's GUS player
/// does, and every voice here starts at the note's full velocity.
///
/// 17500/2.27: brings GM music onto the GUS's level, which is itself matched
/// to FM — so digital SFX keep one balance against music whichever of the
/// three devices a game selects. Re-measure with the same method if any
/// source's level changes.
///
/// Measure this *after* any change to sample addressing. The first attempt at
/// this constant was taken while the synth still ran the GF1's DRAM transform
/// over its flat pool: instruments aliased onto each other, which is both
/// audibly wrong and 2.7x louder, and calibrating against it baked the bug
/// into the level.
pub(super) const GM_SCALE_Q16: i32 = 7_700;

/// The PC speaker, level-matched to the same reference as the other two, but
/// *derived* rather than measured — and it can be, because a square wave's
/// level is known exactly rather than depending on what a game plays.
///
/// A square's rms equals its amplitude (crest factor 1), so a full-scale
/// square would sit at rms 32767 — 33 dB above the FM music that
/// `GUS_SCALE_Q16` above measured at rms 727, i.e. it would arrive as a
/// full-scale rail. Scaling so the amplitude *is* 727 puts a speaker tone at
/// the same rms as the other devices' music, which is the same balance rule
/// the GUS and GM constants follow: `727/32767 * 65536`.
///
/// Nothing plays over it in practice — a game that picks the speaker has no
/// other device — so this is about not startling anyone when a beep lands
/// during Sound Blaster audio, and about the constant being a decision with a
/// derivation rather than a knob someone turned until it sounded right.
pub(super) const SPEAKER_SCALE_Q16: i32 = 1_454;

/// One knob for overall loudness, applied to the summed mix just before the
/// single clip. Unity: the headroom already lives in the per-source scales
/// above (that is exactly what the CT1745 table ceiling buys), so rescaling
/// here would only trade it away. This is the place to change if the whole
/// machine should be louder or quieter.
pub(super) const OUTPUT_GAIN_Q16: i32 = 65_536;

/// Per-thread Sound Blaster card state: the BLASTER-declared channel/IRQ map,
/// and either the passthrough remap binding or the emulated library card
/// depending on `mode`. The generic virtual 8237 it observes is bus
/// infrastructure shared with every DMA-using card, so it lives on
/// `PcMachine` and is passed in per call.
pub struct SoundBlaster {
    /// The emulated card (used only when emulating).
    core: sound::sb::Sb,
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
            core: sound::sb::Sb::new(),
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
            // card so the next program sees a clean, idle one. Parking the
            // sink is ours — it is shared with every other source.
            self.core.reset_for_exit();
            crate::kernel::sound::stop(machine, true); // session end: power down
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
    /// `sb16`/`adlib`); emulated, to the library card. Only the 8237 is
    /// virtual in passthrough.
    pub fn is_passthrough(&self, p: u16) -> bool {
        (p >= self.io_base && p < self.io_base + 0x10) || matches!(p, 0x388..=0x38B)
    }

    /// Read an SB DSP/mixer/OPL passthrough port, with a tiny compatibility
    /// shim for DSP command E4h/E8h (test register write/read). Some older
    /// games poll base+0Eh forever waiting for E8h to produce a byte; QEMU
    /// sb16 does not appear to surface that response through passthrough.
    pub fn sb_read<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16) -> u8 {
        if self.emulated() {
            return self.core.port_read(p);
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
            // bits the card latched (bits 0-3, one per channel); reading
            // clears them — real-8237 semantics completion pollers rely on.
            // Passthrough continues to the shadow/real chip.
            if self.emulated() && (port == 0x08 || port == 0xD0) {
                return self.core.take_tc_status(port == 0xD0);
            }
            return dma.io_read(machine, port);
        };

        // Emulated card: the live current-count comes from the card's play
        // cursor (there is no real 8257 to interrogate).
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
            // `prog` is already captured (io_write), and we read the guest
            // ring for the card at playback. Nothing to remap.
            return;
        }
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = self.dma8 as usize;
        let c16 = self.dma16 as usize;
        // Armed = unmasked. NOT `count != 0`: the 8237 count register holds
        // transfers MINUS ONE, so 0 is a legal one-transfer block — exactly
        // what a driver's minimal DMA-wiring probe arms (MONKEY2's
        // SOUNBLAS.IMS). Treating it as idle left the real chip unprogrammed,
        // so the probe's completion IRQ never came and the driver gave up
        // with "Unable to initialize SoundDriver". "Has the guest armed this
        // *since we last acted*" is `count_gen` below, not the count value.
        let armed8 = c8 < 4 && !dma.ch[c8].masked;
        let armed16 = (5..8).contains(&c16) && !dma.ch[c16].masked;
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
        // The card decodes against the base and reports the IRQ/DMA numbers
        // back through its mixer configuration registers.
        self.core.set_wiring(self.io_base, self.irq, self.dma8, self.dma16);
    }

    // ── The emulated card's machine side ────────────────────────────────
    //
    // Active only when no real card answers. The library card runs the DSP
    // register file and command FSM; everything below supplies it with what a
    // passive card cannot have — the clock, the interrupt line, the guest's
    // DMA ring, and the sink's pipe depth.

    /// Software emulation vs real-card passthrough — the boot-time platform
    /// probe's verdict (`platform::Audio`), not probed here. The OPL window
    /// for passthrough is part of the DOS io_policy template for the same
    /// reason: derived, not granted at runtime.
    fn emulated(&self) -> bool {
        !crate::kernel::platform::get().audio.sb_passthrough()
    }

    /// Emulated DSP/mixer/FM port write. The card decodes; when it decodes a
    /// start-playback command it hands it back, because only we can read the
    /// guest's DMA controller for the ring that command refers to.
    fn emu_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        let now = machine.get_ticks();
        let Some(start) = self.core.port_write(p, val, now) else { return };
        let is16 = start.bits == 16;
        let chan = if is16 { self.dma16 } else { self.dma8 } as usize;
        if chan >= dma.ch.len() {
            return; // BLASTER declared a channel that does not exist
        }
        let prog = dma.ch[chan].prog;
        let (gpa, len) = chan_gpa_len(&prog, is16);
        // How deep the sink's pipe runs is our policy, not the card's.
        let min_fill = crate::kernel::sound::min_fill(self.core.rate()).unwrap_or(0);
        self.core.begin(start, gpa, len, min_fill);
        if super::PORT_TRACE {
            crate::dbg_println!(
                "[dsp] start bits={} single={} gpa={:08X} len={} chan={}",
                start.bits, start.single, gpa, len, chan
            );
        }
    }

    /// Deliver a latched 0xF2/0xF3 trigger-IRQ (the BLASTER IRQ probe). A
    /// real card answers within microseconds; the next slice is well inside
    /// any probe's poll window.
    pub fn deliver_trigger_irq(&mut self, vpic: &mut super::vpic::VirtualPic) {
        if !self.emulated() {
            return;
        }
        if self.core.take_trigger() && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Complete a single-cycle transfer too short for the pump clock to see
    /// (see the card's `take_probe`), on the slice alongside 0xF2's latched
    /// trigger IRQ.
    pub fn deliver_probe_irq<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        vpic: &mut super::vpic::VirtualPic,
    ) {
        if !self.emulated() {
            return;
        }
        if self.core.take_probe(machine.get_ticks()) && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Whether the emulated DSP owns the canonical sink right now: playing,
    /// or holding the stream open through the hangover. The top of the
    /// producer priority chain (DSP > GUS > OPL).
    pub fn dsp_owns_sink(&self) -> bool {
        self.emulated() && self.core.owns_sink()
    }

    /// Rate the DSP stream runs the mixer session at.
    pub fn dsp_rate(&self) -> u32 {
        self.core.rate()
    }

    /// A DSP playback (re)started since the last call: the mixer pump must
    /// re-key its session so pump frames and DSP stream frames coincide.
    pub fn take_restart(&mut self) -> bool {
        self.core.take_restart()
    }

    /// Whether the FM synth wants the canonical stream held open (voices
    /// sounding, or the driver wrote between-notes recently).
    pub fn opl_audible(&self, now: u64) -> bool {
        self.core.fm_audible(now)
    }

    /// Mix every producer on this card into the same final PCM block.
    ///
    /// The DSP half needs a DMA cycle first: the card names the ring window
    /// it wants and we move those bytes out of guest memory for it. Fetch in
    /// ring-sized runs — `copy_from` may cross a VM/backend boundary, and
    /// doing it once per DSP sample cost thousands of crossings a second and
    /// starved the shared GUS/SB sink under Doom.
    pub(super) fn mix_into<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        rate: u32,
        base: u64,
        block: &mut [(i32, i32)],
    ) {
        if let Some(f) = self.core.dsp_fetch(rate, base, block.len()) {
            let fb = f.frame_bytes as usize;
            let mut scratch = alloc::vec![0u8; f.source_frames * fb];
            let mut copied = 0usize;
            while copied < f.source_frames {
                let abs = f.first + copied as u64;
                let pos = (abs % f.buf_frames as u64) as usize;
                let run = (f.source_frames - copied).min(f.buf_frames as usize - pos);
                let addr = f.gpa as usize + pos * fb;
                let lo = copied * fb;
                machine.copy_from(addr, &mut scratch[lo..lo + run * fb]);
                copied += run;
            }
            self.core.mix_dsp(rate, base, &scratch, &f, block);
        }
        self.core.mix_fm(rate, block);
    }

    /// Drive the emulated DSP's guest-visible clock from the mixer's drain
    /// point and put its interrupt line up when it asks. `drained`/`pushed`
    /// are already converted into the DSP's own frames by the pump.
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
        if self.core.advance_clock(now, drained, pushed) && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Emulated DMA current-address/count read: serve the active SB channel's
    /// live state from the card's play cursor (auto-init down-count), other
    /// channels from the captured base programming. The flip-flop and the
    /// programmed base are the controller's — ours; the cursor is the card's.
    /// Mirrors `dma_read`'s flip-flop split.
    fn emu_dma_read(&mut self, dma: &mut Dma8237, is_cnt: bool, chan: usize, hi_ctrl: bool) -> u8 {
        let is_active = chan == self.dma8 as usize || chan == self.dma16 as usize;
        // The guest reading the active channel's count = it serviced the block
        // (it computed where to refill). Extend the card's commit horizon.
        if is_cnt && is_active {
            self.core.mark_block_serviced();
        }
        let ff = if hi_ctrl { &mut dma.ff_hi } else { &mut dma.ff_lo };
        let low = !*ff;
        *ff = !*ff;
        if self.core.playing() && is_active {
            if low {
                let (count, consumed) = self.core.dma_cursor();
                dma.read_latch = if is_cnt {
                    count
                } else {
                    dma.ch[chan].prog.addr.wrapping_add(consumed)
                };
            }
            let v = dma.read_latch;
            return if low { v as u8 } else { (v >> 8) as u8 };
        }
        let p = dma.ch[chan].prog;
        // Post-terminal-count state: a finished single-cycle transfer reads
        // count 0xFFFF (underflow) and the address one past the end, until the
        // channel is restarted — not the base programming.
        let v = if is_active && self.core.at_terminal_count() {
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
