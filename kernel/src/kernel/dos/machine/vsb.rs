//! The machine's Sound Blaster: everything a card needs that is *not* the chip.
//!
//! The emulated chip itself is [`sound::sb::Sb`] — a passive state machine in
//! `//lib:sound` (DSP + CT1745 mixer + the OPL on the same card) that owns no
//! sample memory and reaches nothing. This file is the machine around it, and
//! it has a second job the GUS never had: the card is EITHER real silicon this
//! guest holds OR that software model — never both, never neither. That XOR is
//! [`SbDevice`], settled once in `configure_from_env` from the boot probe's
//! verdict, and every question below is answered by matching it rather than by
//! re-asking the platform. The two payloads carry disjoint state and disjoint
//! methods, so "is there a card?" is never a question a caller can forget to
//! ask: it cannot name the passthrough half without having matched it.
//!
//!  - **Passthrough** — a real card answers (QEMU `sb16`/`adlib` on metal): DSP
//!    traffic forwards to it, and the guest's DMA buffer is aliased onto the
//!    channel buffer the real 8237 transfers from (`maybe_remap` → `arm`;
//!    the guest's pages are re-mapped, not copied, so its own writes land
//!    where the card reads). No library card exists; this is the kernel
//!    driving real hardware and cannot be anything else.
//!
//!    Note what does NOT drive that: the DSP window. `maybe_remap` runs off
//!    the guest's 8237 port writes, and the SB is never told an address, so
//!    passthrough could in principle grant the DSP ports outright. It stays
//!    trapped for three things it buys instead: the write-status busy
//!    flicker real chips pulse and QEMU's sb16 does not (Prince of Persia
//!    spins on it), the E4h/E8h test-register answer, and — since every
//!    access already traps — translating a guest window onto a card
//!    strapped at a different base (`host_port`). DSP traffic is commands,
//!    not sample data, so the exits are rare.
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
///
/// Doubled from the 7,700 GUS-matched value: WAV-measured against DOOM2, GM
/// music sat ~-6 dB under the digital SFX (RMS ~440 vs ~900) — a ratio
/// unchanged across the ROM-bank rework, i.e. long-standing, just unmasked
/// once the start delay and dropouts were fixed. Pending a dosemu
/// balance-comparison pass.
pub(super) const GM_SCALE_Q16: i32 = 15_400;

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

/// One canonical 128-frame block at the SB16 maximum of 16-bit stereo.
const DSP_SCRATCH_BYTES: usize = 128 * 4;

/// What the guest was TOLD its card is: the `BLASTER=` declaration. Every
/// number a DOS program uses comes from here — the ports it pokes, the vPIC
/// line it hooks, the virtual 8237 channels it programs — and none of them
/// need have anything to do with where a physical card actually sits. Shared
/// by both devices below, because it describes the guest, not the silicon.
pub struct Blaster {
    pub io_base: u16, // BLASTER A — DSP/mixer port base the guest decodes
    pub irq: u8,      // BLASTER I — guest vPIC IRQ injected on SB completion
    pub dma8: u8,     // BLASTER D — guest's 8-bit vDMA channel (0..3)
    pub dma16: u8,    // BLASTER H — guest's 16-bit vDMA channel (5..7)
}

/// The unique physical Sound Blaster, as a capability. Neither `Copy` nor
/// `Clone`: holding it IS the authority to drive the card, and it carries the
/// wiring the holder needs to reach it. It lives in exactly one place —
/// this thread's device when the guest drives real silicon, or the mixer's
/// sink when the mixer does.
///
/// Everything here used to be four fields on `SoundBlaster` with `0xFF`/`0`
/// standing in for "no card". Presence of the value is the answer now, so the
/// passthrough paths are total instead of sentinel-guarded.
pub struct NativeSb {
    /// Where the card actually decodes — the passthrough target. The guest's
    /// own base (`Blaster.io_base`) may differ in mixed mode.
    pub base: u16,
    /// The line the card really asserts on completion, relayed to the guest's
    /// BLASTER IRQ.
    pub irq: u8,
    /// The real 8237 channels the card is strapped to. A guest transfer on its
    /// own BLASTER channel must drive THESE.
    pub dma8: u8,
    /// `None` on a pre-SB16 card, which has no 16-bit channel at all.
    pub dma16: Option<u8>,
}

/// This card is real silicon, XOR it is a software model — never both, and
/// never neither. Which one it is decides what the whole machine side of the
/// SB even *means*: there is no play cursor to interpolate on a real card
/// (the 8237 has a live count), and no DMA alias to build for an emulated one
/// (nothing pulls the bus). So the two sets of state and the two sets of
/// methods live on the two payloads, and a caller reaches either only by
/// matching — which is also what proves the other one is not there.
pub enum SbDevice {
    /// A physical card answers: the guest's DSP traffic is forwarded to it and
    /// its DMA buffer aliased onto the real channel.
    Native(PassthroughSb),
    /// No card answers: `//lib:sound`'s passive card runs, and this file feeds
    /// it the clock, the interrupt line, the guest ring and the pipe depth.
    Emulated(EmulatedSb),
}

/// The machine side of a REAL card: the physical card itself plus everything
/// needed to keep a guest's illusion over it — the DSP command tracker behind
/// the synthesized busy bit, and the guest-buffer↔channel-buffer alias.
///
/// None of this is state a card *has*; it is state about *this guest's* use of
/// one, which is why it sits here and not in `NativeSb`: handing the card on
/// to the mixer's sink moves `card` out and leaves the binding behind to be
/// torn down.
pub struct PassthroughSb {
    /// The card. Passthrough is total in this variant — there is no "maybe a
    /// card" state to guard, because the variant is the guarantee.
    pub card: NativeSb,
    dsp_test_reg: u8,
    /// Last mixer index the guest selected (`base+0x04`), so `base+0x05`
    /// can answer the wiring registers from the guest's own numbers.
    mixer_idx: u8,
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

/// The machine side of the EMULATED card: `//lib:sound`'s passive chip plus
/// the two things a passive chip cannot own — a between-pump position
/// estimate, and somewhere to land the guest's ring bytes.
pub struct EmulatedSb {
    /// The library card: DSP register file + command FSM, CT1745 mixer, OPL.
    core: sound::sb::Sb,
    /// Between-pump DMA-cursor estimator. The card's cursor advances only at
    /// pump boundaries, in whole-chunk jumps — a MOD player that polls the
    /// 8237 count to find the play position (Pinball Fantasies) sees it
    /// frozen, then leaping ~512 transfers, and its coherency loop never
    /// converges. Count reads instead extrapolate from the last pump on the
    /// guest's fine clock (`rdtsc`): `est_frames` + elapsed·`est_slope`,
    /// where the slope is measured pump-over-pump from the drain slave
    /// itself (frames per 2^32 TSC ticks, EWMA-smoothed) — no TSC frequency
    /// calibration anywhere. Clamped to `est_cap` (nothing past what the
    /// sink was handed, never across an un-raised block IRQ) and monotonic
    /// via `est_served` (a pump reconciling behind the estimate holds, never
    /// rewinds).
    est_frames: u64,
    est_tsc: u64,
    est_cap: u64,
    est_slope: u64,
    est_served: u64,
    /// Linearized guest DMA window for the software mixer. The emulated SB16
    /// is capped at the canonical mix rate, so one 128-frame 16-bit stereo
    /// block is the strict maximum. Audio mixing therefore never allocates.
    dsp_scratch: [u8; DSP_SCRATCH_BYTES],
}

/// The machine's Sound Blaster: what the guest was told, and the one device
/// that answers for it.
pub struct SoundBlaster {
    /// What the guest believes. Read by both devices; owned by neither.
    pub blaster: Blaster,
    /// Real silicon or software model — see [`SbDevice`]. Public because the
    /// mixer and the I/O policy legitimately need to know *which*, and the
    /// match that tells them also hands them the right receiver.
    pub device: SbDevice,
}

impl PassthroughSb {
    fn new(card: NativeSb) -> Self {
        Self {
            card,
            dsp_test_reg: 0, mixer_idx: 0, dsp_read_data: None, dsp_expect_test_write: false,
            dsp_param_bytes: 0, dsp_dma_active: false, dsp_write_busy: 0,
            bound_chan: 0xFF, bound_host: 0xFF,
            bound_gpa: 0, bound_len: 0, bound_vpage: 0, bound_pages: 0,
            suspended: false, last_gen: [0; 8],
        }
    }
}

impl EmulatedSb {
    fn new() -> Self {
        Self {
            core: sound::sb::Sb::new(),
            est_frames: 0, est_tsc: 0, est_cap: 0, est_slope: 0, est_served: 0,
            dsp_scratch: [0; DSP_SCRATCH_BYTES],
        }
    }
}

impl SoundBlaster {
    /// Defaults: A220 I7 D1 H5 (guest sees SB IRQ 7; the host chip stays
    /// on its real line and the IRQ relay maps host→guest, so the two are
    /// intentionally decoupled). Overridden by the guest's `BLASTER=` env.
    ///
    /// Starts emulated: whether this thread gets the physical card is decided
    /// in `configure_from_env`, from what the boot probe found.
    pub fn new() -> Self {
        Self {
            blaster: Blaster { io_base: 0x220, irq: 7, dma8: 1, dma16: 5 },
            device: SbDevice::Emulated(EmulatedSb::new()),
        }
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
        let Self { blaster, device } = self;
        match device {
            SbDevice::Emulated(emu) => {
                // No real card / no buffer alias in emulation: just stop the
                // card so the next program sees a clean, idle one. Parking the
                // sink is ours — it is shared with every other source.
                emu.core.reset_for_exit();
                crate::kernel::sound::stop(machine, true); // session end: power down
            }
            SbDevice::Native(pt) => pt.release(machine, blaster),
        }
    }

    /// SB ports this card decodes — the dispatch guard for both devices: the
    /// DSP/mixer block `[io_base, io_base+0x10)` and the OPL2/3 FM window
    /// 0x388-0x38B. BLASTER's declaration, so it is the same question whether
    /// the answer will come from silicon or from the library card.
    pub fn owns(&self, p: u16) -> bool {
        let b = &self.blaster;
        (p >= b.io_base && p < b.io_base + 0x10) || matches!(p, 0x388..=0x38B)
    }

    /// Read an SB DSP/mixer/OPL port.
    pub fn sb_read<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16) -> u8 {
        let Self { blaster, device } = self;
        match device {
            SbDevice::Emulated(emu) => emu.core.port_read(p),
            SbDevice::Native(pt) => pt.read(machine, dma, blaster, p),
        }
    }

    /// Write an SB DSP/mixer/OPL port.
    pub fn sb_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        let Self { blaster, device } = self;
        match device {
            SbDevice::Emulated(emu) => emu.write(machine, dma, blaster, p, val),
            SbDevice::Native(pt) => pt.write(machine, dma, blaster, p, val),
        }
    }

    /// DMA-port read. Two distinct sources of truth, never conflated:
    ///
    ///  - **armed SB channel, count register** → the live current-count of
    ///    whichever chip is actually pacing the transfer: the real 8237 under
    ///    passthrough, the card's own play cursor when emulated. Both
    ///    decrement during playback and underflow to 0xFFFF at terminal count
    ///    — exactly the real-hw semantics Dune2's `0x4D8` ISR expects.
    ///  - **everything else** (not-yet-armed = programming snapshot,
    ///    non-SB channels, addr/page/status) → `Dma8237::io_read`, i.e.
    ///    the captured guest programming.
    pub fn dma_read<A: crate::Arch>(&mut self, machine: &mut A, dma: &mut Dma8237, port: u16) -> u8 {
        let Self { blaster, device } = self;
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
            return match device {
                SbDevice::Emulated(emu) if port == 0x08 || port == 0xD0 =>
                    emu.core.take_tc_status(port == 0xD0),
                _ => dma.io_read(machine, port),
            };
        };
        match device {
            SbDevice::Emulated(emu) => emu.dma_read(machine, dma, blaster, is_cnt, chan, hi_ctrl),
            SbDevice::Native(pt) => pt.dma_read(machine, dma, blaster, port, is_cnt, chan, hi_ctrl),
        }
    }

    /// Called after every virtual-8237 write. Only a real card needs anything
    /// here: emulated, the virtual-8237 `prog` is already captured (io_write)
    /// and we read the guest ring for the card at playback — there is no chip
    /// to program and no buffer to alias.
    pub fn maybe_remap<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237) {
        let Self { blaster, device } = self;
        if let SbDevice::Native(pt) = device {
            pt.maybe_remap(machine, regs, dma, blaster);
        }
    }

    /// Task switched to the background. Emulated has nothing to detach — its
    /// "DMA" is a read of guest memory that happens only while we run it.
    pub fn sb_suspend<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs) {
        if let SbDevice::Native(pt) = &mut self.device {
            pt.suspend(machine);
        }
    }

    /// Task switched back to the foreground: re-materialize the binding.
    pub fn sb_resume<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237) {
        let Self { blaster, device } = self;
        if let SbDevice::Native(pt) = device {
            pt.resume(machine, regs, dma, blaster);
        }
    }

    /// Apply this thread's `BLASTER=Axxx Iy Dz Hw …` env string, and settle
    /// which device answers for it. Unknown or missing tokens leave the SB16
    /// defaults. `env` is the raw DOS environment block (NUL-separated
    /// `KEY=VAL`, double-NUL terminated).
    ///
    /// This is where the card is acquired: the boot probe's verdict plus a
    /// readable strap is the whole condition. Anything less — no card, no
    /// wiring to relay, or an owner who asked for the mixer — and the guest
    /// gets the library card instead. There is no third state, so no
    /// passthrough path anywhere below has to ask whether a card is there.
    pub fn configure_from_env(&mut self, env: &[u8]) {
        let plat = crate::kernel::platform::get();
        self.device = match (plat.audio.sb_passthrough(), plat.sb_card, plat.sb_wiring) {
            (true, Some(card), Some(w)) => SbDevice::Native(PassthroughSb::new(NativeSb {
                base: card.base, irq: w.irq, dma8: w.dma8, dma16: w.dma16,
            })),
            _ => SbDevice::Emulated(EmulatedSb::new()),
        };
        if let Some(val) = env_var(env, b"BLASTER") {
            for tok in val.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
                let (key, rest) = (tok[0].to_ascii_uppercase(), &tok[1..]);
                let radix = if key == b'A' || key == b'P' { 16 } else { 10 };
                let Some(n) = parse_uint(rest, radix) else { continue };
                match key {
                    b'A' => self.blaster.io_base = n as u16,
                    b'I' => self.blaster.irq = n as u8,
                    b'D' => self.blaster.dma8 = n as u8,
                    b'H' => self.blaster.dma16 = n as u8,
                    _ => {}
                }
            }
        }
        // The emulated card decodes against the base and reports the IRQ/DMA
        // numbers back through its mixer configuration registers. A real card
        // reports its own straps and the machine translates instead.
        if let SbDevice::Emulated(emu) = &mut self.device {
            let b = &self.blaster;
            emu.core.set_wiring(b.io_base, b.irq, b.dma8, b.dma16);
        }
    }
}

// ── The real card's machine side ────────────────────────────────────────────

impl PassthroughSb {
    /// Ports inside the DSP window that MUST trap, as a mask of offsets
    /// from `io_base`. Everything else can be granted to the guest outright
    /// (the IOPB is per-port), so DSP traffic on a correctly-declared card
    /// costs no exits at all. Only a real card has this question: there is
    /// nothing to grant a guest whose card is a software model.
    ///
    /// What traps and why:
    ///
    ///  * the whole window when the card is strapped somewhere other than
    ///    BLASTER's base — every access needs `host_port` translation.
    ///  * mixer index+data (0x04/0x05): ALWAYS. Registers 0x80/0x81 are the
    ///    SB16's soft-straps — the kernel owns the physical wiring (its IRQ
    ///    arming and DMA remap are derived from it), so a guest write there
    ///    must never reach silicon (`write` drops it) and a read reports
    ///    the guest's labels, not physical facts (`read`). On the era's
    ///    bare metal a game COULD restrap the card; under a kernel that
    ///    relays the line, that same write silently kills every completion.
    ///    Mixer traffic is volume knobs — cold path, the trap costs nothing.
    ///  * DSP data/status (0x0A/0x0C/0x0E) under QEMU only, where the
    ///    E4h/E8h test register and the write-status busy flicker must be
    ///    synthesized because QEMU's sb16 lacks what real silicon has.
    ///
    /// So on a correctly-declared card the hot DSP ports trap nothing —
    /// only the mixer pair stays supervised, to guard the straps.
    pub fn trap_mask(&self, b: &Blaster) -> u16 {
        if self.card.base != b.io_base {
            return 0xFFFF;
        }
        let mut m = (1 << 0x04) | (1 << 0x05);
        if crate::kernel::platform::get().host == crate::kernel::platform::Host::Qemu {
            m |= (1 << 0x0A) | (1 << 0x0C) | (1 << 0x0E);
        }
        m
    }

    /// The physical port for a guest port in the DSP window. BLASTER is the
    /// owner's declaration; the window traps on every access, so a card
    /// strapped somewhere else costs nothing to support — same traps, one
    /// different addend.
    #[inline]
    fn host_port(&self, b: &Blaster, p: u16) -> u16 {
        if self.card.base == b.io_base {
            return p;
        }
        match p.checked_sub(b.io_base) {
            Some(off) if off < 0x10 => self.card.base + off,
            _ => p, // OPL and anything else is at a fixed address
        }
    }

    /// Release the DMA binding and quiesce the card — exec/exit cleanup.
    /// The per-channel buffers are permanent; this just detaches the guest
    /// alias and clears the re-arm cursor so a reused device can't dangle.
    /// Also resets the SB DSP and masks the host SB channels so the next
    /// program sees a clean card — without this, OMF re-launch from a
    /// launcher inherits OMF1's mid-playback DSP / armed-8237 state and
    /// OMF2's sound-init probe falls into a "wait for the card to settle"
    /// timeout branch (526 `INT 21 AH=2C` calls in the hang trace).
    /// Idempotent.
    fn release<A: crate::Arch>(&mut self, machine: &mut A, b: &Blaster) {
        self.unbind(machine);
        // SB DSP reset: write 1 then 0 to io_base+6. QEMU's sb16 processes
        // this atomically; the hardware ~3 µs hold is irrelevant under
        // emulation. Puts the DSP back in its post-power-on state so the
        // next program's reset+probe behaves like the first one's.
        let reset = self.host_port(b, b.io_base + 0x06);
        machine.outb(reset, 1);
        machine.outb(reset, 0);
        // Stop any in-flight host DMA cold; the next bind reprograms and
        // unmasks. These are the card's own 8-bit/16-bit lines.
        mask_real_8237(machine, self.card.dma8);
        if let Some(d16) = self.card.dma16 { mask_real_8237(machine, d16); }
        self.suspended = false;
        self.last_gen = [0; 8];
        self.dsp_param_bytes = 0;
        self.dsp_dma_active = false;
        self.dsp_expect_test_write = false;
    }

    /// Read a DSP/mixer/OPL port off the real card, with a tiny compatibility
    /// shim for DSP command E4h/E8h (test register write/read). Some older
    /// games poll base+0Eh forever waiting for E8h to produce a byte; QEMU
    /// sb16 does not appear to surface that response through passthrough.
    fn read<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, b: &Blaster, p: u16) -> u8 {
        if p == b.io_base + 0x05 {
            // Mixer data. Registers 0x80/0x81 report the IRQ and DMA the
            // card is strapped to — physical facts the guest must NOT see
            // in passthrough: it was told its own numbers by BLASTER, and
            // the machine translates (the vPIC relays the card's line onto
            // the guest's, the virtual 8237 remaps its channels). A guest
            // believing the straps would hook a line we never raise. Every
            // other mixer register is real state and passes through.
            match self.mixer_idx {
                0x80 => return match b.irq {
                    2 => 0x01, 5 => 0x02, 7 => 0x04, 10 => 0x08, _ => 0x02,
                },
                0x81 => {
                    let lo = match b.dma8 { 0 => 0x01, 1 => 0x02, 3 => 0x08, _ => 0x02 };
                    let hi = match b.dma16 { 5 => 0x20, 6 => 0x40, 7 => 0x80, _ => 0 };
                    return lo | hi;
                }
                _ => {}
            }
        }
        if p == b.io_base + 0x0A {
            if let Some(v) = self.dsp_read_data.take() {
                return v;
            }
        } else if p == b.io_base + 0x0E && self.dsp_read_data.is_some() {
            return 0x80;
        } else if p == b.io_base + 0x0C {
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
            let v = machine.inb(self.host_port(b, p));
            if self.dsp_single_cycle_busy(machine, dma, b) {
                self.dsp_write_busy = self.dsp_write_busy.wrapping_add(1);
                if self.dsp_write_busy & 8 != 0 {
                    return v | 0x80;
                }
            }
            return v;
        }
        machine.inb(self.host_port(b, p))
    }

    /// True while a single-cycle DSP DMA transfer is genuinely mid-block: a
    /// start/continue command is active *and* the real 8237's live current-
    /// count hasn't yet underflowed to the terminal 0xFFFF. Gates the DSP
    /// write-status busy flicker in `read`. The `dsp_dma_active` flag is
    /// checked first, so an idle/paused/completed channel costs no port I/O.
    /// 16-bit single-cycle isn't modelled (no client polls for it); the
    /// 8-bit/ADPCM host channel is the only one a `0x14`-class command drives.
    /// The 8237 single-cycle mode check (bit 4 clear) keeps auto-init clients
    /// (Quake, Dune2, ROTT) unconditionally exempt — their busy bit stays 0
    /// even across a pause/continue — so their command polls never throttle.
    fn dsp_single_cycle_busy<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, b: &Blaster) -> bool {
        self.dsp_dma_active
            && dma.ch[b.dma8 as usize].prog.mode & 0x10 == 0
            && real_8237_count(machine, self.card.dma8) != 0xFFFF
    }

    /// Write a DSP/mixer/OPL port through to the real card. DSP E4h/E8h are
    /// handled locally; all other traffic continues to the silicon.
    ///
    /// On the DSP command port we also run a minimal opcode/parameter tracker
    /// — enough to keep the synthesized write-status busy bit (see `read`)
    /// honest across the start/pause/resume of a single-cycle transfer. It
    /// never suppresses a write: every byte still reaches the card. A DSP
    /// reset (write to base+0x06) clears the tracker.
    fn write<A: crate::Arch>(&mut self, machine: &mut A, _dma: &Dma8237, b: &Blaster, p: u16, val: u8) {
        if p == b.io_base + 0x06 {
            // DSP reset — drop any half-decoded command / transfer state.
            self.dsp_param_bytes = 0;
            self.dsp_dma_active = false;
            self.dsp_expect_test_write = false;
        } else if p == b.io_base + 0x0C {
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
        if p == b.io_base + 0x04 {
            self.mixer_idx = val;
        } else if p == b.io_base + 0x05 && matches!(self.mixer_idx, 0x80 | 0x81) {
            // The guest may move ITS view of the wiring — the relay and the
            // remap follow BLASTER — but the physical straps stay where the
            // kernel found them; nothing else on the machine knows they
            // moved. This filter is why the mixer pair is always in
            // `trap_mask`.
            return;
        }
        machine.outb(self.host_port(b, p), val);
    }

    /// Serve the armed SB channel's live addr/count from the real 8237;
    /// everything else from the captured guest programming.
    #[allow(clippy::too_many_arguments)]
    fn dma_read<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        dma: &mut Dma8237,
        b: &Blaster,
        port: u16,
        is_cnt: bool,
        chan: usize,
        hi_ctrl: bool,
    ) -> u8 {
        let host = if chan == b.dma8 as usize { Some(self.card.dma8) }
                   else if chan == b.dma16 as usize { self.card.dma16 }
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
                        // Count register: the real 8257's live current-count —
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

    /// When the BLASTER channel is (re)armed, alias the guest's DMA buffer
    /// onto that channel's permanent host buffer and program the real 8237.
    /// A no-op until the guest finishes a count write (the per-block re-arm
    /// signal).
    fn maybe_remap<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237, b: &Blaster) {
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = b.dma8 as usize;
        let c16 = b.dma16 as usize;
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
                (c16, true, self.card.dma16.unwrap_or(0xFF) as usize)
            } else if armed8 {
                (c8, false, self.card.dma8 as usize)
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
    /// `maybe_remap` (a guest port write) and `resume` (replaying the
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
        // Armed: the real 8257 is now authoritative for this channel's
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
    /// longer ours. The virtual 8237 keeps the armed state; `resume`
    /// replays it. Must run with this task's address space active.
    fn suspend<A: crate::Arch>(&mut self, machine: &mut A) {
        if self.bound_gpa == 0 { return; }
        mask_real_8237(machine, self.bound_host);
        self.unbind(machine);
        self.suspended = true;
    }

    /// Task switched back to the foreground: re-materialize the binding —
    /// re-alias every channel the virtual 8237 still shows armed and
    /// reprogram the real 8237. Must run with this task's address space
    /// active.
    fn resume<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dma: &mut Dma8237, _b: &Blaster) {
        if !self.suspended { return; }
        self.suspended = false;
        for chan in 0..8 {
            if !dma.ch[chan].armed { continue; }
            let is16 = chan >= 4;
            let host = if is16 { self.card.dma16.unwrap_or(0xFF) } else { self.card.dma8 } as usize;
            let p = dma.ch[chan].prog;
            let (gpa, len) = chan_gpa_len(&p, is16);
            self.arm(machine, regs, dma, chan, host, is16, gpa, len, p.mode);
        }
    }
}

// ── The emulated card's machine side ────────────────────────────────────────
//
// The library card runs the DSP register file and command FSM; everything
// here supplies it with what a passive card cannot have — the clock, the
// interrupt line, the guest's DMA ring, and the sink's pipe depth. None of it
// is reachable without matching `SbDevice::Emulated`, which is the point:
// there is no play cursor to interpolate and no ring to fetch when a real
// card is doing the transferring.

impl EmulatedSb {
    /// Emulated DSP/mixer/FM port write. The card decodes; when it decodes a
    /// start-playback command it hands it back, because only we can read the
    /// guest's DMA controller for the ring that command refers to.
    fn write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, b: &Blaster, p: u16, val: u8) {
        let now = machine.get_ticks();
        let Some(start) = self.core.port_write(p, val, now) else { return };
        let is16 = start.bits == 16;
        let chan = if is16 { b.dma16 } else { b.dma8 } as usize;
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
    pub fn deliver_trigger_irq(&mut self, vpic: &mut super::vpic::VirtualPic, irq: u8) {
        if self.core.take_trigger() && !vpic.is_requested(irq) {
            vpic.raise(irq);
        }
    }

    /// Complete a single-cycle transfer too short for the pump clock to see
    /// (see the card's `take_probe`), on the slice alongside 0xF2's latched
    /// trigger IRQ.
    pub fn deliver_probe_irq<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        vpic: &mut super::vpic::VirtualPic,
        irq: u8,
    ) {
        if self.core.take_probe(machine.get_ticks()) && !vpic.is_requested(irq) {
            vpic.raise(irq);
        }
    }

    /// Whether the emulated DSP owns the canonical sink right now: playing,
    /// or holding the stream open through the hangover. The top of the
    /// producer priority chain (DSP > GUS > OPL).
    pub fn dsp_owns_sink(&self) -> bool {
        self.core.owns_sink()
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
            let need = f.source_frames * fb;
            let Some(scratch) = self.dsp_scratch.get_mut(..need) else {
                debug_assert!(false, "SB fetch exceeds fixed mixer block");
                self.core.mix_fm(rate, block);
                return;
            };
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
            self.core.mix_dsp(rate, base, scratch, &f, block);
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
        irq: u8,
        drained: u64,
        pushed: u64,
    ) {
        let now = machine.get_ticks();
        if self.core.advance_clock(now, drained, pushed) && !vpic.is_requested(irq) {
            vpic.raise(irq);
        }
        // Re-anchor the count-read estimator on the reconciled cursor and
        // measure the frames-per-TSC slope from this pump interval. A cursor
        // behind the previous anchor is a session restart — drop the
        // monotonicity floor with it (the slope survives: the machine's
        // clock ratio didn't change with the transfer).
        let frames = self.core.cursor_frames();
        let tsc = machine.rdtsc();
        if self.core.playing() {
            let df = frames.wrapping_sub(self.est_frames);
            let dt = tsc.wrapping_sub(self.est_tsc);
            // Sane interval only: forward, sub-second-ish, cursor moved.
            if (1..1 << 40).contains(&dt) && (1..1 << 20).contains(&df) {
                let slope = (((df as u128) << 32) / dt as u128) as u64;
                self.est_slope = if self.est_slope == 0 {
                    slope
                } else {
                    (self.est_slope * 3 + slope) / 4
                };
            }
        }
        if frames < self.est_frames {
            self.est_served = 0;
        }
        self.est_frames = frames;
        self.est_tsc = tsc;
        self.est_cap = pushed.min(self.core.next_irq_frames()).max(frames);
    }

    /// The estimated play cursor for a count/address read *between* pumps:
    /// the last reconciled position plus TSC-elapsed × measured slope,
    /// capped and monotonic (see the `est_*` field docs). With no slope
    /// measured yet this degrades to the pump-quantized cursor.
    fn dma_pos_estimate<A: crate::Arch>(&mut self, machine: &mut A) -> u64 {
        let dt = machine.rdtsc().wrapping_sub(self.est_tsc);
        let adv = if dt < 1 << 40 {
            ((dt as u128 * self.est_slope as u128) >> 32) as u64
        } else {
            0
        };
        let mut pos = self.est_frames.saturating_add(adv).min(self.est_cap);
        if self.est_served > pos && self.est_served >= self.est_frames {
            pos = self.est_served; // a lagging re-anchor holds, never rewinds
        }
        self.est_served = pos;
        pos
    }

    /// Emulated DMA current-address/count read: serve the active SB channel's
    /// live state from the card's play cursor (auto-init down-count), other
    /// channels from the captured base programming. The flip-flop and the
    /// programmed base are the controller's — ours; the cursor is the card's.
    fn dma_read<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        dma: &mut Dma8237,
        b: &Blaster,
        is_cnt: bool,
        chan: usize,
        hi_ctrl: bool,
    ) -> u8 {
        let is_active = chan == b.dma8 as usize || chan == b.dma16 as usize;
        // The guest reading the active channel's count = it serviced the block
        // (it computed where to refill). Extend the card's commit horizon.
        if is_cnt && is_active {
            self.core.mark_block_serviced();
        }
        let ff = if hi_ctrl { &mut dma.ff_hi } else { &mut dma.ff_lo };
        let low = !*ff;
        *ff = !*ff;
        if self.core.playing() && is_active {
            // Latched at the low-byte read so the lo/hi pair is coherent —
            // the estimator must not advance between the two halves (the
            // hi/lo tear is the very thing a driver's tolerance loop probes
            // for). Estimated, not pump-quantized: a poll loop watching for
            // the cursor to enter a window needs it to move smoothly.
            if low {
                let pos = self.dma_pos_estimate(machine);
                let (count, consumed) = self.core.dma_cursor_at(pos);
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
