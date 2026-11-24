//! Driving a REAL Sound Blaster on a guest's behalf.
//!
//! The machine model in `dos/machine/vsb.rs` emulates a Sound Blaster when
//! none is present. When one IS present, none of that runs: the guest's DSP
//! traffic goes to the silicon and its DMA buffer is aliased onto the
//! channel buffer the real 8237 transfers from. Everything that touches the
//! card or the physical DMA controller to make that work is here, because
//! this is a driver — the personality that wants it must not be poking a
//! CT1745 mixer or an 8237 page register itself.
//!
//! The split against the model is: **this file knows silicon, the model
//! knows the guest.** So the virtual 8237 and the lockstep DSP shadow stay
//! on the model side and call in with plain values; nothing here dereferences
//! a machine-model type. What is left is genuinely physical —
//!
//!   - the DSP handshake and the command sequence that programs a card into
//!     a stream the guest already believes it has ([`NativeSb::adopt`]);
//!   - port forwarding, with the two lies the guest needs told (see
//!     [`NativeSb::trap_mask`]);
//!   - the guest-buffer ↔ channel-buffer page alias ([`NativeSb::arm`] /
//!     [`NativeSb::unbind`]) and the real 8237 programming behind it.
//!
//! This is [`sb16`](super::sb16)'s sibling, not its rival: that file owns the
//! card as the kernel's PCM *sink*, this one lends it to a guest. Both are
//! reached only while holding an [`Sb16`], which is the possession proof.

use super::sb16::Sb16;
use sound::opl::{OPERATOR_OFFSETS, Registers};
use sound::sb::Wiring as Blaster;

/// Cache-disable attribute for the native ISA DMA alias. The platform
/// installs it as a borrowed mapping of the card's permanent channel pages.
const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// DSP reset: 1 then 0 to `base+6`, the power-on handshake.
fn dsp_reset<A: crate::Core>(machine: &mut A, base: u16) {
    machine.outb(base + 0x06, 1);
    machine.outb(base + 0x06, 0);
}

/// One DSP command/data byte, once the write buffer says it is ready.
fn dsp_write<A: crate::Core>(machine: &mut A, base: u16, byte: u8) {
    for _ in 0..100_000 {
        if machine.inb(base + 0x0C) & 0x80 == 0 {
            break;
        }
    }
    machine.outb(base + 0x0C, byte);
}

/// The machine side of a REAL card: the physical card itself plus everything
/// needed to keep a guest's illusion over it — the DSP command tracker behind
/// the synthesized busy bit, and the guest-buffer↔channel-buffer alias.
///
/// None of this is state a card *has*; it is state about *this guest's* use of
/// one, which is why it sits here and not in [`Sb16`]: handing the card on
/// to the mixer's sink moves `card` out and leaves the binding behind to be
/// torn down.
pub struct NativeSb {
    /// The machine's card, held. Passthrough is total in this variant — there
    /// is no "maybe a card" state to guard, because possession is the
    /// guarantee: this value cannot be copied or conjured, only moved in.
    pub card: Sb16,
    opl2: bool,
    /// Last mixer index the guest selected (`base+0x04`), so `base+0x05`
    /// can answer the wiring registers from the guest's own numbers.
    mixer_idx: u8,
    /// Software completions still awaiting the guest's DSP acknowledge.
    carried_irq: u8,
    /// Hardware PCM latches for which an edge already reached the virtual PIC.
    notified_irq: u8,
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

impl NativeSb {
    /// The OSD briefly selects the master register, then puts the guest's
    /// mixer index back so its next data-port access still targets its choice.
    pub fn set_master<A: crate::Core>(&self, machine: &mut A, raw: u8) {
        self.card.set_master(machine, raw);
        machine.outb(self.card.base + 0x04, self.mixer_idx);
    }

    pub fn set_source<A: crate::Core>(&self, machine: &mut A,
        source: crate::kernel::osd::SbSource, level: u8) {
        self.card.set_source(machine, source, level);
        machine.outb(self.card.base + 0x04, self.mixer_idx);
    }

    fn new(card: Sb16) -> Self {
        Self {
            card,
            // QEMU's YM3812 aliases its upper ports onto the lower bank.
            opl2: crate::kernel::platform::get().host == crate::kernel::platform::Host::Qemu,
            mixer_idx: 0,
            carried_irq: 0,
            notified_irq: 0,
            bound_chan: 0xFF, bound_host: 0xFF,
            bound_gpa: 0, bound_len: 0, bound_vpage: 0, bound_pages: 0,
            suspended: false, last_gen: [0; 8],
        }
    }

    pub fn fm_shadow_port(&self, b: &Blaster, port: u16) -> u16 {
        if self.opl2
            && (matches!(port, 0x38a | 0x38b)
                || matches!(port.wrapping_sub(b.io_base), 2 | 3))
        {
            return port - 2;
        }
        port
    }

    fn opl_write<A: crate::Core>(&self, machine: &mut A, index: u16, val: u8) {
        if self.opl2 && index >= 0x100 { return; }
        let port = 0x388 + (index >> 8) * 2;
        machine.outb(port, index as u8);
        self.opl_delay(machine, 3_300);
        machine.outb(port + 1, val);
        self.opl_delay(machine, 23_000);
    }

    fn opl_delay<A: crate::Core>(&self, machine: &A, ns: u64) {
        if self.opl2 { return; }
        let start = machine.now();
        while machine.now().saturating_sub(start) < ns {
            core::hint::spin_loop();
        }
    }

    pub fn restore_fm<A: crate::Core>(&mut self, machine: &mut A, registers: Option<&Registers>) {
        if core::mem::take(&mut self.card.fm_parked) {
            for bank in [0, 0x100] {
                for offset in OPERATOR_OFFSETS {
                    self.opl_write(machine, bank + 0x80 + offset, 0);
                }
            }
        }
        if let Some(registers) = registers {
            registers.replay(|index, val| self.opl_write(machine, index, val));
            let index = registers.index();
            let port = if self.opl2 { 0x388 } else { 0x388 + (index >> 8) * 2 };
            machine.outb(port, index as u8);
            self.opl_delay(machine, 3_300);
        }
    }

    pub fn park_fm<A: crate::Core>(&mut self, machine: &mut A, registers: Option<&Registers>) {
        let Some(registers) = registers else { return; };
        // DSP reset leaves OPL running. Force a fast release even for
        // instruments with a zero release rate, then clear their programming.
        for bank in [0, 0x100] {
            for offset in OPERATOR_OFFSETS {
                self.opl_write(machine, bank + 0x80 + offset, 0x0f);
            }
            for voice in 0..9 {
                self.opl_write(machine, bank + 0xb0 + voice, 0);
            }
        }
        // Release the percussion keys while rhythm mode is still enabled.
        self.opl_write(machine, 0xbd, 0x20);
        self.opl_write(machine, 0xbd, 0);
        self.opl_write(machine, 0x04, 0x60);
        self.opl_write(machine, 0x04, 0x80);
        registers.replay(|index, _| {
            if !Registers::is_key_register(index)
                && !matches!(index, 0x04 | 0x80..=0x95 | 0x104 | 0x105 | 0x180..=0x195)
            {
                self.opl_write(machine, index, 0);
            }
        });
        if !self.opl2 {
            self.opl_write(machine, 0x104, 0);
            self.opl_write(machine, 0x105, 0);
        }
        machine.outb(0x388, 0);
        self.card.fm_parked = true;
    }

    /// Take possession of `card` and program it into the stream `st`
    /// describes — the state the guest believes its card is already in,
    /// carried by the model that watched every DSP write go past.
    ///
    /// Order matters and is the card's, not ours: reset clears the DSP, then
    /// the speaker and the stream parameters, then the start command last,
    /// because on a real DSP the start command is what latches the format and
    /// begins the transfer. The DMA side needs nothing here — the virtual
    /// 8237 still holds the guest's programming, and the next `arm` re-arms
    /// the real controller from it.
    pub fn adopt<A: crate::Core>(
        machine: &mut A, card: Sb16, st: sound::sb::DspState, mixer_idx: u8, pending: u8,
    ) -> Self {
        let base = card.base;
        let mixer = |machine: &mut A, index: u8| {
            machine.outb(base + 0x04, index);
            machine.inb(base + 0x05)
        };
        crate::compact_println!(
            "sb: native mixer master={:#04x} voice={:#04x} FM={:#04x} output={:#04x}",
            mixer(machine, 0x22), mixer(machine, 0x04),
            mixer(machine, 0x26), mixer(machine, 0x3c));
        machine.outb(base + 0x04, 0);
        dsp_reset(machine, base);
        dsp_write(machine, base, if st.speaker { 0xD1 } else { 0xD3 });
        // Rate: an SB16 takes it directly; anything older only understands the
        // time constant, and 256 − 1e6/rate is its inverse.
        if card.dma16.is_some() {
            dsp_write(machine, base, 0x41);
            dsp_write(machine, base, (st.rate >> 8) as u8);
            dsp_write(machine, base, st.rate as u8);
        } else {
            let tc = 256u32.saturating_sub(1_000_000 / st.rate.max(1));
            dsp_write(machine, base, 0x40);
            dsp_write(machine, base, tc as u8);
        }
        dsp_write(machine, base, 0x48);
        dsp_write(machine, base, st.block as u8);
        dsp_write(machine, base, (st.block >> 8) as u8);
        if st.playing {
            // Start command: 8-bit legacy opcodes carry the format in the
            // opcode; 16-bit ones carry it in a mode byte.
            if st.bits == 16 {
                dsp_write(machine, base, if st.single { 0xB0 } else { 0xB6 });
                // Preserve the guest's SB16 mode byte across card handoff.
                dsp_write(machine, base, (if st.signed { 0x10 } else { 0 })
                    | (if st.stereo { 0x20 } else { 0 }));
                dsp_write(machine, base, st.block as u8);
                dsp_write(machine, base, (st.block >> 8) as u8);
            } else {
                dsp_write(machine, base, if st.single { 0xC0 } else { 0xC6 });
                dsp_write(machine, base, (if st.signed { 0x10 } else { 0 })
                    | (if st.stereo { 0x20 } else { 0 }));
                dsp_write(machine, base, st.block as u8);
                dsp_write(machine, base, (st.block >> 8) as u8);
            }
        }
        crate::compact_dbg_println!(
            "[sb] card taken: {}Hz {}bit {} {} block={} speaker={} playing={}",
            st.rate, st.bits, if st.stereo { "stereo" } else { "mono" },
            if st.single { "single" } else { "auto" }, st.block, st.speaker, st.playing
        );
        let mut native = Self::new(card);
        native.mixer_idx = mixer_idx;
        machine.outb(base + 0x04, mixer_idx);
        native.carried_irq = pending;
        native
    }

    /// Give the card back. The caller must have `release`d it first.
    pub fn into_card(self) -> Sb16 {
        self.card
    }

    /// The physical card, for the questions only its own straps answer.
    pub fn card(&self) -> &Sb16 {
        &self.card
    }

    /// Whether a background suspend detached the alias, so the next swap-in
    /// knows it must replay the guest's channel programming.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// Read the hardware cursor while the guest's playback ring is still bound.
    fn bound_dma_count<A: crate::Core>(&self, machine: &mut A, channel: usize) -> Option<u16> {
        (self.bound_chan != 0xff && usize::from(self.bound_chan) == channel)
            .then(|| real_8237_count(machine, self.bound_host))
    }

    fn irq_status<A: crate::Core>(&self, machine: &mut A) -> Option<u8> {
        if !self.card.has_ct1745() {
            return None;
        }
        let index = self.card.base + 0x04;
        machine.outb(index, 0x82);
        let status = machine.inb(index + 1);
        machine.outb(index, self.mixer_idx);
        Some(status)
    }

    /// Filter stale host edges and remember completions already posted to DOS.
    pub fn relay_irq<A: crate::Core>(&mut self, machine: &mut A) -> bool {
        let Some(status) = self.irq_status(machine) else { return true; };
        // A completion of the same width coalesces with a latch the guest
        // still owes an acknowledgement for, including one from the mixer.
        let fresh = status & !(self.notified_irq | self.carried_irq);
        self.notified_irq = status & 0x03;
        fresh & 0x07 != 0
    }

    /// Freeze the DMA controller before sampling the cursor and interrupt latches.
    /// The second status value contains PCM edges the kernel has yet to relay.
    pub fn relinquish<A: crate::Core>(
        &mut self, machine: &mut A, b: &Blaster, channel: usize,
    ) -> (Option<u16>, Option<(u8, u8)>) {
        self.mask_dma(machine);
        let count = self.bound_dma_count(machine, channel);
        let interrupts = self.irq_status(machine).map(|status| {
            let pcm = status & 0x03;
            (pcm | self.carried_irq, pcm & !(self.notified_irq | self.carried_irq))
        });
        self.reset_and_unbind(machine, b);
        (count, interrupts)
    }

    /// Clear the suspended mark once the caller has replayed the programming.
    pub fn clear_suspended(&mut self) {
        self.suspended = false;
    }

    /// Has the guest re-armed `chan` since we last acted on it? The model
    /// owns the generation counter; the binding that must follow it is ours.
    pub fn take_rearm(&mut self, chan: usize, cur_gen: u32) -> bool {
        if self.last_gen[chan] == cur_gen { return false; }
        self.last_gen[chan] = cur_gen;
        true
    }
}

// ── The real card's machine side ────────────────────────────────────────────

impl NativeSb {
    /// Trap accesses needed to translate the guest's wiring, track DSP
    /// commands, and preserve completion latches across mode changes.
    /// A mismatched I/O base requires translation for the entire window.
    pub fn trap_mask(&self, b: &Blaster) -> u16 {
        if self.card.base != b.io_base {
            return 0xFFFF;
        }
        // OPL aliases, mixer, DSP writes, and completion acknowledgements.
        0x030F | (1 << 0x04) | (1 << 0x05) | (1 << 0x06) | (1 << 0x0C) | (1 << 0x0E) | (1 << 0x0F)
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
    pub fn release<A: crate::Core>(&mut self, machine: &mut A, b: &Blaster) {
        self.mask_dma(machine);
        self.reset_and_unbind(machine, b);
    }

    fn mask_dma<A: crate::Core>(&self, machine: &mut A) {
        mask_real_8237(machine, self.card.dma8);
        if let Some(d16) = self.card.dma16 { mask_real_8237(machine, d16); }
    }

    fn reset_and_unbind<A: crate::Core>(&mut self, machine: &mut A, b: &Blaster) {
        self.unbind(machine);
        // SB DSP reset: write 1 then 0 to io_base+6. QEMU's sb16 processes
        // this atomically; the hardware ~3 µs hold is irrelevant under
        // emulation. Puts the DSP back in its post-power-on state so the
        // next program's reset+probe behaves like the first one's.
        let reset = self.host_port(b, b.io_base + 0x06);
        machine.outb(reset, 1);
        machine.outb(reset, 0);
        // Silence what the channels would transfer if anything unmasked them.
        // The buffer still holds this program's last lap — `unbind` copied it
        // back to the guest, it did not clear it — and an auto-init transfer
        // has no LVI gate, so it would simply play again.
        crate::kernel::drivers::sb16::zero_channel_buf(&self.card, self.card.dma8);
        if let Some(d16) = self.card.dma16 {
            crate::kernel::drivers::sb16::zero_channel_buf(&self.card, d16);
        }
        self.suspended = false;
        self.last_gen = [0; 8];
        self.carried_irq = 0;
        self.notified_irq = 0;
    }

    /// Read the card, translating its wiring and exposing PCM completions
    /// carried across from the software DSP until the guest acknowledges them.
    pub fn read<A: crate::Core>(&mut self, machine: &mut A, b: &Blaster, p: u16) -> u8 {
        if p == b.io_base + 0x05 {
            // Mixer data. Registers 0x80/0x81 report the IRQ and DMA the card
            // is strapped to — physical facts the guest must NOT see: it was
            // told its own numbers by BLASTER and the machine translates.
            // Every other mixer register is real state and passes through.
            match self.mixer_idx {
                0x80 => return match b.irq {
                    2 => 0x01, 5 => 0x02, 7 => 0x04, 10 => 0x08, _ => 0x02,
                },
                0x81 => {
                    let lo = match b.dma8 { 0 => 0x01, 1 => 0x02, 3 => 0x08, _ => 0x02 };
                    let hi = match b.dma16 { 5 => 0x20, 6 => 0x40, 7 => 0x80, _ => 0 };
                    return lo | hi;
                }
                0x82 => return machine.inb(self.host_port(b, p)) | self.carried_irq,
                _ => {}
            }
        }
        let ack = match p.wrapping_sub(b.io_base) {
            0x0E => 0x01,
            0x0F => 0x02,
            _ => 0,
        };
        self.carried_irq &= !ack;
        self.notified_irq &= !ack;
        machine.inb(self.host_port(b, p))
    }

    /// Write a DSP/mixer/OPL port through to the real card. Only the mixer
    /// strap pair is filtered (see `trap_mask`); every other byte reaches the
    /// silicon verbatim, because the silicon is the card.
    pub fn write<A: crate::Core>(&mut self, machine: &mut A, b: &Blaster, p: u16, val: u8) {
        if p == b.io_base + 0x06 && val == 0 {
            self.carried_irq = 0;
            self.notified_irq = 0;
        }
        if p == b.io_base + 0x04 {
            self.mixer_idx = val;
        } else if p == b.io_base + 0x05 && matches!(self.mixer_idx, 0x80 | 0x81) {
            // The guest may move ITS view of the wiring — the relay and the
            // remap follow BLASTER — but the physical straps stay where the
            // kernel found them; nothing else on the machine knows they moved.
            // This filter is why the mixer pair is always in `trap_mask`.
            return;
        }
        if p == b.io_base + 0x05
            && matches!(self.mixer_idx, 0x04 | 0x22 | 0x26 | 0x30..=0x35 | 0x3c)
        {
            crate::compact_println!("sb: mixer {:#04x} <- {:#04x}", self.mixer_idx, val);
        }
        if p == b.io_base + 0x05 {
            match self.mixer_idx {
                0x22 => crate::kernel::osd::observe_sb_master(val),
                0x30 | 0x31 => crate::kernel::osd::observe_sb_master_channel(self.mixer_idx, val),
                0x32..=0x37 => crate::kernel::osd::observe_sb_source(self.mixer_idx, val),
                _ => {}
            }
        }
        machine.outb(self.host_port(b, p), val);
        if p == b.io_base + 0x05 {
            let source = match self.mixer_idx {
                0x04 => Some(crate::kernel::osd::SbSource::Wave),
                0x26 => Some(crate::kernel::osd::SbSource::Fm),
                0x28 => Some(crate::kernel::osd::SbSource::Cd),
                _ => None,
            };
            if let Some(source) = source.filter(|_| self.card.has_ct1745()) {
                for index in source.left_register()..=source.left_register() + 1 {
                    machine.outb(self.card.base + 0x04, index);
                    crate::kernel::osd::observe_sb_source(index,
                        machine.inb(self.card.base + 0x05));
                }
                machine.outb(self.card.base + 0x04, self.mixer_idx);
            }
        }
    }

    /// The 8237 status register, for a guest waiting on terminal count.
    ///
    /// Forwarded verbatim. Passthrough means the real chip answers: the guest
    /// programmed a transfer that the real controller is running, so the TC
    /// and request bits it latched ARE the answer, and reading clears them on
    /// both sides at once — which is the semantics the guest expects anyway.
    ///
    /// Deliberately no translation. The card is restrapped to BLASTER's own
    /// channels at boot (`sb16::restrap`), so the guest's channel numbering
    /// and the card's are the same numbering; re-mapping bits between them
    /// would be inventing a difference that isn't there. Only the ADDRESS
    /// registers need our intervention, because the guest's buffer is
    /// COW-relocated and the real chip must be pointed at the alias.
    ///
    /// The virtual controller used to answer a hardcoded 0 here — a value
    /// that never arrives. A driver waiting on TC rather than the completion
    /// IRQ spins forever; SBTEST does exactly that.
    pub fn tc_status<A: crate::Core>(&mut self, machine: &mut A, hi: bool) -> u8 {
        machine.inb(if hi { 0xD0 } else { 0x08 })
    }


    /// Alias the guest buffer at `gpa` onto host DMA channel `host`'s
    /// permanent buffer and program the real 8237. Driven from
    /// `maybe_remap` (a guest port write) and `resume` (replaying the
    /// virtual-8237 state after a task switch).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn arm<A: crate::Core>(&mut self, machine: &mut A,
           chan: usize, host: usize, is16: bool,
           gpa: u32, len: u32, mode: u8) -> bool {
        let bufpage = self.card.dma_page(host);
        if bufpage == 0 { return false; }        // no reserved buffer
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
            return true;
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
            if win_pgoff as usize + num_pages > buf_pages { return false; }
            let span = num_pages * 0x1000;
            // Snapshot the guest's pre-filled content — whole pages, so the
            // unrelated neighbour bytes on partial end pages survive.
            let mut snap = alloc::vec![0u8; span];
            machine.copy_from(vbase as u64, &mut snap);
            // Free the guest's original frames, then alias the range onto
            // the channel buffer with CACHE_DISABLE — externally owned, so
            // COW-fork and address-space teardown both leave it intact.
            crate::kernel::memory::reset(machine, vbase >> 12, num_pages);
            crate::kernel::memory::map_physical(machine,
                vbase >> 12, num_pages, bufpage + win_pgoff, PTE_CACHE_DISABLE);
            machine.copy_to(vbase as u64, &snap);
            self.bound_chan  = chan as u8;
            self.bound_host  = host as u8;
            self.bound_gpa   = gpa;
            self.bound_len   = len;
            self.bound_vpage = vbase >> 12;
            self.bound_pages = num_pages;
        }

        program_real_8237(machine, host as u8, phys, len, mode, is16);
        // Armed: the real 8257 is now authoritative for this channel's
        // live addr/count reads.
        true
    }

    /// Detach the current alias: hand the guest's buffer range fresh
    /// anonymous frames and copy the channel buffer's content back into
    /// them, so the partial-end-page neighbour data survives and the guest
    /// can reuse the linear range. The channel buffer is permanent. No-op
    /// when nothing is bound.
    pub fn unbind<A: crate::Core>(&mut self, machine: &mut A) {
        if self.bound_gpa == 0 { return; }
        let vbase = self.bound_vpage << 12;
        let span  = self.bound_pages * 0x1000;
        let mut snap = alloc::vec![0u8; span];
        machine.copy_from(vbase as u64, &mut snap);
        crate::kernel::memory::fresh(machine,
            self.bound_vpage, self.bound_pages);
        machine.copy_to(vbase as u64, &snap);
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
    pub fn suspend<A: crate::Core>(&mut self, machine: &mut A) {
        if self.bound_gpa == 0 { return; }
        mask_real_8237(machine, self.bound_host);
        self.unbind(machine);
        self.suspended = true;
    }
}

/// Mask host DMA channel `chan` on the real 8237 — stops the card pulling
/// the channel buffer while the owning task is backgrounded.
fn mask_real_8237<A: crate::Core>(machine: &mut A, chan: u8) {
    if (4..8).contains(&chan) { machine.outb(0xD4, 0x04 | (chan - 4)); }
    else if chan < 4 { machine.outb(0x0A, 0x04 | chan); }
}

/// Read the real (QEMU) 8237's live current-count for host channel
/// `host`. Standard sequence: clear the byte-pointer flip-flop, read
/// low then high. QEMU's 8257 decrements this as QEMU-sb16 actually
/// consumes the buffer, so it's exact for both progress and (terminal-
/// count) completion. Channel-native units (bytes for 0-3, words 5-7),
/// matching what the guest programmed.
pub fn real_8237_count<A: crate::Core>(machine: &mut A, host: u8) -> u16 {
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
fn program_real_8237<A: crate::Core>(machine: &mut A, chan: u8, phys: u32, len: u32, mode: u8, is16: bool) {
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
