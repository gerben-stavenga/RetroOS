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
//! reached only while holding an [`SbCard`], which is the possession proof.

use super::sb16::SbCard;
use sound::sb::Wiring as Blaster;

/// PTE cache-disable bit (x86 PCD). On RetroOS it doubles as the
/// "externally owned" mark — COW-fork and address-space teardown both
/// skip such frames — exactly what an aliased permanent DMA buffer needs.
/// Arch's `paging2::flags` is private, so the bit is duplicated here per
/// the arch-boundary rule (small primitives are copied, not cross-called).
const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// DSP reset: 1 then 0 to `base+6`, the power-on handshake.
fn dsp_reset<A: crate::Arch>(machine: &mut A, base: u16) {
    machine.outb(base + 0x06, 1);
    machine.outb(base + 0x06, 0);
}

/// One DSP command/data byte, once the write buffer says it is ready.
fn dsp_write<A: crate::Arch>(machine: &mut A, base: u16, byte: u8) {
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
/// one, which is why it sits here and not in [`SbCard`]: handing the card on
/// to the mixer's sink moves `card` out and leaves the binding behind to be
/// torn down.
pub struct NativeSb {
    /// The machine's card, held. Passthrough is total in this variant — there
    /// is no "maybe a card" state to guard, because possession is the
    /// guarantee: this value cannot be copied or conjured, only moved in.
    pub card: SbCard,
    /// Last mixer index the guest selected (`base+0x04`), so `base+0x05`
    /// can answer the wiring registers from the guest's own numbers.
    mixer_idx: u8,
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
    fn new(card: SbCard) -> Self {
        Self {
            card,
            mixer_idx: 0,
            bound_chan: 0xFF, bound_host: 0xFF,
            bound_gpa: 0, bound_len: 0, bound_vpage: 0, bound_pages: 0,
            suspended: false, last_gen: [0; 8],
        }
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
    pub fn adopt<A: crate::Arch>(machine: &mut A, card: SbCard, st: sound::sb::DspState) -> Self {
        let base = card.base;
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
                // bit5 stereo, bit4 signed — 16-bit DMA is always signed.
                dsp_write(machine, base, 0x10 | if st.stereo { 0x20 } else { 0 });
                dsp_write(machine, base, st.block as u8);
                dsp_write(machine, base, (st.block >> 8) as u8);
            } else {
                dsp_write(machine, base, if st.single { 0xC0 } else { 0xC6 });
                dsp_write(machine, base, if st.stereo { 0x20 } else { 0 });
                dsp_write(machine, base, st.block as u8);
                dsp_write(machine, base, (st.block >> 8) as u8);
            }
        }
        crate::compact_dbg_println!(
            "[sb] card taken: {}Hz {}bit {} {} block={} speaker={} playing={}",
            st.rate, st.bits, if st.stereo { "stereo" } else { "mono" },
            if st.single { "single" } else { "auto" }, st.block, st.speaker, st.playing
        );
        Self::new(card)
    }

    /// Give the card back. The caller must have `release`d it first.
    pub fn into_card(self) -> SbCard {
        self.card
    }

    /// The physical card, for the questions only its own straps answer.
    pub fn card(&self) -> &SbCard {
        &self.card
    }

    /// Whether a background suspend detached the alias, so the next swap-in
    /// knows it must replay the guest's channel programming.
    pub fn suspended(&self) -> bool {
        self.suspended
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
    /// Ports inside the DSP window that MUST trap, as a mask of offsets from
    /// `io_base`. Everything else is granted to the guest outright (the IOPB
    /// is per-port), so DSP traffic on a correctly-declared card costs no
    /// exits at all.
    ///
    /// Exactly two things trap, and only one of them is about this card:
    ///
    ///  * the whole window when the card is strapped somewhere other than
    ///    BLASTER's base — every access needs `host_port` translation.
    ///  * mixer index+data (0x04/0x05): ALWAYS. Registers 0x80/0x81 are the
    ///    SB16's soft-straps, and here the card tells the TRUTH while the
    ///    truth is wrong for this guest — it was told other numbers by
    ///    BLASTER, and the machine translates (the vPIC relays the card's
    ///    line onto the guest's, the virtual 8237 remaps its channels). A
    ///    guest that believed the straps would hook a line we never raise, so
    ///    a write there must not reach silicon (`write` drops it) and a read
    ///    reports the guest's own labels (`read`). Mixer traffic is volume
    ///    knobs — cold path, the trap costs nothing.
    ///
    /// Nothing else is synthesized. Compensating for a *host emulator's*
    /// imperfect card (QEMU's sb16 never pulses the write-status busy bit and
    /// does not surface the E4h/E8h test register) used to live here too;
    /// that is 86Box's job now, and QEMU runs the emulated SB over HDA/AC97,
    /// which exercises the software path instead of a second-rate real one.
    pub fn trap_mask(&self, b: &Blaster) -> u16 {
        if self.card.base != b.io_base {
            return 0xFFFF;
        }
        // Mixer index+data, and the two DSP write ports.
        //
        // The DSP window used to be granted outright, which cost no exits and
        // lost every byte that went through it. That was affordable while the
        // card never changed hands; it is not now. `0x0C` carries every
        // command and parameter and `0x06` is the reset that voids them, so
        // these two are exactly what the shadow needs to stay in lockstep —
        // and no more: the DSP READ ports (0x0A/0x0E) stay granted, so status
        // polls and data reads, which are the hot ones in a playback loop,
        // still cost nothing. A driver programs the DSP per block, not per
        // sample.
        (1 << 0x04) | (1 << 0x05) | (1 << 0x06) | (1 << 0x0C)
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
    pub fn release<A: crate::Arch>(&mut self, machine: &mut A, b: &Blaster) {
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
        // Silence what the channels would transfer if anything unmasked them.
        // The buffer still holds this program's last lap — `unbind` copied it
        // back to the guest, it did not clear it — and an auto-init transfer
        // has no LVI gate, so it would simply play again.
        crate::kernel::drivers::sb16::zero_channel_buf(machine, self.card.dma8);
        if let Some(d16) = self.card.dma16 {
            crate::kernel::drivers::sb16::zero_channel_buf(machine, d16);
        }
        self.suspended = false;
        self.last_gen = [0; 8];
    }

    /// Read a DSP/mixer/OPL port off the real card. Only the mixer's strap
    /// registers are answered locally — see `trap_mask`; everything else the
    /// card reports is the card's own truth and passes straight through.
    pub fn read<A: crate::Arch>(&mut self, machine: &mut A, b: &Blaster, p: u16) -> u8 {
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
                _ => {}
            }
        }
        machine.inb(self.host_port(b, p))
    }

    /// Write a DSP/mixer/OPL port through to the real card. Only the mixer
    /// strap pair is filtered (see `trap_mask`); every other byte reaches the
    /// silicon verbatim, because the silicon is the card.
    pub fn write<A: crate::Arch>(&mut self, machine: &mut A, b: &Blaster, p: u16, val: u8) {
        if p == b.io_base + 0x04 {
            self.mixer_idx = val;
        } else if p == b.io_base + 0x05 && matches!(self.mixer_idx, 0x80 | 0x81) {
            // The guest may move ITS view of the wiring — the relay and the
            // remap follow BLASTER — but the physical straps stay where the
            // kernel found them; nothing else on the machine knows they moved.
            // This filter is why the mixer pair is always in `trap_mask`.
            return;
        }
        machine.outb(self.host_port(b, p), val);
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
    pub fn tc_status<A: crate::Arch>(&mut self, machine: &mut A, hi: bool) -> u8 {
        machine.inb(if hi { 0xD0 } else { 0x08 })
    }


    /// Alias the guest buffer at `gpa` onto host DMA channel `host`'s
    /// permanent buffer and program the real 8237. Driven from
    /// `maybe_remap` (a guest port write) and `resume` (replaying the
    /// virtual-8237 state after a task switch).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn arm<A: crate::Arch>(&mut self, machine: &mut A,
           chan: usize, host: usize, is16: bool,
           gpa: u32, len: u32, mode: u8) -> bool {
        let bufpage = machine.dma_channel_buf(host);
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
        // live addr/count reads.
        true
    }

    /// Detach the current alias: hand the guest's buffer range fresh
    /// anonymous frames and copy the channel buffer's content back into
    /// them, so the partial-end-page neighbour data survives and the guest
    /// can reuse the linear range. The channel buffer is permanent. No-op
    /// when nothing is bound.
    pub fn unbind<A: crate::Arch>(&mut self, machine: &mut A) {
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
    pub fn suspend<A: crate::Arch>(&mut self, machine: &mut A) {
        if self.bound_gpa == 0 { return; }
        mask_real_8237(machine, self.bound_host);
        self.unbind(machine);
        self.suspended = true;
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
pub fn real_8237_count<A: crate::Arch>(machine: &mut A, host: u8) -> u16 {
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
