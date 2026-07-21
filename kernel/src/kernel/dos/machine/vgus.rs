//! The machine's Gravis UltraSound: everything a GF1 needs that is *not* the
//! chip. The chip itself is [`sound::gus::Gf1`] — a passive state machine in
//! `//lib:sound` with no idea what a vPIC, an 8237 or a guest address is.
//!
//! What lives here is exactly the part that could not go with it:
//!
//!  - **presence and wiring.** The guest's `ULTRASND=<base>,<dma>,<rdma>,
//!    <irq>,<midi irq>` env var, the exact contract real drivers use; without
//!    it the device stays absent (`owns` never claims a port).
//!  - **the DMA cycle.** The chip says an upload is armed; this file decodes
//!    the virtual 8237 the guest programmed, fetches the bytes out of guest
//!    memory, and hands them over. The chip never learns the address.
//!  - **the interrupt line.** The chip says it wants service; this file
//!    latches that into the vPIC, and drops a pending request when the card
//!    goes away.
//!  - **the clock**, read once per tick and passed down.
//!  - **diagnostics**, which own mutable statics a library card must not.

use super::*;

/// Always-present, tiny per-thread GUS state: the ULTRASND wiring, plus the
/// chip. Mirrors `SoundBlaster`'s shape — config outside, heavy state behind
/// an `Option` inside the card (a program that never probes pays nothing).
pub struct Gus {
    pub base: u16,   // ULTRASND port base (0x2X0; the GF1 block is base+0x100)
    pub irq: u8,     // ULTRASND GF1 IRQ (wave/ramp/DMA-TC/timers)
    pub dma_ch: u8,  // ULTRASND play DMA channel (sample upload)
    /// `ULTRASND=` seen in this program's env — the device exists. Absent
    /// hardware must stay absent: `owns` gates on this, so probes read 0xFF.
    pub present: bool,
    card: sound::gus::Gf1,
}

impl Gus {
    /// Absent until the program's env declares it (ULTRASND).
    pub fn new() -> Self {
        Gus {
            base: 0x240,
            irq: 5,
            dma_ch: 3,
            present: false,
            card: sound::gus::Gf1::new(0x240),
        }
    }

    /// Ports this card decodes, once the machine says it exists at all.
    pub fn owns(&self, p: u16) -> bool {
        self.present && self.card.owns(p)
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
        self.card.set_base(self.base);
        // One line per program launch: which wiring this program's GUS got.
        // The counterpart of DMX's own "GUS1/GUS2 vs ain't responding" —
        // together they answer every "why is there no GUS music" report.
        crate::dbg_println!(
            "[gus] ULTRASND base={:03X} irq={} dma={}",
            self.base, self.irq, self.dma_ch
        );
    }

    /// Program-exit / exec cleanup: drop the whole chip so the next program
    /// sees a power-on card (same lifecycle as the SB's `release_dma_pool`
    /// and the per-program OPL chip).
    pub fn reset<A: crate::Arch>(&mut self, machine: &mut A, vpic: &mut VirtualPic) {
        let _ = machine; // stream lifecycle is the mixer pump's (it parks on idle)
        // Lower the GF1 line as well as dropping the chip. A voice/timer event
        // may already have latched the IRQ in the vPIC's IRR; dropping the card
        // does not unlatch it, so it stays pending and is delivered AFTER the
        // owning program is gone — straight through the interrupt vector that
        // program installed, into memory that has since been freed and reused.
        // That is a #UD on garbage (Hocus Pocus's GUS IRQ killing the shell
        // after HOCUSG.BAT finished). A card that no longer exists must not
        // still be asking for service.
        vpic.clear_request(self.irq);
        self.card.power_off();
        self.present = false;
    }

    /// Latch the chip's service request into the vPIC. The GF1 line is
    /// edge-triggered into the 8259, so a request that is already pending
    /// coalesces — exactly as it does on hardware.
    fn raise_if_wanted(&mut self, vpic: &mut super::vpic::VirtualPic) {
        if self.card.take_irq() && !vpic.is_requested(self.irq) {
            vpic.raise(self.irq);
        }
    }

    /// Voice-boundary IRQs latched while mixing. `mix_into` cannot reach the
    /// vPIC (it may run a pipe-depth ahead of the speaker, so raising there
    /// would deliver early); this runs from the device tick and asserts.
    pub fn deliver_events(&mut self, vpic: &mut super::vpic::VirtualPic) {
        self.raise_if_wanted(vpic);
    }

    /// Per-quantum device tick, from `machine::audio_tick`: hand the chip the
    /// clock for its rate timers, then assert the line if it asks. Playback
    /// runs through the mixer pump (the common PCM-source path).
    pub fn tick<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        vpic: &mut super::vpic::VirtualPic,
    ) {
        self.card.tick(machine.get_ticks());
        self.raise_if_wanted(vpic);
    }

    /// Guest IN from a decoded port.
    pub fn io_read<A: crate::Arch>(&mut self, machine: &mut A, p: u16) -> u8 {
        let _ = machine;
        let v = self.card.port_in(p);
        let (reg, voice) = self.card.sel();
        if super::PORT_TRACE {
            crate::dbg_println!("[gus] in  {:03X} -> {:02X} (reg {:02X}v{})", p, v, reg, voice);
        }
        gus_ring_record(false, p, v, reg, voice);
        v
    }

    /// Guest OUT to a decoded port.
    pub fn io_write<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237, p: u16, val: u8) {
        let (reg, voice) = self.card.sel();
        if super::PORT_TRACE {
            crate::dbg_println!("[gus] out {:03X} <- {:02X} (reg {:02X}v{})", p, val, reg, voice);
        }
        gus_ring_record(true, p, val, reg, voice);
        self.card.port_out(p, val);
        // A completed reg-0x41 write with the enable bit arms an upload; it
        // is serviced here, where the machine and the 8237 live.
        if self.card.dma_armed() {
            self.service_dma(machine, dma);
        }
    }

    /// Perform the DMA cycle the chip is waiting on: read the guest buffer
    /// the virtual 8237 was programmed with and hand it over.
    ///
    /// This is the whole of what the card cannot do for itself. Everything
    /// spatial is decided here — which channel it sits on (its ULTRASND
    /// strapping, not a chip register), whether that is a 16-bit word channel,
    /// and what guest-physical address the controller holds. The chip supplies
    /// the destination and the sample transforms, and counts what it received.
    ///
    /// We move the transfer in one go and declare terminal count with it: a
    /// GF1 upload is bounded and the driver waits for TC anyway. A host that
    /// wanted per-DRQ granularity would loop here with `tc` false until the
    /// last chunk — the card does not care which.
    fn service_dma<A: crate::Arch>(&mut self, machine: &mut A, dma: &Dma8237) {
        let ch = self.dma_ch as usize;
        if ch >= 8 {
            self.card.dma_write(&[], true); // nowhere to read from; complete it
            return;
        }
        if !self.card.dma_to_card() {
            self.card.dma_write(&[], true); // DRAM→host: completes without data
            return;
        }
        let (gpa, len) = chan_gpa_len(&dma.ch[ch].prog, /*is16=*/ ch >= 4);
        let mut buf = alloc::vec![0u8; len as usize];
        machine.copy_from(gpa as usize, &mut buf);
        self.card.dma_write(&buf, true);
    }
}

/// The GUS as a PCM source for the mixer pump.
impl Gus {
    pub(super) fn mixing(&self) -> bool {
        self.present && self.card.mixing()
    }

    /// Sum wavetable output into the pump block. The scale is *mix policy*
    /// (see `vsb`'s balance constants), so it is applied here rather than in
    /// the chip: the GF1's output is the mixer's reference level — 86Box
    /// `gus_get_buffer` adds it straight in — and the GUS has no guest master
    /// volume, the per-voice ramps already carry it.
    pub(super) fn mix_into<A: crate::Arch>(
        &mut self,
        _machine: &mut A,
        rate: u32,
        _base: u64,
        block: &mut [(i32, i32)],
    ) {
        let g = super::vsb::GUS_SCALE_Q16;
        self.card.mix_into(rate, (g, g), block);
    }
}

// ── Zero-perturbation GUS-access trace ring ──────────────────────────────
// One entry per decoded GUS port IN/OUT, written inline (pure stores, no I/O,
// no formatting) so it doesn't change instruction timing — the same idiom the
// virtual-IF ring (`mode_transitions::IF_RING`) uses, and for the same reason:
// the Duke3D "wedged in the GUS music ISR" hang is timing-sensitive and
// print-tracing (PORT_TRACE) hides it. Dumped only on the F12 state key via
// `dump_gus_ring()`, alongside the IF ring.
//
// This is also why the ring stayed behind when the chip moved to `//lib:sound`:
// it is a pile of mutable statics, which a card meant to be instantiated by
// anyone must not own.
#[derive(Clone, Copy)]
struct GusEvt {
    write: bool,     // true = OUT, false = IN
    in_irq: bool,    // true = recorded while servicing a HW IRQ (ISR context)
    port: u16,
    val: u8,
    reg_sel: u8,     // selected GF1 register at access time
    voice_sel: u8,   // selected voice at access time
}

const GUS_RING_LEN: usize = 128;
static mut GUS_RING: [GusEvt; GUS_RING_LEN] = [GusEvt {
    write: false, in_irq: false, port: 0, val: 0, reg_sel: 0, voice_sel: 0,
}; GUS_RING_LEN];
static mut GUS_RING_POS: usize = 0;

#[inline]
fn gus_ring_record(write: bool, port: u16, val: u8, reg_sel: u8, voice_sel: u8) {
    let in_irq = super::super::IN_HW_IRQ_CONTEXT
        .load(core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let i = GUS_RING_POS % GUS_RING_LEN;
        GUS_RING[i] = GusEvt { write, in_irq, port, val, reg_sel, voice_sel };
        GUS_RING_POS = GUS_RING_POS.wrapping_add(1);
    }
}

/// F12 hook: dump the most recent GUS port accesses (oldest first). A stuck
/// GUS ISR shows up as a short cycle of the same (port, reg) repeating with
/// `irq=1`; an IRQ storm shows the same ISR-drain prologue re-appearing over
/// and over. `total` is the lifetime access count.
pub fn dump_gus_ring() {
    unsafe {
        let pos = GUS_RING_POS;
        let n = pos.min(GUS_RING_LEN);
        crate::dbg_println!("[GUSRING] {} accesses total, showing last {}", pos, n);
        for k in 0..n {
            let i = (pos - n + k) % GUS_RING_LEN;
            let e = GUS_RING[i];
            crate::dbg_println!(
                "[GUSRING] #{:03} {} {:03X} {}={:02X} reg={:02X} v={:02X} irq={}",
                pos - n + k, if e.write { "OUT" } else { "IN " }, e.port,
                if e.write { "val" } else { "->" }, e.val, e.reg_sel, e.voice_sel,
                e.in_irq as u8);
        }
    }
}
