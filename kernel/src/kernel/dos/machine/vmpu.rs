//! The machine's MPU-401 / General MIDI device.
//!
//! Two library cards behind one port pair: [`sound::mpu401::Mpu401`] is the
//! wire (UART mode at `P<port>`, 0x330 by convention) and
//! [`sound::midi::Synth`] is the sound generator. The instruments are NOT
//! this device's problem: a GM device is a ROM-bank instrument, and the ROM
//! is burned once at boot by the kernel (`kernel::midi_bank`) — the synth
//! here just references it, fully resident from its first byte. A boot with
//! no bank leaves the port present and the device silent, like a module
//! with its ROM socket empty.

use super::*;

pub struct Mpu {
    /// `BLASTER=... P<port>` declared an MPU-401. Absent hardware stays
    /// absent: `owns` gates on this, so probes read floating.
    pub present: bool,
    pub base: u16,
    card: sound::mpu401::Mpu401,
    /// Built on first use — the synth carries 32 voices and the MIDI wire
    /// state; a program that never opens the port pays nothing. Instruments
    /// come from the boot ROM by reference.
    synth: Option<alloc::boxed::Box<sound::midi::Synth>>,
}

impl Mpu {
    pub fn new() -> Self {
        Mpu {
            present: false,
            base: 0x330,
            card: sound::mpu401::Mpu401::new(0x330),
            synth: None,
        }
    }

    /// Ports this device decodes, once the machine says it exists.
    pub fn owns(&self, p: u16) -> bool {
        self.present && self.card.owns(p)
    }

    /// Apply the guest's environment: the MPU port comes from `BLASTER`'s
    /// `P<port>` token (our CONFIG.SYS ships `P330`).
    pub fn configure_from_env(&mut self, env: &[u8]) {
        let Some(blaster) = env_var(env, b"BLASTER") else { return };
        for tok in blaster.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
            if tok[0].eq_ignore_ascii_case(&b'P')
                && let Some(n) = parse_uint(&tok[1..], 16)
            {
                self.base = n as u16;
                self.card.set_base(self.base);
                self.present = true;
            }
        }
        if self.present {
            crate::dbg_println!("[mpu] MPU-401 at {:03X}", self.base);
        }
    }

    /// Program-exit cleanup: drop the synth (voices, wire state) so the next
    /// program starts from a power-on device. The ROM, being ROM, stays.
    pub fn reset(&mut self) {
        self.card.reset();
        self.synth = None;
        self.present = false;
    }

    pub fn io_read(&mut self, p: u16) -> u8 {
        self.card.port_in(p)
    }

    pub fn io_write(&mut self, p: u16, val: u8) {
        self.card.port_out(p, val);
    }

    /// Per-quantum service: drain the port's MIDI bytes into the synth.
    /// `arrival_frame` is the mix-frame the bytes arrived at — the synth
    /// applies each at that frame.
    pub fn tick<A: crate::Arch>(&mut self, machine: &mut A, arrival_frame: u64) {
        let _ = machine;
        if !self.present {
            return;
        }
        // Only build the synth once the guest actually drives the port —
        // detection alone (reset/ACK) must not cost the voice engine. A
        // bankless boot never builds one: the wire still ACKs (the port
        // exists), but there is nothing to sound.
        if self.synth.is_none() {
            if !self.card.in_uart() {
                return;
            }
            let Some(bank) = crate::kernel::midi_bank::get() else { return };
            let mut s = sound::midi::Synth::new_boxed(bank);
            s.init();
            self.synth = Some(s);
        }
        while let Some(b) = self.card.take() {
            if let Some(s) = self.synth.as_mut() {
                s.write_at(arrival_frame, b);
            }
        }
    }

    /// Whether the synth currently owes the sink audio.
    pub(super) fn mixing(&self) -> bool {
        // Also true while stamped bytes are still queued: they will start notes
        // at a future frame, so the producer must keep the stream running until
        // they are consumed (otherwise production stops before they render).
        self.synth
            .as_ref()
            .is_some_and(|s| s.mixing() || s.has_pending())
    }

    /// Sum the GM synth into the pump block. The scale is mix policy, like
    /// the GUS's, and is *not* the GUS's: the bank is the same, but a GM
    /// sequence drives far more simultaneous voices, so it needs its own
    /// measured level (see `vsb::GM_SCALE_Q16`).
    pub(super) fn mix_into<A: crate::Arch>(
        &mut self,
        _machine: &mut A,
        rate: u32,
        base: u64,
        block: &mut [(i32, i32)],
    ) {
        let g = super::vsb::GM_SCALE_Q16;
        if let Some(s) = self.synth.as_mut() {
            s.mix_into(rate, base, (g, g), block);
        }
    }
}

impl Default for Mpu {
    fn default() -> Self {
        Self::new()
    }
}
