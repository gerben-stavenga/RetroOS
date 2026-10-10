//! The machine's MPU-401 / General MIDI device.
//!
//! Two library cards behind one port pair: [`sound::mpu401::Mpu401`] is the
//! wire (UART mode at `P<port>`, 0x330 by convention) and
//! [`sound::midi::Synth`] is the sound generator. The instruments are NOT
//! this device's problem: a GM device is a ROM-bank instrument, and the ROM
//! is burned once at boot by whoever owns boot assets and handed to this
//! device with the rest of its wiring — the synth here just references it,
//! fully resident from its first byte. A boot with no bank leaves the port
//! present and the device silent, like a module with its ROM socket empty.

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
    /// MT-32 stream detection and translation for pre-GM games: watches the
    /// SysEx addressee and, when the guest is talking to an MT-32, remaps
    /// its programs/pan/key-shifts to their GM approximations before the
    /// bytes reach the synth. GM streams pass through untouched.
    mt32: alloc::boxed::Box<sound::mt32::Mt32Filter>,
    /// The ROM in the socket, handed in with the rest of this program's
    /// wiring (see [`Mpu::configure_from_env`]). A device does not go
    /// looking for its own ROM: the bank is burned once at boot by whoever
    /// owns boot assets, and arrives here as a value like the port number
    /// does. `None` is an empty socket — the port still answers, silently.
    bank: Option<&'static sound::midi::Bank>,
}

impl Mpu {
    pub fn new() -> Self {
        Mpu {
            present: false,
            base: 0x330,
            card: sound::mpu401::Mpu401::new(0x330),
            synth: None,
            mt32: alloc::boxed::Box::new(sound::mt32::Mt32Filter::new()),
            bank: None,
        }
    }

    /// Ports this device decodes, once the machine says it exists.
    ///
    /// The caller decides whether this software device or the physical MPU
    /// receives a port access. Native SB can keep its DSP and FM hardware
    /// while MIDI is separately routed to this device for HDA playback.
    pub fn owns(&self, p: u16) -> bool {
        self.present && self.card.owns(p)
    }

    /// Apply the guest's environment: the MPU port comes from `BLASTER`'s
    /// `P<port>` token (our RETROOS.INI ships `P330`).
    pub fn configure_from_env(&mut self, env: &[u8], bank: Option<&'static sound::midi::Bank>) {
        self.bank = bank;
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
            crate::compact_dbg_println!("[mpu] MPU-401 at {:03X}", self.base);
        }
    }

    /// Program-exit cleanup: drop the synth (voices, wire state) so the next
    /// program starts from a power-on device. The ROM, being ROM, stays.
    pub fn reset(&mut self) {
        self.card.reset();
        self.synth = None;
        self.mt32.reset();
        self.present = false;
    }

    /// Begin intercepting an already-running game's MIDI stream. Its UART
    /// handshake may have gone to the physical MPU before the route changed.
    /// Start with fresh instruments/voices and accept subsequent data bytes.
    pub fn start_software_route(&mut self) {
        if !self.present { return; }
        self.card.reset();
        self.card.port_out(self.base + 1, 0x3f);
        let _ = self.card.port_in(self.base); // discard our synthetic UART ACK
        self.synth = None;
        self.mt32.reset();
    }

    pub fn stop_software_route(&mut self) {
        self.card.reset();
        self.synth = None;
        self.mt32.reset();
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
            // Native-SB programs may have been created before OSD transferred
            // the card to the kernel mixer.  Their original configuration
            // deliberately had no bank reference; resolve it now so the
            // already-running MPU becomes audible immediately after the
            // handoff.
            let Some(bank) = self.bank.or_else(crate::kernel::midi_bank::get) else { return };
            self.bank = Some(bank);
            let mut s = sound::midi::Synth::new_boxed(bank);
            s.init();
            self.synth = Some(s);
        }
        while let Some(b) = self.card.take() {
            if let Some(s) = self.synth.as_mut() {
                for &out in self.mt32.push(b) {
                    s.write_at(arrival_frame, out);
                }
            }
        }
        if let Some(note) = self.mt32.take_latch_note() {
            crate::compact_dbg_println!("[mpu] {}", note);
        }
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
