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

const MPU_EVENT_QUEUE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpuEvent {
    DataWrite(u8),
    CommandWrite(u8),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MpuStats {
    pub queue_depth: usize,
    pub queue_high_water: usize,
    pub queue_overflows: u64,
    pub data_writes: u64,
    pub command_writes: u64,
    pub events_consumed: u64,
    pub midi_bytes_accepted: u64,
    pub midi_bytes_ignored: u64,
    pub max_event_age_micros: u64,
    pub frames_rendered: u64,
}

pub struct Mpu {
    /// `BLASTER=... P<port>` declared an MPU-401. Absent hardware stays
    /// absent: `owns` gates on this, so probes read floating.
    pub present: bool,
    pub base: u16,
    card: sound::mpu401::Mpu401,
    events: alloc::boxed::Box<sound::event_queue::FixedEventQueue<
        sound::timeline::TimedEvent<MpuEvent>, MPU_EVENT_QUEUE>>,
    replay_uart: bool,
    rate: u32,
    /// Persistent MIDI synthesis state for the DOS personality. It is built
    /// before guest execution/audio servicing, not on the first MIDI byte.
    synth: Option<alloc::boxed::Box<sound::midi::Synth>>,
    /// The ROM in the socket, handed in with the rest of this program's
    /// wiring (see [`Mpu::configure_from_env`]). A device does not go
    /// looking for its own ROM: the bank is burned once at boot by whoever
    /// owns boot assets, and arrives here as a value like the port number
    /// does. `None` is an empty socket — the port still answers, silently.
    bank: Option<&'static sound::midi::Bank>,
    stats: MpuStats,
}

impl Mpu {
    pub fn new() -> Self {
        Mpu {
            present: false,
            base: 0x330,
            card: sound::mpu401::Mpu401::new(0x330),
            events: sound::event_queue::FixedEventQueue::new_boxed(),
            replay_uart: false,
            rate: 44_100,
            synth: None,
            bank: None,
            stats: MpuStats::default(),
        }
    }

    /// Ports this device decodes, once the machine says it exists.
    ///
    /// Whether it decodes at all is not ours to answer: a guest holding the
    /// real Sound Blaster is driving real silicon, and whatever answers at
    /// the declared MPU port — an MPU-401, a wavetable daughterboard, an
    /// external module — is the owner's hardware, not ours to intercept.
    /// (Our synth could not sound anyway: native burns no GM bank.) So the
    /// caller, which holds the SB device and can therefore see which it is,
    /// decides; this only answers the address question.
    pub fn owns(&self, p: u16) -> bool {
        self.present && self.card.owns(p)
    }

    /// Apply the guest's environment: the MPU port comes from `BLASTER`'s
    /// `P<port>` token (our CONFIG.SYS ships `P330`).
    pub fn configure_from_env(&mut self, env: &[u8], bank: Option<&'static sound::midi::Bank>) {
        self.bank = bank;
        if self.synth.is_none() && let Some(bank) = self.bank {
            let mut synth = sound::midi::Synth::new_boxed(bank);
            synth.init();
            self.synth = Some(synth);
        }
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
        self.events.clear();
        self.replay_uart = false;
        self.rate = 44_100;
        self.synth = None;
        self.present = false;
    }

    pub fn stats(&self) -> MpuStats {
        MpuStats {
            queue_depth: self.events.len(),
            queue_high_water: self.events.high_water(),
            queue_overflows: self.events.overflows(),
            ..self.stats
        }
    }

    pub fn io_read(&mut self, p: u16) -> u8 {
        self.card.port_in(p)
    }

    pub fn io_write(&mut self, p: u16, val: u8, at: sound::timeline::AudioTime) {
        self.card.port_out(p, val);
        let event = if p == self.base {
            self.stats.data_writes += 1;
            MpuEvent::DataWrite(val)
        } else {
            self.stats.command_writes += 1;
            MpuEvent::CommandWrite(val)
        };
        if self.events.push(sound::timeline::TimedEvent { at, event }).is_err() {
            crate::dbg_println!("audio: MPU event queue overflow");
        }
    }

    /// Deterministic service: replay all timestamped MIDI operations visible
    /// at the current architecture-provided audio time.
    /// `arrival_frame` is the mix-frame the bytes arrived at — the synth
    /// applies each at that frame.
    pub fn service<A: crate::Arch>(&mut self, machine: &mut A, arrival_frame: u64) {
        if !self.present {
            return;
        }
        let now = sound::timeline::AudioTime::from_micros(machine.audio_time_micros());
        while let Some(timed) = self.events.pop_through(now) {
            self.stats.events_consumed += 1;
            self.stats.max_event_age_micros = self.stats.max_event_age_micros.max(
                now.saturating_duration_since(timed.at),
            );
            match timed.event {
                MpuEvent::CommandWrite(0xFF) => self.replay_uart = false,
                MpuEvent::CommandWrite(0x3F) => self.replay_uart = true,
                MpuEvent::CommandWrite(_) => {}
                MpuEvent::DataWrite(b) if self.replay_uart => {
                    self.stats.midi_bytes_accepted += 1;
                    let elapsed = now.saturating_duration_since(timed.at);
                    let late_frames = elapsed.saturating_mul(u64::from(self.rate)) / 1_000_000;
                    let frame = arrival_frame.saturating_sub(late_frames);
                    if let Some(s) = self.synth.as_mut() {
                        s.write_at(frame, b);
                    }
                }
                MpuEvent::DataWrite(_) => {
                    self.stats.midi_bytes_ignored += 1;
                }
            }
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
            self.rate = rate;
            self.stats.frames_rendered = self.stats.frames_rendered
                .saturating_add(block.len() as u64);
            s.mix_into(rate, base, (g, g), block);
        }
    }
}

impl Default for Mpu {
    fn default() -> Self {
        Self::new()
    }
}
