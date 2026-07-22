//! General MIDI synthesis over the wavetable engine.
//!
//! A MIDI byte stream in, PCM out. This is the synth half of a "Roland" /
//! General MIDI device — the MPU-401 in [`mpu401`](crate::mpu401) is the wire
//! it arrives on, and the two are deliberately separate: the port protocol and
//! the sound generator have nothing to say to each other beyond bytes.
//!
//! Instruments come from Gravis `.PAT` files ([`pat`](crate::pat)) — the bank
//! already on `C:\ULTRASND\MIDI`. Because that is the GF1's own format and the
//! engine is the GF1's own voice model, a note is almost a straight
//! translation: pick the sample covering the note's pitch, set the voice's
//! increment from the pitch ratio, and drive the patch's six-stage envelope
//! through the engine's ramp generator.
//!
//! **Passive, so it cannot load its own patches.** A file lives behind a
//! filesystem, which a card in this crate has no business knowing about. When
//! a program change or a drum note needs an instrument that is not resident,
//! the synth records the want; the host drains
//! [`take_patch_request`](Synth::take_patch_request), resolves it to a file
//! through [`patch_stem`], reads it, and hands the bytes back to
//! [`load_patch`](Synth::load_patch). Until then the note simply does not
//! sound — the same thing a real GUS does when its DRAM lacks the instrument.

use crate::pat::Patch;
use crate::{Engine, Events, LoopMode, MAX_VOICES, volume};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// General MIDI melodic programs 0-127 → `dgguspat` patch file stems.
const MELODIC: [&str; 128] = [
    "acpiano", "britepno", "synpiano", "honky",
    "epiano1", "epiano2", "hrpschrd", "clavinet",
    "celeste", "glocken", "musicbox", "vibes",
    "marimba", "xylophon", "tubebell", "santur",
    "homeorg", "percorg", "rockorg", "church",
    "reedorg", "accordn", "harmonca", "concrtna",
    "nyguitar", "acguitar", "jazzgtr", "cleangtr",
    "mutegtr", "odguitar", "distgtr", "gtrharm",
    "acbass", "fngrbass", "pickbass", "fretless",
    "slapbas1", "slapbas2", "synbass1", "synbass2",
    "violin", "viola", "cello", "contraba",
    "tremstr", "pizzcato", "harp", "timpani",
    "marcato", "slowstr", "synstr1", "synstr2",
    "choir", "doo", "voices", "orchhit",
    "trumpet", "trombone", "tuba", "mutetrum",
    "frenchrn", "hitbrass", "synbras1", "synbras2",
    "sprnosax", "altosax", "tenorsax", "barisax",
    "oboe", "englhorn", "bassoon", "clarinet",
    "piccolo", "flute", "recorder", "woodflut",
    "bottle", "shakazul", "whistle", "ocarina",
    "sqrwave", "sawwave", "calliope", "chiflead",
    "charang", "voxlead", "lead5th", "basslead",
    "fantasia", "warmpad", "polysyn", "ghostie",
    "bowglass", "metalpad", "halopad", "sweeper",
    "aurora", "soundtrk", "crystal", "atmosphr",
    "freshair", "unicorn", "echovox", "startrak",
    "sitar", "banjo", "shamisen", "koto",
    "kalimba", "bagpipes", "fiddle", "shannai",
    "carillon", "agogo", "steeldrm", "woodblk",
    "taiko", "toms", "syntom", "revcym",
    "fx-fret", "fx-blow", "seashore", "jungle",
    "telephon", "helicptr", "applause", "pistol",
];

/// Lowest percussion key the bank covers.
const PERC_LO: u8 = 27;

/// GM percussion: key number → patch stem, for notes 27..=87 on channel 10.
/// Patch ids are `128 + note`, the Gravis convention `ULTRAMID.INI` uses.
const PERCUSSION: [&str; 61] = [
    "highq", "slap", "scratch1", "scratch2",
    "sticks", "sqrclick", "metclick", "metbell",
    "kick1", "kick2", "stickrim", "snare1",
    "claps", "snare2", "tomlo2", "hihatcl",
    "tomlo1", "hihatpd", "tommid2", "hihatop",
    "tommid1", "tomhi2", "cymcrsh1", "tomhi1",
    "cymride1", "cymchina", "cymbell", "tamborin",
    "cymsplsh", "cowbell", "cymcrsh2", "vibslap",
    "cymride2", "bongohi", "bongolo", "congahi1",
    "congahi2", "congalo", "timbaleh", "timbalel",
    "agogohi", "agogolo", "cabasa", "maracas",
    "whistle1", "whistle2", "guiro1", "guiro2",
    "clave", "woodblk1", "woodblk2", "cuica1",
    "cuica2", "triangl1", "triangl2", "shaker",
    "jingles", "belltree", "castinet", "surdo1",
    "surdo2",
];

/// The percussion channel, 0-based (MIDI "channel 10").
const DRUM_CH: u8 = 9;

/// Patch slots: 0-127 melodic programs, 128+key percussion.
const PATCH_SLOTS: usize = 128 + 128;

/// File stem for a patch id (`0..128` melodic, `128+key` percussion), or
/// `None` when the bank has nothing for it. The host turns this into a path —
/// `C:\ULTRASND\MIDI\<stem>.PAT` for the shipped `dgguspat` set.
pub fn patch_stem(id: u16) -> Option<&'static str> {
    if id < 128 {
        return Some(MELODIC[id as usize]);
    }
    let key = (id - 128) as u8;
    let i = key.checked_sub(PERC_LO)? as usize;
    PERCUSSION.get(i).copied()
}

/// MIDI note → frequency in milliHertz, equal temperament, A4 = 440 Hz.
///
/// Integer-only (the kernel is float-free), from a one-octave table scaled by
/// octave. Values are milliHertz for C-1..B-1 (MIDI 0..11).
fn note_hz_milli(note: u8, cents: i32) -> u32 {
    const OCT0: [u32; 12] = [
        8_176, 8_662, 9_177, 9_723, 10_301, 10_913,
        11_562, 12_250, 12_978, 13_750, 14_568, 15_434,
    ];
    let n = note.min(127) as usize;
    let base = OCT0[n % 12];
    let oct = (n / 12) as u32;
    let mut hz = base << oct;
    if cents != 0 {
        // 2^(c/1200) ≈ 1 + c·0.0005946 for small c; a pitch bend of ±2
        // semitones is ±200 cents, where the linear term is within ~2 cents.
        // Good enough for bend, and it costs no float or table.
        let d = (hz as i64 * cents as i64 * 5_946) / 10_000_000;
        hz = (hz as i64 + d).clamp(1, u32::MAX as i64) as u32;
    }
    hz
}

/// Per-channel MIDI controller state.
#[derive(Clone, Copy)]
struct Channel {
    program: u8,
    /// CC7 volume and CC11 expression, 0-127.
    volume: u8,
    expression: u8,
    /// CC10 pan, 0-127 (64 = centre).
    pan: u8,
    /// Pitch bend in cents, from the 14-bit wheel and the RPN0 range.
    bend_cents: i32,
    bend_range_semitones: u8,
    /// CC64 sustain pedal: note-offs are deferred while held.
    sustain: bool,
    /// RPN selection, for the pitch-bend-range dance.
    rpn: u16,
}

impl Channel {
    const fn new() -> Self {
        Channel {
            program: 0,
            volume: 100,
            expression: 127,
            pan: 64,
            bend_cents: 0,
            bend_range_semitones: 2,
            sustain: false,
            rpn: 0x3FFF,
        }
    }
}

/// What a sounding engine voice is playing, so note-off can find it.
#[derive(Clone, Copy, Default)]
struct Note {
    active: bool,
    channel: u8,
    key: u8,
    /// Note-off arrived but the sustain pedal is holding it.
    held: bool,
    /// Envelope stage 0-5, and the patch/sample driving it.
    stage: u8,
    patch: u16,
    sample: u8,
    /// Monotonic counter at note-on, for voice stealing (oldest first).
    age: u64,
    /// Velocity × channel volume × expression, in the ramp domain, so an
    /// envelope stage can scale against it.
    peak: i32,
}

/// A resident instrument. Its sample addresses are already relocated to the
/// shared pool, so only the parsed patch is kept.
struct Resident {
    patch: Patch,
}

/// The General MIDI synthesizer.
pub struct Synth {
    engine: Box<Engine>,
    /// One shared sample pool, exactly like the GF1's DRAM: every voice
    /// addresses into this, so the engine mixes from one `&[u8]`.
    pool: Vec<u8>,
    /// Resident instruments by patch id, `None` until the host loads one.
    resident: Vec<Option<Resident>>,
    /// Patch ids wanted but not resident. A small ring: the host drains it
    /// each tick, and a repeat request is harmless.
    wanted: Vec<u16>,
    channels: [Channel; 16],
    notes: [Note; MAX_VOICES],
    /// MIDI running status and the parameter bytes collected for it.
    status: u8,
    args: [u8; 2],
    argc: u8,
    /// Bytes remaining to swallow in a SysEx message.
    in_sysex: bool,
    /// Monotonic note counter for voice stealing.
    clock: u64,
    /// The host's mix rate, needed to turn a pitch into an address increment.
    out_rate: u32,
}

impl Synth {
    /// An empty synth: no instruments, all channels at GM power-on defaults.
    pub fn new_boxed() -> Box<Synth> {
        let mut resident = Vec::new();
        resident.resize_with(PATCH_SLOTS, || None);
        Box::new(Synth {
            engine: Engine::new_boxed(),
            pool: Vec::new(),
            resident,
            wanted: Vec::new(),
            channels: [Channel::new(); 16],
            notes: [Note::default(); MAX_VOICES],
            status: 0,
            args: [0; 2],
            argc: 0,
            in_sysex: false,
            clock: 0,
            out_rate: 44_100,
        })
    }

    /// All 32 engine voices participate; MIDI has no "active voices" register.
    ///
    /// The pool is a flat array, not a GF1 board: without
    /// [`Addressing::Linear`] every instrument past 256 KB aliases onto
    /// another one through the GF1's bank transform, and a song comes out as
    /// the right notes played by the wrong instruments.
    pub fn init(&mut self) {
        self.engine.active = MAX_VOICES as u8;
        self.engine.addressing = crate::Addressing::Linear;
    }

    /// Tell the synth the host's mix rate. Notes started afterwards use it;
    /// sounding notes are retuned so a rate change mid-song does not detune.
    pub fn set_rate(&mut self, rate: u32) {
        if rate == self.out_rate || rate == 0 {
            return;
        }
        self.out_rate = rate;
        for ch in 0..16u8 {
            self.retune_channel(ch);
        }
    }

    // ── patch residency (the host's half) ────────────────────────────────

    /// A patch id the synth needs and does not have, or `None`. The host
    /// resolves it with [`patch_stem`], reads the file, and calls
    /// [`load_patch`](Self::load_patch). Drain until it returns `None`.
    pub fn take_patch_request(&mut self) -> Option<u16> {
        self.wanted.pop()
    }

    /// Install a `.PAT` file's bytes as patch `id`. Ignored if the bytes do
    /// not parse — a corrupt or absent instrument leaves the slot empty and
    /// its notes silent, never a panic.
    ///
    /// Returns whether the patch became resident, so a host can mark a failed
    /// id and stop re-reading a file that will not parse.
    pub fn load_patch(&mut self, id: u16, bytes: &[u8]) -> bool {
        let Some(mut patch) = Patch::parse(bytes) else {
            return false;
        };
        if id as usize >= PATCH_SLOTS {
            return false;
        }
        let base = self.pool.len() as u32;
        patch.relocate(base);
        self.pool.extend_from_slice(&patch.pcm);
        // The PCM now lives in the pool; drop the patch's private copy so a
        // full bank does not hold every instrument twice.
        patch.pcm = Vec::new();
        self.resident[id as usize] = Some(Resident { patch });
        true
    }

    /// Whether patch `id` is resident.
    pub fn has_patch(&self, id: u16) -> bool {
        self.resident
            .get(id as usize)
            .is_some_and(|r| r.is_some())
    }

    /// Note the host could not supply this patch, so we stop asking.
    pub fn deny_patch(&mut self, id: u16) {
        self.wanted.retain(|&w| w != id);
        let _ = id;
    }

    fn want(&mut self, id: u16) {
        if !self.has_patch(id) && !self.wanted.contains(&id) && self.wanted.len() < 16 {
            self.wanted.push(id);
        }
    }

    // ── the MIDI wire ────────────────────────────────────────────────────

    /// Feed one byte of the MIDI stream. Handles running status, ignores
    /// real-time bytes, and swallows SysEx.
    pub fn write(&mut self, b: u8) {
        // System real-time (0xF8..0xFF) may appear anywhere, even inside a
        // SysEx, and never disturbs running status.
        if b >= 0xF8 {
            return;
        }
        if self.in_sysex {
            if b == 0xF7 {
                self.in_sysex = false;
            }
            // A new status byte also terminates a malformed SysEx.
            if b < 0x80 {
                return;
            }
            self.in_sysex = false;
        }
        if b >= 0x80 {
            match b {
                0xF0 => {
                    self.in_sysex = true;
                    self.status = 0;
                    return;
                }
                0xF1..=0xF7 => {
                    // System common: clears running status; none of it
                    // affects synthesis.
                    self.status = 0;
                    return;
                }
                _ => {
                    self.status = b;
                    self.argc = 0;
                    return;
                }
            }
        }
        if self.status == 0 {
            return; // data byte with no status: nothing to do
        }
        let need = match self.status & 0xF0 {
            0xC0 | 0xD0 => 1, // program change, channel pressure
            _ => 2,
        };
        self.args[self.argc as usize] = b;
        self.argc += 1;
        if self.argc < need {
            return;
        }
        self.argc = 0;
        let ch = (self.status & 0x0F) as usize;
        let (a, b2) = (self.args[0], self.args[1]);
        match self.status & 0xF0 {
            0x80 => self.note_off(ch as u8, a),
            0x90 => {
                if b2 == 0 {
                    self.note_off(ch as u8, a) // velocity 0 = note off
                } else {
                    self.note_on(ch as u8, a, b2)
                }
            }
            0xA0 => {} // polyphonic aftertouch: not modelled
            0xB0 => self.control(ch, a, b2),
            0xC0 => {
                self.channels[ch].program = a & 0x7F;
                if ch as u8 != DRUM_CH {
                    let id = (a & 0x7F) as u16;
                    self.want(id);
                }
            }
            0xD0 => {} // channel pressure: not modelled
            0xE0 => {
                let raw = ((b2 as i32) << 7 | a as i32) - 8192;
                let range = self.channels[ch].bend_range_semitones as i32 * 100;
                self.channels[ch].bend_cents = raw * range / 8192;
                self.retune_channel(ch as u8);
            }
            _ => {}
        }
    }

    fn control(&mut self, ch: usize, cc: u8, val: u8) {
        match cc {
            7 => self.channels[ch].volume = val,
            10 => self.channels[ch].pan = val,
            11 => self.channels[ch].expression = val,
            64 => {
                self.channels[ch].sustain = val >= 64;
                if !self.channels[ch].sustain {
                    self.release_held(ch as u8);
                }
            }
            100 => self.channels[ch].rpn = (self.channels[ch].rpn & 0x3F80) | val as u16,
            101 => self.channels[ch].rpn = (self.channels[ch].rpn & 0x7F) | ((val as u16) << 7),
            6 => {
                // Data entry MSB; RPN 0 is pitch-bend range in semitones.
                if self.channels[ch].rpn == 0 {
                    self.channels[ch].bend_range_semitones = val.max(1);
                }
            }
            120 | 123 => {
                // All sound off / all notes off.
                for i in 0..MAX_VOICES {
                    if self.notes[i].active && self.notes[i].channel == ch as u8 {
                        self.begin_release(i);
                    }
                }
            }
            121 => {
                // Reset all controllers. The pedal going away must also let
                // go of whatever it was holding, or those notes never release.
                self.channels[ch] = Channel::new();
                self.release_held(ch as u8);
            }
            _ => {}
        }
    }

    // ── notes ────────────────────────────────────────────────────────────

    /// The patch id a channel's note uses: percussion is keyed by note.
    fn patch_for(&self, ch: u8, key: u8) -> u16 {
        if ch == DRUM_CH {
            128 + key as u16
        } else {
            self.channels[ch as usize].program as u16
        }
    }

    /// Pick a free voice, else steal the oldest sounding one.
    fn alloc_voice(&mut self) -> usize {
        let mut oldest = 0usize;
        let mut oldest_age = u64::MAX;
        for i in 0..MAX_VOICES {
            if !self.notes[i].active && !self.engine.voices[i].running {
                return i;
            }
            if self.notes[i].age < oldest_age {
                oldest_age = self.notes[i].age;
                oldest = i;
            }
        }
        oldest
    }

    fn note_on(&mut self, ch: u8, key: u8, vel: u8) {
        let id = self.patch_for(ch, key);
        if !self.has_patch(id) {
            self.want(id);
            return; // silent until the host supplies it — as a GUS would be
        }
        // A sequencer retriggers a key constantly without always sending the
        // note-off first. Letting both sound leaves the older voice with no
        // note-off that will ever match it — an instrument that never dies.
        self.release_key(ch, key);
        let hz = self.note_hz_for(ch, key);
        let Some(res) = self.resident[id as usize].as_ref() else { return };
        let si = res.patch.select_index(hz);
        let s = res.patch.samples[si];
        let v = self.alloc_voice();
        self.clock += 1;

        let chan = self.channels[ch as usize];
        // Velocity × volume × expression, all 0-127, into the GF1 log volume
        // domain. The engine's ramp works in that domain, so the envelope's
        // own offsets scale against this ceiling.
        let scale = (vel as u32 * chan.volume as u32 * chan.expression as u32) / (127 * 127);
        let peak = volume::log_from_midi(scale.min(127) as u8) << volume::RAMP_FRACT;

        // Pitch: the sample's recorded root maps to its recorded rate; the
        // engine's increment is in Q32.32 frames per output frame.
        let inc = pitch_inc(&s, hz, self.out_rate);
        let (pan_l, pan_r) = pan_gains(if ch == DRUM_CH { s.balance_pan() } else { chan.pan });

        let voice = &mut self.engine.voices[v];
        *voice = crate::Voice {
            running: true,
            bits16: s.bits16,
            addr: s.start,
            inc,
            start: if s.looped { s.loop_start } else { s.start },
            end: if s.looped { s.loop_end } else { s.end },
            loop_mode: if !s.looped {
                LoopMode::None
            } else if s.bidi {
                LoopMode::Bidi
            } else {
                LoopMode::Forward
            },
            backwards: s.reverse,
            irq_on_end: false,
            rollover: false,
            vol: 0,
            ramp: crate::Ramp::default(),
            pan_l,
            pan_r,
            filter: crate::VoiceFilter::default(),
        };
        self.notes[v] = Note {
            active: true,
            channel: ch,
            key,
            held: false,
            stage: 0,
            patch: id,
            sample: si as u8,
            age: self.clock,
            peak,
        };
        self.start_stage(v, 0);
    }

    /// Release every voice sounding `(ch, key)` — *every* one, not the first.
    /// Two voices can share a key when a sequencer retriggers it, and stopping
    /// only one strands the other with no note-off left to match it.
    fn note_off(&mut self, ch: u8, key: u8) {
        for i in 0..MAX_VOICES {
            let n = self.notes[i];
            if n.active && n.channel == ch && n.key == key && !n.held {
                if self.channels[ch as usize].sustain {
                    self.notes[i].held = true;
                } else {
                    self.begin_release(i);
                }
            }
        }
    }

    /// Force every voice on `(ch, key)` into release, ignoring the sustain
    /// pedal — the retrigger path, where the old note must go regardless.
    fn release_key(&mut self, ch: u8, key: u8) {
        for i in 0..MAX_VOICES {
            let n = self.notes[i];
            if n.active && n.channel == ch && n.key == key {
                self.begin_release(i);
            }
        }
    }

    fn release_held(&mut self, ch: u8) {
        for i in 0..MAX_VOICES {
            if self.notes[i].active && self.notes[i].channel == ch && self.notes[i].held {
                self.begin_release(i);
            }
        }
    }

    /// Enter the release stages (3..5 of the GF1 six-stage envelope) and let
    /// the loop run out.
    fn begin_release(&mut self, v: usize) {
        self.notes[v].held = false;
        // A sustaining loop must stop looping once the key is up, or the note
        // never ends.
        self.engine.voices[v].loop_mode = LoopMode::None;
        if self.notes[v].stage < 3 {
            self.notes[v].stage = 3;
            self.start_stage(v, 3);
        }
    }

    /// Program engine ramp for envelope `stage` of the note in voice `v`.
    ///
    /// This is where the `.PAT` envelope meets the engine: `env_rate[stage]`
    /// is a GF1 ramp-rate register and `env_offset[stage]` a ramp bound, so
    /// both go through the same conversions the GF1 front-end uses. Reaching
    /// the bound raises a ramp event, and [`advance`](Self::advance) uses that
    /// to step to the next stage — which is how a six-stage envelope runs on a
    /// one-segment ramp generator.
    fn start_stage(&mut self, v: usize, stage: u8) {
        let n = self.notes[v];
        let Some(res) = self.resident[n.patch as usize].as_ref() else { return };
        let s = res.patch.samples[n.sample as usize];
        if !s.envelope || stage as usize >= 6 {
            // No envelope: play flat at the note's peak.
            self.engine.voices[v].vol = n.peak;
            self.engine.voices[v].ramp.running = false;
            return;
        }
        let target = ramp_bound(s.env_offset[stage as usize], n.peak);
        let cur = self.engine.voices[v].vol;
        let inc = ramp_inc(s.env_rate[stage as usize]);
        let down = target < cur;
        let r = &mut self.engine.voices[v].ramp;
        r.inc = inc.max(1);
        r.down = down;
        r.floor = if down { target } else { 0 };
        r.ceil = if down { n.peak.max(cur) } else { target };
        r.looped = false;
        r.bidi = false;
        r.irq = true; // tell us when the stage completes
        r.running = true;
        self.notes[v].stage = stage;
    }

    fn note_hz_for(&self, ch: u8, key: u8) -> u32 {
        let cents = if ch == DRUM_CH {
            0 // drums do not bend
        } else {
            self.channels[ch as usize].bend_cents
        };
        note_hz_milli(key, cents)
    }

    /// Re-derive every sounding voice's increment on this channel after a
    /// pitch-bend change.
    fn retune_channel(&mut self, ch: u8) {
        for v in 0..MAX_VOICES {
            let n = self.notes[v];
            if !n.active || n.channel != ch {
                continue;
            }
            let hz = self.note_hz_for(ch, n.key);
            let Some(res) = self.resident[n.patch as usize].as_ref() else { continue };
            let s = res.patch.samples[n.sample as usize];
            self.engine.voices[v].inc = pitch_inc(&s, hz, self.out_rate);
        }
    }

    // ── PCM ──────────────────────────────────────────────────────────────

    /// Whether any voice is still sounding.
    pub fn mixing(&self) -> bool {
        self.engine.any_running()
    }

    /// Sum the synth into `block` at the host's mix rate, scaled by `gain`
    /// (Q16). Envelope stages advance on the engine's ramp events, so the
    /// whole six-stage envelope runs inside the mix with no clock.
    pub fn mix_into(&mut self, rate: u32, gain: (i32, i32), block: &mut [(i32, i32)]) {
        // The host's rate is authoritative and can change between sessions;
        // adopting it here means a caller never has to remember to announce it.
        self.set_rate(rate);
        if !self.mixing() {
            return;
        }
        // The bank is recorded at assorted rates; the engine resamples per
        // voice from its increment, so the "native" rate here is just the
        // output rate — one engine step per output frame.
        for slot in block.iter_mut() {
            let mut ev = Events::default();
            let (l, r) = self.engine.mix_frame(&self.pool, self.out_rate, self.out_rate, &mut ev);
            slot.0 += (l * gain.0) >> 16;
            slot.1 += (r * gain.1) >> 16;
            if ev.ramp_irq != 0 {
                self.advance_envelopes(ev.ramp_irq);
            }
        }
    }

    /// A ramp finished on these voices: step each to its next envelope stage,
    /// or stop the note when the release completes.
    fn advance_envelopes(&mut self, mask: u32) {
        for v in 0..MAX_VOICES {
            if mask & (1 << v) == 0 || !self.notes[v].active {
                continue;
            }
            let stage = self.notes[v].stage;
            // Stage 2 is the sustain point: hold there until note-off.
            if stage == 2 {
                self.engine.voices[v].ramp.running = false;
                continue;
            }
            if stage >= 5 {
                // Release complete: the note is done.
                self.engine.voices[v].running = false;
                self.engine.voices[v].ramp.running = false;
                self.notes[v] = Note::default();
                continue;
            }
            self.start_stage(v, stage + 1);
        }
    }
}

/// A `.PAT` ramp-rate register → the engine's per-frame ramp increment. Same
/// conversion the GF1 front-end applies: the 6-bit field steps the volume's
/// 12-bit significand (hence `<< 4`), and bits 7:6 are the 1/8/64/512 update
/// divider, folded in here as a fractional per-frame rate.
fn ramp_inc(rate_reg: u8) -> i32 {
    let per_update = ((rate_reg & 0x3F) as i32) << 4;
    (per_update << volume::RAMP_FRACT) >> (3 * (rate_reg >> 6).min(3) as i32)
}

/// A `.PAT` envelope offset (the volume's top byte) into the ramp domain,
/// attenuated to this note's peak.
///
/// Both are *log* volumes, so scaling gains means **adding** registers, not
/// multiplying them: `env + peak - FULL` attenuates the envelope point by
/// however far the note's peak sits below unity. Multiplying here would
/// compress the envelope's shape instead of moving its level — a quiet note
/// would get a different attack curve, not just a quieter one.
fn ramp_bound(offset: u8, peak: i32) -> i32 {
    let env = (offset as i32) << (8 + volume::RAMP_FRACT);
    (env + peak - (volume::FULL << volume::RAMP_FRACT)).max(0)
}

/// Q32.32 address increment per output frame that plays `s` at `hz_milli`.
///
/// Two ratios: the sample's recorded rate against the output rate (its natural
/// playback speed), times the wanted pitch against the pitch it was recorded
/// at. `mix_frame` is called with `native == out`, i.e. one engine step per
/// output frame, so both fold in here.
///
/// 128-bit intermediate on purpose: `sample_rate × hz_milli` reaches ~5·10¹¹
/// for a top-octave note, and the Q32 shift would overflow u64.
fn pitch_inc(s: &crate::pat::Sample, hz_milli: u32, out_rate: u32) -> u64 {
    let root = s.root_hz_milli.max(1) as u128;
    let out = out_rate.max(1) as u128;
    let num = (s.sample_rate as u128) * (hz_milli as u128) << 32;
    (num / (out * root)).min(u64::MAX as u128) as u64
}

/// GM pan (0-127, 64 centre) → Q12 constant-power stereo gains, the same law
/// the GF1's 16-position table uses.
fn pan_gains(pan: u8) -> (u16, u16) {
    const PAN: [(u16, u16); 16] = [
        (4096, 0), (4070, 459), (3993, 911), (3866, 1353),
        (3690, 1777), (3468, 2179), (3202, 2554), (2896, 2896),
        (2598, 3166), (2276, 3406), (1931, 3612), (1567, 3784),
        (1189, 3920), (799, 4017), (401, 4076), (0, 4096),
    ];
    PAN[(pan >> 3).min(15) as usize]
}

impl crate::pat::Sample {
    /// The patch's own balance byte as a GM-style 0-127 pan (drums are panned
    /// by the instrument, not the channel).
    fn balance_pan(&self) -> u8 {
        (self.balance.min(15) as u16 * 127 / 15) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal one-sample looping patch with an envelope that releases to
    /// silence — enough to exercise note lifecycle without a real bank.
    fn tiny_patch() -> alloc::vec::Vec<u8> {
        const HDR: usize = 129;
        let mut b = alloc::vec![0u8; HDR];
        b[0..12].copy_from_slice(b"GF1PATCH110\0");
        b[85..87].copy_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&alloc::vec![0u8; 63]); // instrument
        b.extend_from_slice(&alloc::vec![0u8; 47]); // layer
        let pcm = alloc::vec![0x20u8; 256];
        let mut s = alloc::vec![0u8; 96];
        s[8..12].copy_from_slice(&(pcm.len() as u32).to_le_bytes());
        s[12..16].copy_from_slice(&0u32.to_le_bytes());
        s[16..20].copy_from_slice(&(pcm.len() as u32).to_le_bytes());
        s[20..22].copy_from_slice(&44100u16.to_le_bytes());
        s[22..26].copy_from_slice(&1u32.to_le_bytes());          // low
        s[26..30].copy_from_slice(&40_000_000u32.to_le_bytes()); // high
        s[30..34].copy_from_slice(&440_000u32.to_le_bytes());    // root
        s[36] = 7;
        s[37..43].copy_from_slice(&[63, 63, 63, 63, 63, 63]); // fast everywhere
        s[43..49].copy_from_slice(&[255, 240, 240, 200, 100, 0]);
        s[55] = 0x04 | 0x40; // looped + envelope
        b.extend_from_slice(&s);
        b.extend_from_slice(&pcm);
        b
    }

    fn synth() -> alloc::boxed::Box<Synth> {
        let mut s = Synth::new_boxed();
        s.init();
        assert!(s.load_patch(0, &tiny_patch()), "fixture must parse");
        s
    }

    /// Run the mix until nothing sounds, or give up. Returns whether it went
    /// quiet, and how many frames it took.
    fn run_until_silent(s: &mut Synth, limit: usize) -> (bool, usize) {
        let mut block = [(0i32, 0i32); 64];
        for i in 0..(limit / 64) {
            if !s.mixing() {
                return (true, i * 64);
            }
            block.fill((0, 0));
            s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
        }
        (!s.mixing(), limit)
    }

    #[test]
    fn a_note_off_stops_the_note() {
        let mut s = synth();
        s.write(0x90);
        s.write(60);
        s.write(100);
        let mut block = [(0i32, 0i32); 64];
        s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
        assert!(s.mixing(), "the note must be sounding");
        s.write(0x80);
        s.write(60);
        s.write(0);
        let (quiet, _) = run_until_silent(&mut s, 44_100 * 4);
        assert!(quiet, "a released note must stop within four seconds");
    }

    /// The bug this test exists for: a sequencer retriggers a key without an
    /// intervening note-off. If note-on allocates a second voice and note-off
    /// only releases the first, the older one is stranded sounding forever.
    #[test]
    fn retriggering_a_key_does_not_strand_the_older_voice() {
        let mut s = synth();
        for _ in 0..4 {
            s.write(0x90);
            s.write(60);
            s.write(100); // same key, no note-off between
        }
        s.write(0x80);
        s.write(60);
        s.write(0);
        let (quiet, _) = run_until_silent(&mut s, 44_100 * 4);
        assert!(quiet, "one note-off must silence every voice on that key");
    }

    /// Velocity-0 note-on is a note-off, and must release just as completely.
    #[test]
    fn velocity_zero_note_on_releases() {
        let mut s = synth();
        s.write(0x90);
        s.write(60);
        s.write(100);
        s.write(0x90); // running status would do this too
        s.write(60);
        s.write(0);
        let (quiet, _) = run_until_silent(&mut s, 44_100 * 4);
        assert!(quiet, "velocity 0 must behave as note-off");
    }

    /// The sustain pedal defers release; letting go must actually let go, and
    /// so must a reset-all-controllers, which is how a stuck pedal strands
    /// every note under it.
    #[test]
    fn sustain_pedal_defers_release_but_never_strands() {
        let mut s = synth();
        s.write(0xB0);
        s.write(64);
        s.write(127); // pedal down
        s.write(0x90);
        s.write(60);
        s.write(100);
        s.write(0x80);
        s.write(60);
        s.write(0);
        let mut block = [(0i32, 0i32); 64];
        s.mix_into(44_100, (1 << 16, 1 << 16), &mut block);
        assert!(s.mixing(), "the pedal must hold the note");
        s.write(0xB0);
        s.write(121);
        s.write(0); // reset all controllers
        let (quiet, _) = run_until_silent(&mut s, 44_100 * 4);
        assert!(quiet, "resetting controllers must release what the pedal held");
    }

    /// All-notes-off must clear everything, on every channel it names.
    #[test]
    fn all_notes_off_silences_the_channel() {
        let mut s = synth();
        for key in 60..72 {
            s.write(0x90);
            s.write(key);
            s.write(100);
        }
        s.write(0xB0);
        s.write(123);
        s.write(0);
        let (quiet, _) = run_until_silent(&mut s, 44_100 * 4);
        assert!(quiet, "all-notes-off must stop every voice");
    }

    #[test]
    fn patch_stems_cover_gm_and_reject_nonsense() {
        assert_eq!(patch_stem(0), Some("acpiano"));
        assert_eq!(patch_stem(127), Some("pistol"));
        // Percussion is 128 + key; 35 = acoustic bass drum, 42 = closed hat.
        assert_eq!(patch_stem(128 + 35), Some("kick1"));
        assert_eq!(patch_stem(128 + 42), Some("hihatcl"));
        // Keys outside the bank's percussion span have no patch.
        assert_eq!(patch_stem(128 + 10), None);
        assert_eq!(patch_stem(128 + 120), None);
    }
}
