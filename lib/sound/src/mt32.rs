//! MT-32 → General MIDI stream translation.
//!
//! Pre-GM games (Monkey Island, Dune, the Sierra catalogue) drive the
//! MPU-401 expecting a Roland MT-32 behind it: its own 128-preset patch
//! map, programmable custom timbres uploaded over SysEx, reversed pan, and
//! per-patch key shifts. Played raw into a General MIDI synth the program
//! numbers land on unrelated instruments — recognizably wrong music.
//!
//! [`Mt32Filter`] sits between the MPU wire and the GM synth as a passive
//! byte-in/byte-out state machine. It watches SysEx addressees to decide
//! what the stream is talking to (an MT-32 announces itself: Roland
//! manufacturer 0x41, model 0x16 — games upload timbres or greet the LCD
//! before the first note), and once latched onto an MT-32 stream it:
//!
//!   - tracks the PATCH TABLE the game programs over SysEx, so a program
//!     change selects what the game meant, not the raw slot number;
//!   - maps preset timbres through the canonical MT-32→GM table;
//!   - applies the patch's key shift to melodic notes;
//!   - reverses CC#10 pan (the MT-32 pans opposite to the MIDI spec);
//!   - passes channel-10 percussion through (the GM drum map descends
//!     from Roland's, so keys largely agree);
//!   - swallows the SysEx itself (device programming, noise to a GM synth).
//!
//! GM/GS/XG streams pass through untouched. Custom (memory) timbres have no
//! GM equivalent by construction — the game just synthesized a new sound —
//! so they fall back to a fixed neutral program; only real MT-32 synthesis
//! (a munt-based timbre compiler) can do better.
//!
//! This is translation, not synthesis: the output is the closest GM
//! approximation, with composer-authored custom timbres approximated by
//! stand-ins.

/// The canonical MT-32 preset → GM program map (as shipped, in identical
/// form, by ScummVM, DOSBox forks, and every MT-32-aware MIDI router).
#[rustfmt::skip]
pub const MT32_TO_GM: [u8; 128] = [
      0,   1,   0,   2,   4,   4,   5,   3,  16,  17,  18,  16,  16,  19,  20,  21,
      6,   6,   6,   7,   7,   7,   8, 112,  62,  62,  63,  63,  38,  38,  39,  39,
     88,  95,  52,  98,  97,  99,  14,  54, 102,  96,  53, 102,  81, 100,  14,  80,
     48,  48,  49,  45,  41,  40,  42,  42,  43,  46,  45,  24,  25,  28,  27, 104,
     32,  32,  34,  33,  36,  37,  35,  35,  79,  73,  72,  72,  74,  75,  64,  65,
     66,  67,  71,  71,  68,  69,  70,  22,  56,  59,  57,  57,  60,  60,  58,  61,
     61,  11,  11,  98,  14,   9,  14,  13,  12, 107, 107,  77,  78,  78,  76,  76,
     47, 117, 127, 118, 118, 116, 115, 119, 115, 112,  55, 124, 123,   0,  14, 117,
];

/// GM stand-in for custom (memory) timbres — sounds the game uploaded that
/// have no GM identity. Warm pad: neutral in most early-90s scores.
const CUSTOM_TIMBRE_GM: u8 = 89;

/// What the stream has told us it is talking to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamKind {
    /// No classifying SysEx seen yet; treated as GM (pass-through).
    Undecided,
    /// GM / GS / XG addressee seen: pass-through, stay out of the way.
    GeneralMidi,
    /// MT-32 addressee seen: translation active.
    Mt32,
}

/// One patch-table entry: where a program slot points.
#[derive(Clone, Copy)]
struct Patch {
    /// Timbre group: 0=preset A, 1=preset B, 2=memory (custom), 3=rhythm.
    group: u8,
    /// Timbre number within the group (0-63).
    number: u8,
    /// Key shift, stored MT-32 style: 0..=48 meaning -24..=+24 semitones.
    key_shift: u8,
}

impl Patch {
    /// Power-on default: patches 0-63 → preset group A, 64-127 → group B,
    /// no key shift.
    fn default_for(slot: usize) -> Patch {
        Patch {
            group: if slot < 64 { 0 } else { 1 },
            number: (slot % 64) as u8,
            key_shift: 24,
        }
    }
}

/// MIDI percussion channel (0-based): channel 10 on the wire.
const RHYTHM_CHANNEL: u8 = 9;

/// SysEx accumulation cap: enough for a full patch-table write (1KB of
/// data plus header). Longer messages keep the header (address already
/// parsed) and drop the tail.
const SYSEX_MAX: usize = 2048;

pub struct Mt32Filter {
    kind: StreamKind,
    /// Set once per latch for the caller to log; see [`Mt32Filter::take_latch_note`].
    latch_note: Option<&'static str>,

    /// MIDI wire state.
    running_status: u8,
    data: [u8; 2],
    data_len: usize,
    /// Inside F0..F7, accumulating.
    sysex: heapless_vec::SysexBuf,

    /// The MT-32 patch table as the game has programmed it.
    patches: [Patch; 128],
    /// Per-channel semitone shift of the currently selected patch.
    channel_shift: [i8; 16],

    /// Output for the byte(s) produced by the last `push`.
    out: [u8; 4],
    out_len: usize,
}

/// A tiny fixed no_std byte buffer for SysEx accumulation.
mod heapless_vec {
    pub struct SysexBuf {
        pub buf: [u8; super::SYSEX_MAX],
        pub len: usize,
        pub active: bool,
    }

    impl SysexBuf {
        pub const fn new() -> Self {
            SysexBuf { buf: [0; super::SYSEX_MAX], len: 0, active: false }
        }

        pub fn start(&mut self) {
            self.len = 0;
            self.active = true;
        }

        pub fn push(&mut self, b: u8) {
            if self.active && self.len < super::SYSEX_MAX {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }

        pub fn finish(&mut self) -> &[u8] {
            self.active = false;
            &self.buf[..self.len]
        }
    }
}

impl Mt32Filter {
    pub fn new() -> Self {
        Mt32Filter {
            kind: StreamKind::Undecided,
            latch_note: None,
            running_status: 0,
            data: [0; 2],
            data_len: 0,
            sysex: heapless_vec::SysexBuf::new(),
            patches: core::array::from_fn(Patch::default_for),
            channel_shift: [0; 16],
            out: [0; 4],
            out_len: 0,
        }
    }

    pub fn kind(&self) -> StreamKind {
        self.kind
    }

    /// A one-shot description of a latch decision, for the owner to log.
    pub fn take_latch_note(&mut self) -> Option<&'static str> {
        self.latch_note.take()
    }

    /// Feed one wire byte; returns the byte(s) to hand the GM synth.
    pub fn push(&mut self, b: u8) -> &[u8] {
        self.out_len = 0;

        // SysEx accumulation swallows everything up to and including F7
        // (real-time status bytes F8..FF may interleave and pass through).
        if self.sysex.active {
            if b >= 0xF8 {
                self.emit(b);
            } else if b == 0xF7 {
                self.classify_and_apply_sysex();
            } else {
                self.sysex.push(b);
            }
            return &self.out[..self.out_len];
        }

        match b {
            0xF0 => {
                self.sysex.start();
            }
            0xF7 => {} // stray end marker: drop
            0xF1..=0xF6 => {
                // System common: forget running status, pass through.
                self.running_status = 0;
                self.emit(b);
            }
            0xF8..=0xFF => {
                self.emit(b); // real-time: pass through
            }
            0x80..=0xEF => {
                self.running_status = b;
                self.data_len = 0;
            }
            _ => {
                // Data byte under running status.
                if self.running_status == 0 {
                    return &self.out[..self.out_len]; // orphan data: drop
                }
                self.data[self.data_len] = b;
                self.data_len += 1;
                if self.data_len == expected_data_len(self.running_status) {
                    self.data_len = 0;
                    let (status, d0, d1) = (self.running_status, self.data[0], self.data[1]);
                    self.message(status, d0, d1);
                }
            }
        }
        &self.out[..self.out_len]
    }

    /// Device reset (program exit / MPU reset): forget everything.
    pub fn reset(&mut self) {
        *self = Mt32Filter::new();
    }

    fn emit(&mut self, b: u8) {
        if self.out_len < self.out.len() {
            self.out[self.out_len] = b;
            self.out_len += 1;
        }
    }

    fn emit3(&mut self, status: u8, d0: u8, d1: u8) {
        self.emit(status);
        self.emit(d0);
        if expected_data_len(status) == 2 {
            self.emit(d1);
        }
    }

    /// A complete channel message. Translate when latched onto an MT-32
    /// stream; pass through otherwise.
    fn message(&mut self, status: u8, d0: u8, d1: u8) {
        if self.kind != StreamKind::Mt32 {
            self.emit3(status, d0, d1);
            return;
        }
        let channel = status & 0x0F;
        match status & 0xF0 {
            // Program change: route through the game-programmed patch table.
            0xC0 => {
                let patch = self.patches[(d0 & 0x7F) as usize];
                let (gm, shift) = match patch.group {
                    0 | 1 => {
                        let preset = (patch.group * 64 + patch.number.min(63)) as usize;
                        (MT32_TO_GM[preset], patch.key_shift as i8 - 24)
                    }
                    // Custom timbre: the sound was just synthesized by the
                    // game; no GM name exists for it.
                    _ => (CUSTOM_TIMBRE_GM, patch.key_shift as i8 - 24),
                };
                self.channel_shift[channel as usize] = shift;
                self.emit3(status, gm, 0);
            }
            // Notes: apply the selected patch's key shift (never on rhythm).
            0x80 | 0x90 | 0xA0 => {
                let key = if channel == RHYTHM_CHANNEL {
                    d0
                } else {
                    let shifted = d0 as i16 + self.channel_shift[channel as usize] as i16;
                    shifted.clamp(0, 127) as u8
                };
                self.emit3(status, key, d1);
            }
            // CC#10 pan: the MT-32 pans opposite to the MIDI spec.
            0xB0 if d0 == 10 => {
                self.emit3(status, 10, 127 - (d1 & 0x7F));
            }
            _ => self.emit3(status, d0, d1),
        }
    }

    /// End of a SysEx: decide what device the stream addresses, and for a
    /// latched MT-32 stream apply patch-table writes. The SysEx itself is
    /// never forwarded — a GM synth has no use for another device's
    /// programming, and misreading it is how streams get corrupted.
    fn classify_and_apply_sysex(&mut self) {
        let len = self.sysex.len;
        let body: [u8; 8] = {
            let mut head = [0u8; 8];
            let n = len.min(8);
            head[..n].copy_from_slice(&self.sysex.buf[..n]);
            head
        };

        match body {
            // Roland (0x41), model MT-32 (0x16), any device number.
            [0x41, _, 0x16, ..] => {
                if self.kind != StreamKind::Mt32 {
                    self.kind = StreamKind::Mt32;
                    self.latch_note = Some("MT-32 stream detected: GM remap active");
                }
                // Data-set (DT1): apply addressed writes we model.
                if len >= 7 && body[3] == 0x12 {
                    let addr =
                        ((body[4] as u32) << 14) | ((body[5] as u32) << 7) | body[6] as u32;
                    // Copy out to end the borrow; data excludes the trailing
                    // checksum byte.
                    let data_start = 7;
                    let data_end = len.saturating_sub(1).max(data_start);
                    let mut data = [0u8; SYSEX_MAX];
                    let n = data_end - data_start;
                    data[..n].copy_from_slice(&self.sysex.buf[data_start..data_end]);
                    self.apply_mt32_write(addr, &data[..n]);
                }
            }
            // Universal non-realtime, GM System On (F0 7E dev 09 01 F7).
            [0x7E, _, 0x09, 0x01, ..] => self.latch_gm("GM reset seen"),
            // Roland GS (model 0x42) and Yamaha XG (0x43 … 0x4C): GM family.
            [0x41, _, 0x42, ..] => self.latch_gm("GS reset seen"),
            [0x43, ..] => self.latch_gm("XG addressee seen"),
            _ => {}
        }
        let _ = self.sysex.finish();
    }

    fn latch_gm(&mut self, note: &'static str) {
        if self.kind == StreamKind::Undecided {
            self.kind = StreamKind::GeneralMidi;
            self.latch_note = Some(note);
        }
    }

    /// An addressed MT-32 memory write. The one region that changes what we
    /// emit is the patch table at 0x050000: 8 bytes per patch — timbre
    /// group, timbre number, key shift, fine tune, bender range, assign
    /// mode, reverb switch, padding. (Timbre memory at 0x080000 defines the
    /// custom sounds themselves — nothing to do at translation tier; the
    /// patch group value 2 already routes them to the stand-in.)
    fn apply_mt32_write(&mut self, addr: u32, data: &[u8]) {
        const PATCH_BASE: u32 = 5 << 14; // 0x05 00 00 in 7-bit address bytes
        const PATCH_SIZE: u32 = 8;
        const PATCH_END: u32 = PATCH_BASE + 128 * PATCH_SIZE;

        for (i, &value) in data.iter().enumerate() {
            let at = addr + i as u32;
            if !(PATCH_BASE..PATCH_END).contains(&at) {
                continue;
            }
            let rel = at - PATCH_BASE;
            let patch = &mut self.patches[(rel / PATCH_SIZE) as usize];
            match rel % PATCH_SIZE {
                0 => patch.group = value & 3,
                1 => patch.number = value & 63,
                2 => patch.key_shift = value.min(48),
                _ => {}
            }
        }
    }
}

impl Default for Mt32Filter {
    fn default() -> Self {
        Self::new()
    }
}

/// Data bytes carried by each channel-message status.
fn expected_data_len(status: u8) -> usize {
    match status & 0xF0 {
        0xC0 | 0xD0 => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(f: &mut Mt32Filter, bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        for &b in bytes {
            out.extend_from_slice(f.push(b));
        }
        out
    }

    /// The MT-32 LCD greeting Sierra games send: Roland/model 0x16.
    const MT32_LCD_SYSEX: &[u8] =
        &[0xF0, 0x41, 0x10, 0x16, 0x12, 0x20, 0x00, 0x00, 0x48, 0x49, 0x00, 0xF7];

    #[test]
    fn undecided_stream_passes_through() {
        let mut f = Mt32Filter::new();
        assert_eq!(feed(&mut f, &[0xC0, 0x30]), &[0xC0, 0x30]);
        assert_eq!(f.kind(), StreamKind::Undecided);
    }

    #[test]
    fn gm_reset_latches_gm_and_keeps_stream_verbatim() {
        let mut f = Mt32Filter::new();
        let out = feed(&mut f, &[0xF0, 0x7E, 0x7F, 0x09, 0x01, 0xF7, 0xC0, 0x30]);
        assert_eq!(f.kind(), StreamKind::GeneralMidi);
        assert_eq!(out, &[0xC0, 0x30]); // sysex swallowed, message untouched
    }

    #[test]
    fn mt32_sysex_latches_and_remaps_programs() {
        let mut f = Mt32Filter::new();
        assert!(feed(&mut f, MT32_LCD_SYSEX).is_empty());
        assert_eq!(f.kind(), StreamKind::Mt32);
        assert!(f.take_latch_note().is_some());
        // Default patch 0x30 (48) → preset 48 "Strings 1" → GM 48.
        assert_eq!(feed(&mut f, &[0xC0, 48]), &[0xC0, 48]);
        // Patch 0x17 (23) → preset 23 "Echo Pan?" → table says 112.
        assert_eq!(feed(&mut f, &[0xC1, 23]), &[0xC1, MT32_TO_GM[23]]);
    }

    #[test]
    fn patch_table_write_redirects_program_change() {
        let mut f = Mt32Filter::new();
        feed(&mut f, MT32_LCD_SYSEX);
        // DT1 write to patch 0: group B (1), timbre 5, key shift +12 (36).
        // Address 0x05 00 00, data [1, 5, 36], checksum arbitrary.
        let write =
            [0xF0, 0x41, 0x10, 0x16, 0x12, 0x05, 0x00, 0x00, 1, 5, 36, 0x00, 0xF7];
        feed(&mut f, &write);
        let expect_gm = MT32_TO_GM[64 + 5];
        assert_eq!(feed(&mut f, &[0xC0, 0]), &[0xC0, expect_gm]);
        // Melodic note is shifted up an octave; drums are not.
        assert_eq!(feed(&mut f, &[0x90, 60, 100]), &[0x90, 72, 100]);
        assert_eq!(feed(&mut f, &[0x99, 35, 100]), &[0x99, 35, 100]);
    }

    #[test]
    fn custom_timbre_falls_back_to_standin() {
        let mut f = Mt32Filter::new();
        feed(&mut f, MT32_LCD_SYSEX);
        // Patch 3 → group Memory (2), timbre 0.
        let write = [0xF0, 0x41, 0x10, 0x16, 0x12, 0x05, 0x00, 0x18, 2, 0, 24, 0x00, 0xF7];
        feed(&mut f, &write);
        assert_eq!(feed(&mut f, &[0xC0, 3]), &[0xC0, CUSTOM_TIMBRE_GM]);
    }

    #[test]
    fn pan_is_reversed_only_when_latched() {
        let mut f = Mt32Filter::new();
        assert_eq!(feed(&mut f, &[0xB0, 10, 0]), &[0xB0, 10, 0]);
        feed(&mut f, MT32_LCD_SYSEX);
        assert_eq!(feed(&mut f, &[0xB0, 10, 0]), &[0xB0, 10, 127]);
        assert_eq!(feed(&mut f, &[0xB0, 10, 127]), &[0xB0, 10, 0]);
    }

    #[test]
    fn running_status_is_decoded() {
        let mut f = Mt32Filter::new();
        feed(&mut f, MT32_LCD_SYSEX);
        // One status byte, two notes via running status; both re-emitted
        // with explicit status.
        let out = feed(&mut f, &[0x90, 60, 100, 62, 100]);
        assert_eq!(out, &[0x90, 60, 100, 0x90, 62, 100]);
    }

    #[test]
    fn oversized_sysex_keeps_stream_sync() {
        let mut f = Mt32Filter::new();
        let mut long = alloc::vec::Vec::from(&[0xF0, 0x41, 0x10, 0x16, 0x12, 0x08, 0, 0][..]);
        long.extend(core::iter::repeat(0u8).take(SYSEX_MAX + 64));
        long.push(0xF7);
        feed(&mut f, &long);
        assert_eq!(f.kind(), StreamKind::Mt32);
        assert_eq!(feed(&mut f, &[0x90, 60, 100]), &[0x90, 60, 100]);
    }
}
