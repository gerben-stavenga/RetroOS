//! Gravis `.PAT` (GF1PATCH) instrument files — the wavetable bank format.
//!
//! This is the format the Gravis UltraSound shipped its General MIDI
//! instruments in, and the one the `dgguspat` set on `C:\ULTRASND\MIDI` uses.
//! We parse it rather than SoundFont for two reasons, one practical and one
//! structural:
//!
//!  - it is already on the disk, license-clean, and is what every GUS-native
//!    DOS driver loads — so a General MIDI device costs no new asset and no
//!    ROM we are not allowed to ship (the wall the AWE32 and MT-32 hit);
//!  - it *is* the engine's model. A `.PAT` sample carries a GF1 sample
//!    address, loop points, loop/bidi/16-bit mode bits, and a six-stage
//!    envelope whose rates and offsets are GF1 ramp registers — every field
//!    maps onto [`Voice`](crate::Voice) and [`Ramp`](crate::Ramp) directly,
//!    with no domain conversion beyond what the GF1 front-end already does.
//!
//! Parsing only: this module reads a byte slice a host handed over and never
//! touches a file. Layout (all little-endian) is
//!
//! ```text
//!   header      129 bytes   "GF1PATCH110\0", instrument/waveform counts
//!   instrument   63 bytes   name, layer count
//!   layer        47 bytes   sample count
//!   sample       96 bytes   + `size` bytes of PCM, repeated `waveforms` times
//! ```

use alloc::vec::Vec;

/// Fixed header sizes, in bytes.
const HDR: usize = 129;
const INSTR: usize = 63;
const LAYER: usize = 47;
const SAMPLE: usize = 96;

/// `modes` bits in a sample header.
const M_16BIT: u8 = 0x01;
const M_UNSIGNED: u8 = 0x02;
const M_LOOP: u8 = 0x04;
const M_BIDI: u8 = 0x08;
const M_REVERSE: u8 = 0x10;
const M_SUSTAIN: u8 = 0x20;
const M_ENVELOPE: u8 = 0x40;

/// One sample of an instrument, covering a slice of the keyboard.
///
/// Addresses are byte offsets into the patch's own PCM, which the caller
/// concatenates into a sample pool; [`Patch::relocate`] shifts them once the
/// pool position is known.
#[derive(Clone, Copy, Default)]
pub struct Sample {
    /// Byte range of this sample's PCM, and its loop points, all as GF1
    /// *sample-frame* addresses in Q32.32 (what [`Voice`](crate::Voice) wants).
    pub start: u64,
    pub end: u64,
    pub loop_start: u64,
    pub loop_end: u64,
    /// True when the PCM is 16-bit little-endian; false for 8-bit.
    pub bits16: bool,
    /// The PCM is unsigned and must be biased into signed on the way in.
    pub unsigned: bool,
    pub looped: bool,
    pub bidi: bool,
    pub reverse: bool,
    /// Play the loop while the key is held (release leaves it).
    pub sustain: bool,
    /// Run the six-stage envelope; without it the voice plays at full volume.
    pub envelope: bool,
    /// Recording rate of the PCM, Hz.
    pub sample_rate: u32,
    /// Pitch this sample was recorded at, in milliHertz.
    pub root_hz_milli: u32,
    /// Keyboard span this sample covers, in milliHertz.
    pub low_hz_milli: u32,
    pub high_hz_milli: u32,
    /// Fine tuning, cents.
    pub tune: i16,
    /// 0 = hard left, 7/8 = centre, 15 = hard right (GF1 pan positions).
    pub balance: u8,
    /// Six-stage envelope, in the GF1's own ramp-register domain: `rate` is a
    /// ramp-rate register (6-bit increment + 2-bit divider), `offset` a ramp
    /// bound (the volume's top byte).
    pub env_rate: [u8; 6],
    pub env_offset: [u8; 6],
}

/// A parsed instrument: its samples plus the PCM they address.
pub struct Patch {
    pub name: [u8; 16],
    pub samples: Vec<Sample>,
    /// Concatenated PCM for every sample, already normalized to **signed**
    /// (an unsigned source is biased on the way in) so the engine's fetch
    /// needs no per-voice sign handling.
    pub pcm: Vec<u8>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// A GF1 byte address plus its 4-bit fraction, as a Q32.32 *frame* address.
/// `.PAT` loop points are byte offsets with a nibble of fraction; a 16-bit
/// sample's frame index is half its byte offset.
fn frame_q32(byte_off: u32, frac16: u8, bits16: bool) -> u64 {
    let frames = if bits16 { byte_off / 2 } else { byte_off };
    // The nibble is sixteenths of a frame → Q32 fraction.
    let frac = ((frac16 as u64) << 32) / 16;
    ((frames as u64) << 32) | (frac & 0xFFFF_FFFF)
}

impl Patch {
    /// Parse a `.PAT` file. Returns `None` if the bytes are not a GF1PATCH or
    /// are truncated — a guest-supplied or missing bank must not panic.
    pub fn parse(b: &[u8]) -> Option<Patch> {
        if b.len() < HDR + INSTR + LAYER || &b[0..11] != b"GF1PATCH110" {
            return None;
        }
        let waveforms = u16le(b, 85) as usize;
        let mut name = [0u8; 16];
        name.copy_from_slice(&b[HDR + 2..HDR + 18]);

        let mut samples = Vec::new();
        let mut pcm: Vec<u8> = Vec::new();
        let mut o = HDR + INSTR + LAYER;
        for _ in 0..waveforms {
            if o + SAMPLE > b.len() {
                break;
            }
            let frac = b[o + 7];
            let size = u32le(b, o + 8) as usize;
            let loop_start = u32le(b, o + 12);
            let loop_end = u32le(b, o + 16);
            let sample_rate = u16le(b, o + 20) as u32;
            let low = u32le(b, o + 22);
            let high = u32le(b, o + 26);
            let root = u32le(b, o + 30);
            let tune = u16le(b, o + 34) as i16;
            let balance = b[o + 36];
            let mut env_rate = [0u8; 6];
            let mut env_offset = [0u8; 6];
            env_rate.copy_from_slice(&b[o + 37..o + 43]);
            env_offset.copy_from_slice(&b[o + 43..o + 49]);
            let modes = b[o + 55];
            let data = o + SAMPLE;
            if data + size > b.len() {
                break;
            }
            let bits16 = modes & M_16BIT != 0;
            let unsigned = modes & M_UNSIGNED != 0;

            // Append the PCM, biasing unsigned → signed as we go so the
            // engine only ever sees signed data.
            let base_bytes = pcm.len() as u32;
            let src = &b[data..data + size];
            if unsigned {
                if bits16 {
                    // Unsigned 16-bit LE: flip the high byte's sign bit.
                    for (i, &v) in src.iter().enumerate() {
                        pcm.push(if i & 1 == 1 { v ^ 0x80 } else { v });
                    }
                } else {
                    for &v in src {
                        pcm.push(v ^ 0x80);
                    }
                }
            } else {
                pcm.extend_from_slice(src);
            }

            // Byte offsets → GF1 frame addresses, relative to this patch's PCM.
            let base = frame_q32(base_bytes, 0, bits16);
            samples.push(Sample {
                start: base,
                end: base + frame_q32(size as u32, 0, bits16),
                loop_start: base + frame_q32(loop_start, frac & 0x0F, bits16),
                loop_end: base + frame_q32(loop_end, frac >> 4, bits16),
                bits16,
                unsigned,
                looped: modes & M_LOOP != 0,
                bidi: modes & M_BIDI != 0,
                reverse: modes & M_REVERSE != 0,
                sustain: modes & M_SUSTAIN != 0,
                envelope: modes & M_ENVELOPE != 0,
                sample_rate,
                root_hz_milli: root,
                low_hz_milli: low,
                high_hz_milli: high,
                tune,
                balance,
                env_rate,
                env_offset,
            });
            o = data + size;
        }
        if samples.is_empty() {
            return None;
        }
        Some(Patch { name, samples, pcm })
    }

    /// Shift every sample address by `frames`, once the caller knows where
    /// this patch's PCM landed in the shared pool.
    ///
    /// Note the unit: a 16-bit patch's addresses count *frames*, and the pool
    /// is bytes, so the caller passes the pool offset already converted for
    /// this patch's width. Mixed-width patches are why this is per-sample.
    pub fn relocate(&mut self, byte_base: u32) {
        for s in self.samples.iter_mut() {
            let d = frame_q32(byte_base, 0, s.bits16);
            s.start += d;
            s.end += d;
            s.loop_start += d;
            s.loop_end += d;
        }
    }

    /// Index of the sample covering `hz_milli`, or the nearest by root pitch.
    /// Patches split the keyboard into frequency bands (`acpiano.pat` has
    /// seven), and a note outside every band still has to sound.
    ///
    /// Callers want the *index*, not just the sample: a voice's envelope has
    /// to come from the same sample its PCM does, and taking one from sample 0
    /// while playing another is a silent mismatch on every multi-sample patch.
    pub fn select_index(&self, hz_milli: u32) -> usize {
        for (i, s) in self.samples.iter().enumerate() {
            if hz_milli >= s.low_hz_milli && hz_milli <= s.high_hz_milli {
                return i;
            }
        }
        let mut best = 0;
        let mut best_d = u32::MAX;
        for (i, s) in self.samples.iter().enumerate() {
            let d = s.root_hz_milli.abs_diff(hz_milli);
            if d < best_d {
                best_d = d;
                best = i;
            }
        }
        best
    }

    /// The sample covering `hz_milli`. See [`select_index`](Self::select_index).
    pub fn select(&self, hz_milli: u32) -> &Sample {
        &self.samples[self.select_index(hz_milli)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic two-sample patch with known field values, so the
    /// layout arithmetic is checked without depending on a shipped asset.
    fn build(modes: u8, pcm: &[&[u8]]) -> Vec<u8> {
        let mut b = alloc::vec![0u8; HDR];
        b[0..12].copy_from_slice(b"GF1PATCH110\0");
        b[85..87].copy_from_slice(&(pcm.len() as u16).to_le_bytes());
        let mut instr = alloc::vec![0u8; INSTR];
        instr[2..18].copy_from_slice(b"TestInstrument\0\0");
        instr[22] = 1; // layers
        b.extend_from_slice(&instr);
        b.extend_from_slice(&alloc::vec![0u8; LAYER]);
        for (i, data) in pcm.iter().enumerate() {
            let mut s = alloc::vec![0u8; SAMPLE];
            s[7] = 0x20; // loop-start fraction = 0/16, loop-end = 2/16
            s[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            s[12..16].copy_from_slice(&8u32.to_le_bytes()); // loop_start bytes
            s[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            s[20..22].copy_from_slice(&44100u16.to_le_bytes());
            s[22..26].copy_from_slice(&(1000 * (i as u32 + 1)).to_le_bytes());
            s[26..30].copy_from_slice(&(2000 * (i as u32 + 1)).to_le_bytes());
            s[30..34].copy_from_slice(&(1500 * (i as u32 + 1)).to_le_bytes());
            s[36] = 7; // balance: centre
            s[37..43].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
            s[43..49].copy_from_slice(&[10, 20, 30, 40, 50, 60]);
            s[55] = modes;
            b.extend_from_slice(&s);
            b.extend_from_slice(data);
        }
        b
    }

    #[test]
    fn rejects_foreign_and_truncated_input() {
        assert!(Patch::parse(b"not a patch at all, really").is_none());
        let good = build(M_LOOP, &[&[0u8; 16]]);
        assert!(Patch::parse(&good).is_some());
        // Truncated mid-sample-data: parse must bail, not panic or over-read.
        assert!(Patch::parse(&good[..good.len() - 4]).is_none());
    }

    #[test]
    fn eight_bit_unsigned_is_biased_to_signed() {
        let raw: [u8; 4] = [0x00, 0x80, 0xFF, 0x40];
        let p = Patch::parse(&build(M_UNSIGNED, &[&raw])).unwrap();
        // 0x80 is unsigned silence → signed 0x00.
        assert_eq!(&p.pcm[..], &[0x80, 0x00, 0x7F, 0xC0]);
        assert!(p.samples[0].unsigned);
        assert!(!p.samples[0].bits16);
    }

    #[test]
    fn sixteen_bit_unsigned_biases_only_the_high_byte() {
        // Two frames LE: 0x8000 (silence) and 0xC000.
        let raw: [u8; 4] = [0x00, 0x80, 0x00, 0xC0];
        let p = Patch::parse(&build(M_16BIT | M_UNSIGNED, &[&raw])).unwrap();
        assert_eq!(&p.pcm[..], &[0x00, 0x00, 0x00, 0x40]);
        assert!(p.samples[0].bits16);
    }

    #[test]
    fn sixteen_bit_addresses_count_frames_not_bytes() {
        let raw = [0u8; 64]; // 32 frames at 16-bit
        let p = Patch::parse(&build(M_16BIT | M_LOOP, &[&raw])).unwrap();
        let s = p.samples[0];
        assert_eq!(s.start >> 32, 0);
        assert_eq!(s.end >> 32, 32, "64 bytes of 16-bit data is 32 frames");
        // loop_start is byte 8 → frame 4; the fraction nibble is 0.
        assert_eq!(s.loop_start >> 32, 4);
        // loop_end fraction nibble is 2/16 of a frame.
        assert_eq!(s.loop_end >> 32, 32);
        assert_eq!((s.loop_end & 0xFFFF_FFFF) >> 28, 2, "2/16 frame fraction");
    }

    #[test]
    fn samples_concatenate_and_relocate_by_width() {
        let a = [0u8; 16];
        let b = [0u8; 32];
        let mut p = Patch::parse(&build(M_16BIT, &[&a, &b])).unwrap();
        assert_eq!(p.pcm.len(), 48);
        // Second sample starts where the first ended: byte 16 = frame 8.
        assert_eq!(p.samples[1].start >> 32, 8);
        assert_eq!(p.samples[1].end >> 32, 24);
        // Relocating by 100 bytes shifts a 16-bit sample by 50 frames.
        p.relocate(100);
        assert_eq!(p.samples[0].start >> 32, 50);
        assert_eq!(p.samples[1].start >> 32, 58);
    }

    #[test]
    fn mode_bits_and_envelope_survive_the_round_trip() {
        let p = Patch::parse(&build(
            M_16BIT | M_LOOP | M_BIDI | M_SUSTAIN | M_ENVELOPE,
            &[&[0u8; 8]],
        ))
        .unwrap();
        let s = p.samples[0];
        assert!(s.looped && s.bidi && s.sustain && s.envelope);
        assert!(!s.reverse && !s.unsigned);
        assert_eq!(s.env_rate, [1, 2, 3, 4, 5, 6]);
        assert_eq!(s.env_offset, [10, 20, 30, 40, 50, 60]);
        assert_eq!(s.balance, 7);
        assert_eq!(s.sample_rate, 44100);
    }

    /// The synthetic cases above only prove the parser agrees with *my* idea
    /// of the layout. This one parses a real shipped instrument — seven
    /// samples, 16-bit unsigned, looping, with envelopes — and checks the
    /// parse consumes the file exactly, which is what catches a field-offset
    /// error that happens to be self-consistent.
    #[test]
    fn parses_a_real_shipped_instrument() {
        let raw = include_bytes!("../../../apps/ultrasnd/MIDI/acpiano.pat");
        let p = Patch::parse(raw).expect("acpiano.pat must parse");
        assert_eq!(&p.name[..14], b"Acoustic Piano");
        assert_eq!(p.samples.len(), 7, "acpiano is a 7-way keyboard split");

        // Every sample is 16-bit unsigned, looped, with sustain + envelope.
        for s in &p.samples {
            assert!(s.bits16 && s.unsigned && s.looped && s.sustain && s.envelope);
            assert!(!s.bidi && !s.reverse);
            assert_eq!(s.sample_rate, 39062);
            assert!(s.low_hz_milli <= s.root_hz_milli && s.root_hz_milli <= s.high_hz_milli);
            assert!(s.loop_start < s.loop_end && s.loop_end <= s.end);
        }
        // The bands must tile the keyboard in ascending order, with the
        // exact endpoints of this specific file (milliHertz — 26.986 Hz to
        // 4268.98 Hz, roughly A0 to the top of the piano).
        assert_eq!(p.samples[0].low_hz_milli, 26_986);
        assert_eq!(p.samples[0].root_hz_milli, 98_381);
        assert_eq!(p.samples[6].high_hz_milli, 4_268_980);
        for w in p.samples.windows(2) {
            assert!(w[0].high_hz_milli < w[1].low_hz_milli);
        }
        // Exact consumption: the concatenated PCM must equal the file minus
        // every header. An off-by-one in any header size shows up here.
        let headers = HDR + INSTR + LAYER + SAMPLE * 7;
        assert_eq!(p.pcm.len(), raw.len() - headers);
        // Sanity: unsigned 16-bit biased to signed means the last sample's
        // frame count matches its address span.
        let s = p.samples[6];
        assert_eq!((s.end - s.start) >> 32, 4004 / 2);
    }

    #[test]
    fn select_picks_the_band_then_falls_back_to_nearest_root() {
        // Bands: [1000..2000] root 1500, [2000..4000] root 3000.
        let p = Patch::parse(&build(0, &[&[0u8; 8], &[0u8; 8]])).unwrap();
        assert_eq!(p.select(1500).root_hz_milli, 1500);
        assert_eq!(p.select(3500).root_hz_milli, 3000);
        // Far above every band: nearest root wins rather than panicking.
        assert_eq!(p.select(99_999).root_hz_milli, 3000);
        assert_eq!(p.select(1).root_hz_milli, 1500);
    }
}
