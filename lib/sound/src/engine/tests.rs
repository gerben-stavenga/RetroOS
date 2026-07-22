//! Deterministic engine tests — pure integer DSP, so outputs are exact and
//! goldens are stable across hosts.

use super::*;

/// Q32.32 helper: whole sample frames.
fn q32(frames: u64) -> u64 {
    frames << 32
}

/// A GF1 16-bit volume register value in the ramp's fixed-point domain.
fn rvol(reg: i32) -> i32 {
    reg << volume::RAMP_FRACT
}

fn voice_on(v: &mut Voice) {
    v.running = true;
    v.vol = rvol(0xFFF0); // near-unity
    v.pan_l = 0x0FFF;
    v.pan_r = 0x0FFF;
}

#[test]
fn log_volume_endpoints_and_monotonicity() {
    assert_eq!(volume::lin_q16(0), 1);
    assert_eq!(volume::lin_q16(0x1000), 2);
    assert_eq!(volume::lin_q16(0xFFF0), 65408);
    assert_eq!(volume::lin_q16(0xFFFF), 65528);
    // Out-of-domain values clamp instead of shifting into the sign bit.
    assert_eq!(volume::lin_q16(-5), 1);
    assert_eq!(volume::lin_q16(0x2_0000), 65528);
    let mut last = 0;
    for v in 0..=0xFFFF {
        let g = volume::lin_q16(v);
        assert!(g >= last, "lin_q16 not monotone at {v:#x}");
        last = g;
    }
    // Each exponent step is exactly a doubling.
    for e in 0..15 {
        assert_eq!(
            volume::lin_q16((e + 1) << 12),
            volume::lin_q16(e << 12) * 2
        );
    }
}

#[test]
fn forward_loop_wraps_with_overshoot_and_irq() {
    let mem = [0u8; 64];
    let mut e = Engine::new_boxed();
    e.active = 1;
    let v = &mut e.voices[0];
    voice_on(v);
    v.start = q32(8);
    v.end = q32(16);
    v.addr = q32(14);
    v.inc = q32(3) / 2; // 1.5 frames/step
    v.loop_mode = LoopMode::Forward;
    v.irq_on_end = true;

    let mut ev = Events::default();
    let mut out = [0i16; 2];
    e.generate(&mem, &mut out, &mut ev); // 14.0 -> 15.5
    assert_eq!(e.voices[0].addr, q32(31) / 2);
    assert!(!ev.any());
    e.generate(&mem, &mut out, &mut ev); // 15.5 -> 17.0: overshoot 1.0 past end
    assert_eq!(e.voices[0].addr, q32(9), "wrap must preserve overshoot");
    assert_eq!(ev.wave_irq, 1);
    assert!(e.voices[0].running);
}

#[test]
fn bidi_reflects_and_none_stops_or_rolls_over() {
    let mem = [0u8; 64];
    let mut e = Engine::new_boxed();
    e.active = 3;
    for i in 0..3 {
        let v = &mut e.voices[i];
        voice_on(v);
        v.start = q32(8);
        v.end = q32(16);
        v.addr = q32(15);
        v.inc = q32(2); // crosses end on the first step, overshoot 1.0
        v.irq_on_end = true;
    }
    e.voices[0].loop_mode = LoopMode::Bidi;
    e.voices[1].loop_mode = LoopMode::None;
    e.voices[2].loop_mode = LoopMode::None;
    e.voices[2].rollover = true;

    let mut ev = Events::default();
    let mut out = [0i16; 2];
    e.generate(&mem, &mut out, &mut ev);
    // Bidi: reflect to end - overshoot, now playing backwards.
    assert_eq!(e.voices[0].addr, q32(15));
    assert!(e.voices[0].backwards);
    assert!(e.voices[0].running);
    // None: clamp at end and stop (IRQ still fires).
    assert_eq!(e.voices[1].addr, q32(16));
    assert!(!e.voices[1].running);
    // None + rollover: run on past the boundary.
    assert_eq!(e.voices[2].addr, q32(17));
    assert!(e.voices[2].running);
    assert_eq!(ev.wave_irq, 0b111);
}

#[test]
fn backwards_forward_loop_wraps_to_end() {
    let mem = [0u8; 64];
    let mut e = Engine::new_boxed();
    e.active = 1;
    let v = &mut e.voices[0];
    voice_on(v);
    v.start = q32(8);
    v.end = q32(16);
    v.addr = q32(9);
    v.inc = q32(2); // 9.0 -> 7.0: overshoot 1.0 below start
    v.backwards = true;
    v.loop_mode = LoopMode::Forward;

    let mut ev = Events::default();
    let mut out = [0i16; 2];
    e.generate(&mem, &mut out, &mut ev);
    assert_eq!(e.voices[0].addr, q32(15));
    assert!(e.voices[0].backwards);
}

#[test]
fn ramp_advances_every_frame_and_clamps_or_loops() {
    let mem = [0u8; 4];
    let mut e = Engine::new_boxed();
    e.active = 2;

    // Voice 0: a slow rate (one register unit per 512 frames, the GF1's
    // slowest divider) climbing 2 register units, then clamp+stop+IRQ.
    let slow = rvol(1) / 512;
    let v = &mut e.voices[0];
    v.vol = rvol(0x1000);
    v.ramp = Ramp {
        running: true,
        inc: slow,
        floor: rvol(0x1000),
        ceil: rvol(0x1002),
        down: false,
        bidi: false,
        looped: false,
        irq: true,
    };
    // Voice 1: a fast rate, looped: wraps back to floor at the ceiling.
    let v = &mut e.voices[1];
    v.vol = 0;
    v.ramp = Ramp {
        running: true,
        inc: rvol(1),
        floor: 0,
        ceil: rvol(3),
        down: false,
        bidi: false,
        looped: true,
        irq: false,
    };

    let mut ev = Events::default();
    let mut out = [0i16; 2];
    for _ in 0..1024 {
        e.generate(&mem, &mut out, &mut ev);
    }
    // 1024 frames x (1/512 register units) = exactly the 2-unit span.
    assert_eq!(e.voices[0].vol, rvol(0x1002));
    assert!(!e.voices[0].ramp.running);
    assert_eq!(ev.ramp_irq & 1, 1);
    // Looped: wraps around a 3-unit cycle and keeps running.
    assert!(e.voices[1].ramp.running);
    assert!(e.voices[1].vol >= 0 && e.voices[1].vol <= rvol(3));
}

/// The property the phase-counter model got wrong: a ramp rewritten more often
/// than its own update period must still make progress. Reprogramming carries
/// no pacing state, so N frames of ramping advance the volume by N*inc no
/// matter how many times the ramp is restarted in between. DMX rewrites voice
/// ramps every ~20ms, faster than the slow dividers' period, and under the old
/// countdown model those ramps stalled outright.
#[test]
fn frequent_ramp_rewrites_do_not_stall_progress() {
    let mem = [0u8; 4];
    let slow = rvol(1) / 512; // GF1 slowest divider: 512 frames per unit

    let run = |restart_every: usize| -> i32 {
        let mut e = Engine::new_boxed();
        e.active = 1;
        let v = &mut e.voices[0];
        v.vol = rvol(0x8000);
        v.ramp = Ramp {
            running: true,
            inc: slow,
            floor: 0,
            ceil: rvol(0xFFFF),
            down: true,
            bidi: false,
            looped: false,
            irq: false,
        };
        let mut ev = Events::default();
        let mut out = [0i16; 2];
        for i in 0..4096 {
            if restart_every != 0 && i % restart_every == 0 {
                // What a guest ramp-control write does: re-arm, same params.
                e.voices[0].ramp.running = true;
            }
            e.generate(&mem, &mut out, &mut ev);
        }
        rvol(0x8000) - e.voices[0].vol
    };

    let undisturbed = run(0);
    assert_eq!(undisturbed, 4096 * slow, "4096 frames must move 4096 steps");
    // Rewritten far more often than the 512-frame update period would allow.
    assert_eq!(run(64), undisturbed, "a rewrite must not cost progress");
    assert_eq!(run(1), undisturbed, "even a rewrite every single frame");
}

/// The 16-bit data-width transform belongs at the DRAM fetch, not at the
/// address-register write: voices store width-agnostic GF1 addresses, so a
/// control write that changes `bits16` reinterprets the SAME stored address
/// instead of forcing a re-derivation (which is what used to cost a live voice
/// its position). The transform itself keeps address bits 19:18 as the 256 KB
/// bank selector, drops bit 17, and doubles the offset within the bank —
/// DOSBox Staging's `Read16BitSample` computes `upper | (lower << 1)`.
#[test]
fn width_transform_happens_at_fetch_not_at_write() {
    let mut mem = vec![0u8; 1 << 20];
    let gf1_addr: u64 = 0x40000 | 0x1234; // bank bit 18 set, low offset
    let word = 0x40000 | (0x1234 << 1);
    mem[word] = 0x34;
    mem[word + 1] = 0x12;
    assert_eq!(fetch(&mem, true, gf1_addr, 0, Addressing::Gf1Dram), 0x1234);
    // Bit 17 is dropped by the hardware: it selects the same word.
    assert_eq!(fetch(&mem, true, gf1_addr | 0x20000, 0, Addressing::Gf1Dram), 0x1234);
    // The very same address read as 8-bit data is a plain byte index.
    mem[gf1_addr as usize] = 0x7F;
    assert_eq!(fetch(&mem, false, gf1_addr, 0, Addressing::Gf1Dram), 0x7F00);
}

/// A tiny xorshift so the golden buffer is reproducible without std rand.
fn fill_lfsr(buf: &mut [u8]) {
    let mut s = 0xACE1u32;
    for b in buf.iter_mut() {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        *b = s as u8;
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// End-to-end golden: 4 voices (8/16-bit, forward/bidi, panned, one ramping,
/// one backwards) mixed for 4096 frames. Regenerate the literal by running
/// this test and copying the hash from the failure message after any
/// *intentional* engine-semantics change.
#[test]
fn golden_mix() {
    let mut mem = [0u8; 1024];
    fill_lfsr(&mut mem);
    let mut e = Engine::new_boxed();
    e.active = 4;

    let v = &mut e.voices[0]; // 8-bit forward loop, left-leaning
    voice_on(v);
    v.start = q32(16);
    v.end = q32(80);
    v.addr = q32(16);
    v.inc = (q32(1) * 3) / 4;
    v.loop_mode = LoopMode::Forward;
    v.pan_l = 0x0FFF;
    v.pan_r = 0x0400;

    let v = &mut e.voices[1]; // 16-bit bidi, right-leaning
    voice_on(v);
    v.bits16 = true;
    v.start = q32(8);
    v.end = q32(120);
    v.addr = q32(8);
    v.inc = (q32(1) * 5) / 3;
    v.loop_mode = LoopMode::Bidi;
    v.pan_l = 0x0400;
    v.pan_r = 0x0FFF;

    let v = &mut e.voices[2]; // 8-bit loop with a looped down-ramp
    voice_on(v);
    v.start = q32(100);
    v.end = q32(200);
    v.addr = q32(150);
    v.inc = q32(1) / 2;
    v.loop_mode = LoopMode::Forward;
    v.vol = rvol(0xE000);
    v.ramp = Ramp {
        running: true,
        inc: rvol(1), // one register unit per frame (was 8 units per 8 frames)
        floor: rvol(0xA000),
        ceil: rvol(0xE000),
        down: true,
        bidi: true,
        looped: true,
        irq: false,
    };

    let v = &mut e.voices[3]; // 8-bit backwards forward-loop
    voice_on(v);
    v.start = q32(300);
    v.end = q32(400);
    v.addr = q32(399);
    v.inc = (q32(1) * 7) / 5;
    v.backwards = true;
    v.loop_mode = LoopMode::Forward;

    let mut ev = Events::default();
    let mut out = [0i16; 4096 * 2];
    e.generate(&mem, &mut out, &mut ev);

    assert!(out.iter().any(|&s| s != 0), "golden mix produced silence");
    let mut bytes = Vec::with_capacity(out.len() * 2);
    for s in out {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    assert_eq!(
        fnv1a(&bytes),
        // Regenerated when the ramp moved from a lump-every-N-frames staircase
        // to a per-frame fractional slope: voice 2 ramps, so its instantaneous
        // volume differs frame to frame even though the average rate is
        // unchanged. Previous literal: 11527402967319707540.
        11509080982864882439,
        "golden mix hash changed; if the semantics change was intentional, update the literal"
    );
}

/// mix_frame's zero-order-hold pull at out_rate R from native rate 4R must
/// equal every 4th frame of a straight generate() on an identical engine.
#[test]
fn mix_frame_zoh_matches_decimated_generate() {
    let mut mem = [0u8; 512];
    fill_lfsr(&mut mem);

    let setup = |e: &mut Engine| {
        e.active = 2;
        let v = &mut e.voices[0];
        voice_on(v);
        v.start = q32(0);
        v.end = q32(100);
        v.addr = q32(0);
        v.inc = (q32(1) * 7) / 8;
        v.loop_mode = LoopMode::Forward;
        let v = &mut e.voices[1];
        voice_on(v);
        v.bits16 = true;
        v.start = q32(0);
        v.end = q32(200);
        v.addr = q32(50);
        v.inc = (q32(1) * 9) / 7;
        v.loop_mode = LoopMode::Bidi;
    };

    let mut a = Engine::new_boxed();
    let mut b = Engine::new_boxed();
    setup(&mut a);
    setup(&mut b);

    let mut ev = Events::default();
    let mut full = [0i16; 64 * 2];
    b.generate(&mem, &mut full, &mut ev);

    let mut ev = Events::default();
    for k in 0..16 {
        let (l, r) = a.mix_frame(&mem, 44100, 11025, &mut ev);
        let native = k * 4 + 3; // 4 native frames per pull; hold = the last
        // What's under test is that the ZOH pull lands on the same native frame
        // as the decimated `generate`. `mix_frame` is now unclipped (the final
        // mixer owns the one clip point) while `generate` still saturates, and
        // this fixture's voices do sum past i16 — so compare through the same
        // saturation rather than against the raw accumulator.
        let sat = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        assert_eq!(
            (sat(l), sat(r)),
            (full[native * 2], full[native * 2 + 1]),
            "pull {k}"
        );
    }
}

/// The GF1's DRAM addressing must not reach a flat sample pool.
///
/// A GUS models a 1 MB board: 8-bit voices wrap at 20 bits and 16-bit voices
/// keep the 256 KB bank bits while doubling within the bank. A General MIDI
/// pool is an array — a dozen instruments already exceed 256 KB, and applying
/// the board's transform aliases each one onto another. The audible signature
/// is a song played with the wrong instruments, which is how this was found.
#[test]
fn linear_addressing_does_not_wrap_or_bank_like_gf1_dram() {
    // A frame past the 16-bit bank boundary (0x1FFFF frames = 256 KB).
    let frame = 0x20_010u64;
    let byte_linear = frame as usize * 2;
    let mut mem = alloc::vec![0u8; byte_linear + 4];
    // Put a recognizable sample where LINEAR addressing would look.
    mem[byte_linear] = 0x00;
    mem[byte_linear + 1] = 0x40; // i16 0x4000
    // ...and a different one where the GF1 bank transform would land instead.
    let banked = ((frame & 0xC0000) | ((frame & 0x1FFFF) << 1)) as usize;
    assert_ne!(banked, byte_linear, "the transform must actually differ here");
    mem[banked] = 0x00;
    mem[banked + 1] = 0xC0; // i16 -0x4000

    let mut read = |mode: Addressing| -> i32 {
        let mut e = Engine::new_boxed();
        e.active = 1;
        e.addressing = mode;
        let v = &mut e.voices[0];
        v.running = true;
        v.bits16 = true;
        v.addr = frame << 32;
        v.inc = 0; // hold position
        v.end = u64::MAX;
        v.vol = rvol(0xFFF0);
        v.pan_l = 0x0FFF;
        v.pan_r = 0x0FFF;
        let mut ev = Events::default();
        e.step(&mem, &mut ev).0
    };
    let lin = read(Addressing::Linear);
    let gf1 = read(Addressing::Gf1Dram);
    assert!(lin > 0, "linear must read the sample actually at that byte");
    assert!(gf1 < 0, "GF1 mode must read the banked location instead");
}

/// Linear mode must not wrap at the GF1's 1 MB ceiling either.
#[test]
fn linear_addressing_reaches_past_one_megabyte() {
    let frame = 0x10_0004u64; // just past 1 MB of 8-bit frames
    let mut mem = alloc::vec![0u8; frame as usize + 2];
    mem[frame as usize] = 0x7F; // loud positive
    mem[(frame & 0xFFFFF) as usize] = 0x80; // what a 20-bit wrap would hit
    let mut e = Engine::new_boxed();
    e.active = 1;
    e.addressing = Addressing::Linear;
    let v = &mut e.voices[0];
    v.running = true;
    v.addr = frame << 32;
    v.inc = 0;
    v.end = u64::MAX;
    v.vol = rvol(0xFFF0);
    v.pan_l = 0x0FFF;
    v.pan_r = 0x0FFF;
    let mut ev = Events::default();
    assert!(e.step(&mem, &mut ev).0 > 0, "must not wrap at 20 bits");
}
