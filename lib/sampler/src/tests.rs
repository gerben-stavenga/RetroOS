//! Deterministic engine tests — pure integer DSP, so outputs are exact and
//! goldens are stable across hosts.

use super::*;

/// Q32.32 helper: whole sample frames.
fn q32(frames: u64) -> u64 {
    frames << 32
}

fn voice_on(v: &mut Voice) {
    v.running = true;
    v.vol = 0xFFF0; // near-unity
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
fn ramp_dividers_clamp_and_loop() {
    let mem = [0u8; 4];
    let mut e = Engine::new_boxed();
    e.active = 2;

    // Voice 0: slowest divider (every 512 frames), no loop: count updates
    // over 1024 frames, then clamp+stop+IRQ at the ceiling.
    let v = &mut e.voices[0];
    v.vol = 0x1000;
    v.ramp = Ramp {
        running: true,
        inc: 4,
        shift: 3,
        floor: 0x1000,
        ceil: 0x1000 + 8,
        down: false,
        bidi: false,
        looped: false,
        irq: true,
        frames_to_next: 512,
    };
    // Voice 1: fastest divider, looped: wraps back to floor at the ceiling.
    let v = &mut e.voices[1];
    v.vol = 0;
    v.ramp = Ramp {
        running: true,
        inc: 1,
        shift: 0,
        floor: 0,
        ceil: 3,
        down: false,
        bidi: false,
        looped: true,
        irq: false,
        frames_to_next: 1,
    };

    let mut ev = Events::default();
    let mut out = [0i16; 2];
    for _ in 0..1024 {
        e.generate(&mem, &mut out, &mut ev);
    }
    // Updates at frames 512 and 1024: +4, then +4 hits ceil 0x1008 -> clamp.
    assert_eq!(e.voices[0].vol, 0x1008);
    assert!(!e.voices[0].ramp.running);
    assert_eq!(ev.ramp_irq & 1, 1);
    // Looped: 1024 updates over a 3-step cycle (0->1->2->3==ceil->0 wrap).
    assert!(e.voices[1].ramp.running);
    assert!(e.voices[1].vol >= 0 && e.voices[1].vol <= 3);
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
    v.vol = 0xE000;
    v.ramp = Ramp {
        running: true,
        inc: 8,
        shift: 1,
        floor: 0xA000,
        ceil: 0xE000,
        down: true,
        bidi: true,
        looped: true,
        irq: false,
        frames_to_next: 8,
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
        11527402967319707540, // from the first verified run of this exact scene
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
        assert_eq!((l, r), (full[native * 2], full[native * 2 + 1]), "pull {k}");
    }
}
