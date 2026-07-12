//! The unified wavetable sampler — the one integer voice-mixing engine every
//! sample-playback personality programs (GUS/GF1 now; GM-over-SoundFont,
//! AWE32/EMU8000 and the MT-32 timbre renderer later). The engine is a pure
//! function of (voice state, sample memory): it owns no clock, no sample
//! memory, and no device policy — callers decide how many frames to pull and
//! pass the memory their voices address (GUS DRAM, an SF2 sample chunk).
//!
//! Everything is fixed-point integer: the metal i686 kernel builds with
//! `-mmx,-sse,-sse2` and no soft-float, so `f32`/`f64` would silently lower
//! to x87 the kernel doesn't context-switch (see stdlib/nuked_opl3.BUILD for
//! the same rule). Formats:
//!
//!  - addresses/increments: Q32.32 sample-frame index (`u64`). The GF1's
//!    20.9 registers convert losslessly by `<< 23` / `>> 23`; 32 integer
//!    bits also cover SF2 sample pools.
//!  - volume: the GF1's logarithmic 16-bit register domain (exponent in
//!    bits 15-12, mantissa in bits 11-0), held in an `i32` for ramp
//!    headroom. This is the canonical volume domain for every personality:
//!    one exponent step = ×2 = 6.02 dB, so SF2 centibels convert by a
//!    constant integer factor.
//!  - pan: Q12 gains, resolved by the personality (the GF1's 16-position
//!    table is device policy, not engine math).
//!
//! The per-frame mix loop is hot (up to 44.1 kHz × 32 voices), which is why
//! the crate builds `-Copt-level=2` instead of //lib's `-z`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod voice;
pub mod volume;

pub use voice::{Events, LoopMode, Ramp, Voice, VoiceFilter};

/// The engine is sized for its largest client (the GF1's 32 voices);
/// personalities with fewer notes simply leave voices stopped.
pub const MAX_VOICES: usize = 32;

pub struct Engine {
    pub voices: [Voice; MAX_VOICES],
    /// Voices participating in the mix: `voices[..active]`. The GF1's
    /// "active voices" register maps here; MIDI personalities set 32.
    pub active: u8,
    /// Q32 native-frame accumulator for the foreign-rate pull in
    /// [`mix_frame`](Engine::mix_frame).
    mix_acc: u32,
    /// Last native frame generated (zero-order hold for `mix_frame`).
    hold: (i16, i16),
}

impl Engine {
    /// Heap-construct a silent engine in place. The struct is several KB of
    /// voice state; a by-value construction would materialize it on the
    /// kernel stack (64 KB, shared with the guest OUT trap path that
    /// lazily creates devices) — the same trap `OplFm` hit.
    pub fn new_boxed() -> alloc::boxed::Box<Engine> {
        // SAFETY: all-zero bytes are a valid, silent Engine by construction:
        // every field is an integer, a bool (false), or LoopMode, which is
        // repr(u8) with None = 0. Keep it that way when adding fields.
        unsafe {
            let layout = core::alloc::Layout::new::<Engine>();
            let p = alloc::alloc::alloc_zeroed(layout);
            if p.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            alloc::boxed::Box::from_raw(p as *mut Engine)
        }
    }

    /// Reset every voice to power-on silence (the GF1 reset register, a
    /// personality reset, or program cleanup). Keeps `active`.
    pub fn reset(&mut self) {
        for v in self.voices.iter_mut() {
            *v = Voice::default();
        }
        self.mix_acc = 0;
        self.hold = (0, 0);
    }

    /// Whether any participating voice is still producing samples (the
    /// pump's "audible" test, alongside the personality's write-hangover).
    pub fn any_running(&self) -> bool {
        let n = (self.active as usize).min(MAX_VOICES);
        self.voices[..n].iter().any(|v| v.running || v.ramp.running)
    }

    /// Mix `out.len()/2` interleaved-stereo frames from `mem`, OVERWRITING
    /// `out`; voice-boundary IRQ events OR-accumulate into `ev`.
    pub fn generate(&mut self, mem: &[u8], out: &mut [i16], ev: &mut Events) {
        for frame in out.chunks_exact_mut(2) {
            let (l, r) = self.step(mem, ev);
            frame[0] = l;
            frame[1] = r;
        }
    }

    /// Pull one frame at a foreign rate (the `OplFm::mix_frame` discipline):
    /// advance `native_rate / out_rate` native frames with zero-order hold on
    /// the last, so consumption stays locked to the pulling stream's cursor.
    pub fn mix_frame(
        &mut self,
        mem: &[u8],
        native_rate: u32,
        out_rate: u32,
        ev: &mut Events,
    ) -> (i16, i16) {
        let out_rate = out_rate.max(4_000); // caller-programmed; never stall
        self.mix_acc += native_rate;
        while self.mix_acc >= out_rate {
            self.mix_acc -= out_rate;
            self.hold = self.step(mem, ev);
        }
        self.hold
    }

    /// One native frame: fetch/advance every participating voice, tick its
    /// ramp, sum saturating.
    fn step(&mut self, mem: &[u8], ev: &mut Events) -> (i16, i16) {
        let n = (self.active as usize).min(MAX_VOICES);
        let (mut al, mut ar) = (0i32, 0i32);
        for vi in 0..n {
            let v = &mut self.voices[vi];
            if v.running {
                let idx = v.addr >> 32;
                let frac10 = ((v.addr >> 22) & 0x3FF) as i32;
                let s = fetch(mem, v.bits16, idx, frac10);
                let s = v.filter.apply(s);
                // s (16-bit) × log-volume gain (Q16) back to 16-bit, then
                // pan (Q12) into the i32 accumulator.
                let g = (s * volume::lin_q16(v.vol)) >> 16;
                al += (g * v.pan_l as i32) >> 12;
                ar += (g * v.pan_r as i32) >> 12;
                advance(v, vi, ev);
            }
            if v.ramp.running {
                ramp_tick(v, vi, ev);
            }
        }
        (sat16(al), sat16(ar))
    }
}

fn sat16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// Fetch the (interpolated) sample at frame `idx` + `frac10` (top 10 fraction
/// bits — the GF1 interpolates linearly in hardware). 8-bit data is signed
/// DRAM bytes scaled to 16-bit; 16-bit data is little-endian signed frames.
/// Out-of-range reads yield silence rather than trapping: guests can program
/// addresses beyond the memory they uploaded.
fn fetch(mem: &[u8], bits16: bool, idx: u64, frac10: i32) -> i32 {
    let get = |b: usize| -> u8 { mem.get(b).copied().unwrap_or(0) };
    let (s0, s1) = if bits16 {
        let b = (idx as usize).wrapping_mul(2);
        (
            i16::from_le_bytes([get(b), get(b + 1)]) as i32,
            i16::from_le_bytes([get(b + 2), get(b + 3)]) as i32,
        )
    } else {
        let b = idx as usize;
        (
            ((get(b) as i8) as i32) << 8,
            ((get(b + 1) as i8) as i32) << 8,
        )
    };
    s0 + (((s1 - s0) * frac10) >> 10)
}

/// Advance a running voice one frame and resolve start/end crossings with
/// GF1 semantics: the boundary IRQ fires on every crossing when enabled;
/// Forward wraps preserving the overshoot fraction (click-free tracker
/// loops), Bidi reflects, None stops-and-clamps unless `rollover` lets the
/// address run on past the boundary (GUS streaming players depend on that).
fn advance(v: &mut Voice, vi: usize, ev: &mut Events) {
    if v.backwards {
        let new = v.addr.wrapping_sub(v.inc);
        if new <= v.start || new > v.addr {
            boundary(v, vi, ev, /*at_start=*/ true, v.start.wrapping_sub(new));
        } else {
            v.addr = new;
        }
    } else {
        let new = v.addr.wrapping_add(v.inc);
        if new >= v.end || new < v.addr {
            boundary(v, vi, ev, /*at_start=*/ false, new.wrapping_sub(v.end));
        } else {
            v.addr = new;
        }
    }
}

fn boundary(v: &mut Voice, vi: usize, ev: &mut Events, at_start: bool, overshoot: u64) {
    if v.irq_on_end {
        ev.wave_irq |= 1 << vi;
    }
    let len = v.end.saturating_sub(v.start);
    match v.loop_mode {
        LoopMode::None => {
            if v.rollover {
                // Run on past the boundary (IRQ-without-stop streaming).
                let clamped = if at_start { v.start } else { v.end };
                v.addr = if at_start {
                    clamped.wrapping_sub(overshoot)
                } else {
                    clamped.wrapping_add(overshoot)
                };
            } else {
                v.addr = if at_start { v.start } else { v.end };
                v.running = false;
            }
        }
        LoopMode::Forward | LoopMode::Bidi if len == 0 => {
            // Degenerate loop programming; clamp-and-stop rather than spin.
            v.addr = v.start;
            v.running = false;
        }
        LoopMode::Forward => {
            let o = overshoot % len;
            v.addr = if at_start { v.end - o } else { v.start + o };
        }
        LoopMode::Bidi => {
            let o = overshoot % len;
            v.addr = if at_start { v.start + o } else { v.end - o };
            v.backwards = !v.backwards;
        }
    }
}

/// Tick a voice's volume ramp: every `1/8/64/512` frames (the GF1 dividers)
/// add the 6-bit increment in the log-volume register domain, resolving
/// floor/ceil boundaries like the wave loop (clamp / loop / bidi + IRQ).
fn ramp_tick(v: &mut Voice, vi: usize, ev: &mut Events) {
    let r = &mut v.ramp;
    if r.frames_to_next > 1 {
        r.frames_to_next -= 1;
        return;
    }
    r.frames_to_next = 1u16 << (3 * r.shift.min(3));
    let step = r.inc as i32;
    let (hit, bound) = if r.down {
        v.vol -= step;
        (v.vol <= r.floor, r.floor)
    } else {
        v.vol += step;
        (v.vol >= r.ceil, r.ceil)
    };
    if !hit {
        return;
    }
    v.vol = bound;
    if r.irq {
        ev.ramp_irq |= 1 << vi;
    }
    if r.looped {
        if r.bidi {
            r.down = !r.down;
        } else {
            v.vol = if r.down { r.ceil } else { r.floor };
        }
    } else {
        r.running = false;
    }
}

#[cfg(test)]
mod tests;
