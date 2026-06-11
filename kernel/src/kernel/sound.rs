//! Canonical kernel sound API — one PCM output path for every personality.
//!
//! Like [`vfs`](super::vfs), this is a *kernel* subsystem, not an arch concern.
//! It canonicalizes any source PCM — the Sound Blaster DSP wire formats today
//! (8/16-bit, mono/stereo, signed/unsigned); OSS / native producers later — into
//! one shape (**signed 16-bit, interleaved stereo**) and streams it to the
//! RetroOS canonical audio device.
//!
//! That device sits *below* the arch boundary and is reached through ordinary
//! port I/O — exactly as `vfs`→`hdd.rs` reaches the ATA disk via `arch::inb/
//! outb`, never a bespoke `Arch` method (so `trait Arch` stays minimal). The
//! hosted interpreter backs the port window with a WAV-to-disk sink (see
//! `arch-interp/src/devices.rs`, where `std` lives); metal leaves the window
//! unpopulated, so the kernel sound path is inert there and the existing SB
//! passthrough to a real card still produces sound.
//!
//! Routing is decided ONCE at boot (`platform::Audio`): the AC'97 codec
//! where one was found, the port window where a backend installed a sink,
//! nowhere otherwise — `play` just matches the type.

use arch_abi::Arch;
use core::sync::atomic::{AtomicU32, Ordering};

// RetroOS canonical audio device — a kernel-private ISA port window. It is
// *never* guest-visible: only the kernel addresses it, through `arch.outw`
// (guest `OUT`s surface as `KernelEvent::Out` and never reach this window). The
// sample rate fits in 16 bits (every SB rate is < 65536 Hz).
const AUDIO_SIG: u16 = 0x530; // R: signature ('RA'); W: sample rate (Hz)
const AUDIO_LEFT: u16 = 0x532; // W: latch the left i16
const AUDIO_RIGHT: u16 = 0x534; // W: right i16, and commit the (L,R) frame
const SIGNATURE: u16 = 0x5241; // 'R','A' — RetroOS Audio

/// Source PCM wire format, as a producer presents it (the Sound Blaster DSP
/// digital formats: 8-bit unsigned or 16-bit signed, mono or interleaved
/// stereo). The sound layer decodes this into canonical i16 stereo.
#[derive(Clone, Copy)]
pub struct Format {
    /// Sample width in bits: 8 or 16.
    pub bits: u8,
    /// True if samples are signed (16-bit SB DMA); false if unsigned (8-bit).
    pub signed: bool,
    /// 1 = mono, 2 = interleaved stereo (L,R).
    pub channels: u8,
}

impl Format {
    /// Bytes per interleaved frame (all channels).
    pub const fn frame_bytes(self) -> usize {
        (self.bits as usize / 8) * self.channels as usize
    }

    /// Decode one channel's sample at byte offset `byte` into canonical i16.
    fn sample_at(self, bytes: &[u8], byte: usize) -> i16 {
        if self.bits == 16 {
            // 16-bit DMA is signed little-endian.
            let lo = bytes[byte] as u16;
            let hi = bytes[byte + 1] as u16;
            (lo | (hi << 8)) as i16
        } else if self.signed {
            (bytes[byte] as i8 as i16) << 8
        } else {
            // 8-bit unsigned (bias 0x80) → signed, scaled to 16-bit.
            ((bytes[byte] as i16) - 128) << 8
        }
    }

    /// Decode frame `i` into (left, right) canonical i16. Mono duplicates.
    pub(crate) fn frame(self, bytes: &[u8], i: usize) -> (i16, i16) {
        let sb = (self.bits as usize) / 8;
        let base = i * self.frame_bytes();
        if self.channels == 2 {
            (self.sample_at(bytes, base), self.sample_at(bytes, base + sb))
        } else {
            let m = self.sample_at(bytes, base);
            (m, m)
        }
    }
}

/// Last rate programmed into the device, so we only re-emit `AUDIO_SIG` on change.
static LAST_RATE: AtomicU32 = AtomicU32::new(0);

/// Does a backend-installed sink answer behind the canonical port window?
/// Pure probe — called once by `platform::probe`, never cached here.
pub fn window_present(arch: &mut crate::TheArch) -> bool {
    arch.inw(AUDIO_SIG) == SIGNATURE
}

/// Stream a block of source PCM `bytes` (`fmt`, `rate` Hz) to the canonical
/// audio output, canonicalizing to i16 stereo on the way. The sink is the
/// boot-time platform decision; SbPassthrough never produces canonical PCM
/// (the real card owns sound) and Silent drops it.
pub fn play(arch: &mut crate::TheArch, rate: u32, fmt: Format, bytes: &[u8]) {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedAc97 => {
            crate::kernel::ac97::play(arch, rate, fmt, bytes);
            return;
        }
        Audio::EmulatedPortWindow => {}
        Audio::SbPassthrough | Audio::EmulatedSilent => return,
    }
    if LAST_RATE.swap(rate, Ordering::Relaxed) != rate {
        arch.outw(AUDIO_SIG, rate as u16);
    }
    let fb = fmt.frame_bytes();
    if fb == 0 {
        return;
    }
    for i in 0..bytes.len() / fb {
        let (l, r) = fmt.frame(bytes, i);
        arch.outw(AUDIO_LEFT, l as u16);
        arch.outw(AUDIO_RIGHT, r as u16);
    }
}
