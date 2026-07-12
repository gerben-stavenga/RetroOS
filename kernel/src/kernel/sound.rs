//! Canonical kernel sound API — one PCM output path for every personality.
//!
//! Like [`vfs`](super::vfs), this is a *kernel* subsystem, not an machine concern.
//! It canonicalizes any source PCM — the Sound Blaster DSP wire formats today
//! (8/16-bit, mono/stereo, signed/unsigned); OSS / native producers later — into
//! one shape (**signed 16-bit, interleaved stereo**) and streams it to the
//! RetroOS canonical audio device.
//!
//! That device sits *below* the machine boundary and is reached through ordinary
//! port I/O — exactly as `vfs`→`hdd.rs` reaches the ATA disk via `arch::inb/
//! outb`, never a bespoke `Arch` method (so `trait Arch` stays minimal). The
//! hosted interpreter backs the port window with a WAV-to-disk sink (see
//! `machine-interp/src/devices.rs`, where `std` lives); metal leaves the window
//! unpopulated, so the kernel sound path is inert there and the existing SB
//! passthrough to a real card still produces sound.
//!
//! Routing is decided ONCE at boot (`platform::Audio`): the AC'97 codec
//! where one was found, the port window where a backend installed a sink,
//! nowhere otherwise — `play` just matches the type.

use core::sync::atomic::{AtomicU32, Ordering};

// RetroOS canonical audio device — a kernel-private ISA port window. It is
// *never* guest-visible: only the kernel addresses it, through `machine.outw`
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
pub fn window_present<A: crate::Arch>(machine: &mut A) -> bool {
    machine.inw(AUDIO_SIG) == SIGNATURE
}

/// Stream a block of source PCM `bytes` (`fmt`, `rate` Hz) to the canonical
/// audio output, canonicalizing to i16 stereo on the way. The sink is the
/// boot-time platform decision; SbPassthrough never produces canonical PCM
/// (the real card owns sound) and Silent drops it.
pub fn play<A: crate::Arch>(machine: &mut A, rate: u32, fmt: Format, bytes: &[u8]) {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => {
            crate::kernel::hda::play(machine, rate, fmt, bytes);
            return;
        }
        Audio::EmulatedAc97 => {
            crate::kernel::ac97::play(machine, rate, fmt, bytes);
            return;
        }
        Audio::EmulatedPortWindow => {}
        Audio::SbPassthrough | Audio::EmulatedSilent => return,
    }
    if LAST_RATE.swap(rate, Ordering::Relaxed) != rate {
        machine.outw(AUDIO_SIG, rate as u16);
    }
    let fb = fmt.frame_bytes();
    if fb == 0 {
        return;
    }
    for i in 0..bytes.len() / fb {
        let (l, r) = fmt.frame(bytes, i);
        machine.outw(AUDIO_LEFT, l as u16);
        machine.outw(AUDIO_RIGHT, r as u16);
    }
}

/// Tell the selected canonical output that the producer went idle. `park`
/// marks a real session end (DSP reset / program cleanup): the output may
/// power down its hardware fully, not just pause the stream.
pub fn stop<A: crate::Arch>(machine: &mut A, park: bool) {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::hda::stop(machine, park),
        Audio::EmulatedAc97 | Audio::EmulatedPortWindow => {}
        Audio::SbPassthrough | Audio::EmulatedSilent => {}
    }
}

/// The selected output's pipe counters, in **source-rate frames**:
/// `(written, consumed)` — frames accepted via [`play`] and frames the
/// hardware has actually claimed for playback, both since the output's
/// current stream session started. `None` when the output has no real-time
/// consumer (WAV port window, silent): there is no playback clock to read,
/// and the producer must pace itself by virtual time instead.
///
/// This is the pull side of the SB pipe model: the emulated DSP slaves its
/// guest-visible cursor (DMA counts, block IRQs) to `consumed`, so guest
/// timing derives from real playback — the same definition a real card's
/// DMA cursor has — instead of a free-running virtual clock that the sink
/// then has to absorb with a deep latency cushion.
pub fn position<A: crate::Arch>(machine: &mut A) -> Option<(u64, u64)> {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::hda::position(),
        Audio::EmulatedAc97 => crate::kernel::ac97::position(machine),
        Audio::EmulatedPortWindow | Audio::SbPassthrough | Audio::EmulatedSilent => None,
    }
}

/// Minimum pipe fill (source frames at `rate`) a position-slaved producer
/// must keep queued in the selected output: enough to cover the sink's
/// start-of-stream prime plus its claim burst (how far ahead of audible
/// playback the hardware grabs data at once). `None` when [`position`]
/// would return `None` — same routing, probed once per playback session.
pub fn min_fill(rate: u32) -> Option<u32> {
    use crate::kernel::platform::Audio;
    match crate::kernel::platform::get().audio {
        Audio::EmulatedHda => crate::kernel::hda::min_fill(rate),
        Audio::EmulatedAc97 => crate::kernel::ac97::min_fill(rate),
        Audio::EmulatedPortWindow | Audio::SbPassthrough | Audio::EmulatedSilent => None,
    }
}
