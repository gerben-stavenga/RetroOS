//! Hosted VGA emulation: capture the guest's DAC palette from port writes and
//! render the guest screen through the reusable `lib::vga_render` core.
//!
//! This is the hosted half of the VGA passthrough-vs-emulate split. On metal the
//! real card drives the display; the interpreter has no VGA, so it models one
//! *below the arch boundary* (the platform-difference rule). The kernel's
//! `emulate_outb` forwards VGA register writes verbatim via `machine.outb`, so
//! they land on this device — we record the DAC palette here, then read the
//! video mode (BDA `0x449`) and video memory straight from guest RAM to build a
//! `Frame` for `lib::vga_render`. The renderer itself is shared with the future
//! in-RetroOS compositor; only this capture + the host display sink are
//! interpreter-specific.

use crate::devices::{register, PortIo};
use lib::vga_render::{self, Frame, VgaMode};
use std::cell::RefCell;
use std::io::Write as _;

/// BDA byte holding the current BIOS video mode (set by INT 10h AH=00).
const BDA_VIDEO_MODE: usize = 0x449;
/// Guest-physical base of the linear graphics framebuffer (mode 13h).
const VGA_GRAPHICS: usize = 0xA0000;
/// Guest-physical base of the colour text buffer (mode 3: 80×25 char+attr).
const VGA_TEXT: usize = 0xB8000;

thread_local! {
    /// The guest's DAC palette as programmed through ports 0x3C8/0x3C9: 256
    /// entries × (R,G,B), 6-bit components. Lives CPU-thread-local alongside
    /// guest RAM so the render path (same thread) reads it without locking.
    /// Seeded with the EGA defaults in [`attach`] so text mode (which usually
    /// never reprograms the DAC) renders in colour, not black-on-black.
    static PALETTE: RefCell<[u8; 768]> = const { RefCell::new([0u8; 768]) };
}

/// Virtual VGA DAC. The guest's palette loads (write index at 0x3C8, data at
/// 0x3C9 auto-incrementing across R,G,B) are recorded, and the **read side is
/// modelled too** (read index at 0x3C7, data back out of 0x3C9): palette-cycling
/// effects read entries back, rotate, and rewrite them — Prince of Persia's
/// torch flames do exactly this, and a read that answers 0xFF turns every cycled
/// entry into 0x3F/0x3F/0x3F = permanent white. Real VGA keeps separate
/// read/write indices; so do we. Other registers: writes dropped, reads report
/// the ISA "no device" value (0x3DA itself is fabricated in the kernel).
struct VgaRegs {
    windex: u8, // DAC entry currently being written (latched by 0x3C8)
    wsub: u8,   // write component within the entry: 0=R, 1=G, 2=B
    rindex: u8, // DAC entry currently being read (latched by 0x3C7)
    rsub: u8,   // read component within the entry
}

impl PortIo for VgaRegs {
    fn read(&mut self, port: u16, _width: u8) -> u32 {
        match port {
            0x3C7 => 0x03, // DAC state: last operation was a read (we just serve)
            0x3C8 => self.windex as u32,
            0x3C9 => {
                let v = PALETTE.with(|p| {
                    p.borrow()[self.rindex as usize * 3 + self.rsub as usize]
                });
                self.rsub += 1;
                if self.rsub == 3 {
                    self.rsub = 0;
                    self.rindex = self.rindex.wrapping_add(1);
                }
                v as u32
            }
            _ => 0xFFFF_FFFF, // nothing else readable; 0x3DA handled in the kernel
        }
    }
    fn write(&mut self, port: u16, _width: u8, val: u32) {
        let v = val as u8;
        match port {
            0x3C7 => {
                self.rindex = v;
                self.rsub = 0;
            }
            0x3C8 => {
                self.windex = v;
                self.wsub = 0;
            }
            0x3C9 => {
                PALETTE.with(|p| {
                    let i = self.windex as usize * 3 + self.wsub as usize;
                    p.borrow_mut()[i] = v & 0x3F;
                });
                self.wsub += 1;
                if self.wsub == 3 {
                    self.wsub = 0;
                    self.windex = self.windex.wrapping_add(1);
                }
            }
            _ => {} // SEQ/CRTC/GC/AC index+data, DAC mask: not needed to render 13h
        }
    }
}

/// Register the virtual VGA on the legacy VGA register window (0x3C0..0x3DF).
/// Call once at host bring-up; palette capture then runs for the whole session.
pub fn attach() {
    // Seed the DAC with the standard EGA/text defaults so text mode renders in
    // colour even though it never programs the DAC (mode 13h overwrites these).
    PALETTE.with(|p| *p.borrow_mut() = vga_render::fallback_palette());
    register(0x3C0, 0x3DF, Box::new(VgaRegs { windex: 0, wsub: 0, rindex: 0, rsub: 0 }));
}

/// Map the BIOS video mode to a renderable [`VgaMode`], or `None` for modes this
/// renderer doesn't handle yet (40-column text; planar EGA; unchained mode X).
fn renderable_mode(bda_mode: u8) -> Option<VgaMode> {
    match bda_mode {
        0x13 => Some(VgaMode::Mode13h),
        0x02 | 0x03 | 0x07 => Some(VgaMode::Text80x25), // 80×25 colour/mono text
        _ => None,
    }
}

/// Render the guest's current screen into an RGB framebuffer (`0x00RRGGBB` per
/// pixel), returning `(width, height, pixels)`. `None` for modes this renderer
/// doesn't handle yet (see [`renderable_mode`]). Must run on the CPU thread (it
/// reads the active guest address space). Shared by the PPM dump and the live
/// window so both see identical pixels.
pub fn render_current() -> Option<(usize, usize, Vec<u32>)> {
    let mem = crate::vcpu::mem();
    let mode = renderable_mode(mem.read::<u8>(BDA_VIDEO_MODE))?;
    let (w, h) = vga_render::dimensions(mode);
    // Mode 13h: linear A0000, one byte/pixel. Text: 80×25 char+attr at B8000.
    let (base, len) = match mode {
        VgaMode::Mode13h => (VGA_GRAPHICS, w * h),
        VgaMode::Text80x25 => (VGA_TEXT, 80 * 25 * 2),
    };
    let vram = mem.slice(base, len);
    PALETTE.with(|p| {
        let pal = p.borrow();
        let frame = Frame { mode, vram, palette: &pal, font: &lib::vga_font_8x16::FONT_8X16 };
        let mut fb = vec![0u32; w * h];
        vga_render::render(&frame, &mut fb);
        Some((w, h, fb))
    })
}

// ── Shared frame sink (the retroos-play window) ─────────────────────────────
//
// Same shape as the screendump request: a consumer on another thread flips the
// request flag; the CPU thread — the only place guest RAM and the palette are
// valid — renders at its next slice boundary and parks the frame in a shared
// slot. Headless runs never set the flag, so the slice loop pays one relaxed
// atomic load, exactly like the screendump check it sits next to.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static FRAME_REQ: AtomicBool = AtomicBool::new(false);
static FRAME: Mutex<Option<(usize, usize, Vec<u32>)>> = Mutex::new(None);

/// Ask the CPU thread for a frame at its next slice boundary (any thread).
pub fn request_frame() {
    FRAME_REQ.store(true, Ordering::Relaxed);
}

/// Take the most recently published frame, if any (any thread).
pub fn take_frame() -> Option<(usize, usize, Vec<u32>)> {
    FRAME.lock().ok()?.take()
}

/// Service a pending frame request (CPU thread, slice boundary). `None` from
/// the renderer (unhandled mode) leaves the consumer's last frame on screen.
pub(crate) fn maybe_publish() {
    if FRAME_REQ.swap(false, Ordering::Relaxed) {
        if let Some(frame) = render_current() {
            if let Ok(mut slot) = FRAME.lock() {
                *slot = Some(frame);
            }
        }
    }
}

/// If the guest is in **graphics** mode 13h, render the screen to a binary PPM
/// (P6) at `path` and return `true`. Text modes return `false` so `--screenshot`
/// keeps producing the inspectable CP437 character dump (the live window renders
/// text graphically via [`render_current`], but a file screenshot is more useful
/// as text).
pub fn try_dump_ppm(path: &str) -> bool {
    if crate::vcpu::mem().read::<u8>(BDA_VIDEO_MODE) != 0x13 {
        return false;
    }
    let Some((w, h, fb)) = render_current() else {
        return false;
    };
    write_ppm(path, w, h, &fb);
    true
}

/// Write an RGB framebuffer (`0x00RRGGBB` per pixel) as a binary PPM.
fn write_ppm(path: &str, w: usize, h: usize, fb: &[u32]) {
    let mut buf = Vec::with_capacity(w * h * 3 + 32);
    let _ = write!(buf, "P6\n{w} {h}\n255\n");
    for &px in fb {
        buf.push((px >> 16) as u8);
        buf.push((px >> 8) as u8);
        buf.push(px as u8);
    }
    let _ = std::fs::write(path, buf);
}
