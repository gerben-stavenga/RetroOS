//! Rendering the terminal onto a framebuffer.
//!
//! The terminal itself — grid, cursor, ANSI parser — is `lib::term`, shared by
//! every embedder. This module is the part only the kernel needs: on a machine
//! with no VGA text mode, cells have to become pixels. `attach_framebuffer`
//! points it at a mapped packed framebuffer and every write is scanned out
//! through the VGA renderer as an 80×25 text frame; legacy machines attach
//! nothing and let the real card scan B8000 itself.
//!
//! The re-scan is a known wart: the terminal keeps no grid of its own, so this
//! reads back the cells it just wrote and re-renders all 400 rows per byte.
//! It goes away when the terminal owns its grid.

pub use lib::term::{term, Term, Screen, putchar};

use crate::kernel::display::{Framebuffer, PixelFormat};
use lib::vga_fonts::FONT_8X16;
use vga::{Frame, VgaMode};

/// The pixel sink attached to the emulated VGA on framebuffer-only machines.
/// Legacy BIOS leaves this unset and the real VGA scans B8000 directly.
static mut FRAMEBUFFER: Option<Framebuffer> = None;
static mut FORMAT: Option<PixelFormat> = None;
static mut PALETTE: [u8; 768] = [0; 768];

/// Immediate scanout state for the boot console. This is the same packed,
/// horizontally-stretched VGA shadow used by the timed graphics raster; boot
/// text simply renders a complete frame synchronously because no beam-driving
/// event loop exists yet.
struct Scanout {
    pal: vga::Pal,
    pal_cache: [u8; 768],
    surface: alloc::vec::Vec<u8>,
}

impl Scanout {
    const fn new() -> Scanout {
        Scanout {
            pal: vga::Pal::new(),
            pal_cache: [0; 768],
            surface: alloc::vec::Vec::new(),
        }
    }
}

static mut SCANOUT: Scanout = Scanout::new();

/// Identity Attribute-Controller palette. Text rendering consumes the first
/// sixteen entries; mode control remains zero for normal text semantics.
static TEXT_AC: [u8; 21] = {
    let mut ac = [0u8; 21];
    let mut i = 0;
    while i < 16 {
        ac[i] = i as u8;
        i += 1;
    }
    ac
};

/// Make a mapped packed framebuffer the display side of the emulated VGA.
/// Once attached, console writes still target the ordinary B8000 aperture;
/// the VGA flush hook turns changed cells into pixels.
pub fn attach_framebuffer(fb: Framebuffer, format: PixelFormat) {
    unsafe {
        FRAMEBUFFER = Some(fb);
        FORMAT = Some(format);
        PALETTE = vga::fallback_palette();
    }
    lib::term::set_text_flush(flush);
    flush();
}

/// Scan the VGA text aperture through the ordinary all-mode renderer.
fn flush() {
    let fb_p = &raw const FRAMEBUFFER;
    let Some(fb) = (unsafe { *fb_p }) else { return };
    let format_p = &raw const FORMAT;
    let Some(format) = (unsafe { *format_p }) else { return };
    let vram = unsafe {
        core::slice::from_raw_parts(lib::term::term().base as *const u8, 80 * 25 * 2)
    };
    let palette_p = &raw const PALETTE;
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram,
        planes: &[],
        ac: &TEXT_AC,
        palette: unsafe { &*palette_p },
        dac_mask: 0xFF,
        font: &FONT_8X16,
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    scanout(&fb, format, &frame);
}

fn scanout(fb: &Framebuffer, format: PixelFormat, frame: &Frame<'_>) {
    let (w, h) = vga::dimensions(frame.mode);
    let (out_w, out_h) = crate::kernel::display::fit_vga(fb.width, fb.height);
    if w == 0 || h == 0 || out_w < w || out_h < h {
        return;
    }

    // Picture-only shadow, exactly like the timed raster: the bars around it
    // were cleared once when `fbcon` mapped the framebuffer, and every mode
    // fits the same 4:3 rectangle, so they stay black without being rewritten.
    let step = format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    let slack = out_w.div_ceil(w) * 4; // final run's overlapping dword stores
    let scanout_p = &raw mut SCANOUT;
    let s = unsafe { &mut *scanout_p };
    let need = row_bytes * h + slack;
    if s.surface.len() != need {
        s.surface.resize(need, 0);
    }
    s.pal.sync(frame.palette, frame.dac_mask, format, &mut s.pal_cache);
    for sy in 0..h {
        vga::render_row_stretched(frame, sy, &s.pal, &mut s.surface, out_w);
    }
    let sink = crate::kernel::display::LfbDisplay::from_framebuffer(
        *fb,
        crate::kernel::display::FormatSpec::Packed(format),
        None,
    );
    sink.present_shadow(h, &s.surface[..row_bytes * h]);
}
