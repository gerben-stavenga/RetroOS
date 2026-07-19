//! Where pixels go, and how a frame gets there.
//!
//! The backend supplies a [`Framebuffer`] — an address, a stride and a channel
//! layout, discovered once by the platform probe — and the kernel writes into
//! it. The only per-frame call back to the backend is [`present`]: "frame
//! finished, show it" (a WC drain on metal, a window upload on hosted).
//!
//! Always 32 bits per pixel; only the channel LAYOUT varies, and even that is
//! consumed once per palette change rather than per pixel, because the palette
//! table is built in the framebuffer's own format.

/// Where a channel sits in the 32-bit pixel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PixelFormat {
    pub red_pos: u8,
    pub green_pos: u8,
    pub blue_pos: u8,
}

impl PixelFormat {
    /// Re-lay `0x00RRGGBB` into this format. Runs 256 times per palette change.
    pub fn encode(self, rgb: u32) -> u32 {
        ((rgb >> 16) & 0xFF) << self.red_pos
            | ((rgb >> 8) & 0xFF) << self.green_pos
            | (rgb & 0xFF) << self.blue_pos
    }
}

/// Somewhere to write pixels. `Debug` prints just the size — the address and
/// channel positions would drown the boot log's platform line.
impl core::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Framebuffer {}x{}", self.width, self.height)
    }
}

/// Somewhere to write pixels.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Framebuffer {
    /// Kernel-virtual address of pixel (0,0).
    pub va: usize,
    /// `u32`s per row (the pitch, which may exceed `width`).
    pub stride: usize,
    pub width: usize,
    pub height: usize,
    pub format: PixelFormat,
}

/// Backend hook: the frame is finished, show it. Installed by the entry crate
/// like the portio/hostfs/socket hooks.
static mut PRESENT: fn() = || {};

pub fn set_present_hook(f: fn()) {
    unsafe { PRESENT = f };
}

pub fn present() {
    (unsafe { PRESENT })();
}

/// Scratch for the blit: the palette in framebuffer format, and one output row.
pub struct Scratch {
    lut: [u32; 256],
    lut_key: ([u8; 768], u32),
    row: alloc::vec::Vec<u32>,
}

impl Scratch {
    pub const fn new() -> Scratch {
        Scratch { lut: [0; 256], lut_key: ([0; 768], 0), row: alloc::vec::Vec::new() }
    }
}

/// Blit an 8-bit indexed frame, scaled to the framebuffer's 4:3 rectangle.
///
/// DOS modes are authored for a 4:3 display with non-square pixels, so fitting
/// the source to 4:3 — rather than scaling both axes equally — reproduces each
/// mode's pixel aspect: 320x200 stretched 6/5 tall, 320x240 square.
///
/// One pass per SOURCE row: look each source pixel up in the palette table and
/// write its run of output pixels, then copy the finished row to every output
/// row it covers. No division and no gather per output pixel — the run length
/// comes from a Bresenham accumulator, and the fill is a fixed width with `o`
/// advanced by the real amount, so the trailing overwrite is harmless.
pub fn blit_indexed(
    s: &mut Scratch,
    fb: &Framebuffer,
    src: &[u8],
    w: usize,
    h: usize,
    palette: &[u8; 768],
) {
    if w == 0 || h == 0 || src.len() < w * h {
        return;
    }
    // Largest 4:3 rectangle in the framebuffer, centred.
    let (out_w, out_h) = if fb.width * 3 >= fb.height * 4 {
        ((fb.height * 4 / 3).min(fb.width), fb.height)
    } else {
        (fb.width, (fb.width * 3 / 4).min(fb.height))
    };
    if out_w < w || out_h < h {
        return; // no downscaling path
    }
    let origin = (fb.height - out_h) / 2 * fb.stride + (fb.width - out_w) / 2;

    // Palette -> framebuffer format, rebuilt only when the DAC changes.
    let fmt_key = (fb.format.red_pos as u32) << 16
        | (fb.format.green_pos as u32) << 8
        | fb.format.blue_pos as u32;
    if s.lut_key != (*palette, fmt_key) {
        s.lut_key = (*palette, fmt_key);
        for (i, e) in s.lut.iter_mut().enumerate() {
            *e = fb.format.encode(lib::vga_render::pal_rgb_at(palette, i as u8));
        }
    }

    // Each source pixel covers `xbase` or `xbase + 1` output pixels; fill the
    // wider constant every time and step by the true amount.
    let (xbase, xrem) = (out_w / w, out_w % w);
    let (ybase, yrem) = (out_h / h, out_h % h);
    s.row.resize(out_w + xbase + 1, 0);

    let out = unsafe {
        core::slice::from_raw_parts_mut(fb.va as *mut u32, fb.stride * fb.height)
    };
    let (mut oy, mut yerr) = (0usize, 0usize);
    for sy in 0..h {
        let (mut o, mut xerr) = (0usize, 0usize);
        for &idx in &src[sy * w..sy * w + w] {
            let v = s.lut[idx as usize];
            s.row[o..o + xbase + 1].fill(v);
            xerr += xrem;
            o += xbase + if xerr >= w { xerr -= w; 1 } else { 0 };
        }
        yerr += yrem;
        let rows = ybase + if yerr >= h { yerr -= h; 1 } else { 0 };
        for _ in 0..rows {
            let d = origin + oy * fb.stride;
            out[d..d + out_w].copy_from_slice(&s.row[..out_w]);
            oy += 1;
        }
    }
}

/// Blit an already-rendered `0x00RRGGBB` frame — text, planar and split-screen
/// modes, which `vga_render` still draws whole.
pub fn blit_rgb(s: &mut Scratch, fb: &Framebuffer, px: &[u32], w: usize, h: usize) {
    if w == 0 || h == 0 || px.len() < w * h {
        return;
    }
    let (out_w, out_h) = if fb.width * 3 >= fb.height * 4 {
        ((fb.height * 4 / 3).min(fb.width), fb.height)
    } else {
        (fb.width, (fb.width * 3 / 4).min(fb.height))
    };
    if out_w < w || out_h < h {
        return;
    }
    let origin = (fb.height - out_h) / 2 * fb.stride + (fb.width - out_w) / 2;
    let (xbase, xrem) = (out_w / w, out_w % w);
    let (ybase, yrem) = (out_h / h, out_h % h);
    s.row.resize(out_w + xbase + 1, 0);
    let native = fb.format == (PixelFormat { red_pos: 16, green_pos: 8, blue_pos: 0 });
    let out = unsafe {
        core::slice::from_raw_parts_mut(fb.va as *mut u32, fb.stride * fb.height)
    };
    let (mut oy, mut yerr) = (0usize, 0usize);
    for sy in 0..h {
        let (mut o, mut xerr) = (0usize, 0usize);
        for &p in &px[sy * w..sy * w + w] {
            let v = if native { p } else { fb.format.encode(p) };
            s.row[o..o + xbase + 1].fill(v);
            xerr += xrem;
            o += xbase + if xerr >= w { xerr -= w; 1 } else { 0 };
        }
        yerr += yrem;
        let rows = ybase + if yerr >= h { yerr -= h; 1 } else { 0 };
        for _ in 0..rows {
            let d = origin + oy * fb.stride;
            out[d..d + out_w].copy_from_slice(&s.row[..out_w]);
            oy += 1;
        }
    }
}
