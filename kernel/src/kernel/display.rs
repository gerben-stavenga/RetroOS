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

pub use lib::vga_render::PixelFormat;

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

/// Scratch for the blit: the palette in framebuffer format, one source row and
/// one stretched output row.
pub struct Scratch {
    pal: lib::vga_render::Pal,
    pal_cache: [u8; 768],
    src: alloc::vec::Vec<u32>,
    row: alloc::vec::Vec<u32>,
}

impl Scratch {
    pub const fn new() -> Scratch {
        Scratch {
            pal: lib::vga_render::Pal::new(),
            pal_cache: [0; 768],
            src: alloc::vec::Vec::new(),
            row: alloc::vec::Vec::new(),
        }
    }
}

/// Blit a frame — ANY mode — scaled into the framebuffer's 4:3 rectangle.
///
/// DOS modes are authored for a 4:3 display with non-square pixels, so fitting
/// the source to 4:3 rather than scaling both axes equally reproduces each
/// mode's pixel aspect: 320x200 stretched 6/5 tall, 320x240 square.
///
/// One pass per SOURCE row: the renderer draws that row straight into the
/// framebuffer's pixel format, it is stretched once, then copied to every
/// output row it covers. No full-frame intermediate, no per-mode special case,
/// and nothing recomputed per output pixel — run lengths come from a Bresenham
/// accumulator and the fill is a fixed width with the cursor advanced by the
/// true amount, so the overshoot is harmlessly overwritten.
pub fn blit(s: &mut Scratch, fb: &Framebuffer, frame: &lib::vga_render::Frame) {
    let (w, h) = lib::vga_render::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return;
    }
    let (out_w, out_h) = if fb.width * 3 >= fb.height * 4 {
        ((fb.height * 4 / 3).min(fb.width), fb.height)
    } else {
        (fb.width, (fb.width * 3 / 4).min(fb.height))
    };
    if out_w < w || out_h < h {
        return; // no downscaling path
    }
    let origin = (fb.height - out_h) / 2 * fb.stride + (fb.width - out_w) / 2;
    s.pal.sync(frame.palette, fb.format, &mut s.pal_cache);

    // Each source pixel covers `xbase` or `xbase + 1` output pixels; fill the
    // wider constant every time and step by the true amount.
    let (xbase, xrem) = (out_w / w, out_w % w);
    let (ybase, yrem) = (out_h / h, out_h % h);
    s.src.resize(w, 0);
    s.row.resize(out_w + xbase + 1, 0);

    let out = unsafe {
        core::slice::from_raw_parts_mut(fb.va as *mut u32, fb.stride * fb.height)
    };
    let (mut oy, mut yerr) = (0usize, 0usize);
    for sy in 0..h {
        lib::vga_render::render_row(frame, sy, &s.pal, &mut s.src);
        let (mut o, mut xerr) = (0usize, 0usize);
        for &v in &s.src {
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
