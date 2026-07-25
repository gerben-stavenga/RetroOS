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
    /// Full-frame writes are unusually expensive (QEMU-TCG's strong-UC GOP
    /// mapping), so emulated VGA should use a conservative refresh cadence.
    pub slow: bool,
}

/// Backend hook: the frame is finished, show it. Installed by the entry crate
/// like the portio/hostfs/socket hooks.
static mut PRESENT: fn() = || {};
static DAMAGE_EPOCH: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

pub fn set_present_hook(f: fn()) {
    unsafe { PRESENT = f };
}

pub fn present() {
    (unsafe { PRESENT })();
}

/// Tell the incremental blitter that something outside it wrote the display
/// (the framebuffer console, for example), so its next frame repaints fully.
pub fn damage() {
    DAMAGE_EPOCH.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Scratch for the blit: the palette in framebuffer format, one source row,
/// one stretched output row, and the previous source image for dirty spans.
pub struct Scratch {
    pal: lib::vga_render::Pal,
    pal_cache: [u8; 768],
    src: alloc::vec::Vec<u32>,
    row: alloc::vec::Vec<u32>,
    prev: alloc::vec::Vec<u32>,
    prev_w: usize,
    prev_h: usize,
    prev_out_w: usize,
    prev_out_h: usize,
    damage_epoch: u32,
    overlay: bool,
    input_vram: alloc::vec::Vec<u8>,
    input_planes: alloc::vec::Vec<u8>,
    input_mode: Option<lib::vga_render::VgaMode>,
    input_ac: [u8; 21],
    input_palette: [u8; 768],
    input_cga_palette: [u32; 4],
    input_blink: bool,
    input_start_offset: usize,
    input_pixel_pan: usize,
    input_line_compare: usize,
}

impl Default for Scratch {
    fn default() -> Scratch {
        Scratch::new()
    }
}

impl Scratch {
    pub const fn new() -> Scratch {
        Scratch {
            pal: lib::vga_render::Pal::new(),
            pal_cache: [0; 768],
            src: alloc::vec::Vec::new(),
            row: alloc::vec::Vec::new(),
            prev: alloc::vec::Vec::new(),
            prev_w: 0,
            prev_h: 0,
            prev_out_w: 0,
            prev_out_h: 0,
            damage_epoch: 0,
            overlay: false,
            input_vram: alloc::vec::Vec::new(),
            input_planes: alloc::vec::Vec::new(),
            input_mode: None,
            input_ac: [0; 21],
            input_palette: [0; 768],
            input_cga_palette: [0; 4],
            input_blink: false,
            input_start_offset: 0,
            input_pixel_pan: 0,
            input_line_compare: 0,
        }
    }
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    r#"
    .global retroos_fb_copy32
    .type retroos_fb_copy32, @function
retroos_fb_copy32:
    push esi
    push edi
    mov edi, dword ptr [esp + 12]
    mov esi, dword ptr [esp + 16]
    mov ecx, dword ptr [esp + 20]
    cld
    rep movsd
    pop edi
    pop esi
    ret
    .size retroos_fb_copy32, .-retroos_fb_copy32
"#
);

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn retroos_fb_copy32(dst: *mut u32, src: *const u32, len: usize);
}

/// Copy framebuffer pixels in their native 32-bit unit. The freestanding
/// runtime's generic `memcpy` is `rep movsb`; using MOVSD here quarters the
/// architectural transfer count and lets x86/QEMU recognize the bulk store.
#[inline]
unsafe fn copy_pixels(dst: *mut u32, src: *const u32, len: usize) {
    #[cfg(target_arch = "x86")]
    unsafe {
        retroos_fb_copy32(dst, src, len);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rep movsd",
            inout("rcx") len => _,
            inout("rsi") src => _,
            inout("rdi") dst => _,
            options(nostack)
        );
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
pub fn blit(
    s: &mut Scratch,
    fb: &Framebuffer,
    frame: &lib::vga_render::Frame,
    overlay: bool,
) -> usize {
    let (w, h) = lib::vga_render::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return 0;
    }
    let (out_w, out_h) = if fb.width * 3 >= fb.height * 4 {
        ((fb.height * 4 / 3).min(fb.width), fb.height)
    } else {
        (fb.width, (fb.width * 3 / 4).min(fb.height))
    };
    if out_w < w || out_h < h {
        return 0; // no downscaling path
    }
    let epoch = DAMAGE_EPOCH.load(core::sync::atomic::Ordering::Relaxed);
    let external_damage = s.damage_epoch != epoch || (s.overlay && !overlay);
    let same_input = s.input_mode == Some(frame.mode)
        && s.input_blink == frame.blink
        && s.input_start_offset == frame.start_offset
        && s.input_pixel_pan == frame.pixel_pan
        && s.input_line_compare == frame.line_compare
        && s.input_cga_palette == frame.cga_palette
        && s.input_ac == *frame.ac
        && s.input_palette == *frame.palette
        && s.input_vram == frame.vram
        && s.input_planes == frame.planes;
    if same_input && !external_damage {
        s.overlay = overlay;
        return 0;
    }
    s.input_vram.clear();
    s.input_vram.extend_from_slice(frame.vram);
    s.input_planes.clear();
    s.input_planes.extend_from_slice(frame.planes);
    s.input_mode = Some(frame.mode);
    s.input_ac = *frame.ac;
    s.input_palette = *frame.palette;
    s.input_cga_palette = frame.cga_palette;
    s.input_blink = frame.blink;
    s.input_start_offset = frame.start_offset;
    s.input_pixel_pan = frame.pixel_pan;
    s.input_line_compare = frame.line_compare;

    let origin = (fb.height - out_h) / 2 * fb.stride + (fb.width - out_w) / 2;
    s.pal.sync(frame.palette, fb.format, &mut s.pal_cache);

    // Each source pixel covers `xbase` or `xbase + 1` output pixels; fill the
    // wider constant every time and step by the true amount.
    let (xbase, xrem) = (out_w / w, out_w % w);
    let (ybase, yrem) = (out_h / h, out_h % h);
    s.src.resize(w, 0);
    s.row.resize(out_w + xbase + 1, 0);
    let full = s.prev_w != w
        || s.prev_h != h
        || s.prev_out_w != out_w
        || s.prev_out_h != out_h
        || s.prev.len() != w * h
        || external_damage;
    if s.prev.len() != w * h {
        s.prev.resize(w * h, 0);
    }
    s.prev_w = w;
    s.prev_h = h;
    s.prev_out_w = out_w;
    s.prev_out_h = out_h;
    s.damage_epoch = epoch;
    s.overlay = overlay;

    let out = unsafe {
        core::slice::from_raw_parts_mut(fb.va as *mut u32, fb.stride * fb.height)
    };
    let mut copied = 0usize;
    let (mut oy, mut yerr) = (0usize, 0usize);
    for sy in 0..h {
        lib::vga_render::render_row(frame, sy, &s.pal, &mut s.src);
        let prev = &mut s.prev[sy * w..(sy + 1) * w];
        let changed = if full {
            Some((0, w))
        } else {
            let first = s.src.iter().zip(prev.iter()).position(|(a, b)| a != b);
            first.map(|first| {
                let last = s.src.iter().zip(prev.iter()).rposition(|(a, b)| a != b).unwrap();
                (first, last + 1)
            })
        };
        prev.copy_from_slice(&s.src);

        yerr += yrem;
        let rows = ybase + if yerr >= h { yerr -= h; 1 } else { 0 };
        let Some((first, end)) = changed else {
            oy += rows;
            continue;
        };
        let (mut o, mut xerr) = (0usize, 0usize);
        for &v in &s.src {
            s.row[o..o + xbase + 1].fill(v);
            xerr += xrem;
            o += xbase + if xerr >= w { xerr -= w; 1 } else { 0 };
        }
        // The scaler's Bresenham boundaries are floor(x*out_w/w). Expand only
        // the destination span covered by changed source pixels.
        let x0 = first * out_w / w;
        let x1 = (end * out_w).div_ceil(w).min(out_w);
        let len = x1 - x0;
        for _ in 0..rows {
            let d = origin + oy * fb.stride;
            unsafe {
                copy_pixels(out.as_mut_ptr().add(d + x0), s.row.as_ptr().add(x0), len);
            }
            copied += len;
            oy += 1;
        }
    }
    copied
}
