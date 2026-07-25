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
    /// Bare metal: device-row copies use 16-byte non-temporal stores. Real
    /// WC apertures never engage the CPU's fast-string path, so rep movsd
    /// issues one 4-byte store per cycle there; under a hypervisor the
    /// framebuffer is host-RAM-backed (effectively WB) and rep movsd's
    /// fast-string/helper paths win instead — both measured.
    pub wide: bool,
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

/// Scratch for the raster: the palette in framebuffer format, one rendered
/// source row, one full device row (borders + scaled content), and the beam.
pub struct Scratch {
    pal: lib::vga_render::Pal,
    pal_cache: [u8; 768],
    row: alloc::vec::Vec<u32>,
    /// Geometry the beam is armed for `(w, h, out_w, out_h)`; any change
    /// restarts the sweep at the top — a mode switch repaints everything,
    /// borders included, within one refresh period by construction.
    geo: (usize, usize, usize, usize),
    /// Beam position: next source row, and its output-row Bresenham state.
    sy: usize,
    oy: usize,
    yerr: usize,
    /// Fractional row credit: accrues `elapsed_ms × h`, spends `period_ms`
    /// per source row, capped at one frame of debt (a long stall skips
    /// frames instead of fast-forwarding the beam).
    acc: u64,
    last_ms: u64,
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
            row: alloc::vec::Vec::new(),
            geo: (0, 0, 0, 0),
            sy: 0,
            oy: 0,
            yerr: 0,
            acc: 0,
            last_ms: 0,
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

    .global retroos_fb_copy32_wide
    .type retroos_fb_copy32_wide, @function
    /* Wide device-row copy: 16-byte non-temporal stores to the WC
     * framebuffer — four times fewer store instructions than rep movsd.
     * The kernel swaps FPU/SSE state only at thread switch, so the guest's
     * live XMM registers are resident here: xmm0 is spilled around the
     * copy. Head loop aligns the destination to 16 (movntdq requires it);
     * the sfence keeps the NT stores ordered before the caller's
     * present-time WC drain. */
retroos_fb_copy32_wide:
    push esi
    push edi
    mov edi, dword ptr [esp + 12]
    mov esi, dword ptr [esp + 16]
    mov ecx, dword ptr [esp + 20]
    cld
    sub esp, 16
    movdqu [esp], xmm0
1:  test edi, 15
    jz 2f
    test ecx, ecx
    jz 4f
    movsd
    dec ecx
    jmp 1b
2:  mov eax, ecx
    shr eax, 2
    jz 4f
    and ecx, 3
3:  movdqu xmm0, [esi]
    movntdq [edi], xmm0
    add esi, 16
    add edi, 16
    dec eax
    jnz 3b
4:  rep movsd
    movdqu xmm0, [esp]
    add esp, 16
    sfence
    pop edi
    pop esi
    ret
    .size retroos_fb_copy32_wide, .-retroos_fb_copy32_wide
"#
);

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn retroos_fb_copy32(dst: *mut u32, src: *const u32, len: usize);
    fn retroos_fb_copy32_wide(dst: *mut u32, src: *const u32, len: usize);
}

/// Copy framebuffer pixels in their native 32-bit unit. The freestanding
/// runtime's generic `memcpy` is `rep movsb`; using MOVSD here quarters the
/// architectural transfer count and lets x86/QEMU recognize the bulk store.
///
/// `wide` selects 16-byte non-temporal stores (real hardware: ERMS fast
/// strings never engage on the WC framebuffer, so rep movsd issues one
/// 4-byte store per cycle — the wide path quarters the issue count). Under
/// TCG (`fb.slow`) rep movsd IS the fast path — one helper call — so the
/// caller keeps `wide` off there.
#[inline]
unsafe fn copy_pixels(dst: *mut u32, src: *const u32, len: usize, wide: bool) {
    #[cfg(target_arch = "x86")]
    unsafe {
        if wide {
            retroos_fb_copy32_wide(dst, src, len);
        } else {
            retroos_fb_copy32(dst, src, len);
        }
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let _ = wide; // 64-bit metal: measure before adding the SSE path
        core::arch::asm!(
            "rep movsd",
            inout("rcx") len => _,
            inout("rsi") src => _,
            inout("rdi") dst => _,
            options(nostack)
        );
    }
}

/// Vertical-blank length in beam steps (source rows). The 70 Hz VGA CRTC
/// scans 449 lines per frame with 400 visible and 49 blanked, so the blank
/// tail is 49/400 of the visible height — ≈10.9% of the period, ~1.56 ms.
/// `h·49/400` gives the hardware-exact fraction for both the 200-line
/// (double-scanned) and 400-line mode families.
fn vblank_rows(h: usize) -> usize {
    (h * 49 / 400).max(1)
}

/// The beam's guest-visible vertical-retrace state, when a beam is actively
/// sweeping this display: `Some(in_retrace)`. `None` when no raster is live
/// on this scratch (window sink, unfocused thread, real VGA) — the caller
/// falls back to its clock fabrication. This is what makes the fabricated
/// 0x3DA truthful: "in retrace" means the frame really has finished
/// painting, so retrace-raced VRAM updates land exactly as on hardware.
pub fn beam_vretrace(s: &Scratch, now_ms: u64) -> Option<bool> {
    let h = s.geo.1;
    if h == 0 || now_ms.saturating_sub(s.last_ms) > 100 {
        return None;
    }
    Some(s.sy >= h)
}

/// Cheap pre-gate for [`raster`]: would the beam step at all now? Lets the
/// event loop skip the scanout entirely on the (vast majority of) passes
/// where no step is due yet.
pub fn raster_pending(s: &Scratch, now_ms: u64, period_ms: u64) -> bool {
    let h = s.geo.1;
    if h == 0 {
        return true; // not armed yet: run once to arm the geometry
    }
    let total = (h + vblank_rows(h)) as u64;
    s.acc + now_ms.saturating_sub(s.last_ms) * total >= period_ms
}

/// Advance the raster beam and paint the band of device rows now due.
///
/// The frame is presented the way the hardware presented it: a beam sweeps
/// the display top to bottom once per refresh period, re-rendering every
/// pixel from the live VGA state as it passes — scaled content and borders
/// alike. There is no diff, no damage tracking and no idle path: correctness
/// never depends on knowing what changed (nothing can leak through a crash
/// or a mode switch), and the work per call is bounded, so the event loop
/// never stalls on a frame regardless of panel size. The games' own
/// present model (update VRAM during vertical retrace) composes with this
/// exactly as on a real VGA.
///
/// DOS modes are authored for a 4:3 display with non-square pixels, so the
/// source is fitted to the framebuffer's 4:3 rectangle: 320x200 stretched
/// 6/5 tall, 320x240 square. One pass per SOURCE row: the renderer draws the
/// row in the framebuffer's pixel format, it is stretched once into a full
/// device row (black borders at both ends), and that row is copied to every
/// output row it covers — run lengths from a Bresenham accumulator.
///
/// Returns `(pixels_written, wrapped)`; `wrapped` marks the beam finishing a
/// frame — the vertical retrace — where the caller presents.
pub fn raster(
    s: &mut Scratch,
    fb: &Framebuffer,
    frame: &lib::vga_render::Frame,
    now_ms: u64,
    period_ms: u64,
) -> (usize, bool) {
    let (w, h) = lib::vga_render::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return (0, false);
    }
    let (out_w, out_h) = if fb.width * 3 >= fb.height * 4 {
        ((fb.height * 4 / 3).min(fb.width), fb.height)
    } else {
        (fb.width, (fb.width * 3 / 4).min(fb.height))
    };
    if out_w < w || out_h < h {
        return (0, false); // no downscaling path
    }

    let (ybase, yrem) = (out_h / h, out_h % h);
    let bx = (fb.width - out_w) / 2; // left border width
    let by = (fb.height - out_h) / 2; // top border height
    // `render_row_stretched` overwrites a constant ceil(out_w/w) run per
    // source pixel; the buffer carries that much slack past the content.
    let slack = out_w.div_ceil(w);

    if s.geo != (w, h, out_w, out_h) || s.row.len() != out_w + slack {
        s.geo = (w, h, out_w, out_h);
        s.row.clear();
        s.row.resize(out_w + slack, 0);
        s.sy = 0;
        s.oy = 0;
        s.yerr = 0;
        s.acc = 0;
        s.last_ms = now_ms;
        // Mode switch: reclaim the whole panel ONCE — pillarbox bars and
        // letterbox bands included, whatever the previous mode or a console
        // print left there. From here the sweep copies only the picture
        // span, so the bars cost nothing per frame.
        unsafe {
            core::ptr::write_bytes(fb.va as *mut u32, 0, fb.stride * fb.height);
        }
    }

    // Step credit from elapsed virtual time: a sweep is `h` painted rows
    // plus a vertical-blank tail, all steps together spanning one period —
    // at most one frame of debt, at most a bounded band per call.
    let vb = vblank_rows(h);
    let total = (h + vb) as u64;
    let dt = now_ms.saturating_sub(s.last_ms);
    s.last_ms = now_ms;
    s.acc = (s.acc + dt * total).min(total * period_ms);
    let due = (s.acc / period_ms) as usize;
    let paint = due.min((h / 8).max(1));
    if paint == 0 {
        return (0, false);
    }
    s.acc -= paint as u64 * period_ms;

    // Palette synced per band, not per frame: a mid-frame DAC write shears
    // across the sweep exactly like the raster effects it was written for.
    s.pal.sync(frame.palette, fb.format, &mut s.pal_cache);

    let out = unsafe {
        core::slice::from_raw_parts_mut(fb.va as *mut u32, fb.stride * fb.height)
    };
    let mut copied = 0usize;
    let mut wrapped = false;
    for _ in 0..paint {
        if s.sy >= h {
            // Vertical blank: the beam idles below the frame. 0x3DA reads
            // this phase via `beam_vretrace`; nothing is painted.
            s.sy += 1;
            if s.sy == h + vb {
                s.sy = 0;
                s.oy = 0;
                s.yerr = 0;
            }
            continue;
        }
        lib::vga_render::render_row_stretched(frame, s.sy, &s.pal, &mut s.row, out_w);
        s.yerr += yrem;
        let rows = ybase + if s.yerr >= h { s.yerr -= h; 1 } else { 0 };
        for _ in 0..rows {
            let d = (by + s.oy) * fb.stride + bx;
            unsafe {
                copy_pixels(out.as_mut_ptr().add(d), s.row.as_ptr(), out_w, fb.wide);
            }
            copied += out_w;
            s.oy += 1;
        }
        s.sy += 1;
        if s.sy == h {
            // Frame complete: the beam enters vertical blank (the retrace
            // 0x3DA now reports) and the caller presents.
            wrapped = true;
        }
    }
    (copied, wrapped)
}
