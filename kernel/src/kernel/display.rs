//! Where pixels go, and how a frame gets there.
//!
//! The backend supplies a [`Framebuffer`] — an address, a pitch and a channel
//! layout, discovered once by the platform probe — and the kernel writes into
//! it. [`present`] vertically expands a completed packed metal shadow and
//! drains WC stores; [`present_host`] transfers a native frame to a window.
//!
//! Pixels may occupy 2, 3, or 4 bytes. Channel layout and width are consumed
//! when the 256-entry palette is built, not in the per-pixel VGA decoder.

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
    /// Bytes per device row (the pitch, which may exceed width × pixel size).
    pub pitch: usize,
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
static mut PRESENT_HOOK: fn() = || {};

pub fn set_present_hook(f: fn()) {
    unsafe { PRESENT_HOOK = f };
}

/// Complete writes to the platform display. VGA text and the timed VGA raster
/// both end here; the backend decides whether that means an `sfence`, a window
/// publication, or nothing.
pub fn finish_present() {
    (unsafe { PRESENT_HOOK })();
}

/// Largest centered 4:3 VGA picture that fits a physical framebuffer.
pub fn fit_vga(width: usize, height: usize) -> (usize, usize) {
    if width * 3 >= height * 4 {
        ((height * 4 / 3).min(width), height)
    } else {
        (width, (width * 3 / 4).min(height))
    }
}

/// Hosted completed-frame sink. This lives in the allocating kernel rather
/// than `lib::vga_render`, which is also linked by the allocator-free bootloader.
static HOST_PRESENT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn set_host_present_sink(f: fn(usize, usize, &mut alloc::vec::Vec<u32>)) {
    HOST_PRESENT.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

pub fn host_present_sink_installed() -> bool {
    HOST_PRESENT.load(core::sync::atomic::Ordering::Relaxed) != 0
}

pub fn present_host(w: usize, h: usize, pixels: &mut alloc::vec::Vec<u32>) {
    let p = HOST_PRESENT.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(usize, usize, &mut alloc::vec::Vec<u32>) =
            unsafe { core::mem::transmute(p) };
        f(w, h, pixels);
    }
}

/// Scratch for the raster: the palette in framebuffer format, a compact
/// completed-frame surface, and how far the sweep has painted.
pub struct Scratch {
    pal: lib::vga_render::Pal,
    pal_cache: [u8; 768],
    /// Write-back shadow with one picture-width row per VGA source row.
    /// The sweep paints here a band at a time; vertical stretching is
    /// deferred to the completed-frame GOP blit.
    surface: alloc::vec::Vec<u8>,
    /// Geometry the sweep is armed for
    /// `(w, h, out_w, out_h, panel_w, panel_h)`; any change
    /// restarts the sweep at the top — a mode switch repaints everything,
    /// borders included, within one refresh period by construction.
    geo: (usize, usize, usize, usize, usize, usize),
    /// How far the sweep has painted: the next source row to draw. The row
    /// the sweep should reach is derived from `phase`.
    sy: usize,
    /// Display time-slice within the current refresh. Advanced exactly once
    /// per call; missed kernel slices delay the display rather than creating
    /// catch-up debt.
    phase: usize,
    period_ticks: usize,
    /// Last time a pass ran, for liveness only ([`beam_vretrace`] reports
    /// nothing once the sweep has gone quiet).
    last_tick: u64,
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
            surface: alloc::vec::Vec::new(),
            geo: (0, 0, 0, 0, 0, 0),
            sy: 0,
            phase: 0,
            period_ticks: 0,
            last_tick: 0,
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
     * the one end-of-frame present sfence drains all row copies together. */
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

/// Copy one packed framebuffer row. Bulk traffic still moves in dwords; a
/// 16/24-bit row merely has a short 0..3-byte tail.
///
/// `wide` selects 16-byte non-temporal stores (real hardware: ERMS fast
/// strings never engage on the WC framebuffer, so rep movsd issues one
/// 4-byte store per cycle — the wide path quarters the issue count). Under
/// TCG (`fb.slow`) rep movsd IS the fast path — one helper call — so the
/// caller keeps `wide` off there. This deliberately does not fence each row:
/// the caller's single end-of-frame [`present`] drains the whole blit.
#[inline]
unsafe fn copy_bytes(dst: *mut u8, src: *const u8, len: usize, wide: bool) {
    let mut d = dst;
    let mut s = src;
    let mut left = len;

    // The wide assembly advances in dwords while aligning to 16, so feed it an
    // already-aligned destination: packed 16/24-bit pitches need byte heads.
    if wide {
        while left != 0 && d as usize & 15 != 0 {
            unsafe { *d = *s };
            d = unsafe { d.add(1) };
            s = unsafe { s.add(1) };
            left -= 1;
        }
    }
    let dwords = left / 4;
    #[cfg(target_arch = "x86")]
    unsafe {
        if wide && dwords != 0 {
            retroos_fb_copy32_wide(d as *mut u32, s as *const u32, dwords);
        } else {
            retroos_fb_copy32(d as *mut u32, s as *const u32, dwords);
        }
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let _ = wide; // 64-bit metal: measure before adding the SSE path
        core::arch::asm!(
            "rep movsd",
            inout("rcx") dwords => _,
            inout("rsi") s => _,
            inout("rdi") d => _,
            options(nostack)
        );
    }
    let done = dwords * 4;
    d = unsafe { d.add(done) };
    s = unsafe { s.add(done) };
    left -= done;
    while left != 0 {
        unsafe { *d = *s };
        d = unsafe { d.add(1) };
        s = unsafe { s.add(1) };
        left -= 1;
    }
}

/// Publish a completed horizontally-stretched VGA shadow. The shadow holds the
/// PICTURE only — `out_w × vga_height` — so this is pure vertical expansion:
/// each source row is copied to the output rows it covers, at the centered
/// picture origin. Format conversion already happened in the raster pass, and
/// the pillarbox/letterbox bars were painted once at the mode switch, so
/// nothing here touches a pixel outside the picture.
pub fn present(fb: &Framebuffer, vga_height: usize, shadow: &[u8]) -> usize {
    let step = fb.format.bytes_per_pixel as usize;
    let (out_w, out_h) = fit_vga(fb.width, fb.height);
    let row_bytes = out_w * step;
    if vga_height == 0 || shadow.len() < row_bytes * vga_height {
        return 0;
    }
    let bx = (fb.width - out_w) / 2;
    let by = (fb.height - out_h) / 2;
    let (ybase, yrem) = (out_h / vga_height, out_h % vga_height);
    let origin = fb.va + by * fb.pitch + bx * step;

    let mut oy = 0usize;
    let mut yerr = 0usize;
    for sy in 0..vga_height {
        yerr += yrem;
        let carry = (yerr >= vga_height) as usize;
        let rows = ybase + carry;
        yerr -= carry * vga_height;
        let src = shadow[sy * row_bytes..(sy + 1) * row_bytes].as_ptr();
        for _ in 0..rows {
            unsafe {
                copy_bytes((origin + oy * fb.pitch) as *mut u8, src, row_bytes, fb.wide);
            }
            oy += 1;
        }
    }
    finish_present();
    out_w * out_h
}

/// Vertical-blank length in beam steps (source rows). The 70 Hz VGA CRTC
/// scans 449 lines per frame with 400 visible and 49 blanked, so the blank
/// tail is 49/400 of the visible height — ≈10.9% of the period, ~1.56 ms.
/// `h·49/400` gives the hardware-exact fraction for both the 200-line
/// (double-scanned) and 400-line mode families.
fn vblank_rows(h: usize) -> usize {
    (h * 49 / 400).max(1)
}

/// The sweep's guest-visible vertical-retrace state, when one is actively
/// running on this display: `Some(in_retrace)`. `None` when no raster is live
/// on this scratch (window sink, unfocused thread, real VGA) — the caller
/// falls back to its clock fabrication. This is what makes the fabricated
/// 0x3DA truthful: "in retrace" means the frame really has finished
/// painting, so retrace-raced VRAM updates land exactly as on hardware.
pub fn beam_vretrace(s: &Scratch, now_tick: u64) -> Option<bool> {
    let h = s.geo.1;
    if h == 0 || now_tick.saturating_sub(s.last_tick) > 100 {
        return None;
    }
    Some(s.sy >= h)
}

/// The source rows the next [`raster`] can touch, as `(first, count)` — what
/// the caller must have in the guest snapshot before calling it. A pass paints
/// a band, not a frame, so snapshotting the whole aperture copies several times
/// more guest memory than the beam reads.
///
/// No forecast: a pass paints at most `h/8` rows by construction, so the band
/// is the beam's current row plus that cap. The whole frame only when the beam
/// is about to restart at row 0 — unarmed, armed for another mode, or wrapping
/// through vertical blank into the next sweep.
pub fn beam_band(s: &Scratch, w: usize, h: usize) -> (usize, usize) {
    if (s.geo.0, s.geo.1) != (w, h) || h == 0 {
        return (0, h);
    }
    let cap = (h / 8).max(1);
    if s.sy + cap > h + vblank_rows(h) {
        return (0, h); // may wrap and resume at the top
    }
    let first = s.sy.min(h);
    ((first), (first + cap).min(h) - first)
}

/// Advance one display time slice, paint its source-row band, and say whether
/// that finished a frame.
///
/// The frame is presented the way the hardware presented it: a sweep runs down
/// a cached shadow once per refresh period, re-rendering every pixel from the
/// live VGA state as it passes — so mid-frame register and palette writes shear
/// exactly as the raster effects they were written for expect. Pacing is a
/// small discrete counter: 14 processed kernel slices per normal refresh, 50
/// for the conservative slow-framebuffer path. If slices are missed, refresh
/// simply runs late; there is no wall-clock catch-up.
///
/// At vertical blank the completed shadow is copied to the GOP framebuffer in
/// one burst. GOP scanout has no portable vblank/page-flip interface and runs
/// on a clock unrelated to this sweep; exposing each software band directly
/// made the physical display sample a ladder of different update times. The
/// single publication keeps the expensive render work distributed while
/// reducing that race to the shortest operation GOP permits.
///
/// DOS modes are authored for a 4:3 display with non-square pixels, so the
/// source is fitted to the framebuffer's 4:3 rectangle: 320x200 stretched
/// 6/5 tall, 320x240 square. One pass per SOURCE row: the renderer draws the
/// row in the framebuffer's pixel format and stretches it horizontally into
/// the compact `out_w × h` shadow — the picture alone, no borders. The
/// completion blit copies each source row to its vertically stretched output
/// run, using a Bresenham accumulator for non-integral scale factors.
///
/// Returns whether a coherent shadow completed as the beam entered vertical
/// retrace. Publication is deliberately left to the event-loop caller, which
/// owns kernel composition such as the OSD.
pub fn raster(
    s: &mut Scratch,
    fb: &Framebuffer,
    frame: &lib::vga_render::Frame,
    now_tick: u64,
    period_ticks: usize,
) -> bool {
    let (w, h) = lib::vga_render::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return false;
    }
    let (out_w, out_h) = fit_vga(fb.width, fb.height);
    if out_w < w || out_h < h {
        return false; // no downscaling path
    }

    let step = fb.format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    // The stretch writes one 4-byte store per output pixel, up to N per source
    // pixel, so the last row's final run reaches past the picture: the buffer
    // carries N × 4 bytes for it. Earlier rows reach into the next row, which
    // is repainted before the frame is published.
    let slack = out_w.div_ceil(w) * 4;

    if period_ticks == 0 {
        return false;
    }
    let geo = (w, h, out_w, out_h, fb.width, fb.height);
    let reset = s.geo != geo
        || s.surface.len() != row_bytes * h + slack
        || s.period_ticks != period_ticks;
    if reset {
        s.geo = geo;
        s.surface.clear();
        s.surface.resize(row_bytes * h + slack, 0);
        s.sy = 0;
        s.phase = 0;
        s.period_ticks = period_ticks;
        s.last_tick = now_tick;
        // Mode switch: reclaim the whole panel ONCE — pillarbox bars and
        // letterbox bands included, whatever the previous mode or a console
        // print left there. The shadow carries the picture only, so from here
        // every present copies the picture span and the bars cost nothing.
        unsafe { core::ptr::write_bytes(fb.va as *mut u8, 0, fb.pitch * fb.height) };
    }

    // One call is one display time slice. Map the new phase to a beam target;
    // the forward distance is this slice's band. The explicit phase rollover
    // preserves the refresh edge without retaining elapsed-time debt.
    let vb = vblank_rows(h);
    let total = h + vb;
    s.last_tick = now_tick;
    s.phase += 1;
    if s.phase == period_ticks {
        s.phase = 0;
    }
    let target = s.phase * total / period_ticks;
    let paint = (total + target - s.sy) % total;
    if paint == 0 {
        return false;
    }

    // Palette synced per band, not per frame: a mid-frame DAC write shears
    // across the sweep exactly like the raster effects it was written for.
    s.pal.sync(frame.palette, fb.format, &mut s.pal_cache);
    if matches!(frame.mode, lib::vga_render::VgaMode::Planar16 { .. })
        && (reset || s.phase == 0)
    {
        s.pal.sync_planar(frame.ac);
    }

    for _ in 0..paint {
        if s.sy >= h {
            // Vertical blank: the beam idles below the frame. 0x3DA reads
            // this phase via `beam_vretrace`; nothing is painted.
            s.sy += 1;
            if s.sy == h + vb {
                s.sy = 0;
            }
            continue;
        }
        // No pre-clear: `render_row_stretched` overwrites the row's whole
        // `out_w` span, and the overlapping-store tail spills into the next
        // row, which is painted before this frame is published.
        lib::vga_render::render_row_stretched(frame, s.sy, &s.pal, &mut s.surface, out_w);
        s.sy += 1;
        if s.sy == h {
            // Frame complete: the beam enters vertical blank. The event loop
            // must publish this coherent shadow before any next-frame row is
            // allowed to overwrite it. Any remaining blank-time distance is
            // harmlessly absorbed by the next display slice.
            return true;
        }
    }
    false
}

/// The completed packed shadow owned by a raster scratch, as
/// `(vga_height, out_w, pixels)` — the picture alone, `out_w × vga_height`,
/// pitched by `out_w × bytes_per_pixel`. Valid for composition/publication
/// when [`raster`] has just returned `true`.
pub fn completed_shadow(s: &mut Scratch) -> Option<(usize, usize, &mut [u8])> {
    let h = s.geo.1;
    let out_w = s.geo.2;
    let stride = out_w.checked_mul(s.pal.fmt.bytes_per_pixel as usize)?;
    let len = stride.checked_mul(h)?;
    if h == 0 || s.surface.len() < len {
        return None;
    }
    Some((h, out_w, &mut s.surface[..len]))
}
