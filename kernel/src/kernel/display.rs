//! Where pixels go, and how a frame gets there.
//!
//! The backend supplies a [`LfbDisplay`] — a format, framebuffer storage and optional
//! physical-VGA ownership — and the kernel writes into it. `present` vertically
//! expands a completed packed metal shadow and
//! drains WC stores; [`present_host`] transfers a native frame to a window.
//!
//! Pixels may occupy 2, 3, or 4 bytes. Channel layout and width are consumed
//! when the 256-entry palette is built, not in the per-pixel VGA decoder.

pub use lib::vga_render::PixelFormat;

/// How pixels are encoded in a framebuffer sink.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatSpec {
    /// GOP, VESA true-colour LFBs and hosted memory.
    Packed(PixelFormat),
    /// The fixed VGA mode-13 surface used while a physical adapter is held as
    /// a compositable sink.
    Indexed8,
}

/// Somewhere to write pixels. `Debug` prints just the size — the address and
/// channel positions would drown the boot log's platform line.
impl core::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Framebuffer {}x{}", self.width, self.height)
    }
}

/// Framebuffer storage only. Encoding belongs to the containing [`LfbDisplay`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Framebuffer {
    /// Kernel-virtual address of pixel (0,0).
    pub va: usize,
    /// Bytes per device row (the pitch, which may exceed width × pixel size).
    pub pitch: usize,
    pub width: usize,
    pub height: usize,
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

/// A software-presentable display. `bios_display` is present exactly when the
/// framebuffer belongs to a physical VGA adapter held in a fixed mode.
pub struct LfbDisplay {
    pub format: FormatSpec,
    pub framebuffer: Framebuffer,
    pub bios_display: Option<crate::kernel::platform::BiosDisplay>,
}

static mut INDEXED_RGB: [u32; 320 * 200] = [0; 320 * 200];
static mut INDEXED_PIXELS: [u8; 320 * 200] = [0; 320 * 200];

impl core::fmt::Debug for LfbDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("LfbDisplay")
            .field("format", &self.format)
            .field("framebuffer", &self.framebuffer)
            .field("bios_display", &self.bios_display.is_some())
            .finish()
    }
}

impl LfbDisplay {
    /// Establish a display sink from framebuffer storage, its pixel encoding,
    /// and optional ownership of the physical VGA producing that storage.
    /// Boot/GOP, BIOS/VBE and indexed VGA all cross this same boundary.
    pub fn from_framebuffer(
        framebuffer: Framebuffer,
        format: FormatSpec,
        bios_display: Option<crate::kernel::platform::BiosDisplay>,
    ) -> Self {
        Self { format, framebuffer, bios_display }
    }

    pub fn packed_format(&self) -> Option<PixelFormat> {
        match self.format {
            FormatSpec::Packed(format) => Some(format),
            FormatSpec::Indexed8 => None,
        }
    }

    /// Only a VGA-backed sink can yield physical-VGA authority. Other sinks
    /// are returned unchanged.
    pub fn try_into_bios_display(
        mut self,
    ) -> Result<crate::kernel::platform::BiosDisplay, Self> {
        match self.bios_display.take() {
            Some(vga) => Ok(vga),
            None => Err(self),
        }
    }

    /// Convert a completed packed shadow into this sink's framebuffer.
    pub fn present_shadow(&self, source_height: usize, shadow: &[u8]) -> usize {
        present(self, source_height, shadow)
    }

    /// Loader-provided LFBs use the platform publication hook (SFENCE on
    /// metal). A VGA-owned sink is scanned continuously by the adapter and
    /// may run on a pre-SSE CPU, so it deliberately has no fence instruction.
    fn finish_present(&self) {
        if self.bios_display.is_none() {
            finish_present();
        }
    }

    /// Convert a canonical RGB shadow into the fixed indexed VGA sink used by
    /// the native-card OSD.
    pub fn present_indexed(&self, frame: &[u32], sw: usize, sh: usize) {
        assert!(matches!(self.format, FormatSpec::Indexed8));
        let fb = &self.framebuffer;
        assert!(fb.width == 320 && fb.height == 200 && fb.pitch >= 320);
        if sw == 0 || sh == 0 || frame.len() < sw * sh {
            return;
        }
        unsafe {
            let rgb = &mut *core::ptr::addr_of_mut!(INDEXED_RGB);
            for y in 0..200 {
                let sy = y * sh / 200;
                for x in 0..320 {
                    rgb[y * 320 + x] = frame[sy * sw + x * sw / 320];
                }
            }
            let bytes = core::slice::from_raw_parts_mut(
                rgb.as_mut_ptr() as *mut u8,
                rgb.len() * 4,
            );
            crate::kernel::osd::paint(
                bytes, 320 * 4, 320, 200, 320, PixelFormat::NATIVE,
            );

            let idx = &mut *core::ptr::addr_of_mut!(INDEXED_PIXELS);
            for (dst, &c) in idx.iter_mut().zip(rgb.iter()) {
                let r = ((c >> 16) & 0xFF) as usize;
                let g = ((c >> 8) & 0xFF) as usize;
                let b = (c & 0xFF) as usize;
                let ri = (r * 5 + 127) / 255;
                let gi = (g * 5 + 127) / 255;
                let bi = (b * 5 + 127) / 255;
                *dst = (32 + ri * 36 + gi * 6 + bi) as u8;
            }
            for y in 0..200 {
                copy_bytes(
                    (fb.va + y * fb.pitch) as *mut u8,
                    idx[y * 320..].as_ptr(),
                    320,
                    fb.wide,
                );
            }
        }
        // Physical VGA continuously scans this aperture. Unlike a WC GOP/LFB
        // mapping it needs no publication fence (and legacy CPUs may not even
        // implement SFENCE).
    }
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

/// Direct-framebuffer scanout state: a palette in framebuffer format, one
/// compact completed-frame shadow, and the render/publish clock.
pub struct Scratch {
    pal: lib::vga_render::Pal,
    pal_cache: [u8; 768],
    /// Write-back shadow with one picture-width row per VGA source row.
    /// A render pass fills it atomically; vertical stretching is deferred to
    /// the following tick's GOP blit.
    surface: alloc::vec::Vec<u8>,
    /// Geometry the scanout is armed for
    /// `(w, h, out_w, out_h, panel_w, panel_h)`; any change
    /// discards a pending shadow and starts a fresh render.
    geo: (usize, usize, usize, usize, usize, usize),
    mode: Option<lib::vga_render::VgaMode>,
    /// Display time-slice within the current refresh. Phase zero is vertical
    /// retrace. At its trailing edge the whole shadow is rendered; the next
    /// phase publishes it.
    phase: usize,
    period_ticks: usize,
    /// A complete shadow exists and has not yet been published.
    ready: bool,
    /// Last time the clock ran, for liveness only ([`beam_vretrace`] reports
    /// nothing once scanout has gone quiet).
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
            mode: None,
            phase: 0,
            period_ticks: 0,
            ready: false,
            last_tick: 0,
        }
    }

    /// Allocate the scanout scratch without ever materializing its large
    /// palette arrays as a return-value temporary on the kernel stack.
    pub fn new_boxed() -> alloc::boxed::Box<Scratch> {
        let mut boxed = alloc::boxed::Box::<Scratch>::new_uninit();
        let p = boxed.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*p).pal).write(lib::vga_render::Pal::new());
            core::ptr::addr_of_mut!((*p).pal_cache).write([0; 768]);
            core::ptr::addr_of_mut!((*p).surface).write(alloc::vec::Vec::new());
            core::ptr::addr_of_mut!((*p).geo).write((0, 0, 0, 0, 0, 0));
            core::ptr::addr_of_mut!((*p).mode).write(None);
            core::ptr::addr_of_mut!((*p).phase).write(0);
            core::ptr::addr_of_mut!((*p).period_ticks).write(0);
            core::ptr::addr_of_mut!((*p).ready).write(false);
            core::ptr::addr_of_mut!((*p).last_tick).write(0);
            boxed.assume_init()
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
fn present(sink: &LfbDisplay, vga_height: usize, shadow: &[u8]) -> usize {
    let fb = &sink.framebuffer;
    let format = sink.packed_format().expect("packed present on indexed sink");
    let step = format.bytes_per_pixel as usize;
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
    sink.finish_present();
    out_w * out_h
}

/// Number of scheduler phases exposed as vertical retrace. A normal 14-tick
/// frame gets one phase; the deliberately slower TCG path keeps approximately
/// the same 49/449 VGA blanking fraction.
fn vretrace_ticks(period_ticks: usize) -> usize {
    (period_ticks * 49 / 449).max(1).min(period_ticks.saturating_sub(2).max(1))
}

/// Guest-visible vertical retrace for an active direct scanout. `None` when
/// no scanout is live (window sink, unfocused thread, real VGA), so the caller
/// can use its free-running fallback.
pub fn beam_vretrace(s: &Scratch, now_tick: u64) -> Option<bool> {
    if s.geo.1 == 0 || s.period_ticks == 0
        || now_tick.saturating_sub(s.last_tick) > 100
    {
        return None;
    }
    Some(s.phase < vretrace_ticks(s.period_ticks))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanoutAction {
    None,
    Render,
    Publish,
}

/// Advance the direct-display clock and select this tick's bounded operation.
///
/// Phase zero (and the extra blank phases on the slow path) exposes vertical
/// retrace to the guest. At its trailing edge [`render_shadow`] captures the
/// complete current VGA image and palette into write-back RAM. The next tick
/// publishes that immutable shadow to GOP. This mirrors the natural cost split
/// without first performing a 14 ms software scanout before the physical
/// display performs another one.
pub fn scanout_action(
    s: &mut Scratch,
    sink: &LfbDisplay,
    mode: lib::vga_render::VgaMode,
    now_tick: u64,
    period_ticks: usize,
) -> ScanoutAction {
    let fb = &sink.framebuffer;
    let (w, h) = lib::vga_render::dimensions(mode);
    if w == 0 || h == 0 || period_ticks < 3 {
        return ScanoutAction::None;
    }
    let (out_w, out_h) = fit_vga(fb.width, fb.height);
    if out_w < w || out_h < h {
        return ScanoutAction::None;
    }

    let format = sink.packed_format().expect("packed scanout on indexed sink");
    let step = format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    // The stretch writes one 4-byte store per output pixel, up to N per source
    // pixel, so the last row's final run reaches past the picture: the buffer
    // carries N × 4 bytes for it. Earlier rows reach into the next row, which
    // is repainted before the frame is published.
    let slack = out_w.div_ceil(w) * 4;

    let geo = (w, h, out_w, out_h, fb.width, fb.height);
    let reset = s.geo != geo
        || s.mode != Some(mode)
        || s.surface.len() != row_bytes * h + slack
        || s.period_ticks != period_ticks;
    if reset {
        s.geo = geo;
        s.surface.clear();
        s.surface.resize(row_bytes * h + slack, 0);
        s.mode = Some(mode);
        s.period_ticks = period_ticks;
        // A mode switch gets a complete shadow immediately and publishes it
        // on the following tick; there is no useful old frame to preserve.
        s.phase = vretrace_ticks(period_ticks);
        s.ready = false;
        s.last_tick = now_tick;
        unsafe { core::ptr::write_bytes(fb.va as *mut u8, 0, fb.pitch * fb.height) };
        return ScanoutAction::Render;
    }

    s.last_tick = now_tick;
    s.phase = (s.phase + 1) % period_ticks;
    let render_phase = vretrace_ticks(period_ticks);
    let publish_phase = render_phase + 1;
    if s.phase == render_phase {
        s.ready = false;
        ScanoutAction::Render
    } else if s.phase == publish_phase && s.ready {
        s.ready = false;
        ScanoutAction::Publish
    } else {
        ScanoutAction::None
    }
}

/// Render one complete VGA image into the compact write-back shadow. Palette
/// state is folded exactly once, so a completed shadow cannot contain bands
/// from different DAC generations.
pub fn render_shadow(
    s: &mut Scratch,
    sink: &LfbDisplay,
    frame: &lib::vga_render::Frame,
) -> bool {
    let fb = &sink.framebuffer;
    let format = sink.packed_format().expect("packed render on indexed sink");
    let (w, h) = lib::vga_render::dimensions(frame.mode);
    let (out_w, _) = fit_vga(fb.width, fb.height);
    let step = format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    if s.mode != Some(frame.mode)
        || s.geo.0 != w
        || s.geo.1 != h
        || s.surface.len() < row_bytes * h
    {
        return false;
    }
    s.pal.sync(frame.palette, frame.dac_mask, format, &mut s.pal_cache);
    if matches!(frame.mode, lib::vga_render::VgaMode::Planar16 { .. }) {
        s.pal.sync_planar(frame.ac);
    }
    for sy in 0..h {
        lib::vga_render::render_row_stretched(frame, sy, &s.pal, &mut s.surface, out_w);
    }
    s.ready = true;
    true
}

/// The completed packed shadow owned by the direct scanout state, as
/// `(vga_height, out_w, pixels)` — the picture alone, `out_w × vga_height`,
/// pitched by `out_w × bytes_per_pixel`. Valid for composition/publication
/// after [`scanout_action`] returns [`ScanoutAction::Publish`].
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

/// Publication state for a card that scans out its own memory — the Voodoo,
/// whose RAMDAC clocks a complete frame at every buffer swap.
///
/// The card is handed the panel's own encoding (a [`voodoo::Dac`]) and writes
/// packed destination pixels directly, exactly as the VGA path pre-encodes its
/// DAC into the sink format before rendering. What arrives here is therefore just
/// bytes, and publication is a row-per-row copy: no shadow to double-buffer
/// (the frame is already complete), no scaling, no format conversion.
pub struct NativeScanout {
    /// One frame in destination format, `w × h` at `pitch` bytes. Write-back
    /// memory: the panel is written once, by a linear copy per row.
    surface: alloc::vec::Vec<u8>,
    pitch: usize,
    dac: voodoo::Dac,
    /// Geometry the surface and the painted bars are armed for,
    /// `(w, h, panel_w, panel_h)`.
    geo: (usize, usize, usize, usize),
    fmt: Option<PixelFormat>,
}

impl NativeScanout {
    pub const fn new() -> NativeScanout {
        NativeScanout {
            surface: alloc::vec::Vec::new(),
            pitch: 0,
            dac: voodoo::Dac::native(),
            geo: (0, 0, 0, 0),
            fmt: None,
        }
    }

    /// Arm for one frame of `w × h` on `fb`. False when the frame cannot be
    /// shown — too big for the panel, which is reported once rather than
    /// leaving a silently dead screen.
    pub fn arm(&mut self, sink: &LfbDisplay, w: usize, h: usize) -> bool {
        let fb = &sink.framebuffer;
        let format = sink.packed_format().expect("card scanout on indexed sink");
        let geo = (w, h, fb.width, fb.height);
        if w == 0 || h == 0 || w > fb.width || h > fb.height {
            if self.geo != geo {
                self.geo = geo;
                crate::println!(
                    "display: {}x{} card frame does not fit the {}x{} panel — not shown",
                    w, h, fb.width, fb.height
                );
            }
            return false;
        }
        if self.fmt != Some(format) {
            self.fmt = Some(format);
            self.dac = dac_for(format);
        }
        if self.geo != geo {
            self.geo = geo;
            self.pitch = w * format.bytes_per_pixel as usize;
            self.surface.clear();
            self.surface.resize(self.pitch * h, 0);
            // Same contract as the VGA scanout: the bars around the picture
            // are painted once, when the geometry is armed.
            unsafe { core::ptr::write_bytes(fb.va as *mut u8, 0, fb.pitch * fb.height) };
        }
        true
    }

    /// Where the card writes this frame: destination pixels, row pitch, and
    /// the encoding its DAC should clock them out in.
    pub fn target(&mut self) -> (&mut [u8], usize, &voodoo::Dac) {
        (&mut self.surface, self.pitch, &self.dac)
    }

    /// Copy the armed frame to the panel, centered. One linear copy per row.
    pub fn publish(&self, sink: &LfbDisplay) {
        let fb = &sink.framebuffer;
        let format = sink.packed_format().expect("card publish on indexed sink");
        let (w, h) = (self.geo.0, self.geo.1);
        let step = format.bytes_per_pixel as usize;
        if h == 0 || self.surface.len() < self.pitch * h {
            return;
        }
        let origin =
            fb.va + ((fb.height - h) / 2) * fb.pitch + ((fb.width - w) / 2) * step;
        for y in 0..h {
            unsafe {
                copy_bytes(
                    (origin + y * fb.pitch) as *mut u8,
                    self.surface[y * self.pitch..].as_ptr(),
                    self.pitch,
                    fb.wide,
                );
            }
        }
        sink.finish_present();
    }
}

impl Default for NativeScanout {
    fn default() -> NativeScanout {
        NativeScanout::new()
    }
}

/// The panel's channel layout, as a card's DAC wants it stated.
pub fn dac_for(fmt: PixelFormat) -> voodoo::Dac {
    voodoo::Dac {
        r: (fmt.red_pos, fmt.red_size),
        g: (fmt.green_pos, fmt.green_size),
        b: (fmt.blue_pos, fmt.blue_size),
        bytes: fmt.bytes_per_pixel,
    }
}
