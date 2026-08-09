//! Where pixels go, and how a frame gets there.
//!
//! A [`Display`] owns one output backend. Callers only know the packed shadow
//! width and pixel encoding and hand completed shadows to [`Display::present`].
//! `present` vertically
//! expands a completed packed metal shadow and
//! drains WC stores; the host backend transfers a native frame to a window.
//!
//! Pixels may occupy 2, 3, or 4 bytes. Channel layout and width are consumed
//! when the 256-entry palette is built, not in the per-pixel VGA decoder.

pub use vga::PixelFormat;

/// Encoding of a kernel display surface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatSpec {
    Packed(PixelFormat),
    /// A paletted VBE surface whose palette belongs to the guest.
    Indexed8,
}

/// Kernel mapping of physical framebuffer storage. The VGA library never sees
/// this address or the mapping/publication policy attached to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    /// Select the measured wide-store path for real WC apertures.
    pub wide: bool,
}

/// The only display interface visible to renderers. Physical geometry, pitch,
/// mappings, publication policy and VGA ownership stay in the backend.
pub struct Display {
    pub shadow_width: usize,
    pub rgb: PixelFormat,
    backend: Backend,
}

/// Console ownership in transit. A native VGA does not become a kernel
/// render surface merely because it moves from one DOS owner to another.
pub enum DisplayHandoff {
    Surface(Display),
    NativeVga(crate::kernel::platform::NativeVga),
}

impl DisplayHandoff {
    /// Materialize a surface only for an owner that actually renders through
    /// [`Display`] (Linux or the kernel console).
    pub fn into_surface<A: crate::Arch>(
        self,
        machine: &mut A,
        bios: Option<&mut crate::kernel::bios_display::BiosDisplayWorkspace<A>>,
    ) -> Display {
        match self {
            Self::Surface(display) => display,
            Self::NativeVga(native) => Display::new_console(
                machine,
                bios.expect("native VGA surface without BIOS workspace"),
                native,
            ),
        }
    }
}

enum Backend {
    Linear(Framebuffer),
    Vbe {
        framebuffer: Framebuffer,
        native: crate::kernel::platform::NativeVga,
        pages: usize,
    },
    VbeBanked {
        native: crate::kernel::platform::NativeVga,
    },
    Vga {
        framebuffer: Framebuffer,
        native: crate::kernel::platform::NativeVga,
        saved: alloc::boxed::Box<vga::VgaState>,
    },
    Host,
    Headless,
}

impl core::fmt::Debug for Display {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Display")
            .field("shadow_width", &self.shadow_width)
            .field("rgb", &self.rgb)
            .field("backend", &match self.backend {
                Backend::Linear(_) => "linear",
                Backend::Vbe { .. } => "vbe",
                Backend::VbeBanked { .. } => "vbe-banked",
                Backend::Vga { .. } => "vga",
                Backend::Host => "host",
                Backend::Headless => "headless",
            })
            .finish()
    }
}

impl Display {
    /// Construct the kernel display mode selected once during BIOS discovery.
    /// `Platform::vbe_mode == None` means Mode 13h was the startup selection;
    /// it is not a per-call recovery policy.
    pub fn new_selected<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
    ) -> Self {
        match crate::kernel::platform::get().vbe_mode {
            Some(mode) if mode.physical_base != 0 => Self::new_vbe(machine, bios, native, mode)
                .unwrap_or_else(|_| panic!("selected VBE display mode {:#x} failed", mode.number)),
            Some(mode) => Self::new_banked_vbe(machine, bios, native, mode)
                .unwrap_or_else(|_| panic!("selected banked VBE display mode {:#x} failed", mode.number)),
            None => {
                bios.bios_set_mode(machine, &mut native, 0x13)
                    .expect("selected Mode 13h display failed");
                Self::new_vga(native)
            }
        }
    }

    /// Materialize a surface which can be updated without executing firmware.
    /// The boot/terminal console writes through `fmt::Write`, where no machine
    /// execution context exists. A selected banked VBE mode is therefore used
    /// by the DOS/OSD presenter, while this console surface remains Mode 13h.
    pub fn new_console<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
    ) -> Self {
        if let Some(mode) = crate::kernel::platform::get().vbe_mode
            && mode.physical_base != 0
        {
            return Self::new_vbe(machine, bios, native, mode)
                .unwrap_or_else(|_| panic!("selected VBE console mode {:#x} failed", mode.number));
        }
        bios.bios_set_mode(machine, &mut native, 0x13)
            .expect("Mode 13h console display failed");
        Self::new_vga(native)
    }

    pub fn from_framebuffer(
        framebuffer: Framebuffer,
        format: FormatSpec,
    ) -> Self {
        let FormatSpec::Packed(rgb) = format else {
            panic!("indexed framebuffer cannot be a kernel display")
        };
        let (shadow_width, _) = fit_vga(framebuffer.width, framebuffer.height);
        Self { shadow_width, rgb, backend: Backend::Linear(framebuffer) }
    }

    /// Establish the VGA adapter as a known packed linear Mode 13h display.
    pub fn new_vga(native: crate::kernel::platform::NativeVga) -> Self {
        let mut saved = vga::VgaState::new_boxed();
        // A legacy owner must be restored register-for-register. A VBE owner
        // is restored by its firmware mode set and framebuffer handoff; running
        // the legacy save algorithm over a live banked VBE mode corrupts it.
        if native.vbe_mode().is_none() {
            crate::kernel::drivers::vga_hw::save(&mut saved);
        }
        let mut state = vga::VgaState::new();
        let regs = vga::bios_mode_regs(0x13).expect("mode 13h register table");
        state.misc_output = regs.misc;
        state.seq = regs.seq;
        state.gc = regs.gc;
        state.crtc = regs.crtc;
        for i in 0..16 { state.ac[i] = i as u8; }
        state.ac[0x10] = 0x41;
        state.ac[0x12] = 0x0f;
        state.dac = vga::palette_rgb332();
        state.planes.resize(4 * 0x10000, 0);
        crate::kernel::drivers::vga_hw::restore(&state);
        Self {
            shadow_width: 320,
            rgb: PixelFormat::RGB332,
            backend: Backend::Vga {
                framebuffer: Framebuffer {
                    va: crate::LOW_MEM_BASE + 0xA0000,
                    pitch: 320,
                    width: 320,
                    height: 200,
                    slow: false,
                    wide: false,
                },
                native,
                saved,
            },
        }
    }

    /// Select and map a packed linear firmware mode. On failure, return the
    /// still-owned adapter so the caller can fall back to legacy VGA.
    pub fn new_vbe<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
        mode: crate::kernel::platform::VbeMode,
    ) -> Result<Self, crate::kernel::platform::NativeVga> {
        let FormatSpec::Packed(rgb) = mode.format else { return Err(native) };
        if mode.physical_base == 0 {
            return Err(native);
        }
        let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
        let bytes = usize::from(mode.pitch) * usize::from(mode.height);
        let pages = (offset + bytes).div_ceil(crate::PAGE_SIZE);
        if arch_abi::FB_WINDOW_BASE + pages * crate::PAGE_SIZE > arch_abi::FB_WINDOW_END
            || bios.bios_set_mode(machine, &mut native, mode.number).is_err()
        {
            return Err(native);
        }
        let policy = machine.framebuffer_map_policy();
        machine.map_phys_range(
            arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE,
            pages,
            u64::from(mode.physical_base) / crate::PAGE_SIZE as u64,
            policy.flags,
        );
        let framebuffer = Framebuffer {
            va: arch_abi::FB_WINDOW_BASE + offset,
            pitch: usize::from(mode.pitch),
            width: usize::from(mode.width),
            height: usize::from(mode.height),
            slow: policy.slow,
            wide: policy.wide,
        };
        let (shadow_width, _) = fit_vga(framebuffer.width, framebuffer.height);
        crate::println!("Display: VBE {}x{}x{} mode={:#x}",
            mode.width, mode.height, mode.bits_per_pixel, mode.number);
        Ok(Self {
            shadow_width,
            rgb,
            backend: Backend::Vbe { framebuffer, native, pages },
        })
    }

    /// Select a packed VBE mode whose pixels are published through its banked
    /// A000 window. The completed frame remains an ordinary compact Display
    /// shadow; firmware-owned bank selection happens only at `present_native`.
    pub fn new_banked_vbe<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
        mode: crate::kernel::platform::VbeMode,
    ) -> Result<Self, crate::kernel::platform::NativeVga> {
        let FormatSpec::Packed(rgb) = mode.format else { return Err(native) };
        if mode.physical_base != 0 || mode.window_segment == 0
            || mode.window_granularity_kb == 0 || mode.window_size_kb == 0
            || bios.bios_set_mode_request(machine, &mut native, mode.number).is_err()
        {
            return Err(native);
        }
        let (shadow_width, _) = fit_vga(usize::from(mode.width), usize::from(mode.height));
        crate::println!("Display: banked VBE {}x{}x{} mode={:#x}",
            mode.width, mode.height, mode.bits_per_pixel, mode.number);
        Ok(Self { shadow_width, rgb, backend: Backend::VbeBanked { native } })
    }

    pub fn host() -> Self {
        Self { shadow_width: 720, rgb: PixelFormat::NATIVE, backend: Backend::Host }
    }

    pub fn headless() -> Self {
        Self { shadow_width: 0, rgb: PixelFormat::NATIVE, backend: Backend::Headless }
    }

    pub fn is_headless(&self) -> bool { matches!(self.backend, Backend::Headless) }
    pub fn is_host(&self) -> bool { matches!(self.backend, Backend::Host) }
    pub fn is_vga(&self) -> bool {
        matches!(self.backend, Backend::Vbe { .. } | Backend::VbeBanked { .. } | Backend::Vga { .. })
    }
    /// OSD coordinates for a completed VGA shadow. Normal outputs retain the
    /// guest's logical width so the OSD follows the same X/Y enlargement as
    /// the picture. A selected Mode 13h surface instead uses the already-reduced shadow
    /// width and an integer source-row multiplier.
    pub(crate) fn osd_shadow_layout(
        &self,
        source_width: usize,
        shadow_width: usize,
        shadow_height: usize,
    ) -> (usize, usize) {
        match &self.backend {
            Backend::Vga { framebuffer, .. } => (
                shadow_width,
                (shadow_height / framebuffer.height).max(1),
            ),
            _ => (source_width, 1),
        }
    }
    pub fn native_vga(&self) -> Option<&crate::kernel::platform::NativeVga> {
        match &self.backend {
            Backend::Vbe { native, .. }
            | Backend::VbeBanked { native, .. }
            | Backend::Vga { native, .. } => Some(native),
            _ => None,
        }
    }
    pub fn into_native_vga<A: crate::Arch>(
        self,
        machine: &mut A,
    ) -> Result<crate::kernel::platform::NativeVga, Self> {
        match self.backend {
            Backend::Vbe { native, pages, .. } => {
                machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
                Ok(native)
            }
            Backend::VbeBanked { native, .. } => Ok(native),
            Backend::Vga { native, saved, .. } => {
                if native.vbe_mode().is_none() {
                    crate::kernel::drivers::vga_hw::restore(&saved);
                }
                Ok(native)
            }
            _ => Err(self),
        }
    }
    /// Upgrade an already-owned native VGA surface to the platform's selected
    /// OSD mode. Non-VGA sinks (host window, linear boot framebuffer) remain
    /// exactly the surface they already are.
    pub fn into_selected<A: crate::Arch>(
        self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> Self {
        match self.into_native_vga(machine) {
            Ok(native) => Self::new_selected(machine, bios, native),
            Err(display) => display,
        }
    }
    fn framebuffer(&self) -> Option<&Framebuffer> {
        match &self.backend {
            Backend::Linear(fb)
            | Backend::Vbe { framebuffer: fb, .. }
            | Backend::Vga { framebuffer: fb, .. } => Some(fb),
            _ => None,
        }
    }
    fn fit(&self) -> (usize, usize) {
        if let Backend::VbeBanked { ref native } = self.backend {
            let mode = native.vbe_mode().expect("banked VBE display lost its mode");
            return fit_vga(usize::from(mode.width), usize::from(mode.height));
        }
        let Some(fb) = self.framebuffer() else { return (self.shadow_width, 0) };
        if matches!(self.backend, Backend::Vga { .. }) {
            (fb.width, fb.height)
        } else {
            fit_vga(fb.width, fb.height)
        }
    }
    pub fn slow(&self) -> bool { self.framebuffer().is_some_and(|fb| fb.slow) }
    pub fn present(&mut self, height: usize, shadow: &[u8]) -> usize {
        match self.backend {
            Backend::Linear(_) | Backend::Vbe { .. } | Backend::Vga { .. } => {
                blit(self, height, shadow)
            }
            Backend::VbeBanked { .. } => {
                panic!("banked VBE present without BIOS display driver")
            }
            Backend::Host => present_host_shadow(self.shadow_width, height, self.rgb, shadow),
            Backend::Headless => 0,
        }
    }

    /// Publish one completed packed shadow. Most backends are plain memory
    /// sinks; a banked native VBE mode delegates the hardware operation to the
    /// BIOS display driver which owns the real-mode execution workspace.
    pub fn present_native<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: Option<&mut crate::kernel::bios_display::BiosDisplayWorkspace<A>>,
        height: usize,
        shadow: &[u8],
    ) -> usize {
        match &mut self.backend {
            Backend::VbeBanked { native } => bios
                .expect("banked VBE display without BIOS workspace")
                .present(machine, native, height, shadow)
                .unwrap_or_else(|error| panic!("banked VBE present failed: {:?}", error)),
            _ => self.present(height, shadow),
        }
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


/// Tell the backend a frame is complete.
///
/// Loader-provided LFBs use the platform publication hook (an SFENCE on
/// metal). A sink the VGA adapter owns is scanned continuously by that
/// adapter and may run on a pre-SSE CPU, so it deliberately gets no fence.
///
/// This is the one place the framebuffer publication rule is written down.
fn publish(display: &Display) {
    if !display.is_vga() {
        finish_present();
    }
}

/// Publish a completed horizontally-stretched VGA shadow. The shadow holds the
/// PICTURE only — `out_w × vga_height` — so this is pure vertical expansion:
/// each source row is copied to the output rows it covers, at the centered
/// picture origin. Format conversion already happened in the raster pass, and
/// the pillarbox/letterbox bars were painted once at the mode switch, so
/// nothing here touches a pixel outside the picture.
fn blit(display: &Display, vga_height: usize, shadow: &[u8]) -> usize {
    let fb = display.framebuffer().expect("linear display lost framebuffer");
    let format = display.rgb;
    let step = format.bytes_per_pixel as usize;
    let (out_w, out_h) = display.fit();
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
    publish(display);
    out_w * out_h
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
/// than `//lib:vga`, which the allocator-free bootloader does not link.
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

fn present_host_shadow(w: usize, h: usize, rgb: PixelFormat, shadow: &[u8]) -> usize {
    let step = rgb.bytes_per_pixel as usize;
    let Some(bytes) = w.checked_mul(h).and_then(|n| n.checked_mul(step)) else { return 0 };
    if shadow.len() < bytes { return 0; }
    let mut pixels = alloc::vec::Vec::with_capacity(w * h);
    for p in shadow[..bytes].chunks_exact(step) {
        let raw = match step {
            1 => u32::from(p[0]),
            2 => u32::from(u16::from_le_bytes([p[0], p[1]])),
            3 => u32::from(p[0]) | u32::from(p[1]) << 8 | u32::from(p[2]) << 16,
            4 => u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            _ => return 0,
        };
        let channel = |shift: u8, width: u8| -> u32 {
            if width == 0 { return 0; }
            let value = raw >> shift & ((1u32 << width) - 1);
            value * 255 / ((1u32 << width) - 1)
        };
        pixels.push(channel(rgb.red_pos, rgb.red_size) << 16
            | channel(rgb.green_pos, rgb.green_size) << 8
            | channel(rgb.blue_pos, rgb.blue_size));
    }
    present_host(w, h, &mut pixels);
    w * h
}

/// Direct-framebuffer scanout state: a palette in framebuffer format, one
/// compact completed-frame shadow, and the render/publish clock.
pub struct Scratch {
    pal: vga::Pal,
    pal_cache: [u8; 768],
    /// Write-back shadow with one picture-width row per VGA source row.
    /// A render pass fills it atomically; vertical stretching is deferred to
    /// the following tick's GOP blit.
    surface: alloc::vec::Vec<u8>,
    /// Geometry the scanout is armed for
    /// `(w, h, out_w, out_h, panel_w, panel_h)`; any change
    /// discards a pending shadow and starts a fresh render.
    geo: (usize, usize, usize, usize, usize, usize),
    mode: Option<vga::VgaMode>,
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
            pal: vga::Pal::new(),
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
            core::ptr::addr_of_mut!((*p).pal).write(vga::Pal::new());
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
    display: &Display,
    mode: vga::VgaMode,
    now_tick: u64,
    period_ticks: usize,
) -> ScanoutAction {
    let (w, h) = vga::dimensions(mode);
    if w == 0 || h == 0 || period_ticks < 3 {
        return ScanoutAction::None;
    }
    let (out_w, out_h) = display.fit();
    // A sink SMALLER than the guest image is legal: the Bresenham walk in
    // `StretchRow` shrinks as readily as it stretches, and `present` drops
    // source rows the same way. Refusing it here is what made the 320x200
    // mode-13 OSD aperture (266 px after aspect fit, i.e. narrower than every
    // guest mode including 320-wide ones) show nothing at all — and, because
    // the reset path below zeroes the framebuffer, show it as black.
    if out_w == 0 || out_h == 0 {
        return ScanoutAction::None;
    }

    let format = display.rgb;
    let step = format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    // The stretch writes one 4-byte store per output pixel, up to N per source
    // pixel, so the last row's final run reaches past the picture: the buffer
    // carries N × 4 bytes for it. Earlier rows reach into the next row, which
    // is repainted before the frame is published.
    let slack = out_w.div_ceil(w) * 4;

    let geo = (w, h, out_w, out_h, out_w, out_h);
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
        if let Some(fb) = display.framebuffer() {
            unsafe { core::ptr::write_bytes(fb.va as *mut u8, 0, fb.pitch * fb.height) };
        }
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
    display: &Display,
    frame: &vga::Frame,
) -> bool {
    let format = display.rgb;
    let (w, h) = vga::dimensions(frame.mode);
    let (out_w, _) = display.fit();
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
    if matches!(frame.mode, vga::VgaMode::Planar16 { .. }) {
        s.pal.sync_planar(frame.ac);
    }
    for sy in 0..h {
        vga::render_row_stretched(frame, sy, &s.pal, &mut s.surface, out_w);
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

/// The panel's channel layout, as a card's DAC wants it stated.
pub fn dac_for(fmt: PixelFormat) -> voodoo::Dac {
    voodoo::Dac {
        r: (fmt.red_pos, fmt.red_size),
        g: (fmt.green_pos, fmt.green_size),
        b: (fmt.blue_pos, fmt.blue_size),
        bytes: fmt.bytes_per_pixel,
    }
}
