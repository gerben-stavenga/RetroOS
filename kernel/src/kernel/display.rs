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

impl compact_fmt::Format for FormatSpec {
    fn format(
        &self,
        out: &mut dyn compact_fmt::Write,
        _: compact_fmt::FormatSpec,
    ) -> compact_fmt::Result {
        match self {
            Self::Packed(rgb) => compact_fmt::write!(
                out,
                "Packed({}:{}@{},{}@{},{}@{})",
                rgb.bytes_per_pixel, rgb.red_size, rgb.red_pos, rgb.green_size,
                rgb.green_pos, rgb.blue_size, rgb.blue_pos,
            ),
            Self::Indexed8 => out.write_str("Indexed8"),
        }
    }
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

/// Dense unscaled pixels plus the reusable row used to pack one output scanline.
pub(crate) struct NativeSource<'a> {
    pub width: usize,
    pub height: usize,
    pub pixels: &'a [u32],
    pub row: &'a mut alloc::vec::Vec<u8>,
}

/// The only display interface visible to renderers. Physical geometry, pitch,
/// mappings, publication policy and VGA ownership stay in the backend.
pub struct Display {
    pub shadow_width: usize,
    pub rgb: PixelFormat,
    programmable_ramp: bool,
    voodoo_ramp_generation: Option<u64>,
    /// Physical-format staging used only within native-surface presentation.
    /// Retained producers always keep their unscaled `u32` content.
    present_pixels: alloc::vec::Vec<u8>,
    backend: Backend,
}

/// Scanout ownership between complete personality states. A physical handoff
/// carries only operable access to the adapter; authoritative guest VGA state
/// remains in the outgoing/incoming `EmulatedVga`, while the persistent BIOS
/// workspace answers current firmware mode and bank queries.
pub enum DisplayHandoff {
    Surface(Display),
    Vga(crate::kernel::platform::VgaCap),
}

/// Display ownership retained across destruction of the currently active
/// address space. Ordinary focus/error exit restores a snapshot; successful
/// DOS EXEC return transfers the child's complete VGA and lets it replace the
/// parent's recovery image after the parent space is active.
pub enum ExitDisplay {
    Restore(DisplayHandoff),
    DosReplace(crate::kernel::bios_display::DosVideo),
}

impl ExitDisplay {
    pub fn into_surface<A: crate::Arch>(
        self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> Display {
        match self {
            Self::Restore(display) => display.into_surface(machine, bios),
            Self::DosReplace(mut vga) => {
                crate::kernel::dos::release_fullscreen(&mut vga, machine, bios)
                    .into_surface(machine, bios)
            }
        }
    }
}

impl DisplayHandoff {
    pub fn into_surface<A: crate::Arch>(
        self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> Display {
        match self {
            Self::Surface(display) => display,
            Self::Vga(native) => Display::new_selected(
                machine,
                bios,
                native,
            ),
        }
    }

    /// Materialize the dedicated packed surface chosen for SST-1 scanout.
    /// Non-VGA surfaces (UEFI/hosted) are already in their native format.
    pub fn into_voodoo_surface<A: crate::Arch>(
        self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> Display {
        match self {
            Self::Surface(display) => display,
            Self::Vga(native) => Display::new_voodoo_selected(machine, bios, native),
        }
    }

    pub fn from_surface<A: crate::Arch>(display: Display, machine: &mut A) -> Self {
        match display.into_native_capability(machine) {
            Ok(native) => Self::Vga(native),
            Err(display) => Self::Surface(display),
        }
    }
}

enum Backend {
    Linear(Framebuffer),
    Vga {
        native: crate::kernel::platform::VgaCap,
        scanout: VgaScanout,
    },
    Host,
    Headless,
}

enum VgaScanout {
    Mode13 {
        framebuffer: Framebuffer,
        saved: alloc::boxed::Box<vga::VgaState>,
    },
    VbeLinear {
        framebuffer: Framebuffer,
        pages: usize,
    },
    VbeBanked {
        mode: crate::kernel::platform::VbeMode,
        current_bank: u16,
    },
}

impl core::fmt::Debug for Display {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Display")
            .field("shadow_width", &self.shadow_width)
            .field("rgb", &self.rgb)
            .field("backend", &match self.backend {
                Backend::Linear(_) => "linear",
                Backend::Vga { scanout: VgaScanout::Mode13 { .. }, .. } => "vga-mode13",
                Backend::Vga { scanout: VgaScanout::VbeLinear { .. }, .. } => "vga-vbe-linear",
                Backend::Vga { scanout: VgaScanout::VbeBanked { .. }, .. } => "vga-vbe-banked",
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
        native: crate::kernel::platform::VgaCap,
    ) -> Self {
        Self::new_selected_mode(
            machine, bios, native, crate::kernel::platform::get().vbe_mode,
        )
    }

    pub fn new_voodoo_selected<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        native: crate::kernel::platform::VgaCap,
    ) -> Self {
        Self::new_selected_mode(
            machine,
            bios,
            native,
            crate::kernel::platform::get().voodoo_vbe_mode,
        )
    }

    fn new_selected_mode<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::VgaCap,
        selected: Option<crate::kernel::platform::VbeDisplayMode>,
    ) -> Self {
        match selected.map(|mode| mode.into_parts()) {
            Some((mode, rgb, crate::kernel::platform::VbeDisplayScanout::Linear {
                offset, pages,
            })) => Self::new_vbe(machine, bios, native, mode, rgb, offset, pages),
            Some((mode, rgb, crate::kernel::platform::VbeDisplayScanout::Banked)) =>
                Self::new_banked_vbe(machine, bios, native, mode, rgb),
            None => {
                native.bios_set_mode(machine, bios, 0x13);
                Self::new_vga(native)
            }
        }
    }

    pub fn from_framebuffer(
        framebuffer: Framebuffer,
        rgb: PixelFormat,
    ) -> Self {
        let (shadow_width, _) = fit_vga(framebuffer.width, framebuffer.height);
        Self { shadow_width, rgb, programmable_ramp: false,
            voodoo_ramp_generation: None, present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Linear(framebuffer) }
    }

    /// Establish the VGA adapter as a known packed linear Mode 13h display.
    pub fn new_vga(native: crate::kernel::platform::VgaCap) -> Self {
        let mut saved = vga::VgaState::new_boxed();
        // A legacy owner must be restored register-for-register. A VBE owner
        // is restored by its firmware mode set and framebuffer handoff; running
        // the legacy save algorithm over a live banked VBE mode corrupts it.
        crate::kernel::drivers::vga_hw::save(
            &native,
            &mut saved,
            crate::kernel::platform::get().vga_readback,
        );
        let mut state = vga::VgaState::new();
        let regs = vga::bios_mode13_regs();
        state.misc_output = regs.misc;
        state.seq = regs.seq;
        state.gc = regs.gc;
        state.crtc = regs.crtc;
        for i in 0..16 { state.ac[i] = i as u8; }
        state.ac[0x10] = 0x41;
        state.ac[0x12] = 0x0f;
        state.dac = vga::palette_rgb332();
        state.planes.resize(4 * 0x10000, 0);
        crate::kernel::drivers::vga_hw::restore(&native, &state);
        Self {
            shadow_width: 320,
            rgb: PixelFormat::RGB332,
            programmable_ramp: false,
            voodoo_ramp_generation: None,
            present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Vga {
                native,
                scanout: VgaScanout::Mode13 {
                    framebuffer: Framebuffer {
                    va: crate::LOW_MEM_BASE + 0xA0000,
                    pitch: 320,
                    width: 320,
                    height: 200,
                    slow: false,
                    wide: false,
                },
                    saved,
                },
            },
        }
    }

    /// Select and map a packed linear firmware mode validated by BIOS discovery.
    fn new_vbe<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        rgb: PixelFormat,
        offset: usize,
        pages: usize,
    ) -> Self {
        native.bios_set_mode(machine, bios, mode.number);
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
        crate::compact_println!("Display: VBE {}x{}x{} mode={:#x}",
            mode.width, mode.height, mode.bits_per_pixel, mode.number);
        Self {
            shadow_width,
            rgb,
            programmable_ramp: mode.programmable_ramp,
            voodoo_ramp_generation: None,
            present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Vga {
                native,
                scanout: VgaScanout::VbeLinear { framebuffer, pages },
            },
        }
    }

    /// Select a packed VBE mode whose pixels are published through its banked
    /// A000 window. The completed frame remains an ordinary compact Display
    /// shadow; firmware-owned bank selection happens only at [`Self::present`].
    fn new_banked_vbe<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        rgb: PixelFormat,
    ) -> Self {
        native.bios_set_mode_request(machine, bios, mode.number);
        let (shadow_width, _) = fit_vga(usize::from(mode.width), usize::from(mode.height));
        crate::compact_println!("Display: banked VBE {}x{}x{} mode={:#x}",
            mode.width, mode.height, mode.bits_per_pixel, mode.number);
        Self {
            shadow_width,
            rgb,
            programmable_ramp: mode.programmable_ramp,
            voodoo_ramp_generation: None,
            present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Vga {
                native,
                scanout: VgaScanout::VbeBanked { mode, current_bank: 0 },
            },
        }
    }

    pub fn host() -> Self {
        Self { shadow_width: 720, rgb: PixelFormat::NATIVE,
            programmable_ramp: false, voodoo_ramp_generation: None,
            present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Host }
    }

    pub fn headless() -> Self {
        Self { shadow_width: 0, rgb: PixelFormat::NATIVE,
            programmable_ramp: false, voodoo_ramp_generation: None,
            present_pixels: alloc::vec::Vec::new(),
            backend: Backend::Headless }
    }

    pub fn is_headless(&self) -> bool { matches!(self.backend, Backend::Headless) }
    pub fn is_host(&self) -> bool { matches!(self.backend, Backend::Host) }
    pub fn is_vga(&self) -> bool {
        matches!(self.backend, Backend::Vga { .. })
    }

    /// Install the SST-1 gamma table in a programmable direct-colour VBE
    /// mode. A rejected firmware call permanently selects the CPU fallback.
    pub fn program_voodoo_ramp<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        generation: u64,
        ramp: &mut [u8; 256 * 4],
    ) -> bool {
        if !self.programmable_ramp { return false; }
        if self.voodoo_ramp_generation == Some(generation) { return true; }
        let Backend::Vga { native, .. } = &mut self.backend else { return false };
        let mut regs = crate::Regs::empty();
        regs.rax = 0x4F09;
        regs.rbx = 0;
        regs.rcx = 256;
        regs.rdx = 0;
        let ok = native.bios_palette_call(
            machine, bios, &mut regs, Some(ramp), true, true,
        ).is_ok() && regs.rax as u16 == 0x004F;
        if ok {
            self.voodoo_ramp_generation = Some(generation);
        } else {
            self.programmable_ramp = false;
            crate::compact_println!("VBE: programmable direct-colour ramp rejected; using CPU gamma");
        }
        ok
    }

    /// VGA software rendering expects an identity output ramp after Voodoo
    /// gives the display back.
    pub fn restore_voodoo_ramp<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) {
        if self.voodoo_ramp_generation.is_none() { return; }
        let mut ramp = [0u8; 256 * 4];
        for (v, entry) in ramp.chunks_exact_mut(4).enumerate() {
            entry.copy_from_slice(&[v as u8, v as u8, v as u8, 0]);
        }
        let Backend::Vga { native, .. } = &mut self.backend else { return };
        let mut regs = crate::Regs::empty();
        regs.rax = 0x4F09;
        regs.rcx = 256;
        if native.bios_palette_call(
            machine, bios, &mut regs, Some(&mut ramp), true, true,
        ).is_ok() && regs.rax as u16 == 0x004F
        {
            self.voodoo_ramp_generation = None;
        }
    }
    /// The vertical stretch the present step applies after the compositor has
    /// painted the OSD window. The shadow is wide-and-short: `render_shadow` stretches
    /// each mode row HORIZONTALLY to the output width, but keeps the
    /// mode's row count — a 320x200 game on a 480-line output is a
    /// 640x200 shadow whose rows the sink expands x2.4 afterward. The
    /// OSD must divide its cell height by this factor or its glyphs
    /// come out tall-and-narrow on every scaled-up low mode.
    pub fn composition_scale_y(&self, shadow_height: usize) -> usize {
        let (_, out_h) = self.fit();
        (out_h / shadow_height.max(1)).max(1)
    }
    pub fn vga_capability(&self) -> Option<&crate::kernel::platform::VgaCap> {
        match &self.backend {
            Backend::Vga { native, .. } => Some(native),
            _ => None,
        }
    }
    pub fn into_native_capability<A: crate::Arch>(
        self,
        machine: &mut A,
    ) -> Result<crate::kernel::platform::VgaCap, Self> {
        match self.backend {
            Backend::Vga { native, scanout } => {
                match scanout {
                    VgaScanout::Mode13 { saved, .. } => {
                        crate::kernel::drivers::vga_hw::restore(&native, &saved);
                    }
                    VgaScanout::VbeLinear { pages, .. } => {
                        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
                    }
                    VgaScanout::VbeBanked { .. } => {}
                }
                Ok(native)
            }
            _ => Err(self),
        }
    }
    fn framebuffer(&self) -> Option<&Framebuffer> {
        match &self.backend {
            Backend::Linear(fb)
            | Backend::Vga { scanout: VgaScanout::Mode13 { framebuffer: fb, .. }, .. }
            | Backend::Vga { scanout: VgaScanout::VbeLinear { framebuffer: fb, .. }, .. } => Some(fb),
            _ => None,
        }
    }
    fn fit(&self) -> (usize, usize) {
        if let Backend::Vga { scanout: VgaScanout::VbeBanked { mode, .. }, .. } = &self.backend {
            return fit_vga(usize::from(mode.width), usize::from(mode.height));
        }
        let Some(fb) = self.framebuffer() else { return (self.shadow_width, 0) };
        if matches!(self.backend, Backend::Vga { scanout: VgaScanout::Mode13 { .. }, .. }) {
            (fb.width, fb.height)
        } else {
            fit_vga(fb.width, fb.height)
        }
    }
    /// Output canvas used by the shared desktop. Hosted windows follow the
    /// producer's natural size; a physical surface uses its already-selected
    /// picture area so composition reaches [`Self::present`] without another
    /// implicit scale.
    pub fn composition_size(
        &self,
        natural_width: usize,
        natural_height: usize,
    ) -> (usize, usize) {
        if matches!(self.backend, Backend::Host | Backend::Headless) {
            (natural_width, natural_height)
        } else {
            self.fit()
        }
    }
    pub fn slow(&self) -> bool { self.framebuffer().is_some_and(|fb| fb.slow) }

    /// Fill the display's fitted rectangle from one dense native word image.
    /// Each `u32` already contains this display's encoded pixel bits.
    /// Horizontal packing/enlargement happens here, after the producer has
    /// completed its unscaled `width * height` words. At most one packed row
    /// is staged; there is no scaled retained frame.
    pub fn present_native<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        width: usize,
        height: usize,
        pixels: &[u32],
    ) -> usize {
        let Some(words) = width.checked_mul(height) else { return 0 };
        if width == 0 || height == 0 || pixels.len() < words {
            return 0;
        }
        let format = self.rgb;
        let (out_w, out_h) = self.fit();
        let scratch = &mut self.present_pixels;
        match &mut self.backend {
            Backend::Linear(framebuffer)
            | Backend::Vga {
                scanout: VgaScanout::Mode13 { framebuffer, .. }
                    | VgaScanout::VbeLinear { framebuffer, .. },
                ..
            } => blit_native(
                framebuffer, format, out_w, out_h,
                NativeSource { width, height, pixels, row: scratch },
            ),
            Backend::Vga {
                native,
                scanout: VgaScanout::VbeBanked { mode, current_bank },
            } => native.bios_present_native(
                machine, bios, *mode, current_bank,
                NativeSource { width, height, pixels, row: scratch },
            ).unwrap_or_else(|error| lib::compact_panic!("banked VBE present failed: {:?}", error)),
            Backend::Host => {
                let bytes = unsafe {
                    core::slice::from_raw_parts(pixels.as_ptr().cast::<u8>(), words * 4)
                };
                present_host_shadow(width, height, PixelFormat::NATIVE, bytes)
            }
            Backend::Headless => 0,
        }
    }

    /// Publish one completed packed compositor shadow.
    pub fn present<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        height: usize,
        shadow: &mut [u8],
    ) -> usize {
        let format = self.rgb;
        let (out_w, out_h) = self.fit();
        let stride = self.shadow_width * format.bytes_per_pixel as usize;
        if height == 0 || shadow.len() < stride * height {
            return 0;
        }
        if matches!(self.backend, Backend::Linear(_)) {
            return self.present_linear(height, shadow).unwrap_or(0);
        }
        match &mut self.backend {
            Backend::Vga {
                scanout: VgaScanout::Mode13 { framebuffer, .. }
                    | VgaScanout::VbeLinear { framebuffer, .. },
                ..
            } => blit(framebuffer, format, out_w, out_h, height, shadow),
            Backend::Vga {
                native,
                scanout: VgaScanout::VbeBanked { mode, current_bank },
            } => native.bios_present(machine, bios, *mode, current_bank, height, shadow)
                    .unwrap_or_else(|error| lib::compact_panic!("banked VBE present failed: {:?}", error)),
            Backend::Host => present_host_shadow(
                self.shadow_width, height, format, shadow),
            Backend::Headless => 0,
            Backend::Linear(_) => unreachable!(),
        }
    }

    /// Publish only compositor regions whose packed shadow pixels changed.
    /// Hosted and banked sinks currently require whole frames; linear GOP/VBE
    /// and the packed Mode 13h sink receive the exact damaged rectangles.
    pub fn present_regions<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        height: usize,
        shadow: &mut [u8],
        regions: &[crate::kernel::gui::Rect],
    ) -> usize {
        if regions.is_empty() { return 0; }
        if matches!(
            self.backend,
            Backend::Host
                | Backend::Vga { scanout: VgaScanout::VbeBanked { .. }, .. }
        ) {
            return self.present(machine, bios, height, shadow);
        }
        let format = self.rgb;
        let (out_w, out_h) = self.fit();
        let copied = match &mut self.backend {
            Backend::Linear(framebuffer)
            | Backend::Vga {
                scanout: VgaScanout::Mode13 { framebuffer, .. }
                    | VgaScanout::VbeLinear { framebuffer, .. },
                ..
            } => blit_regions(
                framebuffer, format, out_w, out_h, height, shadow, regions,
            ),
            Backend::Headless => 0,
            Backend::Host | Backend::Vga { scanout: VgaScanout::VbeBanked { .. }, .. } => {
                unreachable!()
            }
        };
        finish_present();
        copied
    }

    fn present_linear(&mut self, height: usize, shadow: &[u8]) -> Option<usize> {
        let format = self.rgb;
        let (out_w, out_h) = self.fit();
        let Backend::Linear(framebuffer) = &mut self.backend else { return None };
        let copied = blit(framebuffer, format, out_w, out_h, height, shadow);
        finish_present();
        Some(copied)
    }

    /// Best-effort publication after the kernel has already failed.  A panic
    /// cannot recover the `Arch` and BIOS workspace values held by the dead
    /// stack, but a loader-provided linear framebuffer needs neither: use the
    /// same blit as the normal [`Self::present`] path and publish it directly.
    pub fn panic_present(&mut self, height: usize, shadow: &[u8]) -> usize {
        self.present_linear(height, shadow).unwrap_or(0)
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
#[optimize(speed)]
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

/// Stretch one row of already-encoded `u32` pixels into a packed destination
/// row. The destination drives the walk: every output pixel performs exactly
/// one cached source-word load and one overlapping dword store.
#[optimize(speed)]
pub(crate) fn stretch_native_row(
    source: &[u32],
    destination: &mut [u8],
    out_w: usize,
    pixel_bytes: usize,
) -> bool {
    if source.is_empty() || out_w == 0 || !(1..=4).contains(&pixel_bytes) {
        return false;
    }
    let row_bytes = match out_w.checked_mul(pixel_bytes) {
        Some(bytes) => bytes,
        None => return false,
    };
    if destination.len() < row_bytes + 4 {
        return false;
    }

    let source_w = source.len();
    let (whole, remainder) = (source_w / out_w, source_w % out_w);
    let mut sx = 0usize;
    let mut error = 0usize;
    let mut destination_offset = 0usize;
    for _ in 0..out_w {
        unsafe {
            core::ptr::write_unaligned(
                destination.as_mut_ptr().add(destination_offset).cast::<u32>(),
                *source.get_unchecked(sx),
            );
        }
        destination_offset += pixel_bytes;
        sx += whole;
        error += remainder;
        let mut carry_mask = usize::from(error >= out_w).wrapping_neg();
        // Keep the 0/-1 mask materialized: with opt-level=z LLVM otherwise
        // turns the correction below into a conditional jump in the hot loop.
        unsafe {
            core::arch::asm!(
                "/* {carry_mask} */",
                carry_mask = inout(reg) carry_mask,
                options(nomem, nostack, preserves_flags),
            );
        }
        error -= carry_mask & out_w;
        sx = sx.wrapping_sub(carry_mask);
    }
    true
}
/// Publish a completed horizontally-stretched VGA shadow. The shadow holds the
/// PICTURE only — `out_w × vga_height` — so this is pure vertical expansion:
/// each source row is copied to the output rows it covers, at the centered
/// picture origin. Format conversion already happened in the raster pass, and
/// the pillarbox/letterbox bars were painted once at the mode switch, so
/// nothing here touches a pixel outside the picture.
#[optimize(speed)]
fn blit(
    fb: &Framebuffer,
    format: PixelFormat,
    out_w: usize,
    out_h: usize,
    vga_height: usize,
    shadow: &[u8],
) -> usize {
    let step = format.bytes_per_pixel as usize;
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
    out_w * out_h
}

/// Fill a centered physical rectangle from a dense source-sized word image.
/// Only one packed destination row is staged; it is stretched once and reused
/// for every vertical repetition of that source row.
#[optimize(speed)]
fn blit_native(
    fb: &Framebuffer,
    format: PixelFormat,
    out_w: usize,
    out_h: usize,
    source: NativeSource<'_>,
) -> usize {
    let NativeSource { width: source_w, height: source_h, pixels: source, row } = source;
    let step = usize::from(format.bytes_per_pixel);
    let Some(source_words) = source_w.checked_mul(source_h) else { return 0 };
    let Some(row_bytes) = out_w.checked_mul(step) else { return 0 };
    if source_w == 0 || source_h == 0 || source.len() < source_words {
        return 0;
    }
    row.resize(row_bytes.saturating_add(4), 0);
    let bx = (fb.width - out_w) / 2;
    let by = (fb.height - out_h) / 2;
    let (ybase, yrem) = (out_h / source_h, out_h % source_h);
    let origin = fb.va + by * fb.pitch + bx * step;
    let mut oy = 0usize;
    let mut yerr = 0usize;
    for sy in 0..source_h {
        if !stretch_native_row(
            &source[sy * source_w..(sy + 1) * source_w],
            row,
            out_w,
            step,
        ) {
            return 0;
        }
        yerr += yrem;
        let carry = usize::from(yerr >= source_h);
        let rows = ybase + carry;
        yerr -= carry * source_h;
        for _ in 0..rows {
            unsafe {
                copy_bytes(
                    (origin + oy * fb.pitch) as *mut u8,
                    row.as_ptr(),
                    row_bytes,
                    fb.wide,
                );
            }
            oy += 1;
        }
    }
    out_w * out_h
}

#[optimize(speed)]
fn blit_regions(
    fb: &Framebuffer,
    format: PixelFormat,
    out_w: usize,
    out_h: usize,
    vga_height: usize,
    shadow: &[u8],
    regions: &[crate::kernel::gui::Rect],
) -> usize {
    let step = format.bytes_per_pixel as usize;
    let row_bytes = out_w * step;
    if vga_height == 0 || shadow.len() < row_bytes * vga_height {
        return 0;
    }
    let bx = (fb.width - out_w) / 2;
    let by = (fb.height - out_h) / 2;
    let (ybase, yrem) = (out_h / vga_height, out_h % vga_height);
    let origin = fb.va + by * fb.pitch + bx * step;
    let mut copied = 0usize;
    let mut oy = 0usize;
    let mut yerr = 0usize;
    for sy in 0..vga_height {
        yerr += yrem;
        let carry = (yerr >= vga_height) as usize;
        let rows = ybase + carry;
        yerr -= carry * vga_height;
        for region in regions {
            let top = region.y.max(0) as usize;
            let bottom = (i64::from(region.y) + i64::from(region.height))
                .clamp(0, vga_height as i64) as usize;
            if sy < top || sy >= bottom { continue; }
            let left = region.x.max(0) as usize;
            let right = (i64::from(region.x) + i64::from(region.width))
                .clamp(0, out_w as i64) as usize;
            if left >= right { continue; }
            let bytes = (right - left) * step;
            let src = shadow[sy * row_bytes + left * step..].as_ptr();
            for row in 0..rows {
                unsafe {
                    copy_bytes(
                        (origin + (oy + row) * fb.pitch + left * step) as *mut u8,
                        src,
                        bytes,
                        fb.wide,
                    );
                }
                copied += right - left;
            }
        }
        oy += rows;
    }
    copied
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

/// Direct-framebuffer scanout state: a palette, one native-size `u32` frame,
/// and the render/publish clock.
pub struct Scratch {
    pal: vga::Pal,
    pal_cache: [u8; 768],
    /// Dense native VGA image: exactly `w * h` words, with no presentation
    /// pitch or scaling.
    surface: alloc::vec::Vec<u32>,
    /// Geometry the scanout is armed for
    /// `(w, h, out_w, out_h, panel_w, panel_h)`; any change
    /// discards a pending shadow and starts a fresh render.
    geo: (usize, usize, usize, usize, usize, usize),
    mode: Option<vga::VgaMode>,
    /// Beam phase within the current refresh, scaled to 449 steps. Phase zero
    /// is vertical retrace. At its trailing edge the whole shadow is rendered;
    /// the next clock wakeup publishes it.
    phase: usize,
    refresh_hz: u32,
    /// Rate at which the beam is sampled into a retained compositor surface.
    /// This may be lower than `refresh_hz` without changing guest retrace.
    raster_hz: u32,
    /// Raster period containing the most recent render. This prevents the
    /// 1 ms work cadence from becoming the display clock.
    frame: u64,
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
            refresh_hz: 0,
            raster_hz: 0,
            frame: 0,
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
            core::ptr::addr_of_mut!((*p).refresh_hz).write(0);
            core::ptr::addr_of_mut!((*p).raster_hz).write(0);
            core::ptr::addr_of_mut!((*p).frame).write(0);
            core::ptr::addr_of_mut!((*p).ready).write(false);
            core::ptr::addr_of_mut!((*p).last_tick).write(0);
            boxed.assume_init()
        }
    }

    /// Immutable view of a compositor-owned native-RGB VGA image.
    pub fn surface(&self) -> Option<(usize, usize, PixelFormat, &[u8])> {
        if self.pal.fmt != PixelFormat::NATIVE {
            return None;
        }
        let width = self.geo.0;
        let height = self.geo.1;
        let words = self.surface.get(..width.checked_mul(height)?)?;
        let pixels = unsafe {
            core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 4)
        };
        Some((width, height, PixelFormat::NATIVE, pixels))
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



const BEAM_STEPS: u64 = 449;
const VRETRACE_STEPS: usize = 49;

/// Exact rational refresh identity and beam phase. Reducing `now_ns` to the
/// current second first keeps every multiplication in `u64` even after years
/// of uptime.
fn beam_time(now_ns: u64, refresh_hz: u32) -> (u64, usize) {
    let seconds = now_ns / 1_000_000_000;
    let ns = now_ns % 1_000_000_000;
    let within_second = ns * u64::from(refresh_hz);
    let frame = seconds * u64::from(refresh_hz) + within_second / 1_000_000_000;
    let phase = ((within_second % 1_000_000_000) * BEAM_STEPS / 1_000_000_000) as usize;
    (frame, phase)
}

/// Guest-visible vertical retrace for an active direct scanout. `None` when
/// no scanout is live (window sink, unfocused thread, real VGA), so the caller
/// can use its free-running fallback.
pub fn beam_vretrace(s: &Scratch, now_tick: u64) -> Option<bool> {
    if s.geo.1 == 0 || s.refresh_hz == 0
        || now_tick.saturating_sub(s.last_tick) > 100
    {
        return None;
    }
    Some(s.phase < VRETRACE_STEPS)
}

pub enum ScanoutAction {
    None,
    Render,
    Publish {
        vga_height: usize,
        out_width: usize,
    },
}

/// Advance the direct-display clock and select this tick's bounded operation.
///
/// `refresh_hz` drives guest-visible retrace. `raster_hz` independently limits
/// how often [`render_shadow`] captures the VGA image into retained RAM; OSD
/// uses 20 Hz here without changing a game's beam timing. The tick following a
/// completed render publishes that immutable shadow to its sink.
pub fn scanout_action(
    s: &mut Scratch,
    display: &Display,
    mode: vga::VgaMode,
    now_ns: u64,
    refresh_hz: u32,
    raster_hz: u32,
    raster_size: Option<(usize, usize)>,
) -> ScanoutAction {
    let (w, h) = vga::dimensions(mode);
    if w == 0 || h == 0 || refresh_hz == 0 || raster_hz == 0 {
        return ScanoutAction::None;
    }
    let (_, phase) = beam_time(now_ns, refresh_hz);
    let (frame, _) = beam_time(now_ns, raster_hz);
    // Direct scanout chooses the fitted physical picture. A compositor asks
    // for the guest's natural dimensions, which makes the very same stretched
    // row rasterizer run at a horizontal ratio of exactly one.
    let (out_w, out_h) = raster_size.unwrap_or_else(|| display.fit());
    // A sink SMALLER than the guest image is legal: the Bresenham walk in
    // `StretchRow` shrinks as readily as it stretches, and `present` drops
    // source rows the same way. Refusing it here is what made the 320x200
    // mode-13 OSD aperture (266 px after aspect fit, i.e. narrower than every
    // guest mode including 320-wide ones) show nothing at all — and, because
    // the reset path below zeroes the framebuffer, show it as black.
    if out_w == 0 || out_h == 0 {
        return ScanoutAction::None;
    }

    let geo = (w, h, out_w, out_h, out_w, out_h);
    let reset = s.geo != geo
        || s.mode != Some(mode)
        || s.surface.len() != w * h
        || s.refresh_hz != refresh_hz
        || s.raster_hz != raster_hz;
    if reset {
        s.geo = geo;
        s.surface.clear();
        s.surface.resize(w * h, 0);
        s.mode = Some(mode);
        s.refresh_hz = refresh_hz;
        s.raster_hz = raster_hz;
        // A mode switch gets a complete shadow immediately and publishes it
        // on the following tick. Keep the old complete physical frame until
        // then: scanout is double-buffered, so reconfiguring the write-back
        // side must never destroy the frame the display is still scanning.
        // This matters especially while software briefly changes VGA memory-
        // access registers to update fonts; those writes can make mode
        // classification transiently change even though the visible timing
        // has not.
        s.phase = phase;
        s.frame = frame;
        s.ready = false;
        s.last_tick = now_ns / 1_000_000;
        return ScanoutAction::Render;
    }

    s.last_tick = now_ns / 1_000_000;
    s.phase = phase;
    if s.ready {
        s.ready = false;
        let h = s.geo.1;
        let out_w = s.geo.2;
        if s.surface.get(..s.geo.0.saturating_mul(h)).is_none() {
            return ScanoutAction::None;
        }
        ScanoutAction::Publish {
            vga_height: h,
            out_width: out_w,
        }
    } else if frame != s.frame && phase >= VRETRACE_STEPS {
        s.frame = frame;
        s.ready = false;
        ScanoutAction::Render
    } else {
        ScanoutAction::None
    }
}

/// Transfer a completed packed shadow to its sink. The sink returns its prior
/// front-buffer storage with [`recycle_shadow`], forming a copy-free swapchain.
pub fn take_shadow(s: &mut Scratch) -> alloc::vec::Vec<u32> {
    core::mem::take(&mut s.surface)
}

pub fn recycle_shadow(s: &mut Scratch, pixels: alloc::vec::Vec<u32>) {
    s.surface = pixels;
}

/// Render one complete VGA image into the compact write-back shadow. Palette
/// state is folded exactly once, so a completed shadow cannot contain bands
/// from different DAC generations.
fn raster_shadow(
    s: &mut Scratch,
    format: PixelFormat,
    frame: &vga::Frame,
) -> bool {
    let (w, h) = vga::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return false;
    }
    if s.mode != Some(frame.mode)
        || s.geo.0 != w
        || s.geo.1 != h
        || s.surface.len() < w * h
    {
        return false;
    }
    s.pal.sync(frame.palette, frame.dac_mask, format, &mut s.pal_cache);
    if matches!(frame.mode, vga::VgaMode::Planar16 { .. }) {
        s.pal.sync_planar(frame.ac);
    }
    for sy in 0..h {
        vga::render_row(
            frame,
            sy,
            &s.pal,
            &mut s.surface[sy * w..(sy + 1) * w],
        );
    }
    true
}

pub fn render_shadow(
    s: &mut Scratch,
    format: PixelFormat,
    frame: &vga::Frame,
) -> bool {
    if !raster_shadow(s, format, frame) {
        return false;
    }
    s.ready = true;
    true
}

/// Render a completed native-size frame for an immediate sink.
pub fn render_frame(s: &mut Scratch, format: PixelFormat, frame: &vga::Frame) -> bool {
    let (w, h) = vga::dimensions(frame.mode);
    if w == 0 || h == 0 {
        return false;
    }
    let Some(storage) = w.checked_mul(h) else { return false };
    if s.surface.len() != storage {
        s.surface.clear();
        s.surface.resize(storage, 0);
    }
    s.geo = (w, h, w, h, w, h);
    s.mode = Some(frame.mode);
    s.ready = false;
    raster_shadow(s, format, frame)
}

/// Cheap diagnostic signature of the completed packed shadow. Sampling one
/// byte per cache-line-sized span is enough to distinguish IT's all-black
/// frames from its populated text UI without adding another full-frame walk.
pub fn shadow_sample(s: &Scratch) -> (usize, u32) {
    let len = s.geo.0
        .saturating_mul(s.geo.1)
        .min(s.surface.len());
    let mut nonzero = 0usize;
    let mut hash = 0x811C9DC5u32;
    for &pixel in s.surface[..len].iter().step_by(16) {
        nonzero += usize::from(pixel != 0);
        hash = (hash ^ pixel).wrapping_mul(0x01000193);
    }
    (nonzero, hash)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raster_rate_does_not_change_guest_beam_rate() {
        let mut scratch = Scratch::new();
        let display = Display::host();
        let mode = vga::VgaMode::Mode13h;
        assert!(matches!(
            scanout_action(&mut scratch, &display, mode, 0, 70, 20, Some((320, 200))),
            ScanoutAction::Render,
        ));
        assert!(matches!(
            scanout_action(
                &mut scratch, &display, mode, 15_000_000, 70, 20, Some((320, 200)),
            ),
            ScanoutAction::None,
        ));
        assert_eq!(beam_vretrace(&scratch, 15), Some(true));
        assert!(matches!(
            scanout_action(
                &mut scratch, &display, mode, 20_000_000, 70, 20, Some((320, 200)),
            ),
            ScanoutAction::None,
        ));
        assert_eq!(beam_vretrace(&scratch, 20), Some(false));
        assert!(matches!(
            scanout_action(
                &mut scratch, &display, mode, 50_000_000, 70, 20, Some((320, 200)),
            ),
            ScanoutAction::Render,
        ));
    }

    #[test]
    fn native_row_scaler_writes_one_fractionally_selected_pixel_per_output() {
        let source = [0x1111u32, 0x2222, 0x3333];
        let mut destination = [0u8; 14];
        assert!(stretch_native_row(&source, &mut destination, 5, 2));
        let words: alloc::vec::Vec<u16> = destination[..10]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();
        assert_eq!(words, [0x1111, 0x1111, 0x2222, 0x2222, 0x3333]);
    }

    #[test]
    fn regional_blit_leaves_clean_pixels_untouched() {
        let mut output = alloc::vec![0xAAu8; 4 * 2 * 2];
        let framebuffer = Framebuffer {
            va: output.as_mut_ptr() as usize,
            pitch: 4 * 2,
            width: 4,
            height: 2,
            slow: false,
            wide: false,
        };
        let shadow: alloc::vec::Vec<u8> = (0..16u8).collect();
        assert_eq!(
            blit_regions(
                &framebuffer,
                PixelFormat::RGB565,
                4,
                2,
                2,
                &shadow,
                &[crate::kernel::gui::Rect::new(1, 0, 2, 1)],
            ),
            2,
        );
        assert_eq!(&output[..2], &[0xAA, 0xAA]);
        assert_eq!(&output[2..6], &shadow[2..6]);
        assert!(output[6..].iter().all(|&byte| byte == 0xAA));
    }
}
