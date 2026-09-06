//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live state behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `//lib:vga`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

use crate::Regs;
use super::*;
use crate::kernel::bios_display::{DosVideo, FullscreenVga, EmulatedVga};
use crate::kernel::bios_display::VideoResume;

// ============================================================================
// Machine-wide VGA presence
// ============================================================================

/// Does guest VGA programming reach a real card (vs the emulated register
/// file)? Answered by the eager boot-time probe (`kernel::platform`) —
/// passthrough decides the whole 3Cx/3Dx window and whether context-switch
/// save/restore touches hardware at all. Machine-wide today; per-thread
/// display ownership (foreground DOS owns the card, background threads run
/// emulated) hangs off the same Platform type later.
pub fn physical_vga_present() -> bool {
    // No probe (bare-ELF dev path) ⇒ no card. Guards the console-VGA snapshot
    // that thread-exit takes, which would otherwise trip `get`'s panic there.
    crate::kernel::platform::probed()
        && crate::kernel::platform::get().vga_passthrough
}

impl EmulatedVga {
    /// The single native-to-emulated transition. Capture every piece of state
    /// that lived only in the adapter, publish its framebuffer into the guest
    /// address space, and return the still-unmodified card capability.
    fn snapshot_native<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        native: &mut crate::kernel::platform::NativeVga,
    ) -> Self {
        let mut model = VgaState::new_boxed();
        let current = native.cap().bios_current_vbe_mode(machine, bios)
            .unwrap_or_else(|error| lib::compact_panic!("native BIOS current-mode query failed: {:?}", error));
        let current_bank = current.and_then(|(_, linear)| (!linear).then(|| {
            native.cap().guest_bios_window(machine, bios, None)
                .unwrap_or_else(|error| lib::compact_panic!("native BIOS current-bank query failed: {:?}", error))
        }));
        let physical_lfb = current.and_then(|(mode, linear)| linear.then_some(mode.physical_base));
        let (resume, svga_pages) = if let Some((mode, linear)) = current {
            if matches!(mode.format, crate::kernel::display::FormatSpec::Indexed8)
                || mode.programmable_ramp
            {
                capture_native_vbe_palette(
                    machine, bios, native.cap_mut(), mode, &mut model,
                );
            }
            let mut pitch_regs = Regs::empty();
            pitch_regs.rax = 0x4F06;
            pitch_regs.rbx = 1;
            let logical_pitch = native.cap().guest_bios_scan_line_length(
                machine, bios, &mut pitch_regs,
            ).ok().map(|()| pitch_regs.rbx as u16)
                .filter(|&pitch| pitch != 0)
                .unwrap_or(mode.pitch);
            let mut display_regs = Regs::empty();
            display_regs.rax = 0x4F07;
            display_regs.rbx = 0x0100;
            let display_start = native.cap().guest_bios_display_start(
                machine, bios, &mut display_regs,
            ).map(|()| (display_regs.rcx as u16, display_regs.rdx as u16))
                .unwrap_or((0, 0));
            let pages = capture_native_vbe(
                machine, bios, native.cap_mut(), mode, current_bank,
                logical_pitch, &mut model);
            (VideoResume::Vbe {
                mode,
                request: mode.number | if linear { 0x4000 } else { 0 },
                bank: current_bank,
                display_start,
                logical_pitch,
            }, pages)
        } else {
            let cirrus_readback = crate::kernel::platform::get().vga_readback;
            let checkpoint = if cirrus_readback {
                None
            } else {
                // Generic VGA: 4F04 is an opaque rewind point. After the bulk
                // save destroys the hidden state, restore it separately for
                // the latch spill and for the AC-phase experiment.
                Some(native.cap().bios_checkpoint(machine, bios)
                    .unwrap_or_else(|| lib::compact_panic!(
                        "native VGA has no exact hidden-state capture path"
                    )))
            };
            crate::kernel::drivers::vga_hw::save(
                native.cap(), &mut model, cirrus_readback,
            );

            if let Some(checkpoint) = checkpoint.as_ref() {
                native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
                crate::kernel::drivers::vga_hw::write_latches_and_readback(
                    &mut model,
                );

                native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
                let plane_enable =
                    crate::kernel::drivers::vga_hw::read_ac_register(0x12);

                native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
                crate::kernel::drivers::vga_hw::correct_flip_flop_phase(
                    &mut model,
                    plane_enable,
                );

                native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
                crate::kernel::drivers::vga_hw::checkpoint_restored(&model);
            }
            materialize_emulated_aperture(&mut model, machine);
            let bios_mode = native.cap().bios_current_legacy_mode(machine, bios)
                .unwrap_or_else(|error| lib::compact_panic!("native BIOS legacy-mode query failed: {:?}", error));
            (VideoResume::Legacy { bios_mode }, 0)
        };
        if let Some(physical_base) = physical_lfb {
            machine.redirect_physical_aliases(
                u64::from(physical_base) >> 12,
                SVGA_LFB_BASE >> 12,
                svga_pages,
                true,
            );
        }
        Self {
            state: model,
            svga_pages,
            resume,
            physical_lfb,
        }
    }

    /// Ordinary focus detach: after capturing the VGA, explicitly discard the
    /// hardware-state authority and retain only physical scanout capability.
    fn detach_native<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
    ) -> (Self, crate::kernel::platform::VgaCap) {
        let vga = Self::snapshot_native(machine, bios, &mut native);
        (vga, native.into_cap())
    }

    fn attach_native<A: crate::Arch>(
        mut self,
        machine: &mut A,
        mut native: crate::kernel::platform::VgaCap,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> FullscreenVga {
        // Native ownership means the complete VGA aperture is physical in the
        // incoming DOS address space, including B8000 text memory.
        machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
        if let VideoResume::Vbe { request, .. } = self.resume
            && self.state.svga_w != 0
        {
            native.bios_set_mode_request(machine, &mut *bios, request);
            restore_native_vbe(machine, bios, &mut native, self.resume, &self.state);
            if let Some(physical_base) = self.physical_lfb {
                machine.redirect_physical_aliases(
                    u64::from(physical_base) >> 12,
                    SVGA_LFB_BASE >> 12,
                    self.svga_pages,
                    false,
                );
            }
            discard_emulated_svga(machine, &mut self);
            return FullscreenVga::Native(crate::kernel::platform::NativeVga::restored(native));
        }
        // A live emulated VGA's aperture is its VRAM. Capture the linear
        // representation before converting the complete device to hardware.
        capture_emulated_aperture(&mut self.state, machine);
        // Restore the persistent firmware's legacy-mode bookkeeping first;
        // direct register restoration below may describe a tweaked/unchained
        // mode which no BIOS mode number can express exactly.
        let VideoResume::Legacy { bios_mode } = self.resume else {
            unreachable!("VBE state without an SVGA framebuffer")
        };
        native.bios_set_mode(machine, &mut *bios, u16::from(bios_mode));
        crate::kernel::drivers::vga_hw::restore(&native, &self.state);
        FullscreenVga::Native(crate::kernel::platform::NativeVga::restored(native))
    }

    /// Bind an already-live adapter to this address space without restoring
    /// the saved software image. The hardware state wins: normal DOS return
    /// uses this so the parent's screen continues exactly where the child left
    /// it, with no firmware mode set or visible repaint.
    fn attach_native_replace<A: crate::Arch>(
        mut self,
        machine: &mut A,
        native: crate::kernel::platform::NativeVga,
    ) -> FullscreenVga {
        machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
        if let Some(physical_base) = self.physical_lfb {
            machine.redirect_physical_aliases(
                u64::from(physical_base) >> 12,
                SVGA_LFB_BASE >> 12,
                self.svga_pages,
                false,
            );
        }
        if self.svga_pages != 0 {
            discard_emulated_svga(machine, &mut self);
        }
        FullscreenVga::Native(native)
    }

    fn attach_capability_replace<A: crate::Arch>(
        self,
        machine: &mut A,
        native: crate::kernel::platform::VgaCap,
    ) -> FullscreenVga {
        self.attach_native_replace(
            machine, crate::kernel::platform::NativeVga::restored(native))
    }

    pub fn present<A: crate::Arch>(
        self,
        machine: &mut A,
        display: crate::kernel::display::Display,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> FullscreenVga {
        match display.into_native_capability(machine) {
            Ok(native) => self.attach_native(machine, native, bios),
            Err(display) => {
                FullscreenVga::Emulated(self, display)
            }
        }
    }
}

impl FullscreenVga {
    /// Install a newly constructed emulated VGA into the current address
    /// space. This is construction, not context-switch reconciliation.
    pub fn initialize_active_address_space<A: crate::Arch>(&mut self, machine: &mut A) {
        match self {
            Self::Emulated(vga, _) => {
                materialize_emulated_aperture(&mut vga.state, machine);
            }
            Self::Native(_) => machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0),
        }
    }

    /// Apply one ownership transaction. All kernel targets are panic=abort,
    /// so the closure cannot unwind across the brief move out of `self`; no
    /// empty or transition state exists in the type or can be observed.
    pub(crate) fn map<R>(
        &mut self,
        f: impl FnOnce(Self) -> (Self, R),
    ) -> R {
        unsafe {
            let old = core::ptr::read(self);
            let (new, result) = f(old);
            core::ptr::write(self, new);
            result
        }
    }

}

impl DosVideo {
    /// Apply one ownership transition without ever exposing an empty thread
    /// video slot. Kernel targets are panic=abort, so the closure cannot unwind
    /// across the brief move.
    pub(crate) fn map<R>(&mut self, f: impl FnOnce(Self) -> (Self, R)) -> R {
        unsafe {
            let old = core::ptr::read(self);
            let (new, result) = f(old);
            core::ptr::write(self, new);
            result
        }
    }

    pub fn initialize_active_address_space<A: crate::Arch>(&mut self, machine: &mut A) {
        match self {
            Self::Vga(vga) => materialize_emulated_aperture(&mut vga.state, machine),
            Self::Fullscreen(vga) => vga.initialize_active_address_space(machine),
        }
    }

    pub fn clone_detached_for_child<A: crate::Arch>(&mut self, machine: &mut A) -> Option<Self> {
        let Self::Vga(vga) = self else { return None };
        capture_emulated_aperture(&mut vga.state, machine);
        Some(Self::Vga(vga.clone_for_fork()))
    }

    pub fn capture_address_space_vram<A: crate::Arch>(&mut self, machine: &mut A) {
        if let Some(vga) = self.emulated_mut() {
            capture_emulated_aperture(&mut vga.state, machine);
        }
    }

    pub fn release_for_parent_replace<A: crate::Arch>(&mut self, machine: &mut A) -> Self {
        self.map(|mut returned| {
            if let Some(vga) = returned.emulated_mut() {
                capture_emulated_aperture(&mut vga.state, machine);
            }
            (Self::Vga(EmulatedVga::initial_mode3()), returned)
        })
    }

    pub fn acquire_parent_replace<A: crate::Arch>(&mut self, machine: &mut A, returned: Self) {
        self.map(|parent| {
            let Self::Vga(saved) = parent else {
                return (parent, ());
            };
            let replacement = match returned {
                Self::Fullscreen(FullscreenVga::Native(native)) =>
                    Self::Fullscreen(saved.attach_native_replace(machine, native)),
                Self::Fullscreen(FullscreenVga::Emulated(mut child, display)) => {
                    materialize_emulated_aperture(&mut child.state, machine);
                    Self::Fullscreen(FullscreenVga::Emulated(child, display))
                }
                Self::Vga(mut child) => {
                    materialize_emulated_aperture(&mut child.state, machine);
                    Self::Vga(child)
                }
            };
            (replacement, ())
        });
    }
}

/// Suspend the foreground VGA into state-only form and release its output.
pub fn release_fullscreen<A: crate::Arch>(
    video: &mut DosVideo,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
) -> crate::kernel::display::DisplayHandoff {
    video.map(|video| {
        let DosVideo::Fullscreen(mut fullscreen) = video else {
            lib::compact_panic!("display release from non-fullscreen DOS VGA")
        };
        let handoff = release_display(&mut fullscreen, machine, bios);
        let FullscreenVga::Emulated(vga, headless) = fullscreen else {
            unreachable!("fullscreen release did not detach native VGA")
        };
        debug_assert!(headless.is_headless());
        (DosVideo::Vga(vga), handoff)
    })
}

/// Combine stored VGA state with an output handoff into a fullscreen VGA.
pub fn acquire_fullscreen<A: crate::Arch>(
    video: &mut DosVideo,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: crate::kernel::display::DisplayHandoff,
) {
    video.map(|video| {
        let DosVideo::Vga(vga) = video else {
            lib::compact_panic!("display acquire by already-fullscreen DOS VGA")
        };
        let mut fullscreen = FullscreenVga::Emulated(vga, crate::kernel::display::Display::headless());
        acquire_display(&mut fullscreen, machine, bios, display);
        (DosVideo::Fullscreen(fullscreen), ())
    });
}

pub fn acquire_fullscreen_replace<A: crate::Arch>(
    video: &mut DosVideo,
    machine: &mut A,
    display: crate::kernel::display::DisplayHandoff,
) {
    video.map(|video| {
        let DosVideo::Vga(vga) = video else {
            lib::compact_panic!("replacement display acquire by already-fullscreen DOS VGA")
        };
        let mut fullscreen = FullscreenVga::Emulated(vga, crate::kernel::display::Display::headless());
        acquire_display_replace(&mut fullscreen, machine, display);
        (DosVideo::Fullscreen(fullscreen), ())
    });
}

/// Replace the current output with a headless sink and release the foreground
/// scanout target: either a render surface or a state-free VGA capability.
pub fn release_display<A: crate::Arch>(
    vga: &mut FullscreenVga,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
) -> crate::kernel::display::DisplayHandoff {
    vga.map(|vga| match vga {
        FullscreenVga::Native(native) => {
            let (vga, native) = EmulatedVga::detach_native(machine, bios, native);
            (FullscreenVga::Emulated(vga, crate::kernel::display::Display::headless()),
             crate::kernel::display::DisplayHandoff::Vga(native))
        }
        FullscreenVga::Emulated(vga, display) =>
            (FullscreenVga::Emulated(vga, crate::kernel::display::Display::headless()),
             crate::kernel::display::DisplayHandoff::Surface(display)),
    })
}

/// Replace an emulated VGA's current output target. A bare VgaCap is upgraded
/// to NativeVga only after the complete software state is restored.
pub fn acquire_display<A: crate::Arch>(
    vga: &mut FullscreenVga,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: crate::kernel::display::DisplayHandoff,
) {
    vga.map(|vga| match (vga, display) {
        (FullscreenVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Vga(native)) =>
            (vga.attach_native(machine, native, bios), ()),
        (FullscreenVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Surface(display)) =>
            (vga.present(machine, display, bios), ()),
        (native @ FullscreenVga::Native(_), _) => (native, ()),
    });
}

/// Acquire a live physical VGA without restoring the receiver's recovery
/// image. This is the normal child→parent DOS return operation.
pub fn acquire_display_replace<A: crate::Arch>(
    vga: &mut FullscreenVga,
    machine: &mut A,
    display: crate::kernel::display::DisplayHandoff,
) {
    vga.map(|vga| match (vga, display) {
        (FullscreenVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Vga(native)) =>
            (vga.attach_capability_replace(machine, native), ()),
        (FullscreenVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Surface(display)) =>
            (FullscreenVga::Emulated(vga, display), ()),
        (native @ FullscreenVga::Native(_), _) => (native, ()),
    });
}

// ============================================================================
// VGA register state (AcState + VgaState)
// ============================================================================

// The register file, its plane memory and the port model live in
// `//lib:vga` — a VGA is not DOS policy, and the Linux console, the display
// handover and the real-card driver all hold one too. What stays here is the
// part that needs a guest address space, which a passive card cannot have.
pub use ::vga::VgaState;

/// Non-destructively decide whether the currently owned VGA is already the
/// conventional colour 80x25 text screen expected when COMMAND.COM returns.
pub fn is_standard_text(device: &DosVideo) -> bool {
    match device {
        DosVideo::Fullscreen(FullscreenVga::Native(native)) =>
            crate::kernel::drivers::vga_hw::is_standard_text_mode(native.cap()),
        DosVideo::Vga(dev) | DosVideo::Fullscreen(FullscreenVga::Emulated(dev, _)) => {
            dev.state.svga_w == 0
                && ::vga::is_standard_text(&::vga::Regs {
                    crtc: dev.state.crtc,
                    seq: dev.state.seq,
                    gc: dev.state.gc,
                    misc: dev.state.misc_output,
                })
        }
    }
}

/// Present the emulated planes to the guest at A0000/B8000 — map the window
/// and fill it from suspended state, or mark it trapped when writes must
/// go through the planar ALU. Needs an address space, so it is not the card's.
fn materialize_emulated_aperture<A: crate::Arch>(state: &mut VgaState, machine: &mut A) {
    if state.planes.len() != PLANES_LEN {
        state.planes.resize(PLANES_LEN, 0);
    }
    machine.map_fresh_range(VGA_VRAM_BASE >> 12, PLANES_LEN >> 12);
    let planes = core::mem::take(&mut state.planes);
    write_live_planes(machine, &planes);
    if state.svga_w != 0 {
        machine.copy_page_entries(
            (SVGA_LFB_BASE >> 12) + usize::from(state.svga_bank) * WINDOW_PAGES,
            A0000 >> 12,
            WINDOW_PAGES,
        );
    } else {
        install_aperture(machine, state.cpu_aperture());
    }
    // A live emulated VGA owns page-backed VRAM, never a shadow Vec. `planes`
    // drops here after its representation has been recorded by VgaState.
}

/// The reverse: read the guest's aperture back into the planes.
fn capture_emulated_aperture<A: crate::Arch>(state: &mut VgaState, machine: &mut A) {
    state.planes = read_live_planes(machine);
}


// ============================================================================
// Emulated VGA planar VRAM (trap-backed A0000)
// ============================================================================
//
// Planar/Mode-X graphics route a single CPU store to A0000 through the VGA's
// plane logic into 1-4 of the 4 planes — the result is not what lands in
// linear RAM, so it must be modelled at write time. A0000 is mapped as an MMIO
// trap window while planar modes are active; the #PF path decodes guest CPU
// accesses and kernel-side transfers use `copy_to_guest`. On the chain↔unchain
// hop the chained (mode-13h linear) content is synced into/out of the planes
// (chain4 split/merge). Interp and metal use the same trap marker contract.


/// The emulated VGA's complete 4-plane memory. `VgaState::layout()` maps
/// logical `(plane, offset)` to its physical byte. It lives per-thread on
/// `VgaState::planes` (the
/// focus-owned model) — the same buffer `vga_hw::save` fills for a real
/// card — so the planar trap and the renderer touch it directly, no global and
/// no per-frame copy.
const PLANES_LEN: usize = 4 * 0x10000;
const A0000: usize = 0xA0000;

/// Guest page range whose CPU accesses must pass through the emulated VGA's
/// planar ALU. The card derives this together with its VRAM layout.
pub fn trapped_aperture(vga: &VgaState) -> Option<core::ops::Range<u16>> {
    match vga.cpu_aperture() {
        ::vga::CpuAperture::Trapped { range } =>
            Some(range.start_page..range.end_page),
        _ => None,
    }
}
/// Private, per-address-space backing of the emulated card's four VRAM planes.
/// CPU apertures alias pages from here; this is the one live pixel store.
pub(crate) const VGA_VRAM_BASE: usize = 0x4100_0000;

fn read_live_planes<A: crate::Arch>(machine: &A) -> alloc::vec::Vec<u8> {
    let mut planes = alloc::vec![0; PLANES_LEN];
    machine.copy_from(VGA_VRAM_BASE, &mut planes);
    planes
}

fn write_live_planes<A: crate::Arch>(machine: &mut A, planes: &[u8]) {
    machine.copy_to(VGA_VRAM_BASE, planes);
}

fn aperture_range(aperture: ::vga::CpuAperture) -> Option<::vga::ApertureRange> {
    match aperture {
        ::vga::CpuAperture::Direct { range, .. }
        | ::vga::CpuAperture::Trapped { range } => Some(range),
        ::vga::CpuAperture::None => None,
    }
}

fn install_aperture<A: crate::Arch>(machine: &mut A, aperture: ::vga::CpuAperture) {
    match aperture {
        ::vga::CpuAperture::None => {}
        ::vga::CpuAperture::Direct { range, pages } => machine.copy_page_entries(
            VGA_VRAM_BASE >> 12,
            usize::from(range.start_page),
            usize::from(pages.min(range.end_page - range.start_page)),
        ),
        ::vga::CpuAperture::Trapped { range } => machine.map_phys_range(
            usize::from(range.start_page),
            usize::from(range.end_page - range.start_page),
            0,
            arch_abi::MAP_MMIO,
        ),
    }
}

fn apply_aperture_write<A: crate::Arch>(machine: &mut A, write: ::vga::PortWrite) {
    if write.old_aperture == write.new_aperture {
        return;
    }
    // Remove the complete old view even when the decoded range did not move.
    // A direct view can shrink (16 pages to 8), or change into a trap over the
    // same range; merely installing the new prefix would leave stale aliases.
    if let Some(old) = aperture_range(write.old_aperture) {
        machine.map_fresh_range(
            usize::from(old.start_page),
            usize::from(old.end_page - old.start_page),
        );
    }
    install_aperture(machine, write.new_aperture);
}

/// One complete VGA port operation: `lib/vga` updates registers and VRAM
/// representation together; the kernel merely applies its returned mapping.
pub fn port_write<A: crate::Arch>(
    machine: &mut A,
    state: &mut VgaState,
    port: u16,
    value: u8,
) {
    let write = state.port_write(port, value);
    if let Some(transition) = write.vram_transition {
        let mut planes = read_live_planes(machine);
        transition.apply(&mut planes);
        write_live_planes(machine, &planes);
    }
    apply_aperture_write(machine, write);
}

/// BIOS character-generator services operate on plane 2 regardless of the
/// CPU-visible layout. The font service addresses logical plane 2 directly;
/// no representation transition is needed for a trapped operation.
pub fn bios_load_font<A: crate::Arch>(
    machine: &mut A,
    device: &mut DosVideo,
    map: usize,
    first: usize,
    font: &[u8],
    glyph_h: usize,
) {
    let Some(dev) = device.emulated_mut() else { return };
    let vga = &mut dev.state;
    let mut planes = read_live_planes(machine);
    ::vga::load_font_glyphs(
        &mut planes,
        vga.layout(),
        map,
        first,
        font,
        glyph_h,
    );
    write_live_planes(machine, &planes);
}

/// Apply the text geometry selected by INT 10h AX=111xh. The 14-line ROM font
/// selects the VGA's 350-line text timing; 8- and 16-line fonts use 400 lines.
pub fn bios_set_text_height(device: &mut DosVideo, glyph_h: u8) {
    let Some(dev) = device.emulated_mut() else { return };
    let visible = if glyph_h == 14 { 350u16 } else { 400u16 };
    let end = visible - 1;
    dev.state.crtc[9] = (dev.state.crtc[9] & 0xE0) | (glyph_h - 1);
    dev.state.crtc[0x12] = end as u8;
    dev.state.crtc[7] = (dev.state.crtc[7] & !0x42)
        | (((end >> 8) as u8 & 1) << 1)
        | (((end >> 9) as u8 & 1) << 6);
}

pub fn bios_set_font_map_select(device: &mut DosVideo, select: u8) {
    if let Some(dev) = device.emulated_mut() {
        dev.state.seq[3] = select;
    }
}

// ============================================================================
// VESA SVGA. The framebuffer is a guest user-RAM region at SVGA_LFB_BASE. A
// real-mode guest reaches one 64 KB bank at a time through the 0xA0000 window,
// which we *alias* onto the bank (shared frames via copy_page_entries) — guest
// writes land directly in the framebuffer, always coherent, no copy. A
// protected-mode (DPMI) client can map the same region as a linear framebuffer
// and write it directly. `display_tick` presents by reading the region.
// ============================================================================

/// Guest-linear base of the SVGA framebuffer. Placed at 1 GB — far above the
/// DPMI linear pool (grows up from 0x500000) and the XMS region, well below the
/// 3 GB user-space ceiling — so a DPMI client mapping it as an LFB never
/// collides with the program's own allocations. Sized per mode, rounded up to
/// whole 64 KB banks.
pub(crate) const SVGA_LFB_BASE: usize = 0x4000_0000; // 1 GB
/// Address space reserved for substitute-VBE modes. DPMI clients are allowed
/// to map PhysBasePtr before selecting a mode, so recognition cannot depend on
/// the active mode's geometry.
// VBE 4F00 advertises 0x80 × 64 KiB. Clients map adapter memory, not merely
// the active image (Duke3D asks for 0x3fffff bytes at 800x600x8).
pub(crate) const SVGA_LFB_MAX_BYTES: usize = 16 * 1024 * 1024;
const SVGA_WINDOW: usize = 0x10000; // 64 KB VBE bank granule
const WINDOW_PAGES: usize = SVGA_WINDOW >> 12;

fn svga_shadow_pages(bytes: usize) -> usize {
    bytes.div_ceil(crate::PAGE_SIZE)
}

fn map_linear_vbe<A: crate::Arch>(
    machine: &mut A,
    mode: crate::kernel::platform::VbeMode,
) -> (usize, usize) {
    let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
    let bytes = mode.framebuffer_bytes as usize;
    let pages = (offset + bytes).div_ceil(crate::PAGE_SIZE);
    machine.map_phys_range(
        arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE,
        pages,
        u64::from(mode.physical_base) / crate::PAGE_SIZE as u64,
        arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
    );
    (arch_abi::FB_WINDOW_BASE + offset, pages)
}

fn capture_native_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    current_bank: Option<u16>,
    logical_pitch: u16,
    state: &mut VgaState,
) -> usize {
    let bytes = mode.framebuffer_bytes as usize;
    let pages = svga_shadow_pages(bytes);
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);

    let mut pixels = alloc::vec![0; bytes];
    if current_bank.is_none() && mode.physical_base != 0 {
        let (address, pages) = map_linear_vbe(machine, mode);
        machine.copy_from(address, &mut pixels);
        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
    } else if let Some(current_bank) = current_bank {
        copy_banked_from_card(machine, bios, display, mode, current_bank, &mut pixels);
    }
    machine.copy_to(SVGA_LFB_BASE, &pixels);

    state.svga_w = mode.width;
    state.svga_h = mode.height;
    state.svga_bpp = mode.bits_per_pixel;
    state.svga_pitch = logical_pitch;
    state.svga_bank = current_bank.unwrap_or(0);
    machine.copy_page_entries(
        (SVGA_LFB_BASE >> 12) + usize::from(state.svga_bank) * WINDOW_PAGES,
        A0000 >> 12,
        WINDOW_PAGES,
    );
    crate::compact_println!("VBE: detached guest mode {:#x} {}x{}x{} into shadow",
        mode.number, mode.width, mode.height, state.svga_bpp);
    pages
}

fn restore_native_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    resume: VideoResume,
    state: &VgaState,
) {
    let VideoResume::Vbe { mode, request, bank, display_start, logical_pitch } = resume else {
        unreachable!("legacy VGA state passed to VBE restore")
    };
    let banked = request & 0x4000 == 0;
    let native_pitch = if banked { mode.banked_pitch } else { mode.linear_pitch };
    if logical_pitch != native_pitch {
        let mut regs = Regs::empty();
        regs.rax = 0x4F06;
        regs.rbx = 2;
        regs.rcx = u64::from(logical_pitch);
        let _ = display.guest_bios_scan_line_length(machine, bios, &mut regs);
    }
    let bytes = mode.framebuffer_bytes as usize;
    let mut pixels = alloc::vec![0; bytes];
    machine.copy_from(SVGA_LFB_BASE, &mut pixels);
    if !banked && mode.physical_base != 0 {
        let (address, pages) = map_linear_vbe(machine, mode);
        machine.copy_to(address, &pixels);
        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
    } else if banked {
        copy_banked_to_card(
            machine, bios, display, mode, bank.unwrap_or(0), &pixels,
        );
    }
    if matches!(mode.format, crate::kernel::display::FormatSpec::Indexed8)
        || mode.programmable_ramp
    {
        restore_native_vbe_palette(machine, bios, display, mode, state);
    }
    let mut regs = Regs::empty();
    regs.rax = 0x4F07;
    regs.rbx = 0;
    regs.rcx = u64::from(display_start.0);
    regs.rdx = u64::from(display_start.1);
    let _ = display.guest_bios_display_start(machine, bios, &mut regs);
    crate::compact_println!("VBE: restored guest mode {:#x} from shadow", mode.number);
}

fn capture_native_vbe_palette<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    _mode: crate::kernel::platform::VbeMode,
    state: &mut VgaState,
) {
    let mut entries = alloc::vec![0; 256 * 4];
    let mut regs = Regs::empty();
    regs.rax = 0x4F09;
    regs.rbx = 1;
    regs.rcx = 256;
    display.bios_palette_call(
        machine, bios, &mut regs, Some(&mut entries), false, true,
    ).unwrap_or_else(|error| lib::compact_panic!(
        "native VBE mode has no palette/ramp read service: {:?}",
        error,
    ));
    for (rgb, entry) in state.dac.chunks_exact_mut(3).zip(entries.chunks_exact(4)) {
        rgb.copy_from_slice(&[entry[2], entry[1], entry[0]]);
    }
    state.dac_mask = 0xFF;
    state.dac_index = 0;
    state.dac_state = 0;
}

fn restore_native_vbe_palette<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    _mode: crate::kernel::platform::VbeMode,
    state: &VgaState,
) {
    let mut entries = alloc::vec![0; 256 * 4];
    for (entry, rgb) in entries.chunks_exact_mut(4).zip(state.dac.chunks_exact(3)) {
        entry.copy_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
    }
    let mut regs = Regs::empty();
    regs.rax = 0x4F09;
    regs.rbx = 0;
    regs.rcx = 256;
    display.bios_palette_call(
        machine, bios, &mut regs, Some(&mut entries), true, true,
    ).unwrap_or_else(|error| lib::compact_panic!(
        "native VBE mode has no palette/ramp write service: {:?}",
        error,
    ));
}

fn copy_banked_from_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    current_bank: u16,
    pixels: &mut [u8],
) {
    let granularity = usize::from(mode.window_granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(mode.window_size_kb).max(1) * 1024;
    let address = usize::from(mode.window_segment) << 4;
    for offset in (0..pixels.len()).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if display.bios_set_bank(machine, bios, mode, bank).is_err() { break; }
        let count = window_bytes.min(pixels.len() - offset);
        machine.copy_from(address, &mut pixels[offset..offset + count]);
    }
    let _ = display.bios_set_bank(machine, bios, mode, current_bank);
}

fn copy_banked_to_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    current_bank: u16,
    pixels: &[u8],
) {
    let granularity = usize::from(mode.window_granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(mode.window_size_kb).max(1) * 1024;
    let address = usize::from(mode.window_segment) << 4;
    for offset in (0..pixels.len()).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if display.bios_set_bank(machine, bios, mode, bank).is_err() { break; }
        let count = window_bytes.min(pixels.len() - offset);
        machine.copy_to(address, &pixels[offset..offset + count]);
    }
    let _ = display.bios_set_bank(machine, bios, mode, current_bank);
}

fn discard_emulated_svga<A: crate::Arch>(machine: &mut A, dev: &mut EmulatedVga) {
    machine.unmap_range(
        SVGA_LFB_BASE >> 12,
        dev.svga_pages,
    );
    let state = &mut dev.state;
    state.svga_w = 0;
    state.svga_h = 0;
    state.svga_bpp = 0;
    state.svga_pitch = 0;
    state.svga_bank = 0;
    dev.svga_pages = 0;
}

/// VBE's `PhysBasePtr`. RetroOS's DOS guest has one paged address space shared
/// by VM86 and PM, so the DPMI "physical" address *is* a guest-linear address:
/// we report the framebuffer's linear base, and a PM/DPMI client reaches it
/// directly through its flat selector — no physical→linear mapping needed.
pub const fn svga_lfb_base() -> u32 {
    SVGA_LFB_BASE as u32
}

pub(crate) fn svga_lfb_reserved_contains(addr: u32, size: u32) -> bool {
    if size == 0 { return false; }
    let base = SVGA_LFB_BASE as u32;
    addr >= base
        && addr.checked_add(size).is_some_and(|end| {
            end <= base + SVGA_LFB_MAX_BYTES as u32
        })
}

/// Commit enough substitute-VBE RAM to cover a DPMI mapping. The allocation
/// grows in place so every alias continues to name the same frames.
pub(crate) fn svga_ensure_lfb<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    addr: u32,
    size: u32,
) -> bool {
    let Some(dev) = pc.vga.emulated_mut() else { return false };
    if dev.state.svga_w == 0 || !svga_lfb_reserved_contains(addr, size) {
        return false;
    }
    let offset = addr as usize - SVGA_LFB_BASE;
    let required = offset.saturating_add(size as usize).div_ceil(crate::PAGE_SIZE);
    if required > dev.svga_pages {
        machine.map_fresh_range(
            (SVGA_LFB_BASE >> 12) + dev.svga_pages,
            required - dev.svga_pages,
        );
        dev.svga_pages = required;
    }
    true
}

/// Enter one curated physical-BIOS mode while the process is detached. The
/// shadow has the hardware's exact pitch, image count and bank layout; only
/// the storage is RAM until the process reacquires the adapter.
pub fn svga_set_curated_mode<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    mode: crate::kernel::platform::VbeMode,
    request: u16,
) {
    svga_leave(machine, pc);
    let Some(dev) = pc.vga.emulated_mut() else { return };
    let pages = (mode.framebuffer_bytes as usize).div_ceil(crate::PAGE_SIZE);
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);
    dev.state.svga_w = mode.width;
    dev.state.svga_h = mode.height;
    dev.state.svga_bpp = mode.bits_per_pixel;
    dev.state.svga_pitch = if request & 0x4000 != 0 {
        mode.linear_pitch
    } else {
        mode.banked_pitch
    };
    dev.state.svga_bank = 0;
    dev.svga_pages = pages;
    let linear = request & 0x4000 != 0 && mode.physical_base != 0;
    dev.physical_lfb = linear.then_some(mode.physical_base);
    dev.resume = VideoResume::Vbe {
        mode,
        request,
        bank: (!linear).then_some(0),
        display_start: (0, 0),
        logical_pitch: dev.state.svga_pitch,
    };
    if linear {
        machine.redirect_physical_aliases(
            u64::from(mode.physical_base) >> 12,
            SVGA_LFB_BASE >> 12,
            pages,
            true,
        );
    } else {
        svga_set_bank(machine, pc, 0);
    }
}

/// VBE 4F05h window control: alias the 0xA0000 window onto `bank` of the
/// framebuffer. No copy — the window simply shares the bank's frames.
pub fn svga_set_bank<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, bank: u16) {
    let Some(dev) = pc.vga.emulated_mut() else { return };
    let vga = &mut dev.state;
    if vga.svga_w == 0 {
        return;
    }
    let (granularity, window_bytes, aperture) = match dev.resume {
        VideoResume::Vbe { mode, .. } => (
            usize::from(mode.window_granularity_kb) * 1024,
            usize::from(mode.window_size_kb) * 1024,
            usize::from(mode.window_segment) << 4,
        ),
        VideoResume::Legacy { .. } => (SVGA_WINDOW, SVGA_WINDOW, A0000),
    };
    if granularity == 0 || window_bytes == 0 { return; }
    let byte_offset = usize::from(bank) * granularity;
    let count = window_bytes.div_ceil(crate::PAGE_SIZE);
    if byte_offset / crate::PAGE_SIZE + count > dev.svga_pages { return; }
    let src = (SVGA_LFB_BASE + byte_offset) >> 12;
    machine.copy_page_entries(src, aperture >> 12, count);
    vga.svga_bank = bank;
    if let VideoResume::Vbe { bank: saved, .. } = &mut dev.resume {
        *saved = Some(bank);
    }
}

/// Leave SVGA for a standard VGA mode: detach the window alias and free the
/// framebuffer region.
pub fn svga_leave<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine) {
    let Some(dev) = pc.vga.emulated_mut() else { return };
    let vga = &mut dev.state;
    if vga.svga_w == 0 {
        return;
    }
    let pages = dev.svga_pages;
    if let Some(physical_base) = dev.physical_lfb.take() {
        machine.redirect_physical_aliases(
            u64::from(physical_base) >> 12,
            SVGA_LFB_BASE >> 12,
            pages,
            false,
        );
    }
    // Detach the window alias (drops its shared ref on the current bank), then
    // free the framebuffer region — frees the frames and leaves the entries
    // absent, the only sane "free" for an allocated RAM region.
    machine.map_fresh_range(A0000 >> 12, WINDOW_PAGES);
    machine.unmap_range(SVGA_LFB_BASE >> 12, pages);
    vga.svga_w = 0;
    vga.svga_h = 0;
    vga.svga_bpp = 0;
    vga.svga_pitch = 0;
    vga.svga_bank = 0;
    dev.svga_pages = 0;
}

/// React to a BIOS INT 10h AH=00 video mode set. Register programming and VRAM
/// layout are committed as one operation: first normalize the old CPU view,
/// then install the new register file, then ask the card model for the new CPU
/// view and aperture mapping. `clear` (AL bit 7 clear) zeroes the planes.
pub fn on_set_mode<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    _regs: &mut Regs,
    mode: u8,
    clear: bool,
) {
    // A standard mode-set leaves any active VESA SVGA mode.
    svga_leave(machine, pc);
    // A real card draws its own planes from its own register file.
    let Some(dev) = pc.vga.emulated_mut() else { return };
    // A BIOS mode set while the VGA is detached (OSD/background execution)
    // starts a new hardware state. The opaque 4F04 image belongs to the old
    // mode; the canonical register file and VRAM below become the complete
    // restore authority.
    dev.resume = VideoResume::Legacy { bios_mode: mode };
    let vga = &mut dev.state;
    let mut planes = read_live_planes(machine);
    let old_layout = vga.layout();
    // Program the full canonical register file, exactly as a real BIOS does
    // from its video parameter table. This is what keeps classification
    // register-pure (the hardware never consults BIOS data): a tweaker
    // starts every mode from the same coherent state a real BIOS leaves —
    // and a mode set CLEARS the previous program's tweaks, so Jazz's
    // unchained level mode can't leak into its menu's mode 13h (stale
    // display-start showed the menu at the wrong offset; stale shift/chain
    // bits later misclassified the menu as the level's Mode X entirely).
    if let Some(r) = ::vga::bios_mode_regs(mode) {
        vga.misc_output = r.misc;
        vga.seq = r.seq;
        vga.gc = r.gc;
        vga.crtc = r.crtc;
    }
    let new_layout = vga.layout();
    if old_layout != new_layout {
        ::vga::VramTransition::between(old_layout, new_layout).apply(&mut planes);
    }
    // A real VGA BIOS reloads the DAC on every clearing mode set. Which default
    // depends on the render path: text/CGA/mode 13h index DAC entries directly
    // and need the 16 CGA colours at entries 0..15; planar 16-colour modes map
    // pixels through the Attribute Controller first.
    if matches!(mode, 0x0D..=0x12) {
        // Install the planar EGA DAC even on no-clear mode sets: many EGA games
        // never program the DAC, and our fresh process default is the generic
        // mode-13h fallback. VGA uses an RGBI-compatibility DAC for the 200-line
        // EGA modes (0Dh/0Eh) and the full 64-colour EGA DAC for 350/480-line
        // planar modes.
        vga.dac = if matches!(mode, 0x0D | 0x0E) {
            ::vga::ega_200line_dac()
        } else {
            ::vga::ega_dac()
        };
    } else if clear {
        vga.dac = ::vga::fallback_palette();
    }
    let planar = matches!(mode, 0x0D..=0x12);
    if planar {
        // Standard EGA AC palettes, straight out of the BIOS video parameter
        // table. The 200-line modes are the RGBI-compatibility family: colour
        // 6 is brown at 0x06 (green's secondary bit is the intensity bit, not
        // a colour bit) and the bright bank sits at 0x10..0x17 — the SAME eight
        // DAC entries a game reprograms when it loads its own 16 colours
        // (Xenon 2 writes DAC 0x00..0x17 and never touches the AC). The
        // 350/480-line modes use the full 64-colour EGA encoding instead:
        // brown is 0x14 and the bright bank is 0x38..0x3F.
        const EGA_AC_NORMAL: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];
        const EGA_AC_200LINE: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let ac = if matches!(mode, 0x0D | 0x0E) {
            &EGA_AC_200LINE
        } else {
            &EGA_AC_NORMAL
        };
        vga.ac[..16].copy_from_slice(ac);
        vga.ac[0x10] &= !0x80; // P4/P5 from palette, not colour-select
        vga.ac[0x12] = 0x0F; // colour plane enable: all planes visible
        vga.ac[0x13] = 0x00; // pixel pan
        vga.ac[0x14] = 0x00; // colour select high bits
    }
    if clear { planes.fill(0); }
    // A VGA BIOS text-mode set reloads the ROM character generator even when
    // AL bit 7 asks it to preserve display memory. Once scanout uses the real
    // plane-2 font, omitting this leaves every ordinary BIOS text screen with
    // an all-zero character map after the plane clear above.
    if matches!(mode, 0..=3 | 7) {
        ::vga::load_font_map(
            &mut planes,
            vga.layout(),
            0,
            &lib::vga_fonts::FONT_8X16,
            16,
        );
    }
    write_live_planes(machine, &planes);
    install_aperture(machine, vga.cpu_aperture());
}

/// Trapped planar VRAM write: run the Graphics Controller write-mode logic for a
/// CPU store of `byte` at A0000 offset `off`, fanning it into the 4 planes
/// in the page-backed planes. Used when a linear alias can't model the access —
/// write mode 1 (Mode X latched copy), write modes 2/3, or a multi-plane EGA
/// write. Latches must have been loaded by a prior `vram_read`.
pub fn vram_write<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, off: u32, byte: u8) {
    let (off, map_mask) = vga.cpu_write_address(off as usize);
    let layout = vga.layout();
    let cur = core::array::from_fn(|p| {
        machine.read::<u8>(VGA_VRAM_BASE + layout.index(p, off))
    });
    let out = ::vga::planar_write(cur, vga.latches, &vga.gc, map_mask, byte);
    for p in 0..4 {
        if out[p] != cur[p] {
            machine.write::<u8>(VGA_VRAM_BASE + layout.index(p, off), out[p]);
        }
    }
}

/// Copy bytes into guest memory, routing any overlap with a trap-backed planar
/// A0000 window through the VGA write path. DOS services can legally transfer
/// file/device data straight into video memory; on a real VGA those CPU stores
/// still honour map mask/write-mode/latches, while the emulated path has A0000
/// unmapped so raw `machine.copy_to` would fault in the kernel.
pub fn copy_to_guest<A: crate::Arch>(machine: &mut A, vga: &mut DosVideo, addr: usize, src: &[u8]) {
    let Some(vga) = vga.emulated_mut() else {
        machine.copy_to(addr, src);
        return;
    };
    let vga = &mut vga.state;
    let Some(pages) = trapped_aperture(vga) else {
        machine.copy_to(addr, src);
        return;
    };
    let window_base = usize::from(pages.start) << 12;
    let window_end = usize::from(pages.end) << 12;
    if src.is_empty()
        || addr >= window_end
        || addr.saturating_add(src.len()) <= window_base
    {
        machine.copy_to(addr, src);
        return;
    }

    let mut pos = 0;
    if addr < window_base {
        let n = (window_base - addr).min(src.len());
        machine.copy_to(addr, &src[..n]);
        pos = n;
    }

    while pos < src.len() {
        let cur = addr + pos;
        if cur >= window_end {
            machine.copy_to(cur, &src[pos..]);
            break;
        }
        let n = (window_end - cur).min(src.len() - pos);
        for (i, &byte) in src[pos..pos + n].iter().enumerate() {
            vram_write(machine, vga, (cur + i - window_base) as u32, byte);
        }
        pos += n;
    }
}

/// Trapped planar VRAM read: load the 4 latches from the planes at A0000 offset
/// `off` and return the byte the CPU sees (read map select, or color compare).
pub fn vram_read<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, off: u32) -> u8 {
    let (off, read_plane) = vga.cpu_read_address(off as usize);
    let layout = vga.layout();
    let cur = core::array::from_fn(|p| {
        machine.read::<u8>(VGA_VRAM_BASE + layout.index(p, off))
    });
    let mut gc = vga.gc;
    gc[4] = read_plane as u8;
    let (data, latches) = ::vga::planar_read(cur, &gc);
    vga.latches = latches;
    vga.latches_valid = true;
    data
}

/// Rasterize the 8-wide glyph for `ch` into the current *graphics*-mode
/// framebuffer at character cell `(col,row)`, foreground pixel colour `fg`.
/// A BIOS teletype/write-char in a graphics mode must draw font pixels (there
/// is no text cell to poke) — this covers every graphics mode the model draws:
/// CGA 4-colour (04h/05h) and 2-colour (06h) at 0xB8000, EGA/VGA 16-colour
/// planar (0Dh–12h) into page-backed planes, and linear 256-colour mode 13h at
/// 0xA0000. Returns `false` for a non-graphics mode (caller takes the text-cell
/// path). Cell background pixels are cleared, so a cell fully replaces what was
/// under it, matching a real BIOS's replace (non-XOR) glyph write.
///
/// Each mode uses the ROM font matching its character-cell height: the authentic
/// IBM 8×8 (200-line modes + 13h), 8×14 (EGA 350-line), or 8×16 (VGA 480-line).
/// For an emulated card the live register file, rather than the advisory BDA
/// mode byte, selects the memory layout. Programs are allowed to reprogram the
/// adapter directly and can therefore leave the BDA stale. A native card has
/// no shadow register file; its BIOS mode byte selects the CPU-visible legacy
/// aperture, whose packed mode-4/6 and mode-13 layouts are standardized.
pub fn bios_draw_glyph<A: crate::Arch>(
    machine: &mut A,
    device: &mut DosVideo,
    bios_mode: u8,
    ch: u8,
    col: u32,
    row: u32,
    fg: u8,
) -> bool {
    let mode = match device {
        DosVideo::Fullscreen(FullscreenVga::Native(_)) => bios_mode,
        DosVideo::Vga(dev) | DosVideo::Fullscreen(FullscreenVga::Emulated(dev, _)) =>
            match dev.state.classify_mode() {
            None => return false,
            Some(mode) => match mode {
                ::vga::VgaMode::Text { .. } => return false,
                ::vga::VgaMode::Cga4 => 0x04,
                ::vga::VgaMode::Cga2 => 0x06,
                ::vga::VgaMode::Mode13h => 0x13,
                ::vga::VgaMode::Planar16 { w, h, .. } => match (w, h) {
                    (_, 351..) => 0x12,
                    (_, 201..) => 0x10,
                    (..=320, _) => 0x0D,
                    _ => 0x0E,
                },
                // BIOS text services have no conventional raster contract for
                // a tweaked Mode X or substitute-VBE framebuffer.
                ::vga::VgaMode::ModeX { .. } | ::vga::VgaMode::LinearSvga { .. } => return false,
            },
        },
    };
    let (cell_h, font): (u32, &[u8]) = match mode {
        0x0F | 0x10 => (14, &lib::vga_fonts::FONT_8X14),
        0x11 | 0x12 => (16, &lib::vga_fonts::FONT_8X16),
        0x04 | 0x05 | 0x06 | 0x0D | 0x0E | 0x13 => (8, &lib::vga_fonts::FONT_8X8),
        _ => return false, // text mode (0..3, 7) — caller writes a char cell
    };
    let base = ch as usize * cell_h as usize;
    let glyph = |gy: u32| -> u8 { font[base + gy as usize] };
    let (px0, py0) = (col * 8, row * cell_h);

    match mode {
        // Linear 256-colour: one byte per pixel at 0xA0000, stride 320.
        0x13 => {
            for gy in 0..cell_h {
                let bits = glyph(gy);
                let py = py0 + gy;
                for gx in 0..8u32 {
                    let color = if bits & (0x80 >> gx) != 0 { fg } else { 0 };
                    machine.write::<u8>(0xA0000 + (py * 320 + px0 + gx) as usize, color);
                }
            }
        }
        // CGA 4-colour: 2 bpp at 0xB8000, four pixels/byte, even scanlines at
        // offset 0 and odd at +0x2000, 80-byte rows within a bank.
        0x04 | 0x05 => {
            for gy in 0..8u32 {
                let bits = glyph(gy);
                let py = py0 + gy;
                let bank = 0xB8000 + ((py & 1) * 0x2000 + (py >> 1) * 80) as usize;
                for gx in 0..8u32 {
                    let px = px0 + gx;
                    let color = if bits & (0x80 >> gx) != 0 { fg & 0x03 } else { 0 };
                    let off = bank + (px / 4) as usize;
                    let shift = 6 - (px & 3) * 2;
                    let mut b: u8 = machine.read(off);
                    b = (b & !(0x03 << shift)) | (color << shift);
                    machine.write::<u8>(off, b);
                }
            }
        }
        // CGA 2-colour: 1 bpp at 0xB8000, eight pixels/byte, same bank interleave.
        0x06 => {
            for gy in 0..8u32 {
                let bits = glyph(gy);
                let py = py0 + gy;
                let bank = 0xB8000 + ((py & 1) * 0x2000 + (py >> 1) * 80) as usize;
                for gx in 0..8u32 {
                    let px = px0 + gx;
                    let off = bank + (px / 8) as usize;
                    let mask = 0x80u8 >> (px & 7);
                    let mut b: u8 = machine.read(off);
                    if bits & (0x80 >> gx) != 0 { b |= mask; } else { b &= !mask; }
                    machine.write::<u8>(off, b);
                }
            }
        }
        // EGA/VGA 16-colour planar: set/clear each of the 4 plane bits for the
        // pixel from the 4-bit colour, in page-backed VRAM (what the renderer
        // scans out). Stride follows the CRTC Offset like `classify_mode`.
        0x0D..=0x12 => {
            // Native planar drawing must go through the adapter's GC/latches;
            // this software plane store exists only for the emulated card.
            let Some(dev) = device.emulated_mut() else { return false };
            let vga = &mut dev.state;
            let width: u32 = if mode == 0x0D { 320 } else { 640 };
            let rb = if vga.crtc[0x13] != 0 { vga.crtc[0x13] as u32 * 2 } else { width / 8 };
            for gy in 0..cell_h {
                let bits = glyph(gy);
                let py = py0 + gy;
                for gx in 0..8u32 {
                    let px = px0 + gx;
                    let color = if bits & (0x80 >> gx) != 0 { fg & 0x0F } else { 0 };
                    let byte_off = (py * rb + px / 8) as usize;
                    let mask = 0x80u8 >> (px & 7);
                    for p in 0..4usize {
                        let addr = VGA_VRAM_BASE + p * 0x10000 + byte_off;
                        let mut byte: u8 = machine.read(addr);
                        if (color >> p) & 1 != 0 { byte |= mask; } else { byte &= !mask; }
                        machine.write::<u8>(addr, byte);
                    }
                }
            }
        }
        _ => return false,
    }
    true
}

// ============================================================================
// Emulated display: render to the platform's present sink
// ============================================================================
