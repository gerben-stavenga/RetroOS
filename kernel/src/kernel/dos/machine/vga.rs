//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live state behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `//lib:vga`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

use crate::Regs;
use super::*;
use crate::kernel::bios_display::{DosVideo, FullscreenVga, EmulatedVga};

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
    crate::kernel::platform::get().vga_passthrough
}

impl EmulatedVga {
    fn materialize<A: crate::Arch>(&mut self, machine: &mut A) {
        materialize_emulated_aperture(self, machine);
    }

    fn suspend<A: crate::Arch>(&mut self, machine: &A) {
        self.save_vram(live_vram(machine));
    }

    fn save_vram(&mut self, live: &[u8]) {
        match &mut self.state {
            VgaState::Legacy(state) if state.planes.is_empty() => {
                state.planes.extend_from_slice(&live[..PLANES_LEN]);
            }
            VgaState::Vbe(svga) if self.svga_vram.is_empty() => {
                let bytes = svga.config.framebuffer_bytes as usize;
                self.svga_vram.extend_from_slice(&live[..bytes]);
            }
            _ => {}
        }
    }

    #[cfg(test)]
    fn restore_vram(&mut self, live: &mut [u8]) {
        match &mut self.state {
            VgaState::Legacy(state) if !state.planes.is_empty() => {
                live[..PLANES_LEN].copy_from_slice(&state.planes);
                state.planes.clear();
            }
            VgaState::Vbe(svga) if !self.svga_vram.is_empty() => {
                let bytes = svga.config.framebuffer_bytes as usize;
                live[..bytes].copy_from_slice(&self.svga_vram[..bytes]);
                self.svga_vram.clear();
            }
            _ => {}
        }
    }

    fn resume_vram<A: crate::Arch>(&mut self, machine: &mut A) {
        self.materialize(machine);
    }

    /// The single native-to-emulated transition. Legacy VGA state is captured
    /// from the authoritative adapter. Chipsets without readable latches or a
    /// VBE 4F04 checkpoint retain the complete public register/VRAM state and
    /// explicitly leave the unobservable latch field invalid. VBE metadata and
    /// palette come from the authoritative RetroOS shadows; only its directly
    /// mapped framebuffer is copied back from hardware.
    fn snapshot_native<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        native: &mut crate::kernel::platform::NativeVga,
    ) -> Self {
        let current = bios.vbe_state().copied();
        if let Some(active) = current {
            let mode = active.mode;
            let pages = capture_native_vbe(
                machine, bios, native.cap_mut(), mode, active.svga);
            let mut emulated = Self {
                state: VgaState::Vbe(alloc::boxed::Box::new(active.svga)),
                svga_pages: pages,
                svga_vram: alloc::vec::Vec::new(),
            };
            materialize_emulated_aperture(&mut emulated, machine);
            return emulated;
        }
        let mut legacy = ::vga::LegacyVgaState::new_boxed();
        let cirrus_readback = crate::kernel::platform::get().vga_readback;
        let checkpoint = if cirrus_readback {
            None
        } else {
            native.cap().bios_checkpoint(machine, bios)
        };
        crate::kernel::drivers::vga_hw::save(native.cap(), &mut legacy, cirrus_readback);
        if let Some(checkpoint) = checkpoint.as_ref() {
            native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
            crate::kernel::drivers::vga_hw::write_latches_and_readback(&mut legacy);
            native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
            let plane_enable = crate::kernel::drivers::vga_hw::read_ac_register(0x12);
            native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
            crate::kernel::drivers::vga_hw::correct_flip_flop_phase(&mut legacy, plane_enable);
            native.cap().bios_restore_checkpoint(machine, bios, checkpoint);
            crate::kernel::drivers::vga_hw::checkpoint_restored(&legacy);
        }
        let mut emulated = Self {
            state: VgaState::Legacy(legacy),
            svga_pages: 0,
            svga_vram: alloc::vec::Vec::new(),
        };
        materialize_emulated_aperture(&mut emulated, machine);
        emulated
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
        match &mut self.state {
            VgaState::Vbe(svga) => {
                let svga = **svga;
                native.bios_set_mode_request(machine, &mut *bios, svga.mode_value());
                if let Some(mode) = bios.vbe_state().map(|state| state.mode) {
                    restore_native_vbe(machine, bios, &mut native, mode, svga);
                }
                discard_emulated_svga(machine, &mut self);
                if let Some(mode) = bios.vbe_state().map(|state| state.mode) {
                    select_native_svga_aperture(machine, mode, svga.access);
                }
            }
            VgaState::Legacy(state) => {
                if state.planes.is_empty() {
                    state.planes.extend_from_slice(live_planes(machine));
                }
                // A register restore alone cannot leave an active VBE mode:
                // the adapter's SVGA scanout engine may remain enabled and
                // continue displaying its linear framebuffer while the VGA
                // registers and planes change behind it. Cross the firmware
                // boundary first using the mode recorded by the guest BIOS:
                // this establishes the adapter extensions and firmware BDA,
                // while the exact saved register file and planes restored
                // below retain any subsequent Mode X or other VGA tweaking.
                let bios_mode = crate::kernel::dos::bios::Bda::video_mode(machine);
                native.bios_set_mode(machine, bios, u16::from(bios_mode));
                crate::kernel::drivers::vga_hw::restore(&native, state);
            }
        }
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
            Ok(native) => {
                let needs_software_lfb = self.state.svga().is_some_and(|svga| {
                    matches!(svga.access, ::vga::SvgaAccess::Linear)
                        && bios.curated_mode(svga.mode_number)
                            .is_some_and(|mode| mode.physical_base == 0)
                });
                if needs_software_lfb {
                    FullscreenVga::Emulated(
                        self,
                        crate::kernel::display::Display::new_selected(machine, bios, native),
                    )
                } else {
                    self.attach_native(machine, native, bios)
                }
            }
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
                vga.materialize(machine);
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
            Self::Vga(vga) => vga.materialize(machine),
            Self::Fullscreen(vga) => vga.initialize_active_address_space(machine),
        }
    }

    pub fn clone_detached_for_child<A: crate::Arch>(&mut self, machine: &mut A) -> Option<Self> {
        let Self::Vga(vga) = self else { return None };
        vga.suspend(machine);
        let child = vga.clone_for_fork();
        // Fork took a snapshot, but the parent still owns live VRAM until the
        // actual execution handoff. Keep its allocation, not a stale image.
        if let Some(state) = vga.state.legacy_mut() { state.planes.clear(); }
        vga.svga_vram.clear();
        Some(Self::Vga(child))
    }

    pub fn capture_address_space_vram<A: crate::Arch>(&mut self, machine: &mut A) {
        if let Some(vga) = self.emulated_mut() {
            vga.suspend(machine);
        }
    }

    pub fn resume_vram<A: crate::Arch>(&mut self, machine: &mut A) {
        if let Some(vga) = self.emulated_mut() {
            vga.resume_vram(machine);
        }
    }

    pub fn release_for_parent_replace<A: crate::Arch>(&mut self, machine: &mut A) -> Self {
        self.map(|mut returned| {
            if let Some(vga) = returned.emulated_mut() {
                vga.suspend(machine);
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
                    child.materialize(machine);
                    Self::Fullscreen(FullscreenVga::Emulated(child, display))
                }
                Self::Vga(mut child) => {
                    child.materialize(machine);
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
pub use ::vga::{LegacyVgaState, VgaState};

/// Non-destructively decide whether the currently owned VGA is already the
/// conventional colour 80x25 text screen expected when COMMAND.COM returns.
pub fn is_standard_text(device: &DosVideo) -> bool {
    match device {
        DosVideo::Fullscreen(FullscreenVga::Native(native)) =>
            crate::kernel::drivers::vga_hw::is_standard_text_mode(native.cap()),
        DosVideo::Vga(dev) | DosVideo::Fullscreen(FullscreenVga::Emulated(dev, _)) =>
            dev.state.legacy().is_some_and(|state| ::vga::is_standard_text(&::vga::Regs {
                crtc: state.crtc, seq: state.seq, gc: state.gc, misc: state.misc_output,
            })),
    }
}

/// Present the emulated planes to the guest at A0000/B8000 — map the window
/// and fill it from suspended state, or mark it trapped when writes must
/// go through the planar ALU. Needs an address space, so it is not the card's.
fn materialize_emulated_aperture<A: crate::Arch>(dev: &mut EmulatedVga, machine: &mut A) {
    match &mut dev.state {
        VgaState::Legacy(state) => {
            let base = initialize_live_vram(machine, PLANES_LEN >> 12);
            unsafe { machine.map_shared_pages(VGA_VRAM_BASE >> 12, base, PLANES_LEN >> 12); }
            // An empty image means this device already resides in LiveVram.
            // `initialize_active_address_space` and the subsequent resume hook
            // may both bind it; rebinding must not erase the resident planes.
            if !state.planes.is_empty() {
                assert_eq!(state.planes.len(), PLANES_LEN);
                write_live_planes(machine, &state.planes);
                state.planes.clear();
            }
            install_aperture(machine, state.cpu_aperture());
        }
        VgaState::Vbe(svga) => {
            let pages = (svga.config.framebuffer_bytes as usize).div_ceil(crate::PAGE_SIZE);
            let base = initialize_live_vram(machine, pages);
            unsafe {
                machine.map_shared_pages(VGA_VRAM_BASE >> 12, base, pages);
                machine.map_shared_pages(SVGA_LFB_BASE >> 12, base, pages);
            }
            dev.svga_pages = pages;
            if !dev.svga_vram.is_empty() {
                let bytes = svga.config.framebuffer_bytes as usize;
                live_vram_mut(machine)[..bytes].copy_from_slice(&dev.svga_vram[..bytes]);
                dev.svga_vram.clear();
            }
            machine.copy_page_entries(
                (SVGA_LFB_BASE >> 12)
                    + usize::from(svga.bank().map_or(0, |bank| bank)) * WINDOW_PAGES,
                A0000 >> 12,
                WINDOW_PAGES,
            );
        }
    }
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


/// The shared live VGA store. `VgaState::layout()` maps logical
/// `(plane, offset)` to its byte. Suspended owners retain a private snapshot;
/// the running owner, guest aperture and renderer use the kernel store.
const PLANES_LEN: usize = 4 * 0x10000;
const A0000: usize = 0xA0000;

// The DOS VGA device owns the singleton, its size and its lifetime. Backends
// only allocate/map generic shared RAM; they know nothing about this device.
static LIVE_VRAM: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static LIVE_VRAM_PAGES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Commit the largest framebuffer this machine's DOS VBE boundary can expose
/// before XMS/EMS/DPMI report free memory. A native BIOS supplies its exact
/// curated capacity; the firmware-independent VBE uses RetroOS's own aperture.
pub(crate) fn reserve_live_vram<A: crate::Arch>(
    machine: &mut A,
    native_modes: Option<&[crate::kernel::platform::VbeMode]>,
) {
    let bytes = native_modes.map_or(SVGA_LFB_MAX_BYTES, |modes| {
        modes.iter().map(|mode| mode.framebuffer_bytes as usize)
            .max().unwrap_or(PLANES_LEN)
    });
    initialize_live_vram(machine, bytes.max(PLANES_LEN).div_ceil(crate::PAGE_SIZE));
}

fn initialize_live_vram<A: crate::Arch>(
    machine: &mut A,
    required_pages: usize,
) -> core::ptr::NonNull<u8> {
    use core::sync::atomic::Ordering;
    let pages = LIVE_VRAM_PAGES.load(Ordering::Relaxed);
    if pages >= required_pages
        && let Some(base) = core::ptr::NonNull::new(LIVE_VRAM.load(Ordering::Relaxed))
    {
        return base;
    }
    // Only the single-threaded kernel event loop constructs VGA owners.
    let base = machine.alloc_shared_pages(required_pages);
    if let Some(old) = core::ptr::NonNull::new(LIVE_VRAM.load(Ordering::Relaxed)) {
        let old_bytes = pages * crate::PAGE_SIZE;
        unsafe { core::ptr::copy_nonoverlapping(old.as_ptr(), base.as_ptr(), old_bytes); }
    }
    LIVE_VRAM.store(base.as_ptr(), Ordering::Relaxed);
    LIVE_VRAM_PAGES.store(required_pages, Ordering::Relaxed);
    base
}

fn live_vram_ptr() -> *mut u8 {
    let base = LIVE_VRAM.load(core::sync::atomic::Ordering::Relaxed);
    assert!(!base.is_null(), "VGA VRAM used before device initialization");
    base
}

fn live_vram_ptr_if_initialized() -> Option<core::ptr::NonNull<u8>> {
    core::ptr::NonNull::new(
        LIVE_VRAM.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Borrow the device while guest execution and owner switches are excluded.
pub(crate) fn live_planes<A>(_machine: &A) -> &[u8] {
    &live_vram(_machine)[..PLANES_LEN]
}

pub(crate) fn live_vram<A>(_machine: &A) -> &[u8] {
    use core::sync::atomic::Ordering;
    let bytes = LIVE_VRAM_PAGES.load(Ordering::Relaxed) * crate::PAGE_SIZE;
    unsafe { core::slice::from_raw_parts(live_vram_ptr(), bytes) }
}

/// Guest page range whose CPU accesses must pass through the emulated VGA's
/// planar ALU. The card derives this together with its VRAM layout.
pub fn trapped_aperture(vga: &LegacyVgaState) -> Option<core::ops::Range<u16>> {
    match vga.cpu_aperture() {
        ::vga::CpuAperture::Trapped { range } =>
            Some(range.start_page..range.end_page),
        _ => None,
    }
}
/// Guest alias of the shared kernel VRAM. CPU apertures alias these same
/// pages; address-space teardown/fork must never free or privatize them.
pub(crate) const VGA_VRAM_BASE: usize = 0x4100_0000;

fn live_planes_mut<A>(_machine: &mut A) -> &mut [u8] {
    // The exclusive machine borrow prevents guest entry/owner switches while
    // this kernel view is held. IRQ handlers never access emulated VRAM.
    unsafe { core::slice::from_raw_parts_mut(live_vram_ptr(), PLANES_LEN) }
}

fn live_vram_mut<A>(_machine: &mut A) -> &mut [u8] {
    use core::sync::atomic::Ordering;
    let bytes = LIVE_VRAM_PAGES.load(Ordering::Relaxed) * crate::PAGE_SIZE;
    unsafe { core::slice::from_raw_parts_mut(live_vram_ptr(), bytes) }
}

fn write_live_planes<A: crate::Arch>(machine: &mut A, planes: &[u8]) {
    assert_eq!(planes.len(), PLANES_LEN);
    live_planes_mut(machine).copy_from_slice(planes);
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
    state: &mut LegacyVgaState,
    port: u16,
    value: u8,
) {
    let write = state.port_write(port, value);
    if let Some(transition) = write.vram_transition {
        transition.apply(live_planes_mut(machine));
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
    let Some(vga) = dev.state.legacy_mut() else { return };
    ::vga::load_font_glyphs(
        live_planes_mut(machine),
        vga.layout(),
        map,
        first,
        font,
        glyph_h,
    );
}

/// Apply the text geometry selected by INT 10h AX=111xh. The 14-line ROM font
/// selects the VGA's 350-line text timing; 8- and 16-line fonts use 400 lines.
pub fn bios_set_text_height(device: &mut DosVideo, glyph_h: u8) {
    let Some(dev) = device.emulated_mut() else { return };
    let visible = if glyph_h == 14 { 350u16 } else { 400u16 };
    let end = visible - 1;
    let Some(state) = dev.state.legacy_mut() else { return };
    state.crtc[9] = (state.crtc[9] & 0xE0) | (glyph_h - 1);
    state.crtc[0x12] = end as u8;
    state.crtc[7] = (state.crtc[7] & !0x42)
        | (((end >> 8) as u8 & 1) << 1)
        | (((end >> 9) as u8 & 1) << 6);
}

/// BIOS text services program the same registers as direct guest port I/O.
pub fn bios_write_crtc<A: crate::Arch>(
    machine: &mut A, device: &mut DosVideo, port: u16, index: u8, value: u8,
) {
    if let Some(dev) = device.emulated_mut() {
        if let Some(state) = dev.state.legacy_mut() {
            state.crtc_index = index;
            state.crtc[usize::from(index)] = value;
        }
    } else if device.is_native() {
        machine.outb(port, index);
        machine.outb(port + 1, value);
    }
}

pub fn bios_set_font_map_select(device: &mut DosVideo, select: u8) {
    if let Some(dev) = device.emulated_mut()
        && let Some(state) = dev.state.legacy_mut()
    {
        state.seq[3] = select;
    }
}

// ============================================================================
// VESA SVGA. The framebuffer is the kernel-owned LiveVram store. A
// real-mode guest reaches one 64 KB bank at a time through the 0xA0000 window,
// which we *alias* onto the bank (shared frames via copy_page_entries) — guest
// writes land directly in the framebuffer, always coherent, no copy. A
// protected-mode client reaches the same pages through RetroOS's fixed
// PhysBasePtr. `display_tick` reads the permanent kernel mapping directly.
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

/// Copy between two mappings without allocating another whole VRAM image.
/// The saved guest framebuffer is already the persistent storage; a full-size
/// kernel bounce buffer doubles its RAM cost and exhausts 32 MiB machines.
fn copy_vbe_memory<A: crate::Arch>(
    machine: &mut A,
    source: usize,
    destination: usize,
    bytes: usize,
    scratch: &mut [u8],
) {
    for offset in (0..bytes).step_by(scratch.len()) {
        let count = scratch.len().min(bytes - offset);
        machine.copy_from(source + offset, &mut scratch[..count]);
        machine.copy_to(destination + offset, &scratch[..count]);
    }
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
    svga: ::vga::SvgaState,
) -> usize {
    let bytes = mode.framebuffer_bytes as usize;
    let pages = svga_shadow_pages(bytes);
    let base = initialize_live_vram(machine, pages);
    unsafe {
        machine.map_shared_pages(VGA_VRAM_BASE >> 12, base, pages);
        machine.map_shared_pages(SVGA_LFB_BASE >> 12, base, pages);
    }

    let mut scratch = alloc::vec![0; crate::PAGE_SIZE];
    if matches!(svga.access, ::vga::SvgaAccess::Linear) && mode.physical_base != 0 {
        let (address, pages) = map_linear_vbe(machine, mode);
        copy_vbe_memory(machine, address, SVGA_LFB_BASE, bytes, &mut scratch);
        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
    } else if let Some(current_bank) = svga.bank() {
        copy_banked_from_card(machine, bios, display, mode, current_bank, &mut scratch);
    }

    machine.copy_page_entries(
        (SVGA_LFB_BASE >> 12) + usize::from(svga.bank().map_or(0, |bank| bank)) * WINDOW_PAGES,
        A0000 >> 12,
        WINDOW_PAGES,
    );
    crate::compact_println!("VBE: detached guest mode {:#x} {}x{}x{} into shadow",
        mode.number, mode.width, mode.height, mode.bits_per_pixel);
    pages
}

fn restore_native_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    svga: ::vga::SvgaState,
) {
    let (display_start, logical_pitch) = (svga.display_start, svga.logical_pitch);
    let banked = matches!(svga.access, ::vga::SvgaAccess::Banked { .. });
    let native_pitch = if banked { mode.banked_pitch } else { mode.linear_pitch };
    if logical_pitch != native_pitch {
        let mut regs = Regs::empty();
        regs.rax = 0x4F06;
        regs.rbx = 2;
        regs.rcx = u64::from(logical_pitch);
        let _ = display.guest_bios_scan_line_length(machine, bios, &mut regs);
    }
    let bytes = mode.framebuffer_bytes as usize;
    let mut scratch = alloc::vec![0; crate::PAGE_SIZE];
    if !banked && mode.physical_base != 0 {
        let (address, pages) = map_linear_vbe(machine, mode);
        copy_vbe_memory(machine, SVGA_LFB_BASE, address, bytes, &mut scratch);
        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
    } else if let ::vga::SvgaAccess::Banked { bank } = svga.access {
        copy_banked_to_card(
            machine, bios, display, mode, bank, &mut scratch,
        );
        // The bulk copier restores this physical bank through its private
        // low-level helper. Commit the same value to the authoritative VBE
        // shadow through the public operation as well.
        let _ = display.guest_bios_window(machine, bios, Some(bank));
    }
    if matches!(mode.format, crate::kernel::display::FormatSpec::Indexed8)
        || mode.programmable_ramp
    {
        restore_native_vbe_palette(machine, bios, display, &svga.palette);
    }
    let mut regs = Regs::empty();
    regs.rax = 0x4F07;
    regs.rbx = 0;
    regs.rcx = u64::from(display_start.0);
    regs.rdx = u64::from(display_start.1);
    let _ = display.guest_bios_display_start(machine, bios, &mut regs);
    crate::compact_println!("VBE: restored guest mode {:#x} from shadow", mode.number);
}

fn restore_native_vbe_palette<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    palette: &::vga::VbePalette,
) {
    let Some(state) = bios.vbe_state_mut() else { return };
    state.svga.palette.width = palette.width;
    let mut entries = alloc::vec![0; 256 * 4];
    if !palette.read(0, &mut entries) { return; }
    if display.bios_indexed_palette_call(machine, bios, 0, 0, &mut entries).is_ok()
        && let Some(state) = bios.vbe_state_mut()
    {
        state.svga.palette.clear_dirty();
    }
}

fn copy_banked_from_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    current_bank: u16,
    scratch: &mut [u8],
) {
    let granularity = usize::from(mode.window_granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(mode.window_size_kb).max(1) * 1024;
    let address = usize::from(mode.window_segment) << 4;
    let bytes = mode.framebuffer_bytes as usize;
    for offset in (0..bytes).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if display.bios_set_bank(machine, bios, mode, bank).is_err() { break; }
        let count = window_bytes.min(bytes - offset);
        copy_vbe_memory(machine, address, SVGA_LFB_BASE + offset, count, scratch);
    }
    let _ = display.bios_set_bank(machine, bios, mode, current_bank);
}

fn copy_banked_to_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    mode: crate::kernel::platform::VbeMode,
    current_bank: u16,
    scratch: &mut [u8],
) {
    let granularity = usize::from(mode.window_granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(mode.window_size_kb).max(1) * 1024;
    let address = usize::from(mode.window_segment) << 4;
    let bytes = mode.framebuffer_bytes as usize;
    for offset in (0..bytes).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if display.bios_set_bank(machine, bios, mode, bank).is_err() { break; }
        let count = window_bytes.min(bytes - offset);
        copy_vbe_memory(machine, SVGA_LFB_BASE + offset, address, count, scratch);
    }
    let _ = display.bios_set_bank(machine, bios, mode, current_bank);
}

fn discard_emulated_svga<A: crate::Arch>(machine: &mut A, dev: &mut EmulatedVga) {
    machine.unmap_range(
        SVGA_LFB_BASE >> 12,
        dev.svga_pages,
    );
    dev.svga_pages = 0;
}

fn map_native_lfb<A: crate::Arch>(
    machine: &mut A,
    mode: crate::kernel::platform::VbeMode,
    pages: usize,
) {
    let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
    machine.map_phys_range(
        SVGA_LFB_BASE >> 12,
        pages,
        u64::from(mode.physical_base) >> 12,
        arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
    );
    debug_assert_eq!(offset, 0, "VBE LFB aperture must be page aligned");
}

pub(crate) fn select_native_svga_aperture<A: crate::Arch>(
    machine: &mut A,
    mode: crate::kernel::platform::VbeMode,
    access: ::vga::SvgaAccess,
) {
    let pages = (mode.framebuffer_bytes as usize).div_ceil(crate::PAGE_SIZE);
    if matches!(access, ::vga::SvgaAccess::Linear) && mode.physical_base != 0 {
        map_native_lfb(machine, mode, pages);
    } else {
        machine.unmap_range(SVGA_LFB_BASE >> 12, pages);
        let physical = if mode.window_segment != 0 {
            usize::from(mode.window_segment) << 4
        } else {
            mode.physical_base as usize
        };
        if physical != 0 {
            machine.map_phys_range(
                A0000 >> 12,
                WINDOW_PAGES,
                (physical >> 12) as u64,
                arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
            );
        }
    }
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
    let base = initialize_live_vram(machine, pages);
    unsafe {
        machine.map_shared_pages(VGA_VRAM_BASE >> 12, base, pages);
        machine.map_shared_pages(SVGA_LFB_BASE >> 12, base, pages);
    }
    if request & 0x8000 == 0 {
        live_vram_mut(machine)[..mode.framebuffer_bytes as usize].fill(0);
    }
    let access = if request & 0x4000 != 0 {
        ::vga::SvgaAccess::Linear
    } else {
        ::vga::SvgaAccess::Banked { bank: 0 }
    };
    dev.state = VgaState::Vbe(alloc::boxed::Box::new(::vga::SvgaState::new(
        mode.number, access, mode.svga_config(),
    )));
    dev.svga_pages = pages;
    dev.svga_vram.clear();
    machine.unmap_range(A0000 >> 12, WINDOW_PAGES);
    if request & 0x4000 == 0 {
        svga_set_bank(machine, pc, 0);
    }
}

/// VBE 4F05h window control: alias the 0xA0000 window onto `bank` of the
/// framebuffer. No copy — the window simply shares the bank's frames.
pub fn svga_set_bank<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    bank: u16,
) {
    let Some(dev) = pc.vga.emulated_mut() else { return };
    let Some(svga) = dev.state.svga_mut() else {
        return;
    };
    let granularity = SVGA_WINDOW;
    let window_bytes = SVGA_WINDOW;
    let aperture = A0000;
    let byte_offset = usize::from(bank) * granularity;
    let count = window_bytes.div_ceil(crate::PAGE_SIZE);
    if byte_offset / crate::PAGE_SIZE + count > dev.svga_pages { return; }
    let src = (SVGA_LFB_BASE + byte_offset) >> 12;
    machine.copy_page_entries(src, aperture >> 12, count);
    let _ = svga.window(Some(bank));
}

/// Leave SVGA for a standard VGA mode: detach the window alias and free the
/// framebuffer region.
pub fn svga_leave<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine) {
    let Some(dev) = pc.vga.emulated_mut() else { return };
    if dev.state.svga().is_none() {
        return;
    }
    let pages = dev.svga_pages;
    // Detach the window alias (drops its shared ref on the current bank), then
    // free the framebuffer region — frees the frames and leaves the entries
    // absent, the only sane "free" for an allocated RAM region.
    machine.map_fresh_range(A0000 >> 12, WINDOW_PAGES);
    machine.unmap_range(SVGA_LFB_BASE >> 12, pages);
    dev.state = VgaState::new();
    dev.svga_pages = 0;
    dev.svga_vram.clear();
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
    let Some(vga) = dev.state.legacy_mut() else { return };
    let planes = live_planes_mut(machine);
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
        ::vga::VramTransition::between(old_layout, new_layout).apply(planes);
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
            planes,
            vga.layout(),
            0,
            &lib::vga_fonts::FONT_8X16,
            16,
        );
    }
    install_aperture(machine, vga.cpu_aperture());
}

/// Trapped planar VRAM write: run the Graphics Controller write-mode logic for a
/// CPU store of `byte` at A0000 offset `off`, fanning it into the 4 planes
/// in the page-backed planes. Used when a linear alias can't model the access —
/// write mode 1 (Mode X latched copy), write modes 2/3, or a multi-plane EGA
/// write. Latches must have been loaded by a prior `vram_read`.
pub fn vram_write<A: arch_abi::GuestBytes>(machine: &mut A, vga: &mut LegacyVgaState, off: u32, byte: u8) {
    if let Some(base) = live_vram_ptr_if_initialized() {
        let planes = unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), PLANES_LEN) };
        vram_write_live(planes, vga, off, byte);
        return;
    }

    // Unit-test/early-construction fallback before the DOS VGA singleton has
    // installed its permanent kernel mapping.
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

/// Apply one planar write through the permanent kernel mapping. The guest
/// alias is intentionally absent while the VGA ALU is active; walking that
/// alias through `GuestBytes` here used to perform four translated reads and
/// up to four translated writes for every already-expensive #PF-emulated CPU
/// byte.
#[inline(always)]
fn vram_write_live(planes: &mut [u8], vga: &mut LegacyVgaState, off: u32, byte: u8) {
    let (off, map_mask) = vga.cpu_write_address(off as usize);
    let layout = vga.layout();

    // Ordinary Mode-X drawing is write mode 0 with an unrotated, unmasked CPU
    // byte and no set/reset. In that configuration the VGA ALU reduces exactly
    // to assigning the byte to every enabled plane; avoid fetching four old
    // values and running the general ALU for the overwhelmingly common case.
    if vga.gc[5] & 0x0B == 0
        && vga.gc[3] & 0x1F == 0
        && vga.gc[1] & 0x0F == 0
        && vga.gc[8] == 0xFF
    {
        for p in 0..4 {
            if map_mask & (1 << p) != 0 {
                planes[layout.index(p, off)] = byte;
            }
        }
        return;
    }

    let cur = core::array::from_fn(|p| planes[layout.index(p, off)]);
    let out = ::vga::planar_write(cur, vga.latches, &vga.gc, map_mask, byte);
    for p in 0..4 {
        if out[p] != cur[p] {
            planes[layout.index(p, off)] = out[p];
        }
    }
}

/// Copy bytes into guest memory, routing any overlap with the trap-backed VGA
/// aperture through the VGA write path. DOS services can legally transfer
/// file/device data straight into video memory; on a real VGA those CPU stores
/// still honour map mask/write-mode/latches, while the emulated path has the aperture
/// unmapped so raw `machine.copy_to` would fault in the kernel.
pub fn copy_to_guest<A: arch_abi::GuestBytes>(machine: &mut A, vga: &mut DosVideo, addr: usize, src: &[u8]) {
    let Some(vga) = vga.emulated_mut() else {
        machine.copy_to(addr, src);
        return;
    };
    let Some(vga) = vga.state.legacy_mut() else {
        machine.copy_to(addr, src);
        return;
    };
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
        if let Some(base) = live_vram_ptr_if_initialized() {
            let planes = unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), PLANES_LEN) };
            for (i, &byte) in src[pos..pos + n].iter().enumerate() {
                vram_write_live(planes, vga, (cur + i - window_base) as u32, byte);
            }
        } else {
            for (i, &byte) in src[pos..pos + n].iter().enumerate() {
                vram_write(machine, vga, (cur + i - window_base) as u32, byte);
            }
        }
        pos += n;
    }
}

/// Trapped planar VRAM read: load the 4 latches from the planes at A0000 offset
/// `off` and return the byte the CPU sees (read map select, or color compare).
pub fn vram_read<A: arch_abi::GuestBytes>(machine: &mut A, vga: &mut LegacyVgaState, off: u32) -> u8 {
    let (off, read_plane) = vga.cpu_read_address(off as usize);
    let layout = vga.layout();
    let cur = if let Some(base) = live_vram_ptr_if_initialized() {
        let planes = unsafe { core::slice::from_raw_parts(base.as_ptr(), PLANES_LEN) };
        core::array::from_fn(|p| planes[layout.index(p, off)])
    } else {
        core::array::from_fn(|p| {
            machine.read::<u8>(VGA_VRAM_BASE + layout.index(p, off))
        })
    };
    let mut gc = vga.gc;
    gc[4] = read_plane as u8;
    let (data, latches) = ::vga::planar_read(cur, &gc);
    vga.latches = latches;
    vga.latches_valid = true;
    data
}

/// Read a CPU-visible video byte, including latch effects on a trapped aperture.
fn read_guest_byte<A: arch_abi::GuestBytes>(machine: &mut A, device: &mut DosVideo, addr: usize) -> u8 {
    if let Some(dev) = device.emulated_mut()
        && let Some(vga) = dev.state.legacy_mut()
        && let Some(pages) = trapped_aperture(vga)
    {
        let base = usize::from(pages.start) << 12;
        let end = usize::from(pages.end) << 12;
        if (base..end).contains(&addr) {
            return vram_read(machine, vga, (addr - base) as u32);
        }
    }
    machine.read(addr)
}

/// BIOS mode-set clearing after the new aperture has been installed. EGA/VGA
/// planar modes were already cleared in on_set_mode; the other modes use their
/// CPU-visible windows, which may be direct or trapped (notably CGA mode 6).
pub fn bios_clear_framebuffer<A: arch_abi::GuestBytes>(machine: &mut A, device: &mut DosVideo, mode: u8) {
    if matches!(mode, 0x0D..=0x12) { return; }
    let (base, len) = if mode == 0x13 { (0xA0000, 320 * 200) } else { (0xB8000, 32768) };
    let mut blank = [0u8; 512];
    if !matches!(mode, 4..=6 | 0x13) {
        for cell in blank.chunks_exact_mut(2) { cell.copy_from_slice(&0x0720u16.to_le_bytes()); }
    }
    for offset in (0..len).step_by(blank.len()) {
        copy_to_guest(machine, device, base + offset, &blank[..(len - offset).min(blank.len())]);
    }
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
pub fn bios_draw_glyph<A: arch_abi::GuestBytes>(
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
            match dev.state.legacy().and_then(|state| state.classify_mode()) {
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
                    copy_to_guest(machine, device, 0xA0000 + (py * 320 + px0 + gx) as usize, &[color]);
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
                    let mut b = read_guest_byte(machine, device, off);
                    b = (b & !(0x03 << shift)) | (color << shift);
                    copy_to_guest(machine, device, off, &[b]);
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
                    let mut b = read_guest_byte(machine, device, off);
                    if bits & (0x80 >> gx) != 0 { b |= mask; } else { b &= !mask; }
                    copy_to_guest(machine, device, off, &[b]);
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
            let Some(vga) = dev.state.legacy_mut() else { return false };
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

#[cfg(test)]
mod bios_memory_tests {
    use super::*;
    use alloc::vec::Vec;
    use arch_abi::GuestBytes;

    #[test]
    fn shared_vram_owner_switch_and_fork_preserve_independent_images() {
        let mut live = alloc::vec![0; PLANES_LEN];
        let mut parent = EmulatedVga::initial_mode3();
        parent.restore_vram(&mut live);
        for (i, byte) in live.iter_mut().enumerate() { *byte = (i * 37 + i / 256) as u8; }
        let expected = live.clone();
        // A kernel re-entry/resume of the same owner must not restore stale
        // saved pixels over guest writes.
        parent.restore_vram(&mut live);
        assert_eq!(live, expected);
        parent.save_vram(&live);
        let allocation = parent.state.legacy().map(|state| state.planes.as_ptr());
        let mut child = parent.clone_for_fork();
        assert_eq!(child.state.legacy().map(|state| state.planes.len()), Some(PLANES_LEN));
        child.restore_vram(&mut live);
        assert_eq!(live, expected);
        live.fill(0xC7);
        // Repeated suspend cannot capture the next owner's screen.
        parent.save_vram(&live);
        child.save_vram(&live);
        parent.restore_vram(&mut live);
        assert_eq!(live, expected);
        assert_eq!(parent.state.legacy().map(|state| state.planes.as_ptr()), allocation);
        parent.save_vram(&live);
        child.restore_vram(&mut live);
        assert!(live.iter().all(|&b| b == 0xC7));
        // DOS return transfers the child's image, not the saved parent's.
        child.save_vram(&live);
        parent = child;
        live.fill(0);
        parent.restore_vram(&mut live);
        assert!(live.iter().all(|&b| b == 0xC7));
    }

    struct Memory {
        ram: Vec<u8>,
        planes: Vec<u8>,
        aperture: ::vga::CpuAperture,
    }

    impl Memory {
        fn offset(&self, addr: usize) -> (bool, usize) {
            if (VGA_VRAM_BASE..VGA_VRAM_BASE + PLANES_LEN).contains(&addr) {
                return (true, addr - VGA_VRAM_BASE);
            }
            match self.aperture {
                ::vga::CpuAperture::Trapped { range } => {
                    assert!(!(usize::from(range.start_page) * 4096..usize::from(range.end_page) * 4096)
                        .contains(&addr), "raw BIOS access to trapped VGA at {addr:#x}");
                }
                ::vga::CpuAperture::Direct { range, pages } => {
                    let base = usize::from(range.start_page) * 4096;
                    if (base..base + usize::from(pages) * 4096).contains(&addr) {
                        return (true, addr - base);
                    }
                }
                _ => {}
            }
            (false, addr)
        }
    }

    impl GuestBytes for Memory {
        fn read<T: Copy>(&self, addr: usize) -> T {
            let mut value = core::mem::MaybeUninit::<T>::uninit();
            unsafe {
                let bytes = core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>());
                self.copy_from(addr, bytes);
                value.assume_init()
            }
        }
        fn write<T: Copy>(&mut self, addr: usize, value: T) {
            let bytes = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(value).cast::<u8>(), core::mem::size_of::<T>()) };
            self.copy_to(addr, bytes);
        }
        fn copy_from(&self, addr: usize, dst: &mut [u8]) {
            for (i, byte) in dst.iter_mut().enumerate() {
                let (plane, off) = self.offset(addr + i);
                *byte = if plane { self.planes[off] } else { self.ram[off] };
            }
        }
        fn copy_to(&mut self, addr: usize, src: &[u8]) {
            for (i, byte) in src.iter().enumerate() {
                let (plane, off) = self.offset(addr + i);
                if plane { self.planes[off] = *byte; } else { self.ram[off] = *byte; }
            }
        }
        fn copy_cstr(&self, _: usize, _: &mut [u8]) -> usize { unimplemented!() }
        fn zero(&mut self, _: usize, _: usize) { unimplemented!() }
        fn copy_within(&mut self, _: usize, _: usize, _: usize) { unimplemented!() }
    }

    fn setup(mode: u8) -> (Memory, DosVideo) {
        let mut dev = EmulatedVga::initial_mode3();
        let regs = ::vga::bios_mode_regs(mode).unwrap();
        if let Some(state) = dev.state.legacy_mut() {
            state.seq = regs.seq;
            state.gc = regs.gc;
            state.crtc = regs.crtc;
            state.misc_output = regs.misc;
        }
        let aperture = dev.state.legacy().map_or(::vga::CpuAperture::None, |state| state.cpu_aperture());
        let memory = Memory {
            ram: alloc::vec![0xA5; 0xC0000],
            planes: alloc::vec![0xA5; PLANES_LEN],
            aperture,
        };
        (memory, DosVideo::Vga(dev))
    }

    #[test]
    fn mode_clear_handles_direct_and_trapped_apertures() {
        for mode in [0, 1, 2, 3, 4, 5, 6, 7, 0x13] {
            let (mut memory, mut device) = setup(mode);
            if mode == 6 { assert!(matches!(memory.aperture, ::vga::CpuAperture::Trapped { .. })); }
            bios_clear_framebuffer(&mut memory, &mut device, mode);
            let (base, len) = if mode == 0x13 { (0xA0000, 64000) } else { (0xB8000, 32768) };
            for off in 0..len {
                let expected = if matches!(mode, 4..=6 | 0x13) { 0 } else if off & 1 == 0 { 0x20 } else { 7 };
                assert_eq!(read_guest_byte(&mut memory, &mut device, base + off), expected, "mode {mode:#x} offset {off:#x}");
            }
            if mode == 6 {
                // Sequential mode 6 clears only plane 0, not the other maps.
                for off in 0..32768 {
                    for plane in 1..4 {
                        assert_eq!(memory.planes[::vga::VramLayout::PlaneMinor.index(plane, off)], 0xA5);
                    }
                }
            }
        }
    }

    #[test]
    fn mode6_glyph_reads_and_writes_both_cga_banks_through_vga() {
        let (mut memory, mut device) = setup(6);
        assert!(bios_draw_glyph(&mut memory, &mut device, 6, b'A', 2, 1, 1));
        for row in 0..8 {
            let py = 8 + row;
            let address = 0xB8000 + (py & 1) * 0x2000 + (py >> 1) * 80 + 2;
            assert_eq!(read_guest_byte(&mut memory, &mut device, address), lib::vga_fonts::FONT_8X8[b'A' as usize * 8 + row]);
            assert_eq!(read_guest_byte(&mut memory, &mut device, address - 1), 0xA5);
            assert_eq!(read_guest_byte(&mut memory, &mut device, address + 1), 0xA5);
        }
        assert_eq!(
            device.emulated().and_then(|dev| dev.state.legacy()).map(|state| state.latches),
            Some([0xA5; 4]),
        );
    }
}
