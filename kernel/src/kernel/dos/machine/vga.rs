//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live state behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `//lib:vga`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

use crate::Regs;
use super::*;
use crate::kernel::bios_display::{DisplayedVga, EmulatedVga};
use crate::kernel::bios_display::VbeResume;

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
        let firmware_state = native.cap().bios_save_state(machine, bios);
        let native_mode = native.mode();
        let resume_vbe = match native_mode {
            crate::kernel::platform::NativeVgaMode::Legacy => None,
            crate::kernel::platform::NativeVgaMode::VbeLinear(mode) => Some(VbeResume {
                request: mode.number | 0x4000,
                bank: None,
            }),
            crate::kernel::platform::NativeVgaMode::VbeBanked { mode, current_bank } => Some(VbeResume {
                request: mode.number,
                bank: Some(current_bank),
            }),
        };
        let svga_pages = if resume_vbe.is_some() {
            crate::kernel::drivers::vga_hw::save_dac(native.cap(), &mut model);
            capture_native_vbe(machine, bios, native.cap_mut(), native_mode, &mut model)
        } else {
            crate::kernel::drivers::vga_hw::save(native.cap(), &mut model);
            materialize_emulated_aperture(&mut model, machine);
            0
        };
        Self {
            state: model,
            firmware_state,
            svga_pages,
            resume_vbe,
            rematerialize_aperture: false,
        }
    }

    /// Ordinary focus detach: after capturing the VGA, explicitly discard the
    /// hardware-state authority and retain only physical scanout capability.
    fn detach_native<A: crate::Arch>(
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        mut native: crate::kernel::platform::NativeVga,
    ) -> (Self, crate::kernel::platform::NativeVga) {
        let vga = Self::snapshot_native(machine, bios, &mut native);
        (vga, native)
    }

    fn attach_native<A: crate::Arch>(
        mut self,
        machine: &mut A,
        mut native: crate::kernel::platform::NativeVga,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> DisplayedVga {
        // Native ownership means the complete VGA aperture is physical in the
        // incoming DOS address space, including B8000 text memory.
        machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
        self.state.a0000_trapped = false;
        if let Some(resume) = self.resume_vbe.take()
            && self.state.svga_w != 0
        {
            let exact = self.firmware_state.as_ref().is_some_and(|state| {
                match native.cap().bios_restore_state(machine, &mut *bios, state) {
                    Ok(()) => true,
                    Err(error) => {
                        crate::println!("VGA: VBE 4F04 restore failed: {:?}", error);
                        false
                    }
                }
            });
            let mode = if exact {
                native.cap().bios_mode(bios, resume.request & 0x3FFF).map(|mode| {
                    if resume.request & 0x4000 != 0 {
                        crate::kernel::platform::NativeVgaMode::VbeLinear(mode)
                    } else {
                        crate::kernel::platform::NativeVgaMode::VbeBanked {
                            mode,
                            current_bank: resume.bank.unwrap_or(0),
                        }
                    }
                }).unwrap_or_else(|| native.cap_mut().bios_set_mode_request(
                    machine, &mut *bios, resume.request))
            } else {
                native.cap_mut().bios_set_mode_request(machine, &mut *bios, resume.request)
            };
            restore_native_vbe(machine, bios, native.cap_mut(), mode, &self.state, resume);
            discard_emulated_svga(machine, &mut self);
            *native.mode_mut() = mode;
            return DisplayedVga::Native(native);
        }
        // A live emulated VGA's aperture is its VRAM. Capture the linear
        // representation before converting the complete device to hardware.
        capture_emulated_aperture(&mut self.state, machine);
        // An OSD VBE surface must be left before direct legacy restoration.
        if native.vbe_mode().is_some() {
            let mode = native.cap_mut().bios_set_mode(machine, &mut *bios, 3);
            *native.mode_mut() = mode;
        }
        crate::kernel::drivers::vga_hw::restore(native.cap(), &self.state);
        if let Some(state) = self.firmware_state.as_ref() {
            if let Err(error) = native.cap().bios_restore_state(machine, bios, state) {
                crate::println!("VGA: VBE 4F04 restore failed: {:?}", error);
            } else if crate::kernel::platform::get().host
                == crate::kernel::platform::Host::Qemu
            {
                // SeaVGABIOS/QEMU can return from 4F04 with AC PAS clear,
                // blanking an otherwise fully restored legacy screen.
                crate::kernel::drivers::vga_hw::enable_palette_output(native.cap(), &self.state);
            }
        }
        *native.mode_mut() = crate::kernel::platform::NativeVgaMode::Legacy;
        DisplayedVga::Native(native)
    }

    pub fn present<A: crate::Arch>(
        self,
        machine: &mut A,
        display: crate::kernel::display::Display,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> DisplayedVga {
        match display.into_native_capability(machine) {
            Ok(native) => self.attach_native(machine, native, bios),
            Err(display) => {
                DisplayedVga::Emulated(self, display)
            }
        }
    }
}

impl DisplayedVga {
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

    pub fn hold_surface(&mut self, display: crate::kernel::display::Display) {
        match self {
            Self::Emulated(_, output) => { *output = display; }
            Self::Native(_) => panic!("native VGA already owns physical scanout"),
        }
    }

    pub fn take_surface(&mut self) -> Option<crate::kernel::display::Display> {
        match self {
            Self::Emulated(_, output) => Some(core::mem::replace(
                output, crate::kernel::display::Display::headless())),
            Self::Native(_) => None,
        }
    }

    /// Clone this thread's complete VGA ownership for a child. The parent
    /// keeps an emulated recovery image targeting headless output while the
    /// child receives the live display state.
    pub fn fork_for_child<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> Self {
        match self {
            Self::Native(native) => {
                let parent = EmulatedVga::snapshot_native(machine, bios, native);
                core::mem::replace(self, Self::Emulated(
                    parent, crate::kernel::display::Display::headless()))
            }
            Self::Emulated(vga, _) => {
                capture_emulated_aperture(&mut vga.state, machine);
                let parent = vga.clone_for_fork();
                vga.rematerialize_aperture = true;
                core::mem::replace(self, Self::Emulated(
                    parent, crate::kernel::display::Display::headless()))
            }
        }
    }

    pub fn suspend_state<A: crate::Arch>(&mut self, machine: &mut A) {
        match self {
            Self::Emulated(vga, _) =>
                capture_emulated_aperture(&mut vga.state, machine),
            Self::Native(_) =>
                panic!("native VGA was not detached before exit"),
        }
    }

    /// Capture address-space-backed VRAM before moving this complete VGA to a
    /// different DOS thread at normal EXEC return.
    pub fn prepare_thread_transfer<A: crate::Arch>(&mut self, machine: &mut A) {
        match self {
            Self::Emulated(vga, _) => {
                capture_emulated_aperture(&mut vga.state, machine);
                vga.rematerialize_aperture = true;
            }
            Self::Native(_) => {}
        }
    }

    /// Reconcile VGA memory with the address space which just became active.
    pub fn on_address_space_active<A: crate::Arch>(&mut self, machine: &mut A) {
        match self {
            Self::Native(_) => {
                machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
            }
            Self::Emulated(vga, _) if vga.rematerialize_aperture =>
            {
                materialize_emulated_aperture(&mut vga.state, machine);
                vga.rematerialize_aperture = false;
            }
            Self::Emulated(_, _) => {}
        }
    }

    /// OSD take boundary. A native VBE framebuffer is card state, so query it
    /// while the capability is still here and materialize it into this
    /// thread's ordinary emulated-SVGA RAM before lending the card to OSD.
    pub fn into_emulated_for_osd<A: crate::Arch>(
        self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> (Self, crate::kernel::display::Display) {
        match self {
            Self::Native(native) => {
                let (vga, native) = EmulatedVga::detach_native(
                    machine, bios_workspace, native);
                let display = crate::kernel::display::Display::new_selected(
                    machine, bios_workspace, native);
                (Self::Emulated(vga, crate::kernel::display::Display::headless()), display)
            }
            Self::Emulated(vga, display) => {
                let display = display.into_selected(machine, bios_workspace);
                (Self::Emulated(vga, crate::kernel::display::Display::headless()), display)
            }
        }
    }

    /// Inverse of `into_emulated_for_osd`: restore a captured native VBE mode
    /// and its pixels before making the card authoritative again.
    pub fn raise_from_osd<A: crate::Arch>(
        self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::display::Display,
    ) -> Self {
        match (self, display.into_native_capability(machine)) {
            (Self::Emulated(dev, _), Err(display)) =>
                Self::Emulated(dev, display),
            (Self::Emulated(dev, _), Ok(native)) =>
                dev.attach_native(machine, native, bios_workspace),
            (native @ Self::Native(_), _) => native,
        }
    }

}

/// Replace the current output with a headless sink and release the foreground
/// scanout target: either a render surface or a state-free VGA capability.
pub fn release_display<A: crate::Arch>(
    vga: &mut DisplayedVga,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
) -> crate::kernel::display::DisplayHandoff {
    vga.map(|vga| match vga {
        DisplayedVga::Native(native) => {
            let (vga, native) = EmulatedVga::detach_native(machine, bios, native);
            (DisplayedVga::Emulated(vga, crate::kernel::display::Display::headless()),
             crate::kernel::display::DisplayHandoff::Vga(native))
        }
        DisplayedVga::Emulated(vga, display) =>
            (DisplayedVga::Emulated(vga, crate::kernel::display::Display::headless()),
             crate::kernel::display::DisplayHandoff::Surface(display)),
    })
}

/// Replace an emulated VGA's current output target. A bare VgaCap is upgraded
/// to NativeVga only after the complete software state is restored.
pub fn acquire_display<A: crate::Arch>(
    vga: &mut DisplayedVga,
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: crate::kernel::display::DisplayHandoff,
) {
    vga.map(|vga| match (vga, display) {
        (DisplayedVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Vga(native)) =>
            (vga.attach_native(machine, native, bios), ()),
        (DisplayedVga::Emulated(vga, _), crate::kernel::display::DisplayHandoff::Surface(display)) =>
            (vga.present(machine, display, bios), ()),
        (native @ DisplayedVga::Native(_), _) => (native, ()),
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
pub fn is_standard_text(device: &DisplayedVga) -> bool {
    match device {
        DisplayedVga::Native(native) =>
            crate::kernel::drivers::vga_hw::is_standard_text_mode(native.cap()),
        DisplayedVga::Emulated(dev, _) => {
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
    use ::vga::VgaMode;
    if state.planes.len() != PLANES_LEN {
        state.planes.resize(PLANES_LEN, 0);
    }
    machine.map_fresh_range(VGA_VRAM_BASE >> 12, PLANES_LEN >> 12);
    match state.classify_mode() {
        Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {
            write_live_planes(machine, &state.planes);
            let (base, len) = planar_window(state.gc[6]);
            machine.map_phys_range(base as usize >> 12, len as usize >> 12, 0, arch_abi::MAP_MMIO);
            state.a0000_trapped = true;
        }
        Some(VgaMode::Mode13h) => {
            ::vga::chain4_munge(&mut state.planes);
            write_live_planes(machine, &state.planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, A0000 >> 12, 16);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Text { .. }) => {
            ::vga::text_odd_even_munge(&mut state.planes);
            write_live_planes(machine, &state.planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 8);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Cga4) => {
            ::vga::cga4_munge(&mut state.planes);
            write_live_planes(machine, &state.planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 4);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Cga2) => {
            write_live_planes(machine, &state.planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 4);
            state.a0000_trapped = false;
        }
        Some(VgaMode::LinearSvga { .. }) => {
            write_live_planes(machine, &state.planes);
            machine.copy_page_entries(
                (SVGA_LFB_BASE >> 12) + usize::from(state.svga_bank) * WINDOW_PAGES,
                A0000 >> 12,
                WINDOW_PAGES,
            );
            state.a0000_trapped = false;
        }
        None => {
            write_live_planes(machine, &state.planes);
            state.a0000_trapped = false;
        }
    }
    // A live emulated VGA owns page-backed VRAM, never a shadow Vec.
    state.planes.clear();
}

/// The reverse: read the guest's aperture back into the planes.
fn capture_emulated_aperture<A: crate::Arch>(state: &mut VgaState, machine: &mut A) {
    use ::vga::VgaMode;
    state.planes = read_live_planes(machine);
    match state.classify_mode() {
        Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {}
        Some(VgaMode::Mode13h) => ::vga::chain4_unmunge(&mut state.planes),
        Some(VgaMode::Text { .. }) => ::vga::text_odd_even_unmunge(&mut state.planes),
        Some(VgaMode::Cga4) => ::vga::cga4_unmunge(&mut state.planes),
        Some(VgaMode::Cga2) => {}
        Some(VgaMode::LinearSvga { .. }) | None => {}
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


/// The emulated VGA's plane memory: 4 planes × 64 KB, byte (plane `p`, offset
/// `off`) at `[p*0x10000 + off]`. Lives per-thread on `VgaState::planes` (the
/// focus-owned model) — the same buffer `vga_hw::save` fills for a real
/// card — so the planar trap and the renderer touch it directly, no global and
/// no per-frame copy.
const PLANES_LEN: usize = 4 * 0x10000;
const A0000: usize = 0xA0000;
pub fn planar_window(gc6: u8) -> (u32, u32) {
    match (gc6 >> 2) & 3 {
        0 => (0xA0000, 0x20000),
        1 => (0xA0000, 0x10000),
        2 => (0xB0000, 0x08000),
        _ => (0xB8000, 0x08000),
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

/// React to a Sequencer register write (port 0x3C5) that may change the
/// chain-4 mode or the plane-select mask. Drives the GC[6]-selected aperture.
/// `pc.vga` already holds the post-write register values.
pub fn on_seq_write<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, _regs: &mut Regs) {
    // A real card does its own plane routing.
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    let idx = vga.seq_index & 0x1F;
    match idx {
        4 => {
            // Memory Mode bit 2 disables text odd/even addressing; bit 3
            // enables chain-4. Only (odd/even disabled, chain-4 disabled) is
            // the sequential plane aperture that needs the A0000 trap. That
            // includes Mode X/EGA drawing and temporary text-font access.
            // Entering from text must undo the B800 odd/even packing; entering
            // from mode 13h must undo chain-4. They are different layouts.
            let sequential = vga.seq[4] & 0x0C == 0x04;
            let currently_planar = vga.a0000_trapped;
            if sequential && !currently_planar {
                let source = if vga.gc[6] & 0x01 == 0 {
                    PlanarSource::TextOddEven
                } else if vga.gc[5] & 0x40 != 0 {
                    PlanarSource::Chain4
                } else {
                    PlanarSource::Canonical
                };
                arm_planar(machine, vga, source);
            } else if !sequential && currently_planar {
                if vga.seq[4] & 0x08 != 0 {
                    disarm_planar_to_chain4(machine, vga);
                } else if vga.gc[6] & 0x01 == 0 {
                    disarm_planar_to_text(machine, vga);
                }
            }
        }
        2 => {
            // Map Mask = plane select. Nothing to remap: while planar, A0000
            // stays unmapped and the map mask is honoured by the planar trap
            // (`handle_planar_fault` → `planar_write`), which writes exactly the
            // selected planes — including the multi-plane EGA fan-out the old
            // single-plane alias couldn't do.
            let _ = ();
        }
        _ => {}
    }
}

/// GC Miscellaneous register (index 6) selects which legacy address window
/// the VGA decodes. Programs are free to program it before or after switching
/// the sequencer to sequential-plane access. Keep the MMIO trap on the newly
/// selected window in either order; leaving it on the old text window loses
/// plane-2 font writes (Impulse Tracker does this ordering).
pub fn on_gc_write<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, old_gc6: u8) {
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    if !vga.a0000_trapped || (old_gc6 & 0x0C) == (vga.gc[6] & 0x0C) {
        return;
    }

    let (old_base, old_len) = planar_window(old_gc6);
    // The old aperture contains no independent bytes while trapped: the
    // canonical image is in VGA_VRAM_BASE. Restore ordinary guest RAM beneath
    // it, then place the device trap over the newly selected decode window.
    machine.map_fresh_range(old_base as usize >> 12, old_len as usize >> 12);
    let (new_base, new_len) = planar_window(vga.gc[6]);
    machine.map_phys_range(
        new_base as usize >> 12,
        new_len as usize >> 12,
        0,
        arch_abi::MAP_MMIO,
    );
}

/// Map the GC[6]-selected VGA window as MMIO (present=0 + trap marker) so every
/// guest access reaches the planar ALU. Graphics normally selects A0000, while
/// text character-generator access may select B0000 or B8000.
#[derive(Clone, Copy)]
enum PlanarSource {
    Canonical,
    Chain4,
    TextOddEven,
}

fn arm_planar<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, source: PlanarSource) {
    let mut planes = read_live_planes(machine);
    match source {
        PlanarSource::Canonical => {}
        PlanarSource::Chain4 => ::vga::chain4_unmunge(&mut planes),
        PlanarSource::TextOddEven => ::vga::text_odd_even_unmunge(&mut planes),
    }
    write_live_planes(machine, &planes);
    let (base, len) = planar_window(vga.gc[6]);
    machine.map_phys_range(base as usize >> 12, len as usize >> 12, 0, arch_abi::MAP_MMIO);
    vga.a0000_trapped = true;
}

/// Leave planar access for chain-4: munge the one VRAM store and alias its
/// first 64K as the linear A0000 aperture.
fn disarm_planar_to_chain4<A: crate::Arch>(machine: &mut A, vga: &mut VgaState) {
    let mut planes = read_live_planes(machine);
    ::vga::chain4_munge(&mut planes);
    write_live_planes(machine, &planes);
    machine.copy_page_entries(VGA_VRAM_BASE >> 12, A0000 >> 12, 16);
    vga.a0000_trapped = false;
}

/// Return from sequential plane/font access to the text odd/even B8000 view.
fn disarm_planar_to_text<A: crate::Arch>(machine: &mut A, vga: &mut VgaState) {
    let mut planes = read_live_planes(machine);
    ::vga::text_odd_even_munge(&mut planes);
    write_live_planes(machine, &planes);
    machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 8);
    vga.a0000_trapped = false;
}

/// BIOS character-generator services operate on plane 2 regardless of the
/// CPU-visible text odd/even layout. Normalize the live page-backed image,
/// update the requested 8-KB map, then restore its current layout.
pub fn bios_load_font<A: crate::Arch>(
    machine: &mut A,
    device: &mut DisplayedVga,
    map: usize,
    first: usize,
    font: &[u8],
    glyph_h: usize,
) {
    let dev = match device {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    let mode = vga.classify_mode();
    let mut planes = read_live_planes(machine);
    match mode {
        Some(::vga::VgaMode::Text { .. }) => ::vga::text_odd_even_unmunge(&mut planes),
        Some(::vga::VgaMode::Mode13h) => ::vga::chain4_unmunge(&mut planes),
        Some(::vga::VgaMode::Cga4) => ::vga::cga4_unmunge(&mut planes),
        _ => {}
    }
    ::vga::load_font_glyphs(&mut planes, map, first, font, glyph_h);
    match mode {
        Some(::vga::VgaMode::Text { .. }) => ::vga::text_odd_even_munge(&mut planes),
        Some(::vga::VgaMode::Mode13h) => ::vga::chain4_munge(&mut planes),
        Some(::vga::VgaMode::Cga4) => ::vga::cga4_munge(&mut planes),
        _ => {}
    }
    write_live_planes(machine, &planes);
}

/// Apply the text geometry selected by INT 10h AX=111xh. The 14-line ROM font
/// selects the VGA's 350-line text timing; 8- and 16-line fonts use 400 lines.
pub fn bios_set_text_height(device: &mut DisplayedVga, glyph_h: u8) {
    let dev = match device {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let visible = if glyph_h == 14 { 350u16 } else { 400u16 };
    let end = visible - 1;
    dev.state.crtc[9] = (dev.state.crtc[9] & 0xE0) | (glyph_h - 1);
    dev.state.crtc[0x12] = end as u8;
    dev.state.crtc[7] = (dev.state.crtc[7] & !0x42)
        | (((end >> 8) as u8 & 1) << 1)
        | (((end >> 9) as u8 & 1) << 6);
}

pub fn bios_set_font_map_select(device: &mut DisplayedVga, select: u8) {
    if let DisplayedVga::Emulated(dev, _) = device {
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
pub(crate) const SVGA_LFB_MAX_BYTES: usize = 8 * 1024 * 1024;
const SVGA_WINDOW: usize = 0x10000; // 64 KB VBE bank granule
const WINDOW_PAGES: usize = SVGA_WINDOW >> 12;

fn svga_shadow_pages(pitch: u16, height: u16) -> usize {
    (usize::from(pitch) * usize::from(height)).div_ceil(crate::PAGE_SIZE)
}

fn map_linear_vbe<A: crate::Arch>(
    machine: &mut A,
    mode: crate::kernel::platform::VbeMode,
) -> (usize, usize) {
    let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
    let bytes = usize::from(mode.pitch) * usize::from(mode.height);
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
    native_mode: crate::kernel::platform::NativeVgaMode,
    state: &mut VgaState,
) -> usize {
    let (mode, current_bank) = match native_mode {
        crate::kernel::platform::NativeVgaMode::Legacy => return 0,
        crate::kernel::platform::NativeVgaMode::VbeLinear(mode) => (mode, None),
        crate::kernel::platform::NativeVgaMode::VbeBanked { mode, current_bank } =>
            (mode, Some(current_bank)),
    };
    let bytes = usize::from(mode.pitch) * usize::from(mode.height);
    let pages = svga_shadow_pages(mode.pitch, mode.height);
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
    state.svga_pitch = mode.pitch;
    state.svga_bank = current_bank.unwrap_or(0);
    machine.copy_page_entries(
        (SVGA_LFB_BASE >> 12) + usize::from(state.svga_bank) * WINDOW_PAGES,
        A0000 >> 12,
        WINDOW_PAGES,
    );
    state.a0000_trapped = false;
    crate::println!("VBE: detached guest mode {:#x} {}x{}x{} into shadow",
        mode.number, mode.width, mode.height, state.svga_bpp);
    pages
}

fn restore_native_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::VgaCap,
    native_mode: crate::kernel::platform::NativeVgaMode,
    state: &VgaState,
    resume: VbeResume,
) {
    let (mode, banked) = match native_mode {
        crate::kernel::platform::NativeVgaMode::Legacy => return,
        crate::kernel::platform::NativeVgaMode::VbeLinear(mode) => (mode, false),
        crate::kernel::platform::NativeVgaMode::VbeBanked { mode, .. } => (mode, true),
    };
    let bytes = usize::from(mode.pitch) * usize::from(mode.height);
    let mut pixels = alloc::vec![0; bytes];
    machine.copy_from(SVGA_LFB_BASE, &mut pixels);
    if !banked && mode.physical_base != 0 {
        let (address, pages) = map_linear_vbe(machine, mode);
        machine.copy_to(address, &pixels);
        machine.unmap_range(arch_abi::FB_WINDOW_BASE / crate::PAGE_SIZE, pages);
    } else if banked {
        copy_banked_to_card(
            machine, bios, display, mode, resume.bank.unwrap_or(0), &pixels,
        );
    }
    crate::kernel::drivers::vga_hw::restore_dac(display, state);
    crate::println!("VBE: restored guest mode {:#x} from shadow", mode.number);
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

/// Whole 64 KB banks a `w`×`h`×`bpp` framebuffer needs.
fn svga_banks(w: u16, h: u16, bpp: u8) -> usize {
    let bytes = w as usize * h as usize * (bpp as usize).div_ceil(8);
    bytes.div_ceil(SVGA_WINDOW)
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
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return false,
    };
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

/// Enter a banked SVGA mode (INT 10h AX=4F02h): back the framebuffer with fresh
/// user RAM and alias the 0xA0000 window onto bank 0.
pub fn svga_set_mode<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, w: u16, h: u16, bpp: u8) {
    // The synthetic framebuffer is the emulated model's; a real card runs its
    // own VBE through the ROM.
    if matches!(&pc.vga,
        DisplayedVga::Emulated(dev, _)
            if dev.state.svga_w != 0)
    {
        svga_leave(machine, pc);
    }
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    let pages = svga_banks(w, h, bpp) * WINDOW_PAGES;
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);
    machine.copy_page_entries(SVGA_LFB_BASE >> 12, A0000 >> 12, WINDOW_PAGES);
    vga.svga_w = w;
    vga.svga_h = h;
    vga.svga_bpp = bpp;
    vga.svga_pitch = w * (bpp as u16).div_ceil(8);
    vga.svga_bank = 0;
    dev.svga_pages = pages;
    // A VBE set-mode bypasses on_set_mode, so clear any stale planar marker.
    vga.a0000_trapped = false;
}

/// VBE 4F05h window control: alias the 0xA0000 window onto `bank` of the
/// framebuffer. No copy — the window simply shares the bank's frames.
pub fn svga_set_bank<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, bank: u16) {
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    if vga.svga_w == 0 {
        return;
    }
    let src = (SVGA_LFB_BASE >> 12) + bank as usize * WINDOW_PAGES;
    machine.copy_page_entries(src, A0000 >> 12, WINDOW_PAGES);
    vga.svga_bank = bank;
}

/// Leave SVGA for a standard VGA mode: detach the window alias and free the
/// framebuffer region.
pub fn svga_leave<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine) {
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    if vga.svga_w == 0 {
        return;
    }
    let pages = dev.svga_pages;
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
    vga.a0000_trapped = false;
}

/// React to a BIOS INT 10h AH=00 video mode set. The EGA/VGA 16-colour planar
/// family (0x0D–0x12, e.g. Commander Keen) draws through the 4 planes via the
/// map mask + write modes exactly like Mode X, but a game sets it via the BIOS
/// and never toggles the Sequencer chain-4 bit — so `on_seq_write` never fires
/// and the planar trap would stay disarmed, leaving the plane window empty
/// (a black screen). Arm it here on entry to a planar mode, and disarm on a
/// return to text/linear. `clear` (AL bit 7 clear) zeroes the planes.
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
    let dev = match &mut pc.vga {
        DisplayedVga::Emulated(dev, _) => dev,
        DisplayedVga::Native(_) => return,
    };
    let vga = &mut dev.state;
    let old_mode = vga.classify_mode();
    let mut planes = read_live_planes(machine);
    match old_mode {
        Some(::vga::VgaMode::Mode13h) => ::vga::chain4_unmunge(&mut planes),
        Some(::vga::VgaMode::Text { .. }) => ::vga::text_odd_even_unmunge(&mut planes),
        Some(::vga::VgaMode::Cga4) => ::vga::cga4_unmunge(&mut planes),
        _ => {}
    }
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
        ::vga::load_font_map(&mut planes, 0, &lib::vga_fonts::FONT_8X16, 16);
    }
    match vga.classify_mode() {
        Some(::vga::VgaMode::Planar16 { .. } | ::vga::VgaMode::ModeX { .. }) => {
            write_live_planes(machine, &planes);
            let (base, len) = planar_window(vga.gc[6]);
            machine.map_phys_range(base as usize >> 12, len as usize >> 12, 0, arch_abi::MAP_MMIO);
            vga.a0000_trapped = true;
        }
        Some(::vga::VgaMode::Mode13h) => {
            ::vga::chain4_munge(&mut planes);
            write_live_planes(machine, &planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, A0000 >> 12, 16);
            vga.a0000_trapped = false;
        }
        Some(::vga::VgaMode::Text { .. }) => {
            ::vga::text_odd_even_munge(&mut planes);
            write_live_planes(machine, &planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 8);
            vga.a0000_trapped = false;
        }
        Some(::vga::VgaMode::Cga4) => {
            ::vga::cga4_munge(&mut planes);
            write_live_planes(machine, &planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 4);
            vga.a0000_trapped = false;
        }
        Some(::vga::VgaMode::Cga2) => {
            write_live_planes(machine, &planes);
            machine.copy_page_entries(VGA_VRAM_BASE >> 12, 0xB8000 >> 12, 4);
            vga.a0000_trapped = false;
        }
        _ => {
            write_live_planes(machine, &planes);
            vga.a0000_trapped = false;
        }
    }
}

/// Trapped planar VRAM write: run the Graphics Controller write-mode logic for a
/// CPU store of `byte` at A0000 offset `off`, fanning it into the 4 planes
/// in the page-backed planes. Used when a linear alias can't model the access —
/// write mode 1 (Mode X latched copy), write modes 2/3, or a multi-plane EGA
/// write. Latches must have been loaded by a prior `vram_read`.
pub fn vram_write<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, off: u32, byte: u8) {
    let off = (off & 0xFFFF) as usize;
    let cur = core::array::from_fn(|p| machine.read::<u8>(VGA_VRAM_BASE + p * 0x10000 + off));
    let out = ::vga::planar_write(cur, vga.latches, &vga.gc, vga.seq[2] & 0x0F, byte);
    for p in 0..4 {
        if out[p] != cur[p] {
            machine.write::<u8>(VGA_VRAM_BASE + p * 0x10000 + off, out[p]);
        }
    }
}

/// Copy bytes into guest memory, routing any overlap with a trap-backed planar
/// A0000 window through the VGA write path. DOS services can legally transfer
/// file/device data straight into video memory; on a real VGA those CPU stores
/// still honour map mask/write-mode/latches, while the emulated path has A0000
/// unmapped so raw `machine.copy_to` would fault in the kernel.
pub fn copy_to_guest<A: crate::Arch>(machine: &mut A, vga: &mut DisplayedVga, addr: usize, src: &[u8]) {
    let vga = match vga {
        DisplayedVga::Emulated(vga, _) => vga,
        DisplayedVga::Native(_) => {
            machine.copy_to(addr, src);
            return;
        }
    };
    let vga = &mut vga.state;
    let (window_base, window_len) = planar_window(vga.gc[6]);
    let window_base = window_base as usize;
    let window_end = window_base + window_len as usize;
    if vga.a0000_trapped {
        // The register file, not the BDA mode byte, is the VGA hardware
        // truth. Tweaked-mode programs (Impulse Tracker among them) unchain
        // the sequencer directly without updating 40:49. This is the same
        // chain-4 test that arms the aperture and handles its page faults.
        assert_eq!(vga.seq[4] & 0x08, 0,
            "planar aperture active while VGA chain-4 is enabled");
    }
    if src.is_empty()
        || !vga.a0000_trapped
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
    let off = (off & 0xFFFF) as usize;
    let cur = core::array::from_fn(|p| machine.read::<u8>(VGA_VRAM_BASE + p * 0x10000 + off));
    let (data, latches) = ::vga::planar_read(cur, &vga.gc);
    vga.latches = latches;
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
    device: &mut DisplayedVga,
    bios_mode: u8,
    ch: u8,
    col: u32,
    row: u32,
    fg: u8,
) -> bool {
    let mode = match device {
        DisplayedVga::Native(_) => bios_mode,
        DisplayedVga::Emulated(dev, _) =>
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
            let dev = match device {
                DisplayedVga::Emulated(dev, _) => dev,
                DisplayedVga::Native(_) => return false,
            };
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
