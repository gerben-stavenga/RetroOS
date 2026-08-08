//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live model behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `//lib:vga`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

use crate::Regs;
use super::*;

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

/// Temporary kernel VA used only while copying a native VBE framebuffer into
/// or out of an emulated VGA shadow. It is not an OSD framebuffer.
const NATIVE_VBE_COPY_BASE: usize = 0xFC00_0000;

/// The one emulated VGA owned by a DOS thread: its register/VRAM model and,
/// only while visible, the display on which that model is presented.
pub struct EmulatedVga {
    pub model: alloc::boxed::Box<VgaState>,
    pub display: Option<crate::kernel::platform::Display>,
    /// Native VBE state captured only while the kernel OSD holds the adapter.
    /// This is handoff metadata, not part of the emulated VGA register model.
    pub detached_vbe: Option<DetachedVbe>,
}

#[derive(Clone, Copy)]
pub struct DetachedVbe {
    pub mode: crate::kernel::platform::VbeMode,
    pub bank: Option<crate::kernel::platform::VbeBank>,
}

impl EmulatedVga {
    pub fn present<A: crate::Arch>(
        mut self,
        machine: &mut A,
        display: crate::kernel::platform::Display,
    ) -> DosVga {
        match display.into_native_vga() {
            Ok(native) => {
                // A freshly created DOS VGA has no suspended image yet. Its
                // first attachment adopts the card exactly as the preceding
                // visible owner left it (normally BIOS text mode plus the
                // boot console); manufacturing a zeroed four-plane snapshot
                // here and restoring it blanks the native display. Once this
                // VGA has been suspended, `planes` is populated and later
                // attachments perform the ordinary exact repaint.
                if !self.model.planes.is_empty() {
                    capture_emulated_aperture(&mut self.model, machine);
                }
                machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
                self.model.a0000_trapped = false;
                crate::kernel::drivers::vga_hw::restore(&self.model);
                // Once materialized, the card is the state. Do not retain a
                // second authoritative register/VRAM image in the thread.
                DosVga::Native(native)
            }
            Err(display) => {
                self.display = Some(display);
                DosVga::Emulated(self)
            }
        }
    }
}

/// A thread's VGA device. The variant, rather than machine capability, decides
/// whether guest accesses reach hardware or the emulated register file.
pub enum DosVga {
    /// A real VGA-compatible adapter, held, in this mode. The hardware IS the
    /// state — no model is kept, because a second authoritative register and
    /// VRAM image is exactly the thing that goes stale.
    Native(crate::kernel::platform::NativeVga),
    /// No such adapter here: a VGA is presented instead. The model is the VGA.
    Emulated(EmulatedVga),
}

impl Default for DosVga {
    fn default() -> Self {
        Self::new()
    }
}

impl DosVga {
    pub fn new() -> Self {
        Self::Emulated(EmulatedVga {
            model: VgaState::new_boxed(),
            display: None,
            detached_vbe: None,
        })
    }

    /// Consume a native attachment, snapshot it, and return the emulated
    /// device plus the released physical-card authority.
    pub fn into_emulated<A: crate::Arch>(
        self,
        machine: &mut A,
    ) -> (Self, crate::kernel::platform::Display) {
        match self {
            Self::Native(native) => {
                let mut state = VgaState::new_boxed();
                crate::kernel::drivers::vga_hw::save(&mut state);
                materialize_emulated_aperture(&mut state, machine);
                (
                    Self::Emulated(EmulatedVga {
                        model: state,
                        display: None,
                        detached_vbe: None,
                    }),
                    crate::kernel::platform::Display::new_vga(native),
                )
            }
            Self::Emulated(mut vga) => {
                let display = vga.display.take().expect("hidden VGA has no display");
                (Self::Emulated(vga), display)
            }
        }
    }

    /// OSD take boundary. A native VBE framebuffer is card state, so query it
    /// while the capability is still here and materialize it into this
    /// thread's ordinary emulated-SVGA RAM before lending the card to OSD.
    pub fn into_emulated_for_osd<A: crate::Arch>(
        self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    ) -> (Self, crate::kernel::platform::Display) {
        match self {
            Self::Native(mut native) => {
                let detached_vbe = match &native {
                    crate::kernel::platform::NativeVga::Legacy => None,
                    crate::kernel::platform::NativeVga::Vbe { mode, bank } => Some((*mode, *bank)),
                };
                let mut state = VgaState::new_boxed();
                crate::kernel::drivers::vga_hw::save(&mut state);
                let detached_vbe = if let Some((mode, bank)) = detached_vbe {
                    Some(capture_bios_vbe(
                        machine, bios_workspace, &mut native, &mut state, mode, bank,
                    ))
                } else {
                    materialize_emulated_aperture(&mut state, machine);
                    None
                };
                (
                    Self::Emulated(EmulatedVga { model: state, display: None, detached_vbe }),
                    crate::kernel::platform::Display::new_vga(native),
                )
            }
            other => other.into_emulated(machine),
        }
    }

    /// Consume a detached emulated device and make it the visible owner.
    pub fn present<A: crate::Arch>(
        self,
        machine: &mut A,
        display: crate::kernel::platform::Display,
    ) -> Self {
        match self {
            Self::Emulated(vga) => vga.present(machine, display),
            Self::Native(_) => panic!("VGA already owns native hardware"),
        }
    }

    /// Inverse of `into_emulated_for_osd`: restore a captured native VBE mode
    /// and its pixels before making the card authoritative again.
    pub fn raise_from_osd<A: crate::Arch>(
        self,
        machine: &mut A,
        bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
        display: crate::kernel::platform::Display,
    ) -> Self {
        let native = display.into_native_vga();
        match (self, native) {
            (Self::Emulated(mut dev), Ok(mut native)) if dev.detached_vbe.is_some() => {
                let detached = dev.detached_vbe.take().unwrap();
                let request = detached.mode.number | if detached.bank.is_none() { 0x4000 } else { 0 };
                if bios_workspace.bios_set_mode_request(machine, &mut native, request).is_ok() {
                    restore_bios_vbe(machine, bios_workspace, &mut native, &dev.model, detached);
                    crate::kernel::drivers::vga_hw::restore_dac(&dev.model);
                } else {
                    crate::println!("VBE: failed to restore guest mode {:#x}", detached.mode.number);
                }
                discard_emulated_svga(machine, &mut dev.model);
                Self::Native(native)
            }
            (vga, Err(display)) => vga.present(machine, display),
            (vga, Ok(native)) => vga.present(machine, crate::kernel::platform::Display::new_vga(native)),
        }
    }

    /// Seed this device from what the card is currently showing — the fork
    /// path, where a child inherits the parent's screen. A native device
    /// already IS the card and passes through untouched.
    pub fn snapshot_hardware<A: crate::Arch>(self, machine: &mut A) -> Self {
        match self {
            native @ Self::Native(_) => native,
            Self::Emulated(mut dev) => {
                crate::kernel::drivers::vga_hw::save(&mut dev.model);
                materialize_emulated_aperture(&mut dev.model, machine);
                Self::Emulated(dev)
            }
        }
    }

    pub fn take_saved_state(&mut self) -> Option<alloc::boxed::Box<VgaState>> {
        match self {
            Self::Emulated(vga) if !vga.model.planes.is_empty() =>
                Some(core::mem::replace(&mut vga.model, VgaState::new_boxed())),
            Self::Emulated(_) | Self::Native(_) => None,
        }
    }

    /// Adopt a captured screen. A native owner materializes it immediately
    /// and consumes the shadow; an emulated owner keeps it for its sink.
    pub fn install_saved_state(&mut self, state: alloc::boxed::Box<VgaState>) {
        match self {
            Self::Native(_) => crate::kernel::drivers::vga_hw::restore(&state),
            Self::Emulated(vga) => vga.model = state,
        }
    }

}

// ============================================================================
// VGA register state (AcState + VgaState)
// ============================================================================

// The register file, its plane memory and the port model live in
// `//lib:vga` — a VGA is not DOS policy, and the Linux console, the display
// handover and the real-card driver all hold one too. What stays here is the
// part that needs a guest address space, which a passive card cannot have.
pub use ::vga::VgaState;

/// Present the emulated planes to the guest at A0000/B8000 — map the window
/// and fill it from the model, or mark it trapped when the mode's writes must
/// go through the planar ALU. Needs an address space, so it is not the card's.
fn materialize_emulated_aperture<A: crate::Arch>(state: &mut VgaState, machine: &mut A) {
    use ::vga::VgaMode;
    match state.classify_mode() {
        Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {
            machine.map_phys_range(A0000 >> 12, 16, 0, arch_abi::MAP_MMIO);
            state.a0000_trapped = true;
        }
        Some(VgaMode::Mode13h) => {
            machine.map_fresh_range(A0000 >> 12, 16);
            let mut chained = alloc::vec![0u8; 0x10000];
            ::vga::chain4_merge(&state.planes, &mut chained);
            machine.copy_to(A0000, &chained);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Text80x25) => {
            machine.map_fresh_range(0xB8000 >> 12, 8);
            let mut text = alloc::vec![0u8; 0x8000];
            ::vga::text_odd_even_merge(&state.planes, &mut text);
            machine.copy_to(0xB8000, &text);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Cga4) => {
            machine.map_fresh_range(0xB8000 >> 12, 8);
            let mut cga = alloc::vec![0u8; 0x4000];
            for i in 0..0x2000 {
                cga[i * 2] = state.planes.get(i).copied().unwrap_or(0);
                cga[i * 2 + 1] =
                    state.planes.get(0x10000 + i).copied().unwrap_or(0);
            }
            machine.copy_to(0xB8000, &cga);
            state.a0000_trapped = false;
        }
        Some(VgaMode::Cga2) => {
            machine.map_fresh_range(0xB8000 >> 12, 8);
            let n = 0x4000.min(state.planes.len());
            machine.copy_to(0xB8000, &state.planes[..n]);
            state.a0000_trapped = false;
        }
        Some(VgaMode::LinearSvga { .. }) | None => {
            state.a0000_trapped = false;
        }
    }
}

/// The reverse: read the guest's aperture back into the planes.
fn capture_emulated_aperture<A: crate::Arch>(state: &mut VgaState, machine: &mut A) {
    use ::vga::VgaMode;
    if state.planes.len() != PLANES_LEN {
        state.planes.resize(PLANES_LEN, 0);
    }
    match state.classify_mode() {
        Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {}
        Some(VgaMode::Mode13h) => {
            let mut chained = alloc::vec![0u8; 0x10000];
            machine.copy_from(A0000, &mut chained);
            ::vga::chain4_split(&chained, &mut state.planes);
        }
        Some(VgaMode::Text80x25) => {
            let mut text = alloc::vec![0u8; 0x8000];
            machine.copy_from(0xB8000, &mut text);
            ::vga::text_odd_even_split(&text, &mut state.planes);
        }
        Some(VgaMode::Cga4) => {
            let mut cga = alloc::vec![0u8; 0x4000];
            machine.copy_from(0xB8000, &mut cga);
            for i in 0..0x2000 {
                state.planes[i] = cga[i * 2];
                state.planes[0x10000 + i] = cga[i * 2 + 1];
            }
        }
        Some(VgaMode::Cga2) => {
            machine.copy_from(0xB8000, &mut state.planes[..0x4000]);
        }
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

/// React to a Sequencer register write (port 0x3C5) that may change the
/// chain-4 mode or the plane-select mask. Drives the A0000 paging alias.
/// `pc.vga` already holds the post-write register values.
pub fn on_seq_write<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs) {
    // A real card does its own plane routing.
    let DosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.model;
    let idx = vga.seq_index & 0x1F;
    match idx {
        4 => {
            // Memory Mode bit 3 = chain-4. Set ⇒ chained (mode 13h linear);
            // clear ⇒ unchained (Mode X planes). The chain→unchain hop seeds the
            // planes from the current chained A0000 image (a 13h frame the game
            // unchains into Mode X mid-stream); the reverse merges them back.
            let unchained = vga.seq[4] & 0x08 == 0;
            let currently_planar = vga.a0000_trapped;
            if unchained && !currently_planar {
                let mut chained = alloc::vec![0u8; 0x10000];
                machine.copy_from(A0000, &mut chained);
                arm_planar(machine, vga, Some(&chained));
            } else if !unchained && currently_planar {
                disarm_planar(machine, vga, regs, true);
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

/// Map A0000 as MMIO (present=0 + trap marker) so every guest store/load into
/// A0000 faults into `handle_planar_fault` — the only way one CPU store can fan
/// into 4 planes and honour the latches, write modes, and map mask. The planes
/// live on `vga.planes` (the per-thread VRAM). `seed`: deinterleave an existing
/// chained A0000 image into the planes (the Mode-X chain→unchain hop), or `None`
/// to zero them (a fresh BIOS planar mode-set).
fn arm_planar<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, seed: Option<&[u8]>) {
    if vga.planes.len() != PLANES_LEN {
        vga.planes = alloc::vec![0u8; PLANES_LEN];
    }
    match seed {
        Some(chained) => ::vga::chain4_split(chained, &mut vga.planes),
        None => vga.planes.fill(0),
    }
    machine.map_phys_range(A0000 >> 12, 16, 0, arch_abi::MAP_MMIO);
    vga.a0000_trapped = true;
}

/// Tear down the planar trap: map A0000 back to plain RAM. `merge`: interleave
/// the planes back into a linear A0000 image first (the Mode-X unchain→chain
/// hop, which expects the 13h view preserved); skip it when simply leaving
/// graphics for text (the next mode-set clears the screen anyway).
fn disarm_planar<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, _regs: &mut Regs, merge: bool) {
    machine.map_fresh_range(A0000 >> 12, 16);
    if merge {
        let mut chained = alloc::vec![0u8; 0x10000];
        ::vga::chain4_merge(&vga.planes, &mut chained);
        machine.copy_to(A0000, &chained);
    }
    vga.a0000_trapped = false;
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
const SVGA_WINDOW: usize = 0x10000; // 64 KB VBE bank granule
const WINDOW_PAGES: usize = SVGA_WINDOW >> 12;

fn svga_shadow_pages(pitch: u16, height: u16) -> usize {
    (usize::from(pitch) * usize::from(height)).div_ceil(crate::PAGE_SIZE)
}

fn capture_bios_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::NativeVga,
    state: &mut VgaState,
    mode: crate::kernel::platform::VbeMode,
    bank: Option<crate::kernel::platform::VbeBank>,
) -> DetachedVbe {
    let bytes = usize::from(mode.pitch) * usize::from(mode.height);
    let pages = svga_shadow_pages(mode.pitch, mode.height);
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);

    let mut pixels = alloc::vec![0; bytes];
    if bank.is_none() && mode.physical_base != 0 {
        let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
        let physical_pages = (offset + bytes).div_ceil(crate::PAGE_SIZE);
        machine.map_phys_range(
            NATIVE_VBE_COPY_BASE / crate::PAGE_SIZE,
            physical_pages,
            u64::from(mode.physical_base) / crate::PAGE_SIZE as u64,
            arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
        );
        machine.copy_from(NATIVE_VBE_COPY_BASE + offset, &mut pixels);
        machine.unmap_range(NATIVE_VBE_COPY_BASE / crate::PAGE_SIZE, physical_pages);
    } else if let Some(window) = bank {
        copy_banked_from_card(machine, bios, display, window, &mut pixels);
    }
    machine.copy_to(SVGA_LFB_BASE, &pixels);

    state.svga_w = mode.width;
    state.svga_h = mode.height;
    state.svga_bpp = mode.bits_per_pixel;
    state.svga_pitch = mode.pitch;
    state.svga_bank = 0;
    state.a0000_trapped = false;
    crate::println!("VBE: detached guest mode {:#x} {}x{}x{} into shadow",
        mode.number, mode.width, mode.height, state.svga_bpp);
    DetachedVbe { mode, bank }
}

fn restore_bios_vbe<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::NativeVga,
    state: &VgaState,
    detached: DetachedVbe,
) {
    let mode = detached.mode;
    let bytes = usize::from(mode.pitch) * usize::from(mode.height);
    let mut pixels = alloc::vec![0; bytes];
    machine.copy_from(SVGA_LFB_BASE, &mut pixels);
    if detached.bank.is_none() && mode.physical_base != 0 {
        let offset = mode.physical_base as usize & (crate::PAGE_SIZE - 1);
        let pages = (offset + bytes).div_ceil(crate::PAGE_SIZE);
        machine.map_phys_range(
            NATIVE_VBE_COPY_BASE / crate::PAGE_SIZE,
            pages,
            u64::from(mode.physical_base) / crate::PAGE_SIZE as u64,
            arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
        );
        machine.copy_to(NATIVE_VBE_COPY_BASE + offset, &pixels);
        machine.unmap_range(NATIVE_VBE_COPY_BASE / crate::PAGE_SIZE, pages);
    } else if let Some(window) = detached.bank {
        copy_banked_to_card(machine, bios, display, window, &pixels);
    }
    crate::println!("VBE: restored guest mode {:#x} from shadow", mode.number);
    let _ = state;
}

fn copy_banked_from_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::NativeVga,
    window: crate::kernel::platform::VbeBank,
    pixels: &mut [u8],
) {
    let granularity = usize::from(window.granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(window.window_size_kb).max(1) * 1024;
    let address = usize::from(window.window_segment) << 4;
    for offset in (0..pixels.len()).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if bios.bios_set_bank(machine, display, bank).is_err() { break; }
        let count = window_bytes.min(pixels.len() - offset);
        machine.copy_from(address, &mut pixels[offset..offset + count]);
    }
    let _ = bios.bios_set_bank(machine, display, window.current);
}

fn copy_banked_to_card<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::platform::NativeVga,
    window: crate::kernel::platform::VbeBank,
    pixels: &[u8],
) {
    let granularity = usize::from(window.granularity_kb).max(1) * 1024;
    let window_bytes = usize::from(window.window_size_kb).max(1) * 1024;
    let address = usize::from(window.window_segment) << 4;
    for offset in (0..pixels.len()).step_by(window_bytes) {
        let bank = (offset / granularity) as u16;
        if bios.bios_set_bank(machine, display, bank).is_err() { break; }
        let count = window_bytes.min(pixels.len() - offset);
        machine.copy_to(address, &pixels[offset..offset + count]);
    }
    let _ = bios.bios_set_bank(machine, display, window.current);
}

fn discard_emulated_svga<A: crate::Arch>(machine: &mut A, state: &mut VgaState) {
    machine.unmap_range(
        SVGA_LFB_BASE >> 12,
        svga_shadow_pages(state.svga_pitch, state.svga_h),
    );
    state.svga_w = 0;
    state.svga_h = 0;
    state.svga_bpp = 0;
    state.svga_pitch = 0;
    state.svga_bank = 0;
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

/// Enter a banked SVGA mode (INT 10h AX=4F02h): back the framebuffer with fresh
/// user RAM and alias the 0xA0000 window onto bank 0.
pub fn svga_set_mode<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, w: u16, h: u16, bpp: u8) {
    // The synthetic framebuffer is the emulated model's; a real card runs its
    // own VBE through the ROM.
    let DosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.model;
    let pages = svga_banks(w, h, bpp) * WINDOW_PAGES;
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);
    machine.copy_page_entries(SVGA_LFB_BASE >> 12, A0000 >> 12, WINDOW_PAGES);
    vga.svga_w = w;
    vga.svga_h = h;
    vga.svga_bpp = bpp;
    vga.svga_pitch = w * (bpp as u16).div_ceil(8);
    vga.svga_bank = 0;
    // A VBE set-mode bypasses on_set_mode, so clear any stale planar marker.
    vga.a0000_trapped = false;
    dev.detached_vbe = None;
}

/// VBE 4F05h window control: alias the 0xA0000 window onto `bank` of the
/// framebuffer. No copy — the window simply shares the bank's frames.
pub fn svga_set_bank<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, bank: u16) {
    let DosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.model;
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
    let DosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.model;
    if vga.svga_w == 0 {
        return;
    }
    let pages = svga_banks(vga.svga_w, vga.svga_h, vga.svga_bpp) * WINDOW_PAGES;
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
    vga.a0000_trapped = false;
    dev.detached_vbe = None;
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
    regs: &mut Regs,
    mode: u8,
    clear: bool,
) {
    // A standard mode-set leaves any active VESA SVGA mode.
    svga_leave(machine, pc);
    // A real card draws its own planes from its own register file.
    let DosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.model;
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
    let currently = vga.a0000_trapped;
    if planar && !currently {
        arm_planar(machine, vga, None); // fresh mode-set ⇒ zeroed planes
    } else if planar && currently && clear {
        // Re-set the same planar mode: keep the trap, just blank the planes.
        vga.planes.fill(0);
    } else if !planar && currently {
        disarm_planar(machine, vga, regs, false); // leaving planar ⇒ A0000 back to RAM
    }
}

/// Trapped planar VRAM write: run the Graphics Controller write-mode logic for a
/// CPU store of `byte` at A0000 offset `off`, fanning it into the 4 planes
/// (`vga.planes`). Used when the single-plane alias can't model the access —
/// write mode 1 (Mode X latched copy), write modes 2/3, or a multi-plane EGA
/// write. Latches must have been loaded by a prior `vram_read`.
pub fn vram_write(vga: &mut VgaState, off: u32, byte: u8) {
    let off = (off & 0xFFFF) as usize;
    let pl = &vga.planes;
    let cur = [pl[off], pl[0x10000 + off], pl[0x20000 + off], pl[0x30000 + off]];
    let out = ::vga::planar_write(cur, vga.latches, &vga.gc, vga.seq[2] & 0x0F, byte);
    for p in 0..4 {
        if out[p] != cur[p] {
            vga.planes[p * 0x10000 + off] = out[p];
        }
    }
}

/// Copy bytes into guest memory, routing any overlap with a trap-backed planar
/// A0000 window through the VGA write path. DOS services can legally transfer
/// file/device data straight into video memory; on a real VGA those CPU stores
/// still honour map mask/write-mode/latches, while the emulated path has A0000
/// unmapped so raw `machine.copy_to` would fault in the kernel.
pub fn copy_to_guest<A: crate::Arch>(machine: &mut A, vga: &mut DosVga, addr: usize, src: &[u8]) {
    let DosVga::Emulated(vga) = vga else {
        // A native thread's CPU stores already target the card aperture; no
        // emulated planar trap or shadow state participates.
        machine.copy_to(addr, src);
        return;
    };
    let vga = &mut vga.model;
    const A0000_END: usize = A0000 + 0x10000;
    if vga.a0000_trapped {
        let bda_mode = machine.read::<u8>(0x449);
        let planar_mode =
            matches!(bda_mode, 0x0D..=0x12) || (bda_mode == 0x13 && vga.seq[4] & 0x08 == 0);
        if !planar_mode {
            machine.map_fresh_range(A0000 >> 12, 16);
            vga.a0000_trapped = false;
        }
    }
    if src.is_empty()
        || !vga.a0000_trapped
        || addr >= A0000_END
        || addr.saturating_add(src.len()) <= A0000
    {
        machine.copy_to(addr, src);
        return;
    }

    let mut pos = 0;
    if addr < A0000 {
        let n = (A0000 - addr).min(src.len());
        machine.copy_to(addr, &src[..n]);
        pos = n;
    }

    while pos < src.len() {
        let cur = addr + pos;
        if cur >= A0000_END {
            machine.copy_to(cur, &src[pos..]);
            break;
        }
        let n = (A0000_END - cur).min(src.len() - pos);
        for (i, &byte) in src[pos..pos + n].iter().enumerate() {
            vram_write(vga, (cur + i - A0000) as u32, byte);
        }
        pos += n;
    }
}

/// Trapped planar VRAM read: load the 4 latches from the planes at A0000 offset
/// `off` and return the byte the CPU sees (read map select, or color compare).
pub fn vram_read(vga: &mut VgaState, off: u32) -> u8 {
    let off = (off & 0xFFFF) as usize;
    let pl = &vga.planes;
    let cur = [pl[off], pl[0x10000 + off], pl[0x20000 + off], pl[0x30000 + off]];
    let (data, latches) = ::vga::planar_read(cur, &vga.gc);
    vga.latches = latches;
    data
}

/// Rasterize the 8-wide glyph for `ch` into the current *graphics*-mode
/// framebuffer at character cell `(col,row)`, foreground pixel colour `fg`.
/// A BIOS teletype/write-char in a graphics mode must draw font pixels (there
/// is no text cell to poke) — this covers every graphics mode the model draws:
/// CGA 4-colour (04h/05h) and 2-colour (06h) at 0xB8000, EGA/VGA 16-colour
/// planar (0Dh–12h) into `vga.planes`, and linear 256-colour mode 13h at
/// 0xA0000. Returns `false` for a non-graphics mode (caller takes the text-cell
/// path). Cell background pixels are cleared, so a cell fully replaces what was
/// under it, matching a real BIOS's replace (non-XOR) glyph write.
///
/// Each mode uses the ROM font matching its character-cell height: the authentic
/// IBM 8×8 (200-line modes + 13h), 8×14 (EGA 350-line), or 8×16 (VGA 480-line).
/// A native owner is answered by its own ROM and has no register file to
/// rasterize through, so it takes the caller's text-cell path.
pub fn bios_draw_glyph<A: crate::Arch>(machine: &mut A, device: &mut DosVga, mode: u8, ch: u8, col: u32, row: u32, fg: u8) -> bool {
    let DosVga::Emulated(dev) = device else { return false };
    let vga = &mut dev.model;
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
        // pixel from the 4-bit colour, in `vga.planes` (what the planar renderer
        // scans out). Stride follows the CRTC Offset like `classify_mode`.
        0x0D..=0x12 => {
            if vga.planes.is_empty() {
                vga.planes = alloc::vec![0u8; PLANES_LEN];
            }
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
                        let idx = p * 0x10000 + byte_off;
                        if idx >= vga.planes.len() {
                            continue;
                        }
                        if (color >> p) & 1 != 0 { vga.planes[idx] |= mask; } else { vga.planes[idx] &= !mask; }
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
