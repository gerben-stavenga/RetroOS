//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live model behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `lib::vga_render`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

use crate::Regs;
use super::*;
use core::ops::{Deref, DerefMut};

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
        && crate::kernel::platform::get().display.vga_passthrough()
}

/// Materialize the kernel OSD's fixed native-VGA surface. Done once when F12
/// takes the card; subsequent frames only replace the 320×200 linear aperture.
pub fn prepare_native_osd() {
    let mut state = VgaState::new();
    let regs = lib::vga_render::bios_mode_regs(0x13).expect("mode 13h register table");
    state.misc_output = regs.misc;
    state.seq = regs.seq;
    state.gc = regs.gc;
    state.crtc = regs.crtc;
    state.dac = lib::vga_render::fallback_palette();
    state.planes.resize(4 * 0x10000, 0);
    state.restore_to_hardware();
}

pub struct NativeVga {
    state: VgaState,
    display: crate::kernel::platform::DisplayToken,
}

pub struct EmulatedVga {
    state: VgaState,
}

pub struct PresentedVga {
    state: VgaState,
    display: crate::kernel::platform::DisplayToken,
}

impl NativeVga {
    pub fn into_emulated<A: crate::Arch>(
        mut self,
        machine: &mut A,
    ) -> (EmulatedVga, crate::kernel::platform::DisplayToken) {
        self.state.save_from_hardware();
        self.state.materialize_emulated_aperture(machine);
        (EmulatedVga { state: self.state }, self.display)
    }
}

impl EmulatedVga {
    pub fn present<A: crate::Arch>(
        mut self,
        machine: &mut A,
        display: crate::kernel::platform::DisplayToken,
    ) -> Vga {
        match display {
            display @ crate::kernel::platform::DisplayToken::VgaCard => {
                // A freshly created DOS VGA has no suspended image yet. Its
                // first attachment adopts the card exactly as the preceding
                // visible owner left it (normally BIOS text mode plus the
                // boot console); manufacturing a zeroed four-plane snapshot
                // here and restoring it blanks the native display. Once this
                // VGA has been suspended, `planes` is populated and later
                // attachments perform the ordinary exact repaint.
                if !self.state.planes.is_empty() {
                    self.state.capture_emulated_aperture(machine);
                }
                machine.map_phys_range(0xA0000 >> 12, 0x20, 0xA0000 >> 12, 0);
                self.state.a0000_trapped = false;
                self.state.restore_to_hardware();
                Vga::Native(NativeVga { state: self.state, display })
            }
            display => Vga::Presented(PresentedVga { state: self.state, display }),
        }
    }
}

/// A thread's VGA device. The variant, rather than machine capability, decides
/// whether guest accesses reach hardware or the emulated register file.
pub enum Vga {
    Native(NativeVga),
    Emulated(EmulatedVga),
    Presented(PresentedVga),
}

impl Default for Vga {
    fn default() -> Self {
        Self::new()
    }
}

impl Vga {
    pub fn new() -> Self {
        Self::Emulated(EmulatedVga { state: VgaState::new() })
    }

    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }

    pub fn is_emulated(&self) -> bool {
        !self.is_native()
    }

    pub fn is_presented(&self) -> bool {
        matches!(self, Self::Native(_) | Self::Presented(_))
    }

    /// Consume a native attachment, snapshot it, and return the emulated
    /// device plus the released physical-card authority.
    pub fn into_emulated<A: crate::Arch>(
        self,
        machine: &mut A,
    ) -> (Self, crate::kernel::platform::DisplayToken) {
        match self {
            Self::Emulated(_) => panic!("detached VGA has no display token"),
            Self::Native(vga) => {
                let (vga, display) = vga.into_emulated(machine);
                (Self::Emulated(vga), display)
            }
            Self::Presented(vga) =>
                (Self::Emulated(EmulatedVga { state: vga.state }), vga.display),
        }
    }

    /// Consume a detached emulated device and make it the visible owner.
    pub fn present<A: crate::Arch>(
        self,
        machine: &mut A,
        display: crate::kernel::platform::DisplayToken,
    ) -> Self {
        match self {
            Self::Emulated(vga) => vga.present(machine, display),
            Self::Native(_) | Self::Presented(_) => panic!("VGA already owns a display"),
        }
    }

    pub fn display(&self) -> Option<&crate::kernel::platform::DisplayToken> {
        match self {
            Self::Native(vga) => Some(&vga.display),
            Self::Presented(vga) => Some(&vga.display),
            Self::Emulated(_) => None,
        }
    }

    pub fn snapshot_hardware_into_emulated<A: crate::Arch>(&mut self, machine: &mut A) {
        assert!(self.is_emulated());
        self.save_from_hardware();
        self.materialize_emulated_aperture(machine);
    }

    pub fn swap_state(&mut self, other: &mut Self) {
        core::mem::swap(&mut **self, &mut **other);
    }

    pub fn repaint_native(&self) {
        assert!(self.is_native());
        self.restore_to_hardware();
    }
}

impl Deref for Vga {
    type Target = VgaState;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Native(vga) => &vga.state,
            Self::Emulated(vga) => &vga.state,
            Self::Presented(vga) => &vga.state,
        }
    }
}

impl DerefMut for Vga {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Native(vga) => &mut vga.state,
            Self::Emulated(vga) => &mut vga.state,
            Self::Presented(vga) => &mut vga.state,
        }
    }
}

// ============================================================================
// VGA register state (AcState + VgaState)
// ============================================================================

/// VGA Attribute Controller port (0x3C0) state. The hardware has two
/// independent pieces of state, neither readable from any port:
///   - `index`:        last byte written in index state. Includes the PAS bit
///     (bit 5) which controls screen blanking. Persistent —
///     subsequent data writes do not change it.
///   - `pending_data`: flip-flop position. `false` = next 0x3C0 write is an
///     index byte; `true` = next 0x3C0 write is its data.
///     `inb(0x3DA)` clears `pending_data` (resets the flipflop to index state).
#[derive(Clone, Copy)]
pub struct AcState {
    pub index: u8,
    pub pending_data: bool,
}

impl AcState {
    // PAS=1 (bit 5 of index) matches BIOS-default boot state where the
    // display is enabled. The tracker is needed because the AC flip-flop
    // can't be read from hardware. A `0` default is wrong: programs that
    // never write AC (any program that sticks to text mode and DOS I/O)
    // would have save_from_hardware write index=0 back to 0x3C0,
    // clearing PAS and blanking the display. Default to `0x20` so the
    // tracker matches HW from the moment the kernel boots.
    const fn new() -> Self { Self { index: 0x20, pending_data: false } }
}

/// Global AC state, tracks real hardware across all processes.
pub(super) static mut VGA_AC_STATE: AcState = AcState::new();

/// Per-process VGA state: 256KB framebuffer (4 planes) + all registers.
/// Saved/restored on context switch so each process has its own screen.
pub struct VgaState {
    /// 4 planes × 64KB = 256KB framebuffer (flat: plane 0 at [0..65536], etc.)
    pub planes: alloc::vec::Vec<u8>,
    // ── Registers ──
    pub misc_output: u8,
    pub feature_ctl: u8,
    /// CGA Mode-Control (0x3D8) and Colour-Select (0x3D9). The CGA renderer
    /// resolves its 4-colour palette from these (palette 0/1, foreground
    /// intensity, background/border colour); real-VGA passthrough honours them
    /// in hardware, so they matter only on the emulated (UEFI/hosted) path.
    pub cga_mode_ctl: u8,
    pub cga_color_select: u8,
    pub seq: [u8; 5],
    pub crtc: [u8; 25],
    pub gc: [u8; 9],
    pub ac: [u8; 21],
    pub dac: [u8; 768],
    pub dac_mask: u8,
    // ── Port index / state ──
    pub seq_index: u8,
    pub crtc_index: u8,
    pub gc_index: u8,
    /// AC port flip-flop + latched index. See `VGA_AC_STATE`.
    pub ac_state: AcState,
    /// DAC pixel-address latch (single shared index for read & write)
    pub dac_index: u8,
    /// DAC state byte from inb(0x3C7): 0x00 = write-mode, 0x03 = read-mode
    pub dac_state: u8,
    // ── Emulated-model DAC latches (absent-card port model only) ──
    /// Real VGA keeps *separate* read and write indices; palette-cycling
    /// effects read entries back, rotate, and rewrite them — Prince of
    /// Persia's torch flames do exactly this, and a read answering 0xFF
    /// turns every cycled entry permanent white. `dac_index` above stays
    /// the write index (the save/restore contract); these carry the read
    /// index and the per-entry R/G/B sub-positions.
    pub dac_read_index: u8,
    pub dac_rsub: u8,
    pub dac_wsub: u8,
    /// VGA read latches: the 4 plane bytes loaded by the most recent VRAM read
    /// (one per plane). Write mode 1 (latched copy) writes these straight
    /// through; write modes 0/2/3 ALU the new value against them. Only used on
    /// the trapped planar write path (see `vram_write`/`vram_read`).
    pub latches: [u8; 4],
    // ── VESA SVGA (banked) ──
    /// Active VBE mode geometry; `svga_w == 0` ⇒ not in an SVGA mode. The
    /// framebuffer is a guest-mapped region at `SVGA_LFB_BASE`; the 0xA0000
    /// window is *aliased* onto its current bank (shared frames), so guest
    /// writes land directly in it — no copy, always coherent.
    pub svga_w: u16,
    pub svga_h: u16,
    pub svga_bpp: u8,
    /// Current window-A bank (64 KB granule) the 0xA0000 window aliases.
    pub svga_bank: u16,
    /// This address space's A0000 window is mapped as the planar trap
    /// (present=0 + MMIO marker), so kernel-side writes must route through
    /// `vram_write` instead of raw guest-memory stores.
    pub a0000_trapped: bool,
}

impl Default for VgaState {
    fn default() -> Self {
        Self::new()
    }
}

impl VgaState {
    pub fn new() -> Self {
        Self {
            planes: alloc::vec::Vec::new(),
            // EGA/text DAC defaults so the emulated model renders text in
            // colour even though text-mode programs never program the DAC
            // (mode 13h loads overwrite these). Harmless for the metal
            // snapshot use: restore_to_hardware no-ops until a real save
            // fills `planes`, which also rewrites the whole DAC.
            misc_output: 0,
            feature_ctl: 0,
            cga_mode_ctl: 0,
            cga_color_select: 0,
            seq: [0; 5],
            crtc: [0; 25],
            // GC Bit Mask (index 8) resets to 0xFF — every CPU-data bit passes
            // through; BIOS mode-set leaves it so and Mode X / EGA writes rely
            // on it. Defaulting it to 0 masked every planar write to the latch.
            gc: { let mut g = [0u8; 9]; g[8] = 0xFF; g },
            // AC mode-control (reg 0x10) bit 3 set: blink semantics for
            // attribute bit 7, the BIOS mode-3 power-on default. TUIs that
            // want 16 background colors clear it (INT 10h AX=1003 BL=0 or a
            // direct AC write — both land here); DN's dark-grey panels
            // (bg=8) rendered black until this was modeled.
            ac: { let mut a = [0u8; 21]; a[0x10] = 0x08; a },
            dac: lib::vga_render::fallback_palette(),
            dac_mask: 0xFF,
            seq_index: 0,
            crtc_index: 0,
            gc_index: 0,
            ac_state: AcState::new(),
            dac_index: 0,
            dac_state: 0,
            dac_read_index: 0,
            dac_rsub: 0,
            dac_wsub: 0,
            latches: [0; 4],
            svga_w: 0,
            svga_h: 0,
            svga_bpp: 0,
            svga_bank: 0,
            a0000_trapped: false,
        }
    }

    /// Emulated register-file write — the absent-card half of the VGA
    /// passthrough-vs-emulate split (`Vga::is_emulated`).
    /// This per-thread struct IS the hardware then: `emulate_outb` routes the
    /// 3Cx/3Dx window here instead of to real ports, and save/restore on
    /// context switch becomes a no-op because the state never leaves the
    /// struct. Index/data pairs land in the same arrays the metal
    /// save/restore fills, so every consumer (renderer, mode queries) reads
    /// one representation.
    pub fn port_write(&mut self, port: u16, v: u8) {
        match port {
            0x3C0 => {
                if !self.ac_state.pending_data {
                    self.ac_state.index = v;
                } else {
                    let i = (self.ac_state.index & 0x1F) as usize;
                    if i < 21 {
                        self.ac[i] = v;
                    }
                }
                self.ac_state.pending_data = !self.ac_state.pending_data;
            }
            0x3C2 => self.misc_output = v,
            0x3C4 => self.seq_index = v,
            0x3C5 => {
                let i = (self.seq_index & 0x1F) as usize;
                if i < 5 {
                    self.seq[i] = v;
                }
            }
            0x3C6 => self.dac_mask = v,
            0x3C7 => {
                self.dac_read_index = v;
                self.dac_rsub = 0;
                self.dac_state = 0x03;
            }
            0x3C8 => {
                self.dac_index = v;
                self.dac_wsub = 0;
                self.dac_state = 0x00;
            }
            0x3C9 => {
                let i = self.dac_index as usize * 3 + self.dac_wsub as usize;
                self.dac[i] = v & 0x3F;
                self.dac_wsub += 1;
                if self.dac_wsub == 3 {
                    self.dac_wsub = 0;
                    self.dac_index = self.dac_index.wrapping_add(1);
                }
            }
            0x3CE => self.gc_index = v,
            0x3CF => {
                let i = (self.gc_index & 0x0F) as usize;
                if i < 9 {
                    self.gc[i] = v;
                }
            }
            0x3D4 => self.crtc_index = v,
            0x3D5 => {
                let i = self.crtc_index as usize;
                if i < 25 {
                    self.crtc[i] = v;
                }
            }
            0x3D8 => self.cga_mode_ctl = v,     // CGA Mode Control
            0x3D9 => self.cga_color_select = v, // CGA Colour Select (palette/bg)
            0x3DA => self.feature_ctl = v, // FCR write port (colour)
            _ => {}
        }
    }

    /// Emulated register-file read (see `port_write`). 0x3DA (status + AC
    /// flip-flop reset) stays in `emulate_inb`, which fabricates the retrace
    /// bits for emulated and QEMU cards alike.
    pub fn port_read(&mut self, port: u16) -> u8 {
        match port {
            0x3C0 => self.ac_state.index,
            0x3C1 => {
                let i = (self.ac_state.index & 0x1F) as usize;
                if i < 21 { self.ac[i] } else { 0 }
            }
            0x3C2 => 0, // input status 0: no interrupt pending, monitor present
            0x3C4 => self.seq_index,
            0x3C5 => {
                let i = (self.seq_index & 0x1F) as usize;
                if i < 5 { self.seq[i] } else { 0 }
            }
            0x3C6 => self.dac_mask,
            0x3C7 => self.dac_state,
            0x3C8 => self.dac_index,
            0x3C9 => {
                let v = self.dac[self.dac_read_index as usize * 3 + self.dac_rsub as usize];
                self.dac_rsub += 1;
                if self.dac_rsub == 3 {
                    self.dac_rsub = 0;
                    self.dac_read_index = self.dac_read_index.wrapping_add(1);
                }
                v
            }
            0x3CA => self.feature_ctl,
            0x3CC => self.misc_output,
            0x3CE => self.gc_index,
            0x3CF => {
                let i = (self.gc_index & 0x0F) as usize;
                if i < 9 { self.gc[i] } else { 0 }
            }
            0x3D4 => self.crtc_index,
            0x3D5 => {
                let i = self.crtc_index as usize;
                if i < 25 { self.crtc[i] } else { 0 }
            }
            _ => 0xFF,
        }
    }

    fn materialize_emulated_aperture<A: crate::Arch>(&mut self, machine: &mut A) {
        use lib::vga_render::VgaMode;
        match self.classify_mode() {
            Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {
                machine.map_phys_range(A0000 >> 12, 16, 0, arch_abi::MAP_MMIO);
                self.a0000_trapped = true;
            }
            Some(VgaMode::Mode13h) => {
                machine.map_fresh_range(A0000 >> 12, 16);
                let mut chained = alloc::vec![0u8; 0x10000];
                lib::vga_render::chain4_merge(&self.planes, &mut chained);
                machine.copy_to(A0000, &chained);
                self.a0000_trapped = false;
            }
            Some(VgaMode::Text80x25) => {
                machine.map_fresh_range(0xB8000 >> 12, 8);
                let mut text = alloc::vec![0u8; 0x8000];
                for i in 0..0x4000 {
                    text[i * 2] = self.planes.get(i).copied().unwrap_or(0);
                    text[i * 2 + 1] =
                        self.planes.get(0x10000 + i).copied().unwrap_or(0);
                }
                machine.copy_to(0xB8000, &text);
                self.a0000_trapped = false;
            }
            Some(VgaMode::Cga4) => {
                machine.map_fresh_range(0xB8000 >> 12, 8);
                let mut cga = alloc::vec![0u8; 0x4000];
                for i in 0..0x2000 {
                    cga[i * 2] = self.planes.get(i).copied().unwrap_or(0);
                    cga[i * 2 + 1] =
                        self.planes.get(0x10000 + i).copied().unwrap_or(0);
                }
                machine.copy_to(0xB8000, &cga);
                self.a0000_trapped = false;
            }
            Some(VgaMode::Cga2) => {
                machine.map_fresh_range(0xB8000 >> 12, 8);
                let n = 0x4000.min(self.planes.len());
                machine.copy_to(0xB8000, &self.planes[..n]);
                self.a0000_trapped = false;
            }
            Some(VgaMode::LinearSvga { .. }) | None => {
                self.a0000_trapped = false;
            }
        }
    }

    fn capture_emulated_aperture<A: crate::Arch>(&mut self, machine: &mut A) {
        use lib::vga_render::VgaMode;
        if self.planes.len() != PLANES_LEN {
            self.planes.resize(PLANES_LEN, 0);
        }
        match self.classify_mode() {
            Some(VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) => {}
            Some(VgaMode::Mode13h) => {
                let mut chained = alloc::vec![0u8; 0x10000];
                machine.copy_from(A0000, &mut chained);
                lib::vga_render::chain4_split(&chained, &mut self.planes);
            }
            Some(VgaMode::Text80x25) => {
                let mut text = alloc::vec![0u8; 0x8000];
                machine.copy_from(0xB8000, &mut text);
                for i in 0..0x4000 {
                    self.planes[i] = text[i * 2];
                    self.planes[0x10000 + i] = text[i * 2 + 1];
                }
            }
            Some(VgaMode::Cga4) => {
                let mut cga = alloc::vec![0u8; 0x4000];
                machine.copy_from(0xB8000, &mut cga);
                for i in 0..0x2000 {
                    self.planes[i] = cga[i * 2];
                    self.planes[0x10000 + i] = cga[i * 2 + 1];
                }
            }
            Some(VgaMode::Cga2) => {
                machine.copy_from(0xB8000, &mut self.planes[..0x4000]);
            }
            Some(VgaMode::LinearSvga { .. }) | None => {}
        }
    }

    /// Read current VGA hardware state into this struct. Called only by a
    /// consuming `NativeVga -> EmulatedVga` transition.
    pub(crate) fn save_from_hardware(&mut self) {
        use crate::kernel::portio::{inb, outb};
        if self.planes.is_empty() {
            self.planes = alloc::vec![0u8; 4 * 65536];
        }
        // Capture the AC sequencing state, then reset the flipflop to a
        // known index state. With 0x3C0/0x3DA granted to the guest
        // (io_policy `vga_ports_direct`), the VGA_AC_STATE tracker never saw
        // its writes — the card is the only source of truth, and it must be
        // read BEFORE the 0x3DA reset below destroys the phase.
        let plat = crate::kernel::platform::get();
        if plat.vga_ports_direct() {
            let index = inb(0x3C0); // address-register readback (incl. PAS)
            let pending_data = if plat.vga_readback {
                let crtc_index = inb(0x3D4);
                outb(0x3D4, 0x24); // Cirrus CR24: bit 7 = flip-flop phase
                let phase = inb(0x3D5) & 0x80 != 0;
                outb(0x3D4, crtc_index);
                phase
            } else {
                // Phase not readable on this card — assume index state (the
                // boot warning declared full restore unsupported here).
                false
            };
            self.ac_state = AcState { index, pending_data };
        } else {
            // Trapped AC ports (QEMU): the tracker observed every access.
            self.ac_state = unsafe { VGA_AC_STATE };
        }
        let _ = inb(0x3DA);

        // Capture index registers BEFORE the save loops overwrite them.
        self.seq_index = inb(0x3C4);
        self.crtc_index = inb(0x3D4);
        self.gc_index = inb(0x3CE);

        // Save all registers
        self.misc_output = inb(0x3CC);
        self.feature_ctl = inb(0x3CA);
        for i in 0..5u8 { outb(0x3C4, i); self.seq[i as usize] = inb(0x3C5); }
        for i in 0..25u8 { outb(0x3D4, i); self.crtc[i as usize] = inb(0x3D5); }
        for i in 0..9u8 { outb(0x3CE, i); self.gc[i as usize] = inb(0x3CF); }

        // Data latches, via Cirrus CR22 (latch selected by GC4 read-map).
        // Must happen before the plane copy below — every VRAM read reloads
        // them. Without the readback the latches stay unrecoverable (see the
        // gap comment further down).
        if plat.vga_ports_direct() && plat.vga_readback {
            for plane in 0..4u8 {
                outb(0x3CE, 4); outb(0x3CF, plane);
                outb(0x3D4, 0x22);
                self.latches[plane as usize] = inb(0x3D5);
            }
            outb(0x3CE, 4); outb(0x3CF, self.gc[4]);
        }
        // QEMU reports a zero PEL mask even while its live VGA output is
        // visibly unmasked. Treat that backend's readback as absent; real
        // hardware keeps the exact register value.
        self.dac_mask = if plat.host == crate::kernel::platform::Host::Qemu {
            0xFF
        } else {
            inb(0x3C6)
        };
        // Capture program-tracked DAC index latch + read/write mode before
        // stomping it with our bulk read.
        self.dac_index = inb(0x3C8);
        self.dac_state = inb(0x3C7);
        outb(0x3C7, 0);
        for i in 0..768 { self.dac[i] = inb(0x3C9); }

        // Attribute Controller — must reset flipflop EACH iteration.
        // inb(0x3C1) reads the register but does NOT toggle the flipflop,
        // so without a reset the next outb(0x3C0, i) would be a data write.
        for i in 0..21u8 {
            let _ = inb(0x3DA);
            outb(0x3C0, i);
            self.ac[i as usize] = inb(0x3C1);
        }

        // Restore hardware AC to the program's tracked state. Always write the
        // latched index byte (carries the PAS bit, which the save loop above
        // clobbered to 0). Then, if the program is in index state, do one more
        // 0x3DA read to put the flipflop back.
        let _ = inb(0x3DA);
        outb(0x3C0, self.ac_state.index);
        if !self.ac_state.pending_data {
            let _ = inb(0x3DA);
        }

        crate::dbg_println!("VGA save: seq4={:02X} gc5={:02X} gc6={:02X} crtc14={:02X} crtc17={:02X} ac10={:02X} misc={:02X} start={:04X} dacmask={:02X}",
            self.seq[4], self.gc[5], self.gc[6], self.crtc[0x14], self.crtc[0x17], self.ac[0x10], self.misc_output,
            (self.crtc[0x0C] as u16) << 8 | self.crtc[0x0D] as u16,
            self.dac_mask);

        // Blank the display for the rest of the save. The flat-planar
        // overrides below mis-interpret the current framebuffer if the
        // guest was in chain-4 / chain-2 / odd-even, so without screen-off
        // the user sees a brief frame of scrambled pixels.
        // SEQ Index 1 bit 5 = "Screen Off" — DAC output forced to 0
        // without touching any other register. Restored at the bottom.
        outb(0x3C4, 1); outb(0x3C5, self.seq[1] | 0x20);

        // Force flat planar mode for reading planes:
        // SEQ mem mode = sequential access (no chain-4, no odd/even)
        // GC mode = read mode 0, write mode 0
        // GC misc = graphics mode, A0000/64K window, no chain odd/even
        outb(0x3C4, 4); outb(0x3C5, 0x06);
        outb(0x3CE, 5); outb(0x3CF, 0x00);
        outb(0x3CE, 6); outb(0x3CF, 0x05);

        // GAP (plain VGA only): GC read latches (4 bytes loaded by the most
        // recent VGA memory read) are not preserved across save/restore —
        // the bulk reads below clobber them, and stock VGA exposes no port
        // to read them without a destructive VRAM access. With Cirrus
        // readbacks (`platform::vga_readback`) they were already captured
        // via CR22 above and are reloaded by `restore_to_hardware`.
        //
        // Symptom without readbacks: a mode-X latch blit preempted between
        // its source read and destination write produces 4 wrong bytes when
        // the program resumes:
        //     mov al, [esi]   ; loads latches with src plane bytes
        //     <-- preempt here -->
        //     mov [edi], al   ; write mode 1: writes (wrong) latches to dst
        // The affected window is 1–2 instructions wide, so a lost latch
        // normally appears as one bad 4-byte stripe in one frame.
        // Read planes through the kernel-side low-memory mapping
        // (LOW_MEM_BASE + 0xA0000) so this works regardless of which
        // personality's user pages are currently mapped — Linux threads
        // don't have a 0xA0000 identity mapping at all, so a bare access
        // would fault when suspending shell.elf.
        let vga_window = (crate::LOW_MEM_BASE + 0xA0000) as *const u8;
        for plane in 0..4u8 {
            outb(0x3CE, 4); outb(0x3CF, plane);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vga_window,
                    self.planes[plane as usize * 65536..].as_mut_ptr(),
                    65536,
                );
            }
        }

        // Restore registers we temporarily changed (incl. SEQ[1] to unblank)
        outb(0x3C4, 1); outb(0x3C5, self.seq[1]);
        outb(0x3C4, 4); outb(0x3C5, self.seq[4]);
        outb(0x3CE, 4); outb(0x3CF, self.gc[4]);
        outb(0x3CE, 5); outb(0x3CF, self.gc[5]);
        outb(0x3CE, 6); outb(0x3CF, self.gc[6]);
        // Restore the program's tracked index registers
        outb(0x3C4, self.seq_index);
        outb(0x3D4, self.crtc_index);
        outb(0x3CE, self.gc_index);
    }

    /// Write this struct's state to VGA hardware. Called only while acquiring
    /// the physical lease (or repainting an already-native owner).
    pub(crate) fn restore_to_hardware(&self) {
        if self.planes.is_empty() { return; }
        use crate::kernel::portio::{inb, outb};

        // Reset AC flipflop to known (index) state before any VGA register work.
        let _ = inb(0x3DA);

        // Blank the display for the entire mode-set so the user doesn't see
        // intermediate state — the prior mode's CRTC/AC/DAC settings vs. the
        // new mode's plane data is a parade of garbage otherwise. SEQ Index 1
        // bit 5 = "Screen Off" forces DAC output to 0 without touching any
        // other state. The full-mode SEQ restore below intentionally OR-s bit
        // 5 back in (so the rest of CRTC/GC/AC/DAC reprogramming stays dark);
        // an explicit final write of SEQ[1] unblanks once everything is set.
        outb(0x3C4, 1);
        outb(0x3C5, inb(0x3C5) | 0x20);

        // Step 1: Write planes in forced flat planar mode.
        // Need misc_output for clock source, but force sequential planar access.
        outb(0x3C4, 0); outb(0x3C5, 0x01); // sync reset
        outb(0x3C2, self.misc_output);
        outb(0x3C4, 2); outb(0x3C5, 0x0F); // map mask: all planes
        outb(0x3C4, 4); outb(0x3C5, 0x06); // mem mode: sequential, no chain-4
        outb(0x3C4, 0); outb(0x3C5, 0x03); // release reset
        outb(0x3CE, 5); outb(0x3CF, 0x00); // GC mode: write mode 0
        outb(0x3CE, 6); outb(0x3CF, 0x05); // GC misc: graphics, A0000/64K

        // Write planes through the kernel-side low-memory mapping (see
        // save_from_hardware for the rationale).
        let vga_window = (crate::LOW_MEM_BASE + 0xA0000) as *mut u8;
        for plane in 0..4u8 {
            outb(0x3C4, 2); outb(0x3C5, 1 << plane);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.planes[plane as usize * 65536..].as_ptr(),
                    vga_window,
                    65536,
                );
            }
        }

        // Reload the guest's data latches (captured via Cirrus CR22 in
        // save_from_hardware): stage the four bytes at offset 0, one read
        // pulls all four into the latches, then put the real content back.
        // Writes never load latches and everything below Step 2 is port
        // I/O only, so the guest resumes with its blit state intact. Still
        // in forced flat-planar write mode 0 here, so the staging writes
        // land verbatim.
        {
            let plat = crate::kernel::platform::get();
            if plat.vga_ports_direct() && plat.vga_readback {
                for plane in 0..4u8 {
                    outb(0x3C4, 2); outb(0x3C5, 1 << plane);
                    unsafe { core::ptr::write_volatile(vga_window, self.latches[plane as usize]); }
                }
                unsafe { let _ = core::ptr::read_volatile(vga_window as *const u8); }
                for plane in 0..4u8 {
                    outb(0x3C4, 2); outb(0x3C5, 1 << plane);
                    unsafe { core::ptr::write_volatile(vga_window, self.planes[plane as usize * 65536]); }
                }
            }
        }

        // Step 2: Set target mode registers.
        // Bracket SEQ writes with sync reset so a dot-clock change in
        // misc_output/seq[1] doesn't glitch the sequencer mid-cycle.
        // Reverse iteration so SEQ[0] = self.seq[0] is the last write
        // and naturally acts as the release.
        outb(0x3C4, 0); outb(0x3C5, 0x01); // assert sync reset
        outb(0x3C2, self.misc_output);
        outb(0x3DA, self.feature_ctl); // FCR (color mode write port)
        // SEQ restore: hold screen-off (bit 5) through SEQ[1] so the CRTC/AC/DAC
        // reprogramming below stays dark. The final explicit SEQ[1] write at
        // the end of this function unblanks.
        for i in (0..5u8).rev() {
            let v = if i == 1 { self.seq[1] | 0x20 } else { self.seq[i as usize] };
            outb(0x3C4, i); outb(0x3C5, v);
        }

        // CRTC — unlock first (clear protect bit in reg 0x11)
        outb(0x3D4, 0x11); outb(0x3D5, self.crtc[0x11] & 0x7F);
        for i in 0..25u8 { outb(0x3D4, i); outb(0x3D5, self.crtc[i as usize]); }
        // Graphics Controller
        for i in 0..9u8 { outb(0x3CE, i); outb(0x3CF, self.gc[i as usize]); }
        // Attribute Controller — write all 21 registers
        let _ = inb(0x3DA);
        for i in 0..21u8 { outb(0x3C0, i); outb(0x3C0, self.ac[i as usize]); }
        // Restore the program's AC state. Same pattern as save_from_hardware.
        let _ = inb(0x3DA);
        outb(0x3C0, self.ac_state.index);
        if !self.ac_state.pending_data {
            let _ = inb(0x3DA);
        }
        unsafe { VGA_AC_STATE = self.ac_state; }
        // DAC
        outb(0x3C6, self.dac_mask);
        outb(0x3C8, 0);
        for i in 0..768 { outb(0x3C9, self.dac[i]); }
        // Restore the program's DAC index latch + read/write mode.
        // dac_state bits[1:0]: 0x03 = read-mode (set via 0x3C7),
        //                      0x00 = write-mode (set via 0x3C8).
        if self.dac_state & 3 == 3 {
            outb(0x3C7, self.dac_index);
        } else {
            outb(0x3C8, self.dac_index);
        }
        // Unblank: rewrite SEQ[1] with the saved (bit-5-cleared) value now
        // that CRTC/GC/AC/DAC are all loaded. Has to happen before the index
        // restore below, which sets SEQ index to whatever the program had.
        outb(0x3C4, 1); outb(0x3C5, self.seq[1]);

        // Restore index registers
        outb(0x3C4, self.seq_index);
        outb(0x3D4, self.crtc_index);
        outb(0x3CE, self.gc_index);
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

use core::sync::atomic::Ordering;

/// The emulated VGA's plane memory: 4 planes × 64 KB, byte (plane `p`, offset
/// `off`) at `[p*0x10000 + off]`. Lives per-thread on `VgaState::planes` (the
/// focus-owned model) — the same buffer `save_from_hardware` fills for a real
/// card — so the planar trap and the renderer touch it directly, no global and
/// no per-frame copy.
const PLANES_LEN: usize = 4 * 0x10000;
const A0000: usize = 0xA0000;

/// React to a Sequencer register write (port 0x3C5) that may change the
/// chain-4 mode or the plane-select mask. Drives the A0000 paging alias.
/// `pc.vga` already holds the post-write register values.
pub fn on_seq_write<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs) {
    if pc.vga.is_native() {
        return; // a real card does its own plane routing
    }
    let idx = pc.vga.seq_index & 0x1F;
    match idx {
        4 => {
            // Memory Mode bit 3 = chain-4. Set ⇒ chained (mode 13h linear);
            // clear ⇒ unchained (Mode X planes). The chain→unchain hop seeds the
            // planes from the current chained A0000 image (a 13h frame the game
            // unchains into Mode X mid-stream); the reverse merges them back.
            let unchained = pc.vga.seq[4] & 0x08 == 0;
            let currently_planar = pc.vga.a0000_trapped;
            if unchained && !currently_planar {
                let mut chained = alloc::vec![0u8; 0x10000];
                machine.copy_from(A0000, &mut chained);
                arm_planar(machine, &mut pc.vga, Some(&chained));
            } else if !unchained && currently_planar {
                disarm_planar(machine, &mut pc.vga, regs, true);
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
        Some(chained) => lib::vga_render::chain4_split(chained, &mut vga.planes),
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
        lib::vga_render::chain4_merge(&vga.planes, &mut chained);
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
const SVGA_LFB_BASE: usize = 0x4000_0000; // 1 GB
const SVGA_WINDOW: usize = 0x10000; // 64 KB VBE bank granule
const WINDOW_PAGES: usize = SVGA_WINDOW >> 12;

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
    let pages = svga_banks(w, h, bpp) * WINDOW_PAGES;
    machine.map_fresh_range(SVGA_LFB_BASE >> 12, pages);
    machine.copy_page_entries(SVGA_LFB_BASE >> 12, A0000 >> 12, WINDOW_PAGES);
    pc.vga.svga_w = w;
    pc.vga.svga_h = h;
    pc.vga.svga_bpp = bpp;
    pc.vga.svga_bank = 0;
    // A VBE set-mode bypasses on_set_mode, so clear any stale planar marker.
    pc.vga.a0000_trapped = false;
}

/// VBE 4F05h window control: alias the 0xA0000 window onto `bank` of the
/// framebuffer. No copy — the window simply shares the bank's frames.
pub fn svga_set_bank<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, bank: u16) {
    if pc.vga.svga_w == 0 {
        return;
    }
    let src = (SVGA_LFB_BASE >> 12) + bank as usize * WINDOW_PAGES;
    machine.copy_page_entries(src, A0000 >> 12, WINDOW_PAGES);
    pc.vga.svga_bank = bank;
}

/// Leave SVGA for a standard VGA mode: detach the window alias and free the
/// framebuffer region.
pub fn svga_leave<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine) {
    if pc.vga.svga_w == 0 {
        return;
    }
    let pages = svga_banks(pc.vga.svga_w, pc.vga.svga_h, pc.vga.svga_bpp) * WINDOW_PAGES;
    // Detach the window alias (drops its shared ref on the current bank), then
    // free the framebuffer region — frees the frames and leaves the entries
    // absent, the only sane "free" for an allocated RAM region.
    machine.map_fresh_range(A0000 >> 12, WINDOW_PAGES);
    machine.unmap_range(SVGA_LFB_BASE >> 12, pages);
    pc.vga.svga_w = 0;
    pc.vga.svga_h = 0;
    pc.vga.svga_bpp = 0;
    pc.vga.svga_bank = 0;
    pc.vga.a0000_trapped = false;
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
    if pc.vga.is_native() {
        return; // a real card draws its own planes
    }
    // A standard mode-set leaves any active VESA SVGA mode.
    svga_leave(machine, pc);
    // Program the full canonical register file, exactly as a real BIOS does
    // from its video parameter table. This is what keeps classification
    // register-pure (the hardware never consults BIOS data): a tweaker
    // starts every mode from the same coherent state a real BIOS leaves —
    // and a mode set CLEARS the previous program's tweaks, so Jazz's
    // unchained level mode can't leak into its menu's mode 13h (stale
    // display-start showed the menu at the wrong offset; stale shift/chain
    // bits later misclassified the menu as the level's Mode X entirely).
    if let Some(r) = lib::vga_render::bios_mode_regs(mode) {
        pc.vga.misc_output = r.misc;
        pc.vga.seq = r.seq;
        pc.vga.gc = r.gc;
        pc.vga.crtc = r.crtc;
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
        pc.vga.dac = if matches!(mode, 0x0D | 0x0E) {
            lib::vga_render::ega_200line_dac()
        } else {
            lib::vga_render::ega_dac()
        };
    } else if clear {
        pc.vga.dac = lib::vga_render::fallback_palette();
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
        pc.vga.ac[..16].copy_from_slice(ac);
        pc.vga.ac[0x10] &= !0x80; // P4/P5 from palette, not colour-select
        pc.vga.ac[0x12] = 0x0F; // colour plane enable: all planes visible
        pc.vga.ac[0x13] = 0x00; // pixel pan
        pc.vga.ac[0x14] = 0x00; // colour select high bits
    }
    let currently = pc.vga.a0000_trapped;
    if planar && !currently {
        arm_planar(machine, &mut pc.vga, None); // fresh mode-set ⇒ zeroed planes
    } else if planar && currently && clear {
        // Re-set the same planar mode: keep the trap, just blank the planes.
        pc.vga.planes.fill(0);
    } else if !planar && currently {
        disarm_planar(machine, &mut pc.vga, regs, false); // leaving planar ⇒ A0000 back to RAM
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
    let out = lib::vga_render::planar_write(cur, vga.latches, &vga.gc, vga.seq[2] & 0x0F, byte);
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
pub fn copy_to_guest<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, addr: usize, src: &[u8]) {
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
    let (data, latches) = lib::vga_render::planar_read(cur, &vga.gc);
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
pub fn bios_draw_glyph<A: crate::Arch>(machine: &mut A, vga: &mut VgaState, mode: u8, ch: u8, col: u32, row: u32, fg: u8) -> bool {
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
// Planar #PF decode — the kernel-side trap (no arch involvement: A0000 is left
// unmapped while planar logic is needed, so the guest store/load faults, the
// *existing* PageFault event arrives, and we decode the faulting instruction
// here and emulate it through `vram_write`/`vram_read`).
// ============================================================================

/// Width of the data a string/mov op moves (bytes).
fn opsize(op32: bool, byte_op: bool) -> u32 {
    if byte_op { 1 } else if op32 { 4 } else { 2 }
}

/// Read/write an integer GP register by encoding `idx` and size `sz` (bytes).
/// Maps the x86 register order (0=A,1=C,2=D,3=B,4=SP/AH..,5=BP/CH,6=SI,7=DI).
fn gpr(regs: &mut Regs, idx: u8, sz: u32) -> u32 {
    let full = match idx & 7 {
        0 => regs.rax, 1 => regs.rcx, 2 => regs.rdx, 3 => regs.rbx,
        4 => regs.frame.rsp, 5 => regs.rbp, 6 => regs.rsi, _ => regs.rdi,
    } as u32;
    if sz == 1 {
        match idx & 7 {
            0..=3 => full & 0xFF,            // al/cl/dl/bl
            _ => (match idx & 3 { 0 => regs.rax, 1 => regs.rcx, 2 => regs.rdx, _ => regs.rbx } >> 8) as u32 & 0xFF, // ah/ch/dh/bh
        }
    } else if sz == 2 { full & 0xFFFF } else { full }
}

fn set_gpr(regs: &mut Regs, idx: u8, sz: u32, val: u32) {
    fn slot(regs: &mut Regs, i: u8) -> &mut u64 {
        match i & 7 {
            0 => &mut regs.rax, 1 => &mut regs.rcx, 2 => &mut regs.rdx, 3 => &mut regs.rbx,
            4 => &mut regs.frame.rsp, 5 => &mut regs.rbp, 6 => &mut regs.rsi, _ => &mut regs.rdi,
        }
    }
    if sz == 1 {
        if idx & 4 == 0 {
            let r = slot(regs, idx & 3); *r = (*r & !0xFF) | (val as u64 & 0xFF);     // al/cl/dl/bl
        } else {
            let r = slot(regs, idx & 3); *r = (*r & !0xFF00) | ((val as u64 & 0xFF) << 8); // ah/ch/dh/bh
        }
    } else if sz == 2 {
        let r = slot(regs, idx); *r = (*r & !0xFFFF) | (val as u64 & 0xFFFF);
    } else {
        let r = slot(regs, idx); *r = val as u64; // 32-bit write zero-extends
    }
}

/// Write the six status flags (CF/PF/AF/ZF/SF/OF) for an ALU result of width
/// `sz` bytes, leaving the rest of EFLAGS untouched. CF/AF/OF are supplied by
/// the caller (they depend on the operation); PF (always the low byte), ZF, and
/// SF (the operand-width sign bit) derive from the result.
fn write_flags(regs: &mut Regs, res: u32, sz: u32, cf: bool, af: bool, of: bool) {
    const MASK: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    let msb = 1u32 << (sz * 8 - 1);
    let mut f = regs.frame.rflags & !MASK;
    if cf {
        f |= 1 << 0;
    } // CF
    if (res as u8).count_ones() & 1 == 0 {
        f |= 1 << 2;
    } // PF: parity of low byte
    if af {
        f |= 1 << 4;
    } // AF
    if res == 0 {
        f |= 1 << 6;
    } // ZF (res already masked)
    if res & msb != 0 {
        f |= 1 << 7;
    } // SF
    if of {
        f |= 1 << 11;
    } // OF
    regs.frame.rflags = f;
}

/// Compute an ALU op `a OP b` of width `sz` bytes (1/2/4), update EFLAGS, and
/// return the masked result. `alu` is the 3-bit selector from the primary opcode
/// group (0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP). Logical ops clear
/// CF/OF/AF per the x86 spec; the arithmetic ops follow the standard
/// borrow/overflow definitions. CMP computes a subtraction for flags but the
/// caller discards the returned value. Inputs/outputs are masked to `sz`.
fn alu(regs: &mut Regs, alu: u8, a: u32, b: u32, sz: u32) -> u32 {
    let bits = sz * 8;
    let mask = if sz == 4 {
        0xFFFF_FFFFu32
    } else {
        (1u32 << bits) - 1
    };
    let msb = 1u32 << (bits - 1);
    let (a, b) = (a & mask, b & mask);
    let cf_in = (regs.frame.rflags & 1) as u32;
    match alu {
        0 | 2 => {
            // ADD / ADC
            let c = if alu == 2 { cf_in } else { 0 };
            let sum = a as u64 + b as u64 + c as u64;
            let res = sum as u32 & mask;
            let cf = (sum >> bits) & 1 != 0;
            let af = (a & 0xF) + (b & 0xF) + c > 0xF;
            let of = (a ^ res) & (b ^ res) & msb != 0;
            write_flags(regs, res, sz, cf, af, of);
            res
        }
        3 | 5 | 7 => {
            // SBB / SUB / CMP
            let c = if alu == 3 { cf_in } else { 0 };
            let diff = a as i64 - b as i64 - c as i64;
            let res = diff as u32 & mask;
            let cf = (a as u64) < b as u64 + c as u64;
            let af = ((a & 0xF) as i32 - (b & 0xF) as i32 - c as i32) < 0;
            let of = (a ^ b) & (a ^ res) & msb != 0;
            write_flags(regs, res, sz, cf, af, of);
            res
        }
        _ => {
            // OR / AND / XOR — CF=OF=AF=0
            let res = (match alu {
                1 => a | b,
                4 => a & b,
                _ => a ^ b,
            }) & mask;
            write_flags(regs, res, sz, false, false, false);
            res
        }
    }
}

/// Length of the ModR/M + SIB + displacement that follows the opcode, given the
/// first ModR/M byte and the effective address size (32-bit when `addr32`).
fn modrm_len(modrm: u8, addr32: bool, peek: impl Fn(u32) -> u8, after: u32) -> u32 {
    let md = modrm >> 6;
    let rm = modrm & 7;
    let mut len = 1u32; // the ModR/M byte
    if addr32 {
        let mut sib_rm = rm;
        if rm == 4 { // SIB
            len += 1;
            sib_rm = peek(after + 1) & 7; // base
        }
        len += match md {
            0 => if rm == 5 || (rm == 4 && sib_rm == 5) { 4 } else { 0 },
            1 => 1,
            2 => 4,
            _ => 0, // register direct — not a memory operand (shouldn't fault)
        };
    } else {
        len += match md {
            0 => if rm == 6 { 2 } else { 0 },
            1 => 1,
            2 => 2,
            _ => 0,
        };
    }
    len
}

/// Decode and emulate the faulting A0000 access at offset `off`. `cs_base`/
/// `def32` (default operand & address size) are resolved by the caller, which
/// has the LDT. Returns false (→ real SEGV) for an instruction we don't model,
/// so a gap is loud rather than silent corruption.
#[allow(clippy::too_many_arguments)] // planar #PF decode needs the full seg/mode context
pub fn handle_planar_fault<A: crate::Arch>(machine: &mut A, regs: &mut Regs, vga: &mut VgaState, cs_base: u32, def32: bool, ds_base: u32, es_base: u32, off: u32) -> bool {
    let vm86 = regs.mode() == crate::UserMode::VM86;
    let ip0 = if def32 { regs.ip32() } else { regs.ip32() & 0xFFFF };
    // Pre-read the instruction (max 15 bytes) into a buffer so decoding doesn't
    // hold a borrow of `regs` while the emulation below mutates it.
    let mut buf = [0u8; 16];
    for k in 0..16u32 {
        buf[k as usize] = machine.read::<u8>((cs_base.wrapping_add(ip0).wrapping_add(k)) as usize);
    }
    let peek = |o: u32| -> u8 { buf[(o & 15) as usize] };

    // Prefixes.
    let mut i = 0u32;
    // Interruptible `rep`: a real CPU services pending interrupts between string
    // iterations. We emulate the whole `rep` in one kernel call, so cap it at
    // REP_CHUNK iterations per fault; if CX isn't drained, `not_done` leaves EIP
    // on the instruction so the guest re-faults to continue — and the event loop
    // delivers any pending timer IRQ between chunks. Without this a big keen-4
    // composite `rep movs` runs uninterruptibly, the owed ticks all fire at once
    // when it returns, and the guest's stack overflows.
    const REP_CHUNK: u32 = 2048;
    let mut not_done = false;
    let mut p66 = false;
    let mut p67 = false;
    let mut rep = false;
    // `repne` (F2) vs `repe` (F3) only matters for scas/cmps, which terminate on
    // ZF; for the unconditional string ops (movs/stos/lods) both just mean rep.
    let mut repne = false;
    loop {
        match peek(i) {
            0x66 => { p66 = true; i += 1; }
            0x67 => { p67 = true; i += 1; }
            0xF3 => { rep = true; i += 1; }
            0xF2 => { rep = true; repne = true; i += 1; }
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => { i += 1; } // seg override (base already in CR2)
            _ => break,
        }
    }
    let op32 = def32 ^ p66;
    let addr32 = def32 ^ p67;
    let opcode = peek(i);
    i += 1;

    match opcode {
        // mov r/m8, r8  — store AL-style
        0x88 => {
            let modrm = peek(i);
            let val = gpr(regs, (modrm >> 3) & 7, 1) as u8;
            i += modrm_len(modrm, addr32, peek, i);
            vram_write(vga, off, val);
        }
        // mov r/m16/32, r
        0x89 => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let val = gpr(regs, (modrm >> 3) & 7, sz);
            i += modrm_len(modrm, addr32, peek, i);
            for b in 0..sz { vram_write(vga, off + b, (val >> (b * 8)) as u8); }
        }
        // mov r8, r/m8 — load
        0x8A => {
            let modrm = peek(i);
            let v = vram_read(vga, off);
            set_gpr(regs, (modrm >> 3) & 7, 1, v as u32);
            i += modrm_len(modrm, addr32, peek, i);
        }
        // mov r16/32, r/m
        0x8B => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let mut v = 0u32;
            for b in 0..sz { v |= (vram_read(vga, off + b) as u32) << (b * 8); }
            set_gpr(regs, (modrm >> 3) & 7, sz, v);
            i += modrm_len(modrm, addr32, peek, i);
        }
        // mov AL/AX/EAX <-> moffs — the direct-offset accumulator forms. The
        // memory operand is the faulting window itself, so `off` is already the
        // VRAM offset; only the moffs immediate (addr-size wide) needs to be
        // consumed. Wolf3D's video detection reads `mov al, es:[0]` at A000:0
        // (opcode A0 with an ES override) and crashed here unhandled.
        0xA0 | 0xA1 => {
            let sz = opsize(op32, opcode == 0xA0);
            let mut v = 0u32;
            for b in 0..sz { v |= (vram_read(vga, off + b) as u32) << (b * 8); }
            set_gpr(regs, 0, sz, v);
            i += if addr32 { 4 } else { 2 };
        }
        0xA2 | 0xA3 => {
            let sz = opsize(op32, opcode == 0xA2);
            let val = gpr(regs, 0, sz);
            for b in 0..sz { vram_write(vga, off + b, (val >> (b * 8)) as u8); }
            i += if addr32 { 4 } else { 2 };
        }
        // mov r/m8, imm8
        0xC6 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, peek, i);
            let imm = peek(i + l);
            i += l + 1;
            vram_write(vga, off, imm);
        }
        // mov r/m16/32, imm16/32 — Keen clears VRAM with `mov word es:[di],0`.
        0xC7 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, peek, i);
            let sz = opsize(op32, false);
            let mut imm = 0u32;
            for b in 0..sz { imm |= (peek(i + l + b) as u32) << (b * 8); }
            i += l + sz;
            for b in 0..sz { vram_write(vga, off + b, (imm >> (b * 8)) as u8); }
        }
        // xchg r/m8, r8 — Keen 4's Galaxy engine does `xchg es:[di], al` to
        // touch planar VRAM: the read half loads the GC latches, the write half
        // stores AL through the EGA write path, in one instruction. x86 swap
        // semantics: reg gets the (GC-processed) read byte, VRAM gets reg's old
        // value written via `vram_write` (so map mask / write mode / latches all
        // apply). `vram_read` must run first — it loads the latches the write uses.
        0x86 => {
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            let regval = gpr(regs, ridx, 1) as u8;
            i += modrm_len(modrm, addr32, peek, i);
            let memval = vram_read(vga, off);
            vram_write(vga, off, regval);
            set_gpr(regs, ridx, 1, memval as u32);
        }
        // xchg r/m16/32, r — the word/dword form, byte-by-byte so each byte
        // loads its latch before the matching write (same as the `mov` group).
        0x87 => {
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            let sz = opsize(op32, false);
            let regval = gpr(regs, ridx, sz);
            i += modrm_len(modrm, addr32, peek, i);
            let mut memval = 0u32;
            for b in 0..sz {
                memval |= (vram_read(vga, off + b) as u32) << (b * 8);
                vram_write(vga, off + b, (regval >> (b * 8)) as u8);
            }
            set_gpr(regs, ridx, sz, memval);
        }
        // stos: store (E)AX to ES:DI, count in (E)CX if rep. AL/AX/EAX.
        0xAA | 0xAB => {
            let sz = opsize(op32, opcode == 0xAA);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let al = regs.rax as u32;
            let df = regs.frame.rflags & (1 << 10) != 0;
            for n in 0..chunk {
                let o = if df { off.wrapping_sub(n * sz) } else { off.wrapping_add(n * sz) };
                for b in 0..sz { vram_write(vga, o + b, (al >> (b * 8)) as u8); }
            }
            // Advance DI by the chunk; on `rep`, drop CX by the chunk and, if it
            // isn't drained, leave EIP on the instruction (`not_done`) to resume.
            let step = chunk * sz;
            let di = if df { regs.rdi.wrapping_sub(step as u64) } else { regs.rdi.wrapping_add(step as u64) };
            regs.rdi = if addr32 { di } else { (regs.rdi & !0xFFFF) | (di & 0xFFFF) };
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // lods: load DS:SI into the accumulator (AL/AX/EAX), count in (E)CX if
        // rep. The source (DS:SI) is the faulting A0000 window, so `off` is its
        // VRAM offset — mirror `stos`, but read through `vram_read` (which loads
        // the GC latches / honours read map & read mode) instead of writing. A
        // Keen 4 loop copies off-screen VRAM with `lodsb; stosb; add esi,stride`.
        // Only the final byte survives in the accumulator; intervening reads
        // still run so the latches end up as the real CPU would leave them.
        0xAC | 0xAD => {
            let sz = opsize(op32, opcode == 0xAC);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            // `rep lods` with CX=0 is a no-op — leave the accumulator untouched.
            for n in 0..chunk {
                let o = if df { off.wrapping_sub(n * sz) } else { off.wrapping_add(n * sz) };
                let mut val = 0u32;
                for b in 0..sz { val |= (vram_read(vga, o + b) as u32) << (b * 8); }
                set_gpr(regs, 0, sz, val);
            }
            let step = chunk * sz;
            let si = if df { regs.rsi.wrapping_sub(step as u64) } else { regs.rsi.wrapping_add(step as u64) };
            regs.rsi = if addr32 { si } else { (regs.rsi & !0xFFFF) | (si & 0xFFFF) };
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // movs: DS:SI -> ES:DI. Each operand may be normal RAM or the A0000
        // planar window, resolved per byte below. Recompute both ends from the
        // registers rather than trusting `off` — either operand can fault.
        //
        // A VRAM *source* (DS:SI in A0000) MUST go through `vram_read`, not a raw
        // `regs.read`: A0000 is mapped present=0 (the planar trap), so a direct
        // read page-faults in the kernel (Keen 4's Galaxy engine composites from
        // off-screen VRAM with `rep movs` and crashed here). `vram_read` also
        // loads the GC latches, making a VRAM→VRAM `movs` the correct EGA latch
        // copy. The common `mov al,[si]`/`mov [di],al` latch copy already works
        // via the 0x8A/0x88 handlers. Source (DS:(E)SI) and dest (ES:(E)DI) bases
        // are resolved by the caller (shift-by-4 in VM86, LDT in PM) so the same
        // path serves both: 32-bit-PM `rep movsd` is Doom's Mode-Y plane blit
        // under CWSDPMI/DOS4GW (broke "no graphics under UEFI" — passthrough hides
        // it).
        0xA4 | 0xA5 => {
            let sz = opsize(op32, opcode == 0xA4);
            let amask: u32 = if addr32 { 0xFFFF_FFFF } else { 0xFFFF };
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let mut si = regs.rsi as u32 & amask;
            let mut di = regs.rdi as u32 & amask;
            for _ in 0..chunk {
                for b in 0..sz {
                    let src = ds_base.wrapping_add(si).wrapping_add(b);
                    let dst = es_base.wrapping_add(di).wrapping_add(b);
                    // A VRAM source is the planar trap window (present=0): reading
                    // it with a raw `regs.read` page-faults in the kernel. Route it
                    // through `vram_read` — which also loads the GC latches, so a
                    // VRAM→VRAM `rep movs` (Keen's Galaxy engine composites screens
                    // from off-screen VRAM) is the correct EGA latch copy.
                    let byte = if (0xA0000..0xB0000).contains(&src) {
                        vram_read(vga, src - 0xA0000)
                    } else {
                        machine.read::<u8>(src as usize)
                    };
                    if (0xA0000..0xB0000).contains(&dst) {
                        vram_write(vga, dst - 0xA0000, byte);
                    } else {
                        machine.write::<u8>(dst as usize, byte);
                    }
                }
                if df { si = si.wrapping_sub(sz); di = di.wrapping_sub(sz); }
                else  { si = si.wrapping_add(sz); di = di.wrapping_add(sz); }
            }
            let step = chunk * sz;
            let adj = |v: u64| {
                let nv = if df { (v as u32).wrapping_sub(step) } else { (v as u32).wrapping_add(step) };
                if addr32 { nv as u64 } else { (v & !0xFFFF) | (nv as u64 & 0xFFFF) }
            };
            regs.rsi = adj(regs.rsi);
            regs.rdi = adj(regs.rdi);
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // scas: compare the accumulator (AL/AX/EAX) with ES:DI, set flags like
        // `cmp acc, [es:di]`, advance DI. The memory operand is the faulting
        // A0000 window (present=0), so `off` is its VRAM offset — read it through
        // `vram_read` (loads the GC latches), never a raw `regs.read`. A `repe`
        // (F3) / `repne` (F2) run also terminates on ZF, so it's chunked with an
        // early break when the ZF condition flips (unlike the unconditional
        // stos/movs). Used by DOS blitters to find a run boundary in VRAM.
        0xAE | 0xAF => {
            let sz = opsize(op32, opcode == 0xAE);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let acc = regs.rax as u32;
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let o = if df { off.wrapping_sub(done_n * sz) } else { off.wrapping_add(done_n * sz) };
                let mut mem = 0u32;
                for b in 0..sz { mem |= (vram_read(vga, o + b) as u32) << (b * 8); }
                alu(regs, 7, acc, mem, sz); // CMP acc, mem — flags only
                done_n += 1;
                if rep {
                    // repe (F3) continues while ZF=1; repne (F2) while ZF=0.
                    let zf = regs.frame.rflags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            let step = done_n * sz;
            let di = if df { regs.rdi.wrapping_sub(step as u64) } else { regs.rdi.wrapping_add(step as u64) };
            regs.rdi = if addr32 { di } else { (regs.rdi & !0xFFFF) | (di & 0xFFFF) };
            if rep {
                let rem = total - done_n;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                // Re-fault to resume only if the chunk cap (not the ZF condition)
                // stopped us with counts left.
                not_done = !stop && rem > 0;
            }
        }
        // cmps: compare DS:SI with ES:DI, set flags like `cmp [ds:si], [es:di]`,
        // advance both. Either operand may be in the A0000 window, so recompute
        // both ends from the registers (like `movs`) and route a VRAM operand
        // through `vram_read`. x86 sets flags from [DS:SI] - [ES:DI]. Same
        // `repe`/`repne` ZF termination as scas.
        0xA6 | 0xA7 => {
            let sz = opsize(op32, opcode == 0xA6);
            let amask: u32 = if addr32 { 0xFFFF_FFFF } else { 0xFFFF };
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let mut si = regs.rsi as u32 & amask;
            let mut di = regs.rdi as u32 & amask;
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let mut src1 = 0u32; // [DS:SI]
                let mut src2 = 0u32; // [ES:DI]
                for b in 0..sz {
                    let s = ds_base.wrapping_add(si).wrapping_add(b);
                    let d = es_base.wrapping_add(di).wrapping_add(b);
                    let sb = if (0xA0000..0xB0000).contains(&s) { vram_read(vga, s - 0xA0000) } else { machine.read::<u8>(s as usize) };
                    let db = if (0xA0000..0xB0000).contains(&d) { vram_read(vga, d - 0xA0000) } else { machine.read::<u8>(d as usize) };
                    src1 |= (sb as u32) << (b * 8);
                    src2 |= (db as u32) << (b * 8);
                }
                alu(regs, 7, src1, src2, sz); // CMP [si], [di] — flags only
                if df { si = si.wrapping_sub(sz); di = di.wrapping_sub(sz); }
                else  { si = si.wrapping_add(sz); di = di.wrapping_add(sz); }
                done_n += 1;
                if rep {
                    let zf = regs.frame.rflags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            let step = done_n * sz;
            let adj = |v: u64| {
                let nv = if df { (v as u32).wrapping_sub(step) } else { (v as u32).wrapping_add(step) };
                if addr32 { nv as u64 } else { (v & !0xFFFF) | (nv as u64 & 0xFFFF) }
            };
            regs.rsi = adj(regs.rsi);
            regs.rdi = adj(regs.rdi);
            if rep {
                let rem = total - done_n;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = !stop && rem > 0;
            }
        }
        // ALU with a VRAM operand: the primary-group r/m forms, all eight groups
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP, in both directions and widths. Opcode
        // low 3 bits select form: 0 = `OP r/m8,r8`, 1 = `OP r/m,r`,
        // 2 = `OP r8,r/m8`, 3 = `OP r,r/m`. Even ⇒ byte; the width of the
        // word/dword forms is `opsize(op32, …)`, so it follows the segment's
        // default operand size (16-bit VM86 / 32-bit PM) toggled by a 0x66
        // prefix — exactly like the `mov` arms. The VRAM read goes through
        // `vram_read` (loads the GC latches; read map / read mode honoured); a
        // write-back (every group but CMP, when r/m is the dest) goes through
        // `vram_write` (map mask / write mode / latches). Keen 4's masked-sprite
        // blit reads the screen with `and ax, es:[di]` (0x23) then merges;
        // Doom's Mode-X loop does `cmp byte [vram], dl`.
        op if op < 0x40 && (op & 0x07) < 4 => {
            let group = (op >> 3) & 7;
            let reg_is_dst = op & 0x02 != 0; // forms 2/3: reg <- reg OP [vram]
            let sz = opsize(op32, op & 1 == 0);
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let reg = gpr(regs, ridx, sz);
            let mut mem = 0u32;
            for b in 0..sz {
                mem |= (vram_read(vga, off + b) as u32) << (b * 8);
            }
            if reg_is_dst {
                let res = alu(regs, group, reg, mem, sz);
                if group != 7 {
                    set_gpr(regs, ridx, sz, res);
                } // CMP: flags only
            } else {
                let res = alu(regs, group, mem, reg, sz);
                if group != 7 {
                    // CMP: no write-back
                    for b in 0..sz {
                        vram_write(vga, off + b, (res >> (b * 8)) as u8);
                    }
                }
            }
        }
        // TEST r/m, r (0x84 byte, 0x85 word/dword): AND for flags only. Not
        // part of the group above — TEST has no ALU group number and never
        // writes back, so it is the one read-modify-*no*-write form. The VRAM
        // read still goes through `vram_read`, which loads the GC latches
        // exactly as a real read does. Xenon 2 tests its planar back buffer
        // with `es: test [di], bl` before merging a sprite.
        0x84 | 0x85 => {
            let sz = opsize(op32, opcode == 0x84);
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let reg = gpr(regs, ridx, sz);
            let mut mem = 0u32;
            for b in 0..sz {
                mem |= (vram_read(vga, off + b) as u32) << (b * 8);
            }
            alu(regs, 4, mem, reg, sz); // group 4 = AND, result discarded
        }
        // Grp1: the immediate forms of the ALU group above — ADD/OR/ADC/SBB/
        // AND/SUB/XOR/CMP r/m, imm (0x80 = byte, 0x81 = imm16/32, 0x83 =
        // sign-extended imm8; the group lives in ModRM bits 3-5). Same VRAM
        // read-modify-write path: the read loads the GC latches, the
        // write-back (every group but CMP) goes through the EGA write logic.
        // Operation Wolf clears its planar back buffer with
        // `and byte es:[di], 0`.
        0x80 | 0x81 | 0x83 => {
            let modrm = peek(i);
            let group = (modrm >> 3) & 7;
            let sz = if opcode == 0x80 { 1 } else { opsize(op32, false) };
            let l = modrm_len(modrm, addr32, peek, i);
            let immsz = if opcode == 0x81 { sz } else { 1 };
            let mut imm = 0u32;
            for b in 0..immsz { imm |= (peek(i + l + b) as u32) << (b * 8); }
            if opcode == 0x83 {
                imm = imm as u8 as i8 as i32 as u32; // sign-extend to operand size
                if sz == 2 { imm &= 0xFFFF; }
            }
            i += l + immsz;
            let mut mem = 0u32;
            for b in 0..sz { mem |= (vram_read(vga, off + b) as u32) << (b * 8); }
            let res = alu(regs, group, mem, imm, sz);
            if group != 7 {
                // CMP: flags only, no write-back
                for b in 0..sz { vram_write(vga, off + b, (res >> (b * 8)) as u8); }
            }
        }
        _ => {
            let _ = (rep, addr32);
            crate::println!(
                "  [planar #PF] unhandled opcode {:#04x} off={:#x} ip0={:#x} bytes={:02x?}",
                opcode,
                off,
                ip0,
                &buf[..]
            );
            return false;
        }
    }

    // Advance EIP past the emulated instruction — unless a `rep` was capped
    // mid-string (`not_done`), in which case leave EIP on the instruction so the
    // guest re-executes it (and re-faults) to finish the remaining CX, after the
    // event loop gets a chance to deliver any pending interrupt.
    let new_ip = if not_done { ip0 } else { ip0.wrapping_add(i) };
    let cur_ip = regs.ip32();
    if vm86 { regs.set_ip32((cur_ip & !0xFFFF) | (new_ip & 0xFFFF)); }
    else { regs.set_ip32(new_ip); }
    true
}

// ============================================================================
// Emulated display: render to the platform's present sink
// ============================================================================

/// Read a guest aperture (untrapped, scattered RAM) into `buf` and return it as
/// a slice — the one copy linear modes (mode 13h / text) can't avoid, since that
/// VRAM is guest memory the kernel can't address as a flat region.
/// Snapshot guest bytes `[lo, hi)` of the `len`-byte aperture at `addr` into
/// `buf`, which keeps the aperture's FULL length so the renderer's offsets are
/// the guest's own. Only the requested span is copied — the beam paints a band
/// per pass, and copying the whole aperture each time moved ~14x the bytes it
/// reads (64 KB per pass in mode 13h, megabytes in linear SVGA).
///
/// The buffer is resized only when the length changes: `clear()` + `resize()`
/// would memset every byte immediately before overwriting it.
fn read_aperture<'a, A: crate::Arch>(
    machine: &mut A, buf: &'a mut alloc::vec::Vec<u8>, addr: usize, len: usize,
    lo: usize, hi: usize,
) -> &'a [u8] {
    if buf.len() != len {
        buf.clear();
        buf.resize(len, 0);
    }
    let (lo, hi) = (lo.min(len), hi.min(len));
    if lo < hi {
        machine.copy_from(addr + lo, &mut buf[lo..hi]);
    }
    buf
}

impl VgaState {
    /// The mode the beam is about to scan, from the registers ALONE — no VRAM
    /// is read. Lets the caller size the band before the snapshot that band
    /// determines.
    fn current_mode(&self) -> Option<lib::vga_render::VgaMode> {
        if self.svga_w != 0 {
            let bpp8 = (self.svga_bpp as usize).div_ceil(8);
            return Some(lib::vga_render::VgaMode::LinearSvga {
                w: self.svga_w,
                h: self.svga_h,
                bpp: self.svga_bpp,
                pitch: (self.svga_w as usize * bpp8) as u16,
            });
        }
        self.classify_mode()
    }

    /// Build the displayed frame from the live registers + VRAM: resolve the
    /// mode, point at the video memory, and read the display-start / pixel pan /
    /// line-compare that select the visible window. Planar modes render our own
    /// `planes` in place (no copy); linear modes copy the `band` of their guest
    /// aperture the beam is about to paint into `scratch`. `None` for a mode the
    /// renderer doesn't draw.
    fn scanout<'a, A: crate::Arch>(
        &'a self, machine: &mut A, _regs: &Regs, scratch: &'a mut alloc::vec::Vec<u8>,
        band: (usize, usize),
    ) -> Option<lib::vga_render::Frame<'a>>
    {
        use lib::vga_render::{Frame, VgaMode};
        // VESA SVGA: present the kernel-side linear framebuffer directly. The
        // guest filled it through the banked 0xA0000 window; `display_tick`
        // flushes the live window into `svga_fb` just before this call.
        if self.svga_w != 0 {
            let bpp8 = (self.svga_bpp as usize).div_ceil(8);
            let pitch = self.svga_w as usize * bpp8;
            let size = pitch * self.svga_h as usize;
            return Some(Frame {
                mode: VgaMode::LinearSvga {
                    w: self.svga_w, h: self.svga_h, bpp: self.svga_bpp, pitch: pitch as u16,
                },
                // Linear rows: the band maps straight to a byte span.
                vram: read_aperture(machine, scratch, SVGA_LFB_BASE, size,
                    band.0 * pitch, (band.0 + band.1) * pitch),
                planes: &[],
                ac: &self.ac,
                palette: &self.dac,
                dac_mask: self.dac_mask,
                font: &lib::vga_fonts::FONT_8X16,
                blink: false,
                cga_palette: [0; 4],
                start_offset: 0,
                pixel_pan: 0,
                line_compare: usize::MAX,
            });
        }
        let mode = self.classify_mode()?;
        let (w, h) = lib::vga_render::dimensions(mode);
        // Mode 13h's rows are linear but not contiguous: a panned display-start
        // (screen-shake) slides the origin forward, and below Line Compare the
        // latch resets to 0 — so walk the band's rows the way `row_origin`
        // does and take the span they cover. The buffer stays a full 64 KB
        // window, only the copy shrinks.
        let m13_span = || {
            let start = (((self.crtc[0x0C] as usize) << 8) | self.crtc[0x0D] as usize) * 4;
            let pan = (self.ac[0x13] & 0x07) as usize;
            let lc = self.line_compare(h);
            let (mut lo, mut hi) = (usize::MAX, 0usize);
            for r in band.0..band.0 + band.1 {
                let base = if r >= lc { (r - lc) * w } else { start + r * w + pan };
                lo = lo.min(base);
                hi = hi.max(base + w);
            }
            if lo > hi { (0, 0) } else { (lo, hi) }
        };
        let (vram, planes): (&[u8], &[u8]) = match mode {
            VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } => (&[], &self.planes),
            VgaMode::Mode13h => {
                let (lo, hi) = m13_span();
                (read_aperture(machine, scratch, 0xA0000, 0x10000, lo, hi), &[])
            }
            // 4 KB and 16 KB apertures: banding them would buy back less than
            // the per-row address arithmetic (CGA's two interleaved banks) costs.
            VgaMode::Text80x25 => (read_aperture(machine, scratch, 0xB8000, 80 * 25 * 2, 0, 80 * 25 * 2), &[]),
            VgaMode::Cga4 | VgaMode::Cga2 => (read_aperture(machine, scratch, 0xB8000, 0x4000, 0, 0x4000), &[]),
            VgaMode::LinearSvga { .. } => (&[], &[]), // handled by the short-circuit above
        };
        // Display-start (page-flip front buffer), pixel pan (smooth scroll) and
        // line-compare (split-screen) apply to the planar families and to linear
        // Mode 13h. The display-start latch is in word units for the planar
        // modes (per-plane byte offset) but the address counter runs in
        // doubleword mode under 13h, so each latch step is 4 linear pixels.
        let planar = matches!(mode, VgaMode::Planar16 { .. } | VgaMode::ModeX { .. });
        let mode13 = matches!(mode, VgaMode::Mode13h);
        let start_latch = ((self.crtc[0x0C] as usize) << 8) | self.crtc[0x0D] as usize;
        // CGA palettes come from the Mode-Control/Colour-Select registers. The
        // 640×200 2-colour mode's foreground is the Colour-Select low nibble
        // (background black); the 320×200 4-colour set is the register-resolved
        // palette. Other modes ignore this field.
        let cga_palette = match mode {
            VgaMode::Cga4 => lib::vga_render::cga4_palette(self.cga_mode_ctl, self.cga_color_select),
            VgaMode::Cga2 => [0x000000, lib::vga_render::CGA16[(self.cga_color_select & 0x0F) as usize], 0, 0],
            _ => [0; 4],
        };
        Some(Frame {
            mode,
            vram,
            planes,
            ac: &self.ac,
            palette: &self.dac,
            dac_mask: self.dac_mask,
            font: &lib::vga_fonts::FONT_8X16,
            blink: self.ac[0x10] & 0x08 != 0,
            cga_palette,
            start_offset: if planar { start_latch } else if mode13 { start_latch * 4 } else { 0 },
            pixel_pan: if planar || mode13 { (self.ac[0x13] & 0x07) as usize } else { 0 },
            line_compare: if planar || mode13 { self.line_compare(h) } else { usize::MAX },
        })
    }

    /// Resolve the renderable mode from the live registers — nothing else.
    /// The substitute BIOS programs the canonical register file on every
    /// mode set (`bios_mode_regs`), so `classify` always sees coherent
    /// state: a BIOS-set mode reads back exactly as on real hardware, and a
    /// tweaker's register writes (Doom's unchain, Jazz's wide-stride level,
    /// Dyna Blaster's 256×232) land on top of that base.
    fn classify_mode(&self) -> Option<lib::vga_render::VgaMode> {
        use lib::vga_render;
        let rregs = vga_render::Regs { crtc: self.crtc, seq: self.seq, gc: self.gc, misc: self.misc_output };
        vga_render::classify(&rregs)
    }

    /// CRTC Line Compare (0x18 + overflow bits 8/9): the scanline where the
    /// lower split-screen region restarts from address 0 (the locked status
    /// panel). All-ones ⇒ no split; converted through the same max-scanline
    /// divisor as mode height to match `h`.
    fn line_compare(&self, h: usize) -> usize {
        let lc = self.crtc[0x18] as usize
            | (((self.crtc[7] >> 4) & 1) as usize) << 8
            | (((self.crtc[9] >> 6) & 1) as usize) << 9;
        let scan_div = ((self.crtc[9] as usize & 0x1F) + 1)
            * if self.crtc[9] & 0x80 != 0 { 2 } else { 1 };
        let lc = lc / scan_div.max(1);
        if lc < h { lc } else { usize::MAX }
    }
}

/// Whole-frame throttle for the hosted window sink, off the same tick clock
/// the 0x3DA vertical-retrace fabrication reads. The direct-framebuffer path
/// does not use this: its render/publish state machine owns that cadence.
fn frame_due(now_ticks: u64, hz: u64) -> bool {
    let frame = (now_ticks.wrapping_mul(hz) / 1000) as u32;
    static LAST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    LAST.swap(frame, Ordering::Relaxed) != frame
}

/// Render the emulated VGA's displayed frame to the platform present sink (the
/// GOP framebuffer on UEFI metal, the window/screenshot mailbox on hosted).
/// Free when a real card scans out directly or no sink is installed.
pub fn display_tick<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &Regs, now_ticks: u64) {
    use lib::vga_render;
    let (display_kind, direct) = if let Some(display) = pc.vga.display() {
        (
            display.kind(),
            match display {
                crate::kernel::platform::DisplayToken::Framebuffer(fb) => Some(*fb),
                _ => None,
            },
        )
    } else {
        let Some(display) = crate::kernel::osd::display() else { return };
        (
            display.kind(),
            match display {
                crate::kernel::platform::DisplayToken::Framebuffer(fb) => Some(*fb),
                _ => None,
            },
        )
    };
    if display_kind == crate::kernel::platform::Display::VgaCard {
        if crate::kernel::osd::is_open() {
            display_native_osd(machine, pc, regs, now_ticks);
        }
        return;
    }
    // A real card scans out its own memory — nothing to do. Otherwise we need
    // somewhere to put the frame: a framebuffer we write into, or a window
    // sink. (This used to test only the sink; when fbcon stopped registering
    // one, every metal frame silently returned here.)
    let host_window = match display_kind {
        crate::kernel::platform::Display::Framebuffer => false,
        crate::kernel::platform::Display::HostWindow => true,
        crate::kernel::platform::Display::Headless => return,
        crate::kernel::platform::Display::VgaCard => unreachable!(),
    };
    if pc.vga.is_native() {
        return;
    }
    let prof = crate::kernel::startup::profile_enabled();
    if let Some(fb) = direct {
        // Direct framebuffer: phase zero is guest-visible retrace. Its
        // trailing edge renders one complete immutable shadow; the following
        // tick publishes that shadow to GOP. Rendering and device traffic get
        // separate budgets, and the physical scanout is the only visible
        // top-to-bottom sweep.
        let period_ticks: usize = if fb.slow { 50 } else { 14 };
        let Some(mode) = pc.vga.current_mode() else { return };
        match crate::kernel::display::scanout_action(
            &mut pc.present_scratch2, &fb, mode, now_ticks, period_ticks,
        ) {
            crate::kernel::display::ScanoutAction::None => {}
            crate::kernel::display::ScanoutAction::Render => {
                let p0 = if prof { machine.rdtsc() } else { 0 };
                let full = (0, vga_render::dimensions(mode).1);
                // The source aperture, registers and DAC are captured once for
                // the whole shadow; no palette generation can split the image.
                let Some(frame) =
                    pc.vga.scanout(machine, regs, &mut pc.present_scratch, full)
                else {
                    return;
                };
                let p1 = if prof { machine.rdtsc() } else { 0 };
                let rendered = crate::kernel::display::render_shadow(
                    &mut pc.present_scratch2, &fb, &frame,
                );
                if prof {
                    let p2 = machine.rdtsc();
                    crate::kernel::startup::bill_display(
                        frame.mode,
                        p1.wrapping_sub(p0),
                        rendered as u64,
                        p2.wrapping_sub(p1),
                        0,
                        0,
                    );
                }
            }
            crate::kernel::display::ScanoutAction::Publish => {
                let (vga_h, out_w, shadow) =
                    crate::kernel::display::completed_shadow(&mut pc.present_scratch2)
                        .expect("ready VGA shadow is missing");
                if crate::kernel::osd::is_open() {
                    let vga_w = vga_render::dimensions(mode).0;
                    crate::kernel::osd::paint(
                        shadow,
                        out_w * fb.format.bytes_per_pixel as usize,
                        out_w,
                        vga_h,
                        vga_w,
                        fb.format,
                    );
                }
                let p0 = if prof { machine.rdtsc() } else { 0 };
                let copied = crate::kernel::display::present(&fb, vga_h, shadow);
                let present_cycles = if prof {
                    machine.rdtsc().wrapping_sub(p0)
                } else {
                    0
                };
                crate::kernel::startup::bill_present();
                if prof {
                    crate::kernel::startup::bill_display(
                        mode, 0, 0, 0, present_cycles, copied,
                    );
                }
            }
        }
        return;
    }
    // Window sink (hosted): still takes a whole rendered frame per period.
    if !host_window || !frame_due(now_ticks, 70) {
        return;
    }
    crate::kernel::startup::bill_present();
    let p0 = if prof { machine.rdtsc() } else { 0 };
    // Whole-frame sink: `render` walks every row, so capture the full frame.
    let full = pc.vga.current_mode().map_or((0, 0), |m| (0, vga_render::dimensions(m).1));
    let Some(frame) = pc.vga.scanout(machine, regs, &mut pc.present_scratch, full) else { return };
    let p1 = if prof { machine.rdtsc() } else { 0 };
    let (w, h) = vga_render::dimensions(frame.mode);
    let need = w * h;
    if pc.present_fb.len() < need {
        pc.present_fb.resize(need, 0);
    }
    let fb = &mut pc.present_fb[..need];
    vga_render::render(&frame, fb);
    if crate::kernel::osd::is_open() {
        // `render` writes native 0x00RRGGBB into a tightly-packed w×h buffer.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(fb.as_mut_ptr() as *mut u8, fb.len() * 4)
        };
        crate::kernel::osd::paint(
            bytes, w * 4, w, h, w, vga_render::PixelFormat::NATIVE,
        );
    }
    let p2 = if prof { machine.rdtsc() } else { 0 };
    pc.present_fb.truncate(need);
    crate::kernel::display::present_host(w, h, &mut pc.present_fb);
    if prof {
        let p3 = machine.rdtsc();
        crate::kernel::startup::bill_display(
            frame.mode, p1.wrapping_sub(p0), 1, p2.wrapping_sub(p1),
            p3.wrapping_sub(p2), need);
    }
}

fn display_native_osd<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    regs: &Regs,
    now_ticks: u64,
) {
    // Native OSD presentation is substantially more expensive than ordinary
    // card scanout: the running guest must be rendered to RGB, scaled,
    // quantized into the OSD palette, then copied through the VGA aperture.
    // Doing all of that at the card's 70 Hz cadence starves the guest and its
    // audio clock. Keep the live preview at 10 Hz, with immediate frames for
    // menu input; the guest and mixer still advance on every normal tick.
    static LAST_MS: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(u32::MAX);
    let now = now_ticks as u32;
    let forced = crate::kernel::osd::take_repaint_request();
    let last = LAST_MS.load(Ordering::Relaxed);
    if !forced && now.wrapping_sub(last) < 100 {
        return;
    }
    LAST_MS.store(now, Ordering::Relaxed);
    let Some(mode) = pc.vga.current_mode() else { return };
    let (w, h) = lib::vga_render::dimensions(mode);
    let full = (0, h);
    let Some(frame) =
        pc.vga.scanout(machine, regs, &mut pc.present_scratch, full)
    else {
        return;
    };
    let need = w * h;
    if pc.present_fb.len() < need {
        pc.present_fb.resize(need, 0);
    }
    lib::vga_render::render(&frame, &mut pc.present_fb[..need]);
    crate::kernel::osd::present_native(&pc.present_fb[..need], w, h);
}
