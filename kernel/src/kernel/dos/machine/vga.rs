//! Virtual VGA register state (Attribute Controller + CRTC/sequencer snapshot)
//! — and, when no card is present, the *emulated* VGA itself: the same
//! register file becomes the live model behind `emulate_inb`/`emulate_outb`,
//! and `display_tick` renders the screen through the shared `lib::vga_render`
//! to the platform's present sink. One VGA, emulated once, kernel-side; the
//! backends only supply a framebuffer.

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
pub fn vga_present() -> bool {
    crate::kernel::platform::get().display.vga_passthrough()
}

// ============================================================================
// VGA register state (AcState + VgaState)
// ============================================================================

/// VGA Attribute Controller port (0x3C0) state. The hardware has two
/// independent pieces of state, neither readable from any port:
///   - `index`:        last byte written in index state. Includes the PAS bit
///                     (bit 5) which controls screen blanking. Persistent —
///                     subsequent data writes do not change it.
///   - `pending_data`: flip-flop position. `false` = next 0x3C0 write is an
///                     index byte; `true` = next 0x3C0 write is its data.
/// `inb(0x3DA)` clears `pending_data` (resets the flipflop to index state).
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
            seq: [0; 5],
            crtc: [0; 25],
            gc: [0; 9],
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
        }
    }

    /// Emulated register-file write — the absent-card half of the VGA
    /// passthrough-vs-emulate split (`PcMachine::vga_present == false`).
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

    /// Read current VGA hardware state into this struct. Callers gate on
    /// `PcMachine::vga_present` — with no card the per-thread struct already
    /// *is* the live state (see `port_write`) and there is nothing to save.
    pub fn save_from_hardware(&mut self) {
        use crate::arch::{inb, outb};
        if self.planes.is_empty() {
            self.planes = alloc::vec![0u8; 4 * 65536];
        }
        // Capture tracked AC state, then reset flipflop to known index state.
        self.ac_state = unsafe { VGA_AC_STATE };
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
        self.dac_mask = inb(0x3C6);
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

        crate::dbg_println!("VGA save: seq4={:02X} gc5={:02X} gc6={:02X} crtc14={:02X} crtc17={:02X} ac10={:02X} misc={:02X} start={:04X}",
            self.seq[4], self.gc[5], self.gc[6], self.crtc[0x14], self.crtc[0x17], self.ac[0x10], self.misc_output,
            (self.crtc[0x0C] as u16) << 8 | self.crtc[0x0D] as u16);

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

        // KNOWN GAP: GC read latches (4 bytes loaded by the most recent VGA
        // memory read) are not preserved across save/restore. The bulk reads
        // below clobber them, and the VGA exposes no port to read latches
        // directly — the only way to extract them is to dump them to memory
        // via write mode 1 and read them back, which would require sacrificing
        // 4 bytes of plane RAM at a fixed scratch offset (any prior read to
        // capture that user data would itself destroy the latches we want).
        //
        // Symptom: a mode-X latch blit preempted between its source read and
        // destination write produces 4 wrong bytes when the program resumes:
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

    /// Write this struct's state to VGA hardware. Callers gate on
    /// `PcMachine::vga_present` (see `save_from_hardware`).
    pub fn restore_to_hardware(&self) {
        if self.planes.is_empty() { return; }
        use crate::arch::{inb, outb};

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
// Emulated display: render to the platform's present sink
// ============================================================================

/// Render the emulated VGA's screen and hand it to the platform present sink
/// (`lib::vga_render::set_present_sink` — the GOP framebuffer on UEFI metal,
/// the window/screenshot frame mailbox on hosted). Called from the event
/// loop on PIT-tick cadence; free when a real card displays directly or no
/// sink is installed.
///
/// The mode comes from BDA 0x449 (set by the personality BIOS INT 10h AH=00)
/// — direct-register mode sets aren't derived yet, and planar/mode-X needs
/// VRAM trapping; both match the limitations of the interp renderer this
/// replaces.
pub fn display_tick(pc: &mut PcMachine, regs: &Vcpu, ticks: u32) {
    use lib::vga_render::{self, Frame, VgaMode};
    if vga_present() || !vga_render::present_sink_installed() {
        return;
    }
    // Frame-rate divider: ticks arrive at the PIT rate (1000 Hz kernel
    // default), and a render per tick saturates the event loop — the UEFI
    // mock spent 99% CPU rendering and starved guest execution to ~50
    // port-ins/sec. 50 ticks ≈ 20 fps.
    static ACCUM: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let due = ACCUM.fetch_add(ticks, core::sync::atomic::Ordering::Relaxed) + ticks >= 50;
    if !due {
        return;
    }
    ACCUM.store(0, core::sync::atomic::Ordering::Relaxed);
    // Classify from the live VGA registers (Mode X reprograms them while the
    // BDA byte still reads 0x13); the BDA byte only disambiguates the linear
    // 256-colour families. `None` = a mode the renderer doesn't draw.
    let v = &pc.vga;
    let rregs = vga_render::Regs {
        crtc: v.crtc,
        seq: v.seq,
        gc: v.gc,
        misc: v.misc_output,
    };
    let Some(mode) = vga_render::classify(regs.read::<u8>(0x449), &rregs) else {
        return;
    };
    let (w, h) = vga_render::dimensions(mode);
    // Linear modes read a guest memory window; planar modes read the VGA plane
    // model (filled by the VRAM-trap write path — empty until a guest draws).
    let linear = match mode {
        VgaMode::Mode13h => Some((0xA0000usize, w * h)),
        VgaMode::Text80x25 => Some((0xB8000usize, 80 * 25 * 2)),
        VgaMode::Cga4 | VgaMode::Cga2 => Some((0xB8000usize, 0x4000)),
        VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } => None,
    };
    let mut vram = alloc::vec![0u8; 0];
    if let Some((base, len)) = linear {
        vram = alloc::vec![0u8; len];
        regs.copy_from(base, &mut vram);
    }
    let frame = Frame {
        mode,
        vram: &vram,
        planes: &pc.vga.planes,
        ac: &pc.vga.ac,
        palette: &pc.vga.dac,
        font: &lib::vga_font_8x16::FONT_8X16,
        blink: pc.vga.ac[0x10] & 0x08 != 0,
    };
    let mut fb = alloc::vec![0u32; w * h];
    vga_render::render(&frame, &mut fb);
    vga_render::present(w, h, &fb);
}
