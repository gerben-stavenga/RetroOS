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
    /// VGA read latches: the 4 plane bytes loaded by the most recent VRAM read
    /// (one per plane). Write mode 1 (latched copy) writes these straight
    /// through; write modes 0/2/3 ALU the new value against them. Only used on
    /// the trapped planar write path (see `vram_write`/`vram_read`).
    pub latches: [u8; 4],
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
// Emulated VGA planar VRAM (paging-aliased planes)
// ============================================================================
//
// Planar/Mode-X graphics route a single CPU store to A0000 through the VGA's
// plane logic into 1-4 of the 4 planes — the result is not what lands in
// linear RAM, so it must be modelled at write time. We do it metal-natively
// with paging, no per-write trap: the 4 planes are physical frames; A0000 is
// page-aliased onto the active plane (CPU writes land there directly); the
// renderer reads all 4 planes through a kernel-private guest-VA window. On the
// chain↔unchain hop the chained (mode-13h linear) content is synced into/out
// of the planes (chain4 split/merge). Single-plane access (all Mode X, simple
// EGA) is pure alias; EGA multi-plane set/reset fan-out is the not-yet-handled
// fallback. Interp emulates the same paging; metal does it in page tables.

use core::sync::atomic::{AtomicUsize, AtomicU8, Ordering};

/// 4 plane frames × 64K. 0 = not yet allocated (the singleton VGA VRAM, lazily
/// created the first time a guest unchains into planar graphics).
static VRAM_BASE: AtomicUsize = AtomicUsize::new(0);
/// Which plane the guest A0000 window currently aliases (0..3), or 0xFF when
/// A0000 is plain linear RAM (chained mode 13h / text — not planar).
static A0000_TARGET: AtomicU8 = AtomicU8::new(0xFF);

const NUM_PLANE_FRAMES: usize = 4 * 16; // 256K
/// Kernel-private guest-VA window mapping all 4 planes contiguously; the
/// renderer reads it via `copy_from`. Below the interp's 3GB reservation and
/// far above any DOS/DPMI usage, so it never collides with the guest.
const VRAM_WINDOW: usize = 0x8000_0000;
const A0000: usize = 0xA0000;

/// True while a guest is in unchained planar graphics (A0000 aliases a plane).
pub fn planar_active() -> bool {
    A0000_TARGET.load(Ordering::Relaxed) != 0xFF
}

fn vram_base(machine: &mut crate::TheArch) -> u64 {
    let base = VRAM_BASE.load(Ordering::Relaxed);
    if base != 0 {
        return base as u64;
    }
    let base = machine.alloc_phys_contig(NUM_PLANE_FRAMES, 0);
    machine.map_phys_range(VRAM_WINDOW >> 12, NUM_PLANE_FRAMES, base, 0);
    VRAM_BASE.store(base as usize, Ordering::Relaxed);
    base
}

/// React to a Sequencer register write (port 0x3C5) that may change the
/// chain-4 mode or the plane-select mask. Drives the A0000 paging alias.
/// `pc.vga` already holds the post-write register values.
pub fn on_seq_write(machine: &mut crate::TheArch, pc: &mut PcMachine, regs: &mut Vcpu) {
    if vga_present() {
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
            let currently_planar = planar_active();
            if unchained && !currently_planar {
                let mut chained = alloc::vec![0u8; 0x10000];
                regs.copy_from(A0000, &mut chained);
                arm_planar(machine, regs, Some(&chained));
            } else if !unchained && currently_planar {
                disarm_planar(machine, regs, true);
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

/// Stand up the 4-plane window and map A0000 as MMIO (present=0 + trap marker)
/// so every guest store/load into A0000 faults into `handle_planar_fault` — the
/// only way one CPU store can fan into 4 planes and honour the latches, write
/// modes, and map mask. The kernel owns the planes at `VRAM_WINDOW`; the
/// renderer reads those. `seed`: deinterleave an existing chained A0000 image
/// into the planes (the Mode-X chain→unchain hop), or `None` to zero them (a
/// fresh BIOS planar mode-set). Idempotent if already armed via the callers.
fn arm_planar(machine: &mut crate::TheArch, regs: &mut Vcpu, seed: Option<&[u8]>) {
    let _ = vram_base(machine); // ensure the plane window is allocated + mapped
    let mut planes = alloc::vec![0u8; NUM_PLANE_FRAMES * 4096];
    if let Some(chained) = seed {
        lib::vga_render::chain4_split(chained, &mut planes);
    }
    regs.copy_to(VRAM_WINDOW, &planes);
    machine.map_phys_range(A0000 >> 12, 16, 0, arch_abi::MAP_MMIO);
    A0000_TARGET.store(0, Ordering::Relaxed); // 0 != 0xFF ⇒ planar_active()
}

/// Tear down the planar trap: map A0000 back to plain RAM. `merge`: interleave
/// the planes back into a linear A0000 image first (the Mode-X unchain→chain
/// hop, which expects the 13h view preserved); skip it when simply leaving
/// graphics for text (the next mode-set clears the screen anyway).
fn disarm_planar(machine: &mut crate::TheArch, regs: &mut Vcpu, merge: bool) {
    let mut chained = alloc::vec![0u8; 0x10000];
    if merge {
        let mut planes = alloc::vec![0u8; NUM_PLANE_FRAMES * 4096];
        regs.copy_from(VRAM_WINDOW, &mut planes);
        lib::vga_render::chain4_merge(&planes, &mut chained);
    }
    machine.map_fresh_range(A0000 >> 12, 16);
    if merge {
        regs.copy_to(A0000, &chained);
    }
    A0000_TARGET.store(0xFF, Ordering::Relaxed);
}

/// React to a BIOS INT 10h AH=00 video mode set. The EGA/VGA 16-colour planar
/// family (0x0D–0x12, e.g. Commander Keen) draws through the 4 planes via the
/// map mask + write modes exactly like Mode X, but a game sets it via the BIOS
/// and never toggles the Sequencer chain-4 bit — so `on_seq_write` never fires
/// and the planar trap would stay disarmed, leaving the plane window empty
/// (a black screen). Arm it here on entry to a planar mode, and disarm on a
/// return to text/linear. `clear` (AL bit 7 clear) zeroes the planes.
pub fn on_set_mode(
    machine: &mut crate::TheArch,
    pc: &mut PcMachine,
    regs: &mut Vcpu,
    mode: u8,
    clear: bool,
) {
    if vga_present() {
        return; // a real card draws its own planes
    }
    let planar = matches!(mode, 0x0D..=0x12);
    if planar {
        // Load the standard EGA 16-colour Attribute Controller palette the IBM
        // BIOS programs on every planar mode set. Without it AC[0..15] are 0, so
        // every 4-bit pixel maps to DAC index 0 (black) — Keen never touches the
        // AC, relying on this default. Index i → i for 0..5, brown fixup at 6
        // (0x14), then the bright bank 0x38..0x3F for 8..15.
        const EGA_AC: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];
        pc.vga.ac[..16].copy_from_slice(&EGA_AC);
        pc.vga.ac[0x10] &= !0x80; // mode control: P4/P5 from palette, not colour-select
    }
    let currently = planar_active();
    if planar && !currently {
        arm_planar(machine, regs, None); // fresh mode-set ⇒ zeroed planes
    } else if planar && currently && clear {
        // Re-set the same planar mode: keep the trap, just blank the planes.
        let zero = alloc::vec![0u8; NUM_PLANE_FRAMES * 4096];
        regs.copy_to(VRAM_WINDOW, &zero);
    } else if !planar && currently {
        disarm_planar(machine, regs, false); // leaving planar ⇒ A0000 back to RAM
    }
}

/// Trapped planar VRAM write: run the Graphics Controller write-mode logic for a
/// CPU store of `byte` at A0000 offset `off`, fanning it into the 4 planes
/// (stored at `VRAM_WINDOW`). Used when the single-plane alias can't model the
/// access — write mode 1 (Mode X latched copy), write modes 2/3, or a
/// multi-plane EGA write. Latches must have been loaded by a prior `vram_read`.
pub fn vram_write(regs: &mut Vcpu, vga: &mut VgaState, off: u32, byte: u8) {
    let off = (off & 0xFFFF) as usize;
    let mut cur = [0u8; 4];
    for p in 0..4 {
        cur[p] = regs.read::<u8>(VRAM_WINDOW + p * 0x10000 + off);
    }
    let out = lib::vga_render::planar_write(cur, vga.latches, &vga.gc, vga.seq[2] & 0x0F, byte);
    for p in 0..4 {
        if out[p] != cur[p] {
            regs.write::<u8>(VRAM_WINDOW + p * 0x10000 + off, out[p]);
        }
    }
}

/// Trapped planar VRAM read: load the 4 latches from the planes at A0000 offset
/// `off` and return the byte the CPU sees (read map select, or color compare).
pub fn vram_read(regs: &mut Vcpu, vga: &mut VgaState, off: u32) -> u8 {
    let off = (off & 0xFFFF) as usize;
    let mut cur = [0u8; 4];
    for p in 0..4 {
        cur[p] = regs.read::<u8>(VRAM_WINDOW + p * 0x10000 + off);
    }
    let (data, latches) = lib::vga_render::planar_read(cur, &vga.gc);
    vga.latches = latches;
    data
}

// ============================================================================
// Planar #PF decode — the kernel-side trap (no arch involvement: A0000 is left
// unmapped while planar logic is needed, so the guest store/load faults, the
// *existing* PageFault event arrives, and we decode the faulting instruction
// here and emulate it through `vram_write`/`vram_read`).
// ============================================================================

/// Width of the data a string/mov op moves (bytes).
fn opsize(prefix66: bool, byte_op: bool) -> u32 {
    if byte_op { 1 } else if prefix66 { 2 } else { 4 }
}

/// Read/write an integer GP register by encoding `idx` and size `sz` (bytes).
/// Maps the x86 register order (0=A,1=C,2=D,3=B,4=SP/AH..,5=BP/CH,6=SI,7=DI).
fn gpr(regs: &mut Vcpu, idx: u8, sz: u32) -> u32 {
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

fn set_gpr(regs: &mut Vcpu, idx: u8, sz: u32, val: u32) {
    fn slot(regs: &mut Vcpu, i: u8) -> &mut u64 {
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
pub fn handle_planar_fault(regs: &mut Vcpu, vga: &mut VgaState, cs_base: u32, def32: bool, off: u32) -> bool {
    let vm86 = regs.mode() == crate::UserMode::VM86;
    let ip0 = if def32 { regs.ip32() } else { regs.ip32() & 0xFFFF };
    // Pre-read the instruction (max 15 bytes) into a buffer so decoding doesn't
    // hold a borrow of `regs` while the emulation below mutates it.
    let mut buf = [0u8; 16];
    for k in 0..16u32 {
        buf[k as usize] = regs.read::<u8>((cs_base.wrapping_add(ip0).wrapping_add(k)) as usize);
    }
    let peek = |o: u32| -> u8 { buf[(o & 15) as usize] };

    // Prefixes.
    let mut i = 0u32;
    let mut p66 = false;
    let mut p67 = false;
    let mut rep = false;
    loop {
        match peek(i) {
            0x66 => { p66 = true; i += 1; }
            0x67 => { p67 = true; i += 1; }
            0xF2 | 0xF3 => { rep = true; i += 1; }
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
            i += modrm_len(modrm, addr32, &peek, i);
            vram_write(regs, vga, off, val);
        }
        // mov r/m16/32, r
        0x89 => {
            let modrm = peek(i);
            let sz = opsize(p66, false);
            let val = gpr(regs, (modrm >> 3) & 7, sz);
            i += modrm_len(modrm, addr32, &peek, i);
            for b in 0..sz { vram_write(regs, vga, off + b, (val >> (b * 8)) as u8); }
        }
        // mov r8, r/m8 — load
        0x8A => {
            let modrm = peek(i);
            let v = vram_read(regs, vga, off);
            set_gpr(regs, (modrm >> 3) & 7, 1, v as u32);
            i += modrm_len(modrm, addr32, &peek, i);
        }
        // mov r16/32, r/m
        0x8B => {
            let modrm = peek(i);
            let sz = opsize(p66, false);
            let mut v = 0u32;
            for b in 0..sz { v |= (vram_read(regs, vga, off + b) as u32) << (b * 8); }
            set_gpr(regs, (modrm >> 3) & 7, sz, v);
            i += modrm_len(modrm, addr32, &peek, i);
        }
        // mov r/m8, imm8
        0xC6 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, &peek, i);
            let imm = peek(i + l);
            i += l + 1;
            vram_write(regs, vga, off, imm);
        }
        // stos: store (E)AX to ES:DI, count in (E)CX if rep. AL/AX/EAX.
        0xAA | 0xAB => {
            let sz = opsize(p66, opcode == 0xAA);
            let count = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }).max(1) } else { 1 };
            let al = regs.rax as u32;
            let df = regs.frame.rflags & (1 << 10) != 0;
            for n in 0..count {
                let o = if df { off.wrapping_sub(n * sz) } else { off.wrapping_add(n * sz) };
                for b in 0..sz { vram_write(regs, vga, o + b, (al >> (b * 8)) as u8); }
            }
            // Advance DI/CX like the CPU would.
            let step = count * sz;
            let di = if df { regs.rdi.wrapping_sub(step as u64) } else { regs.rdi.wrapping_add(step as u64) };
            regs.rdi = if addr32 { di } else { (regs.rdi & !0xFFFF) | (di & 0xFFFF) };
            if rep { regs.rcx = if addr32 { 0 } else { regs.rcx & !0xFFFF }; }
        }
        // movs: DS:SI -> ES:DI, the write to ES:DI (in A0000) faults. The source
        // (DS:SI) is normal RAM for the common blit-to-VRAM pattern (Epic
        // Pinball); read it directly and write the destination through the
        // planar logic. (VM86 only — a PM movs would need the source segment's
        // LDT base, which isn't plumbed here; it falls through to a real fault.)
        0xA4 | 0xA5 if !def32 => {
            let sz = opsize(p66, opcode == 0xA4);
            let count = if rep { gpr(regs, 1, 2).max(1) } else { 1 };
            let df = regs.frame.rflags & (1 << 10) != 0;
            let ds_base = (regs.ds as u32) << 4; // VM86 DS:SI source
            let mut si = regs.rsi as u32 & 0xFFFF;
            let mut dst = off;
            for _ in 0..count {
                for b in 0..sz {
                    let byte = regs.read::<u8>(ds_base.wrapping_add(si).wrapping_add(b) as usize);
                    vram_write(regs, vga, dst.wrapping_add(b), byte);
                }
                if df { si = si.wrapping_sub(sz); dst = dst.wrapping_sub(sz); }
                else  { si = si.wrapping_add(sz); dst = dst.wrapping_add(sz); }
            }
            let step = count * sz;
            let adj = |v: u64| if df { (v as u32).wrapping_sub(step) } else { (v as u32).wrapping_add(step) } as u64;
            regs.rsi = (regs.rsi & !0xFFFF) | (adj(regs.rsi) & 0xFFFF);
            regs.rdi = (regs.rdi & !0xFFFF) | (adj(regs.rdi) & 0xFFFF);
            if rep { regs.rcx &= !0xFFFF; }
        }
        _ => {
            let _ = (rep, addr32);
            return false;
        }
    }

    // Advance EIP past the emulated instruction.
    let new_ip = ip0.wrapping_add(i);
    let cur_ip = regs.ip32();
    if vm86 { regs.set_ip32((cur_ip & !0xFFFF) | (new_ip & 0xFFFF)); }
    else { regs.set_ip32(new_ip); }
    let _ = op32;
    true
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
    // An explicit unchain (a guest writing the SEQ chain-4 bit, tracked by the
    // A0000 alias) is the authoritative Mode X signal — `classify` can't see it
    // because our BIOS leaves the GC graphics bit unprogrammed and an
    // unprogrammed SEQ reads the same as a deliberate unchain. Doom (Mode Y,
    // 320×200 unchained) lands here. Resolution comes from the CRTC the game
    // programmed (offset → row bytes; vertical-display-end → height). Only when
    // the BDA still reads 256-colour 0x13: the planar trap is ALSO armed for the
    // EGA 16-colour family (0x0D/0x0E/0x10, Keen), where the BDA names the mode
    // and `classify` resolves the (different) pixel format correctly.
    let bda_mode = regs.read::<u8>(0x449);
    let mode = if planar_active() && bda_mode == 0x13 {
        let row_bytes = if v.crtc[0x13] != 0 { v.crtc[0x13] as u16 * 2 } else { 80 };
        let v_end = v.crtc[0x12] as u16
            | (((v.crtc[7] >> 1) & 1) as u16) << 8
            | (((v.crtc[7] >> 6) & 1) as u16) << 9;
        let mut h = v_end + 1;
        if v.crtc[9] & 0x80 != 0 { h /= 2; }
        // The CRTC vertical-end is meaningful only if the game (re)programmed
        // it; Mode Y games (Doom) keep the BIOS mode-13h CRTC our BIOS never
        // wrote, leaving it ~0. Fall back to the 320×200 Mode Y default.
        if h < 64 || h > 480 { h = 200; }
        VgaMode::ModeX { w: row_bytes * 4, h, row_bytes }
    } else {
        match vga_render::classify(bda_mode, &rregs) {
            // The visible width is the BIOS mode's (classify_bda gives 320/640),
            // but the in-memory ROW STRIDE is the CRTC Offset register (0x13,
            // counted in words). A smooth-scroller (Commander Keen) sets a
            // virtual screen far wider than the 320-px display and pans a window
            // across it; rendering at the mode's nominal 40-byte stride shears
            // the image into stripes. Honour the programmed offset when the
            // guest set one (a plain non-scrolling EGA program leaves it 0).
            Some(VgaMode::Planar16 { w, h, row_bytes }) => {
                let stride = if v.crtc[0x13] != 0 { v.crtc[0x13] as u16 * 2 } else { row_bytes };
                VgaMode::Planar16 { w, h, row_bytes: stride }
            }
            Some(m) => m,
            None => return,
        }
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
    // Planar/Mode-X read all 4 planes from the kernel-private VRAM window (the
    // guest filled them through the A0000 plane alias); empty otherwise.
    let mut planes = alloc::vec![0u8; 0];
    if matches!(mode, VgaMode::Planar16 { .. } | VgaMode::ModeX { .. }) && VRAM_BASE.load(Ordering::Relaxed) != 0 {
        planes = alloc::vec![0u8; NUM_PLANE_FRAMES * 4096];
        regs.copy_from(VRAM_WINDOW, &mut planes);
    }
    // Display Start Address (CRTC 0x0C high, 0x0D low) selects the planar
    // front buffer for page-flipping games; only meaningful in planar modes.
    let start_offset = match mode {
        VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } =>
            ((pc.vga.crtc[0x0C] as usize) << 8) | pc.vga.crtc[0x0D] as usize,
        _ => 0,
    };
    // Horizontal Pixel Panning (AC 0x13, bits 0-3): the fine sub-byte shift for
    // smooth scrolling, paired with the coarse start address above.
    let pixel_pan = match mode {
        VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } => (pc.vga.ac[0x13] & 0x07) as usize,
        _ => 0,
    };
    let frame = Frame {
        mode,
        vram: &vram,
        planes: &planes,
        ac: &pc.vga.ac,
        palette: &pc.vga.dac,
        font: &lib::vga_font_8x16::FONT_8X16,
        blink: pc.vga.ac[0x10] & 0x08 != 0,
        start_offset,
        pixel_pan,
    };
    let mut fb = alloc::vec![0u32; w * h];
    vga_render::render(&frame, &mut fb);
    vga_render::present(w, h, &fb);
}
