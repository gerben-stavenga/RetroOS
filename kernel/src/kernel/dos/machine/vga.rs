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
    // ── VESA SVGA (banked) ──
    /// Active VBE mode geometry; `svga_w == 0` ⇒ not in an SVGA mode. The
    /// framebuffer lives in `svga_fb` (kernel-side, not guest VRAM); the guest
    /// reaches it through the banked 0xA0000 window, flushed in/out per `4F05`.
    pub svga_w: u16,
    pub svga_h: u16,
    pub svga_bpp: u8,
    /// Current window-A bank (64 KB granule) the 0xA0000 window maps.
    pub svga_bank: u16,
    /// The full linear SVGA framebuffer (`pitch*h` bytes), presented directly.
    pub svga_fb: alloc::vec::Vec<u8>,
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
            svga_w: 0,
            svga_h: 0,
            svga_bpp: 0,
            svga_bank: 0,
            svga_fb: alloc::vec::Vec::new(),
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

use core::sync::atomic::{AtomicU8, Ordering};

/// Which plane the guest A0000 window currently aliases (0..3), or 0xFF when
/// A0000 is plain linear RAM (chained mode 13h / text — not planar).
static A0000_TARGET: AtomicU8 = AtomicU8::new(0xFF);

/// The emulated VGA's plane memory: 4 planes × 64 KB, byte (plane `p`, offset
/// `off`) at `[p*0x10000 + off]`. Lives per-thread on `VgaState::planes` (the
/// focus-owned model) — the same buffer `save_from_hardware` fills for a real
/// card — so the planar trap and the renderer touch it directly, no global and
/// no per-frame copy.
const PLANES_LEN: usize = 4 * 0x10000;
const A0000: usize = 0xA0000;

/// True while a guest is in unchained planar graphics (A0000 aliases a plane).
pub fn planar_active() -> bool {
    A0000_TARGET.load(Ordering::Relaxed) != 0xFF
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
                arm_planar(machine, &mut pc.vga, Some(&chained));
            } else if !unchained && currently_planar {
                disarm_planar(machine, &pc.vga, regs, true);
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
fn arm_planar(machine: &mut crate::TheArch, vga: &mut VgaState, seed: Option<&[u8]>) {
    if vga.planes.len() != PLANES_LEN {
        vga.planes = alloc::vec![0u8; PLANES_LEN];
    }
    match seed {
        Some(chained) => lib::vga_render::chain4_split(chained, &mut vga.planes),
        None => vga.planes.fill(0),
    }
    machine.map_phys_range(A0000 >> 12, 16, 0, arch_abi::MAP_MMIO);
    A0000_TARGET.store(0, Ordering::Relaxed); // 0 != 0xFF ⇒ planar_active()
}

/// Tear down the planar trap: map A0000 back to plain RAM. `merge`: interleave
/// the planes back into a linear A0000 image first (the Mode-X unchain→chain
/// hop, which expects the 13h view preserved); skip it when simply leaving
/// graphics for text (the next mode-set clears the screen anyway).
fn disarm_planar(machine: &mut crate::TheArch, vga: &VgaState, regs: &mut Vcpu, merge: bool) {
    machine.map_fresh_range(A0000 >> 12, 16);
    if merge {
        let mut chained = alloc::vec![0u8; 0x10000];
        lib::vga_render::chain4_merge(&vga.planes, &mut chained);
        regs.copy_to(A0000, &chained);
    }
    A0000_TARGET.store(0xFF, Ordering::Relaxed);
}

// ============================================================================
// VESA SVGA (banked). A real-mode guest reaches the multi-MB framebuffer only
// through the 64 KB window at 0xA0000, switching banks via VBE 4F05h. We keep
// the whole framebuffer kernel-side (`vga.svga_fb`) and use 0xA0000 as plain
// RAM staging: a bank switch flushes the live window to its bank and loads the
// requested one. This avoids the page-alias refcount churn `copy_page_entries`
// would cause on every (frequent) bank switch.
// ============================================================================

/// Bytes in one 64 KB VBE window granule.
const SVGA_WINDOW: usize = 0x10000;

/// Enter a banked SVGA mode: allocate the framebuffer and give 0xA0000 a clean
/// 64 KB RAM staging window. Called from INT 10h AX=4F02h.
pub fn svga_set_mode(machine: &mut crate::TheArch, pc: &mut PcMachine, w: u16, h: u16, bpp: u8) {
    let bpp8 = (bpp as usize + 7) / 8;
    pc.vga.svga_fb = alloc::vec![0u8; w as usize * h as usize * bpp8];
    pc.vga.svga_w = w;
    pc.vga.svga_h = h;
    pc.vga.svga_bpp = bpp;
    pc.vga.svga_bank = 0;
    // Plain RAM staging window; also clears any stale planar trap marker (a VBE
    // set-mode bypasses on_set_mode, so Mode-X state could otherwise linger).
    machine.map_fresh_range(A0000 >> 12, SVGA_WINDOW >> 12);
    A0000_TARGET.store(0xFF, Ordering::Relaxed);
}

/// Copy the live 0xA0000 window into the current bank of `svga_fb`.
pub fn svga_flush_window(pc: &mut PcMachine, regs: &Vcpu) {
    if pc.vga.svga_w == 0 {
        return;
    }
    let start = pc.vga.svga_bank as usize * SVGA_WINDOW;
    let n = SVGA_WINDOW.min(pc.vga.svga_fb.len().saturating_sub(start));
    if n > 0 {
        regs.copy_from(A0000, &mut pc.vga.svga_fb[start..start + n]);
    }
}

/// VBE 4F05h window control: flush the current window to its bank, then page the
/// requested bank's bytes into the window (so guest read-backs see them).
pub fn svga_set_bank(pc: &mut PcMachine, regs: &mut Vcpu, bank: u16) {
    if pc.vga.svga_w == 0 {
        return;
    }
    svga_flush_window(pc, regs);
    pc.vga.svga_bank = bank;
    let start = bank as usize * SVGA_WINDOW;
    let n = SVGA_WINDOW.min(pc.vga.svga_fb.len().saturating_sub(start));
    if n > 0 {
        regs.copy_to(A0000, &pc.vga.svga_fb[start..start + n]);
    }
}

/// Leave SVGA back to a standard VGA mode: drop the framebuffer. The caller's
/// mode-set re-backs 0xA0000 (text/graphics) as usual.
pub fn svga_leave(pc: &mut PcMachine) {
    pc.vga.svga_w = 0;
    pc.vga.svga_h = 0;
    pc.vga.svga_bpp = 0;
    pc.vga.svga_bank = 0;
    pc.vga.svga_fb = alloc::vec::Vec::new();
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
    // A standard mode-set leaves any active VESA SVGA mode.
    svga_leave(pc);
    // The IBM BIOS programs CRTC line-compare to its no-split default (0x3FF) on
    // every mode set; our BIOS leaves the CRTC untouched. Without this a program
    // that page-flips but never writes 0x18 (Doom relies on the BIOS default)
    // inherits a stale 0, and the renderer splits the whole screen to address 0
    // (page 0) — the screen renders page 0 for every row. A split-status-panel
    // program overwrites these afterward (it must, the default being 0x3FF).
    pc.vga.crtc[0x18] = 0xFF; // line-compare bits 0..7
    pc.vga.crtc[7] |= 0x10;   // line-compare bit 8 (CRTC overflow)
    pc.vga.crtc[9] |= 0x40;   // line-compare bit 9 (CRTC max-scan-line)
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
        // Standard EGA AC palettes. In 200-line compatibility modes, brown uses
        // value 0x06 because green's secondary bit is the RGBI intensity bit; in
        // normal 350/480-line modes it uses the full-EGA brown value 0x14.
        const EGA_AC_NORMAL: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];
        const EGA_AC_200LINE: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
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
    let currently = planar_active();
    if planar && !currently {
        arm_planar(machine, &mut pc.vga, None); // fresh mode-set ⇒ zeroed planes
    } else if planar && currently && clear {
        // Re-set the same planar mode: keep the trap, just blank the planes.
        pc.vga.planes.fill(0);
    } else if !planar && currently {
        disarm_planar(machine, &pc.vga, regs, false); // leaving planar ⇒ A0000 back to RAM
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

/// Write the six status flags (CF/PF/AF/ZF/SF/OF) for an ALU result of width
/// `sz` bytes, leaving the rest of EFLAGS untouched. CF/AF/OF are supplied by
/// the caller (they depend on the operation); PF (always the low byte), ZF, and
/// SF (the operand-width sign bit) derive from the result.
fn write_flags(regs: &mut Vcpu, res: u32, sz: u32, cf: bool, af: bool, of: bool) {
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
fn alu(regs: &mut Vcpu, alu: u8, a: u32, b: u32, sz: u32) -> u32 {
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
pub fn handle_planar_fault(regs: &mut Vcpu, vga: &mut VgaState, cs_base: u32, def32: bool, ds_base: u32, es_base: u32, off: u32) -> bool {
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
            vram_write(vga, off, val);
        }
        // mov r/m16/32, r
        0x89 => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let val = gpr(regs, (modrm >> 3) & 7, sz);
            i += modrm_len(modrm, addr32, &peek, i);
            for b in 0..sz { vram_write(vga, off + b, (val >> (b * 8)) as u8); }
        }
        // mov r8, r/m8 — load
        0x8A => {
            let modrm = peek(i);
            let v = vram_read(vga, off);
            set_gpr(regs, (modrm >> 3) & 7, 1, v as u32);
            i += modrm_len(modrm, addr32, &peek, i);
        }
        // mov r16/32, r/m
        0x8B => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let mut v = 0u32;
            for b in 0..sz { v |= (vram_read(vga, off + b) as u32) << (b * 8); }
            set_gpr(regs, (modrm >> 3) & 7, sz, v);
            i += modrm_len(modrm, addr32, &peek, i);
        }
        // mov r/m8, imm8
        0xC6 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, &peek, i);
            let imm = peek(i + l);
            i += l + 1;
            vram_write(vga, off, imm);
        }
        // mov r/m16/32, imm16/32 — Keen clears VRAM with `mov word es:[di],0`.
        0xC7 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, &peek, i);
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
            i += modrm_len(modrm, addr32, &peek, i);
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
            i += modrm_len(modrm, addr32, &peek, i);
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
                        regs.read::<u8>(src as usize)
                    };
                    if (0xA0000..0xB0000).contains(&dst) {
                        vram_write(vga, dst - 0xA0000, byte);
                    } else {
                        regs.write::<u8>(dst as usize, byte);
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
            i += modrm_len(modrm, addr32, &peek, i);
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
fn read_aperture<'a>(regs: &Vcpu, buf: &'a mut alloc::vec::Vec<u8>, addr: usize, len: usize) -> &'a [u8] {
    buf.clear();
    buf.resize(len, 0);
    regs.copy_from(addr, buf);
    buf
}

impl VgaState {
    /// Build the displayed frame from the live registers + VRAM: resolve the
    /// mode, point at the video memory, and read the display-start / pixel pan /
    /// line-compare that select the visible window. Planar modes render our own
    /// `planes` in place (no copy); linear modes copy their guest aperture into
    /// `scratch`. `None` for a mode the renderer doesn't draw.
    fn scanout<'a>(&'a self, regs: &Vcpu, scratch: &'a mut alloc::vec::Vec<u8>)
        -> Option<lib::vga_render::Frame<'a>>
    {
        use lib::vga_render::{Frame, VgaMode};
        // VESA SVGA: present the kernel-side linear framebuffer directly. The
        // guest filled it through the banked 0xA0000 window; `display_tick`
        // flushes the live window into `svga_fb` just before this call.
        if self.svga_w != 0 {
            let bpp8 = (self.svga_bpp as usize + 7) / 8;
            let pitch = self.svga_w as usize * bpp8;
            return Some(Frame {
                mode: VgaMode::LinearSvga {
                    w: self.svga_w, h: self.svga_h, bpp: self.svga_bpp, pitch: pitch as u16,
                },
                vram: &self.svga_fb,
                planes: &[],
                ac: &self.ac,
                palette: &self.dac,
                font: &lib::vga_font_8x16::FONT_8X16,
                blink: false,
                start_offset: 0,
                pixel_pan: 0,
                line_compare: usize::MAX,
            });
        }
        let mode = self.classify_mode(regs)?;
        let (w, h) = lib::vga_render::dimensions(mode);
        let (vram, planes): (&[u8], &[u8]) = match mode {
            VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } => (&[], &self.planes),
            // Read the whole 64 KB window, not just w*h: a panned display-start
            // (screen-shake) slides the scanout origin forward, so the visible
            // window can reach past the nominal 320×200 = 64000 bytes.
            VgaMode::Mode13h => (read_aperture(regs, scratch, 0xA0000, 0x10000), &[]),
            VgaMode::Text80x25 => (read_aperture(regs, scratch, 0xB8000, 80 * 25 * 2), &[]),
            VgaMode::Cga4 | VgaMode::Cga2 => (read_aperture(regs, scratch, 0xB8000, 0x4000), &[]),
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
        Some(Frame {
            mode,
            vram,
            planes,
            ac: &self.ac,
            palette: &self.dac,
            font: &lib::vga_font_8x16::FONT_8X16,
            blink: self.ac[0x10] & 0x08 != 0,
            start_offset: if planar { start_latch } else if mode13 { start_latch * 4 } else { 0 },
            pixel_pan: if planar || mode13 { (self.ac[0x13] & 0x07) as usize } else { 0 },
            line_compare: if planar || mode13 { self.line_compare(h) } else { usize::MAX },
        })
    }

    /// Resolve the renderable mode from the live registers. An explicit unchain
    /// (SEQ chain-4 cleared, tracked by `planar_active`) is the authoritative
    /// Mode-Y signal `classify` can't see — our BIOS leaves the GC graphics bit
    /// unprogrammed, so an unchained SEQ reads like the BIOS default; Doom lands
    /// here and its resolution comes from the CRTC it programmed. Otherwise
    /// defer to `classify`, honouring the CRTC Offset as the in-memory row
    /// stride for smooth-scrollers (Keen's wide virtual screen).
    fn classify_mode(&self, regs: &Vcpu) -> Option<lib::vga_render::VgaMode> {
        use lib::vga_render::{self, VgaMode};
        let bda_mode = regs.read::<u8>(0x449);
        if planar_active() && bda_mode == 0x13 {
            let row_bytes = if self.crtc[0x13] != 0 { self.crtc[0x13] as u16 * 2 } else { 80 };
            let v_end = self.crtc[0x12] as u16
                | (((self.crtc[7] >> 1) & 1) as u16) << 8
                | (((self.crtc[7] >> 6) & 1) as u16) << 9;
            let mut h = v_end + 1;
            if self.crtc[9] & 0x80 != 0 { h /= 2; }
            // Mode-Y games keep the BIOS mode-13h CRTC our BIOS never wrote
            // (v-end ~0); fall back to the 320×200 default.
            if h < 64 || h > 480 { h = 200; }
            return Some(VgaMode::ModeX { w: row_bytes * 4, h, row_bytes });
        }
        let rregs = vga_render::Regs { crtc: self.crtc, seq: self.seq, gc: self.gc, misc: self.misc_output };
        match vga_render::classify(bda_mode, &rregs)? {
            VgaMode::Planar16 { w, h, row_bytes } => {
                let stride = if self.crtc[0x13] != 0 { self.crtc[0x13] as u16 * 2 } else { row_bytes };
                Some(VgaMode::Planar16 { w, h, row_bytes: stride })
            }
            m => Some(m),
        }
    }

    /// CRTC Line Compare (0x18 + overflow bits 8/9): the scanline where the
    /// lower split-screen region restarts from address 0 (the locked status
    /// panel). All-ones ⇒ no split; halved under double-scan to match `h`.
    fn line_compare(&self, h: usize) -> usize {
        let lc = self.crtc[0x18] as usize
            | (((self.crtc[7] >> 4) & 1) as usize) << 8
            | (((self.crtc[9] >> 6) & 1) as usize) << 9;
        let lc = if self.crtc[9] & 0x80 != 0 { lc / 2 } else { lc };
        if lc < h { lc } else { usize::MAX }
    }
}

/// VGA refresh throttle: true at most once per ~70 Hz emulated frame, off the
/// same tick clock the 0x3DA vertical-retrace fabrication reads.
fn frame_due(now_ticks: u64) -> bool {
    let frame = (now_ticks.wrapping_mul(70) / 1000) as u32;
    static LAST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    LAST.swap(frame, Ordering::Relaxed) != frame
}

/// Render the emulated VGA's displayed frame to the platform present sink (the
/// GOP framebuffer on UEFI metal, the window/screenshot mailbox on hosted).
/// Free when a real card scans out directly or no sink is installed.
pub fn display_tick(pc: &mut PcMachine, regs: &Vcpu, now_ticks: u64) {
    use lib::vga_render;
    if vga_present() || !vga_render::present_sink_installed() {
        return;
    }
    if !frame_due(now_ticks) {
        return;
    }
    // SVGA: capture the live 0xA0000 window into the framebuffer before present.
    if pc.vga.svga_w != 0 {
        svga_flush_window(pc, regs);
    }
    let mut scratch = alloc::vec::Vec::new();
    let Some(frame) = pc.vga.scanout(regs, &mut scratch) else { return };
    let (w, h) = vga_render::dimensions(frame.mode);
    let mut fb = alloc::vec![0u32; w * h];
    vga_render::render(&frame, &mut fb);
    vga_render::present(w, h, &fb);
}
