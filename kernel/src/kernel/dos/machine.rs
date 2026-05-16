//! PC machine virtualization — the shared "PC age" machine model that both
//! the DOS and DPMI personalities run on top of.
//!
//! This module is policy-free: it owns the per-thread virtual peripherals
//! (8259 PIC, 8253 PIT, PS/2 keyboard, VGA register set), A20 gate state,
//! HMA page tracking, and the primitive helpers that decode/execute the
//! handful of sensitive instructions that trap through the GP fault monitor
//! (I/O, CLI/STI, IRET, PUSHF/POPF, stack push/pop).
//!
//! Personalities call into this module; machine never calls back out.
//! The two personalities (`vm86` for DOS real-mode, `dpmi` for protected
//! mode) provide their own GP fault monitors that dispatch software INTs
//! to their own handlers, but the opcode decode and I/O emulation all
//! route through the primitives here.

extern crate alloc;

use crate::Regs;

pub const IF_FLAG: u32 = 1 << 9;
pub const IOPL_MASK: u32 = 3 << 12;
/// IOPL=1 — kernel-set value for VM86 threads. With IOPL<3 and VME,
/// CLI/STI/PUSHF/POPF/INT/IRET virtualize through VIF instead of touching
/// real IF, which is exactly what the cooperative IRQ-injection model
/// needs. IOPL=0 would also virtualize but trap on a few extras; IOPL=3
/// would let the guest manipulate real IF and bypass the gate.
pub const IOPL_VM86: u32 = 1 << 12;
pub const VM_FLAG: u32 = 1 << 17;

pub const NT_FLAG: u32 = 1 << 14;
/// Flags that user code cannot change (IOPL, VM, NT)
pub const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG | NT_FLAG;

/// HMA spans 16 pages (64KB) starting at page 0x100.
const HMA_PAGE: usize = 0x100;
const HMA_PAGE_COUNT: usize = 16;
/// Shadow region for A20 gate: swap HMA entries here when A20 is off.
const HMA_SHADOW_PAGE: usize = HMA_PAGE + HMA_PAGE_COUNT;

// ============================================================================
// VM86 register helpers — 16-bit views of the 32-bit user frame
// ============================================================================

#[inline]
pub fn vm86_cs(regs: &Regs) -> u16 {
    regs.code_seg()
}

#[inline]
pub fn vm86_ip(regs: &Regs) -> u16 {
    regs.ip32() as u16
}

#[inline]
pub fn vm86_ss(regs: &Regs) -> u16 {
    regs.stack_seg()
}

#[inline]
pub fn vm86_sp(regs: &Regs) -> u16 {
    regs.sp32() as u16
}

#[inline]
pub fn vm86_flags(regs: &Regs) -> u32 {
    regs.flags32()
}

#[inline]
pub fn set_vm86_cs(regs: &mut Regs, cs: u16) {
    regs.set_cs32(cs as u32);
}

#[inline]
pub fn set_vm86_ip(regs: &mut Regs, ip: u16) {
    regs.set_ip32(ip as u32);
}

#[inline]
pub fn set_vm86_sp(regs: &mut Regs, sp: u16) {
    let full = (regs.sp32() & 0xFFFF_0000) | sp as u32;
    regs.set_sp32(full);
}

#[inline]
pub fn set_vm86_flags(regs: &mut Regs, flags: u32) {
    // Merge low 16 bits (user-visible flags), preserve upper EFLAGS (VM, IOPL, VIF, VIP).
    regs.frame.rflags = (regs.frame.rflags & !0xFFFF) | (flags as u64 & 0xFFFF);
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
static mut VGA_AC_STATE: AcState = AcState::new();

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
}

impl VgaState {
    pub fn new() -> Self {
        Self {
            planes: alloc::vec::Vec::new(),
            misc_output: 0,
            feature_ctl: 0,
            seq: [0; 5],
            crtc: [0; 25],
            gc: [0; 9],
            ac: [0; 21],
            dac: [0; 768],
            dac_mask: 0xFF,
            seq_index: 0,
            crtc_index: 0,
            gc_index: 0,
            ac_state: AcState::new(),
            dac_index: 0,
            dac_state: 0,
        }
    }

    /// Read current VGA hardware state into this struct.
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
        // The window is 1–2 instructions wide so the hit rate is very low,
        // and the visible artifact (one bad 4-byte stripe in one frame) is
        // typically invisible. Left unfixed; revisit if we ever observe it.
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

    /// Write this struct's state to VGA hardware.
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
// PcMachine — per-thread machine state
// ============================================================================
// Virtual 8237 DMA controller (generic — not SB-specific)
// ============================================================================
//
// A DOS program programs the 8237 with a *DOS-physical* buffer address,
// but runs paged in VM86, so the real DMA engine would fetch the wrong
// memory. We capture every channel's programming here; the SB-DMA layer
// (see [`SbDmaState`]) later translates the BLASTER-declared channel onto
// the real card's channel by remapping the guest buffer contiguous.
//
// Two cascaded controllers: #1 = 8-bit channels 0-3 (ports 0x00-0x0F),
// #2 = 16-bit channels 4-7 (ports 0xC0-0xDF, register stride ×2). Page
// registers live in the 0x80-0x8F block. Address/count are 16-bit,
// loaded low-then-high through a per-controller byte-pointer flip-flop.

/// One DMA channel's programmed state (what we need to locate and size
/// the transfer in Slice 3): `addr`/`count` are in bytes for 8-bit
/// channels, in *words* for 16-bit channels (8237 quirk).
#[derive(Clone, Copy, Default)]
pub struct DmaChannel {
    pub addr: u16,    // base address register (offset within its page)
    pub count: u16,   // base count register (transfer length − 1)
    pub page: u8,     // page register (high address bits)
    pub mode: u8,     // mode register byte (transfer type, auto-init…)
    pub masked: bool, // channel masked (DRQ ignored) — starts masked
}

/// Generic virtual 8237 pair. Indexed by absolute channel 0..7.
#[derive(Clone, Copy)]
pub struct Dma8237 {
    pub ch: [DmaChannel; 8],
    ff_lo: bool, // controller #1 (ch0-3) byte-pointer flip-flop
    ff_hi: bool, // controller #2 (ch4-7) byte-pointer flip-flop
    /// Per-channel count-program generation: bumped each time the guest
    /// finishes writing a channel's 16-bit count register. This is the
    /// reliable "(re)arm a transfer" signal — a single-cycle SB driver
    /// rewrites count every block (even to the same value), auto-init
    /// writes it once. The SB-DMA layer reprograms the real 8237 when
    /// this changes, independent of mask/unmask.
    pub count_gen: [u32; 8],
}

/// Standard PC/AT page-register port → absolute channel. 0x8F is the
/// refresh page (ch4 is the cascade channel, never used for transfers).
const DMA_PAGE_PORT: [(u16, usize); 7] = [
    (0x87, 0), (0x83, 1), (0x81, 2), (0x82, 3),
    (0x8B, 5), (0x89, 6), (0x8A, 7),
];

impl Dma8237 {
    pub fn new() -> Self {
        // Channels power up masked until the guest clears the mask.
        let mut ch = [DmaChannel::default(); 8];
        for c in &mut ch { c.masked = true; }
        Self { ch, ff_lo: false, ff_hi: false, count_gen: [0; 8] }
    }

    /// True if `port` (already 10-bit-folded) belongs to the 8237.
    pub fn owns(port: u16) -> bool {
        matches!(port, 0x00..=0x0F | 0xC0..=0xDF)
            || DMA_PAGE_PORT.iter().any(|&(p, _)| p == port)
    }

    fn ff(&mut self, hi: bool) -> &mut bool {
        if hi { &mut self.ff_hi } else { &mut self.ff_lo }
    }

    pub fn io_write(&mut self, port: u16, val: u8) {
        // Page registers.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            self.ch[chan].page = val;
            return;
        }
        let hi = port >= 0xC0;
        // Normalize controller #2's ×2 register stride to 0..0x0F.
        let reg = if hi { ((port - 0xC0) >> 1) as u16 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                let ff = self.ff(hi);
                let flip = *ff;
                *ff = !*ff;
                let r = if is_count { &mut self.ch[chan].count }
                        else { &mut self.ch[chan].addr };
                if !flip { *r = (*r & 0xFF00) | val as u16; }
                else     { *r = (*r & 0x00FF) | ((val as u16) << 8); }
                // High byte of a count write completes the 16-bit count:
                // that's the (re)arm signal for this channel.
                if is_count && flip {
                    self.count_gen[chan] = self.count_gen[chan].wrapping_add(1);
                }
            }
            0x0B => { // mode: bits0-1 = channel
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].mode = val;
            }
            0x0A => { // single mask: bits0-1 channel, bit2 = mask/unmask
                let chan = chan_base + (val & 0x03) as usize;
                self.ch[chan].masked = val & 0x04 != 0;
            }
            0x0C => { *self.ff(hi) = false; } // clear byte-pointer flip-flop
            0x0D => { // master clear: reset controller, all channels masked
                *self.ff(hi) = false;
                for c in chan_base..chan_base + 4 { self.ch[c].masked = true; }
            }
            0x0E => { for c in chan_base..chan_base + 4 { self.ch[c].masked = false; } }
            0x0F => { // write all mask bits (bits0-3 → the 4 channels)
                for i in 0..4 { self.ch[chan_base + i].masked = val & (1 << i) != 0; }
            }
            _ => {} // command/request regs: not needed by the SB path
        }
    }

    pub fn io_read(&mut self, port: u16) -> u8 {
        // Page registers read back the latched value.
        if let Some(&(_, chan)) = DMA_PAGE_PORT.iter().find(|&&(p, _)| p == port) {
            return self.ch[chan].page;
        }
        let hi = port >= 0xC0;
        let reg = if hi { ((port - 0xC0) >> 1) as u16 } else { port };
        let chan_base = if hi { 4 } else { 0 };
        match reg {
            0x00..=0x07 => {
                let chan = chan_base + (reg >> 1) as usize;
                let is_count = reg & 1 == 1;
                let v = if is_count { self.ch[chan].count } else { self.ch[chan].addr };
                let ff = self.ff(hi);
                let byte = if !*ff { v as u8 } else { (v >> 8) as u8 };
                *ff = !*ff;
                byte
            }
            0x08 => 0x00, // status: no TC, no requests pending in our model
            _ => 0xFF,
        }
    }
}

/// Per-thread Sound Blaster DMA state: the BLASTER-declared channel/IRQ
/// map plus the generic virtual 8237. The card itself (DSP/mixer/OPL3/
/// EMU8000) is pure passthrough; only this DMA indirection is virtual.
/// Slice 3 fills the remap binding; Slice 4 the IRQ relay.
pub struct SbDmaState {
    pub io_base: u16, // BLASTER A — DSP/mixer port base (passthrough target)
    pub irq: u8,      // BLASTER I — guest vPIC IRQ to inject on SB completion
    pub dma8: u8,     // BLASTER D — guest's 8-bit vDMA channel (0..3)
    pub dma16: u8,    // BLASTER H — guest's 16-bit vDMA channel (5..7)
    /// Real DMA channels QEMU's SB16 is wired to (`-device sb16,dma=`/
    /// `dma16=`; defaults 1/5). Independent of the guest's BLASTER —
    /// a guest channel-D transfer must drive *these* on the real 8237.
    pub host_dma8: u8,
    pub host_dma16: u8,
    pub dma: Dma8237, // generic virtual controller shadow
    // Remap binding: the contiguous phys run the guest buffer was moved
    // to, kept alive across blocks (auto-init reuses it; single-cycle
    // re-arms reuse it). Freed only when the buffer addr/len changes.
    pub remap_start_page: u64,
    pub remap_pages: usize,
    /// Buffer (DOS-phys addr, byte length) the current binding covers.
    last_gpa: u32,
    last_len: u32,
    /// Per-channel `count_gen` last acted on. The real 8237 is
    /// (re)programmed exactly when the guest bumps a channel's count
    /// generation (its per-block re-arm), not on mask/unmask — handles
    /// single-cycle drivers that re-arm without masking.
    last_gen: [u32; 8],
}

impl SbDmaState {
    /// Defaults match a stock SB16/AWE64: A220 I5 D1 H5.
    pub fn new() -> Self {
        Self {
            io_base: 0x220, irq: 5, dma8: 1, dma16: 5,
            host_dma8: 1, host_dma16: 5, // QEMU `-device sb16` defaults
            dma: Dma8237::new(),
            remap_start_page: 0, remap_pages: 0,
            last_gpa: 0, last_len: 0, last_gen: [0; 8],
        }
    }

    /// SB ports that pass straight through to the real card (QEMU
    /// `sb16`/`adlib`): the DSP/mixer block `[io_base, io_base+0x10)` and
    /// the OPL2/3 FM ports 0x388/0x389. Only the 8237 is virtual.
    pub fn is_passthrough(&self, p: u16) -> bool {
        (p >= self.io_base && p < self.io_base + 0x10) || matches!(p, 0x388 | 0x389)
    }

    /// Called after every virtual-8237 write. If the BLASTER-declared
    /// channel just became armed (unmasked, nonzero count), relocate the
    /// guest DMA buffer to a contiguous DMA-safe physical run and program
    /// the *real* 8237 with the translated address — the card then DMAs
    /// correct bytes. If the channel was masked, release the binding.
    pub fn maybe_remap(&mut self) {
        // SB uses exactly its BLASTER D (8-bit) or H (16-bit) channel.
        let c8 = self.dma8 as usize;
        let c16 = self.dma16 as usize;
        let armed8 = c8 < 4 && !self.dma.ch[c8].masked && self.dma.ch[c8].count != 0;
        let armed16 = (5..8).contains(&c16)
            && !self.dma.ch[c16].masked && self.dma.ch[c16].count != 0;

        let (chan, is16, host_chan) = if armed16 {
                (c16, true, self.host_dma16 as usize)
            } else if armed8 {
                (c8, false, self.host_dma8 as usize)
            } else {
                // Idle/masked — keep the binding (reused next block).
                return;
            };

        // Act only when the guest (re)armed this channel: it bumped
        // count_gen since we last acted. This is the per-block re-arm
        // signal regardless of whether the driver masks (single-cycle
        // rewrites count every block; auto-init writes it once). Skips
        // per-write spam without the old coarse mask/unmask latch.
        let cur_gen = self.dma.count_gen[chan];
        if self.last_gen[chan] == cur_gen { return; }
        self.last_gen[chan] = cur_gen;

        let ch = self.dma.ch[chan];
        let (gpa, len, blog2) = if is16 {
            (((ch.page as u32) << 16) | ((ch.addr as u32) << 1),
             ((ch.count as u32) + 1) * 2, 17u32)
        } else {
            (((ch.page as u32) << 16) | ch.addr as u32,
             (ch.count as u32) + 1, 16u32)
        };

        // SB DMA-channel probe: the driver arms several tiny (≤ a few
        // bytes) single-cycle transfers at assorted low addresses
        // (observed: gpa 0x0, 0x73, 0x6573, all len=4) purely to confirm
        // DMA+IRQ wiring — it ignores the data. The reliable signal is
        // the *size* (real audio blocks are KB; e.g. 0x3B81), not the
        // address. We must NOT repoint such pages (a stale page→pool
        // alias + pool reuse corrupts memory — kernel stub #UD at
        // gpa=0). But the transfer must still complete so the card
        // raises the IRQ, else the driver decides "no SB" and falls back
        // to subtitles. Point the real 8237 at a throwaway scratch
        // frame, no page remap. (Also covers any low-system address.)
        if len < 0x100 || (gpa & !0xFFF) < 0x1000 {
            let scratch = crate::kernel::startup::arch_alloc_phys_contig(1, blog2);
            if scratch != 0 {
                program_real_8237(host_chan as u8, (scratch as u32) * 0x1000,
                                   len, ch.mode, is16);
                crate::kernel::startup::arch_free_phys_contig(scratch, 1);
            }
            crate::dbg_println!(
                "[SB-DMA] DMA probe gpa={:#X} len={:#X} -> scratch (no remap)",
                gpa, len);
            return;
        }

        let page_off = (gpa & 0xFFF) as usize;
        let num_pages = (page_off + len as usize + 0xFFF) / 0x1000;

        // (Re)locate the guest buffer onto a contiguous run only when the
        // buffer (addr/len) differs from the live binding. Auto-init
        // reuses the same buffer every block; since we repointed the
        // guest PTEs, its refills land straight in the contiguous pages
        // (true zero-copy) — no re-alloc/re-copy needed.
        if self.remap_pages == 0 || gpa != self.last_gpa || len != self.last_len {
            if self.remap_pages != 0 {
                crate::kernel::startup::arch_free_phys_contig(
                    self.remap_start_page, self.remap_pages);
                self.remap_start_page = 0;
                self.remap_pages = 0;
            }
            let contig =
                crate::kernel::startup::arch_alloc_phys_contig(num_pages, blog2);
            if contig == 0 {
                crate::dbg_println!(
                    "[SB-DMA] no contiguous DMA region for {} pages", num_pages);
                self.last_gen[chan] = cur_gen.wrapping_sub(1); // retry next arm
                return;
            }
            // The ring-1 kernel shares the VM86 address space, so the
            // guest buffer is directly at its DOS-physical = linear
            // address `gpa`. Snapshot it, repoint those pages onto the
            // contiguous run, write the bytes back (now contig-backed).
            let vbase = (gpa & !0xFFF) as usize;
            let span = num_pages * 0x1000;
            let mut snap = alloc::vec![0u8; span];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vbase as *const u8, snap.as_mut_ptr(), span);
            }
            crate::kernel::startup::arch_map_phys_range(
                vbase >> 12, num_pages, contig, 0);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    snap.as_ptr(), vbase as *mut u8, span);
            }
            self.remap_start_page = contig;
            self.remap_pages = num_pages;
            self.last_gpa = gpa;
            self.last_len = len;
        }

        // Always (re)program the real 8237 on every (re)arm — single-
        // cycle drivers re-arm per block, so the real controller must be
        // re-pointed each time even though the binding is unchanged.
        let phys = (self.remap_start_page as u32) * 0x1000 + page_off as u32;
        program_real_8237(host_chan as u8, phys, len, ch.mode, is16);
        crate::dbg_println!(
            "[SB-DMA] vch{} -> hch{} gpa={:#07X} len={:#X} -> phys={:#X} ({} pg, mode={:#04X})",
            chan, host_chan, gpa, len, phys, self.remap_pages, ch.mode);
    }

    /// Apply this thread's `BLASTER=Axxx Iy Dz Hw …` env string. Unknown
    /// or missing tokens leave the SB16 defaults. `env` is the raw DOS
    /// environment block (NUL-separated `KEY=VAL`, double-NUL terminated).
    pub fn configure_from_env(&mut self, env: &[u8]) {
        let Some(val) = env_var(env, b"BLASTER") else { return };
        for tok in val.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
            let (key, rest) = (tok[0].to_ascii_uppercase(), &tok[1..]);
            let radix = if key == b'A' || key == b'P' { 16 } else { 10 };
            let Some(n) = parse_uint(rest, radix) else { continue };
            match key {
                b'A' => self.io_base = n as u16,
                b'I' => self.irq = n as u8,
                b'D' => self.dma8 = n as u8,
                b'H' => self.dma16 = n as u8,
                _ => {}
            }
        }
    }
}

/// Look up `KEY` in a DOS environment block, returning its value bytes.
fn env_var<'a>(env: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < env.len() && env[i] != 0 {
        let end = env[i..].iter().position(|&b| b == 0).map(|p| i + p)?;
        let entry = &env[i..end];
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            if entry[..eq].eq_ignore_ascii_case(key) {
                return Some(&entry[eq + 1..]);
            }
        }
        i = end + 1;
    }
    None
}

/// Program the physical 8237 for `chan` with the translated `phys`
/// address / `len` bytes / `mode`. 8-bit channels (0-3) are byte-
/// addressed; 16-bit channels (5-7) are word-addressed (addr/count in
/// words, page bit16 implied). Standard sequence: mask, clear flip-flop,
/// mode, addr lo/hi, page, count lo/hi, unmask.
fn program_real_8237(chan: u8, phys: u32, len: u32, mode: u8, is16: bool) {
    use crate::arch::outb;
    // Standard PC/AT page-register ports indexed by absolute channel.
    const PAGE: [u8; 8] = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];
    if is16 {
        let m = (chan - 4) as u16;            // local 0..3 on controller #2
        let addr = (phys >> 1) & 0xFFFF;       // word address
        let cnt = (len / 2) - 1;               // word count − 1
        outb(0xD4, 0x04 | (chan - 4));         // mask channel
        outb(0xD8, 0);                         // clear byte-pointer flip-flop
        outb(0xD6, mode);
        outb(0xC0 + (m * 4) as u16, addr as u8);
        outb(0xC0 + (m * 4) as u16, (addr >> 8) as u8);
        outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        outb(0xC0 + (m * 4 + 2) as u16, cnt as u8);
        outb(0xC0 + (m * 4 + 2) as u16, (cnt >> 8) as u8);
        outb(0xD4, chan - 4);                  // unmask channel
    } else {
        let cnt = len - 1;                     // byte count − 1
        outb(0x0A, 0x04 | chan);               // mask channel
        outb(0x0C, 0);                         // clear byte-pointer flip-flop
        outb(0x0B, mode);
        outb((chan as u16) * 2, phys as u8);
        outb((chan as u16) * 2, (phys >> 8) as u8);
        outb(PAGE[chan as usize] as u16, (phys >> 16) as u8);
        outb((chan as u16) * 2 + 1, cnt as u8);
        outb((chan as u16) * 2 + 1, (cnt >> 8) as u8);
        outb(0x0A, chan);                      // unmask channel
    }
}

fn parse_uint(s: &[u8], radix: u32) -> Option<u32> {
    let mut acc: u32 = 0;
    let mut any = false;
    for &b in s {
        let d = (b as char).to_digit(radix)?;
        acc = acc.checked_mul(radix)?.checked_add(d)?;
        any = true;
    }
    any.then_some(acc)
}

/// Policy-free PC machine virtualization — per-thread peripheral state.
///
/// Holds the virtual 8259 PIC, 8253 PIT, PS/2 keyboard, VGA register set,
/// A20 gate state, HMA page tracking, and small latches used by the monitor
/// decoders (skip_irq, e0_pending).
///
/// DOS-specific state (PSP, DTA, heap/free segment, XMS/EMS, FindFirst state,
/// exec-parent chain) lives directly on `thread::DosState`, not here.
pub struct PcMachine {
    pub a20_enabled: bool,
    pub vpit: VirtualPit,
    pub vpic: VirtualPic,
    pub vkbd: VirtualKeyboard,
    pub mouse: MouseState,
    pub skip_irq: bool,
    pub e0_pending: bool,
    pub vga: VgaState,
    /// Sound Blaster DMA virtualization (generic virtual 8237 + the
    /// thread's BLASTER channel/IRQ map). SB itself is passthrough.
    pub sb: SbDmaState,
    /// Last value written to CMOS index port 0x70 (NMI bit masked off).
    /// Reads of port 0x71 pass through to the host CMOS using this index.
    pub cmos_index: u8,

    /// PM/RM transition state. The pm-side cursor isn't a separate
    /// field — it's `regs.SS:SP` when user is on pm side, or
    /// `locked_stack.other_stack` (an `(SS, SP)` pair) when user is on
    /// rm side. See [`super::mode_transitions::pm_get_stack`].
    pub locked_stack: super::mode_transitions::LockedStackState,
}

/// Microsoft Mouse driver (INT 33h) state. Updated by the IRQ 12 packet
/// stream queued via `queue_irq`; queried by INT 33h subfunctions in dos.rs.
pub struct MouseState {
    /// Absolute cursor position, clipped to `[min_x..=max_x]` × `[min_y..=max_y]`.
    pub x: i16,
    pub y: i16,
    /// Current button state. bit 0 = left, 1 = right, 2 = middle.
    pub buttons: u8,
    /// User-set clip range. Defaults match a 640×200 mode.
    pub min_x: i16, pub max_x: i16,
    pub min_y: i16, pub max_y: i16,
    /// AX=0Bh delta accumulators since the last read. Reset by `take_motion()`.
    pub accum_dx: i32,
    pub accum_dy: i32,
    /// AX=01/02 hide-show counter. Cursor is visible iff `show_count <= 0`.
    /// Starts at 1 (hidden); AX=01 decrements, AX=02 increments.
    pub show_count: i8,
    /// Text-mode cursor rendering: where (cell offset 0..2000) we currently
    /// have an inverted attribute, and the original attribute value at that
    /// cell. `None` means no cursor is currently drawn.
    pub drawn_at: Option<u16>,
    pub saved_attr: u8,
    /// AX=0Ch event handler. CX=mask, ES:DX=handler far address. `mask=0`
    /// means no handler installed.
    pub cb_mask: u16,
    pub cb_seg: u16,
    pub cb_off: u16,
    /// Pending event-condition bits since last delivery, plus the deltas
    /// from the last packet that triggered. Read & cleared by the SLOT_INT74
    /// dispatcher when it sets up the user-handler call.
    pub pending_cond: u16,
    pub last_dx: i16,
    pub last_dy: i16,
    /// User GP regs saved across the AX=0Ch handler far-call. ModeSave only
    /// covers CS/EIP/SS/ESP/EFLAGS/segs; we clobber AX/BX/CX/DX/SI/DI to set
    /// up the call, so they have to be bracket-saved here and restored by
    /// the SLOT_INT74_MOUSE_CB_RET slot when the handler RETFs.
    pub saved_rax: u64,
    pub saved_rbx: u64,
    pub saved_rcx: u64,
    pub saved_rdx: u64,
    pub saved_rsi: u64,
    pub saved_rdi: u64,
}

const VGA_TEXT_BASE: u32 = 0xB8000;

impl MouseState {
    pub const fn new() -> Self {
        Self { x: 0, y: 0, buttons: 0,
               min_x: 0, max_x: 639, min_y: 0, max_y: 199,
               accum_dx: 0, accum_dy: 0,
               show_count: 1, drawn_at: None, saved_attr: 0,
               cb_mask: 0, cb_seg: 0, cb_off: 0,
               pending_cond: 0, last_dx: 0, last_dy: 0,
               saved_rax: 0, saved_rbx: 0, saved_rcx: 0,
               saved_rdx: 0, saved_rsi: 0, saved_rdi: 0 }
    }
    /// Apply one PS/2 packet: accumulate raw delta, advance clipped position,
    /// redraw the cursor at the new cell if it's visible. Returns the
    /// AX=0Ch condition bits that fired this packet (so the caller can OR
    /// against the registered event mask and decide to deliver IRQ 12).
    ///
    /// AX=0Ch condition bits (from the spec):
    ///   0x01 = mouse moved
    ///   0x02 = left button pressed
    ///   0x04 = left button released
    ///   0x08 = right button pressed
    ///   0x10 = right button released
    ///   0x20 = middle button pressed
    ///   0x40 = middle button released
    pub fn apply_packet(&mut self, dx: i16, dy: i16, buttons: u8) -> u16 {
        self.accum_dx = self.accum_dx.saturating_add(dx as i32);
        self.accum_dy = self.accum_dy.saturating_add(dy as i32);
        self.x = (self.x as i32 + dx as i32).clamp(self.min_x as i32, self.max_x as i32) as i16;
        self.y = (self.y as i32 + dy as i32).clamp(self.min_y as i32, self.max_y as i32) as i16;
        let prev = self.buttons;
        let cur = buttons;
        self.buttons = cur;
        self.render_if_visible();

        let mut cond: u16 = 0;
        if dx != 0 || dy != 0 { cond |= 0x01; }
        let pressed = !prev & cur;
        let released = prev & !cur;
        if pressed  & 0x01 != 0 { cond |= 0x02; }
        if released & 0x01 != 0 { cond |= 0x04; }
        if pressed  & 0x02 != 0 { cond |= 0x08; }
        if released & 0x02 != 0 { cond |= 0x10; }
        if pressed  & 0x04 != 0 { cond |= 0x20; }
        if released & 0x04 != 0 { cond |= 0x40; }

        // Coalesce condition bits across multiple packets into one delivery;
        // last_dx/dy reflect only the latest packet (real drivers fire once
        // per packet, but our delivery is gated on the IRQ-loop tick).
        self.pending_cond |= cond;
        self.last_dx = dx;
        self.last_dy = dy;
        cond
    }
    /// Take and clear the accumulated delta (for INT 33h AX=0Bh).
    pub fn take_motion(&mut self) -> (i32, i32) {
        let dx = self.accum_dx;
        let dy = self.accum_dy;
        self.accum_dx = 0;
        self.accum_dy = 0;
        (dx, dy)
    }

    /// Text-mode cursor: invert (xor 0x77) the attribute byte at `(x>>3, y>>3)`
    /// using the standard 8×8 mickey-to-cell ratio. No-op if hidden or
    /// already drawn at this cell. Real Microsoft Mouse drivers also do this
    /// in graphics modes via a sprite — we don't (yet); games that go to
    /// mode 13h hide the driver cursor and draw their own anyway.
    pub fn render_if_visible(&mut self) {
        if self.show_count > 0 { return; }
        let col = (self.x >> 3) as u32;
        let row = (self.y >> 3) as u32;
        if col >= 80 || row >= 25 { return; }
        let offset = (row * 80 + col) as u16;
        if Some(offset) == self.drawn_at { return; }
        self.erase_cursor();
        unsafe {
            let attr = (VGA_TEXT_BASE + offset as u32 * 2 + 1) as *mut u8;
            self.saved_attr = core::ptr::read_volatile(attr);
            core::ptr::write_volatile(attr, self.saved_attr ^ 0x77);
        }
        self.drawn_at = Some(offset);
    }

    /// Restore the original attribute under the current cursor cell.
    pub fn erase_cursor(&mut self) {
        if let Some(old) = self.drawn_at.take() {
            unsafe {
                let attr = (VGA_TEXT_BASE + old as u32 * 2 + 1) as *mut u8;
                core::ptr::write_volatile(attr, self.saved_attr);
            }
        }
    }

    /// AX=01h — show cursor: decrement counter; if it just reached 0, draw.
    pub fn show(&mut self) {
        self.show_count -= 1;
        self.render_if_visible();
    }

    /// AX=02h — hide cursor: increment counter; if it was 0, erase.
    pub fn hide(&mut self) {
        if self.show_count <= 0 { self.erase_cursor(); }
        self.show_count += 1;
    }
}

impl PcMachine {
    pub fn new() -> Self {
        // A20 starts disabled. HMA_PAGE wraps to user's private low memory
        // by copying entries[0..16]. HMA_SHADOW_PAGE is left not-present
        // (arch_user_clean cleared it; map_low_mem_user doesn't touch it),
        // which is the correct A20-on state when no extended memory is
        // allocated — set_a20(true) will swap not-present into HMA_PAGE
        // so HMA accesses fault until XMS maps real extended memory.
        crate::kernel::startup::arch_copy_page_entries(0, HMA_PAGE, HMA_PAGE_COUNT);
        Self {
            a20_enabled: false,
            vpit: VirtualPit::new(),
            vpic: VirtualPic::new(),
            vkbd: VirtualKeyboard::new(),
            mouse: MouseState::new(),
            skip_irq: false,
            e0_pending: false,
            vga: VgaState::new(),
            sb: SbDmaState::new(),
            cmos_index: 0,
            locked_stack: super::mode_transitions::LockedStackState::new(),
        }
    }

    /// Toggle A20 gate: HMA either sees shadow (real content) or wraps to page 0.
    pub fn set_a20(&mut self, enabled: bool) {
        if enabled == self.a20_enabled { return; }
        // Shadow always holds the opposite of what's in HMA.
        // Swap them to toggle.
        crate::kernel::startup::arch_swap_page_entries(HMA_SHADOW_PAGE, HMA_PAGE, HMA_PAGE_COUNT);
        self.a20_enabled = enabled;
    }
}

// ============================================================================
// Virtual 8253 PIT
// ============================================================================

const PIT_INPUT_HZ: u64 = 1_193_182;
const HOST_TIMER_HZ: u64 = 1000;

#[derive(Clone, Copy)]
struct VirtualPitChannel {
    reload: u16,
    rw_mode: u8,
    mode: u8,
    write_lsb: Option<u8>,
    read_lsb_next: bool,
    latched: Option<u16>,
    latch_lsb_next: bool,
    start_cycle: u64,
    next_irq_cycle: u64,
    enabled: bool,
}

impl VirtualPitChannel {
    const fn new() -> Self {
        Self {
            reload: 0,
            rw_mode: 3,
            mode: 3,
            write_lsb: None,
            read_lsb_next: true,
            latched: None,
            latch_lsb_next: true,
            start_cycle: 0,
            next_irq_cycle: 0,
            enabled: true,
        }
    }

    #[inline]
    fn divisor(&self) -> u64 {
        match self.reload {
            0 => 65_536,
            v => v as u64,
        }
    }

    #[inline]
    fn current_count(&self, now: u64) -> u16 {
        if !self.enabled {
            return self.reload;
        }
        let div = self.divisor();
        let elapsed = now.saturating_sub(self.start_cycle);
        let raw = match self.mode {
            2 | 3 => {
                let pos = elapsed % div;
                let remaining = div - pos;
                if remaining == div { div } else { remaining }
            }
            _ => {
                if elapsed >= div { 0 } else { div - elapsed }
            }
        };
        raw as u16
    }

    fn latch_count(&mut self, now: u64) {
        self.latched = Some(self.current_count(now));
        self.latch_lsb_next = true;
    }

    fn read_byte(&mut self, now: u64) -> u8 {
        if let Some(latched) = self.latched {
            let byte = if self.latch_lsb_next {
                self.latch_lsb_next = false;
                latched as u8
            } else {
                self.latched = None;
                self.latch_lsb_next = true;
                (latched >> 8) as u8
            };
            return byte;
        }

        let count = self.current_count(now);
        match self.rw_mode {
            1 => count as u8,
            2 => (count >> 8) as u8,
            _ => {
                let byte = if self.read_lsb_next {
                    count as u8
                } else {
                    (count >> 8) as u8
                };
                self.read_lsb_next = !self.read_lsb_next;
                byte
            }
        }
    }

    fn load_count(&mut self, raw: u16, now: u64) {
        self.reload = raw;
        self.write_lsb = None;
        self.read_lsb_next = true;
        self.latched = None;
        self.latch_lsb_next = true;
        self.start_cycle = now;
        self.enabled = true;
        let div = self.divisor();
        self.next_irq_cycle = match self.mode {
            2 | 3 => now.saturating_add(div),
            _ => now.saturating_add(div),
        };
    }

    fn write_byte(&mut self, val: u8, now: u64) {
        match self.rw_mode {
            1 => self.load_count(val as u16, now),
            2 => self.load_count((val as u16) << 8, now),
            _ => {
                if let Some(lo) = self.write_lsb.take() {
                    self.load_count(((val as u16) << 8) | lo as u16, now);
                } else {
                    self.write_lsb = Some(val);
                }
            }
        }
    }

    fn set_command(&mut self, rw_mode: u8, mode: u8) {
        self.rw_mode = rw_mode;
        self.mode = match mode {
            6 => 2,
            7 => 3,
            v => v & 0x07,
        };
        self.write_lsb = None;
        self.read_lsb_next = true;
    }

    fn take_irqs(&mut self, now: u64) -> u32 {
        if !self.enabled {
            return 0;
        }
        let div = self.divisor();
        let mut count = 0u32;
        match self.mode {
            2 | 3 => {
                while now >= self.next_irq_cycle {
                    count = count.saturating_add(1);
                    self.next_irq_cycle = self.next_irq_cycle.saturating_add(div);
                }
            }
            _ => {
                if now >= self.next_irq_cycle {
                    count = 1;
                    self.enabled = false;
                }
            }
        }
        count
    }
}

pub struct VirtualPit {
    last_host_tick: u64,
    frac_accum: u64,
    input_cycles: u64,
    ch0: VirtualPitChannel,
}

impl VirtualPit {
    fn new() -> Self {
        let now = crate::arch::get_ticks();
        Self {
            last_host_tick: now,
            frac_accum: 0,
            input_cycles: 0,
            ch0: VirtualPitChannel::new(),
        }
    }

    fn sync(&mut self) {
        let now = crate::arch::get_ticks();
        let delta_ticks = now.saturating_sub(self.last_host_tick);
        if delta_ticks == 0 {
            return;
        }
        self.last_host_tick = now;
        let total = self.frac_accum.saturating_add(delta_ticks.saturating_mul(PIT_INPUT_HZ));
        self.input_cycles = self.input_cycles.saturating_add(total / HOST_TIMER_HZ);
        self.frac_accum = total % HOST_TIMER_HZ;
    }

    fn read_counter0(&mut self) -> u8 {
        self.sync();
        self.ch0.read_byte(self.input_cycles)
    }

    fn write_counter0(&mut self, val: u8) {
        self.sync();
        self.ch0.write_byte(val, self.input_cycles);
    }

    fn write_command(&mut self, val: u8) {
        self.sync();
        let channel = (val >> 6) & 0x03;
        if channel != 0 {
            return;
        }
        let rw_mode = (val >> 4) & 0x03;
        if rw_mode == 0 {
            self.ch0.latch_count(self.input_cycles);
            return;
        }
        self.ch0.set_command(rw_mode, (val >> 1) & 0x07);
    }

    pub fn take_pending_irqs(&mut self) -> u32 {
        self.sync();
        self.ch0.take_irqs(self.input_cycles)
    }

    /// Debug summary: (enabled, mode, reload, now, next_irq_cycle)
    pub fn debug_state(&self) -> (bool, u8, u16, u64, u64) {
        (
            self.ch0.enabled,
            self.ch0.mode,
            self.ch0.reload,
            self.input_cycles,
            self.ch0.next_irq_cycle,
        )
    }
}

// ============================================================================
// Virtual hardware — per-thread PIC and keyboard emulation
// ============================================================================

pub const VPIC_QUEUE_SIZE: usize = 64;

/// Virtual 8259 PIC (one per thread, master only)
pub struct VirtualPic {
    pub isr: u8,  // In-Service Register
    pub imr: u8,  // Interrupt Mask Register
    queue: [u8; VPIC_QUEUE_SIZE],  // pending interrupt vectors
    head: usize,
    tail: usize,
}

impl VirtualPic {
    pub const fn new() -> Self {
        Self { isr: 0, imr: 0, queue: [0; VPIC_QUEUE_SIZE], head: 0, tail: 0 }
    }

    /// Check if there are pending interrupt vectors in the queue.
    pub fn has_pending(&self) -> bool {
        self.head != self.tail
    }

    /// Check whether a specific vector is already queued.
    pub fn has_pending_vec(&self, vec: u8) -> bool {
        let mut i = self.head;
        while i != self.tail {
            if self.queue[i] == vec {
                return true;
            }
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        false
    }

    /// Non-specific EOI: clear highest-priority (lowest-numbered) in-service bit
    pub fn eoi(&mut self) {
        if self.isr != 0 {
            self.isr &= self.isr - 1; // clear lowest set bit
        }
    }

    /// Debug: copy out the pending queue (vector list in order).
    pub fn debug_queue(&self) -> ([u8; VPIC_QUEUE_SIZE], usize) {
        let mut out = [0u8; VPIC_QUEUE_SIZE];
        let mut n = 0;
        let mut i = self.head;
        while i != self.tail {
            out[n] = self.queue[i];
            n += 1;
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        (out, n)
    }

    /// Queue a pending interrupt vector.
    /// Timer ticks (0x08) are coalesced: only one pending tick is kept.
    /// This prevents timer floods from starving keyboard and other IRQs.
    pub fn push(&mut self, vec: u8) {
        if vec == 0x08 {
            // Check if a timer tick is already queued — if so, skip
            let mut i = self.head;
            while i != self.tail {
                if self.queue[i] == 0x08 { return; }
                i = (i + 1) % VPIC_QUEUE_SIZE;
            }
        }
        let next = (self.tail + 1) % VPIC_QUEUE_SIZE;
        if next != self.head {
            self.queue[self.tail] = vec;
            self.tail = next;
        }
    }

    /// Pop next pending interrupt vector, prioritizing keyboard (0x09) over timer.
    pub fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail { return None; }
        // Scan for a keyboard IRQ and deliver it first
        let mut i = self.head;
        while i != self.tail {
            if self.queue[i] == 0x09 {
                let vec = self.queue[i];
                // Remove from queue by shifting
                let mut j = i;
                loop {
                    let next = (j + 1) % VPIC_QUEUE_SIZE;
                    if next == self.tail { break; }
                    self.queue[j] = self.queue[next];
                    j = next;
                }
                self.tail = if self.tail == 0 { VPIC_QUEUE_SIZE - 1 } else { self.tail - 1 };
                return Some(vec);
            }
            i = (i + 1) % VPIC_QUEUE_SIZE;
        }
        // No keyboard IRQ — pop normally
        let vec = self.queue[self.head];
        self.head = (self.head + 1) % VPIC_QUEUE_SIZE;
        Some(vec)
    }
}

const KBD_BUF_SIZE: usize = 32;

/// Virtual keyboard controller (scancode buffer)
///
/// Models the 8042 output buffer. Incoming scancodes become visible in the
/// controller as soon as the output buffer is free; IRQ1 is merely the
/// notification that data is ready. That lets BIOS INT 9 handlers and games
/// that poll ports 0x60/0x64 observe the same underlying device state.
pub struct VirtualKeyboard {
    buffer: [u8; KBD_BUF_SIZE],
    head: usize,
    tail: usize,
    /// Current scancode visible via port 0x60
    pub port60: u8,
    /// Port 0x61 state used by the BIOS keyboard IRQ handler handshake.
    pub port61: u8,
    /// Output Buffer Full flag — port 0x64 bit 0
    pub obf: bool,
    /// Set after a multi-byte keyboard command (0xED/0xF0/0xF3) consumed its
    /// opcode and is waiting for the parameter byte. The parameter is ACKed
    /// but otherwise discarded — we don't actually drive LEDs, change scancode
    /// sets, or honor typematic rates.
    awaiting_cmd_param: bool,
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self { buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0, port60: 0, port61: 0, obf: false, awaiting_cmd_param: false }
    }

    fn queue_scancode(&mut self, scancode: u8) {
        let next = (self.tail + 1) % KBD_BUF_SIZE;
        if next != self.head {
            self.buffer[self.tail] = scancode;
            self.tail = next;
        }
    }

    fn fill_output(&mut self) -> bool {
        if self.obf {
            return true;
        }
        if self.head == self.tail {
            return false;
        }
        let sc = self.buffer[self.head];
        self.head = (self.head + 1) % KBD_BUF_SIZE;
        self.port60 = sc;
        self.obf = true;
        true
    }

    /// Buffer a scancode from the real keyboard IRQ handler
    pub fn push(&mut self, scancode: u8) {
        if !self.obf {
            self.port60 = scancode;
            self.obf = true;
        } else {
            self.queue_scancode(scancode);
        }
    }

    /// Ensure a scancode is visible in port60 for INT 9 delivery.
    pub fn latch(&mut self) -> bool {
        self.fill_output()
    }

    /// Read port 0x60 — returns current scancode and then exposes the next
    /// queued byte if one is already waiting in the controller.
    pub fn read_port60(&mut self) -> u8 {
        let sc = self.port60;
        self.obf = false;
        self.fill_output();
        sc
    }

    /// Check if data is available (port 0x64 bit 0)
    pub fn has_data(&self) -> bool {
        self.obf
    }

    /// Check if scancodes are queued behind the current output byte.
    pub fn has_buffered(&self) -> bool {
        self.head != self.tail
    }

    pub fn read_port61(&mut self) -> u8 {
        // Bit 4 mirrors the DRAM refresh request line — toggles every ~15µs
        // on real hardware. Several DOS games (Zone 66 / Tran's PMODE/W
        // titles, various Adlib drivers) busy-loop until they observe an
        // edge here, treating it as a sub-tick timer. Flip on every read so
        // a `cmp / je` polling loop exits on the second sample.
        self.port61 ^= 0x10;
        self.port61
    }

    pub fn write_port61(&mut self, val: u8) {
        self.port61 = val;
    }

    /// Host write to port 0x60 — a command (or parameter) directed at the
    /// PS/2 keyboard. We don't model the device, only its protocol: queue
    /// the right ACK / response bytes back into the output buffer so the
    /// guest's polling loop unblocks. Returns true if a response byte was
    /// made visible (caller raises IRQ1).
    pub fn write_port60(&mut self, val: u8) -> bool {
        if self.awaiting_cmd_param {
            self.awaiting_cmd_param = false;
            self.push(0xFA);
            return true;
        }
        match val {
            // Multi-byte commands: ACK opcode now, ACK parameter on next write.
            0xED | 0xF0 | 0xF3 => {
                self.awaiting_cmd_param = true;
                self.push(0xFA);
            }
            // Echo — keyboard returns 0xEE, no ACK.
            0xEE => self.push(0xEE),
            // Read ID — ACK then 2-byte MF2 keyboard ID.
            0xF2 => {
                self.push(0xFA);
                self.push(0xAB);
                self.push(0x83);
            }
            // Single-byte commands that just want an ACK.
            // 0xF4 enable scanning, 0xF5 disable, 0xF6 set defaults, 0xFE resend.
            0xF4 | 0xF5 | 0xF6 | 0xFE => self.push(0xFA),
            // Reset — ACK then BAT-complete.
            0xFF => {
                self.push(0xFA);
                self.push(0xAA);
            }
            // Unknown opcode — keyboard asks the host to resend.
            _ => self.push(0xFE),
        }
        true
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.port60 = 0;
        self.port61 = 0;
        self.obf = false;
        self.awaiting_cmd_param = false;
    }

    /// Pop next key-down scancode, skipping releases (for INT 16h AH=0)
    pub fn pop_key(&mut self) -> Option<u8> {
        while self.head != self.tail {
            let sc = self.buffer[self.head];
            self.head = (self.head + 1) % KBD_BUF_SIZE;
            if sc & 0x80 == 0 {
                return Some(sc);
            }
        }
        None
    }

    /// Peek next key-down scancode without consuming (for INT 16h AH=1)
    pub fn peek_key(&self) -> Option<u8> {
        let mut i = self.head;
        while i != self.tail {
            let sc = self.buffer[i];
            if sc & 0x80 == 0 {
                return Some(sc);
            }
            i = (i + 1) % KBD_BUF_SIZE;
        }
        None
    }
}

/// Strip PS/2 E0 prefix — DOS games expect XT-style scancodes.
/// E0 is consumed; the following scancode passes through as its legacy equivalent.
fn normalize_scancode(pc: &mut PcMachine, scancode: u8) -> Option<u8> {
    if scancode == 0xE0 {
        pc.e0_pending = true;
        return None;
    }
    if pc.e0_pending {
        pc.e0_pending = false;
    }
    Some(scancode)
}

/// Clear the BIOS keyboard buffer at 40:1A..40:3E.
pub fn clear_bios_keyboard_buffer() {
    write_u16(0x40, 0x1A, 0x001E);
    write_u16(0x40, 0x1C, 0x001E);
    for off in (0x1E..0x3E).step_by(2) {
        write_u16(0x40, off, 0);
    }
}

/// Pop the next word from the BIOS keyboard buffer.
pub fn pop_bios_keyboard_word() -> Option<u16> {
    let head = read_u16(0x40, 0x1A);
    let tail = read_u16(0x40, 0x1C);
    if head == tail {
        return None;
    }
    let word = read_u16(0x40, head as u32);
    let next = if head + 2 >= 0x003E { 0x001E } else { head + 2 };
    write_u16(0x40, 0x1A, next);
    Some(word)
}

// ============================================================================
// I/O port emulation
// ============================================================================

/// Emulate IN from a port using the virtual peripherals.
pub fn emulate_inb(pc: &mut PcMachine, port: u16) -> u8 {
    // ISA decodes only A0-A9, so I/O ports alias mod 0x400 (e.g. a
    // gameport at 0x208 also answers 0x608). DOS-era code relies on
    // this; the whole DOS I/O surface is <= 0x3FF. Fold the alias
    // once here so every handler sees the canonical 10-bit address.
    // Wide-decode I/O (PCI/PnP/ACPI/EISA) is out of scope for the
    // VM86 guest — we model none of it — and kernel PCI uses a
    // separate path (arch::inl/outl), not this emulator.
    let port = port & 0x3FF;
    match port {
        // VGA Input Status 1: synthesize retrace signal tied to host wall
        // time so vsync busy-waits actually wait. Mode 13h refresh ~70 Hz
        // (14.286 ms/frame), mapped to a 32-step phase:
        //   phase  0..16 — display active (0x00)            bit0=0 bit3=0
        //   phase 16..24 — horizontal blank (0x01)          bit0=1 bit3=0
        //   phase 24..32 — vertical blank   (0x09)          bit0=1 bit3=1
        // - VL_WaitVBL needs bit3=1 (VBL phase)
        // - VL_SetScreen needs 6+ consecutive bit0=1/bit3=0 (HBL phase)
        // - VL_SetCRTC needs bit0=0 (display active phase)
        // Phase formula: (ticks_ms * 70 cycles/s * 32 phases) / 1000 ms/s,
        // taken mod 32. With ms-resolution ticks the phase advances ~2.24
        // steps per host ms, so a tight busy-wait sees the same phase for
        // many successive reads (gives VL_SetScreen its "consecutive 6+"
        // criterion for free) but bit transitions happen on real wallclock.
        0x3DA => {
            // Read real hardware to reset the AC flip-flop, and track it globally.
            let _real = crate::arch::inb(0x3DA);
            unsafe { VGA_AC_STATE.pending_data = false; }
            let ticks = crate::arch::get_ticks();
            let phase = ((ticks.wrapping_mul(70 * 32)) / 1000) as u32 & 31;
            if phase < 16 { 0x00 } else if phase < 24 { 0x01 } else { 0x09 }
        }
        // VGA ports — pass through to hardware
        0x3C0..=0x3D9 | 0x3DB..=0x3DF => crate::arch::inb(port),
        // Bochs/QEMU VBE Display Interface (BVDI). SeaBIOS uses these
        // to configure QEMU's emulated VGA, even for legacy modes.
        // Pass through so SeaBIOS sees real VBE state.
        0x01CE | 0x01CF | 0x01D0 => crate::arch::inb(port),
        // Gameport (joystick): we don't model a Sound Blaster or dedicated
        // gameport card, so on the ISA bus the gameport is unpopulated —
        // reads return 0xFF (floating data lines, weakly pulled high by
        // the chipset). Full 0x200-0x20F window: gameport cards decode
        // loosely and the canonical port is 0x201, but games hit mirrors
        // across the whole block (and, via 10-bit aliasing folded above,
        // 0x6xx/0xAxx images of it — e.g. Sokoban polling 0x608-0x60B).
        // "No card on bus" for the entire window; explicit arm just
        // suppresses the unhandled-port log during joystick probes.
        0x200..=0x20F => 0xFF,
        // Master PIC command (read ISR)
        0x20 => pc.vpic.isr,
        // Master PIC data (read IMR)
        0x21 => pc.vpic.imr,
        // Keyboard data port — returns current scancode from the virtual 8042.
        0x60 => pc.vkbd.read_port60(),
        // Keyboard controller / speaker port used by BIOS IRQ1 acknowledge sequence.
        0x61 => pc.vkbd.read_port61(),
        // Keyboard status port (bit 0 = output buffer full)
        0x64 => if pc.vkbd.has_data() { 1 } else { 0 },
        0x40 => pc.vpit.read_counter0(),
        0x41 | 0x42 => 0,
        // PIT command register not readable
        0x43 => 0xFF,
        // CMOS index port: read returns the last index byte (rare).
        0x70 => pc.cmos_index,
        // CMOS data port: pass through to host RTC at the saved index.
        // Host CMOS isn't used by the kernel itself, so this is safe; the
        // guest sees real time-of-day plus a UIP/VRT-correct status block.
        0x71 => {
            crate::arch::outb(0x70, pc.cmos_index);
            crate::arch::inb(0x71)
        }
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            let v = crate::arch::inb(p);
            if p != 0x388 && p != 0x389 {
                crate::dbg_println!("[SB-IO] in  {:04X} -> {:02X}", p, v);
            }
            v
        }
        // Virtual 8237 DMA controller (generic; SB-DMA layer reads this).
        p if Dma8237::owns(p) => pc.sb.dma.io_read(p),
        // Unknown ports: return 0xFF (unpopulated bus). Diagnostic — log to
        // surface ports the BIOS or guest expects responses on but we don't
        // virtualize.
        _ => {
            crate::dbg_println!("[port] in  {:04X} -> 0xFF (unhandled)", port);
            0xFF
        }
    }
}

/// Emulate OUT to a port.
pub fn emulate_outb(pc: &mut PcMachine, port: u16, val: u8) {
    // ISA 10-bit I/O decode — fold the alias mod 0x400. See `emulate_inb`.
    let port = port & 0x3FF;
    match port {
        // VGA ports — pass through to hardware, track AC flip-flop + index
        0x3C0 => {
            unsafe {
                if !VGA_AC_STATE.pending_data {
                    VGA_AC_STATE.index = val; // index write — latch full byte (incl. PAS)
                }
                VGA_AC_STATE.pending_data = !VGA_AC_STATE.pending_data;
            }
            crate::arch::outb(port, val);
        }
        0x3C1..=0x3DF => crate::arch::outb(port, val),
        // Bochs/QEMU VBE Display Interface (BVDI) — see emulate_inb.
        0x01CE | 0x01CF | 0x01D0 => crate::arch::outb(port, val),
        // Master PIC command
        0x20 => {
            if val == 0x20 {
                // Non-specific EOI
                // If keyboard IRQ (bit 1) was in service, and the virtual 8042
                // still has data ready, IRQ1 should assert again after EOI.
                let keyboard_in_service = pc.vpic.isr & 0x02 != 0;
                pc.vpic.eoi();
                // Real hardware effectively re-asserts IRQ1 if more scancodes are
                // already visible in the controller when the handler finishes.
                if keyboard_in_service
                    && pc.vkbd.has_data()
                    && !pc.vpic.has_pending_vec(0x09)
                {
                    pc.vpic.push(0x09);
                }
            }
        }
        // Gameport one-shot trigger: no card on this ISA bus window (see
        // emulate_inb above; full 0x200-0x20F to match the read side and
        // the 10-bit alias fold). Writes to absent devices are dropped on
        // real hardware too — silently swallow rather than flood the log.
        0x200..=0x20F => {}
        // Master PIC data (write IMR)
        0x21 => pc.vpic.imr = val,
        // Slave PIC command / data
        0xA0 | 0xA1 => {}
        // Keyboard data port — host-to-device command / parameter byte.
        // The keyboard's response (ACK, BAT, ID, …) becomes visible at port
        // 0x60 and asserts IRQ1, exactly as on real hardware.
        0x60 => {
            if pc.vkbd.write_port60(val) && !pc.vpic.has_pending_vec(0x09) {
                pc.vpic.push(0x09);
            }
        }
        // Keyboard controller / speaker port
        0x61 => pc.vkbd.write_port61(val),
        // Keyboard controller command
        0x64 => {}
        0x43 => pc.vpit.write_command(val),
        0x40 => pc.vpit.write_counter0(val),
        0x41 | 0x42 => {}
        // CMOS index: latch for the next data-port read. Mask off the NMI
        // disable bit (0x80) — we never want guest writes to toggle host NMI.
        0x70 => pc.cmos_index = val & 0x7F,
        // CMOS data writes are dropped — never let the guest mutate host CMOS
        // (BIOS settings, time-of-day, alarm, etc.).
        0x71 => {}
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            if p != 0x388 && p != 0x389 {
                crate::dbg_println!("[SB-IO] out {:04X} <- {:02X}", p, val);
            }
            crate::arch::outb(p, val);
        }
        // Virtual 8237 DMA controller (generic). After capturing the
        // write, re-check whether the BLASTER channel just armed and, if
        // so, remap the guest buffer contiguous + program the real 8237.
        p if Dma8237::owns(p) => {
            pc.sb.dma.io_write(p, val);
            pc.sb.maybe_remap();
        }
        // Unknown ports: silently ignore (BIOS probes various ports during mode switches).
        // Diagnostic — log so we can spot ports SeaBIOS / guest writes to
        // that we need to virtualize but currently drop.
        _ => {
            crate::dbg_println!("[port] out {:04X} <- {:02X} (unhandled)", port, val);
        }
    }
}

// ============================================================================
// Monitor event handlers — kernel-side completion of I/O bubbled from arch
// ============================================================================

/// Resolve the linear base of segment `sel`. VM86 uses `sel*16`; PM walks
/// GDT/LDT via the arch descriptor helpers.
fn seg_base_for(regs: &Regs, sel: u16) -> u32 {
    if regs.mode() == crate::UserMode::VM86 {
        (sel as u32) << 4
    } else {
        crate::arch::monitor::seg_base(sel)
    }
}

/// Complete an `IN AL/AX/EAX, port` the arch monitor bubbled up. Reads `size`
/// bytes through `emulate_inb` and writes the result into `regs.rax`.
pub fn handle_in_event(pc: &mut PcMachine, regs: &mut Regs, port: u16, size: u32) {
    if size == 2 && matches!(port, 0x01CE | 0x01CF | 0x01D0) {
        let val = crate::arch::inw(port) as u64;
        regs.rax = (regs.rax & !0xFFFF) | val;
        return;
    }

    let mut val: u64 = 0;
    for i in 0..size {
        val |= (emulate_inb(pc, port + i as u16) as u64) << (i * 8);
    }
    let mask: u64 = if size >= 4 { 0xFFFF_FFFF } else { (1u64 << (size * 8)) - 1 };
    regs.rax = (regs.rax & !mask) | (val & mask);
}

/// Complete an `OUT port, AL/AX/EAX` the arch monitor bubbled up.
pub fn handle_out_event(pc: &mut PcMachine, regs: &mut Regs, port: u16, size: u32) {
    let val = regs.rax;
    if size == 2 && matches!(port, 0x01CE | 0x01CF | 0x01D0) {
        crate::arch::outw(port, val as u16);
        return;
    }

    for i in 0..size {
        emulate_outb(pc, port + i as u16, (val >> (i * 8)) as u8);
    }
}

/// Complete an `INSB/INSW/INSD` (ES:DI ← port, advance DI). Single element —
/// no REP handling; the CPU traps per iteration when REP is in effect.
pub fn handle_ins_event(pc: &mut PcMachine, regs: &mut Regs, size: u32) {
    let port = regs.rdx as u16;
    let es_base = seg_base_for(regs, regs.es as u16);
    let di = regs.rdi as u32;
    for i in 0..size {
        let b = emulate_inb(pc, port + i as u16);
        unsafe { *((es_base.wrapping_add(di.wrapping_add(i))) as *mut u8) = b; }
    }
    let df = regs.flags32() & (1 << 10) != 0;
    let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };
    regs.rdi = regs.rdi.wrapping_add(delta);
}

/// Complete an `OUTSB/OUTSW/OUTSD` (port ← DS:SI, advance SI). Single element.
pub fn handle_outs_event(pc: &mut PcMachine, regs: &mut Regs, size: u32) {
    let port = regs.rdx as u16;
    let ds_base = seg_base_for(regs, regs.ds as u16);
    let si = regs.rsi as u32;
    for i in 0..size {
        let b = unsafe { *((ds_base.wrapping_add(si.wrapping_add(i))) as *const u8) };
        emulate_outb(pc, port + i as u16, b);
    }
    let df = regs.flags32() & (1 << 10) != 0;
    let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };
    regs.rsi = regs.rsi.wrapping_add(delta);
}

// ============================================================================
// IRQ delivery — buffer hardware events, drain into the virtual PIC
// ============================================================================

/// Buffer a hardware event into the virtual PIC / keyboard.
/// Mode-independent: both VM86 and DPMI share the same virtual devices.
pub fn queue_irq(pc: &mut PcMachine, event: crate::arch::Irq) {
    use crate::arch::Irq;
    match event {
        Irq::Key(sc) => {
            let Some(sc) = normalize_scancode(pc, sc) else { return };
            pc.vkbd.push(sc);
            if pc.vpic.isr & 0x02 == 0 && !pc.vpic.has_pending_vec(0x09) {
                pc.vpic.push(0x09);
            }
        }
        Irq::Tick => {
            let due = pc.vpit.take_pending_irqs();
            for _ in 0..due {
                pc.vpic.push(0x08);
            }
        }
        Irq::Mouse { dx, dy, buttons } => {
            let cond = pc.mouse.apply_packet(dx, dy, buttons);
            // Raise IRQ 12 (vec 0x74) into the virtual PIC iff the user
            // registered a handler whose mask intersects this packet's
            // condition bits. The IVT[0x74] stub at slot SLOT_INT74_MOUSE_CB
            // will trap to kernel, set up callback args, and far-call the
            // user handler.
            if pc.mouse.cb_mask & cond != 0 && !pc.vpic.has_pending_vec(0x74) {
                pc.vpic.push(0x74);
            }
        }
        Irq::Hw(line) => {
            // Real SB completion IRQ → relay to the guest vPIC at the
            // BLASTER-declared vector (IRQ 0-7 → 0x08+line, 8-15 →
            // 0x70+line-8). Ignore other host lines.
            if line == pc.sb.irq {
                let vec = if line < 8 { 0x08 + line } else { 0x70 + (line - 8) };
                if !pc.vpic.has_pending_vec(vec) {
                    pc.vpic.push(vec);
                    crate::dbg_println!(
                        "[SB-DMA] relay SB IRQ{} -> vPIC vec {:#04X} (imr={:#04X} isr={:#04X})",
                        line, vec, pc.vpic.imr, pc.vpic.isr);
                }
            }
        }
    }
}

/// Poll the virtual PIC for a deliverable IRQ, respecting the virtual
/// interrupt flag and in-service register. Returns the vector to deliver
/// (and marks it in-service on the master PIC), or `None` if nothing is
/// ready. The caller is responsible for pushing the interrupt frame
/// (see `dpmi::reflect_int_to_real_mode` / `dpmi::deliver_pm_irq`).
pub fn pick_pending_vec(pc: &mut PcMachine, regs: &mut Regs) -> Option<u8> {
    let vif = regs.frame.rflags & (1u64 << 9) != 0; // IF = virtual interrupt flag
    if !vif {
        if pc.vpic.has_pending() {
            regs.frame.rflags |= 1u64 << 20; // VIP
        }
        return None;
    }
    if pc.vpic.isr != 0 {
        return None;
    }
    let vec = pc.vpic.pop()?;
    if vec == 0x09 {
        if !pc.vkbd.latch() {
            pc.vpic.push(0x09);
            return None;
        }
    }
    if vec == 0x0D {
        crate::dbg_println!(
            "[SB-DMA] deliver SB vec0D to guest ISR (imr={:#04X} isr={:#04X})",
            pc.vpic.imr, pc.vpic.isr);
    }
    let irq_num = vec.wrapping_sub(8);
    if irq_num < 8 {
        pc.vpic.isr |= 1 << irq_num;
    }
    // Clear VIP — interrupt is being serviced
    regs.frame.rflags &= !(1u64 << 20);
    Some(vec)
}

/// Read a u16 from a real-mode seg:off address (unaligned-safe, null-safe)
pub fn read_u16(seg: u32, off: u32) -> u16 {
    let linear = (seg << 4) + off;
    let val: u16;
    unsafe {
        core::arch::asm!(
            "movzx {val:e}, word ptr [{addr}]",
            addr = in(reg) linear,
            val = out(reg) val,
            options(readonly, nostack),
        );
    }
    val
}

/// Write a u16 to a real-mode seg:off address (unaligned-safe, null-safe)
pub fn write_u16(seg: u32, off: u32, val: u16) {
    let linear = (seg << 4) + off;
    unsafe {
        core::arch::asm!(
            "mov word ptr [{addr}], {val:x}",
            addr = in(reg) linear,
            val = in(reg) val,
            options(nostack),
        );
    }
}

/// Push a u16 onto the VM86 stack (SS:SP)
pub fn vm86_push(regs: &mut Regs, val: u16) {
    let sp = vm86_sp(regs).wrapping_sub(2);
    set_vm86_sp(regs, sp);
    write_u16(regs.ss32(), sp as u32, val);
}

/// Pop a u16 from the VM86 stack (SS:SP)
pub fn vm86_pop(regs: &mut Regs) -> u16 {
    let sp = vm86_sp(regs);
    let val = read_u16(regs.ss32(), sp as u32);
    set_vm86_sp(regs, sp.wrapping_add(2));
    val
}


// GP-fault monitor lives in `arch/monitor.rs` now. Kernel only sees the
// resulting `KernelEvent`s via `do_arch_execute()`; the completion helpers
// for In/Out/Ins/Outs live at the top of this file (handle_in_event, etc.).
