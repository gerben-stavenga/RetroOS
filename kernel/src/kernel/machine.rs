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

use crate::kernel::thread;
use crate::Regs;

pub const IF_FLAG: u32 = 1 << 9;
pub const IOPL_MASK: u32 = 3 << 12;
pub const VM_FLAG: u32 = 1 << 17;
pub const VIF_FLAG: u32 = 1 << 19;

/// Flags that VM86 code cannot change (IOPL, VM)
pub const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG;

pub const HMA_PAGE_COUNT: usize = 16;

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
pub fn set_vm86_ss(regs: &mut Regs, ss: u16) {
    regs.set_ss32(ss as u32);
}

#[inline]
pub fn set_vm86_sp(regs: &mut Regs, sp: u16) {
    let full = (regs.sp32() & 0xFFFF_0000) | sp as u32;
    regs.set_sp32(full);
}

#[inline]
pub fn set_vm86_flags(regs: &mut Regs, flags: u32) {
    regs.set_flags32(flags);
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
    const fn new() -> Self { Self { index: 0, pending_data: false } }
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
        crate::arch::cli();
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
        for plane in 0..4u8 {
            outb(0x3CE, 4); outb(0x3CF, plane);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (0xA0000) as *const u8,
                    self.planes[plane as usize * 65536..].as_mut_ptr(),
                    65536,
                );
            }
        }

        // Restore registers we temporarily changed
        outb(0x3C4, 4); outb(0x3C5, self.seq[4]);
        outb(0x3CE, 4); outb(0x3CF, self.gc[4]);
        outb(0x3CE, 5); outb(0x3CF, self.gc[5]);
        outb(0x3CE, 6); outb(0x3CF, self.gc[6]);
        // Restore the program's tracked index registers
        outb(0x3C4, self.seq_index);
        outb(0x3D4, self.crtc_index);
        outb(0x3CE, self.gc_index);
        crate::arch::sti();
    }

    /// Write this struct's state to VGA hardware.
    pub fn restore_to_hardware(&self) {
        if self.planes.is_empty() { return; }
        use crate::arch::{inb, outb};
        crate::arch::cli();

        // Reset AC flipflop to known (index) state before any VGA register work.
        let _ = inb(0x3DA);

        // Step 1: Write planes in forced flat planar mode.
        // Need misc_output for clock source, but force sequential planar access.
        outb(0x3C4, 0); outb(0x3C5, 0x01); // sync reset
        outb(0x3C2, self.misc_output);
        outb(0x3C4, 2); outb(0x3C5, 0x0F); // map mask: all planes
        outb(0x3C4, 4); outb(0x3C5, 0x06); // mem mode: sequential, no chain-4
        outb(0x3C4, 0); outb(0x3C5, 0x03); // release reset
        outb(0x3CE, 5); outb(0x3CF, 0x00); // GC mode: write mode 0
        outb(0x3CE, 6); outb(0x3CF, 0x05); // GC misc: graphics, A0000/64K

        for plane in 0..4u8 {
            outb(0x3C4, 2); outb(0x3C5, 1 << plane);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.planes[plane as usize * 65536..].as_ptr(),
                    (0xA0000) as *mut u8,
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
        for i in (0..5u8).rev() { outb(0x3C4, i); outb(0x3C5, self.seq[i as usize]); }

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
        // Restore index registers
        outb(0x3C4, self.seq_index);
        outb(0x3D4, self.crtc_index);
        outb(0x3CE, self.gc_index);
        crate::arch::sti();
    }
}

// ============================================================================
// PcMachine — per-thread machine state
// ============================================================================

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
    pub skip_irq: bool,
    pub hma_pages: [u64; HMA_PAGE_COUNT],
    pub e0_pending: bool,
    pub vga: VgaState,
}

impl PcMachine {
    pub fn new() -> Self {
        let mut hma_pages = [0u64; HMA_PAGE_COUNT];
        crate::kernel::startup::arch_init_hma(&mut hma_pages);
        Self {
            a20_enabled: false,
            vpit: VirtualPit::new(),
            vpic: VirtualPic::new(),
            vkbd: VirtualKeyboard::new(),
            skip_irq: false,
            hma_pages,
            e0_pending: false,
            vga: VgaState::new(),
        }
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
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self { buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0, port60: 0, port61: 0, obf: false }
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

    pub fn read_port61(&self) -> u8 {
        self.port61
    }

    pub fn write_port61(&mut self, val: u8) {
        self.port61 = val;
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.port60 = 0;
        self.port61 = 0;
        self.obf = false;
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
    match port {
        // VGA Input Status 1: synthesize retrace signal.
        // Cycle (32 reads): 0-15 display active (0x00), 16-23 HBL (0x01),
        // 24-31 VBL (0x09).
        // - VL_WaitVBL needs bit 3=1 (VBL phase)
        // - VL_SetScreen needs 6+ consecutive bit0=1/bit3=0 (HBL phase)
        // - VL_SetCRTC needs bit0=0 (display active phase)
        0x3DA => {
            // Read real hardware to reset the AC flip-flop, and track it globally.
            let _real = crate::arch::inb(0x3DA);
            unsafe { VGA_AC_STATE.pending_data = false; }
            // Synthesize retrace: games (Wolf3D, Keen) poll this in tight loops.
            // QEMU's real retrace is too fast/slow for the polling patterns.
            static mut RETRACE_CTR: u8 = 0;
            let ctr = unsafe {
                RETRACE_CTR = RETRACE_CTR.wrapping_add(1);
                RETRACE_CTR
            };
            let phase = ctr & 31;
            if phase < 16 { 0x00 } else if phase < 24 { 0x01 } else { 0x09 }
        }
        // VGA ports — pass through to hardware
        0x3C0..=0x3D9 | 0x3DB..=0x3DF => crate::arch::inb(port),
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
        // Unknown ports: return 0xFF (unpopulated bus)
        _ => 0xFF,
    }
}

/// Emulate OUT to a port.
pub fn emulate_outb(pc: &mut PcMachine, port: u16, val: u8) {
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
        // Master PIC data (write IMR)
        0x21 => pc.vpic.imr = val,
        // Slave PIC command / data
        0xA0 | 0xA1 => {}
        // Keyboard controller / speaker port
        0x61 => pc.vkbd.write_port61(val),
        // Keyboard controller command
        0x64 => {}
        0x43 => pc.vpit.write_command(val),
        0x40 => pc.vpit.write_counter0(val),
        0x41 | 0x42 => {}
        // Unknown ports: silently ignore (BIOS probes various ports during mode switches)
        _ => {}
    }
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
    }
}

/// Poll the virtual PIC for a deliverable IRQ, respecting the virtual
/// interrupt flag and in-service register. Returns the vector to deliver
/// (and marks it in-service on the master PIC), or `None` if nothing is
/// ready. The caller is responsible for pushing the interrupt frame
/// (see `reflect_interrupt` for VM86 or `dpmi::deliver_hw_irq` for PM).
pub fn pick_pending_vec(pc: &mut PcMachine, regs: &mut Regs) -> Option<u8> {
    let vif = regs.frame.rflags & (1u64 << 9) != 0; // IF = virtual interrupt flag
    let is_pm = regs.mode() != crate::UserMode::VM86;
    if !vif && !is_pm {
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
    let irq_num = vec.wrapping_sub(8);
    if irq_num < 8 {
        pc.vpic.isr |= 1 << irq_num;
    }
    // Clear VIP — interrupt is being serviced
    regs.frame.rflags &= !(1u64 << 20);
    Some(vec)
}

/// Reflect an interrupt through the real-mode IVT: push FLAGS/CS/IP,
/// clear IF, load CS:IP from the vector table.
pub fn reflect_interrupt(regs: &mut Regs, int_num: u8) {
    let old_cs = vm86_cs(regs);
    let old_ip = vm86_ip(regs);
    let new_ip = read_u16(0, (int_num as u32) * 4);
    let new_cs = read_u16(0, (int_num as u32) * 4 + 2);
    vm86_push(regs, vm86_flags(regs) as u16);
    vm86_push(regs, old_cs);
    vm86_push(regs, old_ip);
    regs.clear_flag32(IF_FLAG);
    set_vm86_ip(regs, new_ip);
    set_vm86_cs(regs, new_cs);
}

// ============================================================================
// VM86 instruction decode helpers
// ============================================================================

/// Read a byte from the VM86 address space at CS:IP and advance IP
pub fn fetch_byte(regs: &mut Regs) -> u8 {
    unsafe {
        let cs = regs.cs32();
        let ip = regs.ip32();
        let linear = (cs << 4).wrapping_add(ip);
        let byte = *(linear as *const u8);
        regs.set_ip32(ip.wrapping_add(1));
        byte
    }
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

/// Push a u32 onto the VM86 stack (SS:SP) as two 16-bit halves
pub fn vm86_push32(regs: &mut Regs, val: u32) {
    vm86_push(regs, (val >> 16) as u16);
    vm86_push(regs, val as u16);
}

/// Pop a u32 from the VM86 stack (SS:SP) as two 16-bit halves
pub fn vm86_pop32(regs: &mut Regs) -> u32 {
    let lo = vm86_pop(regs) as u32;
    let hi = vm86_pop(regs) as u32;
    (hi << 16) | lo
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

// ============================================================================
// Raise helper — drain the next pending IRQ and dispatch to the active
// personality. This is the one place the machine layer calls back out to
// the personality (via `crate::kernel::dpmi::deliver_hw_irq` for PM mode
// and `reflect_interrupt` directly for VM86); it lives here so the event
// loop has one canonical entry point.
// ============================================================================

/// Try to deliver one pending interrupt from the virtual PIC.
/// IF is the virtual interrupt flag (arch swaps VIF↔IF at ring 3 boundary).
/// Works for both VM86 (IVT reflect) and DPMI (PM vector dispatch).
pub fn raise_pending(dos: &mut thread::DosState, regs: &mut Regs) {
    let Some(vec) = pick_pending_vec(&mut dos.pc, regs) else { return };
    if regs.mode() == crate::UserMode::VM86 {
        reflect_interrupt(regs, vec);
    } else {
        crate::kernel::dpmi::deliver_hw_irq(dos, regs, vec);
    }
}
