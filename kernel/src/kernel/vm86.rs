//! VM86 mode support for DOS program execution (.COM and .EXE)
//!
//! Provides:
//! - VM86 monitor (handles GP faults from sensitive instructions)
//! - DOS INT 21h emulation (basic character/string I/O, exit)
//! - Virtual hardware (PIC, keyboard) for per-thread device emulation
//! - Signal delivery (hardware IRQs reflected through BIOS IVT)
//! - .COM and MZ .EXE file loaders
//!
//! The BIOS ROM at 0xF0000-0xFFFFF and the BIOS IVT at 0x0000-0x03FF are
//! preserved from the original hardware state (via COW page 0). BIOS handlers
//! work transparently because their I/O instructions trap through the TSS IOPB
//! to our virtual devices.

extern crate alloc;

use crate::kernel::thread;
use crate::vga;
use crate::dbg_println;
use crate::Regs;

const IF_FLAG: u32 = 1 << 9;
const IOPL_MASK: u32 = 3 << 12;
const VM_FLAG: u32 = 1 << 17;
const EMS_ENABLED: bool = false;

/// Dummy file handle returned for /dev/null semantics.
const NULL_FILE_HANDLE: u16 = 99;

/// Flags that VM86 code cannot change (IOPL, VM)
const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG;

#[inline]
fn vm86_cs(regs: &Regs) -> u16 {
    regs.code_seg()
}

#[inline]
fn vm86_ip(regs: &Regs) -> u16 {
    regs.ip32() as u16
}

#[inline]
fn vm86_ss(regs: &Regs) -> u16 {
    regs.stack_seg()
}

#[inline]
fn vm86_sp(regs: &Regs) -> u16 {
    regs.sp32() as u16
}

#[inline]
fn vm86_flags(regs: &Regs) -> u32 {
    regs.flags32()
}

#[inline]
fn set_vm86_cs(regs: &mut Regs, cs: u16) {
    regs.set_cs32(cs as u32);
}

#[inline]
fn set_vm86_ip(regs: &mut Regs, ip: u16) {
    regs.set_ip32(ip as u32);
}

#[inline]
fn set_vm86_ss(regs: &mut Regs, ss: u16) {
    regs.set_ss32(ss as u32);
}

#[inline]
fn set_vm86_sp(regs: &mut Regs, sp: u16) {
    let full = (regs.sp32() & 0xFFFF_0000) | sp as u32;
    regs.set_sp32(full);
}

#[inline]
fn set_vm86_flags(regs: &mut Regs, flags: u32) {
    regs.set_flags32(flags);
}



/// .COM load segment — derived from DOS_AREA_END so the environment block
/// (COM_SEGMENT-0x10, 256 bytes) never overlaps kernel structures.
pub const COM_SEGMENT: u16 = ((DOS_AREA_END + 0xF) >> 4) as u16 + 0x10;
/// .COM code offset within segment
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer (top of 64KB segment)
const COM_SP: u16 = 0xFFFE;

pub const HMA_PAGE_COUNT: usize = 16;

/// Global VGA Attribute Controller state — tracks real hardware.
/// Flipflop: true = next write to 0x3C0 is an index byte; false = data byte.
/// Index: last index written (including PAS bit 5).
static mut VGA_AC_FLIPFLOP: bool = true;
static mut VGA_AC_INDEX: u8 = 0x20;

/// Per-process VGA state: 256KB framebuffer (4 planes) + all registers.
/// Saved/restored on context switch so each process has its own screen.
pub struct VgaState {
    /// 4 planes × 64KB = 256KB framebuffer (flat: plane 0 at [0..65536], etc.)
    pub planes: alloc::vec::Vec<u8>,
    // ── Registers ──
    pub misc_output: u8,
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
    pub ac_index: u8,
    pub ac_flipflop: bool,
    pub dac_read_index: u8,
    pub dac_write_index: u8,
    pub dac_rgb_pos: u8,
}

impl VgaState {
    pub fn new() -> Self {
        Self {
            planes: alloc::vec::Vec::new(),
            misc_output: 0,
            seq: [0; 5],
            crtc: [0; 25],
            gc: [0; 9],
            ac: [0; 21],
            dac: [0; 768],
            dac_mask: 0xFF,
            seq_index: 0,
            crtc_index: 0,
            gc_index: 0,
            ac_index: 0,
            ac_flipflop: true,
            dac_read_index: 0,
            dac_write_index: 0,
            dac_rgb_pos: 0,
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
        self.ac_flipflop = unsafe { VGA_AC_FLIPFLOP };
        self.ac_index = unsafe { VGA_AC_INDEX };
        let _ = inb(0x3DA);

        // Capture index registers BEFORE the save loops overwrite them.
        self.seq_index = inb(0x3C4);
        self.crtc_index = inb(0x3D4);
        self.gc_index = inb(0x3CE);

        // Save all registers
        self.misc_output = inb(0x3CC);
        for i in 0..5u8 { outb(0x3C4, i); self.seq[i as usize] = inb(0x3C5); }
        for i in 0..25u8 { outb(0x3D4, i); self.crtc[i as usize] = inb(0x3D5); }
        for i in 0..9u8 { outb(0x3CE, i); self.gc[i as usize] = inb(0x3CF); }
        self.dac_mask = inb(0x3C6);
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

        // Restore hardware AC to the program's tracked state:
        // inb(0x3DA) → index state, outb(0x3C0, idx) → sets index, goes to data state.
        // If program was in index state, one more inb(0x3DA) resets back.
        let _ = inb(0x3DA);
        outb(0x3C0, self.ac_index);
        if self.ac_flipflop {
            let _ = inb(0x3DA);
        }
        unsafe { VGA_AC_FLIPFLOP = self.ac_flipflop; }

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
        outb(0x3C4, 0); outb(0x3C5, 0x01); // sync reset
        outb(0x3C2, self.misc_output);
        for i in 1..5u8 { outb(0x3C4, i); outb(0x3C5, self.seq[i as usize]); }
        outb(0x3C4, 0); outb(0x3C5, 0x03); // release reset

        // CRTC — unlock first (clear protect bit in reg 0x11)
        outb(0x3D4, 0x11); outb(0x3D5, self.crtc[0x11] & 0x7F);
        for i in 0..25u8 { outb(0x3D4, i); outb(0x3D5, self.crtc[i as usize]); }
        // Graphics Controller
        for i in 0..9u8 { outb(0x3CE, i); outb(0x3CF, self.gc[i as usize]); }
        // Attribute Controller — write all 21 registers
        let _ = inb(0x3DA);
        for i in 0..21u8 { outb(0x3C0, i); outb(0x3C0, self.ac[i as usize]); }
        // Restore the program's AC index + flipflop state:
        let _ = inb(0x3DA);                // → index state
        outb(0x3C0, self.ac_index);        // set index, → data state
        if self.ac_flipflop {
            let _ = inb(0x3DA);            // → index state
        }
        unsafe {
            VGA_AC_FLIPFLOP = self.ac_flipflop;
            VGA_AC_INDEX = self.ac_index;
        }
        // DAC
        outb(0x3C6, self.dac_mask);
        outb(0x3C8, 0);
        for i in 0..768 { outb(0x3C9, self.dac[i]); }
        // Restore index registers
        outb(0x3C4, self.seq_index);
        outb(0x3D4, self.crtc_index);
        outb(0x3CE, self.gc_index);
        crate::arch::sti();
    }
}

pub struct Vm86State {
    pub a20_enabled: bool,
    pub dta: u32,
    pub heap_seg: u16,
    pub dos_pending_char: Option<u8>,
    pub last_child_exit_code: u8,
    pub vpit: VirtualPit,
    pub vpic: VirtualPic,
    pub vkbd: VirtualKeyboard,
    pub exec_parent: Option<ExecParent>,
    pub skip_irq: bool,
    pub xms: Option<alloc::boxed::Box<XmsState>>,
    pub ems: Option<alloc::boxed::Box<EmsState>>,
    pub hma_pages: [u64; HMA_PAGE_COUNT],
    pub e0_pending: bool,
    pub vga: VgaState,
    // FindFirst/FindNext search state. Stored per-thread since the full
    // resolved path doesn't fit in the 21-byte DTA reserved area. DN does
    // one active enumeration at a time.
    pub find_path: [u8; 96],
    pub find_path_len: u8,
    pub find_idx: u16,
}

impl Vm86State {
    pub fn new() -> Self {
        let mut hma_pages = [0u64; HMA_PAGE_COUNT];
        crate::kernel::startup::arch_init_hma(&mut hma_pages);
        Self {
            a20_enabled: false,
            dta: 0,
            heap_seg: 0xA000,
            dos_pending_char: None,
            last_child_exit_code: 0,
            vpit: VirtualPit::new(),
            vpic: VirtualPic::new(),
            vkbd: VirtualKeyboard::new(),
            exec_parent: None,
            skip_irq: false,
            xms: None,
            ems: None,
            hma_pages,
            e0_pending: false,
            vga: VgaState::new(),
            find_path: [0; 96],
            find_path_len: 0,
            find_idx: 0,
        }
    }
}

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
}

// ============================================================================
// Virtual hardware — per-thread PIC and keyboard emulation
// ============================================================================

const VPIC_QUEUE_SIZE: usize = 64;

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
fn normalize_vm86_scancode(dos: &mut thread::DosState, scancode: u8) -> Option<u8> {
    if scancode == 0xE0 {
        dos.vm86.e0_pending = true;
        return None;
    }
    if dos.vm86.e0_pending {
        dos.vm86.e0_pending = false;
    }
    Some(scancode)
}

fn clear_bios_keyboard_buffer() {
    write_u16(0x40, 0x1A, 0x001E);
    write_u16(0x40, 0x1C, 0x001E);
    for off in (0x1E..0x3E).step_by(2) {
        write_u16(0x40, off, 0);
    }
}

fn pop_bios_keyboard_word() -> Option<u16> {
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

fn poll_dos_console_char(dos: &mut thread::DosState) -> Option<u8> {
    let vm86 = &mut dos.vm86;
    if let Some(ch) = vm86.dos_pending_char.take() {
        return Some(ch);
    }

    let word = pop_bios_keyboard_word()?;
    let ascii = word as u8;
    let scan = (word >> 8) as u8;
    if ascii == 0 && scan != 0 {
        vm86.dos_pending_char = Some(scan);
    }
    Some(ascii)
}

// ============================================================================
// XMS (Extended Memory Specification) state
// ============================================================================

const MAX_XMS_HANDLES: usize = 16;
/// XMS address space: linear 0x110000 (after HMA) to ~0xA00000 (below VGA)
/// This is virtual address space in the VM86 process — demand paging provides backing.
const XMS_BASE: u32 = 0x110000; // after HMA (1MB + 64KB)
const XMS_END: u32 = 0x500000;  // 5MB — plenty for DOS games
const XMS_TOTAL_KB: u16 = ((XMS_END - XMS_BASE) / 1024) as u16;

/// A single XMS handle — contiguous range in VM86 linear address space
struct XmsHandle {
    base: u32,    // linear address
    size_kb: u16,
    locked: bool,
}

/// Per-thread XMS driver state.
/// Pure bookkeeping over the VM86 linear address space above HMA.
/// Physical backing is provided by the kernel's demand paging.
pub struct XmsState {
    handles: [Option<XmsHandle>; MAX_XMS_HANDLES],
    a20_local: u16,
    a20_global: u16,
}

impl XmsState {
    fn new() -> Self {
        const NONE: Option<XmsHandle> = None;
        Self { handles: [NONE; MAX_XMS_HANDLES], a20_local: 0, a20_global: 0 }
    }

    /// Find a contiguous free region of `size` bytes. Returns linear address or None.
    fn find_free(&self, size: u32) -> Option<u32> {
        if size == 0 { return Some(XMS_BASE); }

        // Collect allocated ranges, sorted by base
        let mut ranges: [(u32, u32); MAX_XMS_HANDLES] = [(0, 0); MAX_XMS_HANDLES];
        let mut count = 0;
        for h in &self.handles {
            if let Some(h) = h {
                ranges[count] = (h.base, h.size_kb as u32 * 1024);
                count += 1;
            }
        }
        for i in 1..count {
            let mut j = i;
            while j > 0 && ranges[j].0 < ranges[j - 1].0 {
                ranges.swap(j, j - 1);
                j -= 1;
            }
        }

        let mut start = XMS_BASE;
        for i in 0..count {
            let gap = ranges[i].0.saturating_sub(start);
            if gap >= size { return Some(start); }
            start = ranges[i].0 + ranges[i].1;
        }
        if XMS_END.saturating_sub(start) >= size { return Some(start); }
        None
    }

    fn free_kb(&self) -> u16 {
        let mut used: u32 = 0;
        for h in &self.handles {
            if let Some(h) = h {
                used += h.size_kb as u32;
            }
        }
        XMS_TOTAL_KB.saturating_sub(used as u16)
    }

    fn largest_free_kb(&self) -> u16 {
        let mut ranges: [(u32, u32); MAX_XMS_HANDLES] = [(0, 0); MAX_XMS_HANDLES];
        let mut count = 0;
        for h in &self.handles {
            if let Some(h) = h {
                ranges[count] = (h.base, h.size_kb as u32 * 1024);
                count += 1;
            }
        }
        for i in 1..count {
            let mut j = i;
            while j > 0 && ranges[j].0 < ranges[j - 1].0 {
                ranges.swap(j, j - 1);
                j -= 1;
            }
        }
        let mut largest = 0u32;
        let mut start = XMS_BASE;
        for i in 0..count {
            let gap = ranges[i].0.saturating_sub(start);
            if gap > largest { largest = gap; }
            start = ranges[i].0 + ranges[i].1;
        }
        let gap = XMS_END.saturating_sub(start);
        if gap > largest { largest = gap; }
        (largest / 1024) as u16
    }
}

// ============================================================================
// UMA (Upper Memory Area) scan and UMB allocation
// ============================================================================

/// UMA covers pages 0xC0-0xEF (192KB). Pages 0xF0-0xFF are always BIOS ROM.
const UMA_BASE: usize = 0xC0;
const UMA_END: usize = 0xF0;
const UMA_PAGES: usize = UMA_END - UMA_BASE; // 48

/// Bitmap of free pages in UMA (bit i = page UMA_BASE+i). 1=free, 0=ROM/reserved.
/// Set by scan_uma(), then EMS claims 16 pages, rest available for UMB.
static mut UMA_FREE: u64 = 0;

/// Bitmap of UMB-allocated pages (subset of UMA_FREE). 1=allocated by UMB, 0=free.
static mut UMB_ALLOC: u64 = 0;

/// Bitmap of pages reserved for EMS (16 pages for 64KB page frame).
static mut EMS_PAGES: u64 = 0;

/// EMS page frame base page (set by scan_uma)
static mut EMS_BASE_PAGE: usize = 0xD0;

/// Scan UMA to find free pages. A page is "free" if all bytes are 0x00 or 0xFF.
pub fn scan_uma() {
    let mut free: u64 = 0;
    for i in 0..UMA_PAGES {
        let base = ((UMA_BASE + i) * 0x1000) as *const u8;
        let first = unsafe { *base };
        let mut uniform = true;
        for j in 1..0x1000 {
            if unsafe { *base.add(j) } != first { uniform = false; break; }
        }
        if uniform && (first == 0x00 || first == 0xFF) {
            free |= 1 << i;
        }
    }
    unsafe { UMA_FREE = free; }

    // EMS disabled: needs arch-layer phys page management
    // let ems_offset = find_contiguous_run(free, 16, 0xD0 - UMA_BASE);
    // if let Some(off) = ems_offset { ... }

    // Log results
    let umb_free = unsafe { UMA_FREE };
    let ems_base = unsafe { EMS_BASE_PAGE };
    let mut umb_count = 0u32;
    let mut t = umb_free;
    while t != 0 { umb_count += 1; t &= t - 1; }
    dbg_println!("UMA: EMS frame at {:05X}, UMB {}KB free", ems_base * 0x1000, umb_count * 4);
}

/// Find `count` contiguous set bits in `bitmap`, preferring `hint` offset.
fn find_contiguous_run(bitmap: u64, count: usize, hint: usize) -> Option<usize> {
    // Try starting at hint first
    if hint + count <= UMA_PAGES {
        let mask = ((1u64 << count) - 1) << hint;
        if bitmap & mask == mask { return Some(hint); }
    }
    // Scan from start
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if bitmap & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= count { return Some(run_start); }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Get UMB-available bitmap (free pages minus EMS minus already allocated)
fn umb_avail() -> u64 {
    unsafe { UMA_FREE & !UMB_ALLOC }
}

/// Allocate a UMB of at least `paragraphs` size (1 paragraph = 16 bytes).
/// Returns (segment, paragraphs_allocated) or None.
fn umb_alloc(paragraphs: u16) -> Option<(u16, u16)> {
    let pages_needed = ((paragraphs as usize) * 16 + 0xFFF) / 0x1000;
    if pages_needed == 0 { return None; }

    let avail = umb_avail();
    // First-fit contiguous run
    let mut run_start = 0;
    let mut run_len = 0;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len >= pages_needed {
                let mut alloc_mask = 0u64;
                for j in run_start..run_start + pages_needed {
                    alloc_mask |= 1 << j;
                }
                unsafe { UMB_ALLOC |= alloc_mask; }
                let base_page = UMA_BASE + run_start;
                crate::kernel::startup::arch_map_umb(base_page, pages_needed);
                let seg = (base_page as u16) * 0x100; // page to segment
                let paras = (pages_needed as u16) * 0x100;
                return Some((seg, paras));
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Free a UMB by segment address.
fn umb_free(segment: u16) -> bool {
    let page = (segment / 0x100) as usize;
    if page < UMA_BASE || page >= UMA_END { return false; }
    let offset = page - UMA_BASE;

    let alloc = unsafe { UMB_ALLOC };
    if alloc & (1 << offset) == 0 { return false; }

    // Free contiguous run starting at offset
    let mut mask = 0u64;
    let mut i = offset;
    while i < UMA_PAGES && alloc & (1 << i) != 0 {
        mask |= 1 << i;
        i += 1;
    }
    let count = (i - offset) as usize;
    unsafe { UMB_ALLOC &= !mask; }
    crate::kernel::startup::arch_unmap_umb(page, count);
    true
}

/// Largest free UMB in paragraphs.
fn umb_largest() -> u16 {
    let avail = umb_avail();
    let mut largest = 0usize;
    let mut run = 0usize;
    for i in 0..UMA_PAGES {
        if avail & (1 << i) != 0 {
            run += 1;
            if run > largest { largest = run; }
        } else {
            run = 0;
        }
    }
    (largest as u16) * 0x100
}

// ============================================================================
// EMS (Expanded Memory Specification) state
// ============================================================================

const MAX_EMS_HANDLES: usize = 16;
/// Total EMS pages available (256 × 16KB = 4MB)
const EMS_TOTAL_PAGES: u16 = 256;
/// EMS page frame segment — set dynamically by scan_uma()
pub fn ems_frame_seg() -> u16 {
    (unsafe { EMS_BASE_PAGE } as u16) * 0x100
}

fn ems_base_page() -> usize {
    unsafe { EMS_BASE_PAGE }
}

/// Per-thread EMS driver state
pub struct EmsState {
    /// Each handle: list of physical page groups (4 physical pages per EMS page)
    handles: [Option<EmsHandle>; MAX_EMS_HANDLES],
    /// Current mapping: handles[window].0 = handle, .1 = logical page (None = unmapped)
    frame: [Option<(u8, u16)>; 4],
}

struct EmsHandle {
    /// Physical page numbers for each logical page (4 contiguous phys pages per EMS page)
    pages: alloc::vec::Vec<[u64; 4]>,
}

impl EmsState {
    fn new() -> Self {
        const NONE_H: Option<EmsHandle> = None;
        Self { handles: [NONE_H; MAX_EMS_HANDLES], frame: [None; 4] }
    }

    fn alloc_pages(&self) -> u16 {
        let mut used: u16 = 0;
        for h in &self.handles {
            if let Some(h) = h {
                used += h.pages.len() as u16;
            }
        }
        EMS_TOTAL_PAGES.saturating_sub(used)
    }

    /// Free all physical pages held by all handles
    pub fn free_all_pages(&mut self) {
        // EMS disabled: no physical pages to free
    }
}

// ============================================================================
// Virtual I/O port emulation
// ============================================================================

/// Emulate IN from a port.
pub(crate) fn emulate_inb(dos: &mut thread::DosState, port: u16) -> u8 {
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
            unsafe { VGA_AC_FLIPFLOP = true; }
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
        0x20 => dos.vm86.vpic.isr,
        // Master PIC data (read IMR)
        0x21 => dos.vm86.vpic.imr,
        // Keyboard data port — returns current scancode from the virtual 8042.
        0x60 => dos.vm86.vkbd.read_port60(),
        // Keyboard controller / speaker port used by BIOS IRQ1 acknowledge sequence.
        0x61 => dos.vm86.vkbd.read_port61(),
        // Keyboard status port (bit 0 = output buffer full)
        0x64 => if dos.vm86.vkbd.has_data() { 1 } else { 0 },
        0x40 => dos.vm86.vpit.read_counter0(),
        0x41 | 0x42 => 0,
        // PIT command register not readable
        0x43 => 0xFF,
        // Unknown ports: return 0xFF (unpopulated bus)
        _ => 0xFF,
    }
}

/// Emulate OUT to a port.
pub(crate) fn emulate_outb(dos: &mut thread::DosState, port: u16, val: u8) {
    match port {
        // VGA ports — pass through to hardware, track AC flip-flop + index
        0x3C0 => {
            unsafe {
                if VGA_AC_FLIPFLOP {
                    VGA_AC_INDEX = val; // index write
                }
                VGA_AC_FLIPFLOP = !VGA_AC_FLIPFLOP;
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
                let keyboard_in_service = dos.vm86.vpic.isr & 0x02 != 0;
                dos.vm86.vpic.eoi();
                // Real hardware effectively re-asserts IRQ1 if more scancodes are
                // already visible in the controller when the handler finishes.
                if keyboard_in_service
                    && dos.vm86.vkbd.has_data()
                    && !dos.vm86.vpic.has_pending_vec(0x09)
                {
                    dos.vm86.vpic.push(0x09);
                }
            }
        }
        // Master PIC data (write IMR)
        0x21 => dos.vm86.vpic.imr = val,
        // Slave PIC command / data
        0xA0 | 0xA1 => {}
        // Keyboard controller / speaker port
        0x61 => dos.vm86.vkbd.write_port61(val),
        // Keyboard controller command
        0x64 => {}
        0x43 => dos.vm86.vpit.write_command(val),
        0x40 => dos.vm86.vpit.write_counter0(val),
        0x41 | 0x42 => {}
        // Unknown ports: silently ignore (BIOS probes various ports during mode switches)
        _ => {}
    }
}

// ============================================================================
// Signal delivery — buffer hardware events and raise virtual interrupts
// ============================================================================

/// Buffer a hardware event into the virtual PIC / keyboard buffer.
/// Mode-independent: both VM86 and DPMI share the same virtual devices.
pub fn queue_irq(dos: &mut thread::DosState, event: crate::arch::Irq) {
    use crate::arch::Irq;
    match event {
        Irq::Key(sc) => {
            let Some(sc) = normalize_vm86_scancode(dos, sc) else { return };
            dos.vm86.vkbd.push(sc);
            if dos.vm86.vpic.isr & 0x02 == 0 && !dos.vm86.vpic.has_pending_vec(0x09) {
                dos.vm86.vpic.push(0x09);
            }
        }
        Irq::Tick => {
            let due = dos.vm86.vpit.take_pending_irqs();
            for _ in 0..due {
                dos.vm86.vpic.push(0x08);
            }
        }
    }
}

/// Try to deliver one pending interrupt from the virtual PIC.
/// IF is the virtual interrupt flag (arch swaps VIF↔IF at ring 3 boundary).
/// Works for both VM86 (IVT reflect) and DPMI (PM vector dispatch).
pub fn raise_pending(dos: &mut thread::DosState, regs: &mut Regs) {
    let vif = regs.frame.rflags & (1u64 << 9) != 0; // IF = virtual interrupt flag
    let is_pm = regs.mode() != crate::UserMode::VM86;
    if !vif && !is_pm {
        if dos.vm86.vpic.has_pending() {
            regs.frame.rflags |= 1u64 << 20; // VIP
        }
        return;
    }
    if dos.vm86.vpic.isr != 0 {
        return;
    }
    let vec = match dos.vm86.vpic.pop() {
        Some(v) => v,
        None => return,
    };
    if vec == 0x09 {
        if !dos.vm86.vkbd.latch() {
            dos.vm86.vpic.push(0x09);
            return;
        }
    }
    let irq_num = vec.wrapping_sub(8);
    if irq_num < 8 {
        dos.vm86.vpic.isr |= 1 << irq_num;
    }
    // Clear VIP — interrupt is being serviced
    regs.frame.rflags &= !(1u64 << 20);

    if regs.mode() == crate::UserMode::VM86 {
        reflect_interrupt(regs, vec);
    } else {
        crate::kernel::dpmi::deliver_hw_irq(dos, regs, vec);
    }
}


/// Reflect an interrupt through the IVT: push FLAGS/CS/IP, clear IF, set CS:IP.
fn reflect_interrupt(regs: &mut Regs, int_num: u8) {
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
// VM86 monitor — handles GP faults for sensitive instructions
//
// With IOPL=0 all I/O traps here regardless of IOPB.
// VGA ports (0x3C0-0x3DF) are passed through to hardware.
// PIC/keyboard are virtualized. Other ports: IN returns 0xFF, OUT is no-op.
// ============================================================================

/// Read a byte from the VM86 address space at CS:IP and advance IP
fn fetch_byte(regs: &mut Regs) -> u8 {
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
pub(crate) fn read_u16(seg: u32, off: u32) -> u16 {
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
pub(crate) fn write_u16(seg: u32, off: u32, val: u16) {
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
fn vm86_push32(regs: &mut Regs, val: u32) {
    vm86_push(regs, (val >> 16) as u16);
    vm86_push(regs, val as u16);
}

/// Pop a u32 from the VM86 stack (SS:SP) as two 16-bit halves
fn vm86_pop32(regs: &mut Regs) -> u32 {
    let lo = vm86_pop(regs) as u32;
    let hi = vm86_pop(regs) as u32;
    (hi << 16) | lo
}

/// Push a u16 onto the VM86 stack (SS:SP)
pub(crate) fn vm86_push(regs: &mut Regs, val: u16) {
    let sp = vm86_sp(regs).wrapping_sub(2);
    set_vm86_sp(regs, sp);
    write_u16(regs.ss32(), sp as u32, val);
}

/// Pop a u16 from the VM86 stack (SS:SP)
pub(crate) fn vm86_pop(regs: &mut Regs) -> u16 {
    let sp = vm86_sp(regs);
    let val = read_u16(regs.ss32(), sp as u32);
    set_vm86_sp(regs, sp.wrapping_add(2));
    val
}

/// VM86 monitor — called from GP fault handler when EFLAGS.VM=1.
/// Arch boundary swaps VIF↔IF, so IF is the virtual interrupt flag throughout.
pub fn vm86_monitor(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let opcode = fetch_byte(regs);

    match opcode {
        // INT n (0xCD nn)
        0xCD => {
            let int_num = fetch_byte(regs);
            handle_vm86_int(dos, regs, int_num)
        }
        // INT3 (0xCC) — single-byte software interrupt
        0xCC => {
            handle_vm86_int(dos, regs, 0x03)
        }
        // INTO (0xCE) — software interrupt on overflow
        0xCE => {
            if vm86_flags(regs) & (1 << 11) != 0 {
                handle_vm86_int(dos, regs, 0x04)
            } else {
                thread::KernelAction::Done
            }
        }
        // INT1 / ICEBP (0xF1) — single-byte software interrupt
        0xF1 => {
            handle_vm86_int(dos, regs, 0x01)
        }
        // IRET (0xCF) — pop IP, CS, FLAGS from VM86 stack
        // IOPL and VM are preserved (VM86 code cannot change them)
        0xCF => {
            let ip = vm86_pop(regs);
            let cs = vm86_pop(regs);
            let flags = vm86_pop(regs);
            set_vm86_ip(regs, ip);
            set_vm86_cs(regs, cs);
            let preserved = vm86_flags(regs) & PRESERVED_FLAGS;
            set_vm86_flags(regs, (flags as u32 & !PRESERVED_FLAGS) | preserved);
            thread::KernelAction::Done
        }
        // CLI (0xFA)
        0xFA => {
            regs.clear_flag32(IF_FLAG);
            thread::KernelAction::Done
        }
        // STI (0xFB)
        0xFB => {
            regs.set_flag32(IF_FLAG);
            thread::KernelAction::Done
        }
        // PUSHF (0x9C) — push FLAGS (IF already reflects VIF)
        0x9C => {
            vm86_push(regs, vm86_flags(regs) as u16);
            thread::KernelAction::Done
        }
        // POPF (0x9D) — pop FLAGS
        // IOPL and VM are preserved (VM86 code cannot change them)
        0x9D => {
            let flags = vm86_pop(regs);
            let preserved = vm86_flags(regs) & PRESERVED_FLAGS;
            set_vm86_flags(regs, (flags as u32 & !PRESERVED_FLAGS) | preserved);
            thread::KernelAction::Done
        }
        // INSB (0x6C) — IN byte from port DX to ES:DI, advance DI
        0x6C => {
            let port = regs.rdx as u16;
            let val = emulate_inb(dos, port);
            write_u16(regs.es as u32, regs.rdi as u32, val as u16);
            if vm86_flags(regs) & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(1); // DF=1
            } else {
                regs.rdi = regs.rdi.wrapping_add(1);
            }
            thread::KernelAction::Done
        }
        // INSW (0x6D) — IN word from port DX to ES:DI, advance DI
        0x6D => {
            let port = regs.rdx as u16;
            let lo = emulate_inb(dos, port);
            let hi = emulate_inb(dos, port + 1);
            let val = (hi as u16) << 8 | lo as u16;
            write_u16(regs.es as u32, regs.rdi as u32, val);
            if vm86_flags(regs) & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(2);
            } else {
                regs.rdi = regs.rdi.wrapping_add(2);
            }
            thread::KernelAction::Done
        }
        // OUTSB (0x6E) — OUT byte from DS:SI to port DX, advance SI
        0x6E => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32) as u8;
            emulate_outb(dos, port, val);
            if vm86_flags(regs) & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(1);
            } else {
                regs.rsi = regs.rsi.wrapping_add(1);
            }
            thread::KernelAction::Done
        }
        // OUTSW (0x6F) — OUT word from DS:SI to port DX, advance SI
        0x6F => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32);
            emulate_outb(dos, port, val as u8);
            emulate_outb(dos, port + 1, (val >> 8) as u8);
            if vm86_flags(regs) & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(2);
            } else {
                regs.rsi = regs.rsi.wrapping_add(2);
            }
            thread::KernelAction::Done
        }
        // IN AL, imm8 (0xE4)
        0xE4 => {
            let port = fetch_byte(regs) as u16;
            let val = emulate_inb(dos, port);
            regs.rax = (regs.rax & !0xFF) | val as u64;
            thread::KernelAction::Done
        }
        // IN AX, imm8 (0xE5)
        0xE5 => {
            let port = fetch_byte(regs) as u16;
            let lo = emulate_inb(dos, port);
            let hi = emulate_inb(dos, port + 1);
            regs.rax = (regs.rax & !0xFFFF) | (hi as u64) << 8 | lo as u64;
            thread::KernelAction::Done
        }
        // OUT imm8, AL (0xE6)
        0xE6 => {
            let port = fetch_byte(regs) as u16;
            emulate_outb(dos, port, regs.rax as u8);
            thread::KernelAction::Done
        }
        // OUT imm8, AX (0xE7)
        0xE7 => {
            let port = fetch_byte(regs) as u16;
            let val = regs.rax as u16;
            emulate_outb(dos, port, val as u8);
            emulate_outb(dos, port + 1, (val >> 8) as u8);
            thread::KernelAction::Done
        }
        // IN AL, DX (0xEC)
        0xEC => {
            let port = regs.rdx as u16;
            let val = emulate_inb(dos, port);
            regs.rax = (regs.rax & !0xFF) | val as u64;
            thread::KernelAction::Done
        }
        // IN AX, DX (0xED)
        0xED => {
            let port = regs.rdx as u16;
            let lo = emulate_inb(dos, port);
            let hi = emulate_inb(dos, port + 1);
            regs.rax = (regs.rax & !0xFFFF) | (hi as u64) << 8 | lo as u64;
            thread::KernelAction::Done
        }
        // OUT DX, AL (0xEE)
        0xEE => {
            let port = regs.rdx as u16;
            emulate_outb(dos, port, regs.rax as u8);
            thread::KernelAction::Done
        }
        // OUT DX, AX (0xEF)
        0xEF => {
            let port = regs.rdx as u16;
            let val = regs.rax as u16;
            emulate_outb(dos, port, val as u8);
            emulate_outb(dos, port + 1, (val >> 8) as u8);
            thread::KernelAction::Done
        }
        // 0x66 prefix — operand-size override (32-bit in VM86 16-bit mode)
        0x66 => {
            let op = fetch_byte(regs);
            match op {
                // PUSHFD — push 32-bit EFLAGS
                0x9C => {
                    vm86_push32(regs, vm86_flags(regs) & 0xFFFF);
                    thread::KernelAction::Done
                }
                // POPFD — pop 32-bit EFLAGS
                0x9D => {
                    let flags = vm86_pop32(regs);
                    let preserved = vm86_flags(regs) & PRESERVED_FLAGS;
                    set_vm86_flags(regs, (flags & !PRESERVED_FLAGS) | preserved);
                    thread::KernelAction::Done
                }
                // IRETD — pop 32-bit EIP, CS, EFLAGS
                0xCF => {
                    let eip = vm86_pop32(regs);
                    let cs = vm86_pop32(regs);
                    let flags = vm86_pop32(regs);
                    regs.set_ip32(eip);
                    regs.set_cs32(cs & 0xFFFF);
                    let preserved = vm86_flags(regs) & PRESERVED_FLAGS;
                    set_vm86_flags(regs, (flags & !PRESERVED_FLAGS) | preserved);
                    thread::KernelAction::Done
                }
                // IN EAX, imm8
                0xE5 => {
                    let port = fetch_byte(regs) as u16;
                    let b0 = emulate_inb(dos, port);
                    let b1 = emulate_inb(dos, port + 1);
                    let b2 = emulate_inb(dos, port + 2);
                    let b3 = emulate_inb(dos, port + 3);
                    regs.rax = (regs.rax & !0xFFFFFFFF) | (b3 as u64) << 24 | (b2 as u64) << 16 | (b1 as u64) << 8 | b0 as u64;
                    thread::KernelAction::Done
                }
                // OUT imm8, EAX
                0xE7 => {
                    let port = fetch_byte(regs) as u16;
                    let val = regs.rax as u32;
                    emulate_outb(dos, port, val as u8);
                    emulate_outb(dos, port + 1, (val >> 8) as u8);
                    emulate_outb(dos, port + 2, (val >> 16) as u8);
                    emulate_outb(dos, port + 3, (val >> 24) as u8);
                    thread::KernelAction::Done
                }
                // IN EAX, DX
                0xED => {
                    let port = regs.rdx as u16;
                    let b0 = emulate_inb(dos, port);
                    let b1 = emulate_inb(dos, port + 1);
                    let b2 = emulate_inb(dos, port + 2);
                    let b3 = emulate_inb(dos, port + 3);
                    regs.rax = (regs.rax & !0xFFFFFFFF) | (b3 as u64) << 24 | (b2 as u64) << 16 | (b1 as u64) << 8 | b0 as u64;
                    thread::KernelAction::Done
                }
                // OUT DX, EAX
                0xEF => {
                    let port = regs.rdx as u16;
                    let val = regs.rax as u32;
                    emulate_outb(dos, port, val as u8);
                    emulate_outb(dos, port + 1, (val >> 8) as u8);
                    emulate_outb(dos, port + 2, (val >> 16) as u8);
                    emulate_outb(dos, port + 3, (val >> 24) as u8);
                    thread::KernelAction::Done
                }
                // INSD
                0x6D => {
                    let port = regs.rdx as u16;
                    let b0 = emulate_inb(dos, port);
                    let b1 = emulate_inb(dos, port);
                    let b2 = emulate_inb(dos, port);
                    let b3 = emulate_inb(dos, port);
                    let addr = (regs.es as u32) * 16 + (regs.rdi as u16 as u32);
                    unsafe {
                        *(addr as *mut u8) = b0;
                        *((addr + 1) as *mut u8) = b1;
                        *((addr + 2) as *mut u8) = b2;
                        *((addr + 3) as *mut u8) = b3;
                    }
                    if vm86_flags(regs) & (1 << 10) != 0 {
                        regs.rdi = regs.rdi.wrapping_sub(4);
                    } else {
                        regs.rdi = regs.rdi.wrapping_add(4);
                    }
                    thread::KernelAction::Done
                }
                // OUTSD
                0x6F => {
                    let port = regs.rdx as u16;
                    let addr = (regs.ds as u32) * 16 + (regs.rsi as u16 as u32);
                    unsafe {
                        emulate_outb(dos, port, *(addr as *const u8));
                        emulate_outb(dos, port, *((addr + 1) as *const u8));
                        emulate_outb(dos, port, *((addr + 2) as *const u8));
                        emulate_outb(dos, port, *((addr + 3) as *const u8));
                    }
                    if vm86_flags(regs) & (1 << 10) != 0 {
                        regs.rsi = regs.rsi.wrapping_sub(4);
                    } else {
                        regs.rsi = regs.rsi.wrapping_add(4);
                    }
                    thread::KernelAction::Done
                }
                _ => {
                    crate::println!("VM86: FATAL unhandled opcode 0x66 {:#04x} at {:04x}:{:04x}",
                        op, vm86_cs(regs), regs.ip32().wrapping_sub(2));
                    thread::KernelAction::Exit(-11)
                }
            }
        }
        // HLT (0xF4) — yield to another thread
        0xF4 => {
            thread::KernelAction::Yield
        }
        _ => {
            let fault_ip = regs.ip32().wrapping_sub(1);
            let lin = (vm86_cs(regs) as u32) * 16 + fault_ip as u32;
            let next_bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8.min(0x10_0000u32.saturating_sub(lin) as usize)) };
            crate::println!("VM86: FATAL unhandled opcode {:#04x} at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x?}] SS:SP={:04x}:{:04x} flags={:#x}",
                opcode, vm86_cs(regs), fault_ip, lin, next_bytes,
                vm86_ss(regs), vm86_sp(regs), vm86_flags(regs));
            // Dump top of VM86 stack
            let ss = vm86_ss(regs) as u32;
            let sp = vm86_sp(regs) as u32;
            crate::println!("  stack: [{:04x} {:04x} {:04x} {:04x} {:04x} {:04x}]",
                read_u16(ss, sp), read_u16(ss, sp+2), read_u16(ss, sp+4),
                read_u16(ss, sp+6), read_u16(ss, sp+8), read_u16(ss, sp+10));
            // Kill the VM86 thread
            thread::KernelAction::Exit(-11)
        }
    }
}

// ============================================================================
// INT dispatch — intercept DOS/BIOS calls, reflect others via IVT
// ============================================================================

/// Handle INT n from VM86 mode.
/// With VME, only INTs whose bit is SET in the redirection bitmap trap here.
/// Without VME, all INTs trap — unintercepted ones are reflected through IVT.
fn handle_vm86_int(dos: &mut thread::DosState, regs: &mut Regs, int_num: u8) -> thread::KernelAction {
    if !crate::arch::int_intercepted(int_num) {
        reflect_interrupt(regs, int_num);
        return thread::KernelAction::Done;
    }
    match int_num {
        // INT 31h — unified stub dispatch (all intercepted INTs route through
        // IVT stubs that call INT 31h; dispatch by slot number)
        STUB_INT => stub_dispatch(dos, regs),
        _ => {
            panic!("VM86: INT {:02X} intercepted in bitmap but has no handler", int_num);
        }
    }
}

// ============================================================================
// Stub dispatch — routes INT 31h from unified CD 31 array by slot number
// ============================================================================

/// Dispatch INT 31h from the unified stub array. Slot = (IP - 2) / 2.
/// IVT-redirect stubs have a FLAGS/CS/IP frame on the VM86 stack from the
/// original INT; far-call stubs have a CS/IP frame from CALL FAR.
/// The kernel pops these frames directly — no RETF/RETF 2 in the stub.
fn stub_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    let cs = vm86_cs(regs);

    // INT 31h from user code (outside the stub segment) = synth syscall.
    // AH selects the subfunction. Unknown subfunctions fall through to IVT reflect.
    if cs != STUB_SEG {
        return synth_dispatch(dos, regs);
    }

    let slot = ((ip.wrapping_sub(2)) / 2) as u8;
    let is_far_call = matches!(slot,
        SLOT_XMS | SLOT_DPMI_ENTRY | SLOT_CALLBACK_RET | SLOT_RAW_REAL_TO_PM | SLOT_SAVE_RESTORE)
        || (slot >= SLOT_CB_ENTRY_BASE && slot < SLOT_CB_ENTRY_END);

    // IVT-redirect stubs: the original INT pushed FLAGS/CS/IP on the VM86 stack.
    // Restore IF from those saved FLAGS (IF is the virtual interrupt flag).
    if !is_far_call {
        let saved_flags = read_u16(vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4));
        if saved_flags as u32 & IF_FLAG != 0 {
            regs.set_flag32(IF_FLAG);
        } else {
            regs.clear_flag32(IF_FLAG);
        }
    }

    let action = match slot {
        SLOT_XMS => xms_dispatch(dos, regs),
        SLOT_DPMI_ENTRY => {
            crate::kernel::dpmi::dpmi_enter(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CALLBACK_RET => {
            crate::kernel::dpmi::callback_return(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RAW_REAL_TO_PM => {
            crate::kernel::dpmi::raw_switch_real_to_pm(dos, regs);
            thread::KernelAction::Done
        }
        s if s >= SLOT_CB_ENTRY_BASE && s < SLOT_CB_ENTRY_END => {
            let cb_idx = (s - SLOT_CB_ENTRY_BASE) as usize;
            crate::kernel::dpmi::callback_entry(dos, regs, cb_idx);
            thread::KernelAction::Done
        }
        0x13 => int_13h(regs),
        0x20 => {
            // INT 20h — DOS program terminate
            if let Some(parent) = dos.vm86.exec_parent.take() {
                dos.vm86.last_child_exit_code = 0;
                return exec_return(dos, regs, parent);
            }
            thread::KernelAction::Exit(0)
        }
        0x21 => int_21h(dos, regs),
        // INT 25h/26h — Absolute Disk Read/Write — return error
        0x25 | 0x26 => {
            regs.rax = (regs.rax & !0xFF00) | (0x02 << 8); // AH=02 address mark not found
            regs.set_flag32(1); // CF=1 error
            thread::KernelAction::Done
        }
        0x28 => thread::KernelAction::Done, // INT 28h — DOS idle
        0x2E => int_2eh(dos, regs),
        0x2F => int_2fh(dos, regs),
        SLOT_SAVE_RESTORE => thread::KernelAction::Done, // no-op far call (buffer size=0)
        _ => {
            panic!("VM86: INT 31h from unknown stub slot {:#04x} IP={:#06x}", slot, ip);
        }
    };

    // Pop the VM86 stack frame left by the caller before returning.
    // IVT-redirect: original INT pushed FLAGS/CS/IP (6 bytes) — pop and return to caller.
    // Far-call (XMS): CALL FAR pushed CS/IP (4 bytes) — pop and return to caller.
    // Mode-switching stubs (DPMI entry, raw switch, callbacks) replace all regs — skip.
    if !is_far_call {
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        let _flags = vm86_pop(regs); // discard (equivalent to old RETF 2)
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
    } else if matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE) {
        // Returns to caller — pop far-call return address
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
    }
    // Other far-call stubs (DPMI entry, raw switch, callbacks) switch modes entirely

    action
}

// ============================================================================
// Synth syscalls — invoked by user-code INT 31h (outside STUB_SEG).
// Modeled as a tiny set of primitives that COMMAND.COM (or any program)
// can call to coordinate processes + VGA across threads.
// ============================================================================

/// INT 31h from user code. AH selects subfunction.
/// On success: AX=0, CF=0. On error: AX=errno (unsigned), CF=1.
/// Unknown AH reflects through IVT (legacy DPMI int-31 path).
fn synth_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — SYNTH_VGA_TAKE: adopt target thread's screen.
        // Input:  BX = target pid
        // Output: AX = 0 on success, errno on failure; CF reflects error.
        0x00 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            let rv = thread::vga_take(&mut dos.vm86.vga, pid);
            regs.rax = (regs.rax & !0xFFFF) | ((rv as i16 as u16) as u64);
            if rv < 0 { regs.set_flag32(1); } else { regs.clear_flag32(1); }
            thread::KernelAction::Done
        }
        // AH=01h — SYNTH_FORK_EXEC_WAIT: fork+exec program and wait for it.
        // Reads the caller's own PSP cmdline at DS:0080h (byte-count + text),
        // strips leading whitespace and an optional "/C", takes the first
        // whitespace-delimited token as the program name.
        // Output on success (CF=0):
        //          BX = child pid (valid in both exit and decoupled cases)
        //          AX = 0 on normal exit (exit code via INT 21h/4Dh)
        //          AX = 1 on decoupled (F11 broke wait)
        // Output on error (CF=1):
        //          AX = errno
        0x01 => {
            let psp = (regs.ds as u16 as u32) << 4;
            let tail_len = unsafe { *((psp + 0x80) as *const u8) } as usize;
            let read = |i: usize| -> u8 {
                unsafe { *((psp + 0x81 + i as u32) as *const u8) }
            };
            let mut i = 0;
            while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            if i + 1 < tail_len && read(i) == b'/' && (read(i + 1) & 0xDF) == b'C' {
                i += 2;
                while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            }
            let mut filename = [0u8; 128];
            let mut flen = 0;
            while i < tail_len && flen < 127 {
                let c = read(i);
                if matches!(c, b' ' | b'\t' | b'\r' | 0) { break; }
                filename[flen] = c;
                flen += 1;
                i += 1;
            }
            if flen == 0 {
                regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
            let flen = dos_normalize_path(&mut filename, flen);
            // If the name is a .BAT, expand to its first executable command.
            let flen = expand_bat(dos, &mut filename, flen);
            fork_exec(dos, &filename[..flen])
        }
        // Unknown AH: reflect through IVT for legacy/DPMI compatibility.
        _ => {
            reflect_interrupt(regs, 0x31);
            thread::KernelAction::Done
        }
    }
}

// ============================================================================
// BIOS INT 13h — Disk services
// ============================================================================

fn int_13h(regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let dl = regs.rdx as u8; // drive number
    // For floppy drives (DL < 0x80), return "drive not ready" error.
    // Hard drives (DL >= 0x80) are also unsupported — return error.
    match ah {
        // AH=00h Reset Disk — just succeed
        0x00 => {
            regs.rax = regs.rax & !0xFF00; // AH=0 success
            regs.clear_flag32(1);
        }
        // AH=08h Get Drive Parameters
        0x08 => {
            if dl < 0x80 {
                // No floppy drives
                regs.rax = (regs.rax & !0xFF00) | (0x07 << 8); // AH=07 drive parameter activity failed
                regs.set_flag32(1);
            } else {
                // Report a minimal hard drive geometry
                regs.rax = (regs.rax & !0xFF00); // AH=0 success
                regs.rbx = (regs.rbx & !0xFF) | 0; // BL=drive type (0 for HD)
                regs.rcx = (regs.rcx & !0xFFFF) | ((32 << 8) | 63); // CH=max cyl low, CL=max sect
                regs.rdx = (regs.rdx & !0xFFFF) | ((1 << 8) | 1); // DH=max head, DL=number of drives
                regs.clear_flag32(1);
            }
        }
        // AH=15h Get Disk Type
        0x15 => {
            if dl < 0x80 {
                // No floppy: AH=0 means "no such drive"
                regs.rax = regs.rax & !0xFF00;
                regs.set_flag32(1);
            } else {
                // Hard disk present
                regs.rax = (regs.rax & !0xFF00) | (0x03 << 8); // AH=03 = hard disk
                regs.clear_flag32(1);
            }
        }
        _ => {
            // All other functions: return error (drive not ready)
            regs.rax = (regs.rax & !0xFF00) | (0x80 << 8); // AH=80h timeout/not ready
            regs.set_flag32(1);
        }
    }
    thread::KernelAction::Done
}

/// DOS character output — writes via VGA putchar and syncs the BDA cursor
/// position at 0040:0050 so BIOS and programs (like DN) that read the BDA
/// cursor see the correct position.
fn dos_putchar(c: u8) {
    use crate::arch::{outb, inb};
    unsafe {
        let col = core::ptr::read_volatile(0x450 as *const u8) as usize;
        let row = core::ptr::read_volatile(0x451 as *const u8) as usize;
        // Debug: show BDA vs CRTC cursor on first printable char
        if c >= 0x20 && c < 0x7F {
            outb(0x3D4, 0x0E); let ch = inb(0x3D5);
            outb(0x3D4, 0x0F); let cl = inb(0x3D5);
            let crtc_off = (ch as u16) << 8 | cl as u16;
            crate::dbg_println!("dos_putchar '{}': BDA=({},{}) CRTC={} ({},{})",
                c as char, col, row, crtc_off, crtc_off % 80, crtc_off / 80);
        }
        let v = vga::vga();
        v.set_cursor_pos(col, row);
        v.putchar(c);
        let (col, row) = v.cursor_pos();
        core::ptr::write_volatile(0x450 as *mut u8, col as u8);
        core::ptr::write_volatile(0x451 as *mut u8, row as u8);
        // Update CRTC hardware cursor so save_from_hardware captures it
        let offset = (row * 80 + col) as u16;
        outb(0x3D4, 0x0E); outb(0x3D5, (offset >> 8) as u8);
        outb(0x3D4, 0x0F); outb(0x3D5, offset as u8);
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    if ah != 0x2C && ah != 0x2A { crate::dbg_println!("D21 {:02X} AX={:04X}", ah, regs.rax as u16); }
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            dos_putchar(regs.rdx as u8);
            thread::KernelAction::Done
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40); // clear ZF = char available
                } else {
                    regs.set_flag32(0x40); // set ZF = no char available
                }
            } else {
                dos_putchar(dl);
            }
            thread::KernelAction::Done
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            loop {
                let ch = unsafe { *(addr as *const u8) };
                if ch == b'$' { break; }
                dos_putchar(ch);
                addr += 1;
                // Safety limit
                if addr > 0xFFFFF { break; }
            }
            thread::KernelAction::Done
        }
        // AH=0x0B: Check Standard Input Status — AL=0 no char, 0xFF char ready
        0x0B => {
            regs.rax = (regs.rax & !0xFF) | 0x00; // no character available
            thread::KernelAction::Done
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            let off = regs.rdx as u16;
            let seg = regs.ds as u16;
            write_u16(0, (int_num as u32) * 4, off);
            write_u16(0, (int_num as u32) * 4 + 2, seg);
            thread::KernelAction::Done
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => { regs.rdx = (regs.rdx & !0xFF); } // DL=0: break checking off
                0x01 => {} // set break — ignore
                _ => {}
            }
            thread::KernelAction::Done
        }
        // AH=0x34: Get INDOS Flag pointer — returns ES:BX → byte that is
        // nonzero while DOS is executing. We're never "in DOS" from the
        // guest's perspective (kernel services calls synchronously), so
        // point at a permanently-zero byte inside SYSPSP.
        0x34 => {
            regs.es = SYSPSP_SEG as u64;
            regs.rbx = INDOS_FLAG_OFFSET as u64;
            thread::KernelAction::Done
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=64-byte buffer)
        // Returns ASCIIZ path without drive letter or leading backslash
        // DL: 0=default, 1=A, 2=B, 3=C
        0x47 => {
            let dl = regs.rdx as u8;
            let drive = if dl == 0 { 3 } else { dl };
            if drive != 3 {
                // Invalid drive (A:/B:)
                regs.rax = (regs.rax & !0xFFFF) | 0x0F;
                regs.set_flag32(1);
            } else {
                let si = regs.rsi as u16 as u32;
                let addr = ((regs.ds as u16 as u32) << 4) + si;
                let cwd = dos.cwd_str();
                unsafe {
                    let mut pos = 0;
                    for &b in cwd {
                        // Convert '/' to '\' for DOS, skip trailing slash
                        if b == b'/' && pos + 1 >= cwd.len() { break; }
                        *((addr + pos as u32) as *mut u8) = if b == b'/' { b'\\' } else { b };
                        pos += 1;
                    }
                    *((addr + pos as u32) as *mut u8) = 0; // NUL terminate
                }
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | 2; // C:
            thread::KernelAction::Done
        }
        // AH=0x0C: Flush input buffer then execute function in AL
        0x0C => {
            clear_bios_keyboard_buffer();
            dos.vm86.dos_pending_char = None;
            // Just execute the sub-function in AL
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40);
                } else {
                    regs.set_flag32(0x40); // ZF=1
                }
            }
            // Other sub-functions: just return
            thread::KernelAction::Done
        }
        // AH=0x0D: Disk Reset (flush buffers) — no-op on RAM-backed FS
        0x0D => {
            thread::KernelAction::Done
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
            dos.vm86.dta = dta;
            thread::KernelAction::Done
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = dos.vm86.dta;
            regs.es = (dta >> 4) as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | (dta & 0x0F) as u64;
            thread::KernelAction::Done
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 3.30
            regs.rax = (regs.rax & !0xFFFF) | 0x1E03; // AL=3 (major), AH=30 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            thread::KernelAction::Done
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            let off = read_u16(0, (int_num as u32) * 4);
            let seg = read_u16(0, (int_num as u32) * 4 + 2);
            regs.rbx = off as u64;
            regs.es = seg as u64;
            thread::KernelAction::Done
        }
        // AH=0x38: Get country information — return minimal stub
        //
        // DOS 2.x uses a 32-byte buffer; DOS 3.0+ extended it to 34 bytes.
        // Many programs (including NC 2.0) allocate only 32 bytes, so write
        // field-by-field rather than blindly zeroing 34 bytes.
        0x38 => {
            let addr = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
            unsafe {
                let p = addr as *mut u8;
                core::ptr::write_bytes(p, 0, 24); // zero first 24 bytes (through case-map)
                // +00: date format (0 = USA: mm/dd/yy)
                // +02: currency symbol '$\0\0\0\0'
                *p.add(2) = b'$';
                // +07: thousands separator ',\0'
                *p.add(7) = b',';
                // +09: decimal separator '.\0'
                *p.add(9) = b'.';
                // +0B: date separator '/\0'
                *p.add(0x0B) = b'/';
                // +0D: time separator ':\0'
                *p.add(0x0D) = b':';
            }
            regs.rbx = (regs.rbx & !0xFFFF) | 1; // country code = 1 (USA)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
            let mut path = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *((addr + i as u32) as *const u8) };
                if ch == 0 { break; }
                path[i] = ch;
                i += 1;
            }
            let i = dos_normalize_path(&mut path, i);
            let result = dos_chdir(dos, &path[..i]);
            if result < 0 {
                regs.set_flag32(1); // set CF
                regs.rax = (regs.rax & !0xFFFF) | 3; // AX=3 path not found
            } else {
                regs.clear_flag32(1); // clear CF
            }
            thread::KernelAction::Done
        }
        // AH=0x3D: Open file (DS:DX=ASCIIZ filename, AL=access mode)
        0x3D => {
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            // Check for device names (before normalization)
            if EMS_ENABLED && name[..i].eq_ignore_ascii_case(b"EMMXXXX0") {
                regs.rax = (regs.rax & !0xFFFF) | EMS_DEVICE_HANDLE as u64;
                regs.clear_flag32(1);
            } else {
                let i = dos_normalize_path(&mut name, i);
                let mut rbuf = [0u8; 164];
                let resolved = dos_resolve_path(dos, &name[..i], &mut rbuf);
                let name_str = core::str::from_utf8(resolved).unwrap_or("?");
                let fd = crate::kernel::vfs::open(resolved, &mut dos.fds);
                if fd >= 0 {
                    // Populate SFT entry and PSP JFT for this handle
                    let size = crate::kernel::vfs::file_size(fd, &dos.fds);
                    sft_set_file(fd as u16, size);
                    unsafe {
                        let psp = (COM_SEGMENT as u32 * 16) as *mut u8;
                        if (fd as usize) < 20 { *psp.add(0x34 + fd as usize) = fd as u8; }
                    }
                    regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                    regs.clear_flag32(1); // clear carry
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                    regs.set_flag32(1); // set carry
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            let handle = regs.rbx as u16;
            if handle != NULL_FILE_HANDLE && (!EMS_ENABLED || handle != EMS_DEVICE_HANDLE) {
                crate::kernel::vfs::close(handle as i32, &mut dos.fds);
                sft_clear(handle);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as u16 as i32;
            let count = regs.rcx as u16 as usize;
            let buf_addr = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
            if handle == 0 {
                // stdin — read from virtual keyboard
                // Return 0 for now (no line-buffered stdin in VM86)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == 1 || handle == 2 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — return 0 bytes (EOF)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if count == 0 || buf_addr == 0 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, count) };
                let n = crate::kernel::vfs::read(handle, buf, &dos.fds);
                if n >= 0 {
                    regs.rax = (regs.rax & !0xFFFF) | n as u64;
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => {
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            let mut raw = [0u8; 80];
            let mut raw_len = 0;
            while raw_len < 79 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                raw[raw_len] = ch;
                addr += 1;
                raw_len += 1;
            }
            // Normalize: backslash -> slash, strip drive letter
            let norm_len = dos_normalize_path(&mut raw, raw_len);
            // Resolve against cwd (handle absolute vs relative)
            let mut resolved = [0u8; 96];
            let res_len = {
                let mut rlen = 0;
                if norm_len > 0 && raw[0] == b'/' {
                    for i in 1..norm_len {
                        if rlen < resolved.len() { resolved[rlen] = raw[i]; rlen += 1; }
                    }
                } else {
                    for &b in dos.cwd_str() {
                        if rlen < resolved.len() { resolved[rlen] = b; rlen += 1; }
                    }
                    for i in 0..norm_len {
                        if rlen < resolved.len() { resolved[rlen] = raw[i]; rlen += 1; }
                    }
                }
                rlen
            };
            // Store in find state
            let store_len = res_len.min(dos.vm86.find_path.len());
            dos.vm86.find_path[..store_len].copy_from_slice(&resolved[..store_len]);
            dos.vm86.find_path_len = store_len as u8;
            dos.vm86.find_idx = 0;
            find_matching_file(dos, regs)
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            find_matching_file(dos, regs)
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            // If we're in an EXEC'd child, return to parent
            if let Some(parent) = dos.vm86.exec_parent.take() {
                dos.vm86.last_child_exit_code = regs.rax as u8;
                return exec_return(dos, regs, parent);
            }
            let code = regs.rax as u8;
            thread::KernelAction::Exit(code as i32)
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            let avail = 0xA000u16.saturating_sub(dos.vm86.heap_seg);
            if need <= avail {
                let seg = dos.vm86.heap_seg;
                dos.vm86.heap_seg += need;
                regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            // Simple bump allocator — free is a no-op
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            let es = regs.es as u16;
            let new_end32 = es as u32 + regs.rbx as u16 as u32;
            if new_end32 <= 0xA000 {
                let new_end = new_end32 as u16;
                // Program resizing its block — free memory starts after it
                dos.vm86.heap_seg = new_end;
                regs.clear_flag32(1);
            } else {
                // Not enough memory — report max available
                let avail = 0xA000u16.saturating_sub(es);
                regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x44: IOCTL (various subfunctions)
        0x44 => {
            let al = regs.rax as u8;
            match al {
                // AL=0x00: Get Device Information (BX=handle, returns DX=info word)
                0x00 => {
                    let handle = regs.rbx as u16;
                    if handle <= 2 {
                        // stdin/stdout/stderr: bit 7=1 (device), bit 0=1 (stdin), bit 1=1 (stdout)
                        let info: u16 = 0x80 | match handle {
                            0 => 0x01, // stdin
                            _ => 0x02, // stdout/stderr
                        };
                        regs.rdx = (regs.rdx & !0xFFFF) | info as u64;
                        regs.clear_flag32(1);
                    } else if EMS_ENABLED && handle == EMS_DEVICE_HANDLE {
                        // EMMXXXX0 device: bit 7=1 (device)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x80;
                        regs.clear_flag32(1);
                    } else {
                        // File handle: bit 7=0 (file), bits 5-0=drive (2=C:)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0002;
                        regs.clear_flag32(1);
                    }
                }
                // AL=0x07: Check device output status (BX=handle)
                0x07 => {
                    // AL=FFh = ready
                    regs.rax = (regs.rax & !0xFF) | 0xFF;
                    regs.clear_flag32(1);
                }
                // AL=0x08: Check if block device is removable (BL=drive, 0=default,1=A,3=C)
                0x08 => {
                    // AX=0 = removable, AX=1 = fixed
                    regs.rax = (regs.rax & !0xFFFF) | 1; // fixed disk
                    regs.clear_flag32(1); // clear CF
                }
                // AL=0x09: Check if block device is remote (BL=drive)
                0x09 => {
                    regs.rdx = (regs.rdx & !0xFFFF) | 0x0000; // bit 12=0 = local
                    regs.clear_flag32(1);
                }
                _ => {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C)
        0x0E => {
            regs.rax = (regs.rax & !0xFF) | 3; // AL = number of logical drives
            thread::KernelAction::Done
        }
        // AH=0x3C: Create file (CX=attr, DS:DX=filename) — RAM-backed via VFS overlay
        0x3C => {
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let i = dos_normalize_path(&mut name, i);
            let mut rbuf = [0u8; 164];
            let resolved = dos_resolve_path(dos, &name[..i], &mut rbuf);
            let fd = crate::kernel::vfs::create(resolved, &mut dos.fds);
            if fd >= 0 {
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 4; // too many open files
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            // Handle 1=stdout, 2=stderr
            if handle == 1 || handle == 2 {
                let addr = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
                for i in 0..count as u32 {
                    let ch = unsafe { *((addr + i) as *const u8) };
                    dos_putchar(ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else if handle == NULL_FILE_HANDLE {
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else {
                let addr = ((regs.ds as u16 as u32) << 4) + regs.rdx as u16 as u32;
                let data = unsafe { core::slice::from_raw_parts(addr as *const u8, count as usize) };
                let n = crate::kernel::vfs::write(handle as i32, data, &dos.fds);
                regs.rax = (regs.rax & !0xFFFF) | if n >= 0 { n as u64 } else { count as u64 };
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as u16 as i32;
            if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — always at position 0
                regs.rdx = regs.rdx & !0xFFFF;
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let offset = ((regs.rcx as u16 as u32) << 16 | regs.rdx as u16 as u32) as i32;
                let whence = regs.rax as u8 as i32; // AL = origin
                let result = crate::kernel::vfs::seek(handle, offset, whence, &dos.fds);
                if result >= 0 {
                    // Return new position in DX:AX
                    regs.rdx = (regs.rdx & !0xFFFF) | ((result as u32 >> 16) as u64);
                    regs.rax = (regs.rax & !0xFFFF) | (result as u16 as u64);
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x43: Get/Set File Attributes (AL=0: get, AL=1: set)
        // DS:DX = ASCIIZ filename, CX = attributes (for set)
        0x43 => {
            let al = regs.rax as u8;
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let i = dos_normalize_path(&mut name, i);
            let mut rbuf = [0u8; 164];
            let resolved = dos_resolve_path(dos, &name[..i], &mut rbuf);
            // Check if file exists by trying to open it
            let fd = crate::kernel::vfs::open(resolved, &mut dos.fds);
            if fd >= 0 {
                crate::kernel::vfs::close(fd, &mut dos.fds);
                if al == 0 {
                    // Get attributes: return 0x20 (archive) in CX
                    regs.rcx = (regs.rcx & !0xFFFF) | 0x20;
                }
                // Set attributes: just succeed (read-only FS)
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x29: Parse filename into FCB (DS:SI=string, ES:DI=FCB)
        // AL bits: 0=skip leading separators, 1=set drive only if specified,
        //          2=set filename only if specified, 3=set extension only if specified
        0x29 => {
            let ds = regs.ds as u32;
            let mut si = regs.rsi as u16;
            let es = regs.es as u32;
            let di = regs.rdi as u16;
            let fcb = (es << 4) + di as u32;

            // Skip leading whitespace/separators if bit 0 set
            let flags = regs.rax as u8;
            if flags & 1 != 0 {
                loop {
                    let ch = unsafe { *(((ds << 4) + si as u32) as *const u8) };
                    if ch == b' ' || ch == b'\t' || ch == b';' || ch == b',' {
                        si += 1;
                    } else {
                        break;
                    }
                }
            }

            // Zero-fill the 11-byte name field in FCB (drive byte at +0, name at +1..+12)
            unsafe { core::ptr::write_bytes((fcb + 1) as *mut u8, b' ', 11); }

            // Check for drive letter (e.g., "C:")
            let ch0 = unsafe { *(((ds << 4) + si as u32) as *const u8) };
            let ch1 = unsafe { *(((ds << 4) + si as u32 + 1) as *const u8) };
            if ch1 == b':' && ch0.is_ascii_alphabetic() {
                unsafe { *(fcb as *mut u8) = ch0.to_ascii_uppercase() - b'A' + 1; }
                si += 2;
            } else {
                unsafe { *(fcb as *mut u8) = 0; } // default drive
            }

            // Parse filename (up to 8 chars) into FCB+1
            let mut pos = 0u32;
            loop {
                let ch = unsafe { *(((ds << 4) + si as u32) as *const u8) };
                if ch == b'.' || ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                if ch == b'*' {
                    while pos < 8 { unsafe { *((fcb + 1 + pos) as *mut u8) = b'?'; } pos += 1; }
                    si += 1;
                    break;
                }
                if pos < 8 {
                    unsafe { *((fcb + 1 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                    pos += 1;
                }
                si += 1;
            }

            // Parse extension (up to 3 chars) into FCB+9
            let ch = unsafe { *(((ds << 4) + si as u32) as *const u8) };
            if ch == b'.' {
                si += 1;
                pos = 0;
                loop {
                    let ch = unsafe { *(((ds << 4) + si as u32) as *const u8) };
                    if ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                    if ch == b'*' {
                        while pos < 3 { unsafe { *((fcb + 9 + pos) as *mut u8) = b'?'; } pos += 1; }
                        si += 1;
                        break;
                    }
                    if pos < 3 {
                        unsafe { *((fcb + 9 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                        pos += 1;
                    }
                    si += 1;
                }
            }

            // Update SI to point past parsed name
            regs.rsi = (regs.rsi & !0xFFFF) | si as u64;
            // AL=0: no wildcards, AL=1: wildcards present, AL=0xFF: drive invalid
            let has_wildcards = unsafe {
                let name_area = core::slice::from_raw_parts((fcb + 1) as *const u8, 11);
                name_area.iter().any(|&b| b == b'?')
            };
            regs.rax = (regs.rax & !0xFF) | if has_wildcards { 1 } else { 0 };
            thread::KernelAction::Done
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            exec_program(dos, regs)
        }
        // AH=2Ah — Get System Date
        0x2A => {
            // Return a fixed date: 2026-03-22 (Saturday)
            regs.rcx = (regs.rcx & !0xFFFF) | 2026; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | (3 << 8) | 22; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | 6; // AL = day of week (0=Sun, 6=Sat)
            thread::KernelAction::Done
        }
        // AH=2Ch — Get System Time
        0x2C => {
            // Derive from BIOS tick count at 0040:006C (18.2 ticks/sec)
            let ticks = unsafe { *((0x46C) as *const u32) };
            let total_secs = ticks / 18;
            let hours = (total_secs / 3600) % 24;
            let mins = (total_secs / 60) % 60;
            let secs = total_secs % 60;
            let centisecs = ((ticks % 18) * 100) / 18;
            regs.rcx = (regs.rcx & !0xFFFF) | (hours << 8) as u64 | mins as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (secs << 8) as u64 | centisecs as u64;
            thread::KernelAction::Done
        }
        // AH=0x57: Get/Set File Date and Time (AL=0: get, AL=1: set, BX=handle)
        0x57 => {
            let al = regs.rax as u8;
            if al == 0 {
                // Get: return a fixed date/time (2026-03-22 12:00:00)
                // DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2
                // DOS date: bits 15-9=year-1980, 8-5=month, 4-0=day
                let time: u16 = (12 << 11) | (0 << 5) | 0; // 12:00:00
                let date: u16 = (46 << 9) | (3 << 5) | 22; // 2026-03-22
                regs.rcx = (regs.rcx & !0xFFFF) | time as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | date as u64;
                regs.clear_flag32(1);
            } else {
                // Set: succeed silently (read-only FS)
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x60: Canonicalize path (DS:SI=input, ES:DI=output buffer)
        0x60 => {
            let ds = regs.ds as u16 as u32;
            let si = regs.rsi as u16 as u32;
            let es = regs.es as u16 as u32;
            let di = regs.rdi as u16 as u32;
            let src = (ds << 4) + si;
            let dst = (es << 4) + di;
            // Read input path
            let mut name = [0u8; 128];
            let mut len = 0;
            while len < 127 {
                let ch = unsafe { *((src + len as u32) as *const u8) };
                if ch == 0 { break; }
                name[len] = ch;
                len += 1;
            }
            // Build canonical path: if no drive letter, prepend "C:\"
            let mut out = [0u8; 128];
            let mut pos = 0;
            if len >= 2 && name[1] == b':' {
                // Already has drive letter — uppercase it
                out[0] = name[0].to_ascii_uppercase();
                out[1] = b':';
                out[2] = b'\\';
                pos = 3;
                let skip = if len > 2 && (name[2] == b'/' || name[2] == b'\\') { 3 } else { 2 };
                for i in skip..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
                    pos += 1;
                }
            } else {
                // Relative — prepend C:\ + CWD
                out[0] = b'C'; out[1] = b':'; out[2] = b'\\';
                pos = 3;
                let cwd = dos.cwd_str();
                for &ch in cwd {
                    if pos >= 127 { break; }
                    out[pos] = if ch == b'/' { b'\\' } else { ch.to_ascii_uppercase() };
                    pos += 1;
                }
                if pos > 3 && out[pos - 1] != b'\\' { out[pos] = b'\\'; pos += 1; }
                for i in 0..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
                    pos += 1;
                }
            }
            out[pos] = 0;
            // Write to ES:DI
            unsafe {
                core::ptr::copy_nonoverlapping(out.as_ptr(), dst as *mut u8, pos + 1);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x52: Get List of Lists (returns ES:BX → DOS internal structure)
        0x52 => {
            regs.es = LOL_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | 0;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x36: Get Disk Free Space (DL=drive, 0=default,1=A,2=B,3=C...)
        // Returns: AX=sectors/cluster, BX=free clusters, CX=bytes/sector, DX=total clusters
        // On error: AX=0xFFFF
        0x36 => {
            let dl = regs.rdx as u8;
            // Map drive: 0=default(C), 1=A, 2=B, 3=C
            let drive = if dl == 0 { 3 } else { dl };
            if drive == 3 {
                // C: drive — report fake 16MB disk, 8MB free
                // 512 bytes/sector, 8 sectors/cluster (4KB), 4096 total clusters = 16MB
                regs.rax = (regs.rax & !0xFFFF) | 8;    // AX = sectors per cluster
                regs.rbx = (regs.rbx & !0xFFFF) | 2048; // BX = free clusters
                regs.rcx = (regs.rcx & !0xFFFF) | 512;  // CX = bytes per sector
                regs.rdx = (regs.rdx & !0xFFFF) | 4096; // DX = total clusters
            } else {
                // A:/B: or unknown — invalid drive
                regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
            }
            thread::KernelAction::Done
        }
        // AH=0x67: Set Handle Count — stub success
        0x67 => {
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x41: Delete file (DS:DX=filename)
        0x41 => {
            let ds = regs.ds as u16 as u32;
            let dx = regs.rdx as u16 as u32;
            let mut addr = (ds << 4) + dx;
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let i = dos_normalize_path(&mut name, i);
            let mut rbuf = [0u8; 164];
            let resolved = dos_resolve_path(dos, &name[..i], &mut rbuf);
            crate::kernel::vfs::delete(resolved);
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x59: Get Extended Error Information
        0x59 => {
            // Return "file not found" as default extended error
            regs.rax = (regs.rax & !0xFFFF) | 2; // AX = error code (file not found)
            regs.rbx = (regs.rbx & !0xFFFF) | ((1 << 8) | 2); // BH=1 (class: out of resource), BL=2 (action: abort)
            regs.rcx = (regs.rcx & !0xFFFF); // CH=0 (locus: unknown)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x4D: Get Return Code of Subprocess
        0x4D => {
            let code = dos.vm86.last_child_exit_code;
            regs.rax = (regs.rax & !0xFFFF) | code as u64; // AL=exit code, AH=0 (normal)
            thread::KernelAction::Done
        }
        // AH=0x62: Get PSP segment (returns BX=PSP segment)
        0x62 => {
            regs.rbx = (regs.rbx & !0xFFFF) | COM_SEGMENT as u64;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x6C: Extended Open/Create (DOS 4.0+)
        // BX=mode, CX=attributes, DX=action, DS:SI=ASCIIZ filename
        // Action: bit0=open-if-exists, bit4=create-if-not-exists
        0x6C => {
            let action = regs.rdx as u16;
            let ds = regs.ds as u16 as u32;
            let si = regs.rsi as u16 as u32;
            let mut addr = (ds << 4) + si;
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let i = dos_normalize_path(&mut name, i);
            let mut rbuf = [0u8; 164];
            let resolved = dos_resolve_path(dos, &name[..i], &mut rbuf);
            let open_exists = action & 0x01 != 0;
            let create_not = action & 0x10 != 0;

            // Try open first
            let fd = crate::kernel::vfs::open(resolved, &mut dos.fds);
            if fd >= 0 && open_exists {
                let size = crate::kernel::vfs::file_size(fd, &dos.fds);
                sft_set_file(fd as u16, size);
                unsafe {
                    let psp = (COM_SEGMENT as u32 * 16) as *mut u8;
                    if (fd as usize) < 20 { *psp.add(0x34 + fd as usize) = fd as u8; }
                }
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.rcx = (regs.rcx & !0xFFFF) | 1; // CX=1: file opened
                regs.clear_flag32(1);
            } else if create_not {
                // File doesn't exist — create RAM-backed file via VFS overlay
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut dos.fds); }
                let new_fd = crate::kernel::vfs::create(resolved, &mut dos.fds);
                if new_fd >= 0 {
                    regs.rax = (regs.rax & !0xFFFF) | new_fd as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | 2; // CX=2: file created
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 4;
                    regs.set_flag32(1);
                }
            } else {
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut dos.fds); }
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x5D: Server function — subfunction in AL
        0x5D => {
            let al = regs.rax as u8;
            match al {
                // AL=06: Get DOS Swappable Data Area address
                //   Returns DS:SI→ swap area, CX=total size, DX=size that must
                //   always be swapped. Point at SYSPSP (zeroed) with a nominal
                //   size; DPMILOAD just needs a plausible pointer.
                0x06 => {
                    regs.ds = SYSPSP_SEG as u64;
                    regs.rsi = 0;
                    regs.rcx = (regs.rcx & !0xFFFF) | SYSPSP_SIZE as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | SYSPSP_SIZE as u64;
                    regs.clear_flag32(1);
                }
                _ => {
                    regs.rax = (regs.rax & !0xFFFF) | 1; // invalid function
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        0x71 => {
            // LFN (Long File Name) API — not supported.
            // Return AX=7100h so DJGPP/libc knows to fall back to short-name DOS calls.
            regs.rax = (regs.rax & !0xFFFF) | 0x7100;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
        _ => {
            crate::dbg_println!("VM86: unhandled INT 21h AH={:#04x} AX={:04X}", ah, regs.rax as u16);
            // Return "function not supported" (AX=1, carry set)
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
    }
}

/// DOS INT 21h/4B — Load and Execute Program
///
/// Try to open a program file via VFS. If the name has no extension (no dot),
/// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Eh — COMMAND.COM internal execute
// ============================================================================

fn int_2eh(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
    // Treat as COMMAND.COM /C — fork-exec the program in a fresh address space.
    let ds = regs.ds as u16 as u32;
    let si = regs.rsi as u16 as u32;
    let addr = (ds << 4) + si;
    let len = unsafe { *(addr as *const u8) } as usize;
    let mut cmd = [0u8; 128];
    let copy = len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((addr + 1) as *const u8, cmd.as_mut_ptr(), copy);
    }
    let mut start = 0;
    while start < copy && cmd[start] == b' ' { start += 1; }
    let mut end = start;
    while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
    if end <= start { return thread::KernelAction::Done; }

    // Normalize the program name (shift into start of cmd buffer)
    let plen = end - start;
    cmd.copy_within(start..end, 0);
    let plen = dos_normalize_path(&mut cmd, plen);
    fork_exec(dos, &cmd[..plen])
}

// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS + DPMI detection)
// ============================================================================

fn int_2fh(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
    match ax {
        // AX=1687h — DPMI installation check
        0x1687 => {
            regs.rax = regs.rax & !0xFFFF; // AX=0: DPMI available
            // BX = flags (bit 0 = 32-bit programs supported)
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001;
            // CL = processor type (3 = 386)
            regs.rcx = (regs.rcx & !0xFF) | 0x03;
            // DX = DPMI version (0.90)
            regs.rdx = (regs.rdx & !0xFFFF) | 0x005A; // 0x00=major, 0x5A=90 decimal
            // SI = paragraph count for DPMI host private data (0 = none needed)
            regs.rsi = regs.rsi & !0xFFFF;
            // ES:DI = entry point (far call to switch to protected mode)
            regs.es = STUB_SEG as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | slot_offset(SLOT_DPMI_ENTRY) as u64;
            thread::KernelAction::Done
        }
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            thread::KernelAction::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | slot_offset(SLOT_XMS) as u64;
            thread::KernelAction::Done
        }
        _ => {
            // Unhandled — return "not installed" (AL unchanged)
            thread::KernelAction::Done
        }
    }
}

// ============================================================================
// XMS dispatch (called via stub slot SLOT_XMS)
// ============================================================================

/// Ensure XMS state exists for current thread, return mutable reference
fn xms_state(dos: &mut thread::DosState) -> &mut XmsState {
    let vm86 = &mut dos.vm86;
    if vm86.xms.is_none() {
        vm86.xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    vm86.xms.as_deref_mut().unwrap()
}

fn xms_dispatch(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — Get XMS version
        0x00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0300; // XMS 3.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // driver internal revision
            regs.rdx = (regs.rdx & !0xFFFF) | 0x0001; // HMA exists
        }
        // AH=03h — Global enable A20
        0x03 => {
            let xms = xms_state(dos);
            xms.a20_global += 1;
            let vm86 = &mut dos.vm86;
            crate::kernel::startup::arch_set_a20(true, &mut vm86.hma_pages);
            vm86.a20_enabled = true;
            regs.rax = (regs.rax & !0xFFFF) | 1; // success
            regs.rbx = (regs.rbx & !0xFFFF); // BL=0 no error
        }
        // AH=04h — Global disable A20
        0x04 => {
            let xms = xms_state(dos);
            xms.a20_global = xms.a20_global.saturating_sub(1);
            if xms.a20_global == 0 && xms.a20_local == 0 {
                let vm86 = &mut dos.vm86;
                crate::kernel::startup::arch_set_a20(false, &mut vm86.hma_pages);
                vm86.a20_enabled = false;
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=05h — Local enable A20
        0x05 => {
            let xms = xms_state(dos);
            xms.a20_local += 1;
            let vm86 = &mut dos.vm86;
            crate::kernel::startup::arch_set_a20(true, &mut vm86.hma_pages);
            vm86.a20_enabled = true;
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=06h — Local disable A20
        0x06 => {
            let xms = xms_state(dos);
            xms.a20_local = xms.a20_local.saturating_sub(1);
            if xms.a20_local == 0 && xms.a20_global == 0 {
                let vm86 = &mut dos.vm86;
                crate::kernel::startup::arch_set_a20(false, &mut vm86.hma_pages);
                vm86.a20_enabled = false;
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=07h — Query A20 state
        0x07 => {
            let enabled = dos.vm86.a20_enabled;
            regs.rax = (regs.rax & !0xFFFF) | if enabled { 1 } else { 0 };
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=08h — Query free extended memory
        0x08 => {
            let xms = xms_state(dos);
            let largest = xms.largest_free_kb();
            let total = xms.free_kb();
            regs.rax = (regs.rax & !0xFFFF) | largest as u64; // largest free block (KB)
            regs.rdx = (regs.rdx & !0xFFFF) | total as u64;   // total free (KB)
        }
        // AH=09h — Allocate extended memory block (DX=size in KB)
        0x09 => {
            let size_kb = regs.rdx as u16;
            let xms = xms_state(dos);
            let mut handle = None;
            for i in 0..MAX_XMS_HANDLES {
                if xms.handles[i].is_none() {
                    handle = Some(i);
                    break;
                }
            }
            match handle {
                Some(i) => {
                    let size_bytes = size_kb as u32 * 1024;
                    match xms.find_free(size_bytes) {
                        Some(base) => {
                            xms.handles[i] = Some(XmsHandle {
                                base,
                                size_kb,
                                locked: false,
                            });
                            regs.rax = (regs.rax & !0xFFFF) | 1;
                            regs.rdx = (regs.rdx & !0xFFFF) | (i + 1) as u64;
                        }
                        None => {
                            regs.rax = (regs.rax & !0xFFFF);
                            regs.rbx = (regs.rbx & !0xFF) | 0xA0;
                        }
                    }
                }
                None => {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA1;
                }
            }
        }
        // AH=0Ah — Free extended memory block (DX=handle)
        0x0A => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if xms.handles[handle as usize - 1].take().is_some() {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Bh — Move extended memory block (DS:SI = move struct)
        0x0B => {
            xms_move(dos, regs);
        }
        // AH=0Ch — Lock extended memory block (DX=handle)
        0x0C => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref mut h) = xms.handles[handle as usize - 1] {
                    h.locked = true;
                    let addr = h.base;
                    regs.rdx = (regs.rdx & !0xFFFF) | (addr >> 16) as u64;
                    regs.rbx = (regs.rbx & !0xFFFF) | (addr & 0xFFFF) as u64;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Dh — Unlock extended memory block (DX=handle)
        0x0D => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref mut h) = xms.handles[handle as usize - 1] {
                    h.locked = false;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Eh — Get EMB handle information (DX=handle)
        0x0E => {
            let handle = regs.rdx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if let Some(ref h) = xms.handles[handle as usize - 1] {
                    let lock_count = if h.locked { 1u8 } else { 0 };
                    let free_handles = xms.handles.iter().filter(|h| h.is_none()).count() as u8;
                    // BH=lock count, BL=free handles
                    regs.rbx = (regs.rbx & !0xFFFF) | (lock_count as u64) << 8 | free_handles as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | h.size_kb as u64;
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                } else {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=0Fh — Reallocate extended memory block (DX=handle, BX=new size KB)
        // Simple: free old, alloc new (no data preservation — rare in practice)
        0x0F => {
            let handle = regs.rdx as u16;
            let new_kb = regs.rbx as u16;
            let xms = xms_state(dos);
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if xms.handles[handle as usize - 1].is_some() {
                    let old = xms.handles[handle as usize - 1].take().unwrap();
                    let new_bytes = new_kb as u32 * 1024;
                    match xms.find_free(new_bytes) {
                        Some(base) => {
                            xms.handles[handle as usize - 1] = Some(XmsHandle {
                                base,
                                size_kb: new_kb,
                                locked: old.locked,
                            });
                            regs.rax = (regs.rax & !0xFFFF) | 1;
                        }
                        None => {
                            // Restore old handle
                            xms.handles[handle as usize - 1] = Some(old);
                            regs.rax = (regs.rax & !0xFFFF);
                            regs.rbx = (regs.rbx & !0xFF) | 0xA0;
                        }
                    }
                } else {
                    regs.rax = (regs.rax & !0xFFFF);
                    regs.rbx = (regs.rbx & !0xFF) | 0xA2;
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA2;
            }
        }
        // AH=88h — Query free extended memory (32-bit, XMS 3.0)
        0x88 => {
            let xms = xms_state(dos);
            let free = xms.free_kb() as u32;
            regs.rax = (regs.rax & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFFFFFF) | (XMS_END - 1) as u64;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=10h — Request Upper Memory Block (DX=size in paragraphs)
        0x10 => {
            let size = regs.rdx as u16;
            match umb_alloc(size) {
                Some((seg, paras)) => {
                    regs.rax = (regs.rax & !0xFFFF) | 1; // success
                    regs.rbx = (regs.rbx & !0xFFFF) | seg as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | paras as u64;
                }
                None => {
                    let largest = umb_largest();
                    regs.rax = (regs.rax & !0xFFFF); // failure
                    regs.rbx = (regs.rbx & !0xFF) | if largest > 0 { 0xB0 } else { 0xB1 };
                    regs.rdx = (regs.rdx & !0xFFFF) | largest as u64;
                }
            }
        }
        // AH=11h — Release Upper Memory Block (DX=segment)
        0x11 => {
            let seg = regs.rdx as u16;
            if umb_free(seg) {
                regs.rax = (regs.rax & !0xFFFF) | 1; // success
            } else {
                regs.rax = (regs.rax & !0xFFFF); // failure
                regs.rbx = (regs.rbx & !0xFF) | 0xB2; // invalid UMB segment
            }
        }
        _ => {
            dbg_println!("XMS: UNHANDLED AH={:02X}", ah);
            regs.rax = (regs.rax & !0xFFFF); // failure
            regs.rbx = (regs.rbx & !0xFF) | 0x80; // not implemented
        }
    }
    thread::KernelAction::Done
}

/// XMS function 0Bh: Move extended memory block
/// DS:SI points to a move structure:
///   +00: u32 length (bytes)
///   +04: u16 source handle (0=conventional)
///   +06: u32 source offset (or seg:off if handle=0)
///   +0A: u16 dest handle (0=conventional)
///   +0C: u32 dest offset (or seg:off if handle=0)
fn xms_move(dos: &mut thread::DosState, regs: &mut Regs) {
    let ds = regs.ds as u16 as u32;
    let si = regs.rsi as u16 as u32;
    let addr = (ds << 4) + si;

    let length = unsafe { (addr as *const u32).read_unaligned() } as usize;
    let src_handle = unsafe { ((addr + 4) as *const u16).read_unaligned() };
    let src_offset = unsafe { ((addr + 6) as *const u32).read_unaligned() };
    let dst_handle = unsafe { ((addr + 10) as *const u16).read_unaligned() };
    let dst_offset = unsafe { ((addr + 12) as *const u32).read_unaligned() };

    if length == 0 {
        regs.rax = (regs.rax & !0xFFFF) | 1;
        regs.rbx = (regs.rbx & !0xFFFF);
        return;
    }

    // Resolve source to linear address
    let xms = xms_state(dos);
    let src = if src_handle == 0 {
        // Conventional memory: offset is seg:off packed as off(16):seg(16)
        let seg = (src_offset >> 16) as u32;
        let off = (src_offset & 0xFFFF) as u32;
        (seg << 4) + off
    } else {
        let idx = src_handle as usize - 1;
        match xms.handles.get(idx).and_then(|h| h.as_ref()) {
            Some(h) if (src_offset as usize) + length <= h.size_kb as usize * 1024 => {
                h.base + src_offset
            }
            _ => {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA3;
                return;
            }
        }
    };

    // Resolve dest to linear address
    let dst = if dst_handle == 0 {
        let seg = (dst_offset >> 16) as u32;
        let off = (dst_offset & 0xFFFF) as u32;
        (seg << 4) + off
    } else {
        let idx = dst_handle as usize - 1;
        match xms.handles.get(idx).and_then(|h| h.as_ref()) {
            Some(h) if (dst_offset as usize) + length <= h.size_kb as usize * 1024 => {
                h.base + dst_offset
            }
            _ => {
                regs.rax = (regs.rax & !0xFFFF);
                regs.rbx = (regs.rbx & !0xFF) | 0xA5;
                return;
            }
        }
    };

    unsafe {
        core::ptr::copy(src as *const u8, dst as *mut u8, length);
    }
    regs.rax = (regs.rax & !0xFFFF) | 1;
    regs.rbx = (regs.rbx & !0xFFFF);
}

// ============================================================================
// INT 67h — EMS driver
// ============================================================================

/// Ensure EMS state exists for current thread
fn ems_state(dos: &mut thread::DosState) -> &mut EmsState {
    let vm86 = &mut dos.vm86;
    if vm86.ems.is_none() {
        vm86.ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    vm86.ems.as_deref_mut().unwrap()
}

fn int_67h(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=40h — Get status
        0x40 => {
            regs.rax = (regs.rax & !0xFF00); // AH=0: OK
        }
        // AH=41h — Get page frame segment
        0x41 => {
            regs.rbx = (regs.rbx & !0xFFFF) | ems_frame_seg() as u64;
            regs.rax = (regs.rax & !0xFF00); // AH=0
        }
        // AH=42h — Get unallocated page count
        0x42 => {
            let ems = ems_state(dos);
            let free = ems.alloc_pages();
            regs.rbx = (regs.rbx & !0xFFFF) | free as u64;     // BX = free pages
            regs.rdx = (regs.rdx & !0xFFFF) | EMS_TOTAL_PAGES as u64; // DX = total pages
            regs.rax = (regs.rax & !0xFF00); // AH=0
        }
        // AH=43h — Allocate handle (BX=pages needed, returns DX=handle)
        0x43 => {
            let pages_needed = regs.rbx as u16;
            let ems = ems_state(dos);
            // Find free handle
            let mut handle = None;
            for i in 0..MAX_EMS_HANDLES {
                if ems.handles[i].is_none() {
                    handle = Some(i);
                    break;
                }
            }
            match handle {
                Some(i) => {
                    // Allocate physical pages for each EMS page (4 × 4KB per EMS 16KB page)
                    let mut pages = alloc::vec::Vec::with_capacity(pages_needed as usize);
                    let mut ok = true;
                    for _ in 0..pages_needed {
                        let mut group = [0u64; 4];
                        for p in &mut group {
                            match crate::arch::alloc_phys_page() {
                                Some(page) => *p = page,
                                None => { ok = false; break; }
                            }
                        }
                        if !ok { break; }
                        // Zero the allocated pages
                        for &p in &group {
                            crate::kernel::startup::arch_zero_phys_page(p);
                        }
                        pages.push(group);
                    }
                    if ok {
                        ems.handles[i] = Some(EmsHandle { pages });
                        regs.rdx = (regs.rdx & !0xFFFF) | i as u64; // handle (0-based)
                        regs.rax = (regs.rax & !0xFF00); // AH=0
                    } else {
                        // Free any partially allocated pages
                        for group in &pages {
                            for &p in group {
                                if p != 0 { crate::arch::free_phys_page(p); }
                            }
                        }
                        regs.rax = (regs.rax & !0xFF00) | (0x88 << 8); // AH=88: not enough pages
                    }
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x85 << 8); // AH=85: no more handles
                }
            }
        }
        // AH=44h — Map page (AL=physical page 0-3, BX=logical page, DX=handle)
        0x44 => {
            let phys_page = regs.rax as u8; // AL
            let log_page = regs.rbx as u16;
            let handle = regs.rdx as u16;

            if phys_page > 3 {
                regs.rax = (regs.rax & !0xFF00) | (0x8B << 8); // invalid physical page
                return thread::KernelAction::Done;
            }

            let ems = ems_state(dos);

            // BX=FFFFh means unmap
            if log_page == 0xFFFF {
                ems.frame[phys_page as usize] = None;
                crate::kernel::startup::arch_map_ems_window(ems_base_page(), phys_page as usize, None);
                regs.rax = (regs.rax & !0xFF00); // AH=0
                return thread::KernelAction::Done;
            }

            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                return thread::KernelAction::Done;
            }

            match &ems.handles[handle as usize] {
                Some(h) if (log_page as usize) < h.pages.len() => {
                    let phys_pages = &h.pages[log_page as usize];
                    crate::kernel::startup::arch_map_ems_window(ems_base_page(), phys_page as usize, Some(phys_pages));
                    ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                    regs.rax = (regs.rax & !0xFF00); // AH=0
                }
                Some(_) => {
                    regs.rax = (regs.rax & !0xFF00) | (0x8A << 8); // logical page out of range
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                }
            }
        }
        // AH=45h — Release handle (DX=handle)
        0x45 => {
            let handle = regs.rdx as u16;
            let ems = ems_state(dos);
            if (handle as usize) < MAX_EMS_HANDLES && ems.handles[handle as usize].is_some() {
                // Unmap any windows using this handle
                for w in 0..4 {
                    if let Some((h, _)) = ems.frame[w] {
                        if h == handle as u8 {
                            ems.frame[w] = None;
                            crate::kernel::startup::arch_map_ems_window(ems_base_page(), w, None);
                        }
                    }
                }
                // Free physical pages
                if let Some(h) = ems.handles[handle as usize].take() {
                    for group in &h.pages {
                        for &p in group {
                            crate::arch::free_phys_page(p);
                        }
                    }
                }
                regs.rax = (regs.rax & !0xFF00); // AH=0
            } else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
            }
        }
        // AH=46h — Get version
        0x46 => {
            regs.rax = (regs.rax & !0xFF00) | (0x00 << 8); // AH=0
            regs.rax = (regs.rax & !0xFF) | 0x40; // AL=40h = version 4.0
        }
        // AH=4Bh — Get number of open handles
        0x4B => {
            let ems = ems_state(dos);
            let count = ems.handles.iter().filter(|h| h.is_some()).count() as u16;
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax = (regs.rax & !0xFF00);
        }
        // AH=4Ch — Get pages allocated to handle (DX=handle)
        0x4C => {
            let handle = regs.rdx as u16;
            let ems = ems_state(dos);
            if (handle as usize) < MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[handle as usize] {
                    regs.rbx = (regs.rbx & !0xFFFF) | h.pages.len() as u64;
                    regs.rax = (regs.rax & !0xFF00);
                } else {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                }
            } else {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
            }
        }
        // AH=4Dh — Get pages for all handles (ES:DI = buffer)
        0x4D => {
            let ems = ems_state(dos);
            let es = regs.es as u32;
            let di = regs.rdi as u32;
            let mut addr = (es << 4) + di;
            let mut count = 0u16;
            for i in 0..MAX_EMS_HANDLES {
                if let Some(ref h) = ems.handles[i] {
                    unsafe {
                        (addr as *mut u16).write_unaligned(i as u16);
                        ((addr + 2) as *mut u16).write_unaligned(h.pages.len() as u16);
                    }
                    addr += 4;
                    count += 1;
                }
            }
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax = (regs.rax & !0xFF00);
        }
        // AH=50h — Map multiple pages (AL=0: phys page mode, AL=1: segment mode)
        // CX=count, DX=handle, DS:SI=mapping array
        0x50 => {
            let al = regs.rax as u8;
            let count = regs.rcx as u16;
            let handle = regs.rdx as u16;
            let ds = regs.ds as u16 as u32;
            let si = regs.rsi as u16 as u32;
            let base_addr = (ds << 4) + si;

            let ems = ems_state(dos);
            if (handle as usize) >= MAX_EMS_HANDLES || ems.handles[handle as usize].is_none() {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }

            for i in 0..count as u32 {
                let log_page = unsafe { ((base_addr + i * 4) as *const u16).read_unaligned() };
                let phys_raw = unsafe { ((base_addr + i * 4 + 2) as *const u16).read_unaligned() };

                let phys_page = if al == 0 {
                    phys_raw as u8
                } else {
                    // Segment mode: convert segment to physical page index
                    let seg_offset = phys_raw.wrapping_sub(ems_frame_seg());
                    (seg_offset / 0x0400) as u8 // each window is 0x400 paragraphs (16KB)
                };

                if phys_page > 3 {
                    regs.rax = (regs.rax & !0xFF00) | (0x8B << 8);
                    return thread::KernelAction::Done;
                }

                if log_page == 0xFFFF {
                    ems.frame[phys_page as usize] = None;
                    crate::kernel::startup::arch_map_ems_window(ems_base_page(), phys_page as usize, None);
                } else {
                    match &ems.handles[handle as usize] {
                        Some(h) if (log_page as usize) < h.pages.len() => {
                            let phys_pages = &h.pages[log_page as usize];
                            crate::kernel::startup::arch_map_ems_window(ems_base_page(), phys_page as usize, Some(phys_pages));
                            ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                        }
                        _ => {
                            regs.rax = (regs.rax & !0xFF00) | (0x8A << 8);
                            return thread::KernelAction::Done;
                        }
                    }
                }
            }
            regs.rax = (regs.rax & !0xFF00); // AH=0
        }
        // AH=51h — Reallocate pages for handle (DX=handle, BX=new count)
        0x51 => {
            let handle = regs.rdx as u16;
            let new_count = regs.rbx as u16;
            let ems = ems_state(dos);
            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return thread::KernelAction::Done;
            }
            match &mut ems.handles[handle as usize] {
                Some(h) => {
                    let old_count = h.pages.len();
                    if (new_count as usize) > old_count {
                        // Grow: allocate new pages
                        for _ in old_count..(new_count as usize) {
                            let mut group = [0u64; 4];
                            let mut ok = true;
                            for p in &mut group {
                                match crate::arch::alloc_phys_page() {
                                    Some(page) => *p = page,
                                    None => { ok = false; break; }
                                }
                            }
                            if !ok {
                                // Free partially allocated group
                                for &p in &group { if p != 0 { crate::arch::free_phys_page(p); } }
                                regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                                return thread::KernelAction::Done;
                            }
                            h.pages.push(group);
                        }
                    } else if (new_count as usize) < old_count {
                        // Shrink: free excess pages
                        for group in h.pages.drain(new_count as usize..) {
                            for &p in &group {
                                crate::arch::free_phys_page(p);
                            }
                        }
                    }
                    regs.rax = (regs.rax & !0xFF00);
                    regs.rbx = (regs.rbx & !0xFFFF) | new_count as u64;
                }
                None => {
                    regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                }
            }
        }
        // AH=58h — Get mappable physical page array
        0x58 => {
            let al = regs.rax as u8;
            if al == 0 {
                // Sub 0: fill array at ES:DI with (segment, physical_page) pairs
                let es = regs.es as u32;
                let di = regs.rdi as u32;
                let base = (es << 4) + di;
                for i in 0..4u32 {
                    let seg = ems_frame_seg() + (i as u16) * 0x0400;
                    unsafe {
                        ((base + i * 4) as *mut u16).write_unaligned(seg);
                        ((base + i * 4 + 2) as *mut u16).write_unaligned(i as u16);
                    }
                }
                regs.rcx = (regs.rcx & !0xFFFF) | 4; // 4 mappable pages
                regs.rax = (regs.rax & !0xFF00);
            } else {
                // Sub 1: just return count
                regs.rcx = (regs.rcx & !0xFFFF) | 4;
                regs.rax = (regs.rax & !0xFF00);
            }
        }
        _ => {
            dbg_println!("EMS: UNHANDLED AH={:02X}", ah);
            regs.rax = (regs.rax & !0xFF00) | (0x84 << 8); // AH=84: function not supported
        }
    }
    thread::KernelAction::Done
}

fn dos_open_program(dos: &mut thread::DosState, name: &[u8]) -> i32 {
    let mut rbuf = [0u8; 164];
    let resolved = dos_resolve_path(dos, name, &mut rbuf);
    let fd = crate::kernel::vfs::open(resolved, &mut dos.fds);
    if fd >= 0 { return fd; }
    // If the name already has a dot, don't try extensions
    if name.iter().any(|&c| c == b'.') { return fd; }
    // Try .COM
    let rlen = resolved.len();
    let mut buf = [0u8; 168];
    if rlen + 4 <= buf.len() {
        buf[..rlen].copy_from_slice(resolved);
        buf[rlen..rlen + 4].copy_from_slice(b".COM");
        let fd = crate::kernel::vfs::open(&buf[..rlen + 4], &mut dos.fds);
        if fd >= 0 { return fd; }
    }
    // Try .EXE
    if rlen + 4 <= buf.len() {
        buf[rlen..rlen + 4].copy_from_slice(b".EXE");
        let fd = crate::kernel::vfs::open(&buf[..rlen + 4], &mut dos.fds);
        if fd >= 0 { return fd; }
    }
    // Try .ELF
    if rlen + 4 <= buf.len() {
        buf[rlen..rlen + 4].copy_from_slice(b".ELF");
        let fd = crate::kernel::vfs::open(&buf[..rlen + 4], &mut dos.fds);
        if fd >= 0 { return fd; }
    }
    -2 // ENOENT
}

/// Expand a .BAT file to its first executable command.
///
/// If `filename[..flen]` names a .BAT file, open it, find the first line
/// that isn't blank / REM / `@echo off` / `:label`, strip a leading `@`,
/// and copy the first whitespace-delimited token back into `filename`.
/// Returns the new length. For non-.BAT names, returns `flen` unchanged.
///
/// Only the first command is executed — multi-line BAT semantics (loops,
/// conditionals, state) are out of scope for this basic handler.
fn expand_bat(dos: &mut thread::DosState, filename: &mut [u8; 128], flen: usize) -> usize {
    // Case-insensitive suffix check for ".BAT"
    if flen < 4 { return flen; }
    let tail = &filename[flen - 4..flen];
    if !(tail[0] == b'.'
        && (tail[1] & 0xDF) == b'B'
        && (tail[2] & 0xDF) == b'A'
        && (tail[3] & 0xDF) == b'T') { return flen; }

    let mut resolved = [0u8; 164];
    let res = dos_resolve_path(dos, &filename[..flen], &mut resolved);
    let rlen = res.len();
    let mut path = [0u8; 164];
    path[..rlen].copy_from_slice(&resolved[..rlen]);
    let fd = crate::kernel::vfs::open(&path[..rlen], &mut dos.fds);
    if fd < 0 { return flen; }

    let mut buf = [0u8; 512];
    let n = crate::kernel::vfs::read_raw(fd, &mut buf, &dos.fds);
    crate::kernel::vfs::close(fd, &mut dos.fds);
    if n <= 0 { return flen; }
    let n = n as usize;

    // Walk lines, find the first real command.
    let mut p = 0usize;
    while p < n {
        // Skip leading whitespace
        while p < n && matches!(buf[p], b' ' | b'\t') { p += 1; }
        // Blank line?
        if p >= n || matches!(buf[p], b'\r' | b'\n') {
            while p < n && matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Optional leading '@' (suppress echo) — strip it
        let mut q = p;
        if buf[q] == b'@' { q += 1; }
        // REM / ECHO OFF / label — skip whole line
        let lower = |i: usize| -> u8 { if i < n { buf[i] & 0xDF } else { 0 } };
        let end_of_word = |i: usize| -> bool {
            i >= n || matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n')
        };
        let is_rem = lower(q) == b'R' && lower(q+1) == b'E' && lower(q+2) == b'M' && end_of_word(q+3);
        let is_echo = lower(q) == b'E' && lower(q+1) == b'C' && lower(q+2) == b'H' && lower(q+3) == b'O' && end_of_word(q+4);
        let is_label = buf[q] == b':';
        if is_rem || is_echo || is_label {
            while p < n && !matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Real command — extract first whitespace-delimited token
        let start = q;
        let mut end = q;
        while end < n && !matches!(buf[end], b' ' | b'\t' | b'\r' | b'\n') { end += 1; }
        let tok_len = (end - start).min(127);
        // Zero the buffer first so leftover bytes don't leak
        for b in filename.iter_mut() { *b = 0; }
        filename[..tok_len].copy_from_slice(&buf[start..start + tok_len]);
        return dos_normalize_path(filename, tok_len);
    }
    flen
}

/// Resolve path and return ForkExec action for the event loop to execute.
/// Synth ABI: on success BX=child_tid, CF=0. On error AX=errno, CF=1.
fn fork_exec(dos: &mut thread::DosState, prog_name: &[u8]) -> thread::KernelAction {
    // Resolve to full path using DOS cwd
    let mut path = [0u8; 164];
    let resolved = dos_resolve_path(dos, prog_name, &mut path);
    let path_len = resolved.len();

    fn on_error(regs: &mut Regs, err: i32) {
        regs.rax = (regs.rax & !0xFFFF) | err as u64;
        regs.set_flag32(1);
    }

    fn on_success(regs: &mut Regs, child_tid: i32) {
        regs.rbx = (regs.rbx & !0xFFFF) | ((child_tid as u16) as u64);
        regs.clear_flag32(1);
    }

    thread::KernelAction::ForkExec {
        path,
        path_len,
        on_error,
        on_success,
    }
}

/// DOS INT 4Bh EXEC — load and execute a DOS program in-process.
/// Loads a .COM or MZ .EXE into a fresh child segment above `heap_seg`,
/// shares the address space with the parent, and transfers control.
/// Parent resumes via exec_return on child INT 20h / 4C00.
/// Non-DOS formats (ELF, BAT) should be routed through COMMAND.COM /C
/// which uses synth INT 31h AH=01h to fork+exec+wait a separate thread.
fn exec_program(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let al = regs.rax as u8;
    if al != 0 {
        regs.rax = (regs.rax & !0xFFFF) | 1;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }

    // Read ASCIIZ filename from DS:DX
    let ds = regs.ds as u16 as u32;
    let dx = regs.rdx as u16 as u32;
    let mut addr = (ds << 4) + dx;
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = unsafe { *(addr as *const u8) };
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }

    // Read parameter block at ES:BX
    let es = regs.es as u32;
    let bx = regs.rbx as u32;
    let pb = (es << 4) + bx;
    let cmdtail_off = unsafe { ((pb + 2) as *const u16).read_unaligned() } as u32;
    let cmdtail_seg = unsafe { ((pb + 4) as *const u16).read_unaligned() } as u32;
    let cmdtail_addr = (cmdtail_seg << 4) + cmdtail_off;
    let tail_len = unsafe { *(cmdtail_addr as *const u8) } as usize;
    let mut tail = [0u8; 128];
    let copy_len = tail_len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((cmdtail_addr + 1) as *const u8, tail.as_mut_ptr(), copy_len);
    }

    // Normalize the filename (drive letters, backslashes)
    let flen = dos_normalize_path(&mut filename, flen);
    let prog_name: &[u8] = &filename[..flen];

    // --- DOS program: in-process exec (shared address space) ---
    let fd = dos_open_program(dos, prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &dos.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut dos.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &dos.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &dos.fds);
    crate::kernel::vfs::close(fd, &mut dos.fds);

    let is_exe = is_mz_exe(&buf);
    let child_seg = dos.vm86.heap_seg;

    let mut resolved_copy = [0u8; 164];
    let resolved_name = dos_resolve_path(dos, prog_name, &mut resolved_copy);
    let rlen = resolved_name.len();

    let (cs, ip, ss, sp, end_seg) = if is_exe {
        match load_exe_at(child_seg, COM_SEGMENT, &buf, &resolved_copy[..rlen]) {
            Some(t) => t,
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 11;
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    } else {
        load_com_at(child_seg, COM_SEGMENT, &buf, &resolved_copy[..rlen])
    };

    // Copy command tail to child's PSP at child_seg:0080
    let child_psp = (child_seg as u32) << 4;
    unsafe {
        let tail_dst = (child_psp + 0x80) as *mut u8;
        *tail_dst = copy_len as u8;
        core::ptr::copy_nonoverlapping(tail.as_ptr(), tail_dst.add(1), copy_len);
        *tail_dst.add(1 + copy_len) = 0x0D;
    }

    // Save parent state. Parent's INT frame (IP/CS/FLAGS) is on the VM86
    // stack at current SS:SP. exec_return restores SS:SP so stub_dispatch
    // pops the frame and resumes the parent.
    let prev = dos.vm86.exec_parent.take();
    dos.vm86.heap_seg = end_seg.max(dos.vm86.heap_seg);
    dos.vm86.dta = (child_seg as u32) * 16 + 0x80;
    dos.vm86.exec_parent = Some(ExecParent {
        ss: vm86_ss(regs),
        sp: vm86_sp(regs),
        ds: regs.ds as u16,
        es: regs.es as u16,
        heap_seg: child_seg,
        prev: prev.map(alloc::boxed::Box::new),
    });

    // Set child entry. Push child's CS:IP + FLAGS onto the child's stack
    // so that stub_dispatch's pop restores them correctly.
    regs.set_ss32(ss as u32);
    regs.set_sp32(sp as u32);
    let flags = vm86_flags(regs) as u16;
    vm86_push(regs, flags);
    vm86_push(regs, cs);
    vm86_push(regs, ip);
    regs.ds = child_seg as u64;
    regs.es = child_seg as u64;
    regs.clear_flag32(1);
    thread::KernelAction::Done
}

/// Load a .COM binary into VM86 memory at the child segment (above the parent).
/// Creates a minimal PSP at child_seg:0000 and loads code at child_seg:0100.
fn load_com_child(data: &[u8], child_seg: u16) -> (u16, u16, u16, u16) {
    let base = (child_seg as u32) << 4;
    // Minimal child PSP: INT 20h at offset 0, parent PSP, env segment
    unsafe {
        let psp = base as *mut u8;
        core::ptr::write_bytes(psp, 0, 256);
        *psp = 0xCD;                         // INT 20h
        *psp.add(1) = 0x20;
        *psp.add(2) = 0x00;                  // top of memory
        *psp.add(3) = 0xA0;                  // = 0xA000
        // parent PSP = COM_SEGMENT (the original PSP)
        (psp.add(0x16) as *mut u16).write_unaligned(COM_SEGMENT);
        // copy env segment from parent PSP
        let parent_env = ((COM_SEGMENT as u32 * 16 + 0x2C) as *const u16).read_unaligned();
        (psp.add(0x2C) as *mut u16).write_unaligned(parent_env);
        // command tail
        *psp.add(0x80) = 0;
        *psp.add(0x81) = 0x0D;
    }
    // Load .COM code at child_seg:0100
    let load_addr = base + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), load_addr as *mut u8, data.len());
    }
    (child_seg, COM_OFFSET, child_seg, COM_SP)
}


/// Return from an EXEC'd child to the parent.
/// Restores the parent's CS:IP, SS:SP, DS, ES and clears carry (success).
fn exec_return(dos: &mut thread::DosState, regs: &mut Regs, parent: ExecParent) -> thread::KernelAction {
    regs.set_ss32(parent.ss as u32);
    regs.set_sp32(parent.sp as u32);
    regs.clear_flag32(1);
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    dos.vm86.heap_seg = parent.heap_seg;
    dos.vm86.exec_parent = parent.prev.map(|b| *b);
    thread::KernelAction::Done
}

/// Saved parent state for returning from EXEC'd child.
/// Chained via `prev` so nested exec works (e.g. DN.COM→DN.PRG→gfx.com).
pub struct ExecParent {
    pub ss: u16,
    pub sp: u16,
    pub ds: u16,
    pub es: u16,
    pub heap_seg: u16,
    pub prev: Option<alloc::boxed::Box<ExecParent>>,
}

/// Match a filename against a DOS wildcard pattern (e.g. "*.*", "*.EXE").
/// Case-insensitive. Supports '*' and '?' wildcards.
fn dos_wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    // Convert both pattern and name to 11-byte FCB format (8.3, space-padded)
    // then compare. In FCB format, '?' matches any char including space (padding).
    let to_fcb = |s: &[u8]| -> [u8; 11] {
        let mut fcb = [b' '; 11];
        let mut i = 0;
        let mut pos = 0;
        // Base name (up to 8 chars)
        while i < s.len() && s[i] != b'.' && pos < 8 {
            if s[i] == b'*' {
                while pos < 8 { fcb[pos] = b'?'; pos += 1; }
                i += 1;
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        // Skip to dot
        while i < s.len() && s[i] != b'.' { i += 1; }
        if i < s.len() && s[i] == b'.' { i += 1; }
        // Extension (up to 3 chars)
        pos = 8;
        while i < s.len() && pos < 11 {
            if s[i] == b'*' {
                while pos < 11 { fcb[pos] = b'?'; pos += 1; }
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        fcb
    };

    let pat_fcb = to_fcb(pattern);
    let name_fcb = to_fcb(name);

    for i in 0..11 {
        if pat_fcb[i] != b'?' && pat_fcb[i] != name_fcb[i] {
            return false;
        }
    }
    true
}

/// Change working directory. Path is already normalized (no drive letters, forward slashes).
/// Updates the thread's cwd after validating the directory exists.
fn dos_chdir(dos: &mut thread::DosState, path: &[u8]) -> i32 {
    if path == b".." {
        let cwd = dos.cwd_str();
        if cwd.is_empty() { return 0; }
        let without_slash = &cwd[..cwd.len().saturating_sub(1)];
        let new_len = match without_slash.iter().rposition(|&b| b == b'/') {
            Some(pos) => pos + 1,
            None => 0,
        };
        dos.cwd_len = new_len;
        return 0;
    }

    if path.is_empty() || path == b"/" {
        dos.cwd_len = 0;
        return 0;
    }

    let mut new_cwd = [0u8; 64];
    let mut pos = 0;

    if path[0] == b'/' {
        for &b in &path[1..] {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
    } else {
        let cwd = dos.cwd_str();
        for &b in cwd {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
        for &b in path {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
    }
    if pos > 0 && new_cwd[pos - 1] != b'/' {
        if pos < new_cwd.len() { new_cwd[pos] = b'/'; pos += 1; }
    }

    let prefix = &new_cwd[..pos];
    if !crate::kernel::vfs::dir_exists(prefix) {
        return -2;
    }

    dos.set_cwd(prefix);
    0
}

/// Resolve a normalized path to an absolute VFS path.
/// Leading `/` = absolute (strip slash). Otherwise prepend cwd.
/// Returns the resolved path length in `out`.
fn dos_resolve_path<'a>(dos: &mut thread::DosState, path: &[u8], out: &'a mut [u8; 164]) -> &'a [u8] {
    let mut pos = 0;
    if !path.is_empty() && path[0] == b'/' {
        // Absolute — skip leading slash
        for &b in &path[1..] {
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
    } else {
        // Relative — prepend cwd
        let cwd = dos.cwd_str();
        for &b in cwd {
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
        for &b in path {
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
    }
    let result = &out[..pos];
    result
}

/// Normalize a DOS path in-place: convert `\` to `/`, strip drive letter.
/// `C:\foo` → `/foo` (absolute), `C:foo` → `foo` (relative), `\foo` → `/foo`.
/// Returns the new path length.
fn dos_normalize_path(buf: &mut [u8], len: usize) -> usize {
    // Convert backslashes to forward slashes
    for i in 0..len {
        if buf[i] == b'\\' { buf[i] = b'/'; }
    }
    // Strip drive letter prefix (X: or X:/)
    if len >= 2 && buf[0].is_ascii_alphabetic() && buf[1] == b':' {
        buf.copy_within(2..len, 0);
        return len - 2;
    }
    len
}

/// FindFirst/FindNext helper: resume search from dos.vm86.find_idx,
/// updating it in place. Directory and pattern come from find_path.
fn find_matching_file(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // Split find_path into directory and pattern components.
    // find_path is an absolute VFS path like "DN/DN*.SWP" or "*.*".
    // The directory part includes any trailing slash; the pattern is
    // the basename (filespec with wildcards).
    let path_len = dos.vm86.find_path_len as usize;
    let full = &dos.vm86.find_path[..path_len];
    let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let dir_buf = {
        let mut b = [0u8; 96];
        b[..split].copy_from_slice(&full[..split]);
        (b, split)
    };
    let pat_buf = {
        let mut b = [0u8; 32];
        let plen = (path_len - split).min(b.len());
        b[..plen].copy_from_slice(&full[split..split + plen]);
        (b, plen)
    };
    let dir = &dir_buf.0[..dir_buf.1];
    let pat = &pat_buf.0[..pat_buf.1];

    let mut idx = dos.vm86.find_idx as usize;

    loop {
        match crate::kernel::vfs::readdir(dir, idx) {
            Some(entry) => {
                idx += 1;
                let name = &entry.name[..entry.name_len];
                if dos_wildcard_match(pat, name) {
                    dos.vm86.find_idx = idx as u16;
                    // Fill DTA at dos.vm86.dta
                    let dta = dos.vm86.dta;
                    // DTA layout (43 bytes):
                    //   0x00-0x14: reserved (unused by us — state lives in DosState)
                    //   0x15: attribute of matched file
                    //   0x16: file time (2 bytes)
                    //   0x18: file date (2 bytes)
                    //   0x1A: file size (4 bytes, little-endian)
                    //   0x1E: filename (13 bytes, null-terminated, 8.3 format)
                    unsafe {
                        let p = dta as *mut u8;
                        core::ptr::write_bytes(p, 0, 43);
                        *p.add(0x15) = if entry.is_dir { 0x10 } else { 0x20 };
                        (p.add(0x1A) as *mut u32).write_unaligned(entry.size);
                        let name_len = entry.name_len.min(12);
                        core::ptr::copy_nonoverlapping(
                            entry.name.as_ptr(),
                            p.add(0x1E),
                            name_len,
                        );
                        *p.add(0x1E + name_len) = 0;
                    }
                    regs.clear_flag32(1);
                    return thread::KernelAction::Done;
                }
            }
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 18; // no more files
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    }
}

/// Prepare the VM86 IVT for a new process.
///
/// The BIOS IVT at 0x0000-0x03FF is preserved from the COW copy of page 0,
/// so BIOS handlers in ROM (0xF0000-0xFFFFF) are accessible. When a BIOS
/// handler does I/O (IN/OUT), it traps through the IOPB to our virtual
/// PIC/keyboard, so BIOS code works transparently.
///
/// Stub area base in conventional memory (segment 0x0050, offset 0x0000)
pub(crate) const STUB_BASE: u32 = 0x0500;
pub(crate) const STUB_SEG: u16 = 0x0050;

/// Trap vector for all stubs (only one in TSS bitmap)
const STUB_INT: u8 = 0x31;

// Slot assignments in the unified CD 31 array (256 entries, 2 bytes each).
// Slot N at offset N*2 from segment base. After CD 31, IP = N*2+2, slot = (IP-2)/2.
const SLOT_XMS: u8 = 0x00;
const SLOT_DPMI_ENTRY: u8 = 0x01;
pub(crate) const SLOT_CALLBACK_RET: u8 = 0x02;
pub(crate) const SLOT_RAW_REAL_TO_PM: u8 = 0x03;
pub(crate) const SLOT_CB_ENTRY_BASE: u8 = 0x04;
pub(crate) const SLOT_CB_ENTRY_END: u8 = 0x14; // exclusive (16 callbacks)
pub(crate) const SLOT_SAVE_RESTORE: u8 = 0xFD;
pub(crate) const SLOT_EXCEPTION_RET: u8 = 0xFE;
pub(crate) const SLOT_PM_TO_REAL: u8 = 0xFF;

/// Offset within STUB_SEG for a given slot number.
pub(crate) const fn slot_offset(slot: u8) -> u16 { (slot as u16) * 2 }

/// Dummy file handle returned for device "EMMXXXX0" (EMS detection)
const EMS_DEVICE_HANDLE: u16 = 0xFE;

pub fn setup_ivt() {
    // Unified stub array: 256 entries × 2 bytes (CD 31) at 0x0500-0x06FF.
    // Slot N at offset N*2. VM86 traps via TSS bitmap bit 31h; PM fires INT 31h (DPL=3).
    unsafe {
        let b = STUB_BASE as *mut u8;
        for i in 0..256u32 {
            *b.add((i * 2) as usize) = 0xCD;
            *b.add((i * 2 + 1) as usize) = STUB_INT;
        }
    }

    // Patch IVT entries to point to our stubs (IVT lives at linear 0x0000)
    for &int_num in &[0x13u8, 0x20, 0x21, 0x25, 0x26, 0x28, 0x2E, 0x2F] {
        write_u16(0, (int_num as u32) * 4, slot_offset(int_num));
        write_u16(0, (int_num as u32) * 4 + 2, STUB_SEG);
    }

    // Set up fake DOS internal structures (List of Lists + System File Table)
    // so that DJGPP's fstat (which uses INT 21h/52h → SFT) can find file info.
    setup_lol_sft();

    // Scan upper memory to find free pages for UMB/EMS
    scan_uma();
}

// ── Low-memory layout (sequential from STUB_BASE) ──────────────────
// Stubs:   256 × 2 bytes         0x0500–0x06FF
// SYSPSP:  256 bytes             0x0700–0x07FF   (seg 0x70)
// LoL:     0x40 bytes            0x0800–0x083F   (seg 0x80)
// SFT:     6 + 20×59 = 1186      0x0840–0x0CE1
// CDS:     3 × 81 = 243          0x0CE2–0x0DD4
// (env block starts at next paragraph + 0x100 gap for COM_SEGMENT)
//
// SYSPSP is a minimal "system" PSP whose parent-PSP field points to itself,
// matching real DOS: COMMAND.COM's PSP[0x16] points to a distinct SYSPSP
// segment, and SYSPSP[0x16] self-references (terminating the chain).
// DPMILOAD checks grandparent != parent and refuses to run if they match,
// so we must never make the initial program self-parenting.
const SYSPSP_ADDR: u32 = STUB_BASE + 256 * 2;                     // 0x0700
const SYSPSP_SIZE: u32 = 256;
const SYSPSP_SEG: u16 = (SYSPSP_ADDR >> 4) as u16;                // 0x70
/// Offset within SYSPSP of the INDOS flag byte (permanently zero).
/// Placed in the "command tail" area since the system PSP never runs.
const INDOS_FLAG_OFFSET: u16 = 0xFE;
const LOL_ADDR: u32 = SYSPSP_ADDR + SYSPSP_SIZE;                  // 0x0800
const LOL_SIZE: u32 = 0x40;
const SFT_ADDR: u32 = LOL_ADDR + LOL_SIZE;                        // 0x0840
const SFT_ENTRIES: u16 = 20;
const SFT_ENTRY_SIZE: u32 = 59;
const SFT_SIZE: u32 = 6 + SFT_ENTRIES as u32 * SFT_ENTRY_SIZE;    // 1186
const CDS_ADDR: u32 = SFT_ADDR + SFT_SIZE;                        // 0x0CE2
const CDS_ENTRY_SIZE: u32 = 81;
const NUM_DRIVES: u8 = 3;
const CDS_SIZE: u32 = NUM_DRIVES as u32 * CDS_ENTRY_SIZE;         // 243
const DOS_AREA_END: u32 = CDS_ADDR + CDS_SIZE;                    // 0x0DD5
const LOL_SEG: u16 = (LOL_ADDR >> 4) as u16;

/// Write a little-endian u16 to an arbitrary (possibly unaligned) address.
unsafe fn write_le16(addr: *mut u8, val: u16) {
    *addr = val as u8;
    *addr.add(1) = (val >> 8) as u8;
}

/// Write a little-endian u32 to an arbitrary (possibly unaligned) address.
unsafe fn write_le32(addr: *mut u8, val: u32) {
    *addr = val as u8;
    *addr.add(1) = (val >> 8) as u8;
    *addr.add(2) = (val >> 16) as u8;
    *addr.add(3) = (val >> 24) as u8;
}

fn setup_lol_sft() {
    unsafe {
        // Zero the whole DOS area (SYSPSP + LoL + SFT + CDS)
        let total = (DOS_AREA_END - SYSPSP_ADDR) as usize;
        core::ptr::write_bytes(SYSPSP_ADDR as *mut u8, 0, total);

        // SYSPSP: a stand-in for COMMAND.COM's PSP. Its parent-PSP field
        // points to itself, terminating the PSP parent chain. Real DOS
        // does the same for COMMAND.COM. This is what the initial program's
        // PSP[0x16] points to, so DPMILOAD's grandparent check succeeds
        // (grandparent = SYSPSP_SEG != parent = COM_SEGMENT).
        let syspsp = SYSPSP_ADDR as *mut u8;
        *syspsp.add(0) = 0xCD;                // INT 20h
        *syspsp.add(1) = 0x20;
        *syspsp.add(2) = 0x00;                // top of memory = 0xA000
        *syspsp.add(3) = 0xA0;
        write_le16(syspsp.add(0x16), SYSPSP_SEG); // self-reference

        let lol = LOL_ADDR as *mut u8;
        // LoL+04h: far pointer to SFT
        write_le16(lol.add(4), (SFT_ADDR & 0xF) as u16);
        write_le16(lol.add(6), (SFT_ADDR >> 4) as u16);
        // LoL+16h: far pointer to CDS array
        write_le16(lol.add(0x16), (CDS_ADDR & 0xF) as u16);
        write_le16(lol.add(0x18), (CDS_ADDR >> 4) as u16);
        // LoL+20h: number of block devices
        *lol.add(0x20) = 1; // one block device (C:)
        // LoL+21h: LASTDRIVE
        *lol.add(0x21) = NUM_DRIVES;

        // SFT header: next pointer = FFFF:FFFF (end of chain), count = SFT_ENTRIES
        let sft = SFT_ADDR as *mut u8;
        write_le32(sft, 0xFFFFFFFF);
        write_le16(sft.add(4), SFT_ENTRIES);

        // Pre-populate entries 0-2 as character devices (stdin/stdout/stderr)
        for i in 0..3u32 {
            let entry = sft.add(6 + (i * SFT_ENTRY_SIZE) as usize);
            write_le16(entry, 1); // refcount = 1
            write_le16(entry.add(5), 0x80 | if i == 0 { 1 } else { 2 }); // device info
        }

        // CDS entries: A: and B: invalid (flags=0), C: valid
        let cds = CDS_ADDR as *mut u8;
        // C: entry (index 2)
        let c_entry = cds.add(2 * CDS_ENTRY_SIZE as usize);
        // Path: "C:\" (67-byte ASCIIZ field)
        *c_entry.add(0) = b'C';
        *c_entry.add(1) = b':';
        *c_entry.add(2) = b'\\';
        // +43h: flags — 0x4000 = valid physical drive
        write_le16(c_entry.add(0x43), 0x4000);
        // +4Fh: backslash offset (points to the '\' in "C:\")
        write_le16(c_entry.add(0x4F), 2);
    }
}

/// Populate SFT entry for a newly opened file handle.
fn sft_set_file(handle: u16, size: u32) {
    if handle as u32 >= SFT_ENTRIES as u32 { return; }
    unsafe {
        let entry = (SFT_ADDR as *mut u8).add(6 + handle as usize * SFT_ENTRY_SIZE as usize);
        write_le16(entry.add(0x00), 1);       // refcount
        write_le16(entry.add(0x02), 0);       // open mode (read)
        *entry.add(0x04) = 0x20;              // attribute = archive
        write_le16(entry.add(0x05), 0x0000);  // device info = file
        write_le16(entry.add(0x0D), 0x6000);  // time: 12:00:00
        write_le16(entry.add(0x0F), 0x5C76);  // date: 2026-03-22
        write_le32(entry.add(0x11), size);    // file size
        write_le32(entry.add(0x15), 0);       // position = 0
    }
}

/// Clear SFT entry when a file handle is closed.
fn sft_clear(handle: u16) {
    if handle as u32 >= SFT_ENTRIES as u32 { return; }
    unsafe {
        let entry = (SFT_ADDR as *mut u8).add(6 + handle as usize * SFT_ENTRY_SIZE as usize);
        write_le16(entry, 0); // refcount = 0
    }
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Map the PSP and environment for a DOS program.
///
/// - PSP (256 bytes) at COM_SEGMENT:0000.
/// - Environment block 256 bytes before PSP.
///
/// Pages are written via demand paging (ring-1 writes trigger page faults
/// that allocate fresh pages at ring 0).
fn map_psp(psp_seg: u16, parent_psp: u16, prog_name: &[u8]) {
    let psp_addr = (psp_seg as usize) << 4;

    // Environment: create fresh for first load, inherit from parent for child exec
    let env_seg = if psp_seg == parent_psp {
        // First load — create env block below PSP
        let env_seg: u16 = psp_seg - 0x10;
        let env_ptr = ((env_seg as usize) << 4) as *mut u8;
        unsafe { core::ptr::write_bytes(env_ptr, 0, 256); }
        let mut off = 0;
        let comspec = b"COMSPEC=C:\\COMMAND.COM\0";
        unsafe { core::ptr::copy_nonoverlapping(comspec.as_ptr(), env_ptr.add(off), comspec.len()); }
        off += comspec.len();
        let path = b"PATH=C:\\\0";
        unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), env_ptr.add(off), path.len()); }
        off += path.len();
        unsafe {
            *env_ptr.add(off) = 0; off += 1;
            *env_ptr.add(off) = 0x01; *env_ptr.add(off + 1) = 0x00; off += 2;
        }
        let prefix = b"C:\\";
        unsafe { core::ptr::copy_nonoverlapping(prefix.as_ptr(), env_ptr.add(off), prefix.len()); }
        off += prefix.len();
        for &b in prog_name {
            let c = if b == b'/' { b'\\' } else { b.to_ascii_uppercase() };
            unsafe { *env_ptr.add(off) = c; }
            off += 1;
        }
        unsafe { *env_ptr.add(off) = 0; }
        env_seg
    } else {
        // Child exec — inherit parent's env
        unsafe { ((parent_psp as u32 * 16 + 0x2C) as *const u16).read_unaligned() }
    };

    // Parent-PSP segment for PSP[0x16]. For initial load (no real parent),
    // point at SYSPSP — matches real DOS, where COMMAND.COM's parent is the
    // system PSP (not itself). DPMILOAD relies on grandparent != parent.
    let parent_field = if psp_seg == parent_psp { SYSPSP_SEG } else { parent_psp };

    let psp_ptr = psp_addr as *mut u8;
    unsafe {
        core::ptr::write_bytes(psp_ptr, 0, 256);
        *psp_ptr.add(0) = 0xCD; // INT 20h
        *psp_ptr.add(1) = 0x20;
        *psp_ptr.add(2) = 0x00; // top of memory = 0xA000
        *psp_ptr.add(3) = 0xA0;
        // Parent PSP segment
        *psp_ptr.add(0x16) = parent_field as u8;
        *psp_ptr.add(0x17) = (parent_field >> 8) as u8;
        *psp_ptr.add(0x2C) = env_seg as u8;
        *psp_ptr.add(0x2D) = (env_seg >> 8) as u8;
        // JFT: pointer at PSP+0x18 → inline JFT at PSP+0x34
        *(psp_ptr.add(0x18) as *mut u16) = 0x0034; // offset
        *(psp_ptr.add(0x1A) as *mut u16) = psp_seg; // segment
        *(psp_ptr.add(0x32) as *mut u16) = 20; // max open files
        // Inline JFT (20 bytes at PSP+0x34): 0/1/2 = stdin/stdout/stderr, rest = 0xFF
        *psp_ptr.add(0x34) = 0; // stdin → SFT 0
        *psp_ptr.add(0x35) = 1; // stdout → SFT 1
        *psp_ptr.add(0x36) = 2; // stderr → SFT 2
        for i in 3..20usize {
            *psp_ptr.add(0x34 + i) = 0xFF; // closed
        }
        *psp_ptr.add(0x80) = 0; // command tail length
        *psp_ptr.add(0x81) = 0x0D; // CR
    }

}

/// Check if data starts with the MZ signature.
pub fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Load a .COM binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// Layout:
///   Segment COM_SEGMENT:
///     0x0000-0x00FF: PSP (Program Segment Prefix)
///     0x0100-...:    .COM binary code
///   Stack at COM_SEGMENT:COM_SP (top of segment)
pub fn load_com(data: &[u8], prog_name: &[u8]) -> (u16, u16, u16, u16, u16) {
    load_com_at(COM_SEGMENT, COM_SEGMENT, data, prog_name)
}

/// Returns (cs, ip, ss, sp, end_seg) — caller sets heap_seg = end_seg.
fn load_com_at(psp_seg: u16, parent_psp: u16, data: &[u8], prog_name: &[u8]) -> (u16, u16, u16, u16, u16) {
    map_psp(psp_seg, parent_psp, prog_name);
    let end_seg = psp_seg.wrapping_add(0x1000);

    // Copy .COM data at offset 0x100
    let base = (psp_seg as u32) << 4;
    let load_addr = base + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            data.len(),
        );
    }

    (psp_seg, COM_OFFSET, psp_seg, COM_SP, end_seg)
}

/// Load an MZ .EXE binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// MZ header layout (first 28 bytes):
///   0x00: 'MZ' signature
///   0x02: bytes on last page (0 = full 512-byte page)
///   0x04: total pages (512 bytes each, includes header)
///   0x06: relocation count
///   0x08: header size in paragraphs (16 bytes each)
///   0x0E: initial SS (relative to load segment)
///   0x10: initial SP
///   0x14: initial IP
///   0x16: initial CS (relative to load segment)
///   0x18: relocation table offset
pub fn load_exe(data: &[u8], prog_name: &[u8]) -> Option<(u16, u16, u16, u16, u16)> {
    load_exe_at(COM_SEGMENT, COM_SEGMENT, data, prog_name)
}

/// Returns (cs, ip, ss, sp, end_seg) — caller sets heap_seg = end_seg.
fn load_exe_at(psp_seg: u16, parent_psp: u16, data: &[u8], prog_name: &[u8]) -> Option<(u16, u16, u16, u16, u16)> {
    if data.len() < 28 {
        return None;
    }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
    let min_extra = w(0x0A) as u32;
    let init_ss = w(0x0E);
    let init_sp = w(0x10);
    let init_ip = w(0x14);
    let init_cs = w(0x16);
    let reloc_offset = w(0x18) as usize;

    // Calculate file size and load module offset/size
    let file_size = if last_page_bytes == 0 {
        total_pages * 512
    } else {
        (total_pages - 1) * 512 + last_page_bytes
    };
    let header_size = header_paragraphs * 16;
    let load_size = file_size.saturating_sub(header_size) as usize;

    if header_size as usize > data.len() || load_size > data.len() - header_size as usize {
        return None;
    }

    // Load segment: PSP is at psp_seg, load module starts one segment after
    let load_segment = psp_seg + 0x10; // 256 bytes after PSP base

    map_psp(psp_seg, parent_psp, prog_name);

    // Set initial heap past the loaded program (PSP + load image + min extra/BSS)
    let load_paras = ((load_size as u32 + 15) / 16) as u16;
    let end_seg = load_segment.wrapping_add(load_paras).wrapping_add(min_extra as u16);

    // Copy load module
    let load_base = (load_segment as u32) << 4;
    let load_data = &data[header_size as usize..header_size as usize + load_size];
    unsafe {
        core::ptr::copy_nonoverlapping(
            load_data.as_ptr(),
            load_base as *mut u8,
            load_size,
        );
    }

    // Apply relocations: each entry is (offset, segment) within the load module.
    // Add load_segment to the 16-bit word at that address.
    let reloc_end = reloc_offset + reloc_count * 4;
    if reloc_end > data.len() {
        return None;
    }
    for i in 0..reloc_count {
        let entry = reloc_offset + i * 4;
        let off = w(entry) as u32;
        let seg = w(entry + 2) as u32;
        let addr = load_base + (seg << 4) + off;
        unsafe {
            let p = addr as *mut u16;
            let val = p.read_unaligned();
            p.write_unaligned(val.wrapping_add(load_segment));
        }
    }

    let cs = init_cs.wrapping_add(load_segment);
    let ss = init_ss.wrapping_add(load_segment);

    Some((cs, init_ip, ss, init_sp, end_seg))
}
