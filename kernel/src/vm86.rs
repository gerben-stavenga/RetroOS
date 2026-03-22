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

use crate::thread;
use crate::vga;
use crate::dbg_println;
use crate::Regs;

const IF_FLAG: u32 = 1 << 9;
const IOPL_MASK: u32 = 3 << 12;
const VM_FLAG: u32 = 1 << 17;
const VIF_FLAG: u32 = 1 << 19;

/// Flags that VM86 code cannot change (IOPL, VM)
const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG;

fn vme_active() -> bool {
    crate::x86::read_cr4() & crate::x86::cr4::VME != 0
}


/// .COM load segment (standard DOS convention: PSP at seg:0000, code at seg:0100)
pub const COM_SEGMENT: u16 = 0x1000;
/// .COM code offset within segment
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer (top of 64KB segment)
const COM_SP: u16 = 0xFFFE;



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
/// Models the 8042 output buffer.  Scancodes are queued by `push()` when a
/// hardware IRQ arrives.  When INT 9 is reflected into the VM86 guest, the
/// next scancode is *latched* into `port60` so that port 0x60 reads return it
/// (idempotently — multiple reads give the same value, like real hardware).
/// Port 0x64 bit 0 (OBF) is set when a scancode is latched and cleared after
/// the guest's INT 9 handler EOIs.
pub struct VirtualKeyboard {
    buffer: [u8; KBD_BUF_SIZE],
    head: usize,
    tail: usize,
    /// Latched scancode visible via port 0x60 (set when INT 9 is reflected)
    pub port60: u8,
    /// Output Buffer Full flag — port 0x64 bit 0
    pub obf: bool,
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self { buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0, port60: 0, obf: false }
    }

    /// Buffer a scancode from the real keyboard IRQ handler
    pub fn push(&mut self, scancode: u8) {
        let next = (self.tail + 1) % KBD_BUF_SIZE;
        if next != self.head {
            self.buffer[self.tail] = scancode;
            self.tail = next;
        }
    }

    /// Latch the next scancode into port60 for INT 9 delivery.
    /// Called just before reflecting INT 9 to the guest.
    pub fn latch(&mut self) -> bool {
        if self.head == self.tail { return false; }
        let sc = self.buffer[self.head];
        self.head = (self.head + 1) % KBD_BUF_SIZE;
        self.port60 = sc;
        self.obf = true;
        true
    }

    /// Read port 0x60 — returns latched scancode (idempotent, like real 8042)
    pub fn read_port60(&self) -> u8 {
        self.port60
    }

    /// Check if data is available (port 0x64 bit 0)
    pub fn has_data(&self) -> bool {
        self.obf
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
// EMS (Expanded Memory Specification) state
// ============================================================================

const MAX_EMS_HANDLES: usize = 16;
/// Total EMS pages available (256 × 16KB = 4MB)
const EMS_TOTAL_PAGES: u16 = 256;
/// EMS page frame segment (linear 0xD0000)
pub const EMS_FRAME_SEG: u16 = 0xD000;

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
        for w in 0..4 {
            if self.frame[w].is_some() {
                self.frame[w] = None;
                crate::paging2::map_ems_window(w, None);
            }
        }
        for handle in &mut self.handles {
            if let Some(h) = handle.take() {
                for group in &h.pages {
                    for &p in group {
                        crate::phys_mm::free_phys_page(p);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Virtual I/O port emulation
// ============================================================================

/// Emulate IN from a port.
fn emulate_inb(port: u16) -> Result<u8, Action> {
    match port {
        // VGA ports — pass through to hardware
        0x3C0..=0x3DF => Ok(crate::x86::inb(port)),
        // Master PIC command (read ISR)
        0x20 => Ok(thread::current().vpic.isr),
        // Master PIC data (read IMR)
        0x21 => Ok(thread::current().vpic.imr),
        // Keyboard data port — returns latched scancode (like real 8042 output buffer)
        0x60 => {
            let sc = thread::current().vkbd.read_port60();
            if sc != 0 { dbg_println!("KBD: port 0x60 read -> {:02X}", sc); }
            Ok(sc)
        }
        // Keyboard status port (bit 0 = output buffer full)
        0x64 => Ok(if thread::current().vkbd.has_data() { 1 } else { 0 }),
        // PIT counter reads — pass through so timing loops see a changing value
        0x40..=0x42 => Ok(crate::x86::inb(port)),
        // PIT command register not readable
        0x43 => Ok(0xFF),
        // Unknown ports: return 0xFF (unpopulated bus)
        _ => Ok(0xFF)
    }
}

/// Emulate OUT to a port.
fn emulate_outb(port: u16, val: u8) -> Result<(), Action> {
    match port {
        // VGA ports — pass through to hardware
        0x3C0..=0x3DF => {
            crate::x86::outb(port, val);
            Ok(())
        }
        // Master PIC command
        0x20 => {
            if val == 0x20 {
                // Non-specific EOI
                let t = thread::current();
                // If keyboard IRQ (bit 1) was in service, clear output buffer flag
                if t.vpic.isr & 0x02 != 0 {
                    t.vkbd.obf = false;
                }
                t.vpic.eoi();
            }
            Ok(())
        }
        // Master PIC data (write IMR)
        0x21 => {
            thread::current().vpic.imr = val;
            Ok(())
        }
        // Slave PIC command
        0xA0 => Ok(()),
        // Slave PIC data
        0xA1 => Ok(()),
        // Keyboard controller command
        0x64 => Ok(()),
        // PIT command — only allow latch commands (bits 5-4 = 00), block reprogramming
        0x43 => {
            if val & 0x30 == 0x00 { crate::x86::outb(port, val); }
            Ok(())
        }
        // PIT counter data writes — ignore (don't let games reprogram kernel timer)
        0x40..=0x42 => Ok(()),
        // Unknown ports: silently ignore (BIOS probes various ports during mode switches)
        _ => Ok(())
    }
}

// ============================================================================
// Signal delivery — reflect hardware IRQs to VM86 threads via IVT
// ============================================================================

/// Deliver an IRQ event to a VM86 thread: buffer data, reflect through IVT.
///
/// Called from outside the monitor (traps.rs drain, switch_to_thread).
/// EFLAGS.IF may not reflect VIF here, so we map VIF↔IF around reflects.
pub fn deliver_irq(thread: &mut thread::Thread, regs: &mut Regs, event: Option<crate::irq::Irq>) {
    // QEMU bug workaround: QEMU doesn't force Odd/Even read mode in text
    // mode like real VGA hardware does. Periodically restore GC5 bit 4
    // when delivering IRQs, but only when the interrupted code is the DOS
    // program (not BIOS ROM which may need GC5=0x00 for font loading).
    unsafe {
        let cs = regs.frame.f32.cs;
        if cs < 0xC000 {
            let mode = *(0x449 as *const u8);
            if mode <= 3 || mode == 7 {
                let saved_idx = crate::x86::inb(0x3CE);
                crate::x86::outb(0x3CE, 5);
                let gc5 = crate::x86::inb(0x3CF);
                if gc5 & 0x10 == 0 {
                    crate::x86::outb(0x3CF, gc5 | 0x10);
                }
                crate::x86::outb(0x3CE, saved_idx);
            }
        }
    }

    use crate::irq::Irq;
    if let Some(e) = event {
        match e {
            Irq::Key(sc) => { thread.vkbd.push(sc); thread.vpic.push(0x09); }
            Irq::Tick => { thread.vpic.push(0x08); }
        }
    }
    if !thread.vm86_vif { return; }
    // Don't deliver while a handler is in service — prevents nesting into
    // non-reentrant BIOS code (e.g. new timer IRQ injected inside keyboard handler
    // after STI). Pending IRQs stay queued until all handlers EOI.
    if thread.vpic.isr != 0 { return; }
    // Deliver only ONE interrupt at a time to avoid overflowing small DOS stacks
    // (e.g. Prince of Persia SP=0x0080). Remaining events stay queued in vpic
    // and get delivered on subsequent traps after the handler EOIs.
    let vec = match thread.vpic.pop() {
        Some(v) => v,
        None => return,
    };
    // For keyboard IRQ (INT 9): latch scancode into port 0x60 before reflecting
    if vec == 0x09 {
        if !thread.vkbd.latch() {
            // No scancode available — spurious INT 9, drop it
            return;
        }
    }
    let irq_num = vec.wrapping_sub(8);
    if irq_num < 8 {
        thread.vpic.isr |= 1 << irq_num;
    }
    let saved_if = sync_vif(thread, regs);
    reflect_interrupt(regs, vec);
    restore_vif(thread, regs, saved_if);
}

/// Map VIF into EFLAGS.IF so handlers/reflect work with IF naturally.
/// Reads VIF from hardware (VME) or thread.vm86_vif (software).
/// Returns the saved real IF value for restore_vif.
fn sync_vif(thread: &mut thread::Thread, regs: &mut Regs) -> u32 {
    unsafe {
        let saved_if = regs.frame.f32.eflags & IF_FLAG;
        if vme_active() {
            thread.vm86_vif = regs.frame.f32.eflags & VIF_FLAG != 0;
        }
        if thread.vm86_vif { regs.frame.f32.eflags |= IF_FLAG; }
        else { regs.frame.f32.eflags &= !IF_FLAG; }
        saved_if
    }
}

/// Extract VIF from EFLAGS.IF back into thread, restore real IF.
/// Writes VIF back to hardware (VME) if active.
fn restore_vif(thread: &mut thread::Thread, regs: &mut Regs, saved_if: u32) {
    unsafe {
        thread.vm86_vif = regs.frame.f32.eflags & IF_FLAG != 0;
        if vme_active() {
            if thread.vm86_vif { regs.frame.f32.eflags |= VIF_FLAG; }
            else { regs.frame.f32.eflags &= !VIF_FLAG; }
        }
        regs.frame.f32.eflags = (regs.frame.f32.eflags & !IF_FLAG) | saved_if;
    }
}

/// Reflect an interrupt through the IVT: push FLAGS/CS/IP, clear IF, set CS:IP.
/// Caller must ensure EFLAGS.IF reflects VIF (via sync_vif).
fn reflect_interrupt(regs: &mut Regs, int_num: u8) {
    unsafe {
        vm86_push(regs, regs.frame.f32.eflags as u16);
        vm86_push(regs, regs.frame.f32.cs as u16);
        vm86_push(regs, regs.frame.f32.eip as u16);
        regs.frame.f32.eflags &= !IF_FLAG;
        regs.frame.f32.eip = read_u16(0, (int_num as u32) * 4) as u32;
        regs.frame.f32.cs = read_u16(0, (int_num as u32) * 4 + 2) as u32;
    }
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
        let cs = regs.frame.f32.cs;
        let ip = regs.frame.f32.eip;
        let linear = (cs << 4) + ip;
        let byte = *(linear as *const u8);
        regs.frame.f32.eip = ip + 1;
        byte
    }
}

/// Read a u16 from a real-mode seg:off address (unaligned-safe, null-safe)
fn read_u16(seg: u32, off: u32) -> u16 {
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
fn write_u16(seg: u32, off: u32, val: u16) {
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
fn vm86_push(regs: &mut Regs, val: u16) {
    unsafe {
        let sp = (regs.frame.f32.esp as u16).wrapping_sub(2);
        regs.frame.f32.esp = (regs.frame.f32.esp & 0xFFFF0000) | sp as u32;
        write_u16(regs.frame.f32.ss, sp as u32, val);
    }
}

/// Pop a u16 from the VM86 stack (SS:SP)
fn vm86_pop(regs: &mut Regs) -> u16 {
    unsafe {
        let sp = regs.frame.f32.esp as u16;
        let val = read_u16(regs.frame.f32.ss, sp as u32);
        regs.frame.f32.esp = (regs.frame.f32.esp & 0xFFFF0000) | sp.wrapping_add(2) as u32;
        val
    }
}

enum Action {
    Done,
    Switch(usize),
    Yield,
}

/// VM86 monitor — called from GP fault handler when EFLAGS.VM=1.
///
/// Maps VIF↔IF on entry/exit so all opcode handlers work with EFLAGS.IF
/// naturally (as if it were the real interrupt flag from the program's view).
/// On return, extracts VIF from IF and restores real IF=1.
pub fn vm86_monitor(regs: &mut Regs) -> Option<usize> {
    let t = thread::current();
    let saved_if = sync_vif(t, regs);
    let action = monitor_impl(regs);
    restore_vif(t, regs, saved_if);

    match action {
        Action::Done => None,
        Action::Switch(idx) => Some(idx),
        Action::Yield => {
            thread::save_state(t, regs);
            t.state = thread::ThreadState::Ready;
            thread::schedule()
        }
    }
}

/// Inner monitor — EFLAGS.IF reflects VIF throughout.
fn monitor_impl(regs: &mut Regs) -> Action {
    let opcode = fetch_byte(regs);

    match opcode {
        // INT n (0xCD nn)
        0xCD => {
            let int_num = fetch_byte(regs);
            handle_vm86_int(regs, int_num)
        }
        // IRET (0xCF) — pop IP, CS, FLAGS from VM86 stack
        // IOPL and VM are preserved (VM86 code cannot change them)
        0xCF => {
            let ip = vm86_pop(regs);
            let cs = vm86_pop(regs);
            let flags = vm86_pop(regs);
            unsafe {
                regs.frame.f32.eip = ip as u32;
                regs.frame.f32.cs = cs as u32;
                let preserved = regs.frame.f32.eflags & PRESERVED_FLAGS;
                regs.frame.f32.eflags = (flags as u32 & !PRESERVED_FLAGS) | preserved;
            }
            Action::Done
        }
        // CLI (0xFA)
        0xFA => {
            unsafe { regs.frame.f32.eflags &= !IF_FLAG; }
            Action::Done
        }
        // STI (0xFB)
        0xFB => {
            unsafe { regs.frame.f32.eflags |= IF_FLAG; }
            Action::Done
        }
        // PUSHF (0x9C) — push FLAGS (IF already reflects VIF)
        0x9C => {
            vm86_push(regs, unsafe { regs.frame.f32.eflags as u16 });
            Action::Done
        }
        // POPF (0x9D) — pop FLAGS
        // IOPL and VM are preserved (VM86 code cannot change them)
        0x9D => {
            let flags = vm86_pop(regs);
            unsafe {
                let preserved = regs.frame.f32.eflags & PRESERVED_FLAGS;
                regs.frame.f32.eflags = (flags as u32 & !PRESERVED_FLAGS) | preserved;
            }
            Action::Done
        }
        // INSB (0x6C) — IN byte from port DX to ES:DI, advance DI
        0x6C => {
            let port = regs.rdx as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            write_u16(regs.es as u32, regs.rdi as u32, val as u16);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(1); // DF=1
            } else {
                regs.rdi = regs.rdi.wrapping_add(1);
            }
            Action::Done
        }
        // INSW (0x6D) — IN word from port DX to ES:DI, advance DI
        0x6D => {
            let port = regs.rdx as u16;
            let lo = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            let hi = match emulate_inb(port + 1) { Ok(v) => v, Err(a) => return a };
            let val = (hi as u16) << 8 | lo as u16;
            write_u16(regs.es as u32, regs.rdi as u32, val);
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rdi = regs.rdi.wrapping_sub(2);
            } else {
                regs.rdi = regs.rdi.wrapping_add(2);
            }
            Action::Done
        }
        // OUTSB (0x6E) — OUT byte from DS:SI to port DX, advance SI
        0x6E => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32) as u8;
            if let Err(a) = emulate_outb(port, val) { return a; }
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(1);
            } else {
                regs.rsi = regs.rsi.wrapping_add(1);
            }
            Action::Done
        }
        // OUTSW (0x6F) — OUT word from DS:SI to port DX, advance SI
        0x6F => {
            let port = regs.rdx as u16;
            let val = read_u16(regs.ds as u32, regs.rsi as u32);
            if let Err(a) = emulate_outb(port, val as u8) { return a; }
            if let Err(a) = emulate_outb(port + 1, (val >> 8) as u8) { return a; }
            if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                regs.rsi = regs.rsi.wrapping_sub(2);
            } else {
                regs.rsi = regs.rsi.wrapping_add(2);
            }
            Action::Done
        }
        // IN AL, imm8 (0xE4)
        0xE4 => {
            let port = fetch_byte(regs) as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            regs.rax = (regs.rax & !0xFF) | val as u64;
            Action::Done
        }
        // IN AX, imm8 (0xE5)
        0xE5 => {
            let port = fetch_byte(regs) as u16;
            let lo = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            let hi = match emulate_inb(port + 1) { Ok(v) => v, Err(a) => return a };
            regs.rax = (regs.rax & !0xFFFF) | (hi as u64) << 8 | lo as u64;
            Action::Done
        }
        // OUT imm8, AL (0xE6)
        0xE6 => {
            let port = fetch_byte(regs) as u16;
            if let Err(a) = emulate_outb(port, regs.rax as u8) { return a; }
            Action::Done
        }
        // OUT imm8, AX (0xE7)
        0xE7 => {
            let port = fetch_byte(regs) as u16;
            let val = regs.rax as u16;
            if let Err(a) = emulate_outb(port, val as u8) { return a; }
            if let Err(a) = emulate_outb(port + 1, (val >> 8) as u8) { return a; }
            Action::Done
        }
        // IN AL, DX (0xEC)
        0xEC => {
            let port = regs.rdx as u16;
            let val = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            regs.rax = (regs.rax & !0xFF) | val as u64;
            Action::Done
        }
        // IN AX, DX (0xED)
        0xED => {
            let port = regs.rdx as u16;
            let lo = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
            let hi = match emulate_inb(port + 1) { Ok(v) => v, Err(a) => return a };
            regs.rax = (regs.rax & !0xFFFF) | (hi as u64) << 8 | lo as u64;
            Action::Done
        }
        // OUT DX, AL (0xEE)
        0xEE => {
            let port = regs.rdx as u16;
            if let Err(a) = emulate_outb(port, regs.rax as u8) { return a; }
            Action::Done
        }
        // OUT DX, AX (0xEF)
        0xEF => {
            let port = regs.rdx as u16;
            let val = regs.rax as u16;
            if let Err(a) = emulate_outb(port, val as u8) { return a; }
            if let Err(a) = emulate_outb(port + 1, (val >> 8) as u8) { return a; }
            Action::Done
        }
        // 0x66 prefix — operand-size override (32-bit in VM86 16-bit mode)
        0x66 => {
            let op = fetch_byte(regs);
            match op {
                // PUSHFD — push 32-bit EFLAGS
                0x9C => {
                    vm86_push32(regs, unsafe { regs.frame.f32.eflags } & 0xFFFF);
                    Action::Done
                }
                // POPFD — pop 32-bit EFLAGS
                0x9D => {
                    let flags = vm86_pop32(regs);
                    unsafe {
                        let preserved = regs.frame.f32.eflags & PRESERVED_FLAGS;
                        regs.frame.f32.eflags = (flags & !PRESERVED_FLAGS) | preserved;
                    }
                    Action::Done
                }
                // IRETD — pop 32-bit EIP, CS, EFLAGS
                0xCF => {
                    let eip = vm86_pop32(regs);
                    let cs = vm86_pop32(regs);
                    let flags = vm86_pop32(regs);
                    unsafe {
                        regs.frame.f32.eip = eip;
                        regs.frame.f32.cs = cs & 0xFFFF;
                        let preserved = regs.frame.f32.eflags & PRESERVED_FLAGS;
                        regs.frame.f32.eflags = (flags & !PRESERVED_FLAGS) | preserved;
                    }
                    Action::Done
                }
                // IN EAX, imm8
                0xE5 => {
                    let port = fetch_byte(regs) as u16;
                    let b0 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let b1 = match emulate_inb(port + 1) { Ok(v) => v, Err(a) => return a };
                    let b2 = match emulate_inb(port + 2) { Ok(v) => v, Err(a) => return a };
                    let b3 = match emulate_inb(port + 3) { Ok(v) => v, Err(a) => return a };
                    regs.rax = (regs.rax & !0xFFFFFFFF) | (b3 as u64) << 24 | (b2 as u64) << 16 | (b1 as u64) << 8 | b0 as u64;
                    Action::Done
                }
                // OUT imm8, EAX
                0xE7 => {
                    let port = fetch_byte(regs) as u16;
                    let val = regs.rax as u32;
                    if let Err(a) = emulate_outb(port, val as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 1, (val >> 8) as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 2, (val >> 16) as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 3, (val >> 24) as u8) { return a; }
                    Action::Done
                }
                // IN EAX, DX
                0xED => {
                    let port = regs.rdx as u16;
                    let b0 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let b1 = match emulate_inb(port + 1) { Ok(v) => v, Err(a) => return a };
                    let b2 = match emulate_inb(port + 2) { Ok(v) => v, Err(a) => return a };
                    let b3 = match emulate_inb(port + 3) { Ok(v) => v, Err(a) => return a };
                    regs.rax = (regs.rax & !0xFFFFFFFF) | (b3 as u64) << 24 | (b2 as u64) << 16 | (b1 as u64) << 8 | b0 as u64;
                    Action::Done
                }
                // OUT DX, EAX
                0xEF => {
                    let port = regs.rdx as u16;
                    let val = regs.rax as u32;
                    if let Err(a) = emulate_outb(port, val as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 1, (val >> 8) as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 2, (val >> 16) as u8) { return a; }
                    if let Err(a) = emulate_outb(port + 3, (val >> 24) as u8) { return a; }
                    Action::Done
                }
                // INSD
                0x6D => {
                    let port = regs.rdx as u16;
                    let b0 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let b1 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let b2 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let b3 = match emulate_inb(port) { Ok(v) => v, Err(a) => return a };
                    let addr = (regs.es as u32) * 16 + (regs.rdi as u16 as u32);
                    unsafe {
                        *(addr as *mut u8) = b0;
                        *((addr + 1) as *mut u8) = b1;
                        *((addr + 2) as *mut u8) = b2;
                        *((addr + 3) as *mut u8) = b3;
                    }
                    if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                        regs.rdi = regs.rdi.wrapping_sub(4);
                    } else {
                        regs.rdi = regs.rdi.wrapping_add(4);
                    }
                    Action::Done
                }
                // OUTSD
                0x6F => {
                    let port = regs.rdx as u16;
                    let addr = (regs.ds as u32) * 16 + (regs.rsi as u16 as u32);
                    unsafe {
                        let _ = emulate_outb(port, *(addr as *const u8));
                        let _ = emulate_outb(port, *((addr + 1) as *const u8));
                        let _ = emulate_outb(port, *((addr + 2) as *const u8));
                        let _ = emulate_outb(port, *((addr + 3) as *const u8));
                    }
                    if unsafe { regs.frame.f32.eflags } & (1 << 10) != 0 {
                        regs.rsi = regs.rsi.wrapping_sub(4);
                    } else {
                        regs.rsi = regs.rsi.wrapping_add(4);
                    }
                    Action::Done
                }
                _ => {
                    crate::println!("VM86: FATAL unhandled opcode 0x66 {:#04x} at {:04x}:{:04x}",
                        op, unsafe { regs.frame.f32.cs }, unsafe { regs.frame.f32.eip } - 2);
                    match thread::exit_thread(-11) {
                        Some(idx) => Action::Switch(idx),
                        None => Action::Done,
                    }
                }
            }
        }
        // HLT (0xF4) — yield to another thread
        0xF4 => {
            Action::Yield
        }
        _ => {
            crate::println!("VM86: FATAL unhandled opcode {:#04x} at {:04x}:{:04x}",
                opcode, unsafe { regs.frame.f32.cs }, unsafe { regs.frame.f32.eip } - 1);
            // Kill the VM86 thread
            match thread::exit_thread(-11) {
                Some(idx) => Action::Switch(idx),
                None => Action::Done,
            }
        }
    }
}

// ============================================================================
// INT dispatch — intercept DOS/BIOS calls, reflect others via IVT
// ============================================================================

/// Handle INT n from VM86 mode.
/// With VME, only INTs whose bit is SET in the redirection bitmap trap here.
/// Without VME, all INTs trap — unintercepted ones are reflected through IVT.
fn handle_vm86_int(regs: &mut Regs, int_num: u8) -> Action {
    if !crate::descriptors::int_intercepted(int_num) {
        reflect_interrupt(regs, int_num);
        return Action::Done;
    }
    match int_num {
        0x20 => {
            // INT 20h — DOS program terminate
            // If we're in an EXEC'd child, return to parent instead of killing thread
            if let Some(parent) = thread::current().vm86_exec_parent.take() {
                return exec_return(regs, &parent);
            }
            match thread::exit_thread(0) {
                Some(idx) => Action::Switch(idx),
                None => Action::Done,
            }
        }
        0x21 => int_21h(regs),
        // INT 2Eh — COMMAND.COM internal execute
        // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
        0x2E => {
            let ds = regs.ds as u32;
            let si = regs.rsi as u32;
            let addr = (ds << 4) + si;
            let len = unsafe { *(addr as *const u8) } as usize;
            let mut cmd = [0u8; 128];
            let copy = len.min(127);
            unsafe {
                core::ptr::copy_nonoverlapping((addr + 1) as *const u8, cmd.as_mut_ptr(), copy);
            }
            // Skip leading spaces
            let mut start = 0;
            while start < copy && cmd[start] == b' ' { start += 1; }
            // Extract program name
            let mut end = start;
            while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
            if end > start {
                let prog = &cmd[start..end];
                dbg_println!("INT 2E: exec {:?}", unsafe { core::str::from_utf8_unchecked(prog) });
                let fd = dos_open_program(prog);
                if fd >= 0 {
                    let size = crate::vfs::seek(fd, 0, 2);
                    crate::vfs::seek(fd, 0, 0);
                    if size > 0 {
                        let mut buf = alloc::vec![0u8; size as usize];
                        crate::vfs::read_raw(fd, &mut buf);
                        crate::vfs::close(fd);

                        let child_seg = thread::current().vm86_heap_seg;
                        let parent_ss = unsafe { regs.frame.f32.ss };
                        let parent_sp = unsafe { regs.frame.f32.esp };
                        let parent_cs = unsafe { regs.frame.f32.cs };
                        let parent_ip = unsafe { regs.frame.f32.eip };
                        let parent_ds = regs.ds as u16;
                        let parent_es = regs.es as u16;

                        let (cs, ip, ss, sp) = load_com_child(&buf, child_seg);
                        // Advance heap past child (64K for COM)
                        let t = thread::current();
                        t.vm86_heap_seg = child_seg.wrapping_add(0x1000).max(t.vm86_heap_seg);
                        unsafe {
                            regs.frame.f32.cs = cs as u32;
                            regs.frame.f32.eip = ip as u32;
                            regs.frame.f32.ss = ss as u32;
                            regs.frame.f32.esp = sp as u32;
                        }
                        regs.ds = child_seg as u64;
                        regs.es = child_seg as u64;

                        let t = thread::current();
                        t.vm86_exec_parent = Some(ExecParent {
                            ss: parent_ss as u16,
                            sp: parent_sp as u16,
                            cs: parent_cs as u16,
                            ip: parent_ip as u16,
                            ds: parent_ds,
                            es: parent_es,
                        });
                        return Action::Done;
                    }
                    crate::vfs::close(fd);
                }
            }
            // Command not found — just return
            Action::Done
        }
        // INT 28h — DOS idle: yield to other threads
        0x28 => Action::Done, // no-op, but could yield here if desired
        // INT 2Fh — Multiplex interrupt (XMS installation check)
        0x2F => int_2fh(regs),
        // INT 67h — EMS driver
        0x67 => int_67h(regs),
        // INT F0h — XMS dispatch (private, called via far-call stub)
        XMS_INT => xms_dispatch(regs),
        _ => {
            panic!("VM86: INT {:02X} intercepted in bitmap but has no handler", int_num);
        }
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(regs: &mut Regs) -> Action {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        0x02 | 0x06 | 0x09 | 0x0C | 0x0E | 0x19 | 0x1A | 0x25 | 0x29 | 0x2F | 0x33 | 0x4F => {}
        _ => dbg_println!("INT21 AH={:02X} AX={:04X}", ah, regs.rax as u16),
    }
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            vga::vga().putchar(regs.rdx as u8);
            Action::Done
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                // Input: check keyboard, ZF=1 if no char
                unsafe { regs.frame.f32.eflags |= 0x40; } // set ZF = no char available
            } else {
                vga::vga().putchar(dl);
            }
            Action::Done
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let ds = regs.ds as u32;
            let dx = regs.rdx as u32;
            let mut addr = (ds << 4) + dx;
            loop {
                let ch = unsafe { *(addr as *const u8) };
                if ch == b'$' { break; }
                vga::vga().putchar(ch);
                addr += 1;
                // Safety limit
                if addr > 0xFFFFF { break; }
            }
            Action::Done
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            let off = regs.rdx as u16;
            let seg = regs.ds as u16;
            dbg_println!("INT21/25: set IVT[{:02X}] = {:04X}:{:04X}", int_num, seg, off);
            write_u16(0, (int_num as u32) * 4, off);
            write_u16(0, (int_num as u32) * 4 + 2, seg);
            Action::Done
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => { regs.rdx = (regs.rdx & !0xFF); } // DL=0: break checking off
                0x01 => {} // set break — ignore
                _ => {}
            }
            Action::Done
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=64-byte buffer)
        // Returns ASCIIZ path without drive letter or leading backslash
        0x47 => {
            let si = regs.rsi as u32;
            let addr = ((regs.ds as u32) << 4) + si;
            let cwd = thread::current().cwd_str();
            unsafe {
                let mut pos = 0;
                for &b in cwd {
                    // Convert '/' to '\' for DOS, skip trailing slash
                    if b == b'/' && pos + 1 >= cwd.len() { break; }
                    *((addr + pos as u32) as *mut u8) = if b == b'/' { b'\\' } else { b };
                    pos += 1;
                }
                *((addr + pos as u32) as *mut u8) = 0; // NUL terminate
                regs.frame.f32.eflags &= !1; // clear CF
            }
            Action::Done
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | 2; // C:
            Action::Done
        }
        // AH=0x0C: Flush input buffer then execute function in AL
        0x0C => {
            // Just execute the sub-function in AL
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                // Direct console I/O — return "no key"
                unsafe { regs.frame.f32.eflags |= 0x40; } // ZF=1
            }
            // Other sub-functions: just return
            Action::Done
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = ((regs.ds as u32) << 4) + regs.rdx as u32;
            thread::current().vm86_dta = dta;
            Action::Done
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = thread::current().vm86_dta;
            regs.es = (dta >> 4) as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | (dta & 0x0F) as u64;
            Action::Done
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 3.30
            regs.rax = (regs.rax & !0xFFFF) | 0x1E03; // AL=3 (major), AH=30 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            Action::Done
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            let off = read_u16(0, (int_num as u32) * 4);
            let seg = read_u16(0, (int_num as u32) * 4 + 2);
            regs.rbx = off as u64;
            regs.es = seg as u64;
            Action::Done
        }
        // AH=0x38: Get country information — return minimal stub
        //
        // DOS 2.x uses a 32-byte buffer; DOS 3.0+ extended it to 34 bytes.
        // Many programs (including NC 2.0) allocate only 32 bytes, so write
        // field-by-field rather than blindly zeroing 34 bytes.
        0x38 => {
            let addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
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
            unsafe { regs.frame.f32.eflags &= !1; }
            Action::Done
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
            let mut path = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *((addr + i as u32) as *const u8) };
                if ch == 0 { break; }
                path[i] = ch;
                i += 1;
            }
            let result = crate::vfs::chdir(&path[..i]);
            if result < 0 {
                unsafe { regs.frame.f32.eflags |= 1; } // set CF
                regs.rax = (regs.rax & !0xFFFF) | 3; // AX=3 path not found
            } else {
                unsafe { regs.frame.f32.eflags &= !1; } // clear CF
            }
            Action::Done
        }
        // AH=0x3D: Open file (DS:DX=ASCIIZ filename, AL=access mode)
        0x3D => {
            let ds = regs.ds as u32;
            let dx = regs.rdx as u32;
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
            dbg_println!("  Open: {}", unsafe { core::str::from_utf8_unchecked(&name[..i]) });
            let fd = crate::vfs::open(&name[..i]);
            if fd >= 0 {
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                unsafe { regs.frame.f32.eflags &= !1; } // clear carry
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                unsafe { regs.frame.f32.eflags |= 1; } // set carry
            }
            Action::Done
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            let handle = regs.rbx as i32;
            crate::vfs::close(handle);
            unsafe { regs.frame.f32.eflags &= !1; }
            Action::Done
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as i32;
            let count = regs.rcx as usize;
            let buf_addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
            if handle == 0 {
                // stdin — read from virtual keyboard
                // Return 0 for now (no line-buffered stdin in VM86)
                regs.rax = regs.rax & !0xFFFF;
                unsafe { regs.frame.f32.eflags &= !1; }
            } else if handle == 1 || handle == 2 {
                regs.rax = regs.rax & !0xFFFF;
                unsafe { regs.frame.f32.eflags &= !1; }
            } else {
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, count) };
                let n = crate::vfs::read(handle, buf);
                if n >= 0 {
                    regs.rax = (regs.rax & !0xFFFF) | n as u64;
                    unsafe { regs.frame.f32.eflags &= !1; }
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    unsafe { regs.frame.f32.eflags |= 1; }
                }
            }
            Action::Done
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => {
            let ds = regs.ds as u32;
            let dx = regs.rdx as u32;
            let mut addr = (ds << 4) + dx;
            let mut pat = [0u8; 64];
            let mut pat_len = 0;
            while pat_len < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                pat[pat_len] = ch;
                addr += 1;
                pat_len += 1;
            }
            let cwd = thread::current().cwd_str();
            let cwd_s = unsafe { core::str::from_utf8_unchecked(cwd) };
            dbg_println!("  FindFirst: {} (cwd={})", unsafe { core::str::from_utf8_unchecked(&pat[..pat_len]) }, cwd_s);
            // Search from index 0
            find_matching_file(regs, &pat[..pat_len], 0)
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            // Read the stored search index from DTA reserved bytes
            let dta = thread::current().vm86_dta as *const u8;
            let pat_len = unsafe { *dta } as usize;
            let search_idx = unsafe { (dta.add(1) as *const u16).read_unaligned() } as usize;
            let mut pat = [0u8; 64];
            let copy_len = pat_len.min(64);
            unsafe {
                core::ptr::copy_nonoverlapping(dta.add(3), pat.as_mut_ptr(), copy_len);
            }
            find_matching_file(regs, &pat[..copy_len], search_idx)
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            // If we're in an EXEC'd child, return to parent
            if let Some(parent) = thread::current().vm86_exec_parent.take() {
                return exec_return(regs, &parent);
            }
            let code = regs.rax as u8;
            match thread::exit_thread(code as i32) {
                Some(idx) => Action::Switch(idx),
                None => Action::Done,
            }
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            let t = thread::current();
            let avail = 0xA000u16.saturating_sub(t.vm86_heap_seg);
            if need <= avail {
                let seg = t.vm86_heap_seg;
                t.vm86_heap_seg += need;
                regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                unsafe { regs.frame.f32.eflags &= !1; }
                dbg_println!("  alloc {} para → seg {:04X} (heap now {:04X})", need, seg, t.vm86_heap_seg);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                unsafe { regs.frame.f32.eflags |= 1; }
                dbg_println!("  alloc FAIL: need {} avail {} heap={:04X}", need, avail, t.vm86_heap_seg);
            }
            Action::Done
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            // Simple bump allocator — free is a no-op
            unsafe { regs.frame.f32.eflags &= !1; }
            Action::Done
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            let es = regs.es as u16;
            let new_end = es.wrapping_add(regs.rbx as u16);
            if new_end <= 0xA000 {
                // Program resizing its block — free memory starts after it
                thread::current().vm86_heap_seg = new_end;
                unsafe { regs.frame.f32.eflags &= !1; }
            } else {
                // Not enough memory — report max available
                let avail = 0xA000u16.saturating_sub(es);
                regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                unsafe { regs.frame.f32.eflags |= 1; }
            }
            Action::Done
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
                        unsafe { regs.frame.f32.eflags &= !1; }
                    } else {
                        // File handle: bit 7=0 (file), bit 6=0 (not EOF)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0000;
                        unsafe { regs.frame.f32.eflags &= !1; }
                    }
                }
                // AL=0x08: Check if block device is removable (BL=drive, 0=default,1=A,3=C)
                0x08 => {
                    // AX=0 = removable, AX=1 = fixed
                    regs.rax = (regs.rax & !0xFFFF) | 1; // fixed disk
                    unsafe { regs.frame.f32.eflags &= !1; } // clear CF
                }
                // AL=0x09: Check if block device is remote (BL=drive)
                0x09 => {
                    regs.rdx = (regs.rdx & !0xFFFF) | 0x0000; // bit 12=0 = local
                    unsafe { regs.frame.f32.eflags &= !1; }
                }
                _ => {
                    dbg_println!("  IOCTL AL={:02X} BX={:04X}", al, regs.rbx as u16);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    unsafe { regs.frame.f32.eflags |= 1; }
                }
            }
            Action::Done
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C)
        0x0E => {
            regs.rax = (regs.rax & !0xFF) | 3; // AL = number of logical drives
            Action::Done
        }
        // AH=0x3C: Create file
        0x3C => {
            regs.rax = (regs.rax & !0xFFFF) | 5; // error 5 = access denied
            unsafe { regs.frame.f32.eflags |= 1; }
            Action::Done
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            // Handle 1=stdout, 2=stderr
            if handle == 1 || handle == 2 {
                let addr = ((regs.ds as u32) << 4) + regs.rdx as u32;
                for i in 0..count as u32 {
                    let ch = unsafe { *((addr + i) as *const u8) };
                    vga::vga().putchar(ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 5; // access denied
                unsafe { regs.frame.f32.eflags |= 1; }
            }
            Action::Done
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as i32;
            let offset = ((regs.rcx as u32) << 16 | regs.rdx as u16 as u32) as i32;
            let whence = regs.rax as u8 as i32; // AL = origin
            let result = crate::vfs::seek(handle, offset, whence);
            if result >= 0 {
                // Return new position in DX:AX
                regs.rdx = (regs.rdx & !0xFFFF) | ((result as u32 >> 16) as u64);
                regs.rax = (regs.rax & !0xFFFF) | (result as u16 as u64);
                unsafe { regs.frame.f32.eflags &= !1; }
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                unsafe { regs.frame.f32.eflags |= 1; }
            }
            Action::Done
        }
        // AH=0x43: Get/Set File Attributes (AL=0: get, AL=1: set)
        // DS:DX = ASCIIZ filename, CX = attributes (for set)
        0x43 => {
            let al = regs.rax as u8;
            let ds = regs.ds as u32;
            let dx = regs.rdx as u32;
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
            // Check if file exists by trying to open it
            let fd = crate::vfs::open(&name[..i]);
            if fd >= 0 {
                crate::vfs::close(fd);
                if al == 0 {
                    // Get attributes: return 0x20 (archive) in CX
                    regs.rcx = (regs.rcx & !0xFFFF) | 0x20;
                }
                // Set attributes: just succeed (read-only FS)
                unsafe { regs.frame.f32.eflags &= !1; }
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                unsafe { regs.frame.f32.eflags |= 1; }
            }
            Action::Done
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
            Action::Done
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            exec_program(regs)
        }
        // AH=2Ah — Get System Date
        0x2A => {
            // Return a fixed date: 2026-03-22 (Saturday)
            regs.rcx = (regs.rcx & !0xFFFF) | 2026; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | (3 << 8) | 22; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | 6; // AL = day of week (0=Sun, 6=Sat)
            Action::Done
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
            Action::Done
        }
        _ => {
            dbg_println!("VM86: UNHANDLED INT 21h AH={:#04x} AX={:04X} from {:04x}:{:04x}",
                ah, regs.rax as u16, unsafe { regs.frame.f32.cs }, unsafe { regs.frame.f32.eip });
            // Return success (clear carry) so unhandled calls don't break callers
            unsafe { regs.frame.f32.eflags &= !1; }
            Action::Done
        }
    }
}

/// DOS INT 21h/4B — Load and Execute Program
///
/// Try to open a program file via VFS. If the name has no extension (no dot),
/// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS detection)
// ============================================================================

fn int_2fh(regs: &mut Regs) -> Action {
    let ax = regs.rax as u16;
    match ax {
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            dbg_println!("INT 2F/4300: XMS installed");
            Action::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = XMS_STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | XMS_STUB_OFF as u64;
            dbg_println!("INT 2F/4310: XMS entry = {:04X}:{:04X}", XMS_STUB_SEG, XMS_STUB_OFF);
            Action::Done
        }
        _ => {
            // Reflect to BIOS for unhandled multiplex functions
            reflect_interrupt(regs, 0x2F);
            Action::Done
        }
    }
}

// ============================================================================
// XMS dispatch (called via INT F0h from far-call stub)
// ============================================================================

/// Ensure XMS state exists for current thread, return mutable reference
fn xms_state() -> &'static mut XmsState {
    let t = thread::current();
    if t.vm86_xms.is_none() {
        t.vm86_xms = Some(alloc::boxed::Box::new(XmsState::new()));
    }
    t.vm86_xms.as_deref_mut().unwrap()
}

fn xms_dispatch(regs: &mut Regs) -> Action {
    let ah = (regs.rax >> 8) as u8;
    dbg_println!("XMS: AH={:02X}", ah);
    match ah {
        // AH=00h — Get XMS version
        0x00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0300; // XMS 3.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // driver internal revision
            regs.rdx = (regs.rdx & !0xFFFF) | 0x0001; // HMA exists
        }
        // AH=03h — Global enable A20
        0x03 => {
            let xms = xms_state();
            xms.a20_global += 1;
            crate::paging2::set_a20(true);
            thread::current().vm86_a20 = true;
            regs.rax = (regs.rax & !0xFFFF) | 1; // success
            regs.rbx = (regs.rbx & !0xFFFF); // BL=0 no error
        }
        // AH=04h — Global disable A20
        0x04 => {
            let xms = xms_state();
            xms.a20_global = xms.a20_global.saturating_sub(1);
            if xms.a20_global == 0 && xms.a20_local == 0 {
                crate::paging2::set_a20(false);
                thread::current().vm86_a20 = false;
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=05h — Local enable A20
        0x05 => {
            let xms = xms_state();
            xms.a20_local += 1;
            crate::paging2::set_a20(true);
            thread::current().vm86_a20 = true;
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=06h — Local disable A20
        0x06 => {
            let xms = xms_state();
            xms.a20_local = xms.a20_local.saturating_sub(1);
            if xms.a20_local == 0 && xms.a20_global == 0 {
                crate::paging2::set_a20(false);
                thread::current().vm86_a20 = false;
            }
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=07h — Query A20 state
        0x07 => {
            let enabled = thread::current().vm86_a20;
            regs.rax = (regs.rax & !0xFFFF) | if enabled { 1 } else { 0 };
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=08h — Query free extended memory
        0x08 => {
            let xms = xms_state();
            let largest = xms.largest_free_kb();
            let total = xms.free_kb();
            regs.rax = (regs.rax & !0xFFFF) | largest as u64; // largest free block (KB)
            regs.rdx = (regs.rdx & !0xFFFF) | total as u64;   // total free (KB)
            dbg_println!("XMS: free={}KB largest={}KB", total, largest);
        }
        // AH=09h — Allocate extended memory block (DX=size in KB)
        0x09 => {
            let size_kb = regs.rdx as u16;
            let xms = xms_state();
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
                            dbg_println!("XMS: alloc {}KB @ {:#X} → handle {}", size_kb, base, i + 1);
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
            let xms = xms_state();
            if handle >= 1 && (handle as usize - 1) < MAX_XMS_HANDLES {
                if xms.handles[handle as usize - 1].take().is_some() {
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    dbg_println!("XMS: free handle {}", handle);
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
            xms_move(regs);
        }
        // AH=0Ch — Lock extended memory block (DX=handle)
        0x0C => {
            let handle = regs.rdx as u16;
            let xms = xms_state();
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
            let xms = xms_state();
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
            let xms = xms_state();
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
            let xms = xms_state();
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
            let xms = xms_state();
            let free = xms.free_kb() as u32;
            regs.rax = (regs.rax & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (free & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFFFFFF) | (XMS_END - 1) as u64;
            regs.rbx = (regs.rbx & !0xFFFF);
        }
        // AH=10h — Request Upper Memory Block (UMB)
        // AH=11h — Release Upper Memory Block
        0x10 | 0x11 => {
            regs.rax = (regs.rax & !0xFFFF); // failure
            regs.rbx = (regs.rbx & !0xFF) | 0xB1; // no UMBs available
            regs.rdx = (regs.rdx & !0xFFFF); // largest available = 0
        }
        _ => {
            dbg_println!("XMS: UNHANDLED AH={:02X}", ah);
            regs.rax = (regs.rax & !0xFFFF); // failure
            regs.rbx = (regs.rbx & !0xFF) | 0x80; // not implemented
        }
    }
    Action::Done
}

/// XMS function 0Bh: Move extended memory block
/// DS:SI points to a move structure:
///   +00: u32 length (bytes)
///   +04: u16 source handle (0=conventional)
///   +06: u32 source offset (or seg:off if handle=0)
///   +0A: u16 dest handle (0=conventional)
///   +0C: u32 dest offset (or seg:off if handle=0)
fn xms_move(regs: &mut Regs) {
    let ds = regs.ds as u32;
    let si = regs.rsi as u32;
    let addr = (ds << 4) + si;

    let length = unsafe { (addr as *const u32).read_unaligned() } as usize;
    let src_handle = unsafe { ((addr + 4) as *const u16).read_unaligned() };
    let src_offset = unsafe { ((addr + 6) as *const u32).read_unaligned() };
    let dst_handle = unsafe { ((addr + 10) as *const u16).read_unaligned() };
    let dst_offset = unsafe { ((addr + 12) as *const u32).read_unaligned() };

    dbg_println!("XMS move: len={} src_h={} src_off={:#X} dst_h={} dst_off={:#X}",
        length, src_handle, src_offset, dst_handle, dst_offset);

    if length == 0 {
        regs.rax = (regs.rax & !0xFFFF) | 1;
        regs.rbx = (regs.rbx & !0xFFFF);
        return;
    }

    // Resolve source to linear address
    let xms = xms_state();
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
fn ems_state() -> &'static mut EmsState {
    let t = thread::current();
    if t.vm86_ems.is_none() {
        t.vm86_ems = Some(alloc::boxed::Box::new(EmsState::new()));
    }
    t.vm86_ems.as_deref_mut().unwrap()
}

fn int_67h(regs: &mut Regs) -> Action {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x4B | 0x4C => {}
        _ => dbg_println!("EMS: AH={:02X} AX={:04X}", ah, regs.rax as u16),
    }
    match ah {
        // AH=40h — Get status
        0x40 => {
            regs.rax = (regs.rax & !0xFF00); // AH=0: OK
        }
        // AH=41h — Get page frame segment
        0x41 => {
            regs.rbx = (regs.rbx & !0xFFFF) | EMS_FRAME_SEG as u64;
            regs.rax = (regs.rax & !0xFF00); // AH=0
        }
        // AH=42h — Get unallocated page count
        0x42 => {
            let ems = ems_state();
            let free = ems.alloc_pages();
            regs.rbx = (regs.rbx & !0xFFFF) | free as u64;     // BX = free pages
            regs.rdx = (regs.rdx & !0xFFFF) | EMS_TOTAL_PAGES as u64; // DX = total pages
            regs.rax = (regs.rax & !0xFF00); // AH=0
        }
        // AH=43h — Allocate handle (BX=pages needed, returns DX=handle)
        0x43 => {
            let pages_needed = regs.rbx as u16;
            let ems = ems_state();
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
                            match crate::phys_mm::alloc_phys_page() {
                                Some(page) => *p = page,
                                None => { ok = false; break; }
                            }
                        }
                        if !ok { break; }
                        // Zero the allocated pages
                        for &p in &group {
                            crate::paging2::temp_map(p);
                            unsafe {
                                core::ptr::write_bytes(
                                    crate::paging2::temp_map_vaddr() as *mut u8, 0,
                                    crate::paging2::PAGE_SIZE,
                                );
                            }
                            crate::paging2::temp_unmap();
                        }
                        pages.push(group);
                    }
                    if ok {
                        ems.handles[i] = Some(EmsHandle { pages });
                        regs.rdx = (regs.rdx & !0xFFFF) | i as u64; // handle (0-based)
                        regs.rax = (regs.rax & !0xFF00); // AH=0
                        dbg_println!("EMS: alloc {} pages → handle {}", pages_needed, i);
                    } else {
                        // Free any partially allocated pages
                        for group in &pages {
                            for &p in group {
                                if p != 0 { crate::phys_mm::free_phys_page(p); }
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
                return Action::Done;
            }

            let ems = ems_state();

            // BX=FFFFh means unmap
            if log_page == 0xFFFF {
                ems.frame[phys_page as usize] = None;
                crate::paging2::map_ems_window(phys_page as usize, None);
                regs.rax = (regs.rax & !0xFF00); // AH=0
                return Action::Done;
            }

            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8); // invalid handle
                return Action::Done;
            }

            match &ems.handles[handle as usize] {
                Some(h) if (log_page as usize) < h.pages.len() => {
                    let phys_pages = &h.pages[log_page as usize];
                    crate::paging2::map_ems_window(phys_page as usize, Some(phys_pages));
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
            let ems = ems_state();
            if (handle as usize) < MAX_EMS_HANDLES && ems.handles[handle as usize].is_some() {
                // Unmap any windows using this handle
                for w in 0..4 {
                    if let Some((h, _)) = ems.frame[w] {
                        if h == handle as u8 {
                            ems.frame[w] = None;
                            crate::paging2::map_ems_window(w, None);
                        }
                    }
                }
                // Free physical pages
                if let Some(h) = ems.handles[handle as usize].take() {
                    for group in &h.pages {
                        for &p in group {
                            crate::phys_mm::free_phys_page(p);
                        }
                    }
                }
                regs.rax = (regs.rax & !0xFF00); // AH=0
                dbg_println!("EMS: free handle {}", handle);
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
            let ems = ems_state();
            let count = ems.handles.iter().filter(|h| h.is_some()).count() as u16;
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rax = (regs.rax & !0xFF00);
        }
        // AH=4Ch — Get pages allocated to handle (DX=handle)
        0x4C => {
            let handle = regs.rdx as u16;
            let ems = ems_state();
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
            let ems = ems_state();
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
            let ds = regs.ds as u32;
            let si = regs.rsi as u32;
            let base_addr = (ds << 4) + si;

            let ems = ems_state();
            if (handle as usize) >= MAX_EMS_HANDLES || ems.handles[handle as usize].is_none() {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return Action::Done;
            }

            for i in 0..count as u32 {
                let log_page = unsafe { ((base_addr + i * 4) as *const u16).read_unaligned() };
                let phys_raw = unsafe { ((base_addr + i * 4 + 2) as *const u16).read_unaligned() };

                let phys_page = if al == 0 {
                    phys_raw as u8
                } else {
                    // Segment mode: convert segment to physical page index
                    let seg_offset = phys_raw.wrapping_sub(EMS_FRAME_SEG);
                    (seg_offset / 0x0400) as u8 // each window is 0x400 paragraphs (16KB)
                };

                if phys_page > 3 {
                    regs.rax = (regs.rax & !0xFF00) | (0x8B << 8);
                    return Action::Done;
                }

                if log_page == 0xFFFF {
                    ems.frame[phys_page as usize] = None;
                    crate::paging2::map_ems_window(phys_page as usize, None);
                } else {
                    match &ems.handles[handle as usize] {
                        Some(h) if (log_page as usize) < h.pages.len() => {
                            let phys_pages = &h.pages[log_page as usize];
                            crate::paging2::map_ems_window(phys_page as usize, Some(phys_pages));
                            ems.frame[phys_page as usize] = Some((handle as u8, log_page));
                        }
                        _ => {
                            regs.rax = (regs.rax & !0xFF00) | (0x8A << 8);
                            return Action::Done;
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
            let ems = ems_state();
            if (handle as usize) >= MAX_EMS_HANDLES {
                regs.rax = (regs.rax & !0xFF00) | (0x83 << 8);
                return Action::Done;
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
                                match crate::phys_mm::alloc_phys_page() {
                                    Some(page) => *p = page,
                                    None => { ok = false; break; }
                                }
                            }
                            if !ok {
                                // Free partially allocated group
                                for &p in &group { if p != 0 { crate::phys_mm::free_phys_page(p); } }
                                regs.rax = (regs.rax & !0xFF00) | (0x88 << 8);
                                return Action::Done;
                            }
                            h.pages.push(group);
                        }
                    } else if (new_count as usize) < old_count {
                        // Shrink: free excess pages
                        for group in h.pages.drain(new_count as usize..) {
                            for &p in &group {
                                crate::phys_mm::free_phys_page(p);
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
                    let seg = EMS_FRAME_SEG + (i as u16) * 0x0400;
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
    Action::Done
}

fn dos_open_program(name: &[u8]) -> i32 {
    let fd = crate::vfs::open(name);
    if fd >= 0 { return fd; }
    // If the name already has a dot, don't try extensions
    if name.iter().any(|&c| c == b'.') { return fd; }
    // Try .COM
    let len = name.len();
    let mut buf = [0u8; 132];
    if len + 4 <= buf.len() {
        buf[..len].copy_from_slice(name);
        buf[len..len + 4].copy_from_slice(b".COM");
        let fd = crate::vfs::open(&buf[..len + 4]);
        if fd >= 0 { return fd; }
    }
    // Try .EXE
    if len + 4 <= buf.len() {
        buf[len..len + 4].copy_from_slice(b".EXE");
        let fd = crate::vfs::open(&buf[..len + 4]);
        if fd >= 0 { return fd; }
    }
    -2 // ENOENT
}

/// Fork+exec model: create a new VM86 thread with a fresh address space,
/// load the program there (full 640KB available), block parent until child exits.
fn exec_program(regs: &mut Regs) -> Action {
    let al = regs.rax as u8;
    if al != 0 {
        regs.rax = (regs.rax & !0xFFFF) | 1;
        unsafe { regs.frame.f32.eflags |= 1; }
        return Action::Done;
    }

    // Read ASCIIZ filename from DS:DX
    let ds = regs.ds as u32;
    let dx = regs.rdx as u32;
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

    // If COMMAND.COM /C, extract the real program name
    let fname_upper: &[u8] = &filename[..flen];
    let is_shell = fname_upper.windows(11).any(|w|
        w.eq_ignore_ascii_case(b"COMMAND.COM"));
    let mut ti = 0;
    while ti < copy_len && tail[ti] == b' ' { ti += 1; }
    let (prog_name, _) = if is_shell && ti + 1 < copy_len
        && tail[ti] == b'/' && (tail[ti + 1] == b'C' || tail[ti + 1] == b'c')
    {
        let mut start = ti + 2;
        while start < copy_len && tail[start] == b' ' { start += 1; }
        let mut end = start;
        while end < copy_len && tail[end] != b' ' && tail[end] != b'\r' && tail[end] != 0 { end += 1; }
        (&tail[start..end], end - start)
    } else {
        (&filename[..flen] as &[u8], flen)
    };

    // Open and read the program file
    let fd = dos_open_program(prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        unsafe { regs.frame.f32.eflags |= 1; }
        return Action::Done;
    }
    let size = crate::vfs::seek(fd, 0, 2);
    if size <= 0 {
        crate::vfs::close(fd);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        unsafe { regs.frame.f32.eflags |= 1; }
        return Action::Done;
    }
    crate::vfs::seek(fd, 0, 0);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::vfs::read_raw(fd, &mut buf);
    crate::vfs::close(fd);
    let is_exe = is_mz_exe(&buf);

    dbg_println!("EXEC fork: prog={}",
        unsafe { core::str::from_utf8_unchecked(prog_name) });

    // --- Fork a new address space for the child ---
    use crate::paging2;

    let new_root = match paging2::fork_current() {
        Some(r) => r,
        None => {
            regs.rax = (regs.rax & !0xFFFF) | 8;
            unsafe { regs.frame.f32.eflags |= 1; }
            return Action::Done;
        }
    };

    // Save parent state
    let current = thread::current();
    thread::save_state(current, regs);

    // Create child thread
    let child = match thread::create_thread(Some(current), new_root, true) {
        Some(t) => t,
        None => {
            crate::phys_mm::free_phys_page(new_root);
            regs.rax = (regs.rax & !0xFFFF) | 8;
            unsafe { regs.frame.f32.eflags |= 1; }
            return Action::Done;
        }
    };
    crate::phys_mm::free_phys_page(new_root);
    let child_tid = child.tid;
    let child_idx = child_tid as usize;

    // Switch to child's address space: load child's page tables, then
    // set up a fresh VM86 memory layout with full 640KB available.
    child.root.activate();
    paging2::free_user_pages();
    paging2::flush_tlb();
    paging2::map_low_mem_user();
    setup_ivt();

    // Load the program at COM_SEGMENT (full conventional memory)
    let (cs, ip, ss, sp) = if is_exe {
        match load_exe(&buf) {
            Some(t) => t,
            None => {
                // Restore parent's address space and clean up
                current.root.activate();
                thread::exit_thread(1);
                regs.rax = (regs.rax & !0xFFFF) | 11;
                unsafe { regs.frame.f32.eflags |= 1; }
                return Action::Done;
            }
        }
    } else {
        load_com(&buf)
    };

    dbg_println!("EXEC: cs={:04X} ip={:04X} ss={:04X} sp={:04X}", cs, ip, ss, sp);

    // Save child's address space and switch back to parent
    child.root.save();
    current.root.activate();

    // Set up child thread as VM86
    child.mode = thread::ThreadMode::Mode16;
    thread::init_process_thread_vm86(child, cs, ip, ss, sp);
    // Inherit cwd from parent
    child.cwd = current.cwd;
    child.cwd_len = current.cwd_len;
    child.vm86_skip_irq = true;
    // setup_psp/load_exe set these on current() (parent) — copy to child
    child.vm86_dta = current.vm86_dta;
    child.vm86_heap_seg = current.vm86_heap_seg;

    // Block parent until child exits. Clear carry for when parent resumes.
    current.state = thread::ThreadState::Blocked;
    unsafe { regs.frame.f32.eflags &= !1; }

    // Switch to child
    Action::Switch(child_idx)
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
fn exec_return(regs: &mut Regs, parent: &ExecParent) -> Action {
    unsafe {
        regs.frame.f32.cs = parent.cs as u32;
        regs.frame.f32.eip = parent.ip as u32;
        regs.frame.f32.ss = parent.ss as u32;
        regs.frame.f32.esp = parent.sp as u32;
        regs.frame.f32.eflags &= !1; // clear carry
    }
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    Action::Done
}

/// Saved parent state for returning from EXEC'd child
pub struct ExecParent {
    pub ss: u16,
    pub sp: u16,
    pub cs: u16,
    pub ip: u16,
    pub ds: u16,
    pub es: u16,
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

/// Strip DOS path prefix (e.g. "C:\*.*" -> "*.*", ".\*.*" -> "*.*")
fn strip_dos_path(pat: &[u8]) -> &[u8] {
    // Find last backslash or colon
    let mut last = 0;
    let mut found = false;
    for (i, &ch) in pat.iter().enumerate() {
        if ch == b'\\' || ch == b'/' || ch == b':' {
            last = i + 1;
            found = true;
        }
    }
    if found { &pat[last..] } else { pat }
}

/// FindFirst/FindNext helper: search directory from `start_index`, fill DTA on match.
fn find_matching_file(regs: &mut Regs, pattern: &[u8], start_index: usize) -> Action {
    let pat = strip_dos_path(pattern);
    let mut idx = start_index;

    loop {
        match crate::vfs::readdir(idx) {
            Some(entry) => {
                idx += 1;
                let name = &entry.name[..entry.name_len];
                if dos_wildcard_match(pat, name) {
                    // Fill DTA at thread.vm86_dta
                    let dta = thread::current().vm86_dta;
                    // DTA layout (43 bytes):
                    //   0x00: reserved for FindNext (we store pattern_len + search_index + pattern)
                    //   0x15: attribute of matched file
                    //   0x16: file time (2 bytes)
                    //   0x18: file date (2 bytes)
                    //   0x1A: file size (4 bytes, little-endian)
                    //   0x1E: filename (13 bytes, null-terminated, 8.3 format)
                    unsafe {
                        let p = dta as *mut u8;
                        // Clear DTA
                        core::ptr::write_bytes(p, 0, 43);
                        // Store search state in reserved area:
                        // byte 0 = pattern length, bytes 1-2 = next index, bytes 3.. = pattern
                        let pat_store_len = pattern.len().min(18);
                        *p = pat_store_len as u8;
                        (p.add(1) as *mut u16).write_unaligned(idx as u16);
                        core::ptr::copy_nonoverlapping(pattern.as_ptr(), p.add(3), pat_store_len);
                        // Attribute: 0x10 = directory, 0x20 = archive (normal file)
                        *p.add(0x15) = if entry.is_dir { 0x10 } else { 0x20 };
                        // File size (little-endian u32) — unaligned write
                        (p.add(0x1A) as *mut u32).write_unaligned(entry.size);
                        // Filename (up to 12 chars + null, 8.3 format)
                        let name_len = entry.name_len.min(12);
                        core::ptr::copy_nonoverlapping(
                            entry.name.as_ptr(),
                            p.add(0x1E),
                            name_len,
                        );
                        *p.add(0x1E + name_len) = 0;
                    }
                    // Clear carry = success
                    unsafe { regs.frame.f32.eflags &= !1; }
                    dbg_println!("  FindFirst matched: {} (dta={:05X})", unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len]) }, dta);
                    return Action::Done;
                }
            }
            None => {
                // No more files
                regs.rax = (regs.rax & !0xFFFF) | 18; // no more files
                unsafe { regs.frame.f32.eflags |= 1; } // set carry
                return Action::Done;
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
/// Interrupts we emulate in the monitor (INT 10h, 20h, 21h) are trapped
/// via the TSS interrupt redirection bitmap and never reach the IVT.
/// Address of XMS entry stub (in conventional memory, after BDA)
const XMS_STUB_ADDR: u32 = 0x0500;
/// XMS stub segment:offset = 0050:0000
const XMS_STUB_SEG: u16 = 0x0050;
const XMS_STUB_OFF: u16 = 0x0000;
/// Private interrupt number used by XMS far-call stub
const XMS_INT: u8 = 0xF0;

pub fn setup_ivt() {
    // Install XMS entry stub at 0x0500: INT F0h + RETF (3 bytes)
    unsafe {
        let stub = XMS_STUB_ADDR as *mut u8;
        *stub = 0xCD;           // INT
        *stub.add(1) = XMS_INT; // F0h
        *stub.add(2) = 0xCB;   // RETF
    }

}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Map the PSP and environment for a DOS program.
///
/// - PSP (256 bytes) at COM_SEGMENT:0000 = page 0x10, offset 0.
/// - Environment block at page 0x0F (linear 0xF000, segment 0x0F00).
///
/// Both pages are allocated, filled, and mapped via paging2::map_user_page.
fn map_psp() {
    use crate::paging2;

    const PSP_PAGE: usize = 0x10;  // COM_SEGMENT << 4 >> 12
    const ENV_PAGE: usize = 0x0F;  // page before PSP
    const ENV_SEG: u16 = 0x0F00;   // ENV_PAGE << 12 >> 4

    // Environment page (linear 0xF000)
    // Format: NUL-terminated strings, double NUL at end, then u16 count + program name
    let mut env = [0u8; 4096];
    let mut off = 0;
    // COMSPEC — NC checks this to find the command interpreter
    let comspec = b"COMSPEC=C:\\COMMAND.COM\0";
    env[off..off + comspec.len()].copy_from_slice(comspec);
    off += comspec.len();
    let path = b"PATH=C:\\\0";
    env[off..off + path.len()].copy_from_slice(path);
    off += path.len();
    env[off] = 0; // double NUL: end of environment
    off += 1;
    env[off] = 0x01; // word count after env
    env[off + 1] = 0x00;
    off += 2;
    let name = b"C:\\PROG.EXE\0";
    env[off..off + name.len()].copy_from_slice(name);
    paging2::map_user_page(ENV_PAGE, &env);

    // PSP page (linear 0x10000)
    let mut psp = [0u8; 4096];
    psp[0] = 0xCD; // INT 20h
    psp[1] = 0x20;
    psp[2] = 0x00; // top of memory = 0xA000
    psp[3] = 0xA0;
    // Parent PSP segment — point to ourselves (top-level process, like COMMAND.COM)
    psp[0x16] = COM_SEGMENT as u8;
    psp[0x17] = (COM_SEGMENT >> 8) as u8;
    psp[0x2C] = ENV_SEG as u8;
    psp[0x2D] = (ENV_SEG >> 8) as u8;
    psp[0x80] = 0; // command tail length
    psp[0x81] = 0x0D; // CR
    paging2::map_user_page(PSP_PAGE, &psp);

    // Default DTA is at PSP:0080h (linear = COM_SEGMENT*16 + 0x80)
    crate::thread::current().vm86_dta = (COM_SEGMENT as u32) * 16 + 0x80;
}

/// Check if data starts with the MZ signature.
pub fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Load a .COM binary into the VM86 address space.
/// Returns (cs, ip, ss, sp) for initializing the thread.
///
/// Layout:
///   Segment COM_SEGMENT (0x1000):
///     0x0000-0x00FF: PSP (Program Segment Prefix)
///     0x0100-...:    .COM binary code
///   Stack at COM_SEGMENT:COM_SP (top of segment)
pub fn load_com(data: &[u8]) -> (u16, u16, u16, u16) {
    map_psp();
    // COM gets full 64K segment
    thread::current().vm86_heap_seg = COM_SEGMENT.wrapping_add(0x1000);

    // Copy .COM data at offset 0x100
    let base = (COM_SEGMENT as u32) << 4;
    let load_addr = base + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_addr as *mut u8,
            data.len(),
        );
    }

    (COM_SEGMENT, COM_OFFSET, COM_SEGMENT, COM_SP)
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
pub fn load_exe(data: &[u8]) -> Option<(u16, u16, u16, u16)> {
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

    // Load segment: PSP is at COM_SEGMENT, load module starts one segment after
    let psp_segment = COM_SEGMENT;
    let load_segment = psp_segment + 0x10; // 256 bytes after PSP base

    map_psp();

    // Set initial heap past the loaded program (PSP + load image + min extra/BSS)
    let load_paras = ((load_size as u32 + 15) / 16) as u16;
    let end_seg = load_segment.wrapping_add(load_paras).wrapping_add(min_extra as u16);
    thread::current().vm86_heap_seg = end_seg;

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

    Some((cs, init_ip, ss, init_sp))
}
