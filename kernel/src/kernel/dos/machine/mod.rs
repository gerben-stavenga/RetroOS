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

use arch_abi::GuestBytes;
use crate::Regs;
use crate::arch::Vcpu;

pub const IF_FLAG: u32 = 1 << 9;
pub const IOPL_MASK: u32 = 3 << 12;
/// IOPL=1 — kernel-set value for VM86 threads. With IOPL<3 and VME,
/// CLI/STI/PUSHF/POPF/INT/IRET virtualize through VIF instead of touching
/// real IF, which is exactly what the cooperative IRQ-injection model
/// needs. IOPL=0 would also virtualize but trap on a few extras; IOPL=3
/// would let the guest manipulate real IF and bypass the gate.
pub const IOPL_VM86: u32 = 1 << 12;
pub const VM_FLAG: u32 = 1 << 17;


/// HMA spans 16 pages (64KB) starting at page 0x100.
const HMA_PAGE: usize = 0x100;
const HMA_PAGE_COUNT: usize = 16;
/// Shadow region for A20 gate: swap HMA entries here when A20 is off.
const HMA_SHADOW_PAGE: usize = HMA_PAGE + HMA_PAGE_COUNT;

// ============================================================================
// VM86 register helpers — 16-bit views of the 32-bit user frame
// ============================================================================

#[inline]
pub fn vm86_cs(regs: &Vcpu) -> u16 {
    regs.code_seg()
}

#[inline]
pub fn vm86_ip(regs: &Vcpu) -> u16 {
    regs.ip32() as u16
}

#[inline]
pub fn vm86_ss(regs: &Vcpu) -> u16 {
    regs.stack_seg()
}

#[inline]
pub fn vm86_sp(regs: &Vcpu) -> u16 {
    regs.sp32() as u16
}

#[inline]
pub fn vm86_flags(regs: &Vcpu) -> u32 {
    regs.flags32()
}

#[inline]
pub fn set_vm86_cs(regs: &mut Vcpu, cs: u16) {
    regs.set_cs32(cs as u32);
}

#[inline]
pub fn set_vm86_ip(regs: &mut Vcpu, ip: u16) {
    regs.set_ip32(ip as u32);
}

#[inline]
pub fn set_vm86_sp(regs: &mut Vcpu, sp: u16) {
    let full = (regs.sp32() & 0xFFFF_0000) | sp as u32;
    regs.set_sp32(full);
}

#[inline]
pub fn set_vm86_flags(regs: &mut Vcpu, flags: u32) {
    // Merge low 16 bits (user-visible flags), preserve upper EFLAGS (VM, IOPL, VIF, VIP).
    regs.frame.rflags = (regs.frame.rflags & !0xFFFF) | (flags as u64 & 0xFFFF);
}

pub(super) mod vga;
pub use vga::*;
// ============================================================================
// PcMachine — per-thread machine state
// ============================================================================
pub(super) mod vdma;
pub(super) use vdma::*;
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
    pub vrtc: VirtualRtc,
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
    /// AX=0Ch event handler. CX=mask, ES:(E)DX=handler far address. `mask=0`
    /// means no handler installed. `cb_off` is 32-bit: a 16-bit client's DX
    /// occupies the low half; a 32-bit PM client passes the full EDX.
    pub cb_mask: u16,
    pub cb_seg: u16,
    pub cb_off: u32,
    /// True when the AX=0Ch handler was installed by a protected-mode (DPMI)
    /// client: `ES:DX` is a selector:offset, so the callback must be delivered
    /// in PM, not via a VM86 far-call. The symmetric twin of `pmdos_int21`'s
    /// selector handling for INT 21h. See `deliver_mouse_callback`.
    pub cb_is_pm: bool,
    /// Pending event-condition bits since last delivery. `raise_pending`
    /// dispatches when `cb_mask & pending_cond != 0`, and
    /// `deliver_mouse_callback` clears the field as it sets up the AX=0Ch
    /// far-call (so the callback sees the merged conditions exactly once).
    pub pending_cond: u16,
    pub last_dx: i16,
    pub last_dy: i16,
    /// Re-entry guard: true between `deliver_mouse_callback` setting up the
    /// far-call and `mouse_callback_return` unwinding it. Suppresses fresh
    /// dispatches while the user handler is on the stack.
    pub cb_in_flight: bool,
    /// User GP regs saved across the AX=0Ch handler far-call. HostContinuation
    /// covers CS/EIP/SS/ESP/EFLAGS/segs; we clobber AX/BX/CX/DX/SI/DI to set
    /// up the call, so they have to be bracket-saved here and restored by
    /// the SLOT_MOUSE_CB_RET slot when the handler RETFs.
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
               cb_mask: 0, cb_seg: 0, cb_off: 0, cb_is_pm: false,
               pending_cond: 0, last_dx: 0, last_dy: 0,
               cb_in_flight: false,
               saved_rax: 0, saved_rbx: 0, saved_rcx: 0,
               saved_rdx: 0, saved_rsi: 0, saved_rdi: 0 }
    }
    /// Apply one PS/2 packet: accumulate raw delta, advance clipped position,
    /// redraw the cursor at the new cell if it's visible. Returns the
    /// AX=0Ch condition bits that fired this packet (also OR'd into
    /// `pending_cond` for the next `raise_pending` dispatch).
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
        // per packet, but our delivery is gated on the raise_pending tick).
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
        let attr = (VGA_TEXT_BASE + offset as u32 * 2 + 1) as usize;
        let m = crate::arch::mem();
        self.saved_attr = m.read::<u8>(attr);
        m.write::<u8>(attr, self.saved_attr ^ 0x77);
        self.drawn_at = Some(offset);
    }

    /// Restore the original attribute under the current cursor cell.
    pub fn erase_cursor(&mut self) {
        if let Some(old) = self.drawn_at.take() {
            crate::arch::mem().write::<u8>((VGA_TEXT_BASE + old as u32 * 2 + 1) as usize, self.saved_attr);
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
    /// Whether a hardware IRQ or mouse callback is pending delivery — drives the
    /// interpreter's CPU INTR line via `arch::set_irq_line`, so its per-block
    /// interrupt check keeps firing until everything has been delivered.
    pub fn intr_pending(&self) -> bool {
        self.vpic.has_deliverable() || (self.mouse.cb_mask & self.mouse.pending_cond != 0)
    }

    pub fn new() -> Self {
        // A20 starts disabled. HMA_PAGE wraps to user's private low memory
        // by copying entries[0..16]. HMA_SHADOW_PAGE is left not-present
        // (arch_user_clean cleared it; map_low_mem_user doesn't touch it),
        // which is the correct A20-on state when no extended memory is
        // allocated — set_a20(true) will swap not-present into HMA_PAGE
        // so HMA accesses fault until XMS maps real extended memory.
        crate::arch::arch_copy_page_entries(0, HMA_PAGE, HMA_PAGE_COUNT);
        Self {
            a20_enabled: false,
            vpit: VirtualPit::new(),
            vpic: VirtualPic::new(),
            vrtc: VirtualRtc::new(),
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
        crate::arch::arch_swap_page_entries(HMA_SHADOW_PAGE, HMA_PAGE, HMA_PAGE_COUNT);
        self.a20_enabled = enabled;
    }
}

pub(super) mod vpit;
pub(super) use vpit::*;
// ============================================================================
// Virtual hardware — per-thread PIC and keyboard emulation
// ============================================================================

pub(super) mod vpic;
pub(super) use vpic::*;
pub(super) mod vrtc;
pub(super) use vrtc::*;
pub(super) mod vkbd;
pub(super) use vkbd::*;
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
        // VGA Input Status Register 1. Under QEMU its 0x3DA bit 3 doesn't sweep
        // a raster in our setup (passthrough hangs Wolf3D's VL_WaitVBL), so
        // under QEMU *only* we fabricate bit 3 and bit 0; Bochs / real hardware
        // pass through (see the is_qemu gate below). The fabricated values:
        //
        //  - bit 3 (vertical retrace) — 70 Hz frame phase (mode 13h refresh,
        //    14.286 ms / frame), asserted for 8/32 phase-steps ≈ 3.6 ms/frame.
        //    Drives frame-level pacing (Wolf3D VL_WaitVBL, Build vsync).
        //
        //  - bit 0 (display-disabled / blanking) — per-read counter toggling
        //    every 8 reads. Models *horizontal* blanking, which on real VGA
        //    pulses at ~31.5 kHz (every scanline); frame-scale blanking
        //    makes Build engine's per-DAC-entry snow-avoidance wait too slow. Runs of 8
        //    ones/zeros also satisfy "6+ consecutive bit0=X" idioms
        //    (Wolf3D's VL_SetScreen pre-CRTC-write wait, etc.) Vsync ⊂
        //    blanking, so bit 0 is forced 1 whenever bit 3 is set.
        //
        // The real `inb(0x3DA)` is retained for its hardware side-effect:
        // resetting the VGA attribute-controller flip-flop.
        0x3DA => {
            // Reading 0x3DA returns Input Status #1 AND resets the attribute-
            // controller write flip-flop — mirror that side effect either way.
            let real = crate::arch::inb(0x3DA);
            unsafe { VGA_AC_STATE.pending_data = false; }
            // QEMU's 0x3DA bit 3 (vsync) doesn't sweep a raster in our setup, so
            // a passthrough hangs Wolf3D's VL_WaitVBL — under QEMU we fabricate.
            // Bochs and real hardware drive 0x3DA from a real raster, so use the
            // genuine bits there (flip-flop already handled above).
            if !crate::kernel::startup::is_qemu() {
                return real;
            }
            let ticks = crate::arch::get_ticks();
            let phase = ((ticks.wrapping_mul(70 * 32)) / 1000) as u32 & 31;
            let vr = phase >= 24;
            use core::sync::atomic::{AtomicU32, Ordering};
            static DA_READ_COUNT: AtomicU32 = AtomicU32::new(0);
            let hbl = (DA_READ_COUNT.fetch_add(1, Ordering::Relaxed) >> 3) & 1 != 0;
            (if vr { 0x08 } else { 0 }) | (if vr || hbl { 0x01 } else { 0 })
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
        0x20 => pc.vpic.master_isr(),
        // Master PIC data (read IMR)
        0x21 => pc.vpic.master_imr(),
        // Slave PIC command (read ISR)
        0xA0 => pc.vpic.slave_isr(),
        // Slave PIC data (read IMR)
        0xA1 => pc.vpic.slave_imr(),
        // Keyboard data port — returns current scancode from the virtual 8042.
        0x60 => pc.vkbd.read_port60(),
        // Keyboard controller / speaker port used by BIOS IRQ1 acknowledge sequence.
        0x61 => pc.vkbd.read_port61(),
        // Keyboard status port (bit 0 = output buffer full).
        //
        // Model the 8042's refill delay: the controller presents exactly one
        // scancode per IRQ1 and only loads the next FIFO byte once the current
        // interrupt has been serviced. So while a keyboard IRQ is in service,
        // report only the latched byte (no FIFO refill). This makes a guest's
        // INT 9 drain loop see a single scancode and exit — make and release
        // arrive as separate interrupts, as on real hardware.
        //
        // Reproducer: Prince of Persia's INT 9 handler applies the *first*
        // scancode of an interrupt to its movement key-table and discards the
        // rest. With batched delivery a coalesced make+release landed in one
        // INT 9, so it saw "left down" and threw the release away → stuck key.
        // Poll-driven guests keep IRQ1 masked (never in service), so they
        // still advance through the FIFO here.
        0x64 => {
            let ready = if pc.vpic.in_service(1) {
                pc.vkbd.has_data()
            } else {
                pc.vkbd.poll_data()
            };
            if ready { 1 } else { 0 }
        }
        0x40 => pc.vpit.read_counter0(),
        0x41 | 0x42 => 0,
        // PIT command register not readable
        0x43 => 0xFF,
        // CMOS index port: read returns the last index byte (rare).
        0x70 => pc.cmos_index,
        // CMOS data port. Status registers A/B/C are served from the virtual
        // RTC (periodic-interrupt model — see vrtc.rs); every other index
        // passes through to the host RTC so the guest sees real time-of-day.
        // Host CMOS isn't used by the kernel itself, so the passthrough is safe.
        0x71 if VirtualRtc::owns(pc.cmos_index) => pc.vrtc.read(pc.cmos_index),
        0x71 => {
            crate::arch::outb(0x70, pc.cmos_index);
            crate::arch::inb(0x71)
        }
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            let v = pc.sb.sb_read(p);
            v
        }
        // Virtual 8237 DMA controller. SB channel count register is
        // served from the interpolated current-count model (drivers
        // poll it for DMA progress, not just completion).
        p if Dma8237::owns(p) =>
            pc.sb.dma_read(p),
        // Unknown ports read as an unpopulated ISA bus and are logged for missing-device coverage.
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
                let keyboard_in_service = pc.vpic.in_service(1);
                let sb_in_service = pc.sb.irq < 8 && pc.vpic.in_service(pc.sb.irq);
                pc.vpic.master_eoi();
                if sb_in_service {
                    crate::arch::arch_rearm_irq(5);
                }
                // Real hardware re-asserts IRQ1 if more scancodes remain in the
                // controller when the handler finishes. Since reads no longer
                // prefetch, check buffered bytes too — `latch` surfaces the
                // next one at the following INT 9 delivery.
                if keyboard_in_service
                    && (pc.vkbd.has_data() || pc.vkbd.has_buffered())
                    && !pc.vpic.is_requested(1)
                {
                    pc.vpic.raise(1);
                }
            }
        }
        // Gameport one-shot trigger: no card is present on this ISA window.
        0x200..=0x20F => {}
        // Master PIC data (write IMR)
        0x21 => pc.vpic.set_master_imr(val),
        // Slave PIC command
        0xA0 => {
            if val == 0x20 {
                pc.vpic.slave_eoi();
            }
        }
        // Slave PIC data (write IMR)
        0xA1 => pc.vpic.set_slave_imr(val),
        // Keyboard data port — host-to-device command / parameter byte.
        // The keyboard's response (ACK, BAT, ID, …) becomes visible at port
        // 0x60 and asserts IRQ1, exactly as on real hardware.
        0x60 => {
            if pc.vkbd.write_port60(val) && !pc.vpic.is_requested(1) {
                pc.vpic.raise(1);
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
        // CMOS data writes to the virtual RTC status registers (A/B/C) drive
        // the periodic-interrupt model; writes to any other index are dropped
        // so the guest can never mutate host CMOS (time-of-day, alarm, etc.).
        0x71 if VirtualRtc::owns(pc.cmos_index) => pc.vrtc.write(pc.cmos_index, val),
        0x71 => {}
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            pc.sb.sb_write(p, val);
        }
        // Virtual 8237 DMA controller (generic). After capturing the
        // write, re-check whether the BLASTER channel just armed and, if
        // so, remap the guest buffer contiguous + program the real 8237.
        p if Dma8237::owns(p) => {
            pc.sb.dma.io_write(p, val);
            pc.sb.maybe_remap();
        }
        // Unknown port writes are dropped and logged for missing-device coverage.
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
fn seg_base_for(regs: &Vcpu, sel: u16) -> u32 {
    if regs.mode() == crate::UserMode::VM86 {
        (sel as u32) << 4
    } else {
        crate::arch::monitor::seg_base(sel)
    }
}

/// Complete an `IN AL/AX/EAX, port` the arch monitor bubbled up. Reads `size`
/// bytes through `emulate_inb` and writes the result into `regs.rax`.
pub fn handle_in_event(pc: &mut PcMachine, regs: &mut Vcpu, port: u16, size: u32) {
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
pub fn handle_out_event(pc: &mut PcMachine, regs: &mut Vcpu, port: u16, size: u32) {
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
pub fn handle_ins_event(pc: &mut PcMachine, regs: &mut Vcpu, size: u32) {
    let port = regs.rdx as u16;
    let es_base = seg_base_for(regs, regs.es as u16);
    let di = regs.rdi as u32;
    for i in 0..size {
        let b = emulate_inb(pc, port + i as u16);
        regs.write::<u8>(((es_base.wrapping_add(di.wrapping_add(i)))) as usize, b);
    }
    let df = regs.flags32() & (1 << 10) != 0;
    let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };
    regs.rdi = regs.rdi.wrapping_add(delta);
}

/// Complete an `OUTSB/OUTSW/OUTSD` (port ← DS:SI, advance SI). Single element.
pub fn handle_outs_event(pc: &mut PcMachine, regs: &mut Vcpu, size: u32) {
    let port = regs.rdx as u16;
    let ds_base = seg_base_for(regs, regs.ds as u16);
    let si = regs.rsi as u32;
    for i in 0..size {
        let b = regs.read::<u8>(((ds_base.wrapping_add(si.wrapping_add(i)))) as usize);
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
            if vkbd::KBD_TRACE {
                crate::dbg_println!("[kbd] raw {:02X}{} e0p={}", sc,
                    if sc & 0x80 != 0 { " REL" } else { "" }, pc.e0_pending as u8);
            }
            let Some(sc) = normalize_scancode(pc, sc) else { return };
            pc.vkbd.push(sc);
            // Assert IRQ1 only when one isn't already in service or pending —
            // the scancode otherwise waits in the 8042 buffer and the EOI
            // re-assert surfaces it (one scancode per INT 9; see vkbd).
            if !pc.vpic.in_service(1) && !pc.vpic.is_requested(1) {
                pc.vpic.raise(1);
            }
        }
        Irq::Tick => {
            // Edge-triggered: the IRR coalesces repeated ticks into one pending
            // IRQ0, so a slow guest loses ticks rather than flooding — exactly
            // real-hardware behaviour. `take_pending_irqs` keeps the PIT model
            // honest about how many fired.
            if pc.vpit.take_pending_irqs() > 0 {
                pc.vpic.raise(0);
            }
            // RTC periodic interrupt (IRQ8) shares the host timer. When the
            // guest has enabled PIE (CMOS reg B), drive IRQ8 at the programmed
            // rate so the BIOS INT 70h ISR can complete INT 15h AH=86h waits.
            // Edge-triggered like the PIT: coalesce into one pending line.
            if pc.vrtc.take_pending_irqs() > 0 {
                pc.vpic.raise(8);
            }
        }
        Irq::Mouse { dx, dy, buttons } => {
            // No physical mouse hardware is modelled (no PS/2 ports, no
            // IRQ 12 line) and every DOS program reaches the mouse through
            // INT 33 + AX=000Ch callback. So we don't route through the
            // vpic at all — `apply_packet` updates `pending_cond` and
            // `raise_pending` dispatches the AX=0Ch callback directly when
            // the mask matches and the user's IF=1.
            let _ = pc.mouse.apply_packet(dx, dy, buttons);
        }
        Irq::Hw(line) => {
            if line != 5 {
                return;
            }
            // Real QEMU sb16 is wired to host IRQ5. Relay it to the guest's
            // BLASTER-declared IRQ line, but leave the host IRQ masked until
            // the guest completes the virtual interrupt with a PIC EOI.
            if !pc.vpic.is_requested(pc.sb.irq) {
                pc.vpic.raise(pc.sb.irq);
            }
        }
    }
}

/// Poll the virtual PIC for a deliverable IRQ, respecting the virtual
/// interrupt flag and full cascade priority. Returns the vector to deliver
/// (and marks it in-service), or `None` if nothing is ready. The caller is
/// responsible for pushing the interrupt frame (see
/// `dpmi::reflect_int_to_real_mode` / `dpmi::deliver_pm_irq`).
///
/// VIP is kept coherent with deliverability: latched while the guest has IF=0
/// and a deliverable IRQ exists, cleared otherwise. Because `vpic.peek()` is
/// priority-aware (a pending line must out-rank whatever is in service), a
/// higher-priority IRQ preempts an in-service lower one once the guest does
/// `sti` mid-handler — and the VME pending-interrupt `#GP` that fires there
/// always has something real to deliver, so it can't spin.
pub fn pick_pending_vec(pc: &mut PcMachine, regs: &mut Vcpu) -> Option<u8> {
    const VIP: u64 = 1 << 20;
    let vif = regs.frame.rflags & (1u64 << 9) != 0; // IF = virtual interrupt flag
    let candidate = pc.vpic.peek();

    if !vif {
        // Can't deliver now — latch/clear VIP to mirror whether anything would
        // be deliverable the moment the guest re-enables interrupts.
        if candidate.is_some() {
            regs.frame.rflags |= VIP;
        } else {
            regs.frame.rflags &= !VIP;
        }
        return None;
    }

    // IF=1: deliver the highest-priority deliverable line, else make sure VIP
    // is clear so a VME delivery-#GP doesn't re-fire with nothing to hand over.
    let Some(irq) = candidate else {
        regs.frame.rflags &= !VIP;
        return None;
    };

    if irq == 1 {
        // Keyboard: only commit if a scancode is actually latched; otherwise
        // drop the (spurious) request so we don't keep re-selecting it.
        if !pc.vkbd.latch() {
            pc.vpic.clear_request(1);
            regs.frame.rflags &= !VIP;
            return None;
        }
        if vkbd::KBD_TRACE {
            crate::dbg_println!("[kbd] deliver INT9 sc={:02X}{}",
                pc.vkbd.port60,
                if pc.vkbd.port60 & 0x80 != 0 { " REL" } else { "" });
        }
    }

    pc.vpic.ack(irq);
    regs.frame.rflags &= !VIP; // interrupt is being serviced
    let vec = if irq < 8 { 0x08 + irq } else { 0x70 + (irq - 8) };
    Some(vec)
}

/// Read a u16 from a real-mode seg:off address, through the active address
/// space's memory interface (`arch::mem()`) — works under any arch backend.
pub fn read_u16(seg: u32, off: u32) -> u16 {
    crate::arch::mem().read::<u16>(((seg << 4) + off) as usize)
}

/// Write a u16 to a real-mode seg:off address, through `arch::mem()`.
pub fn write_u16(seg: u32, off: u32, val: u16) {
    crate::arch::mem().write::<u16>(((seg << 4) + off) as usize, val);
}

/// Push a u16 onto the VM86 stack (SS:SP)
pub fn vm86_push(regs: &mut Vcpu, val: u16) {
    let sp = vm86_sp(regs).wrapping_sub(2);
    set_vm86_sp(regs, sp);
    write_u16(regs.ss32(), sp as u32, val);
}

/// Pop a u16 from the VM86 stack (SS:SP)
pub fn vm86_pop(regs: &mut Vcpu) -> u16 {
    let sp = vm86_sp(regs);
    let val = read_u16(regs.ss32(), sp as u32);
    set_vm86_sp(regs, sp.wrapping_add(2));
    val
}


// GP-fault monitor lives in `arch/monitor.rs` now. Kernel only sees the
// resulting `KernelEvent`s via `do_arch_execute()`; the completion helpers
// for In/Out/Ins/Outs live at the top of this file (handle_in_event, etc.).
