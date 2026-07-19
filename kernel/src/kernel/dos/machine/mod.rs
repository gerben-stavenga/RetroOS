//! PC machine virtualization — the shared "PC age" machine model that both
//! the DOS and DPMI personalities run on top of.
//!
//! This module is policy-free: it owns the per-thread virtual peripherals
//! (8259 PIC, 8253 PIT, PS/2 keyboard, VGA register set) and the primitive
//! helpers that decode/execute the
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
/// VIF — the guest's virtual interrupt flag (EFLAGS bit 19). The DOS layer's
/// single virtual-IF store; bit 9 (IF) is the real interrupt flag only. The
/// kernel reads/writes the guest's IF here; a flags word the guest *observes*
/// (a FLAGS pushed into a guest IRET frame) carries VIF in the bit-9 slot via
/// `guest_flags`.
pub const VIF_FLAG: u32 = 1 << 19;
pub const IOPL_MASK: u32 = 3 << 12;
/// IOPL=1 — the default *virtual* IOPL a process is born with at execv:
/// spec-CONFORMING (DPMI 0.9 §2.13), so CLI/STI are virtualized but POPF/IRET
/// are left ignored and no single-stepping is armed (full speed). It is NOT the
/// real run IOPL — every ring-3 exit pins the real IOPL to 1; this only rides
/// the saved flags as "the level the client is treated as having", read by the
/// PM gate (`virtual_if_stepping`). Non-conforming clients that re-enable IF via
/// POPF/IRET (DOOM/DOOM2/HEXEN, marked in LOADFIX.CFG) are launched at IOPL=3 so
/// the monitor steps those re-enables. VM86 is unaffected (the gate is PM-only).
pub const IOPL_DEFAULT: u32 = 1 << 12;
pub const VM_FLAG: u32 = 1 << 17;


/// HMA spans 16 pages (64KB) starting at page 0x100. Permanently aliased over
/// page 0 (A20 always wrapped) — see `Machine::new`.
const HMA_PAGE: usize = 0x100;
const HMA_PAGE_COUNT: usize = 16;

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

/// The flags word the guest observes: its virtual-IF (VIF/bit 19) shows in the
/// bit-9 (IF) slot, and the internal VIF bit is masked out. Bit 9 of the *live*
/// frame is the real IF — never what the guest should see.
#[inline]
pub fn guest_flags(regs: &Regs) -> u32 {
    let f = regs.flags32();
    let vif = f & VIF_FLAG != 0;
    (f & !(IF_FLAG | VIF_FLAG)) | if vif { IF_FLAG } else { 0 }
}

pub fn vm86_flags(regs: &Regs) -> u32 {
    guest_flags(regs)
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
    // `flags` is the guest's view: its IF intent is in bit 9. Map it to VIF
    // (bit 19) and set the low-16 status flags; the upper EFLAGS (VM/VIP/VIF
    // handled below) are preserved. Canonical bit 9 is PINNED TO 1 — the host
    // always runs the guest interruptible, the guest's IF is VIF — so a
    // canonical flags word is well-formed wherever it lands in a frame,
    // and bit 9 never carries guest state.
    let want_vif = flags & IF_FLAG != 0;
    // The guest's IOPL bits (12-13) are NOT real state: under VME the VM86 flags
    // image reads back IOPL=3 regardless of the pinned real IOPL=1 (KVM), while
    // TCG hands back the literal 1. Never trust them — preserve the kernel-owned
    // virtual IOPL already in the frame (restored from the VIOPL stash on entry),
    // the same reason bit 9 (IF) is forced and routed through VIF.
    let viopl = regs.frame.rflags & (IOPL_MASK as u64);
    regs.frame.rflags = (regs.frame.rflags & !0xFFFF)
        | ((flags as u64 & 0xFFFF) & !((IF_FLAG | IOPL_MASK) as u64))
        | IF_FLAG as u64
        | viopl;
    if want_vif { regs.frame.rflags |= VIF_FLAG as u64; }
    else        { regs.frame.rflags &= !(VIF_FLAG as u64); }
}

/// Inverse of `guest_flags` for full-width (PM) images: apply a guest-view
/// flags image — the guest's IF intent in the bit-9 slot — to the canonical
/// state. VIF (bit 19) is set from the image's bit-9 slot; VM stays
/// kernel-owned (never image-owned). Canonical bit 9 is PINNED TO 1 (see
/// `set_vm86_flags`) — never read, never guest-controlled.
#[inline]
pub fn apply_guest_flags(regs: &mut Regs, image: u32) {
    let want_vif = image & IF_FLAG != 0;
    let vm = regs.flags32() & VM_FLAG;
    // Preserve the kernel-owned virtual IOPL (see `set_vm86_flags`): the guest's
    // IOPL bits are a VME artifact under KVM, never trusted — like IF.
    let viopl = regs.flags32() & IOPL_MASK;
    let mut nf = (image & !(IF_FLAG | VIF_FLAG | VM_FLAG | IOPL_MASK)) | vm | IF_FLAG | viopl;
    if want_vif { nf |= VIF_FLAG; }
    regs.set_flags32(nf);
}

/// Canonical EFLAGS for entering a kernel-orchestrated VM86 excursion:
/// VM set, the guest's virtual IF on, canonical IF pinned to 1, and the
/// current virtual IOPL riding along. The single construction point for
/// from-scratch VM86 entry flags (DPMI RM calls / callbacks).
#[inline]
pub fn vm86_entry_flags(current: u32) -> u32 {
    VM_FLAG | VIF_FLAG | IF_FLAG | (current & IOPL_MASK)
}

/// Guest-view flags image with the IF slot forced ON — for kernel-built
/// frames whose eventual IRET must leave the guest interruptible (e.g. a
/// launched RM helper that waits on a keypress IRQ).
#[inline]
pub fn guest_flags_if_on(regs: &Regs) -> u32 {
    guest_flags(regs) | IF_FLAG
}

/// Guest-view flags image for an INT-style handler entry: the IF slot and TF
/// (bit 8) are cleared in the image — textbook INT-n semantics, what the CPU
/// itself would push before vectoring.
#[inline]
pub fn guest_flags_handler_entry(regs: &Regs) -> u32 {
    guest_flags(regs) & !(IF_FLAG | (1 << 8))
}

pub(super) mod vga;
pub use vga::*;
// ============================================================================
// PcMachine — per-thread machine state
// ============================================================================
pub(super) mod vdma;
pub(super) use vdma::*;
pub(super) mod opl;
pub(super) mod vsb;
pub(super) use vsb::*;
pub(super) mod vgus;
pub(super) use vgus::*;

/// Look up `KEY` in a DOS environment block, returning its value bytes.
/// Shared by every card's `configure_from_env` (BLASTER, ULTRASND).
pub(super) fn env_var<'a>(env: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < env.len() && env[i] != 0 {
        let end = env[i..].iter().position(|&b| b == 0).map(|p| i + p)?;
        let entry = &env[i..end];
        if let Some(eq) = entry.iter().position(|&b| b == b'=')
            && entry[..eq].eq_ignore_ascii_case(key) {
                return Some(&entry[eq + 1..]);
            }
        i = end + 1;
    }
    None
}

pub(super) fn parse_uint(s: &[u8], radix: u32) -> Option<u32> {
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
/// Holds the virtual 8259 PIC, 8253 PIT, PS/2 keyboard, VGA register set, and
/// small latches used by the monitor decoders (skip_irq, e0_pending).
///
/// DOS-specific state (PSP, DTA, heap/free segment, XMS/EMS, FindFirst state,
/// exec-parent chain) lives directly on `thread::DosState`, not here.
pub struct PcMachine {
    pub vpit: VirtualPit,
    pub vpic: VirtualPic,
    pub vrtc: VirtualRtc,
    pub vkbd: VirtualKeyboard,
    pub mouse: MouseState,
    pub skip_irq: bool,
    pub e0_pending: bool,
    pub vga: VgaState,
    /// Present-path scratch, owned so the frame path allocates NOTHING per
    /// frame. `scanout` copies the live aperture into `present_scratch` and
    /// hands back a `Frame` borrowing it, and `present_fb` receives the
    /// rendered pixels — both sized once on the first frame of a mode and
    /// reused thereafter. They sit beside `vga` rather than inside it because
    /// `scanout` takes `&self` and lends the scratch out with the same
    /// lifetime, which a field of `VgaState` could not satisfy.
    pub present_scratch: alloc::vec::Vec<u8>,
    pub present_fb: alloc::vec::Vec<u32>,
    /// Blit scratch: the palette in framebuffer format, and one output row.
    pub present_scratch2: crate::kernel::display::Scratch,
    /// Generic virtual 8237 DMA controller shadow — bus infrastructure
    /// shared by every DMA-using card model (SB today, GUS next), so it
    /// lives here rather than inside any one card.
    pub dma: Dma8237,
    /// Sound Blaster card state (the thread's BLASTER channel/IRQ map +
    /// DSP passthrough/emulation). Observes `dma` for its transfers.
    pub sb: SoundBlaster,
    /// Gravis UltraSound card state (ULTRASND wiring + the GF1 over the
    /// unified sampler engine). Absent until the env declares it.
    pub gus: Gus,
    /// The mixer pump: the thread's one canonical PCM stream, every emulated
    /// sound device summed into it, paced by the sink's playback position.
    pub mixer: Mixer,
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
    pub fn apply_packet<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs, dx: i16, dy: i16, buttons: u8) -> u16 {
        self.accum_dx = self.accum_dx.saturating_add(dx as i32);
        self.accum_dy = self.accum_dy.saturating_add(dy as i32);
        self.x = (self.x as i32 + dx as i32).clamp(self.min_x as i32, self.max_x as i32) as i16;
        self.y = (self.y as i32 + dy as i32).clamp(self.min_y as i32, self.max_y as i32) as i16;
        let prev = self.buttons;
        let cur = buttons;
        self.buttons = cur;
        self.render_if_visible(machine, regs);

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
    pub fn render_if_visible<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs) {
        if self.show_count > 0 { return; }
        let col = (self.x >> 3) as u32;
        let row = (self.y >> 3) as u32;
        if col >= 80 || row >= 25 { return; }
        let offset = (row * 80 + col) as u16;
        if Some(offset) == self.drawn_at { return; }
        self.erase_cursor(machine);
        let attr = (VGA_TEXT_BASE + offset as u32 * 2 + 1) as usize;
        self.saved_attr = machine.read::<u8>(attr);
        machine.write::<u8>(attr, self.saved_attr ^ 0x77);
        self.drawn_at = Some(offset);
    }

    /// Restore the original attribute under the current cursor cell.
    pub fn erase_cursor<A: crate::Arch>(&mut self, machine: &mut A) {
        if let Some(old) = self.drawn_at.take() {
            machine.write::<u8>((VGA_TEXT_BASE + old as u32 * 2 + 1) as usize, self.saved_attr);
        }
    }

    /// AX=01h — show cursor: decrement counter; if it just reached 0, draw.
    pub fn show<A: crate::Arch>(&mut self, machine: &mut A, regs: &mut Regs) {
        self.show_count -= 1;
        self.render_if_visible(machine, regs);
    }

    /// AX=02h — hide cursor: increment counter; if it was 0, erase.
    pub fn hide<A: crate::Arch>(&mut self, machine: &mut A, _regs: &mut Regs) {
        if self.show_count <= 0 { self.erase_cursor(machine); }
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

    pub fn new<A: crate::Arch>(machine: &mut A) -> Self {
        // A20 is permanently wrapped: HMA_PAGE aliases the user's private low
        // memory by copying entries[0..16], the faithful A20-off default every
        // real machine boots with. We never un-wrap it — a VM86 guest can use
        // neither a real HMA (XMS reports none) nor unreal mode, so the gate has
        // nothing to toggle. Dropping it removes the shadow region, the page
        // swap, and the local/global ref-counting that used to track it.
        machine.copy_page_entries(0, HMA_PAGE, HMA_PAGE_COUNT);
        Self {
            vpit: VirtualPit::new(machine),
            vpic: VirtualPic::new(),
            vrtc: VirtualRtc::new(machine),
            vkbd: VirtualKeyboard::new(),
            mouse: MouseState::new(),
            skip_irq: false,
            e0_pending: false,
            vga: VgaState::new(),
            present_scratch: alloc::vec::Vec::new(),
            present_fb: alloc::vec::Vec::new(),
            present_scratch2: crate::kernel::display::Scratch::new(),
            dma: Dma8237::new(),
            sb: SoundBlaster::new(),
            gus: Gus::new(),
            mixer: Mixer::new(),
            cmos_index: 0,
            locked_stack: super::mode_transitions::LockedStackState::new(),
        }
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

/// Log accesses to unmodeled ISA ports (`[port] … (unhandled)`) for
/// missing-device coverage. Off by default — DN and games hammer unmodeled
/// ports (CRTC mirrors, etc.), which floods the kernel log / `LOG` ring; flip
/// to true when hunting a genuinely missing device.
const PORT_TRACE: bool = false;

/// Emulate IN from a port using the virtual peripherals.
pub fn emulate_inb<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, port: u16) -> u8 {
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
            // No card: the per-thread emulated flip-flop, fabricated status.
            if !vga::vga_present() {
                pc.vga.ac_state.pending_data = false;
                return fabricated_status1(machine);
            }
            let real = machine.inb(0x3DA);
            unsafe { VGA_AC_STATE.pending_data = false; }
            // QEMU's 0x3DA bit 3 (vsync) doesn't sweep a raster in our setup, so
            // a passthrough hangs Wolf3D's VL_WaitVBL — under QEMU we fabricate.
            // Bochs and real hardware drive 0x3DA from a real raster, so use the
            // genuine bits there (flip-flop already handled above).
            if crate::kernel::platform::get().host != crate::kernel::platform::Host::Qemu {
                return real;
            }
            fabricated_status1(machine)
        }
        // VGA ports — pass through to hardware, or the emulated register file
        // when no card is present (see vga::vga_present).
        0x3C0..=0x3D9 | 0x3DB..=0x3DF => {
            if vga::vga_present() {
                machine.inb(port)
            } else {
                pc.vga.port_read(port)
            }
        }
        // Bochs/QEMU VBE Display Interface (BVDI). SeaBIOS uses these
        // to configure QEMU's emulated VGA, even for legacy modes.
        // Pass through so SeaBIOS sees real VBE state.
        0x01CE..=0x01D0 => machine.inb(port),
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
        // The serial pacing in `try_surface` (≥1 ms between bytes) keeps an
        // INT 9 drain loop to a single scancode per interrupt: during a
        // µs-scale handler the next byte "hasn't arrived on the wire yet".
        // The in-service sentinel backstops that when the host deschedules
        // us mid-handler (see queue_tick). Poll-driven guests (IRQ1 masked,
        // never in service) advance through the FIFO here at the paced rate;
        // a surfaced byte still raises its IRQ1 edge (harmlessly latched in
        // the masked IRR, exactly like hardware).
        0x64 => {
            if !pc.vpic.in_service(1) && pc.vkbd.try_surface(machine.get_ticks()) {
                pc.vpic.raise(1);
            }
            if pc.vkbd.has_data() { 1 } else { 0 }
        }
        0x40 => pc.vpit.read_counter0(machine),
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
            machine.outb(0x70, pc.cmos_index);
            machine.inb(0x71)
        }
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            pc.sb.sb_read(machine, &pc.dma, p)
        }
        // Gravis UltraSound (GF1) — exists only when ULTRASND declared it.
        p if pc.gus.owns(p) => pc.gus.io_read(machine, p),
        // Virtual 8237 DMA controller. SB channel count register is
        // served from the interpolated current-count model (drivers
        // poll it for DMA progress, not just completion).
        p if Dma8237::owns(p) =>
            pc.sb.dma_read(machine, &mut pc.dma, p),
        // Unknown ports read as an unpopulated ISA bus and are logged for missing-device coverage.
        _ => {
            if PORT_TRACE {
                crate::dbg_println!("[port] in  {:04X} -> 0xFF (unhandled)", port);
            }
            0xFF
        }
    }
}

/// Emulate OUT to a port.
pub fn emulate_outb<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, port: u16, val: u8) {
    // ISA 10-bit I/O decode — fold the alias mod 0x400. See `emulate_inb`.
    let port = port & 0x3FF;
    match port {
        // VGA ports — pass through to hardware (tracking the AC flip-flop +
        // index, which hardware can't read back), or the emulated register
        // file when no card is present (it has its own per-thread flip-flop).
        0x3C0 => {
            if !vga::vga_present() {
                pc.vga.port_write(port, val);
                return;
            }
            unsafe {
                if !VGA_AC_STATE.pending_data {
                    VGA_AC_STATE.index = val; // index write — latch full byte (incl. PAS)
                }
                VGA_AC_STATE.pending_data = !VGA_AC_STATE.pending_data;
            }
            machine.outb(port, val);
        }
        0x3C1..=0x3DF => {
            if vga::vga_present() {
                machine.outb(port, val);
            } else {
                pc.vga.port_write(port, val);
                // A Sequencer data write may flip chain-4 (mode 13h↔Mode X) or
                // select a plane — drive the A0000 paging alias.
                if port == 0x3C5 {
                    vga::on_seq_write(machine, pc, regs);
                }
            }
        }
        // Bochs/QEMU VBE Display Interface (BVDI) — see emulate_inb.
        0x01CE..=0x01D0 => machine.outb(port, val),
        // Master PIC command
        0x20 => {
            if val == 0x20 {
                // Non-specific EOI. No keyboard coupling here: a scancode
                // arriving mid-handler already latched its own IRR edge when
                // it surfaced (vkbd::try_surface), and the PIC delivers it
                // once the EOI clears the in-service bit — plain 8259
                // behavior, no device knowledge required.
                //
                // Re-arm only the passthrough host IRQ5 (the real QEMU sb16
                // line, masked until the guest EOIs). The emulated SB has no
                // host line — its IRQ is purely virtual — so there is nothing
                // to rearm there (`feedback_no_half_modelled_devices`).
                let sb_in_service = pc.sb.irq < 8 && pc.vpic.in_service(pc.sb.irq);
                pc.vpic.master_eoi();
                if sb_in_service && !pc.sb.is_emulated() {
                    machine.rearm_irq(5);
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
        // The keyboard's response (ACK, BAT, ID, …) queues like any device
        // byte and surfaces on the serial pacing clock with its own IRQ1
        // edge — real keyboards answer on the same ~1 ms wire.
        0x60 => pc.vkbd.write_port60(val),
        // Keyboard controller / speaker port
        0x61 => pc.vkbd.write_port61(val),
        // Keyboard controller command
        0x64 => {}
        0x43 => pc.vpit.write_command(machine, val),
        0x40 => pc.vpit.write_counter0(machine, val),
        0x41 | 0x42 => {}
        // CMOS index: latch for the next data-port read. Mask off the NMI
        // disable bit (0x80) — we never want guest writes to toggle host NMI.
        0x70 => pc.cmos_index = val & 0x7F,
        // CMOS data writes to the virtual RTC status registers (A/B/C) drive
        // the periodic-interrupt model; writes to any other index are dropped
        // so the guest can never mutate host CMOS (time-of-day, alarm, etc.).
        0x71 if VirtualRtc::owns(pc.cmos_index) => pc.vrtc.write(machine, pc.cmos_index, val),
        0x71 => {}
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.is_passthrough(p) => {
            pc.sb.sb_write(machine, &pc.dma, p, val);
        }
        // Gravis UltraSound (GF1) — exists only when ULTRASND declared it.
        p if pc.gus.owns(p) => pc.gus.io_write(machine, &pc.dma, p, val),
        // Virtual 8237 DMA controller (generic). After capturing the
        // write, re-check whether the BLASTER channel just armed and, if
        // so, remap the guest buffer contiguous + program the real 8237.
        p if Dma8237::owns(p) => {
            pc.dma.io_write(machine, p, val);
            pc.sb.maybe_remap(machine, regs, &mut pc.dma);
        }
        // Unknown port writes are dropped and logged for missing-device coverage.
        _ => {
            if PORT_TRACE {
                crate::dbg_println!("[port] out {:04X} <- {:02X} (unhandled)", port, val);
            }
        }
    }
}

// ============================================================================
// Monitor event handlers — kernel-side completion of I/O bubbled from arch
// ============================================================================

/// Resolve the linear base of segment `sel`. VM86 uses `sel*16`; PM walks
/// GDT/LDT via the arch descriptor helpers.
fn seg_base_for<A: crate::Arch>(regs: &Regs, sel: u16) -> u32 {
    if regs.mode() == crate::UserMode::VM86 {
        (sel as u32) << 4
    } else {
        A::seg_base(sel)
    }
}

/// Fabricated VGA Input Status #1 (see the `emulate_inb` 0x3DA arm for why):
/// bit 3 = vertical retrace on a 70 Hz frame phase, bit 0 = blanking from a
/// per-read counter, vsync forcing blanking.
fn fabricated_status1<A: crate::Arch>(machine: &mut A) -> u8 {
    let ticks = machine.get_ticks();
    let phase = ((ticks.wrapping_mul(70 * 32)) / 1000) as u32 & 31;
    let vr = phase >= 24;
    use core::sync::atomic::{AtomicU32, Ordering};
    static DA_READ_COUNT: AtomicU32 = AtomicU32::new(0);
    let hbl = (DA_READ_COUNT.fetch_add(1, Ordering::Relaxed) >> 3) & 1 != 0;
    (if vr { 0x08 } else { 0 }) | (if vr || hbl { 0x01 } else { 0 })
}

/// Complete an `IN AL/AX/EAX, port` the arch monitor bubbled up. Reads `size`
/// bytes through `emulate_inb` and writes the result into `regs.rax`.
pub fn handle_in_event<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, port: u16, size: u32) {
    if size == 2 && matches!(port, 0x01CE..=0x01D0) {
        let val = machine.inw(port) as u64;
        regs.rax = (regs.rax & !0xFFFF) | val;
        return;
    }

    let mut val: u64 = 0;
    for i in 0..size {
        val |= (emulate_inb(machine, pc, port + i as u16) as u64) << (i * 8);
    }
    let mask: u64 = if size >= 4 { 0xFFFF_FFFF } else { (1u64 << (size * 8)) - 1 };
    regs.rax = (regs.rax & !mask) | (val & mask);
}

/// Complete an `OUT port, AL/AX/EAX` the arch monitor bubbled up.
pub fn handle_out_event<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, port: u16, size: u32) {
    let val = regs.rax;
    if size == 2 && matches!(port, 0x01CE..=0x01D0) {
        machine.outw(port, val as u16);
        return;
    }

    for i in 0..size {
        emulate_outb(machine, pc, regs, port + i as u16, (val >> (i * 8)) as u8);
    }
}

/// Complete one `INSB/INSW/INSD` element (ES:DI ← port, advance DI). On `rep`
/// the monitor re-faults per iteration (leaving IP on the instruction), so this
/// does a single element and decrements the count — `dec_rep_count` — each time.
pub fn handle_ins_event<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, size: u32, rep: bool, addr32: bool) {
    let port = regs.rdx as u16;
    let es_base = seg_base_for::<A>(regs, regs.es as u16);
    let di = regs.rdi as u32;
    for i in 0..size {
        let b = emulate_inb(machine, pc, port + i as u16);
        machine.write::<u8>((es_base.wrapping_add(di.wrapping_add(i))) as usize, b);
    }
    let df = regs.flags32() & (1 << 10) != 0;
    let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };
    regs.rdi = regs.rdi.wrapping_add(delta);
    if rep { dec_rep_count(regs, addr32); }
}

/// Complete one `OUTSB/OUTSW/OUTSD` element (port ← DS:SI, advance SI). Same
/// per-iteration `rep` contract as `handle_ins_event`.
pub fn handle_outs_event<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, size: u32, rep: bool, addr32: bool) {
    let port = regs.rdx as u16;
    let ds_base = seg_base_for::<A>(regs, regs.ds as u16);
    let si = regs.rsi as u32;
    for i in 0..size {
        let b = machine.read::<u8>((ds_base.wrapping_add(si.wrapping_add(i))) as usize);
        emulate_outb(machine, pc, regs, port + i as u16, b);
    }
    let df = regs.flags32() & (1 << 10) != 0;
    let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };
    regs.rsi = regs.rsi.wrapping_add(delta);
    if rep { dec_rep_count(regs, addr32); }
}

/// Decrement the `rep` counter after one string-I/O element. The monitor only
/// emits an event when the count was non-zero, so this never underflows: it
/// steps (E)CX toward the 0 that makes the monitor skip the instruction and
/// resume. `addr32` picks ECX vs the 16-bit CX (upper bits preserved).
fn dec_rep_count(regs: &mut Regs, addr32: bool) {
    if addr32 {
        regs.rcx = regs.rcx.wrapping_sub(1);
    } else {
        let cx = (regs.rcx as u16).wrapping_sub(1);
        regs.rcx = (regs.rcx & !0xFFFF) | cx as u64;
    }
}

// ============================================================================
// IRQ delivery — buffer hardware events, drain into the virtual PIC
// ============================================================================

/// Buffer a hardware event into the virtual PIC / keyboard.
/// Mode-independent: both VM86 and DPMI share the same virtual devices.
/// Advance the host-timer-driven PIT/RTC and raise IRQ0/IRQ8 if a period
/// elapsed. The tick has no host payload — it queries `machine`'s timer — so it
/// is separate from `queue_irq` (which runs inside the input-queue drain, where
/// `machine` is borrowed). Edge-triggered: the IRR coalesces repeated ticks into
/// one pending line, so a slow guest loses ticks rather than flooding.
pub fn queue_tick<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine) {
    if pc.vpit.take_pending_irqs(machine) > 0 {
        pc.vpic.raise(0);
    }
    if pc.vrtc.take_pending_irqs(machine) > 0 {
        pc.vpic.raise(8);
    }
    // The 8042's serial clock: surface at most one queued scancode per
    // millisecond, each with its own IRQ1 edge (see vkbd::try_surface). The
    // in-service check is dosemu2's KBD_PIC_HACK sentinel (kbd.c: "timing is
    // not a reliable measure under heavy loads"): if the host deschedules us
    // mid-INT 9 for longer than the pacing period, the next byte must still
    // wait — a byte surfacing mid-handler is exactly the lost-release bug.
    if !pc.vpic.in_service(1) && pc.vkbd.try_surface(machine.get_ticks()) {
        pc.vpic.raise(1);
    }
}

/// A PCM producer the mixer pump sums per block, saturating — the one shape
/// every emulated sound device presents: the SB DSP fills from the guest
/// ring, OPL from nuked-opl3, the GUS from the wavetable sampler; further
/// sampler-backed devices (GM, AWE) join by implementing this. `mix` is a
/// pure frame generator: sub-block events (voice IRQs, block boundaries)
/// are stamped with their session frame (`base + i`) and delivered by the
/// device's *tick* when the sink's drain clock crosses them — never raised
/// from inside `mix`, which runs up to a pipe-fill ahead of the speaker.
enum PcmSource<'a> {
    SoundBlaster(&'a mut SoundBlaster),
    Gus(&'a mut Gus),
}

impl PcmSource<'_> {
    fn mix_into<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        rate: u32,
        base: u64,
        dsp_base: u64,
        block: &mut [(i32, i32)],
    ) {
        match self {
            Self::SoundBlaster(sb) => sb.mix_into(machine, rate, dsp_base, block),
            Self::Gus(gus) => gus.mix_into(machine, rate, base, block),
        }
    }
}

/// Canonical shape the pump plays: signed 16-bit interleaved stereo.
const MIX_CANON: crate::kernel::sound::Format = crate::kernel::sound::Format {
    bits: 16,
    signed: true,
    channels: 2,
};

/// Frames per pump chunk (bounded stack buffers; a due burst loops).
const MIX_CHUNK: usize = 128;

/// The mix's one and only clip point.
fn sat16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// The canonical mix clock. Fixed, and deliberately *not* borrowed from
/// whichever device happens to be loudest: a DOS game commonly plays 11 kHz
/// SB effects over 44 kHz wavetable music, and letting the DSP own the rate
/// resampled the GUS down to the effects' bandwidth — Doom's music came out
/// of an 11 kHz pipe, band-limited to 5.5 kHz with the zero-order hold's
/// staircase images stacked on top. Every source now renders into this clock
/// and resamples itself; the sinks take 44.1 kHz natively, so nothing
/// downstream resamples at all.
const MIX_RATE: u32 = 44100;

/// The one mixer pump: exactly one canonical PCM stream, paced by the sink's
/// playback position (`sound::Pace`), into which every audible `PcmSource`
/// sums its frames. Owns the stream lifecycle (open while anything is
/// audible, paused when everything goes quiet) and the session identity that
/// event stamps and the DSP's guest clock are numbered in.
pub struct Mixer {
    pace: crate::kernel::sound::Pace,
    /// Global mix-frame position at which the current DSP playback began.
    /// The output clock stays continuous when sources come and go; the DSP's
    /// guest-visible cursor is local to each playback, so it uses this epoch
    /// instead of re-keying the whole mixer (which would also disrupt GUS).
    dsp_epoch: u64,
    streaming: bool,
    last_ms: u64,
}

impl Mixer {
    pub const fn new() -> Self {
        Mixer {
            pace: crate::kernel::sound::Pace::new(),
            dsp_epoch: 0,
            streaming: false,
            last_ms: 0,
        }
    }
}

/// Advance emulated sound by one event-loop quantum (no-op for the parts a
/// real card serves): deliver device IRQs, run the mixer pump, then derive
/// every guest-visible clock from the sink's drain position.
pub fn audio_tick<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs) {
    let _ = regs;
    let PcMachine { sb, gus, vpic, mixer, .. } = pc;
    let now = machine.get_ticks();
    let dt = now.saturating_sub(mixer.last_ms).min(100);

    // Device ticks that run regardless of playback: the SB's latched
    // 0xF2/0xF3 trigger IRQ, the GF1 rate timers + DMA-TC IRQ.
    sb.deliver_trigger_irq(vpic);
    sb.deliver_probe_irq(machine, vpic);
    gus.tick(machine, vpic);

    // The pump runs on the millisecond, not on the slice. A DOS program that
    // drives an emulated device hard (the GUS driver writes GF1 registers by
    // the tens of thousands per second) re-enters the event loop far faster
    // than audio needs: the sink's position is an uncached MMIO read — a KVM
    // exit under QEMU — and reading it per slice cost ~25% of a core while
    // the pipe (tens of ms deep) had nothing to do 97% of the time. One read
    // per millisecond is two orders of magnitude inside the pipe's depth.
    if dt == 0 {
        return;
    }
    mixer.last_ms = now;

    // ── the pump ──
    let dsp_on = sb.dsp_owns_sink();
    let gus_on = gus.mixing();
    let opl_on = sb.opl_audible(now);
    if !dsp_on && !gus_on && !opl_on {
        if mixer.streaming {
            crate::kernel::sound::stop(machine, false); // pause, keep configured
            mixer.streaming = false;
        }
        mixer.pace.reset();
        mixer.dsp_epoch = 0;
        gus.on_mix_session();
        return;
    }
    // Source activity does not define the output session. In particular, an
    // SB effect starting over GUS music must not reset the GUS event/drain
    // timeline while older frames are still queued in the physical sink.
    // Give only the DSP its new local frame zero on each playback restart.
    if sb.take_restart() {
        mixer.dsp_epoch = mixer.pace.pushed();
    }
    let rate = MIX_RATE;
    let mut n = mixer.pace.due(machine, rate, dt, MIX_CHUNK);
    let mut base = mixer.pace.pushed() - n;
    // Sources sum into a WIDE accumulator and the mix is clipped exactly once,
    // here, on the way out. Saturating each i16 add per source (what we used to
    // do) clips every source against every other one: a full-scale digital SFX
    // played over FM music pinned the sum at the rail and flat-topped the music
    // with it. Each source carries its own card-accurate scale (see vsb.rs's
    // FM_SCALE_Q16 / DAC_SCALE_Q16 / GUS_SCALE_Q16), which is where the
    // headroom lives, so the clamp below is a backstop, not the normal path.
    let mut frames = [(0i32, 0i32); MIX_CHUNK];
    let mut bytes = [0u8; MIX_CHUNK * 4];
    while n > 0 {
        let run = MIX_CHUNK;
        frames[..run].fill((0, 0));
        let dsp_base = base.saturating_sub(mixer.dsp_epoch);
        let mut sources = [PcmSource::SoundBlaster(sb), PcmSource::Gus(gus)];
        for source in &mut sources {
            source.mix_into(machine, rate, base, dsp_base, &mut frames[..run]);
        }
        for (i, (l, r)) in frames[..run].iter().enumerate() {
            let l = sat16((l * vsb::OUTPUT_GAIN_Q16) >> 16);
            let r = sat16((r * vsb::OUTPUT_GAIN_Q16) >> 16);
            bytes[i * 4..i * 4 + 2].copy_from_slice(&l.to_le_bytes());
            bytes[i * 4 + 2..i * 4 + 4].copy_from_slice(&r.to_le_bytes());
        }
        crate::kernel::sound::play(machine, rate, MIX_CANON, &bytes[..run * 4]);
        base += run as u64;
        n -= run as u64;
    }
    mixer.streaming = true;

    // ── guest clocks & event delivery, on the drain clock ──
    // GUS events are stamped in mix frames; the DSP's cursor, DMA counts and
    // block IRQs are all counted in *its* frames, so the drain point converts
    // into the DSP's rate on the way in.
    let drained = mixer.pace.drained();
    let pushed = mixer.pace.pushed();
    let dsp_rate = sb.dsp_rate().max(1) as u64;
    let to_dsp = |mix: u64| mix.saturating_sub(mixer.dsp_epoch) * dsp_rate / rate as u64;
    sb.dsp_clock_tick(machine, vpic, to_dsp(drained), to_dsp(pushed));
    gus.deliver_events(drained, vpic);

}

pub fn queue_irq<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, event: crate::Irq) {
    use crate::Irq;
    match event {
        Irq::Key(sc) => {
            if vkbd::KBD_TRACE {
                crate::dbg_println!("[kbd] raw {:02X}{} e0p={}", sc,
                    if sc & 0x80 != 0 { " REL" } else { "" }, pc.e0_pending as u8);
            }
            let Some(sc) = normalize_scancode(pc, sc) else { return };
            // Queue only — the byte travels "over the serial link" and
            // surfaces (with its own IRQ1 edge) through the pacing clock in
            // `queue_tick` / the 0x64 poll path. No PIC-state peeking here:
            // the edge-per-surfaced-byte model lets IRR/ISR do the ordering,
            // as on real hardware.
            pc.vkbd.push(sc);
        }
        // Ticks carry no host payload and need the machine timer, so they come
        // through `queue_tick` (which has `&mut machine`), never here — the
        // input-queue drain only ever delivers Key/Mouse events.
        Irq::Tick => {}
        Irq::Mouse { dx, dy, buttons } => {
            // No physical mouse hardware is modelled (no PS/2 ports, no
            // IRQ 12 line) and every DOS program reaches the mouse through
            // INT 33 + AX=000Ch callback. So we don't route through the
            // vpic at all — `apply_packet` updates `pending_cond` and
            // `raise_pending` dispatches the AX=0Ch callback directly when
            // the mask matches and the user's IF=1.
            let _ = pc.mouse.apply_packet(machine, regs, dx, dy, buttons);
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
pub fn pick_pending_vec(pc: &mut PcMachine, regs: &mut Regs) -> Option<u8> {
    const VIP: u64 = 1 << 20;
    let vif = regs.frame.rflags & (VIF_FLAG as u64) != 0; // guest virtual interrupt flag
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
        // Keyboard: only commit if a scancode is still latched — a polling
        // guest may have consumed it through 0x60 before delivery (real
        // edge-mode PICs deliver a stale INT 9 there; we drop the request
        // instead so we don't keep re-selecting it).
        if !pc.vkbd.has_data() {
            if vkbd::KBD_TRACE {
                crate::dbg_println!("[kbd] spurious IRQ1 cleared");
            }
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
pub fn read_u16<A: crate::Arch>(machine: &mut A, seg: u32, off: u32) -> u16 {
    machine.read::<u16>(((seg << 4) + off) as usize)
}

/// Write a u16 to a real-mode seg:off address, through `arch::mem()`.
pub fn write_u16<A: crate::Arch>(machine: &mut A, seg: u32, off: u32, val: u16) {
    machine.write::<u16>(((seg << 4) + off) as usize, val);
}

/// Push a u16 onto the VM86 stack (SS:SP)
pub fn vm86_push<A: crate::Arch>(machine: &mut A, regs: &mut Regs, val: u16) {
    let sp = vm86_sp(regs).wrapping_sub(2);
    set_vm86_sp(regs, sp);
    let ss = regs.ss32();
    write_u16(machine, ss, sp as u32, val);
}

/// Pop a u16 from the VM86 stack (SS:SP)
pub fn vm86_pop<A: crate::Arch>(machine: &mut A, regs: &mut Regs) -> u16 {
    let sp = vm86_sp(regs);
    let val = read_u16(machine, regs.ss32(), sp as u32);
    set_vm86_sp(regs, sp.wrapping_add(2));
    val
}


// GP-fault monitor lives in `arch/monitor.rs` now. Kernel only sees the
// resulting `KernelEvent`s via `do_arch_execute()`; the completion helpers
// for In/Out/Ins/Outs live at the top of this file (handle_in_event, etc.).
