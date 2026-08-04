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
pub(super) mod vvoodoo;
// ============================================================================
// PcMachine — per-thread machine state
// ============================================================================
pub(super) mod vdma;
pub(super) use vdma::*;
pub(super) mod vsb;
pub(super) use vsb::*;
pub(super) mod vgus;
pub(super) use vgus::*;
pub(super) mod vmpu;
pub(super) use vmpu::*;

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
    pub vga: vga::BiosVga,
    /// The 3dfx Voodoo board. Present in every machine but inert until a
    /// guest finds it over PCI and maps its aperture.
    pub voodoo: vvoodoo::VVoodoo,
    /// Present-path scratch, owned so the frame path allocates NOTHING per
    /// frame. `scanout` copies the live aperture into `present_scratch` and
    /// hands back a `Frame` borrowing it; the hosted whole-frame path renders
    /// into `present_fb`. Both are sized once on the first frame of a mode and
    /// reused thereafter. They sit beside `vga` rather than inside it because
    /// `scanout` takes `&self` and lends the scratch out with the same
    /// lifetime, which a field of `VgaState` could not satisfy.
    pub present_scratch: alloc::vec::Vec<u8>,
    pub present_fb: alloc::vec::Vec<u32>,
    /// Direct-display scanout scratch: palette, a completed WB shadow frame,
    /// and render/publish phase timing.
    pub present_scratch2: alloc::boxed::Box<crate::kernel::display::Scratch>,
    /// Publication state for the Voodoo's native-RGB frames on a framebuffer
    /// display. Separate from `present_scratch2`: that one starts from VGA
    /// planes and a DAC, which the card's output has neither of.
    pub voodoo_scanout: crate::kernel::display::NativeScanout,
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
    /// MPU-401 / General MIDI. Absent until BLASTER declares a `P<port>`.
    pub mpu: Mpu,
    /// The PC speaker. Always present — it is the one sound device a PC has
    /// no configuration for — and driven entirely by the port dispatch above:
    /// PIT channel 2's reload for pitch, port 61h bits 0-1 for the gate.
    pub spk: sound::speaker::Speaker,
    /// Per-personality mix state. The event loop owns the output timeline and
    /// asks this machine to sum its emulated devices into each requested span.
    pub mixer: Mixer,
    /// Last value written to CMOS index port 0x70 (NMI bit masked off).
    /// Reads of port 0x71 pass through to the host CMOS using this index.
    pub cmos_index: u8,

    /// Non-zero while an explicit DPMI INT 10h VBE call is executing the
    /// native option ROM. The value identifies the outer RM call so native,
    /// wide-decoded BIOS I/O is enabled only for that exact excursion.
    pub native_vbe_io_rmcs: u32,

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

    /// Built straight into its heap slot: the struct is far too large to pass
    /// through a kernel stack frame (see `DosState::pc`).
    pub fn new_boxed<A: crate::Arch>(machine: &mut A) -> alloc::boxed::Box<Self> {
        // A20 is permanently wrapped: HMA_PAGE aliases the user's private low
        // memory by copying entries[0..16], the faithful A20-off default every
        // real machine boots with. We never un-wrap it — a VM86 guest can use
        // neither a real HMA (XMS reports none) nor unreal mode, so the gate has
        // nothing to toggle. Dropping it removes the shadow region, the page
        // swap, and the local/global ref-counting that used to track it.
        machine.copy_page_entries(0, HMA_PAGE, HMA_PAGE_COUNT);
        // `Box::new(Self { .. })` is not an in-place construction guarantee:
        // rustc may assemble the complete aggregate on the kernel stack before
        // copying it to the allocation. PcMachine is large enough that a tiny
        // field-size increase then makes fork/exec cross the guard page. Write
        // each initialized field directly into uninitialized heap storage.
        let mut boxed = alloc::boxed::Box::<Self>::new_uninit();
        let p = boxed.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*p).vpit).write(VirtualPit::new(machine));
            core::ptr::addr_of_mut!((*p).vpic).write(VirtualPic::new());
            core::ptr::addr_of_mut!((*p).vrtc).write(VirtualRtc::new(machine));
            core::ptr::addr_of_mut!((*p).vkbd).write(VirtualKeyboard::new());
            core::ptr::addr_of_mut!((*p).mouse).write(MouseState::new());
            core::ptr::addr_of_mut!((*p).skip_irq).write(false);
            core::ptr::addr_of_mut!((*p).e0_pending).write(false);
            core::ptr::addr_of_mut!((*p).vga).write(vga::BiosVga::new());
            core::ptr::addr_of_mut!((*p).voodoo).write(vvoodoo::VVoodoo::new());
            core::ptr::addr_of_mut!((*p).present_scratch).write(alloc::vec::Vec::new());
            core::ptr::addr_of_mut!((*p).present_fb).write(alloc::vec::Vec::new());
            core::ptr::addr_of_mut!((*p).present_scratch2)
                .write(crate::kernel::display::Scratch::new_boxed());
            core::ptr::addr_of_mut!((*p).voodoo_scanout)
                .write(crate::kernel::display::NativeScanout::new());
            core::ptr::addr_of_mut!((*p).dma).write(Dma8237::new());
            core::ptr::addr_of_mut!((*p).sb).write(SoundBlaster::new());
            core::ptr::addr_of_mut!((*p).gus).write(Gus::new());
            core::ptr::addr_of_mut!((*p).mpu).write(Mpu::new());
            core::ptr::addr_of_mut!((*p).spk).write(sound::speaker::Speaker::new());
            core::ptr::addr_of_mut!((*p).mixer).write(Mixer::new());
            core::ptr::addr_of_mut!((*p).cmos_index).write(0);
            core::ptr::addr_of_mut!((*p).native_vbe_io_rmcs).write(0);
            core::ptr::addr_of_mut!((*p).locked_stack)
                .write(super::mode_transitions::LockedStackState::new());
            boxed.assume_init()
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
/// Whether the *emulated* MPU-401 answers at `p`. Two conditions, and the
/// interesting one is the SB: a thread holding the real card is driving real
/// silicon, so whatever sits at the declared MPU port is the owner's hardware
/// and we must not intercept it. Which card this thread has is the device
/// variant, matched here — the MPU itself only answers the address question.
fn emulated_mpu(pc: &PcMachine, p: u16) -> bool {
    matches!(pc.sb.device, SbDevice::Emulated(_)) && pc.mpu.owns(p)
}

pub fn emulate_inb<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, port: u16) -> u8 {
    if native_vbe_byte_port(pc, port) {
        return machine.inb(port);
    }
    match port {
        // VGA Input Status Register 1: bit 3 (vertical retrace) and bit 0
        // (blanking). An EMULATED card has no raster, so the value is
        // synthesized from the same phase clock that schedules whole-shadow
        // render/publication. A card the guest actually holds answers for
        // itself — it has a raster, and second-guessing it is how a poll loop
        // ends up waiting on an edge nobody produces.
        //
        // QEMU's BIOS/VGA path used to be special-cased here: its 0x3DA does
        // not sweep, so we read the real register (for the flip-flop side
        // effect), threw the value away, and returned a fabricated one. That
        // made every retrace poll a device exit AND a fabrication — measured
        // at ~23,000 cycles each, and Duke3D polling 54,000 times in one
        // profile window spent 64% of the machine in dispatch. The special
        // case is gone: QEMU is not a VGA reference, and `--firmware uefi` is
        // the supported way to run it (run.sh warns on the BIOS combination).
        0x3DA => {
            // Reading 0x3DA returns Input Status #1 AND resets the attribute-
            // controller write flip-flop — mirror that side effect either way.
            if let vga::BiosVga::Emulated(dev) = &mut pc.vga {
                dev.state.ac_state.pending_data = false;
                return input_status1(machine, &pc.present_scratch2);
            }
            unsafe { VGA_AC_STATE.pending_data = false; }
            machine.inb(0x3DA)
        }
        // VGA ports — pass through to hardware, or the emulated register file
        // when this thread does not own the physical VGA lease.
        0x3C0..=0x3D9 | 0x3DB..=0x3DF => {
            match &mut pc.vga {
                vga::BiosVga::Emulated(dev) => dev.state.port_read(port),
                vga::BiosVga::Bios(_) => machine.inb(port),
            }
        }
        // Bochs/QEMU VBE Display Interface (BVDI). SeaBIOS uses these
        // to configure QEMU's emulated VGA, even for legacy modes.
        // Pass through so SeaBIOS sees real VBE state.
        0x01CE..=0x01D0 => machine.inb(port),
        // Gameport (joystick): we don't model a Sound Blaster or dedicated
        // gameport card, so on the ISA bus the gameport is unpopulated —
        // reads return 0xFF (floating data lines, weakly pulled high by
        // the chipset). Keep the canonical 0x200-0x20F window explicit to
        // suppress diagnostics for ordinary joystick probes. Higher aliases
        // remain unknown ports unless an emulated device explicitly owns them.
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
        // Keyboard controller / speaker port used by BIOS IRQ1 acknowledge
        // sequence. Bit 5 is PIT channel 2's OUT line, which lives in the PIT
        // and not in the 8042 — composed here rather than inside either, since
        // neither device may name the other.
        0x61 => {
            let out = pc.vpit.ch2_output(machine);
            (pc.vkbd.read_port61() & !0x20) | if out { 0x20 } else { 0 }
        }
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
        0x40 => pc.vpit.read_counter(machine, 0),
        0x42 => pc.vpit.read_counter(machine, 2),
        // Channel 1 (DRAM refresh) is not modelled; nothing reads it.
        0x41 => 0,
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
        p if pc.sb.owns(p) => {
            pc.sb.sb_read(machine, p)
        }
        // Gravis UltraSound (GF1) — exists only when ULTRASND declared it.
        p if pc.gus.owns(p) => pc.gus.io_read(machine, p),
        // MPU-401 / General MIDI — exists only when BLASTER declared P<port>.
        p if emulated_mpu(pc, p) => pc.mpu.io_read(p),
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
    if native_vbe_byte_port(pc, port) {
        machine.outb(port, val);
        return;
    }
    match port {
        // VGA ports — pass through to hardware (tracking the AC flip-flop +
        // index, which hardware can't read back), or the emulated register
        // file when no card is present (it has its own per-thread flip-flop).
        0x3C0 => {
            if let vga::BiosVga::Emulated(dev) = &mut pc.vga {
                dev.state.port_write(port, val);
                return;
            }
            unsafe {
                if !VGA_AC_STATE.pending_data { // native card: track the flip-flop here
                    VGA_AC_STATE.index = val; // index write — latch full byte (incl. PAS)
                }
                VGA_AC_STATE.pending_data = !VGA_AC_STATE.pending_data;
            }
            machine.outb(port, val);
        }
        0x3C1..=0x3DF => {
            let vga::BiosVga::Emulated(dev) = &mut pc.vga else {
                machine.outb(port, val);
                return;
            };
            dev.state.port_write(port, val);
            // A Sequencer data write may flip chain-4 (mode 13h↔Mode X) or
            // select a plane — drive the A0000 paging alias.
            if port == 0x3C5 {
                vga::on_seq_write(machine, pc, regs);
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
                // Re-arm the passthrough card's HOST line, which `handle_irq`
                // masked when it queued the completion and which stays masked
                // until the guest EOIs. It is the card's OWN line — the same
                // value the relay matches on — NOT the guest's BLASTER line
                // and not a constant: a
                // restrapped card (86Box moves to IRQ 7) would otherwise have
                // its real line masked forever after the first completion, and
                // every later block would silently never arrive. The emulated
                // SB has no host line — its IRQ is purely virtual — so there is
                // nothing to rearm there (`feedback_no_half_modelled_devices`).
                let guest_irq = pc.sb.blaster.irq;
                let sb_in_service = guest_irq < 8 && pc.vpic.in_service(guest_irq);
                pc.vpic.master_eoi();
                if sb_in_service && let SbDevice::Native(pt) = &pc.sb.device {
                    machine.rearm_irq(pt.card.irq);
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
        // Keyboard controller / speaker port. Bits 0-1 are the speaker's half
        // of its level expression (gate and data); the rest is 8042 business.
        0x61 => {
            pc.vkbd.write_port61(val);
            pc.spk.set_port61(val);
        }
        // Keyboard controller command
        0x64 => {}
        0x43 => pc.vpit.write_command(machine, val),
        0x40 => pc.vpit.write_counter(machine, 0, val),
        // Channel 2 is the speaker's pitch: the card holds no clock of its
        // own, so hand it the new reload as the guest completes it.
        0x42 => {
            pc.vpit.write_counter(machine, 2, val);
            pc.spk.set_divisor(pc.vpit.ch2_reload());
        }
        0x41 => {}
        // CMOS index: latch for the next data-port read. Mask off the NMI
        // disable bit (0x80) — we never want guest writes to toggle host NMI.
        0x70 => pc.cmos_index = val & 0x7F,
        // CMOS data writes to the virtual RTC status registers (A/B/C) drive
        // the periodic-interrupt model; writes to any other index are dropped
        // so the guest can never mutate host CMOS (time-of-day, alarm, etc.).
        0x71 if VirtualRtc::owns(pc.cmos_index) => pc.vrtc.write(machine, pc.cmos_index, val),
        0x71 => {}
        // SB DSP/mixer/OPL → straight to the real QEMU sb16/adlib.
        p if pc.sb.owns(p) => {
            pc.sb.sb_write(machine, &pc.dma, p, val);
        }
        // Gravis UltraSound (GF1) — exists only when ULTRASND declared it.
        p if pc.gus.owns(p) => pc.gus.io_write(machine, &pc.dma, p, val),
        // MPU-401 / General MIDI — exists only when BLASTER declared P<port>.
        p if emulated_mpu(pc, p) => pc.mpu.io_write(p, val),
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

/// VGA Input Status #1 for the emulated card (see the `emulate_inb` 0x3DA
/// arm): bit 3 = vertical retrace, bit 0 = blanking, vsync forcing blanking.
///
/// Bit 3 is the direct scanout clock's retrace phase. Its trailing edge
/// captures VRAM/register/DAC state into one complete shadow, so updates made
/// while this bit is set enter the next rendered frame. Displays without a
/// live direct scanout clock (window sink, unfocused thread) fall back to a
/// fabricated free-running 70 Hz phase, asserted 8/32 steps ≈ 3.6 ms/frame.
///
/// Bit 0 (display-disabled / blanking) — per-read counter toggling every 8
/// reads. Models *horizontal* blanking, which on real VGA pulses at
/// ~31.5 kHz (every scanline); frame-scale blanking makes Build engine's
/// per-DAC-entry snow-avoidance wait too slow. Runs of 8 ones/zeros also
/// satisfy "6+ consecutive bit0=X" idioms (Wolf3D's VL_SetScreen
/// pre-CRTC-write wait, etc.)
fn input_status1<A: crate::Arch>(machine: &mut A, beam: &crate::kernel::display::Scratch) -> u8 {
    let ticks = machine.get_ticks();
    let vr = crate::kernel::display::beam_vretrace(beam, ticks).unwrap_or_else(|| {
        let phase = ((ticks.wrapping_mul(70 * 32)) / 1000) as u32 & 31;
        phase >= 24
    });
    use core::sync::atomic::{AtomicU32, Ordering};
    static DA_READ_COUNT: AtomicU32 = AtomicU32::new(0);
    let hbl = (DA_READ_COUNT.fetch_add(1, Ordering::Relaxed) >> 3) & 1 != 0;
    (if vr { 0x08 } else { 0 }) | (if vr || hbl { 0x01 } else { 0 })
}

/// Bus/device/function the emulated Voodoo answers at. Nothing else responds,
/// so a scan sees exactly one device and every other slot reads as absent.
const VOODOO_BDF: u32 = 0x0000_0800; // bus 0, device 1, function 0

/// The latched `CONFIG_ADDRESS` value (port 0xCF8).
static mut PCI_CONFIG_ADDRESS: u32 = 0;

fn pci_addressed_device() -> Option<u8> {
    let addr = unsafe { core::ptr::read_volatile(&raw const PCI_CONFIG_ADDRESS) };
    // Bit 31 enables the decode; bits 30:24 are reserved.
    if addr & 0x8000_0000 == 0 {
        return None;
    }
    ((addr & 0x00FF_FF00) == VOODOO_BDF).then_some((addr & 0xFC) as u8)
}

/// Serve an `IN` from 0xCF8/0xCFC. `None` means "not a config port".
fn pci_config_in(pc: &mut PcMachine, port: u16, size: u32) -> Option<u32> {
    match port {
        0xCF8 if size == 4 => {
            Some(unsafe { core::ptr::read_volatile(&raw const PCI_CONFIG_ADDRESS) })
        }
        // Reads narrower than a dword address within the data port.
        0xCFC..=0xCFF => {
            let shift = (port - 0xCFC) as u32 * 8;
            let dword = match pci_addressed_device() {
                Some(off) => pc.voodoo.config_read(off),
                // No device: the bus floats high, which is how a scan knows.
                None => 0xFFFF_FFFF,
            };
            Some(dword >> shift)
        }
        _ => None,
    }
}

/// Serve an `OUT` to 0xCF8/0xCFC. `true` means the write was consumed.
fn pci_config_out(pc: &mut PcMachine, port: u16, size: u32, val: u32) -> bool {
    match port {
        0xCF8 if size == 4 => {
            unsafe { core::ptr::write_volatile(&raw mut PCI_CONFIG_ADDRESS, val) };
            true
        }
        0xCFC..=0xCFF => {
            if let Some(off) = pci_addressed_device() {
                let shift = (port - 0xCFC) as u32 * 8;
                if size == 4 && shift == 0 {
                    pc.voodoo.config_write(off, val);
                } else {
                    // Sub-dword write: merge into the current value.
                    let width = size * 8;
                    let mask = if width >= 32 { !0 } else { ((1u32 << width) - 1) << shift };
                    let cur = pc.voodoo.config_read(off);
                    pc.voodoo.config_write(off, (cur & !mask) | ((val << shift) & mask));
                }
            }
            true
        }
        _ => false,
    }
}

/// Native option-ROM ports are width-preserving: one trapped INW/INL becomes
/// one host INW/INL at the same port. Emulated byte devices retain their own
/// lane behavior below; the generic dispatcher must not turn native wide I/O
/// into accesses to adjacent ports.
fn native_vbe_byte_port(pc: &PcMachine, port: u16) -> bool {
    pc.native_vbe_io_rmcs != 0
        && matches!(port, 0xCF8..=0xCFF | 0xF140..=0xF147)
}

fn port_range_contains(first: u16, last: u16, port: u16, size: u32) -> bool {
    port >= first && (port as u32).saturating_add(size).saturating_sub(1) <= last as u32
}

fn native_atomic_port(pc: &PcMachine, port: u16, size: u32) -> bool {
    (size == 2 && matches!(port, 0x01CE..=0x01D0))
        || (pc.native_vbe_io_rmcs != 0
            && matches!(size, 2 | 4)
            && (port_range_contains(0xCF8, 0xCFF, port, size)
                || port_range_contains(0xF140, 0xF147, port, size)))
}

fn native_in<A: crate::Arch>(machine: &mut A, port: u16, size: u32) -> u32 {
    match size {
        1 => machine.inb(port) as u32,
        2 => machine.inw(port) as u32,
        4 => machine.inl(port),
        _ => unreachable!("invalid port-I/O width"),
    }
}

fn native_out<A: crate::Arch>(machine: &mut A, port: u16, size: u32, val: u32) {
    match size {
        1 => machine.outb(port, val as u8),
        2 => machine.outw(port, val as u16),
        4 => machine.outl(port, val),
        _ => unreachable!("invalid port-I/O width"),
    }
}

/// Complete an `IN AL/AX/EAX, port` the arch monitor bubbled up.
pub fn handle_in_event<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, port: u16, size: u32) {
    if native_atomic_port(pc, port, size) {
        let val = native_in(machine, port, size) as u64;
        let mask = if size == 2 { 0xFFFF } else { 0xFFFF_FFFF };
        regs.rax = (regs.rax & !mask) | val;
        return;
    }
    // PCI configuration space (mechanism #1), served whole rather than through
    // the per-byte path below: 0xCF8 is a latched dword and a config read must
    // answer as a unit, where four ISA byte reads would each fall to the
    // unpopulated-bus arm and report 0xFF — no card. Glide's DOS backend
    // reaches the board with raw `inpd`/`outpd` here, not through the PCI BIOS.
    // A native option ROM owns these ports whenever it is driving real
    // hardware, so the emulated card answers only when it is not.
    if !native_vbe_byte_port(pc, port)
        && let Some(val) = pci_config_in(pc, port, size)
    {
        let mask: u64 = if size >= 4 { 0xFFFF_FFFF } else { (1u64 << (size * 8)) - 1 };
        regs.rax = (regs.rax & !mask) | (val as u64 & mask);
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
    if native_atomic_port(pc, port, size) {
        native_out(machine, port, size, val as u32);
        return;
    }
    if !native_vbe_byte_port(pc, port) && pci_config_out(pc, port, size, val as u32) {
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
    if native_atomic_port(pc, port, size) {
        let bytes = native_in(machine, port, size).to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate().take(size as usize) {
            machine.write::<u8>((es_base.wrapping_add(di.wrapping_add(i as u32))) as usize, byte);
        }
    } else {
        for i in 0..size {
            let b = emulate_inb(machine, pc, port + i as u16);
            machine.write::<u8>((es_base.wrapping_add(di.wrapping_add(i))) as usize, b);
        }
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
    if native_atomic_port(pc, port, size) {
        let mut bytes = [0u8; 4];
        for (i, byte) in bytes.iter_mut().enumerate().take(size as usize) {
            *byte = machine.read::<u8>(
                (ds_base.wrapping_add(si.wrapping_add(i as u32))) as usize,
            );
        }
        native_out(machine, port, size, u32::from_le_bytes(bytes));
    } else {
        for i in 0..size {
            let b = machine.read::<u8>((ds_base.wrapping_add(si.wrapping_add(i))) as usize);
            emulate_outb(machine, pc, regs, port + i as u16, b);
        }
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
    /// `None` when this thread holds the real card: silicon mixes itself, and
    /// there is no emulated card to ask for frames.
    SoundBlaster(Option<&'a mut EmulatedSb>),
    Gus(&'a mut Gus),
    Midi(&'a mut Mpu),
    Speaker(&'a mut sound::speaker::Speaker),
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
            Self::SoundBlaster(Some(sb)) => sb.mix_into(machine, rate, dsp_base, block),
            Self::SoundBlaster(None) => {}
            Self::Gus(gus) => gus.mix_into(machine, rate, base, block),
            Self::Midi(mpu) => mpu.mix_into(machine, rate, base, block),
            Self::Speaker(spk) => {
                let g = vsb::SPEAKER_SCALE_Q16;
                spk.mix_into(rate, (g, g), block)
            }
        }
    }
}

/// Canonical shape the pump plays: signed 16-bit interleaved stereo.

/// The canonical mix clock. Fixed, and deliberately *not* borrowed from
/// whichever device happens to be loudest: a DOS game commonly plays 11 kHz
/// SB effects over 44 kHz wavetable music, and letting the DSP own the rate
/// resampled the GUS down to the effects' bandwidth — Doom's music came out
/// of an 11 kHz pipe, band-limited to 5.5 kHz with the zero-order hold's
/// staircase images stacked on top. Every source now renders into this clock
/// and resamples itself, at the rate the SINK asks for
/// (`sound::rate()`) — so nothing downstream resamples at all. An HDA codec
/// that only offers 48 kHz simply moves this clock; it does not add a second
/// conversion behind it.

/// The one mixer pump: exactly one canonical PCM stream, paced by the sink's
/// consumed counter (`sound::Pace`), into which every `PcmSource` sums its
/// frames. The stream runs continuously; inactive sources simply add silence.
/// Its frame numbering is the timeline for device events and the DSP clock.
pub struct Mixer {
    /// Global mix-frame position at which the current DSP playback began.
    /// The output clock stays continuous when sources come and go; the DSP's
    /// guest-visible cursor is local to each playback, so it uses this epoch
    /// instead of re-keying the whole mixer (which would also disrupt GUS).
    dsp_epoch: u64,
}

impl Mixer {
    pub const fn new() -> Self {
        Mixer {
            dsp_epoch: 0,
        }
    }
}

/// Advance emulated sound by one event-loop quantum (no-op for the parts a
/// real card serves): deliver device IRQs, run the mixer pump, then derive
/// Per-slice device service — the audio work whose LATENCY contract is the
/// event-loop slice, not the millisecond pump: the SB's latched 0xF2/0xF3
/// trigger IRQ, single-cycle DMA probe completions (MI2's driver expects
/// the completion back-to-back; a 1 ms floor loses it — see 35e3b27), the
/// GF1 rate timers + DMA-TC IRQ, and the MPU byte drain (stamped at the
/// production frontier — the frame the next produced block starts at, so a
/// note sounds within one millisecond of its OUT; a free-running arrival
/// clock here once stamped a program's first notes seconds ahead, the GM
/// start delay). Called on every event-loop slice, including the ticks==0
/// fast path that skips the pump entirely.
pub fn audio_service<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, pushed: u64) {
    let PcMachine { sb, gus, mpu, vpic, .. } = pc;
    // Latched probe/trigger IRQs are the emulated card's business: a real one
    // raises its own line and the relay carries it.
    let SoundBlaster { blaster, device } = sb;
    if let SbDevice::Emulated(emu) = device {
        emu.deliver_trigger_irq(vpic, blaster.irq);
        emu.deliver_probe_irq(machine, vpic, blaster.irq);
    }
    gus.tick(machine, vpic);
    mpu.tick(machine, pushed);
}

/// every guest-visible clock from the sink's drain position.
pub fn audio_tick<A: crate::Arch>(
    machine: &mut A,
    pc: &mut PcMachine,
    span: crate::kernel::sound::AudioSpan<'_>,
) {
    let PcMachine { sb, gus, mpu, spk, vpic, mixer, .. } = pc;
    // The pump mixes emulated sources only. A thread holding the real card
    // has nothing here: its DSP streams from the guest ring over the ISA bus
    // and its OPL is the card's own, so neither produces frames for us and
    // neither has a cursor for us to clock. Bind it once — every SB question
    // below is on the emulated payload, which is where they mean anything.
    let SoundBlaster { blaster, device } = sb;
    let sb_irq = blaster.irq;
    let mut sb = match device {
        SbDevice::Emulated(emu) => Some(&mut **emu),
        SbDevice::Native(_) => None,
    };
    if sb.as_deref_mut().is_some_and(|e| e.take_restart()) {
        mixer.dsp_epoch = span.pushed_frame;
    }
    let dsp_base = span.base_frame.saturating_sub(mixer.dsp_epoch);
    let mut sources = [
        PcmSource::SoundBlaster(sb.as_deref_mut()),
        PcmSource::Gus(gus),
        PcmSource::Midi(mpu),
        PcmSource::Speaker(spk),
    ];
    for source in &mut sources {
        source.mix_into(machine, span.rate, span.base_frame, dsp_base, span.frames);
    }

    if let Some(emu) = sb {
        let dsp_rate = emu.dsp_rate().max(1) as u64;
        let to_dsp = |mix: u64| {
            mix.saturating_sub(mixer.dsp_epoch) * dsp_rate / span.rate as u64
        };
        emu.dsp_clock_tick(
            machine,
            vpic,
            sb_irq,
            to_dsp(span.drained_frame),
            to_dsp(span.pushed_frame),
        );
    }
    gus.deliver_events(vpic);
}

pub fn queue_irq<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &mut Regs, event: crate::Irq) {
    use crate::Irq;
    match event {
        Irq::Key(sc) => {
            if vkbd::KBD_TRACE {
                crate::dbg_println!("[kbd] raw {:02X}{} e0p={}", sc,
                    if sc & 0x80 != 0 { " REL" } else { "" }, pc.e0_pending as u8);
            }
            let Some((e0, sc)) = normalize_scancode(pc, sc) else { return };
            if e0 {
                pc.vkbd.push(0xE0);
            }
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
            // Only the card this guest actually holds has a line to relay.
            let SbDevice::Native(pt) = &pc.sb.device else { return };
            if line != pt.card.irq {
                return;
            }
            // The physical card's completion line (read from its mixer, or
            // declared for a card that cannot report it). Relay it to the
            // guest's BLASTER IRQ, leaving the host line masked until the
            // guest completes the virtual interrupt with a PIC EOI.
            if !pc.vpic.is_requested(pc.sb.blaster.irq) {
                pc.vpic.raise(pc.sb.blaster.irq);
            }
        }
        // MSI identities are kernel-owned and never map onto the guest's ISA
        // PIC. An unclaimed one is spurious, not a guest interrupt line.
        Irq::Msi(_) => {}
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
