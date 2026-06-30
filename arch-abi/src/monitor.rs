//! Sensitive-instruction monitor — backend-agnostic x86 decoder for #GP traps.
//!
//! When ring-3 code executes an IOPL-sensitive instruction (CLI/STI, PUSHF/POPF,
//! IRET, HLT, INT n, IN/OUT) the CPU raises #GP. Both arch backends land here:
//!  - **metal** takes a real #GP and the guest's page tables are live, so its
//!    [`GuestView`] dereferences linear addresses directly;
//!  - **interp** stops the unicorn slice on #GP and its [`GuestView`] routes
//!    every access through the software MMU **of the interpreted thread**.
//!
//! The decoder, IP advance, flag/stack emulation and the virtual-IF single-step
//! driver are identical on both — they operate purely on [`Regs`] plus the
//! [`GuestView`] memory/segment capability. Only the memory backing differs,
//! which is exactly what `GuestView` abstracts.
//!
//! The view is taken by `&mut`: the monitor *writes* guest memory (PUSHF, INT
//! frame pushes) and, on interp, even a read can demand-commit a page — both
//! mutate the thread's owned address space. On metal that state is the live
//! hardware page tables (the `&mut` is a no-op token); on interp it is the
//! thread's software MMU, which must be the *interpreted* thread's, not whatever
//! space is globally active (the kernel moves `active` to peek other spaces).
//!
//! Instructions finishable at the machine level (flag toggles, stack work, VM86
//! IVT reflect) return [`MonitorResult::Resume`]; those needing kernel help
//! (port emulation, soft INT dispatch, idle) return a typed [`KernelEvent`].

use crate::{IoSize, KernelEvent, Regs, UserMode};

/// The memory + segment-resolution capability the monitor needs, **bound to the
/// interpreted thread**. Each backend implements it over its own guest memory:
/// metal dereferences the linear address directly (its page tables are live);
/// interp resolves through that thread's software MMU. All addresses are linear.
///
/// Methods take `&mut self` because guest writes — and, on interp, demand-paged
/// reads — mutate the thread's address space; the `&mut` makes that exclusive.
pub trait GuestView {
    fn read8(&mut self, lin: u32) -> u8;
    fn read16(&mut self, lin: u32) -> u16;
    fn read32(&mut self, lin: u32) -> u32;
    fn write16(&mut self, lin: u32, val: u16);
    fn write32(&mut self, lin: u32, val: u32);
    /// Linear base of a selector (VM86 callers pass `seg<<4` themselves; this is
    /// only consulted in PM, where the monitor resolves CS/SS through it).
    fn seg_base(&mut self, sel: u16) -> u32;
    /// Is the selector a 32-bit (D/B=1) segment?
    fn seg_is_32(&mut self, sel: u16) -> bool;
    /// Does the VM86 redirection bitmap trap this vector (true) or should the
    /// monitor reflect it through the real-mode IVT itself (false)?
    fn int_intercepted(&mut self, vector: u8) -> bool;
}

/// Result of one monitor decode step. `Resume` is the fast path — the caller
/// returns to ring-3. `Event(e)` carries a typed kernel event to bubble up.
#[derive(Copy, Clone, Debug)]
pub enum MonitorResult {
    Resume,
    Event(KernelEvent),
}

// =============================================================================
// EFLAGS bits the monitor cares about
// =============================================================================

const IF_FLAG:   u32 = 1 << 9;   // real IF (host-only); never guest state
const TF_FLAG:   u32 = 1 << 8;
const IOPL_MASK: u32 = 3 << 12;
const VM_FLAG:   u32 = 1 << 17;
const OF_FLAG:   u32 = 1 << 11;
/// VIF — the guest's virtual interrupt flag. EFLAGS bit 19. This is the single
/// canonical store the kernel reads/writes; bit 9 (IF) is the real interrupt
/// flag only. The guest *observes* its virtual-IF in the bit-9 position (PUSHF
/// result / a popped IRET frame), so we translate at those points only.
const VIF_FLAG:  u32 = 1 << 19;
/// Flags VM86/PM user code cannot modify via POPF/IRET: IOPL, VM, and the real
/// IF (the guest's IF intent lands in VIF instead — see `apply_guest_flags`).
const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG | IF_FLAG;

/// The flags word the *guest* observes (PUSHF / pushed IRET frame): its virtual
/// interrupt flag (VIF/bit 19) appears in the bit-9 (IF) slot; the internal VIF
/// bit is masked out.
#[inline]
fn guest_flags(regs: &Regs) -> u32 {
    let f = regs.flags32();
    let vif = f & VIF_FLAG != 0;
    (f & !(IF_FLAG | VIF_FLAG)) | if vif { IF_FLAG } else { 0 }
}

/// Apply a flags word the guest supplied (POPF / IRET): status flags take
/// effect, IOPL/VM/real-IF are preserved, and the guest's bit-9 (its desired
/// IF) lands in VIF (bit 19).
#[inline]
fn apply_guest_flags(regs: &mut Regs, popped: u32) {
    let want_vif = popped & IF_FLAG != 0;
    let preserved = regs.flags32() & PRESERVED_FLAGS;
    let mut nf = (popped & !(PRESERVED_FLAGS | VIF_FLAG)) | preserved;
    if want_vif { nf |= VIF_FLAG; } else { nf &= !VIF_FLAG; }
    regs.set_flags32(nf);
}

/// When true, after a PM client clears virtual IF (via `CLI`), arm TF=1 and walk
/// the instruction stream so POPF/IRET that would *silently* drop the IF bit at
/// CPL>IOPL get intercepted. Per DPMI 0.9 §2.13 spec-conforming clients use only
/// CLI/STI + AX=0900-0902, so this is belt-and-braces — but it MUST stay `true`:
/// real clients (Hexen via DOS32A, sporadic IF=0 hangs elsewhere) re-enable
/// interrupts via POPF/IRET, and with stepping off virtual IF sticks at 0, the
/// timer IRQ never delivers, and tick-paced delay loops deadlock.
///
/// VM86 never needs this: at IOPL<3 every IF-touching op (including POPF/IRET)
/// #GPs, so the monitor sees them all. Only PM (CPL>IOPL) has the silent-drop
/// hole this closes.
/// True when the current guest's *virtual* IOPL is 3, meaning the client is
/// treated as owning the interrupt flag and POPF/IRET must be honored by
/// single-stepping (compat for the non-conforming clients above: Hexen via
/// DOS32A, sporadic IF=0 hangs). A virtual IOPL < 3 is spec-strict per DPMI 0.9
/// §2.13 — CLI/STI stay virtualized, POPF/IRET are left ignored, no step.
///
/// vIOPL is per-thread interrupt-control state, so it lives in the saved flags
/// exactly like VIF/VIP — NOT a global. The *real* IOPL is pinned to 1 in traps
/// (so CLI/STI/IN/OUT trap); the IOPL field (bits 12-13) carries the *virtual*
/// level, stashed/restored around the iret in the isr like VIF/VIP. Default 3
/// (the old unconditional `TF_VIRTUAL_IF_STEPPING == true`); a per-program
/// policy (LOADFIX.CFG) can launch a client at vIOPL < 3.
#[inline]
pub fn virtual_if_stepping(regs: &Regs) -> bool {
    (regs.flags32() >> 12) & 3 == 3
}

// =============================================================================
// Segment views
// =============================================================================

/// Resolve (linear base, 32-bit?) for the code segment at fault time.
/// VM86 uses CS*16 and is always 16-bit; PM looks through the descriptor table.
#[inline]
fn code_view<V: GuestView>(regs: &Regs, v: &mut V) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.code_seg() as u32) << 4, false)
    } else {
        let cs = regs.code_seg();
        (v.seg_base(cs), v.seg_is_32(cs))
    }
}

/// Resolve (linear base, 32-bit?) for the stack segment at fault time.
#[inline]
fn stack_view<V: GuestView>(regs: &Regs, v: &mut V) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.stack_seg() as u32) << 4, false)
    } else {
        let ss = regs.stack_seg();
        (v.seg_base(ss), v.seg_is_32(ss))
    }
}

// =============================================================================
// Stack helpers (width = SS B bit)
// =============================================================================

#[inline]
fn get_sp(regs: &Regs, ss_32: bool) -> u32 {
    if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF }
}

#[inline]
fn set_sp(regs: &mut Regs, ss_32: bool, val: u32) {
    if ss_32 {
        regs.set_sp32(val);
    } else {
        regs.set_sp32((regs.sp32() & !0xFFFF) | (val & 0xFFFF));
    }
}

#[inline]
fn push16<V: GuestView>(regs: &mut Regs, v: &mut V, ss_base: u32, ss_32: bool, val: u16) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(2);
    set_sp(regs, ss_32, new_sp);
    v.write16(ss_base.wrapping_add(new_sp), val);
}

#[inline]
fn pop16<V: GuestView>(regs: &mut Regs, v: &mut V, ss_base: u32, ss_32: bool) -> u16 {
    let cur = get_sp(regs, ss_32);
    let val = v.read16(ss_base.wrapping_add(cur));
    set_sp(regs, ss_32, cur.wrapping_add(2));
    val
}

#[inline]
fn push32<V: GuestView>(regs: &mut Regs, v: &mut V, ss_base: u32, ss_32: bool, val: u32) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(4);
    set_sp(regs, ss_32, new_sp);
    v.write32(ss_base.wrapping_add(new_sp), val);
}

#[inline]
fn pop32<V: GuestView>(regs: &mut Regs, v: &mut V, ss_base: u32, ss_32: bool) -> u32 {
    let cur = get_sp(regs, ss_32);
    let val = v.read32(ss_base.wrapping_add(cur));
    set_sp(regs, ss_32, cur.wrapping_add(4));
    val
}

/// SW equivalent of the CPU's VM86 INT dispatch, for hosts without VME. Reads
/// CS:IP from the RM IVT at `vector*4`, pushes FLAGS/CS/IP on the current VM86
/// stack, clears IF/TF, and loads the new CS:IP. Called for INTs whose
/// redirection-bitmap bit is clear, and by the kernel's VM86 exception-dispatch
/// path (#DE/#BP/#OF reflect to the program's own real-mode handler).
#[inline]
pub fn sw_reflect_vm86_int<V: GuestView>(regs: &mut Regs, v: &mut V, vector: u8) {
    // IVT lives at linear 0; entries are 4 bytes each.
    let ivt_addr = (vector as u32) * 4;
    let new_ip = v.read16(ivt_addr);
    let new_cs = v.read16(ivt_addr + 2);

    let ss_base = (regs.stack_seg() as u32) << 4;
    // The guest observes its virtual-IF (VIF) in the bit-9 slot of the saved
    // FLAGS; INT-n clears the guest's IF → clear VIF, not the real IF.
    let flags = guest_flags(regs) as u16;
    let old_cs = regs.code_seg();
    let old_ip = regs.ip32() as u16;
    push16(regs, v, ss_base, false, flags);
    push16(regs, v, ss_base, false, old_cs);
    push16(regs, v, ss_base, false, old_ip);
    regs.clear_flag32(VIF_FLAG);
    regs.clear_flag32(TF_FLAG);
    regs.set_cs32(new_cs as u32);
    regs.set_ip32(new_ip as u32);
}

// =============================================================================
// Code helpers
// =============================================================================

/// Advance IP by `n`, respecting CS B bit (wraps to 16 bits for 16-bit code).
#[inline]
fn advance_ip(regs: &mut Regs, cs_32: bool, n: u32) {
    let new_ip = regs.ip32().wrapping_add(n);
    if cs_32 { regs.set_ip32(new_ip); } else { regs.set_ip32(new_ip & 0xFFFF); }
}

// =============================================================================
// Monitor entry
// =============================================================================

/// Decode the instruction at CS:IP and either finish it inline (`Resume`) or
/// return a typed kernel event (`Event`). At entry bit 9 of `regs.flags32()`
/// holds the guest's virtual interrupt flag.
pub fn monitor<V: GuestView>(regs: &mut Regs, v: &mut V) -> MonitorResult {
    use KernelEvent as E;
    use MonitorResult::Event;
    let (cs_base, cs_32) = code_view(regs, v);
    let (ss_base, ss_32) = stack_view(regs, v);
    let start_ip = regs.ip32();
    // Read the i'th instruction byte. Not a closure — each call reborrows `v`
    // so the stack helpers below can also take `&mut V`.
    macro_rules! peek { ($off:expr) => { v.read8(cs_base.wrapping_add(start_ip.wrapping_add($off))) }; }

    // Parse legacy prefixes we care about. Today: 0x66 (operand-size override).
    let mut advance = 0u32;
    let mut op_size_override = false;
    while peek!(advance) == 0x66 {
        op_size_override = true;
        advance += 1;
    }

    let op32 = cs_32 ^ op_size_override;
    let opcode = peek!(advance);
    advance += 1;

    match opcode {
        // ----- Flag / stack instructions (fast path) -----

        // CLI — clear the guest's virtual IF (VIF). The caller (#GP path or
        // step_virtual_if) arms TF=1 so PM POPF/IRET that would silently drop
        // IF get intercepted.
        0xFA => {
            advance_ip(regs, cs_32, advance);
            regs.clear_flag32(VIF_FLAG);
            MonitorResult::Resume
        }
        // STI — re-enable the guest's virtual IF (VIF).
        0xFB => {
            advance_ip(regs, cs_32, advance);
            regs.set_flag32(VIF_FLAG);
            MonitorResult::Resume
        }
        // PUSHF / PUSHFD — the guest sees its VIF in the bit-9 (IF) slot.
        0x9C => {
            advance_ip(regs, cs_32, advance);
            let flags = guest_flags(regs);
            if op32 { push32(regs, v, ss_base, ss_32, flags); }
            else    { push16(regs, v, ss_base, ss_32, flags as u16); }
            MonitorResult::Resume
        }
        // POPF / POPFD — IOPL/VM/real-IF preserved; the guest's bit-9 → VIF.
        0x9D => {
            advance_ip(regs, cs_32, advance);
            let flags = if op32 { pop32(regs, v, ss_base, ss_32) }
                        else    { pop16(regs, v, ss_base, ss_32) as u32 };
            apply_guest_flags(regs, flags);
            MonitorResult::Resume
        }
        // IRET / IRETD — pop IP, CS, FLAGS (same-ring only)
        0xCF => {
            // Don't pre-advance IP — we're loading it from the stack.
            if op32 {
                let new_eip = pop32(regs, v, ss_base, ss_32);
                let new_cs  = pop32(regs, v, ss_base, ss_32) as u16;
                let new_fl  = pop32(regs, v, ss_base, ss_32);
                if new_cs == 0 {
                    return Event(E::Fault);
                }
                regs.set_ip32(new_eip);
                regs.set_cs32(new_cs as u32);
                apply_guest_flags(regs, new_fl);
            } else {
                let new_ip = pop16(regs, v, ss_base, ss_32);
                let new_cs = pop16(regs, v, ss_base, ss_32);
                let new_fl = pop16(regs, v, ss_base, ss_32) as u32;
                if new_cs == 0 && regs.mode() != UserMode::VM86 {
                    return Event(E::Fault);
                }
                regs.set_ip32(new_ip as u32);
                regs.set_cs32(new_cs as u32);
                apply_guest_flags(regs, new_fl);
            }
            MonitorResult::Resume
        }

        // ----- Software interrupts (bubble as SoftInt(n)) -----

        // INT imm8. With VME the redirection bitmap decides; without VME (QEMU
        // TCG / our interp at IOPL<3) every VM86 `CD nn` #GPs here. Present a
        // uniform interface: bitmap-set vectors bubble as SoftInt; the rest are
        // IVT-reflected here so the kernel never sees a "not for us" VM86 INT.
        0xCD => {
            let vector = peek!(advance);
            advance += 1;
            advance_ip(regs, cs_32, advance);
            if regs.mode() == UserMode::VM86 && !v.int_intercepted(vector) {
                sw_reflect_vm86_int(regs, v, vector);
                MonitorResult::Resume
            } else {
                Event(E::SoftInt(vector))
            }
        }
        // INT3
        0xCC => {
            advance_ip(regs, cs_32, advance);
            Event(E::SoftInt(3))
        }
        // INTO — only fires if OF is set; otherwise it's a no-op.
        0xCE => {
            advance_ip(regs, cs_32, advance);
            if regs.flags32() & OF_FLAG != 0 {
                Event(E::SoftInt(4))
            } else {
                MonitorResult::Resume
            }
        }
        // ICEBP / INT1
        0xF1 => {
            advance_ip(regs, cs_32, advance);
            Event(E::SoftInt(1))
        }

        // ----- Halt -----

        0xF4 => {
            advance_ip(regs, cs_32, advance);
            Event(E::Hlt)
        }

        // ----- Port I/O (bubble up — PcMachine emulation lives in kernel) -----

        // IN AL, imm8
        0xE4 => {
            let port = peek!(advance) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            Event(E::In { port, size: IoSize::Byte })
        }
        // IN AX/EAX, imm8
        0xE5 => {
            let port = peek!(advance) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::In { port, size })
        }
        // OUT imm8, AL
        0xE6 => {
            let port = peek!(advance) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            Event(E::Out { port, size: IoSize::Byte })
        }
        // OUT imm8, AX/EAX
        0xE7 => {
            let port = peek!(advance) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::Out { port, size })
        }
        // IN AL, DX
        0xEC => {
            advance_ip(regs, cs_32, advance);
            Event(E::In { port: regs.rdx as u16, size: IoSize::Byte })
        }
        // IN AX/EAX, DX
        0xED => {
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::In { port: regs.rdx as u16, size })
        }
        // OUT DX, AL
        0xEE => {
            advance_ip(regs, cs_32, advance);
            Event(E::Out { port: regs.rdx as u16, size: IoSize::Byte })
        }
        // OUT DX, AX/EAX
        0xEF => {
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::Out { port: regs.rdx as u16, size })
        }

        // ----- String I/O (kernel reads DX / ES:DI / DS:SI directly from regs) -----

        // INSB
        0x6C => {
            advance_ip(regs, cs_32, advance);
            Event(E::Ins { size: IoSize::Byte })
        }
        // INSW / INSD
        0x6D => {
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::Ins { size })
        }
        // OUTSB
        0x6E => {
            advance_ip(regs, cs_32, advance);
            Event(E::Outs { size: IoSize::Byte })
        }
        // OUTSW / OUTSD
        0x6F => {
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::Outs { size })
        }

        // ----- Anything else — real #GP, leave IP pointing at the opcode -----

        _ => Event(E::Fault),
    }
}

// =============================================================================
// Virtual-IF single-step driver (PM only)
// =============================================================================
//
// PM runs CPL=3 at IOPL=1. At CPL>IOPL, POPF/IRET silently drop the IF bit
// instead of #GP-ing, so the #GP monitor alone can't track virtual IF. After a
// client clears virtual IF (via CLI), walk the instruction stream until virtual
// IF returns, emulating every sensitive opcode in software so hardware never
// silently drops IF. Non-sensitive instructions get TF=1 and run one step on
// hardware, returning via #DB to re-check.
//
// Invariants:
// - `regs.ip32()` always points to the next instruction to execute.
// - Only meaningful in PM mode with virtual IF already == 0.
// - TF management lives entirely here; `monitor()` opcode handlers never touch TF.

pub fn step_virtual_if<V: GuestView>(regs: &mut Regs, v: &mut V) -> MonitorResult {
    // Upper bound on sensitive instructions emulated before yielding back to
    // hardware. Prevents a runaway interpret loop on e.g. `POPF; POPF; ...`.
    const BUDGET: usize = 64;

    for _ in 0..BUDGET {
        // Fast path: virtual IF (VIF) came back on — stop stepping.
        if regs.flags32() & VIF_FLAG != 0 {
            regs.clear_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }

        // Peek the next opcode (skipping legacy prefixes) to decide if we MUST
        // emulate it. Only the flag-touching instructions that would silently
        // drop IF need software emulation here.
        let (cs_base, _) = code_view(regs, v);
        let mut p = regs.ip32();
        loop {
            let b = v.read8(cs_base.wrapping_add(p));
            if b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 {
                p = p.wrapping_add(1);
            } else {
                break;
            }
        }
        let op = v.read8(cs_base.wrapping_add(p));
        // 0x9C PUSHF, 0x9D POPF, 0xCF IRET, 0xFA CLI, 0xFB STI.
        let must_emulate = matches!(op, 0x9C | 0x9D | 0xCF | 0xFA | 0xFB);
        if !must_emulate {
            // Non-sensitive instruction — let hardware execute one step, then
            // #DB brings us back to re-check.
            regs.set_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }

        // Sensitive: emulate via the monitor decoder and loop to re-check.
        match monitor(regs, v) {
            MonitorResult::Resume => continue,
            ev @ MonitorResult::Event(_) => return ev,
        }
    }

    // Budget exhausted — back off to hardware stepping for a while.
    regs.set_flag32(TF_FLAG);
    MonitorResult::Resume
}
