//! Sensitive-instruction monitor — backend-agnostic x86 decoder for #GP traps.
//!
//! When ring-3 code executes an IOPL-sensitive instruction (CLI/STI, PUSHF/POPF,
//! IRET, HLT, INT n, IN/OUT) the CPU raises #GP. Both arch backends drive the
//! shared decoder with the faulting [`Vcpu`](crate::Vcpu): register state plus
//! guest memory come from it directly (`vcpu` is [`GuestBytes`](crate::GuestBytes)),
//! and the three descriptor facts the decoder needs — selector base, operand
//! size, VM86 interrupt redirection — come from the backend TYPE parameter `A`
//! as the associated functions [`Arch::seg_base`](crate::Arch::seg_base) etc.
//! No `A` *value* is required, which is what lets the decoder run this deep
//! inside `execute()` where no `&mut A` handle exists — it needs only the type.
//!
//! The vcpu is `&mut` because the monitor *writes* guest memory (PUSHF, INT
//! frame pushes). On interp it resolves the *interpreted* thread's space —
//! which is the globally-active one here, because the monitor runs
//! synchronously inside `execute()` while that thread is the running one.
//!
//! Instructions finishable at the machine level (flag toggles, stack work, VM86
//! IVT reflect) return [`MonitorResult::Resume`]; those needing kernel help
//! (port emulation, soft INT dispatch, idle) return a typed [`KernelEvent`].

use crate::{Arch, GuestBytes, IoSize, KernelEvent, Regs, UserMode};

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

// The hole all of this closes: at CPL>IOPL, `POPF`/`IRET` do **not** #GP — they
// silently drop the IF bit. `CLI`/`STI` do fault, so the monitor sees those for
// free; only the sloppy re-enable is invisible. (VM86 needs none of this: there
// every IF-touching op faults.) The virtual-IF policy — tag the saved-flags
// word with TF so the exit POPF/IRET traps one instruction later — lives
// entirely in `kernel::dos::dpmi::vif`; arch just reflects the #GP/#DB.

// =============================================================================
// Segment views
// =============================================================================

/// Resolve (linear base, 32-bit?) for the code segment at fault time.
/// VM86 uses CS*16 and is always 16-bit; PM looks through the descriptor table.
#[inline]
fn code_view<A: Arch>(regs: &Regs) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.code_seg() as u32) << 4, false)
    } else {
        let cs = regs.code_seg();
        (A::seg_base(cs), A::seg_is_32(cs))
    }
}

/// Resolve (linear base, 32-bit?) for the stack segment at fault time.
#[inline]
fn stack_view<A: Arch>(regs: &Regs) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.stack_seg() as u32) << 4, false)
    } else {
        let ss = regs.stack_seg();
        (A::seg_base(ss), A::seg_is_32(ss))
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
fn push16<P: GuestBytes>(regs: &mut Regs, space: &mut P, ss_base: u32, ss_32: bool, val: u16) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(2);
    set_sp(regs, ss_32, new_sp);
    space.write::<u16>((ss_base.wrapping_add(new_sp)) as usize, val);
}

#[inline]
fn pop16<P: GuestBytes>(regs: &mut Regs, space: &mut P, ss_base: u32, ss_32: bool) -> u16 {
    let cur = get_sp(regs, ss_32);
    let val = space.read::<u16>(ss_base.wrapping_add(cur) as usize);
    set_sp(regs, ss_32, cur.wrapping_add(2));
    val
}

#[inline]
fn push32<P: GuestBytes>(regs: &mut Regs, space: &mut P, ss_base: u32, ss_32: bool, val: u32) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(4);
    set_sp(regs, ss_32, new_sp);
    space.write::<u32>((ss_base.wrapping_add(new_sp)) as usize, val);
}

#[inline]
fn pop32<P: GuestBytes>(regs: &mut Regs, space: &mut P, ss_base: u32, ss_32: bool) -> u32 {
    let cur = get_sp(regs, ss_32);
    let val = space.read::<u32>(ss_base.wrapping_add(cur) as usize);
    set_sp(regs, ss_32, cur.wrapping_add(4));
    val
}

/// SW equivalent of the CPU's VM86 INT dispatch, for hosts without VME. Reads
/// CS:IP from the RM IVT at `vector*4`, pushes FLAGS/CS/IP on the current VM86
/// stack, clears IF/TF, and loads the new CS:IP. Called for INTs whose
/// redirection-bitmap bit is clear, and by the kernel's VM86 exception-dispatch
/// path (#DE/#BP/#OF reflect to the program's own real-mode handler).
#[inline]
pub fn sw_reflect_vm86_int<P: GuestBytes>(regs: &mut Regs, space: &mut P, vector: u8) {
    // IVT lives at linear 0; entries are 4 bytes each.
    let ivt_addr = (vector as u32) * 4;
    let new_ip = space.read::<u16>((ivt_addr) as usize);
    let new_cs = space.read::<u16>((ivt_addr + 2) as usize);

    let ss_base = (regs.stack_seg() as u32) << 4;
    // The guest observes its virtual-IF (VIF) in the bit-9 slot of the saved
    // FLAGS; INT-n clears the guest's IF → clear VIF, not the real IF.
    let flags = guest_flags(regs) as u16;
    let old_cs = regs.code_seg();
    let old_ip = regs.ip32() as u16;
    push16(regs, space, ss_base, false, flags);
    push16(regs, space, ss_base, false, old_cs);
    push16(regs, space, ss_base, false, old_ip);
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

/// Finish decoding a string-I/O instruction (`INS`/`OUTS`). A non-`rep` op is a
/// single element: advance past the instruction and bubble the event so the
/// kernel does the port access. A `rep` op re-faults once per element — leave IP
/// on the instruction so it re-executes after the kernel does one element and
/// decrements the count; this also lets a pending IRQ be delivered between
/// iterations, exactly as hardware's interruptible REP does. When the count is
/// already 0 there is nothing to do: skip the instruction and resume.
fn string_io(regs: &mut Regs, cs_32: bool, advance: u32, rep: bool, addr32: bool, ev: KernelEvent) -> MonitorResult {
    if rep {
        let count = if addr32 { regs.rcx } else { regs.rcx & 0xFFFF };
        if count == 0 {
            advance_ip(regs, cs_32, advance);
            return MonitorResult::Resume;
        }
        // Leave IP on the instruction: it re-faults for the next element.
        MonitorResult::Event(ev)
    } else {
        advance_ip(regs, cs_32, advance);
        MonitorResult::Event(ev)
    }
}

// =============================================================================
// Monitor entry
// =============================================================================

/// Decode the instruction at CS:IP and either finish it inline (`Resume`) or
/// return a typed kernel event (`Event`). At entry bit 9 of `regs.flags32()`
/// holds the guest's virtual interrupt flag.
pub fn monitor<A: Arch>(arch: &mut A, regs: &mut Regs) -> MonitorResult {
    // `arch` IS the active-space accessor (`Arch: GuestBytes`) plus the segment
    // and int-redirection oracle (its associated fns); `regs` is disjoint.
    monitor_rs::<A>(arch, regs)
}

/// The decode body, in split `(regs, memory)` form — `step_virtual_if` drives
/// it with the same two borrows. `A` is used only for its static segment/int
/// resolution (`A::seg_base` etc.); memory is the `A::PageTable` handle.
fn monitor_rs<A: Arch>(arch: &mut A, regs: &mut Regs) -> MonitorResult {
    use KernelEvent as E;
    use MonitorResult::Event;
    let (cs_base, cs_32) = code_view::<A>(regs);
    let (ss_base, ss_32) = stack_view::<A>(regs);
    let start_ip = regs.ip32();
    // Read the i'th instruction byte. Not a closure — each call reborrows
    // `space` so the stack helpers below can also take `&mut` it.
    macro_rules! peek { ($off:expr) => { arch.read::<u8>(cs_base.wrapping_add(start_ip.wrapping_add($off)) as usize) }; }

    // Parse the legacy prefixes we care about: 0x66 (operand-size), 0x67
    // (address-size), and 0xF2/0xF3 (REP — only meaningful on the string I/O
    // ops below; ignored elsewhere). Segment-override prefixes aren't consumed:
    // no sensitive opcode we decode takes one.
    let mut advance = 0u32;
    let mut op_size_override = false;
    let mut addr_size_override = false;
    let mut rep = false;
    loop {
        match peek!(advance) {
            0x66 => { op_size_override = true; advance += 1; }
            0x67 => { addr_size_override = true; advance += 1; }
            0xF2 | 0xF3 => { rep = true; advance += 1; }
            _ => break,
        }
    }

    let op32 = cs_32 ^ op_size_override;
    let addr32 = cs_32 ^ addr_size_override;
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
            if op32 { push32(regs, arch, ss_base, ss_32, flags); }
            else    { push16(regs, arch, ss_base, ss_32, flags as u16); }
            MonitorResult::Resume
        }
        // POPF / POPFD — IOPL/VM/real-IF preserved; the guest's bit-9 → VIF.
        0x9D => {
            advance_ip(regs, cs_32, advance);
            let flags = if op32 { pop32(regs, arch, ss_base, ss_32) }
                        else    { pop16(regs, arch, ss_base, ss_32) as u32 };
            apply_guest_flags(regs, flags);
            MonitorResult::Resume
        }
        // IRET / IRETD — pop IP, CS, FLAGS (same-ring only)
        0xCF => {
            // Don't pre-advance IP — we're loading it from the stack.
            if op32 {
                let new_eip = pop32(regs, arch, ss_base, ss_32);
                let new_cs  = pop32(regs, arch, ss_base, ss_32) as u16;
                let new_fl  = pop32(regs, arch, ss_base, ss_32);
                if new_cs == 0 {
                    return Event(E::Fault);
                }
                regs.set_ip32(new_eip);
                regs.set_cs32(new_cs as u32);
                apply_guest_flags(regs, new_fl);
            } else {
                let new_ip = pop16(regs, arch, ss_base, ss_32);
                let new_cs = pop16(regs, arch, ss_base, ss_32);
                let new_fl = pop16(regs, arch, ss_base, ss_32) as u32;
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
            if regs.mode() == UserMode::VM86 && !A::int_intercepted(vector) {
                sw_reflect_vm86_int(regs, arch, vector);
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
        0x6C => string_io(regs, cs_32, advance, rep, addr32, E::Ins { size: IoSize::Byte, rep, addr32 }),
        // INSW / INSD
        0x6D => {
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            string_io(regs, cs_32, advance, rep, addr32, E::Ins { size, rep, addr32 })
        }
        // OUTSB
        0x6E => string_io(regs, cs_32, advance, rep, addr32, E::Outs { size: IoSize::Byte, rep, addr32 }),
        // OUTSW / OUTSD
        0x6F => {
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            string_io(regs, cs_32, advance, rep, addr32, E::Outs { size, rep, addr32 })
        }

        // ----- Anything else — real #GP, leave IP pointing at the opcode -----

        _ => Event(E::Fault),
    }
}

/// Is a hardware single step pending for this guest? `dpmi::vif` owns TF: it
/// sets it in `regs` to learn a window's exit (or a tagged POPF/IRET loads it),
/// and clears it when the window closes. The KVM engine asks this to decide
/// whether to arm KVM_GUESTDBG_SINGLESTEP for the next entry.
#[inline]
pub fn stepping(regs: &Regs) -> bool {
    regs.flags32() & TF_FLAG != 0
}
