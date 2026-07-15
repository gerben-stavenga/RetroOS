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
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

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

/// The virtual-IF policy for a PM client, encoded in the *virtual* IOPL
/// (EFLAGS bits 12-13).
///
/// The hole all of this closes: at CPL>IOPL, `POPF`/`IRET` do **not** #GP — they
/// silently drop the IF bit. `CLI`/`STI` do fault, so the monitor sees those for
/// free; only the sloppy re-enable is invisible. (VM86 needs none of this: there
/// every IF-touching op faults.)
///
/// | vIOPL | mode     | POPF/IRET re-enable | cost |
/// |-------|----------|---------------------|------|
/// | 1 | [`Iopl1`](IfMode::Iopl1)   | ignored — DPMI 0.9 §2.13 says a host may | nothing: no gate |
/// | 2 | [`Repair`](IfMode::Repair) | honored, caught by a learned exit breakpoint | a few #DB/s |
/// | 3 | [`Iopl3`](IfMode::Iopl3)   | honored, caught by single-stepping the window | ~2500x slower |
///
/// `Iopl1` is spec-strict and free, but a client that re-enables IF the sloppy
/// way HANGS in it: virtual IF sticks at 0, the timer never delivers, and
/// tick-paced delay loops deadlock (DOOM/DOOM2/HEXEN, Hexen via DOS32A).
///
/// `Iopl3` is the reference implementation — always correct, never predicts.
/// It is kept precisely as the escape hatch for a client `Repair` mispredicts.
///
/// `Repair` is `Iopl3`'s answer at `Iopl1`'s price, and is the default. It steps
/// only to LEARN each window's exit, then breakpoints it (see [`if_gate`]).
///
/// vIOPL is per-thread interrupt-control state, so it rides the saved flags
/// exactly like VIF/VIP — never a global. The *real* IOPL is pinned to 1 in
/// traps (so CLI/STI/IN/OUT keep faulting); these bits carry only the virtual
/// level, stashed and restored around the iret.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IfMode {
    Iopl1,
    Repair,
    Iopl3,
}

#[inline]
pub fn if_mode(regs: &Regs) -> IfMode {
    match (regs.flags32() >> 12) & 3 {
        2 => IfMode::Repair,
        3 => IfMode::Iopl3,
        _ => IfMode::Iopl1,
    }
}

/// Does this client honor POPF/IRET at all? True for both `Repair` and `Iopl3`
/// — they differ in HOW the window's exit is caught, not in whether it is.
#[inline]
pub fn virtual_if_stepping(regs: &Regs) -> bool {
    if_mode(regs) != IfMode::Iopl1
}


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

// ── Interrupts-off windows: learn the exit, then breakpoint it ───────────────
//
// Stepping is correct but costs a #DB per instruction — a ~2500x slowdown of
// everything the client runs with interrupts off, which is exactly where DOS
// games put their sound mixing. It is also almost entirely wasted: at IOPL=1
// CLI and STI already #GP, so the ONLY thing stepping buys is catching the
// POPF/IRET that silently re-enables IF. Doom burned ~170k steps/s to find
// ~170 such instructions.
//
// So step only to LEARN. A window opens where VIF goes 1 -> 0 (a CLI) and
// closes where some instruction sets it back (a POPF). Both are addresses the
// CPU actually executed, so both are proven instruction boundaries — no static
// disassembly, nothing undecidable. Remember the pair; the next time that same
// site opens a window, arm a hardware execute breakpoint on its exit and let
// the client run the section at full speed.
//
// Sound, not complete:
//   * A window whose exit faults on its own (an STI #GPs at IOPL=1) needs no
//     breakpoint at all — `EXIT_FAULTS` records that and it runs free forever.
//   * If a window ever leaves by a path we never learned, VIF simply stays 0.
//     Nothing is mis-delivered; the DOS layer's stall guard notices and calls
//     [`relearn`], which drops the bad pairing and steps again.
//   * A backend with no debug registers returns false from `set_exec_breakpoint`
//     and every window steps, exactly as before.
// The worst case is therefore today's behavior — never a hang, and never an
// interrupt delivered inside a section the client believes is protected.

/// What we know about one CLI site: the addresses its window has been seen to
/// re-enable interrupts at, and whether it still owes us stepping.
///
/// The exits are stored PER SITE and armed only while that site's window is
/// open, because **only one interrupts-off window is open at a time**. So the
/// four hardware breakpoints are not a global budget shared by the whole
/// program — they belong to the current window. That is the difference between
/// "the program may have at most 4 instructions that re-enable IF" (DUKE3D has
/// five, and we ran out) and "one critical section may leave through at most 4
/// places", which is a limit no real code comes close to.
const SITES: usize = 64;
const SITE_EXITS: usize = crate::MAX_EXEC_BP;
/// Windows still owed stepping after a mispredict — enough to sample the other
/// branch of a section that has more than one exit.
const PENALTY: u32 = 32;
const ALWAYS_STEP: u32 = u32::MAX;

static SITE_IP: [AtomicU32; SITES] = [const { AtomicU32::new(0) }; SITES];
/// Exit addresses, per site. `SITE_N` of them are valid. An empty list is
/// meaningful: it means every exit seen was an `STI`, which #GPs on its own and
/// needs no breakpoint at all.
static SITE_EX: [[AtomicU32; SITE_EXITS]; SITES] =
    [const { [const { AtomicU32::new(0) }; SITE_EXITS] }; SITES];
static SITE_N: [AtomicU32; SITES] = [const { AtomicU32::new(0) }; SITES];
static SITE_STEP: [AtomicU32; SITES] = [const { AtomicU32::new(0) }; SITES];

/// The site that opened the window we are in, and the stack level it opened at
/// (see [`repair`] — the stack is what tells us whether the client LEFT).
static CUR_SITE: AtomicU32 = AtomicU32::new(0);
static CUR_SP: AtomicU32 = AtomicU32::new(0);
/// Is the window we are in running free on its breakpoints, rather than being
/// stepped? Only such a window can strand virtual IF — see [`repair`].
static PREDICTED: AtomicU32 = AtomicU32::new(0);
/// What is physically armed right now, so an unchanged set costs no DR writes.
static ARMED: [AtomicU32; SITE_EXITS] = [const { AtomicU32::new(0) }; SITE_EXITS];
static ARMED_N: AtomicU32 = AtomicU32::new(0);

/// Forensics: a repair means a real program did something our model had never
/// seen, and that should never pass silently.
pub static REPAIRS: AtomicU32 = AtomicU32::new(0);
pub static REPAIR_SITE: AtomicU32 = AtomicU32::new(0);
pub static REPAIR_IP: AtomicU32 = AtomicU32::new(0);

/// What the virtual-IF machinery actually did, per client. Without these the
/// only symptom of a mode that silently degraded to stepping is "the game feels
/// slow" — a #DB step never reaches the kernel event loop, so nothing else in
/// the system can see one. They are also the parity check between backends: the
/// same client on metal, TCG and KVM must produce the same shape of numbers.
pub static WINDOWS: AtomicU32 = AtomicU32::new(0); // interrupts-off windows opened
pub static PREDICTED_WINDOWS: AtomicU32 = AtomicU32::new(0); // ...run free on learned exits
pub static BP_HITS: AtomicU32 = AtomicU32::new(0); // ...and closed by an exit breakpoint
pub static HW_STEPS: AtomicU32 = AtomicU32::new(0); // single steps handed to hardware

/// Count one single-stepped instruction a backend retired on its own, without
/// coming back through [`step_virtual_if`]. A backend is allowed to keep
/// stepping in place while the next opcode is non-sensitive (both hosted engines
/// do — it saves a full slice exit per instruction); the step still happened and
/// still costs, so it still counts. Without this the fast path would make a
/// stepping client look free.
#[inline]
pub fn count_hw_step() {
    HW_STEPS.fetch_add(1, Relaxed);
}

/// `(windows, predicted, bp_hits, hw_steps, repairs)` — see the statics above.
pub fn vif_stats() -> (u32, u32, u32, u32, u32) {
    (
        WINDOWS.load(Relaxed),
        PREDICTED_WINDOWS.load(Relaxed),
        BP_HITS.load(Relaxed),
        HW_STEPS.load(Relaxed),
        REPAIRS.load(Relaxed),
    )
}

fn slot(ip: u32) -> usize {
    ((ip ^ (ip >> 5) ^ (ip >> 11)) as usize) % SITES
}

fn site_find(ip: u32) -> Option<usize> {
    let i = slot(ip);
    (SITE_IP[i].load(Relaxed) == ip).then_some(i)
}

fn site_entry(ip: u32) -> usize {
    let i = slot(ip);
    if SITE_IP[i].load(Relaxed) != ip {
        SITE_IP[i].store(ip, Relaxed);
        SITE_N[i].store(0, Relaxed);
        SITE_STEP[i].store(0, Relaxed);
    }
    i
}

/// Arm exactly the exits of the window that is opening (none, if it exits on an
/// STI). Skips the hardware writes when the set is already what we want.
fn arm<A: Arch>(arch: &mut A, i: usize) -> bool {
    let n = SITE_N[i].load(Relaxed) as usize;
    let mut buf = [0u32; SITE_EXITS];
    for (b, e) in buf.iter_mut().zip(SITE_EX[i].iter()).take(n) {
        *b = e.load(Relaxed);
    }
    if ARMED_N.load(Relaxed) as usize == n
        && buf.iter().zip(ARMED.iter()).take(n).all(|(b, a)| a.load(Relaxed) == *b)
    {
        return true; // already armed — no DR traffic
    }
    if !arch.set_exec_breakpoints(&buf[..n]) {
        return false; // no debug registers: caller must step
    }
    for (a, b) in ARMED.iter().zip(buf.iter()) {
        a.store(*b, Relaxed);
    }
    ARMED_N.store(n as u32, Relaxed);
    true
}

fn is_armed(addr: u32) -> bool {
    let n = ARMED_N.load(Relaxed) as usize;
    ARMED.iter().take(n).any(|a| a.load(Relaxed) == addr)
}

/// Record an address this site re-enables interrupts at. Returns false only if
/// the site already has [`SITE_EXITS`] distinct exits — a section leaving
/// through five different places, which no real code does.
fn site_add_exit(i: usize, addr: u32) -> bool {
    let n = SITE_N[i].load(Relaxed) as usize;
    for e in SITE_EX[i].iter().take(n) {
        if e.load(Relaxed) == addr {
            return true;
        }
    }
    if n >= SITE_EXITS {
        return false;
    }
    SITE_EX[i][n].store(addr, Relaxed);
    SITE_N[i].store(n as u32 + 1, Relaxed);
    true
}

/// Drop everything learned. Keyed by bare code address, so a new address space
/// must not inherit the previous program's exits.
pub fn forget_if_windows() {
    for i in 0..SITES {
        SITE_IP[i].store(0, Relaxed);
        SITE_N[i].store(0, Relaxed);
        SITE_STEP[i].store(0, Relaxed);
    }
    ARMED_N.store(0, Relaxed);
    CUR_SITE.store(0, Relaxed);
    PREDICTED.store(0, Relaxed);
    // The stats describe one program's windows, so they reset with them.
    for c in [&WINDOWS, &PREDICTED_WINDOWS, &BP_HITS, &HW_STEPS, &REPAIRS] {
        c.store(0, Relaxed);
    }
}

/// Is the current window running free on its breakpoints rather than being
/// stepped? The entire licence for [`repair`]: a window we are STEPPING cannot
/// lose its exit, because the step loop sees every instruction.
pub fn predicting() -> bool {
    PREDICTED.load(Relaxed) != 0
}

/// The PM virtual-IF gate, called after the #GP monitor resumes an instruction.
/// `entry_ip` is where that instruction lives and `vif_was_on` is VIF before it
/// ran, so a 1 -> 0 transition identifies the site that OPENS a window.
pub fn if_gate<A: Arch>(
    arch: &mut A,
    regs: &mut Regs,
    entry_ip: u32,
    vif_was_on: bool,
) -> MonitorResult {
    if regs.flags32() & VIF_FLAG != 0 {
        // The window closed on an instruction that faulted by itself — an STI.
        // Those can never be missed.
        if !vif_was_on {
            let site = CUR_SITE.swap(0, Relaxed);
            if site != 0 {
                let i = site_entry(site);
                let n = SITE_STEP[i].load(Relaxed);
                if n != 0 && n != ALWAYS_STEP {
                    SITE_STEP[i].store(n - 1, Relaxed);
                }
            }
            PREDICTED.store(0, Relaxed);
        }
        regs.clear_flag32(TF_FLAG);
        return MonitorResult::Resume;
    }
    if !vif_was_on {
        // Already inside a window — some other sensitive instruction (a
        // port-I/O #GP, say). Keep the decision the window opened with; do NOT
        // fall into stepping just because this faulted.
        if predicting() {
            regs.clear_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }
        return step_virtual_if(arch, regs);
    }
    // VIF just went 1 -> 0: a new window opens at `entry_ip`.
    CUR_SITE.store(entry_ip, Relaxed);
    CUR_SP.store(regs.sp32(), Relaxed);
    WINDOWS.fetch_add(1, Relaxed);
    // Iopl3 is the reference path: always step, never predict.
    if if_mode(regs) != IfMode::Iopl3
        && let Some(i) = site_find(entry_ip)
        && SITE_STEP[i].load(Relaxed) == 0
        && arm(arch, i)
    {
        PREDICTED_WINDOWS.fetch_add(1, Relaxed);
        PREDICTED.store(1, Relaxed);
        regs.clear_flag32(TF_FLAG);
        return MonitorResult::Resume;
    }
    PREDICTED.store(0, Relaxed);
    step_virtual_if(arch, regs)
}

/// A hardware execute breakpoint fired. If it is one of the exits we armed for
/// the open window, emulate the instruction there — the breakpoint is a FAULT,
/// so it has not run yet — and the window closes. Returns whether it was ours.
pub fn exec_bp_hit<A: Arch>(arch: &mut A, regs: &mut Regs) -> bool {
    if !is_armed(regs.ip32()) {
        return false;
    }
    BP_HITS.fetch_add(1, Relaxed);
    let ev = monitor_rs::<A>(arch, regs);
    if regs.flags32() & VIF_FLAG != 0 {
        CUR_SITE.store(0, Relaxed);
        PREDICTED.store(0, Relaxed);
        regs.clear_flag32(TF_FLAG);
    }
    matches!(ev, MonitorResult::Resume)
}

// =============================================================================
// The driver gates
// =============================================================================
//
// Every backend that runs a ring-3 guest hits the same two decision points: a
// #GP the monitor just finished, and a #DB. What to do at each is POLICY and
// lives here — hand-writing it per driver is exactly how metal, TCG and KVM
// drifted into three different virtual-IF implementations. A driver supplies
// only the two machine facts it alone knows (where the faulting instruction
// was; whether the #DB was an exec breakpoint) and calls these.

/// A #GP the monitor resumed: hand the window to the virtual-IF gate, which
/// either arms this site's learned exits and lets the client run free, or falls
/// back to single-stepping to learn them.
///
/// `entry_ip` is where the resumed instruction lived and `vif_was_on` is VIF as
/// it stood *before* it ran — a 1 -> 0 transition is the site that OPENS an
/// interrupts-off window, which is what the learned breakpoints are keyed on.
///
/// Skipped for `Iopl1` clients (DPMI 0.9 §2.13 lets a host ignore POPF/IRET, so
/// a conforming client re-enables via CLI/STI/AX=0900-0902, which fault on their
/// own) and in VM86 (where every IF-touching op faults, so nothing can be lost).
pub fn gp_gate<A: Arch>(arch: &mut A, regs: &mut Regs, entry_ip: u32, vif_was_on: bool) {
    if virtual_if_stepping(regs) && regs.mode() != UserMode::VM86 {
        let _ = if_gate(arch, regs, entry_ip, vif_was_on);
    }
}

/// A #DB: either one of our learned exit breakpoints (`bp_hit`, from DR6 B0..B3
/// on metal / KVM, from the code-hook address on TCG) or the single-step trap
/// that the stepping path armed. `bp_hit` closes the window without a step;
/// otherwise re-check the next opcode. TF is cleared for a client that isn't
/// stepping at all — nothing in the kernel arms it, but a stale bit in the
/// client's flags would loop.
pub fn db_gate<A: Arch>(arch: &mut A, regs: &mut Regs, bp_hit: bool) -> MonitorResult {
    if bp_hit && exec_bp_hit(arch, regs) {
        return MonitorResult::Resume;
    }
    if virtual_if_stepping(regs) {
        step_virtual_if(arch, regs)
    } else {
        regs.clear_flag32(TF_FLAG);
        MonitorResult::Resume
    }
}

/// Is a hardware single step pending for this guest? The monitor owns TF: it
/// sets it when it wants hardware to retire exactly one (non-sensitive)
/// instruction and clears it when the window closes. Drivers ask this instead of
/// inferring "VIF is off, so step" — that inference is what made `Repair` and
/// `Iopl1` unrepresentable on the hosted engines, which stepped every window
/// regardless of the client's [`IfMode`].
#[inline]
pub fn stepping(regs: &Regs) -> bool {
    regs.flags32() & TF_FLAG != 0
}

/// Repair a virtual IF we lost, and re-open the site that lost it for learning.
///
/// Called when virtual IF has stayed off, with an interrupt pending, far longer
/// than any real critical section — while the window was running free on its
/// breakpoints. Two very different things look like that, and only the STACK
/// tells them apart:
///
///   DUKE3D  sp0=00846c90 sp=00846ec4 -> unwound ABOVE entry: it popped the
///           flags and returned through several frames. It really did leave,
///           through an exit we had not armed. Repair.
///   ROTT    sp0=006d9276 sp=006d9276 -> the SAME stack level it entered with.
///           It never executed a POPF at all: it is still inside its own
///           critical section, just slow (`cli; wait for vertical retrace; popf`
///           runs ~16 ms, and it is entitled to). Do NOT touch it.
///
/// So the test is structural, not temporal: the exit consumes the flags image
/// pushed before the CLI, which can only raise SP above where the window opened.
/// At or below that level the client is still inside, and we have no business
/// touching its interrupt flag — that is the difference between repairing a flag
/// we broke and firing an interrupt into a critical section the client believes
/// is protected. A timeout alone cannot tell those apart; the stack can.
///
/// Then put the site in the penalty box: the next windows are stepped, the exit
/// it really took is learned and added to ITS list, and it runs free forever
/// after. A section with a second exit therefore costs exactly one repair, once.
pub fn repair<A: Arch>(arch: &mut A, regs: &mut Regs) -> bool {
    let _ = arch;
    if !predicting() || regs.sp32() <= CUR_SP.load(Relaxed) {
        return false;
    }
    let site = CUR_SITE.swap(0, Relaxed);
    REPAIRS.fetch_add(1, Relaxed);
    REPAIR_SITE.store(site, Relaxed);
    REPAIR_IP.store(regs.ip32(), Relaxed);
    if site != 0 {
        let i = site_entry(site);
        if SITE_STEP[i].load(Relaxed) != ALWAYS_STEP {
            SITE_STEP[i].store(PENALTY, Relaxed);
        }
    }
    PREDICTED.store(0, Relaxed);
    regs.set_flags32(regs.flags32() | VIF_FLAG);
    regs.clear_flag32(TF_FLAG);
    true
}

pub fn step_virtual_if<A: Arch>(arch: &mut A, regs: &mut Regs) -> MonitorResult {
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
        let (cs_base, _) = code_view::<A>(regs);
        let mut p = regs.ip32();
        loop {
            let b = arch.read::<u8>(cs_base.wrapping_add(p) as usize);
            if b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 {
                p = p.wrapping_add(1);
            } else {
                break;
            }
        }
        let op = arch.read::<u8>(cs_base.wrapping_add(p) as usize);
        // 0x9C PUSHF, 0x9D POPF, 0xCF IRET, 0xFA CLI, 0xFB STI.
        let must_emulate = matches!(op, 0x9C | 0x9D | 0xCF | 0xFA | 0xFB);
        if !must_emulate {
            // Non-sensitive instruction — let hardware execute one step, then
            // #DB brings us back to re-check.
            HW_STEPS.fetch_add(1, Relaxed);
            regs.set_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }

        // Sensitive: emulate via the monitor decoder and loop to re-check.
        let at = regs.ip32();
        match monitor_rs::<A>(arch, regs) {
            MonitorResult::Resume => {
                // The whole point of stepping: if that instruction just restored
                // VIF, it is an address that re-enables interrupts. Intern it
                // into the armed set (an STI needs no breakpoint — it #GPs on
                // its own) and the site may then run free.
                if regs.flags32() & VIF_FLAG != 0 {
                    // This instruction re-enables interrupts, so it is an EXIT
                    // of the window we are in. An STI needs no breakpoint (it
                    // #GPs on its own); a POPF/IRET must be remembered against
                    // this site so the next window can arm it.
                    let site = CUR_SITE.swap(0, Relaxed);
                    if site != 0 {
                        let i = site_entry(site);
                        let ok = op == 0xFB || site_add_exit(i, at);
                        if !ok {
                            SITE_STEP[i].store(ALWAYS_STEP, Relaxed);
                        } else {
                            let n = SITE_STEP[i].load(Relaxed);
                            if n != 0 && n != ALWAYS_STEP {
                                SITE_STEP[i].store(n - 1, Relaxed);
                            }
                        }
                    }
                    PREDICTED.store(0, Relaxed);
                }
                continue;
            }
            ev @ MonitorResult::Event(_) => return ev,
        }
    }

    // Budget exhausted — back off to hardware stepping for a while.
    HW_STEPS.fetch_add(1, Relaxed);
    regs.set_flag32(TF_FLAG);
    MonitorResult::Resume
}
