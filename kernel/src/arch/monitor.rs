//! Sensitive-instruction monitor — policy-free x86 decoder for #GP traps.
//!
//! When user code executes a sensitive instruction (CLI/STI, PUSHF/POPF, IRET,
//! HLT, INT n, IN/OUT), the CPU raises #GP and arch lands here. The monitor
//! decodes the instruction, advances IP, and — for instructions that can be
//! finished entirely at the machine level (flag toggles, stack frame work) —
//! returns `Resume` so the arch #GP handler can iret straight back to user
//! code without a kernel round-trip.
//!
//! Instructions that need kernel help (port emulation via `PcMachine`, soft
//! INT dispatch, guest idle) are returned as a typed `KernelEvent`. The arch
//! #GP handler encodes the event into the `(rax, rdx)` pair that flows across
//! the arch→kernel boundary via `KernelEvent::encode`; the event loop decodes
//! it back via `KernelEvent::decode`.
//!
//! Arch does not need to know anything about DPMI or the LDT layout —
//! `descriptors::seg_base` / `seg_is_32` resolve any selector by reading
//! directly out of `GDT[GDT_LDT]`.
//!
//! The wire format between `encode`/`decode` is a private implementation
//! detail of `KernelEvent` — callers never see raw tag numbers.

use crate::{Regs, UserMode};

/// Operand width for port I/O events.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoSize {
    Byte  = 0,
    Word  = 1,
    Dword = 2,
}

impl IoSize {
    pub const fn bytes(self) -> u32 {
        match self { IoSize::Byte => 1, IoSize::Word => 2, IoSize::Dword => 4 }
    }
    pub const fn from_u32(v: u32) -> Self {
        match v & 3 { 0 => IoSize::Byte, 1 => IoSize::Word, _ => IoSize::Dword }
    }
}

/// Result of one monitor decode step, returned by `monitor()` to its caller
/// (the arch #GP handler). `Resume` is the fast path — the handler iret's
/// straight to user code. `Event(e)` carries a typed decode result the caller
/// encodes into the arch→kernel `(rax, rdx)` boundary via `e.encode()`.
#[derive(Copy, Clone, Debug)]
pub enum MonitorResult {
    /// Instruction fully handled at the machine level; caller resumes user.
    Resume,
    /// Instruction decoded into a kernel event; caller encodes + bubbles it up.
    Event(KernelEvent),
}

/// Canonical kernel-visible event. `do_arch_execute` returns one of these
/// for every ring-3 trap — the event loop matches on shape, not raw numbers.
///
/// Variants split by origin:
/// - **Monitor-produced** (`SoftInt`, `Hlt`, `In`/`Out`/`Ins`/`Outs`, `Fault`)
///   come from `monitor()` decoding a sensitive-instruction #GP. These are
///   the only variants that flow through `encode`.
/// - **Direct-IDT** (`Irq`, `PageFault`, `Exception`) come from raw `int_num`
///   / `err_code` / CR2 and are written into the arch boundary without
///   going through `encode`.
///
/// `decode` is the single inverse and handles both origins.
#[derive(Copy, Clone, Debug)]
pub enum KernelEvent {
    /// Hardware IRQ was ACK'd + queued inline by arch; the event loop just
    /// needs to know a scheduling point happened.
    Irq,
    /// Page fault at `addr` (CR2).
    PageFault { addr: u32 },
    /// CPU-raised fault from ring 3 — e.g. #DE (0), #UD (6), #NP (11), #SS (12),
    /// #AC (17). Never includes #BP/#OF (vectors 3/4) since those are only
    /// raised by the user `INT3`/`INTO` instructions, nor #PF (handled above).
    Exception(u8),
    /// User-executed `INT n` — either monitor-decoded from a #GP'd `INT n` or
    /// delivered directly through a DPL=3 IDT gate (vectors 3, 4, 0x30..=0xFF,
    /// plus VM86 `INT3`/`0xCC` which bypasses VME). Note that `INT 0x80` lands
    /// here too — it's not the same thing as the `SYSCALL` instruction, which
    /// has its own `Syscall` event.
    SoftInt(u8),
    /// User executed the `SYSCALL` instruction (64-bit only). Distinct from
    /// `SoftInt(0x80)`: the IDT gate path and the SYSCALL fast-path land at
    /// different arch entries (`int_vector` vs `syscall_entry_64`); arch tags
    /// the SYSCALL one with int_num=256 so this stays unambiguous.
    Syscall,
    /// HLT from user code — scheduler yields.
    Hlt,
    /// Port `IN` (AL/AX/EAX ← port). Kernel emulates, writes back into rax.
    In { port: u16, size: IoSize },
    /// Port `OUT` (port ← AL/AX/EAX).
    Out { port: u16, size: IoSize },
    /// String `INS` (ES:DI ← port, advance DI by size). Single element — no REP.
    Ins { size: IoSize },
    /// String `OUTS` (port ← DS:SI, advance SI by size). Single element.
    Outs { size: IoSize },
    /// Non-sensitive #GP or unknown opcode — reflect as fault.
    Fault,
}

impl KernelEvent {
    // Private wire format for `encode`/`decode`. Tags are an arbitrary
    // internal numbering — they have no relationship to any CPU vector,
    // IRQ number, or opcode. The arch boundary sees them only as opaque
    // `(event, extra)` u32 pairs.
    const IRQ:        u32 = 1;
    const PAGE_FAULT: u32 = 2;
    const EXCEPTION:  u32 = 3;
    const SOFT_INT:   u32 = 4;
    const HLT:        u32 = 5;
    const IN:         u32 = 6;
    const OUT:        u32 = 7;
    const INS:        u32 = 8;
    const OUTS:       u32 = 9;
    const FAULT:      u32 = 10;
    const SYSCALL:    u32 = 11;

    /// Encode into the `(event, extra)` u32 pair that flows across the
    /// arch→kernel boundary as `(eax, edx)`. Total over all variants.
    /// Exact inverse of `decode`.
    #[inline]
    pub fn encode(self) -> (u32, u32) {
        match self {
            KernelEvent::Irq                  => (Self::IRQ, 0),
            KernelEvent::PageFault { addr }   => (Self::PAGE_FAULT, addr),
            KernelEvent::Exception(n)         => (Self::EXCEPTION, n as u32),
            KernelEvent::SoftInt(n)           => (Self::SOFT_INT, n as u32),
            KernelEvent::Syscall              => (Self::SYSCALL, 0),
            KernelEvent::Hlt                  => (Self::HLT, 0),
            KernelEvent::In  { port, size }   => (Self::IN,  (port as u32) | ((size as u32) << 16)),
            KernelEvent::Out { port, size }   => (Self::OUT, (port as u32) | ((size as u32) << 16)),
            KernelEvent::Ins  { size }        => (Self::INS,  size as u32),
            KernelEvent::Outs { size }        => (Self::OUTS, size as u32),
            KernelEvent::Fault                => (Self::FAULT, 0),
        }
    }

    /// Decode the `(event, extra)` pair produced by `encode`.
    pub fn decode(event: u32, extra: u32) -> Self {
        match event {
            Self::IRQ        => KernelEvent::Irq,
            Self::PAGE_FAULT => KernelEvent::PageFault { addr: extra },
            Self::EXCEPTION  => KernelEvent::Exception(extra as u8),
            Self::SOFT_INT   => KernelEvent::SoftInt(extra as u8),
            Self::SYSCALL    => KernelEvent::Syscall,
            Self::HLT        => KernelEvent::Hlt,
            Self::IN         => KernelEvent::In  { port: extra as u16, size: IoSize::from_u32(extra >> 16) },
            Self::OUT        => KernelEvent::Out { port: extra as u16, size: IoSize::from_u32(extra >> 16) },
            Self::INS        => KernelEvent::Ins  { size: IoSize::from_u32(extra) },
            Self::OUTS       => KernelEvent::Outs { size: IoSize::from_u32(extra) },
            Self::FAULT      => KernelEvent::Fault,
            _ => panic!("KernelEvent::decode: unknown tag {:#x}", event),
        }
    }
}

// =============================================================================
// Segment resolution (re-exported from descriptors)
// =============================================================================

pub use crate::arch::descriptors::{seg_base, seg_is_32};

// =============================================================================
// EFLAGS bits the monitor cares about
// =============================================================================

const IF_FLAG:    u32 = 1 << 9;
const TF_FLAG:    u32 = 1 << 8;
const IOPL_MASK:  u32 = 3 << 12;
const VM_FLAG:    u32 = 1 << 17;
const OF_FLAG:    u32 = 1 << 11;
/// Flags VM86/PM user code cannot modify via POPF/IRET (IOPL, VM).
const PRESERVED_FLAGS: u32 = IOPL_MASK | VM_FLAG;

/// When true, after a PM client clears virtual IF (via `CLI`), arm TF=1
/// and walk the instruction stream so POPF/IRET can be intercepted. Per
/// DPMI 0.9 §2.13 ("Memory access through PUSHF and POPF and the IRETx
/// instruction may not actually access this flag"), spec-conforming
/// clients use only CLI/STI and AX=0900-0902 to manipulate virtual IF,
/// so TF stepping is belt-and-braces for non-conforming clients and
/// extremely expensive (one #DB per instruction inside any CLI region).
/// Flip to `false` to skip TF stepping; flip to `true` to restore the
/// pre-instrumentation behaviour for A/B comparison.
pub const TF_VIRTUAL_IF_STEPPING: bool = false;

// =============================================================================
// Segment views
// =============================================================================

/// Resolve (linear base, 32-bit?) for the code segment at fault time.
/// VM86 uses CS*16 and is always 16-bit; PM looks through GDT/LDT.
#[inline]
fn code_view(regs: &Regs) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.code_seg() as u32) << 4, false)
    } else {
        let cs = regs.code_seg();
        (seg_base(cs), seg_is_32(cs))
    }
}

/// Resolve (linear base, 32-bit?) for the stack segment at fault time.
#[inline]
fn stack_view(regs: &Regs) -> (u32, bool) {
    if regs.mode() == UserMode::VM86 {
        ((regs.stack_seg() as u32) << 4, false)
    } else {
        let ss = regs.stack_seg();
        (seg_base(ss), seg_is_32(ss))
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
unsafe fn push16(regs: &mut Regs, ss_base: u32, ss_32: bool, val: u16) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(2);
    set_sp(regs, ss_32, new_sp);
    unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(new_sp)) as *mut u16, val); }
}

#[inline]
unsafe fn pop16(regs: &mut Regs, ss_base: u32, ss_32: bool) -> u16 {
    let cur = get_sp(regs, ss_32);
    let val = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(cur)) as *const u16) };
    set_sp(regs, ss_32, cur.wrapping_add(2));
    val
}

/// SW equivalent of the CPU's VM86 INT dispatch, for hosts without VME.
/// Reads CS:IP from the RM IVT at `(vector*4)`, pushes FLAGS/CS/IP on the
/// current VM86 stack, clears IF/TF, and loads the new CS:IP. The monitor
/// calls this for INTs whose redirection-bitmap bit is clear so upstream
/// never sees a "not for us" VM86 INT.
/// Synthesize an INT-n in real mode by pushing FLAGS/CS/IP onto the
/// user's VM86 stack and jumping to IVT[vector]. Mirrors what the CPU
/// does for `INT n` in real mode. Used both by the `0xCD` opcode handler
/// for software INTs that aren't intercepted, and by the kernel's
/// exception-dispatch path for #DE/#BP/#OF in VM86 mode (those vectors
/// are also reachable as software INTs, so reflecting to the real-mode
/// IVT handler matches what real DOS does — programs install their own
/// INT 0 handler and the host must invoke it).
#[inline]
pub unsafe fn sw_reflect_vm86_int(regs: &mut Regs, vector: u8) {
    // IVT lives at linear 0. Unaligned reads are fine here (real-mode IVT
    // is paragraph-aligned; entries are 4 bytes each).
    let ivt_addr = (vector as u32) * 4;
    let new_ip = unsafe { core::ptr::read_unaligned(ivt_addr as *const u16) };
    let new_cs = unsafe { core::ptr::read_unaligned((ivt_addr + 2) as *const u16) };

    let ss_base = (regs.stack_seg() as u32) << 4;
    let flags = regs.flags32() as u16;
    let old_cs = regs.code_seg();
    let old_ip = regs.ip32() as u16;
    unsafe {
        push16(regs, ss_base, false, flags);
        push16(regs, ss_base, false, old_cs);
        push16(regs, ss_base, false, old_ip);
    }
    regs.clear_flag32(IF_FLAG);
    regs.clear_flag32(TF_FLAG);
    regs.set_cs32(new_cs as u32);
    regs.set_ip32(new_ip as u32);
}

#[inline]
unsafe fn push32(regs: &mut Regs, ss_base: u32, ss_32: bool, val: u32) {
    let new_sp = get_sp(regs, ss_32).wrapping_sub(4);
    set_sp(regs, ss_32, new_sp);
    unsafe { core::ptr::write_unaligned((ss_base.wrapping_add(new_sp)) as *mut u32, val); }
}

#[inline]
unsafe fn pop32(regs: &mut Regs, ss_base: u32, ss_32: bool) -> u32 {
    let cur = get_sp(regs, ss_32);
    let val = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(cur)) as *const u32) };
    set_sp(regs, ss_32, cur.wrapping_add(4));
    val
}

// =============================================================================
// Code helpers
// =============================================================================

#[inline]
fn peek_byte(cs_base: u32, ip: u32) -> u8 {
    unsafe { *(cs_base.wrapping_add(ip) as *const u8) }
}

/// Advance IP by `n`, respecting CS B bit (wraps to 16 bits for 16-bit code).
#[inline]
fn advance_ip(regs: &mut Regs, cs_32: bool, n: u32) {
    let new_ip = regs.ip32().wrapping_add(n);
    if cs_32 { regs.set_ip32(new_ip); } else { regs.set_ip32(new_ip & 0xFFFF); }
}

// =============================================================================
// Monitor entry
// =============================================================================

/// Decode the instruction at CS:IP and either finish it inline (`Resume`)
/// or return a typed kernel event (`Event`).
///
/// Called from `isr_handler_inner` on #GP from ring-3. At entry the ring-3
/// canonicalization in `isr_handler` has already swapped VIF↔IF so bit 9 of
/// `regs.flags32()` holds the guest's virtual interrupt flag.
pub fn monitor(regs: &mut Regs) -> MonitorResult {
    use KernelEvent as E;
    use MonitorResult::Event;
    let (cs_base, cs_32) = code_view(regs);
    let (ss_base, ss_32) = stack_view(regs);
    let start_ip = regs.ip32();

    // Parse legacy prefixes we care about. Today: 0x66 (operand-size override).
    let mut advance = 0u32;
    let mut op_size_override = false;
    loop {
        match peek_byte(cs_base, start_ip.wrapping_add(advance)) {
            0x66 => { op_size_override = true; advance += 1; }
            _ => break,
        }
    }

    let op32 = cs_32 ^ op_size_override;
    let opcode = peek_byte(cs_base, start_ip.wrapping_add(advance));
    advance += 1;

    match opcode {
        // ----- Flag / stack instructions (fast path) -----

        // CLI — clear virtual IF. The caller (#GP path or step_virtual_if)
        // is responsible for arming TF=1 so POPF/IRET that would silently
        // drop the IF bit at CPL>IOPL get intercepted.
        0xFA => {
            advance_ip(regs, cs_32, advance);
            regs.clear_flag32(IF_FLAG);
            MonitorResult::Resume
        }
        // STI — re-enable virtual IF.
        0xFB => {
            advance_ip(regs, cs_32, advance);
            regs.set_flag32(IF_FLAG);
            MonitorResult::Resume
        }
        // PUSHF / PUSHFD
        0x9C => {
            advance_ip(regs, cs_32, advance);
            let flags = regs.flags32();
            unsafe {
                if op32 { push32(regs, ss_base, ss_32, flags); }
                else    { push16(regs, ss_base, ss_32, flags as u16); }
            }
            MonitorResult::Resume
        }
        // POPF / POPFD — IOPL and VM are preserved
        0x9D => {
            advance_ip(regs, cs_32, advance);
            let flags = unsafe {
                if op32 { pop32(regs, ss_base, ss_32) }
                else    { pop16(regs, ss_base, ss_32) as u32 }
            };
            let preserved = regs.flags32() & PRESERVED_FLAGS;
            regs.set_flags32((flags & !PRESERVED_FLAGS) | preserved);
            MonitorResult::Resume
        }
        // IRET / IRETD — pop IP, CS, FLAGS (same-ring only)
        0xCF => {
            // Don't pre-advance IP — we're loading it from the stack.
            unsafe {
                if op32 {
                    let new_eip = pop32(regs, ss_base, ss_32);
                    let new_cs  = pop32(regs, ss_base, ss_32) as u16;
                    let new_fl  = pop32(regs, ss_base, ss_32);
                    if new_cs == 0 {
                        return Event(E::Fault);
                    }
                    regs.set_ip32(new_eip);
                    regs.set_cs32(new_cs as u32);
                    let preserved = regs.flags32() & PRESERVED_FLAGS;
                    regs.set_flags32((new_fl & !PRESERVED_FLAGS) | preserved);
                } else {
                    let new_ip = pop16(regs, ss_base, ss_32);
                    let new_cs = pop16(regs, ss_base, ss_32);
                    let new_fl = pop16(regs, ss_base, ss_32) as u32;
                    if new_cs == 0 && regs.mode() != UserMode::VM86 {
                        return Event(E::Fault);
                    }
                    regs.set_ip32(new_ip as u32);
                    regs.set_cs32(new_cs as u32);
                    let preserved = regs.flags32() & PRESERVED_FLAGS;
                    regs.set_flags32((new_fl & !PRESERVED_FLAGS) | preserved);
                }
            }
            MonitorResult::Resume
        }

        // ----- Software interrupts (bubble as SoftInt(n)) -----

        // INT imm8. Two CPU behaviors at the VM86 boundary:
        //   - With CR4.VME=1, the CPU consults the TSS interrupt-redirection
        //     bitmap: bits SET trap here, bits CLEAR are IVT-redirected by
        //     hardware and never reach us.
        //   - Without VME (386/486 SX / QEMU TCG), every VM86 `CD nn` #GPs
        //     into the monitor regardless.
        // Present a uniform interface upward: if the vector's bit is set,
        // bubble it as `SoftInt(vec)`; otherwise do the IVT reflect here in
        // arch so the kernel never sees a "not for us" VM86 INT.
        0xCD => {
            let vector = peek_byte(cs_base, start_ip.wrapping_add(advance));
            advance += 1;
            advance_ip(regs, cs_32, advance);
            if regs.mode() == UserMode::VM86
                && !crate::arch::descriptors::int_intercepted(vector)
            {
                unsafe { sw_reflect_vm86_int(regs, vector); }
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
            let port = peek_byte(cs_base, start_ip.wrapping_add(advance)) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            Event(E::In { port, size: IoSize::Byte })
        }
        // IN AX/EAX, imm8
        0xE5 => {
            let port = peek_byte(cs_base, start_ip.wrapping_add(advance)) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            let size = if op32 { IoSize::Dword } else { IoSize::Word };
            Event(E::In { port, size })
        }
        // OUT imm8, AL
        0xE6 => {
            let port = peek_byte(cs_base, start_ip.wrapping_add(advance)) as u16;
            advance += 1;
            advance_ip(regs, cs_32, advance);
            Event(E::Out { port, size: IoSize::Byte })
        }
        // OUT imm8, AX/EAX
        0xE7 => {
            let port = peek_byte(cs_base, start_ip.wrapping_add(advance)) as u16;
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
// Virtual-IF single-step driver
// =============================================================================
//
// DPMI protected mode runs CPL=3 with IOPL=0. At CPL>IOPL, `POPF`/`IRET`
// silently drop the IF bit instead of `#GP`-ing, so we can't use the `#GP`
// monitor alone to track virtual IF. The workaround: after the client clears
// virtual IF (via `CLI`), walk the instruction stream until virtual IF comes
// back on, emulating every sensitive opcode in software so hardware never
// gets a chance to silently drop the IF bit. For non-sensitive instructions
// we arm `TF=1` and let hardware run exactly one instruction, then come back
// via `#DB` to inspect the next opcode.
//
// Invariants:
// - `regs.ip32()` always points to the next instruction to execute.
// - Only called in PM mode with virtual IF already == 0.
// - TF management lives entirely inside this function; individual opcode
//   handlers in `monitor()` do not touch TF.

pub fn step_virtual_if(regs: &mut Regs) -> MonitorResult {
    // Upper bound on how many sensitive instructions we emulate before
    // yielding back to hardware. Prevents a runaway interpret loop on e.g.
    // `POPF; POPF; POPF; ...`.
    const BUDGET: usize = 64;

    for _ in 0..BUDGET {
        // Fast path: virtual IF came back on — stop stepping.
        if regs.flags32() & IF_FLAG != 0 {
            regs.clear_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }

        // Peek the next opcode (skipping legacy prefixes we care about) to
        // decide if we MUST emulate it. Only the flag-touching instructions
        // that would silently drop IF need software emulation here.
        let (cs_base, _) = code_view(regs);
        let mut p = regs.ip32();
        loop {
            let b = peek_byte(cs_base, p);
            if b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 {
                p = p.wrapping_add(1);
            } else {
                break;
            }
        }
        let op = peek_byte(cs_base, p);
        // 0x9C PUSHF, 0x9D POPF, 0xCF IRET, 0xFA CLI, 0xFB STI.
        let must_emulate = matches!(op, 0x9C | 0x9D | 0xCF | 0xFA | 0xFB);
        if !must_emulate {
            // Non-sensitive instruction — let hardware execute one step,
            // then #DB brings us back to re-check.
            regs.set_flag32(TF_FLAG);
            return MonitorResult::Resume;
        }

        // Sensitive: emulate via the monitor decoder and loop to re-check.
        match monitor(regs) {
            MonitorResult::Resume => continue,
            ev @ MonitorResult::Event(_) => return ev,
        }
    }

    // Budget exhausted — back off to hardware stepping for a while.
    regs.set_flag32(TF_FLAG);
    MonitorResult::Resume
}
