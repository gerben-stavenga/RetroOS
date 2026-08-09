//! Emulating an x86 memory access that faulted on a device aperture.
//!
//! When a guest stores to a memory-mapped device the CPU cannot complete the
//! access itself: the bytes do not go to RAM, they go through hardware logic —
//! the VGA's plane ALU, a Voodoo register write. The page is mapped as a trap,
//! the fault lands here, and this decodes the faulting instruction far enough
//! to know what it was trying to do, then performs it against the device.
//!
//! So this is an instruction decoder: operand sizes and prefixes, the ModRM
//! byte, the GPR file, the ALU and its flags, string operations, and the x87
//! 80-bit conversions a guest needs when it stores a float straight into an
//! aperture. Roughly 750 lines of x86, and none of it is about any one device.
//!
//! It lived inside `vga.rs` for years, which is worth naming because it was
//! never VGA code: [`MmioTarget`] has always had a Voodoo arm and the two use
//! this equally. It was simply the VGA that needed an instruction decoder
//! first — the same accident that had `VgaState` living under `dos/`.
//!
//! Machine code, not personality code and not kernel policy: emulating a
//! guest instruction against an emulated device sits at the same layer as the
//! devices themselves, and travels with them.

use crate::Regs;
use super::vga::{self, VgaState};
use super::{set_string_index, step_string_index, string_index};

// Planar #PF decode is a kernel-side trap with no arch involvement: A0000 is
// left unmapped while planar logic is needed, so the guest store/load faults,
// the *existing* PageFault event arrives, and the instruction is emulated here
// through `vga::vram_write`/`vga::vram_read`.

/// Width of the data a string/mov op moves (bytes).
fn opsize(op32: bool, byte_op: bool) -> u32 {
    if byte_op { 1 } else if op32 { 4 } else { 2 }
}

/// Read/write an integer GP register by encoding `idx` and size `sz` (bytes).
/// Maps the x86 register order (0=A,1=C,2=D,3=B,4=SP/AH..,5=BP/CH,6=SI,7=DI).
fn gpr(regs: &mut Regs, idx: u8, sz: u32) -> u32 {
    let full = match idx & 7 {
        0 => regs.rax, 1 => regs.rcx, 2 => regs.rdx, 3 => regs.rbx,
        4 => regs.frame.rsp, 5 => regs.rbp, 6 => regs.rsi, _ => regs.rdi,
    } as u32;
    if sz == 1 {
        match idx & 7 {
            0..=3 => full & 0xFF,            // al/cl/dl/bl
            _ => (match idx & 3 { 0 => regs.rax, 1 => regs.rcx, 2 => regs.rdx, _ => regs.rbx } >> 8) as u32 & 0xFF, // ah/ch/dh/bh
        }
    } else if sz == 2 { full & 0xFFFF } else { full }
}

fn set_gpr(regs: &mut Regs, idx: u8, sz: u32, val: u32) {
    fn slot(regs: &mut Regs, i: u8) -> &mut u64 {
        match i & 7 {
            0 => &mut regs.rax, 1 => &mut regs.rcx, 2 => &mut regs.rdx, 3 => &mut regs.rbx,
            4 => &mut regs.frame.rsp, 5 => &mut regs.rbp, 6 => &mut regs.rsi, _ => &mut regs.rdi,
        }
    }
    if sz == 1 {
        if idx & 4 == 0 {
            let r = slot(regs, idx & 3); *r = (*r & !0xFF) | (val as u64 & 0xFF);     // al/cl/dl/bl
        } else {
            let r = slot(regs, idx & 3); *r = (*r & !0xFF00) | ((val as u64 & 0xFF) << 8); // ah/ch/dh/bh
        }
    } else if sz == 2 {
        let r = slot(regs, idx); *r = (*r & !0xFFFF) | (val as u64 & 0xFFFF);
    } else {
        let r = slot(regs, idx); *r = val as u64; // 32-bit write zero-extends
    }
}

/// Write the six status flags (CF/PF/AF/ZF/SF/OF) for an ALU result of width
/// `sz` bytes, leaving the rest of EFLAGS untouched. CF/AF/OF are supplied by
/// the caller (they depend on the operation); PF (always the low byte), ZF, and
/// SF (the operand-width sign bit) derive from the result.
fn write_flags(regs: &mut Regs, res: u32, sz: u32, cf: bool, af: bool, of: bool) {
    const MASK: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    let msb = 1u32 << (sz * 8 - 1);
    let mut f = regs.frame.rflags & !MASK;
    if cf {
        f |= 1 << 0;
    } // CF
    if (res as u8).count_ones() & 1 == 0 {
        f |= 1 << 2;
    } // PF: parity of low byte
    if af {
        f |= 1 << 4;
    } // AF
    if res == 0 {
        f |= 1 << 6;
    } // ZF (res already masked)
    if res & msb != 0 {
        f |= 1 << 7;
    } // SF
    if of {
        f |= 1 << 11;
    } // OF
    regs.frame.rflags = f;
}

/// Compute an ALU op `a OP b` of width `sz` bytes (1/2/4), update EFLAGS, and
/// return the masked result. `alu` is the 3-bit selector from the primary opcode
/// group (0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP). Logical ops clear
/// CF/OF/AF per the x86 spec; the arithmetic ops follow the standard
/// borrow/overflow definitions. CMP computes a subtraction for flags but the
/// caller discards the returned value. Inputs/outputs are masked to `sz`.
fn alu(regs: &mut Regs, alu: u8, a: u32, b: u32, sz: u32) -> u32 {
    let bits = sz * 8;
    let mask = if sz == 4 {
        0xFFFF_FFFFu32
    } else {
        (1u32 << bits) - 1
    };
    let msb = 1u32 << (bits - 1);
    let (a, b) = (a & mask, b & mask);
    let cf_in = (regs.frame.rflags & 1) as u32;
    match alu {
        0 | 2 => {
            // ADD / ADC
            let c = if alu == 2 { cf_in } else { 0 };
            let sum = a as u64 + b as u64 + c as u64;
            let res = sum as u32 & mask;
            let cf = (sum >> bits) & 1 != 0;
            let af = (a & 0xF) + (b & 0xF) + c > 0xF;
            let of = (a ^ res) & (b ^ res) & msb != 0;
            write_flags(regs, res, sz, cf, af, of);
            res
        }
        3 | 5 | 7 => {
            // SBB / SUB / CMP
            let c = if alu == 3 { cf_in } else { 0 };
            let diff = a as i64 - b as i64 - c as i64;
            let res = diff as u32 & mask;
            let cf = (a as u64) < b as u64 + c as u64;
            let af = ((a & 0xF) as i32 - (b & 0xF) as i32 - c as i32) < 0;
            let of = (a ^ b) & (a ^ res) & msb != 0;
            write_flags(regs, res, sz, cf, af, of);
            res
        }
        _ => {
            // OR / AND / XOR — CF=OF=AF=0
            let res = (match alu {
                1 => a | b,
                4 => a & b,
                _ => a ^ b,
            }) & mask;
            write_flags(regs, res, sz, false, false, false);
            res
        }
    }
}

/// The 80-bit x87 extended value the backend handed us, as an `f64`.
///
/// The x87 stack is where an `fstp [mmio]` keeps the value it is about to
/// store, so the MMIO decoder has to widen it itself: sign, a 15-bit exponent
/// biased by 16383, and a 64-bit significand whose top bit is *explicit*
/// (unlike an IEEE double's hidden bit). Denormals and NaN/infinity payloads
/// are not worth carrying here — a driver storing a vertex coordinate has
/// neither — so they collapse to zero and the saturated exponent.
/// The same, as raw `f64` bits. Bit manipulation only, never `f64` arithmetic:
/// this runs in the fault handler, where the guest's x87 stack is live and
/// this target's float math IS x87 (see `voodoo::float_to_int32`).
fn f80_to_f64_bits(raw: [u8; 10]) -> u64 {
    let sig = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let se = u16::from_le_bytes([raw[8], raw[9]]);
    let sign = (se >> 15) as u64;
    let exp = (se & 0x7fff) as i32;
    if exp == 0 && sig == 0 {
        sign << 63 // ±0
    } else if exp == 0x7fff {
        (sign << 63) | (0x7ffu64 << 52) | ((sig >> 11) & ((1 << 52) - 1))
    } else {
        let e = exp - 16383 + 1023;
        if e <= 0 {
            sign << 63 // underflows a double: flush to ±0
        } else if e >= 0x7ff {
            (sign << 63) | (0x7ffu64 << 52) // overflows: ±inf
        } else {
            // Drop the explicit integer bit, keep the top 52 significand bits.
            (sign << 63) | ((e as u64) << 52) | ((sig >> 11) & ((1 << 52) - 1))
        }
    }
}

/// An 80-bit extended value as `f32` bits, by re-biasing the exponent and
/// truncating the significand — the same shape as [`f80_to_f64_bits`].
fn f80_to_f32_bits(raw: [u8; 10]) -> u32 {
    let sig = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let se = u16::from_le_bytes([raw[8], raw[9]]);
    let sign = (se >> 15) as u32;
    let exp = (se & 0x7fff) as i32;
    if exp == 0 && sig == 0 {
        return sign << 31; // ±0
    }
    if exp == 0x7fff {
        // Inf or NaN: keep the kind, and never let a NaN collapse to infinity.
        let frac = ((sig >> 40) as u32) & 0x7f_ffff;
        let frac = if sig << 1 != 0 && frac == 0 { 1 } else { frac };
        return (sign << 31) | (0xff << 23) | frac;
    }
    let e = exp - 16383 + 127;
    if e <= 0 {
        sign << 31 // underflows a float: flush to ±0
    } else if e >= 0xff {
        (sign << 31) | (0xff << 23) // overflows: ±inf
    } else {
        // Drop the explicit integer bit, keep the top 23 significand bits.
        (sign << 31) | ((e as u32) << 23) | (((sig >> 40) as u32) & 0x7f_ffff)
    }
}

/// An 80-bit extended value truncated toward zero into `width` bits, the
/// conversion `fist`/`fistp` perform (rounding mode is not honoured: the
/// guests that store integers here store already-rounded values).
fn f80_to_int(raw: [u8; 10], width: u32) -> i64 {
    let sig = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let se = u16::from_le_bytes([raw[8], raw[9]]);
    let neg = se & 0x8000 != 0;
    let exp = (se & 0x7fff) as i32;
    if exp == 0 || exp == 0x7fff {
        return 0; // zero, denormal, infinity or NaN: the indefinite value
    }
    // The significand is 1.63 fixed point; the exponent says where the point
    // sits relative to bit 63.
    let shift = 16383 + 63 - exp;
    let mag = if shift >= 64 {
        0
    } else if shift >= 0 {
        sig >> shift
    } else if -shift < 64 {
        sig << -shift
    } else {
        return 0;
    };
    let limit = if width >= 64 { i64::MAX as u64 } else { (1u64 << (width - 1)) - 1 };
    if mag > limit {
        return if neg { -(limit as i64) - 1 } else { limit as i64 };
    }
    if neg { -(mag as i64) } else { mag as i64 }
}

/// Length of the ModR/M + SIB + displacement that follows the opcode, given the
/// first ModR/M byte and the effective address size (32-bit when `addr32`).
fn modrm_len(modrm: u8, addr32: bool, peek: impl Fn(u32) -> u8, after: u32) -> u32 {
    let md = modrm >> 6;
    let rm = modrm & 7;
    let mut len = 1u32; // the ModR/M byte
    if addr32 {
        let mut sib_rm = rm;
        if rm == 4 { // SIB
            len += 1;
            sib_rm = peek(after + 1) & 7; // base
        }
        len += match md {
            0 => if rm == 5 || (rm == 4 && sib_rm == 5) { 4 } else { 0 },
            1 => 1,
            2 => 4,
            _ => 0, // register direct — not a memory operand (shouldn't fault)
        };
    } else {
        len += match md {
            0 => if rm == 6 { 2 } else { 0 },
            1 => 1,
            2 => 2,
            _ => 0,
        };
    }
    len
}

/// Decode and emulate a faulting device-window access at offset `off`. `cs_base`/
/// `def32` (default operand & address size) are resolved by the caller, which
/// has the LDT. Returns false (→ real SEGV) for an instruction we don't model,
/// so a gap is loud rather than silent corruption.
#[allow(clippy::too_many_arguments)] // planar #PF decode needs the full seg/mode context
/// What a trapped memory-window access is talking to.
///
/// A closed set defined by RetroOS (see `dyn` vs enum: the variants are ours,
/// not an external standard), so it is an enum with an exhaustive match. Both
/// devices present a window the guest writes with ordinary instructions, and
/// both need the *same* instruction decoder below — the only difference is
/// where the bytes land.
pub enum MmioTarget<'a> {
    /// The VGA planar aperture selected by GC[6], through the graphics
    /// controller. Text-font access commonly selects B8000 rather than A0000.
    Planar { vga: &'a mut VgaState, base: u32, len: u32 },
    /// The Voodoo's PCI aperture: registers, LFB and texture download.
    Voodoo(&'a mut super::vvoodoo::VVoodoo),
}

impl MmioTarget<'_> {
    #[inline]
    fn write8<A: crate::Arch>(&mut self, machine: &mut A, off: u32, val: u8) {
        match self {
            Self::Planar { vga, .. } => vga::vram_write(machine, vga, off, val),
            Self::Voodoo(vd) => vd.write8(off, val),
        }
    }

    #[inline]
    fn read8<A: crate::Arch>(&mut self, machine: &mut A, off: u32) -> u8 {
        match self {
            Self::Planar { vga, .. } => vga::vram_read(machine, vga, off),
            Self::Voodoo(vd) => vd.read8(off),
        }
    }

    /// End of the faulting instruction. The Voodoo commits any partial dword
    /// here; the VGA has nothing to settle, every byte already landed.
    #[inline]
    fn end_instruction(&mut self) {
        if let Self::Voodoo(vd) = self {
            vd.flush();
        }
    }

    /// Offset of a guest linear address within this window, if it lands there.
    ///
    /// String ops can have either operand inside the trapped window, so they
    /// have to ask per byte instead of assuming A0000 the way this decoder did
    /// when the VGA was its only caller.
    #[inline]
    fn offset(&self, addr: u32) -> Option<u32> {
        match self {
            Self::Planar { base, len, .. } =>
                (*base..base.saturating_add(*len)).contains(&addr).then(|| addr - *base),
            Self::Voodoo(vd) => vd.aperture_offset(addr),
        }
    }
}


/// The segment bases and the faulting offset are all independent inputs the
/// decoder needs; bundling them would only move the list one level down.
#[allow(clippy::too_many_arguments)]
pub fn handle_mmio_fault<A: crate::Arch>(machine: &mut A, regs: &mut Regs, target: &mut MmioTarget<'_>, cs_base: u32, def32: bool, ds_base: u32, es_base: u32, off: u32) -> bool {
    let vm86 = regs.mode() == crate::UserMode::VM86;
    let ip0 = if def32 { regs.ip32() } else { regs.ip32() & 0xFFFF };
    // Pre-read the instruction (max 15 bytes) into a buffer so decoding doesn't
    // hold a borrow of `regs` while the emulation below mutates it.
    let mut buf = [0u8; 16];
    for k in 0..16u32 {
        buf[k as usize] = machine.read::<u8>((cs_base.wrapping_add(ip0).wrapping_add(k)) as usize);
    }
    let peek = |o: u32| -> u8 { buf[(o & 15) as usize] };

    // Prefixes.
    let mut i = 0u32;
    // Interruptible `rep`: a real CPU services pending interrupts between string
    // iterations. We emulate the whole `rep` in one kernel call, so cap it at
    // REP_CHUNK iterations per fault; if CX isn't drained, `not_done` leaves EIP
    // on the instruction so the guest re-faults to continue — and the event loop
    // delivers any pending timer IRQ between chunks. Without this a big keen-4
    // composite `rep movs` runs uninterruptibly, the owed ticks all fire at once
    // when it returns, and the guest's stack overflows.
    const REP_CHUNK: u32 = 2048;
    let mut not_done = false;
    let mut p66 = false;
    let mut p67 = false;
    let mut rep = false;
    // `repne` (F2) vs `repe` (F3) only matters for scas/cmps, which terminate on
    // ZF; for the unconditional string ops (movs/stos/lods) both just mean rep.
    let mut repne = false;
    loop {
        match peek(i) {
            0x66 => { p66 = true; i += 1; }
            0x67 => { p67 = true; i += 1; }
            0xF3 => { rep = true; i += 1; }
            0xF2 => { rep = true; repne = true; i += 1; }
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => { i += 1; } // seg override (base already in CR2)
            _ => break,
        }
    }
    let op32 = def32 ^ p66;
    let addr32 = def32 ^ p67;
    let opcode = peek(i);
    i += 1;

    match opcode {
        // mov r/m8, r8  — store AL-style
        0x88 => {
            let modrm = peek(i);
            let val = gpr(regs, (modrm >> 3) & 7, 1) as u8;
            i += modrm_len(modrm, addr32, peek, i);
            target.write8(machine, off, val);
        }
        // mov r/m16/32, r
        0x89 => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let val = gpr(regs, (modrm >> 3) & 7, sz);
            i += modrm_len(modrm, addr32, peek, i);
            for b in 0..sz { target.write8(machine, off + b, (val >> (b * 8)) as u8); }
        }
        // mov r8, r/m8 — load
        0x8A => {
            let modrm = peek(i);
            let v = target.read8(machine, off);
            set_gpr(regs, (modrm >> 3) & 7, 1, v as u32);
            i += modrm_len(modrm, addr32, peek, i);
        }
        // mov r16/32, r/m
        0x8B => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let mut v = 0u32;
            for b in 0..sz { v |= (target.read8(machine, off + b) as u32) << (b * 8); }
            set_gpr(regs, (modrm >> 3) & 7, sz, v);
            i += modrm_len(modrm, addr32, peek, i);
        }
        // mov AL/AX/EAX <-> moffs — the direct-offset accumulator forms. The
        // memory operand is the faulting window itself, so `off` is already the
        // VRAM offset; only the moffs immediate (addr-size wide) needs to be
        // consumed. Wolf3D's video detection reads `mov al, es:[0]` at A000:0
        // (opcode A0 with an ES override) and crashed here unhandled.
        0xA0 | 0xA1 => {
            let sz = opsize(op32, opcode == 0xA0);
            let mut v = 0u32;
            for b in 0..sz { v |= (target.read8(machine, off + b) as u32) << (b * 8); }
            set_gpr(regs, 0, sz, v);
            i += if addr32 { 4 } else { 2 };
        }
        0xA2 | 0xA3 => {
            let sz = opsize(op32, opcode == 0xA2);
            let val = gpr(regs, 0, sz);
            for b in 0..sz { target.write8(machine, off + b, (val >> (b * 8)) as u8); }
            i += if addr32 { 4 } else { 2 };
        }
        // mov r/m8, imm8
        0xC6 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, peek, i);
            let imm = peek(i + l);
            i += l + 1;
            target.write8(machine, off, imm);
        }
        // mov r/m16/32, imm16/32 — Keen clears VRAM with `mov word es:[di],0`.
        0xC7 => {
            let modrm = peek(i);
            let l = modrm_len(modrm, addr32, peek, i);
            let sz = opsize(op32, false);
            let mut imm = 0u32;
            for b in 0..sz { imm |= (peek(i + l + b) as u32) << (b * 8); }
            i += l + sz;
            for b in 0..sz { target.write8(machine, off + b, (imm >> (b * 8)) as u8); }
        }
        // xchg r/m8, r8 — Keen 4's Galaxy engine does `xchg es:[di], al` to
        // touch planar VRAM: the read half loads the GC latches, the write half
        // stores AL through the EGA write path, in one instruction. x86 swap
        // semantics: reg gets the (GC-processed) read byte, VRAM gets reg's old
        // value written via `vram_write` (so map mask / write mode / latches all
        // apply). `vram_read` must run first — it loads the latches the write uses.
        0x86 => {
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            let regval = gpr(regs, ridx, 1) as u8;
            i += modrm_len(modrm, addr32, peek, i);
            let memval = target.read8(machine, off);
            target.write8(machine, off, regval);
            set_gpr(regs, ridx, 1, memval as u32);
        }
        // xchg r/m16/32, r — the word/dword form, byte-by-byte so each byte
        // loads its latch before the matching write (same as the `mov` group).
        0x87 => {
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            let sz = opsize(op32, false);
            let regval = gpr(regs, ridx, sz);
            i += modrm_len(modrm, addr32, peek, i);
            let mut memval = 0u32;
            for b in 0..sz {
                memval |= (target.read8(machine, off + b) as u32) << (b * 8);
                target.write8(machine, off + b, (regval >> (b * 8)) as u8);
            }
            set_gpr(regs, ridx, sz, memval);
        }
        // stos: store (E)AX to ES:DI, count in (E)CX if rep. AL/AX/EAX.
        0xAA | 0xAB => {
            let sz = opsize(op32, opcode == 0xAA);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let al = regs.rax as u32;
            let df = regs.frame.rflags & (1 << 10) != 0;
            let mut di = string_index(regs.rdi, addr32);
            for _ in 0..chunk {
                let addr = es_base.wrapping_add(di);
                for b in 0..sz {
                    let byte = (al >> (b * 8)) as u8;
                    let byte_addr = addr.wrapping_add(b);
                    if let Some(o) = target.offset(byte_addr) {
                        target.write8(machine, o, byte);
                    } else {
                        machine.write::<u8>(byte_addr as usize, byte);
                    }
                }
                di = step_string_index(di, sz, addr32, df);
            }
            // Advance DI by the chunk; on `rep`, drop CX by the chunk and, if it
            // isn't drained, leave EIP on the instruction (`not_done`) to resume.
            set_string_index(&mut regs.rdi, di, addr32);
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // lods: load DS:SI into the accumulator (AL/AX/EAX), count in (E)CX if
        // rep. The source (DS:SI) is the faulting A0000 window, so `off` is its
        // VRAM offset — mirror `stos`, but read through `vram_read` (which loads
        // the GC latches / honours read map & read mode) instead of writing. A
        // Keen 4 loop copies off-screen VRAM with `lodsb; stosb; add esi,stride`.
        // Only the final byte survives in the accumulator; intervening reads
        // still run so the latches end up as the real CPU would leave them.
        0xAC | 0xAD => {
            let sz = opsize(op32, opcode == 0xAC);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            // `rep lods` with CX=0 is a no-op — leave the accumulator untouched.
            let mut si = string_index(regs.rsi, addr32);
            for _ in 0..chunk {
                let addr = ds_base.wrapping_add(si);
                let mut val = 0u32;
                for b in 0..sz {
                    let byte_addr = addr.wrapping_add(b);
                    let byte = if let Some(o) = target.offset(byte_addr) {
                        target.read8(machine, o)
                    } else {
                        machine.read::<u8>(byte_addr as usize)
                    };
                    val |= (byte as u32) << (b * 8);
                }
                set_gpr(regs, 0, sz, val);
                si = step_string_index(si, sz, addr32, df);
            }
            set_string_index(&mut regs.rsi, si, addr32);
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // movs: DS:SI -> ES:DI. Each operand may be normal RAM or the A0000
        // planar window, resolved per byte below. Recompute both ends from the
        // registers rather than trusting `off` — either operand can fault.
        //
        // A VRAM *source* (DS:SI in A0000) MUST go through `vram_read`, not a raw
        // `regs.read`: A0000 is mapped present=0 (the planar trap), so a direct
        // read page-faults in the kernel (Keen 4's Galaxy engine composites from
        // off-screen VRAM with `rep movs` and crashed here). `vram_read` also
        // loads the GC latches, making a VRAM→VRAM `movs` the correct EGA latch
        // copy. The common `mov al,[si]`/`mov [di],al` latch copy already works
        // via the 0x8A/0x88 handlers. Source (DS:(E)SI) and dest (ES:(E)DI) bases
        // are resolved by the caller (shift-by-4 in VM86, LDT in PM) so the same
        // path serves both: 32-bit-PM `rep movsd` is Doom's Mode-Y plane blit
        // under CWSDPMI/DOS4GW (broke "no graphics under UEFI" — passthrough hides
        // it).
        0xA4 | 0xA5 => {
            let sz = opsize(op32, opcode == 0xA4);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let mut si = string_index(regs.rsi, addr32);
            let mut di = string_index(regs.rdi, addr32);
            for _ in 0..chunk {
                for b in 0..sz {
                    let src = ds_base.wrapping_add(si).wrapping_add(b);
                    let dst = es_base.wrapping_add(di).wrapping_add(b);
                    // A VRAM source is the planar trap window (present=0): reading
                    // it with a raw `regs.read` page-faults in the kernel. Route it
                    // through `vram_read` — which also loads the GC latches, so a
                    // VRAM→VRAM `rep movs` (Keen's Galaxy engine composites screens
                    // from off-screen VRAM) is the correct EGA latch copy.
                    let byte = if let Some(o) = target.offset(src) {
                        target.read8(machine, o)
                    } else {
                        machine.read::<u8>(src as usize)
                    };
                    if let Some(o) = target.offset(dst) {
                        target.write8(machine, o, byte);
                    } else {
                        machine.write::<u8>(dst as usize, byte);
                    }
                }
                si = step_string_index(si, sz, addr32, df);
                di = step_string_index(di, sz, addr32, df);
            }
            set_string_index(&mut regs.rsi, si, addr32);
            set_string_index(&mut regs.rdi, di, addr32);
            if rep {
                let rem = total - chunk;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = rem > 0;
            }
        }
        // scas: compare the accumulator (AL/AX/EAX) with ES:DI, set flags like
        // `cmp acc, [es:di]`, advance DI. The memory operand is the faulting
        // A0000 window (present=0), so `off` is its VRAM offset — read it through
        // `vram_read` (loads the GC latches), never a raw `regs.read`. A `repe`
        // (F3) / `repne` (F2) run also terminates on ZF, so it's chunked with an
        // early break when the ZF condition flips (unlike the unconditional
        // stos/movs). Used by DOS blitters to find a run boundary in VRAM.
        0xAE | 0xAF => {
            let sz = opsize(op32, opcode == 0xAE);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let acc = regs.rax as u32;
            let mut di = string_index(regs.rdi, addr32);
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let addr = es_base.wrapping_add(di);
                let mut mem = 0u32;
                for b in 0..sz {
                    let byte_addr = addr.wrapping_add(b);
                    let byte = if let Some(o) = target.offset(byte_addr) {
                        target.read8(machine, o)
                    } else {
                        machine.read::<u8>(byte_addr as usize)
                    };
                    mem |= (byte as u32) << (b * 8);
                }
                alu(regs, 7, acc, mem, sz); // CMP acc, mem — flags only
                di = step_string_index(di, sz, addr32, df);
                done_n += 1;
                if rep {
                    // repe (F3) continues while ZF=1; repne (F2) while ZF=0.
                    let zf = regs.frame.rflags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            set_string_index(&mut regs.rdi, di, addr32);
            if rep {
                let rem = total - done_n;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                // Re-fault to resume only if the chunk cap (not the ZF condition)
                // stopped us with counts left.
                not_done = !stop && rem > 0;
            }
        }
        // cmps: compare DS:SI with ES:DI, set flags like `cmp [ds:si], [es:di]`,
        // advance both. Either operand may be in the A0000 window, so recompute
        // both ends from the registers (like `movs`) and route a VRAM operand
        // through `vram_read`. x86 sets flags from [DS:SI] - [ES:DI]. Same
        // `repe`/`repne` ZF termination as scas.
        0xA6 | 0xA7 => {
            let sz = opsize(op32, opcode == 0xA6);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let chunk = total.min(REP_CHUNK);
            let df = regs.frame.rflags & (1 << 10) != 0;
            let mut si = string_index(regs.rsi, addr32);
            let mut di = string_index(regs.rdi, addr32);
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let mut src1 = 0u32; // [DS:SI]
                let mut src2 = 0u32; // [ES:DI]
                for b in 0..sz {
                    let s = ds_base.wrapping_add(si).wrapping_add(b);
                    let d = es_base.wrapping_add(di).wrapping_add(b);
                    let sb = match target.offset(s) { Some(o) => target.read8(machine, o), None => machine.read::<u8>(s as usize) };
                    let db = match target.offset(d) { Some(o) => target.read8(machine, o), None => machine.read::<u8>(d as usize) };
                    src1 |= (sb as u32) << (b * 8);
                    src2 |= (db as u32) << (b * 8);
                }
                alu(regs, 7, src1, src2, sz); // CMP [si], [di] — flags only
                si = step_string_index(si, sz, addr32, df);
                di = step_string_index(di, sz, addr32, df);
                done_n += 1;
                if rep {
                    let zf = regs.frame.rflags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            set_string_index(&mut regs.rsi, si, addr32);
            set_string_index(&mut regs.rdi, di, addr32);
            if rep {
                let rem = total - done_n;
                regs.rcx = if addr32 { (regs.rcx & !0xFFFF_FFFF) | rem as u64 }
                           else { (regs.rcx & !0xFFFF) | (rem as u64 & 0xFFFF) };
                not_done = !stop && rem > 0;
            }
        }
        // ALU with a VRAM operand: the primary-group r/m forms, all eight groups
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP, in both directions and widths. Opcode
        // low 3 bits select form: 0 = `OP r/m8,r8`, 1 = `OP r/m,r`,
        // 2 = `OP r8,r/m8`, 3 = `OP r,r/m`. Even ⇒ byte; the width of the
        // word/dword forms is `opsize(op32, …)`, so it follows the segment's
        // default operand size (16-bit VM86 / 32-bit PM) toggled by a 0x66
        // prefix — exactly like the `mov` arms. The VRAM read goes through
        // `vram_read` (loads the GC latches; read map / read mode honoured); a
        // write-back (every group but CMP, when r/m is the dest) goes through
        // `vram_write` (map mask / write mode / latches). Keen 4's masked-sprite
        // blit reads the screen with `and ax, es:[di]` (0x23) then merges;
        // Doom's Mode-X loop does `cmp byte [vram], dl`.
        op if op < 0x40 && (op & 0x07) < 4 => {
            let group = (op >> 3) & 7;
            let reg_is_dst = op & 0x02 != 0; // forms 2/3: reg <- reg OP [vram]
            let sz = opsize(op32, op & 1 == 0);
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let reg = gpr(regs, ridx, sz);
            let mut mem = 0u32;
            for b in 0..sz {
                mem |= (target.read8(machine, off + b) as u32) << (b * 8);
            }
            if reg_is_dst {
                let res = alu(regs, group, reg, mem, sz);
                if group != 7 {
                    set_gpr(regs, ridx, sz, res);
                } // CMP: flags only
            } else {
                let res = alu(regs, group, mem, reg, sz);
                if group != 7 {
                    // CMP: no write-back
                    for b in 0..sz {
                        target.write8(machine, off + b, (res >> (b * 8)) as u8);
                    }
                }
            }
        }
        // TEST r/m, r (0x84 byte, 0x85 word/dword): AND for flags only. Not
        // part of the group above — TEST has no ALU group number and never
        // writes back, so it is the one read-modify-*no*-write form. The VRAM
        // read still goes through `vram_read`, which loads the GC latches
        // exactly as a real read does. Xenon 2 tests its planar back buffer
        // with `es: test [di], bl` before merging a sprite.
        0x84 | 0x85 => {
            let sz = opsize(op32, opcode == 0x84);
            let modrm = peek(i);
            let ridx = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let reg = gpr(regs, ridx, sz);
            let mut mem = 0u32;
            for b in 0..sz {
                mem |= (target.read8(machine, off + b) as u32) << (b * 8);
            }
            alu(regs, 4, mem, reg, sz); // group 4 = AND, result discarded
        }
        // Grp1: the immediate forms of the ALU group above — ADD/OR/ADC/SBB/
        // AND/SUB/XOR/CMP r/m, imm (0x80 = byte, 0x81 = imm16/32, 0x83 =
        // sign-extended imm8; the group lives in ModRM bits 3-5). Same VRAM
        // read-modify-write path: the read loads the GC latches, the
        // write-back (every group but CMP) goes through the EGA write logic.
        // Operation Wolf clears its planar back buffer with
        // `and byte es:[di], 0`.
        0x80 | 0x81 | 0x83 => {
            let modrm = peek(i);
            let group = (modrm >> 3) & 7;
            let sz = if opcode == 0x80 { 1 } else { opsize(op32, false) };
            let l = modrm_len(modrm, addr32, peek, i);
            let immsz = if opcode == 0x81 { sz } else { 1 };
            let mut imm = 0u32;
            for b in 0..immsz { imm |= (peek(i + l + b) as u32) << (b * 8); }
            if opcode == 0x83 {
                imm = imm as u8 as i8 as i32 as u32; // sign-extend to operand size
                if sz == 2 { imm &= 0xFFFF; }
            }
            i += l + immsz;
            let mut mem = 0u32;
            for b in 0..sz { mem |= (target.read8(machine, off + b) as u32) << (b * 8); }
            let res = alu(regs, group, mem, imm, sz);
            if group != 7 {
                // CMP: flags only, no write-back
                for b in 0..sz { target.write8(machine, off + b, (res >> (b * 8)) as u8); }
            }
        }
        // x87 stores into the aperture: `fst`/`fstp` (ModR/M reg field 2 and 3)
        // in single (0xD9), double (0xDD) and integer (0xDB dword, 0xDF word,
        // 0xDF /7 qword) forms. A planar VGA guest never does this, but a Glide
        // driver does nothing else: its triangle setup writes every vertex
        // coordinate and gradient to a *register* with `fstps`, because the
        // values are already on the x87 stack. The value being stored is in
        // ST(0), which is not part of `Regs` — the backend hands it over, and
        // the popping forms pop it afterwards.
        0xD9 | 0xDB | 0xDD | 0xDF if matches!((peek(i) >> 3) & 7, 2 | 3) || (opcode == 0xDF && (peek(i) >> 3) & 7 == 7) => {
            let modrm = peek(i);
            let ext = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let st0 = machine.fpu_st0();
            let (bytes, raw): (u32, u64) = match opcode {
                0xD9 => (4, f80_to_f32_bits(st0) as u64),
                0xDD => (8, f80_to_f64_bits(st0)),
                0xDB => (4, f80_to_int(st0, 32) as u32 as u64),
                _ if ext == 7 => (8, f80_to_int(st0, 64) as u64),
                _ => (2, f80_to_int(st0, 16) as i16 as u16 as u64),
            };
            for b in 0..bytes {
                target.write8(machine, off + b, (raw >> (b * 8)) as u8);
            }
            // Every integer store but `fist` pops, as does `fstp`.
            if ext == 3 || ext == 7 {
                machine.fpu_pop();
            }
        }
        _ => {
            let _ = (rep, addr32);
            crate::println!(
                "  [planar #PF] unhandled opcode {:#04x} off={:#x} ip0={:#x} bytes={:02x?}",
                opcode,
                off,
                ip0,
                &buf[..]
            );
            target.end_instruction();
            return false;
        }
    }

    // Commit anything the target buffered across this instruction (the Voodoo
    // gathers bytes into whole register dwords).
    target.end_instruction();

    // Advance EIP past the emulated instruction — unless a `rep` was capped
    // mid-string (`not_done`), in which case leave EIP on the instruction so the
    // guest re-executes it (and re-faults) to finish the remaining CX, after the
    // event loop gets a chance to deliver any pending interrupt.
    let new_ip = if not_done { ip0 } else { ip0.wrapping_add(i) };
    let cur_ip = regs.ip32();
    if vm86 { regs.set_ip32((cur_ip & !0xFFFF) | (new_ip & 0xFFFF)); }
    else { regs.set_ip32(new_ip); }
    true
}

#[cfg(test)]
mod tests {
    use super::super::{set_string_index, step_string_index, string_index};

    #[test]
    fn interpreted_string_indices_obey_address_width() {
        let mut index = 0xCAFE_BEEF_1234_FFFE;
        assert_eq!(string_index(index, false), 0xFFFE);
        let wrapped = step_string_index(0xFFFE, 4, false, false);
        assert_eq!(wrapped, 2);
        set_string_index(&mut index, wrapped, false);
        assert_eq!(index, 0xCAFE_BEEF_1234_0002);

        assert_eq!(step_string_index(1, 4, false, true), 0xFFFD);
        assert_eq!(step_string_index(0xFFFF_FFFE, 4, true, false), 2);
    }
}
