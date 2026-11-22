//! Restartable x86 instructions against a device aperture.

use arch_abi::entry::{InstructionState, TrapAccess};
#[inline]
pub fn string_index(index: u64, addr32: bool) -> u32 {
    if addr32 { index as u32 } else { index as u16 as u32 }
}

#[inline]
pub fn set_string_index(index: &mut u64, value: u32, addr32: bool) {
    if addr32 {
        *index = (*index & !0xFFFF_FFFF) | value as u64;
    } else {
        *index = (*index & !0xFFFF) | (value as u16 as u64);
    }
}

#[inline]
pub fn step_string_index(index: u32, step: u32, addr32: bool, decrement: bool) -> u32 {
    let value = if decrement { index.wrapping_sub(step) } else { index.wrapping_add(step) };
    if addr32 { value } else { value as u16 as u32 }
}

// Native VGA faults invoke this decoder directly from the ring-0 aperture
// handler. Hosted VGA and Voodoo supply a backend bus to the same decoder.

/// Borrowed general registers in x86 encoding order. Entry owns the CPU frame;
/// the decoder only sees instruction operands, IP, and arithmetic flags.
pub struct Operands<'a> {
    pub gprs: [&'a mut u32; 8],
    pub high: Option<[&'a mut u32; 8]>,
    pub ip: &'a mut u32,
    pub flags: &'a mut u32,
}
impl<'a> Operands<'a> {
    /// Borrow canonical 64-bit registers without copying them. The interpreter
    /// executes 16/32-bit instructions: only dword writes clear an upper half.
    pub fn wide(gprs: [&'a mut u64; 8], ip: &'a mut u32, flags: &'a mut u32) -> Self {
        let mut high = [const { None }; 8];
        let mut index = 0;
        let gprs = gprs.map(|word| {
            // u64 storage is aligned for two disjoint u32s, with no padding.
            let halves = unsafe { &mut *(word as *mut u64).cast::<[u32; 2]>() };
            let [first, second] = halves;
            let (lo, hi) = if cfg!(target_endian = "little") { (first, second) } else { (second, first) };
            high[index] = Some(hi);
            index += 1;
            lo
        });
        Self { gprs, high: Some(high.map(Option::unwrap)), ip, flags }
    }

    #[inline(always)]
    pub fn get(&self, index: u8, bytes: u32) -> u32 {
        let reg = if bytes == 1 { index & 3 } else { index & 7 };
        let value = *self.gprs[usize::from(reg)];
        match bytes { 1 if index & 4 != 0 => (value >> 8) & 255,
            1 => value & 255, 2 => value & 65535, _ => value }
    }
    pub fn set(&mut self, index: u8, bytes: u32, value: u32) {
        let reg = if bytes == 1 { index & 3 } else { index & 7 };
        let shift = if bytes == 1 && index & 4 != 0 { 8 } else { 0 };
        let mask = match bytes { 1 => 255u32 << shift, 2 => 65535, _ => u32::MAX };
        let slot = &mut *self.gprs[usize::from(reg)];
        *slot = (*slot & !mask) | ((value << shift) & mask);
        if bytes == 4 {
            if let Some(high) = &mut self.high { *high[usize::from(reg)] = 0; }
        }
    }
}

/// Width of the data a string/mov op moves (bytes).
fn opsize(op32: bool, byte_op: bool) -> u32 {
    if byte_op { 1 } else if op32 { 4 } else { 2 }
}

/// Decode a plain MOV store without an instruction-address cache. Used by
/// both immediate native fault dispatch and the ordinary MMIO decoder.
/// No guest memory is accessed here; truncation and other opcodes decline.
#[cfg(test)]
pub fn mov_store(code: &[u8], default32: bool,
    regs: &Operands<'_>) -> Option<(u32, u32, u32)> {
    decode_mov_store(code, default32, |index, bytes| gpr(regs, index, bytes))
}

#[cfg(test)]
pub fn decode_mov_store(code: &[u8], default32: bool,
    register: impl Fn(u8, u32) -> u32) -> Option<(u32, u32, u32)> {
    decode_mov_store_from(|at| code[at], code.len(), default32, register)
}

/// Fetch only the bytes needed by this opcode. CR2 already supplies the
/// destination, so displacement bytes need not be read at all. The native
/// handler supplies a volatile reader bounded to the executable code page.
pub fn decode_mov_store_from(read: impl Fn(usize) -> u8,
    available: usize, default32: bool, register: impl Fn(u8, u32) -> u32,
) -> Option<(u32, u32, u32)> {
    let (source, immediate, bytes, len) = decode_mov_encoding(&read, available, default32)?;
    Some((if source == 255 { immediate } else { register(source, bytes) }, bytes, len))
}

// Specialize the byte reader so native instruction fetches remain direct loads.
#[inline]
fn decode_mov_encoding(read: &impl Fn(usize) -> u8, available: usize, default32: bool)
    -> Option<(u8, u32, u32, u32)>
{
    let get = |at: usize| (at < available.min(15)).then(|| read(at));
    let first = get(0)?;
    // The overwhelmingly common forms need no prefix-state loop: bare MOV,
    // or one ES override (Wolf3D's scalar stores). Other prefixes use the
    // same operand decoder after resolving their sizes below.
    let (plain, prefix_len) = if first == 0x26 { (get(1)?, 1) } else { (first, 0) };
    let (opcode, mut i, op32, addr32) = if matches!(plain, 0x88 | 0x89 | 0xc6 | 0xc7 | 0xa2 | 0xa3) {
        (plain, prefix_len + 1, default32, default32)
    } else {
        let mut i = 0;
        let (mut p66, mut p67) = (false, false);
        loop {
            match get(i)? {
                0x66 => p66 = true,
                0x67 => p67 = true,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf2 | 0xf3 => {},
                opcode => break (opcode, i + 1, default32 ^ p66, default32 ^ p67),
            }
            i += 1;
        }
    };
    let bytes = opsize(op32, opcode & 1 == 0);
    let mut source = 255;
    let value = match opcode {
        0x88 | 0x89 | 0xc6 | 0xc7 => {
            let modrm = get(i)?;
            if modrm >> 6 == 3 || (opcode >= 0xc6 && modrm & 0x38 != 0) { return None; }
            let length = modrm_len(modrm, addr32,
                |at| get(at as usize).unwrap_or(0), i as u32) as usize;
            i += length;
            if opcode >= 0xc6 {
                let mut value = 0;
                for byte in 0..bytes {
                    value |= u32::from(get(i + byte as usize)?) << (byte * 8);
                }
                i += bytes as usize;
                value
            } else { source = (modrm >> 3) & 7; 0 }
        }
        0xa2 | 0xa3 => {
            i += if addr32 { 4 } else { 2 };
            source = 0;
            0
        }
        _ => return None,
    };
    if i > available || i > 15 { return None; }
    Some((source, value, bytes, i as u32))
}

fn gpr(regs: &Operands<'_>, idx: u8, sz: u32) -> u32 { regs.get(idx, sz) }
fn set_gpr(regs: &mut Operands<'_>, idx: u8, sz: u32, value: u32) { regs.set(idx, sz, value); }

/// Write the six status flags (CF/PF/AF/ZF/SF/OF) for an ALU result of width
/// `sz` bytes, leaving the rest of EFLAGS untouched. CF/AF/OF are supplied by
/// the caller (they depend on the operation); PF (always the low byte), ZF, and
/// SF (the operand-width sign bit) derive from the result.
fn write_flags(regs: &mut Operands<'_>, res: u32, sz: u32, cf: bool, af: bool, of: bool) {
    const MASK: u32 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    let msb = 1u32 << (sz * 8 - 1);
    let mut f = *regs.flags & !MASK;
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
    *regs.flags = f;
}

/// Compute an ALU op `a OP b` of width `sz` bytes (1/2/4), update EFLAGS, and
/// return the masked result. `alu` is the 3-bit selector from the primary opcode
/// group (0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP). Logical ops clear
/// CF/OF/AF per the x86 spec; the arithmetic ops follow the standard
/// borrow/overflow definitions. CMP computes a subtraction for flags but the
/// caller discards the returned value. Inputs/outputs are masked to `sz`.
fn alu(regs: &mut Operands<'_>, alu: u8, a: u32, b: u32, sz: u32) -> u32 {
    let bits = sz * 8;
    let mask = if sz == 4 {
        0xFFFF_FFFFu32
    } else {
        (1u32 << bits) - 1
    };
    let msb = 1u32 << (bits - 1);
    let (a, b) = (a & mask, b & mask);
    let cf_in = *regs.flags & 1;
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

/// Increment or decrement an operand while preserving CF, the one flag these
/// operations deliberately do not share with ADD/SUB.
fn inc_dec(regs: &mut Operands<'_>, value: u32, decrement: bool, sz: u32) -> u32 {
    let carry = *regs.flags & 1;
    let res = alu(regs, if decrement { 5 } else { 0 }, value, 1, sz);
    *regs.flags = (*regs.flags & !1) | carry;
    res
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
#[inline(always)]
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

/// Memory and device access for the instruction decoder. Native VGA supplies
/// this directly from its ring-0 fault context; hosted execution and Voodoo
/// supply their backend here. The opcode decoder is compiled only once.
pub trait FaultBus {
    fn read8(&mut self, off: u32) -> u8;
    fn write8(&mut self, off: u32, value: u8);
    fn offset(&self, address: u32) -> Option<u32>;
    /// Prove access without resolving faults or changing device state.
    fn accessible(&self, address: u32, len: u32, write: bool) -> bool;
    fn guest_read(&self, address: u32) -> u8;
    fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]);
    fn guest_write(&mut self, address: u32, value: u8);
    /// Forward contiguous RAM-to-device copy. A decline must not read or write
    /// anything. The caller has already limited the string instruction chunk.
    fn copy_from_ram(&mut self, _source: u32, _destination: u32, _len: u32) -> bool { false }
    fn fpu_st0(&self) -> [u8; 10];
    fn fpu_pop(&mut self);
    fn end_instruction(&mut self) {}
}


/// Preflight contiguous page batches. A whole element must be available before
/// any VGA read can alter the latches. Completed prefixes remain restartable.
#[allow(clippy::too_many_arguments)]
fn string_ready(bus: &dyn FaultBus, mut source: Option<(u32, u32)>,
    mut destination: Option<(u32, u32)>, write: bool, size: u32,
    count: u32, addr32: bool, backward: bool) -> u32 {
    let mut done = 0;
    while done < count {
        let mut batch = count - done;
        for (base, index) in source.into_iter().chain(destination) {
            let address = base.wrapping_add(index);
            let room = if backward { (address & 4095) + size } else { 4096 - (address & 4095) };
            batch = batch.min((room / size).max(1));
            if !addr32 {
                let room = if backward { index + size } else { 65536 - index };
                batch = batch.min((room / size).max(1));
            }
        }
        let ready = |operand: Option<(u32, u32)>, write| operand.is_none_or(|(base, index)| {
            let start = base.wrapping_add(index).wrapping_sub(if backward { (batch - 1) * size } else { 0 });
            bus.accessible(start, batch * size, write)
        });
        if !ready(source, false) || !ready(destination, write) { break; }
        done += batch;
        for operand in [&mut source, &mut destination] {
            if let Some((_, index)) = operand { *index = step_string_index(*index, batch * size, addr32, backward); }
        }
    }
    done
}

#[allow(clippy::too_many_arguments)]
pub fn emulate(bus: &mut dyn FaultBus, regs: &mut Operands<'_>, cs_base: u32, def32: bool,
    segments: &[u32; 6], off: u32) -> bool {
    let ip0 = if def32 { *regs.ip } else { *regs.ip & 0xFFFF };
    // Pre-read the instruction (max 15 bytes) into a buffer so decoding doesn't
    // hold a borrow of `regs` while the emulation below mutates it.
    let mut buf = [0u8; 16];
    let code_addr = cs_base.wrapping_add(ip0);
    // Preserve wrapping at the end of the 32-bit linear address space.
    let first = (0x1_0000_0000u64 - u64::from(code_addr)).min(buf.len() as u64) as usize;
    if !bus.accessible(code_addr, first as u32, false) || first < buf.len() && !bus.accessible(0, (buf.len() - first) as u32, false) { return false; }
    bus.guest_read_bytes(code_addr, &mut buf[..first]);
    if first < buf.len() { bus.guest_read_bytes(0, &mut buf[first..]); }
    emulate_code(bus, regs, &buf, def32, segments, off)
}

fn emulate_code(bus: &mut dyn FaultBus, regs: &mut Operands<'_>, buf: &[u8; 16], def32: bool,
    segments: &[u32; 6], off: u32) -> bool {
    let vm86 = *regs.flags & (1 << 17) != 0;
    let ip0 = if def32 { *regs.ip } else { *regs.ip & 0xFFFF };
    if let Some((source, immediate, bytes, len)) = decode_mov_encoding(&|at| buf[at], buf.len(), def32) {
        let value = if source == 255 { immediate } else { regs.get(source, bytes) };
        for b in 0..bytes { bus.write8(off + b, (value >> (b * 8)) as u8); }
        bus.end_instruction();
        let next = ip0.wrapping_add(len);
        *regs.ip = if def32 { next } else { next & 0xffff };
        return true;
    }
    let peek = |o: u32| -> u8 { buf[(o & 15) as usize] };

    // Prefixes.
    let mut i = 0u32;
    // Interruptible `rep`: a real CPU services pending interrupts between string
    // iterations. We emulate the whole `rep` in one kernel call, so cap it at
    // REP_CHUNK iterations per fault; if CX isn't drained, `not_done` leaves EIP
    // on the instruction so the guest re-faults to continue. Returning to the
    // guest between chunks lets pending interrupts run. Without this a big keen-4
    // composite `rep movs` runs uninterruptibly, the owed ticks all fire at once
    // when it returns, and the guest's stack overflows.
    const REP_CHUNK: u32 = 2048;
    let mut not_done = false;
    let mut declined = false;
    let mut p66 = false;
    let mut p67 = false;
    let mut rep = false;
    // `repne` (F2) vs `repe` (F3) only matters for scas/cmps, which terminate on
    // ZF; for the unconditional string ops (movs/stos/lods) both just mean rep.
    let mut repne = false;
    let mut source_segment = 3usize; // DS, overridden only for string sources
    loop {
        match peek(i) {
            0x66 => { p66 = true; i += 1; }
            0x67 => { p67 = true; i += 1; }
            0xF3 => { rep = true; i += 1; }
            0xF2 => { rep = true; repne = true; i += 1; }
            prefix @ (0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65) => {
                source_segment = match prefix { 0x26 => 0, 0x2e => 1, 0x36 => 2,
                    0x3e => 3, 0x64 => 4, _ => 5 };
                i += 1;
            }
            _ => break,
        }
    }
    let ds_base = segments[source_segment];
    let es_base = segments[0];
    let op32 = def32 ^ p66;
    let addr32 = def32 ^ p67;
    let opcode = peek(i);
    i += 1;

    match opcode {
        // mov r8, r/m8 — load
        0x8A => {
            let modrm = peek(i);
            let v = bus.read8(off);
            set_gpr(regs, (modrm >> 3) & 7, 1, v as u32);
            i += modrm_len(modrm, addr32, peek, i);
        }
        // mov r16/32, r/m
        0x8B => {
            let modrm = peek(i);
            let sz = opsize(op32, false);
            let mut v = 0u32;
            for b in 0..sz { v |= (bus.read8(off + b) as u32) << (b * 8); }
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
            for b in 0..sz { v |= (bus.read8(off + b) as u32) << (b * 8); }
            set_gpr(regs, 0, sz, v);
            i += if addr32 { 4 } else { 2 };
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
            let memval = bus.read8(off);
            bus.write8(off, regval);
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
                memval |= (bus.read8(off + b) as u32) << (b * 8);
                bus.write8(off + b, (regval >> (b * 8)) as u8);
            }
            set_gpr(regs, ridx, sz, memval);
        }
        // stos: store (E)AX to ES:DI, count in (E)CX if rep. AL/AX/EAX.
        0xAA | 0xAB => {
            let sz = opsize(op32, opcode == 0xAA);
            let total = if rep { gpr(regs, 1, if addr32 { 4 } else { 2 }) } else { 1 };
            let requested = total.min(REP_CHUNK);
            let chunk = string_ready(bus, None, Some((es_base, regs.get(7, if addr32 { 4 } else { 2 }))), true, sz, requested, addr32, *regs.flags & (1 << 10) != 0);
            if chunk == 0 && requested != 0 { return false; }
            declined = chunk < requested;
            let al = regs.get(0, 4);
            let df = *regs.flags & (1 << 10) != 0;
            let mut di = regs.get(7, if addr32 { 4 } else { 2 });
            for _ in 0..chunk {
                let addr = es_base.wrapping_add(di);
                for b in 0..sz {
                    let byte = (al >> (b * 8)) as u8;
                    let byte_addr = addr.wrapping_add(b);
                    if let Some(o) = bus.offset(byte_addr) {
                        bus.write8(o, byte);
                    } else {
                        bus.guest_write(byte_addr, byte);
                    }
                }
                di = step_string_index(di, sz, addr32, df);
            }
            // Advance DI by the chunk; on `rep`, drop CX by the chunk and, if it
            // isn't drained, leave EIP on the instruction (`not_done`) to resume.
            regs.set(7, if addr32 { 4 } else { 2 }, di);
            if rep {
                let rem = total - chunk;
                regs.set(1, if addr32 { 4 } else { 2 }, rem);
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
            let requested = total.min(REP_CHUNK);
            let chunk = string_ready(bus, Some((ds_base, regs.get(6, if addr32 { 4 } else { 2 }))), None, false, sz, requested, addr32, *regs.flags & (1 << 10) != 0);
            if chunk == 0 && requested != 0 { return false; }
            declined = chunk < requested;
            let df = *regs.flags & (1 << 10) != 0;
            // `rep lods` with CX=0 is a no-op — leave the accumulator untouched.
            let mut si = regs.get(6, if addr32 { 4 } else { 2 });
            for _ in 0..chunk {
                let addr = ds_base.wrapping_add(si);
                let mut val = 0u32;
                for b in 0..sz {
                    let byte_addr = addr.wrapping_add(b);
                    let byte = if let Some(o) = bus.offset(byte_addr) {
                        bus.read8(o)
                    } else {
                        bus.guest_read(byte_addr)
                    };
                    val |= (byte as u32) << (b * 8);
                }
                set_gpr(regs, 0, sz, val);
                si = step_string_index(si, sz, addr32, df);
            }
            regs.set(6, if addr32 { 4 } else { 2 }, si);
            if rep {
                let rem = total - chunk;
                regs.set(1, if addr32 { 4 } else { 2 }, rem);
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
            let requested = total.min(REP_CHUNK);
            let chunk = string_ready(bus, Some((ds_base, regs.get(6, if addr32 { 4 } else { 2 }))), Some((es_base, regs.get(7, if addr32 { 4 } else { 2 }))), true, sz, requested, addr32, *regs.flags & (1 << 10) != 0);
            if chunk == 0 && requested != 0 { return false; }
            declined = chunk < requested;
            let df = *regs.flags & (1 << 10) != 0;
            let mut si = regs.get(6, if addr32 { 4 } else { 2 });
            let mut di = regs.get(7, if addr32 { 4 } else { 2 });
            let bytes = chunk * sz;
            let source = ds_base.wrapping_add(si);
            let destination = es_base.wrapping_add(di);
            let copied = chunk != 0 && !df
                && (addr32 || (si + bytes <= 0x10000 && di + bytes <= 0x10000))
                && source.checked_add(bytes).is_some() && destination.checked_add(bytes).is_some()
                && bus.copy_from_ram(source, destination, bytes);
            if copied {
                si = step_string_index(si, bytes, addr32, false);
                di = step_string_index(di, bytes, addr32, false);
            } else {
                for _ in 0..chunk {
                    for b in 0..sz {
                        let src = ds_base.wrapping_add(si).wrapping_add(b);
                        let dst = es_base.wrapping_add(di).wrapping_add(b);
                        // A VRAM source is the planar trap window (present=0): reading
                        // it with a raw `regs.read` page-faults in the kernel. Route it
                        // through `vram_read` — which also loads the GC latches, so a
                        // VRAM→VRAM `rep movs` (Keen's Galaxy engine composites screens
                        // from off-screen VRAM) is the correct EGA latch copy.
                        let byte = if let Some(o) = bus.offset(src) {
                            bus.read8(o)
                        } else {
                            bus.guest_read(src)
                        };
                        if let Some(o) = bus.offset(dst) {
                            bus.write8(o, byte);
                        } else {
                            bus.guest_write(dst, byte);
                        }
                    }
                    si = step_string_index(si, sz, addr32, df);
                    di = step_string_index(di, sz, addr32, df);
                }
            }
            regs.set(6, if addr32 { 4 } else { 2 }, si);
            regs.set(7, if addr32 { 4 } else { 2 }, di);
            if rep {
                let rem = total - chunk;
                regs.set(1, if addr32 { 4 } else { 2 }, rem);
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
            let requested = total.min(REP_CHUNK);
            let chunk = string_ready(bus, None, Some((es_base, regs.get(7, if addr32 { 4 } else { 2 }))), false, sz, requested, addr32, *regs.flags & (1 << 10) != 0);
            if chunk == 0 && requested != 0 { return false; }
            declined = chunk < requested;
            let df = *regs.flags & (1 << 10) != 0;
            let acc = regs.get(0, 4);
            let mut di = regs.get(7, if addr32 { 4 } else { 2 });
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let addr = es_base.wrapping_add(di);
                let mut mem = 0u32;
                for b in 0..sz {
                    let byte_addr = addr.wrapping_add(b);
                    let byte = if let Some(o) = bus.offset(byte_addr) {
                        bus.read8(o)
                    } else {
                        bus.guest_read(byte_addr)
                    };
                    mem |= (byte as u32) << (b * 8);
                }
                alu(regs, 7, acc, mem, sz); // CMP acc, mem — flags only
                di = step_string_index(di, sz, addr32, df);
                done_n += 1;
                if rep {
                    // repe (F3) continues while ZF=1; repne (F2) while ZF=0.
                    let zf = *regs.flags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            regs.set(7, if addr32 { 4 } else { 2 }, di);
            if rep {
                let rem = total - done_n;
                regs.set(1, if addr32 { 4 } else { 2 }, rem);
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
            let requested = total.min(REP_CHUNK);
            let chunk = string_ready(bus, Some((ds_base, regs.get(6, if addr32 { 4 } else { 2 }))), Some((es_base, regs.get(7, if addr32 { 4 } else { 2 }))), false, sz, requested, addr32, *regs.flags & (1 << 10) != 0);
            if chunk == 0 && requested != 0 { return false; }
            declined = chunk < requested;
            let df = *regs.flags & (1 << 10) != 0;
            let mut si = regs.get(6, if addr32 { 4 } else { 2 });
            let mut di = regs.get(7, if addr32 { 4 } else { 2 });
            let mut done_n = 0u32;
            let mut stop = false;
            while done_n < chunk {
                let mut src1 = 0u32; // [DS:SI]
                let mut src2 = 0u32; // [ES:DI]
                for b in 0..sz {
                    let s = ds_base.wrapping_add(si).wrapping_add(b);
                    let d = es_base.wrapping_add(di).wrapping_add(b);
                    let sb = match bus.offset(s) { Some(o) => bus.read8(o), None => bus.guest_read(s) };
                    let db = match bus.offset(d) { Some(o) => bus.read8(o), None => bus.guest_read(d) };
                    src1 |= (sb as u32) << (b * 8);
                    src2 |= (db as u32) << (b * 8);
                }
                alu(regs, 7, src1, src2, sz); // CMP [si], [di] — flags only
                si = step_string_index(si, sz, addr32, df);
                di = step_string_index(di, sz, addr32, df);
                done_n += 1;
                if rep {
                    let zf = *regs.flags & (1 << 6) != 0;
                    if zf == repne { stop = true; break; }
                }
            }
            regs.set(6, if addr32 { 4 } else { 2 }, si);
            regs.set(7, if addr32 { 4 } else { 2 }, di);
            if rep {
                let rem = total - done_n;
                regs.set(1, if addr32 { 4 } else { 2 }, rem);
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
                mem |= (bus.read8(off + b) as u32) << (b * 8);
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
                        bus.write8(off + b, (res >> (b * 8)) as u8);
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
                mem |= (bus.read8(off + b) as u32) << (b * 8);
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
            for b in 0..sz { mem |= (bus.read8(off + b) as u32) << (b * 8); }
            let res = alu(regs, group, mem, imm, sz);
            if group != 7 {
                // CMP: flags only, no write-back
                for b in 0..sz { bus.write8(off + b, (res >> (b * 8)) as u8); }
            }
        }
        // Grp4: INC/DEC r/m8. A planar blitter uses `inc byte es:[di]`
        // (26 FE /0) to update a byte in its off-screen buffer. These are true
        // read-modify-write operations: the read first loads the VGA latches,
        // then the result passes through the planar write logic. INC and DEC
        // update the arithmetic status flags exactly like ADD/SUB by one, with
        // the architectural exception that they preserve CF.
        0xFE if (peek(i) >> 3) & 7 <= 1 => {
            let modrm = peek(i);
            let ext = (modrm >> 3) & 7;
            i += modrm_len(modrm, addr32, peek, i);
            let mem = u32::from(bus.read8(off));
            let res = inc_dec(regs, mem, ext == 1, 1);
            bus.write8(off, res as u8);
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
            let st0 = bus.fpu_st0();
            let (bytes, raw): (u32, u64) = match opcode {
                0xD9 => (4, f80_to_f32_bits(st0) as u64),
                0xDD => (8, f80_to_f64_bits(st0)),
                0xDB => (4, f80_to_int(st0, 32) as u32 as u64),
                _ if ext == 7 => (8, f80_to_int(st0, 64) as u64),
                _ => (2, f80_to_int(st0, 16) as i16 as u16 as u64),
            };
            for b in 0..bytes {
                bus.write8(off + b, (raw >> (b * 8)) as u8);
            }
            // Every integer store but `fist` pops, as does `fstp`.
            if ext == 3 || ext == 7 {
                bus.fpu_pop();
            }
        }
        _ => {
            let _ = (rep, addr32);
            bus.end_instruction();
            return false;
        }
    }

    // Commit anything the target buffered across this instruction (the Voodoo
    // gathers bytes into whole register dwords).
    bus.end_instruction();

    // Advance EIP past the emulated instruction — unless a `rep` was capped
    // mid-string (`not_done`), in which case leave EIP on the instruction so the
    // guest re-executes it (and re-faults) to finish the remaining CX, after the
    // event loop gets a chance to deliver any pending interrupt.
    let new_ip = if not_done { ip0 } else { ip0.wrapping_add(i) };
    let cur_ip = *regs.ip;
    if vm86 { *regs.ip = (cur_ip & !0xFFFF) | (new_ip & 0xFFFF); }
    else { *regs.ip = new_ip; }
    !(declined && not_done)
}

#[cfg(test)]
mod tests {
    use super::inc_dec;
    use super::{set_string_index, step_string_index, string_index};
    use super::Operands;

    #[test]
    fn borrowed_general_registers_preserve_high_halves_except_dword_writes() {
        let mut words = [0xfeed_beef_1234_5678u64; 8];
        let (mut ip, mut flags) = (0x2345, 0x202);
        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
        regs.set(4, 1, 0xab); // AH
        regs.set(7, 2, 0xcdef); // DI
        regs.set(1, 4, 17); // ECX
        assert_eq!(*regs.gprs[0], 0x1234_ab78);
        assert_eq!(*regs.high.as_ref().unwrap()[0], 0xfeed_beef);
        assert_eq!(*regs.gprs[7], 0x1234_cdef);
        assert_eq!(*regs.high.as_ref().unwrap()[7], 0xfeed_beef);
        assert_eq!(*regs.gprs[1], 17);
        assert_eq!(*regs.high.as_ref().unwrap()[1], 0);
        assert_eq!((*regs.ip, *regs.flags), (0x2345, 0x202));
    }

    struct StringBus { ram: [u8; 4096], vram: [u8; 32] }
    impl super::FaultBus for StringBus {
        fn read8(&mut self, off: u32) -> u8 { self.vram[off as usize] }
        fn write8(&mut self, off: u32, value: u8) { self.vram[off as usize] = value; }
        fn offset(&self, address: u32) -> Option<u32> {
            (0x800..0x820).contains(&address).then(|| address - 0x800)
        }
        fn accessible(&self, _: u32, _: u32, _: bool) -> bool { true }
        fn guest_read(&self, address: u32) -> u8 { self.ram[address as usize] }
        fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
            bytes.copy_from_slice(&self.ram[address as usize..address as usize + bytes.len()]);
        }
        fn guest_write(&mut self, address: u32, value: u8) { self.ram[address as usize] = value; }
        fn fpu_st0(&self) -> [u8; 10] { unreachable!() }
        fn fpu_pop(&mut self) { unreachable!() }
    }
    struct CopyBus {
        ram: alloc::vec::Vec<u8>, vram: alloc::vec::Vec<u8>,
        bulk: bool, copied: alloc::vec::Vec<u32>,
    }
    impl super::FaultBus for CopyBus {
        fn read8(&mut self, off: u32) -> u8 { self.vram[off as usize] }
        fn write8(&mut self, off: u32, value: u8) { self.vram[off as usize] = value; }
        fn offset(&self, address: u32) -> Option<u32> {
            (0x40000..0x50000).contains(&address).then(|| address - 0x40000)
        }
        fn accessible(&self, _: u32, _: u32, _: bool) -> bool { true }
        fn guest_read(&self, address: u32) -> u8 { self.ram[address as usize] }
        fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
            bytes.copy_from_slice(&self.ram[address as usize..address as usize + bytes.len()]);
        }
        fn guest_write(&mut self, address: u32, value: u8) { self.ram[address as usize] = value; }
        fn copy_from_ram(&mut self, source: u32, destination: u32, len: u32) -> bool {
            if !self.bulk || source as usize + len as usize > self.ram.len()
                || destination < 0x40000 || destination + len > 0x50000 { return false; }
            self.vram[(destination - 0x40000) as usize..(destination - 0x40000 + len) as usize]
                .copy_from_slice(&self.ram[source as usize..(source + len) as usize]);
            self.copied.push(len);
            true
        }
        fn fpu_st0(&self) -> [u8; 10] { unreachable!() }
        fn fpu_pop(&mut self) { unreachable!() }
    }

    struct CheckedBus { ram: alloc::vec::Vec<u8>, reads: usize, denied: Option<u32> }
    impl super::FaultBus for CheckedBus {
        fn read8(&mut self, off: u32) -> u8 { self.reads += 1; off as u8 }
        fn write8(&mut self, _: u32, _: u8) { panic!("unexpected device write"); }
        fn offset(&self, a: u32) -> Option<u32> { (0x40000..0x50000).contains(&a).then(|| a - 0x40000) }
        fn accessible(&self, a: u32, n: u32, write: bool) -> bool {
            !write || self.denied.is_none_or(|page| !(a < page + 4096 && a + n > page))
        }
        fn guest_read(&self, a: u32) -> u8 { self.ram[a as usize] }
        fn guest_read_bytes(&self, a: u32, b: &mut [u8]) { b.copy_from_slice(&self.ram[a as usize..a as usize + b.len()]); }
        fn guest_write(&mut self, a: u32, v: u8) {
            assert!(self.accessible(a, 1, true), "supervisor attempted an unavailable store");
            self.ram[a as usize] = v;
        }
        fn fpu_st0(&self) -> [u8; 10] { unreachable!() }
        fn fpu_pop(&mut self) { unreachable!() }
    }

    #[test]
    fn vga_to_ram_stops_before_unavailable_page_without_loading_next_latch() {
        for size in [1, 2, 4] {
            for backward in [false, true] {
                let mut bus = CheckedBus { ram: alloc::vec![0; 0x4000], reads: 0,
                    denied: Some(if backward { 0x1000 } else { 0x2000 }) };
                let code: &[u8] = match size { 1 => &[0xf3, 0xa4], 2 => &[0x66, 0xf3, 0xa5], _ => &[0xf3, 0xa5] };
                bus.ram[..code.len()].copy_from_slice(code);
                let mut words = [0u64; 8];
                let (mut ip, mut flags) = (0, if backward { 1 << 10 } else { 0 });
                let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
                let dest = if backward { 0x2010 - size } else { 0x1ff0 };
                regs.set(6, 4, 0x40100); regs.set(7, 4, dest); regs.set(1, 4, 32);
                assert!(!super::emulate(&mut bus, &mut regs, 0, true, &[0; 6], 0x100));
                assert_eq!(bus.reads, 16, "no latch read for the first uncompleted element");
                assert_eq!(regs.get(1, 4), 32 - 16 / size);
                assert_eq!(regs.get(6, 4), if backward { 0x400f0 } else { 0x40110 });
                assert_eq!(regs.get(7, 4), if backward { 0x2000 - size } else { 0x2000 });
                assert_eq!(*regs.ip, 0);
                bus.denied = None; // kernel makes the destination writable
                assert!(super::emulate(&mut bus, &mut regs, 0, true, &[0; 6], 0x100));
                assert_eq!(bus.reads, (32 * size) as usize);
                assert_eq!(regs.get(1, 4), 0);
                assert_eq!(*regs.ip, code.len() as u32);
            }
        }
    }

    #[test]
    fn straddling_element_is_not_partially_written_or_read() {
        let mut bus = CheckedBus { ram: alloc::vec![0; 0x4000], reads: 0, denied: Some(0x2000) };
        bus.ram[..2].copy_from_slice(&[0xf3, 0xa5]);
        let mut words = [0u64; 8];
        let (mut ip, mut flags) = (0, 0);
        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
        regs.set(6, 4, 0x40000); regs.set(7, 4, 0x1ffe); regs.set(1, 4, 2);
        assert!(!super::emulate(&mut bus, &mut regs, 0, true, &[0; 6], 0));
        assert_eq!(bus.reads, 0);
        assert_eq!(regs.get(6, 4), 0x40000);
        assert_eq!(regs.get(7, 4), 0x1ffe);
        assert_eq!(regs.get(1, 4), 2);
        assert_eq!(*regs.ip, 0);
        assert_eq!(&bus.ram[0x1ffe..0x2002], &[0; 4]);
    }

    #[test]
    fn bulk_movs_matches_scalar_registers_data_and_interruptible_chunks() {
        for default32 in [false, true] {
            for addr32 in [false, true] {
                for size in [1u32, 2, 4] {
                    let mut code = alloc::vec![0xf3];
                    if size != 1 && (size == 4) != default32 { code.push(0x66); }
                    if addr32 != default32 { code.push(0x67); }
                    code.push(if size == 1 { 0xa4 } else { 0xa5 });
                    let mut results = alloc::vec::Vec::new();
                    for bulk in [false, true] {
                        let mut bus = CopyBus { ram: (0..0x20000).map(|i| (i as u8).wrapping_mul(37)).collect(),
                            vram: alloc::vec![0xA5; 65536], bulk, copied: alloc::vec::Vec::new() };
                        bus.ram[..code.len()].copy_from_slice(&code);
                        let mut words = [0u64; 8];
                        let (mut ip, mut flags) = (0, 0xA03);
                        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
                        let high = if addr32 { 0 } else { 0xAAAA0000 };
                        regs.set(6, 4, high | 0x1000);
                        regs.set(7, 4, high | 17);
                        regs.set(1, 4, high | 2053);
                        let bases = [0x40000, 0, 0, 0, 0, 0];
                        assert!(super::emulate(&mut bus, &mut regs, 0, default32, &bases, 17));
                        assert_eq!(*regs.ip, 0, "REP must remain interruptible after 2048 iterations");
                        assert_eq!(regs.get(1, 4), high | 5);
                        assert!(super::emulate(&mut bus, &mut regs, 0, default32, &bases, 17 + 2048 * size));
                        assert_eq!(*regs.ip, code.len() as u32);
                        assert_eq!(*regs.flags, 0xA03);
                        assert_eq!(regs.get(1, 4), high);
                        assert_eq!(regs.get(6, 4), high | (0x1000 + 2053 * size));
                        assert_eq!(regs.get(7, 4), high | (17 + 2053 * size));
                        if bulk { assert_eq!(bus.copied, [2048 * size, 5 * size]); }
                        else { assert!(bus.copied.is_empty()); }
                        results.push(bus.vram);
                    }
                    assert_eq!(results[0], results[1]);
                }
            }
        }
    }

    #[test]
    fn bulk_movs_falls_back_for_backward_wrap_and_device_source() {
        for (addr32, source, destination, count, flags) in [
            (true, 0x1010, 20, 4, 0x602), // DF: individual elements descend.
            (false, 0xfffc, 20, 4, 0x202), // SI wraps within its 16-bit segment.
            (true, 0x40004, 8, 4, 0x202), // VRAM source, including overlapping MOVS.
            (true, 0x1000, 20, 0, 0x202), // No reads or writes for zero REP count.
        ] {
            let mut results = alloc::vec::Vec::new();
            for bulk in [false, true] {
                let mut bus = CopyBus { ram: (0..0x20000).map(|i| (i as u8).wrapping_mul(37)).collect(),
                    vram: (0..65536).map(|i| i as u8).collect(), bulk, copied: alloc::vec::Vec::new() };
                let code: &[u8] = if addr32 { &[0xf3, 0xa5] } else { &[0x67, 0xf3, 0xa5] };
                bus.ram[..code.len()].copy_from_slice(code);
                let mut words = [0u64; 8];
                let (mut ip, mut fl) = (0, flags);
                let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut fl);
                regs.set(6, 4, source); regs.set(7, 4, destination); regs.set(1, 4, count);
                assert!(super::emulate(&mut bus, &mut regs, 0, true, &[0x40000, 0, 0, 0, 0, 0], destination));
                assert!(bus.copied.is_empty());
                results.push((bus.vram, regs.get(6, 4), regs.get(7, 4), regs.get(1, 4), *regs.ip, *regs.flags));
            }
            assert_eq!(results[0], results[1]);
        }
    }

    #[test]
    fn string_font_reads_honour_each_source_segment_override() {
        for (index, prefix) in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65].into_iter().enumerate() {
            let bases = [0x400u32, 0, 0x600, 0x700, 0x800, 0x900];
            let mut bus = StringBus { ram: [0; 4096], vram: [0; 32] };
            bus.ram[..3].copy_from_slice(&[prefix, 0xf3, 0xa4]);
            bus.vram[..4].copy_from_slice(&[0x18, 0x3c, 0x66, 0x7e]);
            let mut words = [0u64; 8];
            let (mut ip, mut flags) = (0, 0);
            let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
            regs.set(6, 4, 0x800u32.wrapping_sub(bases[index]));
            regs.set(7, 4, 16);
            regs.set(1, 4, 4);
            assert!(super::emulate(&mut bus, &mut regs, 0, true, &bases, 0));
            assert_eq!(&bus.ram[0x410..0x414], &[0x18, 0x3c, 0x66, 0x7e], "prefix={prefix:02x}");
            assert_eq!(regs.get(1, 4), 0);
            assert_eq!(*regs.ip, 3);
        }
    }
    #[test]
    fn repeated_lods_uses_the_last_segment_override() {
        let bases = [0x400u32, 0, 0x600, 0x700, 0x900, 0x800];
        let mut bus = StringBus { ram: [0; 4096], vram: [0; 32] };
        bus.ram[..4].copy_from_slice(&[0x64, 0x65, 0xf3, 0xac]);
        bus.vram[..4].copy_from_slice(&[1, 2, 3, 0x5a]);
        let mut words = [0u64; 8];
        let (mut ip, mut flags) = (0, 0);
        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
        regs.set(1, 4, 4);
        assert!(super::emulate(&mut bus, &mut regs, 0, true, &bases, 0));
        assert_eq!(regs.get(0, 1), 0x5a);
        assert_eq!(regs.get(6, 4), 4);
        assert_eq!(regs.get(1, 4), 0);
        assert_eq!(*regs.ip, 4);
    }

    #[test]
    fn scalar_mov_fetches_opcode_and_modrm_without_reading_displacement() {
        let reads = core::cell::Cell::new(0);
        // ES:MOV [DI+disp16],AL. The fault address already includes disp16.
        let header = [0x26, 0x88, 0x85];
        let decoded = super::decode_mov_store_from(|at| {
            reads.set(reads.get() + 1);
            header[at] // fetching either displacement byte would panic
        }, 5, false, |index, bytes| {
            assert_eq!((index, bytes), (0, 1));
            0x5a
        });
        assert_eq!(decoded, Some((0x5a, 1, 5)));
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn immediate_mov_decoder_handles_widths_registers_and_immediates() {
        let mut words = [0u64; 8];
        let (mut ip, mut flags) = (0, 0);
        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
        regs.set(0, 4, 0x12345678);
        for (code, default32, expected) in [
            (&[0x88, 0x27][..], false, (0x56, 1, 2)), // AH
            (&[0x26, 0x89, 7][..], false, (0x5678, 2, 3)),
            (&[0x66, 0x89, 7][..], false, (0x12345678, 4, 3)),
            (&[0x66, 0x89, 7][..], true, (0x5678, 2, 3)),
            (&[0xc6, 7, 0xab][..], false, (0xab, 1, 3)),
            (&[0xc7, 7, 0x34, 0x12][..], false, (0x1234, 2, 4)),
            (&[0xa2, 0x34, 0x12][..], false, (0x78, 1, 3)),
            (&[0x89, 0x84, 0x8d, 1, 2, 3, 4][..], true, (0x12345678, 4, 7)),
        ] {
            assert_eq!(super::mov_store(code, default32, &mut regs), Some(expected));
            for len in 0..code.len() {
                assert_eq!(super::mov_store(&code[..len], default32, &mut regs), None);
            }
        }
        for code in [&[0xf3, 0xaa][..], &[0x89, 0xc0], &[0xc6, 0x0f, 1], &[0x8a, 7]] {
            assert_eq!(super::mov_store(code, false, &mut regs), None);
        }
    }

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

    #[test]
    fn byte_inc_dec_flags_can_preserve_carry() {
        let mut words = [0u64; 8];
        let (mut ip, mut flags) = (0, 0);
        let mut regs = Operands::wide(words.each_mut(), &mut ip, &mut flags);
        *regs.flags = 1; // CF set before INC
        let incremented = inc_dec(&mut regs, 0x7f, false, 1);
        assert_eq!(incremented, 0x80);
        assert_eq!(*regs.flags & 1, 1); // INC preserves CF
        assert_ne!(*regs.flags & (1 << 11), 0); // signed overflow
        assert_ne!(*regs.flags & (1 << 4), 0); // auxiliary carry

        *regs.flags = 0; // CF clear before DEC
        let decremented = inc_dec(&mut regs, 0x80, true, 1);
        assert_eq!(decremented, 0x7f);
        assert_eq!(*regs.flags & 1, 0); // DEC preserves CF
        assert_ne!(*regs.flags & (1 << 11), 0); // signed overflow
        assert_ne!(*regs.flags & (1 << 4), 0); // auxiliary borrow
    }
}

struct PlanarBus<'a> {
    registers: &'a crate::Registers,
    planes: crate::Memory<'a>,
    aperture: core::ops::Range<u32>,
    sequential: Option<crate::SequentialWrite>,
    access: &'a mut dyn TrapAccess,
}

impl FaultBus for PlanarBus<'_> {
    fn read8(&mut self, off: u32) -> u8 { self.registers.read(self.planes, off as usize) }
    fn write8(&mut self, off: u32, value: u8) { self.registers.write(self.planes, off as usize, value); }
    fn offset(&self, address: u32) -> Option<u32> {
        self.aperture.contains(&address).then(|| address - self.aperture.start)
    }
    fn accessible(&self, address: u32, len: u32, write: bool) -> bool {
        let Some(end) = address.checked_add(len) else { return false };
        let mut at = address;
        while at < end {
            if self.aperture.contains(&at) {
                at = end.min(self.aperture.end);
            } else {
                let next = end.min((at | 4095).saturating_add(1));
                if !self.access.resident(at, next - at, write) { return false; }
                at = next;
            }
        }
        true
    }
    fn guest_read(&self, address: u32) -> u8 { unsafe { self.access.read(address) } }
    fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
        unsafe { self.access.read_bytes(address, bytes); }
    }
    fn guest_write(&mut self, address: u32, value: u8) { unsafe { self.access.write(address, value); } }
    fn copy_from_ram(&mut self, source: u32, destination: u32, len: u32) -> bool {
        let Some(end) = source.checked_add(len) else { return false };
        if destination < self.aperture.start
            || destination.checked_add(len).is_none_or(|end| end > self.aperture.end)
            || source < self.aperture.end && end > self.aperture.start
        {
            return false;
        }
        let Some(write) = self.sequential else { return false; };
        let offset = (destination - self.aperture.start) as usize;
        if let Some(pointer) = self.access.direct_ram(source, len) {
            write.write(self.planes, offset, len as usize, |i| unsafe { pointer.add(i).read_volatile() });
        } else {
            if !self.access.resident(source, len, false) { return false; }
            write.write(self.planes, offset, len as usize, |i| unsafe { self.access.read(source + i as u32) });
        }
        true
    }
    fn fpu_st0(&self) -> [u8; 10] { self.access.fpu_st0() }
    fn fpu_pop(&mut self) { self.access.fpu_pop(); }
}

/// Emulate a data access. Both the installed hook and the kernel use this
/// function. The caller controls whether guest RAM access may need paging.
pub fn planar_fault(
    registers: &crate::Registers, planes: crate::Memory<'_>, access: &mut dyn TrapAccess,
    regs: &mut Operands<'_>, segments: &[u32; 6], code_limit: u32, default32: bool, address: u32,
) -> bool {
    let Some((aperture, sequential)) = registers.trap_mode()
        .filter(|(range, _)| range.contains(&address)) else { return false };
    planar_access(registers, planes, access, regs, (segments[1], code_limit, default32),
        aperture, sequential, address, false, |_| *segments).is_some()
}

fn planar_access(
    registers: &crate::Registers, planes: crate::Memory<'_>, access: &mut dyn TrapAccess,
    regs: &mut Operands<'_>, (code_base, code_limit, default32): (u32, u32, bool),
    aperture: core::ops::Range<u32>, sequential: Option<crate::SequentialWrite>, address: u32, fetched: bool,
    segments: impl FnOnce(&dyn TrapAccess) -> [u32; 6],
) -> Option<usize> {
    let offset = address - aperture.start;
    let ip = if default32 { *regs.ip } else { *regs.ip & 65535 };
    let code = code_base.checked_add(ip)?;
    let remaining = code_limit.checked_sub(ip)?;
    let available = (u64::from(remaining) + 1).min(15).min(u64::from(4096 - (code & 4095))) as u32;
    let pointer = if fetched && !aperture.contains(&code) {
        unsafe { access.fetched_code(code) }
    } else {
        None
    };
    if !aperture.contains(&code) && let Some(write) = sequential {
        let register = |index, width| regs.get(index, width);
        let store = if let Some(pointer) = pointer {
            decode_mov_store_from(|i| unsafe { pointer.add(i).read_volatile() },
                available as usize, default32, register)
        } else if access.resident(code, available, false) {
            decode_mov_store_from(|i| unsafe { access.read(code + i as u32) },
                available as usize, default32, register)
        } else {
            None
        };
        if let Some((value, bytes, len)) = store
            && bytes <= aperture.end - address
        {
            write.write(planes, offset as usize, bytes as usize, |i| (value >> (i * 8)) as u8);
            let next = ip.wrapping_add(len);
            *regs.ip = if default32 { next } else { next & 65535 };
            return Some(0);
        }
    }
    if remaining < 15 || code.checked_add(16).is_none_or(|end|
        code < aperture.end && end > aperture.start) { return None; }
    let segments = segments(access);
    let mut bus = PlanarBus { registers, planes, aperture, sequential, access };
    let handled = if let Some(pointer) = pointer {
        let mut bytes = [0; 16];
        let first = (4096 - (code & 4095)).min(bytes.len() as u32) as usize;
        for (i, byte) in bytes[..first].iter_mut().enumerate() {
            *byte = unsafe { pointer.add(i).read_volatile() };
        }
        if first < bytes.len() {
            let next = code + first as u32;
            let tail = &mut bytes[first..];
            if !bus.accessible(next, tail.len() as u32, false) { return None; }
            bus.guest_read_bytes(next, tail);
        }
        emulate_code(&mut bus, regs, &bytes, default32, &segments, offset)
    } else {
        emulate(&mut bus, regs, code_base, default32, &segments, offset)
    };
    handled.then_some(1)
}

/// The entry hook is linked into each execution image. The two regions carry
/// the device's register page and its physical plane storage.
pub unsafe fn trap_handler(state: InstructionState<'_>, access: &mut dyn TrapAccess, regions: [*mut u8; 2]) -> bool {
    use arch_abi::eflags::*;
    let flags = *state.flags;
    if flags & TF_FLAG != 0 || flags & (VIF_FLAG | VIP_FLAG) == (VIF_FLAG | VIP_FLAG) {
        return false;
    }
    if !match state.vector { 14 => state.error & !3 == 4, 13 => state.error == 0, _ => false } {
        return false;
    }
    let registers = unsafe { &*regions[0].cast::<crate::Registers>() };
    if registers.enabled.get() == 0 { return false; }
    let fault = if state.vector == 14 {
        let Ok(address) = u32::try_from(state.address) else { return false };
        let Some((aperture, sequential)) = registers.trap_mode()
            .filter(|(range, _)| range.contains(&address)) else { return false };
        Some((address, aperture, sequential))
    } else {
        if !matches!(*state.gprs[2] as u16, 0x3c4 | 0x3c5) { return false; }
        None
    };
    let start = (registers.profile_enabled.get() != 0).then(cycles);
    let vm86 = flags & VM_FLAG != 0;
    let segment = |access: &dyn TrapAccess, sel| {
        if vm86 { (u32::from(sel) << 4, 65535, false) } else { access.segment(sel) }
    };
    let (base, limit, default32) = segment(access, state.selectors[1]);
    let mut regs = Operands { gprs: state.gprs, high: state.high, ip: state.ip, flags: state.flags };
    if let Some((address, aperture, sequential)) = fault {
        let planes = unsafe { crate::Memory::mapped(regions[1], 4 * 65536) };
        let kind = planar_access(registers, planes, access, &mut regs, (base, limit, default32),
            aperture, sequential, address, true, |access| state.selectors.map(|sel| segment(access, sel).0));
        if let (Some(start), Some(kind)) = (start, kind) {
            registers.profile.record(kind, cycles().wrapping_sub(start));
        }
        return kind.is_some();
    }
    let ip = *regs.ip;
    let Some(code) = base.checked_add(ip) else { return false };
    // Both bytes must be within the current code segment and fetched page.
    // A code-limit #GP must fall through before we ask for a fetched view.
    if limit.saturating_sub(ip) < 1 || code & 4095 == 4095
        || registers.trap_mode().is_some_and(|(range, _)| range.contains(&code))
    {
        return false;
    }
    let pointer = unsafe { access.fetched_code(code) };
    if pointer.is_none() && !access.resident(code, 2, false) { return false; }
    let read = |offset: u32| unsafe {
        if let Some(pointer) = pointer { pointer.add(offset as usize).read_volatile() }
        else { access.read(code + offset) }
    };
    let first = read(0);
    let (opcode, operand32, length) = if first == 0x66 {
        (read(1), !default32, 2)
    } else {
        (first, default32, 1)
    };
    let port = regs.get(2, 2) as u16;
    let word = opcode == 0xef && !operand32;
    if !(opcode == 0xee && matches!(port, 0x3c4 | 0x3c5) || word && port == 0x3c4)
        || !registers.mask_out(port, regs.get(0, 2) as u16, word)
    {
        return false;
    }
    let next = ip.wrapping_add(length);
    *regs.ip = if default32 { next } else { next & 65535 };
    if let Some(start) = start {
        registers.profile.record(3, cycles().wrapping_sub(start));
    }
    true
}

fn cycles() -> u64 {
    #[cfg(target_arch = "x86")]
    { unsafe { core::arch::x86::_rdtsc() } }
    #[cfg(target_arch = "x86_64")]
    { unsafe { core::arch::x86_64::_rdtsc() } }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { 0 }
}
