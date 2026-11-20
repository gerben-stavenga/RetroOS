//! Resident planar emulation. Entry lends general registers and instruction
//! operands; this module never owns or rewrites an interrupt frame.
use ::planar::instruction::{self, FaultBus, Operands};

#[thread_local]
static mut ACTIVE: Option<Context> = None;

struct Context {
    state: *const ::planar::Registers,
    planes: *mut u8,
    base: u32,
    end: u32,
    cs_mode: u32,
    default32: bool,
    code_base: u32,
    code_limit: u32,
    report: ::planar::Report,
    write: Option<::planar::SequentialWrite>,
}

pub(crate) unsafe fn bind(binding: Option<::planar::Binding>) {
    unsafe { crate::entry::install_hook(None); }
    publish();
    unsafe {
        ACTIVE = binding.map(|binding| {
            assert!(!binding.registers.is_null() && binding.registers as usize % 4096 == 0);
            assert!(!binding.planes.is_null() && binding.planes as usize % 4096 == 0);
            Context { state: binding.registers, planes: binding.planes,
                write: None, base: 0, end: 0, cs_mode: u32::MAX, default32: false,
                code_base: 0, code_limit: 0,
                report: ::planar::Report { cycles: 0, details: [[0; 4]; 7] } }
        });
        crate::entry::install_hook((&*(&raw const ACTIVE)).is_some().then_some(instruction_hook));
    }
}

/// Installed with the device binding; entry itself has no device policy.
unsafe extern "C" fn instruction_hook(stack: *mut arch_abi::entry::StackFrame, wide: bool) -> bool {
    let Some(state) = (unsafe { crate::entry::instruction32(stack, wide) }) else { return false };
    instruction(state)
}

#[inline(always)]
fn instruction(state: crate::entry::InstructionState<'_>) -> bool {
    // Only data faults prove the CPU fetched this instruction. Debugging
    // and pending virtual interrupts must go through normal dispatch.
    if *state.flags & 0x100 != 0 || *state.flags & (3 << 19) == 3 << 19
        || !match state.vector { 14 => state.error & !3 == 4, 13 => state.error == 0, _ => false }
    { return false; }
    handle(&mut Operands { gprs: state.gprs, high: state.high, ip: state.ip, flags: state.flags },
        state.selectors, state.vector)
}

/// Refresh derived values after kernel device or descriptor programming.
/// The binding itself persists until the owning context is suspended.
pub(crate) fn prepare(cs: u16, vm86: bool) {
    unsafe {
        let Some(context) = (&mut *(&raw mut ACTIVE)).as_mut() else { return };
        (context.base, context.end) = match (&*context.state).cpu_aperture() {
            ::planar::CpuAperture::Trapped { range } =>
                (u32::from(range.start_page) << 12, u32::from(range.end_page) << 12),
            _ => (0, 0),
        };
        context.write = (&*context.state).sequential_write();
        context.set_code(cs, vm86);
    }
}

/// Publish profiling without another arch call or a change of handler.
pub(crate) fn publish() {
    unsafe {
        let Some(context) = (&mut *(&raw mut ACTIVE)).as_mut() else { return };
        (&*context.state).profile.publish(core::mem::replace(&mut context.report,
            ::planar::Report { cycles: 0, details: [[0; 4]; 7] }));
    }
}

/// Only entry interprets native frames. Segment selectors are ES, CS, SS, DS,
/// FS, GS; IP/flags are instruction operands, not a canonical return frame.
pub(crate) fn handle(regs: &mut Operands<'_>, selectors: [u16; 6], vector: u64) -> bool {
    let Some(context) = (unsafe { (&mut *(&raw mut ACTIVE)).as_mut() }) else { return false };
    let state = unsafe { &*context.state };
    if state.enabled.get() == 0 { return false; }
    let vm86 = *regs.flags & (1 << 17) != 0;
    let key = u32::from(selectors[1]) | if vm86 { 0 } else { 1 << 20 };
    if context.cs_mode != key { context.set_code(selectors[1], vm86); }
    let profile = state.profile_enabled.get() != 0;
    let start = if profile { crate::x86::rdtsc() } else { 0 };
    let (handled, kind) = if vector == 13 {
        (context.output(regs), 3)
    } else {
        // Entry admits only VM86 and compatibility/protected 16/32-bit code.
        let address = crate::x86::read_cr2();
        if !(context.base..context.end).contains(&address) { return false; }
        let offset = address - context.base;
        if context.mov_store(regs, offset) { (true, 0) }
        else {
            (context.emulate(regs, selectors, vm86, offset), 1)
        }
    };
    if profile {
        let elapsed = crate::x86::rdtsc().wrapping_sub(start);
        context.report.cycles = context.report.cycles.wrapping_add(elapsed);
        let detail = &mut context.report.details[kind];
        let calls = (u64::from(detail[1]) << 32 | u64::from(detail[0])).wrapping_add(1);
        let cycles = (u64::from(detail[3]) << 32 | u64::from(detail[2])).wrapping_add(elapsed);
        *detail = [calls as u32, (calls >> 32) as u32, cycles as u32, (cycles >> 32) as u32];
    }
    handled
}

impl Context {
    #[inline(never)]
    fn emulate(&mut self, regs: &mut Operands<'_>, selectors: [u16; 6], vm86: bool, offset: u32) -> bool {
        // Generic emulation can touch other guest pages. Protect its
        // preflight and access together, preserving partial REP progress.
        let _paging = crate::paging2::PagingGuard::lock();
        let segment = |sel| if vm86 { u32::from(sel) << 4 }
            else { crate::descriptors::seg_base(sel) };
        let bases = selectors.map(segment);
        let (cs, def32) = (self.code_base, self.default32);
        self.code_available(*regs.ip, 16) == 16
            && instruction::emulate(self, regs, cs, def32, &bases, offset)
    }

    #[inline(never)]
    fn set_code(&mut self, cs: u16, vm86: bool) {
        use crate::descriptors as segments;
        self.cs_mode = u32::from(cs) | if vm86 { 0 } else { 1 << 20 };
        self.default32 = !vm86 && segments::seg_is_32(cs);
        self.code_base = if vm86 { u32::from(cs) << 4 } else { segments::seg_base(cs) };
        self.code_limit = if vm86 { 0xffff } else { segments::seg_limit(cs) };
    }
    /// Entry admitted an actual user data #PF or instruction #GP, so the CPU
    /// has already fetched IP. Arch exclusively owns the active address space:
    /// no other core can unmap this instruction page while we handle its trap.
    /// Stay on that page and within CS.limit; other pages need a preflight.
    #[inline(always)]
    fn instruction_window(&self, ip: u32) -> u32 {
        if ip > self.code_limit { return 0; }
        let Some(address) = self.code_base.checked_add(ip) else { return 0 };
        if address >= 0xc0000000 || (self.base..self.end).contains(&address) { return 0; }
        let available = (4096 - (address & 4095)).min(15);
        let remaining = self.code_limit - ip;
        if remaining < available { remaining + 1 } else { available }
    }
    fn code_available(&self, ip: u32, wanted: u32) -> u32 {
        if ip > self.code_limit { return 0; }
        let Some(address) = self.code_base.checked_add(ip) else { return 0 };
        let len = (u64::from(self.code_limit) + 1 - u64::from(ip)).min(u64::from(wanted)) as u32;
        let Some(end) = address.checked_add(len) else { return 0 };
        if address < self.end && end > self.base || !self.accessible(address, len, false) { return 0; }
        len
    }
    fn advance(&self, regs: &mut Operands<'_>, len: u32) {
        let next = regs.ip.wrapping_add(len);
        *regs.ip = if self.default32 { next } else { next & 65535 };
    }
    fn mov_store(&mut self, regs: &mut Operands<'_>, offset: u32) -> bool {
        let ip = *regs.ip;
        // Restrict the quick decoder to one resident code page. The generic
        // path can check both pages for instructions straddling a boundary.
        let available = self.instruction_window(ip);
        if available == 0 { return false; }
        let code = self.code_base.wrapping_add(ip) as *const u8;
        let Some((value, bytes, len)) = instruction::decode_mov_store_from(
            |at| unsafe { code.add(at).read_volatile() }, available as usize,
            self.default32, |index, width| regs.get(index, width)) else { return false };
        if bytes > self.end - self.base - offset { return false; }
        let Some(write) = self.write else { return false };
        let planes = unsafe { ::planar::Memory::mapped(self.planes, 4 * 65536) };
        write.write(planes, offset as usize, bytes as usize, |i| (value >> (i * 8)) as u8);
        self.advance(regs, len);
        true
    }
    fn output(&mut self, regs: &mut Operands<'_>) -> bool {
        if self.instruction_window(*regs.ip) < 2 { return false; }
        let code = self.code_base.wrapping_add(*regs.ip) as *const u8;
        let mut opcode = unsafe { code.read_volatile() };
        let mut len = 1;
        let mut operand32 = self.default32;
        if opcode == 0x66 {
            opcode = unsafe { code.add(1).read_volatile() };
            operand32 = !operand32;
            len = 2;
        }
        let port = regs.get(2, 2) as u16;
        if !matches!((opcode, port), (0xee, 0x3c4 | 0x3c5) | (0xef, 0x3c4))
            || opcode == 0xef && operand32 { return false; }
        if !(unsafe { &*self.state }).mask_out(port, regs.get(0, 2) as u16, opcode == 0xef) { return false; }
        if let Some(write) = &mut self.write { write.set_mask(unsafe { (&*self.state).seq.get(2) }); }
        self.advance(regs, len);
        true
    }
}

impl ::planar::instruction::FaultBus for Context {
    fn read8(&mut self, off: u32) -> u8 {
        let planes = unsafe { ::planar::Memory::mapped(self.planes, 4 * 65536) };
        (unsafe { &*self.state }).read(planes, off as usize)
    }
    fn write8(&mut self, off: u32, value: u8) {
        let planes = unsafe { ::planar::Memory::mapped(self.planes, 4 * 65536) };
        (unsafe { &*self.state }).write(planes, off as usize, value);
    }
    fn accessible(&self, address: u32, len: u32, write: bool) -> bool {
        let Some(end) = address.checked_add(len) else { return false };
        if end > 0xc0000000 { return false; }
        let mut at = address;
        while at < end {
            if (self.base..self.end).contains(&at) { at = end.min(self.end); continue; }
            let next = end.min((at | 4095) + 1);
            if !crate::mapping::resident(at, next - at, write) { return false; }
            at = end.min((at | 4095) + 1);
        }
        true
    }
    fn offset(&self, address: u32) -> Option<u32> {
        (self.base..self.end).contains(&address).then(|| address - self.base)
    }
    fn guest_read(&self, address: u32) -> u8 {
        unsafe { (address as *const u8).read_volatile() }
    }
    fn guest_read_bytes(&self, address: u32, bytes: &mut [u8]) {
        for (i, byte) in bytes.iter_mut().enumerate() { *byte = unsafe { (address as *const u8).add(i).read_volatile() }; }
    }
    fn guest_write(&mut self, address: u32, value: u8) {
        unsafe { (address as *mut u8).write_volatile(value); }
    }
    fn copy_from_ram(&mut self, source: u32, destination: u32, len: u32) -> bool {
        let Some(source_end) = source.checked_add(len) else { return false };
        let Some(destination_end) = destination.checked_add(len) else { return false };
        if destination < self.base || destination_end > self.end
            || source < self.end && source_end > self.base { return false; }
        if !crate::mapping::resident(source, len, false) { return false; }
        let planes = unsafe { ::planar::Memory::mapped(self.planes, 4 * 65536) };
        (unsafe { &*self.state }).write_sequential_span(planes, (destination - self.base) as usize, len as usize,
            |i| unsafe { core::ptr::with_exposed_provenance::<u8>(source as usize + i).read_volatile() })
    }
    fn fpu_st0(&self) -> [u8; 10] {
        let mut value = [0; 10];
        unsafe { core::arch::asm!("fstp tbyte ptr [{p}]", "fld tbyte ptr [{p}]", p = in(reg) value.as_mut_ptr(), options(nostack)); }
        value
    }
    fn fpu_pop(&mut self) { unsafe { core::arch::asm!("fstp st(0)", options(nostack)); } }
}
