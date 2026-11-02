//! Native VGA aperture and port handling. MOV stores use immutable decode
//! recipes; VGA ports and sound DMA polling also stay in ring 0.

// Low word: normalized first two instruction bytes. High word: recipe
// (width in bits 0..2, address32 bit 3, immediate bit 4, moffs bit 5,
// one prefix bit 6). Each bucket has two entries, verified at compile time.
#[cfg(any(target_arch = "x86", test))]
const HASH: u32 = 0xd64148c7;
#[cfg(any(target_arch = "x86", test))]
const PREFIXES: [u8; 9] = [0, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67];
#[cfg(any(target_arch = "x86", test))]
const OPCODES: [u8; 6] = [0x88, 0x89, 0xc6, 0xc7, 0xa2, 0xa3];
#[cfg(any(target_arch = "x86", test))]
const fn decode_table(default32: bool) -> [u32; 128] {
    let mut table = [0; 128];
    let mut p = 0;
    while p < PREFIXES.len() {
        let prefix = PREFIXES[p];
        let mut o = 0;
        while o < OPCODES.len() {
            let opcode = OPCODES[o];
            let key = if prefix == 0 { opcode as u32 } else { prefix as u32 | (opcode as u32) << 8 };
            let width = if opcode & 1 == 0 { 1 } else if default32 != (prefix == 0x66) { 4 } else { 2 };
            let recipe = width | (((default32 != (prefix == 0x67)) as u32) << 3)
                | (((opcode == 0xc6 || opcode == 0xc7) as u32) << 4)
                | (((opcode == 0xa2 || opcode == 0xa3) as u32) << 5)
                | (((prefix != 0) as u32) << 6);
            let mut slot = ((key.wrapping_mul(HASH) >> 26) * 2) as usize;
            if table[slot] != 0 { slot += 1; }
            assert!(table[slot] == 0, "decode hash bucket overflow");
            table[slot] = key | recipe << 16;
            o += 1;
        }
        p += 1;
    }
    table
}
#[cfg(any(target_arch = "x86", test))]
static DECODE16: [u32; 128] = decode_table(false);
#[cfg(any(target_arch = "x86", test))]
static DECODE32: [u32; 128] = decode_table(true);

pub fn execute<A: crate::Arch>(machine: &mut A, dos: &mut super::DosState<A>,
    regs: &mut crate::Regs, io: &arch_abi::IoPolicy) -> (crate::KernelEvent, u64) {
    #[cfg(target_arch = "x86")]
    {
        use super::machine::vga;
        let base = vga::live_vram_ptr_if_initialized();
        let state = dos.pc.vga.emulated_mut().and_then(|dev| dev.state.legacy_mut());
        if let (Some(base), Some(state)) = (base, state) {
            let pages = vga::trapped_aperture(state).unwrap_or(0..0);
            let fast = Fast {
                enabled: u32::from(assembly_writes(state)),
                decode: 0,
                cs_mode: 0, default32: 0, code_base: 0, code_limit: 0,
                planes: base.as_ptr() as u32, base: u32::from(pages.start) << 12,
                end: u32::from(pages.end) << 12, plane_mask: u32::from(state.seq.get(2) & 15),
                profile: u32::from(crate::kernel::startup::profile_enabled()),
                cycles_lo: 0, cycles_hi: 0, start_lo: 0, start_hi: 0,
                inline_scanout: u32::from(!crate::kernel::media::enabled()),
                handoff_request: crate::kernel::media::GUEST_MEMORY.request_flag() as u32,
            };
            // The event loop holds live_access across guest execution. The
            // callback only touches resident device state and atomic VRAM.
            let mut context = Context {
                fast, state, ldt: &dos.ldt[..], planes: base.as_ptr(),
                dma: &mut dos.pc.dma, audio: &dos.pc.audio,
                pit_deadline: dos.pc.vpit.irq_deadline_ns(),
                pit: &mut dos.pc.vpit, pic: &mut dos.pc.vpic,
                base: u32::from(pages.start) << 12,
                end: u32::from(pages.end) << 12, yielded: false, stepped: false, user_tf: regs.user_tf(),
            };
            context.set_code(regs.code_seg(), regs.mode() == crate::UserMode::VM86);
            unsafe {
                PLANAR_FAST_CONTEXT = &mut context.fast;
                ACTIVE = (&mut context as *mut Context<'_>).cast();
                let previous = machine.replace_interrupt_handlers(14, arch_abi::InterruptHandlers {
                    entry32: planar_page_fault_32 as *const () as u32,
                    entry64: planar_page_fault_64 as *const () as u64,
                });
                let previous_input = machine.replace_interrupt_handlers(13, arch_abi::InterruptHandlers {
                    entry32: device_io_32 as *const () as u32,
                    entry64: device_io_64 as *const () as u64,
                });
                let mut event = machine.execute(regs, io);
                machine.replace_interrupt_handlers(13, previous_input);
                machine.replace_interrupt_handlers(14, previous);
                ACTIVE = core::ptr::null_mut();
                PLANAR_FAST_CONTEXT = core::ptr::null_mut();
                if context.stepped { event = crate::KernelEvent::EmulatedStep { user_was: context.user_tf }; }
                else if context.yielded { event = crate::KernelEvent::Irq; }
                let fast_cycles = (u64::from(context.fast.cycles_hi) << 32) | u64::from(context.fast.cycles_lo);
                return (event, fast_cycles);
            }
        }
    }
    let _ = dos;
    (machine.execute(regs, io), 0)
}

// This descriptor lives for one CPU loan. Emulated VGA port programming
// traps into this context. Fast mask writes update this descriptor too.
#[cfg(target_arch = "x86")]
#[repr(C)]
struct Fast {
    enabled: u32, decode: u32, cs_mode: u32, default32: u32,
    code_base: u32, code_limit: u32, planes: u32, base: u32,
    end: u32, plane_mask: u32, profile: u32,
    cycles_lo: u32, cycles_hi: u32, start_lo: u32, start_hi: u32,
    inline_scanout: u32, // synchronous scanout requires a Rust deadline check
    handoff_request: u32,
}

#[cfg(target_arch = "x86")]
const _: () = {
    assert!(core::mem::size_of::<Fast>() == 68);
    assert!(core::mem::offset_of!(Fast, decode) == 4);
    assert!(core::mem::offset_of!(Fast, code_base) == 16);
    assert!(core::mem::offset_of!(Fast, planes) == 24);
    assert!(core::mem::offset_of!(Fast, plane_mask) == 36);
    assert!(core::mem::offset_of!(Fast, profile) == 40);
    assert!(core::mem::offset_of!(Fast, cycles_lo) == 44);
    assert!(core::mem::offset_of!(Fast, start_lo) == 52);
    assert!(core::mem::offset_of!(Fast, inline_scanout) == 60);
    assert!(core::mem::offset_of!(Fast, handoff_request) == 64);
};

#[cfg(target_arch = "x86")]
fn assembly_writes(state: &super::machine::vga::LegacyVgaState) -> bool {
    state.seq.get(4) & 0x0c == 0x04 // sequential, plane-minor memory
        && state.gc.get(5) & 0x0b == 0
        && state.gc.get(3) & 0x1f == 0
        && state.gc.get(1) & 0x0f == 0
        && state.gc.get(8) == 0xff
}

// Only the guest-executing BSP installs these DOS entries. The media worker
// never executes a guest. SS-relative access avoids loading Rust's selectors
// on assembly hits; the pointer is cleared before its stack context expires.
#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
static mut PLANAR_FAST_CONTEXT: *mut Fast = core::ptr::null_mut();

#[cfg(target_arch = "x86")]
struct Context<'a> {
    fast: Fast,
    state: &'a mut super::machine::vga::LegacyVgaState,
    ldt: &'a [u64],
    dma: &'a mut super::machine::Dma8237,
    audio: &'a crate::kernel::media::Shared<super::AudioDevices>,
    pit_deadline: u64,
    pit: &'a mut super::machine::VirtualPit,
    pic: &'a mut super::machine::VirtualPic,
    planes: *mut u8,
    base: u32,
    end: u32,
    yielded: bool,
    stepped: bool,
    user_tf: bool,
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn planar_page_fault_32();
    fn planar_page_fault_64();
    fn device_io_32();
    fn device_io_64();
}

#[cfg(target_arch = "x86")]
#[thread_local]
static mut ACTIVE: *mut () = core::ptr::null_mut();

/// GPR slots are identical in both entries: low halves at index * 8.
/// Only the CPU's return-frame width differs. It remains separate from GPRs.
#[cfg(any(target_arch = "x86", test))]
struct Frame { pointer: *mut u8, wide: bool }
#[cfg(any(target_arch = "x86", test))]
impl Frame {
    fn read(&self, offset: usize) -> u32 {
        unsafe { self.pointer.add(offset).cast::<u32>().read() }
    }
    fn ip_offset(&self) -> usize { if self.wide { 80 } else { 72 } }
    fn flags_offset(&self) -> usize { if self.wide { 96 } else { 80 } }
    fn ip(&self) -> u32 { self.read(self.ip_offset()) }
    fn cs(&self) -> u16 { self.read(if self.wide { 88 } else { 76 }) as u16 }
    fn vm86(&self) -> bool { self.read(self.flags_offset()) & (1 << 17) != 0 }
    fn set_ip(&mut self, ip: u32) {
        unsafe { self.pointer.add(self.ip_offset()).cast::<u32>().write(ip); }
    }
    fn advance_ip(&mut self, length: u32, default32: bool) {
        let next = self.ip().wrapping_add(length);
        self.set_ip(if default32 { next } else { next & 0xffff });
    }
    fn selectors(&self) -> (u16, u16) {
        if self.vm86() { (self.read(96) as u16, self.read(92) as u16) }
        else { unsafe { (self.pointer.sub(4).cast::<u16>().read(), self.pointer.sub(8).cast::<u16>().read()) } }
    }
    #[cfg(target_arch = "x86")]
    fn other_selectors(&self) -> (u16, u16, u16) {
        let ss = self.read(if self.wide { 112 } else { 88 }) as u16;
        if self.vm86() { (ss, self.read(100) as u16, self.read(104) as u16) }
        else {
            let fs: u16;
            unsafe { core::arch::asm!("mov {0:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags)); }
            (ss, fs, unsafe { self.pointer.sub(12).cast::<u16>().read() })
        }
    }
    fn operands(&mut self) -> super::machine::mmio::Operands<'_> {
        // Even GPR slots are initialized by assembly; odd slots may be
        // uninitialized. The mutable views do not overlap the return frame.
        unsafe { super::machine::mmio::Operands {
            gprs: &mut *self.pointer.cast(),
            ip: &mut *self.pointer.add(self.ip_offset()).cast(),
            flags: &mut *self.pointer.add(self.flags_offset()).cast(),
        } }
    }
    #[cfg(test)]
    fn register(&self, index: u8, bytes: u32) -> u32 {
        let reg = if bytes == 1 { index & 3 } else { index & 7 };
        let value = self.read(usize::from(reg) * 8);
        match bytes { 1 if index & 4 != 0 => (value >> 8) & 255,
            1 => value & 255, 2 => value & 65535, _ => value }
    }
}

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
#[cold]
unsafe extern "C" fn planar_fault(pointer: *mut u8, wide: u32, address: u32) -> u32 {
    let context = unsafe { &mut *ACTIVE.cast::<Context<'_>>() };
    let mut frame = Frame { pointer, wide: wide != 0 };
    let handled = if !(context.base..context.end).contains(&address) { 0 }
        else if crate::kernel::media::GUEST_MEMORY.reader_requested()
            || crate::kernel::media::inline_video_due()
        {
            // Scheduling point only: ring 1 services scanout, then retries
            // this still-unexecuted instruction in the ring-0 handler.
            context.yielded = true;
            0
        } else { u32::from(context.emulate(&mut frame, address)) };
    if handled != 0 && frame.read(frame.flags_offset()) & 0x100 != 0 {
        context.stepped = true;
        0
    } else { handled }
}

/// Resident device I/O which neither remaps the aperture nor blocks. Other
/// instructions, stepping and a busy audio worker retain the normal monitor.
#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
unsafe extern "C" fn device_io(pointer: *mut u8, wide: u32, _: u32) -> u32 {
    let context = unsafe { &mut *ACTIVE.cast::<Context<'_>>() };
    let mut frame = Frame { pointer, wide: wide != 0 };
    let flags = frame.read(frame.flags_offset());
    if flags & 0x100 != 0 || flags & (3 << 19) == 3 << 19 { return 0; }
    context.set_code(frame.cs(), frame.vm86());
    let ip = frame.ip();
    let Some(address) = context.fast.code_base.checked_add(ip) else { return 0 };
    if ip > context.fast.code_limit { return 0; }
    let code = core::ptr::with_exposed_provenance::<u8>(address as usize);
    let mut opcode = unsafe { code.read_volatile() };
    let mut length = 1;
    let mut operand32 = context.fast.default32 != 0;
    if opcode == 0x66 {
        if ip == context.fast.code_limit { return 0; }
        opcode = unsafe { code.wrapping_add(1).read_volatile() };
        operand32 = !operand32;
        length = 2;
    }
    let now = crate::kernel::portio::now_ns();
    if now >= context.pit_deadline {
        // A normal I/O exit does not resample the event-loop clock. Latch
        // the edge here before falling back, so the completed I/O can be
        // followed by IRQ delivery without waiting for a host clock tick.
        // Keep the original instruction/event intact, including when IF=0:
        // the PIC must remember the edge until interrupts are enabled.
        super::machine::pit_io(context.pit, context.pic, now, |_| ());
        context.pit_deadline = context.pit.irq_deadline_ns();
        return 0;
    }
    if crate::kernel::media::GUEST_MEMORY.reader_requested() { return 0; }
    if crate::kernel::media::inline_video_due() { return 0; }
    let port = if matches!(opcode, 0xe4 | 0xe6) {
        if ip.checked_add(length).is_none_or(|end| end > context.fast.code_limit) { return 0; }
        let immediate = unsafe { code.wrapping_add(length as usize).read_volatile() };
        length += 1;
        opcode += 8; // immediate-port byte IN/OUT → their DX-port opcodes
        u16::from(immediate)
    } else { frame.read(16) as u16 };
    match (opcode, port) {
        (0xec, 0..=7 | 0xc0..=0xcf) | (0xee, 0x0c | 0xd8) => {
            // Never wait for core 1 while trapping a guest instruction.
            // Both paths use the same DMA latch and source-consumption cursor.
            let Some(mut audio) = context.audio.try_lock() else { return 0 };
            // The ordinary event loop transfers worker-raised device IRQs
            // into the PIC before reentering the guest. Do not keep retiring
            // polling instructions while that transfer is pending.
            if audio.pending_irqs != 0 { return 0; }
            let write = (opcode == 0xee).then_some(frame.read(0) as u8);
            let Some(value) = audio.sb.dma_poll(context.dma, port, write, now) else { return 0 };
            if write.is_none() { unsafe { pointer.write(value); } }
        }
        (0xec, 0x3da) => {
            let status = context.state.beam(now).status;
            context.state.ac_state.pending_data = false;
            unsafe { pointer.write(status); }
        }
        (0xee, 0x3c4 | 0x3c5) | (0xef, 0x3c4) => {
            if opcode == 0xef && operand32 { return 0; }
            if !mask_out(context.state, port, frame.read(0) as u16, opcode == 0xef) { return 0; }
            context.fast.plane_mask = u32::from(context.state.seq.get(2) & 15);
            super::machine::vga::scanout_changed();
        }
        _ => return 0,
    }
    frame.advance_ip(length, context.fast.default32 != 0);
    1
}

/// Register selection needs no remap. Mask data is safe only in sequential
/// planar addressing: chain-4 and odd/even can switch to a direct aperture.
#[cfg(any(target_arch = "x86", test))]
fn mask_out(state: &mut ::vga::LegacyVgaState, port: u16, value: u16, word: bool) -> bool {
    match (port, word) {
        (0x3c4, false) => state.seq_index = value as u8,
        (0x3c4, true) if value & 31 == 2 && state.seq.get(4) & 12 == 4 => {
            state.seq_index = value as u8;
            state.seq.set(2, (value >> 8) as u8);
        }
        (0x3c5, false) if state.seq_index & 31 == 2 && state.seq.get(4) & 12 == 4 => {
            state.seq.set(2, value as u8);
        }
        _ => return false,
    }
    true
}

#[cfg(target_arch = "x86")]
impl Context<'_> {
    fn set_code(&mut self, cs: u16, vm86: bool) {
        use super::mode_transitions as segments;
        self.fast.cs_mode = u32::from(cs) | if vm86 { 0 } else { 1 << 20 };
        self.fast.default32 = u32::from(!vm86 && segments::seg_is_32(self.ldt, cs));
        self.fast.decode = if self.fast.default32 != 0 { DECODE32.as_ptr() } else { DECODE16.as_ptr() } as u32;
        self.fast.code_base = if vm86 { u32::from(cs) << 4 } else { segments::seg_base(self.ldt, cs) };
        self.fast.code_limit = if vm86 { 0xffff } else { segments::seg_limit(self.ldt, cs) };
    }
    fn emulate(&mut self, frame: &mut Frame, address: u32) -> bool {
        use super::{machine::mmio, mode_transitions as segments};
        let vm86 = frame.vm86();
        self.set_code(frame.cs(), vm86);
        let (ds, es) = frame.selectors();
        let ds = if vm86 { u32::from(ds) << 4 } else { segments::seg_base(self.ldt, ds) };
        let es = if vm86 { u32::from(es) << 4 } else { segments::seg_base(self.ldt, es) };
        let (base, cs, default32) = (self.base, self.fast.code_base, self.fast.default32 != 0);
        let (ss, fs, gs) = frame.other_selectors();
        let segment = |sel| if vm86 { u32::from(sel) << 4 } else { segments::seg_base(self.ldt, sel) };
        let bases = [es, cs, segment(ss), ds, segment(fs), segment(gs)];
        mmio::emulate(self, &mut frame.operands(), cs, default32, &bases, address - base)
    }

}

#[cfg(target_arch = "x86")]
impl super::machine::mmio::FaultBus for Context<'_> {
    fn read8(&mut self, off: u32) -> u8 {
        let planes = unsafe { ::vga::memory::Memory::mapped(self.planes, super::machine::vga::PLANES_LEN) };
        super::machine::vga::vram_read_live(planes, self.state, off)
    }
    fn write8(&mut self, off: u32, value: u8) {
        let planes = unsafe { ::vga::memory::Memory::mapped(self.planes, super::machine::vga::PLANES_LEN) };
        super::machine::vga::vram_write_live(planes, self.state, off, value);
    }
    fn offset(&self, address: u32) -> Option<u32> {
        (self.base..self.end).contains(&address).then(|| address - self.base)
    }
    fn guest_read(&self, address: u32) -> u8 { unsafe { core::ptr::with_exposed_provenance::<u8>(address as usize).read_volatile() } }
    fn guest_write(&mut self, address: u32, value: u8) { unsafe { core::ptr::with_exposed_provenance_mut::<u8>(address as usize).write_volatile(value); } }
    fn fpu_st0(&self) -> [u8; 10] {
        let mut value = [0; 10];
        unsafe { core::arch::asm!("fstp tbyte ptr [{p}]", "fld tbyte ptr [{p}]", p = in(reg) value.as_mut_ptr(), options(nostack)); }
        value
    }
    fn fpu_pop(&mut self) { unsafe { core::arch::asm!("fstp st(0)", options(nostack)); } }
}

#[cfg(test)]
mod tests {
    use super::{Frame, HASH, PREFIXES, OPCODES, DECODE16, DECODE32};

    #[test]
    fn fast_mask_writes_match_register_file_and_reject_remaps() {
        for memory_mode in [0, 4, 8, 12] {
            for (port, value, word) in [
                (0x3c4, 2, false), (0x3c4, 3, false),
                (0x3c4, 0x0402, true), (0x3c4, 0x0822, true),
                (0x3c4, 0x0404, true), (0x3c5, 8, false),
                (0x3c5, 0x0402, true),
            ] {
                let mut actual = ::vga::LegacyVgaState::new_boxed();
                let mut expected = ::vga::LegacyVgaState::new_boxed();
                for state in [&mut actual, &mut expected] {
                    state.seq.set(4, memory_mode);
                    state.seq_index = 2;
                }
                let before = actual.cpu_aperture();
                let handled = super::mask_out(&mut actual, port, value, word);
                if handled {
                    expected.port_write(port, value as u8);
                    if word { expected.port_write(port + 1, (value >> 8) as u8); }
                }
                assert_eq!(actual.seq_index, expected.seq_index);
                assert_eq!(actual.seq.read(), expected.seq.read());
                assert_eq!(actual.cpu_aperture(), before);
                assert_eq!(handled, port == 0x3c4 && !word
                    || memory_mode == 4 && (port == 0x3c5 && !word
                        || port == 0x3c4 && word && value & 31 == 2));
            }
        }
    }

    #[test]
    fn input_preserves_registers_and_wraps_the_native_ip() {
        for wide in [false, true] {
            for default32 in [false, true] {
                let mut words = [0xdeadbeefu32; 40];
                let mut frame = Frame { pointer: words.as_mut_ptr().cast(), wide };
                frame.set_ip(0xffff);
                let before = words;
                unsafe { frame.pointer.write(9); }
                frame.advance_ip(2, default32);
                assert_eq!(frame.read(0), 0xdeadbe09);
                assert_eq!(frame.ip(), if default32 { 0x10001 } else { 1 });
                for i in 1..words.len() {
                    if i != frame.ip_offset() / 4 { assert_eq!(words[i], before[i]); }
                }
            }
        }
    }

    #[test]
    fn static_tables_cover_every_supported_header_without_population() {
        for (default32, table) in [(false, &DECODE16), (true, &DECODE32)] {
            for first in 0..=255u8 {
                for second in 0..=255u8 {
                    let prefixed = PREFIXES[1..].contains(&first);
                    let key = u32::from(first) | if prefixed { u32::from(second) << 8 } else { 0 };
                    let slot = (key.wrapping_mul(HASH) >> 26) as usize * 2;
                    let hit = table[slot..slot + 2].iter().find(|entry|
                        **entry >> 16 != 0 && **entry & 65535 == key);
                    let opcode = if prefixed { second } else { first };
                    assert_eq!(hit.is_some(), OPCODES.contains(&opcode));
                    if let Some(entry) = hit {
                        let recipe = entry >> 16;
                        let op32 = default32 ^ (first == 0x66);
                        assert_eq!(recipe & 7, if opcode & 1 == 0 { 1 } else if op32 { 4 } else { 2 });
                        assert_eq!(recipe & 8 != 0, default32 ^ (first == 0x67));
                        assert_eq!(recipe & 16 != 0, matches!(opcode, 0xc6 | 0xc7));
                        assert_eq!(recipe & 32 != 0, matches!(opcode, 0xa2 | 0xa3));
                        assert_eq!(recipe & 64 != 0, prefixed);
                    }
                }
            }
        }
    }

    #[test]
    fn common_gpr_slots_preserve_odd_halves_and_return_frame() {
        for wide in [false, true] {
            let mut words = [0xdeadbeefu32; 40];
            for i in 0..8 { words[4 + 2 * i] = 0x12345600 + i as u32; }
            let mut frame = Frame { pointer: unsafe { words.as_mut_ptr().add(4).cast() }, wide };
            frame.set_ip(0x2345);
            let flags = frame.flags_offset() / 4 + 4;
            words[flags] = 0x202;
            let before = words;
            assert_eq!(frame.cs(), 0xbeef);
            assert!(!frame.vm86());
            assert_eq!(frame.selectors(), (0xbeef, 0xbeef));
            for i in 0..8 { assert_eq!(frame.register(i, 4), 0x12345600 + u32::from(i)); }
            assert_eq!(frame.register(4, 1), 0x56);
            {
                let mut regs = frame.operands();
                regs.set(4, 1, 0xab); // AH
                regs.set(7, 2, 0x4321); // DI
                regs.set(1, 4, 17); // ECX
                *regs.ip += 3;
                *regs.flags |= 1;
            }
            assert_eq!(frame.register(0, 4), 0x1234ab00);
            assert_eq!(frame.register(7, 4), 0x12344321);
            assert_eq!(frame.register(1, 4), 17);
            assert_eq!(frame.ip(), 0x2348);
            assert_eq!(frame.read(frame.flags_offset()), 0x203);
            for i in 0..8 { assert_eq!(words[4 + 2 * i + 1], if i == 1 { 0 } else { before[4 + 2 * i + 1] }); }
        }
    }
}
