//! Record planar VGA accesses without decoding an instruction on every fault.

/// One execution of a cached instruction. `reg` is its captured GPR value;
/// instructions with an immediate operand ignore it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Store {
    pub address: u32,
    pub reg: u32,
    pub ins_id: u16,
}

const EMPTY: Store = Store { address: 0, reg: 0, ins_id: 0 };

#[repr(C)]
pub struct Batch {
    buf: [Store; 256],
    len: u32,
}

impl Batch {
    pub const fn new() -> Self { Self { buf: [EMPTY; 256], len: 0 } }
    #[cfg(test)]
    pub fn push(&mut self, store: Store) -> bool {
        if self.len == 256 { return false; }
        self.buf[self.len as usize] = store;
        self.len += 1;
        true
    }
    pub fn drain(&mut self) -> impl Iterator<Item = Store> + '_ {
        let len = core::mem::replace(&mut self.len, 0) as usize;
        self.buf[..len].iter().copied()
    }
}

// Code mode is learned by the normal decoder and valid until a descriptor
// changes. PROTECTED distinguishes selectors from VM86 segment values.
const PROTECTED: u32 = 1 << 20;
const CODE32: u32 = 1 << 22;

/// CS:IP + mode identifies the instruction; code bytes detect self-modification.
/// `address` caches its linear address, and `len` lets the handler advance IP.
#[repr(C)]
#[derive(Clone, Copy)]
struct Identity {
    ip: u32,
    cs_mode: u32,
    code: [u8; 8],
    address: u32,
    len: u8,
}

/// Nothing about the operation is decoded in the fast handler. It only needs
/// an identity and a GPR to capture (x86 encoding 0..7, or 255 for no GPR).
#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct Instruction {
    identity: Identity,
    gpr_index: u8,
}

const NO_INSTRUCTION: Instruction = Instruction {
    identity: Identity { ip: u32::MAX, cs_mode: 0, code: [0; 8], address: 0, len: 0 },
    gpr_index: 255,
};

#[repr(C)]
pub struct FastWrites {
    instructions: [Instruction; 64],
    pub batch: Batch,
}

impl FastWrites {
    pub const fn new() -> Self {
        Self { instructions: [NO_INSTRUCTION; 64], batch: Batch::new() }
    }
    /// Descriptor edits or replacement invalidate all instruction identities.
    /// The pending batch has already been drained before either can happen.
    pub fn clear(&mut self) {
        debug_assert_eq!(self.batch.len, 0);
        self.instructions.fill(NO_INSTRUCTION);
    }
    pub(super) fn remember(&mut self, regs: &crate::Regs, code_base: u32, default32: bool,
        code: [u8; 8], gpr_index: u8, instruction_len: u8) {
        // Every exit drains the batch before the normal decoder replaces an
        // instruction entry, so queued ins_ids remain valid until processed.
        debug_assert_eq!(self.batch.len, 0);
        if regs.err_code & !1 != 6 || regs.frame.rflags & 0x100 != 0
            || regs.mode() == crate::UserMode::Mode64 || instruction_len > 8 { return; }
        let mode = if regs.mode() == crate::UserMode::VM86 { 0 }
            else { PROTECTED | if default32 { CODE32 } else { 0 } };
        let cs_mode = u32::from(regs.code_seg()) | mode;
        let ip = if default32 { regs.ip32() } else { regs.ip32() & 0xffff };
        let address = code_base.wrapping_add(ip);
        if address & 0xfff > 0xff8 || (!default32 && ip > 0xfff8) { return; }
        self.instructions[((ip ^ cs_mode) & 63) as usize] = Instruction {
            identity: Identity { ip, cs_mode, code, address, len: instruction_len },
            gpr_index,
        };
    }
    /// Decode operands from the saved instruction bytes when applying a batch,
    /// rather than carrying width/immediate/high-byte metadata through assembly.
    pub fn drain(&mut self) -> impl Iterator<Item = (u32, u32, u8)> + '_ {
        let instructions = &self.instructions;
        self.batch.drain().map(move |store| {
            let id = &instructions[usize::from(store.ins_id)].identity;
            let (value, bytes) = super::machine::mmio::deferred_store(
                &id.code[..usize::from(id.len)], id.cs_mode & CODE32 != 0, store.reg);
            (store.address, value, bytes)
        })
    }
}

impl Default for FastWrites { fn default() -> Self { Self::new() } }

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn planar_page_fault_32();
    fn planar_page_fault_64();
}

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
static mut PLANAR_FAST_WRITES: *mut FastWrites = core::ptr::null_mut();

#[cfg(target_arch = "x86")]
pub unsafe fn install<A: crate::Arch>(machine: &mut A, writes: &mut FastWrites) -> arch_abi::InterruptHandlers {
    unsafe {
        core::ptr::write_volatile(&raw mut PLANAR_FAST_WRITES, writes);
        machine.replace_interrupt_handlers(14, arch_abi::InterruptHandlers {
            entry32: planar_page_fault_32 as *const () as u32,
            entry64: planar_page_fault_64 as *const () as u64,
        })
    }
}

#[cfg(target_arch = "x86")]
pub unsafe fn uninstall<A: crate::Arch>(machine: &mut A, previous: arch_abi::InterruptHandlers) {
    unsafe {
        machine.replace_interrupt_handlers(14, previous);
        core::ptr::write_volatile(&raw mut PLANAR_FAST_WRITES, core::ptr::null_mut());
    }
}

const _: () = {
    assert!(core::mem::size_of::<Store>() == 12);
    assert!(core::mem::offset_of!(Store, reg) == 4);
    assert!(core::mem::offset_of!(Store, ins_id) == 8);
    assert!(core::mem::offset_of!(Batch, len) == 3072);
    assert!(core::mem::size_of::<Instruction>() == 32);
    assert!(core::mem::offset_of!(Identity, cs_mode) == 4);
    assert!(core::mem::offset_of!(Identity, code) == 8);
    assert!(core::mem::offset_of!(Identity, address) == 16);
    assert!(core::mem::offset_of!(Identity, len) == 20);
    assert!(core::mem::offset_of!(Instruction, gpr_index) == 24);
    assert!(core::mem::offset_of!(FastWrites, batch) == 2048);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_preserves_order_and_resets_after_drain() {
        let mut batch = Batch::new();
        for address in 0..256 { assert!(batch.push(Store { address, ..EMPTY })); }
        assert!(!batch.push(EMPTY));
        for (address, store) in batch.drain().enumerate() { assert_eq!(store.address, address as u32); }
        assert!(batch.drain().next().is_none());
        assert!(batch.push(Store { address: 123, ..EMPTY }));
        assert_eq!(batch.drain().next().unwrap().address, 123);
    }

    #[test]
    fn identities_bind_cs_ip_mode_and_clear_on_descriptor_changes() {
        let code = [0x89, 7, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let admit = |writes: &mut FastWrites, regs: &crate::Regs, base, default32| {
            writes.remember(regs, base, default32, code, 0, 2);
        };
        let mut regs = crate::Regs::empty();
        regs.err_code = 6;
        regs.frame.cs = 15;
        regs.frame.rip = 0x100;
        let mut writes = FastWrites::new();
        let slot = (0x100 ^ 15) & 63;
        admit(&mut writes, &regs, 0x12000, false);
        assert_eq!(writes.instructions[slot].identity.cs_mode, 15 | PROTECTED);
        assert!(writes.batch.push(Store { address: 0xa0123, reg: 0x12345678, ins_id: slot as u16 }));
        assert_eq!(writes.drain().next(), Some((0xa0123, 0x12345678, 2)));
        admit(&mut writes, &regs, 0x12000, true);
        assert_eq!(writes.instructions[slot].identity.cs_mode, 15 | PROTECTED | CODE32);
        assert_eq!(writes.instructions[slot].gpr_index, 0);
        assert!(writes.batch.push(Store { address: 0xa0123, reg: 0x12345678, ins_id: slot as u16 }));
        assert_eq!(writes.drain().next(), Some((0xa0123, 0x12345678, 4)));
        // Base, limit, access and mode edits all invalidate the same cache.
        writes.clear();
        assert!(writes.instructions.iter().all(|entry| entry.identity.ip == u32::MAX));
        regs.frame.rflags = 1 << 17;
        regs.frame.cs = 0x1234;
        admit(&mut writes, &regs, 0x12340, false);
        let slot = (0x100 ^ 0x1234) & 63;
        assert_eq!(writes.instructions[slot].identity.cs_mode, 0x1234);
        assert_eq!(writes.instructions[slot].identity.address, 0x12440);
        regs.frame.cs = 0x2234;
        admit(&mut writes, &regs, 0x22340, false);
        assert_eq!(writes.instructions[slot].identity.cs_mode, 0x2234);
        assert_eq!(writes.instructions[slot].identity.address, 0x22440);
    }
}
