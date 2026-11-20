//! Frame layout and in-place conversion for the shared x86 entry assembly.
//! No interrupt dispatch, paging, allocation, or virtual-interrupt policy.

use crate::Regs;

/// Hybrid 32-bit entry layout. Assembly saves the segments and general
/// registers in the low halves of their canonical `Regs` slots, then leaves a
/// 28-byte expansion gap before the native dword interrupt/IRET tail. Rust
/// widens only that tail for cross-privilege entries. Same-ring ring-0 entries
/// return before widening and therefore never inspect the absent ESP/SS.
///
/// VM86 segs (es, ds, fs, gs) the CPU pushes above the IRET frame for VM86
/// entries are *not* part of `Raw32` — they form the second component of the
/// 32-bit `StackFrame` arm `Frame32`, valid only when EFLAGS.VM is
/// set on entry/exit.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Raw32 {
    pub gs: u64, pub fs: u64, pub es: u64, pub ds: u64,
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub edi: u64, pub esi: u64, pub ebp: u64, pub esp_dummy: u64,
    pub ebx: u64, pub edx: u64, pub ecx: u64, pub eax: u64,
    pub _expand: [u8; 28],
    pub int_num: u32, pub err_code: u32,
    pub eip: u32, pub cs: u32, pub eflags: u32, pub esp: u32, pub ss: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_call_updates_results_without_touching_the_return_frame() {
        let mut regs = Regs::empty();
        regs.frame.rip = 0x12345678;
        regs.frame.rsp = 0x87654321;
        regs.frame.cs = 0x19;
        regs.frame.ss = 0x21;
        regs.frame.rflags = 0x202;
        regs.rbp = 0xabcdef;
        regs.r8 = 0x123456789;
        regs.rax = 0x100;
        regs.rdx = 0xfeed;
        let mut call = KernelCall::from_regs(&regs);
        assert_eq!(call.rax, 0x100);
        assert_eq!(call.rdx, 0xfeed);
        call.rax = 7;
        call.rdx = 0xabcdef0123456789;
        call.write_result(&mut regs);
        assert_eq!(regs.rax, 7);
        assert_eq!(regs.rdx, 0xabcdef0123456789);
        assert_eq!(regs.frame.rip, 0x12345678);
        assert_eq!(regs.frame.rsp, 0x87654321);
        assert_eq!(regs.frame.cs, 0x19);
        assert_eq!(regs.frame.ss, 0x21);
        assert_eq!(regs.frame.rflags, 0x202);
        assert_eq!(regs.rbp, 0xabcdef);
        assert_eq!(regs.r8, 0x123456789);
    }

    #[test]
    fn compact_frame_round_trip_and_edit() {
        for vm86 in [false, true] {
            let mut expected = Regs::empty();
            expected.rax = 0x12345678;
            expected.rdi = 0xabcdef01;
            expected.ds = 0x1234;
            expected.es = 0x2345;
            expected.fs = 0x3456;
            expected.gs = 0x4567;
            expected.int_num = 0x80;
            expected.err_code = 0x42;
            expected.frame = crate::Frame64 {
                rip: 0x123456, cs: 0x23, rflags: 2 | if vm86 { 1 << 17 } else { 0 },
                rsp: 0xabcdef, ss: 0x2b,
            };
            let mut frame: StackFrame = unsafe { core::mem::zeroed() };
            frame.regs = expected;
            unsafe {
                frame.decanonicalize(false);
                assert_eq!(frame.raw32.raw.eip, 0x123456);
                assert_eq!(frame.raw32.raw.esp, 0xabcdef);
                if vm86 {
                    assert_eq!(frame.raw32.raw.ds, 0);
                    assert_eq!(frame.raw32.vm86.ds, 0x1234);
                }
                frame.raw32.raw.int_num = 0xffffff80;
                let regs = frame.canonicalize(false);
                assert_eq!(regs.int_num, 0x80);
                assert_eq!(regs.err_code, 0x42);
                assert_eq!(regs.rax, expected.rax);
                assert_eq!(regs.rdi, expected.rdi);
                assert_eq!([regs.ds, regs.es, regs.fs, regs.gs],
                    [expected.ds, expected.es, expected.fs, expected.gs]);
                assert_eq!(regs.frame.rflags, expected.frame.rflags);
                regs.frame.rip += 2;
                regs.gs = 0x5678;
                frame.decanonicalize(false);
                assert_eq!(frame.raw32.raw.eip, 0x123458);
                let regs = frame.canonicalize(false);
                assert_eq!(regs.gs, 0x5678);
                assert_eq!(regs.frame.rsp, expected.frame.rsp);
            }
        }
    }

    #[test]
    fn narrow_entry_initializes_unsaved_slots_only_during_canonicalization() {
        // Model stack residue in every byte not written by 32-bit assembly.
        let mut frame = core::mem::MaybeUninit::<StackFrame>::uninit();
        unsafe {
            frame.as_mut_ptr().cast::<u8>().write_bytes(0xa5, core::mem::size_of::<StackFrame>());
            let stack = frame.as_mut_ptr();
            let raw = &raw mut (*stack).raw32.raw;
            macro_rules! low { ($field:ident, $value:expr) => {
                (&raw mut (*raw).$field).cast::<u32>().write($value);
            }; }
            // Segment-register moves need only supply the selector bits.
            low!(gs, 0xa5a50033); low!(fs, 0xa5a50043);
            low!(es, 0xa5a5002b); low!(ds, 0xa5a5002b);
            low!(edi, 1); low!(esi, 2); low!(ebp, 3); low!(ebx, 4);
            low!(edx, 5); low!(ecx, 6); low!(eax, 0x87654321);
            (*raw).int_num = 0xffffff80; (*raw).err_code = 0;
            (*raw).eip = 0x1234; (*raw).cs = 0x23; (*raw).eflags = 0x202;
            (*raw).esp = 0x12345678; (*raw).ss = 0x2b;
            let regs = (*stack).canonicalize(false);
            assert_eq!(regs.rax, 0x87654321);
            assert_eq!([regs.rdi, regs.rsi, regs.rbp, regs.rbx, regs.rdx, regs.rcx], [1, 2, 3, 4, 5, 6]);
            assert_eq!([regs.gs, regs.fs, regs.es, regs.ds], [0x33, 0x43, 0x2b, 0x2b]);
            assert_eq!([regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15], [0; 8]);
            assert_eq!(regs.rsp_dummy, 0);
            assert_eq!(regs.int_num, 0x80);
            assert_eq!(regs.frame.rsp, 0x12345678);
            assert_eq!(regs.frame.rip, 0x1234);
            (*stack).decanonicalize(false);
            assert_eq!((*raw).eip, 0x1234);
            assert_eq!((*raw).eax, 0x87654321);
        }
    }

    #[test]
    fn wide_frame_preserves_full_addresses_and_syscall_sentinel() {
        let mut frame: StackFrame = unsafe { core::mem::zeroed() };
        let mut regs = Regs::empty();
        regs.frame.rip = 0x7fff12345678;
        regs.frame.rsp = 0x7fff87654321;
        regs.fs = 0x7fffabcd0000;
        regs.int_num = 256;
        frame.regs = regs;
        unsafe {
            assert_eq!(frame.canonicalize(true).int_num, 256);
            frame.decanonicalize(true);
            assert_eq!(frame.regs.frame.rip, regs.frame.rip);
            assert_eq!(frame.regs.frame.rsp, regs.frame.rsp);
            assert_eq!(frame.regs.fs, regs.fs);
            frame.regs.int_num = 0xfffffffffffffffe;
            assert_eq!(frame.canonicalize(true).int_num, 254);
        }
    }
}

/// 4 VM86 segment selectors the CPU pushes above the IRET frame on a VM86
/// trap. Bytes are valid only when EFLAGS.VM is set on entry/exit; otherwise
/// kernel-stack residue.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vm86Segs {
    pub es: u32, pub ds: u32, pub fs: u32, pub gs: u32,
}

/// Explicit C layout: the optional VM86 words immediately follow Raw32.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame32 {
    pub raw: Raw32,
    pub vm86: Vm86Segs,
}

/// Stack-side view of a saved interrupt frame. Two arms: `regs` is the
/// canonical 64-bit form (216B); the 32-bit arm is `Frame32` — its
/// 216-byte hybrid slot plus the optional VM86 seg tail. `isr_handler` picks
/// the live arm via `from_64`.
///
/// Storage must cover the selected frame and the VM86 tail when present.
/// Native stacks reserve space above their IRET frame; KVM uses its mapped
/// supervisor stack. Same-ring 32-bit traps must bypass canonicalization.
#[repr(C)]
pub union StackFrame {
    pub regs: Regs,
    pub raw32: Frame32,
}

const _: () = {
    assert!(core::mem::offset_of!(Frame32, vm86) == 216);
    assert!(core::mem::size_of::<Raw32>() == core::mem::size_of::<Regs>());
    assert!(core::mem::offset_of!(Raw32, int_num) == 188);
    assert!(core::mem::offset_of!(Raw32, cs) == 200);
    assert!(core::mem::offset_of!(Raw32, gs) == core::mem::offset_of!(Regs, gs));
    assert!(core::mem::offset_of!(Raw32, edi) == core::mem::offset_of!(Regs, rdi));
    assert!(core::mem::offset_of!(Raw32, eax) == core::mem::offset_of!(Regs, rax));
};


impl StackFrame {
    /// Canonicalize a cross-privilege frame without moving its register prefix.
    ///
    /// # Safety
    /// `wide` selects the live assembly layout. A 32-bit frame must include
    /// SS:ESP; a VM86 frame must also include the four segment words.
    pub unsafe fn canonicalize(&mut self, wide: bool) -> &mut Regs {
        if !wide {
            // Assembly (and the pre-canonicalization hook) only stores live
            // dwords. Initialize the rest here, after the hook has declined.
            let prefix = self as *mut Self as *mut u32;
            for slot in 0..20 {
                unsafe { prefix.add(slot * 2 + 1).write(0); }
                if slot < 4 {
                    // Only the selector's low 16 bits are meaningful.
                    let word = unsafe { prefix.add(slot * 2) };
                    unsafe { word.write(u32::from(word.cast::<u16>().read())); }
                } else if (4..12).contains(&slot) || slot == 15 {
                    unsafe { prefix.add(slot * 2).write(0); }
                }
            }
            let raw = unsafe { &self.raw32.raw };
            let (vector, error, ip, cs, flags, sp, ss) =
                (raw.int_num, raw.err_code, raw.eip, raw.cs, raw.eflags, raw.esp, raw.ss);
            let vm = if flags & (1 << 17) != 0 { Some(unsafe { self.raw32.vm86 }) } else { None };
            let regs = unsafe { &mut self.regs };
            regs.int_num = vector as u64;
            regs.err_code = error as u64;
            regs.frame = crate::Frame64 { rip: ip as u64, cs: cs as u64,
                rflags: flags as u64, rsp: sp as u64, ss: ss as u64 };
            if let Some(vm) = vm {
                regs.es = vm.es as u64; regs.ds = vm.ds as u64;
                regs.fs = vm.fs as u64; regs.gs = vm.gs as u64;
            }
        }
        let regs = unsafe { &mut self.regs };
        // PUSH imm8 sign-extends vectors 128..255. SYSCALL uses sentinel 256.
        if regs.int_num != 256 { regs.int_num &= 255; }
        regs
    }

    /// Convert canonical registers to the layout consumed by the IRET path.
    ///
    /// # Safety
    /// The canonical arm must be initialized. Storage must include the VM86
    /// tail if the destination flags request VM86.
    pub unsafe fn decanonicalize(&mut self, wide: bool) {
        if wide { return; }
        let regs = unsafe { self.regs };
        let vm = regs.frame.rflags & (1 << 17) != 0;
        let raw = unsafe { &mut self.raw32.raw };
        if vm { raw.gs = 0; raw.fs = 0; raw.es = 0; raw.ds = 0; }
        raw.int_num = regs.int_num as u32;
        raw.err_code = regs.err_code as u32;
        raw.eip = regs.frame.rip as u32;
        raw.cs = regs.frame.cs as u32;
        raw.eflags = regs.frame.rflags as u32;
        raw.esp = regs.frame.rsp as u32;
        raw.ss = regs.frame.ss as u32;
        if vm {
            self.raw32.vm86 = Vm86Segs { es: regs.es as u32, ds: regs.ds as u32,
                fs: regs.fs as u32, gs: regs.gs as u32 };
        }
    }
}

/// Kernel-call arguments and results, independent of the caller's CPU frame.
/// Fixed-width C layout is identical in the 64-bit host and 32-bit supervisor.
/// Address-valued arguments name supervisor-accessible storage, not host pointers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KernelCall {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
}

impl KernelCall {
    pub fn from_regs(regs: &Regs) -> Self {
        Self { rax: regs.rax, rbx: regs.rbx, rcx: regs.rcx,
            rdx: regs.rdx, rsi: regs.rsi, rdi: regs.rdi }
    }

    pub fn write_result(self, regs: &mut Regs) {
        regs.rax = self.rax;
        regs.rbx = self.rbx;
        regs.rcx = self.rcx;
        regs.rdx = self.rdx;
        regs.rsi = self.rsi;
        regs.rdi = self.rdi;
    }
}

/// Only Execute may leave kernel request processing for the guest IRET path.
#[must_use]
pub enum CallOutcome {
    Complete,
    Execute,
}

const _: () = {
    assert!(core::mem::size_of::<KernelCall>() == 48);
    assert!(core::mem::offset_of!(KernelCall, rdx) == 24);
    assert!(core::mem::offset_of!(KernelCall, rdi) == 40);
};
