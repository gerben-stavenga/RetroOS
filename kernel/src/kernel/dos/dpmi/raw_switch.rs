use arch_abi::GuestBytes;
use super::*;
use crate::arch::Vcpu;
use super::super::mode_transitions;

/// Raw mode switch PM→real. Called via unified stub slot SLOT_PM_TO_REAL.
/// AX has the new DS directly because the stub is `CD 31`.
///
/// Register convention (set by caller before CALL FAR):
///   AX = new real-mode DS
///   CX = new real-mode ES
///   DX = new real-mode SS
///   BX = new real-mode SP
///   SI = new real-mode CS
///   DI = new real-mode IP
fn raw_switch_pm_to_real(_dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_sp = regs.rbx as u16;
    let new_cs = regs.rsi as u16;
    let new_ip = regs.rdi as u16;

    regs.frame.rflags |= (machine::VM_FLAG | machine::VIF_FLAG) as u64;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_ip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_sp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    dos_trace!("[DPMI] raw PM->RM {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        new_cs, new_ip, new_ss, new_sp);
    thread::KernelAction::Done
}

/// Dispatch INT 31h that came from the special-stub segment. Host-
/// initiated return trampolines, entry points, and the PMDOS INT 21
/// short-circuit live here.
/// Slot = (EIP - STUB_BASE - 2) / 2.
pub(in crate::kernel::dos) fn pm_stub_dispatch(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let eip = regs.ip32();
    let stub_base = dos::STUB_BASE;
    let slot = ((eip.wrapping_sub(stub_base + 2)) / 2) as u8;
    // Skip the slot trace for PMDOS INT 21 character-output AHs to keep
    // the exception-handler dump and CRT printf output readable in the log.
    let pmdos_chatty = slot == dos::SLOT_PMDOS_INT21
        && matches!((regs.rax >> 8) as u8, 0x02 | 0x06 | 0x09);
    if !pmdos_chatty {
        dos_trace!("[DPMI] STUB slot={:#04x} EIP={:#x}", slot, eip);
    }

    match slot {
        dos::SLOT_PMDOS_INT21 => {
            super::super::dosabi::pmdos_int21_handler(machine, kt, dos, regs)
        }
        dos::SLOT_PMDOS_INT33 => {
            super::super::dosabi::pmdos_int33_handler(dos, regs)
        }
        dos::SLOT_EXCEPTION_RET => {
            exception_return(dos, regs, ExcReturnVia::V09)
        }
        dos::SLOT_EXCEPTION_RET_V10 => {
            exception_return(dos, regs, ExcReturnVia::V10)
        }
        dos::SLOT_PM_TO_REAL => {
            raw_switch_pm_to_real(dos, regs)
        }
        dos::SLOT_RESUME_CONTINUATION => {
            mode_transitions::resume_continuation_from_stub(dos, regs);
            thread::KernelAction::Done
        }
        dos::SLOT_MOUSE_CB_RET => {
            // PM INT 33h AX=0Ch handler FAR-RETurned into this trampoline.
            // Restore the bracket-saved GP regs and unwind the callback.
            super::super::dosabi::mouse_callback_return(dos, regs);
            thread::KernelAction::Done
        }
        dos::SLOT_SAVE_RESTORE => {
            // No state to save: AX=0305 announces buffer size = 0, so the
            // procedure is a NOP per the spec (matches CWSDPMI's STUB_NOP).
            // We only need to pop the far-call return frame and resume.
            //
            // Frame size depends on the client's operand size: 16-bit CALL
            // FAR pushed IP+CS as 4 bytes; 32-bit CALL FAR pushed EIP+CS
            // as 8 bytes.
            let dpmi = dos.dpmi.as_ref().unwrap();
            let use32 = dpmi.client_use32;
            let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
            let ss_32 = seg_is_32(&dos.ldt[..], regs.stack_seg());
            let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
            let (ret_eip, ret_cs, frame_size) = if use32 {
                let eip = regs.read::<u32>((ss_base.wrapping_add(sp)) as usize);
                let cs = regs.read::<u32>((ss_base.wrapping_add(sp + 4)) as usize);
                (eip, cs, 8u32)
            } else {
                let ip = regs.read::<u16>((ss_base.wrapping_add(sp)) as usize) as u32;
                let cs = regs.read::<u16>((ss_base.wrapping_add(sp + 2)) as usize) as u32;
                (ip, cs, 4u32)
            };
            let new_sp = sp.wrapping_add(frame_size);
            if ss_32 { regs.set_sp32(new_sp); }
            else { let cur = regs.sp32(); regs.set_sp32((cur & !0xFFFF) | (new_sp & 0xFFFF)); }
            regs.set_ip32(ret_eip);
            regs.set_cs32(ret_cs);
            thread::KernelAction::Done
        }
        _ => panic!("pm_stub_dispatch: unhandled slot {:#04x}", slot),
    }
}

/// Real-to-PM raw mode switch.
/// Called from rm_int31_dispatch when VM86 code executes `CALL FAR` to
/// stub slot SLOT_RAW_REAL_TO_PM (INT 31h trap).
///
/// Register convention (set by caller before CALL FAR):
///   AX = new PM DS selector
///   CX = new PM ES selector
///   DX = new PM SS selector
///   (E)BX = new PM (E)SP
///   SI = new PM CS selector
///   (E)DI = new PM (E)IP
pub(in crate::kernel::dos) fn raw_switch_real_to_pm(dos: &mut thread::DosState, regs: &mut Vcpu) {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_cs = regs.rsi as u16;

    // Determine destination operand size from the target CS/SS descriptors,
    // so 16-bit clients don't pick up garbage in EBX/EDI upper bits.
    let (new_esp, new_eip) = {
        let cs_32 = seg_is_32(&dos.ldt[..], new_cs);
        let ss_32 = seg_is_32(&dos.ldt[..], new_ss);
        let esp = if ss_32 { regs.rbx as u32 } else { regs.rbx as u32 & 0xFFFF };
        let eip = if cs_32 { regs.rdi as u32 } else { regs.rdi as u32 & 0xFFFF };
        (esp, eip)
    };

    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::VIF_FLAG as u64;
    regs.frame.cs = new_cs as u64;
    regs.frame.rip = new_eip as u64;
    regs.frame.ss = new_ss as u64;
    regs.frame.rsp = new_esp as u64;
    regs.ds = new_ds as u64;
    regs.es = new_es as u64;
    regs.fs = 0;
    regs.gs = 0;
    dos_trace!("[DPMI] raw RM->PM CS:EIP={:04X}:{:08X} SS:ESP={:04X}:{:08X} DS={:04X} ES={:04X}",
        new_cs, new_eip, new_ss, new_esp, new_ds, new_es);

    // Raw mode switches mutate descriptors in place; LDTR still points at this thread's LDT.
}

// ============================================================================
// Helpers
// ============================================================================


/// Compute flat address from selector:offset.
/// Address size (16 vs 32 bit offset) determined by CS descriptor's D/B bit.
pub(super) fn flat_addr(ldt: &[u64], seg: u16, offset: u32, cs_32: bool) -> u32 {
    let offset = if cs_32 { offset } else { offset & 0xFFFF };
    seg_base(ldt, seg).wrapping_add(offset)
}

pub(super) fn trace_client_selector_leak(_label: &str, _regs: &Vcpu) {}

pub(super) fn set_carry(regs: &mut Vcpu) {
    regs.set_flag32(1); // CF
}

pub(super) fn clear_carry(regs: &mut Vcpu) {
    regs.clear_flag32(1); // CF
}
