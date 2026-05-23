use super::*;
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
pub(in crate::kernel::dos) fn raw_switch_pm_to_real(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_sp = regs.rbx as u16;
    let new_cs = regs.rsi as u16;
    let new_ip = regs.rdi as u16;

    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.raw_pm_state = capture_protected_mode_state(regs);
    }
    restore_rm_psp_view(dos);

    regs.frame.rflags |= (machine::VM_FLAG | machine::IF_FLAG) as u64;
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
pub(in crate::kernel::dos) fn pm_stub_dispatch(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
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
            return super::super::dos::pmdos_int21_handler(kt, dos, regs);
        }
        dos::SLOT_EXCEPTION_RET => {
            return exception_return(dos, regs, ExcReturnVia::V09);
        }
        dos::SLOT_EXCEPTION_RET_V10 => {
            return exception_return(dos, regs, ExcReturnVia::V10);
        }
        dos::SLOT_PM_TO_REAL => {
            return raw_switch_pm_to_real(dos, regs);
        }
        dos::SLOT_RM_IRET_CALL => {
            // PM callback IRETed back to us: writeback + restore the RM
            // caller (callback_entry path). 0300/01/02 path lands here via
            // RM `CD 31` in slot from the RM-side stub instead.
            rm_iret_call(dos, regs);
            return thread::KernelAction::Done;
        }
        dos::SLOT_PM_IRET => {
            let r = mode_transitions::cross_mode_restore(dos, regs);
            // PM-handler path for HW IRQ: client handler ran, IRETed
            // through our stub, cross_mode_restore put us back at the
            // interrupted client state. IRQ context is over.
            super::super::IN_HW_IRQ_CONTEXT.store(false, core::sync::atomic::Ordering::Relaxed);
            return r;
        }
        dos::SLOT_SAVE_RESTORE => {
            save_restore_real_mode_state(dos, regs);

            // Pop the far-call return address and resume caller. Frame size
            // depends on the client's operand size: 16-bit CALL FAR pushed
            // IP+CS as 4 bytes; 32-bit CALL FAR pushed EIP+CS as 8 bytes.
            let dpmi = dos.dpmi.as_ref().unwrap();
            let use32 = dpmi.client_use32;
            let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
            let ss_32 = seg_is_32(&dos.ldt[..], regs.stack_seg());
            let sp = if ss_32 { regs.sp32() } else { regs.sp32() & 0xFFFF };
            let (ret_eip, ret_cs, frame_size) = if use32 {
                let eip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u32) };
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 4)) as *const u32) };
                (eip, cs, 8u32)
            } else {
                let ip = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp)) as *const u16) } as u32;
                let cs = unsafe { core::ptr::read_unaligned((ss_base.wrapping_add(sp + 2)) as *const u16) } as u32;
                (ip, cs, 4u32)
            };
            let new_sp = sp.wrapping_add(frame_size);
            if ss_32 { regs.set_sp32(new_sp); }
            else { regs.set_sp32((regs.sp32() & !0xFFFF) | (new_sp & 0xFFFF)); }
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
pub(in crate::kernel::dos) fn raw_switch_real_to_pm(dos: &mut thread::DosState, regs: &mut Regs) {
    let new_ds = regs.rax as u16;
    let new_es = regs.rcx as u16;
    let new_ss = regs.rdx as u16;
    let new_cs = regs.rsi as u16;
    let saved_rm_state = capture_real_mode_state(
        regs,
        regs.code_seg(),
        regs.ip32() as u16,
        regs.stack_seg(),
        regs.sp32() as u16,
    );

    // Determine destination operand size from the target CS/SS descriptors,
    // so 16-bit clients don't pick up garbage in EBX/EDI upper bits.
    let (new_esp, new_eip) = {
        let cs_32 = seg_is_32(&dos.ldt[..], new_cs);
        let ss_32 = seg_is_32(&dos.ldt[..], new_ss);
        let esp = if ss_32 { regs.rbx as u32 } else { regs.rbx as u32 & 0xFFFF };
        let eip = if cs_32 { regs.rdi as u32 } else { regs.rdi as u32 & 0xFFFF };
        (esp, eip)
    };

    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.raw_rm_state = saved_rm_state;
    }
    enter_pm_psp_view(dos);

    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::IF_FLAG as u64;
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

pub(super) fn capture_real_mode_state(regs: &Regs, cs: u16, ip: u16, ss: u16, sp: u16) -> RawModeState {
    RawModeState {
        flags: regs.flags32() as u32,
        cs,
        ip: ip as u32,
        ss,
        sp: sp as u32,
        ds: regs.ds as u16,
        es: regs.es as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
    }
}

pub(super) fn capture_protected_mode_state(regs: &Regs) -> RawModeState {
    RawModeState {
        flags: regs.flags32(),
        cs: regs.code_seg(),
        ip: regs.ip32(),
        ss: regs.stack_seg(),
        sp: regs.sp32(),
        ds: regs.ds as u16,
        es: regs.es as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
    }
}

fn real_mode_state_buffer_addr(regs: &Regs) -> u32 {
    ((regs.es as u32) << 4).wrapping_add((regs.rdi as u32) & 0xFFFF)
}

pub(super) fn save_restore_real_mode_state(dos: &mut thread::DosState, regs: &Regs) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(dpmi) => dpmi,
        None => return,
    };
    let buf_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
    match regs.rax as u8 {
        0 => unsafe { core::ptr::write_unaligned(buf_addr as *mut RawModeState, dpmi.raw_rm_state) },
        1 => unsafe { dpmi.raw_rm_state = core::ptr::read_unaligned(buf_addr as *const RawModeState) },
        al => crate::kernel::dos::dos_trace!(
            "DPMI save_restore_raw_mode unsupported AL={:02X}", al),
    }
}

pub(in crate::kernel::dos) fn save_restore_protected_mode_state(dos: &mut thread::DosState, regs: &Regs) {
    let dpmi = match dos.dpmi.as_mut() {
        Some(dpmi) => dpmi,
        None => return,
    };
    let buf_addr = real_mode_state_buffer_addr(regs);
    match regs.rax as u8 {
        0 => unsafe { core::ptr::write_unaligned(buf_addr as *mut RawModeState, dpmi.raw_pm_state) },
        1 => unsafe { dpmi.raw_pm_state = core::ptr::read_unaligned(buf_addr as *const RawModeState) },
        al => crate::kernel::dos::dos_trace!(
            "DPMI save_restore_pm_state unsupported AL={:02X}", al),
    }
}

pub(super) fn trace_client_selector_leak(_label: &str, _regs: &Regs) {}

pub(super) fn set_carry(regs: &mut Regs) {
    regs.set_flag32(1); // CF
}

pub(super) fn clear_carry(regs: &mut Regs) {
    regs.clear_flag32(1); // CF
}
