use arch_abi::GuestBytes;
use super::*;
use crate::arch::Vcpu;
use super::super::mode_transitions;
use super::super::mode_transitions::RmCallStruct;

/// INT 31h/0300h — Simulate Real Mode Interrupt
/// Trace helper: peek 16 bytes at RM linear (ds<<4)+edx and print ASCII.
/// Used to see what filename/buffer DOS/4GW hands to real mode.
fn dump_ds_dx(regs: &Vcpu, ds: u16, edx: u32) {
    let linear = ((ds as u32) << 4).wrapping_add(edx & 0xFFFF);
    if linear >= 0x110000 { return; } // guard against non-low memory
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = regs.read::<u8>(((linear + i as u32)) as usize);
    }
    dos_trace!(
        "[DPMI]   DS:DX@{:05X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}  '{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}'",
        linear,
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        printable(bytes[0]), printable(bytes[1]), printable(bytes[2]), printable(bytes[3]),
        printable(bytes[4]), printable(bytes[5]), printable(bytes[6]), printable(bytes[7]),
        printable(bytes[8]), printable(bytes[9]), printable(bytes[10]), printable(bytes[11]),
        printable(bytes[12]), printable(bytes[13]), printable(bytes[14]), printable(bytes[15]),
    );
}

fn printable(b: u8) -> char {
    if (0x20..0x7F).contains(&b) { b as char } else { '.' }
}

// ============================================================================
// DPMI 0300/0301/0302 — explicit PM→RM call mechanics
// ============================================================================

pub(super) fn simulate_real_mode_int(dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let int_num = regs.rbx as u8;

    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    // Read the real-mode call structure from ES:EDI (use client_use32, not cs_32)
    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = regs.read::<RmCallStruct>((struct_addr) as usize);

    { let (ax, bx, cx, dx, ds, es, edi) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi);
      dos_trace!("[DPMI] 0300 int={:02X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X}",
        int_num, ax, bx, cx, dx, ds, es, edi);
      dump_ds_dx(regs, ds, rm.edx); }

    // rm dest: user-supplied SS:SP from the struct, or the live rm
    // cursor if a chain is in flight (LIFO share with outer excursion),
    // else rm_TOS for first-entry.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    regs.write::<RmCallStruct>((struct_addr) as usize, RmCallStruct::capture(regs));
    mode_transitions::push_continuation_and_switch_to_rm_side(dos, regs, rm_dest, Some(struct_addr));

    // Get IVT entry for the interrupt
    let ivt_off = machine::read_u16(regs, 0, (int_num as u32) * 4);
    let ivt_seg = machine::read_u16(regs, 0, (int_num as u32) * 4 + 2);

    // Set up VM86 state
    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    // Push return IRET frame on VM86 stack — push_continuation_and_switch_to_rm_side already
    // set regs.SS:SP = rm_dest.
    let resume_off: u16 = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION);
    let callback_seg: u16 = dos::CTRL_STUB_SEG;
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, resume_off);

    // Set CS:IP to the IVT handler. VM_FLAG already set by toggle.
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;

    dos_trace!("[DPMI] simulate INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        int_num, ivt_seg, ivt_off, rm_dest.0, rm_dest.1.wrapping_sub(6));

    // Now in VM86 mode — the event loop will execute the BIOS handler.
    // When it IRETs to callback_stub, INT 31h fires, and resume_continuation_from_stub() is called.
    thread::KernelAction::Done
}


/// INT 31h/0301h — Call Real Mode Far Procedure
pub(super) fn call_real_mode_proc(dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = regs.read::<RmCallStruct>((struct_addr) as usize);

    // Same LIFO-share rule as simulate_real_mode_int.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    regs.write::<RmCallStruct>((struct_addr) as usize, RmCallStruct::capture(regs));
    mode_transitions::push_continuation_and_switch_to_rm_side(dos, regs, rm_dest, Some(struct_addr));

    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    // For FAR CALL: push return address (callback stub) as FAR return
    let resume_off: u16 = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION);
    let callback_seg: u16 = dos::CTRL_STUB_SEG;
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, resume_off);

    // Jump to the far procedure. VM_FLAG already set by toggle.
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;
    thread::KernelAction::Done
}

/// INT 31h/0302h — Call Real Mode Procedure with IRET Frame
pub(super) fn call_real_mode_proc_iret(dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = regs.read::<RmCallStruct>((struct_addr) as usize);

    { let (ax, bx, cx, dx, ds, es, edi, cs, ip) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi, rm.cs, rm.ip);
      dos_trace!("[DPMI] 0302 AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X} CS:IP={:04X}:{:04X}",
        ax, bx, cx, dx, ds, es, edi, cs, ip);
      let (edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f) =
          (rm.edi, rm.esi, rm.ebp, rm.ebx, rm.edx, rm.ecx, rm.eax, rm.flags);
      dos_trace!("[DPMI] 0302 RMCS full: EDI={:08X} ESI={:08X} EBP={:08X} EBX={:08X} EDX={:08X} ECX={:08X} EAX={:08X} flags={:04X}",
        edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f);
      dump_ds_dx(regs, ds, rm.edx); }

    // Same LIFO-share rule as simulate_real_mode_int.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    regs.write::<RmCallStruct>((struct_addr) as usize, RmCallStruct::capture(regs));
    mode_transitions::push_continuation_and_switch_to_rm_side(dos, regs, rm_dest, Some(struct_addr));

    regs.rax = rm.eax as u64;
    regs.rbx = rm.ebx as u64;
    regs.rcx = rm.ecx as u64;
    regs.rdx = rm.edx as u64;
    regs.rsi = rm.esi as u64;
    regs.rdi = rm.edi as u64;
    regs.rbp = rm.ebp as u64;
    regs.ds = rm.ds as u64;
    regs.es = rm.es as u64;
    regs.fs = rm.fs as u64;
    regs.gs = rm.gs as u64;

    // For IRET frame: push FLAGS, CS, IP (callback return stub)
    let resume_off: u16 = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION);
    let callback_seg: u16 = dos::CTRL_STUB_SEG;
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, resume_off);

    // VM_FLAG already set by toggle.
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;
    thread::KernelAction::Done
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub(in crate::kernel::dos) fn callback_entry(dos: &mut thread::DosState, regs: &mut Vcpu, cb_idx: usize) {
    let cb = match dos.dpmi.as_ref() {
        Some(d) => d.callbacks[cb_idx],
        None => {
            crate::println!("DPMI: callback entry but no DPMI state!");
            return;
        }
    };
    let (pm_cs, pm_eip, rm_struct_sel, rm_struct_off) = match cb {
        Some(cb) => cb,
        None => {
            crate::println!("DPMI: callback {} not allocated!", cb_idx);
            return;
        }
    };



    // Save current real-mode regs into the register structure
    let struct_addr = seg_base(&dos.ldt[..], rm_struct_sel).wrapping_add(rm_struct_off);

    let rm_call = RmCallStruct::capture(regs);
    regs.write::<RmCallStruct>((struct_addr) as usize, rm_call);

    // RM→PM toggle: pushes HostContinuation on the pm side and records
    // the RM call-structure address in it. `resume_continuation` later
    // swaps the handler-visible structure with the live regs and restores
    // the RM caller continuation.
    // DPMI 0.9 §6.1.1: DS:(E)SI must point at the RM stack location
    // where the caller's return addresses are pushed — handler reads
    // CS:IP from there. Capture before push_continuation_and_switch_to_pm_side mutates regs.
    let rm_ss_sp_linear = (regs.stack_seg() as u32).wrapping_shl(4)
        .wrapping_add(regs.sp32());

    let pm_save_at = mode_transitions::push_continuation_and_switch_to_pm_side(dos, regs, Some(struct_addr));

    // Plant an iret-frame above the continuation: the PM callback handler
    // IRETs to SPECIAL_STUB_SEL:SLOT_RESUME_CONTINUATION, which dispatches
    // `resume_continuation_from_stub` for writeback, GP restore, and RM-caller return.
    // Per DPMI 0.9 §6.1.1 the PM callback procedure must execute IRET.
    let handler_use32 = mode_transitions::seg_is_32(&dos.ldt[..], pm_cs);
    regs.frame.rsp = pm_save_at.1 as u64;
    mode_transitions::push_iret_frame(
        &dos.ldt[..], regs, handler_use32,
        dos::STUB_BASE + dos::slot_offset(dos::SLOT_RESUME_CONTINUATION) as u32,
        mode_transitions::SPECIAL_STUB_SEL,
        0x202, // IF=1
    );

    // DS:(E)SI = pointer to RM SS:SP (where IRET frame is pushed) — via
    // the flat low-mem selector so the handler can both read the caller's
    // CS:IP and modify the RM stack if needed.
    // ES:(E)DI = pointer to PM register structure.
    regs.frame.cs = pm_cs as u64;
    regs.set_ip32(pm_eip);
    regs.ds = LOW_MEM_SEL as u64;
    regs.rsi = rm_ss_sp_linear as u64;
    regs.es = rm_struct_sel as u64;
    regs.rdi = rm_struct_off as u64;
    // FS/GS still hold the RM caller's real-mode segment values (e.g.
    // DOS32A leaves arbitrary values there). In PM these would be
    // validated as selectors at exit-iret and #GP on bad GDT/LDT lookup.
    // Spec doesn't promise FS/GS to the PM callback — null them out.
    regs.fs = 0;
    regs.gs = 0;
}



