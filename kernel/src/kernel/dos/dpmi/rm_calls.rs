use super::*;
use super::super::mode_transitions;

/// INT 31h/0300h — Simulate Real Mode Interrupt
/// Trace helper: peek 16 bytes at RM linear (ds<<4)+edx and print ASCII.
/// Used to see what filename/buffer DOS/4GW hands to real mode.
fn dump_ds_dx(ds: u16, edx: u32) {
    let linear = ((ds as u32) << 4).wrapping_add(edx & 0xFFFF);
    if linear >= 0x110000 { return; } // guard against non-low memory
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = unsafe { core::ptr::read_volatile((linear + i as u32) as *const u8) };
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

/// Stub-frame for `SLOT_RM_IRET_CALL` — pushed above the `ModeSave` by
/// every explicit PM→RM-call entry (`0300/01/02` and `callback_entry`).
/// On unwind, `rm_iret_call` writes the post-RM regs into the
/// RmCallStruct at `rm_struct_addr`, then restores the saved GP regs
/// (PM caller's for `0300/01/02`; RM caller's for `callback_entry`).
/// Other slots (`SLOT_PM_IRET`, `SLOT_RM_IRET`) don't need this
/// — handler preservation / spec round-trip handle their GP regs.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CallStubFrame {
    rm_struct_addr: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
}

const CALL_STUB_SIZE: u32 = core::mem::size_of::<CallStubFrame>() as u32;

impl CallStubFrame {
    fn capture(regs: &Regs, rm_struct_addr: u32) -> Self {
        Self {
            rm_struct_addr,
            eax: regs.rax as u32,
            ebx: regs.rbx as u32,
            ecx: regs.rcx as u32,
            edx: regs.rdx as u32,
            esi: regs.rsi as u32,
            edi: regs.rdi as u32,
            ebp: regs.rbp as u32,
        }
    }

    fn restore_gp(&self, regs: &mut Regs) {
        regs.rax = (regs.rax & !0xFFFFFFFF) | self.eax as u64;
        regs.rbx = (regs.rbx & !0xFFFFFFFF) | self.ebx as u64;
        regs.rcx = (regs.rcx & !0xFFFFFFFF) | self.ecx as u64;
        regs.rdx = (regs.rdx & !0xFFFFFFFF) | self.edx as u64;
        regs.rsi = (regs.rsi & !0xFFFFFFFF) | self.esi as u64;
        regs.rdi = (regs.rdi & !0xFFFFFFFF) | self.edi as u64;
        regs.rbp = (regs.rbp & !0xFFFFFFFF) | self.ebp as u64;
    }
}

/// Write a `CallStubFrame` at the (SS, SP) cursor. Returns the new
/// (lower) (SS, SP).
fn host_stack_write_call_args(ldt: &[u64], cursor: (u16, u32), frame: CallStubFrame) -> (u16, u32) {
    let new_sp = cursor.1 - CALL_STUB_SIZE;
    let addr = mode_transitions::seg_base(ldt, cursor.0).wrapping_add(new_sp);
    unsafe { core::ptr::write_unaligned(addr as *mut CallStubFrame, frame); }
    (cursor.0, new_sp)
}

/// Read a `CallStubFrame` at the (SS, SP) cursor.
fn host_stack_read_call_args(ldt: &[u64], cursor: (u16, u32)) -> CallStubFrame {
    let addr = mode_transitions::seg_base(ldt, cursor.0).wrapping_add(cursor.1);
    unsafe { core::ptr::read_unaligned(addr as *const CallStubFrame) }
}

/// SLOT_RM_IRET_CALL dispatch — explicit PM→RM call unwind (0x0300/01/02
/// and `callback_entry`). Pops the `CallStubFrame`, writes current RM regs
/// (the post-call values) into the RmCallStruct at `rm_struct_addr`, then
/// restores the saved GP regs and pops the `ModeSave`. Restoration order
/// is critical: writeback uses *current* (post-RM) regs, so it must run
/// before `restore_gp` overwrites them.
pub(in crate::kernel::dos) fn rm_iret_call(dos: &mut thread::DosState, regs: &mut Regs) {
    // After RM-side IRET, `other_stack` holds the PM cursor.
    // CallStubFrame is the topmost record, ModeSave below it.
    let cursor0 = mode_transitions::pm_get_stack(dos, regs);
    let stub = host_stack_read_call_args(&dos.ldt[..], cursor0);
    let save = mode_transitions::pop_save_at(
        &dos.ldt[..],
        (cursor0.0, cursor0.1 + CALL_STUB_SIZE),
    );

    // Writeback current RM regs into RmCallStruct so the PM caller sees
    // results. Must happen *before* GP-restore overwrites regs.
    let rm_struct_addr = { let f = stub; f.rm_struct_addr };
    let rm_struct = RmCallStruct {
        edi: regs.rdi as u32,
        esi: regs.rsi as u32,
        ebp: regs.rbp as u32,
        _reserved: 0,
        ebx: regs.rbx as u32,
        edx: regs.rdx as u32,
        ecx: regs.rcx as u32,
        eax: regs.rax as u32,
        flags: regs.flags32() as u16,
        es: regs.es as u16,
        ds: regs.ds as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
        ip: regs.ip32() as u16,
        cs: regs.code_seg(),
        sp: regs.sp32() as u16,
        ss: regs.stack_seg(),
    };
    unsafe { *(rm_struct_addr as *mut RmCallStruct) = rm_struct; }

    {
        let (eax, ebx, ecx, edx, esi, edi, flags, ds, es) = (
            rm_struct.eax, rm_struct.ebx, rm_struct.ecx, rm_struct.edx,
            rm_struct.esi, rm_struct.edi, rm_struct.flags, rm_struct.ds, rm_struct.es);
        dos_trace!("[0300 RET-WB] addr={:08X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} SI={:04X} DI={:04X} DS={:04X} ES={:04X} FL={:04X}",
            rm_struct_addr, eax as u16, ebx as u16, ecx as u16, edx as u16,
            esi as u16, edi as u16, ds, es, flags);
    }

    stub.restore_gp(regs);
    save.restore(regs);
    dos.pc.locked_stack.other_stack = save.other_stack();

    // callback_entry path: ModeSave captured RM, so this restored to
    // VM86 with cs:ip = STUB_SEG:slot+2 (the trap-incremented IP, which
    // points at the *next* slot's CD 31). The RM caller reached us via
    // CALL FAR, so pop the 4-byte return frame from the RM stack to land
    // at the post-CALL-FAR continuation. simulate_real_mode_int and
    // call_real_mode_proc{_iret} restore PM and don't take this branch.
    if regs.mode() == crate::UserMode::VM86 {
        let ret_ip = machine::vm86_pop(regs);
        let ret_cs = machine::vm86_pop(regs);
        machine::set_vm86_ip(regs, ret_ip);
        machine::set_vm86_cs(regs, ret_cs);
    }

    dos_trace!("[INT31 RET] AX={:04x} CF={:x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        regs.rax as u16, regs.flags32() & 1,
        regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);

}

/// DPMI real-mode call structure (50 bytes at ES:EDI). Filled by the client
/// before a 0300/0301/0302 INT 31h call; written back by `rm_iret_call` with
/// the post-RM register state. Kept here because the writeback is part of
/// the unwind machinery — the API parsing in `dpmi::call_real_mode_proc` etc.
/// hands us the buffer address at entry.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RmCallStruct {
    edi: u32, esi: u32, ebp: u32, _reserved: u32,
    ebx: u32, edx: u32, ecx: u32, eax: u32,
    flags: u16, es: u16, ds: u16, fs: u16, gs: u16,
    ip: u16, cs: u16, sp: u16, ss: u16,
}

pub(super) fn simulate_real_mode_int(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let int_num = regs.rbx as u8;

    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    // Read the real-mode call structure from ES:EDI (use client_use32, not cs_32)
    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    { let (ax, bx, cx, dx, ds, es, edi) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi);
      dos_trace!("[DPMI] 0300 int={:02X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X}",
        int_num, ax, bx, cx, dx, ds, es, edi);
      dump_ds_dx(ds, rm.edx); }

    // rm dest: user-supplied SS:SP from the struct, or the live rm
    // cursor if a chain is in flight (LIFO share with outer excursion),
    // else rm_TOS for first-entry.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    // PM→RM toggle: pushes ModeSave on pm side. CallStubFrame goes
    // above the save (carries rm_struct_addr + saved PM GP regs for
    // post-call writeback / restore). other_stack is updated with the
    // post-CallStubFrame cursor so the unwind via SLOT_RM_IRET_CALL
    // reads both records in order.
    let stub = CallStubFrame::capture(regs, struct_addr);
    let pm_save_at = mode_transitions::switch_to_rm_side(dos, regs, rm_dest);
    let pm_post = host_stack_write_call_args(&dos.ldt[..], pm_save_at, stub);
    dos.pc.locked_stack.other_stack = Some(pm_post);

    // Get IVT entry for the interrupt
    let ivt_off = machine::read_u16(0, (int_num as u32) * 4);
    let ivt_seg = machine::read_u16(0, (int_num as u32) * 4 + 2);

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

    // Push return IRET frame on VM86 stack — switch_to_rm_side already
    // set regs.SS:SP = rm_dest.
    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Set CS:IP to the IVT handler. VM_FLAG already set by toggle.
    regs.frame.cs = ivt_seg as u64;
    regs.frame.rip = ivt_off as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;

    dos_trace!("[DPMI] simulate INT {:02X} -> {:04X}:{:04X} SS:SP={:04X}:{:04X}",
        int_num, ivt_seg, ivt_off, rm_dest.0, rm_dest.1.wrapping_sub(6));

    // Now in VM86 mode — the event loop will execute the BIOS handler.
    // When it IRETs to callback_stub, INT 31h fires, and rm_iret_call() is called.
    thread::KernelAction::Done
}


/// INT 31h/0301h — Call Real Mode Far Procedure
pub(super) fn call_real_mode_proc(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    // Same LIFO-share rule as simulate_real_mode_int.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    let stub = CallStubFrame::capture(regs, struct_addr);
    let pm_save_at = mode_transitions::switch_to_rm_side(dos, regs, rm_dest);
    let pm_post = host_stack_write_call_args(&dos.ldt[..], pm_save_at, stub);
    dos.pc.locked_stack.other_stack = Some(pm_post);

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
    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // Jump to the far procedure. VM_FLAG already set by toggle.
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;
    thread::KernelAction::Done
}

/// INT 31h/0302h — Call Real Mode Procedure with IRET Frame
pub(super) fn call_real_mode_proc_iret(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;

    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = unsafe { *(struct_addr as *const RmCallStruct) };

    { let (ax, bx, cx, dx, ds, es, edi, cs, ip) =
        (rm.eax as u16, rm.ebx as u16, rm.ecx as u16, rm.edx as u16, rm.ds, rm.es, rm.edi, rm.cs, rm.ip);
      dos_trace!("[DPMI] 0302 AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} EDI={:08X} CS:IP={:04X}:{:04X}",
        ax, bx, cx, dx, ds, es, edi, cs, ip);
      let (edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f) =
          (rm.edi, rm.esi, rm.ebp, rm.ebx, rm.edx, rm.ecx, rm.eax, rm.flags);
      dos_trace!("[DPMI] 0302 RMCS full: EDI={:08X} ESI={:08X} EBP={:08X} EBX={:08X} EDX={:08X} ECX={:08X} EAX={:08X} flags={:04X}",
        edi_f, esi_f, ebp_f, ebx_f, edx_f, ecx_f, eax_f, flags_f);
      dump_ds_dx(ds, rm.edx); }

    // Same LIFO-share rule as simulate_real_mode_int.
    let rm_dest = if rm.ss != 0 {
        (rm.ss, rm.sp as u32)
    } else {
        mode_transitions::rm_get_stack(dos)
    };

    let stub = CallStubFrame::capture(regs, struct_addr);
    let pm_save_at = mode_transitions::switch_to_rm_side(dos, regs, rm_dest);
    let pm_post = host_stack_write_call_args(&dos.ldt[..], pm_save_at, stub);
    dos.pc.locked_stack.other_stack = Some(pm_post);

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
    let callback_off: u16 = dos::slot_offset(dos::SLOT_RM_IRET_CALL);
    let callback_seg: u16 = dos::STUB_SEG;
    machine::vm86_push(regs, rm.flags);
    machine::vm86_push(regs, callback_seg);
    machine::vm86_push(regs, callback_off);

    // VM_FLAG already set by toggle.
    regs.frame.cs = rm.cs as u64;
    regs.frame.rip = rm.ip as u64;
    regs.frame.rflags = (machine::VM_FLAG | machine::IF_FLAG | machine::IOPL_VM86) as u64;
    thread::KernelAction::Done
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub fn callback_entry(dos: &mut thread::DosState, regs: &mut Regs, cb_idx: usize) {
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

    let rm_call = RmCallStruct {
        edi: regs.rdi as u32,
        esi: regs.rsi as u32,
        ebp: regs.rbp as u32,
        _reserved: 0,
        ebx: regs.rbx as u32,
        edx: regs.rdx as u32,
        ecx: regs.rcx as u32,
        eax: regs.rax as u32,
        flags: regs.flags32() as u16,
        es: regs.es as u16,
        ds: regs.ds as u16,
        fs: regs.fs as u16,
        gs: regs.gs as u16,
        ip: regs.ip32() as u16,
        cs: regs.code_seg(),
        sp: regs.sp32() as u16,
        ss: regs.stack_seg(),
    };
    unsafe { *(struct_addr as *mut RmCallStruct) = rm_call; }

    // RM→PM toggle: pushes ModeSave on pm side, lands regs.SS:SP on
    // top of the save in PM mode, captures rm caller's SS:SP into
    // other_stack (so a nested PM→RM transition resumes below it).
    // CallStubFrame goes above the save (carries rm_struct_addr +
    // saved RM GP regs for post-handler writeback / restore); we land
    // the user's regs.SP on top of *both* records and update
    // other_stack stays as set by the toggle (rm caller's SS:SP).
    // DPMI 0.9 §6.1.1: DS:(E)SI must point at the RM stack location
    // where the caller's return addresses are pushed — handler reads
    // CS:IP from there. Capture before switch_to_pm_side mutates regs.
    let rm_ss_sp_linear = (regs.stack_seg() as u32).wrapping_shl(4)
        .wrapping_add(regs.sp32());

    let stub = CallStubFrame::capture(regs, struct_addr);
    let pm_save_at = mode_transitions::switch_to_pm_side(dos, regs);
    let pm_post = host_stack_write_call_args(&dos.ldt[..], pm_save_at, stub);

    // Plant an iret-frame below the CallStubFrame: the PM handler IRETs
    // to SPECIAL_STUB_SEL:SLOT_RM_IRET_CALL which dispatches `rm_iret_call`
    // (writeback + GP/save restore + return-to-RM-caller via CALL FAR pop).
    // Per DPMI 0.9 §6.1.1 the PM callback procedure must execute IRET.
    let client_use32 = dos.dpmi.as_ref().map_or(false, |d| d.client_use32);
    regs.frame.rsp = pm_post.1 as u64;
    mode_transitions::push_iret_frame(
        &dos.ldt[..], regs, client_use32,
        dos::STUB_BASE + dos::slot_offset(dos::SLOT_RM_IRET_CALL) as u32,
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



