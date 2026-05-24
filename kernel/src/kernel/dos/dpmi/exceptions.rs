use super::*;
use super::super::mode_transitions;

fn dump_selector(label: &str, dos: &thread::DosState, sel: u16) {
    let idx = sel_to_idx(sel);
    if idx < LDT_ENTRIES {
        let desc = dos.ldt[idx];
        crate::println!(
            "  {} {:04X}: base={:08X} limit={:08X} raw={:016X}",
            label,
            sel,
            desc_base(desc),
            desc_limit(desc),
            desc,
        );
    } else {
        crate::println!("  {} {:04X}: outside LDT", label, sel);
    }
}

fn dump_words(label: &str, addr: u32) {
    let w0 = unsafe { core::ptr::read_unaligned(addr as *const u16) };
    let w1 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(2) as *const u16) };
    let w2 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(4) as *const u16) };
    let w3 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(6) as *const u16) };
    let w4 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(8) as *const u16) };
    let w5 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(10) as *const u16) };
    let w6 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(12) as *const u16) };
    let w7 = unsafe { core::ptr::read_unaligned(addr.wrapping_add(14) as *const u16) };
    crate::println!(
        "  {} @{:08X}: {:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X} {:04X}",
        label, addr, w0, w1, w2, w3, w4, w5, w6, w7,
    );
}

fn dump_dpmi_fault_context(dos: &thread::DosState, regs: &Regs, exc_num: u32) {
    let cs_base = seg_base(&dos.ldt[..], regs.code_seg());
    let ss_base = seg_base(&dos.ldt[..], regs.stack_seg());
    let ip_addr = cs_base.wrapping_add(regs.ip32());
    let sp_addr = ss_base.wrapping_add(regs.sp32());
    let bp_addr = ss_base.wrapping_add(regs.rbp as u32);
    let bytes = unsafe { core::slice::from_raw_parts(ip_addr as *const u8, 16) };

    crate::println!(
        "[DPMI-FAULT] exc={} at {:04X}:{:08X} err={:04X} AX={:08X} BX={:08X} CX={:08X} DX={:08X} SI={:08X} DI={:08X} BP={:08X}",
        exc_num,
        regs.code_seg(),
        regs.ip32(),
        regs.err_code as u16,
        regs.rax as u32,
        regs.rbx as u32,
        regs.rcx as u32,
        regs.rdx as u32,
        regs.rsi as u32,
        regs.rdi as u32,
        regs.rbp as u32,
    );
    crate::println!(
        "  DS={:04X} ES={:04X} FS={:04X} GS={:04X} SS:SP={:04X}:{:08X} code={:02X?}",
        regs.ds as u16,
        regs.es as u16,
        regs.fs as u16,
        regs.gs as u16,
        regs.stack_seg(),
        regs.sp32(),
        bytes,
    );
    dump_selector("CS", dos, regs.code_seg());
    dump_selector("DS", dos, regs.ds as u16);
    dump_selector("ES", dos, regs.es as u16);
    dump_selector("SS", dos, regs.stack_seg());
    dump_words("stack SP", sp_addr);
    dump_words("stack BP", bp_addr);
}

/// FAR-CALL return frame the host pushes below the spec exception
/// frame. Handler pops it via RETF, landing at our `SLOT_EXCEPTION_RET`
/// stub which traps to `exception_return` via INT 31h.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RetF32 { ret_eip: u32, ret_cs: u32 }

/// 16-bit RETF return frame (4 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RetF16 { ret_ip: u16, ret_cs: u16 }

/// 32-bit DPMI 0.9 exception spec frame body (24 bytes). Sits above
/// `RetF32` on the host stack. Per DPMI 0.9 §6.1.4, handler entry SS:ESP
/// points at RetF32, the 0.9 body lives at +08H..+1FH.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ExcFrame32 {
    err_code: u32,    // +08H
    eip:      u32,    // +0CH
    cs:       u32,    // +10H  (low 16 = CS, high 16 = reserved)
    eflags:   u32,    // +14H
    esp:      u32,    // +18H
    ss:       u32,    // +1CH  (low 16 = SS, high 16 = reserved)
}

/// DPMI 1.0 expanded exception frame body (56 bytes). Sits at
/// SS:(E)SP+20H regardless of client/handler bitness — per spec, the
/// expanded frame always uses 32-bit fields and lives above the 0.9
/// frame. It is written on every dispatch; 0.9 handlers read only the
/// +0..+1FH portion and ignore the expanded bytes above it.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ExcFrameV10 {
    ret_eip:   u32,   // +20H  Return EIP (or CS:IP for 16-bit handler)
    ret_cs:    u32,   // +24H  Return CS (low 16) + Reserved (high 16)
    err_code:  u32,   // +28H  Error code (duplicate of 0.9 +08H)
    eip:       u32,   // +2CH  Faulting EIP (duplicate of 0.9 +0CH)
    cs_xinfo:  u32,   // +30H  Faulting CS (low 16) + ExceptionInfoBits (high 16)
    eflags:    u32,   // +34H  Faulting EFLAGS (duplicate of 0.9 +14H)
    esp:       u32,   // +38H  Faulting ESP (duplicate of 0.9 +18H)
    ss:        u32,   // +3CH  Faulting SS (low 16) + Reserved (high 16)
    es:        u32,   // +40H  ES (low 16) + Reserved (high 16)
    ds:        u32,   // +44H  DS (low 16) + Reserved (high 16)
    fs:        u32,   // +48H  FS (low 16) + Reserved (high 16)
    gs:        u32,   // +4CH  GS (low 16) + Reserved (high 16)
    cr2:       u32,   // +50H  CR2 (valid only for #PF / INT 0EH)
    pte:       u32,   // +54H  PTE (valid only for #PF / INT 0EH)
}

/// 16-bit DPMI 0.9 exception spec frame. Sits above `RetF16` on the
/// host stack as its own region (u16 fields don't share offsets with
/// HostContinuation's u32 fields). dispatch writes the whole struct;
/// exception_return reads it back, copies handler-modified faulting
/// fields into the low halves of HostContinuation's u32 fields.
///
/// The trailing `_pad` bytes bring `RetF16 + ExcFrame16` to exactly 32
/// bytes (0x20). A 16-bit 0.9 handler reads at +00H..+0FH and is
/// oblivious to the padding above; but the constant 0x20 footprint
/// leaves a stable +20H offset for the DPMI 1.0 expanded frame.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ExcFrame16 {
    err_code: u16,    // +04H from SS:SP
    ip:       u16,    // +06H
    cs:       u16,    // +08H
    flags:    u16,    // +0AH
    sp:       u16,    // +0CH
    ss:       u16,    // +0EH
    _pad:     [u16; 8], // +10H..+1FH (reserved for 1.0 expanded-frame slot)
}

/// Dispatch a CPU exception to the client's exception handler (set via INT 31h/0203h).
/// If no handler is set, kill the thread.
///
/// We unconditionally write the full DPMI 1.0 layout on every dispatch:
/// the 0.9 portion (sized for client_use32) at +00..+1FH, followed by
/// the 1.0 expanded frame at +20H..+57H. A 0.9 (0203H) handler reads
/// only the +0..+1FH portion; a 1.0 (0212H/0213H) handler additionally
/// reads the expanded portion. Total = 88 bytes.
///
/// 32-bit client 0.9 portion:
///   [ESP+0]   Return EIP (points to SLOT_EXCEPTION_RET stub)
///   [ESP+4]   Return CS  (special-stub selector)
///   [ESP+8]   Error code (dword)
///   [ESP+12]  Faulting EIP
///   [ESP+16]  Faulting CS (low 16) + Reserved
///   [ESP+20]  Faulting EFLAGS
///   [ESP+24]  Faulting ESP
///   [ESP+28]  Faulting SS (low 16) + Reserved
///
/// 16-bit client 0.9 portion (word fields, then padding to +1FH):
///   [SP+0]    Return IP
///   [SP+2]    Return CS
///   [SP+4]    Error code
///   [SP+6]    Faulting IP
///   [SP+8]    Faulting CS
///   [SP+10]   Faulting FLAGS
///   [SP+12]   Faulting SP
///   [SP+14]   Faulting SS
///   [SP+16..+31] Reserved padding
///
/// 1.0 expanded portion (always 32-bit fields, written at +20H..+57H):
///   [ESP+0x20] Return EIP (for ADD ESP,0x20; RETF path — same stub)
///   [ESP+0x24] Return CS  + Reserved
///   [ESP+0x28] Error code (duplicate)
///   [ESP+0x2C] Faulting EIP (duplicate)
///   [ESP+0x30] Faulting CS (low 16) + ExceptionInfoBits (high 16)
///   [ESP+0x34] Faulting EFLAGS (duplicate)
///   [ESP+0x38] Faulting ESP (duplicate)
///   [ESP+0x3C] Faulting SS (low 16) + Reserved
///   [ESP+0x40] ES + Reserved
///   [ESP+0x44] DS + Reserved
///   [ESP+0x48] FS + Reserved
///   [ESP+0x4C] GS + Reserved
///   [ESP+0x50] CR2 (valid for #PF)
///   [ESP+0x54] PTE (valid for #PF)
pub(in crate::kernel::dos) fn dispatch_dpmi_exception(dos: &mut thread::DosState, regs: &mut Regs, exc_num: u32) -> thread::KernelAction {
    dos_trace!("[DPMI] EXCEPTION {} CS:EIP={:04x}:{:#x} err={:#x} DS={:04x} ES={:04x} FS={:04x} GS={:04x} SS:ESP={:04x}:{:#x}",
        exc_num, regs.code_seg(), regs.ip32(), regs.err_code,
        regs.ds as u16, regs.es as u16, regs.fs as u16, regs.gs as u16,
        regs.stack_seg(), regs.sp32());
    // No verbose dump on handled #GP/#PF -- DPMI clients routinely take
    // these for sensitive-insn emulation; the dump goes to VGA and clobbers
    // the user screen. The unhandled-exception path below still dumps.
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => {
            return thread::KernelAction::Exit(0x0200 | (exc_num as i32 & 0xFF));
        }
    };

    // Lookup precedence: a DPMI 1.0 mode-specific handler (0212H for
    // PM-origin, 0213H for VM86-origin) takes priority; the 0.9 0203H
    // handler is the fallback if no 1.0 handler is installed. The 0.9
    // handler covers both origins by spec, so this gives 1.0 clients
    // mode-specific routing without losing 0.9-compat for vectors that
    // only have the legacy install.
    let from_vm86 = regs.mode() == crate::UserMode::VM86;
    let (handler_sel, handler_off) = if (exc_num as usize) < 32 {
        let n = exc_num as usize;
        let v10 = if from_vm86 {
            dpmi.rm_exc_vectors[n]
        } else {
            dpmi.pm_exc_vectors[n]
        };
        if v10 != (0, 0) { v10 } else { dpmi.exc_vectors[n] }
    } else {
        (0, 0)
    };

    if handler_sel == 0 && handler_off == 0 {
        // Per DPMI 0.9: software-INT exceptions (0/3/4 = #DE/#BP/#OF) reflect
        // to the real-mode IVT when the client has not installed a handler —
        // dpmiload uses INT 3 as "halt on error" and expects the real-mode
        // handler (a bare IRET stub) to bring it back. Hardware faults like
        // #GP (13) or #PF (14) must NOT be reflected: their IVT slots point
        // at unrelated services (e.g. INT 13h is BIOS disk I/O), and the
        // faulting instruction would just re-execute and refault, producing
        // an infinite loop. Terminate the client instead.
        if matches!(exc_num, 0 | 3 | 4) {
            let ivt_off = machine::read_u16(0, exc_num * 4);
            let ivt_seg = machine::read_u16(0, exc_num * 4 + 2);
            dos_trace!("[DPMI] reflect exception {} to IVT {:04X}:{:04X} from {:04X}:{:08X} flags={:04X}",
                exc_num, ivt_seg, ivt_off, regs.code_seg(), regs.ip32(), regs.flags32() as u16);
            // Plant an iret-frame on the user's stack pointing at the
            // faulting CS:EIP. After BIOS returns, `resume_continuation_from_stub` resumes at a
            // host IRET stub that lands back at the faulting instruction.
            // Frame width follows client bitness.
            let client_use32 = dpmi.client_use32;
            let handler_flags = regs.flags32() & !(machine::IF_FLAG | (1u32 << 8));
            mode_transitions::push_iret_frame(&dos.ldt[..], regs, client_use32,
                regs.ip32(), regs.code_seg(), handler_flags);
            return mode_transitions::reflect_int_to_real_mode(dos, regs, exc_num as u8);
        }
        crate::println!("DPMI: exception {} at CS:EIP={:#06x}:{:#x} err={:#x}, no handler",
            exc_num, regs.frame.cs as u16, regs.ip32(), regs.err_code);
        dump_dpmi_fault_context(dos, regs, exc_num);
        startup::arch_dump_exception(dos, regs);
        return thread::KernelAction::Exit(0x0200 | (exc_num as i32 & 0xFF));
    }

    dos_trace!("[DPMI] dispatch exception {} to {:04X}:{:08X} from {:04X}:{:08X} flags={:04X}",
        exc_num, handler_sel, handler_off, regs.code_seg(), regs.ip32(), regs.flags32() as u16);

    let use32 = dpmi.client_use32;
    let stub_off = dos::STUB_BASE + dos::slot_offset(dos::SLOT_EXCEPTION_RET) as u32;
    let stub_off_v10 = dos::STUB_BASE + dos::slot_offset(dos::SLOT_EXCEPTION_RET_V10) as u32;
    let err_code = regs.err_code as u32;

    // Capture faulting state *before* push_continuation_and_switch_to_pm_side mutates regs.
    // `from_vm86` was already captured above for the handler-table lookup.
    let f_eip    = regs.ip32();
    let f_cs     = regs.code_seg();
    let f_eflags = regs.flags32();
    let f_esp    = regs.sp32();
    let f_ss     = regs.stack_seg();
    let f_ds     = regs.ds as u16;
    let f_es     = regs.es as u16;
    let f_fs     = regs.fs as u16;
    let f_gs     = regs.gs as u16;

    let pm_save_at = mode_transitions::push_continuation_and_switch_to_pm_side(dos, regs, None);
    let pm_seg_base = mode_transitions::seg_base(&dos.ldt[..], pm_save_at.0);
    let new_sp;

    let sel_stub = mode_transitions::SPECIAL_STUB_SEL;

    // 1.0 expanded frame (faulting-state portion is always 32-bit
    // fields; same layout for both client bitnesses). Sits at
    // SS:(E)SP+20H regardless of who installed the handler — a 0.9
    // (0203H) handler does not read past +1FH. The expanded RETF target
    // at +20H points at the 1.0 exception-return stub. Width depends on
    // handler bitness: a 32-bit handler pops EIP at +20H + CS at +24H;
    // a 16-bit handler pops IP at +20H + CS at +22H.
    let (v10_ret_eip, v10_ret_cs) = if use32 {
        (stub_off_v10, sel_stub as u32)
    } else {
        // Pack IP at +20H..+21H and CS at +22H..+23H into the low
        // dword; +24H..+27H stays reserved for the 32-bit slot a
        // 16-bit handler never reads.
        ((stub_off_v10 & 0xFFFF) | ((sel_stub as u32) << 16), 0)
    };
    // ExceptionInfoBits (DPMI 1.0 §4.3, at SS:(E)SP+32H, high 16 of
    // the +30H dword):
    //   bit 0 = 0  (fault occurred in client, not in host)
    //   bit 1 = 0  (exception is retriable — handler may fix and resume)
    //   bit 2 = 0  (host-default: retry after handler returns; handler
    //               may set this to 1 to indicate it redirected
    //               execution rather than fixing the cause)
    // All three meaningful bits being zero is the spec's normal-fault
    // value; remaining bits (3..15) are reserved/zero.
    let exc_info_bits: u16 = 0;
    // CR2 / PTE are only meaningful for page faults (INT 0EH), and
    // #PF never reaches this dispatcher: the event loop catches
    // `KE::PageFault` upstream and kills the thread via
    // `signal_thread`. So `exc_num == 14` is unreachable here and
    // both fields stay zero.
    let (v10_cr2, v10_pte) = (0u32, 0u32);
    let v10 = ExcFrameV10 {
        ret_eip:  v10_ret_eip,
        ret_cs:   v10_ret_cs,
        err_code,
        eip:      f_eip,
        cs_xinfo: (f_cs as u32) | ((exc_info_bits as u32) << 16),
        eflags:   f_eflags,
        esp:      f_esp,
        ss:       f_ss as u32,
        es:       f_es as u32,
        ds:       f_ds as u32,
        fs:       f_fs as u32,
        gs:       f_gs as u32,
        cr2:      v10_cr2,
        pte:      v10_pte,
    };

    if use32 {
        // 32-bit: RetF32 (8) + ExcFrame32 (24) + ExcFrameV10 (56) = 88 bytes.
        // The 0.9 portion at +00..+1FH is what a 0203H-installed handler
        // sees; the 1.0 expanded portion at +20H..+57H is invisible to it.
        let retf = RetF32 { ret_eip: stub_off, ret_cs: sel_stub as u32 };
        let frame = ExcFrame32 {
            err_code,
            eip: f_eip, cs: f_cs as u32, eflags: f_eflags,
            esp: f_esp, ss: f_ss as u32,
        };
        new_sp = pm_save_at.1
            - core::mem::size_of::<RetF32>() as u32
            - core::mem::size_of::<ExcFrame32>() as u32
            - core::mem::size_of::<ExcFrameV10>() as u32;
        let addr = pm_seg_base.wrapping_add(new_sp);
        unsafe {
            core::ptr::write_unaligned(addr as *mut RetF32, retf);
            core::ptr::write_unaligned(
                addr.wrapping_add(core::mem::size_of::<RetF32>() as u32) as *mut ExcFrame32,
                frame,
            );
            core::ptr::write_unaligned(
                addr.wrapping_add(
                    (core::mem::size_of::<RetF32>() + core::mem::size_of::<ExcFrame32>()) as u32
                ) as *mut ExcFrameV10,
                v10,
            );
        }
    } else {
        // 16-bit: RetF16 (4) + ExcFrame16 (28, padded) + ExcFrameV10 (56) = 88 bytes.
        // 0.9 handler reads +00..+0FH; padding fills +10H..+1FH so the
        // 1.0 expanded frame still lands at the spec's +20H slot.
        let retf = RetF16 { ret_ip: stub_off as u16, ret_cs: sel_stub };
        let frame = ExcFrame16 {
            err_code: err_code as u16,
            ip: f_eip as u16, cs: f_cs, flags: f_eflags as u16,
            sp: f_esp as u16, ss: f_ss,
            _pad: [0; 8],
        };
        new_sp = pm_save_at.1
            - core::mem::size_of::<RetF16>() as u32
            - core::mem::size_of::<ExcFrame16>() as u32
            - core::mem::size_of::<ExcFrameV10>() as u32;
        let addr = pm_seg_base.wrapping_add(new_sp);
        unsafe {
            core::ptr::write_unaligned(addr as *mut RetF16, retf);
            core::ptr::write_unaligned(
                addr.wrapping_add(core::mem::size_of::<RetF16>() as u32) as *mut ExcFrame16,
                frame,
            );
            core::ptr::write_unaligned(
                addr.wrapping_add(
                    (core::mem::size_of::<RetF16>() + core::mem::size_of::<ExcFrame16>()) as u32
                ) as *mut ExcFrameV10,
                v10,
            );
        }
    }

    regs.frame.rsp = new_sp as u64;
    regs.frame.cs = handler_sel as u64;
    regs.set_ip32(handler_off);

    // DPMI 0.9 §6.1.4: when a VM86-source fault is reflected to a PM
    // handler, DS/ES/FS/GS are "undefined" -- most hosts zero them.
    // Without this, the kernel's IRET-to-handler tries to load the
    // user's old VM86 paragraph values (e.g. DS=0xBE74) as PM selectors
    // and #GPs in ring 0. PM-origin faults keep the cached PM segs.
    if from_vm86 {
        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;
    }

    thread::KernelAction::Done
}

/// Handle return from a DPMI exception handler. Reached when the handler RETFs
/// to our stub in the special-stub segment at SLOT_EXCEPTION_RET which then
/// executes CD 31, routed here via pm_stub_dispatch.
///
/// At this point regs.SS:SP points to the exception frame minus the return
/// address that the handler's RETF already popped. Frame width matches the
/// client type (16-bit clients have word fields, 32-bit clients have dword
/// fields).
///
/// 32-bit client frame remaining:
///   [ESP+0]  error code (dword)
///   [ESP+4]  faulting EIP (possibly modified)
///   [ESP+8]  faulting CS
///   [ESP+12] faulting EFLAGS
///   [ESP+16] faulting ESP
///   [ESP+20] faulting SS
///
/// 16-bit client frame remaining (all words):
///   [SP+0]   error code
///   [SP+2]   faulting IP
///   [SP+4]   faulting CS
///   [SP+6]   faulting FLAGS
///   [SP+8]   faulting SP
///   [SP+10]  faulting SS
/// Which exception-frame view the handler returned through. Selected
/// by the stub slot the handler RETFed into: 0.9 handlers (Function
/// 0203H install) target `SLOT_EXCEPTION_RET` and we read modified
/// faulting state from the 0.9 portion at +00..+1FH; 1.0 handlers
/// (Function 0212H/0213H install) do `ADD (E)SP, 0x20; RETF` and
/// target `SLOT_EXCEPTION_RET_V10`, and we read from the 1.0
/// expanded portion at +20H..+57H.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum ExcReturnVia { V09, V10 }

pub(super) fn exception_return(
    dos: &mut thread::DosState,
    regs: &mut Regs,
    via: ExcReturnVia,
) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_ref() {
        Some(d) => d,
        None => return thread::KernelAction::Done,
    };
    let use32 = dpmi.client_use32;

    // Host-stack layout on entry (low addr → high addr):
    //   new_sp:               RetF{16,32}
    //   new_sp + 4 or 8:      ExcFrame{16,32}   (0.9 spec frame body)
    //   new_sp + 0x20:        ExcFrameV10       (1.0 expanded frame)
    //   pm_save_at.1:         HostContinuation
    let host_seg = mode_transitions::host_stack_pm_seg(dos);
    let host_base = mode_transitions::seg_base(&dos.ldt[..], host_seg);
    let mode_save_sp = dos::host_stack_empty_sp() - mode_transitions::HOST_CONTINUATION_SIZE;

    // Read whichever view the handler modified. Both views share the
    // Both views share the same host_stack region; index into the selected portion.
    // The handler's own SS:SP after RETF is irrelevant to us — it may
    // have moved arbitrarily (locals, pushes that weren't fully popped)
    // and the host stack is the authoritative scratchpad either way.
    let (new_eip, new_cs, new_eflags, new_esp, new_ss) = match via {
        ExcReturnVia::V09 => {
            if use32 {
                let frame_sp = mode_save_sp
                    - core::mem::size_of::<ExcFrameV10>() as u32
                    - core::mem::size_of::<ExcFrame32>() as u32;
                let f = unsafe {
                    core::ptr::read_unaligned(host_base.wrapping_add(frame_sp) as *const ExcFrame32)
                };
                (f.eip, f.cs, f.eflags, f.esp, f.ss)
            } else {
                let frame_sp = mode_save_sp
                    - core::mem::size_of::<ExcFrameV10>() as u32
                    - core::mem::size_of::<ExcFrame16>() as u32;
                let f = unsafe {
                    core::ptr::read_unaligned(host_base.wrapping_add(frame_sp) as *const ExcFrame16)
                };
                // 16-bit fields fold into the low halves of the saved
                // 32-bit registers; upper halves come from the pre-fault
                // capture in HostContinuation below.
                (f.ip as u32, f.cs as u32, f.flags as u32, f.sp as u32, f.ss as u32)
            }
        }
        ExcReturnVia::V10 => {
            // 1.0 expanded frame is always 32-bit fields regardless of
            // client bitness (DPMI 1.0 §4.3). Sits at +20H..+57H from
            // the frame base, i.e. just below HostContinuation on host_stack.
            let frame_sp = mode_save_sp - core::mem::size_of::<ExcFrameV10>() as u32;
            let f = unsafe {
                core::ptr::read_unaligned(host_base.wrapping_add(frame_sp) as *const ExcFrameV10)
            };
            // CS lives in low 16 of cs_xinfo; high 16 is ExceptionInfoBits.
            (f.eip, f.cs_xinfo & 0xFFFF, f.eflags, f.esp, f.ss)
        }
    };

    let mut save = mode_transitions::pop_continuation_at(&dos.ldt[..], (host_seg, mode_save_sp));
    if use32 || via == ExcReturnVia::V10 {
        save.eip    = new_eip;
        save.cs     = new_cs;
        save.eflags = new_eflags;
        save.esp    = new_esp;
        save.ss     = new_ss;
    } else {
        // 0.9 16-bit view: fold word-width modifications into the low
        // 16 bits of HostContinuation's 32-bit slots.
        save.eip    = (save.eip    & 0xFFFF_0000) | new_eip;
        save.cs     = new_cs;
        save.eflags = (save.eflags & 0xFFFF_0000) | new_eflags;
        save.esp    = (save.esp    & 0xFFFF_0000) | new_esp;
        save.ss     = new_ss;
    }
    mode_transitions::resume_continuation(dos, regs, save);

    trace_client_selector_leak("exception_return.out", regs);
    thread::KernelAction::Done
}
