//! DOS interrupt dispatch and suspended-call continuations.

#[path = "dos/clock.rs"]
mod clock;
#[path = "dos/files.rs"]
mod files;
#[path = "dos/console.rs"]
mod console;
#[path = "dos/disk.rs"]
mod disk;
#[path = "dos/int21.rs"]
mod int21;
#[path = "dos/exec.rs"]
mod exec;
#[path = "dos/multiplex.rs"]
mod multiplex;
#[path = "dos/mouse.rs"]
mod mouse;
#[path = "dos/lowmem.rs"]
mod lowmem;

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::{dpmi, machine, mode_transitions, seg_offset};
use crate::kernel::dos::ems::{EMS_ENABLED, int_67h};
use crate::kernel::dos::machine::{
    read_u16, set_vm86_cs, set_vm86_ip, vm86_cs, vm86_ip, vm86_pop, vm86_sp, vm86_ss,
    write_u16,
};
use crate::kernel::dos::xms::xms_dispatch;
#[allow(unused_imports)]
pub(crate) use self::files::{dfs_create_path, dfs_open_existing};
pub(crate) use self::clock::dos_to_unix_datetime;
#[allow(unused_imports)]
pub(crate) use self::lowmem::{
    CTRL_STUB_SEG, JftFull, PSP_JFT_LEN, SLOT_CB_ENTRY_BASE, SLOT_CB_ENTRY_END,
    SLOT_CB_ENTRY_LAST, SLOT_EXCEPTION_RET, SLOT_EXCEPTION_RET_V10, SLOT_KBD_INTERCEPT_RETURN,
    SLOT_MOUSE_CB_RET, SLOT_PMDOS_INT10, SLOT_PMDOS_INT21, SLOT_PMDOS_INT33, SLOT_PM_TO_REAL,
    SLOT_RAW_REAL_TO_PM, SLOT_RESUME, SLOT_RESUME_CONTINUATION, SLOT_SAVE_RESTORE,
    SLOT_VBE_WINDOW, STUB_BASE, STUB_SEG, ctrl_slot_off, slot_offset, vbe_window_ptr,
    SLOT_IPX, SLOT_IPX_RETURN,
};
#[allow(unused_imports)]
pub(super) use self::clock::{cmos_date, rtc_ticks_today, rtc_time};
#[allow(unused_imports)]
pub(super) use self::exec::{Loaded, ParentRef, is_mz_exe, load_com, load_exe};
#[allow(unused_imports)]
pub(super) use self::int21::{dispatch_synchronous_rm_int21, int21_is_synchronous};
#[allow(unused_imports)]
pub(super) use self::lowmem::{
    ENV_PARAS, EXC_STACK_SLOT, EXC_STACK_TOP, Psp, STUB_INT, VBE_MODE_LIST_CAPACITY,
    boot_parent_with_env, boot_psp_seg, font_8x14_addr, font_8x16_addr, font_8x8_addr,
    heap_start, host_stack_base, host_stack_empty_sp, host_stack_size, rm_stack_align_offset,
    rm_stack_base, rm_stack_seg, rm_stack_size, set_first_mcb_seg, setup_ivt,
    vbe_mode_list_addr, video_static_info_addr,
};
#[allow(unused_imports)]
pub(super) use self::mouse::{deliver_mouse_callback, mouse_callback_return};
use self::console::{
    dos_char_resume, dos_putchar, int16_finish_resume, launch_int16_read, log_dos_byte,
};
use self::disk::int_13h;
use self::exec::{exec_replace, exec_return, fork_exec, int_2eh};

use self::int21::int_21h;
use self::exec::{return_to_psp_parent, terminate_resident};
use self::lowmem::{SLOT_COUNTRY_UPCASE, SLOT_DPMI_ENTRY, SLOT_XMS, country_upcase};
use self::mouse::int_33h;
use self::multiplex::int_2fh;

/// Park the guest at its mode-appropriate SLOT_RESUME for a blocking wait.
/// Forces virtual IF so the IRQ that's
/// meant to unblock the wait (kbd, timer) can actually deliver while
/// parked — real DOS BIOS does STI around its wait loops for the same
/// reason. Without this, AH=01/07/08/0A and the SLOT_RESUME re-park loop
/// spin forever after any path that entered the dispatcher with IF
/// cleared (the trap gate at entry, an exception handler, …): pending
/// kbd/timer IRQs queue in the vPIC but `pick_pending_vec` gates them on
/// VIF, and VIF is bit 9 of the saved EFLAGS.
fn park_at_slot_resume<A: crate::Arch>(_machine: &mut A, regs: &mut Regs) {
    if regs.mode() == crate::UserMode::VM86 {
        machine::set_vm86_cs(regs, CTRL_STUB_SEG);
        machine::set_vm86_ip(regs, ctrl_slot_off(SLOT_RESUME));
        regs.frame.rflags |= machine::VIF_FLAG as u64;
    } else {
        regs.set_cs32(super::mode_transitions::SPECIAL_STUB_SEL as u32);
        regs.set_ip32(STUB_BASE + slot_offset(SLOT_RESUME) as u32);
        let flags = machine::guest_flags_if_on(regs);
        machine::apply_guest_flags(regs, flags);
    }
}

/// Arithmetic status bits returned by DOS calls. Control flags such as DF and
/// the caller's interrupt-enable state come from the saved interrupt frame.
const DOS_STATUS_MASK: u32 = 0x08D5; // CF, PF, AF, ZF, SF, OF

fn merge_dos_status(saved_flags: u32, completed_flags: u32) -> u32 {
    (saved_flags & !DOS_STATUS_MASK) | (completed_flags & DOS_STATUS_MASK)
}

enum ResumeEntry<A: crate::Arch> {
    Poll(super::ResumeCallback<A>),
    Int16 { echo: bool, func: u8 },
}

struct DosSuspension<A: crate::Arch> {
    entry: ResumeEntry<A>,
}

/// Turn the current interrupt into a normal return to its resume stub.
/// Its original return frame moves into the continuation before the rewritten
/// frame is popped, so no unfinished interrupt frame remains on the guest
/// stack while the operation is parked. All mode-dependent framing is confined
/// here; syscall implementations merely return a `DosSuspension`.
fn suspend_dos_call<A: crate::Arch>(
    machine: &mut A,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    suspension: DosSuspension<A>,
) {
    let was_vm86 = regs.mode() == crate::UserMode::VM86;
    let (callback, launch_int16) = match suspension.entry {
        ResumeEntry::Poll(callback) => (callback, false),
        ResumeEntry::Int16 { echo, func } if was_vm86 => {
            (int16_finish_resume(machine, echo, func), true)
        }
        ResumeEntry::Int16 { echo, func } => {
            (dos_char_resume(machine, echo, func), false)
        }
    };

    let return_frame = if was_vm86 {
        let ss = vm86_ss(regs) as u32;
        let sp = vm86_sp(regs) as u32;
        let ip = read_u16(machine, ss, sp);
        let cs = read_u16(machine, ss, sp.wrapping_add(2));
        let flags = read_u16(machine, ss, sp.wrapping_add(4));

        // Rewrite this interrupt's own IRET target, then take the same normal
        // pop as every synchronous DOS call.
        write_u16(machine, ss, sp, ctrl_slot_off(SLOT_RESUME));
        write_u16(machine, ss, sp.wrapping_add(2), CTRL_STUB_SEG);
        write_u16(machine, ss, sp.wrapping_add(4), flags | machine::IF_FLAG as u16);
        finish_dos_call(machine, dos, regs);
        super::DosReturnFrame::Vm86 { ip, cs, flags }
    } else {
        let use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
        let (eip, cs, eflags) = super::mode_transitions::pop_iret_frame(
            machine, &dos.ldt[..], regs, use32,
        );
        park_at_slot_resume(machine, regs);
        super::DosReturnFrame::Protected { eip, cs, eflags }
    };

    dos.suspended_calls.push(super::SuspendedCall {
        callback,
        return_frame,
    });

    if launch_int16 {
        launch_int16_read(machine, regs);
    }
}

/// Poll one operation parked at `SLOT_RESUME`. The resume slot is a HLT rather
/// than a tight `INT 31h` loop: the architecture advances IP past HLT and
/// returns `KernelEvent::Hlt`, then the DOS event loop calls this function.
/// Pending IRQs are still delivered normally between polls.
pub(super) fn poll_suspended_call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    let suspended = dos.suspended_calls.pop()
        .expect("SLOT_RESUME fired without a suspended call");
    let return_frame = suspended.return_frame;
    match (suspended.callback.0)(machine, kt, dos, regs) {
        Some(next) => {
            dos.suspended_calls.push(super::SuspendedCall {
                callback: next,
                return_frame,
            });
            park_at_slot_resume(machine, regs);
        }
        None => {
            let completed_flags = machine::guest_flags(regs);
            match return_frame {
                super::DosReturnFrame::Vm86 { ip, cs, flags } => {
                    machine::set_vm86_ip(regs, ip);
                    machine::set_vm86_cs(regs, cs);
                    machine::set_vm86_flags(
                        regs,
                        merge_dos_status(flags as u32, completed_flags),
                    );
                }
                super::DosReturnFrame::Protected { eip, cs, eflags } => {
                    regs.set_ip32(eip);
                    regs.set_cs32(cs as u32);
                    machine::apply_guest_flags(
                        regs,
                        merge_dos_status(eflags, completed_flags),
                    );
                }
            }
        }
    }
    thread::KernelAction::Done
}

// ============================================================================
// RM INT 31h dispatch — routes from the unified CD 31 array by slot number
// ============================================================================

/// Dispatch a kernel-owned DOS/BIOS vector directly (no V86 detour).
///
/// Used by both the V86 stub dispatcher and the DPMI PM soft-int fast path.
/// The caller is responsible for any mode-specific frame housekeeping after
/// the call (V86 stack pop, PM return-frame restore, etc.).
fn dispatch_kernel_syscall<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    vector: u8,
) -> (thread::KernelAction, Option<DosSuspension<A>>) {
    let mut suspension = None;
    let action = match vector {
        0x08 => thread::KernelAction::Done, // timer — handled via VM86 IRQ reflect path
        0x13 => int_13h(machine, regs),
        0x20 => {
            if dos.exec_parent.as_ref().is_some_and(|parent| parent.child_psp == dos.current_psp)
                && let Some(parent) = dos.exec_parent.take()
            {
                dos.last_child_exit_status = 0x0000;
                return (exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/false), None);
            }
            if return_to_psp_parent(machine, dos, regs, 0, None) {
                thread::KernelAction::Done
            } else {
                thread::KernelAction::Exit(0)
            }
        }
        0x21 => int_21h(machine, bios_display, kt, dos, regs, &mut suspension),
        // DOS 1.x TSR entry: DX is the byte offset of the first byte after
        // the resident image, measured from the PSP segment.
        0x27 => {
            let keep = (regs.rdx as u16).div_ceil(16).max(0x10);
            terminate_resident(machine, dos, regs, keep)
        }
        0x33 => int_33h(machine, dos, regs),
        // INT 25h/26h — Absolute Disk Read/Write — return error
        0x25 | 0x26 => {
            regs.rax = (regs.rax & !0xFF00) | (0x02 << 8); // AH=02 address mark not found
            regs.set_flag32(1); // CF=1 error
            thread::KernelAction::Done
        }
        0x28 => thread::KernelAction::Done, // INT 28h — DOS idle
        // INT 29h — DOS FAST_CON_OUT: AL = char to display. Route through
        // the normal console path so VGA and debugcon stay in sync.
        0x29 => {
            let ch = regs.rax as u8; dos_putchar(machine, dos, ch);
            thread::KernelAction::Done
        }
        0x2E => int_2eh(machine, kt, dos, regs),
        0x2F if regs.rax as u16 == 0x7a00 => {
            if let Some(callback) = super::ipx::discover(machine, dos, regs) {
                suspension = Some(DosSuspension { entry: ResumeEntry::Poll(callback) });
            }
            thread::KernelAction::Done
        }
        0x2F => int_2fh(machine, dos, regs),
        0x7A => { super::ipx::api(machine, dos, regs); thread::KernelAction::Done }
        0x67 => {
            if !EMS_ENABLED {
                // No EMS host: AH=80 ("invalid function in handle") so
                // detection probes (AH=40 "get status" / AH=41 "get page
                // frame") see a plain failure instead of getting a stale
                // page-frame paragraph back.
                regs.rax = (regs.rax & !0xFF00) | 0x80_00;
                return (thread::KernelAction::Done, None);
            }
            int_67h(machine, dos, regs)
        }
        _ => thread::KernelAction::Done,
    };
    (action, suspension)
}

/// Dispatch INT 31h from the stub array's VECTOR view (CS == `STUB_SEG`):
/// slot index == INT vector, for all 256. The caller's INT pushed a
/// FLAGS/CS/IP frame. Kernel-DOS vectors route to `dispatch_kernel_syscall`
/// (with the CF/ZF flag dance); every other vector is the personality BIOS —
/// real services or the IRET/EOI defaults (`bios::dispatch`), which own
/// their frame pop. Caller (`syscall`) has already checked CS.
#[inline(never)]
pub(super) fn rm_vector_dispatch<A: crate::Arch>(machine: &mut A, bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    debug_assert_eq!(vm86_cs(regs), STUB_SEG, "rm_vector_dispatch: CS must be STUB_SEG");
    let vector = ((ip.wrapping_sub(2)) / 2) as u8;

    match vector {
        0x13 | 0x20 | 0x21 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2E | 0x2F | 0x33 | 0x67 | 0x7A => {
            // DOS keeps the interrupted register frame in the current PSP.
            // A manually loaded child created with AH=55h returns through
            // its parent's saved frame when it terminates.
            if vector == 0x21 && regs.mode() == crate::UserMode::VM86 {
                let psp_addr = Psp::base(dos.current_psp);
                if machine.read::<[u8; 2]>(psp_addr) == [0xCD, 0x20] {
                    let saved = (u32::from(vm86_ss(regs)) << 16) | u32::from(vm86_sp(regs));
                    machine.write::<u32>(psp_addr + core::mem::offset_of!(Psp, _ss_sp), saved);
                }
            }
            // Restore caller FLAGS into regs so handlers may mutate them
            // (CF/ZF returns); then write back so normal IRET-style pop
            // restores the handler's result to the caller.
            let caller_flags = read_u16(machine, vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4));
            machine::set_vm86_flags(regs, caller_flags as u32);
            let (action, suspension) =
                dispatch_kernel_syscall(machine, bios_display, kt, dos, regs, vector);
            // Exit replaces thread state outright — skip the iret-frame
            // pop entirely. Anything else (Done, ForkExec, Yield, Switch)
            // leaves the issuing thread alive and needs regs.CS:EIP
            // popped to the user's post-INT instruction; otherwise the
            // saved cpu_state retains the kernel stub address and the
            // thread re-traps on its next slice.
            if matches!(action, thread::KernelAction::Exit(_)) {
                return action;
            }
            // Flag-writeback only when we're still in VM86. AH=4C with a
            // PM parent flips mode to PM mid-dispatch via exec_return; in
            // that case regs.SS:SP is the parent's PM stack and the flag
            // writeback would scribble garbage. finish_dos_call below
            // takes the PM branch and merges flags through pop_iret_frame.
            if regs.mode() == crate::UserMode::VM86 && suspension.is_none() {
                let ss = vm86_ss(regs) as u32;
                let off = (vm86_sp(regs) as u32).wrapping_add(4);
                let flags = machine::vm86_flags(regs) as u16;
                write_u16(machine, ss, off, flags);
            }
            // Every interrupt returns now. A suspended call rewrites its own
            // return target to SLOT_RESUME and moves the original frame into
            // its continuation; a synchronous call simply returns normally.
            if let Some(suspension) = suspension {
                suspend_dos_call(machine, dos, regs, suspension);
            } else {
                finish_dos_call(machine, dos, regs);
            }
            action
        }
        _ => super::bios::dispatch(machine, bios_display, dos, regs),
    }
}

/// Dispatch INT 31h from the stub array's CONTROL view (CS ==
/// `CTRL_STUB_SEG`): the far-call entry points and continuation parks the
/// kernel hands out. Slot = (IP - STUB_BASE - 2) / 2 — the same arithmetic
/// as PM's `pm_stub_dispatch` over `SPECIAL_STUB_SEL`. Far-call entries
/// (XMS, save/restore) have a CS/IP frame to pop; everything else either
/// switches mode outright or owns its unwind.
#[inline(never)]
pub(super) fn rm_ctrl_dispatch<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    debug_assert_eq!(vm86_cs(regs), CTRL_STUB_SEG, "rm_ctrl_dispatch: CS must be CTRL_STUB_SEG");
    let slot = ((ip.wrapping_sub(STUB_BASE as u16 + 2)) / 2) as u8;

    let action = match slot {
        SLOT_IPX => { super::ipx::api(machine, dos, regs); thread::KernelAction::Done }
        SLOT_IPX_RETURN => { super::ipx::callback_return(machine, dos, regs); thread::KernelAction::Done }
        SLOT_XMS => xms_dispatch(machine, dos, regs),
        SLOT_DPMI_ENTRY => {
            dpmi::dpmi_enter(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RESUME_CONTINUATION => {
            // Single continuation return. An attached RmCallStruct selects
            // register-block exchange; otherwise this restores the saved state.
            mode_transitions::resume_continuation_from_stub(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RAW_REAL_TO_PM => {
            dpmi::raw_switch_real_to_pm(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CB_ENTRY_BASE..=SLOT_CB_ENTRY_LAST => {
            let cb_idx = (slot - SLOT_CB_ENTRY_BASE) as usize;
            dpmi::callback_entry(machine, dos, regs, cb_idx);
            thread::KernelAction::Done
        }
        SLOT_SAVE_RESTORE => {
            // AX=0305 announces buffer size = 0 to the client, so the
            // save/restore procedures are NOPs (matches CWSDPMI's
            // STUB_NOP). The far-call return frame is popped below by
            // the `matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE)` arm.
            thread::KernelAction::Done
        }
        SLOT_VBE_WINDOW => {
            let ok = super::bios::vbe::vbe_window(
                machine, bios_display, dos, regs,
            );
            regs.rax = (regs.rax & !0xFFFF) | if ok { 0x004F } else { 0x014F };
            thread::KernelAction::Done
        }
        SLOT_COUNTRY_UPCASE => {
            let ch = regs.rax as u8;
            regs.rax = (regs.rax & !0xFF) | country_upcase(ch) as u64;
            thread::KernelAction::Done
        }
        SLOT_KBD_INTERCEPT_RETURN => {
            super::bios::keyboard::int09_intercept_return(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_MOUSE_CB_RET => {
            mouse_callback_return(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RESUME => {
            // Compatibility fallback for an old in-memory stub image. New
            // stubs use HLT and reach the same helper through KE::Hlt.
            poll_suspended_call(machine, kt, dos, regs)
        }
        _ => {
            lib::compact_panic!("VM86: INT 31h unknown control slot {:#04x} CS:IP={:04x}:{:#06x}",
                slot, CTRL_STUB_SEG, ip);
        }
    };

    // Far-call entries that return to their caller: pop the CALL FAR's
    // CS/IP. Mode-switching stubs (DPMI entry, raw switch, callbacks)
    // replace all regs; SLOT_RESUME/SLOT_RESUME_CONTINUATION own their
    // unwind — skip.
    if matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE | SLOT_VBE_WINDOW | SLOT_COUNTRY_UPCASE | SLOT_IPX) {
        let ret_ip = vm86_pop(machine, regs);
        let ret_cs = vm86_pop(machine, regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
    }

    action
}

/// PMDOS INT 21 short-circuit. PM client issued `int 21h`; the host's
/// PM int dispatcher (`deliver_pm_int`) routed to this slot via
/// `dos.pm_vectors[0x21] = (SPECIAL_STUB_SEL, STUB_BASE + SLOT_PMDOS_INT21*2)`,
/// which `dpmi_enter` installs when `client_use32 == false`.
///
/// We service the call directly with PM regs — no `enter_rm`,
/// no mode flip, no bounce buffer. `int_21h` reaches `seg_offset()` which
/// sees `regs.mode() == PM` and resolves DS:DX through the LDT base.
/// On exit `finish_dos_call` does the mode-aware iret-frame pop.
pub(super) fn pmdos_int21_handler<A: crate::Arch>(machine: &mut A, bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // 16-bit DPMI clients issue INT 21h with 16-bit register parameters; the
    // high 16 bits of EAX..EBP are undefined and real (16-bit) DOS never
    // touches them. Zero them for the duration of servicing so every handler's
    // full-width reads (filename/buffer offsets via DS:DX, ES:DI, set-vector
    // offsets, …) see a clean value without per-call masking, then OR the
    // client's original high halves back so they're preserved exactly as DOS
    // would. Skip process-control calls (terminate/TSR/exec/exit): they swap
    // `regs` out to the parent/child, so restoring this client's halves
    // afterward would write into the wrong context.
    let ah = (regs.rax >> 8) as u8;
    let proc_ctrl = matches!(ah, 0x00 | 0x31 | 0x4B | 0x4C);
    let mask16 = !proc_ctrl && dos.dpmi.as_ref().is_some_and(|d| !d.client_use32);
    const HI: u64 = 0xFFFF_0000;
    let saved_hi = if mask16 {
        let s = [
            (regs.rax & HI), (regs.rbx & HI), (regs.rcx & HI), (regs.rdx & HI),
            (regs.rsi & HI), (regs.rdi & HI), (regs.rbp & HI),
        ];
        regs.rax &= !HI; regs.rbx &= !HI; regs.rcx &= !HI; regs.rdx &= !HI;
        regs.rsi &= !HI; regs.rdi &= !HI; regs.rbp &= !HI;
        s
    } else { [0u64; 7] };

    let al_in = regs.rax as u8;
    let mut suspension = None;
    let action = int_21h(machine, bios_display, kt, dos, regs, &mut suspension);

    if mask16 {
        // Pointer-returning calls hand a 32-bit LINEAR through LOW_MEM_SEL
        // (ES:EBX / DS:ESI): there the high half IS the return value, so
        // restoring the client's stale half would corrupt the pointer —
        // DOS/16M's DPMILOAD stores the whole DS:ESI from AH=5D06 (LDS ESI)
        // and dereferenced a stale-half kernel address (DUKE3D music SEGV).
        let keep_ebx = matches!(ah, 0x2F | 0x34 | 0x52);
        let keep_esi = ah == 0x5D && al_in == 0x06;
        regs.rax = (regs.rax & !HI) | saved_hi[0];
        if !keep_ebx {
            regs.rbx = (regs.rbx & !HI) | saved_hi[1];
        }
        regs.rcx = (regs.rcx & !HI) | saved_hi[2];
        regs.rdx = (regs.rdx & !HI) | saved_hi[3];
        if !keep_esi {
            regs.rsi = (regs.rsi & !HI) | saved_hi[4];
        }
        regs.rdi = (regs.rdi & !HI) | saved_hi[5];
        regs.rbp = (regs.rbp & !HI) | saved_hi[6];
    }

    if !matches!(action, thread::KernelAction::Done) { return action; }
    if let Some(suspension) = suspension {
        suspend_dos_call(machine, dos, regs, suspension);
    } else {
        finish_dos_call(machine, dos, regs);
    }
    thread::KernelAction::Done
}

/// PMDOS INT 33h short-circuit. A PM client issued `int 33h`; `pm_vectors[0x33]`
/// routed it here (`SPECIAL_STUB_SEL:STUB_BASE + SLOT_PMDOS_INT33*2`) so the
/// mouse driver runs in PM with the client's PM regs — no RM reflection. This
/// is what makes `regs.mode() == PM` true inside `int_33h` (AX=0Ch records the
/// handler as a PM selector) and `ES:DX` a genuine selector:offset. The mouse
/// subfunctions only touch 16-bit register halves and absolute VGA memory, so
/// no DS:DX buffer translation is needed. On exit `finish_dos_call` does the
/// mode-aware iret-frame pop.
pub(super) fn pmdos_int33_handler<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let _ = int_33h(machine, dos, regs);
    // INT 33h itself never blocks. A pending DOS operation may belong to an
    // outer call interrupted while parked; it must not suppress this nested
    // call's IRET-frame pop.
    finish_dos_call(machine, dos, regs);
    thread::KernelAction::Done
}

fn translate_rm_low_pointer(seg: u16, off: u16) -> (u16, u16) {
    let linear = u32::from(seg) * 16 + u32::from(off);
    // The substitute BIOS fonts live in the first 64 KiB, so 16-bit clients
    // can address them through the existing base-zero low-memory descriptor.
    assert!(linear <= u32::from(u16::MAX), "translated BIOS pointer exceeds 16-bit LOW_MEM_SEL reach");
    (super::dpmi::LOW_MEM_SEL, linear as u16)
}

/// PM INT 10h direct-service path. Video BIOS calls commonly carry buffers in
/// ES:DI or ES:DX; keeping the client in protected mode lets the BIOS handler
/// resolve those selectors through the LDT instead of mistaking them for
/// real-mode paragraphs during generic interrupt reflection.
pub(super) fn pmdos_int10_handler<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    let ax = regs.rax as u16;
    super::bios::video::int10(machine, bios_display, dos, regs);
    // DPMI default reflection does not transfer segment registers between
    // modes. Pointer-bearing BIOS APIs therefore belong to this API translator,
    // not to the real-mode BIOS implementation. AX=1130h returns ES:BP as a
    // real-mode font pointer; convert it before the exit stub reloads ES.
    if ax == 0x1130 {
        let (es, bp) = translate_rm_low_pointer(regs.es as u16, regs.rbp as u16);
        regs.es = u64::from(es);
        regs.rbp = (regs.rbp & !0xFFFF) | u64::from(bp);
    }
    // INT 10h itself never blocks; see the nested-call ownership note above.
    finish_dos_call(machine, dos, regs);
    thread::KernelAction::Done
}

#[cfg(test)]
mod pmdos_translation_tests {
    use super::translate_rm_low_pointer;

    #[test]
    fn font_pointer_becomes_a_protected_mode_low_memory_pointer() {
        assert_eq!(
            translate_rm_low_pointer(0x0339, 0),
            (super::super::dpmi::LOW_MEM_SEL, 0x3390),
        );
    }
}

/// Resume the user after a kernel-serviced DOS call. Mode-aware: the call
/// might have flipped mode (AH=4B EXEC sets up a VM86 child, AH=4C/31
/// restores parent which may be VM86 or PM), so check `regs.mode()`
/// post-handler rather than assuming.
///
///   - VM86: `vm86_iret` restores IP/CS/FLAGS from regs.SS:SP
///     (which is either the child's stack with the entry frame from
///     `exec_program`, or a VM86 parent's stack with the original INT
///     21 frame).
///   - PM: pop the IRET frame `deliver_pm_int` planted on the PM
///     stack and merge DOS status flags so CF/AX results survive.
fn finish_dos_call<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    if regs.mode() == crate::UserMode::VM86 {
        machine::vm86_iret(machine, regs);
    } else {
        let post_handler_status = regs.flags32() & DOS_STATUS_MASK;
        let client_use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
        let (ret_eip, ret_cs, ret_flags) =
            super::mode_transitions::pop_iret_frame(machine, &dos.ldt[..], regs, client_use32);
        regs.set_ip32(ret_eip);
        regs.set_cs32(ret_cs as u32);
        // The planted image is guest-view (`machine::guest_flags`): the
        // client's IF intent rides in the IF slot and the canonical VIF
        // (bit 19) is stripped. Raw-restoring it would clear VIF on every PM
        // DOS call — the caller's virtual IF then sticks at 0 until something
        // else happens to set it (Duke3D's demo loop wedged exactly this way,
        // its tick-wait starved right after an INT 21h). `apply_guest_flags`
        // maps the image's IF slot back to VIF.
        machine::apply_guest_flags(
            regs,
            (ret_flags & !DOS_STATUS_MASK) | post_handler_status,
        );
    }
}

/// INT 31h from real mode user code. AH selects subfunction.
/// On success: AX=0, CF=0. On error: AX=errno (unsigned), CF=1.
#[inline(never)]
pub(super) fn rm_native_syscall<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=0Ch — a one-shot command interpreter announces that it is a
        // launch helper, rather than an independently selectable console.
        // In-process EXEC inside DN must keep DN's outer window selectable.
        0x0C => {
            if dos.exec_parent.is_none() { kt.launcher_psp = dos.current_psp; }
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=01h — launch a program. Normally fork+exec, non-blocking;
        // CH bit 1 replaces this process for a one-shot shell.
        // Input:  DS:DX -> ASCIIZ program filename (no shell parsing here)
        //         ES:BX -> ASCIIZ command tail (use "" for no args; kernel
        //                  installs it at the child's PSP[0x80] in DOS form
        //                  with length byte and trailing CR).
        // Output on success (CF=0): AX=0, BX = child pid.
        // Output on error   (CF=1): AX = errno.
        // Forking caller polls AH=04 (SYNTH_WAITPID) for exit. Shell concerns
        // (parsing, /C, .BAT, built-ins) live entirely in COMMAND.COM.
        0x01 => {
            let read_asciiz = |seg: u16, off: u32, dst: &mut [u8; 128]| -> usize {
                let base = seg_offset(dos, regs, seg, off);
                let mut n = 0;
                while n < 127 {
                    let c = machine.read::<u8>((base + n as u32) as usize);
                    if c == 0 { break; }
                    dst[n] = c;
                    n += 1;
                }
                n
            };
            crate::compact_dbg_println!("synth_fork_exec entry: ds={:04X} dx={:04X} es={:04X} bx={:04X}",
                regs.ds as u16, regs.rdx as u16, regs.es as u16, regs.rbx as u16);
            let mut filename = [0u8; 128];
            let flen = read_asciiz(regs.ds as u16, regs.rdx as u32, &mut filename);
            if flen == 0 {
                regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
            let mut tail = [0u8; 128];
            let tlen = read_asciiz(regs.es as u16, regs.rbx as u32, &mut tail);
            crate::compact_dbg_println!("synth_fork_exec: filename={:?} tail.len={} tail_first8={:02x?}",
                core::str::from_utf8(&filename[..flen]).unwrap_or("<non-utf8>"),
                tlen, &tail[..tlen.min(8)]);
            // CH bit 0 enables the per-launch classic XMS reporting limit.
            // CL carries the child's virtual IOPL — the `IfMode` COMMAND.COM
            // looked up in RETROOS.INI [launch]. It must accept EVERY mode: this used to
            // read `== 3 { 3 } else { 1 }`, from when there were only two, so a
            // `repair` client (2) was silently demoted to spec-strict (1). That
            // is not a slow path, it is a HANG — POPF/IRET stop being honored,
            // virtual IF sticks at 0, and DOOM deadlocks at DMX_Init spinning on
            // a tick that can never arrive. Anything unknown stays conforming.
            let policy = super::LaunchPolicy::from_synth(regs.rcx as u16);
            if regs.rcx & 0x0200 != 0 {
                exec_replace(machine, dos, &filename[..flen], &tail[..tlen], policy, regs)
            } else {
                fork_exec(dos, &filename[..flen], &tail[..tlen], policy, regs, kt)
            }
        }
        // AH=04h — SYNTH_WAITPID: non-blocking probe of child status.
        // BX = child pid (from a prior AH=01).
        // Output:
        //   CF=0, AX=0, BX=child_pid: child has exited; status reaped into
        //                             last_child_exit_status (read via 4Dh).
        //   CF=0, AX=1: child still running, caller should retry / do work.
        //   CF=1, AX=errno: bad pid (-ECHILD, EAGAIN-but-no-children, etc).
        //
        // The focused thread is always running (event loop), so polling here
        // is just a status query — no kernel-side blocking or spurious-wake
        // plumbing. If OSD returns focus to command.com while the child is
        // still alive, AX=1 is itself the signal to release the DOS caller.
        0x04 => {
            // Scans the caller's children → executor (peek + AX/BX/CF writeback).
            let pid = regs.rbx as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::Waitpid }
        }
        // AH=02h — TRACE_ON: enable runtime DOS/DPMI trace gate.
        // AH=03h — TRACE_OFF: disable it.
        // No DPMI 0.9 collision (RM-only path; PM DPMI is dispatched separately).
        0x02 | 0x03 => {
            crate::kernel::startup::set_trace(ah == 0x02);
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=05h — SYNTH_REAP: recycle a zombie child. Display disposition
        // already happened at exit: live transfer on success, parent snapshot
        // restoration on error. BX = child pid.
        0x05 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::Reap }
        }
        // AH=09h — SYNTH_SET_VIOPL: set THIS thread's virtual IOPL (`IfMode`).
        // CL = 1 iopl1 (spec-strict) | 2 repair | 3 iopl3; CH bit 0 = xms32k.
        // CF=0 always.
        //
        // Fork-exec (AH=01h) carries the child's vIOPL in CL because the child
        // is a new thread. An in-process EXEC (INT 21h AH=4Bh) has no new
        // thread to parameterise — it runs on ours — so a shell that runs a
        // .BAT in one address space needs to set the mode itself before each
        // line. `ExecParent` does not save rflags, so the value persists past
        // the child's return; COMMAND.COM restores its own afterwards.
        0x09 => {
            let policy = super::LaunchPolicy::from_synth(regs.rcx as u16);
            super::xms::set_report_limit(dos, policy.xms32k);
            let mode = u64::from(policy.viopl);
            let f = &mut regs.frame.rflags;
            *f = (*f & !(3u64 << 12)) | (mode << 12);
            regs.set_pvi_policy(mode == 1);
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0Ah — SYNTH_LOG_BYTE: mirror AL to the ambient kernel log only.
        // This is the non-VGA half of DOS console output, used by COMMAND.COM
        // for diagnostics from `COPY ... >NUL`: installers keep their screen
        // intact while retroos.log and the in-memory LOG builtin retain the
        // suppressed command output.
        0x0A => {
            log_dos_byte(regs.rax as u8);
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0Bh — SYNTH_TSR_SESSION. AL=0 queries, AL=1 sets.
        // Forked DOS children start with this mark; /B also sets it when
        // launched directly. A nested COMMAND.COM uses ordinary DOS EXEC.
        0x0B => {
            if regs.rax as u8 == 1 { dos.tsr_session = true; }
            regs.rax = (regs.rax & !0xFFFF) | u64::from(dos.tsr_session);
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=06h — SYNTH_VGA_NEEDS_TEXT_MODE: inspect the caller's CURRENT
        // live VGA, after a normal child has handed the adapter back.
        // Output: AL=0 if it is conventional colour 80x25 text; AL=1 if
        // COMMAND.COM should invoke BIOS mode 3 before returning to its caller.
        // This reads mode-defining registers only: the child's exit text,
        // attributes, cursor, palette and display page remain untouched.
        0x06 => {
            let needs_mode3 = !super::machine::vga::is_standard_text(&dos.pc.vga);
            regs.rax = (regs.rax & !0xFF) | needs_mode3 as u64;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=07h — SYNTH_LOG_LINE: read back the in-memory kernel log as DOS
        // display text so a
        // booted system with no serial/debug port (real metal) can surface
        // kernel + dbg_println output. BX = line index (0 = oldest retained),
        // ES:DI = >=512-byte buffer. Output: CX = byte length, CF=0; CF=1 once
        // BX is past the last line (the caller's end-of-log signal). Drives
        // COMMAND.COM's `LOG` builtin (loops BX until CF=1).
        0x07 => {
            let idx = (regs.rbx & 0xFFFF) as usize;
            let mut buf = [0u8; 512];
            match crate::kernel::klog::line(idx, &mut buf) {
                Some(n) => {
                    let mut display = [0u8; 512];
                    let display_len = lib::codepage::current_codepage().display_line(&buf[..n], &mut display);
                    let dest = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32);
                    for (i, &b) in display[..display_len].iter().enumerate() {
                        machine.write::<u8>((dest + i as u32) as usize, b);
                    }
                    regs.rcx = (regs.rcx & !0xFFFF) | (display_len as u64 & 0xFFFF);
                    regs.clear_flag32(1);
                }
                None => regs.set_flag32(1),
            }
            thread::KernelAction::Done
        }
        // AH=08h — SYNTH_SHUTDOWN: park the audio hardware and halt the
        // machine. Never returns to the guest. This is the safe way off real
        // hardware: a raw power-button hold mid-stream wedges the laptop's
        // ALC298 until a cold power cycle, but a codec left with its link in
        // reset rides out any power-off. Drives COMMAND.COM's `SHUTDOWN`
        // builtin.
        //
        // Host::Metal takes halt_forever, NOT shutdown(): shutdown() blind-
        // writes the QEMU/Bochs/VBox poweroff ports (0x604/0xB004/0x4004),
        // and on a real chipset those land in ACPI PM / SMI space with
        // undefined effect — the Blade 14's FCH warm-RESETS, which boots
        // RetroOS again, whose HDA bring-up re-activates the freshly parked
        // codec right before the user cuts power (observed 2026-07-10: that
        // re-wedged the ALC298 the SHUTDOWN command exists to protect).
        0x08 => {
            thread::KernelAction::Shutdown
        }
        // Unknown AH: RetroOS synth space is kernel-owned; anything outside
        // the documented subfunctions is a guest bug. Return AX=errno/CF=1.
        _ => {
            regs.rax = (regs.rax & !0xFFFF) | 1; // invalid function
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::merge_dos_status;

    #[test]
    fn resumed_dos_call_uses_completed_carry_status() {
        // A caller may enter DOS with CF set. A successful deferred operation
        // clears it without changing control flags from the saved frame.
        let saved = 0x0000_0347;
        let completed = saved & !1;
        let merged = merge_dos_status(saved, completed);
        assert_eq!(merged & 1, 0);
        assert_eq!(merged & !super::DOS_STATUS_MASK, saved & !super::DOS_STATUS_MASK);
    }
}
