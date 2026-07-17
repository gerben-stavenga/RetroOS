//! DOS/BIOS interrupt handlers and program loaders.
//!
//! Owns INT 21h (DOS services), INT 13h (disk), INT 2Eh (COMMAND.COM exec),
//! INT 2Fh (multiplex / XMS+DPMI detection), the unified CD-31 stub array
//! and slot dispatch (called from VM86 INT routing and DPMI host code), the
//! low-memory layout (SYSPSP / LoL / SFT / CDS / IRQ stack), and the .COM /
//! MZ .EXE loaders. Everything reachable only from inside the dos personality
//! lives here so `mod.rs` can stay a thin public surface.

extern crate alloc;

use crate::kernel::thread;
use crate::vga;
use crate::Regs;

use super::{
    ExecParent,
    linear, snapshot_env,
    dos_alloc_block, dos_free_block, dos_resize_block,
    dos_set_program_block_owner, dos_keep_resident_block,
    DOS_TRACE_RT,
};
use super::{dpmi, dfs, machine, mode_transitions, xms};
use super::ems::{EMS_ENABLED, EMS_DEVICE_HANDLE, int_67h};
use super::xms::xms_dispatch;
use super::machine::{
    read_u16, write_u16,
    vm86_cs, vm86_ip, vm86_ss, vm86_sp,
    set_vm86_cs, set_vm86_ip,
    vm86_push, vm86_pop,
    clear_bios_keyboard_buffer, pop_bios_keyboard_word,
};

/// Dummy file handle returned for /dev/null semantics.
const NULL_FILE_HANDLE: u16 = 99;

/// .COM entry IP (relative to its PSP segment). Equivalent to `(psp+0x10):0000`.
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer for .COM (top of PSP's 64KB segment)
const COM_SP: u16 = 0xFFFE;
const EXEC_SAVED_IVT_VECTORS: [u8; 11] =
    [0x13, 0x20, 0x21, 0x25, 0x26, 0x28, 0x29, 0x2E, 0x2F, 0x33, 0x67];

const PIT_INPUT_HZ: u64 = 1_193_182;
const BIOS_TICK_DIVISOR: u64 = 65_536;

fn bios_time_of_day<A: crate::Arch>(machine: &mut A) -> (u8, u8, u8, u8) {
    // BIOS tick count at 0040:006C advances at PIT_INPUT_HZ / 65536 Hz.
    // DOS AH=2Ch returns hundredths, so convert through centiseconds instead
    // of approximating the tick rate as 18 Hz. (BDA = guest address space.)
    let ticks = machine.read::<u32>(0x46C) as u64;
    let total_centis = ticks
        .saturating_mul(BIOS_TICK_DIVISOR)
        .saturating_mul(100)
        / PIT_INPUT_HZ;
    let total_secs = total_centis / 100;

    (
        ((total_secs / 3600) % 24) as u8,
        ((total_secs / 60) % 60) as u8,
        (total_secs % 60) as u8,
        (total_centis % 100) as u8,
    )
}

fn cmos_read<A: crate::Arch>(machine: &mut A, index: u8) -> u8 {
    machine.outb(0x70, index);
    machine.inb(0x71)
}

fn cmos_decode(value: u8, binary: bool) -> u8 {
    if binary {
        value
    } else {
        (value & 0x0F).saturating_add((value >> 4).saturating_mul(10))
    }
}

fn day_of_week(mut year: u16, mut month: u8, day: u8) -> u8 {
    // Sakamoto algorithm, returns 0=Sunday .. 6=Saturday (DOS convention).
    const OFFSETS: [u8; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    if month < 3 {
        year = year.saturating_sub(1);
    }
    month = month.clamp(1, 12);
    let y = year as u32;
    ((y + y / 4 - y / 100 + y / 400 + OFFSETS[month as usize - 1] as u32 + day as u32) % 7) as u8
}

fn cmos_date<A: crate::Arch>(machine: &mut A) -> (u16, u8, u8, u8) {
    for _ in 0..10_000 {
        if cmos_read(machine, 0x0A) & 0x80 == 0 {
            break;
        }
    }

    let status_b = cmos_read(machine, 0x0B);
    let binary = status_b & 0x04 != 0;
    let day = cmos_decode(cmos_read(machine, 0x07), binary);
    let month = cmos_decode(cmos_read(machine, 0x08), binary);
    let year_lo = cmos_decode(cmos_read(machine, 0x09), binary);
    let century = cmos_decode(cmos_read(machine, 0x32), binary);

    let year = if (19..=99).contains(&century) {
        century as u16 * 100 + year_lo as u16
    } else if year_lo >= 80 {
        1900 + year_lo as u16
    } else {
        2000 + year_lo as u16
    };

    if !(1980..=2099).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return (2026, 3, 22, 6);
    }

    (year, month, day, day_of_week(year, month, day))
}

/// RTC time of day as binary (hour, minute, second), handling BCD/binary and
/// 12/24-hour CMOS formats. Implausible values collapse to midnight — a
/// wrong-but-sane clock beats letting firmware garbage through.
pub(super) fn rtc_time<A: crate::Arch>(machine: &mut A) -> (u8, u8, u8) {
    for _ in 0..10_000 {
        if cmos_read(machine, 0x0A) & 0x80 == 0 {
            break;
        }
    }
    let status_b = cmos_read(machine, 0x0B);
    let binary = status_b & 0x04 != 0;
    let sec = cmos_decode(cmos_read(machine, 0x00), binary);
    let min = cmos_decode(cmos_read(machine, 0x02), binary);
    let raw_hour = cmos_read(machine, 0x04);
    let mut hour = cmos_decode(raw_hour & 0x7F, binary);
    if status_b & 0x02 == 0 {
        // 12-hour mode: bit 7 = PM, hour 12 wraps to 0.
        hour %= 12;
        if raw_hour & 0x80 != 0 {
            hour += 12;
        }
    }
    if sec > 59 || min > 59 || hour > 23 {
        return (0, 0, 0);
    }
    (hour, min, sec)
}

/// BIOS tick-of-day counter value for "now", read from the RTC — what a real
/// POST stores at 40:6C. Guarded time source: DOS/4GW's 16-bit ticks→time
/// conversion #DEs on a counter whose high word exceeds ~24 hours' worth of
/// ticks, so this never returns more than a day.
pub(super) fn rtc_ticks_today<A: crate::Arch>(machine: &mut A) -> u32 {
    let (hour, min, sec) = rtc_time(machine);
    let secs = (hour as u64) * 3600 + (min as u64) * 60 + sec as u64;
    (secs * PIT_INPUT_HZ / BIOS_TICK_DIVISOR) as u32
}

fn current_dos_timestamp<A: crate::Arch>(machine: &mut A, _regs: &Regs) -> (u16, u16) {
    let (hour, min, sec, _) = bios_time_of_day(machine);
    let (year, month, day, _) = cmos_date(machine);
    let dos_time = ((hour as u16) << 11) | ((min as u16) << 5) | ((sec as u16) / 2);
    let dos_date = ((year.saturating_sub(1980)) << 9) | ((month as u16) << 5) | day as u16;
    (dos_time, dos_date)
}

fn poll_dos_console_char<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> Option<u8> {
    if let Some(ch) = dos.dos_pending_char.take() {
        return Some(ch);
    }

    let word = pop_bios_keyboard_word(machine, regs)?;
    let ascii = word as u8;
    let scan = (word >> 8) as u8;
    if ascii == 0 && scan != 0 {
        dos.dos_pending_char = Some(scan);
    }
    Some(ascii)
}

/// Park the guest at SLOT_RESUME for a blocking I/O wait. Sets CS:IP to
/// the resume stub AND forces IF in the saved EFLAGS so the IRQ that's
/// meant to unblock the wait (kbd, timer) can actually deliver while
/// parked — real DOS BIOS does STI around its wait loops for the same
/// reason. Without this, AH=01/07/08/0A and the SLOT_RESUME re-park loop
/// spin forever after any path that entered the dispatcher with IF
/// cleared (the trap gate at entry, an exception handler, …): pending
/// kbd/timer IRQs queue in the vPIC but `pick_pending_vec` gates them on
/// VIF, and VIF is bit 9 of the saved EFLAGS.
fn park_at_slot_resume<A: crate::Arch>(_machine: &mut A, regs: &mut Regs) {
    machine::set_vm86_cs(regs, CTRL_STUB_SEG);
    machine::set_vm86_ip(regs, ctrl_slot_off(SLOT_RESUME));
    regs.frame.rflags |= machine::VIF_FLAG as u64;
}

// ============================================================================
// RM INT 31h dispatch — routes from the unified CD 31 array by slot number
// ============================================================================

/// Dispatch a kernel-owned DOS/BIOS vector directly (no V86 detour).
///
/// Used by both the V86 stub dispatcher and the DPMI PM soft-int fast path.
/// The caller is responsible for any mode-specific frame housekeeping after
/// the call (V86 stack pop, PM return-frame restore, etc.).
pub(crate) fn dispatch_kernel_syscall<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    vector: u8,
) -> thread::KernelAction {
    match vector {
        0x08 => thread::KernelAction::Done, // timer — handled via VM86 IRQ reflect path
        0x13 => int_13h(regs),
        0x20 => {
            if let Some(parent) = dos.exec_parent.take() {
                dos.last_child_exit_status = 0x0000;
                return exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/false);
            }
            thread::KernelAction::Exit(0)
        }
        0x21 => int_21h(machine, kt, dos, regs),
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
            let ch = regs.rax as u8; dos_putchar(machine, ch);
            thread::KernelAction::Done
        }
        0x2E => int_2eh(machine, kt, dos, regs),
        0x2F => int_2fh(dos, regs),
        0x67 => {
            if !EMS_ENABLED {
                // No EMS host: AH=80 ("invalid function in handle") so
                // detection probes (AH=40 "get status" / AH=41 "get page
                // frame") see a plain failure instead of getting a stale
                // page-frame paragraph back.
                regs.rax = (regs.rax & !0xFF00) | 0x80_00;
                return thread::KernelAction::Done;
            }
            int_67h(machine, dos, regs)
        }
        _ => {
            dos_trace!("dispatch_kernel_syscall: unhandled vector {:#04x}", vector);
            thread::KernelAction::Done
        }
    }
}

/// Dispatch INT 31h from the stub array's VECTOR view (CS == `STUB_SEG`):
/// slot index == INT vector, for all 256. The caller's INT pushed a
/// FLAGS/CS/IP frame. Kernel-DOS vectors route to `dispatch_kernel_syscall`
/// (with the CF/ZF flag dance); every other vector is the personality BIOS —
/// real services or the IRET/EOI defaults (`bios::dispatch`), which own
/// their frame pop. Caller (`syscall`) has already checked CS.
pub(super) fn rm_vector_dispatch<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    debug_assert_eq!(vm86_cs(regs), STUB_SEG, "rm_vector_dispatch: CS must be STUB_SEG");
    let vector = ((ip.wrapping_sub(2)) / 2) as u8;

    match vector {
        0x13 | 0x20 | 0x21 | 0x25 | 0x26 | 0x28 | 0x29 | 0x2E | 0x2F | 0x33 | 0x67 => {
            // Restore caller FLAGS into regs so handlers may mutate them
            // (CF/ZF returns); then write back so normal IRET-style pop
            // restores the handler's result to the caller.
            let caller_flags = read_u16(machine, vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4));
            machine::set_vm86_flags(regs, caller_flags as u32);
            let action = dispatch_kernel_syscall(machine, kt, dos, regs, vector);
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
            if regs.mode() == crate::UserMode::VM86 {
                let ss = vm86_ss(regs) as u32;
                let off = (vm86_sp(regs) as u32).wrapping_add(4);
                let flags = machine::vm86_flags(regs) as u16;
                write_u16(machine, ss, off, flags);
            }
            // The pop is mode-aware: a child of a PM parent (VM86 client of
            // bcc-via-PMDOS) issuing AH=4C runs `exec_return`, which restores
            // the PM parent's SS:SP and clears VM_FLAG. We're then logically
            // resuming a PM caller and must pop the iret-frame
            // `deliver_pm_int` planted on the parent's PM stack, not a
            // VM86-style frame. A pending resume means the handler
            // intentionally parked CS:IP at SLOT_RESUME to block (AH=01/07/
            // 08/0A waiting on the keyboard) — popping here would clobber
            // the redirect; SLOT_RESUME owns the unwind once input arrives.
            if dos.pending_resume.is_none() {
                finish_dos_call(machine, dos, regs);
            }
            action
        }
        _ => super::bios::dispatch(machine, dos, regs),
    }
}

/// Dispatch INT 31h from the stub array's CONTROL view (CS ==
/// `CTRL_STUB_SEG`): the far-call entry points and continuation parks the
/// kernel hands out. Slot = (IP - STUB_BASE - 2) / 2 — the same arithmetic
/// as PM's `pm_stub_dispatch` over `SPECIAL_STUB_SEL`. Far-call entries
/// (XMS, save/restore) have a CS/IP frame to pop; everything else either
/// switches mode outright or owns its unwind.
pub(super) fn rm_ctrl_dispatch<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    debug_assert_eq!(vm86_cs(regs), CTRL_STUB_SEG, "rm_ctrl_dispatch: CS must be CTRL_STUB_SEG");
    let slot = ((ip.wrapping_sub(STUB_BASE as u16 + 2)) / 2) as u8;

    let action = match slot {
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
        SLOT_MOUSE_CB_RET => {
            mouse_callback_return(machine, dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RESUME => {
            // Take the parked closure and call it (FnOnce). It returns
            // `Some(next)` to stay parked (we re-store, rewind IP to the
            // CD 31 so the next fetch re-traps here), or `None` to signal
            // completion (we run the soft-INT iret-frame pop the original
            // slot would have done, unwinding the chain naturally).
            let cb = dos.pending_resume.take()
                .expect("SLOT_RESUME fired without pending_resume");
            match (cb.0)(machine, kt, dos, regs) {
                Some(next) => {
                    dos.pending_resume = Some(next);
                    park_at_slot_resume(machine, regs);
                }
                None => {
                    let ret_ip = vm86_pop(machine, regs);
                    let ret_cs = vm86_pop(machine, regs);
                    let ret_flags = vm86_pop(machine, regs);
                    machine::set_vm86_ip(regs, ret_ip);
                    machine::set_vm86_cs(regs, ret_cs);
                    machine::set_vm86_flags(regs, ret_flags as u32);
                }
            }
            thread::KernelAction::Done
        }
        _ => {
            panic!("VM86: INT 31h unknown control slot {:#04x} CS:IP={:04x}:{:#06x}",
                slot, CTRL_STUB_SEG, ip);
        }
    };

    // Far-call entries that return to their caller: pop the CALL FAR's
    // CS/IP. Mode-switching stubs (DPMI entry, raw switch, callbacks)
    // replace all regs; SLOT_RESUME/SLOT_RESUME_CONTINUATION own their
    // unwind — skip.
    if matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE) {
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
/// We service the call directly with PM regs — no `push_continuation_and_switch_to_rm_side`,
/// no mode flip, no bounce buffer. `int_21h` reaches `linear()` which
/// sees `regs.mode() == PM` and resolves DS:DX through the LDT base.
/// On exit `finish_dos_call` does the mode-aware iret-frame pop.
pub(super) fn pmdos_int21_handler<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
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

    let action = int_21h(machine, kt, dos, regs);

    if mask16 {
        regs.rax = (regs.rax & !HI) | saved_hi[0];
        regs.rbx = (regs.rbx & !HI) | saved_hi[1];
        regs.rcx = (regs.rcx & !HI) | saved_hi[2];
        regs.rdx = (regs.rdx & !HI) | saved_hi[3];
        regs.rsi = (regs.rsi & !HI) | saved_hi[4];
        regs.rdi = (regs.rdi & !HI) | saved_hi[5];
        regs.rbp = (regs.rbp & !HI) | saved_hi[6];
    }

    if !matches!(action, thread::KernelAction::Done) { return action; }
    if dos.pending_resume.is_none() {
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
    if dos.pending_resume.is_none() {
        finish_dos_call(machine, dos, regs);
    }
    thread::KernelAction::Done
}

/// Resume the user after a kernel-serviced DOS call. Mode-aware: the call
/// might have flipped mode (AH=4B EXEC sets up a VM86 child, AH=4C/31
/// restores parent which may be VM86 or PM), so check `regs.mode()`
/// post-handler rather than assuming.
///
///   - VM86: standard `vm86_pop` ×3 — pops FLAGS/CS/IP off regs.SS:SP
///     (which is either the child's stack with the entry frame from
///     `exec_program`, or a VM86 parent's stack with the original INT
///     21 frame).
///   - PM: pop the IRET frame `deliver_pm_int` planted on the PM
///     stack and merge DOS status flags so CF/AX results survive.
fn finish_dos_call<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    // Arithmetic status flags only: CF, PF, AF, ZF, SF, OF. DF (bit 10)
    // is a control flag — handler-set CLD/STD must not leak into caller.
    const STATUS_MASK: u32 = 0x08D5;
    if regs.mode() == crate::UserMode::VM86 {
        let ret_ip = vm86_pop(machine, regs);
        let ret_cs = vm86_pop(machine, regs);
        let ret_flags = vm86_pop(machine, regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
        machine::set_vm86_flags(regs, ret_flags as u32);
    } else {
        let post_handler_status = regs.flags32() & STATUS_MASK;
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
        machine::apply_guest_flags(regs, (ret_flags & !STATUS_MASK) | post_handler_status);
    }
}

/// INT 31h from real mode user code. AH selects subfunction.
/// On success: AX=0, CF=0. On error: AX=errno (unsigned), CF=1.
pub(super) fn rm_native_syscall<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — SYNTH_VGA_TAKE: adopt a (still-zombie) child's farewell
        // screen, then reap the slot.
        // Input:  BX = child pid (must be a zombie of the caller)
        // Output: AX = 0 on success, errno on failure; CF reflects error.
        // The child's on_exit() snapshotted its VGA into its DosState; this
        // call swaps it into ours, restores it to hardware, and recycles
        // the thread slot. Pair with AH=04 SYNTH_WAITPID (peek), then call
        // this once the peek reports "exited".
        0x00 => {
            // Touches a *child* thread (swap its farewell VGA into ours, reap)
            // → defer to the executor, off this thread's `dos`/`kt` borrow.
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::VgaTake }
        }
        // AH=01h — SYNTH_FORK_EXEC: fork+exec program. Non-blocking.
        // Input:  DS:DX -> ASCIIZ program filename (no shell parsing here)
        //         ES:BX -> ASCIIZ command tail (use "" for no args; kernel
        //                  installs it at the child's PSP[0x80] in DOS form
        //                  with length byte and trailing CR).
        // Output on success (CF=0): AX=0, BX = child pid.
        // Output on error   (CF=1): AX = errno.
        // Caller polls AH=04 (SYNTH_WAITPID) for exit. Shell concerns
        // (parsing, /C, .BAT, built-ins) live entirely in COMMAND.COM.
        0x01 => {
            let mut read_asciiz = |seg: u16, off: u32, dst: &mut [u8; 128]| -> usize {
                let base = linear(machine, dos, regs, seg, off);
                let mut n = 0;
                while n < 127 {
                    let c = machine.read::<u8>((base + n as u32) as usize);
                    if c == 0 { break; }
                    dst[n] = c;
                    n += 1;
                }
                n
            };
            crate::dbg_println!("synth_fork_exec entry: ds={:04X} dx={:04X} es={:04X} bx={:04X}",
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
            crate::dbg_println!("synth_fork_exec: filename={:?} tail.len={} tail_first8={:02x?}",
                core::str::from_utf8(&filename[..flen]).unwrap_or("<non-utf8>"),
                tlen, &tail[..tlen.min(8)]);
            // CL carries the child's virtual IOPL — the `IfMode` COMMAND.COM
            // looked up in LOADFIX.CFG. It must accept EVERY mode: this used to
            // read `== 3 { 3 } else { 1 }`, from when there were only two, so a
            // `repair` client (2) was silently demoted to spec-strict (1). That
            // is not a slow path, it is a HANG — POPF/IRET stop being honored,
            // virtual IF sticks at 0, and DOOM deadlocks at DMX_Init spinning on
            // a tick that can never arrive. Anything unknown stays conforming.
            let viopl: u8 = match regs.rcx & 0xFF {
                2 => 2, // IfMode::Repair
                3 => 3, // IfMode::Iopl3
                _ => 1, // IfMode::Iopl1
            };
            fork_exec(dos, &filename[..flen], &tail[..tlen], viopl, regs, kt)
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
        // is just a status query — no kernel-side blocking, no spurious-wake
        // plumbing. command.com loops AH=04 + INT 21h AH=06 (kbd poll) and
        // owns the policy for what to do on user input.
        0x04 => {
            // Scans the caller's children → executor (peek + AX/BX/CF writeback).
            let pid = regs.rbx as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::Waitpid }
        }
        // AH=02h — TRACE_ON: enable runtime DOS/DPMI trace gate.
        // AH=03h — TRACE_OFF: disable it.
        // No DPMI 0.9 collision (RM-only path; PM DPMI is dispatched separately).
        0x02 | 0x03 => {
            DOS_TRACE_RT.store(ah == 0x02, core::sync::atomic::Ordering::Relaxed);
            regs.rax &= !0xFFFF;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=05h — SYNTH_REAP: reap a zombie child without touching VGA.
        // Use after AH=04h waitpid reports CF=0/AX=0 when the caller doesn't
        // want to adopt the child's farewell screen — typically because the
        // child terminated by fault (last_child_exit_status high byte = 0x02)
        // and its VGA state is suspect. BX = child pid.
        0x05 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::Reap }
        }
        // AH=06h — SYNTH_VGA_PEEK_MODE: query the saved VGA state of a
        // zombie child without taking it. BX = child pid.
        // Output: AL = 0 if text mode, 1 if graphics, CF=0; CF=1/AX=errno.
        // GC[6] bit 0 is the VGA Misc/Graphics-Mode register's alpha-graphics
        // select: 0 = text (alphanumeric), 1 = graphics. The caller (typically
        // COMMAND.COM) uses this to decide whether the child's farewell
        // screen is worth adopting — graphics-mode garbage left over after,
        // e.g., a Ctrl-Y abort doesn't compose with the next program's
        // text-mode redraw.
        0x06 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            thread::KernelAction::DosSynthChild { pid, op: thread::DosChildOp::VgaPeekMode }
        }
        // AH=07h — SYNTH_LOG_LINE: read back the in-memory kernel log so a
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
                    let dest = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32);
                    for (i, &b) in buf[..n].iter().enumerate() {
                        machine.write::<u8>((dest + i as u32) as usize, b);
                    }
                    regs.rcx = (regs.rcx & !0xFFFF) | (n as u64 & 0xFFFF);
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
            crate::kernel::hda::emergency_quiesce();
            // Diverging path: the machine halts here, so like the panic
            // handler we don't chase the screen license up the (now
            // irrelevant) call chain — build a writer and render the
            // farewell over whatever the program left on screen.
            let mut screen = crate::vga::Screen::new();
            screen.clear();
            crate::screenln!(screen, "It is now safe to turn off your computer.");
            if crate::kernel::platform::get().host == crate::kernel::platform::Host::Metal {
                machine.halt_forever();
            }
            machine.shutdown();
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

// ============================================================================
// BIOS INT 13h — Disk services
// ============================================================================

fn int_13h(regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let dl = regs.rdx as u8; // drive number
    // For floppy drives (DL < 0x80), return "drive not ready" error.
    // Hard drives (DL >= 0x80) are also unsupported — return error.
    match ah {
        // AH=00h Reset Disk
        0x00 => {
            regs.rax &= !0xFF00; // AH=0 success
            regs.clear_flag32(1);
        }
        // AH=08h Get Drive Parameters
        0x08 => {
            if dl < 0x80 {
                // No floppy drives
                regs.rax = (regs.rax & !0xFF00) | (0x07 << 8); // AH=07 drive parameter activity failed
                regs.set_flag32(1);
            } else {
                // Report a minimal hard drive geometry
                regs.rax &= !0xFF00; // AH=0 success
                regs.rbx &= !0xFF; // BL=drive type (0 for HD)
                regs.rcx = (regs.rcx & !0xFFFF) | ((32 << 8) | 63); // CH=max cyl low, CL=max sect
                regs.rdx = (regs.rdx & !0xFFFF) | ((1 << 8) | 1); // DH=max head, DL=number of drives
                regs.clear_flag32(1);
            }
        }
        // AH=15h Get Disk Type
        0x15 => {
            if dl < 0x80 {
                // No floppy: AH=0 means "no such drive"
                regs.rax &= !0xFF00;
                regs.set_flag32(1);
            } else {
                // Hard disk present
                regs.rax = (regs.rax & !0xFF00) | (0x03 << 8); // AH=03 = hard disk
                regs.clear_flag32(1);
            }
        }
        _ => {
            // All other functions: return error (drive not ready)
            regs.rax = (regs.rax & !0xFF00) | (0x80 << 8); // AH=80h timeout/not ready
            regs.set_flag32(1);
        }
    }
    thread::KernelAction::Done
}

/// Build a `pending_resume` closure for AH=0Ah Buffered Keyboard Input:
/// accumulates typed chars in the caller's DS:DX buffer until Enter is
/// pressed (or the buffer fills, which rings the bell). Backspace erases.
/// On completion, writes count to buffer[1] and appends 0x0D at
/// buffer[count+2], echoes CR+LF. Returns `Some(next)` while still
/// gathering input; `None` once Enter is pressed.
fn buffered_input_resume<A: crate::Arch>(_machine: &mut A, buf_lin: u32, max_chars: u8, count: u8) -> super::ResumeCallback<A> {
    super::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<super::ResumeCallback<A>> {
            let Some(ch) = poll_dos_console_char(machine, dos, regs) else {
                return Some(buffered_input_resume(machine, buf_lin, max_chars, count));
            };
            match ch {
                0x0D => {
                    machine.write::<u8>((buf_lin + 1) as usize, count);
                    machine.write::<u8>((buf_lin + 2 + count as u32) as usize, 0x0D);
                    dos_putchar(machine, 0x0D);
                    dos_putchar(machine, 0x0A);
                    None
                }
                0x08 => {
                    if count > 0 {
                        dos_putchar(machine, 0x08);
                        dos_putchar(machine, b' ');
                        dos_putchar(machine, 0x08);
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count - 1))
                    } else {
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count))
                    }
                }
                _ => {
                    if (count as u32) + 1 < max_chars as u32 {
                        machine.write::<u8>((buf_lin + 2 + count as u32) as usize, ch);
                        dos_putchar(machine, ch);
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count + 1))
                    } else {
                        dos_putchar(machine, 0x07); // bell — no room
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count))
                    }
                }
            }
        }))
}

/// DOS character output — writes via VGA putchar and syncs the BDA cursor
/// Build a `pending_resume` closure that polls the console keyboard.
/// Returns `Some(self)` while waiting; on Some(ch), writes AL=ch (and
/// optionally echoes) then returns `None` to signal completion.
/// `echo`: whether to also `dos_putchar` the read character (AH=01h does
/// this; AH=07h/AH=08h don't).
/// Set up a guest INT 16h AH=00 (wait-for-key) call that returns to the
/// `SLOT_RESUME` stub. Mirrors what a real `INT 16h` does: push FLAGS/CS/IP
/// (the return frame, pointing back at SLOT_RESUME) and enter `IVT[0x16]`.
/// IF is forced so the guest's wait loop can receive the keypress IRQ.
fn launch_int16_read<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let ivt_off = read_u16(machine, 0, 0x16 * 4);
    let ivt_seg = read_u16(machine, 0, 0x16 * 4 + 2);
    let ret_flags = machine::guest_flags_if_on(regs) as u16;
    machine::vm86_push(machine, regs, ret_flags);
    machine::vm86_push(machine, regs, CTRL_STUB_SEG);
    machine::vm86_push(machine, regs, ctrl_slot_off(SLOT_RESUME));
    machine::set_vm86_cs(regs, ivt_seg);
    machine::set_vm86_ip(regs, ivt_off);
    regs.rax &= !0xFF00;                      // AH = 0 (INT 16h AH=00)
    regs.frame.rflags |= machine::VIF_FLAG as u64; // guest VIF=1 while INT 16 runs
}

/// Completion closure for an INT-16-routed DOS char read. Fires once the
/// guest's INT 16h handler IRETs back to SLOT_RESUME, with AX = the key
/// (AL=ASCII, AH=scancode). Applies DOS char-read semantics and returns
/// `None` so SLOT_RESUME pops the original INT 21 return frame.
fn int16_finish_resume<A: crate::Arch>(_machine: &mut A, echo: bool) -> super::ResumeCallback<A> {
    super::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<super::ResumeCallback<A>> {
            let ax = regs.rax as u16;
            let ascii = ax as u8;
            let scan = (ax >> 8) as u8;
            // Extended key: DOS returns AL=0 now, the scancode on the next read.
            if ascii == 0 && scan != 0 {
                dos.dos_pending_char = Some(scan);
            }
            regs.rax = (regs.rax & !0xFF) | ascii as u64;
            if echo && ascii != 0 { dos_putchar(machine, ascii); }
            None
        }))
}

/// position at 0040:0050 so BIOS and programs (like DN) that read the BDA
/// cursor see the correct position.
fn dos_putchar<A: crate::Arch>(machine: &mut A, c: u8) {
    // Mirror DOS console output to the debug log stream alongside VGA.
    crate::vga::debug_byte(c);
    // The BDA cursor (0040:0050/0051) is guest address space — go through the
    // vcpu so the access works under any arch backend, not just a host pointer.
    let col = machine.read::<u8>(0x450) as usize;
    let row = machine.read::<u8>(0x451) as usize;
    let (col, row) = {
        let v = vga::vga();
        v.set_cursor_pos(col, row);
        v.putchar(c);
        v.cursor_pos()
    };
    machine.write::<u8>(0x450, col as u8);
    machine.write::<u8>(0x451, row as u8);
    // Update CRTC hardware cursor so save_from_hardware captures it
    let offset = (row * 80 + col) as u16;
    machine.outb(0x3D4, 0x0E); machine.outb(0x3D5, (offset >> 8) as u8);
    machine.outb(0x3D4, 0x0F); machine.outb(0x3D5, offset as u8);
}

fn psp_struct_seg<A: crate::Arch>(dos: &thread::DosState<A>) -> u16 {
    dos.current_psp
}

fn dos_error_from_errno(err: i32) -> u16 {
    match -err {
        2 => 2,   // file not found
        9 => 6,   // invalid handle
        13 => 5,  // access denied
        24 => 4,  // too many open files
        _ => 1,   // invalid function / generic failure
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    // Skip per-call trace for noisy/chatty AHs: 2C/2A (timer/date polled by
    // running clients), 02/06/09 (character/string output — exception
    // handlers and CRT printf each char separately, splicing trace lines
    // through the user's text output), 40 (write-to-handle — printf in
    // newer CRTs goes here byte-by-byte, same flooding problem as 02/09).
    if !matches!(ah, 0x2C | 0x2A | 0x02 | 0x06 | 0x09 | 0x40) {
        dos_trace!("[INT21] AX={:04x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
            regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
            regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    }
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            let ch = regs.rdx as u8; dos_putchar(machine, ch);
            thread::KernelAction::Done
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                if let Some(ch) = poll_dos_console_char(machine, dos, regs) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40); // clear ZF = char available
                } else {
                    regs.set_flag32(0x40); // set ZF = no char available
                }
            } else {
                dos_putchar(machine, dl);
            }
            thread::KernelAction::Done
        }
        // AH=0x01: STDIN read with echo. Blocks; echoes the char.
        // AH=0x07: Direct STDIN read, no echo, no Ctrl-C check.
        // AH=0x08: STDIN read, no echo (Ctrl-C raises INT 23h — we don't).
        // All three block until a key is available. TC's getch() uses
        // AH=07h; without this AX falls through unmodified and getch()
        // returns garbage (often the AL=0xFF that AH=0Bh just set on
        // kbhit). Block-and-retry via SLOT_RESUME — the parked closure
        // re-polls each event-loop iteration without unwinding the
        // cross-mode chain, so PM clients (DPMI) and VM86 clients use
        // the same path with no risk of corrupting the trampoline IRET
        // frame on rm_dedicated.
        0x01 | 0x07 | 0x08 => {
            let echo = ah == 0x01;
            // Console reads only reach here from VM86: PM/DPMI clients run under
            // an extender that installs its own INT 21h chain, so the pmdos
            // short-circuit never services char input. The INT 16 round-trip
            // below relies on real-mode INT framing (vm86_push, real-mode IVT).
            // Second byte of a prior extended key takes precedence (DOS returns
            // AL=0 then the scancode on the next read).
            if let Some(ch) = dos.dos_pending_char.take() {
                regs.rax = (regs.rax & !0xFF) | ch as u64;
                if echo && ch != 0 { dos_putchar(machine, ch); }
            } else {
                // Real DOS services console input through INT 16h — so do we.
                // Enter the guest's IVT[0x16] (AH=00, wait-for-key) with an
                // iret frame that returns to SLOT_RESUME, where
                // `int16_finish_resume` applies DOS char-read semantics to the
                // returned AX (and pops the original INT 21 frame). A guest that
                // hooks INT 16/INT 9 (and keeps 40:1A empty) is honoured; an
                // unhooked guest just runs the BIOS INT 16h, reading the same
                // 40:1A the old fast path did.
                launch_int16_read(machine, regs);
                dos.pending_resume = Some(int16_finish_resume(machine, echo));
            }
            thread::KernelAction::Done
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let start = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut addr = start;
            loop {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == b'$' { break; }
                dos_putchar(machine, ch);
                addr = addr.wrapping_add(1);
                // Safety limit: cap at 64 KiB from start
                if addr.wrapping_sub(start) > 0xFFFF { break; }
            }
            thread::KernelAction::Done
        }
        // AH=0x0A: Buffered Keyboard Input. DS:DX → buffer.
        //   buffer[0] = max chars including the CR terminator (caller sets)
        //   buffer[1] = count actually typed, NOT including CR (we set)
        //   buffer[2..count+2] = typed characters
        //   buffer[count+2]    = 0x0D (CR terminator)
        // Blocks until Enter; backspace erases. Sokoban's "ENTER YOUR SYSTEM:"
        // prompt is the canonical reason this needs to exist — without it the
        // game spins forever asking for input.
        0x0A => {
            let buf_lin = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let max_chars = machine.read::<u8>((buf_lin) as usize);
            if max_chars == 0 {
                machine.write::<u8>((buf_lin + 1) as usize, 0);
                return thread::KernelAction::Done;
            }
            dos.pending_resume = Some(buffered_input_resume(machine, buf_lin, max_chars, 0));
            park_at_slot_resume(machine, regs);
            thread::KernelAction::Done
        }
        // AH=0x0B: Check Standard Input Status — AL=0 no char, 0xFF char ready.
        // Reflect the BIOS keyboard buffer state (head != tail = char ready).
        // Some Borland C builds back kbhit() with this rather than INT 16h
        // AH=01h, so a hardcoded "no char" silently breaks polling.
        0x0B => {
            let head = read_u16(machine, 0x40, 0x1A);
            let tail = read_u16(machine, 0x40, 0x1C);
            let al = if head != tail { 0xFFu8 } else { 0u8 };
            regs.rax = (regs.rax & !0xFF) | al as u64;
            thread::KernelAction::Done
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                // 16-bit DPMI clients pass a 16-bit handler offset in DX; the
                // high EDX bits are undefined. Storing the full EDX captures
                // stale garbage that later makes the default-stub check in
                // deliver_pm_irq fail, delivering a HW IRQ to VECTOR_STUB:garbage
                // → #GP on the VME 32-bit iret (Jazz Jackrabbit / Borland RTM,
                // which chain the default vector back via AH=35→AH=25).
                let use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
                let off = if use32 { regs.rdx as u32 } else { regs.rdx as u16 as u32 };
                dos.pm_vectors[int_num as usize] = (regs.ds as u16, off);
                return thread::KernelAction::Done;
            }
            let (seg, off) = (regs.ds as u16, regs.rdx as u16);
            write_u16(machine, 0, (int_num as u32) * 4, off);
            write_u16(machine, 0, (int_num as u32) * 4 + 2, seg);
            thread::KernelAction::Done
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => {
                    regs.rdx &= !0xFF; // DL=0: break checking off
                    regs.clear_flag32(1);
                }
                0x01 => {
                    regs.clear_flag32(1); // set break — accepted but ignored
                }
                _ => {
                    dos_trace!("D21 33 unsupported AL={:02X}", al);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x34: Get INDOS Flag pointer — returns ES:BX → byte that is
        // nonzero while DOS is executing. We're never "in DOS" from the
        // guest's perspective (kernel services calls synchronously), so
        // point at a permanently-zero byte inside SYSPSP.
        0x34 => {
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) + INDOS_FLAG_OFFSET as u32) as u64;
            } else {
                regs.es = ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | INDOS_FLAG_OFFSET as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=64-byte buffer)
        // Returns ASCIIZ path without drive letter or leading backslash
        // DL: 0=default, 1=A, 2=B, 3=C
        0x47 => {
            let dl = regs.rdx as u8;
            let drive = if dl == 0 { 3 } else { dl };
            if drive != 3 {
                // Invalid drive (A:/B:)
                regs.rax = (regs.rax & !0xFFFF) | 0x0F;
                regs.set_flag32(1);
            } else {
                let addr = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32) as usize;
                let cwd = dos.dfs.get_cwd();
                machine.copy_to(addr, cwd);
                machine.write::<u8>(addr + cwd.len(), 0);
                dos_trace!("D21 47 DL={:02X} out=\"{}\"",
                    dl, core::str::from_utf8(cwd).unwrap_or("?"));
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | 2; // C:
            thread::KernelAction::Done
        }
        // AH=0x0C: Flush input buffer then execute function in AL
        0x0C => {
            clear_bios_keyboard_buffer(machine, regs);
            dos.dos_pending_char = None;
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                if let Some(ch) = poll_dos_console_char(machine, dos, regs) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40);
                } else {
                    regs.set_flag32(0x40); // ZF=1
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x0D: Disk Reset (flush buffers) — no-op on RAM-backed FS
        0x0D => {
            thread::KernelAction::Done
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            dos.dta = dta;
            thread::KernelAction::Done
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = dos.dta;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | dta as u64;
            } else {
                regs.es = (dta >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (dta & 0x0F) as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 5.00 (DOS/32A and other extenders require >= 4.0)
            regs.rax = (regs.rax & !0xFFFF) | 0x0005; // AL=5 (major), AH=0 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            thread::KernelAction::Done
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                let (sel, off) = dos.pm_vectors[int_num as usize];
                regs.es = sel as u64;
                let client_use32 = dos.dpmi.as_ref().map(|d| d.client_use32).unwrap_or(false);
                if client_use32 {
                    regs.rbx = (regs.rbx & !0xFFFF_FFFF) | off as u64;
                } else {
                    regs.rbx = (regs.rbx & !0xFFFF) | (off & 0xFFFF) as u64;
                }
            } else {
                let off = read_u16(machine, 0, (int_num as u32) * 4);
                let seg = read_u16(machine, 0, (int_num as u32) * 4 + 2);
                regs.es = seg as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | off as u64;
            }
            thread::KernelAction::Done
        }
        // AH=0x38: Get country information — return minimal stub
        //
        // DOS 2.x uses a 32-byte buffer; DOS 3.0+ extended it to 34 bytes.
        // Many programs (including NC 2.0) allocate only 32 bytes, so write
        // field-by-field rather than blindly zeroing 34 bytes.
        0x38 => {
            let addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32) as usize;
            machine.zero(addr, 24); // zero first 24 bytes (through case-map)
            // +00: date format (0 = USA: mm/dd/yy)
            machine.write::<u8>(addr + 2, b'$');     // +02: currency symbol '$\0\0\0\0'
            machine.write::<u8>(addr + 7, b',');     // +07: thousands separator ',\0'
            machine.write::<u8>(addr + 9, b'.');     // +09: decimal separator '.\0'
            machine.write::<u8>(addr + 0x0B, b'/');  // +0B: date separator '/\0'
            machine.write::<u8>(addr + 0x0D, b':');  // +0D: time separator ':\0'
            regs.rbx = (regs.rbx & !0xFFFF) | 1; // country code = 1 (USA)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut path = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr + i as u32) as usize);
                if ch == 0 { break; }
                path[i] = ch;
                i += 1;
            }
            let err = dos.dfs.chdir(&path[..i]);
            dos_trace!("D21 3B raw={:?} err={}",
                core::str::from_utf8(&path[..i]).unwrap_or("<non-utf8>"), err);
            if err != 0 {
                regs.set_flag32(1);
                regs.rax = (regs.rax & !0xFFFF) | err as u64;
            } else {
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x3D: Open file (DS:DX=ASCIIZ filename, AL=access mode)
        0x3D => {
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            // Check for device names (before normalization)
            if EMS_ENABLED && name[..i].eq_ignore_ascii_case(b"EMMXXXX0") {
                regs.rax = (regs.rax & !0xFFFF) | EMS_DEVICE_HANDLE as u64;
                regs.clear_flag32(1);
            } else {
                let raw_name_str = core::str::from_utf8(&name[..i]).unwrap_or("?");
                dos_trace!("D21 3D raw=\"{}\" cwd=\"{}\"", raw_name_str,
                    core::str::from_utf8(dos.dfs.get_cwd()).unwrap_or("?"));
                let fd = match dfs_open_existing(dos, &name[..i]) {
                    Ok(buf) => {
                        let (ref path, len) = buf;
                        dos_trace!("D21 3D open \"{}\"", core::str::from_utf8(&path[..len]).unwrap_or("?"));
                        crate::kernel::vfs::open(&path[..len], &mut kt.fds)
                    }
                    Err(e) => -e,
                };
                if fd >= 0 {
                    // Populate SFT entry and PSP JFT for this handle
                    let size = crate::kernel::vfs::file_size(fd, &kt.fds);
                    sft_set_file(machine, fd as u16, size);
                    if (fd as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), fd as usize, fd as u8); }
                    regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                    regs.clear_flag32(1); // clear carry
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                    regs.set_flag32(1); // set carry
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            let handle = regs.rbx as u16;
            if handle <= 2 || handle == NULL_FILE_HANDLE || (EMS_ENABLED && handle == EMS_DEVICE_HANDLE) {
                if (handle as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), handle as usize, 0xFF); }
                regs.clear_flag32(1);
            } else {
                let rv = crate::kernel::vfs::close(handle as i32, &mut kt.fds);
                if rv >= 0 {
                    sft_clear(machine, handle);
                    if (handle as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), handle as usize, 0xFF); }
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | dos_error_from_errno(rv) as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as u16 as i32;
            let count = regs.rcx as u16 as usize;
            let buf_addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            if handle == 0 {
                // Line-buffered stdin is not implemented.
                regs.rax &= !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == 1 || handle == 2 {
                regs.rax &= !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == NULL_FILE_HANDLE as i32 {
                // Null device EOF.
                regs.rax &= !0xFFFF;
                regs.clear_flag32(1);
            } else if count == 0 || buf_addr == 0 {
                regs.rax &= !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let mut buf = alloc::vec![0u8; count];
                let n = crate::kernel::vfs::read(handle, &mut buf, &kt.fds);
                if n >= 0 {
                    let got = (n as usize).min(count);
                    machine::vga::copy_to_guest(
                        machine,
                        &mut dos.pc.vga,
                        buf_addr as usize,
                        &buf[..got],
                    );
                    // An overlay reload can drop fresh code onto a page that a
                    // prior CLI window was learned at; drop those stale entries so
                    // dpmi::vif re-learns instead of running free on a wrong exit.
                    // PM clients run flat (EIP == linear), so `buf_addr` shares the
                    // site keys' page basis. (Over-invalidation of a data read just
                    // costs one re-learn — retain scans a 64-slot table.)
                    if got > 0
                        && let Some(dpmi) = dos.dpmi.as_mut()
                    {
                        for page in (buf_addr >> 12)..=((buf_addr + got as u32 - 1) >> 12) {
                            dpmi.vif.invalidate_page(page);
                        }
                    }
                    if (n as usize) < count { dos_trace!("D21 3F SHORT h={} req={} got={}", handle, count, n); }
                    let dump_n = (n as usize).min(16);
                    let mut hex = [0u8; 16];
                    hex[..dump_n].copy_from_slice(&buf[..dump_n]);
                    dos_trace!(
                        "D21 3F h={} req={} got={} bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                        handle, count, n,
                        hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6], hex[7],
                        hex[8], hex[9], hex[10], hex[11], hex[12], hex[13], hex[14], hex[15]);
                    regs.rax = (regs.rax & !0xFFFF) | n as u64;
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => {
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut raw = [0u8; 80];
            let mut raw_len = 0;
            while raw_len < 79 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                raw[raw_len] = ch;
                addr += 1;
                raw_len += 1;
            }
            // Resolve DOS path (last component may be a wildcard pattern).
            // Walk the directory components via DFS; append the pattern verbatim.
            let mut abs = [0u8; dfs::DFS_PATH_MAX];
            let alen = match dos.dfs.resolve(&raw[..raw_len], &mut abs) {
                Ok(n) => n,
                Err(_) => {
                    regs.rax = (regs.rax & !0xFFFF) | 3;
                    regs.set_flag32(1);
                    return thread::KernelAction::Done;
                }
            };
            // Split at last '\' to separate dir from pattern.
            let split = abs[..alen].iter().rposition(|&b| b == b'\\').unwrap_or(0);
            let dir_dos = &abs[..split + 1]; // includes trailing '\'
            let pat = &abs[split + 1..alen];
            // Strip trailing '\' for walk (keep "X:\" if dir_dos is exactly that).
            let dir_for_walk = if dir_dos.len() > 3 { &dir_dos[..dir_dos.len() - 1] } else { dir_dos };
            let mut vfs_dir = [0u8; dfs::DFS_PATH_MAX];
            let vlen = match dfs::DfsState::to_vfs_open(dir_for_walk, &mut vfs_dir) {
                Ok(n) => n,
                Err(e) => {
                    regs.rax = (regs.rax & !0xFFFF) | e as u64;
                    regs.set_flag32(1);
                    return thread::KernelAction::Done;
                }
            };
            // Compose "vfs_dir/pat" in dos.find_path.
            let mut pos = 0;
            for &b in &vfs_dir[..vlen] {
                if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
            }
            if vlen > 0 && pos < dos.find_path.len() {
                dos.find_path[pos] = b'/'; pos += 1;
            }
            for &b in pat {
                if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
            }
            dos.find_path_len = pos as u8;
            dos.find_idx = 0;
            find_matching_file(machine, dos, regs)
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            find_matching_file(machine, dos, regs)
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            // If we're in an EXEC'd child, return to parent
            if let Some(parent) = dos.exec_parent.take() {
                // Termination type 00h (normal) | return code in AL.
                dos.last_child_exit_status = (regs.rax as u8) as u16;
                return exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/false);
            }
            let code = regs.rax as u8;
            thread::KernelAction::Exit(code as i32)
        }
        // AH=0x31: Terminate and Stay Resident (TSR)
        // AL = return code, DX = paragraphs to keep (from child's PSP)
        // Like AH=4Ch but the child's memory stays committed: heap_seg
        // remains above the resident block so subsequent parent allocations
        // don't overlap. INT vector hooks the child installed in the IVT
        // remain valid because the IVT is part of the address space and the
        // child's code at heap_seg+offset is still mapped.
        0x31 => {
            if let Some(parent) = dos.exec_parent.take() {
                let keep = regs.rdx as u16;
                // DX is paragraphs from the *child's* PSP, not from parent's
                // heap seg. They differ by the env block + MCB overhead
                // (ENV_PARAS + 2). Using parent.heap_seg here under-counts
                // and leaves the gap between (parent.heap_seg + keep) and
                // the actual resident-block end available for subsequent
                // allocs — overlapping the still-live TSR's image+stack.
                let child_psp_seg = dos.current_psp;
                let resident_top = child_psp_seg.saturating_add(keep);
                // Termination type 03h (TSR) | return code in AL.
                dos.last_child_exit_status = 0x0300 | (regs.rax as u8) as u16;
                // TSR: preserve child's PM env (LDT/dpmi/pm_vectors) so a
                // DPMI host installer like Borland's dpmiload — which
                // calls dpmi_enter, sets up host services, switches back
                // to RM via 0306, then TSRs — leaves the PM session usable
                // by subsequent programs that enter via the raw-switch
                // trampoline.
                let action = exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/true);
                dos_keep_resident_block(machine, dos, regs, child_psp_seg, keep, child_psp_seg);
                dos_trace!("D21 31 TSR kept resident block {:04X}+{:04X} top={:04X}",
                    child_psp_seg, keep, resident_top);
                return action;
            }
            // No exec_parent: cross-thread TSR. Encode termination type 03h
            // | AL into exit_code so the parent's last_child_exit_status
            // (set by exit_thread) carries the TSR marker per AH=4Dh spec.
            let code = regs.rax as u8;
            thread::KernelAction::Exit(0x0300 | (code as i32))
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            match dos_alloc_block(machine, dos, regs, need) {
                Ok(seg) => {
                    regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                    regs.clear_flag32(1);
                    dos_trace!("D21 48 need={:04X} -> seg={:04X} CF=0", need, seg);
                }
                Err(avail) => {
                    regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                    regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                    regs.set_flag32(1);
                    dos_trace!("D21 48 need={:04X} -> avail={:04X} AX=8 CF=1", need, avail);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            let es = regs.es as u16;
            match dos_free_block(machine, dos, regs, es) {
                Ok(()) => regs.clear_flag32(1),
                Err(err) => {
                    regs.rax = (regs.rax & !0xFFFF) | err as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            let es = regs.es as u16;
            let new_paras = regs.rbx as u16;
            match dos_resize_block(machine, dos, regs, es, new_paras) {
                Ok(()) => regs.clear_flag32(1),
                Err((err, max)) => {
                    regs.rax = (regs.rax & !0xFFFF) | err as u64;
                    regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x44: IOCTL (various subfunctions)
        0x44 => {
            let al = regs.rax as u8;
            match al {
                // AL=0x00: Get Device Information (BX=handle, returns DX=info word)
                0x00 => {
                    let handle = regs.rbx as u16;
                    if handle <= 2 {
                        // stdin/stdout/stderr: bit 7=1 (device), bit 0=1 (stdin), bit 1=1 (stdout)
                        let info: u16 = 0x80 | match handle {
                            0 => 0x01, // stdin
                            _ => 0x02, // stdout/stderr
                        };
                        regs.rdx = (regs.rdx & !0xFFFF) | info as u64;
                        regs.clear_flag32(1);
                    } else if EMS_ENABLED && handle == EMS_DEVICE_HANDLE {
                        // EMMXXXX0 device: bit 7=1 (device)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x80;
                        regs.clear_flag32(1);
                    } else {
                        // File handle: bit 7=0 (file), bit 6=1 (not written via
                        // this handle since open), bits 5-0=drive (2=C:).
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0042;
                        regs.clear_flag32(1);
                    }
                }
                // AL=0x07: Check device output status (BX=handle)
                0x07 => {
                    // AL=FFh = ready
                    regs.rax = (regs.rax & !0xFF) | 0xFF;
                    regs.clear_flag32(1);
                }
                // AL=0x08: Check if block device is removable (BL=drive, 0=default,1=A,3=C)
                0x08 => {
                    // AX=0 = removable, AX=1 = fixed
                    regs.rax = (regs.rax & !0xFFFF) | 1; // fixed disk
                    regs.clear_flag32(1); // clear CF
                }
                // AL=0x09: Check if block device is remote (BL=drive)
                0x09 => {
                    regs.rdx &= !0xFFFF; // bit 12=0 = local
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 44 (IOCTL) unsupported AL={:02X} BX={:04X} CX={:04X}",
                        al, regs.rbx as u16, regs.rcx as u16);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C)
        0x0E => {
            regs.rax = (regs.rax & !0xFF) | 3; // AL = number of logical drives
            thread::KernelAction::Done
        }
        // AH=0x3C: Create file (CX=attr, DS:DX=filename) — RAM-backed via VFS overlay
        0x3C => {
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let fd = match dfs_create_path(dos, &name[..i]) {
                Ok((path, len)) => {
                    // Invalidate the parent dir's CI cache so the new file
                    // becomes visible to find_first/find_next on next walk.
                    let parent_end = path[..len].iter().rposition(|&b| b == b'/').unwrap_or(0);
                    dfs::ci::invalidate(&path[..parent_end]);
                    crate::kernel::vfs::create(&path[..len], &mut kt.fds)
                }
                Err(e) => -e,
            };
            if fd >= 0 {
                sft_set_file(machine, fd as u16, 0);
                if (fd as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), fd as usize, fd as u8); }
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.clear_flag32(1);
            } else {
                // Map the VFS errno to a DOS error: EACCES (write-protected --
                // the file/dir isn't RetroOS's to write) is 5 "access denied",
                // the condition every DOS program already knows. Anything else
                // stays 4 "too many open files" (the fd-exhaustion case).
                let ax: u16 = if fd == -5 { 5 } else { 4 };
                regs.rax = (regs.rax & !0xFFFF) | ax as u64;
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            // Handle 1=stdout, 2=stderr
            if handle == 1 || handle == 2 {
                let addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
                for i in 0..count as u32 {
                    let ch = machine.read::<u8>((addr + i) as usize);
                    dos_putchar(machine, ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
                regs.clear_flag32(1);
            } else if handle == NULL_FILE_HANDLE {
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
                regs.clear_flag32(1);
            } else {
                let addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
                let mut data = alloc::vec![0u8; count as usize];
                machine.copy_from(addr as usize, &mut data);
                let n = crate::kernel::vfs::write(machine, handle as i32, &data, &kt.fds);
                if n >= 0 {
                    let size = crate::kernel::vfs::file_size(handle as i32, &kt.fds);
                    sft_set_file(machine, handle, size);
                    regs.rax = (regs.rax & !0xFFFF) | n as u64;
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | dos_error_from_errno(n) as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as u16 as i32;
            if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — always at position 0
                regs.rdx &= !0xFFFF;
                regs.rax &= !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let offset = ((regs.rcx as u16 as u32) << 16 | regs.rdx as u16 as u32) as i32;
                let whence = regs.rax as u8 as i32; // AL = origin
                let result = crate::kernel::vfs::seek(handle, offset, whence, &kt.fds);
                dos_trace!("D21 42 h={} whence={} off={:#X} -> {:#X}", handle, whence, offset as u32, result);
                if result >= 0 {
                    // Return new position in DX:AX
                    regs.rdx = (regs.rdx & !0xFFFF) | ((result as u32 >> 16) as u64);
                    regs.rax = (regs.rax & !0xFFFF) | (result as u16 as u64);
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 6; // invalid handle
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x43: Get/Set File Attributes (AL=0: get, AL=1: set)
        // DS:DX = ASCIIZ filename, CX = attributes (for set)
        0x43 => {
            let al = regs.rax as u8;
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            { let mut hex = [0u8; 32];
              for j in 0..16usize { let b = machine.read::<u8>(addr as usize + j); hex[j*2] = b"0123456789ABCDEF"[(b>>4) as usize]; hex[j*2+1] = b"0123456789ABCDEF"[(b&0xF) as usize]; }
              dos_trace!("D21 43 addr={:08X} hex={}", addr, core::str::from_utf8(&hex).unwrap()); }
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                crate::kernel::vfs::close(fd, &mut kt.fds);
                match al {
                    0 => {
                        // Get attributes: return 0x20 (archive) in CX
                        regs.rcx = (regs.rcx & !0xFFFF) | 0x20;
                        regs.clear_flag32(1);
                    }
                    1 => {
                        regs.rax = (regs.rax & !0xFFFF) | 5; // access denied: attrs are not mutable
                        regs.set_flag32(1);
                    }
                    _ => {
                        regs.rax = (regs.rax & !0xFFFF) | 1;
                        regs.set_flag32(1);
                    }
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x11h FCB FindFirst / AH=0x12h FCB FindNext.
        //
        // The CP/M-era file-find API. Caller fills an "unopened FCB"
        // at DS:DX with `drive(1B) + name(8B,space-pad) + ext(3B,
        // space-pad)`; DOS scans the drive's directory for matches
        // against the (`?`/`*`-wildcarded) pattern, writes a
        // "search FCB" into the current DTA on a hit, returns AL=00
        // (found) or AL=FF (no match). FindNext (AH=12) takes no
        // input — it reads the previous DTA + our find_idx state
        // and continues the scan.
        //
        // Standard FCB layout in DTA after FindFirst:
        //   off 0x00 : drive (1=A, 2=B, ...) of matched file
        //   off 0x01 : 8-byte matched filename, space-padded
        //   off 0x09 : 3-byte matched extension, space-padded
        //   off 0x0C : 2B current block (we set 0)
        //   off 0x0E : 2B record size (we set 128)
        //   off 0x10 : 4B file size (DWORD)
        //   off 0x14 : 2B date (DOS format)
        //   off 0x16 : 2B time (DOS format)
        //   off 0x18 : 8B reserved (DOS-internal next-search state)
        //
        // Extended FCB (caller's FCB[0] == 0xFF): 7-byte prefix
        // before the standard FCB. Marker, 5 reserved, attribute
        // byte. Our DTA write mirrors that prefix.
        0x11 | 0x12 => {
            if ah == 0x11 {
                // FindFirst: parse FCB → compose DOS path → seed
                // dos.find_path / dos.find_idx, then drop into the
                // shared scan loop below.
                let addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
                let (is_ext, fcb_off) = if machine.read::<u8>(addr as usize) == 0xFF { (true, 7) } else { (false, 0) };
                let fcb_base = addr.wrapping_add(fcb_off);
                let drive_byte = machine.read::<u8>((fcb_base) as usize);
                let mut name = [0u8; 8];
                machine.copy_from((fcb_base + 1) as usize, &mut name);
                let mut ext = [0u8; 3];
                machine.copy_from((fcb_base + 9) as usize, &mut ext);
                // Build "[X:][cwd\]NAME[.EXT]" — wildcards stay as-is
                // ('?' for single, real chars for literal). resolve()
                // uppercases and applies cwd.
                let mut dos_path = [0u8; 96];
                let mut dpos = 0;
                if drive_byte != 0 && drive_byte <= 26 {
                    dos_path[0] = b'A' - 1 + drive_byte;
                    dos_path[1] = b':';
                    dos_path[2] = b'\\';
                    dpos = 3;
                }
                let mut k = 0;
                for &c in &name { if c == b' ' { break; } dos_path[dpos] = c; dpos += 1; k += 1; }
                let _ = k;
                let mut has_ext = false;
                for &c in &ext { if c != b' ' { has_ext = true; break; } }
                if has_ext {
                    dos_path[dpos] = b'.'; dpos += 1;
                    for &c in &ext { if c == b' ' { break; } dos_path[dpos] = c; dpos += 1; }
                }
                let mut abs = [0u8; dfs::DFS_PATH_MAX];
                let alen = match dos.dfs.resolve(&dos_path[..dpos], &mut abs) {
                    Ok(n) => n,
                    Err(_) => {
                        regs.rax = (regs.rax & !0xFF) | 0xFF;
                        return thread::KernelAction::Done;
                    }
                };
                let split = abs[..alen].iter().rposition(|&b| b == b'\\').unwrap_or(0);
                let dir_dos = &abs[..split + 1];
                let pat = &abs[split + 1..alen];
                let dir_for_walk = if dir_dos.len() > 3 { &dir_dos[..dir_dos.len() - 1] } else { dir_dos };
                let mut vfs_dir = [0u8; dfs::DFS_PATH_MAX];
                let vlen = match dfs::DfsState::to_vfs_open(dir_for_walk, &mut vfs_dir) {
                    Ok(n) => n,
                    Err(_) => {
                        regs.rax = (regs.rax & !0xFF) | 0xFF;
                        return thread::KernelAction::Done;
                    }
                };
                let mut pos = 0;
                for &b in &vfs_dir[..vlen] {
                    if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
                }
                if vlen > 0 && pos < dos.find_path.len() {
                    dos.find_path[pos] = b'/'; pos += 1;
                }
                for &b in pat {
                    if pos < dos.find_path.len() { dos.find_path[pos] = b; pos += 1; }
                }
                dos.find_path_len = pos as u8;
                dos.find_idx = 0;
                // Stash the drive number + extended-marker for the
                // DTA write below. Drive 0 in the FCB means "current",
                // which our DTA result must report as the actual drive.
                dos.fcb_search_drive = if drive_byte == 0 {
                    // Default drive: derive from resolved abs path.
                    if alen >= 2 && abs[1] == b':' { abs[0] - b'A' + 1 } else { 3 /* C: */ }
                } else { drive_byte };
                dos.fcb_search_ext = is_ext;
            }
            // Shared FindFirst/FindNext scan: walk DFS CI cache from
            // dos.find_idx, return on first match.
            let path_len = dos.find_path_len as usize;
            let full = &dos.find_path[..path_len];
            let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
            let dir = &full[..split];
            let mut pat_buf = [0u8; 32];
            let plen = (path_len - split).min(pat_buf.len());
            pat_buf[..plen].copy_from_slice(&full[split..split + plen]);
            let pat = &pat_buf[..plen];
            let dir_for_ci = if dir.last() == Some(&b'/') { &dir[..dir.len() - 1] } else { dir };
            let mut idx = dos.find_idx as usize;
            let drive = dos.fcb_search_drive;
            let is_ext = dos.fcb_search_ext;
            loop {
                match dfs::ci::entry_at(dir_for_ci, idx) {
                    Some((alias, size, is_dir)) => {
                        idx += 1;
                        if !dos_wildcard_match(pat, alias) { continue; }
                        dos.find_idx = idx as u16;
                        // Write search FCB into DTA. Layout above.
                        let dta = dos.dta as usize;
                        // Zero the (extended-prefix + 32-byte) area first.
                        let total = if is_ext { 7 + 32 } else { 32 };
                        machine.zero(dta, total);
                        let fcb_base = if is_ext {
                            machine.write::<u8>(dta, 0xFF);
                            machine.write::<u8>(dta + 6, if is_dir { 0x10 } else { 0x20 });
                            dta + 7
                        } else {
                            dta
                        };
                        machine.write::<u8>(fcb_base, drive);
                        // Split alias (e.g. "CIV.EXE" or "AUTOEXEC.BAT")
                        // into 8-char name + 3-char ext, space-padded.
                        let mut name_buf = [b' '; 8];
                        let mut ext_buf = [b' '; 3];
                        let dot = alias.iter().position(|&c| c == b'.');
                        let (n, e) = match dot {
                            Some(d) => (&alias[..d], &alias[d + 1..]),
                            None => (alias, &[][..]),
                        };
                        for (i, &c) in n.iter().take(8).enumerate() {
                            name_buf[i] = c.to_ascii_uppercase();
                        }
                        for (i, &c) in e.iter().take(3).enumerate() {
                            ext_buf[i] = c.to_ascii_uppercase();
                        }
                        machine.copy_to(fcb_base + 1, &name_buf);
                        machine.copy_to(fcb_base + 9, &ext_buf);
                        // current block = 0 (offsets 0x0C-0x0D), record
                        // size = 128 (0x0E-0x0F), file size at 0x10-0x13.
                        machine.write::<u16>(fcb_base + 0x0E, 128);
                        machine.write::<u32>(fcb_base + 0x10, size);
                        // Date = 1980-01-01 (0x0021), time = 00:00:00.
                        machine.write::<u16>(fcb_base + 0x14, 0x0021);
                        machine.write::<u16>(fcb_base + 0x16, 0);
                        regs.rax &= !0xFF;
                        return thread::KernelAction::Done;
                    }
                    None => {
                        regs.rax = (regs.rax & !0xFF) | 0xFF;
                        return thread::KernelAction::Done;
                    }
                }
            }
        }
        // AH=0x29: Parse filename into FCB (DS:SI=string, ES:DI=FCB)
        // AL bits: 0=skip leading separators, 1=set drive only if specified,
        //          2=set filename only if specified, 3=set extension only if specified
        0x29 => {
            let ds_base = linear(machine, dos, regs, regs.ds as u16, 0);
            let mut si = regs.rsi as u16;
            let fcb = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32);

            // Skip leading whitespace/separators if bit 0 set
            let flags = regs.rax as u8;
            if flags & 1 != 0 {
                loop {
                    let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                    if ch == b' ' || ch == b'\t' || ch == b';' || ch == b',' {
                        si += 1;
                    } else {
                        break;
                    }
                }
            }

            // Zero-fill the 11-byte name field in FCB (drive byte at +0, name at +1..+12)
            machine.copy_to((fcb + 1) as usize, &[b' '; 11]);

            // Check for drive letter (e.g., "C:")
            let ch0 = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
            let ch1 = machine.read::<u8>((ds_base.wrapping_add(si as u32 + 1)) as usize);
            if ch1 == b':' && ch0.is_ascii_alphabetic() {
                machine.write::<u8>((fcb) as usize, ch0.to_ascii_uppercase() - b'A' + 1);
                si += 2;
            } else {
                machine.write::<u8>((fcb) as usize, 0); // default drive
            }

            // Parse filename (up to 8 chars) into FCB+1
            let mut pos = 0u32;
            loop {
                let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                if ch == b'.' || ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                if ch == b'*' {
                    while pos < 8 { machine.write::<u8>((fcb + 1 + pos) as usize, b'?'); pos += 1; }
                    si += 1;
                    break;
                }
                if pos < 8 {
                    machine.write::<u8>((fcb + 1 + pos) as usize, ch.to_ascii_uppercase());
                    pos += 1;
                }
                si += 1;
            }

            // Parse extension (up to 3 chars) into FCB+9
            let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
            if ch == b'.' {
                si += 1;
                pos = 0;
                loop {
                    let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                    if ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                    if ch == b'*' {
                        while pos < 3 { machine.write::<u8>((fcb + 9 + pos) as usize, b'?'); pos += 1; }
                        si += 1;
                        break;
                    }
                    if pos < 3 {
                        machine.write::<u8>((fcb + 9 + pos) as usize, ch.to_ascii_uppercase());
                        pos += 1;
                    }
                    si += 1;
                }
            }

            // Update SI to point past parsed name
            regs.rsi = (regs.rsi & !0xFFFF) | si as u64;
            // AL=0: no wildcards, AL=1: wildcards present, AL=0xFF: drive invalid
            let mut fcb_name = [0u8; 11];
            machine.copy_from((fcb + 1) as usize, &mut fcb_name);
            let has_wildcards = fcb_name.contains(&b'?');
            regs.rax = (regs.rax & !0xFF) | if has_wildcards { 1 } else { 0 };
            thread::KernelAction::Done
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            exec_program(machine, kt, dos, regs)
        }
        // AH=2Ah — Get System Date
        0x2A => {
            let (year, month, day, dow) = cmos_date(machine);
            regs.rcx = (regs.rcx & !0xFFFF) | year as u64; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | ((month as u64) << 8) | day as u64; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | dow as u64; // AL = day of week (0=Sun, 6=Sat)
            thread::KernelAction::Done
        }
        // AH=2Ch — Get System Time
        0x2C => {
            let (hours, mins, secs, centisecs) = bios_time_of_day(machine);
            regs.rcx = (regs.rcx & !0xFFFF) | ((hours as u64) << 8) | mins as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | ((secs as u64) << 8) | centisecs as u64;
            thread::KernelAction::Done
        }
        // AH=0x57: Get/Set File Date and Time (AL=0: get, AL=1: set, BX=handle)
        0x57 => {
            let al = regs.rax as u8;
            if al == 0 {
                // DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2
                // DOS date: bits 15-9=year-1980, 8-5=month, 4-0=day
                let (time, date) = current_dos_timestamp(machine, regs);
                regs.rcx = (regs.rcx & !0xFFFF) | time as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | date as u64;
                regs.clear_flag32(1);
            } else if al == 1 {
                regs.rax = (regs.rax & !0xFFFF) | 5; // access denied: timestamps are not mutable
                regs.set_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 1;
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x60: Canonicalize path (DS:SI=input, ES:DI=output buffer)
        0x60 => {
            let src = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32);
            let dst = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32);
            // Read input path
            let mut name = [0u8; 128];
            let mut len = 0;
            while len < 127 {
                let ch = machine.read::<u8>((src + len as u32) as usize);
                if ch == 0 { break; }
                name[len] = ch;
                len += 1;
            }
            {
                let cs = regs.frame.cs as u16;
                let ip = regs.frame.rip as u32;
                dos_trace!("D21 60 in=\"{}\" cs:ip={:04X}:{:08X}",
                    core::str::from_utf8(&name[..len]).unwrap_or("?"), cs, ip);
            }
            // Build canonical path: if no drive letter, prepend "C:\"
            let mut out = [0u8; 128];
            let mut pos;
            if len >= 2 && name[1] == b':' {
                // Already has drive letter — uppercase it
                out[0] = name[0].to_ascii_uppercase();
                out[1] = b':';
                out[2] = b'\\';
                pos = 3;
                let skip = if len > 2 && (name[2] == b'/' || name[2] == b'\\') { 3 } else { 2 };
                for item in name.iter().take(len).skip(skip) {
                    if pos >= 127 { break; }
                    out[pos] = if *item == b'/' { b'\\' } else { item.to_ascii_uppercase() };
                    pos += 1;
                }
            } else {
                // Relative — prepend C:\ + CWD (DFS already in DOS form).
                out[0] = b'C'; out[1] = b':'; out[2] = b'\\';
                pos = 3;
                let cwds = dos.dfs.get_cwd();
                for &ch in cwds {
                    if pos >= 127 { break; }
                    out[pos] = ch;
                    pos += 1;
                }
                if pos > 3 && out[pos - 1] != b'\\' { out[pos] = b'\\'; pos += 1; }
                for item in name.iter().take(len) {
                    if pos >= 127 { break; }
                    out[pos] = if *item == b'/' { b'\\' } else { item.to_ascii_uppercase() };
                    pos += 1;
                }
            }
            out[pos] = 0;
            // Write to ES:DI
            machine.copy_to(dst as usize, &out[..pos + 1]);
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x52: Get List of Lists (returns ES:BX → DOS internal structure)
        // Programs read [ES:BX - 2] WORD = first MCB segment (the chain
        // head). LOL doesn't need to be paragraph-aligned: ES:BX expresses
        // any linear address.
        0x52 => {
            let lol_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, lol) as u32;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | lol_addr as u64;
            } else {
                regs.es = (lol_addr >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (lol_addr & 0xF) as u64;
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x36: Get Disk Free Space (DL=drive, 0=default,1=A,2=B,3=C...)
        // Returns: AX=sectors/cluster, BX=free clusters, CX=bytes/sector, DX=total clusters
        // On error: AX=0xFFFF
        0x36 => {
            let dl = regs.rdx as u8;
            // Map drive: 0=default(C), 1=A, 2=B, 3=C
            let drive = if dl == 0 { 3 } else { dl };
            if drive == 3 {
                // C: drive — report fake 16MB disk, 8MB free
                // 512 bytes/sector, 8 sectors/cluster (4KB), 4096 total clusters = 16MB
                regs.rax = (regs.rax & !0xFFFF) | 8;    // AX = sectors per cluster
                regs.rbx = (regs.rbx & !0xFFFF) | 2048; // BX = free clusters
                regs.rcx = (regs.rcx & !0xFFFF) | 512;  // CX = bytes per sector
                regs.rdx = (regs.rdx & !0xFFFF) | 4096; // DX = total clusters
            } else {
                // A:/B: or unknown — invalid drive
                regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
            }
            thread::KernelAction::Done
        }
        // AH=0x37: Get/set switch character. DOS 5+ fixes it at '/' (set is a
        // no-op). Returning DL='/' is load-bearing: the Borland/Microsoft C
        // runtime uses '/' as the *path separator* whenever the switch char is
        // not '/'. A missing/error answer (our old catch-all returned AX=1,CF=1)
        // made bc.exe emit forward-slash paths everywhere — e.g. the TASM object
        // spec "OBJ/H_LDIV.OBJ", where TASM parses the "/H" as the help switch
        // and prints its syntax screen instead of assembling (Wolf3D .PRJ build).
        0x37 => {
            match regs.rax as u8 {
                0x00 => {
                    regs.rax &= !0xFF;                       // AL=00: success
                    regs.rdx = (regs.rdx & !0xFF) | b'/' as u64;
                    regs.clear_flag32(1);
                }
                0x01 => {
                    regs.rax &= !0xFF;                       // accept set, no-op
                    regs.clear_flag32(1);
                }
                _ => {
                    regs.rax = (regs.rax & !0xFF) | 0xFF;    // invalid subfunction
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x67: Set Handle Count
        0x67 => {
            let requested = regs.rbx as u16;
            if requested <= 20 {
                Psp::set_max_files(machine, psp_struct_seg(dos), requested);
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory for an external JFT
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x41: Delete file (DS:DX=filename)
        0x41 => {
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => {
                    // Invalidate parent dir CI cache before delete so a stale
                    // alias→missing-file mapping doesn't confuse later lookups.
                    let parent_end = path[..len].iter().rposition(|&b| b == b'/').unwrap_or(0);
                    dfs::ci::invalidate(&path[..parent_end]);
                    let rv = crate::kernel::vfs::delete(&path[..len]);
                    if rv >= 0 {
                        regs.clear_flag32(1);
                    } else {
                        regs.rax = (regs.rax & !0xFFFF) | 5;
                        regs.set_flag32(1);
                    }
                }
                Err(e) => {
                    regs.rax = (regs.rax & !0xFFFF) | e as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x59: Get Extended Error Information
        0x59 => {
            // Return "file not found" as default extended error
            regs.rax = (regs.rax & !0xFFFF) | 2; // AX = error code (file not found)
            regs.rbx = (regs.rbx & !0xFFFF) | ((1 << 8) | 2); // BH=1 (class: out of resource), BL=2 (action: abort)
            regs.rcx &= !0xFFFF; // CH=0 (locus: unknown)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x58: DOS 5+ allocation strategy / UMB link state
        0x58 => {
            let al = regs.rax as u8;
            match al {
                0x00 => {
                    regs.rax = (regs.rax & !0xFFFF) | dos.alloc_strategy as u64;
                    regs.clear_flag32(1);
                }
                0x01 => {
                    dos.alloc_strategy = regs.rbx as u16;
                    regs.clear_flag32(1);
                }
                0x02 => {
                    regs.rax = (regs.rax & !0xFFFF) | dos.umb_link_state as u64;
                    regs.clear_flag32(1);
                }
                0x03 => {
                    dos.umb_link_state = regs.rbx as u16;
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 58 unsupported AL={:02X}", al);
                    regs.rax = (regs.rax & !0xFFFF) | 1;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x4D: Get Return Code of Subprocess
        // Returns AL = code passed to AH=4Ch/AH=31h, AH = termination type
        // (00h normal, 01h Ctrl-Break, 02h critical error, 03h TSR).
        0x4D => {
            let status = dos.last_child_exit_status;
            regs.rax = (regs.rax & !0xFFFF) | status as u64;
            thread::KernelAction::Done
        }
        // AH=0x50: Set Current Process ID (BX = new PSP). In PM, client
        // passes a selector cached in `psp_cache` (HDPMI behavior); reverse
        // it to a segment before storing. If BX isn't a known selector
        // treat it as a segment value directly (matches HDPMI's
        // `bx_sel2segm` fallthrough).
        0x50 => {
            let bx = regs.rbx as u16;
            let in_pm = regs.mode() != crate::UserMode::VM86;
            let seg = if in_pm {
                super::dpmi::psp_sel_to_segment(dos, bx).unwrap_or(bx)
            } else {
                bx
            };
            dos.current_psp = seg;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x51 / AH=0x62: Get PSP. In PM, return the per-segment
        // selector from `psp_cache` (HDPMI's getpspsel); the client can
        // load it into ES and address its PSP. In RM, return the raw
        // segment.
        0x51 | 0x62 => {
            let in_pm = regs.mode() != crate::UserMode::VM86;
            let bx = if in_pm {
                super::dpmi::get_or_alloc_psp_sel(dos, dos.current_psp)
            } else {
                dos.current_psp
            };
            regs.rbx = (regs.rbx & !0xFFFF) | bx as u64;
            regs.clear_flag32(1);
            let cs = regs.frame.cs as u16;
            let ip = regs.frame.rip as u32;
            dos_trace!("D21 5x -> BX={:04X} cs:ip={:04X}:{:08X}",
                bx, cs, ip);
            thread::KernelAction::Done
        }
        // AH=0x6C: Extended Open/Create (DOS 4.0+)
        // BX=mode, CX=attributes, DX=action, DS:SI=ASCIIZ filename
        // Action: bit0=open-if-exists, bit1=replace-if-exists, bit4=create-if-not-exists
        0x6C => {
            let action = regs.rdx as u16;
            let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let mut i = 0;
            while i < dfs::DFS_PATH_MAX - 1 {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let open_exists = action & 0x01 != 0;
            let replace_exists = action & 0x02 != 0;
            let create_not = action & 0x10 != 0;

            // Try open first
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                if open_exists {
                    let size = crate::kernel::vfs::file_size(fd, &kt.fds);
                    sft_set_file(machine, fd as u16, size);
                    if (fd as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), fd as usize, fd as u8); }
                    regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | 1; // CX=1: file opened
                    regs.clear_flag32(1);
                } else if replace_exists {
                    crate::kernel::vfs::close(fd, &mut kt.fds);
                    let new_fd = match dfs_create_path(dos, &name[..i]) {
                        Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                        Err(e) => -e,
                    };
                    if new_fd >= 0 {
                        sft_set_file(machine, new_fd as u16, 0);
                        if (new_fd as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), new_fd as usize, new_fd as u8); }
                        regs.rax = (regs.rax & !0xFFFF) | new_fd as u64;
                        regs.rcx = (regs.rcx & !0xFFFF) | 3; // CX=3: file replaced
                        regs.clear_flag32(1);
                    } else {
                        regs.rax = (regs.rax & !0xFFFF) | dos_error_from_errno(new_fd) as u64;
                        regs.set_flag32(1);
                    }
                } else {
                    crate::kernel::vfs::close(fd, &mut kt.fds);
                    regs.rax = (regs.rax & !0xFFFF) | 80; // file exists
                    regs.set_flag32(1);
                }
            } else if create_not {
                let new_fd = match dfs_create_path(dos, &name[..i]) {
                    Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                    Err(e) => -e,
                };
                if new_fd >= 0 {
                    sft_set_file(machine, new_fd as u16, 0);
                    if (new_fd as usize) < 20 { Psp::set_jft(machine, psp_struct_seg(dos), new_fd as usize, new_fd as u8); }
                    regs.rax = (regs.rax & !0xFFFF) | new_fd as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | 2; // CX=2: file created
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | dos_error_from_errno(new_fd) as u64;
                    regs.set_flag32(1);
                }
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x5D: Server function — subfunction in AL
        0x5D => {
            let al = regs.rax as u8;
            match al {
                // AL=06: Get DOS Swappable Data Area address
                //   Returns DS:SI→ swap area, CX=total size, DX=size that must
                //   always be swapped. Point at SYSPSP (zeroed) with a nominal
                //   size; DPMILOAD just needs a plausible pointer.
                0x06 => {
                    let syspsp_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32;
                    if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                        regs.ds = dpmi::LOW_MEM_SEL as u64;
                        regs.rsi = (regs.rsi & !0xFFFF) | syspsp_addr as u64;
                    } else {
                        regs.ds = (syspsp_addr >> 4) as u64;
                        regs.rsi &= !0xFFFF;
                    }
                    let sz = core::mem::size_of::<Psp>() as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | sz;
                    regs.rdx = (regs.rdx & !0xFFFF) | sz;
                    regs.clear_flag32(1);
                }
                _ => {
                    dos_trace!("D21 5D unsupported AL={:02X}", al);
                    regs.rax = (regs.rax & !0xFFFF) | 1; // invalid function
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        0x71 => {
            // LFN (Long File Name) API — not supported.
            // Return AX=7100h so DJGPP/libc knows to fall back to short-name DOS calls.
            regs.rax = (regs.rax & !0xFFFF) | 0x7100;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
        0xFF => {
            dos_trace!("VM86: INT 21h AX={:04X} BX={:04X}", regs.rax as u16, regs.rbx as u16);
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
        _ => {
            dos_trace!("VM86: unhandled INT 21h AH={:#04x} AX={:04X}", ah, regs.rax as u16);
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            thread::KernelAction::Done
        }
    }
}

// /// DOS INT 21h/4B — Load and Execute Program
// ///
// /// Try to open a program file via VFS. If the name has no extension (no dot),
// /// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Eh — COMMAND.COM internal execute
// ============================================================================

fn int_2eh<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
    // Treat as COMMAND.COM /C — fork-exec the program in a fresh address space.
    let addr = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32);
    let len = machine.read::<u8>((addr) as usize) as usize;
    let mut cmd = [0u8; 128];
    let copy = len.min(127);
    machine.copy_from((addr + 1) as usize, &mut cmd[..copy]);
    let mut start = 0;
    while start < copy && cmd[start] == b' ' { start += 1; }
    let mut end = start;
    while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
    if end <= start { return thread::KernelAction::Done; }

    // Shift the program name to the start of the buffer.
    let plen = end - start;
    cmd.copy_within(start..end, 0);
    fork_exec(dos, &cmd[..plen], b"", 1, regs, kt)
}

// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS + DPMI detection)
// ============================================================================

/// Fill regs with DPMI 0.90 installation-check reply (shared by INT 2F/1687h
/// and DOS/32A's INT 21h AX=FF87h probe).
fn dpmi_install_check(regs: &mut Regs) {
    regs.rax &= !0xFFFF; // AX=0: DPMI available
    regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // BX bit0 = 32-bit supported
    regs.rcx = (regs.rcx & !0xFF) | 0x03; // CL = 386
    regs.rdx = (regs.rdx & !0xFFFF) | 0x005A; // DX = DPMI 0.90
    regs.rsi &= !0xFFFF; // SI = 0 paragraphs needed
    regs.es = CTRL_STUB_SEG as u64;
    regs.rdi = (regs.rdi & !0xFFFF) | ctrl_slot_off(SLOT_DPMI_ENTRY) as u64;
}

fn int_2fh<A: crate::Arch>(_dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
    dos_trace!("D2F {:04X} BX={:04X} CX={:04X} DX={:04X} cs:ip={:04X}:{:04X}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.code_seg(), regs.ip32() as u16);
    match ax {
        // AX=1687h — DPMI installation check
        0x1687 => {
            dpmi_install_check(regs);
            thread::KernelAction::Done
        }
        // AX=168Ah — DPMI 1.0 Get Vendor-Specific API Entry Point.
        // We do not implement any vendor-specific entry points. Return
        // failure; AL=0 is the success value for this multiplex call.
        0x168A => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL!=0: unsupported
            thread::KernelAction::Done
        }
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            thread::KernelAction::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = CTRL_STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | ctrl_slot_off(SLOT_XMS) as u64;
            thread::KernelAction::Done
        }
        _ => {
            // Unhandled — return "not installed" (AL unchanged). Multiplex
            // probes use this as the protocol, so it's not always a bug —
            // log so a missing-real-TSR bug doesn't hide as "silent miss".
            dos_trace!("D2F unsupported AX={:04X} (returning not-installed)", ax);
            thread::KernelAction::Done
        }
    }
}

// ============================================================================
// INT 33h — Microsoft Mouse driver
// ============================================================================

/// INT 33h — Microsoft Mouse Driver API. Minimal implementation covering
/// the subfunctions DOS games actually use: install check, show/hide cursor
/// (counter only — we don't draw), get/set position, button press/release
/// info (degenerate: returns current state, no history), set range, read
/// motion counters.
///
/// Mouse hardware state lives on `dos.pc.mouse` and is updated by the IRQ 12
/// packet stream queued through `machine::queue_irq`.
fn int_33h<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
    dos_trace!("D33 AX={:04X} BX={:04X} CX={:04X} DX={:04X} ES={:04X}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16, regs.es as u16);
    // Computed before borrowing `m`: a PM install (AX=0Ch) records the handler
    // as a selector and, for a 32-bit client, keeps the full EDX offset.
    let cb_is_pm = regs.mode() != crate::UserMode::VM86;
    let client_use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
    let m = &mut dos.pc.mouse;
    match ax {
        // AX=0000h — reset / installation check.
        // Returns: AX=0xFFFF (driver installed), BX=number of buttons (2).
        0x0000 => {
            m.erase_cursor(machine);
            *m = super::machine::MouseState::new();
            regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
            regs.rbx = (regs.rbx & !0xFFFF) | 2;
        }
        // AX=0001h — show cursor. AX=0002h — hide cursor.
        0x0001 => m.show(machine, regs),
        0x0002 => m.hide(machine, regs),
        // AX=0003h — get position and button status.
        // BX=button mask, CX=x, DX=y.
        0x0003 => {
            regs.rbx = (regs.rbx & !0xFFFF) | m.buttons as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (m.x as u16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (m.y as u16) as u64;
        }
        // AX=0004h — set position. CX=x, DX=y.
        0x0004 => {
            m.x = (regs.rcx as i16).clamp(m.min_x, m.max_x);
            m.y = (regs.rdx as i16).clamp(m.min_y, m.max_y);
            m.render_if_visible(machine, regs);
        }
        // AX=0005h — get button press info. BX=button (0=left, 1=right, 2=mid).
        // Returns AX=button mask, BX=press count since last call (degenerate
        // 0 — we don't track press history), CX=x at last press, DX=y.
        // AX=0006h — same shape for button release.
        0x0005 | 0x0006 => {
            regs.rax = (regs.rax & !0xFFFF) | m.buttons as u64;
            regs.rbx &= !0xFFFF;
            regs.rcx = (regs.rcx & !0xFFFF) | (m.x as u16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (m.y as u16) as u64;
        }
        // AX=0007h — set horizontal range. CX=min, DX=max.
        0x0007 => {
            let (a, b) = (regs.rcx as i16, regs.rdx as i16);
            m.min_x = a.min(b);
            m.max_x = a.max(b);
            m.x = m.x.clamp(m.min_x, m.max_x);
        }
        // AX=0008h — set vertical range. CX=min, DX=max.
        0x0008 => {
            let (a, b) = (regs.rcx as i16, regs.rdx as i16);
            m.min_y = a.min(b);
            m.max_y = a.max(b);
            m.y = m.y.clamp(m.min_y, m.max_y);
        }
        // AX=000Bh — read motion counters (mickeys since last call).
        // CX=dx, DX=dy as signed 16-bit. Resets the accumulators.
        0x000B => {
            let (dx, dy) = m.take_motion();
            regs.rcx = (regs.rcx & !0xFFFF) | (dx as i16 as u16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (dy as i16 as u16) as u64;
        }
        // AX=000Ch — install event handler.
        // CX = condition mask (which events fire the handler), ES:DX = far
        // handler address. CX=0 uninstalls.
        0x000C => {
            m.cb_mask = regs.rcx as u16;
            m.cb_seg  = regs.es as u16;
            // 32-bit PM client → full EDX offset; otherwise the 16-bit DX.
            m.cb_off  = if cb_is_pm && client_use32 { regs.rdx as u32 } else { regs.rdx as u16 as u32 };
            // A DPMI client installs ES:(E)DX as a selector:offset and expects
            // the callback in PM; a real-mode client installs a paragraph.
            m.cb_is_pm = cb_is_pm;
            m.pending_cond = 0;
        }
        _ => {
            dos_trace!("D33 unsupported AX={:04X}", ax);
        }
    }
    thread::KernelAction::Done
}

/// Deliver the INT 33h AX=000Ch software mouse callback.
///
/// Bracket-saves the user GP regs we're about to clobber (AX/BX/CX/DX/SI/DI)
/// since `HostContinuation` only covers CS/EIP/SS/ESP/EFLAGS/segs. The user handler
/// returns via SLOT_MOUSE_CB_RET which restores them and then unwinds through
/// the standard `resume_continuation_from_stub`.
pub(super) fn deliver_mouse_callback<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    use super::machine::vm86_push;
    use super::mode_transitions;

    let cb_is_pm = dos.pc.mouse.cb_is_pm;

    if cb_is_pm {
        // PM client (DPMI): the handler is `selector:offset` and must run in
        // protected mode. Mirror the IRQ PM-entry path (switch to the PM side
        // via a HostContinuation), but return via FAR RET — MS-Mouse handlers
        // end with RETF, not IRET — to the SLOT_MOUSE_CB_RET trampoline.
        mode_transitions::push_continuation_and_switch_to_pm_side(machine, dos, regs, None);
    } else {
        // Real-mode client: ES:DX is a paragraph; far-call it on the RM stack.
        let rm_dest = mode_transitions::rm_get_stack(dos);
        mode_transitions::push_continuation_and_switch_to_rm_side(machine, dos, regs, rm_dest, None);
    }

    let m = &mut dos.pc.mouse;
    // Bracket-save the user GP regs we're about to clobber.
    m.saved_rax = regs.rax;
    m.saved_rbx = regs.rbx;
    m.saved_rcx = regs.rcx;
    m.saved_rdx = regs.rdx;
    m.saved_rsi = regs.rsi;
    m.saved_rdi = regs.rdi;

    let cond = m.pending_cond;
    let buttons = m.buttons as u16;
    let x = m.x as u16;
    let y = m.y as u16;
    let dx = m.last_dx as u16;
    let dy = m.last_dy as u16;
    let cb_seg = m.cb_seg;
    let cb_off = m.cb_off;
    m.pending_cond = 0;

    // Push a FAR-return frame: the handler RETFs to SLOT_MOUSE_CB_RET, which
    // restores the saved GP regs and then unwinds the callback. PM and RM
    // differ only in the stub segment width and the frame writer.
    if cb_is_pm {
        let handler_use32 = mode_transitions::seg_is_32(&dos.ldt[..], cb_seg);
        // SPECIAL_STUB_SEL has base=0, so the offset is the full linear
        // address of the `CD 31` byte (cf. deliver_pm_irq's SLOT_RESUME_CONTINUATION).
        mode_transitions::push_farret_frame(machine, &dos.ldt[..], regs, handler_use32,
            STUB_BASE + slot_offset(SLOT_MOUSE_CB_RET) as u32, mode_transitions::SPECIAL_STUB_SEL);
    } else {
        vm86_push(machine, regs, CTRL_STUB_SEG);
        vm86_push(machine, regs, ctrl_slot_off(SLOT_MOUSE_CB_RET));
    }

    // Load AX=0Ch convention.
    regs.rax = (regs.rax & !0xFFFF) | cond as u64;
    regs.rbx = (regs.rbx & !0xFFFF) | buttons as u64;
    regs.rcx = (regs.rcx & !0xFFFF) | x as u64;
    regs.rdx = (regs.rdx & !0xFFFF) | y as u64;
    regs.rsi = (regs.rsi & !0xFFFF) | dx as u64;
    regs.rdi = (regs.rdi & !0xFFFF) | dy as u64;

    if cb_is_pm {
        regs.frame.cs = cb_seg as u64;
        regs.set_ip32(cb_off);
        // Spec doesn't promise the data segments to the handler (a real
        // mouse handler reloads DS itself); null them so a stale RM segment
        // value can't #GP at the handler's IRET/seg use. Matches the PM-entry
        // convention in `deliver_pm_irq` / `callback_entry`.
        regs.ds = 0;
        regs.es = 0;
        regs.fs = 0;
        regs.gs = 0;
    } else {
        super::machine::set_vm86_cs(regs, cb_seg);
        super::machine::set_vm86_ip(regs, cb_off as u16);
    }

    dos.pc.mouse.cb_in_flight = true;

    dos_trace!("[MOUSE] CB enter cond={:04X} buttons={:02X} x={} y={} dx={} dy={} -> {:04X}:{:08X}{}",
        cond, buttons, x as i16, y as i16, dx as i16, dy as i16, cb_seg, cb_off,
        if cb_is_pm { " (PM)" } else { "" });
}

/// SLOT_MOUSE_CB_RET dispatch: user handler RETFed to this slot.
/// Restore the GP regs `deliver_mouse_callback` clobbered, then unwind via
/// the same `resume_continuation_from_stub` that SLOT_RESUME_CONTINUATION uses.
pub(super) fn mouse_callback_return<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    use super::machine::vm86_pop;
    if !dos.pc.mouse.cb_is_pm {
        // VM86: the stub's `CD 31` (INT 31h, IOPL=3) pushed FLAGS/CS/IP onto
        // the RM stack the handler ran on. Discard that trap iret-frame.
        let _ = vm86_pop(machine, regs);
        let _ = vm86_pop(machine, regs);
        let _ = vm86_pop(machine, regs);
    }
    // PM: the stub's `CD 31` trapped via a CPL3→ring1 transition, so the CPU
    // pushed the iret-frame on the kernel stack, not the client PM stack. The
    // client SS:SP is already at the HostContinuation level — nothing to pop.

    let m = &mut dos.pc.mouse;
    regs.rax = m.saved_rax;
    regs.rbx = m.saved_rbx;
    regs.rcx = m.saved_rcx;
    regs.rdx = m.saved_rdx;
    regs.rsi = m.saved_rsi;
    regs.rdi = m.saved_rdi;
    m.cb_in_flight = false;

    super::mode_transitions::resume_continuation_from_stub(machine, dos, regs);
}

/// Open a DOS program file by literal name. No extension probing, no
/// PATH search -- those are shell concerns and live in COMMAND.COM,
/// matching real DOS where INT 21h AH=4B takes a fully-qualified name.
fn dos_open_program<A: crate::Arch>(kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, name: &[u8]) -> i32 {
    match dfs_open_existing(dos, name) {
        Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
        Err(_) => -2,
    }
}

/// Resolve path and return ForkExec action for the event loop to execute.
/// Synth ABI: on success BX=child_tid, CF=0. On error AX=errno, CF=1.
fn fork_exec<A: crate::Arch>(dos: &mut thread::DosState<A>, prog_name: &[u8], cmdtail: &[u8], viopl: u8, regs: &mut Regs, _kt: &mut thread::KernelThread<A>) -> thread::KernelAction {
    // Verify the file exists (DFS resolve → VFS → would-be open); ENOENT else.
    if dfs_open_existing(dos, prog_name).is_err() {
        regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    // Carry the absolute DOS path (the launcher's namespace), NOT the VFS path.
    // This is the program name a DOS extender reopens its own EXE by, so it must
    // be a real DOS path (the 8.3 names DN/the program used) — `resolve` keeps
    // them verbatim. It's mapped back to VFS only for the read (handle_fork_exec).
    // No VFS form ever reaches the DOS env, and ForkExec stays generic (a
    // personality tag, not a VFS/DOS path field).
    let mut path = [0u8; 164];
    let mut dos_abs = [0u8; dfs::DFS_PATH_MAX];
    let path_len = match dos.dfs.resolve(prog_name, &mut dos_abs) {
        Ok(n) => { path[..n].copy_from_slice(&dos_abs[..n]); n }
        Err(_) => {
            regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
    };

    fn on_error(regs: &mut Regs, err: i32) {
        regs.rax = (regs.rax & !0xFFFF) | err as u64;
        regs.set_flag32(1);
    }

    fn on_success(regs: &mut Regs, child_tid: i32) {
        regs.rax &= !0xFFFF;                            // AX=0 success
        regs.rbx = (regs.rbx & !0xFFFF) | ((child_tid as u16) as u64);
        regs.clear_flag32(1);
    }

    let mut cmdtail_buf = [0u8; 128];
    let cmdtail_len = cmdtail.len().min(127);
    cmdtail_buf[..cmdtail_len].copy_from_slice(&cmdtail[..cmdtail_len]);

    thread::KernelAction::ForkExec {
        path,
        path_len,
        cmdtail: cmdtail_buf,
        cmdtail_len,
        personality_name: Some(thread::PersonalityName::Dos),
        viopl,
        on_error,
        on_success,
    }
}

/// DOS INT 4Bh EXEC — load and execute a DOS program in-process.
/// Loads a .COM or MZ .EXE into a fresh child segment above `heap_seg`,
/// shares the address space with the parent, and transfers control.
/// Parent resumes via exec_return on child INT 20h / 4C00.
/// Non-DOS formats (ELF, BAT) should be routed through COMMAND.COM /C
/// which interprets BAT itself and uses synth INT 31h AH=01h to
/// fork+exec+wait each external command in a separate thread.
fn exec_program<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let al = regs.rax as u8;
    match al {
        0x00 => {}                                  // load & execute — fall through
        0x03 => return exec_load_overlay(machine, kt, dos, regs),
        // AL=01 (load only) and AL=02 (reserved) not implemented. Borland BC
        // and Watcom tools use 00/03 exclusively; surface others so we notice.
        _ => {
            dos_trace!("D21 4B unsupported AL={:02X}", al);
            regs.rax = (regs.rax & !0xFFFF) | 1;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
    }

    // Read ASCIIZ filename from DS:DX
    let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = machine.read::<u8>((addr) as usize);
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }

    // Read parameter block at ES:BX
    let pb = linear(machine, dos, regs, regs.es as u16, regs.rbx as u32);
    let cmdtail_off = machine.read::<u16>((pb + 2) as usize) as u32;
    let cmdtail_seg = machine.read::<u16>((pb + 4) as usize);
    // The embedded (segment, offset) far pointer is a PM selector:offset
    // when the caller is in PM, an RM paragraph:offset in VM86 — same
    // discriminator linear() uses for buffer addresses elsewhere.
    let cmdtail_addr = linear(machine, dos, regs, cmdtail_seg, cmdtail_off);
    let tail_len = machine.read::<u8>((cmdtail_addr) as usize) as usize;
    let mut tail = [0u8; 128];
    let copy_len = tail_len.min(127);
    machine.copy_from((cmdtail_addr + 1) as usize, &mut tail[..copy_len]);

    let prog_name: &[u8] = &filename[..flen];

    {
        let mut tail_vis = [0u8; 80];
        let vis_len = copy_len.min(80);
        for i in 0..vis_len {
            let b = tail[i];
            tail_vis[i] = if !(32..127).contains(&b) { b'?' } else { b };
        }
        dos_trace!("EXEC prog={:?} cmdtail_len={} tail={:?}",
            core::str::from_utf8(prog_name).unwrap_or("?"),
            copy_len,
            core::str::from_utf8(&tail_vis[..vis_len]).unwrap_or("?"));
    }

    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    // ELF binaries need a separate address space — route through fork_exec.
    let is_elf = buf.len() >= 4 && buf[0..4] == [0x7F, b'E', b'L', b'F'];
    dos_trace!("  exec_program: {:?} size={} elf={}", core::str::from_utf8(prog_name), size, is_elf);
    if is_elf {
        return fork_exec(dos, prog_name, b"", 1, regs, kt);
    }

    let is_exe = is_mz_exe(&buf);
    // Layout the child's two arenas above the parent's heap end: env block
    // first (0x10 paragraphs), then PSP+code/BSS. `map_psp` places env at
    // `psp_seg - 0x10`, so `child_seg = heap_seg + 0x10` keeps the env safely
    // inside the child's own allocation and never inside parent memory.
    let child_seg = dos.heap_seg + 0x10;
    dos_trace!("  exec_program: {:?} size={} exe={} child_seg={:04X} parent_psp={:04X}",
        core::str::from_utf8(prog_name), size, is_exe, child_seg, dos.current_psp);

    // Resolve the DOS-form absolute path for the env program-path suffix.
    // Must be drive-qualified uppercase (e.g. "C:\BIN\PROG.EXE") — DOS
    // extenders derive their cwd estimate from this field.
    let mut abs_dos = [0u8; dfs::DFS_PATH_MAX];
    let abs_len = dos.dfs.resolve(prog_name, &mut abs_dos).unwrap_or(0);

    // Parent's PSP segment is now always a real-mode paragraph in
    // `dos.current_psp`. The PSP[0x2C] in memory may have been converted
    // to a selector at `dpmi_enter` — use `saved_rm_env` in that case so
    // the child's parent link / copied env stay in segment form.
    let parent_rm_psp = dos.current_psp;
    let parent_env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if dpmi.env_ldt_idx != 0 && dpmi.saved_rm_psp == parent_rm_psp => {
            dpmi.saved_rm_env
        }
        _ => Psp::env_seg(machine, parent_rm_psp),
    };
    let parent_env_vec = snapshot_env(machine, parent_env_seg);
    let parent = ParentRef { psp_seg: parent_rm_psp, env: &parent_env_vec };

    // Save parent state before reseating the heap chain for the child.
    // INT frame (IP/CS/FLAGS) is on the VM86 stack at current SS:SP;
    // exec_return restores SS:SP so rm_int31_dispatch pops it and resumes.
    let prev = dos.exec_parent.take();
    let parent_heap = dos.heap_seg;
    let parent_heap_base = dos.heap_base_seg;
    let parent_blocks = dos.dos_blocks.clone();
    let parent_dta = dos.dta;

    // Do NOT reset the MCB chain. Real DOS keeps a single chain across EXEC:
    // the parent's blocks stay allocated while the child runs, and the child's
    // env+program are first-fit `dos_alloc_block`'d into genuinely-free regions
    // (load_exe sizes a max-alloc child from `largest_dos_block`, not
    // 0xA000-heap_base). This is load-bearing: a 16-bit DPMI parent (Borland
    // C) keeps a live PM CS aliased onto a conventional block that can sit
    // ABOVE a free gap (so `heap_seg`'s contiguous-run value is below it).
    // Resetting + flooring the child at `heap_seg` let the child overwrite that
    // block — corrupting BC's code (the 0x20cc #GP cascade after TLINK exits).
    // exec_return restores `parent_blocks`, dropping whatever the child added.

    let loaded = if is_exe {
        match load_exe(machine, regs, dos, &parent, &buf, &abs_dos[..abs_len]) {
            Some(l) => l,
            None => {
                dos.heap_seg = parent_heap;
                dos.heap_base_seg = parent_heap_base;
                dos.current_psp = parent_rm_psp;
                dos.dta = parent_dta;
                dos.dos_blocks = parent_blocks;
                super::sync_mcb_chain(machine, dos, regs);
                regs.rax = (regs.rax & !0xFFFF) | 11;
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    } else {
        load_com(machine, regs, dos, &parent, &buf, &abs_dos[..abs_len])
    };
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;
    let psp_seg = loaded.psp_seg;

    Psp::set_cmdline(machine, loaded.psp_seg, &tail[..copy_len]);
    dos.dta = (psp_seg as u32) * 16 + 0x80;
    // DPMI host obligation: parent's PM state must not be observable to the
    // child (no PM handlers fire; child's DPMI entry, if any, allocates a
    // fresh DpmiState). Suspend DPMI state + pm_vectors + LDT, restore in
    // `exec_return`. Swapping the LDT box is cheap (pointer move); the only
    // per-EXEC allocation is the fresh 64KB child LDT.
    let suspended_dpmi = dos.dpmi.take();
    let suspended_pm_vectors = dos.pm_vectors;
    let suspended_pm_dos = core::mem::replace(&mut dos.pm_dos, false);
    let suspended_ldt = core::mem::replace(&mut dos.ldt, super::fresh_ldt());
    let suspended_ldt_alloc = core::mem::replace(
        &mut dos.ldt_alloc,
        [0u32; super::dpmi::LDT_ENTRIES / 32],
    );
    let suspended_pm_rm_vector_shadow = core::mem::replace(
        &mut dos.pm_rm_vector_shadow,
        [(0, 0, 0); 256],
    );
    // The child begins a fresh continuation chain: its locked-stack cursor
    // must not point into the parent's PM stack (see ExecParent docs).
    let suspended_locked_stack = dos.pc.locked_stack.other_stack.take();
    let parent_pm_mode = regs.mode() != crate::UserMode::VM86;
    let mut parent_ivt = [(0u8, 0u16, 0u16); 12];
    for (slot, &int_num) in parent_ivt.iter_mut().zip(EXEC_SAVED_IVT_VECTORS.iter()) {
        let off = read_u16(machine, 0, (int_num as u32) * 4);
        let seg = read_u16(machine, 0, (int_num as u32) * 4 + 2);
        *slot = (int_num, off, seg);
        if parent_pm_mode {
            write_u16(machine, 0, (int_num as u32) * 4, slot_offset(int_num));
            write_u16(machine, 0, (int_num as u32) * 4 + 2, STUB_SEG);
        }
    }
    super::dpmi::install_kernel_ldt_slots(dos);
    super::dpmi::reset_pm_vectors(dos);
    // Reload LDTR after swapping in the child LDT.
    dos.on_resume(machine);
    dos.exec_parent = Some(ExecParent {
        ss: vm86_ss(regs),
        sp: vm86_sp(regs),
        ds: regs.ds as u16,
        es: regs.es as u16,
        heap_seg: parent_heap,
        heap_base_seg: parent_heap_base,
        psp: parent_rm_psp,
        dta: parent_dta,
        dos_blocks: parent_blocks,
        ivt_vectors: parent_ivt,
        dpmi: suspended_dpmi,
        pm_vectors: suspended_pm_vectors,
        ldt: suspended_ldt,
        ldt_alloc: suspended_ldt_alloc,
        pm_rm_vector_shadow: suspended_pm_rm_vector_shadow,
        pm_dos: suspended_pm_dos,
        locked_stack_other: suspended_locked_stack,
        pm_mode: parent_pm_mode,
        prev: prev.map(alloc::boxed::Box::new),
    });

    // Set child entry. Push child's CS:IP + FLAGS onto the child's stack
    // so that rm_int31_dispatch's pop restores them correctly. Force IF
    // on in the pushed flags — DOS hands every program "interrupts on";
    // the parent's current EFLAGS (inherited here) has IF cleared because
    // the INT 21h trap gate cleared it on entry, and without this the
    // child boots with IRQ delivery blocked and any wait/scheduling-tick
    // dependency hangs forever (e.g. OMF after re-launch from a launcher).
    regs.set_ss32(ss as u32);
    regs.set_sp32(sp as u32);
    let flags = machine::guest_flags_if_on(regs) as u16;
    vm86_push(machine, regs, flags);
    vm86_push(machine, regs, cs);
    vm86_push(machine, regs, ip);
    regs.ds = psp_seg as u64;
    regs.es = psp_seg as u64;
    regs.clear_flag32(1);
    // Children always start in VM86; PM parents resume through the dispatch tail.
    regs.frame.rflags |= machine::VM_FLAG as u64;
    dos_trace!("  exec_program loaded: cs:ip={:04X}:{:04X} ss:sp={:04X}:{:04X} heap_seg={:04X}",
        cs, ip, ss, sp, dos.heap_seg);
    thread::KernelAction::Done
}

/// DOS INT 21h/4B AL=03 — Load Overlay.
/// Loads a program into caller-chosen memory. No PSP, no control transfer,
/// no address-space changes. Parameter block at ES:BX:
///   WORD 0: load_segment  — where the file image goes
///   WORD 2: reloc_factor  — value added to each relocated word for MZ EXE
/// For .COM / flat binaries the file is copied verbatim at load_seg:0.
/// For MZ .EXE the load module is copied at load_seg:0 and each relocation
/// entry gets `reloc_factor` added (NOT load_seg — the spec leaves it to
/// the caller, e.g. Borland C passes the segment of the overlay frame).
fn exec_load_overlay<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // ASCIIZ filename at DS:DX
    let mut addr = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = machine.read::<u8>((addr) as usize);
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }
    let prog_name: &[u8] = &filename[..flen];

    // Parameter block at ES:BX — two WORDs.
    let pb = linear(machine, dos, regs, regs.es as u16, regs.rbx as u32);
    let load_seg = machine.read::<u16>((pb) as usize);
    let reloc_factor = machine.read::<u16>((pb + 2) as usize);
    dos_trace!("D21 4B03 LOAD_OVERLAY prog={:?} load_seg={:04X} reloc_factor={:04X}",
        core::str::from_utf8(prog_name).unwrap_or("?"), load_seg, reloc_factor);

    let fd = dos_open_program(kt, dos, prog_name);
    if fd < 0 {
        dos_trace!("D21 4B03 open failed: {:?}", core::str::from_utf8(prog_name).unwrap_or("?"));
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    let size = crate::kernel::vfs::seek(fd, 0, 2, &kt.fds);
    if size <= 0 {
        crate::kernel::vfs::close(fd, &mut kt.fds);
        regs.rax = (regs.rax & !0xFFFF) | 2;
        regs.set_flag32(1);
        return thread::KernelAction::Done;
    }
    crate::kernel::vfs::seek(fd, 0, 0, &kt.fds);
    let mut buf = alloc::vec![0u8; size as usize];
    crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);

    let load_base = (load_seg as u32) << 4;
    if is_mz_exe(&buf) {
        let data = &buf[..];
        let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
        let last_page_bytes = w(0x02) as u32;
        let total_pages = w(0x04) as u32;
        let reloc_count = w(0x06) as usize;
        let header_paragraphs = w(0x08) as u32;
        let reloc_offset = w(0x18) as usize;

        let file_size = if last_page_bytes == 0 {
            total_pages * 512
        } else {
            (total_pages - 1) * 512 + last_page_bytes
        };
        let header_size = header_paragraphs * 16;
        let load_size = file_size.saturating_sub(header_size) as usize;
        let reloc_end = reloc_offset + reloc_count * 4;

        if header_size as usize > data.len()
            || load_size > data.len() - header_size as usize
            || reloc_end > data.len()
        {
            dos_trace!("D21 4B03 bad MZ header");
            regs.rax = (regs.rax & !0xFFFF) | 11;
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }

        let img = &data[header_size as usize..header_size as usize + load_size];
        machine.copy_to(load_base as usize, img);
        // Apply relocations using caller's reloc_factor (not load_seg).
        for i in 0..reloc_count {
            let entry = reloc_offset + i * 4;
            let off = w(entry) as u32;
            let seg = w(entry + 2) as u32;
            let a = (load_base + (seg << 4) + off) as usize;
            let v: u16 = machine.read(a);
            machine.write::<u16>(a, v.wrapping_add(reloc_factor));
        }
        dos_trace!("D21 4B03 MZ loaded: load_size={} relocs={}", load_size, reloc_count);
    } else {
        // Raw / .COM: copy file verbatim at load_seg:0.
        machine.copy_to(load_base as usize, &buf);
        dos_trace!("D21 4B03 raw loaded: size={}", buf.len());
    }

    regs.clear_flag32(1);
    thread::KernelAction::Done
}

/// Return from an EXEC'd child to the parent.
/// Restores the parent's CS:IP, SS:SP, DS, ES and clears carry (success).
fn exec_return<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, parent: ExecParent,
               preserve_pm_env: bool) -> thread::KernelAction {
    crate::dbg_println!("exec_return: parent ss:sp={:04X}:{:04X} ds={:04X} es={:04X} heap={:04X} psp={:04X}",
        parent.ss, parent.sp, parent.ds, parent.es, parent.heap_seg, parent.psp);
    if !parent.pm_mode {
        // Peek the IRET frame waiting on the real-mode parent's stack.
        let lin = ((parent.ss as u32) << 4) + (parent.sp as u32);
        let ret_ip = machine.read::<u16>((lin) as usize);
        let ret_cs = machine.read::<u16>((lin + 2) as usize);
        let ret_flags = machine.read::<u16>((lin + 4) as usize);
        crate::dbg_println!("exec_return: parent IRET frame at {:04X}:{:04X} -> ip={:04X} cs={:04X} flags={:04X}",
            parent.ss, parent.sp, ret_ip, ret_cs, ret_flags);
    }
    dos_trace!("  exec_return: restoring heap={:04X}->{:04X} psp={:04X}->{:04X} ss:sp={:04X}:{:04X} pm_env={}",
        dos.heap_seg, parent.heap_seg,
        dos.current_psp, parent.psp,
        parent.ss, parent.sp,
        if preserve_pm_env && dos.dpmi.is_some() { "kept" } else { "restored" });
    regs.set_ss32(parent.ss as u32);
    regs.set_sp32(parent.sp as u32);
    regs.clear_flag32(1);
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    // Restore parent's mode. The child was always VM86; if the parent
    // was PM, clear VM_FLAG so the dispatch tail runs the PM iret-frame
    // pop on parent's PM stack instead of the VM86 one.
    if parent.pm_mode {
        regs.frame.rflags &= !(machine::VM_FLAG as u64);
    } else {
        regs.frame.rflags |= machine::VM_FLAG as u64;
    }
    dos.heap_seg = parent.heap_seg;
    dos.heap_base_seg = parent.heap_base_seg;
    dos.current_psp = parent.psp;
    dos.dta = parent.dta;
    dos.dos_blocks = parent.dos_blocks;
    super::sync_mcb_chain(machine, dos, regs);
    if parent.pm_mode && !preserve_pm_env {
        for &(int_num, off, seg) in parent.ivt_vectors.iter() {
            write_u16(machine, 0, (int_num as u32) * 4, off);
            write_u16(machine, 0, (int_num as u32) * 4 + 2, seg);
        }
    }
    // PM-environment handling on exec_return:
    //   - Normal exit (AH=4Ch): drop child's dpmi/ldt/pm_vectors, restore
    //     parent's. Child's PM state vanishes with the process.
    //   - TSR exit (AH=31h) when child entered DPMI: keep child's dpmi/ldt/
    //     pm_vectors alive — DPMI host installers (Borland's dpmiload,
    //     CWSDPMI when run as a TSR, etc.) install PM services, switch to
    //     RM via 0306, and TSR. The host's LDT entries, INT vectors and
    //     dpmi state must outlive the TSR so subsequent programs can use
    //     the same PM session via the raw-switch trampoline.
    //   - TSR exit when child has no dpmi: nothing to preserve, fall back
    //     to parent's (might itself be Some if parent is the DPMI client).
    if preserve_pm_env && dos.dpmi.is_some() {
        // Drop parent's saved PM env; keep what's already in dos.*.
    } else {
        dos.dpmi = parent.dpmi;
        dos.pm_vectors = parent.pm_vectors;
        dos.ldt = parent.ldt;
        dos.ldt_alloc = parent.ldt_alloc;
        dos.pm_rm_vector_shadow = parent.pm_rm_vector_shadow;
        dos.pm_dos = parent.pm_dos;
        // Restore the parent's continuation-chain cursor alongside its LDT:
        // the two are a matched pair (cursor indexes stack via LDT selectors).
        dos.pc.locked_stack.other_stack = parent.locked_stack_other;
    }
    // LDTR currently points at the child's LDT — reload (same box if we
    // preserved it, parent's box if we restored).
    dos.on_resume(machine);
    dos.exec_parent = parent.prev.map(|b| *b);
    thread::KernelAction::Done
}

/// Match a filename against a DOS wildcard pattern (e.g. "*.*", "*.EXE").
/// Case-insensitive. Supports '*' and '?' wildcards.
fn dos_wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    // Convert both pattern and name to 11-byte FCB format (8.3, space-padded)
    // then compare. In FCB format, '?' matches any char including space (padding).
    let to_fcb = |s: &[u8]| -> [u8; 11] {
        let mut fcb = [b' '; 11];
        let mut i = 0;
        let mut pos = 0;
        // Base name (up to 8 chars)
        while i < s.len() && s[i] != b'.' && pos < 8 {
            if s[i] == b'*' {
                while pos < 8 { fcb[pos] = b'?'; pos += 1; }
                i += 1;
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        // Skip to dot
        while i < s.len() && s[i] != b'.' { i += 1; }
        if i < s.len() && s[i] == b'.' { i += 1; }
        // Extension (up to 3 chars)
        pos = 8;
        while i < s.len() && pos < 11 {
            if s[i] == b'*' {
                while pos < 11 { fcb[pos] = b'?'; pos += 1; }
                break;
            }
            fcb[pos] = s[i].to_ascii_uppercase();
            i += 1;
            pos += 1;
        }
        fcb
    };

    let pat_fcb = to_fcb(pattern);
    let name_fcb = to_fcb(name);

    for i in 0..11 {
        if pat_fcb[i] != b'?' && pat_fcb[i] != name_fcb[i] {
            return false;
        }
    }
    true
}

/// Resolve a raw DOS path to a VFS path for OPEN (all components must exist).
/// Returns `([u8; DFS_PATH_MAX], len)` on success, DOS error code on failure
/// (2 = file not found, 3 = path not found, 15 = invalid drive).
pub(crate) fn dfs_open_existing<A: crate::Arch>(dos: &thread::DosState<A>, dos_in: &[u8])
    -> Result<([u8; dfs::DFS_PATH_MAX], usize), i32>
{
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    let vlen = dfs::DfsState::to_vfs_open(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// Resolve a raw DOS path to a VFS path for CREATE (final component may not
/// exist yet). Intermediate dirs must exist.
pub(crate) fn dfs_create_path<A: crate::Arch>(dos: &thread::DosState<A>, dos_in: &[u8])
    -> Result<([u8; dfs::DFS_PATH_MAX], usize), i32>
{
    let mut abs = [0u8; dfs::DFS_PATH_MAX];
    let alen = dos.dfs.resolve(dos_in, &mut abs)?;
    let mut out = [0u8; dfs::DFS_PATH_MAX];
    let vlen = dfs::DfsState::to_vfs_create(&abs[..alen], &mut out)?;
    Ok((out, vlen))
}

/// FindFirst/FindNext helper: resume search from dos.find_idx,
/// updating it in place. Directory and pattern come from find_path.
fn find_matching_file<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    // Split find_path into directory and pattern components.
    // find_path is an absolute VFS path like "DN/DN*.SWP" or "*.*".
    // The directory part includes any trailing slash; the pattern is
    // the basename (filespec with wildcards).
    let path_len = dos.find_path_len as usize;
    let full = &dos.find_path[..path_len];
    let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let dir_buf = {
        let mut b = [0u8; 96];
        b[..split].copy_from_slice(&full[..split]);
        (b, split)
    };
    let pat_buf = {
        let mut b = [0u8; 32];
        let plen = (path_len - split).min(b.len());
        b[..plen].copy_from_slice(&full[split..split + plen]);
        (b, plen)
    };
    let dir = &dir_buf.0[..dir_buf.1];
    let pat = &pat_buf.0[..pat_buf.1];

    let mut idx = dos.find_idx as usize;

    // Iterate DFS's per-dir CI cache. Keys are 8.3 aliases (uppercase),
    // already in the form DOS expects in the DTA filename slot — long VFS
    // names live as `BASE~N.EXT` aliases here. Wildcard match runs against
    // the alias, not the long name.
    let dir_for_ci = if dir.last() == Some(&b'/') { &dir[..dir.len() - 1] } else { dir };
    loop {
        match dfs::ci::entry_at(dir_for_ci, idx) {
            Some((alias, size, is_dir)) => {
                idx += 1;
                if dos_wildcard_match(pat, alias) {
                    dos.find_idx = idx as u16;
                    let dta = dos.dta as usize;
                    machine.zero(dta, 43);
                    machine.write::<u8>(dta + 0x15, if is_dir { 0x10 } else { 0x20 });
                    machine.write::<u32>(dta + 0x1A, size);
                    let name_len = alias.len().min(12);
                    machine.copy_to(dta + 0x1E, &alias[..name_len]);
                    machine.write::<u8>(dta + 0x1E + name_len, 0);
                    regs.clear_flag32(1);
                    return thread::KernelAction::Done;
                }
            }
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 18; // no more files
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    }
}

// /// Prepare the VM86 IVT for a new process.
// ///
// /// The BIOS IVT at 0x0000-0x03FF is preserved from the COW copy of page 0,
// /// so BIOS handlers in ROM (0xF0000-0xFFFFF) are accessible. When a BIOS
// /// handler does I/O (IN/OUT), it traps through the IOPB to our virtual
// /// PIC/keyboard, so BIOS code works transparently.
// ///
// ── Low-memory layout ────────────────────────────────────────────────
// Single struct at LOW_MEM_BASE so field offsets propagate automatically
// when sizes change. The fake DOS internal structures (PSP, LoL, SFT, CDS)
// are typed sub-structs; the stub array and IRQ stack are byte arrays.
// `heap_start()` returns the first free paragraph past this layout — the
// initial DOS program's env arena lives there, with its PSP at +0x10.

const LOW_MEM_BASE: u32 = 0x500;
const NUM_DRIVES: u8 = 8;
const SFT_ENTRIES: usize = 20;

/// Program Segment Prefix (DOS 3+, 256 bytes). Only the fields we read or
/// write are named; the rest is reserved padding so byte offsets stay stable
/// for any guest code that walks the structure directly.
///
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct Psp {
    pub int_20:           [u8; 2],   // 0x00 — CD 20 (terminate)
    pub top_of_mem:       u16,        // 0x02 — segment past program (paragraphs)
    _reserved_04:         u8,         // 0x04
    _cpm_call:            [u8; 5],    // 0x05 — far call to CP/M dispatcher
    _terminate_addr:      u32,        // 0x0A — INT 22h vector
    _ctrl_break_addr:     u32,        // 0x0E — INT 23h vector
    _critical_err:        u32,        // 0x12 — INT 24h vector
    pub parent_psp:       u16,        // 0x16 — parent PSP segment
    pub jft:              [u8; 20],   // 0x18 — inline Job File Table
    pub env_seg:          u16,        // 0x2C — environment segment (or 0)
    _ss_sp:               u32,        // 0x2E — SS:SP at last INT 21
    pub max_files:        u16,        // 0x32 — JFT size
    pub jft_far_off:      u16,        // 0x34 — far ptr to active JFT
    pub jft_far_seg:      u16,        // 0x36
    _reserved_38:         [u8; 0x80 - 0x38], // 0x38-0x7F
    pub cmdline_len:      u8,         // 0x80
    pub cmdline:          [u8; 127],  // 0x81-0xFF (CR-terminated)
}
const _: () = assert!(core::mem::size_of::<Psp>() == 256);
impl Psp {
    /// Linear base of the 256-byte PSP at `psp_seg` (`[psp_seg<<4 ..]`).
    #[inline]
    fn base(psp_seg: u16) -> usize { ((psp_seg as u32) << 4) as usize }
    /// Write the whole PSP at `psp_seg`.
    pub fn store<A: crate::Arch>(machine: &mut A, psp_seg: u16, psp: Self) { machine.write::<Self>(Self::base(psp_seg), psp); }
    /// Read PSP[0x2C] (environment segment or selector).
    pub fn env_seg<A: crate::Arch>(machine: &mut A, psp_seg: u16) -> u16 {
        machine.read::<u16>(Self::base(psp_seg) + core::mem::offset_of!(Self, env_seg))
    }
    /// Set one Job File Table entry (PSP[0x18 + idx]).
    pub fn set_jft<A: crate::Arch>(machine: &mut A, psp_seg: u16, idx: usize, val: u8) {
        machine.write::<u8>(Self::base(psp_seg) + core::mem::offset_of!(Self, jft) + idx, val);
    }
    /// Set the JFT size field (PSP[0x32]).
    pub fn set_max_files<A: crate::Arch>(machine: &mut A, psp_seg: u16, n: u16) {
        machine.write::<u16>(Self::base(psp_seg) + core::mem::offset_of!(Self, max_files), n);
    }
    /// Install a command-tail at PSP[0x80] (length byte + bytes + CR).
    pub fn set_cmdline<A: crate::Arch>(machine: &mut A, psp_seg: u16, tail: &[u8]) {
        let n = tail.len().min(126);
        let base = Self::base(psp_seg);
        machine.write::<u8>(base + core::mem::offset_of!(Self, cmdline_len), n as u8);
        let cmd = base + core::mem::offset_of!(Self, cmdline);
        machine.copy_to(cmd, &tail[..n]);
        machine.write::<u8>(cmd + n, 0x0D);
    }
}
impl Default for Psp {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// One System File Table entry (DOS 3+ format, 59 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SftEntry {
    refcount: u16,        // 0x00
    open_mode: u16,       // 0x02
    attribute: u8,        // 0x04
    device_info: u16,     // 0x05
    _reserved_07: [u8; 6],// 0x07
    time: u16,            // 0x0D
    date: u16,            // 0x0F
    size: u32,            // 0x11
    position: u32,        // 0x15
    _trailer: [u8; 34],   // 0x19-0x3A (filename + DOS-internal fields we don't fill)
}
const _: () = assert!(core::mem::size_of::<SftEntry>() == 59);
impl Default for SftEntry {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// SFT header followed by the entry array. Total 1186 bytes.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Sft {
    next: u32,                       // 0x00 — far ptr to next SFT block (FFFF:FFFF = end)
    count: u16,                      // 0x04
    entries: [SftEntry; SFT_ENTRIES],
}

/// List-of-Lists (DOS internal). Only the fields we actually fill are named;
/// the rest is reserved padding.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Lol {
    _reserved_00: [u8; 4],
    sft_off: u16,                    // 0x04 — far ptr to SFT (off, seg)
    sft_seg: u16,
    _reserved_08: [u8; 14],
    cds_off: u16,                    // 0x16 — far ptr to CDS array
    cds_seg: u16,
    _reserved_1a: [u8; 6],
    block_devs: u8,                  // 0x20
    last_drive: u8,                  // 0x21
    _trailer: [u8; 30],
}
const _: () = assert!(core::mem::size_of::<Lol>() == 0x40);
impl Default for Lol {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Current Directory Structure (one per drive letter, DOS 3.3 format).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CdsEntry {
    path: [u8; 67],                  // 0x00 — ASCIIZ (e.g. "C:\")
    flags: u16,                      // 0x43 — 0x4000 = valid physical drive
    _reserved_45: [u8; 10],
    backslash_off: u16,              // 0x4F — offset of '\' in `path`
}
const _: () = assert!(core::mem::size_of::<CdsEntry>() == 81);
impl Default for CdsEntry {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Fixed kernel-owned region in conventional memory.
///
/// The CD 31 stub array, the *system program* (a Program — env + PSP — that
/// stands in for COMMAND.COM; its env carries the master COMSPEC/PATH, its
/// PSP self-references to terminate the parent chain), the LoL → SFT chain
/// DJGPP's fstat walks, the CDS array some programs read, and a private
/// IRQ-reflect stack so BIOS handlers don't trample the user's stack.
#[repr(C, packed)]
struct LowMem {
    stubs:     [[u8; 2]; 256],        // 0x500
    /// Bootstrap sentinel PSP. Acts as the parent_psp / chain terminator
    /// for the very first program loaded (and as a fixed segment we hand
    /// out as a parent reference for cross-AS fork+exec where the actual
    /// parent's PSP isn't reachable). Real DOS keeps an analogous internal
    /// PSP in its resident kernel data — it lives below `heap_start` and
    /// is *not* part of the MCB chain.
    boot_psp:  Psp,                    // 0x700: 256 bytes
    /// First MCB seg in the DOS memory chain. Real DOS stores this at
    /// `[LOL - 2]` (one WORD before the List of Lists structure). Programs
    /// (DOS/4G stubs, MEM utilities, etc.) call AH=52h to get the LOL
    /// pointer and then read the WORD just below it to find the chain
    /// head. `sync_mcb_chain` writes the current `dos.heap_base_seg` here
    /// every time the chain is updated.
    first_mcb_seg: u16,
    lol:       Lol,                    // 0x902
    sft:       Sft,
    cds:       [CdsEntry; NUM_DRIVES as usize],
    /// DPMI 0.9 §3.1.2 locked PM stack (referred to as "host_stack" in
    /// the implementation). 4 KB host-provided buffer used for HW IRQ /
    /// exception / RM-callback handling in PM. Switched onto on the
    /// first reflection to PM and switched away from on outermost
    /// return. Two aliasing LDT selectors (PM16 with B=0, PM32 with
    /// B=1) point at this same buffer so SP values are portable across
    /// client bitness.
    host_stack: [u8; HOST_STACK_SIZE],

    /// Dedicated RM stack — host-provided buffer used by all kernel-
    /// orchestrated RM execution (BIOS reflection from PM, DPMI
    /// 0300/0301/0302 PM->RM calls, RM-side of callbacks). Reused per-thread
    /// across excursions and shared LIFO via `other_stack` (no snapshot copy).
    ///
    /// MUST be large enough for a real-mode interrupt handler's full stack
    /// frame. DPMI 0.9 §3.1.3's 200H is only the *client*-supplied minimum;
    /// the *host*-provided stack for ss=0 sim-INT / BIOS calls must hold the
    /// handler itself. At 200H it overflowed: the Bochs VGA BIOS's VESA
    /// `INT 10h/4F00` handler ran a few bytes past the buffer, and because
    /// `host_stack` (holding the live HostContinuation) sits immediately below
    /// this buffer, the overflow clobbered the HC's segment slots → a garbage
    /// paragraph got popped as a selector on the PM exit → kernel #GP, hanging
    /// every DPMI app under Bochs (whose VGA BIOS is stack-hungrier than
    /// QEMU's SeaBIOS). 4 KB matches what real DPMI extenders provide and
    /// leaves ample headroom, incl. LIFO-nested excursions. Paragraph-aligned
    /// because `host_stack` precedes it and is a multiple of 16 in size.
    rm_stack: [u8; RM_STACK_SIZE],
}

/// Locked PM stack size (see `LowMem::host_stack`).
const HOST_STACK_SIZE: usize = 4096;

/// The locked PM stack is split in two:
///
///   [EXC_STACK_TOP .. HOST_STACK_SIZE]  rm-call / IRQ continuation chain,
///                                       growing down from `host_stack_empty_sp()`
///   [0 .. EXC_STACK_TOP]                exception-dispatch region
///
/// Exception dispatch must NEVER park its frames on the client's own stack:
/// per DPMI 0.9 the handler runs on a host-provided locked stack, and a
/// fixup-style handler (DOS/4GW) legitimately builds its resume IRET frame
/// at `fault_esp - 12` — i.e. right inside anything the host put directly
/// below the faulting ESP. So each dispatch gets a fixed slot here indexed
/// by the current exception nesting depth.
pub(super) const EXC_STACK_TOP: u32 = 2048;
/// Per-nesting-level slot span in the exception region: 126 bytes of
/// host frames (HostContinuation + RetF + 0.9 + 1.0 frames) plus handler
/// scratch. Depth is capped at EXC_STACK_TOP / EXC_STACK_SLOT levels.
pub(super) const EXC_STACK_SLOT: u32 = 1024;
/// Dedicated RM stack size (see `LowMem::rm_stack`).
const RM_STACK_SIZE: usize = 0x1000;

/// Linear address of a `LowMem` field, e.g. `lm_field(offset_of!(LowMem, lol))`.
/// The kernel-owned low-mem area is a *projection* written into guest memory
/// field-by-field through the vcpu — never borrowed as a Rust struct (it sits at
/// a fixed low address the guest can also reach).
#[inline]
fn lm_field(field_off: usize) -> usize { LOW_MEM_BASE as usize + field_off }

/// Update the chain-head pointer that lives at `[LOL - 2]`. Called from
/// `sync_mcb_chain` so AH=52h-style chain walkers see the current
/// `heap_base_seg`.
pub(super) fn set_first_mcb_seg<A: crate::Arch>(machine: &mut A, seg: u16) {
    machine.write::<u16>(lm_field(core::mem::offset_of!(LowMem, first_mcb_seg)), seg);
}

pub(crate) const STUB_BASE: u32 = LOW_MEM_BASE;
pub(crate) const STUB_SEG: u16 = (LOW_MEM_BASE >> 4) as u16;

/// RM alias segment for the CONTROL view of the stub array. The ONE 256-slot
/// `CD 31` array serves two namespaces, separated purely by how its bytes are
/// addressed — the RM twin of PM's `SPECIAL_STUB_SEL` vs `VECTOR_STUB_SEL`
/// selectors aliasing the same array:
///
///   vector view:  `STUB_SEG:vector*2`             — IVT entries; slot == INT
///                 vector for all 256 (kernel-DOS redirects and the
///                 personality BIOS alike)
///   control view: `CTRL_STUB_SEG:STUB_BASE+slot*2` — far-call entry points
///                 the kernel hands out (XMS, DPMI entry, RM callbacks,
///                 resume/continuation parks)
///
/// Same bytes, same trap; CS alone says which namespace, so control-slot
/// numbering can never collide with vector numbering. CTRL_STUB_SEG = 0 makes
/// the control-view offset equal the linear address — the same arithmetic the
/// PM stub selectors use (their base is 0 too), so PM and RM control
/// addresses differ only in the segment/selector half. Segment 0 is never a
/// program's code segment, so the CS discrimination in `syscall` is
/// unambiguous.
pub(crate) const CTRL_STUB_SEG: u16 = 0x0000;

/// Control-view IP for a slot (= the linear address of its stub bytes).
pub(crate) const fn ctrl_slot_off(slot: u8) -> u16 {
    STUB_BASE as u16 + slot_offset(slot)
}
/// Offset within SYSPSP of the INDOS flag byte (permanently zero).
/// Placed in the "command tail" area since the system PSP never runs.
const INDOS_FLAG_OFFSET: u16 = 0xFE;

/// First free paragraph past the kernel-owned low-mem area. The initial
/// DOS program's env arena lives here; its PSP at +0x10.
pub(super) fn heap_start() -> u16 {
    let end = LOW_MEM_BASE as usize + core::mem::size_of::<LowMem>();
    ((end + 15) >> 4) as u16
}

pub(super) fn boot_psp_seg() -> u16 {
    ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u16
}
/// Bootstrap parent reference for the initial program load. The env is the
/// kernel's compiled-in `MASTER_ENV` (no allocation needed); the parent
/// PSP is the boot sentinel.
pub(super) fn boot_parent_with_env<'a>(env: &'a [u8]) -> ParentRef<'a> {
    ParentRef { psp_seg: boot_psp_seg(), env }
}

/// Base linear address + size of the kernel-shared host stack, consumed
/// by dpmi when building the three aliasing LDT selectors (PM16, PM32,
/// VM86 paragraph) that all point at this same buffer.
pub(super) fn host_stack_base() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, host_stack) as u32
}
pub(super) fn host_stack_size() -> u32 {
    HOST_STACK_SIZE as u32
}
/// SP value within `HOST_STACK_PM*_SEL` for an empty locked stack. The
/// selectors have base = host_stack_base() and limit = size−1, so the
/// post-init SP that pushes decrement from is exactly `size`. Used by
/// [`super::mode_transitions::pm_get_stack`] as the chain-empty default.
pub(super) fn host_stack_empty_sp() -> u32 {
    host_stack_size()
}

/// Base linear address + size of the per-thread dedicated RM stack.
/// `rm_stack_seg()` returns the paragraph floor of the buffer's base;
/// callers must add `(base & 0xF)` to any in-segment offset they pass
/// to BIOS as SP, to compensate for any sub-paragraph alignment of
/// the buffer's start within the LowMem layout. `mode_transitions::rm_stack_top`
/// does this for the standard "fresh-excursion top of stack" SP.
pub(super) fn rm_stack_base() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, rm_stack) as u32
}
pub(super) fn rm_stack_size() -> u32 {
    RM_STACK_SIZE as u32
}
pub(super) fn rm_stack_seg() -> u16 {
    (rm_stack_base() >> 4) as u16
}
/// Sub-paragraph offset of the buffer's base within `rm_stack_seg()`.
/// `rm_stack_seg() << 4 + rm_stack_align_offset()` == `rm_stack_base()`.
pub(super) fn rm_stack_align_offset() -> u16 {
    (rm_stack_base() & 0xF) as u16
}

/// Default size of an env block in paragraphs. Env is allocated from the
/// MCB chain like any other AH=48 block — its size is decided at alloc
/// time, not baked into a static struct.
pub(super) const ENV_PARAS: u16 = 32;       // = 512 bytes (DOS5 typical /E:512)

/// Bootstrap env defaults — copied into the freshly-allocated env block of
/// the very first program loaded (boot path). For subsequent children,
/// inheritance comes from the actual parent's env block, not from here.
/// Parse a CONFIG.SYS-style KEY=VALUE config (with `#`/`;` comments) into
/// a DOS env block (NUL-terminated entries, doubly-NUL-terminated). Used
/// by startup to build the master env handed to the first DOS programs.
pub fn parse_config_env(config: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(256);
    for line in config.split(|&b| b == b'\n') {
        let line = trim_ws(line);
        if line.is_empty() || line[0] == b'#' || line[0] == b';' { continue; }
        let eq = match line.iter().position(|&b| b == b'=') { Some(i) => i, None => continue };
        let key = trim_ws(&line[..eq]);
        if key.is_empty() { continue; }
        let val = trim_ws(&line[eq + 1..]);
        out.extend_from_slice(key);
        out.push(b'=');
        out.extend_from_slice(val);
        out.push(0);
    }
    out.push(0);
    out
}

fn trim_ws(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && matches!(s[start], b' ' | b'\t' | b'\r') { start += 1; }
    while end > start && matches!(s[end-1], b' ' | b'\t' | b'\r') { end -= 1; }
    &s[start..end]
}

/// What a child inherits from its parent: PSP segment (for child's PSP[0x16])
/// and env block (copied into the child's fresh env arena, then the DOS 3+
/// suffix appended). The env borrow can point at a live `Program::env`
/// (same-AS exec) or a kernel-side Vec snapshot (cross-AS exec where the
/// parent's pages are gone).
pub(super) struct ParentRef<'a> {
    pub psp_seg: u16,
    pub env: &'a [u8],
}

/// Output of a successful binary load — segment layout plus initial CPU
/// register values for the VM86 thread.
pub(super) struct Loaded {
    #[allow(dead_code)]
    pub env_seg: u16,
    pub psp_seg: u16,
    pub cs: u16,
    pub ip: u16,
    pub ss: u16,
    pub sp: u16,
    /// First paragraph past the loaded image (= `psp_seg + program_paras`).
    #[allow(dead_code)]
    pub end_seg: u16,
}

// ── Stub vector / slot assignments ─────────────────────────────────────
// Slot N at offset N*2 from STUB_SEG. After CD 31, IP = N*2+2, slot = (IP-2)/2.
// VM86 traps via TSS bitmap bit 31h; PM fires INT 31h directly (DPL=3).
pub(super) const STUB_INT: u8 = 0x31;
const SLOT_XMS: u8 = 0x00;
const SLOT_DPMI_ENTRY: u8 = 0x01;
pub(crate) const SLOT_RAW_REAL_TO_PM: u8 = 0x03;
pub(crate) const SLOT_CB_ENTRY_BASE: u8 = 0x04;
// Exclusive end. Stops at 0x13 because slot 0x13 collides with INT 13h
// (disk service) — the callback range MUST NOT shadow any IVT-redirected
// INT vector (INT 0x13 / 0x20 / 0x21 / 0x25 / 0x26 / 0x28 / 0x2E / 0x2F /
// 0x67). 15 callbacks at slots 0x04..0x12.
pub(crate) const SLOT_CB_ENTRY_END: u8 = 0x13;
// Inclusive last callback slot (== SLOT_CB_ENTRY_END - 1); used for the match
// range so it reads as `0x04..=0x12` rather than an exclusive end one short of
// the separate `SLOT_MOUSE_CB_RET`.
pub(crate) const SLOT_CB_ENTRY_LAST: u8 = SLOT_CB_ENTRY_END - 1;
/// Handler RETFs to this slot. `mouse_callback_return` restores the
/// bracket-saved GP regs (HostContinuation doesn't cover them) and then
/// unwinds the INT 33h callback via the standard continuation path.
pub(crate) const SLOT_MOUSE_CB_RET: u8 = 0x14;
/// Generic block-and-retry resume slot. A syscall that can't complete
/// synchronously (e.g. AH=08 with no key in the buffer) stashes a closure
/// in `dos.pending_resume` and parks user CS:IP at this stub. Each
/// event-loop iteration re-traps here, the dispatcher re-invokes the
/// closure; when it returns true (= completed) we run the same iret-frame
/// pop the original soft-INT slot would have run, unwinding the chain
/// naturally. `is_far_call`-tagged so the dispatch tail's auto-pop is
/// suppressed — the SLOT_RESUME handler manages the pop itself.
pub(crate) const SLOT_RESUME: u8 = 0x76;
pub(crate) const SLOT_SAVE_RESTORE: u8 = 0xFD;
/// DPMI 0.9 exception RETF target. Handler installed via Function
/// 0203H pops the FAR-call return at the bottom of the spec frame and
/// lands here; kernel reads handler-modified faulting fields from the
/// 0.9 portion (at +00..+1FH in the frame) and discards the rest.
pub(crate) const SLOT_EXCEPTION_RET: u8 = 0xFE;
/// DPMI 1.0 expanded-frame exception RETF target. Handler installed
/// via Function 0212H/0213H does `ADD (E)SP, 0x20; RETF` to skip past
/// the 0.9 portion and pops the FAR-call return at the +20H slot of
/// the expanded frame, landing here; kernel reads handler-modified
/// faulting fields from the 1.0 expanded portion (at +20H..+57H).
pub(crate) const SLOT_EXCEPTION_RET_V10: u8 = 0xFB;
pub(crate) const SLOT_PM_TO_REAL: u8 = 0xFF;
/// PMDOS INT 21 short-circuit. When `dpmi.pm_dos` is set (16-bit DPMI
/// clients by default), `pm_vectors[0x21]` points here instead of the
/// generic vector stub. The CD 31 traps to `pmdos_int21_handler` which
/// runs the DOS INT 21 dispatcher with PM regs intact (no mode switch),
/// then pops the frame `deliver_pm_int` planted on the client's PM stack. `linear()` sees `regs.mode() == PM` and resolves DS:DX via
/// LDT base lookup — so high-memory PM-block buffers (the case Borland's
/// `dpmiload` hits) are addressed correctly without bounce buffering.
pub(crate) const SLOT_PMDOS_INT21: u8 = 0xFC;
/// PM INT 33h (mouse) direct-service slot. `dpmi_enter` points
/// `pm_vectors[0x33]` here for every DPMI client so a PM `int 33h` is
/// serviced in protected mode with PM regs intact, rather than reflected to
/// real mode. This is what lets `int_33h` see `regs.mode() == PM` (so AX=0Ch
/// records `cb_is_pm`) and read `ES:DX` as a real selector:offset. The RM-side
/// INT 33h still routes through STUB_SEG slot 0x33 (the IVT redirect).
pub(crate) const SLOT_PMDOS_INT33: u8 = 0xFA;
/// Single continuation return target. Reflected INTs, explicit DPMI RM calls,
/// PM callback returns, and PM IRQ unwind all land here after their far return
/// or IRET. `mode_transitions::resume_continuation_from_stub` pops the captured
/// HostContinuation; an attached RmCallStruct address selects register-block
/// exchange.
pub(crate) const SLOT_RESUME_CONTINUATION: u8 = 0x02;

pub(crate) const fn slot_offset(slot: u8) -> u16 { (slot as u16) * 2 }

pub(super) fn setup_ivt<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    // Fill the stub array with `CD 31` so any slot reached by an IVT entry
    // (or PM CALL FAR) traps to STUB_INT and the slot dispatcher.
    let stubs = lm_field(core::mem::offset_of!(LowMem, stubs));
    for i in 0..256 {
        machine.write::<[u8; 2]>(stubs + i * 2, [0xCD, STUB_INT]);
    }

    // No native BIOS ROM (interp's zeroed guest RAM; UEFI metal): the
    // personality installs its own — all 256 IVT entries into the BIOS stub
    // array, services in `bios.rs`. The kernel-DOS redirects below then
    // override their vectors, layered like a real machine (BIOS, DOS on top).
    if crate::kernel::platform::get().firmware == crate::kernel::platform::Firmware::Substitute {
        super::bios::install(machine, regs);
    }

    // HW IRQ vectors (0x08-0x0F + 0x70-0x77) are left pointing at the
    // original BIOS handlers — `raise_pending` delivers IRQs through the
    // pm_vectors table (cross-mode to PM and back for VM86 clients), so the
    // IVT never needs redirection for HW IRQ delivery.

    // Hook the DOS/BIOS soft INTs we intercept so guest CD nn lands in our
    // dispatcher (slot index = INT vector).
    for &int_num in &[0x13u8, 0x20, 0x21, 0x25, 0x26, 0x28, 0x29, 0x2E, 0x2F, 0x33, 0x67] {
        write_u16(machine, 0, (int_num as u32) * 4, slot_offset(int_num));
        write_u16(machine, 0, (int_num as u32) * 4 + 2, STUB_SEG);
    }

    // INT 15h: the SeaBIOS ROM services AH=87h (block move) / AH=89h (switch to
    // PM) with protected-mode code (LGDT) that #GPs under VM86. Steal the vector
    // so our dispatcher emulates those and chains the rest back to the ROM.
    // Native path only: the Substitute BIOS already owns 0x15, and reading it
    // back (or a COW-inherited, already-redirected page 0) would capture our own
    // stub and self-loop the chain — so skip if it's already STUB_SEG.
    if crate::kernel::platform::get().firmware != crate::kernel::platform::Firmware::Substitute {
        let seg = read_u16(machine, 0, 0x15 * 4 + 2);
        if seg != STUB_SEG {
            super::bios::set_native_int15(seg, read_u16(machine, 0, 0x15 * 4));
        }
        write_u16(machine, 0, 0x15 * 4, slot_offset(0x15));
        write_u16(machine, 0, 0x15 * 4 + 2, STUB_SEG);
    }

    setup_lol_sft(machine, regs);
    xms::scan_uma(machine);

    // Force NumLock OFF in the BIOS keyboard-flags byte (40:17 bit 5). The
    // grey arrow keys are E0-stripped down to their numpad twins (Up == 0x48
    // == numpad-8) before the BIOS sees them, so with NumLock on the BIOS
    // renders them as digits ('8'/'2') instead of navigation — and a laptop
    // keyboard may have no NumLock key to clear it. 86box boots NumLock on;
    // QEMU/Bochs boot it off, which is why arrows worked there.
    let kbd_flags = read_u16(machine, 0x40, 0x17) & !0x0020;
    write_u16(machine, 0x40, 0x17, kbd_flags);
}

fn setup_lol_sft<A: crate::Arch>(machine: &mut A, _regs: &mut Regs) {
    let sft_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, sft) as u32;
    let cds_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, cds) as u32;
    let boot_seg = ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u16;

    // Bootstrap sentinel PSP: self-referencing parent_psp terminates any
    // PSP[0x16] walk, env_seg = 0 (env defaults live in MASTER_ENV
    // const, not on the chain). The cmdline area at 0x80+ is otherwise
    // unused and gives us a permanent zero byte at the INDOS-flag offset.
    Psp::store(machine, boot_seg, Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp: boot_seg,         // self-ref terminates the parent chain
        env_seg: 0,
        ..Default::default()
    });

    let lol = Lol {
        sft_off: (sft_addr & 0xF) as u16,
        sft_seg: (sft_addr >> 4) as u16,
        cds_off: (cds_addr & 0xF) as u16,
        cds_seg: (cds_addr >> 4) as u16,
        block_devs: 1,
        last_drive: NUM_DRIVES,
        ..Default::default()
    };
    machine.write::<Lol>(lm_field(core::mem::offset_of!(LowMem, lol)), lol);

    // SFT header: end-of-chain link, entry count + zeroed entries; then
    // pre-populate stdin/stdout/stderr as character devices.
    let mut sft = Sft { next: 0xFFFF_FFFF, count: SFT_ENTRIES as u16, ..Default::default() };
    for fd in 0..3 {
        sft.entries[fd] = SftEntry {
            refcount: 1,
            device_info: if fd == 0 { 0x81 } else { 0x82 },
            ..Default::default()
        };
    }
    machine.write::<Sft>(lm_field(core::mem::offset_of!(LowMem, sft)), sft);

    // CDS: drive 2 = C:\, drive 7 = H:\ (hostfs). Others stay invalid.
    let mk = |drive_letter: u8| -> CdsEntry {
        let mut e = CdsEntry::default();
        e.path[0] = drive_letter;
        e.path[1] = b':';
        e.path[2] = b'\\';
        e.flags = 0x4000;
        e.backslash_off = 2;
        e
    };
    let mut cds = [(); NUM_DRIVES as usize].map(|_| CdsEntry::default());
    cds[2] = mk(b'C');
    cds[7] = mk(b'H');
    machine.write::<[CdsEntry; NUM_DRIVES as usize]>(lm_field(core::mem::offset_of!(LowMem, cds)), cds);
}


/// Linear address of `LowMem.sft.entries[handle]`.
#[inline]
fn sft_entry_addr(handle: usize) -> usize {
    lm_field(core::mem::offset_of!(LowMem, sft) + core::mem::offset_of!(Sft, entries)
        + handle * core::mem::size_of::<SftEntry>())
}

/// Populate SFT entry for a newly opened file handle.
fn sft_set_file<A: crate::Arch>(machine: &mut A, handle: u16, size: u32) {
    if handle as usize >= SFT_ENTRIES { return; }
    machine.write::<SftEntry>(sft_entry_addr(handle as usize), SftEntry {
        refcount: 1,
        attribute: 0x20,    // archive
        time: 0x6000,       // 12:00:00
        date: 0x5C76,       // 2026-03-22
        size,
        ..Default::default()
    });
}

/// Clear SFT entry when a file handle is closed.
fn sft_clear<A: crate::Arch>(machine: &mut A, handle: u16) {
    if handle as usize >= SFT_ENTRIES { return; }
    machine.write::<u16>(sft_entry_addr(handle as usize) + core::mem::offset_of!(SftEntry, refcount), 0);
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Fill a fresh env arena: copy the parent's variable strings (up to the
/// `00 00` terminator), then append the DOS 3+ suffix `01 00 <prog_name> 00`.
/// Per DOS EXEC (AH=4B), the child always gets a fresh arena — the parent's
/// env is *copied*, never shared.
/// Populate a freshly-allocated env block. Copies parent's variable
/// strings (up to the `00 00` terminator) into `env`, then appends the
/// DOS 3+ suffix `01 00 <prog_name> 00`. Per DOS EXEC (AH=4B), each
/// child gets a fresh arena — the parent's env is *copied*, never shared.
fn fill_env(env: &mut [u8], parent_env: &[u8], prog_name: &[u8]) {
    for b in env.iter_mut() { *b = 0; }
    let suffix_need = 2 + prog_name.len() + 1;
    let vars_cap = env.len().saturating_sub(suffix_need);
    let mut off = 0usize;
    let mut i = 0usize;
    let mut prev_was_nul = false;
    while off < vars_cap && i < parent_env.len() {
        let b = parent_env[i];
        env[off] = b;
        i += 1; off += 1;
        if b == 0 && prev_was_nul { break; }
        prev_was_nul = b == 0;
    }
    // DOS 3+ suffix: word 01 00, then child's own program pathname (drive-
    // qualified uppercase DOS form, e.g. "C:\BIN\PROG.EXE"), then NUL. DOS
    // extenders (BC, dos4gw, dos16m) parse this field back.
    env[off] = 0x01; env[off + 1] = 0x00;
    off += 2;
    for &b in prog_name {
        if off + 1 >= env.len() { break; }
        env[off] = b;
        off += 1;
    }
    env[off] = 0;
}

/// Initialize a freshly-allocated PSP at `psp_seg` to point at its env
/// block at `env_seg`, with parent_psp / JFT / cmdline default fields set.
fn init_psp<A: crate::Arch>(machine: &mut A, _regs: &mut Regs, psp_seg: u16, env_seg: u16, parent_psp: u16) {
    let mut jft = [0xFFu8; 20];
    jft[0] = 0; jft[1] = 1; jft[2] = 2;   // stdin/stdout/stderr → SFT 0/1/2
    let mut cmdline = [0u8; 127];
    cmdline[0] = 0x0D;                      // empty tail terminated by CR

    Psp::store(machine, psp_seg, Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp,
        env_seg,
        jft,
        max_files: 20,
        jft_far_off: 0x0018,
        jft_far_seg: psp_seg,
        cmdline_len: 0,
        cmdline,
        ..Default::default()
    });

    let mut env = [0u8; 80];
    machine.copy_from((env_seg as usize) << 4, &mut env);
    let mut dump = [0u8; 80];
    for (i, &b) in env.iter().enumerate() {
        dump[i] = if b == 0 { b'.' } else if !(32..127).contains(&b) { b'?' } else { b };
    }
    dos_trace!("map_psp psp={:04X} env={:04X} parent_psp={:04X} env[0..80]={:?}",
        psp_seg, env_seg, parent_psp,
        core::str::from_utf8(&dump).unwrap_or("?"));
}

/// Check if data starts with the MZ signature.
pub(super) fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Allocate the env block (`ENV_PARAS` paragraphs) and program block as
/// separate AH=48-style allocations on `dos`'s MCB chain, exactly like
/// real DOS does on `INT 21h AH=4B EXEC`. Returns `(env_seg, psp_seg,
/// end_seg)`.
fn alloc_program_blocks<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, prog_paras: u16)
    -> Result<(u16, u16, u16), ()>
{
    let env_seg = dos_alloc_block(machine, dos, regs, ENV_PARAS).map_err(|_| ())?;
    let psp_seg = dos_alloc_block(machine, dos, regs, prog_paras).map_err(|_| ())?;
    let end_seg = psp_seg.wrapping_add(prog_paras);
    Ok((env_seg, psp_seg, end_seg))
}

/// Populate the env block + PSP + load module for a freshly-allocated
/// program. Common to `load_exe` and `load_com`. Sets `dos.current_psp`
/// and re-syncs the MCB chain so block ownership reflects the new PSP.
fn populate_program<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, env_seg: u16, psp_seg: u16,
                    parent: &ParentRef, prog_name: &[u8]) {
    // Build the env arena in a local buffer, write it to guest memory, and
    // read the BLASTER config from the same buffer (no second guest read).
    let mut env = alloc::vec![0u8; (ENV_PARAS as usize) * 16];
    fill_env(&mut env, parent.env, prog_name);
    machine.copy_to(((env_seg as u32) << 4) as usize, &env);
    // Latch this program's BLASTER A/I/D/H into the SB-DMA layer so the
    // virtual 8237 traps the right channel and the IRQ relay uses the
    // right vector. Missing BLASTER leaves the SB16 defaults.
    dos.pc.sb.configure_from_env(&env);
    // ULTRASND makes the (emulated) GUS exist for this program and sets its
    // base/DMA/IRQ wiring; without it the card stays absent.
    dos.pc.gus.configure_from_env(&env);
    init_psp(machine, regs, psp_seg, env_seg, parent.psp_seg);
    dos.current_psp = psp_seg;
    dos_set_program_block_owner(machine, dos, regs, env_seg, psp_seg, psp_seg);
}

/// Load a .COM binary. Allocates env + program block (1000h paragraphs =
/// 64 KB, the standard .COM arena), populates env/PSP/code. Stack at
/// PSP:COM_SP (top of 64 KB segment), code at (psp+0x10):0000.
pub(super) fn load_com<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Loaded {
    let (env_seg, psp_seg, end_seg) = alloc_program_blocks(machine, dos, regs, 0x1000)
        .expect("load_com: allocation failed");
    populate_program(machine, regs, dos, env_seg, psp_seg, parent, prog_name);

    // Load .COM code at psp_seg:0x100 (= (psp_seg+0x10):0).
    let load_addr = ((psp_seg as u32) << 4) + COM_OFFSET as u32;
    machine.copy_to(load_addr as usize, data);

    Loaded {
        env_seg, psp_seg,
        cs: psp_seg, ip: COM_OFFSET, ss: psp_seg, sp: COM_SP,
        end_seg,
    }
}

/// Load an MZ .EXE binary at `heap_end` (env_seg).
///
/// MZ header layout (first 28 bytes):
///   0x00: 'MZ' signature
///   0x02: bytes on last page (0 = full 512-byte page)
///   0x04: total pages (512 bytes each, includes header)
///   0x06: relocation count
///   0x08: header size in paragraphs (16 bytes each)
///   0x0E: initial SS (relative to load segment)
///   0x10: initial SP
///   0x14: initial IP
///   0x16: initial CS (relative to load segment)
///   0x18: relocation table offset
pub(super) fn load_exe<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: &mut thread::DosState<A>, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Option<Loaded> {
    if data.len() < 28 { return None; }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
    let min_extra = w(0x0A) as u32;
    let max_extra = w(0x0C) as u32;
    let init_ss = w(0x0E);
    let init_sp = w(0x10);
    let init_ip = w(0x14);
    let init_cs = w(0x16);
    let reloc_offset = w(0x18) as usize;

    let file_size = if last_page_bytes == 0 {
        total_pages * 512
    } else {
        (total_pages - 1) * 512 + last_page_bytes
    };
    let header_size = header_paragraphs * 16;
    let load_size = file_size.saturating_sub(header_size) as usize;

    if header_size as usize > data.len() || load_size > data.len() - header_size as usize {
        return None;
    }

    let load_paras = (load_size as u32).div_ceil(16) as u16;
    // Real DOS gives the program min(e_maxalloc, available) extra paragraphs
    // above the load module. Programs with e_maxalloc=0xFFFF (Watcom, BC, most
    // Turbo) expect ALL available conventional memory and then `AH=4A` it back
    // down. "Available" is the largest FREE region in the live MCB chain — NOT
    // 0xA000-heap_base — because EXEC no longer resets the chain, so the parent
    // (and prior siblings) keep their blocks. Allocate the env block first,
    // then size the program to the largest remaining free region so it lands
    // in one contiguous block that never overlaps a still-live parent (e.g.
    // BC's PM CS alias). exec_return drops these blocks when the child exits.
    let env_seg = dos_alloc_block(machine, dos, regs, ENV_PARAS).ok()?;
    let avail = super::largest_dos_block(dos);
    let base_paras = 0x10u16.saturating_add(load_paras);
    let floor = base_paras.saturating_add(min_extra as u16);
    if avail < floor { return None; }
    let prog_paras = base_paras.saturating_add(max_extra as u16).min(avail).max(floor);
    let psp_seg = dos_alloc_block(machine, dos, regs, prog_paras).ok()?;
    let end_seg = psp_seg.wrapping_add(prog_paras);
    populate_program(machine, regs, dos, env_seg, psp_seg, parent, prog_name);

    // Load module starts 0x10 paragraphs after the PSP.
    let load_segment = psp_seg + 0x10;

    let load_base = (load_segment as u32) << 4;
    let load_data = &data[header_size as usize..header_size as usize + load_size];
    machine.copy_to(load_base as usize, load_data);

    // Zero the allocation tail so re-exec cannot expose stale data past the image.
    let bss_start = load_base + load_size as u32;
    let bss_end = (end_seg as u32) << 4;
    if bss_end > bss_start {
        machine.zero(bss_start as usize, (bss_end - bss_start) as usize);
    }

    // Apply relocations: each entry is (offset, segment) within the load
    // module. Add load_segment to the 16-bit word at that address.
    let reloc_end = reloc_offset + reloc_count * 4;
    if reloc_end > data.len() { return None; }
    for i in 0..reloc_count {
        let entry = reloc_offset + i * 4;
        let off = w(entry) as u32;
        let seg = w(entry + 2) as u32;
        let addr = (load_base + (seg << 4) + off) as usize;
        let val: u16 = machine.read(addr);
        machine.write::<u16>(addr, val.wrapping_add(load_segment));
    }

    Some(Loaded {
        env_seg, psp_seg,
        cs: init_cs.wrapping_add(load_segment),
        ip: init_ip,
        ss: init_ss.wrapping_add(load_segment),
        sp: init_sp,
        end_seg,
    })
}
