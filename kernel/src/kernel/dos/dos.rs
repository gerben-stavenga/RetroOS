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
    dos_reset_blocks, dos_alloc_block, dos_free_block, dos_resize_block,
    DOS_TRACE_RT, DOS_TRACE_HW_RT,
};
use super::{dpmi, dfs, machine, xms};
use super::ems::{EMS_ENABLED, EMS_DEVICE_HANDLE, int_67h};
use super::xms::xms_dispatch;
use super::dos_trace;
use super::machine::{
    IF_FLAG,
    read_u16, write_u16,
    vm86_cs, vm86_ip, vm86_ss, vm86_sp, vm86_flags,
    set_vm86_cs, set_vm86_ip,
    vm86_push, vm86_pop,
    reflect_interrupt, clear_bios_keyboard_buffer, pop_bios_keyboard_word,
};

/// Dummy file handle returned for /dev/null semantics.
const NULL_FILE_HANDLE: u16 = 99;

/// .COM entry IP (relative to its PSP segment). Equivalent to `(psp+0x10):0000`.
const COM_OFFSET: u16 = 0x0100;
/// Initial stack pointer for .COM (top of PSP's 64KB segment)
const COM_SP: u16 = 0xFFFE;

fn poll_dos_console_char(dos: &mut thread::DosState) -> Option<u8> {
    if let Some(ch) = dos.dos_pending_char.take() {
        return Some(ch);
    }

    let word = pop_bios_keyboard_word()?;
    let ascii = word as u8;
    let scan = (word >> 8) as u8;
    if ascii == 0 && scan != 0 {
        dos.dos_pending_char = Some(scan);
    }
    Some(ascii)
}

/// Handle INT n from VM86 mode. Only bitmap-trapped INTs bubble up here;
/// arch does the SW IVT reflect for the rest. In our setup only `STUB_INT`
/// is in the bitmap.
pub(super) fn handle_vm86_int(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs, int_num: u8) -> thread::KernelAction {
    match int_num {
        STUB_INT => stub_dispatch(kt, dos, regs),
        _ => panic!("VM86: INT {:02X} bubbled to dos but only STUB_INT should trap", int_num),
    }
}

// ============================================================================
// Stub dispatch — routes INT 31h from unified CD 31 array by slot number
// ============================================================================

/// Dispatch a kernel-owned DOS/BIOS vector directly (no V86 detour).
///
/// Used by both the V86 stub dispatcher and the DPMI PM soft-int fast path.
/// The caller is responsible for any mode-specific frame housekeeping after
/// the call (V86 stack pop, PM return-frame restore, etc.).
pub(crate) fn dispatch_kernel_syscall(
    kt: &mut thread::KernelThread,
    dos: &mut thread::DosState,
    regs: &mut Regs,
    vector: u8,
) -> thread::KernelAction {
    match vector {
        0x08 => thread::KernelAction::Done, // timer — handled via VM86 IRQ reflect path
        0x13 => int_13h(regs),
        0x20 => {
            if let Some(parent) = dos.exec_parent.take() {
                dos.last_child_exit_status = 0x0000;
                return exec_return(dos, regs, parent);
            }
            thread::KernelAction::Exit(0)
        }
        0x21 => int_21h(kt, dos, regs),
        // INT 25h/26h — Absolute Disk Read/Write — return error
        0x25 | 0x26 => {
            regs.rax = (regs.rax & !0xFF00) | (0x02 << 8); // AH=02 address mark not found
            regs.set_flag32(1); // CF=1 error
            thread::KernelAction::Done
        }
        0x28 => thread::KernelAction::Done, // INT 28h — DOS idle
        0x2E => int_2eh(kt, dos, regs),
        0x2F => int_2fh(dos, regs),
        0x67 => int_67h(dos, regs),
        _ => {
            dos_trace!("dispatch_kernel_syscall: unhandled vector {:#04x}", vector);
            thread::KernelAction::Done
        }
    }
}

/// Dispatch INT 31h from the unified stub array. Slot = (IP - 2) / 2.
/// IVT-redirect stubs have a FLAGS/CS/IP frame on the VM86 stack from the
/// original INT; far-call stubs have a CS/IP frame from CALL FAR.
/// The kernel pops these frames directly — no RETF/RETF 2 in the stub.
fn stub_dispatch(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ip = vm86_ip(regs);
    let cs = vm86_cs(regs);

    // INT 31h from user code (outside the stub segment) = synth syscall.
    // AH selects the subfunction. Unknown subfunctions fall through to IVT reflect.
    if cs != STUB_SEG {
        return synth_dispatch(kt, dos, regs);
    }

    let slot = ((ip.wrapping_sub(2)) / 2) as u8;
    let is_far_call = matches!(slot,
        SLOT_XMS | SLOT_DPMI_ENTRY | SLOT_CALLBACK_RET | SLOT_RM_INT_RET
        | SLOT_RAW_REAL_TO_PM | SLOT_SAVE_RESTORE)
        || (slot >= SLOT_CB_ENTRY_BASE && slot < SLOT_CB_ENTRY_END);

    let action = match slot {
        SLOT_XMS => xms_dispatch(dos, regs),
        SLOT_DPMI_ENTRY => {
            dpmi::dpmi_enter(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CALLBACK_RET => {
            dpmi::callback_return(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_RM_INT_RET => {
            // Implicit INT reflection (no PM handler installed). Same
            // unwind as a callback, then synthesize the STI that DPMI
            // requires IRQ handlers to perform before IRET — our default
            // stub is the nominal handler here.
            dpmi::callback_return(dos, regs);
            regs.frame.rflags |= machine::IF_FLAG as u64;
            DOS_TRACE_HW_RT.store(true, core::sync::atomic::Ordering::Relaxed);
            thread::KernelAction::Done
        }
        SLOT_RAW_REAL_TO_PM => {
            dpmi::raw_switch_real_to_pm(dos, regs);
            thread::KernelAction::Done
        }
        SLOT_CB_ENTRY_BASE..SLOT_CB_ENTRY_END => {
            let cb_idx = (slot - SLOT_CB_ENTRY_BASE) as usize;
            dpmi::callback_entry(dos, regs, cb_idx);
            thread::KernelAction::Done
        }
        SLOT_HW_IRQ_BASE..SLOT_HW_IRQ_END => {
            // Hardware IRQ N: chain to BIOS handler on private stack.
            // Reflect frame (FLAGS/CS/IP) stays on current stack — BIOS IRET pops it.
            hw_irq_reflect(dos, regs, slot - SLOT_HW_IRQ_BASE);
            return thread::KernelAction::Done;
        }
        0x13 | 0x20 | 0x21 | 0x25 | 0x26 | 0x28 | 0x2E | 0x2F | 0x67 => {
            // Restore caller FLAGS into regs so handlers may mutate them
            // (CF/ZF returns); then write back so normal IRET-style pop
            // restores the handler's result to the caller.
            let caller_flags = read_u16(vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4));
            machine::set_vm86_flags(regs, caller_flags as u32);
            let action = dispatch_kernel_syscall(kt, dos, regs, slot);
            // exec_return / Exit replace thread state — skip the VM86 frame pop below.
            if !matches!(action, thread::KernelAction::Done) {
                return action;
            }
            write_u16(vm86_ss(regs) as u32, (vm86_sp(regs) as u32).wrapping_add(4),
                      machine::vm86_flags(regs) as u16);
            action
        }
        SLOT_HW_IRQ_RET => {
            // BIOS handler IRET'd to trampoline. Restore original SS:SP;
            // the common pop below IRETs the reflect frame back to the
            // interrupted code (including its flags).
            let (ss, sp) = dos.pc.irq_saved_sssp.take().expect("HW_IRQ_RET without saved SS:SP");
            machine::set_vm86_ss(regs, ss);
            machine::set_vm86_sp(regs, sp);
            thread::KernelAction::Done
        }
        SLOT_SAVE_RESTORE => {
            dpmi::save_restore_protected_mode_state(dos, regs);
            thread::KernelAction::Done
        }
        _ => {
            panic!("VM86: INT 31h unknown stub slot {:#04x} CS:IP={:04x}:{:#06x}", slot, cs, ip);
        }
    };

    // Pop the VM86 stack frame left by the caller before returning.
    // IVT-redirect: original INT pushed FLAGS/CS/IP (6 bytes) — pop and return to caller.
    // Far-call (XMS): CALL FAR pushed CS/IP (4 bytes) — pop and return to caller.
    // Mode-switching stubs (DPMI entry, raw switch, callbacks) replace all regs — skip.
    if !is_far_call {
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        let ret_flags = vm86_pop(regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
        machine::set_vm86_flags(regs, ret_flags as u32);
    } else if matches!(slot, SLOT_XMS | SLOT_SAVE_RESTORE) {
        // Returns to caller — pop far-call return address
        let ret_ip = vm86_pop(regs);
        let ret_cs = vm86_pop(regs);
        set_vm86_ip(regs, ret_ip);
        set_vm86_cs(regs, ret_cs);
    }
    // Other far-call stubs (DPMI entry, raw switch, callbacks) switch modes entirely

    action
}

// ============================================================================
// Synth syscalls — invoked by user-code INT 31h (outside STUB_SEG).
// Modeled as a tiny set of primitives that COMMAND.COM (or any program)
// can call to coordinate processes + VGA across threads.
// ============================================================================

/// INT 31h from user code. AH selects subfunction.
/// On success: AX=0, CF=0. On error: AX=errno (unsigned), CF=1.
/// Unknown AH reflects through IVT (legacy DPMI int-31 path).
fn synth_dispatch(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        // AH=00h — SYNTH_VGA_TAKE: adopt target thread's screen.
        // Input:  BX = target pid
        // Output: AX = 0 on success, errno on failure; CF reflects error.
        0x00 => {
            let pid = (regs.rbx & 0xFFFF) as i16 as i32;
            let dst = &mut dos.pc.vga as *mut machine::VgaState;
            let rv = thread::with_target_dos(pid, |target| {
                let src = &mut target.pc.vga;
                if src.planes.is_empty() { return -61; }
                unsafe {
                    core::mem::swap(&mut *dst, src);
                    (*dst).restore_to_hardware();
                }
                0
            });
            regs.rax = (regs.rax & !0xFFFF) | ((rv as i16 as u16) as u64);
            if rv < 0 { regs.set_flag32(1); } else { regs.clear_flag32(1); }
            thread::KernelAction::Done
        }
        // AH=01h — SYNTH_FORK_EXEC_WAIT: fork+exec program and wait for it.
        // Reads the caller's own PSP cmdline at DS:0080h (byte-count + text),
        // strips leading whitespace and an optional "/C", takes the first
        // whitespace-delimited token as the program name.
        // Output on success (CF=0):
        //          BX = child pid (valid in both exit and decoupled cases)
        //          AX = 0 on normal exit (exit code via INT 21h/4Dh)
        //          AX = 1 on decoupled (F11 broke wait)
        // Output on error (CF=1):
        //          AX = errno
        0x01 => {
            let psp = linear(dos, regs, regs.ds as u16, 0);
            let tail_len = unsafe { *((psp + 0x80) as *const u8) } as usize;
            let read = |i: usize| -> u8 {
                unsafe { *((psp + 0x81 + i as u32) as *const u8) }
            };
            let mut i = 0;
            while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            if i + 1 < tail_len && read(i) == b'/' && (read(i + 1) & 0xDF) == b'C' {
                i += 2;
                while i < tail_len && matches!(read(i), b' ' | b'\t') { i += 1; }
            }
            let mut filename = [0u8; 128];
            let mut flen = 0;
            while i < tail_len && flen < 127 {
                let c = read(i);
                if matches!(c, b' ' | b'\t' | b'\r' | 0) { break; }
                filename[flen] = c;
                flen += 1;
                i += 1;
            }
            if flen == 0 {
                regs.rax = (regs.rax & !0xFFFF) | 2; // ENOENT
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
            // If the name is a .BAT, expand to its first executable command.
            let flen = expand_bat(dos, &mut filename, flen, kt);
            fork_exec(dos, &filename[..flen], kt)
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

/// INT 08h — Timer tick (IRQ0).
/// Replaces the BIOS handler: increment BDA tick counter, call INT 1Ch.
/// Handled in kernel to avoid BIOS handler's stack usage on the program's
/// stack (which can corrupt tiny .COM stubs like LZEXE decompressors).
/// Saved BIOS IRQ handlers (before we hook the IVT). Indexed by IRQ number
/// 0..15 (not interrupt vector). IRQ 0..7 = INT 0x08..0x0F, IRQ 8..15 =
/// INT 0x70..0x77.
static mut BIOS_HW_IRQ: [(u16, u16); 16] = [(0, 0); 16];

/// Convert IRQ number (0..15) to its real-mode interrupt vector.
fn irq_to_vector(irq: u8) -> u8 {
    if irq < 8 { 0x08 + irq } else { 0x70 + (irq - 8) }
}

/// INT 08h — Timer tick (IRQ0).
/// Switch to private IRQ stack, then chain to BIOS handler.
/// When the BIOS handler IRETs, it returns to SLOT_HW_IRQ_RET which
/// traps back to kernel to restore the original SS:SP.
/// Hardware IRQ reflect with private stack.
/// The reflect frame (FLAGS/CS/IP) stays on the original VM86 stack.
/// We switch to a private stack, push a trampoline, and jump to the
/// saved BIOS handler.  BIOS IRETs to trampoline → SLOT_HW_IRQ_RET
/// restores SS:SP → post-match pops the reflect frame → done.
fn hw_irq_reflect(dos: &mut thread::DosState, regs: &mut Regs, irq: u8) {
    if dos.pc.irq_saved_sssp.is_none() {
        // First hardware IRQ: switch to private stack, push trampoline.
        dos.pc.irq_saved_sssp = Some((vm86_ss(regs), vm86_sp(regs)));
        machine::set_vm86_ss(regs, IRQ_STACK_SEG);
        machine::set_vm86_sp(regs, IRQ_STACK_TOP);

        vm86_push(regs, vm86_flags(regs) as u16);
        vm86_push(regs, STUB_SEG);
        vm86_push(regs, slot_offset(SLOT_HW_IRQ_RET));
    }
    // Reflect frame (FLAGS/CS/IP) is on the current stack (original or IRQ).
    let (bios_cs, bios_ip) = unsafe { BIOS_HW_IRQ[irq as usize] };
    set_vm86_ip(regs, bios_ip);
    set_vm86_cs(regs, bios_cs);
    regs.clear_flag32(IF_FLAG);
    // Suppress TF inside the BIOS handler. The flags pushed above still have
    // TF=caller's value, so IRET restores stepping when BIOS returns.
    regs.clear_flag32(1 << 8);
}

fn int_13h(regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let dl = regs.rdx as u8; // drive number
    // For floppy drives (DL < 0x80), return "drive not ready" error.
    // Hard drives (DL >= 0x80) are also unsupported — return error.
    match ah {
        // AH=00h Reset Disk — just succeed
        0x00 => {
            regs.rax = regs.rax & !0xFF00; // AH=0 success
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
                regs.rax = regs.rax & !0xFF00; // AH=0 success
                regs.rbx = (regs.rbx & !0xFF) | 0; // BL=drive type (0 for HD)
                regs.rcx = (regs.rcx & !0xFFFF) | ((32 << 8) | 63); // CH=max cyl low, CL=max sect
                regs.rdx = (regs.rdx & !0xFFFF) | ((1 << 8) | 1); // DH=max head, DL=number of drives
                regs.clear_flag32(1);
            }
        }
        // AH=15h Get Disk Type
        0x15 => {
            if dl < 0x80 {
                // No floppy: AH=0 means "no such drive"
                regs.rax = regs.rax & !0xFF00;
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

/// DOS character output — writes via VGA putchar and syncs the BDA cursor
/// position at 0040:0050 so BIOS and programs (like DN) that read the BDA
/// cursor see the correct position.
fn dos_putchar(c: u8) {
    use crate::arch::outb;
    unsafe {
        let col = core::ptr::read_volatile(0x450 as *const u8) as usize;
        let row = core::ptr::read_volatile(0x451 as *const u8) as usize;
        let v = vga::vga();
        v.set_cursor_pos(col, row);
        v.putchar(c);
        let (col, row) = v.cursor_pos();
        core::ptr::write_volatile(0x450 as *mut u8, col as u8);
        core::ptr::write_volatile(0x451 as *mut u8, row as u8);
        // Update CRTC hardware cursor so save_from_hardware captures it
        let offset = (row * 80 + col) as u16;
        outb(0x3D4, 0x0E); outb(0x3D5, (offset >> 8) as u8);
        outb(0x3D4, 0x0F); outb(0x3D5, offset as u8);
    }
}

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

fn int_21h(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    if ah != 0x2C && ah != 0x2A && regs.mode() == crate::UserMode::VM86 {
        dos_trace!(force "[INT21] AX={:04x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
            regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
            regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    }
    match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            dos_putchar(regs.rdx as u8);
            thread::KernelAction::Done
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40); // clear ZF = char available
                } else {
                    regs.set_flag32(0x40); // set ZF = no char available
                }
            } else {
                dos_putchar(dl);
            }
            thread::KernelAction::Done
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let start = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut addr = start;
            loop {
                let ch = unsafe { *(addr as *const u8) };
                if ch == b'$' { break; }
                dos_putchar(ch);
                addr = addr.wrapping_add(1);
                // Safety limit: cap at 64 KiB from start
                if addr.wrapping_sub(start) > 0xFFFF { break; }
            }
            thread::KernelAction::Done
        }
        // AH=0x0B: Check Standard Input Status — AL=0 no char, 0xFF char ready
        0x0B => {
            regs.rax = (regs.rax & !0xFF) | 0x00; // no character available
            thread::KernelAction::Done
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            let off = regs.rdx as u16;
            let seg = regs.ds as u16;
            write_u16(0, (int_num as u32) * 4, off);
            write_u16(0, (int_num as u32) * 4 + 2, seg);
            thread::KernelAction::Done
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => { regs.rdx = regs.rdx & !0xFF; } // DL=0: break checking off
                0x01 => {} // set break — ignore
                _ => {
                    dos_trace!("D21 33 unsupported AL={:02X}", al);
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
                regs.rbx = (regs.rbx & !0xFFFF) | (&raw const low_mem().sys.psp as u32 + INDOS_FLAG_OFFSET as u32) as u64;
            } else {
                regs.es = (&raw const low_mem().sys.psp as u32 >> 4) as u64;
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
                let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
                let cwd = dos.dfs.get_cwd();
                unsafe {
                    for (i, &b) in cwd.iter().enumerate() {
                        *((addr + i as u32) as *mut u8) = b;
                    }
                    *((addr + cwd.len() as u32) as *mut u8) = 0;
                }
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
            clear_bios_keyboard_buffer();
            dos.dos_pending_char = None;
            // Just execute the sub-function in AL
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                if let Some(ch) = poll_dos_console_char(dos) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40);
                } else {
                    regs.set_flag32(0x40); // ZF=1
                }
            }
            // Other sub-functions: just return
            thread::KernelAction::Done
        }
        // AH=0x0D: Disk Reset (flush buffers) — no-op on RAM-backed FS
        0x0D => {
            thread::KernelAction::Done
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
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
            let off = read_u16(0, (int_num as u32) * 4);
            let seg = read_u16(0, (int_num as u32) * 4 + 2);
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                // PM client: return LOW_MEM_SEL:linear so the selector is valid.
                let linear = ((seg as u32) << 4).wrapping_add(off as u32);
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (linear & 0xFFFF) as u64;
            } else {
                // V86 / real mode: return the raw IVT seg:off pair.
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
            let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            unsafe {
                let p = addr as *mut u8;
                core::ptr::write_bytes(p, 0, 24); // zero first 24 bytes (through case-map)
                // +00: date format (0 = USA: mm/dd/yy)
                // +02: currency symbol '$\0\0\0\0'
                *p.add(2) = b'$';
                // +07: thousands separator ',\0'
                *p.add(7) = b',';
                // +09: decimal separator '.\0'
                *p.add(9) = b'.';
                // +0B: date separator '/\0'
                *p.add(0x0B) = b'/';
                // +0D: time separator ':\0'
                *p.add(0x0D) = b':';
            }
            regs.rbx = (regs.rbx & !0xFFFF) | 1; // country code = 1 (USA)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut path = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *((addr + i as u32) as *const u8) };
                if ch == 0 { break; }
                path[i] = ch;
                i += 1;
            }
            let err = dos.dfs.chdir(&path[..i]);
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
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
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
                    sft_set_file(fd as u16, size);
                    if (fd as usize) < 20 { program_at(dos.current_psp).psp.jft[fd as usize] = fd as u8; }
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
            if handle != NULL_FILE_HANDLE && (!EMS_ENABLED || handle != EMS_DEVICE_HANDLE) {
                crate::kernel::vfs::close(handle as i32, &mut kt.fds);
                sft_clear(handle);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as u16 as i32;
            let count = regs.rcx as u16 as usize;
            let buf_addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            if handle == 0 {
                // stdin — read from virtual keyboard
                // Return 0 for now (no line-buffered stdin in VM86)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == 1 || handle == 2 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — return 0 bytes (EOF)
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else if count == 0 || buf_addr == 0 {
                regs.rax = regs.rax & !0xFFFF;
                regs.clear_flag32(1);
            } else {
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, count) };
                crate::dbg_println!("D21 3F enter h={} req={:#X} buf={:08X}", handle, count, buf_addr);
                let n = crate::kernel::vfs::read(handle, buf, &kt.fds);
                crate::dbg_println!("D21 3F exit  h={} req={:#X} got={:#X}", handle, count, n);
                if n >= 0 {
                    if (n as usize) < count { dos_trace!("D21 3F SHORT h={} req={} got={}", handle, count, n); }
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
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut raw = [0u8; 80];
            let mut raw_len = 0;
            while raw_len < 79 {
                let ch = unsafe { *(addr as *const u8) };
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
            find_matching_file(dos, regs)
        }
        // AH=0x4F: Find next matching file
        0x4F => {
            find_matching_file(dos, regs)
        }
        // AH=0x4C: Terminate with return code (AL)
        0x4C => {
            // If we're in an EXEC'd child, return to parent
            if let Some(parent) = dos.exec_parent.take() {
                // Termination type 00h (normal) | return code in AL.
                dos.last_child_exit_status = (regs.rax as u8) as u16;
                return exec_return(dos, regs, parent);
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
                let child_psp_seg = parent.heap_seg;
                let resident_top = child_psp_seg.saturating_add(keep);
                // Termination type 03h (TSR) | return code in AL.
                dos.last_child_exit_status = 0x0300 | (regs.rax as u8) as u16;
                let action = exec_return(dos, regs, parent);
                if resident_top > dos.heap_seg {
                    dos_reset_blocks(dos, resident_top);
                }
                return action;
            }
            let code = regs.rax as u8;
            thread::KernelAction::Exit(code as i32)
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            match dos_alloc_block(dos, need) {
                Ok(seg) => {
                    regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                    regs.clear_flag32(1);
                }
                Err(avail) => {
                    regs.rax = (regs.rax & !0xFFFF) | 8; // insufficient memory
                    regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                    regs.set_flag32(1);
                }
            }
            thread::KernelAction::Done
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            match dos_free_block(dos, regs.es as u16) {
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
            match dos_resize_block(dos, regs.es as u16, regs.rbx as u16) {
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
                        // File handle: bit 7=0 (file), bits 5-0=drive (2=C:)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0002;
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
                    regs.rdx = (regs.rdx & !0xFFFF) | 0x0000; // bit 12=0 = local
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
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let fd = match dfs_create_path(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 4; // too many open files
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
                let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
                for i in 0..count as u32 {
                    let ch = unsafe { *((addr + i) as *const u8) };
                    dos_putchar(ch);
                }
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else if handle == NULL_FILE_HANDLE {
                regs.rax = (regs.rax & !0xFFFF) | count as u64;
            } else {
                let addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
                let data = unsafe { core::slice::from_raw_parts(addr as *const u8, count as usize) };
                let n = crate::kernel::vfs::write(handle as i32, data, &kt.fds);
                regs.rax = (regs.rax & !0xFFFF) | if n >= 0 { n as u64 } else { count as u64 };
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as u16 as i32;
            if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — always at position 0
                regs.rdx = regs.rdx & !0xFFFF;
                regs.rax = regs.rax & !0xFFFF;
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
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            { let p = addr as *const u8; let mut hex = [0u8; 32];
              for j in 0..16usize { let b = unsafe { *p.add(j) }; hex[j*2] = b"0123456789ABCDEF"[(b>>4) as usize]; hex[j*2+1] = b"0123456789ABCDEF"[(b&0xF) as usize]; }
              dos_trace!("D21 43 addr={:08X} hex={}", addr, core::str::from_utf8(&hex).unwrap()); }
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
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
                if al == 0 {
                    // Get attributes: return 0x20 (archive) in CX
                    regs.rcx = (regs.rcx & !0xFFFF) | 0x20;
                }
                // Set attributes: just succeed (read-only FS)
                regs.clear_flag32(1);
            } else {
                regs.rax = (regs.rax & !0xFFFF) | 2; // file not found
                regs.set_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x29: Parse filename into FCB (DS:SI=string, ES:DI=FCB)
        // AL bits: 0=skip leading separators, 1=set drive only if specified,
        //          2=set filename only if specified, 3=set extension only if specified
        0x29 => {
            let ds_base = linear(dos, regs, regs.ds as u16, 0);
            let mut si = regs.rsi as u16;
            let fcb = linear(dos, regs, regs.es as u16, regs.rdi as u32);

            // Skip leading whitespace/separators if bit 0 set
            let flags = regs.rax as u8;
            if flags & 1 != 0 {
                loop {
                    let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                    if ch == b' ' || ch == b'\t' || ch == b';' || ch == b',' {
                        si += 1;
                    } else {
                        break;
                    }
                }
            }

            // Zero-fill the 11-byte name field in FCB (drive byte at +0, name at +1..+12)
            unsafe { core::ptr::write_bytes((fcb + 1) as *mut u8, b' ', 11); }

            // Check for drive letter (e.g., "C:")
            let ch0 = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
            let ch1 = unsafe { *(ds_base.wrapping_add(si as u32 + 1) as *const u8) };
            if ch1 == b':' && ch0.is_ascii_alphabetic() {
                unsafe { *(fcb as *mut u8) = ch0.to_ascii_uppercase() - b'A' + 1; }
                si += 2;
            } else {
                unsafe { *(fcb as *mut u8) = 0; } // default drive
            }

            // Parse filename (up to 8 chars) into FCB+1
            let mut pos = 0u32;
            loop {
                let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                if ch == b'.' || ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                if ch == b'*' {
                    while pos < 8 { unsafe { *((fcb + 1 + pos) as *mut u8) = b'?'; } pos += 1; }
                    si += 1;
                    break;
                }
                if pos < 8 {
                    unsafe { *((fcb + 1 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                    pos += 1;
                }
                si += 1;
            }

            // Parse extension (up to 3 chars) into FCB+9
            let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
            if ch == b'.' {
                si += 1;
                pos = 0;
                loop {
                    let ch = unsafe { *(ds_base.wrapping_add(si as u32) as *const u8) };
                    if ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                    if ch == b'*' {
                        while pos < 3 { unsafe { *((fcb + 9 + pos) as *mut u8) = b'?'; } pos += 1; }
                        si += 1;
                        break;
                    }
                    if pos < 3 {
                        unsafe { *((fcb + 9 + pos) as *mut u8) = ch.to_ascii_uppercase(); }
                        pos += 1;
                    }
                    si += 1;
                }
            }

            // Update SI to point past parsed name
            regs.rsi = (regs.rsi & !0xFFFF) | si as u64;
            // AL=0: no wildcards, AL=1: wildcards present, AL=0xFF: drive invalid
            let has_wildcards = unsafe {
                let name_area = core::slice::from_raw_parts((fcb + 1) as *const u8, 11);
                name_area.iter().any(|&b| b == b'?')
            };
            regs.rax = (regs.rax & !0xFF) | if has_wildcards { 1 } else { 0 };
            thread::KernelAction::Done
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            exec_program(kt, dos, regs)
        }
        // AH=2Ah — Get System Date
        0x2A => {
            // Return a fixed date: 2026-03-22 (Saturday)
            regs.rcx = (regs.rcx & !0xFFFF) | 2026; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | (3 << 8) | 22; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | 6; // AL = day of week (0=Sun, 6=Sat)
            thread::KernelAction::Done
        }
        // AH=2Ch — Get System Time
        0x2C => {
            // Derive from BIOS tick count at 0040:006C (18.2 ticks/sec)
            let ticks = unsafe { *((0x46C) as *const u32) };
            let total_secs = ticks / 18;
            let hours = (total_secs / 3600) % 24;
            let mins = (total_secs / 60) % 60;
            let secs = total_secs % 60;
            let centisecs = ((ticks % 18) * 100) / 18;
            regs.rcx = (regs.rcx & !0xFFFF) | (hours << 8) as u64 | mins as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (secs << 8) as u64 | centisecs as u64;
            thread::KernelAction::Done
        }
        // AH=0x57: Get/Set File Date and Time (AL=0: get, AL=1: set, BX=handle)
        0x57 => {
            let al = regs.rax as u8;
            if al == 0 {
                // Get: return a fixed date/time (2026-03-22 12:00:00)
                // DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2
                // DOS date: bits 15-9=year-1980, 8-5=month, 4-0=day
                let time: u16 = (12 << 11) | (0 << 5) | 0; // 12:00:00
                let date: u16 = (46 << 9) | (3 << 5) | 22; // 2026-03-22
                regs.rcx = (regs.rcx & !0xFFFF) | time as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | date as u64;
                regs.clear_flag32(1);
            } else {
                // Set: succeed silently (read-only FS)
                regs.clear_flag32(1);
            }
            thread::KernelAction::Done
        }
        // AH=0x60: Canonicalize path (DS:SI=input, ES:DI=output buffer)
        0x60 => {
            let src = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
            let dst = linear(dos, regs, regs.es as u16, regs.rdi as u32);
            // Read input path
            let mut name = [0u8; 128];
            let mut len = 0;
            while len < 127 {
                let ch = unsafe { *((src + len as u32) as *const u8) };
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
                for i in skip..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
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
                for i in 0..len {
                    if pos >= 127 { break; }
                    out[pos] = if name[i] == b'/' { b'\\' } else { name[i].to_ascii_uppercase() };
                    pos += 1;
                }
            }
            out[pos] = 0;
            // Write to ES:DI
            unsafe {
                core::ptr::copy_nonoverlapping(out.as_ptr(), dst as *mut u8, pos + 1);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x52: Get List of Lists (returns ES:BX → DOS internal structure)
        0x52 => {
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (&raw const low_mem().lol as u32) as u64;
            } else {
                regs.es = (&raw const low_mem().lol as u32 >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | 0u64;
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
        // AH=0x67: Set Handle Count — stub success
        0x67 => {
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x41: Delete file (DS:DX=filename)
        0x41 => {
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            if let Ok((path, len)) = dfs_open_existing(dos, &name[..i]) {
                crate::kernel::vfs::delete(&path[..len]);
            }
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AH=0x59: Get Extended Error Information
        0x59 => {
            // Return "file not found" as default extended error
            regs.rax = (regs.rax & !0xFFFF) | 2; // AX = error code (file not found)
            regs.rbx = (regs.rbx & !0xFFFF) | ((1 << 8) | 2); // BH=1 (class: out of resource), BL=2 (action: abort)
            regs.rcx = regs.rcx & !0xFFFF; // CH=0 (locus: unknown)
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
        // AH=0x50: Set Current Process ID (BX = new PSP segment)
        // Undocumented in DOS 1-3, documented in 5+. Same backing field as
        // AH=51h/62h. No return value other than the side effect.
        0x50 => {
            dos.current_psp = regs.rbx as u16;
            thread::KernelAction::Done
        }
        // AH=0x51: Get Current Process ID (returns BX = current PSP segment)
        // Undocumented sibling of AH=62h.
        0x51 => {
            regs.rbx = (regs.rbx & !0xFFFF) | dos.current_psp as u64;
            let cs = regs.frame.cs as u16;
            let ip = regs.frame.rip as u32;
            dos_trace!("D21 51 -> BX={:04X} cs:ip={:04X}:{:08X}",
                dos.current_psp, cs, ip);
            thread::KernelAction::Done
        }
        // AH=0x62: Get PSP segment (returns BX=PSP segment)
        0x62 => {
            regs.rbx = (regs.rbx & !0xFFFF) | dos.current_psp as u64;
            regs.clear_flag32(1);
            let cs = regs.frame.cs as u16;
            let ip = regs.frame.rip as u32;
            dos_trace!("D21 62 -> BX={:04X} cs:ip={:04X}:{:08X}",
                dos.current_psp, cs, ip);
            thread::KernelAction::Done
        }
        // AH=0x6C: Extended Open/Create (DOS 4.0+)
        // BX=mode, CX=attributes, DX=action, DS:SI=ASCIIZ filename
        // Action: bit0=open-if-exists, bit4=create-if-not-exists
        0x6C => {
            let action = regs.rdx as u16;
            let mut addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
            let mut name = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let ch = unsafe { *(addr as *const u8) };
                if ch == 0 { break; }
                name[i] = ch;
                addr += 1;
                i += 1;
            }
            let open_exists = action & 0x01 != 0;
            let create_not = action & 0x10 != 0;

            // Try open first
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 && open_exists {
                let size = crate::kernel::vfs::file_size(fd, &kt.fds);
                sft_set_file(fd as u16, size);
                if (fd as usize) < 20 { program_at(dos.current_psp).psp.jft[fd as usize] = fd as u8; }
                regs.rax = (regs.rax & !0xFFFF) | fd as u64;
                regs.rcx = (regs.rcx & !0xFFFF) | 1; // CX=1: file opened
                regs.clear_flag32(1);
            } else if create_not {
                // File doesn't exist — create RAM-backed file via VFS overlay
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut kt.fds); }
                let new_fd = match dfs_create_path(dos, &name[..i]) {
                    Ok((path, len)) => crate::kernel::vfs::create(&path[..len], &mut kt.fds),
                    Err(e) => -e,
                };
                if new_fd >= 0 {
                    regs.rax = (regs.rax & !0xFFFF) | new_fd as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | 2; // CX=2: file created
                    regs.clear_flag32(1);
                } else {
                    regs.rax = (regs.rax & !0xFFFF) | 4;
                    regs.set_flag32(1);
                }
            } else {
                if fd >= 0 { crate::kernel::vfs::close(fd, &mut kt.fds); }
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
                    let syspsp_addr = &raw const low_mem().sys.psp as u32;
                    if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                        regs.ds = dpmi::LOW_MEM_SEL as u64;
                        regs.rsi = (regs.rsi & !0xFFFF) | syspsp_addr as u64;
                    } else {
                        regs.ds = (syspsp_addr >> 4) as u64;
                        regs.rsi = (regs.rsi & !0xFFFF) | 0u64;
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

/// DOS INT 21h/4B — Load and Execute Program
///
/// Try to open a program file via VFS. If the name has no extension (no dot),
/// try appending .COM and .EXE (DOS convention).
// ============================================================================
// INT 2Eh — COMMAND.COM internal execute
// ============================================================================

fn int_2eh(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // DS:SI = pointer to command-line length byte + text (same as PSP:80h format)
    // Treat as COMMAND.COM /C — fork-exec the program in a fresh address space.
    let addr = linear(dos, regs, regs.ds as u16, regs.rsi as u32);
    let len = unsafe { *(addr as *const u8) } as usize;
    let mut cmd = [0u8; 128];
    let copy = len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((addr + 1) as *const u8, cmd.as_mut_ptr(), copy);
    }
    let mut start = 0;
    while start < copy && cmd[start] == b' ' { start += 1; }
    let mut end = start;
    while end < copy && cmd[end] != b' ' && cmd[end] != b'\r' && cmd[end] != 0 { end += 1; }
    if end <= start { return thread::KernelAction::Done; }

    // Shift the program name to the start of the buffer.
    let plen = end - start;
    cmd.copy_within(start..end, 0);
    fork_exec(dos, &cmd[..plen], kt)
}

// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS + DPMI detection)
// ============================================================================

/// Fill regs with DPMI 0.90 installation-check reply (shared by INT 2F/1687h
/// and DOS/32A's INT 21h AX=FF87h probe).
fn dpmi_install_check(regs: &mut Regs) {
    regs.rax = regs.rax & !0xFFFF; // AX=0: DPMI available
    regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // BX bit0 = 32-bit supported
    regs.rcx = (regs.rcx & !0xFF) | 0x03; // CL = 386
    regs.rdx = (regs.rdx & !0xFFFF) | 0x005A; // DX = DPMI 0.90
    regs.rsi = regs.rsi & !0xFFFF; // SI = 0 paragraphs needed
    regs.es = STUB_SEG as u64;
    regs.rdi = (regs.rdi & !0xFFFF) | slot_offset(SLOT_DPMI_ENTRY) as u64;
}

fn int_2fh(_dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
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
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            thread::KernelAction::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | slot_offset(SLOT_XMS) as u64;
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


fn dos_open_program(kt: &mut thread::KernelThread, dos: &mut thread::DosState, name: &[u8]) -> i32 {
    let try_open = |dos: &thread::DosState, kt: &mut thread::KernelThread, n: &[u8]| -> i32 {
        match dfs_open_existing(dos, n) {
            Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
            Err(_) => -2,
        }
    };

    let fd = try_open(dos, kt, name);
    if fd >= 0 { return fd; }
    // If the name already has a dot, don't try extensions
    if name.iter().any(|&c| c == b'.') { return fd; }
    // Try .COM / .EXE / .ELF in turn
    let mut buf = [0u8; 132];
    let nlen = name.len();
    if nlen + 4 > buf.len() { return -2; }
    buf[..nlen].copy_from_slice(name);
    for ext in [b".COM", b".EXE", b".ELF"] {
        buf[nlen..nlen + 4].copy_from_slice(ext);
        let fd = try_open(dos, kt, &buf[..nlen + 4]);
        if fd >= 0 { return fd; }
    }
    -2 // ENOENT
}

/// Expand a .BAT file to its first executable command.
///
/// If `filename[..flen]` names a .BAT file, open it, find the first line
/// that isn't blank / REM / `@echo off` / `:label`, strip a leading `@`,
/// and copy the first whitespace-delimited token back into `filename`.
/// Returns the new length. For non-.BAT names, returns `flen` unchanged.
///
/// Only the first command is executed — multi-line BAT semantics (loops,
/// conditionals, state) are out of scope for this basic handler.
fn expand_bat(dos: &mut thread::DosState, filename: &mut [u8; 128], flen: usize, kt: &mut thread::KernelThread) -> usize {
    // Case-insensitive suffix check for ".BAT"
    if flen < 4 { return flen; }
    let tail = &filename[flen - 4..flen];
    if !(tail[0] == b'.'
        && (tail[1] & 0xDF) == b'B'
        && (tail[2] & 0xDF) == b'A'
        && (tail[3] & 0xDF) == b'T') { return flen; }

    let (vfs_path, vfs_len) = match dfs_open_existing(dos, &filename[..flen]) {
        Ok(v) => v,
        Err(_) => return flen,
    };
    let fd = crate::kernel::vfs::open(&vfs_path[..vfs_len], &mut kt.fds);
    if fd < 0 { return flen; }

    let mut buf = [0u8; 512];
    let n = crate::kernel::vfs::read_raw(fd, &mut buf, &kt.fds);
    crate::kernel::vfs::close(fd, &mut kt.fds);
    if n <= 0 { return flen; }
    let n = n as usize;

    // Walk lines, find the first real command.
    let mut p = 0usize;
    while p < n {
        // Skip leading whitespace
        while p < n && matches!(buf[p], b' ' | b'\t') { p += 1; }
        // Blank line?
        if p >= n || matches!(buf[p], b'\r' | b'\n') {
            while p < n && matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Optional leading '@' (suppress echo) — strip it
        let mut q = p;
        if buf[q] == b'@' { q += 1; }
        // REM / ECHO OFF / label — skip whole line
        let lower = |i: usize| -> u8 { if i < n { buf[i] & 0xDF } else { 0 } };
        let end_of_word = |i: usize| -> bool {
            i >= n || matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n')
        };
        let is_rem = lower(q) == b'R' && lower(q+1) == b'E' && lower(q+2) == b'M' && end_of_word(q+3);
        let is_echo = lower(q) == b'E' && lower(q+1) == b'C' && lower(q+2) == b'H' && lower(q+3) == b'O' && end_of_word(q+4);
        let is_label = buf[q] == b':';
        if is_rem || is_echo || is_label {
            while p < n && !matches!(buf[p], b'\r' | b'\n') { p += 1; }
            continue;
        }
        // Real command — extract first whitespace-delimited token
        let start = q;
        let mut end = q;
        while end < n && !matches!(buf[end], b' ' | b'\t' | b'\r' | b'\n') { end += 1; }
        let tok_len = (end - start).min(127);
        // Zero the buffer first so leftover bytes don't leak
        for b in filename.iter_mut() { *b = 0; }
        filename[..tok_len].copy_from_slice(&buf[start..start + tok_len]);
        return tok_len;
    }
    flen
}

/// Resolve path and return ForkExec action for the event loop to execute.
/// Synth ABI: on success BX=child_tid, CF=0. On error AX=errno, CF=1.
fn fork_exec(dos: &mut thread::DosState, prog_name: &[u8], _kt: &mut thread::KernelThread) -> thread::KernelAction {
    // Resolve raw DOS name → VFS path via DFS.
    let mut path = [0u8; 164];
    let path_len = match dfs_open_existing(dos, prog_name) {
        Ok((p, len)) => {
            path[..len].copy_from_slice(&p[..len]);
            len
        }
        Err(_) => {
            // Let the event loop handle ENOENT by reporting failure.
            return thread::KernelAction::Done;
        }
    };

    fn on_error(regs: &mut Regs, err: i32) {
        regs.rax = (regs.rax & !0xFFFF) | err as u64;
        regs.set_flag32(1);
    }

    fn on_success(regs: &mut Regs, child_tid: i32) {
        regs.rbx = (regs.rbx & !0xFFFF) | ((child_tid as u16) as u64);
        regs.clear_flag32(1);
    }

    thread::KernelAction::ForkExec {
        path,
        path_len,
        on_error,
        on_success,
    }
}

/// DOS INT 4Bh EXEC — load and execute a DOS program in-process.
/// Loads a .COM or MZ .EXE into a fresh child segment above `heap_seg`,
/// shares the address space with the parent, and transfers control.
/// Parent resumes via exec_return on child INT 20h / 4C00.
/// Non-DOS formats (ELF, BAT) should be routed through COMMAND.COM /C
/// which uses synth INT 31h AH=01h to fork+exec+wait a separate thread.
fn exec_program(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    let al = regs.rax as u8;
    match al {
        0x00 => {}                                  // load & execute — fall through
        0x03 => return exec_load_overlay(kt, dos, regs),
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
    let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = unsafe { *(addr as *const u8) };
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }

    // Read parameter block at ES:BX
    let pb = linear(dos, regs, regs.es as u16, regs.rbx as u32);
    let cmdtail_off = unsafe { ((pb + 2) as *const u16).read_unaligned() } as u32;
    let cmdtail_seg = unsafe { ((pb + 4) as *const u16).read_unaligned() } as u32;
    let cmdtail_addr = (cmdtail_seg << 4) + cmdtail_off;
    let tail_len = unsafe { *(cmdtail_addr as *const u8) } as usize;
    let mut tail = [0u8; 128];
    let copy_len = tail_len.min(127);
    unsafe {
        core::ptr::copy_nonoverlapping((cmdtail_addr + 1) as *const u8, tail.as_mut_ptr(), copy_len);
    }

    let prog_name: &[u8] = &filename[..flen];

    // TRACE: log cmdtail and filename BC passes to EXEC
    {
        let mut tail_vis = [0u8; 80];
        let vis_len = copy_len.min(80);
        for i in 0..vis_len {
            let b = tail[i];
            tail_vis[i] = if b < 32 || b >= 127 { b'?' } else { b };
        }
        dos_trace!("EXEC prog={:?} cmdtail_len={} tail={:?}",
            core::str::from_utf8(prog_name).unwrap_or("?"),
            copy_len,
            core::str::from_utf8(&tail_vis[..vis_len]).unwrap_or("?"));
    }

    // --- DOS program: in-process exec (shared address space) ---
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
    crate::dbg_println!("  exec_program: {:?} size={} elf={}", core::str::from_utf8(prog_name), size, is_elf);
    if is_elf {
        return fork_exec(dos, prog_name, kt);
    }

    let is_exe = is_mz_exe(&buf);
    // Layout the child's two arenas above the parent's heap end: env block
    // first (0x10 paragraphs), then PSP+code/BSS. `map_psp` places env at
    // `psp_seg - 0x10`, so `child_seg = heap_seg + 0x10` keeps the env safely
    // inside the child's own allocation and never inside parent memory.
    let child_seg = dos.heap_seg + 0x10;
    crate::dbg_println!("  exec_program: {:?} size={} exe={} child_seg={:04X} parent_psp={:04X}",
        core::str::from_utf8(prog_name), size, is_exe, child_seg, dos.current_psp);

    // Resolve the DOS-form absolute path for the env program-path suffix.
    // Must be drive-qualified uppercase (e.g. "C:\BIN\PROG.EXE") — DOS
    // extenders derive their cwd estimate from this field.
    let mut abs_dos = [0u8; dfs::DFS_PATH_MAX];
    let abs_len = dos.dfs.resolve(prog_name, &mut abs_dos).unwrap_or(0);

    // Build parent reference. In PM the parent's PSP[0x2C] may hold a
    // selector (32-bit client) and dos.current_psp is PSP_SEL — read the
    // captured RM env paragraph from DpmiState. In RM PSP[0x2C] is the RM
    // segment.
    let parent_psp = dos.current_psp;
    let parent_env_seg = match dos.dpmi.as_ref() {
        Some(dpmi) if parent_psp == dpmi::PSP_SEL => dpmi.saved_rm_env,
        _ => Program::at(parent_psp.wrapping_sub(0x10)).psp.env_seg,
    };
    let parent_env_vec = snapshot_env(parent_env_seg);
    let parent = ParentRef { psp_seg: parent_psp, env: &parent_env_vec };
    let loaded = if is_exe {
        match load_exe(dos.heap_seg, &parent, &buf, &abs_dos[..abs_len]) {
            Some(l) => l,
            None => {
                regs.rax = (regs.rax & !0xFFFF) | 11;
                regs.set_flag32(1);
                return thread::KernelAction::Done;
            }
        }
    } else {
        load_com(dos.heap_seg, &parent, &buf, &abs_dos[..abs_len])
    };
    let child_seg = loaded.program.psp_seg();
    let cs = loaded.cs; let ip = loaded.ip; let ss = loaded.ss; let sp = loaded.sp;
    let end_seg = loaded.end_seg;

    // Copy command tail to child's PSP at child_seg:0080
    loaded.program.set_cmdline(&tail[..copy_len]);

    // Save parent state. Parent's INT frame (IP/CS/FLAGS) is on the VM86
    // stack at current SS:SP. exec_return restores SS:SP so stub_dispatch
    // pops the frame and resumes the parent.
    let prev = dos.exec_parent.take();
    let parent_heap = dos.heap_seg;
    let parent_heap_base = dos.heap_base_seg;
    let parent_blocks = dos.dos_blocks.clone();
    dos.heap_seg = end_seg.max(dos.heap_seg);
    dos.heap_base_seg = dos.heap_seg;
    dos.dos_blocks.clear();
    dos.dta = (child_seg as u32) * 16 + 0x80;
    dos.current_psp = child_seg;
    dos.exec_parent = Some(ExecParent {
        ss: vm86_ss(regs),
        sp: vm86_sp(regs),
        ds: regs.ds as u16,
        es: regs.es as u16,
        heap_seg: parent_heap,
        heap_base_seg: parent_heap_base,
        psp: parent_psp,
        dos_blocks: parent_blocks,
        prev: prev.map(alloc::boxed::Box::new),
    });

    // Set child entry. Push child's CS:IP + FLAGS onto the child's stack
    // so that stub_dispatch's pop restores them correctly.
    regs.set_ss32(ss as u32);
    regs.set_sp32(sp as u32);
    let flags = vm86_flags(regs) as u16;
    vm86_push(regs, flags);
    vm86_push(regs, cs);
    vm86_push(regs, ip);
    regs.ds = child_seg as u64;
    regs.es = child_seg as u64;
    regs.clear_flag32(1);
    crate::dbg_println!("  exec_program loaded: cs:ip={:04X}:{:04X} ss:sp={:04X}:{:04X} end_seg={:04X} heap_seg={:04X}",
        cs, ip, ss, sp, end_seg, dos.heap_seg);
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
fn exec_load_overlay(kt: &mut thread::KernelThread, dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
    // ASCIIZ filename at DS:DX
    let mut addr = linear(dos, regs, regs.ds as u16, regs.rdx as u32);
    let mut filename = [0u8; 128];
    let mut flen = 0;
    while flen < 127 {
        let ch = unsafe { *(addr as *const u8) };
        if ch == 0 { break; }
        filename[flen] = ch;
        flen += 1;
        addr += 1;
    }
    let prog_name: &[u8] = &filename[..flen];

    // Parameter block at ES:BX — two WORDs.
    let pb = linear(dos, regs, regs.es as u16, regs.rbx as u32);
    let load_seg = unsafe { (pb as *const u16).read_unaligned() };
    let reloc_factor = unsafe { ((pb + 2) as *const u16).read_unaligned() };
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
        unsafe {
            core::ptr::copy_nonoverlapping(img.as_ptr(), load_base as *mut u8, load_size);
        }
        // Apply relocations using caller's reloc_factor (not load_seg).
        for i in 0..reloc_count {
            let entry = reloc_offset + i * 4;
            let off = w(entry) as u32;
            let seg = w(entry + 2) as u32;
            let a = load_base + (seg << 4) + off;
            unsafe {
                let p = a as *mut u16;
                let v = p.read_unaligned();
                p.write_unaligned(v.wrapping_add(reloc_factor));
            }
        }
        dos_trace!("D21 4B03 MZ loaded: load_size={} relocs={}", load_size, reloc_count);
    } else {
        // Raw / .COM: copy file verbatim at load_seg:0.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), load_base as *mut u8, buf.len());
        }
        dos_trace!("D21 4B03 raw loaded: size={}", buf.len());
    }

    regs.clear_flag32(1);
    thread::KernelAction::Done
}

/// Return from an EXEC'd child to the parent.
/// Restores the parent's CS:IP, SS:SP, DS, ES and clears carry (success).
fn exec_return(dos: &mut thread::DosState, regs: &mut Regs, parent: ExecParent) -> thread::KernelAction {
    crate::dbg_println!("  exec_return: restoring heap={:04X}->{:04X} psp={:04X}->{:04X} ss:sp={:04X}:{:04X}",
        dos.heap_seg, parent.heap_seg,
        dos.current_psp, parent.psp,
        parent.ss, parent.sp);
    regs.set_ss32(parent.ss as u32);
    regs.set_sp32(parent.sp as u32);
    regs.clear_flag32(1);
    regs.ds = parent.ds as u64;
    regs.es = parent.es as u64;
    dos.heap_seg = parent.heap_seg;
    dos.heap_base_seg = parent.heap_base_seg;
    dos.current_psp = parent.psp;
    dos.dos_blocks = parent.dos_blocks;
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
pub(crate) fn dfs_open_existing(dos: &thread::DosState, dos_in: &[u8])
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
pub(crate) fn dfs_create_path(dos: &thread::DosState, dos_in: &[u8])
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
fn find_matching_file(dos: &mut thread::DosState, regs: &mut Regs) -> thread::KernelAction {
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

    loop {
        match crate::kernel::vfs::readdir(dir, idx) {
            Some(entry) => {
                idx += 1;
                let name = &entry.name[..entry.name_len];
                if dos_wildcard_match(pat, name) {
                    dos.find_idx = idx as u16;
                    // Fill DTA at dos.dta
                    let dta = dos.dta;
                    // DTA layout (43 bytes):
                    //   0x00-0x14: reserved (unused by us — state lives in DosState)
                    //   0x15: attribute of matched file
                    //   0x16: file time (2 bytes)
                    //   0x18: file date (2 bytes)
                    //   0x1A: file size (4 bytes, little-endian)
                    //   0x1E: filename (13 bytes, null-terminated, 8.3 format)
                    unsafe {
                        let p = dta as *mut u8;
                        core::ptr::write_bytes(p, 0, 43);
                        *p.add(0x15) = if entry.is_dir { 0x10 } else { 0x20 };
                        (p.add(0x1A) as *mut u32).write_unaligned(entry.size);
                        let name_len = entry.name_len.min(12);
                        core::ptr::copy_nonoverlapping(
                            entry.name.as_ptr(),
                            p.add(0x1E),
                            name_len,
                        );
                        *p.add(0x1E + name_len) = 0;
                    }
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

/// Prepare the VM86 IVT for a new process.
///
/// The BIOS IVT at 0x0000-0x03FF is preserved from the COW copy of page 0,
/// so BIOS handlers in ROM (0xF0000-0xFFFFF) are accessible. When a BIOS
/// handler does I/O (IN/OUT), it traps through the IOPB to our virtual
/// PIC/keyboard, so BIOS code works transparently.
///
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
/// Note: the spec puts the inline JFT at 0x18 and a far-pointer to it at 0x34;
/// the kernel here puts the JFT at 0x34 and the far-pointer (→0x34) at 0x18.
/// Existing programs (DJGPP, BC, dos4gw, dos16m) use INT 21 for handles, so
/// neither layout is observable — preserved here unchanged.
#[repr(C, packed)]
pub(super) struct Psp {
    pub int_20:           [u8; 2],   // 0x00 — CD 20 (terminate)
    pub top_of_mem:       u16,        // 0x02 — segment past program (paragraphs)
    _reserved_04:         u8,         // 0x04
    _cpm_call:            [u8; 5],    // 0x05 — far call to CP/M dispatcher
    _terminate_addr:      u32,        // 0x0A — INT 22h vector
    _ctrl_break_addr:     u32,        // 0x0E — INT 23h vector
    _critical_err:        u32,        // 0x12 — INT 24h vector
    pub parent_psp:       u16,        // 0x16 — parent PSP segment
    pub jft_far_off:      u16,        // 0x18 — (kernel layout: JFT pointer offset)
    pub jft_far_seg:      u16,        // 0x1A — (kernel layout: JFT pointer segment)
    _reserved_1c:         [u8; 0x10], // 0x1C-0x2B
    pub env_seg:          u16,        // 0x2C — environment segment (or 0)
    _ss_sp:               u32,        // 0x2E — SS:SP at last INT 21
    pub max_files:        u16,        // 0x32 — JFT size
    pub jft:              [u8; 20],   // 0x34 — inline JFT (kernel layout)
    _reserved_48:         [u8; 0x80 - 0x48], // 0x48-0x7F
    pub cmdline_len:      u8,         // 0x80
    pub cmdline:          [u8; 127],  // 0x81-0xFF (CR-terminated)
}
const _: () = assert!(core::mem::size_of::<Psp>() == 256);
impl Default for Psp {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// One System File Table entry (DOS 3+ format, 59 bytes).
#[repr(C, packed)]
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
struct Sft {
    next: u32,                       // 0x00 — far ptr to next SFT block (FFFF:FFFF = end)
    count: u16,                      // 0x04
    entries: [SftEntry; SFT_ENTRIES],
}

/// List-of-Lists (DOS internal). Only the fields we actually fill are named;
/// the rest is reserved padding.
#[repr(C, packed)]
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
    sys:       Program,                // 0x700: env + psp = 512 bytes
    lol:       Lol,                    // 0x900
    sft:       Sft,                    // 0x940
    cds:       [CdsEntry; NUM_DRIVES as usize],
    _pad:      [u8; 6],                // align irq_stack to a paragraph boundary
    irq_stack: [u8; 256],
}

const _: () = assert!(
    (LOW_MEM_BASE as usize + core::mem::offset_of!(LowMem, irq_stack)) % 16 == 0,
    "irq_stack base must be paragraph-aligned (adjust LowMem._pad)",
);

/// Borrow the kernel-owned low-mem area as a typed `&'static mut`.
/// Single-threaded kernel; the borrow checker treats successive calls as
/// independent borrows, so callers must avoid actually aliasing the data.
#[inline]
fn low_mem() -> &'static mut LowMem {
    unsafe { &mut *(LOW_MEM_BASE as *mut LowMem) }
}

pub(crate) const STUB_BASE: u32 = LOW_MEM_BASE;
pub(crate) const STUB_SEG: u16 = (LOW_MEM_BASE >> 4) as u16;
pub(crate) const IRQ_STACK_SEG: u16 =
    ((LOW_MEM_BASE as usize + core::mem::offset_of!(LowMem, irq_stack)) >> 4) as u16;
pub(crate) const IRQ_STACK_TOP: u16 = 256;
/// Offset within SYSPSP of the INDOS flag byte (permanently zero).
/// Placed in the "command tail" area since the system PSP never runs.
const INDOS_FLAG_OFFSET: u16 = 0xFE;

/// First free paragraph past the kernel-owned low-mem area. The initial
/// DOS program's env arena lives here; its PSP at +0x10.
pub(super) fn heap_start() -> u16 {
    let end = LOW_MEM_BASE as usize + core::mem::size_of::<LowMem>();
    ((end + 15) >> 4) as u16
}

/// The system Program (master env + stand-in PSP) used as bootstrap parent
/// for the initial DOS thread and as chain-terminator for PSP[0x16].
pub(super) fn sys_program() -> &'static mut Program {
    &mut low_mem().sys
}
pub(super) fn sys_psp_seg() -> u16 { sys_program().psp_seg() }

/// One DOS program's env arena + PSP, laid out contiguously in real-mode
/// memory: env at offset 0 (256 bytes), PSP at offset 256 (256 bytes).
/// Hence `psp_seg = env_seg + 0x10`.
#[repr(C, packed)]
pub(super) struct Program {
    pub env: [u8; 256],
    pub psp: Psp,
}
const _: () = assert!(core::mem::size_of::<Program>() == 512);

impl Program {
    /// Borrow the program at `env_seg` (where its env arena begins).
    pub fn at(env_seg: u16) -> &'static mut Self {
        unsafe { &mut *(((env_seg as u32) << 4) as *mut Self) }
    }
    pub fn env_seg(&self) -> u16 { (self as *const _ as u32 >> 4) as u16 }
    pub fn psp_seg(&self) -> u16 { self.env_seg() + 0x10 }
    /// Install a command-tail at PSP[0x80] (length byte + bytes + CR).
    pub fn set_cmdline(&mut self, tail: &[u8]) {
        let n = tail.len().min(self.psp.cmdline.len() - 1);
        self.psp.cmdline_len = n as u8;
        self.psp.cmdline[..n].copy_from_slice(&tail[..n]);
        self.psp.cmdline[n] = 0x0D;
    }
    /// Borrow as the parent for child loads (PSP segment + env block).
    pub fn as_parent(&self) -> ParentRef<'_> {
        ParentRef { psp_seg: self.psp_seg(), env: &self.env }
    }
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

/// Output of a successful binary load — the program's address space view
/// plus initial CPU register values for the VM86 thread.
pub(super) struct Loaded {
    pub program: &'static mut Program,
    pub cs: u16,
    pub ip: u16,
    pub ss: u16,
    pub sp: u16,
    /// First paragraph past the loaded image; used to set the new heap base.
    pub end_seg: u16,
}

// ── Stub vector / slot assignments ─────────────────────────────────────
// Slot N at offset N*2 from STUB_SEG. After CD 31, IP = N*2+2, slot = (IP-2)/2.
// VM86 traps via TSS bitmap bit 31h; PM fires INT 31h directly (DPL=3).
const STUB_INT: u8 = 0x31;
const SLOT_XMS: u8 = 0x00;
const SLOT_DPMI_ENTRY: u8 = 0x01;
pub(crate) const SLOT_CALLBACK_RET: u8 = 0x02;
pub(crate) const SLOT_RAW_REAL_TO_PM: u8 = 0x03;
pub(crate) const SLOT_CB_ENTRY_BASE: u8 = 0x04;
pub(crate) const SLOT_CB_ENTRY_END: u8 = 0x14; // exclusive (16 callbacks)
/// Slots SLOT_HW_IRQ_BASE + N route IRQ N (0..15) so its BIOS handler runs
/// on a private IRQ stack, not the user's stack.
pub(crate) const SLOT_HW_IRQ_BASE: u8 = 0xE0;
pub(crate) const SLOT_HW_IRQ_END: u8 = 0xF0;
/// VM86-only: RM IRET target for implicit INT reflection (no PM handler
/// installed). `rm_int_return` restores PM state and synthesizes the STI
/// the DPMI spec requires our default stub to perform before IRET.
pub(crate) const SLOT_RM_INT_RET: u8 = 0xFA;
pub(crate) const SLOT_HW_IRQ_RET: u8 = 0xFC;
pub(crate) const SLOT_SAVE_RESTORE: u8 = 0xFD;
pub(crate) const SLOT_EXCEPTION_RET: u8 = 0xFE;
pub(crate) const SLOT_PM_TO_REAL: u8 = 0xFF;

pub(crate) const fn slot_offset(slot: u8) -> u16 { (slot as u16) * 2 }

pub(super) fn setup_ivt() {
    // Fill the stub array with `CD 31` so any slot reached by an IVT entry
    // (or PM CALL FAR) traps to STUB_INT and the slot dispatcher.
    for entry in low_mem().stubs.iter_mut() {
        *entry = [0xCD, STUB_INT];
    }

    // Hook BIOS HW IRQ vectors (0x08-0x0F + 0x70-0x77) through private-stack
    // slots; save the original BIOS pointers so hw_irq_reflect can chain.
    for irq in 0u8..16 {
        let vec = irq_to_vector(irq);
        let ip = read_u16(0, (vec as u32) * 4);
        let cs = read_u16(0, (vec as u32) * 4 + 2);
        unsafe { BIOS_HW_IRQ[irq as usize] = (cs, ip); }
        write_u16(0, (vec as u32) * 4, slot_offset(SLOT_HW_IRQ_BASE + irq));
        write_u16(0, (vec as u32) * 4 + 2, STUB_SEG);
    }
    // Hook the DOS/BIOS soft INTs we intercept so guest CD nn lands in our
    // dispatcher (slot index = INT vector).
    for &int_num in &[0x13u8, 0x20, 0x21, 0x25, 0x26, 0x28, 0x2E, 0x2F, 0x67] {
        write_u16(0, (int_num as u32) * 4, slot_offset(int_num));
        write_u16(0, (int_num as u32) * 4 + 2, STUB_SEG);
    }

    setup_lol_sft();
    xms::scan_uma();
}

fn setup_lol_sft() {
    let sft_addr = &raw const low_mem().sft as u32;
    let cds_addr = &raw const low_mem().cds as u32;

    let lm = low_mem();

    // System program: master env (COMSPEC/PATH defaults) + a placeholder PSP
    // that self-references its parent field. Acts as the bootstrap parent for
    // the initial DOS thread and the chain-terminator for any tool that walks
    // PSP[0x16] upward.
    lm.sys = unsafe { core::mem::zeroed() };
    let mut sys_env_off = 0;
    for src in [&b"COMSPEC=C:\\COMMAND.COM\0"[..], &b"PATH=C:\\\0"[..]] {
        lm.sys.env[sys_env_off..sys_env_off + src.len()].copy_from_slice(src);
        sys_env_off += src.len();
    }
    lm.sys.env[sys_env_off] = 0;     // double-NUL terminator (no DOS 3+ suffix)
    let sys_psp_seg = lm.sys.psp_seg();
    let sys_env_seg = lm.sys.env_seg();
    lm.sys.psp = Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp: sys_psp_seg,      // self-ref terminates the parent chain
        env_seg: sys_env_seg,
        ..Default::default()
    };

    lm.lol = Lol {
        sft_off: (sft_addr & 0xF) as u16,
        sft_seg: (sft_addr >> 4) as u16,
        cds_off: (cds_addr & 0xF) as u16,
        cds_seg: (cds_addr >> 4) as u16,
        block_devs: 1,
        last_drive: NUM_DRIVES,
        ..Default::default()
    };

    // SFT header: end-of-chain link, entry count + zeroed entries; then
    // pre-populate stdin/stdout/stderr as character devices.
    lm.sft = unsafe { core::mem::zeroed() };
    lm.sft.next = 0xFFFF_FFFF;
    lm.sft.count = SFT_ENTRIES as u16;
    for fd in 0..3 {
        lm.sft.entries[fd] = SftEntry {
            refcount: 1,
            device_info: if fd == 0 { 0x81 } else { 0x82 },
            ..Default::default()
        };
    }

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
    lm.cds = [(); NUM_DRIVES as usize].map(|_| CdsEntry::default());
    lm.cds[2] = mk(b'C');
    lm.cds[7] = mk(b'H');
}

/// Borrow the program containing the PSP at `psp_seg` (env starts at psp_seg-0x10).
pub(super) fn program_at(psp_seg: u16) -> &'static mut Program {
    Program::at(psp_seg.wrapping_sub(0x10))
}

/// Populate SFT entry for a newly opened file handle.
fn sft_set_file(handle: u16, size: u32) {
    if handle as usize >= SFT_ENTRIES { return; }
    low_mem().sft.entries[handle as usize] = SftEntry {
        refcount: 1,
        attribute: 0x20,    // archive
        time: 0x6000,       // 12:00:00
        date: 0x5C76,       // 2026-03-22
        size,
        ..Default::default()
    };
}

/// Clear SFT entry when a file handle is closed.
fn sft_clear(handle: u16) {
    if handle as usize >= SFT_ENTRIES { return; }
    low_mem().sft.entries[handle as usize].refcount = 0;
}

// ============================================================================
// DOS program loaders (.COM and MZ .EXE)
// ============================================================================

/// Fill a fresh env arena: copy the parent's variable strings (up to the
/// `00 00` terminator), then append the DOS 3+ suffix `01 00 <prog_name> 00`.
/// Per DOS EXEC (AH=4B), the child always gets a fresh arena — the parent's
/// env is *copied*, never shared.
fn fill_env(env: &mut [u8; 256], parent_env: &[u8], prog_name: &[u8]) {
    *env = [0; 256];
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

/// Initialize a freshly-placed program's env arena and PSP from a parent.
fn map_program(prog: &mut Program, parent: &ParentRef, prog_name: &[u8]) {
    fill_env(&mut prog.env, parent.env, prog_name);

    let env_seg = prog.env_seg();
    let psp_seg = prog.psp_seg();
    let mut jft = [0xFFu8; 20];
    jft[0] = 0; jft[1] = 1; jft[2] = 2;   // stdin/stdout/stderr → SFT 0/1/2
    let mut cmdline = [0u8; 127];
    cmdline[0] = 0x0D;                      // empty tail terminated by CR

    prog.psp = Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp: parent.psp_seg,
        jft_far_off: 0x0034,                // far ptr at PSP[0x18] → inline JFT at PSP[0x34]
        jft_far_seg: psp_seg,
        env_seg,
        max_files: 20,
        jft,
        cmdline_len: 0,
        cmdline,
        ..Default::default()
    };

    // TRACE: dump env block (first 80 bytes) for debugging.
    let mut dump = [0u8; 80];
    for (i, &b) in prog.env.iter().take(80).enumerate() {
        dump[i] = if b == 0 { b'.' } else if b < 32 || b >= 127 { b'?' } else { b };
    }
    dos_trace!("map_psp psp={:04X} env={:04X} parent_psp={:04X} prog={:?} env[0..80]={:?}",
        psp_seg, env_seg, parent.psp_seg,
        core::str::from_utf8(prog_name).unwrap_or("?"),
        core::str::from_utf8(&dump).unwrap_or("?"));
}

/// Check if data starts with the MZ signature.
pub(super) fn is_mz_exe(data: &[u8]) -> bool {
    data.len() >= 28 && data[0] == b'M' && data[1] == b'Z'
}

/// Load a .COM binary at `heap_end` (env_seg). Stack at PSP:COM_SP (top of
/// 64KB segment), code at (psp+0x10):0000. Caller advances heap to `end_seg`.
pub(super) fn load_com(heap_end: u16, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Loaded {
    let prog = Program::at(heap_end);
    map_program(prog, parent, prog_name);
    let psp_seg = prog.psp_seg();

    // Load .COM code at psp_seg:0x100 (= (psp_seg+0x10):0).
    let load_addr = ((psp_seg as u32) << 4) + COM_OFFSET as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), load_addr as *mut u8, data.len());
    }

    Loaded {
        cs: psp_seg, ip: COM_OFFSET, ss: psp_seg, sp: COM_SP,
        end_seg: psp_seg.wrapping_add(0x1000),
        program: prog,
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
pub(super) fn load_exe(heap_end: u16, parent: &ParentRef,
                       data: &[u8], prog_name: &[u8]) -> Option<Loaded> {
    if data.len() < 28 { return None; }

    let w = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);

    let last_page_bytes = w(0x02) as u32;
    let total_pages = w(0x04) as u32;
    let reloc_count = w(0x06) as usize;
    let header_paragraphs = w(0x08) as u32;
    let min_extra = w(0x0A) as u32;
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

    let prog = Program::at(heap_end);
    map_program(prog, parent, prog_name);
    let psp_seg = prog.psp_seg();

    // Load module starts 0x10 paragraphs after the PSP.
    let load_segment = psp_seg + 0x10;
    let load_paras = ((load_size as u32 + 15) / 16) as u16;
    let end_seg = load_segment.wrapping_add(load_paras).wrapping_add(min_extra as u16);

    let load_base = (load_segment as u32) << 4;
    let load_data = &data[header_size as usize..header_size as usize + load_size];
    unsafe {
        core::ptr::copy_nonoverlapping(load_data.as_ptr(), load_base as *mut u8, load_size);
    }

    // Zero BSS from end of load module up to end_seg. DOS itself doesn't —
    // the MZ loader just copies the image and allocates extra paragraphs
    // uninitialized; real CRTs (Borland c0, Watcom cstart, ...) zero BSS
    // from linker symbols. We zero defensively on re-exec, where the backing
    // pages may retain prior-run data.
    let bss_start = load_base + load_size as u32;
    let bss_end = (end_seg as u32) << 4;
    if bss_end > bss_start {
        unsafe { core::ptr::write_bytes(bss_start as *mut u8, 0, (bss_end - bss_start) as usize); }
    }

    // Apply relocations: each entry is (offset, segment) within the load
    // module. Add load_segment to the 16-bit word at that address.
    let reloc_end = reloc_offset + reloc_count * 4;
    if reloc_end > data.len() { return None; }
    for i in 0..reloc_count {
        let entry = reloc_offset + i * 4;
        let off = w(entry) as u32;
        let seg = w(entry + 2) as u32;
        let addr = load_base + (seg << 4) + off;
        unsafe {
            let p = addr as *mut u16;
            let val = p.read_unaligned();
            p.write_unaligned(val.wrapping_add(load_segment));
        }
    }

    Some(Loaded {
        cs: init_cs.wrapping_add(load_segment),
        ip: init_ip,
        ss: init_ss.wrapping_add(load_segment),
        sp: init_sp,
        end_seg,
        program: prog,
    })
}
