//! INT 33h mouse services and guest callbacks.

use crate::Regs;
use crate::kernel::thread;

use super::lowmem::{CTRL_STUB_SEG, SLOT_MOUSE_CB_RET, STUB_BASE, ctrl_slot_off, slot_offset};

// ============================================================================
// INT 33h — Microsoft Mouse driver
// ============================================================================

/// INT 33h — Microsoft Mouse Driver API. Minimal implementation covering
/// the subfunctions DOS games actually use: install check, show/hide cursor
/// (counter only — we don't draw), get/set position, button press/release
/// history, set range, read motion counters.
///
/// Mouse hardware state lives on `dos.pc.mouse` and is updated by the IRQ 12
/// packet stream queued through `machine::queue_irq`.
pub(super) fn int_33h<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
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
            *m = crate::kernel::dos::machine::MouseState::new();
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
        // Returns AX=button mask, BX=transition count since the last query for
        // this button, CX=x and DX=y at the last transition. Reading consumes
        // only the selected button's counter.
        // AX=0006h — same shape for button release.
        0x0005 | 0x0006 => {
            let button = (regs.rbx as u16) as usize;
            regs.rax = (regs.rax & !0xFFFF) | m.buttons as u64;
            let (count, x, y) = if button < 3 && ax == 0x0005 {
                let count = core::mem::take(&mut m.press_count[button]);
                (count, m.last_press_x[button], m.last_press_y[button])
            } else if button < 3 {
                let count = core::mem::take(&mut m.release_count[button]);
                (count, m.last_release_x[button], m.last_release_y[button])
            } else {
                (0, m.x, m.y)
            };
            regs.rbx = (regs.rbx & !0xFFFF) | count as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (x as u16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (y as u16) as u64;
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
        _ => {}
    }
    thread::KernelAction::Done
}

/// Deliver the INT 33h AX=000Ch software mouse callback.
///
/// Bracket-saves the user GP regs we're about to clobber (AX/BX/CX/DX/SI/DI)
/// since `HostContinuation` only covers CS/EIP/SS/ESP/EFLAGS/segs. The user handler
/// returns via SLOT_MOUSE_CB_RET which restores them and then unwinds through
/// the standard `resume_continuation_from_stub`.
pub(in crate::kernel::dos) fn deliver_mouse_callback<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    use crate::kernel::dos::machine::vm86_push;
    use crate::kernel::dos::mode_transitions;

    let cb_is_pm = dos.pc.mouse.cb_is_pm;

    if cb_is_pm {
        // PM client (DPMI): the handler is `selector:offset` and must run in
        // protected mode. Mirror the IRQ PM-entry path (switch to the PM side
        // via a HostContinuation), but return via FAR RET — MS-Mouse handlers
        // end with RETF, not IRET — to the SLOT_MOUSE_CB_RET trampoline.
        mode_transitions::enter_pm(dos, regs, None);
    } else {
        // Real-mode client: ES:DX is a paragraph; far-call it on the RM stack.
        let rm_dest = mode_transitions::rm_stack(dos, regs);
        mode_transitions::enter_rm(dos, regs, rm_dest, None);
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
        crate::kernel::dos::machine::set_vm86_cs(regs, cb_seg);
        crate::kernel::dos::machine::set_vm86_ip(regs, cb_off as u16);
    }

    dos.pc.mouse.cb_in_flight = true;

    dos_trace!("[MOUSE] CB enter cond={:04X} buttons={:02X} x={} y={} dx={} dy={} -> {:04X}:{:08X}{}",
        cond, buttons, x as i16, y as i16, dx as i16, dy as i16, cb_seg, cb_off,
        if cb_is_pm { " (PM)" } else { "" });
}

/// SLOT_MOUSE_CB_RET dispatch: user handler RETFed to this slot.
/// Restore the GP regs `deliver_mouse_callback` clobbered, then unwind via
/// the same `resume_continuation_from_stub` that SLOT_RESUME_CONTINUATION uses.
pub(in crate::kernel::dos) fn mouse_callback_return<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) {
    use crate::kernel::dos::machine::vm86_pop;
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

    crate::kernel::dos::mode_transitions::resume_continuation_from_stub(machine, dos, regs);
}
