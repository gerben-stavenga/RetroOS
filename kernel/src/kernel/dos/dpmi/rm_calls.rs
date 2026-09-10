use crate::Regs;
use super::*;
use super::super::mode_transitions;
use super::super::mode_transitions::RmCallStruct;

// Real-mode callback stack semantics are subtle and the current implementation
// deliberately follows a CWSDPMI/DOS4GW compatibility path. Before changing
// callback entry or return, read DPMI_REAL_MODE_CALLBACKS.md at the repository
// root; it records the specification contract, the different CWSDPMI and
// HDPMI implementations, the Raptor failure that exposed this path, and the
// remaining Windows test.

#[derive(Clone, Copy)]
enum Transfer { Interrupt(u8), FarCall, Iret }

impl Transfer {
    fn entry_flags(self, supplied: u16) -> u32 {
        let flags = u32::from(supplied);
        match self {
            Self::FarCall => flags,
            // DPMI 0300/0302 push the supplied FLAGS unchanged, but enter
            // the RM handler with IF and TF clear.
            Self::Interrupt(_) | Self::Iret => flags & !(machine::IF_FLAG | (1 << 8)),
        }
    }
}

fn transfer<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, transfer: Transfer) -> thread::KernelAction {
    let client_use32 = dos.dpmi.as_ref().unwrap().client_use32;
    let struct_addr = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, client_use32);
    let rm = machine.read::<RmCallStruct>((struct_addr) as usize);
    if matches!(transfer, Transfer::Interrupt(0x10))
        && rm.eax as u16 & 0xFF00 == 0x4F00
        && crate::kernel::platform::get().firmware == crate::kernel::platform::Firmware::NativeBios
    { dos.pc.native_vbe_io_rmcs = struct_addr; }

    let rm_stack = if rm.ss == 0 { mode_transitions::rm_stack(dos, regs) }
                   else { (rm.ss, rm.sp as u32) };
    machine.write::<RmCallStruct>(struct_addr as usize, RmCallStruct::capture(regs));
    mode_transitions::enter_rm(dos, regs, rm_stack, Some(struct_addr));
    mode_transitions::suspend_call_vif(dos);
    rm.restore(regs);

    let resume = dos::ctrl_slot_off(dos::SLOT_RESUME_CONTINUATION);
    if !matches!(transfer, Transfer::FarCall) {
        machine::vm86_push(machine, regs, rm.flags);
    }
    machine::vm86_push(machine, regs, dos::CTRL_STUB_SEG);
    machine::vm86_push(machine, regs, resume);

    let (cs, ip) = match transfer {
        Transfer::Interrupt(n) => (
            machine::read_u16(machine, 0, n as u32 * 4 + 2),
            machine::read_u16(machine, 0, n as u32 * 4),
        ),
        _ => (rm.cs, rm.ip),
    };
    regs.frame.cs = cs as u64;
    regs.frame.rip = ip as u64;
    machine::set_vm86_flags(regs, transfer.entry_flags(rm.flags));
    thread::KernelAction::Done
}

pub(super) fn simulate_real_mode_int<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    transfer(machine, dos, regs, Transfer::Interrupt(regs.rbx as u8))
}

pub(super) fn call_real_mode_proc<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    transfer(machine, dos, regs, Transfer::FarCall)
}

pub(super) fn call_real_mode_proc_iret<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    transfer(machine, dos, regs, Transfer::Iret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_interrupt_entry_clears_if_tf_and_preserves_status() {
        for transfer in [Transfer::Interrupt(0x21), Transfer::Iret] {
            for control in [0, 0x100, 0x200, 0x300] {
                let supplied = 0x0CD7 | control; // arithmetic flags and DF
                let mut regs = Regs::empty();
                regs.set_flags32(machine::VM_FLAG | machine::VIF_FLAG | machine::IOPL_DEFAULT);
                machine::set_vm86_flags(&mut regs, transfer.entry_flags(supplied));
                assert_eq!(machine::guest_flags(&regs) & 0x0FD7, 0x0CD7);
                assert_eq!(regs.flags32() & machine::VIF_FLAG, 0);
                assert!(!regs.user_tf());
                assert_ne!(regs.flags32() & machine::VM_FLAG, 0);
            }
        }
    }

    #[test]
    fn far_call_uses_supplied_if_tf_instead_of_current_state() {
        for control in [0, 0x100, 0x200, 0x300] {
            let supplied = 0x0CD7 | control;
            let mut regs = Regs::empty();
            regs.set_flags32(machine::VM_FLAG | machine::VIF_FLAG | machine::IOPL_DEFAULT);
            machine::set_vm86_flags(&mut regs, Transfer::FarCall.entry_flags(supplied));
            assert_eq!(machine::guest_flags(&regs) & 0x0FD7, u32::from(supplied));
            assert_eq!(regs.user_tf(), control & 0x100 != 0);
        }
    }
}

/// Real-mode callback entry — real-mode code called one of our callback stubs.
/// Save real-mode state, fill register structure, switch to PM callback handler.
pub(in crate::kernel::dos) fn callback_entry<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs, cb_idx: usize) {
    let cb = match dos.dpmi.as_ref() {
        Some(d) => d.callbacks[cb_idx],
        None => {
            crate::compact_println!("DPMI: callback entry but no DPMI state!");
            return;
        }
    };
    let (pm_cs, pm_eip, rm_struct_sel, rm_struct_off) = match cb {
        Some(cb) => cb,
        None => {
            crate::compact_println!("DPMI: callback {} not allocated!", cb_idx);
            return;
        }
    };



    // Save current real-mode regs into the register structure
    let struct_addr = seg_base(&dos.ldt[..], rm_struct_sel).wrapping_add(rm_struct_off);

    let rm_call = RmCallStruct::capture(regs);
    machine.write::<RmCallStruct>((struct_addr) as usize, rm_call);

    // RM→PM toggle: pushes HostContinuation on the pm side and records
    // the RM call-structure address in it. `resume_continuation` later
    // swaps the handler-visible structure with the live regs and restores
    // the RM caller continuation.
    // DPMI 0.9 §6.1.1: DS:(E)SI must point at the RM stack location
    // where the caller's return addresses are pushed — handler reads
    // CS:IP from there. Capture before enter_pm mutates regs.
    // 16-bit SP, not sp32(): the real-mode caller only maintains SP, and ESP's
    // high half legally carries stale garbage (VM86 pushes/pops move SP while
    // ESP31:16 keeps whatever an earlier PM context left there). Folding those
    // bits in aimed DS:ESI at a kernel address — DUKE3D's DOS/16M callback
    // handler read [ESI+0x14] and SEGV'd on the first timer tick after its
    // music started.
    let rm_ss_sp_linear = (regs.stack_seg() as u32).wrapping_shl(4)
        .wrapping_add(regs.sp32() & 0xFFFF);

    mode_transitions::enter_pm(dos, regs, Some(struct_addr));

    // Plant an iret-frame above the continuation: the PM callback handler
    // IRETs to SPECIAL_STUB_SEL:SLOT_RESUME_CONTINUATION, which dispatches
    // `resume_continuation_from_stub` for writeback, GP restore, and RM-caller return.
    // Per DPMI 0.9 §6.1.1 the PM callback procedure must execute IRET. The
    // frame width follows the client type, not the callback selector's D bit:
    // 32-bit DOS extenders commonly put callback thunks in a D=0 segment and
    // return with an explicit operand-size override (`66 CF`).
    let client_use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
    mode_transitions::push_iret_frame(machine, 
        &dos.ldt[..], regs, client_use32,
        dos::STUB_BASE + dos::slot_offset(dos::SLOT_RESUME_CONTINUATION) as u32,
        mode_transitions::SPECIAL_STUB_SEL,
        0x202, // IF=1
    );

    // DS:(E)SI = pointer to RM SS:SP (where the caller's return frame lives).
    // This is the CWSDPMI representation: flat low-memory DS plus a linear
    // ESI. HDPMI instead aliases the current RM SS with a callback-specific
    // selector and passes ESI=SP. Both point to the correct entry byte, but
    // they lead DOS/4GW to encode the returned RMCS SP differently. See
    // DPMI_REAL_MODE_CALLBACKS.md before changing either side of this path.
    // ES:(E)DI = pointer to PM register structure.
    regs.frame.cs = pm_cs as u64;
    regs.set_ip32(pm_eip);
    // Match the established CWSDPMI callback wrapper: EAX identifies an
    // allocated user callback (type zero), while the real-mode AX value lives
    // in the register structure at ES:(E)DI. Some extender callback thunks use
    // this otherwise-unspecified live value to select their wrapper path.
    regs.rax = 0;
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
