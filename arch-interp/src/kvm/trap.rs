//! KVM adaptations around the shared canonical guest trap handler.
use arch_abi::{GuestBytes, KernelEvent, Regs, UserMode};
use arch_abi::trap::Outcome;
use super::setup::KvmCpu;

impl arch_abi::trap::Machine for crate::backend::Interp {
    fn can_fault(&self) -> bool { crate::phys::can_fault() }
    fn resolve_page_fault(&mut self, _regs: &Regs, address: u64) -> bool {
        let Ok(address) = u32::try_from(address) else { return false; };
        if crate::paging::space_translate(address).is_none() {
            crate::paging::space_demand(address)
        } else {
            crate::paging::space_cow_fault(address)
        }
    }
}

pub(super) fn handle(k: &KvmCpu, regs: &mut Regs) -> Option<KernelEvent> {
    let mut machine = crate::backend::Interp;
    // KVM leaves SCE disabled. Normalize its SYSCALL #UD to the sentinel
    // produced by metal's SYSCALL entry before shared event classification.
    if regs.mode() == UserMode::Mode64 && regs.int_num == 6 {
        let ip = regs.frame.rip;
        if machine.read::<u8>(ip) == 0x0f && machine.read::<u8>(ip + 1) == 0x05 {
            regs.frame.rip += 2;
            regs.rcx = regs.frame.rip;
            regs.r11 = regs.frame.rflags;
            regs.int_num = 256;
        }
    }
    let address = if regs.int_num == 14 {
        k.vcpu.get_sregs().expect("KVM_GET_SREGS").cr2
    } else { 0 };
    match arch_abi::trap::handle(&mut machine, regs, address) {
        Outcome::Resume => None,
        Outcome::ReturnToKernel(KernelEvent::Fault) => Some(KernelEvent::Exception(13)),
        Outcome::ReturnToKernel(KernelEvent::Exception(n))
            if regs.mode() == UserMode::VM86 && n != 13 && !crate::desc::int_intercepted(n) => {
                arch_abi::monitor::sw_reflect_vm86_int(regs, &mut machine, n);
                None
            }
        Outcome::ReturnToKernel(KernelEvent::Exception(n)) if regs.mode() == UserMode::VM86 && n != 13 => {
            Some(KernelEvent::SoftInt(n))
        }
        Outcome::ReturnToKernel(event) => Some(event),
    }
}
