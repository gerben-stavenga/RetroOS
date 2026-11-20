//! The host only resumes arch and waits for its kernel handoff. Guest faults,
//! instruction monitoring, and mode transitions never leave the supervisor.
use super::setup::{self, KvmCpu};
use arch_abi::{KernelEvent, vm::{self, Exchange}};
use kvm_ioctls::VcpuExit;
use std::os::fd::AsRawFd;
use core::sync::atomic::Ordering;

pub(super) fn until_return(cpu: &mut KvmCpu, executing: bool) {
    loop {
        match cpu.vcpu.run() {
            Ok(VcpuExit::IoOut(vm::EXIT_PORT, bytes)) => {
                assert_eq!(bytes.len(), 4);
                let address = u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
                let physical = address.checked_sub(vm::IMAGE_VIRTUAL).unwrap() + vm::IMAGE_PHYSICAL;
                assert!(physical + core::mem::size_of::<Exchange>() <= vm::IMAGE_LIMIT);
                let pointer = unsafe { cpu.image.add(physical).cast::<Exchange>() };
                assert!(cpu.message.is_null() || cpu.message == pointer);
                cpu.message = pointer;
                cpu.vcpu.get_kvm_run().request_interrupt_window = 0;
                return;
            }
            Ok(VcpuExit::IoOut(0xe9, bytes)) => { eprint!("{}", String::from_utf8_lossy(bytes)); }
            Ok(VcpuExit::IoOut(vm::PANIC_PORT, _)) => panic!("arch supervisor panicked"),
            Err(e) if e.errno() == libc::EINTR => {
                cpu.vcpu.set_kvm_immediate_exit(0);
                if executing { cpu.vcpu.get_kvm_run().request_interrupt_window = 1; }
            }
            Ok(VcpuExit::IrqWindowOpen) => {
                // Injection requires KVM's interrupt window. In particular,
                // EINTR can stop in arch with IF=0 or a trap still in flight.
                cpu.vcpu.get_kvm_run().request_interrupt_window = 0;
                let irq = kvm_bindings::kvm_interrupt { irq: vm::INTERRUPT_VECTOR };
                assert_eq!(unsafe { libc::ioctl(cpu.vcpu.as_raw_fd(), 0x4004ae86u64, &irq) }, 0,
                    "KVM_INTERRUPT: {}", std::io::Error::last_os_error());
            }
            Ok(exit) => {
                let reason = format!("{exit:?}");
                panic!("unexpected arch supervisor exit: {reason}; regs={:?}; sregs={:?}", cpu.vcpu.get_regs(), cpu.vcpu.get_sregs());
            }
            Err(error) => panic!("KVM_RUN: {error}"),
        }
    }
}

pub fn execute(max_time: core::time::Duration) -> KernelEvent {
    if max_time.is_zero() { return KernelEvent::Irq; }
    crate::screendump::maybe_dump();
    crate::screendump::maybe_render_live();
    super::descriptors_ready();
    setup::with(|cpu| {
        cpu.vcpu.set_kvm_immediate_exit(0);
        unsafe {
            (*cpu.message).operation = vm::op::EXECUTE;
            (*cpu.message).regs = (*(&raw const crate::vcpu::REGS)).regs;
        }
        let now = crate::machine::now();
        let deadline = now.saturating_add(max_time.as_nanos().min(u64::MAX as u128) as u64);
        // Clear immediate_exit before inspecting the alarm: an older signal
        // invalidates its deadline, and a subsequent signal still forces exit.
        if !setup::alarm_deadline().is_some_and(|armed| now < armed && armed <= deadline) {
            setup::arm_alarm(deadline);
        }
        setup::CPU_TID.store(cpu.tid, Ordering::Release);
        until_return(cpu, true);
        setup::CPU_TID.store(0, Ordering::Release);
        let message = unsafe { &*cpu.message };
        unsafe { (*(&raw mut crate::vcpu::REGS)).regs = message.regs; }
        KernelEvent::decode(message.result[0] as u32, message.result[1])
    })
}
