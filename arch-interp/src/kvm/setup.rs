//! KVM VM/vcpu bring-up and the real-time preemption kick.
//!
//! One VM, one vcpu, one memory slot: guest-physical `[0, PHYS_SIZE)` is the
//! same memfd mapping the TCG engine hands Unicorn (`phys::region_base()`), so
//! frame aliasing, COW sharing and hole-punched frees are transparently
//! visible to the guest. No in-kernel irqchip and no in-kernel PIT — the
//! RetroOS kernel emulates the PIC/PIT itself; hardware interrupts surface to
//! it as `KernelEvent::Irq` returns and are never injected into the guest.

use kvm_bindings::{kvm_sregs, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use std::cell::RefCell;

pub(super) struct KvmCpu {
    /// Keeps the VM fd alive (memory slots die with it).
    pub _vm: VmFd,
    pub vcpu: VcpuFd,
    /// Current KVM_SET_GUEST_DEBUG single-step state (toggle only on change).
    pub single_step: bool,
    /// The vcpu's reset sregs — the template each entry builds on, so fields
    /// this engine doesn't manage (apic_base, interrupt_bitmap) keep the
    /// values KVM expects.
    pub sregs0: kvm_sregs,
}

thread_local! {
    /// The engine's vcpu — thread-local like all interp state; created lazily
    /// on first `execute()`, i.e. on the CPU thread.
    static KVM: RefCell<Option<KvmCpu>> = const { RefCell::new(None) };
}

pub(super) fn with<R>(f: impl FnOnce(&mut KvmCpu) -> R) -> R {
    KVM.with(|cell| {
        let mut slot = cell.borrow_mut();
        f(slot.get_or_insert_with(init))
    })
}

fn init() -> KvmCpu {
    let kvm = Kvm::new().expect("open /dev/kvm (is the kvm module loaded and the device accessible?)");
    let vm = kvm.create_vm().expect("KVM_CREATE_VM");

    // Legacy VMX real/vm86 emulation scratch (pre-unrestricted-guest CPUs);
    // required to exist, must not overlap guest RAM. Park it high.
    vm.set_tss_address(0xE000_0000).expect("KVM_SET_TSS_ADDR");

    // The single memory slot over the phys memfd view.
    let region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0,
        guest_phys_addr: 0,
        memory_size: crate::phys::PHYS_SIZE as u64,
        userspace_addr: crate::phys::region_base() as u64,
    };
    unsafe { vm.set_user_memory_region(region) }.expect("KVM_SET_USER_MEMORY_REGION");

    let vcpu = vm.create_vcpu(0).expect("KVM_CREATE_VCPU");

    // Host-supported CPUID, minus the paravirt tells: the guest is meant to see
    // a plain (fast) PC, exactly like metal. Zero the hypervisor leaves and the
    // hypervisor-present bit.
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).expect("KVM_GET_SUPPORTED_CPUID");
    for e in cpuid.as_mut_slice().iter_mut() {
        if e.function == 1 {
            e.ecx &= !(1 << 31); // CPUID.1:ECX.HYPERVISOR
        }
        if (0x4000_0000..=0x4000_00FF).contains(&e.function) {
            e.eax = 0;
            e.ebx = 0;
            e.ecx = 0;
            e.edx = 0;
        }
    }
    vcpu.set_cpuid2(&cpuid).expect("KVM_SET_CPUID2");

    // Guest-side tables: the shared SYS window plus the KVM trap shim (a
    // Once — the kernel's io_policy may already have initialized it through
    // `allow_io_ports` before the first execute()).
    super::shim::ensure_shim();

    arm_timer_kick();

    let sregs0 = vcpu.get_sregs().expect("KVM_GET_SREGS");
    KvmCpu { _vm: vm, vcpu, single_step: false, sregs0 }
}

/// Program the real-time preemption kick: a 1 ms CLOCK_MONOTONIC timer signals
/// THIS thread (SIGEV_THREAD_ID) with SIGURG. The handler is a no-op installed
/// WITHOUT SA_RESTART, so a signal landing during `KVM_RUN` bounces the ioctl
/// out with EINTR — the engine returns `KernelEvent::Irq` and the kernel pumps
/// its timer from `get_ticks()` deltas. A signal landing while host code runs
/// is consumed harmlessly (nothing is lost: ticks are derived from elapsed
/// time, not from counting kicks). 1 ms matches metal's 1 kHz PIT grid.
fn arm_timer_kick() {
    unsafe {
        extern "C" fn noop(_: libc::c_int) {}
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = noop as *const () as usize;
        sa.sa_flags = 0; // no SA_RESTART: KVM_RUN must EINTR
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGURG, &sa, core::ptr::null_mut()), 0);

        let mut sev: libc::sigevent = core::mem::zeroed();
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = libc::SIGURG;
        sev.sigev_notify_thread_id = libc::gettid();
        let mut timer: libc::timer_t = core::mem::zeroed();
        assert_eq!(libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer), 0);
        let period = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let spec = libc::itimerspec { it_interval: period, it_value: period };
        assert_eq!(libc::timer_settime(timer, 0, &spec, core::ptr::null_mut()), 0);
    }
}
