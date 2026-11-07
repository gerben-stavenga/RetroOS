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
    /// The last KVM_SET_GUEST_DEBUG `control` word written, so an unchanged
    /// state costs no ioctl (see `run::apply_guest_debug`). 0 = never written.
    pub dbg_control: u32,
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

    let mut vcpu = vm.create_vcpu(0).expect("KVM_CREATE_VCPU");

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
    // the first per-entry I/O policy installation).
    super::shim::ensure_shim();

    install_alarm(&mut vcpu);

    let sregs0 = vcpu.get_sregs().expect("KVM_GET_SREGS");
    KvmCpu { _vm: vm, vcpu, dbg_control: 0, sregs0 }
}

use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
// One hosted execution CPU. The signal handler only writes KVM's documented
// immediate_exit byte; no allocation, locks, or guest-state borrowing.
static CPU_TID: AtomicI32 = AtomicI32::new(0);
static IMMEDIATE_EXIT: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
thread_local! {
    static TIMER: std::cell::Cell<Option<libc::timer_t>> = const { std::cell::Cell::new(None) };
}
extern "C" fn alarm_signal(_: libc::c_int) {
    let pointer = IMMEDIATE_EXIT.load(Ordering::Acquire);
    if !pointer.is_null() { unsafe { pointer.write_volatile(1); } }
}
fn install_alarm(vcpu: &mut VcpuFd) {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = alarm_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGURG, &sa, core::ptr::null_mut()), 0);
        CPU_TID.store(libc::gettid(), Ordering::Release);
        IMMEDIATE_EXIT.store(&raw mut vcpu.get_kvm_run().immediate_exit, Ordering::Release);
        let mut sev: libc::sigevent = core::mem::zeroed();
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = libc::SIGURG;
        sev.sigev_notify_thread_id = libc::gettid();
        let mut timer: libc::timer_t = core::mem::zeroed();
        assert_eq!(libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer), 0);
        TIMER.with(|slot| slot.set(Some(timer)));
    }
    arm_alarm(crate::machine::alarm_deadline());
}
pub(crate) fn arm_alarm(deadline: Option<u64>) {
    TIMER.with(|slot| {
        if let Some(timer) = slot.get() {
            // Convert between clock epochs once, then ask POSIX for a one-shot
            // absolute alarm. A zero it_value means cancellation, never "now".
            let mut clock: libc::timespec = unsafe { core::mem::zeroed() };
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock); }
            let remaining = deadline.map(|end| end.saturating_sub(crate::machine::now()));
            let nanos = remaining.map_or(0, |delta|
                (clock.tv_sec as u64).saturating_mul(1_000_000_000)
                    .saturating_add(clock.tv_nsec as u64).saturating_add(delta.max(1)));
            let value = libc::timespec { tv_sec: (nanos / 1_000_000_000) as _, tv_nsec: (nanos % 1_000_000_000) as _ };
            let spec = libc::itimerspec { it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 }, it_value: value };
            assert_eq!(unsafe { libc::timer_settime(timer, libc::TIMER_ABSTIME, &spec, core::ptr::null_mut()) }, 0);
        }
    });
}
pub(crate) fn kick() {
    let tid = CPU_TID.load(Ordering::Acquire);
    if tid != 0 { unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGURG); } }
}

impl Drop for KvmCpu {
    fn drop(&mut self) {
        // Revoke the signal target before VcpuFd unmaps kvm_run. A final alarm
        // during TLS teardown must never write through a dangling pointer.
        IMMEDIATE_EXIT.store(core::ptr::null_mut(), Ordering::Release);
        CPU_TID.store(0, Ordering::Release);
        let _ = TIMER.try_with(|slot| {
            if let Some(timer) = slot.take() { unsafe { libc::timer_delete(timer); } }
        });
    }
}
