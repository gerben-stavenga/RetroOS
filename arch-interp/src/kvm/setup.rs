//! Host setup for the real arch supervisor. Runtime requests never install
//! guest page tables, descriptor tables, or application registers with ioctls.
use kvm_bindings::{kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use std::cell::RefCell;
use arch_abi::vm::{self, Exchange};

pub(super) struct KvmCpu {
    pub _vm: VmFd,
    pub planar_bound: bool,
    pub vcpu: VcpuFd,
    pub image: *mut u8,
    pub message: *mut Exchange,
}
thread_local! { static KVM: RefCell<Option<KvmCpu>> = const { RefCell::new(None) }; }
// All VM CPUs share donated RAM and reference counts. Serialize supervisor
// transitions, including fault handling, just as the metal paging lock does.
static SUPERVISOR: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(super) fn with<R>(f: impl FnOnce(&mut KvmCpu) -> R) -> R {
    let _lock = SUPERVISOR.lock().unwrap();
    KVM.with(|cell| {
        let mut slot = cell.borrow_mut();
        f(slot.get_or_insert_with(init))
    })
}
fn init() -> KvmCpu {
    let kvm = Kvm::new().expect("open /dev/kvm");
    let vmfd = kvm.create_vm().expect("KVM_CREATE_VM");
    vmfd.set_tss_address(0xe0000000).expect("KVM_SET_TSS_ADDR");
    let image = unsafe { libc::mmap(core::ptr::null_mut(), vm::IMAGE_LIMIT,
        libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    assert_ne!(image, libc::MAP_FAILED);
    let entry = super::entry::load(image.cast());
    let ownership = crate::phys::ownership();
    assert!(!ownership.counts.is_null() && ownership.counts as usize % 4096 == 0);
    for (slot, physical, bytes, host) in [
        (0, 0, vm::IMAGE_LIMIT, image as u64),
        (1, vm::IMAGE_LIMIT as u64, crate::phys::PHYS_SIZE - vm::IMAGE_LIMIT,
            unsafe { crate::phys::region_base().add(vm::IMAGE_LIMIT) } as u64),
        (2, vm::COUNTS_PHYSICAL, ownership.active.next_multiple_of(4096), ownership.counts as u64),
    ] {
        unsafe { vmfd.set_user_memory_region(kvm_userspace_memory_region {
            slot, flags: 0, guest_phys_addr: physical, memory_size: bytes as u64, userspace_addr: host,
        }) }.expect("KVM_SET_USER_MEMORY_REGION");
    }
    let mut vcpu = vmfd.create_vcpu(0).expect("KVM_CREATE_VCPU");
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).expect("KVM_GET_SUPPORTED_CPUID");
    for e in cpuid.as_mut_slice() {
        if e.function == 1 { e.ecx &= !(1 << 31); }
        if (0x40000000..=0x400000ff).contains(&e.function) { e.eax = 0; e.ebx = 0; e.ecx = 0; e.edx = 0; }
    }
    vcpu.set_cpuid2(&cpuid).expect("KVM_SET_CPUID2");
    super::entry::boot(&vcpu, entry);
    install_alarm(&mut vcpu);
    let mut cpu = KvmCpu { planar_bound: false, _vm: vmfd, vcpu, image: image.cast(), message: core::ptr::null_mut() };
    super::run::until_return(&mut cpu, false);
    let message = unsafe { &mut *cpu.message };
    message.operation = vm::op::CONFIGURE;
    message.args = [ownership.regions_len as u64, ownership.active as u64, 0, 0, 0, 0];
    for (i, region) in unsafe { core::slice::from_raw_parts(ownership.regions, ownership.regions_len) }.iter().enumerate() {
        let bytes = &mut message.data[i * 24..i * 24 + 24];
        bytes[..8].copy_from_slice(&region.first.to_le_bytes());
        bytes[8..16].copy_from_slice(&region.end.to_le_bytes());
        bytes[16..24].copy_from_slice(&(region.offset as u64).to_le_bytes());
    }
    super::run::until_return(&mut cpu, false);
    cpu
}
use core::sync::atomic::{AtomicI32, Ordering};
// One hosted execution CPU. The signal handler only writes KVM's documented
// immediate_exit byte; no allocation, locks, or guest-state borrowing.
static CPU_TID: AtomicI32 = AtomicI32::new(0);
thread_local! {
    static IMMEDIATE_EXIT: std::cell::Cell<*mut u8> = const { std::cell::Cell::new(core::ptr::null_mut()) };
    static TIMER: std::cell::Cell<Option<libc::timer_t>> = const { std::cell::Cell::new(None) };
}
extern "C" fn alarm_signal(_: libc::c_int) {
    let _ = IMMEDIATE_EXIT.try_with(|slot| {
        let pointer = slot.get();
        if !pointer.is_null() { unsafe { pointer.write_volatile(1); } }
    });
}
fn install_alarm(vcpu: &mut VcpuFd) {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = alarm_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGURG, &sa, core::ptr::null_mut()), 0);
        IMMEDIATE_EXIT.with(|slot| slot.set(&raw mut vcpu.get_kvm_run().immediate_exit));
        let mut sev: libc::sigevent = core::mem::zeroed();
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = libc::SIGURG;
        sev.sigev_notify_thread_id = libc::gettid();
        let mut timer: libc::timer_t = core::mem::zeroed();
        assert_eq!(libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer), 0);
        TIMER.with(|slot| slot.set(Some(timer)));
    }
}
pub(crate) fn arm_alarm(deadline: Option<u64>) {
    CPU_TID.store(if deadline.is_some() { unsafe { libc::gettid() } } else { 0 }, Ordering::Release);
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
        let _ = IMMEDIATE_EXIT.try_with(|slot| slot.set(core::ptr::null_mut()));
        let _ = CPU_TID.compare_exchange(unsafe { libc::gettid() }, 0, Ordering::AcqRel, Ordering::Acquire);
        let _ = TIMER.try_with(|slot| {
            if let Some(timer) = slot.take() { unsafe { libc::timer_delete(timer); } }
        });
        unsafe { libc::munmap(self.image.cast(), vm::IMAGE_LIMIT); }
    }
}

/// Map the owner's resident pages into the supervisor for the duration of a
/// loan. No host pointer appears in a VM request or in supervisor storage.
pub(super) unsafe fn bind_planar(binding: Option<planar::Binding>) {
    with(|cpu| {
        if binding.is_none() && !cpu.planar_bound { return; }
        if let Some(b) = binding {
            assert!(!cpu.planar_bound, "detach planar storage before replacing it");
            for (slot, host, physical, size) in [
                (3, b.registers as u64, vm::PLANAR_PHYSICAL, 4096),
                (4, b.planes as u64, vm::PLANAR_PHYSICAL + 4096, 4 * 65536),
            ] {
                assert!(host != 0 && host % 4096 == 0);
                unsafe { cpu._vm.set_user_memory_region(kvm_userspace_memory_region {
                    slot, flags: 0, guest_phys_addr: physical, memory_size: size, userspace_addr: host,
                }) }.expect("map borrowed planar storage");
            }
        }
        let message = unsafe { &mut *cpu.message };
        message.operation = vm::op::BIND_PLANAR;
        message.page_count = 0;
        message.args = [binding.is_some() as u64, 0, 0, 0, 0, 0];
        super::run::until_return(cpu, false);
        if binding.is_none() {
            // Revoke the VM aliases before releasing the owner's loan.
            for slot in [3, 4] {
                unsafe { cpu._vm.set_user_memory_region(kvm_userspace_memory_region {
                    slot, ..Default::default()
                }) }.expect("unmap borrowed planar storage");
            }
        }
        cpu.planar_bound = binding.is_some();
    })
}
