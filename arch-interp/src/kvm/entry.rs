//! One-time ELF loading and entry into the freestanding arch supervisor.
//! Subsequent entries resume KVM_RUN; all IRET and mode changes happen in arch.
use arch_abi::vm;
const IMAGE: &[u8] = include_bytes!(env!("ARCH_SUPERVISOR_IMAGE"));
fn u16_at(at: usize) -> usize { u16::from_le_bytes(IMAGE[at..at + 2].try_into().unwrap()) as usize }
fn u32_at(at: usize) -> usize { u32::from_le_bytes(IMAGE[at..at + 4].try_into().unwrap()) as usize }
pub(super) fn load(memory: *mut u8) -> u64 {
    assert_eq!(&IMAGE[..7], b"\x7fELF\x01\x01\x01");
    for i in 0..u16_at(44) {
        let ph = u32_at(28) + i * u16_at(42);
        if u32_at(ph) != 1 { continue; }
        let offset = u32_at(ph + 4);
        let physical = u32_at(ph + 12);
        let filesz = u32_at(ph + 16);
        let memsz = u32_at(ph + 20);
        assert!(filesz <= memsz && physical + memsz <= vm::IMAGE_LIMIT);
        unsafe { core::ptr::copy_nonoverlapping(IMAGE[offset..offset + filesz].as_ptr(), memory.add(physical), filesz); }
    }
    (u32_at(24) - vm::IMAGE_VIRTUAL + vm::IMAGE_PHYSICAL) as u64
}
pub(super) fn boot(vcpu: &kvm_ioctls::VcpuFd, entry: u64) {
    let mut s = vcpu.get_sregs().expect("KVM_GET_SREGS bootstrap");
    s.cr0 = 0x33;
    s.cr3 = 0;
    s.cr4 = 0x600;
    s.efer = 0;
    let data = kvm_bindings::kvm_segment { base: 0, limit: u32::MAX, selector: 0x10,
        type_: 3, present: 1, dpl: 0, db: 1, s: 1, g: 1, ..Default::default() };
    s.cs = kvm_bindings::kvm_segment { selector: 8, type_: 11, ..data };
    s.ds = data; s.es = data; s.fs = data; s.gs = data; s.ss = data;
    vcpu.set_sregs(&s).expect("KVM_SET_SREGS bootstrap");
    vcpu.set_regs(&kvm_bindings::kvm_regs { rip: entry, rflags: 2, ..Default::default() }).expect("KVM_SET_REGS bootstrap");
}
