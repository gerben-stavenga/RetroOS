//! KVM-engine proofs: enter the guest for real (VM86 and flat PM), drive the
//! trap shim, demand paging, COW, and the shared monitor end-to-end on
//! hardware. Each test skips with a message when `/dev/kvm` is unavailable
//! (CI without nested virt), so the suite stays green everywhere.
//!
//! NOTE: these share the crate's global live context (`vcpu::REGS`) and the
//! phys memfd, so everything runs inside ONE #[test] (Rust runs tests on
//! separate threads; a second REGS user would race).

use super::*;
use crate::space::RootPageTable;
use crate::sysdesc::{VIF_FLAG, VM_FLAG};
use arch_abi::{GuestBytes, KernelEvent, Regs, Vcpu, USER_CS, USER_DS};

fn kvm_available() -> bool {
    kvm_ioctls::Kvm::new().is_ok()
}

/// Run `execute()` until a non-Irq event (the 1 ms timer kick can interleave
/// anywhere), with a bound so a wedged guest fails the test instead of
/// hanging it.
fn run_to_event() -> KernelEvent {
    for _ in 0..10_000 {
        match execute() {
            KernelEvent::Irq => continue,
            ev => return ev,
        }
    }
    panic!("guest made no progress (10k Irq slices)");
}

fn set_regs(regs: Regs) {
    crate::vcpu::set_current_vcpu(Vcpu::new(regs, RootPageTable(crate::mmu::active_id())));
}

fn regs() -> Regs {
    unsafe { (*(&raw const crate::vcpu::REGS)).regs }
}

#[test]
fn kvm_engine_proofs() {
    if !kvm_available() {
        assert!(
            std::env::var_os("RETRO_REQUIRE_KVM").is_none(),
            "RETRO_REQUIRE_KVM set but /dev/kvm is unavailable"
        );
        eprintln!("SKIP: /dev/kvm unavailable — KVM engine proofs not run");
        return;
    }
    crate::mmu::init();
    let mut mem = RootPageTable(crate::mmu::active_id());

    // ── VM86: `int 0x31` (the trapped DPMI stub vector) from real-mode code.
    // The INT is IOPL-sensitive at IOPL=1 → #GP → shim → shared monitor →
    // redirection bitmap traps 0x31 → SoftInt(0x31). Exercises: v86 entry
    // shape, demand-#PF on the first code fetch, the #GP monitor path.
    // 0xB8 0x34 0x12   mov ax, 0x1234
    // 0xCD 0x31        int 0x31
    mem.copy_to(0x7C00, &[0xB8, 0x34, 0x12, 0xCD, 0x31]);
    let mut r = Regs::empty();
    r.set_cs32(0);
    r.set_ip32(0x7C00);
    r.set_ss32(0);
    r.set_sp32(0x7000);
    r.set_flags32((VM_FLAG as u32) | VIF_FLAG | 2);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x31) => {}
        ev => panic!("VM86 int 0x31: expected SoftInt(0x31), got {ev:?}"),
    }
    let r = regs();
    assert_eq!(r.rax as u16, 0x1234, "mov ax retired before the INT");
    assert_eq!(r.ip32(), 0x7C05, "monitor advanced IP past the INT");
    assert!(r.flags32() & (VM_FLAG as u32) != 0, "still VM86 after the trap");

    // ── Flat PM: a store to an unmapped page (demand-#PF resolved inside the
    // engine), then `int 0x80` → SoftInt(0x80). Exercises: CPL3 PM entry with
    // no trampoline, in-engine demand paging on a data write, DPL-3 gate INT.
    // 0xC7 0x05 <addr> <imm32>   mov dword [0x0030_0000], 0xDEADBEEF
    // 0xCD 0x80                  int 0x80
    let code: u32 = 0x0020_0000;
    let data: u32 = 0x0030_0000;
    let stack: u32 = 0x0028_0000;
    let mut prog = vec![0xC7, 0x05];
    prog.extend_from_slice(&data.to_le_bytes());
    prog.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    prog.extend_from_slice(&[0xCD, 0x80]);
    mem.copy_to(code as usize, &prog);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x80) => {}
        ev => panic!("PM int 0x80: expected SoftInt(0x80), got {ev:?}"),
    }
    let r = regs();
    assert_eq!(r.code_seg(), USER_CS, "still flat user CS");
    assert_eq!(r.frame.ss as u16, USER_DS, "still flat user SS");
    assert_eq!(
        mem.read::<u32>(data as usize),
        0xDEAD_BEEF,
        "the demand-faulted store landed in guest memory"
    );

    // ── PM #GP path: `hlt` at CPL3 → #GP(0) → monitor → KernelEvent::Hlt.
    mem.copy_to(code as usize, &[0xF4]);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::Hlt => {}
        ev => panic!("PM hlt: expected Hlt, got {ev:?}"),
    }

    // ── COW: fork the space, write to a shared page in the child, verify the
    // parent's copy is untouched (the #PF → space_cow_fault path under KVM).
    mem.write::<u32>(data as usize, 0x1111_1111);
    let parent = crate::mmu::active_id();
    let child = crate::mmu::fork_copy(parent);
    crate::mmu::switch_to(child);
    // In the child: increment the shared dword, then int 0x80.
    // 0xFF 0x05 <addr>   inc dword [data]
    // 0xCD 0x80          int 0x80
    let mut prog = vec![0xFF, 0x05];
    prog.extend_from_slice(&data.to_le_bytes());
    prog.extend_from_slice(&[0xCD, 0x80]);
    let mut child_mem = RootPageTable(child);
    child_mem.copy_to(code as usize, &prog);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x80) => {}
        ev => panic!("COW child: expected SoftInt(0x80), got {ev:?}"),
    }
    assert_eq!(child_mem.read::<u32>(data as usize), 0x1111_1112, "child sees its increment");
    crate::mmu::switch_to(parent);
    crate::vcpu::set_current_vcpu(Vcpu::new(Regs::empty(), RootPageTable(parent)));
    assert_eq!(
        mem.read::<u32>(data as usize),
        0x1111_1111,
        "parent's page untouched by the child's COW write"
    );
}
