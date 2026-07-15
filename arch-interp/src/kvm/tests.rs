//! KVM-engine proofs: enter the guest for real (VM86 and flat PM), drive the
//! trap shim, demand paging, COW, and the shared monitor end-to-end on
//! hardware. Each test skips with a message when `/dev/kvm` is unavailable
//! (CI without nested virt), so the suite stays green everywhere.
//!
//! NOTE: these share the crate's global live context (`vcpu::REGS`) and the
//! phys memfd, so everything runs inside ONE #[test] (Rust runs tests on
//! separate threads; a second REGS user would race).

use arch_abi::Arch;
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
    // Seed the backend's live frame directly (arch-level proof, below the
    // kernel loop where `execute` would swap them in). Space is unchanged —
    // the active one, set via `Arch::activate` where a test needs to switch.
    unsafe { (*core::ptr::addr_of_mut!(crate::vcpu::REGS)).regs = regs; }
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
    let mut mem = crate::backend::Interp;

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
    let mut child_mem = crate::backend::Interp;
    child_mem.copy_to(code as usize, &prog);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x80) => {}
        ev => panic!("COW child: expected SoftInt(0x80), got {ev:?}"),
    }
    assert_eq!(child_mem.read::<u32>(data as usize), 0x1111_1112, "child sees its increment");
    crate::backend::Interp.activate(RootPageTable(parent), core::ptr::null_mut(), core::ptr::null_mut());
    set_regs(Regs::empty());
    assert_eq!(
        mem.read::<u32>(data as usize),
        0x1111_1111,
        "parent's page untouched by the child's COW write"
    );

    // ── IOPB fast path: an allowed port exits as a direct KVM_EXIT_IO (no
    // #GP, no shim) and must surface with the monitor's exact contract — IP
    // advanced, OUT value in EAX, IN result taken from EAX on re-entry (the
    // canceled KVM completion must NOT clobber it). Then the same code with
    // the port denied again goes through the shim + monitor and must behave
    // identically — the two paths are meant to be observationally equal.
    // 0xB0 0x5A   mov al, 0x5A
    // 0xE6 0xE0   out 0xE0, al
    // 0xE4 0xE0   in  al, 0xE0
    // 0xCD 0x80   int 0x80
    let io_prog: &[u8] = &[0xB0, 0x5A, 0xE6, 0xE0, 0xE4, 0xE0, 0xCD, 0x80];
    for (label, allowed) in [("fast path", true), ("shim path", false)] {
        reset_io_bitmap();
        if allowed {
            allow_io_ports(0xE0, 1);
        }
        mem.copy_to(code as usize, io_prog);
        let mut r = Regs::empty();
        r.init_user_process(code, stack);
        set_regs(r);
        match run_to_event() {
            KernelEvent::Out { port: 0xE0, size: arch_abi::IoSize::Byte } => {}
            ev => panic!("{label}: expected Out(0xE0), got {ev:?}"),
        }
        let r = regs();
        assert_eq!(r.rax as u8, 0x5A, "{label}: OUT value in AL");
        assert_eq!(r.ip32(), code + 4, "{label}: IP advanced past the OUT");
        match run_to_event() {
            KernelEvent::In { port: 0xE0, size: arch_abi::IoSize::Byte } => {}
            ev => panic!("{label}: expected In(0xE0), got {ev:?}"),
        }
        assert_eq!(regs().ip32(), code + 6, "{label}: IP advanced past the IN");
        // The kernel's device answer.
        unsafe { (*(&raw mut crate::vcpu::REGS)).regs.rax = 0xA5 };
        match run_to_event() {
            KernelEvent::SoftInt(0x80) => {}
            ev => panic!("{label}: expected SoftInt(0x80), got {ev:?}"),
        }
        assert_eq!(regs().rax as u8, 0xA5, "{label}: IN result in AL survived re-entry");
    }
    reset_io_bitmap();

    // ── FPU switch: fx_switch swaps the vcpu's live x87/SSE state with a
    // thread save area (metal's arch_switch_to semantics). Thread A parks a
    // marker in XMM0; a switch to a clean thread B clobbers XMM0; switching
    // back must restore A's marker — through the XSAVE round-trip.
    // A: mov eax, 0x11223344; movd xmm0, eax; int 0x80
    mem.copy_to(code as usize, &[0xB8, 0x44, 0x33, 0x22, 0x11, 0x66, 0x0F, 0x6E, 0xC0, 0xCD, 0x80]);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    let mut slot = crate::machine::clean_fx_template();
    fx_switch(&mut slot); // A out (slot = A's state), clean B in
    assert_eq!(
        u32::from_le_bytes(slot.0[160..164].try_into().unwrap()),
        0x1122_3344,
        "outgoing thread's XMM0 captured into its save area"
    );
    // B: mov eax, 0xDEADBEEF; movd xmm0, eax; int 0x80
    mem.copy_to(code as usize, &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x66, 0x0F, 0x6E, 0xC0, 0xCD, 0x80]);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    fx_switch(&mut slot); // B out, A back in
    assert_eq!(
        u32::from_le_bytes(slot.0[160..164].try_into().unwrap()),
        0xDEAD_BEEF,
        "thread B's XMM0 captured on the way out"
    );
    // A resumes: movd eax, xmm0; int 0x80 — the marker must have survived B.
    mem.copy_to(code as usize, &[0x66, 0x0F, 0x7E, 0xC0, 0xCD, 0x80]);
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    assert_eq!(
        regs().rax as u32,
        0x1122_3344,
        "thread A's XMM0 restored across the switch"
    );

    // ── The virtual-IF modes, on real hardware: DR0-3 via KVM_SET_GUEST_DEBUG.
    // Folded in here rather than as its own #[test] because the live context is
    // global (see this module's header). The TCG build runs the same source
    // against Unicorn code hooks — that is the parity proof.
    crate::vif_tests::proofs();
}
