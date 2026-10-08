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
use arch_abi::{GuestBytes, KernelEvent, Regs, USER_CS, USER_DS};

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

    // A VM86 POPF with reserved bit 15 set must behave like a hardware
    // flags load, not feed an invalid VMCS to Intel KVM (DN's CPU probe).
    // mov ax,0x8202; push ax; popf; pushf; pop ax; int 0x31
    mem.copy_to(0x7D00, &[0xB8, 0x02, 0x82, 0x50, 0x9D,
                        0x9C, 0x58, 0xCD, 0x31]);
    mem.copy_to(0x6FFE, &[0, 0]); // back the stack used by PUSH/POPF
    let mut probe = r;
    probe.set_ip32(0x7D00);
    set_regs(probe);
    let event = run_to_event();
    assert!(matches!(event, KernelEvent::SoftInt(0x31)), "reserved flags probe: {event:?}");
    assert_eq!(regs().rax as u16 & 0x8202, 0x0202);
    assert_eq!(regs().ip32(), 0x7D09);

    // D3X detects a 386 by toggling NT with POPF and reading it with PUSHF.
    // Both instructions trap in VM86, so NT must survive backend re-entry
    // between them. Restore the original flags before returning to DOS.
    mem.copy_to(0x7D20, &[
        0x9C, 0x59,             // pushf; pop cx
        0x89, 0xC8,             // mov ax,cx
        0x35, 0x00, 0x40,       // xor ax,0x4000
        0x50, 0x9D,             // push ax; popf
        0x9C, 0x58,             // pushf; pop ax
        0x51, 0x9D,             // push cx; popf
        0x31, 0xC8,             // xor ax,cx
        0xCD, 0x31,
    ]);
    let mut probe = r;
    probe.set_ip32(0x7D20);
    set_regs(probe);
    let event = run_to_event();
    assert!(matches!(event, KernelEvent::SoftInt(0x31)), "D3X CPU probe: {event:?}");
    assert_eq!(regs().rax as u16, 0x4000, "NT must be writable in VM86");
    assert_eq!(regs().flags32() & 0x4000, 0, "probe restored NT");

    // Both IRET widths must normalize the stacked FLAGS before re-entry.
    // Return to 0100:6e10, then PUSHF/POP AX reads what the guest observes.
    for op32 in [false, true] {
        mem.copy_to(0x7E00, if op32 { &[0x66, 0xCF][..] } else { &[0xCF][..] });
        mem.copy_to(0x7E10, &[0x9C, 0x58, 0xCD, 0x31]);
        if op32 {
            mem.copy_to(0x6FF0, &[0x10, 0x6E, 0, 0, 0, 1, 0, 0, 2, 0x82, 0, 0]);
        } else {
            mem.copy_to(0x6FF0, &[0x10, 0x6E, 0, 1, 2, 0x82]);
        }
        let mut probe = r;
        probe.set_ip32(0x7E00);
        probe.set_sp32(0x6FF0);
        set_regs(probe);
        let event = run_to_event();
        assert!(matches!(event, KernelEvent::SoftInt(0x31)), "IRET op32={op32}: {event:?}");
        assert_eq!(regs().rax as u16 & 0x8202, 0x0202);
        assert_eq!(regs().code_seg(), 0x100);
        assert_eq!(regs().ip32(), 0x6E14);
        assert_eq!(regs().sp32(), if op32 { 0x6FFC } else { 0x6FF6 });
    }

    // A host page-table edit at an unchanged CR3 must invalidate instruction
    // fetches too. Keep both frames alive and exchange their mappings so the
    // allocator cannot accidentally reuse the original physical page.
    mem.copy_to(0x8C00, &[0xB8, 0x78, 0x56, 0xCD, 0x31]);
    crate::mmu::swap_entries(7, 8, 1);
    let mut remapped = r;
    remapped.set_ip32(0x7C00);
    set_regs(remapped);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x31)));
    assert_eq!(regs().rax as u16, 0x5678, "execute the remapped frame, not a stale TLB entry");

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

    // A timer interrupt may switch 64-bit contexts only after KVM has
    // delivered any pending syscall #UD to the trap shim. Repeatedly switch
    // between distinct code addresses at both timer and syscall boundaries;
    // a stale queued exception at the new MOV/JMP must never escape as #UD.
    let entries = [0x0060_0000usize, 0x0060_1000];
    for &entry in &entries {
        mem.copy_to(entry, &[0xb8, 24, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7]);
    }
    let mut contexts = [Regs::empty(); 2];
    for (i, context) in contexts.iter_mut().enumerate() {
        context.init_user_process_64(entries[i] as u64, stack as u64);
    }
    let mut active = 0;
    let mut syscalls = 0;
    let start = std::time::Instant::now();
    set_regs(contexts[active]);
    while start.elapsed() < std::time::Duration::from_millis(100) {
        match execute() {
            KernelEvent::Irq => {},
            KernelEvent::Syscall => { syscalls += 1; },
            event => panic!("64-bit context switch yielded {event:?}"),
        }
        contexts[active] = regs();
        active ^= 1;
        set_regs(contexts[active]);
    }
    assert!(syscalls > 100, "64-bit syscall contexts made progress");

}
