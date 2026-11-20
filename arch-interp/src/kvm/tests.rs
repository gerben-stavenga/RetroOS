//! KVM-engine proofs: enter the guest for real (VM86 and flat PM), drive the
//! arch supervisor, demand paging, COW, and the shared monitor end-to-end on
//! hardware. Each test skips with a message when `/dev/kvm` is unavailable
//! (CI without nested virt), so the suite stays green everywhere.
//!
//! NOTE: these share the crate's global live context (`vcpu::REGS`) and the
//! phys memfd, so everything runs inside ONE #[test] (Rust runs tests on
//! separate threads; a second REGS user would race).

use arch_abi::eflags;
#[cfg(test)]
use crate::test_memory;

use arch_abi::{Memory as _, Arch as _};
use super::*;
use crate::space::RootPageTable;
use arch_abi::{GuestBytes, KernelEvent, Regs, USER_CS, USER_DS};

static INPUT: std::sync::Mutex<std::vec::Vec<(arch_abi::Irq, u64)>> = std::sync::Mutex::new(std::vec::Vec::new());
fn receive_input(event: arch_abi::Irq, timestamp: u64) { INPUT.lock().unwrap().push((event, timestamp)); }
fn drain_input(f: &mut dyn FnMut(arch_abi::Irq, u64)) {
    let events = core::mem::take(&mut *INPUT.lock().unwrap());
    for (event, timestamp) in events { f(event, timestamp); }
}

fn kvm_available() -> bool {
    kvm_ioctls::Kvm::new().is_ok()
}

/// Run until a non-Irq event, allowing unrelated wakeups to interleave.
fn run_to_event() -> KernelEvent {
    for _ in 0..10_000 {
        match execute(core::time::Duration::from_millis(100)) {
            KernelEvent::Irq => continue,
            ev => return ev,
        }
    }
    panic!("guest made no progress (10k Irq slices)");
}

fn set_regs(regs: Regs) {
    let base = if regs.mode() == arch_abi::UserMode::VM86 { u64::from(regs.code_seg()) << 4 } else { <crate::Interp as arch_abi::X86>::seg_base(regs.code_seg()) as u64 };
    crate::mmu_tests::executable(base + regs.frame.rip);
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
        crate::phys::init_test_ram();
    if !kvm_available() {
        assert!(
            std::env::var_os("RETRO_REQUIRE_KVM").is_none(),
            "RETRO_REQUIRE_KVM set but /dev/kvm is unavailable"
        );
        eprintln!("SKIP: /dev/kvm unavailable — KVM engine proofs not run");
        return;
    }
    crate::phys::init_test_ram();
    let mut mem = crate::backend::Interp;
    crate::backend::check_virtual_irq_frame(&mut mem);

    // ── VM86: `int 0x31` (the trapped DPMI stub vector) from real-mode code.
    // The INT is IOPL-sensitive at IOPL=1 → #GP → arch → shared monitor →
    // redirection bitmap traps 0x31 → SoftInt(0x31). Exercises: v86 entry
    // shape, demand-#PF on the first code fetch, the #GP monitor path.
    // 0xB8 0x34 0x12   mov ax, 0x1234
    // 0xCD 0x31        int 0x31
    mem.copy_to(0x7C00, &[0xB8, 0x34, 0x12, 0xCD, 0x31], crate::test_memory::input(5));
    let mut r = Regs::empty();
    r.set_cs32(0);
    r.set_ip32(0x7C00);
    r.set_ss32(0);
    r.set_sp32(0x7000);
    r.set_flags32(eflags::VM_FLAG | eflags::VIF_FLAG | 2);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x31) => {}
        ev => panic!("VM86 int 0x31: expected SoftInt(0x31), got {ev:?}"),
    }
    let r = regs();
    assert_eq!(r.rax as u16, 0x1234, "mov ax retired before the INT");
    assert_eq!(r.ip32(), 0x7C05, "monitor advanced IP past the INT");
    assert!(r.flags32() & eflags::VM_FLAG != 0, "still VM86 after the trap");

    // Absolute one-shot alarms must preempt guest-only computation. An
    // interruption is supplied by the host timer, not a deadline pre-check.
    crate::machine::install_input_sink(receive_input);
    mem.copy_to(0x7E00, &[0xeb, 0xfe], crate::test_memory::input(5));
    let mut spinning = r;
    spinning.set_ip32(0x7E00);
    set_regs(spinning);
    let end = mem.now() + 3_000_000;



    let mut wakes = 0;
    loop {
        assert!(matches!(execute(core::time::Duration::from_nanos(end.saturating_sub(mem.now()))), KernelEvent::Irq));
        wakes += 1;
        if mem.now() >= end { break; }
        assert!(wakes < 3, "an unrequested periodic heartbeat is still running");
    }
    assert!(mem.now() - end < 200_000_000, "one-shot alarm was excessively late");

    // A queued event is historical data, not an execution interruption.
    mem.copy_to(0x7E10, &[0xcd, 0x31], crate::test_memory::input(5));
    crate::machine::post_irq(arch_abi::Irq::Key(0x2e));
    // Let the host signal arrive while outside KVM_RUN.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let mut resumed = r;
    resumed.set_ip32(0x7E10);
    set_regs(resumed);
    assert!(matches!(execute(core::time::Duration::from_millis(100)), KernelEvent::SoftInt(0x31)));
    let mut count = 0;
    drain_input(&mut |event, _| {
        assert!(matches!(event, arch_abi::Irq::Key(0x2e)));
        count += 1;
    });
    assert_eq!(count, 1, "execution must leave queued data alone");

    // A fresh host interrupt while code is running still returns Irq.
    set_regs(spinning);
    let poster = std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        crate::machine::post_irq(arch_abi::Irq::Key(0xae));
    });
    assert!(matches!(execute(core::time::Duration::from_millis(100)), KernelEvent::Irq));
    poster.join().unwrap();
    set_regs(resumed);
    assert!(matches!(execute(core::time::Duration::from_millis(100)), KernelEvent::SoftInt(0x31)));
    drain_input(&mut |event, _| assert!(matches!(event, arch_abi::Irq::Key(0xae))));
    // Input must wake an idle CPU even with the timer completely disarmed.
    let poster = std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(3));
        crate::machine::post_irq(arch_abi::Irq::Key(0x1e));
    });
    mem.idle(core::time::Duration::from_millis(100));
    poster.join().unwrap();
    let mut input = false;
    drain_input(&mut |event, _| input |= matches!(event, arch_abi::Irq::Key(0x1e)));
    assert!(input, "input was lost during the idle transition");

    // Returning through a software interrupt must leave the one-shot usable by
    // the next execute. A shorter budget must replace it; a signal delivered
    // while the host is running must invalidate it before another guest entry.
    set_regs(spinning);
    assert!(matches!(execute(core::time::Duration::from_millis(1)), KernelEvent::Irq));
    set_regs(resumed);
    assert!(matches!(execute(core::time::Duration::from_secs(2)), KernelEvent::SoftInt(0x31)));
    let armed = setup::alarm_deadline().expect("software interrupt cancelled the alarm");
    set_regs(resumed);
    assert!(matches!(execute(core::time::Duration::from_secs(3)), KernelEvent::SoftInt(0x31)));
    assert_eq!(setup::alarm_deadline(), Some(armed), "execute replaced an earlier alarm");
    set_regs(resumed);
    assert!(matches!(execute(core::time::Duration::from_millis(100)), KernelEvent::SoftInt(0x31)));
    assert!(setup::alarm_deadline().is_some_and(|deadline| deadline < armed),
        "shorter execute budget did not bring the deadline forward");
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(setup::alarm_deadline(), None, "host-side expiration retained a stale alarm");
    set_regs(spinning);
    let started = mem.now();
    assert!(matches!(execute(core::time::Duration::from_millis(1)), KernelEvent::Irq));
    assert!(mem.now() - started < 200_000_000, "expired alarm prevented rearming");

    // A VM86 POPF with reserved bit 15 set must behave like a hardware
    // flags load, not feed an invalid VMCS to Intel KVM (DN's CPU probe).
    // mov ax,0x8202; push ax; popf; pushf; pop ax; int 0x31
    mem.copy_to(0x7D00, &[0xB8, 0x02, 0x82, 0x50, 0x9D,
                        0x9C, 0x58, 0xCD, 0x31], crate::test_memory::input(5));
    mem.copy_to(0x6FFE, &[0, 0], crate::test_memory::input(5)); // back the stack used by PUSH/POPF
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
    ], crate::test_memory::input(5));
    let mut probe = r;
    probe.set_ip32(0x7D20);
    set_regs(probe);
    let event = run_to_event();
    assert!(matches!(event, KernelEvent::SoftInt(0x31)), "D3X CPU probe: {event:?}");
    assert_eq!(regs().rax as u16, 0x4000, "NT must be writable in VM86");
    assert_eq!(regs().flags32() & eflags::NT_FLAG, 0, "probe restored NT");

    // Both IRET widths must normalize the stacked FLAGS before re-entry.
    // Return to 0100:6e10, then PUSHF/POP AX reads what the guest observes.
    for op32 in [false, true] {
        mem.copy_to(0x7E00, if op32 { &[0x66, 0xCF][..] } else { &[0xCF][..] }, crate::test_memory::input(5));
        mem.copy_to(0x7E10, &[0x9C, 0x58, 0xCD, 0x31], crate::test_memory::input(5));
        if op32 {
            mem.copy_to(0x6FF0, &[0x10, 0x6E, 0, 0, 0, 1, 0, 0, 2, 0x82, 0, 0], crate::test_memory::input(5));
        } else {
            mem.copy_to(0x6FF0, &[0x10, 0x6E, 0, 1, 2, 0x82], crate::test_memory::input(5));
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
    mem.copy_to(0x8C00, &[0xB8, 0x78, 0x56, 0xCD, 0x31], crate::test_memory::input(5));
    let first_page = arch_abi::UserPage::new(0x7000).unwrap();
    let second_page = arch_abi::UserPage::new(0x8000).unwrap();
    let first = arch_abi::mapping::read_mapping(&mut mem, first_page).unwrap();
    let second = arch_abi::mapping::read_mapping(&mut mem, second_page).unwrap();
    let arch_abi::page_entry::PageEntry::Writable(first_mapping) = first else { panic!("expected owned RAM") };
    let arch_abi::page_entry::Backing::Owned(frame) = first_mapping.backing else { panic!("expected owned RAM") };
    assert!(unsafe { test_memory::ownership().retain(frame.number()) });
    unsafe {
        arch_abi::mapping::replace_mapping(&mut mem, first_page, second, test_memory::input(5)).0.unwrap();
        arch_abi::mapping::replace_mapping(&mut mem, second_page, first, test_memory::input(5)).0.unwrap();
    }
    test_memory::free_phys_page(frame.number());
    let mut remapped = r;
    remapped.set_ip32(0x7C00);
    set_regs(remapped);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x31)));
    assert_eq!(regs().rax as u16, 0x5678, "execute the remapped frame, not a stale TLB entry");

    // ── Flat PM: a store to an unmapped page (demand-#PF resolved inside the
    // engine), then `int 0x80` → SoftInt(0x80). Exercises: CPL3 PM return through IRET, in-engine demand paging on a data write, DPL-3 gate INT.
    // 0xC7 0x05 <addr> <imm32>   mov dword [0x0030_0000], 0xDEADBEEF
    // 0xCD 0x80                  int 0x80
    let code: u32 = 0x0020_0000;
    let data: u32 = 0x0030_0000;
    let stack: u32 = 0x0028_0000;
    let mut prog = vec![0xC7, 0x05];
    prog.extend_from_slice(&data.to_le_bytes());
    prog.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    prog.extend_from_slice(&[0xCD, 0x80]);
    mem.copy_to(code as u64, &prog, crate::test_memory::input(5));
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
        mem.read::<u32>(data as u64),
        0xDEAD_BEEF,
        "the demand-faulted store landed in guest memory"
    );

    espfix_proof(&mut mem, code, data, stack, false);
    planar_device_proof(&mut mem, code, stack);

    // ── PM #GP path: `hlt` at CPL3 → #GP(0) → monitor → KernelEvent::Hlt.
    mem.copy_to(code as u64, &[0xF4], crate::test_memory::input(5));
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::Hlt => {}
        ev => panic!("PM hlt: expected Hlt, got {ev:?}"),
    }

    // ── COW: fork the space, write to a shared page in the child, verify the
    // parent's copy is untouched (the #PF → space_cow_fault path under KVM).
    mem.write::<u32>(data as u64, 0x1111_1111);
    let mut child = RootPageTable::empty();
    mem.user_fork(&mut child, test_memory::input(5));
    let parent = crate::backend::Interp.activate(child);
    // In the child: increment the shared dword, then int 0x80.
    // 0xFF 0x05 <addr>   inc dword [data]
    // 0xCD 0x80          int 0x80
    let mut prog = vec![0xFF, 0x05];
    prog.extend_from_slice(&data.to_le_bytes());
    prog.extend_from_slice(&[0xCD, 0x80]);
    let mut child_mem = crate::backend::Interp;
    child_mem.copy_to(code as u64, &prog, crate::test_memory::input(5));
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    match run_to_event() {
        KernelEvent::SoftInt(0x80) => {}
        ev => panic!("COW child: expected SoftInt(0x80), got {ev:?}"),
    }
    assert_eq!(child_mem.read::<u32>(data as u64), 0x1111_1112, "child sees its increment");
    crate::backend::Interp.activate(parent);
    set_regs(Regs::empty());
    assert_eq!(
        mem.read::<u32>(data as u64),
        0x1111_1111,
        "parent's page untouched by the child's COW write"
    );

    mem.copy_to(code as u64, &[0xe7, arch_abi::vm::EXIT_PORT as u8, 0xcd, 0x80], crate::test_memory::input(5));
    let mut handoff = Regs::empty();
    handoff.init_user_process(code, stack);
    handoff.rax = 0xdeadbeef;
    set_regs(handoff);
    assert!(matches!(run_to_event(), KernelEvent::Out { port: arch_abi::vm::EXIT_PORT, size: arch_abi::IoSize::Dword }));
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));

    // Port access is denied by the supervisor's TSS and decoded by the
    // shared monitor. The returned frame has already advanced past the OUT.
    let io_prog: &[u8] = &[0xB0, 0x5A, 0xE6, 0xE0, 0xE4, 0xE0, 0xCD, 0x80];
    {
        let label = "monitored port";
        mem.copy_to(code as u64, io_prog, crate::test_memory::input(5));
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

    // ── FPU switch: fx_switch swaps the vcpu's live x87/SSE state with a
    // thread save area (metal's switch_fx semantics). Thread A parks a
    // marker in XMM0; a switch to a clean thread B clobbers XMM0; switching
    // back must restore A's marker — through the XSAVE round-trip.
    // A: mov eax, 0x11223344; movd xmm0, eax; int 0x80
    mem.copy_to(code as u64, &[0xB8, 0x44, 0x33, 0x22, 0x11, 0x66, 0x0F, 0x6E, 0xC0, 0xCD, 0x80], crate::test_memory::input(5));
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    // Address-space activation must not exchange FPU or register state.
    // The XMM0 assertion below observes the marker across this round-trip.
    let before_activation = regs();
    let previous = mem.activate(RootPageTable::default());
    let mut empty = mem.activate(previous);
    mem.destroy_space(&mut empty);
    assert_eq!(regs().frame.rip, before_activation.frame.rip);
    assert_eq!(regs().rax, before_activation.rax);
    let mut slot = crate::machine::clean_fx_template();
    fx_switch(&mut slot); // A out (slot = A's state), clean B in
    assert_eq!(
        u32::from_le_bytes(slot.0[160..164].try_into().unwrap()),
        0x1122_3344,
        "outgoing thread's XMM0 captured into its save area"
    );
    // B: mov eax, 0xDEADBEEF; movd xmm0, eax; int 0x80
    mem.copy_to(code as u64, &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x66, 0x0F, 0x6E, 0xC0, 0xCD, 0x80], crate::test_memory::input(5));
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
    mem.copy_to(code as u64, &[0x66, 0x0F, 0x7E, 0xC0, 0xCD, 0x80], crate::test_memory::input(5));
    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    assert_eq!(
        regs().rax as u32,
        0x1122_3344,
        "thread A's XMM0 restored across the switch"
    );

    // TF must start after IRET, not while restoring registers in entry.asm.
    // Re-enter twice to verify one guest instruction per step, then clear TF.
    mem.copy_to(code as u64, &[0x40, 0x40, 0xcd, 0x80], crate::test_memory::input(5)); // inc eax; inc eax; int 80
    let mut stepped = r;
    stepped.set_ip32(code);
    stepped.rax = 10;
    stepped.set_forced_tf(true);
    stepped.project_tf();
    set_regs(stepped);
    for n in 1..=2 {
        assert!(matches!(run_to_event(), KernelEvent::DebugTrap));
        assert_eq!(regs().ip32(), code + n);
        assert_eq!(regs().rax, 10 + n as u64);
        assert_eq!(regs().code_seg(), USER_CS);
    }
    let mut unstepped = regs();
    unstepped.set_forced_tf(false);
    unstepped.project_tf();
    set_regs(unstepped);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));

    // Long-mode return must restore FS/GS bases and the full-width GPRs.
    let tls_code = 0x0050_0000;
    let fs_base = 0x0051_0000;
    let gs_base = 0x0052_0000;
    mem.copy_to(tls_code, &[
        0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov rax, fs:[0]
        0x65, 0x48, 0x8b, 0x1c, 0x25, 0, 0, 0, 0, // mov rbx, gs:[0]
        0x0f, 0x05,
    ], crate::test_memory::input(5));
    mem.copy_to(fs_base, &0x1234567887654321u64.to_le_bytes(), crate::test_memory::input(5));
    mem.copy_to(gs_base, &0xfedcba9876543210u64.to_le_bytes(), crate::test_memory::input(5));
    let mut tls = Regs::empty();
    tls.init_user_process_64(tls_code, stack as u64);
    tls.fs = fs_base;
    tls.gs = gs_base;
    tls.r15 = 0xabcdef0123456789;
    set_regs(tls);
    assert!(matches!(run_to_event(), KernelEvent::Syscall));
    assert_eq!(regs().rax, 0x1234567887654321);
    assert_eq!(regs().rbx, 0xfedcba9876543210);
    assert_eq!(regs().r15, tls.r15);
    assert_eq!((regs().fs, regs().gs), (fs_base, gs_base));

    // Full-width paging is performed inside arch, including kernel copies,
    // execution above 512 GiB, and COW after a fork.
    let high = (1u64 << 39) + 0x1234_0000;
    let zero = arch_abi::mapping::read_mapping(&mut mem, UserPage::new(0x7000_0000).unwrap()).unwrap();
    unsafe { mem.fill_mappings(UserPage::new(high).unwrap(), 2, zero, test_memory::input(8)).0.unwrap(); }
    mem.copy_to(high, &[0x48, 0xff, 0x07, 0x48, 0x8b, 0x07, 0x0f, 0x05], crate::test_memory::input(5)); // inc [rdi]; mov rax,[rdi]; syscall
    mem.write::<u64>(high + 4096, 41);
    let mut child = RootPageTable::empty();
    mem.user_fork(&mut child, test_memory::input(8));
    let parent = mem.activate(child);
    let mut high_regs = Regs::empty();
    high_regs.init_user_process_64(high, stack as u64);
    high_regs.rdi = high + 4096;
    set_regs(high_regs);
    assert!(matches!(run_to_event(), KernelEvent::Syscall));
    assert_eq!(regs().rax, 42);
    assert_eq!(mem.read::<u64>(high + 4096), 42);
    let mut child = mem.activate(parent);
    assert_eq!(mem.read::<u64>(high + 4096), 41);
    mem.destroy_space(&mut child);

    espfix_proof(&mut mem, code, data, stack, true);

    // A timer interrupt may switch 64-bit contexts only after KVM has
    // delivered any pending syscall #UD to the arch supervisor. Repeatedly switch
    // between distinct code addresses at both timer and syscall boundaries;
    // a stale queued exception at the new MOV/JMP must never escape as #UD.
    let entries = [0x0060_0000usize, 0x0060_1000];
    for &entry in &entries {
        // syscall; then spend time in guest computation before the next one.
        // The timer must interrupt KVM_RUN, not merely expire in host code.
        mem.copy_to((entry) as u64, &[0xb8, 24, 0, 0, 0, 0x0f, 0x05,
            0xb9, 0x40, 0x42, 0x0f, 0, 0xff, 0xc9, 0x75, 0xfc, 0xeb, 0xee], crate::test_memory::input(5));
    }
    let mut contexts = [Regs::empty(); 2];
    for (i, context) in contexts.iter_mut().enumerate() {
        context.init_user_process_64(entries[i] as u64, stack as u64);
    }
    // Expire the alarm during the shared return path. Supervisor register
    // state must never escape as a user context, even before the first IRET.
    let mut syscall = contexts[0];
    syscall.frame.rip = entries[0] as u64 + 5;
    syscall.rax = 24;
    set_regs(syscall);
    let early = execute(core::time::Duration::from_nanos(1));
    assert!(matches!(early, KernelEvent::Syscall | KernelEvent::Irq));
    assert_eq!(regs().code_seg(), arch_abi::USER_CS64);
    assert!(matches!(regs().frame.rip, ip if ip == entries[0] as u64 + 5 || ip == entries[0] as u64 + 7));
    let mut active = 0;
    let mut syscalls = 0;
    let mut alarms = 0;
    let start = std::time::Instant::now();
    set_regs(contexts[active]);
    while start.elapsed() < std::time::Duration::from_millis(100) {
        match execute(core::time::Duration::from_micros(100)) {
            KernelEvent::Irq => {
                alarms += 1;
            },
            KernelEvent::Syscall => { syscalls += 1; },
            event => panic!("64-bit context switch yielded {event:?}"),
        }
        contexts[active] = regs();
        active ^= 1;
        set_regs(contexts[active]);
    }
    assert!(syscalls > 100, "64-bit syscall contexts made progress");
    assert!(alarms > 10, "context switches exercised real alarm preemption");


}

/// The native entries execute inside the VM against the owner's exact pages.
fn planar_device_proof(mem: &mut crate::Interp, code: u32, stack: u32) {
    use arch_abi::X86;
    let storage = unsafe { libc::mmap(core::ptr::null_mut(), 65 * 4096,
        libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    assert_ne!(storage, libc::MAP_FAILED);
    let state = unsafe { &*storage.cast::<planar::Registers>() };
    let planes = unsafe { storage.cast::<u8>().add(4096) };
    state.enabled.set(1); state.profile_enabled.set(1);
    state.seq.set(4, 4); state.seq.set(2, 1); state.gc.set(8, 255); state.gc.set(6, 4);
    let aperture = UserPage::new(0xa0000).unwrap();
    let mut previous = [PageEntry::Absent; 16];
    mem.read_mappings(aperture, &mut previous).unwrap();
    unsafe { mem.fill_mappings(aperture, 16, PageEntry::Intercepted, test_memory::input(8)).0.unwrap(); }
    let binding = planar::Binding { registers: state, planes };
    // Two MOV stores separated by a sequencer mask change; then a VGA read.
    let program = [0xb0, 0x11, 0xa2, 0, 0, 0x0a, 0,
        0xba, 0xc4, 3, 0, 0, 0x66, 0xb8, 2, 2, 0x66, 0xef,
        0xb0, 0x22, 0xa2, 0, 0, 0x0a, 0, 0xa0, 0, 0, 0x0a, 0, 0xcd, 0x80];
    mem.copy_to(code as u64, &program, test_memory::input(5));
    let mut r = Regs::empty(); r.init_user_process(code, stack); set_regs(r);
    unsafe { mem.bind_planar(Some(binding)); }
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)), "VGA and port accesses stay in the supervisor");
    let report = state.profile.take();
    assert!(report.details[0][0] + report.details[1][0] >= 3);
    assert_eq!(regs().rax as u8, 0x11);
    assert_eq!(state.seq.get(2), 2);
    assert_eq!(state.seq_index.get(), 2);
    assert_eq!(state.latches.read(), [0x11, 0x22, 0, 0]);
    let vram = unsafe { planar::Memory::mapped(planes, 4 * 65536) };
    assert_eq!((vram.get(0), vram.get(1)), (Some(0x11), Some(0x22)));

    // Enter long mode, then run the same 32-bit program in compatibility
    // mode. Its native tail is now 64-bit; untouched GPR halves must survive.
    mem.copy_to(0x0061_0000, &[0x0f, 0x05], test_memory::input(5));
    let mut r = Regs::empty(); r.init_user_process_64(0x0061_0000, u64::from(stack)); set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::Syscall));
    state.seq.set(2, 1);
    let mut r = Regs::empty(); r.init_user_process(code, stack);
    r.rdi = 0xabcd_1234_5678_4321; r.r8 = 0xfeed_beef_2345_6789;
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    assert_eq!(regs().rdi, 0xabcd_1234_5678_4321);
    assert_eq!(regs().r8, 0xfeed_beef_2345_6789);
    assert_eq!(regs().rax as u8, 0x11);

    // VM86 takes the compact native tail, with segment selectors above it.
    // Use distinct segment bases so a mistaken protected-mode segment read
    // cannot accidentally pass. The handler remains installed across modes.
    mem.copy_to(0x92000, &[0xb0, 0x5a, 0xa2, 0x10, 0,
        0xba, 0xc4, 3, 0xb8, 2, 4, 0xef,
        0xb0, 0x6b, 0x26, 0xa2, 0x20, 0,
        0xb9, 4, 0, 0xf3, 0xa4, 0xcd, 0x31], test_memory::input(5));
    // REP reads plane zero (the default GC read map).
    for i in 0..4 { vram.put((0x30 + i) * 4, 0x70 + i as u8); }
    let mut r = Regs::empty();
    r.frame.cs = 0x9200; r.frame.ss = 0x800; r.frame.rsp = 0x1000;
    r.frame.rflags = u64::from(eflags::VM_FLAG | eflags::IF_FLAG | eflags::VIF_FLAG) | 2;
    r.ds = 0xa000; r.es = 0xa001; r.fs = 0x1234; r.gs = 0x5678;
    r.rsi = 0x30; r.rdi = 0x40;
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x31)));
    assert_eq!(vram.get(0x10 * 4 + 1), Some(0x5a));
    assert_eq!(vram.get(0x30 * 4 + 2), Some(0x6b));
    for i in 0..4 { assert_eq!(vram.get((0x50 + i) * 4 + 2), Some(0x70 + i as u8)); }
    assert_eq!((regs().rsi, regs().rdi, regs().rcx), (0x34, 0x44, 0));
    assert_eq!((regs().ds, regs().es, regs().fs, regs().gs), (0xa000, 0xa001, 0x1234, 0x5678));
    assert_eq!((regs().frame.ss, regs().frame.rsp), (0x800, 0x1000));
    state.seq.set(2, 2);

    // Ordinary kernel returns leave the handler installed. Device mode changes
    // are visible through that same register page without another binding call.
    state.enabled.set(0);
    let mut r = Regs::empty(); r.init_user_process(code, stack); set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::PageFault { addr: 0xa0000 }));
    state.enabled.set(1);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    state.profile.take();

    // VGA source faults first. The destination's next page still needs COW.
    mem.copy_to(code as u64, &[0xf3, 0xa5, 0xcd, 0x80], test_memory::input(5));
    let dest = 0x0040_0ff0;
    mem.copy_to(dest, &[0; 16], test_memory::input(5));
    let before = mem.supply_pages(arch_abi::page_supply::PageInput::new()).0;
    let mut r = Regs::empty(); r.init_user_process(code, stack);
    r.rsi = 0xa0000; r.rdi = dest; r.rcx = 32; set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::PageFault { addr: 0xa0000 }));
    assert_eq!(regs().rsi, 0xa0010);
    assert_eq!(regs().rdi, dest + 16);
    assert_eq!(regs().rcx, 28);
    assert_eq!(regs().frame.rip, code as u64);
    assert_eq!(mem.supply_pages(arch_abi::page_supply::PageInput::new()).0, before,
        "planar does not spend the guest fault reserve");
    mem.copy_to(dest + 16, &[0; 112], test_memory::input(5));
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    assert_eq!(regs().rcx, 0);
    assert_eq!(regs().rdi, dest + 128);
    // Complete instruction at a page end uses only its fetched page. A split
    // instruction takes the generic preflight before reading the next page.
    for start in [code + 4094, code + 4095] {
        mem.copy_to(u64::from(start), &[0x88, 0x07, 0xcd, 0x80], test_memory::input(5));
        let mut r = Regs::empty(); r.init_user_process(start, stack);
        r.rdi = 0xa0080; r.rax = 0x5e; set_regs(r);
        assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
        assert_eq!(vram.get(0x80 * 4 + 1), Some(0x5e));
    }
    // A debugged instruction must leave the device and registers untouched
    // until the kernel sees its page fault. Clearing TF then resumes normally.
    mem.copy_to(u64::from(code), &[0x88, 0x07, 0xcd, 0x80], test_memory::input(5));
    let mut r = Regs::empty(); r.init_user_process(code, stack);
    r.rdi = 0xa0090; r.rax = 0x73; r.frame.rflags |= u64::from(eflags::TF_FLAG); r.set_user_tf(true);
    let untouched = vram.get(0x90 * 4 + 1);
    set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::PageFault { addr: 0xa0090 }));
    assert_eq!(regs().frame.rip, u64::from(code));
    assert_eq!(vram.get(0x90 * 4 + 1), untouched);
    let mut r = regs(); r.frame.rflags &= !u64::from(eflags::TF_FLAG); r.set_user_tf(false); set_regs(r);
    assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
    assert_eq!(vram.get(0x90 * 4 + 1), Some(0x73));

    // An instruction fetch from the intercepted aperture is not a data
    // instruction to emulate, even if a planar handler is installed.
    let mut r = Regs::empty(); r.init_user_process(0xa0000, stack);
    // Deliberately do not use set_regs: that fixture marks a RAM code page
    // executable, whereas this proof must attempt an intercepted fetch.
    unsafe { (*(&raw mut crate::vcpu::REGS)).regs = r; }
    assert!(matches!(run_to_event(), KernelEvent::PageFault { addr: 0xa0000 }));
    assert_eq!(regs().frame.rip, 0xa0000);

    unsafe {
        mem.bind_planar(None);
        mem.replace_mappings(aperture, &previous, test_memory::input(8)).0.unwrap();
        assert_eq!(libc::munmap(storage, 65 * 4096), 0);
    }
}

/// Exercise the real two-instruction ring-1 return, in legacy and IA-32e mode.
fn espfix_proof(mem: &mut crate::Interp, code: u32, data: u32, stack: u32, long: bool) {
    fn descriptor(base: u32, access: u8) -> u64 {
        0xffff | (u64::from(base & 0xffff) << 16)
            | (u64::from((base >> 16) & 255) << 32)
            | (u64::from(access) << 40) | (u64::from(base >> 24) << 56)
    }
    let ldt = [0, descriptor(stack, 0xf3), descriptor(code, 0xfb)];
    mem.load_ldt(&ldt);
    for narrow_code in [false, true] {
        // PUSH/POP uses SP; MOV observes the whole ESP. Neither changes flags.
        let mut program = vec![0x50, 0x58];
        if narrow_code { program.push(0x66); }
        program.push(0x9c); // pushfd
        if narrow_code { program.extend_from_slice(&[0x66, 0x67]); }
        program.extend_from_slice(&[0x8f, 0x05]); // pop dword [data+4]
        program.extend_from_slice(&(data + 4).to_le_bytes());
        if narrow_code { program.extend_from_slice(&[0x66, 0x67]); }
        program.extend_from_slice(&[0x89, 0x25]); // mov [absolute address],esp
        program.extend_from_slice(&data.to_le_bytes());
        program.extend_from_slice(&[0xcd, 0x80]);
        mem.copy_to(u64::from(code), &program, crate::test_memory::input(5));
        let mut r = Regs::empty();
        r.init_user_process(if narrow_code { 0 } else { code }, 0xabcd_8000);
        r.frame.ss = 0x0f;
        if narrow_code { r.frame.cs = 0x17; }
        r.frame.rflags |= u64::from(eflags::DF_FLAG | eflags::CF_FLAG); // DF and CF must survive the intermediate IRET
        r.rax = 0x1234_5678; r.rbx = 0x2345_6789; r.rcx = 0x3456_789a;
        r.rdx = 0x4567_89ab; r.rsi = 0x5678_9abc; r.rdi = 0x6789_abcd;
        r.rbp = 0x789a_bcde;
        if long { r.r8 = 0x1234_5678_9abc_def0; r.r15 = 0xfedc_ba98_7654_3210; }
        mem.write::<u32>(u64::from(stack + 0x7ffc), 0);
        set_regs(r);
        assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)), "espfix long={long} code16={narrow_code}");
        let got = regs();
        assert_eq!(mem.read::<u32>(u64::from(data)), 0xabcd_8000, "live ESP high half");
        assert_eq!(got.frame.rsp, r.frame.rsp, "saved ESP high half");
        assert_eq!([got.rax, got.rbx, got.rcx, got.rdx, got.rsi, got.rdi, got.rbp],
            [r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp], "register restore");
        assert_eq!(got.frame.rflags & u64::from(eflags::DF_FLAG | eflags::CF_FLAG), u64::from(eflags::DF_FLAG | eflags::CF_FLAG), "application flags");
        assert_eq!(mem.read::<u32>(u64::from(data + 4)) & 0x3703, 0x1603,
            "live flags: IOPL=1, IF=1, TF=0, DF=1, CF=1");
        if long { assert_eq!([got.r8, got.r15], [r.r8, r.r15]); }
        // Replay a saved ring-1 continuation through the real exit path.
        // In particular, returning after POP ESP must restart it.
        for offset in [0, 1] {
            espfix_resume(r, offset, long);
            assert!(matches!(run_to_event(), KernelEvent::SoftInt(0x80)));
            assert_eq!(mem.read::<u32>(u64::from(data)), 0xabcd_8000);
            assert_eq!(regs().frame.rsp, r.frame.rsp);
        }
        let mut stepped = r;
        stepped.set_user_tf(true);
        stepped.project_tf();
        set_regs(stepped);
        assert!(matches!(run_to_event(), KernelEvent::DebugTrap));
        assert_eq!(regs().frame.rip, r.frame.rip + 1, "TF starts at the first app instruction");
        assert_eq!(regs().frame.rsp, r.frame.rsp - if narrow_code { 2 } else { 4 });
    }
    mem.load_ldt(&[]);
}

/// Resolve test breakpoints from the supervisor ELF, without a runtime ABI.
fn supervisor_symbol(name: &str) -> u64 {
    let elf = include_bytes!(env!("ARCH_SUPERVISOR_IMAGE"));
    let word = |i: usize| u32::from_le_bytes(elf[i..i + 4].try_into().unwrap()) as usize;
    let half = |i: usize| u16::from_le_bytes(elf[i..i + 2].try_into().unwrap()) as usize;
    let sections = word(32);
    let size = half(46);
    for i in 0..half(48) {
        let section = sections + i * size;
        if word(section + 4) != 2 { continue; } // SHT_SYMTAB
        let strings = word(sections + word(section + 24) * size + 16);
        for offset in (word(section + 16)..word(section + 16) + word(section + 20)).step_by(word(section + 36)) {
            let start = strings + word(offset);
            let end = start + elf[start..].iter().position(|&b| b == 0).unwrap();
            if &elf[start..end] == name.as_bytes() { return word(offset + 4) as u64; }
        }
    }
    panic!("missing supervisor symbol {name}");
}

fn espfix_resume(r: Regs, offset: u64, long: bool) {
    let ip = supervisor_symbol("espfix_return") + offset;
    setup::with(|cpu| {
        let mut debug = kvm_bindings::kvm_guest_debug::default();
        debug.control = kvm_bindings::KVM_GUESTDBG_ENABLE | kvm_bindings::KVM_GUESTDBG_USE_HW_BP;
        debug.arch.debugreg[0] = ip;
        debug.arch.debugreg[7] = 0x401;
        cpu.vcpu.set_guest_debug(&debug).unwrap();
        unsafe { (*cpu.message).operation = op::EXECUTE; (*cpu.message).regs = r; }
        loop {
            match cpu.vcpu.run().unwrap() {
                kvm_ioctls::VcpuExit::Debug(_) => break,
                kvm_ioctls::VcpuExit::IoOut(0xe9, bytes) => eprint!("{}", String::from_utf8_lossy(bytes)),
                exit => panic!("expected espfix breakpoint, got {exit:?}"),
            }
        }
        let live = cpu.vcpu.get_regs().unwrap();
        let segments = cpu.vcpu.get_sregs().unwrap();
        assert_eq!(live.rip, ip);
        assert_eq!(segments.cs.selector, 0x51);
        assert_eq!(segments.ss.selector, 0x49);
        assert_eq!(segments.ss.db, 0);
        assert_eq!(segments.efer & (1 << 10) != 0, long);
        assert_eq!(live.rflags & u64::from(eflags::VM_FLAG | eflags::NT_FLAG | eflags::IF_FLAG | eflags::TF_FLAG), 0);
        assert_eq!(live.rflags & u64::from(eflags::IOPL_MASK), 1 << eflags::IOPL_SHIFT);
        assert_eq!([live.rax, live.rbx, live.rcx, live.rdx, live.rsi, live.rdi, live.rbp],
            [r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp]);
        if offset == 1 { assert_eq!(live.rsp as u32, 0xabcd_0004); }
        // Save exactly the supervisor context an interrupt would preserve.
        let mut interrupted = r;
        interrupted.frame = arch_abi::Frame64 { rip: live.rip,
            cs: u64::from(segments.cs.selector), rflags: live.rflags,
            rsp: live.rsp, ss: u64::from(segments.ss.selector) };
        let physical = segments.ss.base as usize - vm::IMAGE_VIRTUAL + vm::IMAGE_PHYSICAL;
        let slot = unsafe { cpu.image.add(physical).cast::<[u32; 6]>() };
        let pending = unsafe { slot.read_unaligned() };
        cpu.vcpu.set_guest_debug(&kvm_bindings::kvm_guest_debug::default()).unwrap();
        super::run::until_return(cpu, false);
        let message = unsafe { &*cpu.message };
        assert!(matches!(KernelEvent::decode(message.result[0] as u32, message.result[1]), KernelEvent::SoftInt(0x80)));
        assert_eq!(unsafe { slot.read_unaligned() }, pending);
        // Submit the saved ring-1 frame as a return destination. Ordinary
        // guest setup is unnecessary: its code and slot are resident arch data.
        unsafe { (*(&raw mut crate::vcpu::REGS)).regs = interrupted; }
    });
}
