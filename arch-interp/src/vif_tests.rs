//! Virtual-IF proofs: the three `IfMode`s, driven end-to-end on whichever
//! engine this crate was built with.
//!
//! The contract they pin down is the one that used to be written three times —
//! once in `arch-metal/src/traps.rs`, once per hosted engine — and was three
//! different things:
//!
//! | vIOPL | mode     | POPF at CPL>IOPL   | what it costs                    |
//! |-------|----------|--------------------|----------------------------------|
//! | 1     | `Iopl1`  | ignored (spec)     | nothing: no window is even gated |
//! | 2     | `Repair` | honored            | steps the FIRST window, then arms |
//! |       |          |                    | that window's exit and runs free  |
//! | 3     | `Iopl3`  | honored            | steps EVERY window                |
//!
//! In protected mode a `POPF` at CPL > IOPL does not fault — it silently drops
//! the IF bit — so a client that re-enables interrupts that way is invisible
//! unless the host goes looking. That is what these three modes are: three
//! prices for looking. The guest below re-enables IF exactly that way, in a
//! loop, at one recurring site — so `Repair` gets to learn the site once and
//! then predict it, which is the whole point of it existing.
//!
//! Both engines run the same source. That is the parity check: any divergence
//! between the Unicorn code-hook breakpoints and KVM's real DR0-3 shows up as a
//! different number here.

use crate::sysdesc::VIF_FLAG;
use arch_abi::monitor;
use arch_abi::{GuestBytes, KernelEvent, Regs, USER_CS};

/// Guest: a critical section that leaves through the sloppy POPF, in a loop, so
/// the same CLI site opens `ITERS` windows.
///
///   loop:  pushf                  ; flags image with IF=1
///          cli                    ; #GP -> monitor: virtual IF 0, window opens
///          nop x NOPS             ; the window body (non-sensitive)
///          popf                   ; the sloppy re-enable: no fault at CPL>IOPL
///          dec ecx
///          jnz loop
///          int 0x80               ; ends the test
const NOPS: usize = 8;
const ITERS: u32 = 4;

fn program() -> Vec<u8> {
    let mut p = vec![0x9C, 0xFA]; // pushf; cli
    p.extend(core::iter::repeat_n(0x90, NOPS)); // nop x NOPS
    p.push(0x9D); // popf
    p.push(0x49); // dec ecx
    // jnz back to the top: rel8 counts from the byte after the branch.
    let body = 2 + NOPS + 1 + 1 + 2; // pushf+cli, nops, popf, dec, jnz
    p.extend_from_slice(&[0x75, (-(body as i32)) as u8]);
    p.extend_from_slice(&[0xCD, 0x80]); // int 0x80
    p
}

/// Run until a non-`Irq` event (the timer grid interleaves anywhere), bounded so
/// a wedged guest fails the test instead of hanging it.
fn run_to_event() -> KernelEvent {
    for _ in 0..2_000_000 {
        match crate::engine::execute() {
            KernelEvent::Irq => continue,
            ev => return ev,
        }
    }
    panic!("guest made no progress");
}

/// Run the loop above as a PM client whose virtual IOPL is `viopl`, and report
/// `(virtual IF at the end, monitor stats)`.
fn run_client(viopl: u32) -> (bool, (u32, u32, u32, u32, u32)) {
    let code: u32 = 0x0020_0000;
    let stack: u32 = 0x0028_0000;
    crate::backend::Interp.copy_to(code as usize, &program());

    // Each client is a fresh program as far as the monitor is concerned: the
    // learned exits are keyed by bare code address, and so are the stats.
    monitor::forget_if_windows();

    let mut r = Regs::empty();
    r.init_user_process(code, stack);
    r.rcx = ITERS as u64;
    // The virtual IOPL rides in the client's own flags (bits 12-13) — it is
    // per-thread interrupt-control state, exactly like VIF/VIP. This is the bit
    // the TCG engine used to squash to 1 on every exit, which silently made
    // every hosted client an `Iopl1` one.
    r.set_flags32((r.flags32() & !(3 << 12)) | (viopl << 12));
    unsafe { (*core::ptr::addr_of_mut!(crate::vcpu::REGS)).regs = r; }

    match run_to_event() {
        KernelEvent::SoftInt(0x80) => {}
        ev => panic!("vIOPL={viopl}: expected SoftInt(0x80) at the end of the loop, got {ev:?}"),
    }
    let r = unsafe { (*(&raw const crate::vcpu::REGS)).regs };
    assert_eq!(r.code_seg(), USER_CS, "still a flat PM client");
    assert_eq!(r.rcx as u32, 0, "the loop ran all {ITERS} iterations");
    (r.flags32() & VIF_FLAG != 0, monitor::vif_stats())
}

/// The three modes, on this engine.
pub(crate) fn proofs() {
    crate::mmu::init();

    // ── Iopl1 (vIOPL=1): spec-strict. DPMI 0.9 §2.13 lets a host ignore
    // POPF/IRET, so nothing is gated at all: no window is opened, nothing is
    // stepped, and the client's virtual IF stays off — it re-enables interrupts
    // through a door we are entitled not to watch. (A client that really needs
    // this is why `Repair` exists; that it HANGS here is the documented cost.)
    let (vif, (windows, predicted, bp_hits, steps, repairs)) = run_client(1);
    assert!(!vif, "Iopl1: POPF must not restore virtual IF");
    assert_eq!(
        (windows, predicted, bp_hits, steps, repairs),
        (0, 0, 0, 0, 0),
        "Iopl1: no window gated, nothing stepped, nothing armed"
    );

    // ── Iopl3 (vIOPL=3): the reference path. Every window is single-stepped,
    // so the POPF is always caught and virtual IF always comes back — at a #DB
    // per instruction. It never predicts, so it can never mispredict.
    let (vif, (windows, predicted, bp_hits, steps, repairs)) = run_client(3);
    assert!(vif, "Iopl3: POPF restores virtual IF");
    assert_eq!(windows, ITERS, "Iopl3: every CLI opens a window");
    assert_eq!(predicted, 0, "Iopl3 never predicts — that is what it is for");
    assert_eq!(bp_hits, 0, "Iopl3 arms no breakpoints");
    assert!(
        steps >= ITERS * NOPS as u32,
        "Iopl3 steps every instruction of every window: {steps} < {}",
        ITERS * NOPS as u32
    );
    assert_eq!(repairs, 0, "a stepped window cannot lose its exit");

    // ── Repair (vIOPL=2): Iopl3's answer at Iopl1's price. The first window is
    // stepped to LEARN where this site re-enables interrupts; that address is
    // then armed as an exit breakpoint and every later window runs FREE — the
    // breakpoint catches the POPF, the monitor emulates it, the window closes.
    //
    // This is the assertion that the hosted engines used to fail structurally:
    // neither implemented `set_exec_breakpoints`, so `arm()` returned false and
    // Repair silently degraded into Iopl3 — correct, but paying ~2500x on every
    // window forever, on a machine that had no way to tell you.
    let (vif, (windows, predicted, bp_hits, steps, repairs)) = run_client(2);
    assert!(vif, "Repair: POPF restores virtual IF");
    assert_eq!(windows, ITERS, "Repair: every CLI opens a window");
    assert_eq!(
        predicted,
        ITERS - 1,
        "Repair: the first window is stepped to learn the exit, the rest run free"
    );
    assert_eq!(
        bp_hits,
        ITERS - 1,
        "Repair: every predicted window is closed by its exit breakpoint"
    );
    assert!(
        steps <= NOPS as u32 + 4,
        "Repair steps the learning window ONLY: {steps} steps for one window of {NOPS}"
    );
    assert_eq!(repairs, 0, "the learned exit is the one the client really takes");
}

// One REGS-driving test per engine binary: the crate's live context
// (`vcpu::REGS`, the phys memfd) is global, and Rust runs #[test]s on separate
// threads. The KVM build folds these proofs into `kvm_engine_proofs` for the
// same reason (see kvm/tests.rs).
#[cfg(feature = "tcg")]
#[test]
fn tcg_virtual_if_proofs() {
    proofs();
}
