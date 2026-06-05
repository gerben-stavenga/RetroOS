//! The software x86 core: a persistent Unicorn instance the kernel drives one
//! run-slice at a time via `do_arch_execute`.
//!
//! Design:
//! * The kernel's global `REGS` (a `Vcpu`) is the source of truth for register
//!   state. Each `execute()` loads `REGS` into Unicorn, runs a slice, then
//!   stores Unicorn's registers back into `REGS`.
//! * Guest memory is the software MMU (`mmu.rs`): a reserved, demand-committed
//!   host VA window per address space. Unicorn maps pages of the *active* space
//!   lazily — the first access to a page faults into the mem hook, which asks
//!   the MMU to demand-commit it and maps that host page into Unicorn by
//!   pointer, so guest execution and `arch::mem()` share the same bytes. On a
//!   context switch the active space's lazily-mapped pages are dropped, so the
//!   incoming space re-faults its own pages in.
//! * A run ends at the first sensitive event (software `INT`, port `IN`/`OUT`,
//!   an illegal access → `PageFault`) or after `SLICE` instructions retire
//!   (a deterministic timer tick → `Irq`).

use crate::{mmu, vcpu};
use arch_abi::{IoSize, KernelEvent, Regs, UserMode};
use core::cell::RefCell;
use core::ffi::c_void;
use std::collections::BTreeSet;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

const PAGE: u64 = 4096;

/// Instructions per run-slice — also the timer-IRQ granularity (deterministic).
const SLICE: usize = 100_000;

/// Per-run hook scratch.
#[derive(Default)]
struct Ctx {
    /// Event a hook stopped the slice with (if any).
    pending: Option<KernelEvent>,
    /// Raw `INT n` / exception vector a hook stopped on (decided in `execute`).
    pending_intr: Option<u32>,
    /// Guest pages currently mapped into Unicorn for the active space. Cleared
    /// (and the pages unmapped) on a context switch.
    mapped: BTreeSet<u64>,
}

thread_local! {
    /// The single software CPU. Built lazily on first `execute()`; persists
    /// (with its hooks) across slices and address spaces.
    static MACHINE: RefCell<Option<Unicorn<'static, Ctx>>> = const { RefCell::new(None) };
}

/// Build the Unicorn instance and install the event hooks. No memory is mapped
/// up front — pages are mapped lazily as the guest faults them in.
fn build() -> Unicorn<'static, Ctx> {
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, Ctx::default())
        .expect("unicorn init");

    // Software INT n (CPU exceptions surface here too) — record the raw vector;
    // `execute` decides VM86 reflect-to-IVT vs. bubble to the kernel.
    uc.add_intr_hook(|uc, intno| {
        uc.get_data_mut().pending_intr = Some(intno);
        let _ = uc.emu_stop();
    })
    .expect("intr hook");

    // Port OUT → Out event; the value is in EAX (synced back to REGS).
    uc.add_insn_out_hook(|uc, port, size, _val| {
        uc.get_data_mut().pending = Some(KernelEvent::Out { port: port as u16, size: io_size(size) });
        let _ = uc.emu_stop();
    })
    .expect("out hook");

    // Port IN → In event. The dummy 0 is overwritten by the kernel's EAX.
    uc.add_insn_in_hook(|uc, port, size| {
        uc.get_data_mut().pending = Some(KernelEvent::In { port: port as u16, size: io_size(size) });
        let _ = uc.emu_stop();
        0
    })
    .expect("in hook");

    // Access to an unmapped page → ask the MMU to demand-commit it, map that
    // host page into Unicorn, and retry. An illegal address bubbles a fault.
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX, |uc, _t: MemType, addr, _sz, _v| {
        let page = addr & !(PAGE - 1);
        match mmu::demand(addr as usize) {
            Some(writable) => {
                let prot = if writable { Prot::ALL } else { Prot::READ | Prot::EXEC };
                let host = unsafe { mmu::active_base().add(page as usize) };
                let ok = unsafe { uc.mem_map_ptr(page, PAGE, prot, host as *mut c_void).is_ok() };
                if ok {
                    uc.get_data_mut().mapped.insert(page);
                }
                ok // retry if we mapped it
            }
            None => {
                uc.get_data_mut().pending = Some(KernelEvent::PageFault { addr: addr as u32 });
                let _ = uc.emu_stop();
                false
            }
        }
    })
    .expect("unmapped hook");

    // Write/exec against a present-but-protected page (e.g. a read-only .text
    // page). COW lands in M4; for now this is a genuine fault.
    uc.add_mem_hook(HookType::MEM_PROT, 0, u64::MAX, |uc, _t: MemType, addr, _sz, _v| {
        uc.get_data_mut().pending = Some(KernelEvent::PageFault { addr: addr as u32 });
        let _ = uc.emu_stop();
        false
    })
    .expect("prot hook");

    uc
}

fn io_size(bytes: usize) -> IoSize {
    match bytes {
        1 => IoSize::Byte,
        2 => IoSize::Word,
        _ => IoSize::Dword,
    }
}

fn io_with<R>(f: impl FnOnce(&mut Unicorn<'static, Ctx>) -> R) -> R {
    MACHINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        f(slot.get_or_insert_with(build))
    })
}

/// Run the current Vcpu (`REGS`) for one slice and return the next event.
///
/// Two execution modes share one Unicorn instance: 32-bit flat protected mode
/// (Linux) and 16-bit real mode (VM86/DOS). The mode is read from `REGS` each
/// slice; segment registers and `CR0.PE` are configured to match. VM86 `INT n`
/// that the redirection bitmap does NOT intercept is reflected to the guest's
/// real-mode IVT here and execution continues — only trapped vectors (and the
/// DPL=3 gates 3/4) bubble to the kernel.
pub fn execute() -> KernelEvent {
    io_with(|uc| loop {
        let regs = unsafe { &mut (*(&raw mut vcpu::REGS)).regs };
        let mode = regs.mode();
        let begin = configure(uc, regs, mode);
        {
            let d = uc.get_data_mut();
            d.pending = None;
            d.pending_intr = None;
        }

        let run = uc.emu_start(begin, 0xFFFF_FFFF, 0, SLICE);
        store_regs(uc, regs, mode);

        if let Some(intno) = uc.get_data_mut().pending_intr.take() {
            let n = intno as u8;
            if mode == UserMode::VM86 && n != 3 && n != 4 && !crate::desc::int_intercepted(n) {
                // Not a trap vector: reflect to the guest's real-mode IVT and
                // keep running (an IVT stub will `int 0x31` if it needs us).
                unsafe { crate::monitor::sw_reflect_vm86_int(regs, n) };
                continue;
            }
            return KernelEvent::SoftInt(n);
        }
        if let Some(ev) = uc.get_data_mut().pending.take() {
            return ev;
        }
        return match run {
            Ok(()) => KernelEvent::Irq, // whole slice retired → timer tick
            Err(_) => KernelEvent::Fault,
        };
    })
}

/// Drop `count` pages at `vpage` from Unicorn's active mapping so a later access
/// re-faults them with the MMU's new state. Called after any arch call that
/// mutates the active space's mappings.
pub fn invalidate_uc(vpage: usize, count: usize) {
    io_with(|uc| {
        for p in vpage..vpage + count {
            let base = (p as u64) * PAGE;
            if uc.get_data_mut().mapped.remove(&base) {
                let _ = uc.mem_unmap(base, PAGE);
            }
        }
    });
}

/// Drop the entire active-space mapping from Unicorn (on a context switch); the
/// incoming space re-faults its pages in lazily.
pub fn flush_uc() {
    io_with(|uc| {
        let pages: Vec<u64> = uc.get_data().mapped.iter().copied().collect();
        for base in pages {
            let _ = uc.mem_unmap(base, PAGE);
        }
        uc.get_data_mut().mapped.clear();
    });
}

const VM_FLAG: u64 = 1 << 17;
const IOPL_MASK: u64 = 3 << 12;

/// Configure Unicorn for `mode`, load `REGS`, and return the linear start PC.
fn configure(uc: &mut Unicorn<'static, Ctx>, r: &Regs, mode: UserMode) -> u64 {
    let cr0 = uc.reg_read(RegisterX86::CR0).unwrap_or(1);
    let w = |uc: &mut Unicorn<'static, Ctx>, reg, v: u64| { let _ = uc.reg_write(reg, v); };

    w(uc, RegisterX86::EAX, r.rax);
    w(uc, RegisterX86::EBX, r.rbx);
    w(uc, RegisterX86::ECX, r.rcx);
    w(uc, RegisterX86::EDX, r.rdx);
    w(uc, RegisterX86::ESI, r.rsi);
    w(uc, RegisterX86::EDI, r.rdi);
    w(uc, RegisterX86::EBP, r.rbp);

    if mode == UserMode::VM86 {
        // Real mode: PE=0, segment*16 addressing, 16-bit operands. (We model
        // VM86 as real mode — same seg<<4 semantics — rather than PM+VME.)
        w(uc, RegisterX86::CR0, cr0 & !1);
        w(uc, RegisterX86::CS, r.code_seg() as u64);
        w(uc, RegisterX86::DS, r.ds & 0xFFFF);
        w(uc, RegisterX86::ES, r.es & 0xFFFF);
        w(uc, RegisterX86::SS, r.stack_seg() as u64);
        w(uc, RegisterX86::FS, r.fs & 0xFFFF);
        w(uc, RegisterX86::GS, r.gs & 0xFFFF);
        w(uc, RegisterX86::ESP, r.sp32() as u64 & 0xFFFF);
        w(uc, RegisterX86::EIP, r.ip32() as u64 & 0xFFFF);
        // Drop VM (real mode has no VM bit); keep the rest, force reserved bit 1.
        w(uc, RegisterX86::EFLAGS, (r.flags() & !VM_FLAG) | 2);
        // `begin` is the EIP offset — Unicorn adds the CS base (CS<<4) itself.
        r.ip32() as u64 & 0xFFFF
    } else {
        // Protected-mode flat 32-bit (Linux): PE=1, flat segments (Unicorn's
        // base-0 default — we don't sync selectors), 32-bit.
        w(uc, RegisterX86::CR0, cr0 | 1);
        w(uc, RegisterX86::ESP, r.frame.rsp);
        w(uc, RegisterX86::EIP, r.frame.rip);
        w(uc, RegisterX86::EFLAGS, r.frame.rflags);
        r.frame.rip
    }
}

fn store_regs(uc: &mut Unicorn<'static, Ctx>, r: &mut Regs, mode: UserMode) {
    let rd = |uc: &mut Unicorn<'static, Ctx>, reg| uc.reg_read(reg).unwrap_or(0);
    r.rax = rd(uc, RegisterX86::EAX);
    r.rbx = rd(uc, RegisterX86::EBX);
    r.rcx = rd(uc, RegisterX86::ECX);
    r.rdx = rd(uc, RegisterX86::EDX);
    r.rsi = rd(uc, RegisterX86::ESI);
    r.rdi = rd(uc, RegisterX86::EDI);
    r.rbp = rd(uc, RegisterX86::EBP);
    r.frame.rsp = rd(uc, RegisterX86::ESP);
    r.frame.rip = rd(uc, RegisterX86::EIP);

    if mode == UserMode::VM86 {
        // Segments may have changed (mov/pop); read them back.
        r.set_cs32(rd(uc, RegisterX86::CS) as u32);
        r.set_ss32(rd(uc, RegisterX86::SS) as u32);
        r.ds = rd(uc, RegisterX86::DS);
        r.es = rd(uc, RegisterX86::ES);
        r.fs = rd(uc, RegisterX86::FS);
        r.gs = rd(uc, RegisterX86::GS);
        // Re-assert VM86 in the saved flags so `regs.mode()` stays VM86 for the
        // kernel (we ran in real mode, which carries no VM bit).
        r.frame.rflags = rd(uc, RegisterX86::EFLAGS) | VM_FLAG | IOPL_MASK;
    } else {
        r.frame.rflags = rd(uc, RegisterX86::EFLAGS);
    }
}
