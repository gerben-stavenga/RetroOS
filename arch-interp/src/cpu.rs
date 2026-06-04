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
use arch_abi::{IoSize, KernelEvent, Regs};
use core::cell::RefCell;
use core::ffi::c_void;
use std::collections::BTreeSet;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

const PAGE: u64 = 4096;

/// Instructions per run-slice — also the timer-IRQ granularity (deterministic).
const SLICE: usize = 500;

/// Per-run hook scratch.
#[derive(Default)]
struct Ctx {
    /// Event a hook stopped the slice with (if any).
    pending: Option<KernelEvent>,
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

    // Software INT n → SoftInt(n).
    uc.add_intr_hook(|uc, intno| {
        uc.get_data_mut().pending = Some(KernelEvent::SoftInt(intno as u8));
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
pub fn execute() -> KernelEvent {
    io_with(|uc| {
        let regs = unsafe { &mut (*(&raw mut vcpu::REGS)).regs };
        load_regs(uc, regs);
        uc.get_data_mut().pending = None;

        let pc = regs.frame.rip;
        let run = uc.emu_start(pc, 0xFFFF_FFFF, 0, SLICE);

        store_regs(uc, regs);

        if let Some(ev) = uc.get_data_mut().pending.take() {
            return ev;
        }
        match run {
            Ok(()) => KernelEvent::Irq, // whole slice retired → timer tick
            Err(_) => KernelEvent::Fault,
        }
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

// Register sync. M2/M3 sync the general-purpose file, instruction pointer, and
// flags; the guest runs flat (segment bases 0), so selector/GDT sync is M4.

fn load_regs(uc: &mut Unicorn<'static, Ctx>, r: &Regs) {
    let _ = uc.reg_write(RegisterX86::EAX, r.rax);
    let _ = uc.reg_write(RegisterX86::EBX, r.rbx);
    let _ = uc.reg_write(RegisterX86::ECX, r.rcx);
    let _ = uc.reg_write(RegisterX86::EDX, r.rdx);
    let _ = uc.reg_write(RegisterX86::ESI, r.rsi);
    let _ = uc.reg_write(RegisterX86::EDI, r.rdi);
    let _ = uc.reg_write(RegisterX86::EBP, r.rbp);
    let _ = uc.reg_write(RegisterX86::ESP, r.frame.rsp);
    let _ = uc.reg_write(RegisterX86::EIP, r.frame.rip);
    let _ = uc.reg_write(RegisterX86::EFLAGS, r.frame.rflags);
}

fn store_regs(uc: &mut Unicorn<'static, Ctx>, r: &mut Regs) {
    r.rax = uc.reg_read(RegisterX86::EAX).unwrap_or(0);
    r.rbx = uc.reg_read(RegisterX86::EBX).unwrap_or(0);
    r.rcx = uc.reg_read(RegisterX86::ECX).unwrap_or(0);
    r.rdx = uc.reg_read(RegisterX86::EDX).unwrap_or(0);
    r.rsi = uc.reg_read(RegisterX86::ESI).unwrap_or(0);
    r.rdi = uc.reg_read(RegisterX86::EDI).unwrap_or(0);
    r.rbp = uc.reg_read(RegisterX86::EBP).unwrap_or(0);
    r.frame.rsp = uc.reg_read(RegisterX86::ESP).unwrap_or(0);
    r.frame.rip = uc.reg_read(RegisterX86::EIP).unwrap_or(0);
    r.frame.rflags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
}
