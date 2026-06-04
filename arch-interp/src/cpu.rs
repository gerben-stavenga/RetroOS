//! The software x86 core: a persistent Unicorn instance the kernel drives one
//! run-slice at a time via `do_arch_execute`.
//!
//! Design:
//! * The kernel's global `REGS` (a `Vcpu`) is the source of truth for register
//!   state. Each `execute()` loads `REGS` into Unicorn, runs a slice, then
//!   stores Unicorn's registers back into `REGS`.
//! * Guest RAM is the interpreter's `GUEST_RAM` buffer, mapped *by pointer*
//!   into Unicorn (`mem_map_ptr`). So guest execution and the kernel's
//!   `arch::mem()` touch the very same bytes — one source of truth, no copying.
//! * A run ends at the first sensitive event (software `INT`, port `IN`/`OUT`)
//!   or after `SLICE` instructions retire (a deterministic timer tick → `Irq`).
//!   The hooks stash the event; `execute` returns it as the canonical
//!   `KernelEvent` the kernel event loop already understands.
//!
//! Milestone 2 runs a flat 32-bit guest over a single mapped region; the
//! demand-paged software MMU and segmentation come in M3/M4.

use crate::vcpu;
use arch_abi::{IoSize, KernelEvent, Regs};
use core::cell::RefCell;
use core::ffi::c_void;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

/// Instructions per run-slice — also the timer-IRQ granularity (deterministic).
const SLICE: usize = 500;

/// Per-run hook scratch: the event a hook stopped the slice with (if any).
#[derive(Default)]
struct Ctx {
    pending: Option<KernelEvent>,
}

thread_local! {
    /// The single software CPU. Built lazily on first `execute()` once guest
    /// RAM exists; persists (with its memory mapping + hooks) across slices.
    static MACHINE: RefCell<Option<Unicorn<'static, Ctx>>> = const { RefCell::new(None) };
}

/// Build the Unicorn instance: map the shared guest RAM and install the event
/// hooks. Called once.
fn build() -> Unicorn<'static, Ctx> {
    let (ram, len) = vcpu::guest_ram();
    assert!(!ram.is_null(), "guest RAM not initialized before execute()");

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, Ctx::default())
        .expect("unicorn init");

    // Share the kernel's guest-RAM buffer with the software CPU (no copy).
    unsafe {
        uc.mem_map_ptr(0, len as u64, Prot::ALL, ram as *mut c_void)
            .expect("map guest RAM");
    }

    // Software INT n → SoftInt(n). (Flat 32-bit guest: every INT surfaces;
    // VM86 redirection / exception splitting is M4.)
    uc.add_intr_hook(|uc, intno| {
        uc.get_data_mut().pending = Some(KernelEvent::SoftInt(intno as u8));
        let _ = uc.emu_stop();
    })
    .expect("intr hook");

    // Port OUT → Out event; the value is already in EAX (synced back to REGS),
    // matching how the metal monitor surfaces it.
    uc.add_insn_out_hook(|uc, port, size, _val| {
        uc.get_data_mut().pending = Some(KernelEvent::Out { port: port as u16, size: io_size(size) });
        let _ = uc.emu_stop();
    })
    .expect("out hook");

    // Port IN → In event. The hook must return a value for the in-flight
    // instruction; the kernel overwrites EAX with the real value before resume,
    // so the dummy 0 here is immediately discarded.
    uc.add_insn_in_hook(|uc, port, size| {
        uc.get_data_mut().pending = Some(KernelEvent::In { port: port as u16, size: io_size(size) });
        let _ = uc.emu_stop();
        0
    })
    .expect("in hook");

    // Access outside the mapped region → page fault (CR2 = faulting address).
    // With the flat M2 mapping this only fires for genuinely-bad accesses; the
    // demand-paging retry path arrives with the software MMU (M3).
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX, |uc, _t: MemType, addr, _sz, _v| {
        uc.get_data_mut().pending = Some(KernelEvent::PageFault { addr: addr as u32 });
        let _ = uc.emu_stop();
        false // do not retry — surface the fault
    })
    .expect("mem hook");

    uc
}

fn io_size(bytes: usize) -> IoSize {
    match bytes {
        1 => IoSize::Byte,
        2 => IoSize::Word,
        _ => IoSize::Dword,
    }
}

/// Run the current Vcpu (`REGS`) for one slice and return the next event.
pub fn execute() -> KernelEvent {
    MACHINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let uc = slot.get_or_insert_with(build);

        // Kernel REGS → software CPU.
        let regs = unsafe { &mut (*(&raw mut vcpu::REGS)).regs };
        load_regs(uc, regs);
        uc.get_data_mut().pending = None;

        let pc = regs.frame.rip;
        let run = uc.emu_start(pc, 0xFFFF_FFFF, 0, SLICE);

        // Software CPU → kernel REGS.
        store_regs(uc, regs);

        if let Some(ev) = uc.get_data_mut().pending.take() {
            return ev;
        }
        match run {
            // Whole slice retired with no event → deterministic timer tick.
            Ok(()) => KernelEvent::Irq,
            Err(_) => KernelEvent::Fault,
        }
    })
}

// Register sync. M2 syncs the general-purpose file, instruction pointer, and
// flags; the guest runs flat (segment bases 0), so selector/GDT sync is left
// for M4. EAX..EFLAGS are 32-bit here; the upper halves of `Regs` stay 0.

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
