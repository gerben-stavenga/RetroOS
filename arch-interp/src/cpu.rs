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
    /// `INT n` / exception vector a hook stopped on (decided in `execute`).
    pending_intr: Option<u8>,
    /// Whether `pending_intr` was a software `int n` (true) or a CPU fault
    /// (false) — decoded from bit 8 of the patched intr-hook vector.
    pending_is_int: bool,
    /// CPU fault error code (e.g. the faulting selector for #GP/#NP) — decoded
    /// from bits 16..31 of the patched intr-hook vector.
    pending_err: u16,
    /// Guest pages currently mapped into Unicorn for the active space. Cleared
    /// (and the pages unmapped) on a context switch.
    mapped: BTreeSet<u64>,
    /// Whether the high scratch window (GDT/LDT/trampoline, [`SYS_BASE`]) is
    /// mapped into Unicorn yet — done once, lazily, on first PM-descriptor run.
    sys_mapped: bool,
}

thread_local! {
    /// The single software CPU. Built lazily on first `execute()`; persists
    /// (with its hooks) across slices and address spaces.
    static MACHINE: RefCell<Option<Unicorn<'static, Ctx>>> = const { RefCell::new(None) };
}

/// Real-mode `INT`/fault reflection done *in place* on the live Unicorn state:
/// push FLAGS/CS/IP, vector CS:IP through the IVT, clear IF/TF. Called from the
/// intr hook so `emu_start` runs straight through the handler (like TCG's
/// `do_interrupt`) instead of bouncing to the kernel per int — letting the batch
/// retire a full slice. Mirrors `monitor::sw_reflect_vm86_int`, but on `uc`.
fn reflect_vm86_inline<'a>(uc: &mut Unicorn<'a, Ctx>, vector: u8) {
    use RegisterX86 as R;
    let cs = uc.reg_read(R::CS).unwrap_or(0) as u16;
    let ip = uc.reg_read(R::EIP).unwrap_or(0) as u16;
    let flags = uc.reg_read(R::EFLAGS).unwrap_or(0) as u32;
    let ss = uc.reg_read(R::SS).unwrap_or(0) as u32;
    let mut sp = uc.reg_read(R::ESP).unwrap_or(0) as u16;
    // Guest memory (IVT, stack) goes through the software MMU, not `uc` — the IVT
    // page isn't mapped into Unicorn (the guest never touches it; we do).
    let m = crate::vcpu::mem();
    let base = ss << 4;
    for word in [flags as u16, cs, ip] {
        sp = sp.wrapping_sub(2);
        m.write::<u16>((base + sp as u32) as usize, word);
    }
    let new_ip = m.read::<u16>(vector as usize * 4);
    let new_cs = m.read::<u16>(vector as usize * 4 + 2);
    let _ = uc.reg_write(R::ESP, sp as u64);
    let _ = uc.reg_write(R::CS, new_cs as u64);
    let _ = uc.reg_write(R::EIP, new_ip as u64);
    let _ = uc.reg_write(R::EFLAGS, (flags & !0x300) as u64); // clear IF (0x200) + TF (0x100)
}

/// Build the Unicorn instance and install the event hooks. No memory is mapped
/// up front — pages are mapped lazily as the guest faults them in.
fn build() -> Unicorn<'static, Ctx> {
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, Ctx::default())
        .expect("unicorn init");

    // Software INT n and CPU exceptions both surface here. Our local Unicorn
    // patch encodes `exception_is_int` in bit 8 of `intno` (vectors are <= 0xFF),
    // so we record the vector and that bit; `execute` turns it into a clean
    // SoftInt (software int) vs Exception (CPU fault) event.
    uc.add_intr_hook(|uc, intno| {
        let vector = (intno & 0xFF) as u8;
        // Real-mode (VM86, PE=0) `INT n`/fault that the redirection bitmap does
        // not trap: reflect to the IVT *in place* and keep running, so the slice
        // runs through the handler like TCG does — only trapped vectors (0x31)
        // and the DPL=3 gates (3/4) bubble to the kernel. PM ints/faults always
        // bubble (decided by `execute`).
        if vector != 3 && vector != 4
            && uc.reg_read(RegisterX86::CR0).unwrap_or(1) & 1 == 0
            && !crate::desc::int_intercepted(vector)
        {
            reflect_vm86_inline(uc, vector);
            return; // no emu_stop → emu_start continues at the handler
        }
        let d = uc.get_data_mut();
        d.pending_intr = Some(vector);
        d.pending_is_int = intno & 0x100 != 0;
        d.pending_err = ((intno >> 16) & 0xFFFF) as u16;
        let _ = uc.emu_stop();
    })
    .expect("intr hook");

    // The CPU's interrupt check, run before every basic block — the analog of
    // QEMU's `cpu_handle_interrupt` before each TB. If the INTR line is asserted
    // (a pending vpic IRQ / host input) AND the guest can take it now (IF=1),
    // stop at this clean block boundary so the kernel's `deliver_pm_irq` injects
    // here. While the line is clear (the common case) this is just an atomic
    // load. The IF=0→1 case falls out for free: we skip while IF=0 and stop at
    // the first block after the guest re-enables interrupts.
    uc.add_block_hook(1, 0, |uc, _addr, size| {
        // Charge virtual time by the block's retired work here, not on full-slice
        // retirement — so it advances even in port-IN / int-heavy loops that
        // never complete a slice (e.g. DN's `in 0x3DA` retrace poll, whose VGA
        // phase is derived from this clock). ~3 bytes/instruction.
        crate::machine::advance_virtual_time((size as u64 / 3).max(1));
        if crate::machine::irq_line() {
            let flags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
            if flags & 0x200 != 0 {
                let _ = uc.emu_stop();
            }
        }
    })
    .expect("block hook");

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

/// Per-slice transition trace, gated by `RETRO_TRACE` (checked once). Logs each
/// run's entry/exit mode, CS:IP, SS:SP and the event that ended it — the lens
/// used to bring up VM86/PM execution on this backend.
fn trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_TRACE").is_some())
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
        // Service an off-thread VGA-screen snapshot request, and paint the live
        // terminal view if enabled (both read the active guest space here, where
        // it's valid — the CPU thread).
        crate::screendump::maybe_dump();
        crate::screendump::maybe_render_live();
        #[cfg(feature = "display")]
        crate::display::tick();
        let regs = unsafe { &mut (*(&raw mut vcpu::REGS)).regs };
        let mode = regs.mode();
        let begin = configure(uc, regs, mode);
        {
            let d = uc.get_data_mut();
            d.pending = None;
            d.pending_intr = None;
            d.pending_is_int = false;
            d.pending_err = 0;
        }

        if trace_on() {
            eprintln!("[run] mode={:?} cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ds={:#06x} flags={:#x}",
                mode, regs.code_seg(), regs.frame.rip, regs.frame.ss as u16, regs.frame.rsp,
                regs.ds as u16, regs.frame.rflags);
        }
        let run = uc.emu_start(begin, 0xFFFF_FFFF, 0, SLICE);
        store_regs(uc, regs, mode);
        if trace_on() {
            let intr = uc.get_data().pending_intr;
            let ev = uc.get_data().pending.is_some();
            eprintln!("   -> cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} intr={:?} ev={} run={:?}",
                regs.code_seg(), regs.frame.rip, regs.frame.ss as u16, regs.frame.rsp,
                intr, ev, run.is_ok());
        }

        if let Some(n) = uc.get_data_mut().pending_intr.take() {
            let is_int = uc.get_data().pending_is_int;
            if mode == UserMode::VM86 {
                // Non-trapped VM86 ints are reflected to the IVT in the intr hook
                // (run-through), so only trapped vectors (0x31) and the DPL=3
                // gates (3/4) reach here.
                return KernelEvent::SoftInt(n);
            }
            // Protected mode: the engine tells us directly whether this was a
            // software `int n` or a CPU fault (`exception_is_int`, surfaced by
            // our Unicorn patch). A fault becomes a typed Exception carrying the
            // CPU error code (the faulting selector for #NP/#GP — what a DPMI
            // host needs to demand-load the right overlay segment); a software
            // int (`int 0x21`/`0x11`/…) becomes a SoftInt. No vector heuristics,
            // no guest-opcode inspection.
            if is_int {
                return KernelEvent::SoftInt(n);
            }
            regs.err_code = uc.get_data().pending_err as u64;
            return KernelEvent::Exception(n);
        }
        if let Some(ev) = uc.get_data_mut().pending.take() {
            return ev;
        }
        return match run {
            // Virtual time is charged per basic block in the block hook (above),
            // so nothing to add here. A bare `Ok` is either a full-slice retire
            // or a block-hook IRQ stop — both just hand control to the kernel.
            Ok(()) => KernelEvent::Irq,
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

// ── High scratch window: descriptor tables + the ring-3 entry trampoline ─────
//
// To run a protected-mode client (Linux flat-32 *or* a 16/32-bit DPMI client)
// the software CPU must resolve segment selectors through real descriptor
// tables — a write to a segment register in PM makes Unicorn load base/limit/D
// from the GDT/LDT in *guest* memory (QEMU `helper_load_seg`). We reserve a
// window above the user VA range (the MMU never maps there) and place there:
//   * a small GDT mirroring the kernel's flat ring-0/ring-3 + BDA + TLS slots,
//   * the active LDT (copied from the kernel's table — DPMI descriptors live
//     there), pointed at by LDTR, and
//   * a one-byte `iretd` trampoline plus a ring-0 stack.
// CPL only becomes 3 by *returning* to a DPL-3 stack, so we can't just write
// SS=ring3 (a same-privilege load demands CPL==DPL already). Instead each PM
// entry resets to CPL 0 (a brief real-mode SS load), programs the tables, then
// `iretd`s through a CPL-0→3 frame — exactly how real kernels enter ring 3.
const SYS_BASE: u64 = 0xFFFE_0000;
const GDT_ADDR: u64 = SYS_BASE; // 256-byte GDT (32 entries)
const LDT_ADDR: u64 = SYS_BASE + 0x1000; // up to LDT_MAX_BYTES
const TRAMP_ADDR: u64 = SYS_BASE + 0x5000; // the `iretd` byte
const RING0_SP_TOP: u64 = SYS_BASE + 0x7000; // ring-0 stack top (frame just below)
const SYS_SIZE: usize = 0x8000;
const GDT_BYTES: usize = 32 * 8;
const LDT_MAX_BYTES: usize = 0x4000; // 2048 descriptors

// Flat ring-0 selectors the trampoline runs under (GDT indices 1 and 3, to
// match the kernel's `descriptors.rs` KERNEL_CS=0x08 / KERNEL_DS=0x18 layout).
const KERNEL_CS: u16 = 0x08;
const KERNEL_DS: u16 = 0x18;
/// LDT selector value (GDT slot 12 on metal). We program LDTR's base directly,
/// so the selector is cosmetic, but keep the kernel's value for fidelity.
const LDT_SEL: u16 = 0x60;

/// Pack a legacy 8-byte segment descriptor. `flags4` is the high nibble
/// (G, D/B, L, AVL); `access` is the type/DPL/P byte.
fn gdt_desc(base: u32, limit: u32, access: u8, flags4: u8) -> u64 {
    (limit as u64 & 0xFFFF)
        | ((base as u64 & 0xFFFF) << 16)
        | (((base as u64 >> 16) & 0xFF) << 32)
        | ((access as u64) << 40)
        | (((limit as u64 >> 16) & 0xF) << 48)
        | ((flags4 as u64 & 0xF) << 52)
        | (((base as u64 >> 24) & 0xFF) << 56)
}

/// Write a memory-management register (GDTR/LDTR) via the `uc_x86_mmr` layout
/// `{ selector:u16, _pad, base:u64@8, limit:u32@16, flags:u32@20 }` (24 bytes).
fn set_mmr(uc: &Unicorn<'static, Ctx>, reg: RegisterX86, selector: u16, base: u64, limit: u32, flags: u32) {
    let mut buf = [0u8; 24];
    buf[0..2].copy_from_slice(&selector.to_le_bytes());
    buf[8..16].copy_from_slice(&base.to_le_bytes());
    buf[16..20].copy_from_slice(&limit.to_le_bytes());
    buf[20..24].copy_from_slice(&flags.to_le_bytes());
    let _ = uc.reg_write_long(reg, &buf);
}

/// Map the scratch window (once) and seed the `iretd` trampoline byte.
fn ensure_sys_mapped(uc: &mut Unicorn<'static, Ctx>) {
    if uc.get_data().sys_mapped {
        return;
    }
    let _ = uc.mem_map(SYS_BASE, SYS_SIZE as u64, Prot::ALL);
    let _ = uc.mem_write(TRAMP_ADDR, &[0xCF]); // IRETD (32-bit ring-0 CS)
    uc.get_data_mut().sys_mapped = true;
}

/// Refresh the GDT (flat ring-0/ring-3 + BDA alias + present TLS slots) and the
/// LDT (the kernel's active table) in the scratch window, and point GDTR/LDTR
/// at them.
fn write_tables(uc: &mut Unicorn<'static, Ctx>) {
    use arch_abi::{USER_CS, USER_DS};
    let mut gdt = [0u64; 32];
    gdt[(KERNEL_CS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0x9A, 0xC); // ring-0 code32
    gdt[(KERNEL_DS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0x92, 0xC); // ring-0 data32
    gdt[(USER_CS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0xFA, 0xC); // ring-3 code32 (Linux)
    gdt[(USER_DS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0xF2, 0xC); // ring-3 data32 (Linux)
    gdt[8] = gdt_desc(0x400, 0xFFFF, 0xF2, 0x4); // 0x40: BIOS Data Area alias (DPMI compat)
    crate::desc::for_each_tls(|idx, base, _limit| {
        if idx < 32 {
            gdt[idx] = gdt_desc(base, 0xF_FFFF, 0xF2, 0xC);
        }
    });
    let mut gbytes = [0u8; GDT_BYTES];
    for (i, d) in gdt.iter().enumerate() {
        gbytes[i * 8..i * 8 + 8].copy_from_slice(&d.to_le_bytes());
    }
    let _ = uc.mem_write(GDT_ADDR, &gbytes);
    set_mmr(uc, RegisterX86::GDTR, 0, GDT_ADDR, (GDT_BYTES - 1) as u32, 0);

    let ldt = crate::desc::ldt_raw();
    let n = ldt.len().min(LDT_MAX_BYTES / 8);
    let mut lbytes = std::vec![0u8; n * 8];
    for (i, d) in ldt.iter().take(n).enumerate() {
        lbytes[i * 8..i * 8 + 8].copy_from_slice(&d.to_le_bytes());
    }
    if !lbytes.is_empty() {
        let _ = uc.mem_write(LDT_ADDR, &lbytes);
    }
    let ldt_limit = if lbytes.is_empty() { 0 } else { (lbytes.len() - 1) as u32 };
    set_mmr(uc, RegisterX86::LDTR, LDT_SEL, LDT_ADDR, ldt_limit, 0x8200);
}

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

    match mode {
        UserMode::VM86 => {
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
        }
        UserMode::Mode32 => configure_pm(uc, r),
        UserMode::Mode64 => {
            // 64-bit guests aren't interpreted yet (the core runs in 32-bit
            // mode); fall back to the old flat-32 setup so the existing 64-bit
            // ELF smoke paths don't regress.
            w(uc, RegisterX86::CR0, cr0 | 1);
            w(uc, RegisterX86::ESP, r.frame.rsp);
            w(uc, RegisterX86::EIP, r.frame.rip);
            w(uc, RegisterX86::EFLAGS, r.frame.rflags);
            r.frame.rip
        }
    }
}

/// Protected-mode (32-bit) entry through real descriptor tables. Handles both
/// Linux flat-32 (CS=USER_CS) and 16/32-bit DPMI clients (LDT selectors) the
/// same way: program GDT/LDT, then `iretd` into the CPL-3 client.
fn configure_pm(uc: &mut Unicorn<'static, Ctx>, r: &Regs) -> u64 {
    ensure_sys_mapped(uc);
    let w = |uc: &mut Unicorn<'static, Ctx>, reg, v: u64| { let _ = uc.reg_write(reg, v); };

    // 1. Force CPL 0: a real-mode SS load (PE=0) sets the cached DPL to 0, then
    //    re-enable PE. From CPL 0 we can load the ring-0 trampoline segments and
    //    the DPL-3 client data segments alike.
    let cr0 = uc.reg_read(RegisterX86::CR0).unwrap_or(1);
    w(uc, RegisterX86::CR0, cr0 & !1);
    w(uc, RegisterX86::SS, 0);
    w(uc, RegisterX86::CR0, cr0 | 1);

    // 2. Program the descriptor tables, then load the client's data segments
    //    (DPL 3 loads fine at CPL 0; they survive the iret since DPL == new CPL).
    write_tables(uc);
    w(uc, RegisterX86::DS, r.ds & 0xFFFF);
    w(uc, RegisterX86::ES, r.es & 0xFFFF);
    w(uc, RegisterX86::FS, r.fs & 0xFFFF);
    w(uc, RegisterX86::GS, r.gs & 0xFFFF);

    // 3. Build the inter-privilege iret frame (EIP, CS, EFLAGS, ESP, SS) and run
    //    the trampoline under the flat ring-0 selectors.
    let flags = (r.flags32() & !(VM_FLAG as u32)) | 2;
    let frame = [r.ip32(), r.code_seg() as u32, flags, r.sp32(), r.frame.ss as u32];
    let mut bytes = [0u8; 20];
    for (i, v) in frame.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let frame_addr = RING0_SP_TOP - bytes.len() as u64;
    let _ = uc.mem_write(frame_addr, &bytes);

    w(uc, RegisterX86::SS, KERNEL_DS as u64);
    w(uc, RegisterX86::ESP, frame_addr);
    w(uc, RegisterX86::CS, KERNEL_CS as u64);
    w(uc, RegisterX86::EFLAGS, 2);
    w(uc, RegisterX86::EIP, TRAMP_ADDR);
    TRAMP_ADDR
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

    match mode {
        UserMode::VM86 => {
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
        }
        UserMode::Mode32 => {
            // PM client: a far jump / mov may have reloaded any selector — read
            // them all back so the kernel sees the live segment state.
            let cs = rd(uc, RegisterX86::CS) as u16;
            let ss = rd(uc, RegisterX86::SS) as u16;
            r.set_cs32(cs as u32);
            r.set_ss32(ss as u32);
            r.ds = rd(uc, RegisterX86::DS);
            r.es = rd(uc, RegisterX86::ES);
            r.fs = rd(uc, RegisterX86::FS);
            r.gs = rd(uc, RegisterX86::GS);
            r.frame.rflags = rd(uc, RegisterX86::EFLAGS);
            // On a 16-bit stack/code segment only SP / IP are meaningful. The
            // ring-0 → ring-3 `iretd` trampoline leaves the high half of ESP
            // (and possibly EIP) holding stale bits from the trampoline's own
            // 32-bit stack, since x86 keeps the upper bits when SS/CS are 16-bit.
            // The kernel treats these as flat offsets, so normalize them here.
            if !crate::desc::seg_is_32(ss) {
                r.frame.rsp &= 0xFFFF;
            }
            if !crate::desc::seg_is_32(cs) {
                r.frame.rip &= 0xFFFF;
            }
        }
        UserMode::Mode64 => {
            r.frame.rflags = rd(uc, RegisterX86::EFLAGS);
        }
    }
}
