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

use crate::sysdesc::{
    ensure_sys_window, if_to_vif, sys_phys, sys_ptr, vif_to_if, write_tables, GDT_ADDR, GDT_BYTES,
    IF_FLAG, IOPL_MASK, KERNEL_CS, KERNEL_DS, LDT_ADDR, LDT_SEL, NT_FLAG, RING0_SP_TOP, SYS_BASE,
    SYS_SIZE, TF_FLAG, TRAMP_ADDR, VIF_FLAG, VM_FLAG,
};
use crate::vcpu;
use arch_abi::monitor::MonitorResult;
use arch_abi::{IoSize, KernelEvent, Regs, UserMode};
use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

/// Instructions between forced returns to the kernel — the timer-IRQ delivery
/// grid. A trap returns before this is spent and the *remainder* carries over
/// ([`BUDGET`]); only a clean run to the boundary resets it. So IRQ0 lands on a
/// fixed cumulative-instruction grid regardless of how the guest's I/O chopped
/// the run up — like real hardware where `IN`/`INT` don't restart the PIT. Must
/// be <= the shortest timer period a guest programs (Doom's 140 Hz ~= 14k instr).
const IRQ_PERIOD: usize = 2_000;

thread_local! {
    /// Instructions left until the next forced kernel return (IRQ0 grid point):
    /// decremented by every run, carried across traps, reset at the loop top once
    /// a run reaches the boundary with no trap pending.
    static BUDGET: Cell<usize> = const { Cell::new(IRQ_PERIOD) };
}

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
    /// CR2 captured at the FIRST page fault of the slice. With CR0.PG=1 and no
    /// usable guest IDT, a #PF QEMU can't vector escalates to #DF whose own
    /// (faulting) delivery clobbers CR2 — so we snapshot it when the first fault
    /// fires, before the escalation, rather than reading it back afterwards.
    pending_cr2: u32,
    /// Virtual-time accounting for the in-flight `emu_start`. The block hook
    /// accumulates retired work into `slice_instr`; `stopped` records whether a
    /// hook cut the slice short. A slice that runs to its instruction budget
    /// retires the whole budget (the block hook undercounts a chained-TB loop —
    /// it fires per TB entry, not per iteration), so on a full retire we charge
    /// the budget; on an early stop we charge the accumulated work.
    slice_instr: u64,
    stopped: bool,
    /// Virtual-IF watch: set while a PM client runs with its virtual IF off
    /// (TF stepping armed). The intr hook uses it to keep single-stepping
    /// INSIDE one `emu_start` — re-arming TF and continuing per #DB — and
    /// only stops the slice when the next opcode is one of the five
    /// IF-touching instructions `step_virtual_if` must emulate. Without this,
    /// every stepped instruction pays a full slice exit/re-entry (~25µs), and
    /// audio ISRs that legitimately run long VIF=0 stretches (Duke3D's mixer)
    /// crawl two orders of magnitude below the virtual CPU's speed.
    vif_watch: Option<VifWatch>,
}

#[derive(Clone, Copy)]
struct VifWatch {
    cs: u16,
    cs_base: u32,
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

/// Build the Unicorn instance and install the event hooks. Guest physical RAM is
/// mapped as ONE region (the `phys` memfd); the CPU runs CR0.PG=1 with our page
/// tables in that RAM, so a TLB miss is a softmmu walk, not a per-page region
/// creation. Demand paging and faults surface as #PF (vector 14), handled in
/// `execute`.
fn build() -> Unicorn<'static, Ctx> {
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, Ctx::default())
        .expect("unicorn init");

    // The single guest-physical region: [0, PHYS_SIZE) backed by the memfd view.
    // With paging on, unicorn walks our tables and indexes here.
    unsafe {
        uc.mem_map_ptr(
            0,
            crate::phys::PHYS_SIZE as u64,
            Prot::ALL,
            crate::phys::region_base() as *mut c_void,
        )
        .expect("map guest-physical region");
    }
    // Allocate + map the GDT/LDT/iretd-trampoline window into every space.
    ensure_sys_window();

    // Software INT n and CPU exceptions both surface here. Our local Unicorn
    // patch encodes `exception_is_int` in bit 8 of `intno` (vectors are <= 0xFF),
    // so we record the vector and that bit; `execute` turns it into a clean
    // SoftInt (software int) vs Exception (CPU fault) / demand-#PF event.
    uc.add_intr_hook(|uc, intno| {
        let vector = (intno & 0xFF) as u8;
        let is_int = intno & 0x100 != 0;
        // Virtual-IF stepping fast path: a #DB from the armed TF while the PM
        // client's virtual IF is off. Peek the NEXT opcode; if it is not one
        // of the five IF-touching instructions (PUSHF/POPF/IRET/CLI/STI),
        // re-arm TF and continue INSIDE this `emu_start` — the whole stepped
        // stretch then costs one hook callback per instruction instead of a
        // full slice exit/re-entry. Falls through (and stops) for sensitive
        // opcodes, a CS change, or an unmapped code page — the slice loop
        // routes those to `step_virtual_if` exactly as before.
        if vector == 1 && !is_int {
            if let Some(w) = uc.get_data().vif_watch {
                use RegisterX86 as R;
                if uc.reg_read(R::CS).unwrap_or(0) as u16 == w.cs {
                    let eip = uc.reg_read(R::EIP).unwrap_or(0) as u32;
                    let pd = crate::paging::active_pd();
                    let mut lin = w.cs_base.wrapping_add(eip);
                    let mut op = None;
                    for _ in 0..8 {
                        let Some(pa) = crate::paging::translate(pd, lin) else { break };
                        let b = unsafe { *(crate::phys::region_base() as *const u8).add(pa as usize) };
                        // Legacy prefixes (operand/address size, lock, rep, seg overrides).
                        if matches!(b, 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
                                     | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65) {
                            lin = lin.wrapping_add(1);
                            continue;
                        }
                        op = Some(b);
                        break;
                    }
                    if matches!(op, Some(b) if !matches!(b, 0x9C | 0x9D | 0xCF | 0xFA | 0xFB)) {
                        let fl = uc.reg_read(R::EFLAGS).unwrap_or(0);
                        let _ = uc.reg_write(R::EFLAGS, fl | 0x100); // re-arm TF
                        return; // no emu_stop → continue stepping in place
                    }
                }
            }
        }
        // A page fault is the paging backend's own business: demand-commit or
        // genuine SEGV is decided in `execute` (it needs CR2 + the active page
        // tables). It surfaces as #PF (vector 14) when unicorn can report it, or
        // — because we run the guest with no usable IDT — escalated to #DF
        // (vector 8, error code 0) when unicorn tried and failed to vector the
        // #PF through the (empty) guest IDT. Treat both as the underlying fault
        // so the interp owns paging, exactly as the old PG=0 MEM_UNMAPPED path
        // did (the guest's own IDT must never see our page-table faults).
        if (vector == 14 || vector == 8) && !is_int {
            // Keep the FIRST fault's vector + CR2: a #PF (14) that immediately
            // escalates to #DF (8) calls this hook twice in one instruction, and
            // the escalation's CR2 is garbage. The first call wins.
            if uc.get_data().pending_intr.is_none() {
                let cr2 = uc.reg_read(RegisterX86::CR2).unwrap_or(0) as u32;
                let d = uc.get_data_mut();
                d.pending_intr = Some(vector);
                d.pending_is_int = false;
                d.pending_err = ((intno >> 16) & 0xFFFF) as u16;
                d.pending_cr2 = cr2;
            }
            uc.get_data_mut().stopped = true;
            let _ = uc.emu_stop();
            return;
        }
        // Genuine VM86 CPU exception the redirection bitmap does not trap (e.g.
        // #DE, #UD): reflect to the IVT *in place* and keep running, so the slice
        // runs through the program's own real-mode handler like TCG does.
        //
        // At IOPL=1 the IOPL-sensitive instructions — `INT n` included — raise
        // #GP (vector 13), NOT a direct software interrupt, so they no longer
        // arrive here as vector n: the shared monitor decodes the #GP and does
        // the IVT reflect (or bubbles SoftInt for trapped/DPL=3 vectors). Vector
        // 13 must therefore bubble, never reflect (reflecting it would vector
        // through IVT[0Dh] — a guest disk/UMB handler — instead of the monitor).
        // #PF (14/8) is excluded above (the paging backend's). PM faults bubble.
        let _ = is_int;
        let in_vm86 = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0) & VM_FLAG != 0;
        if vector != 3 && vector != 4 && vector != 13
            && in_vm86
            && !crate::desc::int_intercepted(vector)
        {
            reflect_vm86_inline(uc, vector);
            return; // no emu_stop → emu_start continues at the handler
        }
        let d = uc.get_data_mut();
        d.pending_intr = Some(vector);
        d.pending_is_int = is_int;
        d.pending_err = ((intno >> 16) & 0xFFFF) as u16;
        d.stopped = true;
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
        // Accumulate retired work (~3 bytes/instruction) for this slice. This
        // undercounts a tight chained-TB loop (the hook fires on TB entry, not
        // per iteration), so the *full-retire* charge in `run_slice` uses the
        // instruction budget instead; this accumulator is the time source only
        // for early stops (port-IN / int-heavy loops like DN's `in 0x3DA`
        // retrace poll, whose VGA phase is derived from this clock).
        uc.get_data_mut().slice_instr += (size as u64 / 3).max(1);
        if crate::machine::irq_line() {
            let flags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
            if flags & 0x200 != 0 {
                uc.get_data_mut().stopped = true;
                let _ = uc.emu_stop();
            }
        }
    })
    .expect("block hook");

    // Port OUT → Out event; the value is in EAX (synced back to REGS).
    uc.add_insn_out_hook(|uc, port, size, _val| {
        let d = uc.get_data_mut();
        d.pending = Some(KernelEvent::Out { port: port as u16, size: io_size(size) });
        d.stopped = true;
        let _ = uc.emu_stop();
    })
    .expect("out hook");

    // Port IN → In event. The dummy 0 is overwritten by the kernel's EAX.
    uc.add_insn_in_hook(|uc, port, size| {
        let d = uc.get_data_mut();
        d.pending = Some(KernelEvent::In { port: port as u16, size: io_size(size) });
        d.stopped = true;
        let _ = uc.emu_stop();
        0
    })
    .expect("in hook");

    // A guest *physical* address outside [0, PHYS_SIZE) — i.e. a page table that
    // points at a non-existent frame, or a bad CR3. That is a hard fault (the
    // demand/permission faults are virtual #PFs handled via the intr hook), so
    // surface the faulting *virtual* address from CR2 and stop.
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX, |uc, _t: MemType, _addr, _sz, _v| {
        let cr2 = uc.reg_read(RegisterX86::CR2).unwrap_or(0) as u32;
        let d = uc.get_data_mut();
        d.pending = Some(KernelEvent::PageFault { addr: cr2 });
        d.stopped = true;
        let _ = uc.emu_stop();
        false
    })
    .expect("unmapped hook");

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
        // The single `&mut Vcpu` for this iteration — the one unsafe here is
        // dereferencing the `static mut REGS`; everything downstream (register
        // access via `Deref<Target=Regs>`, guest memory via `GuestBytes`, the
        // monitor calls) is a safe reborrow of it.
        let vcpu = unsafe { &mut *(&raw mut vcpu::REGS) };
        let mode = vcpu.mode();
        // Virtual-IF stepping: while a PM client has its virtual IF (VIF) off,
        // emulate the leading IF-touching opcodes in software so we only ever
        // hand unicorn a non-sensitive instruction (which `configure` then
        // TF-single-steps).
        if mode == UserMode::Mode32 && vcpu.flags32() & VIF_FLAG == 0 {
            // A sensitive op decoded during stepping (e.g. IRET popping CS=0)
            // bubbles as an Event — surface it rather than re-entering.
            if let MonitorResult::Event(ev) = arch_abi::monitor::step_virtual_if(&mut crate::backend::Interp, &mut vcpu.regs) {
                return ev;
            }
        }
        // Roll to the next IRQ0 grid period once the last was fully spent; a trap
        // carries the remainder over so the grid stays fixed in cumulative
        // instructions (the kernel pumps the PIT on every return regardless).
        if budget_spent() {
            BUDGET.with(|b| b.set(IRQ_PERIOD));
        }
        let begin = configure(uc, vcpu, mode);
        {
            let d = uc.get_data_mut();
            d.pending = None;
            d.pending_intr = None;
            d.pending_is_int = false;
            d.pending_err = 0;
            d.pending_cr2 = 0;
        }

        if trace_on() {
            eprintln!("[run] mode={:?} cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ds={:#06x} flags={:#x}",
                mode, vcpu.code_seg(), vcpu.frame.rip, vcpu.frame.ss as u16, vcpu.frame.rsp,
                vcpu.ds as u16, vcpu.frame.rflags);
        }
        let mut run = run_slice(uc, begin, usize::MAX);
        // Resolve interp-internal stops without bubbling to the kernel:
        //  * Demand #PF (vector 14): the faulting VA is absent — commit a fresh
        //    frame, flush the TLB (CR3 rewrite), and re-run at the faulting EIP.
        //    A present-page fault (RO write) or illegal VA bubbles as PageFault.
        //  * Trampoline retire: if the slice budget expired with EIP still inside
        //    the CPL-0 iretd scratch window (the block hook counts it too), ring-0
        //    mid-switch state must NOT surface as user vcpu — the kernel would
        //    deliver IRQs onto it and corrupt the client (duke3d/raptor DOS/4GW
        //    wild-jump SEGVs; DN exec-window ffbf panics). Step it out first.
        for _ in 0..256 {
            let d = uc.get_data();
            if matches!(d.pending_intr, Some(14) | Some(8)) && !d.pending_is_int {
                let cr2 = d.pending_cr2;
                // Absent VA → demand-commit a fresh frame; present VA → a write to
                // a read-only page, which is a COW page to privatise (else genuine).
                let resolved = if crate::paging::space_translate(cr2).is_none() {
                    crate::paging::space_demand(cr2)
                } else {
                    crate::paging::space_cow_fault(cr2)
                };
                if resolved {
                    flush_tlb(uc);
                    {
                        let d = uc.get_data_mut();
                        d.pending_intr = None;
                        d.pending_is_int = false;
                        d.pending_err = 0;
                        d.pending_cr2 = 0;
                    }
                    let eip = uc.reg_read(RegisterX86::EIP).unwrap_or(0);
                    run = run_slice(uc, eip, usize::MAX);
                    continue;
                }
                break; // genuine fault — handled below as PageFault
            }
            let eip = uc.reg_read(RegisterX86::EIP).unwrap_or(0);
            if uc.get_data().pending.is_some()
                || uc.get_data().pending_intr.is_some()
                || !(SYS_BASE..SYS_BASE + SYS_SIZE as u64).contains(&eip)
            {
                break;
            }
            run = run_slice(uc, eip, 1);
        }
        store_regs(uc, vcpu, mode);
        // A page fault that demand-paging did not resolve is a genuine SEGV: the
        // kernel signals the thread. Carry CR2 + the #PF error code.
        if matches!(uc.get_data().pending_intr, Some(14) | Some(8)) && !uc.get_data().pending_is_int {
            let cr2 = uc.get_data().pending_cr2;
            vcpu.err_code = uc.get_data().pending_err as u64;
            uc.get_data_mut().pending_intr = None;
            return KernelEvent::PageFault { addr: cr2 };
        }
        if trace_on() {
            let intr = uc.get_data().pending_intr;
            let ev = uc.get_data().pending.is_some();
            eprintln!("   -> cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} intr={:?} ev={} run={:?}",
                vcpu.code_seg(), vcpu.frame.rip, vcpu.frame.ss as u16, vcpu.frame.rsp,
                intr, ev, run.is_ok());
        }

        if let Some(n) = uc.get_data_mut().pending_intr.take() {
            let is_int = uc.get_data().pending_is_int;
            // #DB single-step trap from the virtual-IF stepping (configure armed
            // TF while the PM client's IF is off): the one non-sensitive
            // instruction retired; loop back so `step_virtual_if` re-checks.
            if n == 1 && !is_int {
                // A single-stepped port `in`/`out` raises the I/O hook AND the
                // #DB on the SAME instruction. The instruction already retired,
                // so the I/O event must be delivered — not dropped by this
                // re-step `continue` (the loop top clears `pending`). Losing it
                // silently swallowed a PM IRQ handler's `out 0x20` EOI, leaving
                // IRQ0 stuck in-service forever (Doom timer freeze after
                // I_StartupTimer; the ISR EOIs while IF=0, i.e. single-stepped).
                if let Some(ev) = uc.get_data_mut().pending.take() {
                    return ev;
                }
                continue;
            }
            // Sensitive-instruction #GP (error code 0): decode through the shared
            // monitor — the same decoder arch-metal runs on its real #GP, so the
            // kernel NEVER sees an Exception(13) for these on either backend. At
            // IOPL=1 this covers VM86 CLI/STI/PUSHF/POPF/IRET/INT (all #GP) and
            // PM CLI/STI (PM POPF/IRET silently drop IF and are caught by TF
            // stepping instead). `Resume` re-enters the client; `Event` bubbles
            // (SoftInt for trapped/IVT-redirected INTs and INT3/INTO, In/Out for
            // port I/O, Hlt for idle); `Fault` is a genuine #GP, handled below.
            // Reproducer: DOS/4GW's IRQ epilogue STIs on every timer tick
            // (duke3d/raptor at sound init); forwarding the #GP to the client's
            // own handler cascaded into a wild jump.
            if n == 13 && !is_int && uc.get_data().pending_err == 0 {
                match arch_abi::monitor::monitor(&mut crate::backend::Interp, &mut vcpu.regs) {
                    MonitorResult::Resume => continue,
                    MonitorResult::Event(KernelEvent::Fault) => {} // genuine #GP
                    MonitorResult::Event(ev) => return ev,
                }
            }
            if mode == UserMode::VM86 {
                // Residual VM86 traps the monitor didn't consume: genuine
                // exceptions the intr hook bubbled, and the DPL=3 gates. Match
                // the pre-IOPL=1 behaviour and surface them as SoftInt(n).
                return KernelEvent::SoftInt(n);
            }
            // Protected mode: a software `int n` (DPL=3 gate / 0x80) becomes a
            // SoftInt; any other CPU fault becomes a typed Exception carrying the
            // error code (the faulting selector for #NP/#GP — what a DPMI host
            // needs to demand-load the right overlay segment).
            if is_int {
                return KernelEvent::SoftInt(n);
            }
            vcpu.err_code = uc.get_data().pending_err as u64;
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

/// Flush the softmmu TLB by rewriting CR3 (no global pages, so this drops every
/// cached translation). The keystone for the paging model: after the kernel
/// edits page tables, the next walk must see the new entries.
fn flush_tlb(uc: &mut Unicorn<'static, Ctx>) {
    let cr3 = uc.reg_read(RegisterX86::CR3).unwrap_or(0);
    let _ = uc.reg_write(RegisterX86::CR3, cr3);
    let _ = uc.ctl_flush_tlb();
}

// Virtual-IF single-stepping and sensitive-instruction decoding now live in the
// shared `arch_abi::monitor`, driven through `InterpView` (see top of file).
// Both backends emulate `CLI`/`STI`/`PUSHF`/`POPF`/`IRET`/`INT` identically;
// only the guest-memory backing differs (interp = software MMU, metal = live
// page tables). PM clients run CPL=3/IOPL=1: `CLI`/`STI` `#GP` (decoded by the
// monitor), `POPF`/`IRET` silently drop IF at CPL>IOPL (caught by TF stepping).
// VM86 runs CPL=3/IOPL=1 too: there *every* IF-touching op (and `INT n`) `#GP`s,
// so the monitor sees them all and no TF stepping is needed.

/// Run up to `count` guest instructions and charge virtual time by what actually
/// retired. A run that hits its instruction budget (no hook stopped it) retired
/// the whole `count` — the block hook undercounts a chained-TB loop, so we must
/// not trust its accumulator there or a tight compute loop freezes virtual time
/// (the timer never ticks; DOS/4GW's IRQ-dispatch loop waits forever). An early
/// stop charges the block-accumulated work, which is accurate for the TB-breaking
/// poll loops (DN's `in 0x3DA`) that the accumulator exists for.
fn run_slice(uc: &mut Unicorn<'static, Ctx>, begin: u64, max: usize) -> Result<(), uc_error> {
    let count = BUDGET.with(|b| b.get()).min(max).max(1);
    {
        let d = uc.get_data_mut();
        d.slice_instr = 0;
        d.stopped = false;
    }
    let r = uc.emu_start(begin, 0xFFFF_FFFF, 0, count);
    let d = uc.get_data();
    let instr = if d.stopped { d.slice_instr } else { count as u64 };
    crate::machine::advance_virtual_time(instr.max(1));
    BUDGET.with(|b| b.set(b.get().saturating_sub(instr as usize)));
    r
}

/// Whether the IRQ0 grid boundary was reached (budget spent).
fn budget_spent() -> bool {
    BUDGET.with(|b| b.get()) == 0
}

/// Invalidate cached translations for a range after an arch call mutated the
/// active space's page tables. `configure` reloads CR3 at the start of every
/// slice (a full TLB flush), so the only window this must cover is a mutation
/// applied while the CPU is already configured — handled by a CR3 rewrite.
pub fn invalidate_uc(vpage: usize, count: usize) {
    MACHINE.with(|cell| {
        if let Some(uc) = cell.borrow_mut().as_mut() {
            flush_tlb(uc);
            // Also drop cached TRANSLATIONS for the affected linears, not just the
            // softmmu TLB: a COW/remap can repoint a linear at a freshly recycled
            // physical frame that still carries a previous owner's TBs (TBs are
            // keyed by physical addr), and `flush_tlb` alone would leave Unicorn
            // running that stale code. Per page (frames are scattered, so a range
            // isn't physically contiguous — see `invalidate_code_range`).
            for p in 0..count {
                let lin = ((vpage + p) as u64) << 12;
                let _ = uc.ctl_remove_cache(lin, lin + 0x1000);
            }
        }
    });
}

/// Drop Unicorn's cached translations for guest-linear `[addr, addr+len)`. Called
/// from the host-side guest-memory write path (`vcpu.rs`) so that code loaded into
/// guest RAM by the kernel — DOS overlay/EXE loads, relocations, BSS — invalidates
/// any stale TB, restoring the x86 store-vs-fetch coherence the real CPU gives for
/// free (and that Unicorn only honors for stores routed through its own softmmu,
/// which a direct host-pointer write bypasses). Invalidates PER PAGE: the interp's
/// frames are scattered, so `ctl_remove_cache(gva, gva+len)` — which resolves the
/// START gva to a physical addr and adds `len` in PHYSICAL space — would hit the
/// wrong frames past the first page boundary.
///
/// `try_borrow`: the `vcpu.rs` write path runs only in kernel context (between
/// slices); in-`emu_start` reflections write via `InterpView` (direct paging), not
/// this path. The guard keeps a future re-entrant write from panicking — it would
/// silently skip, which `RETRO_FLUSH_TB` would then surface.
pub fn invalidate_code_range(addr: u32, len: u32) {
    if len == 0 {
        return;
    }
    MACHINE.with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else { return };
        let Some(uc) = slot.as_mut() else { return };
        let end = addr as u64 + len as u64;
        let mut p = (addr as u64) & !0xFFF;
        while p < end {
            let page_end = p + 0x1000;
            let _ = uc.ctl_remove_cache(p.max(addr as u64), page_end.min(end));
            p = page_end;
        }
    });
}

/// Flush all cached translations (on a context switch). The incoming space's
/// CR3 is loaded by the next `configure`; this drops the outgoing TLB now.
pub fn flush_uc() {
    MACHINE.with(|cell| {
        if let Some(uc) = cell.borrow_mut().as_mut() {
            flush_tlb(uc);
        }
    });
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

/// Enter the guest through the CPL0 `iretd` trampoline. `frame` is the iret
/// stack image (5 dwords for PM, 9 for VM86 with the VM bit set); `pre_segs`,
/// when present, loads the client's DS/ES/FS/GS at CPL0 before the iret (PM —
/// VM86 carries them in the frame). Returns the trampoline start PC.
fn run_trampoline(uc: &mut Unicorn<'static, Ctx>, frame: &[u32], pre_segs: Option<[u16; 4]>) -> u64 {
    let w = |uc: &mut Unicorn<'static, Ctx>, reg, v: u64| { let _ = uc.reg_write(reg, v); };
    let cr0 = uc.reg_read(RegisterX86::CR0).unwrap_or(0x11);

    // 0. Exit VM86 first. When the previous slice was a VM86 task (the common
    //    case — the next entry is another VM86 task or its INT handler), EFLAGS.VM
    //    is still set; clearing PE/PG and loading flat selectors while VM=1 leaves
    //    the CPU in VM86, where `CS=KERNEL_CS` is misread as a real-mode segment
    //    and the trampoline `iretd` never switches. Forcing EFLAGS=2 (VM=0, ring-0
    //    flags) drops VM86 so the CPL-0 bootstrap below is interpreted as PM.
    w(uc, RegisterX86::EFLAGS, 2);

    // 1. Drop to real mode (clear PE *and* PG together — legal in one write) and
    //    do a real-mode SS load so the cached CPL is 0.
    w(uc, RegisterX86::CR0, cr0 & !0x8000_0001);
    w(uc, RegisterX86::SS, 0);

    // 2. Tables into the SYS frames; GDTR/LDTR at the PHYSICAL base while PG=0.
    let ldt_limit = write_tables();
    set_mmr(uc, RegisterX86::GDTR, 0, sys_phys(GDT_ADDR), (GDT_BYTES - 1) as u32, 0);
    set_mmr(uc, RegisterX86::LDTR, LDT_SEL, sys_phys(LDT_ADDR), ldt_limit, 0x8200);

    // 3. PE on (PG still off): load flat ring-0 CS, and the client data segments
    //    for PM (DPL-3 loads fine at CPL 0; they survive the iret).
    w(uc, RegisterX86::CR0, (cr0 & !0x8000_0000) | 1);
    w(uc, RegisterX86::CS, KERNEL_CS as u64);
    if let Some([ds, es, fs, gs]) = pre_segs {
        w(uc, RegisterX86::DS, ds as u64);
        w(uc, RegisterX86::ES, es as u64);
        w(uc, RegisterX86::FS, fs as u64);
        w(uc, RegisterX86::GS, gs as u64);
    }

    // 4. Build the iret frame at the top of the ring-0 stack (linear SYS).
    let frame_addr = RING0_SP_TOP - (frame.len() * 4) as u64;
    let fp = sys_ptr(frame_addr);
    for (i, v) in frame.iter().enumerate() {
        unsafe { core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), fp.add(i * 4), 4); }
    }
    w(uc, RegisterX86::SS, KERNEL_DS as u64);
    w(uc, RegisterX86::ESP, frame_addr);
    w(uc, RegisterX86::EFLAGS, 2);
    w(uc, RegisterX86::EIP, TRAMP_ADDR);

    // 5. Enable paging: CR3 = active page directory, then PE|PG. With PG on, the
    //    iret's CS/SS (PM) reload reads GDT/LDT through the page tables, so point
    //    GDTR/LDTR at the LINEAR window now.
    // Enable SSE so SSE2 instructions don't #UD: CR4.OSFXSR|OSXMMEXCPT, and CR0
    // with EM cleared + MP set. rust-musl emits MOVQ/MOVD to XMM in startup;
    // without this the guest faults at its first SSE2 op. Mirrors metal
    // (descriptors.rs sets the same when the CPU reports FXSR).
    w(uc, RegisterX86::CR4, 0x600);
    w(uc, RegisterX86::CR3, crate::paging::frame_phys(crate::paging::active_pd()) as u64);
    w(uc, RegisterX86::CR0, (((cr0 | 0x8000_0001) | 0x10) | 0x2) & !0x4);
    set_mmr(uc, RegisterX86::GDTR, 0, GDT_ADDR, (GDT_BYTES - 1) as u32, 0);
    set_mmr(uc, RegisterX86::LDTR, LDT_SEL, LDT_ADDR, ldt_limit, 0x8200);
    TRAMP_ADDR
}

/// Configure Unicorn for `mode`, load `REGS`, and return the linear start PC.
fn configure(uc: &mut Unicorn<'static, Ctx>, r: &Regs, mode: UserMode) -> u64 {
    // DIAGNOSTIC "no-translation-cache" mode (RETRO_FLUSH_TB=1): flush ALL
    // translation blocks at every slice entry, forcing Unicorn to re-decode every
    // instruction from current guest memory. With caching disabled this way, no
    // stale TB can survive a host-side code overwrite — so if a bug REPRODUCES
    // with caching but VANISHES here, it is a missing TB-invalidation (see
    // `invalidate_code_range`). Too slow for normal use; a CI run with this on is
    // the regression net for the stale-TB class (see TODO.md §9).
    if std::env::var_os("RETRO_FLUSH_TB").is_some() {
        let _ = uc.ctl_flush_tb();
    }
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
            // VM86 runs PAGED now (PE=1, VM=1, PG=1) — its real-mode seg<<4 linear
            // addresses translate through the per-thread page tables, giving DOS
            // isolation under the single shared physical region. Entry is by IRET
            // into a frame whose EFLAGS image has VM=1 (the only valid v86 entry),
            // pinned at IOPL=1 exactly like arch-metal's ring-3 guests. At IOPL<3
            // every VM86 IOPL-sensitive op — CLI/STI/PUSHF/POPF/IRET *and* `INT n`
            // — #GPs into the shared monitor, which tracks the virtual IF and
            // IVT-reflects the INTs; the host, not unicorn's native IF, owns
            // interrupt state. NEVER IOPL=3: that lets the guest toggle the real
            // IF behind the kernel's back and bypasses the per-swap-in IO bitmap.
            // Project VIF (bit 19) into the bit-9 IF slot the guest runs with.
            uc.get_data_mut().vif_watch = None;
            let flags = vif_to_if((r.flags32() & !(IOPL_MASK as u32) & !NT_FLAG) | (VM_FLAG as u32) | (1 << 12) | 2);
            let frame = [
                r.ip32() & 0xFFFF,
                r.code_seg() as u32,
                flags,
                r.sp32() & 0xFFFF,
                r.stack_seg() as u32,
                (r.es & 0xFFFF) as u32,
                (r.ds & 0xFFFF) as u32,
                (r.fs & 0xFFFF) as u32,
                (r.gs & 0xFFFF) as u32,
            ];
            run_trampoline(uc, &frame, None)
        }
        UserMode::Mode32 => {
            // The client runs CPL=3, IOPL=1 — exactly like the real processor on
            // metal. CLI/STI #GP and are emulated against the virtual IF (rflags
            // bit 9); POPF/IRET silently drop IF at CPL>IOPL, so while the virtual
            // IF is 0 we single-step (TF=1) and `step_virtual_if` emulates the
            // IF-touching opcodes in software. With IF on we run at full speed.
            // Project VIF (bit 19) into the bit-9 IF slot; then if the guest's IF
            // is off, single-step so POPF/IRET get caught (CPL>IOPL drops them).
            let mut flags = vif_to_if((r.flags32() & !(VM_FLAG as u32) & !(IOPL_MASK as u32) & !NT_FLAG) | (1 << 12) | 2);
            if flags & IF_FLAG == 0 {
                flags |= TF_FLAG; // step the next non-sensitive instruction
                // Arm the intr hook's in-place stepping fast path (see the
                // #DB branch in the intr hook): per-#DB it re-arms TF and
                // continues within the slice until a sensitive opcode shows.
                uc.get_data_mut().vif_watch = Some(VifWatch {
                    cs: r.code_seg(),
                    cs_base: crate::desc::seg_base(r.code_seg()),
                });
            } else {
                uc.get_data_mut().vif_watch = None;
            }
            let frame = [r.ip32(), r.code_seg() as u32, flags, r.sp32(), r.frame.ss as u32];
            let segs = [r.ds as u16, r.es as u16, r.fs as u16, r.gs as u16];
            run_trampoline(uc, &frame, Some(segs))
        }
        UserMode::Mode64 => {
            // 64-bit guests aren't interpreted yet (the core runs in 32-bit mode);
            // run flat-32 at CPL3 via the same trampoline so memory still goes
            // through the page tables. (Smoke paths only.) IOPL=1 like every
            // other ring-3 guest — never IOPL=3.
            let flags = (r.frame.rflags as u32 & !(IOPL_MASK as u32)) | (1 << 12) | 2;
            use arch_abi::{USER_CS, USER_DS};
            let frame = [r.frame.rip as u32, USER_CS as u32, flags, r.frame.rsp as u32, USER_DS as u32];
            run_trampoline(uc, &frame, Some([USER_DS, USER_DS, USER_DS, USER_DS]))
        }
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

    match mode {
        UserMode::VM86 => {
            // Segments may have changed (mov/pop); read them back.
            r.set_cs32(rd(uc, RegisterX86::CS) as u32);
            r.set_ss32(rd(uc, RegisterX86::SS) as u32);
            r.ds = rd(uc, RegisterX86::DS);
            r.es = rd(uc, RegisterX86::ES);
            r.fs = rd(uc, RegisterX86::FS);
            r.gs = rd(uc, RegisterX86::GS);
            // Re-assert VM86 so `regs.mode()` stays VM86 for the kernel; normalize
            // IOPL to the kernel invariant (1, never 3). Mirror the emulated IF
            // (bit 9) into the canonical VIF (bit 19) and set the real IF =1.
            let uc_fl = if_to_vif(rd(uc, RegisterX86::EFLAGS) as u32) as u64;
            r.frame.rflags = (uc_fl & !IOPL_MASK) | VM_FLAG | (1 << 12);
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
            // Normalize IOPL to the kernel invariant (1, never 3) and strip the
            // stepping TF. The guest ran at CPL=3/IOPL=1, so CLI/STI #GP'd into
            // the monitor; mirror the emulated IF (bit 9) into the canonical VIF
            // (bit 19) and set the real IF =1.
            let uc_fl = if_to_vif(rd(uc, RegisterX86::EFLAGS) as u32) as u64;
            r.frame.rflags = (uc_fl & !IOPL_MASK & !(TF_FLAG as u64)) | (1 << 12);
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
