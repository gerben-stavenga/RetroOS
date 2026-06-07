//! DPMI (DOS Protected Mode Interface) 0.9 emulation
//!
//! Minimal DPMI server for DOS4GW/DOOM: mode switch, LDT descriptors,
//! linear memory allocation, real-mode interrupt simulation, and I/O
//! virtualization from 32-bit protected mode.
//!
//! A DOS thread starts in VM86 (real mode), detects DPMI via INT 2F/1687h,
//! then calls the entry point to switch to 32-bit protected mode. INT 31h
//! services are dispatched directly from the event loop (IDT DPL=3 for
//! vectors 0x30-0xFF). GP faults from protected mode (#13 with Mode32)
//! handle sensitive instructions: I/O, CLI/STI, PUSHF/POPF, HLT, IRET.

extern crate alloc;

use arch_abi::Arch;
use arch_abi::GuestBytes;
use alloc::boxed::Box;
use crate::arch::Vcpu;
use crate::kernel::thread;
use crate::kernel::dos;
use super::machine;
use super::mode_transitions::{seg_base, seg_is_32};
use crate::kernel::startup;
use crate::Regs;

mod state;
pub(in crate::kernel::dos) use self::state::{DpmiState, LDT_ENTRIES, LOW_MEM_SEL, MEM_BASE, PSP_SEL};
use self::state::{CLIENT_CS_LDT_IDX, CLIENT_DS_LDT_IDX, CLIENT_SS_LDT_IDX, LOW_MEM_LDT_IDX, MemBlock, PSP_LDT_IDX};
mod descriptors;
pub(in crate::kernel::dos) use self::descriptors::{desc_base, desc_limit, install_kernel_ldt_slots, reset_pm_vectors};
use self::descriptors::{alloc_ldt, alloc_ldt_range, desc_is_seg_alias, free_ldt, idx_to_sel, ldt_is_allocated, make_code_desc_ex, make_data_desc, make_data_desc_ex, sel_to_idx, set_desc_base, set_desc_limit, trace_dpmi_desc, valid_ldt_selector_idx};
mod rm_calls;
pub(in crate::kernel::dos) use self::rm_calls::callback_entry;
use self::rm_calls::{call_real_mode_proc, call_real_mode_proc_iret, simulate_real_mode_int};
mod exceptions;
pub(in crate::kernel::dos) use self::exceptions::dispatch_dpmi_exception;
use self::exceptions::{exception_return, ExcReturnVia};
mod psp;
pub(in crate::kernel::dos) use self::psp::{install_dpmi_psp_view, get_or_alloc_psp_sel, psp_sel_to_segment};
mod raw_switch;
pub(in crate::kernel::dos) use self::raw_switch::{pm_stub_dispatch, raw_switch_real_to_pm};
use self::raw_switch::{clear_carry, flat_addr, set_carry, trace_client_selector_leak};

// ============================================================================
// DPMI entry — mode switch from Dos/VM86 to Dos/DPMI (protected mode)
// ============================================================================

/// Switch from VM86 to 32-bit protected mode.
/// Called from rm_int31_dispatch when the DPMI entry stub executes.
pub(in crate::kernel::dos) fn dpmi_enter(dos: &mut thread::DosState, regs: &mut Vcpu) {
    let client_type = regs.rax as u16; // AX: 0=16-bit, 1=32-bit
    // DPMI entry is a FAR CALL; the real-mode stack holds the PM return CS:IP.
    let ret_ip = machine::vm86_pop(regs);
    let ret_cs = machine::vm86_pop(regs);
    let real_ss = regs.stack_seg();
    let real_sp = regs.sp32() as u16;
    dos_trace!("[DPMI] ENTER AX={} ({}bit client) caller={:04X}:{:04X} psp={:04X} rm_ss:sp={:04X}:{:04X} ds={:04X} es={:04X}",
        client_type, if client_type != 0 { 32 } else { 16 },
        ret_cs, ret_ip, dos.current_psp, real_ss, real_sp, regs.ds as u16, regs.es as u16);

    let mut dpmi = DpmiState::new();
    dpmi.mem_next = dos.dpmi_mem_next;
    dpmi.client_use32 = client_type != 0;
    // 16-bit DPMI clients (Borland) issue INT 21 directly from PM with
    // high-base PM selector buffers and rely on the host to handle them.
    // PMDOS short-circuits INT 21 to a kernel handler that services the
    // call with PM regs intact — see SLOT_PMDOS_INT21 docstring.
    dos.pm_dos = !dpmi.client_use32;

    // Set up initial LDT entries.
    // Kernel slots (VECTOR_STUB, SPECIAL_STUB, LOW_MEM, IRQ_PM16/32_STACK) plus
    // PSP_LDT_IDX reservation are already installed on `dos.ldt` by
    // install_kernel_ldt_slots at thread init. Here we only write the three
    // per-DPMI-client selectors: CS/DS/SS based on the caller's RM state.
    //
    // CS stays 16-bit: the return from mode switch is still 16-bit stub code.
    // SS must be 32-bit for 32-bit clients so interrupts save/restore full ESP.
    // DS/ES stay 16-bit (data segments don't affect stack width).
    let use32 = client_type != 0;

    // CS — code, base = ret_cs * 16 (caller's CS, not stub segment).
    // Placed at LDT[16] (CWSDPMI's l_acode) — see CLIENT_CS_LDT_IDX docs.
    let cs_base = (ret_cs as u32) * 16;
    dos.ldt[CLIENT_CS_LDT_IDX] = make_code_desc_ex(cs_base, 0xFFFF, false);
    dos.ldt_alloc[CLIENT_CS_LDT_IDX / 32] |= 1 << (CLIENT_CS_LDT_IDX % 32);

    // DS — data, base = real-mode DS * 16, limit = 64K.
    // Placed at LDT[17] (CWSDPMI's l_adata).
    let ds_base = (regs.ds as u32) * 16;
    dos.ldt[CLIENT_DS_LDT_IDX] = make_data_desc_ex(ds_base, 0xFFFF, false);
    dos.ldt_alloc[CLIENT_DS_LDT_IDX / 32] |= 1 << (CLIENT_DS_LDT_IDX % 32);

    // SS — stack, base = real_ss * 16, limit = 64K.
    // 32-bit clients need B=1 so the CPU uses full ESP during interrupts.
    // Placed at LDT[19] (CWSDPMI's l_aenv slot, repurposed — RetroOS doesn't
    // separately allocate an env selector).
    let ss_base = (real_ss as u32) * 16;
    dos.ldt[CLIENT_SS_LDT_IDX] = make_data_desc_ex(ss_base, 0xFFFF, use32);
    dos.ldt_alloc[CLIENT_SS_LDT_IDX / 32] |= 1 << (CLIENT_SS_LDT_IDX % 32);

    let cs_sel = idx_to_sel(CLIENT_CS_LDT_IDX);
    let ds_sel = idx_to_sel(CLIENT_DS_LDT_IDX);
    let ss_sel = idx_to_sel(CLIENT_SS_LDT_IDX);

    // Round client allocation pool up to a 1 MB boundary. DOS/4GW appears to
    // treat the first 0501 base as a slab origin and takes a private code path
    // when it is not MB-aligned (matches CWSDPMI's VADDR_START=0x400000).
    dpmi.mem_next = (dpmi.mem_next + 0xFFFFF) & !0xFFFFF;
    dos.dpmi_mem_next = dpmi.mem_next;

    // pm_vectors stays zero-initialized: sel=0 means "no client handler",
    // which signals reflect-to-real-mode in deliver_pm_int. INT 31h/0204h
    // synthesizes the stub address on demand for clients that chain to the
    // default handler.

    // Attach DPMI state to thread, then install the one-shot DPMI PSP
    // view: LDT[18] (PSP_SEL) descriptor for the entering client's PSP,
    // seed the PSP cache with (initial_psp, PSP_SEL), capture
    // saved_rm_psp/saved_rm_env, and convert PSP[0x2C] from segment to
    // selector per §4.1. `dos.current_psp` stays as the segment value
    // (pure DOS state).
    dos.dpmi = Some(Box::new(dpmi));
    install_dpmi_psp_view(dos);

    // PMDOS: route PM INT 21 to the kernel's direct-service handler.
    if dos.pm_dos {
        dos.pm_vectors[0x21] = (
            super::mode_transitions::SPECIAL_STUB_SEL,
            dos::STUB_BASE + dos::slot_offset(dos::SLOT_PMDOS_INT21) as u32,
        );
    }

    // Route PM INT 33h (mouse) to the kernel's direct-service handler for
    // every DPMI client (16- and 32-bit). Servicing it in PM is what lets the
    // kernel-modeled mouse driver record a PM-installed AX=0Ch handler as a
    // selector (`cb_is_pm`) and call it back in PM — the symmetric twin of the
    // INT 21 PMDOS routing above. A client may still override pm_vectors[0x33].
    dos.pm_vectors[0x33] = (
        super::mode_transitions::SPECIAL_STUB_SEL,
        dos::STUB_BASE + dos::slot_offset(dos::SLOT_PMDOS_INT33) as u32,
    );

    // No arch_load_ldt here: `dos.ldt` is a fixed per-thread buffer allocated
    // at thread init, and the context switch into this thread already pointed
    // LDTR at it. Mutations to `dos.ldt[CLIENT_CS/DS/SS]` are visible to the
    // CPU without reloading.

    // Trace non-empty low LDT slots for clients that derive paragraphs from descriptor bases.
    for i in 1..8 {
        let d = dos.ldt[i];
        if d != 0 {
            dos_trace!("[DPMI] INIT_LDT idx={} sel={:04X} base={:08X} raw={:016X}",
                i, idx_to_sel(i), desc_base(d), d);
        }
    }

    regs.frame.rflags &= !(machine::VM_FLAG as u64);
    regs.frame.rflags |= machine::IF_FLAG as u64;
    regs.frame.cs = cs_sel as u64;
    regs.frame.rip = ret_ip as u64;
    regs.frame.ss = ss_sel as u64;
    regs.frame.rsp = real_sp as u64;
    regs.ds = ds_sel as u64;
    regs.es = PSP_SEL as u64;
    regs.fs = 0;
    regs.gs = 0;
    dos_trace!("[DPMI] ENTER -> pm cs:eip={:04X}:{:08X} ss:esp={:04X}:{:08X} ds={:04X} es={:04X}",
        regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32(),
        regs.ds as u16, regs.es as u16);
}

// PM #GP monitor lives in `arch/monitor.rs`. The arch decoder handles
// CLI/STI/PUSHF/POPF/IRET directly (fast-path iret to user) and bubbles
// INT/HLT/IN/OUT/INS/OUTS up as `KernelEvent`s. PM software-INT dispatch
// for installed client vectors is `mode_transitions::deliver_pm_int`.


// ============================================================================
// INT 31h — DPMI services API
// ============================================================================

/// PM client-initiated INT 31h — the DPMI service API, dispatched by AX.
/// Caller (`dos::syscall`) has already classified the trap as client-side
/// (CS not in the kernel's stub LDT slots).
pub(super) fn dpmi_api(machine: &mut crate::TheArch, dos: &mut thread::DosState, regs: &mut Vcpu) -> thread::KernelAction {
    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => {
            crate::println!("DPMI: INT 31h from client but no DPMI state!");
            set_carry(regs);
            return thread::KernelAction::Done;
        }
    };

    let ax = regs.rax as u16;
    dos_trace!("[INT31] AX={:04x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x} cs:ip={:04X}:{:04X}",
        ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16,
        regs.code_seg(), regs.ip32() as u16);

    // Optional PM TF single-step arming.
    #[allow(dead_code)]
    if false {
        use core::sync::atomic::Ordering;
        if dos::PM_STEP_BUDGET.load(Ordering::Relaxed) == 0 {
            static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !ONCE.swap(true, Ordering::Relaxed) {
                dos::PM_STEP_BUDGET.store(200_000, Ordering::Relaxed);
                regs.set_flag32(1 << 8); // TF on return to client
                dos_trace!("[STEP] armed 200000 steps at first INT 31 (PM init)");
            }
        }
    }

    match ax {
        // AX=0000h — Allocate LDT Descriptors
        // CX = number of descriptors
        // Returns: AX = base selector
        0x0000 => {
            let count = (regs.rcx & 0xFFFF) as usize;
            if count == 0 { set_carry(regs); return thread::KernelAction::Done; }
            // DPMI 0.9 §0000: allocated descriptors should match the
            // client's bitness — 16-bit clients get D=0, 32-bit get D=1.
            // Borland's dpmiload (16-bit client) inspects descriptor flags
            // after alloc; getting D=1 for a 16-bit client trips its
            // sanity check and trips the "Application load & execute
            // error FFFB" bail.
            let use32 = dos.dpmi.as_ref().map_or(true, |d| d.client_use32);
            // DPMI requires the returned descriptors to be a contiguous run.
            match alloc_ldt_range(&mut dos.ldt_alloc, count) {
                Some(idx) => {
                    for extra in idx..(idx + count) {
                        dos.ldt[extra] = make_data_desc_ex(0, 0, use32);
                        trace_dpmi_desc("0000 alloc", idx_to_sel(extra), dos.ldt[extra]);
                    }
                    let sel = idx_to_sel(idx);
                    regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                    clear_carry(regs);
                }
                None => set_carry(regs),
            }
        }
        // AX=0001h — Free LDT Descriptor
        // BX = selector
        0x0001 => {
            let sel = regs.rbx as u16;
            let idx = sel_to_idx(sel);
            dos_trace!("[DPMI] 0001 free sel={:04X} idx={}", sel, idx);
            if sel & 0x0004 == 0 || idx < 16 || !ldt_is_allocated(&dos.ldt_alloc, idx) {
                dos_trace!(
                    "[DPMI] 0001 ignoring non-owned/free selector sel={:04X} idx={} caller={:04X}:{:04X}",
                    sel, idx, regs.code_seg(), regs.ip32() as u16,
                );
                clear_carry(regs);
                return thread::KernelAction::Done;
            }
            free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
            // Null out any segment register still holding the freed selector,
            // otherwise IRET back to user mode will GP fault.
            if regs.ds as u16 == sel { regs.ds = 0; }
            if regs.es as u16 == sel { regs.es = 0; }
            if regs.fs as u16 == sel { regs.fs = 0; }
            if regs.gs as u16 == sel { regs.gs = 0; }
            clear_carry(regs);
        }
        // AX=0002h — Segment to Descriptor
        // BX = real-mode segment. Returns: AX = selector (maps 64KB at seg<<4)
        0x0002 => {
            let seg = regs.rbx as u16;
            let base = (seg as u32) << 4;
            for idx in 1..LDT_ENTRIES {
                if ldt_is_allocated(&dos.ldt_alloc, idx) && desc_is_seg_alias(dos.ldt[idx], base) {
                    let sel = idx_to_sel(idx);
                    regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                    dos_trace!("[DPMI] 0002 seg={:04X} -> reuse sel={:04X} base={:08X}", seg, sel, base);
                    clear_carry(regs);
                    return thread::KernelAction::Done;
                }
            }
            if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
                dos.ldt[idx] = make_data_desc_ex(base, 0xFFFF, false);
                let sel = idx_to_sel(idx);
                regs.rax = (regs.rax & !0xFFFF) | sel as u64;
                dos_trace!("[DPMI] 0002 seg={:04X} -> sel={:04X} base={:08X}", seg, sel, base);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0003h — Get Selector Increment Value
        // Returns: AX = 8
        0x0003 => {
            regs.rax = (regs.rax & !0xFFFF) | 8;
            clear_carry(regs);
        }
        // AX=0006h — Get Segment Base Address
        // BX = selector. Returns: CX:DX = base
        0x0006 => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let base = desc_base(dos.ldt[idx]);
                dos_trace!("[DPMI] 0006 sel={:04X} -> base={:08X}", sel, base);
                regs.rcx = (regs.rcx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | (base & 0xFFFF) as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0007h — Set Segment Base Address
        // BX = selector, CX:DX = base
        0x0007 => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let mut base = ((regs.rcx as u32 & 0xFFFF) << 16) | (regs.rdx as u32 & 0xFFFF);
                if let Some(dpmi) = dos.dpmi.as_ref() {
                    if !dpmi.client_use32 && dpmi.env_ldt_idx != 0 && (base & 0xF) == 0 {
                        let psp_base = desc_base(dos.ldt[PSP_LDT_IDX]);
                        let env_sel = crate::arch::mem().read::<u16>(((psp_base + 0x2C)) as usize);
                        if env_sel != 0 && ((env_sel as u32) << 4) == base {
                            let env_idx = sel_to_idx(env_sel);
                            if env_idx < LDT_ENTRIES && ldt_is_allocated(&dos.ldt_alloc, env_idx) {
                                let env_base = desc_base(dos.ldt[env_idx]);
                                if env_base != base {
                                    dos_trace!("[DPMI] 0007 env selector-as-segment sel={:04X} base={:08X}->{:08X}", env_sel, base, env_base);
                                    base = env_base;
                                }
                            }
                        }
                    }
                }
                set_desc_base(&mut dos.ldt[idx], base);
                trace_dpmi_desc("0007 base", sel, dos.ldt[idx]);
                dos_trace!("[DPMI] 0007 sel={:04X} base={:08X}", sel, base);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0008h — Set Segment Limit
        // BX = selector, CX:DX = limit
        0x0008 => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let limit = ((regs.rcx as u32 & 0xFFFF) << 16) | (regs.rdx as u32 & 0xFFFF);
                set_desc_limit(&mut dos.ldt[idx], limit);
                trace_dpmi_desc("0008 limit", sel, dos.ldt[idx]);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0009h — Set Descriptor Access Rights
        // BX = selector, CL = access rights byte, CH = extended type
        0x0009 => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let cl = regs.rcx as u8;
                let ch = (regs.rcx >> 8) as u8;
                // Match CWSDPMI: force the descriptor to stay code/data (S=1)
                // and only accept G/D/B/AVL in the high nibble.
                dos.ldt[idx] &= !0x00F0_FF00_0000_0000;
                dos.ldt[idx] |= ((0x10 | cl) as u64) << 40;
                dos.ldt[idx] |= ((ch & 0xD0) as u64) << 48;
                trace_dpmi_desc("0009 rights", sel, dos.ldt[idx]);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=000Ah — Create Alias Descriptor (data alias of code segment)
        // BX = selector. Returns: AX = new data selector
        0x000A => {
            let sel = regs.rbx as u16;
            if let Some(src_idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                if let Some(new_idx) = alloc_ldt(&mut dos.ldt_alloc) {
                    let mut desc = dos.ldt[src_idx];
                    // Change type from code to data (clear bit 3 of type nibble = execute bit)
                    // Access byte bit 43 = execute. Clear it, set writable (bit 41)
                    desc &= !(1u64 << 43); // clear execute
                    desc |= 1u64 << 41;    // set writable
                    dos.ldt[new_idx] = desc;
                    let new_sel = idx_to_sel(new_idx);
                    trace_dpmi_desc("000A alias", new_sel, desc);
                    regs.rax = (regs.rax & !0xFFFF) | new_sel as u64;
                    dos_trace!("[DPMI] 000A alias src_sel={:04X} -> new_sel={:04X} base={:08X}",
                        sel, new_sel, desc_base(desc));
                    clear_carry(regs);
                } else {
                    set_carry(regs);
                }
            } else {
                set_carry(regs);
            }
        }
        // AX=000Bh — Get Descriptor
        // BX = selector, ES:EDI = buffer (8 bytes)
        0x000B => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let dest = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
                let desc = dos.ldt[idx];
                crate::arch::mem().write::<u64>((dest) as usize, desc);
                dos_trace!("[DPMI] 000B sel={:04X} -> base={:08X} raw={:016X}", sel,
                    desc_base(desc), desc);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=000Ch — Set Descriptor
        // BX = selector, ES:EDI = descriptor (8 bytes)
        0x000C => {
            let sel = regs.rbx as u16;
            if let Some(idx) = valid_ldt_selector_idx(&dos.ldt_alloc, sel) {
                let src = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
                let mut new_desc = regs.read::<u64>((src) as usize);
                // Match CWSDPMI: force the descriptor to stay non-system.
                new_desc |= 1u64 << 44;
                dos.ldt[idx] = new_desc;
                trace_dpmi_desc("000C set", sel, new_desc);
                dos_trace!("[DPMI] 000C sel={:04X} base={:08X} raw={:016X}", sel,
                    desc_base(new_desc), new_desc);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0100h — Allocate DOS Memory Block
        // BX = paragraphs. Returns: AX = real-mode segment, DX = selector
        0x0100 => {
            let paragraphs = regs.rbx as u16;
            match dos::dos_alloc_block(dos, paragraphs) {
                Ok(seg) => {
                    if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
                        let base = (seg as u32) * 16;
                        let limit = (paragraphs as u32).saturating_mul(16).saturating_sub(1);
                        dos.ldt[idx] = make_data_desc(base, limit);
                        let sel = idx_to_sel(idx);
                        regs.rax = (regs.rax & !0xFFFF) | seg as u64;
                        regs.rdx = (regs.rdx & !0xFFFF) | sel as u64;
                        dos_trace!("[DPMI] 0100 alloc paragraphs={:04X} -> seg={:04X} sel={:04X} base={:08X}",
                            paragraphs, seg, sel, base);
                        clear_carry(regs);
                    } else {
                        let _ = dos::dos_free_block(dos, seg);
                        regs.rax = (regs.rax & !0xFFFF) | 8;
                        set_carry(regs);
                    }
                }
                Err(max) => {
                    regs.rax = (regs.rax & !0xFFFF) | 8;
                    regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                    set_carry(regs);
                }
            }
        }
        // AX=0101h — Free DOS Memory Block
        // DX = selector
        0x0101 => {
            let sel = regs.rdx as u16;
            let idx = sel_to_idx(sel);
            if !ldt_is_allocated(&dos.ldt_alloc, idx) {
                regs.rax = (regs.rax & !0xFFFF) | 9;
                set_carry(regs);
            } else {
                let base = desc_base(dos.ldt[idx]);
                let seg = (base >> 4) as u16;
                match dos::dos_free_block(dos, seg) {
                    Ok(()) => {
                        free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
                        clear_carry(regs);
                    }
                    Err(err) => {
                        regs.rax = (regs.rax & !0xFFFF) | err as u64;
                        set_carry(regs);
                    }
                }
            }
        }
        // AX=0102h — Resize DOS Memory Block
        // BX = new paragraphs, DX = selector
        0x0102 => {
            let paragraphs = regs.rbx as u16;
            let sel = regs.rdx as u16;
            let idx = sel_to_idx(sel);
            if !ldt_is_allocated(&dos.ldt_alloc, idx) {
                regs.rax = (regs.rax & !0xFFFF) | 9;
                set_carry(regs);
            } else {
                let base = desc_base(dos.ldt[idx]);
                let seg = (base >> 4) as u16;
                match dos::dos_resize_block(dos, seg, paragraphs) {
                    Ok(()) => {
                        let limit = (paragraphs as u32).saturating_mul(16).saturating_sub(1);
                        dos.ldt[idx] = make_data_desc(base, limit);
                        clear_carry(regs);
                    }
                    Err((err, max)) => {
                        regs.rax = (regs.rax & !0xFFFF) | err as u64;
                        regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                        set_carry(regs);
                    }
                }
            }
        }
        // AX=0200h — Get Real Mode Interrupt Vector
        // BL = interrupt number. Returns: CX:DX = seg:off
        0x0200 => {
            let int_num = regs.rbx as u8;
            let off = machine::read_u16(0, (int_num as u32) * 4);
            let seg = machine::read_u16(0, (int_num as u32) * 4 + 2);
            regs.rcx = (regs.rcx & !0xFFFF) | seg as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0201h — Set Real Mode Interrupt Vector
        // BL = interrupt number, CX:DX = seg:off
        0x0201 => {
            let int_num = regs.rbx as u8;
            let seg = regs.rcx as u16;
            let off = regs.rdx as u16;
            dos_trace!("[DPMI] 0201 set RM vec {:02X} = {:04X}:{:04X}", int_num, seg, off);
            machine::write_u16(0, (int_num as u32) * 4, off);
            machine::write_u16(0, (int_num as u32) * 4 + 2, seg);
            clear_carry(regs);
        }
        // AX=0202h — Get Processor Exception Handler Vector
        // BL = exception number. DPMI 0.9 only defines 0..14 (CPU exceptions);
        // higher indices return CF=1 to match CWSDPMI.
        0x0202 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 15 {
                let (sel, off) = dpmi.exc_vectors[exc as usize];
                regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
                regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0203h — Set Processor Exception Handler Vector
        // BL = exception number, CX:EDX = selector:offset. Same 0..14 range.
        0x0203 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 15 {
                dpmi.exc_vectors[exc as usize] = (regs.rcx as u16, regs.rdx as u32);
                dos_trace!("[DPMI] 0203 set exception {:02X} = {:04X}:{:08X}",
                    exc, regs.rcx as u16, regs.rdx as u32);
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0210h — Get Extended Processor Exception Handler Vector (PM)
        // BL = exception number (00H-1FH). Returns CX:(E)DX = selector:offset
        // of the 1.0 PM handler. Range is the full 0..31, vs 0..14 for 0202H.
        0x0210 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
                let (sel, off) = dpmi.pm_exc_vectors[exc as usize];
                regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
                regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
                clear_carry(regs);
            } else {
                regs.rax = 0x8021;
                set_carry(regs);
            }
        }
        // AX=0211h — Get Extended Processor Exception Handler Vector (RM)
        // BL = exception number (00H-1FH). Returns CX:(E)DX = selector:offset
        // of the 1.0 RM handler (PM target — host does implied mode switch).
        0x0211 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
                let (sel, off) = dpmi.rm_exc_vectors[exc as usize];
                regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
                regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
                clear_carry(regs);
            } else {
                regs.rax = 0x8021;
                set_carry(regs);
            }
        }
        // AX=0212h — Set Extended Processor Exception Handler Vector (PM)
        // BL = exception number (00H-1FH), CX:(E)DX = handler. Installs into
        // the PM-origin table, leaving the 0.9 slot (exc_vectors) untouched
        // so it remains the fallback for vectors without a 1.0 handler.
        0x0212 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
                dpmi.pm_exc_vectors[exc as usize] = (regs.rcx as u16, regs.rdx as u32);
                dos_trace!("[DPMI] 0212 set PM exception {:02X} = {:04X}:{:08X}",
                    exc, regs.rcx as u16, regs.rdx as u32);
                clear_carry(regs);
            } else {
                regs.rax = 0x8021;
                set_carry(regs);
            }
        }
        // AX=0213h — Set Extended Processor Exception Handler Vector (RM)
        // BL = exception number (00H-1FH), CX:(E)DX = handler (PM target).
        // Installs into the RM-origin table; host does an implied mode switch
        // to PM to invoke the handler when a VM86-origin fault hits.
        0x0213 => {
            let exc = regs.rbx as u8;
            if (exc as usize) < 32 {
                dpmi.rm_exc_vectors[exc as usize] = (regs.rcx as u16, regs.rdx as u32);
                dos_trace!("[DPMI] 0213 set RM exception {:02X} = {:04X}:{:08X}",
                    exc, regs.rcx as u16, regs.rdx as u32);
                clear_carry(regs);
            } else {
                regs.rax = 0x8021;
                set_carry(regs);
            }
        }
        // AX=0204h — Get Protected Mode Interrupt Vector
        // BL = interrupt number. Returns: CX:EDX = selector:offset
        // If no client handler is installed, synthesize the address of the
        // default CD 31 stub slot — clients store this as a chain-to handler.
        0x0204 => {
            let int_num = regs.rbx as u8;
            let (sel, off) = dos.pm_vectors[int_num as usize];
            regs.rcx = (regs.rcx & !0xFFFF) | sel as u64;
            regs.rdx = (regs.rdx & !0xFFFFFFFF) | off as u64;
            clear_carry(regs);
        }
        // AX=0205h — Set Protected Mode Interrupt Vector
        // BL = interrupt number, CX:EDX = selector:offset
        0x0205 => {
            let int_num = regs.rbx as u8;
            let sel = regs.rcx as u16;
            // 16-bit clients pass a 16-bit offset in DX (high EDX undefined);
            // masking avoids storing stale high bits that break deliver_pm_irq's
            // default-stub check. See AH=25 in dos.rs for the full failure mode.
            let off = if dpmi.client_use32 { regs.rdx as u32 } else { regs.rdx as u16 as u32 };
            dos_trace!("[DPMI] 0205 set vec {:02X} = {:04X}:{:#X}", int_num, sel, off);
            dos.pm_vectors[int_num as usize] = (sel, off);
            clear_carry(regs);
        }
        // AX=0300h — Simulate Real Mode Interrupt
        // BL = interrupt number, ES:EDI = real-mode call structure (50 bytes)
        0x0300 => {
            return simulate_real_mode_int(dos, regs);
        }
        // AX=0301h — Call Real Mode Far Procedure
        // ES:EDI = real-mode call structure
        0x0301 => {
            return call_real_mode_proc(dos, regs);
        }
        // AX=0302h — Call Real Mode Procedure with IRET Frame
        // ES:EDI = real-mode call structure (procedure returns via IRET)
        0x0302 => {
            return call_real_mode_proc_iret(dos, regs);
        }
        // AX=0303h — Allocate Real Mode Callback Address
        // DS:SI = PM callback handler, ES:DI = real-mode register structure
        // Returns: CX:DX = real-mode callback address (segment:offset)
        0x0303 => {
            let dpmi = dos.dpmi.as_mut().unwrap();
            // Find a free callback slot
            let slot = dpmi.callbacks.iter().position(|c| c.is_none());
            match slot {
                Some(i) => {
                    dpmi.callbacks[i] = Some((
                        regs.ds as u16,
                        regs.rsi as u32,
                        regs.es as u16,
                        regs.rdi as u32,
                    ));
                    // Return real-mode address: STUB_SEG:slot_offset(SLOT_CB_ENTRY_BASE + i)
                    let rm_off = dos::slot_offset(dos::SLOT_CB_ENTRY_BASE + i as u8);
                    regs.rcx = (regs.rcx & !0xFFFF) | dos::STUB_SEG as u64;
                    regs.rdx = (regs.rdx & !0xFFFF) | rm_off as u64;
                    clear_carry(regs);
                }
                None => set_carry(regs),
            }
        }
        // AX=0304h — Free Real Mode Callback Address
        // CX:DX = real-mode callback address to free
        0x0304 => {
            let dpmi = dos.dpmi.as_mut().unwrap();
            let off = regs.rdx as u16;
            let cb_base = dos::slot_offset(dos::SLOT_CB_ENTRY_BASE);
            let cb_end = dos::slot_offset(dos::SLOT_CB_ENTRY_END);
            if off >= cb_base && off < cb_end {
                let idx = ((off - cb_base) / 2) as usize;
                dpmi.callbacks[idx] = None;
                clear_carry(regs);
            } else {
                set_carry(regs);
            }
        }
        // AX=0400h — Get DPMI Version
        // Returns: AH=major, AL=minor, BX=flags, CL=processor, DH=master PIC, DL=slave PIC
        // BX bits: 0=32-bit, 1=returns to RM (else VM86), 2=virtual memory
        // supported. We're 32-bit with demand-paged VM (0501H allocations are
        // lazy-committed via #PF — see `mem_next` bump-only logic at the
        // allocator), so bits 0 and 2 are set.
        0x0400 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0100; // version 1.00
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0005; // 32-bit + VM
            regs.rcx = (regs.rcx & !0xFF) | 0x03;     // 386 processor
            // DH = master PIC base vector, DL = slave PIC base vector
            // Report 0x08/0x70 (matching real-mode BIOS mapping) so DJGPP hooks
            // IRQ 1 as INT 9 (keyboard), IRQ 0 as INT 8 (timer), etc.
            regs.rdx = (regs.rdx & !0xFFFF) | ((0x08 << 8) | 0x70) as u64;
            clear_carry(regs);
        }
        // AX=0401h — Get DPMI Capabilities (DPMI 1.0)
        // ES:(E)DI = 128-byte buffer for host major/minor + vendor string.
        // Returns AX=capability flags, CX=DX=0 (reserved). All optional 1.0
        // features (page A/D, device mapping, demand zero-fill, write-protect)
        // are reported as not-supported — we're a no-frills demand-paged host
        // and clients should fall back to plain 0501H/0502H allocation. The
        // spec allows AX=0 even under VM, since every cap here is optional
        // when virtual memory is supported.
        0x0401 => {
            regs.rax = regs.rax & !0xFFFF;            // AX = 0  (no optional caps)
            regs.rcx = regs.rcx & !0xFFFF;            // CX = 0  (reserved)
            regs.rdx = regs.rdx & !0xFFFF;            // DX = 0  (reserved)
            let dest = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
            // Buffer layout (DPMI 1.0 §3.4): [0]=major (decimal), [1]=minor,
            // [2..]=ASCIIZ vendor identifier (≤126 bytes).
            const VENDOR: &[u8] = b"RetroOS DPMI Host\0";
            regs.write::<u8>(dest as usize, 1);        // host major = 1
            regs.write::<u8>(dest as usize + 1, 0);    // host minor = 0
            regs.write_bytes(dest as usize + 2, VENDOR);
            clear_carry(regs);
        }
        // AX=0500h — Get Free Memory Information
        // ES:EDI = 48-byte buffer. Mirror CWSDPMI: fields that aren't applicable
        // stay as 0xFFFFFFFF ("unknown / no limit"). DOS/4GW branches on [3]/[7]
        // (linear space) — concrete small values trigger a conservative path.
        0x0500 => {
            let dest = flat_addr(&dos.ldt[..], regs.es as u16, regs.rdi as u32, dpmi.client_use32);
            let physical_pages: u32 = 4096;
            let free_pages: u32 = 4096;
            let swap_pages: u32 = 0x4000; // pretend 64 MB of paging file (CWSDPMI default w/ swap)
            let mut info = [0xFFFF_FFFFu32; 12];
            info[4] = physical_pages;            // total unlocked
            info[6] = physical_pages;            // total physical
            info[2] = free_pages;                // max locked alloc
            info[5] = free_pages;                // total free
            info[8] = swap_pages;                // paging file pages
            info[1] = swap_pages + physical_pages; // max unlocked alloc (pages)
            info[0] = info[1] << 12;             // largest block (bytes)
            for (i, value) in info.into_iter().enumerate() {
                regs.write::<u32>(dest as usize + i * 4, value);
            }
            clear_carry(regs);
        }
        // AX=0501h — Allocate Memory Block
        // BX:CX = size in bytes. Returns: BX:CX = linear address, SI:DI = handle
        0x0501 => {
            let size = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            if size == 0 { set_carry(regs); return thread::KernelAction::Done; }
            // Align to page boundary.
            let aligned = (size + 0xFFF) & !0xFFF;
            let base = dpmi.mem_next;
            dpmi.mem_next = dpmi.mem_next.wrapping_add(aligned);
            dos.dpmi_mem_next = dos.dpmi_mem_next.max(dpmi.mem_next);
            // Keep the DPMI 0.9 handle equal to the base address. Several
            // extenders assume this CWSDPMI-compatible handle shape.
            let handle = base;
            // Record the block
            let mut stored = false;
            for slot in dpmi.mem_blocks.iter_mut() {
                if slot.is_none() {
                    *slot = Some(MemBlock { base, size: aligned });
                    stored = true;
                    break;
                }
            }
            if !stored { set_carry(regs); return thread::KernelAction::Done; }
            // Return linear address in BX:CX
            dos_trace!("[DPMI] 0501 alloc size={:#x} -> base={:#x} handle={:#x}", size, base, handle);
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (base & 0xFFFF) as u64;
            regs.rsi = (regs.rsi & !0xFFFF) | ((handle >> 16) & 0xFFFF) as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (handle & 0xFFFF) as u64;
            clear_carry(regs);
        }
        // AX=0502h — Free Memory Block
        // SI:DI = handle
        0x0502 => {
            let handle = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            for slot in dpmi.mem_blocks.iter_mut() {
                if let Some(blk) = slot {
                    if blk.base == handle {
                        *slot = None;
                        break;
                    }
                }
            }
            clear_carry(regs);
        }
        // AX=0503h — Resize Memory Block
        // BX:CX = new size, SI:DI = handle
        // Returns: BX:CX = new linear address, SI:DI = new handle
        0x0503 => {
            let new_size = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            let handle = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            let aligned = (new_size + 0xFFF) & !0xFFF;
            // Grow in place; pages are committed lazily.
            // This preserves existing data (pages already faulted in stay mapped).
            let mut base = handle;
            let mut found = false;
            for slot in dpmi.mem_blocks.iter_mut() {
                if let Some(blk) = slot {
                    if blk.base == handle {
                        // Ensure mem_next covers the grown region
                        let end = blk.base.wrapping_add(aligned);
                        if end > dpmi.mem_next {
                            dpmi.mem_next = end;
                        }
                        dos.dpmi_mem_next = dos.dpmi_mem_next.max(dpmi.mem_next);
                        blk.size = aligned;
                        base = blk.base;
                        found = true;
                        break;
                    }
                }
            }
            if !found { set_carry(regs); return thread::KernelAction::Done; }
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (base & 0xFFFF) as u64;
            regs.rsi = (regs.rsi & !0xFFFF) | ((base >> 16) & 0xFFFF) as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (base & 0xFFFF) as u64;
            clear_carry(regs);
        }
        // AX=0600h-0601h — Lock/Unlock Linear Region (no-op, all memory is locked)
        0x0600 | 0x0601 => {
            clear_carry(regs);
        }
        // AX=0702h — Mark Page as Demand Paging Candidate
        // AX=0703h — Discard Page Contents
        // This host does not implement demand-paged VM, so these are advisory no-ops.
        0x0702 | 0x0703 => {
            clear_carry(regs);
        }
        // AX=0900h — Get and Disable Virtual Interrupt State
        // Returns: AL = previous state (1=enabled, 0=disabled)
        0x0900 => {
            let prev = if regs.frame.rflags & (1 << 9) != 0 { 1u64 } else { 0u64 };
            regs.frame.rflags &= !(1 << 9);
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0901h — Get and Enable Virtual Interrupt State
        0x0901 => {
            let prev = if regs.frame.rflags & (1 << 9) != 0 { 1u64 } else { 0u64 };
            regs.frame.rflags |= 1 << 9;
            regs.rax = (regs.rax & !0xFF) | prev;
            clear_carry(regs);
        }
        // AX=0902h — Get Virtual Interrupt State
        0x0902 => {
            regs.rax = (regs.rax & !0xFF) | if regs.frame.rflags & (1 << 9) != 0 { 1 } else { 0 };
            clear_carry(regs);
        }
        // AX=0A00h — Get Vendor-Specific API Entry Point (not supported)
        0x0A00 => {
            set_carry(regs);
        }
        // AX=0305h — Get State Save/Restore Addresses
        // AX=0 means "no client buffer needed"; host keeps state internally.
        // Matches CWSDPMI (exphdlr.c:1145). A non-zero size is a semantic
        // signal to clients that changes their setup path even if they never
        // call the routine.
        0x0305 => {
            regs.rax = regs.rax & !0xFFFF;
            // Real-mode save/restore: stub slot SLOT_SAVE_RESTORE
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u64;
            // Protected-mode save/restore entry in the special-stub segment.
            regs.rsi = (regs.rsi & !0xFFFF) | super::mode_transitions::SPECIAL_STUB_SEL as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (dos::STUB_BASE + dos::slot_offset(dos::SLOT_SAVE_RESTORE) as u32) as u64;
            clear_carry(regs);
        }
        // AX=0306h — Get Raw Mode Switch Addresses
        // Returns real-to-PM and PM-to-real switch entry points
        0x0306 => {
            // BX:CX = real-to-PM entry point (real-mode segment:offset)
            regs.rbx = (regs.rbx & !0xFFFF) | dos::STUB_SEG as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | dos::slot_offset(dos::SLOT_RAW_REAL_TO_PM) as u64;
            // SI:(E)DI = PM-to-real entry in the special-stub segment.
            regs.rsi = (regs.rsi & !0xFFFF) | super::mode_transitions::SPECIAL_STUB_SEL as u64;
            regs.rdi = (regs.rdi & !0xFFFFFFFF) | (dos::STUB_BASE + dos::slot_offset(dos::SLOT_PM_TO_REAL) as u32) as u64;
            clear_carry(regs);
        }
        // AX=0507h — Set Page Attributes (DPMI 1.0)
        // All our memory is committed, so this is a no-op.
        0x0507 => {
            clear_carry(regs);
        }
        // AX=0E00h — Get Coprocessor Status
        // AX=0E01h — Set Coprocessor Emulation
        // FPU is always available and not emulated.
        0x0E00 => {
            regs.rax = (regs.rax & !0xFFFF) | 0x0E00;
            // BX: bit 0 = MPv (FPU exists), bits 4-7 = FPU type (4=487SX+)
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0041;
            clear_carry(regs);
        }
        0x0E01 => {
            clear_carry(regs);
        }
        // AX=0800h — Physical Address Mapping
        // BX:CX = physical address, SI:DI = size
        // Returns BX:CX = linear address
        0x0800 => {
            let phys = ((regs.rbx as u32 & 0xFFFF) << 16) | (regs.rcx as u32 & 0xFFFF);
            let size = ((regs.rsi as u32 & 0xFFFF) << 16) | (regs.rdi as u32 & 0xFFFF);
            let aligned = (size + 0xFFF) & !0xFFF;
            // Allocate virtual range from DPMI linear memory pool
            let base = dpmi.mem_next;
            dpmi.mem_next = dpmi.mem_next.wrapping_add(aligned);
            dos.dpmi_mem_next = dos.dpmi_mem_next.max(dpmi.mem_next);
            // Map physical pages at the allocated virtual address via ring-0 arch call
            let num_pages = aligned as usize / 4096;
            let vpage_start = base as usize / 4096;
            let ppage_start = phys as u64 / 4096;
            // PWT (bit 3) + PCD (bit 4): write-through, cache-disable for MMIO
            machine.map_phys_range(vpage_start, num_pages, ppage_start, (1 << 3) | (1 << 4));
            // Return linear address
            regs.rbx = (regs.rbx & !0xFFFF) | ((base >> 16) as u64);
            regs.rcx = (regs.rcx & !0xFFFF) | ((base & 0xFFFF) as u64);
            clear_carry(regs);
        }
        // AX=0801h — Free Physical Address Mapping (no-op, we don't track)
        0x0801 => {
            clear_carry(regs);
        }
        _ => {
            dos_trace!("  DPMI: unhandled INT 31h AX={:04X} BX={:04X} CX={:04X} DX={:04X} CS:EIP={:04x}:{:#x}",
                ax, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
                regs.code_seg(), regs.ip32());
            set_carry(regs);
            regs.rax = (regs.rax & !0xFFFF) | 0x8001; // unsupported function
        }
    }

    dos_trace!("[INT31 RET] AX={:04x} CF={:x} | BX={:04x} CX={:04x} DX={:04x} SI={:04x} DI={:04x} DS={:04x} ES={:04x}",
        regs.rax as u16, regs.frame.rflags & 1,
        regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
        regs.rsi as u16, regs.rdi as u16, regs.ds as u16, regs.es as u16);
    trace_client_selector_leak("dpmi_int31.exit", regs);
    thread::KernelAction::Done
}

// ============================================================================
// Real-mode callbacks (INT 31h/0300h, 0301h)
// ============================================================================
