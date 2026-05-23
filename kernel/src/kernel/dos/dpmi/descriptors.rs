use super::*;
use super::super::mode_transitions;

const TRACE_DPMI_SELECTORS: &[u16] = &[];

pub(super) fn trace_dpmi_desc(label: &str, sel: u16, desc: u64) {
    if TRACE_DPMI_SELECTORS.contains(&sel) {
        crate::println!(
            "[DPMI-DESC] {} sel={:04X} base={:08X} limit={:08X} raw={:016X}",
            label,
            sel,
            DpmiState::desc_base(desc),
            DpmiState::desc_limit(desc),
            desc,
        );
    }
}

/// Populate the kernel-owned LDT slots and default pm_vectors. Called from
/// `DosState::new()` so the PMDOS infrastructure is always live — HW IRQ
/// routing can use it even before any DPMI client has called dpmi_enter.
pub(in crate::kernel::dos) fn install_kernel_ldt_slots(dos: &mut thread::DosState) {
    // Reserve + install each kernel slot.
    let mark = |dos: &mut thread::DosState, idx: usize, desc: u64| {
        dos.ldt[idx] = desc;
        dos.ldt_alloc[idx / 32] |= 1 << (idx % 32);
    };
    mark(dos, mode_transitions::VECTOR_STUB_LDT_IDX,  DpmiState::make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, mode_transitions::SPECIAL_STUB_LDT_IDX, DpmiState::make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, LOW_MEM_LDT_IDX,      DpmiState::make_data_desc_ex(0, 0xFFFFF, false));
    // Both PM aliases at the same base — SP value is offset-portable across
    // the three views (PM16/PM32/VM86 paragraph) of the same physical buffer.
    let host_base = dos::host_stack_base();
    let host_limit = dos::host_stack_size() - 1;
    mark(dos, mode_transitions::HOST_STACK_PM16_LDT_IDX, DpmiState::make_data_desc_ex(host_base, host_limit, false));
    mark(dos, mode_transitions::HOST_STACK_PM32_LDT_IDX, DpmiState::make_data_desc_ex(host_base, host_limit, true));
    // `enter_pm_psp_view` fills PSP_LDT_IDX on each RM→PM transition.
    dos.ldt_alloc[PSP_LDT_IDX / 32] |= 1 << (PSP_LDT_IDX % 32);

    reset_pm_vectors(dos);
}

/// Fill `dos.pm_vectors` with the default `vector_stub` entries. Each vector
/// traps to its own CD 31 slot in the vector-stub segment; `vector_stub_reflect`
/// then reflects the interrupt to the real-mode IVT. Called from thread init
/// and from the EXEC path so a child never inherits a DPMI parent's hooks.
pub(in crate::kernel::dos) fn reset_pm_vectors(dos: &mut thread::DosState) {
    for i in 0..256 {
        dos.pm_vectors[i] = (mode_transitions::VECTOR_STUB_SEL, dos::STUB_BASE + (i as u32) * 2);
    }
}

// ── LDT bitmap helpers — operate on the thread-wide `dos.ldt`/`ldt_alloc` ──
//
// Descriptor *layout* helpers (make_*_desc_ex, set_desc_base, desc_base, …)
// stay as associated fns on DpmiState since they're pure; the bitmap-mutating
// allocators live here because they own the placement policy (l_free == 16)
// and the free/alloc state is part of DosState now.

/// Allocate an LDT selector. Returns index (16..LDT_ENTRIES) or None.
/// Starts at 16 to match CWSDPMI's `l_free`, leaving LDT[1..15] null so
/// DOS/4GW's `lar`-probe of low slots sees an empty range like CWSDPMI does.
///
/// Takes `ldt_alloc` as `&mut [u32]` (not `&mut DosState`) so call sites that
/// already hold `&mut dos.dpmi` can still invoke via disjoint field borrow:
/// `alloc_ldt(&mut dos.ldt_alloc)`.
pub(in crate::kernel::dos) fn alloc_ldt(ldt_alloc: &mut [u32]) -> Option<usize> {
    for idx in 16..LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        if ldt_alloc[word] & (1 << bit) == 0 {
            ldt_alloc[word] |= 1 << bit;
            dos_trace!("[DPMI] alloc_ldt -> idx={} sel={:04X}", idx, DpmiState::idx_to_sel(idx));
            return Some(idx);
        }
    }
    dos_trace!("[DPMI] alloc_ldt FAILED (LDT full)");
    None
}

/// Allocate a contiguous run of LDT selectors. Returns the first index.
pub(in crate::kernel::dos) fn alloc_ldt_range(ldt_alloc: &mut [u32], count: usize) -> Option<usize> {
    if count == 0 || count >= LDT_ENTRIES {
        return None;
    }
    'outer: for first in 16..=(LDT_ENTRIES - count) {
        for idx in first..(first + count) {
            let word = idx / 32;
            let bit = idx % 32;
            if ldt_alloc[word] & (1 << bit) != 0 {
                continue 'outer;
            }
        }
        for idx in first..(first + count) {
            let word = idx / 32;
            let bit = idx % 32;
            ldt_alloc[word] |= 1 << bit;
        }
        dos_trace!("[DPMI] alloc_ldt_range({}) -> idx={}..{} sel={:04X}..{:04X}",
            count, first, first + count - 1,
            DpmiState::idx_to_sel(first), DpmiState::idx_to_sel(first + count - 1));
        return Some(first);
    }
    dos_trace!("[DPMI] alloc_ldt_range({}) FAILED", count);
    None
}

/// Free an LDT selector by index (clears the descriptor and its alloc bit).
pub(in crate::kernel::dos) fn free_ldt(ldt: &mut [u64], ldt_alloc: &mut [u32], idx: usize) {
    if idx > 0 && idx < LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        ldt_alloc[word] &= !(1 << bit);
        ldt[idx] = 0;
    }
}

pub(in crate::kernel::dos) fn ldt_is_allocated(ldt_alloc: &[u32], idx: usize) -> bool {
    if idx >= LDT_ENTRIES {
        return false;
    }
    let word = idx / 32;
    let bit = idx % 32;
    ldt_alloc[word] & (1 << bit) != 0
}
