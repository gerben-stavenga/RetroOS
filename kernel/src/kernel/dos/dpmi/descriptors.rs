use super::*;
use super::super::mode_transitions;

const TRACE_DPMI_SELECTORS: &[u16] = &[];

/// Convert LDT index to selector (TI=1, RPL=3).
pub(super) fn idx_to_sel(idx: usize) -> u16 {
    ((idx as u16) << 3) | 4 | 3
}

/// Convert selector to LDT index.
pub(super) fn sel_to_idx(sel: u16) -> usize {
    (sel >> 3) as usize
}

/// Build a data descriptor (present, DPL=3, writable).
/// db = D/B bit: false = 16-bit, true = 32-bit.
pub(super) fn make_data_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
    let (limit_val, g) = if limit > 0xFFFFF {
        (limit >> 12, 1u64)
    } else {
        (limit, 0u64)
    };
    let access: u64 = 0xF2;
    let flags: u64 = (g << 7) | ((db as u64) << 6);
    build_descriptor(base, limit_val, access, flags)
}

/// Build a 32-bit data descriptor (present, DPL=3, writable).
pub(super) fn make_data_desc(base: u32, limit: u32) -> u64 {
    make_data_desc_ex(base, limit, true)
}

/// Build a code descriptor (present, DPL=3, readable).
/// db = D bit: false = 16-bit, true = 32-bit.
pub(super) fn make_code_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
    let (limit_val, g) = if limit > 0xFFFFF {
        (limit >> 12, 1u64)
    } else {
        (limit, 0u64)
    };
    let access: u64 = 0xFA;
    let flags: u64 = (g << 7) | ((db as u64) << 6);
    build_descriptor(base, limit_val, access, flags)
}

/// Get the base address from an LDT descriptor.
pub(in crate::kernel::dos) fn desc_base(desc: u64) -> u32 {
    let b0 = ((desc >> 16) & 0xFFFF) as u32;
    let b1 = ((desc >> 32) & 0xFF) as u32;
    let b2 = ((desc >> 56) & 0xFF) as u32;
    b0 | (b1 << 16) | (b2 << 24)
}

/// Get the limit from an LDT descriptor, taking the G bit into account.
pub(in crate::kernel::dos) fn desc_limit(desc: u64) -> u32 {
    let l0 = (desc & 0xFFFF) as u32;
    let l1 = ((desc >> 48) & 0x0F) as u32;
    let raw = l0 | (l1 << 16);
    if desc & (1 << 55) != 0 {
        (raw << 12) | 0xFFF
    } else {
        raw
    }
}

/// Set base address in a descriptor.
pub(super) fn set_desc_base(desc: &mut u64, base: u32) {
    *desc &= !0xFF00_00FF_FFFF_0000;
    *desc |= ((base & 0xFFFF) as u64) << 16;
    *desc |= (((base >> 16) & 0xFF) as u64) << 32;
    *desc |= (((base >> 24) & 0xFF) as u64) << 56;
}

/// Match CWSDPMI segment-to-descriptor reuse heuristic.
pub(super) fn desc_is_seg_alias(desc: u64, base: u32) -> bool {
    let lim0 = (desc & 0xFFFF) as u16;
    let lim1 = ((desc >> 48) & 0xFF) as u8;
    let base0 = ((desc >> 16) & 0xFFFF) as u16;
    let base1 = ((desc >> 32) & 0xFF) as u8;
    let base2 = ((desc >> 56) & 0xFF) as u8;

    lim0 == 0xFFFF
        && lim1 == 0
        && base2 == 0
        && base0 == (base as u16)
        && base1 == ((base >> 16) as u8)
}

/// Set limit in a descriptor, adjusting the G bit.
pub(super) fn set_desc_limit(desc: &mut u64, limit: u32) {
    let (lim, g) = if limit > 0xFFFFF {
        (limit >> 12, true)
    } else {
        (limit, false)
    };
    *desc &= !0x000F_0000_0000_FFFF;
    *desc &= !(1u64 << 55);
    *desc |= (lim & 0xFFFF) as u64;
    *desc |= (((lim >> 16) & 0x0F) as u64) << 48;
    if g {
        *desc |= 1u64 << 55;
    }
}

pub(super) fn trace_dpmi_desc(label: &str, sel: u16, desc: u64) {
    if TRACE_DPMI_SELECTORS.contains(&sel) {
        crate::println!(
            "[DPMI-DESC] {} sel={:04X} base={:08X} limit={:08X} raw={:016X}",
            label,
            sel,
            desc_base(desc),
            desc_limit(desc),
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
    mark(dos, mode_transitions::VECTOR_STUB_LDT_IDX,  make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, mode_transitions::SPECIAL_STUB_LDT_IDX, make_code_desc_ex(0, 0x0FFF, false));
    mark(dos, LOW_MEM_LDT_IDX,      make_data_desc_ex(0, 0xFFFFF, false));
    // Both PM aliases at the same base — SP value is offset-portable across
    // the three views (PM16/PM32/VM86 paragraph) of the same physical buffer.
    let host_base = dos::host_stack_base();
    let host_limit = dos::host_stack_size() - 1;
    mark(dos, mode_transitions::HOST_STACK_PM16_LDT_IDX, make_data_desc_ex(host_base, host_limit, false));
    mark(dos, mode_transitions::HOST_STACK_PM32_LDT_IDX, make_data_desc_ex(host_base, host_limit, true));
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
// Descriptor layout helpers live next to the LDT bitmap allocators because
// both encode the DPMI host's selector policy (l_free == 16).

/// Allocate an LDT selector. Returns index (16..LDT_ENTRIES) or None.
/// Starts at 16 to match CWSDPMI's `l_free`, leaving LDT[1..15] null so
/// DOS/4GW's `lar`-probe of low slots sees an empty range like CWSDPMI does.
///
/// Takes `ldt_alloc` as `&mut [u32]` (not `&mut DosState`) so call sites that
/// already hold `&mut dos.dpmi` can still invoke via disjoint field borrow:
/// `alloc_ldt(&mut dos.ldt_alloc)`.
pub(super) fn alloc_ldt(ldt_alloc: &mut [u32]) -> Option<usize> {
    for idx in 16..LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        if ldt_alloc[word] & (1 << bit) == 0 {
            ldt_alloc[word] |= 1 << bit;
            dos_trace!("[DPMI] alloc_ldt -> idx={} sel={:04X}", idx, idx_to_sel(idx));
            return Some(idx);
        }
    }
    dos_trace!("[DPMI] alloc_ldt FAILED (LDT full)");
    None
}

/// Allocate a contiguous run of LDT selectors. Returns the first index.
pub(super) fn alloc_ldt_range(ldt_alloc: &mut [u32], count: usize) -> Option<usize> {
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
            idx_to_sel(first), idx_to_sel(first + count - 1));
        return Some(first);
    }
    dos_trace!("[DPMI] alloc_ldt_range({}) FAILED", count);
    None
}

/// Free an LDT selector by index (clears the descriptor and its alloc bit).
pub(super) fn free_ldt(ldt: &mut [u64], ldt_alloc: &mut [u32], idx: usize) {
    if idx > 0 && idx < LDT_ENTRIES {
        let word = idx / 32;
        let bit = idx % 32;
        ldt_alloc[word] &= !(1 << bit);
        ldt[idx] = 0;
    }
}

pub(super) fn ldt_is_allocated(ldt_alloc: &[u32], idx: usize) -> bool {
    if idx >= LDT_ENTRIES {
        return false;
    }
    let word = idx / 32;
    let bit = idx % 32;
    ldt_alloc[word] & (1 << bit) != 0
}

/// Build an x86 segment descriptor from components.
/// flags: high nibble of byte 6: bit 7 = G, bit 6 = D/B, bit 5 = L, bit 4 = AVL.
fn build_descriptor(base: u32, limit: u32, access: u64, flags: u64) -> u64 {
    let mut desc: u64 = 0;
    desc |= (limit & 0xFFFF) as u64;
    desc |= ((base & 0xFFFF) as u64) << 16;
    desc |= (((base >> 16) & 0xFF) as u64) << 32;
    desc |= (access & 0xFF) << 40;
    let byte6 = (((limit >> 16) & 0x0F) as u64) | (flags & 0xF0);
    desc |= byte6 << 48;
    desc |= (((base >> 24) & 0xFF) as u64) << 56;
    desc
}
