use super::*;
use super::state::PspCacheEntry;

/// One-shot at DPMI entry: install the initial PSP selector and (per
/// spec 4.1) convert PSP[0x2C] env segment to a selector. Pre-seeds the
/// PSP cache with `(initial_psp, PSP_SEL)` so the well-known LDT[18]
/// keeps its CWSDPMI-shape value for clients that probe.
///
/// Does NOT touch `dos.current_psp` — that's pure DOS state and stays as
/// the segment value the entering program had.
pub(in crate::kernel::dos) fn install_dpmi_psp_view(dos: &mut thread::DosState, regs: &mut Vcpu) {
    let rm_psp = dos.current_psp;
    let psp_base = (rm_psp as u32) * 16;
    let env_seg = regs.read::<u16>(((psp_base + 0x2C)) as usize);

    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };

    dpmi.saved_rm_psp = rm_psp;
    dpmi.saved_rm_env = env_seg;

    // PSP_SEL (= LDT[18]) descriptor: base = initial PSP, limit = 64K. Spec
    // says 100h but DOS/4GW reuses ES as scratch and needs 64K.
    dos.ldt[PSP_LDT_IDX] = make_data_desc_ex(psp_base, 0xFFFF, false);
    dos.ldt_alloc[0] |= 1 << PSP_LDT_IDX;

    // Seed the PSP cache with the initial PSP → PSP_SEL mapping so AH=51
    // returns PSP_SEL for this PSP and AH=50 maps PSP_SEL back to the
    // segment.
    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.psp_cache[0] = PspCacheEntry { segment: rm_psp, selector: PSP_SEL };
    }

    // Env conversion: PSP[0x2C] segment → selector. One-shot per spec
    // 4.1; never re-toggled. 16-bit Borland-family clients (DPMI16BI /
    // RTM) and 32-bit extenders (DOS/4GW) both observe selector form here.
    if let Some(dpmi) = dos.dpmi.as_mut() {
        dpmi.env_ldt_idx = 0;
    }
    if env_seg != 0 {
        if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
            let env_base = (env_seg as u32) * 16;
            dos.ldt[idx] = make_data_desc_ex(env_base, 0xFFFF, false);
            let env_sel = idx_to_sel(idx);
            regs.write::<u16>((psp_base + 0x2C) as usize, env_sel);
            if let Some(dpmi) = dos.dpmi.as_mut() {
                dpmi.env_ldt_idx = idx;
            }
        }
    }
}

/// Look up an existing PSP selector for `segment`, or allocate a new one.
/// Mirrors HDPMI's `allocxsel(seg, limit=0xFF)`: per-segment stable
/// mapping, fresh LDT slot on first sight. Returns 0 on alloc failure.
pub(in crate::kernel::dos) fn get_or_alloc_psp_sel(
    dos: &mut thread::DosState,
    segment: u16,
) -> u16 {
    if let Some(dpmi) = dos.dpmi.as_ref() {
        for entry in &dpmi.psp_cache {
            if entry.selector != 0 && entry.segment == segment {
                return entry.selector;
            }
        }
    }
    let idx = match alloc_ldt(&mut dos.ldt_alloc) {
        Some(i) => i,
        None => return 0,
    };
    let psp_base = (segment as u32) * 16;
    dos.ldt[idx] = make_data_desc_ex(psp_base, 0xFF, false);
    let sel = idx_to_sel(idx);
    if let Some(dpmi) = dos.dpmi.as_mut() {
        for entry in dpmi.psp_cache.iter_mut() {
            if entry.selector == 0 {
                *entry = PspCacheEntry { segment, selector: sel };
                break;
            }
        }
    }
    sel
}

/// Reverse lookup: PSP selector → RM segment. Used by AH=50 in PM to
/// translate a client-passed selector back to the segment value RM DOS
/// needs. Returns `None` if `selector` isn't a known PSP selector — the
/// caller should treat the value as already being a segment (matches
/// HDPMI's `bx_sel2segm` fallthrough).
pub(in crate::kernel::dos) fn psp_sel_to_segment(
    dos: &thread::DosState,
    selector: u16,
) -> Option<u16> {
    let dpmi = dos.dpmi.as_ref()?;
    for entry in &dpmi.psp_cache {
        if entry.selector != 0 && entry.selector == selector {
            return Some(entry.segment);
        }
    }
    None
}
