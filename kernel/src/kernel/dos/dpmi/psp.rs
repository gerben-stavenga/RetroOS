use super::*;
use super::state::PspCacheEntry;

/// One-shot at DPMI entry: install the initial PSP selector and (per
/// spec 4.1) convert PSP[0x2C] env segment to a selector. Pre-seeds the
/// PSP cache with `(initial_psp, PSP_SEL)` so the well-known LDT[18]
/// keeps its CWSDPMI-shape value for clients that probe.
///
/// Does NOT touch `dos.current_psp` — that's pure DOS state and stays as
/// the segment value the entering program had.
pub(in crate::kernel::dos) fn install_dpmi_psp_view<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>) {
    let rm_psp = dos.current_psp;
    let psp_base = (rm_psp as u32) * 16;
    let env_seg = machine.read::<u16>((psp_base + 0x2C) as usize);

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
    dpmi.psp_cache[0] = PspCacheEntry { segment: rm_psp, selector: PSP_SEL };

    // Env conversion: PSP[0x2C] segment → selector. One-shot per spec
    // 4.1; never re-toggled. 16-bit Borland-family clients (DPMI16BI /
    // RTM) and 32-bit extenders (DOS/4GW) both observe selector form here.
    dpmi.env_ldt_idx = 0;
    if env_seg != 0
        && let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
            let env_base = (env_seg as u32) * 16;
            dos.ldt[idx] = make_data_desc_ex(env_base, 0xFFFF, false);
            let env_sel = idx_to_sel(idx);
            machine.write::<u16>((psp_base + 0x2C) as usize, env_sel);
            dpmi.env_ldt_idx = idx;
        }
}

/// Look up an existing PSP selector for `segment`, or allocate a new one.
/// Mirrors HDPMI's `allocxsel(seg, limit=0xFF)`: per-segment stable
/// mapping, fresh LDT slot on first sight. Returns 0 on alloc failure.
pub(in crate::kernel::dos) fn get_or_alloc_psp_sel<A: crate::Arch>(
    dos: &mut thread::DosState<A>,
    segment: u16,
) -> u16 {
    if let Some(dpmi) = dos.dpmi.as_ref() {
        for entry in &dpmi.psp_cache {
            if entry.selector != 0 && entry.segment == segment {
                return entry.selector;
            }
        }
    }
    // PMDOS also serves NE clients without a DPMI layer. Their loader already
    // installed the PSP descriptor; reuse it rather than allocating an alias
    // on every AH=51h/62h call.
    if dos.dpmi.is_none()
        && let Some(index) = dos.ldt.iter().position(|&d|
            d & (1 << 47) != 0 && d & (1 << 43) == 0
            && desc_base(d) == u32::from(segment) * 16 && desc_limit(d) >= 0xff)
    {
        return idx_to_sel(index);
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
pub(in crate::kernel::dos) fn psp_sel_to_segment<A: crate::Arch>(
    dos: &thread::DosState<A>,
    selector: u16,
) -> Option<u16> {
    if dos.dpmi.is_none() {
        if selector & 7 != 7 { return None; }
        let desc = *dos.ldt.get(usize::from(selector >> 3))?;
        let base = desc_base(desc);
        return (desc & (1 << 47) != 0 && desc & (1 << 43) == 0
            && base & 15 == 0 && base < 0x100000 && desc_limit(desc) >= 0xff)
            .then_some((base >> 4) as u16);
    }
    let dpmi = dos.dpmi.as_ref()?;
    for entry in &dpmi.psp_cache {
        if entry.selector != 0 && entry.selector == selector {
            return Some(entry.segment);
        }
    }
    None
}
