use super::*;

/// RM→PM transition: build the PM-side PSP view from the active RM PSP.
///
/// Captures the current RM PSP segment and PSP[0x2C] (so PM→RM can restore
/// them), rebuilds the fixed `PSP_SEL` LDT[4] descriptor with base = current
/// RM PSP * 16, and (for 32-bit clients per DPMI 0.9 §4.1) allocates a fresh
/// env selector and patches PSP[0x2C] to point at it. Finally sets
/// `dos.current_psp = PSP_SEL` so PM-side AH=51/62 reflections return a value
/// the client can load into ES.
///
/// 16-bit clients (DOS/16M) read PSP[0x2C] as an RM segment, so leave it
/// unpatched — the env_ldt_idx stays 0 and PM→RM has nothing to undo.
pub(in crate::kernel::dos) fn enter_pm_psp_view(dos: &mut thread::DosState) {
    if dos.current_psp == PSP_SEL {
        return;
    }

    let rm_psp = dos.current_psp;
    let psp_base = (rm_psp as u32) * 16;
    let env_seg = unsafe { core::ptr::read_volatile((psp_base + 0x2C) as *const u16) };

    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };

    dpmi.saved_rm_psp = rm_psp;
    dpmi.saved_rm_env = env_seg;

    // PSP_SEL descriptor: base = active RM PSP, limit = 64K. Spec says
    // limit=100h but real extenders (DOS/4GW) reuse ES as scratch and need
    // the full 64K window.
    dos.ldt[PSP_LDT_IDX] = DpmiState::make_data_desc_ex(psp_base, 0xFFFF, false);
    dos.ldt_alloc[0] |= 1 << PSP_LDT_IDX;

    dpmi.env_ldt_idx = 0;
    if dpmi.client_use32 && env_seg != 0 {
        if let Some(idx) = alloc_ldt(&mut dos.ldt_alloc) {
            let env_base = (env_seg as u32) * 16;
            dos.ldt[idx] = DpmiState::make_data_desc_ex(env_base, 0xFFFF, false);
            let env_sel = DpmiState::idx_to_sel(idx);
            unsafe { core::ptr::write_volatile((psp_base + 0x2C) as *mut u16, env_sel); }
            dpmi.env_ldt_idx = idx;
        }
    }

    dos.current_psp = PSP_SEL;
}

/// PM→RM transition: undo the PM-side PSP view set up by `enter_pm_psp_view`.
///
/// Restores the original PSP[0x2C] (32-bit clients), frees the env selector
/// LDT slot, and sets `dos.current_psp` back to the RM PSP segment captured
/// on entry so reflected AH=51/62 returns an RM-loadable value.
pub(in crate::kernel::dos) fn restore_rm_psp_view(dos: &mut thread::DosState) {
    if dos.current_psp != PSP_SEL {
        return;
    }

    let dpmi = match dos.dpmi.as_mut() {
        Some(d) => d,
        None => return,
    };
    let rm_psp = dpmi.saved_rm_psp;
    let psp_base = (rm_psp as u32) * 16;

    if dpmi.env_ldt_idx != 0 {
        unsafe { core::ptr::write_volatile((psp_base + 0x2C) as *mut u16, dpmi.saved_rm_env); }
        let idx = dpmi.env_ldt_idx;
        free_ldt(&mut dos.ldt[..], &mut dos.ldt_alloc, idx);
        dpmi.env_ldt_idx = 0;
    }

    dos.current_psp = rm_psp;
}

pub(in crate::kernel::dos) fn sync_psp_view_for_regs(dos: &mut thread::DosState, regs: &Regs) {
    if regs.mode() == crate::UserMode::VM86 {
        restore_rm_psp_view(dos);
    } else {
        enter_pm_psp_view(dos);
    }
}
