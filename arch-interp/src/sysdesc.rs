//! Guest-side system-descriptor infrastructure shared by both engines: the SYS
//! window (GDT/LDT/trampoline/ring-0 stack frames mapped into every space), the
//! table writer, and the EFLAGS entry/exit normalization helpers.
//!
//! Moved out of `cpu.rs` (the TCG engine) because the KVM engine consumes the
//! exact same tables and flag conventions: the window frames are real guest
//! physical memory holding real descriptors, so whichever CPU executes the
//! guest — softmmu or hardware — walks identical structures. Engine-specific
//! programming of GDTR/LDTR (Unicorn MMR writes vs `KVM_SET_SREGS`) stays in
//! the engines.

// ── EFLAGS bits + the virtual-IF projection ─────────────────────────────────

pub(crate) const IF_FLAG: u32 = 1 << 9;
pub(crate) const TF_FLAG: u32 = 1 << 8;
/// NT (Nested Task, EFLAGS bit 14). A real `INT` clears NT on entry, so DOS/DPMI
/// guests never legitimately run with it set; the interp's software INT
/// reflection doesn't clear it, so a once-set NT would persist and turn the
/// guest's next `IRET` into a task-switch return (wild fault). We strip it on
/// every guest entry so the interp matches metal (NT=0). Without this, Dos
/// Navigator's launch path faults with Borland RTE 204.
pub(crate) const NT_FLAG: u32 = 1 << 14;
/// VIF (EFLAGS bit 19) — the kernel's canonical store for the guest's virtual
/// interrupt flag, shared with arch-metal. Both engines run the guest with its
/// IF in the native bit-9 slot, so the entry/exit boundary mirrors between the
/// two: bit 9 ← VIF on the way into the guest, VIF ← bit 9 on the way out.
pub(crate) const VIF_FLAG: u32 = 1 << 19;
pub(crate) const VM_FLAG: u64 = 1 << 17;
pub(crate) const IOPL_MASK: u64 = 3 << 12;

/// Entry: project the guest's virtual IF (VIF/bit 19) into the bit-9 (IF) slot
/// the executing CPU runs with.
#[inline]
pub(crate) fn vif_to_if(flags: u32) -> u32 {
    let vif = flags & VIF_FLAG != 0;
    (flags & !IF_FLAG) | if vif { IF_FLAG } else { 0 }
}

/// Exit: mirror the executed IF (bit 9) back into VIF (bit 19), and set the real
/// IF (bit 9) = 1 — the host-side invariant (the host owns preemption — the TCG
/// instruction budget or the KVM timer kick — so the real IF never gates guest
/// state).
#[inline]
pub(crate) fn if_to_vif(flags: u32) -> u32 {
    let vif = flags & IF_FLAG != 0;
    (flags & !VIF_FLAG) | IF_FLAG | if vif { VIF_FLAG } else { 0 }
}

// ── High scratch window: descriptor tables + supervisor scraps ───────────────
//
// To run a protected-mode client (Linux flat-32 *or* a 16/32-bit DPMI client)
// the CPU must resolve segment selectors through real descriptor tables — a
// write to a segment register in PM loads base/limit/D from the GDT/LDT in
// *guest* memory. We reserve a window above the user VA range (the MMU never
// maps there) and place there:
//   * a small GDT mirroring the kernel's flat ring-0/ring-3 + BDA + TLS slots,
//   * the active LDT (copied from the kernel's table — DPMI descriptors live
//     there), pointed at by LDTR,
//   * a one-byte `iretd` trampoline plus a ring-0 stack (TCG engine: CPL only
//     becomes 3 by *returning* to a DPL-3 stack, so each PM entry resets to
//     CPL 0 and `iretd`s through a CPL-0→3 frame — exactly how real kernels
//     enter ring 3; the KVM engine instead sets the segment caches directly).
pub(crate) const SYS_BASE: u64 = 0xFFFE_0000;
pub(crate) const GDT_ADDR: u64 = SYS_BASE; // 256-byte GDT (32 entries)
pub(crate) const LDT_ADDR: u64 = SYS_BASE + 0x1000; // up to LDT_MAX_BYTES
pub(crate) const TRAMP_ADDR: u64 = SYS_BASE + 0x5000; // the `iretd` byte (TCG)
pub(crate) const RING0_SP_TOP: u64 = SYS_BASE + 0x7000; // ring-0 stack top (frame just below)
// KVM-engine pages (the in-guest trap shim; unused — but still allocated and
// mapped — on the TCG engine, whose traps surface as Unicorn hooks instead):
#[cfg(feature = "kvm")]
pub(crate) const IDT_ADDR: u64 = SYS_BASE + 0x8000; // 256 × 8-byte interrupt gates
#[cfg(feature = "kvm")]
pub(crate) const STUB_ADDR: u64 = SYS_BASE + 0x9000; // 256 × 16-byte exit stubs
pub(crate) const TSS_ADDR: u64 = SYS_BASE + 0xA000; // TSS + all-deny IOPB
pub(crate) const SYS_SIZE: usize = 0xB000;
pub(crate) const GDT_BYTES: usize = 32 * 8;
pub(crate) const LDT_MAX_BYTES: usize = 0x4000; // 2048 descriptors

// Flat ring-0 selectors the supervisor scraps run under (GDT indices 1 and 3,
// to match the kernel's `descriptors.rs` KERNEL_CS=0x08 / KERNEL_DS=0x18 layout).
pub(crate) const KERNEL_CS: u16 = 0x08;
pub(crate) const KERNEL_DS: u16 = 0x18;
/// TSS selector (GDT slot 9 — unused by the kernel's layout). The KVM engine's
/// TR points here for the CPL3→CPL0 stack switch (TSS.esp0) and the IOPB.
pub(crate) const TSS_SEL: u16 = 0x48;
/// LDT selector value (GDT slot 12 on metal). Both engines program the LDT
/// base/limit directly, so the selector is cosmetic, but keep the kernel's
/// value for fidelity.
pub(crate) const LDT_SEL: u16 = 0x60;

/// Pack a legacy 8-byte segment descriptor. `flags4` is the high nibble
/// (G, D/B, L, AVL); `access` is the type/DPL/P byte.
pub(crate) fn gdt_desc(base: u32, limit: u32, access: u8, flags4: u8) -> u64 {
    (limit as u64 & 0xFFFF)
        | ((base as u64 & 0xFFFF) << 16)
        | (((base as u64 >> 16) & 0xFF) << 32)
        | ((access as u64) << 40)
        | (((limit as u64 >> 16) & 0xF) << 48)
        | ((flags4 as u64 & 0xF) << 52)
        | (((base as u64 >> 24) & 0xFF) << 56)
}

/// The contiguous guest-physical frames backing the SYS window (GDT, LDT,
/// trampoline, ring-0 stack), shared by every address space. Allocated once;
/// `register_kernel_window` maps `SYS_BASE` onto them in every page directory.
static SYS_FRAMES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

pub(crate) fn sys_base_frame() -> u64 {
    *SYS_FRAMES.get().expect("SYS window not initialized")
}

/// Host pointer to a SYS-window linear address (the frames are contiguous, so
/// the linear offset within the window is the offset within the frame run).
pub(crate) fn sys_ptr(linear: u64) -> *mut u8 {
    unsafe { crate::phys::frame_ptr(sys_base_frame()).add((linear - SYS_BASE) as usize) }
}

/// Physical address of a SYS-window linear address (for GDTR/LDTR base while
/// paging is momentarily off during the TCG CPL0 bootstrap).
#[cfg(feature = "tcg")]
pub(crate) fn sys_phys(linear: u64) -> u64 {
    (crate::paging::frame_phys(sys_base_frame()) as u64) + (linear - SYS_BASE)
}

/// Allocate the SYS frames, seed the `iretd` trampoline byte, and register the
/// window so every page directory (existing and future) maps it. Idempotent.
pub(crate) fn ensure_sys_window() {
    SYS_FRAMES.get_or_init(|| {
        let frames = crate::phys::alloc_frames(SYS_SIZE / 4096);
        unsafe { *crate::phys::frame_ptr(frames).add((TRAMP_ADDR - SYS_BASE) as usize) = 0xCF; }
        crate::paging::register_kernel_window((SYS_BASE / 4096) as usize, frames, SYS_SIZE / 4096);
        frames
    });
}

/// Refresh the GDT (flat ring-0/ring-3 + BDA alias + present TLS slots) and the
/// LDT (the kernel's active table) in the SYS-window frames. Returns the LDT
/// byte limit (the GDTR/LDTR bases are set by the engine, which knows its
/// paging phase). Writes go to the shared phys frames, not through the CPU.
pub(crate) fn write_tables() -> u32 {
    use arch_abi::{USER_CS, USER_DS};
    let mut gdt = [0u64; 32];
    gdt[(KERNEL_CS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0x9A, 0xC); // ring-0 code32
    gdt[(KERNEL_DS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0x92, 0xC); // ring-0 data32
    gdt[(USER_CS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0xFA, 0xC); // ring-3 code32 (Linux)
    gdt[(USER_DS >> 3) as usize] = gdt_desc(0, 0xF_FFFF, 0xF2, 0xC); // ring-3 data32 (Linux)
    gdt[8] = gdt_desc(0x400, 0xFFFF, 0xF2, 0x4); // 0x40: BIOS Data Area alias (DPMI compat)
    // 0x48: the KVM engine's 32-bit TSS (type 0xB = busy — VM entry requires TR
    // busy). Present in the GDT on both engines for one canonical table image;
    // nothing on the TCG engine ever loads it.
    gdt[(TSS_SEL >> 3) as usize] = gdt_desc(TSS_ADDR as u32, 0x1FF, 0x8B, 0x0);
    crate::desc::for_each_tls(|idx, base, _limit| {
        if idx < 32 {
            gdt[idx] = gdt_desc(base, 0xF_FFFF, 0xF2, 0xC);
        }
    });
    let gp = sys_ptr(GDT_ADDR);
    for (i, d) in gdt.iter().enumerate() {
        unsafe { core::ptr::copy_nonoverlapping(d.to_le_bytes().as_ptr(), gp.add(i * 8), 8); }
    }

    let ldt = crate::desc::ldt_raw();
    let n = ldt.len().min(LDT_MAX_BYTES / 8);
    let lp = sys_ptr(LDT_ADDR);
    for (i, d) in ldt.iter().take(n).enumerate() {
        unsafe { core::ptr::copy_nonoverlapping(d.to_le_bytes().as_ptr(), lp.add(i * 8), 8); }
    }
    if n == 0 { 0 } else { (n * 8 - 1) as u32 }
}
