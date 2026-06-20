//! Segment resolution + canonical event types, mirroring the parts of
//! `kernel/src/arch/monitor.rs` the kernel/dos layers reach for.
//!
//! `KernelEvent`/`IoSize` are the shared contract (re-exported from `arch-abi`).
//! `seg_base`/`seg_is_32`/`sw_reflect_vm86_int` are consulted by the DOS/VM86
//! personality; the interpreter resolves them against its software descriptor
//! model, built out in Milestone 2.

pub use arch_abi::{IoSize, KernelEvent};
use arch_abi::Regs;

/// Linear base of selector `sel` in the active descriptor tables.
pub fn seg_base(sel: u16) -> u32 {
    crate::desc::seg_base(sel)
}

/// Whether selector `sel` is a 32-bit (D=1) segment.
pub fn seg_is_32(sel: u16) -> bool {
    crate::desc::seg_is_32(sel)
}

/// Synthesize a real-mode `INT n` on the guest's VM86 stack: push FLAGS/CS/IP,
/// clear IF/TF, and load CS:IP from the real-mode IVT at `vector*4`. Mirrors the
/// CPU's real-mode INT delivery (and the metal monitor's `sw_reflect_vm86_int`).
///
/// # Safety
/// Reads/writes guest VM86 memory (the IVT at linear 0 and the SS:SP stack).
pub unsafe fn sw_reflect_vm86_int(regs: &mut Regs, vector: u8) {
    const VIF_FLAG: u32 = 1 << 19; // guest virtual IF (canonical store)
    const IF_FLAG: u32 = 1 << 9;   // real IF (host-only); guest's view in bit 9
    const TF_FLAG: u32 = 1 << 8;
    let m = crate::vcpu::mem();

    let ivt = (vector as u32) * 4;
    let new_ip = m.read::<u16>(ivt as usize);
    let new_cs = m.read::<u16>((ivt + 2) as usize);

    let ss_base = (regs.stack_seg() as u32) << 4;
    let mut sp = regs.sp32() & 0xFFFF;
    let mut push = |val: u16| {
        sp = sp.wrapping_sub(2) & 0xFFFF;
        m.write::<u16>((ss_base + sp) as usize, val);
    };
    // The guest observes its virtual IF (VIF) in the bit-9 (IF) slot of the
    // pushed FLAGS; INT-n then clears the guest's IF → clear VIF, not real IF.
    let f = regs.flags32();
    let guest_flags = (f & !(IF_FLAG | VIF_FLAG)) | if f & VIF_FLAG != 0 { IF_FLAG } else { 0 };
    push(guest_flags as u16);
    push(regs.code_seg());
    push(regs.ip32() as u16);

    regs.set_sp32((regs.sp32() & !0xFFFF) | sp);
    regs.clear_flag32(VIF_FLAG);
    regs.clear_flag32(TF_FLAG);
    regs.set_cs32(new_cs as u32);
    regs.set_ip32(new_ip as u32);
}
