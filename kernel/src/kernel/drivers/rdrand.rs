//! Optional x86 hardware entropy source.
use crate::kernel::random::Unavailable;

pub fn fill(bytes: &mut [u8]) -> Result<(), Unavailable> {
    #[cfg(target_arch = "x86")]
    {
        // Early 486/386 machines lack CPUID: test the ID bit before using it.
        let before: u32;
        let after: u32;
        let changed: u32;
        unsafe {
            core::arch::asm!(
                "pushfd", "pop {before:e}", "mov {changed:e}, {before:e}", "xor {changed:e}, 0x200000",
                "push {changed:e}", "popfd", "pushfd", "pop {after:e}", "push {before:e}", "popfd",
                before=out(reg)before, after=out(reg)after, changed=out(reg)changed,
            );
        }
        let _ = changed;
        if (before ^ after) & (1 << 21) == 0 {
            return Err(Unavailable);
        }
    }
    #[cfg(target_arch = "x86")]
    let features = core::arch::x86::__cpuid(1).ecx;
    #[cfg(target_arch = "x86_64")]
    let features = core::arch::x86_64::__cpuid(1).ecx;
    if features & (1 << 30) == 0 {
        return Err(Unavailable);
    }
    for chunk in bytes.chunks_mut(4) {
        let mut generated = None;
        for _ in 0..16 {
            let value: u32;
            let valid: u8;
            unsafe {
                core::arch::asm!("rdrand {value:e}", "setc {valid}", value=out(reg)value, valid=out(reg_byte)valid, options(nostack));
            }
            if valid != 0 {
                generated = Some(value.to_ne_bytes());
                break;
            }
        }
        let value = generated.ok_or(Unavailable)?;
        chunk.copy_from_slice(&value[..chunk.len()]);
    }
    Ok(())
}
