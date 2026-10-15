//! BIOS equipment, memory and system services: INT 11h, 12h and 15h.
use crate::Regs;
use crate::kernel::dos::machine::vm86_set_return_flag;
use super::Bda;

pub(super) fn int11<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let equipment: u16 = bda_field!(machine, equipment);
    regs.rax = (regs.rax & !0xFFFF) | u64::from(equipment);
}

pub(super) fn int12<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let kb: u16 = bda_field!(machine, mem_size_kb);
    regs.rax = (regs.rax & !0xFFFF) | u64::from(kb);
}

pub(super) fn int15<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    match (regs.rax >> 8) as u8 {
        // AH=84h joystick support. We expose no game port, so report all
        // four active-low buttons released and zeroed timing counters.
        // Leaving this call untouched is not a harmless "unsupported"
        // result: old games commonly ignore CF and inspect AL directly;
        // their input AX (84xx) then looks like a permanently held fire
        // button. Dyna Blaster does exactly that in its title/menu loop.
        0x84 => match regs.rdx as u16 {
            0 => {
                regs.rax = (regs.rax & !0xFF) | 0xF0;
                vm86_set_return_flag(machine, regs, 1, false);
            }
            1 => {
                regs.rax &= !0xFFFF;
                regs.rbx &= !0xFFFF;
                regs.rcx &= !0xFFFF;
                regs.rdx &= !0xFFFF;
                vm86_set_return_flag(machine, regs, 1, false);
            }
            _ => {
                regs.rax = (regs.rax & !0xFF00) | 0x8600;
                vm86_set_return_flag(machine, regs, 1, true);
            }
        },
        // AH=87h block move: the ROM does this via a protected-mode LGDT
        // excursion (illegal under VM86). Do the copy directly instead.
        0x87 => int15_block_move(machine, regs),
        // AH=89h switch-to-PM: a VM86 guest cannot take over real PM — the
        // monitor owns it. Refuse, exactly as EMM386 does (DPMI is the
        // sanctioned path). AH=86h = "unsupported", CF set.
        0x89 => {
            regs.rax = (regs.rax & !0xFF00) | 0x8600;
            vm86_set_return_flag(machine, regs, 1, true);
        }
        _ => {},
    }
}

/// INT 15h AH=87h — copy a block to/from extended memory. `ES:SI` → the
/// caller's GDT; descriptor `[0x10]` is the source, `[0x18]` the destination,
/// each carrying a 24/32-bit linear base (bytes 2–4 = base 0–23, byte 7 =
/// 24–31). `CX` = words to copy. We perform the copy directly — the same
/// operation as XMS AH=0Bh (`copy_within`) — instead of letting the ROM `LGDT`
/// into protected mode, which is illegal under VM86.
fn int15_block_move<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let gdt = ((regs.es as u32) << 4) + (regs.rsi as u32 & 0xFFFF);
    let base = |desc: u32| -> u32 {
        let d = (gdt + desc) as usize;
        (machine.read::<u16>(d + 2) as u32)                      // base bits 0–15
            | (((machine.read::<u16>(d + 4) as u32) & 0xFF) << 16) // byte 4: bits 16–23
            | (((machine.read::<u16>(d + 6) as u32) >> 8) << 24)   // byte 7: bits 24–31
    };
    let src = base(0x10);
    let dst = base(0x18);
    let len = (regs.rcx as usize & 0xFFFF) * 2;
    machine.copy_within(src as usize, dst as usize, len);
    regs.rax &= !0xFF00;       // AH = 0 (success)
    vm86_set_return_flag(machine, regs, 1, false);  // CF = 0
}
