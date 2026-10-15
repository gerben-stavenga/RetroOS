//! BIOS timer IRQ and clock services: INT 08h and INT 1Ah.
use crate::Regs;
use crate::kernel::dos::{dos, machine, DosState};
use crate::kernel::dos::dosabi::STUB_SEG;
use machine::{read_u16};
use crate::kernel::dos::machine::vm86_set_return_flag;
use super::Bda;

/// Returns true when INT 1Ch was chained using the existing IRET frame.
pub(super) fn int08<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs) -> bool {
    // Timer tick. EOI before the 1C chain (the C BIOS EOI'd after
    // geninterrupt(0x1C) returned; chaining by frame-reuse means we
    // never regain control, so the EOI moves ahead of the handler).
    let t: u32 = bda_field!(machine, tick_count);
    bda_field!(machine, tick_count = t.wrapping_add(1));
    let motor_ticks: u8 = bda_field!(machine, diskette_motor_timeout);
    if motor_ticks != 0 {
        let motor_ticks = motor_ticks - 1;
        bda_field!(machine, diskette_motor_timeout = motor_ticks);
        if motor_ticks == 0 {
            let status: u8 = bda_field!(machine, diskette_motor_status);
            bda_field!(machine, diskette_motor_status = status & 0xF0);
        }
    }
    dos.pc.vpic.master_ocw2(0x60); // Specific EOI: IRQ0
    // Chain the user timer tick like a real INT 08 does. The
    // selector tells us whether anyone hooked INT 1C — unhooked
    // points back into this array (a no-op), so skip the bounce.
    let seg = read_u16(machine, 0, 0x1C * 4 + 2);
    if seg != STUB_SEG {
        let off = read_u16(machine, 0, 0x1C * 4);
        // Reuse the caller's IRET frame: the 1C handler's IRET
        // returns straight to the interrupted code.
        machine::set_vm86_cs(regs, seg);
        machine::set_vm86_ip(regs, off);
        return true;
    }
    false
}

// ============================================================================
// INT 1Ah: system timer
// ============================================================================

pub(super) fn int1a<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let ah = (regs.rax >> 8) as u8;
    match ah {
        0x00 => {
            // Read tick count: CX:DX = ticks, AL = midnight flag.
            let ticks: u32 = bda_field!(machine, tick_count);
            regs.rcx = (regs.rcx & !0xFFFF) | (ticks >> 16) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | (ticks & 0xFFFF) as u64;
            regs.rax &= !0xFF; // AL = 0 (no rollover)
        }
        0x01 => {
            // Set tick count from CX:DX.
            let t = ((regs.rcx as u16 as u32) << 16) | regs.rdx as u16 as u32;
            bda_field!(machine, tick_count = t);
        }
        0x02 => {
            // Read RTC time: CH=hours CL=minutes DH=seconds DL=DST flag,
            // all BCD, CF clear on success — the real AT BIOS ABI. Backed
            // by the host CMOS like the 40:6C seed.
            let (hour, min, sec) = dos::rtc_time(machine);
            let bcd = |v: u8| ((v / 10) << 4) | (v % 10);
            regs.rcx = (regs.rcx & !0xFFFF)
                | ((bcd(hour) as u64) << 8)
                | bcd(min) as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | ((bcd(sec) as u64) << 8);
            vm86_set_return_flag(machine, regs, 1, false);
        }
        0x04 => {
            // Read RTC date: CH=century CL=year DH=month DL=day,
            // all BCD, CF clear on success, even when CMOS stores binary.
            let (year, month, day, _) = dos::cmos_date(machine);
            let bcd = |v: u8| ((v / 10) << 4) | (v % 10);
            regs.rcx = (regs.rcx & !0xFFFF)
                | ((bcd((year / 100) as u8) as u64) << 8)
                | bcd((year % 100) as u8) as u64;
            regs.rdx = (regs.rdx & !0xFFFF)
                | ((bcd(month) as u64) << 8)
                | bcd(day) as u64;
            vm86_set_return_flag(machine, regs, 1, false);
        }
        _ => {}
    }
}
