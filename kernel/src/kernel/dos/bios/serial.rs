//! BIOS COM1 services over the same UART used by port-based DOS drivers.
use crate::kernel::dos::DosState;
use crate::{Arch, Regs};

pub(super) fn int14<A: Arch>(dos: &mut DosState<A>, regs: &mut Regs) {
    // COM1 BIOS service. Port-based DOS drivers use the same UART.
    let uart = &mut dos.pc.uart;
    let function = (regs.rax >> 8) as u8;
    if regs.rdx as u16 != 0 {
        regs.rax = (regs.rax & !0xff00) | 0x8000;
    } else {
        let mut timeout = false;
        match function {
            0 => {
                let format = regs.rax as u8;
                let divisor = [1047u16, 768, 384, 192, 96, 48, 24, 12][(format >> 5) as usize];
                uart.write(3, 0x80);
                uart.write(0, divisor as u8);
                uart.write(1, (divisor >> 8) as u8);
                uart.write(3, format & 0x1f);
                uart.write(1, 0);
                uart.write(4, 3);
            }
            1 => {
                if uart.read(5) & 0x20 != 0 {
                    uart.write(0, regs.rax as u8);
                } else {
                    timeout = true;
                }
            }
            2 => {
                if uart.read(5) & 1 != 0 {
                    regs.rax = (regs.rax & !0xff) | uart.read(0) as u64;
                } else {
                    timeout = true;
                }
            }
            3 => {}
            _ => timeout = true,
        }
        let status = uart.read(5) | if timeout { 0x80 } else { 0 };
        if function == 0 || function == 3 {
            regs.rax = (regs.rax & !0xff) | uart.read(6) as u64;
        }
        regs.rax = (regs.rax & !0xff00) | ((status as u64) << 8);
    }
    if uart.poll_irq() {
        dos.pc.vpic.raise(4);
    }
}
