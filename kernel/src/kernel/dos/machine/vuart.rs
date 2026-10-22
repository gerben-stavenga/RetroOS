//! Virtual COM1: 16550 registers and IRQ4, backed by the OSD null-modem cable.
use crate::kernel::net::lan;
use alloc::collections::VecDeque;

pub struct Uart {
    divisor: u16,
    ier: u8,
    lcr: u8,
    mcr: u8,
    scratch: u8,
    fifo: bool,
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    overrun: bool,
    thre: bool,
    modem: u8,
    delta: u8,
    irq: bool,
    active: bool,
    lease: Option<u64>,
    cable_epoch: u64,
}
impl Uart {
    pub fn new() -> Self {
        Self {
            divisor: 12,
            ier: 0,
            lcr: 0,
            mcr: 0,
            scratch: 0,
            fifo: false,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            overrun: false,
            thre: true,
            modem: 0,
            delta: 0,
            irq: false,
            active: false,
            lease: None,
            cable_epoch: 0,
        }
    }
    fn loopback(&self) -> bool {
        self.mcr & 0x10 != 0
    }
    fn capacity(&self) -> usize {
        if self.fifo { 16 } else { 1 }
    }
    fn receive(&mut self, byte: u8) {
        if self.rx.len() < self.capacity() {
            self.rx.push_back(byte);
        } else {
            self.overrun = true;
        }
    }
    fn sync(&mut self) {
        if !self.active {
            return;
        }
        let epoch = lan::serial_epoch();
        if epoch != self.cable_epoch {
            self.cable_epoch = epoch;
            self.rx.clear();
            self.tx.clear();
            self.overrun = false;
            self.thre = true;
        }
        if self.loopback() {
            let modem = ((self.mcr & 2) << 3)
                | ((self.mcr & 1) << 5)
                | ((self.mcr & 4) << 4)
                | ((self.mcr & 8) << 4);
            self.update_modem(modem);
            return;
        }
        if self.lease.is_none() && lan::serial_connected() {
            self.lease = lan::serial_claim();
        }
        self.update_modem(if self.lease.is_some() && lan::serial_connected() {
            0xb0
        } else {
            0
        });
        let Some(lease) = self.lease else { return };
        while let Some(byte) = self.tx.front().copied() {
            if !lan::serial_send(lease, byte) {
                break;
            }
            self.tx.pop_front();
            if self.tx.is_empty() {
                self.thre = true;
            }
        }
        // Backpressure preserves TCP's stream when the guest is descheduled.
        while self.rx.len() < self.capacity() {
            let Some(byte) = lan::serial_receive(lease) else {
                break;
            };
            self.receive(byte);
        }
    }
    fn update_modem(&mut self, value: u8) {
        let changed = self.modem ^ value;
        self.delta |= (changed >> 4) & 0xb;
        if self.modem & 0x40 != 0 && value & 0x40 == 0 {
            self.delta |= 4;
        }
        self.modem = value;
    }
    fn reason(&self) -> u8 {
        if self.ier & 4 != 0 && self.overrun {
            6
        } else if self.ier & 1 != 0 && !self.rx.is_empty() {
            4
        } else if self.ier & 2 != 0 && self.thre {
            2
        } else if self.ier & 8 != 0 && self.delta != 0 {
            0
        } else {
            1
        }
    }
    /// Return the rising edge of the UART interrupt output. Acknowledging a
    /// cause through IIR/RBR/LSR/MSR lowers it before a subsequent cause rises.
    pub fn poll_irq(&mut self) -> bool {
        self.sync();
        let pending = self.mcr & 8 != 0 && self.reason() != 1;
        let edge = pending && !self.irq;
        self.irq = pending;
        edge
    }
    fn refresh_irq(&mut self) {
        // Record deassertion after a register side effect; assertion is sampled
        // by poll_irq so a port access cannot swallow an interrupt edge.
        if self.mcr & 8 == 0 || self.reason() == 1 {
            self.irq = false;
        }
    }
    pub fn read(&mut self, register: u16) -> u8 {
        self.active = true;
        self.sync();
        let value = match register {
            0 if self.lcr & 0x80 != 0 => self.divisor as u8,
            1 if self.lcr & 0x80 != 0 => (self.divisor >> 8) as u8,
            0 => self.rx.pop_front().unwrap_or(0),
            1 => self.ier,
            2 => {
                let reason = self.reason();
                if reason == 2 {
                    self.thre = false;
                }
                reason | if self.fifo { 0xc0 } else { 0 }
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => {
                let value = 0x60 * self.tx.is_empty() as u8
                    | (!self.rx.is_empty()) as u8
                    | ((self.overrun as u8) << 1);
                self.overrun = false;
                value
            }
            6 => {
                let value = self.modem | self.delta;
                self.delta = 0;
                value
            }
            7 => self.scratch,
            _ => 0xff,
        };
        self.refresh_irq();
        value
    }
    pub fn write(&mut self, register: u16, value: u8) {
        self.active = true;
        self.sync();
        match register {
            0 if self.lcr & 0x80 != 0 => self.divisor = (self.divisor & 0xff00) | value as u16,
            1 if self.lcr & 0x80 != 0 => {
                self.divisor = (self.divisor & 0xff) | ((value as u16) << 8)
            }
            0 => {
                self.thre = false;
                if self.loopback() {
                    self.receive(value);
                    self.thre = true;
                } else if self.tx.len() < 16 {
                    self.tx.push_back(value);
                }
            }
            1 => {
                if self.ier & 2 == 0 && value & 2 != 0 && self.tx.is_empty() {
                    self.thre = true;
                }
                self.ier = value & 0xf;
            }
            2 => {
                if self.fifo != (value & 1 != 0) || value & 2 != 0 {
                    self.rx.clear();
                    self.overrun = false;
                }
                if value & 4 != 0 {
                    self.tx.clear();
                    self.thre = true;
                }
                self.fifo = value & 1 != 0;
            }
            3 => self.lcr = value,
            4 => self.mcr = value & 0x1f,
            7 => self.scratch = value,
            _ => {}
        }
        self.sync();
        self.refresh_irq();
    }
}
impl Drop for Uart {
    fn drop(&mut self) {
        if let Some(lease) = self.lease {
            lan::serial_release(lease);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback_irq_and_divisor_latches() {
        let mut uart = Uart::new();
        uart.write(3, 0x80);
        uart.write(0, 3);
        uart.write(1, 1);
        assert_eq!(uart.read(0), 3);
        assert_eq!(uart.read(1), 1);
        uart.write(3, 3);
        uart.write(4, 0x1f); // loopback and OUT2
        assert_eq!(uart.read(6) & 0xf0, 0xf0);
        uart.write(1, 3);
        assert!(uart.poll_irq());
        assert_eq!(uart.read(2), 2);
        assert!(!uart.poll_irq());
        uart.write(0, 0x55);
        assert!(uart.poll_irq());
        assert_eq!(uart.read(2), 4);
        assert_eq!(uart.read(0), 0x55);
        assert_eq!(uart.read(2), 2);
        assert_eq!(uart.read(2), 1);
        uart.write(0, 1);
        uart.write(0, 2);
        assert_ne!(uart.read(5) & 2, 0);
        assert_eq!(uart.read(0), 1);
        assert_eq!(uart.read(5) & 2, 0);
    }
}
