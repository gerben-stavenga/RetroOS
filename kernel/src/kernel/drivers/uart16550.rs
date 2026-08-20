//! Minimal polling driver for 16550-compatible ISA UARTs.
//!
//! This module owns UART hardware mechanics only. Higher-level protocols and
//! a future serial console must remain above it and decide what a timeout means
//! for their own state machines.

use crate::kernel::portio::{inb, outb};
pub use arch_abi::ComPort;

const COM1_BASE: u16 = 0x3F8;
const COM2_BASE: u16 = 0x2F8;

const fn base(port: ComPort) -> u16 {
    match port {
        ComPort::Com1 => COM1_BASE,
        ComPort::Com2 => COM2_BASE,
    }
}

/// UART setup supported by the current serial users.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UartConfig {
    /// Divisor for the UART's 115200 base clock.
    pub divisor: u16,
    /// Line-control register value, normally 8N1 (`0x03`).
    pub line_control: u8,
    /// FIFO-control register value.
    pub fifo_control: u8,
    /// Modem-control register value.
    pub modem_control: u8,
}

impl UartConfig {
    pub const UART_115200_8N1: Self = Self {
        divisor: 1,
        line_control: 0x03,
        fifo_control: 0xC7,
        modem_control: 0x0B,
    };
}

/// Errors returned by bounded polling operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartError {
    Timeout,
}

/// A polling 16550 UART endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uart16550 {
    port: ComPort,
}

impl Uart16550 {
    pub const fn new(port: ComPort) -> Self {
        Self { port }
    }

    fn base(self) -> u16 {
        base(self.port)
    }

    /// Probe the scratch register without changing the configured line mode.
    pub fn is_present(self) -> bool {
        let scratch = self.base() + 7;
        outb(scratch, 0xAA);
        inb(scratch) == 0xAA
    }

    /// Configure the UART for a polling 8N1-style connection.
    pub fn initialize(self, config: UartConfig) {
        let base = self.base();
        outb(base + 1, 0x00); // Disable interrupts.
        outb(base + 3, 0x80); // Enable DLAB.
        outb(base, config.divisor as u8);
        outb(base + 1, (config.divisor >> 8) as u8);
        outb(base + 3, config.line_control);
        outb(base + 2, config.fifo_control);
        outb(base + 4, config.modem_control);
    }

    /// Send one byte, waiting at most `polls` status reads for transmitter
    /// holding-register readiness.
    pub fn write_byte(self, polls: u32, byte: u8) -> Result<(), UartError> {
        if !self.wait_ready(polls, 0x20) {
            return Err(UartError::Timeout);
        }
        outb(self.base(), byte);
        Ok(())
    }

    /// Receive one byte, waiting at most `polls` status reads for data-ready.
    pub fn read_byte(self, polls: u32) -> Result<u8, UartError> {
        if !self.wait_ready(polls, 0x01) {
            return Err(UartError::Timeout);
        }
        Ok(inb(self.base()))
    }

    /// Discard bytes already buffered by the UART.
    pub fn drain_rx(self) {
        while inb(self.base() + 5) & 0x01 != 0 {
            let _ = inb(self.base());
        }
    }

    fn wait_ready(self, polls: u32, mask: u8) -> bool {
        for _ in 0..polls {
            if inb(self.base() + 5) & mask != 0 {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{base, ComPort, Uart16550, UartConfig};

    #[test]
    fn standard_ports_and_configuration_are_stable() {
        assert_eq!(base(ComPort::Com1), 0x3F8);
        assert_eq!(base(ComPort::Com2), 0x2F8);
        assert_eq!(Uart16550::new(ComPort::Com1).base(), 0x3F8);
        assert_eq!(Uart16550::new(ComPort::Com2).base(), 0x2F8);
        assert_eq!(UartConfig::UART_115200_8N1.divisor, 1);
        assert_eq!(UartConfig::UART_115200_8N1.line_control, 0x03);
    }
}
