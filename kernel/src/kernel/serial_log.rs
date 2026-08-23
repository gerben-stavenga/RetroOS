//! Polling kernel log sink for a configured 16550 UART.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use arch_abi::ComPort;
use crate::kernel::drivers::uart16550::{Uart16550, UartConfig};

const DISABLED: u8 = 0;
const LIVE: u8 = 1;
const FAILED: u8 = 2;

// Early and panic logging has no IRQ-driven TX queue. Poll only until the UART
// can accept the byte; this does not wait for or require peer acknowledgement.
// Keep the bound finite so broken hardware cannot hang boot.
const TX_READY_POLLS: u32 = 100_000;

static STATE: AtomicU8 = AtomicU8::new(DISABLED);
static PORT: AtomicU8 = AtomicU8::new(0);
static PREVIOUS_WAS_CR: AtomicBool = AtomicBool::new(false);

const fn encode_port(port: ComPort) -> u8 {
    match port {
        ComPort::Com1 => 1,
        ComPort::Com2 => 2,
    }
}

fn selected_uart() -> Option<Uart16550> {
    match PORT.load(Ordering::Relaxed) {
        1 => Some(Uart16550::new(ComPort::Com1)),
        2 => Some(Uart16550::new(ComPort::Com2)),
        _ => None,
    }
}

/// Initialize the output-only phase of the configured serial console.
///
/// Called once from metal boot glue after `kernel::portio` is installed and
/// before normal startup logging begins.
pub fn init(port: ComPort) -> bool {
    let uart = Uart16550::new(port);
    if !uart.is_present() {
        STATE.store(FAILED, Ordering::Relaxed);
        return false;
    }

    uart.initialize(UartConfig::UART_115200_8N1);
    PORT.store(encode_port(port), Ordering::Relaxed);
    PREVIOUS_WAS_CR.store(false, Ordering::Relaxed);
    STATE.store(LIVE, Ordering::Relaxed);
    true
}

fn present_byte(byte: u8, previous_was_cr: &mut bool, mut send: impl FnMut(u8) -> bool) -> bool {
    if byte == b'\n' && !*previous_was_cr && !send(b'\r') {
        return false;
    }
    if !send(byte) {
        return false;
    }
    *previous_was_cr = byte == b'\r';
    true
}

/// Mirror one ambient log byte to the UART. A no-op until `init` succeeds.
/// On the first timeout, disable the sink so later logging remains bounded.
pub fn write_byte(byte: u8) {
    if STATE.load(Ordering::Relaxed) != LIVE {
        return;
    }
    let Some(uart) = selected_uart() else {
        STATE.store(FAILED, Ordering::Relaxed);
        return;
    };

    let mut previous_was_cr = PREVIOUS_WAS_CR.load(Ordering::Relaxed);
    let sent = present_byte(byte, &mut previous_was_cr, |value| {
        uart.write_byte(TX_READY_POLLS, value).is_ok()
    });
    PREVIOUS_WAS_CR.store(previous_was_cr, Ordering::Relaxed);
    if !sent {
        STATE.store(FAILED, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::present_byte;

    fn collect(bytes: &[u8]) -> ([u8; 8], usize) {
        let mut out = [0; 8];
        let mut len = 0;
        let mut previous_was_cr = false;
        for &byte in bytes {
            assert!(present_byte(byte, &mut previous_was_cr, |byte| {
                if len == out.len() {
                    return false;
                }
                out[len] = byte;
                len += 1;
                true
            }));
        }
        (out, len)
    }

    #[test]
    fn translates_lone_lf_to_crlf() {
        let (out, len) = collect(b"\n");
        assert_eq!(&out[..len], b"\r\n");
    }

    #[test]
    fn preserves_existing_crlf() {
        let (out, len) = collect(b"\r\n");
        assert_eq!(&out[..len], b"\r\n");
    }
}
