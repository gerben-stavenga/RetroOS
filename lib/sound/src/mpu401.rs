//! MPU-401 — the MIDI port every DOS game means by "Roland" or "General MIDI".
//!
//! Two ports at the card's base (0x330 by convention): data at `base+0` and
//! status/command at `base+1`. The status byte is **active low** — bit 7 clear
//! means "output ready to accept a byte", bit 6 clear means "input has a byte
//! waiting" — which is the single most common thing to get backwards.
//!
//! We implement **UART mode** only, and that is a deliberate scope choice, not
//! a shortcut. The MPU-401's "intelligent mode" put sequencer timing,
//! metronome and track memory on the card; almost no DOS game used it, because
//! the cheap clones everyone owned only did UART. Games send the reset/UART
//! handshake and then stream raw MIDI bytes, which is exactly what this
//! surfaces. A program that insists on intelligent mode will fail detection
//! and pick another device — the correct outcome, and far better than
//! pretending and then mistiming its music.
//!
//! Passive: bytes the guest writes queue up for the host to drain into a
//! synth. The card holds no synth, no clock, and no interrupt policy.

/// Depth of the guest→host MIDI byte queue. A dense SysEx bank dump is the
/// worst case; a full queue drops the oldest byte rather than growing without
/// bound, and a dropped byte costs one note, never the stream.
const QUEUE: usize = 1024;

/// Status-register bits. Active low, both of them.
#[allow(dead_code)] // documents the bit we deliberately always leave clear
const ST_OUTPUT_BUSY: u8 = 0x40; // clear = we can accept a data byte
const ST_INPUT_EMPTY: u8 = 0x80; // clear = a byte is waiting to be read

/// MPU-401 commands (written to `base+1`).
const CMD_RESET: u8 = 0xFF;
const CMD_UART: u8 = 0x3F;

/// The acknowledge byte a command produces in the read FIFO.
const ACK: u8 = 0xFE;

pub struct Mpu401 {
    /// Port base; the card decodes `base` and `base+1`.
    pub base: u16,
    /// UART mode entered (command 0x3F). Out of it, data writes are ignored.
    uart: bool,
    /// Bytes the guest has written, waiting for the host to drain.
    out: [u8; QUEUE],
    out_head: usize,
    out_len: usize,
    /// Bytes the guest can read back — only ever command acknowledges, since
    /// nothing on our side originates MIDI.
    ack_pending: u8,
}

impl Mpu401 {
    pub const fn new(base: u16) -> Self {
        Mpu401 {
            base,
            uart: false,
            out: [0; QUEUE],
            out_head: 0,
            out_len: 0,
            ack_pending: 0,
        }
    }

    pub fn set_base(&mut self, base: u16) {
        self.base = base;
    }

    /// The two ports this card decodes.
    pub fn owns(&self, p: u16) -> bool {
        p == self.base || p == self.base + 1
    }

    /// Guest IN.
    pub fn port_in(&mut self, p: u16) -> u8 {
        if p == self.base {
            // Data port: hand back a queued acknowledge, else 0.
            if self.ack_pending > 0 {
                self.ack_pending -= 1;
                return ACK;
            }
            return 0;
        }
        // Status port, active low: the output-busy bit stays clear because we
        // can always accept a byte, and input-empty is set unless an
        // acknowledge is waiting.
        if self.ack_pending == 0 { ST_INPUT_EMPTY } else { 0 }
    }

    /// Guest OUT.
    pub fn port_out(&mut self, p: u16, val: u8) {
        if p == self.base {
            if self.uart {
                self.push(val);
            }
            return;
        }
        match val {
            CMD_RESET => {
                // Reset acknowledges and leaves UART mode. Detection routines
                // send this twice and expect an ACK each time.
                self.uart = false;
                self.out_len = 0;
                self.out_head = 0;
                self.ack_pending = self.ack_pending.saturating_add(1);
            }
            CMD_UART => {
                self.uart = true;
                self.ack_pending = self.ack_pending.saturating_add(1);
            }
            // Any other command: acknowledge so a probe does not hang, but do
            // not pretend to enter intelligent mode.
            _ => self.ack_pending = self.ack_pending.saturating_add(1),
        }
    }

    fn push(&mut self, b: u8) {
        if self.out_len == QUEUE {
            // Full: drop the oldest so the newest still lands.
            self.out_head = (self.out_head + 1) % QUEUE;
            self.out_len -= 1;
        }
        let tail = (self.out_head + self.out_len) % QUEUE;
        self.out[tail] = b;
        self.out_len += 1;
    }

    /// Drain one queued MIDI byte for the host to feed a synth, or `None`.
    pub fn take(&mut self) -> Option<u8> {
        if self.out_len == 0 {
            return None;
        }
        let b = self.out[self.out_head];
        self.out_head = (self.out_head + 1) % QUEUE;
        self.out_len -= 1;
        Some(b)
    }

    /// Whether the guest has put the port into UART mode — the host's cue
    /// that this device is the one the program chose.
    pub fn in_uart(&self) -> bool {
        self.uart
    }

    /// Drop all state: program exit.
    pub fn reset(&mut self) {
        self.uart = false;
        self.out_len = 0;
        self.out_head = 0;
        self.ack_pending = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> Mpu401 {
        Mpu401::new(0x330)
    }

    #[test]
    fn decodes_exactly_two_ports() {
        let m = card();
        assert!(m.owns(0x330) && m.owns(0x331));
        assert!(!m.owns(0x32F) && !m.owns(0x332));
    }

    #[test]
    fn reset_then_uart_is_the_detection_handshake() {
        let mut m = card();
        // Status with nothing pending: input-empty set (active low = no data).
        assert_eq!(m.port_in(0x331) & ST_INPUT_EMPTY, ST_INPUT_EMPTY);
        // Output-ready is bit 6 clear, always.
        assert_eq!(m.port_in(0x331) & ST_OUTPUT_BUSY, 0);

        m.port_out(0x331, CMD_RESET);
        // Now a byte is waiting: input-empty clear.
        assert_eq!(m.port_in(0x331) & ST_INPUT_EMPTY, 0);
        assert_eq!(m.port_in(0x330), ACK);
        // Consumed.
        assert_eq!(m.port_in(0x331) & ST_INPUT_EMPTY, ST_INPUT_EMPTY);

        m.port_out(0x331, CMD_UART);
        assert_eq!(m.port_in(0x330), ACK);
        assert!(m.in_uart());
    }

    #[test]
    fn data_is_ignored_until_uart_mode() {
        let mut m = card();
        m.port_out(0x330, 0x90); // before the handshake
        assert_eq!(m.take(), None);
        m.port_out(0x331, CMD_UART);
        m.port_out(0x330, 0x90);
        m.port_out(0x330, 0x40);
        m.port_out(0x330, 0x7F);
        assert_eq!(m.take(), Some(0x90));
        assert_eq!(m.take(), Some(0x40));
        assert_eq!(m.take(), Some(0x7F));
        assert_eq!(m.take(), None);
    }

    #[test]
    fn reset_leaves_uart_mode_and_clears_the_queue() {
        let mut m = card();
        m.port_out(0x331, CMD_UART);
        m.port_out(0x330, 0x90);
        m.port_out(0x331, CMD_RESET);
        assert!(!m.in_uart());
        assert_eq!(m.take(), None, "queued bytes die with the reset");
        m.port_out(0x330, 0x90);
        assert_eq!(m.take(), None, "and data is ignored again");
    }

    #[test]
    fn a_full_queue_drops_the_oldest_not_the_newest() {
        let mut m = card();
        m.port_out(0x331, CMD_UART);
        for i in 0..(QUEUE + 10) {
            m.port_out(0x330, (i & 0x7F) as u8);
        }
        // The first ten are gone; the queue holds the most recent QUEUE bytes.
        let first = m.take().unwrap();
        assert_eq!(first, (10 & 0x7F) as u8);
        let mut n = 1;
        while m.take().is_some() {
            n += 1;
        }
        assert_eq!(n, QUEUE);
    }

    #[test]
    fn unknown_commands_acknowledge_rather_than_hang_a_probe() {
        let mut m = card();
        m.port_out(0x331, 0x3D); // some intelligent-mode command
        assert_eq!(m.port_in(0x331) & ST_INPUT_EMPTY, 0);
        assert_eq!(m.port_in(0x330), ACK);
        assert!(!m.in_uart(), "acknowledging is not entering intelligent mode");
    }
}
