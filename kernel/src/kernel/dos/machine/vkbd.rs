//! Virtual PS/2 keyboard + BIOS keyboard buffer.

use super::*;

const KBD_BUF_SIZE: usize = 32;

/// Virtual keyboard controller (scancode buffer)
///
/// Models the 8042 output buffer. Incoming scancodes become visible in the
/// controller as soon as the output buffer is free; IRQ1 is merely the
/// notification that data is ready. That lets BIOS INT 9 handlers and games
/// that poll ports 0x60/0x64 observe the same underlying device state.
pub struct VirtualKeyboard {
    buffer: [u8; KBD_BUF_SIZE],
    head: usize,
    tail: usize,
    /// Current scancode visible via port 0x60
    pub port60: u8,
    /// Port 0x61 state used by the BIOS keyboard IRQ handler handshake.
    pub port61: u8,
    /// Output Buffer Full flag — port 0x64 bit 0
    pub obf: bool,
    /// Set after a multi-byte keyboard command (0xED/0xF0/0xF3) consumed its
    /// opcode and is waiting for the parameter byte. The parameter is ACKed
    /// but otherwise discarded — we don't actually drive LEDs, change scancode
    /// sets, or honor typematic rates.
    awaiting_cmd_param: bool,
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self { buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0, port60: 0, port61: 0, obf: false, awaiting_cmd_param: false }
    }

    fn queue_scancode(&mut self, scancode: u8) {
        let next = (self.tail + 1) % KBD_BUF_SIZE;
        if next != self.head {
            self.buffer[self.tail] = scancode;
            self.tail = next;
        }
    }

    fn fill_output(&mut self) -> bool {
        if self.obf {
            return true;
        }
        if self.head == self.tail {
            return false;
        }
        let sc = self.buffer[self.head];
        self.head = (self.head + 1) % KBD_BUF_SIZE;
        self.port60 = sc;
        self.obf = true;
        true
    }

    /// Buffer a scancode from the real keyboard IRQ handler
    pub fn push(&mut self, scancode: u8) {
        if !self.obf {
            self.port60 = scancode;
            self.obf = true;
        } else {
            self.queue_scancode(scancode);
        }
    }

    /// Ensure a scancode is visible in port60 for INT 9 delivery.
    pub fn latch(&mut self) -> bool {
        self.fill_output()
    }

    /// Read port 0x60 — returns current scancode and then exposes the next
    /// queued byte if one is already waiting in the controller.
    pub fn read_port60(&mut self) -> u8 {
        let sc = self.port60;
        self.obf = false;
        self.fill_output();
        sc
    }

    /// Check if data is available (port 0x64 bit 0)
    pub fn has_data(&self) -> bool {
        self.obf
    }

    /// Check if scancodes are queued behind the current output byte.
    pub fn has_buffered(&self) -> bool {
        self.head != self.tail
    }

    pub fn read_port61(&mut self) -> u8 {
        // Bit 4 mirrors the DRAM refresh request line — toggles every ~15µs
        // on real hardware. Several DOS games (Zone 66 / Tran's PMODE/W
        // titles, various Adlib drivers) busy-loop until they observe an
        // edge here, treating it as a sub-tick timer. Flip on every read so
        // a `cmp / je` polling loop exits on the second sample.
        self.port61 ^= 0x10;
        self.port61
    }

    pub fn write_port61(&mut self, val: u8) {
        self.port61 = val;
    }

    /// Host write to port 0x60 — a command (or parameter) directed at the
    /// PS/2 keyboard. We don't model the device, only its protocol: queue
    /// the right ACK / response bytes back into the output buffer so the
    /// guest's polling loop unblocks. Returns true if a response byte was
    /// made visible (caller raises IRQ1).
    pub fn write_port60(&mut self, val: u8) -> bool {
        if self.awaiting_cmd_param {
            self.awaiting_cmd_param = false;
            self.push(0xFA);
            return true;
        }
        match val {
            // Multi-byte commands: ACK opcode now, ACK parameter on next write.
            0xED | 0xF0 | 0xF3 => {
                self.awaiting_cmd_param = true;
                self.push(0xFA);
            }
            // Echo — keyboard returns 0xEE, no ACK.
            0xEE => self.push(0xEE),
            // Read ID — ACK then 2-byte MF2 keyboard ID.
            0xF2 => {
                self.push(0xFA);
                self.push(0xAB);
                self.push(0x83);
            }
            // Single-byte commands that just want an ACK.
            // 0xF4 enable scanning, 0xF5 disable, 0xF6 set defaults, 0xFE resend.
            0xF4 | 0xF5 | 0xF6 | 0xFE => self.push(0xFA),
            // Reset — ACK then BAT-complete.
            0xFF => {
                self.push(0xFA);
                self.push(0xAA);
            }
            // Unknown opcode — keyboard asks the host to resend.
            _ => self.push(0xFE),
        }
        true
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.port60 = 0;
        self.port61 = 0;
        self.obf = false;
        self.awaiting_cmd_param = false;
    }

    /// Pop next key-down scancode, skipping releases (for INT 16h AH=0)
    pub fn pop_key(&mut self) -> Option<u8> {
        while self.head != self.tail {
            let sc = self.buffer[self.head];
            self.head = (self.head + 1) % KBD_BUF_SIZE;
            if sc & 0x80 == 0 {
                return Some(sc);
            }
        }
        None
    }

    /// Peek next key-down scancode without consuming (for INT 16h AH=1)
    pub fn peek_key(&self) -> Option<u8> {
        let mut i = self.head;
        while i != self.tail {
            let sc = self.buffer[i];
            if sc & 0x80 == 0 {
                return Some(sc);
            }
            i = (i + 1) % KBD_BUF_SIZE;
        }
        None
    }
}

/// Strip PS/2 E0 prefix — DOS games expect XT-style scancodes.
/// E0 is consumed; the following scancode passes through as its legacy equivalent.
pub(super) fn normalize_scancode(pc: &mut PcMachine, scancode: u8) -> Option<u8> {
    if scancode == 0xE0 {
        pc.e0_pending = true;
        return None;
    }
    if pc.e0_pending {
        pc.e0_pending = false;
    }
    Some(scancode)
}

/// Clear the BIOS keyboard buffer at 40:1A..40:3E.
pub fn clear_bios_keyboard_buffer() {
    write_u16(0x40, 0x1A, 0x001E);
    write_u16(0x40, 0x1C, 0x001E);
    for off in (0x1E..0x3E).step_by(2) {
        write_u16(0x40, off, 0);
    }
}

/// Pop the next word from the BIOS keyboard buffer.
pub fn pop_bios_keyboard_word() -> Option<u16> {
    let head = read_u16(0x40, 0x1A);
    let tail = read_u16(0x40, 0x1C);
    if head == tail {
        return None;
    }
    let word = read_u16(0x40, head as u32);
    let next = if head + 2 >= 0x003E { 0x001E } else { head + 2 };
    write_u16(0x40, 0x1A, next);
    Some(word)
}

