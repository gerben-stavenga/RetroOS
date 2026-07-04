//! Virtual PS/2 keyboard + BIOS keyboard buffer.

use super::*;

const KBD_BUF_SIZE: usize = 32;

/// Flip to `true` to trace every scancode in/out of the virtual 8042
/// (push from the host IRQ, INT 9 latch/delivery, guest port-0x60 read).
/// Unconditional dbg_println — bypasses the DOS_TRACE_RT gate, which is
/// suppressed in HW-IRQ context exactly where keyboard pushes happen.
pub(super) const KBD_TRACE: bool = false;

/// Virtual keyboard controller (scancode buffer)
///
/// Models the 8042 the way the hardware actually behaves, with its one
/// non-negotiable physical property made explicit: **bytes arrive over a slow
/// serial link, roughly one per millisecond.** `try_surface(now)` moves the
/// next queued byte into the output buffer only when the buffer is free and
/// the previous byte surfaced on an earlier millisecond tick; each surfaced
/// byte raises its own IRQ1 edge at the PIC (the caller's job).
///
/// That single pacing rule reproduces every guarantee DOS software was
/// written against, with the device itself knowing nothing about the
/// interrupt pipeline (the PIC's IRR/ISR handles ordering, as on real
/// hardware):
///  - a 0x60 re-read inside an INT 9 handler (game hook chaining to the BIOS
///    handler — Prince of Persia, OMF, Raptor) returns the byte the interrupt
///    was raised for, because the next byte "is still on the wire";
///  - an INT 9 drain loop polling 0x64 sees exactly one scancode and exits —
///    make and release arrive as separate interrupts;
///  - a byte arriving while INT 9 is in service waits its turn and arrives
///    as its own IRQ1 afterwards, so releases are never coalesced away.
///
/// The PUMP (queue_tick / the 0x64 poll path) additionally refuses to
/// surface a byte while IRQ1 is in service — dosemu2's KBD_PIC_HACK
/// sentinel (kbd.c: "timing is not a reliable measure under heavy loads"):
/// host scheduling can stretch a µs-scale handler past any pacing period,
/// and a byte surfacing mid-handler is exactly the lost-release bug.
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
    /// Millisecond tick when the last byte surfaced (the serial pacing).
    last_surface_ms: u64,
    /// Set after a multi-byte keyboard command (0xED/0xF0/0xF3) consumed its
    /// opcode and is waiting for the parameter byte. The parameter is ACKed
    /// but otherwise discarded — we don't actually drive LEDs, change scancode
    /// sets, or honor typematic rates.
    awaiting_cmd_param: bool,
}

impl VirtualKeyboard {
    pub const fn new() -> Self {
        Self {
            buffer: [0; KBD_BUF_SIZE], head: 0, tail: 0, port60: 0, port61: 0, obf: false,
            last_surface_ms: 0, awaiting_cmd_param: false,
        }
    }

    fn queue_scancode(&mut self, scancode: u8) {
        let next = (self.tail + 1) % KBD_BUF_SIZE;
        if next != self.head {
            self.buffer[self.tail] = scancode;
            self.tail = next;
        }
    }

    /// Buffer a scancode (or command-response byte) from the host side. It
    /// never becomes visible at port 0x60 here — bytes surface only through
    /// `try_surface`, on the serial-pacing clock.
    pub fn push(&mut self, scancode: u8) {
        if KBD_TRACE {
            crate::dbg_println!("[kbd] push {:02X}{} obf={} buf={}",
                scancode, if scancode & 0x80 != 0 { " REL" } else { "" },
                self.obf as u8, self.depth());
        }
        self.queue_scancode(scancode);
    }

    fn depth(&self) -> usize {
        (self.tail + KBD_BUF_SIZE - self.head) % KBD_BUF_SIZE
    }

    /// The 8042's serial clock: move the next queued byte into the output
    /// buffer iff the buffer is free and the last byte surfaced on an earlier
    /// millisecond tick (`now_ms` = `get_ticks()`, 1 kHz on every backend).
    /// Returns true when a byte surfaced — the caller raises the IRQ1 edge:
    /// exactly one edge per byte, blind to whatever the guest's handler is
    /// doing (the PIC's IRR/ISR takes it from there, as on real hardware).
    pub fn try_surface(&mut self, now_ms: u64) -> bool {
        if self.obf || self.head == self.tail || now_ms == self.last_surface_ms {
            return false;
        }
        let sc = self.buffer[self.head];
        self.head = (self.head + 1) % KBD_BUF_SIZE;
        self.port60 = sc;
        self.obf = true;
        self.last_surface_ms = now_ms;
        if KBD_TRACE {
            crate::dbg_println!("[kbd] surface {:02X}{} t={} buf={}",
                sc, if sc & 0x80 != 0 { " REL" } else { "" }, now_ms, self.depth());
        }
        true
    }

    /// Read port 0x60. Clears OBF and returns the current scancode WITHOUT
    /// pulling the next queued byte forward — the next byte surfaces via
    /// `try_surface` on a later millisecond, so a re-read inside the same
    /// handler (Prince of Persia's hook → BIOS chain) sees the same byte,
    /// exactly as on real hardware where the next scancode is still in
    /// serial transfer.
    pub fn read_port60(&mut self) -> u8 {
        let sc = self.port60;
        if KBD_TRACE {
            crate::dbg_println!("[kbd] read60 -> {:02X}{} (was_obf={} buf={})",
                sc, if sc & 0x80 != 0 { " REL" } else { "" }, self.obf as u8, self.depth());
        }
        self.obf = false;
        sc
    }

    /// Check if a byte is latched in the output buffer (no refill).
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
    /// guest's polling loop unblocks (they surface on the serial pacing
    /// clock like any device byte).
    pub fn write_port60(&mut self, val: u8) {
        if self.awaiting_cmd_param {
            self.awaiting_cmd_param = false;
            self.push(0xFA);
            return;
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
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.port60 = 0;
        self.port61 = 0;
        self.obf = false;
        self.last_surface_ms = 0;
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

/// Normalize an MF2/AT scancode before it reaches the guest BIOS and any
/// INT-9-hooking game. Two transforms, both required:
///
///  - **Strip the E0 prefix.** Old DOS games hook INT 9 and read port 0x60
///    raw, expecting XT-style scancodes (no E0); the grey navigation keys
///    then collapse onto their numpad twins (Up → 0x48 == numpad-8, etc.).
///  - **Drop the MF2 "fake shift" codes** — E0 2A/AA (LShift), E0 36/B6
///    (RShift) — that a real keyboard brackets the grey keys with. With the
///    E0 stripped they would otherwise land as a *real* Shift and corrupt the
///    shift state (the original cause of arrows doing nothing on 86box).
///
/// Navigation then relies on NumLock being OFF, so the stripped numpad codes
/// render as arrows rather than digits — `setup_ivt` forces it off. (QEMU and
/// Bochs boot NumLock off and emit neither E0-less numpads nor fake shifts,
/// so this only began to matter under 86box, whose accurate MF2 keyboard
/// emits the fake shifts and whose BIOS boots NumLock on.)
pub(super) fn normalize_scancode(pc: &mut PcMachine, scancode: u8) -> Option<u8> {
    if scancode == 0xE0 {
        pc.e0_pending = true;
        return None;
    }
    if pc.e0_pending {
        pc.e0_pending = false;
        if matches!(scancode, 0x2A | 0xAA | 0x36 | 0xB6) {
            return None;
        }
    }
    Some(scancode)
}

/// Clear the BIOS keyboard buffer at 40:1A..40:3E.
pub fn clear_bios_keyboard_buffer<P: arch_abi::GuestBytes>(regs: &mut Vcpu<P>) {
    write_u16(regs, 0x40, 0x1A, 0x001E);
    write_u16(regs, 0x40, 0x1C, 0x001E);
    for off in (0x1E..0x3E).step_by(2) {
        write_u16(regs, 0x40, off, 0);
    }
}

/// Pop the next word from the BIOS keyboard buffer.
pub fn pop_bios_keyboard_word<P: arch_abi::GuestBytes>(regs: &mut Vcpu<P>) -> Option<u16> {
    let head = read_u16(regs, 0x40, 0x1A);
    let tail = read_u16(regs, 0x40, 0x1C);
    if head == tail {
        return None;
    }
    let word = read_u16(regs, 0x40, head as u32);
    let next = if head + 2 >= 0x003E { 0x001E } else { head + 2 };
    write_u16(regs, 0x40, 0x1A, next);
    Some(word)
}

