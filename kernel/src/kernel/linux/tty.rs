//! Console input discipline. Readline shells disable canonical input and echo;
//! plain shells rely on the terminal to buffer, edit and echo their command line.
use alloc::vec::Vec;

const ICANON: u32 = 2;
const ECHO: u32 = 8;
const ECHOE: u32 = 16;
const ECHOK: u32 = 32;
const ECHONL: u32 = 64;
const ECHOCTL: u32 = 512;

pub(super) struct Console {
    pub termios: [u8; 36],
    line: Vec<u8>,
    origin: usize,
}

impl Console {
    pub fn new() -> Self {
        let mut termios = [0; 36];
        termios[..4].copy_from_slice(&0x100u32.to_le_bytes()); // ICRNL
        termios[8..12].copy_from_slice(&0xb0u32.to_le_bytes()); // CS8 | CREAD
        termios[12..16].copy_from_slice(&(ICANON | ECHO | ECHOE | ECHOK | ECHOCTL).to_le_bytes());
        termios[17..24].copy_from_slice(&[3, 28, 127, 21, 4, 0, 1]);
        Self {
            termios,
            line: Vec::new(),
            origin: 0,
        }
    }

    pub fn set_column(&mut self, column: usize) {
        if self.line.is_empty() {
            self.origin = column;
        }
    }

    fn flags(&self) -> u32 {
        u32::from_le_bytes(self.termios[12..16].try_into().unwrap())
    }

    pub fn configure(&mut self, settings: [u8; 36], flush: bool, mut deliver: impl FnMut(&[u8])) {
        if flush {
            self.line.clear();
        } else if self.flags() & ICANON != 0
            && u32::from_le_bytes(settings[12..16].try_into().unwrap()) & ICANON == 0
        {
            if !self.line.is_empty() {
                deliver(&self.line);
            }
            self.line.clear();
        }
        self.termios = settings;
    }

    fn echo_byte(&self, byte: u8, echo: &mut impl FnMut(&[u8])) {
        if self.flags() & ECHO == 0 {
            if byte == b'\n' && self.flags() & ECHONL != 0 {
                echo(b"\n");
            }
        } else if self.flags() & ECHOCTL != 0
            && (byte < 32 || byte == 127)
            && byte != b'\n'
            && byte != b'\t'
        {
            echo(&[b'^', if byte == 127 { b'?' } else { byte + 64 }]);
        } else {
            echo(&[byte]);
        }
    }

    fn erase(&mut self, echo: &mut impl FnMut(&[u8])) {
        let Some(byte) = self.line.pop() else {
            return;
        };
        // Erase an entire UTF-8 character, not an individual continuation byte.
        if byte >= 128 {
            let mut current = byte;
            while current & 0xc0 == 0x80 {
                let Some(previous) = self.line.pop() else {
                    break;
                };
                current = previous;
            }
        }
        if self.flags() & (ECHO | ECHOE) == ECHO | ECHOE {
            let width = if byte == b'\t' {
                let column = self.line.iter().fold(self.origin, |col, &b| {
                    if b == b'\t' {
                        (col + 8) & !7
                    } else if b & 0xc0 == 0x80 {
                        col
                    } else {
                        col + 1
                    }
                });
                8 - column % 8
            } else if (byte < 32 || byte == 127) && self.flags() & ECHOCTL != 0 {
                2
            } else {
                1
            };
            for _ in 0..width {
                echo(b"\x08 \x08");
            }
        } else {
            self.echo_byte(self.termios[19], echo);
        }
    }

    pub fn input(
        &mut self,
        bytes: &[u8],
        mut deliver: impl FnMut(&[u8]),
        mut eof: impl FnMut(),
        mut echo: impl FnMut(&[u8]),
    ) {
        let input = u32::from_le_bytes(self.termios[..4].try_into().unwrap());
        for &raw in bytes {
            if raw == b'\r' && input & 0x80 != 0 {
                continue;
            } // IGNCR
            let byte = match raw {
                b'\r' if input & 0x100 != 0 => b'\n',
                b'\n' if input & 0x40 != 0 => b'\r',
                byte => byte,
            };
            if self.flags() & ICANON == 0 {
                deliver(&[byte]);
                self.echo_byte(byte, &mut echo);
            } else if byte != 0 && (byte == self.termios[19] || byte == 8) {
                self.erase(&mut echo);
            } else if byte != 0 && byte == self.termios[20] {
                if self.flags() & ECHOE != 0 {
                    while !self.line.is_empty() {
                        self.erase(&mut echo);
                    }
                } else {
                    self.line.clear();
                    self.echo_byte(byte, &mut echo);
                    if self.flags() & (ECHO | ECHOK) == ECHO | ECHOK {
                        echo(b"\n");
                    }
                }
            } else if byte != 0 && byte == self.termios[21] {
                if self.line.is_empty() {
                    eof();
                } else {
                    deliver(&self.line);
                    self.line.clear();
                }
            } else if byte == b'\n' || (byte != 0 && byte == self.termios[28]) {
                // VEOL
                self.line.push(byte);
                self.echo_byte(byte, &mut echo);
                deliver(&self.line);
                self.line.clear();
            } else if self.line.len() < 1000 {
                self.line.push(byte);
                self.echo_byte(byte, &mut echo);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn input(tty: &mut Console, bytes: &[u8]) -> (Vec<u8>, Vec<u8>, usize) {
        let (mut data, mut echo, mut eof) = (Vec::new(), Vec::new(), 0);
        tty.input(
            bytes,
            |b| data.extend_from_slice(b),
            || eof += 1,
            |b| echo.extend_from_slice(b),
        );
        (data, echo, eof)
    }

    #[test]
    fn plain_shell_echoes_before_read_and_edits_before_delivery() {
        let mut tty = Console::new();
        assert_eq!(input(&mut tty, b"echx"), (vec![], b"echx".to_vec(), 0));
        assert_eq!(
            input(&mut tty, b"\x7fo hi\r"),
            (b"echo hi\n".to_vec(), b"\x08 \x08o hi\n".to_vec(), 0)
        );
    }

    #[test]
    fn readline_raw_mode_delivers_without_kernel_echo() {
        let mut tty = Console::new();
        let mut settings = tty.termios;
        settings[12..16].fill(0);
        tty.configure(settings, false, |_| panic!("unexpected input"));
        assert_eq!(
            input(&mut tty, b"a\x1b[A\r"),
            (b"a\x1b[A\n".to_vec(), vec![], 0)
        );
    }

    #[test]
    fn password_input_is_buffered_without_echo() {
        let mut tty = Console::new();
        tty.termios[12] &= !(ECHO as u8);
        assert_eq!(
            input(&mut tty, b"secret\r"),
            (b"secret\n".to_vec(), vec![], 0)
        );
    }

    #[test]
    fn utf8_erase_kill_and_eof() {
        let mut tty = Console::new();
        assert_eq!(input(&mut tty, "é\u{7f}x\u{15}".as_bytes()).0, b"");
        assert_eq!(input(&mut tty, b"\x04").2, 1);
        assert_eq!(
            input(&mut tty, b"hi\x04"),
            (b"hi".to_vec(), b"hi".to_vec(), 0)
        );
        assert_eq!(input(&mut tty, b"\x04").2, 1);
    }

    #[test]
    fn tab_erasure_preserves_the_shell_prompt() {
        let mut tty = Console::new();
        tty.set_column(2);
        assert_eq!(
            input(&mut tty, b"\t\x7f").1,
            [b"\t".as_slice(), b"\x08 \x08".repeat(6).as_slice()].concat()
        );
    }

    #[test]
    fn raw_transition_releases_pending_line_and_flush_discards_it() {
        let mut tty = Console::new();
        input(&mut tty, b"pending");
        let mut raw = tty.termios;
        raw[12] &= !(ICANON as u8);
        let mut data = Vec::new();
        tty.configure(raw, false, |b| data.extend_from_slice(b));
        assert_eq!(data, b"pending");
        let mut tty = Console::new();
        input(&mut tty, b"discard");
        tty.configure(raw, true, |_| panic!("flushed input delivered"));
        assert_eq!(input(&mut tty, b"x").0, b"x");
    }
}
