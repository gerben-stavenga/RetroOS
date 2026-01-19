//! VGA text mode output
//!
//! Supports both direct physical access (0xB8000) for bootloader
//! and paging-aware access via configurable base address.

use core::fmt::{self, Write};

const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const VGA_SIZE: usize = VGA_WIDTH * VGA_HEIGHT;

/// ANSI escape sequence parser state
#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Escape,  // saw ESC
    Csi,     // saw ESC [
}

/// VGA text mode state
pub struct Vga {
    pub base: usize,
    cursor_x: usize,
    cursor_y: usize,
    attr: u8,
    esc_state: EscState,
    esc_param: u8,
    /// Enable screen buffer writes (disable for early boot debugging)
    pub screen_enabled: bool,
}

impl Vga {
    const fn new() -> Self {
        Self {
            base: 0xB8000,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07, // LightGray on Black
            esc_state: EscState::Normal,
            esc_param: 0,
            screen_enabled: true,
        }
    }

    /// Convert ANSI color code to VGA color
    fn ansi_to_vga(code: u8, bright: bool) -> u8 {
        // ANSI: black, red, green, yellow, blue, magenta, cyan, white
        // VGA:  black, blue, green, cyan, red, magenta, brown, lightgray
        const MAP: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];
        MAP[code as usize & 7] + if bright { 8 } else { 0 }
    }

    /// Handle ANSI SGR (Select Graphic Rendition) code
    fn handle_sgr(&mut self, code: u8) {
        match code {
            0 => self.attr = 0x07,  // reset
            30..=37 => self.attr = (self.attr & 0xF0) | Self::ansi_to_vga(code - 30, false),
            40..=47 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_vga(code - 40, false) << 4),
            90..=97 => self.attr = (self.attr & 0xF0) | Self::ansi_to_vga(code - 90, true),
            100..=107 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_vga(code - 100, true) << 4),
            _ => {}
        }
    }

    fn buffer(&mut self) -> &mut [u16] {
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u16, VGA_SIZE) }
    }

    pub fn clear(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        for cell in self.buffer() {
            *cell = blank;
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    fn scroll(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        let buffer = self.buffer();
        buffer.copy_within(VGA_WIDTH.., 0);
        buffer[VGA_SIZE - VGA_WIDTH..].fill(blank);
    }

    pub fn putchar(&mut self, c: u8) {
        // Output to QEMU debug console (port 0xE9)
        unsafe {
            core::arch::asm!("out dx, al", in("dx") 0xE9u16, in("al") c);
        }

        if !self.screen_enabled {
            return;
        }

        // Handle ANSI escape sequences
        match self.esc_state {
            EscState::Escape => {
                if c == b'[' {
                    self.esc_state = EscState::Csi;
                    self.esc_param = 0;
                } else {
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Csi => {
                if c.is_ascii_digit() {
                    self.esc_param = self.esc_param.saturating_mul(10).saturating_add(c - b'0');
                } else if c == b'm' {
                    self.handle_sgr(self.esc_param);
                    self.esc_state = EscState::Normal;
                } else {
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Normal => {}
        }

        match c {
            0x1b => {
                self.esc_state = EscState::Escape;
            }
            b'\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            b'\r' => {
                self.cursor_x = 0;
            }
            _ => {
                let offset = self.cursor_y * VGA_WIDTH + self.cursor_x;
                self.buffer()[offset] = (self.attr as u16) << 8 | (c as u16);
                self.cursor_x += 1;
                if self.cursor_x >= VGA_WIDTH {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }
            }
        }

        if self.cursor_y >= VGA_HEIGHT {
            self.scroll();
            self.cursor_y = VGA_HEIGHT - 1;
        }
    }
}

impl Write for Vga {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.putchar(byte);
        }
        Ok(())
    }
}

/// Global VGA state
static mut VGA: Vga = Vga::new();

/// Access the global VGA state
pub fn vga() -> &'static mut Vga {
    unsafe { &mut *(&raw mut VGA) }
}

/// Print formatted text
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::vga::vga().write_fmt(format_args!($($arg)*));
    }};
}

/// Print formatted text with newline
#[macro_export]
macro_rules! println {
    () => { $crate::vga::vga().putchar(b'\n') };
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::vga::vga().putchar(b'\n');
    }};
}
