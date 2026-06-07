//! Host terminal raw mode for the interactive console. Puts stdin into
//! char-at-a-time, no-echo, no-signal mode so keystrokes reach the guest
//! immediately (and are echoed once, by the guest shell — not the host tty),
//! and so Ctrl-C/Ctrl-Z arrive as bytes for the keyboard translator rather than
//! signalling the host process.
//!
//! Restored via `atexit`, not `Drop`: the kernel exits through
//! `std::process::exit` (= libc `exit`, which runs atexit handlers), so a Drop
//! guard would never fire and would leave the user's terminal wedged.

use std::sync::OnceLock;

static ORIG: OnceLock<libc::termios> = OnceLock::new();

extern "C" fn restore() {
    if let Some(orig) = ORIG.get() {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
        }
    }
}

/// Put stdin into raw mode. No-op if stdin isn't a TTY (piped input still works
/// — bytes are read raw either way) or if already entered.
pub fn enter_raw_mode() {
    unsafe {
        let fd = libc::STDIN_FILENO;
        if libc::isatty(fd) == 0 {
            return;
        }
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut orig) != 0 {
            return;
        }
        if ORIG.set(orig).is_err() {
            return; // already in raw mode
        }
        let mut raw = orig;
        // Char-at-a-time, no echo, no line editing, no ISIG (Ctrl-C → byte).
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::BRKINT);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
        libc::atexit(restore);
    }
}
