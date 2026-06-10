//! Hosted display frame mailbox.
//!
//! The VGA itself is emulated exactly once, kernel-side (the DOS machine
//! layer's `VgaState` + `display_tick` rendering through `lib::vga_render`);
//! this backend supplies only a place for the pixels — the hosted half of
//! "backends provide a framebuffer". The hosted `main` installs a present
//! sink that calls [`publish`]; the retroos-play window thread [`take`]s the
//! latest frame and blits it, and the `--screenshot` path [`peek`]s it.
//! (The interp registers no VGA device on its port bus, so the kernel's
//! presence probe reads 0xFF and picks the emulated register file.)

use std::sync::Mutex;

/// Latest rendered frame: (width, height, 0x00RRGGBB pixels). Publish
/// overwrites; take consumes; peek clones.
static FRAME: Mutex<Option<(usize, usize, Vec<u32>)>> = Mutex::new(None);

/// Store a rendered frame as the latest (the present sink; CPU thread).
pub fn publish(w: usize, h: usize, px: &[u32]) {
    if let Ok(mut slot) = FRAME.lock() {
        *slot = Some((w, h, px.to_vec()));
    }
}

/// Take the most recently published frame, if any (the play window thread).
pub fn take_frame() -> Option<(usize, usize, Vec<u32>)> {
    FRAME.lock().ok()?.take()
}

/// Clone the most recently published frame without consuming it (screenshots).
pub fn peek_frame() -> Option<(usize, usize, Vec<u32>)> {
    FRAME.lock().ok()?.clone()
}
