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

struct Mailbox {
    ready: Option<(usize, usize, Vec<u32>)>,
    spare: Vec<u32>,
}

/// Latest rendered frame plus a returned allocation for the CPU renderer.
static FRAME: Mutex<Mailbox> = Mutex::new(Mailbox {
    ready: None,
    spare: Vec::new(),
});

/// Swap a completed frame into the mailbox (the present sink; CPU thread).
pub fn publish(w: usize, h: usize, px: &mut Vec<u32>) {
    if let Ok(mut mailbox) = FRAME.lock() {
        std::mem::swap(px, &mut mailbox.spare);
        let completed = std::mem::take(&mut mailbox.spare);
        if let Some((_, _, old)) = mailbox.ready.replace((w, h, completed)) {
            mailbox.spare = old;
        }
    }
}

/// Take the most recently published frame, if any (the play window thread).
pub fn take_frame() -> Option<(usize, usize, Vec<u32>)> {
    FRAME.lock().ok()?.ready.take()
}

/// Return a consumed frame allocation for the CPU thread's next render.
pub fn recycle_frame(px: Vec<u32>) {
    if let Ok(mut mailbox) = FRAME.lock() {
        if px.capacity() > mailbox.spare.capacity() {
            mailbox.spare = px;
        }
    }
}

/// Clone the most recently published frame without consuming it (screenshots).
pub fn peek_frame() -> Option<(usize, usize, Vec<u32>)> {
    FRAME.lock().ok()?.ready.clone()
}
