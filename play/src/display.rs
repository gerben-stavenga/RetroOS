//! The SDL window: video out, keyboard + mouse in. Runs on the MAIN thread —
//! SDL's event pump belongs to the thread that created the window — while the
//! CPU/kernel runs on a worker thread (see `main.rs`).
//!
//! Video is pull-based across the thread boundary: each loop iteration asks the
//! backend for a frame (`request_frame`), the CPU thread renders at its next
//! slice boundary (the only thread where guest RAM and the captured VGA state
//! are valid — same pattern as the `--screenshot` dump), and the next iteration
//! `take_frame`s and blits it. Input crosses the other way through the
//! backend's thread-safe IRQ queue (`post_irq`).

use retroos_arch_interp as arch;

use arch::Irq;
use sdl2::event::Event;
use sdl2::keyboard::{Mod, Scancode};
use sdl2::mouse::MouseButton;
use sdl2::pixels::PixelFormatEnum;
use std::time::Duration;

/// Default window size: 2× a 320×200 mode-13h frame. Other modes are scaled to
/// fill (SDL stretches the texture to the canvas).
const WIN_W: u32 = 640;
const WIN_H: u32 = 400;
/// Main-loop period: pump input + present at ~60 Hz.
const TICK: Duration = Duration::from_millis(16);

/// Create the window and run the pump/present loop forever. Quits the process
/// on window close. Panics on SDL failure — a play run with no usable display
/// is a hard configuration error, not something to limp past.
pub fn run() -> ! {
    let sdl = sdl2::init().expect("SDL init");
    let video = sdl.video().expect("SDL video");
    let window = video
        .window("RetroOS — DOS", WIN_W, WIN_H)
        .position_centered()
        .build()
        .expect("SDL window");
    let mut canvas = window.into_canvas().build().expect("SDL canvas");
    let texture_creator = canvas.texture_creator();
    let mut event_pump = sdl.event_pump().expect("SDL event pump");

    // INT 33h button mask (bit 0 left, 1 right, 2 middle) — the kernel's mouse
    // packet wants the current mask, not edge events.
    let mut buttons: u8 = 0;
    // Fractional motion carry: window-pixel deltas are scaled to the INT 33h
    // coordinate space (640×200), so a slow 1-px vertical move is < 1 unit and
    // must accumulate instead of truncating to zero.
    let mut acc = (0.0f32, 0.0f32);
    // Pointer captured (SDL relative mode): grabbed on first click, released
    // with Ctrl+F10 (the DOSBox convention).
    let mut captured = false;
    // Last presented frame dimensions — window resizes on change.
    let mut last_dims = (0usize, 0usize);

    loop {
        for event in event_pump.poll_iter() {
            match event {
                Event::Quit { .. } => std::process::exit(0),
                Event::KeyDown { scancode: Some(Scancode::F10), keymod, .. }
                    if keymod.intersects(Mod::LCTRLMOD | Mod::RCTRLMOD) =>
                {
                    captured = false; // Ctrl+F10: release the pointer
                    sdl.mouse().set_relative_mouse_mode(false);
                    let _ = canvas.window_mut().set_title("RetroOS — DOS");
                }
                Event::KeyDown { scancode: Some(sc), repeat: false, .. } => {
                    if let Some(pc) = pc_scancode(sc) {
                        arch::post_irq(Irq::Key(pc));
                    }
                }
                Event::KeyUp { scancode: Some(sc), .. } => {
                    if let Some(pc) = pc_scancode(sc) {
                        arch::post_irq(Irq::Key(pc | 0x80));
                    }
                }
                Event::MouseMotion { xrel, yrel, .. } => {
                    // Scale window-pixel deltas to the INT 33h space the
                    // kernel's MouseState lives in (640×200 over the window).
                    let (w, h) = canvas.window().size();
                    acc.0 += xrel as f32 * 640.0 / w.max(1) as f32;
                    acc.1 += yrel as f32 * 200.0 / h.max(1) as f32;
                    let (dx, dy) = (acc.0 as i16, acc.1 as i16);
                    if dx != 0 || dy != 0 {
                        acc.0 -= dx as f32;
                        acc.1 -= dy as f32;
                        arch::post_irq(Irq::Mouse { dx, dy, buttons });
                    }
                }
                Event::MouseButtonDown { mouse_btn, .. } => {
                    if !captured {
                        captured = true; // first click grabs the pointer
                        sdl.mouse().set_relative_mouse_mode(true);
                        let _ = canvas
                            .window_mut()
                            .set_title("RetroOS — DOS (Ctrl+F10 releases mouse)");
                    }
                    if let Some(bit) = button_bit(mouse_btn) {
                        buttons |= bit;
                        arch::post_irq(Irq::Mouse { dx: 0, dy: 0, buttons });
                    }
                }
                Event::MouseButtonUp { mouse_btn, .. } => {
                    if let Some(bit) = button_bit(mouse_btn) {
                        buttons &= !bit;
                        arch::post_irq(Irq::Mouse { dx: 0, dy: 0, buttons });
                    }
                }
                _ => {}
            }
        }

        // Blit the latest frame the kernel's display tick published (PIT-tick
        // cadence; one loop-period of latency, by design).
        if let Some((w, h, fb)) = arch::take_frame() {
            // Integer scaling: size the window to a whole multiple of the
            // frame so glyph columns stay crisp. The old fixed 640-wide
            // window forced 720x400 text into a 0.89x downscale — every
            // 9-dot cell lost a column and text read "thin". Scale to
            // ~800px tall: text (400) -> 2x, mode 13h (200) -> 4x.
            if (w, h) != last_dims {
                last_dims = (w, h);
                let scale = (800 / h as u32).max(1);
                let _ = canvas
                    .window_mut()
                    .set_size(w as u32 * scale, h as u32 * scale);
            }
            // A fresh streaming texture each frame keeps this trivial across
            // mode/size changes; at 320×200/720×400 it's negligible. RGB888 is
            // SDL's *alpha-less* 32-bit format (X8R8G8B8) whose channel masks
            // are exactly our 0x00RRGGBB u32 — a byte-for-byte memcpy on a
            // little-endian host, and the window stays opaque. (ARGB8888 with
            // our alpha=0 makes a compositing WM render the window invisible.)
            let mut texture = texture_creator
                .create_texture_streaming(PixelFormatEnum::RGB888, w as u32, h as u32)
                .expect("texture");
            let bytes =
                unsafe { core::slice::from_raw_parts(fb.as_ptr() as *const u8, fb.len() * 4) };
            let _ = texture.update(None, bytes, w * 4);
            let _ = canvas.copy(&texture, None, None); // stretch to the window
            canvas.present();
        }
        std::thread::sleep(TICK);
    }
}

/// SDL button → INT 33h mask bit (0 = left, 1 = right, 2 = middle).
fn button_bit(btn: MouseButton) -> Option<u8> {
    Some(match btn {
        MouseButton::Left => 0x01,
        MouseButton::Right => 0x02,
        MouseButton::Middle => 0x04,
        _ => return None,
    })
}

/// SDL (USB-HID) scancode → PC Set-1 make code. Covers the keys a DOS program
/// reads through the BIOS; arrows/navigation use their bare (un-prefixed) codes,
/// matching the stdin pump's escape-sequence mapping. `None` for unmapped keys.
fn pc_scancode(sc: Scancode) -> Option<u8> {
    use Scancode::*;
    Some(match sc {
        Escape => 0x01,
        Num1 => 0x02, Num2 => 0x03, Num3 => 0x04, Num4 => 0x05, Num5 => 0x06,
        Num6 => 0x07, Num7 => 0x08, Num8 => 0x09, Num9 => 0x0A, Num0 => 0x0B,
        Minus => 0x0C, Equals => 0x0D, Backspace => 0x0E, Tab => 0x0F,
        Q => 0x10, W => 0x11, E => 0x12, R => 0x13, T => 0x14, Y => 0x15,
        U => 0x16, I => 0x17, O => 0x18, P => 0x19,
        LeftBracket => 0x1A, RightBracket => 0x1B, Return => 0x1C,
        LCtrl => 0x1D, RCtrl => 0x1D,
        A => 0x1E, S => 0x1F, D => 0x20, F => 0x21, G => 0x22, H => 0x23,
        J => 0x24, K => 0x25, L => 0x26, Semicolon => 0x27, Apostrophe => 0x28,
        Grave => 0x29, LShift => 0x2A, Backslash => 0x2B,
        Z => 0x2C, X => 0x2D, C => 0x2E, V => 0x2F, B => 0x30, N => 0x31,
        M => 0x32, Comma => 0x33, Period => 0x34, Slash => 0x35, RShift => 0x36,
        KpMultiply => 0x37, LAlt => 0x38, RAlt => 0x38, Space => 0x39,
        CapsLock => 0x3A,
        F1 => 0x3B, F2 => 0x3C, F3 => 0x3D, F4 => 0x3E, F5 => 0x3F, F6 => 0x40,
        F7 => 0x41, F8 => 0x42, F9 => 0x43, F10 => 0x44, F11 => 0x57, F12 => 0x58,
        // Bare extended-key codes (no 0xE0 prefix), as the stdin pump posts them.
        Up => 0x48, Down => 0x50, Left => 0x4B, Right => 0x4D,
        Home => 0x47, End => 0x4F, PageUp => 0x49, PageDown => 0x51,
        Insert => 0x52, Delete => 0x53,
        _ => return None,
    })
}
