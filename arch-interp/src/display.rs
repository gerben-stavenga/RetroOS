//! Live SDL2 A/V/input window — the hosted display sink.
//!
//! SDL2 is **push/poll**: we own the loop. The CPU/kernel runs on the main
//! thread and, at each execution-slice boundary (`cpu::execute`), calls
//! [`tick`] — which drains SDL input events into the kernel's IRQ queue and
//! blits the framebuffer that `lib::vga_render` produced from the captured VGA
//! state. SDL never runs an event loop of its own; it's just a sink we poke,
//! exactly like the WAV audio sink and the terminal screendump.
//!
//! Everything here stays on the one CPU/main thread (the SDL handles aren't
//! `Send`, and guest RAM is thread-local to that thread anyway), so the window
//! is created in [`init`] from `main` before `kernel::startup()` and pumped from
//! the same thread thereafter.

use arch_abi::Irq;
use sdl2::event::Event;
use sdl2::keyboard::Scancode;
use sdl2::pixels::PixelFormatEnum;
use sdl2::render::{TextureCreator, WindowCanvas};
use sdl2::video::WindowContext;
use sdl2::{EventPump, Sdl, VideoSubsystem};
use std::cell::RefCell;
use std::time::{Duration, Instant};

/// Default window size: 2× a 320×200 mode-13h frame. Other modes are scaled to
/// fill (SDL stretches the texture to the canvas).
const WIN_W: u32 = 640;
const WIN_H: u32 = 400;
/// Don't present faster than this (the CPU slice hook fires far more often).
const FRAME_INTERVAL: Duration = Duration::from_millis(16); // ~60 Hz

struct Display {
    // `_sdl`/`_video` are kept alive for the lifetime of the window/pump.
    _sdl: Sdl,
    _video: VideoSubsystem,
    canvas: WindowCanvas,
    texture_creator: TextureCreator<WindowContext>,
    event_pump: EventPump,
    last_present: Instant,
}

thread_local! {
    static DISPLAY: RefCell<Option<Display>> = const { RefCell::new(None) };
}

/// Create the window. Call once on the CPU/main thread before `startup()`.
/// Panics on SDL failure — a `--window` run with no usable display is a hard
/// configuration error, not something to limp past.
pub fn init() {
    let sdl = sdl2::init().expect("SDL init");
    let video = sdl.video().expect("SDL video");
    let window = video
        .window("RetroOS — DOS", WIN_W, WIN_H)
        .position_centered()
        .build()
        .expect("SDL window");
    // No vsync: we throttle presentation ourselves and must never block the CPU
    // thread waiting on the display's refresh.
    let canvas = window.into_canvas().build().expect("SDL canvas");
    let texture_creator = canvas.texture_creator();
    let event_pump = sdl.event_pump().expect("SDL event pump");
    DISPLAY.with(|d| {
        *d.borrow_mut() = Some(Display {
            _sdl: sdl,
            _video: video,
            canvas,
            texture_creator,
            event_pump,
            last_present: Instant::now() - FRAME_INTERVAL,
        });
    });
}

/// Drain input + present a frame. Cheap no-op when no window was created. Runs
/// on the CPU thread from the execution-slice hook.
pub fn tick() {
    DISPLAY.with(|d| {
        let mut slot = d.borrow_mut();
        let Some(disp) = slot.as_mut() else { return };
        pump_input(disp);
        present(disp);
    });
}

/// Poll all pending SDL events: window close quits the host; key press/release
/// become PS/2 scancodes posted to the kernel IRQ queue (press = scancode,
/// release = scancode | 0x80 — the convention the stdin pump and kernel use).
fn pump_input(disp: &mut Display) {
    for event in disp.event_pump.poll_iter() {
        match event {
            Event::Quit { .. } => {
                // Runs atexit (restores the terminal the kernel may have raw-ed).
                std::process::exit(0);
            }
            Event::KeyDown { scancode: Some(sc), repeat: false, .. } => {
                if let Some(pc) = pc_scancode(sc) {
                    crate::machine::post_irq(Irq::Key(pc));
                }
            }
            Event::KeyUp { scancode: Some(sc), .. } => {
                if let Some(pc) = pc_scancode(sc) {
                    crate::machine::post_irq(Irq::Key(pc | 0x80));
                }
            }
            _ => {}
        }
    }
}

/// Render the guest's current screen (if a renderable mode) and blit it,
/// throttled to `FRAME_INTERVAL`.
fn present(disp: &mut Display) {
    if disp.last_present.elapsed() < FRAME_INTERVAL {
        return;
    }
    let Some((w, h, fb)) = crate::vga::render_current() else {
        return; // text/unhandled mode: leave the last frame up
    };
    disp.last_present = Instant::now();

    // A fresh streaming texture each frame keeps this trivial across mode/size
    // changes; at 320×200/720×400 it's negligible. RGB888 is SDL's *alpha-less*
    // 32-bit format (X8R8G8B8) whose channel masks are exactly our 0x00RRGGBB
    // u32 — so the upload is a byte-for-byte memcpy on a little-endian host, and
    // the window stays opaque. (ARGB8888 with our alpha=0 makes a compositing WM
    // render the whole window transparent — "nothing in the window".)
    let mut texture = disp
        .texture_creator
        .create_texture_streaming(PixelFormatEnum::RGB888, w as u32, h as u32)
        .expect("texture");
    let bytes = unsafe { core::slice::from_raw_parts(fb.as_ptr() as *const u8, fb.len() * 4) };
    let _ = texture.update(None, bytes, w * 4);
    let _ = disp.canvas.copy(&texture, None, None); // stretch to the window
    disp.canvas.present();
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
