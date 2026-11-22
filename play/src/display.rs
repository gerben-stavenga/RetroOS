//! The SDL window: video out, keyboard + mouse in. Runs on the MAIN thread —
//! SDL's event pump belongs to the thread that created the window — while the
//! CPU/kernel runs on a worker thread (see `main.rs`).
//!
//! The kernel publishes its latest completed frame. The window reads it
//! and applies the selected scaling when presenting fullscreen DOS.

use retroos_arch_interp as arch;

use arch::Irq;
use kernel::kernel::display::{ExternalDisplay, FrameLayout};
use sdl2::event::{Event, WindowEvent};
use sdl2::keyboard::{Mod, Scancode};
use sdl2::mouse::MouseButton;
use sdl2::pixels::{Color, PixelFormatEnum};
use sdl2::rect::Rect;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Main-loop period: pump input + present at ~60 Hz.
const TICK: Duration = Duration::from_millis(16);

struct Frame {
    layout: FrameLayout,
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

static FRAME: Mutex<Option<Frame>> = Mutex::new(None);
static VIEWPORT: AtomicU64 = AtomicU64::new(0);

pub const ENDPOINT: ExternalDisplay = ExternalDisplay {
    output: || {
        let size = VIEWPORT.load(Ordering::Relaxed);
        (b"Host", (size >> 32) as usize, size as u32 as usize)
    },
    present: |layout, width, height, pixels| {
        *FRAME.lock().unwrap() = Some(Frame { layout, width, height, pixels });
    },
};

fn report_viewport((width, height): (u32, u32)) {
    VIEWPORT.store((u64::from(width) << 32) | u64::from(height), Ordering::Relaxed);
}

/// Create the window and run the pump/present loop forever. Quits the process
/// on window close. Panics on SDL failure — a play run with no usable display
/// is a hard configuration error, not something to limp past.
pub fn run(sdl: &sdl2::Sdl) -> ! {
    let video = sdl.video().expect("SDL video");
    // Keep a large restored size in case the window manager ignores maximize.
    // Leave room for decorations even if SDL only reports the full display.
    let (width, height) = video.display_usable_bounds(0)
        .or_else(|_| video.display_bounds(0))
        .map(|area| (area.width() - area.width() / 10, area.height() - area.height() / 10))
        .unwrap_or((960, 600));
    let window = video
        .window("RetroOS — DOS", width, height)
        .position_centered()
        .resizable()
        .build()
        .expect("SDL window");
    sdl2::hint::set("SDL_RENDER_SCALE_QUALITY", "nearest");
    let mut canvas = window.into_canvas().build().expect("SDL canvas");
    canvas.window_mut().maximize();
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
    let mut texture = None;
    let mut source = (width, height);
    let mut layout = FrameLayout::Desktop;
    let mut pane = canvas.output_size().unwrap_or_else(|_| canvas.window().size());
    report_viewport(pane);
    let mut target = Rect::new(0, 0, pane.0, pane.1);

    loop {
        let mut redraw = false;
        for event in event_pump.poll_iter() {
            match event {
                Event::Quit { .. } => std::process::exit(0),
                Event::Window { win_event: WindowEvent::Exposed, .. } => {
                    redraw = true;
                }
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
                    // Convert window coordinates through the rendered picture,
                    // then to the INT 33h space (640×200).
                    let (w, h) = canvas.window().size();
                    acc.0 += xrel as f32 * 640.0 * pane.0 as f32
                        / (w.max(1) as f32 * target.width() as f32);
                    acc.1 += yrel as f32 * 200.0 * pane.1 as f32
                        / (h.max(1) as f32 * target.height() as f32);
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

        let viewport = canvas.output_size().unwrap_or_else(|_| canvas.window().size());
        if viewport.0 == 0 || viewport.1 == 0 {
            std::thread::sleep(TICK);
            continue;
        }
        if viewport != pane {
            pane = viewport;
            report_viewport(pane);
            redraw = true;
        }

        let frame = FRAME.lock().unwrap().take();
        if let Some(Frame { layout: new_layout, width, height, pixels }) = frame {
            layout = new_layout;
            let dimensions = (width as u32, height as u32);
            if texture.is_none() || dimensions != source {
                source = dimensions;
                texture = Some(texture_creator.create_texture_streaming(
                    PixelFormatEnum::RGB888, source.0, source.1,
                ).expect("texture"));
            }
            // SDL RGB888 is the kernel's opaque XRGB8888 pixel layout.
            let bytes =
                unsafe { core::slice::from_raw_parts(pixels.as_ptr().cast::<u8>(), pixels.len() * 4) };
            texture.as_mut().unwrap().update(None, bytes, width * 4).expect("upload frame");
            redraw = true;
        }
        if redraw {
            target = picture_rect(pane, source, layout);
            canvas.set_draw_color(Color::BLACK);
            canvas.clear();
            if let Some(texture) = &texture {
                canvas.copy(texture, None, target).expect("present frame");
            }
            canvas.present();
        }
        std::thread::sleep(TICK);
    }
}

fn picture_rect(
    (width, height): (u32, u32), (source_w, source_h): (u32, u32), layout: FrameLayout,
) -> Rect {
    let (w, h) = layout.output_size((width as usize, height as usize), (source_w as usize, source_h as usize));
    let (w, h) = (w.max(1) as u32, h.max(1) as u32);
    Rect::new(((width - w) / 2) as i32, ((height - h) / 2) as i32, w, h)
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
