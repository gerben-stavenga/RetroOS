//! Publishing the terminal as graphical content.
//!
//! The terminal itself — grid, cursor, ANSI parser — is `lib::term`, shared by
//! every embedder. This module turns that grid into a canonical 720x400 content
//! buffer, attaches it to a personality-neutral scene node, and composes the
//! scene into the current display's packed shadow. Legacy boot consoles may
//! still let a real VGA scan B8000 directly before the event loop takes over.
//!
//! Rendering reads the terminal's own grid — 4000 bytes, drawn whole. No
//! personality or content producer sees the physical framebuffer format.

pub use lib::term::{Term, putchar, term};

use crate::kernel::display::Display;
use core::sync::atomic::{AtomicBool, Ordering};
use lib::vga_fonts::FONT_8X16;
use vga::{Frame, VgaMode};

/// VGA text palette used to turn terminal attributes into canonical RGB.
static mut PALETTE: [u8; 768] = [0; 768];

/// Packed terminal shadow. Terminal writes only dirty the grid; the event-loop
/// display tick renders this buffer (the boot console flushes at its handoff),
/// after which the shared display boundary composites the OSD and publishes it.
struct Scanout {
    pal: vga::Pal,
    pal_cache: [u8; 768],
    /// Producer back buffer; a surface commit swaps it with the desktop front.
    content: alloc::vec::Vec<u8>,
    /// Output-format shadow produced by the GUI scene compositor.
    surface: alloc::vec::Vec<u8>,
    /// Startup/panic path before an event loop owns the real desktop.
    bootstrap_desktop: Option<crate::kernel::gui::Desktop>,
}

impl Scanout {
    const fn new() -> Scanout {
        Scanout {
            pal: vga::Pal::new(),
            pal_cache: [0; 768],
            content: alloc::vec::Vec::new(),
            surface: alloc::vec::Vec::new(),
            bootstrap_desktop: None,
        }
    }
}

static mut SCANOUT: Scanout = Scanout::new();
static DIRTY: AtomicBool = AtomicBool::new(true);

/// Request a terminal/OSD frame at the next event-loop display tick.
pub fn mark_dirty() {
    DIRTY.store(true, Ordering::Release);
}

/// Identity Attribute-Controller palette. Text rendering consumes the first
/// sixteen entries; mode control remains zero for normal text semantics.
static TEXT_AC: [u8; 21] = {
    let mut ac = [0u8; 21];
    let mut i = 0;
    while i < 16 {
        ac[i] = i as u8;
        i += 1;
    }
    ac
};

/// Render the terminal into its back buffer, commit it to the retained surface,
/// and pass the completed desktop shadow to the display boundary.
pub fn present<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut Display,
) {
    if !DIRTY.swap(false, Ordering::AcqRel) || display.shadow_width == 0 {
        return;
    }
    let Some((height, shadow)) = render(display, None) else {
        return;
    };
    display.present(machine, bios, height, shadow);
}

/// Event-loop publication through the desktop that outlives every focused
/// personality. Focusing an endpoint forces one frame even when the shared
/// terminal cells themselves did not change.
pub fn present_on<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    let focus_changed = desktop.focus(endpoint);
    if (!focus_changed && !DIRTY.swap(false, Ordering::AcqRel)) || display.shadow_width == 0 {
        return;
    }
    DIRTY.store(false, Ordering::Release);
    let Some((height, shadow)) = render(display, Some((desktop, endpoint))) else {
        return;
    };
    display.present(machine, bios, height, shadow);
}

/// Best-effort terminal publication for the panic handler.  The system is no
/// longer live, so deliberately seize the global scanout even if the failed
/// call chain had borrowed it.
pub fn panic_present(display: &mut Display) {
    if let Some((height, shadow)) = render(display, None) {
        display.panic_present(height, shadow);
    }
}

fn render(
    display: &mut Display,
    desktop: Option<(
        &mut crate::kernel::gui::Desktop,
        crate::kernel::gui::EndpointId,
    )>,
) -> Option<(usize, &'static mut [u8])> {
    if display.shadow_width == 0 {
        return None;
    }
    unsafe {
        if PALETTE == [0; 768] {
            PALETTE = vga::fallback_palette();
        }
    }
    let vram = lib::term::term().cells_bytes();
    let palette_p = &raw const PALETTE;
    let frame = Frame {
        mode: VgaMode::Text {
            cols: 80,
            rows: 25,
            cell_w: 9,
            cell_h: 16,
        },
        vram,
        planes: &[],
        ac: &TEXT_AC,
        palette: unsafe { &*palette_p },
        dac_mask: 0xFF,
        font: &FONT_8X16,
        font_b: &FONT_8X16,
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    render_frame(display, &frame, desktop)
}

fn render_frame(
    display: &mut Display,
    frame: &Frame<'_>,
    desktop: Option<(
        &mut crate::kernel::gui::Desktop,
        crate::kernel::gui::EndpointId,
    )>,
) -> Option<(usize, &'static mut [u8])> {
    let managed = desktop.is_some();
    let (w, h) = vga::dimensions(frame.mode);
    let out_w = display.shadow_width;
    if w == 0 || h == 0 || out_w == 0 {
        return None;
    }

    // The terminal is a content producer, not an output renderer. Keep its
    // native 720x400 XRGB8888 pixels independent of the physical display;
    // scene composition performs scaling and output-format conversion.
    let content_format = vga::PixelFormat::NATIVE;
    let content_step = content_format.bytes_per_pixel as usize;
    let content_row_bytes = w * content_step;
    let slack = 4; // final render_row_stretched overlapping dword store
    let scanout_p = &raw mut SCANOUT;
    let s = unsafe { &mut *scanout_p };
    let Scanout {
        pal,
        pal_cache,
        content,
        surface,
        bootstrap_desktop,
    } = s;
    let need = content_row_bytes * h + slack;
    if content.len() != need {
        content.resize(need, 0);
    }
    pal.sync(frame.palette, frame.dac_mask, content_format, pal_cache);
    for sy in 0..h {
        vga::render_row_stretched(frame, sy, pal, content, w);
    }

    const TERMINAL_SURFACE: crate::kernel::gui::SurfaceKey = crate::kernel::gui::SurfaceKey(1);
    const TERMINAL_PRESENTATION: crate::kernel::gui::PresentationKey =
        crate::kernel::gui::PresentationKey(1);
    const BOOT_ENDPOINT: crate::kernel::gui::EndpointId = crate::kernel::gui::EndpointId(0);
    let (desktop, endpoint) = match desktop {
        Some(pair) => pair,
        None => (
            bootstrap_desktop.get_or_insert_with(crate::kernel::gui::Desktop::new),
            BOOT_ENDPOINT,
        ),
    };
    desktop.focus(endpoint);
    let surface_id = desktop
        .ensure_surface(endpoint, TERMINAL_SURFACE)
        .expect("create terminal surface");
    let node_width = if managed { w } else { out_w };
    let node = desktop
        .ensure_node(
            endpoint,
            TERMINAL_PRESENTATION,
            crate::kernel::gui::Rect::new(0, 0, node_width as u32, h as u32),
        )
        .expect("create terminal presentation node");
    let placement = desktop.geometry(node).expect("live terminal presentation node");
    let mut transaction = crate::kernel::gui::Transaction::new(endpoint);
    transaction
        .set_geometry(
            node,
            crate::kernel::gui::Rect::new(
                placement.x,
                placement.y,
                node_width as u32,
                h as u32,
            ),
        )
        .attach(node, Some(surface_id))
        .set_visible(node, true);
    desktop
        .commit(transaction)
        .expect("commit terminal presentation node");

    let submitted = core::mem::take(content);
    let buffer = crate::kernel::gui::SurfaceBuffer::new(
        w,
        h,
        content_row_bytes,
        content_format,
        submitted,
    )
    .expect("valid terminal content buffer");
    let recycled = desktop
        .commit_surface(endpoint, surface_id, buffer)
        .expect("commit terminal surface");
    *content = recycled
        .map(crate::kernel::gui::SurfaceBuffer::into_pixels)
        .unwrap_or_default();
    let extent = desktop.extent();
    let (canvas_width, canvas_height) = display.composition_size(
        extent.width as usize,
        extent.height as usize,
    );
    if display.is_host() {
        display.shadow_width = canvas_width;
    }
    desktop
        .compose_retained(canvas_width, canvas_height, display.rgb, surface)
        .expect("compose terminal scene");
    Some((canvas_height, surface))
}
