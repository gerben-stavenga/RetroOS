//! GOP linear-framebuffer text console — the kernel console on UEFI-class
//! machines (the `run_uefi.sh` mock, modern laptops), which have no VGA text
//! mode: the display is a dumb linear framebuffer and writes to 0xB8000 show
//! nothing.
//!
//! The console keeps its 80×25 char+attr cell model unchanged — `lib::vga`
//! writes cells into a RAM shadow buffer instead of 0xB8000 (same move the
//! hosted build makes, `host_console_init`) — and this module renders dirty
//! cells through `lib::vga_render` into the multiboot-reported framebuffer
//! after every console write (the `set_text_flush` hook). Text renders at
//! 720×400, centered.
//!
//! Like `boot.rs`, this is metal boot glue: legacy-BIOS machines never call
//! `init` and keep writing real B8000 text cells; the kernel above notices
//! nothing either way.

use arch::paging2::{self, PAGE_SIZE};
use lib::vga_render::{self, Frame, VgaMode};
use lib::vga_font_8x16::FONT_8X16;

/// The RAM text buffer the console writes cells into (replaces 0xB8000).
/// 0x0720 = blank: space on light-gray-on-black.
static mut TEXT_BUF: [u16; 80 * 25] = [0x0720; 80 * 25];

/// Cells as last rendered to pixels; `flush` re-renders only what differs.
/// All-zero ≠ any real cell (attr 0x00 is never written), so the first flush
/// after `init` renders the whole backlog.
static mut SHADOW: [u16; 80 * 25] = [0; 80 * 25];

/// DAC palette for attribute colors (filled from `fallback_palette` at init).
static mut PALETTE: [u8; 768] = [0; 768];
/// Identity Attribute-Controller palette (AC[i]=i): text rendering doesn't use
/// the planar colour path, but `Frame` requires the field. Mode-control byte
/// (index 0x10) left 0 = blink semantics, matching `blink: false` here.
static FBCON_AC: [u8; 21] = {
    let mut a = [0u8; 21];
    let mut i = 0;
    while i < 16 { a[i] = i as u8; i += 1; }
    a
};

/// Framebuffer geometry, set once by `init` (None until then / on legacy VGA).
struct Geom {
    /// First mapped framebuffer pixel, as a kernel VA.
    va: usize,
    /// Row pitch in pixels (multiboot pitch is in bytes; bpp is 32 here).
    stride: usize,
    /// Pixel offset of the centered 720×400 text origin within the mapping.
    origin: usize,
    /// Total mapped pixels from `va` (bounds for the cell renderer).
    len: usize,
    /// Convert the renderer's canonical 0x00RRGGBB pixels to the GOP layout.
    format: PixelFormat,
}
static mut GEOM: Option<Geom> = None;

const TEXT_W: usize = 720;
const TEXT_H: usize = 400;
const CELL_W: usize = 9;
const CELL_H: usize = 16;

#[derive(Clone, Copy)]
struct PixelFormat {
    red_pos: u8,
    red_size: u8,
    green_pos: u8,
    green_size: u8,
    blue_pos: u8,
    blue_size: u8,
}

impl PixelFormat {
    fn from_multiboot(info: &arch::MultibootInfo) -> Option<Self> {
        if info.framebuffer_bpp != 32 {
            return None;
        }
        let [red_pos, red_size, green_pos, green_size, blue_pos, blue_size] =
            info.color_info;
        let fields = [
            (red_pos, red_size),
            (green_pos, green_size),
            (blue_pos, blue_size),
        ];
        let mut used = 0u32;
        for (pos, size) in fields {
            if size == 0 || size > 16 || pos >= 32 || pos as u16 + size as u16 > 32 {
                return None;
            }
            let mask = (((1u64 << size) - 1) << pos) as u32;
            if used & mask != 0 {
                return None;
            }
            used |= mask;
        }
        Some(Self {
            red_pos,
            red_size,
            green_pos,
            green_size,
            blue_pos,
            blue_size,
        })
    }

    fn is_native(self) -> bool {
        (self.red_pos, self.red_size, self.green_pos, self.green_size,
            self.blue_pos, self.blue_size) == (16, 8, 8, 8, 0, 8)
    }

    fn encode(self, rgb: u32) -> u32 {
        fn channel(value: u32, pos: u8, size: u8) -> u32 {
            let max = (1u64 << size) - 1;
            ((((value as u64 * max) + 127) / 255) << pos) as u32
        }
        channel((rgb >> 16) & 0xFF, self.red_pos, self.red_size)
            | channel((rgb >> 8) & 0xFF, self.green_pos, self.green_size)
            | channel(rgb & 0xFF, self.blue_pos, self.blue_size)
    }
}

fn geom() -> &'static mut Option<Geom> {
    unsafe { &mut *(&raw mut GEOM) }
}

/// Whether the framebuffer console owns the display (a linear framebuffer
/// was handed over and mapped). Probed by `kernel::platform`.
pub fn active() -> bool {
    geom().is_some()
}

/// Early hook, called by `boot_kernel` before the first `println!`: if the
/// bootloader handed us a linear RGB framebuffer (i.e. there is no VGA text
/// mode to write to), repoint the console's cell buffer at RAM. The pixel
/// side (`init`) comes later in boot — cell writes accumulate in the buffer
/// meanwhile and the first flush renders the backlog.
///
/// Returns whether the framebuffer console is in use.
pub fn early(info: &arch::MultibootInfo) -> bool {
    if info.flags & arch::MULTIBOOT_INFO_FRAMEBUFFER == 0 {
        return false; // legacy boot: real VGA text at B8000
    }
    // Type 2 is EGA-text: the "framebuffer" is B8000-style cells — the normal
    // console path already handles that. Only direct-RGB needs rendering.
    if info.framebuffer_type != 1 {
        return false;
    }
    crate::vga::vga().base = (&raw mut TEXT_BUF) as usize;
    true
}

/// Map the framebuffer and start rendering. Called once paging, phys_mm and
/// the #PF handler are up (the mapping writes demand-allocate page tables),
/// still at ring 0 — so `paging2` is called directly, not via arch calls.
pub fn init(info: &arch::MultibootInfo) {
    if info.flags & arch::MULTIBOOT_INFO_FRAMEBUFFER == 0 || info.framebuffer_type != 1 {
        return;
    }
    let addr = info.framebuffer_addr;
    let pitch = info.framebuffer_pitch as usize;
    let width = info.framebuffer_width as usize;
    let height = info.framebuffer_height as usize;

    // The renderer emits 0x00RRGGBB. GOP commonly exposes either BGRX memory
    // (the native little-endian representation of that value) or RGBX memory;
    // use Multiboot's channel metadata instead of assuming one firmware layout.
    let [rp, rs, gp, gs, bp, bs] = info.color_info;
    lib::println!(
        "fbcon: GOP {}x{} pitch={} bpp={} R{}/{} G{}/{} B{}/{} addr={:#x}",
        width, height, pitch, info.framebuffer_bpp, rp, rs, gp, gs, bp, bs, addr
    );
    let Some(format) = PixelFormat::from_multiboot(info) else {
        lib::println!(
            "fbcon: unsupported pixel format {}bpp R{}/{} G{}/{} B{}/{} — no display",
            info.framebuffer_bpp, rp, rs, gp, gs, bp, bs
        );
        // Blind-debug signal: a machine with no debug port shows nothing at
        // all otherwise. Map just the first stripe of the framebuffer and
        // fill it with 0xFF bytes — white-ish on any channel order or depth
        // — so "framebuffer handed over but format rejected" is visible.
        let stripe_bytes = (pitch * 32).min(1 << 20);
        let pages = ((addr & (PAGE_SIZE as u64 - 1)) as usize + stripe_bytes + PAGE_SIZE - 1)
            / PAGE_SIZE;
        for i in 0..pages {
            paging2::map_user_page_phys(
                paging2::FB_WINDOW_BASE / PAGE_SIZE + i,
                addr / PAGE_SIZE as u64 + i as u64,
                paging2::flags::CACHE_DISABLE,
            );
        }
        let base = paging2::FB_WINDOW_BASE + (addr & (PAGE_SIZE as u64 - 1)) as usize;
        unsafe {
            core::slice::from_raw_parts_mut(base as *mut u8, stripe_bytes).fill(0xFF);
        }
        return;
    };
    if width < TEXT_W || height < TEXT_H {
        lib::println!("fbcon: framebuffer {}x{} too small — no display", width, height);
        return;
    }

    // Map the framebuffer (cache-disabled MMIO) into the FB window. The
    // physical address may sit above 4GB (OVMF does this with the NVMe BAR) —
    // PAE/compat PTEs carry 64-bit phys, so keep it u64 end to end. (Legacy
    // 32-bit paging couldn't, but a pre-PAE CPU has no UEFI/GOP to boot from.)
    let fb_bytes = pitch * height;
    let page_off = (addr & (PAGE_SIZE as u64 - 1)) as usize;
    let pages = (page_off + fb_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    assert!(
        paging2::FB_WINDOW_BASE + pages * PAGE_SIZE <= paging2::FB_WINDOW_END,
        "fbcon: framebuffer larger than the FB window"
    );
    let ppage = addr / PAGE_SIZE as u64;
    for i in 0..pages {
        paging2::map_user_page_phys(
            paging2::FB_WINDOW_BASE / PAGE_SIZE + i,
            ppage + i as u64,
            paging2::flags::CACHE_DISABLE,
        );
    }

    lib::println!("fbcon: format accepted, native_blit={}", format.is_native());
    let stride = pitch / 4;
    let origin = (height - TEXT_H) / 2 * stride + (width - TEXT_W) / 2;
    unsafe { PALETTE = vga_render::fallback_palette(); }
    *geom() = Some(Geom {
        va: paging2::FB_WINDOW_BASE + page_off,
        stride,
        origin,
        len: stride * height,
        format,
    });

    // Wipe the boot splash (the pre-paging life-sign strip boot_kernel
    // paints) now that the console owns the pixels.
    unsafe { core::slice::from_raw_parts_mut((paging2::FB_WINDOW_BASE + page_off) as *mut u32, stride * height).fill(0) };

    lib::vga::set_text_flush(flush);
    // The emulated VGA's display sink: DOS screens (text or mode 13h) render
    // kernel-side through lib::vga_render and land here for the GOP blit.
    lib::vga_render::set_present_sink(present_dos_frame);
    flush(); // render the boot backlog accumulated since `early`
}

/// Set when a DOS frame painted the framebuffer: the console's dirty-cell
/// shadow no longer matches the pixels, so the next console flush repaints
/// from scratch (otherwise the kernel console stays invisible after a DOS
/// program exits — the diff thinks nothing changed).
static DOS_PAINTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Present sink for the kernel-emulated VGA: integer-scale and center the
/// rendered DOS frame in the GOP framebuffer.
///
/// Unchanged frames are skipped BEFORE touching the framebuffer: the GOP
/// mapping is uncached, so a full blit costs tens of milliseconds — at tick
/// cadence that saturated the event loop and starved guest port I/O to ~64
/// ins/sec (reproducer: DN's CGA snow-avoidance polls 0x3DA around every
/// word it writes; its UI draw extrapolated to ~500 seconds). The compare
/// runs in cached RAM and costs microseconds.
fn present_dos_frame(w: usize, h: usize, px: &[u32]) {
    let Some(g) = geom() else { return };
    if w == 0 || h == 0 || px.len() < w * h {
        return;
    }
    static mut PREV: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    let prev = unsafe { &mut *(&raw mut PREV) };
    if prev.len() == w * h && prev[..] == px[..w * h] {
        return;
    }
    prev.clear();
    prev.extend_from_slice(&px[..w * h]);
    let fb_w = g.stride; // pixels per row (pitch); visible width <= stride
    let fb_h = g.len / g.stride;
    let k = (fb_w / w).min(fb_h / h).max(1);
    let (out_w, out_h) = ((w * k).min(fb_w), (h * k).min(fb_h));
    let origin = (fb_h - out_h) / 2 * g.stride + (fb_w - out_w) / 2;
    let out = unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) };
    for y in 0..out_h {
        let src_row = &px[(y / k) * w..(y / k) * w + w];
        let dst = &mut out[origin + y * g.stride..origin + y * g.stride + out_w];
        for (x, d) in dst.iter_mut().enumerate() {
            let rgb = src_row[x / k];
            *d = if g.format.is_native() { rgb } else { g.format.encode(rgb) };
        }
    }
    DOS_PAINTED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Re-render every cell that changed since the last flush. Installed as the
/// console's post-write hook; also safe to call any time.
fn flush() {
    let Some(g) = geom() else { return };
    // A DOS frame painted over us: wipe and repaint the whole console.
    if DOS_PAINTED.swap(false, core::sync::atomic::Ordering::Relaxed) {
        let out = unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) };
        out.fill(0);
        unsafe { (&mut *(&raw mut SHADOW)).fill(0) };
    }
    let text: &[u16; 80 * 25] = unsafe { &*(&raw const TEXT_BUF) };
    let shadow = unsafe { &mut *(&raw mut SHADOW) };
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram: unsafe {
            core::slice::from_raw_parts((&raw const TEXT_BUF) as *const u8, 80 * 25 * 2)
        },
        planes: &[],
        ac: &FBCON_AC,
        palette: unsafe { &*(&raw const PALETTE) },
        font: &FONT_8X16,
        blink: false,
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let out = unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) };
    let native = g.format.is_native();
    let mut cell_pixels = [0u32; CELL_W * CELL_H];
    for i in 0..80 * 25 {
        if shadow[i] != text[i] {
            shadow[i] = text[i];
            if native {
                vga_render::render_text_cell(
                    &frame,
                    i % 80,
                    i / 80,
                    &mut out[g.origin..],
                    g.stride,
                );
                continue;
            }

            let cell = i * 2;
            let cell_frame = Frame {
                mode: VgaMode::Text80x25,
                vram: &frame.vram[cell..cell + 2],
                planes: &[],
                ac: &FBCON_AC,
                palette: frame.palette,
                font: frame.font,
                blink: frame.blink,
                start_offset: 0,
                pixel_pan: 0,
                line_compare: usize::MAX,
            };
            vga_render::render_text_cell(&cell_frame, 0, 0, &mut cell_pixels, CELL_W);
            let x = (i % 80) * CELL_W;
            let y = (i / 80) * CELL_H;
            for row in 0..CELL_H {
                let dst = g.origin + (y + row) * g.stride + x;
                for col in 0..CELL_W {
                    out[dst + col] = g.format.encode(cell_pixels[row * CELL_W + col]);
                }
            }
        }
    }
}
