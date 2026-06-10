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
}
static mut GEOM: Option<Geom> = None;

const TEXT_W: usize = 720;
const TEXT_H: usize = 400;

fn geom() -> &'static mut Option<Geom> {
    unsafe { &mut *(&raw mut GEOM) }
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

    // The renderer emits 0x00RRGGBB; accept exactly that layout (32 bpp,
    // R/G/B at bits 16/8/0 — what GOP/bochs-display modes are). Anything
    // else: stay on the 0xE9 debug console rather than render garbage.
    let [rp, rs, gp, gs, bp, bs] = info.color_info;
    if info.framebuffer_bpp != 32 || (rp, rs, gp, gs, bp, bs) != (16, 8, 8, 8, 0, 8) {
        lib::println!(
            "fbcon: unsupported pixel format {}bpp R{}/{} G{}/{} B{}/{} — no display",
            info.framebuffer_bpp, rp, rs, gp, gs, bp, bs
        );
        return;
    }
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

    let stride = pitch / 4;
    let origin = (height - TEXT_H) / 2 * stride + (width - TEXT_W) / 2;
    unsafe { PALETTE = vga_render::fallback_palette(); }
    *geom() = Some(Geom {
        va: paging2::FB_WINDOW_BASE + page_off,
        stride,
        origin,
        len: stride * height,
    });

    lib::vga::set_text_flush(flush);
    flush(); // render the boot backlog accumulated since `early`
}

/// Re-render every cell that changed since the last flush. Installed as the
/// console's post-write hook; also safe to call any time.
fn flush() {
    let Some(g) = geom() else { return };
    let text: &[u16; 80 * 25] = unsafe { &*(&raw const TEXT_BUF) };
    let shadow = unsafe { &mut *(&raw mut SHADOW) };
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram: unsafe {
            core::slice::from_raw_parts((&raw const TEXT_BUF) as *const u8, 80 * 25 * 2)
        },
        palette: unsafe { &*(&raw const PALETTE) },
        font: &FONT_8X16,
    };
    let out = unsafe {
        core::slice::from_raw_parts_mut(g.va as *mut u32, g.len)
    };
    let out = &mut out[g.origin..];
    for i in 0..80 * 25 {
        if shadow[i] != text[i] {
            shadow[i] = text[i];
            vga_render::render_text_cell(&frame, i % 80, i / 80, out, g.stride);
        }
    }
}
