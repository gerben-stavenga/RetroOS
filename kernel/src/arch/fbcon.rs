//! GOP linear-framebuffer text console — the kernel console on UEFI-class
//! machines (the `run_uefi.sh` mock, modern laptops), which have no VGA text
//! mode: the display is a dumb linear framebuffer and writes to 0xB8000 show
//! nothing.
//!
//! There is ONE VGA model: the shared text aperture at phys 0xB8000 (the
//! kernel console keeps `lib::vga`'s cell base there — LOW_MEM_BASE + 0xB8000 —
//! the same memory DOS programs and DN write, since `map_low_mem_user` identity-
//! maps 0xA0-0xBF into every process). This module renders that one aperture
//! through `lib::vga_render` and blits it via `present_dos_frame` — the same
//! present path `display_tick` uses for DOS frames. The `set_text_flush` hook
//! presents it immediately on kernel console writes (boot-message visibility
//! before the event loop runs `display_tick`); at runtime `display_tick` is the
//! presenter. Text renders at 720×400, centered/integer-scaled.
//!
//! Like `boot.rs`, this is metal boot glue: legacy-BIOS machines never call
//! `init` and keep writing real B8000 text cells the hardware scans; the kernel
//! above notices nothing either way.

use arch::paging2::{self, PAGE_SIZE};
use lib::vga_render::{self, Frame, VgaMode};
use lib::vga_fonts::FONT_8X16;

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
            // 8-bit channels (the usual RGBX/BGRX framebuffers) need no rescale:
            // (value*255+127)/255 == value. Skip the divide — it dominated the
            // present blit. The multiply/divide is only needed for 15/16-bit.
            if size == 8 {
                return value << pos;
            }
            let max = (1u64 << size) - 1;
            ((((value as u64 * max) + 127) / 255) << pos) as u32
        }
        channel((rgb >> 16) & 0xFF, self.red_pos, self.red_size)
            | channel((rgb >> 8) & 0xFF, self.green_pos, self.green_size)
            | channel(rgb & 0xFF, self.blue_pos, self.blue_size)
    }
}

fn geom() -> &'static mut Option<Geom> {
    let p = &raw mut GEOM;
    unsafe { &mut *p }
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
    // Leave the console's cell base where `boot_kernel` set it: the shared VGA
    // text aperture (LOW_MEM_BASE + 0xB8000 = real phys 0xB8000) — the SAME
    // memory DOS programs and DN write and `display_tick` presents. One screen,
    // like VGA-text hardware; no separate RAM shadow buffer.
    true
}

/// Map the framebuffer and start rendering. Called once paging, phys_mm and
/// the #PF handler are up (the mapping writes demand-allocate page tables),
/// still at ring 0 — so `paging2` is called directly, not via arch calls.
pub fn init(info: &arch::MultibootInfo, screen: &mut lib::vga::Screen) {
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
    lib::screenln!(
        screen,
        "fbcon: GOP {}x{} pitch={} bpp={} R{}/{} G{}/{} B{}/{} addr={:#x}",
        width, height, pitch, info.framebuffer_bpp, rp, rs, gp, gs, bp, bs, addr
    );
    let Some(format) = PixelFormat::from_multiboot(info) else {
        lib::screenln!(
            screen,
            "fbcon: unsupported pixel format {}bpp R{}/{} G{}/{} B{}/{} — no display",
            info.framebuffer_bpp, rp, rs, gp, gs, bp, bs
        );
        // Blind-debug signal: a machine with no debug port shows nothing at
        // all otherwise. Map just the first stripe of the framebuffer and
        // fill it with 0xFF bytes — white-ish on any channel order or depth
        // — so "framebuffer handed over but format rejected" is visible.
        let stripe_bytes = (pitch * 32).min(1 << 20);
        let pages = ((addr & (PAGE_SIZE as u64 - 1)) as usize + stripe_bytes).div_ceil(PAGE_SIZE);
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
        lib::screenln!(screen, "fbcon: framebuffer {}x{} too small — no display", width, height);
        return;
    }

    // Map the framebuffer into the FB window. A linear framebuffer wants
    // Write-Combining: blits are sequential streaming writes, and WC bursts them
    // into a few bus transactions instead of one-per-pixel. Strong-UC (PCD) makes
    // a full-frame blit cost tens of milliseconds (~70 ns/pixel), which starves
    // the DOS event loop; WC drops that to well under a millisecond. Fall back to
    // CACHE_DISABLE if the CPU has no PAT (no WC slot to point the PAT bit at).
    // The physical address may sit above 4GB (OVMF does this with the NVMe BAR) —
    // PAE/compat PTEs carry 64-bit phys, so keep it u64 end to end. (Legacy
    // 32-bit paging couldn't, but a pre-PAE CPU has no UEFI/GOP to boot from.)
    // QEMU-TCG's display only re-scans pages its dirty-tracking flags, and it
    // misses Write-Combining bursts (the WC fast path skips the dirty mark) — a
    // WC present lands in RAM but the window never repaints it (only the region
    // the boot console already dirtied shows). KVM (MMU dirty tracking) and real
    // hardware (continuous scanout) both see WC fine. Detect plain QEMU-TCG via
    // its hypervisor signature ("TCGTCGTCGTCG") and use strong-UC there, where
    // every write is a dirty-tracked device access the display picks up.
    let (_, hv_ebx, _, _) = arch::x86::cpuid(0x4000_0000);
    let (_, _, cpuid1_ecx, _) = arch::x86::cpuid(1);
    let qemu_tcg = (cpuid1_ecx >> 31) & 1 == 1 && hv_ebx == 0x5447_4354; // "TCGT"
    let fb_cache_flag = if paging2::wc_pat_enabled() && !qemu_tcg {
        paging2::flags::WRITE_COMBINE
    } else {
        paging2::flags::CACHE_DISABLE
    };
    if qemu_tcg {
        lib::screenln!(screen, "fbcon: QEMU-TCG detected — strong-UC framebuffer (WC not scanned)");
    }
    let fb_bytes = pitch * height;
    let page_off = (addr & (PAGE_SIZE as u64 - 1)) as usize;
    let pages = (page_off + fb_bytes).div_ceil(PAGE_SIZE);
    assert!(
        paging2::FB_WINDOW_BASE + pages * PAGE_SIZE <= paging2::FB_WINDOW_END,
        "fbcon: framebuffer larger than the FB window"
    );
    let ppage = addr / PAGE_SIZE as u64;
    for i in 0..pages {
        paging2::map_user_page_phys(
            paging2::FB_WINDOW_BASE / PAGE_SIZE + i,
            ppage + i as u64,
            fb_cache_flag,
        );
    }

    lib::screenln!(screen, "fbcon: format accepted, native_blit={}", format.is_native());
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

    // Back the VGA text aperture with real RAM. `boot_kernel` left the console's
    // cell base at LOW_MEM_BASE + 0xB8000, but on a UEFI machine that maps to the
    // unbacked legacy physical 0xB8000 (reads 0xFF → a white screen). Point the
    // kernel low-mem window's 0xB8000-0xBFFFF at a dedicated allocated aperture
    // instead — RAM the console can read/write. This is the singleton VGA text
    // memory; DOS processes map the SAME pages at their guest 0xB8000, so the
    // kernel console and every DOS program share one screen, like VGA hardware.
    let aperture = paging2::vga_text_aperture_ppage();
    for i in 0..8 {
        paging2::map_user_page_phys(
            (paging2::LOW_MEM_BASE + 0xB8000) / PAGE_SIZE + i,
            aperture + i as u64,
            paging2::flags::CACHE_DISABLE,
        );
    }
    // alloc_contig doesn't zero — blank the text aperture (space, light-gray on
    // black) so the first flush renders a clean screen, not leftover RAM.
    unsafe {
        core::slice::from_raw_parts_mut((paging2::LOW_MEM_BASE + 0xB8000) as *mut u16, 80 * 25)
            .fill(0x0720);
    }

    lib::vga::set_text_flush(flush);
    // The emulated VGA's display sink: DOS screens (text or mode 13h) render
    // kernel-side through lib::vga_render and land here for the GOP blit.
    lib::vga_render::set_present_sink(present_dos_frame);
    lib::vga_render::set_present_indexed_sink(present_indexed_frame);
    flush(); // render the boot backlog accumulated since `early`
}

/// Present sink for the kernel-emulated VGA: integer-scale and center the
/// rendered DOS frame in the GOP framebuffer.
///
/// Unchanged frames are skipped BEFORE touching the framebuffer: the GOP
/// mapping is uncached, so a full blit costs tens of milliseconds — at tick
/// cadence that saturated the event loop and starved guest port I/O to ~64
/// ins/sec (reproducer: DN's CGA snow-avoidance polls 0x3DA around every
/// word it writes; its UI draw extrapolated to ~500 seconds). The compare
/// runs in cached RAM and costs microseconds.
/// Set when a DOS frame painted the framebuffer via `present_dos_frame`: the
/// console's dirty-cell shadow no longer matches the pixels, so the next `flush`
/// repaints the whole screen (else the kernel console stays invisible after a
/// DOS graphics frame — the diff would think nothing changed).
static DOS_PAINTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);


/// One output row, shared by both sinks. 16 KB of BSS covers panels to 4096 px
/// (a frame-sized buffer would not fit the kernel image at all).
const EXP_MAX: usize = 4096;
static mut EXP_ROW: [u32; EXP_MAX] = [0; EXP_MAX];
const SRC_MAX: usize = 2048;

/// Largest 4:3 rectangle that fits the panel, and where it starts.
///
/// DOS modes are authored for a 4:3 display with non-square pixels, so fitting
/// the source to 4:3 — rather than scaling both axes equally — reproduces each
/// mode's pixel aspect automatically: 320x200 comes out stretched 6/5 tall,
/// 320x240 square, 360x400 wide, exactly as a VGA monitor showed them.
fn out_geometry(g: &Geom, w: usize, h: usize) -> Option<(usize, usize, usize)> {
    if w == 0 || h == 0 {
        return None;
    }
    let fb_w = g.stride;
    let fb_h = g.len / g.stride;
    let (out_w, out_h) = if fb_w * 3 >= fb_h * 4 {
        ((fb_h * 4 / 3).min(fb_w), fb_h) // wider than 4:3 -> pillarbox
    } else {
        (fb_w, (fb_w * 3 / 4).min(fb_h)) // taller -> letterbox
    };
    if out_w == 0 || out_h == 0 {
        return None;
    }
    Some((out_w, out_h, (fb_h - out_h) / 2 * g.stride + (fb_w - out_w) / 2))
}

/// How many output columns each SOURCE column covers.
///
/// The horizontal map is a pure function of (w, out_w) — identical for every
/// row and every frame — so it is built once per geometry rather than
/// re-derived per pixel. It also inverts the inner loop: walking source columns
/// and writing each one's run replaces a per-output-column indexed gather with
/// one load and a short sequential fill.
fn column_runs(w: usize, out_w: usize) -> Option<&'static [u16]> {
    if w > SRC_MAX || out_w > EXP_MAX {
        return None;
    }
    static mut RUNS: [u16; SRC_MAX] = [0; SRC_MAX];
    static mut KEY: (usize, usize) = (0, 0);
    let runs = unsafe { &mut *(&raw mut RUNS) };
    if unsafe { *(&raw const KEY) } != (w, out_w) {
        unsafe { *(&raw mut KEY) = (w, out_w) };
        for r in runs[..w].iter_mut() {
            *r = 0;
        }
        for ox in 0..out_w {
            runs[ox * w / out_w] += 1;
        }
    }
    Some(&runs[..w])
}

/// Present an 8-bit indexed frame, the whole pipeline in one pass per source
/// row: palette -> panel format via a table, stretch, then copy the finished
/// row down to every output row that maps to it.
///
/// The table is the point. Palette entries change rarely (a fade, a mode set);
/// pixels are converted 64,000 times a frame. Building `palette -> panel u32`
/// once when the DAC changes removes BOTH the per-pixel palette lookup and the
/// per-pixel format encode — and with it the full-frame RGB intermediate that
/// existed only to carry pixels between those two conversions.
fn present_indexed_frame(w: usize, h: usize, src: &[u8], palette: &[u8; 768]) {
    let Some(g) = geom() else { return };
    let Some(geo) = out_geometry(&g, w, h) else { return };
    let (out_w, out_h, origin) = geo;

    // palette -> panel format, rebuilt only when the DAC actually changes.
    static mut LUT: [u32; 256] = [0; 256];
    static mut LUT_PAL: [u8; 768] = [0; 768];
    let lut = unsafe { &mut *(&raw mut LUT) };
    let cached = unsafe { &mut *(&raw mut LUT_PAL) };
    if cached != palette {
        cached.copy_from_slice(palette);
        for (i, e) in lut.iter_mut().enumerate() {
            let rgb = lib::vga_render::pal_rgb_at(palette, i as u8);
            *e = if g.format.is_native() { rgb } else { g.format.encode(rgb) };
        }
    }

    let runs = column_runs(w, out_w);
    let Some(runs) = runs else {
        return; // geometry beyond the tables; the RGB path handles it
    };
    let out = unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) };
    let exp = unsafe { &mut *(&raw mut EXP_ROW) };
    let y_step = ((h as u64) << 16) / out_h as u64;
    let mut sy = 0u64;
    let mut prev_sry = usize::MAX;
    for oy in 0..out_h {
        let sry = (sy >> 16) as usize;
        sy += y_step;
        let drow = origin + oy * g.stride;
        let dst = unsafe { out.get_unchecked_mut(drow..drow + out_w) };
        if sry != prev_sry {
            prev_sry = sry;
            let row = unsafe { src.get_unchecked(sry * w..sry * w + w) };
            let mut o = 0usize;
            for i in 0..w {
                let v = unsafe { *lut.get_unchecked(*row.get_unchecked(i) as usize) };
                let n = unsafe { *runs.get_unchecked(i) } as usize;
                for e in unsafe { exp.get_unchecked_mut(o..o + n) } {
                    *e = v;
                }
                o += n;
            }
        }
        dst.copy_from_slice(unsafe { exp.get_unchecked(..out_w) });
    }
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)); }
    DOS_PAINTED.store(true, core::sync::atomic::Ordering::Relaxed);
}

fn present_dos_frame(w: usize, h: usize, px: &[u32]) {
    let Some(g) = geom() else { return };
    if w == 0 || h == 0 || px.len() < w * h {
        return;
    }
    let fb_w = g.stride; // pixels per row (pitch); visible width <= stride
    let fb_h = g.len / g.stride;
    // DOS modes are all authored for a 4:3 display with non-square pixels, so
    // present into the largest 4:3 rectangle that fits the panel and scale the
    // source into it with independent X/Y factors. Integer square-pixel scaling
    // would show each mode at its raw pixel-grid aspect — 320×200 too wide,
    // 360×400 too tall; this gives 320×200 elongated (tall) pixels and 360×400
    // wide pixels, matching a real VGA monitor.
    let (out_w, out_h) = if fb_w * 3 >= fb_h * 4 {
        ((fb_h * 4 / 3).min(fb_w), fb_h) // panel wider than 4:3 → pillarbox
    } else {
        (fb_w, (fb_w * 3 / 4).min(fb_h)) // taller than 4:3 → letterbox
    };
    if out_w == 0 || out_h == 0 {
        return;
    }
    let origin = (fb_h - out_h) / 2 * g.stride + (fb_w - out_w) / 2;
    // DIAGNOSTIC: with the RAM sink armed, blit into ordinary kernel memory
    // instead of the mapped framebuffer. Same pixels, same loop — but no MMIO
    // and, under QEMU, no display dirty-page tracking. The delta between the
    // two is what the framebuffer itself costs us.
    // Heap, not BSS: a 3 MB static array overruns the kernel's mapped image
    // and the machine never boots. Allocated once, on first use.
    static mut RAM_FB: *mut u32 = core::ptr::null_mut();
    let out = if crate::kernel::startup::fb_to_ram() {
        unsafe {
            let slot = &raw mut RAM_FB;
            if (*slot).is_null() {
                *slot = alloc::vec![0u32; g.len].leak().as_mut_ptr();
            }
            core::slice::from_raw_parts_mut(*slot, g.len)
        }
    } else {
        unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) }
    };
    // On a resolution change (a mode switch — e.g. text 720×400 → Mode-Y
    // 320×200), the centered image and its letterbox border move, so clear the
    // whole framebuffer once to drop stale pixels from the previous mode. This
    // is render bookkeeping, not a frame cache: every frame is blitted (no
    // content-compare skip — that silently froze the screen when the cached
    // frame went stale against another writer).
    static mut LAST_DIMS: (usize, usize) = (0, 0);
    let last_p = &raw mut LAST_DIMS;
    let last = unsafe { &mut *last_p };
    if *last != (w, h) {
        *last = (w, h);
        out.fill(0);
    }
    // This blit runs at the present rate on the guest thread, so its cost is
    // stolen guest time — once a present exceeds the ~14 ms frame budget the
    // guest starves.
    //
    // Row-at-a-time: scale each SOURCE row once into a full-width expanded row,
    // then copy that row to every output row mapping to it. Two wins over
    // scaling straight to the panel per output row:
    //
    //   * memory. The working set is ONE output row (4 KB at 1024 px), not a
    //     frame-sized intermediate.
    //   * work. The per-output-pixel indexed load — a gather with a fractional
    //     step, which cannot vectorize — runs once per source row rather than
    //     once per output row (200 x 1024 instead of 768 x 1024 here). The
    //     remaining ~570 rows are a straight `copy_from_slice`.
    //
    // Format encoding folds into the same pass: the expanded row is built in
    // the framebuffer's own format, so no separate encode-staging row is
    // needed. Fixed-point 16.16 nearest-neighbour; indices are provably in
    // range (`sx>>16 < w`, `sy>>16 < h`, dst within `g.len`), so bounds checks
    // are elided.
    let y_step = ((h as u64) << 16) / out_h as u64;
    let native = g.format.is_native();
    // One output row, not one frame: 16 KB of BSS covers panels to 4096 px.
    // (A frame-sized static does not fit the kernel image — it must be heap.)
    const EXP_MAX: usize = 4096;
    static mut EXP_ROW: [u32; EXP_MAX] = [0; EXP_MAX];
    // How many output columns each SOURCE column covers. The horizontal map is
    // a pure function of (w, out_w) — the same for every row and every frame —
    // so it is computed once per geometry instead of re-derived per pixel. That
    // also inverts the inner loop: walking source columns and writing each
    // one's run turns 1024 indexed gathers per row into 320 loads and 1024
    // sequential stores.
    const SRC_MAX: usize = 2048;
    static mut RUNS: [u16; SRC_MAX] = [0; SRC_MAX];
    static mut RUNS_KEY: (usize, usize) = (0, 0);

    let exp = unsafe { &mut *(&raw mut EXP_ROW) };
    let runs = unsafe { &mut *(&raw mut RUNS) };
    let runs_ok = w <= SRC_MAX && out_w <= EXP_MAX;
    if runs_ok && unsafe { *(&raw const RUNS_KEY) } != (w, out_w) {
        unsafe { *(&raw mut RUNS_KEY) = (w, out_w) };
        // Column ox samples source column (ox * w) / out_w; count how many
        // consecutive ox share each source column.
        for r in runs[..w].iter_mut() {
            *r = 0;
        }
        for ox in 0..out_w {
            let sc = ox * w / out_w;
            runs[sc] += 1;
        }
    }

    let mut sy = 0u64;
    let mut prev_sry = usize::MAX;
    for oy in 0..out_h {
        let sry = (sy >> 16) as usize;
        sy += y_step;
        let drow = origin + oy * g.stride;
        let dst = unsafe { out.get_unchecked_mut(drow..drow + out_w) };
        if !runs_ok {
            // Geometry beyond the tables (no panel we have): sample per output
            // column straight to the framebuffer.
            let x_step = ((w as u64) << 16) / out_w as u64;
            let src_row = unsafe { px.get_unchecked(sry * w..sry * w + w) };
            let mut sx = 0u64;
            for d in dst.iter_mut() {
                let rgb = unsafe { *src_row.get_unchecked((sx >> 16) as usize) };
                *d = if native { rgb } else { g.format.encode(rgb) };
                sx += x_step;
            }
            continue;
        }
        if sry != prev_sry {
            prev_sry = sry;
            let src_row = unsafe { px.get_unchecked(sry * w..sry * w + w) };
            // One load per SOURCE pixel, then its run of identical output
            // pixels written sequentially — no gather, no per-pixel stepping,
            // and the format test hoisted out of both loops.
            let mut o = 0usize;
            if native {
                for i in 0..w {
                    let v = unsafe { *src_row.get_unchecked(i) };
                    let n = runs[i] as usize;
                    for e in unsafe { exp.get_unchecked_mut(o..o + n) } {
                        *e = v;
                    }
                    o += n;
                }
            } else {
                for i in 0..w {
                    let v = g.format.encode(unsafe { *src_row.get_unchecked(i) });
                    let n = runs[i] as usize;
                    for e in unsafe { exp.get_unchecked_mut(o..o + n) } {
                        *e = v;
                    }
                    o += n;
                }
            }
        }
        dst.copy_from_slice(unsafe { exp.get_unchecked(..out_w) });
    }
    // The framebuffer is Write-Combining: its stores sit in the CPU's WC buffers
    // until something drains them. A display controller scanning out (real metal)
    // — or QEMU's display refresh / KVM dirty tracking — reads framebuffer memory,
    // so an undrained WC buffer leaves the just-blitted frame invisible until the
    // next frame happens to evict it (the live window looks frozen even though the
    // guest is running). SFENCE drains the WC buffers so each present is globally
    // visible immediately.
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)); }
    DOS_PAINTED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Re-render the cells of the shared VGA text aperture that changed since the
/// last flush, straight to the framebuffer. The kernel console and every DOS
/// process share one screen at phys 0xB8000 (read through the LOW_MEM_BASE
/// window) — `flush` reads that aperture (not a private buffer), so there is one
/// screen. Installed as the console post-write hook for immediate boot-message
/// visibility; cheap (a per-cell diff, no allocation), unlike the full-frame
/// `display_tick` path which presents the same aperture during runtime.
fn flush() {
    let Some(g) = geom() else { return };
    // A DOS frame painted over us: wipe and repaint the whole console.
    if DOS_PAINTED.swap(false, core::sync::atomic::Ordering::Relaxed) {
        // DIAGNOSTIC: with the RAM sink armed, blit into ordinary kernel memory
    // instead of the mapped framebuffer. Same pixels, same loop — but no MMIO
    // and, under QEMU, no display dirty-page tracking. The delta between the
    // two is what the framebuffer itself costs us.
    // Heap, not BSS: a 3 MB static array overruns the kernel's mapped image
    // and the machine never boots. Allocated once, on first use.
    static mut RAM_FB: *mut u32 = core::ptr::null_mut();
    let out = if crate::kernel::startup::fb_to_ram() {
        unsafe {
            let slot = &raw mut RAM_FB;
            if (*slot).is_null() {
                *slot = alloc::vec![0u32; g.len].leak().as_mut_ptr();
            }
            core::slice::from_raw_parts_mut(*slot, g.len)
        }
    } else {
        unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) }
    };
        out.fill(0);
        let sp = &raw mut SHADOW;
        unsafe { (*sp).fill(0) };
    }
    // The shared text aperture (real phys 0xB8000 via the low-mem window).
    let text: &[u16] = unsafe {
        core::slice::from_raw_parts((paging2::LOW_MEM_BASE + 0xB8000) as *const u16, 80 * 25)
    };
    let vram: &[u8] = unsafe {
        core::slice::from_raw_parts((paging2::LOW_MEM_BASE + 0xB8000) as *const u8, 80 * 25 * 2)
    };
    let shadow_p = &raw mut SHADOW;
    let shadow = unsafe { &mut *shadow_p };
    let palette_p = &raw const PALETTE;
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram,
        planes: &[],
        ac: &FBCON_AC,
        palette: unsafe { &*palette_p },
        font: &FONT_8X16,
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    // DIAGNOSTIC: with the RAM sink armed, blit into ordinary kernel memory
    // instead of the mapped framebuffer. Same pixels, same loop — but no MMIO
    // and, under QEMU, no display dirty-page tracking. The delta between the
    // two is what the framebuffer itself costs us.
    // Heap, not BSS: a 3 MB static array overruns the kernel's mapped image
    // and the machine never boots. Allocated once, on first use.
    static mut RAM_FB: *mut u32 = core::ptr::null_mut();
    let out = if crate::kernel::startup::fb_to_ram() {
        unsafe {
            let slot = &raw mut RAM_FB;
            if (*slot).is_null() {
                *slot = alloc::vec![0u32; g.len].leak().as_mut_ptr();
            }
            core::slice::from_raw_parts_mut(*slot, g.len)
        }
    } else {
        unsafe { core::slice::from_raw_parts_mut(g.va as *mut u32, g.len) }
    };
    let native = g.format.is_native();
    let mut cell_pixels = [0u32; CELL_W * CELL_H];
    for i in 0..80 * 25 {
        if shadow[i] != text[i] {
            shadow[i] = text[i];
            if native {
                vga_render::render_text_cell(&frame, i % 80, i / 80, &mut out[g.origin..], g.stride);
                continue;
            }
            let cell = i * 2;
            let cell_frame = Frame {
                mode: VgaMode::Text80x25,
                vram: &vram[cell..cell + 2],
                planes: &[],
                ac: &FBCON_AC,
                palette: frame.palette,
                font: frame.font,
                blink: frame.blink,
                cga_palette: [0; 4],
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
