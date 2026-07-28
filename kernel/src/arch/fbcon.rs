//! GOP linear-framebuffer text console — the kernel console on UEFI-class
//! machines (the `run_uefi.sh` mock, modern laptops), which have no VGA text
//! mode: the display is a dumb linear framebuffer and writes to 0xB8000 show
//! nothing.
//!
//! There is ONE VGA model: the shared text aperture at phys 0xB8000 (the
//! kernel console keeps `lib::vga`'s cell base there — LOW_MEM_BASE + 0xB8000 —
//! the same memory DOS programs and DN write, since `map_low_mem_user` identity-
//! maps 0xA0-0xBF into every process). This module only maps/describes the
//! framebuffer and supplies the shared aperture to `kernel::vga`, which makes
//! that emulated VGA visible. The kernel above this glue uses the same VGA
//! console interface as it does on a legacy machine.
//!
//! Like `boot.rs`, this is metal boot glue: legacy-BIOS machines never call
//! `init` and keep writing real B8000 text cells the hardware scans; the kernel
//! above notices nothing either way.

use arch::paging2::{self, PAGE_SIZE};
use lib::vga_render::PixelFormat;

/// Framebuffer geometry, set once by `init` (None until then / on legacy VGA).
struct Geom {
    /// First mapped framebuffer pixel, as a kernel VA.
    va: usize,
    /// Row pitch in bytes.
    pitch: usize,
    width: usize,
    height: usize,
    /// Convert the renderer's canonical 0x00RRGGBB pixels to the GOP layout.
    format: PixelFormat,
    /// QEMU-TCG needs strong-UC stores for display dirty tracking.
    slow: bool,
    /// Bare metal (no hypervisor): wide NT stores for device-row copies.
    wide: bool,
}
static mut GEOM: Option<Geom> = None;

const TEXT_W: usize = 720;
const TEXT_H: usize = 400;

fn geom() -> &'static mut Option<Geom> {
    let p = &raw mut GEOM;
    unsafe { &mut *p }
}

/// Whether the framebuffer console owns the display (a linear framebuffer
/// was handed over and mapped). Probed by `kernel::platform`.
pub fn active() -> bool {
    geom().is_some()
}

/// The GOP framebuffer, as a descriptor the kernel can blit into directly.
/// Installed into `HostEnv` by the metal entry; the platform probe freezes it
/// into `Display::Framebuffer`.
pub fn framebuffer() -> Option<crate::kernel::display::Framebuffer> {
    let g = (*geom()).as_ref()?;
    Some(crate::kernel::display::Framebuffer {
        va: g.va,
        pitch: g.pitch,
        width: g.width,
        height: g.height,
        format: g.format,
        slow: g.slow,
        wide: g.wide,
    })
}

/// End of frame. The framebuffer is Write-Combining: stores sit in the CPU's WC
/// buffers until something drains them, and a display controller scanning out —
/// or QEMU's refresh — reads memory, so an undrained buffer leaves the frame
/// invisible until the next one happens to evict it. SFENCE makes each present
/// visible immediately.
pub fn present() {
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
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
/// Multiboot `framebuffer_type`: 0 = indexed, 1 = RGB, 2 = EGA text.
const FB_TYPE_RGB: u8 = 1;
const FB_TYPE_EGA_TEXT: u8 = 2;

pub fn init(info: &arch::MultibootInfo, screen: &mut lib::vga::Screen) {
    // No framebuffer offered at all (our own legacy bootloader), or the loader
    // honoured the header's EGA-text request (GRUB on a legacy BIOS, which
    // reports type 2 with addr 0xB8000). Either way the card owns the panel and
    // there is nothing here to drive — NOT a failure.
    if info.flags & arch::MULTIBOOT_INFO_FRAMEBUFFER == 0
        || info.framebuffer_type == FB_TYPE_EGA_TEXT
    {
        return;
    }
    // Past this point a LINEAR framebuffer was handed over: the loader has put
    // the display somewhere only we can paint, so failing to render into it
    // means no display at all. Panicking is the honest outcome — returning
    // early would leave `platform::probe` unable to distinguish "no framebuffer
    // offered" from "offered but unusable", and it would then classify a
    // framebuffer machine as `VgaCard`/`NativeBios` and call ROM video services
    // that cannot paint this panel. Accept more formats here to fix a panic.
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
    // Blind-debug signal, painted BEFORE we panic: a machine with no debug port
    // and no usable console shows nothing at all otherwise. Map the first
    // stripe of the framebuffer and fill it with 0xFF — white-ish on any
    // channel order or depth — so "framebuffer handed over but unusable" is
    // visible even though the panic message below will not be.
    let blind_signal = || {
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
    };
    if info.framebuffer_type != FB_TYPE_RGB {
        blind_signal();
        panic!("fbcon: framebuffer type {} unsupported (need {} = RGB)",
            info.framebuffer_type, FB_TYPE_RGB);
    }
    let bytes_per_pixel = info.framebuffer_bpp.div_ceil(8) as usize;
    let Some(format) = PixelFormat::from_rgb(bytes_per_pixel as u8, info.color_info) else {
        blind_signal();
        panic!("fbcon: unsupported pixel format {}bpp R{}/{} G{}/{} B{}/{} — need packed 16/24/32-bit RGB",
            info.framebuffer_bpp, rp, rs, gp, gs, bp, bs);
    };
    if pitch < width * bytes_per_pixel {
        blind_signal();
        panic!("fbcon: pitch {} smaller than {} packed pixels", pitch, width);
    }
    if width < TEXT_W || height < TEXT_H {
        blind_signal();
        panic!("fbcon: framebuffer {}x{} smaller than the {}x{} text console",
            width, height, TEXT_W, TEXT_H);
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
    *geom() = Some(Geom {
        va: paging2::FB_WINDOW_BASE + page_off,
        pitch,
        width,
        height,
        format,
        slow: qemu_tcg,
        wide: (cpuid1_ecx >> 31) & 1 == 0, // no hypervisor = real WC aperture
    });

    // Wipe the boot splash (the pre-paging life-sign strip boot_kernel
    // paints) now that the console owns the pixels.
    unsafe {
        core::slice::from_raw_parts_mut(
            (paging2::FB_WINDOW_BASE + page_off) as *mut u8,
            pitch * height,
        )
        .fill(0)
    };

    // Back the VGA text aperture with real RAM. `boot_kernel` left the console's
    // cell base at LOW_MEM_BASE + 0xB8000, but on a UEFI machine that maps to the
    // unbacked legacy physical 0xB8000 (reads 0xFF → a white screen). Point the
    // kernel low-mem window's 0xB8000-0xBFFFF at a dedicated allocated aperture
    // instead — RAM the console can read/write. This is the singleton VGA text
    // memory; DOS processes map the SAME pages at their guest 0xB8000, so the
    // kernel console and every DOS program share one screen, like VGA hardware.
    let aperture = paging2::vga_text_aperture_ppage();
    for i in 0..8 {
        // Cacheable, FOREIGN: RAM we allocated (not a card's MMIO), shared with
        // every DOS process, so no address space may free or COW it. It was
        // uncached only because CACHE_DISABLE used to double as the
        // "externally owned" marker — see `flags::FOREIGN`.
        paging2::map_user_page_phys(
            (paging2::LOW_MEM_BASE + 0xB8000) / PAGE_SIZE + i,
            aperture + i as u64,
            paging2::flags::FOREIGN,
        );
    }
    // alloc_contig doesn't zero — blank the text aperture (space, light-gray on
    // black) so the first flush renders a clean screen, not leftover RAM.
    unsafe {
        core::slice::from_raw_parts_mut((paging2::LOW_MEM_BASE + 0xB8000) as *mut u16, 80 * 25)
            .fill(0x0720);
    }

    // From here on the linear framebuffer is simply the emulated VGA's sink.
    // Kernel text output keeps using the same B8000 cells and VGA interface.
    crate::vga::attach_framebuffer(framebuffer().unwrap());
}
