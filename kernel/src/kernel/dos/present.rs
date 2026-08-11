//! Putting the machine's picture on the machine's display.
//!
//! The emulated VGA, the Voodoo and the OSD all produce pixels; `platform` says
//! what this machine can actually show them on. This is where those meet: when
//! a frame is due, scan the current owner's VGA out into a frame, composite
//! the overlay, and present it through whatever sink the probe handed over.
//!
//! Kernel work, not machine work, which is why it is here and not beside the
//! cards. Everything it names on the display side — `Display`,
//! `Sink`, `Scratch`, the OSD — is a capability or a
//! sink the kernel owns; the machine below produces a picture and has no
//! opinion about where it goes.

use crate::Regs;
use crate::kernel::bios_display::DisplayedVga;
use core::sync::atomic::Ordering;

use super::machine::{PcMachine, vga::{SVGA_LFB_BASE, VGA_VRAM_BASE}};
use ::vga::VgaState;

/// Read a guest aperture (untrapped, scattered RAM) into `buf` and return it as
/// a slice — the one copy linear modes (mode 13h / text) can't avoid, since that
/// VRAM is guest memory the kernel can't address as a flat region.
/// Snapshot guest bytes `[lo, hi)` of the `len`-byte aperture at `addr` into
/// `buf`, which keeps the aperture's FULL length so the renderer's offsets are
/// the guest's own. Only the requested span is copied — the beam paints a band
/// per pass, and copying the whole aperture each time moved ~14x the bytes it
/// reads (64 KB per pass in mode 13h, megabytes in linear SVGA).
///
/// The buffer is resized only when the length changes: `clear()` + `resize()`
/// would memset every byte immediately before overwriting it.
fn read_aperture<'a, A: crate::Arch>(
    machine: &mut A, buf: &'a mut alloc::vec::Vec<u8>, addr: usize, len: usize,
    lo: usize, hi: usize,
) -> &'a [u8] {
    if buf.len() != len {
        buf.clear();
        buf.resize(len, 0);
    }
    let (lo, hi) = (lo.min(len), hi.min(len));
    if lo < hi {
        machine.copy_from(addr + lo, &mut buf[lo..hi]);
    }
    buf
}

/// Build the displayed frame from the live registers + VRAM: resolve the
/// mode, point at the video memory, and read the display-start / pixel pan /
/// line-compare that select the visible window. Planar modes render our own
/// `planes` in place (no copy); linear modes copy the `band` of their guest
/// aperture the beam is about to paint into `scratch`. `None` for a mode the
/// renderer doesn't draw.
fn scanout<'a, A: crate::Arch>(
    state: &'a VgaState, machine: &mut A, _regs: &Regs, scratch: &'a mut alloc::vec::Vec<u8>,
    band: (usize, usize),
) -> Option<::vga::Frame<'a>>
{
    use ::vga::{Frame, VgaMode};
    // VESA SVGA: present the kernel-side linear framebuffer directly. The
    // guest filled it through the banked 0xA0000 window; `display_tick`
    // flushes the live window into `svga_fb` just before this call.
    if state.svga_w != 0 {
        let pitch = state.svga_pitch as usize;
        let size = pitch * state.svga_h as usize;
        return Some(Frame {
            mode: VgaMode::LinearSvga {
                w: state.svga_w, h: state.svga_h, bpp: state.svga_bpp, pitch: pitch as u16,
            },
            // Linear rows: the band maps straight to a byte span.
            vram: read_aperture(machine, scratch, SVGA_LFB_BASE, size,
                band.0 * pitch, (band.0 + band.1) * pitch),
            planes: &[],
            ac: &state.ac,
            palette: &state.dac,
            dac_mask: state.dac_mask,
            font: &lib::vga_fonts::FONT_8X16,
            font_b: &lib::vga_fonts::FONT_8X16,
            blink: false,
            cga_palette: [0; 4],
            start_offset: 0,
            pixel_pan: 0,
            line_compare: usize::MAX,
        });
    }
    let mode = state.classify_mode()?;
    let (w, h) = ::vga::dimensions(mode);
    // Mode 13h's rows are linear but not contiguous: a panned display-start
    // (screen-shake) slides the origin forward, and below Line Compare the
    // latch resets to 0 — so walk the band's rows the way `row_origin`
    // does and take the span they cover. The buffer stays a full 64 KB
    // window, only the copy shrinks.
    let m13_span = || {
        let start = (((state.crtc[0x0C] as usize) << 8) | state.crtc[0x0D] as usize) * 4;
        let pan = (state.ac[0x13] & 0x07) as usize;
        let lc = state.line_compare(h);
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for r in band.0..band.0 + band.1 {
            let base = if r >= lc { (r - lc) * w } else { start + r * w + pan };
            lo = lo.min(base);
            hi = hi.max(base + w);
        }
        if lo > hi { (0, 0) } else { (lo, hi) }
    };
    let fallback_font: &[u8] = match mode {
        VgaMode::Text { cell_h: 8, .. } => &lib::vga_fonts::FONT_8X8,
        VgaMode::Text { cell_h: 14, .. } => &lib::vga_fonts::FONT_8X14,
        _ => &lib::vga_fonts::FONT_8X16,
    };
    let (vram, planes, font, font_b): (&[u8], &[u8], &[u8], &[u8]) = match mode {
        VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } =>
            (&[], read_aperture(machine, scratch, VGA_VRAM_BASE, 4 * 0x10000, 0, 4 * 0x10000), fallback_font, fallback_font),
        VgaMode::Mode13h => {
            let (lo, hi) = m13_span();
            (read_aperture(machine, scratch, 0xA0000, 0x10000, lo, hi), &[], fallback_font, fallback_font)
        }
        VgaMode::Text { cols, rows, cell_h, .. } => {
            // Text cells live at B8000, but their glyphs are programmable VGA
            // memory in plane 2: 32 bytes per character, with only `cell_h`
            // scanlines displayed. Trackers and DOS shells load custom fonts
            // there and then use otherwise meaningless character codes as UI
            // tiles. Repack the selected VGA character map into the compact
            // 256*cell_h layout consumed by the renderer.
            let text_len = usize::from(cols) * usize::from(rows) * 2;
            let glyph_h = usize::from(cell_h);
            let font_len = 256 * glyph_h;
            const VGA_MAP_LEN: usize = 0x2000;
            if scratch.len() != text_len + 2 * VGA_MAP_LEN {
                scratch.clear();
                scratch.resize(text_len + 2 * VGA_MAP_LEN, 0);
            }
            if state.a0000_trapped {
                // During character-generator access GC[6] may turn B8000 into
                // the sequential plane aperture. On metal that window is an
                // intentional MMIO page fault, so kernel scanout must not
                // dereference it. The text image is canonical at this point:
                // characters in plane 0, attributes in plane 1, both at even
                // CRTC word offsets.
                for cell in 0..text_len / 2 {
                    let off = cell * 2;
                    scratch[cell * 2] = machine.read(VGA_VRAM_BASE + off);
                    scratch[cell * 2 + 1] =
                        machine.read(VGA_VRAM_BASE + 0x10000 + off);
                }
            } else {
                machine.copy_from(0xB8000, &mut scratch[..text_len]);
            }
            // Sequencer Character Map Select: B uses bits 1:0 plus bit 4;
            // A uses bits 3:2 plus bit 5. The encoded selector is reordered
            // into the physical 8-KB map number by moving its high bit low.
            let map_b = usize::from((state.seq[3] & 0x03) << 1 | (state.seq[3] >> 4) & 1);
            let map_a = usize::from(((state.seq[3] >> 2) & 0x03) << 1
                | (state.seq[3] >> 5) & 1);
            for (map, dst_base) in [(map_a, text_len), (map_b, text_len + VGA_MAP_LEN)] {
                let font_base = VGA_VRAM_BASE + 2 * 0x10000 + map * 0x2000;
                machine.copy_from(font_base, &mut scratch[dst_base..dst_base + VGA_MAP_LEN]);
                // VGA reserves 32 bytes per glyph. Compact the selected map
                // in place for the renderer; walking forward is safe because
                // every destination begins at or below its source.
                for ch in 0..256 {
                    let src = dst_base + ch * 32;
                    let dst = dst_base + ch * glyph_h;
                    scratch.copy_within(src..src + glyph_h, dst);
                }
            }
            let (vram, fonts) = scratch.split_at(text_len);
            let font = &fonts[..font_len];
            let font_b = &fonts[VGA_MAP_LEN..VGA_MAP_LEN + font_len];
            (vram, &[], font, font_b)
        }
        // 4 KB and 16 KB apertures: banding them would buy back less than
        // the per-row address arithmetic (CGA's two interleaved banks) costs.
        VgaMode::Cga4 | VgaMode::Cga2 =>
            (read_aperture(machine, scratch, 0xB8000, 0x4000, 0, 0x4000), &[], fallback_font, fallback_font),
        VgaMode::LinearSvga { .. } => (&[], &[], fallback_font, fallback_font), // handled by the short-circuit above
    };
    // Display-start (page-flip front buffer), pixel pan (smooth scroll) and
    // line-compare (split-screen) apply to the planar families and to linear
    // Mode 13h. The display-start latch is in word units for the planar
    // modes (per-plane byte offset) but the address counter runs in
    // doubleword mode under 13h, so each latch step is 4 linear pixels.
    let planar = matches!(mode, VgaMode::Planar16 { .. } | VgaMode::ModeX { .. });
    let mode13 = matches!(mode, VgaMode::Mode13h);
    let start_latch = ((state.crtc[0x0C] as usize) << 8) | state.crtc[0x0D] as usize;
    // CGA palettes come from the Mode-Control/Colour-Select registers. The
    // 640×200 2-colour mode's foreground is the Colour-Select low nibble
    // (background black); the 320×200 4-colour set is the register-resolved
    // palette. Other modes ignore this field.
    let cga_palette = match mode {
        VgaMode::Cga4 => ::vga::cga4_palette(state.cga_mode_ctl, state.cga_color_select),
        VgaMode::Cga2 => [0x000000, ::vga::CGA16[(state.cga_color_select & 0x0F) as usize], 0, 0],
        _ => [0; 4],
    };
    Some(Frame {
        mode,
        vram,
        planes,
        ac: &state.ac,
        palette: &state.dac,
        dac_mask: state.dac_mask,
        font,
        font_b,
        blink: state.ac[0x10] & 0x08 != 0,
        cga_palette,
        start_offset: if planar { start_latch } else if mode13 { start_latch * 4 } else { 0 },
        pixel_pan: if planar || mode13 { (state.ac[0x13] & 0x07) as usize } else { 0 },
        line_compare: if planar || mode13 { state.line_compare(h) } else { usize::MAX },
    })
}

/// Whole-frame throttle for the hosted window sink, off the same tick clock
/// the 0x3DA vertical-retrace fabrication reads. The direct-framebuffer path
/// does not use this: its render/publish state machine owns that cadence.
fn frame_due(now_ticks: u64, hz: u64) -> bool {
    let frame = (now_ticks.wrapping_mul(hz) / 1000) as u32;
    static LAST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    LAST.swap(frame, Ordering::Relaxed) != frame
}

/// Use the allocation-free `Vec<u32>` frame store as packed 16/24/32-bit
/// storage. The extra bytes in the final word are outside the returned frame.
fn packed_frame(storage: &mut alloc::vec::Vec<u32>, bytes: usize) -> &mut [u8] {
    storage.resize(bytes.div_ceil(4), 0);
    unsafe {
        core::slice::from_raw_parts_mut(storage.as_mut_ptr() as *mut u8, bytes)
    }
}

/// Nearest-neighbour horizontal fit from a card-native packed frame into the
/// display shadow. Vertical fitting remains `Display::present`'s job, exactly
/// as it is for a VGA shadow.
fn stretch_packed_rows(
    src: &[u8],
    src_w: usize,
    dst: &mut [u8],
    dst_w: usize,
    height: usize,
    step: usize,
) {
    let src_stride = src_w * step;
    let dst_stride = dst_w * step;
    if src_w == dst_w {
        dst[..dst_stride * height].copy_from_slice(&src[..src_stride * height]);
        return;
    }
    let base = src_w / dst_w;
    let rem = src_w % dst_w;
    for y in 0..height {
        let src_row = &src[y * src_stride..(y + 1) * src_stride];
        let dst_row = &mut dst[y * dst_stride..(y + 1) * dst_stride];
        let (mut sx, mut err) = (0usize, 0usize);
        for pixel in dst_row.chunks_exact_mut(step) {
            pixel.copy_from_slice(&src_row[sx * step..(sx + 1) * step]);
            sx += base;
            err += rem;
            if err >= dst_w {
                sx += 1;
                err -= dst_w;
            }
        }
    }
}

/// Drive the Voodoo's display: report the vertical retrace it paces swaps on,
/// and present a frame once one is ready. Returns true when the card owns the
/// display, so the VGA path stands down.
///
/// The retrace is the host's clock, handed to the card — it has none of its
/// own, which is why a deferred `swapbufferCMD` needs this call to complete.
fn voodoo_display_tick<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    pc: &mut PcMachine,
    now_ticks: u64,
) -> bool {
    if !pc.voodoo.active() {
        return false;
    }
    // 60 Hz, the refresh Glide programs for every resolution we serve.
    let refresh_due = frame_due(now_ticks, 60);
    if refresh_due {
        pc.voodoo.vblank();
    }
    // A newly opened or edited OSD must repaint even when the guest is
    // sitting on a completed front buffer and no longer swapping.
    let osd_open = crate::kernel::osd::is_open();
    if !pc.voodoo.frame_ready && !(osd_open && refresh_due) {
        return true;
    }
    let (w, h) = pc.voodoo.dimensions();
    let (w, h) = (w as usize, h as usize);
    // Where the frame goes is the display's business, not the card's. On a
    // framebuffer the card clocks pixels straight out in the panel's own
    // encoding and the panel takes a row copy; a window sink wants whole
    // native-RGB frames. A real VGA card has neither entry point — the board's
    // pass-through relay would drive the monitor directly there, and we have
    // nothing to emulate that with, so the frame is dropped. No token at all
    // means this thread does not own the console: a Glide program in the
    // background still swaps, it just is not seen.
    let display = match &mut pc.vga {
        DisplayedVga::Emulated(_, display) => Some(display),
        DisplayedVga::Native(_) => None,
    };
    if let Some(display) = display {
        // Hosted windows track the card's native geometry. A framebuffer's
        // shadow width was selected with its display mode and remains shared
        // with VGA, so both sources receive the same physical fit.
        if display.is_host() {
            display.shadow_width = w;
        }
        let out_w = display.shadow_width;
        let step = display.rgb.bytes_per_pixel as usize;
        if out_w == 0 || w == 0 || h == 0 {
            return true;
        }

        let dac = crate::kernel::display::dac_for(display.rgb);
        let shadow_len = out_w * h * step;
        let shadow = packed_frame(&mut pc.present_fb, shadow_len);
        if out_w == w {
            pc.voodoo.scanout(shadow, out_w * step, &dac);
        } else {
            let native_len = w * h * step;
            pc.present_scratch.resize(native_len, 0);
            pc.voodoo.scanout(&mut pc.present_scratch, w * step, &dac);
            stretch_packed_rows(&pc.present_scratch, w, shadow, out_w, h, step);
        }
        display.present(machine, bios, h, shadow);
    }
    true
}

pub fn display_tick<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    pc: &mut PcMachine,
    regs: &Regs,
    now_ticks: u64,
) {
    
    // A Glide program that has mapped the Voodoo owns the display: the card
    // scans out instead of the VGA, exactly as the real board's pass-through
    // relay does when it switches out of VGA mode.
    if voodoo_display_tick(machine, &mut *bios, pc, now_ticks) {
        return;
    }
    // A real card scans out its own VRAM: there is no register file to read
    // and nothing for a software present to do.
    let DisplayedVga::Emulated(dev, display) = &mut pc.vga else {
        return;
    };
    let vga = &mut dev.state;
    if display.is_headless() { return; }
    let prof = crate::kernel::startup::profile_enabled();
    if !display.is_host() {
        // Direct framebuffer: phase zero is guest-visible retrace. Its
        // trailing edge renders one complete immutable shadow; the following
        // tick publishes that shadow to GOP. Rendering and device traffic get
        // separate budgets, and the physical scanout is the only visible
        // top-to-bottom sweep.
        let period_ticks: usize = if display.slow() { 50 } else { 14 };
        let Some(mode) = vga.current_mode() else { return };
        match crate::kernel::display::scanout_action(
            &mut pc.present_scratch2, display, mode, now_ticks, period_ticks,
        ) {
            crate::kernel::display::ScanoutAction::None => {}
            crate::kernel::display::ScanoutAction::Render => {
                let p0 = if prof { machine.rdtsc() } else { 0 };
                let full = (0, ::vga::dimensions(mode).1);
                // The source aperture, registers and DAC are captured once for
                // the whole shadow; no palette generation can split the image.
                let Some(frame) =
                    scanout(vga, machine, regs, &mut pc.present_scratch, full)
                else {
                    return;
                };
                let p1 = if prof { machine.rdtsc() } else { 0 };
                let rendered = crate::kernel::display::render_shadow(
                    &mut pc.present_scratch2, display, &frame,
                );
                if prof {
                    let p2 = machine.rdtsc();
                    crate::kernel::startup::bill_display(
                        frame.mode,
                        p1.wrapping_sub(p0),
                        rendered as u64,
                        p2.wrapping_sub(p1),
                        0,
                        0,
                    );
                }
            }
            crate::kernel::display::ScanoutAction::Publish => {
                let (vga_h, out_w, shadow) =
                    crate::kernel::display::completed_shadow(&mut pc.present_scratch2)
                        .expect("ready VGA shadow is missing");
                let p0 = if prof { machine.rdtsc() } else { 0 };
                debug_assert_eq!(display.shadow_width, out_w);
                let copied = display.present(machine, &mut *bios, vga_h, shadow);
                let present_cycles = if prof {
                    machine.rdtsc().wrapping_sub(p0)
                } else {
                    0
                };
                crate::kernel::startup::bill_present();
                if prof {
                    crate::kernel::startup::bill_display(
                        mode, 0, 0, 0, present_cycles, copied,
                    );
                }
            }
        }
        return;
    }
    // Window sink (hosted): still takes a whole rendered frame per period.
    if !frame_due(now_ticks, 70) {
        return;
    }
    crate::kernel::startup::bill_present();
    let p0 = if prof { machine.rdtsc() } else { 0 };
    // Whole-frame sink: `render` walks every row, so capture the full frame.
    let full = vga.current_mode().map_or((0, 0), |m| (0, ::vga::dimensions(m).1));
    let Some(frame) = scanout(vga, machine, regs, &mut pc.present_scratch, full) else { return };
    let p1 = if prof { machine.rdtsc() } else { 0 };
    let (w, h) = ::vga::dimensions(frame.mode);
    let need = w * h;
    if pc.present_fb.len() < need {
        pc.present_fb.resize(need, 0);
    }
    let fb = &mut pc.present_fb[..need];
    ::vga::render(&frame, fb);
    let p2 = if prof { machine.rdtsc() } else { 0 };
    pc.present_fb.truncate(need);
    display.shadow_width = w;
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(pc.present_fb.as_mut_ptr() as *mut u8, need * 4)
    };
    display.present(machine, bios, h, bytes);
    if prof {
        let p3 = machine.rdtsc();
        crate::kernel::startup::bill_display(
            frame.mode, p1.wrapping_sub(p0), 1, p2.wrapping_sub(p1),
            p3.wrapping_sub(p2), need);
    }
}
