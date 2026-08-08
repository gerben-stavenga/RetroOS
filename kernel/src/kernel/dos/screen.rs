//! Putting the machine's screen on the machine's display.
//!
//! The VGA model, the Voodoo and the OSD all produce pixels; `platform` says
//! what this machine can actually show them on. This is where those meet: when
//! a frame is due, scan the current owner's model out into a frame, composite
//! the overlay, and present it through whatever sink the probe handed over.
//!
//! Kernel work, not machine work, which is why it is here and not beside the
//! cards. Everything it names on the display side — `DisplayToken`,
//! `LfbDisplay`, `Scratch`, `NativeScanout`, the OSD — is a capability or a
//! sink the kernel owns; the machine below produces a picture and has no
//! opinion about where it goes.

use crate::Regs;
use core::sync::atomic::Ordering;

use super::machine::{PcMachine, vga::{BiosVga, SVGA_LFB_BASE}};
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
    let (vram, planes): (&[u8], &[u8]) = match mode {
        VgaMode::Planar16 { .. } | VgaMode::ModeX { .. } => (&[], &state.planes),
        VgaMode::Mode13h => {
            let (lo, hi) = m13_span();
            (read_aperture(machine, scratch, 0xA0000, 0x10000, lo, hi), &[])
        }
        // 4 KB and 16 KB apertures: banding them would buy back less than
        // the per-row address arithmetic (CGA's two interleaved banks) costs.
        VgaMode::Text80x25 => (read_aperture(machine, scratch, 0xB8000, 80 * 25 * 2, 0, 80 * 25 * 2), &[]),
        VgaMode::Cga4 | VgaMode::Cga2 => (read_aperture(machine, scratch, 0xB8000, 0x4000, 0, 0x4000), &[]),
        VgaMode::LinearSvga { .. } => (&[], &[]), // handled by the short-circuit above
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
        font: &lib::vga_fonts::FONT_8X16,
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

/// Drive the Voodoo's display: report the vertical retrace it paces swaps on,
/// and present a frame once one is ready. Returns true when the card owns the
/// display, so the VGA path stands down.
///
/// The retrace is the host's clock, handed to the card — it has none of its
/// own, which is why a deferred `swapbufferCMD` needs this call to complete.
fn voodoo_display_tick(pc: &mut PcMachine, now_ticks: u64) -> bool {
    if pc.voodoo.linear_base.is_none() {
        return false;
    }
    // 60 Hz, the refresh Glide programs for every resolution we serve.
    if frame_due(now_ticks, 60) {
        pc.voodoo.vblank();
    }
    if !pc.voodoo.frame_ready {
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
    match pc.vga.display() {
        Some(crate::kernel::platform::DisplayToken::LfbDisplay(fb)) => {
            if fb.packed_format().is_none() {
                return true;
            }
            if pc.voodoo_scanout.arm(fb, w, h) {
                let (out, pitch, dac) = pc.voodoo_scanout.target();
                pc.voodoo.scanout(out, pitch, dac);
                pc.voodoo_scanout.publish(fb);
            }
        }
        Some(_) => {}
        None => {
            if crate::kernel::display::host_present_sink_installed() {
                let need = w * h;
                if pc.present_fb.len() < need {
                    pc.present_fb.resize(need, 0);
                }
                pc.present_fb.truncate(need);
                // The window sink takes `0x00RRGGBB` frames; that is just this
                // buffer's bytes with the identity encoding.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        pc.present_fb.as_mut_ptr() as *mut u8,
                        need * 4,
                    )
                };
                pc.voodoo.scanout(bytes, w * 4, &voodoo::Dac::native());
                crate::kernel::display::present_host(w, h, &mut pc.present_fb);
            }
        }
    }
    true
}

pub fn display_tick<A: crate::Arch>(machine: &mut A, pc: &mut PcMachine, regs: &Regs, now_ticks: u64) {
    
    // A Glide program that has mapped the Voodoo owns the display: the card
    // scans out instead of the VGA, exactly as the real board's pass-through
    // relay does when it switches out of VGA mode.
    if voodoo_display_tick(pc, now_ticks) {
        return;
    }
    // A real card scans out its own VRAM: there is no register file to read
    // and nothing for a software present to do.
    let BiosVga::Emulated(dev) = &mut pc.vga else { return };
    let vga = &mut dev.state;
    // Hidden devices have no sink of their own; while the monitor holds the
    // card, its sink is where this thread's preview goes.
    let display = match &dev.display {
        Some(display) => display,
        None => {
            let Some(display) = crate::kernel::osd::display() else { return };
            display
        }
    };
    // Where the frame goes: a sink we blit into, a window, or nowhere. A card
    // scanning out its own VRAM needs no software present at all. (This used
    // to test only the sink; when fbcon stopped registering one, every metal
    // frame silently returned here.)
    let (direct, host_window) = match display {
        crate::kernel::platform::DisplayToken::LfbDisplay(sink) => (Some(sink), false),
        crate::kernel::platform::DisplayToken::HostWindow => (None, true),
        crate::kernel::platform::DisplayToken::BiosDisplay(_)
        | crate::kernel::platform::DisplayToken::Headless => return,
    };
    let prof = crate::kernel::startup::profile_enabled();
    if let Some(sink) = direct {
        let fb = &sink.framebuffer;
        // Direct framebuffer: phase zero is guest-visible retrace. Its
        // trailing edge renders one complete immutable shadow; the following
        // tick publishes that shadow to GOP. Rendering and device traffic get
        // separate budgets, and the physical scanout is the only visible
        // top-to-bottom sweep.
        let period_ticks: usize = if fb.slow { 50 } else { 14 };
        let Some(mode) = vga.current_mode() else { return };
        match crate::kernel::display::scanout_action(
            &mut pc.present_scratch2, sink, mode, now_ticks, period_ticks,
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
                    &mut pc.present_scratch2, sink, &frame,
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
                if crate::kernel::osd::is_open() {
                    let vga_w = ::vga::dimensions(mode).0;
                    let format = sink.packed_format().expect("indexed sink reached packed OSD");
                    crate::kernel::osd::paint(
                        shadow,
                        out_w * format.bytes_per_pixel as usize,
                        out_w,
                        vga_h,
                        vga_w,
                        format,
                    );
                }
                let p0 = if prof { machine.rdtsc() } else { 0 };
                let copied = sink.present_shadow(vga_h, shadow);
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
    if !host_window || !frame_due(now_ticks, 70) {
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
    if crate::kernel::osd::is_open() {
        // `render` writes native 0x00RRGGBB into a tightly-packed w×h buffer.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(fb.as_mut_ptr() as *mut u8, fb.len() * 4)
        };
        crate::kernel::osd::paint(
            bytes, w * 4, w, h, w, ::vga::PixelFormat::NATIVE,
        );
    }
    let p2 = if prof { machine.rdtsc() } else { 0 };
    pc.present_fb.truncate(need);
    crate::kernel::display::present_host(w, h, &mut pc.present_fb);
    if prof {
        let p3 = machine.rdtsc();
        crate::kernel::startup::bill_display(
            frame.mode, p1.wrapping_sub(p0), 1, p2.wrapping_sub(p1),
            p3.wrapping_sub(p2), need);
    }
}

