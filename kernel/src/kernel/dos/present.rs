//! Putting the machine's picture on the machine's display.
//!
//! The emulated VGA and Voodoo produce process-owned pixels; `platform` says
//! what this machine can actually show them on. This is where those meet: when
//! a frame is due, scan the current owner's video into its retained surface.
//! The event-loop compositor combines that surface with other windows.
//!
//! Kernel work, not machine work, which is why it is here and not beside the
//! cards. Everything it names on the display side — `Display`,
//! `Sink` and `Scanout` — is a capability or a
//! sink the kernel owns; the machine below produces a picture and has no
//! opinion about where it goes.

use crate::Regs;
use crate::kernel::bios_display::{DosVideo, FullscreenVga};
use core::sync::atomic::Ordering;

use super::machine::PcMachine;
use ::vga::VgaState;

static mut LAST_DIAG_MODE: Option<::vga::VgaMode> = None;
static mut LAST_DIAG_BLACK: Option<bool> = None;
static DIAG_LINES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static DIAG_RENDERS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

fn diagnose_shadow(state: &VgaState, mode: ::vga::VgaMode, nonzero: usize, hash: u32) {
    if !crate::kernel::startup::trace_enabled() {
        return;
    }
    let black = nonzero == 0;
    let old_mode = unsafe { core::ptr::read_volatile(&raw const LAST_DIAG_MODE) };
    let old_black = unsafe { core::ptr::read_volatile(&raw const LAST_DIAG_BLACK) };
    let changed = old_mode != Some(mode) || old_black != Some(black);
    let render = DIAG_RENDERS.fetch_add(1, Ordering::Relaxed) + 1;
    if !changed && !render.is_multiple_of(32) {
        return;
    }
    unsafe {
        core::ptr::write_volatile(&raw mut LAST_DIAG_MODE, Some(mode));
        core::ptr::write_volatile(&raw mut LAST_DIAG_BLACK, Some(black));
    }
    if DIAG_LINES.fetch_add(1, Ordering::Relaxed) >= 64 {
        return;
    }
    let Some(state) = state.legacy() else {
        crate::compact_dbg_println!(
            "[vgascan] mode={:?} black={} nz={} hash={:08X}",
            mode_name(mode), black as u8, nonzero, hash,
        );
        return;
    };
    crate::compact_dbg_println!(
        "[vgascan] mode={:?} black={} nz={} hash={:08X} seq={:02X?} gc5={:02X} gc6={:02X} acidx={:02X} ac10={:02X} dacmask={:02X}",
        mode_name(mode), black as u8, nonzero, hash, &state.seq[..],
        state.gc[5], state.gc[6], state.ac_state.index,
        state.ac[0x10], state.dac_mask,
    );
}

fn mode_name(mode: vga::VgaMode) -> &'static str {
    match mode {
        vga::VgaMode::Text { .. } => "Text",
        vga::VgaMode::Mode13h => "Mode13h",
        vga::VgaMode::Cga4 => "Cga4",
        vga::VgaMode::Cga2 => "Cga2",
        vga::VgaMode::Planar16 { .. } => "Planar16",
        vga::VgaMode::ModeX { .. } => "ModeX",
        vga::VgaMode::LinearSvga { .. } => "LinearSvga",
    }
}

/// Build the displayed frame from the live registers + VRAM: resolve the
/// mode, point at LiveVram, and read the display-start / pixel pan /
/// line-compare that select the visible window. `None` means the current
/// register state does not describe a renderable mode.
fn scanout<'a, A: crate::Arch>(
    state: &'a VgaState, machine: &'a A, _regs: &Regs,
    svga_start: usize,
) -> Option<::vga::Frame<'a>>
{
    use ::vga::{Frame, VgaMode};
    // Both VGA programming models scan out of the one kernel-owned live store.
    // Guest LFB and bank windows are aliases of these pages, so no capture copy
    // is needed before rendering.
    if let Some(svga) = state.svga() {
        let size = svga.visible_frame_bytes();
        let live = super::machine::vga::live_vram(machine);
        let end = svga_start.checked_add(size)?;
        let vram = live.get(svga_start..end)?;
        return Some(Frame {
            plane_layout: ::vga::VramLayout::PlaneMinor,
            mode: VgaMode::LinearSvga {
                w: svga.config.width,
                h: svga.config.height,
                bpp: svga.config.bits_per_pixel,
                pitch: svga.logical_pitch,
            },
            vram,
            planes: &[],
            ac: &[0; 21],
            palette: &svga.palette.rgb,
            dac_mask: svga.palette.mask(),
            font: &lib::vga_fonts::FONT_8X16,
            font_b: &lib::vga_fonts::FONT_8X16,
            font_maps: None,
            blink: false, text_cursor: None,
            cga_palette: [0; 4],
            start_offset: 0,
            pixel_pan: 0,
            line_compare: usize::MAX,
            blank_start: usize::MAX,
        });
    }
    let state = state.legacy()?;
    let mode = state.classify_mode()?;
    let (_, h) = ::vga::dimensions(mode);
    // The shared borrow prevents guest execution/owner switches until the
    // returned frame is consumed. No IRQ handler accesses this store.
    let live = super::machine::vga::live_planes(machine);
    let vram = if matches!(mode, VgaMode::Mode13h) { &live[..0x10000] } else { &[] };
    let map_b = (state.seq[3] & 0x03) << 1 | (state.seq[3] >> 4) & 1;
    let map_a = ((state.seq[3] >> 2) & 0x03) << 1 | (state.seq[3] >> 5) & 1;
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
        plane_layout: state.layout(),
        mode,
        vram,
        planes: live,
        ac: &state.ac,
        palette: &state.dac,
        dac_mask: state.dac_mask,
        font: &[],
        font_b: &[],
        font_maps: Some((map_a, map_b)),
        blink: state.ac[0x10] & 0x08 != 0,
        text_cursor: ::vga::TextCursor::from_crtc(&state.crtc, (machine.now() / 250_000_000) % 2 == 0),
        cga_palette,
        start_offset: if planar || matches!(mode, VgaMode::Text { .. }) { start_latch } else if mode13 { start_latch * 4 } else { 0 },
        pixel_pan: if planar || mode13 { (state.ac[0x13] & 0x07) as usize } else { 0 },
        line_compare: if planar || mode13 { state.line_compare(h) } else { usize::MAX },
        blank_start: if planar || mode13 { state.vertical_blank_start(h) } else { usize::MAX },
    })
}

/// Whole-frame throttle for the hosted window sink, off the same tick clock
/// the 0x3DA vertical-retrace fabrication reads. The direct-framebuffer path
/// does not use this: its render/publish state machine owns that cadence.
fn frame_due(now_ns: u64, hz: u64) -> bool {
    let frame = (u128::from(now_ns) * u128::from(hz) / 1_000_000_000) as u32;
    static LAST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    LAST.swap(frame, Ordering::Relaxed) != frame
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
    now_ns: u64,
    external: Option<&mut crate::kernel::display::Display>,
) -> bool {
    let Some(voodoo) = pc.voodoo.as_mut() else {
        return false;
    };
    if !voodoo.active() {
        return false;
    }
    // 60 Hz, the refresh Glide programs for every resolution we serve.
    let refresh_due = frame_due(now_ns, 60);
    if refresh_due {
        voodoo.vblank();
    }
    // A newly opened or edited OSD must repaint even when the guest is
    // sitting on a completed front buffer and no longer swapping.
    let osd_open = crate::kernel::osd::is_open();
    if !voodoo.frame_ready && !(osd_open && refresh_due) {
        return true;
    }
    let (w, h) = voodoo.dimensions();
    let (w, h) = (w as usize, h as usize);
    // Where the frame goes is the display's business, not the card's. On a
    // framebuffer the card clocks pixels straight out in the panel's own
    // encoding and the panel takes a row copy; a window sink wants whole
    // native-RGB frames. A real VGA card has neither entry point — the board's
    // pass-through relay would drive the monitor directly there, and we have
    // nothing to emulate that with, so the frame is dropped. No token at all
    // means this thread does not own the console: a Glide program in the
    // background still swaps, it just is not seen.
    let display = external.or(match &mut pc.vga {
        DosVideo::Fullscreen(FullscreenVga::Emulated(_, display)) => Some(display),
        DosVideo::Vga(_) | DosVideo::Fullscreen(FullscreenVga::Native(_)) => None,
    });
    if let Some(display) = display {
        // Hosted windows track the card's native geometry. A framebuffer's
        // shadow width was selected with its display mode and remains shared
        // with VGA, so both sources receive the same physical fit.
        if display.is_host() {
            display.shadow_width = w;
        }
        let step = display.rgb.bytes_per_pixel as usize;
        if w == 0 || h == 0 {
            return true;
        }

        let dac = crate::kernel::display::dac_for(display.rgb);
        let mut ramp = [0u8; 256 * 4];
        let generation = voodoo.vbe_ramp(&mut ramp);
        let hardware_gamma = display.program_voodoo_ramp(
            machine, bios, generation, &mut ramp,
        );
        let Some(shadow) = pc.scanout.packed_surface(w, h, display.rgb) else {
            return true;
        };
        if hardware_gamma {
            voodoo.scanout_raw(shadow, w * step, &dac);
        } else {
            voodoo.scanout(shadow, w * step, &dac);
        }
        display.present_packed(machine, bios, w, h, shadow);
    }
    true
}

/// Publish one completed emulated-VGA frame. State-only DOS enters the shared
/// desktop as an opaque content node; fullscreen DOS keeps its direct display
/// path because it deliberately owns the whole adapter.
fn publish_vga_surface(
    width: usize,
    height: usize,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    const DOS_SCANOUT: crate::kernel::gui::PresentationKey =
        crate::kernel::gui::PresentationKey(2);
    const DOS_SURFACE: crate::kernel::gui::SurfaceKey = crate::kernel::gui::SurfaceKey(2);
    desktop.focus(endpoint);
    let surface_id = desktop
        .ensure_surface(endpoint, DOS_SURFACE)
        .expect("create DOS VGA surface");
    let node = desktop
        .ensure_node(
            endpoint,
            DOS_SCANOUT,
            crate::kernel::gui::Rect::new(0, 0, width as u32, height as u32),
        )
        .expect("create DOS VGA presentation node");
    let placement = desktop.geometry(node).expect("live DOS VGA presentation node");
    let geometry = crate::kernel::gui::Rect::new(
        placement.x, placement.y, width as u32, height as u32,
    );
    let structural = desktop.node_state(node).is_none_or(|current| {
        current.geometry != geometry
            || current.content != Some(surface_id)
            || !current.visible
    });
    if structural {
        let mut transaction = crate::kernel::gui::Transaction::new(endpoint);
        transaction
            .set_geometry(node, geometry)
            .attach(node, Some(surface_id))
            .set_visible(node, true);
        desktop.commit(transaction).expect("commit DOS VGA presentation node");
    }
    desktop.damage_surface(endpoint, DOS_SURFACE);

}

/// Attach a completed background snapshot without changing compositor focus.
pub(super) fn attach_retained_vga_surface(
    width: usize,
    height: usize,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    const DOS_SCANOUT: crate::kernel::gui::PresentationKey =
        crate::kernel::gui::PresentationKey(2);
    const DOS_SURFACE: crate::kernel::gui::SurfaceKey = crate::kernel::gui::SurfaceKey(2);
    let surface_id = desktop
        .ensure_surface(endpoint, DOS_SURFACE)
        .expect("create retained DOS VGA surface");
    let node = desktop
        .ensure_node(
            endpoint,
            DOS_SCANOUT,
            crate::kernel::gui::Rect::new(0, 0, width as u32, height as u32),
        )
        .expect("create retained DOS VGA presentation node");
    let placement = desktop.geometry(node).expect("retained DOS VGA presentation node");
    let geometry = crate::kernel::gui::Rect::new(
        placement.x, placement.y, width as u32, height as u32,
    );
    let structural = desktop.node_state(node).is_none_or(|current| {
        current.geometry != geometry
            || current.content != Some(surface_id)
            || !current.visible
    });
    if structural {
        let mut transaction = crate::kernel::gui::Transaction::new(endpoint);
        transaction
            .set_geometry(node, geometry)
            .attach(node, Some(surface_id))
            .set_visible(node, true);
        desktop.commit(transaction).expect("commit retained DOS VGA presentation node");
    }
    desktop.damage_surface(endpoint, DOS_SURFACE);
}

/// Rasterize the detached VGA into an output-independent retained preview.
/// Native RGB is intentional: PixelBuffer carries its own format and the
/// compositor converts it to the eventual output format when the OSD opens.
pub(super) fn snapshot_retained_surface<A: crate::Arch>(
    machine: &mut A,
    dos: &mut crate::kernel::thread::DosState<A>,
    regs: &Regs,
) {
    let pc = &mut dos.pc;
    let (vga, output) = (&mut pc.vga, &mut pc.scanout);
    let DosVideo::Vga(dev) = vga else { return };
    let svga_start = dev.state.svga().map_or(0, |svga| svga.display_byte_offset());
    let Some(frame) = scanout(&dev.state, machine, regs, svga_start) else { return };
    let format = output.format();
    let _ = crate::kernel::display::render_frame(output, format, &frame);
}

pub fn display_tick<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    pc: &mut PcMachine,
    regs: &Regs,
    now_ns: u64,
    mut external: Option<&mut crate::kernel::display::Display>,
    mut presentation: Option<(
        &mut crate::kernel::gui::Desktop,
        crate::kernel::gui::EndpointId,
    )>,
) {
    // A physical Voodoo board takes the monitor away from the VGA card with
    // its pass-through relay.  Our Voodoo is a software producer, so on a
    // native-VGA machine it instead needs the adapter converted into a packed
    // Display sink before it can own scanout.  Preserve the guest's complete
    // VGA/VBE state in EmulatedVga; that same state is then ready to render
    // again when Glide switches the relay back to VGA.
    //
    // Do this only on the Native -> Emulated edge.  Once detached, the Display
    // remains beside the emulated VGA and both VGA and Voodoo can select it
    // without further firmware mode changes or ownership transactions.
    if pc.voodoo.as_ref().is_some_and(|voodoo| voodoo.active())
        && pc.vga.is_native()
    {
        let handoff = super::machine::vga::release_fullscreen(&mut pc.vga, machine, &mut *bios);
        let display = handoff.into_voodoo_surface(machine, &mut *bios);
        pc.vga.map(|vga| match vga {
            DosVideo::Vga(vga) => (
                DosVideo::Fullscreen(FullscreenVga::Emulated(vga, display)),
                (),
            ),
            DosVideo::Fullscreen(_) => unreachable!("Voodoo display detach left fullscreen VGA active"),
        });
        crate::compact_println!("Display: Voodoo acquired packed scanout from native VGA");
    }

    // A Glide program that has mapped the Voodoo owns the display: the card
    // scans out instead of the VGA, exactly as the real board's pass-through
    // relay does when it switches out of VGA mode.
    if voodoo_display_tick(machine, &mut *bios, pc, now_ns, external.as_deref_mut()) {
        return;
    }
    // Native VBE scans out the guest's directly mapped framebuffer. Its only
    // present-side work is publishing batched raw-DAC compatibility writes;
    // native legacy VGA makes that flush a no-op and also returns here.
    if let DosVideo::Fullscreen(FullscreenVga::Native(native)) = &mut pc.vga {
        bios.flush_vbe_ports(machine, native.cap_mut());
        return;
    }
    // A real legacy card scans out its own VRAM: there is no register file to
    // read and nothing for a software present to do.
    let (dev, display) = match &mut pc.vga {
        DosVideo::Vga(dev) => {
            let Some(display) = external else { return };
            (dev, display)
        }
        DosVideo::Fullscreen(FullscreenVga::Emulated(dev, display)) => (dev, display),
        DosVideo::Fullscreen(FullscreenVga::Native(_)) => return,
    };
    display.restore_voodoo_ramp(machine, bios);
    let svga_start = dev.state.svga().map_or(0, |svga| svga.display_byte_offset());
    let vga = &dev.state;
    if display.is_headless() { return; }
    if !display.is_host() {
        // Direct framebuffer: phase zero is guest-visible retrace. Its
        // trailing edge renders one complete immutable shadow; the following
        // tick publishes that shadow to GOP. Rendering and device traffic get
        // separate budgets, and the physical scanout is the only visible
        // top-to-bottom sweep.
        let refresh_hz: u32 = if display.slow() { 20 } else { 70 };
        // OSD publication samples the live VGA producer at 20 Hz, but the
        // guest-visible beam continues at its normal rate. Conflating these
        // clocks makes retrace-polled games themselves run at OSD speed.
        let raster_hz = if crate::kernel::osd::is_open() { 20 } else { refresh_hz };
        let Some(mode) = vga.current_mode() else { return };
        let raster_size = presentation
            .is_some()
            .then(|| ::vga::dimensions(mode));
        match crate::kernel::display::scanout_action(
            &mut pc.scanout,
            display,
            mode,
            now_ns,
            refresh_hz,
            raster_hz,
            raster_size,
        ) {
            crate::kernel::display::ScanoutAction::None => {}
            crate::kernel::display::ScanoutAction::Render => {
                let capture_sample = crate::kernel::osd_profile::Sample::start(machine);
                // The source aperture, registers and DAC are captured once for
                // the whole shadow; no palette generation can split the image.
                let Some(frame) =
                    scanout(vga, machine, regs, svga_start)
                else {
                    return;
                };
                let (width, height) = ::vga::dimensions(frame.mode);
                capture_sample.finish(machine, crate::kernel::osd_profile::Stage::Capture, width * height);
                let raster_sample = crate::kernel::osd_profile::Sample::start(machine);
                let rendered = crate::kernel::display::render_shadow(
                    &mut pc.scanout, display.rgb, &frame,
                );
                raster_sample.finish(machine, crate::kernel::osd_profile::Stage::Raster, width * height);
                if rendered
                    && let Some((desktop, endpoint)) = presentation.as_mut()
                {
                    let (width, height) = ::vga::dimensions(frame.mode);
                    publish_vga_surface(width, height, desktop, *endpoint);
                }
                if rendered && crate::kernel::startup::trace_enabled() {
                    let (nonzero, hash) =
                        crate::kernel::display::shadow_sample(&pc.scanout);
                    diagnose_shadow(vga, frame.mode, nonzero, hash);
                }
            }
            crate::kernel::display::ScanoutAction::Publish {
                vga_height: vga_h,
                out_width: out_w,
            } => {
                debug_assert!(presentation.is_some() || display.shadow_width == out_w);
                // A retained surface became available at Render, when its
                // producer actually changed the pixels. This later phase
                // exists only to transfer direct-scanout shadows.
                if presentation.is_none() {
                    let pixels = crate::kernel::display::take_shadow(&mut pc.scanout);
                    display.present_packed(
                        machine,
                        &mut *bios,
                        ::vga::dimensions(mode).0,
                        vga_h,
                        &pixels,
                    );
                    crate::kernel::display::recycle_shadow(&mut pc.scanout, pixels);
                }
            }
        }
        return;
    }
    // Window sink (hosted): still takes a whole rendered frame per period.
    if !frame_due(now_ns, 70) {
        return;
    }
    // Whole-frame sink: `render` walks every row, so capture the full frame.
    let Some(frame) = scanout(vga, machine, regs, svga_start) else { return };
    let (w, h) = ::vga::dimensions(frame.mode);
    let rendered = crate::kernel::display::render_frame(
        &mut pc.scanout,
        display.rgb,
        &frame,
    );
    if !rendered { return }
    if crate::kernel::startup::trace_enabled() {
        let (nonzero, hash) = crate::kernel::display::shadow_sample(&pc.scanout);
        diagnose_shadow(vga, frame.mode, nonzero, hash);
    }
    display.shadow_width = w;
    if let Some((desktop, endpoint)) = presentation {
        publish_vga_surface(w, h, desktop, endpoint);
    } else {
        let pixels = crate::kernel::display::take_shadow(&mut pc.scanout);
        display.present_packed(machine, bios, w, h, &pixels);
        crate::kernel::display::recycle_shadow(&mut pc.scanout, pixels);
    }
}
