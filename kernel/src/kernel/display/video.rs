//! Resident scanout and composition. Legacy VGA consumes its shared device
//! registers and memory at beam phases, on either the guest or media core.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use crate::kernel::{gui, media};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static REFRESH_HZ: AtomicU32 = AtomicU32::new(70);
static LAST_FRAME: AtomicU32 = AtomicU32::new(u32::MAX);
static PHASE_DRIVEN: AtomicBool = AtomicBool::new(false);
static NEXT_PHASE_US: AtomicU32 = AtomicU32::new(0);
fn set_deadline(ns: u64) {
    NEXT_PHASE_US.store(ns.div_ceil(1000) as u32, Ordering::Relaxed);
}
fn frame_period() -> u32 {
    let now = crate::kernel::portio::now_ns();
    let hz = u64::from(REFRESH_HZ.load(Ordering::Relaxed));
    ((now / 1_000_000_000) * hz + (now % 1_000_000_000) * hz / 1_000_000_000) as u32
}
fn due() -> bool {
    if PHASE_DRIVEN.load(Ordering::Relaxed) {
        let now = (crate::kernel::portio::now_ns() / 1000) as u32;
        return now.wrapping_sub(NEXT_PHASE_US.load(Ordering::Relaxed)) as i32 >= 0;
    }
    let frame = frame_period();
    LAST_FRAME.load(Ordering::Relaxed) != frame
}

// VBE has no legacy CRTC row/latch engine. Keep its existing linear capture
// path distinct from the shared VGA device consumer.
struct LinearSource {
    live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion),
    mode: vga::VgaMode,
    vram: Vec<u8>, planes: Vec<u8>,
    palette: [u8; 768], dac_mask: u8,
}
impl LinearSource {
    fn new(frame: &vga::Frame<'_>, live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion)) -> Self {
        let mut result = Self { live, mode: frame.mode, vram: Vec::new(), planes: Vec::new(),
            palette: frame.palette, dac_mask: frame.dac_mask };
        result.configure(frame, live);
        result
    }
    fn configure(&mut self, frame: &vga::Frame<'_>, live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion)) {
        self.mode = frame.mode;
        self.live = live;
        self.vram.resize(frame.vram.len(), 0);
        self.palette = frame.palette;
        self.dac_mask = frame.dac_mask;
    }
    fn frame(&self) -> vga::Frame<'_> {
        vga::Frame {
            memory: None, mode: self.mode, vram: &self.vram, planes: &[],
            font: &[], font_b: &[], plane_layout: vga::VramLayout::PlaneMinor,
            ac: [0; 21], palette: self.palette, dac_mask: self.dac_mask,
            cga_palette: [0; 4], font_maps: None, blink: false, text_cursor: None,
            start_offset: 0, pixel_pan: 0, split_pixel_pan: 0,
            line_compare: usize::MAX, blank_start: usize::MAX,
        }
    }
}

pub(super) struct Video {
    fb: Framebuffer,
    format: PixelFormat,
    source: Option<LinearSource>,
    legacy: Option<vga::scanout::Scanout>,
    legacy_epoch: u32,
    legacy_ready: Option<vga::VgaMode>,
    presented: Vec<u8>,
    source_revision: Option<u32>,
    owner: Option<gui::EndpointId>,
    voodoo: Option<alloc::sync::Arc<crate::kernel::dos::VoodooOutput>>,
    scanout: Box<Scanout>,
    scene: Option<gui::ResidentScene>,
    composed: Vec<u8>,
    row: Vec<u8>,
    canvas: (usize, usize),
    last_output: Option<(usize, usize)>,
    announced: bool,
}
impl Video {
    fn new(fb: Framebuffer, format: PixelFormat) -> Self {
        Self { fb, format, source: None, legacy: None, legacy_epoch: 0, legacy_ready: None, presented: Vec::new(), source_revision: None, owner: None, voodoo: None, scanout: Scanout::new_boxed(),
            scene: None, composed: Vec::new(), row: alloc::vec![0; fb.width * usize::from(format.bytes_per_pixel)],
            canvas: (fb.width, fb.height), last_output: None, announced: false }
    }
    pub(super) fn invalidate(&mut self) {
        self.source_revision = None;
        self.last_output = None;
    }
    fn render(&mut self) {
        if self.owner.is_some() && self.scene.is_none() { return; }
        if let Some(legacy) = &mut self.legacy {
            if self.legacy_epoch != crate::kernel::dos::scanout_epoch() { return; }
            let now = crate::kernel::portio::now_ns();
            let completed = legacy.advance(now, &mut self.scanout.surface, media::checkpoint);
            set_deadline(legacy.deadline_ns());
            if self.legacy_epoch != crate::kernel::dos::scanout_epoch() { return; }
            let Some(mode) = completed.or(self.legacy_ready.take()) else { return };
            core::mem::swap(&mut self.scanout.surface, &mut self.presented);
            let (w, h) = vga::dimensions(mode);
            self.scanout.geo = (w, h, w, h, w, h);
            self.scanout.mode = Some(mode);
            self.scanout.pal.fmt = self.format;
        }
        let _stall = crate::kernel::portio::StallWatch::new("video render/present");
        if let Some(voodoo) = &self.voodoo {
            let w = self.scanout.geo.0;
            let h = self.scanout.geo.1;
            if !voodoo.scanout(&mut self.scanout.surface, w, h,
                w * usize::from(self.format.bytes_per_pixel), &dac_for(self.format)) {
                return;
            }
        }
        if let Some(source) = &mut self.source {
            let (vram, planes) = source.live;
            let Some(revision) = self.source_revision else { return };
            if !crate::kernel::dos::sample_live(vram, &mut source.vram,
                planes, &mut source.planes, revision) { return; }
            let mut frame = source.frame();
            if !(crate::kernel::portio::now_ns() / 250_000_000).is_multiple_of(2) {
                frame.text_cursor = None;
            }
            raster_shadow(&mut self.scanout, self.format, &frame, true);
        }
        if let Some(legacy) = &mut self.legacy {
            let mut cooperate = || {
                media::checkpoint();
                if self.legacy_epoch == crate::kernel::dos::scanout_epoch() {
                    let now = crate::kernel::portio::now_ns();
                    if now >= legacy.deadline_ns() {
                        if let Some(mode) = legacy.advance(now, &mut self.scanout.surface, media::checkpoint) {
                            self.legacy_ready = Some(mode);
                        }
                        set_deadline(if self.legacy_ready.is_some() { now } else { legacy.deadline_ns() });
                    }
                }
            };
            present_image(&self.fb, self.format, self.canvas, &mut self.last_output,
                &mut self.scene, &mut self.composed, &mut self.row,
                (self.scanout.geo.0, self.scanout.geo.1, self.format, &self.presented), &mut cooperate);
        } else {
            let Some(image) = self.scanout.surface() else { return };
            present_image(&self.fb, self.format, self.canvas, &mut self.last_output,
                &mut self.scene, &mut self.composed, &mut self.row, image, &mut media::checkpoint);
        }
        finish_present();
        if !self.announced {
            if media::enabled() {
                if self.legacy.is_some() {
                    crate::compact_dbg_println!("Video service: phase-driven VGA scanout");
                } else {
                    crate::compact_dbg_println!("Video service: rendering at {} Hz", REFRESH_HZ.load(Ordering::Relaxed));
                }
            }
            self.announced = true;
        }
        // A slow frame drops missed refreshes rather than immediately doing
        // another full frame. Leave a publication window for the guest core.
        LAST_FRAME.store(frame_period(), Ordering::Relaxed);

    }
}

/// Presentation reads a stable completed image. Its checkpoints keep beam
/// fetches moving even while a slow physical framebuffer is being copied.
fn present_image(fb: &Framebuffer, format: PixelFormat, canvas: (usize, usize),
    last_output: &mut Option<(usize, usize)>, scene: &mut Option<gui::ResidentScene>,
    composed: &mut Vec<u8>, row: &mut Vec<u8>,
    image: (usize, usize, PixelFormat, &[u8]), cooperate: &mut dyn FnMut()) {
    let (w, h, image_format, pixels) = image;
    let (width, height, pixels) = if let Some(scene) = scene {
        let live = gui::PixelBuffer::new(w, h, w * usize::from(image_format.bytes_per_pixel), image_format, pixels).ok();
        scene.render(live, canvas.0, canvas.1, format, composed);
        (canvas.0, canvas.1, &composed[..])
    } else { (w, h, pixels) };
    let output = if (width, height) == canvas { canvas }
        else { native_output_size(fb.width, fb.height, width, height) };
    if *last_output != Some(output) {
        clear_packed_bars_cooperative(fb, format, output, cooperate);
        *last_output = Some(output);
    }
    blit_packed_cooperative(fb, format, output,
        PackedSource { width, height, pixels, row }, cooperate);
}

impl Display {
    pub(crate) fn resident_video(&self) -> bool { self.framebuffer().is_some() }
    pub(crate) fn pause_video(&self) {
        if let Some(service) = &self.video { service.pause(); }
    }
    pub(crate) fn poll_video(&self) {
        if !media::enabled() && let Some(service) = &self.video { service.activate(); }
    }
    fn video_service(&mut self) -> Option<&media::VideoService<Video>> {
        let fb = *self.framebuffer()?;
        // Retire the earlier one-shot presenter before transferring its sink.
        if let Some(work) = self.presentation.take() { drop(work); }
        if self.video.is_none() {
            self.video = Some(unsafe { media::VideoService::new(Video::new(fb, self.rgb), due, Video::render) });
        }
        self.video.as_ref()
    }

    /// Bind a device lifetime and backing store. Register writes are already
    /// visible to the consumer; there is no per-write configuration to publish.
    pub(crate) fn bind_legacy(&mut self, device: &vga::LegacyVgaState,
        memory: vga::memory::Memory<'static>, epoch: u32, owner: Option<gui::EndpointId>) -> bool {
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_lock() {
            if video.legacy.as_ref().is_none_or(|old| !old.same_device(device))
                || video.legacy_epoch != epoch || video.owner != owner {
                video.legacy = Some(vga::scanout::Scanout::new(device, memory,
                    video.format, crate::kernel::portio::now_ns()));
                video.legacy_epoch = epoch;
                video.legacy_ready = None;
                video.source = None;
                video.source_revision = None;
                video.voodoo = None;
                video.owner = owner;
                if owner.is_none() { video.scene = None; }
            }
            if let Some(mode) = device.classify_mode() {
                let (w, h) = vga::dimensions(mode);
                // VGA timing registers can briefly describe nonsense during a
                // mode set. Bound reservations; standard modes fit this limit.
                if w <= 2048 && h <= 1024 {
                    let pixels = (w * h).max(720 * 480);
                    let video = &mut *video;
                    let legacy = video.legacy.as_mut().unwrap();
                    legacy.reserve(pixels, &mut video.scanout.surface);
                    legacy.reserve(pixels, &mut video.presented);
                }
            }
            set_deadline(video.legacy.as_ref().unwrap().deadline_ns());
            PHASE_DRIVEN.store(true, Ordering::Relaxed);
        }
        service.activate();
        true
    }

    pub(crate) fn linear_needs_publication(&self, revision: u32, owner: Option<gui::EndpointId>) -> bool {
        let Some(service) = &self.video else { return true };
        service.try_lock().is_some_and(|video|
            video.source_revision != Some(revision) || video.owner != owner || video.voodoo.is_some())
    }

    /// Linear VBE fallback. Legacy VGA instead binds its shared device above.
    pub(crate) fn publish_linear(&mut self, frame: &vga::Frame<'_>, owner: Option<gui::EndpointId>) -> bool {
        if !matches!(frame.mode, vga::VgaMode::LinearSvga { .. }) { return false; }
        let planes = &[];
        let Some(live) = crate::kernel::dos::LiveRegion::from_slice(frame.vram)
            .zip(crate::kernel::dos::LiveRegion::from_slice(planes)) else { return false };
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_lock() {
            video.voodoo = None;
            video.legacy = None;
            video.source_revision = Some(crate::kernel::dos::scanout_revision());
            if let Some(source) = &mut video.source { source.configure(frame, live); }
            else { video.source = Some(LinearSource::new(frame, live)); }
            let (w, h) = vga::dimensions(frame.mode);
            let format = video.format;
            let bytes = w * h * usize::from(format.bytes_per_pixel) + vga::PACKED_ROW_PADDING;
            video.scanout.surface.resize(bytes, 0);
            video.scanout.geo = (w, h, w, h, w, h);
            video.scanout.mode = Some(frame.mode);
            video.owner = owner;
            if owner.is_none() { video.scene = None; }
        }
        PHASE_DRIVEN.store(false, Ordering::Relaxed);
        REFRESH_HZ.store(70, Ordering::Relaxed);
        service.activate();
        true
    }

    pub(crate) fn publish_voodoo(&mut self,
        output: &alloc::sync::Arc<crate::kernel::dos::VoodooOutput>, owner: Option<gui::EndpointId>,
    ) -> bool {
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_lock() {
            let (w, h) = output.dimensions();
            if w != 0 && h != 0 && w <= 4096 && h <= 4096 {
                video.source = None;
                video.legacy = None;
                video.source_revision = None;
                if video.voodoo.as_ref().is_none_or(|old| !alloc::sync::Arc::ptr_eq(old, output)) {
                    video.voodoo = Some(output.clone());
                }
                let format = video.format;
                video.scanout.packed_surface(w, h, format);
                video.owner = owner;
                if owner.is_none() { video.scene = None; }
            }
        }
        PHASE_DRIVEN.store(false, Ordering::Relaxed);
        REFRESH_HZ.store(60, Ordering::Relaxed);
        service.activate();
        true
    }

    pub(crate) fn publish_composition<'a, A: crate::Arch>(
        &mut self, machine: &A, windows: &mut gui::WindowManager, width: usize, height: usize,
        resolve: impl Fn(gui::EndpointId, gui::SurfaceKey) -> Option<gui::PixelBuffer<'a>>,
    ) -> bool {
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_publish() {
            let sample = crate::kernel::osd_profile::Sample::start(machine);
            let owner = video.owner;
            let format = video.format;
            windows.publish_processes(&mut video.scene, resolve, owner, format);
            let step = usize::from(video.format.bytes_per_pixel);
            video.composed.resize(width * height * step, 0);
            video.canvas = (width, height);
            sample.finish(machine, crate::kernel::osd_profile::Stage::Snapshot, 0);
        }
        let sample = crate::kernel::osd_profile::Sample::start(machine);
        service.activate();
        sample.finish(machine, crate::kernel::osd_profile::Stage::Register, 0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_linear_vbe_samples_new_pixels_without_another_publication() {
        let _access = crate::kernel::dos::live_access();
        let mut guest = [0x00ff0000u32.to_le_bytes(), 0x000000ffu32.to_le_bytes()].concat();
        let ac = [0; 21];
        let palette = [0; 768];
        let frame = vga::Frame {
            memory: None,
            mode: vga::VgaMode::LinearSvga { w: 2, h: 1, bpp: 32, pitch: 8 },
            vram: &guest, planes: &[], plane_layout: vga::VramLayout::PlaneMinor,
            ac: ac, palette: palette, dac_mask: 255, cga_palette: [0; 4],
            font: &[], font_b: &[], font_maps: None, blink: false, text_cursor: None,
            start_offset: 0, pixel_pan: 0, split_pixel_pan: 0,
            line_compare: usize::MAX, blank_start: usize::MAX,
        };
        // Backing stays alive and is only changed between render calls.
        let live = unsafe { (crate::kernel::dos::LiveRegion::for_test(&guest),
            crate::kernel::dos::LiveRegion::for_test(&[])) };
        let captured = LinearSource::new(&frame, live);
        let expected = guest.clone();
        let mut framebuffer = alloc::vec![0u8; 8];
        let fb = Framebuffer { va: framebuffer.as_mut_ptr() as usize, pitch: 8,
            width: 2, height: 1, slow: false, wide: false };
        let mut video = Video::new(fb, PixelFormat::NATIVE);
        video.scanout.surface.resize(8 + vga::PACKED_ROW_PADDING, 0);
        video.scanout.geo = (2, 1, 2, 1, 2, 1);
        video.scanout.mode = Some(captured.mode);
        video.source = Some(captured);
        video.source_revision = Some(crate::kernel::dos::scanout_revision());
        let source_capacity = video.scanout.surface.capacity();
        let row_capacity = video.row.capacity();
        video.render();
        assert_eq!(framebuffer, expected);
        framebuffer.fill(0);
        guest.copy_from_slice(&[0x0000ff00u32.to_le_bytes(); 2].concat());
        // Never combine current VRAM with obsolete register state.
        video.source_revision = Some(crate::kernel::dos::scanout_revision().wrapping_sub(1));
        video.render();
        assert!(framebuffer.iter().all(|&byte| byte == 0));
        video.source_revision = Some(crate::kernel::dos::scanout_revision());
        video.render(); // No second register publication or core-0 frame copy.
        assert_eq!(framebuffer, guest);
        assert_eq!(video.scanout.surface.capacity(), source_capacity);
        assert_eq!(video.row.capacity(), row_capacity);
    }
}
