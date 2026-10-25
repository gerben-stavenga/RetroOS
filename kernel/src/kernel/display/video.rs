//! Resident, independently paced display pipeline. The producer publishes
//! register state; sampling, decoding, composition and scanout run here.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use crate::kernel::{gui, media};
use core::sync::atomic::{AtomicU32, Ordering};

static REFRESH_HZ: AtomicU32 = AtomicU32::new(70);
static LAST_FRAME: AtomicU32 = AtomicU32::new(u32::MAX);
fn frame_period() -> u32 {
    let now = crate::kernel::portio::now_ns();
    let hz = u64::from(REFRESH_HZ.load(Ordering::Relaxed));
    ((now / 1_000_000_000) * hz + (now % 1_000_000_000) * hz / 1_000_000_000) as u32
}
fn due() -> bool {
    let frame = frame_period();
    LAST_FRAME.load(Ordering::Relaxed) != frame
}

struct ScanoutSource {
    live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion),
    mode: vga::VgaMode,
    vram: Vec<u8>, planes: Vec<u8>, font: Vec<u8>, font_b: Vec<u8>,
    plane_layout: vga::VramLayout,
    ac: [u8; 21], palette: [u8; 768], dac_mask: u8,
    cga_palette: [u32; 4], font_maps: Option<(u8, u8)>, blink: bool,
    text_cursor: Option<vga::TextCursor>, start_offset: usize,
    pixel_pan: usize, split_pixel_pan: usize, line_compare: usize, blank_start: usize,
}
fn copy(destination: &mut Vec<u8>, source: &[u8]) {
    destination.resize(source.len(), 0);
    destination.copy_from_slice(source);
}
impl ScanoutSource {
    fn new(frame: &vga::Frame<'_>, live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion)) -> Self {
        let mut result = Self {
            live, mode: frame.mode, vram: Vec::new(), planes: Vec::new(),
            font: Vec::new(), font_b: Vec::new(), plane_layout: frame.plane_layout,
            ac: [0; 21], palette: [0; 768], dac_mask: 0,
            cga_palette: [0; 4], font_maps: None, blink: false, text_cursor: None,
            start_offset: 0, pixel_pan: 0, split_pixel_pan: 0,
            line_compare: usize::MAX, blank_start: usize::MAX,
        };
        result.configure(frame, live);
        result
    }
    fn configure(&mut self, frame: &vga::Frame<'_>, live: (crate::kernel::dos::LiveRegion, crate::kernel::dos::LiveRegion)) {
        self.mode = frame.mode;
        let planes = if matches!(frame.mode, vga::VgaMode::Mode13h) { &[][..] } else { frame.planes };
        self.live = live;
        self.vram.resize(frame.vram.len(), 0);
        self.planes.resize(planes.len(), 0);
        copy(&mut self.font, frame.font);
        copy(&mut self.font_b, frame.font_b);
        self.plane_layout = frame.plane_layout;
        self.ac = *frame.ac; self.palette = *frame.palette; self.dac_mask = frame.dac_mask;
        self.cga_palette = frame.cga_palette; self.font_maps = frame.font_maps;
        self.blink = frame.blink; self.text_cursor = frame.text_cursor;
        self.start_offset = frame.start_offset; self.pixel_pan = frame.pixel_pan;
        self.split_pixel_pan = frame.split_pixel_pan;
        self.line_compare = frame.line_compare; self.blank_start = frame.blank_start;
    }
    fn frame(&self) -> vga::Frame<'_> {
        vga::Frame {
            mode: self.mode, vram: &self.vram, planes: &self.planes,
            font: &self.font, font_b: &self.font_b, plane_layout: self.plane_layout,
            ac: &self.ac, palette: &self.palette, dac_mask: self.dac_mask,
            cga_palette: self.cga_palette, font_maps: self.font_maps, blink: self.blink,
            text_cursor: self.text_cursor, start_offset: self.start_offset, pixel_pan: self.pixel_pan,
            split_pixel_pan: self.split_pixel_pan, line_compare: self.line_compare, blank_start: self.blank_start,
        }
    }
}

pub(super) struct Video {
    fb: Framebuffer,
    format: PixelFormat,
    source: Option<ScanoutSource>,
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
        Self { fb, format, source: None, source_revision: None, owner: None, voodoo: None, scanout: Scanout::new_boxed(),
            scene: None, composed: Vec::new(), row: alloc::vec![0; fb.width * usize::from(format.bytes_per_pixel)],
            canvas: (fb.width, fb.height), last_output: None, announced: false }
    }
    pub(super) fn invalidate(&mut self) {
        self.source_revision = None;
        self.last_output = None;
    }
    fn render(&mut self) {
        if self.owner.is_some() && self.scene.is_none() { return; }
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
            if !crate::kernel::dos::sample_live(vram, &mut source.vram, planes, &mut source.planes) { return; }
            let mut frame = source.frame();
            if !(crate::kernel::portio::now_ns() / 250_000_000).is_multiple_of(2) {
                frame.text_cursor = None;
            }
            raster_shadow(&mut self.scanout, self.format, &frame, true);
        }
        let (width, height, pixels) = if let Some(scene) = &mut self.scene {
            let live = self.scanout.surface().and_then(|(w, h, format, pixels)|
                gui::PixelBuffer::new(w, h, w * usize::from(format.bytes_per_pixel), format, pixels).ok());
            scene.render(live, self.canvas.0, self.canvas.1, self.format, &mut self.composed);
            (self.canvas.0, self.canvas.1, &self.composed[..])
        } else if let Some((w, h, _, pixels)) = self.scanout.surface().filter(|_| self.source.is_some() || self.voodoo.is_some()) {
            (w, h, pixels)
        } else { return };
        let output = if (width, height) == self.canvas { self.canvas }
            else { native_output_size(self.fb.width, self.fb.height, width, height) };
        if self.last_output != Some(output) {
            clear_packed_bars_cooperative(&self.fb, self.format, output, media::checkpoint);
            self.last_output = Some(output);
        }
        blit_packed_cooperative(&self.fb, self.format, output,
            PackedSource { width, height, pixels, row: &mut self.row }, media::checkpoint);
        finish_present();
        if !self.announced {
            if media::enabled() {
                crate::compact_dbg_println!("Video service: rendering at {} Hz", REFRESH_HZ.load(Ordering::Relaxed));
            }
            self.announced = true;
        }
        // A slow frame drops missed refreshes rather than immediately doing
        // another full frame. Leave a publication window for the guest core.
        LAST_FRAME.store(frame_period(), Ordering::Relaxed);
    }
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

    pub(crate) fn vga_needs_publication(&self, revision: u32, owner: Option<gui::EndpointId>) -> bool {
        let Some(service) = &self.video else { return true };
        service.try_lock().is_some_and(|video|
            video.source_revision != Some(revision) || video.owner != owner || video.voodoo.is_some())
    }

    /// Publish device registers and bind resident VRAM. The renderer samples
    /// the bytes itself; this never builds a frame on the guest core.
    pub(crate) fn publish_vga(&mut self, frame: &vga::Frame<'_>, owner: Option<gui::EndpointId>) -> bool {
        let planes = if matches!(frame.mode, vga::VgaMode::Mode13h) { &[][..] } else { frame.planes };
        let Some(live) = crate::kernel::dos::LiveRegion::from_slice(frame.vram)
            .zip(crate::kernel::dos::LiveRegion::from_slice(planes)) else { return false };
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_lock() {
            video.voodoo = None;
            video.source_revision = Some(crate::kernel::dos::scanout_revision());
            if let Some(source) = &mut video.source { source.configure(frame, live); }
            else { video.source = Some(ScanoutSource::new(frame, live)); }
            let (w, h) = vga::dimensions(frame.mode);
            let format = video.format;
            let bytes = w * h * usize::from(format.bytes_per_pixel) + vga::PACKED_ROW_PADDING;
            video.scanout.surface.resize(bytes, 0);
            video.scanout.geo = (w, h, w, h, w, h);
            video.scanout.mode = Some(frame.mode);
            video.owner = owner;
            if owner.is_none() { video.scene = None; }
        }
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
    fn resident_vga_samples_new_pixels_without_another_publication() {
        let _access = crate::kernel::dos::live_access();
        let mut guest = [0x00ff0000u32.to_le_bytes(), 0x000000ffu32.to_le_bytes()].concat();
        let ac = [0; 21];
        let palette = [0; 768];
        let frame = vga::Frame {
            mode: vga::VgaMode::LinearSvga { w: 2, h: 1, bpp: 32, pitch: 8 },
            vram: &guest, planes: &[], plane_layout: vga::VramLayout::PlaneMinor,
            ac: &ac, palette: &palette, dac_mask: 255, cga_palette: [0; 4],
            font: &[], font_b: &[], font_maps: None, blink: false, text_cursor: None,
            start_offset: 0, pixel_pan: 0, split_pixel_pan: 0,
            line_compare: usize::MAX, blank_start: usize::MAX,
        };
        // Backing stays alive and is only changed between render calls.
        let live = unsafe { (crate::kernel::dos::LiveRegion::for_test(&guest),
            crate::kernel::dos::LiveRegion::for_test(&[])) };
        let captured = ScanoutSource::new(&frame, live);
        let expected = guest.clone();
        let mut framebuffer = alloc::vec![0u8; 8];
        let fb = Framebuffer { va: framebuffer.as_mut_ptr() as usize, pitch: 8,
            width: 2, height: 1, slow: false, wide: false };
        let mut video = Video::new(fb, PixelFormat::NATIVE);
        video.scanout.surface.resize(8 + vga::PACKED_ROW_PADDING, 0);
        video.scanout.geo = (2, 1, 2, 1, 2, 1);
        video.scanout.mode = Some(captured.mode);
        video.source = Some(captured);
        let source_capacity = video.scanout.surface.capacity();
        let row_capacity = video.row.capacity();
        video.render();
        assert_eq!(framebuffer, expected);
        framebuffer.fill(0);
        guest.copy_from_slice(&[0x0000ff00u32.to_le_bytes(); 2].concat());
        video.render(); // No second register publication or core-0 frame copy.
        assert_eq!(framebuffer, guest);
        assert_eq!(video.scanout.surface.capacity(), source_capacity);
        assert_eq!(video.row.capacity(), row_capacity);
    }
}
