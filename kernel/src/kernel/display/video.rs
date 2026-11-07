//! Resident scanout and composition. VGA and VBE consume their device
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

fn deadline(now: u64) -> u64 {
    if PHASE_DRIVEN.load(Ordering::Relaxed) {
        // The compact deadline wraps every ~71 minutes. Interpret it against
        // the iteration's time sample, including an already-due phase.
        let micros = NEXT_PHASE_US.load(Ordering::Relaxed)
            .wrapping_sub((now / 1000) as u32) as i32;
        if micros <= 0 { now } else { (now / 1000 + micros as u64) * 1000 }
    } else {
        let hz = u64::from(REFRESH_HZ.load(Ordering::Relaxed).max(1));
        let frame = (u128::from(now) * u128::from(hz) / 1_000_000_000) as u32;
        if LAST_FRAME.load(Ordering::Relaxed) != frame { now } else {
            ((u128::from(now) * u128::from(hz) / 1_000_000_000 + 1)
                * 1_000_000_000).div_ceil(u128::from(hz)) as u64
        }
    }
}

pub(super) struct Video {
    fb: Framebuffer,
    format: PixelFormat,
    device: Option<vga::scanout::Scanout>,
    device_epoch: u32,
    device_ready: Option<(vga::VgaMode, u64)>,
    presented: Vec<u8>,
    owner: Option<gui::EndpointId>,
    voodoo: Option<alloc::sync::Arc<crate::kernel::dos::VoodooOutput>>,
    scanout: Box<Scanout>,
    scene: Option<gui::ResidentScene>,
    composed: Vec<u8>,
    row: Vec<u8>,
    canvas: (usize, usize),
    last_output: Option<(usize, usize)>,
    announced: bool,
    next_present_ns: u64,
}
impl Video {
    fn new(fb: Framebuffer, format: PixelFormat) -> Self {
        Self { fb, format, device: None, device_epoch: 0, device_ready: None, presented: Vec::new(), owner: None, voodoo: None, scanout: Scanout::new_boxed(),
            scene: None, composed: Vec::new(), row: alloc::vec![0; fb.width * usize::from(format.bytes_per_pixel)],
            canvas: (fb.width, fb.height), last_output: None, announced: false, next_present_ns: 0 }
    }
    pub(super) fn invalidate(&mut self) {
        self.last_output = None;
    }
    fn render(&mut self) {
        // A slow presenter must yield before beam catch-up as well as before
        // output. Otherwise the catch-up itself can consume the guest's entire
        // publication window on a single CPU.
        let present_started = crate::kernel::portio::now_ns();
        if present_started < self.next_present_ns {
            set_deadline(self.next_present_ns);
            return;
        }
        if self.owner.is_some() && self.scene.is_none() { return; }
        if let Some(device) = &mut self.device {
            if self.device_epoch != crate::kernel::dos::scanout_epoch() { return; }
            let now = crate::kernel::portio::now_ns();
            let completed = device.advance(now, &mut self.scanout.surface, media::checkpoint);
            set_deadline(device.deadline_ns());
            if self.device_epoch != crate::kernel::dos::scanout_epoch() { return; }
            if let Some(mode) = completed {
                self.device_ready = Some((mode, device.present_after_ns(now)));
            }
            let Some((mode, after)) = self.device_ready else { return };
            if now < after {
                set_deadline(device.deadline_ns().min(after));
                return;
            }
            self.device_ready = None;
            core::mem::swap(&mut self.scanout.surface, &mut self.presented);
            let (w, h) = vga::dimensions(mode);
            self.scanout.geo = (w, h, w, h, w, h);
            self.scanout.mode = Some(mode);
            self.scanout.pal.fmt = self.format;
        }
        // Scanout phases above remain current even when the physical sink is
        // slow. A completed copy must leave time before presenting again:
        // checkpoints can finish another VGA frame during that same copy.
        let _stall = crate::kernel::portio::StallWatch::new("video render/present");
        if let Some(voodoo) = &self.voodoo {
            let w = self.scanout.geo.0;
            let h = self.scanout.geo.1;
            if !voodoo.scanout(&mut self.scanout.surface, w, h,
                w * usize::from(self.format.bytes_per_pixel), &dac_for(self.format)) {
                return;
            }
        }
        if let Some(device) = &mut self.device {
            let mut cooperate = || {
                media::checkpoint();
                if self.device_epoch == crate::kernel::dos::scanout_epoch() {
                    let now = crate::kernel::portio::now_ns();
                    if now >= device.deadline_ns() {
                        if let Some(mode) = device.advance(now, &mut self.scanout.surface, media::checkpoint) {
                            self.device_ready = Some((mode, device.present_after_ns(now)));
                        }
                        set_deadline(self.device_ready.map_or(device.deadline_ns(),
                            |(_, after)| device.deadline_ns().min(after)));
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
                if self.device.is_some() {
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
        let finished = crate::kernel::portio::now_ns();
        let interval = 1_000_000_000 / u64::from(REFRESH_HZ.load(Ordering::Relaxed).max(1));
        self.next_present_ns = if finished.saturating_sub(present_started) >= interval {
            finished.saturating_add(interval)
        } else { 0 };
        if self.next_present_ns != 0 { set_deadline(self.next_present_ns); }

    }
}

/// Presentation reads a stable completed image. Its checkpoints keep beam
/// fetches moving even while a slow physical framebuffer is being copied.
#[allow(clippy::too_many_arguments)] // Borrows disjoint renderer fields while scanout advances.
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
    fn video_service(&mut self) -> Option<&media::VideoService<Video>> {
        let fb = *self.framebuffer()?;
        // Retire the earlier one-shot presenter before transferring its sink.
        if let Some(work) = self.presentation.take() { drop(work); }
        if self.video.is_none() {
            self.video = Some(unsafe { media::VideoService::new(Video::new(fb, self.rgb), due, deadline, Video::render) });
        }
        self.video.as_ref()
    }

    /// Bind a device lifetime and backing store. Register writes are already
    /// visible to the consumer; there is no per-write configuration to publish.
    pub(crate) fn bind_vga(&mut self, device: &vga::VgaState,
        memory: vga::memory::Memory<'static>, epoch: u32, owner: Option<gui::EndpointId>) -> bool {
        let Some(service) = self.video_service() else { return false };
        if let Some(mut video) = service.try_lock() {
            if video.device.as_ref().is_none_or(|old| !old.same_device(device))
                || video.device_epoch != epoch || video.owner != owner {
                video.device = Some(vga::scanout::Scanout::new(device, memory,
                    video.format, crate::kernel::portio::now_ns()));
                video.device_epoch = epoch;
                video.device_ready = None;
                video.voodoo = None;
                video.owner = owner;
                if owner.is_none() { video.scene = None; }
            }
            if let Some(mode) = device.current_mode() {
                let (w, h) = vga::dimensions(mode);
                // VGA timing registers can briefly describe nonsense during a
                // mode set. Bound reservations; standard modes fit this limit.
                if w <= 2048 && h <= 1024 {
                    let pixels = (w * h).max(720 * 480);
                    let video = &mut *video;
                    let device = video.device.as_mut().unwrap();
                    device.reserve(pixels, &mut video.scanout.surface);
                    device.reserve(pixels, &mut video.presented);
                }
            }
            set_deadline(video.device.as_ref().unwrap().deadline_ns().max(video.next_present_ns));
            PHASE_DRIVEN.store(true, Ordering::Relaxed);
        }
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
                video.device = None;
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
