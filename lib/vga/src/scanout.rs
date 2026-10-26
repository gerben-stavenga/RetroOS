//! One scanout consumer, driven synchronously on CPU entry or asynchronously
//! by a media core. Only the consumer owns latches and the partial image.
use alloc::vec::Vec;
use crate::{beam::{Phase, Sequencer, Timing}, memory::Memory, Frame, LegacyVgaState,
    Pal, PixelFormat, VgaMode, dimensions, render_row_packed, PACKED_ROW_PADDING};

pub struct Scanout {
    device: LegacyVgaState,
    beam: Sequencer,
    memory: Memory<'static>,
    back: Vec<u8>,
    mode: Option<VgaMode>,
    pal: Pal,
    palette: [u8; 768],
    format: PixelFormat,
    collecting: bool,
    rows: usize,
    split: usize,
    last_ns: u64,
}
impl Scanout {
    pub fn new(device: &LegacyVgaState, memory: Memory<'static>, format: PixelFormat, now: u64) -> Self {
        let timing = Timing::from_registers(device.misc_output.get(), &device.seq.read(), &device.crtc.read());
        Self { device: device.scanout_view(), beam: Sequencer::new(timing, now), memory,
            back: Vec::new(), mode: None, pal: Pal::new(), palette: [0; 768], format,
            collecting: false, rows: 0, split: usize::MAX, last_ns: now }
    }
    pub fn same_device(&self, device: &LegacyVgaState) -> bool {
        self.device.registers.same_device(&device.registers)
    }
    /// Allocation is done by the owner before/while binding, never by advance.
    /// Rebinding an unchanged device only reserves capacity, not register state.
    pub fn reserve(&mut self, pixels: usize, front: &mut Vec<u8>) {
        let bytes = pixels * usize::from(self.format.bytes_per_pixel) + PACKED_ROW_PADDING;
        for buffer in [&mut self.back, front] {
            if buffer.capacity() < bytes {
                let length = buffer.len();
                buffer.reserve(bytes.saturating_sub(length));
                // Vec capacity is only virtual space in the demand-paged
                // kernel heap. Back ALL capacity on the owner core before
                // handing it to the allocation-free scanout consumer.
                buffer.resize(buffer.capacity(), 0);
                buffer.truncate(length);
            }
        }
    }
    pub fn deadline_ns(&self) -> u64 { self.beam.deadline_ns() }

    /// Process all phases through `now`, swapping only a completed active image
    /// into front. Registers are read at their hardware latch/fetch phases.
    pub fn advance(&mut self, now: u64, front: &mut Vec<u8>, mut checkpoint: impl FnMut()) -> Option<VgaMode> {
        let timing = Timing::from_registers(self.device.misc_output.get(),
            &self.device.seq.read(), &self.device.crtc.read());
        if timing != self.beam.timing() {
            self.beam.reprogram(timing, now);
            self.collecting = false;
        }
        // After suspension, historical pixels no longer exist in VRAM. Drop
        // the incomplete image and start at the next frame, rather than invent
        // many old frames from current memory or starve the guest catching up.
        let frame_ns = timing.time_at(timing.frame_clocks());
        if now.saturating_sub(self.last_ns) > frame_ns {
            self.beam = Sequencer::new(timing, now);
            self.collecting = false;
        }
        self.last_ns = now;
        let mut completed = None;
        while let Some(event) = self.beam.next(now) {
            match event.phase {
                Phase::RetraceStart => { self.device.latch_display_start(event.frame + 1); }
                Phase::RetraceEnd => { self.device.latch_pixel_pan(event.frame + 1); }
                Phase::FrameStart => {
                    self.mode = self.device.classify_mode();
                    self.rows = 0;
                    self.split = usize::MAX;
                    self.collecting = false;
                    if let Some(mode) = self.mode {
                        let (w, h) = dimensions(mode);
                        let bytes = w * h * usize::from(self.format.bytes_per_pixel) + PACKED_ROW_PADDING;
                        if w != 0 && h != 0 && bytes <= self.back.capacity() && bytes <= front.capacity() {
                            self.back.resize(bytes, 0);
                            self.collecting = true;
                        }
                    }
                }
                Phase::RowStart => {
                    checkpoint();
                    let Some(mode) = self.mode.filter(|_| self.collecting) else { continue };
                    let (w, h) = dimensions(mode);
                    let line = usize::from(event.line);
                    let repeat = (usize::from(timing.vertical_display) / h).max(1);
                    let compare = usize::from(self.device.crtc.get(0x18))
                        | (usize::from(self.device.crtc.get(7) & 0x10) << 4)
                        | (usize::from(self.device.crtc.get(9) & 0x40) << 3);
                    if line == compare + 1 { self.split = line.div_ceil(repeat); }
                    if line >= usize::from(timing.vertical_display) || !line.is_multiple_of(repeat) { continue; }
                    let row = line / repeat;
                    if row >= h || row != self.rows { continue; }
                    let mut frame = device_frame(&self.device, self.memory, mode, now);
                    frame.line_compare = self.split;
                    self.pal.sync(&frame.palette, frame.dac_mask, self.format, &mut self.palette);
                    self.pal.sync_planar(&frame.ac);
                    let stride = w * usize::from(self.format.bytes_per_pixel);
                    render_row_packed(&frame, row, &self.pal,
                        &mut self.back[row * stride..(row + 1) * stride + PACKED_ROW_PADDING]);
                    self.rows += 1;
                    if self.rows == h {
                        core::mem::swap(front, &mut self.back);
                        completed = Some(mode);
                        self.collecting = false;
                    }
                }
                _ => {}
            }
        }
        completed
    }
}

fn device_frame<'a>(state: &LegacyVgaState, memory: Memory<'a>, mode: VgaMode, now: u64) -> Frame<'a> {
    let (_, h) = dimensions(mode);
    let planar = matches!(mode, VgaMode::Planar16 { .. } | VgaMode::ModeX { .. });
    let mode13 = matches!(mode, VgaMode::Mode13h);
    let seq3 = state.seq.get(3);
    let map_b = (seq3 & 3) << 1 | (seq3 >> 4) & 1;
    let map_a = ((seq3 >> 2) & 3) << 1 | (seq3 >> 5) & 1;
    let pan = if matches!(mode, VgaMode::ModeX { .. } | VgaMode::Mode13h) {
        usize::from((state.pixel_pan() >> 1) & 3)
    } else if planar { usize::from(state.pixel_pan() & 7) } else { 0 };
    let start = usize::from(state.display_start());
    let ac = state.ac.read();
    Frame {
        memory: Some(memory), mode, vram: &[], planes: &[], plane_layout: state.layout(),
        ac, palette: state.dac.read(), dac_mask: state.dac_mask.get(),
        font: &[], font_b: &[], font_maps: Some((map_a, map_b)), blink: ac[16] & 8 != 0,
        text_cursor: crate::TextCursor::from_crtc(&state.crtc.read(), (now / 250_000_000).is_multiple_of(2)),
        cga_palette: match mode {
            VgaMode::Cga4 => crate::cga4_palette(state.cga_mode_ctl.get(), state.cga_color_select.get()),
            VgaMode::Cga2 => [0, crate::CGA16[usize::from(state.cga_color_select.get() & 15)], 0, 0],
            _ => [0; 4],
        },
        start_offset: if planar || matches!(mode, VgaMode::Text { .. }) { start } else if mode13 { start * 4 } else { 0 },
        pixel_pan: pan, split_pixel_pan: if ac[16] & 0x20 != 0 { 0 } else { pan },
        line_compare: usize::MAX,
        blank_start: if planar || mode13 { state.vertical_blank_start(h) } else { usize::MAX },
    }
}
