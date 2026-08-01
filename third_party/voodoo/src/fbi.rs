//! Frame Buffer Interface: video-memory layout, buffer swapping, fastfill and
//! scanout.
//!
//! Everything here takes the framebuffer RAM as an explicit `&[u8]` /
//! `&mut [u8]` argument — the card knows *offsets into* video memory, never
//! where that memory lives.

use crate::raster::Dither;
use crate::regs::*;
use crate::rgba::Rgba;

pub const NO_BUFFER: u32 = u32::MAX;

/// The part of the FBI state that is derived from registers rather than
/// stored in them (`fbi_state` in the C, minus the RAM pointer).
#[derive(Debug)]
pub struct Fbi {
    /// Byte mask of video memory (`size - 1`).
    pub mask: u32,
    /// Byte offsets of the up-to-3 RGB buffers; `NO_BUFFER` when absent.
    pub rgboffs: [u32; 3],
    /// Byte offset of the aux (depth/alpha) buffer; `NO_BUFFER` when absent.
    pub auxoffs: u32,

    pub frontbuf: u8,
    pub backbuf: u8,

    pub yorigin: u32,

    pub width: u32,
    pub height: u32,
    pub rowpixels: u32,
    pub tile_width: u32,
    pub tile_height: u32,
    pub x_tiles: u32,

    pub vblank_dont_swap: bool,

    /// Memory FIFO size in dwords; 0 when disabled. We do not emulate the
    /// FIFO's timing, only its programmed size (the guest reads free space).
    pub fifo_size: i32,
}

impl Fbi {
    pub fn new(fb_bytes: usize) -> Self {
        Self {
            mask: (fb_bytes as u32).saturating_sub(1),
            rgboffs: [0, 0, NO_BUFFER],
            auxoffs: NO_BUFFER,
            frontbuf: 0,
            backbuf: 1,
            yorigin: 0,
            width: 640,
            height: 480,
            rowpixels: 640,
            tile_width: 64,
            tile_height: 16,
            x_tiles: 10,
            vblank_dont_swap: false,
            fifo_size: 0,
        }
    }

    /// `recompute_video_memory` — SST-1 (Voodoo 1) layout only.
    pub fn recompute_video_memory(&mut self, reg: &[u32]) {
        let buffer_pages = fbiinit2_video_buffer_offset(reg[fbiInit2]);
        let fifo_start_page = fbiinit4_memory_fifo_start_row(reg[fbiInit4]);
        let mut fifo_last_page = fbiinit4_memory_fifo_stop_row(reg[fbiInit4]);

        let memory_config = fbiinit2_enable_triple_buf(reg[fbiInit2]);

        // Tiles are 64x16 on the SST-1; x_tiles counts half-tiles.
        self.tile_width = 64;
        self.tile_height = 16;
        self.x_tiles = fbiinit1_x_video_tiles(reg[fbiInit1]);
        self.rowpixels = self.tile_width * self.x_tiles;

        // First RGB buffer always starts at 0, the second right after it.
        self.rgboffs[0] = 0;
        self.rgboffs[1] = buffer_pages * 0x1000;

        match memory_config {
            // 3 color buffers, 0 aux buffers
            1 => {
                self.rgboffs[2] = 2 * buffer_pages * 0x1000;
                self.auxoffs = NO_BUFFER;
            }
            // 3 color buffers, 1 aux buffer
            2 => {
                self.rgboffs[2] = 2 * buffer_pages * 0x1000;
                self.auxoffs = 3 * buffer_pages * 0x1000;
            }
            // 0 (and the reserved 3): 2 color buffers, 1 aux buffer
            _ => {
                self.rgboffs[2] = NO_BUFFER;
                self.auxoffs = 2 * buffer_pages * 0x1000;
            }
        }

        for buf in 0..3 {
            if self.rgboffs[buf] != NO_BUFFER && self.rgboffs[buf] > self.mask {
                self.rgboffs[buf] = self.mask;
            }
        }
        if self.auxoffs != NO_BUFFER && self.auxoffs > self.mask {
            self.auxoffs = self.mask;
        }

        if fifo_last_page > self.mask / 0x1000 {
            fifo_last_page = self.mask / 0x1000;
        }
        self.fifo_size = if fifo_start_page <= fifo_last_page
            && fbiinit0_enable_memory_fifo(reg[fbiInit0])
        {
            let size = (fifo_last_page + 1 - fifo_start_page) as i32 * 0x1000 / 4;
            size.min(65536 * 2)
        } else {
            0
        };

        // Reset front/back if they now point at a buffer that does not exist.
        if self.rgboffs[2] == NO_BUFFER {
            if self.frontbuf == 2 {
                self.frontbuf = 0;
            }
            if self.backbuf == 2 {
                self.backbuf = 0;
            }
        }
    }

    /// `voodoo_swap_buffers` — rotate front/back (2- or 3-buffer).
    pub fn swap_buffers(&mut self) {
        if self.rgboffs[2] == NO_BUFFER {
            self.frontbuf = 1 - self.frontbuf;
            self.backbuf = 1 - self.frontbuf;
        } else {
            self.frontbuf = (self.frontbuf + 1) % 3;
            self.backbuf = (self.frontbuf + 1) % 3;
        }
    }

    /// Byte offset of the buffer `fbzMode`'s draw-buffer field selects, and
    /// how many 16-bit pixels fit between it and the end of video memory.
    fn draw_target(&self, destbuf: u32) -> Option<(u32, u32)> {
        let off = match destbuf {
            0 => self.rgboffs[self.frontbuf as usize],
            1 => self.rgboffs[self.backbuf as usize],
            _ => return None,
        };
        if off == NO_BUFFER {
            return None;
        }
        Some((off, (self.mask + 1 - off) / 2))
    }

    pub fn color_buffer(&self, sel: u32) -> Option<(u32, u32)> {
        match sel {
            0 | 1 => self.draw_target(sel),
            2 => {
                if self.auxoffs == NO_BUFFER {
                    None
                } else {
                    Some((self.auxoffs, (self.mask + 1 - self.auxoffs) / 2))
                }
            }
            _ => None,
        }
    }

    /// `fastfill` — fill the clip rectangle with `color1` (dithered, as the
    /// hardware does) and/or the aux buffer with `zaColor`.
    pub fn fastfill(&self, reg: &[u32], fb: &mut [u8]) {
        let fbz = reg[fbzMode];
        if !fbzmode_rgb_buffer_mask(fbz) && !fbzmode_aux_buffer_mask(fbz) {
            return;
        }

        let sx = ((reg[clipLeftRight] >> 16) & 0x3ff) as usize;
        let ex = (reg[clipLeftRight] & 0x3ff) as usize;
        let sy = ((reg[clipLowYHighY] >> 16) & 0x3ff) as usize;
        let ey = (reg[clipLowYHighY] & 0x3ff) as usize;
        let (sx, ex) = if sx > ex { (ex, sx) } else { (sx, ex) };

        if fbzmode_rgb_buffer_mask(fbz) {
            if let Some((base, max)) = self.draw_target(fbzmode_draw_buffer(fbz)) {
                // The fill colour is dithered per (x, y) like any other write,
                // which is why the hardware builds a 4x4 pattern up front.
                let c = Rgba::from_argb(reg[color1]);
                for y in sy..ey {
                    let dither = Dither::new(y as i32, fbz);
                    let row = y * self.rowpixels as usize;
                    for x in sx..ex {
                        let off = row + x;
                        if (off as u32) < max {
                            write_pixel(fb, base as usize + off * 2, dither.pixel(x as i32, c));
                        }
                    }
                }
            }
        }

        if fbzmode_aux_buffer_mask(fbz) && self.auxoffs != NO_BUFFER {
            let max = (self.mask + 1 - self.auxoffs) / 2;
            let depth = (reg[zaColor] & 0xffff) as u16;
            self.fill_rect(fb, self.auxoffs, max, sx, ex, sy, ey, depth);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_rect(
        &self,
        fb: &mut [u8],
        base: u32,
        max: u32,
        sx: usize,
        ex: usize,
        sy: usize,
        ey: usize,
        pixel: u16,
    ) {
        for y in sy..ey {
            let row = y * self.rowpixels as usize;
            for x in sx..ex {
                let off = row + x;
                if (off as u32) < max {
                    write_pixel(fb, base as usize + off * 2, pixel);
                }
            }
        }
    }

    /// Scan the visible front buffer out into `out` as 0x00RRGGBB, one u32 per
    /// pixel, `out_pitch` pixels per output row.
    ///
    /// This is the whole of "what the monitor sees": the SST-1 has no text
    /// mode, no planes and no palette in the display path — video memory is
    /// already RGB565 at `rowpixels` stride.
    ///
    /// `out` receives packed pixels in the destination's own encoding, one row
    /// per visible line at `out_pitch` BYTES, exactly as the RAMDAC would clock
    /// them at the monitor. Nothing downstream has to know a pixel format: the
    /// gamma CLUT and the encoding are folded into one component ramp per
    /// channel first, so the inner loop is three table reads and a store.
    pub fn scanout(&self, fb: &[u8], clut: &Clut, dac: &Dac, out: &mut [u8], out_pitch: usize) {
        let base = self.rgboffs[self.frontbuf as usize];
        if base == NO_BUFFER {
            return;
        }
        let ramp = dac.ramps(clut);
        let step = dac.bytes as usize;
        let width = (self.width as usize).min(out_pitch / step.max(1));
        for y in 0..self.height as usize {
            let src = base as usize + y * self.rowpixels as usize * 2;
            let dst = y * out_pitch;
            if dst + width * step > out.len() {
                break;
            }
            for x in 0..width {
                let off = src + x * 2;
                let p = if off + 1 < fb.len() {
                    u16::from_le_bytes([fb[off], fb[off + 1]])
                } else {
                    0
                };
                let enc = ramp.r[((p >> 11) & 0x1f) as usize]
                    | ramp.g[((p >> 5) & 0x3f) as usize]
                    | ramp.b[(p & 0x1f) as usize];
                let bytes = enc.to_le_bytes();
                out[dst + x * step..dst + (x + 1) * step].copy_from_slice(&bytes[..step]);
            }
        }
    }
}

/// Where the destination keeps each colour channel in a packed pixel, and how
/// wide that pixel is. The board's DAC drove analog RGB and knew nothing of
/// pixel formats; this is the emulated equivalent — the host states its
/// channel layout once and the card clocks pixels out in it.
///
/// Channel positions, not lookup tables: the tables this expands to are 128
/// entries built per frame, and a table-shaped `Dac` is kilobytes that then
/// have to live somewhere no kernel stack can hold them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dac {
    /// `(shift, bits)` per channel, as a packed pixel stores it.
    pub r: (u8, u8),
    pub g: (u8, u8),
    pub b: (u8, u8),
    pub bytes: u8,
}

/// The 5/6/5 component ramps for one scanout: bit-replication (what the
/// RAMDAC does to reach 8 bits), then the gamma CLUT, then the destination
/// encoding — 128 entries total, rebuilt per frame.
pub struct DacRamps {
    pub r: [u32; 32],
    pub g: [u32; 64],
    pub b: [u32; 32],
}

impl Dac {
    /// An identity 8-8-8 destination: `0x00RRGGBB`, four bytes per pixel.
    pub const fn native() -> Dac {
        Dac { r: (16, 8), g: (8, 8), b: (0, 8), bytes: 4 }
    }

    /// One 8-bit component placed in its channel.
    #[inline]
    fn place(v: u32, (shift, bits): (u8, u8)) -> u32 {
        (v >> (8 - bits as u32)) << shift
    }

    fn ramps(&self, clut: &Clut) -> DacRamps {
        let mut ramps = DacRamps { r: [0; 32], g: [0; 64], b: [0; 32] };
        for (i, e) in ramps.r.iter_mut().enumerate() {
            let v = ((i as u32) << 3) | ((i as u32) >> 2);
            *e = Self::place(clut.component(v, 16), self.r);
        }
        for (i, e) in ramps.g.iter_mut().enumerate() {
            let v = ((i as u32) << 2) | ((i as u32) >> 4);
            *e = Self::place(clut.component(v, 8), self.g);
        }
        for (i, e) in ramps.b.iter_mut().enumerate() {
            let v = ((i as u32) << 3) | ((i as u32) >> 2);
            *e = Self::place(clut.component(v, 0), self.b);
        }
        ramps
    }
}

#[inline]
pub fn rgb565_to_rgb888(p: u16) -> u32 {
    let r = ((p >> 11) & 0x1f) as u32;
    let g = ((p >> 5) & 0x3f) as u32;
    let b = (p & 0x1f) as u32;
    // Replicate the high bits into the low ones, as the RAMDAC does.
    let r = (r << 3) | (r >> 2);
    let g = (g << 2) | (g >> 4);
    let b = (b << 3) | (b >> 2);
    (r << 16) | (g << 8) | b
}

#[inline]
pub fn read_pixel(fb: &[u8], byte_off: usize) -> u16 {
    if byte_off + 1 < fb.len() {
        u16::from_le_bytes([fb[byte_off], fb[byte_off + 1]])
    } else {
        0
    }
}

#[inline]
pub fn write_pixel(fb: &mut [u8], byte_off: usize, v: u16) {
    if byte_off + 1 < fb.len() {
        fb[byte_off..byte_off + 2].copy_from_slice(&v.to_le_bytes());
    }
}

/// The RAMDAC colour lookup table (`clutData`, 33 entries), which the SST-1
/// applies to everything it scans out.
///
/// MAME expands it into a 5-6-5 pen table; we interpolate on the fly instead,
/// for the same reason the texel tables are computed rather than stored — a
/// 64K-entry pen table is not something to carry into a kernel for a handful
/// of multiplies per pixel.
#[derive(Debug, Clone)]
pub struct Clut {
    entries: [u32; 33],
    /// Set while the CLUT is the identity, which lets scanout skip it.
    identity: bool,
}

impl Default for Clut {
    fn default() -> Self {
        Self::new()
    }
}

impl Clut {
    pub fn new() -> Self {
        let mut entries = [0u32; 33];
        for (pen, e) in entries.iter_mut().enumerate().take(32) {
            let v = ((pen as u32) << 3) | ((pen as u32) >> 2);
            *e = (v << 16) | (v << 8) | v;
        }
        entries[32] = 0x00ff_ffff;
        Self { entries, identity: true }
    }

    /// `reg_clut_w` — index in bits 24-31, colour in the low 24.
    pub fn write(&mut self, data: u32) {
        let index = ((data >> 24) & 0xff) as usize;
        if index <= 32 {
            self.entries[index] = data & 0xff_ffff;
            self.identity = false;
        }
    }

    /// Interpolate one component between the two CLUT entries that bracket it.
    #[inline]
    fn interp(&self, color: u32, shift: u32) -> u32 {
        // Some games write 0 to the last entry when they mean 0xff.
        let last = if self.entries[32] == 0 && self.entries[31] != 0 {
            0x00ff_ffff
        } else {
            self.entries[32]
        };
        let at = |i: usize| -> u32 {
            let e = if i >= 32 { last } else { self.entries[i] };
            (e >> shift) & 0xff
        };
        let i = (color >> 3) as usize;
        let frac = color & 7;
        (at(i) * (8 - frac) + at(i + 1) * frac) >> 3
    }

    /// One 8-bit component after the gamma CLUT. `shift` selects the channel
    /// (16/8/0), matching the CLUT entries' 8-8-8 layout.
    #[inline]
    pub fn component(&self, v: u32, shift: u32) -> u32 {
        if self.identity { v } else { self.interp(v, shift) }
    }

    /// The 8-8-8 colour a 5-6-5 framebuffer pixel scans out as.
    #[inline]
    pub fn pen(&self, p: u16) -> u32 {
        if self.identity {
            return rgb565_to_rgb888(p);
        }
        let raw = rgb565_to_rgb888(p);
        let r = self.interp((raw >> 16) & 0xff, 16);
        let g = self.interp((raw >> 8) & 0xff, 8);
        let b = self.interp(raw & 0xff, 0);
        (r << 16) | (g << 8) | b
    }
}
