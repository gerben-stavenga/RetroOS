//! Linear frame buffer window: the guest writing pixels straight into video
//! memory (`lfb_w` / `lfb_r` in the C).
//!
//! This is the path every 3D game uses for 2D work — menus, the console,
//! software-decoded video — so it is worth having before a single triangle is
//! rasterized.

use crate::fbi::{Fbi, read_pixel, write_pixel};
use crate::raster::{Dither, FogTable, Poly, Stats, pixel_pipeline};
use crate::regs::*;
use crate::rgba::Rgba;

pub const LFB_RGB_PRESENT: u32 = 1;
pub const LFB_ALPHA_PRESENT: u32 = 2;
pub const LFB_DEPTH_PRESENT: u32 = 4;
pub const LFB_DEPTH_PRESENT_MSW: u32 = 8;

#[derive(Default, Clone, Copy)]
struct Source {
    r: u32,
    g: u32,
    b: u32,
    a: u32,
    w: u32,
}

#[inline]
fn e565(v: u32) -> (u32, u32, u32) {
    let (r, g, b) = ((v >> 11) & 0x1f, (v >> 5) & 0x3f, v & 0x1f);
    ((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2))
}

#[inline]
fn ex555(v: u32) -> (u32, u32, u32) {
    let (r, g, b) = ((v >> 10) & 0x1f, (v >> 5) & 0x1f, v & 0x1f);
    ((r << 3) | (r >> 2), (g << 3) | (g >> 2), (b << 3) | (b >> 2))
}

#[inline]
fn e555x(v: u32) -> (u32, u32, u32) {
    ex555(v >> 1)
}

#[inline]
fn e1555(v: u32) -> (u32, u32, u32, u32) {
    let (r, g, b) = ex555(v);
    (if (v >> 15) & 1 != 0 { 0xff } else { 0 }, r, g, b)
}

#[inline]
fn e5551(v: u32) -> (u32, u32, u32, u32) {
    let (r, g, b) = e555x(v);
    (r, g, b, if v & 1 != 0 { 0xff } else { 0 })
}

/// Decode the written dword into up to two source pixels.
///
/// Returns `(mask, sources, is_16bit)`; `is_16bit` means the LFB offset
/// addresses 16-bit pixels and must be doubled (`offset <<= 1` in the C).
fn decode(lfb_mode: u32, za: u32, data: u32) -> (u32, [Source; 2], bool) {
    let mut s = [Source::default(); 2];
    // Default depth and alpha come from zaColor.
    s[0].w = za & 0xffff;
    s[1].w = s[0].w;
    s[0].a = za >> 24;
    s[1].a = s[0].a;

    let fmt = lfbmode_write_format(lfb_mode);
    let lanes = lfbmode_rgba_lanes(lfb_mode);
    // Lanes 1 and 3 (ABGR/BGRA) swap the R and B channels.
    let swap_rb = lanes == 1 || lanes == 3;
    // Lanes 2 and 3 (RGBA/BGRA) put alpha in the low bits of 5-5-5-1 forms.
    let alpha_low = lanes >= 2;

    let both = LFB_RGB_PRESENT | (LFB_RGB_PRESENT << 4);

    let (mask, is16) = match fmt {
        // 16-bit RGB 5-6-5
        0 => {
            let (r0, g0, b0) = e565(data & 0xffff);
            let (r1, g1, b1) = e565(data >> 16);
            (s[0].r, s[0].g, s[0].b) = (r0, g0, b0);
            (s[1].r, s[1].g, s[1].b) = (r1, g1, b1);
            (both, true)
        }
        // 16-bit RGB x-5-5-5 / 5-5-5-x
        1 => {
            let f = if alpha_low { e555x } else { ex555 };
            let (r0, g0, b0) = f(data & 0xffff);
            let (r1, g1, b1) = f(data >> 16);
            (s[0].r, s[0].g, s[0].b) = (r0, g0, b0);
            (s[1].r, s[1].g, s[1].b) = (r1, g1, b1);
            (both, true)
        }
        // 16-bit ARGB 1-5-5-5 / 5-5-5-1
        2 => {
            for (i, half) in [data & 0xffff, data >> 16].into_iter().enumerate() {
                let (a, r, g, b) = if alpha_low {
                    let (r, g, b, a) = e5551(half);
                    (a, r, g, b)
                } else {
                    e1555(half)
                };
                (s[i].a, s[i].r, s[i].g, s[i].b) = (a, r, g, b);
            }
            (
                LFB_RGB_PRESENT
                    | LFB_ALPHA_PRESENT
                    | ((LFB_RGB_PRESENT | LFB_ALPHA_PRESENT) << 4),
                true,
            )
        }
        // 32-bit RGB x-8-8-8 / 8-8-8-x
        4 => {
            let v = if alpha_low { data >> 8 } else { data };
            (s[0].r, s[0].g, s[0].b) = ((v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
            (LFB_RGB_PRESENT, false)
        }
        // 32-bit ARGB 8-8-8-8 / RGBA 8-8-8-8
        5 => {
            if alpha_low {
                s[0].a = data & 0xff;
                (s[0].r, s[0].g, s[0].b) =
                    ((data >> 24) & 0xff, (data >> 16) & 0xff, (data >> 8) & 0xff);
            } else {
                s[0].a = (data >> 24) & 0xff;
                (s[0].r, s[0].g, s[0].b) =
                    ((data >> 16) & 0xff, (data >> 8) & 0xff, data & 0xff);
            }
            (LFB_RGB_PRESENT | LFB_ALPHA_PRESENT, false)
        }
        // 32-bit depth + RGB 5-6-5
        12 => {
            s[0].w = data >> 16;
            let (r, g, b) = e565(data & 0xffff);
            (s[0].r, s[0].g, s[0].b) = (r, g, b);
            (LFB_RGB_PRESENT | LFB_DEPTH_PRESENT_MSW, false)
        }
        // 32-bit depth + RGB x-5-5-5
        13 => {
            s[0].w = data >> 16;
            let (r, g, b) = if alpha_low { e555x(data & 0xffff) } else { ex555(data & 0xffff) };
            (s[0].r, s[0].g, s[0].b) = (r, g, b);
            (LFB_RGB_PRESENT | LFB_DEPTH_PRESENT_MSW, false)
        }
        // 32-bit depth + ARGB 1-5-5-5
        14 => {
            s[0].w = data >> 16;
            let (a, r, g, b) = if alpha_low {
                let (r, g, b, a) = e5551(data & 0xffff);
                (a, r, g, b)
            } else {
                e1555(data & 0xffff)
            };
            (s[0].a, s[0].r, s[0].g, s[0].b) = (a, r, g, b);
            (
                LFB_RGB_PRESENT | LFB_ALPHA_PRESENT | LFB_DEPTH_PRESENT_MSW,
                false,
            )
        }
        // 16-bit depth
        15 => {
            s[0].w = data & 0xffff;
            s[1].w = data >> 16;
            (LFB_DEPTH_PRESENT | (LFB_DEPTH_PRESENT << 4), true)
        }
        _ => (0, false),
    };

    if swap_rb {
        for p in &mut s {
            core::mem::swap(&mut p.r, &mut p.b);
        }
    }
    (mask, s, is16)
}

/// `lfb_w` — a guest dword written into the LFB window.
///
/// `offset` is the dword offset within the LFB aperture; `mem_mask` marks
/// which bytes of `data` the guest actually wrote. `poly` carries the
/// register snapshot the pixel-pipeline path needs; the raw path ignores all
/// but its buffer offsets.
#[allow(clippy::too_many_arguments)]
pub fn write(
    fbi: &Fbi,
    reg: &mut [u32],
    fb: &mut [u8],
    offset: u32,
    data: u32,
    mem_mask: u32,
    poly: &Poly,
    fog: &FogTable,
) -> Stats {
    let mut stats = Stats::default();
    let lfb_mode = reg[lfbMode];

    let mut data = data;
    let mut mem_mask = mem_mask;
    if lfbmode_byte_swizzle_writes(lfb_mode) {
        data = data.swap_bytes();
        mem_mask = mem_mask.swap_bytes();
    }
    if lfbmode_word_swap_writes(lfb_mode) {
        data = data.rotate_left(16);
        mem_mask = mem_mask.rotate_left(16);
    }

    let (mut mask, src, is16) = decode(lfb_mode, reg[zaColor], data);
    if mask == 0 {
        return stats;
    }
    let offset = if is16 { offset << 1 } else { offset };

    let mut x = (offset & 0x3ff) as i32;
    let y = ((offset >> 10) & 0x3ff) as i32;

    // Drop the halves the guest did not write.
    if mem_mask & 0x0000_ffff == 0 {
        mask &= !(0x0f - LFB_DEPTH_PRESENT_MSW);
    }
    if mem_mask & 0xffff_0000 == 0 {
        mask &= !(0xf0 + LFB_DEPTH_PRESENT_MSW);
    }

    let Some((dest, destmax)) = fbi.color_buffer(lfbmode_write_buffer_select(lfb_mode)) else {
        return stats;
    };
    let (depth, depthmax) = fbi
        .color_buffer(2)
        .map_or((None, 0), |(o, m)| (Some(o), m));

    // The raw path takes its Y origin from lfbMode, the pipelined path from
    // fbzMode — the hardware really does read two different bits here.
    let pipelined = lfbmode_enable_pixel_pipeline(lfb_mode);
    let flip = if pipelined {
        fbzmode_y_origin(reg[fbzMode])
    } else {
        lfbmode_y_origin(lfb_mode)
    };
    let scry = if flip { (fbi.yorigin as i32) - y } else { y };
    if scry < 0 {
        return stats;
    }

    if pipelined {
        // Run each written pixel through the full pipeline, drawing into the
        // buffer lfbMode selected rather than the one fbzMode would.
        let mut poly = poly.clone();
        poly.destbase = dest;
        poly.depthbase = depth;
        let mut pix = 0;
        while mask != 0 {
            if mask & 0x0f != 0 {
                let s = src[pix.min(1)];
                pixel_pipeline(
                    &poly,
                    x,
                    scry,
                    Rgba::new(s.a as i32, s.r as i32, s.g as i32, s.b as i32),
                    s.w as u16,
                    fb,
                    fog,
                    &mut stats,
                );
            }
            x += 1;
            mask >>= 4;
            pix += 1;
        }
        reg[fbiPixelsIn] = reg[fbiPixelsIn].wrapping_add(stats.pixels_in);
        reg[fbiPixelsOut] = reg[fbiPixelsOut].wrapping_add(stats.pixels_out);
        reg[fbiChromaFail] = reg[fbiChromaFail].wrapping_add(stats.chroma_fail);
        reg[fbiZfuncFail] = reg[fbiZfuncFail].wrapping_add(stats.zfunc_fail);
        reg[fbiAfuncFail] = reg[fbiAfuncFail].wrapping_add(stats.afunc_fail);
        return stats;
    }

    // Raw path: no pipeline, but the write is still dithered.
    let dither = Dither::new(scry, reg[fbzMode]);
    let alpha_planes = fbzmode_enable_alpha_planes(reg[fbzMode]);
    let mut bufoffs = scry * fbi.rowpixels as i32 + x;
    let mut pix = 0;
    while mask != 0 {
        if mask & 0x0f != 0 {
            let s = src[pix.min(1)];
            let has_rgb = mask & LFB_RGB_PRESENT != 0;
            let has_alpha = mask & LFB_ALPHA_PRESENT != 0;
            let has_depth = mask & (LFB_DEPTH_PRESENT | LFB_DEPTH_PRESENT_MSW) != 0;

            if has_rgb && (bufoffs as u32) < destmax {
                let c = Rgba::new(s.a as i32, s.r as i32, s.g as i32, s.b as i32);
                write_pixel(fb, dest as usize + bufoffs as usize * 2, dither.pixel(x, c));
            }
            if let Some(depth) = depth {
                if (bufoffs as u32) < depthmax {
                    if alpha_planes {
                        if has_alpha {
                            write_pixel(fb, depth as usize + bufoffs as usize * 2, s.a as u16);
                        }
                    } else if has_depth {
                        write_pixel(fb, depth as usize + bufoffs as usize * 2, s.w as u16);
                    }
                }
            }
            reg[fbiPixelsOut] = reg[fbiPixelsOut].wrapping_add(1);
            stats.pixels_out += 1;
        }
        bufoffs += 1;
        x += 1;
        mask >>= 4;
        pix += 1;
    }
    stats
}

/// `lfb_r` — a guest dword read from the LFB window.
pub fn read(fbi: &Fbi, reg: &[u32], fb: &[u8], offset: u32) -> u32 {
    let lfb_mode = reg[lfbMode];

    let x = ((offset << 1) & 0x3fe) as usize;
    let y = ((offset >> 9) & 0x3ff) as usize;

    let Some((base, bufmax)) = fbi.color_buffer(lfbmode_read_buffer_select(lfb_mode)) else {
        return 0xffff_ffff;
    };

    let scry = if lfbmode_y_origin(lfb_mode) {
        (fbi.yorigin as usize).wrapping_sub(y) & 0x3ff
    } else {
        y
    };

    let bufoffs = scry * fbi.rowpixels as usize + x;
    if bufoffs as u32 >= bufmax {
        return 0xffff_ffff;
    }

    let lo = read_pixel(fb, base as usize + bufoffs * 2) as u32;
    let hi = read_pixel(fb, base as usize + (bufoffs + 1) * 2) as u32;
    let mut data = lo | (hi << 16);

    if lfbmode_word_swap_reads(lfb_mode) {
        data = data.rotate_left(16);
    }
    if lfbmode_byte_swizzle_reads(lfb_mode) {
        data = data.swap_bytes();
    }
    data
}
