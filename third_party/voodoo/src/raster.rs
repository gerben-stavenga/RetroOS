//! The rasterizer: triangle setup, span walking and the per-pixel pipeline.
//!
//! Ported from Aaron Giles' `voodoo_renderer` in MAME's `voodoo_render.cpp`
//! (BSD-3-Clause). The stage order and every mode decode follow the C:
//! stipple → depth → texture → colour combine → alpha test → fog → alpha
//! blend → write.
//!
//! Two things differ deliberately, both about ownership rather than about the
//! hardware:
//!
//!  - Framebuffer and texture memory are `&[u8]` / `&mut [u8]` arguments, so
//!    the buffers are byte offsets and every access is bounds-checked against
//!    the slice the host handed in.
//!  - `Poly` is a plain value holding everything one triangle needs. Nothing
//!    is read from a register mid-triangle, which is what makes a span a pure
//!    function of `(Poly, y)` — the property that lets spans be split across
//!    cores, or expressed as a kernel, without touching this file.

use crate::fbi::{read_pixel, rgb565_to_rgb888, write_pixel};
use crate::regs::*;
use crate::rgba::Rgba;
use crate::texture::{Texture, compute_lodbase};

const DITHER_MATRIX_4X4: [i32; 16] = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];
const DITHER_MATRIX_2X2: [i32; 16] = [8, 10, 8, 10, 11, 9, 11, 9, 8, 10, 8, 10, 11, 9, 11, 9];

/// Per-scanline dithering state (`dither_helper`).
#[derive(Clone, Copy)]
pub struct Dither {
    row: Option<[i32; 4]>,
    row_4x4: [i32; 4],
}

impl Dither {
    pub fn new(y: i32, fbzmode: u32) -> Self {
        let yi = (y & 3) as usize * 4;
        let raw_4x4 = [
            DITHER_MATRIX_4X4[yi],
            DITHER_MATRIX_4X4[yi + 1],
            DITHER_MATRIX_4X4[yi + 2],
            DITHER_MATRIX_4X4[yi + 3],
        ];
        let row = if !fbzmode_enable_dithering(fbzmode) {
            None
        } else if fbzmode_dither_type(fbzmode) == 0 {
            Some(raw_4x4)
        } else {
            Some([
                DITHER_MATRIX_2X2[yi],
                DITHER_MATRIX_2X2[yi + 1],
                DITHER_MATRIX_2X2[yi + 2],
                DITHER_MATRIX_2X2[yi + 3],
            ])
        };
        Self { row, row_4x4: raw_4x4 }
    }

    // Hardware-verified dither equations.
    #[inline]
    fn rb(value: i32, dither: i32) -> u16 {
        (((value << 1) - (value >> 4) + (value >> 7) + dither) >> 4) as u16
    }

    #[inline]
    fn g(value: i32, dither: i32) -> u16 {
        (((value << 2) - (value >> 4) + (value >> 6) + dither) >> 4) as u16
    }

    /// Dither a colour and pack it as 5-6-5.
    #[inline]
    pub fn pixel(&self, x: i32, c: Rgba) -> u16 {
        match self.row {
            None => (((c.r >> 3) << 11) | ((c.g >> 2) << 5) | (c.b >> 3)) as u16,
            Some(row) => {
                let d = row[(x & 3) as usize];
                (Self::rb(c.r, d) << 11) | (Self::g(c.g, d) << 5) | Self::rb(c.b, d)
            }
        }
    }

    #[inline]
    pub fn raw_4x4(&self, x: i32) -> i32 {
        self.row_4x4[(x & 3) as usize]
    }

    /// The subtractive dither value used by alpha blending.
    #[inline]
    pub fn subtract(&self, x: i32) -> i32 {
        match self.row {
            None => 0,
            Some(row) => (15 - row[(x & 3) as usize]) >> 1,
        }
    }
}

/// `compute_wfloat` — the pseudo-float form of iterated W, used for depth and
/// fog.
#[inline]
pub fn compute_wfloat(iterw: i64) -> i32 {
    let exp = (iterw as u64).leading_zeros() as i32 - 16;
    if exp < 0 {
        return 0x0000;
    }
    if exp >= 16 {
        return 0xffff;
    }
    (((exp << 12) | (((iterw >> (35 - exp)) as i32) ^ 0x1fff)) as i32) + 1
}

/// `clamped_z` — real clamp, or the pseudo-clamp the manual documents.
#[inline]
pub fn clamped_z(iterz: i32, fbzcp: u32) -> i32 {
    if fbzcp_rgbzw_clamp(fbzcp) {
        return (iterz >> 12).clamp(0, 0xffff);
    }
    let result = (iterz as u32) >> 12;
    if result == 0xfffff {
        0
    } else if result == 0x10000 {
        0xffff
    } else {
        (result & 0xffff) as i32
    }
}

/// `clamped_w`.
#[inline]
pub fn clamped_w(iterw: i64, fbzcp: u32) -> i32 {
    if fbzcp_rgbzw_clamp(fbzcp) {
        return ((iterw >> 48) as i32).clamp(0, 0xff);
    }
    let result = ((iterw as u64) >> 48) as u32;
    if result == 0xffff {
        0
    } else if result == 0x100 {
        0xff
    } else {
        (result & 0xff) as i32
    }
}

/// `clamped_argb` — clamp iterated colour, or apply the pseudo-clamp.
#[inline]
pub fn clamped_argb(iter: Rgba, fbzcp: u32) -> Rgba {
    let shr = |v: i32| v >> 20;
    let mut r = Rgba::new(shr(iter.a), shr(iter.r), shr(iter.g), shr(iter.b));
    if fbzcp_rgbzw_clamp(fbzcp) {
        r.clamp_to_u8();
        return r;
    }
    // result = val & 0xfff; 0xfff becomes 0, 0x100 becomes 0xff.
    let fix = |v: i32| -> i32 {
        let v = v & 0xfff;
        if v == 0xfff {
            0
        } else if v == 0x100 {
            0xff
        } else {
            v & 0xff
        }
    };
    Rgba::new(fix(r.a), fix(r.r), fix(r.g), fix(r.b))
}

/// Everything one triangle needs, snapshotted from the registers at command
/// time (`poly_data`). Iterated values are the plane equations, evaluated
/// per-pixel from the A vertex.
#[derive(Debug, Default, Clone)]
pub struct Poly {
    pub destbase: u32,
    pub depthbase: Option<u32>,
    pub rowpixels: i32,
    pub yorigin: i32,

    pub clipleft: i32,
    pub clipright: i32,
    pub cliptop: i32,
    pub clipbottom: i32,

    pub ax: i32,
    pub ay: i32,
    pub startr: i32,
    pub startg: i32,
    pub startb: i32,
    pub starta: i32,
    pub startz: i32,
    pub startw: i64,
    pub drdx: i32,
    pub dgdx: i32,
    pub dbdx: i32,
    pub dadx: i32,
    pub dzdx: i32,
    pub dwdx: i64,
    pub drdy: i32,
    pub dgdy: i32,
    pub dbdy: i32,
    pub dady: i32,
    pub dzdy: i32,
    pub dwdy: i64,

    /// Per-TMU iterated S/T/W, `[tmu0, tmu1]`.
    pub tex: [Option<TexIter>; 2],

    pub color0: u32,
    pub color1: u32,
    pub chromakey: u32,
    pub chromarange: u32,
    pub fogcolor: u32,
    pub zacolor: u32,
    pub stipple: u32,
    pub alpharef: u32,

    /// `lfbMode.write_w_select`, which the LFB fog path consults.
    pub lfb_write_w_select: bool,

    pub fbzcp: u32,
    pub fbzmode: u32,
    pub alphamode: u32,
    pub fogmode: u32,
    pub texmode: [u32; 2],
}

/// Iterated texture coordinates for one TMU.
#[derive(Debug, Default, Clone, Copy)]
pub struct TexIter {
    pub starts: i64,
    pub startt: i64,
    pub startw: i64,
    pub dsdx: i64,
    pub dtdx: i64,
    pub dwdx: i64,
    pub dsdy: i64,
    pub dtdy: i64,
    pub dwdy: i64,
}

/// What the rasterizer counted, folded back into the statistics registers by
/// the caller.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub pixels_in: u32,
    pub pixels_out: u32,
    pub chroma_fail: u32,
    pub zfunc_fail: u32,
    pub afunc_fail: u32,
}

/// The tables `fogTable` fills in, kept next to the FBI registers.
#[derive(Debug, Clone, Copy)]
pub struct FogTable {
    pub blend: [u8; 64],
    pub delta: [u8; 64],
}

impl Default for FogTable {
    fn default() -> Self {
        Self { blend: [0; 64], delta: [0; 64] }
    }
}

/// Everything the pipeline may read but does not own.
pub struct Scene<'a> {
    pub fb: &'a mut [u8],
    pub tex_ram: [&'a [u8]; 2],
    pub textures: [&'a Texture; 2],
    pub fog: &'a FogTable,
    pub bilinear_mask: i32,
}

/// Rasterize one triangle. `verts` are the three vertices in 12.4 fixed point
/// (the `vertexA/B/C` registers).
pub fn draw_triangle(poly: &Poly, verts: [(i32, i32); 3], scene: &mut Scene<'_>) -> Stats {
    let mut stats = Stats::default();

    // Sort by Y; the edge walk needs top, middle, bottom.
    let mut v = [
        (verts[0].0 as f32 / 16.0, verts[0].1 as f32 / 16.0),
        (verts[1].0 as f32 / 16.0, verts[1].1 as f32 / 16.0),
        (verts[2].0 as f32 / 16.0, verts[2].1 as f32 / 16.0),
    ];
    // Three-element insertion sort; `slice::sort_by` lives in `alloc`.
    if v[0].1 > v[1].1 {
        v.swap(0, 1);
    }
    if v[1].1 > v[2].1 {
        v.swap(1, 2);
    }
    if v[0].1 > v[1].1 {
        v.swap(0, 1);
    }
    let (v1, v2, v3) = (v[0], v[1], v[2]);

    let starty = round_coordinate(v1.1);
    let stopy = round_coordinate(v3.1);
    if stopy <= starty {
        return stats;
    }

    let dxdy_v1v2 = if v2.1 == v1.1 { 0.0 } else { (v2.0 - v1.0) / (v2.1 - v1.1) };
    let dxdy_v1v3 = if v3.1 == v1.1 { 0.0 } else { (v3.0 - v1.0) / (v3.1 - v1.1) };
    let dxdy_v2v3 = if v3.1 == v2.1 { 0.0 } else { (v3.0 - v2.0) / (v3.1 - v2.1) };

    for y in starty..stopy {
        let fully = y as f32 + 0.5;
        let (mut startx, mut stopx) = if fully < v2.1 {
            (v1.0 + (fully - v1.1) * dxdy_v1v2, v1.0 + (fully - v1.1) * dxdy_v1v3)
        } else {
            (v2.0 + (fully - v2.1) * dxdy_v2v3, v1.0 + (fully - v1.1) * dxdy_v1v3)
        };
        if startx > stopx {
            core::mem::swap(&mut startx, &mut stopx);
        }
        rasterize_span(poly, y, round_coordinate(startx), round_coordinate(stopx), scene, &mut stats);
    }
    stats
}

/// MAME's `round_coordinate`: floor, then round up past the half.
#[inline]
fn round_coordinate(value: f32) -> i32 {
    let result = libm_floor(value) as i32;
    result + ((value - result as f32 > 0.5) as i32)
}

#[inline]
fn libm_floor(v: f32) -> f32 {
    // no_std floor for the values we see here (well inside i32 range).
    let t = v as i32 as f32;
    if v < 0.0 && t != v { t - 1.0 } else { t }
}

/// One scanline of one triangle (`voodoo_renderer::rasterizer`).
pub fn rasterize_span(
    poly: &Poly,
    y: i32,
    startx: i32,
    stopx: i32,
    scene: &mut Scene<'_>,
    stats: &mut Stats,
) {
    let fbzmode = poly.fbzmode;
    let fbzcp = poly.fbzcp;
    let alphamode = poly.alphamode;
    let fogmode = poly.fogmode;

    let scry = if fbzmode_y_origin(fbzmode) { poly.yorigin - y } else { y };

    let (mut startx, mut stopx) = (startx, stopx);
    stats.pixels_in += (stopx - startx).max(0) as u32;

    if fbzmode_enable_clipping(fbzmode) {
        if scry < poly.cliptop || scry >= poly.clipbottom {
            return;
        }
        if startx >= poly.clipright {
            return;
        }
        stopx = stopx.min(poly.clipright);
        startx = startx.max(poly.clipleft);
    }
    if scry < 0 || stopx <= startx {
        return;
    }

    // Row bases, as byte offsets into the framebuffer slice.
    let dest_row = poly.destbase as usize + (scry * poly.rowpixels) as usize * 2;
    let depth_row = poly.depthbase.map(|b| b as usize + (scry * poly.rowpixels) as usize * 2);

    // Starting parameters: the plane equations evaluated at (startx, y).
    let dx = startx - (poly.ax >> 4);
    let dy = y - (poly.ay >> 4);
    let mut iterargb = Rgba::new(
        (poly.starta + dy * poly.dady + dx * poly.dadx) << 8,
        (poly.startr + dy * poly.drdy + dx * poly.drdx) << 8,
        (poly.startg + dy * poly.dgdy + dx * poly.dgdx) << 8,
        (poly.startb + dy * poly.dbdy + dx * poly.dbdx) << 8,
    );
    let iterargb_delta = Rgba::new(poly.dadx << 8, poly.drdx << 8, poly.dgdx << 8, poly.dbdx << 8);
    let mut iterz = poly.startz + dy * poly.dzdy + dx * poly.dzdx;
    let mut iterw = (poly.startw + dy as i64 * poly.dwdy + dx as i64 * poly.dwdx) << 16;
    let iterw_delta = poly.dwdx << 16;

    // Per-TMU iterators, in doubles as the C does.
    let mut ts = [(0.0f64, 0.0f64, 0.0f64); 2];
    let mut td = [(0.0f64, 0.0f64, 0.0f64); 2];
    let mut lodbase = [0i32; 2];
    for i in 0..2 {
        if let Some(t) = poly.tex[i] {
            ts[i] = (
                (t.starts + dy as i64 * t.dsdy + dx as i64 * t.dsdx) as f64,
                (t.startt + dy as i64 * t.dtdy + dx as i64 * t.dtdx) as f64,
                (t.startw + dy as i64 * t.dwdy + dx as i64 * t.dwdx) as f64,
            );
            td[i] = (t.dsdx as f64, t.dtdx as f64, t.dwdx as f64);
            lodbase[i] = compute_lodbase(t.dsdx, t.dsdy, t.dtdx, t.dtdy);
        }
    }

    let dither = Dither::new(scry, fbzmode);
    let mut stipple_bits = poly.stipple;

    for x in startx..stopx {
        'pixel: {
            if fbzmode_enable_stipple(fbzmode) && !stipple_test(fbzmode, x, scry, &mut stipple_bits) {
                break 'pixel;
            }

            let wfloat = compute_wfloat(iterw);
            let depthval = compute_depthval(poly, fbzmode, fbzcp, wfloat, iterz);

            let depth_pixel = depth_row
                .map(|base| read_pixel(scene.fb, base + x as usize * 2) as i32)
                .unwrap_or(0);

            if fbzmode_enable_depthbuf(fbzmode) {
                let source = if fbzmode_depth_source_compare(fbzmode) {
                    (poly.zacolor & 0xffff) as i32
                } else {
                    depthval
                };
                if !depth_test(fbzmode, depth_pixel, source) {
                    stats.zfunc_fail += 1;
                    break 'pixel;
                }
            }

            // Texture pipeline: TMU1 feeds TMU0, TMU0 feeds the colour path.
            let mut texel = Rgba::default();
            for i in [1usize, 0usize] {
                if poly.tex[i].is_none() {
                    continue;
                }
                let texmode = poly.texmode[i];
                if i == 0 && texmode_seq_8_downld(texmode) {
                    // Repurposed in the rasterizer: send the config value.
                    texel = Rgba::from_argb(0x11);
                    continue;
                }
                let mut lod = lodbase[i];
                let t = scene.textures[i].fetch_texel(
                    texmode,
                    dither.raw_4x4(x) as u32,
                    ts[i].0,
                    ts[i].1,
                    ts[i].2,
                    &mut lod,
                    scene.bilinear_mask,
                    scene.tex_ram[i],
                );
                texel = scene.textures[i].combine_texture(texmode, t, texel, lod);
            }

            let mut color = clamped_argb(iterargb, fbzcp);
            if !combine_color(&mut color, poly, fbzcp, fbzmode, texel, iterz, iterw, stats) {
                break 'pixel;
            }

            if alphamode_alphatest(alphamode)
                && !alpha_test(alphamode, color.a as u32, poly.alpharef)
            {
                stats.afunc_fail += 1;
                break 'pixel;
            }

            let prefog = color;
            if fogmode_enable_fog(fogmode) {
                apply_fogging(
                    &mut color, poly, fbzmode, fogmode, fbzcp, x, &dither, wfloat, iterz, iterw,
                    iterargb, scene.fog,
                );
            }

            if alphamode_alphablend(alphamode) {
                let dpix = read_pixel(scene.fb, dest_row + x as usize * 2);
                alpha_blend(
                    &mut color, fbzmode, alphamode, x, &dither, dpix, depth_pixel, prefog,
                );
            }

            // Write colour and depth.
            if fbzmode_rgb_buffer_mask(fbzmode) {
                write_pixel(scene.fb, dest_row + x as usize * 2, dither.pixel(x, color));
            }
            if fbzmode_aux_buffer_mask(fbzmode) {
                if let Some(base) = depth_row {
                    let v = if fbzmode_enable_alpha_planes(fbzmode) {
                        color.a as u16
                    } else {
                        depthval as u16
                    };
                    write_pixel(scene.fb, base + x as usize * 2, v);
                }
            }
            stats.pixels_out += 1;
        }

        // Advance the iterated parameters.
        iterargb.add(iterargb_delta);
        iterz += poly.dzdx;
        iterw += iterw_delta;
        for i in 0..2 {
            if poly.tex[i].is_some() {
                ts[i].0 += td[i].0;
                ts[i].1 += td[i].1;
                ts[i].2 += td[i].2;
            }
        }
    }
}

#[inline]
fn stipple_test(fbzmode: u32, x: i32, scry: i32, bits: &mut u32) -> bool {
    if fbzmode_stipple_pattern(fbzmode) == 0 {
        // Rotate mode.
        *bits = bits.rotate_right(1);
        (*bits as i32) < 0
    } else {
        // Pattern mode.
        let index = ((scry & 3) << 3) | (!x & 7);
        (*bits >> index) & 1 != 0
    }
}

fn compute_depthval(poly: &Poly, fbzmode: u32, fbzcp: u32, wfloat: i32, iterz: i32) -> i32 {
    let mut result = if fbzmode_wbuffer_select(fbzmode) {
        if !fbzmode_depth_float_select(fbzmode) {
            wfloat
        } else if iterz as u32 & 0xf000_0000 != 0 {
            0x0000
        } else if iterz as u32 & 0x0fff_f000 == 0 {
            0xffff
        } else {
            let exp = (iterz as u32).leading_zeros() as i32 - 4;
            return ((exp << 12) | ((iterz >> (15 - exp)) ^ 0x1fff)) + 1;
        }
    } else {
        clamped_z(iterz, fbzcp)
    };

    if fbzmode_enable_depth_bias(fbzmode) {
        result = (result + (poly.zacolor as u16 as i16) as i32).clamp(0, 0xffff);
    }
    result
}

#[inline]
fn depth_test(fbzmode: u32, depthdest: i32, depthsource: i32) -> bool {
    match fbzmode_depth_function(fbzmode) {
        0 => false,                          // never
        1 => depthsource < depthdest,        // less than
        2 => depthsource == depthdest,       // equal
        3 => depthsource <= depthdest,       // less than or equal
        4 => depthsource > depthdest,        // greater than
        5 => depthsource != depthdest,       // not equal
        6 => depthsource >= depthdest,       // greater than or equal
        _ => true,                           // always
    }
}

#[inline]
fn alpha_test(alphamode: u32, alpha: u32, alpharef: u32) -> bool {
    match alphamode_alphafunction(alphamode) {
        0 => false,
        1 => alpha < alpharef,
        2 => alpha == alpharef,
        3 => alpha <= alpharef,
        4 => alpha > alpharef,
        5 => alpha != alpharef,
        6 => alpha >= alpharef,
        _ => true,
    }
}

/// `chroma_key_test` — false kills the pixel.
fn chroma_key_test(color: Rgba, poly: &Poly) -> bool {
    let key = Rgba::from_argb(poly.chromakey);
    let range = poly.chromarange;

    if !chromarange_enable(range) {
        // Non-range: an exact RGB match kills the pixel.
        return !(color.r == key.r && color.g == key.g && color.b == key.b);
    }

    // Range version: each channel votes, and the votes combine per the mode.
    // The bits are assembled blue-green-red, as in the C.
    let high = Rgba::from_argb(range);
    let vote = |test: i32, low: i32, high: i32, exclusive: bool| -> i32 {
        ((test >= low && test <= high) as i32) ^ (exclusive as i32)
    };
    let mut results = vote(color.b, key.b, high.b, chromarange_blue_exclusive(range));
    results <<= 1;
    results |= vote(color.g, key.g, high.g, chromarange_green_exclusive(range));
    results <<= 1;
    results |= vote(color.r, key.r, high.r, chromarange_red_exclusive(range));

    if chromarange_union_mode(range) {
        results == 0
    } else {
        results != 7
    }
}

/// `combine_color` — the colour path. Returns false when the pixel is killed
/// by chroma key or alpha mask.
#[allow(clippy::too_many_arguments)]
fn combine_color(
    color: &mut Rgba,
    poly: &Poly,
    fbzcp: u32,
    fbzmode: u32,
    texel: Rgba,
    iterz: i32,
    iterw: i64,
    stats: &mut Stats,
) -> bool {
    // c_other
    let mut c_other = match fbzcp_cc_rgbselect(fbzcp) {
        0 => *color,
        1 => texel,
        2 => Rgba::from_argb(poly.color1),
        _ => Rgba::default(),
    };

    if fbzmode_enable_chromakey(fbzmode) && !chroma_key_test(c_other, poly) {
        stats.chroma_fail += 1;
        return false;
    }

    // a_other
    match fbzcp_cc_aselect(fbzcp) {
        0 => c_other.merge_alpha(*color),
        1 => c_other.merge_alpha(texel),
        2 => c_other.a = Rgba::from_argb(poly.color1).a,
        _ => c_other.zero_alpha(),
    }

    if fbzmode_enable_alpha_mask(fbzmode) && (c_other.a & 1) == 0 {
        return false;
    }

    // c_local
    let mut c_local = if !fbzcp_cc_localselect_override(fbzcp) {
        if fbzcp_cc_localselect(fbzcp) == 0 {
            *color
        } else {
            Rgba::from_argb(poly.color0)
        }
    } else if texel.a & 0x80 == 0 {
        *color
    } else {
        Rgba::from_argb(poly.color0)
    };

    // a_local
    match fbzcp_cca_localselect(fbzcp) {
        1 => c_local.a = Rgba::from_argb(poly.color0).a,
        2 => c_local.a = (clamped_z(iterz, fbzcp) >> 8) & 0xff,
        3 => c_local.a = clamped_w(iterw, fbzcp) & 0xff,
        _ => c_local.merge_alpha(*color),
    }

    // Zero or c_other / a_other.
    let mut blend_color = if fbzcp_cc_zero_other(fbzcp) { Rgba::default() } else { c_other };
    if fbzcp_cca_zero_other(fbzcp) {
        blend_color.zero_alpha();
    } else {
        blend_color.merge_alpha(c_other);
    }

    // Subtract c_local / a_local.
    if fbzcp_cc_sub_clocal(fbzcp) || fbzcp_cca_sub_clocal(fbzcp) {
        let mut sub_val = if fbzcp_cc_sub_clocal(fbzcp) { c_local } else { Rgba::default() };
        if fbzcp_cca_sub_clocal(fbzcp) {
            sub_val.merge_alpha(c_local);
        } else {
            sub_val.zero_alpha();
        }
        blend_color.sub(sub_val);
    }

    // Blend factor, RGB then alpha.
    let mut blend_factor = match fbzcp_cc_mselect(fbzcp) {
        1 => c_local,
        2 => c_other.select_alpha(),
        3 => c_local.select_alpha(),
        4 => texel.select_alpha(),
        5 => texel,
        _ => Rgba::default(),
    };
    match fbzcp_cca_mselect(fbzcp) {
        1 | 3 => blend_factor.merge_alpha(c_local),
        2 => blend_factor.merge_alpha(c_other),
        4 => blend_factor.merge_alpha(texel),
        _ => blend_factor.zero_alpha(),
    }

    if !fbzcp_cc_reverse_blend(fbzcp) {
        blend_factor.xor_imm(0, 0xff, 0xff, 0xff);
    }
    if !fbzcp_cca_reverse_blend(fbzcp) {
        blend_factor.xor_imm(0xff, 0, 0, 0);
    }

    let mut add_val = match fbzcp_cc_add_aclocal(fbzcp) {
        1 => c_local,
        2 => c_local.select_alpha(),
        _ => Rgba::default(),
    };
    if fbzcp_cca_add_aclocal(fbzcp) {
        add_val.merge_alpha(c_local);
    } else {
        add_val.zero_alpha();
    }

    blend_factor.add_imm(1);
    blend_color.scale_add_and_clamp(blend_factor, add_val);

    if fbzcp_cca_invert_output(fbzcp) {
        blend_color.xor_imm(0xff, 0, 0, 0);
    }
    if fbzcp_cc_invert_output(fbzcp) {
        blend_color.xor_imm(0, 0xff, 0xff, 0xff);
    }

    *color = blend_color;
    true
}

#[allow(clippy::too_many_arguments)]
fn apply_fogging(
    color: &mut Rgba,
    poly: &Poly,
    fbzmode: u32,
    fogmode: u32,
    fbzcp: u32,
    x: i32,
    dither: &Dither,
    wfloat: i32,
    iterz: i32,
    iterw: i64,
    iterargb: Rgba,
    fog: &FogTable,
) {
    let mut fog_color = Rgba::from_argb(poly.fogcolor);

    if fogmode_fog_constant(fogmode) {
        if !fogmode_fog_mult(fogmode) {
            fog_color.add(*color);
            fog_color.clamp_to_u8();
        }
    } else {
        if fogmode_fog_add(fogmode) {
            fog_color.zero_rgb();
            fog_color.zero_alpha();
        }
        if !fogmode_fog_mult(fogmode) {
            fog_color.sub(*color);
        }

        let mut fogblend = match fogmode_fog_zalpha(fogmode) {
            0 => {
                let mut fog_depth = wfloat;
                if fbzmode_enable_depth_bias(fbzmode) {
                    fog_depth =
                        (fog_depth + (poly.zacolor as u16 as i16) as i32).clamp(0, 0xffff);
                }
                let idx = ((fog_depth >> 10) & 63) as usize;
                let delta = fog.delta[idx] as i32;
                // The SST-1 masks the low bits of the delta.
                let mut deltaval = (delta & 0xfc) * ((fog_depth >> 2) & 0xff);
                if fogmode_fog_zones(fogmode) && (delta & 2) != 0 {
                    deltaval = -deltaval;
                }
                deltaval >>= 6;
                if fogmode_fog_dither(fogmode) {
                    deltaval += dither.raw_4x4(x);
                }
                deltaval >>= 4;
                fog.blend[idx] as i32 + deltaval
            }
            1 => iterargb.a,
            2 => clamped_z(iterz, fbzcp) >> 8,
            _ => clamped_w(iterw, fbzcp),
        };

        fogblend += 1;
        fog_color.scale_imm_and_clamp(fogblend);
        if !fogmode_fog_mult(fogmode) {
            fog_color.add(*color);
            fog_color.clamp_to_u8();
        }
    }

    fog_color.merge_alpha(*color);
    *color = fog_color;
}

#[allow(clippy::too_many_arguments)]
fn alpha_blend(
    color: &mut Rgba,
    fbzmode: u32,
    alphamode: u32,
    x: i32,
    dither: &Dither,
    dpix: u16,
    depth_pixel: i32,
    prefog: Rgba,
) {
    let mut dst_color = Rgba::from_argb(rgb565_to_rgb888(dpix));
    let mut da = 0xff;
    if fbzmode_enable_alpha_planes(fbzmode) {
        da = depth_pixel & 0xff;
        dst_color.a = da;
    }

    if fbzmode_alpha_dither_subtract(fbzmode) {
        let dith = dither.subtract(x);
        dst_color.r += dith;
        dst_color.g += dith >> 1;
        dst_color.b += dith;
    }

    let sa = color.a;
    let mut src_scale = match alphamode_srcrgbblend(alphamode) {
        1 => Rgba::splat(sa + 1),
        2 => {
            let mut s = dst_color;
            s.add_imm(1);
            s
        }
        3 => Rgba::splat(da + 1),
        4 => Rgba::splat(256),
        5 => Rgba::splat(0x100 - sa),
        6 => {
            let mut s = Rgba::splat(0x100);
            s.sub(dst_color);
            s
        }
        7 => Rgba::splat(0x100 - da),
        15 => Rgba::splat(sa.min(0x100 - da) + 1),
        _ => Rgba::default(),
    };
    src_scale.a = if alphamode_srcalphablend(alphamode) == 4 { 256 } else { 0 };

    let mut dst_scale = match alphamode_dstrgbblend(alphamode) {
        1 => Rgba::splat(sa + 1),
        2 => {
            let mut s = *color;
            s.add_imm(1);
            s
        }
        3 => Rgba::splat(da + 1),
        4 => Rgba::splat(256),
        5 => Rgba::splat(0x100 - sa),
        6 => {
            let mut s = Rgba::splat(0x100);
            s.sub(*color);
            s
        }
        7 => Rgba::splat(0x100 - da),
        15 => {
            let mut s = prefog;
            s.add_imm(1);
            s
        }
        _ => Rgba::default(),
    };
    dst_scale.a = if alphamode_dstalphablend(alphamode) == 4 { 256 } else { 0 };

    color.scale2_add_and_clamp(src_scale, dst_color, dst_scale);
}

/// `pixel_pipeline` — one LFB-written pixel run through the full pipeline.
///
/// This is the `lfbMode.enable_pixel_pipeline()` path: the guest supplies the
/// colour and depth instead of the iterators, and everything downstream of the
/// colour combine still applies.
#[allow(clippy::too_many_arguments)]
pub fn pixel_pipeline(
    poly: &Poly,
    x: i32,
    scry: i32,
    src_color: Rgba,
    sz: u16,
    fb: &mut [u8],
    fog: &FogTable,
    stats: &mut Stats,
) {
    let fbzmode = poly.fbzmode;
    stats.pixels_in += 1;

    if fbzmode_enable_clipping(fbzmode)
        && (x < poly.clipleft || x >= poly.clipright || scry < poly.cliptop
            || scry >= poly.clipbottom)
    {
        return;
    }

    if fbzmode_enable_stipple(fbzmode) {
        let mut bits = poly.stipple;
        if !stipple_test(fbzmode, x, scry, &mut bits) {
            return;
        }
    }

    let dest_row = poly.destbase as usize + (scry * poly.rowpixels) as usize * 2;
    let depth_row = poly.depthbase.map(|b| b as usize + (scry * poly.rowpixels) as usize * 2);

    // Depth for LFB writes comes straight from the written data: no bias.
    let depthval = sz as i32;
    let depth_pixel = depth_row
        .map(|base| read_pixel(fb, base + x as usize * 2) as i32)
        .unwrap_or(0);

    if fbzmode_enable_depthbuf(fbzmode) {
        let source = if fbzmode_depth_source_compare(fbzmode) {
            (poly.zacolor & 0xffff) as i32
        } else {
            depthval
        };
        if !depth_test(fbzmode, depth_pixel, source) {
            stats.zfunc_fail += 1;
            return;
        }
    }

    let mut color = src_color;

    if fbzmode_enable_chromakey(fbzmode) && !chroma_key_test(color, poly) {
        stats.chroma_fail += 1;
        return;
    }
    if fbzmode_enable_alpha_mask(fbzmode) && (color.a & 1) == 0 {
        return;
    }
    if alphamode_alphatest(poly.alphamode)
        && !alpha_test(poly.alphamode, color.a as u32, poly.alpharef)
    {
        stats.afunc_fail += 1;
        return;
    }

    let dither = Dither::new(scry, fbzmode);
    let prefog = color;
    if fogmode_enable_fog(poly.fogmode) {
        let iterz = (sz as i32) << 12;
        let iterw = if poly.lfb_write_w_select {
            ((poly.zacolor as u64) << 16) as i64
        } else {
            ((sz as u64) << 16) as i64
        };
        apply_fogging(
            &mut color, poly, fbzmode, poly.fogmode, poly.fbzcp, x, &dither, depthval, iterz,
            iterw, Rgba::default(), fog,
        );
    }

    if alphamode_alphablend(poly.alphamode) {
        let dpix = read_pixel(fb, dest_row + x as usize * 2);
        alpha_blend(&mut color, fbzmode, poly.alphamode, x, &dither, dpix, depth_pixel, prefog);
    }

    if fbzmode_rgb_buffer_mask(fbzmode) {
        write_pixel(fb, dest_row + x as usize * 2, dither.pixel(x, color));
    }
    if fbzmode_aux_buffer_mask(fbzmode) {
        if let Some(base) = depth_row {
            let v = if fbzmode_enable_alpha_planes(fbzmode) {
                color.a as u16
            } else {
                depthval as u16
            };
            write_pixel(fb, base + x as usize * 2, v);
        }
    }
    stats.pixels_out += 1;
}
