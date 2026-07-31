//! Texture Mapper Unit: LOD layout, texel fetch and the texture combine unit.
//!
//! Ported from Aaron Giles' `rasterizer_texture` in MAME's
//! `voodoo_render.cpp`. Texture RAM is not owned here either — it arrives as a
//! `&[u8]` argument, and the TMU holds byte offsets into it.

use crate::regs::*;
use crate::rgba::Rgba;

/// The texel decode tables MAME precomputes. We decode arithmetically
/// instead: the tables are 64K entries × 3 formats, which is a quarter of a
/// megabyte of lookup we would have to carry into a `no_std` kernel to save a
/// handful of shifts.
#[inline]
fn expand(v: u32, bits: u32) -> i32 {
    // Replicate the high bits down, as `rgbexpand` does.
    let shift = 8 - bits;
    (((v << shift) | (v >> (bits.saturating_sub(shift).max(1)))) & 0xff) as i32
}

#[inline]
fn decode16(format: u32, texel: u32) -> u32 {
    match format {
        // 10: RGB 5-6-5
        10 => Rgba::new(
            0xff,
            expand((texel >> 11) & 0x1f, 5),
            expand((texel >> 5) & 0x3f, 6),
            expand(texel & 0x1f, 5),
        )
        .to_argb(),
        // 11: ARGB 1-5-5-5
        11 => Rgba::new(
            if (texel >> 15) & 1 != 0 { 0xff } else { 0 },
            expand((texel >> 10) & 0x1f, 5),
            expand((texel >> 5) & 0x1f, 5),
            expand(texel & 0x1f, 5),
        )
        .to_argb(),
        // 12: ARGB 4-4-4-4
        _ => Rgba::new(
            expand((texel >> 12) & 0xf, 4),
            expand((texel >> 8) & 0xf, 4),
            expand((texel >> 4) & 0xf, 4),
            expand(texel & 0xf, 4),
        )
        .to_argb(),
    }
}

/// The 256-entry lookup a format uses for its 8-bit index. `palette` is the
/// TMU's NCC/palette table, already selected by the caller.
#[inline]
fn decode8(format: u32, val: u32, palette: &[u32; 256]) -> u32 {
    let v = val as i32;
    match format & 7 {
        // RGB 3-3-2
        0 => Rgba::new(0xff, expand(val >> 5, 3), expand((val >> 2) & 7, 3), expand(val & 3, 2))
            .to_argb(),
        // NCC / palette: the dynamic table
        1 | 5 | 6 | 7 => palette[(val & 0xff) as usize],
        // 8-bit alpha
        2 => Rgba::new(v, v, v, v).to_argb(),
        // 8-bit intensity
        3 => Rgba::new(0xff, v, v, v).to_argb(),
        // 8-bit alpha, intensity 4-4
        _ => {
            let a = expand(val >> 4, 4);
            let i = expand(val & 0xf, 4);
            Rgba::new(a, i, i, i).to_argb()
        }
    }
}

/// Per-TMU state that is derived from its registers (`rasterizer_texture`).
#[derive(Debug)]
pub struct Texture {
    pub mask: u32,
    lodmin: i32,
    lodmax: i32,
    lodbias: i32,
    lodmask: u32,
    lodoffset: [u32; 9],
    wmask: i32,
    hmask: i32,
    detailmax: i32,
    detailbias: i32,
    detailscale: u32,
    /// NCC (2) and straight palette (2) tables, selected by format.
    palette: [[u32; 256]; 2],
    ncc: [[u32; 12]; 2],
    /// The currently selected 256-entry table, rebuilt by `recompute`.
    lookup: [u32; 256],
    pub regdirty: bool,
}

impl Texture {
    pub fn new(tex_bytes: usize) -> Self {
        Self {
            mask: (tex_bytes as u32).saturating_sub(1),
            lodmin: 0,
            lodmax: 0,
            lodbias: 0,
            lodmask: 0x1ff,
            lodoffset: [0; 9],
            wmask: 0xff,
            hmask: 0xff,
            detailmax: 0,
            detailbias: 0,
            detailscale: 0,
            palette: [[0; 256]; 2],
            ncc: [[0; 12]; 2],
            lookup: [0; 256],
            regdirty: true,
        }
    }

    /// `ncc_w` — a write to the NCC/palette register block.
    pub fn ncc_w(&mut self, regindex: usize, data: u32) {
        // I/Q entries in NCC 0 reference the palette when the high bit is set.
        if data & 0x8000_0000 != 0 && (4..12).contains(&regindex) {
            let index = ((((data >> 24) & 0x7f) << 1) | (regindex as u32 & 1)) as usize;
            self.palette[0][index] = 0xff00_0000 | (data & 0xff_ffff);
            self.palette[1][index] = Rgba::new(
                expand((data >> 18) & 0x3f, 6),
                expand((data >> 12) & 0x3f, 6),
                expand((data >> 6) & 0x3f, 6),
                expand(data & 0x3f, 6),
            )
            .to_argb();
            return;
        }
        if regindex < 24 {
            self.ncc[regindex / 12][regindex % 12] = data;
            self.regdirty = true;
        }
    }

    /// `compute_ncc` — expand a YIQ table into 256 texels.
    fn compute_ncc(&self, table: usize) -> [u32; 256] {
        let regs = &self.ncc[table];
        let ybase = |i: usize| ((regs[i / 4] >> ((i % 4) * 8)) & 0xff) as i32;
        let sext9 = |v: u32| (((v & 0x1ff) as i32) << 23) >> 23;

        let mut out = [0u32; 256];
        for (index, texel) in out.iter_mut().enumerate() {
            let y = ybase((index >> 4) & 0xf);
            let i = regs[4 + ((index >> 2) & 3)];
            let q = regs[8 + (index & 3)];
            let r = (y + sext9(i >> 18) + sext9(q >> 18)).clamp(0, 255);
            let g = (y + sext9(i >> 9) + sext9(q >> 9)).clamp(0, 255);
            let b = (y + sext9(i) + sext9(q)).clamp(0, 255);
            *texel = Rgba::new(0xff, r, g, b).to_argb();
        }
        out
    }

    /// `recompute` — rebuild LOD offsets and the selected texel table from the
    /// TMU's registers.
    pub fn recompute(&mut self, reg: &[u32]) {
        let texlod = reg[tLOD];
        self.lodmin = (texlod_lodmin(texlod) << 6) as i32;
        self.lodmax = (texlod_lodmax(texlod) << 6) as i32;
        self.lodbias = ((((texlod_lodbias(texlod) << 2) as u8) as i8) as i32) << 4;

        self.lodmask = if texlod_lod_tsplit(texlod) {
            if texlod_lod_odd(texlod) { 0x0aa } else { 0x155 }
        } else {
            0x1ff
        };

        self.wmask = 0xff;
        self.hmask = 0xff;
        if texlod_lod_s_is_wider(texlod) {
            self.hmask >>= texlod_lod_aspect(texlod);
        } else {
            self.wmask >>= texlod_lod_aspect(texlod);
        }

        let texmode = reg[textureMode];
        let bppscale = texmode_format(texmode) >> 3;

        let mut base = reg[texBaseAddr] & 0x0f_ffff;
        base <<= 3;
        self.lodoffset[0] = base & self.mask;

        if texlod_tmultibaseaddr(texlod) {
            for (i, r) in [texBaseAddr_1, texBaseAddr_2, texBaseAddr_3_8].iter().enumerate() {
                self.lodoffset[i + 1] = (((reg[*r] & 0x0f_ffff) << 3) & self.mask) as u32;
            }
        } else {
            for lod in 1..4u32 {
                if self.lodmask & (1 << (lod - 1)) != 0 {
                    let w = ((self.wmask >> (lod - 1)) + 1) as u32;
                    let h = ((self.hmask >> (lod - 1)) + 1) as u32;
                    base = base.wrapping_add((w * h) << bppscale);
                }
                self.lodoffset[lod as usize] = base & self.mask;
            }
        }

        for lod in 4..=8u32 {
            if self.lodmask & (1 << (lod - 1)) != 0 {
                let w = ((self.wmask >> (lod - 1)) + 1) as u32;
                let h = ((self.hmask >> (lod - 1)) + 1) as u32;
                base = base.wrapping_add(((w * h).max(4)) << bppscale);
            }
            self.lodoffset[lod as usize] = base & self.mask;
        }

        let texdetail = reg[tDetail];
        self.detailmax = texdetail_detail_max(texdetail);
        self.detailbias = ((((texdetail_detail_bias(texdetail) << 2) as u8) as i8) as i32) << 6;
        self.detailscale = texdetail_detail_scale(texdetail);

        // Select the dynamic 256-entry table for the formats that need one.
        let format = texmode_format(texmode);
        self.lookup = match format & 7 {
            1 => self.compute_ncc(texmode_ncc_table_select(texmode) as usize),
            5 | 7 => self.palette[0],
            6 => self.palette[1],
            _ => self.lookup,
        };

        self.regdirty = false;
    }

    #[inline]
    fn lookup_single_texel(&self, format: u32, texbase: u32, s: i32, t: i32, ram: &[u8]) -> u32 {
        if ram.is_empty() {
            return 0;
        }
        if format < 8 {
            let off = ((texbase.wrapping_add((t + s) as u32)) & self.mask) as usize;
            decode8(format, ram[off % ram.len()] as u32, &self.lookup)
        } else {
            let off = ((texbase.wrapping_add(2 * (t + s) as u32)) & self.mask) as usize;
            let off = off % (ram.len() - 1).max(1);
            let texel = u16::from_le_bytes([ram[off], ram[off + 1]]) as u32;
            if (10..=12).contains(&format) {
                decode16(format, texel)
            } else {
                // 8 bits of alpha in the high byte, 8-bit index in the low.
                (decode8(format, texel & 0xff, &self.lookup) & 0xff_ffff) | ((texel & 0xff00) << 16)
            }
        }
    }

    /// `fetch_texel` — S/T are 32.32 iterated values; `lod` comes in as the
    /// per-triangle LOD base and is adjusted here.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_texel(
        &self,
        texmode: u32,
        dither_4x4: u32,
        iters: f64,
        itert: f64,
        iterw: f64,
        lod: &mut i32,
        bilinear_mask: i32,
        ram: &[u8],
    ) -> Rgba {
        let (mut s, mut t);
        if texmode_enable_perspective(texmode) {
            let recip = 256.0 / iterw;
            s = (iters * recip) as i32;
            t = (itert * recip) as i32;
            *lod -= fast_log2(iterw, 32);
        } else {
            s = (iters * (1.0 / (1 << 24) as f64)) as i32;
            t = (itert * (1.0 / (1 << 24) as f64)) as i32;
        }

        if texmode_clamp_neg_w(texmode) && iterw < 0.0 {
            s = 0;
            t = 0;
        }

        *lod += self.lodbias;
        if texmode_enable_lod_dither(texmode) {
            *lod += (dither_4x4 as i32) << 4;
        }
        *lod = (*lod).clamp(self.lodmin, self.lodmax);

        let mut ilod = *lod >> 8;
        ilod += ((!self.lodmask >> ilod.clamp(0, 31)) & 1) as i32;
        let ilod = ilod.clamp(0, 8);

        let texbase = self.lodoffset[ilod as usize];
        let smax = self.wmask >> ilod;
        let tmax = self.hmask >> ilod;

        let format = texmode_format(texmode);
        let point_sampled = (*lod == self.lodmin && !texmode_magnification_filter(texmode))
            || (*lod != self.lodmin && !texmode_minification_filter(texmode));

        if point_sampled {
            let shift = ilod + 8;
            s >>= shift;
            t >>= shift;
            if texmode_clamp_s(texmode) {
                s = s.clamp(0, smax);
            }
            if texmode_clamp_t(texmode) {
                t = t.clamp(0, tmax);
            }
            s &= smax;
            t &= tmax;
            t *= smax + 1;
            Rgba::from_argb(self.lookup_single_texel(format, texbase, s, t, ram))
        } else {
            s >>= ilod;
            t >>= ilod;
            // Subtract half a texel so (0.5,0.5) lands on a whole texel.
            s -= 0x80;
            t -= 0x80;
            let sfrac = (s & bilinear_mask) as u32;
            let tfrac = (t & bilinear_mask) as u32;
            s >>= 8;
            t >>= 8;
            let mut s1 = s + 1;
            let mut t1 = t + 1;

            if texmode_clamp_s(texmode) {
                if s < 0 {
                    s = 0;
                    s1 = 0;
                } else if s >= smax {
                    s = smax;
                    s1 = smax;
                }
            }
            s &= smax;
            s1 &= smax;

            if texmode_clamp_t(texmode) {
                if t < 0 {
                    t = 0;
                    t1 = 0;
                } else if t >= tmax {
                    t = tmax;
                    t1 = tmax;
                }
            }
            t &= tmax;
            t1 &= tmax;
            t *= smax + 1;
            t1 *= smax + 1;

            Rgba::bilinear(
                self.lookup_single_texel(format, texbase, s, t, ram),
                self.lookup_single_texel(format, texbase, s1, t, ram),
                self.lookup_single_texel(format, texbase, s, t1, ram),
                self.lookup_single_texel(format, texbase, s1, t1, ram),
                sfrac,
                tfrac,
            )
        }
    }

    /// `combine_texture` — the TMU's own colour combine unit, which feeds the
    /// next TMU or the colour path.
    pub fn combine_texture(&self, texmode: u32, c_local: Rgba, c_other: Rgba, lod: i32) -> Rgba {
        let mut blend_color = if texmode_tc_zero_other(texmode) {
            Rgba::default()
        } else {
            c_other
        };
        if texmode_tca_zero_other(texmode) {
            blend_color.zero_alpha();
        } else {
            blend_color.merge_alpha(c_other);
        }

        if texmode_tc_sub_clocal(texmode) || texmode_tca_sub_clocal(texmode) {
            let mut sub_val = if texmode_tc_sub_clocal(texmode) {
                c_local
            } else {
                Rgba::default()
            };
            if texmode_tca_sub_clocal(texmode) {
                sub_val.merge_alpha(c_local);
            } else {
                sub_val.zero_alpha();
            }
            blend_color.sub(sub_val);
        }

        // Detail factor, shared by both mselect paths.
        let detail = || -> i32 {
            if self.detailbias <= lod {
                0
            } else {
                (((self.detailbias - lod) << self.detailscale) >> 8).min(self.detailmax)
            }
        };

        let mut blend_factor = match texmode_tc_mselect(texmode) {
            1 => c_local,
            2 => c_other.select_alpha(),
            3 => c_local.select_alpha(),
            4 => Rgba::splat(detail()),
            5 => Rgba::splat(lod & 0xff),
            _ => Rgba::default(),
        };

        match texmode_tca_mselect(texmode) {
            1 | 3 => blend_factor.merge_alpha(c_local),
            2 => blend_factor.merge_alpha(c_other),
            4 => blend_factor.a = detail(),
            5 => blend_factor.a = lod & 0xff,
            _ => blend_factor.zero_alpha(),
        }

        if !texmode_tc_reverse_blend(texmode) {
            blend_factor.xor_imm(0, 0xff, 0xff, 0xff);
        }
        if !texmode_tca_reverse_blend(texmode) {
            blend_factor.xor_imm(0xff, 0, 0, 0);
        }
        blend_factor.add_imm(1);

        let mut add_val = match texmode_tc_add_aclocal(texmode) {
            1 => c_local,
            2 => c_local.select_alpha(),
            _ => Rgba::default(),
        };
        if texmode_tca_add_aclocal(texmode) {
            add_val.merge_alpha(c_local);
        } else {
            add_val.zero_alpha();
        }

        blend_color.scale_add_and_clamp(blend_factor, add_val);

        if texmode_tc_invert_output(texmode) {
            blend_color.xor_imm(0, 0xff, 0xff, 0xff);
        }
        if texmode_tca_invert_output(texmode) {
            blend_color.xor_imm(0xff, 0, 0, 0);
        }
        blend_color
    }
}

/// Fractional log2 of the top 7 mantissa bits (`s_log2_table`).
const LOG2_TABLE: [u8; 128] = [
    0, 2, 5, 8, 11, 14, 16, 19, 22, 25, 27, 30, 33, 35, 38, 40,
    43, 46, 48, 51, 53, 56, 58, 61, 63, 65, 68, 70, 73, 75, 77, 80,
    82, 84, 87, 89, 91, 93, 96, 98, 100, 102, 104, 106, 109, 111, 113, 115,
    117, 119, 121, 123, 125, 127, 129, 132, 134, 136, 138, 140, 141, 143, 145, 147,
    149, 151, 153, 155, 157, 159, 161, 162, 164, 166, 168, 170, 172, 173, 175, 177,
    179, 181, 182, 184, 186, 188, 189, 191, 193, 194, 196, 198, 200, 201, 203, 205,
    206, 208, 209, 211, 213, 214, 216, 218, 219, 221, 222, 224, 225, 227, 229, 230,
    232, 233, 235, 236, 238, 239, 241, 242, 244, 245, 247, 248, 250, 251, 253, 254,
];

/// `fast_log2` — log2 as a 24.8 fixed-point value. `fracbits` says how many
/// fractional bits the value carried when it was converted from fixed point.
pub fn fast_log2(value: f64, fracbits: i32) -> i32 {
    if value < 0.0 {
        return 0;
    }
    // Only the 11-bit exponent and the top 7 mantissa bits matter.
    let ival = (value.to_bits() >> 45) as u32;
    let exp = (ival >> 7) as i32 - 1023 - fracbits;
    (exp << 8) | LOG2_TABLE[(ival & 127) as usize] as i32
}

/// `compute_lodbase` — the per-triangle LOD base from the S/T gradients.
pub fn compute_lodbase(dsdx: i64, dsdy: i64, dtdx: i64, dtdy: i64) -> i32 {
    let (fdsdx, fdsdy) = (dsdx as f64, dsdy as f64);
    let (fdtdx, fdtdy) = (dtdx as f64, dtdy as f64);
    let texdx = fdsdx * fdsdx + fdtdx * fdtdx;
    let texdy = fdsdy * fdsdy + fdtdy * fdtdy;
    // 64 fractional bits in the source; halve because we want the sqrt.
    fast_log2(texdx.max(texdy), 64) / 2
}

impl Texture {
    /// Byte offset of the given LOD within texture memory.
    #[inline]
    pub fn lod_offset(&self, lod: usize) -> u32 {
        self.lodoffset[lod.min(8)]
    }

    /// Row width (in texels, minus one) at the given LOD.
    #[inline]
    pub fn lod_width(&self, lod: usize) -> u32 {
        (self.wmask >> lod.min(8)) as u32
    }
}

impl Texture {
    /// `write_ptr` — byte offset a texture download lands at.
    #[inline]
    pub fn write_offset(&self, lod: usize, s: u32, t: u32, scale: u32) -> u32 {
        let lod = lod.min(8);
        let offs = t * ((self.wmask >> lod) as u32 + 1) + s;
        (self.lodoffset[lod].wrapping_add((scale * offs) & !3)) & self.mask
    }
}
