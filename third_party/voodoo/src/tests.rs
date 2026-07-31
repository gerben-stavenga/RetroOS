extern crate alloc;

use crate::*;
use alloc::vec;
use alloc::vec::Vec;

const FB_BYTES: usize = 4 << 20;
const TEX_BYTES: usize = 2 << 20;
const LFB_APERTURE: u32 = 0x40_0000;

/// The card plus the memory the host owns on its behalf.
struct Card {
    v: Voodoo,
    fb: Vec<u8>,
    tex: Vec<u8>,
}

impl Card {
    /// Bring a card up the way a driver does: enable hardware init, program
    /// the memory layout, then the video timing.
    fn boot() -> Self {
        let mut c = Card {
            v: Voodoo::new(Kind::Voodoo1, FB_BYTES, TEX_BYTES),
            fb: vec![0u8; FB_BYTES],
            tex: vec![0u8; TEX_BYTES],
        };
        c.v.set_init_enable(1);
        // 640 pixels per row = 10 tiles of 64.
        c.w(fbiInit1, 10 << 4);
        // Each buffer is 640*480*2 bytes = 150 pages of 0x1000.
        c.w(fbiInit2, 150 << 11);
        c.w(hSync, 1);
        c.w(vSync, 1);
        c.w(videoDimensions, (479 << 16) | 639);
        c
    }

    /// Write a register by its dword index.
    fn w(&mut self, reg: usize, data: u32) -> Events {
        self.wa((reg * 4) as u32, data)
    }

    /// Write anywhere in the aperture.
    fn wa(&mut self, addr: u32, data: u32) -> Events {
        let mut tex: [&mut [u8]; 1] = [&mut self.tex];
        self.v.write(&mut self.fb, &mut tex, addr, data, !0)
    }

    fn r(&self, addr: u32) -> u32 {
        self.v.read(&self.fb, addr, Beam::default())
    }

    fn frame(&self) -> Vec<u32> {
        let mut out = vec![0u32; 640 * 480];
        self.v.render(&self.fb, &mut out, 640);
        out
    }
}

#[test]
fn video_memory_layout_follows_fbi_init() {
    let c = Card::boot();
    assert_eq!(c.v.dimensions(), (640, 480));
    assert_eq!(c.v.fbi.rowpixels, 640);
    assert_eq!(c.v.fbi.rgboffs[0], 0);
    assert_eq!(c.v.fbi.rgboffs[1], 150 * 0x1000);
    // Two colour buffers and one aux buffer is the default config.
    assert_eq!(c.v.fbi.rgboffs[2], fbi::NO_BUFFER);
    assert_eq!(c.v.fbi.auxoffs, 2 * 150 * 0x1000);
}

#[test]
fn fastfill_then_swap_is_what_the_monitor_sees() {
    let mut c = Card::boot();

    // Clear the *back* buffer to a known colour.
    c.w(clipLeftRight, 640);
    c.w(clipLowYHighY, 480);
    c.w(color1, 0x00_f8_fc_08);
    let draw_back = 1 << 14;
    c.w(fbzMode, (1 << 9) | draw_back);
    let ev = c.w(fastfillCMD, 0);
    assert!(!ev.any());

    // Still on the front buffer: nothing visible yet.
    assert_eq!(c.frame()[0], 0);

    let ev = c.w(swapbufferCMD, 0);
    assert!(ev.swap);
    assert_eq!(c.v.fbi.frontbuf, 1);

    // 0xf8/0xfc/0x08 truncates to 5-6-5; scanout expands the high bits back
    // down, so f8/fc saturate to ff and 08 stays 08.
    let out = c.frame();
    assert_eq!(out[0], 0x00_ff_ff_08);
    assert_eq!(out[640 * 479 + 639], 0x00_ff_ff_08);
}

#[test]
fn lfb_write_read_roundtrip() {
    let mut c = Card::boot();

    // Write format 0 (RGB 5-6-5), ARGB lanes, front buffer for both.
    c.w(lfbMode, 0);

    let red = 0xf800u32;
    let blue = 0x001fu32;
    c.wa(LFB_APERTURE, red | (blue << 16));

    assert_eq!(c.r(LFB_APERTURE), red | (blue << 16));

    let out = c.frame();
    assert_eq!(out[0], 0x00_ff_00_00);
    assert_eq!(out[1], 0x00_00_00_ff);
    assert_eq!(out[2], 0);
}

#[test]
fn read_only_and_write_only_registers_are_honoured() {
    let mut c = Card::boot();

    // fbiPixelsOut is read-only: the write must not land.
    c.w(fbiPixelsOut, 0x1234);
    assert_eq!(c.r((fbiPixelsOut * 4) as u32), 0);

    // Unmapped register: reads return all ones.
    assert_eq!(c.r((0x1c8 * 4) as u32), 0xffff_ffff);
}

#[test]
fn status_reports_the_visible_buffer_and_retrace() {
    let mut c = Card::boot();
    let st = c.r((status * 4) as u32);
    assert_eq!((st >> 10) & 3, 0);
    assert_eq!(st & 0x40, 0);

    c.w(swapbufferCMD, 0);
    let st = c.v.read(&c.fb, (status * 4) as u32, Beam { in_vblank: true, vpos: 0 });
    assert_eq!((st >> 10) & 3, 1);
    assert_eq!(st & 0x40, 0x40);
}

/// Configure the colour path so that the iterated RGB passes straight
/// through: c_other = iterated, blend factor 0 inverted to 0xff (+1 = 0x100),
/// nothing added.
fn flat_shaded(c: &mut Card, r: u32, g: u32, b: u32) {
    c.w(fbzColorPath, 0);
    c.w(alphaMode, 0);
    c.w(fogMode, 0);
    // Draw to the front buffer, colour writes on, no depth, no dithering.
    c.w(fbzMode, 1 << 9);
    // Iterated colour is 12.12 fixed point, constant across the triangle.
    c.w(startR, r << 12);
    c.w(startG, g << 12);
    c.w(startB, b << 12);
    for d in [dRdX, dGdX, dBdX, dRdY, dGdY, dBdY, dAdX, dAdY, dZdX, dZdY] {
        c.w(d, 0);
    }
}

#[test]
fn gouraud_triangle_covers_the_right_pixels() {
    let mut c = Card::boot();
    flat_shaded(&mut c, 0xff, 0x80, 0x00);

    // A right triangle with the square corner at (10,10).
    c.w(vertexAx, 10 << 4);
    c.w(vertexAy, 10 << 4);
    c.w(vertexBx, 50 << 4);
    c.w(vertexBy, 10 << 4);
    c.w(vertexCx, 10 << 4);
    c.w(vertexCy, 50 << 4);
    c.w(triangleCMD, 0);

    let out = c.frame();
    let at = |x: usize, y: usize| out[y * 640 + x];

    // 0xff/0x80 through 5-6-5 and back.
    let expect = 0x00_ff_82_00;
    assert_eq!(at(12, 12), expect, "inside the triangle");
    assert_eq!(at(11, 40), expect, "inside, near the vertical edge");
    assert_eq!(at(45, 12), expect, "inside, near the hypotenuse");

    assert_eq!(at(45, 45), 0, "outside, past the hypotenuse");
    assert_eq!(at(5, 12), 0, "outside, left of the triangle");
    assert_eq!(at(12, 5), 0, "outside, above the triangle");

    // The statistics registers counted the work. (`fbiTrianglesOut` is not
    // readable on an SST-1 — it arrived with the Voodoo 2.)
    assert!(c.r((fbiPixelsOut * 4) as u32) > 700);
    assert_eq!(c.r((fbiTrianglesOut * 4) as u32), 0xffff_ffff);
}

#[test]
fn depth_test_rejects_pixels_behind_the_buffer() {
    let mut c = Card::boot();
    flat_shaded(&mut c, 0xff, 0xff, 0xff);

    // Clear the depth buffer to "infinitely far" first, as a driver does.
    c.w(clipLeftRight, 640);
    c.w(clipLowYHighY, 480);
    c.w(zaColor, 0xffff);
    c.w(fbzMode, 1 << 10);
    c.w(fastfillCMD, 0);

    // Depth buffering on, function "less than", write both buffers, and a
    // constant Z of 0x8000 across the triangle (20.12 fixed point).
    let depth_less_than = 1 << 5;
    c.w(fbzMode, (1 << 9) | (1 << 10) | (1 << 4) | depth_less_than);
    c.w(startZ, 0x8000 << 12);

    let tri = |c: &mut Card| {
        c.w(vertexAx, 10 << 4);
        c.w(vertexAy, 10 << 4);
        c.w(vertexBx, 50 << 4);
        c.w(vertexBy, 10 << 4);
        c.w(vertexCx, 10 << 4);
        c.w(vertexCy, 50 << 4);
        c.w(triangleCMD, 0);
    };
    tri(&mut c);
    assert_eq!(c.frame()[12 * 640 + 12], 0x00_ff_ff_ff);

    // The same triangle again, further away and in a different colour: every
    // pixel must fail the depth test.
    let before = c.r((fbiZfuncFail * 4) as u32);
    flat_shaded(&mut c, 0x00, 0x00, 0xff);
    c.w(fbzMode, (1 << 9) | (1 << 10) | (1 << 4) | depth_less_than);
    c.w(startZ, 0xc000 << 12);
    tri(&mut c);

    assert_eq!(c.frame()[12 * 640 + 12], 0x00_ff_ff_ff, "the near pixel survives");
    assert!(c.r((fbiZfuncFail * 4) as u32) > before, "the far pixels were rejected");
}

#[test]
fn textured_triangle_samples_texture_memory() {
    let mut c = Card::boot();

    // A solid RGB 5-6-5 texture, written straight into the host's texture
    // memory (the fetch path is what is under test here, not `texture_w`).
    let texel: u16 = 0x07e0; // pure green
    for chunk in c.tex.chunks_exact_mut(2) {
        chunk.copy_from_slice(&texel.to_le_bytes());
    }

    // Colour path: c_other = texture RGB, blend factor 0x100, texturing on.
    c.w(fbzColorPath, 1 | (1 << 27));
    c.w(alphaMode, 0);
    c.w(fogMode, 0);
    c.w(fbzMode, 1 << 9);

    // TMU0: format 10 (RGB 5-6-5), point sampled, and the "texture only"
    // combine — blend from zero, then add c_local.
    let texmode = (10 << 8) | (1 << 12) | (1 << 18) | (1 << 21) | (1 << 27);
    let tmu0 = 0x200; // chip select bits: TMU0 only
    c.wa(((textureMode * 4) as u32) | (tmu0 << 2), texmode);
    c.wa(((tLOD * 4) as u32) | (tmu0 << 2), 0);
    c.wa(((texBaseAddr * 4) as u32) | (tmu0 << 2), 0);
    // Constant S/T/W across the triangle: sample the same texel everywhere.
    for r in [startS, startT, dSdX, dTdX, dSdY, dTdY] {
        c.wa(((r * 4) as u32) | (tmu0 << 2), 0);
    }

    c.w(vertexAx, 10 << 4);
    c.w(vertexAy, 10 << 4);
    c.w(vertexBx, 50 << 4);
    c.w(vertexBy, 10 << 4);
    c.w(vertexCx, 10 << 4);
    c.w(vertexCy, 50 << 4);
    c.w(triangleCMD, 0);

    let out = c.frame();
    // 5-6-5 green expands to 0x00ff00 on the way back out.
    assert_eq!(out[12 * 640 + 12], 0x00_00_ff_00, "textured pixel");
    assert_eq!(out[45 * 640 + 45], 0, "outside the triangle");
}

#[test]
fn swap_can_wait_for_vertical_retrace() {
    let mut c = Card::boot();

    // Bit 0 set: swap on the next retrace, not now.
    let ev = c.w(swapbufferCMD, 1);
    assert!(!ev.swap, "the swap is deferred");
    assert_eq!(c.v.fbi.frontbuf, 0);
    // A game polling status sees the swap it queued.
    assert_eq!((c.r((status * 4) as u32) >> 28) & 7, 1);

    let ev = c.v.vblank();
    assert!(ev.swap, "the retrace completed it");
    assert_eq!(c.v.fbi.frontbuf, 1);
    assert_eq!((c.r((status * 4) as u32) >> 28) & 7, 0);

    // Waiting two retraces means one is not enough.
    c.w(swapbufferCMD, 1 | (2 << 1));
    assert!(!c.v.vblank().swap);
    assert!(c.v.vblank().swap);
    assert_eq!(c.v.fbi.frontbuf, 0);
}

#[test]
fn vretrace_register_reports_the_beam() {
    let c = Card::boot();
    let addr = (vRetrace * 4) as u32;
    assert_eq!(c.v.read(&c.fb, addr, Beam { in_vblank: false, vpos: 137 }), 137);
    assert_eq!(c.v.read(&c.fb, addr, Beam { in_vblank: true, vpos: 137 }), 0);
}

#[test]
fn dithering_varies_within_the_4x4_cell() {
    let mut c = Card::boot();
    c.w(clipLeftRight, 640);
    c.w(clipLowYHighY, 480);
    // A colour that does not sit on a 5-6-5 boundary, so dithering shows.
    c.w(color1, 0x00_7c_7c_7c);
    c.w(fbzMode, (1 << 9) | (1 << 8));
    c.w(fastfillCMD, 0);

    let out = c.frame();
    let row: Vec<u32> = out[..4].to_vec();
    assert!(
        row.iter().any(|p| *p != row[0]),
        "the 4x4 dither cell must not be flat: {row:x?}"
    );

    // With dithering off the same fill is uniform.
    c.w(fbzMode, 1 << 9);
    c.w(fastfillCMD, 0);
    let out = c.frame();
    assert!(out[..4].iter().all(|p| *p == out[0]));
}

#[test]
fn chroma_key_kills_matching_pixels() {
    let mut c = Card::boot();
    flat_shaded(&mut c, 0xff, 0x80, 0x00);
    // Key on exactly the colour the triangle iterates.
    c.w(chromaKey, 0x00_ff_80_00);
    c.w(chromaRange, 0);
    c.w(fbzMode, (1 << 9) | (1 << 1));

    c.w(vertexAx, 10 << 4);
    c.w(vertexAy, 10 << 4);
    c.w(vertexBx, 50 << 4);
    c.w(vertexBy, 10 << 4);
    c.w(vertexCx, 10 << 4);
    c.w(vertexCy, 50 << 4);
    c.w(triangleCMD, 0);

    assert_eq!(c.frame()[12 * 640 + 12], 0, "the keyed pixel was killed");
    assert!(c.r((fbiChromaFail * 4) as u32) > 700);
}

#[test]
fn alpha_blending_mixes_with_the_destination() {
    let mut c = Card::boot();

    // Fill the front buffer with pure blue.
    c.w(clipLeftRight, 640);
    c.w(clipLowYHighY, 480);
    c.w(color1, 0x00_00_00_ff);
    c.w(fbzMode, 1 << 9);
    c.w(fastfillCMD, 0);

    // Draw red at 50% alpha over it: src*alpha + dst*(1-alpha).
    flat_shaded(&mut c, 0xff, 0x00, 0x00);
    c.w(startA, 0x80 << 12);
    let src_alpha = 1 << 8;
    let one_minus_src_alpha = 5 << 12;
    c.w(alphaMode, (1 << 4) | src_alpha | one_minus_src_alpha);

    c.w(vertexAx, 10 << 4);
    c.w(vertexAy, 10 << 4);
    c.w(vertexBx, 50 << 4);
    c.w(vertexBy, 10 << 4);
    c.w(vertexCx, 10 << 4);
    c.w(vertexCy, 50 << 4);
    c.w(triangleCMD, 0);

    let p = c.frame()[12 * 640 + 12];
    let (r, g, b) = ((p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff);
    assert!((120..=140).contains(&r), "about half the red: {r:#x}");
    assert_eq!(g, 0);
    assert!((115..=135).contains(&b), "about half the blue: {b:#x}");
}

#[test]
fn lfb_pixel_pipeline_write_respects_the_depth_test() {
    let mut c = Card::boot();

    // Clear depth to near, so a far LFB write must be rejected.
    c.w(clipLeftRight, 640);
    c.w(clipLowYHighY, 480);
    c.w(zaColor, 0x1000);
    c.w(fbzMode, 1 << 10);
    c.w(fastfillCMD, 0);

    // Pixel pipeline on, RGB 5-6-5 writes into the front buffer, depth test
    // "less than" against the value the write carries.
    c.w(fbzColorPath, 0);
    c.w(alphaMode, 0);
    c.w(fogMode, 0);
    c.w(fbzMode, (1 << 9) | (1 << 4) | (1 << 5));
    // Format 12: 32-bit depth + RGB 5-6-5, pipeline enabled.
    c.w(lfbMode, 12 | (1 << 8));

    // Depth 0x8000 is behind the cleared 0x1000: rejected.
    c.wa(LFB_APERTURE, 0xf800 | (0x8000 << 16));
    assert_eq!(c.frame()[0], 0, "far pixel rejected");
    assert!(c.r((fbiZfuncFail * 4) as u32) > 0);

    // Depth 0x0800 is in front: accepted.
    c.wa(LFB_APERTURE, 0xf800 | (0x0800 << 16));
    assert_eq!(c.frame()[0], 0x00_ff_00_00, "near pixel drawn");
}

#[test]
fn clut_recolours_scanout() {
    let mut c = Card::boot();
    c.w(lfbMode, 0);
    c.wa(LFB_APERTURE, 0xffff); // white
    assert_eq!(c.frame()[0], 0x00_ff_ff_ff);

    // Invert the CLUT ramp: entry n holds (31-n) scaled to 8 bits.
    for i in 0..=32u32 {
        let v = if i >= 32 { 0 } else { (31 - i) * 255 / 31 };
        c.w(clutData, (i << 24) | (v << 16) | (v << 8) | v);
    }
    assert_eq!(c.frame()[0], 0x00_00_00_00, "white now scans out as black");
}
