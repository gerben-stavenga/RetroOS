//! SST-1 register map, alias map and per-register access rights.
//!
//! Transliterated from `voodoo.cpp` (Aaron Giles' MAME Voodoo core, via
//! DOSBox Staging) — see the crate docs for the derivation notice. Names are
//! kept identical to the C so the two can be diffed by eye.

#![allow(non_upper_case_globals, dead_code)]

// Register indices are *dword* indices: `0x104/4` in the C.
macro_rules! regs {
    ($($name:ident = $byte:literal),* $(,)?) => {
        $(pub const $name: usize = $byte / 4;)*
    };
}

regs! {
    status = 0x000, intrCtrl = 0x004,
    vertexAx = 0x008, vertexAy = 0x00c, vertexBx = 0x010, vertexBy = 0x014,
    vertexCx = 0x018, vertexCy = 0x01c,
    startR = 0x020, startG = 0x024, startB = 0x028, startZ = 0x02c,
    startA = 0x030, startS = 0x034, startT = 0x038, startW = 0x03c,

    dRdX = 0x040, dGdX = 0x044, dBdX = 0x048, dZdX = 0x04c,
    dAdX = 0x050, dSdX = 0x054, dTdX = 0x058, dWdX = 0x05c,
    dRdY = 0x060, dGdY = 0x064, dBdY = 0x068, dZdY = 0x06c,
    dAdY = 0x070, dSdY = 0x074, dTdY = 0x078, dWdY = 0x07c,

    triangleCMD = 0x080,
    fvertexAx = 0x088, fvertexAy = 0x08c, fvertexBx = 0x090, fvertexBy = 0x094,
    fvertexCx = 0x098, fvertexCy = 0x09c,
    fstartR = 0x0a0, fstartG = 0x0a4, fstartB = 0x0a8, fstartZ = 0x0ac,
    fstartA = 0x0b0, fstartS = 0x0b4, fstartT = 0x0b8, fstartW = 0x0bc,

    fdRdX = 0x0c0, fdGdX = 0x0c4, fdBdX = 0x0c8, fdZdX = 0x0cc,
    fdAdX = 0x0d0, fdSdX = 0x0d4, fdTdX = 0x0d8, fdWdX = 0x0dc,
    fdRdY = 0x0e0, fdGdY = 0x0e4, fdBdY = 0x0e8, fdZdY = 0x0ec,
    fdAdY = 0x0f0, fdSdY = 0x0f4, fdTdY = 0x0f8, fdWdY = 0x0fc,

    ftriangleCMD = 0x100, fbzColorPath = 0x104, fogMode = 0x108, alphaMode = 0x10c,
    fbzMode = 0x110, lfbMode = 0x114, clipLeftRight = 0x118, clipLowYHighY = 0x11c,
    nopCMD = 0x120, fastfillCMD = 0x124, swapbufferCMD = 0x128, fogColor = 0x12c,
    zaColor = 0x130, chromaKey = 0x134, chromaRange = 0x138, userIntrCMD = 0x13c,

    stipple = 0x140, color0 = 0x144, color1 = 0x148, fbiPixelsIn = 0x14c,
    fbiChromaFail = 0x150, fbiZfuncFail = 0x154, fbiAfuncFail = 0x158,
    fbiPixelsOut = 0x15c, fogTable = 0x160,

    fbiInit4 = 0x200, vRetrace = 0x204, backPorch = 0x208, videoDimensions = 0x20c,
    fbiInit0 = 0x210, fbiInit1 = 0x214, fbiInit2 = 0x218, fbiInit3 = 0x21c,
    hSync = 0x220, vSync = 0x224, clutData = 0x228, dacData = 0x22c,
    maxRgbDelta = 0x230,

    fbiInit5 = 0x244, fbiInit6 = 0x248, fbiInit7 = 0x24c,
    fbiSwapHistory = 0x258, fbiTrianglesOut = 0x25c,

    textureMode = 0x300, tLOD = 0x304, tDetail = 0x308, texBaseAddr = 0x30c,
    texBaseAddr_1 = 0x310, texBaseAddr_2 = 0x314, texBaseAddr_3_8 = 0x318,
    trexInit0 = 0x31c, trexInit1 = 0x320, nccTable = 0x324,
}

/// Alias map of the first 64 registers when `fbiInit3` bit 0 remaps them.
pub const REGISTER_ALIAS_MAP: [u8; 0x40] = [
    status as u8, (0x004 / 4) as u8, vertexAx as u8, vertexAy as u8,
    vertexBx as u8, vertexBy as u8, vertexCx as u8, vertexCy as u8,
    startR as u8, dRdX as u8, dRdY as u8, startG as u8,
    dGdX as u8, dGdY as u8, startB as u8, dBdX as u8,
    dBdY as u8, startZ as u8, dZdX as u8, dZdY as u8,
    startA as u8, dAdX as u8, dAdY as u8, startS as u8,
    dSdX as u8, dSdY as u8, startT as u8, dTdX as u8,
    dTdY as u8, startW as u8, dWdX as u8, dWdY as u8,

    triangleCMD as u8, (0x084 / 4) as u8, fvertexAx as u8, fvertexAy as u8,
    fvertexBx as u8, fvertexBy as u8, fvertexCx as u8, fvertexCy as u8,
    fstartR as u8, fdRdX as u8, fdRdY as u8, fstartG as u8,
    fdGdX as u8, fdGdY as u8, fstartB as u8, fdBdX as u8,
    fdBdY as u8, fstartZ as u8, fdZdX as u8, fdZdY as u8,
    fstartA as u8, fdAdX as u8, fdAdY as u8, fstartS as u8,
    fdSdX as u8, fdSdY as u8, fstartT as u8, fdTdX as u8,
    fdTdY as u8, fstartW as u8, fdWdX as u8, fdWdY as u8,
];

pub const REGISTER_READ: u8 = 0x01;
pub const REGISTER_WRITE: u8 = 0x02;
pub const REGISTER_PIPELINED: u8 = 0x04;
pub const REGISTER_FIFO: u8 = 0x08;

const R: u8 = REGISTER_READ;
const W: u8 = REGISTER_WRITE;
const RW: u8 = R | W;
const RP: u8 = R | REGISTER_PIPELINED;
const WF: u8 = W | REGISTER_FIFO;
const RWF: u8 = RW | REGISTER_FIFO;
const WPF: u8 = W | REGISTER_PIPELINED | REGISTER_FIFO;
const RWPF: u8 = RW | REGISTER_PIPELINED | REGISTER_FIFO;
const XX: u8 = 0;

/// Per-register access rights (`voodoo_register_access` in the C).
pub const VOODOO_REGISTER_ACCESS: [u8; 0x100] = [
    // 0x000
    RP, XX, WPF, WPF, WPF, WPF, WPF, WPF,
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    // 0x040
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    // 0x080
    WPF, XX, WPF, WPF, WPF, WPF, WPF, WPF,
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    // 0x0c0
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WPF,
    // 0x100
    WPF, RWPF, RWPF, RWPF, RWF, RWF, RWF, RWF,
    WF, WF, WF, WF, WF, WF, XX, XX,
    // 0x140
    RWF, RWF, RWF, R, R, R, R, R,
    WF, WF, WF, WF, WF, WF, WF, WF,
    // 0x180
    WF, WF, WF, WF, WF, WF, WF, WF,
    WF, WF, WF, WF, WF, WF, WF, WF,
    // 0x1c0
    WF, WF, WF, WF, WF, WF, WF, WF,
    XX, XX, XX, XX, XX, XX, XX, XX,
    // 0x200
    RW, R, RW, RW, RW, RW, RW, RW,
    W, W, W, W, W, XX, XX, XX,
    // 0x240
    XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX,
    // 0x280
    XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX,
    // 0x2c0
    XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX,
    // 0x300
    WPF, WPF, WPF, WPF, WPF, WPF, WPF, WF,
    WF, WF, WF, WF, WF, WF, WF, WF,
    // 0x340
    WF, WF, WF, WF, WF, WF, WF, WF,
    WF, WF, WF, WF, WF, WF, WF, WF,
    // 0x380
    WF, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX,
    // 0x3c0
    XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX,
];

// ---- bitfield accessors (the FOO_BAR(val) macros in the C) ----

#[inline]
pub const fn initen_enable_hw_init(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn initen_remap_init_to_dac(v: u32) -> bool { (v >> 2) & 1 != 0 }

#[inline]
pub const fn fbzmode_enable_dithering(v: u32) -> bool { (v >> 8) & 1 != 0 }
#[inline]
pub const fn fbzmode_rgb_buffer_mask(v: u32) -> bool { (v >> 9) & 1 != 0 }
#[inline]
pub const fn fbzmode_aux_buffer_mask(v: u32) -> bool { (v >> 10) & 1 != 0 }
#[inline]
pub const fn fbzmode_enable_alpha_planes(v: u32) -> bool { (v >> 18) & 1 != 0 }
#[inline]
pub const fn fbzmode_draw_buffer(v: u32) -> u32 { (v >> 14) & 3 }
#[inline]
pub const fn fbzmode_y_origin(v: u32) -> bool { (v >> 17) & 1 != 0 }

#[inline]
pub const fn lfbmode_write_format(v: u32) -> u32 { v & 0xf }
#[inline]
pub const fn lfbmode_write_buffer_select(v: u32) -> u32 { (v >> 4) & 3 }
#[inline]
pub const fn lfbmode_read_buffer_select(v: u32) -> u32 { (v >> 6) & 3 }
#[inline]
pub const fn lfbmode_enable_pixel_pipeline(v: u32) -> bool { (v >> 8) & 1 != 0 }
#[inline]
pub const fn lfbmode_rgba_lanes(v: u32) -> u32 { (v >> 9) & 3 }
#[inline]
pub const fn lfbmode_word_swap_writes(v: u32) -> bool { (v >> 11) & 1 != 0 }
#[inline]
pub const fn lfbmode_byte_swizzle_writes(v: u32) -> bool { (v >> 12) & 1 != 0 }
#[inline]
pub const fn lfbmode_y_origin(v: u32) -> bool { (v >> 13) & 1 != 0 }
#[inline]
pub const fn lfbmode_word_swap_reads(v: u32) -> bool { (v >> 15) & 1 != 0 }
#[inline]
pub const fn lfbmode_byte_swizzle_reads(v: u32) -> bool { (v >> 16) & 1 != 0 }

#[inline]
pub const fn fbiinit0_vga_passthru(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn fbiinit0_graphics_reset(v: u32) -> bool { (v >> 1) & 1 != 0 }
#[inline]
pub const fn fbiinit0_enable_memory_fifo(v: u32) -> bool { (v >> 13) & 1 != 0 }
#[inline]
pub const fn fbiinit1_x_video_tiles(v: u32) -> u32 { (v >> 4) & 0xf }
#[inline]
pub const fn fbiinit2_enable_triple_buf(v: u32) -> u32 { (v >> 4) & 1 }
#[inline]
pub const fn fbiinit2_video_buffer_offset(v: u32) -> u32 { (v >> 11) & 0x1ff }
#[inline]
pub const fn fbiinit3_tri_register_remap(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn fbiinit3_yorigin_subtract(v: u32) -> u32 { (v >> 22) & 0x3ff }
#[inline]
pub const fn fbiinit4_memory_fifo_start_row(v: u32) -> u32 { (v >> 8) & 0x3ff }
#[inline]
pub const fn fbiinit4_memory_fifo_stop_row(v: u32) -> u32 { (v >> 18) & 0x3ff }

// ---- fbzColorPath ----
#[inline]
pub const fn fbzcp_cc_rgbselect(v: u32) -> u32 { v & 3 }
#[inline]
pub const fn fbzcp_cc_aselect(v: u32) -> u32 { (v >> 2) & 3 }
#[inline]
pub const fn fbzcp_cc_localselect(v: u32) -> u32 { (v >> 4) & 1 }
#[inline]
pub const fn fbzcp_cca_localselect(v: u32) -> u32 { (v >> 5) & 3 }
#[inline]
pub const fn fbzcp_cc_localselect_override(v: u32) -> bool { (v >> 7) & 1 != 0 }
#[inline]
pub const fn fbzcp_cc_zero_other(v: u32) -> bool { (v >> 8) & 1 != 0 }
#[inline]
pub const fn fbzcp_cc_sub_clocal(v: u32) -> bool { (v >> 9) & 1 != 0 }
#[inline]
pub const fn fbzcp_cc_mselect(v: u32) -> u32 { (v >> 10) & 7 }
#[inline]
pub const fn fbzcp_cc_reverse_blend(v: u32) -> bool { (v >> 13) & 1 != 0 }
#[inline]
pub const fn fbzcp_cc_add_aclocal(v: u32) -> u32 { (v >> 14) & 3 }
#[inline]
pub const fn fbzcp_cc_invert_output(v: u32) -> bool { (v >> 16) & 1 != 0 }
#[inline]
pub const fn fbzcp_cca_zero_other(v: u32) -> bool { (v >> 17) & 1 != 0 }
#[inline]
pub const fn fbzcp_cca_sub_clocal(v: u32) -> bool { (v >> 18) & 1 != 0 }
#[inline]
pub const fn fbzcp_cca_mselect(v: u32) -> u32 { (v >> 19) & 7 }
#[inline]
pub const fn fbzcp_cca_reverse_blend(v: u32) -> bool { (v >> 22) & 1 != 0 }
#[inline]
pub const fn fbzcp_cca_add_aclocal(v: u32) -> bool { (v >> 23) & 3 != 0 }
#[inline]
pub const fn fbzcp_cca_invert_output(v: u32) -> bool { (v >> 25) & 1 != 0 }
#[inline]
pub const fn fbzcp_cca_subpixel_adjust(v: u32) -> bool { (v >> 26) & 1 != 0 }
#[inline]
pub const fn fbzcp_texture_enable(v: u32) -> bool { (v >> 27) & 1 != 0 }
#[inline]
pub const fn fbzcp_rgbzw_clamp(v: u32) -> bool { (v >> 28) & 1 != 0 }

// ---- fbzMode (the rest) ----
#[inline]
pub const fn fbzmode_enable_clipping(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn fbzmode_enable_chromakey(v: u32) -> bool { (v >> 1) & 1 != 0 }
#[inline]
pub const fn fbzmode_enable_stipple(v: u32) -> bool { (v >> 2) & 1 != 0 }
#[inline]
pub const fn fbzmode_wbuffer_select(v: u32) -> bool { (v >> 3) & 1 != 0 }
#[inline]
pub const fn fbzmode_enable_depthbuf(v: u32) -> bool { (v >> 4) & 1 != 0 }
#[inline]
pub const fn fbzmode_depth_function(v: u32) -> u32 { (v >> 5) & 7 }
#[inline]
pub const fn fbzmode_dither_type(v: u32) -> u32 { (v >> 11) & 1 }
#[inline]
pub const fn fbzmode_stipple_pattern(v: u32) -> u32 { (v >> 12) & 1 }
#[inline]
pub const fn fbzmode_enable_alpha_mask(v: u32) -> bool { (v >> 13) & 1 != 0 }
#[inline]
pub const fn fbzmode_enable_depth_bias(v: u32) -> bool { (v >> 16) & 1 != 0 }
#[inline]
pub const fn fbzmode_alpha_dither_subtract(v: u32) -> bool { (v >> 19) & 1 != 0 }
#[inline]
pub const fn fbzmode_depth_source_compare(v: u32) -> bool { (v >> 20) & 1 != 0 }
#[inline]
pub const fn fbzmode_depth_float_select(v: u32) -> bool { (v >> 21) & 1 != 0 }

// ---- alphaMode ----
#[inline]
pub const fn alphamode_alphatest(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn alphamode_alphafunction(v: u32) -> u32 { (v >> 1) & 7 }
#[inline]
pub const fn alphamode_alphablend(v: u32) -> bool { (v >> 4) & 1 != 0 }
#[inline]
pub const fn alphamode_srcrgbblend(v: u32) -> u32 { (v >> 8) & 15 }
#[inline]
pub const fn alphamode_dstrgbblend(v: u32) -> u32 { (v >> 12) & 15 }
#[inline]
pub const fn alphamode_srcalphablend(v: u32) -> u32 { (v >> 16) & 15 }
#[inline]
pub const fn alphamode_dstalphablend(v: u32) -> u32 { (v >> 20) & 15 }
#[inline]
pub const fn alphamode_alpharef(v: u32) -> u32 { (v >> 24) & 0xff }

// ---- fogMode ----
#[inline]
pub const fn fogmode_enable_fog(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn fogmode_fog_add(v: u32) -> bool { (v >> 1) & 1 != 0 }
#[inline]
pub const fn fogmode_fog_mult(v: u32) -> bool { (v >> 2) & 1 != 0 }
#[inline]
pub const fn fogmode_fog_zalpha(v: u32) -> u32 { (v >> 3) & 3 }
#[inline]
pub const fn fogmode_fog_constant(v: u32) -> bool { (v >> 5) & 1 != 0 }
#[inline]
pub const fn fogmode_fog_dither(v: u32) -> bool { (v >> 6) & 1 != 0 }
#[inline]
pub const fn fogmode_fog_zones(v: u32) -> bool { (v >> 7) & 1 != 0 }

// ---- textureMode ----
#[inline]
pub const fn texmode_enable_perspective(v: u32) -> bool { v & 1 != 0 }
#[inline]
pub const fn texmode_minification_filter(v: u32) -> bool { (v >> 1) & 1 != 0 }
#[inline]
pub const fn texmode_magnification_filter(v: u32) -> bool { (v >> 2) & 1 != 0 }
#[inline]
pub const fn texmode_clamp_neg_w(v: u32) -> bool { (v >> 3) & 1 != 0 }
#[inline]
pub const fn texmode_enable_lod_dither(v: u32) -> bool { (v >> 4) & 1 != 0 }
#[inline]
pub const fn texmode_ncc_table_select(v: u32) -> u32 { (v >> 5) & 1 }
#[inline]
pub const fn texmode_clamp_s(v: u32) -> bool { (v >> 6) & 1 != 0 }
#[inline]
pub const fn texmode_clamp_t(v: u32) -> bool { (v >> 7) & 1 != 0 }
#[inline]
pub const fn texmode_format(v: u32) -> u32 { (v >> 8) & 0xf }
#[inline]
pub const fn texmode_tc_zero_other(v: u32) -> bool { (v >> 12) & 1 != 0 }
#[inline]
pub const fn texmode_tc_sub_clocal(v: u32) -> bool { (v >> 13) & 1 != 0 }
#[inline]
pub const fn texmode_tc_mselect(v: u32) -> u32 { (v >> 14) & 7 }
#[inline]
pub const fn texmode_tc_reverse_blend(v: u32) -> bool { (v >> 17) & 1 != 0 }
#[inline]
pub const fn texmode_tc_add_aclocal(v: u32) -> u32 { (v >> 18) & 3 }
#[inline]
pub const fn texmode_tc_invert_output(v: u32) -> bool { (v >> 20) & 1 != 0 }
#[inline]
pub const fn texmode_tca_zero_other(v: u32) -> bool { (v >> 21) & 1 != 0 }
#[inline]
pub const fn texmode_tca_sub_clocal(v: u32) -> bool { (v >> 22) & 1 != 0 }
#[inline]
pub const fn texmode_tca_mselect(v: u32) -> u32 { (v >> 23) & 7 }
#[inline]
pub const fn texmode_tca_reverse_blend(v: u32) -> bool { (v >> 26) & 1 != 0 }
#[inline]
pub const fn texmode_tca_add_aclocal(v: u32) -> bool { (v >> 27) & 3 != 0 }
#[inline]
pub const fn texmode_tca_invert_output(v: u32) -> bool { (v >> 29) & 1 != 0 }
#[inline]
pub const fn texmode_seq_8_downld(v: u32) -> bool { (v >> 31) & 1 != 0 }

// ---- tLOD / tDetail ----
#[inline]
pub const fn texlod_lodmin(v: u32) -> u32 { v & 0x3f }
#[inline]
pub const fn texlod_lodmax(v: u32) -> u32 { (v >> 6) & 0x3f }
#[inline]
pub const fn texlod_lodbias(v: u32) -> u32 { (v >> 12) & 0x3f }
#[inline]
pub const fn texlod_lod_odd(v: u32) -> bool { (v >> 18) & 1 != 0 }
#[inline]
pub const fn texlod_lod_tsplit(v: u32) -> bool { (v >> 19) & 1 != 0 }
#[inline]
pub const fn texlod_lod_s_is_wider(v: u32) -> bool { (v >> 20) & 1 != 0 }
#[inline]
pub const fn texlod_lod_aspect(v: u32) -> u32 { (v >> 21) & 3 }
#[inline]
pub const fn texlod_tmultibaseaddr(v: u32) -> bool { (v >> 24) & 1 != 0 }
#[inline]
pub const fn texlod_tdata_swizzle(v: u32) -> bool { (v >> 25) & 1 != 0 }
#[inline]
pub const fn texlod_tdata_swap(v: u32) -> bool { (v >> 26) & 1 != 0 }

#[inline]
pub const fn texdetail_detail_max(v: u32) -> i32 { (v & 0xff) as i32 }
#[inline]
pub const fn texdetail_detail_bias(v: u32) -> u32 { (v >> 8) & 0x3f }
#[inline]
pub const fn texdetail_detail_scale(v: u32) -> u32 { (v >> 14) & 7 }

#[inline]
pub const fn fbiinit1_video_timing_reset(v: u32) -> bool { (v >> 8) & 1 != 0 }
#[inline]
pub const fn fbiinit1_software_blank(v: u32) -> bool { (v >> 12) & 1 != 0 }

// ---- chromaRange ----
#[inline]
pub const fn chromarange_blue_exclusive(v: u32) -> bool { (v >> 24) & 1 != 0 }
#[inline]
pub const fn chromarange_green_exclusive(v: u32) -> bool { (v >> 25) & 1 != 0 }
#[inline]
pub const fn chromarange_red_exclusive(v: u32) -> bool { (v >> 26) & 1 != 0 }
#[inline]
pub const fn chromarange_union_mode(v: u32) -> bool { (v >> 27) & 1 != 0 }
#[inline]
pub const fn chromarange_enable(v: u32) -> bool { (v >> 28) & 1 != 0 }

#[inline]
pub const fn lfbmode_write_w_select(v: u32) -> bool { (v >> 14) & 1 != 0 }
