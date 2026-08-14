//! `//third_party/voodoo` — a 3dfx Voodoo Graphics (SST-1) as a passive,
//! host-agnostic state machine.
//!
//! **Derived from** Aaron Giles' Voodoo emulation in MAME (`voodoo.cpp`,
//! `voodoo_render.cpp`, `voodoo_regs.h`; BSD-3-Clause). Function, register and
//! field names are kept identical to the C so the two can be read side by
//! side. See `third_party/voodoo/README.md` for the licence and the full
//! derivation.
//!
//! # The contract
//!
//! Same discipline as `//lib:sound`: nothing here reaches out, and the card
//! never owns memory the guest can see.
//!
//!  - **registers** — [`Voodoo::write`] / [`Voodoo::read`] are functions of
//!    card state and the memory handed in, nothing else.
//!  - **memory is an argument.** Video memory (the 2/4 MB the guest maps
//!    through the PCI BAR) and the per-TMU texture memory are passed in per
//!    call as `&[u8]` / `&mut [u8]`. The card knows *offsets* — which buffer is
//!    front, where the aux buffer starts — never an address. A host that maps
//!    that memory straight into the guest's address space and a host that
//!    keeps it in a `Vec` look identical from in here.
//!  - **presentation is the host's** — [`Voodoo::render`] decodes the visible
//!    buffer into a plain RGB pixel slice. Where that slice goes, and when,
//!    is not a property of the card.
//!  - **events are reported, not delivered** — a write returns [`Events`]
//!    saying "the guest swapped buffers" or "the display mode changed"; the
//!    host decides what that means.
//!
//! # What is here
//!
//! A complete SST-1: register decode and access rights, the fbiInit-driven
//! memory layout, retrace-synchronised buffer swapping, `fastfill`, the linear
//! frame buffer window in both its raw and pixel-pipeline forms, the CLUT and
//! scanout, and the rasterizer — triangle setup, both TMUs, the colour path,
//! chroma key, alpha, fog, blending and dithering.
//!
//! **Not modelled**: FIFO *timing*. Every command completes inside the write
//! that issued it, and the FIFO-free fields in `status` always read empty, so
//! a guest never stalls on us. Nothing about the pixels depends on it. The
//! Voodoo 2 additions (the setup unit, `cmdFifo`, the 2D blitter) are absent
//! by design — [`Kind`] exists so they land as match arms, not as a fork.

#![cfg_attr(not(test), no_std)]
// Register names are the hardware's, kept identical to `voodoo.cpp`.
#![allow(non_upper_case_globals)]

pub mod fbi;
pub mod lfb;
pub mod raster;
mod reciplog;
pub use reciplog::fast_reciplog;
pub mod regs;
pub mod rgba;
pub mod texture;

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
mod tests;

use fbi::{Clut, Fbi};
pub use fbi::Dac;
use raster::{FogTable, Poly, Scene, TexIter};
use regs::*;
use texture::Texture;

/// Triangle setup registers, decoded into the internal fixed-point forms the
/// rasterizer wants (the `fbi_state` setup fields in the C).
#[derive(Debug, Default, Clone, Copy)]
struct Setup {
    ax: i32, ay: i32,
    bx: i32, by: i32,
    cx: i32, cy: i32,
    startr: i32, startg: i32, startb: i32, starta: i32, startz: i32,
    drdx: i32, dgdx: i32, dbdx: i32, dadx: i32, dzdx: i32,
    drdy: i32, dgdy: i32, dbdy: i32, dady: i32, dzdy: i32,
    startw: i64, dwdx: i64, dwdy: i64,
}

/// `float_to_int32` — the "f" register aliases carry IEEE floats.
///
/// Integer only, and deliberately so: this runs inside the MMIO fault handler,
/// where the guest's x87 stack is LIVE. This target has no SSE, so `f32`
/// arithmetic here compiles to x87 and executes on that stack — Glide keeps
/// its triangle gradients there across the very `fstp`s that land here, and
/// the values it stored afterwards came back as the x87 indefinite QNaN.
/// Shifting the mantissa by the exponent is what the C does anyway.
#[inline]
fn float_to_int32(data: u32, fixedbits: i32) -> i32 {
    const MAX_SHIFT: i32 = i32::BITS as i32;
    let exponent = (((data >> 23) & 0xff) as i32 - 127 - 23 + fixedbits)
        .clamp(-MAX_SHIFT, MAX_SHIFT);
    let mantissa = ((data & 0x7f_ffff) | 0x80_0000) as i64;
    let result = if exponent < 0 {
        if exponent > -MAX_SHIFT { (mantissa >> -exponent) as i32 } else { 0 }
    } else {
        (mantissa << exponent).clamp(i32::MIN as i64, i32::MAX as i64) as i32
    };
    if data & 0x8000_0000 != 0 { result.wrapping_neg() } else { result }
}

/// The same, in the 16.32 width the S/T/W iterators are kept at.
#[inline]
fn float_to_int64(data: u32, fixedbits: i32) -> i64 {
    let exponent = ((data >> 23) & 0xff) as i32 - 127 - 23 + fixedbits;
    let mantissa = ((data & 0x7f_ffff) | 0x80_0000) as i64;
    let result = if exponent < 0 {
        if exponent > -64 { mantissa >> -exponent } else { 0 }
    } else if exponent < 64 {
        mantissa << exponent
    } else {
        i64::MAX
    };
    if data & 0x8000_0000 != 0 { result.wrapping_neg() } else { result }
}

/// Which card this is. Only [`Kind::Voodoo1`] is implemented; the enum exists
/// so the Voodoo 2 differences land as `match` arms rather than as a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Voodoo1,
}

/// What a register write asked the host to do. All false is the common case.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Events {
    /// The guest swapped buffers: a new frame is ready to present.
    pub swap: bool,
    /// Display dimensions or the output-enable state changed.
    pub video_mode_changed: bool,
}

/// Where the display beam is. The card has no clock of its own, so the host
/// says — the same rule the sound cards follow for their sample clock.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Beam {
    /// Inside the vertical blanking interval.
    pub in_vblank: bool,
    /// Current scanline, reported by `vRetrace` outside of blanking.
    pub vpos: u16,
}

impl Events {
    pub fn any(&self) -> bool {
        self.swap || self.video_mode_changed
    }
}

/// Address decode within the card's 16 MB PCI aperture (`voodoo_w`).
const OFFSET_MASK: u32 = 0x3f_ffff;
const OFFSET_BASE: u32 = 0xc0_0000 / 4;
const LFB_BASE: u32 = 0x80_0000 / 4;

pub struct Voodoo {
    pub kind: Kind,
    /// Raw register file, indexed by dword register number.
    pub reg: [u32; 0x400],
    pub fbi: Fbi,

    dac: [u8; 8],
    dac_read_result: u8,

    /// `initEnable`, written by the host from PCI config space (offset 0x40).
    init_enable: u32,
    chipmask: u8,
    alt_regmap: bool,

    /// VGA pass-through off, i.e. the Voodoo drives the monitor.
    pub output_on: bool,
    pub send_config: bool,
    pub tmu_config: u32,

    /// Deferred-swap state: `swapbufferCMD` can ask to wait for retrace.
    vblank_swap_pending: bool,
    vblank_swap: u8,
    vblank_count: u8,
    swaps_pending: u32,

    setup: Setup,
    /// Per-TMU register files and iterated S/T/W.
    tmureg: [[u32; 0x400]; 2],
    tmuiter: [TexIter; 2],
    tex: [Texture; 2],
    fog: FogTable,
    clut: Clut,
}

impl Voodoo {
    /// `fb_bytes` and `tex_bytes` are the sizes of the video and per-TMU
    /// texture memory the host will hand to every call — 2 MB and 2 MB on a
    /// real SST-1, powers of two either way. Only the sizes live here; the
    /// memory itself is an argument to every call that touches it.
    pub fn new(kind: Kind, fb_bytes: usize, tex_bytes: usize) -> Self {
        debug_assert!(fb_bytes.is_power_of_two());
        Self {
            kind,
            reg: [0; 0x400],
            fbi: Fbi::new(fb_bytes),
            dac: [0; 8],
            dac_read_result: 0,
            init_enable: 0,
            // FBI plus one TMU, which is what an SST-1 board carries.
            chipmask: 0x03,
            alt_regmap: false,
            output_on: false,
            send_config: false,
            tmu_config: 0x11,
            vblank_swap_pending: false,
            vblank_swap: 0,
            vblank_count: 0,
            swaps_pending: 0,
            setup: Setup::default(),
            tmureg: [[0; 0x400]; 2],
            tmuiter: [TexIter::default(); 2],
            tex: [Texture::new(tex_bytes), Texture::new(tex_bytes)],
            fog: FogTable::default(),
            clut: Clut::new(),
        }
    }

    /// PCI config-space `initEnable` (offset 0x40): it gates the fbiInit
    /// registers and remaps `fbiInit2` reads onto the DAC.
    pub fn set_init_enable(&mut self, value: u32) {
        self.init_enable = value;
    }

    /// A guest dword write anywhere in the card's aperture.
    ///
    /// `tex` is the per-TMU texture memory, `tex[0]` and `tex[1]`; pass an
    /// empty slice for a board with no TMU wired up.
    pub fn write(
        &mut self,
        fb: &mut [u8],
        tex: &mut [&mut [u8]],
        addr: u32,
        data: u32,
        mask: u32,
    ) -> Events {
        // Nothing may overtake a swap the guest has already asked for. On the
        // board the memory FIFO holds every command behind `swapbufferCMD`
        // until the retrace retires it; here the swap is deferred to a host
        // vblank while the writes behind it would otherwise execute at once —
        // so the next frame's `grBufferClear` erased the buffer about to be
        // shown, and every other presented frame came out black. Retiring the
        // swap first restores the order the FIFO guaranteed.
        let mut events = Events::default();
        if self.vblank_swap_pending {
            self.swap_buffers();
            events.swap = true;
        }
        let offset = (addr >> 2) & OFFSET_MASK;
        let inner = if offset & OFFSET_BASE == 0 {
            self.register_w(fb, tex, offset, data)
        } else if offset & LFB_BASE == 0 {
            // The pipelined LFB path needs the same register snapshot a
            // triangle does; building it is cheap next to the write itself.
            let poly = self.snapshot();
            lfb::write(&self.fbi, &mut self.reg, fb, offset, data, mask, &poly, &self.fog);
            Events::default()
        } else {
            self.texture_w(tex, offset, data);
            Events::default()
        };
        events.swap |= inner.swap;
        events.video_mode_changed |= inner.video_mode_changed;
        events
    }

    /// A guest dword read. `beam` is the host's display clock — the card does
    /// not have one (the same rule as `Engine::mix_frame`'s rate).
    pub fn read(&self, fb: &[u8], addr: u32, beam: Beam) -> u32 {
        let offset = (addr >> 2) & OFFSET_MASK;
        if offset & OFFSET_BASE == 0 {
            self.register_r(offset, beam)
        } else if offset & LFB_BASE == 0 {
            lfb::read(&self.fbi, &self.reg, fb, offset)
        } else {
            0xffff_ffff
        }
    }

    /// Decode the visible buffer into `out` as one 0x00RRGGBB word per pixel,
    /// `out_pitch` words per row. `out` is the host's; the card never keeps it.
    pub fn render(&self, fb: &[u8], dac: &Dac, out: &mut [u8], out_pitch: usize) {
        // `fbiInit1` bit 12 blanks the display without disturbing memory.
        if fbiinit1_software_blank(self.reg[fbiInit1]) {
            for p in out.iter_mut() {
                *p = 0;
            }
            return;
        }
        self.fbi.scanout(fb, &self.clut, dac, out, out_pitch);
    }

    /// Scan out without applying the SST-1 CLUT. Used when a programmable
    /// physical RAMDAC applies the expanded CLUT after reading the surface.
    pub fn render_raw(&self, fb: &[u8], dac: &Dac, out: &mut [u8], out_pitch: usize) {
        if fbiinit1_software_blank(self.reg[fbiInit1]) {
            out.fill(0);
            return;
        }
        self.fbi.scanout(fb, &Clut::new(), dac, out, out_pitch);
    }

    pub fn vbe_ramp(&self, out: &mut [u8; 256 * 4]) -> u64 {
        self.clut.vbe_ramp(out);
        self.clut.generation()
    }

    /// The host tells the card a vertical retrace began. Returns the events
    /// it caused — a deferred `swapbufferCMD` completing, most of the time.
    pub fn vblank(&mut self) -> Events {
        self.vblank_count = self.vblank_count.saturating_add(1).min(250);
        if self.vblank_swap_pending && self.vblank_count >= self.vblank_swap {
            self.swap_buffers();
            return Events { swap: true, ..Default::default() };
        }
        Events::default()
    }

    /// `swap_buffers` — rotate the buffers and record the interval.
    fn swap_buffers(&mut self) {
        // A history of swap intervals, four bits each.
        self.reg[fbiSwapHistory] =
            (self.reg[fbiSwapHistory] << 4) | (self.vblank_count.min(15) as u32);
        self.fbi.swap_buffers();
        self.swaps_pending = self.swaps_pending.saturating_sub(1);
        self.vblank_count = 0;
        self.vblank_swap_pending = false;
    }

    /// Visible resolution the guest has programmed.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.fbi.width, self.fbi.height)
    }

    /// `texture_w` — a dword written into the TMU aperture.
    fn texture_w(&mut self, tex: &mut [&mut [u8]], offset: u32, data: u32) {
        let tmu_num = ((offset >> 19) & 3) as usize;
        if tmu_num >= 2 || self.chipmask & (2 << tmu_num) == 0 {
            return;
        }
        if self.tex[tmu_num].regdirty {
            let regs = self.tmureg[tmu_num];
            self.tex[tmu_num].recompute(&regs);
        }
        let Some(ram) = tex.get_mut(tmu_num) else { return };

        let texlod = self.tmureg[tmu_num][tLOD];
        let mut data = data;
        if texlod_tdata_swizzle(texlod) {
            data = data.swap_bytes();
        }
        if texlod_tdata_swap(texlod) {
            data = data.rotate_left(16);
        }

        let texmode = self.tmureg[tmu_num][textureMode];
        let bytes_per_texel = if texmode_format(texmode) < 8 { 1 } else { 2 };

        let lod = ((offset >> 15) & 0x0f) as usize;
        if lod > 8 {
            return;
        }
        let tt = (offset >> 7) & 0xff;
        // Sequential 8-bit downloads pack four texels per dword.
        // Sequential 8-bit downloads pack four texels per dword. The masks
        // differ per texel width and are NOT 0xff: an 8-bit row advances four
        // texels per dword (0xfc), a 16-bit row two (0xfe).
        let seq_8 = texmode_seq_8_downld(self.tmureg[0][textureMode]);
        let ts = if bytes_per_texel == 1 {
            (offset << if seq_8 { 2 } else { 1 }) & 0xfc
        } else {
            (offset << 1) & 0xfe
        };

        let addr = self.tex[tmu_num].write_offset(lod, ts, tt, bytes_per_texel) as usize;
        for i in 0..4 {
            if addr + i < ram.len() {
                ram[addr + i] = ((data >> (i * 8)) & 0xff) as u8;
            }
        }
    }

    fn register_w(
        &mut self,
        fb: &mut [u8],
        tex: &mut [&mut [u8]],
        offset: u32,
        data: u32,
    ) -> Events {
        let mut chips = ((offset >> 8) & 0xf) as u8;
        if chips == 0 {
            chips = 0xf;
        }
        chips &= self.chipmask;

        // The first 64 registers can be aliased differently.
        let is_aliased = (offset & 0x800c0) == 0x80000 && self.alt_regmap;
        let regnum = if is_aliased {
            REGISTER_ALIAS_MAP[(offset & 0x3f) as usize] as usize
        } else {
            (offset & 0xff) as usize
        };

        if VOODOO_REGISTER_ACCESS[regnum] & REGISTER_WRITE == 0 {
            return Events::default();
        }

        let mut events = Events::default();
        let fbi_chip = chips & 1 != 0;

        match regnum {
            nopCMD => {
                if data & 1 != 0 {
                    self.reset_counters();
                }
                if data & 2 != 0 {
                    self.reg[fbiTrianglesOut] = 0;
                }
            }

            fastfillCMD => self.fbi.fastfill(&self.reg, fb),

            swapbufferCMD => {
                // Bit 0 asks for the swap to wait for vertical retrace; bits
                // 1-8 are how many retraces to wait for. A game that polls
                // `status` for pending swaps throttles itself on this, so the
                // wait has to be real — the host reports the retrace by
                // calling `vblank`.
                self.swaps_pending = self.swaps_pending.saturating_add(1);
                self.vblank_swap = ((data >> 1) & 0xff) as u8;
                self.fbi.vblank_dont_swap = (data >> 9) & 1 != 0;
                if data & 1 == 0 {
                    self.swap_buffers();
                    events.swap = true;
                } else {
                    self.vblank_swap_pending = true;
                }
            }

            triangleCMD | ftriangleCMD => {
                self.reg[fbiTrianglesOut] = self.reg[fbiTrianglesOut].wrapping_add(1);
                self.draw_triangle(fb, tex);
            }

            // Vertex data is 12.4 fixed point.
            vertexAx..=vertexCy | fvertexAx..=fvertexCy => {
                let (regnum, v) = if regnum >= fvertexAx {
                    // The floating aliases feed the same physical 16-bit
                    // 12.4 registers. Glide relies on that width for its
                    // snapping trick: it adds 3<<18 to a coordinate and the
                    // bias disappears at this truncation boundary.
                    (regnum - 0x20, float_to_int32(data, 4) as i16 as i32)
                } else {
                    (regnum, data as i16 as i32)
                };
                if fbi_chip {
                    let s = &mut self.setup;
                    match regnum {
                        vertexAx => s.ax = v,
                        vertexAy => s.ay = v,
                        vertexBx => s.bx = v,
                        vertexBy => s.by = v,
                        vertexCx => s.cx = v,
                        _ => s.cy = v,
                    }
                }
            }

            // Iterated R/G/B/A/Z are 12.12; S/T are 14.18 and W is 2.30, both
            // held internally as 16.32.
            startR..=dWdY | fstartR..=fdWdY => {
                let is_float = regnum >= fstartR;
                let regnum = if is_float { regnum - 0x20 } else { regnum };
                self.write_iterated(regnum, data, is_float, chips);
            }

            // Texture registers live in the TMU that claimed the write.
            textureMode..=texBaseAddr_3_8 => {
                for i in 0..2 {
                    if chips & (2 << i) != 0 {
                        self.tmureg[i][regnum] = data;
                        self.tex[i].regdirty = true;
                    }
                }
            }

            // NCC / palette tables, 24 registers per TMU.
            r if (nccTable..nccTable + 24).contains(&r) => {
                for i in 0..2 {
                    if chips & (2 << i) != 0 {
                        self.tex[i].ncc_w(r - nccTable, data);
                    }
                }
            }

            // Fog table: two entries per register.
            r if (fogTable..fogTable + 32).contains(&r) => {
                if fbi_chip {
                    let base = (r - fogTable) * 2;
                    self.fog.delta[base] = (data & 0xff) as u8;
                    self.fog.blend[base] = ((data >> 8) & 0xff) as u8;
                    self.fog.delta[base + 1] = ((data >> 16) & 0xff) as u8;
                    self.fog.blend[base + 1] = ((data >> 24) & 0xff) as u8;
                }
            }

            hSync | vSync | backPorch | videoDimensions => {
                if fbi_chip {
                    self.reg[regnum] = data;
                    if self.reg[hSync] != 0
                        && self.reg[vSync] != 0
                        && self.reg[videoDimensions] != 0
                    {
                        let hvis = self.reg[videoDimensions] & 0x3ff;
                        let vvis = (self.reg[videoDimensions] >> 16) & 0x3ff;
                        let new_width = (hvis + 1) & !1;
                        let new_height = (vvis + 1) & !1;
                        if self.fbi.width != new_width || self.fbi.height != new_height {
                            self.fbi.width = new_width;
                            self.fbi.height = new_height;
                            events.video_mode_changed = true;
                        }
                        if regnum == videoDimensions {
                            self.fbi.recompute_video_memory(&self.reg);
                        }
                    }
                }
            }

            fbiInit0 => {
                if fbi_chip && initen_enable_hw_init(self.init_enable) {
                    let new_output_on = fbiinit0_vga_passthru(data);
                    if self.output_on != new_output_on {
                        self.output_on = new_output_on;
                        events.video_mode_changed = true;
                    }
                    self.reg[fbiInit0] = data;
                    if fbiinit0_graphics_reset(data) {
                        self.reset_counters();
                        self.reg[fbiTrianglesOut] = 0;
                    }
                    self.fbi.recompute_video_memory(&self.reg);
                }
            }

            fbiInit1 | fbiInit2 | fbiInit4 => {
                if fbi_chip && initen_enable_hw_init(self.init_enable) {
                    self.reg[regnum] = data;
                    self.fbi.recompute_video_memory(&self.reg);
                }
            }

            fbiInit3 => {
                if fbi_chip && initen_enable_hw_init(self.init_enable) {
                    self.reg[regnum] = data;
                    self.alt_regmap = fbiinit3_tri_register_remap(data);
                    self.fbi.yorigin = fbiinit3_yorigin_subtract(data);
                    self.fbi.recompute_video_memory(&self.reg);
                }
            }

            // Voodoo 2 only; ignored on an SST-1.
            fbiInit5 | fbiInit6 | fbiInit7 => {}

            dacData => {
                if fbi_chip {
                    let dacreg = ((data >> 8) & 7) as usize;
                    if data & 0x800 == 0 {
                        self.dac[dacreg] = (data & 0xff) as u8;
                    } else {
                        self.dac_read_result = self.dac_read(dacreg);
                    }
                }
            }

            clutData => {
                // Ignored while video timing is held in reset, as on the chip.
                if fbi_chip && !fbiinit1_video_timing_reset(self.reg[fbiInit1]) {
                    self.clut.write(data);
                }
            }

            trexInit1 => {
                self.send_config = (data >> 11) & 1 != 0;
                self.reg[regnum] = data;
            }

            _ => {
                if fbi_chip {
                    self.reg[regnum] = data;
                }
            }
        }

        events
    }

    /// One of the iterated setup registers (`startR`..`dWdY`). The FBI keeps
    /// colour, Z and W; the TMUs keep S, T and their own W.
    fn write_iterated(&mut self, regnum: usize, data: u32, is_float: bool, chips: u8) {
        let fbi_chip = chips & 1 != 0;
        // Colour and Z: 12.12 fixed point.
        let i32v = || if is_float { float_to_int32(data, 12) } else { data as i32 };
        // S and T: 14.18 in the register, 16.32 internally.
        let st = || {
            if is_float {
                float_to_int64(data, 32)
            } else {
                (data as i32 as i64) << 14
            }
        };
        // W: 2.30 in the register, 16.32 internally.
        let w = || {
            if is_float {
                float_to_int64(data, 32)
            } else {
                (data as i32 as i64) << 2
            }
        };

        let s = &mut self.setup;
        match regnum {
            startR if fbi_chip => s.startr = i32v(),
            startG if fbi_chip => s.startg = i32v(),
            startB if fbi_chip => s.startb = i32v(),
            startA if fbi_chip => s.starta = i32v(),
            startZ if fbi_chip => s.startz = i32v(),
            dRdX if fbi_chip => s.drdx = i32v(),
            dGdX if fbi_chip => s.dgdx = i32v(),
            dBdX if fbi_chip => s.dbdx = i32v(),
            dAdX if fbi_chip => s.dadx = i32v(),
            dZdX if fbi_chip => s.dzdx = i32v(),
            dRdY if fbi_chip => s.drdy = i32v(),
            dGdY if fbi_chip => s.dgdy = i32v(),
            dBdY if fbi_chip => s.dbdy = i32v(),
            dAdY if fbi_chip => s.dady = i32v(),
            dZdY if fbi_chip => s.dzdy = i32v(),
            _ => {}
        }

        // W is shared: the FBI iterates it for depth and fog, each TMU for
        // its own perspective divide.
        if matches!(regnum, startW | dWdX | dWdY) {
            let v = w();
            if fbi_chip {
                match regnum {
                    startW => self.setup.startw = v,
                    dWdX => self.setup.dwdx = v,
                    _ => self.setup.dwdy = v,
                }
            }
            for i in 0..2 {
                if chips & (2 << i) != 0 {
                    match regnum {
                        startW => self.tmuiter[i].startw = v,
                        dWdX => self.tmuiter[i].dwdx = v,
                        _ => self.tmuiter[i].dwdy = v,
                    }
                }
            }
        }

        if matches!(regnum, startS | startT | dSdX | dTdX | dSdY | dTdY) {
            let v = st();

            for i in 0..2 {
                if chips & (2 << i) != 0 {
                    let t = &mut self.tmuiter[i];
                    match regnum {
                        startS => t.starts = v,
                        startT => t.startt = v,
                        dSdX => t.dsdx = v,
                        dTdX => t.dtdx = v,
                        dSdY => t.dsdy = v,
                        _ => t.dtdy = v,
                    }
                }
            }
        }
    }

    /// Snapshot every register the pixel pipeline reads into a [`Poly`].
    ///
    /// Taking the copy up front is what makes a span a pure function: nothing
    /// downstream can observe a register the guest changed mid-primitive, and
    /// the hardware, which latches these at command time, behaves the same.
    fn snapshot(&self) -> Poly {
        let fbzmode = self.reg[fbzMode];
        let (destbase, depthbase) = (
            self.fbi
                .color_buffer(fbzmode_draw_buffer(fbzmode))
                .map(|(o, _)| o)
                .unwrap_or(0),
            self.fbi.color_buffer(2).map(|(o, _)| o),
        );
        Poly {
            destbase,
            depthbase,
            rowpixels: self.fbi.rowpixels as i32,
            yorigin: self.fbi.yorigin as i32,
            clipleft: ((self.reg[clipLeftRight] >> 16) & 0x3ff) as i32,
            clipright: (self.reg[clipLeftRight] & 0x3ff) as i32,
            cliptop: ((self.reg[clipLowYHighY] >> 16) & 0x3ff) as i32,
            clipbottom: (self.reg[clipLowYHighY] & 0x3ff) as i32,
            ax: self.setup.ax,
            ay: self.setup.ay,
            startr: self.setup.startr,
            startg: self.setup.startg,
            startb: self.setup.startb,
            starta: self.setup.starta,
            startz: self.setup.startz,
            startw: self.setup.startw,
            drdx: self.setup.drdx,
            dgdx: self.setup.dgdx,
            dbdx: self.setup.dbdx,
            dadx: self.setup.dadx,
            dzdx: self.setup.dzdx,
            dwdx: self.setup.dwdx,
            drdy: self.setup.drdy,
            dgdy: self.setup.dgdy,
            dbdy: self.setup.dbdy,
            dady: self.setup.dady,
            dzdy: self.setup.dzdy,
            dwdy: self.setup.dwdy,
            tex: [None, None],
            color0: self.reg[color0],
            color1: self.reg[color1],
            chromakey: self.reg[chromaKey],
            chromarange: self.reg[chromaRange],
            fogcolor: self.reg[fogColor],
            zacolor: self.reg[zaColor],
            stipple: self.reg[stipple],
            alpharef: alphamode_alpharef(self.reg[alphaMode]),
            lfb_write_w_select: lfbmode_write_w_select(self.reg[lfbMode]),
            fbzcp: self.reg[fbzColorPath],
            fbzmode,
            alphamode: self.reg[alphaMode],
            fogmode: self.reg[fogMode],
            texmode: [self.tmureg[0][textureMode], self.tmureg[1][textureMode]],
        }
    }

    /// Snapshot the registers and rasterize one triangle.
    fn draw_triangle(&mut self, fb: &mut [u8], tex: &mut [&mut [u8]]) {
        if self.fbi.color_buffer(fbzmode_draw_buffer(self.reg[fbzMode])).is_none() {
            return;
        }

        // Subpixel adjustment happens in the internal registers, as the
        // documentation says, so it persists into the next triangle.
        if fbzcp_cca_subpixel_adjust(self.reg[fbzColorPath]) {
            self.subpixel_adjust();
        }

        let mut poly = self.snapshot();
        let textured = fbzcp_texture_enable(self.reg[fbzColorPath]);
        for i in 0..2 {
            if textured && self.chipmask & (2 << i) != 0 {
                poly.tex[i] = Some(self.tmuiter[i]);
                if self.tex[i].regdirty {
                    let regs = self.tmureg[i];
                    self.tex[i].recompute(&regs);
                }
            }
        }

        let verts = [
            (self.setup.ax, self.setup.ay),
            (self.setup.bx, self.setup.by),
            (self.setup.cx, self.setup.cy),
        ];

        let empty: &[u8] = &[];
        let tex0: &[u8] = tex.first().map(|s| &**s).unwrap_or(empty);
        let tex1: &[u8] = tex.get(1).map(|s| &**s).unwrap_or(empty);
        let (t0, t1) = self.tex.split_at(1);
        let mut scene = Scene {
            fb,
            tex_ram: [tex0, tex1],
            textures: [&t0[0], &t1[0]],
            fog: &self.fog,
            // 0xf0 on a Voodoo 1, 0xff on a Voodoo 2.
            bilinear_mask: 0xf0,
        };
        let stats = raster::draw_triangle(&poly, verts, &mut scene);

        self.reg[fbiPixelsIn] = self.reg[fbiPixelsIn].wrapping_add(stats.pixels_in);
        self.reg[fbiPixelsOut] = self.reg[fbiPixelsOut].wrapping_add(stats.pixels_out);
        self.reg[fbiChromaFail] = self.reg[fbiChromaFail].wrapping_add(stats.chroma_fail);
        self.reg[fbiZfuncFail] = self.reg[fbiZfuncFail].wrapping_add(stats.zfunc_fail);
        self.reg[fbiAfuncFail] = self.reg[fbiAfuncFail].wrapping_add(stats.afunc_fail);
    }

    /// The documented subpixel correction, applied to the internal registers.
    fn subpixel_adjust(&mut self) {
        let dx = 8 - (self.setup.ax & 15);
        let dy = 8 - (self.setup.ay & 15);
        let s = &mut self.setup;
        s.startr += (dy * s.drdy + dx * s.drdx) >> 4;
        s.startg += (dy * s.dgdy + dx * s.dgdx) >> 4;
        s.startb += (dy * s.dbdy + dx * s.dbdx) >> 4;
        s.starta += (dy * s.dady + dx * s.dadx) >> 4;
        s.startz += (dy * s.dzdy + dx * s.dzdx) >> 4;
        s.startw += (dy as i64 * s.dwdy + dx as i64 * s.dwdx) >> 4;
        for t in &mut self.tmuiter {
            t.startw += (dy as i64 * t.dwdy + dx as i64 * t.dwdx) >> 4;
            t.starts += (dy as i64 * t.dsdy + dx as i64 * t.dsdx) >> 4;
            t.startt += (dy as i64 * t.dtdy + dx as i64 * t.dtdx) >> 4;
        }
    }

    fn dac_read(&self, regnum: usize) -> u8 {
        match regnum {
            // Just enough to make the driver's startup probe happy.
            5 => match self.dac[7] {
                0x01 => 0x55,
                0x07 => 0x71,
                0x0b => 0x79,
                _ => 0xff,
            },
            _ => self.dac[regnum],
        }
    }

    fn register_r(&self, offset: u32, beam: Beam) -> u32 {
        let regnum = (offset & 0xff) as usize;
        if VOODOO_REGISTER_ACCESS[regnum] & REGISTER_READ == 0 {
            return 0xffff_ffff;
        }

        match regnum {
            status => {
                let mut result = 0u32;
                // bits 5:0 — PCI FIFO free space (we never stall, so: empty)
                result |= 0x3f;
                // bit 6 — vertical retrace
                if beam.in_vblank {
                    result |= 0x40;
                }
                // bits 7:9 stay clear: no operation is ever pending, because
                // every command completes inside the write that issued it.
                // bits 11:10 — which buffer is visible
                result |= (self.fbi.frontbuf as u32) << 10;
                // bits 27:12 — memory FIFO free space
                result |= 0xffff << 12;
                // bits 30:28 — swaps still pending, which is how a game
                // paces itself against the display.
                result |= self.swaps_pending.min(7) << 28;
                result
            }

            // Current scanline, or 0 while blanking.
            vRetrace => {
                if beam.in_vblank {
                    0
                } else {
                    beam.vpos as u32
                }
            }

            // initEnable bit 2 maps this read onto the DAC.
            fbiInit2 => {
                if initen_remap_init_to_dac(self.init_enable) {
                    self.dac_read_result as u32
                } else {
                    self.reg[regnum]
                }
            }

            // All counters are 24-bit.
            fbiPixelsIn | fbiChromaFail | fbiZfuncFail | fbiAfuncFail | fbiPixelsOut
            | fbiTrianglesOut => self.reg[regnum] & 0xff_ffff,

            _ => self.reg[regnum],
        }
    }

    fn reset_counters(&mut self) {
        for r in [fbiPixelsIn, fbiChromaFail, fbiZfuncFail, fbiAfuncFail, fbiPixelsOut] {
            self.reg[r] = 0;
        }
    }
}
