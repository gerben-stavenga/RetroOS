# voodoo — 3dfx Voodoo Graphics (SST-1) as a passive card

## Derivation

This crate is a Rust transliteration of **Aaron Giles' Voodoo emulation from
MAME** (`src/devices/video/voodoo.cpp`, `voodoo_render.cpp`,
`voodoo_regs.h`) — license `BSD-3-Clause`, copyright Aaron Giles.

The rasterizer, texture unit and pixel pipeline (`raster.rs`, `texture.rs`,
`rgba.rs`) follow MAME's modern factoring closely and deliberately —
`stipple_test`, `compute_depthval`, `depth_test`, `combine_color`,
`alpha_test`, `chroma_key_test`, `apply_fogging`, `alpha_blend`,
`write_pixel`, `rasterizer_texture::{recompute, fetch_texel,
combine_texture}` — so the two can be read side by side when a behaviour is
in question.

Register decode, the video-memory layout and the LFB window (`regs.rs`,
`fbi.rs`, `lfb.rs`) were transliterated from the same code as it appears in
DOSBox Staging's `voodoo.cpp`, which carries the older MAME core plus DOSBox
integration by kekko and Bernhard Schelling under `BSD-3-Clause AND
GPL-2.0-or-later`. Those parts are the Giles original in substance; none of
the GPL-carrying DOSBox glue (threading, SDL, `PIC_`/`RENDER_` calls, config
sections) is present here, and MAME is the reference we track.

Nothing is copied verbatim — the code is rewritten against a different memory
and ownership model (see below) — but it is unambiguously a derived work and
is credited as such.

## What makes it "passive"

The same contract as `//lib:sound`, restated for a graphics card:

- **Memory is an argument, not a member.** Video memory — the 2 or 4 MB the
  guest maps through the PCI BAR — is passed in per call:
  `write(&mut self, fb: &mut [u8], ...)`, `render(&self, fb: &[u8], out: &mut
  [u32], pitch)`. The card holds *offsets* into it (which buffer is front,
  where the aux buffer begins), never a pointer. A host that maps that memory
  straight into the guest's address space and one that keeps it in a `Vec`
  are indistinguishable from in here.
- **No clock.** Anything time-dependent is an argument: `read(..., in_vretrace)`.
- **Events are reported, not delivered.** A register write returns `Events`
  ("the guest swapped buffers"); the host decides whether that means present a
  frame, raise an interrupt, or nothing.
- **No presentation policy.** `render` decodes the visible buffer into a plain
  RGB slice. Scaling, pacing and where it lands are the host's.

## Status

A complete SST-1, in the sense that everything which can change a pixel is
ported:

- **Registers** — decode, the alias map, per-register access rights, the
  fbiInit-driven memory layout, `initEnable` gating, the DAC.
- **Display** — retrace-synchronised buffer swapping (`swapbufferCMD` bit 0
  and its interval, with `swaps_pending` visible in `status`), the `vRetrace`
  register, the 33-entry CLUT, software blank, and scanout.
- **Rasterizer** — triangle setup with subpixel adjustment, span walking,
  stipple (both modes), depth testing against Z or W with float-Z and bias,
  the colour path in full, chroma key including range mode, alpha test and
  alpha mask, fog (table with zones and dither, iterated A/Z/W, constant),
  alpha blending with every source and destination factor, and dithered 5-6-5
  writes.
- **Texturing** — both TMUs, LOD layout and selection, point-sampled and
  bilinear fetch, the perspective divide, every texel format including NCC
  and the palette tables, the texture combine unit, and texture downloads.
- **LFB** — reads, raw writes (dithered, as on the chip), and the full
  pixel-pipeline write path.

**Not modelled: FIFO timing.** Commands complete inside the write that issues
them and the FIFO-free fields in `status` always read empty, so a guest never
stalls on us. This is a deliberate omission — it changes *when* work happens,
never what the frame looks like — and it is the one place where a game that
measures the card's speed could tell the difference.

The Voodoo 2 additions (the `sSetupMode` setup unit, `cmdFifo`, the 2D
blitter) are absent; `Kind` exists so they can land as match arms rather than
as a fork.
