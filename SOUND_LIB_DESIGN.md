# Sound cards as a host-agnostic library

Design for lifting the emulated sound cards (`vgus.rs`, `vsb.rs`, `opl.rs`)
out of `kernel/src/kernel/dos/machine/` into a standalone library, so that a
card is a passive state machine any emulator can drive — and so AWE32 and
MPU-401/GM are *new cards against a contract* rather than new copies of
kernel-entangled code.

Written after the GUS landed (`//lib:sampler` + `vgus.rs`) and the E1M8
mixer-pacing work.

Three constraints shape the whole thing:

- **Cards are passive.** A card never reaches out. It has exactly three
  ports: sample bytes in/out, a clock passed *as an argument*, and an IRQ
  level the host samples. No `Arch`, no `get_ticks`, no vPIC, no traits to
  implement, no callbacks to register.
- **A card never names a location.** It models the DMA registers *the guest
  programs into it* — because the guest reads those back — and nothing else.
  No guest physical address, no 8237, no page register, no host memory. It
  knows *which channel* it was latched onto, never *where that points*.
- **Accounting derives from data actually moved.** Guest-visible cursors,
  counts and terminal-count flags are computed from bytes the card really
  consumed or accepted — never synthesized from a clock the card should not
  know about.

The first two are the user-facing goal: maximal freedom to hook the library
up. The third is what makes that freedom *correct* rather than merely tidy,
and section 2.3 is the heart of the document.

## 0. What is already right

Three things do not need fixing, and the design should preserve them.

**The voice engine is already extracted.** `//lib:sampler`
(`lib/sampler/src/lib.rs`) is clock-free, memory-free and integer-only: the
caller decides how many frames to pull and supplies the sample memory. Its
header already names AWE32/EMU8000 and MT-32 as future clients, and
`VoiceFilter::apply` (`lib/sampler/src/voice.rs:74`) is a documented
pass-through stub reserved for exactly that work.

**The mixer seam already exists.** `PcmSource` (`machine/mod.rs:860`) is the
one shape every emulated device presents, and its doc comment already says
*"further sampler-backed devices (GM, AWE) join by implementing this"*. Per
the closed-set rule it stays an enum with an exhaustive match — the set of
cards RetroOS emulates is ours to close.

**The SB is already split.** `SoundBlaster` (`vsb.rs:329`) holds `emu:
EmuDsp` (`vsb.rs:188`) — the entire emulated card — beside a block of
passthrough-only fields (`dsp_test_reg` … `last_gen`) that exist solely to
drive a *real* card through the IOPB. `EmuDsp` is the thing that moves;
the passthrough wrapper is kernel business and stays put.

## 1. What leaks today

### 1.1 GUS: two calls, and neither is deep

Audit of `machine` use in `vgus.rs`:

| entry point | uses `machine` for |
|---|---|
| `io_read` (`:393`) | nothing — `let _ = machine;` |
| `reset` (`:305`) | nothing — `let _ = machine;` |
| `mix_into` (`:856`) | nothing — `_machine` |
| `io_write` (`:443`) | forwarding into `service_dma` |
| `service_dma` (`:506`) | one `machine.copy_from(gpa, &mut buf)` |
| `tick` (`:345`) | one `machine.get_ticks()` |

So the card's entire arch dependency is *read guest memory* and *what time
is it*. Plus `&mut VirtualPic` for the IRQ line — and `vpic` is itself a
pure virtual chip, not kernel policy.

That is not a deep entanglement, it is the ISA bus contract. The GUS is
ready to move almost as-is.

### 1.2 SB: the drain-clock fiction

The DSP is where the real design debt sits. Neither card actually models a
DMA transfer:

- The GUS does the **whole programmed length in one `copy_from`**, sets
  `dma_tc`, and latches the IRQ for the next tick. No pacing at all.
- The SB **never transfers anything**. `mix_dsp_into` (`vsb.rs:1202`) reads
  the guest ring lazily at mix time — only the span this chunk needs,
  clamped by `committed_end` (`vsb.rs:1274`) — and `emu_dma_read`
  (`vsb.rs:1403`) *synthesizes* the guest-visible 8237 current-count from
  `EmuDsp::cursor`, which is slaved to the sink's playback position.

The synthesis works, and it bought a real win (the pipe model took SB
latency from 116 ms to 47 ms). But it has a standing cost:

- Every register a guest might poll must be back-derived by hand. `cursor`,
  `slack`, `next_irq`, `blocks_done`/`blocks_acked`, `dma_tc`, `tc_status`
  and the commit horizon all exist to make the fiction observationally
  consistent.
- The cursor advances in coarse per-pump jumps, which is the root cause
  behind the DMA-count-coherency spin: a game polling address and count
  with a tolerance of ~64 transfers never sees a consistent pair.
- Worst of all for this document: the fiction is *the host's clock model
  leaking into the card*. A card that only makes sense when driven by our
  drain-slaved `Pace` is not a library.

The GUS carries the same latent shape — a guest polling the 8237 count
mid-upload sees it already at terminal — it simply has not bitten, because
GUS uploads are short and drivers wait for TC anyway.

### 1.3 OPL: clock only

`OplFm` (`opl.rs`) takes `now` explicitly already (`write(now, …)`,
`audible(now)`); `mix_into` takes `machine` but only to satisfy the
`PcmSource` signature. It is the easiest of the three and mostly needs
its `nuked_opl3` dependency carried across.

## 2. The card contract

### 2.1 Three ports

Every card in the library exposes the same passive surface. No trait, no
injected dependency — the host calls in, the card answers.

```rust
// ── register file ──────────────────────────────────────────────
fn owns(&self, port: u16) -> bool;
fn port_in(&mut self, port: u16) -> u8;
fn port_out(&mut self, port: u16, val: u8);

// ── clock: passed in, never read ───────────────────────────────
fn tick(&mut self, now_ms: u64);

// ── IRQ: a level the host samples, never a call outward ────────
fn irq_line(&self) -> bool;

// ── PCM: pure frame generation, no I/O of any kind ─────────────
fn mix_into(&mut self, rate: u32, block: &mut [(i32, i32)]);
```

`tick` taking its clock as an argument is the same discipline
`Engine::mix_frame` already uses for its rate. `irq_line` as a *level* the
host samples (rather than a `vpic.raise` the card performs) is what removes
the last kernel type from the signature list.

### 2.2 Sample bytes: the fourth port, in two directions

DMA becomes a byte stream with no addresses in it. The card says which
channel the guest latched onto and whether a transfer is armed; the host —
which owns the 8237 and guest memory — moves the bytes.

```rust
fn dma_channel(&self) -> Option<u8>;   // what the guest programmed
fn dma_active(&self)  -> bool;         // a transfer is armed

// GUS-shaped (sink): the card files bytes into its own DRAM, applying its
// own reg-0x41 transforms, advancing its own address, TC-ing itself.
fn dma_write(&mut self, bytes: &[u8]) -> usize;   // bytes accepted

// SB-shaped (source): the card takes PCM into its ring; its DAC consumes.
fn dma_feed(&mut self, bytes: &[u8]) -> usize;    // bytes accepted
fn consumed(&self) -> u64;                        // frames the DAC took
```

The host feeds as fast or as slowly as it likes — a byte per DRQ for a
cycle-accurate emulator, a whole block per pump for us. The card's own
counters advance by what it actually received or played, so a host that
paces differently gets correct register readback for free instead of
needing to share our timing model.

Note what is *absent*: `gpa`, `len`, page registers, `Dma8237`. The card
reports a channel number; translating that to an address is the host's job,
because only the host knows what a channel means.

### 2.3 Consumption-based accounting

**The single decision this design turns on:** the card counts bytes *its
DAC consumed*, not bytes it received.

On real hardware those are nearly the same thing — the card's FIFO is tiny
and drains at the sample rate — which is why the distinction never had to
be made explicit. In an emulator they are wildly different: the host may
feed a full pipe-depth ahead of the speaker.

Count *received* bytes and the block-completion IRQ fires when the data
arrived, i.e. a pipe-depth early. That is precisely the problem the
drain-slaved cursor was invented to solve.

Count *consumed* bytes and the IRQ fires when the audio was actually
played — by construction, with no reference to any clock. The host becomes
free to feed arbitrarily far ahead, which is the freedom we wanted, and the
guest-visible cursor becomes honest, which fixes the coherency jumpiness as
a side effect.

The happy consequence is that **this reproduces today's timing rather than
disturbing it.** `mix_into` *is* the consumption point, and the pump already
calls it paced by `Pace` (`kernel/src/kernel/sound.rs:181`), which is
already drain-slaved. Same numbers, derived from data movement instead of
synthesized from a clock the card should not know about. The SB rewrite is
therefore mostly *deletion*: `cursor`, `slack`, `next_irq` and the commit
horizon collapse into "how many frames has the DAC taken, and how many has
the host fed".

The one genuinely new obligation is underrun. Today an unserviced ring
replays stale data via `committed_end`; under the new model the card has
simply not been fed, so it must reproduce the same guest-visible behaviour
(a real card keeps cycling its ring and replays) rather than falling silent.

## 3. What stays kernel-side

The split is "spatial and temporal facts belong to the host":

- **The 8237** (`vdma.rs`), page registers, and every guest physical
  address. The host reads `dma_channel()`, decodes its own controller,
  performs `copy_from`, and reconstructs the guest-visible count from what
  the card reports.
- **The vPIC** (`vpic.rs`). The host samples `irq_line()` and drives its
  own interrupt controller.
- **The clock.** `machine.get_ticks()` is read once per `audio_tick` and
  passed down.
- **Configuration discovery.** `configure_from_env` for `ULTRASND=`
  (`vgus.rs:279`) and `BLASTER=` (`vsb.rs:846`) is DOS-personality policy;
  the library takes base/irq/dma as plain constructor arguments.
- **The SB passthrough path** in its entirety — real 8237 programming, the
  DMA alias binding, `platform::get().audio.sb_passthrough()`, IOPB. This
  cannot be a library concern; it is the kernel driving real hardware.
- **The mixer pump** — `audio_tick` (`machine/mod.rs:935`), `Mixer`
  (`:910`), `MIX_RATE`, `Pace`, and the sink routing in
  `kernel/src/kernel/sound.rs`. Which sink to play into is machine policy.
- **Diagnostics with statics** — the F12 GUS trace ring (`vgus.rs:887`) and
  `PORT_TRACE`. A library card should not own mutable globals; if the ring
  survives, it wraps the card at the call site.

Open question, deliberately not decided here: the per-card mix scale
constants (`FM_SCALE_Q16`, `DAC_SCALE_Q16`, `GUS_SCALE_Q16`,
`OUTPUT_GAIN_Q16`, `vsb.rs:67-88`) are *relative level* facts between
cards, sourced from 86Box. They are arguably library data (a card's output
level is a property of the card) but only mean anything as a set. Suggest
each card exposes its own scale and the host owns the master gain.

## 4. Crate layout

Grow `//lib:sampler` into `//lib:sound`:

```
lib/sound/src/
  lib.rs        // re-exports; the PcmSource-shaped card surface
  engine/       // today's sampler: engine, voice, volume
  format.rs     // today's sound::Format (a wire decoder, not kernel policy)
  gus.rs        // GF1
  sb.rs         // DSP + CT1745 mixer (today's EmuDsp + SbMixer)
  opl.rs        // nuked-opl3 wrapper
  awe.rs        // EMU8000                      (new)
  midi.rs       // MIDI channel state + voice allocation (new)
  mpu401.rs     // UART/intelligent mode        (new)
```

One crate, not two. The `-Copt-level=2` justification in the current
`lib/BUILD.bazel` (the 44.1 kHz × 32-voice mix loop, versus `//lib`'s `-z`)
covers the whole thing, and the engine remains the bulk of the code.
Register decode is not hot but does not object to being optimised.

`sound::Format` moves down; `sound::Pace` does not (it is sink policy).

## 5. Migration order

1. **GUS pilot.** Two arch calls, mechanical. Move `Gus`/`GusCore` to
   `lib/sound/src/gus.rs`, convert `service_dma` to `dma_write`, `tick` to
   take `now_ms`, `deliver_events` to `irq_line`. The kernel keeps the
   ULTRASND parse, the 8237 decode, the vPIC, and the trace ring.
   *Verify:* the E1M8/Doom GUS recipes — real-time production to 0.1 %, no
   note gaps, and the DUKE3D GUS-ISR path.
2. **OPL.** Nearly free; carries the `nuked_opl3` dependency across.
3. **SB core.** `EmuDsp` + `SbMixer` → `lib/sound/src/sb.rs` with
   consumption-based accounting (section 2.3), leaving `SoundBlaster` in
   the kernel as the passthrough wrapper that owns an optional library
   core. This is the only step with real timing risk.
   *Verify:* the full game battery under screenshot test, not Doom alone —
   DUKE3D, ROTT, PoP, Dune 2 speech (single-cycle), and the SB16 channel-5
   self-test. Plus the shell launch path, not `--cmd`.
4. **New cards** against the contract that fell out.

Step 1 is deliberately allowed to be imperfect: the API is what falls out
of one working case, and steps 2–3 are what prove it generalises. Do not
try to design the final contract before the GUS builds.

## 6. The new cards

**AWE32 is GUS-shaped, not SB-shaped.** The EMU8000 is its own register
file at 0x620/0xA20/0xE20 with 32 wavetable voices over sample RAM,
sharing only the SB base address. It is a near-copy of `gus.rs` against
the same `sampler::Engine`, not an addition to the DSP state machine.

It has one problem the GUS does not: **its General MIDI sound set lives in
Creative's 1 MB on-card ROM.** The GUS ships complete precisely because the
*guest* uploads its own patches. So an AWE32 without that ROM plays only
guest-uploaded SF2 — which real drivers do support, but is not what a game
selecting "AWE32" expects. Either we substitute a free SoundFont for the
ROM presets or we accept partial support; this needs deciding before the
work starts, not during.

**MPU-401 + General MIDI has no such wall**, which is why it should come
first among the new cards. The guest sends MIDI bytes and *we* choose the
SoundFont — no ROM contract at all. Nothing exists today beyond the 6850
status stub at `vgus.rs:420`, and a missing MPU-401 at 0x330 is a known
live cause of "no music" in games that fall back to it.

It also forces us to build the pieces AWE32 then reuses for free:

- MIDI channel state + voice allocation (note on/off, program change,
  pitch bend, controllers) — `midi.rs`, genuinely shared.
- An SF2 preset/sample model.
- The real 2-pole resonant lowpass, filling in the `VoiceFilter::apply`
  stub that was reserved for it.
- ADSR as chained `Ramp` segments, which `Ramp`'s doc already anticipates.

**Roland MT-32 proper** stays out of scope: it needs Roland's ROMs, the
same licensing wall the GUS was chosen to avoid. Games asking for "Roland"
are served by MPU-401 + GM.

## 7. Risks

- **The SB timing is freshly debugged.** Section 2.3 argues the rewrite
  reproduces current behaviour because `mix_into` is already the
  consumption point, but that argument is theory until step 3 runs the
  game battery. If it does not hold, the fallback is to keep `EmuDsp`'s
  cursor as-is inside the library and accept that the card carries one
  host-shaped assumption — worse, but not fatal.
- **Underrun semantics** (end of 2.3) are the one behaviour that must be
  re-implemented rather than moved. Get it wrong and unserviced rings go
  silent instead of replaying.
- **`alloc` in the library.** Cards heap-allocate (1 MB GUS DRAM, the
  boxed engine — see the 64 KB kernel-stack rule that forced
  `new_boxed`). The crate stays `no_std` + `extern crate alloc`, as
  `//lib:sampler` already is.
- **Scope creep into a full ISA device framework.** This document is about
  sound cards. `vpic`, `vdma`, `vpit` are also pure state machines and it
  will be tempting to move them too. They are not sound, they have one
  consumer, and moving them buys nothing today.
