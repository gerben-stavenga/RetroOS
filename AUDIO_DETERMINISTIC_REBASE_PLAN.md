# Deterministic Audio Rebase Plan

## Objective

Rebuild the useful deterministic-audio work on top of the current
`origin/master` while adopting the upstream nanosecond clock architecture and
removing timing, wakeup, and reset mechanisms that are now redundant.

Do not mechanically replay all commits from
`experiment/deterministic-midi-validation`. Start from the new upstream state
and selectively port only the behavior identified below.

## Current State and Safety Requirements

- Source branch: `experiment/deterministic-midi-validation`
- Audited upstream: `origin/master` at `780d25c`
- Common ancestor at audit time: `a2a3864`
- Preserve all untracked plan and analysis documents.
- Preserve upstream Voodoo, VGA ownership, device timing, and Tomb Raider demo
  changes.
- Do not modify or delete the source branch until the reconstructed branch has
  been validated.
- Before creating the rework branch, record `git status --short` and save the
  source branch name and commit ID.
- The current uncommitted edits in `kernel/src/kernel/sound.rs` and
  `kernel/src/kernel/startup.rs` are naming-only edits to obsolete blocking
  reset plumbing. Do not port them.

## Upstream Architecture to Adopt

Treat upstream's clock implementation as authoritative:

- `Arch::now()` supplies monotonic nanoseconds.
- Metal selects stable/invariant TSC when possible, then HPET, then PIT channel
  2 as fallback.
- IRQ0 is a coalescible wakeup, not the elapsed-time authority.
- The event loop samples `world_now_ns` and calculates `elapsed_ns`.
- World, device, display, and audio advancement use nanoseconds.
- Audio rendering receives the absolute world time and elapsed interval from
  the upstream event loop.

Do not restore:

- `audio_time_micros()`;
- `take_audio_service_wakeups()`;
- pending-tick-based elapsed-time accounting;
- HPET-specific stall reconciliation;
- a separate MIDI/audio cadence clock;
- `ServiceDivider`;
- fractional microsecond accumulation;
- the branch's duplicate `AudioTimeline`.

## Cross-Reference with the Target Audio Architecture

The long-term design is documented in the
`RetroOS Deterministic Audio Architecture` wiki page. It targets more than
MPU-401: every DOS audio provider should eventually have a narrow synchronous
frontend in guest/VM86 context and a deterministic renderer-owned backend.

Apply the sources in this order when they disagree:

1. Current working PoC behavior and its verified findings.
2. Current branch code required to make that PoC work.
3. Current upstream architecture, especially `Arch::now()` and nanosecond world
   advancement.
4. The wiki's intended long-term boundaries.
5. Older speculative implementation details in either plan.

The stable target boundaries are:

```text
guest/VM86 frontend
  -> immediate guest-visible protocol state
  -> timestamped audio-relevant history
  -> deterministic source backend
  -> canonical mixer
  -> independent sink transport
```

This changes the interpretation of several PoC components:

| PoC component | Long-term value | Rebase decision |
|---|---|---|
| `AudioRuntime` | Source-neutral orchestration boundary | Keep a reduced version; remove private clock/wakeup adapters |
| `AudioTimeline` | Logical history/render frontier | Replace implementation with a nanosecond frontier; do not keep the microsecond-to-millisecond adapter |
| `AudioTime` | Common event timestamp | Keep as nanoseconds or a narrow wrapper over `u64 now_ns` |
| `TimedEvent<T>` | Per-device historical event | Keep generic |
| `FixedEventQueue<T, N>` | Preallocated frontend/backend handoff | Keep and instrument |
| `AudioSource`/DOS aggregate | Common MIDI/OPL/SB/GUS renderer boundary | Keep the contract with minimal structure |
| `RenderMode` | Deliverable PCM versus state-only deadline catch-up | Keep as a target capability, but do not preserve a no-op implementation |
| `ServiceDivider` | PoC wakeup adapter | Drop; upstream owns service wakeups |
| fractional microseconds | Old millisecond-renderer adapter | Drop; upstream is nanosecond-native |

The PoC also corrected or refined wiki assumptions:

- Queue raw MPU command and data writes in one ordering domain. The implemented
  replay needs interface-reset and UART history, so queuing only completed MIDI
  messages is too high-level for the proven MPU design.
- Rendering need not execute directly inside the hard IRQ. The verified PoC
  uses the timer/architecture wakeup to regain kernel control, then runs the
  preinitialized runtime in kernel context. Preserve deterministic wakeup
  ownership without reintroducing a separate IRQ audio counter.
- `AdvanceOnly` is architecturally necessary for bounded deadline catch-up, but
  the current PoC implementation does not actually advance source state. Treat
  it as unfinished future work rather than verified functionality.
- MIDI-only isolation is intentional during the PoC. Keep it for experimental
  validation, but do not mistake it for final production configuration.

Provider migration implications:

- OPL is the next low-risk provider: synchronously accept/register guest writes,
  queue timestamped register changes, and let renderer-owned oscillator and
  envelope state evolve between events.
- SB requires timestamped DSP state changes plus DMA staging. Guest DMA/IRQ
  progression must derive from `AudioTime` and virtual device semantics, never
  HDA or hosted-sink consumption.
- GUS requires timestamped register changes and an explicit strategy for
  mutable device RAM. Render barriers before DRAM mutation remain the initial
  preferred approach.
- Cross-device rendering must eventually honor the earliest timestamp among
  active per-device queues. Separate queues must share one `AudioTime` domain.
- The canonical mixer and sink transport must remain personality-neutral;
  preroll, pacing, physical cursor tracking, and recovery belong below the
  source layer.

## Commit Disposition

### Drop as Superseded

- `9a2efac fix(timer): recover elapsed time across firmware stalls`
- `52ff17c refactor(audio): formalize service cadence divider`
- `7fe5b29 fix(audio): retain fractional AudioTime remainder`
- `5c094a7 feat(audio): separate timer audio wakeups`
- `737f6ae feat(audio): gate PCM service on timer wakeups`

### Port the Behavior onto Upstream Timing

- `b96d3b7 feat(audio): gate playback on continuous mixer preroll`
- `0224e82 fix(audio): stabilize device restart and route servicing`
- `43b2572 fix(audio): preserve preroll across delayed service`
- `b89ee1b feat(audio): add logical time and fixed event queue`
- `e37f405 feat(audio): timestamp DOS MIDI writes`
- `69bb554 feat(audio): preinitialize the DOS MIDI synth`
- `2ba7d6a fix(audio): construct the MIDI event queue in place`
- `da6cfa9 feat(audio): service MIDI history at deterministic cadence`
- `4ee9a2f refactor(audio): replay MPU inside source rendering`
- `e2bafd6 refactor(audio): make MIDI source self-contained`

For these commits, preserve the behavior rather than their original structure.
Use nanosecond timestamps and the upstream audio rendering path.

### Preserve the Contracts, Replace the PoC Clock Plumbing

- `78f3a76 feat(audio): add logical AudioRuntime boundary`
- `7871a6f refactor(audio): add generic source render boundary`
- `1062ee5 refactor(audio): formalize logical AudioTimeline`
- `a930cf4 refactor(audio): expose runtime render mode`
- `40ac277 refactor(audio): make runtime own the sink`

These commits are not merely MIDI scaffolding. They are the intended extension
points for migrating OPL, SB, and GUS to synchronous guest frontends plus
deterministic renderer-owned backends. Preserve their architectural contracts,
but do not preserve the obsolete microsecond/tick implementation literally.

- Keep a small, source-neutral `AudioRuntime` orchestration boundary around the
  logical render frontier, canonical mix invocation, sink controls, and sink
  ownership.
- Keep a generic source/render boundary suitable for a DOS aggregate containing
  MIDI, OPL, SB, and GUS.
- Keep the distinction between producing PCM and advancing state through PCM
  that is no longer deliverable. Do not retain the current no-op
  `AdvanceOnly` implementation as if it were complete.
- Replace the current `AudioTimeline` elapsed-microsecond adapter with a
  nanosecond logical render frontier. Upstream `Arch::now()` supplies time; the
  timeline records how far source history has been reconstructed.
- Keep runtime ownership only where it creates this stable source/mixer/sink
  boundary. Do not duplicate upstream's clock-source selection, IRQ wakeup, or
  elapsed-time calculation.

### Optional Diagnostics and Validation

- `f0d607a feat(logging): add monotonic timestamps to klog`
- `91125de test(audio): update steady-state log assertions`
- `f5c6141 feat(audio): add MPU validation counters`
- `7ae75fd feat(audio): report sink continuity counters`
- `71dc26d feat(audio): add trace-only scheduler timing`
- `bcba8ab test(audio): isolate MIDI validation from PCM devices`
- `cc7486e test(audio): bundle DOSMid MIDI fixtures`
- `239696a docs: add deterministic MIDI validation plan`

Keep validation counters and fixtures if useful. Drop trace-only scheduler
timing unless it is still actively needed. Keep global klog timestamps in a
separate optional commit.

## Per-File Instructions

### Clock and Architecture

#### `arch-abi/src/arch.rs`

- Take the upstream file as the base.
- Do not restore `audio_time_micros()`.
- Do not restore `take_audio_service_wakeups()`.
- Use `now()` as the sole absolute time source.

#### `arch-metal/src/backend.rs`

- Take the upstream file unchanged.
- Do not restore forwarding methods for obsolete clock APIs.

#### `arch-metal/src/irq.rs`

- Take the upstream file unchanged.
- Preserve upstream TSC, HPET, and PIT channel 2 source selection.
- Preserve coalesced IRQ0 wakeups.
- Do not restore branch pending-audio-wakeup accounting.

### Event Loop and Runtime Ownership

#### `kernel/src/kernel/startup.rs`

- Start with upstream.
- Preserve `world_now_ns` and `elapsed_ns` calculation.
- Render audio from the existing upstream wakeup/advance path.
- Do not call `take_pending_ticks()` to determine elapsed time.
- Do not call `take_audio_service_wakeups()`.
- Do not recreate a MIDI service divider.
- Do not install the obsolete blocking-operation callback.
- If global log timestamps are retained, derive them directly from
  `world_now_ns`.

#### `kernel/src/lib.rs`

- Start from upstream and construct only the reduced, source-neutral
  `AudioRuntime` required by the retained architecture.
- Do not restore the old runtime's microsecond timeline, fractional remainder,
  service divider, or private wakeup accounting.

### Sound Core and Sink Lifecycle

#### `kernel/src/kernel/sound.rs`

Port these behaviors:

- initialize a physical sink stopped;
- collect a controlled preroll before starting DMA;
- reset sink and software cursor state together;
- re-enter preroll after a real underrun or requested reset;
- avoid generating an arbitrarily large catch-up block after a long stall;
- retain useful continuity and recovery counters;
- support a generic deferred sink reset request for HDA route changes.
- retain a small `AudioRuntime` boundary that can later service a DOS aggregate
  source containing MIDI, OPL, SB, and GUS;
- retain a logical render frontier distinct from both `world_now_ns` and the
  physical sink cursor;
- retain a generic interval-rendering contract capable of producing PCM or
  advancing obsolete source history without retaining PCM.

Remove or replace these branch mechanisms:

- the current `AudioTimeline` implementation that only converts absolute
  microseconds into elapsed milliseconds;
- `ServiceDivider` integration;
- fractional-time remainder handling;
- separate audio-service wakeup state;
- microsecond clock conversion;
- blocking-operation callback adapters;
- unused trace-only scheduler state unless explicitly retained for diagnosis.

The replacement runtime must accept upstream `world_now_ns`/`elapsed_ns`; it
must not call another architecture clock to progress itself. Integrate preroll
with the upstream nanosecond `Clock` and render callback. A large `elapsed_ns`
interval while stopped or recovering must not be synthesized directly into the
finite DMA ring. The eventual deadline path must advance source state through
obsolete history separately from producing deliverable PCM.

#### `lib/sound/src/sink.rs`

- Port restartable device lifecycle support.
- Keep device pause/start/reset operations required by common sink recovery.
- Reset software and hardware cursor baselines consistently.
- Keep preroll-compatible stopped initialization.
- Convert any elapsed-time assumptions to nanoseconds.

#### `lib/sound/src/timeline.rs`

- Remove `ServiceDivider`.
- Remove microsecond elapsed-time conversion.
- Remove fractional remainder handling.
- Keep or replace `AudioTime` as a nanosecond-backed monotonic timestamp type.
- Keep `TimedEvent<T>` generic so the same queue primitive can later carry
  `MpuEvent`, `OplEvent`, `SbEvent`, and `GusEvent` without a global event enum.
- Add only the logical render-frontier operations actually required by the
  interval renderer; do not create an independently advancing clock.
- Keep `RenderMode` as a target contract only if `AdvanceOnly` has real source
  semantics. Do not port the current branch's no-op implementation unchanged.

#### `lib/sound/src/event_queue.rs`

- Keep the fixed-capacity event queue.
- Preserve allocation-free steady-state operation.
- Store events with nanosecond timestamps, either as `u64 at_ns` or a minimal
  typed wrapper.

#### `lib/sound/src/lib.rs`

- Export `event_queue`.
- Export a reduced timestamp module only if it remains necessary.
- Do not export obsolete divider or timeline machinery.

### Physical Audio Drivers

#### `kernel/src/kernel/drivers/hda.rs`

Port:

- cached output capability detection;
- stable selected-output state independent of playback state;
- reset-time programming of the selected output route;
- deferred sink reset request when the OSD changes the route;
- pause/reset/start support;
- restart-safe stream cursor initialization;
- concise route availability and selected/fallback logging if still desired.

Do not restore:

- event-loop `apply_pending_output_route()` processing;
- immediate reset from a video or blocking-operation callback;
- a second pending-output-route state when normal HDA state is sufficient.

#### `kernel/src/kernel/drivers/ac97.rs`

- Port restart-safe cursor initialization.
- Port pause/reset/start support required by the common sink lifecycle.
- Ensure consumed and written baselines are reset together before restart.

#### `kernel/src/kernel/drivers/sb16.rs`

- Port only lifecycle methods required by the common sink interface.
- Avoid unrelated SB16 changes.

### Remove Obsolete Blocking Infrastructure

#### `kernel/src/kernel/blocking.rs`

- Do not port this file.
- Delete it from the reconstructed branch if introduced accidentally.

#### `kernel/src/kernel/mod.rs`

- Do not export a `blocking` module.

#### `kernel/src/kernel/core_bios.rs`

- Take upstream as the base.
- Do not restore audio reset calls around native VGA mode switches.
- Do not restore branch-only mode-switch diagnostic logging as part of the
  audio changes.

The immediate reset path caused the F12 OSD to freeze on the SEJT. After its
publishers were removed, `blocking.rs` and its subscriber registration became
dead plumbing.

### DOS and MIDI

#### `kernel/src/kernel/dos/machine/vmpu.rs`

Port:

- fixed-capacity timestamped MPU event queue;
- boxed queue construction where required to avoid stack pressure;
- preinitialized MIDI synth and sound bank;
- deterministic replay of events that are due for the current render span;
- useful overflow, late-event, and queue-depth counters.

Replace all uses of `audio_time_micros()` with nanosecond timestamps supplied by
`machine.now()` at the actual guest `OUT` operation. Do not stamp guest events
with a cached event-loop time, because writes occurring between wakeups must
retain their ordering and sub-millisecond positions. Do not create an
independently advancing MIDI clock.

#### `lib/sound/src/mpu401.rs`

- Keep the passive MPU device refactor needed by queued event replay.
- Keep port parsing and device state separate from synth rendering.
- Avoid unrelated interface churn.

#### `kernel/src/kernel/dos/machine/mod.rs`

- Start with upstream because this file also contains upstream nanosecond device
  timing changes.
- Port MIDI event submission and MIDI source rendering manually.
- Capture `machine.now()` when the guest performs an MPU write.
- Preserve the DOS aggregate source boundary so OPL, SB, and GUS can be migrated
  behind the same interface later.
- Preserve `RenderMode` only as a real interval-rendering contract; do not keep
  an `AdvanceOnly` branch that advances no source state.
- Keep MIDI-only source isolation on this experimental validation branch until
  a second deterministic source is migrated. Do not treat it as final
  production policy.

#### `kernel/src/kernel/dos/mod.rs`

- Preserve upstream method signatures and nanosecond advancement.
- Adapt MIDI rendering to those signatures.
- Do not restore old tick or microsecond arguments.

#### `kernel/src/kernel/dos/dos.rs`

- Preserve `AUDIO_VALIDATION=MIDI` for the PoC validation branch because the
  current experiment intentionally disconnects non-migrated PCM providers.
- Mark the setting temporary and remove it when the remaining providers use the
  deterministic frontend/backend path.
- Before an upstream production merge, prefer a test-specific configuration or
  make the normal default enable every migrated provider.

The intended flow is:

```text
DOS MPU write
  -> sample machine.now() at the guest operation
  -> timestamp event with AudioTime(now_ns)
  -> enqueue fixed-size event
  -> upstream wakeup calculates elapsed_ns
  -> audio renderer replays due MPU events
  -> MIDI synth renders into the normal mix span
  -> common sink preroll and DMA path
```

### Logging

#### `lib/src/log.rs`

- Treat global Linux-style timestamps as optional.
- If retained, place them in a separate commit.
- Derive timestamps from upstream `now_ns`; do not maintain a second clock.
- Prefer a `set_timestamp_ns()` interface and format milliseconds inside the
  logger.

Check all tests for anchored log patterns before retaining the prefix globally.

### Configuration, Tests, Documentation, and Assets

#### `etc/CONFIG.SYS`

- Keep `AUDIO_VALIDATION=MIDI` while this branch remains an explicit MPU-only
  architecture validation build.
- Do not describe MIDI-only isolation as the final user-facing configuration.
- Remove the setting, or move it into a test-specific image, once OPL/SB/GUS
  migration begins or before merging a normal production configuration.

- Remove `AUDIO_VALIDATION=MIDI` from the normal image.
- If isolated MIDI validation is still needed, inject it through a dedicated
  test image or test-specific configuration.

#### `test/audio_steady.sh`

- Rewrite assertions against the final retained log messages.
- Allow only a deliberately chosen bounded recovery count.
- Do not test obsolete pipe-depth or old wakeup metrics.
- Ensure optional global timestamp prefixes do not break matching.

#### `BUILD.bazel`

- Keep only DOSMid fixture/image targets that remain used.
- Add test-specific MIDI isolation here rather than changing production
  `CONFIG.SYS`, if isolation remains necessary.
- Do not modify unrelated upstream app, image, or emulator targets.

#### `test/dosmid/*`

- Keep as a separate optional manual-validation commit.
- Preserve DOS-compatible 8.3 filenames.
- Verify redistribution terms before proposing the files upstream.

#### `DETERMINISTIC_MIDI_VALIDATION_PLAN.md`

- Preserve the document.
- Mark clock, pending-tick, divider, and fractional-time stages as superseded by
  upstream.
- Record that the final port uses upstream `now_ns` and IRQ0 wakeups.
- Do not rewrite incomplete historical findings as though they had originally
  used the new architecture.

## Upstream-Only Areas to Preserve

Do not remove or overwrite upstream changes in these areas while resolving
conflicts:

- `kernel/src/kernel/display.rs`;
- DOS BIOS and VGA ownership;
- Voodoo MMIO, scanout, and presentation;
- PIT, RTC, keyboard, SB, GUS, and other device nanosecond advancement;
- `lib/sound/src/gus.rs`;
- `lib/sound/src/pacer.rs`;
- `lib/sound/src/sb.rs`;
- `third_party/voodoo/*`;
- Tomb Raider demo assets and build entries.

An apparent deletion in `git diff origin/master..old-branch` is not evidence
that the old branch intended to remove a newly added upstream file.

## Implementation Stages

### Stage 1: Establish a Clean Upstream Baseline

- [ ] Record the source branch name, `HEAD`, `origin/master`, and working-tree
      status.
- [ ] Preserve all plan files outside any destructive branch operation.
- [ ] Create a new rework branch from the current `origin/master`.
- [ ] Build the normal kernel and run the smallest boot smoke test before
      porting code.
- [ ] Record the exact baseline commands and results.

### Stage 2: Port Restartable Sink Preroll

- [ ] Port stopped sink initialization.
- [ ] Port the controlled preroll threshold.
- [ ] Port underrun/reset transition back into preroll.
- [ ] Port restart-safe cursor initialization for HDA and AC97.
- [ ] Ensure delayed elapsed time does not create an oversized catch-up write.
- [ ] Do not introduce any independent timing source.
- [ ] Build and run focused sound unit tests.
- [ ] Boot QEMU with HDA and confirm initialization, playback start, and stable
      operation.
- [ ] Commit this stage independently.

Suggested commit:

```text
feat(audio): add restartable sink preroll lifecycle
```

### Stage 3: Port HDA Output Route Reset

- [ ] Cache available HDA output routes at initialization.
- [ ] Keep selected route visible and mutable while playback is stopped.
- [ ] Make HDA reset program the current selected route.
- [ ] Make OSD route changes request a deferred sink reset.
- [ ] Confirm no event-loop `apply_pending_output_route()` remains.
- [ ] Confirm no video blocking hook is introduced.
- [ ] Test repeated Speaker/Jack switching before and during playback.
- [ ] Commit this stage independently.

Suggested commit:

```text
fix(hda): preserve output route across deferred sink resets
```

### Stage 4: Port Timestamped MPU Rendering

- [ ] Add the fixed-capacity event queue.
- [ ] Represent timestamps in nanoseconds.
- [ ] Timestamp DOS MPU writes by sampling `machine.now()` at each guest
      operation.
- [ ] Preinitialize the MIDI synth and bank.
- [ ] Replay all events due for the current audio render span.
- [ ] Keep event ordering deterministic.
- [ ] Define and test queue-overflow behavior.
- [ ] Do not add `ServiceDivider`, the old elapsed-microsecond `AudioTimeline`,
      or a second audio wakeup.
- [ ] Preserve a reduced source-neutral runtime and nanosecond logical render
      frontier suitable for later OPL/SB/GUS providers.
- [ ] Boot to DN with MPU initialization visible.
- [ ] Play a MIDI file under QEMU with HDA.
- [ ] Commit this stage independently.

Suggested commit:

```text
feat(midi): queue timestamped MPU events for audio rendering
```

### Stage 5: Validation Surface

- [ ] Retain only useful MPU and sink continuity counters.
- [ ] Update `test/audio_steady.sh` for final logs and bounded recovery.
- [ ] Preserve MIDI-only isolation for this PoC validation branch.
- [ ] Clearly mark the isolation temporary and record that GVOICE/SB/GUS tests
      are expected to remain unavailable until those providers are migrated.
- [ ] Before production merge, move isolation to a test-specific image or
      restore all migrated providers in normal `CONFIG.SYS`.
- [ ] Run focused unit tests and QEMU smoke tests.
- [ ] Commit tests independently.

Suggested commit:

```text
test(audio): validate MIDI timing and sink continuity
```

### Stage 6: Optional DOSMid Fixtures

- [ ] Verify redistribution terms.
- [ ] Preserve 8.3 filenames.
- [ ] Add only files needed for manual validation.
- [ ] Verify they appear in the intended test/distribution directory.
- [ ] Commit fixtures separately from kernel code.

Suggested commit:

```text
test(midi): add DOSMid validation fixtures
```

### Stage 7: Documentation and Optional Logging

- [ ] Update the deterministic MIDI plan with upstream supersession findings.
- [ ] If global klog timestamps are retained, implement them in a separate
      commit using upstream nanoseconds.
- [ ] Audit every shell test for timestamp-sensitive log matching.
- [ ] Commit documentation separately.

Suggested commit:

```text
docs(audio): update deterministic MIDI validation findings
```

## Validation Requirements

After each implementation stage:

- run `git diff --check`;
- run the smallest relevant Bazel tests;
- build the normal kernel;
- boot the known-good manually constructed QEMU HDA configuration;
- confirm expected audio and MPU initialization messages are present;
- inspect the diff against `origin/master` for accidental upstream reversions.

Before finalizing:

- run the complete repository test suite;
- confirm all emulator processes terminate;
- run the GitHub CI-equivalent checks, including Clippy;
- boot the normal HDD path;
- boot the GRUB multiload ISO path if still covered by the suite;
- run DOSMid through HDA in QEMU;
- deploy to SEJT only after QEMU validation;
- on SEJT, test DN startup, sustained MIDI playback, F12 OSD entry/exit, HDA
  Speaker/Jack switching, and a game with digital audio where supported;
- inspect kernel logs for queue overflow, repeated recovery, route fallback,
  or continuous underruns.

## Final Acceptance Criteria

The rework is complete only when:

- upstream `now_ns` is the only elapsed-time authority;
- IRQ0 remains only a wakeup source;
- no separate audio wakeup counter or cadence divider exists;
- no obsolete blocking-operation module or registration remains;
- sink playback starts through controlled preroll and recovers safely;
- HDA and AC97 restart with synchronized cursor state;
- HDA route changes work through deferred sink reset;
- MPU writes are timestamped and replayed deterministically during normal audio
  rendering;
- normal `CONFIG.SYS` does not disable PCM devices for validation;
- upstream Voodoo, VGA, timing, and demo work remains intact;
- the complete test suite and CI-equivalent checks pass;
- the final diff contains only behavior required for the retained feature.
