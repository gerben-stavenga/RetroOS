# Deterministic Audio Rebase: Exact Execution Plan

## 1. Mission

Reconstruct the useful work from `experiment/deterministic-midi-validation` on
top of the current `origin/master` without replaying the obsolete timer and
wakeup implementation.

The finished branch must preserve the architecture proven by the MPU-401 PoC:

```text
VM86 guest operation
  -> synchronous guest-visible frontend state
  -> timestamped audio-relevant history
  -> deterministic source backend
  -> canonical mixer
  -> independent sink transport
```

The implementation must remain suitable for later OPL, Sound Blaster, and GUS
backend migration. Only MPU-401/MIDI is implemented as a deterministic source
in this task. Do not implement OPL, SB, or GUS migration now.

Read `AUDIO_DETERMINISTIC_REBASE_PLAN.md` completely before starting. Use this
document as the exact execution procedure and the other document as the design
rationale.

## 2. Authority Order

When sources disagree, use this order:

1. Behavior verified by the current MPU PoC and its tests.
2. Current code on `experiment/deterministic-midi-validation` that is required
   for that behavior.
3. Current `origin/master`, especially its `Arch::now()` nanosecond time model.
4. `RetroOS Deterministic Audio Architecture` in the project wiki.
5. Speculative or unimplemented details in older plans.

Do not silently choose a lower-authority design when a higher-authority source
contradicts it. Record the discrepancy in the rebase plan's findings section.

## 3. Non-Negotiable Constraints

- Do not perform a mechanical `git rebase` of all source-branch commits.
- Do not merge the old branch into the new branch.
- Do not cherry-pick any timer, wakeup, divider, fractional-time, or blocking
  reset commit wholesale.
- Do not restore `audio_time_micros()`.
- Do not restore `take_audio_service_wakeups()`.
- Do not make pending IRQ count the elapsed-time authority.
- Do not restore `ServiceDivider`.
- Do not restore fractional microsecond accumulation.
- Do not modify upstream TSC/HPET/PIT2 source selection.
- Do not restore video-mode blocking callbacks or immediate sink reset around
  native VGA mode changes.
- Do not add an event-loop `apply_pending_output_route()` path.
- Do not make the runtime or canonical mixer understand MPU, OPL, SB, or GUS
  protocol details.
- Do not migrate OPL, SB, or GUS in this task.
- Do not delete any plan or analysis Markdown file.
- Do not discard the two existing uncommitted source-branch edits. Preserve
  them in a named stash before finally switching the main checkout.
- Keep unrelated upstream Voodoo, VGA, device timing, and Tomb Raider changes.
- Use `apply_patch` for manual source edits.
- After every logical stage, run `git diff --check` and the specified tests.
- Do not proceed after a failed required test until the cause is understood.

## 4. Known Starting State

At plan creation time:

```text
source branch: experiment/deterministic-midi-validation
source merge base: a2a3864ecbafadbf7cf44740fabd0ae6812d5c8f
audited origin/master: 780d25c
```

Tracked but uncommitted edits exist in:

```text
kernel/src/kernel/sound.rs
kernel/src/kernel/startup.rs
```

Those edits only rename obsolete immediate blocking-reset plumbing. Do not port
them, but preserve them recoverably.

Plan and analysis files are untracked. They must survive branch reconstruction.

If `origin/master` has advanced beyond `780d25c`, inspect the intervening commits
before implementation. If they touch any file listed in section 8, update this
plan's findings before editing code.

## 5. Stage 0: Record and Preserve the Source State

- [ ] Run:

```bash
git fetch origin
git branch --show-current
git rev-parse HEAD
git rev-parse origin/master
git merge-base HEAD origin/master
git status --short
```

- [ ] Save the command output in the working notes for the final handoff.
- [ ] Confirm the active branch is
      `experiment/deterministic-midi-validation`. If it is not, stop and report
      the actual branch.
- [ ] Confirm the only tracked uncommitted files are the two files listed in
      section 4. If any other tracked file is modified, stop and inspect it.
- [ ] Confirm these documents exist:

```text
AUDIO_CLOCK_AUDIT_PLAN.md
AUDIO_DETERMINISTIC_REBASE_PLAN.md
AUDIO_DETERMINISTIC_REBASE_EXECUTION_PLAN.md
AUDIO_PACING_STABILITY_FIX_PLAN.md
AUDIO_PREROLL_RESUME_GATE_PLAN.md
HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md
OSD_AUDIO_UNDERRUN_RECOVERY_ANALYSIS.md
DETERMINISTIC_MIDI_VALIDATION_PLAN.md
```

- [ ] Stage only the untracked plan/analysis documents with this exact command.
      Do not use `git add *.md`, `git add -A`, or `git add .`:

```bash
git add \
  AUDIO_CLOCK_AUDIT_PLAN.md \
  AUDIO_DETERMINISTIC_REBASE_PLAN.md \
  AUDIO_DETERMINISTIC_REBASE_EXECUTION_PLAN.md \
  AUDIO_PACING_STABILITY_FIX_PLAN.md \
  AUDIO_PREROLL_RESUME_GATE_PLAN.md \
  HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md \
  OSD_AUDIO_UNDERRUN_RECOVERY_ANALYSIS.md
```
- [ ] Verify with `git diff --cached --name-only` that only Markdown files are
      staged.
- [ ] Commit the plan documents with:

```text
docs(audio): preserve deterministic rebase plans
```

- [ ] Record the resulting documentation commit ID as `PLAN_COMMIT`.
- [ ] Confirm `backup/deterministic-midi-pre-rebase` does not already exist. If
      it exists, stop and inspect it instead of moving it.
- [ ] Create a non-moving backup ref at the resulting source HEAD:

```bash
git branch backup/deterministic-midi-pre-rebase
```

- [ ] Do not push the backup branch unless the user requests it.

## 6. Stage 1: Create a Clean Rework Branch Without Disturbing the Dirty Checkout

Use a temporary Git worktree so the two source-branch modifications remain
untouched during reconstruction.

- [ ] Create a unique empty temporary directory with `mktemp -d` and record it
      as `REWORK_DIR`.
- [ ] Add a worktree and branch from the fetched upstream tip:

```bash
git worktree add -b experiment/deterministic-audio-rebase "$REWORK_DIR" origin/master
```

- [ ] Enter `REWORK_DIR`.
- [ ] Cherry-pick only `PLAN_COMMIT` so the approved plans survive on the new
      branch.
- [ ] Cherry-pick `239696a` immediately afterward. That commit contains the
      tracked `DETERMINISTIC_MIDI_VALIDATION_PLAN.md`, which predates the new
      untracked plan-preservation commit and would otherwise be absent from the
      branch created from `origin/master`.
- [ ] Verify both cherry-picks contain documentation only before continuing.
- [ ] Run:

```bash
git status --short
git log -3 --oneline
git diff origin/master...HEAD --stat
```

- [ ] Confirm the only differences from `origin/master` are documentation
      files from the two preservation commits.
- [ ] If the branch name already exists, do not overwrite it. Stop and inspect
      the existing branch before deciding whether to reuse it.

## 7. Stage 2: Establish and Test the Upstream Baseline

Run these commands before porting any source code:

```bash
bazelisk build //:image //kernel:kernel_elf
bazelisk test //arch-interp:all --platforms=@platforms//host
```

Then run this bounded normal boot smoke:

```bash
QEMU_DISPLAY=none timeout 30 ./run.sh qemu \
  --firmware uefi --arch x64 --sound hda --headless \
  > /tmp/retroos-audio-rebase-baseline.log 2>&1 || test $? -eq 124
```

The timeout exit is expected because the booted DOS environment remains
interactive. Inspect `/tmp/retroos-audio-rebase-baseline.log` and confirm the
kernel reached normal DOS/DN initialization without panic. If `run.sh` does not
forward kernel debug output in the current upstream version, run it once under
`bash -x`, copy the fully resolved QEMU command, add `-debugcon stdio`, and run
that resolved command under the same 30-second timeout. Record the exact command
used and reuse it for all later QEMU HDA validation.

- [ ] Record every command and exit status.
- [ ] Do not fix pre-existing upstream failures as part of this branch.
- [ ] If a baseline test fails, repeat it once and inspect the failure.
- [ ] If the failure is reproducible on untouched `origin/master`, record it as
      an upstream baseline failure and ask before proceeding.
- [ ] Confirm no build or test command changed tracked files.

## 8. File Ownership Map

Use this table throughout the work. Do not expand the change surface without a
demonstrated dependency.

| File | Required action |
|---|---|
| `arch-abi/src/arch.rs` | Keep upstream; use existing `now()` only |
| `arch-metal/src/backend.rs` | Keep upstream unchanged |
| `arch-metal/src/irq.rs` | Keep upstream unchanged |
| `lib/sound/src/timeline.rs` | Port only nanosecond `AudioTime`, generic `TimedEvent`, and real render-mode contract |
| `lib/sound/src/event_queue.rs` | Port fixed queue and tests; convert timestamps to nanoseconds |
| `lib/sound/src/lib.rs` | Export only retained primitives |
| `kernel/src/kernel/sound.rs` | Add reduced runtime and preroll/reset behavior on upstream nanosecond advance path |
| `kernel/src/kernel/startup.rs` | Replace local clock/sink ownership with reduced runtime without changing upstream wakeup logic |
| `kernel/src/lib.rs` | Construct reduced runtime only if required by the alternate startup path |
| `lib/sound/src/sink.rs` | Port restartable sink/device lifecycle |
| `kernel/src/kernel/drivers/hda.rs` | Port restart-safe stream and route reset behavior |
| `kernel/src/kernel/drivers/ac97.rs` | Port restart-safe lifecycle behavior |
| `kernel/src/kernel/drivers/sb16.rs` | Port only common sink lifecycle methods |
| `kernel/src/kernel/dos/machine/vmpu.rs` | Port MPU frontend/history/backend PoC using nanoseconds |
| `lib/sound/src/mpu401.rs` | Port passive MPU wire model required by replay |
| `kernel/src/kernel/dos/machine/mod.rs` | Port DOS aggregate source and timestamp capture |
| `kernel/src/kernel/dos/mod.rs` | Adapt audio callback signatures only |
| `kernel/src/kernel/dos/dos.rs` | Preserve temporary MIDI validation selection |
| `etc/CONFIG.SYS` | Preserve temporary MPU-only PoC selection, clearly documented |
| `test/audio_steady.sh` | Adapt final lifecycle assertions |
| `BUILD.bazel` | Add only required fixture/test entries |
| `test/dosmid/*` | Port as a separate fixture commit |
| `lib/src/log.rs` | Optional separate commit only; not required for architecture |
| `kernel/src/kernel/blocking.rs` | Do not create or port |
| `kernel/src/kernel/core_bios.rs` | Keep upstream; no audio blocking calls |
| `kernel/src/kernel/mod.rs` | Do not add `blocking` module |

## 9. Stage 3: Add Nanosecond Event Primitives

Implement this stage before changing runtime or MIDI code.

### 9.1 `AudioTime`

- [ ] Create or adapt `lib/sound/src/timeline.rs`.
- [ ] Define `AudioTime` as a monotonic nanosecond value:

```rust
pub struct AudioTime(u64);
```

- [ ] Provide exactly the operations currently required by queueing and
      rendering:

```rust
AudioTime::ZERO
AudioTime::from_nanos(u64)
AudioTime::as_nanos() -> u64
AudioTime::saturating_duration_since(AudioTime) -> u64
```

- [ ] Keep ordering derives.
- [ ] Do not provide `from_micros()` or `as_micros()` compatibility aliases.
      Compile errors must identify remaining old-unit call sites.
- [ ] Convert time to frame positions using `u128` arithmetic and division by
      `1_000_000_000`, not `1_000_000`.
- [ ] Add tests proving:
  - one second at 48 kHz maps to 48,000 frames;
  - 500 microseconds represented as 500,000 ns maps to 24 frames at 48 kHz;
  - saturating subtraction cannot underflow.

### 9.2 `TimedEvent<T>`

- [ ] Keep `TimedEvent<T>` generic.
- [ ] Store `at: AudioTime` and `event: T`.
- [ ] Do not introduce a global cross-device `AudioEvent` enum.

### 9.3 `RenderMode`

- [ ] Keep `RenderMode::{ProducePcm, AdvanceOnly}` as the target source
      contract.
- [ ] Add a comment stating that `AdvanceOnly` means source state must actually
      advance while PCM is discarded.
- [ ] Do not add a branch that simply returns without advancing state.
- [ ] If the reduced runtime cannot yet execute `AdvanceOnly`, leave the mode
      at the interface boundary and return a clearly named unsupported path
      only in code that is unreachable in this PoC. Prefer not calling the mode
      until a source implements it.

### 9.4 Fixed event queue

- [ ] Port `lib/sound/src/event_queue.rs` from commit `b89ee1b` and follow-up
      `2ba7d6a`, manually rather than by cherry-picking.
- [ ] Preserve:
  - fixed capacity;
  - FIFO order;
  - equal-timestamp insertion order;
  - explicit `Result<(), T>` on full;
  - overflow counter;
  - high-water counter;
  - `new_boxed()` to avoid materializing a large queue on the kernel stack;
  - correct `Drop` for initialized entries.
- [ ] Preserve `pop_through(time)` semantics: events at exactly `time` are due.
- [ ] Keep the `N == 0` behavior safe.
- [ ] Update all tests to nanoseconds.

### 9.5 Validate and commit

- [ ] Export the retained modules from `lib/sound/src/lib.rs`.
- [ ] Run:

```bash
bazelisk test //lib:sound_test --platforms=@platforms//host
```
- [ ] Run metal and host Clippy for `//lib:sound`:

```bash
bazelisk build --config=clippy //lib:sound
bazelisk build --config=clippy --platforms=@platforms//host //lib:sound
```
- [ ] Run `git diff --check`.
- [ ] Inspect `git diff origin/master -- lib/sound` and confirm no unrelated
      sound-library changes were copied.
- [ ] Commit:

```text
refactor(audio): add nanosecond event primitives
```

## 10. Stage 4: Introduce the Reduced Source-Neutral Runtime

The purpose of this stage is to preserve the long-term architecture, not the
old runtime implementation.

### 10.1 Runtime ownership

- [ ] Add a reduced `AudioRuntime` in `kernel/src/kernel/sound.rs`.
- [ ] It may own:
  - `Clock`;
  - `Option<Sink>`;
  - a nanosecond logical render frontier if needed by exact event placement;
  - source-neutral service/control statistics that remain useful.
- [ ] It must not own:
  - an architecture clock source;
  - an IRQ counter;
  - a service divider;
  - a fractional microsecond remainder;
  - DOS or MPU-specific state.

### 10.2 Service API

- [ ] Give the runtime a service method that receives time from upstream. Use a
      signature equivalent to:

```rust
fn service<A: Arch>(
    &mut self,
    machine: &mut A,
    now: AudioTime,
    elapsed_ns: u64,
    mix: impl FnMut(&mut A, AudioSpan<'_>),
)
```

- [ ] Do not call `machine.now()` inside this method to calculate elapsed time.
      The upstream event loop already supplies the authoritative interval.
- [ ] Keep `now` available to source rendering for event boundaries.
- [ ] Route ordinary PCM production through upstream's nanosecond-native
      `sound::advance()` implementation.
- [ ] Do not copy the old `AudioTimeline::elapsed_micros()` method.
- [ ] Do not copy `fractional_micros`.
- [ ] Do not copy `SchedulerCensus` unless a currently used test requires a
      specific counter. Prefer upstream tracing.

### 10.3 Source boundary

- [ ] Retain `AudioSpan`.
- [ ] Retain a source-neutral render boundary. It may be a trait or the existing
      personality callback, but it must support a future DOS aggregate source.
- [ ] Do not add dynamic source registration.
- [ ] Do not add separate runtime knowledge of MIDI, OPL, SB, or GUS.
- [ ] Do not implement a no-op `AdvanceOnly` service path.

### 10.4 Event-loop wiring

- [ ] Begin from upstream `kernel/src/kernel/startup.rs`.
- [ ] Preserve:
  - `last_world_ns`;
  - `irq_clock_wakeup`;
  - IRQ0 event removal;
  - `world_now_ns = machine.now()` only when the backend wakeup permits it;
  - `elapsed_ns = world_now_ns - last_world_ns`;
  - upstream order of world, audio, display, and input advancement.
- [ ] Replace local `audio_clock` and `sink` ownership with `AudioRuntime` only
      to the extent required by the runtime boundary.
- [ ] Invoke runtime service only when upstream would have invoked
      `sound::advance()`.
- [ ] Pass `AudioTime::from_nanos(world_now_ns)` and `elapsed_ns`.
- [ ] Keep the personality's audio callback as the source aggregate boundary.
- [ ] Do not add a second service cadence.
- [ ] Do not install a blocking-operation hook.

### 10.5 Validate and commit

- [ ] Build `//kernel:kernel_elf`.
- [ ] Run relevant host tests.
- [ ] Boot to DN with the normal current sound behavior unchanged.
- [ ] Compare logs against the untouched upstream baseline.
- [ ] Run `git diff --check`.
- [ ] Confirm no arch clock file changed.
- [ ] Commit:

```text
refactor(audio): establish a nanosecond runtime boundary
```

## 11. Stage 5: Port Restartable Sink Preroll

Use commits `b96d3b7`, `0224e82`, `43b2572`, and the sink-related portion of
`686a12c` only as references. Apply behavior manually to upstream.

### 11.1 Common sink lifecycle

- [ ] Extend `sound::sink::Device` only with lifecycle operations genuinely
      required by all physical implementations.
- [ ] Preserve stopped initialization.
- [ ] Preserve explicit pause/reset/start sequencing.
- [ ] Keep software written/consumed baselines synchronized with the physical
      stream reset.
- [ ] Do not submit fake silence while claiming source time advanced.

### 11.2 Kernel sink state

- [ ] Introduce `PlaybackState::{PreRoll, Running}`.
- [ ] On construction, leave the physical device stopped.
- [ ] Set preroll target from the configured OSD latency, clamped to at least
      one hardware block and at most the safe device lead.
- [ ] Mix and submit real source PCM while stopped.
- [ ] Start the physical stream only after queued real PCM reaches the target.
- [ ] On real underrun or requested reset:
  - pause/reset the device;
  - reset software cursor baselines;
  - reset the pacer;
  - clear learned rate state;
  - enter `PreRoll`;
  - refill before restarting.
- [ ] Preserve useful counters: starts, recoveries, underruns, queue headroom.
- [ ] Do not globally flood klog on repeated recovery.

### 11.3 Delayed service

- [ ] Preserve upstream's finite-ring safety check.
- [ ] Do not render an arbitrarily large delayed interval into the DMA ring.
- [ ] Do not interpret a long elapsed interval by itself as proof of a physical
      underrun.
- [ ] Keep source-state deadline advancement as an explicit future
      `AdvanceOnly` responsibility; do not fake it by returning from the source.

### 11.4 Driver changes

- [ ] In HDA, reset stream descriptor and software counters together.
- [ ] In AC97, reset channel and software counters together.
- [ ] In SB16 sink mode, implement only required common lifecycle operations.
- [ ] Confirm ordinary native SB passthrough behavior is unchanged.

### 11.5 Validate and commit

- [ ] Run sink/library unit tests.
- [ ] Build kernel and image.
- [ ] Boot QEMU with HDA.
- [ ] Confirm logs show sink initialized stopped, real mixer data submitted,
      playback start after preroll, and first hardware frame consumed.
- [ ] Run `test/audio_steady.sh` with a short duration first.
- [ ] Run it again for at least 60 seconds after the short run passes.
- [ ] Run `git diff --check`.
- [ ] Commit:

```text
feat(audio): add restartable sink preroll lifecycle
```

## 12. Stage 6: Port HDA Output Routing Through Deferred Sink Reset

Use `0224e82` and `686a12c` as behavioral references.

- [ ] Detect and cache available HDA output routes during HDA initialization.
- [ ] Store selected output route as ordinary HDA state independent of whether
      playback is running.
- [ ] Keep route labels derived from existing route/pin constants.
- [ ] Let the OSD update the selected HDA route field immediately.
- [ ] Have the OSD request a generic deferred sink reset.
- [ ] Make the runtime service sink controls even when no PCM frames are
      produced in that iteration.
- [ ] Make HDA reset/reprogramming read the current selected route.
- [ ] Log only concise initialization and selected/fallback information.
- [ ] Do not print an unchanged "requested route" on every OSD input attempt.
- [ ] Do not add `OUTPUT_ROUTE_PENDING` if the selected route field already
      contains the desired state.
- [ ] Do not add `apply_pending_output_route()` to the main event loop.
- [ ] Do not call HDA register programming directly from OSD code.
- [ ] Do not add any video-mode reset subscriber.

Validate:

- [ ] Build and boot QEMU HDA.
- [ ] Toggle every detected output repeatedly before playback starts.
- [ ] Toggle every detected output repeatedly during playback.
- [ ] Confirm each change causes one deferred sink reset and fresh preroll.
- [ ] Confirm the OSD selection remains mutable while playback is stopped.
- [ ] Run `git diff --check`.
- [ ] Commit:

```text
fix(hda): apply output routes through deferred sink reset
```

## 13. Stage 7: Port the MPU Frontend and Timestamped History

Use commits `e37f405`, `69bb554`, `2ba7d6a`, `da6cfa9`, `4ee9a2f`, and
`e2bafd6` as references. Do not cherry-pick them wholesale.

### 13.1 Lifetime and initialization

- [ ] Make the virtual MPU belong to the DOS personality/machine lifetime.
- [ ] Do not create or destroy it for each DOS program.
- [ ] Preinitialize the synth and immutable GM bank outside audio service.
- [ ] Keep patch data resident and immutable while active.
- [ ] Construct the 4096-event queue directly in its heap allocation.
- [ ] Do not allocate, parse files, or map memory from runtime service.

### 13.2 Synchronous frontend

- [ ] Preserve immediate guest-visible MPU behavior in VM86 I/O context:
  - port ownership;
  - status reads;
  - ACK behavior;
  - command mode;
  - UART state;
  - reset semantics.
- [ ] Do not delay guest-visible protocol parsing until audio rendering.
- [ ] Do not reset the external MIDI synth merely because the MPU interface is
      reset unless the proved PoC explicitly does so.

### 13.3 Timestamp capture

- [ ] On every guest write to MPU data or command port, sample
      `machine.now()` at that operation.
- [ ] Convert that value with `AudioTime::from_nanos()`.
- [ ] Apply the synchronous frontend operation.
- [ ] Enqueue the corresponding raw `MpuEvent` with the same timestamp.
- [ ] Put command and data writes in the same queue.
- [ ] Preserve FIFO order for equal timestamps.
- [ ] Do not timestamp writes with `Clock::produced_frames()`.
- [ ] Do not timestamp writes with cached `world_now_ns` from the previous
      timer wakeup.
- [ ] Do not queue only completed high-level MIDI messages; the verified PoC
      requires raw MPU command/data history.

### 13.4 Audio-side replay

- [ ] Keep separate replay-side MPU protocol state.
- [ ] Consume all events due through the current render boundary.
- [ ] Convert event nanoseconds to the correct source frame position using
      integer `u128` arithmetic.
- [ ] Apply events at their historical frame position, not at the end of the
      service call.
- [ ] Continue synth envelope and voice evolution when the event queue is empty.
- [ ] Remove or bypass the old MPU deferred FIFO and event-loop `Mpu::tick()`
      delivery path.
- [ ] Keep queue high-water, overflow, event production, event consumption,
      and late-event counters.
- [ ] Never silently drop a full-queue event. Make overflow visible and retain
      the existing explicit PoC policy.

### 13.5 DOS aggregate source

- [ ] Keep the current deterministic source count at one: MIDI.
- [ ] Expose MIDI through the DOS aggregate source/callback, not directly to
      HDA.
- [ ] Keep canonical mixer accumulation between MIDI and sink.
- [ ] Do not add runtime knowledge of `MpuEvent`.
- [ ] Leave OPL, SB, GUS, and speaker protocol state available to the guest as
      required by the current PoC, but do not poll/mix their PCM into the
      deterministic source when MIDI-only validation is active.
- [ ] Do not delete their guest-visible I/O devices in this task.

### 13.6 Validate and commit

- [ ] Run event queue and MIDI library unit tests.
- [ ] Build kernel/image.
- [ ] Boot the manually known-good QEMU HDA configuration.
- [ ] Confirm logs show MPU initialization, HDA initialization, sink preroll,
      playback start, and first frame consumed.
- [ ] Run DOSMid interactively and play at least one bundled multi-minute MIDI.
- [ ] Confirm event production and consumption counters increase.
- [ ] Confirm queue overflow remains zero.
- [ ] Confirm music continues while no new MPU writes arrive.
- [ ] Run `git diff --check`.
- [ ] Commit:

```text
feat(midi): replay timestamped MPU history in the audio runtime
```

## 14. Stage 8: Preserve Explicit MPU-Only Validation

The current branch intentionally validates one deterministic source. Preserve
that experimental condition; do not represent it as final production policy.

- [ ] Keep or restore `AUDIO_VALIDATION=MIDI` in `etc/CONFIG.SYS`.
- [ ] Add a comment or plan note stating that it temporarily disconnects
      non-migrated PCM providers from the canonical mixer.
- [ ] Keep guest-visible SB/GUS/OPL devices where the current PoC keeps them.
- [ ] Do not claim GVOICE, SB digital audio, GUS output, or speaker output is
      expected to work in this validation configuration.
- [ ] Record expected test exclusions explicitly.
- [ ] Do not delete failing tests globally. Skip them only in the validation
      configuration or document expected failure if test infrastructure cannot
      select configuration.
- [ ] Ensure normal source code still compiles with the validation check
      disabled.
- [ ] Run a MIDI-only QEMU boot and DOSMid playback.
- [ ] Commit:

```text
test(audio): isolate deterministic MIDI validation
```

## 15. Stage 9: Update Audio Tests and Add Fixtures

### 15.1 Steady-state test

- [ ] Update `test/audio_steady.sh` only after final log messages are known.
- [ ] Assert:
  - physical sink initialized stopped;
  - playback reached running state;
  - hardware consumed a first frame;
  - recovery count is within the deliberately chosen bound.
- [ ] Use substring matching so optional global timestamp prefixes do not break
      the test.
- [ ] Ensure QEMU is terminated by timeout even when the DOS program remains at
      `TC-OK` or waits for keyboard input.
- [ ] Do not mention `SBTEST.COM` in this HDA continuity test.

### 15.2 DOSMid fixtures

- [ ] Port `test/dosmid/*` and only the required `BUILD.bazel` entries in a
      separate commit.
- [ ] Preserve DOS 8.3 names.
- [ ] Keep DOSMid in its own directory.
- [ ] Verify redistribution terms from the bundled documentation.
- [ ] Do not add unrelated game-image dependencies to tests.

### 15.3 Commits

- [ ] Commit test logic:

```text
test(audio): validate sink continuity and MIDI replay
```

- [ ] Commit fixtures separately:

```text
test(midi): add DOSMid validation fixtures
```

## 16. Stage 10: Update Documentation with Actual Findings

- [ ] Update `DETERMINISTIC_MIDI_VALIDATION_PLAN.md` only where completed work
      or newly discovered divergence must be recorded.
- [ ] Do not rewrite untouched historical sections as if they originally used
      upstream nanosecond timing.
- [ ] Mark these old mechanisms superseded:
  - HPET reconciliation commit;
  - pending-tick elapsed-time authority;
  - separate audio wakeup counter;
  - 500 Hz `ServiceDivider`;
  - microsecond `AudioTimeline` adapter;
  - fractional microsecond remainder.
- [ ] Record that upstream now supplies TSC, HPET, or PIT2-backed `now_ns` and
      coalesced IRQ0 wakeups.
- [ ] Record that raw MPU command/data queueing was required by the verified
      PoC, even though the older wiki suggested completed MIDI events.
- [ ] Record that mixing runs after the architecture wakeup regains kernel
      control, not as heavy work directly inside the hard IRQ.
- [ ] Record that `AdvanceOnly` remains a required future capability but the
      current no-op implementation was not retained as completed behavior.
- [ ] Record that OPL is the next low-risk migration and SB/GUS require mutable
      memory strategies.
- [ ] Commit documentation separately:

```text
docs(audio): reconcile the MIDI PoC with upstream timing
```

## 17. Optional Global Klog Timestamps

Do not include global klog timestamps in the core audio commits.

Only retain them if the user explicitly approves the optional commit after the
audio implementation passes tests.

If approved:

- [ ] Derive timestamps from upstream nanoseconds.
- [ ] Do not maintain a second logging clock.
- [ ] Audit all test log matchers.
- [ ] Keep formatting independent of audio code.
- [ ] Commit separately:

```text
feat(logging): prefix klog with monotonic timestamps
```

## 18. Stage 11: Full Validation

Run validation in this order. Do not start the next tier until the previous
tier passes.

### Tier 1: Static checks

```bash
git diff --check
git status --short
```

Verify manually:

- [ ] no `audio_time_micros` remains;
- [ ] no `take_audio_service_wakeups` remains;
- [ ] no `ServiceDivider` remains;
- [ ] no `fractional_micros` remains;
- [ ] no `before_blocking_operation` call remains;
- [ ] no `blocking::install` remains;
- [ ] no event-loop `apply_pending_output_route` remains;
- [ ] no arch clock file differs from `origin/master` unless a later upstream
      change made an explicitly reviewed adaptation necessary.

Use `rg` for each forbidden symbol and include the results in the handoff.

### Tier 2: Build and unit tests

```bash
bazelisk build //:image //kernel:kernel_elf
bazelisk test //arch-interp:all --platforms=@platforms//host
```

Run all directly relevant `//lib:sound` and kernel tests discovered from the
current BUILD files.

### Tier 3: CI-equivalent Clippy

```bash
bazelisk build --config=clippy \
  //kernel:kernel //lib:lib //lib:sound \
  //arch-abi:arch-abi //arch-metal:arch-metal

bazelisk build --config=clippy --platforms=@platforms//host \
  //kernel:kernel //kernel:retroos-host \
  //arch-interp:arch-interp //lib:lib //lib:sound //arch-abi:arch-abi
```

### Tier 4: End-to-end suite

Run:

```bash
test/run_all.sh
```

- [ ] Monitor emulator processes while the suite runs.
- [ ] Confirm each QEMU and 86Box process exits before the next conflicting
      instance starts.
- [ ] If a test reaches `TC-OK` and remains visible, distinguish expected guest
      waiting from harness failure to terminate the emulator.
- [ ] Do not solve emulator cleanup failures by weakening audio assertions.
- [ ] Record intentional MIDI-only exclusions separately from unexpected
      failures.

### Tier 5: QEMU HDA validation

- [ ] Use the manually constructed QEMU HDA configuration that previously
      produced reliable debug output when `run.sh` stdout did not.
- [ ] Boot to DN.
- [ ] Run DOSMid and play a long MIDI file.
- [ ] Run DOOM General MIDI with digital audio disabled in the MPU-only
      validation configuration.
- [ ] Hold keys and exercise ordinary gameplay.
- [ ] Open and close F12 OSD repeatedly.
- [ ] Switch HDA output routes repeatedly.
- [ ] Confirm low bounded recovery count, zero queue overflow, and sustained
      event consumption.

### Tier 6: SEJT validation

Use the `retroos-sejt-hardware` skill and its current deployment procedure.

- [ ] Confirm HPET is enabled in SEJT BIOS before interpreting timing results.
- [ ] Deploy only after all QEMU tiers pass.
- [ ] Boot to DN.
- [ ] Run DOSMid for several minutes.
- [ ] Run DOOM General MIDI and hold keys long enough to exercise USB legacy
      SMM disturbance.
- [ ] Enter and exit F12 OSD repeatedly.
- [ ] Verify output route selection works before and during playback.
- [ ] Inspect available kernel logs for queue overflow and repeated recovery.
- [ ] Do not reintroduce video blocking reset as a workaround.

## 19. Stage 12: Diff Audit Against Upstream

Run:

```bash
git diff --stat origin/master...HEAD
git diff --name-status origin/master...HEAD
git log --reverse --oneline origin/master..HEAD
```

For every changed file:

- [ ] State which requirement necessitates it.
- [ ] Remove formatting-only or unrelated refactoring.
- [ ] Confirm no upstream code was reverted merely because the source branch
      predates it.
- [ ] Confirm no build image, game image, ISO, GRUB, or emulator target changed
      unless required specifically for DOSMid validation.
- [ ] Confirm source/mixer/sink boundaries remain narrow.
- [ ] Confirm MIDI-specific logic stays in the DOS/MPU source layer.
- [ ] Confirm sink transport remains source-neutral.

If a file cannot be justified in one sentence, revert that file's rework and
reimplement the requirement with a smaller surface.

## 20. Stage 13: Move the Main Checkout Safely

Perform this only after the rework branch is clean and fully validated.

- [ ] Return to the original checkout.
- [ ] Confirm the two known Rust modifications are still present and no new
      modifications appeared.
- [ ] Save them recoverably:

```bash
git stash push -m "pre-rebase obsolete blocking reset rename" -- \
  kernel/src/kernel/sound.rs kernel/src/kernel/startup.rs
```

- [ ] Verify `git status --short` is clean.
- [ ] Ensure the rework worktree is clean.
- [ ] Remove the temporary worktree using `git worktree remove REWORK_DIR`.
- [ ] Switch the main checkout to:

```bash
git switch experiment/deterministic-audio-rebase
```

- [ ] Confirm the stash still exists with `git stash list`.
- [ ] Do not apply that stash to the new branch.
- [ ] Confirm all plan documents are present.
- [ ] Run one final `git status --short` and `git diff --check`.

Do not delete the original source branch or backup branch in this task.

## 21. Required Commit Series

Keep the resulting history logically separable. Use these commits unless a
compile dependency requires combining adjacent stages:

```text
docs(audio): preserve deterministic rebase plans
refactor(audio): add nanosecond event primitives
refactor(audio): establish a nanosecond runtime boundary
feat(audio): add restartable sink preroll lifecycle
fix(hda): apply output routes through deferred sink reset
feat(midi): replay timestamped MPU history in the audio runtime
test(audio): isolate deterministic MIDI validation
test(audio): validate sink continuity and MIDI replay
test(midi): add DOSMid validation fixtures
docs(audio): reconcile the MIDI PoC with upstream timing
```

Do not amend or squash these commits without user approval. Do not add the
optional global klog timestamp commit unless approved.

## 22. Stop and Ask Conditions

Stop implementation and report before proceeding if any of these occurs:

- `origin/master` has new overlapping audio changes not covered by this plan;
- baseline upstream tests fail reproducibly;
- exact guest-write timestamps cannot be obtained from `machine.now()` without
  changing the `Arch` contract;
- `AdvanceOnly` would require fabricating or skipping source-state progression;
- the event queue requires allocation after initialization;
- preserving raw MPU history conflicts with immediate guest-visible protocol;
- the runtime requires DOS-specific types;
- sink reset requires direct OSD-to-HDA programming;
- HDA route switching again depends on playback having started;
- QEMU cannot reach DN after a stage that should preserve boot;
- emulator test processes accumulate or fail to terminate;
- SEJT freezes on F12 OSD;
- any proposed fix requires restoring the video blocking reset hook;
- unrelated upstream VGA/Voodoo/timing files would need to be reverted;
- the complete test suite has an unexpected failure unrelated to documented
  MIDI-only validation exclusions.

## 23. Final Acceptance Criteria

The task is complete only when all statements are true:

- [ ] The new branch is based on current `origin/master`.
- [ ] Upstream `Arch::now()` is the only elapsed-time authority.
- [ ] Guest MPU writes are timestamped with `machine.now()` at the operation.
- [ ] The runtime receives upstream `world_now_ns` and `elapsed_ns`.
- [ ] A reduced source-neutral `AudioRuntime` boundary remains.
- [ ] A nanosecond logical render frontier remains distinct from sink cursors.
- [ ] `TimedEvent<T>` and `FixedEventQueue<T, N>` are reusable by future
      providers.
- [ ] Raw MPU command and data writes share one ordered queue.
- [ ] MPU frontend behavior is immediate and guest-visible.
- [ ] MPU replay and MIDI synth state belong to deterministic source rendering.
- [ ] MIDI reaches the sink only through the canonical mixer.
- [ ] Sink preroll and recovery are source-neutral.
- [ ] HDA/AC97 restart cursor state is synchronized.
- [ ] HDA route changes use a deferred generic sink reset.
- [ ] No separate audio wakeup counter, service divider, fractional time, or
      blocking video reset remains.
- [ ] MIDI-only validation remains explicitly temporary.
- [ ] OPL, SB, and GUS are not migrated prematurely.
- [ ] Full build, unit tests, Clippy, end-to-end tests, QEMU HDA, and approved
      SEJT validation pass or have only explicitly documented baseline/
      validation exclusions.
- [ ] Every changed file has a direct requirement.
- [ ] All plan files survived.
- [ ] The original branch, backup branch, and preservation stash remain
      recoverable.
