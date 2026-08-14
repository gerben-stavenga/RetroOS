# Audio Pre-roll Resume Gate: Exact Implementation Plan

## 1. Objective

Replace immediate codec playback with a generic audio readiness gate. A newly
created sink must remain stopped when the first mixer block arrives. It must
start physical playback only after the mixer has supplied a continuous pre-roll
of real output frames. After a genuine runtime underrun or an unserviceable
elapsed-time gap, the same gate must stop playback, discard stale queued audio,
re-prime the pacer, collect a fresh continuous pre-roll, and resume.

This is intentionally independent of display mode changes, the OSD, BIOS calls,
or any other individual source of latency. Audio must infer readiness from its
own producer continuity and hardware cursor state.

The implementation must retain permanent lifecycle logging so
`/proc/klog.txt` remains useful on real hardware. An underrun immediately stops
the stream, so log that one state transition rather than retaining the old
consecutive-underrun compactor.

## 2. Required baseline

Implement this plan on top of the HPET-only fix, not on top of any experimental
audio branch.

The required product history is:

    <current origin/master>
    fix(timer): recover elapsed time across firmware stalls

The reference commit for the timer fix in the current repository is:

    65dfcf2 fix(timer): recover elapsed time across firmware stalls

The local test branch may contain the equivalent cherry-picked commit with a
different object ID (`9a2efac` at the time this plan was written). Compare the
patch, not only the commit ID.

Do not include or depend on these experimental commits:

    8bc6f96 fix(audio): stabilize pacing across delayed pumps
    2111520 test(audio): prime output before first mixer pump
    b804722 test(audio): prime output only at startup

Do not inherit startup silence submission, predicted-write pacing, or runtime
silence insertion from those experiments.

The lifecycle markers from:

    a1e6e72 debug(audio): trace startup and compact underruns

are required behavior, but reimplement them against the new state machine as
specified below. Its underrun compaction is obsolete once the first underrun
immediately stops playback. Do not blindly cherry-pick `a1e6e72`, because its
parent contains the rejected startup-silence experiment and its implementation
assumes an always-running sink.

## 3. Create the implementation branch

1. Fetch upstream:

       git fetch origin

2. Verify that the working tree has no tracked modifications:

       git status --short --branch

3. Preserve all existing untracked plan and analysis Markdown files. Do not
   add, delete, stash, or commit them.

4. Create a new branch from the current blessed upstream master:

       git switch -c fix/audio-preroll-resume-gate origin/master

5. Cherry-pick the HPET fix only:

       git cherry-pick 65dfcf2

6. Confirm the branch contains exactly one product commit over upstream before
   implementation:

       git log --oneline origin/master..HEAD
       git diff --stat origin/master...HEAD

7. If the HPET commit is already present in `origin/master`, do not cherry-pick
   it a second time. Record that fact and start directly from `origin/master`.

## 4. Scope limits

Product changes are allowed only in:

    lib/sound/src/sink.rs
    kernel/src/kernel/sound.rs
    kernel/src/kernel/drivers/hda.rs
    kernel/src/kernel/drivers/ac97.rs
    kernel/src/kernel/drivers/sb16.rs

Tests colocated in those files may be changed or added.

Do not modify:

- display, OSD, VGA, VBE, BIOS, DOS, Linux, scheduler, input, or event-loop
  call sites;
- HPET, LAPIC, PIT, IRQ, or timer code beyond the existing HPET commit;
- HDA stream format, BDL geometry, codec routing, jack selection, or volume;
- AC'97 or SB16 geometry and format;
- build targets, images, GRUB configuration, PXE configuration, deployment
  scripts, or test fixtures;
- the pacer control law in `lib/sound/src/pacer.rs`;
- the configured normal latency or OSD latency controls;
- any Multiboot or aperture code.

Do not add a thread, timer, interrupt route, allocation, second PCM ring, or
display-to-audio callback.

## 5. Preserve these invariants

1. The DMA ring is the only physical-output buffer.
2. Frames submitted by the real mixer are the only frames that count toward
   pre-roll readiness. Do not manufacture silence to satisfy the gate.
3. A first mixer submission proves only that production began; it does not
   immediately start the codec.
4. While playback is stopped, the hardware consumer cursor remains stationary
   and must not drive `Pacer` feedback.
5. Pre-roll production uses the device's nominal rate exactly:

       device_rate << RATE_FP_SHIFT

6. Starting or restarting playback creates a fresh hardware cursor origin and
   reinitializes the pacer to the device's nominal rate.
7. Entering recovery discards stale queued output. Old game audio must never be
   replayed after an OSD, video, firmware, or scheduling stall.
8. A runtime stall may intentionally create a short silent gap. It must not
   create crackling, rapid catch-up playback, or prolonged pitch correction.
9. The source `Clock` must never be rewound. When an elapsed batch is discarded
   because it cannot safely be represented, do not call `Clock::produce` for
   that discarded batch.
10. Session teardown still performs the existing full hardware shutdown.

## 6. Extend the device contract with playback-only pause

In `lib/sound/src/sink.rs`, add this required method to `Device`:

    fn pause(&mut self);

Define its contract precisely in documentation:

- stop only PCM playback DMA;
- leave the device initialized and restartable by `start()`;
- re-baseline device-side playback counters so the next `start()` begins from
  a fresh zero cursor;
- do not tear down controller command infrastructure required by `start()`;
- be safe when playback is already stopped;
- do not allocate.

Forward `pause()` in the existing `impl<T: Device + ?Sized> Device for &mut T`.

Keep `halt()` as full session teardown. Do not redefine `halt()` as temporary
pause.

### 6.1 HDA implementation

In `kernel/src/kernel/drivers/hda.rs`:

1. Implement `Device::pause()` by invoking the existing playback-only stop
   operation (`stop_playback()`).
2. Do not call `stop_corb_rirb()` from `pause()`.
3. Keep `halt()` as:

       stop_playback();
       stop_corb_rirb();

4. Verify `start()` re-baselines `consumed_hw`, `last_hw_pos`, and `reported`
   before setting RUN. Preserve that behavior.
5. Preserve pending output-route application in `start()`.

### 6.2 AC'97 implementation

In `kernel/src/kernel/drivers/ac97.rs`:

1. Move or share the current RUN-bit clearing operation so `pause()` clears
   `PO_CR_RUN` without destroying controller setup.
2. Let `halt()` call the same playback stop operation unless teardown requires
   additional existing work.
3. Keep `start()` responsible for resetting its position/report counters.

### 6.3 SB16 implementation

In `kernel/src/kernel/drivers/sb16.rs`:

1. Implement `pause()` using the existing auto-init DMA halt and DMA-channel
   mask sequence currently used by `halt()`.
2. Preserve whatever DSP reset/speaker state is required for the existing
   `start()` to reprogram playback reliably.
3. Keep `halt()` behavior unchanged or share the exact same lower-level stop
   helper if temporary pause and final teardown are equivalent for this driver.
4. Do not change guest-visible Sound Blaster emulation; this applies only to a
   physical SB16 adopted as the kernel mixer sink.

## 7. Make the shared sink explicitly stopped or running

In `lib/sound/src/sink.rs`, add an explicit private playback state. A boolean
named `running` is sufficient; do not introduce a larger enum unless tests show
that more states are necessary.

### 7.1 Construction

Change `Sink::new` as follows:

1. Validate ring geometry as before.
2. Clear the ring as before.
3. Do not call `dev.start()`.
4. Initialize `running` to `false`.
5. Initialize all software cursors to zero.

Update its documentation: construction arms ownership and clears storage but
does not start physical playback.

### 7.2 Start operation

Add:

    pub fn start(&mut self)

It must:

1. Assert or return early if already running. Prefer an idempotent early return
   to make recovery robust.
2. Require at least one submitted frame. Add a debug assertion that
   `written_frames > 0`.
3. Call `dev.start()` exactly once per stopped-to-running transition.
4. Set `running = true`.

### 7.3 Pause and reset operation

Add:

    pub fn pause_and_reset(&mut self)

It must:

1. If running, call `dev.pause()` and set `running = false`.
2. If already stopped, do not call the device again.
3. Clear the complete DMA ring to zero.
4. Reset `write_pos`, `written_frames`, `played_frames`, and
   `written_frames_at_last_completion` to zero.
5. Leave device ownership intact.

This is the only operation used to abandon stale queued audio and prepare a
fresh pre-roll.

### 7.4 Polling

When `running == false`, `poll()` must return `Report::default()` without
calling `dev.frames_played()`.

When running, preserve the current cursor and underrun behavior.

Add:

    pub fn is_running(&self) -> bool

for the kernel wrapper and tests.

### 7.5 Teardown

`into_device()` must still call `dev.halt()` for full session teardown whether
the sink is running or stopped. Do not substitute `pause()` there.

## 8. Add the kernel pre-roll state machine

In `kernel/src/kernel/sound.rs`, add a private state to the kernel `Sink`:

    enum PlaybackState {
        PreRoll,
        Running,
    }

Initialize it to `PreRoll` in `Sink::new`.

Do not submit startup silence in `Sink::new`. The inner sink must have:

    written_frames == 0
    consumed_frames == 0
    is_running() == false

Add these fields to the kernel wrapper:

    playback: PlaybackState
    has_produced_audio: bool

Do not add a separate pre-roll frame counter. While stopped and freshly reset,
`inner.written_frames()` is the exact number of accumulated real pre-roll
frames.

## 9. Define readiness constants

Add one private constant near `MIX_CHUNK`:

    const MAX_PREROLL_GAP_MS: u64 = 15;

The pre-roll target follows the OSD-configured latency. Calculate it from the
active device rate with ceiling division, round it up to at least one hardware
completion block, and cap it at `inner.max_ahead_frames()`:

    requested = (rate * configured_latency_ms).div_ceil(1000)
    target = requested.max(inner.block_frames()).min(inner.max_ahead_frames())

Add an assertion that the result is nonzero. Do not introduce a fixed 50 ms
minimum: low latency is an explicit project requirement. The hardware block is
the unavoidable lower bound (about 2.7 ms for HDA, 10.7 ms for AC'97, and
21.3 ms for the current SB16 geometry).

Use this same target calculation at initialization, after recovery, and when
deciding whether to start playback. Normal running feedback uses the same
configured latency target.

## 10. Permanent lifecycle logs

Retain concise, event-driven logs. Do not print one line per pump.

At sink construction print once:

    sound: sink initialized stopped rate=R preroll_frames=P

On the first nonempty mixer submission in the sink's lifetime print once:

    sound: first mixer block submitted frames=N queued=Q

Whenever a pre-roll is discarded because its service gap exceeded
`MAX_PREROLL_GAP_MS`, print:

    sound: preroll reset gap_ms=D discarded_frames=Q

Whenever playback starts or restarts print:

    sound: playback start preroll_frames=Q target_frames=P

Whenever running playback enters recovery print one line:

    sound: playback recovery reason=REASON underruns=N written=W consumed=C

Use one of these exact reason strings:

    underrun
    producer_behind
    ring_capacity

Increment `UNDERRUNS` before printing only when `REASON` is `underrun`. For the
other reasons, print the current unchanged total. This one recovery line
replaces the old separate `WARNING: sound underrun` line.

Preserve the existing first hardware-consumption marker:

    sink: first frame played

It may appear again after a restart because each run has a fresh cursor origin.
That is useful and intentional.

Do not add timestamps, per-pump logs, or debug-only feature flags in this
implementation.

## 11. Remove obsolete underrun compaction

Do not carry `pending_underrun`, `skipped_underruns`, or the `... skipped N ...`
message into this implementation.

The state machine guarantees that the first underrun report transitions from
`Running` to `PreRoll`, pauses the device, and prevents further hardware polling
until playback restarts. There can therefore be only one underrun report per
recovery episode. If the log contains many recovery lines, those are distinct
failed restart episodes and must remain visible rather than being compacted.

Keep the global `UNDERRUNS` total. Increment it exactly once when an underrun
causes a `Running` to `PreRoll` transition, and include the new total in that
transition's lifecycle line.

## 12. Pre-roll production behavior

Refactor `sound::advance` so stopped/pre-roll and running behavior are explicit.

### 12.1 Beginning a pre-roll pump

When `playback == PreRoll`:

1. Do not poll the hardware device.
2. Do not call `Pacer::update_rate`.
3. Use the nominal device rate for both source pitch and frame count:

       nominal_rate_q16 = u64::from(inner.rate()) << RATE_FP_SHIFT

4. If `elapsed_ms > MAX_PREROLL_GAP_MS`:
   - log the pre-roll reset if queued frames are nonzero;
   - call `inner.pause_and_reset()`;
   - set `elapsed_ms = 0` for this pump;
   - do not mix or submit a catch-up block for the discarded interval.
5. Otherwise, let the existing `Clock::produce` and mixer path produce the
   current pump at nominal rate.

The first mixer block must only begin accumulation. It must not special-case an
immediate device start.

### 12.2 Completing a pre-roll pump

After all chunks for the current pump have been submitted:

1. Read `queued = inner.written_frames()`; consumed remains zero while stopped.
2. If `queued` is below the current configured-latency pre-roll target, remain
   in `PreRoll`.
3. If `queued` reaches that target:
   - replace the pacer with `sound::Pacer::new(inner.rate())`;
   - reset `last_consumed`, `ms_since_cursor`, and `rate_q16` to their initial
     values;
   - call `inner.start()`;
   - set `playback = Running`;
   - print the playback-start marker.

Do not add any fixed cushion beyond the configured target and one device block.
The pre-roll is intentionally low-latency and drains naturally toward the same
target after playback starts.

## 13. Running behavior and recovery triggers

When `playback == Running`, retain the HPET-only pacing behavior. Do not add the
predicted-write algorithm from `8bc6f96`.

Enter `PreRoll` through one shared private helper such as:

    fn enter_preroll(&mut self, reason: RecoveryReason)

The helper must:

1. If the reason is `underrun`, increment `UNDERRUNS` exactly once.
2. Log the recovery reason, underrun total, and current cursors.
3. Call `inner.pause_and_reset()`.
4. Replace the pacer with `sound::Pacer::new(inner.rate())`.
5. Reset `last_consumed`, `ms_since_cursor`, and `rate_q16`.
6. Set `playback = PreRoll`.

Use it for exactly these conditions:

1. `report.underrun.is_some()` → `underrun`.
2. `written < consumed` when observed independently → `producer_behind`.
3. The existing condition where the current elapsed production cannot fit
   below `safety_ceiling_frames()` → `ring_capacity`.

For any pump that enters pre-roll from running state:

- set `elapsed_ms = 0`;
- do not render or submit the stale elapsed interval;
- begin fresh pre-roll on the next nonzero healthy pump.

Do not prime silence in any recovery path.

Avoid recovering twice from one poll. Give `report.underrun` precedence, then
skip the `written < consumed` check for that same transition.

## 14. Pitch-rate publication while gated

While in `PreRoll`, publish the nominal device rate through
`publish_mixing_rate_q16`. Do not publish stale pacer state from the previous
run.

When playback starts, the newly constructed pacer also begins at that nominal
rate. This is the intended pacer re-priming that prevents the resampler from
slowly converging from obsolete pre-stall feedback.

Normal running publication remains the pacer's steady `s_q16`, exactly as on
the HPET-only baseline.

## 15. Required unit tests

### 15.1 Shared sink tests in `lib/sound/src/sink.rs`

Extend `TestDevice` with separate `starts`, `pauses`, and `halts` counters.

Add or update tests proving all of the following:

1. `Sink::new` clears the ring and does not start the device.
2. Submitting frames while stopped does not start the device.
3. `start()` starts exactly once and is idempotent while already running.
4. `poll()` while stopped does not query or advance the device cursor.
5. `pause_and_reset()` calls `pause()` once when running.
6. `pause_and_reset()` is device-idempotent while already stopped.
7. `pause_and_reset()` clears ring content and resets every software cursor.
8. A fresh submission after reset begins at ring position zero.
9. Start after reset establishes a fresh completion origin.
10. `into_device()` calls full `halt()`, not only `pause()`.
11. Existing gain, capacity, completion, and underrun tests still pass after
    adapting them to call `start()` explicitly where hardware movement is
    required.

### 15.2 Kernel sound tests

Extract only small pure helpers if needed; do not build a second fake audio
engine in `kernel/src/kernel/sound.rs`.

Add tests for:

1. 48 kHz and a configured 10 ms latency calculate 480 frames before block
   rounding.
2. The target is rounded up to at least one device block.
3. The target is capped by `max_ahead_frames()`.
4. A first 128-frame block does not satisfy a 10 ms HDA target.
5. Consecutive healthy submissions crossing the configured target request one
   start.
6. A gap greater than 15 ms resets accumulated pre-roll.
7. A gap of exactly 15 ms remains valid.
8. A discarded gap produces zero frames for that pump.
9. One underrun report increments the total once and immediately requests a
   transition to pre-roll; a stopped/pre-roll poll cannot create another
   underrun.

If testing the complete kernel wrapper requires invasive mocking, put the state
transition arithmetic in a small private pure helper and test that helper. Do
not expose a public testing API.

## 16. Focused validation

Run in this order:

    git diff --check

    bazelisk test --platforms=@platforms//host \
      //lib:sound_test \
      //kernel:kernel_unit_test

    bazelisk build //kernel:kernel_elf //:grub_module_iso

Run Clippy using the same command or target used by the repository's current
GitHub CI workflow. Inspect `.github/workflows` rather than guessing the flags.
Fix only warnings introduced in the allowed product files.

## 17. QEMU validation

Boot the GRUB module ISO with an explicit HDA device and a silent host backend:

    timeout 20s qemu-system-i386 \
      -m 512 \
      -cpu pentium3 \
      -cdrom bazel-bin/retroos_grub_module.iso \
      -boot order=d \
      -audiodev driver=none,id=snd0 \
      -device intel-hda \
      -device hda-duplex,audiodev=snd0 \
      -machine pcspk-audiodev=snd0 \
      -debugcon stdio \
      -display none \
      -no-reboot

Confirm the log order is:

    sound: sink initialized stopped ...
    sound: first mixer block submitted ...
    sound: playback start preroll_frames=... target_frames=...
    hda: stream RUN ...
    sink: first frame played

The exact ordering of the playback-start and HDA RUN lines may be reversed only
if the kernel marker is emitted after `inner.start()`; choose one ordering and
keep it deterministic.

Reject the implementation if any of these occur:

- HDA RUN appears before the first mixer block;
- playback starts after only one 128-frame block;
- repeated underrun/recovery/start cycles occur under idle QEMU;
- repeated recovery/start loops occur under idle QEMU;
- an assertion reports producer overtake.

## 18. Full automated validation

After focused and QEMU validation pass, run the repository's complete test suite
using the documented command in the repository. Ensure emulator tests terminate
and do not leave QEMU or 86Box processes running.

Do not weaken, skip, or lengthen unrelated tests merely to make this feature
pass.

## 19. SEJT deployment and hardware test

Use the repository's SEJT hardware workflow and deploy the ordinary Multiboot
kernel with both existing modules:

    bazel-bin/retroos-base.img.gz /
    bazel-bin/retroos-games.img.gz /home/retroos/GAMES

Do not deploy a monolithic HDD kernel. Do not enable RLOG if the branch is not
prepared for it. Publication must not reboot the machine without explicit user
authorization.

After manual reboot, collect `/proc/klog.txt` and verify:

1. HDA does not RUN at sink construction.
2. The first mixer block begins pre-roll but does not start playback.
3. Playback starts after the configured latency target, rounded up to one HDA
   block—not after an artificial 50 ms delay.
4. The former ~2,000 startup-underrun flood is absent.
5. Each genuine recovery episode has one lifecycle line; no `... skipped ...`
   message or separate underrun warning remains.
6. DOOM has no detectable pitch bend while a key is held.
7. Duke3D VESA 800x600 survives F12 OSD open/close.
8. After OSD close, audio resumes after a short clean gap without crackling,
   alternating silence/speed-up chunks, or long pitch convergence.
9. A game video-mode switch produces at most a short clean pause and one
   recovery/pre-roll/start sequence.
10. The OSD mix rate returns immediately near 48 kHz because the pacer is
    reinitialized on restart.

If recovery loops continuously, record the lifecycle lines before changing
the configured latency or `MAX_PREROLL_GAP_MS` blindly.

## 20. Commit structure

Produce one implementation commit on top of the HPET commit:

    fix(audio): gate playback on continuous mixer pre-roll

The commit body must explain:

- physical playback remains stopped until continuous real mixer output fills
  the configured latency target, rounded up to one hardware block;
- underrun and oversized-gap recovery discard stale audio and reuse the same
  gate;
- restarting the pacer at nominal device rate avoids prolonged resampler
  convergence;
- playback-only pause keeps HDA command transport alive;
- lifecycle markers and one counted recovery line per underrun episode remain
  as permanent hardware diagnostics;
- no display-specific coupling, extra buffer, allocation, thread, timer, or
  interrupt path was added.

Do not commit this plan or any other plan/analysis Markdown file.

## 21. Final review checklist

Before handing the branch back, confirm:

    git status --short --branch
    git diff --check origin/master...HEAD
    git log --oneline origin/master..HEAD
    git diff --stat origin/master...HEAD

The only commits over the required baseline must be the HPET fix, if not
already upstream, and the single pre-roll-gate implementation commit.

The final report must include:

- exact branch and commit IDs;
- changed product files;
- focused, Clippy, full-suite, and QEMU results;
- QEMU lifecycle log sequence;
- SEJT lifecycle and recovery observations, if hardware testing was performed;
- any remaining uncertainty, especially whether the 15 ms continuity gap
  requires hardware tuning.
