# Stable Audio Pacing Across Delayed Kernel Pumps: Exact Fix Plan

## 1. Objective

Fix the audible tape-like pitch modulation heard through HDA when foreground
work delays the event loop, especially while moving continuously in DOOM.

The HDA stream is already programmed for a fixed 48,000 frames/second. The OSD
"Mix rate" is the software producer rate selected by the latency controller,
not the codec format. The current caller violates `Pacer::update_rate`'s
documented contract: it passes the write cursor before including the frames
which the current elapsed interval is about to produce. A delayed 10 ms pump
therefore looks approximately 480 frames too shallow and causes an artificial
rate correction close to +960 Hz at the default 30 ms latency. This matches
the observed OSD rate near 49 kHz.

Produce one focused commit:

    fix(audio): stabilize pacing across delayed pumps

The completed fix must have these properties:

1. HDA remains programmed for 48 kHz, 16-bit stereo.
2. A delayed pump does not create a queue-depth error solely because its frames
   have not yet been submitted.
3. Initial playback starts with the configured latency already represented by
   silence in the existing DMA ring.
4. Underrun recovery re-establishes that silent latency without advancing the
   emulated source clock.
5. Normal 1 ms pumps and delayed multi-millisecond pumps produce the same
   steady effective rate when hardware consumption is exactly 48 kHz.
6. No new allocation, DMA buffer, interrupt route, thread, timer, or hardware
   interface is introduced.
7. HDA, AC'97, and mixed real-SB sinks continue using the same common pacing
   path.

## 2. Mandatory scope limits

Allowed product file:

    kernel/src/kernel/sound.rs

If a deterministic controller test cannot be expressed cleanly there, a test
may additionally be added to:

    lib/sound/src/pacer.rs

Do not modify any other product file during the first implementation.

In particular, do not change:

- `kernel/src/kernel/drivers/hda.rs`;
- HDA stream format, BDL geometry, SDLPIB accounting, or output routing;
- `arch-metal/src/irq.rs` or timer calibration;
- display, keyboard, scheduler, DOS, VGA, aperture, Multiboot, build, image,
  ISO, GRUB, PXE, or deployment code;
- `sound::sink::Device` or its implementations;
- the OSD latency range or default;
- the existing `Pacer` control law, bandwidth, or learned state;
- CI lint failures outside the changed code.

Do not add a hard rate clamp in this commit. A clamp can hide incorrect queue
accounting and can slow legitimate recovery from a real clock mismatch. It is
a separately justified fallback only if the corrected accounting still shows
audible excursions on hardware.

Do not add HDA completion interrupts. The existing 30 ms queue is intended to
absorb ordinary event-loop stalls; this fix makes the controller interpret
those stalls correctly.

Do not commit either this plan or
`HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md`.

## 3. Establish the baseline

1. Run:

       git status --short --branch

2. The only allowed pre-existing untracked files are:

       HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md
       AUDIO_PACING_STABILITY_FIX_PLAN.md

   If any tracked file is modified or any other file is present, stop and ask
   the user. Do not discard, stash, or overwrite unknown work.

3. Confirm the branch and head:

       git branch --show-current
       git log -1 --oneline

   Expected branch:

       feature/hda-output-controls

4. Record the current diff from upstream for reference only:

       git diff --stat origin/master...HEAD

5. Run the focused baseline tests:

       bazelisk test --platforms=@platforms//host \
         //kernel:kernel_unit_test //lib:sound_test

6. If either baseline target fails, stop and report the first useful error.
   Do not alter unrelated code to make the baseline green.

## 4. Preserve the pacing invariants

Before editing, read these exact regions completely:

    lib/sound/src/pacer.rs
    lib/sound/src/sink.rs
    kernel/src/kernel/sound.rs

Keep these invariants throughout the change:

1. `written_frames` and `consumed_frames` are absolute sink cursors with the
   same origin.
2. The queue depth is `written_frames - consumed_frames` after recovery has
   guaranteed that written is not behind consumed.
3. `Clock` is source time. Priming silence must not call `Clock::produce` and
   must not change `Clock::produced_q16`.
4. The pacer's learned state `s_q16` is retained across ordinary delayed pumps
   and underrun recovery.
5. The controller update runs only when the hardware cursor moved, as it does
   now. Do not restore per-pump controller updates.
6. The value passed as `written` to `Pacer::update_rate` must include the frames
   expected from the elapsed interval currently being serviced.
7. The actual number of frames submitted remains determined by
   `Clock::produce`; prediction must not itself advance source time.
8. Priming writes only zero-valued frames into the existing sink ring and
   advances only the sink write cursor.

## 5. Add a pure current-pump prediction helper

In `kernel/src/kernel/sound.rs`, add one small private helper near `Clock` or
immediately before `advance`:

    fn predicted_written(
        clock: &Clock,
        written: u64,
        rate_q16: u64,
        elapsed_ms: u64,
    ) -> u64

Its implementation must:

1. Call the existing non-mutating `Clock::frames_for(rate_q16, elapsed_ms)`.
2. Add that frame count to `written` with `saturating_add`.
3. Not mutate `Clock`, `Sink`, or `Pacer`.

Do not duplicate the fixed-point frame calculation outside `Clock::frames_for`.

## 6. Predict with the previously selected rate

In `sound::advance`, inside the active-sink path:

1. After polling and reading `written`, `consumed`, and `fill`, calculate the
   rate which was already in force before this pump:

       previous_rate_q16 = output.rate_q16
           .unwrap_or_else(|| output.producer.s_q16())

2. Do not call `update_rate` yet.

3. For a normal non-underrun pump, calculate:

       controller_written = predicted_written(
           clock,
           written,
           previous_rate_q16,
           elapsed_ms,
       )

4. When `drained > 0`, call `Pacer::update_rate` with
   `controller_written`, not the stale `written` cursor.

5. Continue passing the real `consumed`, `fill`, and accumulated
   `ms_since_cursor` values.

6. Continue using the returned rate for the current call to `Clock::produce`.
   The prediction uses the previous rate to break the otherwise circular
   dependency; the actual production uses the newly corrected rate.

7. Preserve the existing rule that no controller update occurs when
   `drained == 0`.

8. Update the nearby comment so it states explicitly that the queue
   measurement includes the current elapsed interval's predicted production.
   Do not rewrite unrelated documentation.

The steady delayed-pump example must now evaluate as follows:

    nominal rate:       48,000 Hz
    target:              1,440 frames
    elapsed:                10 ms
    written before pump: 1,440
    consumed:               480
    predicted production:   480
    controller written:    1,920
    controller anchor:     1,920
    queue error q:             0

The controller must therefore return exactly its current learned rate in this
idealized case instead of producing an approximately +960 Hz dashpot jump.

## 7. Prime the existing ring with silence

Add one private method to the kernel `Sink` wrapper in
`kernel/src/kernel/sound.rs`:

    fn prime_silence_to(&mut self, target_ahead_frames: u64)

The method must:

1. Read the current `written_frames` and `consumed_frames` from `self.inner`.
2. Compute current ahead depth with `saturating_sub`.
3. Compute only the missing amount needed to reach `target_ahead_frames`.
4. Cap the target at `self.inner.max_ahead_frames()`.
5. Submit zero `(i32, i32)` frames through the existing `play`/`submit` path in
   chunks no larger than `MIX_CHUNK`.
6. Use unity gain (`1 << 16`) or call `inner.submit` directly; zero multiplied
   by any gain remains zero. Prefer the smaller diff.
7. Allocate no heap memory. Use one fixed stack array of `MIX_CHUNK` zero
   frames and submit slices of it.
8. Never call `Clock::produce`, a source mixer, or a hardware start/stop method.

Move `const MIX_CHUNK: usize = 128` earlier in the file only if required for
the method to use it. Do not change its value.

### 7.1 Prime at construction

In `Sink::new`, after creating `sound::sink::Sink` and obtaining its device
rate:

1. Construct the kernel `Sink` value as usual.
2. Calculate the requested latency exactly as `advance` does:

       requested = ceil(rate * audio_latency_ms / 1000)

3. Cap it at `inner.max_ahead_frames()`.
4. Call `prime_silence_to(requested)` before returning the new sink.

This claims already-zero ring frames as initial latency without advancing
emulated source time. Do not start the device a second time.

### 7.2 Prime after underrun recovery

In the existing `written < consumed` branch of `advance`:

1. Call `recover_from_underrun()` as today. This reanchors the sink write
   cursor at the consumer.
2. Call `prime_silence_to(fill as u64)` immediately afterward.
3. Reload `written` from `output.inner.written_frames()`; do not assume the
   arithmetic result.
4. Set `output.last_consumed = consumed`.
5. Set `output.ms_since_cursor = 0`.
6. Set `output.rate_q16 = None` so the next ordinary measurement starts from
   the retained learned state `producer.s_q16()`.
7. Set `elapsed_ms = 0` for this recovery call. The missed source interval is
   discarded rather than replayed over the freshly restored latency.
8. Do not call `Pacer::update_rate` in the recovery branch.

The recovery is intentionally a discrete loss of an already missed interval,
not a pitch excursion. The following tick resumes normal source production at
the learned rate.

## 8. Add deterministic regression tests

Add a private `#[cfg(test)] mod tests` to `kernel/src/kernel/sound.rs`, or add
to an existing test module if one exists by implementation time.

Use pure counters and `Clock`; do not instantiate HDA, map memory, or run QEMU.

### 8.1 Delayed pump does not change the rate

Add a test named:

    delayed_pump_prediction_does_not_invent_queue_deficit

Test exactly this case:

1. Create `Clock::new()`.
2. Use `rate_q16 = 48_000 << RATE_FP_SHIFT`.
3. Use `target = 1_440`, `written = 1_440`, `consumed = 480`, and
   `elapsed_ms = 10`.
4. Assert that `predicted_written(...) == 1_920`.
5. Create `sound::Pacer::new(48_000)`.
6. Call `update_rate(1_920, 480, 1_440, 10)`.
7. Assert that the returned rate is exactly `rate_q16`.

The test must fail if `written` rather than predicted written is passed: that
incorrect input produces a substantial rate increase.

### 8.2 Prediction does not advance source time

Add a test named:

    predicting_current_pump_does_not_advance_clock

1. Create a new `Clock`.
2. Record `produced_frames()`.
3. Call `predicted_written` for a 10 ms interval.
4. Assert that `produced_frames()` is unchanged.
5. Then call `Clock::produce` once and assert that it produces 480 frames.

### 8.3 Multi-pump stability

Add a test named:

    mixed_service_intervals_keep_ideal_sink_at_nominal_rate

Simulate at least this sequence of elapsed intervals:

    [1, 1, 10, 1, 7, 1, 1, 14, 1]

For each interval:

1. Advance a synthetic consumed cursor by exactly
   `48_000 * elapsed_ms / 1000`, preserving fractional arithmetic if needed.
2. Predict the current pump's production from the current rate.
3. Call `update_rate` only for that cursor movement.
4. Assert after every update that the effective rate remains exactly
   `48_000 << RATE_FP_SHIFT` for this ideal sink.
5. Advance the synthetic written cursor by the actual due frames.

Keep this test pure and short. If exact fractional bookkeeping makes the test
opaque, use intervals whose products are integral, as the listed intervals are
at 48 kHz.

### 8.4 Priming arithmetic

If `prime_silence_to` is difficult to instantiate without a kernel device,
extract only its arithmetic into a private pure helper:

    fn silence_frames_needed(written: u64, consumed: u64, target: u64) -> u64

Test that it returns:

- 1,440 for written=consumed=0 and target=1,440;
- 960 for written=480, consumed=0 and target=1,440;
- 0 when already at or above target;
- the full target when consumed has overtaken written and recovery has rebased
  both cursors to the same value.

Do not introduce a public API solely for testing.

## 9. Focused verification

Run, in this order:

1. Formatting/whitespace:

       git diff --check

2. Host unit tests:

       bazelisk test --platforms=@platforms//host \
         //kernel:kernel_unit_test //lib:sound_test

3. Production kernel build:

       bazelisk build //kernel:kernel_elf

4. Exact CI metal Clippy command:

       bazelisk build --config=clippy \
         //kernel:kernel //lib:lib //lib:sound \
         //arch-abi:arch-abi //arch-metal:arch-metal

5. Exact CI host Clippy command:

       bazelisk build --config=clippy --platforms=@platforms//host \
         //kernel:kernel //kernel:retroos-host \
         //arch-interp:arch-interp //lib:lib //lib:sound //arch-abi:arch-abi

The branch currently inherits unrelated Clippy findings from `origin/master`.
The acceptance rule is:

- no diagnostic may point to a line changed by this fix;
- no new diagnostic may appear compared with the recorded baseline;
- do not repair unrelated Clippy findings in this commit.

6. Run the full suite:

       bash test/run_all.sh

The suite must finish and leave no QEMU or 86Box process behind. Report the
exact pass/fail/skip summary.

## 10. Commit discipline

Before committing:

1. Run:

       git status --short
       git diff --stat
       git diff -- kernel/src/kernel/sound.rs lib/sound/src/pacer.rs

2. Confirm no file outside the allowed scope changed.

3. Confirm neither plan is staged:

       git diff --cached --name-only

4. Stage only the actual implementation file or files.

5. Create exactly one commit:

       git commit -m "fix(audio): stabilize pacing across delayed pumps" \
         -m "Include the current pump's predicted production in latency feedback so delayed event-loop service does not create false rate excursions. Prime the existing sink ring with silence at startup and underrun recovery without advancing emulated source time."

6. Do not push unless the user explicitly asks.

## 11. SEJT validation without RLOG

Do this only after the user explicitly asks to deploy or test on SEJT.

Use the SEJT hardware workflow with RLOG disabled. Build and publish the normal
kernel plus the standard Multiboot modules. Do not send an RCTL reboot. Ask the
user to reboot the SEJT manually.

Manual acceptance test:

1. Boot the new deployment and open the F12 OSD Sound tab.
2. Confirm the HDA output route remains Speaker unless configured otherwise.
3. Start DOOM and enter a level with continuous music.
4. Observe Mix rate while standing still for at least 20 seconds.
5. Hold Up continuously for at least 20 seconds in a visually busy scene.
6. Release Up and continue listening for another 20 seconds.
7. Repeat at the default 30 ms latency.
8. The rate should remain close to its learned steady value and must not jump
   toward roughly 49 kHz in step with movement.
9. There must be no periodic tape-like slowing and speeding.
10. A single interruption after a genuine underrun is acceptable evidence of
    insufficient service time; continuous pitch modulation is not.

Record the observed stationary rate, moving rate range, latency setting, and
whether any underrun warning appeared on a visible console.

## 12. Stop conditions and second-stage investigation

Stop the first implementation after the scoped commit and tests. Do not add
more fixes speculatively.

If SEJT still shows audible wow after the prediction and priming fix:

1. Enable the existing Trace diagnostics through the OSD.
2. Collect or transcribe the existing `census:` and `audio: rate=` lines by an
   available evidence channel. Do not assume RLOG exists.
3. Compare `dt_sum`, `drained`, `produced`, `rate`, `s`, depth, and target
   between stationary and moving cases.
4. Check for `WARNING: sound underrun` messages.
5. Only then choose one separate follow-up:

   - Bound HDA SDLPIB deltas by plausible/in-flight progress if cursor jumps
     are observed.
   - Make pending tick take/reset atomic with respect to timer interrupts if
     census shows lost elapsed time.
   - Split or budget synchronous framebuffer publication if pumps are delayed
     beyond the configured ring latency.
   - Add a conservative instantaneous rate-excursion clamp only if accounting
     is correct but cursor quantization still creates audible modulation.

Each follow-up requires its own diagnosis, tests, and commit. Do not combine
any of them with the initial pacing fix.

