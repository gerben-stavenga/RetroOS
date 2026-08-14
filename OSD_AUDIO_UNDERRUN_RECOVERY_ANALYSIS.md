# OSD Audio Underrun Recovery Analysis and Isolation Test

## Observed behavior

On the Intel D945GSEJT, opening the F12 OSD while a game is running slows the
game substantially. This is plausibly caused by the additional framebuffer
capture, conversion, OSD composition, scaling, and framebuffer publication.

After closing the OSD, audio does not immediately become continuous. It plays
short accelerated chunks separated by silence. The chunks gradually slow and
merge into a continuous stream.

## Relevant execution order

The main loop advances audio before publishing the display:

    timer elapsed time
        -> advance game devices
        -> poll and feed audio
        -> capture/render/publish display and OSD
        -> next loop iteration

Putting audio first prevents the current framebuffer operation from delaying
the current audio pump. A slow display operation can still delay the next pump.
The HDA codec continues consuming its DMA ring during that delay.

At the default 30 ms latency, approximately 1,440 frames are queued at 48 kHz.
If OSD work prevents the producer from running for longer than that, the HDA
consumer can reach or pass the producer frontier.

## Relationship to silence priming

Commit `8bc6f96 fix(audio): stabilize pacing across delayed pumps` introduced
three related behaviors:

1. It predicts the frames about to be produced by the current delayed pump
   before updating the queue controller. This prevents an unsubmitted pump
   from looking like a false queue deficit.
2. It primes the DMA ring with the configured latency in silence at startup.
3. After recovery, it rebases the producer at the hardware cursor, restores
   the configured latency with silence, and discards the obsolete source-time
   interval instead of replaying it.

For a detected overtake where:

    consumed > written

the new recovery inserts approximately 30 ms of silence once. This silence is
intentional: it creates safe headroom without advancing the game's source
clock or replaying stale audio. By itself, one priming operation should not
cause a long sequence of bursts and gaps.

Repeated OSD stalls could repeatedly exhaust that new queue and therefore
cause repeated recoveries and repeated 30 ms silent regions. That is one
possible contributor while the OSD remains open.

## Suspected equality boundary

The shared sink declares an underrun when an active producer has reached or
fallen behind the consumer:

    written_frames <= consumed_frames

The kernel recovery path currently runs only when:

    written < consumed

Therefore this exact boundary is possible:

    written == consumed

At equality, the DMA queue is empty and the sink reports an underrun, but the
kernel does not rebase or prime silence. The pacer must rebuild the requested
30 ms queue by temporarily producing faster than the codec consumes.

That predicts the reported pattern:

    queue empty
        -> short accelerated audio chunk
        -> codec consumes the chunk and reaches silence
        -> another accelerated chunk is produced
        -> queue depth grows gradually
        -> chunks merge into continuous playback
        -> effective rate settles toward steady state

The pacer's control loop is deliberately gentle, so rebuilding an empty queue
through feedback can take noticeably longer than inserting the target depth
immediately.

This equality mismatch existed before the silence-priming commit. The commit
changes recovery after a strict overtake, but it does not handle equality.

## Evidence available without a diagnostic build

After reproducing the issue, inspect:

    C:\PROC\KLOG.TXT

Look for:

    WARNING: sound underrun #N written_frames=W consumed_frames=C

Interpret the values as follows:

- `W == C`: strongly supports the unhandled empty-queue boundary.
- `W < C`, one warning near OSD closure: the new recovery probably inserted
  one silent latency region and should have recovered quickly.
- `W < C`, repeated warnings while the OSD is open: OSD display work repeatedly
  exhausts the queue despite each recovery.
- no warning: investigate cursor polling, a missed modular HDA ring wrap, or a
  path where the queue becomes audibly shallow without satisfying the sink's
  active-producer underrun rule.

## Isolation objective

Determine separately whether the useful hardware improvement came from:

1. `65dfcf2 fix(timer): recover elapsed time across firmware stalls`;
2. the complete audio commit `8bc6f96`;
3. only the delayed-pump prediction portion of `8bc6f96`;
4. silence priming/re-priming;
5. an interaction between the timer and audio commits.

The stable OSD pitch-rate value does not need to equal exactly 48 kHz for this
test. Judge audible continuity, game speed, recovery after OSD closure, held-key
behavior, and underrun messages independently.

## Branch variants

Create test variants from the same current `origin/master` so results are not
confounded by unrelated history.

### Variant A: current master

Contains the author's pitch/frame-count split but neither branch fix.

Purpose:

- establish current upstream behavior;
- show whether OSD recovery trouble already exists without either fix.

### Variant B: HPET correction only

Apply only:

    65dfcf2 fix(timer): recover elapsed time across firmware stalls

Do not include any part of `8bc6f96`.

Purpose:

- isolate the improvement in whole-system/game timing during SMM stalls;
- test whether HPET correction alone removes the original held-key slowdown;
- observe OSD recovery using master's original audio recovery behavior.

This is the most important next hardware test because HPET correction is
currently believed to be the primary added value.

### Variant C: HPET correction plus complete audio fix

This is the already tested and pushed branch:

    fix/audio-pacing-stall-recovery

Purpose:

- reproduce the current OSD burst/silence recovery;
- compare it directly with Variant B.

### Variant D: HPET correction plus prediction only

Start from Variant B and add only the non-mutating current-pump prediction:

- add `predicted_written`;
- use the previous effective frame-count rate to predict current production;
- feed the predicted write frontier to `Pacer::update_rate`;
- retain master's original startup and underrun recovery behavior;
- do not add `prime_silence_to`;
- do not add `silence_frames_needed`;
- do not set `elapsed_ms = 0` as part of the removed priming recovery.

Purpose:

- preserve the mathematically justified delayed-pump queue measurement;
- determine whether silence insertion/recovery is responsible for the new
  audible post-OSD behavior.

Variant D should be created only if Variant B differs materially from Variant
C. Testing B first avoids maintaining an unnecessary intermediate patch.

## Required test order

Test Variant B first. The current deployed Variant C result is already known.

For Variant B:

1. Boot and confirm LAPIC/HPET is active.
2. Let DN run for at least one minute.
3. Run a DOOM automatic demo and listen for stable pitch and speed.
4. Hold a key for at least 20 seconds and compare game speed with the demo.
5. Open F12 for at least 20 seconds during active audio.
6. Close F12 and time how long audio takes to become continuous.
7. Repeat the F12 test once to check reproducibility.
8. Return to DN and inspect `C:\PROC\KLOG.TXT` for underrun lines.
9. Record the OSD Mix rate at one, three, and five minutes, but treat it as the
   learned pitch timebase rather than a pass/fail requirement.

Compare Variant B against Variant C on:

| Observation | Variant B: HPET only | Variant C: HPET + full audio fix |
|---|---:|---:|
| Held-key game slowdown | | |
| Audible pitch modulation while holding a key | | |
| Slowdown while F12 is open | | |
| Time to continuous audio after closing F12 | | |
| Burst/silence pattern after closing F12 | | |
| Number of underrun warnings | | |
| Equal-cursor underruns (`W == C`) | | |
| Strict overtake underruns (`W < C`) | | |
| Freeze or other regression | | |

## Decision rules

- If Variant B keeps the held-key improvement and recovers from F12 more
  cleanly than Variant C, keep the HPET commit and reconsider the audio commit.
- If B and C recover identically, silence priming is unlikely to be the cause;
  investigate the equality boundary or OSD display starvation directly.
- If C is better than B except for post-F12 recovery, test Variant D to retain
  delayed-pump prediction without silence priming.
- If D preserves C's normal audio stability and improves post-F12 recovery,
  split the audio commit and submit prediction separately.
- If `W == C` warnings correlate with every prolonged recovery, fix the
  recovery trigger to consume the sink's underrun report or consistently use
  `written <= consumed`, with tests preventing repeated recovery while idle.
- If repeated strict overtakes occur while F12 remains open, audio recovery is
  only treating the symptom. The primary fix should reduce OSD display cost,
  reduce its publication cadence, or otherwise ensure the audio pump runs
  before the 30 ms queue drains.

## Safety and commit discipline

- Keep each test variant on a separate temporary branch.
- Do not rewrite or force-push `fix/audio-pacing-stall-recovery` during the
  comparison.
- Run focused kernel/sound tests and build `//kernel:kernel_elf` before every
  deployment.
- Deploy the ordinary Multiboot kernel with base and games modules.
- Record the deployed checksum for each variant so observations cannot be
  assigned to the wrong build.
- Do not implement the Stage 2 clock audit during this isolation test.
