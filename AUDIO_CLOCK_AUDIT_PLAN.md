# Audio Pacing Integration and Clock Audit Plan

## 1. Purpose and mandatory stage boundary

This work has two strictly separated stages.

**Stage 1** rebases the two still-relevant fixes onto the author's current
`origin/master`, removes the abandoned OSD/bandwidth experiment, drops the
cancelled typematic experiment, tests the integrated result, and deploys it to
the Intel D945GSEJT for user evaluation.

**Stage 2** adds temporary kernel-log clock diagnostics only if the user tests
Stage 1 and explicitly asks to continue. Do not begin Stage 2 automatically.

The author's current master contains:

    f31234e fix(audio): pin source pitch to the pacer's steady rate, not the trimmed rate
    f14a4bc fix(audio): OSD "Mix rate" shows the pitch rate s, not the trimmed rate

Those changes separate two rates:

- `pitch_rate_q16 = producer.s_q16()` is the stable source-phase timebase and
  is what the OSD now displays;
- `rate_q16 = s - 2wq` is the short-term frame-count rate used to regulate DMA
  queue depth.

Preserve this split. The author's fix prevents queue correction from directly
detuning sources. It does not replace either of the two branch fixes retained
in Stage 1:

    e61d783 fix(audio): stabilize pacing across delayed pumps
    4880ee7 fix(timer): recover elapsed time across firmware stalls

The first prevents a delayed pump from fabricating a queue deficit and primes
silence during startup/recovery. The second restores elapsed time when HPET
shows that firmware/SMM delayed timer delivery.

The stable SEJT OSD value near 46,850 Hz remains unexplained. Because master
now displays `s`, it means the pacer learned approximately that steady rate;
it is no longer merely an instantaneous queue-trimmed value. The exact nearby
ratio remains diagnostically important:

    48,000 * 1000 / 1024 = 46,875

Do not implement a production clock fix based on this resemblance alone.

---

# Stage 1: Rebase, simplify, verify, and obtain a hardware result

## 2. Stage 1 allowed outcome

At the Stage 1 checkpoint, the feature branch must contain exactly two unique
commits above current `origin/master`, in this order:

1. `fix(audio): stabilize pacing across delayed pumps`
2. `fix(timer): recover elapsed time across firmware stalls`

The exact hashes may change during rebase. No OSD diagnostics, runtime pacer
bandwidth control, typematic experiment, audit instrumentation, or plan file
may be committed.

## 3. Inspect and protect the starting state

Run:

    git status --short --branch
    git branch --show-current
    git log -8 --oneline --decorate
    git remote -v

Expected branch:

    feature/hda-output-controls

Expected pre-rebase HEAD when this plan was updated:

    4880ee7 fix(timer): recover elapsed time across firmware stalls

Expected tracked modifications are exactly:

    kernel/src/kernel/osd.rs
    kernel/src/kernel/sound.rs
    lib/sound/src/pacer.rs

These are the abandoned OSD diagnostics and runtime bandwidth experiment.
Expected untracked planning files are exactly:

    AUDIO_CLOCK_AUDIT_PLAN.md
    AUDIO_PACING_STABILITY_FIX_PLAN.md
    HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md

If another modified or untracked file exists, stop and report it. Do not
discard, stash, overwrite, or include unknown work.

Create a local safety branch at the original HEAD:

    git branch backup/hda-output-controls-pre-clock-integration HEAD

If that branch name already exists, compare its hash with HEAD. If they differ,
use a timestamped backup name rather than moving or deleting the old backup.

Do not push the backup unless the user asks.

## 4. Remove only the abandoned uncommitted experiment

Preserve its patch outside the repository:

    git diff -- kernel/src/kernel/osd.rs kernel/src/kernel/sound.rs \
      lib/sound/src/pacer.rs > /tmp/retroos-osd-audio-experiment.diff

Verify that the patch is non-empty:

    test -s /tmp/retroos-osd-audio-experiment.diff

Restore exactly those three files to HEAD:

    git restore --source=HEAD -- \
      kernel/src/kernel/osd.rs \
      kernel/src/kernel/sound.rs \
      lib/sound/src/pacer.rs

Confirm that no tracked changes remain:

    git diff --exit-code
    git status --short

Only the three plan files listed above may now appear, all untracked. Do not
delete any plan file. Do not restore the saved experiment later.

## 5. Refresh and identify the rebase boundaries

Fetch the author's repository:

    git fetch origin

Record:

    git rev-parse origin/master
    git log -5 --oneline origin/master
    git merge-base HEAD origin/master

The historical fork point expected for this branch is:

    d82280087866e535e05b9b5e9f8901e922372082

Verify that `d822800` is an ancestor of both the current branch and
`origin/master`:

    git merge-base --is-ancestor d822800 HEAD
    git merge-base --is-ancestor d822800 origin/master

Both commands must succeed. If either fails, stop; do not guess a replacement
fork point.

Confirm that these four branch commits are the only commits to consider:

    git log --reverse --oneline d822800..HEAD

Expected order:

    e61d783 fix(audio): stabilize pacing across delayed pumps
    7e9832e fix(keyboard): reduce legacy USB typematic stalls
    5489f45 Revert "fix(keyboard): reduce legacy USB typematic stalls"
    4880ee7 fix(timer): recover elapsed time across firmware stalls

If the list differs, stop and report it.

## 6. Rebase while dropping the cancelled typematic pair

Use an interactive rebase onto current `origin/master`. The todo list must
contain only these two `pick` lines, in this order:

    pick e61d783 fix(audio): stabilize pacing across delayed pumps
    pick 4880ee7 fix(timer): recover elapsed time across firmware stalls

Delete the lines for `7e9832e` and `5489f45`; do not squash them and do not
retain an empty revert. The command is:

    git rebase -i --onto origin/master d822800

Before saving the todo list, verify that no other commit is dropped or
reordered.

### 6.1 Resolve the expected `sound.rs` overlap

The audio commit and master both modify `kernel/src/kernel/sound.rs`. Resolve
the file by preserving both designs; do not choose one whole side.

The resolved file must retain all of the following from current master:

1. `PITCH_MIX_RATE_Q16_LO` and `PITCH_MIX_RATE_Q16_HI`.
2. `mixing_rate_q16()` documented as and returning the pitch timebase.
3. A separate `pitch_rate_q16` derived from `output.producer.s_q16()`.
4. `AudioSpan.rate` set from `pitch_rate_q16`, not `rate_q16`.
5. `Clock::produce(rate_q16, elapsed_ms)` still using the effective
   frame-count rate.
6. `publish_mixing_rate_q16(pitch_rate_q16)` publishing `s` to the OSD.

The resolved file must also retain all of the following from the delayed-pump
fix:

1. Initial silence priming to the requested latency in `Sink::new`.
2. `Sink::prime_silence_to` using the existing DMA ring without advancing the
   source clock.
3. `predicted_written` using `Clock::frames_for` without mutating `Clock`.
4. `silence_frames_needed`.
5. Controller updates using predicted current-pump production and the
   previously selected effective rate.
6. Underrun and safety-ceiling recovery re-priming silence and discarding the
   obsolete source interval by setting `elapsed_ms` to zero.
7. The focused tests introduced by the fix.

Keep the variable roles explicit:

    rate_q16        = effective frame-count rate, s - 2wq
    pitch_rate_q16  = steady source-phase rate, s

Do not make prediction use `pitch_rate_q16`; prediction estimates how many
frames the producer is about to submit, so it must use the previous effective
frame-count rate.

Do not reintroduce the temporary `update_rate_with_bandwidth` API or bandwidth
atomics. Master's normal `Pacer::update_rate` control law remains unchanged.

After resolving the file:

    git add kernel/src/kernel/sound.rs
    git rebase --continue

Resolve no unrelated conflict by taking an entire side without inspection.

### 6.2 Timer commit expectations

The timer commit should add HPET runtime state and one-way missing-time
reconciliation to current master's `arch-metal/src/irq.rs`. Preserve master's
existing LAPIC calibration overshoot calculation. The resulting code must:

- calibrate LAPIC against the actual HPET interval observed;
- retain HPET frequency/counter state after calibration;
- add elapsed milliseconds only when HPET time is ahead of delivered logical
  ticks;
- cap one returned catch-up batch at 64 ms while retaining the remainder;
- leave the PIT fallback unchanged when HPET/LAPIC setup is unavailable.

Do not add the Stage 2 audit counters during this rebase.

## 7. Verify the simplified commit stack

Run:

    git status --short --branch
    git log --reverse --oneline origin/master..HEAD
    git diff --stat origin/master..HEAD
    git diff --check origin/master..HEAD
    git range-diff d822800..backup/hda-output-controls-pre-clock-integration \
      origin/master..HEAD

The unique log must contain exactly two commits. The range diff must show the
typematic commit and its revert as dropped, and the two retained fixes as
rebased/modified only as needed for current master.

Expected product files unique to the branch are limited to:

    arch-metal/src/irq.rs
    kernel/src/kernel/sound.rs

If any other product file differs from `origin/master`, stop and explain why.

The three plan files remain untracked and must not appear in either commit.

## 8. Stage 1 tests

Run these in order and stop at the first real failure:

### 8.1 Focused unit tests

    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test

### 8.2 Required builds

    bazelisk build //:image //kernel:kernel_elf

### 8.3 Clippy matching GitHub CI

    bazelisk build --config=clippy \
      //kernel:kernel //lib:lib //lib:sound \
      //arch-abi:arch-abi //arch-metal:arch-metal

    bazelisk build --config=clippy --platforms=@platforms//host \
      //kernel:kernel //kernel:retroos-host \
      //arch-interp:arch-interp //lib:lib //lib:sound //arch-abi:arch-abi

### 8.4 Complete repository suite

    test/run_all.sh

Do not change unrelated code to silence a pre-existing warning or repair an
unrelated environmental failure. Report skipped tests and prerequisites
separately from failures.

### 8.5 Optional QEMU listening smoke test

If the open-source image contains the required audio-producing program, run
QEMU HDA for at least 60 seconds and listen/check for underruns. Do not add
diagnostics yet and do not claim that OSD convergence is measured accurately
from a brief run.

Use the existing launcher and a supported UEFI display path. Preserve the
complete debug-console log in `/tmp`. If no suitable open-source audio program
is available, skip this optional test and state why.

## 9. Stage 1 commit and branch policy

The rebase rewrites the two retained commit hashes. Do not create a third
cleanup commit. If conflict resolution accidentally omitted part of either
fix, amend the corresponding commit during the rebase or redo the rebase from
the backup branch.

Do not force-push until all Stage 1 tests pass and the user asks to push. Use
`--force-with-lease`, never plain `--force`, because the branch history was
rewritten.

Do not commit this plan or the other plan files.

## 10. Deploy the Stage 1 checkpoint to SEJT

The agent must read and follow the `retroos-sejt-hardware` skill before any
SEJT build, deployment, reboot, or observation. This branch has no RLOG, so use
the skill's no-RLOG path.

Build and deploy the normal Multiboot kernel with both base and games modules.
Do not deploy an HDD image, diagnostic audit build, or non-Multiboot artifact.
Record the deployed kernel checksum and module checksums.

Deployment is not proof of execution. Ask the user to reboot the SEJT manually
and confirm that the displayed boot/checksum corresponds to the new build.

## 11. User test checklist for the Stage 1 checkpoint

Ask the user to test all of the following before Stage 2:

1. Confirm boot reports LAPIC and HPET operation as expected.
2. Let DN remain in 720x400 70 Hz mode with the OSD closed for at least one
   minute; listen for stable audio if audio is active.
3. Open the F12 Sound page. Remember that master now displays pacer `s`, the
   pitch timebase, not the instantaneous frame-count trim.
4. Record the initial Mix rate and its value after one, three, and five
   minutes. Do not use only a single observation.
5. Run DOOM's automatic demo and listen for pitch stability.
6. Hold a key during gameplay for at least 20 seconds and compare game speed
   and music pitch with the automatic demo.
7. Return to DN if possible and record whether the Mix rate continues moving
   or stabilizes.
8. Report underrun warnings, freezes, route/output regressions, or audible
   wow separately.

At this checkpoint, stop. Report the clean two-commit stack, all test results,
deployment checksum, and the requested user observations. Do not add clock
audit code until the user explicitly says to proceed.

---

# Stage 2: Temporary independent clock audit

## 12. Stage 2 entry condition and objective

Begin this stage only after the user has tested Stage 1 and explicitly asks to
continue.

The audit must determine which layer causes a steady pitch timebase near
46,850 Hz:

1. approximately 1,024 raw LAPIC interrupts occur per 1,000 HPET milliseconds;
2. logical/system milliseconds diverge from HPET;
3. HDA SDLPIB consumption diverges from the controller's 24 MHz WALLCLK;
4. the HDA ring completes an unobserved full wrap between cursor polls;
5. frame production/queue control diverges despite correct clocks;
6. display work only increases pump latency, exposing one of the above.

The audit observes behavior only. It must not change timer programming, HPET
correction policy, HDA format, DMA geometry, cursor semantics, pacing law,
latency target, pitch/frame-rate split, display cadence, or emulator settings.

## 13. Stage 2 output and scope

Write three machine-parseable records to the normal kernel log approximately
every five seconds while HDA audio is active:

    clock-audit: ...
    hda-clock-audit: ...
    audio-clock-audit: ...

They must appear in QEMU debug-console output and `C:\PROC\KLOG.TXT`. They must
not require F12, Trace, Profile, RLOG, CONFIG.SYS, or a new command-line flag.

Allowed product files are exactly:

    arch-metal/src/irq.rs
    kernel/src/kernel/drivers/hda.rs
    kernel/src/kernel/sound.rs

Do not modify the OSD or `lib/sound/src/pacer.rs`. Do not restore runtime
bandwidth tuning. Keep the audit in one separable temporary commit and do not
push it without user approval.

## 14. Common audit rules

1. Use fixed-size integer state only; do not allocate in hot paths.
2. Accumulate monotonic totals and subtract window baselines.
3. Use wrapping subtraction for 32-bit hardware counters.
4. Print raw deltas beside every derived rate.
5. Use five-second windows to limit klog volume.
6. Do not print in an interrupt handler; increment raw counters there and
   format records in ordinary kernel context.
7. Do not gate records on Trace/Profile.
8. The first audio window after stream start/recovery is warm-up evidence and
   must not be used alone for a steady-state conclusion.
9. Preserve complete raw logs before extracting summary lines.

Constants:

    HDA WALLCLK frequency:       24,000,000 ticks/second
    HDA stream rate:                 48,000 frames/second
    HDA wall ticks per frame:            500
    HDA ring frames:                    8,192
    HDA ring duration:             170,666 us approximately
    HDA wall ticks per ring:       4,096,000

## 15. Timer/HPET audit

In `arch-metal/src/irq.rs`, add a raw timer-interrupt counter incremented once
in each actual timer interrupt path. HPET-added reconciliation milliseconds
must not increment it.

Also accumulate:

- HPET elapsed milliseconds;
- change in logical `TIMER_TICKS`;
- ticks returned by `take_pending_ticks` after the 64 ms cap;
- HPET corrections added by the Stage 1 timer fix;
- current pending backlog;
- number of serviced batches and maximum batch size.

Print from `take_pending_ticks`, after computing the current batch:

    clock-audit: hpet_ms=<delta> raw_irq=<delta> logical=<delta> serviced=<delta> corrections=<delta> pending=<current> batches=<delta> max_batch=<window-max>

Do not modify the one-way correction algorithm while measuring it.

Focused tests must prove:

- 5,120 raw interrupts over 5,000 HPET ms remain visible as 5,120;
- 4,900 raw interrupts plus 100 corrections produce 5,000 logical ticks;
- the 64 ms cap retains rather than loses backlog;
- cumulative delta arithmetic is correct.

## 16. HDA WALLCLK/SDLPIB audit

In `kernel/src/kernel/drivers/hda.rs`, define the HDA global `WALLCLK` register
at offset `0x30`. Add private fixed-size audit state to `Hda` and initialize it
when playback starts.

On every existing `Hda::advance` poll:

1. Read 32-bit WALLCLK.
2. Accumulate its wrapping delta.
3. Record poll count and maximum WALLCLK gap.
4. Run existing SDLPIB accounting unchanged.
5. Record cursor-move count and maximum SDLPIB frame step.

At 120,000,000 accumulated WALLCLK ticks, derive:

    wall_us         = wall_ticks * 1,000,000 / 24,000,000
    expected_frames = wall_ticks / 500
    cursor_frames   = consumed_hw - window_start_consumed
    cursor_hz       = cursor_frames * 24,000,000 / wall_ticks
    shortfall       = expected_frames - cursor_frames, signed
    max_poll_us     = max_poll_ticks * 1,000,000 / 24,000,000
    wrap_risk       = max_poll_ticks >= 4,096,000

Print:

    hda-clock-audit: wall_ticks=<delta> wall_us=<derived> expected=<frames> cursor=<frames> cursor_hz=<derived> shortfall=<signed> polls=<count> moves=<count> max_poll_us=<derived> max_step=<frames> wrap_risk=<0-or-1> lpib=<current-byte-position>

Do not infer or compensate for a missed wrap during the audit.

Focused tests must cover nominal 48,000 Hz, the 46,875 Hz case, 32-bit
WALLCLK wrap, the exact full-ring risk threshold, and signed shortfall.

## 17. Audio producer/queue audit with master's rate split

In `kernel/src/kernel/sound.rs`, add fixed-size private audit state to `Sink`.
Accumulate values already computed by `sound::advance`:

- effective elapsed `os_ms` actually passed to `Clock::produce`;
- drained frames and produced frames;
- pump count, cursor-move count, and maximum pump `dt_ms`;
- queue-depth minimum, maximum, and final value;
- target depth;
- recovery count and global underrun count;
- **effective frame-count rate** `rate_q16 = s - 2wq`: min/max/end;
- **pitch rate** `pitch_rate_q16 = s`: min/max/end.

Keep these two rates separate in names and output. Do not call both “mix
rate.” The existing OSD displays `pitch_rate_q16`; the audit must expose both.

If recovery sets `elapsed_ms` to zero, count the recovery but do not fabricate
produced time. Initialize minima from the first real sample, not zero.

After at least 5,000 accumulated `os_ms`, derive:

    drain_hz   = drained * 1000 / os_ms
    produce_hz = produced * 1000 / os_ms

Print:

    audio-clock-audit: os_ms=<delta> drained=<frames> drain_hz=<derived> produced=<frames> produce_hz=<derived> frame_min=<hz> frame_max=<hz> frame_end=<hz> pitch_min=<hz> pitch_max=<hz> pitch_end=<hz> queue_min=<frames> queue_max=<frames> queue_end=<frames> target=<frames> pumps=<count> cursor_moves=<count> max_dt=<ms> recoveries=<count> underruns=<global-total>

Focused tests must cover 48,000 and 46,875 rate arithmetic, first-sample
minima, a 64 ms maximum pump, and zero-duration recovery.

## 18. Stage 2 build verification

Run:

    git diff --check
    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test
    bazelisk build //kernel:kernel_elf

Then inspect:

    git diff --stat
    git status --short

Only the three allowed product files may be modified. No plan file may be
staged. If committed for deployment, use one temporary commit:

    debug(audio): audit timer and HDA clock domains

## 19. QEMU collection plan

Create one directory:

    AUDIT_DIR="/tmp/retroos-audio-clock-audit-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$AUDIT_DIR"

For each run, save the exact command in `CASE.command`, complete output in
`CASE.log`, audit lines in `CASE.audit.txt`, and boot identity in
`CASE.boot.txt`. Run for at least 60 seconds after audio begins and retain at
least the final three complete windows.

Extract with:

    grep -aE '^(clock-audit|hda-clock-audit|audio-clock-audit):' CASE.log \
      > CASE.audit.txt
    grep -aE '^(IRQ:|Audio:|Display:|hda: selected|hda: stream RUN)' CASE.log \
      > CASE.boot.txt

Required cases, using the repository's supported UEFI QEMU path:

1. HDA, TCG, headless, an audio-producing DOS program.
2. HDA, KVM, headless, the same program, only if `/dev/kvm` is usable.
3. AC'97, TCG, headless, the same program; no HDA audit line is expected.
4. HDA, TCG, displayed, DN idle.
5. HDA, TCG, displayed, the same audio-producing program.

Use an image which actually contains the selected program. Do not hardcode a
DOOM path unless that path exists in the selected image at execution time.
Record the resolved image and command. If GUI execution requires permission,
request it rather than silently substituting headless mode.

Do not use QEMU BIOS VGA as a required comparison. The repository documents
that path as inaccurate. 86Box is optional only for a legacy PIT audit; its
configured SB16 path cannot exercise HDA WALLCLK or SDLPIB.

## 20. SEJT collection plan

Follow the `retroos-sejt-hardware` skill. Deploy the temporary audit kernel
with base and games modules through the no-RLOG path, record checksums, and ask
the user to reboot manually.

Run each scenario for at least 60 seconds:

1. DN 720x400 70 Hz, OSD closed.
2. DN, OSD open.
3. DOOM automatic demo without held input.
4. DOOM while holding a key for at least 20 seconds.
5. Return to DN and wait 30 seconds if possible.

Read `C:\PROC\KLOG.TXT` and preserve every complete line beginning with the
three audit prefixes, plus boot lines identifying LAPIC/HPET, display, HDA
codec, and stream format. If the ring wrapped, repeat shorter scenarios; do
not increase log frequency.

## 21. Interpretation matrix

Use at least three steady windows.

| Pattern | Conclusion |
|---|---|
| `raw_irq` near 5,120 per `hpet_ms` near 5,000; HDA `cursor_hz` near 48,000; audio `drain_hz` and `pitch_end` near 46,875 | LAPIC/logical time runs near 1,024 Hz; one-way HPET recovery cannot remove excess ticks. |
| Timer fields near 5,000 and HDA `cursor_hz` near 48,000, but `pitch_end` remains near 46,875 | Timer and physical sink are sound; inspect pacer/queue integration. |
| Timer fields near 5,000 and HDA cursor near 46,875 relative to WALLCLK | HDA SDLPIB consumption/accounting is the divergent layer. |
| HDA shortfall is near one or more multiples of 8,192 and `wrap_risk=1` | A full modular cursor wrap may be lost between polls. |
| `wrap_risk=0` and `max_poll_us` is comfortably below 170,666 | Full-ring poll loss is ruled out for that window. |
| `frame_*` swings while `pitch_*` stays steady and queue stays near target | Master's pitch/frame split works; short-term queue regulation is no longer direct pitch modulation. |
| `pitch_*` itself slowly converges away from 48,000 | The pacer's learned clock estimate is moving; compare timer and HDA references to identify why. |
| Displayed mode raises `max_dt` but not `cursor_hz`, `pitch_end`, or wrap risk | Display is a stressor only, not a clock source. |
| Displayed mode alone sets `wrap_risk=1` | Synchronous display work exposes unsafe modular cursor polling. |
| QEMU and SEJT show the same ratio | Common RetroOS timer/pacing logic. |
| QEMU remains near 48,000 but SEJT approaches 46,875 | SEJT timer delivery/calibration or physical HDA behavior. |
| QEMU HDA is wrong while QEMU AC'97 is correct with matching timer fields | HDA-specific cursor path. |
| HDA and AC'97 are both wrong with the same timer ratio | Common timer or audio-clock path. |
| Recoveries/underruns recur | Do not trust steady-rate inference until the resets are explained. |

## 22. Stage 2 report and stop condition

Report:

- tested commit and exact files changed;
- focused test/build results;
- exact emulator commands, image, acceleration, display mode, and raw-log
  paths;
- final three steady windows per case, including timer fields, HDA cursor rate
  and poll gap, audio drain/produce rates, both frame and pitch rates, queue,
  recoveries, and underruns;
- the matching interpretation row, confidence, and remaining ambiguity;
- SEJT checksum and user-provided klog evidence when available.

Stop after reporting evidence. Do not implement a production fix, amend the
two Stage 1 commits, push the diagnostic commit, or remove this plan unless the
user explicitly requests the next action.
