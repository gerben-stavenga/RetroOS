# HDA Output and Audio Volume Rework: Exact Implementation Plan

## 1. Result to produce

Start from fetched origin/master and create a new branch containing exactly
these three commits, in this order:

    feat(hda): add runtime output route selection
    feat(hda): configure output route from CONFIG.SYS
    feat(audio): add configurable perceptual master volume

Required final behavior:

1. When the selected backend is HDA, the F12 OSD Sound tab contains a fourth
   row named "HDA out", after Volume, Latency, and Mix rate.
2. That row cycles through exactly Speaker, Jack, and Headphone.
3. Speaker is the built-in HDA route preference.
4. The HDA row is absent for every non-HDA backend.
5. HDA_OUTPUT=Speaker|Jack|Headphone selects the initial route.
6. Volume remains displayed as 0--100 in increments of 10, but those positions
   use perceptual 4 dB gain steps instead of linear amplitude.
7. Built-in and shipped volume defaults are both 50.
8. AUDIO_VOLUME accepts only the displayed steps from 0 through 100.
9. Volume affects HDA, AC'97, and real Sound Blaster in SB_AUDIO=mixed mode.
10. Guest-owned SB_AUDIO=native remains unaffected.

Each commit must build and pass focused tests before starting the next commit.
Do not combine, reorder, squash, or amend the commits.

## 2. Mandatory scope limits

- Base the work on fetched origin/master, not the old feature merge base.
- Do not cherry-pick 6ad84c8 or d2fcca0; use them read-only as references.
- Do not port general PCI-DMA allocation or old playback-cursor accounting.
- Do not change Arch, sound::sink::Device, common sink interfaces, DMA,
  paging, Multiboot, aperture mapping, PXE, GRUB, image/ISO rules, deployment
  scripts, VBE, or build targets.
- Do not add Auto. Jack sensing is future work.
- Do not hard-code HDA node IDs.
- Do not add generic OSD registration, descriptors, callbacks, vectors,
  OsdControl, sound::osd_controls, or a backend-control framework.
- Do not recover HDA through its boot-time static or add a lock around it.
  Current master gives the unique mutable HDA capability to sound::Sink.
- Do not write physical Sound Blaster mixer registers for master volume.
- Do not persist runtime OSD changes.
- Do not perform unrelated formatting, renaming, comments, or refactoring.
- Do not commit this plan.

Allowed product paths only:

    kernel/src/kernel/drivers/hda.rs
    kernel/src/kernel/osd.rs
    kernel/src/kernel/startup.rs
    etc/CONFIG.SYS

Put tests in private cfg(test) modules in the file owning the pure behavior.
Do not add a Bazel test target.

## 3. Explicit exclusions

### 3.1 General PCI-DMA allocation

The old branch linked TarFS and games into a large kernel, consuming low
physical memory before ISA-DMA buffers were reserved. Current master has a
small kernel and external Multiboot modules accessed through an aperture.

Keep the current HDA channel-5 buffer. Do not add alloc_driver_contig, change
dma_channel_buf, or edit architecture crates.

### 3.2 Playback-cursor bounding

Current master disables HDA completion interrupts, polls SDLPIB, and permits
the ring to consume scrubbed silence. The old emitted/consumed bound belonged
to another interrupt and DMA-position-buffer design.

Do not modify Hda::advance, producer accounting, Device, or sink cursor logic.

## 4. Prepare the branch

1. Run:

       git status --short --branch

2. The only allowed entry is untracked
   HDA_DMA_OUTPUT_CONTROLS_REWORK_PLAN.md. If anything else appears, stop and
   ask the user. Do not discard it.

3. Fetch and record the base:

       git fetch origin master
       git rev-parse origin/master
       git rev-parse staging/inagy

4. If the hashes differ, report it but use origin/master unless instructed
   otherwise.

5. Check the destination:

       git branch --list feature/hda-dma-output-controls-v2

6. If it exists, stop and ask what to do. Do not reset or delete it.

7. Create the branch:

       git switch -c feature/hda-dma-output-controls-v2 origin/master

8. Confirm state and references:

       git rev-parse HEAD
       git status --short --branch
       git show -s --format='%H %s' 6ad84c8
       git show -s --format='%H %s' d2fcca0

9. Run baseline tests:

       bazelisk test --platforms=@platforms//host \
         //kernel:kernel_unit_test //lib:sound_test

10. If baseline tests fail, stop and report the exact target and first useful
    error. Do not edit product code.

## 5. Commit 1: runtime HDA route selection

Commit subject:

    feat(hda): add runtime output route selection

Only hda.rs and osd.rs may change in this commit.

### 5.1 Add the HDA preference model

In kernel/src/kernel/drivers/hda.rs:

1. Import AtomicBool, AtomicU8, and Ordering from core::sync::atomic. Use
   qualified names instead if that makes a smaller diff.

2. Add this private enum exactly:

       #[derive(Clone, Copy, PartialEq, Eq, Debug)]
       #[repr(u8)]
       enum OutputRoute {
           Speaker = 0,
           Jack = 1,
           Headphone = 2,
       }

3. Add:

       const DEFAULT_OUTPUT_ROUTE: OutputRoute = OutputRoute::Speaker;

4. Add OutputRoute::ALL in Speaker, Jack, Headphone order.

5. Add private pure methods:

   - from_raw(u8), falling back to DEFAULT_OUTPUT_ROUTE;
   - label(), returning exactly b"Speaker", b"Jack", or b"Headphone";
   - next(forward), wrapping through all three values in either direction.

6. Near the HDA singleton add:

       static OUTPUT_ROUTE: AtomicU8 =
           AtomicU8::new(DEFAULT_OUTPUT_ROUTE as u8);
       static OUTPUT_ROUTE_PENDING: AtomicBool = AtomicBool::new(false);

7. Add only this public OSD-facing API:

       pub fn output_route_label() -> &'static [u8]
       pub fn cycle_output_route(forward: bool)

8. output_route_label reads OUTPUT_ROUTE relaxed, decodes it, and returns label.

9. cycle_output_route reads/decodes the route, calculates next, stores it
   relaxed, sets OUTPUT_ROUTE_PENDING true relaxed, and prints one concise
   requested-route line. It must never access the HDA singleton or obtain
   &mut Hda.

The atomics are a request mailbox, not hardware ownership.

### 5.2 Add exact route scoring

1. Change output_pin_score to take route explicitly:

       fn output_pin_score(w: &Widget, route: OutputRoute) -> i32

2. In select_output_path, load/decode OUTPUT_ROUTE once before iterating pins
   and pass the same route to every score call.

3. Preserve existing rejection and baseline behavior: PIN_CAP_OUT,
   DEFAULT_PORT_NONE, base/device/fixed/association scores, graph scoring, and
   codec-specific topology scoring.

4. Add only these preference bonuses before association scoring:

   - Speaker: +2000 for DEFAULT_DEVICE_SPEAKER and independently +2000 for
     DEFAULT_PORT_FIXED.
   - Jack: +4000 when the port is not fixed.
   - Headphone: +5000 for DEFAULT_DEVICE_HP_OUT; otherwise +3000 when the port
     is not fixed.

5. Use firmware device/port fields only, never node IDs.

6. Update only the HDA module-level sentence that describes the fixed output
   ranking so it states that valid paths are ranked by the selected preference.
   Do not rewrite the rest of the module documentation.

### 5.3 Consume requests through the owned HDA object

Do not copy the old mutex/global-access design. sound::Sink owns &mut Hda, so
HDA consumes requests during normal mutable Device calls.

1. In setup_corb_rirb, after stopping CORB/RIRB and before programming bases:

   - clear stale status with w8(RIRBSTS, 0x05);
   - set self.verb_failed = false.

2. Add private Hda::apply_pending_output_route().

3. Return unless OUTPUT_ROUTE_PENDING.swap(false, Ordering::Relaxed) is true.

4. For a pending request:

   - save self.pin, self.dac, self.pin_def, and self.path;
   - call setup_corb_rirb();
   - call select_output_path();
   - treat false or self.verb_failed as failure;
   - on failure restore all four fields, stop CORB/RIRB, log once, and return;
   - if pin changed, disable old pin with VERB_SET_PIN_WIDGET_CONTROL payload 0;
   - if DAC changed, detach old converter with VERB_SET_CONV_STREAM_CHAN
     payload 0;
   - call configure_path();
   - program the selected DAC converter format with existing STREAM_FMT;
   - stop CORB/RIRB;
   - log selected pin/DAC on success or one timeout if verbs failed.

5. Do not stop, reset, rebuild, re-prime, or reallocate PCM DMA.

6. Call apply_pending_output_route at the start of Device::start, before the
   format assertion and RUN.

7. Call it at the start of Device::frames_played, before advance().

Boot requests apply before playback and OSD requests on the next sink poll.
Multiple requests before a poll may collapse to the latest intentionally.

### 5.4 Add the conditional Sound-tab row

In kernel/src/kernel/osd.rs:

1. Preserve indices 0 Volume, 1 Latency, and 2 Mix rate.

2. Add:

       const SOUND_ITEM_HDA_OUTPUT: usize = 3;
       const SOUND_NUM_ITEMS_BASE: usize = 3;

3. Remove fixed SOUND_NUM_ITEMS.

4. Add pure helper sound_item_count_for(Audio), returning 4 only for
   Audio::EmulatedHda and 3 for every other Audio variant.

5. Add sound_item_count(), calling the helper with platform::get().audio.

6. Clamp Sound selection in set_active_sel with sound_item_count() - 1.

7. Return sound_item_count() in active_item_count's Sound arm.

8. In adjust, HDA row calls:

       crate::kernel::drivers::hda::cycle_output_route(up)

   Preserve Volume/Latency; Mix rate remains read-only.

9. In item_line render "HDA out  <label>" using output_route_label().

10. Do not show N/A on non-HDA systems; omit the row through item count.

11. Do not change tab order, initial tab, keys, panel layout, or existing labels.

### 5.5 Commit 1 tests

Use private pure tests only; do not touch MMIO or global HDA state.

In hda.rs test:

1. Default is Speaker.
2. Raw 0,1,2 map to Speaker, Jack, Headphone; invalid maps to Speaker.
3. Labels are exact.
4. Forward and backward cycle order and wrap are exact.
5. No-output and disconnected pins are rejected for all routes.
6. Speaker ranks fixed speaker above external line out.
7. Jack ranks external line out above fixed speaker.
8. Headphone ranks external headphone above another external jack.
9. Headphone still gives another external jack a usable fallback.

Construct private synthetic Widget values; expose no internals publicly.

In osd.rs test sound_item_count_for: EmulatedHda returns 4 and every other
Audio variant returns 3. Do not fake the platform singleton.

### 5.6 Verify and commit commit 1

Run:

    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test
    bazelisk build //kernel:kernel_elf
    QEMU_DISPLAY=none timeout 60 ./run.sh qemu --arch x64 \
      --sound hda --cmd TESTS/SBTEST.COM
    git diff --check
    git diff --stat
    git status --short

Inspect the complete hda.rs/osd.rs diff. Verify only those files plus the
untracked plan. Then:

    git add kernel/src/kernel/drivers/hda.rs kernel/src/kernel/osd.rs
    git diff --cached --check
    git diff --cached --stat
    git commit -m "feat(hda): add runtime output route selection"

Do not stage the plan.

## 6. Commit 2: configure the HDA route

Commit subject:

    feat(hda): configure output route from CONFIG.SYS

Only hda.rs, startup.rs, and etc/CONFIG.SYS may change in this commit.

### 6.1 Add exact HDA_OUTPUT parsing

In hda.rs:

1. Add pure:

       fn parse_output_route(raw: &[u8]) -> Option<OutputRoute>

2. Use eq_ignore_ascii_case.

3. Accept exactly Speaker, Jack, and Headphone in any ASCII case.

4. Reject empty, whitespace, numeric, prefix/suffix, Auto, and unknown values.

5. Add:

       pub fn configure_output_route(raw: Option<&[u8]>)

6. Exact behavior:

   - None stores Speaker and explicitly stores false to the pending flag.
   - Some(valid) stores parsed route; pending is true only when it is not
     Speaker.
   - Some(invalid) stores Speaker, explicitly stores false to pending, and
     prints exactly one diagnostic. Format the raw value with
     core::str::from_utf8(raw).unwrap_or("<non-UTF8>"); do not allocate.
   - Never access HDA or MMIO.

Probe precedes CONFIG.SYS, so non-Speaker configuration uses the mailbox and is
consumed by Device::start or Device::frames_played.

### 6.2 Wire HDA_OUTPUT into startup

1. Find:

       let master_env = load_master_env();

2. Immediately after it call:

       crate::kernel::drivers::hda::configure_output_route(
           crate::kernel::dos::config_var(&master_env, b"HDA_OUTPUT"),
       );

3. Do not clone, add BootConfig fields/aliases, or move SB_AUDIO policy.

4. Keep this before sound::Sink::new and the first program.

### 6.3 Add shipped configuration

Near sound settings in etc/CONFIG.SYS add exactly:

    # HDA output preference: Speaker, Jack, or Headphone.
    HDA_OUTPUT=Speaker

Do not add HDAPORT, numeric aliases, or Auto.

### 6.4 Commit 2 tests

Pure parser tests must verify canonical and mixed-case accepted values, and
reject empty, Auto, numbers, surrounding spaces, suffixes, and unknown values.
Do not mutate route atomics in parallel tests.

### 6.5 Verify and commit commit 2

Run:

    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test
    bazelisk build //kernel:kernel_elf
    QEMU_DISPLAY=none timeout 60 ./run.sh qemu --arch x64 \
      --sound hda --cmd TESTS/SBTEST.COM
    git diff --check
    git diff --stat
    git status --short

Verify only commit-2 files changed, then:

    git add kernel/src/kernel/drivers/hda.rs kernel/src/kernel/startup.rs \
      etc/CONFIG.SYS
    git diff --cached --check
    git diff --cached --stat
    git commit -m "feat(hda): configure output route from CONFIG.SYS"

Do not stage the plan.

## 7. Commit 3: configurable perceptual master volume

Commit subject:

    feat(audio): add configurable perceptual master volume

Only osd.rs, startup.rs, and etc/CONFIG.SYS may change in this commit.

### 7.1 Add the fixed gain curve

In osd.rs:

1. Add:

       const DEFAULT_VOLUME_PCT: u32 = 50;

2. Initialize VOL_PCT with DEFAULT_VOLUME_PCT.

3. Preserve VOL_MAX=100, VOL_STEP=10, adjustment behavior, percentage text,
   and bar rendering.

   Update the nearby comment that currently describes the value as a linear
   percentage of unity. It must instead say that the displayed percentage
   selects a perceptual gain step and that 100 is unity.

4. Add exactly:

       const VOLUME_GAIN_Q16: [i32; 11] = [
           0, 1039, 1646, 2609, 4135, 6554,
           10387, 16462, 26090, 41350, 65536,
       ];

5. Entries mean 0=mute, followed by -36, -32, -28, -24, -20, -16, -12,
   -8, -4, and 0 dB for positions 10 through 100.

6. Add pure:

       fn volume_gain_q16(percent: u32) -> i32

7. Divide by VOL_STEP, clamp index to the final entry, and return it. Do not use
   floating point, logs, powers, interpolation, allocation, or runtime setup.

8. master_gain_q16 loads VOL_PCT and calls volume_gain_q16.

9. Do not edit sink, HDA, AC'97, SB16, mixers, clipping, or platform policy.
   The common sink already applies this gain once before narrowing/clipping.

### 7.2 Parse AUDIO_VOLUME

1. Add pure:

       fn parse_volume_percent(raw: &[u8]) -> Option<u32>

2. Accept one or more ASCII decimal digits. Leading zeroes are allowed.

3. Reject empty, signs, whitespace, suffixes, non-ASCII digits, overflow,
   values above 100, and values not divisible by 10.

4. Add:

       pub fn configure_master_volume(raw: Option<&[u8]>)

5. Exact behavior:

   - None stores DEFAULT_VOLUME_PCT.
   - Some(valid) stores parsed value.
   - Some(invalid) prints exactly one diagnostic and stores
     DEFAULT_VOLUME_PCT. Format the raw value with
     core::str::from_utf8(raw).unwrap_or("<non-UTF8>"); do not allocate.

6. Write existing VOL_PCT. Do not add another configured variable or store Q16
   gains in CONFIG.SYS.

### 7.3 Wire AUDIO_VOLUME into startup

Beside HDA configuration immediately after load_master_env add:

    crate::kernel::osd::configure_master_volume(
        crate::kernel::dos::config_var(&master_env, b"AUDIO_VOLUME"),
    );

Keep it before sound::Sink::new and the first program. Do not add BootConfig,
command-line overrides, persistence, or a generic settings layer.

### 7.4 Add shipped configuration

Near other sound settings in etc/CONFIG.SYS add:

    # Kernel-mixed master volume: 0 to 100 in steps of 10.
    AUDIO_VOLUME=50

Do not describe it as controlling SB_AUDIO=native.

### 7.5 Commit 3 tests

In private osd.rs pure-helper tests verify:

1. DEFAULT_VOLUME_PCT is 50.
2. All eleven exact percentages return exact table values.
3. Zero is silence and 100 is 65536 unity.
4. Table entries strictly increase.
5. Values above 100 safely return unity.
6. Parser accepts all eleven canonical values.
7. Parser accepts 00, 050, and 0100.
8. Parser rejects empty, +50, -50, surrounding spaces, 50%, 55, 110,
   non-digits, and overflowing input.

Do not mutate VOL_PCT in parallel tests. Do not add backend-specific gain tests;
sink integration is unchanged.

### 7.6 Verify and commit commit 3

Run:

    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test
    bazelisk build //kernel:kernel_elf
    QEMU_DISPLAY=none timeout 60 ./run.sh qemu --arch x64 \
      --sound hda --cmd TESTS/SBTEST.COM
    git diff --check
    git diff --stat
    git status --short

Verify only commit-3 files changed, then:

    git add kernel/src/kernel/osd.rs kernel/src/kernel/startup.rs etc/CONFIG.SYS
    git diff --cached --check
    git diff --cached --stat
    git commit -m "feat(audio): add configurable perceptual master volume"

Do not stage the plan.

## 8. Validate the complete branch

### 8.1 Verify history and scope

Run:

    git rev-list --count origin/master..HEAD
    git log --oneline --decorate origin/master..HEAD
    git diff --name-only origin/master..HEAD
    git diff --check origin/master..HEAD
    git status --short --branch

Require exactly three commits in order, only the four allowed product paths,
the plan untracked/uncommitted, and no other worktree changes.

Review each commit:

    git show --stat --oneline HEAD~2
    git show --stat --oneline HEAD~1
    git show --stat --oneline HEAD
    git show --format=fuller --check HEAD~2
    git show --format=fuller --check HEAD~1
    git show --format=fuller --check HEAD

### 8.2 Run all automated coverage

Run:

    bazelisk test --platforms=@platforms//host \
      //kernel:kernel_unit_test //lib:sound_test
    bash test/run_all.sh

Request sandbox permission if fixtures/emulators are blocked. Record passes,
failures, timeouts, and legitimate skips separately.

### 8.3 Run QEMU smoke coverage

Run:

    bazelisk build //kernel:kernel_elf
    QEMU_DISPLAY=none timeout 60 ./run.sh qemu --arch x64 \
      --sound hda --cmd TESTS/SBTEST.COM

Require HDA probe/path/playback progress and no codec timeout or KERNEL PANIC.
This is not proof of interactive OSD or physical analog routing.

### 8.4 Optional SEJT validation

Do not deploy without approval. If approved, use the repository SEJT workflow
and RLOG. Check initial Speaker, three-route wrap, route changes without panic,
configured Jack/Headphone, conditional Sound row, AUDIO_VOLUME=50 display, and
audibly distinct volume steps.

## 9. Stop conditions

Stop and ask if the initial worktree is unexpected, destination exists,
baseline fails, master architecture differs, Device would need changing, PCM
DMA would need stopping/reallocation, forbidden paths seem necessary, an
unrelated failure appears, or hardware deployment lacks authorization.

## 10. Final handoff

Do not push, squash, rebase, amend, deploy, or delete reference branches unless
separately requested.

Report branch/base, commit hashes, changed files, focused/full tests, QEMU,
SEJT status, and confirmation that the plan remains untracked.

Final history:

    feat(audio): add configurable perceptual master volume
    feat(hda): configure output route from CONFIG.SYS
    feat(hda): add runtime output route selection
    <fetched origin/master>
