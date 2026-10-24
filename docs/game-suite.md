# DOS game regression suite

## Full RustDOS catalog

`test/rustdos_suite.py` imports the complete RustDOS catalog at commit
`81076c73d85c55abf8e6b0229291adf729f134c5`: **72 scenarios, 15 games,
16 installations** (Wolfenstein has two distributions). Nothing is removed
from the upstream scenario set. The games are Doom, Heretic, Duke Nukem 3D,
Descent, Raptor, Wolfenstein 3D, Commander Keen 1, Jill of the Jungle, Cosmo,
Duke Nukum, Scorched Earth, Alley Cat, Digger, Sopwith, and Rogue.

```sh
python3 test/rustdos_suite.py --list
python3 test/rustdos_suite.py --fetch-only
python3 test/rustdos_suite.py --select keen1/vga-20000
python3 test/rustdos_suite.py --native-profile --select alleycat/cga-300-normal,digger/cga-300-normal
```

The reference source checkout defaults to
`~/.local/share/retroos/rust-dos/source`, shared with the durable user-local
Rust-DOS installer. `--reference-checkout` can select another location.

The pinned JSON retains every archive URL and SHA-256, installer script,
hardware INI, file override, gameplay script, golden group, timeout, and
partner configuration. `python3 tools/import_rustdos_suite.py` regenerates it
from the vendored, separately GPL-licensed upstream catalog. A regression
test checks exact equality with the Rust catalog's evaluated output.

`--fetch-only` uses a separate pinned RustDOS checkout to provision the exact
game files with the upstream installers, then independently verifies every
download's SHA-256. It requires Git, Cargo and curl; Cargo builds the reference
installer without SDL. This checkout does not change `tmp/rust-dos`.
The default cache is `~/.cache/rust-dos/game-suite`, shared with RustDOS;
`--cache` or `GAME_SUITE_CACHE` selects another location. Provisioning uses
RustDOS; **scenario replay boots the RetroOS kernel**. The replay disk also
includes the pinned Ultrasound software and patch bank that RustDOS normally
exposes on its synthetic drive, placed at RetroOS's `C:\ULTRASND` location.

Replay uses a new opt-in hosted control protocol. The CPU stops between
kernel event-loop iterations. `Wait`, `Key`, `Keys`, `Hold`, `Type`,
`PressUntil`, `WaitFor`, `Check`, `Shot`, `Listen`, `Record`, and `Cycles`
retain their upstream meanings. Time derives from retired guest instructions,
held keys send distinct make/break scancodes, and captures do not advance time.
Stopping occurs at the next execution boundary, so time can overshoot by a
partial CPU slice. Changing speed preserves elapsed time. The protocol is
TCG-only; ordinary hosted and KVM runs retain their existing behavior.

RetroOS can select Unicorn's 486 and Pentium models and change the instruction
rate. **Full hardware parity is not implemented.** A 386 model, separate
interpreter/recompiler implementations, CGA/EGA adapter identification,
SB2/SB Pro and disabled-card configurations, Disney DAC selection, and linked
two-machine transports are reported as `unsupported`, never as passing tests.
`--native-profile` explicitly runs single-machine scripts on native devices
where their requested settings cannot be selected; results include every
deviation and successful adapted cases say `pass-native`. Linked cases remain
unsupported. This flag does not suppress failed script conditions or silence.
The disconnected hosted audio sink makes audible scenarios fail.

Artifacts are written under `tmp/rustdos-suite/run-.../`: the complete pinned
catalog, a copied kernel binary, reports, each scenario's command and starting
file hashes, isolated disk/tree, screenshots, audio intervals, logs, checkpoint
metrics and failure step with guest time. A copied kernel keeps an in-progress
run independent of concurrent Bazel rebuilds. The disk session overlay does
not export game writes after shutdown.

Reference hashes must come from RetroOS. RustDOS's hashes depend on its own
DOS kernel, framebuffer renderer and sound implementation and cannot serve as
RetroOS references. Record a passing scenario with `--bless`, inspect the
PPM/WAV files, then repeat it with `--compare`. References live separately in
`test/games/rustdos-golden/` and retain upstream golden groups. Reviewed
references are included for configured `keen1/vga-20000` and native replays of
Alley Cat, Digger, Sopwith and Rogue, including gameplay pictures. Other cases
need their own reviewed references. A profile marker prevents comparing an
adapted run against a configured reference. Failed scenarios never replace
references.

```sh
python3 test/rustdos_suite.py --native-profile --select digger/cga-300-normal --bless
python3 test/rustdos_suite.py --native-profile --select digger/cga-300-normal --compare
python3 test/rustdos_suite.py --native-profile --jobs 4
python3 test/rustdos_suite_test.py
bazelisk test //arch-interp:suite-control-test --platforms=@platforms//host
```

`--select`/`GAME_SUITE` filters scenario names. `--jobs`/`GAME_SUITE_JOBS`
controls independent processes. `--timeout` overrides the per-case host
deadline; it does not alter script wait limits. `--no-build` uses existing
kernel and COMMAND.COM artifacts. The suite remains opt-in, outside CI and
`test/run_all.sh`. Failures and unsupported configurations return exit code 1.

## Small bundled smoke suite

`python3 test/ega_pages.py` checks the substitute BIOS's EGA page sizes and
page selection on UEFI/QEMU/KVM. It draws two different pages, selects page 1,
redraws the hidden page 0, and verifies that page 1 remains visible. It also
checks masked planar reads/writes and their flags. This
guards the graphics page-flip bug that made Cosmo and Duke Nukum flicker.
The test uses a private disk and saves artifacts under `build/ci/ega-pages-*`.
It requires QEMU, KVM, OVMF, e2fsprogs and Pillow.

The opt-in suite plays bundled DOS games on the hosted RetroOS kernel. It
checks actual graphics and input-driven progress, preserves captures, and
can compare stable screens with reviewed reference pictures.

```sh
python3 test/game_suite.py --list
python3 test/game_suite.py --compare
python3 test/game_suite.py --select digger,keen --compare --jobs 2
python3 test/game_suite.py --engine kvm
```

Python 3, Bazel, and `mkfs.ext4` from e2fsprogs are required. The runner builds
only the hosted kernel; it does not build or change the main disk image.
`--no-build` uses the existing binary, and `--host-bin /path/to/binary`
selects another build. KVM requires access to `/dev/kvm`.

The suite uses installed games already in `showcase-bundle`, so it needs no
game downloads. `--source /path/to/tree` selects another installed tree with
the same `GAMES/...` layout. The current catalog covers real-mode Digger,
Commander Keen's EGA graphics and menu input, and Doom's DOS/4GW demo with
silent and SB16 configurations. It is separate from `test/run_all.sh` and CI.

## Isolation and results

Every scenario copies its game into a new directory, applies its configuration
overrides, and includes the repository's `BOOT.INI` and `RETROOS.INI`. It formats
a small, sparse ext4 disk from that directory and starts a separate hosted
kernel. Game writes cannot change the original assets or another scenario.
The disk uses RetroOS's ordinary boot storage policy and writable session
overlay. The copied tree records the starting files; session writes are in
the guest's RAM overlay and are not exported when the process stops.

Each invocation creates `tmp/game-suite/run-.../` containing:

- `report.md` and `report.json`: results and checkpoint metrics; `metadata.json`
  records the engine, storage, reference mode and kernel binary's SHA-256.
- A scenario directory with `retroos.log`, `command.json`, `inputs.json`
  (SHA-256 of each starting file), `scenario.json`, `result.json`, the starting
  C: tree and disk.
- Named PPM screenshots, the latest `screen.txt` and `screen.txt.ppm`, full
  `audio.wav`, and named WAV intervals for audio checks.
- An `.expected.ppm` beside each picture compared with a reference.

PPM is the hosted kernel's native image format; image viewers and ImageMagick
can open it. All captures are retained on passing and failing runs. A new
invocation never reuses files from an earlier run.

## Checks and references

The runner requires the game to enter the kernel's event loop. It fails on
kernel panic markers, unexpected process exits (including exit code zero),
deadline overruns, missing screen/log markers, malformed or blank captures,
wrong graphics dimensions, and insufficient screen changes between checkpoints.
Audio checks require actual samples with a specified minimum peak. Logs go
straight to a file so verbose guest output cannot fill a pipe and stall a run.

`--compare` additionally requires references for checkpoints with
`reference: true` (the default). It counts pixels where any RGB channel differs
by more than `channel_tolerance`, default 16, and fails if the fraction exceeds
`max_changed`, default 0.05. Dimensions must match exactly. References live in
`test/games/golden/<engine>/<scenario>/<checkpoint>.ppm`; each engine has its
own references. The committed TCG references cover Digger's title and Keen's
title and menu.

```sh
# Inspect captures from an ordinary run first, then explicitly record changes.
python3 test/game_suite.py --select keen --bless
python3 test/game_suite.py --select keen --compare
```

Bless writes references only after the entire scenario passes. Failed scenarios
and unexpected passes never replace references. Review the resulting images
before committing them. Without `--compare`, all structural, progress, log,
process and audio checks still run.

Unlike RustDOS's in-process harness, this runner controls an external process
using host time and the existing one-second screenshot watcher. It does not
promise identical frame or audio hashes across runs, nor equality between
TCG and KVM. SHA-256 values in reports identify artifacts, rather than serving
as deterministic assertions. Moving gameplay checkpoints set `reference: false`
and check graphics dimensions, colour coverage and progress instead. Use
condition waits for initialization, and keep reference checks on stable screens.

## Known failures

The SB16 Doom scenario currently reports `known-fail` when its audio interval
contains no sound. The hosted WAV port sink is explicitly disconnected in
`kernel/src/kernel/sound.rs`: it does not implement the output device's ring,
cursor and completion contract. The test keeps this gap visible.

A catalog entry's `expect_failure` must match the actual failure message.
An unrelated failure still fails the suite. A marked scenario that passes
reports `unexpected-pass` and fails the suite, prompting removal of the mark.
Successful cases and matching known failures return exit code zero; failures
and unexpected passes return one.

## Extending the catalog

Edit `test/games/catalog.json`. Each entry names an `id`, source `directory`,
`executable`, optional `arguments`, total `timeout`, optional `files` overrides
relative to the game directory, and sequential `steps`. Paths stay within the
scenario's copied tree. Input is a key tap; `repeat` sends several taps rather
than holding a key down.

| Operation | Fields | Purpose |
|---|---|---|
| `wait` | `seconds` | Delay while checking process health and the deadline |
| `key` | `key`, optional `repeat`, `interval` | Tap Enter, Space, Tab, Esc, F1, or an arrow |
| `text` | `contains`, optional `timeout` | Wait for text in the latest VGA text capture |
| `log` | `contains`, optional `timeout` | Wait for a guest log marker |
| `shot` | `name`, optional `settle`, `size`, `min_colours`, `min_lit` | Capture and validate graphics |
| `shot` | optional `different_from`, `min_change` | Require visual progress from an earlier checkpoint |
| `shot` | optional `reference`, `channel_tolerance`, `max_changed` | Control reference comparisons |
| `listen` | `name`, `seconds`, optional `min_seconds`, `min_peak` | Require non-silent audio in this interval |
| `exit` | `contains`, optional `timeout` | Wait for exit zero and require a completion log marker |

Use `exit` as the last step of a scenario that intentionally finishes. A
completion marker is required because some guest error paths also exit zero.

Run the harness's regression tests with:

```sh
python3 test/game_suite_test.py
```

They cover truncated images, image comparison tolerances, unpatched WAV tails,
path validation, log flooding, early zero exits, panics, and preservation of
references and source files when a later checkpoint fails, and strict known
failure matching with unexpected-pass detection.
