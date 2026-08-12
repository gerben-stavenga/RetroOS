#!/usr/bin/env bash
# 86Box SB assertions — the reference for the REAL card.
#
# 86Box models an SB16 faithfully (the DSP test register, the write-status
# busy flicker, a completion IRQ per block) where QEMU's sb16 does not, and it
# is the ONLY backend that exercises the restrap: its card powers up on its own
# straps and RetroOS moves it to whatever BLASTER declares. Every bug that
# lives in that gap is invisible everywhere else.
#
# What this asserts, in order of what has actually broken:
#
#   1. SUSTAINED completion-IRQ delivery (SBIRQ.COM). The kernel used to
#      re-arm a hardcoded host IRQ 5 after the guest's EOI, so on a card
#      restrapped to IRQ 7 the first completion arrived and every later one
#      was masked off forever. Doom replayed one fragment as a tick; DUKE3D
#      reported "invalid or conflicting IRQ". Every polled probe passed.
#      IRQ-COUNT is the number that matters: 1 is the bug, 0 is a dead line.
#   2. The single-cycle completion protocol (SBTEST.COM).
#   3. Discovery/init conformance (SBDISC.COM).
#
# 86Box is a GUI application with no log to grep, so each probe writes its
# verdict to a file on C: and this script reads it back out of the disk image
# afterwards with debugfs — no screen scraping, no root. Three things had to
# be true for that to work at all, and none of them were until now: the probe
# needs a command channel (CONFIG.SYS TEST=, since 86Box has no fw_cfg), the
# guest's writes need to reach the image rather than the volatile RAM overlay,
# and the VM has to power off so those writes are flushed.
#
# Usage:
#   test/sb_86box.sh              run the assertions
#   test/sb_86box.sh --learn      open 86Box once so it records its own
#                                 per-device SB section (needed only if you
#                                 want to sweep straps; the default run uses
#                                 whatever 86Box defaults to, which is the
#                                 case that found the bug)
set -u
cd "$(dirname "$0")/.."

: "${BOX86:=}"
if [ -z "$BOX86" ]; then
    for c in "$HOME/bin/86Box.AppImage" /home/gerben/86Box/86Box-Linux-x86_64-b6130.AppImage; do
        [ -x "$c" ] && BOX86="$c" && break
    done
fi
FLATPAK_ID=""
if command -v flatpak >/dev/null 2>&1; then
    FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
fi
# BOX86 stays empty for a flatpak install: run.sh has its own flatpak launch
# path (it must pass --env and --filesystem grants), and setting BOX86 to a
# "flatpak run ..." string would bypass it.
[ -n "$BOX86" ] || [ -n "$FLATPAK_ID" ] || {
    echo "86Box not found; set BOX86=/path/to/86Box.AppImage" >&2; exit 2; }

# The CONFIGURED VM, not a scratch one: 86Box's machine/sound setup lives in
# its 86box.cfg, and a fresh dir would run whatever run.sh synthesizes rather
# than the machine this suite is meant to assert against. Derived exactly as
# run.sh does, and EXPORTED so run.sh uses the same dir we read back from.
if [ -z "${VM_DIR:-}" ]; then
    if [ -n "$FLATPAK_ID" ]; then
        VM_DIR="$HOME/.var/app/$FLATPAK_ID/data/86Box/RetroOS"
    else
        VM_DIR="$HOME/.local/share/86Box/RetroOS"
    fi
fi
export VM_DIR
# run.sh -i takes an image KEYWORD, not a path; IMG is the file the same
# keyword resolves to, which is what debugfs reads the verdicts back out of.
IMG_KIND="${IMG_KIND:-image}"
# 86Box runs a COPY inside the VM dir ($VM_DIR/disk.img), not bazel-bin's
# image, so that copy is where a probe's verdict lands and where we read it.
IMG="${IMG:-$VM_DIR/disk.img}"

# Only one probe may use this VM directory at a time.  This also prevents a
# second test runner from copying a new disk image underneath an active 86Box.
mkdir -p "$VM_DIR"
if ! exec 9>"$VM_DIR/.retroos-test.lock"; then
    echo "Cannot create the 86Box test lock in: $VM_DIR" >&2
    exit 2
fi
if ! flock -n 9; then
    echo "86Box test VM is already in use: $VM_DIR" >&2
    exit 2
fi
# A VM left behind by an interrupted older run does not hold the lock above.
# Refuse to start another copy against that same disk; silently sharing it can
# make the result file appear to belong to the wrong probe.
existing_vm=$(pgrep -af -- "--vmpath[[:space:]]+$VM_DIR([[:space:]]|$)" || true)
if [ -n "$existing_vm" ]; then
    echo "86Box test VM already has a running instance:" >&2
    echo "$existing_vm" >&2
    echo "Close that instance before rerunning the test." >&2
    exit 2
fi

# Read a probe's verdict file out of the image the run just used. The DOS C:
# root is an ext4 subtree, so debugfs reads it without mounting (no root).
read_verdict() {
    local img="$1" name="$2" part_off part out
    [ -f "$img" ] || return 1
    # Partition 2 carries the ext4 root with C:; partition 1 is the boot TAR.
    part_off=$(partx -g -o START -n 2 "$img" 2>/dev/null | tr -d ' ')
    [ -n "$part_off" ] || return 1
    # A real file, not <(dd ...): debugfs seeks, and a process substitution is
    # a pipe — it fails with "Illegal seek" and reads nothing, silently.
    part=$(mktemp) || return 1
    dd if="$img" bs=512 skip="$part_off" of="$part" status=none 2>/dev/null
    out=$(debugfs -R "cat home/retroos/$name" "$part" 2>/dev/null)
    rm -f "$part"
    printf '%s' "$out"
}

if [ "${1:-}" = "--learn" ]; then
    mkdir -p "$VM_DIR"
    echo "Opening 86Box. In Settings -> Sound -> Sound Blaster 16 -> Configure,"
    echo "set base/IRQ/DMA, then quit. The section 86Box writes is what a strap"
    echo "sweep needs:"
    echo
    ./run.sh 86box -i "$IMG_KIND" || true
    echo
    echo "--- per-device sections found in $VM_DIR/86box.cfg ---"
    awk '/^\[/{p=0} /Sound Blaster|SB16|sb16/{p=1} p' "$VM_DIR/86box.cfg" 2>/dev/null
    exit 0
fi

FAILED=0
VM_PGID=""

# Stop a launched VM, whichever way it was launched.
#
# Killing the job we started is NOT enough, and neither is killing its process
# group: `flatpak run` hands the app off to the flatpak session helper, so
# bubblewrap and 86Box end up re-parented OUTSIDE our session entirely. The
# job exits, the emulator keeps running, and its window stays on screen — a
# suite run used to leave one VM behind per hung probe.
#
# So: kill the process group (covers an AppImage or a PATH install, which do
# stay in our session), and additionally ask flatpak to stop the app, which is
# the only thing that reaches a re-parented one.
kill_vm() {
    if [ -n "$VM_PGID" ]; then
        kill -TERM -- "-$VM_PGID" 2>/dev/null
        # Do not wait forever if the emulator ignores TERM or its GUI helper
        # keeps the process group alive.  Give it a short grace period, then
        # forcibly reap the complete group before the next probe starts.
        local i
        for i in 1 2 3 4 5; do
            kill -0 -- "-$VM_PGID" 2>/dev/null || break
            sleep 1
        done
        if kill -0 -- "-$VM_PGID" 2>/dev/null; then
            kill -KILL -- "-$VM_PGID" 2>/dev/null
        fi
        wait "$VM_PGID" 2>/dev/null || true
        VM_PGID=""
    fi
    if [ -n "$FLATPAK_ID" ]; then
        flatpak kill "$FLATPAK_ID" >/dev/null 2>&1
    fi
    # Give the window server a moment to reap before the next probe copies
    # over the disk image the VM had open.
    sleep 1
}
# A ^C or a script-level timeout must not leave a VM (and its window) behind.
trap 'kill_vm; exit 130' INT TERM
trap 'kill_vm' EXIT

# How long a single probe may take, in seconds: 86Box boots an AMI BIOS POST,
# then RetroOS, then the program. Generous — the loop exits as soon as the
# verdict appears, so a healthy probe costs whatever it actually needs.
PROBE_TIMEOUT="${PROBE_TIMEOUT:-240}"

# $1 = probe .COM path on C:, $2 = verdict filename, $3.. = required markers.
#
# The probe is launched through CONFIG.SYS's TEST= line (run.sh injects it into
# this run's disk copy), which is the only command channel 86Box has — it takes
# no fw_cfg and no command line.
#
# We poll for the verdict file rather than wait for the process to exit,
# because 86Box never exits: RetroOS's `shutdown()` pokes the QEMU/Bochs/
# VirtualBox ACPI shutdown ports and 86Box's PIIX4 PM base is elsewhere, so the
# guest halts and the window stays up. Killing it once the verdict has landed
# is the normal end of a probe here, not a failure.
run_probe() {
    local prog="$1" log="$2"; shift 2
    echo "=== $prog ==="

    setsid ./run.sh 86box -i "$IMG_KIND" --cmd "$prog" >/dev/null 2>&1 &
    local pid=$! waited=0 verdict=""
    VM_PGID="$pid"
    while [ "$waited" -lt "$PROBE_TIMEOUT" ]; do
        sleep 5
        waited=$((waited + 5))
        verdict=$(read_verdict "$IMG" "$log")
        [ -n "$verdict" ] && break
        # If it died on its own, stop waiting on it.
        kill -0 "$pid" 2>/dev/null || break
    done

    # A healthy probe has already powered the VM off (the kernel's ACPI
    # soft-off reaches 86Box's PIIX4 now), so this only catches a hung one.
    # NOT pkill on a name pattern: this script's own name matches "86box" and
    # it would kill itself. The process group is the precise thing to kill.
    kill_vm
    # Read once more now that the VM is definitely gone: a clean power-off is
    # what flushes the image, so on the normal path the verdict only becomes
    # visible AFTER the loop above noticed the process exit.
    [ -n "$verdict" ] || verdict=$(read_verdict "$IMG" "$log")

    if [ -z "$verdict" ]; then
        echo "FAIL: no $log in the image after ${PROBE_TIMEOUT}s — the probe did not run" >&2
        FAILED=1
        return
    fi
    echo "$verdict"

    local m
    for m in "$@"; do
        if ! printf '%s' "$verdict" | grep -q "$m"; then
            echo "FAIL: expected '$m'" >&2
            FAILED=1
        fi
    done
    # Any FAIL- marker the probe emitted is a failure even if the required
    # markers are present, so a new probe failure cannot pass silently.
    if printf '%s' "$verdict" | grep -q 'FAIL-'; then
        echo "FAIL: probe reported a failure marker" >&2
        FAILED=1
    fi
}

# 1. Sustained completion IRQs on the REAL card, on whatever line the restrap
#    left it. This is the assertion the suite was missing.
run_probe "TESTS/SBIRQ.COM"  SBIRQ.LOG  IRQ-SUSTAINED-OK

# 2. Single-cycle completion protocol.
run_probe "TESTS/SBTEST.COM" SBTEST.LOG BUSY-OK EDGE-OK TC-OK

# 3. Discovery / init conformance.
run_probe "TESTS/SBDISC.COM" SBDISC.LOG

if [ "$FAILED" = 0 ]; then
    echo "PASS: 86Box SB assertions"
else
    echo "FAIL: 86Box SB assertions" >&2
fi
exit "$FAILED"
