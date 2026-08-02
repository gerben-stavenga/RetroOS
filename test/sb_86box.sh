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
# afterwards with debugfs — no screen scraping, no root.
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
if [ -z "$BOX86" ] && command -v flatpak >/dev/null 2>&1; then
    FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
    [ -n "$FLATPAK_ID" ] && BOX86="flatpak run $FLATPAK_ID"
fi
[ -n "$BOX86" ] || { echo "86Box not found; set BOX86=/path/to/86Box.AppImage" >&2; exit 2; }

VM_DIR="${VM_DIR:-$HOME/.local/share/86Box/retroos-sbsweep}"
IMG="${IMG:-bazel-bin/image.bin}"

# Read a probe's verdict file out of the image the run just used. The DOS C:
# root is an ext4 subtree, so debugfs reads it without mounting (no root).
read_verdict() {
    local img="$1" name="$2" part_off
    part_off=$(partx -g -o START -n 1 "$img" 2>/dev/null | tr -d ' ')
    [ -n "$part_off" ] || return 1
    debugfs -R "cat home/retroos/$name" \
        <(dd if="$img" bs=512 skip="$part_off" 2>/dev/null) 2>/dev/null
}

if [ "${1:-}" = "--learn" ]; then
    mkdir -p "$VM_DIR"
    echo "Opening 86Box. In Settings -> Sound -> Sound Blaster 16 -> Configure,"
    echo "set base/IRQ/DMA, then quit. The section 86Box writes is what a strap"
    echo "sweep needs:"
    echo
    BOX86="$BOX86" ./run.sh 86box -i "$IMG" || true
    echo
    echo "--- per-device sections found in $VM_DIR/86box.cfg ---"
    awk '/^\[/{p=0} /Sound Blaster|SB16|sb16/{p=1} p' "$VM_DIR/86box.cfg" 2>/dev/null
    exit 0
fi

FAILED=0

# $1 = probe .COM path on C:, $2 = verdict filename, $3.. = required markers.
# The probe is launched through the ordinary shell path (not --cmd) so the run
# is the one a user would get; 86Box exits when the program does.
run_probe() {
    local prog="$1" log="$2"; shift 2
    echo "=== $prog ==="
    BOX86="$BOX86" ./run.sh 86box -i "$IMG" --cmd "$prog" >/dev/null 2>&1 || true

    local verdict
    verdict=$(read_verdict "$IMG" "$log")
    if [ -z "$verdict" ]; then
        echo "FAIL: no $log in the image — the probe did not run" >&2
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
