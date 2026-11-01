#!/usr/bin/env bash
# Run our SB probes under DOSBox-X as an independent oracle.
#
# DOSBox-X is a second, mature implementation: where it disagrees with our
# emulated card, one of us is wrong about the hardware — which is exactly
# the question our own tests cannot answer about themselves.
#
# The probes write their verdict to C:\<name>.LOG, and DOSBox's C: is a host
# directory, so the answer comes back as a plain file: no screen scraping,
# and it survives DOSBox being killed (the log is closed before the probe
# parks on a keypress).
#
# Run this from YOUR desktop session — DOSBox-X wants a display, and
# headless attempts in the flatpak sandbox left the DSP unresponsive
# (FAIL-RST), which is itself unexplained.
#
# Usage: test/dosbox_probe.sh [SBDISC|SBTEST]
set -euo pipefail
cd "$(dirname "$0")/.."
PROBE="${1:-SBDISC}"
D="${DOSBOX_PROBE_DIR:-$HOME/dosbox-probe}"
mkdir -p "$D"
D=$(realpath "$D")
SRC="bazel-bin/test/dos/sbproto/$PROBE.COM"
if [ ! -f "$SRC" ]; then
    echo "missing declared probe $SRC; run bazelisk test //tests:dosbox_probe" >&2
    exit 1
fi
# Bazel outputs are read-only, so a plain cp onto a previous copy fails with
# EACCES; install writes a fresh writable file.
install -m 0644 "$SRC" "$D/$PROBE.COM" || exit 1
rm -f "$D/$PROBE.LOG"

flatpak run --filesystem="$D" com.dosbox_x.DOSBox-X \
    -nopromptfolder \
    -set "sblaster sbtype=sb16" -set "sblaster sbbase=220" \
    -set "sblaster irq=7" -set "sblaster dma=1" -set "sblaster hdma=5" \
    -c "mount c $D" -c "c:" -c "$PROBE.COM"

echo "--- $PROBE.LOG ---"
cat "$D/$PROBE.LOG"
! grep -q 'FAIL' "$D/$PROBE.LOG"
case "$PROBE" in
    SBDISC) grep -q 'AUTOINIT-OK' "$D/$PROBE.LOG" ;;
    SBTEST) grep -q 'TC-OK' "$D/$PROBE.LOG" ;;
    *) echo "Unknown SB reference probe: $PROBE" >&2; exit 2 ;;
esac
