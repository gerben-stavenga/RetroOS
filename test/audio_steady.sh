#!/usr/bin/env bash
# Steady-state audio health — does playback keep working, not just start.
#
# Every probe we have is init-time; they stop before the interesting part.
# Today's real regressions all lived AFTER the first block: the codec lapping
# the producer (echo), a wedged drain clock (silence), a pipe that drifted.
# The current sink exposes lifecycle and recovery events in klog. This reads
# those events after a real game has been playing for a while and asserts that
# the stream started and did not enter underrun recovery:
#
#   sink initialized      a real HDA sink was selected
#   playback start        pre-roll completed and DMA was armed
#   first frame played    HDA reported actual playback progress
#   recovery count        at most two underrun recoveries, matching the old
#                         resynchronization tolerance
#
# Usage: test/audio_steady.sh [--kvm] [seconds]
set -u
cd "$(dirname "$0")/.."
ACCEL=(); [ "${1:-}" = "--kvm" ] && { ACCEL=(--kvm); shift; }
SECS="${1:-60}"
LOG="${TMPDIR:-/tmp}/audio_steady.$$.log"

QEMU_DISPLAY=none timeout $((SECS + 20)) ./run.sh qemu "${ACCEL[@]}" --arch x64 \
    --sound hda --cmd "GAMES/DOOMS/DOOM.EXE" > "$LOG" 2>&1

initialized=$(grep -a -c 'sound: sink initialized stopped' "$LOG" || true)
started=$(grep -a -c 'sound: playback start' "$LOG" || true)
first_frame=$(grep -a -c 'sink: first frame played' "$LOG" || true)
underruns=$(grep -a -c 'sound: playback recovery reason=underrun' "$LOG" || true)

if [ "$initialized" -eq 0 ]; then
    echo "FAIL: no HDA sink initialization ($LOG)"
    exit 1
fi
if [ "$started" -eq 0 ] || [ "$first_frame" -eq 0 ]; then
    echo "FAIL: HDA never reached playback (start=$started first_frame=$first_frame; $LOG)"
    exit 1
fi
echo "sink initialized=$initialized playback_start=$started first_frame=$first_frame underruns=$underruns"

fail=0
say() { echo "  $1"; }
[ "$underruns" -le 2 ] || {
    say "FAIL underrun recoveries=$underruns (maximum allowed: 2)"
    fail=1
}
say "underrun recoveries=$underruns (maximum allowed: 2)"

if [ "$fail" -eq 0 ]; then
    echo "audio_steady: OK after ${SECS}s"
else
    echo "audio_steady: FAILED (log: $LOG)"
fi
exit $fail
