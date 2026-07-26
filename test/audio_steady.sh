#!/usr/bin/env bash
# Steady-state audio health — does playback keep working, not just start.
#
# Every probe we have is init-time; they stop before the interesting part.
# Today's real regressions all lived AFTER the first block: the codec lapping
# the producer (echo), a wedged drain clock (silence), a pipe that drifted.
# The sink driver already counts everything needed to see them — this reads
# those counters after a real game has been playing for a while and asserts
# the invariants:
#
#   dropped = 0            frames refused at the ring's ahead-ceiling; any
#                          drop means the pacer overfilled (echo/garble)
#   resyncs <= 2           codec laps; one at session start is normal, a
#                          storm means the drain clock is wrong
#   emitted = 4*written    every source frame reached the ring as stereo i16
#   consumed <= emitted    the drain never claims frames never produced
#   pipe within 15..45 ms  the universal depth, neither starved nor bloated
#
# Usage: test/audio_steady.sh [--kvm] [seconds]
set -u
cd "$(dirname "$0")/.."
ACCEL=(); [ "${1:-}" = "--kvm" ] && { ACCEL=(--kvm); shift; }
SECS="${1:-60}"
LOG="${TMPDIR:-/tmp}/audio_steady.$$.log"

QEMU_DISPLAY=none timeout $((SECS + 20)) ./run.sh qemu "${ACCEL[@]}" --arch x64 \
    --sound hda --cmd "GAMES/DOOMS/DOOM.EXE" > "$LOG" 2>&1

last=$(grep -a '^hda: diag' "$LOG" | tail -1)
if [ -z "$last" ]; then
    echo "FAIL: no hda diag lines — the sink never streamed ($LOG)"
    exit 1
fi
echo "$last"

val() { sed -n "s/.*\b$1=\([0-9]*\).*/\1/p" <<<"$last"; }
written=$(val written_src); consumed=$(val consumed_hw); emitted=$(val emitted)
dropped=$(val dropped);     resyncs=$(val resyncs)

fail=0
say() { echo "  $1"; }
[ "${dropped:-1}" -eq 0 ] || { say "FAIL dropped=$dropped (pacer overfilled the ring)"; fail=1; }
[ "${resyncs:-9}" -le 2 ] || { say "FAIL resyncs=$resyncs (codec lapping repeatedly)"; fail=1; }
[ "$emitted" -eq $((written * 4)) ] || { say "FAIL emitted=$emitted != 4*written_src=$written"; fail=1; }
[ "$consumed" -le "$emitted" ] || { say "FAIL consumed=$consumed > emitted=$emitted"; fail=1; }

# Pipe depth in ms: (emitted - consumed) bytes / 4 per frame / 44.1 per ms.
pipe_ms=$(( (emitted - consumed) / 4 / 44 ))
if [ "$pipe_ms" -lt 15 ] || [ "$pipe_ms" -gt 45 ]; then
    say "FAIL pipe=${pipe_ms}ms outside 15..45"
    fail=1
else
    say "pipe=${pipe_ms}ms"
fi

if [ "$fail" -eq 0 ]; then
    echo "audio_steady: OK after ${SECS}s"
else
    echo "audio_steady: FAILED (log: $LOG)"
fi
exit $fail
