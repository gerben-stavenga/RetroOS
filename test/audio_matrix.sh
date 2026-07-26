#!/usr/bin/env bash
# Audio matrix — the guest must see the same devices regardless of what
# renders them.
#
# Two backends, two jobs, because each is authoritative for different
# hardware:
#
#   QEMU  — the SINK reference. Its AC'97 and Intel HDA models are good, and
#           they are the modern-machine path: our emulated SB/GUS/GM produce
#           canonical PCM and the kernel renders it out one of those codecs.
#           QEMU's own sb16 is NOT used here: it lacks the DSP test register
#           and the write-status busy flicker that real chips have, so
#           testing SB against it would validate our workarounds instead of
#           our design.
#   86Box — the SB reference (not yet wired up, see below). It models a real
#           SB16/Pro faithfully, so the passthrough/native path and the
#           physical-configuration sweep belong there.
#
# What is asserted: the guest-visible protocol, which must not depend on the
# sink. SBTEST.COM exercises the emulated DSP's completion protocol (busy
# flicker, busy->idle edge, 8237 terminal count); GUSTEST the GF1's detection
# and register readback. Neither program can tell which codec is downstream —
# and that is the property under test.
#
# Usage: test/audio_matrix.sh [--kvm]
set -u
cd "$(dirname "$0")/.."
LOG_DIR="${TMPDIR:-/tmp}/audio_matrix.$$"
mkdir -p "$LOG_DIR"
ACCEL=(); [ "${1:-}" = "--kvm" ] && ACCEL=(--kvm)

# probe:expected-markers
PROBES=(
    "TESTS/SBTEST.COM:BUSY-OK EDGE-OK TC-OK"
    "TESTS/GUSTEST.EXE:GDRAM-OK GREG-OK GTIMER-OK GDMA-OK GVOICE-OK"
)
SINKS=(ac97 hda none)

pass=0; fail=0
printf '%-10s %-22s %s\n' SINK PROBE RESULT
for sink in "${SINKS[@]}"; do
  for entry in "${PROBES[@]}"; do
    prog="${entry%%:*}"; expect="${entry#*:}"
    log="$LOG_DIR/$sink-$(basename "$prog").log"
    QEMU_DISPLAY=none timeout 60 ./run.sh qemu "${ACCEL[@]}" --arch x64 \
        --sound "$sink" --cmd "$prog" > "$log" 2>&1
    missing=()
    for e in $expect; do grep -aq "$e" "$log" || missing+=("$e"); done
    if [ ${#missing[@]} -eq 0 ]; then
        pass=$((pass+1)); printf '%-10s %-22s ok\n' "$sink" "$(basename "$prog")"
    else
        fail=$((fail+1))
        printf '%-10s %-22s FAIL missing:%s (%s)\n' "$sink" "$(basename "$prog")" \
            "$(IFS=,; echo "${missing[*]}")" "$log"
    fi
  done
done

echo
echo "audio_matrix: $pass passed, $fail failed (logs in $LOG_DIR)"
echo
echo "NOT COVERED HERE — the native/passthrough SB sweep (physical base, IRQ,"
echo "8-bit and 16-bit channel, x SB_AUDIO=native|mixed) belongs on 86Box,"
echo "whose SB16 model is faithful. Wiring it up needs 86Box's per-device"
echo "config keys, which its AppImage does not expose to grep: run it once"
echo "with sndcard=sb16, let it write its defaults, and read the section it"
echo "generates. The invariant to assert there is the same one: BLASTER is"
echo "what the guest sees, so SBTEST's three markers must hold no matter"
echo "where the real card is strapped."
[ "$fail" -eq 0 ]
