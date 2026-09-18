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
#   86Box — the SB reference (test/sb_86box.sh). It models a real
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
set -uo pipefail
cd "$(dirname "$0")/.."
source test/lib/qemu_common.sh
qemu_bazel build //:image //kernel:kernel_elf || exit 1
LOG_DIR=$(mktemp -d -t retroos-audio-matrix.XXXXXX)
ACCEL=(); [ "${1:-}" = "--kvm" ] && ACCEL=(--kvm)
pid=""
trap 'qemu_stop_and_reap "$pid"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
    AUDIO_BACKEND=none QEMU_DISPLAY=none timeout --kill-after=5 90 \
        ./run.sh qemu "${ACCEL[@]}" --arch x64 --firmware uefi -i image \
        --sound "$sink" --cmd "$prog" > "$log" 2>&1 &
    pid=$!
    # Both probes wait for a key after their last verdict.
    qemu_wait_for_log "$log" "${expect##* }\|KERNEL PANIC\|panicked\|-FAIL" 90 "$pid" || true
    qemu_stop_and_reap "$pid"
    pid=""
    missing=()
    for e in $expect; do grep -aq "$e" "$log" || missing+=("$e"); done
    if grep -aqE 'KERNEL PANIC|panicked|SEGV|-FAIL' "$log"; then
        missing+=("no-crash-or-failure")
    fi
    if [ ${#missing[@]} -eq 0 ]; then
        pass=$((pass+1)); printf '%-10s %-22s ok\n' "$sink" "$(basename "$prog")"
    else
        fail=$((fail+1))
        # Show why here: the log lives in a temp dir that CI throws away.
        printf '=== %s %s last 40 lines ===\n' "$sink" "$(basename "$prog")" >&2
        tail -40 "$log" >&2
        printf '%-10s %-22s FAIL missing:%s (%s)\n' "$sink" "$(basename "$prog")" \
            "$(IFS=,; echo "${missing[*]}")" "$log"
    fi
  done
done

echo
echo "audio_matrix: $pass passed, $fail failed (logs in $LOG_DIR)"
echo
echo "Native SB16 coverage: test/sb_86box.sh (not a physical-configuration sweep)."
[ "$fail" -eq 0 ]
