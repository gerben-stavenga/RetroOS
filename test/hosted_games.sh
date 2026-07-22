#!/bin/bash
# Hosted end-to-end smoke tests for CI.
#
# Each case boots a program on the hosted backend via test/hosted_test.py,
# optionally drives keyboard input, and asserts the kernel never panicked
# (and, for the text-mode DN shell, that its screen painted). The default TCG
# (software CPU) engine runs on any GitHub-hosted runner; set ENGINE=kvm to
# run the same cases on the KVM engine (needs /dev/kvm — skips cleanly when
# absent so CI stays green). Add a case by appending a `run` line.
#
# Exit 0 = all passed.
set -uo pipefail
cd "$(dirname "$0")/.."

IMG=bazel-bin/image.bin          # the open-source image carries the committed games
[ -f "$IMG" ] || { echo "no $IMG — run: bazelisk build //:image"; exit 1; }

HOST_BIN=bazel-bin/kernel/retroos-host
if [ "${ENGINE:-tcg}" = kvm ]; then
    # Probe by actually opening the device — `test -w` misses ACL grants.
    if ! { : <> /dev/kvm; } 2>/dev/null; then
        echo "SKIP: ENGINE=kvm but /dev/kvm unavailable — hosted games not run"
        exit 0
    fi
    HOST_BIN=bazel-bin/kernel/retroos-host-kvm
fi
[ -f "$HOST_BIN" ] || { echo "no $HOST_BIN — run: bazelisk build //kernel:$(basename "$HOST_BIN") --platforms=@platforms//host"; exit 1; }

PY="python3 test/hosted_test.py --host-bin $HOST_BIN --image $IMG"
fail=0
run() { local label="$1"; shift; echo "=== $label ==="; $PY "$@" || { fail=1; echo "  ^ FAILED: $label"; }; }

# DN (Dos Navigator) boots into its text-mode file manager: assert the event
# loop ran (no boot panic) and the panel painted. Note: launching a program
# from DN's file panel with Enter is a known DPMI-overlay bug (see the
# dn-enter-launch-bug memory) — not exercised here.
run "DN boots + panel paints" \
    --keys "" --settle 5 --timeout 20 \
    --expect-log "event_loop entered" --expect-screen "free bytes on drive"

# DIGGER: 16-bit real-mode game, launched headless + a few driven keystrokes.
run "DIGGER (real-mode) + keyboard" \
    --cmd "GAMES/DIGGER/DIGGER.EXE" --keys "wait:3,SPACE,wait:1,RIGHT,RIGHT,ENTER" \
    --settle 2 --timeout 25

# DOOM shareware: 32-bit DOS/4GW protected-mode game — reaching its setup
# without a kernel panic exercises the DPMI + mode-13h path.
run "DOOM (shareware, DPMI) boots" \
    --cmd "GAMES/DOOMS/DOOM.EXE" --settle 2 --timeout 35

# Emulated-SB single-cycle completion protocol (test/dos/sbproto): the DSP
# write-status busy flicker, the 8237 status TC bit, and the post-terminal
# count underflow — each regressed or went missing at least once (PoP's
# end-door hang / level-transition freeze). TC-OK on screen = all three hold.
run "SB DSP completion protocol" \
    --cmd "TESTS/SBTEST.COM" --settle 3 --timeout 30 \
    --expect-log "BUSY-OK" --expect-log "EDGE-OK" --expect-log "TC-OK"

# Emulated-GUS (GF1) probe (test/dos/gusproto): DRAM poke/peek detection
# and register-file readback through the voice/register-select scheme.
# Markers accrete as GF1 phases land (timers, DMA upload, audible voice).
run "GUS (GF1) registers, DRAM, timer IRQ, DMA upload, voice" \
    --cmd "TESTS/GUSTEST.EXE" --settle 3 --timeout 45 \
    --expect-log "GDRAM-OK" --expect-log "GREG-OK" --expect-log "GTIMER-OK" \
    --expect-log "GDMA-OK" --expect-log "GVOICE-OK"

# PC speaker (test/dos/spkproto): PIT channel 2's OUT line at port 61h bit 5 —
# the only part of the speaker path a guest can check by itself, and the part
# programs poll as a PIT presence test and a sub-tick delay source. TONES-DONE
# means the tone sequence also ran to completion; measuring its pitch needs a
# host-side capture (see the .asm header for the recipe).
run "PC speaker OUT line + tone sequence" \
    --cmd "TESTS/SPKTEST.COM" --settle 3 --timeout 30 \
    --expect-log "OUT-OK" --expect-log "TONES-DONE"

exit $fail
