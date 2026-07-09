#!/bin/bash
# HX DPMI conformance test.
#
# Runs Japeth's DPMI probe (TESTS/DPMI.EXE, from the HX DOS Extender — freeware,
# see test/dpmi/HX-CREDITS.txt) under the hosted TCG backend and asserts that
# RetroOS's DPMI 0.90 host answers the probe with a full, sane state dump and
# the client survives the real<->protected mode round-trips.
#
# `DPMI.EXE -r` exercises: V86 entry, INT 2Fh AX=1687 (get DPMI entry), the
# real->protected switch, DPMI host version query, LDT/selector setup, GDTR/
# IDTR/LDTR/TR readback, PIC-base query, state-save-buffer sizing, and the
# "raw" real<->protected mode-switch entry points. dosemu2 uses the same tool
# as a reference (dosemu2 issue #52, where it SEGV'd — the crash we must not
# regress into).
#
# Exits 0 on PASS, 1 on FAIL.
set -e -o pipefail
cd "$(dirname "$0")/.."

bazelisk build //:image 2>&1 | tail -1
bazelisk build //kernel:retroos-host --platforms=@platforms//host 2>&1 | tail -1

LOG=/tmp/dpmi-hx.log
# Hosted backend routes the DOS program's INT 21h console output to stdout,
# so the probe's dump lands in the log for content assertions.
timeout 40 bazel-bin/kernel/retroos-host --cmd "TESTS/DPMI.EXE -r" bazel-bin/image.bin \
    </dev/null > "$LOG" 2>&1 || true

fail() { echo "FAIL: $1"; echo "----- last 30 log lines -----"; tail -30 "$LOG"; exit 1; }

grep -qiE "KERNEL PANIC|panicked|SEGV|Segmentation" "$LOG" && fail "kernel/DPMI crash during probe"
grep -qi "DPMI v0.90 host found"  "$LOG" || fail "DPMI 0.90 host not detected (dump missing)"
grep -qi "raw jump to real-mode"  "$LOG" || fail "raw real<->protected mode-switch entries not reported"
grep -qi "GDTR:"                  "$LOG" || fail "descriptor-table state (GDTR/IDTR/LDTR) not reported"
grep -q  "All commands done"      "$LOG" || fail "DPMI.EXE did not run to completion"

echo "PASS: HX DPMI probe completed; DPMI 0.90 host reported full state, no crash"
