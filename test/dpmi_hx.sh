#!/bin/bash
# HX DPMI conformance test.
#
# Runs Japeth's DPMI probe (TESTS/DPMI.EXE, from the HX DOS Extender — freeware,
# see test/dpmi/HX-CREDITS.txt) under the selected hosted engine and asserts that
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
source test/lib/hosted_common.sh


LOG=/tmp/dpmi-hx.log
fail() { echo "FAIL: $1"; echo "----- last 30 log lines -----"; tail -30 "$LOG"; exit 1; }

# The probe also benchmarks 100,000 reflected INTs, 100,000 simulated INTs,
# 500,000 virtual-IF calls and 200,000 raw mode-switch round trips. Nested
# KVM on a shared CI runner can exceed 40 seconds while still progressing.
# Keep a bounded deadline, allowing the complete workload on slower hosts.
# Hosted INT 21h console output lands in the log for content assertions.
status=0
timeout --kill-after=5 180 "$HOST_BIN" --cmd "TESTS/DPMI.EXE -r" bazel-bin/image.bin \
    </dev/null > "$LOG" 2>&1 || status=$?
if [ "$status" -eq 124 ]; then
    fail "HX DPMI probe timed out after 180 seconds"
elif [ "$status" -ne 0 ]; then
    fail "HX DPMI probe exited with status $status"
fi

grep -qiE "KERNEL PANIC|panicked|SEGV|Segmentation" "$LOG" && fail "kernel/DPMI crash during probe"
# The shared hosted debug stream can interrupt DOS text between INT 21h
# writes. Remove only the informational clock-start line from content checks;
# crash checks above and failure diagnostics retain the complete raw log.
python3 - "$LOG" "$LOG.probe" <<'PYTHON'
from pathlib import Path
import re
import sys
text = Path(sys.argv[1]).read_text(errors="replace")
text = re.sub(r"CLOCK: first event-loop clock sample \([^\r\n]*\)\r?\n", "", text)
Path(sys.argv[2]).write_text(text)
PYTHON
grep -qi "DPMI v0.90 host found"  "$LOG.probe" || fail "DPMI 0.90 host not detected (dump missing)"
grep -qi "raw jump to real-mode"  "$LOG.probe" || fail "raw real<->protected mode-switch entries not reported"
grep -qi "GDTR:"                  "$LOG.probe" || fail "descriptor-table state (GDTR/IDTR/LDTR) not reported"
for benchmark in \
    'time calling 100.000 * INT 69h:' \
    'time calling 100.000 * INT 31h, AX=0300h (Sim INT 69h):' \
    'time calling 500.000 * INT 31h, AX=0901h:' \
    'time 200.000 * raw mode switches PM->RM->,PM:'; do
    grep -F "$benchmark" "$LOG.probe" || fail "benchmark did not complete: $benchmark"
done
grep -qF '[mem] exit tid=1 code=0' "$LOG" || fail "DPMI.EXE did not exit successfully"
grep -q  "All commands done"      "$LOG" || fail "DPMI.EXE did not run to completion"

echo "PASS: HX DPMI probe completed; DPMI 0.90 host reported full state, no crash"
