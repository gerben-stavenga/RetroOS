#!/bin/bash
# Ring-3 DPMI IRETD must not load VIF (SDM RETURN-TO-SAME-PRIVILEGE-LEVEL).
set -e -o pipefail
cd "$(dirname "$0")/.."
source test/lib/hosted_common.sh


LOG=/tmp/retroos-vifiret.log
timeout 30 "$HOST_BIN" --cmd "TESTS/VIFIRET.COM" bazel-bin/image.bin \
    </dev/null > "$LOG" 2>&1 || true

if ! grep -q "VIFIRET PASS" "$LOG"; then
    echo "FAIL: DPMI IRETD/VIF probe did not complete"
    tail -30 "$LOG"
    exit 1
fi
echo "PASS: ring-3 DPMI IRETD left VIF set"
