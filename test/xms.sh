#!/bin/bash
# XMS 3.0 conformance probe under the hosted backend.
set -e -o pipefail
cd "$(dirname "$0")/.."
source test/lib/hosted_common.sh


LOG=/tmp/retroos-xms.log
timeout 30 "$HOST_BIN" --cmd "TESTS/XMSPROBE.COM" bazel-bin/image.bin \
    </dev/null > "$LOG" 2>&1 || true

if ! grep -q "XMSPROBE PASS" "$LOG"; then
    echo "FAIL: XMS probe did not complete"
    tail -30 "$LOG"
    exit 1
fi
echo "PASS: XMS 3.0 allocation, move, lock, extended, and UMB services"
