#!/bin/bash
# XMS 3.0 conformance probe under the hosted backend.
set -e -o pipefail
cd "$(dirname "$0")/.."
source test/lib/hosted_common.sh

root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
mkdir "$root/TESTS"
cp bazel-bin/test/dos/xmsprobe/XMSPROBE.COM "$root/TESTS/XMSPROBE.COM"

LOG="$root/probe.log"
timeout 30 "$HOST_BIN" --cmd "TESTS/XMSPROBE.COM" "$root" \
    </dev/null > "$LOG" 2>&1 || true

if ! grep -q "XMSPROBE PASS" "$LOG"; then
    echo "FAIL: XMS probe did not complete"
    tail -30 "$LOG"
    exit 1
fi
echo "PASS: XMS 3.0 allocation, move, lock, extended, and UMB services"
