#!/bin/bash
# Dark Forces (DOS/4GW) regression smoke test: build image_proprietary,
# boot QEMU, autoload GAMES/DFORCES/DARK.EXE. PASS if the game reaches
# its main loop (we don't drive input -- just check no kernel panic
# within 30s of DOS/4GW init).
#
# DARK.EXE is a 32-bit DOS/4GW Protected Mode client; a successful run
# exercises the same DPMI surface as BCC plus 32-bit-specific paths
# (LDT alloc with 32-bit defaults, larger memory blocks, DPMI exception
# cascade). This is the test that bisects to first-bad commit 8a7caf0.
#
# Exits 0 on PASS, 1 on FAIL.
set -e -o pipefail
cd "$(dirname "$0")/.."

bazelisk build //:image_proprietary 2>&1 | tail -3

cp bazel-bin/image_proprietary.bin /tmp/dark-test.img
chmod +w /tmp/dark-test.img

LOG=/tmp/dark-test.log
timeout 30 qemu-system-i386 \
    -drive file=/tmp/dark-test.img,format=raw,snapshot=on \
    -m 64M -display none -debugcon stdio -serial null -no-reboot \
    -fw_cfg name=opt/cmdline,string="GAMES/DFORCES/DARK.EXE" \
    -fw_cfg name=opt/cwd,string="GAMES/DFORCES/" \
    > "$LOG" 2>&1 || true

if grep -q "KERNEL PANIC" "$LOG"; then
    echo "FAIL: kernel panic during DARK.EXE run"
    grep -B2 -A6 "KERNEL PANIC" "$LOG" | head -20
    exit 1
fi

# Game runs and exits cleanly (game-side fault is fine -- we're testing
# the host's exception cascade, not Dark Forces' own correctness).
if ! grep -qE "All commands done|DOS/4GW" "$LOG"; then
    echo "FAIL: DARK.EXE didn't run"
    tail -20 "$LOG"
    exit 1
fi

echo "PASS: DARK.EXE ran without kernel panic"
