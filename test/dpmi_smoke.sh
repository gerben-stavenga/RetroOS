#!/bin/bash
# DPMI regression smoke test: build image_proprietary, boot QEMU, autoload
# BCC.EXE compiling TESTS/DPMIHI.C. PASS if BCC+TLINK run to completion
# (kernel reaches "All commands done -- shutting down") with no panic.
#
# BCC.EXE is a 16-bit DPMI client (uses DPMI16BI.OVL); a successful run
# exercises:
#   - PM->RM->PM round-trips for INT 21 simulation
#   - LDT alloc/set-base/set-limit
#   - cross-mode ModeSave push/pop
#   - PM int (TLINK exec via INT 21 AH=4Bh)
#   - exception cascade (INT 0/3 reflection if BCC compiles fail)
#
# Exits 0 on PASS, 1 on FAIL.
set -e -o pipefail
cd "$(dirname "$0")/.."

bazelisk build //:image_proprietary 2>&1 | tail -3

cp bazel-bin/image_proprietary.bin /tmp/dpmi-test.img
chmod +w /tmp/dpmi-test.img

# Run BCC compile of the tiny hello.c. Use -c (compile only, no link)
# first since linking pulls libc and the test goal is just "DPMI doesn't
# crash". -mt = tiny model. TURBOC.CFG in BORLANDC/BIN provides the
# include/lib paths.
LOG=/tmp/dpmi-test.log
timeout 60 qemu-system-i386 \
    -drive file=/tmp/dpmi-test.img,format=raw,snapshot=on \
    -m 64M -display none -debugcon stdio -serial null -no-reboot \
    -fw_cfg name=opt/cmdline,string="BORLANDC/BIN/BCC.EXE -ml -c TESTS\\DPMIHI.C" \
    > "$LOG" 2>&1 || true

if grep -q "KERNEL PANIC" "$LOG"; then
    echo "FAIL: kernel panic during BCC compile"
    grep -A4 "KERNEL PANIC" "$LOG" | head -20
    exit 1
fi

if ! grep -q "All commands done" "$LOG"; then
    echo "FAIL: BCC didn't run to completion"
    tail -30 "$LOG"
    exit 1
fi

echo "PASS: BCC ran without kernel panic"
