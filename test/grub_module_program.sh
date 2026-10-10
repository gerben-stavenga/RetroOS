#!/usr/bin/env bash
# Run representative DOS programs from the release GRUB Multiboot USB image.
#
# This is intentionally small: the existing hosted and raw-disk tests already
# cover the device and program matrices.  This test only verifies that the
# actual USB image supplies the core and combined showcase modules.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

bazelisk build //:grub_module_usb >/dev/null

run_program() {
    local name="$1" command="$2" log="$tmp_dir/$1.log"
    echo "=== $name ==="

    # The guest may remain interactive after reporting success.  The harness
    # must therefore terminate QEMU, and must escalate if QEMU does not
    # handle SIGTERM promptly.
    timeout --kill-after=5s 60s qemu-system-i386 \
        -m 512 -cpu pentium3 \
        -device qemu-xhci,id=usb \
        -drive if=none,id=stick,file=bazel-bin/retroos_grub_module_usb.img,format=raw,snapshot=on \
        -device usb-storage,bus=usb.0,drive=stick,bootindex=1 \
        -boot order=c \
        -fw_cfg "name=opt/cmdline,string=$command" \
        -debugcon "file:$log" \
        -display none -no-reboot >/dev/null 2>&1 || true

    grep -q 'Optional module: /showcase-bundle/ (256 MiB)' "$log"
    ! grep -q 'KERNEL PANIC' "$log"
}

# BusyBox is supplied by the core image.
run_program "core_probe" '/bin/busybox true'
grep -q '\[mem\] exit tid=1 code=0' "$tmp_dir/core_probe.log"

# DOOM is supplied by the combined showcase image. The regular game tests
# cover execution beyond DOS/4GW startup.
run_program "showcase_program" '/GAMES/DOOMS/DOOM.EXE'
grep -q 'Starting /GAMES/DOOMS/DOOM.EXE' "$tmp_dir/showcase_program.log"

echo "PASS: Multiboot USB image executed core and showcase programs"
