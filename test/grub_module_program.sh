#!/usr/bin/env bash
# Run representative DOS programs from the real GRUB Multiboot ISO.
#
# This is intentionally small: the existing hosted and raw-disk tests already
# cover the device and program matrices.  This test only verifies that the
# actual ISO supplies the base and games modules to the normal DOS path.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

bazelisk build //:grub_module_iso >/dev/null

run_program() {
    local name="$1" command="$2" log="$tmp_dir/$1.log"
    echo "=== $name ==="

    timeout 35s qemu-system-i386 \
        -m 512 -cpu pentium3 \
        -cdrom bazel-bin/retroos_grub_module.iso \
        -boot order=d \
        -fw_cfg "name=opt/cmdline,string=$command" \
        -debugcon "file:$log" \
        -display none -no-reboot >/dev/null 2>&1 || true

    grep -q 'Multiboot ext4 (32 MB, volatile overlay) → /$' "$log"
    grep -q 'Multiboot ext4 (96 MB, volatile overlay) → /home/retroos/GAMES$' "$log"
    ! grep -q 'KERNEL PANIC' "$log"
}

# SBTEST.COM is in the base module and exercises command execution after the
# Multiboot root has been installed.
run_program "base_probe" 'TESTS/SBTEST.COM'
grep -q 'BUSY-OK' "$tmp_dir/base_probe.log"
grep -q 'EDGE-OK' "$tmp_dir/base_probe.log"
grep -q 'TC-OK' "$tmp_dir/base_probe.log"

# DOOM.EXE is in the separate games module.  Reaching its DOS/4GW startup is
# sufficient here; the hosted and raw-image tests cover the deeper game test.
run_program "games_program" 'GAMES/DOOMS/DOOM.EXE'
grep -q 'Starting GAMES/DOOMS/DOOM.EXE' "$tmp_dir/games_program.log"

echo "PASS: Multiboot ISO executed base and games-module programs"
