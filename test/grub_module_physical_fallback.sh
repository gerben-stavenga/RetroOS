#!/bin/bash
# Verify a module root takes precedence while a physical ext4 disk is exposed
# read-only below /disk1.
set -euo pipefail
cd "$(dirname "$0")/.."

bazelisk build //:grub_module_iso //:image >/dev/null
log=$(mktemp)
trap 'rm -f "$log"' EXIT
timeout 18s qemu-system-i386 \
    -m 512 -cpu pentium3 \
    -cdrom bazel-bin/retroos_grub_module.iso \
    -drive file=bazel-bin/image.bin,format=raw,snapshot=on \
    -boot order=d -debugcon "file:$log" -display none -no-reboot >/dev/null 2>&1 || true

grep -q 'Multiboot ext4 (32 MB, volatile overlay) → /$' "$log"
grep -q 'ext4 partition (1024 MB) → /disk1$' "$log"
! grep -q 'ext4 root (' "$log"
echo "PASS: module root wins and physical ext4 is /disk1 fallback"
