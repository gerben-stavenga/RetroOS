#!/bin/bash
# Verify a module root takes precedence while a physical ext4 disk is exposed
# read-only below /disk1.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp_dir=$(mktemp -d)
log=$(mktemp)
trap 'rm -rf "$tmp_dir"; rm -f "$log"' EXIT
bazelisk build //:root_module_base_gzip //kernel:kernel_elf //:image >/dev/null
mkdir -p "$tmp_dir/iso/boot/grub"
cp bazel-bin/retroos-base.img.gz "$tmp_dir/iso/boot/retroos-base.img.gz"
cp bazel-bin/kernel/kernel.elf "$tmp_dir/iso/boot/kernel.elf"
printf '%s\n' \
    'set timeout=0' \
    'set default=0' \
    'menuentry "RetroOS base module" {' \
    '    terminal_output console' \
    '    insmod multiboot' \
    '    insmod gzio' \
    '    multiboot /boot/kernel.elf' \
    '    module /boot/retroos-base.img.gz retroos.mount=/' \
    '    boot' \
    '}' > "$tmp_dir/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$tmp_dir/module.iso" "$tmp_dir/iso" >/dev/null
# The boot probe may remain in its shell after reporting success; always reap
# QEMU even if it does not exit promptly after the timeout signal.
timeout --kill-after=5s 18s qemu-system-i386 \
    -m 512 -cpu pentium3 \
    -cdrom "$tmp_dir/module.iso" \
    -drive file=bazel-bin/image.bin,format=raw,snapshot=on \
    -boot order=d -debugcon "file:$log" -display none -no-reboot >/dev/null 2>&1 || true

grep -q 'Multiboot ext4 (32 MB, volatile overlay) → /$' "$log"
grep -q 'ext4 partition (1024 MB) → /disk1$' "$log"
! grep -q 'ext4 root (' "$log"
echo "PASS: module root wins and physical ext4 is /disk1 fallback"
