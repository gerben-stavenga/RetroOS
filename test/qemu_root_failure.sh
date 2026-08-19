#!/bin/bash
# Verify that boot without any root filesystem fails immediately.
# This is generic startup/root-selection policy, not HostFS protocol coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
source test/lib/qemu_common.sh

tmp_dir=$(mktemp -d -t retroos-qemu-hostfs-root.XXXXXX)
log="$tmp_dir/debugcon.log"
trap 'rm -rf "$tmp_dir"' EXIT

qemu_bazel build //kernel:kernel_elf >/dev/null
mkdir -p "$tmp_dir/iso/boot/grub"
cp bazel-bin/kernel/kernel.elf "$tmp_dir/iso/boot/kernel.elf"
printf '%s\n' \
    'set timeout=0' \
    'set default=0' \
    'menuentry "RetroOS kernel-only HostFS root probe" {' \
    '    terminal_output console' \
    '    insmod multiboot' \
    '    multiboot /boot/kernel.elf' \
    '    boot' \
    '}' > "$tmp_dir/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$tmp_dir/kernel-only.iso" "$tmp_dir/iso" >/dev/null

# No module or disk filesystem, and no hostfs= parameter: the kernel must fail
# immediately instead of falling back to an unavailable HostFS root.
# This probe intentionally expects the kernel to halt in its panic path;
# timeout termination is therefore an accepted result, unlike a QEMU crash.
qemu_status=0
timeout --kill-after=5s 20s qemu-system-i386 \
    -m 128M -cpu pentium3 \
    -cdrom "$tmp_dir/kernel-only.iso" \
    -boot order=d -serial null \
    -debugcon "file:$log" -display none -no-reboot >/dev/null 2>&1 || qemu_status=$?
case "$qemu_status" in
    124|137) ;;
    0) echo 'FAIL: kernel-only probe exited without timeout/panic status' >&2; exit 1 ;;
    *) echo "FAIL: QEMU exited with status $qemu_status" >&2; exit 1 ;;
esac

if ! grep -q 'No root filesystem available' "$log"; then
    echo 'FAIL: expected no-root panic was not observed' >&2
    tail -80 "$log" >&2 || true
    exit 1
fi
echo "PASS: boot without a root filesystem fails immediately"
