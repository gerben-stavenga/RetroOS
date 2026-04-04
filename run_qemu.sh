#!/bin/bash
# Run RetroOS in QEMU with debugcon output
# Usage: ./run_qemu.sh [386|686|x64] [extra qemu args...]

set -e
set -o pipefail

ARCH="${1:-386}"
shift 2>/dev/null || true
IMG="${1:-proprietary}"
shift 2>/dev/null || true

case "$ARCH" in
    386)  QEMU=qemu-system-i386;   CPU="-cpu 486" ;;
    686)  QEMU=qemu-system-i386;   CPU="" ;;
    x64)  QEMU=qemu-system-x86_64; CPU="" ;;
    *)    echo "Usage: $0 [386|686|x64] [image|proprietary|ext4] [extra qemu args...]"; exit 1 ;;
esac

case "$IMG" in
    image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
    proprietary) BAZEL_TARGET="//:image_proprietary";  IMAGE_FILE="image_proprietary.bin" ;;
    ext4)        BAZEL_TARGET="//:image_ext4";          IMAGE_FILE="image_ext4.bin" ;;
    grub)        BAZEL_TARGET="//:grub_iso //:image_ext4" ;;
    *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4, grub)"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

find_bazel() {
    if command -v bazelisk >/dev/null 2>&1; then
        command -v bazelisk
        return
    fi
    if [ -x "$HOME/bin/bazelisk" ]; then
        printf '%s\n' "$HOME/bin/bazelisk"
        return
    fi
    if [ -x "/home/gerben/bin/bazelisk" ]; then
        printf '%s\n' "/home/gerben/bin/bazelisk"
        return
    fi
    if command -v bazel >/dev/null 2>&1; then
        command -v bazel
        return
    fi
    echo "Could not find bazelisk or bazel" >&2
    exit 1
}

# Build selected image(s)
"$(find_bazel)" build $BAZEL_TARGET 2>&1 | tail -3

if [ "$IMG" = "grub" ]; then
    ISO="$SCRIPT_DIR/bazel-bin/retroos_grub.iso"
    DISK="$SCRIPT_DIR/bazel-bin/image_ext4.bin"
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        $QEMU \
        $CPU \
        -cdrom "$ISO" \
        -drive "file=$DISK,format=raw,snapshot=on" \
        -boot order=d \
        -debugcon stdio \
        -no-reboot \
        "$@"
else
    IMAGE="$SCRIPT_DIR/bazel-bin/$IMAGE_FILE"
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        $QEMU \
        $CPU \
        -drive "file=$IMAGE,format=raw,snapshot=on" \
        -debugcon stdio \
        -no-reboot \
        "$@"
fi
