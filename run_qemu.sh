#!/bin/bash
# Run RetroOS in QEMU with debugcon output
# Usage: ./run_qemu.sh [386|686|x64] [extra qemu args...]

set -e
set -o pipefail

ARCH="${1:-386}"
shift 2>/dev/null || true

case "$ARCH" in
    386)  QEMU=qemu-system-i386;   CPU="-cpu 486" ;;
    686)  QEMU=qemu-system-i386;   CPU="" ;;
    x64)  QEMU=qemu-system-x86_64; CPU="" ;;
    *)    echo "Usage: $0 [386|686|x64] [extra qemu args...]"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build image
~/bin/bazelisk build //:image 2>&1 | tail -3

IMAGE="$SCRIPT_DIR/bazel-bin/image.bin"

# Run with clean environment to avoid snap/glibc conflicts
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
