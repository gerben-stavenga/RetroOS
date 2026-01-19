#!/bin/bash
# Run RetroOS in QEMU with debugcon output

# Find the image relative to runfiles
RUNFILES="${BASH_SOURCE[0]}.runfiles"
if [[ -d "$RUNFILES" ]]; then
    IMAGE="$RUNFILES/_main/image.bin"
else
    # Fallback for direct execution
    IMAGE="$(dirname "$0")/image.bin"
fi

# Run with clean environment to avoid snap/glibc conflicts
exec env -i \
    PATH="/usr/bin:/bin:/usr/local/bin" \
    HOME="$HOME" \
    DISPLAY="${DISPLAY:-}" \
    XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    qemu-system-i386 \
    -drive "file=$IMAGE,format=raw,snapshot=on" \
    -debugcon stdio \
    -no-reboot \
    "$@"
