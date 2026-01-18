#!/bin/bash
# Find image in runfiles or use argument
if [[ -n "$1" && -f "$RUNFILES_DIR/_main/$1" ]]; then
    IMAGE="$RUNFILES_DIR/_main/$1"
elif [[ -n "$1" && -f "$1" ]]; then
    IMAGE="$1"
else
    IMAGE="${RUNFILES_DIR:-$0.runfiles}/_main/image.bin"
fi
shift 2>/dev/null || true

# Copy to temp since Bazel files are read-only and QEMU may need write access
TEMP_IMAGE=$(mktemp)
cp "$IMAGE" "$TEMP_IMAGE"
trap "rm -f $TEMP_IMAGE" EXIT

exec qemu-system-i386 \
    -drive "file=$TEMP_IMAGE,format=raw" \
    -debugcon stdio \
    -no-reboot \
    "$@"
