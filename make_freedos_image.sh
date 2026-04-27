#!/bin/bash
# Build a FAT16 data disk with proprietary apps for use with FreeDOS.
# Requires: mtools
#
# Setup (one-time):
#   Download FreeDOS LiveCD from https://www.freedos.org/download/
#   Place the .img or .iso as apps/freedos/FD13LIVE.img
#
# Usage: ./make_freedos_image.sh
# Run:   ./run_qemu.sh 386 freedos

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

APPS_DIR="$SCRIPT_DIR/apps-proprietary"
OUTPUT="$SCRIPT_DIR/freedos_apps.img"
IMG_SIZE=256  # MiB

echo "Creating ${IMG_SIZE}MB FAT16 data disk..."
dd if=/dev/zero of="$OUTPUT" bs=1M count=$IMG_SIZE status=none

# No partition table — just a bare FAT16 filesystem (superfloppy)
mformat -i "$OUTPUT" -c 8 -h 16 -s 63 -T $((IMG_SIZE * 2048)) ::

# Copy proprietary apps
echo "Copying proprietary apps..."
copy_dir() {
    local src="$1" dst="$2" img="$3"
    mmd -D s -i "$img" "::$dst" 2>/dev/null || true
    find "$src" -maxdepth 1 -type f | while read -r f; do
        mcopy -D o -i "$img" "$f" "::$dst/$(basename "$f" | tr '[:lower:]' '[:upper:]')" 2>/dev/null || true
    done
    find "$src" -maxdepth 1 -type d -not -path "$src" | while read -r d; do
        copy_dir "$d" "$dst/$(basename "$d" | tr '[:lower:]' '[:upper:]')" "$img"
    done
}

# Copy regular apps (skip non-DOS dirs like freedos, linux_test, hello64_linux, etc.)
SKIP_DIRS="freedos|hello64|hello64_linux|linux_test|stress64|gfx_com"
echo "Copying apps..."
for d in "$SCRIPT_DIR/apps"/*/; do
    [ -d "$d" ] || continue
    dname=$(basename "$d")
    echo "$dname" | grep -qE "^($SKIP_DIRS)$" && continue
    UPPER=$(echo "$dname" | tr '[:lower:]' '[:upper:]')
    echo "  $UPPER"
    copy_dir "$d" "$UPPER" "$OUTPUT"
done

# Overlay proprietary apps (overwrite if same name)
for d in "$APPS_DIR"/*/; do
    [ -d "$d" ] || continue
    dname=$(basename "$d" | tr '[:lower:]' '[:upper:]')
    echo "  $dname (proprietary)"
    copy_dir "$d" "$dname" "$OUTPUT"
done

# Overlay freedos-only files (CWSDPMI.EXE for Quake/Doom on plain DOS, etc.)
FREEDOS_DIR="$SCRIPT_DIR/freedos"
if [ -d "$FREEDOS_DIR" ]; then
    for d in "$FREEDOS_DIR"/*/; do
        [ -d "$d" ] || continue
        dname=$(basename "$d" | tr '[:lower:]' '[:upper:]')
        # Skip the FreeDOS-system stuff (FD14LIVE.iso, freedos_hdd.img live
        # at the FREEDOS_DIR top level, not in a subdir, so they're not hit
        # here anyway). Subdirs are app overlays.
        echo "  $dname (freedos-only overlay)"
        copy_dir "$d" "$dname" "$OUTPUT"
    done
fi

echo ""
echo "Done: $OUTPUT (${IMG_SIZE}MB)"
echo ""
echo "To run, place FreeDOS image at freedos/FD14LIVE.iso then:"
echo "  ./run_qemu.sh 386 -i freedos"
echo ""
echo "Apps will be on D:\\"
