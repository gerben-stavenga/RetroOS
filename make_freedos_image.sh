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
IMG_SIZE=1024  # MiB — matches the 1GB FAT16 RetroOS disk; apps total ~912MB
               # and silently overflowed the old 256MB image, dropping the
               # freedos/ overlays (CWSDPMI etc.).

echo "Creating ${IMG_SIZE}MB FAT16 data disk..."
dd if=/dev/zero of="$OUTPUT" bs=1M count=$IMG_SIZE status=none

# No partition table — just a bare FAT16 filesystem (superfloppy).
# -c 32 (16KB clusters) keeps 1GB under the FAT16 65525-cluster limit
# (-c 8 / 4KB clusters caps FAT16 at 256MB).
mformat -i "$OUTPUT" -c 32 -h 16 -s 63 -T $((IMG_SIZE * 2048)) ::

# Copy proprietary apps. No `|| true`: a failed copy (disk full, bad name)
# now aborts the build (set -e) instead of being silently dropped, which is
# how a half-empty image used to escape with a "Done" message. Process
# substitution (not `find | while`) keeps the loop in the main shell so set -e
# actually fires.
echo "Copying proprietary apps..."
copy_dir() {
    local src="$1" dst="$2" img="$3"
    # Create dst only if absent (dir-exists is the one benign case — apps/games
    # and apps-proprietary/games both map to ::GAMES); a real mmd failure aborts.
    mdir -i "$img" "::$dst" >/dev/null 2>&1 || mmd -i "$img" "::$dst"
    while IFS= read -r f; do
        mcopy -D o -i "$img" "$f" "::$dst/$(basename "$f" | tr '[:lower:]' '[:upper:]')"
    done < <(find "$src" -maxdepth 1 -type f)
    while IFS= read -r d; do
        copy_dir "$d" "$dst/$(basename "$d" | tr '[:lower:]' '[:upper:]')" "$img"
    done < <(find "$src" -maxdepth 1 -type d -not -path "$src")
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
