#!/bin/bash
# Run RetroOS in 86box (PCem-derived, period-accurate PC emulator).
# Use this for testing DOS games where QEMU's VGA emulation falls
# short — EGA hardware-scroll, cycle-accurate timing, etc.
#
# Setup (one-time):
#   1. Download AppImage from https://github.com/86Box/86Box/releases
#      and place at $HOME/bin/86Box.AppImage (or override via $BOX86).
#   2. Get the ROM set:
#        git clone https://github.com/86Box/roms ~/.local/share/86Box/roms
#   3. Launch 86box once, click Settings, configure a 386/486 machine
#      with VGA + IDE HDD pointing at "$VM_DIR/disk.img" (the symlink
#      this script keeps fresh).
#   4. Save. The config lands in $VM_DIR/86box.cfg.
#
# Usage:  ./run_86box.sh [extra 86box args...]
#
# Notes:
#   - 86box doesn't have QEMU's -debugcon stdio; redirect COM1 to a
#     host serial in the GUI (Settings → Ports) if you need debug log.
#   - Default image is image_proprietary; override with -i image to
#     use the open-source image.

set -e
set -o pipefail

IMG="proprietary"
while [ $# -gt 0 ]; do
    case "$1" in
        -i) IMG="$2"; shift 2 ;;
        *)  break ;;
    esac
done

case "$IMG" in
    image)        BAZEL_TARGET="//:image";              IMAGE_FILE="image.bin" ;;
    proprietary)  BAZEL_TARGET="//:image_proprietary";  IMAGE_FILE="image_proprietary.bin" ;;
    ext4)         BAZEL_TARGET="//:image_ext4";         IMAGE_FILE="image_ext4.bin" ;;
    *)            echo "Unknown image type: $IMG (image | proprietary | ext4)"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

find_bazel() {
    if command -v bazelisk >/dev/null 2>&1; then command -v bazelisk; return; fi
    if [ -x "$HOME/bin/bazelisk" ]; then printf '%s\n' "$HOME/bin/bazelisk"; return; fi
    if command -v bazel >/dev/null 2>&1; then command -v bazel; return; fi
    echo "Could not find bazelisk or bazel" >&2
    exit 1
}

"$(find_bazel)" build "$BAZEL_TARGET" 2>&1 | tail -3

# Resolve the VM data dir. Flatpak puts it under ~/.var/app/<id>/data/86Box;
# native install puts it under ~/.local/share/86Box. Pick whichever exists
# (or default to native) — user can override via $VM_DIR.
if [ -z "${VM_DIR:-}" ]; then
    if command -v flatpak >/dev/null 2>&1; then
        FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
        if [ -n "$FLATPAK_ID" ]; then
            VM_DIR="${HOME}/.var/app/${FLATPAK_ID}/data/86Box/RetroOS"
        fi
    fi
    : "${VM_DIR:=${HOME}/.local/share/86Box/RetroOS}"
fi

mkdir -p "$VM_DIR"
# Copy (not symlink) the bazel-built image into the VM dir. Flatpak's
# sandbox blocks following symlinks to ~/.cache/bazel without explicit
# --filesystem grants, so be safe by materializing the image inside
# the VM dir 86box can read directly. The image is sparse so the copy
# is fast even at 1 GiB. rm first in case an earlier script run left
# a symlink — cp would refuse with "same file" since it'd dereference.
rm -f "${VM_DIR}/disk.img"
cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"

# Drop a working config template the first time around so we don't
# have to walk the user through Settings → Hard disks. Period choice:
# 486DX2-66 + 16 MiB + standard VGA + IDE, boot order = HDD first.
# Image geometry: 1 GiB = 63 sectors × 16 heads × 2080 cylinders.
# If a config exists but has no [Hard disks] section (because 86box's
# GUI rewrote it and dropped what we wrote), append the HDD entry so
# the next boot sees disk.img on the IDE controller.
if [ -f "${VM_DIR}/86box.cfg" ] && ! grep -q '^\[Hard disks\]' "${VM_DIR}/86box.cfg"; then
    cat >> "${VM_DIR}/86box.cfg" <<'EOF'

[Hard disks]
hdd_01_parameters = 63, 16, 2080, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0
EOF
    echo "Re-added [Hard disks] section to $VM_DIR/86box.cfg"
fi

if [ ! -f "${VM_DIR}/86box.cfg" ]; then
    cat > "${VM_DIR}/86box.cfg" <<'EOF'
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = ami486
cpu_family = i486dx2
cpu_speed = 66666666
fpu_type = built_in
mem_size = 16384
time_sync = local
pit_mode = -1
fpu_softfloat = 0

[Video]
gfxcard = vga

[Input devices]
mouse_type = ps2

[Sound]
sndcard = sbpro2

[Network]
net_card = none

[Ports (COM & LPT)]
serial1_enabled = 1
serial1_passthrough_enabled = 0
serial2_enabled = 0
lpt1_device = none

[Storage controllers]
hdc = ide_isa
fdc_type = internal

[Hard disks]
hdd_01_parameters = 63, 16, 2080, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0

[Floppy and CD-ROM drives]
fdd_01_type = none
fdd_02_type = none
EOF
    echo "Created default 86box config at $VM_DIR/86box.cfg"
fi

# Find 86box: explicit $BOX86 overrides; else try AppImage at $HOME/bin;
# else any installed flatpak whose app id contains "86box"; else `86box`
# in PATH (native package).
if [ -n "${BOX86:-}" ]; then
    exec "$BOX86" --vmpath "$VM_DIR" "$@"
fi
if [ -x "$HOME/bin/86Box.AppImage" ]; then
    exec "$HOME/bin/86Box.AppImage" --vmpath "$VM_DIR" "$@"
fi
if command -v flatpak >/dev/null 2>&1; then
    FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
    if [ -n "$FLATPAK_ID" ]; then
        # VM dir holds disk.img (real file, not symlink) so default
        # flatpak filesystem perms are enough.
        exec flatpak run "$FLATPAK_ID" --vmpath "$VM_DIR" "$@"
    fi
fi
if command -v 86box >/dev/null 2>&1; then
    exec 86box --vmpath "$VM_DIR" "$@"
fi

echo "86box binary not found." >&2
echo "Tried: \$BOX86, \$HOME/bin/86Box.AppImage, any installed flatpak (containing \"86box\"), 86box in PATH." >&2
echo "Either install the AppImage from https://github.com/86Box/86Box/releases" >&2
echo "or install via flatpak (search: flatpak search 86box)." >&2
exit 1
