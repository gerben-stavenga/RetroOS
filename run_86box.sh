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
# Usage:  ./run_86box.sh [-i image|proprietary|ext4|freedos] [extra 86box args...]
#
# Notes:
#   - 86box doesn't have QEMU's -debugcon stdio; redirect COM1 to a
#     host serial in the GUI (Settings → Ports) if you need debug log.
#   - Default image is image_proprietary; override with -i image to
#     use the open-source image.
#   - `-i freedos` boots the shared persistent FreeDOS install (the same
#     freedos/freedos_hdd.img run_qemu.sh / run_bochs.sh use) with the apps
#     disk as D:, as a closer-to-hardware DOS reference. Install it first via
#     ./run_qemu.sh -i freedos (that path runs the ISO installer); 86box
#     just boots the result.

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
    freedos)      BAZEL_TARGET="//:freedos_apps" ;;
    *)            echo "Unknown image type: $IMG (image | proprietary | ext4 | freedos)"; exit 1 ;;
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

# Emit a BIOS-friendly "spt, heads, cyl" CHS for a raw disk image: 63 spt ×
# 16 heads, cylinders sized to cover the file. < 1024 cyl needs no BIOS
# translation; matches the geometry run_bochs.sh/run_qemu.sh use for FreeDOS.
geom_for() {
    local sectors=$(( $(stat -c%s "$1") / 512 ))
    echo "63, 16, $(( sectors / (63 * 16) ))"
}

"$(find_bazel)" build "$BAZEL_TARGET" 2>&1 | tail -3

# Resolve the VM data dir. Flatpak puts it under ~/.var/app/<id>/data/86Box;
# native install puts it under ~/.local/share/86Box. Pick whichever exists
# (or default to native) — user can override via $VM_DIR. FreeDOS uses its
# own VM dir so its config doesn't clash with the RetroOS one.
VM_NAME="RetroOS"
[ "$IMG" = "freedos" ] && VM_NAME="RetroOS-FreeDOS"
if [ -z "${VM_DIR:-}" ]; then
    if command -v flatpak >/dev/null 2>&1; then
        FLATPAK_ID=$(flatpak list --app --columns=application 2>/dev/null | grep -i 86box | head -1)
        if [ -n "$FLATPAK_ID" ]; then
            VM_DIR="${HOME}/.var/app/${FLATPAK_ID}/data/86Box/${VM_NAME}"
        fi
    fi
    : "${VM_DIR:=${HOME}/.local/share/86Box/${VM_NAME}}"
fi

mkdir -p "$VM_DIR"
FS_GRANT=""

if [ "$IMG" = "freedos" ]; then
    # ---- FreeDOS reference mode ----
    # Boot the shared persistent FreeDOS HDD (same file run_qemu.sh /
    # run_bochs.sh use) with the apps disk as D:. The HDD is used in place via
    # a flatpak --filesystem grant, so an install/config done by any launcher
    # persists across all three. Install it first with ./run_qemu.sh -i freedos
    # (that path runs the ISO installer); 86box just boots the result.
    FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"
    HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
    if [ ! -f "$HDD_IMG" ] || [ ! -f "$FDOS_DIR/.installed" ]; then
        echo "FreeDOS is not installed at $HDD_IMG." >&2
        echo "Install it first:  ./run_qemu.sh -i freedos   (runs the installer)" >&2
        echo "then re-run:       ./run_86box.sh -i freedos" >&2
        exit 1
    fi
    chmod u+rw "$HDD_IMG"
    HDD_GEOM="$(geom_for "$HDD_IMG")"
    # 86box (flatpak) can't reach the project dir by default — grant it so the
    # persistent HDD path resolves inside the sandbox.
    FS_GRANT="--filesystem=$FDOS_DIR"

    # Apps disk (//:freedos_apps): copy into the VM dir as a real file — the
    # flatpak sandbox can't follow the bazel-bin symlink into ~/.cache.
    APPS_LINE=""
    APPS_SRC=""
    for cand in "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_apps.img" \
                "$SCRIPT_DIR/freedos_proprietary.img"; do
        [ -f "$cand" ] && APPS_SRC="$cand" && break
    done
    if [ -n "$APPS_SRC" ]; then
        rm -f "$VM_DIR/apps.img"
        cp --reflink=auto "$APPS_SRC" "$VM_DIR/apps.img"
        chmod u+rw "$VM_DIR/apps.img"
        APPS_LINE="hdd_02_fn = apps.img
hdd_02_ide_channel = 0:1
hdd_02_parameters = $(geom_for "$VM_DIR/apps.img"), 0, ide"
        echo "Apps disk on D: $APPS_SRC"
    else
        echo "(no apps disk found; D: not mounted — build //:freedos_apps)"
    fi

    # Regenerated each run (paths/geometry are derived, not user-owned).
    cat > "$VM_DIR/86box.cfg" <<EOF
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = tx97
cpu_family = pentium_p54c
cpu_speed = 166666666
cpu_multi = 2.5
cpu_use_dynarec = 1
fpu_type = internal
mem_size = 32768
time_sync = local
pit_mode = -1
fpu_softfloat = 0

[Video]
gfxcard = vga

[Input devices]
keyboard_type = keyboard_ps2
mouse_type = ps2

[Sound]
sndcard = sb16
fm_driver = nuked

[Network]
net_card = none

[Ports (COM & LPT)]
serial1_enabled = 1
serial2_enabled = 0
lpt1_device = none

[Storage controllers]
hdc = internal
fdc_type = internal

[Hard disks]
hdd_01_fn = $HDD_IMG
hdd_01_ide_channel = 0:0
hdd_01_parameters = $HDD_GEOM, 0, ide
$APPS_LINE

[Floppy and CD-ROM drives]
fdd_01_type = 35_2hd
fdd_02_type = none
EOF
    echo "Wrote FreeDOS 86box config to $VM_DIR/86box.cfg"
else

# Copy (not symlink) the bazel-built image into the VM dir. Flatpak's
# sandbox blocks following symlinks to ~/.cache/bazel without explicit
# --filesystem grants, so be safe by materializing the image inside
# the VM dir 86box can read directly. The image is sparse so the copy
# is fast even at 1 GiB. rm first in case an earlier script run left
# a symlink — cp would refuse with "same file" since it'd dereference.
rm -f "${VM_DIR}/disk.img"
cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"
# Bazel outputs are read-only; 86box opens the HDD image read-write and will
# refuse to attach a read-only file (BIOS then finds no boot disk and falls
# back to floppy). Make it writable, exactly as run_bochs.sh/run_qemu.sh do.
chmod u+rw "${VM_DIR}/disk.img"

# Drop a working config template the first time around so we don't
# have to walk the user through Settings → Hard disks. Period choice:
# Pentium-166 on an ASUS TX97 (430TX, 1997 Award BIOS) + 32 MiB + VGA +
# onboard IDE + Sound Blaster 16. Board choice is load-bearing: RetroOS's
# bootloader reads the disk ONLY via INT 13h AH=42 (LBA extensions, see
# boot/src/lib.rs read_disk), which 1995 boards (endeavor/430FX) lack, so
# they hang right after the POST device summary. The 1997 TX97 BIOS has
# INT 13h extensions, so the bootloader's self-load succeeds.
# Speed note: 86box has a recompiler (unlike Bochs, ~P75 ceiling) so this
# host holds a fast Pentium at real time; P166 is comfortable. If the
# status bar shows below 100% real time, drop cpu_speed/cpu_multi.
# Disk geometry 63 spt × 16 heads × 2145 cyl: a BIOS-friendly CHS that
# the AMI BIOS auto-detect can translate (the image's native 16×16×8448
# can't — 8448 cyl/16 heads needs 256 heads to map under 1024 cyl, which
# hangs POST at "Detecting IDE"). RetroOS boots via LBA so the exact CHS
# doesn't matter to it; this just covers the image (last ~264 KB zero-pad
# tail is unused — boot/kernel/TAR all live near the start).
# If a config exists but has no [Hard disks] section (because 86box's
# GUI rewrote it and dropped what we wrote), append the HDD entry so
# the next boot sees disk.img on the IDE controller.
if [ -f "${VM_DIR}/86box.cfg" ] && ! grep -q '^\[Hard disks\]' "${VM_DIR}/86box.cfg"; then
    cat >> "${VM_DIR}/86box.cfg" <<'EOF'

[Hard disks]
hdd_01_parameters = 63, 16, 2145, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0
EOF
    echo "Re-added [Hard disks] section to $VM_DIR/86box.cfg"
fi

# Same defensive re-add for the sound card: the 16-bit-DMA games
# (Duke3D/ROTT via the Apogee Sound System) need a real SB16, and 86box's
# GUI sometimes drops the [Sound] section on save, leaving the card silent.
if [ -f "${VM_DIR}/86box.cfg" ] && ! grep -q '^sndcard' "${VM_DIR}/86box.cfg"; then
    cat >> "${VM_DIR}/86box.cfg" <<'EOF'

[Sound]
sndcard = sb16
fm_driver = nuked
EOF
    echo "Re-added [Sound] sndcard=sb16 to $VM_DIR/86box.cfg"
fi

# A: must be a real (empty) 1.44M drive. With the FDC enabled but the drive
# set to 'none', the AMI BIOS halts at POST on "Floppy drive A: failure"
# before it reaches the HDD. The 86box GUI likes to reset this to 'none' on
# save, so force it back each launch.
if [ -f "${VM_DIR}/86box.cfg" ] && grep -q '^fdd_01_type = none' "${VM_DIR}/86box.cfg"; then
    sed -i 's/^fdd_01_type = none/fdd_01_type = 35_2hd/' "${VM_DIR}/86box.cfg"
    echo "Set floppy A: to 1.44M (was none) in $VM_DIR/86box.cfg"
fi

if [ ! -f "${VM_DIR}/86box.cfg" ]; then
    cat > "${VM_DIR}/86box.cfg" <<'EOF'
[General]
vid_renderer = qt_software
window_remember = 0
sound_gain = 0

[Machine]
machine = tx97
cpu_family = pentium_p54c
cpu_speed = 166666666
cpu_multi = 2.5
cpu_use_dynarec = 1
fpu_type = internal
mem_size = 32768
time_sync = local
pit_mode = -1
fpu_softfloat = 0

[Video]
gfxcard = vga

[Input devices]
mouse_type = ps2

[Sound]
sndcard = sb16
fm_driver = nuked

[Network]
net_card = none

[Ports (COM & LPT)]
serial1_enabled = 1
serial1_passthrough_enabled = 0
serial2_enabled = 0
lpt1_device = none

[Storage controllers]
hdc = internal
fdc_type = internal

[Hard disks]
hdd_01_parameters = 63, 16, 2145, 0, ide
hdd_01_fn = disk.img
hdd_01_ide_channel = 0:0

[Floppy and CD-ROM drives]
# A: must be a real (empty) 1.44M drive, not "none": with the FDC enabled
# but no drive, the AMI BIOS POST halts on "Floppy drive A: failure" before
# it reaches the HDD. Empty 1.44M passes the seek test and falls through to C:.
fdd_01_type = 35_2hd
fdd_02_type = none
EOF
    echo "Created default 86box config at $VM_DIR/86box.cfg"
fi
fi  # end image-vs-freedos setup

# 86box is a Qt app. The flatpak only shares the X11 socket (sockets=x11),
# not Wayland, so on a Wayland desktop Qt's default wayland plugin aborts
# with "Failed to create wl_display". Force XWayland (xcb) — DISPLAY +
# /tmp/.X11-unix are reachable through the x11 socket. Override by exporting
# QT_QPA_PLATFORM yourself (e.g. =wayland) before running.
: "${QT_QPA_PLATFORM:=xcb}"
export QT_QPA_PLATFORM

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
        # flatpak filesystem perms are enough. Pass the Qt platform into
        # the sandbox (host env doesn't cross the flatpak boundary).
        # $FS_GRANT is "--filesystem=<freedos dir>" in FreeDOS mode (the
        # persistent HDD lives outside the sandbox's data dir), empty otherwise.
        exec flatpak run --env=QT_QPA_PLATFORM="$QT_QPA_PLATFORM" $FS_GRANT \
            "$FLATPAK_ID" --vmpath "$VM_DIR" "$@"
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
