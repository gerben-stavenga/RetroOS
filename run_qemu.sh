#!/bin/bash
# Run RetroOS in QEMU with debugcon output
# Usage: ./run_qemu.sh [386|686|x64] [-i image] [-r binary] [-h hostfs_dir] [extra qemu args...]

set -e
set -o pipefail

ARCH="${1:-386}"
shift 2>/dev/null || true

# Default to the open-source image so fresh checkouts work out of the box.
# Pass `-i proprietary` to use the full image with proprietary binaries
# (requires apps-proprietary/ to be populated).
IMG="image"
START_BIN=""
HOSTFS_DIR="$HOME"

while [ $# -gt 0 ]; do
    case "$1" in
        -i) IMG="$2";        shift 2 ;;
        -r) START_BIN="$2";  shift 2 ;;
        -h) HOSTFS_DIR="$2"; shift 2 ;;
        *)  break ;;
    esac
done

case "$ARCH" in
    386)  QEMU=qemu-system-i386;   CPU="-cpu 486" ;;
    686)  QEMU=qemu-system-i386;   CPU="" ;;
    x64)  QEMU=qemu-system-x86_64; CPU="" ;;
    *)    echo "Usage: $0 [386|686|x64] [-i image] [-r binary] [-h hostfs_dir] [extra qemu args...]"; exit 1 ;;
esac

# AdLib (YM3812 / OPL2) on 0x388-0x389 for FM music passthrough; virtio-sound
# as the PCM sink for the upcoming Layer 1 / Layer 2 audio stack (kernel as DMA
# replacement, DOS SB façade above). Override backend with AUDIO_BACKEND=alsa|
# sdl|... if pulseaudio isn't available.
AUDIO_BACKEND="${AUDIO_BACKEND:-pa}"
AUDIO_ARGS=(
    -audiodev "${AUDIO_BACKEND},id=snd0"
    -device adlib,audiodev=snd0
    -device virtio-sound-pci,audiodev=snd0
)

case "$IMG" in
    image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
    proprietary) BAZEL_TARGET="//:image_proprietary";  IMAGE_FILE="image_proprietary.bin" ;;
    ext4)        BAZEL_TARGET="//:image_ext4";          IMAGE_FILE="image_ext4.bin" ;;
    grub)        BAZEL_TARGET="//:grub_iso //:image_ext4" ;;
    freedos)     BAZEL_TARGET="//:freedos_apps";        IMAGE_FILE="freedos_apps.img" ;;
    *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4, grub, freedos)"; exit 1 ;;
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
if [ -n "$BAZEL_TARGET" ]; then
    "$(find_bazel)" build $BAZEL_TARGET 2>&1 | tail -3
fi

if [ "$IMG" = "grub" ]; then
    ISO="$SCRIPT_DIR/bazel-bin/retroos_grub.iso"
    DISK="$SCRIPT_DIR/bazel-bin/image_ext4.bin"
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
        $QEMU \
        $CPU \
        -cdrom "$ISO" \
        -drive "file=$DISK,format=raw,snapshot=on" \
        -boot order=d \
        -debugcon stdio \
        "${AUDIO_ARGS[@]}" \
        -no-reboot \
        "$@"
elif [ "$IMG" = "freedos" ]; then
    # Look for FreeDOS install media + HDD + apps disk in a few candidate
    # locations. Override any of them with FDOS_DIR / FDOS_ISO / FDOS_HDD /
    # APPS_IMG env vars.
    FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"

    # FreeDOS install ISO/IMG (boot media). Search FDOS_DIR, then project
    # root, then ~/Downloads.
    if [ -z "${FDOS_ISO:-}" ]; then
        for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
            for f in "$d"/FD*.iso "$d"/FD*.ISO; do
                [ -f "$f" ] && FDOS_ISO="$f" && break 2
            done
        done
    fi
    FDOS_HDD="${FDOS_HDD:-}"
    if [ -z "$FDOS_HDD" ]; then
        for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
            for f in "$d"/FD*.img "$d"/FD*.IMG; do
                [ -f "$f" ] && FDOS_HDD="$f" && break 2
            done
        done
    fi
    if [ -z "$FDOS_ISO" ] && [ -z "$FDOS_HDD" ]; then
        echo "No FreeDOS install media found."
        echo "Looked in: $FDOS_DIR/, $SCRIPT_DIR/, $HOME/Downloads/"
        echo "Download from https://www.freedos.org/download/ and place .iso or .img there,"
        echo "or set FDOS_ISO / FDOS_HDD env var to its full path."
        exit 1
    fi

    # Apps disk: bazel-built first, then make_freedos_image.sh output at root.
    if [ -z "${APPS_IMG:-}" ]; then
        for cand in \
            "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
            "$SCRIPT_DIR/freedos_apps.img" \
            "$SCRIPT_DIR/freedos_proprietary.img"; do
            [ -f "$cand" ] && APPS_IMG="$cand" && break
        done
    fi
    if [ -z "${APPS_IMG:-}" ] || [ ! -f "$APPS_IMG" ]; then
        echo "Apps disk not found. Build with 'bazelisk build //:freedos_apps'"
        echo "or run ./make_freedos_image.sh, or set APPS_IMG=<path>."
        exit 1
    fi
    echo "Using apps disk: $APPS_IMG"

    # Persistent FreeDOS HDD lives next to the install media by default.
    HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
    FDOS_ARGS=""
    APPS_DRIVE=""
    FDOS_INSTALLED="$FDOS_DIR/.installed"
    if [ ! -f "$HDD_IMG" ]; then
        # First run: create HDD and boot from ISO to install
        echo "Creating 256MB FreeDOS hard disk..."
        qemu-img create -f raw "$HDD_IMG" 256M
        rm -f "$FDOS_INSTALLED"
    elif [ ! -f "$FDOS_INSTALLED" ]; then
        # HDD pre-existed (e.g. you copied in a ready-made install). Trust
        # it and skip the installer.
        touch "$FDOS_INSTALLED"
    fi
    if [ ! -f "$FDOS_INSTALLED" ]; then
        # Not yet installed: boot from ISO
        if [ -n "$FDOS_ISO" ]; then
            FDOS_ARGS="-cdrom $FDOS_ISO -boot order=d"
        elif [ -n "$FDOS_HDD" ]; then
            FDOS_ARGS="-drive file=$FDOS_HDD,format=raw,snapshot=on -boot order=b"
        fi
        echo "Booting FreeDOS installer. After install completes, run:"
        echo "  touch $FDOS_INSTALLED"
        echo "Then run this script again to boot from HDD."
    else
        # Installed: boot from HDD, attach apps as second drive
        APPS_DRIVE="-drive file=$APPS_IMG,format=raw,snapshot=on"
        echo "Booting FreeDOS from HDD. Apps on D:. Delete $HDD_IMG and $FDOS_INSTALLED to reinstall."
    fi
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
        $QEMU \
        $CPU \
        -debugcon stdio \
        -m 32 \
        -k en-us \
        -global i8042.kbd-throttle=on \
        -drive "file=$HDD_IMG,format=raw" \
        $APPS_DRIVE \
        $FDOS_ARGS \
        "${AUDIO_ARGS[@]}" \
        -no-reboot \
        "$@"
else
    IMAGE="$SCRIPT_DIR/bazel-bin/$IMAGE_FILE"
    FWCFG_ARGS=()
    FWCFG_TMPDIR=""
    if [ -n "$START_BIN" ]; then
        # Write the cmdline to a tempfile and use fw_cfg's file= form. The
        # string= form word-splits on commas, which collide with TLINK's
        # arg separator.
        FWCFG_TMPDIR=$(mktemp -d -t retroos-fwcfg.XXXXXX)
        printf '%s' "$START_BIN" > "$FWCFG_TMPDIR/cmdline"
        FWCFG_ARGS+=(-fw_cfg "name=opt/cmdline,file=$FWCFG_TMPDIR/cmdline")
        # When -h is also given, default cwd to host/ so relative paths in
        # the program's args resolve against the host workspace.
        if [ -n "$HOSTFS_DIR" ]; then
            FWCFG_ARGS+=(-fw_cfg "name=opt/cwd,string=host/")
        fi
    fi
    HOSTFS_ARGS=()
    if [ -n "$HOSTFS_DIR" ]; then
        HOSTFS_SOCK="/tmp/retroos-hostfs.sock"
        HOSTFS_ARGS=(
            -serial chardev:hostfs
            -chardev "socket,id=hostfs,path=$HOSTFS_SOCK,server=on,wait=off"
        )
        # Launch hostfs server in background, kill on exit
        "$SCRIPT_DIR/hostfs.py" "$HOSTFS_DIR" "$HOSTFS_SOCK" &
        HOSTFS_PID=$!
        trap "kill $HOSTFS_PID 2>/dev/null; [ -n \"$FWCFG_TMPDIR\" ] && rm -rf \"$FWCFG_TMPDIR\"" EXIT
    elif [ -n "$FWCFG_TMPDIR" ]; then
        trap "rm -rf $FWCFG_TMPDIR" EXIT
    fi
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
        $QEMU \
        $CPU \
        -drive "file=$IMAGE,format=raw,snapshot=on" \
        -debugcon stdio \
        "${FWCFG_ARGS[@]}" \
        "${HOSTFS_ARGS[@]}" \
        "${AUDIO_ARGS[@]}" \
        -no-reboot \
        "$@"
fi
