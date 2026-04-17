#!/bin/bash
# Run RetroOS in QEMU with debugcon output
# Usage: ./run_qemu.sh [386|686|x64] [extra qemu args...]

set -e
set -o pipefail

ARCH="${1:-386}"
shift 2>/dev/null || true
IMG="${1:-proprietary}"
shift 2>/dev/null || true
# Treat 3rd positional as HOSTFS_DIR only if present and not a flag.
HOSTFS_DIR=""
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    HOSTFS_DIR="$1"
    shift
fi

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
        $QEMU \
        $CPU \
        -cdrom "$ISO" \
        -drive "file=$DISK,format=raw,snapshot=on" \
        -boot order=d \
        -debugcon stdio \
        -no-reboot \
        "$@"
elif [ "$IMG" = "freedos" ]; then
    FDOS_DIR="$SCRIPT_DIR/apps/freedos"
    APPS_IMG="$SCRIPT_DIR/bazel-bin/freedos_apps.img"
    # Find FreeDOS boot media (ISO or IMG)
    FDOS_ISO=""; FDOS_HDD=""
    for f in "$FDOS_DIR"/FD*.iso "$FDOS_DIR"/FD*.ISO; do
        [ -f "$f" ] && FDOS_ISO="$f" && break
    done
    for f in "$FDOS_DIR"/FD*.img "$FDOS_DIR"/FD*.IMG; do
        [ -f "$f" ] && FDOS_HDD="$f" && break
    done
    if [ -z "$FDOS_ISO" ] && [ -z "$FDOS_HDD" ]; then
        echo "No FreeDOS image found in $FDOS_DIR/"
        echo "Download from https://www.freedos.org/download/ and place .iso or .img there."
        exit 1
    fi
    if [ ! -f "$APPS_IMG" ]; then
        echo "Apps disk not found. Bazel should have built it."
        exit 1
    fi
    HDD_IMG="$FDOS_DIR/freedos_hdd.img"
    FDOS_ARGS=""
    APPS_DRIVE=""
    FDOS_INSTALLED="$FDOS_DIR/.installed"
    if [ ! -f "$HDD_IMG" ]; then
        # First run: create HDD and boot from ISO to install
        echo "Creating 256MB FreeDOS hard disk..."
        qemu-img create -f raw "$HDD_IMG" 256M
        rm -f "$FDOS_INSTALLED"
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
        $QEMU \
        $CPU \
        -m 32 \
        -k en-us \
        -global i8042.kbd-throttle=on \
        -drive "file=$HDD_IMG,format=raw" \
        $APPS_DRIVE \
        $FDOS_ARGS \
        -no-reboot \
        "$@"
else
    IMAGE="$SCRIPT_DIR/bazel-bin/$IMAGE_FILE"
    HOSTFS_ARGS=""
    if [ -n "$HOSTFS_DIR" ]; then
        HOSTFS_SOCK="/tmp/retroos-hostfs.sock"
        HOSTFS_ARGS="-serial chardev:hostfs -chardev socket,id=hostfs,path=$HOSTFS_SOCK,server=on,wait=off"
        # Launch hostfs server in background, kill on exit
        "$SCRIPT_DIR/hostfs.py" "$HOSTFS_DIR" "$HOSTFS_SOCK" &
        HOSTFS_PID=$!
        trap "kill $HOSTFS_PID 2>/dev/null" EXIT
    fi
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        $QEMU \
        $CPU \
        -drive "file=$IMAGE,format=raw,snapshot=on" \
        -debugcon stdio \
        $HOSTFS_ARGS \
        -no-reboot \
        "$@"
fi
