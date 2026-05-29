#!/bin/bash
# Run RetroOS in Bochs.
#
# This follows the same image-selection/build flow as run_qemu.sh, but
# uses a local bochsrc + VM directory instead of QEMU flags. Bochs' Unix
# serial plumbing is not a drop-in replacement for QEMU hostfs, so this
# launcher focuses on booting the selected image with sound + VGA enabled.
#
# Usage: ./run_bochs.sh [386|686|x64] [-i image|proprietary|ext4] [extra bochs args...]

set -e
set -o pipefail

ARCH="${1:-386}"
shift 2>/dev/null || true

IMG="proprietary"
while [ $# -gt 0 ]; do
    case "$1" in
        -i) IMG="$2"; shift 2 ;;
        *)  break ;;
    esac
done

case "$ARCH" in
    386|686|x64) ;;
    *) echo "Usage: $0 [386|686|x64] [-i image|proprietary|ext4] [extra bochs args...]"; exit 1 ;;
esac

# Bochs has no 386/486 CPU model in the Ubuntu 24.04 package. Use a non-PAE
# Pentium by default so the kernel takes its legacy paging path; Bochs exposes
# a current PAE setup bug at CR0.PG enable with PAE-capable models.
BOCHS_CPU_MODEL="${BOCHS_CPU_MODEL:-pentium}"
BOCHS_IPS="${BOCHS_IPS:-50000000}"
# Clock pacing. Default `none` runs the interpreter flat-out (fastest) with
# guest time derived from `ips` instead of throttling to wall-clock — handy
# since Bochs is slow. Set BOCHS_SYNC=realtime for faithful timing (game
# speed / music tempo), or `slowdown` to only brake when ahead.
BOCHS_SYNC="${BOCHS_SYNC:-none}"

case "$IMG" in
    image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
    proprietary) BAZEL_TARGET="//:image_proprietary"; IMAGE_FILE="image_proprietary.bin" ;;
    ext4)        BAZEL_TARGET="//:image_ext4";        IMAGE_FILE="image_ext4.bin" ;;
    *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4)"; exit 1 ;;
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
    if command -v bazel >/dev/null 2>&1; then
        command -v bazel
        return
    fi
    echo "Could not find bazelisk or bazel" >&2
    exit 1
}

find_bochs() {
    if [ -n "${BOCHS_BIN:-}" ] && [ -x "$BOCHS_BIN" ]; then
        printf '%s\n' "$BOCHS_BIN"
        return
    fi
    for cand in \
        "$HOME/bin/bochs" \
        "$HOME/bin/Bochs" \
        /usr/bin/bochs \
        /usr/local/bin/bochs; do
        if [ -x "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    if command -v bochs >/dev/null 2>&1; then
        command -v bochs
        return
    fi
    echo "Could not find bochs. Set BOCHS_BIN or install bochs." >&2
    exit 1
}

find_bochs_bios() {
    if [ -n "${BOCHS_BIOS:-}" ] && [ -f "$BOCHS_BIOS" ]; then
        printf '%s\n' "$BOCHS_BIOS"
        return
    fi
    if [ -n "${BOCHS_SHARE:-}" ] && [ -f "$BOCHS_SHARE/BIOS-bochs-legacy" ]; then
        printf '%s\n' "$BOCHS_SHARE/BIOS-bochs-legacy"
        return
    fi
    if [ -n "${BXSHARE:-}" ] && [ -f "$BXSHARE/BIOS-bochs-legacy" ]; then
        printf '%s\n' "$BXSHARE/BIOS-bochs-legacy"
        return
    fi
    for cand in \
        /usr/share/bochs/BIOS-bochs-legacy \
        /usr/share/bochs/BIOS-bochs-latest \
        /usr/share/bochs/BIOS-qemu-latest \
        /usr/local/share/bochs/BIOS-bochs-latest \
        /usr/local/share/bochs/BIOS-bochs-legacy; do
        if [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    echo "Could not find Bochs BIOS image. Install bochsbios or set BOCHS_BIOS." >&2
    exit 1
}

find_bochs_vga_rom() {
    if [ -n "${BOCHS_VGA_ROM:-}" ] && [ -f "$BOCHS_VGA_ROM" ]; then
        printf '%s\n' "$BOCHS_VGA_ROM"
        return
    fi
    if [ -n "${BOCHS_SHARE:-}" ] && [ -f "$BOCHS_SHARE/VGABIOS-lgpl-latest.bin" ]; then
        printf '%s\n' "$BOCHS_SHARE/VGABIOS-lgpl-latest.bin"
        return
    fi
    if [ -n "${BXSHARE:-}" ] && [ -f "$BXSHARE/VGABIOS-lgpl-latest.bin" ]; then
        printf '%s\n' "$BXSHARE/VGABIOS-lgpl-latest.bin"
        return
    fi
    for cand in \
        /usr/share/bochs/VGABIOS-lgpl-latest.bin \
        /usr/share/vgabios/vgabios-stdvga.bin \
        /usr/share/vgabios/vgabios.bin \
        /usr/share/seabios/vgabios-stdvga.bin \
        /usr/share/seabios/vgabios-bochs-display.bin \
        /usr/local/share/bochs/VGABIOS-lgpl-latest.bin \
        /usr/local/share/vgabios/vgabios-stdvga.bin \
        /usr/local/share/vgabios/vgabios.bin; do
        if [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    echo "Could not find Bochs VGA ROM image. Install vgabios or set BOCHS_VGA_ROM." >&2
    exit 1
}

"$(find_bazel)" build "$BAZEL_TARGET" 2>&1 | tail -3

BOCHS_BIN="$(find_bochs)"
BOCHS_BIOS="$(find_bochs_bios)"
BOCHS_VGA_ROM="$(find_bochs_vga_rom)"

# Persistent VM state. Keep the disk image materialized in this directory so
# Bochs can open it without needing any symlink/sandbox magic.
if [ -z "${VM_DIR:-}" ]; then
    : "${VM_DIR:=${HOME}/.local/share/Bochs/RetroOS}"
fi
mkdir -p "$VM_DIR"
rm -f "${VM_DIR}/disk.img"
cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"
chmod u+rw "${VM_DIR}/disk.img"

BOCHSRC="${VM_DIR}/bochsrc.txt"
cat > "$BOCHSRC" <<EOF
#
# Exact geometry for the RetroOS raw image, rewritten for Bochs' CHS limits:
# 8448 cylinders * 16 heads * 16 sectors * 512 bytes = 1,107,296,256 bytes.
#
# Prefer BIOS-bochs-legacy for this launcher. On Ubuntu 24.04, BIOS-bochs-latest
# triple-faults inside rombios32 before it reaches the boot sector.
megs: 64
cpu: model="$BOCHS_CPU_MODEL", count=1, ips="$BOCHS_IPS", reset_on_triple_fault=1
# RetroOS debug console (dbg_println, the [prof] profiler, the DOS console
# mirror) writes to port 0xE9 - the same debugcon QEMU captures by default.
# Bochs only echoes 0xE9 when this hack is enabled; output goes to Bochs
# stdout (capture by teeing this script). Without it the kernel trace is lost.
port_e9_hack: enabled=1
romimage: file="$BOCHS_BIOS"
vgaromimage: file="$BOCHS_VGA_ROM"
boot: disk
clock: sync=$BOCHS_SYNC, time0=local
mouse: enabled=1, type=ps2
speaker: enabled=1, mode=sound
sb16: wavemode=1, midimode=0, dmatimer=750000, log="$VM_DIR/sb16.log", loglevel=2
ata0-master: type=disk, path="$VM_DIR/disk.img", mode=flat, cylinders=8448, heads=16, spt=16, biosdetect=auto, translation=lba
log: "$VM_DIR/bochs.log"
com1: enabled=1, mode=file, dev="$VM_DIR/serial.out"
EOF
echo "Wrote Bochs config to $BOCHSRC"

BOCHS_ARGS=(-q -f "$BOCHSRC" -unlock)
if [ "${BOCHS_DEBUG:-0}" != "1" ]; then
    BOCHS_RC="${VM_DIR}/bochs.rc"
    printf 'c\n' > "$BOCHS_RC"
    BOCHS_ARGS=(-q -rc "$BOCHS_RC" -f "$BOCHSRC" -unlock)
fi

if [ -n "${BOCHS_DISPLAY_LIBRARY:-}" ]; then
    exec env -i \
        PATH="/usr/bin:/bin:/usr/local/bin" \
        HOME="$HOME" \
        DISPLAY="${DISPLAY:-}" \
        TERM="${TERM:-xterm-256color}" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
        DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
        "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "$@" "display_library: ${BOCHS_DISPLAY_LIBRARY}"
fi

exec env -i \
    PATH="/usr/bin:/bin:/usr/local/bin" \
    HOME="$HOME" \
    DISPLAY="${DISPLAY:-}" \
    TERM="${TERM:-xterm-256color}" \
    XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
    "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "$@"
