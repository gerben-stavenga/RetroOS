#!/bin/bash
# Run RetroOS in Bochs.
#
# This follows the same image-selection/build flow as run_qemu.sh, but
# uses a local bochsrc + VM directory instead of QEMU flags. Bochs' Unix
# serial plumbing is not a drop-in replacement for QEMU hostfs, so this
# launcher focuses on booting the selected image with sound + VGA enabled.
#
# Usage: ./run_bochs.sh [386|686|x64] [-i image|proprietary|ext4|freedos] [extra bochs args...]
#
# `-i freedos` boots a real FreeDOS install in Bochs (a closer-to-hardware
# reference for comparing DOS game behavior against RetroOS), mirroring
# run_qemu.sh's freedos mode: persistent HDD at freedos/freedos_hdd.img, the
# apps disk (//:freedos_apps) mounted as D:, and a first-run ISO install.

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
# Clock pacing. Default `realtime` ties guest time to the wall clock so games
# run at the right speed (animation pace, music tempo) instead of sprinting —
# guest timers (PIT/RTC) then fire at real-world rates. With `realtime` Bochs
# brakes whenever it runs ahead; if the host can't sustain BOCHS_IPS in real
# time the guest simply runs below full speed. Set BOCHS_SYNC=none to run the
# interpreter flat-out (fastest, but guest time races ahead of real time —
# games run too fast), or `slowdown` to cap at realtime without aligning.
BOCHS_SYNC="${BOCHS_SYNC:-realtime}"
# Host-window repaint rate (Hz). Bochs repaints the framebuffer on the
# *emulated* clock; the historic default is only a few Hz, which looks choppy.
# 60 Hz gives smooth video (paired with sync=realtime so the CPU doesn't
# outrun the redraw). Cheap for 320x200/640x480 modes.
BOCHS_VGA_UPDATE_FREQ="${BOCHS_VGA_UPDATE_FREQ:-60}"

case "$IMG" in
    image)       BAZEL_TARGET="//:image";             IMAGE_FILE="image.bin" ;;
    proprietary) BAZEL_TARGET="//:image_proprietary"; IMAGE_FILE="image_proprietary.bin" ;;
    ext4)        BAZEL_TARGET="//:image_ext4";        IMAGE_FILE="image_ext4.bin" ;;
    freedos)     BAZEL_TARGET="//:freedos_apps" ;;
    *)           echo "Unknown image type: $IMG (choose: image, proprietary, ext4, freedos)"; exit 1 ;;
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
BOCHSRC="${VM_DIR}/bochsrc.txt"

# Shared bochsrc preamble (host devices, CPU, sound, VGA) - identical for the
# RetroOS image and the FreeDOS reference; only the disk/boot lines differ.
#
# Prefer BIOS-bochs-legacy for this launcher. On Ubuntu 24.04, BIOS-bochs-latest
# triple-faults inside rombios32 before it reaches the boot sector.
bochsrc_preamble() {
    cat <<EOF
megs: 64
cpu: model="$BOCHS_CPU_MODEL", count=1, ips="$BOCHS_IPS", reset_on_triple_fault=1
# RetroOS debug console (dbg_println, the [prof] profiler, the DOS console
# mirror) writes to port 0xE9 - the same debugcon QEMU captures by default.
# Bochs only echoes 0xE9 when this hack is enabled; output goes to Bochs
# stdout (capture by teeing this script). Without it the kernel trace is lost.
port_e9_hack: enabled=1
romimage: file="$BOCHS_BIOS"
vgaromimage: file="$BOCHS_VGA_ROM"
# update_freq = host-window repaints/sec on the emulated clock. Default is a
# few Hz (choppy); 60 Hz gives smooth video. extension=vbe matches the Bochs
# VBE display interface (ports 0x1CE/0x1CF) the kernel programs.
vga: extension=vbe, update_freq=$BOCHS_VGA_UPDATE_FREQ
clock: sync=$BOCHS_SYNC, time0=local
mouse: enabled=1, type=ps2
speaker: enabled=1, mode=sound
sb16: wavemode=1, midimode=0, dmatimer=750000, log="$VM_DIR/sb16.log", loglevel=2
log: "$VM_DIR/bochs.log"
com1: enabled=1, mode=file, dev="$VM_DIR/serial.out"
EOF
}

if [ "$IMG" = "freedos" ]; then
    # ---- FreeDOS reference mode (mirrors run_qemu.sh's `-i freedos`) ----
    # Boot the persistent FreeDOS HDD; mount the apps disk as D: (ata0-slave).
    FDOS_DIR="${FDOS_DIR:-$SCRIPT_DIR/freedos}"

    # Install ISO (boot media for first-run install). Search FDOS_DIR, project
    # root, then ~/Downloads. Override with FDOS_ISO.
    if [ -z "${FDOS_ISO:-}" ]; then
        for d in "$FDOS_DIR" "$SCRIPT_DIR" "$HOME/Downloads"; do
            for f in "$d"/FD*.iso "$d"/FD*.ISO; do
                [ -f "$f" ] && FDOS_ISO="$f" && break 2
            done
        done
    fi

    # Persistent HDD (read-write, like run_qemu.sh - so an install/config sticks).
    HDD_IMG="${HDD_IMG:-$FDOS_DIR/freedos_hdd.img}"
    FDOS_INSTALLED="$FDOS_DIR/.installed"
    if [ ! -f "$HDD_IMG" ]; then
        echo "Creating 256MB FreeDOS hard disk at $HDD_IMG..."
        if command -v qemu-img >/dev/null 2>&1; then
            qemu-img create -f raw "$HDD_IMG" 256M >/dev/null
        else
            dd if=/dev/zero of="$HDD_IMG" bs=1M count=256 status=none
        fi
        rm -f "$FDOS_INSTALLED"
    elif [ ! -f "$FDOS_INSTALLED" ]; then
        # HDD pre-existed (copied-in ready-made install): trust it, skip installer.
        touch "$FDOS_INSTALLED"
    fi

    # Apps disk (built above as //:freedos_apps): bazel output first, then root.
    if [ -z "${APPS_IMG:-}" ]; then
        for cand in \
            "$SCRIPT_DIR/bazel-bin/freedos_apps.img" \
            "$SCRIPT_DIR/freedos_apps.img" \
            "$SCRIPT_DIR/freedos_proprietary.img"; do
            [ -f "$cand" ] && APPS_IMG="$cand" && break
        done
    fi

    # 256MB image -> 520 cyl x 16 heads x 63 spt (partition starts at sector 63).
    # Bochs needs explicit CHS for a flat image; LBA translation for the OS.
    FDOS_GEOM='mode=flat, cylinders=520, heads=16, spt=63, translation=lba'

    if [ ! -f "$FDOS_INSTALLED" ]; then
        # First run: boot the install ISO; the (empty) HDD is the target.
        [ -n "${FDOS_ISO:-}" ] || {
            echo "No FreeDOS ISO found (FD*.iso) in $FDOS_DIR/, $SCRIPT_DIR/, $HOME/Downloads/."
            echo "Download from https://www.freedos.org/download/ or set FDOS_ISO."
            exit 1
        }
        echo "Booting FreeDOS installer from $FDOS_ISO."
        echo "After install completes, run:  touch $FDOS_INSTALLED"
        { bochsrc_preamble
          echo "boot: cdrom"
          echo "ata0-master: type=disk, path=\"$HDD_IMG\", $FDOS_GEOM"
          echo "ata1-master: type=cdrom, path=\"$FDOS_ISO\", status=inserted"
        } > "$BOCHSRC"
    else
        # Installed: boot HDD; apps disk as D:, copied so a Bochs crash can't
        # corrupt the source (QEMU uses snapshot=on for the same reason).
        echo "Booting FreeDOS from $HDD_IMG (persistent)."
        APPS_LINE=""
        if [ -n "${APPS_IMG:-}" ] && [ -f "$APPS_IMG" ]; then
            cp --reflink=auto "$APPS_IMG" "$VM_DIR/apps.img"
            chmod u+rw "$VM_DIR/apps.img"
            APPS_LINE="ata0-slave: type=disk, path=\"$VM_DIR/apps.img\", $FDOS_GEOM"
            echo "Apps disk on D: $APPS_IMG"
        else
            echo "(no apps disk found; D: not mounted - build //:freedos_apps or set APPS_IMG)"
        fi
        { bochsrc_preamble
          echo "boot: disk"
          echo "ata0-master: type=disk, path=\"$HDD_IMG\", $FDOS_GEOM"
          [ -n "$APPS_LINE" ] && echo "$APPS_LINE"
        } > "$BOCHSRC"
    fi
else
    rm -f "${VM_DIR}/disk.img"
    cp --reflink=auto "${SCRIPT_DIR}/bazel-bin/${IMAGE_FILE}" "${VM_DIR}/disk.img"
    chmod u+rw "${VM_DIR}/disk.img"
    # Exact geometry for the RetroOS raw image, rewritten for Bochs' CHS limits:
    # 8448 cylinders * 16 heads * 16 sectors * 512 bytes = 1,107,296,256 bytes.
    { bochsrc_preamble
      echo "boot: disk"
      echo "ata0-master: type=disk, path=\"$VM_DIR/disk.img\", mode=flat, cylinders=8448, heads=16, spt=16, biosdetect=auto, translation=lba"
    } > "$BOCHSRC"
fi
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
