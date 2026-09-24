#!/usr/bin/env bash
# One disposable boot image and one persistent data image, for every backend.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat <<'HELP'
Usage: ./run.sh [qemu|bochs|86box|hosted] [options] [-- emulator arguments]
  --data-image PATH       Persistent disk (default: build/data.bin)
  --firmware bios|uefi    Default: UEFI for QEMU, BIOS elsewhere
  --freedos               Boot FreeDOS from the same data disk (BIOS only)
  --arch 386|686|x64      QEMU CPU selection (default: 386)
  --hd ata|ahci|nvme       QEMU data controller (default: NVMe on UEFI, ATA on BIOS)
  --sound sb|ac97|hda|none QEMU sound (default: hda; other emulators: sb)
  --sb-audio native|mixed QEMU guest audio policy
  --cmd, -c, -r COMMAND   Run a command (QEMU or hosted)
  --host, -H, -h DIR      Host directory (QEMU HostFS or hosted root)
  --headless, -T          No window (QEMU or hosted)
  --kvm                  Use KVM (QEMU or hosted)
  --wav, -w PATH          Hosted audio capture
  --screenshot, -s PATH   Hosted screenshot
  --trace, -t             Hosted instruction trace

The boot image is built on every launch. The data image is built and copied
only when missing; subsequent launches use it directly, preserving writes.
RETROOS_DATA_IMAGE also selects the data path. VM_DIR selects the Bochs/86Box
configuration directory. Old -i image modes and --gpt have been removed.
HELP
}
fail() { echo "run.sh: $*" >&2; exit 1; }
BACKEND=qemu FIRMWARE= SOUND= ARCH=386 FREEDOS=0 HEADLESS=0 KVM=0
COMMAND= HOST_DIR= WAV= SHOT= TRACE=0 SB_AUDIO= HD=
DATA_IMAGE="${RETROOS_DATA_IMAGE:-$SCRIPT_DIR/build/data.bin}"
PASS=()
case "${1:-}" in
    qemu|bochs|86box|hosted) BACKEND="$1"; shift ;;
    -h|help) usage; exit 0 ;;
esac
while [ $# -gt 0 ]; do
    case "$1" in
        --help) usage; exit 0 ;;
        --backend|--data-image|--firmware|--arch|--hd|--sound|--sb-audio|--cmd|-c|-r|--host|-H|-h|--wav|-w|--screenshot|-s)
            [ $# -ge 2 ] || fail "$1 needs a value"
            case "$1" in
                --backend) BACKEND="$2" ;; --data-image) DATA_IMAGE="$2" ;;
                --firmware) FIRMWARE="$2" ;; --arch) ARCH="$2" ;;
                --hd) HD="$2" ;;
                --sound) SOUND="$2" ;; --sb-audio) SB_AUDIO="$2" ;;
                --cmd|-c|-r) COMMAND="$2" ;; --host|-H|-h) HOST_DIR="$2" ;;
                --wav|-w) WAV="$2" ;; --screenshot|-s) SHOT="$2" ;;
            esac
            shift 2 ;;
        --freedos) FREEDOS=1; shift ;;
        --headless|-T) HEADLESS=1; shift ;;
        --kvm) KVM=1; shift ;;
        --trace|-t) TRACE=1; shift ;;
        -i|--image|--gpt) fail "$1 was removed; use --data-image PATH or --freedos" ;;
        --) shift; PASS=("$@"); break ;;
        *) fail "unknown option: $1 (pass emulator options after --)" ;;
    esac
done
case "$BACKEND" in qemu|bochs|86box|hosted) ;; *) fail "unknown backend: $BACKEND" ;; esac
[ -n "$FIRMWARE" ] || { if [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ]; then FIRMWARE=uefi; else FIRMWARE=bios; fi; }
[ -n "$SOUND" ] || { if [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ]; then SOUND=hda; else SOUND=sb; fi; }
case "$FIRMWARE" in bios|uefi) ;; *) fail "unknown firmware: $FIRMWARE" ;; esac
case "$HD" in ''|ata|ahci|nvme) ;; *) fail "unknown disk controller: $HD" ;; esac
[ -z "$HD" ] || [ "$BACKEND" = qemu ] || fail "--hd requires QEMU"
[ -n "$HD" ] || { if [ "$FIRMWARE" = uefi ]; then HD=nvme; else HD=ata; fi; }
case "$SOUND" in sb|ac97|hda|none) ;; *) fail "unknown sound: $SOUND" ;; esac
case "$ARCH" in 386|686|x64) ;; *) fail "unknown architecture: $ARCH" ;; esac
case "$SB_AUDIO" in ''|native|mixed) ;; *) fail "unknown audio policy: $SB_AUDIO" ;; esac
if [ "$FREEDOS" = 1 ]; then
    [ "$HD" = ata ] || fail "FreeDOS requires --hd ata"
    [ "$FIRMWARE" = bios ] && [ "$BACKEND" != hosted ] || fail "FreeDOS needs a BIOS emulator"
    [ -z "$COMMAND$HOST_DIR" ] || fail "--cmd/--host require RetroOS"
fi
if [ "$BACKEND" = bochs ] || [ "$BACKEND" = 86box ]; then
    [ "$KVM$HEADLESS" = 00 ] && [ -z "$COMMAND$HOST_DIR$SB_AUDIO" ] || fail "these options require QEMU or hosted"
    [ "${RETROOS_86BOX_KERNEL_LOG:-0}" = 0 ] || fail "serial injection into the persistent disk is not supported"
    case "$SOUND" in sb|none) ;; *) fail "this backend supports sb or none" ;; esac
fi
[ "$BACKEND" != 86box ] || [ "$FIRMWARE" = bios ] || fail "86Box requires BIOS"
[ -z "$HOST_DIR" ] || [ -d "$HOST_DIR" ] || fail "host directory does not exist: $HOST_DIR"

BAZEL="${BAZEL:-$(command -v bazelisk || command -v bazel || true)}"
[ -n "$BAZEL" ] || BAZEL="$HOME/bin/bazelisk"
BAZEL=$(command -v "$BAZEL" || true)
[ -n "$BAZEL" ] || fail "install bazelisk or set BAZEL"
WORK=$(mktemp -d -t retroos-run.XXXXXX)
VM_PID= HOSTFS_PID= STAGED=
cleanup() {
    local pid
    for pid in "$VM_PID" "$HOSTFS_PID"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    [ -z "$STAGED" ] || rm -f "$STAGED"
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_vm() { "$@" <&0 & VM_PID=$!; local status=0; wait "$VM_PID" || status=$?; VM_PID=; return "$status"; }

# Build outputs never serve as the writable disk. Publish a complete seed once.
if [ "$BACKEND" != hosted ] || [ -z "$HOST_DIR" ]; then
    DATA_IMAGE=$(realpath -m "$DATA_IMAGE")
    mkdir -p "$(dirname "$DATA_IMAGE")"
    exec 9>"$DATA_IMAGE.lock"
    flock -n 9 || fail "data image is already in use: $DATA_IMAGE"
    if [ ! -e "$DATA_IMAGE" ]; then
        SEED=data_disk
        [ ! -d apps-proprietary ] || SEED=data_disk_proprietary
        # The persistent Bazel server must not inherit the data-image lock.
        "$BAZEL" build "//:$SEED" 9>&-
        # Hard-link publication is atomic and never replaces an existing image.
        STAGED=$(mktemp "$(dirname "$DATA_IMAGE")/.data-seed.XXXXXX")
        cp --reflink=auto "bazel-bin/$SEED.bin" "$STAGED"
        chmod u+rw "$STAGED"
        ln "$STAGED" "$DATA_IMAGE"
        rm "$STAGED"
        STAGED=
    fi
    [ -f "$DATA_IMAGE" ] && [ -w "$DATA_IMAGE" ] || fail "data image is not writable: $DATA_IMAGE"
    "$BAZEL" build //:boot_disk 9>&-
    BOOT_IMAGE="$WORK/boot.bin"
    cp --reflink=auto bazel-bin/boot_disk.bin "$BOOT_IMAGE"
    chmod u+rw "$BOOT_IMAGE"
    echo "Persistent data: $DATA_IMAGE"
fi
source "$SCRIPT_DIR/tools/run/$BACKEND.sh"
launch
