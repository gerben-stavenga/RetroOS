#!/usr/bin/env bash
# One disposable boot image and one persistent data image, for every backend.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat <<'HELP'
Usage: ./run.sh [qemu|bochs|86box|unipcemu|rust-dos|rust-dos-games|hosted] [options] [-- emulator arguments]
  --data-image PATH       Persistent disk (default: build/data.bin)
  --firmware bios|uefi    Default: UEFI for QEMU, BIOS elsewhere
  --freedos               Boot FreeDOS from the same data disk (BIOS only)
  --arch 386|686|x64      CPU selection (default: 386, UniPCemu: 686)
  --hd ata|ahci|nvme       QEMU data controller; UniPCemu accepts ATA
  --sound sb|ac97|hda|none QEMU sound (default: hda; other emulators: sb)
  --net virtio|e1000|e1000e|none  QEMU NIC (default: virtio for RetroOS)
  --sb-audio native|mixed QEMU guest audio policy
  --cmd, -c, -r COMMAND   Run a startup command
  --headless, -T          No window (QEMU or hosted)
  --kvm                  Use KVM (QEMU or hosted); use configured live SMB files in QEMU
  --live-root            Use the live SMB profile explicitly (QEMU only)
  --wav, -w PATH          Hosted audio capture
  --screenshot, -s PATH   Hosted screenshot
  --trace, -t             Hosted instruction trace

The boot image is built on every launch. The data image is built and copied
only when missing; subsequent launches use it directly, preserving writes.
rust-dos-games instead builds a disposable FAT16 C: from the packaged files;
changes made in that mode are discarded when it exits.
RETROOS_DATA_IMAGE also selects the data path. VM_DIR selects the Bochs/86Box
configuration directory. Old -i image modes and --gpt have been removed.
Host-directory sharing uses [smb] mounts in RETROOS.INI (see BOOTING.md).
The deprecated --host directory shortcut has been removed.
After tools/qemu_live.py setup, qemu --kvm uses the live SMB profile.
An explicit --data-image keeps the separate persistent-disk mode.
HELP
}
fail() { echo "run.sh: $*" >&2; exit 1; }
BACKEND=qemu FIRMWARE= SOUND= ARCH=386 ARCH_EXPLICIT=0 FREEDOS=0 HEADLESS=0 KVM=0
COMMAND= WAV= SHOT= TRACE=0 SB_AUDIO= HD=
NETWORK= LIVE=auto DATA_EXPLICIT=0
LIVE_PROFILE="${RETROOS_QEMU_LIVE_PROFILE:-$SCRIPT_DIR/build/qemu-live.json}"
[ -z "${RETROOS_DATA_IMAGE:-}" ] || DATA_EXPLICIT=1
DATA_IMAGE="${RETROOS_DATA_IMAGE:-$SCRIPT_DIR/build/data.bin}"
PASS=()
case "${1:-}" in
    qemu|bochs|86box|unipcemu|rust-dos|rust-dos-games|hosted) BACKEND="$1"; shift ;;
    -h|help) usage; exit 0 ;;
esac
while [ $# -gt 0 ]; do
    case "$1" in
        --help) usage; exit 0 ;;
        --backend|--data-image|--firmware|--arch|--hd|--sound|--net|--sb-audio|--cmd|-c|-r|--wav|-w|--screenshot|-s)
            [ $# -ge 2 ] || fail "$1 needs a value"
            case "$1" in
                --backend) BACKEND="$2" ;; --data-image) DATA_IMAGE="$2"; DATA_EXPLICIT=1 ;;
                --firmware) FIRMWARE="$2" ;;
                --hd) HD="$2" ;;
                --arch) ARCH="$2"; ARCH_EXPLICIT=1 ;;
                --sound) SOUND="$2" ;; --sb-audio) SB_AUDIO="$2" ;;
                --net) NETWORK="$2" ;;
                --cmd|-c|-r) COMMAND="$2" ;;
                --wav|-w) WAV="$2" ;; --screenshot|-s) SHOT="$2" ;;
            esac
            shift 2 ;;
        --host|-H|-h) fail "$1 is deprecated and removed; configure an [smb] mount in RETROOS.INI (see BOOTING.md)" ;;
        --freedos) FREEDOS=1; shift ;;
        --headless|-T) HEADLESS=1; shift ;;
        --kvm) KVM=1; shift ;;
        --live-root) LIVE=1; shift ;;
        --trace|-t) TRACE=1; shift ;;
        -i|--image|--gpt) fail "$1 was removed; use --data-image PATH or --freedos" ;;
        --) shift; PASS=("$@"); break ;;
        *) fail "unknown option: $1 (pass emulator options after --)" ;;
    esac
done
case "$BACKEND" in qemu|bochs|86box|unipcemu|rust-dos|rust-dos-games|hosted) ;; *) fail "unknown backend: $BACKEND" ;; esac
[ "$BACKEND" != unipcemu ] || [ "$ARCH_EXPLICIT" = 1 ] || ARCH=686
[ -n "$FIRMWARE" ] || { if [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ]; then FIRMWARE=uefi; else FIRMWARE=bios; fi; }
[ -n "$SOUND" ] || { if [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ]; then SOUND=hda; else SOUND=sb; fi; }
case "$FIRMWARE" in bios|uefi) ;; *) fail "unknown firmware: $FIRMWARE" ;; esac
case "$HD" in ''|ata|ahci|nvme) ;; *) fail "unknown disk controller: $HD" ;; esac
[ -z "$HD" ] || [ "$BACKEND" = qemu ] || [ "$BACKEND" = rust-dos ] || { [ "$BACKEND" = unipcemu ] && [ "$HD" = ata ]; } || fail "--hd requires QEMU or Rust-DOS (UniPCemu accepts ATA)"
[ -n "$HD" ] || { if [ "$FIRMWARE" = uefi ]; then HD=nvme; else HD=ata; fi; }
case "$SOUND" in sb|ac97|hda|none) ;; *) fail "unknown sound: $SOUND" ;; esac
case "$NETWORK" in ''|virtio|e1000|e1000e|none) ;; *) fail "unknown network: $NETWORK" ;; esac
[ -z "$NETWORK" ] || [ "$BACKEND" = qemu ] || fail "--net requires QEMU"
[ -n "$NETWORK" ] || { if [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ]; then NETWORK=virtio; else NETWORK=none; fi; }
case "$ARCH" in 386|686|x64) ;; *) fail "unknown architecture: $ARCH" ;; esac
case "$SB_AUDIO" in ''|native|mixed) ;; *) fail "unknown audio policy: $SB_AUDIO" ;; esac
if [ "$FREEDOS" = 1 ]; then
    [ "$HD" = ata ] || fail "FreeDOS requires --hd ata"
    [ "$FIRMWARE" = bios ] && [ "$BACKEND" != hosted ] || fail "FreeDOS needs a BIOS emulator"
    [ -z "$COMMAND" ] || fail "--cmd requires RetroOS"
fi
if [ "$BACKEND" = bochs ] || [ "$BACKEND" = 86box ] || [ "$BACKEND" = unipcemu ]; then
    [ "$KVM$HEADLESS" = 00 ] && [ -z "$SB_AUDIO" ] || fail "these options require QEMU or hosted"
    [ "${RETROOS_86BOX_KERNEL_LOG:-0}" = 0 ] || fail "serial injection into the persistent disk is not supported"
    case "$SOUND" in sb|none) ;; *) fail "this backend supports sb or none" ;; esac
fi
[ "$BACKEND" != 86box ] || [ "$FIRMWARE" = bios ] || fail "86Box requires BIOS"
if [ "$BACKEND" = unipcemu ]; then
    [ "$FIRMWARE" = bios ] || fail "UniPCemu requires BIOS"
    [ "$ARCH" = 686 ] || fail "UniPCemu requires --arch 686 for i430fx or i440fx"
    [ "$HD" = ata ] || fail "UniPCemu requires ATA disks"
fi

if [ "$LIVE" = auto ]; then
    LIVE=0
    if [ "$BACKEND" = qemu ] && [ "$KVM" = 1 ] && [ "$FREEDOS" = 0 ] && [ "$DATA_EXPLICIT" = 0 ] && [ -f "$LIVE_PROFILE" ]; then LIVE=1; fi
fi
if [ "$LIVE" = 1 ]; then
    [ "$BACKEND" = qemu ] && [ "$FREEDOS" = 0 ] || fail "--live-root requires QEMU booting RetroOS"
    [ "$DATA_EXPLICIT" = 0 ] || fail "choose live files or --data-image, not both"
    [ "$NETWORK" = virtio ] || fail "live SMB files require --net virtio"
    [ -f "$LIVE_PROFILE" ] || fail "run python3 tools/qemu_live.py setup first"
fi

BAZEL="${BAZEL:-$(command -v bazelisk || command -v bazel || true)}"
[ -n "$BAZEL" ] || BAZEL="$HOME/bin/bazelisk"
BAZEL=$(command -v "$BAZEL" || true)
[ -n "$BAZEL" ] || fail "install bazelisk or set BAZEL"
WORK=$(mktemp -d -t retroos-run.XXXXXX)
VM_PID= SMB_PID= STAGED= RUST_DOS_IMAGE_LINK=
cleanup() {
    if [ -n "$VM_PID" ]; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    if [ -n "$SMB_PID" ]; then
        kill "$SMB_PID" 2>/dev/null || true
        wait "$SMB_PID" 2>/dev/null || true
    fi
    [ -z "$STAGED" ] || rm -f "$STAGED"
    [ -z "$RUST_DOS_IMAGE_LINK" ] || rm -f -- "$RUST_DOS_IMAGE_LINK"
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_vm() { "$@" <&0 & VM_PID=$!; local status=0; wait "$VM_PID" || status=$?; VM_PID=; return "$status"; }

# Build outputs never serve as the writable disk. Publish a complete seed once.
if [ "$BACKEND" = rust-dos-games ]; then
    GAMES_TARGET=rust_dos_games_disk
    [ ! -d apps-proprietary ] || GAMES_TARGET=rust_dos_games_disk_proprietary
    "$BAZEL" build "//:$GAMES_TARGET"
    GAMES_IMAGE="$WORK/games.img"
    cp --reflink=auto "bazel-bin/$GAMES_TARGET.img" "$GAMES_IMAGE"
    chmod u+rw "$GAMES_IMAGE"
elif [ "$LIVE" = 1 ]; then
    "$BAZEL" build //:boot_disk
    BOOT_IMAGE="$WORK/boot.img"
    cp --reflink=auto bazel-bin/boot_disk.bin "$BOOT_IMAGE"
    chmod 600 "$BOOT_IMAGE"
    DATA_IMAGE=
    python3 "$SCRIPT_DIR/tools/qemu_live.py" serve --work "$WORK" --boot-image "$BOOT_IMAGE" --command "$COMMAND" --profile "$LIVE_PROFILE" &
    SMB_PID=$!
    for ((attempt=0; attempt<200; attempt++)); do
        [ ! -f "$WORK/smb-ready" ] || break
        kill -0 "$SMB_PID" 2>/dev/null || { wait "$SMB_PID" || true; fail "live SMB setup failed"; }
        sleep .1
    done
    [ -f "$WORK/smb-ready" ] || fail "live SMB setup timed out"
else
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
    BOOT_TARGET=boot_disk
    [ "$BACKEND" != rust-dos ] || BOOT_TARGET=native_boot_disk
    "$BAZEL" build "//:$BOOT_TARGET" 9>&-
    BOOT_IMAGE="$WORK/boot.img"
    cp --reflink=auto "bazel-bin/$BOOT_TARGET.bin" "$BOOT_IMAGE"
    chmod u+rw "$BOOT_IMAGE"
    if [ "$FREEDOS" = 0 ] && [ "$BACKEND" != rust-dos ]; then
        python3 "$SCRIPT_DIR/tools/vm_mount_config.py" --boot-image "$BOOT_IMAGE" --data-image "$DATA_IMAGE" --command "$COMMAND"
    fi
    echo "Persistent data: $DATA_IMAGE"
fi
source "$SCRIPT_DIR/tools/run/$BACKEND.sh"
launch
