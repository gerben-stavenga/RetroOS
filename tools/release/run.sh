#!/bin/bash
# Prebuilt release launcher. No build tools or source checkout required.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
fail() { echo "run.sh: $*" >&2; exit 1; }
FIRMWARE=bios ARCH=686 SOUND=hda HEADLESS=0 KVM=0 FREEDOS=0
COMMAND= HOST_DIR= SB_AUDIO= HOSTFS_PID= VM_PID=
DATA_IMAGE="${RETROOS_DATA_IMAGE:-$SCRIPT_DIR/data.img}"
PASS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --firmware|--sound|--arch|--data-image|--cmd)
            [ $# -ge 2 ] || fail "$1 needs a value"
            case "$1" in
                --firmware) FIRMWARE="$2" ;; --sound) SOUND="$2" ;;
                --arch) ARCH="$2" ;; --data-image) DATA_IMAGE="$2" ;; --cmd) COMMAND="$2" ;;
            esac
            shift 2 ;;
        --headless) HEADLESS=1; shift ;;
        --kvm) KVM=1; shift ;;
        --help)
            echo 'Usage: ./run.sh [--firmware bios|uefi] [--sound hda|ac97|sb|none] [--arch 386|686|x64] [--headless] [--kvm] [--data-image PATH] [--cmd COMMAND] [-- QEMU arguments]'
            exit 0 ;;
        --) shift; PASS=("$@"); break ;;
        *) fail "unknown option: $1" ;;
    esac
done
case "$FIRMWARE" in bios|uefi) ;; *) fail 'invalid firmware' ;; esac
case "$SOUND" in hda|ac97|sb|none) ;; *) fail 'invalid sound device' ;; esac
case "$ARCH" in 386|686|x64) ;; *) fail 'invalid architecture' ;; esac
DATA_IMAGE=$(realpath "$DATA_IMAGE")
[ -w "$DATA_IMAGE" ] || fail "data disk must be writable: $DATA_IMAGE"
exec 9>"$DATA_IMAGE.lock"
flock -n 9 || fail "data disk is already in use: $DATA_IMAGE"
WORK=$(mktemp -d -t retroos-release.XXXXXX)
cleanup() {
    if [ -n "$VM_PID" ]; then kill "$VM_PID" 2>/dev/null || true; wait "$VM_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp --reflink=auto "$SCRIPT_DIR/boot.img" "$WORK/boot.img"
BOOT_IMAGE="$WORK/boot.img"
run_vm() { "$@" <&0 & VM_PID=$!; local status=0; wait "$VM_PID" || status=$?; VM_PID=; return "$status"; }
source "$SCRIPT_DIR/tools/run/qemu.sh"
launch
