#!/bin/bash
# Run RetroOS in Bochs with UEFI/OVMF.
#
# This script combines the UEFI setup from run_uefi.sh (GOP, NVMe, ESP/GRUB)
# with the Bochs configuration from run_bochs.sh.
#
# Usage: ./run_uefi_bochs.sh [image.bin] [extra bochs args...]

set -e
set -o pipefail

IMAGE=""
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        *)  if [ -z "$IMAGE" ]; then IMAGE="$1"; else EXTRA+=("$1"); fi ;;
    esac
    shift
done

if [ -z "$IMAGE" ]; then
    IMAGE="bazel-bin/image_proprietary.bin"
    [ -f "$IMAGE" ] || IMAGE="bazel-bin/image.bin"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

find_bazel() {
    if command -v bazelisk >/dev/null 2>&1; then
        command -v bazelisk
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
    for cand in /usr/bin/bochs /usr/local/bin/bochs; do
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

find_bochs_vga_rom() {
    if [ -n "${BOCHS_VGA_ROM:-}" ] && [ -f "$BOCHS_VGA_ROM" ]; then
        printf '%s\n' "$BOCHS_VGA_ROM"
        return
    fi
    for cand in \
        /usr/share/bochs/VGABIOS-lgpl-latest \
        /usr/share/bochs/VGABIOS-lgpl-latest.bin \
        /usr/share/vgabios/vgabios-stdvga.bin \
        /usr/share/seabios/vgabios-bochs-display.bin \
        /usr/local/share/bochs/VGABIOS-lgpl-latest.bin; do
        if [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            return
        fi
    done
    echo "Could not find Bochs VGA ROM image." >&2
    exit 1
}

BAZEL="$(find_bazel)"
"$BAZEL" build //kernel:kernel_elf >/dev/null 2>&1
# If IMAGE was just a name, it might need building. But usually we point to a .bin.
if [[ "$IMAGE" == bazel-bin/* ]]; then
    # try to guess target
    TARGET="//:$(basename "${IMAGE%.bin}")"
    "$BAZEL" build "$TARGET" >/dev/null 2>&1 || true
fi

[ -f "$IMAGE" ] || { echo "run_uefi_bochs: no image at $IMAGE" >&2; exit 1; }
KERNEL="bazel-bin/kernel/kernel.elf"
[ -f "$KERNEL" ] || { echo "run_uefi_bochs: no kernel at $KERNEL" >&2; exit 1; }

# Persistent VM state
VM_DIR="${HOME}/.local/share/Bochs/RetroOS_UEFI"
mkdir -p "$VM_DIR"
BOCHSRC="${VM_DIR}/bochsrc.txt"

# Bochs 2.7 caps romimage at 2MB (BIOSROMSZ in memory.h), so the 4MB OVMF
# builds modern distros ship panic with "ROM image too large". The last
# Ubuntu edk2 that shipped a unified 2MB OVMF.fd is jammy's 2022.02 —
# fetch that package once and cache the firmware in VM_DIR.
OVMF_PATH="$VM_DIR/OVMF_2M.fd"
if [ ! -f "$OVMF_PATH" ]; then
    OVMF_DEB_URL="http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/ovmf_2022.02-3ubuntu0.22.04.6_all.deb"
    echo "Fetching 2MB OVMF (Bochs cannot load the 4MB builds)..."
    OVMF_TMP="$(mktemp -d -t retroos-ovmf.XXXXXX)"
    curl -fsSL -o "$OVMF_TMP/ovmf.deb" "$OVMF_DEB_URL"
    dpkg-deb -x "$OVMF_TMP/ovmf.deb" "$OVMF_TMP/x"
    install -m 644 "$OVMF_TMP/x/usr/share/ovmf/OVMF.fd" "$OVMF_PATH"
    rm -rf "$OVMF_TMP"
fi

# Build ESP (identical to run_uefi.sh)
WORK="$(mktemp -d -t retroos-uefi-bochs.XXXXXX)"
# We don't trap EXIT here because Bochs needs these files while running.
# Instead we put them in VM_DIR.
# Note: OVMF exposes no usable GOP on Bochs's VGA (QemuVideoDxe doesn't
# bind), so GRUB reports "no suitable video mode found" and the kernel
# boots without a multiboot framebuffer — it falls back to emulated VGA
# text, which works. Display parity with metal fbcon is not available here.
cat > "$WORK/grub.cfg" <<'EOF'
set timeout=0
insmod all_video
insmod efi_gop
set gfxmode=auto
set gfxpayload=keep
menuentry "RetroOS (multiboot)" {
    search --no-floppy --file /kernel.elf --set=root
    multiboot /kernel.elf
    boot
}
EOF

grub-mkstandalone -O x86_64-efi -o "$WORK/BOOTX64.EFI" \
    "boot/grub/grub.cfg=$WORK/grub.cfg" >/dev/null

ESP="$VM_DIR/esp.img"
truncate -s 64M "$ESP"
mformat -i "$ESP" -F ::
mmd    -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy  -i "$ESP" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy  -i "$ESP" "$KERNEL" ::/kernel.elf
rm -rf "$WORK"

cp --reflink=auto "$IMAGE" "$VM_DIR/disk.img"
chmod u+rw "$VM_DIR/disk.img"

BOCHS_BIN="$(find_bochs)"
BOCHS_VGA_ROM="$(find_bochs_vga_rom)"

# Bochs config for UEFI.
# - ROM is top-aligned at 4GB: 2MB OVMF flashes at 0xffe00000.
# - reset_on_triple_fault=0: this rig exists to debug metal boot faults;
#   on a triple fault Bochs panics and dumps full CPU state to the log
#   instead of silently rebooting.
cat <<EOF > "$BOCHSRC"
megs: 1024
cpu: model=core2_penryn_t9600, count=1, ips=50000000, reset_on_triple_fault=0
pci: enabled=1, chipset=i440fx
port_e9_hack: enabled=1
romimage: file="$OVMF_PATH", address=0xffe00000
vgaromimage: file="$BOCHS_VGA_ROM"
vga: extension=vbe, update_freq=60
clock: sync=realtime, time0=local
mouse: enabled=1, type=ps2
speaker: enabled=1, mode=sound
sb16: wavemode=1, midimode=0, dmatimer=750000, log="$VM_DIR/sb16.log", loglevel=2
log: "$VM_DIR/bochs.log"
com1: enabled=1, mode=file, dev="$VM_DIR/serial.out"
# Boot from the ESP
boot: disk
# ata0-master is our main RetroOS image
ata0-master: type=disk, path="$VM_DIR/disk.img", mode=flat, cylinders=8448, heads=16, spt=16, biosdetect=auto, translation=lba
# ata0-slave is the ESP containing the kernel + GRUB
ata0-slave: type=disk, path="$ESP", mode=flat, cylinders=128, heads=16, spt=63, biosdetect=auto, translation=lba
EOF

# Headless use: BOCHS_DISPLAY=rfb starts a VNC server on :5900 (a client
# must connect within 30s or Bochs panics). Default is Bochs's built-in
# GUI choice (X11 here).
if [ -n "${BOCHS_DISPLAY:-}" ]; then
    echo "display_library: ${BOCHS_DISPLAY}" >> "$BOCHSRC"
fi

echo "Wrote Bochs config to $BOCHSRC"

BOCHS_ARGS=(-q -f "$BOCHSRC" -unlock)
if [ "${BOCHS_DEBUG:-0}" != "1" ]; then
    BOCHS_RC="${VM_DIR}/bochs.rc"
    printf 'c\n' > "$BOCHS_RC"
    BOCHS_ARGS=(-q -rc "$BOCHS_RC" -f "$BOCHSRC" -unlock)
fi

exec "$BOCHS_BIN" "${BOCHS_ARGS[@]}" "${EXTRA[@]}"
