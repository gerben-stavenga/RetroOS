#!/bin/bash
# Boot RetroOS on a UEFI-only "modern laptop" mock.
#
# This deliberately mimics a current machine (e.g. a 2024 Razer Blade):
#   - OVMF (edk2) firmware: UEFI boot, no CSM, no legacy BIOS services
#   - GOP-only display:  -device bochs-display — a dumb linear framebuffer
#     with NO VGA ports and NO text mode (touching 0xB8000/VGA regs does
#     nothing, exactly like real modern hardware)
#   - NVMe-only storage: the RetroOS image is attached as an NVMe namespace;
#     there is no IDE/AHCI disk, so the ATA driver must find nothing
#   - USB keyboard (xHCI) — though q35 still provides an i8042, which is the
#     bring-up crutch until a xHCI/HID driver exists
#
# The kernel is loaded by a standalone GRUB (multiboot1) from a generated
# ESP — an interim stand-in until `boot-uefi` (our own UEFI entry with GOP
# framebuffer handoff) replaces it. The kernel binary itself is UNCHANGED
# from the legacy-BIOS boot.
#
# Console: the kernel's 0xE9 debug log → stdio (-debugcon). With no VGA text
# mode, that's the only console until the GOP framebuffer renderer lands.
#
# Usage: ./run_uefi.sh [image.bin] [--headless] [-- extra qemu args]
#   default image: bazel-bin/image_proprietary.bin (falls back to image.bin)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE=""
HEADLESS=0
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --headless|-H) HEADLESS=1 ;;
        --) shift; EXTRA+=("$@"); break ;;
        *)  if [ -z "$IMAGE" ]; then IMAGE="$1"; else EXTRA+=("$1"); fi ;;
    esac
    shift
done
if [ -z "$IMAGE" ]; then
    IMAGE="bazel-bin/image_proprietary.bin"
    [ -f "$IMAGE" ] || IMAGE="bazel-bin/image.bin"
fi
[ -f "$IMAGE" ] || { echo "run_uefi: no image at $IMAGE (bazelisk build //:image)" >&2; exit 1; }

KERNEL="bazel-bin/kernel/kernel.elf"
[ -f "$KERNEL" ] || { echo "run_uefi: no kernel at $KERNEL (bazelisk build //kernel:kernel_elf)" >&2; exit 1; }

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
[ -f "$OVMF_CODE" ] || { echo "run_uefi: OVMF not found (apt install ovmf)" >&2; exit 1; }

# Build the ESP fresh each run (cheap: ~1s). Standalone GRUB embeds its own
# grub.cfg in a memdisk; it then locates kernel.elf on the ESP by search.
WORK="$(mktemp -d -t retroos-uefi.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/grub.cfg" <<'EOF'
set timeout=0
menuentry "RetroOS (multiboot)" {
    search --no-floppy --file /kernel.elf --set=root
    multiboot /kernel.elf
    boot
}
EOF

grub-mkstandalone -O x86_64-efi -o "$WORK/BOOTX64.EFI" \
    "boot/grub/grub.cfg=$WORK/grub.cfg" >/dev/null

ESP="$WORK/esp.img"
truncate -s 64M "$ESP"
mformat -i "$ESP" -F ::
mmd    -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy  -i "$ESP" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy  -i "$ESP" "$KERNEL" ::/kernel.elf

# Private writable VARS copy (OVMF persists boot entries into it).
cp "$OVMF_VARS" "$WORK/vars.fd"

DISPLAY_ARGS=()
if [ "$HEADLESS" = 1 ]; then
    DISPLAY_ARGS+=(-display none)
fi

# -cpu max: the default qemu64 model lacks VME, forcing the kernel's software
# VM86 monitor; real hardware (and run_qemu.sh) has VME.
exec qemu-system-x86_64 \
    -M q35 -m 512 -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -nodefaults \
    -device bochs-display \
    -drive file="$ESP",if=none,id=esp,format=raw \
    -device nvme,drive=esp,serial=esp0 \
    -drive file="$IMAGE",if=none,id=hd,format=raw,snapshot=on \
    -device nvme,drive=hd,serial=retro1 \
    -device qemu-xhci -device usb-kbd \
    -debugcon stdio \
    -no-reboot \
    "${DISPLAY_ARGS[@]}" \
    "${EXTRA[@]}"
