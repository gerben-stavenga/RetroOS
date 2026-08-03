#!/bin/bash
# Install the current build onto this machine's metal boot path. Run as root:
#
#   sudo tools/install_kernel.sh
#
# Two files, and they MUST come from the same build:
#
#   kernel.elf -> /boot/retroos/kernel.elf   what GRUB multiboots (stripped)
#   kernel.sym -> <C:>/BOOT/KERNEL.SYM       what the stack tracer reads
#
# kernel.elf carries no symbol table any more, so a panic backtrace is named
# only if KERNEL.SYM is present AND matches. A stale symbol file is worse than
# none: the addresses still resolve, to the wrong functions. That is the whole
# reason this is one script rather than two steps you might do separately.
#
# Usage:
#   sudo tools/install_kernel.sh                 # /boot/retroos + /home/retroos
#   sudo tools/install_kernel.sh /mnt/c-root     # different C: root
#   sudo KERNEL_DEST=/boot/other tools/install_kernel.sh
set -euo pipefail
cd "$(dirname "$0")/.."

C_ROOT="${1:-/home/retroos}"
KERNEL_DEST="${KERNEL_DEST:-/boot/retroos}"

[ "$(id -u)" = 0 ] || { echo "run me as root: sudo tools/install_kernel.sh" >&2; exit 1; }

# Refuse to install half of a pair. A C: root without BOOT/ is not a RetroOS
# root, and dropping KERNEL.SYM somewhere the kernel never reads would leave
# the installed kernel silently symbol-less.
if [ ! -d "$C_ROOT/BOOT" ]; then
    echo "$C_ROOT/BOOT does not exist — run tools/install_boot_dir.sh $C_ROOT first" >&2
    echo "(that installs COMMAND.COM, DN and SHELL.ELF; this only refreshes the kernel)" >&2
    exit 1
fi

ELF=bazel-bin/kernel/kernel.elf
SYM=bazel-bin/kernel/kernel.sym
# Build as the invoking user, not as root: bazel under sudo would write a
# root-owned output tree and cache into the wrong home, and every later
# non-root build would fail on it.
if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" bazelisk build //kernel:kernel_elf //kernel:kernel_sym >/dev/null
else
    bazelisk build //kernel:kernel_elf //kernel:kernel_sym >/dev/null
fi
[ -f "$ELF" ] && [ -f "$SYM" ] || { echo "build produced no $ELF / $SYM" >&2; exit 1; }

echo "kernel  $(stat -c%s "$ELF") bytes -> $KERNEL_DEST/kernel.elf"
mkdir -p "$KERNEL_DEST"
cp "$ELF" "$KERNEL_DEST/kernel.elf"

echo "symbols $(stat -c%s "$SYM") bytes -> $C_ROOT/BOOT/KERNEL.SYM"
cp "$SYM" "$C_ROOT/BOOT/KERNEL.SYM"
# Match the BOOT directory rather than leaving a root-owned file in someone's
# home tree: this is C: content, and its owner should keep being able to manage
# it (and to rewrite it from an ordinary non-root build).
chown --reference="$C_ROOT/BOOT" "$C_ROOT/BOOT/KERNEL.SYM"
chmod 664 "$C_ROOT/BOOT/KERNEL.SYM"

echo
echo "Installed. The next RetroOS boot should print:"
echo "    Loading kernel symbols ($(stat -c%s "$SYM") bytes)"
