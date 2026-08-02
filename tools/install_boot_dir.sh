#!/bin/bash
# Install C:\BOOT into a RetroOS C: root on the host.
#
# C:\BOOT (DN + COMMAND.COM + LOADFIX.CFG + SHELL.ELF) is ordinary content on
# the C: filesystem, not something the kernel carries. The packaged ext4 images
# get it from the build. A hosted run started with `--host /` uses the machine's
# real /home/retroos as C:, so that tree needs its own copy — this script puts
# it there, and refreshes it after a rebuild.
#
# Usage: tools/install_boot_dir.sh [C_ROOT]        (default: /home/retroos)
set -euo pipefail

C_ROOT="${1:-/home/retroos}"
cd "$(dirname "$0")/.."

bazelisk build //:extras_tar >/dev/null

if [ ! -d "$C_ROOT" ]; then
    echo "$C_ROOT does not exist — pass the C: root as the first argument" >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
tar xf bazel-bin/extras_tar.tar -C "$TMP" home/retroos/BOOT

rm -rf "$C_ROOT/BOOT"
cp -r "$TMP/home/retroos/BOOT" "$C_ROOT/BOOT"
# RetroOS writes a file only when it belongs to the C: root's group AND carries
# g+w (see lwext4::writable); DN rewrites its own .cfg/.ini in place.
chmod -R g+w "$C_ROOT/BOOT"

echo "installed $C_ROOT/BOOT ($(find "$C_ROOT/BOOT" -type f | wc -l) files)"
