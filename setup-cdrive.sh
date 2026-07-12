#!/usr/bin/env bash
# Set up /home/retroos as RetroOS's DOS C: on THIS machine, sharing repo
# content via symlinks (no copy). Run with sudo (creates dirs under /home).
#
# Requires the ext4fs symlink-following support (commit 9f320aa): RetroOS reads
# the raw ext4 of your Linux root, follows symlinks, but ONLY within the same
# partition — so the repo must live on the same ext4 as /home/retroos (it does
# if the repo is under /home). Reboot into RetroOS after running this.
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
C=/home/retroos

echo "Repo:   $REPO"
echo "C: root: $C"

mkdir -p "$C/GAMES"

# Games: one symlink per game directory, shareware + proprietary, merged into
# C:\GAMES (the */ glob skips loose files like BUILD.bazel).
for d in "$REPO"/apps/games/*/ "$REPO"/apps-proprietary/games/*/; do
    [ -d "$d" ] || continue
    ln -sfn "${d%/}" "$C/GAMES/$(basename "$d")"
done

# Toolchains / utilities (single dir symlinks).
ln -sfn "$REPO/apps-proprietary/BORLANDC" "$C/BORLANDC"
ln -sfn "$REPO/apps-proprietary/BP"       "$C/BP"
ln -sfn "$REPO/apps-proprietary/nc"       "$C/NC"
ln -sfn "$REPO/apps-boot/tc"              "$C/TC"

# C:\CONFIG.SYS overrides the bootfs default (the kernel reads C:\CONFIG.SYS
# first, then C:\BOOT\CONFIG.SYS). COMSPEC points at the bootfs COMMAND.COM;
# PATH covers DN/COMMAND (C:\BOOT), Turbo C, Borland C, Borland Pascal.
cat > "$C/CONFIG.SYS" <<'CFG'
COMSPEC=C:\BOOT\COMMAND.COM
PATH=C:\;C:\BOOT;C:\TC;C:\BORLANDC\BIN;C:\BP\BIN
ADLIB=A388
BLASTER=A220 I7 D1 H5 P330 T6
ULTRASND=240,1,1,5,5
ULTRADIR=C:\ULTRASND
CFG

echo
echo "Done. C: layout:"
ls -la "$C"
echo
echo "Games under C:\\GAMES:"
ls "$C/GAMES" | sed 's/^/  /'
