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
mkdir -p "$C/OS2/DLL" "$C/OS2/APPS" "$C/WINDOWS/SYSTEM32" "$C/WINDOWS/APPS"

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

# Native OS/2 system DLLs and smoke applications share the DOS C: tree.
bazelisk build \
    //apps/os2/doscalls:doscalls_dll \
    //apps/os2/kbdcalls:kbdcalls_dll \
    //apps/os2/viocalls:viocalls_dll \
    //apps/os2/nls:nls_dll \
    //test/os2/hello:hello_lx \
    //test/os2/watcom_io:watcom_io
cp -f "$REPO/bazel-bin/apps/os2/doscalls/DOSCALLS.DLL" "$C/OS2/DLL/"
cp -f "$REPO/bazel-bin/apps/os2/kbdcalls/KBDCALLS.DLL" "$C/OS2/DLL/"
cp -f "$REPO/bazel-bin/apps/os2/viocalls/VIOCALLS.DLL" "$C/OS2/DLL/"
cp -f "$REPO/bazel-bin/apps/os2/nls/NLS.DLL" "$C/OS2/DLL/"
cp -f "$REPO/bazel-bin/test/os2/hello/hello_lx.exe" "$C/OS2/APPS/HELLO.EXE"
cp -f "$REPO/bazel-bin/test/os2/watcom_io/watcom_io.exe" "$C/OS2/APPS/WATCIO.EXE"

# Native Win32 replacement DLLs and console acceptance programs.
bazelisk build \
    //apps/windows/kernel32:kernel32_dll \
    //apps/windows/user32:user32_dll \
    //test/windows/hello:hello \
    //test/windows/watcom_io:watcom_io
cp -f "$REPO/bazel-bin/apps/windows/kernel32/KERNEL32.DLL" "$C/WINDOWS/SYSTEM32/"
cp -f "$REPO/bazel-bin/apps/windows/user32/USER32.DLL" "$C/WINDOWS/SYSTEM32/"
cp -f "$REPO/bazel-bin/test/windows/hello/hello.exe" "$C/WINDOWS/APPS/HELLO.EXE"
cp -f "$REPO/bazel-bin/test/windows/watcom_io/watcom_io.exe" "$C/WINDOWS/APPS/WATCIO.EXE"

# C:\ULTRASND — the GUS instrument patches ULTRADIR (below) points at. The
# disk image gets these from //:ultrasnd_tar; this drive needs them too, or
# DMX detects the GF1, finds no .PAT files, and silently disables music
# (sfx keep working — the "GUS in QEMU but not on metal" report).
#
# One directory link, not a link per patch. The repo names are lowercase and
# the image's tar mapping uppercases them, but DOS never sees either directly:
# every lookup goes through DFS's case-folding cache, which derives the 8.3
# alias (ACBASS.PAT) from whatever the real name is. 196 links to spell the
# names differently bought nothing.
ln -sfn "$REPO/apps/ultrasnd" "$C/ULTRASND"

# C:\BOOT — the DOS system directory (DN, COMMAND.COM, LOADFIX.CFG,
# SHELL.ELF). Ordinary content on C:, exactly like the packaged ext4 images
# carry it; the kernel embeds nothing, so without this there is no shell.
# A copy, not a symlink: these are build outputs under bazel-bin.
"$REPO/tools/install_boot_dir.sh" "$C"

# C:\CONFIG.SYS is the only config the kernel reads. COMSPEC points at
# C:\BOOT\COMMAND.COM; PATH covers DN/COMMAND (C:\BOOT), Turbo C, Borland C,
# Borland Pascal.
cat > "$C/CONFIG.SYS" <<'CFG'
COMSPEC=C:\BOOT\COMMAND.COM
PATH=C:\;C:\BOOT;C:\TC;C:\BORLANDC\BIN;C:\BP\BIN
ADLIB=A388
BLASTER=A220 I7 D1 H5 P330 T6
ULTRASND=240,3,3,5,5
ULTRADIR=C:\ULTRASND
CFG

echo
echo "Done. C: layout:"
ls -la "$C"
echo
echo "Games under C:\\GAMES:"
ls "$C/GAMES" | sed 's/^/  /'
