#!/bin/bash
# Bazel genrule ACTION (not run by hand): compile a Turbo C source into a
# DOS MZ .EXE by booting RetroOS in QEMU and running TCC inside it.
#
#   qemu_tcc.sh <image.bin> <hostfs.py> <src.c> <out.exe>
#
# Mounts a staging dir via hostfs (RW), boots the image with cmdline
# `TC/TCC.EXE -mt -lt STUB.C`; RetroOS shuts down when TCC exits. Source
# is staged CRLF + ASCII (TCC 2.01 silently aborts on LF/UTF-8). QEMU is
# a host tool, consistent with ld/nasm already used by genrules here.
set -e -o pipefail

# Safety-net cleanup. The real reap happens in-flow after qemu (see
# below) — Bazel's process-wrapper fails the action if a background
# child (hostfs.py) outlives the command, so it must be wait()'d, not
# just killed. This trap only covers early-exit paths.
trap '[ -n "${HFS_PID:-}" ] && { kill "$HFS_PID" 2>/dev/null; wait "$HFS_PID" 2>/dev/null; }; true' EXIT

IMAGE="$1"; HOSTFS="$2"; SRC="$3"; OUT="$4"
STAGE="$(mktemp -d)"
SOCK="$STAGE/hfs.sock"
LOG="$STAGE/debugcon.log"
# (EXIT trap incl. hostfs-kill is set at the top with diagnostics.)

# Stage source CRLF + ASCII under a DOS 8.3 name. CRLF is REQUIRED:
# in-OS TC 2.01 via the fw_cfg launcher silently aborts on raw LF
# ("Undefined symbol _main") — see memory feedback_dos_source_encoding.
# (The earlier asm "bad object file" was a separate no-shell issue, not
# this transform.) Interactive in-place compiles tolerate LF; this
# automated path does not.
sed 's/$/\r/' "$SRC" | LC_ALL=C tr -cd '\11\12\15\40-\176' > "$STAGE/STUB.C"

python3 "$HOSTFS" "$STAGE" "$SOCK" & HFS_PID=$!
# Wait for the hostfs socket to appear.
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

# Direct TCC via the kernel fw_cfg launcher (VFS path from FS root, as
# the kernel itself invokes it: startup.rs run_dos_program b"boot/TC/
# TCC.EXE"). stub.c MUST be pure C (no `asm`): this automated path has
# no shell/COMMAND.COM, so TCC's `asm`-restart (spawns TASM via INT 21h
# EXEC) hangs/panics here; pure C compiles reliably. cwd=host/ is where
# TCC reads STUB.C and writes STUB.EXE (the hostfs stage dir).
# `-ms` (small model) emits an MZ .EXE; `-mt` (tiny) would emit a .COM,
# which breaks the stub++payload MZ packing and caps the app at ~64 KB.
# NOT a hang when slow: TCC does hundreds of single-chunk hostfs serial
# round-trips (every include/OBJ/EXE byte), so the compile legitimately
# takes ~tens of seconds and DOES complete (hostfs log shows CREATE
# STUB.EXE + WRITE). 120s cap = enough to finish, still bounded so a
# genuine hang fails in ~2min rather than being masked.
timeout 120 qemu-system-i386 -cpu 486 \
    -drive "file=$IMAGE,format=raw,snapshot=on" \
    -m 64M -display none -no-reboot \
    -debugcon "file:$LOG" \
    -serial chardev:hostfs \
    -chardev "socket,id=hostfs,path=$SOCK,server=on,wait=off" \
    -fw_cfg "name=opt/cmdline,string=boot/TC/TCC.EXE -ms STUB.C" \
    -fw_cfg "name=opt/cwd,string=host/" \
    < /dev/null > "$STAGE/qemu.log" 2>&1 || true

# Stop AND reap hostfs now, in-flow. Bazel's process-wrapper fails the
# action (Exit 1) if the command leaves a live background child, even
# when bash returns 0 — so the EXIT-trap kill alone isn't enough; we
# must wait() it so no process lingers past script exit.
if [ -n "${HFS_PID:-}" ]; then
    kill "$HFS_PID" 2>/dev/null || true
    wait "$HFS_PID" 2>/dev/null || true
    HFS_PID=
fi

if [ ! -f "$STAGE/STUB.EXE" ]; then
    echo "qemu_tcc: TCC did not produce STUB.EXE (stage kept: $STAGE)" >&2
    echo "---- qemu.log ----" >&2; tail -10 "$STAGE/qemu.log" >&2 2>/dev/null || true
    echo "---- debugcon ----" >&2; tail -40 "$LOG" >&2 2>/dev/null || true
    exit 1
fi
cp "$STAGE/STUB.EXE" "$OUT"
rm -rf "$STAGE"
exit 0
