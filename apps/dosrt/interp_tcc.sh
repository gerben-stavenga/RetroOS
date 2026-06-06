#!/bin/bash
# Bazel genrule ACTION (not run by hand): compile a Turbo C source into a DOS
# MZ .EXE by running TCC inside RetroOS on the *interpreter* backend
# (retroos-host) — headless, deterministic, no QEMU.
#
#   interp_tcc.sh <retroos-host> <image.bin> <src.c> <out.exe>
#
# Replaces qemu_tcc.sh. The interpreter has a native hostfs (`--host DIR`, a
# COM1 transport to a host directory), so unlike the QEMU path there is no
# socket bridge (hostfs.py), no background process to reap, and no VM to boot —
# which is what made the old genrule flaky. Output is byte-identical to the
# QEMU build (same in-OS TCC, same input).
set -e -o pipefail

HOST="$1"; IMAGE="$2"; SRC="$3"; OUT="$4"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Stage source CRLF + ASCII under a DOS 8.3 name. CRLF is REQUIRED: in-OS TC
# 2.01 via the fw_cfg launcher silently aborts on raw LF ("Undefined symbol
# _main") — see memory feedback_dos_source_encoding. stub.c MUST be pure C (no
# `asm`): this automated path has no shell/COMMAND.COM for TCC's asm-restart.
sed 's/$/\r/' "$SRC" | LC_ALL=C tr -cd '\11\12\15\40-\176' > "$STAGE/STUB.C"

# Run TCC headless. `--host $STAGE` mounts the stage dir as the guest's hostfs
# (/host); cwd `host/` is where TCC reads STUB.C and writes STUB.EXE. `-ms`
# (small model) emits an MZ .EXE; `-mt` (tiny) would emit a .COM, which breaks
# the stub++payload MZ packing and caps the app at ~64 KB. The interpreter
# shuts down when TCC exits; no wall-clock cap is needed (it's deterministic,
# and Bazel's action timeout still bounds a real hang).
"$HOST" --host "$STAGE" \
    --cmd "boot/TC/TCC.EXE -ms STUB.C" --cwd "host/" \
    "$IMAGE" < /dev/null > "$STAGE/run.log" 2>&1 || true

if [ ! -f "$STAGE/STUB.EXE" ]; then
    echo "interp_tcc: TCC did not produce STUB.EXE (stage kept: $STAGE)" >&2
    echo "---- run.log ----" >&2; tail -40 "$STAGE/run.log" >&2 2>/dev/null || true
    trap - EXIT
    exit 1
fi
cp "$STAGE/STUB.EXE" "$OUT"
