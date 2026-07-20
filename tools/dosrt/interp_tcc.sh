#!/bin/bash
# Bazel genrule ACTION (not run by hand): compile a Turbo C source into a DOS
# binary by running TCC inside RetroOS on the *interpreter* backend
# (retroos-host) — headless, deterministic, no QEMU.
#
#   interp_tcc.sh <retroos-host> <image.bin> <src.c> <out> [tcc flags…]
#
# The guest source name is the uppercased basename of <src.c> (must be 8.3);
# the guest output name is the basename of <out> — TCC's emission must match
# (e.g. `-ms` STUB.C → STUB.EXE, `-mt -lt` COMMAND.C → COMMAND.COM). Flags
# default to `-ms` (small model MZ .EXE, what the dosrt stub packing needs).
#
# Replaces qemu_tcc.sh. The interpreter has a native hostfs (`--host DIR`, a
# COM1 transport to a host directory), so unlike the QEMU path there is no
# socket bridge (hostfs.py), no background process to reap, and no VM to boot —
# which is what made the old genrule flaky. Output is byte-identical to the
# QEMU build (same in-OS TCC, same input).
set -e -o pipefail

HOST="$1"; IMAGE="$2"; SRC="$3"; OUT="$4"
shift 4
TCC_FLAGS="${*:--ms}"
GUEST_SRC="$(basename "$SRC" | tr '[:lower:]' '[:upper:]')"
GUEST_OUT="$(basename "$OUT")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Stage source CRLF + ASCII under a DOS 8.3 name. CRLF is REQUIRED: in-OS TC
# 2.01 via the fw_cfg launcher silently aborts on raw LF ("Undefined symbol
# _main") — see memory feedback_dos_source_encoding. The source MUST be pure C
# (no `asm`): this automated path has no shell/COMMAND.COM for TCC's
# asm-restart.
sed 's/$/\r/' "$SRC" | LC_ALL=C tr -cd '\11\12\15\40-\176' > "$STAGE/$GUEST_SRC"

# Run TCC headless. `--host $STAGE` mounts the stage dir as the guest's hostfs
# (/host); cwd `host/` is where TCC reads the source and writes the output.
# The interpreter shuts down when TCC exits; no wall-clock cap is needed (it's
# deterministic, and Bazel's action timeout still bounds a real hang).
# --c-root / : the in-OS toolchain needs DOS C: = root, because TURBOC.CFG
# pins -IC:\TC\INCLUDE / -LC:\TC\LIB (the image's TC/ lives at the root). The
# normal-boot default (C: = /home/retroos) would hide C:\TC.
"$HOST" --host "$STAGE" \
    --c-root / \
    --cmd "TC/TCC.EXE $TCC_FLAGS $GUEST_SRC" --cwd "host/" \
    "$IMAGE" < /dev/null > "$STAGE/run.log" 2>&1 || true

if [ ! -f "$STAGE/$GUEST_OUT" ]; then
    echo "interp_tcc: TCC did not produce $GUEST_OUT (stage kept: $STAGE)" >&2
    echo "---- run.log ----" >&2; tail -40 "$STAGE/run.log" >&2 2>/dev/null || true
    trap - EXIT
    exit 1
fi
cp "$STAGE/$GUEST_OUT" "$OUT"
