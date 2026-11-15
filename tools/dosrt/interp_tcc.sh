#!/bin/bash
# Bazel genrule ACTION (not run by hand): compile a Turbo C source into a DOS
# binary by running TCC inside RetroOS on the *interpreter* backend
# (retroos-host) — headless, no QEMU.
#
#   interp_tcc.sh <retroos-host> <tc.tar> <src.c> <out> [tcc flags…]
#
# The guest source name is the uppercased basename of <src.c> (must be 8.3);
# the guest output name is the basename of <out> — TCC's emission must match
# (e.g. `-ms` STUB.C → STUB.EXE, `-mt -lt` COMMAND.C → COMMAND.COM). Flags
# default to `-ms` (small model MZ .EXE, what the dosrt stub packing needs).
#
# Source and output live in a private host directory.
set -e -o pipefail

HOST="$1"; COMPILER="$2"; SRC="$3"; OUT="$4"
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

tar -xf "$COMPILER" -C "$STAGE"
chmod -R u+w "$STAGE"
mkdir -p "$STAGE/RETROOS"
cat > "$STAGE/RETROOS/RETROOS.INI" <<'INI'
[environment]
PATH=C:\TC
INI
if [ -c /dev/retroos-control ]; then
    # RetroOS already provides the DOS execution environment. Use the exact
    # compiler bytes from the build input in an isolated working directory.
    # Linux hosts use the interpreter below because they cannot execute MZ.
    (
        cd "$STAGE"
        PATH=TC ./TC/TCC.EXE $TCC_FLAGS '-ITC\INCLUDE' '-LTC\LIB' "$GUEST_SRC"
    ) < /dev/null > "$STAGE/run.log" 2>&1 || true
else
    "$HOST" --c-root / --cmd "TC/TCC.EXE $TCC_FLAGS -ITC\INCLUDE -LTC\LIB $GUEST_SRC" --cwd / \
        "$STAGE" < /dev/null > "$STAGE/run.log" 2>&1 || true
fi

if [ ! -f "$STAGE/$GUEST_OUT" ]; then
    echo "interp_tcc: TCC did not produce $GUEST_OUT (stage kept: $STAGE)" >&2
    echo "---- run.log ----" >&2; tail -40 "$STAGE/run.log" >&2 2>/dev/null || true
    trap - EXIT
    exit 1
fi
cp "$STAGE/$GUEST_OUT" "$OUT"
