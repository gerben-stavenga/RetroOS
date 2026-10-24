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
# Source and output live on a private ext4 image. No file-sharing server is
# needed in this build action; TCC uses the same block-backed VFS as native boot.
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

# Extract the ext4 partition from the immutable build input into a sparse
# working volume. Modifying the input image would corrupt Bazel's shared cache.
read -r PART_START PART_BYTES < <(python3 - "$IMAGE" <<'PYIMAGE'
import struct, sys
with open(sys.argv[1], 'rb') as stream:
    stream.seek(0x1ce)
    entry = stream.read(16)
start, count = struct.unpack_from('<II', entry, 8)
print(start * 512, count * 512)
PYIMAGE
)
dd if="$IMAGE" of="$STAGE/disk.img" bs=1M iflag=skip_bytes,count_bytes \
    skip="$PART_START" count="$PART_BYTES" conv=sparse status=none
VOLUME_ID="$(blkid -p -s UUID -o value "$STAGE/disk.img")"
cat > "$STAGE/BOOT.INI" <<INI
[bundle]
source=UUID=$VOLUME_ID
subdir=/
[mount "build"]
source=UUID=$VOLUME_ID
path=/
drive=C
access=rw
grant=/
INI
debugfs -w -f /dev/stdin "$STAGE/disk.img" > "$STAGE/stage.log" 2>&1 <<EOF
rm /RETROOS/BOOT.INI
write "$STAGE/BOOT.INI" /RETROOS/BOOT.INI
write "$STAGE/$GUEST_SRC" /$GUEST_SRC
EOF
"$HOST" --c-root / --cmd "TC/TCC.EXE $TCC_FLAGS $GUEST_SRC" --cwd / \
    "$STAGE/disk.img" < /dev/null > "$STAGE/run.log" 2>&1 || true
debugfs -R "dump /$GUEST_OUT $STAGE/$GUEST_OUT" "$STAGE/disk.img" \
    >> "$STAGE/stage.log" 2>&1

if [ ! -f "$STAGE/$GUEST_OUT" ]; then
    echo "interp_tcc: TCC did not produce $GUEST_OUT (stage kept: $STAGE)" >&2
    echo "---- run.log ----" >&2; tail -40 "$STAGE/run.log" >&2 2>/dev/null || true
    trap - EXIT
    exit 1
fi
cp "$STAGE/$GUEST_OUT" "$OUT"
