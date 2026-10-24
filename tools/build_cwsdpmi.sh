#!/bin/bash
# Build CWSDPMI.EXE inside RetroOS using TC 2.01 + TASM (copied from BC++ 3.1).
#
# Stages cwsdpmi/ sources and the toolchain on a private ext4 volume,
# boots RetroOS with a `;`-separated cmdline that runs TASM on each .ASM,
# TCC on each .C, then TLINK to combine. RetroOS shuts down when the last
# command exits; outputs land in the stage dir.
#
# Note: TCC 2.01 generates 8086/286 code only. That's still fine here —
# BCC's `-3` flag only widens the C side with 386-only 16-bit opcodes
# (movzx, imul reg,imm). cwsdpmi's true 32-bit code is in the .ASM files
# (mswitch, tables, etc.) under USE32 segments, which TASM produces.

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$ROOT/freedos/cwsdpmi"
STAGE="${STAGE:-/tmp/cwsdpmi_build}"

rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in "$SRC_DIR"/*.c "$SRC_DIR"/*.h "$SRC_DIR"/*.asm "$SRC_DIR"/*.inc "$SRC_DIR"/3.RNG; do
    [ -f "$f" ] || continue
    cp "$f" "$STAGE/$(basename "$f" | tr '[:lower:]' '[:upper:]')"
done

ASM_FILES="CWSDSTUB DOUTILS DPMISIM MSWITCH START TABLES UEXTMEM UNLOAD VCPI XMS"
C_FILES="CONTROL DALLOC EXPHDLR PAGING UTILS VALLOC"
AFLAGS='/MX /T /DRUN_RING=3 /DI31PROT'
CFLAGS='-ms -O -DRUN_RING=3 -DI31PROT'

CMD=""
for asm in $ASM_FILES; do
    CMD="${CMD}TC/TASM.EXE $AFLAGS $asm.ASM;"
done
for c in $C_FILES; do
    CMD="${CMD}TC/TCC.EXE $CFLAGS -c $c.C;"
done
# constub.obj (control.c with -DSTUB) — TCC's -o sets the output OBJ name
CMD="${CMD}TC/TCC.EXE $CFLAGS -DSTUB -oCONSTUB -c CONTROL.C;"

# Final link of CWSDPMI.EXE. The full obj list overflows the 127-byte DOS
# PSP cmdline limit, so write it as a TLINK response file in the host dir
# and invoke TLINK with @CWSLNK.RSP. Format: line 1 = obj list (`+` joins,
# `,` ends), line 2 = exe name, line 3 = map name.
{
    echo 'START.OBJ+CONTROL.OBJ+DALLOC.OBJ+DOUTILS.OBJ+DPMISIM.OBJ+EXPHDLR.OBJ+'
    echo 'MSWITCH.OBJ+PAGING.OBJ+TABLES.OBJ+UEXTMEM.OBJ+UTILS.OBJ+UNLOAD.OBJ+'
    echo 'VALLOC.OBJ+XMS.OBJ+VCPI.OBJ'
    echo 'CWSDPMI.EXE'
    echo 'CWSDPMI.MAP'
} > "$STAGE/CWSLNK.RSP"
CMD="${CMD}TC/TLINK.EXE /3 /S /C /M @CWSLNK.RSP"

echo "Stage:   $STAGE"
echo "Cmdline: $CMD"
echo

cd "$ROOT"
bazelisk build //:image_min
bazelisk build //kernel:retroos-host --platforms=@platforms//host
VOLUME="$(mktemp -t retroos-cwsdpmi-volume.XXXXXX)"
trap 'rm -f "$VOLUME"' EXIT
read -r PART_START PART_BYTES < <(python3 - <<'PYIMAGE'
import struct
with open('bazel-bin/image_min.bin', 'rb') as stream:
    stream.seek(0x1ce)
    start, count = struct.unpack_from('<II', stream.read(16), 8)
print(start * 512, count * 512)
PYIMAGE
)
dd if=bazel-bin/image_min.bin of="$VOLUME" bs=1M iflag=skip_bytes,count_bytes \
    skip="$PART_START" count="$PART_BYTES" conv=sparse status=none
debugfs -R "rdump /TC $STAGE" "$VOLUME"
python3 test/disk_fixture.py --root "$STAGE" -- bazel-bin/kernel/retroos-host \
    --c-root / --cwd / --cmd "$CMD"
