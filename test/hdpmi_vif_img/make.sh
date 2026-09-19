#!/bin/bash
# Build a ~16 MB bootable FreeDOS HDD with HDPMI32I+SETPVI+VIFIRET.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

HDD="${HDD_IMG:-freedos/freedos_hdd.img}"
[ -f "$HDD" ] || { echo "need $HDD (install FreeDOS once)" >&2; exit 1; }
[ -f freedos/hx/HDPMI32I.EXE ] || { echo "need freedos/hx/HDPMI32I.EXE" >&2; exit 1; }

nasm -f bin -o /tmp/SETPVI.COM test/dos/setpvi/setpvi.asm
nasm -f bin -o /tmp/VIFIRET.COM test/dos/vifiret/vifiret.asm

OUT_DIR="${OUT_DIR:-$ROOT/test/hdpmi_vif_img}"
IMG="$OUT_DIR/vifiret-hdpmi.img"
ZIP="$OUT_DIR/vifiret-hdpmi-freedos.zip"
mkdir -p "$OUT_DIR"

# 32 cyl × 16 heads × 63 spt = 32256 sectors = 15.75 MiB
CYL=32 HEADS=16 SPT=63
SECTS=$((CYL * HEADS * SPT))
PART_START=63
PART_SECTS=$((SECTS - PART_START))

python3 - "$HDD" "$IMG" "$SECTS" "$PART_START" "$PART_SECTS" "$HEADS" "$SPT" <<'PY'
import struct, sys
hdd, img_path, sects, start, psects, heads, spt = sys.argv[1], sys.argv[2], *[int(x) for x in sys.argv[3:]]
img = bytearray(sects * 512)
with open(hdd, "rb") as f:
    mbr = f.read(512)
    f.seek(start * 512)
    fdos_boot = f.read(512)
img[:440] = mbr[:440]
# CHS for start LBA 63: C=0 H=1 S=63
def chs(lba):
    c = lba // (heads * spt)
    r = lba % (heads * spt)
    h = r // spt
    s = (r % spt) + 1
    return bytes((h, (s & 63) | ((c >> 8) << 6), c & 255))
end = start + psects - 1
ent = bytearray(16)
ent[0] = 0x80
ent[1:4] = chs(start)
ent[4] = 0x06
ent[5:8] = chs(end)
struct.pack_into("<II", ent, 8, start, psects)
img[446:462] = ent
img[510:512] = b"\x55\xaa"
img[start * 512:(start + 1) * 512] = fdos_boot
open(img_path, "wb").write(img)
open("/tmp/vifiret-fdos-boot.bin", "wb").write(fdos_boot)
print(f"wrote {img_path} ({sects} sectors, part {psects} from {start})")
PY

mkfs.fat -F 16 -n VIFIRET --offset "$PART_START" "$IMG" >/dev/null

python3 - "$IMG" "$PART_START" "$PART_SECTS" /tmp/vifiret-fdos-boot.bin <<'PY'
# Keep mkfs BPB (cluster/FAT size); restore FreeDOS jump + boot code.
# mkfs.fat --offset still writes the whole-disk sector count and hidden=0.
import struct, sys
img, start, psects, bootp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
with open(img, "rb+") as f:
    f.seek(start * 512)
    fat = bytearray(f.read(512))
    fdos = open(bootp, "rb").read(512)
    out = bytearray(fdos)
    out[0x0B:0x3E] = fat[0x0B:0x3E]
    struct.pack_into("<H", out, 0x18, 63)       # sectors/track
    struct.pack_into("<H", out, 0x1A, 16)       # heads
    struct.pack_into("<I", out, 0x1C, start)    # hidden
    if psects < 65535:
        struct.pack_into("<H", out, 0x13, psects)
        struct.pack_into("<I", out, 0x20, 0)
    else:
        struct.pack_into("<H", out, 0x13, 0)
        struct.pack_into("<I", out, 0x20, psects)
    out[510:512] = b"\x55\xaa"
    f.seek(start * 512)
    f.write(out)
print("merged FreeDOS boot sector, hidden=%d total=%d" % (start, psects))
PY

FAT="$IMG@@$((PART_START * 512))"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mcopy -i "$HDD@@32256" ::KERNEL.SYS "$STAGE/KERNEL.SYS"
mcopy -i "$HDD@@32256" ::COMMAND.COM "$STAGE/COMMAND.COM"
mcopy -i "$HDD@@32256" ::FREEDOS/BIN/HIMEMX.EXE "$STAGE/HIMEMX.EXE"
mcopy -i "$HDD@@32256" ::FREEDOS/BIN/FDAPM.COM "$STAGE/FDAPM.COM"

crlf() { sed $'s/$/\r/' "$1" > "$2"; }
cat > "$STAGE/fdconfig.u" <<'EOF'
DOS=HIGH
LASTDRIVE=Z
BUFFERS=20
FILES=40
DEVICE=C:\HIMEMX.EXE
SHELL=C:\COMMAND.COM C:\ /E:1024 /P=C:\FDAUTO.BAT
EOF
cat > "$STAGE/fdauto.u" <<'EOF'
@ECHO OFF
C:
HDPMI32I.EXE -r -b
SETPVI.COM
IF ERRORLEVEL 1 GOTO FAIL
VIFIRET.COM /H
ECHO.
TYPE VIFIRET.LOG
ECHO.
ECHO PASS = IRETD left VIF set (correct).
ECHO FAIL stage 6 = IRETD loaded VIF from the frame (86Box bug).
PAUSE
GOTO END
:FAIL
ECHO SETPVI FAIL
PAUSE
:END
EOF
crlf "$STAGE/fdconfig.u" "$STAGE/FDCONFIG.SYS"
crlf "$STAGE/fdauto.u" "$STAGE/FDAUTO.BAT"

mcopy -D o -i "$FAT" "$STAGE/KERNEL.SYS" ::KERNEL.SYS
mcopy -D o -i "$FAT" "$STAGE/COMMAND.COM" ::COMMAND.COM
mcopy -D o -i "$FAT" "$STAGE/HIMEMX.EXE" ::HIMEMX.EXE
mcopy -D o -i "$FAT" "$STAGE/FDAPM.COM" ::FDAPM.COM
mcopy -D o -i "$FAT" "$STAGE/FDCONFIG.SYS" ::FDCONFIG.SYS
mcopy -D o -i "$FAT" "$STAGE/FDAUTO.BAT" ::FDAUTO.BAT
mcopy -D o -i "$FAT" freedos/hx/HDPMI32I.EXE ::HDPMI32I.EXE
mcopy -D o -i "$FAT" /tmp/SETPVI.COM ::SETPVI.COM
mcopy -D o -i "$FAT" /tmp/VIFIRET.COM ::VIFIRET.COM

mdir -i "$FAT" ::
ls -l "$IMG"
(cd "$OUT_DIR" && zip -9 -j "$ZIP" vifiret-hdpmi.img README.txt)
ls -l "$ZIP"
echo "artifact: $ZIP"
