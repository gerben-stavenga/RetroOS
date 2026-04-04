#!/bin/bash
# Create a test disk image with both TAR and ext4 partitions.
# Takes the Bazel-built image and adds an ext4 partition with test files.
# No root/sudo required.
#
# Usage: ./make_ext4_test.sh [image.bin]

set -e

SRC="${1:-bazel-bin/image.bin}"
OUT="image_ext4_test.bin"

if [ ! -f "$SRC" ]; then
    echo "Source image not found: $SRC"
    echo "Run: bazelisk build //:image"
    exit 1
fi

cp "$SRC" "$OUT"
chmod +w "$OUT"

# Read TAR partition LBA from MBR entry 1
TAR_LBA=$(python3 -c "
import struct
data = open('$OUT','rb').read(512)
print(struct.unpack_from('<I', data, 0x1C6)[0])
")

# ext4 partition: start at sector 16384 (8MB offset), 48MB size
EXT4_START=16384
EXT4_SECTORS=98304  # 48MB
EXT4_SIZE_BYTES=$((EXT4_SECTORS * 512))

echo "TAR partition at sector $TAR_LBA"
echo "ext4 partition at sector $EXT4_START, ${EXT4_SIZE_BYTES} bytes"

# Create directory with test files to populate the ext4 image
POPULATE=$(mktemp -d)
mkdir -p "$POPULATE/GAMES"
echo "Hello from ext4!" > "$POPULATE/HELLO.TXT"
echo "This is a test file on the ext4 partition." > "$POPULATE/GAMES/README.TXT"
# Minimal DOS .COM: INT 21h/09h print + INT 21h/4Ch exit
printf '\xB4\x09\xBA\x0A\x01\xCD\x21\xB8\x00\x4C\xCD\x21Hello from ext4!\x24' > "$POPULATE/GAMES/TEST.COM"

# Create ext4 filesystem image with -d (populate from directory, no root needed)
EXT4_IMG=$(mktemp)
dd if=/dev/zero of="$EXT4_IMG" bs=512 count=$EXT4_SECTORS 2>/dev/null
mkfs.ext4 -q -b 1024 -L "RetroTest" -d "$POPULATE" "$EXT4_IMG"
rm -rf "$POPULATE"

# Write ext4 data into the disk image at the right offset
dd if="$EXT4_IMG" of="$OUT" bs=512 seek=$EXT4_START conv=notrunc 2>/dev/null
rm "$EXT4_IMG"

# Patch MBR partition entry 2 (at 0x1CE) with ext4 partition info
python3 -c "
import struct
with open('$OUT', 'r+b') as f:
    f.seek(0x1CE)
    entry = struct.pack('<BBBBBBBBII',
        0x00,           # status: inactive
        0, 0, 0,        # CHS start (unused)
        0x83,           # type: Linux
        0, 0, 0,        # CHS end (unused)
        $EXT4_START,    # LBA start
        $EXT4_SECTORS,  # size in sectors
    )
    f.write(entry)
"

echo ""
echo "Created $OUT with ext4 partition"
echo "  Partition 1: TAR at sector $TAR_LBA (type 0xDA)"
echo "  Partition 2: ext4 at sector $EXT4_START (type 0x83)"
echo ""
echo "Test files on ext4:"
echo "  /HELLO.TXT"
echo "  /GAMES/README.TXT"
echo "  /GAMES/TEST.COM"
echo ""
echo "Run:"
echo "  qemu-system-i386 -drive file=$OUT,format=raw,snapshot=on -debugcon stdio -no-reboot"
