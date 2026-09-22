#!/usr/bin/env python3
"""Build the PERSISTENT data disk: one C: shared by RetroOS and FreeDOS.

This is the disk that survives.  The build seeds it once; after that it is the
user's, and run.sh never rewrites it wholesale.  The boot disk carries
everything the build owns (tools/build_boot_disk.py).

Layout:

    LBA 0           FreeDOS MBR (bootnorm.asm) + partition table
    p1 @ LBA 63     FAT32, type 0x0C, ACTIVE -- C: in BOTH worlds:
                        KERNEL.SYS, COMMAND.COM, FDCONFIG.SYS   FreeDOS boots it
                        GAMES/, TC/, BORLANDC/, CD/, ...        the DOS world
    p2              ext4 -- the Linux personality's '/' (busybox userland)

Why one FAT volume for both: FreeDOS has no VFS and reads only FAT, so the
only way a game is playable under both systems is for both to see the same
bytes at the same path.  Paths baked in at install time (SLIP5000/CONFIG.INI
holds C:\\GAMES\\SLIP5000; TOMBPATH.TXT holds C:\\TOMBRAID) make the drive
letter a permanent commitment, so C: must be C: on both sides -- which it is,
because FreeDOS letters the first DOS-typed primary partition and the boot
disk's ESP is type 0xEF, which DOS skips.

FreeDOS uses FDCONFIG.SYS; RetroOS keeps its key=value startup settings
in CONFIG/CONFIG.SYS.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

SECTOR = 512
MIB = 1024 * 1024
ALIGN = 2048                    # 1 MiB alignment for both partitions
PART_TYPE_FAT32_LBA = 0x0C
PART_TYPE_LINUX = 0x83

# The BPB is everything the boot code must NOT supply itself: geometry written
# by mformat.  FAT32 runs from 0x0B through the filesystem-type string at 0x5A.
BPB_START = 0x0B
BPB_END = 0x5A
HIDDEN_SECTORS = 0x1C           # u32 in the BPB: the partition's start LBA


def run(cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def nasm(src, out):
    run(["nasm", src, "-o", out])
    if os.path.getsize(out) != SECTOR:
        sys.exit("%s assembled to %d bytes, expected one %d-byte sector"
                 % (src, os.path.getsize(out), SECTOR))
    return out


def mtools_cfg(work):
    path = os.path.join(work, "mtoolsrc")
    with open(path, "w") as f:
        f.write("mtools_skip_check=1\n")
    return path


def bios_heads(total_sectors):
    """The head count a BIOS reports for a disk of this size.

    The classic LBA-assist translation: 63 sectors per track, and the smallest
    head count from 16/32/64/128/255 that keeps the cylinder count under 1024.
    This is not cosmetic -- FreeDOS recomputes CHS from the LBA fields using
    the geometry it was handed and prints "using suspect partition ... with
    calculated values" on every boot when the stored triple disagrees.  A
    0xFE/0xFF 'ignore me' sentinel does not satisfy it either; the numbers
    have to actually match.
    """
    for heads in (16, 32, 64, 128):
        if total_sectors <= 1024 * heads * 63:
            return heads
    return 255


def chs(lba, heads, spt=63):
    """Encode an LBA as CHS, saturating at the 1023-cylinder ceiling."""
    cyl, rem = divmod(lba, heads * spt)
    head, sec = divmod(rem, spt)
    if cyl > 1023:
        cyl, head, sec = 1023, heads - 1, spt - 1
    return bytes([head, ((cyl >> 2) & 0xC0) | (sec + 1), cyl & 0xFF])


def write_mbr(image, mbr_code, entries, heads):
    """FreeDOS's MBR code + our partition table.

    Only the first 440 bytes of the assembled sector are code; the rest is the
    table area, which we own.
    """
    with open(mbr_code, "rb") as f:
        code = f.read(440)
    with open(image, "r+b") as f:
        f.seek(0)
        f.write(code)
        f.seek(0x1B8)
        f.write(struct.pack("<I", 0x5E77_0005))   # disk signature
        f.write(b"\x00\x00")
        for i, (active, ptype, start, count) in enumerate(entries):
            f.seek(0x1BE + 16 * i)
            f.write(struct.pack("<B3sB3sII", 0x80 if active else 0x00,
                                chs(start, heads), ptype,
                                chs(start + count - 1, heads),
                                start, count))
        f.seek(0x1FE)
        f.write(b"\x55\xaa")


def install_vbr(image, start, vbr_bin):
    """Splice FreeDOS's boot code onto mformat's BPB.

    This is what SYS.COM does: the geometry in the BPB has to stay exactly as
    the formatter wrote it, while the code around it becomes FreeDOS's.  Get
    this backwards and the volume mounts fine and then boots to garbage.
    """
    with open(vbr_bin, "rb") as f:
        boot = bytearray(f.read())
    with open(image, "r+b") as f:
        f.seek(start * SECTOR)
        formatted = bytearray(f.read(SECTOR))

        boot[BPB_START:BPB_END] = formatted[BPB_START:BPB_END]
        # mformat writes hidden-sectors relative to the image it formatted, so
        # formatting through an @@offset can leave it zero.  The boot code adds
        # it to every LBA it reads: wrong here means reading the wrong disk
        # region entirely.
        struct.pack_into("<I", boot, HIDDEN_SECTORS, start)
        boot[0x1FE:0x200] = b"\x55\xaa"

        f.seek(start * SECTOR)
        f.write(boot)

        # FAT32 keeps a backup boot sector (BPB offset 0x32, usually sector 6).
        backup = struct.unpack_from("<H", boot, 0x32)[0]
        if 0 < backup < 16:
            f.seek((start + backup) * SECTOR)
            f.write(boot)


def populate_fat(image, start, sectors, tree, freedos_dir, work, heads):
    env = dict(os.environ, MTOOLSRC=mtools_cfg(work))
    at = "%s@@%d" % (image, start * SECTOR)

    # Geometry must be stated, not left to mformat: FreeDOS takes heads and
    # sectors-per-track from the BPB and cross-checks the MBR's CHS against
    # them, so a formatter-invented geometry produces the "suspect partition"
    # warning even when the LBA fields are perfect.  Same numbers as the
    # partition table (see bios_heads).
    run(["mformat", "-i", at, "-F", "-v", "RETROOS",
         "-h", str(heads), "-s", "63", "-T", str(sectors), "::"], env=env)

    def mmd(path):
        subprocess.run(["mmd", "-D", "s", "-i", at, "::" + path],
                       env=env, stderr=subprocess.DEVNULL)

    def mcopy(src, dest):
        run(["mcopy", "-D", "o", "-i", at, src, "::" + dest], env=env)

    # FreeDOS system files first, so KERNEL.SYS lands at the head of the root
    # directory the way SYS.COM would leave it.
    for name in ("KERNEL.SYS", "COMMAND.COM"):
        mcopy(os.path.join(freedos_dir, name), "/" + name)

    # FreeDOS reads FDCONFIG.SYS in preference to CONFIG.SYS, which is what
    # keeps FreeDOS startup separate from RetroOS CONFIG/CONFIG.SYS.
    fdconfig = os.path.join(work, "FDCONFIG.SYS")
    with open(fdconfig, "w", newline="\r\n") as f:
        f.write("DOS=HIGH\n")
        f.write("FILES=40\n")
        f.write("BUFFERS=20\n")
        f.write("SHELLHIGH=C:\\COMMAND.COM C:\\ /P /E:512\n")
    mcopy(fdconfig, "/FDCONFIG.SYS")

    # Runtime mount point; writable DN state lives separately in CONFIG/DN.
    mmd("/RETROOS")
    mmd("/CONFIG")
    mmd("/CONFIG/DN")
    mmd("/TEMP")

    if not tree:
        return
    for root, dirs, files in os.walk(tree):
        rel = os.path.relpath(root, tree)
        prefix = "" if rel == "." else "/" + rel.replace(os.sep, "/")
        for d in sorted(dirs):
            mmd(prefix + "/" + d)
        for name in sorted(files):
            src = os.path.join(root, name)
            if os.path.islink(src) or not os.path.isfile(src):
                continue
            mcopy(src, prefix + "/" + name)


def build_ext4(image, start, sectors, tree, work):
    """mkfs.ext4 cannot write at an offset, so build it beside and splice."""
    part = os.path.join(work, "linux.ext4")
    with open(part, "wb") as f:
        f.truncate(sectors * SECTOR)
    # VFS path walking needs real parent directories for the C: mount and
    # the boot-volume binding, even though their contents live elsewhere.
    root = os.path.join(work, "linux-root")
    if tree:
        shutil.copytree(tree, root, symlinks=True)
    os.makedirs(os.path.join(root, "home", "retroos"), exist_ok=True)
    os.makedirs(os.path.join(root, "bootfs"), exist_ok=True)
    os.makedirs(os.path.join(root, "tmp"), exist_ok=True)
    os.chmod(os.path.join(root, "tmp"), 0o1777)
    os.chmod(os.path.join(root, "home", "retroos"), 0o2775)
    cmd = ["mkfs.ext4", "-q", "-b", "4096", "-L", "RetroOS-root",
           "-d", root]
    run(cmd + [part])
    with open(image, "r+b") as out, open(part, "rb") as src:
        out.seek(start * SECTOR)
        shutil.copyfileobj(src, out, 8 * MIB)
    os.unlink(part)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dos-tree", help="directory published as C:\\")
    ap.add_argument("--linux-tree", help="directory published as Linux /")
    ap.add_argument("--freedos-src", default="freedos/sys",
                    help="bootnorm.asm, boot32lb.asm, KERNEL.SYS, COMMAND.COM")
    ap.add_argument("--fat-mb", type=int, default=3072)
    ap.add_argument("--ext4-mb", type=int, default=512)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    # LBA 63 -- cylinder 0, head 1, sector 1 -- for any BIOS geometry with 63
    # sectors per track, which is every geometry a DOS-era BIOS reports.  A
    # 1 MiB-aligned start cannot match CHS under a geometry chosen at runtime
    # from the disk's size, and FreeDOS warns loudly about the mismatch on
    # every boot ("using suspect partition ... with calculated values").
    fat_start = 63
    fat_sectors = args.fat_mb * MIB // SECTOR
    ext4_start = fat_start + fat_sectors
    ext4_start += (-ext4_start) % ALIGN
    ext4_sectors = args.ext4_mb * MIB // SECTOR
    total = ext4_start + ext4_sectors
    total += (-total) % (16 * 63)  # exact CHS capacity for 86Box/Bochs

    work = tempfile.mkdtemp(prefix="retroos-datadisk.")
    try:
        with open(args.out, "wb") as f:
            f.truncate(total * SECTOR)

        mbr = nasm(os.path.join(args.freedos_src, "bootnorm.asm"),
                   os.path.join(work, "mbr.bin"))
        vbr = nasm(os.path.join(args.freedos_src, "boot32lb.asm"),
                   os.path.join(work, "vbr.bin"))

        heads = bios_heads(total)
        populate_fat(args.out, fat_start, fat_sectors, args.dos_tree,
                     args.freedos_src, work, heads)
        install_vbr(args.out, fat_start, vbr)
        build_ext4(args.out, ext4_start, ext4_sectors, args.linux_tree, work)
        write_mbr(args.out, mbr, [
            (True, PART_TYPE_FAT32_LBA, fat_start, fat_sectors),
            (False, PART_TYPE_LINUX, ext4_start, ext4_sectors),
        ], heads)

        print("data disk %s: FAT32 C: %d MiB at LBA %d, ext4 / %d MiB at LBA %d"
              % (args.out, args.fat_mb, fat_start, args.ext4_mb, ext4_start))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
