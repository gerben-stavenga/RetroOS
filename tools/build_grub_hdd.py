#!/usr/bin/env python3
"""Assemble a GRUB-booted RetroOS hard-disk image.

Layout — one partition, no bespoke boot container:

    sector 0        GRUB boot.img + our MBR partition table
    sector 1..      GRUB core.img (biosdisk + part_msdos + ext2 + multiboot)
    sector 2048     ext4 root: /boot/kernel.elf, /boot/grub/grub.cfg, extras

GRUB's own `grub-install` wants a block device and `grub-bios-setup` is not
always packaged, so the two embed steps are done here instead. They are the
only fiddly part and they are small:

  * boot.img holds the LBA of core.img's first sector at offset 0x5c.
  * core.img's first sector (diskboot.img) ends with a block list describing
    where the REST of core.img lives: {start LBA: u64, sectors: u16, load
    segment: u16} at 0x1F4. Laying core.img down contiguously from sector 1
    makes that entry {2, sectors-1, 0x820}.
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile

SECTOR = 512
PART_START = 2048          # leaves 1 MiB for boot.img + core.img
BOOT_IMG_KERNEL_SECTOR = 0x5c
DISKBOOT_BLOCKLIST = 0x1F4
CORE_LOAD_SEGMENT = 0x820
# Enough to find the root, read ext4 and hand off via multiboot. `all_video`
# is what makes GRUB set the framebuffer mode the kernel's multiboot header
# asks for — without it the kernel comes up with no linear framebuffer.
GRUB_MODULES = [
    "biosdisk", "part_msdos", "ext2", "normal", "multiboot",
    "configfile", "echo", "ls", "all_video",
]


def run(cmd):
    subprocess.run(cmd, check=True)


def embed_grub(disk, grub_dir, prefix):
    """Write boot.img to sector 0 and a freshly built core.img from sector 1."""
    with tempfile.TemporaryDirectory() as tmp:
        core_path = os.path.join(tmp, "core.img")
        run(["grub-mkimage", "-O", "i386-pc", "-o", core_path, "-p", prefix,
             *GRUB_MODULES])

        boot = bytearray(open(os.path.join(grub_dir, "boot.img"), "rb").read())
        core = bytearray(open(core_path, "rb").read())
        core += b"\0" * (-len(core) % SECTOR)
        sectors = len(core) // SECTOR
        if 1 + sectors > PART_START:
            sys.exit(f"core.img is {sectors} sectors, does not fit before {PART_START}")

        struct.pack_into("<Q", boot, BOOT_IMG_KERNEL_SECTOR, 1)
        struct.pack_into("<Q", core, DISKBOOT_BLOCKLIST, 2)
        struct.pack_into("<H", core, DISKBOOT_BLOCKLIST + 8, sectors - 1)
        struct.pack_into("<H", core, DISKBOOT_BLOCKLIST + 10, CORE_LOAD_SEGMENT)

        with open(disk, "r+b") as f:
            f.write(boot)
            f.seek(SECTOR)
            f.write(core)


def write_partition_table(disk, start, sectors):
    """One 0x83 entry. GRUB's boot.img leaves 0x1BE..0x1FE for exactly this."""
    entry = bytearray(16)
    entry[0] = 0x80          # bootable
    entry[4] = 0x83          # Linux
    struct.pack_into("<I", entry, 8, start)
    struct.pack_into("<I", entry, 12, sectors)
    with open(disk, "r+b") as f:
        f.seek(0x1BE)
        f.write(bytes(entry) + bytes(48))
        f.seek(0x1FE)
        f.write(b"\x55\xAA")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--grub-cfg", required=True)
    ap.add_argument("--extras", required=True, help="extras tar for the ext4 root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-mb", type=int, default=1024)
    ap.add_argument("--grub-dir", default="/usr/lib/grub/i386-pc")
    args = ap.parse_args()

    part_sectors = args.size_mb * 1024 * 1024 // SECTOR

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        os.makedirs(os.path.join(root, "boot", "grub"))
        run(["tar", "xf", args.extras, "-C", root])
        run(["cp", args.kernel, os.path.join(root, "boot", "kernel.elf")])
        run(["cp", args.grub_cfg, os.path.join(root, "boot", "grub", "grub.cfg")])

        # Same rule as the legacy image: RetroOS writes a file only when it
        # belongs to the C: root's group AND carries g+w.
        retroos = os.path.join(root, "home", "retroos")
        if os.path.isdir(retroos):
            run(["chmod", "-R", "g+w", retroos])

        ext4 = os.path.join(tmp, "ext4.img")
        with open(ext4, "wb") as f:
            f.truncate(part_sectors * SECTOR)
        run(["mkfs.ext4", "-q", "-b", "4096", "-L", "RetroOS", "-d", root, ext4])

        with open(args.out, "wb") as f:
            f.truncate((PART_START + part_sectors) * SECTOR)
        run(["dd", f"if={ext4}", f"of={args.out}", "bs=512",
             f"seek={PART_START}", "conv=notrunc", "status=none"])

    embed_grub(args.out, args.grub_dir, "(hd0,msdos1)/boot/grub")
    write_partition_table(args.out, PART_START, part_sectors)


if __name__ == "__main__":
    main()
