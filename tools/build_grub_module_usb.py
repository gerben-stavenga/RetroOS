#!/usr/bin/env python3
"""Build an editable BIOS/UEFI USB disk for the GRUB module release.

Unlike the hybrid ISO, this image has an ordinary MBR with one FAT32
boot partition containing all release files. GRUB's menu is
/boot/grub/grub.cfg on partition 1.
"""

import argparse
import os
import shutil
import struct
import tempfile

from build_boot_disk import (GAP_SECTORS, SECTOR,
                             build_efi_binary, build_fat_partition,
                             install_grub_bios,
                             write_partition_table)


DISK_SIGNATURE = 0x5E77_0006
BOOT_VOLUME_SERIAL = 0x5E77_0001
PART_TYPE_FAT32_LBA = 0x0C
BOOT_MIB = 128
DIAGNOSTIC_GRUB_MODULES = (
    "all_video", "fat", "gzio",
    "multiboot2", "normal", "part_msdos", "search_fs_file", "videoinfo",
)


def module_closure(grub_lib, roots):
    dependencies = {}
    with open(os.path.join(grub_lib, "moddep.lst")) as source:
        for line in source:
            name, deps = line.split(":", 1)
            dependencies[name] = deps.split()
    selected = set()

    def add(name):
        if name in selected:
            return
        if name not in dependencies:
            raise ValueError(f"GRUB module missing from moddep.lst: {name}")
        selected.add(name)
        for dependency in dependencies[name]:
            add(dependency)

    for name in roots:
        add(name)
    return selected


def set_hidden_sectors(image, start):
    """Keep each FAT32 BPB consistent with its MBR partition offset."""
    with open(image, "r+b") as disk:
        disk.seek(start * SECTOR)
        vbr = disk.read(SECTOR)
        backup = struct.unpack_from("<H", vbr, 0x32)[0]
        for relative in (0, backup):
            disk.seek((start + relative) * SECTOR + 0x1C)
            disk.write(struct.pack("<I", start))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--games", help="optional games RAM module")
    ap.add_argument("--grub-cfg", required=True)
    ap.add_argument("--ini", help="editable RetroOS configuration alongside the modules")
    ap.add_argument("--license", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--grub-lib", default="/usr/lib/grub/i386-pc")
    ap.add_argument("--boot-mb", type=int, default=BOOT_MIB)
    ap.add_argument("--minimal-grub-modules", action="store_true")
    args = ap.parse_args()
    if args.boot_mb < 64:
        ap.error("FAT32 partition must be at least 64 MiB")

    boot_sectors = args.boot_mb * 1024 * 1024 // SECTOR
    total_sectors = GAP_SECTORS + boot_sectors

    with tempfile.TemporaryDirectory(prefix="retroos-module-usb.") as work:
        tree = os.path.join(work, "tree")
        boot = os.path.join(tree, "boot")
        os.makedirs(boot)
        for source, name in ((args.kernel, "kernel.elf"),
                             (args.base, "retroos-base.img.gz")):
            shutil.copyfile(source, os.path.join(boot, name))
        if args.games:
            shutil.copyfile(args.games, os.path.join(boot, "retroos-games.img.gz"))
        if args.ini:
            shutil.copyfile(args.ini, os.path.join(boot, "RETROOS.INI"))
        shutil.copyfile(args.license, os.path.join(tree, "THIRD_PARTY_LICENSES.md"))

        cfg = os.path.join(work, "grub.cfg")
        with open(cfg, "w") as out, open(args.grub_cfg) as source:
            out.write("insmod part_msdos\ninsmod fat\ninsmod search_fs_file\n")
            out.write("search --no-floppy --file /boot/kernel.elf --set=root\n")
            out.write(source.read())

        # The UEFI executable needs only enough embedded configuration to find
        # the FAT partition. Both firmware paths then read the editable file.
        bootstrap = os.path.join(work, "efi-bootstrap.cfg")
        with open(bootstrap, "w") as out:
            out.write("insmod part_msdos\ninsmod fat\ninsmod search_fs_file\n")
            out.write("insmod normal\ninsmod configfile\n")
            out.write("search --no-floppy --file /boot/kernel.elf --set=root\n")
            out.write("configfile /boot/grub/grub.cfg\n")

        with open(args.out, "wb") as out:
            out.truncate(total_sectors * SECTOR)
        write_partition_table(args.out, [
            (True, PART_TYPE_FAT32_LBA, GAP_SECTORS, boot_sectors),
        ])
        install_grub_bios(args.out, work, args.grub_lib)
        with open(args.out, "r+b") as disk:
            disk.seek(0x1B8)
            disk.write(struct.pack("<I", DISK_SIGNATURE))
        efi = build_efi_binary(work, bootstrap)
        grub_modules = (module_closure(args.grub_lib, DIAGNOSTIC_GRUB_MODULES)
                        if args.minimal_grub_modules else None)
        build_fat_partition(args.out, GAP_SECTORS, boot_sectors, work,
                            args.grub_lib, cfg, args.kernel, tree, efi,
                            root_kernel=False, grub_modules=grub_modules,
                            volume_serial=BOOT_VOLUME_SERIAL)
        set_hidden_sectors(args.out, GAP_SECTORS)

    print(f"USB image {args.out}: FAT32 LBA p1 at LBA {GAP_SECTORS}")


if __name__ == "__main__":
    main()
