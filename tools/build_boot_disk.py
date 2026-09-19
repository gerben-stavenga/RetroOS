#!/usr/bin/env python3
"""Build the RetroOS BOOT DISK — pure build output, rebuilt every launch.

This disk carries no state.  Everything on it comes from the current build, so
`--fresh` for it is just `rm`: there is nothing to preserve, diff or migrate.
Guest state lives on the separate data disk (tools/build_data_disk.py).

Layout:

    LBA 0           GRUB boot.img (+ our partition table at 0x1BE)
    LBA 1 .. 2047   GRUB core.img in the MBR gap
    p1 @ 1 MiB      FAT32, type 0xEF:
                        /boot/grub/{grub.cfg,i386-pc/*.mod}   BIOS GRUB
                        /EFI/BOOT/BOOTX64.EFI                 UEFI GRUB
                        /kernel.elf                           multiboot target
                        /BOOT/...                             mounted at C:\\BOOT

One FAT partition does three jobs: it is GRUB's prefix volume on BIOS, the EFI
System Partition on UEFI, and the source of C:\\BOOT in the dev loop.  Type
0xEF keeps DOS from assigning it a drive letter -- FreeDOS only lettertypes
01/04/06/0B/0C/0E -- which is what keeps the data disk's FAT as C: in both
worlds.  That type byte is load-bearing, not cosmetic.

GRUB is installed without loop mounts or root: boot.img and core.img are
written to the raw sectors and the modules are copied in with mtools, which is
the same privilege-free constraint run.sh's build_gpt_disk already works under.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

SECTOR = 512
GAP_SECTORS = 2048          # 1 MiB: GRUB's core.img lives here
PART_TYPE_ESP = 0xEF

# Offset in GRUB's boot.img of the 64-bit LBA where core.img starts.
# (GRUB_BOOT_MACHINE_KERNEL_SECTOR in grub's boot.h.)
BOOT_IMG_KERNEL_SECTOR = 0x5C

# Modules core.img needs before it can read its own prefix: enough to find the
# FAT partition on a BIOS disk and run a config from it.  Everything else is
# loaded as a .mod from /boot/grub at runtime.
CORE_MODULES = ["biosdisk", "part_msdos", "fat"]

GRUB_CFG = """\
set timeout={timeout}
set default=0

# The kernel's multiboot header asks for a linear framebuffer; GRUB can only
# satisfy that with a video driver loaded.  Harmless on BIOS.
insmod all_video
insmod efi_gop
set gfxmode=auto
set gfxpayload=keep

menuentry "RetroOS" {{
    search --no-floppy --file /kernel.elf --set=root
    multiboot /kernel.elf{cmdline}
    boot
}}

menuentry "FreeDOS (data disk)" {{
    insmod chain
    # The data disk's own FreeDOS MBR would do this too if you booted that disk
    # directly; this entry just saves changing the boot order.
    set root=(hd1)
    chainloader +1
    boot
}}
"""


def run(cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def mtools_cfg(work):
    """mtools refuses raw images with odd geometry unless told not to care."""
    path = os.path.join(work, "mtoolsrc")
    with open(path, "w") as f:
        f.write("mtools_skip_check=1\n")
    return path


def build_grub_cfg(work, timeout, cmdline):
    cfg = os.path.join(work, "grub.cfg")
    extra = (" " + cmdline) if cmdline else ""
    with open(cfg, "w") as f:
        f.write(GRUB_CFG.format(timeout=timeout, cmdline=extra))
    return cfg


def write_partition_table(image, entries):
    """Write MBR partition entries, preserving the boot code already at 0.

    CHS fields are filled with the 0xFE/0xFF 'use LBA' sentinel rather than
    real geometry: every consumer here (GRUB, OVMF, our own kernel) reads the
    LBA fields, and a wrong CHS is worse than an obviously-invalid one.
    """
    with open(image, "r+b") as f:
        for i, (active, ptype, start, count) in enumerate(entries):
            entry = struct.pack(
                "<B3sB3sII",
                0x80 if active else 0x00,
                b"\xfe\xff\xff",
                ptype,
                b"\xfe\xff\xff",
                start,
                count,
            )
            f.seek(0x1BE + 16 * i)
            f.write(entry)
        f.seek(0x1FE)
        f.write(b"\x55\xaa")


def install_grub_bios(image, work, grub_lib, cfg):
    """boot.img in sector 0, core.img in the gap, prefix on p1."""
    core = os.path.join(work, "core.img")
    run([
        "grub-mkimage",
        "-O", "i386-pc",
        "-o", core,
        "-p", "(hd0,msdos1)/boot/grub",
        "-c", cfg,
    ] + CORE_MODULES)

    core_sectors = (os.path.getsize(core) + SECTOR - 1) // SECTOR
    if core_sectors >= GAP_SECTORS - 1:
        sys.exit("core.img is %d sectors, does not fit in the %d-sector MBR gap"
                 % (core_sectors, GAP_SECTORS - 1))

    with open(os.path.join(grub_lib, "boot.img"), "rb") as f:
        boot_img = bytearray(f.read(SECTOR))
    # Point boot.img at core.img, which we place at LBA 1.
    struct.pack_into("<Q", boot_img, BOOT_IMG_KERNEL_SECTOR, 1)

    with open(image, "r+b") as f:
        # Bytes 0x00-0x1BD only: the partition table is written afterwards and
        # must not be clobbered by boot.img's own (empty) table area.
        f.seek(0)
        f.write(boot_img[:0x1BE])
        f.seek(SECTOR)
        with open(core, "rb") as c:
            f.write(c.read())
    return core_sectors


def build_fat_partition(image, start, sectors, work, grub_lib, cfg,
                        kernel, boot_tree, efi_binary):
    """Format p1 in place and populate it with mtools (no mounting)."""
    env = dict(os.environ, MTOOLSRC=mtools_cfg(work))
    at = "%s@@%d" % (image, start * SECTOR)

    run(["mformat", "-i", at, "-F", "-T", str(sectors), "::"], env=env)

    def mmd(path):
        subprocess.run(["mmd", "-D", "s", "-i", at, "::" + path],
                       env=env, stderr=subprocess.DEVNULL)

    def mcopy(src, dest):
        run(["mcopy", "-D", "o", "-i", at, src, "::" + dest], env=env)

    # GRUB's prefix volume (BIOS): modules the core loads at runtime.
    for d in ("/boot", "/boot/grub", "/boot/grub/i386-pc"):
        mmd(d)
    mcopy(cfg, "/boot/grub/grub.cfg")
    mods = [os.path.join(grub_lib, m) for m in sorted(os.listdir(grub_lib))
            if m.endswith((".mod", ".lst")) or m == "modinfo.sh"]
    run(["mcopy", "-D", "o", "-i", at] + mods + ["::/boot/grub/i386-pc/"],
        env=env)

    # UEFI: the ESP layout the firmware looks for unconditionally.
    mmd("/EFI")
    mmd("/EFI/BOOT")
    mcopy(efi_binary, "/EFI/BOOT/BOOTX64.EFI")

    mcopy(kernel, "/kernel.elf")

    # C:\BOOT in the dev loop, mounted over the data disk's own BOOT directory.
    if boot_tree:
        mmd("/BOOT")
        for root, dirs, files in os.walk(boot_tree):
            rel = os.path.relpath(root, boot_tree)
            prefix = "/BOOT" if rel == "." else "/BOOT/" + rel.replace(os.sep, "/")
            for d in sorted(dirs):
                mmd(prefix + "/" + d)
            for name in sorted(files):
                mcopy(os.path.join(root, name), prefix + "/" + name)


def build_efi_binary(work, cfg):
    """A standalone UEFI GRUB with its config in a memdisk.

    Standalone rather than prefix-based so the UEFI path needs nothing else on
    the partition -- the same cfg drives both firmwares.
    """
    out = os.path.join(work, "BOOTX64.EFI")
    embedded = os.path.join(work, "embedded.cfg")
    shutil.copyfile(cfg, embedded)
    run(["grub-mkstandalone", "-O", "x86_64-efi", "-o", out,
         "boot/grub/grub.cfg=" + embedded])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel", required=True, help="kernel.elf (multiboot)")
    ap.add_argument("--boot-tree", help="directory published as C:\\BOOT")
    ap.add_argument("--grub-lib", default="/usr/lib/grub/i386-pc")
    ap.add_argument("--size-mb", type=int, default=128)
    ap.add_argument("--timeout", type=int, default=0,
                    help="GRUB menu timeout; 0 boots RetroOS immediately")
    ap.add_argument("--cmdline", default="", help="appended to the multiboot line")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if not os.path.isdir(args.grub_lib):
        sys.exit("no GRUB i386-pc modules at %s (apt install grub-pc-bin)"
                 % args.grub_lib)

    total_sectors = args.size_mb * 1024 * 1024 // SECTOR
    part_start = GAP_SECTORS
    part_sectors = total_sectors - part_start

    work = tempfile.mkdtemp(prefix="retroos-bootdisk.")
    try:
        with open(args.out, "wb") as f:
            f.truncate(total_sectors * SECTOR)

        cfg = build_grub_cfg(work, args.timeout, args.cmdline)
        efi = build_efi_binary(work, cfg)

        # Partition table first: build_fat_partition formats through an offset
        # and install_grub_bios only touches 0x00-0x1BD, so ordering is free --
        # but the table must exist before grub-mkimage's prefix can resolve.
        write_partition_table(args.out, [(True, PART_TYPE_ESP,
                                          part_start, part_sectors)])
        core_sectors = install_grub_bios(args.out, work, args.grub_lib, cfg)
        build_fat_partition(args.out, part_start, part_sectors, work,
                            args.grub_lib, cfg, args.kernel, args.boot_tree, efi)

        print("boot disk %s: %d MiB, core.img %d sectors, FAT32 p1 at LBA %d"
              % (args.out, args.size_mb, core_sectors, part_start))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
