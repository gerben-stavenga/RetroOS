#!/usr/bin/env python3
"""Build a BIOS boot disk with RetroOS's own MBR loader and runtime files."""

import argparse
import os
import struct
import subprocess
import tarfile
import tempfile

SECTOR = 512
RUNTIME_LBA = 65536  # Leave 32 MiB for the bootloader and kernel TAR.
TOTAL_SECTORS = 128 * 1024 * 1024 // SECTOR


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.bundle, "rb") as source, open(args.out, "wb") as image:
        # pkg_tar places the bootloader in A, whose 512-byte TAR header is
        # stripped so its MBR code becomes sector zero.
        header = source.read(SECTOR)
        if header[:100].split(b"\0", 1)[0] != b"A":
            raise SystemExit("boot bundle must start with bootloader entry A")
        while chunk := source.read(1024 * 1024):
            image.write(chunk)
        if image.tell() > RUNTIME_LBA * SECTOR:
            raise SystemExit("boot bundle exceeds its 32 MiB partition")
        image.truncate(TOTAL_SECTORS * SECTOR)

    with open(args.out, "r+b") as image:
        image.seek(0x1BE)
        first = image.read(16)
        start = struct.unpack_from("<I", first, 8)[0]
        if first[4] != 0xDA or not 0 < start < RUNTIME_LBA:
            raise SystemExit("bootloader has an unexpected partition table")
        image.seek(0x1BE + 12)
        image.write(struct.pack("<I", RUNTIME_LBA - start))
        image.seek(0x1CE)
        image.write(struct.pack("<B3sB3sII", 0, b"\xfe\xff\xff", 0xEF,
                                b"\xfe\xff\xff", RUNTIME_LBA,
                                TOTAL_SECTORS - RUNTIME_LBA))

    with tempfile.TemporaryDirectory(prefix="retroos-native-boot-") as work:
        with tarfile.open(args.runtime) as archive:
            archive.extractall(work, filter="data")
        config = os.path.join(work, "mtoolsrc")
        with open(config, "w") as file:
            file.write("mtools_skip_check=1\n")
        env = dict(os.environ, MTOOLSRC=config)
        volume = f"{args.out}@@{RUNTIME_LBA * SECTOR}"
        subprocess.run(["mformat", "-i", volume, "-F", "-T",
                        str(TOTAL_SECTORS - RUNTIME_LBA), "::"],
                       check=True, env=env)
        for root, dirs, files in os.walk(work):
            if root == work:
                dirs.sort()
            relative = os.path.relpath(root, work)
            prefix = "" if relative == "." else "/" + relative.replace(os.sep, "/")
            for directory in sorted(dirs):
                subprocess.run(["mmd", "-D", "s", "-i", volume,
                                "::" + prefix + "/" + directory],
                               check=True, env=env)
            for name in sorted(files):
                if root == work and name == "mtoolsrc":
                    continue
                path = os.path.join(root, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    subprocess.run(["mcopy", "-D", "o", "-i", volume,
                                    path, "::" + prefix + "/" + name],
                                   check=True, env=env)


if __name__ == "__main__":
    main()
