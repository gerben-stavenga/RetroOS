#!/usr/bin/env python3
"""Pack the current DOS source payload into a disposable FAT16 C: image."""

import argparse
import os
import subprocess
import tarfile
import tempfile

MIB = 1024 * 1024
CLUSTER = 64 * 512


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rust-dos-games-") as work:
        tree = os.path.join(work, "tree")
        os.mkdir(tree)
        # Data CONFIG files override the boot bundle's defaults.
        for source in (args.runtime, args.data):
            with tarfile.open(source) as archive:
                archive.extractall(tree, filter="data")

        occupied = 0
        for root, dirs, files in os.walk(tree):
            occupied += len(dirs) * CLUSTER
            for name in files:
                size = os.path.getsize(os.path.join(root, name))
                occupied += max(1, (size + CLUSTER - 1) // CLUSTER) * CLUSTER
        # Leave room for save files. FAT16 with 32 KiB clusters remains below
        # its cluster limit throughout this range.
        size_mb = max(256, ((occupied * 5 // 4 + 128 * MIB + 64 * MIB - 1) // (64 * MIB)) * 64)
        if size_mb > 1920:
            raise SystemExit("DOS payload exceeds the FAT16 image size limit")
        sectors = size_mb * MIB // 512
        with open(args.out, "wb") as image:
            image.truncate(size_mb * MIB)

        config = os.path.join(work, "mtoolsrc")
        with open(config, "w") as file:
            file.write("mtools_skip_check=1\n")
        env = dict(os.environ, MTOOLSRC=config)
        volume = args.out
        subprocess.run(["mformat", "-i", volume, "-T", str(sectors),
                        "-c", "64", "-v", "RETROOS", "::"], check=True, env=env)
        for root, dirs, files in os.walk(tree):
            relative = os.path.relpath(root, tree)
            prefix = "" if relative == "." else "/" + relative.replace(os.sep, "/")
            for directory in sorted(dirs):
                subprocess.run(["mmd", "-D", "s", "-i", volume,
                                "::" + prefix + "/" + directory], check=True, env=env)
            for name in sorted(files):
                path = os.path.join(root, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    subprocess.run(["mcopy", "-D", "o", "-i", volume, path,
                                    "::" + prefix + "/" + name], check=True, env=env)


if __name__ == "__main__":
    main()
