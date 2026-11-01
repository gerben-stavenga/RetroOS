#!/usr/bin/env python3
"""Build a raw ext4 image for a GRUB Multiboot module."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

def run(cmd):
    subprocess.run(cmd, check=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contents", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-mb", type=int, default=128, help="minimum image size; grows to fit the runtime")
    ap.add_argument("--writable-root", action="store_true")
    args = ap.parse_args()
    if args.size_mb <= 0:
        ap.error("--size-mb must be positive")
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        os.mkdir(root)
        run(["tar", "xf", args.contents, "-C", root])
        if args.writable_root:
            run(["chmod", "-R", "u+w", root])
        else:
            retroos = os.path.join(root, "home", "retroos")
            if os.path.isdir(retroos):
                run(["chmod", "-R", "u+w", retroos])
        # Account for filesystem blocks, metadata and writable session space.
        # The requested size is a floor: runtime DLL additions must not make
        # smaller diagnostic and GRUB module builds run out of disk space.
        blocks = sum((p.stat().st_size + 4095) // 4096 if p.is_file() else 1
                     for p in Path(root).rglob("*") if not p.is_symlink())
        needed = blocks * 4096 * 9 // 8 + 8 * 1024 * 1024
        size_mb = max(args.size_mb, ((needed + 16 * 1024 * 1024 - 1) // (16 * 1024 * 1024)) * 16)
        run(["truncate", "-s", f"{size_mb}M", args.out])
        mkfs = ["mkfs.ext4", "-q", "-F", "-b", "4096", "-L", "RetroOS"]
        if args.writable_root:
            owner = os.stat(root)
            mkfs += ["-E", f"root_owner={owner.st_uid}:{owner.st_gid}"]
        mkfs += ["-d", root, args.out]
        run(mkfs)

if __name__ == "__main__":
    main()
