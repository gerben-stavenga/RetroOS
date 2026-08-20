#!/usr/bin/env python3
"""Build a raw ext4 image for a GRUB Multiboot module."""
import argparse
import os
import subprocess
import tempfile

def run(cmd):
    subprocess.run(cmd, check=True)

# Feature names outside lwext4's supported masks (EXT4_SUPPORTED_FINCOM /
# _FRO_COM). An unsupported incompat bit makes lwext4 refuse the mount; an
# unsupported ro_compat bit silently forces read-only. Full rationale in
# //BUILD.bazel, the ext4_root genrule.
UNSUPPORTED_FEATURES = (
    "metadata_csum_seed",
    "orphan_file",
    "bigalloc",
    "quota",
    "project",
    "verity",
    "shared_blocks",
    "encrypt",
    "casefold",
    "inline_data",
    "largedir",
)

def feature_opts(img):
    """`-O ^feature` for each name this mke2fs recognises (dry run, no write)."""
    opts = []
    for f in UNSUPPORTED_FEATURES:
        probe = subprocess.run(["mkfs.ext4", "-n", "-q", "-O", f"^{f}", img],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode == 0:
            opts += ["-O", f"^{f}"]
    return opts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contents", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-mb", type=int, default=128)
    ap.add_argument("--writable-root", action="store_true")
    args = ap.parse_args()
    if args.size_mb <= 0:
        ap.error("--size-mb must be positive")
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        os.mkdir(root)
        run(["tar", "xf", args.contents, "-C", root])
        if args.writable_root:
            run(["chmod", "-R", "g+w", root])
        else:
            retroos = os.path.join(root, "home", "retroos")
            if os.path.isdir(retroos):
                run(["chmod", "-R", "g+w", retroos])
        run(["truncate", "-s", f"{args.size_mb}M", args.out])
        mkfs = ["mkfs.ext4", "-q", "-F", "-b", "4096", "-L", "RetroOS"]
        mkfs += feature_opts(args.out)
        if args.writable_root:
            owner = os.stat(root)
            mkfs += ["-E", f"root_owner={owner.st_uid}:{owner.st_gid}"]
        mkfs += ["-d", root, args.out]
        run(mkfs)

if __name__ == "__main__":
    main()
