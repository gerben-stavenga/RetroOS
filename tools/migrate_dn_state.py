#!/usr/bin/env python3
"""Separate DN's writable state on an offline C: directory or shared data image.

Copies old state without deleting it or replacing existing CONFIG/DN files.
Usage: tools/migrate_dn_state.py /home/retroos
       tools/migrate_dn_state.py --image build/data.bin
"""
import argparse
import fcntl
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = {"COM", "PRG", "OVR", "DLG", "LNG", "HLP"}
TEMPORARY = {"FLG", "SWP", "TMP", "BAK"}
DEFAULTS = {"EDT", "EXT", "HGL", "MNU", "VWR", "XRN"}


def migrate(root):
    if not root.is_dir():
        raise ValueError(f"C: directory does not exist: {root}")
    state = root / "CONFIG" / "DN"
    state.mkdir(parents=True, exist_ok=True)
    (root / "TEMP").mkdir(exist_ok=True)
    # Earlier refactors used both names. Prefer RETROOS, then the older BOOT.
    for old in (root / "RETROOS" / "DN", root / "BOOT" / "DN"):
        if not old.is_dir():
            continue
        for source in old.iterdir():
            if source.is_file() and source.suffix.upper().lstrip(".") not in RUNTIME | TEMPORARY:
                target = state / source.name.upper()
                if not target.exists():
                    shutil.copyfile(source, target)
    for source in (ROOT / "apps-boot" / "dn").iterdir():
        target = state / source.name
        if source.suffix.lstrip(".") in DEFAULTS and not target.exists():
            shutil.copyfile(source, target)
    # COMMAND.COM's writable launch policy belongs with the other settings.
    loadfix = root / "CONFIG" / "LOADFIX.CFG"
    if not loadfix.exists():
        sources = [root / "RETROOS" / "LOADFIX.CFG", root / "BOOT" / "LOADFIX.CFG",
                   ROOT / "tools" / "command" / "LOADFIX.CFG"]
        source = next((p for p in sources if p.is_file()), None)
        if source:
            shutil.copyfile(source, loadfix)
    config = root / "CONFIG.SYS"
    seed_config = ROOT / "etc" / "CONFIG.SYS"
    lines = (config if config.exists() else seed_config).read_bytes().splitlines()
    lines = [line.replace(b"C:\\BOOT", b"C:\\RETROOS") for line in lines]
    lines = [line for line in lines if line.split(b"=", 1)[0].strip().upper()
             not in (b"DN", b"DNSWP", b"TEMP")]
    # DN.COM takes the first DN/DNSWP variable as its flag-file directory.
    lines = [b"DNSWP=C:\\TEMP", b"TEMP=C:\\TEMP", b"DN=C:\\CONFIG\\DN"] + lines
    config.write_bytes(b"\r\n".join(lines) + b"\r\n")
    # The ext4 backend authorizes writes using the C: root's group.
    for path in [root / "CONFIG", state, root / "TEMP", config, *state.iterdir(), *([loadfix] if loadfix.exists() else [])]:
        shutil.chown(path, group=root.stat().st_gid)
        path.chmod(path.stat().st_mode | 0o020)


def migrate_image(image):
    # Same lock as run.sh: never edit a live emulator's filesystem.
    with open(str(image) + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with image.open("rb") as stream:
            mbr = stream.read(512)
        if len(mbr) != 512 or mbr[510:] != b"\x55\xaa" or mbr[450] not in (0x0B, 0x0C):
            raise ValueError("expected a shared data image with FAT32 partition 1")
        offset = struct.unpack_from("<I", mbr, 454)[0] * 512
        volume = f"{image}@@{offset}"

        def exists(path):
            return subprocess.run(["mdir", "-i", volume, "::/" + path],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

        def copy(*args):
            subprocess.run(["mcopy", "-i", volume, *map(str, args)], check=True)

        with tempfile.TemporaryDirectory(prefix="retroos-dn-state-") as temp:
            root = Path(temp)
            for path in ("CONFIG.SYS", "CONFIG", "RETROOS/DN", "BOOT/DN", "RETROOS/LOADFIX.CFG", "BOOT/LOADFIX.CFG"):
                if exists(path):
                    dest = root / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    copy("-s", "::/" + path, dest)
            migrate(root)
            for path in ("CONFIG", "CONFIG/DN", "TEMP"):
                if not exists(path):
                    subprocess.run(["mmd", "-i", volume, "::/" + path], check=True)
            for source in (root / "CONFIG" / "DN").iterdir():
                copy("-o", source, "::/CONFIG/DN/" + source.name)
            copy("-o", root / "CONFIG" / "LOADFIX.CFG", "::/CONFIG/LOADFIX.CFG")
            copy("-o", root / "CONFIG.SYS", "::/CONFIG.SYS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="store_true")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        (migrate_image if args.image else migrate)(args.path)
    except BlockingIOError:
        parser.exit(1, "data image is in use; stop its emulator before migrating DN state\n")
    print(f"DN state configured at C:\\CONFIG\\DN; temporary files at C:\\TEMP ({args.path})")


if __name__ == "__main__":
    main()
