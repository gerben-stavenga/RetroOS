#!/usr/bin/env python3
"""Stage and install a matched RetroOS GRUB module boot on an existing Linux system."""

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
STAGE_ROOT = ROOT / "build" / "grub-module-install"
MANAGED = Path("/etc/grub.d/42_retroos_module")
ESP_TYPES = {"0xef", "ef", "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"}
UUID_FORMAT = re.compile(r"(?:[0-9a-fA-F]{4}-[0-9a-fA-F]{4}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\Z")


def output(*args):
    return subprocess.check_output(args, text=True)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def filesystem(path):
    return json.loads(output("findmnt", "--json", "--target", str(path),
                             "--output", "UUID,FSTYPE,TARGET,FSROOT"))["filesystems"][0]


def candidates():
    """Recognizable physical FAT/ext4 volumes, excluding USB and EFI partitions."""
    devices = json.loads(output("lsblk", "-J", "-b", "-o",
                                "NAME,PATH,FSTYPE,UUID,SIZE,TYPE,PARTTYPE,TRAN,MOUNTPOINTS"))["blockdevices"]
    found = []

    def visit(node, usb=False):
        usb = usb or node.get("tran") == "usb"
        fstype = (node.get("fstype") or "").lower()
        uuid = node.get("uuid") or ""
        parttype = (node.get("parttype") or "").lower()
        if (not usb and node.get("type") in {"disk", "part"}
                and fstype in {"vfat", "ext4"} and UUID_FORMAT.fullmatch(uuid)
                and parttype not in ESP_TYPES):
            found.append({"path": node["path"], "uuid": uuid, "fstype": fstype,
                          "size": node["size"], "mountpoints": node.get("mountpoints") or []})
        for child in node.get("children") or []:
            visit(child, usb)

    for device in devices:
        visit(device)
    return found


def choose_c_volume(volumes, requested):
    if requested:
        if not UUID_FORMAT.fullmatch(requested):
            raise ValueError("--c-uuid must be a FAT or ext4 filesystem UUID")
        matches = [v for v in volumes if v["uuid"].lower() == requested.lower()]
    else:
        matches = volumes
    if len(matches) == 1:
        return matches[0]
    listing = "\n".join(f"  {v['path']} {v['fstype']} {v['uuid']} ({v['size'] // (1024**2)} MiB)"
                        for v in volumes) or "  none"
    raise ValueError(f"Select one C: volume with --c-uuid. Candidates:\n{listing}")


def choose_c_for_host(volumes, requested, c_ram, linux_root_fstype):
    if c_ram and requested:
        raise ValueError("Choose either --c-ram or --c-uuid")
    if c_ram or (not requested and linux_root_fstype == "btrfs"):
        return None
    if not volumes:
        if requested:
            raise ValueError(f"C: UUID not found: {requested}")
        return None
    return choose_c_volume(volumes, requested)


def validate_c_dir(path):
    parts = path.split("/")
    if (len(path) >= 128 or len(parts) < 2 or parts[0] or
            any(not part or part in {".", ".."} or
                not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts[1:])):
        raise ValueError("--c-dir must be a canonical absolute directory path under the ext4 volume")
    return path


def grub_path(destination, mount):
    """Translate a Linux path to a path relative to GRUB's filesystem root."""
    target = Path(mount["target"]).resolve()
    rel = destination.resolve().relative_to(target)
    fsroot = Path(mount["fsroot"].lstrip("/"))
    path = "/" + (fsroot / rel).as_posix().lstrip("/")
    if not re.fullmatch(r"/[A-Za-z0-9_@./-]+", path):
        raise ValueError(f"GRUB cannot use this path: {path}")
    return path


def grub_entries(plan):
    uuid = plan["boot_uuid"]
    base = plan["grub_release"]
    args = [f"retroos.c-uuid={plan['c_uuid']}"] if plan["c_uuid"] else []
    if plan.get("c_dir"):
        args.append(f"retroos.c-root={plan['c_dir']}")
    if plan.get("root_uuid"):
        args.append(f"retroos.root={plan['root_uuid']}")
    entries = []
    for label, overlay in (("protected disk", " ram-overlay"), ("persistent disk", "")):
        kernel_args = " ".join(args + (["ram-overlay"] if overlay else []))
        kernel_line = f"    multiboot2 {base}/kernel.elf" + (f" {kernel_args}" if kernel_args else "")
        entries.append(f'''menuentry "RetroOS ({label})" {{
    insmod part_gpt
    insmod part_msdos
    insmod ext2
    insmod fat
    insmod btrfs
    insmod multiboot2
    insmod gzio
    search --no-floppy --fs-uuid --set=root {uuid}
{kernel_line}
    if [ "$grub_platform" = "pc" ]; then
        set gfxpayload=text
    else
        insmod all_video
        set gfxmode=auto
        set gfxpayload=auto
    fi
    module2 {base}/retroos-base.img.gz retroos.mount=/
    boot
}}
''')
    return "\n".join(entries)


def grub_config_path():
    for path in (Path("/boot/grub/grub.cfg"), Path("/boot/grub2/grub.cfg")):
        if path.is_file():
            return path
    raise ValueError("existing GRUB configuration not found under /boot/grub or /boot/grub2")


def c_home(volume, c_dir="/home/retroos"):
    if volume["fstype"] != "ext4":
        return None
    for mountpoint in volume["mountpoints"]:
        if not mountpoint:
            continue
        mount = filesystem(mountpoint)
        if (mount.get("uuid") or "").lower() == volume["uuid"].lower() and mount.get("fsroot") == "/":
            return str(Path(mountpoint) / c_dir.lstrip("/"))
    return None


def create_c_home(home):
    if home.exists():
        if not home.is_dir():
            raise ValueError(f"C: home is not a directory: {home}")
        return
    try:
        group = grp.getgrnam("retroos")
    except KeyError:
        subprocess.run(["groupadd", "--system", "retroos"], check=True)
        group = grp.getgrnam("retroos")
    home.mkdir(parents=True)
    os.chown(home, int(os.environ.get("SUDO_UID", "0")), group.gr_gid)
    home.chmod(0o2775)


def ensure_c_home(volume, c_dir="/home/retroos"):
    if volume["fstype"] != "ext4":
        return
    mounted_home = c_home(volume, c_dir)
    if mounted_home:
        create_c_home(Path(mounted_home))
        return
    with tempfile.TemporaryDirectory(prefix="retroos-c-") as temporary:
        subprocess.run(["mount", "-t", "ext4", "-o", "rw",
                        f"UUID={volume['uuid']}", temporary], check=True)
        try:
            mounted = filesystem(temporary)
            if (mounted.get("uuid") or "").lower() != volume["uuid"].lower() or mounted.get("fsroot") != "/":
                raise ValueError("Mounted C: volume does not match the selected ext4 UUID")
            create_c_home(Path(temporary) / c_dir.lstrip("/"))
        finally:
            subprocess.run(["umount", temporary], check=True)


def prepare(iso, destination, requested_c, requested_root, c_ram=False, requested_dir=None):
    if os.geteuid() == 0:
        raise PermissionError("prepare as a normal user; installation runs as root")
    if not iso.is_file():
        raise FileNotFoundError(f"ISO not found: {iso}")
    volumes = candidates()
    linux_root = filesystem("/")
    c_volume = choose_c_for_host(volumes, requested_c, c_ram, linux_root["fstype"])
    if requested_dir and (not c_volume or c_volume["fstype"] != "ext4"):
        raise ValueError("--c-dir requires an ext4 C: volume")
    c_dir = validate_c_dir(requested_dir or "/home/retroos") if c_volume and c_volume["fstype"] == "ext4" else None
    home = c_home(c_volume, c_dir) if c_dir else None
    if requested_root:
        if not UUID_FORMAT.fullmatch(requested_root) or len(requested_root) != 36:
            raise ValueError("--root-uuid requires an ext4 UUID")
        matches = [v for v in volumes if v["fstype"] == "ext4"
                   and v["uuid"].lower() == requested_root.lower()]
        if len(matches) != 1:
            raise ValueError("--root-uuid must identify one ext4 volume")
    existing = destination
    while not existing.exists():
        existing = existing.parent
    boot_fs = filesystem(existing)
    if not boot_fs.get("uuid") or boot_fs.get("fstype") not in {"ext4", "vfat", "btrfs"}:
        raise ValueError("destination needs a UUID-bearing ext4, FAT, or Btrfs filesystem readable by GRUB")
    if not Path("/etc/grub.d").is_dir():
        raise ValueError("/etc/grub.d is missing; install GRUB first")
    grub_cfg = grub_config_path()
    iso_digest = sha256(iso)
    release = destination / "releases" / iso_digest[:12]
    plan = {"iso_sha256": iso_digest, "release": str(release),
            "destination": str(destination), "boot_uuid": boot_fs["uuid"],
            "grub_release": grub_path(release, boot_fs), "c_uuid": c_volume["uuid"] if c_volume else None,
            "c_device": c_volume["path"] if c_volume else None,
            "c_fstype": c_volume["fstype"] if c_volume else None,
            "c_home": home, "c_dir": c_dir, "root_uuid": requested_root,
            "grub_config": str(grub_cfg)}
    stage = STAGE_ROOT / iso_digest[:12]
    stage.mkdir(parents=True, exist_ok=True)
    for name in ("kernel.elf", "retroos-base.img.gz"):
        subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(iso),
                        "-extract", "/boot/" + name, str(stage / name)],
                       stdout=subprocess.DEVNULL, check=True)
    entries = grub_entries(plan)
    (stage / "grub.cfg").write_text(entries)
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    (stage / "42_retroos_module").write_text('#!/bin/sh\nexec tail -n +3 "$0"\n' + entries)
    (stage / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    names = ("kernel.elf", "retroos-base.img.gz", "grub.cfg", "42_retroos_module", "plan.json")
    (stage / "checksums.json").write_text(json.dumps({name: sha256(stage / name) for name in names}, indent=2) + "\n")
    STAGE_ROOT.mkdir(parents=True, exist_ok=True)
    (STAGE_ROOT / "selected").write_text(str(stage) + "\n")
    selected = f"{c_volume['path']} ({c_volume['uuid']})" if c_volume else "RAM module"
    print(f"Prepared {stage}\nGRUB filesystem: {boot_fs['uuid']}\nC: {selected}")
    if c_volume and c_volume["fstype"] == "ext4":
        if home:
            print(f"Installation will ensure {home} exists for ext4 C:.")
        else:
            print(f"Installation will temporarily mount the selected ext4 volume and ensure {c_dir} exists.")
    print(f"Review {stage / 'grub.cfg'}, then run the installer as root.")


def install():
    if os.geteuid() != 0:
        raise PermissionError("installation requires root")
    stage = Path((STAGE_ROOT / "selected").read_text().strip()).resolve()
    if not stage.is_relative_to(STAGE_ROOT.resolve()):
        raise ValueError("staged path is outside the installer workspace")
    sums = json.loads((stage / "checksums.json").read_text())
    for name, expected in sums.items():
        if sha256(stage / name) != expected:
            raise ValueError(f"staged file changed: {name}; prepare again")
    plan = json.loads((stage / "plan.json").read_text())
    destination = Path(plan["destination"])
    existing = destination
    while not existing.exists():
        existing = existing.parent
    boot_fs = filesystem(existing)
    if boot_fs.get("uuid") != plan["boot_uuid"] or grub_path(Path(plan["release"]), boot_fs) != plan["grub_release"]:
        raise ValueError("GRUB destination changed; prepare again")
    if plan["c_uuid"]:
        c_volume = choose_c_volume(candidates(), plan["c_uuid"])
        if c_volume["fstype"] != plan["c_fstype"]:
            raise ValueError("C: filesystem type changed; prepare again")
    if str(grub_config_path()) != plan["grub_config"]:
        raise ValueError("GRUB configuration moved; prepare again")
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    if plan["c_uuid"]:
        ensure_c_home(c_volume, plan["c_dir"] or "/home/retroos")
    release = Path(plan["release"])
    release.parent.mkdir(parents=True, exist_ok=True)
    files = ("kernel.elf", "retroos-base.img.gz")
    if release.exists():
        for name in files:
            if not (release / name).is_file() or sha256(release / name) != sums[name]:
                raise ValueError(f"existing release is incomplete or changed: {release}")
    else:
        with tempfile.TemporaryDirectory(prefix=".retroos-", dir=release.parent) as temp:
            pending = Path(temp) / "release"
            pending.mkdir()
            for name in files:
                shutil.copyfile(stage / name, pending / name)
            pending.rename(release)
    for name in files:
        os.chown(release / name, 0, 0)
        (release / name).chmod(0o644)
    old_managed = MANAGED.read_bytes() if MANAGED.exists() else None
    if old_managed is not None:
        Path(str(MANAGED) + ".previous").write_bytes(old_managed)
    try:
        shutil.copyfile(stage / "42_retroos_module", MANAGED)
        MANAGED.chmod(0o755)
        if shutil.which("update-grub"):
            subprocess.run(["update-grub"], check=True)
        else:
            command = shutil.which("grub-mkconfig") or shutil.which("grub2-mkconfig")
            if not command:
                raise ValueError("grub-mkconfig is missing")
            subprocess.run([command, "-o", plan["grub_config"]], check=True)
    except Exception:
        if old_managed is None:
            MANAGED.unlink(missing_ok=True)
        else:
            MANAGED.write_bytes(old_managed)
            MANAGED.chmod(0o755)
        raise
    print("Installed GRUB entries for RetroOS (protected disk) and RetroOS (persistent disk).")
    print("No partition was formatted, and no reboot was performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="stage files and GRUB entries for review")
    parser.add_argument("--iso", type=Path, default=ROOT / "bazel-bin/retroos_grub_module.iso")
    parser.add_argument("--destination", type=Path, default=Path("/boot/retroos"))
    parser.add_argument("--c-uuid", help="C: filesystem UUID; required when several candidates exist")
    parser.add_argument("--c-ram", action="store_true", help="use the RAM module for C:")
    parser.add_argument("--c-dir", help="directory inside selected ext4 C: volume (default: /home/retroos)")
    parser.add_argument("--root-uuid", help="optional ext4 UUID for Linux /")
    args = parser.parse_args()
    if args.prepare:
        prepare(args.iso.resolve(), args.destination.resolve(), args.c_uuid, args.root_uuid, args.c_ram, args.c_dir)
    else:
        install()


if __name__ == "__main__":
    main()
