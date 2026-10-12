#!/usr/bin/env python3
"""Stage and install a matched RetroOS GRUB module boot on an existing Linux system."""

import argparse
import configparser
from contextlib import contextmanager
import hashlib
import json
import io
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import tarfile

from machine_install import copy_showcase_tree, retire_managed

ROOT = Path(__file__).resolve().parent.parent
STAGE_ROOT = ROOT / "build" / "grub-module-install"
MANAGED = Path("/etc/grub.d/42_retroos_module")
OTHER_MANAGED = Path("/etc/grub.d/41_retroos")
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


def choose_c_for_host(volumes, requested, c_ram):
    if c_ram and requested:
        raise ValueError("Choose either --c-ram or --c-uuid")
    if c_ram:
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
    home = plan.get("grub_destination", str(Path(base).parent.parent))
    if plan.get("c_uuid"):
        config_home = (plan.get("c_dir") or "").rstrip("/") + "/RETROOS"
        config_root = f"    search --no-floppy --fs-uuid --set=retroos_config {plan['c_uuid']}\n"
        config_prefix = "($retroos_config)" + config_home
    else:
        config_root = ""
        config_prefix = home
    entries = []
    for label, overlay in (("protected disk", " ram-overlay"), ("persistent disk", "")):
        kernel_args = "ram-overlay" if overlay else ""
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
{config_root}    module2 {config_prefix}/BOOT.INI retroos.config=boot
    module2 {config_prefix}/RETROOS.INI retroos.config=ini
    boot
}}
''')
    return "\n".join(entries)


def mount_configuration(plan):
    """Mount policy is a reviewable INI file, independent of GRUB write mode."""
    mounts = []
    if plan.get("root_uuid"):
        home = plan.get("c_dir") or "/home/retroos"
        mounts.append(f'[mount "linux"]\nsource=UUID={plan["root_uuid"]}\npath=/\naccess=rw\ngrant={home}\n')
    if plan.get("c_uuid"):
        home = plan.get("c_dir") or "/"
        mounts.append(f'[mount "data"]\nsource=UUID={plan["c_uuid"]}\npath=/home/retroos\nsubdir={home}\ndrive=C\naccess=rw\ngrant={home}\n')
    elif plan.get("root_uuid"):
        mounts.append('[mount "session"]\nsource=bundle\npath=/home/retroos\ndrive=C\naccess=ram\n')
    if not mounts:
        mounts.append('[mount "session"]\nsource=bundle\npath=/\ndrive=C\naccess=ram\n')
    return '[bundle]\nsource=module\nsubdir=/\n\n' + "\n".join(mounts)


def migrate_boot_configuration(plan, previous):
    """Keep custom mounts, but make the selected C: and module backing explicit."""
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(previous)
    for section in list(config.sections()):
        if section == "bundle" or config[section].get("drive", "").upper() == "C":
            config.remove_section(section)
    generated = configparser.ConfigParser(interpolation=None)
    generated.read_string(mount_configuration(plan))
    config["bundle"] = dict(generated["bundle"])
    for section in generated.sections():
        if generated[section].get("drive", "").upper() == "C":
            config[section] = dict(generated[section])
    text = io.StringIO()
    config.write(text, space_around_delimiters=False)
    return text.getvalue()


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


def visible_c_home(volume, c_dir):
    if volume["fstype"] == "ext4":
        return c_home(volume, c_dir)
    for mountpoint in volume["mountpoints"]:
        if mountpoint:
            mount = filesystem(mountpoint)
            if ((mount.get("uuid") or "").lower() == volume["uuid"].lower()
                    and mount.get("fsroot") == "/"):
                return mountpoint
    return None


def create_c_home(home):
    if home.exists():
        if not home.is_dir():
            raise ValueError(f"C: home is not a directory: {home}")
        return
    home.mkdir(parents=True)
    os.chown(home, int(os.environ.get("SUDO_UID", str(os.getuid()))),
             int(os.environ.get("SUDO_GID", str(os.getgid()))))
    home.chmod(0o755)


@contextmanager
def mounted_c_home(volume, c_dir="/home/retroos"):
    """Expose the selected C: tree, including unmounted FAT data volumes."""
    for mountpoint in volume["mountpoints"]:
        if not mountpoint:
            continue
        mounted = filesystem(mountpoint)
        if ((mounted.get("uuid") or "").lower() == volume["uuid"].lower()
                and mounted.get("fsroot") == "/"):
            home = Path(mountpoint) / c_dir.lstrip("/") if volume["fstype"] == "ext4" else Path(mountpoint)
            if not home.resolve().is_relative_to(Path(mountpoint).resolve()):
                raise ValueError("C: directory escapes the selected volume")
            create_c_home(home)
            yield home
            return
    with tempfile.TemporaryDirectory(prefix="retroos-c-") as temporary:
        subprocess.run(["mount", "-t", volume["fstype"], "-o", "rw",
                        f"UUID={volume['uuid']}", temporary], check=True)
        try:
            mounted = filesystem(temporary)
            if (mounted.get("uuid") or "").lower() != volume["uuid"].lower() or mounted.get("fsroot") != "/":
                raise ValueError("Mounted C: volume does not match the selected UUID")
            home = Path(temporary) / c_dir.lstrip("/") if volume["fstype"] == "ext4" else Path(temporary)
            if not home.resolve().is_relative_to(Path(temporary).resolve()):
                raise ValueError("C: directory escapes the selected volume")
            create_c_home(home)
            yield home
        finally:
            subprocess.run(["umount", temporary], check=True)


def ensure_c_home(volume, c_dir="/home/retroos"):
    with mounted_c_home(volume, c_dir):
        pass


def seed_c_files(home, stage, copy_showcase=False):
    """Install writable settings once; upgrades preserve disk-owned settings."""
    settings = home / "RETROOS"
    if settings.is_symlink() or (settings.exists() and not settings.is_dir()):
        raise ValueError(f"configuration directory must be an ordinary directory: {settings}")
    settings.mkdir(exist_ok=True)
    owner = home.stat()
    os.chown(settings, owner.st_uid, owner.st_gid)
    settings.chmod(0o755)
    for name in ("BOOT.INI", "RETROOS.INI"):
        target = settings / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError(f"configuration must be an ordinary file: {target}")
        if not target.exists():
            with target.open("xb") as output, (stage / name).open("rb") as source:
                shutil.copyfileobj(source, output)
        target.chmod(0o644)
        os.chown(target, owner.st_uid, owner.st_gid)
    if copy_showcase:
        return copy_showcase_tree(stage / "showcase", home, (owner.st_uid, owner.st_gid))
    return 0


def extract_boot_file(image, name, destination):
    if image.is_dir():
        source = image / name
        if name == "kernel.elf" and not source.exists():
            source = image / "kernel/kernel.elf"
        shutil.copyfile(source, destination)
        return
    if image.suffix.lower() == ".iso":
        with tempfile.TemporaryDirectory(prefix="retroos-extract-") as work:
            menu = Path(work) / "grub.cfg"
            subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(image),
                            "-extract", "/boot/grub/grub.cfg", str(menu)],
                           stdout=subprocess.DEVNULL, check=True)
            release = re.search(r"^set retroos_release=(\S+)$", menu.read_text(), re.M)
            if not release: raise ValueError("image has no selected RetroOS release")
            subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(image),
                            "-extract", release[1] + "/" + name, str(destination)],
                           stdout=subprocess.DEVNULL, check=True)
        return
    with image.open("rb") as disk:
        mbr = disk.read(512)
    if mbr[510:512] != b"\x55\xaa" or mbr[450] not in (0x0C, 0xEF):
        raise ValueError("boot image needs an MBR with a FAT32 boot partition first")
    start = struct.unpack_from("<I", mbr, 454)[0]
    if start == 0:
        raise ValueError("boot image has no FAT32 partition offset")
    filesystem = f"{image}@@{start * 512}"
    menu = subprocess.check_output(["mtype", "-i", filesystem, "::/boot/grub/grub.cfg"]).decode()
    release = re.search(r"^set retroos_release=(\S+)$", menu, re.M)
    if not release: raise ValueError("image has no selected RetroOS release")
    subprocess.run(["mcopy", "-i", filesystem,
                    f"::{release[1]}/{name}", str(destination)], check=True)


def prepare(image, destination, requested_c, requested_root, c_ram=False, requested_dir=None, copy_showcase=False, showcase_archive=None):
    if os.geteuid() == 0:
        raise PermissionError("prepare as a normal user; installation runs as root")
    if not image.is_file() and not image.is_dir():
        raise FileNotFoundError(f"boot image or core directory not found: {image}")
    volumes = candidates()
    c_volume = choose_c_for_host(volumes, requested_c, c_ram)
    if copy_showcase and not c_volume:
        raise ValueError("--copy-showcase requires a physical C: volume")
    if requested_dir and (not c_volume or c_volume["fstype"] != "ext4"):
        raise ValueError("--c-dir requires an ext4 C: volume")
    c_dir = validate_c_dir(requested_dir or "/home/retroos") if c_volume and c_volume["fstype"] == "ext4" else None
    home = visible_c_home(c_volume, c_dir) if c_volume else None
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
    if image.is_dir():
        kernel = image / "kernel.elf"
        if not kernel.exists():
            kernel = image / "kernel/kernel.elf"
        image_digest = hashlib.sha256((sha256(kernel) + sha256(image / "retroos-base.img.gz")).encode()).hexdigest()
    else:
        image_digest = sha256(image)
    release = destination / "releases" / image_digest[:12]
    plan = {"image_sha256": image_digest, "release": str(release),
            "destination": str(destination), "boot_uuid": boot_fs["uuid"],
            "grub_release": grub_path(release, boot_fs),
            "grub_destination": grub_path(destination, boot_fs), "c_uuid": c_volume["uuid"] if c_volume else None,
            "c_device": c_volume["path"] if c_volume else None,
            "c_fstype": c_volume["fstype"] if c_volume else None,
            "c_home": home, "c_dir": c_dir, "root_uuid": requested_root,
            "grub_config": str(grub_cfg)}
    stage_id = image_digest[:12]
    if copy_showcase:
        showcase = showcase_archive or ROOT / "showcase.tar"
        if showcase_archive is None and not showcase.exists():
            showcase = ROOT / "bazel-bin/showcase_module_tar.tar"
        stage_id = hashlib.sha256((image_digest + sha256(showcase)).encode()).hexdigest()[:12]
    stage = STAGE_ROOT / stage_id
    stage.mkdir(parents=True, exist_ok=True)
    for name in ("kernel.elf", "retroos-base.img.gz"):
        extract_boot_file(image, name, stage / name)
    plan["copy_showcase"] = copy_showcase
    if copy_showcase:
        with tarfile.open(showcase) as archive:
            archive.extractall(stage / "showcase", filter="data")
    entries = grub_entries(plan)
    (stage / "grub.cfg").write_text(entries)
    legacy_boot = destination / "BOOT.INI"
    # Preserve customized module mount policy when migrating an older install.
    disk_boot = Path(home) / "RETROOS/BOOT.INI" if home else None
    if disk_boot and disk_boot.exists():
        boot_text = disk_boot.read_text()
    else:
        boot_text = migrate_boot_configuration(plan, legacy_boot.read_text()) if legacy_boot.exists() else mount_configuration(plan)
    (stage / "BOOT.INI").write_text(boot_text)
    template = ROOT / "etc" / "RETROOS.INI"
    user_ini = destination / "RETROOS.INI"
    disk_ini = Path(home) / "RETROOS/RETROOS.INI" if home else None
    if disk_ini and disk_ini.exists():
        user_ini = disk_ini
    shutil.copyfile(user_ini if user_ini.exists() else template, stage / "RETROOS.INI")
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    (stage / "42_retroos_module").write_text('#!/bin/sh\nexec tail -n +3 "$0"\n' + entries)
    (stage / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    names = [str(path.relative_to(stage)) for path in stage.rglob("*")
             if path.is_file() and path.name != "checksums.json"]
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
    if c_volume:
        config_home = (c_dir or "").rstrip("/") + "/RETROOS"
        print(f"INIs: C:{config_home}; edits persist in the persistent disk entry.")
    else:
        print("INIs: RAM session; edit the boot copies from Linux for persistent changes.")
    print("Showcase: copy missing files into C:" if copy_showcase else "Showcase: skip")
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
    if plan["c_uuid"]:
        with mounted_c_home(c_volume, plan["c_dir"] or "/home/retroos") as home:
            copied = seed_c_files(home, stage, plan.get("copy_showcase", False))
            print(f"Configuration: {home}/RETROOS (persistent C:)")
            if plan.get("copy_showcase"):
                print(f"Copied {copied} missing showcase files into C:.")
    user_ini = destination / "RETROOS.INI"
    if not user_ini.exists():
        shutil.copyfile(stage / "RETROOS.INI", user_ini)
        user_ini.chmod(0o644)
    boot_ini = destination / "BOOT.INI"
    old_boot = boot_ini.read_bytes() if boot_ini.exists() else None
    old_managed = MANAGED.read_bytes() if MANAGED.exists() else None
    if old_managed is not None:
        Path(str(MANAGED) + ".previous").write_bytes(old_managed)
    other_mode = None
    try:
        other_mode = retire_managed(OTHER_MANAGED)
        shutil.copyfile(stage / "BOOT.INI", boot_ini)
        boot_ini.chmod(0o644)
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
        if other_mode is not None:
            OTHER_MANAGED.chmod(other_mode)
        if old_boot is None: boot_ini.unlink(missing_ok=True)
        else: boot_ini.write_bytes(old_boot)
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
    parser.add_argument("--image", "--iso", dest="image", type=Path,
                        default=ROOT if (ROOT / "retroos-base.img.gz").exists() else ROOT / "bazel-bin")
    parser.add_argument("--destination", type=Path, default=Path("/boot/retroos"))
    parser.add_argument("--c-uuid", help="C: filesystem UUID; required when several candidates exist")
    parser.add_argument("--c-ram", action="store_true", help="use the RAM module for C:")
    parser.add_argument("--c-dir", help="directory inside selected ext4 C: volume (default: /home/retroos)")
    parser.add_argument("--copy-showcase", action=argparse.BooleanOptionalAction, default=False,
                        help="copy missing showcase files into the selected physical C: volume")
    parser.add_argument("--root-uuid", help="optional ext4 UUID for Linux /")
    args = parser.parse_args()
    if args.prepare:
        prepare(args.image.resolve(), args.destination.resolve(), args.c_uuid, args.root_uuid, args.c_ram, args.c_dir, args.copy_showcase)
    else:
        install()


if __name__ == "__main__":
    main()
