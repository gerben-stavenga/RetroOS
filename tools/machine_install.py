#!/usr/bin/env python3
"""Prepare or install a matched kernel/runtime release on an ext4 Linux root."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / "build" / "machine-install"


def runtime_filter(member, destination):
    # This guest link is absolute in RetroOS, not in the installing host.
    guest_links = {'bin/rc': '/COMMANDER/RC/RC.EXE', 'bin/rcedit': 'rc'}
    if member.issym() and guest_links.get(member.name.removeprefix('./')) == member.linkname:
        return tarfile.tar_filter(member, destination)
    return tarfile.data_filter(member, destination)


def checksum(path):
    data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def filesystem(path):
    return json.loads(subprocess.check_output(
        ["findmnt", "--json", "--target", str(path), "--output", "UUID,FSTYPE,TARGET,FSROOT"]
    ))["filesystems"][0]


def validate(c_root, destination):
    root = filesystem("/")
    if root["fstype"] != "ext4" or not root.get("uuid") or root["fsroot"] != "/":
        raise ValueError("installation currently requires an ext4 Linux root")
    for path in (c_root, destination):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) or ".." in path.parts:
            raise ValueError(f"unsupported boot path: {path}")
        existing = path
        while not existing.exists():
            existing = existing.parent
        if filesystem(existing) != root:
            raise ValueError(f"{path} must be on the Linux root filesystem (separate /boot is not supported yet)")
    if not c_root.is_dir():
        raise ValueError(f"C: root does not exist: {c_root}")
    return root["uuid"]


def grub_entries(plan):
    release = plan["release"]
    uuid = plan["uuid"]
    boot_ini = plan.get("boot_ini", f"{plan.get('destination', release)}/BOOT.INI")
    user_ini = f"{plan['c_root']}/RETROOS/RETROOS.INI"
    entries = []
    for name, extra in (("current, persistent", ""), ("current, protected disk", " ram-overlay")):
        entries.append(f'''menuentry "RetroOS ({name})" {{
    insmod part_gpt
    insmod ext2
    insmod multiboot2
    search --no-floppy --fs-uuid --set=root {uuid}
    multiboot2 {release}/kernel.elf{extra}
    # multiboot2 resets gfxpayload from the kernel header; override it here.
    # Native BIOS boots keep hardware VGA, including planar and Mode X modes.
    if [ "$grub_platform" = "pc" ]; then
        set gfxpayload=text
    else
        insmod all_video
        set gfxmode=auto
        set gfxpayload=auto
    fi
    module2 {boot_ini} retroos.config=boot
    module2 {user_ini} retroos.config=ini
    boot
}}
''')
    return "\n".join(entries)


def prepare(c_root, destination, archive=None):
    uuid = validate(c_root, destination)
    archive = archive or ROOT / "bazel-bin" / "machine_boot_tar.tar"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    release = destination / "releases" / digest[:12]
    if len(str(release / "RETROOS")) >= 128 or len(str(c_root)) >= 128:
        raise ValueError("installed paths exceed the kernel's 127-byte limit")
    # Versioned directories keep the previous kernel/runtime pair available.
    stage = STAGE / digest[:12]
    stage.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(stage / "runtime", filter=runtime_filter)
    # User settings have one permanent location and are never overwritten.
    user_ini = c_root / "RETROOS" / "RETROOS.INI"
    settings = user_ini.read_text() if user_ini.exists() else (stage / "runtime" / "RETROOS" / "RETROOS.INI").read_text()
    if re.search(r'^\s*\[(?:mount |bundle\])', settings, re.M):
        raise ValueError(f"{user_ini} contains storage policy; move its mounts to BOOT.INI before installing")
    (stage / "RETROOS.INI").write_text(settings)
    boot_ini = (f'[bundle]\nsource=UUID={uuid}\nsubdir={release}\n\n'
                f'[mount "linux"]\nsource=UUID={uuid}\npath=/\naccess=rw\ngrant={c_root}\n'
                f'[mount "dos"]\nsource=UUID={uuid}\nsubdir={c_root}\npath={c_root}\ndrive=C\naccess=rw\ngrant={c_root}\n')
    existing_boot = destination / "BOOT.INI"
    if existing_boot.exists():
        previous = existing_boot.read_text()
        bundle = f'[bundle]\nsource=UUID={uuid}\nsubdir={release}\n\n'
        if '[bundle]' not in previous:
            raise ValueError(f"{existing_boot} has no [bundle] section")
        boot_ini = re.sub(r'(?ms)^\[bundle\]\s*\n.*?(?=^\[|\Z)', lambda _: bundle, previous, count=1)
    (stage / "BOOT.INI").write_text(boot_ini)
    plan = dict(uuid=uuid, c_root=str(c_root), destination=str(destination),
                release=str(release), boot_ini=str(destination / "BOOT.INI"), archive_sha256=digest,
                user_ini_sha256=hashlib.sha256(user_ini.read_bytes()).hexdigest() if user_ini.exists() else None,
                boot_ini_sha256=hashlib.sha256(existing_boot.read_bytes()).hexdigest() if existing_boot.exists() else None)
    # Retire only the two old RetroOS entries that load the obsolete location.
    # Preserve every other custom entry, and verify the original before install.
    custom = Path("/etc/grub.d/40_custom")
    if custom.exists():
        original = custom.read_text()
        pattern = r'menuentry "RetroOS \((?:protected disk|writeable disk|writable disk)\)" \{\n[^{}]*\n\}'
        def retire(match):
            if re.search(r"multiboot2? /boot/retroos/kernel\.elf", match[0]):
                return "# RetroOS entries are managed by /etc/grub.d/41_retroos."
            return match[0]
        updated = re.sub(pattern, retire, original)
        if updated != original:
            plan["custom_sha256"] = hashlib.sha256(custom.read_bytes()).hexdigest()
            (stage / "40_custom").write_text(updated)
    (stage / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    entries = grub_entries(plan)
    (stage / "grub.cfg").write_text(entries)
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    (stage / "41_retroos").write_text('#!/bin/sh\nexec tail -n +3 "$0"\n' + entries)
    # Record the exact staged files; install checks them before changing anything.
    files = [p for p in stage.rglob("*") if (p.is_file() or p.is_symlink()) and p.name != "checksums.json"]
    (stage / "checksums.json").write_text(json.dumps({str(p.relative_to(stage)):
        checksum(p) for p in files}, indent=2) + "\n")
    (STAGE / "selected").write_text(str(stage) + "\n")
    print(f"Prepared {stage}\nRoot UUID: {uuid}\nC: {c_root}\nRuntime: {release}/RETROOS")
    print("Review grub.cfg, then run the installer as root without --prepare.")


def install():
    if os.geteuid() != 0:
        raise PermissionError("installation needs root: sudo tools/install_kernel.sh")
    stage = Path((STAGE / "selected").read_text().strip())
    sums = json.loads((stage / "checksums.json").read_text())
    for name, expected in sums.items():
        if checksum(stage / name) != expected:
            raise ValueError(f"staged file changed: {name}; prepare again")
    plan = json.loads((stage / "plan.json").read_text())
    c_root = Path(plan["c_root"])
    if validate(c_root, Path(plan["destination"])) != plan["uuid"]:
        raise ValueError("root UUID changed; prepare again")
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    release = Path(plan["release"])
    if not release.exists():
        release.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".install-", dir=release.parent) as temp:
            pending = Path(temp) / "runtime"
            shutil.copytree(stage / "runtime", pending, symlinks=True)
            pending.rename(release)
    else:
        for source in (stage / "runtime").rglob("*"):
            if source.is_symlink():
                target = release / source.relative_to(stage / "runtime")
                if not target.is_symlink() or os.readlink(target) != os.readlink(source):
                    raise ValueError(f"existing release link changed: {target}")
            elif source.is_file():
                target = release / source.relative_to(stage / "runtime")
                if not target.is_file() or target.read_bytes() != source.read_bytes():
                    raise ValueError(f"existing release is incomplete or changed: {target}")
    for path in [release, *release.rglob("*")]:
        os.chown(path, 0, 0, follow_symlinks=False)
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)
    user_ini = c_root / "RETROOS" / "RETROOS.INI"
    if user_ini.exists():
        expected = plan["user_ini_sha256"]
        if expected is None or hashlib.sha256(user_ini.read_bytes()).hexdigest() != expected:
            raise ValueError("user RETROOS.INI changed since preparation; prepare again")
    else:
        if plan["user_ini_sha256"] is not None:
            raise ValueError("user RETROOS.INI disappeared since preparation; prepare again")
        user_ini.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / "RETROOS.INI", user_ini)
        owner = c_root.stat()
        os.chown(user_ini.parent, owner.st_uid, owner.st_gid)
        os.chown(user_ini, owner.st_uid, owner.st_gid)
        user_ini.chmod(0o664)
    custom = Path("/etc/grub.d/40_custom")
    if "custom_sha256" in plan and hashlib.sha256(custom.read_bytes()).hexdigest() != plan["custom_sha256"]:
        raise ValueError("40_custom changed since preparation; prepare again")
    managed = Path("/etc/grub.d/41_retroos")
    old_managed = managed.read_bytes() if managed.exists() else None
    old_custom = custom.read_bytes() if "custom_sha256" in plan else None
    for path, data in ((managed, old_managed), (custom, old_custom)):
        if data is not None:
            previous = Path(str(path) + ".previous")
            previous.write_bytes(data)
            previous.chmod(0o644)
    boot_ini = Path(plan["boot_ini"])
    old_boot = boot_ini.read_bytes() if boot_ini.exists() else None
    actual_boot_hash = hashlib.sha256(old_boot).hexdigest() if old_boot is not None else None
    if actual_boot_hash != plan["boot_ini_sha256"]:
        raise ValueError("BOOT.INI changed since preparation; prepare again")
    if old_boot is not None:
        Path(str(boot_ini) + ".previous").write_bytes(old_boot)
    try:
        shutil.copyfile(stage / "BOOT.INI", boot_ini)
        boot_ini.chmod(0o644)
        shutil.copyfile(stage / "41_retroos", managed)
        managed.chmod(0o755)
        if old_custom is not None:
            shutil.copyfile(stage / "40_custom", custom)
        subprocess.run(["update-grub"], check=True)
    except Exception:
        if old_boot is None: boot_ini.unlink(missing_ok=True)
        else: boot_ini.write_bytes(old_boot)
        if old_custom is not None:
            custom.write_bytes(old_custom)
        if old_managed is None:
            managed.unlink(missing_ok=True)
        else:
            managed.write_bytes(old_managed)
        raise
    print(f"Installed {release}. Select 'RetroOS (current, persistent)' to keep changes.")
    print("Other GRUB entries and previous releases are retained. No reboot performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--archive", type=Path, help="prebuilt matched kernel/runtime tar")
    parser.add_argument("--c-root", type=Path, default=Path("/home/retroos"))
    parser.add_argument("--destination", type=Path, default=Path("/boot/retroos"))
    args = parser.parse_args()
    if args.prepare:
        prepare(args.c_root.resolve(), args.destination.resolve(), args.archive)
    else:
        install()


if __name__ == "__main__":
    main()
