#!/usr/bin/env python3
"""Prepare or install a matched disk-backed runtime on FAT or ext4 C:."""
import argparse
import configparser
from contextlib import contextmanager
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
MANAGED = Path("/etc/grub.d/41_retroos")
CUSTOM = Path("/etc/grub.d/40_custom")
OTHER_MANAGED = Path("/etc/grub.d/42_retroos_module")


def default_c_dir(volume):
    """Use the installing user's DOS directory when it is on this volume."""
    home = Path.home().resolve()
    for mountpoint in volume.get("mountpoints", []):
        if mountpoint and home.is_relative_to(Path(mountpoint).resolve()):
            relative = (home / "DOS").relative_to(Path(mountpoint).resolve())
            return "/" + relative.as_posix()
    return "/DOS"


def session_layout(plan):
    """Choose namespace paths independently of the physical C: subdirectory."""
    root = plan.get("linux_root") or plan.get("root_uuid")
    same = root and root == plan.get("c_uuid")
    c_dir = plan.get("c_dir") or "/"
    c_path = c_dir if same and c_dir != "/" else "/dos"
    home = plan.get("session_home")
    if not home:
        installing_home = Path.home().resolve()
        if same and Path(c_dir).is_relative_to(installing_home):
            home = str(installing_home)
        elif same and Path(c_dir).name == "DOS" and Path(c_dir).parent != Path('/'):
            home = str(Path(c_dir).parent)
        else:
            home = "/RETROOS/HOME"
    return c_path, home


def runtime_filter(member, destination):
    # This guest link is absolute in RetroOS, not in the installing host.
    guest_links = {'bin/rc': '/COMMANDER/RC/RC.EXE', 'bin/rcedit': 'rc'}
    if member.issym() and guest_links.get(member.name.removeprefix('./')) == member.linkname:
        # Repeated preparation encounters these links from the first extract.
        # tar_filter follows the existing final link and treats its guest
        # target as a host extraction destination. Only the parent must stay
        # inside the staging tree: tarfile replaces the final symlink itself.
        root = Path(destination).resolve()
        parent = (root / member.name).parent.resolve()
        if not parent.is_relative_to(root):
            raise tarfile.OutsideDestinationError(member, str(parent))
        return member.replace(mode=None, uid=None, gid=None, uname=None, gname=None)
    return tarfile.data_filter(member, destination)


def checksum(path):
    data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def filesystem(path):
    return json.loads(subprocess.check_output(
        ["findmnt", "--json", "--target", str(path), "--output", "UUID,FSTYPE,TARGET,FSROOT"]
    ))["filesystems"][0]


def filesystem_for(path):
    existing = path
    while not existing.exists():
        existing = existing.parent
    return filesystem(existing)


def validate(c_root, destination):
    for path in (c_root, destination):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) or ".." in path.parts:
            raise ValueError(f"unsupported boot path: {path}")
    data = filesystem_for(c_root)
    if data["fstype"] not in {"ext4", "vfat"} or not data.get("uuid") or data["fsroot"] != "/":
        raise ValueError("C: requires a FAT or ext4 volume")
    boot = filesystem_for(destination)
    if boot["fstype"] not in {"ext4", "vfat", "btrfs"} or not boot.get("uuid"):
        raise ValueError("boot files require a UUID-bearing filesystem readable by GRUB")
    if c_root.exists() and not c_root.is_dir():
        raise ValueError(f"C: root is not a directory: {c_root}")
    return data["uuid"]


def storage_layout(c_root, destination, volume=None, c_dir=None, root_uuid=None):
    import grub_module_install as grub
    boot = filesystem_for(destination)
    if boot["fstype"] not in {"ext4", "vfat", "btrfs"} or not boot.get("uuid"):
        raise ValueError("boot files require a UUID-bearing filesystem readable by GRUB")
    if volume:
        c_dir = c_dir or (default_c_dir(volume) if volume["fstype"] == "ext4" else "/")
        if c_dir != "/":
            grub.validate_c_dir(c_dir)
        home = grub.visible_c_home(volume, c_dir)
        c_root = Path(home) if home else None
        data = dict(fstype=volume["fstype"], uuid=volume["uuid"])
    else:
        validate(c_root, destination)
        data = filesystem_for(c_root)
        relative = c_root.relative_to(Path(data["target"]).resolve())
        c_dir = "/" + relative.as_posix() if relative.parts else "/"
    if data["fstype"] not in {"ext4", "vfat"}:
        raise ValueError("disk runtime requires FAT or ext4 C:")
    if root_uuid:
        selected_root = grub.choose_c_volume(grub.candidates(), root_uuid)
        if selected_root["fstype"] != "ext4":
            raise ValueError("--root-uuid requires an ext4 Linux root")
    root = filesystem("/")
    linux_root = root_uuid or (root.get("uuid") if root["fstype"] == "ext4"
        and root.get("fsroot") == "/" and root.get("uuid") == data["uuid"] else None)
    return dict(c_uuid=data["uuid"], c_fstype=data["fstype"], c_dir=c_dir,
                c_root=str(c_root) if c_root else None, c_volume=volume,
                linux_root=linux_root, boot_uuid=boot["uuid"], boot_fs=boot)


def normalize_runtime(root):
    """Use the existing VFS link manifest on both FAT and ext4."""
    links = []
    for path in sorted(root.rglob("*")):
        if not path.is_symlink():
            continue
        relative = path.relative_to(root)
        if relative.parent != Path("bin"):
            raise ValueError(f"unsupported runtime symlink: {relative}")
        links.append(path.name + "\t" + os.readlink(path) + "\n")
        path.unlink()
    if links:
        (root / "RETROOS/UNIXLINK.LST").write_text("".join(links))


def boot_configuration(plan, previous=None):
    """Only root integration differs; C: and the runtime are filesystem-neutral."""
    config = configparser.ConfigParser(interpolation=None)
    if previous:
        config.read_string(previous)
    c_path, home = session_layout(plan)
    if "session" not in config:
        config["session"] = {"home": home}
    home = config["session"].get("home", home)
    config["bundle"] = {"source": "UUID=" + plan["c_uuid"], "subdir": plan["runtime_subdir"]}
    for section in list(config.sections()):
        if config[section].get("drive", "").upper() == "C":
            config.remove_section(section)
    if plan.get("linux_root"):
        same = plan["linux_root"] == plan["c_uuid"]
        config['mount "linux"'] = {"source": "UUID=" + plan["linux_root"], "path": "/",
                                   "access": "rw" if same else "ro"}
        if same:
            config['mount "linux"']["grant"] = home if home != "/RETROOS/HOME" else plan["c_dir"]
    config['mount "dos"'] = {"source": "UUID=" + plan["c_uuid"], "subdir": plan["c_dir"],
        "path": c_path, "drive": "C", "access": "rw", "grant": plan["c_dir"]}
    import io
    text = io.StringIO()
    config.write(text, space_around_delimiters=False)
    return text.getvalue()


def grub_entries(plan):
    release = plan.get("grub_release", plan["release"])
    uuid = plan.get("boot_uuid") or plan["uuid"]
    boot_ini = plan.get("boot_ini", f"{plan.get('destination', release)}/BOOT.INI")
    user_ini = f"{plan['c_root']}/RETROOS/RETROOS.INI"
    config_search = ""
    if "c_uuid" in plan:
        config_search = f"    search --no-floppy --fs-uuid --set=retroos_config {plan['c_uuid']}\n"
        home = plan["c_dir"].rstrip("/") + "/RETROOS"
        boot_ini = f"($retroos_config){home}/BOOT.INI"
        user_ini = f"($retroos_config){home}/RETROOS.INI"
    entries = []
    for name, extra in (("current, persistent", ""), ("current, protected disk", " ram-overlay")):
        entries.append(f'''menuentry "RetroOS ({name})" {{
    insmod part_gpt
    insmod part_msdos
    insmod fat
    insmod btrfs
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
{config_search}    module2 {boot_ini} retroos.config=boot
    module2 {user_ini} retroos.config=ini
    boot
}}
''')
    return "\n".join(entries)


def retire_managed(path):
    """Keep a previous boot strategy's script, but omit its stale kernel menu."""
    if not path.exists() or b'RetroOS (' not in path.read_bytes():
        return None
    mode = path.stat().st_mode & 0o777
    previous = Path(str(path) + ".previous")
    shutil.copyfile(path, previous)
    previous.chmod(0o644)
    path.chmod(0o644)
    return mode


def copy_showcase_tree(source, destination, owner=None):
    """Seed ordinary C: files, preserving existing files and symlink trees."""
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        return 0
    if not destination.exists():
        destination.mkdir()
        destination.chmod(0o755)
        if owner is not None:
            os.chown(destination, *owner)
    copied = 0
    for entry in sorted(source.iterdir()):
        target = destination / entry.name
        if entry.is_dir():
            copied += copy_showcase_tree(entry, target, owner)
        elif not target.exists() and not target.is_symlink():
            try:
                with entry.open('rb') as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
            except FileExistsError:
                continue
            target.chmod((entry.stat().st_mode & 0o777) | 0o600)
            if owner is not None:
                os.chown(target, *owner)
            copied += 1
    return copied


def prepare(c_root, destination, archive=None, copy_showcase=False, showcase_archive=None,
            volume=None, c_dir=None, root_uuid=None):
    import grub_module_install as grub
    layout = storage_layout(c_root, destination, volume, c_dir, root_uuid)
    c_root = Path(layout["c_root"]) if layout["c_root"] else None
    uuid = layout["c_uuid"]
    archive = archive or ROOT / "bazel-bin" / "machine_boot_tar.tar"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    release = destination / "releases" / digest[:12]
    runtime_subdir = layout["c_dir"].rstrip("/") + "/RETROOS/releases/" + digest[:12]
    if len(runtime_subdir + "/RETROOS") >= 128:
        raise ValueError("installed paths exceed the kernel's 127-byte limit")
    # Versioned directories keep the previous kernel/runtime pair available.
    stage_id = digest[:12]
    if copy_showcase:
        showcase_archive = showcase_archive or (ROOT / 'showcase.tar' if (ROOT / 'showcase.tar').exists()
                                               else ROOT / 'bazel-bin/showcase_module_tar.tar')
        showcase_digest = hashlib.sha256(showcase_archive.read_bytes()).hexdigest()
        stage_id = hashlib.sha256((digest + showcase_digest).encode()).hexdigest()[:12]
    stage = STAGE / stage_id
    stage.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(stage / "runtime", filter=runtime_filter)
    normalize_runtime(stage / "runtime")
    if copy_showcase:
        with tarfile.open(showcase_archive) as tar:
            tar.extractall(stage / 'showcase', filter='data')
    # User settings live on C: for FAT and ext4 alike. Unmounted C: is read
    # only during installation; existing files there are preserved.
    user_ini = c_root / "RETROOS/RETROOS.INI" if c_root else None
    legacy_ini = destination / "RETROOS.INI"
    source_ini = user_ini if user_ini and user_ini.exists() else legacy_ini
    if not source_ini.exists():
        source_ini = stage / "runtime/RETROOS/RETROOS.INI"
    settings = source_ini.read_text()
    if re.search(r'^\s*\[(?:mount |bundle\])', settings, re.M):
        raise ValueError("RETROOS.INI contains storage policy; move mounts to BOOT.INI")
    settings_path=stage / "RETROOS.INI"
    # User configuration can contain Wi-Fi and SMB credentials.
    settings_path.touch(mode=0o600, exist_ok=True)
    settings_path.chmod(0o600)
    settings_path.write_text(settings)
    existing_boot = c_root / "RETROOS/BOOT.INI" if c_root else None
    policy = existing_boot if existing_boot and existing_boot.exists() else destination / "BOOT.INI"
    owner = c_root.stat() if c_root and c_root.exists() else None
    plan = dict(layout, uuid=uuid, destination=str(destination),
                c_owner=[owner.st_uid, owner.st_gid] if owner else [os.getuid(), os.getgid()],
                copy_showcase=copy_showcase, release=str(release), runtime_subdir=runtime_subdir,
                grub_release=grub.grub_path(release, layout["boot_fs"]), archive_sha256=digest,
                settings_observed=c_root is not None,
                user_ini_sha256=checksum(user_ini) if user_ini and user_ini.exists() else None,
                boot_ini_sha256=checksum(existing_boot) if existing_boot and existing_boot.exists() else None)
    (stage / "BOOT.INI").write_text(boot_configuration(plan, policy.read_text() if policy.exists() else None))
    # Retire only the two old RetroOS entries that load the obsolete location.
    # Preserve every other custom entry, and verify the original before install.
    custom = CUSTOM
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
    print(f"Prepared {stage}\nC: UUID={uuid} {layout['c_dir']}\nRuntime: {runtime_subdir} (disk-backed)\nKernel: {release}/kernel.elf")
    print('Showcase: copy missing files into C:' if copy_showcase else 'Showcase: skip; use existing C: files')
    print("Review grub.cfg, then run the installer as root without --prepare.")


def install():
    if os.geteuid() != 0:
        raise PermissionError("installation needs root: sudo tools/install_kernel.sh")
    stage = Path((STAGE / "selected").read_text().strip()).resolve()
    if not stage.is_relative_to(STAGE.resolve()):
        raise ValueError("staged path is outside the installer workspace")
    sums = json.loads((stage / "checksums.json").read_text())
    for name, expected in sums.items():
        if checksum(stage / name) != expected:
            raise ValueError(f"staged file changed: {name}; prepare again")
    plan = json.loads((stage / "plan.json").read_text())
    import grub_module_install as grub
    boot = filesystem_for(Path(plan["destination"]))
    if boot["uuid"] != plan["boot_uuid"] or grub.grub_path(Path(plan["release"]), boot) != plan["grub_release"]:
        raise ValueError("GRUB destination changed; prepare again")
    if plan["c_volume"]:
        volume = grub.choose_c_volume(grub.candidates(), plan["c_uuid"])
        if volume["fstype"] != plan["c_fstype"]:
            raise ValueError("C: filesystem type changed; prepare again")
        with grub.mounted_c_home(volume, plan["c_dir"]) as home:
            install_into(stage, plan, home)
    else:
        home = Path(plan["c_root"])
        if validate(home, Path(plan["destination"])) != plan["c_uuid"]:
            raise ValueError("C: UUID changed; prepare again")
        grub.create_c_home(home)
        install_into(stage, plan, home)


def install_into(stage, plan, c_root):
    import grub_module_install as grub
    settings = c_root / "RETROOS"
    for path in (settings, settings / "releases"):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError(f"runtime directory must be an ordinary directory: {path}")
    for name in ("RETROOS.INI", "BOOT.INI"):
        path = settings / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f"configuration must be an ordinary file: {path}")
    subprocess.run(["grub-script-check", str(stage / "grub.cfg")], check=True)
    release = c_root / "RETROOS/releases" / plan["archive_sha256"][:12]
    if release.is_symlink():
        raise ValueError(f"runtime release must be an ordinary directory: {release}")
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
        if plan["c_fstype"] == "ext4":
            os.chown(path, 0, 0, follow_symlinks=False)
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
    kernel_release = Path(plan["release"])
    kernel_release.mkdir(parents=True, exist_ok=True)
    kernel = kernel_release / "kernel.elf"
    if kernel.exists() and kernel.read_bytes() != (release / "kernel.elf").read_bytes():
        raise ValueError(f"existing kernel changed: {kernel}")
    if not kernel.exists():
        shutil.copyfile(release / "kernel.elf", kernel)
    kernel.chmod(0o644)
    user_ini = c_root / "RETROOS" / "RETROOS.INI"
    if user_ini.exists() and plan["settings_observed"]:
        expected = plan["user_ini_sha256"]
        if expected is None or hashlib.sha256(user_ini.read_bytes()).hexdigest() != expected:
            raise ValueError("user RETROOS.INI changed since preparation; prepare again")
    elif not user_ini.exists():
        if plan["user_ini_sha256"] is not None:
            raise ValueError("user RETROOS.INI disappeared since preparation; prepare again")
        user_ini.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / "RETROOS.INI", user_ini)
        owner = c_root.stat()
        os.chown(user_ini.parent, owner.st_uid, owner.st_gid)
        os.chown(user_ini, owner.st_uid, owner.st_gid)
        user_ini.chmod(0o600)
    owner = c_root.stat()
    os.chown(user_ini.parent, owner.st_uid, owner.st_gid)
    os.chown(user_ini, owner.st_uid, owner.st_gid)
    user_ini.chmod(0o600)
    custom = CUSTOM
    if "custom_sha256" in plan and hashlib.sha256(custom.read_bytes()).hexdigest() != plan["custom_sha256"]:
        raise ValueError("40_custom changed since preparation; prepare again")
    managed = MANAGED
    old_managed = managed.read_bytes() if managed.exists() else None
    old_custom = custom.read_bytes() if "custom_sha256" in plan else None
    for path, data in ((managed, old_managed), (custom, old_custom)):
        if data is not None:
            previous = Path(str(path) + ".previous")
            previous.write_bytes(data)
            previous.chmod(0o644)
    boot_ini = c_root / "RETROOS/BOOT.INI"
    old_boot = boot_ini.read_bytes() if boot_ini.exists() else None
    actual_boot_hash = hashlib.sha256(old_boot).hexdigest() if old_boot is not None else None
    if plan["settings_observed"] and actual_boot_hash != plan["boot_ini_sha256"]:
        raise ValueError("BOOT.INI changed since preparation; prepare again")
    if old_boot is not None:
        Path(str(boot_ini) + ".previous").write_bytes(old_boot)
    other_mode = None
    try:
        other_mode = retire_managed(OTHER_MANAGED)
        boot_ini.parent.mkdir(parents=True, exist_ok=True)
        boot_ini.write_text(boot_configuration(plan, old_boot.decode() if old_boot is not None else (stage / "BOOT.INI").read_text()))
        boot_ini.chmod(0o644)
        os.chown(boot_ini, owner.st_uid, owner.st_gid)
        shutil.copyfile(stage / "41_retroos", managed)
        managed.chmod(0o755)
        if old_custom is not None:
            shutil.copyfile(stage / "40_custom", custom)
        grub.update_grub()
    except Exception:
        if other_mode is not None:
            OTHER_MANAGED.chmod(other_mode)
        if old_boot is None: boot_ini.unlink(missing_ok=True)
        else: boot_ini.write_bytes(old_boot)
        if old_custom is not None:
            custom.write_bytes(old_custom)
        if old_managed is None:
            managed.unlink(missing_ok=True)
        else:
            managed.write_bytes(old_managed)
        raise
    if plan.get('copy_showcase'):
        owner = c_root.stat()
        copied = copy_showcase_tree(stage / 'showcase', c_root, (owner.st_uid, owner.st_gid))
        print(f'Copied {copied} showcase files into {c_root}; existing files and links preserved.')
    print(f"Installed disk runtime at {release}. Select 'RetroOS (current, persistent)' to keep changes.")
    print("Other GRUB entries and previous releases are retained. No reboot performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--archive", type=Path, help="prebuilt matched kernel/runtime tar")
    parser.add_argument("--c-root", type=Path, default=Path.home() / "DOS")
    parser.add_argument("--destination", type=Path, default=Path("/boot/retroos"))
    parser.add_argument('--copy-showcase', action=argparse.BooleanOptionalAction, default=None,
                        help='seed C: with showcase files, preserving existing files (default: ask on a terminal only when creating C:, otherwise skip)')
    parser.add_argument('--showcase-archive', type=Path, help='optional showcase tar to copy into C:')
    args = parser.parse_args()
    if args.prepare:
        copy_showcase = args.copy_showcase
        if copy_showcase is None:
            import sys
            copy_showcase = not args.c_root.exists() and not args.c_root.is_symlink() and sys.stdin.isatty() and input(
                f'Copy showcase (games, commanders and assets) into {args.c_root}, preserving existing files? [y/N] '
            ).strip().lower() in ('y', 'yes')
        prepare(args.c_root.resolve(), args.destination.resolve(), args.archive,
                copy_showcase, args.showcase_archive)
    else:
        install()


if __name__ == "__main__":
    main()
