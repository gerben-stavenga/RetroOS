#!/usr/bin/env python3
"""Install RetroOS alongside Linux, with ext4 or FAT for persistent C:."""
import argparse
import configparser
import io
import json
import os
from pathlib import Path
import tempfile

import machine_install as disk
import grub_module_install as module

ROOT = Path(__file__).resolve().parent.parent
SELECTED = ROOT / 'build/install-selected.json'


def installation_mode(args, root_fs, boot_fs, c_fs):
    if args.module or args.image or args.c_ram:
        return 'module'
    return 'disk' if c_fs['fstype'] in ('ext4', 'vfat') else 'module'


def filesystem_for(path):
    existing = path
    while not existing.exists():
        existing = existing.parent
    return disk.filesystem(existing)


def c_selection(path, fs):
    """Translate a mounted C: path to UUID/subdirectory for the GRUB backend."""
    if fs['fstype'] not in ('ext4', 'vfat') or fs.get('fsroot') != '/':
        raise ValueError('--c-root must be on a mounted FAT or ext4 volume, outside subvolume mounts')
    relative = path.relative_to(Path(fs['target']).resolve())
    if fs['fstype'] == 'vfat':
        if relative.parts:
            raise ValueError('FAT --c-root must be the volume mountpoint; use --c-uuid to select the whole volume')
        return fs['uuid'], None
    return fs['uuid'], module.validate_c_dir('/' + relative.as_posix())


def configure_usb(usb, c_uuid=None, c_ram=False, c_dir=None, root_uuid=None, preview=False):
    """Configure an already-flashed, mounted USB; leave host GRUB untouched."""
    usb = usb.resolve()
    fs = disk.filesystem(usb)
    if (fs['fstype'] != 'vfat' or Path(fs['target']).resolve() != usb
            or fs.get('fsroot') != '/'):
        raise ValueError('--usb must be the mountpoint of the flashed FAT32 partition')
    target = usb / 'boot/retroos/BOOT.INI'
    if not target.is_file() or target.is_symlink():
        raise ValueError('RetroOS BOOT.INI not found on USB; flash the USB image first')
    volumes = module.candidates()
    volume = module.choose_c_for_host(volumes, c_uuid, c_ram)
    if c_dir is not None:
        if not volume or volume['fstype'] != 'ext4':
            raise ValueError('--c-dir requires an ext4 C: volume')
        if c_dir != '/':
            module.validate_c_dir(c_dir)
    if root_uuid and not any(v['fstype'] == 'ext4' and v['uuid'].lower() == root_uuid.lower()
                             for v in volumes):
        raise ValueError('--root-uuid must identify one supported ext4 volume')
    plan = {'c_uuid': volume['uuid'] if volume else None, 'c_dir': c_dir,
            'root_uuid': root_uuid}
    previous = target.read_text()
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(previous)
    generated = configparser.ConfigParser(interpolation=None)
    generated.read_string(module.mount_configuration(plan))
    # Replace the selected C: and optional Unix root, retaining other mounts.
    for section in list(config.sections()):
        if config[section].get('drive', '').upper() == 'C' or (
                root_uuid and config[section].get('path') == '/'):
            config.remove_section(section)
    if any(config[s].get('path') == '/' for s in config.sections()):
        for section in generated.sections():
            if generated[section].get('drive') == 'C' and generated[section].get('path') == '/':
                generated[section]['path'] = '/home/retroos'
    for section in generated.sections():
        if section != 'bundle' and section in config:
            raise ValueError(f'USB mount name conflicts with generated section: {section}')
        config[section] = dict(generated[section])
    text = io.StringIO()
    config.write(text, space_around_delimiters=False)
    if preview:
        print(text.getvalue(), end='')
        return
    target.with_suffix('.INI.previous').write_text(previous)
    with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text.getvalue())
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    print(f'Updated {target}; previous configuration saved as BOOT.INI.previous')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--usb', type=Path, help='configure BOOT.INI on an already-flashed mounted USB; --prepare previews only')
    parser.add_argument('--module', action='store_true', help='force a RAM-loaded core (legacy option)')
    parser.add_argument('--image', '--iso', type=Path, dest='image', help='optional USB/ISO image supplying the core')
    parser.add_argument('--archive', type=Path, help='matched disk-runtime archive')
    parser.add_argument('--destination', type=Path, default=Path('/boot/retroos'))
    parser.add_argument('--c-root', type=Path, help='C: directory, or mountpoint of a FAT volume')
    parser.add_argument('--c-uuid', help='FAT or ext4 C: filesystem UUID')
    parser.add_argument('--c-dir', help='C: directory inside an ext4 volume')
    parser.add_argument('--c-ram', action='store_true', help='use session-only C:')
    parser.add_argument('--root-uuid', help='optional ext4 volume for Linux /')
    parser.add_argument('--copy-showcase', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--showcase-archive', type=Path)
    args = parser.parse_args()
    if args.c_root and (args.c_uuid or args.c_dir or args.c_ram):
        parser.error('choose --c-root or --c-uuid/--c-dir/--c-ram')
    if args.usb:
        if (args.module or args.image or args.archive or args.c_root
                or args.copy_showcase is not None or args.showcase_archive
                or args.destination != Path('/boot/retroos')):
            parser.error('--usb supports --prepare, --c-uuid, --c-ram, --c-dir and --root-uuid')
        configure_usb(args.usb, args.c_uuid, args.c_ram, args.c_dir, args.root_uuid, args.prepare)
        return
    if not args.prepare:
        if SELECTED.exists():
            selection = json.loads(SELECTED.read_text())
            backend = module if selection['mode'] == 'module' else disk
            selected = module.STAGE_ROOT / 'selected' if backend is module else disk.STAGE / 'selected'
            if selected.read_text().strip() != selection['stage']:
                raise ValueError('prepared installation changed; prepare again')
        else:
            backend = module if args.module else disk
        backend.install()
        return
    if os.geteuid() == 0:
        raise PermissionError('prepare as a normal user; installation runs as root')
    c_root = (args.c_root or Path('/home/retroos')).resolve()
    destination = args.destination.resolve()
    root_fs = disk.filesystem('/')
    boot_fs = filesystem_for(destination)
    c_fs = filesystem_for(c_root)
    volume = None
    c_dir = args.c_dir
    forced_module = args.module or args.image or args.c_ram
    if not forced_module and (args.c_uuid or args.c_dir or c_fs['fstype'] not in ('ext4', 'vfat')):
        volume = module.choose_c_for_host(module.candidates(), args.c_uuid, False)
        if volume:
            if c_dir and volume['fstype'] != 'ext4':
                raise ValueError('--c-dir requires an ext4 C: volume')
            c_fs = {'fstype': volume['fstype']}
    mode = installation_mode(args, root_fs, boot_fs, c_fs)
    if mode == 'disk':
        copy = args.copy_showcase
        if copy is None:
            import sys
            copy = (volume is None and not c_root.exists() and sys.stdin.isatty() and input(
                f'Copy missing showcase files into {c_root}? [y/N] ').strip().lower() in ('y', 'yes'))
        archive = args.archive or (ROOT / 'machine_boot.tar' if (ROOT / 'machine_boot.tar').exists() else None)
        disk.prepare(c_root if volume is None else None, destination, archive, copy, args.showcase_archive,
                     volume=volume, c_dir=c_dir, root_uuid=args.root_uuid)
        selected = disk.STAGE / 'selected'
    else:
        if args.archive:
            raise ValueError('--archive supplies a disk runtime; use --image or the bundled RAM core for this layout')
        c_uuid, c_dir = args.c_uuid, args.c_dir
        if args.c_root or (not (args.c_uuid or args.c_dir or args.c_ram)
                           and root_fs['fstype'] == 'ext4' and c_fs['fstype'] == 'ext4'):
            c_uuid, c_dir = c_selection(c_root, c_fs)
        core = args.image or (ROOT if (ROOT / 'retroos-base.img.gz').exists() else ROOT / 'bazel-bin')
        module.prepare(core.resolve(), destination, c_uuid, args.root_uuid,
                       args.c_ram, c_dir, bool(args.copy_showcase), args.showcase_archive)
        selected = module.STAGE_ROOT / 'selected'
    SELECTED.parent.mkdir(parents=True, exist_ok=True)
    SELECTED.write_text(json.dumps({'mode': mode, 'stage': selected.read_text().strip()}) + '\n')
    print('Prepared a machine installation; run the same installer as root to install it.')


if __name__ == '__main__':
    main()
