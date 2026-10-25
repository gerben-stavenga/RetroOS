#!/usr/bin/env python3
"""Run a hosted kernel against an isolated ext4 fixture; copy guest changes back.

The guest sees a real block device. There is no host filesystem backend or
transport. Test input trees are snapshotted before launch and only guest-changed
files are copied back, so concurrent host logs are not overwritten.
"""
from pathlib import Path
import argparse
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import uuid


def fingerprint(path):
    if path.is_symlink():
        return ('link', os.readlink(path))
    if path.is_file():
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').digest()
        return ('file', digest, path.stat().st_mode & 0o777)
    return ('dir',)


def manifest(root):
    return {str(path.relative_to(root)): fingerprint(path) for path in root.rglob('*')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a hosted kernel command is required')
    root = args.root.resolve()
    with tempfile.TemporaryDirectory(prefix='retroos-disk-fixture-') as raw:
        work = Path(raw)
        tree = work / 'tree'
        shutil.copytree(root, tree, symlinks=True)
        original = manifest(tree)
        config = tree / 'RETROOS/BOOT.INI'
        config.parent.mkdir(exist_ok=True)
        volume_id = str(uuid.uuid4())
        c_root = command[command.index('--c-root') + 1] if '--c-root' in command else (
            '/home/retroos' if (tree / 'home/retroos').is_dir() else '/')
        c_root = '/' + c_root.strip('/')
        settings = (f'[bundle]\nsource=UUID={volume_id}\nsubdir=/\n'
                    f'[mount "fixture"]\nsource=UUID={volume_id}\npath=/\naccess=rw\ngrant=/\n')
        if c_root.strip('/'):
            settings += (f'[mount "dos"]\nsource=UUID={volume_id}\nsubdir={c_root}\n'
                         f'path={c_root}\ndrive=C\naccess=rw\ngrant=/\n')
        else:
            settings += 'drive=C\n'
        config.write_text(settings)
        before = manifest(tree)
        image = work / 'disk.img'
        occupied = sum(p.stat().st_size for p in tree.rglob('*') if p.is_file() and not p.is_symlink())
        with image.open('wb') as stream:
            stream.truncate(max(64 * 1024 * 1024, occupied * 2 + 32 * 1024 * 1024))
        subprocess.run(['mkfs.ext4', '-q', '-F', '-U', volume_id, '-E',
                        f'root_owner={os.getuid()}:{os.getgid()}', '-d', str(tree), str(image)], check=True)
        process = subprocess.Popen([*command, str(image)])
        def stop(number, _frame):
            if process.poll() is None:
                process.send_signal(number)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        result = process.wait()
        extracted = work / 'extracted'
        extracted.mkdir()
        subprocess.run(['debugfs', '-R', f'rdump / {extracted}', str(image)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        after = manifest(extracted)
        for name, state in after.items():
            if name == 'lost+found' or name.startswith('lost+found/') or name == 'RETROOS/BOOT.INI':
                continue
            if before.get(name) == state:
                continue
            source, destination = extracted / name, root / name
            if state[0] == 'dir':
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.is_symlink() or destination.is_file():
                    destination.unlink()
                if state[0] == 'link':
                    destination.symlink_to(os.readlink(source))
                else:
                    shutil.copy2(source, destination)
        for name in sorted(original, key=lambda x: x.count('/'), reverse=True):
            target = root / name
            if name not in after and (target.exists() or target.is_symlink()) and fingerprint(target) == original[name]:
                if target.is_dir() and not target.is_symlink():
                    if not any(target.iterdir()):
                        target.rmdir()
                else:
                    target.unlink()
        raise SystemExit(result if result >= 0 else 128 - result)


if __name__ == '__main__':
    main()
