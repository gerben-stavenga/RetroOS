#!/usr/bin/env python3
"""Install local WCN7850 firmware without embedding it in the source tree.

Use --directory for a mounted RetroOS root, --c-root for a directory-backed
C:, or --data-image for its FAT C:.
Compressed Linux .zst/.xz firmware is unpacked before installation.
"""
import argparse
import fcntl
import lzma
from pathlib import Path
import struct
import subprocess
import tempfile

FAMILY = Path('ath12k/WCN7850/hw2.0')
FILES = ('amss.bin', 'm3.bin', 'board-2.bin', 'Notice.txt')
MAXIMUM = 32 * 1024 * 1024


def unpack(source, destination):
    """Read and validate all files before changing the installation target."""
    images = {}
    for name in FILES:
        base = Path(source) / FAMILY / name
        if base.is_file():
            image = base.read_bytes()
        elif Path(str(base) + '.zst').is_file():
            image = subprocess.check_output(['zstd', '-q', '-d', '-c', str(base) + '.zst'])
        elif Path(str(base) + '.xz').is_file():
            image = lzma.decompress(Path(str(base) + '.xz').read_bytes())
        else:
            raise ValueError(f'Missing firmware or license: {base}')
        if not image or len(image) > MAXIMUM:
            raise ValueError(f'Invalid firmware size: {name}')
        if name.endswith('.bin'):
            magic = b'QCA-ATH12K-BOARD\0' if name == 'board-2.bin' else b'\x7fELF'
            if not image.startswith(magic):
                raise ValueError(f'Unexpected firmware format: {name}')
        images[name] = image
    destination = Path(destination) / FAMILY
    destination.mkdir(parents=True, exist_ok=True)
    for name, image in images.items():
        (destination / name).write_bytes(image)
    return destination


def install_disk(image, files):
    image = Path(image).resolve(strict=True)
    # Same advisory lock used by run.sh; never edit a running VM's disk.
    with Path(str(image) + '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with image.open('rb') as stream:
            mbr = stream.read(512)
        if len(mbr) != 512 or mbr[510:] != b'\x55\xaa':
            raise ValueError('Expected an MBR data disk')
        starts = [struct.unpack_from('<I', mbr, 446 + i * 16 + 8)[0]
                  for i in range(4) if mbr[446 + i * 16 + 4] in (1, 4, 6, 11, 12, 14)]
        if len(starts) != 1:
            raise ValueError('Expected exactly one FAT C: partition')
        volume = f'{image}@@{starts[0] * 512}'
        parent = '::'
        for part in ('RETROOS', 'FIRMWARE', *FAMILY.parts):
            parent += '/' + part
            exists = subprocess.run(['mdir', '-i', volume, parent], capture_output=True)
            if exists.returncode:
                subprocess.run(['mmd', '-i', volume, parent], check=True)
        for name in FILES:
            subprocess.run(['mcopy', '-o', '-i', volume, str(files / name), parent + '/' + name], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('/lib/firmware'))
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--directory', type=Path)
    target.add_argument('--c-root', type=Path, help='install under C:\\RETROOS\\FIRMWARE in this C: directory')
    target.add_argument('--data-image', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='retroos-wifi-firmware-') as temporary:
        files = unpack(args.source, temporary)
        if args.data_image:
            install_disk(args.data_image, files)
        else:
            import shutil
            root = args.c_root / 'RETROOS/FIRMWARE' if args.c_root else args.directory / 'lib/firmware'
            destination = root / FAMILY
            destination.mkdir(parents=True, exist_ok=True)
            for name in FILES:
                shutil.copyfile(files / name, destination / name)
    print('Installed WCN7850 firmware and its license.')


if __name__ == '__main__':
    main()
