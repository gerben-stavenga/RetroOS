#!/usr/bin/env python3
"""Build a native Wi-Fi bring-up USB image using locally installed firmware.

The firmware is loaded into RAM by GRUB, so bring-up does not depend on USB
mass-storage support or on access to the laptop's internal filesystem.
This creates an image file only; it never writes a physical USB device.
"""
import argparse
import gzip
from pathlib import Path
import subprocess
import tarfile
import tempfile

from wifi_firmware import unpack

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('/lib/firmware'))
    parser.add_argument('--out', type=Path, default=ROOT / 'build/native-wifi/retroos-wifi.img')
    args = parser.parse_args()
    output = args.out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    run('bazelisk', 'build', '//kernel:kernel_elf', '//:root_module_base_tar')
    with tempfile.TemporaryDirectory(prefix='retroos-wifi-image-') as directory:
        work = Path(directory)
        firmware = work / 'firmware'
        unpack(args.source, firmware)
        contents = work / 'contents.tar'
        # Preserve the boot bundle's symlinks and metadata without extracting
        # them into the host filesystem. Add only this device's firmware.
        with tarfile.open(ROOT / 'bazel-bin/root_module_base_tar.tar') as base, tarfile.open(contents, 'w') as combined:
            for member in base:
                combined.addfile(member, base.extractfile(member) if member.isfile() else None)
            combined.add(firmware, arcname='lib/firmware')
        image = work / 'base.img'
        run('python3', ROOT / 'tools/build_module_image.py', '--contents', contents,
            '--size-mb', '32', '--writable-root', '--out', image)
        compressed = work / 'base.img.gz'
        with image.open('rb') as source, compressed.open('wb') as target:
            with gzip.GzipFile(fileobj=target, mode='wb', mtime=0) as archive:
                import shutil
                shutil.copyfileobj(source, archive)
        run('python3', ROOT / 'tools/build_grub_module_usb.py',
            '--kernel', ROOT / 'bazel-bin/kernel/kernel.elf', '--base', compressed,
            '--grub-cfg', ROOT / 'tools/grub-module.cfg', '--boot-ini', ROOT / 'etc/BOOT.INI',
            '--ini', ROOT / 'etc/RETROOS.INI', '--license', ROOT / 'THIRD_PARTY_LICENSES.md', '--out', output)
    print(f'Native Wi-Fi diagnostic image: {output}')
    print('Boot its default RAM session; inspect C:\\KLOG.TXT and C:\\PROC\\WIFI.')


if __name__ == '__main__':
    main()
