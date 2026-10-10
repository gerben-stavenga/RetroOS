#!/usr/bin/env python3
"""Configure a disposable VM boot image for its explicitly attached data disk.

Only the boot COPY is modified. The supplied data image is opened read-only;
its filesystem UUIDs become the same INI mount sources used on real hardware.
"""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile
import uuid


def volumes(path):
    result = []
    with Path(path).open('rb') as stream:
        mbr = stream.read(512)
        starts = [struct.unpack_from('<I', mbr, 446+i*16+8)[0]
                  for i in range(4) if mbr[446+i*16+4] and struct.unpack_from('<I', mbr, 446+i*16+12)[0]]
        for start in starts or [0]:
            stream.seek(start*512)
            boot = stream.read(512)
            if boot[510:512] == b'\x55\xaa' and struct.unpack_from('<H', boot, 11)[0] == 512:
                signature, serial = (66, 67) if boot[22:24] == b'\0\0' else (38, 39)
                if boot[signature] == 0x29:
                    ident = struct.unpack_from('<I', boot, serial)[0]
                    result.append(('fat', f'{ident >> 16:04X}-{ident & 0xffff:04X}'))
            stream.seek(start*512 + 1024)
            sb = stream.read(120)
            if sb[56:58] == b'\x53\xef':
                result.append(('ext4', str(uuid.UUID(bytes=sb[104:120]))))
    return result


def split_configuration(text):
    """Separate user settings from storage sections, preserving text and comments."""
    boot, user = [], []
    target = user
    for line in text.splitlines(keepends=True):
        section = line.strip()
        if section.startswith('['):
            target = boot if section == '[bundle]' or section.startswith('[mount ') else user
        target.append(line)
    return ''.join(boot), ''.join(user)


def boot_configuration(text, detected):
    mounts, _ = split_configuration(text)
    if '[bundle]' in mounts:
        # The VM's runtime is always on its separately attached boot disk.
        begin = mounts.index('[bundle]')
        end = mounts.find('[', begin + 1)
        mounts = mounts[:begin] + (mounts[end:] if end >= 0 else '')
    if '[mount "data"]' not in mounts:
        mounts = configure('', detected)
    return '[bundle]\nsource=UUID=5E77-0002\nsubdir=/\n\n' + mounts


def configure(text, detected):
    root = next((ident for kind, ident in detected if kind == 'ext4'), None)
    data = next(((kind, ident) for kind, ident in detected if kind == 'fat'), None)
    if data is None and root: data = ('ext4', root)
    if data is None: raise ValueError('Attached data image has no FAT/ext4 filesystem UUID')
    # Retain system, regional and environment defaults, replace mount policy.
    text = text.split('[mount "session"]', 1)[0]
    if root:
        text += f'[mount "linux"]\nsource=UUID={root}\npath=/\naccess=rw\ngrant=/home/retroos\n\n'
    kind, ident = data
    text += f'[mount "data"]\nsource=UUID={ident}\npath=/home/retroos\ndrive=C\naccess=rw\n'
    if kind == 'ext4': text += 'subdir=/home/retroos\ngrant=/home/retroos\n'
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot-image', required=True)
    parser.add_argument('--data-image', required=True)
    parser.add_argument('--command', help='One-shot startup command for the disposable boot copy')
    args = parser.parse_args()
    boot = str(Path(args.boot_image).resolve()) + '@@1048576'
    text = subprocess.check_output(['mtype', '-i', boot, '::RETROOS/RETROOS.INI']).decode('utf-8')
    if args.command:
        if any(c in args.command for c in '\r\n\0'):
            raise ValueError('Startup command must be one line')
        text = text.split('[mount \"session\"]', 1)[0] + '[environment]\nTEST=' + args.command + '\n'
    generated = boot_configuration('', volumes(args.data_image))
    _, settings = split_configuration(text)
    with tempfile.TemporaryDirectory(prefix='retroos-vm-config-') as work:
        for name, content in [('BOOT.INI', generated), ('RETROOS.INI', settings)]:
            path = Path(work)/name
            path.write_text(content)
            subprocess.run(['mcopy', '-o', '-i', boot, str(path), '::RETROOS/' + name], check=True)



if __name__ == '__main__': main()
