#!/usr/bin/env python3
"""Execute copied VBE 2.0 PM entry points against the banked software display."""
from pathlib import Path
import shutil
import subprocess
import tempfile

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-vbe-pm-') as directory:
        work = Path(directory)
        data = work / 'data.img'
        with data.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.fat', '-F', '16', str(data)], check=True,
                       stdout=subprocess.DEVNULL)
        shutil.copyfile(ROOT / 'bazel-bin/test/dos/svgaprobe/VBEPM.COM', work / 'VBEPM.COM')
        subprocess.run(['mcopy', '-i', str(data), str(work / 'VBEPM.COM'), '::'], check=True)
        boot = prepare_boot(work, data)
        result = subprocess.run([
            str(ROOT / 'bazel-bin/kernel/retroos-host-kvm'),
            '--boot-disk', str(boot), '--cmd', '/home/retroos/VBEPM.COM', str(data),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=45)
        text = result.stdout.decode(errors='replace')
        assert result.returncode == 0 and 'VBE-PM PASS' in text and 'VBE-PM FAIL' not in text, text
        assert '[mem] exit tid=1 code=0' in text, text
        print('PASS: 320x240 banked mode, 336-byte pitch, relocated PM calls bypass hooked INT 10h')


if __name__ == '__main__':
    main()
