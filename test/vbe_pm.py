#!/usr/bin/env python3
"""Execute copied VBE 2.0 PM entry points against the banked software display."""
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-vbe-pm-') as directory:
        work = Path(directory)
        shutil.copyfile(ROOT / 'bazel-bin/test/dos/svgaprobe/VBEPM.COM', work / 'VBEPM.COM')
        result = subprocess.run([
            str(ROOT / 'bazel-bin/kernel/retroos-host-kvm'),
            '--cmd', '/VBEPM.COM', str(work),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=45)
        text = result.stdout.decode(errors='replace')
        assert result.returncode == 0 and 'VBE-PM PASS' in text and 'VBE-PM FAIL' not in text, text
        assert '[mem] exit tid=1 code=0' in text, text
        print('PASS: 320x240 banked mode, 336-byte pitch, relocated PM calls bypass hooked INT 10h')


if __name__ == '__main__':
    main()
