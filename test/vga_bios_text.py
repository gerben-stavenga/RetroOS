#!/usr/bin/env python3
"""Verify paired VGA readback and BIOS text access through a trapped aperture."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='vga-bios-text-') as directory:
        work = Path(directory)
        disk = work / 'data.img'
        with disk.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.fat', '-F', '16', str(disk)], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(['mcopy', '-i', str(disk),
                        str(ROOT / 'bazel-bin/test/dos/svgaprobe/VGATEXT.COM'), '::'], check=True)
        log = work / 'kernel.log'
        with log.open('wb') as output:
            process = subprocess.Popen([
                './run.sh', 'qemu', '--kvm', '--headless', '--sound', 'none',
                '--net', 'none', '--data-image', str(disk),
                '--cmd', '/home/retroos/VGATEXT.COM',
            ], cwd=ROOT, env=dict(os.environ, RETROOS_PREBUILT='1'),
                stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                start_new_session=True)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                assert 'FATAL' not in text and 'VGA-TEXT FAIL' not in text, text
                if 'VGA-TEXT PASS' in text and '[mem] exit tid=1 code=0' in text:
                    print('PASS: paired VGA read/write addressing and BIOS text access through a trapped aperture')
                    return
                assert process.poll() is None, text
                time.sleep(.05)
            raise AssertionError('VGA text probe timed out\n' + log.read_text(errors='replace'))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
