#!/usr/bin/env python3
"""Boot with USB keyboard and mouse to exercise both xHCI DMA lanes."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def main():
    subprocess.run([shutil.which('bazelisk') or 'bazel', 'build', '//:boot_disk', '//:data_disk'],
                   cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-xhci-') as temp:
        log = Path(temp) / 'debug.log'
        with log.open('w') as output:
            proc = subprocess.Popen([
                'qemu-system-i386', '-m', '128', '-display', 'none', '-serial', 'none',
                '-no-reboot', '-debugcon', 'stdio',
                '-drive', f'file={ROOT}/bazel-bin/boot_disk.bin,format=raw,snapshot=on',
                '-drive', f'file={ROOT}/bazel-bin/data_disk.bin,format=raw,snapshot=on',
                '-device', 'qemu-xhci,id=usb',
                '-device', 'usb-kbd,bus=usb.0', '-device', 'usb-mouse,bus=usb.0',
                '-fw_cfg', 'name=opt/cmdline,string=TESTS/HELLO.COM',
            ], stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 60
                while proc.poll() is None and time.monotonic() < deadline:
                    if 'All commands done' in log.read_text(errors='replace'):
                        break
                    time.sleep(.1)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=10)
        text = log.read_text(errors='replace')
        for expected in ('xHCI: keyboard ready', 'xHCI: mouse ready',
                         'Hello from HELLO.COM!', 'All commands done'):
            assert expected in text, text
        assert not any(marker in text for marker in ('FATAL', 'PANIC', 'panicked')), text
    print('PASS: xHCI keyboard and mouse initialized and kernel boot completed')


if __name__ == '__main__':
    main()
