#!/usr/bin/env python3
"""Verify PM-only VBE palette changes and page flips reach resident scanout."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

from game_suite import ppm

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='vbe-pm-video-') as directory:
        work = Path(directory)
        disk = work / 'data.img'
        with disk.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.fat', '-F', '16', str(disk)], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(['mcopy', '-i', str(disk),
                        str(ROOT / 'bazel-bin/test/dos/svgaprobe/VBEVIS.COM'), '::'], check=True)
        log = work / 'kernel.log'
        qmp = work / 'qmp'
        env = dict(os.environ, RETROOS_PREBUILT='1', AUDIO_BACKEND='none')
        with log.open('wb') as output:
            process = subprocess.Popen([
                './run.sh', 'qemu', '--kvm', '--headless', '--sound', 'none',
                '--net', 'none', '--data-image', str(disk),
                '--cmd', '/home/retroos/VBEVIS.COM', '--', '-smp', '2',
                '-qmp', f'unix:{qmp},server=on,wait=off',
            ], cwd=ROOT, env=env, stdout=output, stderr=output,
                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            def wait_for(predicate, description, timeout=45):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    text = log.read_text(errors='replace')
                    assert process.poll() is None, text[-4000:]
                    assert 'VBE-PM FAIL' not in text and 'FATAL' not in text, text[-4000:]
                    if predicate():
                        return
                    time.sleep(.05)
                raise AssertionError(description + '\n' + log.read_text(errors='replace')[-4000:])

            wait_for(qmp.exists, 'QMP socket did not appear')
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(5)
                connection.connect(str(qmp))
                with connection.makefile('rwb') as stream:
                    stream.readline()

                    def call(command, **arguments):
                        stream.write((json.dumps(dict(execute=command, arguments=arguments)) + '\n').encode())
                        stream.flush()
                        while True:
                            response = json.loads(stream.readline())
                            assert 'error' not in response, response
                            if 'return' in response:
                                return response['return']

                    call('qmp_capabilities')
                    for name, expected in [('RED', (255, 0, 0)),
                                           ('GREEN', (0, 255, 0)),
                                           ('BLUE', (0, 0, 255))]:
                        if name == 'RED':
                            wait_for(lambda: 'VBE-VISUAL-RED' in log.read_text(errors='replace'),
                                     'visual probe did not start')
                        shot = work / (name + '.ppm')

                        def correct_colour():
                            call('screendump', filename=str(shot))
                            width, height, pixels = ppm(shot.read_bytes())
                            return all(tuple(pixels[offset:offset + 3]) == expected
                                       for x in [.3, .5, .7] for y in [.3, .5, .7]
                                       for offset in [(int(height * y) * width + int(width * x)) * 3])

                        wait_for(correct_colour, name + ' did not reach the display', timeout=5)
                        # Check successive presentations, not just one lucky frame.
                        for _ in range(8):
                            time.sleep(.05)
                            assert correct_colour(), name + ' flickered or displayed a stale page/palette'
                        call('human-monitor-command', **{'command-line': 'sendkey ret'})
                    wait_for(lambda: 'VBE-PM PASS' in log.read_text(errors='replace'),
                             'visual probe did not finish')
                    call('quit')
            process.wait(timeout=5)
            print('PASS: PM palette updates and page flips remain visible across successive UEFI/KVM frames')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)


if __name__ == '__main__':
    main()
