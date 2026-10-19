#!/usr/bin/env python3
"""Linux yield/wait keep keyboard focus and a stable frame above a DOS launcher."""
from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = ROOT / 'build/ci/console-focus'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-console-focus-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        subprocess.run(['gcc', '-O2', '-nostdlib', '-static', '-no-pie', '-fno-pie',
                        '-fno-stack-protector', str(ROOT / 'test/linux_console_focus_probe.c'),
                        '-o', str(home / 'PROBE.ELF')], check=True)
        subprocess.run(['nasm', '-f', 'bin', str(ROOT / 'test/linux_console_focus_launcher.asm'),
                        '-o', str(home / 'LAUNCH.COM')], check=True)
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(work / 'profile.json')
        qmp = work / 'qmp.sock'
        log_path = artifacts / 'klog.txt'
        with log_path.open('w') as log:
            process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm',
                '--headless', '--sound', 'none', '--cmd', '/home/retroos/LAUNCH.COM',
                '--', '-m', '512', '-qmp', f'unix:{qmp},server=on,wait=off'],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            connection = None
            try:
                deadline = time.monotonic() + 120
                while not qmp.exists():
                    assert process.poll() is None and time.monotonic() < deadline, str(log_path)
                    time.sleep(.1)
                connection = socket.socket(socket.AF_UNIX)
                connection.connect(str(qmp))
                connection.settimeout(10)
                stream = connection.makefile('rwb')
                stream.readline()

                def command(name, **arguments):
                    stream.write((json.dumps({'execute': name, 'arguments': arguments}) + '\n').encode())
                    stream.flush()
                    while True:
                        reply = json.loads(stream.readline())
                        assert 'error' not in reply, reply
                        if 'return' in reply:
                            return reply['return']

                command('qmp_capabilities')
                deadline = time.monotonic() + 25
                while not (home / 'ready').exists():
                    assert process.poll() is None and time.monotonic() < deadline, (
                        'Linux yield returned focus to the DOS launcher; ' + str(log_path))
                    time.sleep(.1)
                # Both Linux processes are now blocked: child on terminal input,
                # parent on child exit. Polling must not clear their shared frame.
                time.sleep(.7)
                colored = []
                for index in range(8):
                    path = artifacts / f'frame-{index}.ppm'
                    command('screendump', filename=str(path))
                    with Image.open(path) as image:
                        colored.append(sum(g > r + 20 and g > b + 20
                                           for r, g, b in image.convert('RGB').getdata()))
                    time.sleep(.04)
                assert min(colored) > 10000, ('Shared terminal frame was cleared', colored)
                command('human-monitor-command', **{'command-line': 'sendkey k'})
                time.sleep(.1)
                command('human-monitor-command', **{'command-line': 'sendkey ret'})
                deadline = time.monotonic() + 10
                while not (home / 'result').exists():
                    assert process.poll() is None and time.monotonic() < deadline, (
                        'Keyboard input missed the waiting Linux child; ' + str(log_path))
                    time.sleep(.1)
                assert (home / 'result').read_text() == 'FOCUS PASS\n'
            finally:
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=15)
    print('PASS: Linux yield/wait retain console focus, frame and keyboard above DOS')


if __name__ == '__main__':
    main()
