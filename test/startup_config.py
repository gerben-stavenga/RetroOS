#!/usr/bin/env python3
"""Check INI startup arguments, overrides, locale and restart behavior."""
from pathlib import Path
import importlib.util
import sys
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-start-config-') as tmp:
        work = Path(tmp)
        root = work / 'home/retroos'
        (root / 'RETROOS').mkdir(parents=True)
        config = root / 'RETROOS/RETROOS.INI'
        source = work / 'probe.asm'
        source.write_text('''bits 16
org 100h
mov dx, message
mov ah, 9
int 21h
xor cx, cx
mov cl, [80h]
mov bx, 1
mov dx, 81h
mov ah, 40h
int 21h
mov dx, newline
mov ah, 9
int 21h
mov ax, 6601h
int 21h
jc no_cp850
cmp bx, 850
jne no_cp850
mov dx, cp850
mov ah, 9
int 21h
no_cp850:
mov ax, 4c00h
int 21h
message db 'STARTUP-OK ', '$'
newline db 13, 10, '$'
cp850 db 'CP850', 13, 10, '$'
''')
        subprocess.run(['nasm', '-f', 'bin', source, '-o', root / 'BOOT.COM'], check=True)
        subprocess.run(['bazelisk', 'build', '//kernel:retroos-host',
                        '--platforms=@platforms//host'], cwd=ROOT, check=True)

        def boot(label, extra=(), repeated=True):
            log = work / (label + '.log')
            with log.open('wb') as output:
                proc = subprocess.Popen([str(ROOT / 'bazel-bin/kernel/retroos-host'),
                                         '--host', str(work), *extra],
                                        stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        data = log.read_bytes()
                        if (data.count(b'STARTUP-OK') >= 2 if repeated else proc.poll() is not None):
                            break
                        if proc.poll() is not None:
                            break
                        time.sleep(.05)
                    else:
                        raise AssertionError('boot timed out: ' + label)
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=5)
            data = log.read_bytes()
            assert b'STARTUP-OK ' + label.encode() in data, data[-4000:]
            if repeated:
                assert b'Startup program exited, restarting' in data, data[-4000:]
            else:
                assert proc.returncode == 0 and b'All commands done' in data, data[-4000:]
            print('PASS:', label)

        config.write_bytes(b'[system]\nstart=C:\\BOOT.COM configured\n')
        boot('configured')
        config.write_bytes(b'[system]\nstart=C:\\BOOT.COM cp850\n[locale]\ncodepage=850\n')
        boot('cp850')
        assert b'CP850' in (work / 'cp850.log').read_bytes()
        boot('override', ['--cmd', 'BOOT.COM override'], repeated=False)
        config.write_bytes(b'[system]\nstart=MISSING.COM\n[environment]\nTEST=BOOT.COM test\n')
        boot('test', repeated=False)


if __name__ == '__main__':
    main()
