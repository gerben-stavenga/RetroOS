#!/usr/bin/env python3
"""Check startup config migration, precedence, arguments, and restart behavior."""
from pathlib import Path
import importlib.util
import sys
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT / 'tools'))
    spec = importlib.util.spec_from_file_location('installer', ROOT / 'tools/machine_install.py')
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with tempfile.TemporaryDirectory(prefix='retroos-start-config-') as tmp:
        work = Path(tmp)
        root = work / 'home/retroos'
        root.mkdir(parents=True)
        fresh = work / 'fresh'
        fresh.mkdir()
        migration.migrate(fresh)
        assert b'START=C:\\RETROOS\\DN\\DN.COM' in (fresh / 'CONFIG/CONFIG.SYS').read_bytes()
        legacy = b'CUSTOM=keep\r\nSTART=C:\\CUSTOM.COM arg\r\n'
        (root / 'CONFIG.SYS').write_bytes(legacy)
        migration.migrate(root)
        config = root / 'CONFIG/CONFIG.SYS'
        assert b'CUSTOM=keep' in config.read_bytes()
        assert b'START=C:\\CUSTOM.COM arg' in config.read_bytes()
        assert (root / 'CONFIG.SYS').read_bytes() == legacy
        config.write_bytes(b'START=BOOT.COM newer\r\nCUSTOM=new\r\n')
        migration.migrate(root)
        assert b'START=BOOT.COM newer' in config.read_bytes()
        assert b'CUSTOM=new' in config.read_bytes()
        print('PASS: migration preserves custom settings and prefers the new config')

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
mov ax, 4c00h
int 21h
message db 'STARTUP-OK ', '$'
newline db 13, 10, '$'
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

        (root / 'CONFIG.SYS').write_bytes(b'START=BOOT.COM legacy\n')
        config.write_bytes(b'START=C:\\BOOT.COM configured\n')
        boot('configured')
        boot('override', ['--cmd', 'BOOT.COM override'], repeated=False)
        config.write_bytes(b'START=MISSING.COM\nTEST=BOOT.COM test\n')
        boot('test', repeated=False)
        config.unlink()
        boot('legacy')


if __name__ == '__main__':
    main()
