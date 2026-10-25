#!/usr/bin/env python3
"""Check CPU duty limits, live BIOS ticks and per-program batch policy on KVM."""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = r"""
bits 16
org 100h
xor ah, ah
int 1ah
mov bp, dx
mov ecx, 40000000h
.busy:
dec ecx
jnz .busy
xor ah, ah
int 1ah
sub dx, bp
mov bx, dx
mov dx, message
mov ah, 9
int 21h
mov cx, 4
.hex:
rol bx, 4
mov dl, bl
and dl, 15
add dl, '0'
cmp dl, '9'
jbe .digit
add dl, 7
.digit:
mov ah, 2
int 21h
loop .hex
mov dx, newline
mov ah, 9
int 21h
mov ax, 4c00h
int 21h
message db 'PACING TICKS=', '$'
newline db 13, 10, '$'
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('KVM access is required')
    if not args.no_build:
        subprocess.run(['bazelisk', 'build', '//tools/command:command_com'], check=True)
        subprocess.run(['bazelisk', 'build', '//kernel:retroos-host-kvm',
                        '--platforms=@platforms//host'], check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-cpu-pacing-') as raw:
        root = Path(raw)
        (root / 'RETROOS').mkdir()
        shutil.copyfile('bazel-bin/tools/command/COMMAND.COM', root / 'COMMAND.COM')
        (root / 'probe.asm').write_text(PROBE)
        subprocess.run(['nasm', '-f', 'bin', str(root / 'probe.asm'),
                        '-o', str(root / 'NORMAL.COM')], check=True)
        for name in ('LIMITED', 'WRAPPED'):
            shutil.copyfile(root / 'NORMAL.COM', root / (name + '.COM'))
        (root / 'RETROOS/RETROOS.INI').write_text(
            '[environment]\nCOMSPEC=C:\\COMMAND.COM\n'
            '[launch]\nLIMITED.COM=cpu25\nWRAPPED.COM=loadfix cpu25\n')
        (root / 'CHECK.BAT').write_bytes(b'LIMITED.COM\r\nNORMAL.COM\r\n')

        def run(command):
            result = subprocess.run([
                'python3', 'test/disk_fixture.py', '--root', raw, '--',
                'bazel-bin/kernel/retroos-host-kvm', '--cmd', command,
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=60)
            text = result.stdout.decode(errors='replace')
            ticks = [int(n, 16) for n in re.findall(r'PACING TICKS=([0-9A-F]{4})', text)]
            if result.returncode or not ticks or 'panicked' in text:
                raise AssertionError(command + '\n' + text)
            print(command, ticks, flush=True)
            return ticks, text

        normal, _ = run('COMMAND.COM /C NORMAL.COM')
        limited, text = run('COMMAND.COM /C LIMITED.COM')
        assert 'DOS CPU limit: 25%' in text
        # A broad ratio tolerates tick quantization and host scheduling while
        # rejecting a dropped policy, stopped clock or ineffective limiter.
        assert normal[0] > 0 and limited[0] >= normal[0] * 2, (normal, limited)
        wrapped, text = run('COMMAND.COM /C WRAPPED.COM')
        assert 'DOS CPU limit: 25%' in text and wrapped[0] >= normal[0] * 2
        batch, _ = run('COMMAND.COM /C CHECK.BAT')
        assert len(batch) == 2 and batch[0] >= batch[1] * 2 and batch[1] > 0, batch
        print('PASS: fork, LOADFIX and batch CPU policies; BIOS clock remains live')


if __name__ == '__main__':
    main()
