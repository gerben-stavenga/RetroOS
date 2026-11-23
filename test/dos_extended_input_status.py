#!/usr/bin/env python3
"""Check that DOS input status sees both bytes of a single extended key."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
bits 16
org 100h
mov ah, 0bh
int 21h
test al, al
jnz fail

; Seed the same BIOS keyboard buffer entry that IRQ1 would store for Down.
mov ax, 40h
mov es, ax
mov word [es:1eh], 50e0h
mov word [es:1ah], 1eh
mov word [es:1ch], 20h
mov ah, 0bh
int 21h
cmp al, 0ffh
jne fail
mov ah, 07h
int 21h
test al, al
jnz fail

; The BIOS buffer is empty after the leading zero. DOS still owns the scan
; byte, so polling must report it immediately, with no further input.
mov ah, 0bh
int 21h
cmp al, 0ffh
jne fail
mov ah, 07h
int 21h
cmp al, 50h
jne fail
mov ah, 0bh
int 21h
test al, al
jnz fail
mov ah, 09h
mov dx, passed
int 21h
mov ax, 4c00h
int 21h
fail:
mov ax, 4c01h
int 21h
passed db 'DOS EXTENDED INPUT STATUS PASS',13,10,'$'
'''


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-dos-key-status-') as directory:
        root = Path(directory)
        source = root / 'probe.asm'
        source.write_text(PROBE)
        subprocess.run(['nasm', '-f', 'bin', source, '-o', root / 'PROBE.COM'], check=True)
        result = subprocess.run(
            [ROOT / 'bazel-bin/kernel/retroos-host', '--cmd', 'PROBE.COM', root],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors='replace', timeout=20,
        )
        assert result.returncode == 0 and 'DOS EXTENDED INPUT STATUS PASS' in result.stdout, result.stdout
        print('PASS: DOS input status stays ready until both bytes of an arrow are read')


if __name__ == '__main__':
    main()
