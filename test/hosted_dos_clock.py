#!/usr/bin/env python3
"""Check the hosted RTC and COMMAND.COM's clock resync after a forked child."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TICKS_PER_DAY = 0x1800B0

PARENT = r'''
bits 16
org 100h
xor ax, ax
int 1ah
mov [initial], dx
mov [initial+2], cx
; Deliberately set a stale time, half a day away from the host RTC.
mov eax, [initial]
add eax, 0c0058h
cmp eax, 1800b0h
jb set_clock
sub eax, 1800b0h
set_clock:
mov dx, ax
shr eax, 16
mov cx, ax
mov ax, 0100h
int 1ah
; Load COMMAND.COM into our DOS world as DN does for a one-shot shell.
mov sp, stack_top
mov bx, (stack_top-$$+100h+15)/16
mov ah, 4ah
int 21h
jc fail
mov [params+4], ds
push ds
pop es
mov ax, 4b00h
mov bx, params
mov dx, command
int 21h
push cs
pop ds
jc fail
mov ah, 4dh
int 21h
test ax, ax
jnz fail
xor ax, ax
int 1ah
mov [resumed], dx
mov [resumed+2], cx
mov ah, 3ch
xor cx, cx
mov dx, result
int 21h
jc fail
mov bx, ax
mov ah, 40h
mov cx, 8
mov dx, initial
int 21h
mov ah, 3eh
int 21h
mov ax, 4c00h
int 21h
fail:
mov ax, 4c01h
int 21h
command db 'C:\\RETROOS\\COMMAND.COM',0
params dw 0,command_tail,0,0,0,0,0
command_tail db 13,' /C CHILD.COM',13
result db 'CLOCK.BIN',0
initial dd 0
resumed dd 0
times 512 db 0
stack_top:
'''

CHILD = r'''
bits 16
org 100h
mov ax, 0100h
xor cx, cx
xor dx, dx
int 1ah
wait_ticks:
hlt
xor ax, ax
int 1ah
cmp dx, 25
jb wait_ticks
mov ax, 4c00h
int 21h
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kvm', action='store_true')
    options = parser.parse_args()
    runner = 'retroos-play-kvm' if options.kvm else 'retroos-play'
    with tempfile.TemporaryDirectory(prefix='retroos-dos-clock-') as directory:
        root = Path(directory)
        (root / 'RETROOS').mkdir()
        shutil.copyfile(ROOT / 'bazel-bin/tools/command/COMMAND.COM', root / 'RETROOS/COMMAND.COM')
        for name, source in [('PARENT', PARENT), ('CHILD', CHILD)]:
            asm = root / (name + '.ASM')
            asm.write_text(source)
            subprocess.run(['nasm', '-f', 'bin', asm, '-o', root / (name + '.COM')], check=True)
        start = datetime.now(timezone.utc).timestamp()
        result = subprocess.run(
            [ROOT / 'bazel-bin/play' / runner, root, '--cmd', 'PARENT.COM', '--no-audio'],
            env=dict(os.environ, SDL_VIDEODRIVER='dummy', TZ='UTC0'),
            capture_output=True, timeout=25,
        )
        end = datetime.now(timezone.utc).timestamp()
        clock = root / 'CLOCK.BIN'
        log = result.stderr.decode(errors='replace')
        assert result.returncode == 0 and clock.is_file() and 'synth_fork_exec: filename=' in log, log
        initial, resumed = struct.unpack('<II', clock.read_bytes())
        for label, ticks in [('startup', initial), ('after COMMAND.COM', resumed)]:
            # BIOS ticks are quantized and the RTC is sampled at one-second resolution.
            elapsed_from_start = (ticks * 65536 / 1193182 - (start % 86400) + 2) % 86400
            assert ticks < TICKS_PER_DAY and elapsed_from_start <= end - start + 3, (label, ticks)
        print('PASS: hosted DOS starts on real time and COMMAND.COM resyncs after its child exits')


if __name__ == '__main__':
    main()
