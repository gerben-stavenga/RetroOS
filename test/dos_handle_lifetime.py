#!/usr/bin/env python3
"""Repeated nested DOS EXEC must close child files and preserve parent handles."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LEAK = r'''
bits 16
org 100h
mov dx, name
mov ax, 3d00h
int 21h
jc fail
mov dx, ok
jmp print
fail:
mov dx, bad
print:
mov ah, 9
int 21h
mov ax, 4c00h
int 21h
name db 'DATA.BIN',0
ok db 'OPEN OK',13,10,'$'
bad db 'OPEN FAILED',13,10,'$'
'''
PARENT = r'''
bits 16
org 100h
mov sp, stack_top
mov bx, (stack_top-$$+100h+15)/16
mov ah, 4ah
int 21h
jc fail
mov [params+4],ds
mov dx, data_name
mov ax,3d00h
int 21h
jc fail
mov [handle],ax
mov [tail+1],al
mov word [iterations],40
again:
mov bx,[handle]
xor cx,cx
xor dx,dx
mov ax,4200h
int 21h
jc fail
push ds
pop es
mov bx,params
mov dx,child_name
mov ax,4b00h
int 21h
push cs
pop ds
jc fail
mov bx,[handle]
mov cx,1
mov dx,byte_read
mov ah,3fh
int 21h
jc fail
cmp ax,1
jne fail
cmp byte [byte_read],'a'
jne fail
dec word [iterations]
jnz again
mov dx,ok
jmp print
fail:
mov dx,bad
print:
mov ah,9
int 21h
mov ax,4c00h
int 21h
params dw 0,tail,0,0,0,0,0
tail db 1,0,13
handle dw 0
iterations dw 0
byte_read db 0
child_name db 'CHILD.COM',0
data_name db 'DATA.BIN',0
ok db 'PARENT HANDLES PASS',13,10,'$'
bad db 'PARENT HANDLES FAIL',13,10,'$'
times 512 db 0
stack_top:
'''
CHILD = r'''
bits 16
org 100h
xor bx,bx
mov bl,[81h]
mov [handle],bx
mov cx,1
mov dx,byte_read
mov ah,3fh
int 21h
jc fail
cmp byte [byte_read],'h'
jne fail
mov bx,[handle]
mov ah,3eh
int 21h
jc fail
mov dx,data_name
mov ax,3d00h
int 21h
jc fail
; Leave this new file open. Normal child exit must release it.
EXIT
fail:
mov dx,bad
mov ah,9
int 21h
mov ax,4c01h
int 21h
handle dw 0
byte_read db 0
data_name db 'DATA.BIN',0
bad db 'CHILD HANDLES FAIL',13,10,'$'
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--engine', choices=['kvm', 'interp'], default='kvm')
    args = parser.parse_args()
    os.chdir(ROOT)
    target = 'retroos-host-kvm' if args.engine == 'kvm' else 'retroos-host'
    if not args.no_build:
        subprocess.run(['bazelisk', 'build', '//tools/command:command_com'], check=True)
        subprocess.run(['bazelisk', 'build', '--platforms=@platforms//host',
                        '//kernel:' + target], check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-handle-lifetime-') as raw:
        root = Path(raw)
        (root / 'RETROOS').mkdir()
        shutil.copyfile('bazel-bin/tools/command/COMMAND.COM', root / 'COMMAND.COM')
        (root / 'RETROOS/RETROOS.INI').write_text('[environment]\nCOMSPEC=C:\\COMMAND.COM\n')
        (root / 'DATA.BIN').write_bytes(b'handle test')

        def assemble(name, source):
            asm = root / (name + '.asm')
            asm.write_text(source)
            subprocess.run(['nasm', '-f', 'bin', str(asm), '-o', str(root / (name + '.COM'))], check=True)

        def run(batch):
            (root / 'CHECK.BAT').write_bytes(batch)
            result = subprocess.run(['python3', 'test/disk_fixture.py', '--root', raw,
                '--', 'bazel-bin/kernel/' + target, '--cmd', 'COMMAND.COM /C CHECK.BAT'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=90)
            text = result.stdout.decode(errors='replace')
            assert result.returncode == 0 and 'panicked' not in text, text
            return text

        assemble('LEAK', LEAK)
        output = run(b'LEAK.COM\r\n' * 80)
        assert output.count('OPEN OK') == 80 and 'OPEN FAILED' not in output, output
        print('PASS: 80 unclosed-child-file launches')
        assemble('PARENT', PARENT)
        for exit_instruction in ('mov ax,4c00h\nint 21h', 'int 20h'):
            assemble('CHILD', CHILD.replace('EXIT', exit_instruction))
            output = run(b'PARENT.COM\r\n')
            assert 'PARENT HANDLES PASS' in output and 'HANDLES FAIL' not in output, output
            print('PASS: 40 nested children preserve parent handle and shared offset:', exit_instruction.splitlines()[-1])
        # A failed grandchild load must not discard the current EXEC parent.
        (root / 'BAD.EXE').write_bytes(b'MZ' + bytes(6) + b'\xff\xff' + bytes(54))
        failed_exec = r"""
mov [params+4],ds
push ds
pop es
mov bx,params
mov dx,bad_name
mov ax,4b00h
int 21h
push cs
pop ds
jnc fail
mov bx,[handle]
"""
        child = CHILD.replace('mov [handle],bx', 'mov [handle],bx' + failed_exec)
        child += "\nparams dw 0,tail,0,0,0,0,0\ntail db 0,13\nbad_name db 'BAD.EXE',0\n"
        assemble('CHILD', child.replace('EXIT', 'mov ax,4c00h\nint 21h'))
        output = run(b'PARENT.COM\r\n')
        assert 'PARENT HANDLES PASS' in output and 'HANDLES FAIL' not in output, output
        print('PASS: failed nested EXEC preserves the parent descriptor snapshot')



if __name__ == '__main__':
    main()
