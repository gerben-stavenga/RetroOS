#!/usr/bin/env python3
"""Real DOS drive/CDS enumeration, per-drive cwd and read-only spare partitions."""
import hashlib
import pathlib
import tempfile
from boot_composition import run, file, image, boot

PROBE = r'''
bits 16
org 100h
    mov ah,52h
    int 21h
    cmp byte [es:bx+21h],9
    jne fail
    les bx,[es:bx+16h]
    test word [es:bx+4*81+43h],4000h
    jz fail
    test word [es:bx+7*81+43h],4000h
    jnz fail
    test word [es:bx+8*81+43h],4000h
    jz fail
    push ds
    pop es
    mov si,letters
next:
    lodsb
    test al,al
    jz final
    mov [letter],al
    sub al,'A'
    mov dl,al
    mov ah,0eh
    int 21h
    cmp al,9
    jne fail
    mov ah,19h
    int 21h
    add al,'A'
    cmp al,[letter]
    jne fail
    push si
    mov si,cwdbuf
    xor dl,dl
    mov ah,47h
    int 21h
    jc fail
    cmp byte [cwdbuf],0
    jne fail
    mov dx,dirname
    mov ah,3bh
    int 21h
    jc fail
    mov dx,filename
    mov ax,3d00h
    int 21h
    jc fail
    mov bx,ax
    mov ax,4400h
    int 21h
    jc fail
    and dl,3fh
    add dl,'A'
    cmp dl,[letter]
    jne fail
    mov dx,buffer
    mov cx,1
    mov ah,3fh
    int 21h
    jc fail
    cmp ax,1
    jne fail
    mov al,[buffer]
    cmp al,[letter]
    jne fail
    mov ah,3eh
    int 21h
    mov dx,pattern
    xor cx,cx
    mov ah,4eh
    int 21h
    jc fail
    mov dx,newfile
    xor cx,cx
    mov ah,3ch
    int 21h
    jnc fail
    mov ah,36h
    xor dl,dl
    int 21h
    cmp ax,0ffffh
    je fail
    test bx,bx
    jnz fail
    pop si
    jmp next
final:
    mov dl,4
    mov ah,0eh
    int 21h
    mov si,cwdbuf
    xor dl,dl
    mov ah,47h
    int 21h
    jc fail
    cmp dword [cwdbuf],00524944h ; DIR\0 retained while other drives changed
    jne fail
    mov dl,7 ; H must remain absent with no HostFS
    mov ah,0eh
    int 21h
    mov ah,19h
    int 21h
    cmp al,4
    jne fail
    mov dx,ok
    jmp print
fail:
    mov dx,bad
print:
    mov ah,9
    int 21h
    mov ax,4c00h
    int 21h
letters db 'EFGI',0
letter db 0
dirname db '\DIR',0
filename db 'TEST.TXT',0
pattern db '*.TXT',0
newfile db 'NEW.TXT',0
buffer db 0
cwdbuf times 64 db 0
ok db 'COMPOSITION-OK',13,10,'$'
bad db 'COMPOSITION-FAIL',13,10,'$'
'''

def main():
    run('bazelisk', 'build', '//kernel:kernel_elf')
    with tempfile.TemporaryDirectory(prefix='retroos-extra-drives-') as tmp:
        work = pathlib.Path(tmp)
        source = work / 'probe.asm'
        source.write_text(PROBE)
        probe = work / 'probe.com'
        run('nasm', '-f', 'bin', '-o', probe, source)
        tree = work / 'module-tree'
        file(tree, 'home/retroos/RETROOS/PROBE.COM', probe.read_bytes())
        (tree / 'bin').mkdir()
        module = image(work, 'module', tree, 'ext4')
        volumes = []
        for letter in 'CEFGI':
            tree = work / letter
            file(tree, 'DIR/TEST.TXT', letter.encode())
            if letter == 'C':
                (tree / 'CONFIG').mkdir()
            volumes.append(image(work, letter, tree, 'fat'))
        disk = work / 'partitions.img'
        sectors = volumes[0].stat().st_size // 512
        with disk.open('wb') as out:
            out.truncate((2048 + 5 * sectors + 2048) * 512)
        table = 'label: gpt\n' + ''.join(
            f'start={2048 + i * sectors},size={sectors},type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n'
            for i in range(5))
        run('sfdisk', disk, input=table, text=True)
        with disk.open('r+b') as out:
            for i, volume in enumerate(volumes):
                out.seek((2048 + i * sectors) * 512)
                out.write(volume.read_bytes())
        before = hashlib.sha256(disk.read_bytes()).digest()
        text = boot(work, 'extra-partition-drives', module, [disk])
        for letter, number in zip('EFGI', range(1, 5)):
            assert f'DOS {letter}: → /disk{number}' in text, text
        assert hashlib.sha256(disk.read_bytes()).digest() == before
        print('PASS: E/F/G/I CDS, selection, per-drive cwd, read/find, handle drive, read-only; H reserved')

if __name__ == '__main__':
    main()
