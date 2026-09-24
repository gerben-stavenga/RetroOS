#!/usr/bin/env python3
"""Check automatic C: selection and writes on the actual selected data volume."""
import pathlib
import subprocess
import tempfile
from boot_composition import ROOT, run, file, image, boot, partition_image

PROBE = r'''
bits 16
org 100h
    mov dx, name
    xor cx, cx
    mov ah, 3ch
    int 21h
    jc fail
    mov bx, ax
    mov dx, payload
    mov cx, 1
    mov ah, 40h
    int 21h
    jc fail
    cmp ax, 1
    jne fail
    mov ah, 3eh
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
name db 'C:\SELECT.OK',0
payload db 'S'
ok db 'COMPOSITION-OK',13,10,'$'
bad db 'COMPOSITION-FAIL',13,10,'$'
'''


def main():
    run('bazelisk', 'build', '//kernel:kernel_elf')
    with tempfile.TemporaryDirectory(prefix='retroos-selection-') as temp:
        work = pathlib.Path(temp)
        source = work / 'probe.asm'
        source.write_text(PROBE)
        probe = work / 'probe.com'
        run('nasm', '-f', 'bin', '-o', probe, source)
        module_tree = work / 'module-tree'
        file(module_tree, 'home/retroos/RETROOS/PROBE.COM', probe.read_bytes())
        (module_tree / 'bin').mkdir()
        module = image(work, 'module', module_tree, 'ext4')
        # (label, [(format, directories)], selected volume, selected home)
        cases = [
            ('empty-fat', [('fat', [])], 0, ''),
            ('config', [('fat', []), ('fat', ['CONFIG'])], 1, ''),
            ('games', [('fat', []), ('fat', ['GAMES'])], 1, ''),
            ('ultramid', [('fat', []), ('fat', ['ULTRAMID'])], 1, ''),
            ('fat-with-efi', [('fat', []), ('fat', ['EFI', 'CONFIG'])], 1, ''),
            ('fat-with-grub', [('fat', []), ('fat', ['boot/grub', 'GAMES'])], 1, ''),
            ('fat-with-runtime', [('fat', []), ('fat', ['EFI', 'RETROOS', 'CONFIG'])], 1, ''),
            ('esp-mbr', [('esp-mbr', ['EFI', 'CONFIG', 'GAMES']), ('fat', [])], 1, ''),
            ('esp-gpt', [('esp-gpt', []), ('fat', [])], 1, ''),
            ('ext4-retroos', [('fat', []), ('ext4', ['home/retroos'])], 1, 'home/retroos/'),
            ('ext4-other-home', [('fat', []), ('ext4', ['home/zoe', 'home/alice'])], 1, 'home/alice/'),
            ('preferred-home', [('ext4', ['home/alice']), ('ext4', ['home/retroos'])], 1, 'home/retroos/'),
            ('fat-before-other-home', [('ext4', ['home/alice']), ('fat', ['CONFIG'])], 1, ''),
            ('linux-root-and-home', [('ext4', ['bin', 'home/retroos', 'RETROOS', 'boot/grub']), ('fat', [])], 0, 'home/retroos/'),
            ('linux-root-fat-c', [('ext4', ['bin', 'home/retroos', 'RETROOS', 'boot/grub']), ('fat', ['CONFIG'])], 1, ''),
            ('linux-root-empty-fat', [('ext4', ['bin']), ('fat', [])], 1, ''),
            ('main-fat-largest', [('fat', []), ('fat', [], 64)], 1, ''),
            ('empty-tie', [('fat', []), ('fat', [])], 0, ''),
        ]
        for label, layouts, selected, home in cases:
            disks = []
            for i, (kind, directories, *size) in enumerate(layouts):
                tree = work / f'{label}-{i}-tree'
                tree.mkdir()
                for directory in directories:
                    (tree / directory).mkdir(parents=True, exist_ok=True)
                volume = image(work, f'{label}-{i}', tree, 'fat' if kind.startswith('esp') else kind,
                               size_mb=size[0] if size else 32)
                if kind.startswith('esp'):
                    table, typ = ('dos', 'ef') if kind == 'esp-mbr' else ('gpt', 'U')
                    volume = partition_image(work, f'{label}-{i}', volume, table, typ)
                disks.append(volume)
            text = boot(work, label, module, disks)
            assert 'DOS C: maps to /home/retroos/' in text, text
            if label.startswith('linux-root'):
                assert 'Mounting ext4 root' in text and 'Multiboot ext4' not in text, text
            for i, (kind, *_) in enumerate(layouts):
                path = '/' + (home if i == selected else '') + 'SELECT.OK'
                if kind == 'fat' or kind.startswith('esp'):
                    volume = str(disks[i]) + ('@@1048576' if kind.startswith('esp') else '')
                    result = subprocess.run(['mtype', '-i', volume, '::' + path], capture_output=True)
                else:
                    result = run('debugfs', '-R', 'cat ' + path, disks[i], capture_output=True)
                assert (result.stdout == b'S') == (i == selected), (label, i, result.stdout, result.stderr)
        print('PASS: C: selection writes reach the chosen physical FAT/ext4 volume')


if __name__ == '__main__':
    main()
