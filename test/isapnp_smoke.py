#!/usr/bin/env python3
"""PnP discovery precedes legacy SB16 fallback, including already-active cards."""
import pathlib
import subprocess
import tempfile
from unittest.mock import patch
from boot_composition import run, file, image, boot

PROBE = r'''
bits 16
org 100h
mov dx, message
mov ah, 9
int 21h
mov ax, 4c00h
int 21h
message db 'COMPOSITION-OK',13,10,'$'
'''


def main():
    run('bazelisk', 'build', '//kernel:kernel_elf')
    with tempfile.TemporaryDirectory(prefix='retroos-isapnp-') as temp:
        work = pathlib.Path(temp)
        asm = work / 'probe.asm'
        asm.write_text(PROBE)
        probe = work / 'probe.com'
        run('nasm', '-f', 'bin', '-o', probe, asm)
        tree = work / 'root'
        file(tree, 'home/retroos/RETROOS/PROBE.COM', probe.read_bytes())
        file(tree, 'home/retroos/CONFIG/CONFIG.SYS',
             b'SB_AUDIO=native\nBLASTER=A220 I7 D1 H5 P330 T6\n')
        (tree / 'bin').mkdir()
        module = image(work, 'root', tree, 'ext4')
        text = boot(work, 'no-pnp-card', module, [])
        assert 'ISA PnP: no Sound Blaster found; trying legacy DSP discovery' in text, text
        assert 'ISA LPC:' not in text, text
        text = boot(work, 'unsupported-lpc-opt-in', module, [],
                    extra_args='isa-lpc=disappointment')
        assert 'ISA LPC: dISAppointment: skipped: unsupported LPC chipset' in text, text
        assert text.index('ISA LPC:') < text.index('ISA PnP:'), text
        popen = subprocess.Popen

        def with_sb(args, *rest, **kwargs):
            if args[0] == 'qemu-system-i386':
                args = [*args, '-audiodev', 'none,id=snd0', '-device',
                        'sb16,audiodev=snd0,iobase=0x220,irq=7,dma=1,dma16=5']
            return popen(args, *rest, **kwargs)

        with patch('subprocess.Popen', with_sb):
            text = boot(work, 'already-active-sb16', module, [])
        assert 'sb: DSP 4.' in text, text
        assert text.index('ISA PnP: no Sound Blaster found') < text.index('sb: DSP 4.'), text
        print('PASS: PnP-first discovery and legacy SB16 fallback')


if __name__ == '__main__':
    main()
