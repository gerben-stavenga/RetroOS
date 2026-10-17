#!/usr/bin/env python3
"""Select DOS scaling through the real OSD and inspect UEFI framebuffer pixels."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from PIL import Image, ImageChops
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
bits 16
org 100h
    mov dx, ready
    mov ah, 9
    int 21h
    mov ax, 13h
    int 10h
    mov ax, 0a000h
    mov es, ax
    xor di, di
    mov cx, 64000
    mov al, 1
    rep stosb
.wait:
    xor ah, ah
    int 16h
    jmp .wait
ready db 'DISPLAY SCALING READY',13,10,'$'
'''


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-display-scaling-'))
    print('Artifacts:', work, flush=True)
    data = work / 'data.img'
    with data.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', data)
    run('mmd', '-i', data, '::RETROOS')
    (work / 'probe.asm').write_text(PROBE)
    run('nasm', '-f', 'bin', work / 'probe.asm', '-o', work / 'SCALE.COM')
    run('mcopy', '-i', data, work / 'SCALE.COM', '::SCALE.COM')
    boot = prepare_boot(work, data, '[environment]\nTEST=SCALE.COM\n')
    grub = subprocess.check_output(['mtype', '-i', f'{boot}@@1048576', '::boot/grub/grub.cfg']).decode()
    (work / 'grub.cfg').write_text(grub.replace('set gfxmode=auto', 'set gfxmode=1280x800')
                                  .replace('set gfxpayload=auto', 'set gfxpayload=1280x800'))
    run('mcopy', '-o', '-i', f'{boot}@@1048576', work / 'grub.cfg', '::boot/grub/grub.cfg')
    # The development disk's UEFI loader embeds its own GRUB configuration.
    run('grub-mkstandalone', '-O', 'x86_64-efi', '-o', work / 'BOOTX64.EFI',
        'boot/grub/grub.cfg=' + str(work / 'grub.cfg'))
    run('mcopy', '-o', '-i', f'{boot}@@1048576', work / 'BOOTX64.EFI', '::EFI/BOOT/BOOTX64.EFI')
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
    qmp, log = work / 'qmp', work / 'klog'
    args = ['qemu-system-x86_64', '-m', '256', '-display', 'none', '-serial', 'none',
            '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
            '-drive', f'if=pflash,format=raw,file={work / "vars.fd"}',
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw,snapshot=on',
            '-debugcon', f'file:{log}', '-qmp', f'unix:{qmp},server=on,wait=off', '-no-reboot']
    with (work / 'stderr').open('w') as errors:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                assert not any(marker in text for marker in ('PANIC', 'FATAL')), text
                if 'DISPLAY SCALING READY' in text:
                    break
                assert process.poll() is None, (text, (work / 'stderr').read_text())
                time.sleep(.1)
            else:
                raise AssertionError(text)
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(15)
                connection.connect(str(qmp))
                stream = connection.makefile('rwb')
                stream.readline()

                def call(command, **arguments):
                    stream.write((json.dumps(dict(execute=command, arguments=arguments)) + '\n').encode())
                    stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        assert 'error' not in response, response
                        if 'return' in response:
                            return response['return']

                def key(name):
                    call('send-key', keys=[{'type': 'qcode', 'data': name}], **{'hold-time': 50})
                    time.sleep(.3)

                def check(name, expected):
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        shot = work / (name + '.ppm')
                        call('screendump', filename=str(shot))
                        with Image.open(shot) as image:
                            image = image.convert('RGB')
                            assert image.size == (1280, 800), image.size
                            r, g, b = image.split()
                            mask = ImageChops.multiply(b.point(lambda v: 255 if v >= 160 else 0),
                                ImageChops.multiply(r.point(lambda v: 255 if v < 16 else 0),
                                                    g.point(lambda v: 255 if v < 16 else 0)))
                            bounds = mask.getbbox()
                            if bounds == expected:
                                image.save(work / (name + '.png'))
                                print('PASS:', name, bounds, flush=True)
                                return
                        time.sleep(.1)
                    raise AssertionError((name, bounds, expected))

                call('qmp_capabilities')
                check('default-aspect', (107, 0, 1173, 800))
                current = 0
                for name, selection, expected in [
                    ('fill', 1, (0, 0, 1280, 800)),
                    ('sharp', 2, (160, 0, 1120, 800)),
                    ('square', 3, (0, 0, 1280, 800)),
                    ('restored-aspect', 0, (107, 0, 1173, 800)),
                ]:
                    key('f12')
                    key('tab')  # Sound -> Display
                    if name == 'fill':
                        key('right')
                    elif name == 'restored-aspect':
                        key('left')
                        key('left')
                        key('left')
                    else:
                        for _ in range(abs(selection - current)):
                            key('down' if selection > current else 'up')
                        key('ret')
                    current = selection
                    call('screendump', filename=str(work / (name + '-osd.ppm')))
                    key('esc')
                    check(name, expected)
                call('quit')
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
