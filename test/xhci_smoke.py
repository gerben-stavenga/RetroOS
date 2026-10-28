#!/usr/bin/env python3
"""Exercise xHCI enumeration and real input with no PS/2 fallback."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parent.parent

# Wait for an 'a' key plus mouse motion and a left click, then exit normally.
# DOS/BIOS observations verify delivery beyond merely configuring endpoints.
PROBE = r'''
bits 16
org 100h
%macro key_seen 2
    test byte [seen], %1
    jnz %%done
    or byte [seen], %1
    push ax
    push dx
    mov dx, %2
    mov ah, 9
    int 21h
    pop dx
    pop ax
%%done:
%endmacro
    xor ax, ax
    int 33h
    cmp ax, 0ffffh
    jne failure
    mov ax, 0bh
    int 33h
    mov dx, ready
    mov ah, 9
    int 21h
.loop:
    mov ah, 1
    int 16h
    jz .mouse
    xor ah, ah
    int 16h
%ifdef TWO_KEYBOARDS
%ifdef FOUR_KEYBOARDS
    cmp al, 'c'
    jne .fourth_key
    key_seen 16, key_c
.fourth_key:
    cmp al, 'd'
    jne .second_key
    key_seen 32, key_d
.second_key:
%endif
    cmp al, 'b'
    jne .first_key
    key_seen 8, key_b
.first_key:
%endif
    cmp al, 'a'
    jne .mouse
    key_seen 1, key_a
.mouse:
    mov ax, 0bh
    int 33h
    or cx, dx
    jz .buttons
    or byte [seen], 2
.buttons:
    mov ax, 3
    int 33h
    test bx, 1
    jz .check
    or byte [seen], 4
.check:
%ifdef FOUR_KEYBOARDS
    cmp byte [seen], 63
%elifdef TWO_KEYBOARDS
    cmp byte [seen], 15
%else
    cmp byte [seen], 7
%endif
    jne .loop
    mov dx, passed
    mov ah, 9
    int 21h
    mov ax, 4c00h
    int 21h
failure:
    mov ax, 4c01h
    int 21h
seen db 0
key_a db 'USB KEY a',13,10,'$'
key_b db 'USB KEY b',13,10,'$'
key_c db 'USB KEY c',13,10,'$'
key_d db 'USB KEY d',13,10,'$'
ready db 'USB INPUT READY',13,10,'$'
passed db 'USB INPUT PASS',13,10,'$'
'''


def session(work, disk, name, controllers, keyboard, mouse, uefi=False, hubs=0, second_keyboard=None, four_keyboards=False):
    log = work / (name + '.log')
    qmp = work / (name + '.sock')
    boot = prepare_boot(work, disk)
    args = [
        'qemu-system-i386', '-machine', 'pc,i8042=off', '-m', '256',
        '-display', 'none', '-serial', 'none', '-no-reboot',
        '-debugcon', 'file:' + str(log),
        '-drive', f'file={boot},format=raw,snapshot=on',
        '-drive', f'file={disk},format=raw,snapshot=on',
        '-qmp', f'unix:{qmp},server=on,wait=off',
        '-fw_cfg', 'name=opt/cmdline,string=' + ('FOUR.COM' if four_keyboards else 'DUAL.COM' if second_keyboard is not None else 'INPUT.COM'),
    ]
    if uefi:
        args[0] = 'qemu-system-x86_64'
        variables = work / 'vars.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={variables}']
    for index in range(controllers):
        args += ['-device', f'qemu-xhci,id=usb{index}' + (',p2=8' if four_keyboards else '')]
    chain = '1'
    for index in range(hubs):
        args += ['-device', f'usb-hub,id=hub{index},bus=usb{keyboard}.0,port={chain},port-power=on']
        chain += '.3'
    if second_keyboard is not None:
        # Bind each keyboard to a different console so QMP can deliver input
        # to both independently, while both remain connected and configured.
        args += ['-vga', 'none', '-device', 'VGA,id=video0',
                 '-device', 'secondary-vga,id=video1']
        second_port = ',port=' + chain[:-1] + '1' if hubs and second_keyboard == keyboard else ''
        args += ['-device', f'usb-kbd,id=kbd2,display=video1,bus=usb{second_keyboard}.0{second_port}']
    if four_keyboards:
        for index in (2, 3):
            port = ',port=' + chain[:-1] + str(index + 3) if hubs else ''
            args += ['-device', f'secondary-vga,id=video{index}',
                     '-device', f'usb-kbd,id=kbd{index + 1},display=video{index},bus=usb{keyboard}.0{port}']
    key_port = ',port=' + chain[:-1] + '2' if hubs else ''
    mouse_port = ',port=' + chain[:-1] + '4' if hubs and mouse == keyboard else ''
    args += ['-device', f'usb-kbd,id=kbd,bus=usb{keyboard}.0{key_port}' + (',display=video0' if second_keyboard is not None else ''),
             '-device', f'usb-mouse,id=mouse,bus=usb{mouse}.0{mouse_port}']
    with (work / (name + '.stderr')).open('w') as errors:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors,
                                stdin=subprocess.DEVNULL)
        try:
            def wait_for(marker):
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    text = log.read_text(errors='replace') if log.exists() else ''
                    if marker in text:
                        return text
                    assert proc.poll() is None and not any(m in text for m in ('FATAL', 'PANIC')), text
                    time.sleep(.1)
                raise AssertionError(name + ': ' + text)

            wait_for('USB INPUT READY')
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(15)
                connection.connect(str(qmp))
                stream = connection.makefile('rwb')
                stream.readline()

                def call(command, arguments=None):
                    stream.write((json.dumps(dict(execute=command, arguments=arguments or {})) + '\n').encode())
                    stream.flush()
                    while True:
                        result = json.loads(stream.readline())
                        assert 'error' not in result, result
                        if 'return' in result:
                            return result['return']

                call('qmp_capabilities')
                keyboards = [('a', 'video0'), ('b', 'video1')] if second_keyboard is not None else [('a', None)]
                if four_keyboards:
                    keyboards += [('c', 'video2'), ('d', 'video3')]
                for key, display in keyboards:
                    # Force the compact transfer ring to wrap before the key
                    # the guest requires. Losing a pipe at wrap must fail.
                    for sent in (['x'] * 40 + [key] if four_keyboards and not uefi else [key]):
                        for down in (True, False):
                            arguments = {'events': [{'type': 'key', 'data': {
                                'down': down, 'key': {'type': 'qcode', 'data': sent}}}]}
                            if display:
                                arguments['device'] = display
                            call('input-send-event', arguments)
                            if down and sent == key:
                                wait_for('USB KEY ' + key)
                            time.sleep(.03 if four_keyboards and not uefi else .2)
                call('input-send-event', {'events': [
                    {'type': 'rel', 'data': {'axis': 'x', 'value': 20}},
                    {'type': 'btn', 'data': {'down': True, 'button': 'left'}}]})
                text = wait_for('All commands done')
            assert 'USB INPUT PASS' in text, text
            assert text.count('xHCI: running') == min(controllers, 4), text
            assert text.count('xHCI: hub ready') == hubs, text
            assert text.count('xHCI: keyboard ready') == (4 if four_keyboards else 2 if second_keyboard is not None else 1), text
            for expected in ('xHCI: keyboard ready', 'xHCI: mouse ready',
                             'IRQ: no i8042'):
                assert expected in text, text
            if controllers > 4:
                assert 'xHCI: controller limit reached' in text, text
            assert not any(marker in text for marker in ('FATAL', 'PANIC', 'panicked')), text
            print(f'PASS: {name}: USB keyboard, motion and click delivered', flush=True)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)


def main():
    subprocess.run([shutil.which('bazelisk') or 'bazel', 'build', '//:boot_disk'],
                   cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-xhci-') as temp:
        work = Path(temp)
        source = work / 'input.asm'
        source.write_text(PROBE)
        probe = work / 'INPUT.COM'
        subprocess.run(['nasm', '-f', 'bin', str(source), '-o', str(probe)], check=True)
        disk = work / 'data.img'
        with disk.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024)
        subprocess.run(['mkfs.fat', '-F', '32', str(disk)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['mcopy', '-i', str(disk), str(probe), '::INPUT.COM'], check=True)
        subprocess.run(['nasm', '-DTWO_KEYBOARDS', '-f', 'bin', str(source), '-o', str(probe)], check=True)
        subprocess.run(['mcopy', '-i', str(disk), str(probe), '::DUAL.COM'], check=True)
        subprocess.run(['nasm', '-DTWO_KEYBOARDS', '-DFOUR_KEYBOARDS', '-f', 'bin', str(source), '-o', str(probe)], check=True)
        subprocess.run(['mcopy', '-i', str(disk), str(probe), '::FOUR.COM'], check=True)
        subprocess.run(['mmd', '-i', str(disk), '::RETROOS'], check=True)
        subprocess.run(['mcopy', '-i', str(disk), str(ROOT / 'etc/RETROOS.INI'), '::RETROOS/RETROOS.INI'], check=True)
        session(work, disk, 'four-keyboards', 1, 0, 0, second_keyboard=0, four_keyboards=True)
        session(work, disk, 'four-keyboards-deep-hub', 1, 0, 0, hubs=3, second_keyboard=0, four_keyboards=True)
        session(work, disk, 'four-keyboards-uefi', 1, 0, 0, uefi=True, hubs=1, second_keyboard=0, four_keyboards=True)
        session(work, disk, 'two-keyboards', 1, 0, 0, second_keyboard=0)
        session(work, disk, 'two-keyboards-hub', 1, 0, 0, hubs=1, second_keyboard=0)
        session(work, disk, 'two-keyboards-split', 2, 0, 0, second_keyboard=1)
        session(work, disk, 'two-keyboards-uefi', 1, 0, 0, uefi=True, hubs=1, second_keyboard=0)
        session(work, disk, 'hub', 1, 0, 0, hubs=1)
        session(work, disk, 'nested-hubs', 1, 0, 0, hubs=2)
        session(work, disk, 'deep-hubs', 1, 0, 0, hubs=5)
        session(work, disk, 'hub-split', 2, 0, 1, hubs=1)
        session(work, disk, 'uefi-hub', 1, 0, 0, uefi=True, hubs=1)
        session(work, disk, 'shared', 1, 0, 0)
        session(work, disk, 'split', 2, 0, 1)
        session(work, disk, 'empty-first', 3, 1, 2)
        session(work, disk, 'capacity', 5, 3, 2)
        session(work, disk, 'uefi-split', 3, 1, 2, uefi=True)


if __name__ == '__main__':
    main()
