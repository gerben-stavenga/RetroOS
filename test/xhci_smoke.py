#!/usr/bin/env python3
"""Exercise xHCI enumeration and real input with no PS/2 fallback."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent

# Wait for an 'a' key plus mouse motion and a left click, then exit normally.
# DOS/BIOS observations verify delivery beyond merely configuring endpoints.
PROBE = r'''
bits 16
org 100h
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
    cmp al, 'a'
    jne .mouse
    or byte [seen], 1
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
    cmp byte [seen], 7
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
ready db 'USB INPUT READY',13,10,'$'
passed db 'USB INPUT PASS',13,10,'$'
'''


def session(work, disk, name, controllers, keyboard, mouse, uefi=False):
    log = work / (name + '.log')
    qmp = work / (name + '.sock')
    args = [
        'qemu-system-i386', '-machine', 'pc,i8042=off', '-m', '256',
        '-display', 'none', '-serial', 'none', '-no-reboot',
        '-debugcon', 'file:' + str(log),
        '-drive', f'file={ROOT}/bazel-bin/boot_disk.bin,format=raw,snapshot=on',
        '-drive', f'file={disk},format=raw,snapshot=on',
        '-qmp', f'unix:{qmp},server=on,wait=off',
        '-fw_cfg', 'name=opt/cmdline,string=INPUT.COM',
    ]
    if uefi:
        args[0] = 'qemu-system-x86_64'
        variables = work / 'vars.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={variables}']
    for index in range(controllers):
        args += ['-device', f'qemu-xhci,id=usb{index}']
    args += ['-device', f'usb-kbd,id=kbd,bus=usb{keyboard}.0',
             '-device', f'usb-mouse,id=mouse,bus=usb{mouse}.0']
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
                call('input-send-event', {'events': [
                    {'type': 'key', 'data': {'down': True, 'key': {'type': 'qcode', 'data': 'a'}}}]})
                time.sleep(.2)
                call('input-send-event', {'events': [
                    {'type': 'key', 'data': {'down': False, 'key': {'type': 'qcode', 'data': 'a'}}}]})
                call('input-send-event', {'events': [
                    {'type': 'rel', 'data': {'axis': 'x', 'value': 20}},
                    {'type': 'btn', 'data': {'down': True, 'button': 'left'}}]})
                text = wait_for('All commands done')
            assert 'USB INPUT PASS' in text, text
            assert text.count('xHCI: running') == min(controllers, 4), text
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
        subprocess.run(['mmd', '-i', str(disk), '::CONFIG', '::RETROOS'], check=True)
        subprocess.run(['mcopy', '-i', str(disk), str(ROOT / 'etc/CONFIG.SYS'), '::CONFIG/CONFIG.SYS'], check=True)
        session(work, disk, 'shared', 1, 0, 0)
        session(work, disk, 'split', 2, 0, 1)
        session(work, disk, 'empty-first', 3, 1, 2)
        session(work, disk, 'capacity', 5, 3, 2)
        session(work, disk, 'uefi-split', 3, 1, 2, uefi=True)


if __name__ == '__main__':
    main()
