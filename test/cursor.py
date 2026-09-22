#!/usr/bin/env python3
"""Check BDA/CRTC cursor state and visible placement under BIOS and UEFI."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from PIL import Image, ImageChops

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, data, firmware):
    sock = work / (firmware + '.qmp')
    log = work / (firmware + '.log')
    args = ['qemu-system-x86_64', '-m', '256', '-display', 'none', '-serial', 'none',
            '-debugcon', 'file:' + str(log), '-qmp', f'unix:{sock},server=on,wait=off', '-no-reboot']
    boot = ROOT / 'bazel-bin/boot_disk.bin'
    if firmware == 'uefi':
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
        args += ['-M', 'q35', '-nodefaults', '-device', 'bochs-display',
                 '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={work / "vars.fd"}',
                 '-drive', f'file={boot},if=none,id=boot,format=raw,snapshot=on',
                 '-device', 'piix3-ide,id=boot-ide',
                 '-device', 'ide-hd,drive=boot,bus=boot-ide.0,unit=0,bootindex=1',
                 '-drive', f'file={data},if=none,id=data,format=raw,snapshot=on',
                 '-device', 'ide-hd,drive=data,bus=boot-ide.0,unit=1']
    else:
        args += ['-drive', f'file={boot},format=raw,snapshot=on',
                 '-drive', f'file={data},format=raw,snapshot=on']
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            output = log.read_text(errors='replace') if log.exists() else ''
            assert 'CURSOR-PROBE-FAIL' not in output, output
            if 'CURSOR-PROBE-PASS' in output:
                break
            assert proc.poll() is None, output
            time.sleep(.1)
        else:
            raise AssertionError('probe did not finish: ' + output)
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(5)
            conn.connect(str(sock))
            stream = conn.makefile('rwb')
            stream.readline()

            def call(command, **args):
                stream.write((json.dumps(dict(execute=command, arguments=args)) + '\n').encode())
                stream.flush()
                while True:
                    reply = json.loads(stream.readline())
                    assert 'error' not in reply, reply
                    if 'return' in reply:
                        return reply['return']

            call('qmp_capabilities')
            # Sample both blink phases; do not confuse a hidden phase with a missing cursor.
            seen = False
            hidden = False
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                shot = work / (firmware + '.ppm')
                call('screendump', filename=str(shot))
                im = Image.open(shot).convert('RGB')
                blue = Image.eval(im.getchannel('B'), lambda x: 255 if 160 <= x <= 180 else 0)
                for channel in ('R', 'G'):
                    dark = im.getchannel(channel).point(lambda x: 255 if x < 16 else 0)
                    blue = ImageChops.multiply(blue, dark)
                bounds = blue.getbbox()
                # Background is blue; only the cursor has all channels near full intensity.
                white = im.convert('L').point(lambda x: 255 if x >= 240 else 0)
                cursor = white.getbbox()
                if bounds and cursor:
                    bx, by, right, bottom = bounds
                    width, height = right - bx, bottom - by
                    x, y, endx, endy = cursor
                    assert abs((x - bx) / width - 17 / 80) < .004, (firmware, bounds, cursor)
                    assert abs((y - by) / height - (9*16+14) / 400) < .004, (firmware, bounds, cursor)
                    assert abs((endx - x) / width - 1 / 80) < .004, (firmware, bounds, cursor)
                    assert abs((endy - y) / height - 2 / 400) < .004, (firmware, bounds, cursor)
                    im.save(work / (firmware + '-cursor.png'))
                    seen = True
                elif bounds:
                    hidden = True
                if seen and hidden:
                    break
                time.sleep(.08)
            assert seen and hidden, (firmware, 'cursor did not appear and blink')
            call('quit')
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
    print('PASS:', firmware, 'BDA, CRTC, page switching, cursor placement and blink')


def main():
    run('bazelisk', 'build', '//:boot_disk')
    # Retain logs and screenshots for inspection.
    work = Path(tempfile.mkdtemp(prefix='retroos-cursor-'))
    print('Artifacts:', work, flush=True)
    data = work / 'data.img'
    with data.open('wb') as out:
        out.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', data)
    for name in ('RETROOS', 'CONFIG'):
        run('mmd', '-i', data, '::' + name)
    run('nasm', '-f', 'bin', ROOT / 'test/cursor_probe.asm', '-o', work / 'CURSOR.COM')
    run('mcopy', '-i', data, work / 'CURSOR.COM', '::CURSOR.COM')
    (work / 'CONFIG.SYS').write_text('TEST=CURSOR.COM\n')
    run('mcopy', '-i', data, work / 'CONFIG.SYS', '::CONFIG/CONFIG.SYS')
    for firmware in ('bios', 'uefi'):
        session(work, data, firmware)


if __name__ == '__main__':
    main()
