#!/usr/bin/env python3
"""Launch the interactive Linux shell through real DN and its DOS batch helper."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from game_suite import ppm

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', action='store_true', help='Boot the bundle and GNU shell from the same native ext4 volume')
    parser.add_argument('--kernel', type=Path, default=ROOT / 'bazel-bin/kernel/kernel.elf')
    parser.add_argument('--sound', choices=('none', 'hda'), default='none')
    parser.add_argument('--cpus', type=int, default=6)
    parser.add_argument('--smb-home', action='store_true')
    parser.add_argument('--midi-bank', action='store_true')
    parser.add_argument('--timeout', type=float, default=120)
    options = parser.parse_args()
    artifacts = ROOT / 'build/ci/dn-shell'
    if options.native_root:
        artifacts = artifacts.with_name('dn-shell-native-root')
        if options.kernel != ROOT / 'bazel-bin/kernel/kernel.elf':
            artifacts = artifacts.with_name('dn-shell-native-root-previous')
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-dn-shell-') as directory:
        work = Path(directory)
        home = work / 'root/home/retroos'
        (home / 'RETROOS').mkdir(parents=True)
        (home / 'TEMP').mkdir()
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_orphan_console_probe.c'),
                        '-o', str(home / 'orphan-console')], check=True)
        (home / 'run.bat').write_bytes(b'shell.elf\r\n')
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        shutil.copytree(ROOT / 'boot-bundle/dn', home / 'DN')
        if options.midi_bank:
            shutil.copytree(ROOT / 'showcase-bundle/ULTRASND', home / 'ULTRASND')
        control_path = None
        native_command = None
        if options.native_root:
            tree = work / 'root'
            runtime = tree / 'boot/runtime'
            (runtime / 'RETROOS').mkdir(parents=True)
            shutil.copytree(ROOT / 'boot-bundle/dn', runtime / 'DN')
            for name in ('SHELL.ELF', 'COMMAND.COM'):
                subprocess.run(['mcopy', '-i', str(ROOT / 'bazel-bin/boot_disk.bin') + '@@1048576',
                                '::RETROOS/' + name, str(runtime / 'RETROOS' / name)], check=True)
            for name in ('/bin/sh', '/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/libc.so.6'):
                destination = tree / name.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(name, destination)
            ident = str(uuid.uuid4())
            config = (f'[bundle]\nsource=UUID={ident}\nsubdir=/boot/runtime\n'
                      f'[mount "linux"]\nsource=UUID={ident}\npath=/\naccess=rw\ngrant=/home/retroos\n'
                      '[session]\nhome=/home/retroos\n'
                      f'[mount "dos"]\nsource=UUID={ident}\nsubdir=/home/retroos\npath=/home/retroos\ndrive=C\naccess=rw\ngrant=/home/retroos\n')
            (runtime / 'RETROOS/BOOT.INI').write_text(config)
            shutil.copyfile(ROOT / 'etc/RETROOS.INI', runtime / 'RETROOS/RETROOS.INI')
            grub = work / 'iso/boot/grub'
            grub.mkdir(parents=True)
            for name, source in [('kernel.elf', options.kernel),
                                 ('BOOT.INI', runtime / 'RETROOS/BOOT.INI'),
                                 ('RETROOS.INI', runtime / 'RETROOS/RETROOS.INI')]:
                shutil.copyfile(source, grub.parent / name)
            (grub / 'grub.cfg').write_text('set timeout=0\nmenuentry RetroOS {\n multiboot2 /boot/kernel.elf\n insmod all_video\n set gfxmode=auto\n set gfxpayload=auto\n module2 /boot/BOOT.INI retroos.config=boot\n module2 /boot/RETROOS.INI retroos.config=ini\n boot\n}\n')
            subprocess.run(['grub-mkrescue', '-o', str(work / 'boot.iso'), str(work / 'iso')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
            control_path = str(work / 'control')
            native_command = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-M', 'q35',
                '-m', '2048', '-smp', str(options.cpus), '-display', 'none', '-nic', 'none', '-no-reboot',
                '-nodefaults', '-device', 'bochs-display',
                '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                '-drive', f'if=pflash,format=raw,file={work}/vars.fd', '-cdrom', str(work / 'boot.iso'), '-boot', 'order=d',
                '-serial', 'none', '-chardev', f'socket,id=mcp,path={control_path},server=on,wait=off', '-serial', 'chardev:mcp',
                '-fw_cfg', 'name=opt/mcp,string=com2', '-qmp', f'unix:{work}/qmp,server=on,wait=off', '-debugcon', 'stdio',
                '-drive', f'file={work}/home.img,format=raw,if=none,id=home', '-device', 'nvme,drive=home,serial=RETROOS-DN-SHELL']
            if options.sound == 'hda':
                native_command += ['-audiodev', 'none,id=snd0', '-device', 'intel-hda', '-device', 'hda-duplex,audiodev=snd0']
        data = work / 'home.img'
        with data.open('wb') as output:
            output.truncate(128 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', *(['-U', ident] if options.native_root else []),
                        '-d', str(work / 'root'), str(data)], check=True)
        profile = {'root': '/', 'c_root': str(home)}
        if not options.smb_home:
            profile['native_home_image'] = str(data)
        (work / 'profile.json').write_text(json.dumps(profile))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(work / 'profile.json')
        with (artifacts / 'klog.txt').open('w') as log:
            process = subprocess.Popen(native_command or [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound', options.sound,
                '--', '-m', '2048', '-smp', str(options.cpus),
                '-qmp', f'unix:{work}/qmp,server=on,wait=off',
                '-drive', f'file={data},format=raw,if=none,id=home',
                '-device', 'nvme,drive=home,serial=RETROOS-DN-SHELL'],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            control = socket.socket(socket.AF_UNIX)
            stream = None
            try:
                deadline = time.monotonic() + options.timeout
                while time.monotonic() < deadline:
                    text = (artifacts / 'klog.txt').read_text(errors='replace')
                    match = re.search(r'MCP control: (\S+)', text)
                    if match:
                        control_path = match.group(1)
                    if control_path and 'event_loop entered' in text:
                        control.connect(control_path)
                        control.settimeout(10)
                        stream = control.makefile('rb')
                        break
                    assert process.poll() is None, text[-2000:]
                    time.sleep(.1)
                assert stream is not None, 'No kernel control connection'

                def request(command):
                    control.sendall(command.encode() + b'\n')
                    reply = json.loads(stream.readline())
                    assert reply.get('ok', True), reply
                    return reply

                time.sleep(5)
                request('texthex ' + b'cd C:\\RETROOS'.hex())
                request('key enter')
                time.sleep(2)
                request('texthex ' + b'C:\\RETROOS\\COMMAND.COM /B C:\\run.bat'.hex())
                request('key enter')
                started = time.monotonic()
                submitted = False
                while time.monotonic() < deadline:
                    screen = bytes.fromhex(request('screen')['texthex']).decode()
                    (artifacts / 'screen.txt').write_text(screen)
                    if not submitted and time.monotonic() - started > 8:
                        marker = b"printf '\\104\\116\\137\\123\\110\\105\\114\\114\\137\\120\\101\\123\\123\\012'"
                        command = b'/home/retroos/orphan-console && ' + marker + b" > /home/retroos/pass; printf '\\033[42m'; " + marker + b"; printf '\\033[0m'"
                        for offset in range(0, len(command), 30):
                            request('texthex ' + command[offset:offset + 30].hex())
                        request('key enter')
                        submitted = True
                    if submitted and 'DN_SHELL_PASS' in screen:
                        time.sleep(.3)
                        with socket.socket(socket.AF_UNIX) as qmp:
                            qmp.connect(str(work / 'qmp'))
                            qmp.settimeout(10)
                            with qmp.makefile('rwb') as messages:
                                messages.readline()
                                def qcommand(name, **arguments):
                                    messages.write((json.dumps({'execute': name, 'arguments': arguments}) + '\n').encode())
                                    messages.flush()
                                    while True:
                                        reply = json.loads(messages.readline())
                                        assert 'error' not in reply, reply
                                        if 'return' in reply:
                                            return
                                qcommand('qmp_capabilities')
                                frame = artifacts / 'terminal.ppm'
                                qcommand('screendump', filename=str(frame))
                                _, _, pixels = ppm(frame.read_bytes())
                                green = sum(g > r + 20 and g > b + 20
                                            for r, g, b in zip(pixels[::3], pixels[1::3], pixels[2::3]))
                                assert green > 1000, ('Terminal output missing from physical framebuffer', green)
                                terminal_pixels = pixels
                                request('key f12')
                                for index in range(8):
                                    time.sleep(.15)
                                    frame = artifacts / f'osd-{index}.ppm'
                                    qcommand('screendump', filename=str(frame))
                                    _, _, pixels = ppm(frame.read_bytes())
                                    lit = sum(max(r, g, b) > 30 for r, g, b in zip(pixels[::3], pixels[1::3], pixels[2::3]))
                                    assert lit > 10000, ('F12 display disappeared', index, lit)
                                    assert sum(a != b for a, b in zip(pixels, terminal_pixels)) > 10000, 'F12 overlay never appeared'
                                request('key esc')
                                time.sleep(.2)
                                qcommand('screendump', filename=str(artifacts / 'terminal-restored.ppm'))
                                _, _, pixels = ppm((artifacts / 'terminal-restored.ppm').read_bytes())
                                green = sum(g > r + 20 and g > b + 20
                                            for r, g, b in zip(pixels[::3], pixels[1::3], pixels[2::3]))
                                assert green > 1000, 'Terminal did not return after closing F12'
                        request('status')
                        request('debug dump')
                        break
                    time.sleep(.25)
                else:
                    request('debug dump')
                    raise AssertionError('DN shell launch failed; see ' + str(artifacts))
            finally:
                if stream is not None:
                    stream.close()
                control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
        recovered = work / 'pass'
        if options.smb_home:
            shutil.copyfile(home / 'pass', recovered)
        else:
            subprocess.run(['debugfs', '-R', f'dump /home/retroos/pass {recovered}', str(data)], check=True, capture_output=True)
        assert recovered.read_bytes() == b'DN_SHELL_PASS\n'
        text = (artifacts / 'klog.txt').read_text(errors='replace')
        assert 'child tid=3, parent tid=2' in text, 'DOS batch helper path was not exercised'
    print('PASS: real DN launches SHELL.ELF; interactive shell accepts input and persists output')


if __name__ == '__main__':
    main()
