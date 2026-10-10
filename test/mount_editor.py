#!/usr/bin/env python3
"""Boot the bundled DN and export UUID mount choices through the real OSD."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def testcase(shared):
    with tempfile.TemporaryDirectory(prefix='retroos-mount-editor-') as directory:
        work = Path(directory)
        boot, data, qmp, log = (work/name for name in ('boot.img', 'data.img', 'qmp', 'klog'))
        shutil.copyfile(ROOT/'bazel-bin/boot_disk.bin', boot)
        with data.open('wb') as stream:
            stream.truncate((64 if shared else 16)*1024*1024)
        if shared:
            tree = work/'tree'
            home = tree/'home/retroos'
            home.mkdir(parents=True)
            home.chmod(0o775)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-b', '4096', '-d', str(tree), str(data)], check=True)
            subprocess.run(['python3', str(ROOT/'tools/vm_mount_config.py'),
                            '--boot-image', str(boot), '--data-image', str(data)], check=True)
        else:
            subprocess.run(['mkfs.fat', '-F', '16', str(data)], check=True, stdout=subprocess.DEVNULL)
        args = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
                '-display', 'none', '-serial', 'none', '-audiodev', 'none,id=snd0',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw',
                '-device', f'VGA,romfile={ROOT}/third_party/vgabios/vgabios-stdvga.bin',
                '-debugcon', f'file:{log}', '-qmp', f'unix:{qmp},server=on,wait=off', '-no-reboot']
        with (work/'stderr').open('w') as stderr:
            process = subprocess.Popen(args, stderr=stderr)
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    content = log.read_text(errors='replace') if log.exists() else ''
                    if 'Dos Navigator  Version' in content:
                        break
                    assert 'PANIC' not in content, content
                    time.sleep(.1)
                else:
                    raise RuntimeError(content)
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.connect(str(qmp))
                    with connection.makefile('rwb') as stream:
                        stream.readline()

                        def call(command, **arguments):
                            stream.write((json.dumps(dict(execute=command, arguments=arguments))+'\n').encode())
                            stream.flush()
                            while True:
                                response = json.loads(stream.readline())
                                assert 'error' not in response, response
                                if 'return' in response:
                                    return response['return']

                        call('qmp_capabilities')
                        time.sleep(2)
                        # OSD starts on Sound; CD's speed row uses Left/Right,
                        # so move down before cycling past CD to HD and Mnt.
                        keys = ['f12', 'tab', 'right', 'right', 'down', 'right', 'right',
                                'down', 'right', 'down', 'right', 'down', 'down', 'ret']
                        if shared:
                            keys = ['f12', 'tab', 'right', 'right', 'down', 'right', 'right',
                                    'down', 'down', 'down', 'down', 'ret']
                        for key in keys:
                            call('send-key', keys=[{'type': 'qcode', 'data': key}], **{'hold-time': 50})
                            time.sleep(1 if key == 'f12' else .4)
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if 'Mount setup:' in log.read_text(errors='replace'):
                                break
                            time.sleep(.1)
                        if 'Mount setup: Saved' not in log.read_text(errors='replace'):
                            call('screendump', filename='/tmp/retroos-mount-editor-failure.ppm')
                            raise RuntimeError(log.read_text(errors='replace')[-4000:])
                        call('quit')
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
        if shared:
            text = subprocess.check_output(['debugfs', '-R', 'cat /home/retroos/RETROOS.INI', str(data)],
                                           stderr=subprocess.DEVNULL).decode()
            assert text.count('source=UUID=') == 2 and 'path=/\n' in text, text
        else:
            text = subprocess.check_output(['mtype', '-i', str(data), '::RETROOS.INI']).decode()
        assert 'source=UUID=' in text and 'drive=C' in text and 'access=rw' in text, text
        assert 'START=C:\\DN\\DN.COM' in text, text
        assert 'Mount setup: Saved' in log.read_text(errors='replace')
        print(f'PASS: default DN boot and OSD mount setup export (shared root/C={shared})', flush=True)


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    testcase(False)
    testcase(True)


if __name__ == '__main__':
    main()
