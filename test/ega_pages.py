#!/usr/bin/env python3
"""Check BIOS EGA page selection and hidden-page redraw on UEFI/QEMU/KVM."""
import argparse
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--boot-image', type=Path,
                        help='Test a saved kernel image, for throughput comparisons')
    args = parser.parse_args()
    if not args.no_build:
        subprocess.run(['bazelisk', 'build', '//:boot_disk',
                        '//test/dos/egapages:egapages_com'], cwd=ROOT, check=True)
    output = ROOT / 'build/ci'
    output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='ega-pages-', dir=output))
    tree = work / 'tree'
    drive = tree / 'home/retroos'
    (drive / 'RETROOS').mkdir(parents=True)
    shutil.copyfile(ROOT / 'bazel-bin/test/dos/egapages/EGAPAGES.COM', drive / 'EGAPAGES.COM')
    for name in ['BOOT.INI', 'RETROOS.INI']:
        shutil.copyfile(ROOT / 'etc' / name, drive / 'RETROOS' / name)
    disk = work / 'data.img'
    with disk.open('wb') as f:
        f.truncate(64 * 1024 * 1024)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(disk)], check=True)
    qmp = work / 'qmp.sock'
    log = work / 'retroos.log'
    command = ['./run.sh', 'qemu', '--kvm', '--headless', '--sound', 'none',
               '--data-image', str(disk), '--cmd', 'EGAPAGES.COM', '--',
               '-qmp', f'unix:{qmp},server=on,wait=off']
    if args.boot_image:
        boot = work / 'boot.img'
        subprocess.run(['cp', '--reflink=auto', '--sparse=always',
                        str(args.boot_image), str(boot)], check=True)
        boot.chmod(boot.stat().st_mode | 0o200)
        subprocess.run(['python3', 'tools/vm_mount_config.py', '--boot-image', str(boot),
                        '--data-image', str(disk), '--command', 'EGAPAGES.COM'],
                       cwd=ROOT, check=True)
        # Reuse the launcher's devices without rebuilding the saved kernel.
        command = ['bash', '-c', '''
SCRIPT_DIR=$PWD
WORK=$1 BOOT_IMAGE=$2 DATA_IMAGE=$3
ARCH=386 FIRMWARE=uefi HEADLESS=1 KVM=1 SOUND=none HD=nvme FREEDOS=0
COMMAND=EGAPAGES.COM HOST_DIR= SB_AUDIO=
PASS=(-qmp "unix:$WORK/qmp.sock,server=on,wait=off")
run_vm() { "$@"; }
source tools/run/qemu.sh
launch
''', 'ega-pages', str(work), str(boot), str(disk)]
    with log.open('wb') as f:
        process = subprocess.Popen(command, cwd=ROOT, stdout=f, stderr=f,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            content = log.read_text(errors='replace')
            assert 'EGA-PAGES-FAIL' not in content, content[-3000:]
            assert 'FATAL' not in content, content[-3000:]
            assert process.poll() is None, content[-3000:]
            if 'EGA-PAGES-PASS' in content:
                break
            time.sleep(.1)
        else:
            raise AssertionError('EGA probe timed out: ' + content[-3000:])
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(10)
            connection.connect(str(qmp))
            with connection.makefile('rwb') as stream:
                stream.readline()

                def call(command, **arguments):
                    stream.write((json.dumps(dict(execute=command, arguments=arguments)) + '\n').encode())
                    stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        assert 'error' not in response, response
                        if 'return' in response:
                            return response['return']

                call('qmp_capabilities')
                # Verify the visible front page as well as the BDA values:
                # redrawing page 0 must not replace the selected blue page 1.
                for i in range(5):
                    time.sleep(.1)
                    shot = work / f'page1-{i}.ppm'
                    call('screendump', filename=str(shot))
                    image = Image.open(shot).convert('RGB')
                    r, g, b = image.getpixel((image.width // 2, image.height // 2))
                    assert b >= 150 and r < 30 and g < 30, ('front page is not blue', (r, g, b))
                call('quit')
        process.wait(timeout=5)
        print(f'PASS: EGA page size, BDA offset, page selection and hidden-page redraw ({work})')
        timing = re.search(r'EGA-MOV-CYCLES=([0-9A-F]{16})', content)
        if timing:
            cycles = int(timing[1], 16)
            print(f'MOV stores: {cycles} TSC ticks / 32768 = {cycles / 32768:.1f} ticks/store')
    finally:
        if process.poll() is None:
            import signal
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
