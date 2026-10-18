#!/usr/bin/env python3
"""Boot the native Wi-Fi diagnostic image and verify its firmware RAM bundle.

QEMU verifies packaging and the absent-radio path, not WCN7850 hardware.
Requires locally installed firmware; nothing is downloaded for this test.
"""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from wifi_firmware import FAMILY, FILES, unpack


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, image, uefi=False, physical_c=False):
    work.mkdir()
    disk = work / 'boot.img'
    shutil.copyfile(image, disk)
    volume = f'{disk}@@1048576'
    firmware_path = ('/home/retroos/RETROOS/FIRMWARE' if physical_c else '/lib/firmware')
    config = work / 'RETROOS.INI'
    config.write_text('[environment]\nTEST=/bin/busybox grep -q detected /proc/wifi;'
                      f'/bin/busybox wc -c {firmware_path}/ath12k/WCN7850/hw2.0/amss.bin'
                      + (';/bin/busybox grep -q detected /home/retroos/proc/wifi' if uefi else '') + '\n')
    run('mcopy', '-o', '-i', volume, config, '::boot/retroos/RETROOS.INI')
    if uefi:
        # Match native installs where C: is exposed below the Unix root.
        boot_config = work / 'BOOT.INI'
        boot_config.write_text('[bundle]\nsource=module\nsubdir=/\n'
                               '[mount "linux"]\nsource=bundle\npath=/\naccess=ram\n'
                               '[mount "dos"]\nsource=bundle\npath=/home/retroos\ndrive=C\naccess=ram\n')
        run('mcopy', '-o', '-i', volume, boot_config, '::boot/retroos/BOOT.INI')
    log = work / 'klog'
    args = ['qemu-system-x86_64', '-m', '256', '-cpu', 'max' if uefi else '486,-tsc',
            '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
            '-drive', f'file={disk},format=raw,snapshot=on', '-debugcon', f'file:{log}']
    if uefi:
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={work / "vars.fd"}']
    else:
        args += ['-machine', 'pc,hpet=off']
    if physical_c:
        # A native disk install overlays RETROOS with a matched runtime.
        # Firmware stored on C: must remain accessible through that overlay.
        tree = work / 'tree'
        target = tree / 'home/retroos/RETROOS/FIRMWARE' / FAMILY
        shutil.copytree(work.parent / 'expected' / FAMILY, target)
        backing = work / 'native.img'
        with backing.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024)
        uuid = '12345678-1234-1234-1234-123456789abc'
        run('mkfs.ext4', '-q', '-F', '-U', uuid, '-d', tree, backing)
        boot_config = work / 'BOOT.INI'
        boot_config.write_text('[bundle]\nsource=module\nsubdir=/\n'
                               f'[mount "linux"]\nsource=UUID={uuid}\npath=/\naccess=rw\ngrant=/home/retroos\n'
                               f'[mount "dos"]\nsource=UUID={uuid}\nsubdir=/home/retroos\n'
                               'path=/home/retroos\ndrive=C\naccess=rw\ngrant=/home/retroos\n'
                               '[mount "tools"]\nsource=bundle\nsubdir=/bin\npath=/bin\naccess=ram\n')
        run('mcopy', '-o', '-i', volume, boot_config, '::boot/retroos/BOOT.INI')
        args += ['-drive', f'file={backing},format=raw,snapshot=on']
    with (work / 'stderr').open('w') as errors:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 45
            while True:
                text = log.read_text(errors='replace') if log.exists() else ''
                assert '!!! FATAL !!!' not in text and 'PANIC' not in text, text[-5000:]
                exits = re.findall(r'\[mem\] exit tid=\d+ code=(-?\d+) ', text)
                if len(exits) >= (3 if uefi else 2):
                    break
                assert process.poll() is None, (text[-5000:], (work / 'stderr').read_text())
                assert time.monotonic() < deadline, text[-5000:]
                time.sleep(.1)
            assert exits == ['0'] * (3 if uefi else 2), text[-5000:]
            assert 'WiFi: no supported native radio detected' in text
            assert 'BHI/BHIE' not in text
        finally:
            process.terminate()
            process.wait(timeout=5)
    print(f'PASS: {work.name}: absent radio, status file, firmware readable from ' +
          ('persistent C: through runtime mount' if physical_c else 'RAM'), flush=True)


def main():
    source = Path(os.environ.get('WIFI_FIRMWARE_SOURCE', '/lib/firmware'))
    work = Path(tempfile.mkdtemp(prefix='retroos-wifi-boot-'))
    image = work / 'wifi.img'
    print('Artifacts:', work, flush=True)
    run('python3', ROOT / 'tools/build_wifi_image.py', '--source', source, '--out', image)
    expected = unpack(source, work / 'expected')
    volume = f'{image}@@1048576'
    config = subprocess.check_output(['mtype', '-i', volume, '::boot/grub/grub.cfg']).decode()
    release = re.search(r'^set retroos_release=(\S+)', config, re.M).group(1)
    compressed = work / 'base.img.gz'
    run('mcopy', '-i', volume, '::' + release + '/retroos-base.img.gz', compressed)
    raw = work / 'base.img'
    with gzip.open(compressed, 'rb') as source_image, raw.open('wb') as destination:
        shutil.copyfileobj(source_image, destination)
    for name in FILES:
        contents = subprocess.check_output(['debugfs', '-R', f'cat /lib/firmware/{FAMILY}/{name}', str(raw)],
                                           stderr=subprocess.DEVNULL)
        assert hashlib.sha256(contents).digest() == hashlib.sha256((expected / name).read_bytes()).digest(), name
    print('PASS: every firmware file and license preserved in GRUB RAM module', flush=True)
    session(work / 'bios', image)
    session(work / 'uefi', image, uefi=True)
    session(work / 'native-c', image, uefi=True, physical_c=True)


if __name__ == '__main__':
    main()
